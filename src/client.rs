//! The `Backend` over the API of an `agentsafe serve`, reached through `tailscale serve` or, on
//! the same host, through its Unix socket.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use ureq::Agent;
use zeroize::Zeroizing;

use crate::backend::{Backend, Exposed, Fetched, MetaPatch, Purpose, Put, Refusal, Selection};
use crate::vault::{Catalog, validate_name};

const TIMEOUT: Duration = Duration::from_secs(10);
/// The largest answer read; the server caps request bodies far lower.
const ANSWER_LIMIT: u64 = 16 * 1024 * 1024;

enum Transport {
    Http(Agent),
    Unix(PathBuf),
}

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }
}

pub struct RemoteBackend {
    transport: Transport,
    server: String,
}

#[derive(Deserialize)]
struct Entries<T> {
    entries: T,
}

#[derive(Serialize)]
#[serde(untagged)]
enum FetchBody<'a> {
    Names { names: &'a [String] },
    All { all: bool },
}

#[derive(Serialize)]
struct PutBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<Exposed<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merge: Option<Exposed<'a>>,
    #[serde(skip_serializing_if = "MetaPatch::is_empty")]
    meta: &'a MetaPatch,
}

#[derive(Deserialize)]
struct Merged {
    keys: usize,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

impl RemoteBackend {
    /// `server` is an `http(s)://` URL, or `unix:PATH` for a server on this host.
    pub fn new(server: &str) -> RemoteBackend {
        let transport = match server.strip_prefix("unix:") {
            Some(path) => Transport::Unix(PathBuf::from(path)),
            None => Transport::Http(
                Agent::config_builder()
                    .timeout_global(Some(TIMEOUT))
                    .http_status_as_error(false)
                    .build()
                    .into(),
            ),
        };
        RemoteBackend {
            transport,
            server: server.trim_end_matches('/').to_string(),
        }
    }

    /// Sends one request and returns the status and the body of a 2xx answer. Any other status
    /// is a short error that shows only an `{"error": ...}` body: the server never puts a value
    /// there, while another body could hold one.
    fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
        entry: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let body = match body {
            Some(b) => Some(Zeroizing::new(serde_json::to_vec(b)?)),
            None => None,
        };
        let uri = format!("/api/v1/{path}");
        let body = body.as_ref().map(|b| b.as_slice());
        let (status, answer) = match &self.transport {
            Transport::Http(agent) => self.http(agent, method, &uri, body),
            Transport::Unix(socket) => unix(socket, method, &uri, body),
        }
        .with_context(|| format!("cannot reach {}", self.server))?;
        if (200..300).contains(&status) {
            return Ok(answer);
        }
        if let (404, Some(name)) = (status, entry) {
            return Err(Refusal::NotFound(name.into()).into());
        }
        let detail = serde_json::from_slice::<ErrorBody>(&answer)
            .map(|b| format!(": {}", b.error.chars().take(200).collect::<String>()))
            .unwrap_or_default();
        if status == 403 {
            bail!("the server refused the request (403){detail}");
        }
        bail!("the server answered {status}{detail}")
    }

    fn http(
        &self,
        agent: &Agent,
        method: Method,
        uri: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Zeroizing<Vec<u8>>)> {
        let url = format!("{}{uri}", self.server);
        let body = body.unwrap_or_default();
        let response = match method {
            Method::Get => agent.get(&url).header("Sec-Agentsafe", "1").call(),
            Method::Delete => agent.delete(&url).header("Sec-Agentsafe", "1").call(),
            Method::Post | Method::Put => {
                let request = if let Method::Post = method {
                    agent.post(&url)
                } else {
                    agent.put(&url)
                };
                request
                    .header("Sec-Agentsafe", "1")
                    .content_type("application/json")
                    .send(body)
            }
        };
        let mut response = response?;
        let status = response.status().as_u16();
        let answer = response
            .body_mut()
            .with_config()
            .limit(ANSWER_LIMIT)
            .read_to_vec()?;
        Ok((status, Zeroizing::new(answer)))
    }

    fn json<T: for<'de> Deserialize<'de>>(&self, answer: &[u8]) -> Result<T> {
        // Parse errors quote the body, which may hold values.
        serde_json::from_slice(answer).map_err(|_| anyhow!("invalid answer from {}", self.server))
    }
}

/// One HTTP/1.1 exchange over the socket, closed by the server after its answer.
fn unix(
    socket: &std::path::Path,
    method: Method,
    uri: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Zeroizing<Vec<u8>>)> {
    let body = body.unwrap_or_default();
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let mut request = Zeroizing::new(
        format!(
            "{} {uri} HTTP/1.1\r\nHost: localhost\r\nSec-Agentsafe: 1\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            method.as_str(),
            body.len()
        )
        .into_bytes(),
    );
    request.extend_from_slice(body);
    stream.write_all(&request)?;
    let mut raw = Zeroizing::new(Vec::new());
    stream.take(ANSWER_LIMIT).read_to_end(&mut raw)?;
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("no end of headers in the answer")?;
    let head = std::str::from_utf8(&raw[..end]).context("headers are not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .context("no status in the answer")?;
    // The server sends whole bodies with a Content-Length, and closes the connection after them.
    if lines.any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:")) {
        bail!("a chunked answer is not supported");
    }
    Ok((status, Zeroizing::new(raw[end + 4..].to_vec())))
}

impl Backend for RemoteBackend {
    fn catalog(&self) -> Result<Catalog> {
        let answer = self.call(Method::Get, "entries", None::<&()>, None)?;
        Ok(self.json::<Entries<Catalog>>(&answer)?.entries)
    }

    /// The server audits every remote fetch as `get`, whatever the purpose.
    fn fetch(&self, _purpose: Purpose, selection: &Selection) -> Result<Fetched> {
        let body = match selection {
            Selection::All => FetchBody::All { all: true },
            Selection::Names(names) => FetchBody::Names { names },
        };
        let answer = self.call(Method::Post, "fetch", Some(&body), None)?;
        let fetched: Fetched = self.json(&answer)?;
        if let Selection::Names(names) = selection
            && let Some(missing) = names.iter().find(|n| !fetched.entries.contains_key(*n))
        {
            bail!("the server did not return {missing}");
        }
        Ok(fetched)
    }

    fn put(&self, name: &str, put: Put) -> Result<()> {
        validate_name(name)?;
        let body = PutBody {
            values: put.values.as_ref().map(Exposed),
            merge: None,
            meta: &put.meta,
        };
        self.call(
            Method::Put,
            &format!("entries/{name}"),
            Some(&body),
            Some(name),
        )?;
        Ok(())
    }

    fn merge(&self, name: &str, put: Put) -> Result<usize> {
        validate_name(name)?;
        let body = PutBody {
            values: None,
            merge: put.values.as_ref().map(Exposed),
            meta: &put.meta,
        };
        let answer = self.call(
            Method::Put,
            &format!("entries/{name}"),
            Some(&body),
            Some(name),
        )?;
        Ok(self.json::<Merged>(&answer)?.keys)
    }

    fn remove(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        self.call(
            Method::Delete,
            &format!("entries/{name}"),
            None::<&()>,
            Some(name),
        )?;
        Ok(())
    }
}
