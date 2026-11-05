//! The `Backend` over the API of an `agentsafe serve` reached through `tailscale serve`.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use ureq::http::{Response, StatusCode};
use ureq::typestate::WithBody;
use ureq::{Agent, RequestBuilder};
use zeroize::Zeroizing;

use crate::backend::{Backend, Exposed, Fetched, MetaPatch, Purpose, Put, Refusal, Selection};
use crate::vault::{Catalog, validate_name};

pub struct RemoteBackend {
    agent: Agent,
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
    pub fn new(server: &str) -> RemoteBackend {
        let agent = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(10)))
            .http_status_as_error(false)
            .build()
            .into();
        RemoteBackend {
            agent,
            server: server.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1/{path}", self.server)
    }

    /// Turns a failed call or a non-2xx status into a short error. Only an `{"error": ...}`
    /// body is shown: the server never puts a value there, while another body could hold one.
    fn check(
        &self,
        response: Result<Response<ureq::Body>, ureq::Error>,
        entry: Option<&str>,
    ) -> Result<Response<ureq::Body>> {
        let mut response = response.with_context(|| format!("cannot reach {}", self.server))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        if let (StatusCode::NOT_FOUND, Some(name)) = (status, entry) {
            return Err(Refusal::NotFound(name.into()).into());
        }
        let detail = response
            .body_mut()
            .with_config()
            .limit(4096)
            .read_to_vec()
            .ok()
            .and_then(|body| serde_json::from_slice::<ErrorBody>(&body).ok())
            .map(|b| format!(": {}", b.error.chars().take(200).collect::<String>()))
            .unwrap_or_default();
        if status == StatusCode::FORBIDDEN {
            bail!("the server refused the request (403){detail}");
        }
        bail!("the server answered {status}{detail}")
    }

    fn read<T: for<'de> Deserialize<'de>>(&self, mut response: Response<ureq::Body>) -> Result<T> {
        let body = Zeroizing::new(
            response
                .body_mut()
                .read_to_vec()
                .with_context(|| format!("cannot read the answer of {}", self.server))?,
        );
        // Parse errors quote the body, which may hold values.
        serde_json::from_slice(&body).map_err(|_| anyhow!("invalid answer from {}", self.server))
    }

    fn send_json(
        &self,
        request: RequestBuilder<WithBody>,
        body: &impl Serialize,
        entry: Option<&str>,
    ) -> Result<Response<ureq::Body>> {
        let body = Zeroizing::new(serde_json::to_vec(body)?);
        self.check(
            request
                .header("Sec-Agentsafe", "1")
                .content_type("application/json")
                .send(body.as_slice()),
            entry,
        )
    }
}

impl Backend for RemoteBackend {
    fn catalog(&self) -> Result<Catalog> {
        let response = self
            .agent
            .get(self.url("entries"))
            .header("Sec-Agentsafe", "1")
            .call();
        let entries: Entries<Catalog> = self.read(self.check(response, None)?)?;
        Ok(entries.entries)
    }

    /// The server audits every remote fetch as `get`, whatever the purpose.
    fn fetch(&self, _purpose: Purpose, selection: &Selection) -> Result<Fetched> {
        let body = match selection {
            Selection::All => FetchBody::All { all: true },
            Selection::Names(names) => FetchBody::Names { names },
        };
        let response = self.send_json(self.agent.post(self.url("fetch")), &body, None)?;
        let fetched: Entries<Fetched> = self.read(response)?;
        if let Selection::Names(names) = selection
            && let Some(missing) = names.iter().find(|n| !fetched.entries.contains_key(*n))
        {
            bail!("the server did not return {missing}");
        }
        Ok(fetched.entries)
    }

    fn put(&self, name: &str, put: Put) -> Result<()> {
        validate_name(name)?;
        let body = PutBody {
            values: put.values.as_ref().map(Exposed),
            merge: None,
            meta: &put.meta,
        };
        let request = self.agent.put(self.url(&format!("entries/{name}")));
        self.send_json(request, &body, Some(name))?;
        Ok(())
    }

    fn merge(&self, name: &str, put: Put) -> Result<usize> {
        validate_name(name)?;
        let body = PutBody {
            values: None,
            merge: put.values.as_ref().map(Exposed),
            meta: &put.meta,
        };
        let request = self.agent.put(self.url(&format!("entries/{name}")));
        let merged: Merged = self.read(self.send_json(request, &body, Some(name))?)?;
        Ok(merged.keys)
    }

    fn remove(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let response = self
            .agent
            .delete(self.url(&format!("entries/{name}")))
            .header("Sec-Agentsafe", "1")
            .call();
        self.check(response, Some(name))?;
        Ok(())
    }
}
