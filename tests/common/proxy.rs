//! The stand-in for `tailscale serve`, and the wait for a server's socket. Only the tests that
//! reach the server over HTTP include it.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const PEER: &str = "100.101.102.103";
const CAP: &str = "github.com/falistos/agentsafe/cap/agentsafe";

pub fn caps(values: &str) -> String {
    format!(r#"{{"{CAP}": [{values}]}}"#)
}

/// Waits until `serve` accepts connections on `socket`; panics if it exits or takes too long.
pub fn wait_for_socket(socket: &Path, serve: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(socket).is_err() {
        if let Some(status) = serve.try_wait().unwrap() {
            panic!("serve exited: {status}");
        }
        assert!(Instant::now() < deadline, "serve did not start");
        thread::sleep(Duration::from_millis(20));
    }
}

/// Stands in for `tailscale serve --accept-app-caps`: forwards HTTP from TCP to the socket,
/// dropping the client's `Tailscale-*` and `X-Forwarded-*` headers and setting the ones the test
/// chooses, with `Host: localhost`.
pub struct Proxy {
    pub addr: String,
    pub headers: Arc<Mutex<Vec<(String, String)>>>,
}

impl Proxy {
    pub fn start(socket: &Path) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let headers = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::clone(&headers);
        let socket = socket.to_path_buf();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { break };
                let injected = shared.lock().unwrap().clone();
                let socket = socket.clone();
                thread::spawn(move || forward(conn, &socket, &injected));
            }
        });
        Proxy { addr, headers }
    }

    /// `caps` is the `Tailscale-App-Capabilities` value, none when the peer has no grant.
    pub fn peer(&self, caps: Option<&str>, login: Option<&str>) {
        let mut headers = vec![("X-Forwarded-For".to_string(), PEER.to_string())];
        if let Some(caps) = caps {
            headers.push(("Tailscale-App-Capabilities".into(), caps.into()));
        }
        if let Some(login) = login {
            headers.push(("Tailscale-User-Login".into(), login.into()));
        }
        *self.headers.lock().unwrap() = headers;
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

fn forward(mut client: TcpStream, socket: &Path, injected: &[(String, String)]) {
    let mut head = Vec::new();
    let mut byte = [0u8];
    while !head.ends_with(b"\r\n\r\n") {
        if client.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let mut lines = head.split("\r\n").filter(|l| !l.is_empty());
    let mut out = format!("{}\r\n", lines.next().unwrap());
    for line in lines {
        let name = line.split(':').next().unwrap().trim().to_ascii_lowercase();
        let name = name.replace('_', "-");
        let dropped = name == "tailscale-app-capabilities"
            || name.starts_with("tailscale-user-")
            || name.starts_with("x-forwarded-")
            || name == "host"
            || name == "connection";
        if !dropped {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out.push_str("Host: localhost\r\nConnection: close\r\n");
    for (name, value) in injected {
        write!(out, "{name}: {value}\r\n").unwrap();
    }
    out.push_str("\r\n");
    let mut server = UnixStream::connect(socket).unwrap();
    server.write_all(out.as_bytes()).unwrap();
    let (mut from_client, mut to_server) =
        (client.try_clone().unwrap(), server.try_clone().unwrap());
    thread::spawn(move || {
        let _ = io::copy(&mut from_client, &mut to_server);
    });
    let _ = io::copy(&mut server, &mut client);
    let _ = client.shutdown(Shutdown::Both);
}
