//! `agentsafe serve` behind a stand-in for `tailscale serve`, and the CLI in remote mode.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use secrecy::ExposeSecret;
use tempfile::TempDir;

const API_TOKEN: &str = "fixture-token-0123456789abcdef";
const DB_PASSWORD: &str = "fx-pa\"ss:word/with+chars";
const OTHER_VALUE: &str = "other-fixture-value-31415";
const CAP: &str = "github.com/falistos/agentsafe/cap/agentsafe";
const PEER: &str = "100.101.102.103";

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn caps(values: &str) -> String {
    format!(r#"{{"{CAP}": [{values}]}}"#)
}

/// A config directory: the server's (local, with a fixture vault) or a client's (remote).
struct Home {
    dir: TempDir,
}

impl Home {
    fn local() -> Home {
        let dir = tempfile::tempdir().unwrap();
        let identity = age::x25519::Identity::generate();
        let key = dir.path().join("key.txt");
        fs::write(&key, format!("{}\n", identity.to_string().expose_secret())).unwrap();
        fs::write(
            dir.path().join("config.toml"),
            format!("identity = {:?}\n", key.to_str().unwrap()),
        )
        .unwrap();
        let home = Home { dir };
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/env");
        for name in ["app", "db"] {
            let file = fixtures.join(format!("{name}.env"));
            home.ok(&["import", file.to_str().unwrap(), "--name", name]);
        }
        home.ok_stdin(&["set", "other", "--key", "V"], OTHER_VALUE);
        home
    }

    fn remote(proxy: &Proxy) -> Home {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("config.toml"),
            format!("server = \"http://{}/\"\n", proxy.addr),
        )
        .unwrap();
        Home { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentsafe"));
        cmd.args(args)
            .env("AGENTSAFE_CONFIG", self.path("config.toml"))
            .env("HOME", self.dir.path())
            .env("USER", "tester")
            .env_remove("XDG_RUNTIME_DIR");
        cmd
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn ok_stdin(&self, args: &[&str], stdin: &str) -> String {
        let out = self.run(args, stdin);
        assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
        text(&out.stdout)
    }

    fn ok(&self, args: &[&str]) -> String {
        self.ok_stdin(args, "")
    }

    /// Runs a command expected to fail, and returns its stderr.
    fn fails(&self, args: &[&str]) -> String {
        let out = self.run(args, "");
        assert!(!out.status.success(), "{args:?} succeeded");
        text(&out.stderr)
    }

    fn audit(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(self.path("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

/// `agentsafe serve` on a socket in its own temp dir.
struct Server {
    home: Home,
    socket: PathBuf,
    child: Option<Child>,
}

impl Server {
    fn start(home: Home) -> Server {
        let socket = home.path("agentsafe.sock");
        Server::start_at(home, socket)
    }

    fn start_at(home: Home, socket: PathBuf) -> Server {
        let child = home
            .cmd(&["serve", "--socket", socket.to_str().unwrap()])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut server = Server {
            home,
            socket,
            child: Some(child),
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&server.socket).is_err() {
            if let Some(status) = server.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("serve exited: {status}");
            }
            assert!(Instant::now() < deadline, "serve did not start");
            thread::sleep(Duration::from_millis(20));
        }
        server
    }

    fn stop(&mut self) -> ExitStatus {
        let mut child = self.child.take().unwrap();
        let killed = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(killed.success());
        child.wait().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Stands in for `tailscale serve --accept-app-caps`: forwards HTTP from TCP to the socket,
/// dropping the client's `Tailscale-*` and `X-Forwarded-*` headers and setting the ones the test
/// chooses, with `Host: localhost`.
struct Proxy {
    addr: String,
    headers: Arc<Mutex<Vec<(String, String)>>>,
}

impl Proxy {
    fn start(socket: &Path) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let headers = Arc::new(Mutex::new(Vec::new()));
        let shared = headers.clone();
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
    fn peer(&self, caps: Option<&str>, login: Option<&str>) {
        let mut headers = vec![("X-Forwarded-For".to_string(), PEER.to_string())];
        if let Some(caps) = caps {
            headers.push(("Tailscale-App-Capabilities".into(), caps.into()));
        }
        if let Some(login) = login {
            headers.push(("Tailscale-User-Login".into(), login.into()));
        }
        *self.headers.lock().unwrap() = headers;
    }

    fn url(&self, path: &str) -> String {
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
        out.push_str(&format!("{name}: {value}\r\n"));
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

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

/// Status and body of an API request through the proxy, with the CSRF header unless `csrf` is false.
fn api(proxy: &Proxy, method: &str, path: &str, body: Option<&str>, csrf: bool) -> (u16, String) {
    let agent = agent();
    let url = proxy.url(path);
    let csrf = if csrf { "1" } else { "0" };
    // A client-sent capability header, which the proxy must drop like Serve does.
    let forged = caps(r#"{"entries": ["*"], "actions": ["admin"]}"#);
    let response = match (method, body) {
        ("GET", _) => agent
            .get(&url)
            .header("Sec-Agentsafe", csrf)
            .header("Tailscale-App-Capabilities", &forged)
            .call(),
        ("DELETE", _) => agent
            .delete(&url)
            .header("Sec-Agentsafe", csrf)
            .header("Tailscale-App-Capabilities", &forged)
            .call(),
        (method, body) => {
            let request = if method == "POST" {
                agent.post(&url)
            } else {
                agent.put(&url)
            };
            request
                .header("Sec-Agentsafe", csrf)
                .header("Tailscale-App-Capabilities", &forged)
                .content_type("application/json")
                .send(body.unwrap_or("{}"))
        }
    };
    let mut response = response.unwrap();
    let status = response.status().as_u16();
    assert_eq!(
        response.headers().get("cache-control").unwrap(),
        "no-store",
        "{method} {path}"
    );
    (status, response.body_mut().read_to_string().unwrap())
}

const ROUTES: [(&str, &str, Option<&str>); 7] = [
    ("GET", "/api/v1/entries", None),
    ("GET", "/api/v1/entries/app", None),
    ("POST", "/api/v1/fetch", Some(r#"{"all": true}"#)),
    (
        "PUT",
        "/api/v1/entries/app",
        Some(r#"{"meta": {"owner": "x"}}"#),
    ),
    ("DELETE", "/api/v1/entries/app", None),
    ("GET", "/", None),
    ("GET", "/api/v1/nothing-here", None),
];

fn assert_no_value(raw: &str) {
    for value in [API_TOKEN, DB_PASSWORD, OTHER_VALUE] {
        assert!(!raw.contains(value), "a value in {raw}");
        let encoded = STANDARD.encode(value);
        assert!(!raw.contains(&encoded), "a base64 value in {raw}");
    }
}

#[test]
fn requests_without_a_grant_or_the_csrf_header_are_refused_everywhere() {
    let server = Server::start(Home::local());
    let proxy = Proxy::start(&server.socket);
    let admin = caps(r#"{"entries": ["*"], "actions": ["admin"]}"#);
    let peers = [
        None,
        Some(r#"{"example.com/cap/other": [{"entries": ["*"], "actions": ["admin"]}]}"#.into()),
        Some(caps(
            r#"{"entries": ["*"], "actions": ["delete"]}, {"entries": ["*"], "actions": ["get"], "x": 1}"#,
        )),
        Some(caps("")),
        Some("not json".into()),
    ];
    for peer in &peers {
        proxy.peer(peer.as_deref(), None);
        for (method, path, body) in ROUTES {
            let (status, body) = api(&proxy, method, path, body, true);
            assert_eq!(status, 403, "{peer:?} {method} {path}: {body}");
            assert_no_value(&body);
        }
    }

    proxy.peer(Some(&admin), Some("alice@example.com"));
    for (method, path, body) in &ROUTES[..5] {
        let (status, body) = api(&proxy, method, path, *body, false);
        assert_eq!(status, 403, "no CSRF header: {method} {path}: {body}");
    }

    // Straight to the socket, past the proxy: no header is no right.
    let mut raw = UnixStream::connect(&server.socket).unwrap();
    raw.write_all(
        b"GET /api/v1/entries HTTP/1.1\r\nHost: localhost\r\nSec-Agentsafe: 1\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut answer = String::new();
    raw.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");

    // The CLI in remote mode reports the refusal without a body that could hold values.
    proxy.peer(None, None);
    let client = Home::remote(&proxy);
    for args in [
        &["list"][..],
        &["scrub"],
        &["run", "--env", "app", "--", "true"],
    ] {
        let err = client.fails(args);
        assert!(err.contains("403"), "{args:?}: {err}");
    }

    let denied: Vec<_> = server
        .home
        .audit()
        .into_iter()
        .filter(|l| l["via"] == "api")
        .collect();
    assert!(denied.iter().all(|l| l["result"] == "denied"), "{denied:?}");
    let first = &denied[0];
    assert_eq!(first["who"], format!("node:{PEER}"));
    assert_eq!(first["action"], "list");
    assert_eq!(first["reason"], "no capability header");
    assert!(denied.iter().any(|l| l["who"] == "alice@example.com"
        && l["action"] == "rm"
        && l["entry"] == "app"
        && l["reason"] == "missing Sec-Agentsafe header"));
    assert!(denied.iter().any(|l| l["who"] == "unknown"));
}

#[test]
fn grants_decide_what_is_listed_described_and_fetched() {
    let server = Server::start(Home::local());
    let proxy = Proxy::start(&server.socket);
    proxy.peer(
        Some(&caps(
            r#"{"entries": ["app*"], "actions": ["get"]}, {"entries": ["db"], "actions": ["list"]}"#,
        )),
        None,
    );
    let client = Home::remote(&proxy);

    let list = client.ok(&["list"]);
    let names: Vec<&str> = list
        .lines()
        .skip(1)
        .map(|l| l.split('\t').next().unwrap())
        .collect();
    assert_eq!(names, ["app", "db"], "{list}");
    assert!(
        client
            .ok(&["describe", "db"])
            .contains("keys: DB_DSN, DB_PASSWORD, DB_USER")
    );
    assert!(
        client
            .fails(&["describe", "other"])
            .contains("no entry named other")
    );

    // Existence is only revealed to a caller who could list the name.
    let describe = |name: &str| {
        api(
            &proxy,
            "GET",
            &format!("/api/v1/entries/{name}"),
            None,
            true,
        )
        .0
    };
    assert_eq!(describe("app"), 200);
    assert_eq!(describe("other"), 403);
    assert_eq!(describe("missing"), 403);
    assert_eq!(describe("app-missing"), 404);

    let fetch = |body: &str| api(&proxy, "POST", "/api/v1/fetch", Some(body), true);
    let (status, body) = fetch(r#"{"names": ["app", "db"]}"#);
    assert_eq!(status, 403, "{body}");
    assert_no_value(&body);
    let (status, body) = fetch(r#"{"all": true}"#);
    assert_eq!(status, 200);
    let all: serde_json::Value = serde_json::from_str(&body).unwrap();
    let names: Vec<&String> = all["entries"].as_object().unwrap().keys().collect();
    assert_eq!(names, ["app"]);
    assert_eq!(all["entries"]["app"]["API_TOKEN"], API_TOKEN);
    for bad in [
        r#"{"names": ["app"], "all": true}"#,
        r#"{"all": false}"#,
        r#"{"names": "app"}"#,
        "{",
    ] {
        assert_eq!(fetch(bad).0, 400, "{bad}");
    }

    let err = client.fails(&["edit", "db", "--owner", "x"]);
    assert!(err.contains("403"), "{err}");
    let err = client.fails(&["run", "--env", "app", "--env", "db", "--", "true"]);
    assert!(err.contains("403"), "{err}");
    let scrubbed = client.ok_stdin(&["scrub"], &format!("{API_TOKEN} {DB_PASSWORD}\n"));
    assert_eq!(scrubbed, format!("***app*** {DB_PASSWORD}\n"));

    let audit = server.home.audit();
    let api_lines: Vec<_> = audit.iter().filter(|l| l["via"] == "api").collect();
    let summary: Vec<(String, String, String)> = api_lines
        .iter()
        .map(|l| {
            (
                l["action"].as_str().unwrap().into(),
                l["entry"].as_str().unwrap_or("-").into(),
                l["result"].as_str().unwrap().into(),
            )
        })
        .collect();
    let line = |a: &str, e: &str, r: &str| (a.to_string(), e.to_string(), r.to_string());
    assert_eq!(
        summary,
        [
            line("describe", "other", "denied"),
            line("describe", "missing", "denied"),
            line("get", "db", "denied"),
            line("get", "app", "ok"),
            line("edit", "db", "denied"),
            line("get", "db", "denied"),
            line("get", "app", "ok"),
        ]
    );
    assert!(api_lines.iter().all(|l| l["who"] == format!("node:{PEER}")));
}

#[test]
fn remote_run_set_edit_and_rm_act_on_the_server_vault() {
    let server = Server::start(Home::local());
    let proxy = Proxy::start(&server.socket);
    let writer = caps(r#"{"entries": ["*"], "actions": ["get", "put"]}"#);
    proxy.peer(Some(&writer), Some("alice@example.com"));
    let client = Home::remote(&proxy);

    let script = format!("test \"$VAR\" = {API_TOKEN} && echo \"$VAR\" injected");
    let out = client.ok(&[
        "run",
        "--env",
        "app:API_TOKEN=VAR",
        "--",
        "sh",
        "-c",
        &script,
    ]);
    assert_eq!(out, "***app*** injected\n");

    let value = "remote-set-value-2718";
    client.ok_stdin(
        &[
            "set",
            "cloud",
            "--key",
            "TOKEN",
            "--description",
            "Remote fixture",
        ],
        &format!("{value}\n"),
    );
    client.ok(&["edit", "cloud", "--owner", "ops"]);
    let described = server.home.ok(&["describe", "cloud"]);
    assert!(described.contains("keys: TOKEN"), "{described}");
    assert!(
        described.contains("description: Remote fixture"),
        "{described}"
    );
    assert!(described.contains("owner: ops"), "{described}");
    let check = format!("test \"$TOKEN\" = {value} && echo same");
    assert_eq!(
        server
            .home
            .ok(&["run", "--env", "cloud", "--", "sh", "-c", &check]),
        "same\n"
    );

    assert!(
        client
            .fails(&["edit", "nothing", "--owner", "x"])
            .contains("no entry named nothing")
    );
    assert!(client.fails(&["rm", "cloud"]).contains("403"));
    proxy.peer(
        Some(&caps(r#"{"entries": ["cloud"], "actions": ["admin"]}"#)),
        Some("alice@example.com"),
    );
    client.ok(&["rm", "cloud"]);
    assert!(
        client
            .fails(&["rm", "cloud"])
            .contains("no entry named cloud")
    );
    assert!(!server.home.ok(&["list"]).contains("cloud"));

    let oversized = format!(r#"{{"values": {{"K": "{}"}}}}"#, "x".repeat(70 * 1024));
    assert_eq!(
        api(&proxy, "PUT", "/api/v1/entries/big", Some(&oversized), true).0,
        413
    );

    let raw = fs::read_to_string(server.home.path("audit.jsonl")).unwrap();
    assert_no_value(&raw);
    assert!(!raw.contains(value) && !raw.contains(&STANDARD.encode(value)));
    let api_lines: Vec<(String, String, String, String)> = server
        .home
        .audit()
        .into_iter()
        .filter(|l| l["via"] == "api")
        .map(|l| {
            let s = |k: &str| l[k].as_str().unwrap_or("-").to_string();
            (s("who"), s("action"), s("entry"), s("result"))
        })
        .collect();
    let line = |a: &str, e: &str, r: &str| {
        (
            "alice@example.com".to_string(),
            a.to_string(),
            e.to_string(),
            r.to_string(),
        )
    };
    assert_eq!(
        api_lines,
        [
            line("get", "app", "ok"),
            line("put", "cloud", "ok"),
            line("edit", "cloud", "ok"),
            line("edit", "nothing", "error"),
            line("rm", "cloud", "denied"),
            line("rm", "cloud", "ok"),
            line("rm", "cloud", "error"),
        ]
    );
}

#[test]
fn the_socket_is_private_replaces_a_stale_one_and_goes_away_on_sigterm() {
    let home = Home::local();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agentsafe.sock");
    drop(UnixListener::bind(&socket).unwrap());
    assert!(
        UnixStream::connect(&socket).is_err(),
        "the stale socket answers"
    );

    let mut server = Server::start_at(home, socket.clone());
    let meta = fs::symlink_metadata(&socket).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 1, "staging directory left behind");

    let busy = server
        .home
        .fails(&["serve", "--socket", socket.to_str().unwrap()]);
    assert!(busy.contains("in use"), "{busy}");

    let status = server.stop();
    assert!(status.success(), "{status}");
    assert!(!socket.exists());
}

#[test]
fn serve_needs_a_local_config() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    fs::write(&config, "server = \"http://127.0.0.1:1\"\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agentsafe"))
        .args([
            "serve",
            "--socket",
            dir.path().join("s.sock").to_str().unwrap(),
        ])
        .env("AGENTSAFE_CONFIG", &config)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("serve needs a local config"));
    assert!(!dir.path().join("s.sock").exists());
}
