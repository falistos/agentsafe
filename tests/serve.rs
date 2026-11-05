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
        terminate(self.child.as_ref().unwrap());
        self.child.take().unwrap().wait().unwrap()
    }
}

fn terminate(child: &Child) {
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
}

/// The exit status, or `None` if the child still runs after `limit`.
fn wait_at_most(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() > deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Kills the servers a failed test leaves running.
struct Children(Vec<Child>);

impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
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
        assert!(!raw.contains(value), "a fixture value leaked");
        let encoded = STANDARD.encode(value);
        assert!(!raw.contains(&encoded), "a base64 fixture value leaked");
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
    let mut entries: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    entries.sort();
    assert_eq!(entries, ["agentsafe.sock", "agentsafe.sock.lock"]);
    let lock = dir.path().join("agentsafe.sock.lock");
    assert_eq!(
        fs::metadata(lock).unwrap().permissions().mode() & 0o777,
        0o600
    );

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

#[test]
fn an_invalid_field_is_refused_without_being_echoed() {
    let server = Server::start(Home::local());
    let proxy = Proxy::start(&server.socket);
    proxy.peer(
        Some(&caps(r#"{"entries": ["*"], "actions": ["put"]}"#)),
        Some("alice@example.com"),
    );
    let body = serde_json::json!({ "meta": { "rotate_by": API_TOKEN } }).to_string();
    let (status, answer) = api(&proxy, "PUT", "/api/v1/entries/app", Some(&body), true);
    assert_eq!(status, 400);
    assert_no_value(&answer);
    assert!(answer.contains("YYYY-MM-DD"));

    let err = Home::remote(&proxy).fails(&["edit", "app", "--rotate-by", API_TOKEN]);
    assert_no_value(&err);
    assert!(err.contains("YYYY-MM-DD"));

    assert_no_value(&fs::read_to_string(server.home.path("audit.jsonl")).unwrap());
    let refused: Vec<_> = server
        .home
        .audit()
        .into_iter()
        .filter(|l| l["via"] == "api")
        .map(|l| (l["action"].clone(), l["entry"].clone(), l["result"].clone()))
        .collect();
    let edit = (
        serde_json::json!("edit"),
        serde_json::json!("app"),
        serde_json::json!("error"),
    );
    assert_eq!(refused, [edit.clone(), edit]);
}

#[test]
fn concurrent_starts_leave_one_server_on_the_socket() {
    let home = Home::local();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agentsafe.sock");
    // The race is timing-dependent: several rounds make a regression show up reliably.
    for round in 0..5 {
        let mut children = Children(
            (0..12)
                .map(|_| {
                    home.cmd(&["serve", "--socket", socket.to_str().unwrap()])
                        .stdin(Stdio::null())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap()
                })
                .collect(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let running = loop {
            let running: Vec<usize> = (0..children.0.len())
                .filter(|&i| children.0[i].try_wait().unwrap().is_none())
                .collect();
            if running.len() <= 1 || Instant::now() > deadline {
                break running;
            }
            thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(
            running.len(),
            1,
            "round {round}: servers on one socket path"
        );
        let winner = running[0];
        for (i, child) in children.0.iter_mut().enumerate() {
            if i == winner {
                continue;
            }
            assert!(!child.wait().unwrap().success());
            let mut err = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut err)
                .unwrap();
            assert!(err.contains("in use"), "{err}");
        }
        while UnixStream::connect(&socket).is_err() {
            assert!(
                Instant::now() < deadline,
                "round {round}: the socket is not reachable"
            );
            thread::sleep(Duration::from_millis(20));
        }

        let winner = &mut children.0[winner];
        terminate(winner);
        assert!(winner.wait().unwrap().success());
        assert!(!socket.exists());
    }
}

#[test]
fn sigterm_cuts_a_stalled_request_after_the_grace_period() {
    let mut server = Server::start(Home::local());
    let mut conn = UnixStream::connect(&server.socket).unwrap();
    let head = format!(
        "PUT /api/v1/entries/app HTTP/1.1\r\nHost: localhost\r\nSec-Agentsafe: 1\r\n\
         Tailscale-App-Capabilities: {}\r\nContent-Length: 200\r\n\r\n{{",
        caps(r#"{"entries": ["*"], "actions": ["admin"]}"#)
    );
    conn.write_all(head.as_bytes()).unwrap();
    // Let the handler start waiting on the rest of the body.
    thread::sleep(Duration::from_millis(200));

    let child = server.child.as_mut().unwrap();
    terminate(child);
    let status = wait_at_most(child, Duration::from_secs(8));
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    assert!(!server.socket.exists());
    server.child = None;
    drop(conn);
}

// The admin web UI, through the same proxy.

const FORWARDED_HOST: &str = "agentsafe.example.ts.net";
const SAME_ORIGIN: [(&str, &str); 1] = [("Sec-Fetch-Site", "same-origin")];

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map_or("", |(_, v)| v)
    }
}

/// A browser's request to the UI: `form` is sent urlencoded unless it is a GET, and redirects
/// are not followed.
fn ui(
    proxy: &Proxy,
    method: &str,
    path: &str,
    form: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> Reply {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .build()
        .into();
    let url = proxy.url(path);
    let result = if method == "GET" {
        let mut request = agent.get(&url);
        for (k, v) in headers {
            request = request.header(*k, *v);
        }
        request.call()
    } else {
        let mut request = agent.post(&url);
        for (k, v) in headers {
            request = request.header(*k, *v);
        }
        request.send_form(form.iter().copied())
    };
    let mut response = result.unwrap();
    Reply {
        status: response.status().as_u16(),
        headers: response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
            .collect(),
        body: response.body_mut().read_to_string().unwrap(),
    }
}

fn get(proxy: &Proxy, path: &str) -> Reply {
    ui(proxy, "GET", path, &[], &[])
}

fn post(proxy: &Proxy, path: &str, form: &[(&str, &str)]) -> Reply {
    ui(proxy, "POST", path, form, &SAME_ORIGIN)
}

fn admin_of(entries: &str) -> String {
    caps(&format!(
        r#"{{"entries": [{entries}], "actions": ["admin"]}}"#
    ))
}

impl Proxy {
    /// The host `tailscale serve` forwards, which the UI compares with a request's `Origin`.
    fn forwarded_host(&self, host: &str) {
        self.headers
            .lock()
            .unwrap()
            .push(("X-Forwarded-Host".into(), host.into()));
    }
}

fn admin_proxy(server: &Server, entries: &str) -> Proxy {
    let proxy = Proxy::start(&server.socket);
    proxy.peer(Some(&admin_of(entries)), Some("alice@example.com"));
    proxy.forwarded_host(FORWARDED_HOST);
    proxy
}

#[test]
fn the_ui_is_for_admins_and_shows_only_their_entries() {
    let server = Server::start(Home::local());
    let proxy = Proxy::start(&server.socket);

    proxy.peer(
        Some(&caps(r#"{"entries": ["*"], "actions": ["get", "put"]}"#)),
        Some("bob@example.com"),
    );
    for path in ["/", "/new", "/audit", "/e/app"] {
        let reply = get(&proxy, path);
        assert_eq!(reply.status, 403, "{path}");
        assert_no_value(&reply.body);
    }
    let denied: Vec<_> = server
        .home
        .audit()
        .into_iter()
        .filter(|l| l["via"] == "ui")
        .collect();
    assert!(
        denied
            .iter()
            .all(|l| l["result"] == "denied" && l["who"] == "bob@example.com"),
        "{denied:?}"
    );
    assert_eq!(denied.len(), 4);

    proxy.peer(Some(&admin_of(r#""db*""#)), Some("alice@example.com"));
    let reply = get(&proxy, "/");
    assert_eq!(reply.status, 200);
    assert!(reply.body.contains(r#"href="/e/db""#), "{}", reply.body);
    for other in ["app", "other"] {
        assert!(!reply.body.contains(&format!("/e/{other}")), "{other}");
    }
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(reply.header("referrer-policy"), "no-referrer");
    assert_eq!(
        reply.header("content-security-policy"),
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    );
    assert_eq!(get(&proxy, "/e/db").status, 200);
    assert_eq!(get(&proxy, "/e/app").status, 403);
    assert_eq!(get(&proxy, "/e/nothing").status, 403);
    assert_eq!(get(&proxy, "/audit").status, 403);
    let page = get(&proxy, "/e/db");
    assert!(page.body.contains("DB_PASSWORD"), "{}", page.body);
    assert_no_value(&page.body);
}

#[test]
fn entry_text_is_html_escaped() {
    let server = Server::start(Home::local());
    let hostile = r#"<script>alert(1)</script>" autofocus x=""#;
    server.home.ok(&["edit", "db", "--description", hostile]);
    server.home.ok(&["edit", "db", "--owner", "<b>owner</b>"]);
    let proxy = admin_proxy(&server, r#""*""#);
    for path in ["/", "/e/db"] {
        let body = get(&proxy, path).body;
        assert!(!body.contains("<script"), "{path}: {body}");
        assert!(!body.contains("<b>owner"), "{path}");
        assert!(
            body.contains("&lt;script&gt;alert(1)&lt;"),
            "{path}: {body}"
        );
    }
    assert!(!get(&proxy, "/e/db").body.contains(r#"" autofocus"#));
}

#[test]
fn non_get_ui_requests_need_a_same_origin_signal() {
    let server = Server::start(Home::local());
    let proxy = admin_proxy(&server, r#""*""#);
    let edit = |owner: &str, headers: &[(&str, &str)]| {
        let form = [("owner", owner)];
        ui(&proxy, "POST", "/e/db/meta", &form, headers)
    };

    let refused: [&[(&str, &str)]; 5] = [
        &[("Sec-Fetch-Site", "cross-site")],
        &[("Sec-Fetch-Site", "same-site")],
        &[("Origin", "https://evil.example")],
        &[],
        // A foreign Origin is not saved by a matching host elsewhere in the request.
        &[
            ("Origin", "https://evil.example"),
            ("Referer", "https://agentsafe.example.ts.net/"),
        ],
    ];
    for headers in refused {
        let reply = edit("attacker", headers);
        assert_eq!(reply.status, 403, "{headers:?}");
        assert!(!reply.header("content-security-policy").is_empty());
    }
    // The refusal came before the write.
    assert!(!server.home.ok(&["describe", "db"]).contains("owner:"));
    let cross: Vec<_> = server
        .home
        .audit()
        .into_iter()
        .filter(|l| l["reason"] == "cross-origin request")
        .collect();
    assert_eq!(cross.len(), refused.len());
    assert_eq!(cross[0]["via"], "ui");
    assert_eq!(cross[0]["result"], "denied");

    let accepted: [(&[(&str, &str)], &str); 3] = [
        (&[("Sec-Fetch-Site", "same-origin")], "one"),
        (&[("Sec-Fetch-Site", "none")], "two"),
        (&[("Origin", "https://agentsafe.example.ts.net")], "three"),
    ];
    for (headers, owner) in accepted {
        let reply = edit(owner, headers);
        assert_eq!(reply.status, 303, "{headers:?}");
        assert_eq!(reply.header("location"), "/e/db?done=meta");
        let described = server.home.ok(&["describe", "db"]);
        assert!(
            described.contains(&format!("owner: {owner}")),
            "{described}"
        );
    }
}

#[test]
fn values_replaced_in_the_ui_reach_a_remote_run() {
    let server = Server::start(Home::local());
    let proxy = admin_proxy(&server, r#""*""#);
    let client = Home::remote(&proxy);
    let fresh = "ui-replaced-value-8675309";

    let reply = post(
        &proxy,
        "/e/app/values",
        &[(
            "values",
            &format!("API_TOKEN={fresh}\r\nOTHER_KEY=short-but-long-enough\r\n"),
        )],
    );
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), "/e/app?done=values");
    let script = format!("test \"$VAR\" = {fresh} && echo \"$VAR\" injected");
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
    // Replaced, not merged: the old keys are gone.
    assert!(!server.home.ok(&["describe", "app"]).contains("API_URL"));
    // Nothing shows the values back.
    let page = get(&proxy, "/e/app?done=values");
    assert!(page.body.contains("Values replaced."));
    assert!(!page.body.contains(fresh) && !page.body.contains(API_TOKEN));

    // A line that is not KEY=VALUE is refused by number, without being quoted.
    let reply = post(
        &proxy,
        "/e/app/values",
        &[("values", "A=1\nleaked-looking-line-31337\n")],
    );
    assert_eq!(reply.status, 400);
    assert!(reply.body.contains("line 2"), "{}", reply.body);
    assert!(!reply.body.contains("leaked-looking-line-31337"));
    // A name that does not exist is not created by this form.
    assert_eq!(
        post(&proxy, "/e/nothing/values", &[("values", "A=1")]).status,
        404
    );
    assert!(!server.home.ok(&["list"]).contains("nothing"));

    let puts: Vec<_> = server
        .home
        .audit()
        .into_iter()
        .filter(|l| l["via"] == "ui" && l["action"] == "put")
        .collect();
    assert_eq!(puts.len(), 1, "{puts:?}");
    assert_eq!(puts[0]["who"], "alice@example.com");
    assert_eq!(puts[0]["entry"], "app");
    let raw = fs::read_to_string(server.home.path("audit.jsonl")).unwrap();
    assert!(!raw.contains(fresh));
}

#[test]
fn new_entries_are_created_and_deleted_on_a_typed_confirmation() {
    let server = Server::start(Home::local());
    let proxy = admin_proxy(&server, r#""db*", "cloud""#);

    let created = post(
        &proxy,
        "/new",
        &[
            ("name", "cloud"),
            ("values", "TOKEN=ui-created-value-1618"),
            ("description", "Made in the UI"),
            ("tags", "a, b"),
            ("rotate_by", "2020-01-01"),
        ],
    );
    assert_eq!(created.status, 303, "{}", created.body);
    assert_eq!(created.header("location"), "/e/cloud?done=created");
    let described = server.home.ok(&["describe", "cloud"]);
    assert!(described.contains("keys: TOKEN"), "{described}");
    assert!(
        described.contains("description: Made in the UI"),
        "{described}"
    );
    let list = get(&proxy, "/").body;
    assert!(list.contains(r#"class="overdue""#), "{list}");

    let again = post(
        &proxy,
        "/new",
        &[("name", "cloud"), ("values", "TOKEN=other-value-1")],
    );
    assert_eq!(again.status, 400);
    assert!(again.body.contains("already exists"));
    assert_eq!(
        post(&proxy, "/new", &[("name", "bad name"), ("values", "A=1")]).status,
        400
    );
    let outside = post(&proxy, "/new", &[("name", "github"), ("values", "A=1")]);
    assert_eq!(outside.status, 403);
    assert!(!server.home.ok(&["list"]).contains("github"));

    let wrong = post(&proxy, "/e/cloud/delete", &[("confirm", "clou")]);
    assert_eq!(wrong.status, 400);
    assert!(server.home.ok(&["list"]).contains("cloud"));
    assert_eq!(
        post(&proxy, "/e/app/delete", &[("confirm", "app")]).status,
        403
    );
    let deleted = post(&proxy, "/e/cloud/delete", &[("confirm", "cloud")]);
    assert_eq!(deleted.status, 303);
    assert_eq!(deleted.header("location"), "/?done=deleted");
    assert!(!server.home.ok(&["list"]).contains("cloud"));
    assert!(server.home.ok(&["list"]).contains("app"));
}

/// Reads one HTTP request per connection and answers 200; the raw requests are kept.
fn fake_ntfy() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/topic", listener.local_addr().unwrap());
    let received = Arc::new(Mutex::new(Vec::new()));
    let shared = received.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { break };
            let mut raw = Vec::new();
            let mut byte = [0u8];
            while !raw.ends_with(b"\r\n\r\n") {
                if conn.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                raw.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&raw).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse().unwrap());
            let mut body = vec![0u8; length];
            conn.read_exact(&mut body).unwrap();
            raw.extend(body);
            shared.lock().unwrap().push(text(&raw));
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    (url, received)
}

/// A server whose config also sets `[serve].ntfy`.
fn server_with_ntfy(url: Option<&str>) -> Server {
    let home = Home::local();
    if let Some(url) = url {
        let mut config = fs::read_to_string(home.path("config.toml")).unwrap();
        config.push_str(&format!("\n[serve]\nntfy = {url:?}\n"));
        fs::write(home.path("config.toml"), config).unwrap();
    }
    Server::start(home)
}

fn reveal_lines(server: &Server) -> Vec<serde_json::Value> {
    server
        .home
        .audit()
        .into_iter()
        .filter(|l| l["action"] == "reveal")
        .collect()
}

#[test]
fn reveal_needs_a_reason_audits_it_and_notifies_without_the_value() {
    let (url, received) = fake_ntfy();
    let server = server_with_ntfy(Some(&url));
    let proxy = admin_proxy(&server, r#""*""#);

    for reason in ["", "   ", "a b c", "  ab  "] {
        let reply = post(&proxy, "/e/app/reveal", &[("reason", reason)]);
        assert_eq!(reply.status, 400, "{reason:?}");
        assert_no_value(&reply.body);
    }
    assert!(reveal_lines(&server).is_empty());
    assert!(received.lock().unwrap().is_empty());
    // Nobody reveals what they cannot administer.
    proxy.peer(Some(&admin_of(r#""db*""#)), Some("bob@example.com"));
    assert_eq!(
        post(&proxy, "/e/app/reveal", &[("reason", "looking around")]).status,
        403
    );
    assert_eq!(reveal_lines(&server).len(), 1);
    assert_eq!(reveal_lines(&server)[0]["result"], "denied");
    proxy.peer(Some(&admin_of(r#""*""#)), Some("alice@example.com"));
    proxy.forwarded_host(FORWARDED_HOST);

    let reply = post(
        &proxy,
        "/e/app/reveal",
        &[("reason", "rotating the api key")],
    );
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("cache-control"), "no-store");
    assert!(reply.body.contains(API_TOKEN), "{}", reply.body);
    assert!(reply.body.contains("API_TOKEN"));

    let lines = reveal_lines(&server);
    let line = lines.last().unwrap();
    assert_eq!(line["who"], "alice@example.com");
    assert_eq!(line["via"], "ui");
    assert_eq!(line["entry"], "app");
    assert_eq!(line["result"], "ok");
    assert_eq!(line["reason"], "rotating the api key");
    assert_eq!(line["notify"], "sent");
    let raw = fs::read_to_string(server.home.path("audit.jsonl")).unwrap();
    assert_no_value(&raw);

    let sent = received.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(sent[0].starts_with("POST /topic "), "{}", sent[0]);
    assert!(
        sent[0]
            .to_ascii_lowercase()
            .contains("title: agentsafe reveal")
    );
    assert!(sent[0].ends_with("alice@example.com revealed app: rotating the api key"));
    assert_no_value(&sent[0]);
    assert!(!sent[0].contains("fixture"));
}

#[test]
fn reveal_works_when_ntfy_is_down_or_not_configured() {
    // A port that nothing listens on.
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/topic", listener.local_addr().unwrap())
    };
    for (ntfy, notify) in [(Some(closed.as_str()), Some("failed")), (None, None)] {
        let server = server_with_ntfy(ntfy);
        let proxy = admin_proxy(&server, r#""*""#);
        let reply = post(
            &proxy,
            "/e/other/reveal",
            &[("reason", "checking the value")],
        );
        assert_eq!(reply.status, 200, "{ntfy:?}: {}", reply.body);
        assert!(reply.body.contains(OTHER_VALUE));
        let lines = reveal_lines(&server);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["result"], "ok");
        assert_eq!(lines[0]["reason"], "checking the value");
        assert_eq!(lines[0].get("notify").and_then(|n| n.as_str()), notify);
    }
}

#[test]
fn the_audit_page_is_for_admins_of_everything_and_lists_newest_first() {
    let server = server_with_ntfy(None);
    let proxy = admin_proxy(&server, r#""*""#);
    post(&proxy, "/e/app/reveal", &[("reason", "first reason given")]);
    post(
        &proxy,
        "/e/other/reveal",
        &[("reason", "second reason given")],
    );

    let page = get(&proxy, "/audit");
    assert_eq!(page.status, 200);
    let first = page.body.find("first reason given").unwrap();
    let second = page.body.find("second reason given").unwrap();
    assert!(second < first, "newest first");
    assert!(page.body.contains("alice@example.com"));
    assert_no_value(&page.body);
    assert!(get(&proxy, "/").body.contains(r#"href="/audit""#));

    proxy.peer(Some(&admin_of(r#""db*""#)), Some("bob@example.com"));
    let refused = get(&proxy, "/audit");
    assert_eq!(refused.status, 403);
    assert!(!refused.body.contains("first reason given"));
    assert!(!get(&proxy, "/").body.contains(r#"href="/audit""#));

    // Only the last 200 lines are shown.
    for i in 0..210 {
        server.home.ok_stdin(
            &["set", &format!("bulk{i}"), "--key", "K"],
            "bulk-value-123456\n",
        );
    }
    proxy.peer(Some(&admin_of(r#""*""#)), Some("alice@example.com"));
    let page = get(&proxy, "/audit").body;
    assert_eq!(page.matches("<tr><td>").count(), 200);
    assert!(page.contains("bulk209") && !page.contains("first reason given"));
}
