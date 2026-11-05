//! Sweeps every error path of the CLI and the server for a leaked value.
//!
//! A fixture marker goes into every input a command or a route accepts, malformed on purpose
//! too, and neither it nor its base64 may come back in any stdout, stderr, HTTP answer, server
//! log or audit line. Entry names and key names are not values: the product echoes them.
//! Left out because showing the value is the product's job: the file `render -o` writes, a UI
//! reveal of the marker, and a `reveal` reason, which is audited as written.

#![expect(
    clippy::unwrap_used,
    reason = "a fixture or setup step that fails must panic the test, as unwrap does"
)]

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use tempfile::TempDir;

mod common;
#[path = "common/proxy.rs"]
mod proxy;

use common::{fixtures, local_dir, text};
use proxy::{Proxy, caps, wait_for_socket};

const MARKER: &str = "leakmark-Zq7XcV4n2Pw9";
const ADMIN: &str = r#"{"entries": ["*"], "actions": ["admin"]}"#;

/// The marker and its base64 (standard and URL-safe) at the three alignments it can have inside
/// a larger blob, without the characters its neighbours would change.
fn needles() -> Vec<Vec<u8>> {
    let mut out = vec![MARKER.as_bytes().to_vec()];
    for offset in 0..3usize {
        let mut blob = vec![0u8; offset];
        blob.extend_from_slice(MARKER.as_bytes());
        let partial_tail = usize::from(blob.len() % 3 != 0);
        let from = (offset * 8).div_ceil(6);
        for encoded in [STANDARD_NO_PAD.encode(&blob), URL_SAFE_NO_PAD.encode(&blob)] {
            let stable = &encoded[from..encoded.len() - partial_tail];
            out.push(stable.as_bytes().to_vec());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The identity of the server vault: a config dir with a fixture vault.
struct Lab {
    dir: TempDir,
}

impl Lab {
    fn local() -> Lab {
        let lab = Lab { dir: local_dir() };
        let key = lab.path("key.txt");
        // A server whose ntfy topic is the marker, and which cannot reach it.
        lab.config(
            "ntfy.toml",
            &format!(
                "identity = {:?}\n[serve]\nntfy = \"http://127.0.0.1:1/{MARKER}\"\n",
                key.display()
            ),
        );
        fs::create_dir(lab.path("work")).unwrap();
        lab
    }

    fn remote(addr: &str) -> Lab {
        let lab = Lab {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir(lab.path("work")).unwrap();
        lab.config("config.toml", &format!("server = \"http://{addr}/\"\n"));
        lab
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn config(&self, name: &str, text: &str) {
        fs::write(self.path(name), text).unwrap();
    }

    /// A file of the working directory.
    fn work(&self, name: &str, content: &[u8]) -> String {
        let path = self.path("work").join(name);
        fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn command(&self, config: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentsafe"));
        cmd.args(args)
            .env("AGENTSAFE_CONFIG", self.path(config))
            .env("HOME", self.dir.path())
            .env("USER", "tester")
            .env_remove("XDG_RUNTIME_DIR");
        cmd
    }
}

/// `agentsafe serve` with its stderr in a file.
struct Server {
    child: Child,
    socket: PathBuf,
}

impl Server {
    fn start(lab: &Lab, config: &str) -> Server {
        let socket = lab.path("agentsafe.sock");
        let log = File::create(lab.path("serve.log")).unwrap();
        let child = lab
            .command(config, &["serve", "--socket", socket.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut server = Server { child, socket };
        wait_for_socket(&server.socket, &mut server.child);
        server
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A `Proxy` for a peer with these grants, none when `grants` is `None`.
fn peer_proxy(socket: &Path, grants: Option<&str>) -> Proxy {
    let proxy = Proxy::start(socket);
    proxy.peer(grants.map(caps).as_deref(), Some("alice@example.com"));
    proxy
}

/// What a case must do for its error path to count as reached.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    /// A non-zero exit, or an HTTP 4xx.
    Refused,
    /// A zero exit, or an HTTP 2xx or 3xx.
    Served,
}

impl Outcome {
    fn of_exit(status: ExitStatus) -> Outcome {
        if status.success() {
            Outcome::Served
        } else {
            Outcome::Refused
        }
    }

    fn of_http(status: u16) -> Outcome {
        if status < 400 {
            Outcome::Served
        } else {
            Outcome::Refused
        }
    }
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

struct Sweep {
    needles: Vec<Vec<u8>>,
    problems: Vec<String>,
    cases: usize,
    audit: PathBuf,
    audit_seen: usize,
    log: PathBuf,
    log_seen: usize,
}

impl Sweep {
    fn new(lab: &Lab) -> Sweep {
        Sweep {
            needles: needles(),
            problems: Vec::new(),
            cases: 0,
            audit: lab.path("audit.jsonl"),
            audit_seen: 0,
            log: lab.path("serve.log"),
            log_seen: 0,
        }
    }

    fn look(&mut self, what: &str, channel: &str, bytes: &[u8]) {
        if self.needles.iter().any(|n| contains(bytes, n)) {
            self.problems
                .push(format!("{what}: {channel} holds the marker or its base64"));
        }
    }

    /// The audit lines and server log lines written since the previous case.
    fn logs(&mut self, what: &str) {
        for (path, seen, channel) in [
            (self.audit.clone(), self.audit_seen, "audit line"),
            (self.log.clone(), self.log_seen, "server log"),
        ] {
            let bytes = fs::read(path).unwrap_or_default();
            self.look(what, channel, bytes.get(seen..).unwrap_or_default());
            if channel == "audit line" {
                self.audit_seen = bytes.len();
            } else {
                self.log_seen = bytes.len();
            }
        }
    }

    fn reached(&mut self, what: &str, wanted: Outcome, got: Outcome) {
        if wanted != got {
            self.problems.push(format!(
                "{what}: expected it to be {wanted:?}, so its error path may not be the one swept"
            ));
        }
    }

    fn cli(
        &mut self,
        lab: &Lab,
        config: &str,
        input: &str,
        args: &[&str],
        stdin: &[u8],
        outcome: Outcome,
    ) -> Output {
        self.cases += 1;
        let what = format!("agentsafe {} [{input}]", args.join(" "));
        let mut child = lab
            .command(config, args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The command may fail before it reads stdin.
        let _ = child.stdin.take().unwrap().write_all(stdin);
        let out = child.wait_with_output().unwrap();
        self.reached(&what, outcome, Outcome::of_exit(out.status));
        self.look(&what, "stdout", &out.stdout);
        self.look(&what, "stderr", &out.stderr);
        self.logs(&what);
        out
    }

    /// `cli` on the lab's own config.
    fn local(
        &mut self,
        lab: &Lab,
        input: &str,
        args: &[&str],
        stdin: &[u8],
        outcome: Outcome,
    ) -> Output {
        self.cli(lab, "config.toml", input, args, stdin, outcome)
    }

    /// `route` is `METHOD /path`.
    fn http(
        &mut self,
        proxy: &Proxy,
        route: &str,
        input: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        outcome: Outcome,
    ) -> Reply {
        self.cases += 1;
        let what = format!("{route} [{input}]");
        let (method, path) = route.split_once(' ').unwrap();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .build()
            .into();
        let mut request = ureq::http::Request::builder()
            .method(method)
            .uri(proxy.url(path));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut response = agent.run(request.body(body).unwrap()).unwrap();
        let status = response.status().as_u16();
        let mut sent_headers = String::new();
        for (name, value) in response.headers() {
            writeln!(
                sent_headers,
                "{name}: {}",
                value.to_str().unwrap_or_default()
            )
            .unwrap();
        }
        let body = response.body_mut().read_to_vec().unwrap();
        self.reached(&what, outcome, Outcome::of_http(status));
        self.look(&what, "HTTP headers", sent_headers.as_bytes());
        self.look(&what, "HTTP body", &body);
        self.logs(&what);
        Reply { status, body }
    }
}

const JSON: [(&str, &str); 2] = [("Sec-Agentsafe", "1"), ("Content-Type", "application/json")];
const FORM: [(&str, &str); 2] = [
    ("Sec-Fetch-Site", "same-origin"),
    ("Content-Type", "application/x-www-form-urlencoded"),
];
const META: [&str; 8] = [
    "--description",
    MARKER,
    "--owner",
    MARKER,
    "--used-by",
    MARKER,
    "--tag",
    MARKER,
];

/// Inputs of `set` on stdin that the dotenv parser or the store refuses.
const SET_STDIN: [(&str, &str); 7] = [
    ("line without =", "GOOD=value-1234\n{M}\n"),
    ("unterminated quote", "K=\"{M}\n"),
    ("text after quote", "K=\"{M}\" {M}\n"),
    ("digit key", "9{M}=x\n"),
    ("key with space", "{M} {M}=x\n"),
    ("comments only", "# {M}\n"),
    ("export alone", "export {M}\n"),
];
const IMPORT_FILES: [(&str, &str); 5] = [
    ("line without =", "GOOD=value-1234\nBAD {M}\n"),
    ("unterminated quote", "K=\"{M}\n"),
    ("text after quote", "K='{M}' {M}\n"),
    ("digit key", "9{M}=x\n"),
    ("comments only", "# {M}\n"),
];
/// `(input, template, entry allowed)`
const TEMPLATES: [(&str, &str, &str); 7] = [
    ("unclosed tag", "x {{ {M} ", "held"),
    ("unknown filter", "{{ secrets.held.SECRET | {M} }}", "held"),
    ("undefined key", "{M} {{ secrets.held.{M} }}", "held"),
    ("bad operation", "{{ secrets.held.SECRET + 1 }} {M}", "held"),
    ("bad block", "{% if %}{M}", "held"),
    ("entry not allowed", "{M} {{ secrets.held.SECRET }}", "app"),
    ("no such entry", "{M} {{ secrets.held.SECRET }}", "nothing"),
];
const CONFIGS: [(&str, &str); 11] = [
    (
        "malformed line after ntfy",
        "identity = \"/x\"\n[serve]\nntfy = \"https://ntfy.sh/{M}\"\nsocket = {M}\n",
    ),
    (
        "ntfy of the wrong type",
        "identity = \"/x\"\n[serve]\nntfy = [\"{M}\"]\n",
    ),
    (
        "unquoted ntfy",
        "identity = \"/x\"\n[serve]\nntfy = https://ntfy.sh/{M}\n",
    ),
    ("unknown key", "identity = \"/x\"\nunknown = \"{M}\"\n"),
    (
        "unknown key in [serve]",
        "identity = \"/x\"\n[serve]\nntfy_url = \"{M}\"\n",
    ),
    ("unquoted identity", "identity = {M}\n"),
    ("unterminated string", "identity = \"{M}\n"),
    ("both modes", "identity = \"{M}\"\nserver = \"{M}\"\n"),
    ("empty server", "server = \"\"\n# {M}\n"),
    ("duplicate key", "identity = \"{M}\"\nidentity = \"{M}\"\n"),
    ("not a table", "{M}\n"),
];
/// `(input, entry, status, body)` of `PUT /api/v1/entries/<entry>`.
const PUT_BODIES: [(&str, &str, u16, &str); 13] = [
    ("truncated JSON", "e1", 400, "{\"values\": {\"K\": \"{M}\""),
    (
        "value of the wrong type",
        "e1",
        400,
        "{\"values\": {\"K\": 5, \"J\": \"{M}\"}}",
    ),
    (
        "list as value",
        "e1",
        400,
        "{\"values\": {\"K\": [\"{M}\"]}}",
    ),
    (
        "unknown field",
        "e1",
        400,
        "{\"values\": {\"K\": \"{M}\"}, \"{M}\": \"{M}\"}",
    ),
    (
        "unknown meta field",
        "app",
        400,
        "{\"meta\": {\"{M}\": \"{M}\"}}",
    ),
    (
        "invalid rotate_by",
        "app",
        400,
        "{\"meta\": {\"rotate_by\": \"{M}\"}}",
    ),
    (
        "invalid rotate_by in base64",
        "app",
        400,
        "{\"meta\": {\"rotate_by\": \"{B64}\"}}",
    ),
    (
        "invalid rotate_by with every field",
        "e1",
        400,
        "{\"values\": {\"K\": \"value-1234\"}, \"meta\": {\"rotate_by\": \"{M}\", \"description\": \"{M}\", \
         \"owner\": \"{M}\", \"used_by\": [\"{M}\"], \"tags\": [\"{M}\"]}}",
    ),
    (
        "meta of an absent entry",
        "e1",
        404,
        "{\"meta\": {\"description\": \"{M}\"}}",
    ),
    (
        "no pairs",
        "e1",
        400,
        "{\"values\": {}, \"meta\": {\"description\": \"{M}\"}}",
    ),
    ("not JSON", "e1", 400, "{M}"),
    ("not an object", "e1", 400, "[\"{M}\"]"),
    (
        "null values",
        "e1",
        400,
        "{\"values\": null, \"meta\": null, \"{M}\": 1}",
    ),
];
const FETCH_BODIES: [(&str, &str); 8] = [
    ("truncated JSON", "{\"names\": [\"app\"], \"{M}\""),
    ("names of the wrong type", "{\"names\": 5, \"x\": \"{M}\"}"),
    ("all of the wrong type", "{\"all\": \"{M}\"}"),
    (
        "both selectors",
        "{\"names\": [\"app\"], \"all\": true, \"{M}\": 1}",
    ),
    ("neither selector", "{}"),
    ("unknown field", "{\"{M}\": true}"),
    ("not JSON", "{M}"),
    ("all false", "{\"all\": false}"),
];
type Fields = &'static [(&'static str, &'static str)];
const NEW_FORMS: [(&str, Fields); 9] = [
    (
        "line without =",
        &[("name", "e2"), ("values", "GOOD=value-1234\n{M}\n")],
    ),
    (
        "unterminated quote",
        &[("name", "e2"), ("values", "K=\"{M}")],
    ),
    (
        "text after quote",
        &[("name", "e2"), ("values", "K='{M}' {M}")],
    ),
    ("digit key", &[("name", "e2"), ("values", "9{M}=x")]),
    ("comments only", &[("name", "e2"), ("values", "# {M}")]),
    (
        "invalid rotate_by",
        &[
            ("name", "e2"),
            ("values", "K=value-1234"),
            ("rotate_by", "{M}"),
            ("description", "{M}"),
            ("owner", "{M}"),
            ("used_by", "{M}"),
            ("tags", "{M}"),
        ],
    ),
    ("no name field", &[("values", "K={M}")]),
    ("no values field", &[("name", "e2"), ("description", "{M}")]),
    (
        "unknown field",
        &[("name", "e2"), ("values", "9{M}=x"), ("{M}", "{M}")],
    ),
];
/// `(route, input, fields)` of the forms of one entry.
const ENTRY_FORMS: [(&str, &str, Fields); 9] = [
    (
        "POST /e/app/values",
        "line without =",
        &[("values", "{M}\n")],
    ),
    (
        "POST /e/app/values",
        "no values field",
        &[("description", "{M}")],
    ),
    (
        "POST /e/nothing/values",
        "no such entry",
        &[("values", "K={M}")],
    ),
    (
        "POST /e/app/meta",
        "invalid rotate_by",
        &[
            ("rotate_by", "{M}"),
            ("description", "{M}"),
            ("owner", "{M}"),
            ("used_by", "{M}\n{M}"),
        ],
    ),
    (
        "POST /e/nothing/meta",
        "no such entry",
        &[("description", "{M}")],
    ),
    ("POST /e/app/reveal", "short reason", &[("reason", "a")]),
    ("POST /e/app/reveal", "no reason field", &[("{M}", "{M}")]),
    (
        "POST /e/app/delete",
        "wrong confirmation",
        &[("confirm", "{M}")],
    ),
    ("POST /e/app/delete", "no confirm field", &[("{M}", "{M}")]),
];

/// The text with the marker, and its base64 where `{B64}` stands.
fn m(template: &str) -> String {
    template
        .replace("{M}", MARKER)
        .replace("{B64}", &STANDARD.encode(MARKER))
}

/// An urlencoded form body, the marker substituted in the fields.
fn form(fields: &[(&str, &str)]) -> Vec<u8> {
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", percent(&m(k)), percent(&m(v))))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

fn percent(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            out.push(char::from(byte));
        } else {
            write!(out, "%{byte:02X}").unwrap();
        }
    }
    out
}

fn with_byte(text: &str, byte: u8) -> Vec<u8> {
    let mut bytes = m(text).into_bytes();
    bytes.push(byte);
    bytes
}

#[test]
fn no_error_path_leaks_a_value() {
    let lab = Lab::local();
    let mut sweep = Sweep::new(&lab);
    cli_store_cases(&lab, &mut sweep);
    cli_file_cases(&lab, &mut sweep);
    cli_output_cases(&lab, &mut sweep);
    config_cases(&lab, &mut sweep);

    let server = Server::start(&lab, "ntfy.toml");
    let admin = peer_proxy(&server.socket, Some(ADMIN));
    api_cases(&mut sweep, &admin);
    ui_cases(&mut sweep, &admin);
    let nobody = peer_proxy(&server.socket, None);
    let reader = peer_proxy(
        &server.socket,
        Some(r#"{"entries": ["app"], "actions": ["get"]}"#),
    );
    refusal_cases(&mut sweep, [&nobody, &reader]);
    remote_cases(&mut sweep, &admin);

    assert!(
        sweep.cases > 100,
        "only {} cases ran: the sweep shrank",
        sweep.cases
    );
    assert!(
        sweep.problems.is_empty(),
        "{} problems in {} cases:\n{}",
        sweep.problems.len(),
        sweep.cases,
        sweep.problems.join("\n")
    );
}

/// `set`, `edit` and `import`: stdin, every metadata flag, and an invalid date.
fn cli_store_cases(lab: &Lab, sweep: &mut Sweep) {
    use Outcome::{Refused, Served};
    for name in ["app", "db"] {
        let file = fixtures().join(format!("{name}.env"));
        let args = ["import", file.to_str().unwrap(), "--name", name];
        sweep.local(lab, "fixture", &args, b"", Served);
    }
    // The marker is stored as a value, so a path that dumps the vault shows it.
    let stored = m("{M}\n");
    let held = ["set", "held", "--key", "SECRET"];
    sweep.local(lab, "stdin value", &held, stored.as_bytes(), Served);
    sweep.local(lab, "stored", &["list"], b"", Served);
    sweep.local(lab, "stored", &["describe", "held"], b"", Served);

    let binary = with_byte("{M} ", 0xff);
    sweep.local(
        lab,
        "stdin not UTF-8",
        &["set", "e1", "--key", "K"],
        &binary,
        Refused,
    );
    for (input, stdin) in SET_STDIN {
        sweep.local(lab, input, &["set", "e1"], m(stdin).as_bytes(), Refused);
    }
    let valid = lab.work("valid.env", b"GOOD=value-1234\n");
    for rotate_by in [m("{M}"), m("2026-99-99-{M}"), m("{B64}")] {
        let flags = [&["--rotate-by", rotate_by.as_str()][..], &META].concat();
        let set = [&["set", "e1", "--key", "K"][..], &flags].concat();
        sweep.local(lab, "invalid --rotate-by", &set, stored.as_bytes(), Refused);
        let edit = [&["edit", "app"][..], &flags].concat();
        sweep.local(lab, "invalid --rotate-by", &edit, b"", Refused);
        let import = [&["import", valid.as_str(), "--name", "e1"][..], &flags].concat();
        sweep.local(lab, "invalid --rotate-by", &import, b"", Refused);
    }
    let edit = [&["edit", "nothing"][..], &META].concat();
    sweep.local(lab, "flags, no such entry", &edit, b"", Refused);
    let set = [&["set", "bad name", "--key", "K"][..], &META].concat();
    sweep.local(lab, "flags, invalid name", &set, stored.as_bytes(), Refused);
    sweep.local(lab, "no flag", &["edit", "app"], b"", Refused);
}

/// `import`, `render` and `verify-import`: the files they read.
fn cli_file_cases(lab: &Lab, sweep: &mut Sweep) {
    use Outcome::{Refused, Served};
    let binary = with_byte("K={M}", 0xff);
    let file = lab.work("bad.env", &binary);
    sweep.local(
        lab,
        "not UTF-8",
        &["import", &file, "--name", "e1"],
        b"",
        Refused,
    );
    for (input, content) in IMPORT_FILES {
        let file = lab.work("bad.env", m(content).as_bytes());
        sweep.local(lab, input, &["import", &file, "--name", "e1"], b"", Refused);
    }

    let out = lab.path("work").join("rendered.txt");
    let out = out.to_str().unwrap();
    for (input, template, allow) in TEMPLATES {
        let file = lab.work("t.tmpl", m(template).as_bytes());
        let args = ["render", &file, "--allow", allow, "-o", out];
        sweep.local(lab, input, &args, b"", Refused);
        if Path::new(out).exists() {
            let problem = format!("render [{input}]: wrote its output file on a failure");
            sweep.problems.push(problem);
        }
    }
    let file = lab.work("t.tmpl", &with_byte("{M}", 0xff));
    let args = ["render", &file, "--allow", "held", "-o", out];
    sweep.local(lab, "template not UTF-8", &args, b"", Refused);
    let args = [
        "render",
        &file,
        "--allow",
        "held",
        "-o",
        "/nonexistent-dir/out",
    ];
    sweep.local(lab, "output directory missing", &args, b"", Refused);

    // Where the product shows the value on purpose: the file it writes.
    let file = lab.work("t.tmpl", b"{{ secrets.held.SECRET }}");
    let args = ["render", &file, "--allow", "held", "-o", out];
    sweep.local(lab, "template of the value", &args, b"", Served);
    if fs::read_to_string(out).unwrap() != MARKER {
        sweep
            .problems
            .push("render -o: the file does not hold the value".into());
    }

    let src = lab.path("work").join("verify");
    fs::create_dir(&src).unwrap();
    let imported = src.join("a.env");
    fs::write(&imported, "K=value-1234\n").unwrap();
    let args = ["import", imported.to_str().unwrap(), "--name", "verify"];
    sweep.local(lab, "fixture", &args, b"", Served);
    fs::write(&imported, m("K={M}\n")).unwrap();
    fs::write(src.join("b.env"), m("K={M}\n")).unwrap();
    let args = ["verify-import", src.to_str().unwrap()];
    sweep.local(lab, "changed and unknown files", &args, b"", Refused);
    sweep.local(
        lab,
        "no such directory",
        &["verify-import", "/nonexistent-dir"],
        b"",
        Refused,
    );
    sweep.local(lab, "no such entry", &["describe", "nothing"], b"", Refused);
    sweep.local(lab, "no such entry", &["rm", "nothing"], b"", Refused);
}

/// `run` and `scrub`, which show the value masked.
fn cli_output_cases(lab: &Lab, sweep: &mut Sweep) {
    use Outcome::{Refused, Served};
    let script = r#"echo "$SECRET"; echo "$SECRET" >&2; printf %s "$SECRET" | base64; exit 3"#;
    let args = ["run", "--env", "held", "--", "sh", "-c", script];
    let out = sweep.local(lab, "child prints the value", &args, b"", Refused);
    if out.status.code() != Some(3) {
        sweep
            .problems
            .push("run [child prints the value]: not the child's exit code".into());
    }
    let arg = m("{M}");
    let args = ["run", "--env", "held", "--", "./no-such-command", &arg];
    sweep.local(lab, "no such command", &args, b"", Refused);
    let args = ["run", "--env", "held:NOPE", "--", "true"];
    sweep.local(lab, "no such key", &args, b"", Refused);
    let blob = m("before {M} after {B64}");
    let out = sweep.local(
        lab,
        "stdin holds the value",
        &["scrub"],
        blob.as_bytes(),
        Served,
    );
    if out.stdout != b"before ***held*** after ***held***" {
        sweep
            .problems
            .push("scrub: the value is not masked as expected".into());
    }
}

fn config_cases(lab: &Lab, sweep: &mut Sweep) {
    use Outcome::Refused;
    let key = lab.path("key.txt");
    for (i, (input, text)) in CONFIGS.into_iter().enumerate() {
        let name = format!("bad{i}.toml");
        lab.config(&name, &m(text));
        sweep.cli(lab, &name, input, &["list"], b"", Refused);
        let serve = ["serve", "--socket", "/nonexistent-dir/s.sock"];
        sweep.cli(lab, &name, input, &serve, b"", Refused);
    }
    let recipients = format!(
        "identity = {:?}\nrecipients = [\"{MARKER}\"]\n",
        key.display()
    );
    lab.config("recipients.toml", &recipients);
    let args = ["set", "e1", "--key", "K"];
    sweep.cli(
        lab,
        "recipients.toml",
        "invalid recipient",
        &args,
        b"value-1234\n",
        Refused,
    );

    // An identity file that is not one, and holds the marker.
    let garbage = lab.path("garbage.key");
    fs::write(&garbage, m("# {M}\nAGE-SECRET-KEY-{M}\n{M}\n")).unwrap();
    lab.config(
        "garbage.toml",
        &format!("identity = {:?}\n", garbage.display()),
    );
    for args in [
        &["scrub"][..],
        &["run", "--env", "app", "--", "true"],
        &["set", "e1", "--key", "K"],
    ] {
        sweep.cli(
            lab,
            "garbage.toml",
            "identity file",
            args,
            b"value-1234\n",
            Refused,
        );
    }
}

fn api_cases(sweep: &mut Sweep, proxy: &Proxy) {
    use Outcome::Refused;
    for (input, entry, status, body) in PUT_BODIES {
        let route = format!("PUT /api/v1/entries/{entry}");
        let reply = sweep.http(proxy, &route, input, &JSON, m(body).as_bytes(), Refused);
        if reply.status != status {
            let got = reply.status;
            sweep
                .problems
                .push(format!("{route} [{input}]: answered {got}, not {status}"));
        }
    }
    let binary = with_byte(r#"{"values": {"K": "{M}"#, 0xff);
    sweep.http(
        proxy,
        "PUT /api/v1/entries/e1",
        "not UTF-8",
        &JSON,
        &binary,
        Refused,
    );
    let big = m(&format!(
        "{{\"values\": {{\"K\": \"{{M}}{}{{M}}\"}}}}",
        "x".repeat(70 * 1024)
    ));
    let reply = sweep.http(
        proxy,
        "PUT /api/v1/entries/e1",
        "over the body limit",
        &JSON,
        big.as_bytes(),
        Refused,
    );
    if reply.status != 413 {
        sweep
            .problems
            .push("PUT /api/v1/entries/e1 [over the body limit]: not a 413".into());
    }
    api_other_cases(sweep, proxy);
}

fn api_other_cases(sweep: &mut Sweep, proxy: &Proxy) {
    use Outcome::{Refused, Served};
    for (input, body) in FETCH_BODIES {
        sweep.http(
            proxy,
            "POST /api/v1/fetch",
            input,
            &JSON,
            m(body).as_bytes(),
            Refused,
        );
    }

    let query = m("?x={M}&y=");
    for route in [
        "GET /api/v1/entries",
        "GET /api/v1/entries/app",
        "GET /api/v1/entries/held",
    ] {
        sweep.http(
            proxy,
            &format!("{route}{query}"),
            "query string",
            &JSON,
            b"",
            Served,
        );
    }
    sweep.http(
        proxy,
        &format!("GET /api/v1/entries/e1{query}"),
        "query string, no entry",
        &JSON,
        b"",
        Refused,
    );
    let body = m("{M}");
    for route in [
        "POST /api/v1/entries",
        "PATCH /api/v1/entries/e1",
        "GET /api/v1/fetch",
        "POST /api/v1/nothing",
    ] {
        sweep.http(
            proxy,
            route,
            "unsupported method or route",
            &JSON,
            body.as_bytes(),
            Refused,
        );
    }
    let put = m(r#"{"values": {"K": "{M}"}}"#);
    let no_csrf = [("Content-Type", "application/json")];
    sweep.http(
        proxy,
        "PUT /api/v1/entries/e1",
        "no Sec-Agentsafe header",
        &no_csrf,
        put.as_bytes(),
        Refused,
    );
    let csrf_off = [("Sec-Agentsafe", "0")];
    sweep.http(
        proxy,
        "POST /api/v1/fetch",
        "Sec-Agentsafe: 0",
        &csrf_off,
        put.as_bytes(),
        Refused,
    );
    sweep.http(
        proxy,
        "DELETE /api/v1/entries/nothing",
        "body",
        &JSON,
        put.as_bytes(),
        Refused,
    );
}

fn ui_cases(sweep: &mut Sweep, proxy: &Proxy) {
    use Outcome::Refused;
    for (input, fields) in NEW_FORMS {
        sweep.http(proxy, "POST /new", input, &FORM, &form(fields), Refused);
    }
    for (route, input, fields) in ENTRY_FORMS {
        sweep.http(proxy, route, input, &FORM, &form(fields), Refused);
    }
    // Bodies a form parser rejects, or the server limits.
    let mut binary = b"name=e2&values=9".to_vec();
    binary.extend_from_slice(m("{M}%FF").as_bytes());
    sweep.http(
        proxy,
        "POST /new",
        "percent-encoded bytes, not UTF-8",
        &FORM,
        &binary,
        Refused,
    );
    let bad = m("name=e2&values=%ZZ{M}%");
    sweep.http(
        proxy,
        "POST /new",
        "bad percent-encoding",
        &FORM,
        bad.as_bytes(),
        Refused,
    );
    let json_form = [
        ("Sec-Fetch-Site", "same-origin"),
        ("Content-Type", "application/json"),
    ];
    let body = m(r#"{"name": "e2", "values": "K={M}"}"#);
    sweep.http(
        proxy,
        "POST /new",
        "JSON as a form",
        &json_form,
        body.as_bytes(),
        Refused,
    );
    let no_type = [("Sec-Fetch-Site", "same-origin")];
    let body = m("name=e2&values=K%3D{M}");
    sweep.http(
        proxy,
        "POST /new",
        "no content type",
        &no_type,
        body.as_bytes(),
        Refused,
    );
    let values = format!("K={{M}}{}{{M}}", "x".repeat(70 * 1024));
    let big = form(&[("name", "e2"), ("values", &values)]);
    sweep.http(
        proxy,
        "POST /new",
        "over the body limit",
        &FORM,
        &big,
        Refused,
    );
    let type_only = [("Content-Type", "application/x-www-form-urlencoded")];
    let body = form(&[("values", "K={M}")]);
    sweep.http(
        proxy,
        "POST /e/app/values",
        "cross-origin",
        &type_only,
        &body,
        Refused,
    );
    let cross = [
        ("Sec-Fetch-Site", "cross-site"),
        ("Content-Type", "application/x-www-form-urlencoded"),
    ];
    let body = form(&[("reason", "{M} {M}")]);
    sweep.http(
        proxy,
        "POST /e/app/reveal",
        "cross-site",
        &cross,
        &body,
        Refused,
    );

    ui_page_cases(sweep, proxy);
}

fn ui_page_cases(sweep: &mut Sweep, proxy: &Proxy) {
    use Outcome::{Refused, Served};
    // Pages that render what the vault and the log hold.
    let query = m("?done={M}&x={M}");
    for route in ["/", "/new", "/e/app", "/e/held", "/audit"] {
        sweep.http(
            proxy,
            &format!("GET {route}{query}"),
            "query string",
            &[],
            b"",
            Served,
        );
    }
    sweep.http(
        proxy,
        &format!("GET /e/app/nothing{query}"),
        "query string",
        &[],
        b"",
        Refused,
    );
    // A reveal whose notification fails: the ntfy topic holds the marker.
    let reveal = form(&[("reason", "checking the leak sweep")]);
    let reply = sweep.http(
        proxy,
        "POST /e/app/reveal",
        "ntfy topic holds the marker",
        &FORM,
        &reveal,
        Served,
    );
    if !text(&reply.body).contains("fixture-token-0123456789abcdef") {
        sweep
            .problems
            .push("POST /e/app/reveal: the reveal did not show the value".into());
    }
    sweep.http(proxy, "GET /audit", "after the reveal", &[], b"", Served);
}

/// Callers who may not do what they ask, with the marker in what they send.
fn refusal_cases(sweep: &mut Sweep, proxies: [&Proxy; 2]) {
    use Outcome::Refused;
    let put = m(r#"{"values": {"K": "{M}"}, "meta": {"description": "{M}"}}"#);
    let fetch = m(r#"{"names": ["app", "db"], "{M}": 1}"#);
    let new = form(&[("name", "e3"), ("values", "K={M}")]);
    let values = form(&[("values", "K={M}")]);
    let reveal = form(&[("reason", "{M} {M}")]);
    for (who, proxy) in ["no grant", "get only"].into_iter().zip(proxies) {
        sweep.http(
            proxy,
            "PUT /api/v1/entries/app",
            who,
            &JSON,
            put.as_bytes(),
            Refused,
        );
        sweep.http(
            proxy,
            "POST /api/v1/fetch",
            who,
            &JSON,
            fetch.as_bytes(),
            Refused,
        );
        sweep.http(proxy, "POST /new", who, &FORM, &new, Refused);
        sweep.http(proxy, "POST /e/app/values", who, &FORM, &values, Refused);
        sweep.http(proxy, "POST /e/app/reveal", who, &FORM, &reveal, Refused);
    }
}

/// The CLI in remote mode, where the server's answers reach the client's stderr.
fn remote_cases(sweep: &mut Sweep, admin: &Proxy) {
    use Outcome::{Refused, Served};
    let client = Lab::remote(&admin.addr);
    let stored = m("{M}\n");
    for rotate_by in [m("{M}"), m("2026-99-99-{M}")] {
        let flags = ["--rotate-by", rotate_by.as_str(), "--description", MARKER];
        let set = [&["set", "e4", "--key", "K"][..], &flags].concat();
        sweep.cli(
            &client,
            "config.toml",
            "invalid --rotate-by",
            &set,
            stored.as_bytes(),
            Refused,
        );
        let edit = [&["edit", "app"][..], &flags].concat();
        sweep.cli(
            &client,
            "config.toml",
            "invalid --rotate-by",
            &edit,
            b"",
            Refused,
        );
    }
    let mut run = |input: &str, args: &[&str], stdin: &[u8], outcome| {
        sweep.cli(&client, "config.toml", input, args, stdin, outcome)
    };
    run(
        "line without =",
        &["set", "e4"],
        m("GOOD=value-1234\n{M}\n").as_bytes(),
        Refused,
    );
    run(
        "no such entry",
        &["edit", "nothing", "--description", MARKER],
        b"",
        Refused,
    );
    let file = client.work("bad.env", m("K=\"{M}\n").as_bytes());
    run(
        "unterminated quote",
        &["import", &file, "--name", "e4"],
        b"",
        Refused,
    );
    let script = r#"echo "$SECRET"; echo "$SECRET" >&2; exit 4"#;
    run(
        "child prints the value",
        &["run", "--env", "held", "--", "sh", "-c", script],
        b"",
        Refused,
    );
    run(
        "stdin holds the value",
        &["scrub"],
        stored.as_bytes(),
        Served,
    );
    let template = client.work("t.tmpl", m("{{ secrets.held.SECRET | {M} }}").as_bytes());
    let out = client.path("rendered.txt");
    let args = [
        "render",
        &template,
        "--allow",
        "held",
        "-o",
        out.to_str().unwrap(),
    ];
    run("unknown filter", &args, b"", Refused);
}
