use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Barrier;
use std::thread;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
use secrecy::ExposeSecret;
use tempfile::TempDir;

const API_TOKEN: &str = "fixture-token-0123456789abcdef";
const DB_PASSWORD: &str = "fx-pa\"ss:word/with+chars";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/env")
}

struct Home {
    dir: TempDir,
    /// Config path when it is not `<dir>/config.toml`.
    config: Option<PathBuf>,
}

impl Home {
    fn new() -> Home {
        let dir = tempfile::tempdir().unwrap();
        let identity = age::x25519::Identity::generate();
        let key = dir.path().join("key.txt");
        fs::write(
            &key,
            format!(
                "# test identity\n{}\n",
                identity.to_string().expose_secret()
            ),
        )
        .unwrap();
        fs::write(
            dir.path().join("config.toml"),
            format!("identity = {:?}\n", key.to_str().unwrap()),
        )
        .unwrap();
        Home { dir, config: None }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentsafe"));
        cmd.args(args)
            .env(
                "AGENTSAFE_CONFIG",
                self.config
                    .clone()
                    .unwrap_or_else(|| self.dir.path().join("config.toml")),
            )
            .env("USER", "tester");
        cmd
    }

    fn agentsafe(&self, args: &[&str]) -> Output {
        self.cmd(args).stdin(Stdio::null()).output().unwrap()
    }

    fn agentsafe_stdin(&self, args: &[&str], stdin: &str) -> Output {
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

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn audit_lines(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(self.path("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn import_fixtures(&self) {
        for name in ["app", "db"] {
            let file = fixtures().join(format!("{name}.env"));
            let out = self.agentsafe(&["import", file.to_str().unwrap(), "--name", name]);
            assert!(out.status.success(), "{}", text(&out.stderr));
        }
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn run_masks_plain_and_base64_output() {
    let home = Home::new();
    home.import_fixtures();
    let out = home.agentsafe(&[
        "run",
        "--env",
        "app:API_TOKEN=VAR",
        "--",
        "sh",
        "-c",
        "echo $VAR; printf %s \"$VAR\" | base64",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(!stdout.contains(API_TOKEN), "{stdout}");
    assert!(!stdout.contains(&STANDARD.encode(API_TOKEN)), "{stdout}");
    assert!(
        !stdout.contains(&STANDARD_NO_PAD.encode(&API_TOKEN[..21])),
        "{stdout}"
    );
    assert_eq!(stdout.matches("***app***").count(), 2, "{stdout}");
}

#[test]
fn run_masks_stderr_and_keeps_the_exit_code() {
    let home = Home::new();
    home.import_fixtures();
    let out = home.agentsafe(&[
        "run",
        "--env",
        "db",
        "--",
        "sh",
        "-c",
        "echo \"$DB_PASSWORD\" >&2; exit 7",
    ]);
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(text(&out.stderr), "***db***\n");
}

#[test]
fn verify_import_reports_ok_for_fixtures() {
    let home = Home::new();
    home.import_fixtures();
    let out = home.agentsafe(&["verify-import", fixtures().to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stdout));
    assert_eq!(text(&out.stdout), "app.env\tapp\tOK\ndb.env\tdb\tOK\n");
}

#[test]
fn verify_import_reports_mismatch_and_unknown_files() {
    let home = Home::new();
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("app.env");
    fs::copy(fixtures().join("app.env"), &file).unwrap();
    let out = home.agentsafe(&["import", file.to_str().unwrap(), "--name", "app"]);
    assert!(out.status.success());
    fs::write(&file, "API_TOKEN=changed-value\n").unwrap();
    fs::write(src.path().join("other.env"), "X=1\n").unwrap();
    let out = home.agentsafe(&["verify-import", src.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stdout),
        "app.env\tapp\tMISMATCH\nother.env\t-\tNOT IMPORTED\n"
    );
}

#[test]
fn set_list_and_describe_never_show_values() {
    let home = Home::new();
    let value = "sk-fixture-set-value-42";
    let out = home.agentsafe_stdin(
        &[
            "set",
            "cloud",
            "--key",
            "TOKEN",
            "--description",
            "Fixture API token",
            "--owner",
            "ops",
            "--used-by",
            "svc1",
            "--rotate-by",
            "2027-01-31",
            "--tag",
            "api",
        ],
        &format!("{value}\n"),
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = home.agentsafe(&["list"]);
    let describe = home.agentsafe(&["describe", "cloud"]);
    for out in [&list, &describe] {
        assert!(out.status.success());
        assert!(!text(&out.stdout).contains(value));
    }
    assert!(text(&list.stdout).contains("cloud\t1\tops\t2027-01-31\tapi\tFixture API token"));
    assert!(text(&describe.stdout).contains("keys: TOKEN\n"));

    for file in ["vault.age", "catalog.toml"] {
        let path = home.dir.path().join(file);
        assert!(!text(&fs::read(&path).unwrap()).contains(value));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let run = home.agentsafe(&["run", "--env", "cloud", "--", "sh", "-c", "echo $TOKEN"]);
    assert_eq!(text(&run.stdout), "***cloud***\n");
}

#[test]
fn describe_flags_values_too_short_to_mask() {
    let home = Home::new();
    home.import_fixtures();
    let out = home.agentsafe(&["describe", "app"]);
    assert!(text(&out.stdout).contains("unmasked: PIN (under 6 bytes)"));
}

#[test]
fn render_writes_only_to_a_regular_file() {
    let home = Home::new();
    home.import_fixtures();
    let template = home.dir.path().join("t.j2");
    fs::write(&template, "token={{ secrets.app.API_TOKEN }}\n").unwrap();
    let target = home.dir.path().join("out.conf");
    let status = home
        .cmd(&["render", template.to_str().unwrap(), "--allow", "app"])
        .stdout(File::create(&target).unwrap())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        format!("token={API_TOKEN}\n")
    );
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let piped = home.agentsafe(&["render", template.to_str().unwrap(), "--allow", "app"]);
    assert!(!piped.status.success());
    assert!(piped.stdout.is_empty());

    let target = home.dir.path().join("denied.conf");
    let status = home
        .cmd(&["render", template.to_str().unwrap(), "--allow", "db"])
        .stdout(File::create(&target).unwrap())
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(!fs::read_to_string(&target).unwrap().contains(API_TOKEN));
}

#[test]
fn scrub_masks_every_known_value() {
    let home = Home::new();
    home.import_fixtures();
    let input = format!("a {API_TOKEN} b {DB_PASSWORD} c\n");
    let out = home.agentsafe_stdin(&["scrub"], &input);
    assert_eq!(text(&out.stdout), "a ***app*** b ***db*** c\n");
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn cli(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentsafe"))
        .args(args)
        .env("AGENTSAFE_CONFIG", config)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn init_creates_a_working_local_setup_without_printing_the_secret_key() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("nested/agentsafe/config.toml");
    let out = cli(&config, &["init"]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let stdout = text(&out.stdout);
    let identity = config.with_file_name("identity.txt");
    assert!(stdout.contains(config.to_str().unwrap()), "{stdout}");
    assert!(stdout.contains(identity.to_str().unwrap()), "{stdout}");
    assert!(stdout.contains("age1"), "{stdout}");
    assert!(!stdout.contains("AGE-SECRET-KEY"), "{stdout}");
    assert!(!text(&out.stderr).contains("AGE-SECRET-KEY"));

    assert_eq!(mode(config.parent().unwrap()), 0o700);
    assert_eq!(mode(&identity), 0o600);
    assert!(
        fs::read_to_string(&identity)
            .unwrap()
            .contains("AGE-SECRET-KEY-")
    );

    let home = Home {
        dir: tmp,
        config: Some(config),
    };
    let out = home.agentsafe_stdin(&["set", "cloud", "--key", "TOKEN"], "sk-init-value-123\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = home.agentsafe(&["list"]);
    assert!(
        text(&list.stdout).contains("cloud\t1\t"),
        "{}",
        text(&list.stdout)
    );
    let run = home.agentsafe(&["run", "--env", "cloud", "--", "sh", "-c", "echo $TOKEN"]);
    assert_eq!(text(&run.stdout), "***cloud***\n");
}

#[test]
fn init_twice_refuses_and_leaves_the_files_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("config.toml");
    let identity = tmp.path().join("identity.txt");
    assert!(cli(&config, &["init"]).status.success());
    let before = (fs::read(&config).unwrap(), fs::read(&identity).unwrap());

    let out = cli(&config, &["init"]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("already exists"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(
        before,
        (fs::read(&config).unwrap(), fs::read(&identity).unwrap())
    );

    // An existing identity alone blocks init too, and no config is written next to it.
    fs::remove_file(&config).unwrap();
    let out = cli(&config, &["init"]);
    assert!(!out.status.success());
    assert!(!config.exists());
    assert_eq!(before.1, fs::read(&identity).unwrap());
}

#[test]
fn init_server_writes_a_remote_config_and_every_command_then_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("config.toml");
    let out = cli(
        &config,
        &["init", "--server", "http://agentsafe.example:8443"],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        "server = \"http://agentsafe.example:8443\"\n"
    );
    assert!(!tmp.path().join("identity.txt").exists());

    for args in [
        &["list"][..],
        &["describe", "x"],
        &["rm", "x"],
        &["edit", "x", "--owner", "o"],
        &["scrub"],
        &["run", "--env", "x", "--", "true"],
    ] {
        let out = cli(&config, args);
        assert!(!out.status.success(), "{args:?}");
        assert!(
            text(&out.stderr).contains("remote mode is not available yet"),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
}

#[test]
fn config_needs_exactly_one_of_identity_and_server() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("config.toml");
    for body in [
        "recipients = []\n",
        "identity = \"/nowhere/key.txt\"\nserver = \"http://x\"\n",
    ] {
        fs::write(&config, body).unwrap();
        let out = cli(&config, &["list"]);
        assert!(!out.status.success(), "{body}");
        let err = text(&out.stderr);
        assert!(err.contains(config.to_str().unwrap()), "{err}");
        assert!(err.contains("invalid config"), "{err}");
    }
}

#[test]
fn serve_table_is_accepted() {
    let home = Home::new();
    let mut config = fs::read_to_string(home.path("config.toml")).unwrap();
    config.push_str(
        "[serve]\nsocket = \"/tmp/agentsafe.sock\"\nntfy = \"https://ntfy.example/topic\"\n",
    );
    fs::write(home.path("config.toml"), config).unwrap();
    assert!(home.agentsafe(&["list"]).status.success());
}

#[test]
fn edit_changes_metadata_and_leaves_values_alone() {
    let home = Home::new();
    home.import_fixtures();
    let sees_token = |home: &Home| {
        let script = format!("test \"$API_TOKEN\" = {API_TOKEN} && echo same");
        text(
            &home
                .agentsafe(&["run", "--env", "app", "--", "sh", "-c", &script])
                .stdout,
        )
    };
    assert_eq!(sees_token(&home), "same\n");

    let out = home.agentsafe(&[
        "edit",
        "app",
        "--description",
        "Edited",
        "--owner",
        "ops",
        "--used-by",
        "svc1",
        "--used-by",
        "svc2",
        "--rotate-by",
        "2027-02-01",
        "--tag",
        "a",
        "--tag",
        "b",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(sees_token(&home), "same\n");
    let describe = text(&home.agentsafe(&["describe", "app"]).stdout);
    for line in [
        "description: Edited\n",
        "keys: API_TOKEN, API_URL, GREETING, PIN\n",
        "used_by: svc1, svc2\n",
        "owner: ops\n",
        "rotate_by: 2027-02-01\n",
        "tags: a, b\n",
    ] {
        assert!(describe.contains(line), "{line:?} not in {describe}");
    }
    // The import source survives an edit, and verify-import still matches.
    assert!(describe.contains("source: "), "{describe}");
    assert!(
        home.agentsafe(&["verify-import", fixtures().to_str().unwrap()])
            .status
            .success()
    );

    // An absent flag leaves its field alone; an empty value clears it.
    let out = home.agentsafe(&["edit", "app", "--tag", ""]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = text(&home.agentsafe(&["list"]).stdout);
    assert!(
        list.contains("app\t4\tops\t2027-02-01\t-\tEdited"),
        "{list}"
    );
    let out = home.agentsafe(&[
        "edit",
        "app",
        "--rotate-by",
        "",
        "--description",
        "",
        "--owner",
        "",
        "--used-by",
        "",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let describe = text(&home.agentsafe(&["describe", "app"]).stdout);
    for label in ["description:", "used_by:", "owner:", "rotate_by:", "tags:"] {
        assert!(!describe.contains(label), "{label} in {describe}");
    }
    assert_eq!(sees_token(&home), "same\n");
}

#[test]
fn edit_rejects_unknown_entries_missing_flags_and_bad_dates() {
    let home = Home::new();
    home.import_fixtures();
    let out = home.agentsafe(&["edit", "nope", "--owner", "ops"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("no entry named nope"));
    assert!(!text(&home.agentsafe(&["list"]).stdout).contains("nope"));

    let out = home.agentsafe(&["edit", "app"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("nothing to change"));

    let out = home.agentsafe(&["edit", "app", "--rotate-by", "tomorrow"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("YYYY-MM-DD"));
}

#[test]
fn rm_deletes_an_entry_and_rejects_unknown_ones() {
    let home = Home::new();
    home.import_fixtures();
    let out = home.agentsafe(&["rm", "app"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let list = text(&home.agentsafe(&["list"]).stdout);
    assert!(!list.contains("app\t"), "{list}");
    assert!(list.contains("db\t"), "{list}");
    let run = home.agentsafe(&["run", "--env", "app", "--", "true"]);
    assert!(!run.status.success());
    // Its values are gone from the masker too.
    let scrub = home.agentsafe_stdin(&["scrub"], &format!("{API_TOKEN}\n"));
    assert_eq!(text(&scrub.stdout), format!("{API_TOKEN}\n"));

    let out = home.agentsafe(&["rm", "app"]);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("no entry named app"));
}

#[test]
fn import_replaces_import_env() {
    let home = Home::new();
    let file = fixtures().join("db.env");
    let out = home.agentsafe(&["import-env", file.to_str().unwrap(), "--name", "db"]);
    assert!(!out.status.success());
    let out = home.agentsafe(&["import", file.to_str().unwrap(), "--name", "db"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&home.agentsafe(&["list"]).stdout).contains("db\t3\t"));
}

#[test]
fn render_reads_the_secrets_namespace() {
    let home = Home::new();
    home.import_fixtures();
    let render = |template: &str| {
        let path = home.path("t.j2");
        fs::write(&path, template).unwrap();
        let target = home.path("out.conf");
        let status = home
            .cmd(&["render", path.to_str().unwrap(), "--allow", "app"])
            .stdout(File::create(&target).unwrap())
            .status()
            .unwrap();
        (status.success(), fs::read_to_string(&target).unwrap())
    };
    let (ok, out) = render("t={{ secrets[\"app\"].API_TOKEN }}\n");
    assert!(ok);
    assert_eq!(out, format!("t={API_TOKEN}\n"));
    // An entry that is not allowed is undefined.
    assert!(!render("t={{ secrets.db.DB_USER }}\n").0);
}

#[test]
fn audit_log_records_every_operation_and_never_a_value() {
    let home = Home::new();
    let set_value = "sk-audit-set-value-77";
    home.import_fixtures();
    assert!(
        home.agentsafe_stdin(
            &["set", "cloud", "--key", "TOKEN"],
            &format!("{set_value}\n")
        )
        .status
        .success()
    );
    let template = home.path("t.j2");
    fs::write(
        &template,
        "{{ secrets.app.API_TOKEN }}{{ secrets.app.PIN }}\n",
    )
    .unwrap();
    let rendered = home
        .cmd(&["render", template.to_str().unwrap(), "--allow", "app"])
        .stdout(File::create(home.path("out.conf")).unwrap())
        .status()
        .unwrap();
    assert!(rendered.success());
    let fixtures_dir = fixtures();
    let steps: [&[&str]; 8] = [
        &["run", "--env", "app", "--env", "db", "--", "true"],
        &["edit", "app", "--owner", "ops"],
        &["rm", "cloud"],
        &["verify-import", fixtures_dir.to_str().unwrap()],
        &["list"],
        &["describe", "app"],
        &["run", "--env", "nope", "--", "true"],
        &["edit", "nope", "--owner", "ops"],
    ];
    for args in steps {
        home.agentsafe(args);
    }
    let scrub = home.agentsafe_stdin(&["scrub"], &format!("{API_TOKEN} {set_value}"));
    assert!(scrub.status.success());

    let audit = home.path("audit.jsonl");
    assert_eq!(mode(&audit), 0o600);
    let lines = home.audit_lines();
    let seen: Vec<(String, Option<String>, String)> = lines
        .iter()
        .map(|l| {
            (
                l["action"].as_str().unwrap().to_string(),
                l["entry"].as_str().map(str::to_string),
                l["result"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let expected = [
        ("put", Some("app"), "ok"),
        ("put", Some("db"), "ok"),
        ("put", Some("cloud"), "ok"),
        ("render", Some("app"), "ok"),
        ("run", Some("app"), "ok"),
        ("run", Some("db"), "ok"),
        ("edit", Some("app"), "ok"),
        ("rm", Some("cloud"), "ok"),
        ("verify-import", None, "ok"),
        ("run", Some("nope"), "error"),
        ("edit", Some("nope"), "error"),
        ("scrub", None, "ok"),
    ]
    .map(|(a, e, r)| (a.to_string(), e.map(str::to_string), r.to_string()));
    assert_eq!(seen, expected);

    for line in &lines {
        let ts = line["ts"].as_str().unwrap();
        assert!(
            ts.parse::<jiff::Timestamp>().is_ok() && ts.ends_with('Z'),
            "{ts}"
        );
        assert_eq!(line["who"], "local:tester");
        assert_eq!(line["via"], "local");
        if line["result"] == "error" {
            assert!(
                line["reason"]
                    .as_str()
                    .unwrap()
                    .contains("no entry named nope")
            );
        }
    }

    let raw = fs::read_to_string(&audit).unwrap();
    let values = [API_TOKEN, DB_PASSWORD, set_value, "1234", "fx-user"];
    for value in values {
        for encoded in [
            value.to_string(),
            STANDARD.encode(value),
            URL_SAFE.encode(value),
            STANDARD_NO_PAD.encode(value),
        ] {
            assert!(!raw.contains(&encoded), "{encoded} in the audit log");
        }
    }
}

#[test]
fn an_audit_write_failure_fails_the_command_and_releases_no_value() {
    let home = Home::new();
    home.import_fixtures();
    // A directory where the log should be makes every append fail.
    fs::remove_file(home.path("audit.jsonl")).unwrap();
    fs::create_dir(home.path("audit.jsonl")).unwrap();
    let marker = home.path("ran");
    let script = format!("touch {}", marker.display());
    let out = home.agentsafe(&["run", "--env", "app", "--", "sh", "-c", &script]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("audit log"),
        "{}",
        text(&out.stderr)
    );
    assert!(!marker.exists());

    let out = home.agentsafe_stdin(&["set", "x", "--key", "K"], "some-value-123\n");
    assert!(!out.status.success());
    // Reads that are not audited keep working.
    assert!(home.agentsafe(&["list"]).status.success());
}

#[test]
fn list_and_verify_import_do_not_depend_on_the_catalog_export() {
    let home = Home::new();
    home.import_fixtures();
    fs::remove_file(home.path("catalog.toml")).unwrap();

    let out = home.agentsafe(&["verify-import", fixtures().to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stdout));
    assert_eq!(text(&out.stdout), "app.env\tapp\tOK\ndb.env\tdb\tOK\n");
    let list = text(&home.agentsafe(&["list"]).stdout);
    assert!(
        list.contains("app\t4\t") && list.contains("db\t3\t"),
        "{list}"
    );
    assert!(text(&home.agentsafe(&["describe", "app"]).stdout).contains("keys: API_TOKEN"));
    // The export is rewritten by the next save, and a stale one is never read.
    fs::write(home.path("catalog.toml"), "").unwrap();
    assert!(text(&home.agentsafe(&["list"]).stdout).contains("app\t4\t"));
}

#[test]
fn concurrent_rm_and_edit_leave_the_entry_deleted() {
    let home = Home::new();
    for round in 0..4 {
        let victim = format!("victim{round}");
        let out = home.agentsafe_stdin(
            &["set", &victim, "--key", "TOKEN"],
            "fixture-victim-12345\n",
        );
        assert!(out.status.success(), "{}", text(&out.stderr));
        let barrier = Barrier::new(8);
        thread::scope(|s| {
            s.spawn(|| {
                barrier.wait();
                // Succeeds, or finds the entry already edited and then removed: either order.
                home.agentsafe(&["rm", &victim]);
            });
            for i in 0..7 {
                let (barrier, victim) = (&barrier, &victim);
                let home = &home;
                s.spawn(move || {
                    barrier.wait();
                    home.agentsafe(&["edit", victim, "--description", &format!("edit {i}")]);
                });
            }
        });
        let list = text(&home.agentsafe(&["list"]).stdout);
        assert!(
            !list.contains(&victim),
            "round {round}: {victim} came back:\n{list}"
        );
    }
}

#[test]
fn concurrent_sets_lose_no_entry() {
    let home = Home::new();
    for round in 0..3 {
        let barrier = Barrier::new(8);
        thread::scope(|s| {
            for i in 0..8 {
                let (barrier, home) = (&barrier, &home);
                s.spawn(move || {
                    barrier.wait();
                    let name = format!("entry{round}x{i}");
                    let out = home.agentsafe_stdin(
                        &["set", &name, "--key", "TOKEN"],
                        &format!("fixture-parallel-{i}-12345\n"),
                    );
                    assert!(out.status.success(), "{}", text(&out.stderr));
                });
            }
        });
        let list = text(&home.agentsafe(&["list"]).stdout);
        for i in 0..8 {
            let name = format!("entry{round}x{i}\t");
            assert!(
                list.contains(&name),
                "round {round}: {name:?} lost:\n{list}"
            );
        }
    }
    assert_eq!(mode(&home.path("vault.lock")), 0o600);
}
