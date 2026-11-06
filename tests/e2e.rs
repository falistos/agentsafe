#![expect(
    clippy::unwrap_used,
    reason = "a fixture or setup step that fails must panic the test, as unwrap does"
)]

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
use rustix::process::{ioctl_tiocsctty, setsid};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

mod common;

use common::{fixtures, local_dir, text};

const API_TOKEN: &str = "fixture-token-0123456789abcdef";
const DB_PASSWORD: &str = "fx-pa\"ss:word/with+chars";

struct Home {
    dir: TempDir,
    /// Config path when it is not `<dir>/config.toml`.
    config: Option<PathBuf>,
}

impl Home {
    fn new() -> Home {
        let dir = local_dir();
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

/// The agentsafe process holds every fetched value: no core dump, and on Linux no other process
/// of the user reads its memory or environment.
#[test]
fn run_is_not_dumpable() {
    let home = Home::new();
    home.import_fixtures();
    let (probe, expected) = if cfg!(target_os = "linux") {
        (
            "ulimit -c; cat /proc/$PPID/environ >/dev/null 2>&1 && echo readable || echo denied",
            "0\ndenied\n",
        )
    } else {
        ("ulimit -c", "0\n")
    };
    // The soft limit raised first, so that the 0 comes from agentsafe, not from the test host.
    let out = Command::new("sh")
        .args([
            "-c",
            "ulimit -S -c \"$(ulimit -H -c)\" && exec \"$@\"",
            "sh",
        ])
        .arg(env!("CARGO_BIN_EXE_agentsafe"))
        .args(["run", "--env", "db", "--", "sh", "-c", probe])
        .env("AGENTSAFE_CONFIG", home.path("config.toml"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(text(&out.stdout), expected, "{}", text(&out.stderr));
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
fn verify_import_reports_unreadable_files_without_mismatch() {
    let home = Home::new();
    let src = tempfile::tempdir().unwrap();
    for name in ["denied", "binary"] {
        let file = src.path().join(format!("{name}.env"));
        fs::copy(fixtures().join("app.env"), &file).unwrap();
        let out = home.agentsafe(&["import", file.to_str().unwrap(), "--name", name]);
        assert!(out.status.success(), "{}", text(&out.stderr));
    }
    fs::set_permissions(
        src.path().join("denied.env"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    fs::write(src.path().join("binary.env"), b"K=\xff\xfe\n").unwrap();
    let out = home.agentsafe(&["verify-import", src.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stdout),
        "binary.env\tbinary\tUNREADABLE (invalid data)\n\
         denied.env\tdenied\tUNREADABLE (permission denied)\n"
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
fn render_refuses_an_allowed_entry_the_template_never_reads() {
    let home = Home::new();
    home.import_fixtures();
    let template = home.path("t.j2");
    // No `{{ }}`: the output would be the template text.
    fs::write(&template, "DEPLOY_USER=secrets[\"db\"].DB_USER\n").unwrap();
    let t = template.to_str().unwrap();
    let existing = home.path("existing.env");
    fs::write(&existing, "old\n").unwrap();
    let created = home.path("created.env");
    for target in [&existing, &created] {
        let out = home.agentsafe(&["render", t, "--allow", "db", "-o", target.to_str().unwrap()]);
        assert!(!out.status.success());
        let stderr = text(&out.stderr);
        assert!(stderr.contains("db"), "{stderr}");
        assert!(stderr.contains("{{ secrets[\"NAME\"].KEY }}"), "{stderr}");
        assert!(!stderr.contains("DEPLOY_USER"), "{stderr}");
        assert!(!stderr.contains(DB_PASSWORD), "{stderr}");
    }
    assert_eq!(fs::read_to_string(&existing).unwrap(), "old\n");
    assert!(!created.exists());
}

#[test]
fn render_names_the_allowed_entry_that_the_template_leaves_unread() {
    let home = Home::new();
    home.import_fixtures();
    let template = home.path("t.j2");
    let target = home.path("out.conf");
    let render = |source: &str| {
        fs::write(&template, source).unwrap();
        home.agentsafe(&[
            "render",
            template.to_str().unwrap(),
            "--allow",
            "app",
            "--allow",
            "db",
            "-o",
            target.to_str().unwrap(),
        ])
    };

    let out = render("{{ secrets.app.API_TOKEN }}\n");
    assert!(!out.status.success());
    let stderr = text(&out.stderr);
    assert!(stderr.contains("db") && !stderr.contains("app"), "{stderr}");
    assert!(!stderr.contains(API_TOKEN), "{stderr}");
    assert!(!target.exists());

    // Listing the names reads no entry.
    let out = render("{% for name in secrets %}{{ name }}{% endfor %}");
    assert!(!out.status.success());
    assert!(!target.exists());

    let out = render("{{ secrets.app.API_TOKEN }}:{{ secrets[\"db\"].DB_USER }}\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(fs::read_to_string(&target).unwrap().starts_with(API_TOKEN));
}

#[test]
fn render_publishes_a_private_file_by_rename() {
    let home = Home::new();
    home.import_fixtures();
    let template = home.path("t.j2");
    fs::write(&template, "token={{ secrets.app.API_TOKEN }}\n").unwrap();
    let target = home.path("out.conf");
    fs::write(&target, "old\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    // A reader that opened the old file never sees what render writes.
    let mut reader = File::open(&target).unwrap();
    let t = template.to_str().unwrap();
    let out = home.agentsafe(&[
        "render",
        t,
        "--allow",
        "app",
        "-o",
        target.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "");
    let mut seen = String::new();
    reader.read_to_string(&mut seen).unwrap();
    assert_eq!(seen, "old\n");
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        format!("token={API_TOKEN}\n")
    );
    assert_eq!(mode(&target), 0o600);

    let mut names: Vec<String> = fs::read_dir(home.dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with('.'))
        .collect();
    names.sort();
    assert!(names.is_empty(), "temporary files left: {names:?}");

    // A bare file name lands in the current directory.
    let out = home
        .cmd(&["render", t, "--allow", "app", "-o", "bare.conf"])
        .current_dir(home.dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(mode(&home.path("bare.conf")), 0o600);

    // No output, a missing parent, or a denied template: nothing is written.
    assert!(
        !home
            .agentsafe(&["render", t, "--allow", "app"])
            .status
            .success()
    );
    let orphan = home.path("missing/out.conf");
    let out = home.agentsafe(&[
        "render",
        t,
        "--allow",
        "app",
        "-o",
        orphan.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("does not exist"),
        "{}",
        text(&out.stderr)
    );
    assert!(!home.path("missing").exists());
    let denied = home.path("denied.conf");
    let out = home.agentsafe(&["render", t, "--allow", "db", "-o", denied.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(!denied.exists());
}

#[test]
fn scrub_masks_every_known_value() {
    let home = Home::new();
    home.import_fixtures();
    let input = format!("a {API_TOKEN} b {DB_PASSWORD} c\n");
    let out = home.agentsafe_stdin(&["scrub"], &input);
    assert_eq!(text(&out.stdout), "a ***app*** b ***db*** c\n");
}

/// Building the masker must stay fast on long periodic values, not only on random ones.
#[test]
fn scrub_masks_long_values_in_bounded_time() {
    let repetitive = "abcdefgh".repeat(8 * 1024);
    let random: String = (0u32..1024)
        .map(|i| hex::encode(Sha256::digest(i.to_le_bytes())))
        .collect();
    for (name, value) in [("repetitive", &repetitive), ("random", &random)] {
        assert_eq!(value.len(), 64 * 1024);
        let home = Home::new();
        let out = home.agentsafe_stdin(&["set", name, "--key", "K"], value);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let input = home.path("input.txt");
        fs::write(&input, format!("before {value} after\n")).unwrap();
        let mut child = home
            .cmd(&["scrub"])
            .stdin(File::open(&input).unwrap())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let status = wait_at_most(&mut child, Duration::from_secs(20));
        assert!(status.is_some_and(|s| s.success()), "{name}: {status:?}");
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, format!("before ***{name}*** after\n"));
    }
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
fn init_server_writes_a_remote_config_that_every_command_uses() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("config.toml");
    // Port 1 on loopback refuses at once: each command fails reaching the server.
    let out = cli(&config, &["init", "--server", "http://127.0.0.1:1"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        "server = \"http://127.0.0.1:1\"\n"
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
            text(&out.stderr).contains("cannot reach http://127.0.0.1:1"),
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
        let _ = fs::remove_file(&target);
        let out = home.agentsafe(&[
            "render",
            path.to_str().unwrap(),
            "--allow",
            "app",
            "--output",
            target.to_str().unwrap(),
        ]);
        (
            out.status.success(),
            fs::read_to_string(&target).unwrap_or_default(),
        )
    };
    let (ok, out) = render("t={{ secrets[\"app\"].API_TOKEN }}\n");
    assert!(ok);
    assert_eq!(out, format!("t={API_TOKEN}\n"));
    // An entry that is not allowed is undefined.
    assert!(!render("t={{ secrets.db.DB_USER }}\n").0);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario that checks the audit line of each operation in turn"
)]
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
    let out_conf = home.path("out.conf");
    let rendered = home.agentsafe(&[
        "render",
        template.to_str().unwrap(),
        "--allow",
        "app",
        "-o",
        out_conf.to_str().unwrap(),
    ]);
    assert!(rendered.status.success());
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

/// The exit status, or `None` (and the child killed) if it still runs after `limit`.
fn wait_at_most(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Kills a process left behind by a failing test.
struct KillOnDrop(String);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = Command::new("kill").args(["-KILL", &self.0]).output();
    }
}

fn signal(signal: &str, pid: &str) {
    let out = Command::new("kill")
        .args([&format!("-{signal}"), pid])
        .output()
        .unwrap();
    assert!(out.status.success(), "kill -{signal} {pid}");
}

fn is_alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .output()
        .unwrap()
        .status
        .success()
}

/// The content of `path` once `until` accepts it; a bounded wait, since the machine may be loaded.
fn wait_for_file(path: &Path, until: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(content) = fs::read_to_string(path)
            && until(&content)
        {
            return content;
        }
        assert!(
            Instant::now() < deadline,
            "{} never got there",
            path.display()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// `agentsafe run --env app -- sh -c SCRIPT`, with the script's pid and marker files in `dir`.
fn spawn_run(home: &Home, dir: &Path, script: &str) -> Child {
    home.cmd(&["run", "--env", "app", "--", "sh", "-c", script])
        .env("PIDFILE", dir.join("pid"))
        .env("MARKER", dir.join("marker"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn sigterm_to_run_ends_the_child_and_exits_128_plus_the_signal() {
    let home = Home::new();
    home.import_fixtures();
    let dir = tempfile::tempdir().unwrap();
    let mut run = spawn_run(&home, dir.path(), "echo $$ > \"$PIDFILE\"; exec sleep 41");
    let pid = wait_for_file(&dir.path().join("pid"), |c| c.ends_with('\n'))
        .trim()
        .to_string();
    let _cleanup = KillOnDrop(pid.clone());

    signal("TERM", &run.id().to_string());
    let status = wait_at_most(&mut run, Duration::from_secs(10)).expect("run exits");
    assert_eq!(status.code(), Some(128 + 15));
    let deadline = Instant::now() + Duration::from_secs(10);
    while is_alive(&pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!is_alive(&pid), "the child outlived agentsafe");
}

#[test]
fn a_child_that_handles_the_signal_has_its_output_masked_and_its_exit_code_kept() {
    let home = Home::new();
    home.import_fixtures();
    let dir = tempfile::tempdir().unwrap();
    let script = "trap 'echo \"caught $API_TOKEN\"; exit 3' TERM; echo $$ > \"$PIDFILE\"; \
                  while :; do sleep 0.05; done";
    let mut run = spawn_run(&home, dir.path(), script);
    let pid = wait_for_file(&dir.path().join("pid"), |c| c.ends_with('\n'))
        .trim()
        .to_string();
    let _cleanup = KillOnDrop(pid);

    signal("TERM", &run.id().to_string());
    let out = {
        let mut stdout = String::new();
        run.stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        stdout
    };
    let status = wait_at_most(&mut run, Duration::from_secs(10)).expect("run exits");
    assert_eq!(status.code(), Some(3));
    assert_eq!(out, "caught ***app***\n");
}

#[test]
fn run_keeps_waiting_for_a_child_that_survives_the_signal() {
    let home = Home::new();
    home.import_fixtures();
    let dir = tempfile::tempdir().unwrap();
    let script = "trap 'echo got >> \"$MARKER\"' HUP; echo $$ > \"$PIDFILE\"; \
                  while :; do sleep 0.05; done";
    let mut run = spawn_run(&home, dir.path(), script);
    let pid = wait_for_file(&dir.path().join("pid"), |c| c.ends_with('\n'))
        .trim()
        .to_string();
    let _cleanup = KillOnDrop(pid.clone());

    signal("HUP", &run.id().to_string());
    assert_eq!(
        wait_for_file(&dir.path().join("marker"), |c| c == "got\n"),
        "got\n"
    );
    assert!(run.try_wait().unwrap().is_none(), "run left with its child");

    signal("KILL", &pid);
    let status = wait_at_most(&mut run, Duration::from_secs(10)).expect("run exits");
    assert_eq!(status.code(), Some(128 + 9));
}

#[test]
fn ctrl_c_in_a_terminal_reaches_the_child_once() {
    let home = Home::new();
    home.import_fixtures();
    let dir = tempfile::tempdir().unwrap();

    // A terminal of our own: `run` leads a session whose controlling terminal is the pty, so
    // that ^C written to the master signals its whole foreground group, as a keyboard does.
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let slave = File::options()
        .read(true)
        .write(true)
        .open(OsStr::from_bytes(name.to_bytes()))
        .unwrap();
    let script = "trap 'echo INT >> \"$MARKER\"' INT; echo $$ > \"$PIDFILE\"; echo ready; \
                  while :; do sleep 0.05 & wait $!; done";
    let mut cmd = home.cmd(&["run", "--env", "app", "--", "sh", "-c", script]);
    cmd.env("PIDFILE", dir.path().join("pid"))
        .env("MARKER", dir.path().join("marker"))
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    // SAFETY: the closure only makes system calls, between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            setsid()?;
            ioctl_tiocsctty(io::stdin())?;
            Ok(())
        });
    }
    let mut run = cmd.spawn().unwrap();
    let screen = Arc::new(Mutex::new(String::new()));
    let reader = {
        let screen = Arc::clone(&screen);
        let mut master = File::from(master.try_clone().unwrap());
        thread::spawn(move || {
            let mut buf = [0; 256];
            while let Ok(n @ 1..) = master.read(&mut buf) {
                screen
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        })
    };
    let pid = wait_for_file(&dir.path().join("pid"), |c| c.ends_with('\n'))
        .trim()
        .to_string();
    let _cleanup = KillOnDrop(pid.clone());
    let deadline = Instant::now() + Duration::from_secs(30);
    while !screen.lock().unwrap().contains("ready") {
        assert!(Instant::now() < deadline, "the child never said ready");
        thread::sleep(Duration::from_millis(20));
    }

    File::from(master).write_all(b"\x03").unwrap();
    wait_for_file(&dir.path().join("marker"), |c| c == "INT\n");
    // A second delivery would follow the first at once; a second of grace is plenty.
    thread::sleep(Duration::from_secs(1));
    assert_eq!(
        fs::read_to_string(dir.path().join("marker")).unwrap(),
        "INT\n"
    );

    signal("KILL", &pid);
    let status = wait_at_most(&mut run, Duration::from_secs(10)).expect("run exits");
    assert_eq!(status.code(), Some(128 + 9));
    drop(reader);
}

#[test]
fn a_missing_vault_is_an_error_everywhere() {
    let home = Home::new();
    home.import_fixtures();
    fs::rename(home.path("vault.age"), home.path("vault.age.bak")).unwrap();

    let out = home.agentsafe_stdin(&["scrub"], &format!("token {API_TOKEN}\n"));
    assert!(!out.status.success());
    assert_eq!(text(&out.stdout), "");
    assert!(
        text(&out.stderr).contains("no vault at"),
        "{}",
        text(&out.stderr)
    );
    let marker = home.path("ran");
    let script = format!("touch {}", marker.display());
    let out = home.agentsafe(&["run", "--env", "app", "--", "sh", "-c", &script]);
    assert!(!out.status.success());
    assert!(!marker.exists());
    for args in [&["list"][..], &["describe", "app"], &["rm", "app"]] {
        let out = home.agentsafe(args);
        assert!(!out.status.success(), "{args:?}");
        assert!(text(&out.stderr).contains("no vault at"), "{args:?}");
    }
    let out = home.agentsafe_stdin(&["set", "x", "--key", "K"], "value-123456\n");
    assert!(!out.status.success());
    assert!(!home.path("vault.age").exists());
}

#[test]
fn a_corrupt_vault_is_named_in_the_error() {
    let home = Home::new();
    fs::write(home.path("vault.age"), "not an age file\n").unwrap();
    let out = home.agentsafe(&["list"]);
    assert!(!out.status.success());
    let vault = home.path("vault.age");
    let expected = format!("cannot decrypt {}", vault.display());
    assert!(
        text(&out.stderr).contains(&expected),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn init_creates_an_empty_vault_and_init_server_none() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("local/config.toml");
    assert!(cli(&config, &["init"]).status.success());
    let vault = config.with_file_name("vault.age");
    assert_eq!(mode(&vault), 0o600);
    let out = cli(&config, &["list"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).lines().count(), 1);

    let remote = tmp.path().join("remote/config.toml");
    assert!(
        cli(&remote, &["init", "--server", "http://127.0.0.1:1"])
            .status
            .success()
    );
    assert!(!remote.with_file_name("vault.age").exists());

    // An existing vault is never overwritten, nor paired with a new identity.
    let restored = tmp.path().join("restored/config.toml");
    fs::create_dir(restored.parent().unwrap()).unwrap();
    fs::write(restored.with_file_name("vault.age"), "backup").unwrap();
    assert!(!cli(&restored, &["init"]).status.success());
    assert_eq!(
        fs::read_to_string(restored.with_file_name("vault.age")).unwrap(),
        "backup"
    );
    assert!(!restored.exists());
}

#[test]
fn a_write_that_cannot_be_audited_changes_nothing() {
    let home = Home::new();
    home.import_fixtures();
    fs::remove_file(home.path("audit.jsonl")).unwrap();
    fs::create_dir(home.path("audit.jsonl")).unwrap();

    assert!(!home.agentsafe(&["rm", "app"]).status.success());
    let out = home.agentsafe_stdin(&["set", "app", "--key", "NEW"], "new-value-123456\n");
    assert!(!out.status.success());
    let out = home.agentsafe_stdin(&["set", "fresh", "--key", "K"], "fresh-value-123456\n");
    assert!(!out.status.success());
    assert!(
        !home
            .agentsafe(&["edit", "db", "--owner", "x"])
            .status
            .success()
    );

    let list = text(&home.agentsafe(&["list"]).stdout);
    assert!(
        list.contains("app\t4\t") && list.contains("db\t3\t-\t"),
        "{list}"
    );
    assert!(!list.contains("fresh"), "{list}");
    let describe = text(&home.agentsafe(&["describe", "app"]).stdout);
    assert!(
        describe.contains("keys: API_TOKEN, API_URL, GREETING, PIN"),
        "{describe}"
    );
}

#[test]
fn config_errors_never_quote_the_file() {
    let home = Home::new();
    let config = home.path("config.toml");
    let base = fs::read_to_string(&config).unwrap();
    let topic = "https://ntfy.example/fixture-topic-8b1e";
    for (extra, line) in [
        (format!("[serve]\nntfy = \"{topic}\" trailing\n"), 3),
        (format!("recipients = \"{topic}\"\n"), 2),
    ] {
        fs::write(&config, format!("{base}{extra}")).unwrap();
        let out = home.agentsafe(&["list"]);
        assert!(!out.status.success());
        let err = text(&out.stderr);
        assert!(!err.contains("fixture-topic"), "the config line was quoted");
        assert!(err.contains(config.to_str().unwrap()), "{err}");
        assert!(err.contains(&format!("line {line}, column")), "{err}");
    }

    // A recipient that is a secret key pasted by mistake is not quoted either.
    let pasted = "AGE-SECRET-KEY-1FIXTURENOTAREALKEYFIXTURENOTAREALKEYFIXTURENOTAREAL";
    fs::write(&config, format!("{base}recipients = [\"{pasted}\"]\n")).unwrap();
    let out = home.agentsafe_stdin(&["set", "x", "--key", "K"], "value-123456\n");
    assert!(!out.status.success());
    assert!(
        !text(&out.stderr).contains("FIXTURENOTAREALKEY"),
        "the recipient was quoted"
    );
}

#[test]
fn a_failing_catalog_export_is_a_warning_after_the_commit() {
    let home = Home::new();
    home.import_fixtures();
    fs::remove_file(home.path("catalog.toml")).unwrap();
    fs::create_dir(home.path("catalog.toml")).unwrap();

    let out = home.agentsafe(&["rm", "app"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("warning"),
        "{}",
        text(&out.stderr)
    );
    assert!(!text(&home.agentsafe(&["list"]).stdout).contains("app\t"));
    let last = home.audit_lines().pop().unwrap();
    assert_eq!(
        (&last["action"], &last["result"]),
        (&"rm".into(), &"ok".into())
    );
}

#[test]
fn a_relative_config_path_works() {
    let home = Home::new();
    let out = home
        .cmd(&["set", "cloud", "--key", "TOKEN"])
        .env("AGENTSAFE_CONFIG", "config.toml")
        .current_dir(home.dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"relative-value-123\n")?;
            child.wait_with_output()
        })
        .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&home.agentsafe(&["list"]).stdout).contains("cloud\t1\t"));
}

#[test]
fn a_write_against_a_held_lock_fails_as_busy() {
    let home = Home::new();
    home.import_fixtures();
    let lock = File::create(home.path("vault.lock")).unwrap();
    lock.lock().unwrap();

    let started = Instant::now();
    let mut child = home
        .cmd(&["rm", "app"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = wait_at_most(&mut child, Duration::from_secs(9));
    assert!(status.is_some_and(|s| !s.success()), "{status:?}");
    assert!(started.elapsed() >= Duration::from_secs(4));
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(err.contains("vault is busy"), "{err}");

    drop(lock);
    assert!(text(&home.agentsafe(&["list"]).stdout).contains("app\t4\t"));
}

#[test]
fn a_crlf_env_file_imports() {
    let home = Home::new();
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("win.env");
    fs::write(
        &file,
        "# windows\r\nexport TOKEN=\"crlf-quoted-value-1\"\r\nBARE=crlf-bare-value-2\r\nMULTI=\"a\r\nb\"\r\nLONE=\"x\ry\"\r\n",
    )
    .unwrap();
    let out = home.agentsafe(&["import", file.to_str().unwrap(), "--name", "win"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let script = "test \"$TOKEN\" = crlf-quoted-value-1 && test \"$BARE\" = crlf-bare-value-2 \
                  && test \"$MULTI\" = \"$(printf 'a\\nb')\" && test \"$LONE\" = \"$(printf 'x\\ry')\" \
                  && echo same";
    let out = home.agentsafe(&["run", "--env", "win", "--", "sh", "-c", script]);
    assert_eq!(text(&out.stdout), "same\n", "{}", text(&out.stderr));
    let out = home.agentsafe(&["verify-import", src.path().to_str().unwrap()]);
    assert_eq!(text(&out.stdout), "win.env\twin\tOK\n");
}

const OVH_CHECK: &str = "test \"$OVH_APPLICATION_KEY\" = a-123456 \
    && test \"$OVH_CONSUMER_KEY\" = ck-new-654321 && echo same";

#[test]
fn set_with_a_key_changes_that_key_and_keeps_the_others_and_the_metadata() {
    let home = Home::new();
    let out = home.agentsafe_stdin(
        &["set", "ovh", "--description", "OVH API"],
        "OVH_APPLICATION_KEY=a-123456\nOVH_CONSUMER_KEY=ck-old-123456\n",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));

    let out = home.agentsafe_stdin(
        &["set", "ovh", "--key", "OVH_CONSUMER_KEY"],
        "ck-new-654321\n",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stderr),
        "stored ovh: set OVH_CONSUMER_KEY (2 keys)\n"
    );

    let described = text(&home.agentsafe(&["describe", "ovh"]).stdout);
    assert!(
        described.contains("keys: OVH_APPLICATION_KEY, OVH_CONSUMER_KEY\n"),
        "{described}"
    );
    assert!(described.contains("description: OVH API\n"), "{described}");
    let out = home.agentsafe(&["run", "--env", "ovh", "--", "sh", "-c", OVH_CHECK]);
    assert_eq!(text(&out.stdout), "same\n", "{}", text(&out.stderr));

    // A key that is not there yet is added.
    let out = home.agentsafe_stdin(&["set", "ovh", "--key", "OVH_ENDPOINT"], "ovh-eu\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("(3 keys)"));

    let writes: Vec<_> = home
        .audit_lines()
        .into_iter()
        .filter(|l| l["action"] != "run")
        .collect();
    assert_eq!(writes.len(), 3, "{writes:?}");
    assert!(
        writes
            .iter()
            .all(|l| l["action"] == "put" && l["result"] == "ok")
    );
    assert!(
        !fs::read_to_string(home.path("audit.jsonl"))
            .unwrap()
            .contains("ck-new")
    );
}

#[test]
fn set_with_lines_still_replaces_every_value() {
    let home = Home::new();
    home.agentsafe_stdin(
        &["set", "ovh"],
        "OLD_ONE=old-value-1\nOLD_TWO=old-value-2\n",
    );
    let out = home.agentsafe_stdin(&["set", "ovh"], "NEW_ONE=new-value-1\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "stored ovh (1 key)\n");
    let described = text(&home.agentsafe(&["describe", "ovh"]).stdout);
    assert!(described.contains("keys: NEW_ONE\n"), "{described}");
}

/// Base64 tokens as a tunnel token file holds them: one line, `=` padding, no key.
const PADDED_TOKENS: [&str; 2] = [
    "eyJhIjoiZml4dHVyZS1hY2NvdW50IiwidCI6Ijk5In0=",
    "c2VjcmV0LXRva2VuLWZpeHR1cmU==",
];

#[test]
fn a_padded_base64_token_is_refused_by_import_and_set() {
    for token in PADDED_TOKENS {
        let home = Home::new();
        let src = tempfile::tempdir().unwrap();
        let file = src.path().join("tunnel.token");
        fs::write(&file, format!("{token}\n")).unwrap();

        let imported = home.agentsafe(&["import", file.to_str().unwrap(), "--name", "tunnel"]);
        let set = home.agentsafe_stdin(&["set", "tunnel"], &format!("{token}\n"));
        for out in [&imported, &set] {
            assert!(!out.status.success());
            let stderr = text(&out.stderr);
            assert!(stderr.contains("set NAME --key KEY < FILE"), "{stderr}");
            assert!(!stderr.contains(&token[..12]), "{stderr}");
        }
        assert_eq!(text(&home.agentsafe(&["list"]).stdout).lines().count(), 1);
        let catalog = fs::read_to_string(home.path("catalog.toml")).unwrap_or_default();
        assert!(!catalog.contains(&token[..12]), "{catalog}");
    }
}

#[test]
fn a_key_outside_the_dotenv_grammar_is_refused() {
    let home = Home::new();
    for key in ["my=key", "1abc", "a b", ""] {
        let out = home.agentsafe_stdin(&["set", "amb", "--key", key], "value-123456\n");
        assert!(!out.status.success(), "{key:?} accepted");
        let stderr = text(&out.stderr);
        assert!(!stderr.contains("value-123456"), "{stderr}");
        assert!(key.is_empty() || !stderr.contains(key), "{stderr}");
    }
    assert_eq!(text(&home.agentsafe(&["list"]).stdout).lines().count(), 1);
}

#[test]
fn a_padded_base64_token_is_stored_by_set_with_a_key() {
    for token in PADDED_TOKENS {
        let home = Home::new();
        let out = home.agentsafe_stdin(&["set", "tunnel", "--key", "TOKEN"], &format!("{token}\n"));
        assert!(out.status.success(), "{}", text(&out.stderr));
        let out = home
            .cmd(&[
                "run",
                "--env",
                "tunnel:TOKEN=T",
                "--",
                "sh",
                "-c",
                "test \"$T\" = \"$EXPECTED\" && echo same",
            ])
            .env("EXPECTED", token)
            .output()
            .unwrap();
        assert_eq!(text(&out.stdout), "same\n", "{}", text(&out.stderr));
    }
}

#[test]
fn a_file_with_one_value_next_to_empty_keys_imports() {
    let home = Home::new();
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("mixed.env");
    fs::write(&file, "EMPTY=\nREAL=mixed-real-value-1\n").unwrap();
    let out = home.agentsafe(&["import", file.to_str().unwrap(), "--name", "mixed"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&home.agentsafe(&["describe", "mixed"]).stdout).contains("keys: EMPTY, REAL\n"));
}

#[test]
fn keys_with_a_dash_import_and_run_under_their_own_names() {
    let home = Home::new();
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("bots.env");
    fs::write(
        &file,
        "billing-bot=dash-key-value-1\nother-bot=dash-key-value-2\n",
    )
    .unwrap();
    let out = home.agentsafe(&["import", file.to_str().unwrap(), "--name", "bots"]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let out = home.agentsafe(&[
        "run",
        "--env",
        "bots:billing-bot=T",
        "--",
        "sh",
        "-c",
        "test \"$T\" = dash-key-value-1 && echo same",
    ]);
    assert_eq!(text(&out.stdout), "same\n", "{}", text(&out.stderr));

    // The shell cannot expand `$billing-bot`; `env` lists the variables under their own names.
    let out = home.agentsafe(&["run", "--env", "bots", "--", "env"]);
    let listed = text(&out.stdout);
    assert!(listed.contains("billing-bot=***bots***\n"), "{listed}");
    assert!(listed.contains("other-bot=***bots***\n"), "{listed}");

    let out = home.agentsafe(&["verify-import", src.path().to_str().unwrap()]);
    assert_eq!(text(&out.stdout), "bots.env\tbots\tOK\n");
}

/// JSON as Python's `json.dumps` writes it: non-ASCII as lower-case `\uXXXX`, astral characters
/// as surrogate pairs.
fn json_ascii(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(out, "\\u{unit:04x}").expect("writing to a String cannot fail");
                }
            }
        }
    }
    out
}

#[test]
fn run_and_scrub_mask_the_extra_json_and_percent_spellings() {
    let home = Home::new();
    let value = "fx/välue-🔑-2718";
    let out = home.agentsafe_stdin(&["set", "uni", "--key", "V"], value);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let serde = serde_json::to_string(value).unwrap();
    let spellings = [
        json_ascii(value),
        serde[1..serde.len() - 1].replace('/', "\\/"),
        value
            .bytes()
            .map(|b| match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' => char::from(b).to_string(),
                b => format!("%{b:02x}"),
            })
            .collect(),
    ];
    assert_eq!(spellings[0], "fx/v\\u00e4lue-\\ud83d\\udd11-2718");
    for spelling in &spellings {
        let out = home.agentsafe(&[
            "run",
            "--env",
            "uni",
            "--",
            "sh",
            "-c",
            "printf '<%s>\\n' \"$1\"",
            "sh",
            spelling,
        ]);
        assert_eq!(text(&out.stdout), "<***uni***>\n", "{spelling}");
        let out = home.agentsafe_stdin(&["scrub"], &format!("<{spelling}>\n"));
        assert_eq!(text(&out.stdout), "<***uni***>\n", "{spelling}");
    }
}

#[test]
fn set_help_names_both_input_forms() {
    let out = Command::new(env!("CARGO_BIN_EXE_agentsafe"))
        .args(["set", "--help"])
        .output()
        .unwrap();
    let about = text(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        about.contains("KEY=VALUE") && about.contains("--key"),
        "{about}"
    );
}
