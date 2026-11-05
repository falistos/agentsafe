use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use secrecy::ExposeSecret;
use tempfile::TempDir;

const API_TOKEN: &str = "fixture-token-0123456789abcdef";
const DB_PASSWORD: &str = "fx-pa\"ss:word/with+chars";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/env")
}

struct Home {
    dir: TempDir,
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
        Home { dir }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe"));
        cmd.args(args)
            .env("SAFE_CONFIG", self.dir.path().join("config.toml"));
        cmd
    }

    fn safe(&self, args: &[&str]) -> Output {
        self.cmd(args).stdin(Stdio::null()).output().unwrap()
    }

    fn safe_stdin(&self, args: &[&str], stdin: &str) -> Output {
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

    fn import_fixtures(&self) {
        for name in ["app", "db"] {
            let file = fixtures().join(format!("{name}.env"));
            let out = self.safe(&["import-env", file.to_str().unwrap(), "--name", name]);
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
    let out = home.safe(&[
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
    let out = home.safe(&[
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
    let out = home.safe(&["verify-import", fixtures().to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stdout));
    assert_eq!(text(&out.stdout), "app.env\tapp\tOK\ndb.env\tdb\tOK\n");
}

#[test]
fn verify_import_reports_mismatch_and_unknown_files() {
    let home = Home::new();
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("app.env");
    fs::copy(fixtures().join("app.env"), &file).unwrap();
    let out = home.safe(&["import-env", file.to_str().unwrap(), "--name", "app"]);
    assert!(out.status.success());
    fs::write(&file, "API_TOKEN=changed-value\n").unwrap();
    fs::write(src.path().join("other.env"), "X=1\n").unwrap();
    let out = home.safe(&["verify-import", src.path().to_str().unwrap()]);
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
    let out = home.safe_stdin(
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
    let list = home.safe(&["list"]);
    let describe = home.safe(&["describe", "cloud"]);
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

    let run = home.safe(&["run", "--env", "cloud", "--", "sh", "-c", "echo $TOKEN"]);
    assert_eq!(text(&run.stdout), "***cloud***\n");
}

#[test]
fn describe_flags_values_too_short_to_mask() {
    let home = Home::new();
    home.import_fixtures();
    let out = home.safe(&["describe", "app"]);
    assert!(text(&out.stdout).contains("unmasked: PIN (under 6 bytes)"));
}

#[test]
fn render_writes_only_to_a_regular_file() {
    let home = Home::new();
    home.import_fixtures();
    let template = home.dir.path().join("t.j2");
    fs::write(&template, "token={{ safe.app.API_TOKEN }}\n").unwrap();
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

    let piped = home.safe(&["render", template.to_str().unwrap(), "--allow", "app"]);
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
    let out = home.safe_stdin(&["scrub"], &input);
    assert_eq!(text(&out.stdout), "a ***app*** b ***db*** c\n");
}
