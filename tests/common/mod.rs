//! Fixtures shared by every integration test.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;
use tempfile::TempDir;

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/env")
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A config directory with a new identity (`key.txt`), a `config.toml` that points at it and an
/// empty vault, as `init` leaves them.
pub fn local_dir() -> TempDir {
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
    write_empty_vault(dir.path(), &identity);
    dir
}

/// An empty vault encrypted to `identity`.
fn write_empty_vault(dir: &Path, identity: &age::x25519::Identity) {
    let recipient = identity.to_public();
    let recipient: &dyn age::Recipient = &recipient;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted = Vec::new();
    encryptor
        .wrap_output(&mut encrypted)
        .unwrap()
        .finish()
        .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("vault.age"))
        .unwrap()
        .write_all(&encrypted)
        .unwrap();
}
