use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};
use secrecy::ExposeSecret;

use crate::config::Config;
use crate::vault::Store;

/// Creates the config directory (0700) and the config; for a local setup also a new age identity
/// and an empty vault. No file is ever overwritten, and nothing is written if one of them exists.
pub fn init(server: Option<String>) -> Result<()> {
    let config = std::path::absolute(Config::path()?)?;
    let dir = config.parent().unwrap_or(Path::new("."));
    let identity = dir.join("identity.txt");
    let vault = dir.join("vault.age");

    let mut targets = vec![&config];
    if server.is_none() {
        targets.push(&identity);
        targets.push(&vault);
    }
    for path in targets {
        if path.try_exists()? {
            bail!(
                "{} already exists, refusing to overwrite it",
                path.display()
            );
        }
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;

    if let Some(server) = server {
        if server.is_empty() {
            bail!("server URL is empty");
        }
        write_new(&config, toml_assign("server", &server).as_bytes())?;
        println!("config: {}", config.display());
        return Ok(());
    }

    let key = age::x25519::Identity::generate();
    let public = key.to_public();
    let file = format!(
        "# created: {}\n# public key: {public}\n{}\n",
        jiff::Timestamp::now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        key.to_string().expose_secret()
    );
    write_new(&identity, file.as_bytes())?;
    Store::new(dir, identity.clone(), Vec::new()).create()?;
    let text = format!(
        "{}# Extra recipients the vault is also encrypted to, e.g. an offline recovery key.\nrecipients = []\n",
        toml_assign("identity", &identity.to_string_lossy())
    );
    write_new(&config, text.as_bytes())?;
    println!("config: {}", config.display());
    println!("identity: {}", identity.display());
    println!("public key: {public}");
    Ok(())
}

fn toml_assign(key: &str, value: &str) -> String {
    format!("{key} = {}\n", toml::Value::String(value.to_string()))
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
