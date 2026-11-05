use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Deserialize)]
struct RawConfig {
    identity: Option<PathBuf>,
    server: Option<String>,
    /// Extra age recipients, e.g. an offline recovery key.
    #[serde(default)]
    recipients: Vec<String>,
    #[serde(default)]
    serve: Serve,
}

/// Settings of `agentsafe serve`.
#[derive(Deserialize, Default)]
pub struct Serve {
    pub socket: Option<String>,
    /// Where the admin UI posts a notification when it reveals values.
    pub ntfy: Option<String>,
}

pub enum Mode {
    Local {
        identity: PathBuf,
        recipients: Vec<String>,
    },
    Remote {
        server: String,
    },
}

pub struct Config {
    pub path: PathBuf,
    pub mode: Mode,
    pub serve: Serve,
}

impl Config {
    /// `$AGENTSAFE_CONFIG`, or `~/.config/agentsafe/config.toml`.
    pub fn path() -> Result<PathBuf> {
        match std::env::var_os("AGENTSAFE_CONFIG") {
            Some(p) => Ok(PathBuf::from(p)),
            None => Ok(home()?.join(".config/agentsafe/config.toml")),
        }
    }

    pub fn load() -> Result<Config> {
        let path = Config::path()?;
        let text = fs::read_to_string(&path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        let raw: RawConfig =
            toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
        let mode = match (raw.identity, raw.server) {
            (Some(identity), None) => Mode::Local {
                identity: match identity.strip_prefix("~") {
                    Ok(rest) => home()?.join(rest),
                    Err(_) => identity,
                },
                recipients: raw.recipients,
            },
            (None, Some(server)) if !server.is_empty() => Mode::Remote { server },
            (None, Some(_)) => bail!("invalid config {}: server is empty", path.display()),
            (Some(_), Some(_)) => bail!(
                "invalid config {}: set either `identity` (local) or `server` (remote), not both",
                path.display()
            ),
            (None, None) => bail!(
                "invalid config {}: set `identity` (local) or `server` (remote)",
                path.display()
            ),
        };
        Ok(Config {
            path,
            mode,
            serve: raw.serve,
        })
    }

    /// The directory holding the config, the vault, the catalog and the audit log.
    pub fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("."))
    }
}

pub fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}
