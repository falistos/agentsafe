use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::policy::Action;

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
    /// The uid whose connections carry Tailscale Serve's identity headers: `tailscaled`'s.
    #[serde(default)]
    pub tailscaled_uid: u32,
    /// The rights of other local users, who connect to the socket directly.
    #[serde(default, rename = "grant")]
    pub grants: Vec<LocalGrant>,
}

/// A `[[serve.grant]]` table: what the processes of one uid may do.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalGrant {
    pub uid: u32,
    pub entries: Vec<String>,
    pub actions: Vec<Action>,
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
        // Absolute, so the directory of a bare `config.toml` is not empty.
        let path = std::path::absolute(Config::path()?)?;
        let text = fs::read_to_string(&path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        let raw: RawConfig = toml::from_str(&text).map_err(|e| parse_error(&path, &text, &e))?;
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

/// TOML errors quote the offending line, which can hold the ntfy URL: report only where it is
/// and what kind of error it is.
fn parse_error(path: &Path, text: &str, e: &toml::de::Error) -> anyhow::Error {
    let kind = if toml::from_str::<toml::Table>(text).is_err() {
        "not valid TOML"
    } else {
        "an unknown setting or a value of the wrong type"
    };
    let Some(span) = e.span() else {
        return anyhow!("invalid config {}: {kind}", path.display());
    };
    let before = text.get(..span.start).unwrap_or(text);
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    anyhow!(
        "invalid config {}: {kind} at line {}, column {}",
        path.display(),
        before.matches('\n').count() + 1,
        before[line_start..].chars().count() + 1
    )
}

pub fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}
