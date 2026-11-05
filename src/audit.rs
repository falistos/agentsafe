use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Ok,
    Denied,
    Error,
}

/// One audited event: the outcome of a vault access (a fetch or a write), not of the whole
/// command. Argument and input errors that never reach the vault are not logged, and a `run` whose
/// key lookup or child fails after a successful fetch stays `ok`. Never carries a value.
#[derive(Serialize)]
pub struct Event {
    pub who: String,
    pub via: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    pub result: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How the owner was notified, when the event notified them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<String>,
}

#[derive(Serialize)]
struct Line<'a> {
    ts: String,
    #[serde(flatten)]
    event: &'a Event,
}

/// Append-only JSON lines file, created 0600.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> AuditLog {
        AuditLog { path }
    }

    /// Opened before a write, so a write that could not be audited is not made.
    pub fn open(&self) -> Result<OpenLog<'_>> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)
            .with_context(|| format!("cannot write audit log {}", self.path.display()))?;
        Ok(OpenLog { log: self, file })
    }

    pub fn append(&self, event: &Event) -> Result<()> {
        self.open()?.append(event)
    }
}

pub struct OpenLog<'a> {
    log: &'a AuditLog,
    file: File,
}

impl OpenLog<'_> {
    /// A single `write` per line, so concurrent appenders never interleave.
    pub fn append(mut self, event: &Event) -> Result<()> {
        let mut line = serde_json::to_vec(&Line {
            ts: jiff::Timestamp::now()
                .strftime("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            event,
        })?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .with_context(|| format!("cannot write audit log {}", self.log.path.display()))
    }
}
