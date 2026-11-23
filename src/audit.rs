use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;

/// Rotate `audit.jsonl` to `audit.jsonl.1` once it reaches this size, bounding disk usage.
const MAX_AUDIT_BYTES: u64 = 10 * 1024 * 1024;

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

/// Append-only JSON lines file, created 0600, rotated once it reaches `max_bytes`.
pub struct AuditLog {
    path: PathBuf,
    max_bytes: u64,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> AuditLog {
        AuditLog {
            path,
            max_bytes: MAX_AUDIT_BYTES,
        }
    }

    fn rotate_if_full(&self) -> Result<()> {
        let len = match fs::metadata(&self.path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("cannot stat audit log {}", self.path.display()));
            }
        };
        if len < self.max_bytes {
            return Ok(());
        }
        let backup = self.path.with_extension("jsonl.1");
        match fs::rename(&self.path, &backup) {
            Ok(()) => Ok(()),
            // A concurrent writer may have rotated the file between stat and rename.
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => {
                Err(e).with_context(|| format!("cannot rotate audit log {}", self.path.display()))
            }
        }
    }

    /// Opened before a write, so a write that could not be audited is not made.
    pub fn open(&self) -> Result<OpenLog<'_>> {
        self.rotate_if_full()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_once_max_bytes_is_reached() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog {
            path: path.clone(),
            max_bytes: 200,
        };
        let event = || Event {
            who: "test".into(),
            via: "api".into(),
            action: "get".into(),
            entry: Some("demo".into()),
            result: Outcome::Ok,
            reason: None,
            notify: None,
        };
        for _ in 0..5 {
            log.append(&event()).expect("append");
        }
        let backup = path.with_extension("jsonl.1");
        assert!(backup.exists(), "expected rotated backup file");
        assert!(fs::metadata(&path).expect("metadata").len() < 200);
    }
}
