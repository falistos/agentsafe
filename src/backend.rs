use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Result, anyhow, bail};
use jiff::civil::Date;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditLog, Event, Outcome};
use crate::mask::{MIN_LEN, Masker};
use crate::vault::{Catalog, Entry, Meta, Store, validate_name};

/// Key name to value, for one entry.
pub type Values = BTreeMap<String, SecretString>;
/// Entry name to its values.
pub type Fetched = BTreeMap<String, Values>;

/// What the fetched values are for; the backend audits it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    Run,
    Render,
    Scrub,
    VerifyImport,
}

impl Purpose {
    fn action(self) -> &'static str {
        match self {
            Purpose::Run => "run",
            Purpose::Render => "render",
            Purpose::Scrub => "scrub",
            Purpose::VerifyImport => "verify-import",
        }
    }
}

pub enum Selection {
    All,
    Names(Vec<String>),
}

/// A metadata change: an absent field is left alone, an empty one clears it.
/// `rotate_by` is `YYYY-MM-DD`, or empty to clear.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct MetaPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_by: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl MetaPatch {
    pub fn is_empty(&self) -> bool {
        *self == MetaPatch::default()
    }

    fn apply(self, meta: &mut Meta) -> Result<()> {
        let text = |v: String| Some(v).filter(|v| !v.is_empty());
        // Parse first, so a bad date leaves the metadata untouched.
        let rotate_by = match self.rotate_by {
            None => None,
            Some(d) if d.is_empty() => Some(None),
            Some(d) => {
                Some(Some(Date::from_str(&d).map_err(|_| {
                    anyhow!("invalid rotate-by {d:?}: use YYYY-MM-DD")
                })?))
            }
        };
        if let Some(v) = self.description {
            meta.description = text(v);
        }
        if let Some(v) = self.used_by {
            meta.used_by = v;
        }
        if let Some(v) = self.owner {
            meta.owner = text(v);
        }
        if let Some(v) = rotate_by {
            meta.rotate_by = v;
        }
        if let Some(v) = self.tags {
            meta.tags = v;
        }
        if let Some(v) = self.source {
            meta.source = text(v);
        }
        Ok(())
    }
}

/// New values and/or a metadata change. With no values the entry must already exist.
pub struct Put {
    pub values: Option<Values>,
    pub meta: MetaPatch,
}

/// Where the vault lives: every command except `init` goes through it.
pub trait Backend {
    /// Metadata and key names of every entry; no values.
    fn catalog(&self) -> Result<Catalog>;
    /// The values of the selected entries.
    fn fetch(&self, purpose: Purpose, selection: &Selection) -> Result<Fetched>;
    fn put(&self, name: &str, put: Put) -> Result<()>;
    fn remove(&self, name: &str) -> Result<()>;
}

/// A masker for everything that was fetched, entry by entry.
pub fn masker(fetched: &Fetched) -> Masker {
    Masker::new(fetched.iter().flat_map(|(name, values)| {
        values
            .values()
            .map(move |v| (name.as_str(), v.expose_secret()))
    }))
}

pub struct LocalBackend {
    store: Store,
    audit: AuditLog,
    who: String,
}

impl LocalBackend {
    pub fn new(store: Store, dir: &Path) -> LocalBackend {
        let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
        LocalBackend {
            store,
            audit: AuditLog::new(dir.join("audit.jsonl")),
            who: format!("local:{user}"),
        }
    }

    fn record(
        &self,
        action: &str,
        entry: Option<&str>,
        outcome: Outcome,
        reason: Option<String>,
    ) -> Result<()> {
        self.audit.append(&Event {
            who: self.who.clone(),
            via: "local".into(),
            action: action.into(),
            entry: entry.map(str::to_string),
            result: outcome,
            reason,
            notify: None,
        })
    }

    /// Audits the outcome of an operation on one entry; an audit failure wins over the result.
    fn record_result<T>(&self, action: &str, entry: &str, result: Result<T>) -> Result<T> {
        match &result {
            Ok(_) => self.record(action, Some(entry), Outcome::Ok, None)?,
            Err(e) => self.record(action, Some(entry), Outcome::Error, Some(format!("{e:#}")))?,
        }
        result
    }

    fn apply_put(&self, name: &str, put: Put) -> Result<()> {
        validate_name(name)?;
        let mut vault = self.store.load()?;
        let entry = match (&put.values, vault.entries.contains_key(name)) {
            (None, false) => bail!("no entry named {name}"),
            (Some(values), _) if values.is_empty() => bail!("no KEY=VALUE pairs given"),
            _ => vault
                .entries
                .entry(name.to_string())
                .or_insert_with(Entry::default),
        };
        put.meta.apply(&mut entry.meta)?;
        if let Some(values) = put.values {
            entry.values = values;
        }
        self.store.save(&vault)
    }
}

impl Backend for LocalBackend {
    fn catalog(&self) -> Result<Catalog> {
        self.store.catalog()
    }

    fn fetch(&self, purpose: Purpose, selection: &Selection) -> Result<Fetched> {
        let action = purpose.action();
        let requested: Option<BTreeSet<&str>> = match selection {
            Selection::All => None,
            Selection::Names(names) => Some(names.iter().map(String::as_str).collect()),
        };
        // Entry-less actions are one line however many entries were read.
        let per_entry = matches!(purpose, Purpose::Run | Purpose::Render);

        let vault = match self.store.load() {
            Ok(vault) => vault,
            Err(e) => {
                let reason = format!("{e:#}");
                if let (Some(names), true) = (&requested, per_entry) {
                    for name in names {
                        self.record(action, Some(name), Outcome::Error, Some(reason.clone()))?;
                    }
                }
                return Err(e);
            }
        };
        let names: Vec<String> = match &requested {
            None => vault.entries.keys().cloned().collect(),
            Some(names) => {
                let missing: Vec<&str> = names
                    .iter()
                    .copied()
                    .filter(|n| !vault.entries.contains_key(*n))
                    .collect();
                if !missing.is_empty() {
                    for name in &missing {
                        self.record(
                            action,
                            Some(name),
                            Outcome::Error,
                            Some(format!("no entry named {name}")),
                        )?;
                    }
                    bail!("no entry named {}", missing[0]);
                }
                names.iter().map(|n| n.to_string()).collect()
            }
        };
        // Logged before the values leave the backend: if the audit write fails, none are released.
        if per_entry {
            for name in &names {
                self.record(action, Some(name), Outcome::Ok, None)?;
            }
        } else {
            self.record(action, None, Outcome::Ok, None)?;
        }
        let mut vault = vault;
        Ok(names
            .into_iter()
            .filter_map(|n| vault.entries.remove(&n).map(|e| (n, e.values)))
            .collect())
    }

    fn put(&self, name: &str, put: Put) -> Result<()> {
        let action = if put.values.is_some() { "put" } else { "edit" };
        let result = self.apply_put(name, put);
        self.record_result(action, name, result)
    }

    fn remove(&self, name: &str) -> Result<()> {
        let result = (|| {
            let mut vault = self.store.load()?;
            if vault.entries.remove(name).is_none() {
                bail!("no entry named {name}");
            }
            self.store.save(&vault)
        })();
        self.record_result("rm", name, result)
    }
}

/// Key names of values too short to be masked, for the `set` warning.
pub fn short_keys(values: &Values) -> Vec<&str> {
    values
        .iter()
        .filter(|(_, v)| v.expose_secret().len() < MIN_LEN)
        .map(|(k, _)| k.as_str())
        .collect()
}
