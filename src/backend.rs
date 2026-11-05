use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use anyhow::Result;
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
    /// A fetch through the server's API.
    Get,
}

impl Purpose {
    fn action(self) -> &'static str {
        match self {
            Purpose::Run => "run",
            Purpose::Render => "render",
            Purpose::Scrub => "scrub",
            Purpose::VerifyImport => "verify-import",
            Purpose::Get => "get",
        }
    }
}

pub enum Selection {
    All,
    Names(Vec<String>),
}

/// An error the caller can fix, which the server answers with 404 or 400.
#[derive(Debug)]
pub enum Refusal {
    NotFound(String),
    Invalid(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Refusal::NotFound(name) => write!(f, "no entry named {name}"),
            Refusal::Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Refusal {}

/// A metadata change: an absent field is left alone, an empty one clears it.
/// `rotate_by` is `YYYY-MM-DD`, or empty to clear.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
            // The rejected text is not quoted: it reaches API answers and the audit log.
            Some(d) => Some(Some(Date::from_str(&d).map_err(|_| {
                Refusal::Invalid("invalid rotate-by: use YYYY-MM-DD".into())
            })?)),
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

/// Serializes values in clear, for the API's request and response bodies only.
pub struct Exposed<'a>(pub &'a Values);

impl Serialize for Exposed<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(self.0.iter().map(|(k, v)| (k, v.expose_secret())))
    }
}

/// A masker for everything that was fetched, entry by entry.
pub fn masker(fetched: &Fetched) -> Masker {
    Masker::new(fetched.iter().flat_map(|(name, values)| {
        values
            .values()
            .map(move |v| (name.as_str(), v.expose_secret()))
    }))
}

/// Who the audit log names for an operation, and through what.
#[derive(Clone)]
pub struct Caller {
    pub who: String,
    pub via: &'static str,
}

/// The age vault on this machine. The `Backend` impl acts as the local user; the server calls
/// the `*_as` methods with the identity of each request.
pub struct LocalBackend {
    store: Store,
    audit: AuditLog,
    user: Caller,
}

impl LocalBackend {
    pub fn new(store: Store, dir: &Path) -> LocalBackend {
        let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
        LocalBackend {
            store,
            audit: AuditLog::new(dir.join("audit.jsonl")),
            user: Caller {
                who: format!("local:{user}"),
                via: "local",
            },
        }
    }

    /// Records a request refused before it reached the vault.
    pub fn record_denied(
        &self,
        caller: &Caller,
        action: &str,
        entry: Option<&str>,
        reason: &str,
    ) -> Result<()> {
        self.record(
            caller,
            action,
            entry,
            Outcome::Denied,
            Some(reason.to_string()),
        )
    }

    fn record(
        &self,
        caller: &Caller,
        action: &str,
        entry: Option<&str>,
        outcome: Outcome,
        reason: Option<String>,
    ) -> Result<()> {
        self.record_notified(caller, action, entry, outcome, reason, None)
    }

    fn record_notified(
        &self,
        caller: &Caller,
        action: &str,
        entry: Option<&str>,
        outcome: Outcome,
        reason: Option<String>,
        notify: Option<&str>,
    ) -> Result<()> {
        self.audit.append(&Event {
            who: caller.who.clone(),
            via: caller.via.into(),
            action: action.into(),
            entry: entry.map(str::to_string),
            result: outcome,
            reason,
            notify: notify.map(str::to_string),
        })
    }

    /// Audits the outcome of an operation on one entry; an audit failure wins over the result.
    fn record_result<T>(
        &self,
        caller: &Caller,
        action: &str,
        entry: &str,
        result: Result<T>,
    ) -> Result<T> {
        match &result {
            Ok(_) => self.record(caller, action, Some(entry), Outcome::Ok, None)?,
            Err(e) => self.record(
                caller,
                action,
                Some(entry),
                Outcome::Error,
                Some(format!("{e:#}")),
            )?,
        }
        result
    }

    fn apply_put(&self, name: &str, put: Put) -> Result<()> {
        validate_name(name).map_err(|e| Refusal::Invalid(e.to_string()))?;
        self.store.update(|vault| {
            let entry = match (&put.values, vault.entries.contains_key(name)) {
                (None, false) => return Err(Refusal::NotFound(name.into()).into()),
                (Some(values), _) if values.is_empty() => {
                    return Err(Refusal::Invalid("no KEY=VALUE pairs given".into()).into());
                }
                _ => vault
                    .entries
                    .entry(name.to_string())
                    .or_insert_with(Entry::default),
            };
            put.meta.apply(&mut entry.meta)?;
            if let Some(values) = put.values {
                entry.values = values;
            }
            Ok(())
        })
    }

    pub fn fetch_as(
        &self,
        caller: &Caller,
        purpose: Purpose,
        selection: &Selection,
    ) -> Result<Fetched> {
        let action = purpose.action();
        let requested: Option<BTreeSet<&str>> = match selection {
            Selection::All => None,
            Selection::Names(names) => Some(names.iter().map(String::as_str).collect()),
        };
        // Entry-less actions are one line however many entries were read.
        let per_entry = matches!(purpose, Purpose::Run | Purpose::Render | Purpose::Get);

        let vault = match self.store.load() {
            Ok(vault) => vault,
            Err(e) => {
                let reason = format!("{e:#}");
                if let (Some(names), true) = (&requested, per_entry) {
                    for name in names {
                        self.record(
                            caller,
                            action,
                            Some(name),
                            Outcome::Error,
                            Some(reason.clone()),
                        )?;
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
                            caller,
                            action,
                            Some(name),
                            Outcome::Error,
                            Some(format!("no entry named {name}")),
                        )?;
                    }
                    return Err(Refusal::NotFound(missing[0].into()).into());
                }
                names.iter().map(|n| n.to_string()).collect()
            }
        };
        // Logged before the values leave the backend: if the audit write fails, none are released.
        if per_entry {
            for name in &names {
                self.record(caller, action, Some(name), Outcome::Ok, None)?;
            }
        } else {
            self.record(caller, action, None, Outcome::Ok, None)?;
        }
        let mut vault = vault;
        Ok(names
            .into_iter()
            .filter_map(|n| vault.entries.remove(&n).map(|e| (n, e.values)))
            .collect())
    }

    /// The values of one entry for the admin UI, audited as `reveal` with the reason. `notify`
    /// takes the message for the owner and says whether it was delivered; it runs before the
    /// audit line, which records the outcome and is written before any value is released.
    pub fn reveal_as(
        &self,
        caller: &Caller,
        name: &str,
        reason: &str,
        notify: Option<impl Fn(&str) -> bool>,
    ) -> Result<Values> {
        let mut vault = match self.store.load() {
            Ok(vault) => vault,
            Err(e) => {
                let why = format!("{e:#}");
                self.record(caller, "reveal", Some(name), Outcome::Error, Some(why))?;
                return Err(e);
            }
        };
        let Some(entry) = vault.entries.remove(name) else {
            let why = format!("no entry named {name}");
            self.record(caller, "reveal", Some(name), Outcome::Error, Some(why))?;
            return Err(Refusal::NotFound(name.into()).into());
        };
        let notified = notify.map(|send| {
            if send(&format!("{} revealed {name}: {reason}", caller.who)) {
                "sent"
            } else {
                "failed"
            }
        });
        self.record_notified(
            caller,
            "reveal",
            Some(name),
            Outcome::Ok,
            Some(reason.to_string()),
            notified,
        )?;
        Ok(entry.values)
    }

    pub fn put_as(&self, caller: &Caller, name: &str, put: Put) -> Result<()> {
        let action = if put.values.is_some() { "put" } else { "edit" };
        let result = self.apply_put(name, put);
        self.record_result(caller, action, name, result)
    }

    pub fn remove_as(&self, caller: &Caller, name: &str) -> Result<()> {
        let result = self.store.update(|vault| {
            if vault.entries.remove(name).is_none() {
                return Err(Refusal::NotFound(name.into()).into());
            }
            Ok(())
        });
        self.record_result(caller, "rm", name, result)
    }
}

impl Backend for LocalBackend {
    fn catalog(&self) -> Result<Catalog> {
        self.store.catalog()
    }

    fn fetch(&self, purpose: Purpose, selection: &Selection) -> Result<Fetched> {
        self.fetch_as(&self.user, purpose, selection)
    }

    fn put(&self, name: &str, put: Put) -> Result<()> {
        self.put_as(&self.user, name, put)
    }

    fn remove(&self, name: &str) -> Result<()> {
        self.remove_as(&self.user, name)
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
