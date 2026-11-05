use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use age::{Decryptor, Encryptor, Identity, IdentityFile, Recipient};
use anyhow::{Context, Result, anyhow, bail};
use jiff::civil::Date;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::mask::MIN_LEN;

/// How long a write waits for `vault.lock` before it gives up as busy.
const LOCK_WAIT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Meta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub used_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_by: Option<Date>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Canonical path of the file the values were imported from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Entry {
    pub meta: Meta,
    #[serde(serialize_with = "expose_values")]
    pub values: BTreeMap<String, SecretString>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    #[serde(default)]
    pub entries: BTreeMap<String, Entry>,
}

/// An entry as the catalog shows it: metadata and key names, never values.
#[derive(Serialize, Deserialize)]
pub struct CatalogEntry {
    #[serde(flatten)]
    pub meta: Meta,
    pub keys: Vec<String>,
    /// Keys whose value is too short to be masked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmasked: Vec<String>,
}

pub type Catalog = BTreeMap<String, CatalogEntry>;

pub struct Store {
    identity: PathBuf,
    recipients: Vec<String>,
    vault: PathBuf,
    catalog: PathBuf,
    lock: PathBuf,
}

impl Store {
    /// The vault, its lock and the catalog export live in `dir`, next to the config.
    pub fn new(dir: &Path, identity: PathBuf, recipients: Vec<String>) -> Store {
        Store {
            identity,
            recipients,
            vault: dir.join("vault.age"),
            catalog: dir.join("catalog.toml"),
            lock: dir.join("vault.lock"),
        }
    }

    /// Derived from the decrypted vault; `catalog.toml` is an export and is never read back.
    pub fn catalog(&self) -> Result<Catalog> {
        Ok(catalog_of(&self.load()?))
    }

    pub fn load(&self) -> Result<Vault> {
        let file = match File::open(&self.vault) {
            Ok(f) => f,
            // Never an empty vault: `scrub` would then mask nothing.
            Err(e) if e.kind() == ErrorKind::NotFound => bail!(
                "no vault at {}: `agentsafe init` creates one, or restore it from a backup",
                self.vault.display()
            ),
            Err(e) => {
                return Err(e).with_context(|| format!("cannot open {}", self.vault.display()));
            }
        };
        let identities = self.identity_file()?.into_identities()?;
        let cannot_decrypt = || format!("cannot decrypt {}", self.vault.display());
        let mut reader = Decryptor::new(file)
            .with_context(cannot_decrypt)?
            .decrypt(identities.iter().map(|i| -> &dyn Identity { i.as_ref() }))
            .with_context(cannot_decrypt)?;
        let mut plain = Zeroizing::new(Vec::new());
        reader
            .read_to_end(&mut plain)
            .with_context(cannot_decrypt)?;
        // Parse errors quote the offending text, which is vault content: never surface them.
        std::str::from_utf8(&plain)
            .ok()
            .and_then(|text| toml::from_str(text).ok())
            .ok_or_else(|| anyhow!("{} decrypts but does not parse", self.vault.display()))
    }

    /// Writes an empty vault, for `init`.
    pub fn create(&self) -> Result<()> {
        self.save(&Vault::default())
    }

    /// Load, change and save the vault under an exclusive lock on `vault.lock`, held until the
    /// vault and the catalog are written. Nothing is saved if `change` fails. The lock is per open
    /// file, so it also serialises threads of one process; readers take none, the save is atomic.
    /// The lock is awaited at most `LOCK_WAIT`, so a write waiting on it cannot hold up a shutdown.
    pub fn update<T>(&self, change: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&self.lock)
            .with_context(|| format!("cannot open {}", self.lock.display()))?;
        let deadline = Instant::now() + LOCK_WAIT;
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(TryLockError::WouldBlock) => {
                    bail!("vault is busy ({} is locked)", self.lock.display())
                }
                Err(TryLockError::Error(e)) => {
                    return Err(e).with_context(|| format!("cannot lock {}", self.lock.display()));
                }
            }
        }
        let mut vault = self.load()?;
        let result = change(&mut vault)?;
        self.save(&vault)?;
        Ok(result)
    }

    fn save(&self, vault: &Vault) -> Result<()> {
        let mut recipients = self.identity_file()?.to_recipients()?;
        for (i, r) in self.recipients.iter().enumerate() {
            // Not quoted: a secret key pasted here by mistake would be printed.
            let r = age::x25519::Recipient::from_str(r)
                .map_err(|e| anyhow!("invalid recipient #{} in the config: {e}", i + 1))?;
            recipients.push(Box::new(r));
        }
        let plain = Zeroizing::new(toml::to_string(vault)?);
        let mut encrypted = Vec::new();
        let mut writer = Encryptor::with_recipients(
            recipients.iter().map(|r| -> &dyn Recipient { r.as_ref() }),
        )?
        .wrap_output(&mut encrypted)?;
        writer.write_all(plain.as_bytes())?;
        writer.finish()?;
        write_atomic(&self.vault, &encrypted)?;

        // The vault is the commit: a failed export is repaired by the next write.
        let exported = toml::to_string(&catalog_of(vault))
            .map_err(anyhow::Error::from)
            .and_then(|text| write_atomic(&self.catalog, text.as_bytes()));
        if let Err(e) = exported {
            eprintln!("agentsafe: warning: the change is saved, but {e:#}");
        }
        Ok(())
    }

    fn identity_file(&self) -> Result<IdentityFile<age::NoCallbacks>> {
        IdentityFile::from_file(self.identity.to_string_lossy().into_owned())
            .with_context(|| format!("cannot read identity {}", self.identity.display()))
    }
}

fn catalog_of(vault: &Vault) -> Catalog {
    vault
        .entries
        .iter()
        .map(|(name, e)| {
            let entry = CatalogEntry {
                meta: e.meta.clone(),
                keys: e.values.keys().cloned().collect(),
                unmasked: e
                    .values
                    .iter()
                    .filter(|(_, v)| v.expose_secret().len() < MIN_LEN)
                    .map(|(k, _)| k.clone())
                    .collect(),
            };
            (name.clone(), entry)
        })
        .collect()
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        bail!("invalid entry name {name:?}: use letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

fn expose_values<S: Serializer>(
    values: &BTreeMap<String, SecretString>,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.collect_map(values.iter().map(|(k, v)| (k, v.expose_secret())))
}

/// The temp file is created 0600 by `tempfile` and renamed over the target, so readers never see
/// a partial file and the mode never widens.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    // A bare file name has an empty parent, which cannot be opened to sync.
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}
