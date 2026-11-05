use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::{Decryptor, Encryptor, Identity, IdentityFile, Recipient};
use anyhow::{Context, Result, anyhow, bail};
use jiff::civil::Date;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::mask::MIN_LEN;

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
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vault::default()),
            Err(e) => {
                return Err(e).with_context(|| format!("cannot open {}", self.vault.display()));
            }
        };
        let identities = self.identity_file()?.into_identities()?;
        let mut reader = Decryptor::new(file)?
            .decrypt(identities.iter().map(|i| i.as_ref() as &dyn Identity))
            .with_context(|| format!("cannot decrypt {}", self.vault.display()))?;
        let mut plain = Zeroizing::new(Vec::new());
        reader.read_to_end(&mut plain)?;
        // Parse errors quote the offending text, which is vault content: never surface them.
        std::str::from_utf8(&plain)
            .ok()
            .and_then(|text| toml::from_str(text).ok())
            .ok_or_else(|| anyhow!("{} decrypts but does not parse", self.vault.display()))
    }

    /// Load, change and save the vault under an exclusive lock on `vault.lock`, held until the
    /// vault and the catalog are written. Nothing is saved if `change` fails. The lock is per open
    /// file, so it also serialises threads of one process; readers take none, the save is atomic.
    pub fn update<T>(&self, change: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&self.lock)
            .with_context(|| format!("cannot open {}", self.lock.display()))?;
        lock.lock()
            .with_context(|| format!("cannot lock {}", self.lock.display()))?;
        let mut vault = self.load()?;
        let result = change(&mut vault)?;
        self.save(&vault)?;
        Ok(result)
    }

    fn save(&self, vault: &Vault) -> Result<()> {
        let mut recipients = self.identity_file()?.to_recipients()?;
        for r in &self.recipients {
            let r = age::x25519::Recipient::from_str(r)
                .map_err(|e| anyhow!("invalid recipient {r} in config: {e}"))?;
            recipients.push(Box::new(r));
        }
        let plain = Zeroizing::new(toml::to_string(vault)?);
        let mut encrypted = Vec::new();
        let mut writer =
            Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as &dyn Recipient))?
                .wrap_output(&mut encrypted)?;
        writer.write_all(plain.as_bytes())?;
        writer.finish()?;
        write_atomic(&self.vault, &encrypted)?;

        write_atomic(
            &self.catalog,
            toml::to_string(&catalog_of(vault))?.as_bytes(),
        )
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
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}
