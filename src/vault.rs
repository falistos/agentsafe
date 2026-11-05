use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::{Decryptor, Encryptor, Identity, IdentityFile, Recipient};
use anyhow::{Context, Result, anyhow, bail};
use jiff::civil::Date;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::mask::{MIN_LEN, Masker};

#[derive(Deserialize)]
struct Config {
    identity: PathBuf,
    /// Extra age recipients, e.g. an offline recovery key.
    #[serde(default)]
    recipients: Vec<String>,
}

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

impl Vault {
    pub fn masker(&self) -> Masker {
        Masker::new(self.entries.iter().flat_map(|(name, e)| {
            e.values
                .values()
                .map(move |v| (name.as_str(), v.expose_secret()))
        }))
    }
}

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
}

impl Store {
    /// Reads `$SAFE_CONFIG`, or `~/.config/safe/config.toml`; the vault and catalog live next to it.
    pub fn open() -> Result<Store> {
        let path = match std::env::var_os("SAFE_CONFIG") {
            Some(p) => PathBuf::from(p),
            None => home()?.join(".config/safe/config.toml"),
        };
        let text = fs::read_to_string(&path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new("."));
        let identity = match config.identity.strip_prefix("~") {
            Ok(rest) => home()?.join(rest),
            Err(_) => config.identity,
        };
        Ok(Store {
            identity,
            recipients: config.recipients,
            vault: dir.join("vault.age"),
            catalog: dir.join("catalog.toml"),
        })
    }

    pub fn catalog(&self) -> Result<Catalog> {
        match fs::read_to_string(&self.catalog) {
            Ok(text) => toml::from_str(&text)
                .with_context(|| format!("invalid catalog {}", self.catalog.display())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Catalog::new()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", self.catalog.display())),
        }
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

    pub fn save(&self, vault: &Vault) -> Result<()> {
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

        let catalog: Catalog = vault
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
            .collect();
        write_atomic(&self.catalog, toml::to_string(&catalog)?.as_bytes())
    }

    fn identity_file(&self) -> Result<IdentityFile<age::NoCallbacks>> {
        IdentityFile::from_file(self.identity.to_string_lossy().into_owned())
            .with_context(|| format!("cannot read identity {}", self.identity.display()))
    }
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

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
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
