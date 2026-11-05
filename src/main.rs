mod dotenv;
mod mask;
mod vault;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::str::FromStr;
use std::thread;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use jiff::civil::Date;
use minijinja::syntax::SyntaxConfig;
use minijinja::{Environment, UndefinedBehavior};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::mask::{MIN_LEN, Masker};
use crate::vault::{Entry, Store, Vault, validate_name};

/// Secrets for AI agents: values go into child processes and files, never to the caller's output.
///
/// Configuration: `$SAFE_CONFIG` or `~/.config/safe/config.toml`, with `identity = "<age identity
/// file>"` and optional `recipients = ["age1…"]`. `vault.age` and `catalog.toml` sit next to it.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List entries with their metadata.
    List,
    /// Show one entry's metadata and key names, never its values.
    Describe { name: String },
    /// Create or replace an entry's values, read from stdin as KEY=VALUE lines.
    Set {
        name: String,
        /// Store all of stdin (minus one trailing newline) as this single key.
        #[arg(long)]
        key: Option<String>,
        #[command(flatten)]
        meta: MetaArgs,
    },
    /// Create or replace an entry from a .env file.
    ImportEnv {
        file: PathBuf,
        #[arg(long)]
        name: String,
        #[command(flatten)]
        meta: MetaArgs,
    },
    /// Run a command with entries in its environment and its output masked.
    ///
    /// `--env NAME` injects every key of the entry under its own name; `NAME:KEY` injects one key,
    /// `NAME:KEY=VAR` injects it as VAR. The child's stdout and stderr are pipes, even from a
    /// terminal, and every known value is replaced with ***NAME*** in them, also when base64,
    /// hex, JSON- or URL-encoded. Not masked: values under 6 bytes, hashed, encrypted, reversed or
    /// otherwise transformed output, and anything the child writes to files or the network.
    Run {
        #[arg(long = "env", required = true, value_name = "NAME[:KEY[=VAR]]")]
        env: Vec<EnvSpec>,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// Render a minijinja template to stdout, which must be redirected to a file (made 0600).
    ///
    /// Allowed entries are exposed as `safe["NAME"].KEY`.
    Render {
        template: PathBuf,
        /// Entry the template may read; repeat for several.
        #[arg(long, required = true)]
        allow: Vec<String>,
    },
    /// Copy stdin to stdout with every known value masked.
    Scrub,
    /// Compare each file of a directory with the entry imported from it, by fingerprint.
    VerifyImport { dir: PathBuf },
}

#[derive(Args)]
struct MetaArgs {
    #[arg(long)]
    description: Option<String>,
    /// Where the entry is used; repeat for several.
    #[arg(long)]
    used_by: Vec<String>,
    #[arg(long)]
    owner: Option<String>,
    /// Date the values must be rotated by (YYYY-MM-DD).
    #[arg(long)]
    rotate_by: Option<Date>,
    /// Repeat for several.
    #[arg(long = "tag")]
    tags: Vec<String>,
}

#[derive(Clone)]
struct EnvSpec {
    name: String,
    key: Option<String>,
    var: Option<String>,
}

impl FromStr for EnvSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (name, rest) = match s.split_once(':') {
            Some((name, rest)) => (name, Some(rest)),
            None => (s, None),
        };
        let (key, var) = match rest.map(|r| r.split_once('=').unwrap_or((r, ""))) {
            Some((key, var)) => (Some(key.to_string()), Some(var).filter(|v| !v.is_empty())),
            None => (None, None),
        };
        if name.is_empty() || key.as_deref() == Some("") {
            return Err("expected NAME, NAME:KEY or NAME:KEY=VAR".into());
        }
        Ok(EnvSpec {
            name: name.to_string(),
            key,
            var: var.map(str::to_string),
        })
    }
}

fn main() -> ExitCode {
    match run(Cli::parse().cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("safe: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cmd: Cmd) -> Result<ExitCode> {
    let store = Store::open()?;
    match cmd {
        Cmd::List => list(&store)?,
        Cmd::Describe { name } => describe(&store, &name)?,
        Cmd::Set { name, key, meta } => {
            let mut input = Zeroizing::new(String::new());
            io::stdin()
                .read_to_string(&mut input)
                .context("stdin is not UTF-8 text")?;
            let values = match key {
                Some(key) => {
                    let value = input.strip_suffix('\n').unwrap_or(&input);
                    BTreeMap::from([(key, value.to_string())])
                }
                None => dotenv::parse(&input).context("stdin")?,
            };
            store_entry(&store, &name, values, meta, None)?;
        }
        Cmd::ImportEnv { file, name, meta } => {
            let text = Zeroizing::new(
                fs::read_to_string(&file)
                    .with_context(|| format!("cannot read {}", file.display()))?,
            );
            let values = dotenv::parse(&text).with_context(|| file.display().to_string())?;
            let source = file.canonicalize()?.to_string_lossy().into_owned();
            store_entry(&store, &name, values, meta, Some(source))?;
        }
        Cmd::Run { env, command } => return run_child(&store, &env, &command),
        Cmd::Render { template, allow } => render(&store, &template, &allow)?,
        Cmd::Scrub => store
            .load()?
            .masker()
            .copy(io::stdin().lock(), io::stdout().lock())?,
        Cmd::VerifyImport { dir } => return verify_import(&store, &dir),
    }
    Ok(ExitCode::SUCCESS)
}

fn list(store: &Store) -> Result<()> {
    let dash = |s: Option<String>| s.filter(|s| !s.is_empty()).unwrap_or("-".into());
    println!("NAME\tKEYS\tOWNER\tROTATE_BY\tTAGS\tDESCRIPTION");
    for (name, e) in store.catalog()? {
        println!(
            "{name}\t{}\t{}\t{}\t{}\t{}",
            e.keys.len(),
            dash(e.meta.owner),
            dash(e.meta.rotate_by.map(|d| d.to_string())),
            dash(Some(e.meta.tags.join(","))),
            dash(e.meta.description),
        );
    }
    Ok(())
}

fn describe(store: &Store, name: &str) -> Result<()> {
    let mut catalog = store.catalog()?;
    let e = catalog
        .remove(name)
        .ok_or_else(|| anyhow!("no entry named {name}"))?;
    let m = e.meta;
    let fields = [
        ("name", Some(name.to_string())),
        ("description", m.description),
        ("keys", Some(e.keys.join(", "))),
        (
            "unmasked",
            (!e.unmasked.is_empty())
                .then(|| format!("{} (under {MIN_LEN} bytes)", e.unmasked.join(", "))),
        ),
        ("used_by", Some(m.used_by.join(", "))),
        ("owner", m.owner),
        ("rotate_by", m.rotate_by.map(|d| d.to_string())),
        ("tags", Some(m.tags.join(", "))),
        ("source", m.source),
    ];
    for (label, value) in fields {
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            println!("{label}: {v}");
        }
    }
    Ok(())
}

fn store_entry(
    store: &Store,
    name: &str,
    values: BTreeMap<String, String>,
    meta: MetaArgs,
    source: Option<String>,
) -> Result<()> {
    validate_name(name)?;
    if values.is_empty() {
        bail!("no KEY=VALUE pairs given");
    }
    let mut vault = store.load()?;
    let entry = vault
        .entries
        .entry(name.to_string())
        .or_insert_with(Entry::default);
    let short: Vec<&str> = values
        .iter()
        .filter(|(_, v)| v.len() < MIN_LEN)
        .map(|(k, _)| k.as_str())
        .collect();
    if !short.is_empty() {
        eprintln!(
            "warning: {} under {MIN_LEN} bytes, will not be masked",
            short.join(", ")
        );
    }
    let count = values.len();
    entry.values = values
        .into_iter()
        .map(|(k, v)| (k, SecretString::from(v)))
        .collect();
    let m = &mut entry.meta;
    if meta.description.is_some() {
        m.description = meta.description;
    }
    if !meta.used_by.is_empty() {
        m.used_by = meta.used_by;
    }
    if meta.owner.is_some() {
        m.owner = meta.owner;
    }
    if meta.rotate_by.is_some() {
        m.rotate_by = meta.rotate_by;
    }
    if !meta.tags.is_empty() {
        m.tags = meta.tags;
    }
    if source.is_some() {
        m.source = source;
    }
    store.save(&vault)?;
    eprintln!("stored {name} ({count} keys)");
    Ok(())
}

fn run_child(store: &Store, specs: &[EnvSpec], command: &[OsString]) -> Result<ExitCode> {
    let vault = store.load()?;
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for spec in specs {
        let entry = get(&vault, &spec.name)?;
        match &spec.key {
            None => {
                for (k, v) in &entry.values {
                    cmd.env(k, v.expose_secret());
                }
            }
            Some(key) => {
                let v = entry
                    .values
                    .get(key)
                    .ok_or_else(|| anyhow!("entry {} has no key {key}", spec.name))?;
                cmd.env(spec.var.as_ref().unwrap_or(key), v.expose_secret());
            }
        }
    }
    let masker = vault.masker();
    let mut child = cmd
        .spawn()
        .with_context(|| format!("cannot run {}", command[0].to_string_lossy()))?;
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    thread::scope(|s| {
        s.spawn(|| pump(&masker, stdout, io::stdout()));
        s.spawn(|| pump(&masker, stderr, io::stderr()));
    });
    let status = child.wait()?;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    Ok(ExitCode::from(code as u8))
}

/// If our own output closes, keep draining the child so it is not blocked on a full pipe.
fn pump(masker: &Masker, mut from: impl Read, to: impl Write) {
    if masker.copy(&mut from, to).is_err() {
        let _ = io::copy(&mut from, &mut io::sink());
    }
}

fn render(store: &Store, template: &Path, allow: &[String]) -> Result<()> {
    let out = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    if !out.metadata()?.is_file() {
        bail!("stdout must be redirected to a file: safe render TEMPLATE --allow NAME > FILE");
    }
    out.set_permissions(Permissions::from_mode(0o600))?;
    let source = fs::read_to_string(template)
        .with_context(|| format!("cannot read {}", template.display()))?;
    let vault = store.load()?;
    let mut ctx = BTreeMap::new();
    for name in allow {
        let values: BTreeMap<String, String> = get(&vault, name)?
            .values
            .iter()
            .map(|(k, v)| (k.clone(), v.expose_secret().to_string()))
            .collect();
        ctx.insert(name.clone(), values);
    }
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    env.set_syntax(
        SyntaxConfig::builder()
            .keep_trailing_newline(true)
            .build()
            .expect("default delimiters are valid"),
    );
    // Error details can quote rendered values: report only the kind and the line.
    let rendered = env
        .render_str(&source, BTreeMap::from([("safe", ctx)]))
        .map_err(|e| {
            anyhow!(
                "template error: {} at line {}",
                e.kind(),
                e.line().unwrap_or(0)
            )
        })?;
    let rendered = Zeroizing::new(rendered);
    (&out).write_all(rendered.as_bytes())?;
    Ok(())
}

fn verify_import(store: &Store, dir: &Path) -> Result<ExitCode> {
    let vault = store.load()?;
    let mut files = Vec::new();
    for item in fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let path = item?.path();
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    let mut all_ok = true;
    for path in files {
        let file_name = path.file_name().unwrap_or_default().to_string_lossy();
        let source = path.canonicalize()?.to_string_lossy().into_owned();
        let Some((name, entry)) = vault
            .entries
            .iter()
            .find(|(_, e)| e.meta.source.as_deref() == Some(&source))
        else {
            println!("{file_name}\t-\tNOT IMPORTED");
            all_ok = false;
            continue;
        };
        let text = Zeroizing::new(fs::read_to_string(&path).unwrap_or_default());
        let same = dotenv::parse(&text).is_ok_and(|parsed| {
            dotenv::fingerprint(parsed.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                == dotenv::fingerprint(
                    entry
                        .values
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.expose_secret())),
                )
        });
        println!(
            "{file_name}\t{name}\t{}",
            if same { "OK" } else { "MISMATCH" }
        );
        all_ok &= same;
    }
    Ok(if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn get<'a>(vault: &'a Vault, name: &str) -> Result<&'a Entry> {
    vault
        .entries
        .get(name)
        .ok_or_else(|| anyhow!("no entry named {name}"))
}
