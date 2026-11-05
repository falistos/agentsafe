mod audit;
mod backend;
mod config;
mod dotenv;
mod init;
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
use minijinja::syntax::SyntaxConfig;
use minijinja::{Environment, UndefinedBehavior};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::backend::{
    Backend, LocalBackend, MetaPatch, Purpose, Put, Selection, Values, masker, short_keys,
};
use crate::config::{Config, Mode};
use crate::mask::{MIN_LEN, Masker};
use crate::vault::Store;

/// Secrets for AI agents: values go into child processes and files, never to the caller's output.
///
/// Config: `$AGENTSAFE_CONFIG` or `~/.config/agentsafe/config.toml`; `agentsafe init` creates it.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the config and a new age identity (or a remote config with --server).
    Init {
        /// Write a remote config pointing at this server URL; no identity is created.
        #[arg(long, value_name = "URL")]
        server: Option<String>,
    },
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
    Import {
        file: PathBuf,
        /// Name of the entry to store the file's pairs in.
        #[arg(long)]
        name: String,
        #[command(flatten)]
        meta: MetaArgs,
    },
    /// Change an entry's metadata; its values are untouched.
    Edit {
        name: String,
        #[command(flatten)]
        meta: MetaArgs,
    },
    /// Delete an entry.
    Rm { name: String },
    /// Run a command with entries in its environment and its output masked.
    Run {
        /// Entry to inject: NAME (all keys), NAME:KEY, or NAME:KEY=VAR; repeat for several.
        #[arg(long = "env", required = true, value_name = "NAME[:KEY[=VAR]]")]
        env: Vec<EnvSpec>,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// Render a template (`secrets["NAME"].KEY`) to stdout, which must be redirected to a file.
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

/// An empty value clears the field.
#[derive(Args)]
struct MetaArgs {
    /// What the entry is for; empty clears.
    #[arg(long)]
    description: Option<String>,
    /// Where the entry is used; repeat for several, empty clears.
    #[arg(long)]
    used_by: Vec<String>,
    /// Who owns the entry; empty clears.
    #[arg(long)]
    owner: Option<String>,
    /// Date the values must be rotated by (YYYY-MM-DD); empty clears.
    #[arg(long)]
    rotate_by: Option<String>,
    /// Free-form label; repeat for several, empty clears.
    #[arg(long = "tag")]
    tags: Vec<String>,
}

impl MetaArgs {
    fn into_patch(self, source: Option<String>) -> MetaPatch {
        // Repeatable flags: none given leaves the field alone, empty values only clear it.
        let list = |v: Vec<String>| {
            (!v.is_empty()).then(|| v.into_iter().filter(|s| !s.is_empty()).collect())
        };
        MetaPatch {
            description: self.description,
            used_by: list(self.used_by),
            owner: self.owner,
            rotate_by: self.rotate_by,
            tags: list(self.tags),
            source,
        }
    }
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
            eprintln!("agentsafe: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cmd: Cmd) -> Result<ExitCode> {
    if let Cmd::Init { server } = cmd {
        init::init(server)?;
        return Ok(ExitCode::SUCCESS);
    }
    let config = Config::load()?;
    let dir = config.dir().to_path_buf();
    let backend = match config.mode {
        Mode::Local {
            identity,
            recipients,
        } => LocalBackend::new(Store::new(&dir, identity, recipients), &dir),
        Mode::Remote { ref server } => bail!(
            "remote mode is not available yet (server = {server:?} in {})",
            config.path.display()
        ),
    };
    let backend: &dyn Backend = &backend;
    match cmd {
        Cmd::Init { .. } => unreachable!("handled above"),
        Cmd::List => list(backend)?,
        Cmd::Describe { name } => describe(backend, &name)?,
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
            store_entry(backend, &name, values, meta, None)?;
        }
        Cmd::Import { file, name, meta } => {
            let text = Zeroizing::new(
                fs::read_to_string(&file)
                    .with_context(|| format!("cannot read {}", file.display()))?,
            );
            let values = dotenv::parse(&text).with_context(|| file.display().to_string())?;
            let source = file.canonicalize()?.to_string_lossy().into_owned();
            store_entry(backend, &name, values, meta, Some(source))?;
        }
        Cmd::Edit { name, meta } => {
            let patch = meta.into_patch(None);
            if patch.is_empty() {
                bail!(
                    "nothing to change: pass --description, --used-by, --owner, --rotate-by or --tag"
                );
            }
            backend.put(
                &name,
                Put {
                    values: None,
                    meta: patch,
                },
            )?;
            eprintln!("edited {name}");
        }
        Cmd::Rm { name } => {
            backend.remove(&name)?;
            eprintln!("removed {name}");
        }
        Cmd::Run { env, command } => return run_child(backend, &env, &command),
        Cmd::Render { template, allow } => render(backend, &template, allow)?,
        Cmd::Scrub => {
            let fetched = backend.fetch(Purpose::Scrub, &Selection::All)?;
            masker(&fetched).copy(io::stdin().lock(), io::stdout().lock())?;
        }
        Cmd::VerifyImport { dir } => return verify_import(backend, &dir),
    }
    Ok(ExitCode::SUCCESS)
}

fn list(backend: &dyn Backend) -> Result<()> {
    let dash = |s: Option<String>| s.filter(|s| !s.is_empty()).unwrap_or("-".into());
    println!("NAME\tKEYS\tOWNER\tROTATE_BY\tTAGS\tDESCRIPTION");
    for (name, e) in backend.catalog()? {
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

fn describe(backend: &dyn Backend, name: &str) -> Result<()> {
    let mut catalog = backend.catalog()?;
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
    backend: &dyn Backend,
    name: &str,
    values: BTreeMap<String, String>,
    meta: MetaArgs,
    source: Option<String>,
) -> Result<()> {
    let values: Values = values
        .into_iter()
        .map(|(k, v)| (k, SecretString::from(v)))
        .collect();
    let short = short_keys(&values);
    if !short.is_empty() {
        eprintln!(
            "warning: {} under {MIN_LEN} bytes, will not be masked",
            short.join(", ")
        );
    }
    let count = values.len();
    backend.put(
        name,
        Put {
            values: Some(values),
            meta: meta.into_patch(source),
        },
    )?;
    eprintln!("stored {name} ({count} keys)");
    Ok(())
}

fn run_child(backend: &dyn Backend, specs: &[EnvSpec], command: &[OsString]) -> Result<ExitCode> {
    let names = specs.iter().map(|s| s.name.clone()).collect();
    let fetched = backend.fetch(Purpose::Run, &Selection::Names(names))?;
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for spec in specs {
        let values = &fetched[&spec.name];
        match &spec.key {
            None => {
                for (k, v) in values {
                    cmd.env(k, v.expose_secret());
                }
            }
            Some(key) => {
                let v = values
                    .get(key)
                    .ok_or_else(|| anyhow!("entry {} has no key {key}", spec.name))?;
                cmd.env(spec.var.as_ref().unwrap_or(key), v.expose_secret());
            }
        }
    }
    let masker = masker(&fetched);
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

fn render(backend: &dyn Backend, template: &Path, allow: Vec<String>) -> Result<()> {
    let out = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    if !out.metadata()?.is_file() {
        bail!("stdout must be redirected to a file: agentsafe render TEMPLATE --allow NAME > FILE");
    }
    out.set_permissions(Permissions::from_mode(0o600))?;
    let source = fs::read_to_string(template)
        .with_context(|| format!("cannot read {}", template.display()))?;
    let fetched = backend.fetch(Purpose::Render, &Selection::Names(allow))?;
    let ctx: BTreeMap<String, BTreeMap<String, String>> = fetched
        .iter()
        .map(|(name, values)| {
            let values = values
                .iter()
                .map(|(k, v)| (k.clone(), v.expose_secret().to_string()))
                .collect();
            (name.clone(), values)
        })
        .collect();
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
        .render_str(&source, BTreeMap::from([("secrets", ctx)]))
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

fn verify_import(backend: &dyn Backend, dir: &Path) -> Result<ExitCode> {
    let catalog = backend.catalog()?;
    let fetched = backend.fetch(Purpose::VerifyImport, &Selection::All)?;
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
        let Some((name, values)) = catalog
            .iter()
            .find(|(_, e)| e.meta.source.as_deref() == Some(&source))
            .and_then(|(name, _)| fetched.get_key_value(name))
        else {
            println!("{file_name}\t-\tNOT IMPORTED");
            all_ok = false;
            continue;
        };
        let text = Zeroizing::new(fs::read_to_string(&path).unwrap_or_default());
        let same = dotenv::parse(&text).is_ok_and(|parsed| {
            dotenv::fingerprint(parsed.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                == dotenv::fingerprint(values.iter().map(|(k, v)| (k.as_str(), v.expose_secret())))
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
