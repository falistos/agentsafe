//! Kernel restrictions on the agentsafe process itself.

use anyhow::{Context, Result};
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

/// No core dump, and on Linux no same-user ptrace or `/proc/PID/mem` read: any of them would
/// expose decrypted values. A child of `run` inherits the core limit as its soft limit only.
pub fn process() -> Result<()> {
    let core = getrlimit(Resource::Core);
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: core.maximum,
        },
    )
    .context("cannot disable core dumps")?;
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .context("cannot make the process non-dumpable")?;
    Ok(())
}

/// Confines `serve` with Landlock: read and write only beneath `writable`, read the `readable`
/// files and `/etc` (name resolution for ntfy), no TCP bind, no signal or abstract socket
/// outside the process. Returns how much the kernel enforces.
#[cfg(target_os = "linux")]
pub fn sandbox(
    writable: &[&std::path::Path],
    readable: &[&std::path::Path],
) -> Result<&'static str> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
        Scope, path_beneath_rules,
    };
    let abi = ABI::V6;
    let read = AccessFs::from_read(abi) & !AccessFs::Execute;
    let write = AccessFs::from_all(abi) & !AccessFs::Execute;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::BindTcp)?
        .scope(Scope::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(writable, write))?
        .add_rules(path_beneath_rules(readable, read))?
        .add_rules(path_beneath_rules(["/etc"], read))?
        .restrict_self()
        .context("cannot enable Landlock")?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => "enforced",
        RulesetStatus::PartiallyEnforced => "partly enforced (older kernel)",
        RulesetStatus::NotEnforced => "not enforced (kernel without Landlock)",
    })
}
