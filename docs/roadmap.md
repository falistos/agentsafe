# Roadmap

## Phase 1 (this release)

Local CLI that reads the vault directly: `init`, `list`, `describe`, `set`, `import`, `edit`, `rm`,
`run` with masked pipes, `render`, `scrub`, `verify-import`, and a local `audit.jsonl`.

## Phase 2: daemon and web UI

- `agentsafe serve` daemon under launchd: decrypts the vault once, serves the CLI over a 0600 Unix socket
  and checks the caller with `peer_cred`. The CLI and the `PostToolUse` hook stop holding the
  identity themselves.
- Caller identity on the tailnet with Tailscale `WhoIs` through the LocalAPI; per-tag policy
  (`policy.toml`) for tagged nodes, full UI for the owner's user nodes only.
- Append-only audit log (`audit.jsonl`): caller, action, entry, result; never a value.
- Web UI on the tailnet IP (no proxy in front, so the peer address stays real): list, metadata
  editing, add, reveal with a mandatory reason, an audit line and a ntfy notification.
- `agentsafe run --interactive` through a pty, `export` to regenerate `~/.secrets` byte for byte, and
  `export --check`.

## Phase 3: svc1

Move the daemon to svc1, add its identity as a vault recipient, serve `render` to other hosts under
their tag policy, and remove the keys from the mini.
