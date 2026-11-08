# Roadmap

## Done

- Local CLI on an age vault: `init`, `list`, `describe`, `set`, `import`, `edit`, `rm`, `run` with
  masked output, `render`, `scrub`, `verify-import`.
- Streamed masking of raw values, base64, hex, JSON as `serde_json` writes it (also with
  lower-case `\uXXXX` escapes of non-ASCII characters and `\/`) and percent-encoding with upper- or
  lower-case hex.
- Writes under `vault.lock`; the catalog derived from the vault, `catalog.toml` an export only.
- An audit log of value fetches, writes and refused requests (successful catalog reads are not
  logged).
- The `Backend` seam, with a local and a remote implementation.
- `agentsafe serve` on a 0600 Unix socket behind `tailscale serve --accept-app-caps`, with
  per-entry grants from the tailnet policy, a CSRF header on the API, `<socket>.lock` and a 5 s
  shutdown grace.
- The admin web UI: metadata, write-only values, creation, deletion, reveal with a reason and an
  optional ntfy notification, and the audit view.
- One-key rotation (`set NAME --key KEY`, the API's `merge`), signal forwarding in `run`, and
  `render` refusing an allowed entry its template never reads (0.1.1).
- A migration guide from a directory of secret files ([migrate.md](migrate.md)).
- Masking of a value its own marker contains and of a six-byte value inside base64; one key
  grammar for every write (0.1.2).
- Remote mode checked on a real tailnet, and the systemd unit of [deploy.md](deploy.md) under
  systemd.
- Plain keys: a key marked `--plain` is injected and rendered but never masked, for configuration
  kept next to a secret.

## Left

- `run` through a pty, for interactive commands: today the child's stdout and stderr are pipes.
- `export`, to regenerate an env file from the vault, and `export --check`, to report drift
  without printing values.
- An agent hook that pipes tool output through `agentsafe scrub` before the agent reads it.

## Later: short-lived credentials

The server keeps a root credential and hands the agent a short-lived one minted at fetch time, like
the dynamic secrets of HashiCorp Vault, so a leaked value matters little. It fits the current API:
`fetch` would return the minted value in place of a stored one.

Candidate providers, each to be verified before any work:

- GitHub App installation tokens, which expire after 1 hour.
- Tailscale OAuth client access tokens, which expire after 1 hour.
- Cloudflare API tokens created with an expiry.
- OVH: to check.
