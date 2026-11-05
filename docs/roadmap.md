# Roadmap

## Done

- Local CLI on an age vault: `init`, `list`, `describe`, `set`, `import`, `edit`, `rm`, `run` with
  masked output, `render`, `scrub`, `verify-import`.
- Masking of raw, base64, hex, JSON-escaped and percent-encoded values, streamed.
- Writes under `vault.lock`; the catalog derived from the vault, `catalog.toml` an export only.
- A local audit log of every vault access.
- The `Backend` seam, with a local and a remote implementation.
- `agentsafe serve` on a 0600 Unix socket behind `tailscale serve --accept-app-caps`, with
  per-entry grants from the tailnet policy, a CSRF header on the API, `<socket>.lock` and a 5 s
  shutdown grace.
- The admin web UI: metadata, write-only values, creation, deletion, reveal with a reason and an
  optional ntfy notification, and the audit view.

## Left

- `run` through a pty, for interactive commands: today the child's stdout and stderr are pipes.
- `export`, to regenerate an env file from the vault, and `export --check`, to report drift
  without printing values.
- An agent hook that pipes tool output through `agentsafe scrub` before the agent reads it.
- A test on a real tailnet: Serve's headers, the policy example and the unit file of
  [deploy.md](deploy.md).
- UI security headers on authorization refusals
  ([#7](https://github.com/falistos/agentsafe/issues/7)).

## Later: short-lived credentials

The server keeps a root credential and hands the agent a short-lived one minted at fetch time, like
the dynamic secrets of HashiCorp Vault, so a leaked value matters little. It fits the current API:
`fetch` would return the minted value in place of a stored one.

Candidate providers, each to be verified before any work:

- GitHub App installation tokens, which expire after 1 hour.
- Tailscale OAuth client access tokens, which expire after 1 hour.
- Cloudflare API tokens created with an expiry.
- OVH: to check.
