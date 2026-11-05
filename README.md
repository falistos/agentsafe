# agentsafe

A secrets manager for AI agents. The agent works with entry names and metadata; values only reach
child processes and rendered files, the output it reads is masked, and every vault access is
audited.

Values live in one age-encrypted file. The CLI reads it directly on the vault host (local mode),
or through an `agentsafe serve` on the tailnet that checks each caller's Tailscale grants (remote
mode).

## Install

Release archives, once a release is published, are on the
[releases page](https://github.com/falistos/agentsafe/releases) as
`agentsafe-<tag>-<target>.tar.gz` for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`
and `aarch64-apple-darwin`, with a `SHA256SUMS` file.

From source (Rust 1.89 or later):

```sh
cargo install --git https://github.com/falistos/agentsafe
```

## Quickstart (local mode)

```sh
agentsafe init                                     # config, age identity
agentsafe set github --key TOKEN < token.txt       # or KEY=VALUE lines on stdin
agentsafe list                                     # names and metadata, never values
agentsafe run --env github:TOKEN=GH_TOKEN -- gh api user   # value in the child, output masked
agentsafe render app.env.j2 --allow github > app.env       # value in a 0600 file
```

`init` creates `~/.config/agentsafe/` (0700) with `config.toml` and `identity.txt` (0600) and
never overwrites them. `$AGENTSAFE_CONFIG` overrides the config path. In local mode the owner's
agents on the vault host need no grant, header or reason: they act as the owner, and the audit log
records it.

## Commands

| Command | Does |
|---|---|
| `agentsafe init [--server URL]` | Creates the config and, without `--server`, an age identity. |
| `agentsafe list` | Entries with key count, owner, rotation date, tags, description. |
| `agentsafe describe NAME` | One entry's metadata and key names, and which keys are too short to mask. |
| `agentsafe set NAME [--key KEY]` | Stores values read from stdin: `KEY=VALUE` lines, or all of stdin (minus one trailing newline) as `KEY`. |
| `agentsafe import FILE --name NAME` | Stores a `.env` file (`export`, quotes, comments; no `$VAR` expansion). |
| `agentsafe edit NAME` | Changes metadata only. Needs at least one metadata flag. |
| `agentsafe rm NAME` | Deletes an entry. |
| `agentsafe run --env NAME[:KEY[=VAR]] … -- CMD ARGS` | Runs `CMD` with the values in its environment, its stdout and stderr masked. Exits with the child's code. |
| `agentsafe render TEMPLATE --allow NAME … > FILE` | Renders a minijinja template where `secrets["NAME"].KEY` reads allowed entries. Refuses a stdout that is not a regular file and makes the file 0600. |
| `agentsafe scrub` | Copies stdin to stdout with the values masked. |
| `agentsafe verify-import DIR` | Compares each file of `DIR` with the entry imported from it by SHA-256 fingerprint: `OK`, `MISMATCH` or `NOT IMPORTED`; exits 1 unless all are `OK`. |
| `agentsafe serve [--socket PATH]` | Serves the local vault over HTTP on a Unix socket for `tailscale serve`. See [docs/deploy.md](docs/deploy.md). |

`set`, `import` and `edit` take `--description`, `--owner`, `--rotate-by YYYY-MM-DD`, and
repeatable `--used-by` and `--tag`; an empty value clears the field (`--tag ''`). Values are never
accepted as arguments.

## Masking

`run` masks the values of the entries named in `--env`, every key of them even when only one key
is injected. `scrub` masks every entry the caller may get: all of them in local mode, those it has
`get` on in remote mode. A match becomes `***NAME***`, also when the value appears base64-encoded
(standard and URL-safe, at the three byte alignments a value can have inside a larger blob),
hex-encoded (lower and upper case), JSON-escaped or percent-encoded. Matching is streamed with a
hold-back, so a value split across reads is still masked.

`run` does not mask a value of another entry that the child reads elsewhere, for example from a
file or its own `agentsafe` call; pipe such output through `agentsafe scrub`.

Values and encoded forms shorter than 6 bytes are not masked: they occur in ordinary output and
masking them would corrupt it. `set` warns about them and `describe` lists them.

## Remote mode

`agentsafe serve` runs on the vault host behind `tailscale serve --accept-app-caps`, which tells it
who the caller is and which grants the tailnet policy gives them. On another host,
`agentsafe init --server https://host.tailnet.ts.net` writes a config with no identity: every
command then goes to the server, and values are injected and masked on the client. Owners with
`admin` also get a small web UI (metadata, write-only value replacement, reveal with a reason and
an optional ntfy notification, audit view).

Setup, unit file and policy example: [docs/deploy.md](docs/deploy.md). Design and API:
[docs/design.md](docs/design.md). Threat model: [docs/threat-model.md](docs/threat-model.md).

## What it does not protect against

`agentsafe` prevents accidents: a value pasted into a transcript, a `.env` file read by mistake. It
is not a sandbox. An agent determined to see a value can still get it, for example by:

- transforming it before printing: hashing, encrypting, reversing, printing it character by
  character, or an encoding not listed above;
- writing it to a file or sending it over the network from inside `agentsafe run`, then reading it
  back outside;
- `agentsafe render` to a file, then reading the file;
- in local mode, reading the age identity, which any process running as the same user can do.

In remote mode:

- a host allowed to `get` an entry holds its values in memory while a command runs, and any process
  there can call the API with that host's grants: the server sees a tailnet node, not a process;
- whoever runs as the server user or as root on the vault host can read every value, and
  `tailscaled` there terminates TLS and sees the values it proxies;
- a holder of `admin` can reveal values in the UI; the reveal is audited and, with ntfy, notified,
  not prevented.

## License

MIT OR Apache-2.0, at your option: [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).

## Development

```sh
make gate   # cargo fmt --check, cargo clippy -D warnings, cargo test
```
