# agentsafe

A small secrets manager for AI agents. Values live in one age-encrypted file; agents work with
names and metadata, and values only reach child processes and rendered files. No command prints a
value to the caller.

## Setup

```sh
agentsafe init
```

`init` creates `~/.config/agentsafe/` (0700), a new age identity (`identity.txt`, 0600) and
`config.toml` pointing at it, and prints the paths and the public key. It never overwrites either
file. The config holds exactly one of `identity = "<age identity file>"` (local) or
`server = "<URL>"` (remote, `agentsafe init --server URL`): a remote config sends every command
except `init` and `serve` to an `agentsafe serve` at that URL (`https://host.tailnet.ts.net` or
`http://...`), which checks the caller's grants; values are injected and masked on the client.
`recipients = []` lists extra recipients the vault is also encrypted to, e.g. an offline recovery
key. A `[serve]` table sets `socket = "<path>"` for `agentsafe serve`.

`$AGENTSAFE_CONFIG` overrides the config path. `vault.age` (values and metadata, encrypted) and
`catalog.toml` (metadata and key names, plaintext, an export regenerated on every write and never
read back) sit next to the config. Both are written atomically with mode 0600; writes hold an
exclusive lock on `vault.lock`, so concurrent `set`, `edit` and `rm` do not lose each other's
changes. `audit.jsonl` (0600, one JSON line per event: `ts`, `who`, `via`, `action`, `entry`,
`result`, never a value) sits there too. A line records the outcome of the vault access (fetch or
write), not of the whole command: argument and input errors that never reach the vault are not
logged, and a `run` whose key lookup or child fails after a successful fetch stays `ok`.

## Commands

| Command | Does |
|---|---|
| `agentsafe init [--server URL]` | Creates the config and, locally, an age identity. |
| `agentsafe list` | Entries with key count, owner, rotation date, tags, description. |
| `agentsafe describe NAME` | One entry's metadata and key names, and which keys are too short to mask. |
| `agentsafe set NAME [--key KEY]` | Stores values read from stdin: `KEY=VALUE` lines, or all of stdin as `KEY`. |
| `agentsafe import FILE --name NAME` | Stores a `.env` file (`export`, quotes, comments; no `$VAR` expansion). |
| `agentsafe edit NAME` | Changes metadata only; values are untouched. Needs at least one metadata flag. |
| `agentsafe rm NAME` | Deletes an entry. |
| `agentsafe run --env NAME[:KEY[=VAR]] … -- CMD ARGS` | Runs `CMD` with the values in its environment, stdout and stderr masked. |
| `agentsafe render TEMPLATE --allow NAME … > FILE` | Renders a minijinja template; `secrets["NAME"].KEY` reads allowed entries only. Refuses a terminal or pipe as stdout and makes the file 0600. |
| `agentsafe scrub` | Copies stdin to stdout with every known value masked. |
| `agentsafe serve [--socket PATH]` | Serves the local vault's API on a Unix socket (0600) for `tailscale serve --accept-app-caps=github.com/falistos/agentsafe/cap/agentsafe unix:PATH`. Socket: `--socket`, `[serve].socket`, `$XDG_RUNTIME_DIR/agentsafe.sock`, or `agentsafe.sock` next to the config. Each request needs grants of that capability, `{"entries": ["NAME", "PREFIX*", "*"], "actions": ["list", "get", "put", "admin"]}` (`get` and `put` imply `list`, `admin` implies all and `rm`), and is audited with `via: "api"`. |
| `agentsafe verify-import DIR` | For each file of `DIR`, compares the SHA-256 fingerprint of its parsed `KEY=VALUE` set with the entry imported from it. Prints names and `OK`, `MISMATCH` or `NOT IMPORTED`; exits 1 unless all are `OK`. |

`set`, `import` and `edit` take `--description`, `--owner`, `--rotate-by YYYY-MM-DD`, and repeatable
`--used-by` and `--tag`; an empty value clears the field (`--tag ''`). Values are never accepted
as arguments.

## Masking

`run` masks the values of the entries it injects and `scrub` those of every entry, replacing each
with `***NAME***`, also when it appears base64-encoded
(standard and URL-safe, at the three byte alignments a value can have inside a larger blob),
hex-encoded (lower and upper case), JSON-escaped or percent-encoded. Matching is streamed with a
hold-back of the bytes that could start a value, so a value split across reads is still masked.

Values and encoded forms shorter than 6 bytes are not masked: they occur in ordinary output and
masking them would corrupt it. `set` warns about them and `describe` lists them.

## What it does not protect against

`agentsafe` prevents accidents: a value pasted into a transcript, a `.env` file read by mistake. It is
not a sandbox. An agent determined to see a value can still get it, for example by:

- transforming it before printing: hashing, encrypting, reversing, printing it character by
  character, or an encoding not listed above;
- writing it to a file or sending it over the network from inside `agentsafe run`, then reading it back
  outside;
- `agentsafe render` to a file, then reading the file;
- reading the age identity, which any process running as the same user can do.

## Development

```sh
make gate   # cargo fmt --check, cargo clippy -D warnings, cargo test
```
