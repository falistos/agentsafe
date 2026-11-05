# safe

A small secrets manager for AI agents. Values live in one age-encrypted file; agents work with
names and metadata, and values only reach child processes and rendered files. No command prints a
value to the caller.

## Setup

```sh
age-keygen -o ~/.config/safe/identity.txt
cat > ~/.config/safe/config.toml <<'EOF'
identity = "~/.config/safe/identity.txt"
# Extra recipients the vault is also encrypted to, e.g. an offline recovery key.
recipients = []
EOF
```

`$SAFE_CONFIG` overrides the config path. `vault.age` (values and metadata, encrypted) and
`catalog.toml` (metadata and key names, plaintext, regenerated on every write) sit next to the
config. Both are written atomically with mode 0600.

## Commands

| Command | Does |
|---|---|
| `safe list` | Entries with key count, owner, rotation date, tags, description. |
| `safe describe NAME` | One entry's metadata and key names, and which keys are too short to mask. |
| `safe set NAME [--key KEY]` | Stores values read from stdin: `KEY=VALUE` lines, or all of stdin as `KEY`. |
| `safe import-env FILE --name NAME` | Stores a `.env` file (`export`, quotes, comments; no `$VAR` expansion). |
| `safe run --env NAME[:KEY[=VAR]] … -- CMD ARGS` | Runs `CMD` with the values in its environment, stdout and stderr masked. |
| `safe render TEMPLATE --allow NAME … > FILE` | Renders a minijinja template; `safe["NAME"].KEY` reads allowed entries only. Refuses a terminal or pipe as stdout and makes the file 0600. |
| `safe scrub` | Copies stdin to stdout with every known value masked. |
| `safe verify-import DIR` | For each file of `DIR`, compares the SHA-256 fingerprint of its parsed `KEY=VALUE` set with the entry imported from it. Prints names and `OK`, `MISMATCH` or `NOT IMPORTED`; exits 1 unless all are `OK`. |

`set` and `import-env` take `--description`, `--owner`, `--rotate-by YYYY-MM-DD`, and repeatable
`--used-by` and `--tag`; values are never accepted as arguments.

## Masking

`run` and `scrub` replace every known value with `***NAME***`, also when it appears base64-encoded
(standard and URL-safe, at the three byte alignments a value can have inside a larger blob),
hex-encoded (lower and upper case), JSON-escaped or percent-encoded. Matching is streamed with a
hold-back of the bytes that could start a value, so a value split across reads is still masked.

Values and encoded forms shorter than 6 bytes are not masked: they occur in ordinary output and
masking them would corrupt it. `set` warns about them and `describe` lists them.

## What it does not protect against

`safe` prevents accidents: a value pasted into a transcript, a `.env` file read by mistake. It is
not a sandbox. An agent determined to see a value can still get it, for example by:

- transforming it before printing: hashing, encrypting, reversing, printing it character by
  character, or an encoding not listed above;
- writing it to a file or sending it over the network from inside `safe run`, then reading it back
  outside;
- `safe render` to a file, then reading the file;
- reading the age identity, which any process running as the same user can do.

## Development

```sh
make gate   # cargo fmt --check, cargo clippy -D warnings, cargo test
```
