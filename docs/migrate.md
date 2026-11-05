# Move a secrets directory into agentsafe

From a directory of plain files (`~/.secrets/*.env`, one-token files, a dotfiles manager's
decrypted output) to entries that agents use by name. What to move, what to leave as a file, and
how to check that nothing changed for the commands that use them.

## What moves, what stays

Move a file when people or agents read it to run a command. Leave it a file when a program reads
it by path and you do not control that program, or when its job is to print the value:

| Consumer | Example | Why it stays a file |
|---|---|---|
| A credential helper | an MCP `headersHelper`, a git or docker credential helper | it must print the value, and `run` masks output |
| A service by path | a compose secret mount, a `--token-file` flag, a shell startup file | nothing runs it under `agentsafe run` |
| A file its owner rewrites | a refreshed OAuth token, a gateway's key list | the vault would hold a stale copy |
| A binary key | a raw 16-byte key | values are UTF-8 text (store it base64 if you must) |

A program you control can move: make it read the environment first and the file second, then run
it under `agentsafe run`.

## Import

A `.env` file becomes one entry with the file's keys:

```sh
agentsafe import ~/.secrets/ovh-api.env --name ovh-api --description "OVH API, full access"
```

`import` reads `export`, quotes, comments and multi-line quoted values, and expands no `$VAR`: a
value is the file's text. Where a shell sourcing the file would have expanded `$1` in a password or
split an unquoted JSON object, agentsafe keeps what the file says. Keys may hold `.` and `-`.

A one-value file (a token, a PEM key) is stored with `--key`, all of stdin minus one trailing
newline:

```sh
agentsafe set github-ci-runners --key GITHUB_CI_RUNNERS_TOKEN < ~/.secrets/github-ci-runners.token
```

Never `import` a one-value file. A base64 token that ends in `=` would read as `TOKEN=` with an
empty value, and the token would become a key name, which `list` shows. `import` refuses such
input, but `--key` is the right tool.

Several one-value files that belong together go into one entry: pipe `KEY="value"` lines into
`agentsafe set NAME` (double-quoted, with `\n` for newlines), or `set --key` them one by one.
`set --key` changes that key only; `set` with lines and `import` replace the entry's values.

## Check before deleting

`verify-import DIR` compares each file directly in `DIR` (not its subdirectories) with the entry
imported from it, by fingerprint, and prints `OK`, `MISMATCH`, `UNREADABLE` or `NOT IMPORTED` per file:

```sh
agentsafe verify-import ~/.secrets
```

For one-value files, compare what a command gets without printing it:

```sh
agentsafe run --env github-ci-runners -- sh -c 'printf %s "$GITHUB_CI_RUNNERS_TOKEN" | shasum -a 256'
printf %s "$(cat ~/.secrets/github-ci-runners.token)" | shasum -a 256
```

Before deleting the files, back up the vault: `vault.age` and its identity, or put an offline
recovery key in `recipients` (each write then encrypts the vault to it too). The age header lists
one `-> X25519` line per recipient: `grep -a -c '^-> X25519' vault.age`.

## Change the commands

| Before | After |
|---|---|
| `set -a; . ~/.secrets/ovh-api.env; set +a; ./deploy` | `agentsafe run --env ovh-api -- ./deploy` |
| `curl -H "Authorization: Bearer $(cat ~/.secrets/x.token)" …` | `agentsafe run --env x -- sh -c 'curl -H "Authorization: Bearer $X_TOKEN" …'` |
| `cat > ~/.secrets/x.token` | `… \| agentsafe set x --key X_TOKEN` |
| a config file with the value in it | a template and `agentsafe render TEMPLATE --allow x -o FILE` |

Use `sh -c`, not your login shell. A shell that reads startup files for every invocation (zsh
reads `~/.zshenv`) can reset the variables `run` injected.

Then tell the agents. One rule in their instructions is enough: entries are listed by
`agentsafe list`, used through `agentsafe run`, stored through `agentsafe set`, and the files left
in the directory belong to the services that read them.
