# Threat model

`agentsafe` prevents accidents, not a determined attacker with code execution as the owner. Its
job is to keep secret values out of what an AI agent reads and repeats, and to make every access
visible.

## Assets

- **Secret values**, in `vault.age` and, while a command runs, in the memory of the CLI, its child
  and, in remote mode, the server.
- **The age identity** (`identity.txt`, and any offline recovery identity): it decrypts the vault
  and every backup of it.
- **The audit log** (`audit.jsonl`): its value is that it is complete and unaltered.
- **The ntfy URL**: whoever knows the topic can read the reveal notifications or send fake ones.
- **Metadata** (names, key names, descriptions): stored in plaintext in `catalog.toml`, not
  treated as secret.

## Actors

### The agent

An AI agent running commands as the owner, on the vault host (local mode) or on another host
(remote mode). It is assumed to make mistakes, not to attack.

Stops:

- No command prints a value: `list` and `describe` show names and metadata, `set` and `import` take
  values from stdin or a file, never from arguments.
- `run` masks the values of the entries it injects in the child's stdout and stderr; `scrub` masks
  every entry the caller may get, in the encodings listed in the README.
- `render` refuses a stdout that is not a regular file and makes it 0600.
- Error messages never quote a value: `.env` errors give a line number, template errors give the
  kind and the line, a vault that does not parse is reported without its content, API errors never
  echo the request body.
- Every fetch and write is audited before a value is released.

Does not stop: a value transformed before printing, written to a file or sent over the network from
inside `run`, read back from a rendered file, or a value of another entry that the child reads
elsewhere (`run` does not mask it). In local mode the agent can read `identity.txt`. In remote mode
it holds the fetched values in memory and can call the API with its host's grants.

### Other local users

Other accounts on the client or the vault host.

Stops: the config directory is 0700; the config, identity, vault, catalog, lock, audit log, socket
lock and socket are 0600. A rendered file is 0600.

Does not stop: root, or anything running as the owner or the server user.

### Tailnet peers

Any node that can reach the vault host.

Stops:

- Only requests through Serve carry a capability header, and Serve strips one the client sent. A
  request without a valid grant is refused and audited.
- A grant names entries and actions; `get` is needed for values, `admin` for deletion, the UI and
  reveal. A `describe` of an entry the caller may not list is refused whether or not it exists.
- Values cross the tailnet inside WireGuard, and with an `https://` server URL Serve adds TLS on
  the `ts.net` name.

Does not stop: a peer with a grant doing what the grant allows; any process on a granted node using
that node's grants (the server sees a node or a user, not a process); a policy file that grants too
much.

### A browser page

A page on another site, open in the owner's browser while the owner's device is on the tailnet.

Stops:

- `/api/` requires `Sec-Agentsafe: 1`, which a cross-origin page cannot send without a CORS
  preflight that the server never grants.
- The UI refuses a state-changing request unless `Sec-Fetch-Site` is `same-origin` or `none`, or,
  without that header, unless `Origin` matches `X-Forwarded-Host`.
- UI pages send a strict CSP with `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and
  `Cache-Control: no-store` on every answer, so a revealed value is not cached.

Does not stop: a compromised browser or extension, or someone at the owner's unlocked screen.
Authorization refusals and unknown paths miss the CSP and `Referrer-Policy`
([#7](https://github.com/falistos/agentsafe/issues/7)); they carry no value.

## Assumptions

- **`tailscaled` is trusted.** It authenticates peers, sets `Tailscale-User-Login`,
  `X-Forwarded-For` and `Tailscale-App-Capabilities`, removes forged ones, and terminates TLS, so it
  sees every value it proxies. It runs as root and can connect to the 0600 socket.
- **The server user is trusted.** It holds the identity; it, root, and anything running as either
  can read every value and rewrite the audit log.
- **Tailscale policy is the access control.** `agentsafe` has no user database. Whoever can edit the
  tailnet policy file, or tag a node, decides who gets which values.
- **The owner is trusted in local mode.** On the vault host the owner and the owner's agents need no
  grant, header or reason; the audit log records what they do.
- **Backups are as sensitive as the identity that decrypts them.** A backup of `vault.age` is safe
  only while every identity it is encrypted to stays private.
