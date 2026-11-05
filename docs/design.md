# Design

## Model

### Vault

`vault.age` is one TOML document encrypted with age to the recipient of the config's `identity`
plus each X25519 recipient in `recipients`. It maps entry names to metadata and values:

```toml
[entries.github.meta]
description = "GitHub API"
tags = ["ci"]

[entries.github.values]
TOKEN = "..."
```

Entry names use letters, digits, `.`, `_` and `-`. Metadata fields are `description`, `used_by`,
`owner`, `rotate_by` (a date), `tags` and `source` (the canonical path `import` read, used by
`verify-import`).

The config directory holds:

| File | Content |
|---|---|
| `config.toml` | `identity` or `server`, `recipients`, and a `[serve]` table (`socket`, `ntfy`). |
| `identity.txt` | The age identity (local mode only). |
| `vault.age` | The encrypted vault. |
| `vault.lock` | The write lock. |
| `catalog.toml` | A plaintext export of names, metadata and key names. |
| `audit.jsonl` | The audit log. |

`init` creates the directory 0700 and the config and identity 0600. The vault and the catalog are
written to a temporary file and renamed into place, so readers never see a partial file and the
mode stays 0600. A write loads, changes and saves the vault under an exclusive lock on
`vault.lock`, so concurrent `set`, `edit` and `rm` (and server requests) do not lose each other's
changes; readers take no lock. Adding a recipient takes effect at the next write, which re-encrypts
the vault to the new list.

### Catalog

The catalog is derived from the decrypted vault on every read: metadata, key names, and `unmasked`,
the keys whose value is under 6 bytes. `catalog.toml` is an export rewritten on every write and
never read back; editing it changes nothing. It is plaintext: names, metadata and key names are not
treated as secrets.

### Audit

`audit.jsonl` (0600) gets a line for each value fetch, each write and each refused request. Two
kinds of vault access are not logged:

- a successful catalog read (`list`, `describe`, `GET /api/v1/entries[/NAME]`, the UI pages): it
  decrypts the vault but returns no value;
- a fetch of every entry (`scrub`, `verify-import`, `{"all": true}` on the API) when the vault
  cannot be loaded: it fails before any line is written. A fetch of named entries logs the load
  error per entry.

A line records the outcome of the vault access, not of the whole command: argument and input errors
that never reach the vault are not logged, and a `run` whose key lookup or child fails after a
successful fetch stays `ok`. The line is written before any value leaves the backend; if it cannot
be written, no value is released. The format is at the end of this document.

### Backend seam

Every command except `init` and `serve` goes through the `Backend` trait (`src/backend.rs`):
`catalog`, `fetch`, `put`, `remove`. `LocalBackend` reads the vault on this machine;
`RemoteBackend` (`src/client.rs`) calls the API of an `agentsafe serve`. Injection, rendering and
masking happen in the CLI on top of the trait, so they behave the same in both modes.

### Local mode

The config has `identity = "<path>"` (a leading `~` is expanded). The CLI decrypts the vault
itself. There are no grants, no CSRF header and no reveal reason: on the vault host the owner and
the owner's agents act as the owner, and their fetches and writes are audited with
`who: "local:$USER"` and `via: "local"`. This is deliberate: security applies where it does not get in the way of the owner.

### Remote mode

The config has `server = "<URL>"` (`https://host.tailnet.ts.net`, or `http://...`) and no identity.
`agentsafe init --server URL` writes it. Every command except `init` and `serve` calls the server,
which checks the caller's grants and audits with `via: "api"`. The client gets values only from
`fetch`, holds them in memory for the command, injects and masks them locally. The server audits
every remote fetch as `get`, whatever the command. `serve` refuses a remote config.

## Serve integration

```
agent host ──tailnet──▶ tailscaled (Serve, TLS on host.tailnet.ts.net:443)
                           │ HTTP over a Unix socket, with identity headers
                           ▼
                        agentsafe serve ──▶ vault.age, audit.jsonl
```

`agentsafe serve` listens on a Unix socket: `--socket`, else `[serve].socket`, else
`$XDG_RUNTIME_DIR/agentsafe.sock`, else `agentsafe.sock` next to the config. It is started behind
`tailscale serve --accept-app-caps=github.com/falistos/agentsafe/cap/agentsafe unix:<socket>`.

### Headers

| Header | Set by Serve | Used for |
|---|---|---|
| `Tailscale-App-Capabilities` | The peer's values of the accepted capabilities, as a JSON object. Serve removes one the client sent. | The caller's grants. |
| `Tailscale-User-Login` | The login of a user node; absent for a tagged node. | `who` in the audit log. |
| `X-Forwarded-For` | The peer's tailnet address. | `who` for a tagged node: `node:<address>`. |
| `X-Forwarded-Host` | The host the client asked for. | The UI's `Origin` check. |
| `Sec-Agentsafe` | No: the client sends `Sec-Agentsafe: 1`. | CSRF guard on `/api/`. |

### Why a missing header is refused

The server has no user database: Tailscale policy is the access control, and the capability header
is the only proof of a grant. A request without it comes from a peer that holds none of the
accepted capabilities, or did not come through Serve. Either way it gets no rights, so it is
refused with 403 and audited as `denied`. A header that is not ASCII (Serve Q-encodes non-ASCII
values) or not a JSON object of arrays is refused as malformed, and one without a valid value for
the capability as having no grant.

### Why the socket is 0600

Serve strips identity and capability headers sent by the client, but a process that connects to
the socket directly bypasses Serve and can send any header, including a grant of `admin` on `*`.
The socket is therefore bound in a fresh 0700 directory, narrowed to 0600 and renamed into place,
so only the server user (and root, which `tailscaled` runs as) can connect. `serve` holds an
exclusive lock on `<socket>.lock` while it runs: a second `serve` on the same socket is refused,
and a socket left by a crashed server is removed. On SIGTERM or SIGINT it stops accepting, gives
open requests at most 5 s, then removes the socket. A write runs whole under `vault.lock`, so
cutting a request never leaves a half-written vault.

### CSRF

The tailnet authenticates the owner's browser too, so a page on another site that the owner visits
could send requests to the server with the owner's grants.

- Every `/api/` request needs `Sec-Agentsafe: 1`. A browser cannot add a custom header to a
  cross-origin request without a CORS preflight, and the server never answers one with permission.
- The UI accepts a request other than GET or HEAD only with `Sec-Fetch-Site: same-origin` or
  `none`, or, when the browser sends no `Sec-Fetch-Site`, with an `Origin` whose host is the
  `X-Forwarded-Host` that Serve sets. This is the rule of Go's `http.CrossOriginProtection`.
- UI answers carry `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';
  form-action 'self'; frame-ancestors 'none'` and `Referrer-Policy: no-referrer`; every answer
  carries `Cache-Control: no-store`. Open item: refusals from the authorization layer (no grant,
  missing header) and unknown UI paths miss the CSP and `Referrer-Policy`
  ([#7](https://github.com/falistos/agentsafe/issues/7)).

## Capability

The capability is `github.com/falistos/agentsafe/cap/agentsafe`. Each value granted in the tailnet
policy is an object with exactly two fields:

```json
{"entries": ["github", "ci-*"], "actions": ["get"]}
```

- `entries`: exact names, `PREFIX*` for every name that starts with `PREFIX`, or `*` for every
  entry. A `*` elsewhere than at the end makes the value invalid.
- `actions`: `list`, `get`, `put`, `admin`. `get` and `put` imply `list`; `admin` implies all of
  them and is the only one that allows `rm`, the UI and reveal.

A caller's rights are the union of its values: an action on an entry is allowed when one value both
matches the entry and holds or implies the action. Two values do not combine into a cross product.
An invalid value (unknown field or action, bad pattern) is ignored with a warning on the server's
stderr; when no value is valid the request is refused.

Examples, as they appear in the header:

```json
{"github.com/falistos/agentsafe/cap/agentsafe": [
  {"entries": ["github", "ci-*"], "actions": ["get"]},
  {"entries": ["staging-db"], "actions": ["put"]}
]}
```

Here the caller can fetch `github` and every `ci-*` entry, write `staging-db`, and list all three;
it cannot fetch `staging-db`. `{"entries": ["*"], "actions": ["admin"]}` gives everything, including
the audit page of the UI.

## API

All paths are under `/api/v1/`. Bodies are JSON, at most 64 KiB. An error answer is
`{"error": "<message>"}` and never quotes a value or the request body.

| Request | Needs | Answer |
|---|---|---|
| `GET /api/v1/entries` | `list` | `{"entries": {NAME: CATALOG_ENTRY}}`, only the entries the caller may list. |
| `GET /api/v1/entries/NAME` | `list` on NAME | `CATALOG_ENTRY`. 403 whether or not the entry exists, when not allowed. |
| `PUT /api/v1/entries/NAME` | `put` on NAME | Body `{"values": {KEY: VALUE}, "meta": META_PATCH}`, either or both. 204. With `meta` only, the entry must exist. |
| `DELETE /api/v1/entries/NAME` | `admin` on NAME | 204. |
| `POST /api/v1/fetch` | `get` on each name | Body `{"names": [NAME, ...]}` or `{"all": true}`. `{"entries": {NAME: {KEY: VALUE}}}`. One forbidden name refuses the whole request; `all` returns the entries the caller may get. |

`CATALOG_ENTRY` is the metadata fields plus `keys` and, when not empty, `unmasked`. `META_PATCH`
takes `description`, `used_by`, `owner`, `rotate_by` (`YYYY-MM-DD`), `tags` and `source`; an absent
field is left alone and an empty one clears it.

Statuses: 400 for an invalid name, body or date, 403 for a refusal, 404 for a missing entry, 409
for a conflict, 413 for a body over the limit, 500 otherwise.

## Admin UI

`agentsafe serve` also serves server-rendered HTML pages, without JavaScript, outside `/api/`, to
callers with `admin` on at least one entry. They list and act only on the entries the caller has
`admin` on, and are audited with `via: "ui"`.

| Path | Does |
|---|---|
| `/` | The entries. |
| `/new` | Creates an entry; refused if it exists. |
| `/e/NAME` | Metadata and key names. |
| `/e/NAME/meta` | Saves metadata. |
| `/e/NAME/values` | Replaces the values (write-only); the entry must exist. |
| `/e/NAME/reveal` | Shows the values once. Needs a reason with at least 4 non-space characters, kept up to 200. |
| `/e/NAME/delete` | Deletes on a typed confirmation of the name. |
| `/audit` | The last 200 audit lines, for `admin` on `*`. |

A reveal is audited as `reveal` with the reason. With `[serve] ntfy = "<URL>"` the server first
POSTs `<who> revealed <NAME>: <reason>` to that URL (never a value, 3 s timeout); the audit line
then has `"notify": "sent"` or `"failed"`, and a failed notification does not block the reveal.

## Audit line format

One JSON object per line:

```json
{"ts":"2026-11-05T16:44:21Z","who":"local:alice","via":"local","action":"run","entry":"github","result":"ok"}
{"ts":"2026-11-05T16:44:31Z","who":"node:100.64.0.9","via":"api","action":"rm","entry":"github","result":"denied","reason":"not allowed"}
{"ts":"2026-11-05T16:45:02Z","who":"alice@example.com","via":"ui","action":"reveal","entry":"github","result":"ok","reason":"rotate the CI token","notify":"sent"}
```

| Field | Value |
|---|---|
| `ts` | UTC, to the second. |
| `who` | `local:$USER`; through the server the `Tailscale-User-Login`, else `node:<X-Forwarded-For>`, else `unknown`. |
| `via` | `local`, `api` or `ui`. |
| `action` | `run`, `render`, `get` and `reveal` (one line per entry); `scrub` and `verify-import` (one line, no entry); `put`, `edit`, `rm`; and, for refusals only, `list`, `describe`, `audit` or `request`. |
| `entry` | The entry, when the action has one. |
| `result` | `ok`, `denied` (refused before the vault) or `error` (the vault access failed). |
| `reason` | The refusal or error message, or the reveal reason. |
| `notify` | `sent` or `failed`, on a reveal with ntfy configured. |

Successful catalog reads and the load failure of a fetch of every entry are not logged (see
[Audit](#audit)). No line ever carries a value.
