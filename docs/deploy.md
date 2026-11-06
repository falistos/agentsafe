# Deploy `agentsafe serve`

> Checked on a real tailnet, on a macOS host (a LaunchAgent, Tailscale 1.104.1) serving a macOS
> client: `list`, `describe`, `run`, `render`, `set` and `rm` worked and were audited by the
> caller's login. The systemd unit below was checked on Debian 12 (systemd 252) with the v0.1.2
> release binary, the Serve headers sent by hand: the API, the UI, a reveal with ntfy and a clean
> stop all worked under its sandbox. Report what differs.

The server runs as a dedicated user under systemd on a Linux host, listens on a Unix socket, and
`tailscale serve` publishes it on the tailnet with the callers' grants.

Requirements: Tailscale 1.94 or later on the server, HTTPS certificates enabled on the tailnet
(Serve needs them), and an `agentsafe` binary in `/usr/local/bin`. Tailscale 1.92 brought
`--accept-app-caps` but rejects a `unix:` target; Serve accepts Unix sockets from 1.94.

## 1. User, config and identity

```sh
sudo useradd --system --home-dir /var/lib/agentsafe --shell /usr/sbin/nologin agentsafe
sudo install -d -o agentsafe -g agentsafe -m 0700 /var/lib/agentsafe
sudo -u agentsafe env AGENTSAFE_CONFIG=/var/lib/agentsafe/config.toml agentsafe init
```

`init` prints the public key and writes `/var/lib/agentsafe/config.toml`, `identity.txt` and an
empty `vault.age`. Add the server settings to the config:

```toml
identity = "/var/lib/agentsafe/identity.txt"
recipients = ["age1...offline recovery key..."]

[serve]
socket = "/run/agentsafe/agentsafe.sock"
# ntfy = "https://ntfy.example.com/<secret topic>"
```

To manage entries on the host, run the CLI as that user with the same `AGENTSAFE_CONFIG`; it uses
local mode and is audited as `local:agentsafe`.

## 2. systemd unit

`/etc/systemd/system/agentsafe.service`:

```ini
[Unit]
Description=agentsafe server
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
User=agentsafe
Group=agentsafe
Environment=AGENTSAFE_CONFIG=/var/lib/agentsafe/config.toml
ExecStart=/usr/local/bin/agentsafe serve
Restart=on-failure
# serve gives open requests 5 s after SIGTERM; a write waits at most 5 s for vault.lock.
TimeoutStopSec=15

StateDirectory=agentsafe
StateDirectoryMode=0700
RuntimeDirectory=agentsafe
RuntimeDirectoryMode=0700
UMask=0077
# A core dump would hold decrypted values.
LimitCORE=0

NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
# AF_INET and AF_INET6 only for the ntfy notification.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now agentsafe
journalctl -u agentsafe    # "agentsafe: serving on /run/agentsafe/agentsafe.sock (Landlock: enforced)"
```

The socket is 0600 in a 0700 directory: only `agentsafe` and root (`tailscaled`) can connect. Keep
it that way; a process that reaches the socket directly can claim any grant (see
[design.md](design.md#why-the-socket-is-0600)).

## 3. Tailscale Serve

```sh
sudo tailscale serve --bg \
  --accept-app-caps=github.com/falistos/agentsafe/cap/agentsafe \
  unix:/run/agentsafe/agentsafe.sock
```

Serve needs root, or an operator allowed to run `sudo tailscale`, to proxy a Unix socket. Without
`--https=PORT` it takes 443. Pick a port nothing on the host binds on its tailnet address: Serve
takes the port from every tailnet peer before the host sees the connection, so a web server already
on that address and port stops answering them. With another port, add it to the URLs below and to
the grant's `ip`.

Serve answers on `https://<host>.<tailnet>.ts.net` and forwards each request with the caller's
values of that capability in `Tailscale-App-Capabilities`. Without `--accept-app-caps` every
request is refused with `no capability header`.

## 4. Tailscale policy

The server node is tagged `tag:agentsafe`. A grant needs `ip` to reach port 443 and `app` to carry
the agentsafe grant. Here agents on `tag:agent` nodes may fetch two entries and every `ci-*` entry,
and the owner has `admin` on everything:

```json
{
  "tagOwners": {
    "tag:agentsafe": ["autogroup:admin"],
    "tag:agent": ["autogroup:admin"]
  },
  "grants": [
    {
      "src": ["tag:agent"],
      "dst": ["tag:agentsafe"],
      "ip": ["tcp:443"],
      "app": {
        "github.com/falistos/agentsafe/cap/agentsafe": [
          {"entries": ["github", "npm", "ci-*"], "actions": ["get"]}
        ]
      }
    },
    {
      "src": ["owner@example.com"],
      "dst": ["tag:agentsafe"],
      "ip": ["tcp:443"],
      "app": {
        "github.com/falistos/agentsafe/cap/agentsafe": [
          {"entries": ["*"], "actions": ["admin"]}
        ]
      }
    }
  ]
}
```

The value format is in [design.md](design.md#capability). Tagged nodes are audited as
`node:<tailnet address>`, user nodes by their login.

## 5. Client

On an agent host, with the tailnet up:

```sh
agentsafe init --server https://<host>.<tailnet>.ts.net
agentsafe list
agentsafe run --env github:TOKEN=GH_TOKEN -- gh api user
```

The client config holds only `server`; there is no identity on the client.

## 6. ntfy (optional)

With `[serve] ntfy = "<URL>"`, each reveal in the UI POSTs `<who> revealed <NAME>: <reason>` to
that URL with the title `agentsafe reveal`. The request has no authentication header, so the URL
must accept an anonymous publish; use a topic name nobody can guess, or a self-hosted server. The
URL is a secret: it is not logged. A failed notification (3 s timeout) does not block the reveal and
is recorded as `"notify": "failed"`.

## 7. Backups

Back up `vault.age` and `identity.txt`, separately: together they give every value. `catalog.toml`
is regenerated on the next write; keep `audit.jsonl` if the history matters. Without `vault.age`
every command fails with `no vault at PATH`: restore it, or run `init` on a new directory.

Keep an offline recovery recipient, so that losing the server's identity does not lose the vault:

```sh
age-keygen -o recovery.txt     # on an offline machine; prints the public key
```

Put the public key in `recipients` (X25519 `age1...` keys only), then make one write, for example
`agentsafe edit NAME --tag ...` as the `agentsafe` user: the vault is re-encrypted to the new list
on the next write, not before. A backup of `vault.age` can then be read without the server:

```sh
age -d -i recovery.txt vault.age    # prints the vault as TOML, values included
```
