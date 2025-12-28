# HostIt (server)

Self-hosted TCP tunnel server + web dashboard.

## Run

```sh
# from this folder
go run ./cmd/server
```

## Build 

```sh
./build.sh
./bin/tunnel-server
```

Defaults:
- Web dashboard: `http://127.0.0.1:7002`
- Config file: `server.json` (created on first save)
- Auth DB: `auth.db`

Tunnel security defaults:
- Agent↔server control/data TCP is TLS-encrypted by default (self-signed cert auto-generated next to `server.json` as `server.crt`/`server.key`).
- Agent↔server UDP data (used for UDP forwarding) is encrypted at the message layer by default (AES-GCM, 256-bit).

UDP encryption options:
- Configure in the server dashboard: UDP Encryption = No encryption / 128-bit / 256-bit.
- UDP keys can be regenerated manually from the dashboard and are auto-rotated every 60 days.

## First-time setup

- Open the dashboard.
- If no users exist yet, you'll be redirected to `/setup` to create the initial admin account.

## Deploy notes

- If hosting publicly, put this behind HTTPS (reverse proxy) and run with `-cookie-secure`.
- The dashboard is protected by login + session cookies and includes basic CSRF protection.

TLS knobs:
- Disable tunnel TLS: `-disable-tls`
- Set custom cert/key paths: `-tls-cert /path/to/server.crt -tls-key /path/to/server.key`
- Disable UDP message encryption (deprecated): `-disable-udp-encryption`
