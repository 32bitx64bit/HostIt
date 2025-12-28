# playit-prototype (server)

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

## First-time setup

- Open the dashboard.
- If no users exist yet, you'll be redirected to `/setup` to create the initial admin account.

## Deploy notes

- If hosting publicly, put this behind HTTPS (reverse proxy) and run with `-cookie-secure`.
- The dashboard is protected by login + session cookies and includes basic CSRF protection.
