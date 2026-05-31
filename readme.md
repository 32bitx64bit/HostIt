# HostIt

[![Go Version](https://img.shields.io/badge/Go-1.26.1-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](./LICENSE)
[![Release](https://img.shields.io/badge/release-v3.1.0-brightgreen)](https://github.com/32bitx64bit/HostIt/releases/latest)

A high-performance, self-hosted tunneling service — an alternative to services like Playit.gg or Ngrok. Expose your local projects to the internet even when your ISP or router blocks port forwarding, with better security than raw port forwarding.

## Features

- **TCP & UDP tunneling** — forward any local service through a single outbound connection
- **Domain-based routing** — assign custom domains to tunnels with automatic Let's Encrypt TLS certificates
- **Built-in email server** — SMTP, IMAP, and POP3 with DKIM signing and SQLite storage
- **Web dashboard** — manage tunnels, domains, and email accounts from a browser
- **Declarative config** — define tunnels in `apps.json` for auto-registration on agent start
- **Systemd integration** — run as a background service with automatic restart
- **Go SDK** — programmatically register and manage tunnels from your own Go applications

## Quick Start

### Prerequisites

- Go 1.26.1 or newer
- A Linux VPS for the server
- Ports **7000** (control), **7001** (data), and **7002** (dashboard) open on the server
- Client machine needs `client/` + `shared/` directories; server needs `server/` + `shared/`

### Server (Linux)

```sh
cd server
./build.sh
./server.sh
```

Open `http://<server-host>:7002` in a browser. The first visit shows a setup wizard — complete it, and the server is ready.

To run as a systemd service:

```sh
sudo sh server/install-service.sh
```

### Client

#### Linux

```sh
cd client
./build.sh
./client.sh
```

Open the dashboard at `http://127.0.0.1:7003`, enter your server IP and setup token, then click **Save + restart agent**.

#### Windows (experimental)

```powershell
cd client
.\build.ps1
.\client.ps1
```

Open `http://127.0.0.1:7003` and configure the server IP and token.

> Windows support is experimental and not fully tested. Expect rough edges.

### Systemd Services

Running via SSH or terminal means the process dies when the session ends. Use systemd to keep it alive.

| Service | Unit | Logs |
|---------|------|------|
| Server | `hostit-server.service` | `journalctl -u hostit-server.service -f` |
| Agent | `hostit-agent.service` | `journalctl -u hostit-agent.service -f` |

```sh
# Server
cd server && ./build.sh
sudo sh server/install-service.sh

# Agent
cd client && ./build.sh
sudo sh client/install-service.sh

# Stop
sudo systemctl stop hostit-server.service
sudo systemctl stop hostit-agent.service
```

Both dashboards include **Process → Restart / Exit**. Under systemd, these terminate the process and systemd restarts it automatically.

## Developer Integration

HostIt provides a Go SDK for registering and managing tunnels programmatically. Your app talks to the local agent at `http://127.0.0.1:7003` — the agent handles server negotiation, domain selection, and conflict resolution.

### Setup

Clone the repository and use a `replace` directive to point at the local `shared` module:

```
require hostit/shared v0.0.0
replace hostit/shared => ./path/to/HostIt/shared
```

Then import the SDK:

```go
import "hostit/shared/sdk"
```

### Basic Usage

```go
client := sdk.NewClient("http://127.0.0.1:7003")

resp, err := client.Register(ctx, sdk.RegisterRequest{
    Name:      "my-app",
    Proto:     "tcp",
    LocalPort: 3000,
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Tunnel active: %s -> %s\n", resp.PublicAddr, resp.LocalAddr)
```

All API responses use a JSON envelope that the SDK unwraps automatically:

```json
{"status": "ok",    "data": {...}}
{"status": "error", "message": "..."}
```

### Domain Routing

When the server's domain manager is enabled:

```go
resp, err := client.Register(ctx, sdk.RegisterRequest{
    Name:      "my-app",
    Proto:     "tcp",
    LocalPort: 3000,
    Domain:    "auto",
})
```

- `""` — port-only tunnel, no domain
- `"auto"` — auto-suggests `my-app.<base-domain>`, prompts for selection if taken
- `"app.example.com"` — explicit domain, fails if already in use

When `resp.Status == "pending_domain"`, present available domains to the user:

```go
domains, _ := client.ListDomains(ctx)
resp, _ = client.SelectDomain(ctx, resp.RequestID, resp.RouteName, "my-app.example.com")
```

### Updating Routes

Change a route's local port without re-registering:

```go
client.UpdateRoute(ctx, "my-app", sdk.RouteUpdate{
    LocalAddr: "127.0.0.1:4000",
})
```

### Other Operations

```go
routes, _ := client.ListRoutes(ctx)               // all active routes
stats, _  := client.RouteStats(ctx, "my-app")      // per-route status
client.RemoveRoute(ctx, "my-app")                   // unregister
status, _ := client.Status(ctx)                     // agent connection status
wsURL    := client.EventsURL()                      // WebSocket URL for live events
```

### Email Account Management

When the agent's email service is enabled:

```go
acct, err := client.CreateMailAccount(ctx, "alice", "password123")
fmt.Printf("Created: %s\n", acct.Address) // alice@<domain>

client.UpdateMailAccountPassword(ctx, "alice", "newpassword456")
client.DeleteMailAccount(ctx, "alice")
```

HTTP endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/mail/accounts` | List all accounts |
| `POST` | `/api/mail/accounts` | Create account |
| `PATCH` | `/api/mail/accounts/{username}` | Change password |
| `DELETE` | `/api/mail/accounts/{username}` | Delete account |

### Email Message Operations

```go
addr, _ := client.AuthenticateMail(ctx, "alice", "password123")

msgs, _ := client.ListMailMessages(ctx, "alice", "password123")
for _, m := range msgs {
    fmt.Printf("[%d] %s - %s\n", m.ID, m.From, m.Subject)
}

full, _ := client.GetMailMessage(ctx, "alice", "password123", 42)
fmt.Println(full.Body)

client.DeleteMailMessage(ctx, "alice", "password123", 42)
```

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/mail/login` | Authenticate, returns email address |
| `POST` | `/api/mail/inbox` | List messages |
| `POST` | `/api/mail/message` | Read full message with body |
| `POST` | `/api/mail/delete` | Delete message |

### Taking Over Mail with the SDK Lock

If your application wants to run its own mail server and prevent the built-in mail service from being accidentally re-enabled, use the SDK lock:

```go
client.LockMailService(ctx, true)
```

When locked:
- The built-in mail service is forced disabled, even if the server dashboard tries to enable it
- The lock persists across agent restarts
- `lockedBySDK` is reported as `true` in the agent's `/api/status` under `email`
- Your app can use HostIt's TCP tunnels to expose your own mail server on standard ports (25, 465, 587, 143, 993)

Release the lock when your app shuts down:

```go
client.LockMailService(ctx, false)
```

### Declarative Config (apps.json)

Place an `apps.json` next to `agent.json` for routes that should always be registered:

```json
{
  "apps": [
    {
      "name": "webapp",
      "proto": "tcp",
      "local_port": 3000,
      "domain": "auto",
      "auto_start": true
    },
    {
      "name": "api",
      "proto": "tcp",
      "local_port": 8080,
      "public_port": 9090
    }
  ]
}
```

Routes with `"auto_start": true` register automatically when the agent connects to the server.
