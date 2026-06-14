# HostIt

[![Go Version](https://img.shields.io/badge/Go-1.26.1-00ADD8?logo=go)](https://go.dev/)
[![Core License](https://img.shields.io/badge/core-AGPL--3.0-blue)](./LICENSE)
[![SDK License](https://img.shields.io/badge/SDK-LGPL--3.0-blue)](./LICENSE-SDK)
[![Release](https://img.shields.io/badge/release-v3.1.1-brightgreen)](https://github.com/32bitx64bit/HostIt/releases/latest)

A high-performance, self-hosted tunneling service — an alternative to services like Playit.gg or Ngrok. Expose your local projects to the internet even when your ISP or router blocks port forwarding, with better security than raw port forwarding.

## Features

- **TCP & UDP tunneling** — forward any local service through a single outbound connection
- **Multiple agents per server** — run many local agents behind one server exit point, each with a persistent Ed25519 identity; routes, domains, and the mail service are attributed and addressed per agent
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

### HTTP API Reference

The SDK is a thin HTTP client over the agent's local API. You can reimplement it in any language by sending the requests below to the agent's base URL (default: `http://127.0.0.1:7003`).

#### Response Envelope

Every response is a JSON object with a `status` field:

```json
{"status": "ok", "data": {...}}
{"status": "error", "message": "..."}
```

- On success the HTTP status is `2xx` and the payload is in `data`.
- On failure the HTTP status is `4xx`/`5xx`, `status` is `"error"`, and `message` contains a human-readable description.

#### Status Values

| Value | Meaning |
|-------|---------|
| `ok` | Request succeeded (envelope level) |
| `error` | Request failed (envelope level) |
| `active` | Route is registered and forwarding |
| `pending_domain` | Route is waiting for domain selection (see `ListDomains` + `SelectDomain`) |
| `failed` | Server/agent rejected the route operation |
| `updated` | Route update was applied successfully |

#### Tunnel Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/register` | Register a new route |
| `GET` | `/api/v1/routes` | List active routes |
| `DELETE` | `/api/v1/routes/{name}` | Remove a route |
| `POST` / `PATCH` | `/api/v1/routes/update` | Update an existing route |
| `GET` | `/api/v1/route/stats?name={name}` | Get per-route status |
| `GET` | `/api/v1/status` | Get agent connection status |
| `GET` | `/api/v1/domains` | List available domains |
| `POST` | `/api/v1/domains/select` | Confirm a domain choice |
| `WebSocket` | `/api/v1/events` | Subscribe to live route events |

#### Schemas

**`RegisterRequest`** — `POST /api/v1/register`

```json
{
  "name": "my-app",
  "proto": "tcp",
  "local_port": 3000,
  "local_host": "127.0.0.1",
  "public_port": 0,
  "domain": "auto",
  "encrypted": false
}
```

- `proto`: `"tcp"` (default), `"udp"`, or `"both"`
- `local_host`: defaults to `"127.0.0.1"`
- `domain`: `""` for port-only, `"auto"` to auto-suggest, or an explicit FQDN
- `public_port`: `0` means auto-assign

**`RegisterResponse`** — returned by `/api/v1/register` and `/api/v1/domains/select`

```json
{
  "status": "active",
  "request_id": "...",
  "route_name": "my-app",
  "public_addr": "1.2.3.4:12345",
  "local_addr": "127.0.0.1:3000",
  "proto": "tcp",
  "domain": "my-app.example.com",
  "available_domains": [...]
}
```

When `status` is `"pending_domain"`, `available_domains` contains:

```json
{
  "host": "my-app.example.com",
  "available": true,
  "reason": "",
  "used_by": ""
}
```

**`DomainSelectRequest`** — `POST /api/v1/domains/select`

```json
{
  "request_id": "...",
  "route_name": "my-app",
  "domain": "my-app.example.com"
}
```

**`RouteUpdateRequest`** — `POST` / `PATCH` `/api/v1/routes/update`

```json
{
  "name": "my-app",
  "local_port": 4000,
  "local_host": "127.0.0.1",
  "public_port": 0,
  "domain": "auto"
}
```

Only include fields you want to change. The response `data` is `{"status":"updated","route_name":"my-app"}`.

**`Route`** — returned by `GET /api/v1/routes`

```json
{
  "name": "my-app",
  "proto": "tcp",
  "public_addr": "1.2.3.4:12345",
  "local_addr": "127.0.0.1:3000"
}
```

**`RouteStats`** — returned by `GET /api/v1/route/stats`

```json
{
  "name": "my-app",
  "proto": "tcp",
  "public_addr": "1.2.3.4:12345",
  "local_addr": "127.0.0.1:3000",
  "agent": "default",
  "connected": true,
  "source": "dynamic"
}
```

**`StatusResponse`** — returned by `GET /api/v1/status`

```json
{
  "connected": true,
  "server": "wss://host.example.com:7000",
  "version": "3.1.1",
  "routes_count": 2
}
```

**`DomainsResponse`** — returned by `GET /api/v1/domains`

```json
{
  "base": "example.com",
  "available": [
    {"host": "my-app.example.com", "available": true, ...}
  ]
}
```

**`AppEvent`** — sent over the `ws://127.0.0.1:7003/api/v1/events` WebSocket

```json
{
  "type": "route_updated",
  "timestamp": 1717660800000,
  "route_name": "my-app",
  "detail": ""
}
```

Common event types: `connected`, `disconnected`, `routes_updated`, `route_updated`.

#### Mail Endpoints

| Method | Path | Body | Response `data` |
|--------|------|------|-----------------|
| `GET` | `/api/mail/accounts` | — | `MailAccount[]` |
| `POST` | `/api/mail/accounts` | `{"username":"alice","password":"..."}` | `MailAccount` |
| `PATCH` | `/api/mail/accounts/{username}` | `{"password":"..."}` | empty (`204`) |
| `DELETE` | `/api/mail/accounts/{username}` | — | empty (`204`) |
| `POST` | `/api/mail/login` | `{"username":"alice","password":"..."}` | `{"username":"alice","address":"alice@example.com"}` |
| `POST` | `/api/mail/inbox` | `{"username":"alice","password":"..."}` | `MailMessage[]` |
| `POST` | `/api/mail/message` | `{"username":"alice","password":"...","messageId":42}` | `MailMessageFull` |
| `POST` | `/api/mail/delete` | `{"username":"alice","password":"...","messageId":42}` | empty (`204`) |
| `POST` | `/api/mail/lock` | `{"locked":true}` | `{"locked":true,"enabled":false}` |

Mail schemas:

```json
{
  "MailAccount": {"username": "alice", "address": "alice@example.com"},
  "MailMessage": {
    "id": 42,
    "mailbox": "INBOX",
    "date": "2024-06-06T12:00:00Z",
    "from": "bob@example.com",
    "to": "alice@example.com",
    "subject": "Hello",
    "flags": ["\\Seen"],
    "size": 1234
  },
  "MailMessageFull": {
    /* all MailMessage fields */
    "body": "..."
  }
}
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

## License

HostIt uses a split license:

- Core project components are licensed under the GNU Affero General Public License v3.0. This includes the server, agent, dashboards, tunnel runtime, mail runtime, and shared code outside the SDK integration surface.
- The Go SDK integration surface is licensed under the GNU Lesser General Public License v3.0. This includes `shared/sdk` and the shared API type definitions in `shared/apitypes` that the SDK exposes.

The LGPLv3 SDK license allows proprietary applications to use the SDK without requiring the application's own source code to be published solely because it links to or imports the SDK, subject to the LGPLv3 terms. Changes to the SDK integration surface itself remain covered by LGPLv3.

`LICENSE-GPL` is included because LGPLv3 incorporates GPLv3 terms by reference. It supports the SDK license and does not change the core project license from AGPLv3.
