# HostIt
HostIt is a high performance self hosted version of similar services such as Playit.gg or Ngrok used to create a tunnel to forward your local projects to the wider web.
Very useful especially in cases where your ISP or router can't do port forwarding, and also provides better security than port forwarding. 

## Quick Start

### Prerequisites
- GO version 1.26.1 (Or greater) needs to be installed.
- VPS for a Linux server (With go installed as well)
- Ports 7000/7001 (agent control and data listeners), 7002 (dashboard). So ensure these ports are opened and not blocked.
- Make sure the respective folders are on the respective machines. Client + Shared for the client, and then server + shared for the server.

### Server (Linux only)
1. cd into the server directory
Then run
   ```sh
   ./build.sh
   ```
2. Start the server. 
   ```sh
   ./server.sh
   ```
3. Open the dashboard (`http://<server-host>:7002`) to finish setup. First start shows the setup wizard, once finished the server has been setup.

4. Optionally, run it as a service, via install-service.sh (Must be ran as sudo)

### Client

#### Linux client
1. cd into the client dictory and run
   ```sh
   ./build.sh
   ```
2. Start the agent launcher script (the dashboard runs on `127.0.0.1:7003` by default):
   ```sh
   ./client.sh
   ```
3. Setup the client with the correct token and server IP.

4. Click "Save + restart agent", it should connect successfully to the server, unless something is misconfigured.

5. Optionally run it as a service, via install-service.sh (must be ran as sudo)
#### Windows client
1. cd into the client dictory and run 
   ```powershell
   .\build.ps1
   ```
2. Run the launcher:
   ```powershell
   .\client.ps1
   ```
3. Setup the client with the correct token and server IP.

4. Click "Save + restart agent", it should connect successfully to the server, unless something is misconfigured.

5. Additional note, windows is considered experimental, and untested. Expect bugs!

## Run in the background (daemon) on Linux

If you launch the server from a SSH, it will close when the SSH tunnel is terminated / closed. If you launch the client from the terminal, and it closes, the client will close.

Use systemd so it keeps running in the background and can auto-restart.

### Server systemd service

- Build once: `cd server && ./build.sh`
- Install + start (requires sudo): `sudo sh ./server/install-service.sh`
- Logs: `journalctl -u hostit-server.service -f`
- Stop completely: `sudo systemctl stop hostit-server.service`

### Agent systemd service

- Build once: `cd client && ./build.sh`
- Install + start (requires sudo): `sudo sh ./client/install-service.sh`
- Logs: `journalctl -u hostit-agent.service -f`
- Stop completely: `sudo systemctl stop hostit-agent.service`

### Restart/exit from inside the app

Both dashboards now include **Process → Restart / Exit**.
- When running under systemd, clicking these will terminate the process and systemd will bring it back.
- If not running under systemd, it will just exit.

## Developer Integration

HostIt provides a Go SDK that lets your application register tunnel routes through a running HostIt agent. Your app talks to the local agent on `127.0.0.1:7003`, and the agent handles the rest — server negotiation, domain selection, conflict resolution.

### Import

Add the SDK to your project:

```sh
go get github.com/32bitx64bit/HostIt/shared/sdk
```

Then in your `go.mod`, add a replace directive pointing to the local path (since the shared module isn't published separately yet):

```
require github.com/32bitx64bit/HostIt/shared v0.0.0
replace github.com/32bitx64bit/HostIt/shared => ./path/to/HostIt/shared
```

### Basic Usage

```go
import "github.com/32bitx64bit/HostIt/shared/sdk"

func main() {
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
}
```

The agent API is open on localhost. All responses use a JSON envelope:

```json
// Success
{"status": "ok", "data": {...}}

// Error
{"status": "error", "message": "..."}
```

The SDK unwraps this automatically.

### Domain Routing

If the server has the domain manager enabled, your app can request a domain:

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

When `resp.Status == "pending_domain"`, list available domains and let the user pick:

```go
domains, _ := client.ListDomains(ctx)
// Present domains to user...
resp, _ = client.SelectDomain(ctx, resp.RequestID, resp.RouteName, "my-app.example.com")
```

### Updating Routes

Change a route's local port without re-registering (useful when your app restarts on a different port):

```go
client.UpdateRoute(ctx, "my-app", sdk.RouteUpdate{
    Name:      "my-app",
    LocalAddr: "127.0.0.1:4000",
})
```

### Other Operations

```go
routes, _ := client.ListRoutes(ctx)       // all active routes
stats, _ := client.RouteStats(ctx, "my-app") // per-route status
client.RemoveRoute(ctx, "my-app")         // unregister
status, _ := client.Status(ctx)           // agent connection status
wsURL := client.EventsURL()               // WebSocket URL for real-time events
```

### Email Account Management

If the agent has the email service enabled, you can manage accounts through the SDK:

```go
// Create a new email account
acct, err := client.CreateMailAccount(ctx, "alice", "password123")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Created: %s\n", acct.Address) // alice@<domain>

// Change password
err = client.UpdateMailAccountPassword(ctx, "alice", "newpassword456")

// Delete account (and all its messages)
err = client.DeleteMailAccount(ctx, "alice")
```

These correspond to the agent's HTTP endpoints:
- `GET /api/mail/accounts` — list all accounts
- `POST /api/mail/accounts` — create account
- `PATCH /api/mail/accounts/{username}` — change password
- `DELETE /api/mail/accounts/{username}` — delete account

### Email Message Operations

Read and manage messages for a specific account:

```go
// Authenticate and get the account address
addr, err := client.AuthenticateMail(ctx, "alice", "password123")

// List inbox messages
msgs, err := client.ListMailMessages(ctx, "alice", "password123")
for _, m := range msgs {
    fmt.Printf("[%d] %s - %s\n", m.ID, m.From, m.Subject)
}

// Read a full message
full, err := client.GetMailMessage(ctx, "alice", "password123", 42)
fmt.Println(full.Body)

// Delete a message
err = client.DeleteMailMessage(ctx, "alice", "password123", 42)
```

Endpoints:
- `POST /api/mail/login` — authenticate, returns address
- `POST /api/mail/inbox` — list messages
- `POST /api/mail/message` — read full message
- `POST /api/mail/delete` — delete message

### Declarative Config (apps.json)

For apps that always need the same routes, place an `apps.json` next to `agent.json`:

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

Routes with `auto_start: true` register automatically when the agent connects to the server.

