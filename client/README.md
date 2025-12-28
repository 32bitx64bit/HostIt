# HostIt (client)

Local agent that connects to the tunnel server and forwards based on server-pushed routes.

Security:
- The agent↔server tunnel uses TLS for control/data TCP by default.
- For UDP forwarding, the agent↔server UDP data channel is encrypted at the message layer by default.

With self-signed TLS certs, you can optionally pin the server cert fingerprint in `agent.json` using `TLSPinSHA256` (sha256 of the server cert DER, hex).

## Run

```sh
# from this folder
go run ./cmd/agent -server 127.0.0.1 -token YOUR_TOKEN
```

## Build

```sh
./build.sh
./bin/tunnel-agent
```

Defaults:
- Agent dashboard (single page): `http://127.0.0.1:7003/`
- Config file: `agent.json` (created on first save)

