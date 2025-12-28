# playit-prototype (client)

Local agent that connects to the tunnel server and forwards public TCP connections to a local TCP service.

## Run

```sh
# from this folder
go run ./cmd/agent
```

## Build

```sh
./build.sh
./bin/tunnel-agent
```

Defaults:
- Agent dashboard: `http://127.0.0.1:7003`
- Config file: `agent.json` (created on first save)

