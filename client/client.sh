#!/usr/bin/env sh
set -eu

# Optional overrides
: "${WEB:=127.0.0.1:7003}"
: "${CONFIG:=agent.json}"
: "${SERVER:=127.0.0.1}"
: "${TOKEN:=}"

if [ -n "${TOKEN}" ]; then
	exec go run ./cmd/agent -web "${WEB}" -config "${CONFIG}" -server "${SERVER}" -token "${TOKEN}"
fi

exec go run ./cmd/agent -web "${WEB}" -config "${CONFIG}" -server "${SERVER}" -autostart=false
