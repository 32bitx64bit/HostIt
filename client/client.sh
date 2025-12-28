#!/usr/bin/env sh
set -eu

# Optional overrides
: "${WEB:=:7003}"
: "${CONFIG:=agent.json}"

exec go run ./cmd/agent -web "${WEB}" -config "${CONFIG}"
