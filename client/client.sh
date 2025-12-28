#!/usr/bin/env sh
set -eu

# Always run from this script's directory so relative CONFIG paths are stable.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

# Optional overrides
: "${WEB:=127.0.0.1:7003}"
: "${CONFIG:=agent.json}"

# If you set SERVER/TOKEN in your environment, they'll be passed to the agent.
# If unset, the agent will load saved values from CONFIG.
: "${SERVER:=}"
: "${TOKEN:=}"

case "${CONFIG}" in
	/*) ;; 
	*) CONFIG="${ROOT}/${CONFIG}" ;;
esac

args="-web ${WEB} -config ${CONFIG}"

if [ -n "${SERVER}" ]; then
	args="${args} -server ${SERVER}"
fi

if [ -n "${TOKEN}" ]; then
	args="${args} -token ${TOKEN}"
	# With an explicit token, we can autostart.
	exec go run ./cmd/agent ${args}
fi

# No token provided; run UI-only mode.
exec go run ./cmd/agent ${args} -autostart=false
