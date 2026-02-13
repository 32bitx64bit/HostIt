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
fi

# Let the agent decide whether to autostart based on config file contents.
# The agent will check if server/token are configured (either via flags or config file)
# and auto-start if both are present.
if [ -x ./bin/tunnel-agent ]; then
	exec ./bin/tunnel-agent ${args}
fi
exec go run ./cmd/agent ${args}
