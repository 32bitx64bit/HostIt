#!/usr/bin/env sh
set -eu

# Optional overrides
: "${WEB:=:7002}"
: "${CONFIG:=server.json}"
: "${AUTH_DB:=auth.db}"
: "${COOKIE_SECURE:=0}" # set to 1 when behind HTTPS
: "${SESSION_TTL:=168h}" # 7 days

args="-web ${WEB} -config ${CONFIG} -auth-db ${AUTH_DB} -session-ttl ${SESSION_TTL}"
if [ "${COOKIE_SECURE}" = "1" ]; then
  args="${args} -cookie-secure"
fi

exec go run ./cmd/server ${args}
