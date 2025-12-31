#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)
cd "$SCRIPT_DIR"

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

# Wrapper flags (handled by this script) can be passed before any server flags.
# - Default: do NOT rebuild (fast dev loop)
# - Force rebuild: ./server.sh --build
BUILD=0
EXTRA_ARGS=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --build|--rebuild)
      BUILD=1
      shift
      ;;
    --)
      shift
      # Everything after -- is forwarded verbatim.
      EXTRA_ARGS="$*"
      break
      ;;
    *)
      # Forward unknown args to the server binary.
      EXTRA_ARGS="${EXTRA_ARGS} $1"
      shift
      ;;
  esac
done

if [ ! -x ./bin/tunnel-server ]; then
  BUILD=1
fi
if [ "$BUILD" = "1" ]; then
  ./build.sh
fi

exec ./bin/tunnel-server ${args} ${EXTRA_ARGS}
