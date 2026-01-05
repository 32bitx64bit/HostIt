#!/usr/bin/env sh
set -eu

# Installs a systemd service so HostIt server keeps running after SSH disconnect.
# Usage: sudo ./install-service.sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)

if [ "$(id -u)" != "0" ]; then
  echo "ERROR: run as root (sudo)" >&2
  exit 1
fi

mkdir -p /etc/hostit
if [ ! -f /etc/hostit/server.env ]; then
  cat > /etc/hostit/server.env <<'EOF'
# Optional overrides for server/server.sh
# WEB=:7002
# CONFIG=server.json
# AUTH_DB=auth.db
# COOKIE_SECURE=0
# SESSION_TTL=168h
EOF
  chmod 0644 /etc/hostit/server.env
fi

UNIT_SRC="$SCRIPT_DIR/hostit-server.service"
UNIT_DST="/etc/systemd/system/hostit-server@.service"
cp "$UNIT_SRC" "$UNIT_DST"
chmod 0644 "$UNIT_DST"

systemctl daemon-reload

INST_RAW="$SCRIPT_DIR"
INST_ESC=$(systemd-escape -p "$INST_RAW")
systemctl enable --now "hostit-server@${INST_ESC}.service"

echo "Installed and started: hostit-server@${INST_ESC}.service"
echo "Status: systemctl status hostit-server@${INST_ESC}.service"
