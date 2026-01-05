#!/usr/bin/env sh
set -eu

# Installs a systemd service so HostIt agent keeps running after SSH disconnect.
# Usage: sudo ./install-service.sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)

if [ "$(id -u)" != "0" ]; then
  echo "ERROR: run as root (sudo)" >&2
  exit 1
fi

mkdir -p /etc/hostit
if [ ! -f /etc/hostit/agent.env ]; then
  cat > /etc/hostit/agent.env <<'EOF'
# Optional overrides for client/client.sh
# WEB=127.0.0.1:7003
# CONFIG=agent.json
# SERVER=
# TOKEN=
EOF
  chmod 0644 /etc/hostit/agent.env
fi

UNIT_SRC="$SCRIPT_DIR/hostit-agent.service"
UNIT_DST="/etc/systemd/system/hostit-agent@.service"
cp "$UNIT_SRC" "$UNIT_DST"
chmod 0644 "$UNIT_DST"

systemctl daemon-reload

INST_RAW="$SCRIPT_DIR"
INST_ESC=$(systemd-escape -p "$INST_RAW")
systemctl enable --now "hostit-agent@${INST_ESC}.service"

echo "Installed and started: hostit-agent@${INST_ESC}.service"
echo "Status: systemctl status hostit-agent@${INST_ESC}.service"
