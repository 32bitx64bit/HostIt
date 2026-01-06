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
  printf '%s\n' \
    '# Optional overrides for server/server.sh' \
    '# WEB=:7002' \
    '# CONFIG=server.json' \
    '# AUTH_DB=auth.db' \
    '# COOKIE_SECURE=0' \
    '# SESSION_TTL=168h' \
    > /etc/hostit/server.env
  chmod 0644 /etc/hostit/server.env
fi

UNIT_SRC="$SCRIPT_DIR/hostit-server.service"
UNIT_DST="/etc/systemd/system/hostit-server.service"

# Generate a concrete unit with the correct absolute WorkingDirectory.
printf '%s\n' \
  '[Unit]' \
  'Description=HostIt Tunnel Server' \
  'After=network-online.target' \
  'Wants=network-online.target' \
  '' \
  '[Service]' \
  'Type=simple' \
  "WorkingDirectory=${SCRIPT_DIR}" \
  'EnvironmentFile=-/etc/hostit/server.env' \
  '' \
  'ExecStartPre=/bin/sh -c "test -x ./bin/tunnel-server || (echo Missing ./bin/tunnel-server. Run ./build.sh once as your user. >&2; exit 1)"' \
  "ExecStart=${SCRIPT_DIR}/server.sh" \
  '' \
  'Restart=always' \
  'RestartSec=2' \
  'NoNewPrivileges=true' \
  '' \
  '[Install]' \
  'WantedBy=multi-user.target' \
  > "$UNIT_DST"

chmod 0644 "$UNIT_DST"

echo "Wrote: $UNIT_DST"
systemctl daemon-reload

echo "Enabling + starting (non-blocking): hostit-server.service"
systemctl enable --now --no-block hostit-server.service

echo "Installed and started: hostit-server.service"
echo "Status: systemctl status hostit-server.service"
