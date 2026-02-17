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
  printf '%s\n' \
    '# Optional overrides for client/client.sh' \
    '# WEB=127.0.0.1:7003' \
    '# CONFIG=agent.json' \
    '# SERVER=' \
    '# TOKEN=' \
    > /etc/hostit/agent.env
  chmod 0644 /etc/hostit/agent.env
fi

UNIT_SRC="$SCRIPT_DIR/hostit-agent.service"
UNIT_DST="/etc/systemd/system/hostit-agent.service"

printf '%s\n' \
  '[Unit]' \
  'Description=HostIt Tunnel Agent' \
  'After=network-online.target' \
  'Wants=network-online.target' \
  '' \
  '[Service]' \
  'Type=simple' \
  "WorkingDirectory=${SCRIPT_DIR}" \
  'EnvironmentFile=-/etc/hostit/agent.env' \
  '' \
  'ExecStartPre=/bin/sh -c "test -x ./bin/tunnel-agent || (echo Missing ./bin/tunnel-agent. Run ./build.sh once as your user. >&2; exit 1)"' \
  "ExecStart=${SCRIPT_DIR}/client.sh" \
  '' \
  'Restart=always' \
  'RestartSec=2' \
  'NoNewPrivileges=true' \
  '' \
  '[Install]' \
  'WantedBy=multi-user.target' \
  > "$UNIT_DST"

chmod 0644 "$UNIT_DST"

systemctl daemon-reload

echo "Wrote: $UNIT_DST"
echo "Enabling + starting (non-blocking): hostit-agent.service"
systemctl enable --now --no-block hostit-agent.service

echo "Installed and started: hostit-agent.service"
echo "Status: systemctl status hostit-agent.service"
