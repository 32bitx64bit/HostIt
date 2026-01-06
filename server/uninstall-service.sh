#!/usr/bin/env sh
set -eu

# Uninstalls the systemd service for HostIt server.
# Usage: sudo ./uninstall-service.sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)

if [ "$(id -u)" != "0" ]; then
  echo "ERROR: run as root (sudo)" >&2
  exit 1
fi

systemctl disable --now hostit-server.service 2>/dev/null || true
rm -f /etc/systemd/system/hostit-server.service
systemctl daemon-reload

echo "Removed: hostit-server.service"
