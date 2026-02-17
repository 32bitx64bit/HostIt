#!/bin/bash
# Setup script for UDP buffer tuning to reduce packet loss
# This script configures kernel parameters for high-bandwidth UDP streaming
# Run with sudo: sudo bash setup-udp-buffers.sh

set -e

echo "=== HostIt UDP Buffer Configuration ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Current values
echo "Current UDP buffer settings:"
echo "  rmem_max: $(sysctl -n net.core.rmem_max) bytes"
echo "  wmem_max: $(sysctl -n net.core.wmem_max) bytes"
echo "  rmem_default: $(sysctl -n net.core.rmem_default) bytes"
echo "  wmem_default: $(sysctl -n net.core.wmem_default) bytes"
echo ""

# Recommended values for high-bandwidth streaming (6+ ports)
RMEM_MAX=67108864       # 64 MB
WMEM_MAX=67108864       # 64 MB
RMEM_DEFAULT=33554432   # 32 MB
WMEM_DEFAULT=33554432   # 32 MB

echo "Applying recommended settings for high-load scenarios..."
echo "  rmem_max: $RMEM_MAX bytes (64 MB)"
echo "  wmem_max: $WMEM_MAX bytes (64 MB)"
echo "  rmem_default: $RMEM_DEFAULT bytes (32 MB)"
echo "  wmem_default: $WMEM_DEFAULT bytes (32 MB)"
echo ""

# Apply settings
sysctl -w net.core.rmem_max=$RMEM_MAX
sysctl -w net.core.wmem_max=$WMEM_MAX
sysctl -w net.core.rmem_default=$RMEM_DEFAULT
sysctl -w net.core.wmem_default=$WMEM_DEFAULT

# Additional UDP memory settings
sysctl -w net.ipv4.udp_mem="262144 524288 1048576"

# Make persistent across reboots
SYSCTL_FILE="/etc/sysctl.d/99-hostit-udp.conf"
cat > "$SYSCTL_FILE" << EOF
# HostIt UDP buffer configuration for high-bandwidth streaming
# These settings are optimized for scenarios like Sunshine streaming with multiple ports

# Maximum socket receive buffer size
net.core.rmem_max = $RMEM_MAX

# Maximum socket send buffer size
net.core.wmem_max = $WMEM_MAX

# Default socket receive buffer size
net.core.rmem_default = $RMEM_DEFAULT

# Default socket send buffer size
net.core.wmem_default = $WMEM_DEFAULT

# UDP memory limits (min, pressure, max) in pages
net.ipv4.udp_mem = 262144 524288 1048576
EOF

echo "Settings applied and persisted to $SYSCTL_FILE"
echo ""

# Verify new values
echo "New UDP buffer settings:"
echo "  rmem_max: $(sysctl -n net.core.rmem_max) bytes"
echo "  wmem_max: $(sysctl -n net.core.wmem_max) bytes"
echo "  rmem_default: $(sysctl -n net.core.rmem_default) bytes"
echo "  wmem_default: $(sysctl -n net.core.wmem_default) bytes"
echo ""

echo "=== Configuration Complete ==="
echo ""
echo "Next steps:"
echo "1. Rebuild the server and client:"
echo "   cd server && ./build.sh"
echo "   cd ../client && ./build.sh"
echo ""
echo "2. Restart the server and agent services"
echo ""
echo "3. Monitor logs for buffer size confirmation:"
echo "   Look for: 'UDP buffers [server]: read=X write=Y (requested 67108864)'"
echo ""
echo "4. Monitor queue drops:"
echo "   Look for: 'UDP agent queue drops' or 'UDP public queue drops'"
echo ""
echo "Optional: Override worker count with environment variable:"
echo "   export HOSTIT_UDP_WORKERS=32"
echo "   ./server.sh  # or ./client.sh"
