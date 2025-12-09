#!/bin/bash
#
# ShellTrack Installation Script
# Usage: sudo ./install.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    echo_error "This script must be run as root (use sudo)"
    exit 1
fi

echo "============================================"
echo "       ShellTrack Installation Script       "
echo "============================================"
echo ""

# Get script directory (where the extracted files are)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if running from release package or from scripts/ directory
if [ -f "$SCRIPT_DIR/shelltrack" ]; then
    # Running from release package root
    INSTALL_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../shelltrack" ]; then
    # Running from scripts/ directory in release package
    INSTALL_DIR="$(dirname "$SCRIPT_DIR")"
elif [ -f "$SCRIPT_DIR/../target/release/shelltrack" ]; then
    # Running from dev environment
    INSTALL_DIR="$SCRIPT_DIR/.."
    DEV_MODE=true
else
    echo_error "Cannot find shelltrack binary. Make sure you're running from the extracted release package."
    exit 1
fi

echo_info "Install directory: $INSTALL_DIR"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo_info "Detected: $NAME $VERSION_ID"
else
    echo_error "Cannot detect OS version"
    exit 1
fi

# Install dependencies
echo_info "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq auditd 2>/dev/null || echo_warn "auditd may already be installed"

# Create directories
echo_info "Creating directories..."
mkdir -p /opt/shelltrack
mkdir -p /etc/shelltrack
mkdir -p /var/log/shelltrack

# Copy binary
echo_info "Installing shelltrack binary..."
if [ "$DEV_MODE" = true ]; then
    cp "$INSTALL_DIR/target/release/shelltrack" /opt/shelltrack/shelltrack
else
    cp "$INSTALL_DIR/shelltrack" /opt/shelltrack/shelltrack
fi
chmod +x /opt/shelltrack/shelltrack

# Copy config
echo_info "Installing configuration..."
if [ -f "$INSTALL_DIR/config/shelltrack.toml" ]; then
    cp "$INSTALL_DIR/config/shelltrack.toml" /etc/shelltrack/shelltrack.toml.example
    if [ ! -f /etc/shelltrack/shelltrack.toml ]; then
        cp "$INSTALL_DIR/config/shelltrack.toml" /etc/shelltrack/shelltrack.toml
    fi
fi
chmod 600 /etc/shelltrack/shelltrack.toml 2>/dev/null || true

# Install systemd service
echo_info "Installing systemd service..."
if [ -f "$INSTALL_DIR/systemd/shelltrack.service" ]; then
    cp "$INSTALL_DIR/systemd/shelltrack.service" /etc/systemd/system/
elif [ -f "$INSTALL_DIR/shelltrack.service" ]; then
    cp "$INSTALL_DIR/shelltrack.service" /etc/systemd/system/
fi
systemctl daemon-reload

# Configure auditd
echo_info "Configuring auditd..."
cat > /etc/audit/rules.d/shelltrack.rules << 'EOF'
-D
-b 8192
-a always,exit -F arch=b64 -S execve -k shelltrack
-a always,exit -F arch=b32 -S execve -k shelltrack
EOF

# Restart auditd
systemctl restart auditd 2>/dev/null || systemctl start auditd 2>/dev/null || true

# Enable and start shelltrack
echo_info "Enabling and starting ShellTrack service..."
systemctl enable shelltrack
systemctl start shelltrack || echo_warn "Failed to start shelltrack - please configure /etc/shelltrack/shelltrack.toml first"

echo ""
echo "============================================"
echo "       Installation Complete!               "
echo "============================================"
echo ""
echo "Configuration: /etc/shelltrack/shelltrack.toml"
echo ""
echo "Commands:"
echo "  systemctl status shelltrack   - Check status"
echo "  systemctl restart shelltrack  - Restart service"
echo "  journalctl -u shelltrack -f   - View logs"
echo ""
echo_warn "Edit /etc/shelltrack/shelltrack.toml and add your Telegram bot token!"
echo ""
