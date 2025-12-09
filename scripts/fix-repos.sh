#!/bin/bash
#
# Fix Ubuntu 24.10 (Oracular) Repository Issues
# Ubuntu 24.10 reached EOL in July 2025, so we need to use old-releases
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo_error "This script must be run as root (use sudo)"
    exit 1
fi

echo "============================================"
echo "   Fix Ubuntu 24.10 Repository Issues      "
echo "============================================"
echo ""

# Detect Ubuntu version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo_info "Detected: $NAME $VERSION_ID ($VERSION_CODENAME)"
else
    echo_error "Cannot detect OS version"
    exit 1
fi

# Check if Ubuntu 24.10
if [[ "$VERSION_CODENAME" == "oracular" ]]; then
    echo_warn "Ubuntu 24.10 (Oracular) reached End of Life in July 2025"
    echo_info "Switching to old-releases.ubuntu.com..."
    
    # Backup current sources
    echo_info "Backing up current sources..."
    cp /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.backup.$(date +%s) 2>/dev/null || true
    
    # Create new sources file pointing to old-releases
    echo_info "Creating new sources file..."
    cat > /etc/apt/sources.list.d/ubuntu.sources << 'EOF'
Types: deb
URIs: http://old-releases.ubuntu.com/ubuntu/
Suites: oracular oracular-updates oracular-backports oracular-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
    
    echo_info "Sources file updated"

    # Update package list
    echo_info "Updating package list..."
    apt-get update
    
    echo ""
    echo_info "Repository configuration fixed!"
    echo ""
    
elif [[ "$VERSION_ID" == "24.04" ]] || [[ "$VERSION_CODENAME" == "noble" ]]; then
    echo_info "Ubuntu 24.04 LTS detected - repositories should be fine"
    
    # Just update
    echo_info "Updating package list..."
    apt-get update
    
else
    echo_warn "Unknown Ubuntu version. Proceeding anyway..."
    apt-get update || true
fi

echo ""
echo "============================================"
echo "           Repository Fix Complete!         "
echo "============================================"
echo ""
echo "Next step:"
echo "  sudo bash scripts/install.sh"
echo ""

