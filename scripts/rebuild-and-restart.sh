#!/bin/bash
#
# Rebuild and Restart ShellTrack
# This script rebuilds the project and restarts the service
# Run WITHOUT sudo: ./scripts/rebuild-and-restart.sh
#

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   Rebuild and Restart ShellTrack          ${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${RED}✗ Do NOT run this script with sudo${NC}"
    echo -e "${YELLOW}Usage: ./scripts/rebuild-and-restart.sh${NC}"
    exit 1
fi

# Get project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Run tests first
echo -e "${YELLOW}[1/5]${NC} Running tests..."
if cargo test --lib; then
    echo -e "${GREEN}✓ Tests passed${NC}"
else
    echo -e "${RED}✗ Tests failed${NC}"
    echo -e "${YELLOW}Continue anyway? (y/N)${NC}"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo -e "${YELLOW}[2/5]${NC} Building release binary..."
cargo build --release

echo ""
echo -e "${YELLOW}[3/5]${NC} Copying binary to /opt/shelltrack/..."
sudo cp target/release/shelltrack /opt/shelltrack/

echo ""
echo -e "${YELLOW}[4/5]${NC} Restarting ShellTrack service..."
sudo systemctl restart shelltrack

echo ""
echo -e "${YELLOW}[5/5]${NC} Checking service status..."
sleep 2
sudo systemctl status shelltrack --no-pager -l

echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}✓ ShellTrack rebuilt and restarted!${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${YELLOW}View live logs:${NC}"
echo "  sudo journalctl -u shelltrack -f"
echo ""
echo -e "${YELLOW}Test SSH failed logins:${NC}"
echo "  ssh wronguser@localhost"
echo ""

