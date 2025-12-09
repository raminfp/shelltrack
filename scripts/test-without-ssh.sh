#!/bin/bash
#
# Test ShellTrack without SSH
# Test audit logging of commands
#

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   Testing ShellTrack (Audit Commands)     ${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

echo -e "${YELLOW}[1]${NC} Opening log viewer in background..."
echo -e "${BLUE}You can view logs with: ${YELLOW}sudo journalctl -u shelltrack -f${NC}"
echo ""

echo -e "${YELLOW}[2]${NC} Executing various commands to trigger audit logs..."
echo ""

# Execute a series of commands that will be logged
commands=(
    "whoami"
    "id"
    "hostname"
    "uname -a"
    "ps aux"
    "ls -la /etc"
    "cat /etc/os-release"
    "netstat -tlnp"
    "ss -tlnp"
    "df -h"
)

for cmd in "${commands[@]}"; do
    echo -e "${GREEN}Executing:${NC} $cmd"
    eval "$cmd" > /dev/null 2>&1 || true
    sleep 0.5
done

echo ""
echo -e "${YELLOW}[3]${NC} Executing some 'sensitive' commands..."
echo ""

# These might be flagged as more important
sensitive_commands=(
    "sudo -n -l"
    "cat /etc/passwd"
    "find /etc -name '*.conf'"
)

for cmd in "${sensitive_commands[@]}"; do
    echo -e "${GREEN}Executing:${NC} $cmd"
    eval "$cmd" > /dev/null 2>&1 || true
    sleep 0.5
done

echo ""
echo -e "${YELLOW}[4]${NC} Waiting for audit events to be processed..."
sleep 3

echo ""
echo -e "${YELLOW}[5]${NC} Recent audit events (last 20):"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
sudo ausearch -k shelltrack -ts recent 2>/dev/null | tail -20 || echo "No events found yet"

echo ""
echo -e "${YELLOW}[6]${NC} Recent ShellTrack logs:"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
sudo journalctl -u shelltrack --since "2 minutes ago" -n 20 --no-pager

echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}✓ Test completed!${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${YELLOW}To view live logs:${NC}"
echo "  sudo journalctl -u shelltrack -f"
echo ""
echo -e "${YELLOW}To view audit events:${NC}"
echo "  sudo ausearch -k shelltrack -i"
echo ""
echo -e "${YELLOW}To install SSH server for SSH testing:${NC}"
echo "  sudo apt install openssh-server"
echo "  sudo systemctl start ssh"
echo ""

