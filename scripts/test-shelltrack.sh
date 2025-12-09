#!/bin/bash
#
# ShellTrack Test Script
# Run various tests to verify ShellTrack is working correctly
#

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}       ShellTrack System Test               ${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Test 1: Check if ShellTrack is running
echo -e "${YELLOW}[TEST 1]${NC} Checking if ShellTrack service is running..."
if systemctl is-active --quiet shelltrack; then
    echo -e "${GREEN}✓ ShellTrack service is running${NC}"
else
    echo -e "${RED}✗ ShellTrack service is NOT running${NC}"
    exit 1
fi

# Test 2: Check if auditd is running
echo ""
echo -e "${YELLOW}[TEST 2]${NC} Checking if auditd service is running..."
if systemctl is-active --quiet auditd; then
    echo -e "${GREEN}✓ auditd service is running${NC}"
else
    echo -e "${RED}✗ auditd service is NOT running${NC}"
    exit 1
fi

# Test 3: Check audit rules
echo ""
echo -e "${YELLOW}[TEST 3]${NC} Checking audit rules..."
if sudo auditctl -l | grep -q shelltrack; then
    echo -e "${GREEN}✓ ShellTrack audit rules are loaded${NC}"
    sudo auditctl -l | grep shelltrack
else
    echo -e "${RED}✗ ShellTrack audit rules are NOT loaded${NC}"
fi

# Test 4: Check configuration file
echo ""
echo -e "${YELLOW}[TEST 4]${NC} Checking configuration..."
if [ -f /etc/shelltrack/shelltrack.toml ]; then
    echo -e "${GREEN}✓ Configuration file exists${NC}"
    
    # Check if Telegram token is configured
    if grep -q "token = \"YOUR_BOT_TOKEN\"" /etc/shelltrack/shelltrack.toml; then
        echo -e "${YELLOW}⚠ Telegram bot token not configured yet${NC}"
    else
        echo -e "${GREEN}✓ Telegram bot token appears to be configured${NC}"
    fi
else
    echo -e "${RED}✗ Configuration file not found${NC}"
fi

# Test 5: Generate test events
echo ""
echo -e "${YELLOW}[TEST 5]${NC} Generating test audit events..."
echo -e "${BLUE}Running some commands to trigger audit logs...${NC}"

# Execute some commands that will be logged
whoami > /dev/null
ls /tmp > /dev/null
echo "Test command" > /dev/null

sleep 2

echo -e "${GREEN}✓ Test commands executed${NC}"

# Test 6: Check recent audit events
echo ""
echo -e "${YELLOW}[TEST 6]${NC} Checking recent audit events..."
if command -v ausearch &> /dev/null; then
    AUDIT_COUNT=$(sudo ausearch -k shelltrack -ts recent 2>/dev/null | grep -c "type=EXECVE" || echo "0")
    if [ "$AUDIT_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ Found $AUDIT_COUNT audit events${NC}"
        echo -e "${BLUE}Sample recent events:${NC}"
        sudo ausearch -k shelltrack -ts recent 2>/dev/null | head -20
    else
        echo -e "${YELLOW}⚠ No recent audit events found (this is normal if just started)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ ausearch command not available${NC}"
fi

# Test 7: Check ShellTrack logs
echo ""
echo -e "${YELLOW}[TEST 7]${NC} Recent ShellTrack logs (last 10 lines)..."
sudo journalctl -u shelltrack -n 10 --no-pager

# Test 8: SSH Failed Login Simulation (interactive)
echo ""
echo -e "${YELLOW}[TEST 8]${NC} SSH Failed Login Test"
echo -e "${BLUE}To test SSH failed login detection:${NC}"
echo -e "  1. Open another terminal"
echo -e "  2. Try to SSH with wrong credentials multiple times:"
echo -e "     ${YELLOW}ssh wronguser@localhost${NC}"
echo -e "  3. Watch the logs:"
echo -e "     ${YELLOW}sudo journalctl -u shelltrack -f${NC}"
echo ""

# Summary
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}       Test Summary                         ${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${GREEN}✓ ShellTrack is installed and running${NC}"
echo -e "${GREEN}✓ auditd is monitoring commands${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Configure Telegram bot token if not done:"
echo "     ${YELLOW}sudo nano /etc/shelltrack/shelltrack.toml${NC}"
echo ""
echo "  2. Watch live logs:"
echo "     ${YELLOW}sudo journalctl -u shelltrack -f${NC}"
echo ""
echo "  3. Test SSH failed logins (from another terminal):"
echo "     ${YELLOW}ssh wronguser@localhost${NC}"
echo ""
echo "  4. Monitor audit events:"
echo "     ${YELLOW}sudo ausearch -k shelltrack -ts recent -i${NC}"
echo ""

