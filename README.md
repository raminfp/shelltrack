# ShellTrack

Real-time SSH brute-force detection and command tracking with Telegram alerts.

## Quick Install

```bash
# Download latest release
wget https://github.com/raminfp/shelltrack/releases/latest/download/shelltrack-x86_64-ubuntu24.04.tar.gz

# Extract
tar -xzf shelltrack-x86_64-ubuntu24.04.tar.gz

# Install
sudo ./install.sh
```

## Configuration

Edit `/etc/shelltrack/shelltrack.toml`:

```toml
[telegram]
enabled = true
bot_token = "YOUR_BOT_TOKEN"    # Get from @BotFather
chat_id = "YOUR_CHAT_ID"        # Get from @userinfobot
```

Then restart:
```bash
sudo systemctl restart shelltrack
```

## Commands

```bash
# Service
sudo systemctl start shelltrack
sudo systemctl stop shelltrack
sudo systemctl restart shelltrack
sudo systemctl status shelltrack

# Logs
sudo journalctl -u shelltrack -f
```

## Block Attackers (Firewall)

When you receive a brute-force alert, block the attacker IP:

```bash
# Using iptables
sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP

# Using ufw
sudo ufw deny from <ATTACKER_IP>
```

Make iptables rules persistent:
```bash
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

View blocked IPs:
```bash
sudo iptables -L INPUT -n -v
```

## Build from Source

```bash
cargo build --release
sudo ./scripts/install.sh
```

## License

MIT
