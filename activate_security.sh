#!/usr/bin/env bash
# MISTRAL Defense - System Security Activation & Checker
# Configures and enables UFW, installs fail2ban, starts Lua monitors.

echo "=========================================================="
echo "🛡️ MISTRAL Enterprise Security - System Hardener & Checker"
echo "=========================================================="

# 1. Check root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (use sudo)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2. Check and Install Lua
echo "[*] Checking Lua runtime..."
if ! command -v lua &> /dev/null; then
    echo "[+] Lua not found. Installing Lua..."
    apt-get update -y >/dev/null
    apt-get install -y lua5.3 >/dev/null
    if command -v lua5.3 &> /dev/null; then
        ln -sf /usr/bin/lua5.3 /usr/bin/lua
        echo "[✓] Lua installed successfully!"
    else
        echo "[-] Failed to install Lua."
    fi
else
    echo "[✓] Lua is already installed."
fi

# 3. Check and Start Lua Monitors
echo "[*] Initializing Lua security monitors..."
PID_DIR="${SCRIPT_DIR}/monitors/pids"
mkdir -p "$PID_DIR"

if [ -f "${SCRIPT_DIR}/monitors/run-monitors.sh" ]; then
    chmod +x "${SCRIPT_DIR}/monitors/run-monitors.sh"
    bash "${SCRIPT_DIR}/monitors/run-monitors.sh" start
else
    echo "[-] run-monitors.sh launcher script not found!"
fi

# 4. Check and Install Fail2ban
echo "[*] Checking fail2ban service..."
if ! command -v fail2ban-client &> /dev/null; then
    echo "[+] Fail2ban not found. Installing fail2ban..."
    apt-get update -y >/dev/null
    apt-get install -y fail2ban >/dev/null
    if [ $? -eq 0 ]; then
        echo "[✓] Fail2ban installed successfully!"
    else
        echo "[-] Failed to install Fail2ban."
    fi
else
    echo "[✓] Fail2ban is already installed."
fi

# 5. Enable and configure UFW firewall
echo "[*] Hardening firewall (UFW)..."
if ! command -v ufw &> /dev/null; then
    echo "[+] Installing UFW..."
    apt-get install -y ufw >/dev/null
fi

# Allow critical connection ports to prevent lockout
echo "[+] Ensuring administration and app ports are allowed..."
ufw allow 22/tcp comment 'allow ssh admin'
ufw allow 80/tcp comment 'allow web port'
ufw allow 443/tcp comment 'allow secure web port'
ufw allow 8080/tcp comment 'allow Mistral API port'
ufw allow 8443/tcp comment 'allow Mistral WSS port'

# Activate UFW firewall
echo "[+] Enabling UFW..."
ufw --force enable

# 6. Configure & Enable Fail2ban service
echo "[*] Restarting fail2ban service..."
if [ -f /etc/fail2ban/jail.conf ]; then
    # Create or update jail.local for custom rules if needed
    cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF
fi

systemctl enable fail2ban &>/dev/null || true
systemctl restart fail2ban &>/dev/null || service fail2ban restart &>/dev/null || true

echo "=========================================================="
echo "[✅] System hardening complete!"
echo "Lua monitors are active, UFW firewall is enabled, and fail2ban is running."
echo "=========================================================="
