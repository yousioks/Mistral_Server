#!/bin/bash
# MISTRAL Server - Security Scanners Installer
# Installs Semgrep and Trivy on Ubuntu/Debian

echo "========================================================"
echo "🛡️ MISTRAL Enterprise Security - Scanner Installer 🛡️"
echo "========================================================"
echo "[*] Checking for root privileges..."
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (use sudo)"
  exit 1
fi

echo "[*] Updating package list..."
apt-get update -y > /dev/null

echo "[1/2] Installing Semgrep (SAST)..."
if ! command -v semgrep &> /dev/null; then
    echo "[+] Installing python3-pip..."
    apt-get install -y python3-pip > /dev/null
    echo "[+] Installing semgrep via pip..."
    pip3 install semgrep --break-system-packages > /dev/null || { echo "Falling back to pipx..."; apt-get install -y pipx > /dev/null && pipx install semgrep > /dev/null && ln -s /root/.local/bin/semgrep /usr/local/bin/semgrep; }
    if command -v semgrep &> /dev/null; then
        echo "[+] Semgrep installed successfully!"
    else
        echo "[-] Failed to install Semgrep."
    fi
else
    echo "[✓] Semgrep is already installed."
fi

echo "[2/2] Installing Trivy (Vulnerability Scanner)..."
if ! command -v trivy &> /dev/null; then
    echo "[+] Installing dependencies..."
    apt-get install -y wget apt-transport-https gnupg lsb-release > /dev/null
    echo "[+] Adding Aqua Security GPG key..."
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null
    echo "[+] Adding Trivy repository..."
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list > /dev/null
    echo "[+] Installing Trivy..."
    apt-get update -y > /dev/null
    apt-get install -y trivy > /dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Trivy installed successfully!"
    else
        echo "[-] Failed to install Trivy."
    fi
else
    echo "[✓] Trivy is already installed."
fi

echo "========================================================"
echo "[✅] Installation Complete."
echo "You can now run scans from the Mistral Client Dashboard!"
echo "========================================================"
