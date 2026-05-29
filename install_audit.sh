#!/bin/bash
# MISTRAL Defense - Audit Installation Script
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

echo "Installing Bash Command Audit Hook..."

cat << 'EOF' > /etc/profile.d/mistral_audit.sh
# MISTRAL DEFENSE AUDIT
export PROMPT_COMMAND='RETRN_VAL=$?;logger -p local6.debug -t mistral-audit "USER=$(whoami) PID=$$ PWD=$(pwd) CMD=$(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//") IP=$(echo $SSH_CLIENT | awk "{print \$1}")"'
EOF

chmod +x /etc/profile.d/mistral_audit.sh
echo "Audit hook installed! Commands will now be logged to syslog."
echo "Please re-login to your SSH session to apply the hook."
