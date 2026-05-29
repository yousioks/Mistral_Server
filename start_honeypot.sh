#!/bin/bash
# MISTRAL Defense - Honeypot Deployment
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

echo "Starting Mistral Defense Honeypot..."
# Run a dummy container that looks like an important service
docker run -d --name remon_payment_gateway --restart always alpine tail -f /dev/null

echo "Honeypot started! Any interaction with 'remon_payment_gateway' will trigger a CRITICAL alert."
