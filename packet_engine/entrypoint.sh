#!/bin/bash
set -e

echo "Starting Packet Engine Entrypoint..."

# Ensure Suricata logging directory exists
mkdir -p /var/log/suricata/

# Update Suricata rules (Emerging Threats Open by default)
echo "Updating Suricata rules..."
suricata-update

# Start Suricata in Daemon mode
# Note: we use the default suricata.yaml config and override the interface
INTERFACE=${CAPTURE_INTERFACE:-eth0}
echo "Cleaning up any stale PID files..."
rm -f /var/run/suricata.pid
echo "Starting Suricata on interface $INTERFACE..."
suricata -D -c /etc/suricata/suricata.yaml -i $INTERFACE

# Wait for the eve.json file to be created before starting the Python tail script
echo "Waiting for /var/log/suricata/eve.json to be created..."
while [ ! -f /var/log/suricata/eve.json ]; do
    sleep 1
done

echo "eve.json found! Starting Python EveReader..."
exec python main.py
