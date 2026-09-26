#!/bin/bash
set -e

echo "Starting Packet Engine Entrypoint..."

# Ensure Suricata logging directory exists
mkdir -p /var/log/suricata/

# Update Suricata rules if not already present
if [ ! -f /var/lib/suricata/rules/suricata.rules ]; then
    echo "Updating Suricata rules..."
    suricata-update || true
else
    echo "Suricata rules already present, skipping full download..."
fi

# Configure HOME_NET to include the enterprise subnets
# This ensures Suricata correctly classifies traffic direction
echo "Configuring Suricata HOME_NET for enterprise subnets..."
sed -i 's|HOME_NET:.*|HOME_NET: "[10.0.1.0/24,10.0.2.0/24]"|' /etc/suricata/suricata.yaml
sed -i 's|EXTERNAL_NET:.*|EXTERNAL_NET: "!$HOME_NET"|' /etc/suricata/suricata.yaml

# Include custom local rules if present
if [ -f /etc/suricata/rules/local.rules ]; then
    echo "Adding /etc/suricata/rules/local.rules to Suricata configuration..."
    if ! grep -q "/etc/suricata/rules/local.rules" /etc/suricata/suricata.yaml; then
        sed -i '/rule-files:/a\  - /etc/suricata/rules/local.rules' /etc/suricata/suricata.yaml
    fi
fi

# Clean up stale PID files
echo "Cleaning up any stale PID files..."
rm -f /var/run/suricata.pid

# Enable flow, dns, and http event types in eve-log
echo "Enabling flow, dns, and http logs in Suricata..."
sed -i 's/# *- flow/- flow/g' /etc/suricata/suricata.yaml
sed -i 's/# *- dns/- dns/g' /etc/suricata/suricata.yaml
sed -i 's/# *- http/- http/g' /etc/suricata/suricata.yaml

# Sniff on all non-loopback network interfaces (e.g. eth0, eth1)
IFACE_ARGS=""
for iface in $(ls -1 /sys/class/net | grep -v lo); do
    IFACE_ARGS="$IFACE_ARGS -i $iface"
done

echo "Starting Suricata on interfaces: $IFACE_ARGS..."
suricata -D -c /etc/suricata/suricata.yaml $IFACE_ARGS

# Wait for the eve.json file to be created before starting the Python tail script
echo "Waiting for /var/log/suricata/eve.json to be created..."
while [ ! -f /var/log/suricata/eve.json ]; do
    sleep 1
done

echo "eve.json found! Starting Python EveReader..."
exec python main.py

