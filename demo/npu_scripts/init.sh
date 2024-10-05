#!/bin/bash

echo "Create TLS certificate for gNMI server..."
sudo mkdir /etc/sonic/tls
if [ ! -f /etc/sonic/tls/server.key ]; then
    sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/sonic/tls/server.key -out /etc/sonic/tls/server.crt -days 365 -nodes -subj "/C=US/ST=California/L=San-Jose/O=Cisco"
fi
cat /etc/sonic/config_db.json | jq '. + { GNMI: { certs: { server_crt: "/etc/sonic/tls/server.crt", server_key: "/etc/sonic/tls/server.key" } } }' > config_db.json.tmp
sudo cp config_db.json.tmp /etc/sonic/config_db.json

# Reload config and gNMI server
sudo config reload -y
sudo systemctl stop gnmi
sudo systemctl start gnmi
