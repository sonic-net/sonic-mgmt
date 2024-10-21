#!/bin/bash

# Setup gNMI certs
echo "Create TLS certificate for gNMI server..."
sudo mkdir /etc/sonic/tls
if [ ! -f /etc/sonic/tls/server.key ]; then
    sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/sonic/tls/server.key -out /etc/sonic/tls/server.crt -days 365 -nodes -subj "/C=US/ST=California/L=San-Jose/O=Cisco"
fi

sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" subtype SmartSwitch
sonic-db-cli CONFIG_DB hset 'GNMI|certs' server_crt /etc/sonic/tls/server.crt
sonic-db-cli CONFIG_DB hset 'GNMI|certs' server_key /etc/sonic/tls/server.key
sudo config save -y

docker exec gnmi sed -i 's|if \[ ! -z $CA_CRT \]; then|if [ -n "$CA_CRT" ] \&\& [ "$CA_CRT" != "null" ]; then|' /usr/bin/gnmi-native.sh
docker exec swss sed -i 's/tcp:\/\/${mgmt_ip}:8100/tcp:\/\/0.0.0.0:8100/g' /usr/bin/orchagent.sh

# Reload config to restart gNMI server
sudo config reload -y
