#!/bin/bash

echo "Creating certificate ..."
sudo  mkdir /etc/sonic/tls
sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/sonic/tls/server.key -out /etc/sonic/tls/server.crt -days 365 -nodes -subj "/C=US/ST=California/L=San-Jose/O=Cisco"

echo "Updating config-db ..."
sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" subtype SmartSwitch
sonic-db-cli CONFIG_DB hset 'GNMI|certs' server_crt /etc/sonic/tls/server.crt
sonic-db-cli CONFIG_DB hset 'GNMI|certs' server_key /etc/sonic/tls/server.key
sonic-db-cli CONFIG_DB hset 'DEVICE_METADATA|localhost' switch_type dpu
sudo config save -y

echo "Switch syncd to DASH ..."
docker cp syncd:/usr/bin/syncd_init_common.sh .
sed -i '/CMD_SYNCD/s/syncd$/syncd_dash/' ./syncd_init_common.sh
docker cp ./syncd_init_common.sh syncd:/usr/bin/syncd_init_common.sh

echo "Enable BMv2 dash-engine service ..."
sudo systemctl enable dash-engine && sudo systemctl start dash-engine

echo "Update orchagent ZMQ IP to host IP ..."
docker exec gnmi sed -i 's|if \[ ! -z $CA_CRT \]; then|if [ -n "$CA_CRT" ] \&\& [ "$CA_CRT" != "null" ]; then|' /usr/bin/gnmi-native.sh
docker commit gnmi docker-sonic-gnmi:latest
/usr/bin/gnmi.sh stop
/usr/bin/gnmi.sh start
docker exec swss sed -i 's/tcp:\/\/${mgmt_ip}:8100/tcp:\/\/0.0.0.0:8100/g' /usr/bin/orchagent.sh
docker commit swss docker-orchagent:latest
/usr/bin/swss.sh stop
/usr/bin/swss.sh start
echo "Reload config ..."
sudo config reload -y
