#!/bin/bash

echo "Updating switch type to DPU ..."
sonic-db-cli CONFIG_DB hset 'DEVICE_METADATA|localhost' switch_type dpu
sudo config save -y

echo "Switch syncd to DASH ..."
docker cp syncd:/usr/bin/syncd_init_common.sh .
sed -i '/CMD_SYNCD/s/syncd$/syncd_dash/' ./syncd_init_common.sh
docker cp ./syncd_init_common.sh syncd:/usr/bin/syncd_init_common.sh

echo "Enable BMv2 dash-engine service ..."
sudo systemctl enable dash-engine && sudo systemctl start dash-engine

echo "Update orchagent ZMQ IP to host IP ..."
docker exec -it swss sed -i 's/127.0.0.1/0.0.0.0/g' /usr/bin/orchagent.sh
docker exec -it swss sed -i 's/midplane_ip/midplane_mgmt_ip/g' /usr/bin/orchagent.sh
docker commit swss docker-orchagent:latest

echo "Reload config ..."
sudo config reload -y
