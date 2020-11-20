#!/bin/sh

# Sample post install script
#
cd /
echo "Provisioning Script Start"
pwd
ls -la
sudo cp /home/admin/config_db_temp.json /etc/sonic/config_db.json
docker ps
docker images
echo "Provisioning Script End"
exit 0