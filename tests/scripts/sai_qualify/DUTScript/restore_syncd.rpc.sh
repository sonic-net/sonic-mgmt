#!/bin/bash

# remove syncd-rpc container and restore DUT

DIR=$(dirname $(readlink -f "$0")) # absolute path
. $DIR/Utils.sh
get_asic
get_os_version

docker stop syncd
docker rm syncd

docker tag docker-syncd-${ASIC}:${OS_VERSION} docker-syncd-${ASIC}:latest
config reload -y
