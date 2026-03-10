#!/bin/bash

DIR=$(dirname $(readlink -f "$0")) # absolute path
. $DIR/Utils.sh
get_asic
get_os_version

docker stop syncd
docker rm syncd
#replace syncd with syncd-rpc
echo "Tag [docker-syncd-${ASIC}-rpc:${OS_VERSION}]  To [docker-syncd-${ASIC}-rpc]"
docker tag docker-syncd-${ASIC}-rpc:${OS_VERSION} docker-syncd-${ASIC}-rpc
echo "Tag [docker-syncd-${ASIC}-rpc] to  [docker-syncd-${ASIC}:latest]"
docker tag docker-syncd-${ASIC}-rpc docker-syncd-${ASIC}:latest
/usr/bin/syncd.sh start
