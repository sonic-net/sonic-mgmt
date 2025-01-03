#!/bin/bash

set -euo pipefail

set -x

IMAGE_DIR_NAME=$1

mount -t proc /proc
mount -t tmpfs tmpfs /run
mount --bind /host/${IMAGE_DIR_NAME}/docker /var/lib/docker

dockerd -l warn &

sleep 3

docker system prune -f

rm -rf /host/${IMAGE_DIR_NAME}/rw
touch /host/${IMAGE_DIR_NAME}/platform/firsttime
