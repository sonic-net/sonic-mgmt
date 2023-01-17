#!/bin/bash -x

# remove saiserver and restore DUT

docker stop saiserver
docker rm saiserver
config reload -y
