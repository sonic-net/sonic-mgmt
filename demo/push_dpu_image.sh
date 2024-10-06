#!/bin/bash

source ./demo_env.sh

echo "Pushing DASH container to DPU ..."
$DPU_PW $SCP $DEMO_BUILDIMAGE_DIR/target/docker-dash-engine.gz admin@$DPU_IP:
echo "Stopping DASH engine ..."
$DPU_PW $SSH admin@$DPU_IP "sudo systemctl stop dash-engine"
$DPU_PW $SSH admin@$DPU_IP "docker rm dash_engine"
echo "Loading new DASH engine ..."
$DPU_PW $SSH admin@$DPU_IP "docker load -i docker-dash-engine.gz"
$DPU_PW $SSH admin@$DPU_IP "sudo systemctl start dash-engine"
echo "Reload config ..."
$DPU_PW $SSH admin@$DPU_IP "sudo config reload -y"
