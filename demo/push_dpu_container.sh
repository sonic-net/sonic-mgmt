#!/bin/bash

source ./demo_env.sh

echo "Pushing DASH container to DPU ..."
$DPU_PW $SSH admin@$DPU_IP "rm -f docker-dash-engine.gz"
$DPU_PW $SSH admin@$DPU_IP "rm -f docker-syncd-vs-dbg.gz"
$DPU_PW $SCP $DEMO_BUILDIMAGE_DIR/target/docker-dash-engine.gz admin@$DPU_IP:
$DPU_PW $SCP $DEMO_BUILDIMAGE_DIR/target/docker-syncd-vs-dbg.gz admin@$DPU_IP:
echo ""

echo "Stopping DASH engine ..."
$DPU_PW $SSH admin@$DPU_IP "sudo systemctl stop dash-engine"
$DPU_PW $SSH admin@$DPU_IP "docker rm dash_engine"
$DPU_PW $SSH admin@$DPU_IP "sudo systemctl stop syncd"
$DPU_PW $SSH admin@$DPU_IP "docker rm syncd"
echo ""

echo "Loading new DASH engine ..."
$DPU_PW $SSH admin@$DPU_IP "docker load -i docker-dash-engine.gz"
$DPU_PW $SSH admin@$DPU_IP "docker load -i docker-syncd-vs-dbg.gz"

echo "Update syncd startup config ..."
echo "Switch syncd to DASH ..."
docker cp syncd:/usr/bin/syncd_init_common.sh .
sed -i '/CMD_SYNCD/s/syncd$/syncd_dash/' ./syncd_init_common.sh
docker cp ./syncd_init_common.sh syncd:/usr/bin/syncd_init_common.sh

echo "Launch services ..."
$DPU_PW $SSH admin@$DPU_IP "sudo systemctl start dash-engine"
$DPU_PW $SSH admin@$DPU_IP "sudo systemctl start syncd"
echo ""

echo "Reload config ..."
$DPU_PW $SSH admin@$DPU_IP "sudo config reload -y"
