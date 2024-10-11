#!/bin/bash

source ./demo_env.sh

echo "Pushing DASH pipeline to DPU ..."
$DPU_PW $SSH admin@$DPU_IP "rm -f /home/admin/dash/*"
$DPU_PW $SSH admin@$DPU_IP "mkdir -p /home/admin/dash"
$DPU_PW $SCP $DEMO_BUILDIMAGE_DIR/src/dash-sai/DASH/dash-pipeline/bmv2/dash_pipeline.bmv2/* admin@$DPU_IP:/home/admin/dash/
$DPU_PW $SSH admin@$DPU_IP "for f in \`ls -1 /home/admin/dash/*\`; do docker cp \$f syncd:/etc/dash; done"

echo "Persistent updated syncd container ..."
$DPU_PW $SSH admin@$DPU_IP "docker commit syncd docker-syncd-vs-dbg:latest"
$DPU_PW $SSH admin@$DPU_IP "docker stop syncd"
$DPU_PW $SSH admin@$DPU_IP "docker rm syncd"

echo "Restart DASH engine ..."
$DPU_PW $SSH admin@$DPU_IP "sudo systemctl stop dash-engine"
$DPU_PW $SSH admin@$DPU_IP "sudo systemctl start dash-engine"

echo "Run config reload to reapply DASH pipeline ..."
$DPU_PW $SSH admin@$DPU_IP "sudo config reload -y -f"

echo ""
