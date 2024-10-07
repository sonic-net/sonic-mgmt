#!/bin/bash

source ./demo_env.sh

echo "Pushing DASH container to DPU ..."
$DPU_PW $SSH admin@$DPU_IP "rm -f sonic-vs.bin"
$DPU_PW $SCP $DEMO_BUILDIMAGE_DIR/target/sonic-vs.bin admin@$DPU_IP:
echo ""
