#!/bin/bash

export DEMO_BUILDIMAGE_DIR=~/code/sonic/buildimage
export DEMO_SONICVPP_DIR=~/code/sonic/platform-vpp-image

export NPU_IP="10.250.0.101"
export NPU_PW="sshpass -p password"

export DPU_IP="10.250.0.55"
export DPU_PW="sshpass -p YourPaSsWoRd"

export SCP="scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
export SSH="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

if ! which sshpass > /dev/null; then
    echo "sshpass is not installed. Installing it..."
    sudo apt-get install -y sshpass
fi
