#!/bin/bash

USER="admin"
PASSWORD="YourPaSsWoRd"
DPU_IP="10.250.0.55"

if ! which sshpass > /dev/null; then
    echo "sshpass is not installed. Installing it..."
    sudo apt-get install -y sshpass
fi

echo "Pushing minigraph to DPU ..."
sshpass -p $PASSWORD scp ../ansible/minigraph/SONIC01DPU.xml* $USER@$DPU_IP:

echo "Installing all scripts to DPU..."
sshpass -p $PASSWORD scp dpu_scripts/* $USER@$DPU_IP:

echo "Installing all scripts to PTF..."
docker cp ptf_scripts/* ptf_vms6-1:/root/
