#!/bin/bash

source ./demo_env.sh

NPU_IP="10.250.0.101"
NPU_PW="sshpass -p password"

DPU_IP="10.250.0.55"
DPU_PW="sshpass -p YourPaSsWoRd"

SCP="scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
SSH="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

if ! which sshpass > /dev/null; then
    echo "sshpass is not installed. Installing it..."
    sudo apt-get install -y sshpass
fi

echo "Installing all scripts to NPU..."
$NPU_PW $SCP npu_scripts/* admin@$NPU_IP:

echo "Pushing minigraph to DPU ..."
$DPU_PW $SCP ../ansible/minigraph/SONIC01DPU.xml* admin@$DPU_IP:

echo "Installing all scripts to DPU..."
$DPU_PW $SCP dpu_scripts/* admin@$DPU_IP:

echo "Pushing p4runtime shell to DPU..."
if [ ! -f p4runtime-sh.tar ]; then
    docker pull p4lang/p4runtime-sh
    docker save p4lang/p4runtime-sh:latest -o p4runtime-sh.tar
fi
$DPU_PW $SCP p4runtime-sh.tar admin@$DPU_IP:
$DPU_PW $SSH admin@$DPU_IP "docker load -i p4runtime-sh.tar"
echo ""

echo "Installing all scripts to PTF..."
docker cp ptf_scripts/* ptf_vms6-1:/root/
echo ""

echo "Pushing dash api to mgmt container"
docker cp $DEMO_BUILDIMAGE_DIR/target/debs/bookworm/libdashapi_1.0.0_amd64.deb mgmt:/home/$USER/
echo "Installing dash api to mgmt container"
docker exec mgmt sudo dpkg -i /home/$USER/libdashapi_1.0.0_amd64.deb
echo ""

echo "Installing SONiC gnmi agent docker image..."
docker load -i $DEMO_SONICVPP_DIR/docker-sonic-gnmi-agent.gz
echo ""
