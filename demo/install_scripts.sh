#!/bin/bash

source ./demo_env.sh

#
# Installing all contents to NPU
#
echo "Installing all scripts to NPU..."
$NPU_PW $SCP npu_scripts/* admin@$NPU_IP:

#
# Installing all contents to DPU
#
echo "Pushing minigraph to DPU ..."
$DPU_PW $SCP ../ansible/minigraph/SONIC01DPU.xml* admin@$DPU_IP:

echo "Installing all scripts to DPU..."
$DPU_PW $SCP dpu_scripts/* admin@$DPU_IP:
$DPU_PW $SSH admin@$DPU_IP "for f in \`ls -1 p4_*.py\`; do docker cp \$f dash_engine:/behavioral-model; done"

echo "Pushing p4runtime shell to DPU..."
if [ ! -f p4runtime-sh.tar ]; then
    docker pull p4lang/p4runtime-sh
    docker save p4lang/p4runtime-sh:latest -o p4runtime-sh.tar
fi
$DPU_PW $SCP p4runtime-sh.tar admin@$DPU_IP:
$DPU_PW $SSH admin@$DPU_IP "docker load -i p4runtime-sh.tar"

echo ""

#
# Installing all contents to PTF
#
echo "Installing all scripts to PTF..."
for f in `ls -1 ptf_scripts/*`; do
    docker cp $f ptf_vms6-1:/root/
done
echo ""

#
# Installing all contents to mgmt container
#
echo "Pushing dash api to mgmt container"
docker cp $DEMO_BUILDIMAGE_DIR/target/debs/bookworm/libdashapi_1.0.0_amd64.deb mgmt:/home/$USER/
echo "Installing dash api to mgmt container"
docker exec mgmt sudo dpkg -i /home/$USER/libdashapi_1.0.0_amd64.deb
echo ""

#
# Installing all contents to host machine
#
echo "Installing SONiC gnmi agent docker image..."
docker load -i $DEMO_SONICVPP_DIR/docker-sonic-gnmi-agent.gz
echo ""
