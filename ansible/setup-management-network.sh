#!/bin/bash
if [[ $(id -u) -ne 0 ]]; then
    echo "Root privilege required"
    exit
fi

function show_help_and_exit()
{
    echo "Usage ${SCRIPT} [options]"
    echo "    options with (*) must be provided"
    echo "    -h -?                  : get this help"
    echo "    -d                     : Delete existed bridge"


    exit $1
}

DEL_EXISTED_BRIDGE=false

while getopts "h?d" opt; do
    case ${opt} in
        h|\? )
            show_help_and_exit 0
            ;;
        d)
            DEL_EXISTED_BRIDGE=true
            ;;
    esac
done


echo "Refreshing apt package lists..."
apt-get update
echo

echo "STEP 1: Checking for j2cli package..."
if ! command -v j2; then
    echo "j2cli not found, installing j2cli"
    cmd="install --user j2cli==0.3.10"
    if ! command -v pip &> /dev/null; then
        pip3 $cmd
    else
        pip $cmd
    fi
fi
echo

echo "STEP 2: Checking for bridge-utils package..."
if ! command -v brctl; then
    echo "brctl not found, installing bridge-utils"
    apt-get install -y bridge-utils
fi
echo

echo "STEP 3: Checking for net-tools package..."
if ! command -v ifconfig; then
    echo "ifconfig not found, install net-tools"
    apt-get install -y net-tools
fi
echo

echo "STEP 4: Checking for ethtool package..."
if ! command -v ethtool; then
    echo "ethtool not found, install ethtool"
    apt-get install -y ethtool
fi
echo

echo "STEP 5: Delete existed br1..."
if [ "$DEL_EXISTED_BRIDGE" = true ] && ifconfig br1 >/dev/null 2>&1; then
    echo "br1 exists, remove it."
    ifconfig br1 down
    brctl delbr br1
else
    echo "Not delete existed bridge or br1 not exists, skipping..."
fi
echo

echo "STEP 6: Checking if bridge br1 already exists..."
if ! ifconfig br1; then
    echo "br1 not found, creating bridge network"
    brctl addbr br1
    brctl show br1
else
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo
    echo "  br1 exists, possibly lab server, are you sure you want to continue?"
    echo
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo
    echo
    echo "Please double check and manually configure IP for br1 to avoid breaking lab server connectivity"
    exit 0
fi
echo

echo "STEP 7: Configuring br1 interface..."
echo "Assigning 10.250.0.1/24 to br1"
ifconfig br1 10.250.0.1/24
ifconfig br1 inet6 add fec0::1/64
echo "Bringing up br1"
ifconfig br1 up
echo

echo "COMPLETE. Bridge info:"
echo
brctl show br1
echo
ifconfig br1
