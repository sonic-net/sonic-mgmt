#!/bin/bash
#show platform summary | grep "ASIC:" | awk -F'[:]' '{print $2}' | xargs
#sample="ASIC: broadcom"

get_platform_summary() {
    PLATFORM_SUM=`show platform summary`
}

transfer_asic_from_platform_sum() {
    if [ -z "$1" ]; then
        echo "Please a platform summary."
        exit 1
    # else
    #     echo "Transfer ASIC standard name: $1"
    fi
    ASIC_STD_NAME=`echo $1 | grep "ASIC:" | awk -F 'ASIC:' '{print $2}' | awk -F'[ ]' '{print $2}' | xargs`
    get_asic_from_std "$ASIC_STD_NAME"
}

get_asic_from_std() {
    if [ -z "$1" ]; then
        echo "Please transfer a ASIC standard name"
        exit 1
    # else
    #     echo "Transfer ASIC standard name: $1"
    fi
    if [[ x"$1" == x"broadcom" ]]; then
        ASIC="brcm"
    elif [[ x"$1" == x"mellanox" ]]; then
        ASIC="mlnx"
    elif [[ x"$1" == x"barefoot" ]]; then
        ASIC="bfn"
    else
        echo "ASIC: $1 does not currently support by saitest"
        exit 1
    fi

    echo "Current ASIC is $ASIC"
}

get_asic() {
    get_platform_summary
    transfer_asic_from_platform_sum "$PLATFORM_SUM"
}

get_os_version() {
    OS_VERSION=`sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version`
}

check_sai_versions() {
    # Print helpFunction in case parameters are empty
    if [ -z "$SAI_VERSION" ]; then
        echo "version set to default v1.";
        SAI_VERSION=  #set the version to null
    fi

    #when v1 set the version to null
    if [[ x"$SAI_VERSION" != x"v2" && x"$SAI_VERSION" != x"" ]]; then
        echo ""
        echo "Error: Version perameters is not right, it only can be [v2].";
    fi
}
