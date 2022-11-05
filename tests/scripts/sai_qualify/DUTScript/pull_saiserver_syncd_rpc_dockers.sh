#!/bin/bash

#Pull saiserver or syncd-rpc container base on platform and OS version

DIR=$(dirname $(readlink -f "$0")) # absolute path
. $DIR/Utils.sh
get_asic
get_os_version

SONIC_REG=acs-repo.corp.microsoft.com:5001

pull_saiserver(){
    docker pull ${SONIC_REG}/docker-saiserver${SAI_VERSION}-${ASIC}:${OS_VERSION}
    docker tag  ${SONIC_REG}/docker-saiserver${SAI_VERSION}-${ASIC}:${OS_VERSION} docker-saiserver${SAI_VERSION}-${ASIC}
}

pull_syncd_rpc(){
    docker pull ${SONIC_REG}/docker-syncd-${ASIC}-rpc:${OS_VERSION}
    docker tag ${SONIC_REG}/docker-syncd-${ASIC}-rpc:${OS_VERSION} docker-syncd-${ASIC}-rpc
}

pull_docker(){
    if [[ x"$TARGET" =~ x"syncd" ]]; then
        echo "Pull docker syncd rpc"
        pull_syncd_rpc
    else
        echo "Pull docker saiserver $SAI_VERSION"
        pull_saiserver
    fi
}

while getopts ":v:t:" args; do
    case $args in
        v)
            SAI_VERSION=${OPTARG}
            ;;
        t)
            TARGET=${OPTARG}
            ;;
        *)
            echo -e "\t-v [v1|v2]: saiserver version, support v1 and v2"
            echo -e "\t-t [saiserver|syncd]: saiserver or syncd"
        ;;
    esac
done

check_sai_versions
pull_docker
