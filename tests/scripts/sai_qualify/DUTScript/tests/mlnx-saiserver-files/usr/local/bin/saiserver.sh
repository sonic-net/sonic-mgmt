#!/bin/bash

#cat /usr/local/bin/saiserver.sh
. /usr/local/bin/saiserver_common.sh

function startplatform() {

    # platform specific tasks

    # start mellanox drivers regardless of
    # boot type
    if [[ x"$sonic_asic_platform" == x"mellanox" ]]; then
        BOOT_TYPE=`getBootType`
        if [[ x"$WARM_BOOT" == x"true" || x"$BOOT_TYPE" == x"fast" ]]; then
            export FAST_BOOT=1
        fi

        if [[ x"$WARM_BOOT" != x"true" ]]; then
            if [[ x"$(/bin/systemctl is-active pmon)" == x"active" ]]; then
                #/bin/systemctl start pmon
                debug "pmon is active while saiserver starting, stop it first"
            fi
        fi

        debug "Starting Firmware update procedure"
        /usr/bin/mst start --with_i2cdev
        /usr/bin/mlnx-fw-upgrade.sh
        /etc/init.d/sxdkernel start
        debug "Firmware update procedure ended"
    fi

    if [[ x"$WARM_BOOT" != x"true" ]]; then
        if [ x$sonic_asic_platform == x'cavium' ]; then
            /etc/init.d/xpnet.sh start
        fi
    fi
}

function waitplatform() {

    if [[ x"$sonic_asic_platform" == x"mellanox" ]]; then
        debug "Starting pmon service..."
        #/bin/systemctl start pmon
        debug "Started pmon service"
    fi
}

function stopplatform1() {

    if [[ x$sonic_asic_platform == x"mellanox" ]] && [[ x$TYPE == x"cold" ]]; then
        debug "Stopping pmon service ahead of saiserver..."
        #/bin/systemctl start pmon
        debug "Stopped pmon service"
    fi

    if [[ x$sonic_asic_platform != x"mellanox" ]] || [[ x$TYPE != x"cold" ]]; then
        debug "${TYPE} shutdown saiserver process ..."
        /usr/bin/docker exec -i saiserver$DEV /usr/bin/saiserver_request_shutdown --${TYPE}

        # wait until saiserver quits gracefully or force saiserver to exit after
        # waiting for 20 seconds
        start_in_secs=${SECONDS}
        end_in_secs=${SECONDS}
        timer_threshold=20
        while docker top saiserver$DEV | grep -q /usr/bin/saiserver \
                && [[ $((end_in_secs - start_in_secs)) -le $timer_threshold ]]; do
            sleep 0.1
            end_in_secs=${SECONDS}
        done

        if [[ $((end_in_secs - start_in_secs)) -gt $timer_threshold ]]; then
            debug "saiserver process in container saiserver$DEV did not exit gracefully"
        fi

        /usr/bin/docker exec -i saiserver$DEV /bin/sync
        debug "Finished ${TYPE} shutdown saiserver process ..."
    fi
}

function stopplatform2() {
    # platform specific tasks

    if [[ x"$WARM_BOOT" != x"true" ]]; then
        if [ x$sonic_asic_platform == x'mellanox' ]; then
            /etc/init.d/sxdkernel stop
            /usr/bin/mst stop
        elif [ x$sonic_asic_platform == x'cavium' ]; then
            /etc/init.d/xpnet.sh stop
            /etc/init.d/xpnet.sh start
        fi
    fi
}

OP=$1
DEV=$2

SERVICE="saiserver"
#PEER="swss"
DEBUGLOG="/tmp/swss-saiserver-debug$DEV.log"
LOCKFILE="/tmp/swss-saiserver-lock$DEV"
NAMESPACE_PREFIX="asic"
if [ "$DEV" ]; then
    NET_NS="$NAMESPACE_PREFIX$DEV" #name of the network namespace
    SONIC_DB_CLI="sonic-db-cli -n $NET_NS"
else
    NET_NS=""
    SONIC_DB_CLI="sonic-db-cli"
fi

case "$1" in
    start|wait|stop)
        $1
        ;;
    *)
        echo "Usage: $0 {start|wait|stop}"
        exit 1
        ;;
esac
