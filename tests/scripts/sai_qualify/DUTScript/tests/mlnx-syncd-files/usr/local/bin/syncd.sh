#!/bin/bash

#cat /usr/local/bin/syncd.sh
. /usr/local/bin/syncd_common.sh

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
                /bin/systemctl stop pmon
                debug "pmon is active while syncd starting, stop it first"
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
        /bin/systemctl start pmon
        debug "Started pmon service"
    fi
}

function stopplatform1() {

    if [[ x$sonic_asic_platform == x"mellanox" ]] && [[ x$TYPE == x"cold" ]]; then
        debug "Stopping pmon service ahead of syncd..."
        /bin/systemctl stop pmon
        debug "Stopped pmon service"
    fi

    if [[ x$sonic_asic_platform != x"mellanox" ]] || [[ x$TYPE != x"cold" ]]; then
        debug "${TYPE} shutdown syncd process ..."
        /usr/bin/docker exec -i syncd$DEV /usr/bin/syncd_request_shutdown --${TYPE}

        # wait until syncd quits gracefully or force syncd to exit after
        # waiting for 20 seconds
        start_in_secs=${SECONDS}
        end_in_secs=${SECONDS}
        timer_threshold=20
        while docker top syncd$DEV | grep -q /usr/bin/syncd \
                && [[ $((end_in_secs - start_in_secs)) -le $timer_threshold ]]; do
            sleep 0.1
            end_in_secs=${SECONDS}
        done

        if [[ $((end_in_secs - start_in_secs)) -gt $timer_threshold ]]; then
            debug "syncd process in container syncd$DEV did not exit gracefully"
        fi

        /usr/bin/docker exec -i syncd$DEV /bin/sync
        debug "Finished ${TYPE} shutdown syncd process ..."
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

SERVICE="syncd"
PEER="swss"
DEBUGLOG="/tmp/swss-syncd-debug$DEV.log"
LOCKFILE="/tmp/swss-syncd-lock$DEV"
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
