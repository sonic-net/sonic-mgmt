#!/bin/bash

#Do not support the multi instance in current saiserver edition
start() {    
    
    NET_NS=""
    SONIC_CFGGEN="sonic-cfggen"
    SONIC_DB_CLI="sonic-db-cli"

    # Obtain our platform as we will mount directories with these names in each docker
    PLATFORM=${PLATFORM:-`$SONIC_CFGGEN -H -v DEVICE_METADATA.localhost.platform`}

    # Obtain our HWSKU as we will mount directories with these names in each docker
    HWSKU=${HWSKU:-`$SONIC_CFGGEN -d -v 'DEVICE_METADATA["localhost"]["hwsku"]'`}

    docker create --privileged --net=host \
        -v /usr/share/sonic/device/$PLATFORM/$HWSKU:/usr/share/sonic/hwsku:ro \
        --name=$DOCKERNAME docker-saiserver-brcm:latest || {
            echo "Failed to docker run" >&1
            exit 4
    }

    /usr/local/bin/container start ${DOCKERNAME}
}

wait() {
    /usr/local/bin/container wait $DOCKERNAME
}

stop() {
    /usr/local/bin/container stop $DOCKERNAME
}

DOCKERNAME=saiserver

# read SONiC immutable variables
[ -f /etc/sonic/sonic-environment ] && . /etc/sonic/sonic-environment

case "$1" in
    start|wait|stop)
        $1
        ;;
    *)
        echo "Usage: $0 {start namespace(optional)|wait namespace(optional)|stop namespace(optional)}"
        exit 1
        ;;
esac
