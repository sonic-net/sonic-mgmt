#!/bin/bash

#cat /usr/bin/saiserver.sh
# single instance containers are still supported (even though it might not look like it)
# if no instance number is passed to this script, $DEV will simply be unset, resulting in docker
# commands being sent to the base container name. E.g. `docker start database$DEV` simply starts
# the container `database` if no instance number is passed since `$DEV` is not defined

function updateSyslogConf()
{
    # On multiNPU platforms, change the syslog target ip to docker0 ip to allow logs from containers
    # running on the namespace to reach the rsyslog service running on the host
    # Also update the container name
    if [[ ($NUM_ASIC -gt 1) ]]; then
        TARGET_IP=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}')
        CONTAINER_NAME="$DOCKERNAME"
        TMP_FILE="/tmp/rsyslog.$CONTAINER_NAME.conf"
        sonic-cfggen -t /usr/share/sonic/templates/rsyslog-container.conf.j2 -a "{\"target_ip\": \"$TARGET_IP\", \"container_name\": \"$CONTAINER_NAME\" }"  > $TMP_FILE
        docker cp $TMP_FILE ${DOCKERNAME}:/etc/rsyslog.conf
        rm -rf $TMP_FILE
    fi
}
function ebtables_config()
{
    if [ "$DEV" ]; then
        # Install ebtables filter in namespaces on multi-asic.
        ip netns exec $NET_NS ebtables-restore < /etc/ebtables.filter.cfg
    else
        if [[ ! ($NUM_ASIC -gt 1) ]]; then
            # Install ebtables filter in host for single asic.
            ebtables-restore < /etc/ebtables.filter.cfg
        fi
    fi
}

function getMountPoint()
{
    echo $1 | python -c "import sys, json, os; mnts = [x for x in json.load(sys.stdin)[0]['Mounts'] if x['Destination'] == '/usr/share/sonic/hwsku']; print('' if len(mnts) == 0 else os.path.abspath(mnts[0]['Source']))" 2>/dev/null
}

function getBootType()
{
    # same code snippet in files/scripts/saiserver.sh
    case "$(cat /proc/cmdline)" in
    *SONIC_BOOT_TYPE=warm*)
        TYPE='warm'
        ;;
    *SONIC_BOOT_TYPE=fastfast*)
        TYPE='fastfast'
        ;;
    *SONIC_BOOT_TYPE=fast*|*fast-reboot*)
        TYPE='fast'
        ;;
    *)
        TYPE='cold'
    esac
    echo "${TYPE}"
}

function preStartAction()
{
    : # nothing
    updateSyslogConf
}

function postStartAction()
{
    : # nothing
}

start() {
    # Obtain boot type from kernel arguments
    BOOT_TYPE=`getBootType`

    # Obtain our platform as we will mount directories with these names in each docker
    PLATFORM=${PLATFORM:-`$SONIC_CFGGEN -H -v DEVICE_METADATA.localhost.platform`}


    # Parse the device specific asic conf file, if it exists
    ASIC_CONF=/usr/share/sonic/device/$PLATFORM/asic.conf
    if [ -f "$ASIC_CONF" ]; then
        source $ASIC_CONF
    fi
    # Obtain our HWSKU as we will mount directories with these names in each docker
    HWSKU=${HWSKU:-`$SONIC_CFGGEN -d -v 'DEVICE_METADATA["localhost"]["hwsku"]'`}
    MOUNTPATH="/usr/share/sonic/device/$PLATFORM/$HWSKU"
    if [ "$DEV" ]; then
        MOUNTPATH="$MOUNTPATH/$DEV"
    fi
    DOCKERCHECK=`docker inspect --type container ${DOCKERNAME} 2>/dev/null`
    if [ "$?" -eq "0" ]; then
        DOCKERMOUNT=`getMountPoint "$DOCKERCHECK"`
        if [ x"$DOCKERMOUNT" == x"$MOUNTPATH" ]; then
            preStartAction
            echo "Starting existing ${DOCKERNAME} container with HWSKU $HWSKU"
            /usr/local/bin/container start ${DOCKERNAME}
            postStartAction
            exit $?
        fi

        # docker created with a different HWSKU, remove and recreate
        echo "Removing obsolete ${DOCKERNAME} container with HWSKU $DOCKERMOUNT"
        docker rm -f ${DOCKERNAME}
    fi
    echo "Creating new ${DOCKERNAME} container with HWSKU $HWSKU"

    # In Multi ASIC platforms the global database config file database_global.json will exist.
    # Parse the file and get the include path for the database_config.json files used in
    # various namesapces. The database_config paths are relative to the DIR of SONIC_DB_GLOBAL_JSON.
    SONIC_DB_GLOBAL_JSON="/var/run/redis/sonic-db/database_global.json"
    if [ -f "$SONIC_DB_GLOBAL_JSON" ]; then
        # TODO Create a separate python script with the below logic and invoke it here.
        redis_dir_list=`/usr/bin/python -c "import sys; import os; import json; f=open(sys.argv[1]); \
                        global_db_dir = os.path.dirname(sys.argv[1]); data=json.load(f); \
                        print(\" \".join([os.path.normpath(global_db_dir+'/'+elem['include']).partition('sonic-db')[0]\
                        for elem in data['INCLUDES'] if 'namespace' in elem])); f.close()" $SONIC_DB_GLOBAL_JSON`
    fi

    if [ -z "$DEV" ]; then
        NET="host"

        # For Multi-ASIC platform we have to mount the redis paths for database instances running in different
        # namespaces, into the single instance dockers like snmp, pmon on linux host. These global dockers
        # will need to get/set tables from databases in different namespaces.
        # /var/run/redis0 ---> mounted as --> /var/run/redis0
        # /var/run/redis1 ---> mounted as --> /var/run/redis1 .. etc
        # The below logic extracts the base DIR's where database_config.json's for various namespaces exist.
        # redis_dir_list is a string of form "/var/run/redis0/ /var/run/redis1/ /var/run/redis2/"
        if [ -n "$redis_dir_list" ]; then
            for redis_dir in $redis_dir_list
            do
                REDIS_MNT=$REDIS_MNT" -v $redis_dir:$redis_dir:rw "
            done
        fi
    else
        # This part of code is applicable for Multi-ASIC platforms. Here we mount the namespace specific
        # redis directory into the docker running in that namespace. Below eg: is for namespace "asic1"
        # /var/run/redis1 ---> mounted as --> /var/run/redis1
        # redis_dir_list is a string of form "/var/run/redis0/ /var/run/redis1/ /var/run/redis2/"
        if [ -n "$redis_dir_list" ]; then
            id=`expr $DEV + 1`
            redis_dir=`echo $redis_dir_list | cut -d " " -f $id`
            REDIS_MNT=" -v $redis_dir:$redis_dir:rw "
        fi
        NET="container:database$DEV"
        DB_OPT=""
    fi
    # TODO: Mellanox will remove the --tmpfs exception after SDK socket path changed in new SDK version
    docker create --privileged -t -v /host/machine.conf:/etc/machine.conf -v /etc/sonic:/etc/sonic:ro -v /host/warmboot:/var/warmboot --tmpfs /run/criu \
        --net=$NET \
        -e RUNTIME_OWNER=local \
        --uts=host \
        --log-opt max-size=2M --log-opt max-file=5 \
        -v /var/log/mellanox:/var/log/mellanox:rw \
        -v mlnx_sdk_socket:/var/run/sx_sdk \
        -v mlnx_sdk_ready:/tmp \
        -v /dev/shm:/dev/shm:rw \
        -e SX_API_SOCKET_FILE=/var/run/sx_sdk/sx_api.sock \
        -v /var/run/redis$DEV:/var/run/redis:rw \
        -v /var/run/redis-chassis:/var/run/redis-chassis:ro \
        -v /usr/share/sonic/device/$PLATFORM/$HWSKU/$DEV:/usr/share/sonic/hwsku:ro \
        $REDIS_MNT \
        -v /usr/share/sonic/device/$PLATFORM:/usr/share/sonic/platform:ro \
        --tmpfs /var/tmp \
        --env "NAMESPACE_ID"="$DEV" \
        --env "NAMESPACE_PREFIX"="$NAMESPACE_PREFIX" \
        --env "NAMESPACE_COUNT"=$NUM_ASIC \
        --name=$DOCKERNAME \
        docker-saiserver-mlnx:latest \
        || {
            echo "Failed to docker run" >&1
            exit 4
    }

    preStartAction
    /usr/local/bin/container start ${DOCKERNAME}
    postStartAction
}

wait() {
    /usr/local/bin/container wait $DOCKERNAME
}

stop() {
    /usr/local/bin/container stop $DOCKERNAME
}

DOCKERNAME=saiserver
OP=$1
DEV=$2 # namespace/device number to operate on
NAMESPACE_PREFIX="asic"
DOCKERNAME=$DOCKERNAME$DEV
if [ "$DEV" ]; then
    NET_NS="$NAMESPACE_PREFIX$DEV" #name of the network namespace

    SONIC_CFGGEN="sonic-cfggen -n $NET_NS"
    SONIC_DB_CLI="sonic-db-cli -n $NET_NS"
 else
    NET_NS=""
    SONIC_CFGGEN="sonic-cfggen"
    SONIC_DB_CLI="sonic-db-cli"
fi

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
