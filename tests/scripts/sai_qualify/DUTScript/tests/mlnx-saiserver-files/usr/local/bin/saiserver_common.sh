#!/bin/bash

#/usr/local/bin/saiserver_common.sh
# common functions used by "saiserver" scipts (saiserver.sh, gbsaiserver.sh, etc..)
# scripts using this must provide implementations of the following functions:
#
# startplatform
# waitplatform
# stopplatform1 and stopplatform2
#
# For examples of these, see gbsaiserver.sh and saiserver.sh.
#

. /usr/local/bin/asic_status.sh

function debug()
{
    /usr/bin/logger $1
    /bin/echo `date` "- $1" >> ${DEBUGLOG}
}

function lock_service_state_change()
{
    debug "Locking ${LOCKFILE} from ${SERVICE}$DEV service"

    exec {LOCKFD}>${LOCKFILE}
    /usr/bin/flock -x ${LOCKFD}
    trap "/usr/bin/flock -u ${LOCKFD}" 0 2 3 15

    debug "Locked ${LOCKFILE} (${LOCKFD}) from ${SERVICE}$DEV service"
}

function unlock_service_state_change()
{
    debug "Unlocking ${LOCKFILE} (${LOCKFD}) from ${SERVICE}$DEV service"
    /usr/bin/flock -u ${LOCKFD}
}

function check_warm_boot()
{
    SYSTEM_WARM_START=`$SONIC_DB_CLI STATE_DB hget "WARM_RESTART_ENABLE_TABLE|system" enable`
    SERVICE_WARM_START=`$SONIC_DB_CLI STATE_DB hget "WARM_RESTART_ENABLE_TABLE|${SERVICE}" enable`
    # SYSTEM_WARM_START could be empty, always make WARM_BOOT meaningful.
    if [[ x"$SYSTEM_WARM_START" == x"true" ]] || [[ x"$SERVICE_WARM_START" == x"true" ]]; then
        WARM_BOOT="true"
    else
        WARM_BOOT="false"
    fi
}

function wait_for_database_service()
{
    # Wait for redis server start before database clean
    until [[ $($SONIC_DB_CLI PING | grep -c PONG) -gt 0 ]]; do
      sleep 1;
    done

    # Wait for configDB initialization
    until [[ $($SONIC_DB_CLI CONFIG_DB GET "CONFIG_DB_INITIALIZED") ]];
        do sleep 1;
    done
}

function getBootType()
{
    # same code snippet in files/build_templates/docker_image_ctl.j2
    case "$(cat /proc/cmdline)" in
    *SONIC_BOOT_TYPE=warm*)
        TYPE='warm'
        ;;
    *SONIC_BOOT_TYPE=fastfast*)
        TYPE='fastfast'
        ;;
    *SONIC_BOOT_TYPE=fast*|*fast-reboot*)
        # check that the key exists
        if [[ $($SONIC_DB_CLI STATE_DB GET "FAST_REBOOT|system") == "1" ]]; then
            TYPE='fast'
        else
            TYPE='cold'
        fi
        ;;
    *)
        TYPE='cold'
    esac
    echo "${TYPE}"
}

start() {
    debug "Starting ${SERVICE}$DEV service..."

   #lock_service_state_change

    mkdir -p /host/warmboot

    wait_for_database_service
    check_warm_boot

    debug "Warm boot flag: ${SERVICE}$DEV ${WARM_BOOT}."

    if [[ x"$WARM_BOOT" == x"true" ]]; then
        # Leave a mark for saiserver scripts running inside docker.
        touch /host/warmboot/warm-starting
    else
        rm -f /host/warmboot/warm-starting
    fi

    startplatform

    # On supervisor card, skip starting asic related services here. In wait(),
    # wait until the asic is detected by pmon and published via database.
    if ! is_chassis_supervisor; then
        # start service docker
        /usr/bin/${SERVICE}.sh start $DEV
        debug "Started ${SERVICE}$DEV service..."
    fi

   #unlock_service_state_change
}

wait() {
    # On supervisor card, wait for asic to be online before starting the docker.
    if is_chassis_supervisor; then
        check_asic_status
        ASIC_STATUS=$?

        # start service docker
        if [[ $ASIC_STATUS == 0 ]]; then
            /usr/bin/${SERVICE}.sh start $DEV
            debug "Started ${SERVICE}$DEV service..."
        fi
    fi

    waitplatform

    /usr/bin/${SERVICE}.sh wait $DEV
}

stop() {
    debug "Stopping ${SERVICE}$DEV service..."

   #lock_service_state_change
    check_warm_boot
    debug "Warm boot flag: ${SERVICE}$DEV ${WARM_BOOT}."

    if [[ x"$WARM_BOOT" == x"true" ]]; then
        TYPE=warm
    else
        TYPE=cold
    fi

    stopplatform1

    /usr/bin/${SERVICE}.sh stop $DEV
    debug "Stopped ${SERVICE}$DEV service..."

    stopplatform2

   #unlock_service_state_change
}
