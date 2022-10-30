#!/bin/bash

#Initalize the syncd-rpc debug environment automatically.
#Including the start the syncd-rpc environment, only restart syncd-rpc for a re-attach to the sai shell, and restore the environment.

syncd_shell=/usr/bin/syncd.sh
syncd_entry_point='--entrypoint \"/bin/bash\" \\'
syncd_target_str="--tmpfs \/var\/tmp"
syncd_wait_in_sec=30

DIR=$(dirname $(readlink -f "$0")) # absolute path
. $DIR/Utils.sh
get_asic
get_os_version

back_up_file() {
    if [ -f "$syncd_shell.bak" ]; then
        echo "$syncd_shell.bak already exists."
    else
        cp $syncd_shell "$syncd_shell.bak"
    fi
}

restore_file() {
    if [ ! -f "$syncd_shell.bak" ]; then
        echo "$syncd_shell.bak not exists. Cannot restore!"
        exit 1
    fi
    cp "$syncd_shell.bak" $syncd_shell
    rm "$syncd_shell.bak"
}

change_syncd_script() {
    sed -i "/$syncd_target_str/a$syncd_entry_point" $syncd_shell
}

prepare_syncd_debug_docker() {
    echo "Preparing syncd rpc debugger container."
    ./pull_saiserver_syncd_rpc_dockers.sh
    ./start_syncd_rpc.sh
    docker cp ./syncd_rpc_shell/init_env.sh syncd:/
    docker commit syncd docker-syncd-${ASIC}-rpc-debug
    docker tag docker-syncd-${ASIC}-rpc-debug docker-syncd-${ASIC}
    docker kill syncd
    docker rm syncd
    $syncd_shell start
}

start_syncd_debugger_docker() {
    systemctl reset-failed
    echo "Restart swss service."
    systemctl restart swss
    n=0
    until [ "$n" -ge $syncd_wait_in_sec ]
    do
        if check_if_syncd_running; then
            syncd_started="true"
            break  # substitute your command here
        fi
        n=$((n+1))
        sleep 1
    done

    if [ x"$syncd_started" != x"true" ]; then
        echo "Syncd docker does not start in time."
        exit 1
    fi
    echo "Syncd debugger container start, stop listeners."
    ./all_listener.sh -o stop
    echo "Setup syncd-rpc env finished."
    echo "Starting syncd debug shell."
    docker exec syncd chmod +x /init_env.sh
    docker exec syncd /init_env.sh
    docker exec -it syncd /usr/bin/syncd --diag -u -s -p /etc/sai.d/sai.profile -r -m /usr/share/sonic/hwsku/port_config.ini
}

check_if_syncd_running() {
    echo "checking syncd debugger container."
    if [ x"$(docker ps -q -f name=syncd)" ]; then
        if [ x"$(docker inspect -f {{.State.Running}} syncd)" == x"true" ]; then
            echo "Syncd start."
            return 0
        else
            echo "Syncd docker state:$(docker inspect -f {{.State.Running}} syncd)"
        fi
    fi
    echo "Syncd does not start."
    return 1
}

helpFunction()
{
   echo ""
   echo "Setup syncd-rpc debugger environment:"
   echo -e "\t-o [start|restore|restart] : start or restore or restart"

   exit 1 # Exit script after printing help
}

check_ops() {
    # Print helpFunction in case parameters are empty
    if [ -z "$op" ]; then
        echo "Some or all of the parameters are empty";
        helpFunction
    fi

    if [[ x"$op" != x"start" && x"$op" != x"restore" && x"$op" != x"restart" ]]; then
        echo ""
        echo "Error: Operation perameters is not right, it only can be [stop|restore|restart].";
        helpFunction
    fi
}

main_fun() {
    if [ x"$op" == x"start" ]; then
        back_up_file
        change_syncd_script
        prepare_syncd_debug_docker
        start_syncd_debugger_docker
    fi

    if [ x"$op" == x"restart" ]; then
        start_syncd_debugger_docker
    fi

    if [ x"$op" == x"restore" ]; then
        restore_file
        ./restore_syncd.rpc.sh
        systemctl reset-failed
        echo "Restart swss service."
        systemctl restart swss
        ./all_listener.sh -o start
    fi
}

while getopts ":o:" args; do
    case $args in
        o)
            op=${OPTARG}
            ;;
        *)
            helpFunction
        ;;
    esac
done

check_ops
main_fun
