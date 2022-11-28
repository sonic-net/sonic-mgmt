#!/bin/bash

#Stop or start all the containers in the DUT

#containers can be started, they must be in order
containers=("swss" "syncd" "radv" "lldp" "dhcp_relay" "teamd" "bgp" "pmon" "telemetry" "acms" "snmp")
op_containers(){
    for cnt in ${containers[*]}; do
        if [[ x"$skip" =~ x"$cnt" ]]; then
            echo "Skip [$op] for container [$cnt]."
        else
           echo "[$op] docker: [$cnt]."
           docker $op $cnt
        fi
    done
}

check_ops() {
    # Print helpFunction in case parameters are empty
    if [ -z "$op" ]; then
        echo "Some or all of the parameters are empty";
        helpFunction
    fi

    if [[ x"$op" != x"start" && x"$op" != x"stop" ]]; then
        echo ""
        echo "Error: Operation perameters is not right, it only can be [stop|start].";
        helpFunction
    fi
}


helpFunction()
{
   echo ""
   echo "Use to operation on containers list:"
   echo  ${containers[*]}
   echo -e "\t-o [start|stop|restart] : start, restart, or stop"
   echo -e "\t-s : the container names in the containers list. It can be like [swss;syncd]"

   exit 1 # Exit script after printing help
}

while getopts ":o:s:" args; do
    case $args in
        o)
            op=${OPTARG}
            ;;
        s)
            skip=${OPTARG}
            ;;
        *)
            helpFunction
        ;;
    esac
done

check_ops
op_containers
