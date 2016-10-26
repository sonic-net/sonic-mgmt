#!/bin/bash

let DEBUG=0

# ---------------------------------
# Read from configfile
function read_configfile_aliases
{
    readonly local port_config=`cat $CONFIGFILE`

    let local line_counter=2
    local port_config_entry
    local ether_number
    local port_alias
    while [ $line_counter -le $LINESNUMBER ]; do
        port_config_entry=`echo "${port_config}" | sed -n "$line_counter"p | sed -n "s/Ethernet//p" | sed -n "s/ [[:digit:]].* //p"`
        ether_number=`echo $port_config_entry | cut -d" " -f1`
        port_alias=`echo $port_config_entry | sed -n "s/[[:digit:]]* //p"`

        # Write into table
        port_config_array[$ether_number]="$port_alias"
        let line_counter="line_counter + 1"

        print_debug "-------------------------------"
        print_debug "PORT_ENTRY = $port_config_entry\n"
        print_debug "ETHER_NUMBER = $ether_number\n"
        print_debug "PORT_ALIAS = $port_alias\n"
    done
}

# ---------------------------------
# Read alises from Redis-db and compare to ones from configfile
function read_redis_aliases_and_compare
{
    let local ether_counter=0
    local port_data_entry
    local port_data_alias

    while [ $ether_counter -le $ETHERMAX ]; do
        port_data_entry=`docker exec -ti database redis-cli hgetall "PORT_TABLE:Ethernet"$ether_counter""`

        # Grep next line after "alias"; remove numbering, quotes and
        # everything else except of alias name.
        port_data_alias=`echo "${port_data_entry}" | grep -A1 'alias' | grep -v 'alias' | sed -n 's/.* \"//p' | sed -n 's/\".*//p'`

        # Compare db-alias to alias from CONFIGFILE
        print_debug "---------------------------------------------"
        print_debug "comparing: configfile_alias='"${port_config_array[$ether_counter]}"'\n
                Redis_alias="$port_data_alias""

        # Check if aliases are same
        if [[ "$port_data_alias" != "${port_config_array[$ether_counter]}" ]]; then
            echo -e "\nERROR: port has got different aliases in port_config.ini and database."
            echo -e "Port name:                 Ethernet$ether_counter"
            echo -e "Alias in port_config.ini:  ${port_config_array[$ether_counter]}"
            echo -e "Alias in Redis DB:         $port_data_alias\n"
            exit 1
        fi
        let ether_counter="ether_counter + 4"
    done
}

function print_debug
{
    if [[ $DEBUG -ne "0" ]]; then
        echo -e "$1"
    fi
}

# ------------- START -------------

readonly CONFIGFILE="/etc/ssw/*/port_config.ini"
readonly LINESNUMBER=`wc -l < $CONFIGFILE`
if [ $LINESNUMBER -lt 2 ]; then
    echo -e "ERROR: wrong port_config table. Please check port_config.ini\n"
    exit 1
fi
let readonly ETHERMAX="($LINESNUMBER - 2) * 4"

# Array where each port alias will be stored
declare -a port_config_array

# Read aliases from configfile
read_configfile_aliases

# Read aliases from Redis-db
read_redis_aliases_and_compare

echo "---------------------------------------------" 
echo "Aliases tested successfully"
echo "---------------------------------------------" 

exit 0
