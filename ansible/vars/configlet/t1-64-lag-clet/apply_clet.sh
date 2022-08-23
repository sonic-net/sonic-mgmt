#! /bin/bash

# Sleep to let all BGP sessions go up & running before adding a T0
sleep 1m
configlet -j /etc/sonic/clet-to_clear.json -d

sonic_release="$(sonic-cfggen -y /etc/sonic/sonic_version.yml -v release)"

sonic_qos_db_fv_reference_with_table=false

#Check for QOS DB format for Field Value refered with tables or not.
declare -a array=("201811" "201911" "202012" "202106")

for i in "${array[@]}"
do
    if [ "$i" == "$sonic_release" ] ; then
        echo "Found"
        sonic_qos_db_fv_reference_with_table=true
    fi
done

if [ "$sonic_qos_db_fv_reference_with_table" == "true" ]; then
    configlet -j /etc/sonic/clet-add.json -u
else
    configlet -j /etc/sonic/clet-add-qos-new-dbfmt.json -u
fi
