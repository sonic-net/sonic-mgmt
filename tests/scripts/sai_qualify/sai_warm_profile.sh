#!/bin/bash

#Change the sai.profile for warm reboot. Including change the file to warmboot mode and recover it.
profile='/etc/sai.d/sai.profile'

back_profile(){
    echo "backup profile: $profile"
    if [[ -f "$profile.bak" ]]; then
        echo "Skip backup profile: $profile, $profile.bak alredy exist."
        exit 1 # Exit script
    else
        cp $profile $profile.bak
    fi
}

restore_profile(){
    echo "restore profile: $profile"
    if [[ ! -f "$profile.bak" ]]; then
        echo "Skip restore profile: $profile, $profile.bak not exist."
        exit 1 # Exit script
    else
        cp $profile.bak $profile
    fi
}

config_warmboot_init(){
    echo "change $profile for warmboot init"
    echo "SAI_WARM_BOOT_WRITE_FILE=/var/warmboot/sai-warmboot.bin" >> $profile
    echo "SAI_WARM_BOOT_READ_FILE=/var/warmboot/sai-warmboot.bin" >> $profile
    echo "SAI_BOOT_TYPE=1" >> $profile
}

config_warmboot_start(){
    echo "change $profile for warmboot start"
    echo "SAI_BOOT_TYPE=1" >> $profile
}

ops(){
    if [[ x"$op" == x"init" ]]; then
        echo "setup warmboot mode"
        back_profile
        config_warmboot_init
    elif [[ x"$op" == x"start" ]]; then
        config_warmboot_start
    else
        restore_profile
    fi

}


check_ops() {
    # Print helpFunction in case parameters are empty
    if [ -z "$op" ]; then
        echo "Some or all of the parameters are empty";
        helpFunction
    fi

    if [[ x"$op" != x"init" && x"$op" != x"start" && x"$op" != x"restore" ]]; then
        echo ""
        echo "Error: Operation perameters is not right, it only can be [setup|restore].";
        helpFunction
    fi
}


helpFunction()
{
   echo ""
   echo "Use to change the sai.profile in saiserver docker:"
   echo -e "\t-o [init|start|restore] : setup to the warmboot mode, or recover to normal"
   
   exit 1 # Exit script after printing help
}

while getopts ":o:" args; do
    case $args in
        o|operation)
            op=${OPTARG} 
            ;;
        *)
            helpFunction
        ;;
    esac
done

check_ops
ops
