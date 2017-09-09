#!/bin/bash

set -e

function usage
{
  echo "testbed-cli. Interface to testbeds"
  echo "Usage : $0 { start-vms | stop-vms    } server-name vault-password-file"
  echo "Usage : $0 { add-topo  | remove-topo | renumber-topo } topo-name vault-password-file"
  echo "Usage : $0 { config-vm } topo-name vm-name vault-password-file"
  echo "Usage : $0 { gen-mg | deploy-mg } topo-name vault-password-file"
  echo
  echo "To start VMs on a server: $0 start-vms 'server-name' ~/.password"
  echo "To stop VMs on a server:  $0 stop-vms 'server-name' ~/.password"
  echo "To deploy a topology on a server: $0 add-topo 'topo-name' ~/.password"
  echo "To remove a topology on a server: $0 remove-topo 'topo-name' ~/.password"
  echo "To renumber a topology on a server: $0 renumber-topo 'topo-name' ~/.password" , where topo-name is target topology
  echo "To configure a VM on a server: $0 config-vm 'topo-name' 'vm-name' ~/.password"
  echo "To generate minigraph for DUT in a topology: $0 gen-mg 'topo-name' ~/.password"
  echo "To deploy minigraph to DUT in a topology: $0 deploy-mg 'topo-name' ~/.password"
  echo
  echo "You should define your topology in testbed.csv file"
  echo
  exit
}

function read_file
{
 echo reading

 # Filter testbed names in the first column in the testbed definition file
 line=$(cat testbed.csv | grep "^$1,")

 if [ $? -ne 0 ]
 then
   echo "Couldn't find topology name '$1'"
   exit
 fi

 NL='
'
 case $line in
  *"$NL"*) echo "Find more than one topology names in testbed.csv"
           exit
           ;;
        *) echo Found topology $1
           ;;
 esac

 IFS=, read -r -a line_arr <<< $line

 testbed_name=${line_arr[1]}
 topo=${line_arr[2]}
 ptf_imagename=${line_arr[3]}
 ptf_ip=${line_arr[4]}
 server=${line_arr[5]}
 vm_base=${line_arr[6]}
 dut=${line_arr[7]}
}

function start_vms
{
  echo "Starting VMs on server '$1'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i veos testbed_start_VMs.yml --vault-password-file="$2" -l "$1"
}

function stop_vms
{
  echo "Stopping VMs on server '$1'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i veos testbed_stop_VMs.yml --vault-password-file="$2" -l "$1"
}

function add_topo
{
  echo "Deploying topology '$1'"

  read_file $1

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i veos testbed_add_vm_topology.yml --vault-password-file="$2" -l "$server" -e topo_name="$topo_name" -e dut_name="$dut" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename"

  ansible-playbook fanout_connect.yml -i veos --limit "$server" --vault-password-file="$2" -e "dut=$dut"

  echo Done
}

function remove_topo
{
  echo "Removing topology '$1'"

  read_file $1

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i veos testbed_remove_vm_topology.yml --vault-password-file="$2" -l "$server" -e topo_name="$topo_name" -e dut_name="$dut" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename"

  echo Done
}

function renumber_topo
{
  echo "Renumbering topology '$1'"

  read_file $1

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i veos testbed_renumber_vm_topology.yml --vault-password-file="$2" -l "$server" -e topo_name="$topo_name" -e dut_name="$dut" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename"

  ansible-playbook fanout_connect.yml -i veos --limit "$server" --vault-password-file="$2" -e "dut=$dut"

  echo Done
}

function generate_minigraph
{
  echo "Generating minigraph '$1'"

  read_file $1

  ansible-playbook -i lab config_sonic_basedon_testbed.yml --vault-password-file="$2" -l "$dut" -e vm_base="$vm_base" -e topo="$topo"

  echo Done
}

function deploy_minigraph
{
  echo "Deploying minigraph '$1'"

  read_file $1

  ansible-playbook -i lab config_sonic_basedon_testbed.yml --vault-password-file="$2" -l "$dut" -e vm_base="$vm_base" -e topo="$topo" -e deploy=true

  echo Done
}

function config_vm
{
  echo "Configure VM $2"

  read_file $1

  ansible-playbook -i veos eos.yml --vault-password-file="$3" -l "$2" -e topo="$topo" -e VM_base="$vm_base"

  echo Done
}

if [ $# -lt 3 ]
then
 usage
fi

case "$1" in
  start-vms)   start_vms $2 $3
               ;;
  stop-vms)    stop_vms $2 $3
               ;;
  add-topo)    add_topo $2 $3
               ;;
  remove-topo) remove_topo $2 $3
               ;;
  renumber-topo) renumber_topo $2 $3
               ;;
  config-vm)   config_vm $2 $3 $4
               ;;
  gen-mg)      generate_minigraph $2 $3
               ;;
  deploy-mg)   deploy_minigraph $2 $3
               ;;
  *)           usage
               ;;
esac
