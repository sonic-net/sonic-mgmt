#!/bin/bash

set -e

function usage
{
  echo "testbed-cli. Interface to testbeds"
  echo "Usage:"
  echo "    $0 [options] (start-vms | stop-vms) <server-name> <vault-password-file>"
  echo "    $0 [options] (add-topo | remove-topo | renumber-topo | connect-topo) <topo-name> <vault-password-file>"
  echo "    $0 [options] refresh-dut <topo-name> <vault-password-file>"
  echo "    $0 [options] (connect-vms | disconnect-vms) <topo-name> <vault-password-file>"
  echo "    $0 [options] config-vm <topo-name> <vm-name> <vault-password-file>"
  echo "    $0 [options] (gen-mg | deploy-mg | test-mg) <topo-name> <inventory> <vault-password-file>"
  echo
  echo "Options:"
  echo "    -t <tbfile> : testbed CSV file name (default: 'testbed.csv')"
  echo "    -m <vmfile> : virtual machine file name (default: 'veos')"
  echo
  echo "Positional Arguments:"
  echo "    <server-name>         : Hostname of server on which to start VMs"
  echo "    <vault-password-file> : Path to file containing Ansible Vault password"
  echo "    <topo-name>           : Name of the target topology"
  echo "    <inventory>           : Name of the Ansible inventory containing the DUT"
  echo
  echo "To start VMs on a server: $0 start-vms 'server-name' ~/.password"
  echo "To restart a subset of VMs:"
  echo "        $0 start-vms server-name vault-password-file -e respin_vms=[vm_list]"
  echo "             vm_list is separated by comma and shouldn't have space in the list."
  echo "                 e.g., respin_vms=[VM0310,VM0330]"
  echo "To stop VMs on a server:  $0 stop-vms 'server-name' ~/.password"
  echo "To deploy a topology on a server: $0 add-topo 'topo-name' ~/.password"
  echo "To remove a topology on a server: $0 remove-topo 'topo-name' ~/.password"
  echo "To renumber a topology on a server: $0 renumber-topo 'topo-name' ~/.password"
  echo "To connect a topology: $0 connect-topo 'topo-name' ~/.password"
  echo "To refresh DUT in a topology: $0 refresh-dut 'topo-name' ~/.password"
  echo "To configure a VM on a server: $0 config-vm 'topo-name' 'vm-name' ~/.password"
  echo "To generate minigraph for DUT in a topology: $0 gen-mg 'topo-name' 'inventory' ~/.password"
  echo "To deploy minigraph to DUT in a topology: $0 deploy-mg 'topo-name' 'inventory' ~/.password"
  echo
  echo "You should define your topology in testbed CSV file"
  echo
  exit
}

function read_file
{
 echo reading

 # Filter testbed names in the first column in the testbed definition file
 line=$(cat $tbfile | grep "^$1,")

 if [ $? -ne 0 ]
 then
   echo "Couldn't find topology name '$1'"
   exit
 fi

 NL='
'
 case $line in
  *"$NL"*) echo "Find more than one topology names in $tbfile"
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
  server=$1
  passwd=$2
  shift
  shift
  echo "Starting VMs on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_start_VMs.yml --vault-password-file="${passwd}" -l "${server}" $@
}

function stop_vms
{
  server=$1
  passwd=$2
  shift
  shift
  echo "Stopping VMs on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_stop_VMs.yml --vault-password-file="${passwd}" -l "${server}" $@
}

function add_topo
{
  topology=$1
  passwd=$2
  shift
  shift
  echo "Deploying topology '${topology}'"

  read_file ${topology}

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_add_vm_topology.yml --vault-password-file="${passwd}" -l "$server" -e topo_name="$topo_name" -e dut_name="$dut" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename" $@

  ansible-playbook fanout_connect.yml -i $vmfile --limit "$server" --vault-password-file="${passwd}" -e "dut=$dut" $@

  echo Done
}

function remove_topo
{
  topology=$1
  passwd=$2
  shift
  shift
  echo "Removing topology '${topology}'"

  read_file ${topology}

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_remove_vm_topology.yml --vault-password-file="${passwd}" -l "$server" -e topo_name="$topo_name" -e dut_name="$dut" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename" $@

  echo Done
}

function renumber_topo
{
  topology=$1
  passwd=$2
  shift
  shift
  echo "Renumbering topology '${topology}'"

  read_file ${topology}

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_renumber_vm_topology.yml --vault-password-file="${passwd}" -l "$server" -e topo_name="$topo_name" -e dut_name="$dut" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename" $@

  ansible-playbook fanout_connect.yml -i $vmfile --limit "$server" --vault-password-file="${passwd}" -e "dut=$dut" $@

  echo Done
}

function refresh_dut
{
  topology=$1
  passwd=$2
  shift
  shift
  echo "Refresh $dut in  '${topology}'"

  read_file ${topology}

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_refresh_dut.yml --vault-password-file="${passwd}" -l "$server" -e topo_name="$topo_name" -e dut_name="$dut" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename" $@

  echo Done
}

function connect_vms
{
  echo "Connect VMs '$1'"

  read_file $1

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_connect_vms.yml --vault-password-file="$2" -l "$server" -e topo_name="$topo_name" -e dut_name="$dut" -e VM_base="$vm_base" -e topo="$topo" -e vm_set_name="$testbed_name"

  echo Done
}

function disconnect_vms
{
  echo "Disconnect VMs '$1'"

  read_file $1

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_disconnect_vms.yml --vault-password-file="$2" -l "$server" -e topo_name="$topo_name" -e dut_name="$dut" -e VM_base="$vm_base" -e topo="$topo" -e vm_set_name="$testbed_name"

  echo Done
}


function generate_minigraph
{
  echo "Generating minigraph '$1'"

  read_file $1

  ansible-playbook -i "$2" config_sonic_basedon_testbed.yml --vault-password-file="$3" -l "$dut" -e testbed_name="$1" -e testbed_file=$tbfile -v

  echo Done
}

function deploy_minigraph
{
  echo "Deploying minigraph '$1'"

  read_file $1

  ansible-playbook -i "$2" config_sonic_basedon_testbed.yml --vault-password-file="$3" -l "$dut" -e testbed_name="$1" -e testbed_file=$tbfile -e deploy=true -e save=true

  echo Done
}

function test_minigraph
{
  echo "Test minigraph generation '$1'"

  read_file $1

  ansible-playbook -i "$2" --diff --connection=local --check config_sonic_basedon_testbed.yml --vault-password-file="$3" -l "$dut" -e testbed_name="$1" -e testbed_file=$tbfile -e local_minigraph=true

  echo Done
}

function config_vm
{
  echo "Configure VM $2"

  read_file $1

  ansible-playbook -i $vmfile eos.yml --vault-password-file="$3" -l "$2" -e topo="$topo" -e VM_base="$vm_base"

  echo Done
}

function connect_topo
{
  echo "Connect to Fanout"

  read_file $1

  ansible-playbook fanout_connect.yml -i $vmfile --limit "$server" --vault-password-file="$2" -e "dut=$dut"
}

vmfile=veos
tbfile=testbed.csv

while getopts "t:m:" OPTION; do
    case $OPTION in
    t)
        tbfile=$OPTARG
        ;;
    m)
        vmfile=$OPTARG
        ;;
    *)
        usage
    esac
done

shift $((OPTIND-1))

if [ $# -lt 3 ]
then
  usage
fi

subcmd=$1
shift
case "${subcmd}" in
  start-vms)   start_vms $@
               ;;
  stop-vms)    stop_vms $@
               ;;
  add-topo)    add_topo $@
               ;;
  remove-topo) remove_topo $@
               ;;
  renumber-topo) renumber_topo $@
               ;;
  connect-topo) connect_topo $@
               ;;
  refresh-dut) refresh_dut $@
               ;;
  connect-vms) connect_vms $@
               ;;
  disconnect-vms) disconnect_vms $@
               ;;
  config-vm)   config_vm $@
               ;;
  gen-mg)      generate_minigraph $@
               ;;
  deploy-mg)   deploy_minigraph $@
               ;;
  connect-vms) connect_vms $@
               ;;
  disconnect-vms) disconnect_vms $@
               ;;
  config-vm)   config_vm $@
               ;;
  gen-mg)      generate_minigraph $@
               ;;
  deploy-mg)   deploy_minigraph $@
               ;;
  test-mg)     test_minigraph $@
               ;;
  *)           usage
               ;;
esac
