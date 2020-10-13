#!/bin/bash

set -e

function usage
{
  echo "testbed-cli. Interface to testbeds"
  echo "Usage:"
  echo "    $0 [options] (start-vms | stop-vms) <server-name> <vault-password-file>"
  echo "    $0 [options] (start-topo-vms | stop-topo-vms) <topo-name> <vault-password-file>"
  echo "    $0 [options] (add-topo | remove-topo | renumber-topo | connect-topo) <topo-name> <vault-password-file>"
  echo "    $0 [options] refresh-dut <topo-name> <vault-password-file>"
  echo "    $0 [options] (connect-vms | disconnect-vms) <topo-name> <vault-password-file>"
  echo "    $0 [options] config-vm <topo-name> <vm-name> <vault-password-file>"
  echo "    $0 [options] (gen-mg | deploy-mg | test-mg) <topo-name> <inventory> <vault-password-file>"
  echo "    $0 [options] (create-master | destroy-master) <k8s-server-name> <vault-password-file>" 
  echo 
  echo "Options:"
  echo "    -t <tbfile>     : testbed CSV file name (default: 'testbed.csv')"
  echo "    -m <vmfile>     : virtual machine file name (default: 'veos')"
  echo "    -k <vmtype>     : vm type (veos|ceos) (default: 'veos')"
  echo "    -n <vm_num>     : vm num (default: 0)"
  echo "    -s <msetnumber> : master set identifier on specified <k8s-server-name> (default: 1)"
  echo
  echo "Positional Arguments:"
  echo "    <server-name>         : Hostname of server on which to start VMs"
  echo "    <vault-password-file> : Path to file containing Ansible Vault password"
  echo "    <topo-name>           : Name of the target topology"
  echo "    <inventory>           : Name of the Ansible inventory containing the DUT"
  echo "    <k8s-server-name>     : Server identifier in form k8s_server_{id}, corresponds to k8s-ubuntu inventory group name"
  echo
  echo "To start all VMs on a server: $0 start-vms 'server-name' ~/.password"
  echo "To restart a subset of VMs:"
  echo "        $0 start-vms server-name vault-password-file -e respin_vms=[vm_list]"
  echo "             vm_list is separated by comma and shouldn't have space in the list."
  echo "                 e.g., respin_vms=[VM0310,VM0330]"
  echo "To pause some time after triggered starting of a batch of VMs:"
  echo "        $0 start-vms server-name vault-password-file -e batch_size=2 -e interval=60"
  echo "To enable autostart of VMs:"
  echo "        $0 start-vms server-name vault-password-file -e autostart=yes"
  echo "To start VMs for specified topology on server: $0 start-topo-vms 'topo-name' ~/.password"
  echo "To stop all VMs on a server:  $0 stop-vms 'server-name' ~/.password"
  echo "To stop VMs for specified topology on server: $0 stop-topo-vms 'topo-name' ~/.password"
  echo "To deploy a topology on a server: $0 add-topo 'topo-name' ~/.password"
  echo "    Optional argument for add-topo:"
  echo "        -e ptf_imagetag=<tag>    # Use PTF image with specified tag for creating PTF container"
  echo "To remove a topology on a server: $0 remove-topo 'topo-name' ~/.password"
  echo "To renumber a topology on a server: $0 renumber-topo 'topo-name' ~/.password"
  echo "To connect a topology: $0 connect-topo 'topo-name' ~/.password"
  echo "To refresh DUT in a topology: $0 refresh-dut 'topo-name' ~/.password"
  echo "To configure a VM on a server: $0 config-vm 'topo-name' 'vm-name' ~/.password"
  echo "To generate minigraph for DUT in a topology: $0 gen-mg 'topo-name' 'inventory' ~/.password"
  echo "To deploy minigraph to DUT in a topology: $0 deploy-mg 'topo-name' 'inventory' ~/.password"
  echo "    gen-mg, deploy-mg, test-mg supports enabling/disabling data ACL with parameter"
  echo "        -e enable_data_plane_acl=true"
  echo "        -e enable_data_plane_acl=false"
  echo "        by default, data acl is enabled"
  echo "To create Kubernetes master on a server: $0 -m k8s-ubuntu create-master 'k8s-server-name'  ~/.password"
  echo "To destroy Kubernetes master on a server: $0 -m k8s-ubuntu destroy-master 'k8s-server-name' ~/.password"
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
  ptf=${line_arr[4]}
  ptf_ip=${line_arr[5]}
  ptf_ipv6=${line_arr[6]}
  server=${line_arr[7]}
  vm_base=${line_arr[8]}
  dut=${line_arr[9]//;/,}
  duts=${dut//[\[\] ]/}
}

function start_vms
{
  server=$1
  passwd=$2
  shift
  shift
  echo "Starting VMs on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile -e VM_num="$vm_num" testbed_start_VMs.yml \
      --vault-password-file="${passwd}" -l "${server}" $@
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

function start_topo_vms
{
  topology=$1
  passwd=$2
  shift
  shift
  read_file ${topology}

  echo "Starting VMs for topology '${topology}' on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_start_VMs.yml --vault-password-file="${passwd}" -l "${server}" -e VM_base="$vm_base" -e topo="$topo" $@
}

function stop_topo_vms
{
  topology=$1
  passwd=$2
  shift
  shift
  read_file ${topology}

  echo "Stopping VMs for topology '${topology}' on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_stop_VMs.yml --vault-password-file="${passwd}" -l "${server}" -e VM_base="$vm_base" -e topo="$topo" $@
}

function add_topo
{
  topology=$1
  passwd=$2
  shift
  shift
  echo "Deploying topology '${topology}'"

  read_file ${topology}

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_add_vm_topology.yml --vault-password-file="${passwd}" -l "$server" -e topo_name="$topo_name" -e dut_name="$duts" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename" -e vm_type="$vm_type" -e ptf_ipv6="$ptf_ipv6" $@

  ansible-playbook fanout_connect.yml -i $vmfile --limit "$server" --vault-password-file="${passwd}" -e "dut=$duts" $@

  # Delete the obsoleted arp entry for the PTF IP
  ip neighbor flush $ptf_ip

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

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_remove_vm_topology.yml --vault-password-file="${passwd}" -l "$server" -e topo_name="$topo_name" -e dut_name="$duts" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename" -e vm_type="$vm_type" -e ptf_ipv6="$ptf_ipv6" $@

  echo Done
}

function connect_topo
{
  topology=$1
  passwd=$2
  shift
  shift

  echo "Connect to Topology '${topology}'"

  read_file ${topology}

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_connect_topo.yml \
                     --vault-password-file="${passwd}" --limit "$server" \
                     -e topo_name="$topo_name" -e dut_name="$duts" \
                     -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" \
                     -e topo="$topo" -e vm_set_name="$testbed_name" \
                     -e ptf_imagename="$ptf_imagename" -e vm_type="$vm_type" -e ptf_ipv6="$ptf_ipv6" $@

  ansible-playbook fanout_connect.yml -i $vmfile --limit "$server" --vault-password-file="${passwd}" -e "dut=$duts" $@

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

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_renumber_vm_topology.yml --vault-password-file="${passwd}" -l "$server" -e topo_name="$topo_name" -e dut_name="$duts" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename" -e ptf_ipv6="$ptf_ipv6"$@

  ansible-playbook fanout_connect.yml -i $vmfile --limit "$server" --vault-password-file="${passwd}" -e "dut=$duts" $@

  echo Done
}

function refresh_dut
{
  topology=$1
  passwd=$2
  shift
  shift
  echo "Refresh $duts in  '${topology}'"

  read_file ${topology}

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_refresh_dut.yml --vault-password-file="${passwd}" -l "$server" -e topo_name="$topo_name" -e dut_name="$duts" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$testbed_name" -e ptf_imagename="$ptf_imagename" -e ptf_ipv6="$ptf_ipv6" $@

  echo Done
}

function connect_vms
{
  echo "Connect VMs '$1'"

  read_file $1

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_connect_vms.yml --vault-password-file="$2" -l "$server" -e topo_name="$topo_name" -e dut_name="$duts" -e VM_base="$vm_base" -e topo="$topo" -e vm_set_name="$testbed_name"

  echo Done
}

function disconnect_vms
{
  echo "Disconnect VMs '$1'"

  read_file $1

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_disconnect_vms.yml --vault-password-file="$2" -l "$server" -e topo_name="$topo_name" -e dut_name="$duts" -e VM_base="$vm_base" -e topo="$topo" -e vm_set_name="$testbed_name"

  echo Done
}

function generate_minigraph
{
  topology=$1
  inventory=$2
  passfile=$3
  shift
  shift
  shift

  echo "Generating minigraph '$topology'"

  read_file $topology

  ansible-playbook -i "$inventory" config_sonic_basedon_testbed.yml --vault-password-file="$passfile" -l "$duts" -e testbed_name="$topology" -e testbed_file=$tbfile -e vm_file=$vmfile -e local_minigraph=true $@

  echo Done
}

function deploy_minigraph
{
  topology=$1
  inventory=$2
  passfile=$3
  shift
  shift
  shift

  echo "Deploying minigraph '$topology'"

  read_file $topology

  ansible-playbook -i "$inventory" config_sonic_basedon_testbed.yml --vault-password-file="$passfile" -l "$duts" -e testbed_name="$topology" -e testbed_file=$tbfile -e vm_file=$vmfile -e deploy=true -e save=true $@

  echo Done
}

function test_minigraph
{
  topology=$1
  inventory=$2
  passfile=$3
  shift
  shift
  shift

  echo "Test minigraph generation '$topology'"

  read_file $topology

  ansible-playbook -i "$inventory" --diff --connection=local --check config_sonic_basedon_testbed.yml --vault-password-file="$passfile" -l "$duts" -e testbed_name="$topology" -e testbed_file=$tbfile -e vm_file=$vmfile -e local_minigraph=true $@

  echo Done
}

function config_vm
{
  echo "Configure VM $2"

  read_file $1

  ansible-playbook -i $vmfile eos.yml --vault-password-file="$3" -l "$2" -e topo="$topo" -e VM_base="$vm_base"

  echo Done
}

function start_k8s_vms
{
  server=$1
  servernumber="${server#*"k8s_server_"}"
  passwd=$2
  shift
  shift

  echo "Starting Kubernetes VMs on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_start_k8s_VMs.yml --vault-password-file="${passwd}" -e k8s="true" -l "${server}" $@
}

function setup_k8s_vms
{
  server=$1
  servernumber="${server#*"k8s_server_"}"
  passwd=$2

  echo "Setting up Kubernetes VMs on server '${server}'"
 
  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_setup_k8s_master.yml -e servernumber="${servernumber}" -e k8s="true" -e msetnumber="${msetnumber}"
}

function stop_k8s_vms
{
  server=$1
  servernumber="${server#*"k8s_server_"}"
  passwd=$2
  shift
  shift
  
  echo "Stopping Kubernetes VMs on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_stop_k8s_VMs.yml --vault-password-file="${passwd}" -l "${server}" -e k8s="true" $@
}

vmfile=veos
tbfile=testbed.csv
vm_type=veos
vm_num=0
msetnumber=1

while getopts "t:m:k:n:s:" OPTION; do
    case $OPTION in
    t)
        tbfile=$OPTARG
        ;;
    m)
        vmfile=$OPTARG
        ;;
    k)
        vm_type=$OPTARG
        ;;
    n)
        vm_num=$OPTARG
        ;;
    s)
        msetnumber=$OPTARG
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
  start-topo-vms) start_topo_vms $@
               ;;
  stop-topo-vms) stop_topo_vms $@
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
  test-mg)     test_minigraph $@
               ;;
  create-master) start_k8s_vms $@
                 setup_k8s_vms $@
               ;;
  destroy-master) stop_k8s_vms $@
               ;; 
  *)           usage
               ;;
esac
