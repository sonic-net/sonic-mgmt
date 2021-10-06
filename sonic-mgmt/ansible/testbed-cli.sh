#!/bin/bash

set -e

function usage
{
  echo "testbed-cli. Interface to testbeds"
  echo "Usage:"
  echo "    $0 [options] (start-vms | stop-vms) <server-name> <vault-password-file>"
  echo "    $0 [options] (start-topo-vms | stop-topo-vms) <testbed-name> <vault-password-file>"
  echo "    $0 [options] (add-topo | remove-topo | renumber-topo | connect-topo) <testbed-name> <vault-password-file>"
  echo "    $0 [options] refresh-dut <testbed-name> <vault-password-file>"
  echo "    $0 [options] (connect-vms | disconnect-vms) <testbed-name> <vault-password-file>"
  echo "    $0 [options] config-vm <testbed-name> <vm-name> <vault-password-file>"
  echo "    $0 [options] announce-routes <testbed-name> <vault-password-file>"
  echo "    $0 [options] (gen-mg | deploy-mg | test-mg) <testbed-name> <inventory> <vault-password-file>"
  echo "    $0 [options] (create-master | destroy-master) <k8s-server-name> <vault-password-file>"
  echo "    $0 [options] restart-ptf <testbed-name> <vault-password-file>"
  echo
  echo "Options:"
  echo "    -t <tbfile>     : testbed CSV file name (default: 'testbed.csv')"
  echo "    -m <vmfile>     : virtual machine file name (default: 'veos')"
  echo "    -k <vmtype>     : vm type (veos|ceos|vsonic) (default: 'veos')"
  echo "    -n <vm_num>     : vm num (default: 0)"
  echo "    -s <msetnumber> : master set identifier on specified <k8s-server-name> (default: 1)"
  echo "    -d <dir>        : sonic vm directory (default: $HOME/sonic-vm)"
  echo
  echo "Positional Arguments:"
  echo "    <server-name>         : Hostname of server on which to start VMs"
  echo "    <vault-password-file> : Path to file containing Ansible Vault password"
  echo "    <testbed-name>        : Name of the target testbed"
  echo "    <inventory>           : Name of the Ansible inventory containing the DUT"
  echo "    <k8s-server-name>     : Server identifier in form k8s_server_{id}, corresponds to k8s_ubuntu inventory group name"
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
  echo "To start VMs for specified testbed on server: $0 start-topo-vms 'testbed-name' ~/.password"
  echo "To stop all VMs on a server:  $0 stop-vms 'server-name' ~/.password"
  echo "To stop VMs for specified testbed on server: $0 stop-topo-vms 'testbed-name' ~/.password"
  echo "To cleanup *all* vms and docker: $0 cleanup-vmhost 'server-name' ~/.password"
  echo "To deploy topology for specified testbed on a server: $0 add-topo 'testbed-name' ~/.password"
  echo "    Optional argument for add-topo:"
  echo "        -e ptf_imagetag=<tag>    # Use PTF image with specified tag for creating PTF container"
  echo "To remove topology for specified testbed on a server: $0 remove-topo 'testbed-name' ~/.password"
  echo "To remove topology and keysight-api-server container for specified testbedon a server:"
  echo "        $0 remove-topo 'testbed-name' ~/.password remove_keysight_api_server"
  echo "To renumber topology for specified testbed on a server: $0 renumber-topo 'testbed-name' ~/.password"
  echo "To connect topology for specified testbed: $0 connect-topo 'testbed-name' ~/.password"
  echo "To refresh DUT of specified testbed: $0 refresh-dut 'testbed-name' ~/.password"
  echo "To configure VMs for specified testbed on a server: $0 config-vm 'testbed-name' 'vm-name' ~/.password"
  echo "To announce routes to DUT for specified testbed: $0 announce-routes 'testbed-name' ~/.password"
  echo "To generate minigraph for DUT in specified testbed: $0 gen-mg 'testbed-name' 'inventory' ~/.password"
  echo "To deploy minigraph to DUT in specified testbed: $0 deploy-mg 'testbed-name' 'inventory' ~/.password"
  echo "    gen-mg, deploy-mg, test-mg supports enabling/disabling data ACL with parameter"
  echo "        -e enable_data_plane_acl=true"
  echo "        -e enable_data_plane_acl=false"
  echo "        by default, data acl is enabled"
  echo "To create Kubernetes master on a server: $0 -m k8s_ubuntu create-master 'k8s-server-name'  ~/.password"
  echo "To destroy Kubernetes master on a server: $0 -m k8s_ubuntu destroy-master 'k8s-server-name' ~/.password"
  echo "To restart ptf of specified testbed: $0 restart-ptf 'testbed-name' ~/.password"
  echo
  echo "You should define your testbed in testbed CSV file"
  echo
  exit
}

function read_csv
{
  # Filter testbed names in the first column in the testbed definition file
  line=$(cat $tbfile | grep "^$1,")

  if [ $? -ne 0 ]
  then
   echo "Couldn't find testbed name '$1'"
   exit
  fi

  NL='
'
  case $line in
    *"$NL"*) echo "Find more than one testbed names in $tbfile"
             exit
             ;;
          *) echo "Found testbed $1"
             ;;
  esac

  IFS=, read -r -a line_arr <<< $line

  vm_set_name=${line_arr[1]}
  topo=${line_arr[2]}
  ptf_imagename=${line_arr[3]}
  ptf=${line_arr[4]}
  ptf_ip=${line_arr[5]}
  ptf_ipv6=${line_arr[6]}
  server=${line_arr[7]}
  vm_base=${line_arr[8]}
  dut=${line_arr[9]//;/,}
  duts=${dut//[\[\] ]/}
  inv_name=${line_arr[10]}
}

function read_yaml
{
  content=$(python -c "from __future__ import print_function; import yaml; print('+'.join(str(tb) for tb in yaml.safe_load(open('$tbfile')) if '$1'==tb['conf-name']))")

  IFS=$'+' read -r -a tb_lines <<< $content
  linecount=${#tb_lines[@]}

  if [ $linecount == 0 ]
  then
    echo "Couldn't find testbed name '$1'"
    exit
  elif [ $linecount -gt 1 ]
  then
    echo "Find more than one testbed name in $tbfile"
    exit
  else
    echo found testbed $1
  fi

  tb_line=${tb_lines[0]}
  line_arr=($1)
  for attr in group-name topo ptf_image_name ptf ptf_ip ptf_ipv6 server vm_base dut inv_name auto_recover comment;
  do
    value=$(python -c "from __future__ import print_function; tb=eval(\"$tb_line\"); print(tb.get('$attr', None))")
    [ "$value" == "None" ] && value=
    line_arr=("${line_arr[@]}" "$value")
  done

  vm_set_name=${line_arr[1]}
  topo=${line_arr[2]}
  ptf_imagename=${line_arr[3]}
  ptf=${line_arr[4]}
  ptf_ip=${line_arr[5]}
  ptf_ipv6=${line_arr[6]}
  server=${line_arr[7]}
  vm_base=${line_arr[8]}
  dut=${line_arr[9]}
  duts=$(python -c "from __future__ import print_function; print(','.join(eval(\"$dut\")))")
  inv_name=${line_arr[10]}
}

function read_file
{
  echo reading

  if [[ $tbfile == *.csv ]]
  then
    read_csv ${testbed_name}
  elif [[ $tbfile == *.yaml ]]
  then
    read_yaml ${testbed_name}
  fi
}

function start_vms
{
  server=$1
  passwd=$2
  shift
  shift
  echo "Starting VMs on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile -e VM_num="$vm_num" -e vm_type="$vm_type" testbed_start_VMs.yml \
      --vault-password-file="${passwd}" -l "${server}" $@
}

function stop_vms
{
  server=$1
  passwd=$2
  shift
  shift
  echo "Stopping VMs on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile -e vm_type="$vm_type" testbed_stop_VMs.yml --vault-password-file="${passwd}" -l "${server}" $@
}

function start_topo_vms
{
  testbed_name=$1
  passwd=$2
  shift
  shift
  read_file ${testbed_name}

  echo "Starting VMs for testbed '${testbed_name}' on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_start_VMs.yml --vault-password-file="${passwd}" -l "${server}" -e VM_base="$vm_base" -e topo="$topo" $@
}

function stop_topo_vms
{
  testbed_name=$1
  passwd=$2
  shift
  shift
  read_file ${testbed_name}

  echo "Stopping VMs for testbed '${testbed_name}' on server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_stop_VMs.yml --vault-password-file="${passwd}" -l "${server}" -e VM_base="$vm_base" -e topo="$topo" $@
}

function add_topo
{
  testbed_name=$1
  passwd=$2
  shift
  shift
  echo "Deploying topology for testbed '${testbed_name}'"

  read_file ${testbed_name}

  echo "$dut" "$duts"

  if [ -n "$sonic_vm_dir" ]; then
      ansible_options="-e sonic_vm_storage_location=$sonic_vm_dir"
  fi

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_add_vm_topology.yml --vault-password-file="${passwd}" -l "$server" \
        -e testbed_name="$testbed_name" -e duts_name="$duts" -e VM_base="$vm_base" \
        -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$vm_set_name" \
        -e ptf_imagename="$ptf_imagename" -e vm_type="$vm_type" -e ptf_ipv6="$ptf_ipv6" \
        $ansible_options $@

  if [[ "$ptf_imagename" != "docker-keysight-api-server" ]]; then
    ansible-playbook fanout_connect.yml -i $vmfile --limit "$server" --vault-password-file="${passwd}" -e "dut=$duts" $@
  fi

  # Delete the obsoleted arp entry for the PTF IP
  ip neighbor flush $ptf_ip || true

  echo Done
}

function remove_topo
{
  testbed_name=$1
  passwd=$2
  shift
  shift
  echo "Removing topology for testbed '${testbed_name}'"

  read_file ${testbed_name}

  remove_keysight_api_server=0
  for i in "$@"
  do
    if [[ "remove_keysight_api_server" == "$i" ]]; then
      remove_keysight_api_server=1
      shift
    fi
  done

  if [ -n "$sonic_vm_dir" ]; then
      ansible_options="-e sonic_vm_storage_location=$sonic_vm_dir"
  fi

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_remove_vm_topology.yml --vault-password-file="${passwd}" -l "$server" \
      -e testbed_name="$testbed_name" -e duts_name="$duts" -e VM_base="$vm_base" \
      -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$vm_set_name" \
      -e ptf_imagename="$ptf_imagename" -e vm_type="$vm_type" -e ptf_ipv6="$ptf_ipv6" \
      -e remove_keysight_api_server="$remove_keysight_api_server" \
      $ansible_options $@

  echo Done
}

function connect_topo
{
  testbed_name=$1
  passwd=$2
  shift
  shift

  echo "Connect topology for testbed '${testbed_name}'"

  read_file ${testbed_name}

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_connect_topo.yml \
                     --vault-password-file="${passwd}" --limit "$server" \
                     -e duts_name="$duts" \
                     -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" \
                     -e topo="$topo" -e vm_set_name="$vm_set_name" \
                     -e ptf_imagename="$ptf_imagename" -e vm_type="$vm_type" -e ptf_ipv6="$ptf_ipv6" $@

  ansible-playbook fanout_connect.yml -i $vmfile --limit "$server" --vault-password-file="${passwd}" -e "dut=$duts" $@

  echo Done
}

function renumber_topo
{
  testbed_name=$1
  passwd=$2
  shift
  shift
  echo "Renumbering topology for testbed '${testbed_name}'"

  read_file ${testbed_name}

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_renumber_vm_topology.yml --vault-password-file="${passwd}" \
      -l "$server" -e testbed_name="$testbed_name" -e duts_name="$duts" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" \
      -e topo="$topo" -e vm_set_name="$vm_set_name" -e ptf_imagename="$ptf_imagename" -e ptf_ipv6="$ptf_ipv6" $@

  ansible-playbook fanout_connect.yml -i $vmfile --limit "$server" --vault-password-file="${passwd}" -e "dut=$duts" $@

  echo Done
}

function restart_ptf
{
  testbed_name=$1
  passwd=$2
  shift
  shift

  read_file ${testbed_name}

  echo "Restart ptf ptf_${vm_set_name} for testbed '${testbed_name}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_renumber_vm_topology.yml --vault-password-file="${passwd}" \
      -l "$server" -e testbed_name="$testbed_name" -e duts_name="$duts" -e VM_base="$vm_base" -e ptf_ip="$ptf_ip" \
      -e topo="$topo" -e vm_set_name="$vm_set_name" -e ptf_imagename="$ptf_imagename" -e ptf_ipv6="$ptf_ipv6" $@

  echo Done
}

function refresh_dut
{
  testbed_name=$1
  passwd=$2
  shift
  shift
  echo "Refresh $duts in testbed '${testbed_name}'"

  read_file ${testbed_name}

  if [ -n "$sonic_vm_dir" ]; then
      ansible_options="-e sonic_vm_storage_location=$sonic_vm_dir"
  fi

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_add_vm_topology.yml --vault-password-file="${passwd}" -l "$server" \
        -e testbed_name="$testbed_name" -e duts_name="$duts" -e VM_base="$vm_base" \
        -e ptf_ip="$ptf_ip" -e topo="$topo" -e vm_set_name="$vm_set_name" \
        -e ptf_imagename="$ptf_imagename" -e vm_type="$vm_type" -e ptf_ipv6="$ptf_ipv6" \
        -e force_stop_sonic_vm="yes" \
        $ansible_options $@

  echo Done
}

function connect_vms
{
  echo "Connect VMs '$1'"

  read_file $1

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_connect_vms.yml --vault-password-file="$2" -l "$server" -e duts_name="$duts" -e VM_base="$vm_base" -e topo="$topo" -e vm_set_name="$vm_set_name"

  echo Done
}

function disconnect_vms
{
  echo "Disconnect VMs '$1'"

  read_file $1

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_disconnect_vms.yml --vault-password-file="$2" -l "$server" -e duts_name="$duts" -e VM_base="$vm_base" -e topo="$topo" -e vm_set_name="$vm_set_name"

  echo Done
}

function announce_routes
{
  testbed_name=$1
  passfile=$2
  shift
  shift

  echo "Announce routes to DUTs of testbed '$testbed_name'"

  read_file $testbed_name

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile testbed_announce_routes.yml --vault-password-file="$passfile" \
      -l "$server" -e vm_set_name="$vm_set_name" -e topo="$topo" -e ptf_ip="$ptf_ip" $@

  echo done
}

function generate_minigraph
{
  testbed_name=$1
  inventory=$2
  passfile=$3
  shift
  shift
  shift

  echo "Generating minigraph for testbed '$testbed_name'"

  read_file $testbed_name

  ansible-playbook -i "$inventory" config_sonic_basedon_testbed.yml --vault-password-file="$passfile" -l "$duts" -e testbed_name="$testbed_name" -e testbed_file=$tbfile -e vm_file=$vmfile -e local_minigraph=true $@

  echo Done
}

function deploy_minigraph
{
  testbed_name=$1
  inventory=$2
  passfile=$3
  shift
  shift
  shift

  echo "Deploying minigraph to testbed '$testbed_name'"

  read_file $testbed_name

  ansible-playbook -i "$inventory" config_sonic_basedon_testbed.yml --vault-password-file="$passfile" -l "$duts" -e testbed_name="$testbed_name" -e testbed_file=$tbfile -e vm_file=$vmfile -e deploy=true -e save=true $@

  echo Done
}

function test_minigraph
{
  testbed_name=$1
  inventory=$2
  passfile=$3
  shift
  shift
  shift

  echo "Test minigraph generation for testbed '$testbed_name'"

  read_file $testbed_name

  ansible-playbook -i "$inventory" --diff --connection=local --check config_sonic_basedon_testbed.yml --vault-password-file="$passfile" -l "$duts" -e testbed_name="$testbed_name" -e testbed_file=$tbfile -e vm_file=$vmfile -e local_minigraph=true $@

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

function cleanup_vmhost
{
  server=$1
  passwd=$2
  shift
  shift
  echo "Cleaning vm_host server '${server}'"

  ANSIBLE_SCP_IF_SSH=y ansible-playbook -i $vmfile -e VM_num="$vm_num" testbed_cleanup.yml \
      --vault-password-file="${passwd}" -l "${server}" $@
}

vmfile=veos
tbfile=testbed.csv
vm_type=veos
vm_num=0
msetnumber=1
sonic_vm_dir=""

while getopts "t:m:k:n:s:d:" OPTION; do
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
    d)
        sonic_vm_dir=$OPTARG
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
  announce-routes) announce_routes $@
               ;;
  gen-mg)      generate_minigraph $@
               ;;
  deploy-mg)   deploy_minigraph $@
               ;;
  test-mg)     test_minigraph $@
               ;;
  cleanup-vmhost) cleanup_vmhost $@
               ;;
  create-master) start_k8s_vms $@
                 setup_k8s_vms $@
               ;;
  destroy-master) stop_k8s_vms $@
               ;;
  restart-ptf) restart_ptf $@
               ;;
  *)           usage
               ;;
esac
