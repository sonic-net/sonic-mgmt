#!/bin/bash

usage() {
    cat >&2 <<EOF
Usage:
  express_tests.sh [-n] [-i inventory] [-t testbed_file] [-d SONIC_MGMT_DIR] [-p log_path] tbname

Description:
  -n
       Do not refresh DUT
  -i inventory
       inventory file (default: westford_hw_inventory,nokia_veos)
  -t testbed_file
       testbed file (default: testbed.csv)
  -d SONIC_MGMT_DIR
       sonic-mgmt repo directory (default: /data/)
  -p log_path
        path to the logs (default: logs)
  -T test_suite
        test suite [t2|masic|platform|ndk|voq] (default: t2)
  tbname
       testbed name

Example:
  ./t2_tests.sh ixr_vdk_chassis4-t2
EOF
}


SONIC_MGMT_DIR=/data
inventory="$SONIC_MGMT_DIR/ansible/westford_hw_inventory,$SONIC_MGMT_DIR/ansible/nokia_veos"
testbed_file="$SONIC_MGMT_DIR/ansible/testbed.csv"
log_path="logs"
refresh_dut=false
exit_on_error=""
test_suite="t2"
ndk_image_url=""
run_in_order=false

while getopts "d:ei:N:nOt:p:T:" opt; do
  case $opt in
    d)
      SONIC_MGMT_DIR=$OPTARG
      ;;
    i)
      inventory=$OPTARG
      ;;
    e)
      exit_on_error=true
      ;;
    N)
      ndk_image_url=$OPTARG
      ;;
    n)
      refresh_dut=""
      ;;
    t)
      testbed_file=$OPTARG
      ;;
    T)
      test_suite=$OPTARG
      ;;
    p)
      log_path=$OPTARG
      ;;
    O)
      run_in_order=true
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit 1
      ;;
  esac
done
shift "$((OPTIND - 1))"

if [ $# -lt 1 ]; then
    usage
    exit 1
fi


echo "log_path = $log_path"
echo "inventory = $inventory"
tbname=$1

RUNTEST_CLI_COMMON_OPTS="\
-i $inventory \
-n $tbname \
-f $testbed_file \
-k debug \
-a False \
-t t2,ndk,any \
-r"

if $run_in_order; then
    RUNTEST_CLI_COMMON_OPTS="$RUNTEST_CLI_COMMON_OPTS -O"
fi

if [ -n "$exit_on_error" ]; then
    RUNTEST_CLI_COMMON_OPTS="$RUNTEST_CLI_COMMON_OPTS -E"
fi

COMMON_EXTRA_ARGS="--deep_clean --allow_recover --capture_console"
# Add ndk image url
if [ "$ndk_image_url" != "" ]; then
  COMMON_EXTRA_ARGS="$COMMON_EXTRA_ARGS --ndk_image_url $ndk_image_url"
fi

# For chassis with KVM's add neighbor_type as sonic and enable macsec
if [[ $tbname == ixre-chassis8* ]]; then
  COMMON_EXTRA_ARGS="$COMMON_EXTRA_ARGS --neighbor_type sonic"
fi

if [ -f /data/pkey.txt ]; then
    pushd $HOME
    mkdir -p .ssh
    cp /data/pkey.txt .ssh/id_rsa
    chmod 600 .ssh/id_rsa
    chmod 600 .ssh/id_rsa
    popd
fi

export ANSIBLE_LIBRARY=$SONIC_MGMT_DIR/ansible/library/

# workaround for issue https://github.com/Azure/sonic-mgmt/issues/1659
export ANSIBLE_KEEP_REMOTE_FILES=1

pushd $SONIC_MGMT_DIR/tests
rm -rf logs
mkdir -p logs


test_platform() {
  tests="\
  platform_tests/cli \
  platform_tests/sfp \
  platform_tests/api \
  platform_tests/test_xcvr_info_in_db.py \
  platform_tests/test_power_budget_info.py \
  platform_tests/test_platform_info.py"
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c \"$tests\" -p $log_path -e \"$COMMON_EXTRA_ARGS\""
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c "$tests" -p $log_path -u -e "$COMMON_EXTRA_ARGS"
}

test_ndk() {
  tests="nokia/suites/platform/ndk/test_chassis.py"
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c \"$tests\" -p $log_path/ndk -e \"--deep_clean\""
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c "$tests" -p $log_path/ndk -u -e "--deep_clean"
}



# Run tests_1vlan on vlab-01 virtual switch
# TODO: Use a marker to select these tests rather than providing a hard-coded list here.

test_macsec() {
  tests="macsec"
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c \"$tests\" -p $log_path -m individual - e \"$COMMON_EXTRA_ARGS\"" > $log_path/run_tests_cmd.txt
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c "$tests" -p $log_path -m individual -e "$COMMON_EXTRA_ARGS"
}

test_voq() {
  tests="\
  voq/test_voq_init.py \
  voq/test_voq_ipfwd.py \
  voq/test_voq_nbr.py \
  voq/test_voq_disrupts.py \
  voq/test_voq_intfs.py"
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c \"$tests\" -p $log_path"
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c "$tests" -p $log_path
}

test_neg_masic() {
  tests="\
  fib \
  voq/test_voq_init.py \
  voq/test_voq_ipfwd.py"

  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c \"$tests\" -p $log_path -e \"$COMMON_EXTRA_ARGS\""
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c \"$tests\" -p $log_path -e \"$COMMON_EXTRA_ARGS\"" > $log_path/run_tests_cmd.txt
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c "$tests" -p $log_path -e \"$COMMON_EXTRA_ARGS\"
}

test_t2_nightly() {
  tests="\
  bgp/test_bgp_fact.py \
  voq/test_voq_init.py \
  voq/test_voq_ipfwd.py \
  platform_tests/cli \
  platform_tests/sfp \
  platform_tests/api \
  platform_tests/test_xcvr_info_in_db.py \
  platform_tests/test_power_budget_info.py \
  platform_tests/test_platform_info.py \
  platform_tests/test_port_toggle.py \
  platform_tests/test_cpu_memory_usage.py \
  test_interfaces.py \
  platform_tests/link_flap \
  fib \
  test_procdockerstatsd.py"

  ndk_tests="nokia/suites/platform"
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c \"$tests\" -p $log_path -e \"$COMMON_EXTRA_ARGS\""
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c \"$tests\" -p $log_path -e \"$COMMON_EXTRA_ARGS\"" > $log_path/run_tests_cmd.txt
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c "$tests" -p $log_path -e "$COMMON_EXTRA_ARGS"
  echo "Running NDK tests using ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c \"$ndk_tests\" -p $log_path/ndk"
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c "$ndk_tests" -p $log_path/ndk
}

test_t2_masic() {
  tests="acl arp autorestart bfd bgp cacl configlet console \
     container_checker copp crm decap \
     dhcp_relay drop_packets dualtor dualtor_io \
     dut_console ecmp everflow fdb fib \
     generic_config_updater http iface_namingmode \
     ip ipfwd ixia lldp log_fidelity macsec \
     memory_checker monit nat ntp pc \
     pfc pfc_asym pfcwd platform_tests portstat process_monitorying qos \
     radv restapi route scp sflow show_techsupport snappi snmp span \
     ssh stress sub_port_interfaces syslog system_health \
     tacacs telemetry test_features.py test_interfaces.py test_nbr_health.py \
     test_procdockerstatsd.py testbed_setup  upgrade_path vlan voq"

  ndk_tests="nokia/suites/platform/ndk"

  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c \"$tests\" -p $log_path -m individual -e \"$COMMON_EXTRA_ARGS\""
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c \"$tests\" -p $log_path -m individual -e \"$COMMON_EXTRA_ARGS\"" > $log_path/run_tests_cmd.txt
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c "$tests" -p $log_path -m individual -e "$COMMON_EXTRA_ARGS"
  echo "Running NDK tests using ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c \"$ndk_tests\" -p $log_path/ndk"
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -u -c "$ndk_tests" -p $log_path/ndk
}

# run tests
echo "Running suite $test_suite"
if [ x$test_suite == x"masic" ]; then
    test_t2_masic
elif [ x$test_suite == x"nightly" ]; then
    test_t2_nightly
elif [ x$test_suite == x"voq" ]; then
    test_voq
elif [ x$test_suite == x"platform" ]; then
    test_platform
elif [ x$test_suite == x"ndk" ]; then
    test_ndk
elif [ x$test_suite == x"neg_masic" ]; then
    test_neg_masic
else
    echo "unknown $test_suite"
    exit 1
fi

source /var/AzDevOps/env-python3/bin/activate; cd $log_path;python3 /data/test_reporting/junit_xml_parser.py . -d
