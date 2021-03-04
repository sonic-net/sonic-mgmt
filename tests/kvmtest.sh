#!/bin/bash -xe

usage() {
    cat >&2 <<EOF
Usage:
  kvmtest.sh [-en] [-i inventory] [-t testbed_file] [-T test suite] [-d SONIC_MGMT_DIR] tbname dut

Description:
  -d SONIC_MGMT_DIR
       sonic-mgmt repo directory (default: /data/sonic-mgmt)
  -e
       exit on error (default: false)
  -i inventory
       inventory file (default: veos_vtb)
  -n
       Do not refresh DUT
  -t testbed_file
       testbed file (default: vtestbed.csv)
  -T test_suite
       test suite [t0|t1-lag] (default: t0)
  tbname
       testbed name
  dut
       DUT name

Example:
  ./kvmtest.sh vms-kvm-t0 vlab-01
EOF
}

inventory="veos_vtb"
testbed_file="vtestbed.csv"
refresh_dut=true
exit_on_error=""
SONIC_MGMT_DIR=/data/sonic-mgmt
test_suite="t0"

while getopts "d:ei:nt:T:" opt; do
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
    n)
      refresh_dut=""
      ;;
    t)
      testbed_file=$OPTARG
      ;;
    T)
      test_suite=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit 1
      ;;
  esac
done
shift "$((OPTIND - 1))"

if [ $# -lt 2 ]; then
    usage
    exit 1
fi

tbname=$1
dut=$2

RUNTEST_CLI_COMMON_OPTS="\
-i $inventory \
-d $dut \
-n $tbname \
-f $testbed_file \
-k debug \
-l warning \
-m individual \
-q 1 \
-a False \
-O \
-r"

if [ -n "$exit_on_error" ]; then
    RUNTEST_CLI_COMMON_OPTS="$RUNTEST_CLI_COMMON_OPTS -E"
fi

test_t0() {
    # Run tests_1vlan on vlab-01 virtual switch
    # TODO: Use a marker to select these tests rather than providing a hard-coded list here.
    tgname=1vlan
    tests="\
    monit/test_monit_status.py \
    platform_tests/test_advanced_reboot.py \
    test_interfaces.py \
    arp/test_arp_dualtor.py \
    bgp/test_bgp_fact.py \
    bgp/test_bgp_gr_helper.py \
    bgp/test_bgp_speaker.py \
    cacl/test_ebtables_application.py \
    cacl/test_cacl_application.py \
    cacl/test_cacl_function.py \
    dhcp_relay/test_dhcp_relay.py \
    lldp/test_lldp.py \
    ntp/test_ntp.py \
    pc/test_po_cleanup.py \
    pc/test_po_update.py \
    route/test_default_route.py \
    arp/test_neighbor_mac.py \
    arp/test_neighbor_mac_noptf.py \
    snmp/test_snmp_cpu.py \
    snmp/test_snmp_interfaces.py \
    snmp/test_snmp_lldp.py \
    snmp/test_snmp_pfc_counters.py \
    snmp/test_snmp_queue.py \
    snmp/test_snmp_loopback.py \
    snmp/test_snmp_default_route.py \
    syslog/test_syslog.py \
    tacacs/test_rw_user.py \
    tacacs/test_ro_user.py \
    tacacs/test_jit_user.py \
    telemetry/test_telemetry.py \
    test_features.py \
    test_procdockerstatsd.py \
    iface_namingmode/test_iface_namingmode.py \
    platform_tests/test_cpu_memory_usage.py \
    bgp/test_bgpmon.py \
    process_monitoring/test_critical_process_monitoring.py"

    pushd $SONIC_MGMT_DIR/tests
    ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c "$tests" -p logs/$tgname
    popd

    # Create and deploy two vlan configuration (two_vlan_a) to the virtual switch
    pushd $SONIC_MGMT_DIR/ansible
    ./testbed-cli.sh -m $inventory -t $testbed_file deploy-mg $tbname lab password.txt -e vlan_config=two_vlan_a
    popd
    sleep 180

    # Run tests_2vlans on vlab-01 virtual switch
    tgname=2vlans
    tests="dhcp_relay/test_dhcp_relay.py"

    pushd $SONIC_MGMT_DIR/tests
    ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c "$tests" -p logs/$tgname
    popd
}

test_t1_lag() {
    tgname=t1_lag
    tests="\
    monit/test_monit_status.py \
    test_interfaces.py \
    bgp/test_bgp_fact.py \
    bgp/test_bgp_allow_list.py \
    bgp/test_bgp_multipath_relax.py \
    bgp/test_bgp_bbr.py \
    bgp/test_bgp_bounce.py \
    bgp/test_bgp_update_timer.py \
    bgp/test_traffic_shift.py \
    lldp/test_lldp.py \
    route/test_default_route.py \
    platform_tests/test_cpu_memory_usage.py \
    bgp/test_bgpmon.py \
    process_monitoring/test_critical_process_monitoring.py"

    pushd $SONIC_MGMT_DIR/tests
    ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c "$tests" -p logs/$tgname
    popd
}

if [ -f /data/pkey.txt ]; then
    pushd $HOME
    mkdir -p .ssh
    cp /data/pkey.txt .ssh/id_rsa
    chmod 600 .ssh/id_rsa
    popd
fi

pushd $SONIC_MGMT_DIR/ansible
if [ -n "$refresh_dut" ]; then
    # Refresh dut in the virtual switch topology
    ./testbed-cli.sh -m $inventory -t $testbed_file -k ceos refresh-dut $tbname password.txt
    sleep 120
fi

# Create and deploy default vlan configuration (one_vlan_a) to the virtual switch
./testbed-cli.sh -m $inventory -t $testbed_file deploy-mg $tbname lab password.txt
sleep 180

popd

export ANSIBLE_LIBRARY=$SONIC_MGMT_DIR/ansible/library/

# workaround for issue https://github.com/Azure/sonic-mgmt/issues/1659
export ANSIBLE_KEEP_REMOTE_FILES=1

# clear logs from previous test runs
rm -rf $SONIC_MGMT_DIR/tests/logs
mkdir -p  $SONIC_MGMT_DIR/tests/logs

# run tests
if [ x$test_suite == x"t0" ]; then
    test_t0
elif [ x$test_suite == x"t1-lag" ]; then
    test_t1_lag
else
    echo "unknown $test_suite"
    exit 1
fi
