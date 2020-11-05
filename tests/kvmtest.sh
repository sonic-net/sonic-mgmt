#!/bin/bash -xe

tbname=$1
dut=$2
inventory="veos_vtb"
testbed_file="vtestbed.csv"

SONIC_MGMT_DIR=/data/sonic-mgmt

cd $HOME
mkdir -p .ssh
cp /data/pkey.txt .ssh/id_rsa
chmod 600 .ssh/id_rsa

# Refresh dut in the virtual switch topology
cd $SONIC_MGMT_DIR/ansible
./testbed-cli.sh -m $inventory -t $testbed_file refresh-dut $tbname password.txt
sleep 120

# Create and deploy default vlan configuration (one_vlan_a) to the virtual switch
./testbed-cli.sh -m $inventory -t $testbed_file deploy-mg $tbname lab password.txt
sleep 180

export ANSIBLE_LIBRARY=$SONIC_MGMT_DIR/ansible/library/

# workaround for issue https://github.com/Azure/sonic-mgmt/issues/1659
export export ANSIBLE_KEEP_REMOTE_FILES=1

PYTEST_CLI_COMMON_OPTS="\
-i $inventory \
-d $dut \
-n $tbname \
-f $testbed_file \
-k debug \
-l warning \
-m individual \
-q 1 \
-a False \
-e --disable_loganalyzer \
-O"

cd $SONIC_MGMT_DIR/tests
rm -rf logs
mkdir -p logs

# Run tests_1vlan on vlab-01 virtual switch
# TODO: Use a marker to select these tests rather than providing a hard-coded list here.
tgname=1vlan
tests="\
monit/test_monit_status.py \
test_interfaces.py \
bgp/test_bgp_fact.py \
bgp/test_bgp_gr_helper.py \
bgp/test_bgp_speaker.py \
cacl/test_cacl_application.py \
cacl/test_cacl_function.py \
dhcp_relay/test_dhcp_relay.py \
ntp/test_ntp.py \
pc/test_po_cleanup.py \
pc/test_po_update.py \
route/test_default_route.py \
snmp/test_snmp_cpu.py \
snmp/test_snmp_interfaces.py \
snmp/test_snmp_lldp.py \
snmp/test_snmp_pfc_counters.py \
snmp/test_snmp_queue.py \
syslog/test_syslog.py \
tacacs/test_rw_user.py \
tacacs/test_ro_user.py \
telemetry/test_telemetry.py \
test_features.py \
test_procdockerstatsd.py \
iface_namingmode/test_iface_namingmode.py \
platform_tests/test_cpu_memory_usage.py"

# FIXME: The lldp test has been temporarily disabled for https://github.com/Azure/sonic-mgmt/pull/2413
# and https://github.com/Azure/sonic-buildimage/pull/5698. The reason is that these two PRs dependent on each other.
# If PR#2413 is not merged, PR#5698 would fail PR test and cannot be merged. If PR#2413 is merged firstly, all
# sonic-mgmt-pr testing would fail before a new image with PR#5698 is ready. The workaround is to temporarily disable
# LLDP for sonic-mgmt-pr testing. Merge PR#2413 to unblock PR#5698. After a new image with PR#5698 is ready, then
# enable LLDP testing again.
# lldp/test_lldp.py

pushd $SONIC_MGMT_DIR/tests
./run_tests.sh $PYTEST_CLI_COMMON_OPTS -c "$tests" -p logs/$tgname
popd

# Create and deploy two vlan configuration (two_vlan_a) to the virtual switch
cd $SONIC_MGMT_DIR/ansible
./testbed-cli.sh -m $inventory -t $testbed_file deploy-mg $tbname lab password.txt -e vlan_config=two_vlan_a
sleep 180

# Run tests_2vlans on vlab-01 virtual switch
tgname=2vlans
tests="dhcp_relay/test_dhcp_relay.py"

pushd $SONIC_MGMT_DIR/tests
./run_tests.sh $PYTEST_CLI_COMMON_OPTS -c "$tests" -p logs/$tgname
popd
