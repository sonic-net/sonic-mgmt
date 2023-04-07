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
  tbname
       testbed name

Example:
  ./express_tests.sh ixr_hr_chassis-express
EOF
}


SONIC_MGMT_DIR=/data
inventory="$SONIC_MGMT_DIR/ansible/westford_hw_inventory,$SONIC_MGMT_DIR/ansible/nokia_veos"
testbed_file="$SONIC_MGMT_DIR/ansible/testbed.csv"
log_path="logs"
refresh_dut=false
exit_on_error=""

while getopts "d:ei:nt:p:" opt; do
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
    p)
      log_path=$OPTARG
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
-l info \
-a False \
-O \
-u \
-r"

if [ -n "$exit_on_error" ]; then
    RUNTEST_CLI_COMMON_OPTS="$RUNTEST_CLI_COMMON_OPTS -E"
fi

if [ -f /data/pkey.txt ]; then
    pushd $HOME
    mkdir -p .ssh
    cp /data/pkey.txt .ssh/id_rsa
    chmod 600 .ssh/id_rsa
    popd
fi

export ANSIBLE_LIBRARY=$SONIC_MGMT_DIR/ansible/library/

# workaround for issue https://github.com/Azure/sonic-mgmt/issues/1659
export ANSIBLE_KEEP_REMOTE_FILES=1

pushd $SONIC_MGMT_DIR/tests
rm -rf logs
mkdir -p logs

# Run tests_1vlan on vlab-01 virtual switch
# TODO: Use a marker to select these tests rather than providing a hard-coded list here.
tests="\
bgp/test_bgp_fact.py \
platform_tests \
voq/test_voq_ipfwd.py"

echo "Cleaning up the DUTs /var/log directory"
./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -c test_pretest.py -p %log_path -e "-k test_cleanup_testbed --deep_clean --skip_sanity"

if [[ $tbname == ixre-chassis8* ]]
then
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -m individual -c \"$tests\" -p $log_path -e \"-m express --neighbor_type sonic\""
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -m individual -c "$tests" -p $log_path -e "-m express --neighbor_type sonic"
else
  echo "./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -m individual -c \"$tests\" -p $log_path -e \"-m express\""
  ./run_tests.sh $RUNTEST_CLI_COMMON_OPTS -m individual -c "$tests" -p $log_path -e "-m express"
fi
