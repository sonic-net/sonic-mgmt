import pytest
import time
import logging

from tests.common.helpers.snmp_helpers import DEF_WAIT_TIMEOUT, get_snmp_facts

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

# Matches the post-load settle in the test body.
LOAD_SETTLE_SEC = 40
# Each vCPU iteration runs "nohup yes ... & sleep 1" over Ansible (often >1s wall time).
SPAWN_PER_VCPU_SEC = 2
# Slack after SNMP wait_until (DEF_WAIT_TIMEOUT) for top and Ansible; not SNMP poll time.
POST_LOAD_MARGIN_SEC = 60
DEFAULT_WATCHDOG_TIMEOUT_SEC = 300
# Above this, spawning the load plus a slow SNMP wait can outlast the default watchdog.
HIGH_SCALE_VCPU_THRESHOLD = 16


def _yes_watchdog_timeout_sec(host_vcpus):
    if host_vcpus <= HIGH_SCALE_VCPU_THRESHOLD:
        return DEFAULT_WATCHDOG_TIMEOUT_SEC
    return host_vcpus * SPAWN_PER_VCPU_SEC + LOAD_SETTLE_SEC + DEF_WAIT_TIMEOUT + POST_LOAD_MARGIN_SEC


@pytest.mark.bsl
def test_snmp_cpu(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts):
    """
    Test SNMP CPU Utilization

      - Pulls CPU usage via shell commans
      - Polls SNMP for CPU usage
      - Difference should be < 2% (allowing float->int rounding on each result)


    TODO: abstract the snmp OID by SKU
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    host_facts = duthost.setup()['ansible_facts']
    if "ansible_processor_vcpus" in host_facts:
        host_vcpus = int(host_facts['ansible_processor_vcpus'])
    else:
        res = duthost.shell("nproc")
        host_vcpus = int(res['stdout'])

    logger.info("found {} cpu on the dut".format(host_vcpus))

    # Gather facts with SNMP version 2
    snmp_facts = get_snmp_facts(
        duthost, localhost, host=hostip, version="v2c",
        community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], is_dell=True, wait=True)['ansible_facts']

    assert int(snmp_facts['ansible_ChStackUnitCpuUtil5sec'])

    watchdog_pid = None
    try:
        # Start a watchdog that guarantees cleanup even if the test times out or aborts.
        # Without this, 'yes' processes can leak on weak-per-core platforms (e.g. armhf)
        # where the test may be killed before reaching the finally block.
        # See: https://github.com/sonic-net/sonic-mgmt/issues/21517
        # On high vCPU platforms, outlive vCPU spawn + SNMP wait_until + top; others keep 300s.
        watchdog_timeout = _yes_watchdog_timeout_sec(host_vcpus)
        logger.info("yes-process watchdog timeout set to %s seconds", watchdog_timeout)
        watchdog_cmd = "nohup sh -c 'sleep {}; pkill -x -9 yes' >/dev/null 2>&1 & echo $!".format(
            watchdog_timeout)
        watchdog_pid = duthost.shell(watchdog_cmd)['stdout'].strip()

        for i in range(host_vcpus):
            duthost.shell("nohup yes > /dev/null 2>&1 & sleep 1")

        # Wait for load to reflect in SNMP
        time.sleep(LOAD_SETTLE_SEC)

        # Gather facts with SNMP version 2
        snmp_facts = get_snmp_facts(
            duthost, localhost, host=hostip, version="v2c",
            community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], is_dell=True, wait=True)['ansible_facts']

        # Pull CPU utilization via shell
        # Explanation: Run top command with 2 iterations, 5sec delay.
        # Discard the first iteration, then grap the CPU line from the second,
        # subtract 100% - idle, and round down to integer.

        output = duthost.shell(
            "top -bn2 -d5 | awk '/^top -/ { p=!p } { if (!p) print }' | awk '/Cpu/ { cpu = 100 - $8 };"
            "END   { print cpu }' | awk '{printf \"%.0f\",$1}'")

        logger.info(str(snmp_facts['ansible_ChStackUnitCpuUtil5sec']))
        logger.info(str(output['stdout']))

        cpu_diff = abs(
            int(snmp_facts['ansible_ChStackUnitCpuUtil5sec']) - int(output['stdout']))

        if cpu_diff > 5:
            pytest.fail("cpu diff large than 5%%, %d, %d" % (
                int(snmp_facts['ansible_ChStackUnitCpuUtil5sec']), int(output['stdout'])))

    finally:
        # Cancel the watchdog so it doesn't fire during later tests
        if watchdog_pid:
            duthost.shell("kill {} 2>/dev/null || true".format(watchdog_pid),
                          module_ignore_errors=True)
        duthost.shell("killall yes", module_ignore_errors=True)
