import pytest
import time
import logging

from tests.common.helpers.snmp_helpers import get_snmp_facts

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

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

    hostip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    host_facts = duthost.setup()['ansible_facts']
    if host_facts.has_key("ansible_processor_vcpus"):
        host_vcpus = int(host_facts['ansible_processor_vcpus'])
    else:
        res = duthost.shell("nproc")
        host_vcpus = int(res['stdout'])

    logger.info("found {} cpu on the dut".format(host_vcpus))

    # Gather facts with SNMP version 2
    snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"], is_dell=True, wait=True)['ansible_facts']

    assert int(snmp_facts['ansible_ChStackUnitCpuUtil5sec'])

    try:
        for i in range(host_vcpus):
            duthost.shell("nohup yes > /dev/null 2>&1 & sleep 1")

        # Wait for load to reflect in SNMP
        time.sleep(20)

        # Gather facts with SNMP version 2
        snmp_facts = get_snmp_facts(localhost, host=hostip, version="v2c", community=creds_all_duts[duthost]["snmp_rocommunity"], is_dell=True, wait=True)['ansible_facts']

        # Pull CPU utilization via shell
        # Explanation: Run top command with 2 iterations, 5sec delay.
        # Discard the first iteration, then grap the CPU line from the second,
        # subtract 100% - idle, and round down to integer.

        output = duthost.shell("top -bn2 -d5 | awk '/^top -/ { p=!p } { if (!p) print }' | awk '/Cpu/ { cpu = 100 - $8 };END   { print cpu }' | awk '{printf \"%.0f\",$1}'")

        print int(snmp_facts['ansible_ChStackUnitCpuUtil5sec'])
        print int(output['stdout'])

        cpu_diff = abs(int(snmp_facts['ansible_ChStackUnitCpuUtil5sec']) - int(output['stdout']))

        if cpu_diff > 5:
            pytest.fail("cpu diff large than 5%%, %d, %d" % (int(snmp_facts['ansible_ChStackUnitCpuUtil5sec']), int(output['stdout'])))

        duthost.shell("killall yes")
    except:
        duthost.shell("killall yes")
        raise
