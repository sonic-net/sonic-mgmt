import pytest
import time
from ansible_host import AnsibleHost

@pytest.mark.bsl
def test_snmp_cpu(ansible_adhoc, testbed, creds):
    """
    Test SNMP CPU Utilization

      - Pulls CPU usage via shell commans
      - Polls SNMP for CPU usage
      - Difference should be < 2% (allowing float->int rounding on each result)


    TODO: abstract the snmp OID by SKU
    """

    hostname = testbed['dut']
    ans_host = AnsibleHost(ansible_adhoc, hostname)
    lhost = AnsibleHost(ansible_adhoc, 'localhost', True)
    hostip = ans_host.host.options['inventory_manager'].get_host(hostname).vars['ansible_host']
    host_facts = ans_host.setup()['ansible_facts']
    host_vcpus = int(host_facts['ansible_processor_vcpus'])

    # Gather facts with SNMP version 2
    snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"], is_dell=True)['ansible_facts']

    assert int(snmp_facts['ansible_ChStackUnitCpuUtil5sec'])

    try:
        for i in range(host_vcpus):
            ans_host.shell("nohup yes > /dev/null 2>&1 & sleep 1")

        # Wait for load to reflect in SNMP
        time.sleep(20)

        # Gather facts with SNMP version 2
        snmp_facts = lhost.snmp_facts(host=hostip, version="v2c", community=creds["snmp_rocommunity"], is_dell=True)['ansible_facts']

        # Pull CPU utilization via shell
        # Explanation: Run top command with 2 iterations, 5sec delay. 
        # Discard the first iteration, then grap the CPU line from the second,
        # subtract 100% - idle, and round down to integer.

        output = ans_host.shell("top -bn2 -d5 | awk '/^top -/ { p=!p } { if (!p) print }' | awk '/Cpu/ { cpu = 100 - $8 };END   { print cpu }' | awk '{printf \"%.0f\",$1}'")

        print int(snmp_facts['ansible_ChStackUnitCpuUtil5sec'])
        print int(output['stdout'])

        cpu_diff = abs(int(snmp_facts['ansible_ChStackUnitCpuUtil5sec']) - int(output['stdout']))

        if cpu_diff > 5:
            pytest.fail("cpu diff large than 5%%, %d, %d" % (int(snmp_facts['ansible_ChStackUnitCpuUtil5sec']), int(output['stdout'])))

        ans_host.shell("killall yes")
    except:
        ans_host.shell("killall yes")
        raise
