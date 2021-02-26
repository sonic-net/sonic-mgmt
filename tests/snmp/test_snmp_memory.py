"""
Test SNMP memory MIB in SONiC.
Parameters:
    --percentage: Set optional percentege of difference for test
"""

import pytest
from tests.common.helpers.assertions import pytest_assert # pylint: disable=import-error
pytestmark = [
    pytest.mark.topology('any')
]

CALC_DIFF = lambda snmp, sys_data: float(abs(snmp - int(sys_data)) * 100) / float(snmp)

@pytest.fixture(autouse=True, scope="module")
def get_parameter(request):
    """
    Get optional parameter percentage or return default 4%
    """
    global percent
    percent = request.config.getoption("--percentage") or 4
    return percent

@pytest.fixture()
def load_memory(duthosts, rand_one_dut_hostname):
    """
    Execute script in background to load memory
    """
    duthost = duthosts[rand_one_dut_hostname]
    duthost.copy(src='snmp/memory.py', dest='/tmp/memory.py')
    duthost.shell("nohup python /tmp/memory.py > /dev/null 2>&1 &")
    yield
    duthost.shell("killall python /tmp/memory.py", module_ignore_errors=True)

def collect_memory(duthosts, rand_one_dut_hostname):
    """
    Collect memory data from DUT
    """
    duthost = duthosts[rand_one_dut_hostname]
    facts = {}
    output = duthost.shell("cat /proc/meminfo")['stdout_lines']
    for line in output:
        split = line.split()
        facts.update({split[0].replace(":", ""): split[-2]})
    return facts

def test_snmp_memory(duthosts, rand_one_dut_hostname, localhost, creds):
    """
    Verify if memory MIB equals to data collected from DUT
    """
    duthost = duthosts[rand_one_dut_hostname]
    host_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=host_ip, version="v2c",
                                      community=creds["snmp_rocommunity"])['ansible_facts']
    facts = collect_memory(duthosts, rand_one_dut_hostname)
    compare = (('ansible_sysTotalFreeMemery', 'MemFree'), ('ansible_sysTotalBuffMemory', 'Buffers'),
               ('ansible_sysCachedMemory', 'Cached'))

    # Verify correct behaviour of sysTotalMemery, sysTotalSharedMemory
    pytest_assert(not abs(snmp_facts['ansible_sysTotalMemery'] - int(facts['MemTotal'])),
                  "Unexpected res sysTotalMemery {}".format(snmp_facts['ansible_sysTotalMemery']))
    pytest_assert(not abs(snmp_facts['ansible_sysTotalSharedMemory'] - int(facts['Shmem'])),
                  "Unexpected res sysTotalSharedMemory {}".format(snmp_facts['ansible_sysTotalSharedMemory']))

    # Verify correct behaviour of sysTotalFreeMemery, sysTotalBuffMemory, sysCachedMemory
    snmp_diff = [snmp for snmp, sys_data in compare if CALC_DIFF(snmp_facts[snmp],
                                                                 facts[sys_data]) > percent]
    pytest_assert(not snmp_diff,
                  "Snmp memory MIBs: {} differs more than {} %".format(snmp_diff, percent))


def test_snmp_memory_load(duthosts, rand_one_dut_hostname, localhost, creds, load_memory):
    """
    Verify SNMP total free memory matches DUT results in stress test
    """
    # Start memory stress generation
    duthost = duthosts[rand_one_dut_hostname]
    host_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = localhost.snmp_facts(host=host_ip, version="v2c",
                                      community=creds["snmp_rocommunity"])['ansible_facts']
    mem_free = duthost.shell("grep MemFree /proc/meminfo | awk '{print $2}'")['stdout']
    pytest_assert(CALC_DIFF(snmp_facts['ansible_sysTotalFreeMemery'], mem_free) < percent,
                  "sysTotalFreeMemery differs by more than {}".format(percent))
