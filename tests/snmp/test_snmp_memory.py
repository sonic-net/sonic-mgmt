"""
Test SNMP memory MIB in SONiC.
Parameters:
    --percentage: Set optional percentege of difference for test
"""

import pytest
import logging
from tests.common.helpers.assertions import pytest_assert # pylint: disable=import-error
from tests.common.helpers.snmp_helpers import get_snmp_facts
pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

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
def load_memory(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Execute script in background to load memory
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.copy(src='snmp/memory.py', dest='/tmp/memory.py')
    duthost.shell("nohup python /tmp/memory.py > /dev/null 2>&1 &")
    yield
    duthost.shell("killall python /tmp/memory.py", module_ignore_errors=True)

def collect_memory(duthost):
    """
    Collect memory data from DUT
    """
    facts = {}
    output = duthost.shell("cat /proc/meminfo")['stdout_lines']
    for line in output:
        split = line.split()
        facts.update({split[0].replace(":", ""): split[-2]})
    return facts

def test_snmp_memory(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts):
    """
    Verify if memory MIB equals to data collected from DUT
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    host_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    compare = (('ansible_sysTotalFreeMemery', 'MemFree'), ('ansible_sysTotalBuffMemory', 'Buffers'),
               ('ansible_sysCachedMemory', 'Cached'), ('ansible_sysTotalSharedMemory', 'Shmem'))

    # Checking memory attributes within a certain percentage is not guarantee to
    # work 100% of the time. There could always be a big memory change between the
    # test read from snmp and read from system.
    # Allow the test to retry a few times before claiming failure.
    for _ in range(3):
        snmp_facts = get_snmp_facts(localhost, host=host_ip, version="v2c",
                                    community=creds_all_duts[duthost]["snmp_rocommunity"], wait=True)['ansible_facts']
        facts = collect_memory(duthost)
        # Verify correct behaviour of sysTotalMemery
        pytest_assert(not abs(snmp_facts['ansible_sysTotalMemery'] - int(facts['MemTotal'])),
                      "Unexpected res sysTotalMemery {} v.s. {}".format(snmp_facts['ansible_sysTotalMemery'], facts['MemTotal']))

        # Verify correct behaviour of sysTotalFreeMemery, sysTotalBuffMemory, sysCachedMemory, sysTotalSharedMemory
        new_comp = set()
        snmp_diff = []
        for snmp, sys_data in compare:
            if CALC_DIFF(snmp_facts[snmp], facts[sys_data]) > percent:
                snmp_diff.append(snmp)
                new_comp.add((snmp, sys_data))

        compare = new_comp
        if not snmp_diff:
            return

        logging.info("Snmp memory MIBs: {} differs more than {} %".format(snmp_diff, percent))

    pytest.fail("Snmp memory MIBs: {} differs more than {} %".format(snmp_diff, percent))


def test_snmp_memory_load(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts, load_memory):
    """
    Verify SNMP total free memory matches DUT results in stress test
    """
    # Start memory stress generation
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    host_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(localhost, host=host_ip, version="v2c",
                                community=creds_all_duts[duthost]["snmp_rocommunity"], wait=True)['ansible_facts']
    mem_free = duthost.shell("grep MemFree /proc/meminfo | awk '{print $2}'")['stdout']
    pytest_assert(CALC_DIFF(snmp_facts['ansible_sysTotalFreeMemery'], mem_free) < percent,
                  "sysTotalFreeMemery differs by more than {}".format(percent))
