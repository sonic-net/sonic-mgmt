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
    Get optional parameter percentage
    """
    global user_input_percentage
    user_input_percentage = request.config.getoption("--percentage")
    return user_input_percentage

def get_percentage_threshold(total_mem):
    """
    When total memory is small, the same difference will be more
    pronounced. So we should allow for more difference.
    """
    if user_input_percentage:
        return user_input_percentage
    if total_mem > 2 * 1024 * 1024:
        return 4
    else:
        return 12

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
    compare = (('ansible_sysTotalFreeMemory', 'MemFree'), ('ansible_sysTotalBuffMemory', 'Buffers'),
               ('ansible_sysCachedMemory', 'Cached'), ('ansible_sysTotalSharedMemory', 'Shmem'))

    mem_total = collect_memory(duthost)['MemTotal']
    percentage = get_percentage_threshold(int(mem_total))

    # Checking memory attributes within a certain percentage is not guarantee to
    # work 100% of the time. There could always be a big memory change between the
    # test read from snmp and read from system.
    # Allow the test to retry a few times before claiming failure.
    for _ in range(3):
        snmp_facts = get_snmp_facts(localhost, host=host_ip, version="v2c",
                                    community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
        facts = collect_memory(duthost)
        # net-snmp calculate cached memory as cached + sreclaimable
        facts['Cached'] = int(facts['Cached']) + int(facts['SReclaimable'])
        # Verify correct behaviour of sysTotalMemory
        pytest_assert(not abs(snmp_facts['ansible_sysTotalMemory'] - int(facts['MemTotal'])),
                      "Unexpected res sysTotalMemory {} v.s. {}".format(snmp_facts['ansible_sysTotalMemory'], facts['MemTotal']))

        # Verify correct behaviour of sysTotalFreeMemory, sysTotalBuffMemory, sysCachedMemory, sysTotalSharedMemory
        new_comp = set()
        snmp_diff = []
        for snmp, sys_data in compare:
            if CALC_DIFF(snmp_facts[snmp], facts[sys_data]) > percentage:
                snmp_diff.append(snmp)
                new_comp.add((snmp, sys_data))

        compare = new_comp
        if not snmp_diff:
            return

        logging.info("Snmp memory MIBs: {} differs more than {} %".format(snmp_diff, percentage))

    pytest.fail("Snmp memory MIBs: {} differs more than {} %".format(snmp_diff, percentage))


def test_snmp_memory_load(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts, load_memory):
    """
    Verify SNMP total free memory matches DUT results in stress test
    """
    # Start memory stress generation
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    host_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
    snmp_facts = get_snmp_facts(localhost, host=host_ip, version="v2c",
                                community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
    mem_free = duthost.shell("grep MemFree /proc/meminfo | awk '{print $2}'")['stdout']
    mem_total = duthost.shell("grep MemTotal /proc/meminfo | awk '{print $2}'")['stdout']
    percentage = get_percentage_threshold(int(mem_total))
    pytest_assert(CALC_DIFF(snmp_facts['ansible_sysTotalFreeMemory'], mem_free) < percentage,
                  "sysTotalFreeMemory differs by more than {}".format(percentage))

def test_snmp_swap(duthosts, enum_rand_one_per_hwsku_hostname, localhost, creds_all_duts):
    """
    Verify swap info is correct
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    host_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']

    total_swap = duthost.shell("grep SwapTotal /proc/meminfo | awk '{print $2}'")['stdout']
    free_swap = duthost.shell("grep SwapFree /proc/meminfo | awk '{print $2}'")['stdout']

    if total_swap == "0":
        pytest.skip("Swap is not on for this device, snmp does not support swap related queries when swap isn't on")

    snmp_facts = get_snmp_facts(localhost, host=host_ip, version="v2c", include_swap=True,
                                community=creds_all_duts[duthost.hostname]["snmp_rocommunity"], wait=True)['ansible_facts']
    snmp_total_swap = snmp_facts['ansible_sysTotalSwap']
    snmp_free_swap = snmp_facts['ansible_sysTotalFreeSwap']

    logging.info("total_swap {}, free_swap {}, snmp_total_swap {}, snmp_free_swap {}".format(total_swap, free_swap, snmp_total_swap, snmp_free_swap))

    pytest_assert(CALC_DIFF(snmp_total_swap, total_swap) < percent,
                  "sysTotalSwap differs by more than {}: expect {} received {}".format(percent, total_swap, snmp_total_swap))

    if snmp_free_swap == 0 or snmp_total_swap / snmp_free_swap >= 2:
        """
        Free swap is less than half of total swap, compare used swap instead
        The comparison could get inaccurate if the number to compare is close to 0,
        so we test only one of used/free swap space.
        """
        pytest_assert(CALC_DIFF(snmp_total_swap - snmp_free_swap, int(total_swap) - int(free_swap)) < percent,
                      "Used Swap (calculated using sysTotalFreeSwap) differs by more than {}: expect {} received {}".format(
                          percent, snmp_total_swap - snmp_free_swap, int(total_swap) - int(free_swap)))
    else:
        pytest_assert(CALC_DIFF(snmp_free_swap, free_swap) < percent,
                      "sysTotalFreeSwap differs by more than {}: expect {} received {}".format(percent, snmp_free_swap, free_swap))
