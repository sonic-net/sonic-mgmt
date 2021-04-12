import pytest
import random
from tests.common.ixia.common_helpers import enable_packet_aging, start_pfcwd,\
    get_portchannel_member
from tests.common.config_reload import config_reload
from tests.conftest import generate_priority_lists

@pytest.fixture(autouse=True, scope="module")
def rand_lossless_prio(request):
    """
    Fixture that randomly selects a lossless priority

    Args:
        request (object): pytest request object

    Yields:
        lossless priority (str): string containing 'hostname|lossless priority'

    """
    lossless_prios = generate_priority_lists(request, "lossless")
    if lossless_prios:
        yield random.sample(lossless_prios, 1)[0]
    else:
        yield 'unknown|unknown'

@pytest.fixture(autouse=True, scope="module")
def rand_lossy_prio(request):
    """
    Fixture that randomly selects a lossy priority

    Args:
        request (object): pytest request object

    Yields:
        lossy priority (str): string containing 'hostname|lossy priority'

    """
    lossy_prios = generate_priority_lists(request, "lossy")
    if lossy_prios:
        yield random.sample(lossy_prios, 1)[0]
    else:
        yield 'unknown|unknown'

@pytest.fixture(autouse=True, scope="module")
def start_pfcwd_after_test(duthosts, rand_one_dut_hostname):
    """
    Ensure that PFC watchdog is enabled with default setting after tests

    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Yields:
        N/A
    """
    yield

    duthost = duthosts[rand_one_dut_hostname]
    start_pfcwd(duthost)

@pytest.fixture(autouse=True, scope="module")
def enable_packet_aging_after_test(duthosts, rand_one_dut_hostname):
    """
    Ensure that packet aging is enabled after tests

    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Yields:
        N/A
    """
    yield

    duthost = duthosts[rand_one_dut_hostname]
    enable_packet_aging(duthost)

def __need_set_pc_minlinks(duthost):
    """
    Check if we need to set portchannel min links to 1 for the DUT

    Args:
        duthost (object): device unnder test

    Returns:
        True if we need to set min links to 1, False otherwise
    """
    pc_member = get_portchannel_member(duthost)
    if pc_member is not None:
        for pc in pc_member:
            intfs = pc_member[pc]
            if len(intfs) > 1:
                return True

    return False

@pytest.fixture(autouse=True, scope="module")
def set_pc_minlinks_before_test(duthosts, rand_one_dut_hostname):
    """
    Set the portchannel min links to 1 before tests

    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Yields:
        N/A
    """
    duthost = duthosts[rand_one_dut_hostname]

    if __need_set_pc_minlinks(duthost):
        pc_member = get_portchannel_member(duthost)
        for pc in pc_member:
            cmd = r'redis-cli -n 4 hset "PORTCHANNEL|{}" "min_links" "1"'.format(pc)
            duthost.shell(cmd)

        duthost.shell('sudo config save -y')
        config_reload(duthost=duthost, config_source='config_db', wait=240)

    yield

@pytest.fixture(autouse=True, scope="module")
def reload_config_after_test(duthosts, rand_one_dut_hostname):
    """
    Reload minigraph configuration after test if we have modified portchannel
    min links

    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Yields:
        N/A
    """
    yield

    duthost = duthosts[rand_one_dut_hostname]
    if __need_set_pc_minlinks(duthost):
        config_reload(duthost=duthost, config_source='minigraph', wait=240)
