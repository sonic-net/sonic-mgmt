import pytest
import random
from tests.common.ixia.common_helpers import enable_packet_aging, start_pfcwd,\
    get_portchannel_member
from tests.common.config_reload import config_reload
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
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
    pc_member = get_portchannel_member(duthost)

    if pc_member is not None:
        for pc in list(pc_member.keys()):
            cmd = r'redis-cli -n 4 hset "PORTCHANNEL|{}" "min_links" "1"'.format(pc)
            duthost.shell(cmd)

        duthost.shell('sudo config save -y')
        if isMellanoxDevice(duthost):
            wait_sec = 240
        else:
            wait_sec = 90

        config_reload(duthost=duthost, config_source='config_db', wait=wait_sec)

    yield

@pytest.fixture(autouse=True, scope="module")
def reload_config_after_test(duthosts, rand_one_dut_hostname):
    """
    Reload minigraph configuration after test

    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Yields:
        N/A
    """
    yield

    duthost = duthosts[rand_one_dut_hostname]
    if isMellanoxDevice(duthost):
        wait_sec = 240
    else:
        wait_sec = 90

    config_reload(duthost=duthost, config_source='minigraph', wait=wait_sec)
