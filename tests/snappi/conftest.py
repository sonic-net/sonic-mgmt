import pytest
import random
from tests.common.snappi.common_helpers import enable_packet_aging, start_pfcwd
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


@pytest.fixture(scope="module")
def pfc_pause_quanta_values(duthosts, rand_one_dut_hostname):
    """
    Retrieves a dictionary of pfc pause quantas for the headroom test
    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname
    Returns:
        pfc_pause_quanta_values: Mapped from pfc pause quanta to whether
                                the headroom test will fail or not
                                E.g. {1:True, 2:False, 3:False}
    """
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts['platform']
    pfc_pause_quanta_values = {}
    if '8102' in platform:
        pfc_pause_quanta_values[1] = True
        pfc_pause_quanta_values[2] = True
        pfc_pause_quanta_values[3] = False
    elif '7050cx3' in platform:
        pfc_pause_quanta_values[1] = True
        pfc_pause_quanta_values[2] = False
    else:
        pfc_pause_quanta_values = None
    
    return pfc_pause_quanta_values
