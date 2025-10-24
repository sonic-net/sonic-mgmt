import pytest
import random
from tests.common.snappi_tests.common_helpers import enable_packet_aging, start_pfcwd
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


@pytest.fixture(autouse=True,  scope="module")
def load_gcu_config(duthosts):
    def load_file(dut, filename):
        if dut.stat(path=filename)['stat']['exists']:
            result = dut.shell(f"config apply-patch {filename}")
            if result['stdout_lines'][-1] != 'Patch applied successfully.':
                raise RuntimeError(f"GCU patch{filename} was not applied successfully:Result: {result}")
            return True
        else:
            return False

    for dut in duthosts:
        home = dut.shell(cmd="echo $HOME")['stdout']
        path = f"{home}/gcu_patches/"
        if dut.stat(path=path)['stat']['exists']:
            if dut.is_multi_asic:
                for asic in range(16):
                    filename = f"{path}/patch{asic}.json"
                    if load_file(dut, filename):
                        continue
                    else:
                        break
            else:
                filename = f"{path}/patch.json"
                load_file(dut, filename)
    yield
    return
