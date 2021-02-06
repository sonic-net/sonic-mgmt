import pytest

from tests.conftest import generate_port_lists, generate_priority_lists

@pytest.fixture(autouse=True, scope="module")
def rand_one_oper_up_intf(request):
    """
    Fixture that randomly selects one oper up interface

    Args:
        request (object): pytest request object

    Yields:
        interface (str): string containing 'hostname|selected intf'

    """
    oper_up_intfs = generate_port_lists(request, "oper_up_ports")
    if oper_up_intfs:
        yield random.sample(oper_up_intfs, 1)[0]
    else:
        yield 'unknown|unknown'

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
