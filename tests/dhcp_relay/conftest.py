import pytest
from tests.common import constants


@pytest.fixture(scope="module", autouse=True)
def skip_dhcp_relay_tests(tbinfo):
    """
    Skip dhcp relay tests on certain testbed types

    Args:
        tbinfo(fixture): testbed related info fixture

    Yields:
        None
    """
    if 'backend' in tbinfo['topo']['name']:
        pytest.skip("Skipping dhcp relay tests. Unsupported topology {}".format(tbinfo['topo']['name']))


@pytest.fixture(autouse=True, scope="module")
def is_backend_topology(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
        Check if the current test is running on the backend topology.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)

    return is_backend_topology
