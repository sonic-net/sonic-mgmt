import pytest

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
