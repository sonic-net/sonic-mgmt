import pytest

@pytest.fixture(scope="module", autouse=True)
def skip_everflow_test(tbinfo):
    """
    Skip everflow tests on certain testbed types

    Args:
        tbinfo(fixture): testbed related info fixture

    Yields:
        None
    """
    if 'backend' in tbinfo['topo']['name']:
        pytest.skip("Skipping everflow tests. Unsupported topology {}".format(tbinfo['topo']['name']))
