import pytest


def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the COPP tests.
    """
    parser.addoption(
        "--stress_restart_round",
        action="store",
        type=int,
        default=10,
        help="Set custom restart rounds",
    )
    parser.addoption(
        "--stress_restart_duration",
        action="store",
        type=int,
        default=90,
        help="Set custom restart rounds",
    )
    parser.addoption(
        "--stress_restart_pps",
        action="store",
        type=int,
        default=100,
        help="Set custom restart rounds",
    )


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
