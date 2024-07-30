import pytest

"""
    Pytest configuration used by the COPP tests.
"""
def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the COPP tests.
    """

    parser.addoption(
        "--copp_swap_syncd",
        action="store_true",
        default=False,
        help="Swap syncd container with syncd-rpc container",
    )
    parser.addoption(
        "--send_rate_limit",
        action="store",
        default=2000,
        help="Set custom server send rate limit",
    )
    parser.addoption(
        "--copp_reboot_type",
        action="store",
        type=str,
        default="cold",
        help="reboot type such as cold, fast, warm, soft"
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
