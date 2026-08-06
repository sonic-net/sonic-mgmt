import pytest
from tests.common import constants

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


@pytest.fixture(params=["4", "6"])
def ip_versions(request):
    """
    Parameterized fixture for IP versions.
    """
    yield request.param


@pytest.fixture(params=["VlanSubnet", "VlanSubnetIPinIP"])
def packet_type(request):
    """
    Parameterized fixture for packet types used for neighbor miss tests
    """
    yield request.param


@pytest.fixture(autouse=True, scope="module")
def is_backend_topology(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
        Check if the current test is running on the backend topology.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)

    return is_backend_topology


@pytest.fixture(params=[64, 1514, 4096])
def packet_size(request):
    """
    Parameterized fixture for packet sizes.
    4096 is the biggest frame size currently because of an issue with
    ptf_nn_agent, which truncates jumbo packets to 4096 bytes.
    Refer: https://github.com/p4lang/ptf/issues/226
    """
    yield request.param
