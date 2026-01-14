import pytest
import json
import random
import logging

from time import sleep
from netaddr import IPNetwork
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.route.utils import generate_intf_neigh, generate_route_file, prepare_dut, cleanup_dut


pytestmark = [
    pytest.mark.topology("t0", "m0", "any"),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

LOG_EXPECT_ADD_ROUTE_FAILED = ".*Failed to create route.*"


def get_cfg_facts(duthost, asic_index):
    if duthost.sonichost.is_multi_asic:
        asic_ns = "asic{}".format(asic_index)
        cmd = "sonic-cfggen -d --print-data -n {}".format(asic_ns)
        tmp_facts = json.loads(duthost.shell(cmd)['stdout'])
    # return config db contents(running-config)
    else:
        cmd = "sonic-cfggen -d --print-data"
        tmp_facts = json.loads(duthost.shell(cmd)['stdout'])

    return tmp_facts


def get_intf_ips(interface_name, cfg_facts):
    prefix_to_intf_table_map = {
        'Vlan': 'VLAN_INTERFACE',
        'PortChannel': 'PORTCHANNEL_INTERFACE',
        'Ethernet': 'INTERFACE',
        'Loopback': 'LOOPBACK_INTERFACE'
    }

    intf_table_name = None

    ip_facts = {
        'ipv4': [],
        'ipv6': []
    }

    for pfx, t_name in list(prefix_to_intf_table_map.items()):
        if pfx in interface_name:
            intf_table_name = t_name
            break

    if intf_table_name is None:
        return ip_facts

    if intf_table_name not in cfg_facts:
        return ip_facts

    for intf in cfg_facts[intf_table_name]:
        if '|' in intf:
            if_name, ip = intf.split('|')
            if interface_name in if_name:
                ip = IPNetwork(ip)
                if ip.version == 4:
                    ip_facts['ipv4'].append(ip)
                else:
                    ip_facts['ipv6'].append(ip)

    return ip_facts


@pytest.fixture(params=['Loopback', 'Vlan'])
def interface_types(request):
    """
    Parameterized fixture for interface types.
    """
    yield request.param


@pytest.fixture(autouse=True)
def verify_expected_loganalyzer_logs(
    enum_rand_one_per_hwsku_frontend_hostname, loganalyzer
):
    """
    Verify that expected failure messages are seen in logs during test execution
    Args:
        duthost: DUT fixture
        loganalyzer: Loganalyzer utility fixture
    """
    expectRegex = [
        ]
    ignoreRegex = [
        ".*ERR.* create failed, object already exists.*",
        ".*ERR.* bulkCreate: Failed to create object.*",
        ".*ERR.* api SAI_COMMON_API_BULK_CREATE failed in syncd mode.*",
        ".*ERR.* flush_creating_entries: EntityBulker.flush create entries failed.*",
        ".*ERR.* handleSaiFailure: Encountered failure in create operation.*",
        ".*ERR.* start: Encountered failure in create operation.*",
        ".*ERR.* Failed to add UC route .* Entry Already Exists.",
        r".*ERR.* uc_route_set_async_pre_send_validate .* \[Entry Already Exists\].",
        ".*ERR.* mlnx_create_route_async.* Entry Already Exists.",
        ".*ERR.* object key SAI_OBJECT_TYPE_ROUTE_ENTRY:.* already exists.*",  # TODO move to expectRegex
        ".*ERR.* addRoutePost: Failed to create route.*",  # TODO move to expectRegex
    ]
    if loganalyzer:
        # Skip if loganalyzer is disabled
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].expect_regex.extend(
            expectRegex
        )
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(
            ignoreRegex
        )


@pytest.fixture(scope="module", autouse=True)
def reload_dut(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    config_reload(duthost, safe_reload=True, wait_for_bgp=True)


@pytest.fixture
def setup_routes(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                 enum_rand_one_frontend_asic_index, ip_versions, interface_types):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    cfg_facts = get_cfg_facts(duthost, enum_rand_one_frontend_asic_index)
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    prefixes = []

    if interface_types == 'Loopback':
        # Get loopback ips
        intf_ips = get_intf_ips('Loopback', cfg_facts)
        pytest_require((len(intf_ips['ipv4']) + len(intf_ips['ipv6'])) > 0, "No IP configured on Loopback0")
    else:
        # Get vlan ips
        intf_ips = get_intf_ips('Vlan', cfg_facts)
        pytest_require((len(intf_ips['ipv4']) + len(intf_ips['ipv6'])) > 0, "No IP configured on any Vlan")

    # Generate interfaces and neighbors
    intf_neighs, str_intf_nexthop = generate_intf_neigh(
        asichost, 1, ip_versions)
    if ip_versions == 4:
        prefixes.append(str(random.choice(intf_ips['ipv4'])).split("/")[0])
    else:
        prefixes.append(str(random.choice(intf_ips['ipv6'])).split("/")[0])

    # Setup interface IPs and neighbors
    prepare_dut(asichost, intf_neighs)

    # Generate a temp json file for route configuration
    route_file_set = duthost.shell("mktemp")["stdout"]
    generate_route_file(duthost, prefixes, str_intf_nexthop, route_file_set, "SET")

    yield route_file_set

    # Remove interface IPs and neighbors
    cleanup_dut(asichost, intf_neighs)
    duthost.shell("rm {}".format(route_file_set))


def test_duplicate_routes(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                          enum_rand_one_frontend_asic_index, setup_routes):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    swss_cfg_file_set = setup_routes

    # Get orchagent pid before applying config
    pid_before = duthost.shell("pidof orchagent")['stdout']

    # Apply route configuration
    logger.info("Applying routes via swssconfig...")
    json_set = "/dev/stdin < {}".format(swss_cfg_file_set)

    result = duthost.docker_exec_swssconfig(
        json_set, "swss", enum_rand_one_frontend_asic_index
    )

    if result["rc"] != 0:
        pytest.fail(
            "Failed to apply route configuration file: {}".format(result["stderr"])
        )

    # If T2 chassis, there maybe more than 32K routes per RH/AH neighbor.
    # when previous uplink LC finished reload_dut, the routes update may still be in progress even after all BGP
    # sessions are up. So wait for a longer time.
    route_wait_time = 5
    if 't2' in duthosts.tbinfo['topo']['name']:
        route_wait_time = 60
    sleep(route_wait_time)

    # Verify that orchagent has not crashed
    verify_orchagent_running_or_assert(duthost)
    pid_after = duthost.shell("pidof orchagent")['stdout']
    pytest_assert(pid_before == pid_after, "Error: Orchagent restarted")
