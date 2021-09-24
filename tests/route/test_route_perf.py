import pytest
import json
import logging
import time
from datetime import datetime
from tests.common.utilities import wait_until
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert

CRM_POLL_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

ROUTE_TABLE_NAME = 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY'

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        The route_checker script will compare routes in APP_DB and ASIC_DB, and an ERROR will be
        recorded if mismatch. The testcase will add 10,000 routes to APP_DB, and route_checker may
        detect mismatch during this period. So a new pattern is added to ignore possible error logs.

        Args:
            duthost: DUT fixture
            loganalyzer: Loganalyzer utility fixture
    """
    ignoreRegex = [
        ".*ERR route_check.py:.*",
        ".*ERR.* \'routeCheck\' status failed.*"
    ]
    if loganalyzer:
        # Skip if loganalyzer is disabled
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(ignoreRegex)

@pytest.fixture(params=[4, 6])
def ip_versions(request):
    """
    Parameterized fixture for IP versions.
    """
    yield request.param

@pytest.fixture(scope='function', autouse=True)
def reload_dut(duthosts, enum_rand_one_per_hwsku_frontend_hostname, request):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    if request.node.rep_call.failed:
        #Issue a config_reload to clear statically added route table and ip addr
        logging.info("Reloading config..")
        config_reload(duthost)

@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """ Set CRM polling interval to 1 second """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLL_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)
    yield
    duthost.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)

def prepare_dut(duthost, intf_neighs):
    for intf_neigh in intf_neighs:
        # Set up interface
        duthost.shell('sudo config interface ip add {} {}'.format(intf_neigh['interface'], intf_neigh['ip']))
        # Set up neighbor
        duthost.shell('sudo ip neigh replace {} lladdr {} dev {}'.format(intf_neigh['neighbor'], intf_neigh['mac'], intf_neigh['interface']))

def cleanup_dut(duthost, intf_neighs):
    for intf_neigh in intf_neighs:
        # Delete neighbor
        duthost.shell('sudo ip neigh del {} dev {}'.format(intf_neigh['neighbor'], intf_neigh['interface']))
        # remove interface
        duthost.shell('sudo config interface ip remove {} {}'.format(intf_neigh['interface'], intf_neigh['ip']))

def generate_intf_neigh(duthost, num_neigh, ip_version):
    interfaces = duthost.show_interface(command='status')['ansible_facts']['int_status']
    up_interfaces = []
    for intf, values in interfaces.items():
        if values['admin_state'] == 'up' and values['oper_state'] == 'up':
            up_interfaces.append(intf)
    if not up_interfaces:
        raise Exception('DUT does not have up interfaces')

    # Generate interfaces and neighbors
    intf_neighs = []
    str_intf_nexthop = {'ifname':'', 'nexthop':''}

    idx_neigh = 0
    for itfs_name in up_interfaces:
        if not itfs_name.startswith("PortChannel") and interfaces[itfs_name]['vlan'].startswith("PortChannel"):
            continue
        if interfaces[itfs_name]['vlan'] == 'trunk':
            continue
        if ip_version == 4:
            intf_neigh = {
                'interface' : itfs_name,
                'ip' : '10.%d.0.1/24' % (idx_neigh + 1),
                'neighbor' : '10.%d.0.2' % (idx_neigh + 1),
                'mac' : '54:54:00:ad:48:%0.2x' % idx_neigh
            }
        else:
            intf_neigh = {
                'interface' : itfs_name,
                'ip' : '%x::1/64' % (0x2000 + idx_neigh),
                'neighbor' : '%x::2' % (0x2000 + idx_neigh),
                'mac' : '54:54:00:ad:48:%0.2x' % idx_neigh
            }

        intf_neighs.append(intf_neigh)
        if idx_neigh == 0:
            str_intf_nexthop['ifname'] += intf_neigh['interface']
            str_intf_nexthop['nexthop'] += intf_neigh['neighbor']
        else:
            str_intf_nexthop['ifname'] += ',' + intf_neigh['interface']
            str_intf_nexthop['nexthop'] += ',' + intf_neigh['neighbor']
        idx_neigh += 1
        if idx_neigh == num_neigh:
            break

    if not intf_neighs:
        raise Exception('DUT does not have interfaces available for test')

    return intf_neighs, str_intf_nexthop

def generate_route_file(duthost, prefixes, str_intf_nexthop, dir, op):
    route_data = []
    for prefix in prefixes:
        key = 'ROUTE_TABLE:' + prefix
        route = {}
        route['ifname'] = str_intf_nexthop['ifname']
        route['nexthop'] = str_intf_nexthop['nexthop']
        route_command = {}
        route_command[key] = route
        route_command['OP'] = op
        route_data.append(route_command)

    # Copy json file to DUT
    duthost.copy(content=json.dumps(route_data, indent=4), dest=dir, verbose=False)

def count_routes(host):
    num = host.shell(
        'sonic-db-cli ASIC_DB eval "return #redis.call(\'keys\', \'{}*\')" 0'.format(ROUTE_TABLE_NAME),
        module_ignore_errors=True, verbose=True)['stdout']
    return int(num)

def exec_routes(duthost, prefixes, str_intf_nexthop, op):
    # Create a tempfile for routes
    route_file_dir = duthost.shell('mktemp')['stdout']

    # Generate json file for routes
    generate_route_file(duthost, prefixes, str_intf_nexthop, route_file_dir, op)

    # Check the number of routes in ASIC_DB
    start_num_route = count_routes(duthost)

    # Calculate timeout as a function of the number of routes
    route_timeout = max(len(prefixes) / 250, 1) # Allow at least 1 second even when there is a limited number of routes

    # Calculate expected number of route and record start time
    if op == 'SET':
        expected_num_routes = start_num_route + len(prefixes)
    elif op == 'DEL':
        expected_num_routes = start_num_route - len(prefixes)
    else:
        pytest.fail('Operation {} not supported'.format(op))
    start_time = datetime.now()

    # Apply routes with swssconfig
    result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(route_file_dir),
                           module_ignore_errors=True)
    if result['rc'] != 0:
        pytest.fail('Failed to apply route configuration file: {}'.format(result['stderr']))

    # Wait until the routes set/del applys to ASIC_DB
    def _check_num_routes(expected_num_routes):
        # Check the number of routes in ASIC_DB
        return count_routes(duthost) == expected_num_routes

    if not wait_until(route_timeout, 0.5, _check_num_routes, expected_num_routes):
        pytest.fail('failed to add routes within time limit')

    # Record time when all routes show up in ASIC_DB
    end_time = datetime.now()

    # Check route entries are correct
    asic_route_keys = duthost.shell('sonic-db-cli ASIC_DB eval "return redis.call(\'keys\', \'{}*\')" 0'\
        .format(ROUTE_TABLE_NAME), verbose=False)['stdout_lines']
    asic_prefixes = []
    for key in asic_route_keys:
        json_obj = key[len(ROUTE_TABLE_NAME) + 1 : ]
        asic_prefixes.append(json.loads(json_obj)['dest'])
    if op == 'SET':
        assert all(prefix in asic_prefixes for prefix in prefixes)
    elif op == 'DEL':
        assert all(prefix not in asic_prefixes for prefix in prefixes)
    else:
        pytest.fail('Operation {} not supported'.format(op))

    # Retuen time used for set/del routes
    return (end_time - start_time).total_seconds()

def test_perf_add_remove_routes(duthosts, enum_rand_one_per_hwsku_frontend_hostname, request, ip_versions):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Number of routes for test
    set_num_routes = request.config.getoption("--num_routes")

    # Generate interfaces and neighbors
    NUM_NEIGHS = 8
    intf_neighs, str_intf_nexthop = generate_intf_neigh(duthost, NUM_NEIGHS, ip_versions)

    route_tag = "ipv{}_route".format(ip_versions)
    used_routes_count = duthost.get_crm_resources().get("main_resources").get(route_tag, {}).get("used")
    avail_routes_count = duthost.get_crm_resources().get("main_resources").get(route_tag, {}).get("available")
    pytest_assert(avail_routes_count, "CRM main_resources data is not ready within adjusted CRM polling time {}s".\
            format(CRM_POLL_INTERVAL))
    num_routes = min(avail_routes_count, set_num_routes)
    logger.info("IP route utilization before test start: Used: {}, Available: {}, Test count: {}"\
        .format(used_routes_count, avail_routes_count, num_routes))

    # Generate ip prefixes of routes
    if (ip_versions == 4):
        prefixes = ['%d.%d.%d.%d/%d' % (101 + int(idx_route / 256 ** 2), int(idx_route / 256) % 256, idx_route % 256, 0, 24)
                    for idx_route in range(num_routes)]
    else:
        prefixes = ['%x:%x:%x::/%d' % (0x3000 + int(idx_route / 65536), idx_route % 65536, 1, 64)
                    for idx_route in range(num_routes)]
    try:
        # Set up interface and interface for routes
        prepare_dut(duthost, intf_neighs)

        # Add routes
        time_set = exec_routes(duthost, prefixes, str_intf_nexthop, 'SET')
        logger.info('Time to set %d ipv%d routes is %.2f seconds.' % (num_routes, ip_versions, time_set))

        # Remove routes
        time_del = exec_routes(duthost, prefixes, str_intf_nexthop, 'DEL')
        logger.info('Time to del %d ipv%d routes is %.2f seconds.' % (num_routes, ip_versions, time_del))
    finally:
        cleanup_dut(duthost, intf_neighs)
