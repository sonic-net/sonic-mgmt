import pytest
import json
from datetime import datetime
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

ROUTE_JSON = 'route.json'
ROUTE_TIMEOUT = 20 # Time limit for applying route changes
ROUTE_TABLE_NAME = 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY'

def prepare_dut(duthost):
    # Set up interface
    duthost.shell('sudo config interface ip add Ethernet72 10.1.0.54/31')
    
    # Set up neighbor
    duthost.shell('sudo ip neigh add 10.1.0.37 lladdr 55:54:00:ad:48:98 dev Ethernet72')

def cleanup_dut(duthost):
    # Delete neighbor
    duthost.shell('sudo ip neigh del 10.1.0.37 dev Ethernet72')

    # remove files
    duthost.shell('rm {}'.format(ROUTE_JSON))
    duthost.shell('docker exec -i swss rm {}'.format(ROUTE_JSON))

    # remove interface
    duthost.shell('sudo config interface ip remove Ethernet72 10.1.0.54/31')

def generate_route_file(duthost, prefixes, op):
    route_data = []
    for prefix in prefixes:
        key = 'ROUTE_TABLE:' + prefix
        route = {}
        route['ifname'] = 'Ethernet72'
        route['nexthop'] = '10.1.0.37'
        route_command = {}
        route_command[key] = route
        route_command['OP'] = op
        route_data.append(route_command)

    # Copy json file to DUT
    duthost.copy(content=json.dumps(route_data, indent=4), dest=ROUTE_JSON)

def exec_routes(duthost, num_routes, op):
    # generate ip prefixes of routes
    prefixes = ['%d.%d.%d.%d/%d' % (101 + int(idx_route / 256 ** 2), int(idx_route / 256) % 256, idx_route % 256, 0, 24)
                for idx_route in range(num_routes)]

    # Generate json file for routes
    generate_route_file(duthost, prefixes, op)

    # Copy route file to swss container
    duthost.shell('docker cp {} swss:/'.format(ROUTE_JSON))
    
    # Check the number of routes in ASIC_DB
    start_num_route = int(duthost.shell('sonic-db-cli ASIC_DB keys \'{}*\' | wc -l'.format(ROUTE_TABLE_NAME))['stdout'])
    
    # Calculate expected number of route and record start time
    if op == 'SET':
        expected_num_routes = start_num_route + num_routes
    elif op == 'DEL':
        expected_num_routes = start_num_route - num_routes
    else:
        pytest.fail('Operation {} not supported'.format(op))
    start_time = datetime.now()

    # Apply routes with swssconfig
    duthost.shell('docker exec -i swss swssconfig /{}'.format(ROUTE_JSON))

    # Wait until the routes set/del applys to ASIC_DB
    def _check_num_routes(expected_num_routes):
        # Check the number of routes in ASIC_DB
        num_routes = int(duthost.shell('sonic-db-cli ASIC_DB keys \'{}*\' | wc -l'.format(ROUTE_TABLE_NAME))['stdout'])
        return num_routes == expected_num_routes
    if not wait_until(ROUTE_TIMEOUT, 0.5, _check_num_routes, expected_num_routes):
        pytest.fail('failed to add routes within time limit')

    # Record time when all routes show up in ASIC_DB
    end_time = datetime.now()

    # Check route entries are correct
    asic_route_keys = duthost.shell('sonic-db-cli ASIC_DB keys \'{}*\''.format(ROUTE_TABLE_NAME))['stdout_lines']
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

def test_perf_add_remove_routes(duthost):
    # Number of routes for test
    num_routes = 10000

    # Set up interface and interface for routes
    prepare_dut(duthost)

    # Add routes
    time_set = exec_routes(duthost, num_routes, 'SET')
    print('Time to set %d routes is %.2f seconds.' % (num_routes, time_set))

    # Remove routes
    time_del = exec_routes(duthost, num_routes, 'DEL')
    print('Time to del %d routes is %.2f seconds.' % (num_routes, time_del))

    # Cleanup DUT
    cleanup_dut(duthost)
