import pytest
import json
from datetime import datetime
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

ROUTE_TABLE_NAME = 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY'

def prepare_dut(duthost, intf_neighs):
    for intf_neigh in intf_neighs:
        # Set up interface
        duthost.shell('sudo config interface ip add {} {}'.format(intf_neigh['interface'], intf_neigh['ip']))
        
        # Set up neighbor
        duthost.shell('sudo ip neigh add {} lladdr {} dev {}'.format(intf_neigh['neighbor'], intf_neigh['mac'], intf_neigh['interface']))

def cleanup_dut(duthost, intf_neighs):
    for intf_neigh in intf_neighs:
        # Delete neighbor
        duthost.shell('sudo ip neigh del {} dev {}'.format(intf_neigh['neighbor'], intf_neigh['interface']))

        # remove interface
        duthost.shell('sudo config interface ip remove {} {}'.format(intf_neigh['interface'], intf_neigh['ip']))

def generate_intf_neigh(num_neigh):
    # Generate interfaces and neighbors
    intf_neighs = []
    str_intf_nexthop = {'ifname':'', 'nexthop':''}
    for idx_neigh in range(num_neigh):
        intf_neigh = {
            'interface' : 'Ethernet%d' % (idx_neigh * 4 + 4),
            'ip' : '10.%d.0.1/24' % (idx_neigh + 1),
            'neighbor' : '10.%d.0.2' % (idx_neigh + 1),
            'mac' : '54:54:00:ad:48:%0.2x' % idx_neigh
        }
        intf_neighs.append(intf_neigh)
        if idx_neigh == 0:
            str_intf_nexthop['ifname'] += intf_neigh['interface']
            str_intf_nexthop['nexthop'] += intf_neigh['neighbor']
        else:
            str_intf_nexthop['ifname'] += ',' + intf_neigh['interface']
            str_intf_nexthop['nexthop'] += ',' + intf_neigh['neighbor']
    
    return intf_neighs, str_intf_nexthop

def generate_intf_neigh_ipv6(num_neigh):
    # Generate interfaces and neighbors
    intf_neighs = []
    str_intf_nexthop = {'ifname':'', 'nexthop':''}
    for idx_neigh in range(num_neigh):
        intf_neigh = {
            'interface' : 'Ethernet%d' % (idx_neigh * 4),
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
    duthost.copy(content=json.dumps(route_data, indent=4), dest=dir)

def exec_routes(duthost, prefixes, str_intf_nexthop, op):
    # Create a tempfile for routes
    route_file_dir = duthost.shell('mktemp')['stdout']

    # Generate json file for routes
    generate_route_file(duthost, prefixes, str_intf_nexthop, route_file_dir, op)

    # Check the number of routes in ASIC_DB
    start_num_route = int(duthost.shell('sonic-db-cli ASIC_DB eval "return #redis.call(\'keys\', \'{}*\')" 0'.format(ROUTE_TABLE_NAME))['stdout'])
    
    # Calculate timeout as a function of the number of routes
    route_timeout = max(len(prefixes) / 500, 1) # Allow at least 1 second even when there is a limited number of routes

    # Calculate expected number of route and record start time
    if op == 'SET':
        expected_num_routes = start_num_route + len(prefixes)
    elif op == 'DEL':
        expected_num_routes = start_num_route - len(prefixes)
    else:
        pytest.fail('Operation {} not supported'.format(op))
    start_time = datetime.now()

    # Apply routes with swssconfig
    duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(route_file_dir))

    # Wait until the routes set/del applys to ASIC_DB
    def _check_num_routes(expected_num_routes):
        # Check the number of routes in ASIC_DB
        num_routes = int(duthost.shell('sonic-db-cli ASIC_DB eval "return #redis.call(\'keys\', \'{}*\')" 0'.format(ROUTE_TABLE_NAME))['stdout'])
        return num_routes == expected_num_routes
    if not wait_until(route_timeout, 0.5, _check_num_routes, expected_num_routes):
        pytest.fail('failed to add routes within time limit')

    # Record time when all routes show up in ASIC_DB
    end_time = datetime.now()

    # Check route entries are correct
    asic_route_keys = duthost.shell('sonic-db-cli ASIC_DB eval "return redis.call(\'keys\', \'{}*\')" 0'.format(ROUTE_TABLE_NAME))['stdout_lines']
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

def test_perf_add_remove_routes(duthost, request):
    # Number of routes for test
    num_routes = request.config.getoption("--num_routes")

    # Generate interfaces and neighbors
    intf_neighs, str_intf_nexthop = generate_intf_neigh(8)

    # Generate ip prefixes of routes
    prefixes = ['%d.%d.%d.%d/%d' % (101 + int(idx_route / 256 ** 2), int(idx_route / 256) % 256, idx_route % 256, 0, 24)
                for idx_route in range(num_routes)]

    # Set up interface and interface for routes
    prepare_dut(duthost, intf_neighs)

    # Add routes
    time_set = exec_routes(duthost, prefixes, str_intf_nexthop, 'SET')
    print('Time to set %d ipv4 routes is %.2f seconds.' % (num_routes, time_set))

    # Remove routes
    time_del = exec_routes(duthost, prefixes, str_intf_nexthop, 'DEL')
    print('Time to del %d ipv4 routes is %.2f seconds.' % (num_routes, time_del))

    # Cleanup DUT
    cleanup_dut(duthost, intf_neighs)

def test_perf_add_remove_routes_ipv6(duthost, request):
    # Number of routes for test
    num_routes = request.config.getoption("--num_routes")

    # Generate interfaces and neighbors
    intf_neighs, str_intf_nexthop = generate_intf_neigh_ipv6(8)

    # Generate ip prefixes of routes
    prefixes = ['%x:%x:%x::/%d' % (0x3000 + int(idx_route / 65536), idx_route % 65536, 1, 64)
                for idx_route in range(num_routes)]

    # Set up interface and interface for routes
    prepare_dut(duthost, intf_neighs)

    # Add routes
    time_set = exec_routes(duthost, prefixes, str_intf_nexthop, 'SET')
    print('Time to set %d ipv6 routes is %.2f seconds.' % (num_routes, time_set))

    # Remove routes
    time_del = exec_routes(duthost, prefixes, str_intf_nexthop, 'DEL')
    print('Time to del %d ipv6 routes is %.2f seconds.' % (num_routes, time_del))

    # Cleanup DUT
    cleanup_dut(duthost, intf_neighs)
