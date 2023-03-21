import pytest
import json
import logging
import time
import re
import random
import ipaddress
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from datetime import datetime
from tests.common.utilities import wait_until
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.generators import generate_ips

CRM_POLL_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

ROUTE_TABLE_NAME = 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY'
DEFAULT_NUM_ROUTES = 10000
DEAFULT_M0_MX_NUM_ROUTES = 500


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


def prepare_dut(asichost, intf_neighs):
    for intf_neigh in intf_neighs:
        # Set up interface
        asichost.config_ip_intf(intf_neigh['interface'], intf_neigh['ip'], "add")
        # Set up neighbor
        asichost.run_ip_neigh_cmd("replace " + intf_neigh['neighbor'] + " lladdr " + intf_neigh['mac'] + " dev " + intf_neigh['interface'])

def cleanup_dut(asichost, intf_neighs):
    for intf_neigh in intf_neighs:
        # Delete neighbor
        asichost.run_ip_neigh_cmd("del " + intf_neigh['neighbor'] + " dev " + intf_neigh['interface'])
        # remove interface
        asichost.config_ip_intf(intf_neigh['interface'], intf_neigh['ip'], 'remove')

def generate_intf_neigh(asichost, num_neigh, ip_version):
    interfaces = asichost.show_interface(command='status')['ansible_facts']['int_status']
    up_interfaces = []
    for intf, values in list(interfaces.items()):
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
                # change prefix ip starting with 3 to avoid overlap with any bgp ip
                'ip' : '30.%d.0.1/24' % (idx_neigh + 1),
                'neighbor' : '30.%d.0.2' % (idx_neigh + 1),
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


def exec_routes(duthost, enum_rand_one_frontend_asic_index, prefixes, str_intf_nexthop, op):
    # Create a tempfile for routes
    route_file_dir = duthost.shell('mktemp')['stdout']

    # Generate json file for routes
    generate_route_file(duthost, prefixes, str_intf_nexthop, route_file_dir, op)
    logger.info('Route file generated and copied')

    # Check the number of routes in ASIC_DB
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    start_num_route = asichost.count_routes(ROUTE_TABLE_NAME)

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

    logger.info('Before pushing route to swssconfig')
    # Apply routes with swssconfig
    json_name = '/dev/stdin < {}'.format(route_file_dir)
    result = duthost.docker_exec_swssconfig(json_name, 'swss', enum_rand_one_frontend_asic_index)

    if result['rc'] != 0:
        pytest.fail('Failed to apply route configuration file: {}'.format(result['stderr']))
    logger.info('All route entries have been pushed')

    total_delay = 0
    actual_num_routes = asichost.count_routes(ROUTE_TABLE_NAME)
    while actual_num_routes != expected_num_routes:
        diff = abs(expected_num_routes - actual_num_routes)
        delay = max(diff / 5000, 1)
        now = datetime.now()
        total_delay = (now - start_time).total_seconds()
        logger.info('Current {} expected {} delayed {} will delay {}'.format(actual_num_routes, expected_num_routes, total_delay, delay))
        time.sleep(delay)
        actual_num_routes = asichost.count_routes(ROUTE_TABLE_NAME)
        if total_delay >= route_timeout:
            break

    # Record time when all routes show up in ASIC_DB
    end_time = datetime.now()
    logger.info('All route entries have been installed in ASIC_DB in {} seconds'.format((end_time - start_time).total_seconds()))

    # Check route entries are correct
    asic_route_keys = asichost.get_route_key(ROUTE_TABLE_NAME)
    table_name_length = len(ROUTE_TABLE_NAME)
    asic_route_keys_set = set([re.search("\"dest\":\"([0-9a-f:/\.]*)\"", x[table_name_length:]).group(1) for x in asic_route_keys])
    prefixes_set = set(prefixes)
    diff = prefixes_set - asic_route_keys_set
    if op == 'SET':
        if diff:
            pytest.fail("The following entries have not been installed into ASIC {}".format(diff))
    elif op == 'DEL':
        if diff != prefixes_set:
            pytest.fail("The following entries have not been withdrawn from ASIC {}".format(prefixes_set - diff))

    # Return time used for set/del routes
    return (end_time - start_time).total_seconds()

def test_perf_add_remove_routes(tbinfo, duthosts, ptfadapter, enum_rand_one_per_hwsku_frontend_hostname, request, ip_versions, enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    # Number of routes for test
    set_num_routes = request.config.getoption("--num_routes")
    if set_num_routes is None:
        topo_name = tbinfo["topo"]["name"]
        if topo_name in ["m0", "mx"]:
            set_num_routes = DEAFULT_M0_MX_NUM_ROUTES
        else:
            set_num_routes = DEFAULT_NUM_ROUTES

    # Generate interfaces and neighbors
    NUM_NEIGHS = 50 # Update max num neighbors for multi-asic
    intf_neighs, str_intf_nexthop = generate_intf_neigh(asichost, NUM_NEIGHS, ip_versions)
   
    route_tag = "ipv{}_route".format(ip_versions)
    used_routes_count = asichost.count_crm_resources("main_resources", route_tag, "used")
    avail_routes_count = asichost.count_crm_resources("main_resources", route_tag, "available")
    pytest_assert(avail_routes_count, "CRM main_resources data is not ready within adjusted CRM polling time {}s".\
            format(CRM_POLL_INTERVAL))
    
    num_routes = min(avail_routes_count, set_num_routes)
    logger.info("IP route utilization before test start: Used: {}, Available: {}, Test count: {}"\
        .format(used_routes_count, avail_routes_count, num_routes))

    ipv4_prefix_set = [101, 41, 200, 9]
    ipv6_prefix_set = [0x3000, 0x1000, 0x00FF, 0x0123]
    # Generate ip prefixes of routes
    if (ip_versions == 4):
        random_oct = random.choice(ipv4_prefix_set)
        prefixes = ['%d.%d.%d.%d/%d' % (random_oct + int(idx_route / 256 ** 2), int(idx_route / 256) % 256, idx_route % 256, 0, 24)
                    for idx_route in range(num_routes)]
    else:
        random_oct = random.choice(ipv6_prefix_set)
        prefixes = ['%x:%x:%x:%x::/%d' % (random_oct, random_oct + int(idx_route / 65536), int(idx_route / 65536) % 65536, idx_route % 65536, 64)
                    for idx_route in range(1, num_routes+1)]
    try:
        # Set up interface and interface for routes
        prepare_dut(asichost, intf_neighs)

        # Add routes
        time_set = exec_routes(duthost, enum_rand_one_frontend_asic_index, prefixes, str_intf_nexthop, 'SET')
        logger.info('Time to set %d ipv%d routes is %.2f seconds.' % (num_routes, ip_versions, time_set))

        # Traffic verification with 10 random routes
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ptf_portmap = mg_facts['minigraph_ptf_indices']
        port_indices = mg_facts['minigraph_port_indices']
        nexthop_intf = str_intf_nexthop['ifname'].split(',')
        src_port =  random.choice(nexthop_intf)
        ptf_src_port = port_indices[mg_facts['minigraph_portchannels'][src_port]['members'][0]] if \
                       src_port.startswith("PortChannel") else port_indices[src_port] 
        ptf_dst_ports = []
        for nh_ports in nexthop_intf:
            if nh_ports.startswith("PortChannel"):
                ptf_dst_ports.append(port_indices[mg_facts['minigraph_portchannels'][nh_ports]['members'][0]])
            else:
                ptf_dst_ports.append(port_indices[nh_ports])
        dst_nws = random.sample(prefixes,10)
        for dst_nw in dst_nws:
            if (ip_versions == 4):
                ip_dst = generate_ips(1,dst_nw,[])
                send_and_verify_traffic(duthost, ptfadapter, tbinfo, ip_dst, ptf_dst_ports, ptf_src_port)
            else:
                ip_dst = dst_nw.split('/')[0] + '1'
                send_and_verify_traffic(duthost, ptfadapter, tbinfo, ip_dst, ptf_dst_ports, \
                                        ptf_src_port, ipv6=True)

        # Remove routes
        time_del = exec_routes(duthost, enum_rand_one_frontend_asic_index, prefixes, str_intf_nexthop, 'DEL')
        logger.info('Time to del %d ipv%d routes is %.2f seconds.' % (num_routes, ip_versions, time_del))
    finally:
        cleanup_dut(asichost, intf_neighs)


def send_and_verify_traffic(duthost, ptfadapter, tbinfo, ip_dst, expected_ports, ptf_src_port, ipv6=False):
    if ipv6:
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_src='2001:db8:85a3::8a2e:370:7334',
            ipv6_dst=ip_dst,
            ipv6_hlim=64,
            tcp_sport=1234,
            tcp_dport=4321)
    else:
        pkt = testutils.simple_tcp_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_src='1.1.1.1',
            ip_dst=ip_dst,
            ip_ttl=64,
            tcp_sport=1234,
            tcp_dport=4321)

    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    if ipv6:
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'hlim')
    else:
        exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')

    logger.info('Sending packet from src port - {} , expecting to recieve on any port'.format(ptf_src_port))
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_src_port, pkt)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=expected_ports)
