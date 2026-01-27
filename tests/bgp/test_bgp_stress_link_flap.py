import asyncio
import logging
import pytest
import time
import json
import ipaddress
from jinja2 import Template
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, wait_tcp_connection, get_upstream_neigh_type
from tests.common.config_reload import config_reload
from bgp_helpers import BGPMON_TEMPLATE_FILE, BGP_MONITOR_NAME
from bgp_helpers import BGPSENTINEL_CONFIG_FILE
from bgp_helpers import BGP_MONITOR_PORT

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0', 't1', "m0", "mx", 'm1', 'lt2', 'ft2')
]

stop_tasks = False
SLEEP_DURATION = 0.005
TEST_RUN_DURATION = 300
MEMORY_EXHAUST_THRESHOLD = 300
dut_flap_count = 0
fanout_flap_count = 0
neighbor_flap_count = 0

LOOP_TIMES_LEVEL_MAP = {
    'debug': 60,
    'basic': 3600,
    'confident': 21600,
    'thorough': 432000
}

BGP_SENTINEL_TMPL = '''{
    "BGP_SENTINELS": {
        "BGPSentinel": {
            "ip_range": {{ v4_listen_range }},
            "name": "BGPSentinel",
            "src_address": "{{ v4_src_address }}"
        },
        "BGPSentinelV6": {
            "ip_range": {{ v6_listen_range }},
            "name": "BGPSentinelV6",
            "src_address": "{{ v6_src_address }}"
        }
    }
}'''

CONFIG_DB_BACKUP_PATH = "/tmp/config_db_backup.json"
CONFIG_DB_PATH = "/etc/sonic/config_db.json"


@pytest.fixture(scope="module", autouse=True)
def backup_and_restore_config_db(duthosts, rand_one_dut_hostname):
    """
    Module-level fixture to backup config_db.json before tests and restore it after tests.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Save current running config and reload to ensure clean starting condition
    logger.info("Saving running config and performing config reload on {} to ensure clean state".format(
        duthost.hostname))
    duthost.command("sudo config save -y")
    # Backup config_db.json before tests
    logger.info("Backing up {} to {} on {}".format(CONFIG_DB_PATH, CONFIG_DB_BACKUP_PATH, duthost.hostname))
    duthost.command("sudo cp {} {}".format(CONFIG_DB_PATH, CONFIG_DB_BACKUP_PATH))

    config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)

    yield

    # Restore config_db.json and reload after tests
    logger.info("Restoring {} from {} on {}".format(CONFIG_DB_PATH, CONFIG_DB_BACKUP_PATH, duthost.hostname))
    duthost.command("sudo mv {} {}".format(CONFIG_DB_BACKUP_PATH, CONFIG_DB_PATH))
    logger.info("Performing config reload on {}".format(duthost.hostname))
    config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)


def get_dut_listen_range(tbinfo):
    """Get the DUT listen range for BGP configuration

    This function finds the backplane interface subnet for BGP Sentinel/Monitor configuration.
    It looks for any neighbor VM that has a backplane interface (bp_interface) defined.

    On T1 topology: T2 neighbors
    On T0 topology: T1 neighbors

    Args:
        tbinfo: testbed info containing topology configuration

    Returns:
        tuple: (ipv4_subnet, ipv6_subnet, spine_bp_addr)
            - ipv4_subnet: IPv4 backplane subnet (e.g., "10.10.246.0/24")
            - ipv6_subnet: IPv6 backplane subnet (e.g., "fc0a::/64")
            - spine_bp_addr: dict of {device_name: {'ipv4': ip, 'ipv6': ip}}
    """
    ipv4_subnet, ipv6_subnet = None, None
    spine_bp_addr = {}
    topo_name = tbinfo['topo']['name']
    upstream_nbr_type = get_upstream_neigh_type(tbinfo, is_upper=True)
    logger.info("get_dut_listen_range: topo_name={}, upstream_nbr_type={}".format(topo_name, upstream_nbr_type))

    for k, v in tbinfo['topo']['properties']['configuration'].items():
        # Check if this device has backplane interface - this is the key indicator
        if 'bp_interface' not in v:
            continue

        # For T1 topology (upstream=T2): T2 neighbors have 'spine' in properties
        # For T0 topology (upstream=T1): T1 neighbors just have bp_interface, no special property
        # So we check: either has 'spine' property, OR is an upstream neighbor type (T1/T2 in VM name)
        is_upstream_neighbor = False

        # Check by property (works for T1 topology where T2 neighbors have 'spine')
        if 'spine' in v.get('properties', []):
            is_upstream_neighbor = True
            logger.debug("Found upstream neighbor {} by 'spine' property".format(k))
        # Check by VM name pattern (works for T0 topology where T1 neighbors are named ARISTAxxT1)
        elif upstream_nbr_type and upstream_nbr_type in k.upper():
            is_upstream_neighbor = True
            logger.debug("Found upstream neighbor {} by name pattern (contains {})".format(k, upstream_nbr_type))

        if is_upstream_neighbor:
            try:
                ipv4_addr = ipaddress.ip_interface(v['bp_interface']['ipv4'].encode().decode())
                ipv6_addr = ipaddress.ip_interface(v['bp_interface']['ipv6'].encode().decode())
                ipv4_subnet = str(ipv4_addr.network)
                ipv6_subnet = str(ipv6_addr.network)
                spine_bp_addr[k] = {'ipv4': str(ipv4_addr.ip), 'ipv6': str(ipv6_addr.ip)}
                logger.info("Found backplane for {}: IPv4={}, IPv6={}".format(k, ipv4_subnet, ipv6_subnet))
            except (KeyError, AttributeError) as e:
                logger.warning("Failed to parse backplane interface for {}: {}".format(k, e))
                continue

    logger.info("get_dut_listen_range result: ipv4_subnet={}, ipv6_subnet={}, spine_bp_addr={}".format(
        ipv4_subnet, ipv6_subnet, spine_bp_addr))
    return ipv4_subnet, ipv6_subnet, spine_bp_addr


def add_route_to_dut_lo(ptfhost, spine_bp_addr, lo_ipv4_addr, lo_ipv6_addr):
    """Add routes on PTF to reach DUT loopback addresses via spine backplane"""
    logger.info("Adding routes on PTF to reach DUT loopback addresses")
    ipv4_nh, ipv6_nh = None, None
    for spine_name, v in spine_bp_addr.items():
        # Add ptf route to dut lo address (IPv4)
        if ipv4_nh is None:
            ptfhost.shell("ip route add {} via {}".format(lo_ipv4_addr, v['ipv4']), module_ignore_errors=True)
            time.sleep(5)
            ipv4_res = ptfhost.shell("ping {} -c 3 -I backplane".format(lo_ipv4_addr), module_ignore_errors=True)
            if ipv4_res['rc'] != 0:
                ptfhost.shell("ip route del {} via {}".format(lo_ipv4_addr, v['ipv4']), module_ignore_errors=True)
            else:
                ipv4_nh = v['ipv4']
                logger.info("Added route to DUT loopback IPv4 {} via {}".format(lo_ipv4_addr, ipv4_nh))

        # Add ptf route to dut lo address (IPv6)
        if ipv6_nh is None:
            ptfhost.shell("ip route add {} via {}".format(lo_ipv6_addr, v['ipv6']), module_ignore_errors=True)
            time.sleep(5)
            ipv6_res = ptfhost.shell("ping {} -c 3 -I backplane".format(lo_ipv6_addr), module_ignore_errors=True)
            if ipv6_res['rc'] != 0:
                ptfhost.shell("ip route del {} via {}".format(lo_ipv6_addr, v['ipv6']), module_ignore_errors=True)
            else:
                ipv6_nh = v['ipv6']
                logger.info("Added route to DUT loopback IPv6 {} via {}".format(lo_ipv6_addr, ipv6_nh))

    return ipv4_nh, ipv6_nh


def is_bgp_monitor_session_established(duthost, monitor_ips):
    """Check if BGP Monitor sessions are established"""
    bgp_summary = duthost.shell('vtysh -c "show bgp summary json"', module_ignore_errors=True)['stdout']
    if not bgp_summary:
        return False

    bgp_data = json.loads(bgp_summary)

    for ip in monitor_ips:
        # Check both IPv4 and IPv6 BGP instances
        for af in ['ipv4Unicast', 'ipv6Unicast']:
            if af in bgp_data:
                peers = bgp_data[af].get('peers', {})
                if ip in peers:
                    state = peers[ip].get('state', '')
                    if state.lower() == 'established':
                        logger.info("BGP Monitor session established for {}".format(ip))
                        return True
    return False


def setup_bgp_sentinel(duthost, ipv4_subnet, ipv6_subnet, lo_ipv4_addr, lo_ipv6_addr, ptf_bp_v4, ptf_bp_v6):
    """Configure BGP Sentinel on DUT

    Args:
        duthost: DUT host object
        ipv4_subnet: IPv4 subnet for listen range (e.g., "10.10.246.0/24")
        ipv6_subnet: IPv6 subnet for listen range (e.g., "fc0a::/64")
        lo_ipv4_addr: DUT loopback IPv4 address (source address)
        lo_ipv6_addr: DUT loopback IPv6 address (source address)
        ptf_bp_v4: PTF backplane IPv4 address (to be included in listen range)
        ptf_bp_v6: PTF backplane IPv6 address (to be included in listen range)
    """
    logger.info("Applying BGPSentinel configuration (IPv4 + IPv6)")
    # Follow the same behavior with test_bgp_sentinel.py
    sentinel_args = {
        'v4_listen_range': json.dumps([ipv4_subnet, ptf_bp_v4 + '/32']),
        'v6_listen_range': json.dumps([ipv6_subnet, ptf_bp_v6 + '/128']),
        'v4_src_address': lo_ipv4_addr,
        'v6_src_address': lo_ipv6_addr
    }
    sentinel_template = Template(BGP_SENTINEL_TMPL)
    sentinel_config = sentinel_template.render(**sentinel_args)
    duthost.copy(content=sentinel_config, dest=BGPSENTINEL_CONFIG_FILE)
    duthost.shell("sonic-cfggen -j {} -w".format(BGPSENTINEL_CONFIG_FILE))
    time.sleep(5)
    logger.info("BGPSentinel configuration applied")


def setup_bgp_monitor(duthost, ptfhost, ptf_bp_v4, ptf_bp_v6, lo_ipv4_addr, lo_ipv6_addr, dut_asn,
                      enable_v4=True, enable_v6=True):
    """Configure BGP Monitor on DUT and start ExaBGP on PTF"""
    bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
    monitor_ips = []

    if enable_v4:
        logger.info("Applying BGPMonV4 configuration")
        bgpmon_v4_args = {
            'db_table_name': 'BGP_MONITORS',
            'peer_addr': ptf_bp_v4,
            'asn': dut_asn,
            'local_addr': lo_ipv4_addr,
            'peer_name': BGP_MONITOR_NAME + '_V4'
        }
        bgpmon_v4_config = bgpmon_template.render(**bgpmon_v4_args)
        bgpmon_v4_file = '/tmp/bgpmon_v4.json'
        duthost.copy(content=bgpmon_v4_config, dest=bgpmon_v4_file)
        duthost.shell("sonic-cfggen -j {} -w".format(bgpmon_v4_file))
        monitor_ips.append(ptf_bp_v4)
        time.sleep(5)
        logger.info("BGPMonV4 configuration applied")

    if enable_v6:
        logger.info("Applying BGPMonV6 configuration")
        bgpmon_v6_args = {
            'db_table_name': 'BGP_MONITORS',
            'peer_addr': ptf_bp_v6,
            'asn': dut_asn,
            'local_addr': lo_ipv6_addr,
            'peer_name': BGP_MONITOR_NAME + '_V6'
        }
        bgpmon_v6_config = bgpmon_template.render(**bgpmon_v6_args)
        bgpmon_v6_file = '/tmp/bgpmon_v6.json'
        duthost.copy(content=bgpmon_v6_config, dest=bgpmon_v6_file)
        duthost.shell("sonic-cfggen -j {} -w".format(bgpmon_v6_file))
        monitor_ips.append(ptf_bp_v6)
        time.sleep(5)
        logger.info("BGPMonV6 configuration applied")

    return monitor_ips


def start_exabgp_monitors(ptfhost, ptf_bp_v4, ptf_bp_v6, lo_ipv4_addr, lo_ipv6_addr, dut_asn,
                          enable_v4=True, enable_v6=True):
    """Start ExaBGP processes on PTF for BGP Monitor sessions"""
    logger.info("Starting ExaBGP peers for BGP Monitor on PTF")

    if enable_v4:
        ptfhost.exabgp(name=BGP_MONITOR_NAME + '_V4',
                       state="started",
                       local_ip=ptf_bp_v4,
                       router_id=ptf_bp_v4,
                       peer_ip=lo_ipv4_addr,
                       local_asn=dut_asn,
                       peer_asn=dut_asn,
                       port=BGP_MONITOR_PORT)
        if not wait_tcp_connection(ptfhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60):
            raise RuntimeError("Failed to start BGP Monitor V4 on port {}".format(BGP_MONITOR_PORT))
        logger.info("ExaBGP V4 process started on port {}".format(BGP_MONITOR_PORT))

    if enable_v6:
        ptfhost.exabgp(name=BGP_MONITOR_NAME + '_V6',
                       state="started",
                       local_ip=ptf_bp_v6,
                       router_id=ptf_bp_v4,  # Use IPv4 as router-id
                       peer_ip=lo_ipv6_addr,
                       local_asn=dut_asn,
                       peer_asn=dut_asn,
                       port=BGP_MONITOR_PORT + 1)
        if not wait_tcp_connection(ptfhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT + 1, timeout_s=60):
            raise RuntimeError("Failed to start BGP Monitor V6 on port {}".format(BGP_MONITOR_PORT + 1))
        logger.info("ExaBGP V6 process started on port {}".format(BGP_MONITOR_PORT + 1))


def cleanup_bgp_sentinel(duthost):
    """Clean up BGP Sentinel configuration on DUT"""
    logger.info("Cleaning up BGP Sentinel configuration")

    # Remove BGP Sentinel entries from CONFIG_DB
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinel'", asic_index='all')
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinelV6'", asic_index='all')

    # Remove config file
    duthost.file(path=BGPSENTINEL_CONFIG_FILE, state='absent')

    time.sleep(3)
    logger.info("BGP Sentinel cleanup completed")


def cleanup_bgp_monitor(duthost, ptfhost, bgp_monitor_ips=None, bgp_monitor_routes=None, dut_lo_addr=None):
    """Clean up BGP Monitor configuration on DUT and PTF

    Args:
        duthost: DUT host object
        ptfhost: PTF host object
        bgp_monitor_ips: List of monitor IP addresses to remove from CONFIG_DB
        bgp_monitor_routes: Dict with 'ipv4_nh' and 'ipv6_nh' for PTF route cleanup
        dut_lo_addr: Tuple of (lo_ipv4, lo_ipv6) DUT loopback addresses
    """
    logger.info("Cleaning up BGP Monitor configuration")

    # Stop ExaBGP processes on PTF
    ptfhost.exabgp(name=BGP_MONITOR_NAME + '_V4', state="absent")
    ptfhost.exabgp(name=BGP_MONITOR_NAME + '_V6', state="absent")

    # Remove BGP Monitor config files from DUT
    for f in ['/tmp/bgpmon_v4.json', '/tmp/bgpmon_v6.json']:
        duthost.file(path=f, state='absent')

    # Remove BGP Monitor entries from CONFIG_DB
    if bgp_monitor_ips:
        for monitor_ip in bgp_monitor_ips:
            duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(monitor_ip),
                                         asic_index='all')

    # Remove PTF routes to DUT loopback
    if bgp_monitor_routes and dut_lo_addr:
        lo_ipv4, lo_ipv6 = dut_lo_addr
        ipv4_nh = bgp_monitor_routes.get('ipv4_nh')
        ipv6_nh = bgp_monitor_routes.get('ipv6_nh')
        if ipv4_nh and lo_ipv4:
            ptfhost.shell("ip route del {} via {}".format(lo_ipv4, ipv4_nh), module_ignore_errors=True)
        if ipv6_nh and lo_ipv6:
            ptfhost.shell("ip route del {} via {}".format(lo_ipv6, ipv6_nh), module_ignore_errors=True)

    time.sleep(3)
    logger.info("BGP Monitor cleanup completed")


@pytest.fixture(scope='module')
def setup(duthosts, rand_one_dut_hostname, nbrhosts, fanouthosts):
    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    portchannels = config_facts.get('PORTCHANNEL_MEMBER', {})
    dev_nbrs = config_facts.get('DEVICE_NEIGHBOR', {})
    bgp_neighbor = list(bgp_neighbors.keys())[0]

    logger.debug("setup config_facts {}".format(config_facts))
    logger.debug("setup nbrhosts {}".format(nbrhosts))
    logger.debug("setup bgp_neighbors {}".format(bgp_neighbors))
    logger.debug("setup dev_nbrs {}".format(dev_nbrs))
    logger.debug("setup portchannels {}".format(portchannels))
    logger.debug("setup test_neighbor {}".format(bgp_neighbor))

    interface_list = dev_nbrs.keys()
    logger.debug('interface_list: {}'.format(interface_list))

    # verify sessions are established
    pytest_assert(wait_until(30, 5, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                  "Not all BGP sessions are established on DUT")

    ip_intfs = duthost.show_and_parse('show ip interface')
    logger.debug("setup ip_intfs {}".format(ip_intfs))

    # Create a mapping of neighbor IP to interfaces and their details
    neighbor_ip_to_interfaces = {}

    # Loop through the ip_intfs list to populate the mapping
    for ip_intf in ip_intfs:
        neighbor_ip = ip_intf['neighbor ip']
        interface_name = ip_intf['interface']
        if neighbor_ip not in neighbor_ip_to_interfaces:
            neighbor_ip_to_interfaces[neighbor_ip] = {}

        # Check if the interface is in portchannels and get the relevant devices
        if interface_name in portchannels:
            for dev_name in portchannels[interface_name]:
                if dev_name in dev_nbrs and dev_nbrs[dev_name]['name'] == ip_intf['bgp neighbor']:
                    neighbor_ip_to_interfaces[neighbor_ip][dev_name] = dev_nbrs[dev_name]
        # If not in portchannels, check directly in dev_nbrs
        elif interface_name in dev_nbrs and dev_nbrs[interface_name]['name'] == ip_intf['bgp neighbor']:
            neighbor_ip_to_interfaces[neighbor_ip][interface_name] = dev_nbrs[interface_name]

    # Update bgp_neighbors with the new 'interface' key
    for ip, details in bgp_neighbors.items():
        if ip in neighbor_ip_to_interfaces:
            details['interface'] = neighbor_ip_to_interfaces[ip]

    setup_info = {
        'neighhosts': bgp_neighbors,
        "eth_nbrs": dev_nbrs
    }

    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # verify sessions are established after test
    if not duthost.check_bgp_session_state(bgp_neighbors):
        for port in interface_list:
            logger.info("no shutdown dut interface {} port {}".format(duthost, port))
            duthost.no_shutdown(port)

            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
            if fanout and fanout_port:
                logger.info("no shutdown fanout interface, fanout {} port {}".format(fanout, fanout_port))
                fanout.no_shutdown(fanout_port)

            neighbor = dev_nbrs[port]["name"]
            neighbor_port = dev_nbrs[port]["port"]
            neighbor_host = nbrhosts.get(neighbor, {}).get('host', None)
            if neighbor_host:
                neighbor_host.no_shutdown(neighbor_port)
                logger.info("no shutdown neighbor interface, neighbor {} port {}".format(neighbor, neighbor_port))
            else:
                logger.debug("neighbor host not found for {} port {}".format(neighbor, neighbor_port))

            time.sleep(1)

    pytest_assert(wait_until(600, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                  "Not all BGP sessions are established on DUT")


async def flap_dut_interface(duthost, port, sleep_duration, test_run_duration):
    logger.info("flap dut {} interface {} delay time {} timeout {}".format(
        duthost, port, sleep_duration, test_run_duration))
    global dut_flap_count

    start_time = time.time()  # Record the start time
    while not stop_tasks and time.time() - start_time < test_run_duration:
        duthost.shutdown(port)
        await asyncio.sleep(sleep_duration)
        duthost.no_shutdown(port)
        await asyncio.sleep(sleep_duration)
        dut_flap_count += 1
        if stop_tasks:
            logger.info("Stop flap task, breaking dut flap dut {} interface {} flap count  {}".format(
                duthost, port, dut_flap_count))
            break


async def flap_fanout_interface_all(interface_list, fanouthosts, duthost, sleep_duration, test_run_duration):
    global fanout_flap_count
    fanout_interfaces = {}

    for port in interface_list:
        fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
        if fanout and fanout_port:
            if fanout not in fanout_interfaces:
                fanout_interfaces[fanout] = []
            fanout_interfaces[fanout].append(fanout_port)

    logger.info("flap interface fanout port {}".format(fanout_interfaces))

    start_time = time.time()  # Record the start time
    while not stop_tasks and time.time() - start_time < test_run_duration:
        for fanout_host, fanout_ports in fanout_interfaces.items():
            logger.info("flap interface fanout {} port {}".format(fanout_host, fanout_port))
            fanout_host.shutdown_multiple(fanout_ports)
            await asyncio.sleep(sleep_duration)
            fanout_host.no_shutdown_multiple(fanout_ports)
            await asyncio.sleep(sleep_duration)

        fanout_flap_count += 1
        if stop_tasks:
            logger.info("Stop flap task, breaking flap fanout {} dut {} flap count {}".format(
                fanouthosts, duthost, fanout_flap_count))
            break


async def flap_fanout_interface(interface_list, fanouthosts, duthost, sleep_duration, test_run_duration):
    global fanout_flap_count

    start_time = time.time()  # Record the start time
    while not stop_tasks and time.time() - start_time < test_run_duration:
        for port in interface_list:
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname, port)
            if fanout and fanout_port:
                logger.info("flap interface fanout {} port {}".format(fanout, fanout_port))
                fanout.shutdown(fanout_port)
                await asyncio.sleep(sleep_duration)
                fanout.no_shutdown(fanout_port)
                await asyncio.sleep(sleep_duration)
            else:
                logger.warning("fanout not found for {} port {}".format(duthost.hostname, port))

            if stop_tasks:
                break

        fanout_flap_count += 1
        if stop_tasks:
            logger.info("Stop flap task, breaking flap fanout {} dut {} interface {} flap count  {}".format(
                fanouthosts, duthost, port, fanout_flap_count))
            break


async def flap_neighbor_interface(neighbor, neighbor_port, sleep_duration, test_run_duration):
    logger.info("flap neighbor {} interface {}".format(neighbor, neighbor_port))
    global neighbor_flap_count

    start_time = time.time()  # Record the start time
    while not stop_tasks and time.time() - start_time < test_run_duration:
        neighbor.shutdown(neighbor_port)
        await asyncio.sleep(sleep_duration)
        neighbor.no_shutdown(neighbor_port)
        await asyncio.sleep(sleep_duration)
        neighbor_flap_count += 1
        if stop_tasks:
            logger.info("Stop flap task, breaking flap neighbor {} interface {} flap count {}".format(
                neighbor, neighbor_port, neighbor_flap_count))
            break


async def monitor_system_resources(duthost, test_run_duration, interval=60):
    logger.info("Monitoring system resources for {} seconds, interval {} seconds".format(test_run_duration, interval))
    start_time = time.time()

    monitor_count = 0

    while not stop_tasks and time.time() - start_time < test_run_duration:
        logger.info("Memory usage:")
        cmd = "free -m"
        cmd_response = duthost.shell(cmd, module_ignore_errors=True)
        logger.info("loop {} cmd {} rsp {}".format(monitor_count, cmd, cmd_response.get('stdout', None)))
        monitor_count += 1

        await asyncio.sleep(interval)

        if stop_tasks:
            logger.info("Stop monitor task, breaking monitor system resources monitor_count {} ".format(monitor_count))
            break


def _run_stress_link_flap_test(duthost, setup, nbrhosts, fanouthosts, test_type, normalized_level):
    """
    Common function to run stress link flap test.
    This is extracted from test_bgp_stress_link_flap to be reused by other test variants.
    """
    global stop_tasks
    global dut_flap_count
    global fanout_flap_count
    global neighbor_flap_count

    cmd = "vtysh -c \"show running-config\""
    pfcwd_cmd_response = duthost.shell(cmd, module_ignore_errors=True)
    logger.info("Dump the FRR config: cmd: {} response: {}".format(cmd, pfcwd_cmd_response.get('stdout', None)))

    test_run_duration = LOOP_TIMES_LEVEL_MAP[normalized_level]
    logger.debug('normalized_level {}, set test run duration {}'.format(normalized_level, test_run_duration))

    # Skip the test on Virtual Switch due to fanout switch dependency and warm reboot
    asic_type = duthost.facts['asic_type']
    if (asic_type == "vs" or asic_type == "vpp") and (test_type == "fanout" or test_type == "all"):
        pytest.skip("Stress link flap test is not supported on Virtual Switch")

    if asic_type != "vs" and asic_type != "vpp":
        delay_time = SLEEP_DURATION
    else:
        delay_time = SLEEP_DURATION * 100

    eth_nbrs = setup.get('eth_nbrs', {})
    interface_list = eth_nbrs.keys()
    logger.debug('interface_list: {}'.format(interface_list))

    stop_tasks = False
    dut_flap_count = 0
    fanout_flap_count = 0
    neighbor_flap_count = 0

    def check_test_type(match_type):
        return test_type in [match_type, "all"]

    async def flap_interfaces():
        flap_tasks = []
        if check_test_type("dut"):
            for interface in interface_list:
                task = asyncio.create_task(
                    flap_dut_interface(duthost, interface, delay_time, test_run_duration))
                logger.info("Start flap dut {} interface {}".format(duthost, interface))
                flap_tasks.append(task)

        if check_test_type("neighbor"):
            for interface in interface_list:
                neighbor_name = eth_nbrs[interface]["name"]
                neighbor_port = eth_nbrs[interface]["port"]
                neighbor_host = nbrhosts.get(neighbor_name, {}).get('host', None)
                if neighbor_host:
                    task = asyncio.create_task(
                        flap_neighbor_interface(neighbor_host, neighbor_port, delay_time, test_run_duration))
                    logger.info("Start flap neighbor {} port {}".format(neighbor_host, neighbor_port))
                    flap_tasks.append(task)
                else:
                    logger.debug("neighbor host not found for {} port {}".format(neighbor_name, neighbor_port))

        if check_test_type("fanout"):
            task = asyncio.create_task(
                flap_fanout_interface(interface_list, fanouthosts, duthost, delay_time, test_run_duration))
            logger.info("Start flap fanout {} dut {} ".format(fanouthosts, duthost))
            flap_tasks.append(task)

        if normalized_level == 'thorough':
            task = asyncio.create_task(
                monitor_system_resources(duthost, test_run_duration, interval=1800))
            logger.info("Start monitor system resources {}".format(duthost))
            flap_tasks.append(task)

        logger.info("flap_tasks {} ".format(flap_tasks))
        start_time = time.time()

        await asyncio.sleep(test_run_duration)

        global stop_tasks
        stop_tasks = True
        logger.info("stop_tasks {} ".format(flap_tasks))

        await asyncio.gather(*flap_tasks)

        logger.info("Test running for {} seconds".format(time.time() - start_time))
        logger.info("Test run duration dut_flap_count {} fanout_flap_count {} neighbor_flap_count {}".format(
            dut_flap_count, fanout_flap_count, neighbor_flap_count))

        # Clean up the task list after joining all tasks
        logger.info("clear tasks {} ".format(flap_tasks))
        flap_tasks.clear()

    asyncio.run(flap_interfaces())

    if asic_type == "vpp":
        sleep_time = 180
    else:
        sleep_time = 60
    logger.info("Test Completed, waiting for {} seconds to stabilize the system".format(sleep_time))
    time.sleep(sleep_time)


@pytest.mark.parametrize("test_type", ["dut", "fanout", "neighbor", "all"])
def test_bgp_stress_link_flap(duthosts, rand_one_dut_hostname, setup, nbrhosts, fanouthosts, test_type,
                              get_function_completeness_level):
    """
    Test BGP stress link flap without any additional features (Sentinel/Monitor).
    This is the basic stress test that flaps interfaces on DUT, fanout, or neighbor.
    """
    duthost = duthosts[rand_one_dut_hostname]

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'

    _run_stress_link_flap_test(duthost, setup, nbrhosts, fanouthosts, test_type, normalized_level)


@pytest.mark.parametrize("test_type", ["dut"])
def test_bgp_stress_link_flap_with_sentinel(duthosts, rand_one_dut_hostname, setup, nbrhosts, fanouthosts,
                                            ptfhost, tbinfo, test_type, get_function_completeness_level):
    """
    Test BGP stress link flap with BGP Sentinel enabled.
    BGP Sentinel is a dynamic BGP peering feature that allows passive BGP sessions.
    """
    duthost = duthosts[rand_one_dut_hostname]

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'

    # Get required topology information with safe key access
    try:
        common_config = tbinfo['topo']['properties']['configuration_properties']['common']
        ptf_bp_v4 = common_config.get('nhipv4', '')
        ptf_bp_v6 = common_config.get('nhipv6', '').lower()
    except KeyError as e:
        pytest.skip("BGP Sentinel test requires topology configuration_properties: missing {}".format(e))

    if not ptf_bp_v4 or not ptf_bp_v6:
        pytest.skip("BGP Sentinel test requires PTF backplane addresses (nhipv4/nhipv6)")

    ipv4_subnet, ipv6_subnet, spine_bp_addr = get_dut_listen_range(tbinfo)

    if not ipv4_subnet or not ipv6_subnet:
        pytest.skip("BGP Sentinel test requires spine topology with backplane interfaces")

    # Get DUT loopback addresses
    lo_facts = duthost.setup()['ansible_facts']['ansible_Loopback0']
    lo_ipv4_addr = lo_facts['ipv4']['address']
    lo_ipv6_addr = None
    for item in lo_facts['ipv6']:
        if not item['address'].startswith('fe80'):
            lo_ipv6_addr = item['address']
            break

    if not lo_ipv4_addr or not lo_ipv6_addr:
        pytest.skip("BGP Sentinel test requires DUT loopback addresses")

    try:
        # Setup BGP Sentinel
        setup_bgp_sentinel(duthost, ipv4_subnet, ipv6_subnet, lo_ipv4_addr, lo_ipv6_addr, ptf_bp_v4, ptf_bp_v6)

        # Run the stress link flap test
        _run_stress_link_flap_test(duthost, setup, nbrhosts, fanouthosts, test_type, normalized_level)

        # Verify BGP sessions are still established after test
        bgp_neighbors = setup.get('neighhosts', {})
        pytest_assert(wait_until(600, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                      "Not all BGP sessions are established on DUT after test")

    finally:
        # Cleanup BGP Sentinel configuration
        cleanup_bgp_sentinel(duthost)


@pytest.mark.parametrize("test_type", ["dut"])
def test_bgp_stress_link_flap_with_monitor(duthosts, rand_one_dut_hostname, setup, nbrhosts, fanouthosts,
                                           ptfhost, tbinfo, test_type, get_function_completeness_level):
    """
    Test BGP stress link flap with BGP Monitor enabled.
    BGP Monitor sessions allow external systems to receive BGP routing updates.
    """
    duthost = duthosts[rand_one_dut_hostname]

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'

    # Get required topology information with safe key access
    try:
        common_config = tbinfo['topo']['properties']['configuration_properties']['common']
        dut_asn = common_config.get('dut_asn')
        ptf_bp_v4 = common_config.get('nhipv4', '')
        ptf_bp_v6 = common_config.get('nhipv6', '').lower()
    except KeyError as e:
        pytest.skip("BGP Monitor test requires topology configuration_properties: missing {}".format(e))

    if not dut_asn or not ptf_bp_v4 or not ptf_bp_v6:
        pytest.skip("BGP Monitor test requires dut_asn and PTF backplane addresses (nhipv4/nhipv6)")

    _, _, spine_bp_addr = get_dut_listen_range(tbinfo)

    if not spine_bp_addr:
        pytest.skip("BGP Monitor test requires spine topology with backplane interfaces")

    # Get DUT loopback addresses
    lo_facts = duthost.setup()['ansible_facts']['ansible_Loopback0']
    lo_ipv4_addr = lo_facts['ipv4']['address']
    lo_ipv6_addr = None
    for item in lo_facts['ipv6']:
        if not item['address'].startswith('fe80'):
            lo_ipv6_addr = item['address']
            break

    if not lo_ipv4_addr or not lo_ipv6_addr:
        pytest.skip("BGP Monitor test requires DUT loopback addresses")

    bgp_monitor_ips = []
    bgp_monitor_routes = {}
    dut_lo_addr = (lo_ipv4_addr, lo_ipv6_addr)

    try:
        # Add routes on PTF to reach DUT loopback addresses
        ipv4_nh, ipv6_nh = add_route_to_dut_lo(ptfhost, spine_bp_addr, lo_ipv4_addr, lo_ipv6_addr)
        bgp_monitor_routes = {'ipv4_nh': ipv4_nh, 'ipv6_nh': ipv6_nh}

        # Setup BGP Monitor
        bgp_monitor_ips = setup_bgp_monitor(duthost, ptfhost, ptf_bp_v4, ptf_bp_v6,
                                            lo_ipv4_addr, lo_ipv6_addr, dut_asn)

        # Start ExaBGP processes on PTF
        start_exabgp_monitors(ptfhost, ptf_bp_v4, ptf_bp_v6, lo_ipv4_addr, lo_ipv6_addr, dut_asn)

        # Wait for BGP Monitor sessions to establish
        logger.info("Waiting for BGP Monitor sessions to establish...")
        if wait_until(60, 5, 0, is_bgp_monitor_session_established, duthost, bgp_monitor_ips):
            logger.info("BGP Monitor sessions established successfully")
        else:
            logger.warning("BGP Monitor sessions did not establish within timeout")

        # Run the stress link flap test
        _run_stress_link_flap_test(duthost, setup, nbrhosts, fanouthosts, test_type, normalized_level)

        # Verify BGP sessions are still established after test
        bgp_neighbors = setup.get('neighhosts', {})
        pytest_assert(wait_until(600, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                      "Not all BGP sessions are established on DUT after test")

        # Verify BGP Monitor sessions are still established
        if is_bgp_monitor_session_established(duthost, bgp_monitor_ips):
            logger.info("BGP Monitor sessions remain established after stress test")
        else:
            logger.warning("BGP Monitor sessions not established after stress test")

    finally:
        # Cleanup BGP Monitor configuration
        cleanup_bgp_monitor(duthost, ptfhost, bgp_monitor_ips=bgp_monitor_ips,
                            bgp_monitor_routes=bgp_monitor_routes, dut_lo_addr=dut_lo_addr)


@pytest.mark.parametrize("test_type", ["dut"])
def test_bgp_stress_link_flap_with_sentinel_and_monitor(duthosts, rand_one_dut_hostname, setup, nbrhosts,
                                                        fanouthosts, ptfhost, tbinfo, test_type,
                                                        get_function_completeness_level):
    """
    Test BGP stress link flap with both BGP Sentinel and BGP Monitor enabled.
    This test verifies that both features work together under stress conditions.
    """
    duthost = duthosts[rand_one_dut_hostname]

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'

    # Get required topology information with safe key access
    try:
        common_config = tbinfo['topo']['properties']['configuration_properties']['common']
        dut_asn = common_config.get('dut_asn')
        ptf_bp_v4 = common_config.get('nhipv4', '')
        ptf_bp_v6 = common_config.get('nhipv6', '').lower()
    except KeyError as e:
        pytest.skip("BGP Sentinel and Monitor test requires topology configuration_properties: missing {}".format(e))

    if not dut_asn or not ptf_bp_v4 or not ptf_bp_v6:
        pytest.skip("BGP Sentinel and Monitor test requires dut_asn and PTF backplane addresses (nhipv4/nhipv6)")

    ipv4_subnet, ipv6_subnet, spine_bp_addr = get_dut_listen_range(tbinfo)

    if not ipv4_subnet or not ipv6_subnet or not spine_bp_addr:
        pytest.skip("BGP Sentinel and Monitor test requires spine topology with backplane interfaces")

    # Get DUT loopback addresses
    lo_facts = duthost.setup()['ansible_facts']['ansible_Loopback0']
    lo_ipv4_addr = lo_facts['ipv4']['address']
    lo_ipv6_addr = None
    for item in lo_facts['ipv6']:
        if not item['address'].startswith('fe80'):
            lo_ipv6_addr = item['address']
            break

    if not lo_ipv4_addr or not lo_ipv6_addr:
        pytest.skip("BGP Sentinel and Monitor test requires DUT loopback addresses")

    bgp_monitor_ips = []
    bgp_monitor_routes = {}
    dut_lo_addr = (lo_ipv4_addr, lo_ipv6_addr)

    try:
        # Setup BGP Sentinel
        setup_bgp_sentinel(duthost, ipv4_subnet, ipv6_subnet, lo_ipv4_addr, lo_ipv6_addr, ptf_bp_v4, ptf_bp_v6)

        # Add routes on PTF to reach DUT loopback addresses
        ipv4_nh, ipv6_nh = add_route_to_dut_lo(ptfhost, spine_bp_addr, lo_ipv4_addr, lo_ipv6_addr)
        bgp_monitor_routes = {'ipv4_nh': ipv4_nh, 'ipv6_nh': ipv6_nh}

        # Setup BGP Monitor
        bgp_monitor_ips = setup_bgp_monitor(duthost, ptfhost, ptf_bp_v4, ptf_bp_v6,
                                            lo_ipv4_addr, lo_ipv6_addr, dut_asn)

        # Start ExaBGP processes on PTF
        start_exabgp_monitors(ptfhost, ptf_bp_v4, ptf_bp_v6, lo_ipv4_addr, lo_ipv6_addr, dut_asn)

        # Wait for BGP Monitor sessions to establish
        logger.info("Waiting for BGP Monitor sessions to establish...")
        if wait_until(60, 5, 0, is_bgp_monitor_session_established, duthost, bgp_monitor_ips):
            logger.info("BGP Monitor sessions established successfully")
        else:
            logger.warning("BGP Monitor sessions did not establish within timeout")

        # Run the stress link flap test
        _run_stress_link_flap_test(duthost, setup, nbrhosts, fanouthosts, test_type, normalized_level)

        # Verify BGP sessions are still established after test
        bgp_neighbors = setup.get('neighhosts', {})
        pytest_assert(wait_until(600, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                      "Not all BGP sessions are established on DUT after test")

        # Verify BGP Monitor sessions are still established
        if is_bgp_monitor_session_established(duthost, bgp_monitor_ips):
            logger.info("BGP Monitor sessions remain established after stress test")
        else:
            logger.warning("BGP Monitor sessions not established after stress test")

    finally:
        # Cleanup both BGP Sentinel and Monitor configurations
        cleanup_bgp_sentinel(duthost)
        cleanup_bgp_monitor(duthost, ptfhost, bgp_monitor_ips=bgp_monitor_ips,
                            bgp_monitor_routes=bgp_monitor_routes, dut_lo_addr=dut_lo_addr)
