import asyncio
import logging
import pytest
import time
import json
from jinja2 import Template
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, get_upstream_neigh_type
from bgp_helpers import BGPMON_TEMPLATE_FILE, BGPMON_CONFIG_FILE, BGP_MONITOR_NAME
from bgp_helpers import BGPSENTINEL_CONFIG_FILE

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


def get_dut_listen_range(tbinfo):
    """Get the DUT listen range for BGP configuration"""
    import ipaddress
    ipv4_subnet, ipv6_subnet = None, None
    spine_bp_addr = {}
    upstream_nbr_type = get_upstream_neigh_type(tbinfo, is_upper=True)
    for k, v in tbinfo['topo']['properties']['configuration'].items():
        if ((upstream_nbr_type == 'T0' and 'tor' in v['properties']) or
                (upstream_nbr_type == 'T2' and 'spine' in v['properties'])):
            ipv4_addr = ipaddress.ip_interface(v['bp_interface']['ipv4'].encode().decode())
            ipv6_addr = ipaddress.ip_interface(v['bp_interface']['ipv6'].encode().decode())
            ipv4_subnet = str(ipv4_addr.network)
            ipv6_subnet = str(ipv6_addr.network)
            spine_bp_addr[k] = {'ipv4': str(ipv4_addr.ip), 'ipv6': str(ipv6_addr.ip)}
    return ipv4_subnet, ipv6_subnet, spine_bp_addr


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

    # verify sessions are established
    wait_until(120, 5, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys()))

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


@pytest.mark.parametrize("test_type", ["dut", "fanout", "neighbor", "all"])
def test_bgp_stress_link_flap(duthosts, rand_one_dut_hostname, setup, nbrhosts, fanouthosts, test_type,
                              get_function_completeness_level, tbinfo):
    global stop_tasks
    global dut_flap_count
    global fanout_flap_count
    global neighbor_flap_count

    duthost = duthosts[rand_one_dut_hostname]

    # Get DUT ASN and PTF backplane addresses
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    ptf_bp_v4 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4']
    ptf_bp_v6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6'].lower()
    ipv4_subnet, ipv6_subnet, spine_bp_addr = get_dut_listen_range(tbinfo)

    logger.info("Applying BGPSentinel configuration (IPv4 + IPv6)")
    sentinel_args = {
        'v4_listen_range': json.dumps([ipv4_subnet]),
        'v6_listen_range': json.dumps([ipv6_subnet]),
        'v4_src_address': list(spine_bp_addr.values())[0]['ipv4'],
        'v6_src_address': list(spine_bp_addr.values())[0]['ipv6']
    }
    sentinel_template = Template(BGP_SENTINEL_TMPL)
    sentinel_config = sentinel_template.render(**sentinel_args)
    duthost.copy(content=sentinel_config, dest=BGPSENTINEL_CONFIG_FILE)
    duthost.shell("sonic-cfggen -j {} -w".format(BGPSENTINEL_CONFIG_FILE))
    time.sleep(5)
    logger.info("BGPSentinel configuration applied")

    logger.info("Applying BGPMonV4 configuration")
    bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
    bgpmon_v4_args = {
        'db_table_name': 'BGP_MONITORS',
        'peer_addr': ptf_bp_v4,
        'asn': dut_asn,
        'local_addr': list(spine_bp_addr.values())[0]['ipv4'],
        'peer_name': BGP_MONITOR_NAME + '_V4'
    }
    bgpmon_v4_config = bgpmon_template.render(**bgpmon_v4_args)
    bgpmon_v4_file = '/tmp/bgpmon_v4.json'
    duthost.copy(content=bgpmon_v4_config, dest=bgpmon_v4_file)
    duthost.shell("sonic-cfggen -j {} -w".format(bgpmon_v4_file))
    time.sleep(5)
    logger.info("BGPMonV4 configuration applied")

    logger.info("Applying BGPMonV6 configuration")
    bgpmon_v6_args = {
        'db_table_name': 'BGP_MONITORS',
        'peer_addr': ptf_bp_v6,
        'asn': dut_asn,
        'local_addr': list(spine_bp_addr.values())[0]['ipv6'],
        'peer_name': BGP_MONITOR_NAME + '_V6'
    }
    bgpmon_v6_config = bgpmon_template.render(**bgpmon_v6_args)
    bgpmon_v6_file = '/tmp/bgpmon_v6.json'
    duthost.copy(content=bgpmon_v6_config, dest=bgpmon_v6_file)
    duthost.shell("sonic-cfggen -j {} -w".format(bgpmon_v6_file))
    time.sleep(5)
    logger.info("BGPMonV6 configuration applied")

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'
    TEST_RUN_DURATION = LOOP_TIMES_LEVEL_MAP[normalized_level]
    logger.debug('normalized_level {}, set test run duration {}'.format(normalized_level, TEST_RUN_DURATION))

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
                    flap_dut_interface(duthost, interface, delay_time, TEST_RUN_DURATION))
                logger.info("Start flap dut {} interface {}".format(duthost, interface))
                flap_tasks.append(task)

        if check_test_type("neighbor"):
            for interface in interface_list:
                neighbor_name = eth_nbrs[interface]["name"]
                neighbor_port = eth_nbrs[interface]["port"]
                neighbor_host = nbrhosts.get(neighbor_name, {}).get('host', None)
                if neighbor_host:
                    task = asyncio.create_task(
                        flap_neighbor_interface(neighbor_host, neighbor_port, delay_time, TEST_RUN_DURATION))
                    logger.info("Start flap neighbor {} port {}".format(neighbor_host, neighbor_port))
                    flap_tasks.append(task)
                else:
                    logger.debug("neighbor host not found for {} port {}".format(neighbor_name, neighbor_port))

        if check_test_type("fanout"):
            task = asyncio.create_task(
                flap_fanout_interface(interface_list, fanouthosts, duthost, delay_time, TEST_RUN_DURATION))
            logger.info("Start flap fanout {} dut {} ".format(fanouthosts, duthost))
            flap_tasks.append(task)

        if normalized_level == 'thorough':
            task = asyncio.create_task(
                monitor_system_resources(duthost, TEST_RUN_DURATION, interval=1800))
            logger.info("Start monitor system resources {}".format(duthost))
            flap_tasks.append(task)

        logger.info("flap_tasks {} ".format(flap_tasks))
        start_time = time.time()

        await asyncio.sleep(TEST_RUN_DURATION)

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

    # Cleanup BGP configurations
    logger.info("Cleaning up BGPSentinel and BGPMonitor configurations")
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinel'", asic_index='all')
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinelV6'", asic_index='all')
    duthost.file(path=BGPSENTINEL_CONFIG_FILE, state='absent')

    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(ptf_bp_v4), asic_index='all')
    duthost.file(path='/tmp/bgpmon_v4.json', state='absent')

    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(ptf_bp_v6), asic_index='all')
    duthost.file(path='/tmp/bgpmon_v6.json', state='absent')

    time.sleep(5)
    logger.info("BGP configurations cleanup completed")

    return
