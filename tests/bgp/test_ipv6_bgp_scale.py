'''
Test plan PR: https://github.com/sonic-net/sonic-mgmt/pull/15702
'''

import datetime
import pytest
import logging
import json
import gzip
import base64
import ipaddress
import random
import time
from copy import deepcopy
from threading import Thread, Event
from tests.common.helpers.assertions import pytest_assert
import ptf.packet as scapy
from ptf.testutils import simple_icmpv6_packet
from ptf.mask import Mask

pytestmark = [
    pytest.mark.topology(
        't0-isolated-d2u254s1', 't0-isolated-d2u254s2', 't0-isolated-d2u510', 't0-isolated-d2u510s2',
        't1-isolated-d254u2s1', 't1-isolated-d254u2s2', 't1-isolated-d510u2',
        't1-isolated-d254u2', 't1-isolated-d510u2s2'
    )
]

logger = logging.getLogger(__name__)


ACTION_ANNOUNCE = 'announce'
ACTION_WITHDRAW = 'withdraw'
DUT_PORT = "dut_port"
PTF_PORT = "ptf_port"
IPV6_KEY = "ipv6"
MAX_BGP_SESSIONS_DOWN_COUNT = 0
MAX_DOWNTIME = 10  # seconds
MAX_DOWNTIME_ONE_PORT_FLAPPING = 30  # seconds
MAX_DOWNTIME_UNISOLATION = 300  # seconds
MAX_DOWNTIME_NEXTHOP_GROUP_MEMBER_CHANGE = 30  # seconds
PKTS_SENDING_TIME_SLOT = 1  # seconds
MAX_CONVERGENCE_WAIT_TIME = 300  # seconds
PACKETS_PER_TIME_SLOT = 500 // PKTS_SENDING_TIME_SLOT
MASK_COUNTER_WAIT_TIME = 10  # wait some seconds for mask counters processing packets
STATIC_ROUTES = ['0.0.0.0/0', '::/0']
WITHDRAW_ROUTE_NUMBER = 1
PACKET_QUEUE_LENGTH = 1000000
global_icmp_type = 123


def setup_packet_mask_counters(ptf_dataplane, icmp_type):
    """
    Create a mask counters for packet sending
    """
    exp_pkt = simple_icmpv6_packet(
        icmp_type=icmp_type
    )
    masked_exp_pkt = Mask(exp_pkt)
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, 'src')
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, 'dst')
    masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "src")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "dst")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMPv6Unknown, "cksum")
    ptf_dataplane.create_mask_counters(masked_exp_pkt)

    return masked_exp_pkt


@pytest.fixture(scope="function")
def bgp_peers_info(tbinfo, duthost):
    bgp_info = {}
    topo_name = tbinfo['topo']['name']

    while True:
        down_neighbors = get_down_bgp_sessions_neighbors(duthost)
        if len(down_neighbors) <= MAX_BGP_SESSIONS_DOWN_COUNT:
            if down_neighbors:
                logging.warning("There are down_neighbors %s", down_neighbors)
            break

    alias = duthost.show_and_parse("show interfaces alias")
    for hostname in tbinfo['topo']['properties']['configuration'].keys():
        if ('t0' in topo_name and 'T1' not in hostname) \
            or ('t1' in topo_name and 'T0' not in hostname) \
                or (hostname in down_neighbors):
            continue
        bgp_info[hostname] = {}
        ptf_port = tbinfo['topo']['properties']['topology']['VMs'][hostname]['vlans'][0]
        bgp_info[hostname][PTF_PORT] = ptf_port
        bgp_info[hostname][DUT_PORT] = alias[ptf_port]['name']

        topo_cfg_intfs = tbinfo['topo']['properties']['configuration'][hostname]['interfaces']
        if 'Loopback0' in topo_cfg_intfs and 'ipv6' in topo_cfg_intfs['Loopback0']:
            bgp_info[hostname]['lo_v6'] = topo_cfg_intfs['Loopback0']['ipv6']
        if 'ipv6' in topo_cfg_intfs['Ethernet1']:
            bgp_info[hostname][IPV6_KEY] = \
                topo_cfg_intfs['Ethernet1']['ipv6'].split('/')[0]
        elif 'lacp' in topo_cfg_intfs['Ethernet1']:
            pc_name = 'Port-Channel' + \
                str(topo_cfg_intfs['Ethernet1']['lacp'])
            bgp_info[hostname][IPV6_KEY] = \
                topo_cfg_intfs[pc_name]['ipv6'].split('/')[0]

    logging.info("BGP peers info: %s", bgp_info)
    return bgp_info


def get_down_bgp_sessions_neighbors(duthost):
    return duthost.shell("show ipv6 bgp sum | grep ARISTA | awk '$10 !~ /^[0-9]+$/ {print $NF}'")['stdout_lines']


@pytest.fixture(scope="function")
def announce_bgp_routes_teardown(localhost, tbinfo, ptfhosts):
    servers_dut_interfaces = {}
    # If servers in tbinfo, means tb was deployed with multi servers
    if 'servers' in tbinfo:
        servers_dut_interfaces = {value['ptf_ip'].split("/")[0]: value['dut_interfaces']
                                  for value in tbinfo['servers'].values()}
    yield servers_dut_interfaces
    for ptfhost in ptfhosts:
        ptf_ip = ptfhost.mgmt_ip
        announce_routes(localhost, tbinfo, ptf_ip, servers_dut_interfaces.get(ptf_ip, ''))


def announce_routes(localhost, tbinfo, ptf_ip, dut_interfaces):
    topo_name = tbinfo['topo']['name']
    localhost.announce_routes(
        topo_name=topo_name,
        ptf_ip=ptf_ip,
        action=ACTION_ANNOUNCE,
        path="../ansible/",
        log_path="/tmp",
        dut_interfaces=dut_interfaces,
        upstream_neighbor_groups=tbinfo['upstream_neighbor_groups'] if 'upstream_neighbor_groups' in tbinfo else 0,
        downstream_neighbor_groups=tbinfo['downstream_neighbor_groups'] if 'downstream_neighbor_groups' in tbinfo else 0
    )


def get_all_bgp_ipv6_routes(duthost):
    logger.info("Getting ipv6 routes")
    return json.loads(
        duthost.shell("docker exec bgp vtysh -c 'show ipv6 route bgp json'")['stdout']
    )


def generate_packets(prefixes, dut_mac, src_mac):
    pkts = []
    for prefix in prefixes:
        network = ipaddress.ip_network(prefix)
        addr = str(network[0] if network.num_addresses == 1 else network[1])
        pkt = simple_icmpv6_packet(
            eth_dst=dut_mac,
            eth_src=src_mac,
            ipv6_dst=addr,
            icmp_type=global_icmp_type
        )
        pkts.append(bytes(pkt))

    return pkts


def change_routes_on_peers(localhost, ptf_ip, topo_name, peers_routes_to_change, action, dut_interfaces):
    localhost.announce_routes(
        topo_name=topo_name,
        adhoc=True,
        ptf_ip=ptf_ip,
        action=action,
        peers_routes_to_change=peers_routes_to_change,
        path="../ansible/",
        log_path="/tmp",
        dut_interfaces=dut_interfaces
    )


def remove_nexthops_in_routes(routes, nexthops):
    ret_routes = deepcopy(routes)
    prefixes_to_remove = []
    for prefix, attr in ret_routes.items():
        _nhs = [nh for nh in attr[0]['nexthops'] if nh['ip'] not in nexthops]
        if len(_nhs) == 0:
            prefixes_to_remove.append(prefix)
        else:
            attr[0]['nexthops'] = _nhs
    for prefix in prefixes_to_remove:
        ret_routes[prefix] = []
    return ret_routes


def compare_routes(running_routes, expected_routes):
    logger.info(f"compare_routes called at {datetime.datetime.now()}")
    is_same = True
    diff_cnt = 0
    missing_prefixes = []
    nh_diff_prefixes = []

    expected_set = set(expected_routes.keys())
    running_set = set(running_routes.keys())
    missing = expected_set - running_set
    extra = running_set - expected_set

    # Count missing_prefixes and nh_diff_prefixes
    for prefix, attr in expected_routes.items():
        if prefix not in running_routes:
            is_same = False
            diff_cnt += 1
            missing_prefixes.append(prefix)
            continue
        except_nhs = [nh['ip'] for nh in attr[0]['nexthops']]
        running_nhs = [nh['ip'] for nh in running_routes[prefix][0]['nexthops'] if "active" in nh and nh["active"]]
        if except_nhs != running_nhs:
            is_same = False
            diff_cnt += 1
            nh_diff_prefixes.append((prefix, except_nhs, running_nhs))

    if len(expected_routes) != len(running_routes):
        is_same = False
        logger.info("Count unmatch, expected_routes count=%d,  running_routes count=%d",
                    len(expected_routes), len(running_routes))
        if missing:
            logger.info("Missing prefixes in running_routes: %s", list(missing))
        if extra:
            logger.info("Extra prefixes in running_routes: %s", list(extra))

    if missing_prefixes:
        logger.info("Prefixes missing in running_routes: %s", missing_prefixes)
    if nh_diff_prefixes:
        for prefix, expected, running in nh_diff_prefixes:
            logger.info("Prefix %s nexthops not match, expected: %s, running: %s", prefix, expected, running)

    logger.info("%d of %d routes are different", diff_cnt, len(expected_routes))
    return is_same


def calculate_downtime(ptf_dp, end_time, start_time, masked_exp_pkt):
    logger.warning("Waiting %d seconds for mask counters to be updated", MASK_COUNTER_WAIT_TIME)
    time.sleep(MASK_COUNTER_WAIT_TIME)
    rx_total = sum(list(ptf_dp.mask_rx_cnt[masked_exp_pkt].values())[:-1])  # Exclude the backplane
    tx_total = sum(ptf_dp.mask_tx_cnt[masked_exp_pkt].values())
    if tx_total == 0:
        logger.warning("No packets are sent")
    missing_pkt_cnt = tx_total - rx_total
    if missing_pkt_cnt < 0:
        logger.warning("There are packets noise on ptf dataplane")
    pps = tx_total / (end_time - start_time).total_seconds()
    downtime = missing_pkt_cnt / pps if pps > 0 else 10000000
    logger.info(
        "traffic thread duration: %s seconds,\n rx_counters: %s,\n tx_counters: %s,\n" +
        "Total packets received: %d,\n Total packets sent: %d,\n Missing packets: %d\n" +
        "Estimated pps %s, downtime is %s",
        (end_time - start_time).total_seconds(),
        ptf_dp.mask_rx_cnt[masked_exp_pkt],
        ptf_dp.mask_tx_cnt[masked_exp_pkt],
        rx_total,
        tx_total,
        missing_pkt_cnt,
        pps,
        downtime
    )
    return downtime


def validate_rx_tx_counters(ptf_dp, end_time, start_time, masked_exp_pkt, downtime_threshold=MAX_DOWNTIME):
    downtime = calculate_downtime(ptf_dp, end_time, start_time, masked_exp_pkt)
    pytest_assert(downtime < downtime_threshold, "Downtime is too long")


def flush_counters(ptf_dp, masked_exp_pkt):
    logging.info("Flushing counters")
    for idx in ptf_dp.mask_rx_cnt[masked_exp_pkt].keys():
        ptf_dp.mask_rx_cnt[masked_exp_pkt][idx] = 0
    for idx in ptf_dp.mask_tx_cnt[masked_exp_pkt].keys():
        ptf_dp.mask_tx_cnt[masked_exp_pkt][idx] = 0
    logging.info("after flush rx_counters: %s, tx_counters: %s",
                 ptf_dp.mask_rx_cnt[masked_exp_pkt], ptf_dp.mask_tx_cnt[masked_exp_pkt])


def send_packets(
    terminated,
    ptf_dataplane,
    device_num,
    port_num,
    pkts,
    sending_timeslot=PKTS_SENDING_TIME_SLOT,
    pkt_cnt_per_timeslot=PACKETS_PER_TIME_SLOT
):
    last_round_time = datetime.datetime.now()
    pkts_len = len(pkts)
    rounds_per_timeslot = 1 + (pkt_cnt_per_timeslot // pkts_len)
    rounds_cnt = 0
    while True:
        if terminated.is_set():
            logging.info("%d packets are sent", rounds_cnt * pkts_len)
            break
        logging.info("round %d, sending %d packets", rounds_cnt, rounds_cnt * pkts_len)
        for _ in range(rounds_per_timeslot):
            for pkt in pkts:
                ptf_dataplane.send(device_num, port_num, pkt)

        while datetime.datetime.now() - last_round_time < datetime.timedelta(seconds=sending_timeslot):
            time.sleep(sending_timeslot / 10.0)

        last_round_time = datetime.datetime.now()
        rounds_cnt += 1


def get_ecmp_routes(startup_routes, bgp_peers_info):
    p2p_ipv6_nei_map = {
        value[IPV6_KEY]: hostname for hostname, value in bgp_peers_info.items()
    }
    lo_ipv6_set = set([value['lo_v6'] for _, value in bgp_peers_info.items()])
    neighbor_ecmp_routes = {}
    for prefix, value in startup_routes.items():
        # Default route
        if prefix in STATIC_ROUTES:
            continue
        if prefix in lo_ipv6_set:
            continue
        for nexthop in value[0]['nexthops']:
            if nexthop['ip'] not in p2p_ipv6_nei_map:
                continue
            neighbor_ecmp_routes.setdefault(p2p_ipv6_nei_map[nexthop['ip']], set())
            neighbor_ecmp_routes[p2p_ipv6_nei_map[nexthop['ip']]].add(prefix)
    return neighbor_ecmp_routes


def remove_routes_with_nexthops(candidate_routes, nexthop_to_remove, result_routes):
    removed_routes = remove_nexthops_in_routes(candidate_routes, nexthop_to_remove)
    for prefix, value in removed_routes.items():
        if len(value) == 0:
            result_routes.pop(prefix)
        else:
            result_routes[prefix] = value


def check_bgp_routes_converged(duthost, expected_routes, shutdown_ports, timeout=MAX_CONVERGENCE_WAIT_TIME, interval=1,
                               log_path="/tmp", compressed=False, action='no_action'):
    logger.info("Start to check bgp routes converged")
    expected_routes_json = json.dumps(expected_routes, separators=(',', ':'))

    result = duthost.check_bgp_ipv6_routes_converged(
        expected_routes=expected_routes_json,
        shutdown_ports=shutdown_ports,
        timeout=timeout,
        interval=interval,
        log_path=log_path,
        compressed=compressed,
        action=action
    )

    start_time = result.get("start_time")
    end_time = result.get("end_time")

    if result.get("converged"):
        logger.info(f"BGP converged start: {start_time}, end: {end_time}, duration: {end_time - start_time} seconds")
        ret = {
            "converged": result.get("converged"),
            "start_time": start_time,
            "end_time": end_time
        }
        return ret
    else:
        # When routes convergence fail, if the action is shutdown and shutdown_ports is not empty, restore interfaces
        if action == 'shutdown' and shutdown_ports:
            logger.info(f"Recover interfaces {shutdown_ports} after failure")
            duthost.no_shutdown_multiple(shutdown_ports)
        pytest.fail(f"BGP routes are not stable in {timeout} seconds")


def compress_expected_routes(expected_routes):
    json_str = json.dumps(expected_routes)
    compressed = gzip.compress(json_str.encode('utf-8'))
    b64_str = base64.b64encode(compressed).decode('utf-8')
    return b64_str


@pytest.mark.parametrize("flapping_port_count", [1, 10, 20])
def test_sessions_flapping(
    duthost,
    ptfadapter,
    bgp_peers_info,
    flapping_port_count,
    announce_bgp_routes_teardown
):
    '''
    This test is to make sure When BGP sessions are flapping,
    control plane is functional and data plane has no downtime or acceptable downtime.
    Steps:
        Start and keep sending packets with all routes to the random one open port via ptf.
        Shutdown flapping_port_count random port(s) that establishing bgp sessions.
        Wait for routes are stable, check if all nexthops connecting the shut down ports are disappeared in routes.
        Stop packet sending
        Estimate data plane down time by check packet count sent, received and duration.
    Expected result:
        Dataplane downtime is less than MAX_DOWNTIME_ONE_PORT_FLAPPING.
    '''
    global global_icmp_type
    global_icmp_type += 1
    pdp = ptfadapter.dataplane
    pdp.set_qlen(PACKET_QUEUE_LENGTH)
    exp_mask = setup_packet_mask_counters(pdp, global_icmp_type)
    bgp_neighbors = [hostname for hostname in bgp_peers_info.keys()]

    # Select flapping ports randomly
    random.shuffle(bgp_neighbors)
    flapping_neighbors, unflapping_neighbors = bgp_neighbors[:flapping_port_count], bgp_neighbors[flapping_port_count:]
    flapping_ports = [bgp_peers_info[neighbor][DUT_PORT] for neighbor in flapping_neighbors]
    unflapping_ports = [bgp_peers_info[neighbor][DUT_PORT] for neighbor in unflapping_neighbors]
    logger.info("Flapping_port_count is %d, flapping ports: %s and unflapping ports %s",
                flapping_port_count, flapping_ports, unflapping_ports)

    # Select a random unflapping neighbor to send packets
    injection_bgp_neighbor = random.choice(unflapping_neighbors)
    injection_dut_port = bgp_peers_info[injection_bgp_neighbor][DUT_PORT]
    logger.info("Injection BGP neighbor: %s. Injection dut port: %s", injection_bgp_neighbor, injection_dut_port)
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    neighbor_ecmp_routes = get_ecmp_routes(startup_routes, bgp_peers_info)
    pkts = generate_packets(
        neighbor_ecmp_routes[injection_bgp_neighbor],
        duthost.facts['router_mac'],
        pdp.get_mac(pdp.port_to_device(injection_port), injection_port)
    )

    nexthops_to_remove = [b[IPV6_KEY] for b in bgp_peers_info.values() if b[DUT_PORT] in flapping_ports]
    expected_routes = deepcopy(startup_routes)
    remove_routes_with_nexthops(startup_routes, nexthops_to_remove, expected_routes)
    compressed_expected_routes = compress_expected_routes(expected_routes)
    terminated = Event()
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, pdp.port_to_device(injection_port), injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    traffic_thread.start()
    start_time = datetime.datetime.now()

    try:
        result = check_bgp_routes_converged(
            duthost,
            compressed_expected_routes,
            flapping_ports,
            MAX_CONVERGENCE_WAIT_TIME,
            compressed=True,
            action='shutdown'
        )
        terminated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        validate_rx_tx_counters(pdp, end_time, start_time, exp_mask, MAX_DOWNTIME_ONE_PORT_FLAPPING)
        if not result.get("converged"):
            pytest.fail("BGP routes are not stable in long time")
    finally:
        duthost.no_shutdown_multiple(flapping_ports)


def test_nexthop_group_member_scale(
    duthost,
    ptfadapter,
    ptfhosts,
    localhost,
    tbinfo,
    bgp_peers_info,
    announce_bgp_routes_teardown,
    topo_bgp_routes,
    request
):
    '''
    This test is to make sure when routes on BGP peers are flapping,
    control plane is functional and data plane has no downtime or acceptable downtime.
    Steps:
        1. Start and keep sending packets with all routes to the random one open port via ptf.
        2. For all routes, remove one nexthop by withdraw the route from one peer.
        3. Wait for routes are stable.
        4. Stop sending packets and estimate data plane down time.
        5. For all routes, announce the route to the peer.
        6. Wait for routes are stable.
        7. Stop sending packets and estimate data plane down time.
    Expected result:
        Dataplane downtime is less than MAX_DOWNTIME_NEXTHOP_GROUP_MEMBER_CHANGE.
    '''
    servers_dut_interfaces = announce_bgp_routes_teardown
    topo_name = tbinfo['topo']['name']
    global global_icmp_type
    global_icmp_type += 1
    pdp = ptfadapter.dataplane
    pdp.set_qlen(PACKET_QUEUE_LENGTH)
    exp_mask = setup_packet_mask_counters(pdp, global_icmp_type)
    injection_bgp_neighbor = random.choice(list(bgp_peers_info.keys()))
    injection_dut_port = bgp_peers_info[injection_bgp_neighbor][DUT_PORT]
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    neighbor_ecmp_routes = get_ecmp_routes(startup_routes, bgp_peers_info)

    pkts = generate_packets(
        neighbor_ecmp_routes[injection_bgp_neighbor],
        duthost.facts['router_mac'],
        pdp.get_mac(pdp.port_to_device(injection_port), injection_port)
    )
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6']
    peers_routes_to_change = {}
    selected_routes = set()

    max_flap_neighbor_number = request.config.option.max_flap_neighbor_number
    for index, (neighbor_hostname, routes) in enumerate(neighbor_ecmp_routes.items()):
        if max_flap_neighbor_number and index == max_flap_neighbor_number:
            break
        withdraw_number = 0
        for route in routes:
            if route in selected_routes:
                continue
            peers_routes_to_change.setdefault(neighbor_hostname, [])
            peers_routes_to_change[neighbor_hostname].append((route, nhipv6, None))
            selected_routes.add(route)
            withdraw_number += 1
            if withdraw_number == WITHDRAW_ROUTE_NUMBER:
                break
    logger.info("peers_routes_to_change: %s", peers_routes_to_change)
    pytest_assert(max_flap_neighbor_number and len(peers_routes_to_change) == max_flap_neighbor_number or
                  len(peers_routes_to_change) == len(neighbor_ecmp_routes),
                  "Flap neighbor count is not enough: {}".format(len(peers_routes_to_change)))
    # ------------withdraw routes and test ------------ #
    terminated = Event()
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, pdp.port_to_device(injection_port), injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    start_time = datetime.datetime.now()
    traffic_thread.start()
    expected_routes = deepcopy(startup_routes)
    for peer, routes in peers_routes_to_change.items():
        prefixes = [r[0] for r in routes]
        nexthop_to_remove = [b[IPV6_KEY] for n, b in bgp_peers_info.items() if n == peer]
        current_routes = {p: a for p, a in startup_routes.items() if p in prefixes}
        remove_routes_with_nexthops(current_routes, nexthop_to_remove, expected_routes)

    for ptfhost in ptfhosts:
        ptf_ip = ptfhost.mgmt_ip
        change_routes_on_peers(localhost, ptf_ip, topo_name, peers_routes_to_change, ACTION_WITHDRAW,
                               servers_dut_interfaces.get(ptf_ip, ''))
    compressed_expected_routes = compress_expected_routes(expected_routes)
    result = check_bgp_routes_converged(
        duthost,
        compressed_expected_routes,
        [],
        MAX_CONVERGENCE_WAIT_TIME,
        compressed=True,
        action='no_action'
    )
    terminated.set()
    traffic_thread.join()
    end_time = datetime.datetime.now()
    validate_rx_tx_counters(pdp, end_time, start_time, exp_mask, MAX_DOWNTIME_NEXTHOP_GROUP_MEMBER_CHANGE)
    if not result.get("converged"):
        pytest.fail("BGP routes are not stable in long time")

    # ------------announce routes and test ------------ #
    global_icmp_type += 1
    exp_mask = setup_packet_mask_counters(pdp, global_icmp_type)
    pkts = generate_packets(
        neighbor_ecmp_routes[injection_bgp_neighbor],
        duthost.facts['router_mac'],
        pdp.get_mac(pdp.port_to_device(injection_port), injection_port)
    )
    for hostname, routes in peers_routes_to_change.items():
        for route in routes:
            prefix = route[0].upper()
            found = False
            for topo_route in topo_bgp_routes[hostname]['ipv6']:
                if topo_route[0] == prefix:
                    route[2] = topo_route[2]
                    found = True
                    break
            if not found:
                logger.warning('Fail to update AS path of route %s, because of prefix was not found in topo', route[0])
    terminated = Event()
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, pdp.port_to_device(injection_port), injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    start_time = datetime.datetime.now()
    traffic_thread.start()
    for ptfhost in ptfhosts:
        ptf_ip = ptfhost.mgmt_ip
        change_routes_on_peers(localhost, ptf_ip, topo_name, peers_routes_to_change, ACTION_ANNOUNCE,
                               servers_dut_interfaces.get(ptf_ip, ''))
    compressed_startup_routes = compress_expected_routes(startup_routes)
    result = check_bgp_routes_converged(
        duthost,
        compressed_startup_routes,
        [],
        MAX_CONVERGENCE_WAIT_TIME,
        compressed=True,
        action='no_action'
    )
    terminated.set()
    traffic_thread.join()
    end_time = datetime.datetime.now()
    validate_rx_tx_counters(pdp, end_time, start_time, exp_mask, MAX_DOWNTIME_NEXTHOP_GROUP_MEMBER_CHANGE)
    if not result.get("converged"):
        pytest.fail("BGP routes are not stable in long time")


def test_device_unisolation(
    duthost,
    ptfadapter,
    bgp_peers_info,
    announce_bgp_routes_teardown,
    tbinfo
):
    '''
    This test is for the worst scenario that all ports are flapped,
    verify control/data plane have acceptable convergence time.
    Steps:
        Shut down all ports on device. (shut down T1 sessions ports on T0 DUT, shut down T0 sessions ports on T1 DUT.)
        Wait for routes are stable.
        Start and keep sending packets with all routes to all ports via ptf.
        Startup all ports and wait for routes are stable.
        Stop sending packets.
        Estimate control/data plane convergence time.
    Expected result:
        Dataplane downtime is less than MAX_DOWNTIME_UNISOLATION.
    '''
    global global_icmp_type
    global_icmp_type += 1
    pdp = ptfadapter.dataplane
    pdp.set_qlen(PACKET_QUEUE_LENGTH)
    exp_mask = setup_packet_mask_counters(pdp, global_icmp_type)

    bgp_ports = [bgp_info[DUT_PORT] for bgp_info in bgp_peers_info.values()]

    injection_bgp_neighbor = random.choice(list(bgp_peers_info.keys()))
    injection_dut_port = bgp_peers_info[injection_bgp_neighbor][DUT_PORT]
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    neighbor_ecmp_routes = get_ecmp_routes(startup_routes, bgp_peers_info)
    pkts = generate_packets(
        neighbor_ecmp_routes[injection_bgp_neighbor],
        duthost.facts['router_mac'],
        pdp.get_mac(pdp.port_to_device(injection_port), injection_port)
    )

    nexthops_to_remove = [b[IPV6_KEY] for b in bgp_peers_info.values() if b[DUT_PORT] in bgp_ports]
    expected_routes = deepcopy(startup_routes)
    remove_routes_with_nexthops(startup_routes, nexthops_to_remove, expected_routes)
    try:
        compressed_expected_routes = compress_expected_routes(expected_routes)
        result = check_bgp_routes_converged(
            duthost,
            compressed_expected_routes,
            bgp_ports,
            MAX_CONVERGENCE_WAIT_TIME,
            compressed=True,
            action='shutdown'
        )
        if not result.get("converged"):
            pytest.fail("BGP routes are not stable in long time")
    except Exception:
        duthost.no_shutdown_multiple(bgp_ports)

    terminated = Event()
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, pdp.port_to_device(injection_port), injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    start_time = datetime.datetime.now()
    traffic_thread.start()
    compressed_expected_routes = compress_expected_routes(startup_routes)
    result = check_bgp_routes_converged(
        duthost,
        compressed_expected_routes,
        bgp_ports,
        MAX_CONVERGENCE_WAIT_TIME,
        compressed=True,
        action='startup'
    )
    terminated.set()
    traffic_thread.join()
    end_time = datetime.datetime.now()
    validate_rx_tx_counters(pdp, end_time, start_time, exp_mask, MAX_DOWNTIME_UNISOLATION)
    if not result.get("converged"):
        pytest.fail("BGP routes are not stable in long time")
