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
import re
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
MAX_DOWN_BGP_SESSIONS_ALLOWED = 0
MAX_TIME_CONFIG = {
    'dataplane_downtime': 1,
    'controlplane_convergence': 300
}
PKTS_SENDING_TIME_SLOT = 1  # seconds
PACKETS_PER_TIME_SLOT = 500 // PKTS_SENDING_TIME_SLOT
MASK_COUNTER_WAIT_TIME = 10  # wait some seconds for mask counters processing packets
STATIC_ROUTES = ['0.0.0.0/0', '::/0']
WITHDRAW_ROUTE_NUMBER = 1
PACKET_QUEUE_LENGTH = 1000000
global_icmp_type = 123
test_results = {}
current_test = ""


@pytest.fixture(scope="module", autouse=True)
def log_test_results():
    yield
    logger.info("test_results: %s", test_results)


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


def _get_max_time(time_type, ratio=1):
    # Get the max time for dataplane or controlplane with a ratio
    # As of now, not enough strong data to set a baseline and a ratio for convergence time
    return MAX_TIME_CONFIG[time_type] * ratio


@pytest.fixture(scope="function")
def bgp_peers_info(tbinfo, duthost):
    bgp_info = {}
    topo_name = tbinfo['topo']['name']

    logger.info("Waiting for BGP sessions are established")
    while True:
        down_neighbors = get_down_bgp_sessions_neighbors(duthost)
        start_time = datetime.datetime.now()
        if len(down_neighbors) <= MAX_DOWN_BGP_SESSIONS_ALLOWED:
            if down_neighbors:
                logger.warning("There are down_neighbors %s", down_neighbors)
            break
        if (datetime.datetime.now() - start_time).total_seconds() > _get_max_time('controlplane_convergence'):
            pytest.fail("There are too many BGP sessions down: {}".format(down_neighbors))

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

    logger.info("BGP peers info: %s", bgp_info)
    return bgp_info


def get_down_bgp_sessions_neighbors(duthost):
    return duthost.shell("show ipv6 bgp sum | grep ARISTA | awk '$10 !~ /^[0-9]+$/ {print $NF}'")['stdout_lines']


@pytest.fixture(scope="function")
def design_routes(topo_bgp_routes, bgp_peers_info):
    ret = {}
    for hostname, routes in topo_bgp_routes.items():
        if hostname not in bgp_peers_info:
            continue
        for route in routes[IPV6_KEY]:
            prefix = str(ipaddress.ip_network(route[0]))
            if prefix not in ret:
                ret[prefix] = set()
            ret[prefix].add(bgp_peers_info[hostname][IPV6_KEY])
    return ret


@pytest.fixture(scope="function")
def setup_routes_before_test(localhost, duthost, tbinfo, vmhosts, ptfhosts, design_routes, bgp_peers_info):
    servers_dut_interfaces = {}
    # If servers in tbinfo, means tb was deployed with multi servers
    if 'servers' in tbinfo:
        servers_dut_interfaces = {value['ptf_ip'].split("/")[0]: value['dut_interfaces']
                                  for value in tbinfo['servers'].values()}
    if not validate_dut_routes(duthost, tbinfo, design_routes):
        ptf_container = "ptf_%s" % tbinfo['group-name']
        for vmhost in vmhosts:
            vmhost.command("sudo docker exec %s supervisorctl restart exabgpv6:*" % ptf_container)
        for ptfhost in ptfhosts:
            ptf_ip = ptfhost.mgmt_ip
            announce_routes(localhost, tbinfo, ptf_ip, servers_dut_interfaces.get(ptf_ip, ''))
    yield servers_dut_interfaces


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


def get_all_bgp_ipv6_routes(duthost, save_snapshot=False):
    logger.info("Getting ipv6 routes")
    routes_str = duthost.shell("docker exec bgp vtysh -c 'show ipv6 route bgp json'")['stdout']
    if save_snapshot:
        with open("/tmp/bgp_ipv6_routes_" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + '.json', "w") as f:
            f.write(routes_str)
    return json.loads(routes_str)


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


def validate_dut_routes(duthost, tbinfo, expected_routes):
    identical = True
    running_routes = get_all_bgp_ipv6_routes(duthost)
    checked_prefixes = set()
    for prefix, attr in running_routes.items():
        running_only_nhps = []
        topo_only_nhps = []
        running_nhs = [nh['ip'] for nh in attr[0]['nexthops']]
        topo_nhs = expected_routes[prefix] if prefix in expected_routes else []
        checked_prefixes.add(prefix)
        if prefix in STATIC_ROUTES or len(running_nhs) == 1:
            logger.info("Skip validate route %s", prefix)
            continue
        running_only_nhps = set(running_nhs) - set(topo_nhs)
        topo_only_nhps = set(topo_nhs) - set(running_nhs)
        if running_only_nhps or topo_only_nhps:
            logger.warning("Prefix %s nexthops not match, running only: %s, topo only: %s",
                           prefix, running_only_nhps, topo_only_nhps)
            identical = False
    for prefix in expected_routes.keys() - checked_prefixes:
        if prefix in STATIC_ROUTES:
            continue
        logger.warning("Prefix %s is missing in DUT routes", prefix)
        identical = False
    return identical


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
    global current_test, test_results
    test_results[current_test] = f"traffic thread duration: {(end_time - start_time).total_seconds()} seconds, " + \
        f"rx_counters: {ptf_dp.mask_rx_cnt[masked_exp_pkt]}, " + \
        f"tx_counters: {ptf_dp.mask_tx_cnt[masked_exp_pkt]}, " + \
        f"Total packets received: {rx_total}, " + \
        f"Total packets sent: {tx_total}, " + \
        f"Missing packets: {missing_pkt_cnt}, " + \
        f"Estimated pps: {pps}, " + \
        f"downtime: {downtime}"
    return downtime


def validate_rx_tx_counters(ptf_dp, end_time, start_time, masked_exp_pkt, downtime_threshold=10):
    downtime = calculate_downtime(ptf_dp, end_time, start_time, masked_exp_pkt)
    return downtime < downtime_threshold


def flush_counters(ptf_dp, masked_exp_pkt):
    logger.info("Flushing counters")
    for idx in ptf_dp.mask_rx_cnt[masked_exp_pkt].keys():
        ptf_dp.mask_rx_cnt[masked_exp_pkt][idx] = 0
    for idx in ptf_dp.mask_tx_cnt[masked_exp_pkt].keys():
        ptf_dp.mask_tx_cnt[masked_exp_pkt][idx] = 0
    logger.info("after flush rx_counters: %s, tx_counters: %s",
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
            logger.info("%d packets are sent", rounds_cnt * pkts_len)
            break
        logger.info("round %d, sending %d packets", rounds_cnt, rounds_cnt * pkts_len)
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


def _restore(duthost, connection_type, shutdown_connections, shutdown_all_connections):
    if connection_type == 'ports':
        logger.info(f"Recover interfaces {shutdown_connections} after failure")
        duthost.no_shutdown_multiple(shutdown_connections)
    elif connection_type == 'bgp_sessions':
        if shutdown_all_connections:
            logger.info("Recover all BGP sessions after failure")
            duthost.shell("sudo config bgp startup all")
        else:
            for session in shutdown_connections:
                logger.info(f"Recover BGP session {session} after failure")
                duthost.shell(f"sudo config bgp startup neighbor {session}")


def check_bgp_routes_converged(duthost, expected_routes, shutdown_connections=None, connection_type='none',
                               shutdown_all_connections=False, timeout=300, interval=1,
                               log_path="/tmp", compressed=False, action='no_action'):
    shutdown_connections = shutdown_connections or []
    logger.info("Start to check bgp routes converged")
    expected_routes_json = json.dumps(expected_routes, separators=(',', ':'))

    result = duthost.check_bgp_ipv6_routes_converged(
        expected_routes=expected_routes_json,
        shutdown_connections=shutdown_connections,
        connection_type=connection_type,
        shutdown_all_connections=shutdown_all_connections,
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
        # When routes convergence fail, if the action is shutdown and shutdown_connections is not empty
        # restore interfaces
        if action == 'shutdown' and shutdown_connections:
            _restore(duthost, connection_type, shutdown_connections, shutdown_all_connections)
        pytest.fail(f"BGP routes aren't stable in {timeout} seconds")


@pytest.fixture(scope="function")
def clean_ptf_dataplane(ptfadapter):
    """
    Drain queued packets and clear mask counters before and after each test.
    The idea is that each test should start with clean dataplane state without
    having to restart ptfadapter fixture for each test.
    Takes in the function scope so that each parametrized test case also gets a clean dataplane.
    """
    dp = ptfadapter.dataplane

    def _perform_cleanup_on_dp():
        dp.drain()
        dp.clear_masks()
    # Before test run DP cleanup
    _perform_cleanup_on_dp()
    yield
    # After test run DP cleanup
    _perform_cleanup_on_dp()


def compress_expected_routes(expected_routes):
    json_str = json.dumps(expected_routes)
    compressed = gzip.compress(json_str.encode('utf-8'))
    b64_str = base64.b64encode(compressed).decode('utf-8')
    return b64_str


def get_route_programming_start_time_from_syslog(duthost, connection_type, action, LOG_STAMP, syslog='/var/log/syslog'):
    """
    Parse syslog for the first route programming event time. Returns the timestamp of the first route change event.
    """
    state = 'down' if action == 'shutdown' else 'up'
    if connection_type == 'ports':
        cmd = f'grep "swss#portmgrd: " | grep "admin status to {state}"'
    elif connection_type == 'bgp_sessions':
        cmd = f'grep "admin state is set to \'{state}\'"'
    else:
        logger.info("[FLAP TEST] No RP analysis for connection_type: %s", connection_type)
        return None
    log_pattern = f'/{LOG_STAMP}/ {{found=1}} found'
    pattern = f'sudo awk "{log_pattern}" {syslog} | {cmd} | head -n 1'
    syslog_stamp = duthost.shell(pattern)['stdout'].strip()
    shut_time_str = " ".join(syslog_stamp.split()[:4])
    rp_start_time = datetime.datetime.strptime(shut_time_str, "%Y %b %d %H:%M:%S.%f")
    return rp_start_time


def get_route_programming_metrics_from_sairedis_replay(duthost, start_time, sairedislog='/var/log/swss/sairedis.rec'):
    nhg_pattern = "|r|SAI_OBJECT_TYPE_NEXT_HOP_GROUP:"
    route_pattern = "|R|SAI_OBJECT_TYPE_ROUTE_ENTRY"
    ts_regex = re.compile(r'\d{4}-\d{2}-\d{2}\.\d{2}:\d{2}:\d{2}\.\d+')

    def read_lines(path):
        try:
            return duthost.shell(f"sudo grep -e '{nhg_pattern}' -e '{route_pattern}' {path}")['stdout'].splitlines()
        except Exception as e:
            logger.warning("Failed to read %s: %s", path, e)
            return []
    lines = read_lines(sairedislog)
    if not lines:
        logger.warning("No RP events in %s, trying fallback", sairedislog)
        lines = read_lines(sairedislog + ".1")
    if not lines:
        return {
            "RP Start Time": start_time,
            "Route Programming Duration": None,
            "RP Error": "No RP events found"
        }
    deltas = []
    route_events_count = 0
    for line in lines:
        m = ts_regex.search(line)
        if not m:
            continue
        ts = datetime.datetime.strptime(m.group(0), "%Y-%m-%d.%H:%M:%S.%f")
        if ts <= start_time:
            continue
        if nhg_pattern in line:
            deltas.append((ts - start_time).total_seconds())
        elif route_pattern in line:
            route_events_count += 1
    return {"RP Start Time": start_time, "Route Programming Duration": deltas[-1] if deltas else None,
            "Route Events Count": route_events_count, "NextHopGroup Events Count": len(deltas)}


def _select_targets_to_flap(bgp_peers_info, all_flap, flapping_count):
    """Selects flapping_neighbors, injection_neighbor, flapping_ports, injection_port"""
    bgp_neighbors = list(bgp_peers_info.keys())
    pytest_assert(len(bgp_neighbors) >= 2, "At least two BGP neighbors required for flap test")
    if all_flap:
        flapping_neighbors = bgp_neighbors
        injection_neighbor = random.choice(bgp_neighbors)
        logger.info(f"[FLAP TEST] All neighbors are flapping: {len(flapping_neighbors)}")
    else:
        flapping_neighbors = random.sample(bgp_neighbors, flapping_count)
        injection_candidates = [n for n in bgp_neighbors if n not in flapping_neighbors]
        injection_neighbor = random.choice(injection_candidates)
        logger.info(f"[FLAP TEST] Flapping neighbors count: {len(flapping_neighbors)}, "
                    f"Flapping neighbors: {flapping_neighbors}")
    flapping_ports = [bgp_peers_info[n][DUT_PORT] for n in flapping_neighbors]
    injection_dut_port = bgp_peers_info[injection_neighbor][DUT_PORT]
    injection_port = [info[PTF_PORT] for info in bgp_peers_info.values() if info[DUT_PORT] == injection_dut_port][0]
    logger.info(f"Flapping ports: {flapping_ports}")
    logger.info(f"[FLAP TEST] Injection neighbor: {injection_neighbor}, Injection DUT port: {injection_dut_port}")
    logger.info("Injection port: %s", injection_port)
    return flapping_neighbors, injection_neighbor, flapping_ports, injection_port


def flapper(duthost, ptfadapter, bgp_peers_info, transient_setup, flapping_count, connection_type, action):
    """
    Orchestrates interface/BGP session flapping and recovery on the DUT, generating test traffic to assess both
    control and data plane convergence behavior. This function is designed for use in test scenarios
    where some or all BGP neighbors or ports are shut down and restarted.

    Behavior:
      - On shutdown action: Randomly selects (or selects all) BGP neighbors/ports to flap, as well as an injection port
        to use for sending traffic during the event. It computes expected post-flap routes and sets up traffic streams.
      - On startup action: Reuses the previously determined injection/flapping selections to restore connectivity and
        again validates route convergence and traffic recovery.
      - Measures and validates data plane downtime across the operations, helping to detect issues in convergence times.
      - Reports and validates route programming data from syslog/sairedis logs for control plane convergence.
      - Returns details about the selected connections and test traffic for subsequent phases.

    Returns:
        For shutdown phase: dict with flapping_connections, injection_port, compressed_startup_routes, prefixes.
        For startup phase: empty dict.
    """
    global global_icmp_type, current_test, test_results
    current_test = f"flapper_{action}_{connection_type}_count_{flapping_count}"
    global_icmp_type += 1
    pdp = ptfadapter.dataplane
    pdp.clear_masks()
    pdp.set_qlen(PACKET_QUEUE_LENGTH)
    exp_mask = setup_packet_mask_counters(pdp, global_icmp_type)
    all_flap = (flapping_count == 'all')

    # Currently treating the shutdown action as a setup mechanism for a startup action to follow.
    # So we only do the selection of flapping and injection neighbors when action is shutdown
    # And we reuse the same selection for startup action
    if action == 'shutdown':
        bgp_neighbors = list(bgp_peers_info.keys())
        pytest_assert(len(bgp_neighbors) >= 2, "At least two BGP neighbors required for flap test")

        # Choose target neighbors (to flap) and injection (to keep traffic stable)
        flapping_neighbors, injection_neighbor, flapping_ports, injection_port = _select_targets_to_flap(
            bgp_peers_info, all_flap, flapping_count
        )

        flapping_connections = {'ports': flapping_ports, 'bgp_sessions': flapping_neighbors}.get(connection_type, [])
        # Build expected routes after shutdown
        startup_routes = get_all_bgp_ipv6_routes(duthost, save_snapshot=False)
        neighbor_ecmp_routes = get_ecmp_routes(startup_routes, bgp_peers_info)
        prefixes = neighbor_ecmp_routes[injection_neighbor]
        nexthops_to_remove = [b[IPV6_KEY] for b in bgp_peers_info.values() if b[DUT_PORT] in flapping_ports]
        expected_routes = deepcopy(startup_routes)
        remove_routes_with_nexthops(startup_routes, nexthops_to_remove, expected_routes)
        compressed_routes = compress_expected_routes(expected_routes)
    elif action == 'startup':
        compressed_routes = transient_setup['compressed_startup_routes']
        injection_port = transient_setup['injection_port']
        flapping_connections = transient_setup['flapping_connections']
        prefixes = transient_setup['prefixes']
    else:
        logger.warning(f"Action {action} provided is not supported, skipping flapper function")
        return {}

    pkts = generate_packets(
        prefixes,
        duthost.facts['router_mac'],
        pdp.get_mac(pdp.port_to_device(injection_port), injection_port)
    )
    # Downtime ratio is calculated by dividing the number of flapping neighbors by 5, from test data
    downtime_ratio = len(flapping_connections) / 5
    downtime_threshold = _get_max_time('dataplane_downtime', downtime_ratio)
    terminated = Event()
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, pdp.port_to_device(injection_port), injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    traffic_thread.start()
    start_time = datetime.datetime.now()
    LOG_STAMP = "RP_ANALYSIS_STAMP_%s" % start_time.strftime("%Y%m%d_%H%M%S")
    duthost.shell('sudo logger "%s"' % LOG_STAMP)
    try:
        result = check_bgp_routes_converged(
            duthost=duthost,
            expected_routes=compressed_routes,
            shutdown_connections=flapping_connections,
            connection_type=connection_type,
            shutdown_all_connections=all_flap,
            timeout=_get_max_time('controlplane_convergence'),
            compressed=True,
            action=action
        )
        terminated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        acceptable_downtime = validate_rx_tx_counters(pdp, end_time, start_time, exp_mask, downtime_threshold)
        if not acceptable_downtime:
            if action == 'shutdown':
                _restore(duthost, connection_type, flapping_connections, all_flap)
            pytest.fail(f"Dataplane downtime is too high, threshold is {downtime_threshold} seconds")
        if not result.get("converged"):
            pytest.fail("BGP routes are not stable in long time")
    finally:
        # Ensure traffic is stopped
        terminated.set()
        traffic_thread.join()
    rp_start_time = get_route_programming_start_time_from_syslog(duthost, connection_type, action, LOG_STAMP)
    if rp_start_time:
        RP_metrics = get_route_programming_metrics_from_sairedis_replay(duthost, rp_start_time)
        logger.info(f"[FLAP TEST] Route programming metrics after {action}: {RP_metrics}")
        test_results[f"{current_test}_RP"] = RP_metrics
        RP_duration = RP_metrics.get('Route Programming Duration')
        if RP_duration is not None and RP_duration > _get_max_time('controlplane_convergence'):
            _restore(duthost, connection_type, flapping_connections, all_flap)
            pytest.fail(f"RP Time during {current_test} is too long: {RP_duration} seconds")
    else:
        logger.info(f"[FLAP TEST] No Route Programming metrics found after {action}")
        test_results[f"{current_test}_RP"] = "No RP metrics found"

    return {
        "flapping_connections": flapping_connections,
        "injection_port": injection_port,
        "compressed_startup_routes": compress_expected_routes(startup_routes),
        "prefixes": prefixes
    } if action == 'shutdown' else {}


def test_nexthop_group_member_scale(
    duthost,
    ptfadapter,
    ptfhosts,
    localhost,
    tbinfo,
    bgp_peers_info,
    clean_ptf_dataplane,
    setup_routes_before_test,
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
    global current_test
    current_test = request.node.name + "_withdraw"
    servers_dut_interfaces = setup_routes_before_test
    topo_name = tbinfo['topo']['name']
    global global_icmp_type
    global_icmp_type += 1
    pdp = ptfadapter.dataplane
    pdp.clear_masks()
    pdp.set_qlen(PACKET_QUEUE_LENGTH)
    exp_mask = setup_packet_mask_counters(pdp, global_icmp_type)
    injection_bgp_neighbor = random.choice(list(bgp_peers_info.keys()))
    injection_dut_port = bgp_peers_info[injection_bgp_neighbor][DUT_PORT]
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost, True)
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
    try:
        compressed_expected_routes = compress_expected_routes(expected_routes)
        result = check_bgp_routes_converged(
            duthost=duthost,
            expected_routes=compressed_expected_routes,
            shutdown_connections=[],
            connection_type='none',
            shutdown_all_connections=False,
            timeout=_get_max_time('controlplane_convergence'),
            compressed=True,
            action='no_action'
        )
        terminated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        acceptable_downtime = validate_rx_tx_counters(pdp, end_time, start_time, exp_mask,
                                                      _get_max_time('dataplane_downtime', 1))
        if not acceptable_downtime:
            for ptfhost in ptfhosts:
                ptf_ip = ptfhost.mgmt_ip
                announce_routes(localhost, tbinfo, ptf_ip, servers_dut_interfaces.get(ptf_ip, ''))
            pytest.fail(f"Dataplane downtime is too high, threshold is "
                        f"{_get_max_time('dataplane_downtime', 1)} seconds")
        if not result.get("converged"):
            pytest.fail("BGP routes are not stable in long time")
    finally:
        pass
    # ------------announce routes and test ------------ #
    current_test = request.node.name + "_announce"
    global_icmp_type += 1
    pdp.clear_masks()
    exp_mask = setup_packet_mask_counters(pdp, global_icmp_type)
    pkts = generate_packets(
        neighbor_ecmp_routes[injection_bgp_neighbor],
        duthost.facts['router_mac'],
        pdp.get_mac(pdp.port_to_device(injection_port), injection_port)
    )
    terminated = Event()
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, pdp.port_to_device(injection_port), injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    start_time = datetime.datetime.now()
    traffic_thread.start()
    for ptfhost in ptfhosts:
        ptf_ip = ptfhost.mgmt_ip
        announce_routes(localhost, tbinfo, ptf_ip, servers_dut_interfaces.get(ptf_ip, ''))
    compressed_startup_routes = compress_expected_routes(startup_routes)
    result = check_bgp_routes_converged(
        duthost=duthost,
        expected_routes=compressed_startup_routes,
        shutdown_connections=[],
        connection_type='none',
        shutdown_all_connections=False,
        timeout=_get_max_time('controlplane_convergence'),
        compressed=True,
        action='no_action'
    )
    terminated.set()
    traffic_thread.join()
    end_time = datetime.datetime.now()
    acceptable_downtime = validate_rx_tx_counters(pdp, end_time, start_time, exp_mask,
                                                  _get_max_time('dataplane_downtime', 1))
    if not acceptable_downtime:
        pytest.fail(f"Dataplane downtime is too high, threshold is {_get_max_time('dataplane_downtime', 1)} seconds")
    if not result.get("converged"):
        pytest.fail("BGP routes are not stable in long time")


@pytest.mark.parametrize("flapping_neighbor_count", [1, 10])
def test_bgp_admin_flap(
    request,
    duthost,
    ptfadapter,
    bgp_peers_info,
    clean_ptf_dataplane,
    flapping_neighbor_count,
    setup_routes_before_test
):
    """
    Validates that both control plane and data plane remain functional with acceptable downtime when BGP sessions are
    flapped (brought down and back up), simulating various failure or maintenance scenarios.

    Uses the flapper function to orchestrate the flapping of BGP sessions and measure convergence times.

    Parameters range from flapping a single session to all sessions.

    Expected result:
        Dataplane downtime is less than MAX_BGP_SESSION_DOWNTIME or MAX_DOWNTIME_UNISOLATION for all ports.
    """
    # Measure shutdown convergence
    transient_setup = flapper(duthost, ptfadapter, bgp_peers_info, None, flapping_neighbor_count,
                              'bgp_sessions', 'shutdown')
    # Measure startup convergence
    flapper(duthost, ptfadapter, None, transient_setup, flapping_neighbor_count, 'bgp_sessions', 'startup')


@pytest.mark.parametrize("flapping_port_count", [1, 10, 20, 'all'])
def test_sessions_flapping(
    request,
    duthost,
    ptfadapter,
    bgp_peers_info,
    clean_ptf_dataplane,
    flapping_port_count,
    setup_routes_before_test
):
    '''
    Validates that both control plane and data plane remain functional with acceptable downtime when BGP sessions are
    flapped (brought down and back up), simulating various failure or maintenance scenarios.

    Uses the flapper function to orchestrate the flapping of BGP sessions and measure convergence times.

    Parameters range from flapping a single session to all sessions.

    Expected result:
        Dataplane downtime is less than MAX_DOWNTIME_PORT_FLAPPING or MAX_DOWNTIME_UNISOLATION for all ports.
    '''
    # Measure shutdown convergence
    transient_setup = flapper(duthost, ptfadapter, bgp_peers_info, None, flapping_port_count, 'ports', 'shutdown')
    # Measure startup convergence
    flapper(duthost, ptfadapter, None, transient_setup, flapping_port_count, 'ports', 'startup')
