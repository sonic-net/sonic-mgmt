'''
Test plan PR: https://github.com/sonic-net/sonic-mgmt/pull/15702
'''

import datetime
import pytest
import logging
import json
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
        't0-isolated-d2u254s1', 't0-isolated-d2u254s2', 't0-isolated-d2u510',
        't1-isolated-d254u2s1', 't1-isolated-d254u2s2', 't1-isolated-d510u2'
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
MAX_DONWTIME_NEXTHOP_GROUP_MEMBER_CHANGE = 30  # seconds
PKTS_SENDING_TIME_SLOT = 1  # seconds
MAX_CONVERGENCE_WAIT_TIME = 300  # seconds
PACKETS_PER_TIME_SLOT = 500 // PKTS_SENDING_TIME_SLOT
MASK_COUNTER_WAIT_TIME = 10  # wait some seconds for mask counters processing packets
STATIC_ROUTES = ['0.0.0.0/0', '::/0']
ICMP_TYPE = 123


@pytest.fixture(scope="module")
def setup_packet_mask_counters(ptfadapter):
    """
    Create a mask counters for packet sending
    """
    ptf_dp = ptfadapter.dataplane
    exp_pkt = simple_icmpv6_packet(
        icmp_type=ICMP_TYPE
    )
    masked_exp_pkt = Mask(exp_pkt)
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, 'src')
    masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, 'dst')
    masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "src")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "dst")
    masked_exp_pkt.set_do_not_care_scapy(scapy.IPv6, "hlim")
    masked_exp_pkt.set_do_not_care_scapy(scapy.ICMPv6Unknown, "cksum")
    ptf_dp.create_mask_counters(masked_exp_pkt)

    yield masked_exp_pkt


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
def announce_bgp_routes_teardown(localhost, tbinfo):
    yield
    announce_routes(localhost, tbinfo)


def announce_routes(localhost, tbinfo):
    topo_name = tbinfo['topo']['name']
    ptf_ip = tbinfo['ptf_ip']
    localhost.announce_routes(
        topo_name=topo_name,
        ptf_ip=ptf_ip,
        action=ACTION_ANNOUNCE,
        path="../ansible/",
        log_path="logs"
    )


def get_all_bgp_ipv6_routes(duthost):
    return json.loads(
        duthost.shell("docker exec bgp vtysh -c 'show ipv6 route bgp json'")['stdout']
    )


def generate_packets(routes, dut_mac, src_mac):
    pkts = []
    for prefix in routes.keys():
        addr = str(ipaddress.ip_network(prefix)[1])
        pkt = simple_icmpv6_packet(
            eth_dst=dut_mac,
            eth_src=src_mac,
            ipv6_dst=addr,
            icmp_type=ICMP_TYPE
        )
        pkts.append(bytes(pkt))

    return pkts


def change_routes_on_peers(localhost, topo_name, ptf_ip, peers_routes_to_change, action):
    localhost.announce_routes(
        topo_name=topo_name,
        adhoc=True,
        ptf_ip=ptf_ip,
        action=action,
        peers_routes_to_change=peers_routes_to_change,
        path="../ansible/",
        log_path="logs"
    )


def remove_nexthops_in_routes(routes, nexthops):
    ret_routes = deepcopy(routes)
    prefxies_to_remove = []
    for prefix, attr in ret_routes.items():
        _nhs = [nh for nh in attr[0]['nexthops'] if nh['ip'] not in nexthops]
        if len(_nhs) == 0:
            prefxies_to_remove.append(prefix)
        else:
            attr[0]['nexthops'] = _nhs
    for prefix in prefxies_to_remove:
        ret_routes.pop(prefix)
    return ret_routes


def compare_routes(running_routes, expected_routes):
    is_same = True
    diff_cnt = 0
    if len(expected_routes) != len(running_routes):
        is_same = False
        logger.info("Count unmatch, expected_routes count=%d,  running_routes count=%d",
                    len(expected_routes), len(running_routes))
        return is_same
    for prefix, attr in expected_routes.items():
        if prefix not in running_routes:
            is_same = False
            diff_cnt += 1
            continue
        except_nhs = [nh['ip'] for nh in attr[0]['nexthops']]
        running_nhs = [nh['ip'] for nh in running_routes[prefix][0]['nexthops']]
        if except_nhs != running_nhs:
            is_same = False
            diff_cnt += 1
    logger.info("%d of %d routes are different", diff_cnt, len(expected_routes))
    return is_same


def caculate_downtime(ptf_dp, end_time, start_time, masked_exp_pkt):
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
    downtime = caculate_downtime(ptf_dp, end_time, start_time, masked_exp_pkt)
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


def wait_for_ipv6_bgp_routes_recovery(duthost, expected_routes, start_time, timeout=MAX_CONVERGENCE_WAIT_TIME):
    is_first_run = True
    while not compare_routes(get_all_bgp_ipv6_routes(duthost), expected_routes):
        if datetime.datetime.now() - start_time > datetime.timedelta(seconds=timeout) and not is_first_run:
            logging.info("Actual routes: %s", get_all_bgp_ipv6_routes(duthost))
            logging.info("Expected routes: %s", expected_routes)
            logging.error("BGP routes are not stable in long time")
            return False
        is_first_run = False
    logger.info("Routes are stable after : %s", datetime.datetime.now() - start_time)
    return True


@pytest.mark.parametrize("flapping_port_count", [1,  10, 20])
def test_sessions_flapping(
    duthost,
    ptfadapter,
    bgp_peers_info,
    flapping_port_count,
    setup_packet_mask_counters,
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
        Estamite data plane down time by check packet count sent, received and duration.
    Expected result:
        Dataplane downtime is less than MAX_DOWNTIME_ONE_PORT_FLAPPING.
    '''
    pdp = ptfadapter.dataplane
    exp_mask = setup_packet_mask_counters
    bgp_ports = [bgp_info[DUT_PORT] for bgp_info in bgp_peers_info.values()]
    random.shuffle(bgp_ports)
    flapping_ports, unflapping_ports = bgp_ports[:flapping_port_count], bgp_ports[flapping_port_count:]
    logger.info("Flapping_port_count is %d, flapping ports: %s and unflapping ports %s",
                flapping_port_count, flapping_ports, unflapping_ports)
    injection_dut_port = random.choice(unflapping_ports)
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ecmp_routes = {r: v for r, v in startup_routes.items() if len(v[0]['nexthops']) > 1 and r not in STATIC_ROUTES}
    pkts = generate_packets(
        ecmp_routes,
        duthost.facts['router_mac'],
        pdp.get_mac(0, injection_port)
    )

    nexthops_to_remove = [b[IPV6_KEY] for b in bgp_peers_info.values() if b[DUT_PORT] in flapping_ports]
    expected_routes = remove_nexthops_in_routes(startup_routes, nexthops_to_remove)
    terminated = Event()
    # TODO: update device number for multi-servers topo by method port_to_device
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, 0, injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    traffic_thread.start()
    start_time = datetime.datetime.now()
    duthost.shutdown_multiple(flapping_ports)
    ports_shut_time = datetime.datetime.now()

    try:
        recovered = wait_for_ipv6_bgp_routes_recovery(
            duthost,
            expected_routes,
            ports_shut_time,
            MAX_CONVERGENCE_WAIT_TIME
        )
        terminated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        validate_rx_tx_counters(pdp, end_time, start_time, exp_mask, MAX_DOWNTIME_ONE_PORT_FLAPPING)
        if not recovered:
            pytest.fail("BGP routes are not stable in long time")
    finally:
        duthost.no_shutdown_multiple(flapping_ports)


def test_device_unisolation(
    duthost,
    ptfadapter,
    bgp_peers_info,
    setup_packet_mask_counters,
    announce_bgp_routes_teardown
):
    '''
    This test is for the worst senario that all ports are flapped,
    verify control/data plane have acceptable conergence time.
    Steps:
        Shut down all ports on device. (shut down T1 sessions ports on T0 DUT, shut down T0 sesssions ports on T1 DUT.)
        Wait for routes are stable.
        Start and keep sending packets with all routes to all portes via ptf.
        Unshut all ports and wait for routes are stable.
        Stop sending packets.
        Estamite control/data plane convergence time.
    Expected result:
        Dataplane downtime is less than MAX_DOWNTIME_UNISOLATION.
    '''
    pdp = ptfadapter.dataplane
    exp_mask = setup_packet_mask_counters
    bgp_ports = [bgp_info[DUT_PORT] for bgp_info in bgp_peers_info.values()]
    injection_dut_port = random.choice(bgp_ports)
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ecmp_routes = {r: v for r, v in startup_routes.items() if len(v[0]['nexthops']) > 1 and r not in STATIC_ROUTES}
    pkts = generate_packets(
        ecmp_routes,
        duthost.facts['router_mac'],
        pdp.get_mac(0, injection_port)
    )

    nexthops_to_remove = [b[IPV6_KEY] for b in bgp_peers_info.values() if b[DUT_PORT] in bgp_ports]
    expected_routes = remove_nexthops_in_routes(startup_routes, nexthops_to_remove)
    try:
        duthost.shutdown_multiple(bgp_ports)
        ports_shut_time = datetime.datetime.now()
        recovered = wait_for_ipv6_bgp_routes_recovery(
            duthost,
            expected_routes,
            ports_shut_time,
            MAX_CONVERGENCE_WAIT_TIME
        )
        if not recovered:
            pytest.fail("BGP routes are not stable in long time")
    except Exception:
        duthost.no_shutdown_multiple(bgp_ports)

    terminated = Event()
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, 0, injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    start_time = datetime.datetime.now()
    traffic_thread.start()
    duthost.no_shutdown_multiple(bgp_ports)
    ports_startup_time = datetime.datetime.now()
    recovered = wait_for_ipv6_bgp_routes_recovery(
        duthost,
        startup_routes,
        ports_startup_time,
        MAX_CONVERGENCE_WAIT_TIME
    )
    terminated.set()
    traffic_thread.join()
    end_time = datetime.datetime.now()
    validate_rx_tx_counters(pdp, end_time, start_time, exp_mask, MAX_DOWNTIME_UNISOLATION)
    if not recovered:
        pytest.fail("BGP routes are not stable in long time")


def test_nexthop_group_member_scale(
    duthost,
    ptfadapter,
    localhost,
    tbinfo,
    bgp_peers_info,
    setup_packet_mask_counters,
    announce_bgp_routes_teardown
):
    '''
    This test is to make sure when routes on BGP peers are flapping,
    control plane is functional and data plane has no downtime or acceptable downtime.
    Steps:
        1. Start and keep sending packets with all routes to the random one open port via ptf.
        2. For all routes, remove one nexthop by withdraw the route from one peer.
        3. Wait for routes are stable.
        4. Stop sending packets and estamite data plane down time.
        5. For all routes, announce the route to the peer.
        6. Wait for routes are stable.
        7. Stop sending packets and estamite data plane down time.
    Expected result:
        Dataplane downtime is less than MAX_DONWTIME_NEXTHOP_GROUP_MEMBER_CHANGE.
    '''
    topo_name = tbinfo['topo']['name']
    if 't1' in topo_name:
        pytest.skip("Skip test on T1 topology because every route only have one nexthop")

    ptf_ip = tbinfo['ptf_ip']
    pdp = ptfadapter.dataplane
    exp_mask = setup_packet_mask_counters
    bgp_ports = [bgp_info[DUT_PORT] for bgp_info in bgp_peers_info.values()]
    injection_dut_port = random.choice(bgp_ports)
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ecmp_routes = {
        r: v for r, v in startup_routes.items()
        if len(v[0]['nexthops']) == len(bgp_peers_info) and r not in STATIC_ROUTES
    }
    pkts = generate_packets(
        ecmp_routes,
        duthost.facts['router_mac'],
        pdp.get_mac(0, injection_port)
    )
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6']
    routes_in_tuple = [(r, nhipv6, None) for r in ecmp_routes.keys()]
    peers_routes_to_change = {peer: routes_in_tuple[index::len(bgp_peers_info.keys())]
                              for index, peer in enumerate(bgp_peers_info.keys())}

    # ------------withdraw routes and test ------------ #
    terminated = Event()
    # TODO: update device number for multi-servers topo by method port_to_device
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, 0, injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    start_time = datetime.datetime.now()
    traffic_thread.start()
    expected_routes = deepcopy(startup_routes)
    for peer, routes in peers_routes_to_change.items():
        prefixes = [r[0] for r in routes]
        nexthop_to_remove = [b[IPV6_KEY] for n, b in bgp_peers_info.items() if n == peer]
        expected_routes.update(
            remove_nexthops_in_routes({p: a for p, a in ecmp_routes.items() if p in prefixes}, nexthop_to_remove)
        )
    change_routes_on_peers(localhost, topo_name, ptf_ip, peers_routes_to_change, ACTION_WITHDRAW)
    withdraw_time = datetime.datetime.now()
    recovered = wait_for_ipv6_bgp_routes_recovery(duthost, expected_routes, withdraw_time, MAX_CONVERGENCE_WAIT_TIME)
    terminated.set()
    traffic_thread.join()
    end_time = datetime.datetime.now()
    validate_rx_tx_counters(pdp, end_time, start_time, exp_mask, MAX_DONWTIME_NEXTHOP_GROUP_MEMBER_CHANGE)
    if not recovered:
        pytest.fail("BGP routes are not stable in long time")

    # ------------announce routes and test ------------ #
    terminated = Event()
    # TODO: update device number for multi-servers topo by method port_to_device
    traffic_thread = Thread(
        target=send_packets, args=(terminated, pdp, 0, injection_port, pkts)
    )
    flush_counters(pdp, exp_mask)
    start_time = datetime.datetime.now()
    traffic_thread.start()
    announce_routes(localhost, tbinfo)
    announce_time = datetime.datetime.now()
    recovered = wait_for_ipv6_bgp_routes_recovery(duthost, startup_routes, announce_time, MAX_CONVERGENCE_WAIT_TIME)
    terminated.set()
    traffic_thread.join()
    end_time = datetime.datetime.now()
    validate_rx_tx_counters(pdp, end_time, start_time, exp_mask, MAX_DONWTIME_NEXTHOP_GROUP_MEMBER_CHANGE)
    if not recovered:
        pytest.fail("BGP routes are not stable in long time")
