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
from threading import Thread, Event
from tests.common.helpers.assertions import pytest_assert
from ptf.testutils import simple_icmpv6_packet

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
MAX_CONVERGENCE_WAIT_TIME = 200  # seconds
MAX_PKTS_COUNT = MAX_CONVERGENCE_WAIT_TIME * 10000   # ptf can send around 10000 icmpv6 packets per second
MAX_DOWNTIME = 10  # seconds
PKTS_SENDING_INTERVAL = 1  # seconds
PKTS_QUERY_TIME_INTERVAL = PKTS_SENDING_INTERVAL / 10.0  # seconds


@pytest.fixture(scope="module")
def bgp_peers_info(tbinfo, duthost):
    bgp_info = {}
    topo_name = tbinfo['topo']['name']
    for hostname in tbinfo['topo']['properties']['configuration'].keys():
        if ('t0' in topo_name and 'T1' not in hostname) or ('t1' in topo_name and 'T0' not in hostname):
            continue
        bgp_info[hostname] = {}
        alias = duthost.show_and_parse("show interfaces alias")
        ptf_port = tbinfo['topo']['properties']['topology']['VMs'][hostname]['vlans'][0]
        bgp_info[hostname][PTF_PORT] = ptf_port
        bgp_info[hostname][DUT_PORT] = [_a['name'] for _a in alias if _a['alias'] == 'etp' + str(ptf_port + 1)][0]
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


@pytest.fixture(scope="function")
def announce_bgp_routes_teardown(localhost, tbinfo):
    yield
    topo_name = tbinfo['topo']['name']
    ptf_ip = tbinfo['ptf_ip']
    localhost.announce_routes(
        topo_name=topo_name,
        ptf_ip=ptf_ip,
        action="announce",
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
            ipv6_dst=addr
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
    ret_routes = dict(routes)  # make a deep copy here
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


def compare_routes(expected_routes, running_routes):
    if len(expected_routes) != len(running_routes):
        return False
    for prefix, attr in expected_routes.items():
        if prefix not in running_routes:
            return False
        except_nhs = [nh['ip'] for nh in attr[0]['nexthops']]
        running_nhs = [nh['ip'] for nh in running_routes[prefix][0]['nexthops']]
        if except_nhs != running_nhs:
            return False
    return True


def caculate_downtime(ptf_dp, end_time, start_time):
    rx_total = sum(list(ptf_dp.rx_counters.values())[:-1])  # Exclude the backplane
    tx_total = sum(ptf_dp.tx_counters.values())
    missing_pkt_cnt = tx_total - rx_total
    pps = tx_total / (end_time - start_time).total_seconds()
    downtime = missing_pkt_cnt / pps
    logger.info(
        "traffic thread duration: %s seconds,\n rx_counters: %s,\n tx_counters: %s,\n" +
        "Total packets received: %d,\n Total packets sent: %d,\n Missing packets: %d" +
        "Estimated pps %s, downtime is %s",
        (end_time - start_time).total_seconds(),
        ptf_dp.rx_counters,
        ptf_dp.tx_counters,
        rx_total,
        tx_total,
        missing_pkt_cnt,
        pps,
        downtime
    )
    return downtime


def validate_downtime(downtime):
    pytest_assert(downtime < MAX_DOWNTIME, "Downtime is too long")


def validate_rx_tx_counters(ptf_dp, end_time, start_time):
    downtime = caculate_downtime(ptf_dp, end_time, start_time)
    validate_downtime(downtime)


def flush_counters(ptf_dp):
    logging.info("Flushing counters")
    for idx in ptf_dp.rx_counters.keys():
        ptf_dp.rx_counters[idx] = 0
    for idx in ptf_dp.tx_counters.keys():
        ptf_dp.tx_counters[idx] = 0
    logging.info("after flush rx_counters: %s, tx_counters: %s", ptf_dp.rx_counters, ptf_dp.tx_counters)


def send_packets(terminated, ptf_dataplane, device_num, port_num, pkts, count):
    last_round_time = datetime.datetime.now()
    for round in range(count):
        if terminated.is_set():
            logging.info("%d packets are sent", round*len(pkts))
            break
        while datetime.datetime.now() - last_round_time < datetime.timedelta(seconds=PKTS_SENDING_INTERVAL):
            time.sleep(PKTS_QUERY_TIME_INTERVAL)

        last_round_time = datetime.datetime.now()
        for pkt in pkts:
            ptf_dataplane.send(device_num, port_num, pkt)


def wait_for_ipv6_bgp_routes_recovery(duthost, expected_routes, start_time, timeout=MAX_CONVERGENCE_WAIT_TIME):
    while not compare_routes(get_all_bgp_ipv6_routes(duthost), expected_routes):
        if datetime.datetime.now() - start_time > datetime.timedelta(seconds=timeout):
            logging.info("Actual routes: %s", get_all_bgp_ipv6_routes(duthost))
            logging.info("Expected routes: %s", expected_routes)
            pytest.fail("BGP routes are not stable in long time")
    logger.info("Routes are stable after : %s", datetime.datetime.now() - start_time)


def test_sessions_flapping(duthost, ptfadapter, bgp_peers_info):
    '''
    This test is to make sure When BGP sessions are flapping,
    control plane is functional and data plane has no downtime or acceptable downtime.
    Steps:
        Start and keep sending packets with all routes to the random one open port via ptf.
        Shutdown one or half random port(s) that establishing bgp sessions.
        Wait for routes are stable, check if all nexthops connecting the shut down ports are disappeared in routes.
        Stop packet sending
        Estamite data plane down time by check packet count sent, received and duration.
    Expected result:
        Dataplane downtime is less than MAX_CONVERGENCE_WAIT_TIME.
    '''
    pdp = ptfadapter.dataplane
    bgp_ports = [bgp_info[DUT_PORT] for bgp_info in bgp_peers_info.values()]
    random.shuffle(bgp_ports)
    flapping_ports, unflapping_ports = bgp_ports[:len(bgp_ports) // 2], bgp_ports[len(bgp_ports) // 2:]
    logger.info("Flapping ports: %s and unflapping ports %s", flapping_ports, unflapping_ports)
    injection_dut_port = random.choice(unflapping_ports)
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ecmp_routes = {r: v for r, v in startup_routes.items() if len(v[0]['nexthops']) > 1}
    pkts = generate_packets(
        ecmp_routes,
        duthost.facts['router_mac'],
        pdp.get_mac(0, injection_port)
    )

    ternimated = Event()
    # TODO: update device number for multi-servers topo by method port_to_device
    traffic_thread = Thread(target=send_packets, args=(ternimated, pdp, 0, injection_port, pkts, MAX_PKTS_COUNT))
    flush_counters(pdp)
    start_time = datetime.datetime.now()
    traffic_thread.start()

    try:
        duthost.shutdown_multiple(flapping_ports)
        ports_shut_time = datetime.datetime.now()
        nexthops_to_remove = [b[IPV6_KEY] for b in bgp_peers_info.values() if b[DUT_PORT] in flapping_ports]
        expected_routes = remove_nexthops_in_routes(startup_routes, nexthops_to_remove)
        wait_for_ipv6_bgp_routes_recovery(duthost, expected_routes, ports_shut_time, MAX_CONVERGENCE_WAIT_TIME)
        ternimated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        validate_rx_tx_counters(pdp, end_time, start_time)
    finally:
        duthost.no_shutdown_multiple(flapping_ports)


def test_device_unisolation(duthost, ptfadapter, bgp_peers_info):
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
        Dataplane downtime is less than MAX_CONVERGENCE_WAIT_TIME.
    '''
    pdp = ptfadapter.dataplane
    bgp_ports = [bgp_info[DUT_PORT] for bgp_info in bgp_peers_info.values()]
    injection_dut_port = random.choice(bgp_ports)
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ecmp_routes = {r: v for r, v in startup_routes.items() if len(v[0]['nexthops']) > 1}
    pkts = generate_packets(
        ecmp_routes,
        duthost.facts['router_mac'],
        pdp.get_mac(0, injection_port)
    )

    try:
        duthost.shutdown_multiple(bgp_ports)
        ports_shut_time = datetime.datetime.now()
        nexthops_to_remove = [b[IPV6_KEY] for b in bgp_peers_info.values() if b[DUT_PORT] in bgp_ports]
        expected_routes = remove_nexthops_in_routes(startup_routes, nexthops_to_remove)
        wait_for_ipv6_bgp_routes_recovery(duthost, expected_routes, ports_shut_time, MAX_CONVERGENCE_WAIT_TIME)
        start_time = datetime.datetime.now()
        ternimated = Event()
        # TODO: update device number for multi-servers topo by method port_to_device
        traffic_thread = Thread(target=send_packets, args=(ternimated, pdp, 0, injection_port, pkts, MAX_PKTS_COUNT))
        flush_counters(pdp)
        traffic_thread.start()
    finally:
        duthost.no_shutdown_multiple(bgp_ports)
        ports_startup_time = datetime.datetime.now()
        while not compare_routes(get_all_bgp_ipv6_routes(duthost), startup_routes):
            if datetime.datetime.now() - ports_startup_time > datetime.timedelta(seconds=MAX_CONVERGENCE_WAIT_TIME):
                logging.info("Actual routes: %s", get_all_bgp_ipv6_routes(duthost))
                logging.info("Expected routes: %s", startup_routes)
                pytest.fail("BGP routes are not stable after ports unshut in long time")

        logger.info("Routes are stable after startup all ports: %s", datetime.datetime.now() - ports_startup_time)
        ternimated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        validate_rx_tx_counters(pdp, end_time, start_time)


def test_nexthop_group_member_scale(
    duthost,
    ptfadapter,
    localhost,
    tbinfo,
    bgp_peers_info,
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
        Dataplane downtime is less than MAX_CONVERGENCE_WAIT_TIME.
    '''
    topo_name = tbinfo['topo']['name']
    if 't1' in topo_name:
        pytest.skip("Skip test on T1 topology because every route only have one nexthop")

    ptf_ip = tbinfo['ptf_ip']
    pdp = ptfadapter.dataplane
    bgp_ports = [bgp_info[DUT_PORT] for bgp_info in bgp_peers_info.values()]
    injection_dut_port = random.choice(bgp_ports)
    injection_port = [i[PTF_PORT] for i in bgp_peers_info.values() if i[DUT_PORT] == injection_dut_port][0]
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ecmp_routes = {r: v for r, v in startup_routes.items() if len(v[0]['nexthops']) == len(bgp_peers_info)}
    pkts = generate_packets(
        ecmp_routes,
        duthost.facts['router_mac'],
        pdp.get_mac(0, injection_port)
    )
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6']
    routes_in_tuple = [(r, nhipv6, None) for r in ecmp_routes.keys()]
    peers_routes_to_change = {peer: routes_in_tuple[index::len(bgp_peers_info.keys())]
                              for index, peer in enumerate(bgp_peers_info.keys())}

    start_time = datetime.datetime.now()
    ternimated = Event()
    # TODO: update device number for multi-servers topo by method port_to_device
    traffic_thread = Thread(target=send_packets, args=(ternimated, pdp, 0, injection_port, pkts, MAX_PKTS_COUNT))
    flush_counters(pdp)
    traffic_thread.start()
    try:
        change_routes_on_peers(localhost, topo_name, ptf_ip, peers_routes_to_change, ACTION_WITHDRAW)
        withdraw_time = datetime.datetime.now()
        expected_routes = dict(startup_routes)
        for peer, routes in peers_routes_to_change.items():
            prefixes = [r[0] for r in routes]
            nexthop_to_remove = [b[IPV6_KEY] for n, b in bgp_peers_info.items() if n == peer]
            expected_routes.update(
                remove_nexthops_in_routes({p: a for p, a in ecmp_routes.items() if p in prefixes}, nexthop_to_remove)
            )
        wait_for_ipv6_bgp_routes_recovery(duthost, expected_routes, withdraw_time, MAX_CONVERGENCE_WAIT_TIME)
        ternimated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        validate_rx_tx_counters(pdp, end_time, start_time)

    finally:
        start_time = datetime.datetime.now()
        ternimated = Event()
        # TODO: update device number for multi-servers topo by method port_to_device
        traffic_thread = Thread(target=send_packets, args=(ternimated, pdp, 0, injection_port, pkts, MAX_PKTS_COUNT))
        flush_counters(pdp)
        traffic_thread.start()
        change_routes_on_peers(localhost, topo_name, ptf_ip, peers_routes_to_change, ACTION_ANNOUNCE)
        announce_time = datetime.datetime.now()
        wait_for_ipv6_bgp_routes_recovery(duthost, startup_routes, announce_time, MAX_CONVERGENCE_WAIT_TIME)
        ternimated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        validate_rx_tx_counters(pdp, end_time, start_time)
