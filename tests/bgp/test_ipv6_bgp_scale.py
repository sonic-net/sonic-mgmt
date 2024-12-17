import datetime
import pytest
import logging
import json
import ipaddress
import random
from threading import Thread, Event
from tests.common.helpers.assertions import pytest_assert
from ptf.testutils import simple_icmpv6_packet

pytestmark = [
    pytest.mark.topology(
        't0-isolated-d2u254s1', 't0-isolated-d2u254s2', 't0-isolated-d2u510',
        't1-isolated-d254u2s1', 't1-isolated-d254u2s2', 't1-isolated-d510u2'
    ),
]

logger = logging.getLogger(__name__)


ACTION_ANNOUNCE = 'announce'
ACTION_WITHDRAW = 'withdraw'
PORT_KEY = "port"
IPV6_KEY = "ipv6"
MAX_PKTS_COUNT = 60 * 1000
MAX_CONVERGENCE_WAIT_TIME = 60  # seconds


@pytest.fixture(scope="module")
def bgp_peers_info(tbinfo):
    bgp_info = {}
    topo_name = tbinfo['topo']['name']
    for hostname in tbinfo['topo']['properties']['configuration'].keys():
        if ('t0' in topo_name and 'T1' not in hostname) or ('t1' in topo_name and 'T0' not in hostname):
            continue
        bgp_info[hostname] = {}
        bgp_info[hostname][PORT_KEY] = \
            'Ethernet' + str(tbinfo['topo']['properties']['topology']['VMs'][hostname]['vlans'][0])
        if 'ipv6' in tbinfo['topo']['properties']['configuration'][hostname]['interfaces']['Ethernet1']:
            bgp_info[hostname][IPV6_KEY] = \
                tbinfo['topo']['properties']['configuration'][hostname]['interfaces']['Ethernet1']['ipv6'].split('/')[0]
        elif 'lacp' in tbinfo['topo']['properties']['configuration'][hostname]['interfaces']['Ethernet1']:
            pc_name = 'Port-Channel' + \
                str(tbinfo['topo']['properties']['configuration'][hostname]['interfaces']['Ethernet1']['lacp'])
            bgp_info[hostname][IPV6_KEY] = \
                tbinfo['topo']['properties']['configuration'][hostname]['interfaces'][pc_name]['ipv6'].split('/')[0]
    return bgp_info


def get_all_bgp_ipv6_routes(duthost):
    # FIXME: The output of the command has a leading colon, which is not valid JSON.
    # username@dut-hostname:~$ show ipv6 route bgp json | head
    #     :
    #     {
    #     "::/0":[
    #         {
    #         "prefix":"::/0",
    #         "prefixLen":0,
    #         "protocol":"bgp",
    return json.loads(
        duthost.shell('show ipv6 route bgp json')['stdout'].strip(':')  # remove the : at the start of the string
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


def change_routes_on_peers(localhost, topo_name, ptf_ip, routes, action, peers):
    localhost.announce_routes(
        topo_name=topo_name,
        adhoc=True,
        ptf_ip=ptf_ip,
        action=action,
        routes=routes,
        peers=peers,
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


def validate_rx_tx_counters(ptf_dp, end_time, start_time):
    rx_total = sum(ptf_dp.rx_counters.values())
    tx_total = sum(ptf_dp.tx_counters.values())
    missing_pkt_cnt = tx_total - rx_total
    logger.info("Total packets received: %d", rx_total)
    logger.info("Total packets sent: %d", tx_total)
    logger.info("Missing packets: %d", missing_pkt_cnt)
    if missing_pkt_cnt > 0:
        pps = tx_total / (end_time - start_time).total_seconds()
        downtime = missing_pkt_cnt / pps
        logger.info("Estimated downtime is %s", downtime)
        pytest_assert(downtime < 0.1, "Downtime is too long")


# TODO: currently we don't need the precision of the counters
# so we don't care the safety of the counters
# make this method thread-safe if needed
def unsafe_flash_counters(ptf_dp):
    for idx in ptf_dp.rx_counters.keys():
        ptf_dp.rx_counters[idx] = 0
    for idx in ptf_dp.tx_counters.keys():
        ptf_dp.tx_counters[idx] = 0


def send_packets(terminated, ptf_dataplane, device_num, port_num, pkts, count):
    for round in range(count):
        if terminated.is_set():
            break
        for pkt in pkts:
            ptf_dataplane.send(device_num, port_num, pkt)


def test_sessions_flapping(duthost, ptfadapter, bgp_peers_info):
    pdp = ptfadapter.dataplane
    bgp_ports = [bgp_info[PORT_KEY] for bgp_info in bgp_peers_info.values()]
    random.shuffle(bgp_ports)
    flapping_ports, unflapping_ports = bgp_ports[:len(bgp_ports) // 2], bgp_ports[len(bgp_ports) // 2:]
    logger.info("Flapping ports: %s", flapping_ports)
    injection_port = int(random.choice(unflapping_ports).replace("Ethernet", ""))
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ecmp_routes = {r: v for r, v in startup_routes.items() if len(v[0]['nexthops']) > 1}
    pkts = generate_packets(
        ecmp_routes,
        duthost.facts['router_mac'],
        pdp.get_mac(0, injection_port)
    )

    # TODO: update device number for multi-servers topo by method port_to_device
    ternimated = Event()
    traffic_thread = Thread(target=send_packets, args=(ternimated, pdp, 0, injection_port, pkts, MAX_PKTS_COUNT))
    unsafe_flash_counters(pdp)
    start_time = datetime.datetime.now()
    logger.info("Starting traffic thread at %s", start_time)
    traffic_thread.start()

    try:
        duthost.shutdown_multiple(flapping_ports)
        port_shut_time = datetime.datetime.now()
        logger.info("Ports %s are shutdown at %s", flapping_ports, port_shut_time)

        nexthops_to_remove = [b[IPV6_KEY] for b in bgp_peers_info.items() if b[PORT_KEY] in flapping_ports]
        expected_routes = remove_nexthops_in_routes(startup_routes, nexthops_to_remove)
        while not compare_routes(get_all_bgp_ipv6_routes(duthost), expected_routes):
            if datetime.datetime.now() - start_time > datetime.timedelta(seconds=MAX_CONVERGENCE_WAIT_TIME):
                pytest.fail("BGP routes are not stable after ports shutdown in long time")

        logger.info("Routes are stable after ports shutdown: %s", datetime.datetime.now() - port_shut_time)
    finally:
        duthost.no_shutdown_multiple(flapping_ports)

    ternimated.set()
    traffic_thread.join()
    end_time = datetime.datetime.now()
    logger.info("Traffic thread is terminated at %s", end_time)
    validate_rx_tx_counters(pdp, end_time, start_time)


def test_unisolation(duthost, ptfadapter, bgp_peers_info):
    pdp = ptfadapter.dataplane
    bgp_ports = [bgp_info[PORT_KEY] for bgp_info in bgp_peers_info.values()]
    injection_port = int(random.choice(bgp_ports).replace("Ethernet", ""))
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

        nexthops_to_remove = [b[IPV6_KEY] for b in bgp_peers_info.values() if b[PORT_KEY] in bgp_ports]
        expected_routes = remove_nexthops_in_routes(startup_routes, nexthops_to_remove)
        while not compare_routes(get_all_bgp_ipv6_routes(duthost), expected_routes):
            if datetime.datetime.now() - ports_shut_time > datetime.timedelta(seconds=MAX_CONVERGENCE_WAIT_TIME):
                pytest.fail("BGP routes are not stable after ports shutdown in long time")

        logger.info("Routes are stable after shutdown all ports: %s", datetime.datetime.now() - ports_shut_time)

        start_time = datetime.datetime.now()
        ternimated = Event()
        # TODO: update device number for multi-servers topo by method port_to_device
        traffic_thread = Thread(target=send_packets, args=(ternimated, pdp, 0, injection_port, pkts, MAX_PKTS_COUNT))
        unsafe_flash_counters(pdp)
        traffic_thread.start()
    finally:
        duthost.no_shutdown_multiple(bgp_ports)
        ports_startup_time = datetime.datetime.now()
        while not compare_routes(get_all_bgp_ipv6_routes(duthost), startup_routes):
            if datetime.datetime.now() - ports_shut_time > datetime.timedelta(seconds=MAX_CONVERGENCE_WAIT_TIME):
                pytest.fail("BGP routes are not stable after ports unshut in long time")

        logger.info("Routes are stable after startup all ports: %s", datetime.datetime.now() - ports_startup_time)

    ternimated.set()
    traffic_thread.join()
    end_time = datetime.datetime.now()
    logger.info("Traffic thread is terminated at %s", end_time)
    validate_rx_tx_counters(pdp, end_time, start_time)


def test_nexthop_group_member_scale(duthost, ptfadapter, localhost, tbinfo, bgp_peers_info):
    topo_name = tbinfo['topo']['name']
    ptf_ip = tbinfo['ptf_ip']
    pdp = ptfadapter.dataplane
    bgp_ports = [bgp_info[PORT_KEY] for bgp_info in bgp_peers_info.values()]
    injection_port = int(random.choice(bgp_ports).replace("Ethernet", ""))
    logger.info("Injection port: %s", injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ecmp_routes = {r: v for r, v in startup_routes.items() if len(v[0]['nexthops']) > 1}
    pkts = generate_packets(
        ecmp_routes,
        duthost.facts['router_mac'],
        pdp.get_mac(0, injection_port)
    )
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6']
    picked_routes = [(r, nhipv6, None) for r in random.sample(ecmp_routes.keys(), len(ecmp_routes) // 2)]

    bgp_peers = bgp_peers_info.keys()
    random_half_peers = random.sample(bgp_peers, len(bgp_peers) // 2)

    start_time = datetime.datetime.now()
    ternimated = Event()
    # TODO: update device number for multi-servers topo by method port_to_device
    traffic_thread = Thread(target=send_packets, args=(ternimated, pdp, 0, injection_port, pkts, MAX_PKTS_COUNT))
    unsafe_flash_counters(pdp)
    traffic_thread.start()
    try:
        change_routes_on_peers(localhost, topo_name, ptf_ip, picked_routes, ACTION_WITHDRAW, random_half_peers)
        withdraw_time = datetime.datetime.now()

        nexthops_to_remove = [b[IPV6_KEY] for n, b in bgp_peers_info.items() if n in random_half_peers]
        expected_routes = dict(startup_routes)
        expected_routes.update(
            remove_nexthops_in_routes(picked_routes, nexthops_to_remove)
        )
        while not compare_routes(get_all_bgp_ipv6_routes(duthost), expected_routes):
            if datetime.datetime.now() - withdraw_time > datetime.timedelta(seconds=MAX_CONVERGENCE_WAIT_TIME):
                pytest.fail("BGP routes are not stable in long time")

        logger.info("Routes are stable after routes withdrawn: %s", datetime.datetime.now() - withdraw_time)

        ternimated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        logger.info("Traffic thread is terminated at %s", end_time)
        validate_rx_tx_counters(pdp, end_time, start_time)

    finally:
        start_time = datetime.datetime.now()
        # TODO: update device number for multi-servers topo by method port_to_device
        ternimated = Event()
        traffic_thread = Thread(target=send_packets, args=(ternimated, pdp, 0, injection_port, pkts, MAX_PKTS_COUNT))
        unsafe_flash_counters(pdp)
        traffic_thread.start()
        change_routes_on_peers(localhost, topo_name, ptf_ip, picked_routes, ACTION_ANNOUNCE, random_half_peers)
        announce_time = datetime.datetime.now()

        while not get_all_bgp_ipv6_routes(duthost) == startup_routes:
            if datetime.datetime.now() - announce_time > datetime.timedelta(seconds=MAX_CONVERGENCE_WAIT_TIME):
                pytest.fail("BGP routes are not stable in long time")

        logger.info("Routes are stable after routes announcement: %s", datetime.datetime.now() - announce_time)

        ternimated.set()
        traffic_thread.join()
        end_time = datetime.datetime.now()
        logger.info("Traffic thread is killed at %s", end_time)
        validate_rx_tx_counters(pdp, end_time, start_time)
