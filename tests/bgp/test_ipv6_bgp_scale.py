import datetime
import pytest
import logging
import json
import ipaddress
import random
from threading import Thread
from tests.common.helpers.assertions import pytest_assert
from ptf.testutils import simple_icmpv6_packet, send_packet

pytestmark = [
    pytest.mark.topology(
        't0-isolated-d2u254s1', 't0-isolated-d2u254s2', 't0-isolated-d2u510',
        't1-isolated-d254u2s1', 't1-isolated-d254u2s2', 't1-isolated-d510u2'
    ),
]

logger = logging.getLogger(__name__)


ACTION_ANNOUNCE = 'announce'
ACTION_WITHDRAW = 'withdraw'


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
        pkts.append(pkt)

    return pkts


def change_routes_on_peers(action, routes, peers):
    pass


def are_bgp_routes_stable():
    pass


def get_all_bgp_ports():
    pass


def get_all_bgp_peers():
    pass


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
    ptf_dp.flush_counters()


def test_sessions_flapping(duthost, ptfadapter):
    pdp = ptfadapter.dataplane
    bgp_ports = get_all_bgp_ports()
    flapping_ports = random.choice(bgp_ports, len(bgp_ports) // 2)
    logger.info("Flapping ports: %s", flapping_ports)
    unflapping_ports = bgp_ports - flapping_ports
    injection_port = random.choice(unflapping_ports, 1)
    logger.info("Injection port: %s", injection_port)
    injection_tuple = (pdp.port_to_device(injection_port), injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ipv6_routes = {r: v for r, v in startup_routes if len(v[0]['nexthops']) > 1}
    pkts = generate_packets(
        ipv6_routes,
        duthost.facts['router_mac'],
        pdp.get_mac()
    )

    traffic_thread = Thread(target=send_packet, args=(ptfadapter, injection_tuple, pkts, float("inf")))
    start_time = datetime.datetime.now()
    logger.info("Starting traffic thread at %s", start_time)
    traffic_thread.start()

    try:
        duthost.shutdown_multiple(flapping_ports)
        logger.info("Ports %s are shutdown at %s", flapping_ports, datetime.datetime.now())

        while not are_bgp_routes_stable():
            if datetime.datetime.now() - start_time > datetime.timedelta(seconds=60):
                pytest.fail("BGP routes are not stable after ports shutdown in long time")

        logger.info("Routes are stable after ports shutdown at %s", datetime.datetime.now())
    finally:
        duthost.no_shutdown_multiple(flapping_ports)
        logger.info("Ports %s are no shutdown at %s", flapping_ports, datetime.datetime.now())

    traffic_thread.kill()
    end_time = datetime.datetime.now()
    logger.info("Traffic thread is killed at %s", end_time)
    validate_rx_tx_counters(pdp, end_time, start_time)


def test_unisolation(duthost, ptfadapter):
    pdp = ptfadapter.dataplane
    bgp_ports = get_all_bgp_ports()
    injection_port = random.choice(bgp_ports, 1)
    logger.info("Injection port: %s", injection_port)
    injection_tuple = (pdp.port_to_device(injection_port), injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ipv6_routes = {r: v for r, v in startup_routes if len(v[0]['nexthops']) > 1}
    pkts = generate_packets(
        ipv6_routes,
        duthost.facts['router_mac'],
        pdp.get_mac()
    )

    try:
        duthost.shutdown_multiple(bgp_ports)
        ports_shut_time = datetime.datetime.now()

        while not are_bgp_routes_stable():
            if datetime.datetime.now() - ports_shut_time > datetime.timedelta(seconds=60):
                pytest.fail("BGP routes are not stable after ports shutdown in long time")

        start_time = datetime.datetime.now()
        traffic_thread = Thread(target=send_packet, args=(ptfadapter, injection_tuple, pkts, float("inf")))
        traffic_thread.start()

    finally:
        duthost.no_shutdown_multiple(bgp_ports)
        while not are_bgp_routes_stable():
            if datetime.datetime.now() - ports_shut_time > datetime.timedelta(seconds=60):
                pytest.fail("BGP routes are not stable after ports unshut in long time")

    traffic_thread.kill()
    end_time = datetime.datetime.now()
    logger.info("Traffic thread is killed at %s", end_time)
    validate_rx_tx_counters(pdp, end_time, start_time)


def test_nexthop_group_member_scale(duthost, ptfadapter):
    pdp = ptfadapter.dataplane
    bgp_ports = get_all_bgp_ports()
    injection_port = random.choice(bgp_ports, 1)
    logger.info("Injection port: %s", injection_port)
    injection_tuple = (pdp.port_to_device(injection_port), injection_port)

    startup_routes = get_all_bgp_ipv6_routes(duthost)
    ipv6_routes = {r: v for r, v in startup_routes if len(v[0]['nexthops']) > 1}
    pkts = generate_packets(
        ipv6_routes,
        duthost.facts['router_mac'],
        pdp.get_mac()
    )
    random_half_ipv6_routes = random.choice(ipv6_routes, len(ipv6_routes) // 2)

    bgp_peers = get_all_bgp_peers()
    random_half_peers = random.choice(bgp_peers, len(bgp_peers) // 2)

    start_time = datetime.datetime.now()
    traffic_thread = Thread(target=send_packet, args=(ptfadapter, injection_tuple, pkts, float("inf")))
    traffic_thread.start()
    try:
        change_routes_on_peers(ACTION_WITHDRAW, random_half_ipv6_routes, random_half_peers)
        withdraw_time = datetime.datetime.now()

        while not are_bgp_routes_stable():
            if datetime.datetime.now() - withdraw_time > datetime.timedelta(seconds=60):
                pytest.fail("BGP routes are not stable after ports shutdown in long time")

        traffic_thread.kill()
        end_time = datetime.datetime.now()
        logger.info("Traffic thread is killed at %s", end_time)
        validate_rx_tx_counters(pdp, end_time, start_time)

    finally:
        start_time = datetime.datetime.now()
        traffic_thread = Thread(target=send_packet, args=(ptfadapter, injection_tuple, pkts, float("inf")))
        traffic_thread.start()
        change_routes_on_peers(ACTION_ANNOUNCE, random_half_ipv6_routes, random_half_peers)
        announce_time = datetime.datetime.now()

        while not are_bgp_routes_stable():
            if datetime.datetime.now() - announce_time > datetime.timedelta(seconds=60):
                pytest.fail("BGP routes are not stable after ports shutdown in long time")

        traffic_thread.kill()
        end_time = datetime.datetime.now()
        logger.info("Traffic thread is killed at %s", end_time)
        validate_rx_tx_counters(pdp, end_time, start_time)
