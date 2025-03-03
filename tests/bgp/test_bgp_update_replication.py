import time
import math
import datetime
import pytest
import logging
import textfsm

from tests.common.helpers.bgp import BGPNeighbor
from tests.common.helpers.constants import DEFAULT_NAMESPACE
# TODO: move to helpers?
from tests.bgp.test_bgp_update_timer import is_neighbor_sessions_established
# END TODO

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# Fixture params
PEER_COUNT = 1  # 6
WAIT_TIMEOUT = 120

# General constants
ASN_BASE = 61000
PORT_BASE = 11000
SUBNET_TMPL = "10.{second_iter}.{first_iter}.0/24"


'''
    Helper functions
'''


def next_route(num_routes, nexthop):
    loop_iterations = math.floor(num_routes ** 0.5)

    for first_iter in range(1, loop_iterations + 1):
        for second_iter in range(1, loop_iterations + 1):
            yield {
                "prefix": SUBNET_TMPL.format(first_iter=first_iter, second_iter=second_iter),
                "nexthop": nexthop
            }


def measure_stats(dut):
    proc_template = "./bgp/templates/show_proc_extended.textfsm"
    bgp_sum_template = "./bgp/templates/bgp_summary_extended.textfsm"

    proc_cpu = dut.shell("show processes cpu | head -n 10", module_ignore_errors=True)['stdout']
    bgp_sum = dut.shell("show ip bgp summary | grep memory", module_ignore_errors=True)['stdout']

    with open(proc_template) as template:
        fsm = textfsm.TextFSM(template)
        parsed_proc = fsm.ParseTextToDicts(proc_cpu)

    with open(bgp_sum_template) as template:
        fsm = textfsm.TextFSM(template)
        parsed_bgp_sum = fsm.ParseTextToDicts(bgp_sum)

    stats = {"timestamp": datetime.datetime.now().time()}
    stats.update(parsed_proc[0])
    stats.update(parsed_bgp_sum[0])

    return stats


@pytest.fixture
def setup_bgp_peers(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    tbinfo,
    ptfhost,
    setup_interfaces,
    is_dualtor,
    is_quagga
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    dut_asn = mg_facts["minigraph_bgp_asn"]
    dut_type = mg_facts["minigraph_devices"][duthost.hostname]["type"]
    neigh_type = "LeafRouter" if dut_type in ["ToRRouter", "SpineRouter", "BackEndToRRouter"] else "ToRRouter"

    # Establish peers - 1 route injector, the rest receivers
    connections = setup_interfaces
    bgp_peers: list[BGPNeighbor] = []

    # Validate that the expected number of connections were established
    pytest_assert(
        len(connections) == PEER_COUNT,
        f"Incorrect number of bgp peers established: {len(bgp_peers)} exist, {PEER_COUNT} expected"
    )

    # Validate that all connection namespaces are the same
    connection_ns_set = {connection.get("namespace") for connection in connections}
    pytest_assert(
        len(connection_ns_set) == 1,
        f"Multiple namespaces present: {connection_ns_set}"
    )

    for i, connection in enumerate(connections):
        peer_asn = ASN_BASE + i
        peer_port = PORT_BASE + i
        connection_namespace = connection.get("namespace", DEFAULT_NAMESPACE)

        peer = BGPNeighbor(
            duthost=duthost,
            ptfhost=ptfhost,
            name=f"peer{i}",
            neighbor_ip=connection["neighbor_addr"].split("/")[0],
            neighbor_asn=peer_asn,
            dut_ip=connection["local_addr"].split("/")[0],
            dut_asn=dut_asn,
            port=peer_port,
            neigh_type=neigh_type,
            namespace=connection_namespace,
            is_multihop=is_quagga or is_dualtor,
            is_passive=False
        )

        bgp_peers.append(peer)

    # Start sessions
    for peer in bgp_peers:
        peer.start_session()

    yield bgp_peers

    # End sessions
    for peer in bgp_peers:
        peer.stop_session()


'''
    Tests
'''


def test_bgp_update_replication(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    setup_bgp_peers,
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    bgp_peers: list[BGPNeighbor] = setup_bgp_peers

    # Ensure new sessions are ready
    if not wait_until(
        WAIT_TIMEOUT,
        5,
        20,
        lambda: is_neighbor_sessions_established(duthost, bgp_peers),
    ):
        pytest.fail(f"Could not establish the following bgp sessions: {bgp_peers}")

    # Extract injector and receivers
    route_injector = bgp_peers[0]
    route_receivers = bgp_peers[1:PEER_COUNT]

    logger.info(f"Route injector: '{route_injector}', route receivers: '{route_receivers}'")

    results = [measure_stats(duthost)]

    # Inject routes
    for interval in [3.0, 1.0, 0.5]:
        # Repeat 1000 times
        for _ in range(3):
            # Inject 10000 routes
            for route in next_route(num_routes=10_000, nexthop=route_injector.ip):
                route_injector.announce_route(route)

            # Measure
            results.append(measure_stats(duthost))

            # Remove routes
            for route in next_route(num_routes=10_000, nexthop=route_injector.ip):
                route_injector.withdraw_route(route)

            results.append(measure_stats(duthost))

        time.sleep(interval)

    results.append(measure_stats(duthost))

    logger.debug(results)
