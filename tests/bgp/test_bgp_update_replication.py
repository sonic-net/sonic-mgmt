import time
import math
import datetime
from typing import Any
import pytest
import logging
import textfsm
from tabulate import tabulate

from tests.common.helpers.bgp import BGPNeighbor
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.bgp.bgp_helpers import is_neighbor_sessions_established

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, is_ipv6_only_topology

logger = logging.getLogger(__name__)

# Fixture params
PEER_COUNT = 16
WAIT_TIMEOUT = 120

pytestmark = [
    pytest.mark.topology('t0', 't1', 't2', 'lt2', 'ft2'),
    pytest.mark.disable_loganalyzer
]


'''
    Helper functions
'''


def generate_routes(num_routes, nexthop, is_ipv6=False):
    '''
    Generator which yields specified amount of dummy routes, in a dict that the route injector
    can use to announce and withdraw these routes.
    '''
    if is_ipv6:
        SUBNET_TMPL = "2001:db8:{first_iter:x}:{second_iter:x}::/64"
    else:
        SUBNET_TMPL = "10.{first_iter}.{second_iter}.0/24"
    loop_iterations = math.floor(num_routes ** 0.5)

    for first_iter in range(1, loop_iterations + 1):
        for second_iter in range(1, loop_iterations + 1):
            yield {
                "prefix": SUBNET_TMPL.format(first_iter=first_iter, second_iter=second_iter),
                "nexthop": nexthop
            }


def measure_stats(dut, is_ipv6=False):
    '''
    Validates that the provided DUT is responsive during test, and that device stats do not
    exceed specified thresholds, and if so, returns a dictionary containing device statistics
    at the time of function call.
    '''
    PROC_TEMPLATE = "./bgp/templates/show_proc_extended.textfsm"
    BGP_SUM_TEMPLATE = "./bgp/templates/bgp_summary_extended.textfsm"

    # Time in seconds commands should execute within
    responsive_threshold = 2

    time_before_cmd = time.process_time()

    proc_cpu = dut.shell("show processes cpu | head -n 10", module_ignore_errors=True)['stdout']
    time_first_cmd = time.process_time()

    bgp_cmd = f"show ip{'v6' if is_ipv6 else ''} bgp summary | grep memory"
    bgp_sum = dut.shell(bgp_cmd, module_ignore_errors=True)['stdout']
    time_second_cmd = time.process_time()

    num_cores = dut.shell('cat /proc/cpuinfo | grep "cpu cores" | uniq', module_ignore_errors=True)['stdout']
    time_third_cmd = time.process_time()

    # Check that DUT remains responsive - average the response time for each command
    response_times = [
        time_first_cmd - time_before_cmd,
        time_second_cmd - time_first_cmd,
        time_third_cmd - time_second_cmd
    ]
    average_response_time = sum(response_times) / len(response_times)

    pytest_assert(
        responsive_threshold > average_response_time,
        f"SSH session took longer than average of {responsive_threshold} sec to respond"
    )

    with open(PROC_TEMPLATE) as template:
        fsm = textfsm.TextFSM(template)
        parsed_proc = fsm.ParseTextToDicts(proc_cpu)

    with open(BGP_SUM_TEMPLATE) as template:
        fsm = textfsm.TextFSM(template)
        parsed_bgp_sum = fsm.ParseTextToDicts(bgp_sum)

    stats: dict[str, Any] = {"timestamp": datetime.datetime.now().time()}
    stats.update(parsed_proc[0])
    stats.update(parsed_bgp_sum[0])

    cpu_usage = float(stats['av1']) * 100 / float(num_cores.split()[-1])
    mem_usage = (float(stats["mem_total"]) - float(stats["mem_free"])) * 100 / float(stats["mem_total"])

    stats.update({
        'cpu_usage': cpu_usage,
        'mem_usage': mem_usage
    })

    logger.debug(stats)

    return stats


@pytest.fixture
def setup_duthost_intervals(duthost):
    '''
    Fixture to allow for dynamic interval definitions for each interval, based on duthost facts.
    The default is left relatively long to ensure that it passes on all platforms.

    Returns a list of float values.
    '''
    DEFAULT_INTERVALS = [10.0, 9.0, 8.0]
    PLATFORM_INTERVALS = {
        'mellanox': [4.0, 3.5, 3.0],
        'arista': [5.0, 4.5, 4.0]
    }
    dut_platform = duthost.facts["platform"]

    for platform, intervals in PLATFORM_INTERVALS.items():
        if dut_platform not in platform:
            continue
        logger.info(f"'{platform}' found in platform {dut_platform}, intervals {intervals} selected")
        return intervals

    logger.info(f"No matching conditions for platform {dut_platform}, selecting default intervals {DEFAULT_INTERVALS}")
    return DEFAULT_INTERVALS


@pytest.fixture
def setup_bgp_peers(
    duthost,
    tbinfo,
    ptfhost,
    setup_interfaces,
    is_dualtor,
    is_quagga
):
    ASN_BASE = 61000
    PORT_BASE = 11000
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    dut_asn = mg_facts["minigraph_bgp_asn"]
    dut_type = mg_facts["minigraph_devices"][duthost.hostname]["type"]
    if dut_type in ["ToRRouter", "SpineRouter", "BackEndToRRouter", "LowerSpineRouter"]:
        neigh_type = "LeafRouter"
    elif dut_type == "UpperSpineRouter":
        neigh_type = "LowerSpineRouter"
    else:
        neigh_type = "ToRRouter"

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
            is_ipv6_only=is_ipv6_only_topology(tbinfo),
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
    duthost,
    tbinfo,
    setup_bgp_peers,
    setup_duthost_intervals,
):
    NUM_ROUTES = 10_000
    bgp_peers: list[BGPNeighbor] = setup_bgp_peers
    duthost_intervals: list[float] = setup_duthost_intervals
    is_ipv6 = is_ipv6_only_topology(tbinfo)

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

    results = [measure_stats(duthost, is_ipv6)]
    base_rib = int(results[0]["num_rib"])
    min_expected_rib = base_rib + NUM_ROUTES
    max_expected_rib = base_rib + (2 * NUM_ROUTES)

    # Inject and withdraw routes with a specified interval in between iterations
    for interval in duthost_intervals:
        # Repeat 20 times
        for _ in range(20):
            # Inject 10000 routes
            route_injector.announce_routes_batch(
                generate_routes(
                    num_routes=NUM_ROUTES, nexthop=route_injector.ip,
                    is_ipv6=is_ipv6
                )
            )
            time.sleep(interval)

            # Measure after injection
            results.append(measure_stats(duthost, is_ipv6))

            # Validate all routes have been received
            curr_num_rib = int(results[-1]["num_rib"])
            pytest_assert(
                curr_num_rib >= min_expected_rib,
                f"All routes have not been received: current '{curr_num_rib}', expected: '{min_expected_rib}'"
            )
            if curr_num_rib < max_expected_rib:
                logger.warning(
                    f"All routes have not been announced: current '{curr_num_rib}', expected: '{max_expected_rib}'"
                )

            # Remove routes
            route_injector.withdraw_routes_batch(
                generate_routes(
                    num_routes=NUM_ROUTES, nexthop=route_injector.ip,
                    is_ipv6=is_ipv6
                )
            )
            time.sleep(interval)

            # Measure after removal
            results.append(measure_stats(duthost, is_ipv6))

            # Validate all routes have been withdrawn
            curr_num_rib = int(results[-1]["num_rib"])
            pytest_assert(
                curr_num_rib <= min_expected_rib,
                f"All withdrawls have not been received: current '{curr_num_rib}', expected: '{min_expected_rib}'"
            )
            if curr_num_rib > base_rib:
                logger.warning(
                    f"All announcements have not been withdrawn: current '{curr_num_rib}', expected: '{base_rib}'"
                )

    results.append(measure_stats(duthost, is_ipv6))

    # Output results as TSV for analysis in other programs
    results_tsv = tabulate(results, headers="keys", tablefmt="tsv")

    # Output results in human-readable format as well
    results_table = tabulate(results, headers="keys")

    logger.info('TSV: \n' + results_tsv)
    logger.info('Results: \n' + results_table)
