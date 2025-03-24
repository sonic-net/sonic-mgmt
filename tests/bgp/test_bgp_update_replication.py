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
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# Fixture params
PEER_COUNT = 16
WAIT_TIMEOUT = 120

# General constants
ASN_BASE = 61000
PORT_BASE = 11000
SUBNET_TMPL = "10.{first_iter}.{second_iter}.0/24"


'''
    Helper functions
'''


def generate_routes(num_routes, nexthop):
    '''
    Generator which yields specified amount of dummy routes, in a dict that the route injector
    can use to announce and withdraw these routes.
    '''
    loop_iterations = math.floor(num_routes ** 0.5)

    for first_iter in range(1, loop_iterations + 1):
        for second_iter in range(1, loop_iterations + 1):
            yield {
                "prefix": SUBNET_TMPL.format(first_iter=first_iter, second_iter=second_iter),
                "nexthop": nexthop
            }


def measure_stats(dut):
    '''
    Validates that the provided DUT is responsive during test, and that device stats do not
    exceed specified thresholds, and if so, returns a dictionary containing device statistics
    at the time of function call.
    '''
    proc_template = "./bgp/templates/show_proc_extended.textfsm"
    bgp_sum_template = "./bgp/templates/bgp_summary_extended.textfsm"
    # Time in seconds commands should execute within
    responsive_threshold = 2
    # Percentage thresholds
    cpu_threshold = 90.0
    mem_threshold = 90.0

    time_before_cmd = time.process_time()

    proc_cpu = dut.shell("show processes cpu | head -n 10", module_ignore_errors=True)['stdout']
    time_first_cmd = time.process_time()

    bgp_sum = dut.shell("show ip bgp summary | grep memory", module_ignore_errors=True)['stdout']
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

    with open(proc_template) as template:
        fsm = textfsm.TextFSM(template)
        parsed_proc = fsm.ParseTextToDicts(proc_cpu)

    with open(bgp_sum_template) as template:
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

    # Check that CPU usage isn't excessive
    pytest_assert(
        cpu_threshold > cpu_usage,
        f"CPU utilisation has reached {cpu_usage}, which is above threshold of {cpu_threshold}"
    )

    # Check that memory usage isn't excessive
    pytest_assert(
        mem_threshold > mem_usage,
        f"Memory utilisation has reached {mem_usage}, which is above threshold of {mem_threshold}"
    )

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
    prev_num_rib = int(results[0]["num_rib"])

    # Inject and withdraw routes with a specified interval in between iterations
    for interval in [3.0, 1.0, 0.5]:
        # Repeat 20 times
        for _ in range(20):
            # Inject 10000 routes
            num_routes = 10_000
            route_injector.announce_routes_batch(generate_routes(num_routes=num_routes, nexthop=route_injector.ip))

            time.sleep(interval)

            # Measure after injection
            results.append(measure_stats(duthost))

            # Validate all routes have been received
            curr_num_rib = int(results[-1]["num_rib"])
            expected = prev_num_rib + (2 * num_routes)
            pytest_assert(
                curr_num_rib == expected,
                f"All routes have not been received: current '{curr_num_rib}', expected: '{expected}'"
            )
            prev_num_rib = curr_num_rib

            # Remove routes
            route_injector.withdraw_routes_batch(generate_routes(num_routes=num_routes, nexthop=route_injector.ip))

            time.sleep(interval)

            # Measure after removal
            results.append(measure_stats(duthost))

            # Validate all routes have been withdrawn
            curr_num_rib = int(results[-1]["num_rib"])
            expected = prev_num_rib - (2 * num_routes)
            pytest_assert(
                curr_num_rib == expected,
                f"All routes have not been withdrawn: current '{curr_num_rib}', expected: '{expected}'"
            )
            prev_num_rib = curr_num_rib

    results.append(measure_stats(duthost))

    # Output results as TSV for analysis in other programs
    results_tsv = tabulate(results, headers="keys", tablefmt="tsv")

    # Output results in human-readable format as well
    results_table = tabulate(results, headers="keys")

    logger.info('TSV: \n' + results_tsv)
    logger.info('Results: \n' + results_table)
