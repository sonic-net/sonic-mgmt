"""
Test utils used by the link flap tests.
"""
import logging
import random

from tests.common.platform.device_utils import fanout_switch_port_lookup, __get_dut_if_status

logger = logging.getLogger(__name__)


def __build_candidate_list(candidates, fanout, fanout_port, dut_port, status):
    """
    Add candidates to list for link flap test.

    Args:
        candidates: List of tuple with DUT's port,
        fanout port and fanout
        fanout: Fanout host object
        fanout_port: Port of fanout
        dut_port: Port of DUT
        completeness_level: Completeness level.

    Returns:
        A list of tuple with DUT's port, fanout port
        and fanout
    """
    if not fanout or not fanout_port:
        logger.info("Skipping port {} that is not found in connection graph".format(dut_port))
    elif status[dut_port]['admin_state'] == 'down':
        logger.info("Skipping port {} that is admin down".format(dut_port))
    else:
        candidates.append((dut_port, fanout, fanout_port))


def build_test_candidates(dut, fanouthosts, port, completeness_level=None):
    """
    Find test candidates for link flap test.

    Args:
        dut: DUT host object
        fanouthosts: List of fanout switch instances.
        port: port, when port == 'unknown' or 'all_ports'
              candidate will be all ports. A warning  will
              be generated if the port == 'unknown'.
              caller can use 'all_ports' explicitly to mute
              the warning.
        completeness_level: Completeness level.

    Returns:
        A list of tuple with DUT's port, fanout port
        and fanout
    """
    candidates = []

    if port not in ['unknown', 'all_ports']:
        status = __get_dut_if_status(dut, port)
        fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut.hostname, port)
        __build_candidate_list(candidates, fanout, fanout_port, port, status)
    else:
        # Build the full list
        if port == 'unknown':
            logger.warning("Failed to get ports enumerated as parameter. Fall back to test all ports")
        status = __get_dut_if_status(dut)

        for dut_port in list(status.keys()):
            fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut.hostname, dut_port)
            __build_candidate_list(candidates, fanout, fanout_port, dut_port, status)

        if completeness_level == 'debug':
            candidates = random.sample(candidates, 1)

    return candidates


def check_portchannel_status(dut, dut_port_channel, exp_state, verbose=False):
    """
    Check portchannel status on the DUT.

    Args:
        dut: DUT host object
        dut_port_channel: Portchannel of DUT
        exp_state: State of DUT's port ('up' or 'down')
        verbose: Logging port state.

    Returns:
        Bool value which confirm port state
    """
    status = __get_dut_if_status(dut, dut_port_channel)[dut_port_channel]
    if verbose:
        logger.debug("Portchannel status : %s", status)
    return status['oper_state'] == exp_state


def check_orch_cpu_utilization(dut, orch_cpu_threshold):
    """
    Compare orchagent CPU utilization

    Args:
        dut: DUT host object
        orch_cpu_threshold: orch cpu threshold
    """
    orch_cpu = dut.shell("COLUMNS=512 show processes cpu | grep orchagent | awk '{print $9}'")["stdout_lines"]
    for line in orch_cpu:
        if int(float(line)) > orch_cpu_threshold:
            return False
    return True


def check_bgp_routes(dut, start_time_ipv4_route_counts, start_time_ipv6_route_counts):
    """
    Make Sure all ip routes are relearned with jitter of ~MAX_DIFF

    Args:
        dut: DUT host object
        start_time_ipv4_route_counts: IPv4 route counts at start
        start_time_ipv6_route_counts: IPv6 route counts at start
    """
    MAX_DIFF = 5

    sumv4, sumv6 = dut.get_ip_route_summary(skip_kernel_tunnel=True)
    totalsv4 = sumv4.get('Totals', {})
    totalsv6 = sumv6.get('Totals', {})
    routesv4 = totalsv4.get('routes', 0)
    routesv6 = totalsv6.get('routes', 0)
    logger.info("IPv4 routes: start {} end {}, summary {}".format(start_time_ipv4_route_counts, routesv4, sumv4))
    logger.info("IPv6 routes: start {} end {}, summary {}".format(start_time_ipv6_route_counts, routesv6, sumv6))

    incr_ipv4_route_counts = abs(int(float(start_time_ipv4_route_counts)) - int(float(routesv4)))
    incr_ipv6_route_counts = abs(int(float(start_time_ipv6_route_counts)) - int(float(routesv6)))
    return incr_ipv4_route_counts < MAX_DIFF and incr_ipv6_route_counts < MAX_DIFF
