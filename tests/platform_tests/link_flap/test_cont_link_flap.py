"""
Tests the continuous link flap in SONiC.

Parameters:
    --orch_cpu_threshold <port> (int): Which port you want the test to send traffic
        to. Default is 3.
"""

import logging
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common import port_toggle
from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates, \
    check_orch_cpu_utilization, check_bgp_routes, get_avg_redis_mem_usage, \
    get_frr_daemon_memory_usage, log_redis_state, \
    validate_frr_daemon_memory_increase, validate_redis_memory_increase, wait_for_memory_to_settle
from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.platform.device_utils import toggle_one_link
from tests.common.plugins.test_completeness import CompletenessLevel

pytestmark = [
    pytest.mark.disable_route_check,
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.supported_completeness_level(CompletenessLevel.confident, CompletenessLevel.thorough)
]


class TestContLinkFlap(object):
    """
    TestContLinkFlap class for continuous link flap
    """

    @staticmethod
    def get_candidates(duthost, fanouthosts, completeness_level="confident"):
        candidates = build_test_candidates(duthost, fanouthosts, 'all_ports', completeness_level=completeness_level)
        pytest_require(candidates, "Didn't find any port that is admin up and present in the connection graph")
        logging.info("Randomly selected candidates: %s", candidates)
        return candidates

    def test_cont_link_flap(self, request, duthosts, nbrhosts, enum_rand_one_per_hwsku_frontend_hostname,
                            fanouthosts, bring_up_dut_interfaces, tbinfo):
        """
        Validates that continuous link flap works as expected

        Test steps:
            1.) Flap randomly sampled interfaces one by one in 1-3 iteration
                to cause BGP Flaps.
            2.) Flap randomly sampled interfaces on peer (FanOutLeaf) one by one 1-3 iteration
                to cause BGP Flaps.
            3.) Watch for memory (show system-memory), FRR daemons memory(vtysh -c "show memory bgp/zebra"),
                orchagent CPU Utilization and Redis_memory.

        Pass Criteria: All routes must be re-learned with < 10% increase in Redis/FRR memory usage and
            ORCH agent CPU consumption below threshold after 3 mins after stopping flaps.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        duthost.command("sonic-clear arp")
        orch_cpu_threshold = request.config.getoption("--orch_cpu_threshold")
        completeness_level = request.config.getoption("--completeness_level")
        if not completeness_level or completeness_level not in ["confident", "thorough"]:
            completeness_level = "confident"

        # Record memory status at start
        memory_output = duthost.shell("show system-memory")["stdout"]
        logging.info("Memory Status at start: %s", memory_output)

        # Record Redis Memory at start
        start_time_redis_memory = get_avg_redis_mem_usage(duthost, 5, 5)
        logging.info("Redis Memory: %f M", start_time_redis_memory)
        log_redis_state(duthost, "start")

        # Record ipv4 route counts at start
        sumv4, sumv6 = duthost.get_ip_route_summary(skip_kernel_tunnel=True, skip_kernel_linkdown=True)
        logging.debug("sumv4  {} ".format(sumv4))
        logging.debug("sumv6  {} ".format(sumv6))

        totalsv4 = sumv4.get('Totals', {})
        totalsv6 = sumv6.get('Totals', {})
        start_time_ipv4_route_counts = totalsv4.get('routes', 0)
        start_time_ipv6_route_counts = totalsv6.get('routes', 0)
        logging.info("IPv4 routes: start {}, summary {}".format(start_time_ipv4_route_counts, sumv4))
        logging.info("IPv6 routes: start {}, summary {}".format(start_time_ipv6_route_counts, sumv6))

        # Record FRR daemons memory status at start
        frr_demons_to_check = ['bgpd', 'zebra']
        start_time_frr_daemon_memory = {}
        for daemon in frr_demons_to_check:
            start_time_frr_daemon_memory[daemon] = get_frr_daemon_memory_usage(duthost, daemon)
            logging.info(f"{daemon} memory usage at start: \n%s", start_time_frr_daemon_memory[daemon])

        # Make Sure Orch CPU < orch_cpu_threshold before starting test.
        logging.info("Make Sure orchagent CPU utilization is less that %d before link flap", orch_cpu_threshold)
        if 't2' in tbinfo['topo']['name']:
            # In T2 topology, if the test is run on uplink LC first, it needs more time for the CPU to cool down
            # More details in bug 16186
            wait_timeout = 600
        else:
            wait_timeout = 100
        pytest_assert(wait_until(wait_timeout, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                      "Orch CPU utilization {} > orch cpu threshold {} before link flap"
                      .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                              orch_cpu_threshold))

        # Flap randomly sampled interfaces one by one on DUT
        for iteration in range(3):
            logging.info("%d Iteration flap randomly sampled interfaces one by one on DUT", iteration + 1)
            selected_candidates = self.get_candidates(duthost, fanouthosts, completeness_level=completeness_level)
            selected_ports = [dut_port for dut_port, fanout, fanout_port in selected_candidates]
            port_toggle(duthost, tbinfo, ports=selected_ports, wait_after_ports_up=30, watch=True)

        # Flap randomly sampled interfaces one by one on Peer Device
        for iteration in range(3):
            logging.info("%d Iteration flap randomly sampled interfaces one by one on Peer Device", iteration + 1)
            selected_candidates = self.get_candidates(duthost, fanouthosts, completeness_level=completeness_level)
            for dut_port, fanout, fanout_port in selected_candidates:
                toggle_one_link(duthost, dut_port, fanout, fanout_port, watch=True)

        # Make Sure all ipv4/ipv6 routes are relearned with jitter of ~5
        if not wait_until(120, 2, 0, check_bgp_routes, duthost,
                          start_time_ipv4_route_counts, start_time_ipv6_route_counts):
            endv4, endv6 = duthost.get_ip_route_summary(skip_kernel_tunnel=True, skip_kernel_linkdown=True)
            failmsg = []
            failmsg.append("IP routes are not equal after link flap: before ipv4 {} ipv6 {}, after ipv4 {} ipv6 {}"
                           .format(sumv4, sumv6, endv4, endv6))
            config_facts = duthost.get_running_config_facts()
            nei_meta = config_facts.get('DEVICE_NEIGHBOR_METADATA', {})
            dut_type = None
            dev_meta = config_facts.get('DEVICE_METADATA', {})
            if "localhost" in dev_meta and "type" in dev_meta["localhost"]:
                dut_type = dev_meta["localhost"]["type"]

            for k, v in list(nei_meta.items()):
                if v['type'] in ['SmartCable', 'Server', 'Asic'] or dut_type == v['type']:
                    continue
                nbrhost = nbrhosts[k]['host']
                if isinstance(nbrhost, EosHost):
                    res = nbrhost.eos_command(commands=['show ip bgp sum'])
                    failmsg.append(res['stdout'])
                    res = nbrhost.eos_command(commands=['show ipv6 bgp sum'])
                    failmsg.append(res['stdout'])
                elif isinstance(nbrhost, SonicHost):
                    res = nbrhost.command('vtysh -c "show ip bgp sum"')
                    failmsg.append(res['stdout'])
                    res = nbrhost.command('vtysh -c "show ipv6 bgp sum"')
                    failmsg.append(res['stdout'])
                else:
                    pass

            pytest.fail(str(failmsg))

        # Diagnostic snapshot before the bundled memory-settle poll. The poll
        # below replaces the previous fixed 30s sleep + sequential FRR / Redis
        # checks; it samples both metrics each iteration and exits early when
        # all thresholds are satisfied. max_wait is topology-aware (see
        # link_flap_utils._memory_settle_max_wait_for_topology).
        memory_output = duthost.shell("show system-memory")["stdout"]
        logging.info("Memory Status at end: %s", memory_output)

        end_time_frr_daemon_memory, end_time_redis_memory = wait_for_memory_to_settle(
            duthost, tbinfo, frr_demons_to_check,
            start_time_frr_daemon_memory, start_time_redis_memory)

        # Diagnostic orchagent CPU log (the hard check happens at the end of the test).
        orch_cpu = duthost.shell(
            "COLUMNS=512 show processes cpu | grep orchagent | awk '{print $1, $9}'")["stdout_lines"]
        for line in orch_cpu:
            pid, util = line.split(" ")
            logging.info("Orchagent PID {0} CPU Util at end: {1}".format(pid, util))

        logging.info("Redis Memory at start: %f M", start_time_redis_memory)
        logging.info("Redis Memory at end: %f M", end_time_redis_memory)
        log_redis_state(duthost, "end")

        # Final assertions on the readings the poll loop produced.
        for daemon in frr_demons_to_check:
            for asic_index, end_mem in end_time_frr_daemon_memory[daemon].items():
                start_mem = start_time_frr_daemon_memory[daemon][asic_index]
                passed, threshold = validate_frr_daemon_memory_increase(tbinfo, start_mem, end_mem)
                daemon_name = daemon if not duthost.is_multi_asic else f"{daemon}-asic{asic_index}"
                pytest_assert(
                    passed,
                    f"{daemon_name} memory increase more than expected: {threshold}%")

        pytest_assert(
            validate_redis_memory_increase(tbinfo, start_time_redis_memory, end_time_redis_memory),
            "Redis Memory Increases more than expected: start {}, end {}".format(
                start_time_redis_memory, end_time_redis_memory))

        # Orchagent CPU should consume < orch_cpu_threshold at last.
        logging.info("watch orchagent CPU utilization when it goes below %d", orch_cpu_threshold)
        pytest_assert(wait_until(900, 20, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                      "Orch CPU utilization {} > orch cpu threshold {} after link flap"
                      .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                              orch_cpu_threshold))
