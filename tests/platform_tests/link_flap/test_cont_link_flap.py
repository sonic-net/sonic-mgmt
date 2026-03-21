"""
Tests the continuous link flap in SONiC.

Parameters:
    --orch_cpu_threshold <port> (int): Which port you want the test to send traffic
        to. Default is 3.
"""

import logging
import pytest
import time
import math
import re

from collections import defaultdict

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common import port_toggle
from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates,\
    check_orch_cpu_utilization, check_bgp_routes, get_avg_redis_mem_usage, validate_redis_memory_increase
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

    def get_frr_daemon_memory_usage(self, duthost, daemon):
        frr_daemon_memory_per_asics = {}

        for asic in duthost.asics:
            frr_daemon_memory_output = duthost.shell(duthost.get_vtysh_cmd_for_namespace(
                f'vtysh -c "show memory {daemon}"', asic.namespace))["stdout"]
            logging.info(f"{daemon} memory status: \n%s", frr_daemon_memory_output)

            # Parse the output for the three memory values
            used_ordinary_blocks = 0
            used_small_blocks = 0
            holding_block_headers = 0
            for line in frr_daemon_memory_output.splitlines():
                if "Used ordinary blocks:" in line:
                    used_ordinary_blocks = TestContLinkFlap._parse_memory_value(line)
                elif "Used small blocks:" in line:
                    used_small_blocks = TestContLinkFlap._parse_memory_value(line)
                elif "Holding block headers:" in line:
                    holding_block_headers = TestContLinkFlap._parse_memory_value(line)

            total_memory = used_ordinary_blocks + used_small_blocks + holding_block_headers
            logging.info("{} total memory for asic{}: {} MiB; ordinary {}, small {}, holding {}".format(
                daemon, asic.asic_index, total_memory, used_ordinary_blocks, used_small_blocks, holding_block_headers))
            frr_daemon_memory_per_asics[asic.asic_index] = total_memory

        return frr_daemon_memory_per_asics

    @staticmethod
    def _parse_memory_value(line):
        match = re.search(r':\s*([\d.]+)\s*(bytes|KiB|MiB)?', line)
        if not match:
            return 0
        value = float(match.group(1))
        unit = match.group(2)
        if unit == 'bytes' or unit is None:
            return value / (1024 * 1024)
        elif unit == 'KiB':
            return value / 1024
        elif unit == 'MiB':
            return value
        else:
            return value

    def save_counter_values(self, dut, stage):
        if not hasattr(self, "drop_counters"):
            self.drop_counters = {}
            self.intf_counters = {}

        self.drop_counters[stage] = dut.show_and_parse(show_cmd="show dropcounter count")
        self.intf_counters[stage] = dut.show_and_parse(show_cmd="show interface counter")

    def check_all_counters(self, dut):
        if not hasattr(self, "drop_counters"):
            raise RuntimeError("Checking counters without collecting them first. This shouldn't happen!")

        # First drop counter's check.
        def compare_counters(counter_type, pre_list, post_list):
            failed_counters = []
            if len(pre_list) != len(post_list):
                raise RuntimeError(
                    f"Mismatch in number of interfaces before and after test."
                    f" pre_list(len:{len(pre_list)})={pre_list},"
                    f"post_list(len:{len(post_list)})={post_list}")

            if counter_type == "drop":
                check_list = ['rx_err', 'rx_drops', 'tx_err', 'tx_drops']
            if counter_type == "intf":
                check_list = ['rx_drp', 'rx_err', 'tx_drp', 'tx_err', 'rx_ok', 'rx_ovr', 'tx_ok', 'tx_ovr']
            for i in range(len(pre_list)):
                # Give 5% tolerance
                pre_line = pre_list[i]
                post_line = post_list[i]
                # drop Counters: line format:
                # {'iface': 'Ethernet0', 'state': 'X', 'rx_err': '0', 'rx_drops': '0', 'tx_err': '0', 'tx_drops': '0'}
                pytest_assert(
                    pre_line['iface'] == post_line['iface'],
                    f"Interface names before and after counter checks don't "
                    f"match. pre:{pre_line}, post:{post_line}")
                for entry in check_list:
                    # math.isclose(int("1,000,000".replace(",", "_")), int("1,000,000".replace(",", "_")))

                    if not math.isclose(
                            int(pre_line[entry].replace(",", "_")),
                            int(post_line[entry].replace(",", "_")),
                            abs_tol=2000,
                            rel_tol=0.05):
                        failed_counters.append(
                            f"{counter_type}:{pre_line['iface']}:"
                            f"{entry}:pre_value({pre_line[entry]}) post_value({post_line[entry]})")

            pytest_assert(
                failed_counters == [],
                f"Mismatches found: {failed_counters}")

        compare_counters('drop', self.drop_counters['pre'], self.drop_counters['post'])
        compare_counters('intf', self.intf_counters['pre'], self.intf_counters['post'])

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
            start_time_frr_daemon_memory[daemon] = self.get_frr_daemon_memory_usage(duthost, daemon)
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

        # Save the counter values for all interfaces.
        self.save_counter_values(duthost, "pre")

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

        # Wait 30s for the memory usage to be stable
        time.sleep(30)

        # Record memory status at end
        memory_output = duthost.shell("show system-memory")["stdout"]
        logging.info("Memory Status at end: %s", memory_output)

        # Check the FRR daemons memory usage at end
        end_time_frr_daemon_memory = {}
        incr_frr_daemon_memory_threshold = defaultdict(lambda: {})

        for daemon in frr_demons_to_check:
            for asic_index, asic_frr_memory in start_time_frr_daemon_memory[daemon].items():
                incr_frr_daemon_memory_threshold[daemon][asic_index] = 10 if tbinfo["topo"]["type"] in ["m0", "mx"]\
                                                                       else 5

                min_threshold_percent = 1 / float(asic_frr_memory) * 100

                if min_threshold_percent > incr_frr_daemon_memory_threshold[daemon][asic_index]:
                    incr_frr_daemon_memory_threshold[daemon][asic_index] = math.ceil(min_threshold_percent)

                logging.info(f"The memory increment threshold for frr daemon {daemon}-asic{asic_index} "
                             f"is {incr_frr_daemon_memory_threshold[daemon][asic_index]}%")

        for daemon in frr_demons_to_check:
            # Record FRR daemon memory status at end
            end_time_frr_daemon_memory[daemon] = self.get_frr_daemon_memory_usage(duthost, daemon)
            logging.info(f"{daemon} memory usage at end: \n%s", end_time_frr_daemon_memory[daemon])

            # Calculate diff in FRR daemon memory
            for asic_index, end_frr_memory in end_time_frr_daemon_memory[daemon].items():
                incr_frr_daemon_memory = float(end_frr_memory) - float(start_time_frr_daemon_memory[daemon][asic_index])

                daemon_name = daemon if not duthost.is_multi_asic else f"{daemon}-asic{asic_index}"
                logging.info(f"{daemon_name} absolute difference: %d", incr_frr_daemon_memory)

                # Check FRR daemon memory only if it is increased else default to pass
                if incr_frr_daemon_memory > 0:
                    percent_incr_frr_daemon_memory = \
                        (incr_frr_daemon_memory / float(start_time_frr_daemon_memory[daemon][asic_index])) * 100
                    logging.info(f"{daemon_name} memory percentage increase: %d", percent_incr_frr_daemon_memory)
                    pytest_assert(percent_incr_frr_daemon_memory < incr_frr_daemon_memory_threshold[daemon][asic_index],
                                  f"{daemon_name} memory increase more than expected: "
                                  f"{incr_frr_daemon_memory_threshold[daemon][asic_index]}%")

        # Record orchagent CPU utilization at end
        orch_cpu = duthost.shell(
            "COLUMNS=512 show processes cpu | grep orchagent | awk '{print $1, $9}'")["stdout_lines"]
        for line in orch_cpu:
            pid, util = line.split(" ")
            logging.info("Orchagent PID {0} CPU Util at end: {1}".format(pid, util))

        # Record Redis Memory at end
        end_time_redis_memory = get_avg_redis_mem_usage(duthost, 5, 5)
        logging.info("Redis Memory at start: %f M", start_time_redis_memory)
        logging.info("Redis Memory at end: %f M", end_time_redis_memory)

        result = validate_redis_memory_increase(tbinfo, start_time_redis_memory, end_time_redis_memory)
        pytest_assert(result, "Redis Memory Increases more than expected: start {}, end {}"
                      .format(start_time_redis_memory, end_time_redis_memory))

        # Orchagent CPU should consume < orch_cpu_threshold at last.
        logging.info("watch orchagent CPU utilization when it goes below %d", orch_cpu_threshold)
        pytest_assert(wait_until(900, 20, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                      "Orch CPU utilization {} > orch cpu threshold {} after link flap"
                      .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                              orch_cpu_threshold))

        # check counter values
        self.save_counter_values(duthost, "post")
        self.check_all_counters(duthost)
