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

from collections import defaultdict

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common import port_toggle
from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates,\
    check_orch_cpu_utilization, check_bgp_routes
from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.platform.device_utils import toggle_one_link

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


class TestContLinkFlap(object):
    """
    TestContLinkFlap class for continuous link flap
    """

    def get_frr_daemon_memory_usage(self, duthost, daemon):
        frr_daemon_memory_per_asics = {}

        for asic in duthost.asics:
            frr_daemon_memory_output = asic.run_vtysh(f'-c "show memory {daemon}"')["stdout"]

            logging.info(
                f"{daemon}{('-' + asic.namespace) if asic.namespace else ''} memory status: \n%s",
                frr_daemon_memory_output
            )

            frr_daemon_memory = asic.run_vtysh(
                f'-c "show memory {daemon}" | grep "Used ordinary blocks"'
            )["stdout"].split()[-2]

            frr_daemon_memory_per_asics[asic.asic_index] = frr_daemon_memory

        return frr_daemon_memory_per_asics

    def test_cont_link_flap(self, request, duthosts, nbrhosts, enum_rand_one_per_hwsku_frontend_hostname,
                            fanouthosts, bring_up_dut_interfaces, tbinfo):
        """
        Validates that continuous link flap works as expected

        Test steps:
            1.) Flap all interfaces one by one in 1-3 iteration
                to cause BGP Flaps.
            2.) Flap all interfaces on peer (FanOutLeaf) one by one 1-3 iteration
                to cause BGP Flaps.
            3.) Watch for memory (show system-memory), FRR daemons memory(vtysh -c "show memory bgp/zebra"),
                orchagent CPU Utilization and Redis_memory.

        Pass Criteria: All routes must be re-learned with < 5% increase in Redis/FRR memory usage and
            ORCH agent CPU consumption below threshold after 3 mins after stopping flaps.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        duthost.command("sonic-clear arp")
        orch_cpu_threshold = request.config.getoption("--orch_cpu_threshold")

        # Record memory status at start
        memory_output = duthost.shell("show system-memory")["stdout"]
        logging.info("Memory Status at start: %s", memory_output)

        # Record Redis Memory at start
        start_time_redis_memory = duthost.shell(
            r"redis-cli info memory | grep used_memory_human | sed -e 's/.*:\(.*\)M/\1/'")["stdout"]
        logging.info("Redis Memory: %s M", start_time_redis_memory)

        # Record ipv4 route counts at start
        sumv4, sumv6 = duthost.get_ip_route_summary(skip_kernel_tunnel=True)
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
        pytest_assert(wait_until(100, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                      "Orch CPU utilization {} > orch cpu threshold {} before link flap"
                      .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                              orch_cpu_threshold))

        # Flap all interfaces one by one on DUT
        for iteration in range(3):
            logging.info("%d Iteration flap all interfaces one by one on DUT", iteration + 1)
            port_toggle(duthost, tbinfo, watch=True)

        # Flap all interfaces one by one on Peer Device
        for iteration in range(3):
            logging.info("%d Iteration flap all interfaces one by one on Peer Device", iteration + 1)
            candidates = build_test_candidates(duthost, fanouthosts, 'all_ports')

            pytest_require(candidates, "Didn't find any port that is admin up and present in the connection graph")

            for dut_port, fanout, fanout_port in candidates:
                toggle_one_link(duthost, dut_port, fanout, fanout_port, watch=True)

        # Make Sure all ipv4/ipv6 routes are relearned with jitter of ~5
        if not wait_until(120, 2, 0, check_bgp_routes, duthost,
                          start_time_ipv4_route_counts, start_time_ipv6_route_counts):
            endv4, endv6 = duthost.get_ip_route_summary(skip_kernel_tunnel=True)
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
        end_time_redis_memory = duthost.shell(
            r"redis-cli info memory | grep used_memory_human | sed -e 's/.*:\(.*\)M/\1/'")["stdout"]
        logging.info("Redis Memory at start: %s M", start_time_redis_memory)
        logging.info("Redis Memory at end: %s M", end_time_redis_memory)

        # Calculate diff in Redis memory
        incr_redis_memory = float(end_time_redis_memory) - float(start_time_redis_memory)
        logging.info("Redis absolute  difference: %d", incr_redis_memory)

        # Check redis memory only if it is increased else default to pass
        if incr_redis_memory > 0.0:
            percent_incr_redis_memory = (incr_redis_memory / float(start_time_redis_memory)) * 100
            logging.info("Redis Memory percentage Increase: %d", percent_incr_redis_memory)
            incr_redis_memory_threshold = 10 if tbinfo["topo"]["type"] in ["m0", "mx"] else 5
            pytest_assert(percent_incr_redis_memory < incr_redis_memory_threshold,
                          "Redis Memory Increase more than expected: {}".format(percent_incr_redis_memory))

        # Orchagent CPU should consume < orch_cpu_threshold at last.
        logging.info("watch orchagent CPU utilization when it goes below %d", orch_cpu_threshold)
        pytest_assert(wait_until(45, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                      "Orch CPU utilization {} > orch cpu threshold {} after link flap"
                      .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                              orch_cpu_threshold))
