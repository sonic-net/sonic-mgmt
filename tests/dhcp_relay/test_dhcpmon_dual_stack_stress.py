import logging
import time

import pytest

from tests.common.dhcp_relay_utils import query_dhcpmon_counter_result
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m  # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.ptf_runner import ptf_runner

pytestmark = [
    pytest.mark.topology("dualtor"),
    pytest.mark.device_type("physical"),
]

logger = logging.getLogger(__name__)

STRESS_DURATION_SEC = 300
PROBE_DURATION_SEC = 10
# DHCPmon flushes its counters to COUNTERS_DB every 20 seconds.
COUNTER_FLUSH_WAIT_SEC = 25
FAMILIES = {"v4": "Discover", "v6": "Solicit"}


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, loganalyzer):
    if loganalyzer:
        for duthost in duthosts:
            loganalyzer[duthost.hostname].ignore_regex.extend([
                r".*ERR memory_threshold_check: Free memory [.\d]+ is less then free memory threshold [.\d]+",
            ])
    yield


def get_dhcpmon_programs(duthost):
    """Return {supervisor program: pid} for every DHCPmon program, asserting each one is RUNNING."""
    lines = duthost.shell("docker exec dhcp_relay supervisorctl status",
                          module_ignore_errors=True)["stdout_lines"]
    programs = {}
    for line in lines:
        fields = line.split()
        if fields and fields[0].startswith("dhcpmon:"):
            pytest_assert(fields[1] == "RUNNING",
                          "{} DHCPmon is not running: {}".format(duthost.hostname, line))
            programs[fields[0]] = fields[3].rstrip(",")
    pytest_assert(programs, "No DHCPmon program found on {}".format(duthost.hostname))
    return programs


def get_rx_counters(duthosts, vlan):
    return {
        duthost.hostname: {
            family: query_dhcpmon_counter_result(duthost, vlan, is_v6=(family == "v6"))["RX"][msg]
            for family, msg in FAMILIES.items()
        }
        for duthost in duthosts
    }


def send_dual_stack_traffic(ptfhost, client_ports, duration):
    ptf_runner(ptfhost, "ptftests", "dhcp_dual_stack_stress_test.DHCPDualStackStressTest",
               platform_dir="ptftests",
               params={"client_port_indices": client_ports, "duration": duration},
               log_file="/tmp/dhcp_dual_stack_stress_test.log",
               qlen=100000, is_python3=True)
    time.sleep(COUNTER_FLUSH_WAIT_SEC)


def test_dhcpmon_concurrent_dual_stack_traffic(ptfhost, duthosts, dut_dhcp_relay_data,
                                               setup_standby_ports_on_rand_unselected_tor,
                                               toggle_all_simulator_ports_to_rand_selected_tor_m):  # noqa: F811
    """
    In dual-ToR mode, DHCPmon's IPv4 and IPv6 receive threads both look up the
    MUX state of the ingress port in STATE_DB for every downlink packet.
    Verify that sustained concurrent DHCPv4 and DHCPv6 client traffic neither
    terminates DHCPmon nor stops it from processing packets.
    """
    for dhcp_relay in dut_dhcp_relay_data:
        vlan = dhcp_relay["downlink_vlan_iface"]["name"]
        client_ports = [dhcp_relay["client_iface"]["port_idx"]] + dhcp_relay["other_client_ports"]
        programs = {duthost.hostname: get_dhcpmon_programs(duthost) for duthost in duthosts}

        before = get_rx_counters(duthosts, vlan)
        send_dual_stack_traffic(ptfhost, client_ports, STRESS_DURATION_SEC)
        after_stress = get_rx_counters(duthosts, vlan)
        logger.info("DHCPmon RX counters before %s, after stress %s", before, after_stress)

        active = {
            host: [family for family in FAMILIES if after_stress[host][family] > before[host][family]]
            for host in before
        }
        pytest_assert(any(len(families) == len(FAMILIES) for families in active.values()),
                      "No ToR counted both DHCPv4 and DHCPv6 traffic: {}".format(active))

        send_dual_stack_traffic(ptfhost, client_ports, PROBE_DURATION_SEC)
        after_probe = get_rx_counters(duthosts, vlan)

        for duthost in duthosts:
            host = duthost.hostname
            pytest_assert(get_dhcpmon_programs(duthost) == programs[host],
                          "DHCPmon restarted on {} during dual-stack traffic".format(host))
            for family in active[host]:
                pytest_assert(after_probe[host][family] > after_stress[host][family],
                              "DHCPmon on {} stopped counting DHCP{} packets after dual-stack traffic"
                              .format(host, family))
