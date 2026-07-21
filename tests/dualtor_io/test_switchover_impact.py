import pytest
import os
import json
import time
import random

from datetime import datetime

from tests.common.config_reload import config_reload
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, select_test_mux_ports      # noqa: F401
from tests.common.dualtor.dual_tor_common import cable_type                                                 # noqa: F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                             # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, \
                                                change_mac_addresses               # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import wait_until

import logging


pytestmark = [
    pytest.mark.topology("dualtor")
]


def set_mux_state(duthost, interface, state):
    """
    @summary: Sets mux state for given dut and interface.
        force_standby_tor is causing issues when toggling same interface multiple times.
    @param duthost: dut host to toggle mux interface.
    @param interface (str): interface to toggle (or 'all').
    @param state (str): state to set interface.
    """
    duthost.shell(f"sudo config muxcable mode auto {interface}")
    duthost.shell(f"sudo config muxcable mode {state} {interface}")
    duthost.shell(f"sudo config muxcable mode auto {interface}")


def wait_for_mux_state(duthost, port, expected_state, timeout=30):
    """
    @summary: Waits until a MUX port reaches the expected state.
    @param duthost: dut host to check mux state on.
    @param port (str): interface to check.
    @param expected_state (str): expected mux state ('active' or 'standby').
    @param timeout (int): maximum seconds to wait.
    """
    def check():
        result = duthost.show_and_parse(f"show mux status {port}")
        return any(r.get('status', '').lower() == expected_state for r in result)
    pytest_assert(wait_until(timeout, 5, 0, check),
                  f"Port {port} did not reach {expected_state}")


@pytest.mark.enable_active_active
@pytest.mark.parametrize("switchover", ["planned"])
def test_tor_switchover_impact(request,                                                    # noqa: F811
                               upper_tor_host, lower_tor_host,                             # noqa: F811
                               send_t1_to_server_with_action,                              # noqa: F811
                               cable_type,                                                 # noqa: F811
                               select_test_mux_ports,                                      # noqa: F811
                               pytestconfig,                                               # noqa: F811
                               switchover,                                                 # noqa: F811
                               ipv4_neighbors=10, ipv6_neighbors=64,                       # noqa: F811
                               planned_threshold=0.1, unplanned_threshold=0.4,             # noqa: F811
                               iterations=100):                                            # noqa: F811
    """
    Measure impact when active-standby ToR is going through switchover.
    must run with --enable_switchover_impact_test to enable.

    Steps:
        1. sets upper tor to active on all ports.
        2. start traffic test on random interface.
        3. switch upper tor interface to standby.
        4. record traffic impact
        5. start traffic test on interface again.
        6. switch upper tor interface to active.
    """

    threshold = planned_threshold if switchover == "planned" else unplanned_threshold
    stop_after = 60 if switchover == "planned" else 0

    def test(duthost, interface, state):
        if switchover == "planned":
            set_mux_state(duthost, interface, state)
        else:
            config_reload(duthost, wait_for_bgp=True)

    def get_interface_neighbor_mac_map():
        interface_mac_dict = {}
        arp = upper_tor_host.shell("show arp")["stdout"].splitlines()
        for line in arp:
            entry = line.split()
            interface_mac_dict[entry[2]] = entry[1]
        return interface_mac_dict

    def add_neighbor_entries(mac, vlan, count, version):
        cmds = []
        for i in range(100, 100+count):
            if version == 4:
                ip = f"192.168.0.{i}"
                cmds.append(f"ip -4 neigh replace {ip} lladdr {mac} dev {vlan}")
            else:
                ip = f"fc02:1000::{hex(i)[2:]}"
                cmds.append(f"ip -6 neigh replace {ip} lladdr {mac} dev {vlan}")
        upper_tor_host.shell_cmds(cmds=cmds)
        lower_tor_host.shell_cmds(cmds=cmds)

    def del_neighbor_entries(mac, vlan, count, version):
        cmds = []
        for i in range(100, 100+count):
            if version == 4:
                ip = f"192.168.0.{i}"
                cmds.append(f"ip -4 neigh del {ip} lladdr {mac} dev {vlan}")
            else:
                ip = f"fc02:1000::{hex(i)[2:]}"
                cmds.append(f"ip -6 neigh del {ip} lladdr {mac} dev {vlan}")
        upper_tor_host.shell_cmds(cmds=cmds)
        lower_tor_host.shell_cmds(cmds=cmds)

    def get_metric_data(metrics):
        """
        @summary: Extracts calculated switchover duration based on recorded mux metrics on ToR.
        @param metrics (dict): Mux metric data recorded from 'show mux metric <interface> --json'.
        @return float: calculated switchover duration.
        """
        end_time_string = metrics.get("linkmgrd_switch_standby_end") or metrics.get("linkmgrd_switch_active_end")
        start_time_string = metrics.get("linkmgrd_switch_standby_start") or metrics.get("linkmgrd_switch_active_start")
        if end_time_string:
            end_time = datetime.strptime(end_time_string, "%Y-%b-%d %H:%M:%S.%f").timestamp()
            start_time = datetime.strptime(start_time_string, "%Y-%b-%d %H:%M:%S.%f").timestamp()
            return end_time - start_time
        else:
            return None

    def record_results(results):
        """
        @summary: Records the test results to a file named "test_tor_switchover_impact.json".
        @param results (dict): Test results.
        """
        file_name = f"test_tor_switchover_impact-{switchover}.json"
        log_file = pytestconfig.getoption("log_file", None)
        log_dir = os.path.dirname(os.path.abspath(log_file))
        file_dst = os.path.join(log_dir, file_name)
        logging.info("Save dualtor-io switchover test file to %s", file_dst)
        with open(file_dst, 'w') as file:
            file.write(json.dumps(results, indent=4))

    def verify_test_result(test_results, interface):
        """
        @summary: Formats test results from switchover test.
        @param test_results (dict): Test results recieved from running send_t1_to_server_with_action.
        @param interface (str): Interface name.
        @return (dict, dict): (formatted test results, formatted failures.)
        """
        results = {}
        failures = {}
        for ipv4 in test_results:
            # Initialize results dict
            results[ipv4] = {}
            results[ipv4]['mux status'] = {}
            results[ipv4]['mux metric'] = {}
            results[ipv4]['disruptions'] = []

            # Record mux metrics
            results[ipv4]['mux status']["ut_mux_status"] = json.loads(
                upper_tor_host.shell(f"show mux status {interface} --json")["stdout"])
            results[ipv4]['mux status']["lt_mux_status"] = json.loads(
                lower_tor_host.shell(f"show mux status {interface} --json")["stdout"])

            # Record mux stats
            results[ipv4]['mux metric']["ut_metrics"] = json.loads(
                upper_tor_host.shell(f"show mux metric {interface} --json")["stdout"])
            results[ipv4]['mux metric']["lt_metrics"] = json.loads(
                lower_tor_host.shell(f"show mux metric {interface} --json")["stdout"])

            # Measure and record metric switchover time
            ut_switchover_time = get_metric_data(results[ipv4]['mux metric']["ut_metrics"])
            lt_switchover_time = get_metric_data(results[ipv4]['mux metric']["lt_metrics"])
            results[ipv4]['mux metric']["ut_switchover_time"] = ut_switchover_time
            results[ipv4]['mux metric']["lt_switchover_time"] = lt_switchover_time

            # May be multiple disruptions. loop through and record any that may be present.
            for disruption in test_results[ipv4]['disruptions']:
                # Get test results
                entry = disruption.copy()

                # Revise start and end time to readable string
                entry["start_time"] = str(datetime.fromtimestamp(disruption["start_time"]))
                entry["end_time"] = str(datetime.fromtimestamp(disruption["end_time"]))

                # Calculate impact duration and get mux metrics
                duration = float(disruption['end_time']) - float(disruption['start_time'])
                entry["duration"] = duration

                # Append entry to results
                results[ipv4]['disruptions'].append(entry)

                # Check failure test cases
                ut_diff = ut_switchover_time and abs(entry["duration"] - ut_switchover_time) > threshold
                lt_diff = lt_switchover_time and abs(entry["duration"] - lt_switchover_time) > threshold
                failure_cases = {"Traffic impact exceeds threshold": duration > threshold,
                                 "metrics don't match impact measurement": ut_diff and lt_diff,
                                 "UT metrics not present": ut_switchover_time is None,
                                 "LT metrics not present": lt_switchover_time is None}

                if True in failure_cases.values():
                    failures[ipv4] = results[ipv4]
                    failures[ipv4]["Failed test cases"] = failure_cases

            if len(results[ipv4]['disruptions']) > 1 and switchover == "planned":
                if not failures[ipv4]:
                    failures[ipv4] = results[ipv4]
                    failures[ipv4]["Failed test cases"] = {}
                failures[ipv4]["Failed test cases"]["Multiple disruptions detected for single switchover"] = True

        return results, failures

    """Test Start"""

    if not request.config.getoption('--enable_switchover_impact_test'):
        logging.info("Switchover impact test disabled. \
                     To enable the test, run with '--enable_switchover_impact_test'")
        return

    logs = {}
    logs["results"] = {}
    logs["failures"] = {}

    interface_mac_dict = get_interface_neighbor_mac_map()
    vlan = list(upper_tor_host.get_vlan_brief().keys())[0]

    logging.info("Starting switchover impact test.")

    for i in range(1, iterations + 1):
        """ Test Setup: """
        # get test interface
        duthost = random.choice([upper_tor_host, lower_tor_host])
        test_mux_ports = select_test_mux_ports(cable_type, 2)
        interface = test_mux_ports[1]
        mac = interface_mac_dict[interface]

        logging.info(f"test_tor_switchover_impact:{interface}:{i}")
        add_neighbor_entries(mac, vlan, ipv4_neighbors, 4)
        add_neighbor_entries(mac, vlan, ipv6_neighbors, 6)

        """ Step 1: """
        # Force upper tor to active:
        set_mux_state(duthost, 'all', 'active')
        time.sleep(30)

        """ Steps 2: """
        # traffic test from t1 to server and do standby switchover.
        result = send_t1_to_server_with_action(duthost, send_interval=0.01, stop_after=stop_after,
                                               action=lambda: test(duthost, interface, 'standby'),
                                               tor_vlan_port=interface, verify=False)

        del_neighbor_entries(mac, vlan, ipv4_neighbors, 4)
        del_neighbor_entries(mac, vlan, ipv6_neighbors, 6)

        """ Step 3: """
        # check test results and add to logs
        test_tag = f"Iteration:{i}, Interface:{interface}, UpperToRState:standby"
        results, failures = verify_test_result(result, interface)
        logs["results"][test_tag] = results.copy()
        if failures:
            logs["failures"][test_tag] = failures.copy()

    record_results(logs)
    failure_message = f"Failure detected, check logs/test_tor_switchover_traffic_impact-{switchover}.json."
    pytest_assert(not logs["failures"], failure_message)


@pytest.mark.skip_active_active
@pytest.mark.topology("dualtor")
def test_tor_switchover_impact_bulk(request,                                               # noqa: F811
                                    upper_tor_host, lower_tor_host,                        # noqa: F811
                                    cable_type,                                            # noqa: F811
                                    select_test_mux_ports):                                # noqa: F811
    """
    Stress-test bulk MUX switchover and detect syslog errors.

    Steps:
        1. Select a fixed pool of num_ports MUX interfaces.
        2. Force all ports to active once as a known baseline.
        3. Each iteration: randomly select a subset of ports and toggle them
           (active→standby or standby→active) for realistic stress coverage.
        4. After each iteration, analyze syslog on both ToRs for any errors.
    """

    if not request.config.getoption('--enable_switchover_impact_test'):
        pytest.skip("Bulk switchover impact test disabled. "
                    "To enable the test, run with '--enable_switchover_impact_test'")

    iterations = request.config.getoption("--switchover_iterations", default=100)
    num_ports = request.config.getoption("--switchover_num_ports", default=8)

    # Verify the testbed has enough active-standby MUX ports to run the bulk test.
    available_mux_ports = select_test_mux_ports(cable_type, num_ports)
    if len(available_mux_ports) < num_ports:
        pytest.skip(
            f"test_tor_switchover_impact_bulk requires at least {num_ports} active-standby MUX ports, "
            f"but only {len(available_mux_ports)} are available."
        )

    # One LogAnalyzer per ToR using common match/ignore config.
    analyzers = {}
    for label, host in [("UpperToR", upper_tor_host), ("LowerToR", lower_tor_host)]:
        la = LogAnalyzer(ansible_host=host, marker_prefix=f"test_tor_switchover_impact_bulk_{label}:")
        la.load_common_config()
        analyzers[label] = la

    def check_syslog_errors():
        """Analyze syslog on both ToRs since the last marker, then advance the marker."""
        for label, la in analyzers.items():
            try:
                la.analyze(markers[label])
            except LogAnalyzerError as err:
                pytest.fail(f"Syslog errors detected on {label}:\n{err}")
        for label, la in analyzers.items():
            markers[label] = la.init()

    # Place initial markers before any toggling begins.
    markers = {label: la.init() for label, la in analyzers.items()}

    # Randomly pick one ToR to issue mux toggle commands from.
    duthost = random.choice([upper_tor_host, lower_tor_host])
    logging.info("test_tor_switchover_impact_bulk: using %s as duthost", duthost.hostname)
    port_pool = available_mux_ports[:num_ports]
    port_states = {port: True for port in port_pool}  # True = active, False = standby
    duthost.shell("sudo config muxcable mode active all")
    for p in port_pool:
        wait_for_mux_state(duthost, p, 'active')

    try:
        for i in range(1, iterations + 1):
            # Toggle all ports each iteration, alternating between standby and active
            # based on their current tracked state.
            ports_to_standby = [p for p in port_pool if port_states[p]]
            ports_to_active = [p for p in port_pool if not port_states[p]]

            logging.info(
                "test_tor_switchover_impact_bulk: iteration %d/%d, toggling to standby: %s, to active: %s",
                i, iterations, ports_to_standby, ports_to_active
            )

            for p in ports_to_standby:
                set_mux_state(duthost, p, 'standby')
                wait_for_mux_state(duthost, p, 'standby')
                port_states[p] = False
            for p in ports_to_active:
                set_mux_state(duthost, p, 'active')
                wait_for_mux_state(duthost, p, 'active')
                port_states[p] = True

            check_syslog_errors()
    finally:
        # Restore all ports to active before releasing to auto to ensure
        # a clean testbed state even if the test failed mid-iteration.
        logging.info("test_tor_switchover_impact_bulk: restoring all ports to active")
        duthost.shell("sudo config muxcable mode active all")
        for p in port_pool:
            try:
                wait_for_mux_state(duthost, p, 'active')
            except Exception as e:
                logging.warning("test_tor_switchover_impact_bulk: port %s did not reach active during cleanup: %s",
                                p, e)
        duthost.shell("sudo config muxcable mode auto all")
