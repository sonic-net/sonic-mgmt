import pytest
import os
import json
import time
import random

from datetime import datetime

from tests.common.config_reload import config_reload
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, select_test_mux_ports      # noqa: F401
from tests.common.dualtor.dual_tor_common import cable_type                                                 # noqa: F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                              # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, \
                                                change_mac_addresses               # noqa: F401
from tests.common.helpers.assertions import pytest_assert

import logging


pytestmark = [
    pytest.mark.topology("dualtor")
]


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

    def set_mux_state(duthost, interface, state):
        """
        @summary: Sets mux state for given dut and interface.
            force_standby_tor is causing issues when toggling same interface multiple times.
        @param duthost: dut host to toggle mux interface.
        @param interface (str): interface to toggle.
        @param state (str): state to set interface.
        """
        duthost.shell(f"sudo config muxcable mode auto {interface}")
        duthost.shell(f"sudo config muxcable mode {state} {interface}")
        duthost.shell(f"sudo config muxcable mode auto {interface}")

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
