import pytest
import random
import time
import logging
import re
import shlex

from tests.common.dhcp_relay_utils import init_dhcpmon_counters, validate_dhcpmon_counters
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.gcu_utils import generate_tmpfile, create_checkpoint, \
    apply_patch, expect_op_success, delete_tmpfile, \
    rollback_or_reload, delete_checkpoint
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import check_link_status
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.dhcp_relay_utils import check_routes_to_dhcp_server
from tests.common.dhcp_relay_utils import restart_dhcp_service, wait_dhcp_relay_ready
from tests.common.dhcp_relay_utils import enable_sonic_dhcpv4_relay_agent  # noqa: F401

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs'),
    pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"]),
]

SUPPORTED_DHCPV4_TYPE = [
    "Unknown", "Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform", "Bootp"
]
SUPPORTED_DIR = ["TX", "RX"]


BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'
CLIENT_SENT_PACKET_COUNT = 7

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(
        rand_one_dut_hostname,
        loganalyzer,
        enable_sonic_dhcpv4_relay_agent   # noqa: F811
):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        ignoreRegex = [
            r".*ERR snmp#snmp-subagent.*",
            r".*ERR rsyslogd: omfwd: socket (\d+): error (\d+) sending via udp: Network is (unreachable|down).*",
            r".*ERR rsyslogd: omfwd/udp: socket (\d+): sendto\(\) error: Network is (unreachable|down).*"
        ]
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(ignoreRegex)

    yield


def check_interface_status(duthost, relay_agent="isc-relay-agent"):
    if relay_agent == "sonic-relay-agent":
        if ":67" in duthost.shell(
                 "docker exec -t dhcp_relay ss -nlp | grep dhcp4relay",
                 module_ignore_errors=True)["stdout"]:
            return True
    else:
        if ":67" in duthost.shell(
                 "docker exec -t dhcp_relay ss -nlp | grep dhcrelay",
                 module_ignore_errors=True)["stdout"]:
            return True

    return False


def _replace_config_db_hash(duthost, table, name, values):
    """Replace one CONFIG_DB hash using sonic-db-cli."""
    key = "{}|{}".format(table, name)
    commands = ["sonic-db-cli CONFIG_DB del {}".format(shlex.quote(key))]
    for field, value in sorted(values.items()):
        if isinstance(value, list):
            field = "{}@".format(field)
            value = ",".join(value)
        commands.append(
            "sonic-db-cli CONFIG_DB hset {} {} {}".format(
                shlex.quote(key), shlex.quote(field), shlex.quote(str(value))))
    duthost.shell_cmds(cmds=commands)


def _set_config_db_list_field(duthost, table, name, field, values):
    """Set or remove one CONFIG_DB list field using sonic-db-cli."""
    key = "{}|{}".format(table, name)
    field = "{}@".format(field)
    if values:
        command = "sonic-db-cli CONFIG_DB hset {} {} {}".format(
            shlex.quote(key), shlex.quote(field), shlex.quote(",".join(values)))
    else:
        command = "sonic-db-cli CONFIG_DB hdel {} {}".format(
            shlex.quote(key), shlex.quote(field))
    duthost.shell(command)


def _set_sonic_dhcpv4_relay_flag(duthost, value):
    """Set the native DHCPv4 relay flag, or remove it when value is None."""
    key = "DEVICE_METADATA|localhost"
    field = "has_sonic_dhcpv4_relay"
    if value is None:
        command = "sonic-db-cli CONFIG_DB hdel {} {}".format(
            shlex.quote(key), shlex.quote(field))
    else:
        command = "sonic-db-cli CONFIG_DB hset {} {} {}".format(
            shlex.quote(key), shlex.quote(field), shlex.quote(value))
    duthost.shell(command)


def _set_dhcp_relay_server_state(duthost, vlan_name, vlan_names, backend, v4_servers, v6_servers,
                                 original_native_v4, original_v6):
    """Configure only the selected VLAN without triggering an implicit service restart."""
    for current_vlan in vlan_names:
        isc_v4_servers = v4_servers if backend == "isc" and current_vlan == vlan_name else []
        _set_config_db_list_field(
            duthost, "VLAN", current_vlan, "dhcp_servers", isc_v4_servers)

        native_v4 = dict(original_native_v4[current_vlan])
        native_v4.pop("dhcpv4_servers", None)
        if backend == "sonic" and current_vlan == vlan_name and v4_servers:
            native_v4["dhcpv4_servers"] = v4_servers
        _replace_config_db_hash(duthost, "DHCPV4_RELAY", current_vlan, native_v4)

        v6_config = dict(original_v6[current_vlan])
        v6_config.pop("dhcpv6_servers", None)
        if current_vlan == vlan_name and v6_servers:
            v6_config["dhcpv6_servers"] = v6_servers
        _replace_config_db_hash(duthost, "DHCP_RELAY", current_vlan, v6_config)


def _assert_dhcp_relay_server_state(duthost, vlan_name, vlan_names, backend, v4_servers, v6_servers):
    """Verify that only the selected VLAN has the requested server configuration."""
    config = duthost.get_running_config_facts()
    for current_vlan in vlan_names:
        expected_isc_v4 = v4_servers if backend == "isc" and current_vlan == vlan_name else []
        expected_sonic_v4 = v4_servers if backend == "sonic" and current_vlan == vlan_name else []
        expected_v6 = v6_servers if current_vlan == vlan_name else []
        actual_isc_v4 = config.get("VLAN", {}).get(
            current_vlan, {}).get("dhcp_servers", [])
        actual_sonic_v4 = config.get("DHCPV4_RELAY", {}).get(
            current_vlan, {}).get("dhcpv4_servers", [])
        actual_v6 = config.get("DHCP_RELAY", {}).get(
            current_vlan, {}).get("dhcpv6_servers", [])

        pytest_assert(sorted(actual_isc_v4) == sorted(expected_isc_v4),
                      "Unexpected ISC DHCPv4 servers for {}: expected {}, got {}"
                      .format(current_vlan, expected_isc_v4, actual_isc_v4))
        pytest_assert(sorted(actual_sonic_v4) == sorted(expected_sonic_v4),
                      "Unexpected SONiC DHCPv4 servers for {}: expected {}, got {}"
                      .format(current_vlan, expected_sonic_v4, actual_sonic_v4))
        pytest_assert(sorted(actual_v6) == sorted(expected_v6),
                      "Unexpected DHCPv6 servers for {}: expected {}, got {}"
                      .format(current_vlan, expected_v6, actual_v6))


def _restart_dhcp_relay_for_process_layout(duthost, relay_types):
    """Restart the container when no relay agent exists or use the shared readiness helper."""
    if relay_types:
        restart_dhcp_service(duthost, relay_types)
        return

    duthost.shell("systemctl reset-failed dhcp_relay")
    duthost.shell("systemctl restart dhcp_relay")
    duthost.shell("systemctl reset-failed dhcp_relay")


def _assert_dhcp_relay_process_layout(duthost, vlan_name, backend, has_v4, has_v6):
    """Assert the global and selected-VLAN supervisor process layout."""
    last_entries = {"value": []}

    def _has_expected_layout():
        output = duthost.shell(
            "docker exec dhcp_relay supervisorctl status", module_ignore_errors=True)
        entries = []
        for line in output["stdout_lines"]:
            parts = line.split()
            if len(parts) >= 2:
                entries.append((parts[0].split(":")[-1], parts[1]))
        last_entries["value"] = entries

        def _matching(program):
            return [state for name, state in entries if name == program]

        expected_dhcp6relay = ["RUNNING"] if has_v6 else []
        expected_dhcp4relay = ["RUNNING"] if backend == "sonic" else []
        expected_isc = [
            ("isc-dhcpv4-relay-{}".format(vlan_name), "RUNNING")
        ] if backend == "isc" and has_v4 else []
        expected_monitors = [
            ("dhcpmon-{}".format(vlan_name), "RUNNING")
        ] if has_v4 or has_v6 else []
        actual_isc = sorted(
            (name, state) for name, state in entries if name.startswith("isc-dhcpv4-relay-"))
        actual_monitors = sorted(
            (name, state) for name, state in entries if name.startswith("dhcpmon-"))

        return (
            _matching("dhcprelayd") == ["RUNNING"]
            and _matching("dhcp6relay") == expected_dhcp6relay
            and _matching("dhcp4relay") == expected_dhcp4relay
            and actual_isc == expected_isc
            and actual_monitors == expected_monitors
        )

    pytest_assert(
        wait_until(120, 5, 0, _has_expected_layout),
        "Unexpected dhcp_relay supervisor layout for backend={} v4={} v6={}: {}"
        .format(backend, has_v4, has_v6, last_entries["value"]))


@pytest.fixture(scope="function")
def enable_source_port_ip_in_relay(duthosts, rand_one_dut_hostname, tbinfo, request):
    duthost = duthosts[rand_one_dut_hostname]

    relay_agent = request.getfixturevalue("relay_agent")

    if relay_agent == "sonic-relay-agent":
        """
        Configure the deployment_id directly incase of sonic-dhcpv4-relay agent support and reset the default.
        Restart of dhcp service is not required.
        dhcpv4 process, socket validations are already covered as part of fixtures.
        """
        try:
            # Read and cache the original deployment_id
            default_deployment_id = duthost.shell('sonic-db-cli CONFIG_DB hget '    # noqa: F841
                                                  '"DEVICE_METADATA|localhost" "deployment_id"',
                                                  module_ignore_errors=True)["stdout"].strip()
            duthost.shell('sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "deployment_id" "8"',
                          module_ignore_errors=True)
            yield
        finally:
            duthost.shell(f'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost"'
                          f' "deployment_id" "{default_deployment_id}"', module_ignore_errors=True)
    else:
        """
        Enable source port ip in relay function
        -si parameter(Enable source port ip in relay function) will be added if deployment_id is '8', ref:
        https://github.com/sonic-net/sonic-buildimage/blob/e0e0c0c1b3c58635bc25fde6a77ca3b0849dfde1/dockers/docker-dhcp-relay/dhcpv4-relay.agents.j2#L16
        """

        json_patch = [
            {
                "op": "replace",
                "path": "/DEVICE_METADATA/localhost/deployment_id",
                "value": "8"
            }
        ]

        tmpfile = generate_tmpfile(duthost)
        logger.info("tmpfile {}".format(tmpfile))
        check_point = "dhcp_relay"
        try:
            create_checkpoint(duthost, check_point)
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
            restart_dhcp_service(duthost, ['isc'])

            def dhcp_ready(enable_source_port_ip_in_relay):
                dhcp_relay_running = duthost.is_service_fully_started("dhcp_relay")
                dhcp_relay_process = duthost.shell("ps -ef |grep dhcrelay|grep -v grep",
                                                   module_ignore_errors=True)["stdout"]
                dhcp_mon_process = duthost.shell("ps -ef |grep dhcpmon|grep -v grep",
                                                 module_ignore_errors=True)["stdout"]
                dhcp_mon_process_running = "dhcpmon" in dhcp_mon_process
                if enable_source_port_ip_in_relay:
                    dhcp_relay_process_ready = "-si" in dhcp_relay_process and "dhcrelay" in dhcp_relay_process
                else:
                    dhcp_relay_process_ready = "-si" not in dhcp_relay_process and "dhcrelay" in dhcp_relay_process
                return dhcp_relay_running and dhcp_relay_process_ready and dhcp_mon_process_running
            pytest_assert(wait_until(60, 2, 0, dhcp_ready, True), "Source port ip in relay is not enabled!")
            yield
        finally:
            delete_tmpfile(duthost, tmpfile)
            logger.info("Rolled back to original checkpoint")
            rollback_or_reload(duthost, check_point)
            delete_checkpoint(duthost, check_point)
            restart_dhcp_service(duthost, ['isc'])
            pytest_assert(wait_until(60, 2, 0, dhcp_ready, False), "Source port ip in relay is not disabled!")


@pytest.mark.skip_config_dhcpv4_relay_agent
def test_dhcp_relay_process_layout(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data,
                                   tbinfo, relay_agent):
    """Verify the DHCP relay process matrix as server configuration changes."""
    duthost = duthosts[rand_one_dut_hostname]
    backend = "sonic" if relay_agent == "sonic-relay-agent" else "isc"
    pytest_assert(dut_dhcp_relay_data, "No DHCP relay data is available for the process matrix")
    selected_relay = dut_dhcp_relay_data[0]
    vlan_name = selected_relay["downlink_vlan_iface"]["name"]
    match = re.fullmatch(r"Vlan(\d+)", vlan_name)
    pytest_assert(match, "Unexpected VLAN interface name {}".format(vlan_name))

    v4_servers = list(selected_relay["downlink_vlan_iface"]["dhcp_server_addrs"])
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    v6_servers = list(minigraph_facts.get("dhcpv6_servers", []))
    pytest_assert(v4_servers, "No DHCPv4 server is available for {}".format(vlan_name))
    pytest_assert(v6_servers, "No DHCPv6 server is available for {}".format(vlan_name))

    original_config = duthost.get_running_config_facts()
    vlan_names = {vlan_name}
    for table, field in [
            ("VLAN", "dhcp_servers"),
            ("DHCPV4_RELAY", "dhcpv4_servers"),
            ("DHCP_RELAY", "dhcpv6_servers")]:
        vlan_names.update(
            name for name, values in original_config.get(table, {}).items()
            if values.get(field))
    vlan_names = sorted(vlan_names)
    original_isc_v4 = {
        name: list(original_config.get("VLAN", {}).get(name, {}).get("dhcp_servers", []))
        for name in vlan_names
    }
    original_native_v4 = {
        name: dict(original_config.get("DHCPV4_RELAY", {}).get(name, {}))
        for name in vlan_names
    }
    original_v6 = {
        name: dict(original_config.get("DHCP_RELAY", {}).get(name, {}))
        for name in vlan_names
    }
    metadata = original_config.get("DEVICE_METADATA", {}).get("localhost", {})
    original_flag_present = "has_sonic_dhcpv4_relay" in metadata
    original_flag = metadata.get("has_sonic_dhcpv4_relay")
    original_backend = "sonic" if str(original_flag).lower() == "true" else "isc"

    feature_state = original_config.get("FEATURE", {}).get("dhcp_relay", {}).get("state")
    pytest_assert(feature_state in ["enabled", "always_enabled"],
                  "dhcp_relay feature must remain enabled, got {}".format(feature_state))

    states = [
        ("no-v4-no-v6", False, False),
        ("v4-only", True, False),
        ("v6-only", False, True),
        ("v4-and-v6", True, True),
    ]

    try:
        _set_sonic_dhcpv4_relay_flag(duthost, "True" if backend == "sonic" else None)
        for state_name, has_v4, has_v6 in states:
            logger.info("Checking DHCP relay process state %s for %s on %s",
                        state_name, vlan_name, backend)
            expected_v4 = v4_servers if has_v4 else []
            expected_v6 = v6_servers if has_v6 else []
            _set_dhcp_relay_server_state(
                duthost, vlan_name, vlan_names, backend, expected_v4, expected_v6,
                original_native_v4, original_v6)
            _assert_dhcp_relay_server_state(
                duthost, vlan_name, vlan_names, backend, expected_v4, expected_v6)

            relay_types = []
            if backend == "sonic" or has_v4:
                relay_types.append(backend)
            if has_v6:
                relay_types.append("v6")
            _restart_dhcp_relay_for_process_layout(duthost, relay_types)
            _assert_dhcp_relay_process_layout(duthost, vlan_name, backend, has_v4, has_v6)

            current_feature_state = duthost.shell(
                'sonic-db-cli CONFIG_DB hget "FEATURE|dhcp_relay" "state"')["stdout"].strip()
            pytest_assert(current_feature_state in ["enabled", "always_enabled"],
                          "dhcp_relay feature changed in state {}: {}"
                          .format(state_name, current_feature_state))
            critical_status = duthost.critical_process_status("dhcp_relay")
            pytest_assert(critical_status["status"] and not critical_status["exited_critical_process"],
                          "dhcp_relay critical processes are unhealthy in state {}: {}"
                          .format(state_name, critical_status))
    finally:
        for current_vlan in vlan_names:
            _set_config_db_list_field(
                duthost, "VLAN", current_vlan, "dhcp_servers", original_isc_v4[current_vlan])
            _replace_config_db_hash(
                duthost, "DHCPV4_RELAY", current_vlan, original_native_v4[current_vlan])
            _replace_config_db_hash(
                duthost, "DHCP_RELAY", current_vlan, original_v6[current_vlan])
        _set_sonic_dhcpv4_relay_flag(
            duthost, original_flag if original_flag_present else None)
        original_relay_types = []
        if original_backend == "sonic":
            original_relay_types.append("sonic")
        elif any(original_isc_v4.values()):
            original_relay_types.append("isc")
        if any(config.get("dhcpv6_servers") for config in original_v6.values()):
            original_relay_types.append("v6")
        _restart_dhcp_relay_for_process_layout(duthost, original_relay_types)


def test_interface_binding(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data, relay_agent):
    if relay_agent == "isc-relay-agent":
        duthost = duthosts[rand_one_dut_hostname]
        skip_release(duthost, ["201811", "201911", "202106"])
        if not check_interface_status(duthost):
            config_reload(duthost)
            wait_critical_processes(duthost)
            pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost))
            wait_dhcp_relay_ready(duthost, ['isc'])
        output = duthost.shell("docker exec -t dhcp_relay ss -nlp | grep dhcrelay", module_ignore_errors=True)["stdout"]
        logger.info(output)
        for dhcp_relay in dut_dhcp_relay_data:
            assert "{}:67".format(dhcp_relay['downlink_vlan_iface']['name']) in output, \
                "{} is not found in {}".format("{}:67".format(dhcp_relay['downlink_vlan_iface']['name']), output)
            for iface in dhcp_relay['uplink_interfaces']:
                assert "{}:67".format(iface) in output, "{} is not found in {}".format("{}:67".format(iface), output)


def restart_dhcpmon_in_debug(duthost):
    program_name = "dhcpmon"
    program_pid_list = []
    program_list = duthost.shell("ps aux | grep {}".format(program_name))
    matches = re.findall(r'/usr/sbin/dhcpmon.*', program_list["stdout"])

    for program_info in program_list["stdout_lines"]:
        if program_name in program_info:
            program_pid = int(program_info.split()[1])
            program_pid_list.append(program_pid)

    for program_pid in program_pid_list:
        kill_cmd_result = duthost.shell("sudo kill -9 {} || true".format(program_pid), module_ignore_errors=True)
        # Get the exit code of 'kill' command
        exit_code = kill_cmd_result["rc"]
        if exit_code != 0:
            stderr = kill_cmd_result.get("stderr", "")
            if "No such process" not in stderr:
                pytest.fail("Failed to stop program '{}' before test. Error: {}".format(program_name, stderr))

    if matches:
        for dhcpmon_cmd in matches:
            if "-D" not in dhcpmon_cmd:
                dhcpmon_cmd += " -D"
            duthost.shell("docker exec -d dhcp_relay %s" % dhcpmon_cmd)
    else:
        assert False, "Failed to start dhcpmon in debug counter mode\n"


def get_acl_count_by_mark(rand_unselected_dut, mark):
    output = rand_unselected_dut.shell("iptables -nvL DHCP | grep 'DROP' | grep '{}' | awk '{{print $1}}'"
                                       .format(mark))
    pytest_assert(output["rc"] == 0 and len(output["stdout_lines"]) == 1,
                  "Failed get DHCP acl count for {}, err: {}".format(mark, output["stderr"]))
    return int(output["stdout"].strip())


@pytest.fixture(scope="function")
def verify_acl_drop_on_standby_tor(rand_unselected_dut, dut_dhcp_relay_data, testing_config, tbinfo, request):
    testing_mode, _ = testing_config
    if testing_mode == DUAL_TOR_MODE and "dualtor-aa" not in tbinfo["topo"]["name"]:
        pre_client_dhcp_acl_counts = {}
        for dhcp_relay in dut_dhcp_relay_data:
            client_interface_name = dhcp_relay["client_iface"]["name"]
            # Get acl mark per interface
            output = (rand_unselected_dut
                      .shell(r"ebtables -L INPUT | grep '\-i {} \-j mark \-\-mark\-set' | awk '{{print $6}}'"
                             .format(client_interface_name)))
            pytest_assert(output["rc"] == 0 and len(output["stdout_lines"]) == 1,
                          "Failed get DHCP acl mark for {}, err: {}".format(client_interface_name, output["stderr"]))
            mark = output["stdout"].strip()
            pre_client_dhcp_acl_counts[client_interface_name] = {"mark": mark}
            # Get acl count by acl mark
            pre_client_dhcp_acl_counts[client_interface_name]["count"] = get_acl_count_by_mark(rand_unselected_dut,
                                                                                               mark)

    yield

    if hasattr(request.node, "rep_call") and request.node.rep_call.failed:
        logger.info("Skip standby ToR ACL drop validation because the test call failed")
        return

    if testing_mode == DUAL_TOR_MODE and "dualtor-aa" not in tbinfo["topo"]["name"]:
        for client_interface_name, item in pre_client_dhcp_acl_counts.items():
            after_count = get_acl_count_by_mark(rand_unselected_dut, item["mark"])
            pytest_assert(after_count == item["count"] + CLIENT_SENT_PACKET_COUNT,
                          "Drop count of {} {} is unexpected, pre: {}, after: {}"
                          .format(client_interface_name, item["mark"], item["count"], after_count))


def test_dhcp_relay_default(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,    # noqa: F811
                            rand_unselected_dut,
                            toggle_all_simulator_ports_to_rand_selected_tor_m,    # noqa: F811
                            verify_acl_drop_on_standby_tor,
                            relay_agent):     # noqa: F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """

    testing_mode, duthost = testing_config

    skip_dhcpmon = any(vers in duthost.os_version for vers in ["201811", "201911", "202111"])
    try:
        for dhcp_relay in dut_dhcp_relay_data:
            if not skip_dhcpmon:
                dhcp_server_num = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
                if testing_mode == DUAL_TOR_MODE:
                    standby_duthost = rand_unselected_dut
                    restart_dhcpmon_in_debug(standby_duthost)
                    init_dhcpmon_counters(standby_duthost)
                    expected_standby_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +0/ +0, Offer: +0/ +0, Request: +0/ +0, ACK: +0/ +0+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'])
                    loganalyzer_standby = LogAnalyzer(ansible_host=standby_duthost, marker_prefix="dhcpmon counter")
                    marker_standby = loganalyzer_standby.init()
                    loganalyzer_standby.expect_regex = [expected_standby_agg_counter_message]
                restart_dhcpmon_in_debug(duthost)
                init_dhcpmon_counters(duthost)
                if testing_mode == DUAL_TOR_MODE:
                    expected_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +1/ +%d, Offer: +1/ +1, Request: +1/ +%d, ACK: +1/ +1+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num)
                else:
                    expected_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +1/ +%d, Offer: +1/ +1, Request: +2/ +%d, ACK: +1/ +1+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num * 2)
                loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="dhcpmon counter")
                marker = loganalyzer.init()
                loganalyzer.expect_regex = [expected_agg_counter_message]
            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPTest",
                       platform_dir="ptftests",
                       params={"hostname": duthost.hostname,
                               "client_port_index": dhcp_relay['client_iface']['port_idx'],
                               # This port is introduced to test DHCP relay packet received
                               # on other client port
                               "other_client_port": repr(dhcp_relay['other_client_ports']),
                               "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                               "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                               "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                               "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                               "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                               "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                               "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                               "dest_mac_address": BROADCAST_MAC,
                               "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                               "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                               "uplink_mac": str(dhcp_relay['uplink_mac']),
                               "testing_mode": testing_mode,
                               "kvm_support": True,
                               "relay_agent": relay_agent,
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                       log_file=("/tmp/dhcp_relay_test.DHCPTest.default.{}.log"
                                 .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                       is_python3=True)
            if not skip_dhcpmon:
                time.sleep(36)      # dhcpmon debug counter prints every 18 seconds
                loganalyzer.analyze(marker)
                dhcp_server_sum = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
                dhcp_relay_request_times = 2
                if testing_mode == DUAL_TOR_MODE:
                    loganalyzer_standby.analyze(marker_standby)
                    dhcp_relay_request_times = 1
                    # If the testing mode is DUAL_TOR_MODE, standby tor's dhcpmon relay counters should all be 0
                    validate_dhcpmon_counters(dhcp_relay, standby_duthost, {}, {})
                expected_downlink_counter = {
                    "RX": {"Unknown": 1, "Discover": 1, "Request": dhcp_relay_request_times, "Bootp": 1,
                           "Decline": 1, "Release": 1, "Inform": 1},
                    "TX": {"Unknown": 1, "Ack": 1, "Offer": 1, "Nak": 1}
                }
                expected_uplink_counter = {
                    "RX": {"Unknown": 1, "Nak": 1, "Ack": 1, "Offer": 1},
                    "TX": {"Unknown": dhcp_server_sum, "Bootp": dhcp_server_sum, "Discover": dhcp_server_sum,
                           "Request": dhcp_server_sum * dhcp_relay_request_times, "Inform": dhcp_server_sum,
                           "Decline": dhcp_server_sum, "Release": dhcp_server_sum}
                }
                validate_dhcpmon_counters(dhcp_relay, duthost,
                                          expected_uplink_counter,
                                          expected_downlink_counter)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    if not skip_dhcpmon:
        # Clean up - Restart DHCP relay service on DUT to recover original dhcpmon setting
        relay_types = ['sonic' if relay_agent == 'sonic-relay-agent' else 'isc']
        restart_dhcp_service(duthost, relay_types)
        if testing_mode == DUAL_TOR_MODE:
            restart_dhcp_service(standby_duthost, relay_types)
            pytest_assert(wait_until(120, 5, 0, check_interface_status, standby_duthost, relay_agent))
        pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost, relay_agent))


def test_dhcp_relay_with_source_port_ip_in_relay_enabled(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa: F811
    rand_unselected_dut,
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa: F811
    enable_source_port_ip_in_relay,
    verify_acl_drop_on_standby_tor,
    relay_agent  # noqa: F811
):

    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """
    testing_mode, duthost = testing_config

    skip_dhcpmon = any(vers in duthost.os_version for vers in ["201811", "201911", "202111"])

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            if not skip_dhcpmon:
                dhcp_server_num = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
                if testing_mode == DUAL_TOR_MODE:
                    standby_duthost = rand_unselected_dut
                    restart_dhcpmon_in_debug(standby_duthost)
                    init_dhcpmon_counters(standby_duthost)
                    expected_standby_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +0/ +0, Offer: +0/ +0, Request: +0/ +0, ACK: +0/ +0+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'])
                    loganalyzer_standby = LogAnalyzer(ansible_host=standby_duthost, marker_prefix="dhcpmon counter")
                    marker_standby = loganalyzer_standby.init()
                    loganalyzer_standby.expect_regex = [expected_standby_agg_counter_message]
                restart_dhcpmon_in_debug(duthost)
                init_dhcpmon_counters(duthost)
                if testing_mode == DUAL_TOR_MODE:
                    expected_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +1/ +%d, Offer: +1/ +1, Request: +1/ +%d, ACK: +1/ +1+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num)
                else:
                    expected_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +1/ +%d, Offer: +1/ +1, Request: +2/ +%d, ACK: +1/ +1+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num * 2)
                loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="dhcpmon counter")
                marker = loganalyzer.init()
                loganalyzer.expect_regex = [expected_agg_counter_message]

            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPTest",
                       platform_dir="ptftests",
                       params={"hostname": duthost.hostname,
                               "client_port_index": dhcp_relay['client_iface']['port_idx'],
                               # This port is introduced to test DHCP relay packet received
                               # on other client port
                               "other_client_port": repr(dhcp_relay['other_client_ports']),
                               "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                               "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                               "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                               "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                               "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                               "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                               "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                               "dest_mac_address": BROADCAST_MAC,
                               "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                               "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                               "uplink_mac": str(dhcp_relay['uplink_mac']),
                               "testing_mode": testing_mode,
                               "enable_source_port_ip_in_relay": True,
                               "kvm_support": True,
                               "relay_agent": relay_agent,
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                       log_file=("/tmp/dhcp_relay_test.DHCPTest.src_ip.{}.log"
                                 .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                       is_python3=True)

            if not skip_dhcpmon:
                time.sleep(36)      # dhcpmon debug counter prints every 18 seconds
                loganalyzer.analyze(marker)
                dhcp_server_sum = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
                dhcp_relay_request_times = 2
                if testing_mode == DUAL_TOR_MODE:
                    loganalyzer_standby.analyze(marker_standby)
                    dhcp_relay_request_times = 1
                    # If the testing mode is DUAL_TOR_MODE, standby tor's dhcpmon relay counters should all be 0
                    validate_dhcpmon_counters(dhcp_relay, standby_duthost, {}, {})
                expected_downlink_counter = {
                    "RX": {"Unknown": 1, "Discover": 1, "Request": dhcp_relay_request_times, "Bootp": 1,
                           "Decline": 1, "Release": 1, "Inform": 1},
                    "TX": {"Unknown": 1, "Ack": 1, "Offer": 1, "Nak": 1}
                }
                expected_uplink_counter = {
                    "RX": {"Unknown": 1, "Nak": 1, "Ack": 1, "Offer": 1},
                    "TX": {"Unknown": dhcp_server_sum, "Bootp": dhcp_server_sum, "Discover": dhcp_server_sum,
                           "Request": dhcp_server_sum * dhcp_relay_request_times, "Inform": dhcp_server_sum,
                           "Decline": dhcp_server_sum, "Release": dhcp_server_sum}
                }
                validate_dhcpmon_counters(dhcp_relay, duthost,
                                          expected_uplink_counter,
                                          expected_downlink_counter)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    if not skip_dhcpmon:
        # Clean up - Restart DHCP relay service on DUT to recover original dhcpmon setting
        relay_types = ['sonic' if relay_agent == 'sonic-relay-agent' else 'isc']
        restart_dhcp_service(duthost, relay_types)
        if testing_mode == DUAL_TOR_MODE:
            restart_dhcp_service(standby_duthost, relay_types)
            pytest_assert(wait_until(120, 5, 0, check_interface_status, standby_duthost, relay_agent))
        pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost, relay_agent))


def test_dhcp_relay_after_link_flap(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist,
                                    testing_config, relay_agent):
    """Test DHCP relay functionality on T0 topology after uplinks flap
       For each DHCP relay agent running on the DuT, with relay agent running, flap the uplinks,
       then test whether the DHCP relay agent relays packets properly.
    """
    testing_mode, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        # Bring all uplink interfaces down
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('config interface shutdown {}'.format(iface))

        pytest_assert(wait_until(50, 5, 0, check_link_status, duthost, dhcp_relay['uplink_interfaces'], "down"),
                      "Not all uplinks go down")

        # Bring all uplink interfaces back up
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('config interface startup {}'.format(iface))

        # Wait until uplinks are up and routes are recovered
        pytest_assert(wait_until(50, 5, 0, check_routes_to_dhcp_server, duthost, dut_dhcp_relay_data),
                      "Not all DHCP servers are routed")

        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": BROADCAST_MAC,
                           "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True,
                           "relay_agent": relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.link_flap.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


def test_dhcp_relay_start_with_uplinks_down(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist,
                                            testing_config, relay_agent):
    """Test DHCP relay functionality on T0 topology when relay agent starts with uplinks down
       For each DHCP relay agent running on the DuT, bring the uplinks down, then restart the
       relay agent while the uplinks are still down. Then test whether the DHCP relay agent
       relays packets properly.
    """
    testing_mode, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        # Bring all uplink interfaces down
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('config interface shutdown {}'.format(iface))

        pytest_assert(wait_until(50, 5, 0, check_link_status, duthost, dhcp_relay['uplink_interfaces'], "down"),
                      "Not all uplinks go down")

        # Restart DHCP relay service on DUT
        # dhcp_relay service has 3 times restart limit in 20 mins, for 4 vlans config it will hit the maximum limit
        # reset-failed before restart service
        cmds = ['systemctl reset-failed dhcp_relay', 'systemctl restart dhcp_relay']
        duthost.shell_cmds(cmds=cmds)

        # Sleep to give the DHCP relay container time to start up and
        # allow the relay agent to begin listening on the down interfaces
        time.sleep(40)

        # Bring all uplink interfaces back up
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('config interface startup {}'.format(iface))

        # Wait until uplinks are up and routes are recovered
        pytest_assert(wait_until(50, 5, 0, check_routes_to_dhcp_server, duthost, dut_dhcp_relay_data),
                      "Not all DHCP servers are routed")

        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": BROADCAST_MAC,
                           "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True,
                           "relay_agent": relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.uplinks_down.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


def test_dhcp_relay_unicast_mac(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                setup_standby_ports_on_rand_unselected_tor,				 # noqa: F811
                                toggle_all_simulator_ports_to_rand_selected_tor_m, relay_agent):     # noqa: F811
    """Test DHCP relay functionality on T0 topology with unicast mac
       Instead of using broadcast MAC, use unicast MAC of DUT and verify that DHCP relay functionality is entact.
    """
    testing_mode, duthost = testing_config

    if len(dut_dhcp_relay_data) > 1:
        pytest.skip("skip the unicast mac testcase in the multi-Vlan setting")

    for dhcp_relay in dut_dhcp_relay_data:
        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": duthost.facts["router_mac"] if testing_mode != DUAL_TOR_MODE
                                else str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True,
                           "relay_agent": relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.unicast_mac.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


def test_dhcp_relay_random_sport(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                 setup_standby_ports_on_rand_unselected_tor,				 # noqa: F811
                                 toggle_all_simulator_ports_to_rand_selected_tor_m,     # noqa: F811
                                 verify_acl_drop_on_standby_tor, relay_agent):    # noqa: F811
    """Test DHCP relay functionality on T0 topology with random source port (sport)
       If the client is SNAT'd, the source port could be changed to a non-standard port (i.e., not 68).
       Verify that DHCP relay works with random high sport.
    """
    testing_mode, duthost = testing_config

    RANDOM_CLIENT_PORT = random.choice(list(range(1000, 65535)))
    for dhcp_relay in dut_dhcp_relay_data:
        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": BROADCAST_MAC,
                           "client_udp_src_port": RANDOM_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True,
                           "relay_agent": relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.random_sport.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


def test_dhcp_relay_monitor_checksum_validation(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,                                             # noqa F811
                            rand_unselected_dut, relay_agent):     # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """

    testing_mode, duthost = testing_config

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            if testing_mode == DUAL_TOR_MODE:
                standby_duthost = rand_unselected_dut
                restart_dhcpmon_in_debug(standby_duthost)
                init_dhcpmon_counters(standby_duthost)
            restart_dhcpmon_in_debug(duthost)
            init_dhcpmon_counters(duthost)
            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPInvalidChecksumTest",
                       platform_dir="ptftests",
                       params={"hostname": duthost.hostname,
                               "client_port_index": dhcp_relay['client_iface']['port_idx'],
                               # This port is introduced to test DHCP relay packet received
                               # on other client port
                               "other_client_port": repr(dhcp_relay['other_client_ports']),
                               "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                               "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                               "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                               "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                               "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                               "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                               "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                               "dest_mac_address": BROADCAST_MAC,
                               "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                               "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                               "uplink_mac": str(dhcp_relay['uplink_mac']),
                               "testing_mode": testing_mode,
                               "kvm_support": True,
                               "relay_agent": relay_agent,
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                       log_file=("/tmp/dhcp_relay_test.DHCPTest.default.{}.log"
                                 .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                       is_python3=True)
            time.sleep(36)      # dhcpmon debug counter prints every 18 seconds
            if testing_mode == DUAL_TOR_MODE:
                # If the testing mode is DUAL_TOR_MODE, standby tor's dhcpmon relay counters should all be 0
                validate_dhcpmon_counters(dhcp_relay, standby_duthost, {}, {})
            expected_downlink_counter = {
                "RX": {"Malformed": 4}
            }
            expected_uplink_counter = {
                "RX": {"Malformed": 3}
            }
            validate_dhcpmon_counters(dhcp_relay, duthost,
                                      expected_uplink_counter,
                                      expected_downlink_counter)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err


def test_dhcp_broadcast_not_flooded(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist,
                                    testing_config, relay_agent):
    """Verify DHCP broadcast packets are trapped to CPU and not L2-flooded to other VLAN member ports.

    The COPP trap_action for DHCP is 'trap' (SAI_PACKET_ACTION_TRAP), meaning packets
    are sent exclusively to CPU and removed from the forwarding pipeline. This test
    sends DHCP Discover and Request broadcasts from a client port and asserts that
    no copy of the original broadcast appears on any other VLAN member port.
    """
    testing_mode, duthost = testing_config

    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("VS/KVM dataplane does not enforce SAI_PACKET_ACTION_TRAP removal semantics; "
                    "broadcasts are L2-flooded even when COPP traps them to CPU")

    for dhcp_relay in dut_dhcp_relay_data:
        if not dhcp_relay['other_client_ports']:
            pytest.skip("Need at least two VLAN member ports to verify non-flooding behavior")

        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPBroadcastNotFloodedTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "other_client_port": repr(dhcp_relay['other_client_ports']),
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": BROADCAST_MAC,
                           "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True,
                           "relay_agent": relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                   log_file=("/tmp/dhcp_relay_test.DHCPBroadcastNotFloodedTest.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)
