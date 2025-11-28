import pytest
import random  # noqa: F401
import time    # noqa: F401
import logging
import re      # noqa: F401

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa: F401
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzerError
from tests.common.dhcp_relay_utils import (
        check_dhcpv4_socket_status,
        sonic_dhcpv4_flag_config_and_unconfig,
        sonic_dhcp_relay_config,
        sonic_dhcp_relay_unconfig
)
from tests.common.dhcp_relay_utils import enable_sonic_dhcpv4_relay_agent  # noqa: F401

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs'),
    pytest.mark.parametrize("relay_agent", ["sonic-relay-agent"])
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
SINGLE_TOR_MODE = 'single'
CLIENT_VRF_NAME = "Vrf01"   # Global macro for Client VRF
MAX_HOP_COUNT = 16
CONFIG_HOP_COUNT = 2

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


@pytest.mark.skip_config_dhcpv4_relay_agent
def test_dhcpv4_feature_flag_validation(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data, relay_agent):
    """
    Test to verify DHCPv4 feature flag behavior:
    1. Enable feature flag and verify sonic-dhcpv4 process starts.
    2. Disable feature flag and verify fallback to ISC DHCP process.
    """

    duthost = duthosts[rand_one_dut_hostname]

    # Apply valid relay config and enable feature flag
    sonic_dhcp_relay_config(duthost, dut_dhcp_relay_data, False)
    sonic_dhcpv4_flag_config_and_unconfig(duthost, True)

    # Verify sonic-dhcpv4 socket are active
    pytest_assert(wait_until(40, 5, 0, check_dhcpv4_socket_status, duthost, dut_dhcp_relay_data,
                  "sonic_dhcpv4_socket_check"))

    # Cleanup config and disable feature flag
    sonic_dhcp_relay_unconfig(duthost, dut_dhcp_relay_data)
    sonic_dhcpv4_flag_config_and_unconfig(duthost, False)


@pytest.mark.skip_config_dhcpv4_relay_agent
def test_dhcpv4_relay_disabled_validation(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist,
                                          testing_config, setup_standby_ports_on_rand_unselected_tor,
                                          rand_unselected_dut,
                                          toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                                          relay_agent):

    """
    Test to verify that when the DHCPv4 feature flag is disabled:
    - The sonic-dhcpv4 process/socket is not running.
    - A DHCP Discover packet does not receive a response.
    """

    testing_mode, duthost = testing_config
    sonic_dhcp_relay_config(duthost, dut_dhcp_relay_data, False)

    try:
        for dhcp_relay in dut_dhcp_relay_data:
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
                               "dhcpv4_disable_flag": True,
                               "relay_agent": "sonic-relay-agent",
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])
                               },
                       log_file="/tmp/test_dhcpv4_relay_disabled_no_process_no_response.DHCPTest.log", is_python3=True)

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    finally:
        sonic_dhcp_relay_unconfig(duthost, dut_dhcp_relay_data)


@pytest.mark.parametrize("testcase", ["source_intf", "server_id_override"])
def test_dhcp_relay_option82_suboptions(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                        setup_standby_ports_on_rand_unselected_tor,
                                        rand_unselected_dut,
                                        toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
                                        testcase, relay_agent):

    """
    Test Case: DHCP relay option82

    Purpose:
        Validate DHCP relay functionality when using the default VRF.
        The test runs in multiple modes (source interface injection, server ID override) to verify behavior.

    Key Steps:
        - Configure DHCP relay with appropriate server IPs and test-mode specific parameters.
        - Remove existing relay configurations and reconfigure for this test case.
        - Run PTF test to verify relayed DHCP packet behavior (using Option 82 variations).
        - Validate correct transmission of DHCP Discover/Offer/Request/ACK messages through syslog regex patterns.
        - Clean up relay service to restore original DHCP monitor settings.

    Test Modes:
        - source_intf: Inserts 'source_interface' and 'link_selection' flags in relay config.
        - server_id_override: Enables 'server_id_override' flag to override DHCP server IP in Option 82.

    """

    testing_mode, duthost = testing_config
    link_selection = source_intf = server_id_override = None

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            vlan = str(dhcp_relay['downlink_vlan_iface']['name'])
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            duthost.shell(f'config dhcpv4_relay del {vlan}')
            loopback_iface = dhcp_relay["loopback_iface"]    # noqa: F841

            # Add test-case specific options
            if testcase == "source_intf":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers}'
                              f' --link-selection enable --source-interface {loopback_iface} {vlan}')
                link_selection = True
                source_intf = True
            elif testcase == "server_id_override":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers}'
                              f' --server-id-override enable {vlan}')
                server_id_override = True

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
                               "link_selection": link_selection,
                               "source_interface": source_intf,
                               "server_id_override": server_id_override,
                               "relay_agent": relay_agent,
                               "link_selection_ip": str(dhcp_relay['downlink_vlan_iface']['link_selection_ip']),
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])
                               },
                       log_file="/tmp/test_dhcp_relay_option82_suboptions.DHCPTest.log", is_python3=True)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err


@pytest.mark.parametrize("test_mode", [
                                    "discard",
                                    "replace",
                                    "append"
                                ])
def test_dhcp_relay_agent_mode(
        ptfhost,
        dut_dhcp_relay_data,
        validate_dut_routes_exist, testing_config,
        setup_standby_ports_on_rand_unselected_tor,
        rand_unselected_dut,
        toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa: F811
        relay_agent,    # noqa: F811
        test_mode
):

    """
    Test Case: DHCP Relay Agent Mode Functionality on T0 Topology

    Purpose:
        Validate the DHCP relay agent's behavior based on different `agent_relay_mode` settings in CONFIG_DB.
        These modes influence how Option 82 (Relay Agent Information Option) is handled when relaying DHCP packets.

    Relay Modes Tested:
        - "discard": Drops packets containing Option 82.
        - "forward_untouched": Forwards packets with Option 82 unmodified.
        - "forward_and_replace": Replaces existing Option 82 with new data before forwarding.
        - "forward_and_append": Appends a new Option 82 to packets that already have it.

    Key Actions:
        - Configures the device under test (DUT) with the selected relay mode.
        - Executes a PTF test to simulate DHCP traffic and validate relay behavior.
        - Cleans up after test by restoring DHCP relay state.

    """
    testing_mode, duthost = testing_config

    try:
        for dhcp_relay in dut_dhcp_relay_data:

            vlan = str(dhcp_relay['downlink_vlan_iface']['name'])
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            duthost.shell(f'config dhcpv4_relay del {vlan}')

            # Update CONFIG_DB
            duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers}'
                          f' --agent-relay-mode {test_mode} {vlan}')

            # Run PTF test with current mode
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_test.DHCPTest",
                platform_dir="ptftests",
                params={
                    "hostname": duthost.hostname,
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
                    "agent_relay_mode": test_mode,
                    "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name']),
                },
                log_file="/tmp/test_dhcp_relay_agent_mode.log",
                is_python3=True
            )

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err


@pytest.mark.parametrize("testcase", ["vrf_selection", "source_intf", "server_id_override"])
def test_dhcp_relay_with_non_default_vrf(
        ptfhost,
        dut_dhcp_relay_data,
        validate_dut_routes_exist,
        testing_config,
        setup_standby_ports_on_rand_unselected_tor,
        rand_unselected_dut,
        toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa: F811
        testcase,
        relay_agent
):

    """
    Test Case: DHCP Relay with Non-Default VRF on T0 Topology

    Purpose:
        Validate the DHCP relay agent's behavior when configured to operate over a non-default VRF.
        Ensures correct handling of various advanced DHCP features such as VRF selection, source interface,
        and server ID override.

    Testcases:
        - "vrf_selection": Validates that the DHCP relay functions properly when `vrf_selection` is enabled.
        - "source_intf": Verifies correct handling when a specific source interface is used and `link_selection`
          is enabled.
        - "server_id_override": Confirms that the DHCP relay can override the server ID when instructed.

    Key Steps:
        1. Remove IP addresses from involved interfaces.
        2. Create and configure a non-default VRF (`CLIENT_VRF_NAME`).
        3. Bind VLAN and portchannel interfaces to the new VRF.
        4. Re-assign IP addresses and static default routes within the VRF.
        5. Update the CONFIG_DB with test-specific DHCP relay configurations.
        6. Use the PTF test framework to simulate DHCP discover/request flows and validate expected behavior.
        8. Clean up configurations post test (remove VRF, restore IPs, etc.).

    """

    testing_mode, duthost = testing_config
    link_selection = source_intf = server_id_override = None

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface = str(dhcp_relay['downlink_vlan_iface']['name'])
        portchannels = dhcp_relay['portchannels_with_ips']
        vlan_ip = "{}/{}".format(dhcp_relay['downlink_vlan_iface']['addr'], dhcp_relay['downlink_vlan_iface']['mask'])

    # Step 1: Remove IPs from interfaces
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip remove {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip remove {vlan_iface} {vlan_ip}")

    # Step 2: Create VRF
    duthost.shell(f"sudo config vrf add {CLIENT_VRF_NAME}")

    # Step 3: Bind interfaces to VRF
    for pc in portchannels:
        duthost.shell(f"sudo config interface vrf bind {pc} {CLIENT_VRF_NAME}")

    duthost.shell(f"sudo config interface vrf bind {vlan_iface} {CLIENT_VRF_NAME}")
    # Step 4: Re-add IPs to interfaces
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip add {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip add {vlan_iface} {vlan_ip}")
    # Step 5: Add default routes via nexthop in Vrf
    first_params = list(portchannels.values())[0]    # noqa: F841
    duthost.shell(f"sudo config route add prefix vrf {CLIENT_VRF_NAME} 0.0.0.0/0 nexthop"
                  f" vrf {CLIENT_VRF_NAME} {first_params['nexthop']}")

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            duthost.shell(f'config dhcpv4_relay del {vlan_iface}')
            loopback_iface = dhcp_relay["loopback_iface"]    # noqa: F841

            # Add test-case specific options
            if testcase == "vrf_selection":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers}'
                              f' --vrf-selection enable {vlan_iface}')
            elif testcase == "source_intf":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers}'
                              f' --vrf-selection enable --source-interface {loopback_iface}'
                              f' --link-selection enable {vlan_iface}')
                link_selection = True
                source_intf = True
            elif testcase == "server_id_override":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers}'
                              f' --vrf-selection enable --server-id-override enable {vlan_iface}')
                server_id_override = True

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
                               "link_selection": link_selection,
                               "source_interface": source_intf,
                               "server_id_override": server_id_override,
                               "vrf_selection": True,
                               "relay_agent": relay_agent,
                               "client_vrf": CLIENT_VRF_NAME,
                               "portchannels_ip_list": dhcp_relay['portchannels_ip_list'],
                               "link_selection_ip": str(dhcp_relay['downlink_vlan_iface']['link_selection_ip']),
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])
                               },
                       log_file="/tmp/test_dhcp_relay_with_non_default_vrf.DHCPTest.log", is_python3=True)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    finally:
        duthost.shell(f"config dhcpv4_relay del {vlan_iface}", module_ignore_errors=True)
        # VRF config cleanup
        duthost.shell(f"sudo config route del prefix vrf {CLIENT_VRF_NAME} 0.0.0.0/0 nexthop"
                      f" vrf {CLIENT_VRF_NAME} {first_params['nexthop']}")
        duthost.shell(f"sudo config vrf del {CLIENT_VRF_NAME}")
        for pc, params in portchannels.items():
            duthost.shell(f"sudo config interface ip add {pc} {params['ip']}")

        duthost.shell(f"sudo config interface ip add {vlan_iface} {vlan_ip}")


def test_dhcp_relay_with_different_non_default_vrf(
        ptfhost,
        dut_dhcp_relay_data,
        validate_dut_routes_exist,
        testing_config,
        setup_standby_ports_on_rand_unselected_tor,
        rand_unselected_dut,
        toggle_all_simulator_ports_to_rand_selected_tor_m,   # noqa: F811
        relay_agent
):
    """
    Test Case: test_dhcp_relay_with_different_non_default_vrf

    Objective:
        Verify that the DHCP relay agent correctly relays DHCPv4 packets when the client-facing interface
        (VLAN interface) and the server-facing interfaces (PortChannels) are bound to different, non-default VRFs.

    Test Steps:
        1. Remove existing IPs from VLAN and PortChannel interfaces.
        2. Create two separate VRFs: one for the client and one for the server.
        3. Bind VLAN interface to CLIENT_VRF_NAME and PortChannels to SERVER_VRF_NAME.
        4. Reassign IPs back to the interfaces.
        5. Add default routes in SERVER_VRF_NAME for DHCP server reachability.
        6. Configure DHCP relay with vrf_selection and link_selection enabled.
        7. Run the DHCP relay test from the PTF host.
        8. Optionally validate DHCP relay logs using loganalyzer.
        9. Cleanup: remove routes and VRF bindings, restore original config.

    Expected Results:
        - DHCP Discover, Offer, Request, and ACK messages are relayed successfully across different VRFs.
        - Relay behavior matches the expected counters/logs (if enabled).

    """

    SERVER_VRF_NAME = "Vrf03"

    testing_mode, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface = str(dhcp_relay['downlink_vlan_iface']['name'])
        portchannels = dhcp_relay['portchannels_with_ips']
        vlan_ip = "{}/{}".format(dhcp_relay['downlink_vlan_iface']['addr'], dhcp_relay['downlink_vlan_iface']['mask'])

    # Step 1: Remove IPs from interfaces
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip remove {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip remove {vlan_iface} {vlan_ip}")

    # Step 2: Create VRF
    duthost.shell(f"sudo config vrf add {CLIENT_VRF_NAME}")
    duthost.shell(f"sudo config vrf add {SERVER_VRF_NAME}")

    # Step 3: Bind interfaces to VRF
    for pc in portchannels:
        duthost.shell(f"sudo config interface vrf bind {pc} {SERVER_VRF_NAME}")

    duthost.shell(f"sudo config interface vrf bind {vlan_iface} {CLIENT_VRF_NAME}")
    # Step 4: Re-add IPs to interfaces
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip add {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip add {vlan_iface} {vlan_ip}")
    # Step 5: Add default routes via nexthop in Vrf
    first_params = list(portchannels.values())[0]    # noqa: F841
    duthost.shell(f"sudo config route add prefix vrf {SERVER_VRF_NAME} 0.0.0.0/0 nexthop"
                  f" vrf {SERVER_VRF_NAME} {first_params['nexthop']}")

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            loopback_iface = dhcp_relay["loopback_iface"]    # noqa: F841
            duthost.shell(f'config dhcpv4_relay del {vlan_iface}')

            duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers}'
                          f' --server-vrf {SERVER_VRF_NAME} --vrf-selection enable'
                          f' --source-interface {loopback_iface} --link-selection enable'
                          f' --server-id-override enable {vlan_iface}')

            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPTest",
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
                               "client_vrf": CLIENT_VRF_NAME,
                               "link_selection_ip": str(dhcp_relay['downlink_vlan_iface']['link_selection_ip']),
                               "server_vrf": True,
                               "portchannels_ip_list": dhcp_relay['portchannels_ip_list'],
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                       log_file="/tmp/test_dhcp_relay_with_different_non_default_vrf.DHCPTest.log", is_python3=True)

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    finally:
        duthost.shell(f"config dhcpv4_relay del {vlan_iface}", module_ignore_errors=True)
        # VRF config cleanup
        duthost.shell(f"sudo config route del prefix vrf {SERVER_VRF_NAME} 0.0.0.0/0 nexthop"
                      f" vrf {SERVER_VRF_NAME} {first_params['nexthop']}")

        duthost.shell(f"sudo config vrf del {CLIENT_VRF_NAME}")
        duthost.shell(f"sudo config vrf del {SERVER_VRF_NAME}")
        for pc, params in portchannels.items():
            duthost.shell(f"sudo config interface ip add {pc} {params['ip']}")

        duthost.shell(f"sudo config interface ip add {vlan_iface} {vlan_ip}")


@pytest.mark.parametrize("max_hop_count", [CONFIG_HOP_COUNT, MAX_HOP_COUNT])
def test_dhcp_max_hop_count(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,
                            rand_unselected_dut,
                            toggle_all_simulator_ports_to_rand_selected_tor_m, relay_agent,    # noqa: F811
                            max_hop_count):

    testing_mode, duthost = testing_config

    try:
        for dhcp_relay in dut_dhcp_relay_data:

            vlan = str(dhcp_relay['downlink_vlan_iface']['name'])
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            duthost.shell(f'config dhcpv4_relay del {vlan}')

            # Update CONFIG_DB
            duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers}'
                          f' --agent-relay-mode append --max-hop-count {max_hop_count} {vlan}')

            # Run PTF test with current mode
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_test.DHCPTest",
                platform_dir="ptftests",
                params={
                    "hostname": duthost.hostname,
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
                    "agent_relay_mode": "append",
                    "max_hop_count": max_hop_count,
                    "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name']),
                },
                log_file="/tmp/test_dhcp_relay_agent_mode.log",
                is_python3=True
            )

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err
