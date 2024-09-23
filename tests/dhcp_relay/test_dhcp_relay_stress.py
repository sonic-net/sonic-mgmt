import pytest
import time

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.dhcp_relay.dhcp_relay_utils import restart_dhcp_service
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs')
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68


def test_dhcp_relay_restart_with_stress(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                        request, setup_standby_ports_on_rand_unselected_tor,
                                        toggle_all_simulator_ports_to_rand_selected_tor_m):      # noqa F811
    """
    This test case is to make sure DHCPv4 relay would work well when startup with stress packets coming
    """
    # Only test First Vlan
    pytest_require(len(dut_dhcp_relay_data) >= 1, "Skip because cannot get enough vlan data")
    testing_mode, duthost = testing_config

    # Unit: s, indicates duration time for sending stress packets
    duration = request.config.getoption("--stress_restart_duration")
    # Packets sending count per second
    pps = request.config.getoption("--stress_restart_pps")
    test_rounds = request.config.getoption("--stress_restart_round")

    for _ in range(test_rounds):
        # Keep sending packets and then restart dhcp_relay
        ptf_runner(ptfhost, "ptftests", "dhcp_relay_stress_test.DHCPContinuousStressTest", platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dut_dhcp_relay_data[0]['client_iface']['port_idx'],
                            # This port is introduced to test DHCP relay packet received
                            # on other client port
                            "other_client_port": repr(dut_dhcp_relay_data[0]['other_client_ports']),
                            "leaf_port_indices": repr(dut_dhcp_relay_data[0]['uplink_port_indices']),
                            "num_dhcp_servers": len(dut_dhcp_relay_data[0]['downlink_vlan_iface']['dhcp_server_addrs']),
                            "server_ip": dut_dhcp_relay_data[0]['downlink_vlan_iface']['dhcp_server_addrs'],
                            "relay_iface_ip": str(dut_dhcp_relay_data[0]['downlink_vlan_iface']['addr']),
                            "relay_iface_mac": str(dut_dhcp_relay_data[0]['downlink_vlan_iface']['mac']),
                            "relay_iface_netmask": str(dut_dhcp_relay_data[0]['downlink_vlan_iface']['mask']),
                            "dest_mac_address": BROADCAST_MAC,
                            "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                            "switch_loopback_ip": dut_dhcp_relay_data[0]['switch_loopback_ip'],
                            "uplink_mac": str(dut_dhcp_relay_data[0]['uplink_mac']),
                            "testing_mode": testing_mode,
                            "duration": duration,
                            "pps": pps},
                   log_file="/tmp/dhcp_relay_stress_test.DHCPContinuousStressTest.log", is_python3=True,
                   async_mode=True)

        restart_dhcp_service(duthost)

        # Wait packets send during and after dhcrelay starting
        time.sleep(10)
        # Make sure there is not stress packets sent
        ptfhost.shell("kill -9 $(ps aux | grep DHCPContinuousStress | grep -v 'grep' | awk '{print $2}')",
                      module_ignore_errors=True)

        def _check_socket_buffer():
            output = duthost.shell('ss -nlpu | grep Vlan | awk \'{print $2}\'',
                                   module_ignore_errors=True)
            return (not output['rc'] and output['stderr'] == '' and len(output['stdout_lines']) != 0 and
                    all(element == '0' for element in output['stdout_lines']))

        # Make sure there are not packets left in socket buffer.
        pytest_assert(wait_until(30, 1, 0, _check_socket_buffer), "Socket buffer is not zero")

        # Run the DHCP relay test on the PTF host, make sure DHCPv4 relay is functionality good
        ptf_runner(ptfhost, "ptftests", "dhcp_relay_test.DHCPTest", platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dut_dhcp_relay_data[0]['client_iface']['port_idx'],
                            # This port is introduced to test DHCP relay packet received
                            # on other client port
                            "other_client_port": repr(dut_dhcp_relay_data[0]['other_client_ports']),
                            "client_iface_alias": str(dut_dhcp_relay_data[0]['client_iface']['alias']),
                            "leaf_port_indices": repr(dut_dhcp_relay_data[0]['uplink_port_indices']),
                            "num_dhcp_servers":
                                len(dut_dhcp_relay_data[0]['downlink_vlan_iface']['dhcp_server_addrs']),
                            "server_ip": dut_dhcp_relay_data[0]['downlink_vlan_iface']['dhcp_server_addrs'],
                            "relay_iface_ip": str(dut_dhcp_relay_data[0]['downlink_vlan_iface']['addr']),
                            "relay_iface_mac": str(dut_dhcp_relay_data[0]['downlink_vlan_iface']['mac']),
                            "relay_iface_netmask": str(dut_dhcp_relay_data[0]['downlink_vlan_iface']['mask']),
                            "dest_mac_address": BROADCAST_MAC,
                            "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                            "switch_loopback_ip": dut_dhcp_relay_data[0]['switch_loopback_ip'],
                            "uplink_mac": str(dut_dhcp_relay_data[0]['uplink_mac']),
                            "testing_mode": testing_mode},
                   log_file="/tmp/dhcp_relay_test.stress.DHCPTest.log", is_python3=True)
