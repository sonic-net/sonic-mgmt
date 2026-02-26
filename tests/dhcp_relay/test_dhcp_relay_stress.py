import pytest
import time
import logging
import ptf.packet as scapy

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.dhcp_relay.dhcp_relay_utils import restart_dhcp_service, check_dhcp_stress_status
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until, capture_and_check_packet_on_dut
from tests.ptf_runner import ptf_runner
from tests.common.dhcp_relay_utils import enable_sonic_dhcpv4_relay_agent

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs'),
    pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"])
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
DEFAULT_DHCP_SERVER_PORT = 67


@pytest.mark.disable_memory_utilization
def test_dhcp_relay_restart_with_stress(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                        request, setup_standby_ports_on_rand_unselected_tor,
                                        toggle_all_simulator_ports_to_rand_selected_tor_m,
                                        enable_sonic_dhcpv4_relay_agent,relay_agent):      # noqa F811
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
                            "client_iface_alias": str(dut_dhcp_relay_data[0]['client_iface']['alias']),
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
                            "downlink_vlan_iface_name": str(dut_dhcp_relay_data[0]['downlink_vlan_iface']['name']),
                            "relay_agent": relay_agent,
                            "duration": duration,
                            "pps": pps,
                            "kvm_support": True},
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

        # Allow additional drain time for in-flight packets from the stress
        # test that may still be relayed after the socket buffer check passes.
        time.sleep(5)

        # Run the DHCP relay test on the PTF host, make sure DHCPv4 relay is functionality good.
        # Retry up to 3 times because stale relayed packets from the stress test can cause
        # the strict packet-count validation inside DHCPTest to see extra packets.
        functional_params = {
            "hostname": duthost.hostname,
            "client_port_index": dut_dhcp_relay_data[0]['client_iface']['port_idx'],
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
            "testing_mode": testing_mode,
            "downlink_vlan_iface_name": str(dut_dhcp_relay_data[0]['downlink_vlan_iface']['name']),
            "relay_agent": relay_agent,
            "kvm_support": True
        }
        max_retries = 3
        for attempt in range(max_retries):
            result = ptf_runner(ptfhost, "ptftests", "dhcp_relay_test.DHCPTest",
                                platform_dir="ptftests", params=functional_params,
                                log_file="/tmp/dhcp_relay_test.stress.DHCPTest.log",
                                is_python3=True, module_ignore_errors=True)
            if result is True:
                break
            if attempt < max_retries - 1:
                logger.info("Functional DHCPTest failed on attempt %d/%d, "
                            "retrying after drain delay...", attempt + 1, max_retries)
                time.sleep(10)
            else:
                pytest.fail("Functional DHCPTest failed after {} attempts. "
                            "Last result: {}".format(max_retries, result))


@pytest.mark.disable_memory_utilization
@pytest.mark.parametrize('dhcp_type', ['discover', 'offer', 'request', 'ack'])
def test_dhcp_relay_stress(ptfhost, ptfadapter, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                           setup_standby_ports_on_rand_unselected_tor,
                           toggle_all_simulator_ports_to_rand_selected_tor_m,     # noqa F811
                           dhcp_type, clean_processes_after_stress_test,
                           enable_sonic_dhcpv4_relay_agent,relay_agent):
    """Test DHCP relay functionality on T0 topology
       and verify that HCP relay service can handle the maximum load without failure.
    """
    testing_mode, duthost = testing_config
    packets_send_duration = 120
    client_packets_per_sec = 10000

    for dhcp_relay in dut_dhcp_relay_data:
        client_port_name = str(dhcp_relay['client_iface']['name'])
        client_port_id = dhcp_relay['client_iface']['port_idx']
        client_mac = ptfadapter.dataplane.get_mac(0, client_port_id).decode('utf-8')
        server_port_name = dhcp_relay['uplink_interfaces'][0]
        server_mac = ptfadapter.dataplane.get_mac(0, dhcp_relay['uplink_port_indices'][0]).decode('utf-8')
        num_dhcp_servers = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
        params = {
            "hostname": duthost.hostname,
            "client_port_index": client_port_id,
            "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
            "other_client_port": repr(dhcp_relay['other_client_ports']),
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
            "packets_send_duration": packets_send_duration,
            "client_packets_per_sec": client_packets_per_sec,
            "testing_mode": testing_mode,
            "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name']),
            "relay_agent": relay_agent,
            "kvm_support": True
        }
        count_file = '/tmp/dhcp_stress_test_{}'.format(dhcp_type)

        def _check_count_file_exists():
            command = 'ls {} > /dev/null 2>&1 && echo exists || echo missing'.format(count_file)
            output = ptfhost.shell(command)
            return not output['rc'] and output['stdout'].strip() == "exists"

        def _verify_server_packets(pkts):
            dut_received = len([pkt for pkt in pkts
                               if pkt[scapy.BOOTP].xid <= packets_send_duration * client_packets_per_sec])
            logger.info("Stress test results: DUT received = {}, PTF relayed = {} "
                        "(across {} servers)".format(dut_received, exp_count, num_dhcp_servers))
            if dut_received == 0:
                logger.warning("DUT tcpdump captured 0 packets on client interface "
                               "(may be due to resource pressure during stress test)")
            pytest_assert(exp_count > 0,
                          "PTF captured 0 relayed packets on server interfaces. "
                          "Relay failed to forward any packets.")

        def _verify_client_packets(pkts):
            dut_received = len([pkt for pkt in pkts
                                if pkt[scapy.BOOTP].xid <= packets_send_duration * client_packets_per_sec])
            logger.info("Stress test results: DUT received = {}, PTF relayed = {}".format(
                        dut_received, exp_count))
            if dut_received == 0:
                logger.warning("DUT tcpdump captured 0 packets on server interface "
                               "(may be due to resource pressure during stress test)")
            pytest_assert(exp_count > 0,
                          "PTF captured 0 relayed packets on client interface. "
                          "Relay failed to forward any packets.")

        if dhcp_type in ['discover', 'request']:
            interface = client_port_name
            eth_src = client_mac
            pkts_validator = _verify_server_packets
        else:
            interface = server_port_name
            eth_src = server_mac
            pkts_validator = _verify_client_packets

        ptfhost.shell('rm -f {}'.format(count_file), module_ignore_errors=True)

        with capture_and_check_packet_on_dut(
            duthost=duthost, interface=interface,
            pkts_filter="ether src %s and udp dst port %s" % (eth_src, DEFAULT_DHCP_SERVER_PORT),
            pkts_validator=pkts_validator
        ):
            ptf_runner(ptfhost, "ptftests", "dhcp_relay_stress_test.DHCPStress{}Test".format(dhcp_type.capitalize()),
                       platform_dir="ptftests", params=params,
                       log_file="/tmp/dhcp_relay_stress_test.DHCPStressTest.log",
                       qlen=100000, is_python3=True, async_mode=True)
            check_dhcp_stress_status(duthost, packets_send_duration)
            pytest_assert(wait_until(600, 2, 0, _check_count_file_exists), "{} is missing".format(count_file))
            exp_count = int(ptfhost.shell('cat {}'.format(count_file))['stdout'].strip())
            ptfhost.shell('rm -f {}'.format(count_file))

