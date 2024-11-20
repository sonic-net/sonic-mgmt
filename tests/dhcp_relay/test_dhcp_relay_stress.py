import pytest
import time
import ptf.packet as scapy

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.dhcp_relay.dhcp_relay_utils import restart_dhcp_service
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until, capture_and_check_packet_on_dut
from tests.ptf_runner import ptf_runner

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs')
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
DEFAULT_DHCP_SERVER_PORT = 67


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
                            "testing_mode": testing_mode,
                            "kvm_support": True},
                   log_file="/tmp/dhcp_relay_test.stress.DHCPTest.log", is_python3=True)


def check_dhcp_stress_status(duthost, test_duration_seconds):
    # Monitor DHCP status during the test
    start_time = time.time()
    sleep_time = 30
    while time.time() - start_time < test_duration_seconds - sleep_time:
        # Check the status of the DHCP container
        dhcp_container_status = duthost.shell('docker ps | grep dhcp_relay')["stdout"]
        if dhcp_container_status == "":
            assert False, "DHCP container is NOT running."

        # Check CPU usage of the DHCP process
        dhcp_cpu_usage = duthost.shell('show processes cpu --verbose | grep dhc | awk \'{print $9}\'')["stdout"]
        if dhcp_cpu_usage:
            dhcp_cpu_usage_lines = dhcp_cpu_usage.splitlines()
            for cpu_usage in dhcp_cpu_usage_lines:
                cpu_usage_float = float(cpu_usage)
            assert cpu_usage_float < 50.0, "DHCP CPU usage is too high: {}%".format(cpu_usage_float)

        # Check the status of multiple DHCP processes inside the container
        dhcp_process_status = duthost.shell(
             'docker exec dhcp_relay supervisorctl status | grep dhcp | grep -v dhcp6')["stdout"]
        if dhcp_process_status:
            dhcp_process_status_lines = dhcp_process_status.splitlines()
            for dhcp_process_status_line in dhcp_process_status_lines:
                process_name, process_status = dhcp_process_status_line.split()[0], dhcp_process_status_line.split()[1],
                assert process_status == "RUNNING", "{} is not running!".format(process_name)
    time.sleep(sleep_time)


@pytest.mark.parametrize('dhcp_type', ['discover', 'offer', 'request', 'ack'])
def test_dhcp_relay_stress(ptfhost, ptfadapter, dut_dhcp_relay_data, validate_dut_routes_exist,
                           testing_config, dhcp_type, clean_processes_after_stress_test):
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
            "other_client_ports": repr(dhcp_relay['other_client_ports']),
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
            "kvm_support": True
        }
        count_file = '/tmp/dhcp_stress_test_{}.json'.format(dhcp_type)

        def _check_count_file_exists():
            command = 'ls {} > /dev/null 2>&1 && echo exists || echo missing'.format(count_file)
            output = ptfhost.shell(command)
            return not output['rc'] and output['stdout'].strip() == "exists"

        def _verify_server_packets(pkts):
            actual_count = len([pkt for pkt in pkts if pkt[scapy.BOOTP].xid == 0]) * num_dhcp_servers
            lower_bound = int(exp_count * 0.9)
            upper_bound = int(exp_count * 1.1)
            pytest_assert(lower_bound <= actual_count <= upper_bound,
                          "Mismatch: DUT count = {}, PTF count = {}.".format(actual_count, exp_count))

        def _verify_client_packets(pkts):
            actual_count = len([pkt for pkt in pkts if pkt[scapy.BOOTP].xid == 0])
            lower_bound = int(exp_count * 0.9)
            upper_bound = int(exp_count * 1.1)
            pytest_assert(lower_bound <= actual_count <= upper_bound,
                          "Mismatch: DUT count = {}, PTF count = {}.".format(actual_count, exp_count))

        if dhcp_type in ['discover', 'request']:
            interface = client_port_name
            eth_src = client_mac
            pkts_validator = _verify_server_packets
        else:
            interface = server_port_name
            eth_src = server_mac
            pkts_validator = _verify_client_packets

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


@pytest.fixture(scope="function")
def clean_processes_after_stress_test(ptfhost):
    yield
    ptfhost.shell("kill -9 $(ps aux | grep  dhcp_relay_stress_test | grep -v 'grep' | awk '{print $2}')",
                  module_ignore_errors=True)
