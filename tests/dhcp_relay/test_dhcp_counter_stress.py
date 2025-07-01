
import pytest
import ptf.packet as scapy
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.dhcp_relay_utils import init_dhcpcom_relay_counters, validate_dhcpcom_relay_counters
from tests.common.utilities import wait_until, capture_and_check_packet_on_dut
from tests.dhcp_relay.dhcp_relay_utils import check_dhcp_stress_status
from tests.common.helpers.assertions import pytest_assert
from tests.ptf_runner import ptf_runner


BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
DEFAULT_DHCP_SERVER_PORT = 67
DUAL_TOR_MODE = 'dual'
logger = logging.getLogger(__name__)


@pytest.mark.parametrize('dhcp_type', ['discover', 'offer', 'request', 'ack'])
def test_dhcpcom_relay_counters_stress(ptfhost, ptfadapter, dut_dhcp_relay_data, validate_dut_routes_exist,
                                       testing_config, setup_standby_ports_on_rand_unselected_tor,
                                       toggle_all_simulator_ports_to_rand_selected_tor_m,     # noqa F811
                                       dhcp_type, clean_processes_after_stress_test,
                                       rand_unselected_dut, request):
    '''
    Test DHCP relay counters functionality can handle the maximum load within 5% miss.
    '''
    testing_mode, duthost = testing_config
    packets_send_duration = 120
    error_margin = 0.01
    client_packets_per_sec = 25\
        if request.config.option.max_packets_per_sec is None else request.config.option.max_packets_per_sec
    logger.info("Testing mode: {}, client packets per second: {}, error margin: {}".format(
        testing_mode, client_packets_per_sec, error_margin))
    for dhcp_relay in dut_dhcp_relay_data:
        client_port_name = str(dhcp_relay['client_iface']['name'])
        client_port_id = dhcp_relay['client_iface']['port_idx']
        client_mac = ptfadapter.dataplane.get_mac(0, client_port_id).decode('utf-8')
        server_port_name = dhcp_relay['uplink_interfaces'][0]
        server_mac = ptfadapter.dataplane.get_mac(0, dhcp_relay['uplink_port_indices'][0]).decode('utf-8')
        num_dhcp_servers = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
        init_dhcpcom_relay_counters(duthost)
        if testing_mode == DUAL_TOR_MODE:
            standby_duthost = rand_unselected_dut
            init_dhcpcom_relay_counters(standby_duthost)

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

        def _verify_server_packets(pkts, dhcp_type):
            actual_count = len([pkt for pkt in pkts if pkt[scapy.BOOTP].xid == 0]) * num_dhcp_servers
            expected_uplink_counter = {
                "RX": {},
                "TX": {dhcp_type.capitalize(): actual_count}
            }
            expected_downlink_counter = {
                "RX": {dhcp_type.capitalize(): actual_count / num_dhcp_servers},
                "TX": {}
            }
            validate_dhcpcom_relay_counters(dhcp_relay, duthost,
                                            expected_uplink_counter,
                                            expected_downlink_counter, error_margin)
            if testing_mode == DUAL_TOR_MODE:
                validate_dhcpcom_relay_counters(dhcp_relay, standby_duthost,
                                                {}, {}, 0)

        def _verify_client_packets(pkts, dhcp_type):
            actual_count = len([pkt for pkt in pkts if pkt[scapy.BOOTP].xid == 0])
            expected_uplink_counter = {
                "RX": {dhcp_type.capitalize(): actual_count},
                "TX": {}
            }
            expected_downlink_counter = {
                "RX": {},
                "TX": {dhcp_type.capitalize(): actual_count}
            }
            validate_dhcpcom_relay_counters(dhcp_relay, duthost,
                                            expected_uplink_counter,
                                            expected_downlink_counter, error_margin)
            if testing_mode == DUAL_TOR_MODE:
                validate_dhcpcom_relay_counters(dhcp_relay, standby_duthost,
                                                {}, {}, 0)

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
            pkts_validator=pkts_validator,
            pkts_validator_args=[dhcp_type]
        ):
            ptf_runner(ptfhost, "ptftests", "dhcp_relay_stress_test.DHCPStress{}Test".format(dhcp_type.capitalize()),
                       platform_dir="ptftests", params=params,
                       log_file="/tmp/test_dhcpcom_relay_counters_stress.DHCPStressTest.log",
                       qlen=100000, is_python3=True, async_mode=True)
            check_dhcp_stress_status(duthost, packets_send_duration)
            pytest_assert(wait_until(600, 2, 0, _check_count_file_exists), "{} is missing".format(count_file))
            ptfhost.shell('rm -f {}'.format(count_file))
