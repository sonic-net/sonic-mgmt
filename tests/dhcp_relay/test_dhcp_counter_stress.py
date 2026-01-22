import pytest
import logging
import time
import re

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.dhcp_relay_utils import init_dhcpmon_counters, validate_dhcpmon_counters, \
                                          validate_counters_and_pkts_consistency
from tests.common.utilities import wait_until, capture_and_check_packet_on_dut
from tests.dhcp_relay.dhcp_relay_utils import check_dhcp_stress_status
from tests.common.helpers.assertions import pytest_assert
from tests.ptf_runner import ptf_runner

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('physical')
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
DEFAULT_DHCP_SERVER_PORT = 67
DUAL_TOR_MODE = 'dual'
BUFFER_SIZE = 1024 * 1024  # 1MB
logger = logging.getLogger(__name__)
PACKET_RATE_PER_SEC_MAP = {
    "Mellanox-SN2700": 20
}
DEFAULT_PACKET_RATE_PER_SEC = 25


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        ignoreRegex = [
            r".*ERR memory_threshold_check: Free memory [.\d]+ is less then free memory threshold [.\d]+",
        ]
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(ignoreRegex)

    yield


@pytest.mark.parametrize('dhcp_type', ['discover', 'offer', 'request', 'ack'])
def test_dhcpmon_relay_counters_stress(ptfhost, ptfadapter, dut_dhcp_relay_data, validate_dut_routes_exist,
                                       testing_config, setup_standby_ports_on_rand_unselected_tor,
                                       toggle_all_simulator_ports_to_rand_selected_tor_m,     # noqa F811
                                       dhcp_type, clean_processes_after_stress_test,
                                       rand_unselected_dut, request):
    '''
    Test DHCP relay counters functionality can handle the maximum load within 0.01% miss.
    '''
    testing_mode, duthost = testing_config
    packets_send_duration = 120
    error_margin = 0.01
    dut_hwsku = duthost.facts["hwsku"]
    client_packets_per_sec = PACKET_RATE_PER_SEC_MAP.get(dut_hwsku, DEFAULT_PACKET_RATE_PER_SEC) \
        if request.config.option.max_packets_per_sec is None else request.config.option.max_packets_per_sec
    logger.info("Testing mode: {}, client packets per second: {}, error margin: {}".format(
        testing_mode, client_packets_per_sec, error_margin))
    for dhcp_relay in dut_dhcp_relay_data:
        client_port_id = dhcp_relay['client_iface']['port_idx']

        init_dhcpmon_counters(duthost)
        if testing_mode == DUAL_TOR_MODE:
            standby_duthost = rand_unselected_dut
            init_dhcpmon_counters(standby_duthost)

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

        def _verify_packets(pkts):
            # Default DB update timer for dhcpmon is 20s, hence wait for it to write DB
            time.sleep(25)
            validate_counters_and_pkts_consistency(dhcp_relay, duthost, pkts, interface_dict,
                                                   error_in_percentage=error_margin)
            if testing_mode == DUAL_TOR_MODE:
                validate_dhcpmon_counters(dhcp_relay, standby_duthost,
                                          {}, {}, 0)

        def get_ip_link_result(duthost):
            # Get the output of 'ip link' command and parse it to a dictionary of index: name
            cmd_res = duthost.shell('ip link')
            if cmd_res['rc'] != 0:
                pytest.fail("Failed to get ip link result: {}".format(cmd_res['stderr']))

            pattern = re.compile(r'^(\d+):\s+([^\s@:]+)')
            interface_dict = {}

            for line in cmd_res['stdout'].splitlines():
                match = pattern.match(line)
                if match:
                    index = int(match.group(1))
                    name = match.group(2)
                    interface_dict[name] = index

            return interface_dict

        with capture_and_check_packet_on_dut(
            duthost=duthost, interface='any',
            pkts_filter="udp dst port %s or udp dst port %s" % (DEFAULT_DHCP_SERVER_PORT,
                                                                DEFAULT_DHCP_CLIENT_PORT),
            pkts_validator=_verify_packets,
            tcpdump_buffer_size=BUFFER_SIZE
        ):
            ptf_runner(ptfhost, "ptftests", "dhcp_relay_stress_test.DHCPStress{}Test".format(dhcp_type.capitalize()),
                       platform_dir="ptftests", params=params,
                       log_file="/tmp/test_dhcpmon_relay_counters_stress.DHCPStressTest.log",
                       qlen=100000, is_python3=True, async_mode=True)
            check_dhcp_stress_status(duthost, packets_send_duration)
            pytest_assert(wait_until(600, 2, 0, _check_count_file_exists), "{} is missing".format(count_file))
            ptfhost.shell('rm -f {}'.format(count_file))
            interface_dict = get_ip_link_result(duthost)
