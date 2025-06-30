from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
import json
import logging

logger = logging.getLogger(__name__)
SUPPORTED_DHCPV4_TYPE = [
    "Unknown", "Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform", "Bootp"
]
SUPPORTED_DIR = ["TX", "RX"]


def restart_dhcp_service(duthost):
    duthost.shell('systemctl reset-failed dhcp_relay')
    duthost.shell('systemctl restart dhcp_relay')
    duthost.shell('systemctl reset-failed dhcp_relay')

    def _is_dhcp_relay_ready():
        output = duthost.shell('docker exec dhcp_relay supervisorctl status | grep dhcp | awk \'{print $2}\'',
                               module_ignore_errors=True)
        return (not output['rc'] and output['stderr'] == '' and len(output['stdout_lines']) != 0 and
                all(element == 'RUNNING' for element in output['stdout_lines']))

    pytest_assert(wait_until(120, 1, 10, _is_dhcp_relay_ready), "dhcp_relay is not ready after restarting")


def init_dhcpcom_relay_counters(duthost):
    command_output = duthost.shell("sudo sonic-clear dhcp_relay ipv4 counters")
    pytest_assert("Clear DHCPv4 relay counter done" == command_output["stdout"],
                  "dhcp_relay counters are not cleared successfully, output: {}".format(command_output["stdout"]))


def query_dhcpcom_relay_counter_result(duthost, query_key):
    '''
    Query the DHCPv4 counters from the COUNTERS_DB by the given key.
    The returned value is a dictionary and the counter values are converted to integers.
    Example return value:
    {"TX": {"Unknown": 0, "Discover": 48, "Offer": 0, "Request": 96, "Decline": 0, "Ack": 0, "Nak": 0, "Release": 0,
    "Inform": 0, "Bootp": 48}, "RX": {"Unknown": 0, "Discover": 0, "Offer": 1, "Request": 0, "Decline": 0, "Ack": 1,
    "Nak": 0, "Release": 0, "Inform": 0, "Bootp": 0}}
    '''
    counters_query_string = 'sonic-db-cli COUNTERS_DB hgetall "DHCPV4_COUNTER_TABLE:{key}"'
    shell_result = json.loads(
        duthost.shell(counters_query_string.format(key=query_key))['stdout'].replace("\"", "").replace("'", "\"")
    )
    return {
        rx_or_tx: {
            dhcp_type: int(counter_value) for dhcp_type, counter_value in counters.items()
        } for rx_or_tx, counters in shell_result.items()}


def query_and_sum_dhcpcom_relay_counters(duthost, vlan_name, interface_name_list):
    '''Query the DHCPv4 counters from the COUNTERS_DB and sum the counters for the given interface names.'''
    if interface_name_list is None or len(interface_name_list) == 0:
        # If no interface names are provided, return the counters for the VLAN interface only.
        return query_dhcpcom_relay_counter_result(duthost, vlan_name)
    total_counters = {}
    # If interface names are provided, sum all of the provided interface names' counters
    for interface_name in interface_name_list:
        internal_shell_result = query_dhcpcom_relay_counter_result(duthost, vlan_name + ":" + interface_name)
        for rx_or_tx, counters in internal_shell_result.items():
            total_value = total_counters.setdefault(rx_or_tx, {})
            for dhcp_type, counter_value in counters.items():
                total_value[dhcp_type] = total_value.get(dhcp_type, 0) + counter_value
    return total_counters


def compare_dhcpcom_relay_counters_with_warning(actual_counter, expected_counter, warning_msg, error_in_percentage=0.0):
    compare_result = compare_dhcpcom_relay_counter_values(
        actual_counter, expected_counter, error_in_percentage)
    while msg := next(compare_result, False):
        logger.warning(warning_msg + ": " + str(msg))


def compare_dhcpcom_relay_counter_values(dhcp_relay_counter, expected_counter, error_in_percentage=0.0):
    """Compare the DHCP relay counter value with the expected counter."""
    for dir in SUPPORTED_DIR:
        for dhcp_type in SUPPORTED_DHCPV4_TYPE:
            expected_value = expected_counter.setdefault(dir, {}).get(dhcp_type, 0)
            actual_value = dhcp_relay_counter.setdefault(dir, {}).get(dhcp_type, 0)
            logger_message = "DHCP relay counter {} {}: actual value {}, expected value {}".format(
                dir, dhcp_type, actual_value, expected_value)
            if expected_value == actual_value:
                logger.info(logger_message)
            else:
                yield logger_message + ", the actual value is not equal to the expected value"
            pytest_assert(abs(actual_value - expected_value) <=
                          int(expected_value * error_in_percentage / 100),
                          "DHCP relay counter {} {} {} is not equal to expected value {} within error {}%"
                          .format(dir, dhcp_type, actual_value, expected_value, error_in_percentage))


def validate_dhcpcom_relay_counters(dhcp_relay, duthost, expected_uplink_counter,
                                    expected_downlink_counter, error_in_percentage=0.0):
    """Validate the dhcpcom relay counters"""
    logger.info("Expected uplink counters: {}, expected downlink counters: {}, error in percentage: {}%".format(
        expected_uplink_counter, expected_downlink_counter, error_in_percentage))
    downlink_vlan_iface = dhcp_relay['downlink_vlan_iface']['name']
    # it can be portchannel or interface, it depends on the topology
    uplink_portchannels_or_interfaces = dhcp_relay['uplink_interfaces']
    client_iface = dhcp_relay['client_iface']['name']
    portchannels = dhcp_relay['portchannels']

    '''
    If the uplink_portchannels_or_interfaces are portchannels,
        uplink_interfaces will contains the members of the portchannels
    If the uplink_portchannels_or_interfaces are not portchannels,
        uplink_interfaces will equal to uplink_portchannels_or_interfaces
    '''
    uplink_interfaces = []
    compare_warning_msg = "Warning for comparing {} counters and {} counters, hostname:{}. "

    for portchannel_name in uplink_portchannels_or_interfaces:
        if portchannel_name in portchannels.keys():
            uplink_interfaces.extend(portchannels[portchannel_name]['members'])
            portchannel_counters = query_and_sum_dhcpcom_relay_counters(duthost,
                                                                        downlink_vlan_iface,
                                                                        [portchannel_name])
            members_counters = query_and_sum_dhcpcom_relay_counters(duthost,
                                                                    downlink_vlan_iface,
                                                                    portchannels[portchannel_name]['members'])

            # If the portchannel counters and its members' counters are not equal, yield a warning message
            compare_dhcpcom_relay_counters_with_warning(
                portchannel_counters, members_counters,
                compare_warning_msg.format(portchannel_name,
                                           portchannels[portchannel_name]['members'], duthost.hostname),
                error_in_percentage)
        else:
            uplink_interfaces.append(portchannel_name)

    vlan_interface_counter = query_and_sum_dhcpcom_relay_counters(duthost, downlink_vlan_iface, [])
    client_interface_counter = query_and_sum_dhcpcom_relay_counters(duthost, downlink_vlan_iface, [client_iface])
    uplink_portchannels_interfaces_counter = query_and_sum_dhcpcom_relay_counters(
        duthost, downlink_vlan_iface, uplink_portchannels_or_interfaces
    )
    uplink_interface_counter = query_and_sum_dhcpcom_relay_counters(duthost, downlink_vlan_iface, uplink_interfaces)

    compare_dhcpcom_relay_counters_with_warning(
        vlan_interface_counter, client_interface_counter,
        compare_warning_msg.format(downlink_vlan_iface, client_iface, duthost.hostname),
        error_in_percentage)
    compare_dhcpcom_relay_counters_with_warning(
        uplink_portchannels_interfaces_counter, uplink_interface_counter,
        compare_warning_msg.format(uplink_portchannels_or_interfaces, uplink_interfaces, duthost.hostname),
        error_in_percentage)
    compare_dhcpcom_relay_counters_with_warning(
        vlan_interface_counter, expected_downlink_counter,
        compare_warning_msg.format(downlink_vlan_iface, "expected_downlink_counter", duthost.hostname),
        error_in_percentage)
    compare_dhcpcom_relay_counters_with_warning(
        uplink_interface_counter, expected_uplink_counter,
        compare_warning_msg.format(uplink_interfaces, "expected_uplink_counter", duthost.hostname),
        error_in_percentage)
