import re
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
import json
import logging
import ptf.packet as scapy


logger = logging.getLogger(__name__)
SUPPORTED_DHCPV4_TYPE = [
     "Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform", "Bootp", "Unknown", "Malformed"
]
SUPPORTED_DHCPV6_TYPE = [
    "Solicit", "Advertise", "Request", "Confirm", "Renew", "Rebind", "Reply", "Release", "Decline", "Reconfigure",
    "Information-Request", "Relay-Forward", "Relay-Reply", "Unknown", "Malformed"
]
SUPPORTED_DIR = ["TX", "RX"]


def restart_dhcp_service(duthost):
    duthost.shell('systemctl reset-failed dhcp_relay')
    duthost.shell('systemctl restart dhcp_relay')
    duthost.shell('systemctl reset-failed dhcp_relay')

    def _is_dhcp_relay_ready():
        output = duthost.shell('docker exec dhcp_relay supervisorctl status | grep dhc | awk \'{print $2}\'',
                               module_ignore_errors=True)
        return (not output['rc'] and output['stderr'] == '' and len(output['stdout_lines']) != 0 and
                all(element == 'RUNNING' for element in output['stdout_lines']))

    pytest_assert(wait_until(120, 1, 10, _is_dhcp_relay_ready), "dhcp_relay is not ready after restarting")


def init_dhcpmon_counters(duthost, is_v6=False):
    command_output = duthost.shell("sudo sonic-clear dhcp_relay ip{} counters".format("v6" if is_v6 else "v4"))
    pytest_assert("Clear DHCP{} relay counter done".format("v6" if is_v6 else "v4") == command_output["stdout"],
                  "dhcp_relay counters are not cleared successfully, output: {}".format(command_output["stdout"]))


def query_dhcpmon_counter_result(duthost, query_key, is_v6=False):
    '''
    Query the DHCPv4/v6 counters from the COUNTERS_DB by the given key.
    The returned value is a dictionary and the counter values are converted to integers.
    Example return value for DHCPv4:
    {"TX": {"Unknown": 0, "Discover": 48, "Offer": 0, "Request": 96, "Decline": 0, "Ack": 0, "Nak": 0, "Release": 0,
    "Inform": 0, "Bootp": 48}, "RX": {"Unknown": 0, "Discover": 0, "Offer": 1, "Request": 0, "Decline": 0, "Ack": 1,
    "Nak": 0, "Release": 0, "Inform": 0, "Bootp": 0}}
    Example return value for DHCPv6:
    {'TX': "{'Unknown':'0','Solicit':'0','Advertise':'0','Request':'0','Confirm':'0','Renew':'0','Rebind':'0',
    'Reply':'0','Release':'0','Decline':'0','Reconfigure':'0','Information-Request':'0','Relay-Forward':'0',
    'Relay-Reply':'0','Malformed':'0'}", 'RX': "{'Unknown':'0','Solicit':'0','Advertise':'0',
    'Request':'0','Confirm':'0','Renew':'0','Rebind':'0','Reply':'0','Release':'0','Decline':'0','Reconfigure':'0',
    'Information-Request':'0','Relay-Forward':'0','Relay-Reply':'0','Malformed':'0'}"}
    '''
    counters_query_string = 'sonic-db-cli COUNTERS_DB hgetall "DHCP{}_COUNTER_TABLE:{}"' \
                            .format("V6" if is_v6 else "V4", query_key)
    shell_result = json.loads(
        duthost.shell(counters_query_string)['stdout'].replace("\"", "").replace("'", "\"")
    )
    return {
        rx_or_tx: {
            dhcp_type: int(counter_value) for dhcp_type, counter_value in counters.items()
        } for rx_or_tx, counters in shell_result.items()}


def query_and_sum_dhcpmon_counters(duthost, vlan_name, interface_name_list, is_v6=False):
    '''Query the DHCPv4/v6 counters from the COUNTERS_DB and sum the counters for the given interface names.'''
    if interface_name_list is None or len(interface_name_list) == 0:
        # If no interface names are provided, return the counters for the VLAN interface only.
        return query_dhcpmon_counter_result(duthost, vlan_name, is_v6)
    total_counters = {}
    # If interface names are provided, sum all of the provided interface names' counters
    for interface_name in interface_name_list:
        internal_shell_result = query_dhcpmon_counter_result(duthost, vlan_name + ":" + interface_name, is_v6)
        for rx_or_tx, counters in internal_shell_result.items():
            total_value = total_counters.setdefault(rx_or_tx, {})
            for dhcp_type, counter_value in counters.items():
                total_value[dhcp_type] = total_value.get(dhcp_type, 0) + counter_value
    return total_counters


def compare_dhcp_counters_with_warning(actual_counter, expected_counter, warning_msg,
                                       error_in_percentage=0.0, is_v6=False):
    compare_result = compare_dhcp_counters(
        actual_counter, expected_counter, error_in_percentage, is_v6)
    while msg := next(compare_result, False):
        logger.warning(warning_msg + ": " + str(msg))


def compare_dhcp_counters(actual_counter, expected_counter, error_in_percentage=0.0, is_v6=False):
    """Compare the DHCP counter (could come from relay or dhcpmon or anywhere) value with the expected counter."""
    for dir in SUPPORTED_DIR:
        for dhcp_type in SUPPORTED_DHCPV6_TYPE if is_v6 else SUPPORTED_DHCPV4_TYPE:
            expected_value = expected_counter.setdefault(dir, {}).get(dhcp_type, 0)
            actual_value = actual_counter.setdefault(dir, {}).get(dhcp_type, 0)
            logger_message = "DHCP counter {} {}: actual value {}, expected value {}".format(
                dir, dhcp_type, actual_value, expected_value)
            if expected_value == actual_value:
                logger.info(logger_message)
            else:
                yield logger_message + ", the actual value is not equal to the expected value"
            pytest_assert(abs(actual_value - expected_value) <=
                          int(expected_value * error_in_percentage / 100),
                          "DHCP relay counter {} {} {} is not equal to expected value {} within error {}%"
                          .format(dir, dhcp_type, actual_value, expected_value, error_in_percentage))


def validate_dhcpmon_counters(dhcp_relay, duthost, expected_uplink_counter,
                              expected_downlink_counter, error_in_percentage=0.0, is_v6=False):
    """Validate the dhcpmon counters against the expected counters."""
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
            portchannel_counters = query_and_sum_dhcpmon_counters(duthost,
                                                                  downlink_vlan_iface,
                                                                  [portchannel_name],
                                                                  is_v6)
            members_counters = query_and_sum_dhcpmon_counters(duthost,
                                                              downlink_vlan_iface,
                                                              portchannels[portchannel_name]['members'],
                                                              is_v6)

            # If the portchannel counters and its members' counters are not equal, yield a warning message
            compare_dhcp_counters_with_warning(
                portchannel_counters, members_counters,
                compare_warning_msg.format(portchannel_name,
                                           portchannels[portchannel_name]['members'], duthost.hostname),
                error_in_percentage, is_v6)
        else:
            uplink_interfaces.append(portchannel_name)

    vlan_interface_counter = query_and_sum_dhcpmon_counters(duthost, downlink_vlan_iface, [], is_v6)
    client_interface_counter = query_and_sum_dhcpmon_counters(duthost, downlink_vlan_iface, [client_iface], is_v6)
    uplink_portchannels_interfaces_counter = query_and_sum_dhcpmon_counters(
        duthost, downlink_vlan_iface, uplink_portchannels_or_interfaces, is_v6
    )
    uplink_interface_counter = query_and_sum_dhcpmon_counters(duthost, downlink_vlan_iface, uplink_interfaces, is_v6)
    compare_dhcp_counters_with_warning(
        vlan_interface_counter, client_interface_counter,
        compare_warning_msg.format(downlink_vlan_iface, client_iface, duthost.hostname),
        error_in_percentage, is_v6)
    compare_dhcp_counters_with_warning(
        uplink_portchannels_interfaces_counter, uplink_interface_counter,
        compare_warning_msg.format(uplink_portchannels_or_interfaces, uplink_interfaces, duthost.hostname),
        error_in_percentage, is_v6)
    compare_dhcp_counters_with_warning(
        client_interface_counter, expected_downlink_counter,
        compare_warning_msg.format(client_iface, "expected_downlink_counter", duthost.hostname),
        error_in_percentage, is_v6)
    compare_dhcp_counters_with_warning(
        uplink_interface_counter, expected_uplink_counter,
        compare_warning_msg.format(uplink_interfaces, "expected_uplink_counter", duthost.hostname),
        error_in_percentage, is_v6)


def calculate_counters_per_pkts(pkts, is_v6=False):
    """
    Calculate the counters for each interface index based on the packets.
    Return the counters for each interface index.
    """
    all_counters = {}
    for pkt in pkts:
        if hasattr(pkt, 'ifindex') and pkt.haslayer(scapy.DHCP6 if is_v6 else scapy.DHCP):
            counter = all_counters.setdefault(pkt.ifindex, {
                "RX": {},
                "TX": {}
            })
            if is_v6:
                if scapy.DHCP6 in pkt:
                    message_type_int = pkt[scapy.DHCP6].msgtype
                elif scapy.DHCP6_RelayForward in pkt:
                    message_type_int = pkt[scapy.DHCP6_RelayForward].msgtype  # Relay-Forward
                elif scapy.DHCP6_RelayReply in pkt:
                    message_type_int = pkt[scapy.DHCP6_RelayReply].msgtype  # Relay-Reply
            else:
                for opt, val in pkt[scapy.DHCP].options:
                    if opt == "message-type":
                        message_type_int = val
            message_type_str = (SUPPORTED_DHCPV6_TYPE if is_v6 else SUPPORTED_DHCPV4_TYPE)[message_type_int - 1] \
                if message_type_int is not None and message_type_int > 0 else "Unknown"
            sport = pkt[scapy.UDP].sport if pkt.haslayer(scapy.UDP) else None
            dport = pkt[scapy.UDP].dport if pkt.haslayer(scapy.UDP) else None
            if is_v6:
                if message_type_str in ["Solicit", "Request", "Relay-Reply"]:
                    counter["RX"][message_type_str] = counter["RX"].get(message_type_str, 0) + 1
                elif message_type_str in ["Advertise", "Reply", "Relay-Forward"]:
                    counter["TX"][message_type_str] = counter["TX"].get(message_type_str, 0) + 1
            else:
                # For DHCP Discover or Request, dport can only be 67, sport can be 68 or 67
                # All other packets are skipped
                if dport == 67 and (message_type_str == "Discover" or message_type_str == "Request"):
                    if sport == 68:
                        counter["RX"][message_type_str] = counter["RX"].get(message_type_str, 0) + 1
                    elif sport == 67:
                        counter["TX"][message_type_str] = counter["TX"].get(message_type_str, 0) + 1
                # DHCP Offer or Ack, sport can only be 67, dport can be 68 or 67
                # All other packets are skipped
                elif sport == 67 and (message_type_str == "Offer" or message_type_str == "Ack"):
                    if dport == 67:
                        counter["RX"][message_type_str] = counter["RX"].get(message_type_str, 0) + 1
                    elif dport == 68:
                        counter["TX"][message_type_str] = counter["TX"].get(message_type_str, 0) + 1

    return all_counters


def validate_counters_and_pkts_consistency(dhcp_relay, duthost, pkts, interface_name_index_mapping,
                                           error_in_percentage=0.0, is_v6=False):
    """Validate the dhcpmon counters and packets consistence"""
    downlink_vlan_iface = dhcp_relay['downlink_vlan_iface']['name']
    # it can be portchannel or interface, it depends on the topology
    uplink_portchannels_or_interfaces = dhcp_relay['uplink_interfaces']
    portchannels = dhcp_relay['portchannels']
    vlan_members = dhcp_relay['vlan_members']

    '''
    If the uplink_portchannels_or_interfaces are portchannels,
        uplink_interfaces will contains the members of the portchannels
    If the uplink_portchannels_or_interfaces are not portchannels,
        uplink_interfaces will equal to uplink_portchannels_or_interfaces
    '''
    uplink_interfaces = []
    compare_warning_msg = "Warning for comparing {} counters and {} counters, hostname:{}. "
    all_pkt_counters = calculate_counters_per_pkts(pkts, is_v6)
    for portchannel_name in uplink_portchannels_or_interfaces:
        if portchannel_name in portchannels.keys():
            uplink_interfaces.extend(portchannels[portchannel_name]['members'])
            portchannel_counters = query_and_sum_dhcpmon_counters(duthost,
                                                                  downlink_vlan_iface,
                                                                  [portchannel_name],
                                                                  is_v6)
            members_counters = query_and_sum_dhcpmon_counters(duthost,
                                                              downlink_vlan_iface,
                                                              portchannels[portchannel_name]['members'],
                                                              is_v6)

            # If the portchannel counters and its members' counters are not equal, yield a warning message

            portchannel_counter_from_pkts = all_pkt_counters.get(interface_name_index_mapping[portchannel_name],
                                                                 {"RX": {}, "TX": {}})

            members_counter_from_pkts = {
                "RX": {},
                "TX": {}
            }
            # sum the counters from pkts for each member of the portchannel
            for member in portchannels[portchannel_name]['members']:
                merge_counters(members_counter_from_pkts, all_pkt_counters.get(interface_name_index_mapping[member],
                                                                               {"RX": {}, "TX": {}}),
                               is_v6)

            # Compare the portchannel counters from dhcp relay counter and pkts
            compare_dhcp_counters_with_warning(
                portchannel_counters, portchannel_counter_from_pkts,
                compare_warning_msg.format(portchannel_name, portchannel_name + " from pkts", duthost.hostname),
                error_in_percentage, is_v6)

            # Compare the members counters from dhcp relay counter and pkts
            compare_dhcp_counters_with_warning(
                members_counters, members_counter_from_pkts,
                compare_warning_msg.format(portchannels[portchannel_name]['members'],
                                           str(portchannels[portchannel_name]['members']) + " from pkts",
                                           duthost.hostname),
                error_in_percentage, is_v6)

            # Compare the portchannel counters and its members' counters from dhcp relay counter
            compare_dhcp_counters_with_warning(
                portchannel_counters, members_counters,
                compare_warning_msg.format(portchannel_name,
                                           portchannels[portchannel_name]['members'], duthost.hostname),
                error_in_percentage, is_v6)
        else:
            uplink_interfaces.append(portchannel_name)

    vlan_interface_counter = query_and_sum_dhcpmon_counters(duthost, downlink_vlan_iface, [], is_v6)

    # uplink_portchannels_interfaces means the item can be the portchannel or the interface
    # Example:
    #   If there are 4 uplink portchannels, the uplink_portchannels_or_interfaces will be
    #   ['PortChannel101', 'PortChannel103', 'PortChannel105', 'PortChannel106']
    #   If there is no portchannel, the uplink_portchannels_or_interfaces will be
    #   ['Ethernet48', 'Ethernet49', 'Ethernet50', 'Ethernet51']
    uplink_portchannels_interfaces_counter = query_and_sum_dhcpmon_counters(
        duthost, downlink_vlan_iface, uplink_portchannels_or_interfaces, is_v6
    )

    """
    Example:
    Discover counter for PortChannels:
    {'TX': {'Unknown': 0, 'Discover': 141216, 'Offer': 0, 'Request': 0, 'Decline': 0, 'Ack': 0, 'Nak': 0, 'Release': 0,
    'Inform': 0, 'Bootp': 0},
    'RX': {'Unknown': 0, 'Discover': 0, 'Offer': 0, 'Request': 0, 'Decline': 0, 'Ack': 0, 'Nak': 0,
    'Release': 0, 'Inform': 0, 'Bootp': 0}}
    """
    # Query the counters for uplink portchannels interfaces such as:
    # ['Ethernet48', 'Ethernet49', 'Ethernet50', 'Ethernet51']
    uplink_interface_counter = query_and_sum_dhcpmon_counters(duthost, downlink_vlan_iface, uplink_interfaces, is_v6)

    vlan_interface_counter_from_pkts = all_pkt_counters.get(interface_name_index_mapping[downlink_vlan_iface],
                                                            {"RX": {}, "TX": {}})

    # calculate the sum of uplink portchannels interfaces counters from pkts
    uplink_portchannels_interfaces_counter_from_pkts = {
                "RX": {},
                "TX": {}
            }
    for iface in uplink_portchannels_or_interfaces:
        merge_counters(uplink_portchannels_interfaces_counter_from_pkts,
                       all_pkt_counters.get(interface_name_index_mapping[iface], {"RX": {}, "TX": {}}), is_v6)

    # calculate the sum of uplink interface counters from pkts
    uplink_interface_counter_from_pkts = {
                "RX": {},
                "TX": {}
            }
    for iface in uplink_interfaces:
        merge_counters(uplink_interface_counter_from_pkts,
                       all_pkt_counters.get(interface_name_index_mapping[iface], {"RX": {}, "TX": {}}), is_v6)

    # Compare the vlan interface counters from dhcp relay counter and pkts
    compare_dhcp_counters_with_warning(
        vlan_interface_counter, vlan_interface_counter_from_pkts,
        compare_warning_msg.format(downlink_vlan_iface, downlink_vlan_iface + " from pkts", duthost.hostname),
        error_in_percentage, is_v6)

    # Compare the sum of uplink portchannels counters from dhcp relay counter and pkts
    compare_dhcp_counters_with_warning(
        uplink_portchannels_interfaces_counter, uplink_portchannels_interfaces_counter_from_pkts,
        compare_warning_msg.format(uplink_portchannels_or_interfaces,
                                   str(uplink_portchannels_or_interfaces) + " from pkts", duthost.hostname),
        error_in_percentage, is_v6)

    # Compare the uplink portchannel interfaces counter and uplink interface counter from dhcyp relay counter
    compare_dhcp_counters_with_warning(
        uplink_portchannels_interfaces_counter, uplink_interface_counter,
        compare_warning_msg.format(uplink_portchannels_or_interfaces, uplink_interfaces, duthost.hostname),
        error_in_percentage, is_v6)

    # Compare the uplink interface counters from dhcp relay counter and pkts
    compare_dhcp_counters_with_warning(
        uplink_interface_counter, uplink_interface_counter_from_pkts,
        compare_warning_msg.format(uplink_interfaces, str(uplink_interfaces) + " from pkts", duthost.hostname),
        error_in_percentage, is_v6)

    # Compare the vlan interface counters from dhcp relay counter and pkts
    for vlan_member in vlan_members:
        vlan_member_counter = query_and_sum_dhcpmon_counters(duthost, downlink_vlan_iface, [vlan_member], is_v6)
        vlan_member_counter_from_pkts = all_pkt_counters.get(interface_name_index_mapping[vlan_member],
                                                             {"RX": {}, "TX": {}})
        compare_dhcp_counters_with_warning(
            vlan_member_counter, vlan_member_counter_from_pkts,
            compare_warning_msg.format(vlan_member, vlan_member + " from pkts", duthost.hostname),
            error_in_percentage, is_v6)


def merge_counters(source_counter, merge_counter, is_v6=False):
    for dir in SUPPORTED_DIR:
        for dhcp_type in SUPPORTED_DHCPV6_TYPE if is_v6 else SUPPORTED_DHCPV4_TYPE:
            source_counter[dir][dhcp_type] = source_counter.get(dir, {}).get(dhcp_type, 0) + \
                                                                    merge_counter.get(dir, {}).get(dhcp_type, 0)


def sonic_dhcpv4_flag_config_and_unconfig(duthost, dhcpv4_config_flag=False):
    """
    Enable or disable the SONiC DHCPv4 feature flag and restart the DHCP service on the DUT.
    """
    if dhcpv4_config_flag:
        duthost.shell('sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "has_sonic_dhcpv4_relay" "True"',
                      module_ignore_errors=True)
    else:
        duthost.shell('sonic-db-cli CONFIG_DB hdel "DEVICE_METADATA|localhost" "has_sonic_dhcpv4_relay"',
                      module_ignore_errors=True)

    # Save the config and restart DHCP relay service
    duthost.shell('sudo config save -y', module_ignore_errors=True)
    restart_dhcp_service(duthost)


@pytest.fixture()
def enable_sonic_dhcpv4_relay_agent(duthost, request):
    """
    Fixture to enable the DHCP relay feature flag and restart the service.
    """
    if "skip_config_dhcpv4_relay_agent" in request.keywords:
        yield
        return

    if "dut_dhcp_relay_data" in request.fixturenames:
        dut_dhcp_relay_data = request.getfixturevalue("dut_dhcp_relay_data")
    else:
        dut_dhcp_relay_data = None

    try:
        if request.getfixturevalue("relay_agent") == "sonic-relay-agent":
            sonic_dhcpv4_flag_config_and_unconfig(duthost, True)
            sonic_dhcp_relay_config(duthost, dut_dhcp_relay_data, True)
        yield
    finally:
        # Cleanup: disable the feature flag
        if request.getfixturevalue("relay_agent") == "sonic-relay-agent":
            sonic_dhcpv4_flag_config_and_unconfig(duthost, False)
            sonic_dhcp_relay_unconfig(duthost, dut_dhcp_relay_data)


def check_dhcpv4_socket_status(duthost, dut_dhcp_relay_data=None, process_and_socket_check=None):
    """
    Check if the DHCP relay agent is running and listening on expected sockets.
    Works for dhcp4relay.

    """
    # If checking for socket bindings
    cmd = "docker exec -t dhcp_relay ss -nlp | grep dhcp4relay"
    result = duthost.shell(cmd, module_ignore_errors=True)
    output = result.get("stdout", "")

    # Basic static checks
    expected_static_patterns = [
        r"p_raw\s+UNCONN.*dhcp4relay",
        r"udp\s+UNCONN.*0\.0\.0\.0:67.*dhcp4relay"
    ]

    for pattern in expected_static_patterns:
        if not re.search(pattern, output):
            logger.error("Missing expected socket match: %s", pattern)
            return False

    # Validate presence of DHCPv4 socket for each downlink VLAN interface from test data
    if dut_dhcp_relay_data is None:
        logger.error("Missing dut_dhcp_relay_data for VLAN check")
        return False

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface_name = dhcp_relay['downlink_vlan_iface']['name']
        vlan_pattern = r"%{}:67.*dhcp4relay".format(re.escape(vlan_iface_name))
        if not re.search(vlan_pattern, output):
            logger.error("Missing expected DHCPv4 VLAN socket for %s:67", vlan_iface_name)
            return False

    return True


def sonic_dhcp_relay_config(duthost, dut_dhcp_relay_data, socket_check=True):

    if dut_dhcp_relay_data:
        for dhcp_relay in dut_dhcp_relay_data:
            vlan = str(dhcp_relay['downlink_vlan_iface']['name'])
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers} {vlan}')

        if socket_check:
            pytest_assert(wait_until(40, 5, 0, check_dhcpv4_socket_status, duthost, dut_dhcp_relay_data,
                          "sonic_dhcpv4_socket_check"))


def sonic_dhcp_relay_unconfig(duthost, dut_dhcp_relay_data):

    if dut_dhcp_relay_data:
        for dhcp_relay in dut_dhcp_relay_data:
            vlan = str(dhcp_relay['downlink_vlan_iface']['name'])
            duthost.shell(f'config dhcpv4_relay del {vlan}', module_ignore_errors=True)
