import re
import ipaddress
import time
import json
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
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


def restart_dhcp_service(duthost, relay_types):
    """
    Restart dhcp_relay and wait until the requested relay agent(s) are ready.

    relay_types: a non-empty iterable of agent identifiers. Each entry must be one of:
        'isc'          -> Legacy / external v4 relay layout
                          (dockers/docker-dhcp-relay/dhcpv4-relay.agents.j2).
                          Required RUNNING:
                            - every isc-dhcpv4-relay-<Vlan> supervisord entry
                            - every dhcpmon-<Vlan> supervisord entry (paired
                              1:1 with the isc helpers via
                              dhcp-relay.monitors.j2)
                          Notes:
                            - The expected per-Vlan entries are read from
                              supervisord at poll time (parsed from
                              `supervisorctl status`), not derived from
                              CONFIG_DB's VLAN / DHCP_RELAY config. The j2
                              template only renders an isc-dhcpv4-relay-<Vlan>
                              + dhcpmon-<Vlan> pair for Vlans that actually
                              have v4 dhcp_servers configured, so supervisord
                              is the authoritative source for which entries
                              we wait on.
                            - If no Vlan has v4 dhcp_servers defined, the
                              matching set of isc-dhcpv4-relay-<Vlan> /
                              dhcpmon-<Vlan> entries is empty, the loops
                              iterate over nothing, and the 'isc' check
                              passes immediately. This is intentional:
                              there is genuinely nothing to wait for.

        'isc-internal' -> mx internal mode. dhcprelayd consolidates v4 relay
                          into a single `dhcrelay -iu docker0 ...` proc
                          (not a supervisord entry).
                          Required:
                            - exactly one such dhcrelay proc
                          Not checked:
                            - isc-dhcpv4-relay-<Vlan> supervisord entries
                              (stay STOPPED by design in this mode)
                            - dhcpmon-<Vlan> supervisord entries (also stay
                              STOPPED today: dhcpmon does not yet support
                              the mx/isc-internal layout, so when dhcprelayd
                              takes over the v4 relay it does not (re)spawn
                              dhcpmon)
                          TODO: extend this check once dhcpmon supports the
                          mx/isc-internal layout (when a single dhcpmon can
                          monitor the consolidated `dhcrelay -iu docker0`
                          proc); at that point we should require dhcpmon
                          RUNNING here too, mirroring the 'isc' check.

        'sonic'        -> Consolidated v4 relay layout
                          (dockers/docker-dhcp-relay/dhcpv4-sonic-relay.agents.j2).
                          One `/usr/sbin/dhcp4relay` proc handles all v4 VLANs.
                          Required RUNNING:
                            - the single `dhcp4relay` supervisord entry
                          Not checked:
                            - dhcpmon-<Vlan> supervisord entries (dhcp4relay
                              publishes its own counters, so per-Vlan dhcpmon
                              is not part of this layout)

        'v6'           -> IPv6 relay.
                          Required RUNNING:
                            - the `dhcp6relay` supervisord entry
                          Not checked:
                            - any dhcpv6mon / dhcp6mon equivalent. No such
                              daemon ships today; when one lands this check
                              will need to be extended to mirror the 'isc'
                              dhcpmon-<Vlan> check above.
                          TODO: revisit when dhcpv6mon ships.

    The orchestrator (`dhcprelayd`) is always required RUNNING. There is intentionally
    no default; each caller must declare which agent(s) it expects to be active.

    At most one of {'isc', 'isc-internal', 'sonic'} may appear in relay_types: the
    container layout makes them mutually exclusive (driven by has_sonic_dhcpv4_relay
    + mx internal mode), so any combination is unsatisfiable and is rejected up front.
    """
    if not relay_types:
        raise ValueError("restart_dhcp_service: relay_types must be a non-empty iterable")

    duthost.shell('systemctl reset-failed dhcp_relay')
    duthost.shell('systemctl restart dhcp_relay')
    duthost.shell('systemctl reset-failed dhcp_relay')

    wait_dhcp_relay_ready(duthost, relay_types)


def wait_dhcp_relay_ready(duthost, relay_types):
    """
    Wait (without restarting) until the requested relay agent(s) are ready.

    Same `relay_types` contract as `restart_dhcp_service`. Use this when the caller
    has already restarted dhcp_relay (or applied config that triggers a restart, e.g.
    `config reload`, `config load_minigraph`, GCU `apply-patch`) and only needs to
    block on readiness.
    """
    if not relay_types:
        raise ValueError("wait_dhcp_relay_ready: relay_types must be a non-empty iterable")
    relay_types = list(relay_types)
    valid = {'isc', 'isc-internal', 'sonic', 'v6'}
    bad = [t for t in relay_types if t not in valid]
    if bad:
        raise ValueError("wait_dhcp_relay_ready: invalid relay_types %s; allowed %s"
                         % (bad, sorted(valid)))
    v4_modes = [t for t in relay_types if t in {'isc', 'isc-internal', 'sonic'}]
    if len(v4_modes) > 1:
        raise ValueError(
            "wait_dhcp_relay_ready: at most one of {'isc', 'isc-internal', 'sonic'} "
            "may be requested per call (mutually exclusive in the relay container); got %s"
            % v4_modes)

    last_state = {'states': {}, 'internal_procs': []}

    def _supervisor_status_map():
        # supervisorctl returns rc != 0 if ANY entry is not RUNNING (e.g. the one-shot
        # 'start' / 'dependent-startup' entries are EXITED by design). Ignore the rc and
        # parse stdout - the per-entry RUNNING checks below are the real readiness gate.
        out = duthost.shell('docker exec dhcp_relay supervisorctl status',
                            module_ignore_errors=True)['stdout_lines']
        states = {}
        for line in out:
            parts = line.split()
            if len(parts) >= 2:
                # Strip optional "group:" prefix (e.g. "dhcp-relay:dhcprelayd" -> "dhcprelayd").
                states[parts[0].split(':')[-1]] = parts[1]
        return states

    def _is_dhcp_relay_ready():
        states = _supervisor_status_map()
        last_state['states'] = states
        if states.get('dhcprelayd') != 'RUNNING':
            return False
        if 'v6' in relay_types and states.get('dhcp6relay') != 'RUNNING':
            return False
        if 'isc' in relay_types:
            # Drive from supervisord's actual layout: every isc-dhcpv4-relay-*
            # entry currently present must be RUNNING. If none are present,
            # the container has no v4 helpers configured for this layout and
            # the 'isc' check is a no-op (legitimately so - callers expecting
            # specific helpers should pair with their own config setup).
            for name, state in states.items():
                if name.startswith('isc-dhcpv4-relay-') and state != 'RUNNING':
                    return False
            # Same layout-driven rule for dhcpmon-Vlan*: each entry is paired
            # 1:1 with isc-dhcpv4-relay-<Vlan> in the same supervisord conf
            # and must be RUNNING. Intentionally NOT checked in 'isc-internal'
            # / 'sonic' / 'v6' modes - see the docstring for the per-mode
            # rationale (and the v6 TODO for the upcoming dhcpv6mon).
            for name, state in states.items():
                if name.startswith('dhcpmon-') and state != 'RUNNING':
                    return False
        if 'isc-internal' in relay_types:
            internal = duthost.shell(
                "docker exec dhcp_relay pgrep -af '/usr/sbin/dhcrelay.*-iu docker0' || true"
            )['stdout_lines']
            internal = [line for line in internal if line.strip()]
            last_state['internal_procs'] = internal
            if len(internal) != 1:
                return False
        if 'sonic' in relay_types:
            if states.get('dhcp4relay') != 'RUNNING':
                return False
        return True

    pytest_assert(
        wait_until(240, 5, 10, _is_dhcp_relay_ready),
        "dhcp_relay is not ready (relay_types=%s last_supervisor_states=%s isc_internal_procs=%s)"
        % (relay_types, last_state['states'], last_state['internal_procs']))


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
                for message_type_value in pkt[scapy.DHCP].options:
                    if message_type_value[0] == 'message-type':
                        message_type_int = message_type_value[1]
                        # Get the message type value and convert it to an integer
                        break
                else:
                    continue
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
    restart_dhcp_service(duthost, ['sonic'] if dhcpv4_config_flag else ['isc'])


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


def check_routes_to_dhcp_server(duthost, dut_dhcp_relay_data):
    """Validate there is route on DUT to each DHCP server
    """
    output = duthost.shell("show ip bgp sum", module_ignore_errors=True)
    logger.info("bgp state: {}".format(output["stdout"]))
    output = duthost.shell("show int po", module_ignore_errors=True)
    logger.info("portchannel state: {}".format(output["stdout"]))
    default_gw_ip = dut_dhcp_relay_data[0]['default_gw_ip']
    dhcp_servers = set()
    for dhcp_relay in dut_dhcp_relay_data:
        dhcp_servers |= set(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])

    for dhcp_server in dhcp_servers:
        rtInfo = duthost.get_ip_route_info(ipaddress.ip_address(dhcp_server))
        nexthops = rtInfo["nexthops"]
        if len(nexthops) == 0:
            logger.info("Failed to find route to DHCP server '{0}'".format(dhcp_server))
            return False
        if len(nexthops) == 1:
            # if only 1 route to dst available - check that it's not default route via MGMT iface
            route_index_in_list = 0
            ip_dst_index = 0
            route_dst_ip = nexthops[route_index_in_list][ip_dst_index]
            if default_gw_ip and route_dst_ip == ipaddress.ip_address(default_gw_ip):
                logger.info("Found route to DHCP server via default GW(MGMT interface)")
                return False
    return True


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
