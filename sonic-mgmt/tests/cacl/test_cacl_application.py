import ipaddress
import json
import logging
import pytest

from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer globally
    pytest.mark.topology('any')
]

ignored_iptable_rules = []

@pytest.fixture(scope="module", autouse=True)
def ignore_hardcoded_cacl_rule_on_dualtor(tbinfo):
    global ignored_iptable_rules
    # There are some hardcoded cacl rule for dualtot testbed, which should be ignored
    if "dualtor" in tbinfo['topo']['name']:
        rules_to_ignore = [
        "-A INPUT -p udp -m udp --dport 67 -j DHCP",
        "-A DHCP -j RETURN",
        "-N DHCP"
        ]
        ignored_iptable_rules += rules_to_ignore

@pytest.fixture(scope="function", params=["active_tor", "standby_tor"])
def duthost_dualtor(request, upper_tor_host, lower_tor_host, toggle_all_simulator_ports_to_upper_tor):
    which_tor = request.param

    # Add expected DHCP mark iptable rules for standby tor, not for active tor.
    if which_tor == 'standby_tor':
        dut = lower_tor_host
        logger.info("Select standby tor, generate expected DHCP iptables rules for standby tor.")
    else:
        logger.info("Select active tor, don't need to add expected DHCP mark rules.")
        dut = upper_tor_host
    return dut

@pytest.fixture
def expected_dhcp_rules_for_standby(duthost_dualtor, lower_tor_host):
    expected_dhcp_rules = []
    if duthost_dualtor.hostname == lower_tor_host.hostname: 
        mark_keys = duthost_dualtor.shell('/usr/bin/redis-cli -n 6  --raw keys "DHCP_PACKET_MARK*"', module_ignore_errors=True)['stdout']
        mark_keys = mark_keys.split("\n")
        for key in mark_keys:
            mark = duthost_dualtor.shell('/usr/bin/redis-cli -n 6 --raw hget "{}" "mark"'.format(key), module_ignore_errors=False)['stdout']
            if not mark:
                continue
            rule = "-A DHCP -m mark --mark {} -j DROP".format(mark)
            expected_dhcp_rules.append(rule)
    return expected_dhcp_rules

@pytest.fixture(scope="module")
def docker_network(duthost):

    output = duthost.command("docker inspect bridge")

    docker_containers_info = json.loads(output['stdout'])[0]['Containers']
    ipam_info = json.loads(output['stdout'])[0]['IPAM']

    docker_network = {}
    """
    FIXME: Work around dockerd issue. The Gateway entry might be missing. In that case, use 'Subnet' instead.
           Sample output when docker hit the issue (Note that the IPv6 gateway is missing):
				"Config": [
					{
						"Subnet": "240.127.1.1/24",
						"Gateway": "240.127.1.1"
					},
					{
						"Subnet": "fd00::/80"
					}
				]
    """
    docker_network['bridge'] = {'IPv4Address' : ipam_info['Config'][0].get('Gateway', ipam_info['Config'][0].get('Subnet')),
                                'IPv6Address' : ipam_info['Config'][1].get('Gateway', ipam_info['Config'][1].get('Subnet')) }

    docker_network['container'] = {}
    for k,v in docker_containers_info.items():
         docker_network['container'][v['Name']] = {'IPv4Address' : v['IPv4Address'].split('/')[0], 'IPv6Address' : v['IPv6Address'].split('/')[0]}

    return docker_network

@pytest.fixture(scope="function")
def collect_ignored_rules(duthosts, rand_one_dut_hostname):
    """
    Collect existing iptables rules before test, set them as ignored as they are not related to CACL test cases.

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.

    Returns:
        None
    """
    duthost = duthosts[rand_one_dut_hostname]

    ignored_rules_v4 = duthost.command("iptables -S")["stdout_lines"]
    ignored_rules_v6 = duthost.command("ip6tables -S")["stdout_lines"]

    ignored_rules = {}
    ignored_rules["v4"] = ignored_rules_v4
    ignored_rules["v6"] = ignored_rules_v6
    return ignored_rules

@pytest.fixture(scope="function")
def clean_scale_rules(duthosts, rand_one_dut_hostname, collect_ignored_rules):
    """
    Clear other control ACL rules before test to avoid miscalucation,
    delete ACL template json file and clean ACL rules, recover configuration after test.

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        collect_ignored_rules: ignored iptable/ip6table rules.

    Returns:
        None
    """
    duthost = duthosts[rand_one_dut_hostname]

    yield

    logger.info("delete tmp file and recover ACL configuration")
    # delete the tmp file
    duthost.file(path=SCALE_ACL_FILE, state='absent')
    logger.info("Reload config to recover configuration.")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

def is_acl_rule_empty(duthost):
    """
    Check the output of "show acl rule", return True if rules are cleaned.

    Args:
        duthosts: All DUTs belong to the testbed.

    Returns:
        boolean: True of False
    """
    stdout_lines = duthost.command("show acl rule")["stdout_lines"]

    stdout_lines = stdout_lines[2:]
    if len(stdout_lines) != 0:
        return False

    return True

def check_iptable_rules(duthost):
    """
    It just calls duthost.commmand to show iptables.
    The function is used to keep ssh session not timeout, otherwise reconnection
    will be failed due to default CACL DENY rule.

    Args:
        duthosts: All DUTs belong to the testbed.

    Returns:
        boolean: False
    """
    duthost.command("iptables -S")
    duthost.command("ip6tables -S")

    return False
# To specify a port range instead of a single port, use iptables format:
# separate start and end ports with a colon, e.g., "1000:2000"
ACL_SERVICES = {
    "NTP": {
        "ip_protocols": ["udp"],
        "dst_ports": ["123"],
        "multi_asic_ns_to_host_fwd": False
    },
    "SNMP": {
        "ip_protocols": ["tcp", "udp"],
        "dst_ports": ["161"],
        "multi_asic_ns_to_host_fwd": True
    },
    "SSH": {
        "ip_protocols": ["tcp"],
        "dst_ports": ["22"],
        "multi_asic_ns_to_host_fwd": True
    }
}

# Template json file used to test scale rules
SCALE_ACL_FILE = "/tmp/scale_cacl.json"

def parse_int_to_tcp_flags(hex_value):
    tcp_flags_str = ""
    if hex_value & 0x01:
        tcp_flags_str += "FIN,"
    if hex_value & 0x02:
        tcp_flags_str += "SYN,"
    if hex_value & 0x04:
        tcp_flags_str += "RST,"
    if hex_value & 0x08:
        tcp_flags_str += "PSH,"
    if hex_value & 0x10:
        tcp_flags_str += "ACK,"
    if hex_value & 0x20:
        tcp_flags_str += "URG,"
    # iptables doesn't handle the flags below now. It has some special keys for it:
    #   --ecn-tcp-cwr   This matches if the TCP ECN CWR (Congestion Window Received) bit is set.
    #   --ecn-tcp-ece   This matches if the TCP ECN ECE (ECN Echo) bit is set.
    # if hex_value & 0x40:
    #     tcp_flags_str += "ECE,"
    # if hex_value & 0x80:
    #     tcp_flags_str += "CWR,"

    # Delete the trailing comma
    tcp_flags_str = tcp_flags_str[:-1]
    return tcp_flags_str


def get_cacl_tables_and_rules(duthost):
    """
    Gathers control plane ACL tables and rules configured on the device via
    `show acl table` and `show acl rule` commands.

    Returns a list of dictionaries where each element represents a control
    plane ACL table in the following format:

    {
        "name": "<table name>",
        "services": [<list of service names>],
        "rules": [<list of rules>]
    }

    Each rule is itself a dictionary which contains "name", "priority" and
    "action" elements, as well as as one or more unique elements which specify
    rule data. Examples include "IP_PROTOCOL", "SRC_IP", "SRC_IPV6", "DST_IP",
    "DST_IPV6", "L4_SRC_PORT", "L4_DST_PORT", "ETHER_TYPE"
    """
    cacl_tables = []

    # The output of `show acl table` and `show acl rule` are difficult to parse well :(
    # We should consider modifying the output format to make it more easily parsable.
    stdout_lines = duthost.shell("show acl table")["stdout_lines"]

    previous_table_ctrlplane = False
    for line in stdout_lines:
        tokens = line.strip().split()
        # A line beginning a new ACL table definition should contian at least 4
        # columns of data. More recent builds of SONiC output 5 columns (a new
        # 'stage' column)
        if len(tokens) >= 4:
            if tokens[1] == "CTRLPLANE":
                # This is the beginning of a new control plane ACL definition
                previous_table_ctrlplane = True
                cacl_tables.append({"name": tokens[0], "services": [tokens[2]], "rules": []})
            else:
                previous_table_ctrlplane = False
        elif len(tokens) == 1 and previous_table_ctrlplane:
            # If the line only contains one token and the previous table we
            # encountered was a control plane ACL table, the token in this line
            # must be an additional service which the previous table is
            # attached to, so we append it to the list of services of the last
            # table we added
            cacl_tables[-1]["services"].append(tokens[0])

    # Process the rules for each table
    for table in cacl_tables:
        stdout_lines = duthost.shell("show acl rule {}".format(table["name"]))["stdout_lines"]
        # First two lines make up the table header. Get rid of them.
        stdout_lines = stdout_lines[2:]
        for line in stdout_lines:
            tokens = line.strip().split()
            if len(tokens) == 6 and tokens[0] == table["name"]:
                table["rules"].append({"name": tokens[1], "priority": tokens[2], "action": tokens[3]})
                # Strip the trailing colon from the key name
                key = tokens[4][:-1]
                table["rules"][-1][key] = tokens[5]
            elif len(tokens) == 2:
                # If the line only contains two tokens, they must be additional rule data.
                # So we add them to the last rule we appended, stripping the trailing colon from the key name
                key = tokens[0][:-1]
                table["rules"][-1][key] = tokens[1]
            else:
                pytest.fail("Unexpected ACL rule data: {}".format(repr(tokens)))

        # Sort the rules in each table by priority, descending
        table["rules"] = sorted(table["rules"], key=lambda k: k["priority"], reverse=True)

    return cacl_tables


def generate_and_append_block_ip2me_traffic_rules(duthost, iptables_rules, ip6tables_rules, asic_index):
    INTERFACE_TABLE_NAME_LIST = [
        "LOOPBACK_INTERFACE",
        "MGMT_INTERFACE",
        "VLAN_INTERFACE",
        "PORTCHANNEL_INTERFACE",
        "INTERFACE"
    ]

    # Gather device configuration facts
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent", namespace=namespace)["ansible_facts"]
    # Add iptables/ip6tables rules to drop all packets destined for peer-to-peer interface IP addresses
    for iface_table_name in INTERFACE_TABLE_NAME_LIST:
        if iface_table_name in cfg_facts:
            ifaces = cfg_facts[iface_table_name]
            for iface_name in ifaces:
                for iface_cidr in ifaces[iface_name]:
                    try:
                        # There are non-ip_address keys in ifaces. We ignore them with the except
                        ip_ntwrk = ipaddress.ip_network(iface_cidr, strict=False)
                    except ValueError:
                        pass
                    # For VLAN interfaces, the IP address we want to block is the default gateway (i.e.,
                    # the first available host IP address of the VLAN subnet)
                    ip_addr = next(ip_ntwrk.hosts()) if iface_table_name == "VLAN_INTERFACE" else ip_ntwrk.network_address

                    if isinstance(ip_ntwrk, ipaddress.IPv4Network):
                        iptables_rules.append("-A INPUT -d {}/{} -j DROP".format(ip_addr, ip_ntwrk.max_prefixlen))
                    elif isinstance(ip_ntwrk, ipaddress.IPv6Network):
                        ip6tables_rules.append("-A INPUT -d {}/{} -j DROP".format(ip_addr, ip_ntwrk.max_prefixlen))
                    else:
                        pytest.fail("Unrecognized IP address type on interface '{}': {}".format(iface_name, ip_ntwrk))


def generate_expected_rules(duthost, tbinfo, docker_network, asic_index, expected_dhcp_rules_for_standby):
    iptables_rules = []
    ip6tables_rules = []

    # Default policies
    iptables_rules.append("-P INPUT ACCEPT")
    iptables_rules.append("-P FORWARD ACCEPT")
    iptables_rules.append("-P OUTPUT ACCEPT")
    ip6tables_rules.append("-P INPUT ACCEPT")
    ip6tables_rules.append("-P FORWARD ACCEPT")
    ip6tables_rules.append("-P OUTPUT ACCEPT")

    # Allow localhost
    iptables_rules.append("-A INPUT -s 127.0.0.1/32 -i lo -j ACCEPT")
    ip6tables_rules.append("-A INPUT -s ::1/128 -i lo -j ACCEPT")

    if asic_index is None:
    # Allow Communication among docker containers
        for k, v in docker_network['container'].items():
            iptables_rules.append("-A INPUT -s {}/32 -d {}/32 -j ACCEPT".format(docker_network['bridge']['IPv4Address'], docker_network['bridge']['IPv4Address']))
            iptables_rules.append("-A INPUT -s {}/32 -d {}/32 -j ACCEPT".format(v['IPv4Address'], docker_network['bridge']['IPv4Address']))
            ip6tables_rules.append("-A INPUT -s {}/128 -d {}/128 -j ACCEPT".format(docker_network['bridge']['IPv6Address'], docker_network['bridge']['IPv6Address']))
            ip6tables_rules.append("-A INPUT -s {}/128 -d {}/128 -j ACCEPT".format(v['IPv6Address'], docker_network['bridge']['IPv6Address']))

    else:
        iptables_rules.append("-A INPUT -s {}/32 -d {}/32 -j ACCEPT".format(docker_network['container']['database' + str(asic_index)]['IPv4Address'],
                                                                            docker_network['container']['database' + str(asic_index)]['IPv4Address']))
        iptables_rules.append("-A INPUT -s {}/32 -d {}/32 -j ACCEPT".format(docker_network['bridge']['IPv4Address'],
                                                                            docker_network['container']['database' + str(asic_index)]['IPv4Address']))
        ip6tables_rules.append("-A INPUT -s {}/128 -d {}/128 -j ACCEPT".format(docker_network['container']['database' + str(asic_index)]['IPv6Address'],
                                                                               docker_network['container']['database' + str(asic_index)]['IPv6Address']))
        ip6tables_rules.append("-A INPUT -s {}/128 -d {}/128 -j ACCEPT".format(docker_network['bridge']['IPv6Address'],
                                                                               docker_network['container']['database' + str(asic_index)]['IPv6Address']))



    # Allow all incoming packets from established connections or new connections
    # which are related to established connections
    iptables_rules.append("-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    ip6tables_rules.append("-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")

    # Allow bidirectional ICMPv4 ping and traceroute
    iptables_rules.append("-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT")
    iptables_rules.append("-A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT")
    iptables_rules.append("-A INPUT -p icmp -m icmp --icmp-type 3 -j ACCEPT")
    iptables_rules.append("-A INPUT -p icmp -m icmp --icmp-type 11 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 129 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 1 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 3 -j ACCEPT")

    # Allow all incoming Neighbor Discovery Protocol (NDP) NS/NA/RS/RA messages
    ip6tables_rules.append("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j ACCEPT")

    # Allow all incoming IPv4 DHCP packets
    iptables_rules.append("-A INPUT -p udp -m udp --dport 67:68 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p udp -m udp --dport 67:68 -j ACCEPT")

    # Allow all incoming IPv6 DHCP packets
    iptables_rules.append("-A INPUT -p udp -m udp --dport 546:547 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p udp -m udp --dport 546:547 -j ACCEPT")

    # On standby tor, it has expected dhcp mark iptables rules.
    if expected_dhcp_rules_for_standby:
        pytest_assert(isinstance(expected_dhcp_rules_for_standby, list),
		      "expected_dhcp_rules_for_standby should be list! current type is {}".format(type(expected_dhcp_rules_for_standby)))
        iptables_rules.extend(expected_dhcp_rules_for_standby)

    # Allow all incoming BGP traffic
    iptables_rules.append("-A INPUT -p tcp -m tcp --dport 179 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p tcp -m tcp --dport 179 -j ACCEPT")

    extra_rule_branches = ['201911', '202012', '202111']
    if any(branch in duthost.os_version for branch in extra_rule_branches):
        iptables_rules.append("-A INPUT -p tcp -m tcp --sport 179 -j ACCEPT")
        ip6tables_rules.append("-A INPUT -p tcp -m tcp --sport 179 -j ACCEPT")

    # Allow LDP traffic
    if ("wan" in tbinfo['topo']['name']):
        wan_default_rules = [
        "-A INPUT -p tcp -m tcp --dport 646 -j ACCEPT",
        "-A INPUT -p tcp -m tcp --sport 646 -j ACCEPT",
        "-A INPUT -p udp -m udp --dport 646 -j ACCEPT",
        "-A INPUT -p udp -m udp --sport 646 -j ACCEPT",
        "-A INPUT -p tcp -m tcp --sport 179 -j ACCEPT"
        ]
        iptables_rules += wan_default_rules
        ip6tables_rules += wan_default_rules

    # Generate control plane rules from device config
    rules_applied_from_config = 0

    cacl_tables = get_cacl_tables_and_rules(duthost)

    # Walk the ACL tables and generate an iptables rule for each rule
    for table in cacl_tables:
        if len(table["rules"]) == 0:
            logger.info("ACL table {} has no rules".format(table["name"]))
            continue

        acl_services = table["services"]

        for acl_service in acl_services:
            if acl_service not in ACL_SERVICES:
                logger.warning("Ignoring control plane ACL '{}' with unrecognized service '{}'"
                               .format(table["name"], acl_service))
                continue

            # Obtain default IP protocol(s) and destination port(s) for this service
            ip_protocols = ACL_SERVICES[acl_service]["ip_protocols"]
            dst_ports = ACL_SERVICES[acl_service]["dst_ports"]

            table_ip_version = None

            for rule in table["rules"]:
                # If we haven't determined the IP version for this ACL table yet,
                # try to do it now. We attempt to determine heuristically based on
                # whether the src or dst IP of this rule is an IPv4 or IPv6 address.
                if not table_ip_version:
                    if "SRC_IPV6" in rule and rule["SRC_IPV6"]:
                        table_ip_version = 6
                    elif "SRC_IP" in rule and rule["SRC_IP"]:
                        table_ip_version = 4
                else:
                    if (("SRC_IPV6" in rule and rule["SRC_IPV6"] and table_ip_version == 4) or
                        ("SRC_IP" in rule and rule["SRC_IP"] and table_ip_version == 6)):
                        pytest.fail("ACL table '{}' contains both IPv4 and IPv6 rules".format(table["name"]))

            # If we were unable to determine whether this ACL table contains
            # IPv4 or IPv6 rules, log a message and skip processing this table.
            if not table_ip_version:
                pytest.fail("Unable to determine if ACL table '{}' contains IPv4 or IPv6 rules".format(table["name"]))
                continue

            # We assume the rules are already sorted by priority in descending order
            for rule in table["rules"]:
                # Apply the rule to the default protocol(s) for this ACL service
                for ip_protocol in ip_protocols:
                    for dst_port in dst_ports:
                        new_iptables_rule = "-A INPUT"

                        iface_cidr = None
                        if table_ip_version == 6 and "SRC_IPV6" in rule and rule["SRC_IPV6"]:
                            iface_cidr = rule["SRC_IPV6"]
                        elif table_ip_version == 4 and "SRC_IP" in rule and rule["SRC_IP"]:
                            iface_cidr = rule["SRC_IP"]

                        if iface_cidr:
                            ip_ntwrk = ipaddress.ip_network(iface_cidr, strict=False)
                            new_iptables_rule += " -s {}/{}".format(ip_ntwrk.network_address, ip_ntwrk.prefixlen)

                        new_iptables_rule += " -p {0} -m {0} --dport {1}".format(ip_protocol, dst_port)

                        # If there are TCP flags present and ip protocol is TCP, append them
                        if ip_protocol == "tcp" and "TCP_FLAGS" in rule and rule["TCP_FLAGS"]:
                            tcp_flags, tcp_flags_mask = rule["TCP_FLAGS"].split("/")

                            tcp_flags = int(tcp_flags, 16)
                            tcp_flags_mask = int(tcp_flags_mask, 16)

                            if tcp_flags_mask > 0:
                                new_iptables_rule += " --tcp-flags {mask} {flags}".format(mask=parse_int_to_tcp_flags(tcp_flags_mask), flags=parse_int_to_tcp_flags(tcp_flags))

                        # Append the packet action as the jump target
                        new_iptables_rule += " -j {}".format(rule["action"])

                        if table_ip_version == 6:
                            ip6tables_rules.append(new_iptables_rule)
                        else:
                            iptables_rules.append(new_iptables_rule)

                        rules_applied_from_config += 1

    # Append rules which block "ip2me" traffic on p2p interfaces
    generate_and_append_block_ip2me_traffic_rules(duthost, iptables_rules, ip6tables_rules, asic_index)

    # Allow all packets with a TTL/hop limit of 0 or 1
    iptables_rules.append("-A INPUT -m ttl --ttl-lt 2 -j ACCEPT")
    ip6tables_rules.append("-A INPUT -p tcp -m hl --hl-lt 2 -j ACCEPT")

    # If we have added rules from the device config, we lastly add default drop rules
    if rules_applied_from_config > 0:
        # Default drop rules
        iptables_rules.append("-A INPUT -j DROP")
        ip6tables_rules.append("-A INPUT -j DROP")

    return iptables_rules, ip6tables_rules

def generate_nat_expected_rules(duthost, docker_network, asic_index):
    iptables_natrules = []
    ip6tables_natrules = []

    # Default policies
    iptables_natrules.append("-P PREROUTING ACCEPT")
    iptables_natrules.append("-P INPUT ACCEPT")
    iptables_natrules.append("-P OUTPUT ACCEPT")
    iptables_natrules.append("-P POSTROUTING ACCEPT")
    ip6tables_natrules.append("-P PREROUTING ACCEPT")
    ip6tables_natrules.append("-P INPUT ACCEPT")
    ip6tables_natrules.append("-P OUTPUT ACCEPT")
    ip6tables_natrules.append("-P POSTROUTING ACCEPT")


    for acl_service in ACL_SERVICES:
        if ACL_SERVICES[acl_service]["multi_asic_ns_to_host_fwd"]:
            for ip_protocol in ACL_SERVICES[acl_service]["ip_protocols"]:
                for dst_port in ACL_SERVICES[acl_service]["dst_ports"]:
                    # IPv4 rules
                    iptables_natrules.append(
                                             "-A PREROUTING -p {} -m {} --dport {} -j DNAT --to-destination {}".format
                                             (ip_protocol, ip_protocol, dst_port,
                                             docker_network['bridge']['IPv4Address']))

                    iptables_natrules.append(
                                             "-A POSTROUTING -p {} -m {} --dport {} -j SNAT --to-source {}".format
                                             (ip_protocol, ip_protocol, dst_port,
                                             docker_network['container']['database' + str(asic_index)]['IPv4Address']))

                    # IPv6 rules
                    ip6tables_natrules.append(
                                             "-A PREROUTING -p {} -m {} --dport {} -j DNAT --to-destination {}".format
                                             (ip_protocol, ip_protocol, dst_port,
                                             docker_network['bridge']['IPv6Address']))

                    ip6tables_natrules.append(
                                             "-A POSTROUTING -p {} -m {} --dport {} -j SNAT --to-source {}".format
                                             (ip_protocol,ip_protocol, dst_port,
                                             docker_network['container']['database' + str(asic_index)]['IPv6Address']))

    return iptables_natrules, ip6tables_natrules

def generate_expected_cacl_rules(duthost, ip_type):
    """
    Generate expected iptables rules for control ACL based on cacl tables and rules.

    Args:
        duthost: instance of AnsibleHost class
        ip_type: ipv4 or ipv6
        asic_index: the index of asic

    Returns:
        None
    """
    rules_applied_from_config = 0
    iptables_rules = []

    cacl_tables = get_cacl_tables_and_rules(duthost)

    # Walk the ACL tables and generate an iptables rule for each rule
    for table in cacl_tables:
        if len(table["rules"]) == 0:
            logger.info("ACL table {} has no rules".format(table["name"]))
            continue

        acl_services = table["services"]

        for acl_service in acl_services:
            if acl_service not in ACL_SERVICES:
                logger.warning("Ignoring control plane ACL '{}' with unrecognized service '{}'"
                               .format(table["name"], acl_service))
                continue

            # Obtain default IP protocol(s) and destination port(s) for this service
            ip_protocols = ACL_SERVICES[acl_service]["ip_protocols"]
            dst_ports = ACL_SERVICES[acl_service]["dst_ports"]

            # We assume the rules are already sorted by priority in descending order
            for rule in table["rules"]:
                # Apply the rule to the default protocol(s) for this ACL service
                for ip_protocol in ip_protocols:
                    for dst_port in dst_ports:
                        new_iptables_rule = "-A INPUT"

                        iface_cidr = None
                        if ip_type == "ipv6" and "SRC_IPV6" in rule and rule["SRC_IPV6"]:
                            iface_cidr = rule["SRC_IPV6"]
                        elif ip_type == "ipv4" and "SRC_IP" in rule and rule["SRC_IP"]:
                            iface_cidr = rule["SRC_IP"]

                        if iface_cidr and iface_cidr != "0.0.0.0/0" and iface_cidr != "::/0":
                            ip_ntwrk = ipaddress.ip_network(iface_cidr, strict=False)
                            new_iptables_rule += " -s {}/{}".format(ip_ntwrk.network_address, ip_ntwrk.prefixlen)

                        new_iptables_rule += " -p {0} -m {0} --dport {1}".format(ip_protocol, dst_port)

                        # If there are TCP flags present and ip protocol is TCP, append them
                        if ip_protocol == "tcp" and "TCP_FLAGS" in rule and rule["TCP_FLAGS"]:
                            tcp_flags, tcp_flags_mask = rule["TCP_FLAGS"].split("/")

                            tcp_flags = int(tcp_flags, 16)
                            tcp_flags_mask = int(tcp_flags_mask, 16)

                            if tcp_flags_mask > 0:
                                new_iptables_rule += " --tcp-flags {mask} {flags}".format(mask=parse_int_to_tcp_flags(tcp_flags_mask), flags=parse_int_to_tcp_flags(tcp_flags))

                        # Append the packet action as the jump target
                        new_iptables_rule += " -j {}".format(rule["action"])

                        iptables_rules.append(new_iptables_rule)

                        rules_applied_from_config += 1

    # If we have added rules from the device config, we lastly add default drop rules
    if rules_applied_from_config > 0:
        # Default drop rules
        iptables_rules.append("-A INPUT -j DROP")

    return iptables_rules

def generate_scale_rules(duthost, ip_type):
    """
    Generate scale rules for SNMP-ACL, ssh-only, NTP-ACL tables with template json file

    Args:
        duthost: instance of AnsibleHost class
        ip_type: ipv4 or ipv6
        asic_index: the index of asic

    Returns:
        None
    """
    rules_data = {}
    snmp_acl_entry = {}
    ssh_acl_entry = {}
    ntp_acl_entry = {}

    for index in range(1, 51):
        if ip_type == "ipv4":
            src_ip = "20.0.0." + str(1 + index) + "/32"
        else:
            src_ip = "2001::" + str(1 + index) + "/128"
        acl_entry = {}
        acl_entry[index] = {
                            "actions": {
                                "config": {
                                    "forwarding-action": "DROP"
                                }
                            },
                            "config": {
                                "sequence-id": index
                            },
                            "ip": {
                                "config": {
                                    "source-ip-address": src_ip
                                }
                            }
                        }

        snmp_acl_entry.update(acl_entry)
        ssh_acl_entry.update(acl_entry)
        ntp_acl_entry.update(acl_entry)

    rules_data['acl'] = {
        "acl-sets": {
            "acl-set": {
                "SNMP-ACL": {
                    "acl-entries": {
                        "acl-entry": snmp_acl_entry
                    },
                    "config": {
                        "name": "SNMP-ACL"
                    }
                },
                "ssh-only": {
                    "acl-entries": {
                        "acl-entry": ssh_acl_entry
                    },
                    "config": {
                        "name": "ssh-only"
                    }
                },
                "ntp-acl": {
                    "acl-entries": {
                        "acl-entry": ntp_acl_entry
                    },
                    "config": {
                        "name": "ntp-acl"
                    }
                }
            }
        }
    }

    duthost.copy(content=json.dumps(rules_data, indent=4), dest=SCALE_ACL_FILE)

    cmds = 'acl-loader update full {}'.format(SCALE_ACL_FILE)
    duthost.command(cmds)

    logger.info('Waiting all rules to be applied')
    # "acl-loader update full **.json" command will refresh iptables, we have to
    # add the ACCEPT SSH iptables rule after acl-loader command. But on multi-asic
    # testbed, it always costs minutes to sync iptables rules after updating cacl
    # rules, if sleep for more than 3 mins with time.sleep, then, the process tries to
    # add the ACCEPT SSH rule, at this point, SSH connection is disconnected now
    # because the default SSH timeout is 30s, next duthost.command will try to reconnect
    # to DUT, it will trigger ssh login, it will be rejected by default CACL DENY rule,
    # test will fail. We have wait_until to solve this problem, here add wail_until
    # to call check_iptable_rules every 10s to keep ssh session alive, it just calls
    # duthost.command to active ssh connection.
    # In this way, we can active ssh connection and wait as long as we want.

    # It has to wait cacl rules to be effective.
    wait_until(200, 10, 2, check_iptable_rules, duthost)
    # add ACCEPT rule for SSH to make sure testbed access
    duthost.command("iptables -I INPUT 3 -p tcp -m tcp --dport 22 -j ACCEPT")

def verify_cacl(duthost, tbinfo, localhost, creds, docker_network, expected_dhcp_rules_for_standby = None, asic_index = None):
    expected_iptables_rules, expected_ip6tables_rules = generate_expected_rules(duthost, tbinfo, docker_network, asic_index, expected_dhcp_rules_for_standby)

    stdout = duthost.get_asic_or_sonic_host(asic_index).command("iptables -S")["stdout"]
    actual_iptables_rules = stdout.strip().split("\n")

    # Ensure all expected iptables rules are present on the DuT
    logger.info("Number of expected iptable rules:{}, number of acutal iptables rules:{}".format(len(set(expected_iptables_rules)), len(set(actual_iptables_rules))))
    missing_iptables_rules = set(expected_iptables_rules) - set(actual_iptables_rules)
    pytest_assert(len(missing_iptables_rules) == 0, "Missing expected iptables rules: {}".format(repr(missing_iptables_rules)))

    # Ensure there are no unexpected iptables rules present on the DuT
    unexpected_iptables_rules = set(actual_iptables_rules) - set(expected_iptables_rules)
    pytest_assert(len(unexpected_iptables_rules) == 0, "Unexpected iptables rules: {}".format(repr(unexpected_iptables_rules)))

    # TODO: caclmgrd currently applies the "block_ip2me" rules in the order it gathers the interfaces and
    #       their IPs from Config DB, which is indeterminate. We first need to modify caclmgrd to sort
    #       the interfaces and IPs before applying them, then we can do the same here and enable this test.
    #
    # Ensure the iptables rules are applied in the correct order
    #for i in range(len(expected_iptables_rules)):
    #    pytest_assert(actual_iptables_rules[i] == expected_iptables_rules[i], "iptables rules not in expected order")

    stdout = duthost.get_asic_or_sonic_host(asic_index).command("ip6tables -S")["stdout"]
    actual_ip6tables_rules = stdout.strip().split("\n")

    # Ensure all expected ip6tables rules are present on the DuT
    logger.info("Number of expected ip6table rules:{}, number of acutal ip6tables rules:{}".format(len(set(expected_ip6tables_rules)), len(set(actual_ip6tables_rules))))
    missing_ip6tables_rules = set(expected_ip6tables_rules) - set(actual_ip6tables_rules)
    pytest_assert(len(missing_ip6tables_rules) == 0, "Missing expected ip6tables rules: {}".format(repr(missing_ip6tables_rules)))

    # Ensure there are no unexpected ip6tables rules present on the DuT
    unexpected_ip6tables_rules = set(actual_ip6tables_rules) - set(expected_ip6tables_rules)
    pytest_assert(len(unexpected_ip6tables_rules) == 0, "Unexpected ip6tables rules: {}".format(repr(unexpected_ip6tables_rules)))

    # TODO: caclmgrd currently applies the "block_ip2me" rules in the order it gathers the interfaces and
    #       their IPs from Config DB, which is indeterminate. We first need to modify caclmgrd to sort
    #       the interfaces and IPs before applying them, then we can do the same here and enable this test.
    #
    # Ensure the ip6tables rules are applied in the correct order
    #for i in range(len(expected_ip6tables_rules)):
    #    pytest_assert(actual_ip6tables_rules[i] == expected_ip6tables_rules[i], "ip6tables rules not in expected order")

def verify_nat_cacl(duthost, localhost, creds, docker_network, asic_index):
    expected_iptables_rules, expected_ip6tables_rules = generate_nat_expected_rules(duthost, docker_network, asic_index)

    stdout = duthost.get_asic_or_sonic_host(asic_index).command("iptables -t nat -S")["stdout"]
    actual_iptables_rules = stdout.strip().split("\n")

    # Ensure all expected iptables rules are present on the DuT
    missing_iptables_rules = set(expected_iptables_rules) - set(actual_iptables_rules)
    pytest_assert(len(missing_iptables_rules) == 0, "Missing expected iptables nat rules: {}".format(repr(missing_iptables_rules)))

    # Ensure there are no unexpected iptables rules present on the DuT
    unexpected_iptables_rules = set(actual_iptables_rules) - set(expected_iptables_rules)
    pytest_assert(len(unexpected_iptables_rules) == 0, "Unexpected iptables nat rules: {}".format(repr(unexpected_iptables_rules)))

    stdout = duthost.get_asic_or_sonic_host(asic_index).command("ip6tables -t nat -S")["stdout"]
    actual_ip6tables_rules = stdout.strip().split("\n")

    # Ensure all expected ip6tables rules are present on the DuT
    missing_ip6tables_rules = set(expected_ip6tables_rules) - set(actual_ip6tables_rules)
    pytest_assert(len(missing_ip6tables_rules) == 0, "Missing expected ip6tables nat rules: {}".format(repr(missing_ip6tables_rules)))

    # Ensure there are no unexpected ip6tables rules present on the DuT
    unexpected_ip6tables_rules = set(actual_ip6tables_rules) - set(expected_ip6tables_rules)
    pytest_assert(len(unexpected_ip6tables_rules) == 0, "Unexpected ip6tables nat rules: {}".format(repr(unexpected_ip6tables_rules)))

def test_cacl_application_nondualtor(duthosts, tbinfo, rand_one_dut_hostname, localhost, creds, docker_network):
    """
    Test case to ensure caclmgrd is applying control plane ACLs properly

    This is done by generating our own set of expected iptables and ip6tables
    rules based on the DuT's configuration and comparing them against the
    actual iptables/ip6tables rules on the DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    verify_cacl(duthost, tbinfo, localhost, creds, docker_network)

def test_cacl_application_dualtor(duthost_dualtor, tbinfo, localhost, creds, docker_network, expected_dhcp_rules_for_standby):
    """
    Test case to ensure caclmgrd is applying control plane ACLs properly on dualtor.

    This is done by generating our own set of expected iptables and ip6tables
    rules based on the DuT's configuration and comparing them against the
    actual iptables/ip6tables rules on the DuT.
    """
    verify_cacl(duthost_dualtor, tbinfo, localhost, creds, docker_network, expected_dhcp_rules_for_standby)

def test_multiasic_cacl_application(duthosts, tbinfo, rand_one_dut_hostname, localhost, creds, docker_network, enum_frontend_asic_index):
    """
    Test case to ensure caclmgrd is applying control plane ACLs properly on multi-ASIC platform.
    """
    duthost = duthosts[rand_one_dut_hostname]
    verify_cacl(duthost, tbinfo, localhost, creds, docker_network, None, enum_frontend_asic_index)
    verify_nat_cacl(duthost, localhost, creds, docker_network, enum_frontend_asic_index)

def test_cacl_scale_rules_ipv4(duthosts, rand_one_dut_hostname, collect_ignored_rules, clean_scale_rules):
    """
    Test case to ensure cover scale rules for control plan ACL for ipv4

    This is done by collecting existing iptable rules as ingnored rules list, creating scale rules for SNMP-ACL, SSH-ONLY, NTP-ACL tables
    and generating our own set of expected iptables rules based on the DUT's configuration and comparing them against the actual iptables
    rules on the DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ignored_iptable_rules_v4 = collect_ignored_rules["v4"]

    generate_scale_rules(duthost, "ipv4")

    expected_iptables_rules = generate_expected_cacl_rules(duthost, "ipv4")

    # add the SSH ACCEPT rule into expected_iptables_rules list
    expected_iptables_rules.append("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT")

    # Append rules which block "ip2me" traffic on p2p interfaces, only for null multi-asic
    generate_and_append_block_ip2me_traffic_rules(duthost, expected_iptables_rules, [], None)

    actual_iptables_rules = duthost.command("iptables -S")["stdout_lines"]

    # Ensure all expected iptables rules are present on the DuT
    logger.info("Number of expected iptable rules:{}, number of acutal iptables rules:{}, number of ignored_iptable_rules_v4 rules:{}"
                .format(len(set(expected_iptables_rules)), len(set(actual_iptables_rules)), len(set(ignored_iptable_rules_v4))))

    missing_iptables_rules = set(expected_iptables_rules) - set(actual_iptables_rules)
    pytest_assert(len(missing_iptables_rules) == 0, "Missing expected iptables rules: {}".format(repr(missing_iptables_rules)))

    # Ensure there are no unexpected iptables rules present on the DuT
    unexpected_iptables_rules = set(actual_iptables_rules) - set(expected_iptables_rules) - set(ignored_iptable_rules_v4)
    pytest_assert(len(unexpected_iptables_rules) == 0, "Unexpected iptables rules: {}".format(repr(unexpected_iptables_rules)))

def test_cacl_scale_rules_ipv6(duthosts, rand_one_dut_hostname, collect_ignored_rules, clean_scale_rules):
    """
    Test case to ensure cover scale rules for control plan ACL for ipv6

    This is done by collecting existing ip6table rules as ingnored rules list, creating scale rules for SNMP-ACL, SSH-ONLY, NTP-ACL tables
    and generating our own set of expected ip6tables rules based on the DUT's configuration and comparing them against the actual ip6tables
    rules on the DuT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ignored_iptable_rules_v6 = collect_ignored_rules["v6"]

    generate_scale_rules(duthost, "ipv6")

    expected_ip6tables_rules = generate_expected_cacl_rules(duthost, "ipv6")

    # Append rules which block "ip2me" traffic on p2p interfaces, only for null multi-asic
    generate_and_append_block_ip2me_traffic_rules(duthost, [], expected_ip6tables_rules, None)

    actual_ip6tables_rules = duthost.command("ip6tables -S")["stdout_lines"]

    # Ensure all expected ip6tables rules are present on the DuT
    missing_ip6tables_rules = set(expected_ip6tables_rules) - set(actual_ip6tables_rules)
    pytest_assert(len(missing_ip6tables_rules) == 0, "Missing expected ip6tables rules: {}".format(repr(missing_ip6tables_rules)))

    # Ensure there are no unexpected ip6tables rules present on the DuT
    logger.info("Number of expected ip6table rules:{}, number of acutal ip6tables rules:{}, number of ignored_iptable_rules_v6 rules:{}"
                .format(len(set(expected_ip6tables_rules)), len(set(actual_ip6tables_rules)), len(set(ignored_iptable_rules_v6))))

    unexpected_ip6tables_rules = set(actual_ip6tables_rules) - set(expected_ip6tables_rules) - set(ignored_iptable_rules_v6)
    pytest_assert(len(unexpected_ip6tables_rules) == 0, "Unexpected ip6tables rules: {}".format(repr(unexpected_ip6tables_rules)))
