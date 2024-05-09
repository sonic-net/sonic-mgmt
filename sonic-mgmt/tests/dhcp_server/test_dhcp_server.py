import binascii
import contextlib
from datetime import datetime
import json
import logging
import ipaddress
import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
import random
from tests.common.utilities import capture_and_check_packet_on_dut
from tests.common.helpers.assertions import pytest_assert, pytest_require


pytestmark = [
    pytest.mark.topology('mx'),
]


MINIMUM_HOSTS_COUNT = 2
MINIMUM_INTERFACE_MEMBERS_COUNT = 2
DHCP_DEFAULT_LEASE_TIME = 300
DHCP_DEFAULT_CUSTOM_OPTION_VALUE = 'hello_from_sonic'
DHCP_MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
DHCP_IP_DEFAULT_ROUTE = "0.0.0.0"
DHCP_IP_BROADCAST = "255.255.255.255"
DHCP_UDP_CLIENT_PORT = 68
DHCP_UDP_SERVER_PORT = 67
DHCP_MESSAGE_TYPE_DISCOVER_NUM = 1
DHCP_MESSAGE_TYPE_OFFER_NUM = 2
DHCP_MESSAGE_TYPE_REQUEST_NUM = 3
DHCP_MESSAGE_TYPE_ACK_NUM = 5
DHCP_MESSAGE_TYPE_NAK_NUM = 6
DHCP_MESSAGE_TYPE_RELEASE_NUM = 7

STATE_DB_KEY_LEASE_START = 'lease_start'
STATE_DB_KEY_LEASE_END = 'lease_end'
STATE_DB_KEY_IP = 'ip'

DHCP_SERVER_CONFIG_TOOL_GCU = 'gcu'
DHCP_SERVER_CONFIG_TOOL_CLI = 'cli'
DHCP_SERVER_CONFIG_PREFIX_SERVER = 'DHCP_SERVER_IPV4'


def clean_fdb_table(duthost):
    duthost.shell("sonic-clear fdb all")


def ping_dut_refresh_fdb(ptfhost, interface):
    ptfhost.shell("timeout 1 ping -c 1 -w 1 -I {} 255.255.255.255 -b".format(interface), module_ignore_errors=True)


def clean_dhcp_server_config(duthost):
    keys = duthost.shell("sonic-db-cli CONFIG_DB KEYS DHCP_SERVER_IPV4*")
    for key in keys["stdout_lines"]:
        duthost.shell("sonic-db-cli CONFIG_DB DEL '{}'".format(key))


def verify_lease(duthost, dhcp_interface, client_mac, exp_ip, exp_lease_time):
    lease_start = duthost.shell("sonic-db-cli STATE_DB HGET 'DHCP_SERVER_IPV4_LEASE|{}|{}' '{}'"
                                .format(dhcp_interface, client_mac, STATE_DB_KEY_LEASE_START))['stdout']
    lease_end = duthost.shell("sonic-db-cli STATE_DB HGET 'DHCP_SERVER_IPV4_LEASE|{}|{}' '{}'"
                              .format(dhcp_interface, client_mac, STATE_DB_KEY_LEASE_END))['stdout']
    lease_ip = duthost.shell("sonic-db-cli STATE_DB HGET 'DHCP_SERVER_IPV4_LEASE|{}|{}' '{}'"
                             .format(dhcp_interface, client_mac, STATE_DB_KEY_IP))['stdout']
    pytest_assert(lease_ip == exp_ip, "Expected ip=%s while got %s" % (exp_ip, lease_ip))
    lease_start_time = datetime.fromtimestamp(int(lease_start))
    lease_end_time = datetime.fromtimestamp(int(lease_end))
    lease_time = int((lease_end_time - lease_start_time).total_seconds())
    pytest_assert(lease_time == exp_lease_time, "Expected lease_time=%d while got %d" % (exp_lease_time, lease_time))


@pytest.fixture(scope="module")
def parse_vlan_setting_from_running_config(duthost, tbinfo):
    vlan_brief = duthost.get_vlan_brief()
    first_vlan_name = list(vlan_brief.keys())[0]
    first_vlan_info = list(vlan_brief.values())[0]
    first_vlan_prefix = first_vlan_info['interface_ipv4'][0]
    disabled_host_interfaces = tbinfo['topo']['properties']['topology'].get('disabled_host_interfaces', [])
    connected_ptf_ports_idx = [interface for interface in
                               tbinfo['topo']['properties']['topology'].get('host_interfaces', [])
                               if interface not in disabled_host_interfaces]
    dut_intf_to_ptf_index = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
    connected_dut_intf_to_ptf_index = {k: v for k, v in dut_intf_to_ptf_index.items() if v in connected_ptf_ports_idx}
    vlan_members = first_vlan_info['members']
    vlan_member_with_ptf_idx = [(member, connected_dut_intf_to_ptf_index[member])
                                for member in vlan_members if member in dut_intf_to_ptf_index]
    pytest_assert(len(vlan_members) >= MINIMUM_INTERFACE_MEMBERS_COUNT, 'Vlan size is too small for testing')
    vlan_net = ipaddress.ip_network(address=first_vlan_prefix, strict=False)
    vlan_gateway = first_vlan_prefix.split('/')[0]
    vlan_hosts = [str(host) for host in vlan_net.hosts()]
    # to avoid configurate an range contains gateway ip, simply ignore all ip before gateway and gateway itself
    vlan_hosts_after_gateway = vlan_hosts[vlan_hosts.index(vlan_gateway) + 1:]
    pytest_assert(len(vlan_hosts_after_gateway) >= MINIMUM_HOSTS_COUNT, 'Vlan size is too small for testing')
    vlan_setting = {
        'vlan_name': first_vlan_name,
        'vlan_gateway': vlan_gateway,
        'vlan_subnet_mask': str(vlan_net.netmask),
        'vlan_hosts': vlan_hosts_after_gateway,
        'vlan_member_with_ptf_idx': vlan_member_with_ptf_idx,
    }

    logging.info("The vlan_setting before test is %s" % vlan_setting)
    return vlan_setting['vlan_name'], \
        vlan_setting['vlan_gateway'], \
        vlan_setting['vlan_subnet_mask'], \
        vlan_setting['vlan_hosts'], \
        vlan_setting['vlan_member_with_ptf_idx']


@contextlib.contextmanager
def dhcp_server_config(duthost, config_tool, config_to_apply):
    clean_dhcp_server_config(duthost)
    logging.info("The dhcp_server_config: %s" % config_to_apply)
    if config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        dhcp_server_config_gcu(duthost, config_to_apply)
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        dhcp_server_config_cli(duthost, config_to_apply)

    yield

    clean_dhcp_server_config(duthost)


def dhcp_server_config_cli(duthost, config_commands):
    clean_dhcp_server_config(duthost)
    for cmd in config_commands:
        duthost.shell(cmd)


def dhcp_server_config_gcu(duthost, config_to_apply):
    logging.info("The dhcp_server_config: %s" % config_to_apply)
    tmpfile = duthost.shell('mktemp')['stdout']
    try:
        duthost.copy(content=json.dumps(config_to_apply, indent=4), dest=tmpfile)
        output = duthost.shell('config apply-patch {}'.format(tmpfile), module_ignore_errors=True)
        pytest_assert(not output['rc'], "Command is not running successfully")
        pytest_assert(
            "Patch applied successfully" in output['stdout'],
            "Please check if json file is validate"
        )
    finally:
        duthost.file(path=tmpfile, state='absent')


def generate_common_config_patch(vlan_name, gateway, net_mask, dut_ports, ip_ranges):
    pytest_require(len(dut_ports) == len(ip_ranges), "Invalid input, dut_ports and ip_ranges should have same length")
    ret_patch = generate_dhcp_interface_config_patch(vlan_name, gateway, net_mask)
    range_names = ["range_" + ip_range[0] for ip_range in ip_ranges]
    ret_patch += generate_dhcp_range_config_patch(ip_ranges, range_names)
    ret_patch += generate_dhcp_port_config_patch(vlan_name, dut_ports, range_names)
    return ret_patch


def generate_dhcp_interface_config_patch(vlan_name, gateway, net_mask):
    return [
        {
            "op": "add",
            "path": "/DHCP_SERVER_IPV4",
            "value": {
                "%s" % vlan_name: {
                    "gateway": "%s" % gateway,
                    "lease_time": "%s" % DHCP_DEFAULT_LEASE_TIME,
                    "mode": "PORT",
                    "netmask": "%s" % net_mask,
                    "state": "enabled"
                }
            }
        }
    ]


def generate_dhcp_range_config_patch(ip_ranges, range_names):
    ret_range_config_patch = [
        {
            "op": "add",
            "path": "/DHCP_SERVER_IPV4_RANGE",
            "value": {}
        }
    ]
    for range_name, ip_range in zip(range_names, ip_ranges):
        ret_range_config_patch[0]["value"][range_name] = {
                    "range": ip_range
                }

    return ret_range_config_patch


def generate_dhcp_port_config_patch(vlan_name, dut_ports, range_names):
    ret_port_config_patch = [
        {
            "op": "add",
            "path": "/DHCP_SERVER_IPV4_PORT",
            "value": {}
        }
    ]
    for range_name, dut_port in zip(range_names, dut_ports):
        ret_port_config_patch[0]["value"]["%s|%s" % (vlan_name, dut_port)] = {
            "ranges": [
                range_name
            ]
        }

    return ret_port_config_patch


def generate_common_config_cli_commands(vlan_name, gateway, net_mask, dut_ports, ip_ranges):
    pytest_require(len(dut_ports) == len(ip_ranges), "Invalid input, dut_ports and ip_ranges should have same length")
    ret_commands = generate_dhcp_interface_config_cli_commands(vlan_name, gateway, net_mask)
    for i in range(len(dut_ports)):
        range_name = "range_" + ip_ranges[i][0]
        ret_commands += generate_dhcp_range_config_cli_commands(ip_ranges[i], range_name)
        ret_commands += generate_dhcp_port_config_cli_commands(vlan_name, dut_ports[i], range_name)
    return ret_commands


def generate_dhcp_interface_config_cli_commands(vlan_name, gateway, net_mask):
    return [
        'config dhcp_server ipv4 add --mode PORT --lease_time %s ' % DHCP_DEFAULT_LEASE_TIME +
        '--gateway %s --netmask %s %s' % (gateway, net_mask, vlan_name),
        'config dhcp_server ipv4 enable %s' % vlan_name
    ]


def generate_dhcp_range_config_cli_commands(ip_range, range_name="test_single_ip"):
    ret_command = ""
    if len(ip_range) == 1:
        ret_command += 'config dhcp_server ipv4 range add %s %s' % (range_name, ip_range[0])
    elif len(ip_range) == 2:
        ret_command += 'config dhcp_server ipv4 range add %s %s %s' % (range_name, ip_range[0], ip_range[1])
    else:
        pytest.fail("Invalid ip range:%s" % ip_range)
    return [ret_command]


def generate_dhcp_port_config_cli_commands(vlan_name, dut_port, range_name="test_single_ip"):
    return [
        'config dhcp_server ipv4 bind %s %s --range %s' % (vlan_name, dut_port, range_name)
    ]


def match_expected_dhcp_options(pkt_dhcp_options, option_name, expected_value):
    for option in pkt_dhcp_options:
        if option[0] == option_name:
            return option[1] == expected_value
    return False


def convert_mac_to_chaddr(mac):
    return binascii.unhexlify(mac.replace(":", "")) + b'\x00' * 10


def create_dhcp_client_packet(src_mac, message_type, client_options=[], xid=123, ciaddr='0.0.0.0'):
    dhcp_options = [("message-type", message_type)] + client_options + ["end"]
    pkt = scapy.Ether(dst=DHCP_MAC_BROADCAST, src=src_mac)
    pkt /= scapy.IP(src=DHCP_IP_DEFAULT_ROUTE, dst=DHCP_IP_BROADCAST)
    pkt /= scapy.UDP(sport=DHCP_UDP_CLIENT_PORT, dport=DHCP_UDP_SERVER_PORT)
    pkt /= scapy.BOOTP(chaddr=convert_mac_to_chaddr(src_mac), xid=xid, ciaddr=ciaddr)
    pkt /= scapy.DHCP(options=dhcp_options)
    return pkt


def send_and_verify(
    duthost,
    ptfhost,
    ptfadapter,
    test_pkt,
    dut_port_to_capture_pkt,
    ptf_port_index,
    pkts_validator,
    pkts_validator_args=[],
    pkts_validator_kwargs={},
    refresh_fdb_ptf_port=None
):
    pkts_filter = "udp dst port %s" % (DHCP_UDP_CLIENT_PORT)
    with capture_and_check_packet_on_dut(
        duthost=duthost,
        interface=dut_port_to_capture_pkt,
        pkts_filter=pkts_filter,
        pkts_validator=pkts_validator,
        pkts_validator_args=pkts_validator_args,
        pkts_validator_kwargs=pkts_validator_kwargs,
        wait_time=3
    ):
        clean_fdb_table(duthost)
        if refresh_fdb_ptf_port:
            ping_dut_refresh_fdb(ptfhost, refresh_fdb_ptf_port)
        testutils.send_packet(ptfadapter, ptf_port_index, test_pkt)


def validate_dhcp_server_pkts(pkts, test_xid, expected_ip, exp_msg_type, exp_net_mask, exp_server_ip):
    def is_expected_pkt(pkt):
        logging.info("validate_dhcp_server_pkts: %s" % repr(pkt))
        pkt_dhcp_options = pkt[scapy.DHCP].options
        if pkt[scapy.BOOTP].xid != test_xid:
            return False
        elif pkt[scapy.BOOTP].yiaddr != expected_ip:
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "subnet_mask", exp_net_mask):
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "server_id", exp_server_ip):
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "lease_time", DHCP_DEFAULT_LEASE_TIME):
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "message-type", exp_msg_type):
            return False
        return True
    pytest_assert(len([pkt for pkt in pkts if is_expected_pkt(pkt)]) == 1,
                  "Didn't got dhcp packet with expected ip and xid")


def validate_no_dhcp_server_pkts(pkts, test_xid):
    def is_expected_pkt(pkt):
        logging.info("validate_no_dhcp_server_pkts: %s" % repr(pkt))
        pkt_dhcp_options = pkt[scapy.DHCP].options
        if pkt[scapy.BOOTP].xid != test_xid:
            return False
        elif match_expected_dhcp_options(pkt_dhcp_options, "message-type", DHCP_MESSAGE_TYPE_NAK_NUM):
            return False
        return True
    pytest_assert(len([pkt for pkt in pkts if is_expected_pkt(pkt)]) == 0,
                  "Got unexpected dhcp packet")


def validate_dhcp_server_pkts_custom_option(pkts, test_xid, **options):
    def has_custom_option(pkt):
        logging.info("validate_dhcp_server_pkts_custom_option: %s" % repr(pkt))
        if pkt[scapy.BOOTP].xid != test_xid:
            return False
        pkt_dhcp_options = pkt[scapy.DHCP].options
        for option_type, expected_value in options.items():
            if not match_expected_dhcp_options(pkt_dhcp_options, int(option_type), expected_value):
                return False
        return True
    pytest_assert(len([pkt for pkt in pkts if has_custom_option(pkt)]) == 1,
                  "Didn't got dhcp packet with expected custom option")


def verify_discover_and_request_then_release(
        duthost,
        ptfhost,
        ptfadapter,
        dut_port_to_capture_pkt,
        test_xid,
        dhcp_interface,
        ptf_port_index,
        ptf_mac_port_index,
        expected_assigned_ip,
        exp_server_ip,
        net_mask,
        refresh_fdb_ptf_port=None
):
    client_mac = ptfadapter.dataplane.get_mac(0, ptf_mac_port_index).decode('utf-8')
    pkts_validator = validate_dhcp_server_pkts if expected_assigned_ip else validate_no_dhcp_server_pkts
    pkts_validator_args = [test_xid, expected_assigned_ip, DHCP_MESSAGE_TYPE_OFFER_NUM, net_mask, exp_server_ip] \
        if expected_assigned_ip else [test_xid]
    discover_pkt = create_dhcp_client_packet(
        src_mac=client_mac,
        message_type=DHCP_MESSAGE_TYPE_DISCOVER_NUM,
        client_options=[],
        xid=test_xid
    )
    send_and_verify(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port_to_capture_pkt,
        ptf_port_index=ptf_port_index,
        test_pkt=discover_pkt,
        pkts_validator=pkts_validator,
        pkts_validator_args=pkts_validator_args,
        refresh_fdb_ptf_port=refresh_fdb_ptf_port
    )
    request_pkt = create_dhcp_client_packet(
        src_mac=client_mac,
        message_type=DHCP_MESSAGE_TYPE_REQUEST_NUM,
        client_options=[
            ("requested_addr", expected_assigned_ip),
            ("server_id", exp_server_ip)
        ],
        xid=test_xid
    )
    pkts_validator_args = [test_xid, expected_assigned_ip, DHCP_MESSAGE_TYPE_ACK_NUM, net_mask, exp_server_ip] \
        if expected_assigned_ip else [test_xid]
    send_and_verify(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port_to_capture_pkt,
        ptf_port_index=ptf_port_index,
        test_pkt=request_pkt,
        pkts_validator=pkts_validator,
        pkts_validator_args=pkts_validator_args,
        refresh_fdb_ptf_port=refresh_fdb_ptf_port
    )
    if expected_assigned_ip:
        verify_lease(duthost, dhcp_interface, client_mac, expected_assigned_ip, DHCP_DEFAULT_LEASE_TIME)
        release_pkt = create_dhcp_client_packet(
            src_mac=client_mac,
            message_type=DHCP_MESSAGE_TYPE_RELEASE_NUM,
            client_options=[("server_id", exp_server_ip)],
            xid=test_xid,
            ciaddr=expected_assigned_ip
        )
        testutils.send_packet(ptfadapter, ptf_port_index, release_pkt)


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_single_ip_tc1(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        Verify configured interface with client mac not in FDB table can successfully get IP
    """
    test_xid = 1
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    config_cli = generate_common_config_cli_commands(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_gcu = generate_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip,
            exp_server_ip=gateway,
            net_mask=net_mask
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_single_ip_tc2(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool,
):
    """
        Verify configured interface with client mac in FDB table can successfully get IP
    """
    test_xid = 2
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    config_cli = generate_common_config_cli_commands(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_gcu = generate_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip,
            exp_server_ip=gateway,
            net_mask=net_mask,
            refresh_fdb_ptf_port='eth'+str(ptf_port_index)
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_single_ip_tc3(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        Verify configured interface with client mac in FDB table
        but mac was learnt from another interface successfully get IP.
    """
    test_xid = 3
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    config_cli = generate_common_config_cli_commands(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    _, ptf_mac_port_index = random.choice([m for m in vlan_members_with_ptf_idx if m[0] != dut_port])
    config_gcu = generate_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_mac_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip,
            exp_server_ip=gateway,
            net_mask=net_mask,
            refresh_fdb_ptf_port='eth'+str(ptf_mac_port_index)
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_single_ip_tc4(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        Verify no-configured interface cannot get IP
    """
    test_xid = 4
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    assigned_ip = random.choice(vlan_hosts)
    unconfigured_dut_port, unconfigured_ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    configured_dut_port, _ = random.choice([m for m in vlan_members_with_ptf_idx if m[0] != unconfigured_dut_port])
    config_cli = generate_common_config_cli_commands(
        vlan_name, gateway, net_mask, [configured_dut_port], [[assigned_ip]])
    config_gcu = generate_common_config_patch(
        vlan_name, gateway, net_mask, [configured_dut_port], [[assigned_ip]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt='any',
            ptf_port_index=unconfigured_ptf_port_index,
            ptf_mac_port_index=unconfigured_ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=None,
            exp_server_ip=gateway,
            net_mask=net_mask,
            refresh_fdb_ptf_port='eth'+str(unconfigured_ptf_port_index)
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_range_ip(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
       Test single ip assignment with different scenarios, each scenario has a description in scenario_context.
    """
    test_xid = 5
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts[:-1])
    last_ip_in_range = random.choice(vlan_hosts[vlan_hosts.index(expected_assigned_ip) + 1:])
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    config_cli = generate_common_config_cli_commands(
        vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip, last_ip_in_range]])
    config_gcu = generate_common_config_patch(
        vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip, last_ip_in_range]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip,
            exp_server_ip=gateway,
            net_mask=net_mask,
            refresh_fdb_ptf_port='eth'+str(ptf_port_index)
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assigenment_single_ip_mac_move(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        To test port based single ip assignment with client move to an interface has free IP to assign.
    """
    test_xid = 6
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip_0 = random.choice(vlan_hosts)
    dut_port_0, ptf_port_index_0 = random.choice(vlan_members_with_ptf_idx)
    expected_assigned_ip_1 = random.choice([v for v in vlan_hosts if v != expected_assigned_ip_0])
    dut_port_1, ptf_port_index_1 = random.choice([m for m in vlan_members_with_ptf_idx if m[0] != dut_port_0])
    config_cli = generate_common_config_cli_commands(
        vlan_name, gateway, net_mask, [dut_port_0, dut_port_1], [[expected_assigned_ip_0], [expected_assigned_ip_1]])
    config_gcu = generate_common_config_patch(
        vlan_name, gateway, net_mask, [dut_port_0, dut_port_1], [[expected_assigned_ip_0], [expected_assigned_ip_1]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_0,
            ptf_port_index=ptf_port_index_0,
            ptf_mac_port_index=ptf_port_index_0,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_0,
            exp_server_ip=gateway,
            net_mask=net_mask
        )
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_1,
            ptf_port_index=ptf_port_index_1,
            ptf_mac_port_index=ptf_port_index_0,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_1,
            exp_server_ip=gateway,
            net_mask=net_mask
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assigenment_single_ip_mac_swap(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        To test port based single ip assignment with two clients swap their interfaces.
    """
    test_xid = 7
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip_0 = random.choice(vlan_hosts)
    dut_port_0, ptf_port_index_0 = random.choice(vlan_members_with_ptf_idx)
    expected_assigned_ip_1 = random.choice([v for v in vlan_hosts if v != expected_assigned_ip_0])
    dut_port_1, ptf_port_index_1 = random.choice([m for m in vlan_members_with_ptf_idx if m[0] != dut_port_0])
    config_cli = generate_common_config_cli_commands(
        vlan_name, gateway, net_mask, [dut_port_0, dut_port_1], [[expected_assigned_ip_0], [expected_assigned_ip_1]])
    config_gcu = generate_common_config_patch(
        vlan_name, gateway, net_mask, [dut_port_0, dut_port_1], [[expected_assigned_ip_0], [expected_assigned_ip_1]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_0,
            ptf_port_index=ptf_port_index_0,
            ptf_mac_port_index=ptf_port_index_0,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_0,
            exp_server_ip=gateway,
            net_mask=net_mask
        )
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_1,
            ptf_port_index=ptf_port_index_1,
            ptf_mac_port_index=ptf_port_index_1,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_1,
            exp_server_ip=gateway,
            net_mask=net_mask
        )
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_1,
            ptf_port_index=ptf_port_index_1,
            ptf_mac_port_index=ptf_port_index_0,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_1,
            exp_server_ip=gateway,
            net_mask=net_mask
        )
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_0,
            ptf_port_index=ptf_port_index_0,
            ptf_mac_port_index=ptf_port_index_1,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_0,
            exp_server_ip=gateway,
            net_mask=net_mask
        )
