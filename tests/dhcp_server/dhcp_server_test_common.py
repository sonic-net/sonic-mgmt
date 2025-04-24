import binascii
import contextlib
from datetime import datetime
import json
import logging
import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from tests.common.utilities import capture_and_check_packet_on_dut, wait_until
from tests.common.helpers.assertions import pytest_assert, pytest_require


DHCP_DEFAULT_LEASE_TIME = 100
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
DHCP_SERVER_SUPPORTED_OPTION_ID = (
    "147", "148", "149", "163", "164", "165", "166", "167", "168", "169", "170", "171", "172", "173",
    "174", "178", "179", "180", "181", "182", "183", "184", "185", "186", "187", "188", "189", "190",
    "191", "192", "193", "194", "195", "196", "197", "198", "199", "200", "201", "202", "203", "204",
    "205", "206", "207", "214", "215", "216", "217", "218", "219", "222", "223"
)


def vlan_i2n(vlan_id):
    """
        Convert vlan id to vlan name
    """
    return "Vlan%s" % vlan_id


def vlan_n2i(vlan_name):
    """
        Convert vlan name to vlan id
    """
    return vlan_name.replace("Vlan", "")


def clean_fdb_table(duthost):
    duthost.shell("sonic-clear fdb all")


def ping_dut_refresh_fdb(ptfhost, interface):
    ptfhost.shell("timeout 1 ping -c 1 -w 1 -I {} 255.255.255.255 -b".format(interface), module_ignore_errors=True)


def clean_dhcp_server_config(duthost):
    keys = duthost.shell("sonic-db-cli CONFIG_DB KEYS DHCP_SERVER_IPV4*")
    clean_order = [
        "DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS",
        "DHCP_SERVER_IPV4_RANGE",
        "DHCP_SERVER_IPV4_PORT",
        "DHCP_SERVER_IPV4"
    ]
    for key in clean_order:
        for line in keys['stdout_lines']:
            if line.startswith(key + '|'):
                duthost.shell("sonic-db-cli CONFIG_DB DEL '{}'".format(line))


def verify_lease(duthost, dhcp_interface, client_mac, exp_ip, exp_lease_time):
    pytest_assert(
        wait_until(
            11,  # it's by design that there is a latency around 0~11 seconds for updating state db
            1,
            3,
            lambda _dh, _di, _cm: len(_dh.shell(
                    "sonic-db-cli STATE_DB KEYS 'DHCP_SERVER_IPV4_LEASE|{}|{}'".format(_di, _cm)
                )['stdout']) > 0,
            duthost,
            dhcp_interface,
            client_mac
        ),
        'state db doesnt have lease info for client {}'.format(client_mac)
    )
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


@contextlib.contextmanager
def dhcp_server_config(duthost, config_tool, config_to_apply):
    clean_dhcp_server_config(duthost)
    if config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        apply_dhcp_server_config_gcu(duthost, config_to_apply)
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        apply_dhcp_server_config_cli(duthost, config_to_apply)

    yield

    clean_dhcp_server_config(duthost)


def apply_dhcp_server_config_cli(duthost, config_commands):
    logging.info("The dhcp_server_config: %s" % config_commands)
    for cmd in config_commands:
        duthost.shell(cmd)


def apply_dhcp_server_config_gcu(duthost, config_to_apply):
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


def create_common_config_patch(vlan_name, gateway, net_mask, dut_ports, ip_ranges, customized_options=None):
    pytest_require(len(dut_ports) == len(ip_ranges), "Invalid input, dut_ports and ip_ranges should have same length")
    ret_patch = empty_config_patch(customized_options)
    append_common_config_patch(ret_patch, vlan_name, gateway, net_mask, dut_ports, ip_ranges, customized_options)
    return ret_patch


def empty_config_patch(customized_options=None):
    ret_empty_patch = [
        {
            "op": "add",
            "path": "/DHCP_SERVER_IPV4",
            "value": {}
        },
        {
            "op": "add",
            "path": "/DHCP_SERVER_IPV4_RANGE",
            "value": {}
        },
        {
            "op": "add",
            "path": "/DHCP_SERVER_IPV4_PORT",
            "value": {}
        }
    ]
    if customized_options:
        ret_empty_patch.insert(
            0,
            {
                "op": "add",
                "path": "/DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS",
                "value": {}
            }
        )
    return ret_empty_patch


def append_common_config_patch(
    config_patch,
    vlan_name,
    gateway,
    net_mask,
    dut_ports,
    ip_ranges,
    customized_options=None
):
    pytest_require(len(dut_ports) == len(ip_ranges), "Invalid input, dut_ports and ip_ranges should have same length")
    new_patch = []
    if customized_options:
        new_patch += generate_dhcp_custom_option_config_patch(customized_options)
    new_patch += generate_dhcp_interface_config_patch(vlan_name, gateway, net_mask, customized_options)
    range_names = ["range_" + ip_range[0] for ip_range in ip_ranges]
    new_patch += generate_dhcp_range_config_patch(ip_ranges, range_names)
    new_patch += generate_dhcp_port_config_patch(vlan_name, dut_ports, range_names)
    config_patch += new_patch


def generate_dhcp_interface_config_patch(vlan_name, gateway, net_mask, customized_options=None):
    ret_interface_config_patch = [
        {
            "op": "add",
            "path": "/DHCP_SERVER_IPV4/%s" % vlan_name,
            "value": {
                "gateway": "%s" % gateway,
                "lease_time": "%s" % DHCP_DEFAULT_LEASE_TIME,
                "mode": "PORT",
                "netmask": "%s" % net_mask,
                "state": "enabled"
            }
        }
    ]
    if customized_options:
        ret_interface_config_patch[0]["value"]["customized_options"] = list(customized_options.keys())
    return ret_interface_config_patch


def generate_dhcp_range_config_patch(ip_ranges, range_names):
    ret_range_config_patch = []
    for range_name, ip_range in zip(range_names, ip_ranges):
        ret_range_config_patch.append({
            "op": "add",
            "path": "/DHCP_SERVER_IPV4_RANGE/%s" % range_name,
            "value": {
                "range": ip_range
            }
        })
    return ret_range_config_patch


def generate_dhcp_port_config_patch(vlan_name, dut_ports, range_names):
    ret_port_config_patch = []
    for range_name, dut_port in zip(range_names, dut_ports):
        ret_port_config_patch.append({
            "op": "add",
            "path": "/DHCP_SERVER_IPV4_PORT/%s|%s" % (vlan_name, dut_port),
            "value": {
                "ranges": [
                    range_name
                ]
            }
        })
    return ret_port_config_patch


def generate_dhcp_custom_option_config_patch(customized_options):
    ret_custom_option_config_patch = []
    for option_name, option_info in customized_options.items():
        ret_custom_option_config_patch.append({
            "op": "add",
            "path": "/DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS/%s" % option_name,
            "value": option_info
        })
    return ret_custom_option_config_patch


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


def match_expected_dhcp_options(pkt_dhcp_options, option_id, expected_value):
    for option in pkt_dhcp_options:
        if option[0] == option_id:
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
    pkts_filter = "ip and udp dst port %s" % (DHCP_UDP_CLIENT_PORT)
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


def validate_dhcp_server_pkts(
    pkts,
    test_xid,
    expected_ip,
    exp_msg_type,
    exp_net_mask,
    exp_gateway,
    exp_lease_time=DHCP_DEFAULT_LEASE_TIME,
    options=None
):
    def is_expected_pkt(pkt):
        logging.info("validate_dhcp_server_pkts: %s" % repr(pkt))
        pkt_dhcp_options = pkt[scapy.DHCP].options
        if pkt[scapy.BOOTP].xid != test_xid:
            return False
        elif pkt[scapy.BOOTP].yiaddr != expected_ip:
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "subnet_mask", exp_net_mask):
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "router", exp_gateway):
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "lease_time", exp_lease_time):
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "message-type", exp_msg_type):
            return False
        elif options:
            pkt_dhcp_options = pkt[scapy.DHCP].options
            for option_id, expected_value in options.items():
                if not match_expected_dhcp_options(pkt_dhcp_options, int(option_id), expected_value):
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
        for option_id, expected_value in options.items():
            if not match_expected_dhcp_options(pkt_dhcp_options, int(option_id), expected_value):
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
        exp_gateway,
        server_id,
        net_mask,
        refresh_fdb_ptf_port=None,
        exp_lease_time=DHCP_DEFAULT_LEASE_TIME,
        release_needed=True,
        customized_options=None
):
    client_mac = ptfadapter.dataplane.get_mac(0, ptf_mac_port_index).decode('utf-8')
    pkts_validator = validate_dhcp_server_pkts if expected_assigned_ip else validate_no_dhcp_server_pkts
    pkts_validator_args = [
        test_xid,
        expected_assigned_ip,
        DHCP_MESSAGE_TYPE_OFFER_NUM,
        net_mask,
        exp_gateway,
        exp_lease_time,
        customized_options
    ] if expected_assigned_ip else [test_xid]
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
            ("server_id", server_id)
        ],
        xid=test_xid
    )
    pkts_validator_args = [
        test_xid,
        expected_assigned_ip,
        DHCP_MESSAGE_TYPE_ACK_NUM,
        net_mask, exp_gateway,
        exp_lease_time
    ] if expected_assigned_ip else [test_xid]
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
    if expected_assigned_ip and release_needed:
        verify_lease(duthost, dhcp_interface, client_mac, expected_assigned_ip, exp_lease_time)
        send_release_packet(ptfadapter, ptf_port_index, test_xid, client_mac, expected_assigned_ip, server_id)


def send_release_packet(
    ptfadapter,
    ptf_port_index,
    xid,
    client_mac,
    ip_assigned,
    server_id
):
    release_pkt = create_dhcp_client_packet(
        src_mac=client_mac,
        message_type=DHCP_MESSAGE_TYPE_RELEASE_NUM,
        client_options=[("server_id", server_id)],
        xid=xid,
        ciaddr=ip_assigned
    )
    testutils.send_packet(ptfadapter, ptf_port_index, release_pkt)
