import binascii
import logging
import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from tests.common.utilities import capture_and_check_packet_on_dut
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('m0', 'mx'),
]


VLAN_GATE_WAY = '192.168.0.1'
VLAN_SUBNET_MASK = '255.255.255.0'
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


def clean_fdb_table(duthost):
    duthost.shell("sonic-clear fdb all")


def ping_dut_refresh_fdb(ptfhost, interface, vlan_ip):
    ptfhost.shell("timeout 1 ping -c 1 -w 1 -I {} {}".format(interface, vlan_ip), module_ignore_errors=True)


def clean_dhcp_server_config(duthost):
    keys = duthost.shell("sonic-db-cli CONFIG_DB KEYS DHCP_SERVER_IPV4*")
    for key in keys["stdout_lines"]:
        duthost.shell("sonic-db-cli CONFIG_DB DEL '{}'".format(key))


@pytest.fixture(scope="module", autouse=True)
def dhcp_server_config_setup_and_teardown(duthost):
    clean_dhcp_server_config(duthost)
    config_commands = [
                        'config dhcp_server ipv4 add --mode PORT --lease_time %s ' % DHCP_DEFAULT_LEASE_TIME +
                        '--gateway %s --netmask 255.255.255.0 Vlan1000' % VLAN_GATE_WAY,
                        'config dhcp_server ipv4 enable Vlan1000',
                        # config part 1: for single ip assignment test
                        'config dhcp_server ipv4 range add test_single_0 192.168.0.10',
                        'config dhcp_server ipv4 bind Vlan1000 Ethernet0 --range test_single_0',
                        'config dhcp_server ipv4 range add test_single_1 192.168.0.11',
                        'config dhcp_server ipv4 bind Vlan1000 Ethernet1 --range test_single_1',
                        'config dhcp_server ipv4 range add test_single_2 192.168.0.12',
                        'config dhcp_server ipv4 bind Vlan1000 Ethernet2 --range test_single_2',
                        # config part 2: for range assignment test
                        'config dhcp_server ipv4 range add test_range_5 192.168.0.20 192.168.0.24',
                        'config dhcp_server ipv4 bind Vlan1000 Ethernet5 --range test_range_5',
                        # config part 3: for customize options test
                        'config dhcp_server ipv4 option add ' +
                        'sonic_test_option 147 string %s' % DHCP_DEFAULT_CUSTOM_OPTION_VALUE,
                        'config dhcp_server ipv4 option bind Vlan1000 sonic_test_option'
                    ]
    for cmd in config_commands:
        duthost.shell(cmd)

    yield

    clean_dhcp_server_config(duthost)


def match_expected_dhcp_options(pkt_dhcp_options, option_name, expected_value):
    for option in pkt_dhcp_options:
        if option[0] == option_name:
            return option[1] == expected_value
    return False


def convert_mac_to_chaddr(mac):
    return binascii.unhexlify(mac.replace(":", "")) + b'\x00' * 10


def create_dhcp_client_packet(src_mac, message_type, client_options=[], xid=123):
    dhcp_options = [("message-type", message_type)] + client_options + ["end"]
    pkt = scapy.Ether(dst=DHCP_MAC_BROADCAST, src=src_mac)
    pkt /= scapy.IP(src=DHCP_IP_DEFAULT_ROUTE, dst=DHCP_IP_BROADCAST)
    pkt /= scapy.UDP(sport=DHCP_UDP_CLIENT_PORT, dport=DHCP_UDP_SERVER_PORT)
    pkt /= scapy.BOOTP(chaddr=convert_mac_to_chaddr(src_mac), xid=xid)
    pkt /= scapy.DHCP(options=dhcp_options)
    return pkt


def send_and_verify(
    duthost,
    ptfhost,
    ptfadapter,
    senario_context,
    test_pkt,
    pkts_validator,
    pkts_validator_args=[],
    pkts_validator_kwargs={}
):
    dut_port_to_capture_pkt = senario_context['dut_port_to_capture_pkt']
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
        if 'refresh_fdb_ptf_port' in senario_context:
            ping_dut_refresh_fdb(ptfhost, senario_context['refresh_fdb_ptf_port'], VLAN_GATE_WAY)
        ptf_port_index = senario_context['ptf_port_index']
        testutils.send_packet(ptfadapter, ptf_port_index, test_pkt)


def validate_dhcp_server_pkts(pkts, test_xid, expected_ip, expected_msg_type):
    def is_expected_pkt(pkt):
        logging.info("validate_dhcp_server_pkts: %s" % repr(pkt))
        pkt_dhcp_options = pkt[scapy.DHCP].options
        if pkt[scapy.BOOTP].xid != test_xid:
            return False
        elif pkt[scapy.BOOTP].yiaddr != expected_ip:
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "subnet_mask", VLAN_SUBNET_MASK):
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "server_id", VLAN_GATE_WAY):
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "lease_time", DHCP_DEFAULT_LEASE_TIME):
            return False
        elif not match_expected_dhcp_options(pkt_dhcp_options, "message-type", expected_msg_type):
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


# dhcp_server/test_dhcp_server.py::test_dhcp_server_port_based_assignment_single_ip
@pytest.mark.parametrize('senario_context', [
    {
        'description': 'Verify configured interface with \
                        client mac not in FDB table can successfully get IP',
        'dut_port_to_capture_pkt': 'Ethernet0',
        'expected_assigned_ip': '192.168.0.10',
        'ptf_port_index': 0,
        "test_xid": 11
    },
    {
        'description': 'Verify configured interface with \
                        client mac in FDB table can successfully get IP',
        'dut_port_to_capture_pkt': 'Ethernet1',
        'expected_assigned_ip': '192.168.0.11',
        'ptf_port_index': 1,
        'refresh_fdb_ptf_port': 'eth1',
        "test_xid": 12
    },
    {
        'description': 'Verify configured interface with \
                        client mac in FDB table but mac was learnt \
                        from another interface can successfully get IP.',
        'dut_port_to_capture_pkt': 'Ethernet2',
        'expected_assigned_ip': '192.168.0.12',
        'ptf_mac_port_index': 3,
        'ptf_port_index': 2,
        'refresh_fdb_ptf_port': 'eth3',
        "test_xid": 13
    },
    {
        'description': 'Verify no-configured interface cannot get IP',
        'dut_port_to_capture_pkt': 'any',
        "expected_assigned_ip": None,
        'ptf_port_index': 4,
        'refresh_fdb_ptf_port': 'eth4',
        "test_xid": 14
    }
])
def test_dhcp_server_port_based_assignment_single_ip(duthost, ptfhost, ptfadapter, senario_context):
    """
       Test single ip assignment with different senarios, each senario has a description in senario_context.
    """
    test_xid = senario_context['test_xid']
    ptf_mac_port_index = senario_context.get('ptf_mac_port_index', senario_context['ptf_port_index'])
    client_mac = ptfadapter.dataplane.get_mac(0, ptf_mac_port_index).decode('utf-8')
    expected_ip = senario_context['expected_assigned_ip']
    pkts_validator = validate_dhcp_server_pkts if expected_ip else validate_no_dhcp_server_pkts
    pkts_validator_args = [test_xid, expected_ip, DHCP_MESSAGE_TYPE_OFFER_NUM] if expected_ip else [test_xid]
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
        senario_context=senario_context,
        test_pkt=discover_pkt,
        pkts_validator=pkts_validator,
        pkts_validator_args=pkts_validator_args
    )
    request_pkt = create_dhcp_client_packet(
        src_mac=client_mac,
        message_type=DHCP_MESSAGE_TYPE_REQUEST_NUM,
        client_options=[("requested_addr", expected_ip), ("server_id", VLAN_GATE_WAY)],
        xid=test_xid
    )
    pkts_validator_args = [test_xid, expected_ip, DHCP_MESSAGE_TYPE_ACK_NUM] if expected_ip else [test_xid]
    send_and_verify(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        senario_context=senario_context,
        test_pkt=request_pkt,
        pkts_validator=pkts_validator,
        pkts_validator_args=pkts_validator_args
    )


@pytest.mark.parametrize('senario_context', [
    {
        'dut_port_to_capture_pkt': 'Ethernet5',
        'expected_assigned_ip': '192.168.0.20',
        'ptf_port_index': 5,
        "test_xid": 15
    }
])
def test_dhcp_server_port_based_assignment_range(duthost, ptfhost, ptfadapter, senario_context):
    """
       Test range ip assignment
    """
    test_xid = senario_context['test_xid']
    ptf_mac_port_index = senario_context.get('ptf_mac_port_index', senario_context['ptf_port_index'])
    client_mac = ptfadapter.dataplane.get_mac(0, ptf_mac_port_index).decode('utf-8')
    expected_ip = senario_context['expected_assigned_ip']
    pkts_validator = validate_dhcp_server_pkts if expected_ip else validate_no_dhcp_server_pkts
    pkts_validator_args = [test_xid, expected_ip, DHCP_MESSAGE_TYPE_OFFER_NUM] if expected_ip else [test_xid]
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
        senario_context=senario_context,
        test_pkt=discover_pkt,
        pkts_validator=pkts_validator,
        pkts_validator_args=pkts_validator_args
    )
    request_pkt = create_dhcp_client_packet(
        src_mac=client_mac,
        message_type=DHCP_MESSAGE_TYPE_REQUEST_NUM,
        client_options=[("requested_addr", expected_ip), ("server_id", VLAN_GATE_WAY)],
        xid=test_xid
    )
    pkts_validator_args = [test_xid, expected_ip, DHCP_MESSAGE_TYPE_ACK_NUM] if expected_ip else [test_xid]
    send_and_verify(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        senario_context=senario_context,
        test_pkt=request_pkt,
        pkts_validator=pkts_validator,
        pkts_validator_args=pkts_validator_args
    )


@pytest.mark.parametrize('senario_context', [
    {
        'dut_port_to_capture_pkt': 'Ethernet5',
        'ptf_port_index': 5,
        "test_xid": 16
    }
])
def test_dhcp_server_port_based_customize_options(duthost, ptfhost, ptfadapter, senario_context):
    """
        Test dhcp server packets if carry the customized options as expected
    """
    test_xid = senario_context['test_xid']
    ptf_mac_port_index = senario_context['ptf_port_index']
    client_mac = ptfadapter.dataplane.get_mac(0, ptf_mac_port_index).decode('utf-8')
    pkts_validator = validate_dhcp_server_pkts_custom_option
    pkts_validator_args = [test_xid]
    pkts_validator_kwargs = {"147": DHCP_DEFAULT_CUSTOM_OPTION_VALUE.encode('ascii')}
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
        senario_context=senario_context,
        test_pkt=discover_pkt,
        pkts_validator=pkts_validator,
        pkts_validator_args=pkts_validator_args,
        pkts_validator_kwargs=pkts_validator_kwargs
    )
