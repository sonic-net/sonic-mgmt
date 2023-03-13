import pytest
import ipaddress
import sys
import time
import re

import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from mx_utils import create_vlan, remove_vlan, get_vlan_config, check_dnsmasq, refresh_dut_mac_table

pytestmark = [
    pytest.mark.topology('mx'),
]

if sys.version_info.major == 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode

INET_REG = r"(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/\d+"
DUMMY_MAC = "22:22:22:22:22:22"
DHCP_ETHER_TYPE_IP = 0x0800
DHCP_PKT_BOOTP_MIN_LEN = 300
DHCP_SPORT = 67
DHCP_DPORT = 68
DHCP_BOOTP_OP_REPLY = 2
DHCP_BOOTP_HTYPE_ETHERNET = 1
DHCP_BOOTP_HLEN_ETHERNET = 6
# if client has a current IP address otherwise set to zeros
DEFAULT_CLIENT_IP = "0.0.0.0"
DEFAULT_RELAY_AGENT_IP = "0.0.0.0"
DEFAULT_LEASE_TIME = 900
VLAN_IP_BASE = "172.17.0.0"


@pytest.fixture(scope="module")
def dhcp_client_setup_teardown(ptfhost, creds):
    # PTF setup, install dhcp client
    http_proxy = creds.get("proxy_env", {}).get("http_proxy", "")
    http_param = "-o Acquire::http::proxy='{}'".format(http_proxy) if http_proxy != "" else ""
    ptfhost.shell("apt-get {} update".format(http_param), module_ignore_errors=True)
    ptfhost.shell("apt-get {} install isc-dhcp-client -y".format(http_param))

    yield

    ptfhost.shell("apt-get remove isc-dhcp-client -y", module_ignore_errors=True)


def send_dhcp_request(ptfhost, sleep_time=15):
    ptfhost.shell("dhclient")
    time.sleep(sleep_time)


def send_dhcp_release(ptfhost):
    ptfhost.shell("dhclient -r")


def dhcp_setup(duthost, ptfhost, config, ptf_index_port, intf_count):
    duthost.shell("sonic-clear fdb all")
    # Frequent restarts dhcp_relay service may cause start-limit-hit error, use this command to ignore and restart
    duthost.shell("systemctl reset-failed dhcp_relay", module_ignore_errors=True)
    duthost.restart_service("dhcp_relay")

    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "dhcp_relay"),
                  "dhcp_relay not started")
    duthost.shell("docker exec -i dhcp_relay cat /dev/null > /etc/dnsmasq.hosts", module_ignore_errors=True)
    refresh_dut_mac_table(ptfhost, config, ptf_index_port)
    wait_until(600, 3, 0, check_dnsmasq, duthost, intf_count)


def dhcp_ip_assign_test(ptfhost, vlan_config, ptf_index_port):
    try:
        # Prepare
        send_dhcp_request(ptfhost)
        send_dhcp_release(ptfhost)

        send_dhcp_request(ptfhost, 30)
        ip_base = ipaddress.ip_address(UNICODE_TYPE(VLAN_IP_BASE))
        for _, config in vlan_config.items():
            member_number = len(config["members"])
            # No need to verify single interface in a vlan
            if member_number == 1:
                continue

            vlan_members = config["members"]
            for port_index in vlan_members:
                ip = ip_base + port_index * 4 + 1
                ptf_port_name = "eth{}".format(ptf_index_port[port_index])

                output = ptfhost.shell("ip address show {}".format(ptf_port_name))['stdout']
                pytest_assert(str(ip) in output, "Can't get correct dhcp ip for {}".format(ptf_port_name))

    finally:
        send_dhcp_release(ptfhost)


def get_dhcp_ips(duthost, vlan_config, ptf_index_port, ptfhost, intf_count):
    """
    Refresh mac table and get dhcp ips
    """
    intf_ips = {}
    dhcp_setup(duthost, ptfhost, vlan_config, ptf_index_port, intf_count)

    try:
        send_dhcp_request(ptfhost)
        send_dhcp_release(ptfhost)

        send_dhcp_request(ptfhost, 30)
        pattern = re.compile(INET_REG)
        for _, config in vlan_config.items():
            member_number = len(config["members"])
            # No need to verify single interface in a vlan
            if member_number == 1:
                continue

            vlan_members = config["members"]
            for port_index in vlan_members:
                ptf_port_name = "eth{}".format(ptf_index_port[port_index])

                output = ptfhost.shell("ip address show {}".format(ptf_port_name))['stdout']
                match = pattern.search(output)
                pytest_assert(match is not None, "Can't get dhcp ip for {}".format(ptf_port_name))
                intf_ips[ptf_port_name] = match.group()
    finally:
        send_dhcp_release(ptfhost)

    return intf_ips


def change_mac(ptfhost, port_name, mac):
    ptfhost.set_dev_up_or_down(port_name, False)
    ptfhost.shell("ip link set dev {} adress {}".format(port_name, mac), module_ignore_errors=True)
    ptfhost.set_dev_up_or_down(port_name, True)


def get_test_vlan(vlan_config):
    """
    Get first vlan config that member number > 1, interfaces in this vlan should get get correct dhcp packet/ip
    """
    ret_config = None
    for _, config in vlan_config.items():
        if len(config["members"]) > 1:
            ret_config = config

    pytest_require(ret_config is not None, "Can't get vlan that number of member > 1")
    return ret_config


def dhcp_mac_change_test(duthost, ptfhost, vlan_config, ptf_index_port, ptfadapter, intf_count):
    # save origin mac
    test_vlan = get_test_vlan(vlan_config)
    test_intf_index = test_vlan["members"][0]
    ptf_port_name = "eth{}".format(ptf_index_port[test_intf_index])
    mac_before = ptfadapter.dataplane.get_mac(0, test_intf_index)

    try:
        intf_ips_before = get_dhcp_ips(duthost, vlan_config, ptf_index_port, ptfhost, intf_count)
        change_mac(ptfhost, ptf_port_name, DUMMY_MAC)
        intf_ips_after = get_dhcp_ips(duthost, vlan_config, ptf_index_port, ptfhost, intf_count)
        for key, value in intf_ips_before.items():
            pytest_assert(value == intf_ips_after[key], "Get different dhcp ip for {} after mac change".format(key))

    finally:
        # restore mac
        change_mac(ptfhost, ptf_port_name, mac_before)


def create_dhcp_offer_ack_packet(eth_client, eth_server, ip_server, ip_dst, netmask_client, lease_time,
                                 broadcast_address, dhcp_type="offer"):
    """
    Create dhcp offer/ack packet, since the functions create dhcp offer/ack packet in testutils cannot create packets
    which have expected 'options' field.
    """
    ether = scapy.Ether(dst=eth_client, src=eth_server, type=DHCP_ETHER_TYPE_IP)
    ip = scapy.IP(src=ip_server, dst=ip_dst, len=328, ttl=64)
    udp = scapy.UDP(sport=DHCP_SPORT, dport=DHCP_DPORT, len=308)
    bootp = scapy.BOOTP(
        op=DHCP_BOOTP_OP_REPLY,
        htype=DHCP_BOOTP_HTYPE_ETHERNET,
        hlen=DHCP_BOOTP_HLEN_ETHERNET,
        hops=0,
        xid=0,
        secs=0,
        flags=0,
        ciaddr=DEFAULT_CLIENT_IP,
        yiaddr=ip_dst,
        siaddr=ip_server,
        giaddr=DEFAULT_RELAY_AGENT_IP,
        chaddr=testutils.__dhcp_mac_to_chaddr(eth_client)
    )
    bootp /= scapy.DHCP(options=[
        ("message-type", dhcp_type),
        ("server_id", ip_server),
        ("lease_time", lease_time),
        ("renewal_time", 450),
        ("rebinding_time", 787),
        ("subnet_mask", netmask_client),
        ("broadcast_address", broadcast_address),
        ("router", ip_server),
        ("end")
    ])

    pad_bytes = DHCP_PKT_BOOTP_MIN_LEN - len(bootp)
    if pad_bytes > 0:
        bootp /= scapy.PADDING("\x00" * pad_bytes)
        pkt = ether / ip / udp / bootp

    return pkt


def dhcp_send_verify(ptfadapter, port_index, expected_pkt, pkt):
    mask_expected_pkt = Mask(expected_pkt)
    mask_expected_pkt.set_do_not_care_scapy(scapy.IP, "tos")
    mask_expected_pkt.set_do_not_care_scapy(scapy.IP, "id")
    mask_expected_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    mask_expected_pkt.set_do_not_care_scapy(scapy.UDP, "chksum")

    testutils.send_packet(ptfadapter, port_index, pkt)
    # It seems that using [testutils.verify_packet] can't get expected packet, so use poll for now
    res = ptfadapter.dataplane.poll(port_number=port_index, exp_pkt=mask_expected_pkt)
    pytest_assert(isinstance(res, ptfadapter.dataplane.PollSuccess),
                  "Can't get expected dhcp offer packet from port {}".format(port_index))


def dhcp_packet_test(duthost, enum_asic_index, vlan_config, ptfadapter):
    first_vlan_config = get_test_vlan(vlan_config)
    test_port_index = first_vlan_config["members"][0]
    # ip address of dhcp server
    ip_server = first_vlan_config["prefix"].split("/")[0]
    ptf_port_mac = ptfadapter.dataplane.get_mac(0, test_port_index)
    dut_port_mac = duthost.asic_instance(enum_asic_index).get_router_mac()
    vlan_net = ipaddress.ip_network(UNICODE_TYPE(first_vlan_config["prefix"]), strict=False)
    netmask_client = vlan_net.netmask
    broadcast_ip = vlan_net.broadcast_address
    ip_base = ipaddress.ip_address(UNICODE_TYPE(VLAN_IP_BASE))
    ip_client = ip_base + test_port_index * 4 + 1

    # Send dhcp discover packet and verify receive dhcp offer packet
    dhcp_discover_pkt = testutils.dhcp_discover_packet(eth_client=ptf_port_mac)
    expected_dhcp_offer_pkt = create_dhcp_offer_ack_packet(ptf_port_mac, dut_port_mac, ip_server, ip_client,
                                                           netmask_client, DEFAULT_LEASE_TIME, broadcast_ip)
    dhcp_send_verify(ptfadapter, test_port_index, expected_dhcp_offer_pkt, dhcp_discover_pkt)

    # Send dhcp request packet and verify receive dhcp ack packet
    dhcp_request = testutils.dhcp_request_packet(eth_client=ptf_port_mac, ip_server=ip_server, ip_requested=ip_client)
    expected_dhcp_ack_pkt = create_dhcp_offer_ack_packet(ptf_port_mac, dut_port_mac, ip_server, ip_client,
                                                         netmask_client, DEFAULT_LEASE_TIME, broadcast_ip, "ack")
    dhcp_send_verify(ptfadapter, test_port_index, expected_dhcp_ack_pkt, dhcp_request)


@pytest.mark.parametrize("vlan_number", [1, 4, 7])
def test_dhcp_server_tc1_ip_assign(duthost, ptfhost, function_fixture_remove_all_vlans, mx_common_setup_teardown,
                                   dhcp_client_setup_teardown, vlan_number):
    dut_index_port, ptf_index_port, vlan_configs = mx_common_setup_teardown
    vlan_config = get_vlan_config(vlan_configs, vlan_number)
    intf_count = create_vlan(duthost, vlan_config, dut_index_port)
    dhcp_setup(duthost, ptfhost, vlan_config, ptf_index_port, intf_count)
    dhcp_ip_assign_test(ptfhost, vlan_config, ptf_index_port)
    remove_vlan(duthost, vlan_config, dut_index_port)


@pytest.mark.parametrize("vlan_number", [4])
def test_dhcp_server_tc2_mac_change(duthost, ptfhost, ptfadapter, function_fixture_remove_all_vlans,
                                    mx_common_setup_teardown, dhcp_client_setup_teardown,
                                    vlan_number):
    dut_index_port, ptf_index_port, vlan_configs = mx_common_setup_teardown
    vlan_config = get_vlan_config(vlan_configs, vlan_number)
    intf_count = create_vlan(duthost, vlan_config, dut_index_port)
    dhcp_mac_change_test(duthost, ptfhost, vlan_config, ptf_index_port, ptfadapter, intf_count)
    remove_vlan(duthost, vlan_config, dut_index_port)


@pytest.mark.parametrize("vlan_number", [4])
def test_dhcp_server_tc3_packet(duthost, ptfhost, function_fixture_remove_all_vlans, mx_common_setup_teardown,
                                vlan_number, enum_asic_index, ptfadapter):
    dut_index_port, ptf_index_port, vlan_configs = mx_common_setup_teardown
    vlan_config = get_vlan_config(vlan_configs, vlan_number)
    intf_count = create_vlan(duthost, vlan_config, dut_index_port)
    dhcp_setup(duthost, ptfhost, vlan_config, ptf_index_port, intf_count)
    dhcp_packet_test(duthost, enum_asic_index, vlan_config, ptfadapter)
