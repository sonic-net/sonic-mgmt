import binascii
import logging
import pytest
import random
import tempfile
import time
from socket import inet_aton
from scapy.all import sniff as scapy_sniff
from tests.common.utilities import capture_and_check_packet_on_dut
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('mx'),
]

WOL_SLL_PKT_FILTER = 'ether[14:2]==0x0842'
WOL_ETHER_PKT_FILTER = 'ether[12:2]==0x0842'
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
ETHER_TYPE_WOL_BIN = b'\x08\x42'
ETHER_TYPE_WOL_DEC = int('842', 16)
PACKET_TYPE_BROADCAST = 1
PACKET_TYPE_UNICAST = 3
LINK_LAYER_TYPE_ETHER = 1
VLAN_MEMBER_CHANGE_ERR = r'.*Failed to get port by bridge port ID .*'


def generate_pcap_file_path(id: str) -> str:
    return '/tmp/wol_test_%s.pcap' % id


def vlan_n2i(vlan_name):
    """
        Convert vlan name to vlan id
    """
    return vlan_name.replace("Vlan", "")


def p2b(password: str) -> bytes:
    """
        convert password to bytes
    """
    if not password:
        return b''
    if ':' in password:
        return binascii.unhexlify(password.replace(':', ''))
    if '.' in password:
        return inet_aton(password)
    pytest.fail("invalid password %s" % password)


def m2b(mac: str) -> bytes:
    """
        convert mac address to bytes
    """
    return binascii.unhexlify(mac.replace(':', ''))


def build_magic_packet(src_mac: str, target_mac: str, broadcast: bool, password: str = "") -> bytes:
    dst_mac = BROADCAST_MAC if broadcast else target_mac
    return m2b(dst_mac) + m2b(src_mac) + ETHER_TYPE_WOL_BIN \
        + build_magic_packet_payload(target_mac, password)


def build_magic_packet_payload(target_mac: str, password: str = "") -> bytes:
    return b'\xff' * 6 + m2b(target_mac) * 16 + p2b(password)


def test_send_to_single_specific_interface(
    duthost,
    ptfhost,
    get_connected_dut_intf_to_ptf_index
):
    dut_mac = duthost.facts['router_mac']
    target_mac = "1a:2b:3c:d1:e2:f0"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))

    def validate_wol_packets(pkts):
        pytest_assert(len(pkts) == 1, "Unexpected pkts count %s" % len(pkts))
        pkt = pkts[0]
        pytest_assert(pkt.dst == target_mac, "Unexpected dst mac %s" % pkt.dst)
        pytest_assert(pkt.src == dut_mac, "Unexpected src mac %s" % pkt.src)
        pytest_assert(pkt.type == ETHER_TYPE_WOL_DEC)
        pytest_assert(pkt.load == build_magic_packet_payload(target_mac))

    with capture_and_check_packet_on_dut(
        duthost=ptfhost,
        interface='eth'+str(random_ptf_port),
        pkts_filter=WOL_ETHER_PKT_FILTER,
        pkts_validator=validate_wol_packets
    ):
        duthost.shell("wol %s %s" % (random_dut_port, target_mac))


def test_send_to_vlan(
    duthost,
    ptfhost,
    get_connected_dut_intf_to_ptf_index,
    loganalyzer
):
    loganalyzer[duthost.hostname].ignore_regex.append(VLAN_MEMBER_CHANGE_ERR)
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    dut_ptf_int_map = dict(get_connected_dut_intf_to_ptf_index)
    connected_dut_intf = [dut_intf for dut_intf, _ in connected_dut_intf_to_ptf_index]
    dut_mac = duthost.facts['router_mac']
    target_mac = "1a:2b:3c:d1:e2:f1"
    vlan_brief = duthost.get_vlan_brief()
    vlan_names = list(vlan_brief.keys())
    random_vlan = random.choice(vlan_names)
    vlan_members = vlan_brief[random_vlan]['members']
    connected_vlan_members = [member for member in vlan_members if member in connected_dut_intf]
    random_member_to_remove = random.choice(connected_vlan_members)
    random_vlan_members = [member for member in connected_vlan_members if member != random_member_to_remove]
    logging.info("Test with random vlan %s, members %s and member to remove %s"
                 % (random_vlan, random_vlan_members, random_member_to_remove))

    duthost.del_member_from_vlan(vlan_n2i(random_vlan), random_member_to_remove)

    try:
        tcpdump_cmd = 'nohup tcpdump -i %s -w %s %s >/dev/null 2>&1 & echo $!' % \
            (random_member_to_remove, generate_pcap_file_path(random_member_to_remove), WOL_ETHER_PKT_FILTER)
        tcpdump_pid = ptfhost.shell(tcpdump_cmd)["stdout"]
        for member in random_vlan_members + [random_member_to_remove]:
            ptf_int = 'eth' + str(dut_ptf_int_map[member])
            tcpdump_cmd = 'nohup tcpdump -i %s -w %s %s >/dev/null 2>&1 & echo $!' % \
                (ptf_int, generate_pcap_file_path(ptf_int), WOL_ETHER_PKT_FILTER)
            tcpdump_pid = ptfhost.shell(tcpdump_cmd)["stdout"]
            cmd_check_if_process_running = "ps -p %s | grep %s |grep -v grep | wc -l" % (tcpdump_pid, tcpdump_pid)
            success = ptfhost.shell(cmd_check_if_process_running)["stdout"] == "1"
            if not success:
                ptfhost.shell('killall tcpdump', module_ignore_errors=True)
                pytest.fail("Failed to start tcpdump on %s" % member)

        def validate_wol_packets(pkts):
            pytest_assert(len(pkts) == 1, "Unexpected pkts count %s" % len(pkts))
            pkt = pkts[0]
            pytest_assert(pkt.dst == target_mac, "Unexpected dst mac %s" % pkt.dst)
            pytest_assert(pkt.src == dut_mac, "Unexpected src mac %s" % pkt.src)
            pytest_assert(pkt.type == ETHER_TYPE_WOL_DEC)
            pytest_assert(pkt.load == build_magic_packet_payload(target_mac))

        duthost.shell("wol %s %s" % (random_vlan, target_mac))

        time.sleep(1)
        ptfhost.shell('killall tcpdump')
        time.sleep(1)

        ptf_int = 'eth' + str(dut_ptf_int_map[random_member_to_remove])
        with tempfile.NamedTemporaryFile() as temp_pcap:
            ptfhost.fetch(src=generate_pcap_file_path(ptf_int), dest=temp_pcap.name, flat=True)
            pytest_assert(len(scapy_sniff(offline=temp_pcap.name)) == 0)

        for member in random_vlan_members:
            ptf_int = 'eth' + str(dut_ptf_int_map[member])
            with tempfile.NamedTemporaryFile() as temp_pcap:
                ptfhost.fetch(src=generate_pcap_file_path(ptf_int), dest=temp_pcap.name, flat=True)
                validate_wol_packets(scapy_sniff(offline=temp_pcap.name))

    finally:
        duthost.add_member_to_vlan(vlan_n2i(random_vlan), random_member_to_remove, False)


def test_send_broadcast_to_single_interface(
    duthost,
    ptfhost,
    get_connected_dut_intf_to_ptf_index
):
    dut_mac = duthost.facts['router_mac']
    target_mac = "1a:2b:3c:d1:e2:f2"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))

    def validate_wol_packets(pkts):
        pytest_assert(len(pkts) == 1, "Unexpected pkts count %s" % len(pkts))
        pkt = pkts[0]
        pytest_assert(pkt.dst == BROADCAST_MAC, "Unexpected dst mac %s" % pkt.dst)
        pytest_assert(pkt.src == dut_mac, "Unexpected src mac %s" % pkt.src)
        pytest_assert(pkt.type == ETHER_TYPE_WOL_DEC)
        pytest_assert(pkt.load == build_magic_packet_payload(target_mac))

    with capture_and_check_packet_on_dut(
        duthost=ptfhost,
        interface='eth'+str(random_ptf_port),
        pkts_filter=WOL_ETHER_PKT_FILTER,
        pkts_validator=validate_wol_packets
    ):
        duthost.shell("wol %s %s -b" % (random_dut_port, target_mac))


@pytest.mark.parametrize("password", ["11:22:33:44:55:66", "192.168.0.1"])
def test_send_with_password(
    duthost,
    ptfhost,
    get_connected_dut_intf_to_ptf_index,
    password
):
    dut_mac = duthost.facts['router_mac']
    target_mac = "1a:2b:3c:d1:e2:f3"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))

    def validate_wol_packets(pkts):
        pytest_assert(len(pkts) == 1, "Unexpected pkts count %s" % len(pkts))
        pkt = pkts[0]
        pytest_assert(pkt.dst == target_mac, "Unexpected dst mac %s" % pkt.dst)
        pytest_assert(pkt.src == dut_mac, "Unexpected src mac %s" % pkt.src)
        pytest_assert(pkt.type == ETHER_TYPE_WOL_DEC)
        pytest_assert(pkt.load == build_magic_packet_payload(target_mac, password))

    with capture_and_check_packet_on_dut(
        duthost=ptfhost,
        interface='eth'+str(random_ptf_port),
        pkts_filter=WOL_ETHER_PKT_FILTER,
        pkts_validator=validate_wol_packets
    ):
        duthost.shell("wol %s %s -p %s" % (random_dut_port, target_mac, password))


@pytest.mark.parametrize("interval", [0, 2000])
@pytest.mark.parametrize("count", [2, 5])
def test_single_interface_with_count_and_interval(
    duthost,
    ptfhost,
    get_connected_dut_intf_to_ptf_index,
    interval,
    count
):
    dut_mac = duthost.facts['router_mac']
    target_mac = "1a:2b:3c:d1:e2:f4"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))

    def validate_wol_packets(pkts):
        pytest_assert(len(pkts) == count, "Unexpected pkts count %s" % len(pkts))
        last_time = None
        for pkt in pkts:
            pytest_assert(pkt.dst == target_mac, "Unexpected dst mac %s" % pkt.dst)
            pytest_assert(pkt.src == dut_mac, "Unexpected src mac %s" % pkt.src)
            pytest_assert(pkt.type == ETHER_TYPE_WOL_DEC)
            pytest_assert(pkt.load == build_magic_packet_payload(target_mac))
            if last_time:
                millseconds_gap = (pkt.time - last_time) * 1000
                pytest_assert(millseconds_gap > interval - 5 and millseconds_gap < interval + 5,
                              "Unexpected interval %s" % (millseconds_gap))

    with capture_and_check_packet_on_dut(
        duthost=ptfhost,
        interface='eth'+str(random_ptf_port),
        pkts_filter=WOL_ETHER_PKT_FILTER,
        pkts_validator=validate_wol_packets
    ):
        duthost.shell("wol %s %s -i %s -c %s" % (random_dut_port, target_mac, interval, count))


@pytest.mark.parametrize("interval", [0, 2000])
@pytest.mark.parametrize("count", [2, 5])
def test_send_to_vlan_with_count_and_interval(
    duthost,
    ptfhost,
    get_connected_dut_intf_to_ptf_index,
    loganalyzer,
    interval,
    count
):
    loganalyzer[duthost.hostname].ignore_regex.append(VLAN_MEMBER_CHANGE_ERR)
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    dut_ptf_int_map = dict(get_connected_dut_intf_to_ptf_index)
    connected_dut_intf = [dut_intf for dut_intf, _ in connected_dut_intf_to_ptf_index]
    dut_mac = duthost.facts['router_mac']
    target_mac = "1a:2b:3c:d1:e2:f5"
    vlan_brief = duthost.get_vlan_brief()
    vlan_names = list(vlan_brief.keys())
    random_vlan = random.choice(vlan_names)
    vlan_members = vlan_brief[random_vlan]['members']
    connected_vlan_members = [member for member in vlan_members if member in connected_dut_intf]
    random_member_to_remove = random.choice(connected_vlan_members)
    random_vlan_members = [member for member in connected_vlan_members if member != random_member_to_remove]
    logging.info("Test with random vlan %s, members %s and member to remove %s"
                 % (random_vlan, random_vlan_members, random_member_to_remove))

    duthost.del_member_from_vlan(vlan_n2i(random_vlan), random_member_to_remove)

    try:
        tcpdump_cmd = 'nohup tcpdump -i %s -w %s %s >/dev/null 2>&1 & echo $!' % \
            (random_member_to_remove, generate_pcap_file_path(random_member_to_remove), WOL_ETHER_PKT_FILTER)
        tcpdump_pid = ptfhost.shell(tcpdump_cmd)["stdout"]
        for member in random_vlan_members + [random_member_to_remove]:
            ptf_int = 'eth' + str(dut_ptf_int_map[member])
            tcpdump_cmd = 'nohup tcpdump -i %s -w %s %s >/dev/null 2>&1 & echo $!' % \
                (ptf_int, generate_pcap_file_path(ptf_int), WOL_ETHER_PKT_FILTER)
            tcpdump_pid = ptfhost.shell(tcpdump_cmd)["stdout"]
            cmd_check_if_process_running = "ps -p %s | grep %s |grep -v grep | wc -l" % (tcpdump_pid, tcpdump_pid)
            success = ptfhost.shell(cmd_check_if_process_running)["stdout"] == "1"
            if not success:
                ptfhost.shell('killall tcpdump', module_ignore_errors=True)
                pytest.fail("Failed to start tcpdump on %s" % member)

        def validate_wol_packets(pkts):
            pytest_assert(len(pkts) == count, "Unexpected pkts count %s" % len(pkts))
            last_time = None
            for pkt in pkts:
                pytest_assert(pkt.dst == target_mac, "Unexpected dst mac %s" % pkt.dst)
                pytest_assert(pkt.src == dut_mac, "Unexpected src mac %s" % pkt.src)
                pytest_assert(pkt.type == ETHER_TYPE_WOL_DEC)
                pytest_assert(pkt.load == build_magic_packet_payload(target_mac))
                if last_time:
                    millseconds_gap = (pkt.time - last_time) * 1000
                    pytest_assert(millseconds_gap > interval - 5 and millseconds_gap < interval + 5,
                                  "Unexpected interval %s" % (millseconds_gap))

        duthost.shell("wol %s %s -i %s -c %s" % (random_vlan, target_mac, interval, count))

        time.sleep(1)
        ptfhost.shell('killall tcpdump')
        time.sleep(1)

        ptf_int = 'eth' + str(dut_ptf_int_map[random_member_to_remove])
        with tempfile.NamedTemporaryFile() as temp_pcap:
            ptfhost.fetch(src=generate_pcap_file_path(ptf_int), dest=temp_pcap.name, flat=True)
            pytest_assert(len(scapy_sniff(offline=temp_pcap.name)) == 0)

        for member in random_vlan_members:
            ptf_int = 'eth' + str(dut_ptf_int_map[member])
            with tempfile.NamedTemporaryFile() as temp_pcap:
                ptfhost.fetch(src=generate_pcap_file_path(ptf_int), dest=temp_pcap.name, flat=True)
                validate_wol_packets(scapy_sniff(offline=temp_pcap.name))

    finally:
        duthost.add_member_to_vlan(vlan_n2i(random_vlan), random_member_to_remove, False)


def test_unicast_port(
    duthost,
    ptfhost,
    get_connected_dut_intf_to_ptf_index
):
    target_mac = "1a:2b:3c:d1:e2:f6"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))

    def validate_wol_packets(pkts):
        pytest_assert(len(pkts) == 1, "Unexpected pkts count %s" % len(pkts))
        pkt = pkts[0]
        pytest_assert(pkt.lladdrtype == LINK_LAYER_TYPE_ETHER, "Unexpected link layer type %s" % pkt.lladdrtype)
        pytest_assert(pkt.pkttype == PACKET_TYPE_UNICAST, "Unexpected packet type %s" % pkt.pkttype)
        pytest_assert(pkt.proto == ETHER_TYPE_WOL_DEC)
        pytest_assert(pkt.load == build_magic_packet_payload(target_mac))

    with capture_and_check_packet_on_dut(
        duthost=ptfhost,
        interface='any',
        pkts_filter=WOL_SLL_PKT_FILTER,
        pkts_validator=validate_wol_packets
    ):
        duthost.shell("wol %s %s" % (random_dut_port, target_mac))


def test_broadcast_port(
    duthost,
    ptfhost,
    get_connected_dut_intf_to_ptf_index
):
    target_mac = "1a:2b:3c:d1:e2:f7"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))

    def validate_wol_packets(pkts):
        pytest_assert(len(pkts) == 1, "Unexpected pkts count %s" % len(pkts))
        pkt = pkts[0]
        pytest_assert(pkt.lladdrtype == LINK_LAYER_TYPE_ETHER, "Unexpected link layer type %s" % pkt.lladdrtype)
        pytest_assert(pkt.pkttype == PACKET_TYPE_BROADCAST, "Unexpected packet type %s" % pkt.pkttype)
        pytest_assert(pkt.proto == ETHER_TYPE_WOL_DEC)
        pytest_assert(pkt.load == build_magic_packet_payload(target_mac))

    with capture_and_check_packet_on_dut(
        duthost=ptfhost,
        interface='any',
        pkts_filter=WOL_SLL_PKT_FILTER,
        pkts_validator=validate_wol_packets
    ):
        duthost.shell("wol %s %s -b" % (random_dut_port, target_mac))
