import binascii
import logging
import pytest
import random
import tempfile
import time
from socket import inet_aton
from scapy.all import sniff as scapy_sniff
from scapy.all import Ether, UDP, Raw
from tests.common.utilities import capture_and_check_packet_on_dut
from tests.common.helpers.assertions import pytest_assert
import ptf.testutils as testutils

pytestmark = [
    pytest.mark.topology('mx'),
]

WOL_SLL_PKT_FILTER = 'ether[14:2]==0x0842'
WOL_ETHER_PKT_FILTER = 'ether[12:2]==0x0842'
WOL_UDP_PKT_FILTER = 'udp[8:2]==0xffff and udp[10:2]==0xffff and udp[12:2]==0xffff'
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


def get_packets_on_specified_ports(ptfadapter, verifier, ports, device_number=0, duration=1, timeout=0.2):
    """
    Get the packets on the specified ports and device for the specified duration
    """
    logging.info("Get pkts on device %d, port %r", device_number, ports)

    received_pkts_res = {}
    start_time = time.time()
    while (time.time() - start_time) < duration:
        result = testutils.dp_poll(ptfadapter, device_number=device_number, timeout=timeout)
        logging.info(result)
        if isinstance(result, ptfadapter.dataplane.PollSuccess) and result.port in ports:
            if verifier(result.packet):
                if result.port in received_pkts_res:
                    received_pkts_res[result.port].append(result)
                else:
                    received_pkts_res[result.port] = [result]
    return received_pkts_res


def verify_packet(ptfadapter, verifier, port, count=1, device_number=0, duration=1, timeout=0.2):
    received_pkts = get_packets_on_specified_ports(ptfadapter, verifier, [port], device_number, duration, timeout)
    pytest_assert(len(received_pkts) == (1 if count != 0 else 0),
                  "Received packets on ports other than {}".format(port))
    pytest_assert(len(received_pkts.get(port, [])) == count,
                  "Did not receive exactly {} of expected packets on port {}".format(count, port))


def verify_packets(ptfadapter, verifier, ports, count=1, device_number=0, duration=1, timeout=0.2):
    received_pkts = get_packets_on_specified_ports(ptfadapter, verifier, ports, device_number, duration, timeout)
    pytest_assert(set(received_pkts.keys()) == (set(ports) if count != 0 else set()),
                  "Received packets on ports other than {}".format(ports))
    pytest_assert(all(map(lambda pkts: len(pkts) == count, received_pkts.values())),
                  "Did not receive exactly {} of expected packets on all {}".format(count, ports))


@pytest.mark.parametrize("password", ["", "11:22:33:44:55:66", "192.168.0.1"])
@pytest.mark.parametrize("dport", [0, 5678])
@pytest.mark.parametrize("dst_ip", ["", "ipv4", "ipv6"], indirect=True)
def test_send_to_single_specific_interface(
    duthost,
    ptfadapter,
    random_intf_pair,
    dst_ip,
    dport,
    password,
):
    dut_mac = duthost.facts['router_mac']
    target_mac = "1a:2b:3c:d1:e2:f0"
    random_dut_intf, random_ptf_intf = random_intf_pair

    payload = build_magic_packet_payload(target_mac, password)

    pkt = Ether(src=dut_mac, dst=target_mac, type=0x0842)
    pkt /= Raw(load=payload)

    def udp_verifier(pkt):
        try:
            pkt = Ether(pkt)
            pkt_dport = dport if dport else 9
            return UDP in pkt and pkt[2].dport == pkt_dport and pkt[3].load == payload
        except Exception:
            return False

    wol_cmd = "wol {} {}".format(random_dut_intf, target_mac)
    if dst_ip:
        wol_cmd += " -u --ip-address {}".format(dst_ip)
        if dport:
            wol_cmd += " --udp-port {}".format(dport)
    if password:
        wol_cmd += " --password {}".format(password)
    duthost.shell(wol_cmd)

    if dst_ip:
        verify_packet(ptfadapter, udp_verifier, random_ptf_intf)
    else:
        testutils.verify_packet(ptfadapter, pkt, random_ptf_intf)


@pytest.mark.parametrize("dst_ip,dport", [("", ""), ("255.255.255.255", 0), ("::ffff:0:1", 5678)])
def test_send_to_vlan(
    duthost,
    ptfadapter,
    get_connected_dut_intf_to_ptf_index,
    dst_ip,
    dport,
    loganalyzer,
):
    loganalyzer[duthost.hostname].ignore_regex.append(VLAN_MEMBER_CHANGE_ERR)

    dut_ptf_int_map = dict(get_connected_dut_intf_to_ptf_index)
    connected_dut_intf = [dut_intf for dut_intf, _ in get_connected_dut_intf_to_ptf_index]
    dut_mac = duthost.facts['router_mac']
    target_mac = "1a:2b:3c:d1:e2:f1"

    vlan_brief = duthost.get_vlan_brief()
    vlan_names = list(vlan_brief.keys())
    random_vlan = random.choice(vlan_names)
    vlan_members = vlan_brief[random_vlan]['members']
    connected_vlan_members = list(filter(lambda member: member in connected_dut_intf, vlan_members))
    random_member_to_remove = connected_vlan_members.pop(random.randrange(len(connected_vlan_members)))
    connected_ptf_intf = list(map(lambda member: dut_ptf_int_map[member], connected_vlan_members))
    logging.info("Test with random vlan {}, members {} and member to remove {} to ip {} port {}"
                 .format(random_vlan, connected_vlan_members, random_member_to_remove, dst_ip, dport))

    pkt = Ether(src=dut_mac, dst=target_mac, type=0x0842)
    pkt /= Raw(load=build_magic_packet_payload(target_mac))

    def udp_verifier(pkt):
        try:
            pkt = Ether(pkt)
            pkt_dport = dport if dport else 9
            return UDP in pkt and pkt[2].dport == pkt_dport and pkt[3].load == build_magic_packet_payload(target_mac)
        except Exception:
            return False

    duthost.del_member_from_vlan(vlan_n2i(random_vlan), random_member_to_remove)

    wol_cmd = "wol {} {}".format(random_vlan, target_mac)
    if dst_ip:
        wol_cmd += " -u --ip-address {}".format(dst_ip)
    if dport:
        wol_cmd += " --udp-port {}".format(dport)
    duthost.shell(wol_cmd)

    if dst_ip:
        verify_packets(ptfadapter, udp_verifier, connected_ptf_intf)
    else:
        testutils.verify_packets(ptfadapter, pkt, connected_ptf_intf)
        testutils.verify_no_packet_any(ptfadapter, pkt, [dut_ptf_int_map[random_member_to_remove]])

    duthost.add_member_to_vlan(vlan_n2i(random_vlan), random_member_to_remove, False)


def test_send_broadcast_to_single_interface(
    duthost,
    ptfadapter,
    get_connected_dut_intf_to_ptf_index,
):
    dut_mac = duthost.facts['router_mac']
    target_mac = "1a:2b:3c:d1:e2:f0"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_intf, random_ptf_intf = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut intf {} and ptf intf index {}"
                 .format(random_dut_intf, random_ptf_intf))

    pkt = Ether(src=dut_mac, dst=BROADCAST_MAC, type=0x0842)
    pkt /= Raw(load=build_magic_packet_payload(target_mac))

    duthost.shell("wol {} {} -b".format(random_dut_intf, target_mac))

    testutils.verify_packet(ptfadapter, pkt, random_ptf_intf)


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


@pytest.mark.parametrize("password", ["192.168.0.256", "q1:11:22:33:44:55"])
def test_invalid_password(
    duthost,
    get_connected_dut_intf_to_ptf_index,
    password
):
    target_mac = "1a:2b:3c:d1:e2:f7"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))
    exception_catched = False
    try:
        duthost.shell("wol %s %s -b -p %s" % (random_dut_port, target_mac, password))
    except Exception as e:
        exception_catched = True
        pytest_assert("invalid password" in e.results['stderr'], "Unexpected exception %s" % str(e))
    pytest_assert(exception_catched, "No exception catched")


def test_invalid_mac(
    duthost,
    get_connected_dut_intf_to_ptf_index
):
    invalid_mac = "1a:2b:3c:d1:e2:fq"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))
    exception_catched = False
    try:
        duthost.shell("wol %s %s -b" % (random_dut_port, invalid_mac))
    except Exception as e:
        exception_catched = True
        pytest_assert(r'Invalid value for "TARGET_MAC": invalid MAC address 1a:2b:3c:d1:e2:fq' in e.results['stderr']
                      or r'Invalid MAC address' in e.results['stderr'],
                      "Unexpected exception %s" % str(e))
    pytest_assert(exception_catched, "No exception catched")


def test_invalid_interface(
    duthost
):
    target_mac = "1a:2b:3c:d1:e2:f8"
    invalid_interface = "Ethernet999"
    exception_catched = False
    try:
        duthost.shell("wol %s %s -b" % (invalid_interface, target_mac))
    except Exception as e:
        exception_catched = True
        pytest_assert(r'invalid SONiC interface name Ethernet999' in e.results['stderr'],
                      "Unexpected exception %s" % str(e))
    pytest_assert(exception_catched, "No exception catched")


def test_down_interface(
    duthost,
    get_connected_dut_intf_to_ptf_index
):
    target_mac = "1a:2b:3c:d1:e2:f9"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))

    duthost.shutdown(random_dut_port)

    exception_catched = False
    try:
        duthost.shell("wol %s %s -b" % (random_dut_port, target_mac))
    except Exception as e:
        exception_catched = True
        pytest_assert("interface %s is not up" % random_dut_port in e.results['stderr'],
                      "Unexpected exception %s" % str(e))
        pytest_assert(e.results['rc'] == 2, "Unexpected exception %s" % str(e))
    finally:
        duthost.no_shutdown(random_dut_port)
    pytest_assert(exception_catched, "No exception catched")


def test_invalid_interval(
    duthost,
    get_connected_dut_intf_to_ptf_index
):
    target_mac = "1a:2b:3c:d1:e2:fa"
    invalid_interval = "2001"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))
    exception_catched = False
    try:
        duthost.shell("wol %s %s -b -i %s" % (random_dut_port, target_mac, invalid_interval))
    except Exception as e:
        exception_catched = True
        pytest_assert(r'Invalid value for "-i": 2001 is not in the valid range of 0 to 2000.' in e.results['stderr']
                      or r'Invalid value for "INTERVAL": interval must between 0 and 2000' in e.results['stderr'],
                      "Unexpected exception %s" % str(e))
    pytest_assert(exception_catched, "No exception catched")


def test_invalid_count(
    duthost,
    get_connected_dut_intf_to_ptf_index
):
    target_mac = "1a:2b:3c:d1:e2:fb"
    invalid_count = "10"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))
    exception_catched = False
    try:
        duthost.shell("wol %s %s -b -c %s" % (random_dut_port, target_mac, invalid_count))
    except Exception as e:
        exception_catched = True
        pytest_assert(r'Invalid value for "-c": 10 is not in the valid range of 1 to 5.' in e.results['stderr'] or
                      r'Invalid value for "COUNT": count must between 1 and 5' in e.results['stderr'],
                      "Unexpected exception %s" % str(e))
    pytest_assert(exception_catched, "No exception catched")


def test_parameter_constrain_of_count_and_interval(
    duthost,
    get_connected_dut_intf_to_ptf_index
):
    target_mac = "1a:2b:3c:d1:e2:ee"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))
    exception_catched = False
    try:
        duthost.shell("wol %s %s -c 2" % (random_dut_port, target_mac))
    except Exception as e:
        exception_catched = True
        pytest_assert("count and interval must be used together" in e.results['stderr']
                      or "required arguments were not provided", "Unexpected exception %s" % str(e))
    pytest_assert(exception_catched, "No exception catched")

    exception_catched = False
    try:
        duthost.shell("wol %s %s -i 1000" % (random_dut_port, target_mac))
    except Exception as e:
        exception_catched = True
        pytest_assert("count and interval must be used together" in e.results['stderr']
                      or "required arguments were not provided", "Unexpected exception %s" % str(e))
    pytest_assert(exception_catched, "No exception catched")


def test_rc_2_invalid_parameter(
    duthost,
    get_connected_dut_intf_to_ptf_index
):
    target_mac = "1a:2b:3c:d1:e2:fb"
    invalid_count = "10"
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_port, random_ptf_port = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut port %s and ptf port index %s" % (random_dut_port, random_ptf_port))
    exception_catched = False
    try:
        duthost.shell("wol %s %s -b -c %s" % (random_dut_port, target_mac, invalid_count))
    except Exception as e:
        exception_catched = True
        pytest_assert(e.results['rc'] == 2, "Unexpected exception %s" % str(e))
    pytest_assert(exception_catched, "No exception catched")
