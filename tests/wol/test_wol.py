import binascii
import logging
import pytest
import random
import time
from socket import inet_aton
from scapy.all import Ether, UDP, Raw
from tests.common.utilities import capture_and_check_packet_on_dut
from tests.common.helpers.assertions import pytest_assert
import ptf.testutils as testutils
import ptf.dataplane as dataplane

pytestmark = [
    pytest.mark.topology('mx'),
]

WOL_SLL_PKT_FILTER = 'ether[14:2]==0x0842'
WOL_ETHER_PKT_FILTER = 'ether[12:2]==0x0842'
WOL_UDP_PKT_FILTER = 'udp[8:2]==0xffff and udp[10:2]==0xffff and udp[12:2]==0xffff'
TARGET_MAC = "1a:2b:3c:d1:e2:f0"
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


def build_magic_packet_payload(target_mac: str = TARGET_MAC, password: str = "") -> bytes:
    return b'\xff' * 6 + m2b(target_mac) * 16 + p2b(password)


def get_packets_on_specified_ports(ptfadapter, verifier=None, ports=None, device_number=0, duration=1, timeout=0.2):
    """
    Get the packets on the specified ports and device for the specified duration
    """
    logging.info("Get pkts on device %d, port %r", device_number, ports)

    received_pkts_res = {}
    start_time = time.time()
    while (time.time() - start_time) < duration:
        result = testutils.dp_poll(ptfadapter, device_number=device_number, timeout=timeout)
        logging.info(result)
        if isinstance(result, ptfadapter.dataplane.PollSuccess) and (ports is None or result.port in ports):
            if verifier is None or verifier(result.packet):
                if result.port in received_pkts_res:
                    received_pkts_res[result.port].append(result)
                else:
                    received_pkts_res[result.port] = [result]
    return received_pkts_res


def verify_packet(ptfadapter, verifier, port, count=1, interval=None, device_number=0, duration=1, timeout=0.2):
    verify_packets(ptfadapter, verifier, [port], count, interval, device_number, duration, timeout)


def verify_packets(ptfadapter, verifier, ports, count=1, interval=None, device_number=0, duration=1, timeout=0.2):
    received_pkts = get_packets_on_specified_ports(ptfadapter, verifier, None, device_number, duration, timeout)
    pytest_assert(set(received_pkts.keys()) == (set(ports) if count != 0 else set()),
                  "Received packets on ports other than {}".format(ports))
    pytest_assert(all(map(lambda pkts: len(pkts) == count, received_pkts.values())),
                  "Did not receive exactly {} of expected packets on all {}".format(count, ports))
    if count >= 2 and interval is not None:
        for results in received_pkts.values():
            ts = list(map(lambda result: result.time, results))
            ts_diff = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
            pytest_assert(all(map(lambda diff: abs(diff * 1000 - interval) < 5, ts_diff)),
                          "Unexpected interval {}".format(ts_diff))


def verify_packet_any(ptfadapter, verifier, ports, count=1, interval=None, device_number=0, duration=1, timeout=0.2):
    received_pkts = get_packets_on_specified_ports(ptfadapter, verifier, None, device_number, duration, timeout)
    pytest_assert(set(received_pkts.keys()).issubset(ports),
                  "Received packets on ports other than {}".format(ports))
    pytest_assert(sum(map(lambda pkts: len(pkts), received_pkts.values())) == count,
                  "Did not receive a total of exactly {} packets on any of {}".format(count, ports))
    if count >= 2 and interval is not None:
        ts = []
        for results in received_pkts.values():
            ts.extend(map(lambda result: result.time, results))
        ts = sorted(ts)
        ts_diff = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
        pytest_assert(all(map(lambda diff: abs(diff * 1000 - interval) < 5, ts_diff)),
                      "Unexpected interval {}".format(ts_diff))


def get_ether_pkt(src_mac, payload, dst_mac=TARGET_MAC):
    return Ether(src=src_mac, dst=dst_mac, type=0x0842) / Raw(load=payload)


def get_udp_verifier(dport, payload):
    def udp_verifier(pkt):
        try:
            pkt = Ether(pkt)
            return UDP in pkt and pkt[2].dport == dport and pkt[3].load == payload
        except Exception:
            return False
    return udp_verifier


def build_wol_cmd(intf, target_mac=TARGET_MAC, dst_ip=None, dport=None, password=None,
                  broadcast=False, count=None, interval=None):
    wol_cmd = "wol {} {}".format(intf, target_mac)
    if dst_ip is not None:
        wol_cmd += " -u --ip-address {}".format(dst_ip)
        if dport is not None:
            wol_cmd += " --udp-port {}".format(dport)
    if password is not None:
        wol_cmd += " --password {}".format(password)
    if broadcast:
        wol_cmd += " -b"
    if count is not None:
        wol_cmd += " --count {}".format(count)
    if interval is not None:
        wol_cmd += " --interval {}".format(interval)
    return wol_cmd


@pytest.mark.parametrize("interval", [None, 0, 2000])
@pytest.mark.parametrize("count", [None, 2, 5])
@pytest.mark.parametrize("broadcast", [False, True])
@pytest.mark.parametrize("password", [None, "11:22:33:44:55:66", "192.168.0.1"])
def test_send_to_single_specific_interface(
    duthost,
    ptfadapter,
    random_intf_pair,
    password,
    broadcast,
    count,
    interval,
):
    random_dut_intf, random_ptf_index = random_intf_pair

    payload = build_magic_packet_payload("" if password is None else password)
    exp_pkt = get_ether_pkt(duthost.facts["router_mac"], payload)

    duthost.shell(build_wol_cmd(random_dut_intf, password=password,
                  broadcast=broadcast, count=count, interval=interval))

    verify_packet(ptfadapter, lambda pkt: dataplane.match_exp_pkt(exp_pkt, pkt),
                  random_ptf_index, count=1 if count is None else count, interval=interval)


@pytest.mark.parametrize("interval", [None, 0, 2000])
@pytest.mark.parametrize("count", [None, 2, 5])
@pytest.mark.parametrize("password", [None, "11:22:33:44:55:66", "192.168.0.1"])
@pytest.mark.parametrize("dport", [None, 5678])
@pytest.mark.parametrize("dst_ip_intf", ["ipv4", "ipv6"], indirect=True)
def test_send_to_single_specific_interface_udp(
    duthost,
    ptfadapter,
    random_intf_pair_to_remove_under_vlan,
    dst_ip_intf,
    dport,
    password,
    count,
    interval,
):
    random_dut_intf, random_ptf_index = random_intf_pair_to_remove_under_vlan

    payload = build_magic_packet_payload("" if password is None else password)

    duthost.shell(build_wol_cmd(random_dut_intf, dst_ip=dst_ip_intf, dport=dport, password=password,
                  count=count, interval=interval))

    verify_packet(ptfadapter, get_udp_verifier(9 if dport is None else dport, payload),
                  random_ptf_index, count=1 if count is None else count, interval=interval)


@pytest.mark.parametrize("interval", [None, 0, 2000])
@pytest.mark.parametrize("count", [None, 2, 5])
@pytest.mark.parametrize("password", [None, "11:22:33:44:55:66", "192.168.0.1"])
def test_send_to_vlan(
    duthost,
    ptfadapter,
    random_vlan,
    random_intf_pair_to_remove_under_vlan,
    remaining_intf_pair_under_vlan,
    password,
    count,
    interval,
):
    payload = build_magic_packet_payload("" if password is None else password)
    exp_pkt = get_ether_pkt(duthost.facts["router_mac"], payload)

    duthost.shell(build_wol_cmd(random_vlan, password=password,
                  count=count, interval=interval))

    remaining_ptf_index_under_vlan = list(map(lambda item: item[1], remaining_intf_pair_under_vlan))
    verify_packets(ptfadapter, lambda pkt: dataplane.match_exp_pkt(exp_pkt, pkt),
                   remaining_ptf_index_under_vlan, count=1 if count is None else count, interval=interval)


@pytest.mark.parametrize("interval", [None, 0, 2000])
@pytest.mark.parametrize("count", [None, 2, 5])
@pytest.mark.parametrize("password", ["", "11:22:33:44:55:66", "192.168.0.1"])
@pytest.mark.parametrize("dport", [0, 5678])
@pytest.mark.parametrize("dst_ip_vlan", ["ipv4", "ipv6"], indirect=True)
def test_send_to_vlan_udp(
    duthost,
    ptfadapter,
    random_vlan,
    random_intf_pair_to_remove_under_vlan,
    remaining_intf_pair_under_vlan,
    dst_ip_vlan,
    dport,
    password,
    count,
    interval,
):
    payload = build_magic_packet_payload("" if password is None else password)

    duthost.shell(build_wol_cmd(random_vlan, dst_ip=dst_ip_vlan, dport=dport, password=password,
                  count=count, interval=interval))

    remaining_ptf_index_under_vlan = list(map(lambda item: item[1], remaining_intf_pair_under_vlan))
    verify_packet_any(ptfadapter, get_udp_verifier(dport if dport else 9, payload),
                      remaining_ptf_index_under_vlan, count=1 if count is None else count, interval=interval)


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
