import binascii
import logging
import pytest
import time
import ipaddress
from socket import inet_aton
from scapy.all import Ether, UDP, Raw
from tests.common.helpers.assertions import pytest_assert
import ptf.testutils as testutils
from ptf.dataplane import match_exp_pkt

pytestmark = [
    pytest.mark.topology('mx'),
]

TARGET_MAC = "1a:2b:3c:d1:e2:f0"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
DEFAULT_PORT = 9
DEFAULT_IP = "255.255.255.255"
VLAN_MEMBER_CHANGE_ERR = r".*Failed to get port by bridge port ID .*"
TAC_CONNECTION_ERR = r".*audisp-tacplus: tac_connect_single: connection failed with .* is not connected"


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
    pytest.fail("invalid password {}".format(password))


def m2b(mac: str) -> bytes:
    """
        convert mac address to bytes
    """
    return binascii.unhexlify(mac.replace(':', ''))


def build_magic_packet_payload(target_mac: str = TARGET_MAC, password: str = "") -> bytes:
    return b'\xff' * 6 + m2b(target_mac) * 16 + p2b(password)


def get_packets_on_specified_ports(ptfadapter, verifier=None, ports=None, device_number=0, duration=1, timeout=None):
    """
    Get the packets on the specified ports and device for the specified duration
    """
    logging.info("Get pkts on device {}, port {}".format(device_number, ports))

    received_pkts_res = {}
    start_time = time.time()
    while (time.time() - start_time) < duration:
        result = testutils.dp_poll(ptfadapter, device_number=device_number, timeout=timeout)
        if isinstance(result, ptfadapter.dataplane.PollSuccess) and (ports is None or result.port in ports):
            if verifier is None or verifier(result.packet):
                if result.port in received_pkts_res:
                    received_pkts_res[result.port].append(result)
                else:
                    received_pkts_res[result.port] = [result]
    return received_pkts_res


def verify_packet(ptfadapter, verifier, port, count=1, interval=None, device_number=0, duration=1, timeout=None):
    verify_packets(ptfadapter, verifier, [port], count, interval, device_number, duration, timeout)


def verify_packets(ptfadapter, verifier, ports, count=1, interval=None, device_number=0, duration=1, timeout=None):
    received_pkts = get_packets_on_specified_ports(ptfadapter, verifier, None, device_number, duration, timeout)
    pytest_assert(set(received_pkts.keys()) == (set(ports) if count != 0 else set()),
                  "Received packets on ports other than {}: {}".format(ports, list(received_pkts.keys())))
    pytest_assert(all(map(lambda pkts: len(pkts) == count, received_pkts.values())),
                  "Did not receive exactly {} of expected packets on all {}: received {} total packets {}"
                  .format(count, ports, sum(map(len, received_pkts.values())), received_pkts))
    if count >= 2 and interval is not None:
        for results in received_pkts.values():
            ts = list(map(lambda result: result.time, results))
            ts_diff = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
            pytest_assert(all(map(lambda diff: abs(diff * 1000 - interval) < 100, ts_diff)),
                          "Unexpected interval {}".format(ts_diff))


def verify_packet_any(ptfadapter, verifier, ports, count=1, interval=None, device_number=0, duration=1, timeout=None):
    received_pkts = get_packets_on_specified_ports(ptfadapter, verifier, None, device_number, duration, timeout)
    pytest_assert(set(received_pkts.keys()).issubset(ports),
                  "Received packets on ports other than {}: {}".format(ports, list(received_pkts.keys())))
    pytest_assert(sum(map(len, received_pkts.values())) == count,
                  "Did not receive a total of exactly {} packets on any of {}: received {} total packets {}"
                  .format(count, ports, sum(map(len, received_pkts.values())), received_pkts))
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


def get_udp_verifier(dst_ip, dport, payload):
    def udp_verifier(pkt):
        try:
            pkt = Ether(pkt)
            return UDP in pkt and pkt[1].dst == dst_ip and pkt[2].dport == dport and pkt[3].load == payload
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


class TestWOLSendFromInterface:
    @pytest.mark.parametrize("count,interval", [(None, None), (3, 1000)])
    @pytest.mark.parametrize("password", [None, "11:22:33:44:55:66", "192.168.0.1"])
    @pytest.mark.parametrize("broadcast", [False, True])
    def test_wol_send_from_interface(
        self,
        duthost,
        ptfadapter,
        random_intf_pair,
        password,
        broadcast,
        count,
        interval,
    ):
        random_dut_intf, random_ptf_index = random_intf_pair

        payload = build_magic_packet_payload(password="" if password is None else password)
        exp_pkt = get_ether_pkt(duthost.facts["router_mac"], payload,
                                dst_mac=BROADCAST_MAC if broadcast else TARGET_MAC)

        duthost.shell(build_wol_cmd(random_dut_intf, password=password,
                      broadcast=broadcast, count=count, interval=interval))

        verify_packet(ptfadapter, lambda pkt: match_exp_pkt(exp_pkt, pkt),
                      random_ptf_index, count=1 if count is None else count,
                      interval=0 if interval is None else interval)

    def test_wol_send_from_interface_udp_no_ip(
        self,
        duthost,
        ptfadapter,
        loganalyzer,
        random_intf_pair,
    ):
        loganalyzer[duthost.hostname].ignore_regex.extend([VLAN_MEMBER_CHANGE_ERR, TAC_CONNECTION_ERR])

        random_dut_intf, random_ptf_index = random_intf_pair

        payload = build_magic_packet_payload()

        duthost.shell(build_wol_cmd(random_dut_intf) + " -u")

        verify_packet(ptfadapter, get_udp_verifier(DEFAULT_IP, DEFAULT_PORT, payload), random_ptf_index)

    @pytest.mark.parametrize("count,interval", [(None, None), (3, 1000)])
    @pytest.mark.parametrize("password", ["11:22:33:44:55:66", "192.168.0.1"])
    @pytest.mark.parametrize("dport", [5678])
    @pytest.mark.parametrize("dst_ip_intf", ["ipv4", "ipv6"], indirect=True)
    def test_wol_send_from_interface_udp(
        self,
        duthost,
        ptfadapter,
        loganalyzer,
        random_intf_pair_to_remove_under_vlan,
        dst_ip_intf,
        dport,
        password,
        count,
        interval,
    ):
        loganalyzer[duthost.hostname].ignore_regex.extend([VLAN_MEMBER_CHANGE_ERR, TAC_CONNECTION_ERR])

        random_dut_intf, random_ptf_index = random_intf_pair_to_remove_under_vlan

        payload = build_magic_packet_payload(password="" if password is None else password)

        duthost.shell(build_wol_cmd(random_dut_intf, dst_ip=dst_ip_intf, dport=dport, password=password,
                      count=count, interval=interval))

        verify_packet(ptfadapter, get_udp_verifier(dst_ip_intf, DEFAULT_PORT if dport is None else dport, payload),
                      random_ptf_index, count=1 if count is None else count,
                      interval=0 if interval is None else interval)


class TestWOLSendFromVlan:
    @pytest.mark.parametrize("count,interval", [(None, None), (3, 1000)])
    @pytest.mark.parametrize("password", [None, "11:22:33:44:55:66", "192.168.0.1"])
    def test_wol_send_from_vlan(
        self,
        duthost,
        ptfadapter,
        loganalyzer,
        random_vlan,
        random_intf_pair_to_remove_under_vlan,
        remaining_intf_pair_under_vlan,
        password,
        count,
        interval,
    ):
        loganalyzer[duthost.hostname].ignore_regex.extend([VLAN_MEMBER_CHANGE_ERR, TAC_CONNECTION_ERR])

        payload = build_magic_packet_payload(password="" if password is None else password)
        exp_pkt = get_ether_pkt(duthost.facts["router_mac"], payload)

        duthost.shell(build_wol_cmd(random_vlan, password=password,
                      count=count, interval=interval))

        remaining_ptf_index_under_vlan = list(map(lambda item: item[1], remaining_intf_pair_under_vlan))
        verify_packets(ptfadapter, lambda pkt: match_exp_pkt(exp_pkt, pkt),
                       remaining_ptf_index_under_vlan, count=1 if count is None else count,
                       interval=0 if interval is None else interval)

    def test_wol_send_from_vlan_udp_no_ip(
        self,
        duthost,
        ptfadapter,
        loganalyzer,
        random_vlan,
        random_intf_pair_to_remove_under_vlan,
        remaining_intf_pair_under_vlan,
    ):
        loganalyzer[duthost.hostname].ignore_regex.extend([VLAN_MEMBER_CHANGE_ERR, TAC_CONNECTION_ERR])

        payload = build_magic_packet_payload()

        duthost.shell(build_wol_cmd(random_vlan) + " -u")

        remaining_ptf_index_under_vlan = list(map(lambda item: item[1], remaining_intf_pair_under_vlan))
        verify_packets(ptfadapter, get_udp_verifier(DEFAULT_IP, DEFAULT_PORT, payload), remaining_ptf_index_under_vlan)

    @pytest.mark.parametrize("count,interval", [(None, None), (3, 1000)])
    @pytest.mark.parametrize("password", ["11:22:33:44:55:66", "192.168.0.1"])
    @pytest.mark.parametrize("dport", [5678])
    @pytest.mark.parametrize("dst_ip_vlan", ["ipv4", "ipv6"], indirect=True)
    def test_wol_send_from_vlan_udp(
        self,
        duthost,
        ptfadapter,
        loganalyzer,
        random_vlan,
        random_intf_pair_to_remove_under_vlan,
        remaining_intf_pair_under_vlan,
        dst_ip_vlan,
        dport,
        password,
        count,
        interval,
    ):
        loganalyzer[duthost.hostname].ignore_regex.extend([VLAN_MEMBER_CHANGE_ERR, TAC_CONNECTION_ERR])

        payload = build_magic_packet_payload(password="" if password is None else password)

        duthost.shell(build_wol_cmd(random_vlan, dst_ip=dst_ip_vlan, dport=dport, password=password,
                      count=count, interval=interval))

        remaining_ptf_index_under_vlan = list(map(lambda item: item[1], remaining_intf_pair_under_vlan))
        if isinstance(ipaddress.ip_address(dst_ip_vlan), ipaddress.IPv6Address):
            verify_packet_any(ptfadapter, get_udp_verifier(dst_ip_vlan, dport if dport else DEFAULT_PORT, payload),
                              remaining_ptf_index_under_vlan, count=1 if count is None else count,
                              interval=0 if interval is None else interval)
        else:
            verify_packets(ptfadapter, get_udp_verifier(dst_ip_vlan, dport if dport else DEFAULT_PORT, payload),
                           remaining_ptf_index_under_vlan, count=1 if count is None else count,
                           interval=0 if interval is None else interval)


def verify_invalid_wol_cmd(duthost, wol_cmd, exp_err_msgs):
    result = duthost.shell(wol_cmd, module_ignore_errors=True)

    pytest_assert(result["failed"], "WOL did not fail as expected")
    pytest_assert(any(map(lambda msg: msg in result["stderr"], exp_err_msgs)),
                  "Unexpected error: {}".format(result["stderr"]))
    pytest_assert(result["rc"] == 2, "Unexpected rc: {}".format(result["rc"]))


def test_wol_invalid_interface(
    duthost,
):
    invalid_interface = "Ethernet999"
    verify_invalid_wol_cmd(duthost, build_wol_cmd(invalid_interface, broadcast=True),
                           ["invalid SONiC interface name {}".format(invalid_interface)])


def test_wol_down_interface(
    duthost,
    random_intf_pair_down,
):
    random_dut_intf, random_ptf_index = random_intf_pair_down
    verify_invalid_wol_cmd(duthost, build_wol_cmd(random_dut_intf, broadcast=True),
                           ["interface {} is not up".format(random_dut_intf)])


@pytest.mark.parametrize("password", ["192.168.0.256", "q1:11:22:33:44:55"])
def test_wol_parameter_invalid_password(
    duthost,
    random_intf_pair,
    password,
):
    random_dut_intf, random_ptf_index = random_intf_pair
    verify_invalid_wol_cmd(duthost, build_wol_cmd(random_dut_intf, password=password, broadcast=True),
                           ["invalid password",
                            "invalid value '{}' for '--password <PASSWORD>'".format(password)])


def test_wol_parameter_invalid_mac(
    duthost,
    random_intf_pair,
):
    random_dut_intf, random_ptf_index = random_intf_pair
    invalid_mac = "1a:2b:3c:d1:e2:fq"
    verify_invalid_wol_cmd(duthost, build_wol_cmd(random_dut_intf, target_mac=invalid_mac, broadcast=True),
                           ["Invalid value for \"TARGET_MAC\": invalid MAC address 1a:2b:3c:d1:e2:fq",
                            "Invalid MAC address"])


def test_wol_parameter_invalid_interval(
    duthost,
    random_intf_pair,
):
    random_dut_intf, random_ptf_index = random_intf_pair
    invalid_interval = "2001"
    verify_invalid_wol_cmd(duthost,
                           build_wol_cmd(random_dut_intf, broadcast=True, count="2", interval=invalid_interval),
                           ["Invalid value for \"-i\": 2001 is not in the valid range of 0 to 2000.",
                            "Invalid value for \"INTERVAL\": interval must between 0 and 2000"])


def test_wol_parameter_invalid_count(
    duthost,
    random_intf_pair,
):
    random_dut_intf, random_ptf_index = random_intf_pair
    invalid_count = "10"
    verify_invalid_wol_cmd(duthost,
                           build_wol_cmd(random_dut_intf, broadcast=True, count=invalid_count, interval="1000"),
                           ["Invalid value for \"-c\": 10 is not in the valid range of 1 to 5.",
                            "Invalid value for \"COUNT\": count must between 1 and 5"])


def test_wol_parameter_constraint_of_count_and_interval(
    duthost,
    random_intf_pair,
):
    random_dut_intf, random_ptf_index = random_intf_pair
    verify_invalid_wol_cmd(duthost, build_wol_cmd(random_dut_intf, broadcast=True, count="2"),
                           ["count and interval must be used together",
                            "required arguments were not provided"])
    verify_invalid_wol_cmd(duthost, build_wol_cmd(random_dut_intf, broadcast=True, interval="1000"),
                           ["count and interval must be used together",
                            "required arguments were not provided"])


class TestWOLParameter:
    @pytest.mark.parametrize("dport", [None, 5678])
    @pytest.mark.parametrize("dst_ip_intf", [None, "ipv4", "ipv6"], indirect=True)
    def test_wol_parameter_constraint_of_udp(
        self,
        duthost,
        loganalyzer,
        random_intf_pair_to_remove_under_vlan,
        dst_ip_intf,
        dport,
    ):
        loganalyzer[duthost.hostname].ignore_regex.extend([VLAN_MEMBER_CHANGE_ERR, TAC_CONNECTION_ERR])

        random_dut_intf, random_ptf_index = random_intf_pair_to_remove_under_vlan

        invalid_wol_cmd = build_wol_cmd(random_dut_intf)
        if dst_ip_intf:
            invalid_wol_cmd += " --ip-address {}".format(dst_ip_intf)
        if dport:
            invalid_wol_cmd += " --udp-port {}".format(dport)
        if dst_ip_intf or dport:
            verify_invalid_wol_cmd(duthost, invalid_wol_cmd,
                                   ["required arguments were not provided"])

    @pytest.mark.parametrize("dport", [None, 5678])
    @pytest.mark.parametrize("dst_ip_intf", ["ipv4", "ipv6"], indirect=True)
    def test_wol_parameter_udp_with_broadcast(
        self,
        duthost,
        loganalyzer,
        random_intf_pair_to_remove_under_vlan,
        dst_ip_intf,
        dport,
    ):
        loganalyzer[duthost.hostname].ignore_regex.extend([VLAN_MEMBER_CHANGE_ERR, TAC_CONNECTION_ERR])

        random_dut_intf, random_ptf_index = random_intf_pair_to_remove_under_vlan

        invalid_wol_cmd = build_wol_cmd(random_dut_intf, dst_ip=dst_ip_intf, dport=dport, broadcast=True)

        verify_invalid_wol_cmd(duthost, invalid_wol_cmd,
                               ["the argument '--udp' cannot be used with '--broadcast'"])
