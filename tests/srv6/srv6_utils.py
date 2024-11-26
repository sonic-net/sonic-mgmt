import logging
import time
import requests
from scapy.layers.inet6 import IPv6ExtHdrSegmentRouting
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask
from ptf.packet import Ether, Dot1Q, IP, IPv6, UDP
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

#
# log directory inside each vsonic. vsonic starts with admin as user.
#
test_log_dir = "/home/admin/testlogs/"


class MaskException(Exception):
    """Generic Mask Exception"""
    pass


class MyMask(Mask):

    def __init__(self, exp_pkt, ignore_extra_bytes=False, dont_care_all=False):
        Mask.__init__(self, exp_pkt, ignore_extra_bytes)
        if dont_care_all:
            self.mask = [0] * self.size

    def set_care_all(self):
        self.mask = [0xFF] * self.size

    def set_care(self, offset, bitwidth):
        # logger.info("zzz set_care offset:{} bitwidth:{}".format(offset, bitwidth))
        for idx in range(offset, offset + bitwidth):
            offsetB = idx // 8
            offsetb = idx % 8
            self.mask[offsetB] = self.mask[offsetB] | (1 << (7 - offsetb))

    def set_care_packet(self, hdr_type, field_name):
        if hdr_type not in self.exp_pkt:
            self.valid = False
            raise MaskException("Unknown header type")

        try:
            fields_desc = [
                field
                for field in hdr_type.fields_desc
                if field.name
                in self.exp_pkt[hdr_type]
                .__class__(bytes(self.exp_pkt[hdr_type]))
                .fields.keys()
            ]  # build & parse packet to be sure all fields are correctly filled
        except Exception:  # noqa
            self.valid = False
            raise MaskException("Can not build or decode Packet")

        if field_name not in [x.name for x in fields_desc]:
            self.valid = False
            raise MaskException(
                "Field %s does not exist in frame" % field_name)

        hdr_offset = self.size - len(self.exp_pkt[hdr_type])
        offset = 0
        bitwidth = 0
        for f in fields_desc:
            try:
                bits = f.size
            except Exception:  # noqa
                bits = 8 * f.sz
            if f.name == field_name:
                bitwidth = bits
                break
            else:
                offset += bits
        self.set_care(hdr_offset * 8 + offset, bitwidth)


#
# Helper func for print a set of lines
#
def print_lines(outlines):
    for line in outlines:
        logger.debug(line)


#
# Util functions for announce / withdraw routes from ptf docker.
#
def announce_route(ptfip, neighbor, route, nexthop, port):
    change_route("announce", ptfip, neighbor, route, nexthop, port)


def withdraw_route(ptfip, neighbor, route, nexthop, port):
    change_route("withdraw", ptfip, neighbor, route, nexthop, port)


def change_route(operation, ptfip, neighbor, route, nexthop, port):
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "neighbor %s %s route %s next-hop %s" %
            (neighbor, operation, route, nexthop)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


#
# Skip some BGP neighbor check
#
def skip_bgp_neighbor_check(neighbor):
    skip_addresses = []
    for addr in skip_addresses:
        if neighbor == addr:
            return True

    return False


#
# Helper func to check if a list of BGP neighbors are up
#
def check_bgp_neighbors_func(nbrhost, neighbors, vrf=""):
    cmd = "vtysh -c 'show bgp summary'"
    if vrf != "":
        cmd = "vtysh -c 'show bgp vrf {} summary'".format(vrf)
    res = nbrhost.command(cmd)["stdout_lines"]
    found = 0
    for neighbor in neighbors:
        if skip_bgp_neighbor_check(neighbor):
            logger.debug("Skip {} check".format(neighbor))
            found = found + 1
            continue

        for line in res:
            if neighbor in line:
                arr = line.split()
                pfxrcd = arr[9]
                try:
                    int(pfxrcd)
                    found = found + 1
                    logger.debug(
                        "{} ==> BGP neighbor is up and gets pfxrcd {}".format(line, pfxrcd))
                except ValueError:
                    logger.debug(
                        "{} ==> BGP neighbor state {}, not up".format(line, pfxrcd))
    return len(neighbors) == found


#
# Checke BGP neighbors
#
def check_bgp_neighbors(nbrhost, neighbors, vrf=""):
    pytest_assert(check_bgp_neighbors_func(nbrhost, neighbors, vrf))


#
# Helper function to count number of Ethernet interfaces
#
def find_node_interfaces(nbrhost):
    cmd = "show version"
    res = nbrhost.command(cmd)["stdout_lines"]
    hwsku = ""
    for line in res:
        if "HwSKU:" in line:
            logger.debug("{}".format(line))
            sarr = line.split()
            hwsku = sarr[1]
            break

    cmd = "show interface status"
    res = nbrhost.command(cmd)["stdout_lines"]
    found = 0
    for line in res:
        logger.debug("{}".format(line))
        if "Ethernet" in line:
            found = found + 1

    return found, hwsku


#
# Send receive packets
#
def runSendReceive(pkt, src_port, exp_pkt, dst_ports, pkt_expected, ptfadapter):
    """
    @summary Send packet and verify it is received/not received on the expected ports
    @param pkt: The packet that will be injected into src_port
    @param src_ports: The port into which the pkt will be injected
    @param exp_pkt: The packet that will be received on one of the dst_ports
    @param dst_ports: The ports on which the exp_pkt may be received
    @param pkt_expected: Indicated whether it is expected to receive the exp_pkt on one of the dst_ports
    @param ptfadapter: The ptfadapter fixture
    """
    # Send the packet and poll on destination ports
    testutils.send(ptfadapter, src_port, pkt, 1)
    logger.debug("Sent packet: " + pkt.summary())
    (index, rcv_pkt) = testutils.verify_packet_any_port(
        ptfadapter, exp_pkt, dst_ports)
    received = False
    if rcv_pkt:
        received = True
    pytest_assert(received is True)
    logger.debug('index=%s, received=%s' % (str(index), str(received)))
    if received:
        logger.debug("Received packet: " + scapy.Ether(rcv_pkt).summary())
    if pkt_expected:
        logger.debug('Expected packet on dst_ports')
        passed = True if received else False
        logger.debug('Received: ' + str(received))
    else:
        logger.debug('No packet expected on dst_ports')
        passed = False if received else True
        logger.debug('Received: ' + str(received))
    logger.debug('Passed: ' + str(passed))
    return passed


#
# Helper func to check if a list of IPs go via a given set of next hop
#
def check_routes_func(nbrhost, ips, nexthops, vrf="", is_v6=False):
    # Check remote learnt dual homing routes
    vrf_str = ""
    if vrf != "":
        vrf_str = "vrf {}".format(vrf)
    ip_str = "ip"
    if is_v6:
        ip_str = "ipv6"
    for ip in ips:
        cmd = "show {} route {} {} nexthop-group".format(ip_str, vrf_str, ip)
        res = nbrhost.command(cmd)["stdout_lines"]
        print_lines(res)
        found = 0
        for nexthop in nexthops:
            for line in res:
                if nexthop in line:
                    found = found + 1
        if len(nexthops) != found:
            return False
    return True


#
# check if a list of IPs go via a given set of next hop
#
def check_routes(nbrhost, ips, nexthops, vrf="", is_v6=False):
    # Add retry for debugging purpose
    count = 0
    ret = False

    #
    # Sleep 10 sec before retrying
    #
    sleep_duration_for_retry = 10

    # retry 3 times before claiming failure
    while count < 3 and not ret:
        ret = check_routes_func(nbrhost, ips, nexthops, vrf, is_v6)
        if not ret:
            count = count + 1
            # sleep make sure all forwarding structures are settled down.
            time.sleep(sleep_duration_for_retry)
            logger.info("Sleep {} seconds to retry round {}".format(
                sleep_duration_for_retry, count))

    pytest_assert(ret)


#
# Record fwding chain to a file
#
def recording_fwding_chain(nbrhost, fname, comments):

    filename = "{}{}".format(test_log_dir, fname)

    cmd = "mkdir -p {}".format(test_log_dir)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "sudo touch /etc/sonic/frr/vtysh.conf"
    nbrhost.shell(cmd, module_ignore_errors=True)

    cmd = "date >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "echo ' {}' >> {} ".format(comments, filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show bgp summary' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show ip route vrf Vrf1 192.100.1.0 nexthop-group' >> {} ".format(
        filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show ipv6 route fd00:201:201:fff1:11:: nexthop-group' >> {} ".format(
        filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show ipv6 route fd00:202:202:fff2:22:: nexthop-group' >> {} ".format(
        filename)
    nbrhost.shell(cmd, module_ignore_errors=True)

    cmd = "echo '' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)


#
# Debug commands for FRR zebra
#
debug_cmds = [
    'debug zebra events',
    'debug zebra rib',
    'debug zebra rib detailed',
    'debug zebra nht',
    'debug zebra nht detailed',
    'debug zebra dplane',
    'debug zebra nexthop',
    'debug zebra nexthop detail',
    'debug zebra packet',
    'debug zebra packet detail'
]


#
# Turn on/off FRR debug to a file
#
def turn_on_off_frr_debug(duthosts, rand_one_dut_hostname, nbrhosts, filename, vm, is_on=True):
    nbrhost = nbrhosts[vm]['host']
    # save frr log to a file
    pfxstr = " "
    if not is_on:
        pfxstr = " no "

    cmd = "vtysh -c 'configure terminal' -c '{} log file {}'".format(
        pfxstr, filename)
    nbrhost.command(cmd)

    #
    # Change frr debug flags
    #
    for dcmd in debug_cmds:
        cmd = "vtysh -c '" + pfxstr + dcmd + "'"
        nbrhost.command(cmd)

    #
    # Check debug flags
    #
    cmd = "vtysh -c 'show debug'"
    nbrhost.shell(cmd, module_ignore_errors=True)
    #
    # Check log file
    #
    cmd = "vtysh -c 'show run' | grep log"
    nbrhost.shell(cmd, module_ignore_errors=True)


#
# Collect file from bgp docker
#
def collect_frr_debugfile(duthosts, rand_one_dut_hostname, nbrhosts, filename, vm):
    nbrhost = nbrhosts[vm]['host']
    cmd = "mkdir -p {}".format(test_log_dir)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "docker cp bgp:{} {}".format(filename, test_log_dir)
    nbrhost.shell(cmd, module_ignore_errors=True)


def reset_topo_pkt_counter(ptfadapter):
    ptfadapter.dataplane.flush()


def check_topo_recv_pkt_raw(ptfadapter, port=0, dst_ip="", dscp=0, no_packet=False, no_vlan=True, validateDSCP=True):
    # port info is fixed and also define and used in trex_agent.py
    if no_vlan is False:
        if "." in dst_ip:
            pkt_base = Ether()/Dot1Q()/IP(dst=dst_ip, tos=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"
        else:
            pkt_base = Ether()/Dot1Q()/IPv6(dst=dst_ip, tc=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"
    else:
        if "." in dst_ip:
            pkt_base = Ether()/IP(dst=dst_ip, tos=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"
        else:
            pkt_base = Ether()/IPv6(dst=dst_ip, tc=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"

    mask = MyMask(pkt_base, ignore_extra_bytes=True, dont_care_all=True)
    # mask.set_do_not_care_scapy(scapy.Ether, 'dst')
    # mask.set_do_not_care_scapy(scapy.Ether, 'src')
    # mask.set_do_not_care_scapy(scapy.Dot1Q, 'vlan')
    # mask.set_do_not_care_scapy(scapy.IP, "ihl")
    # mask.set_do_not_care_scapy(scapy.IP, "tos")
    # mask.set_do_not_care_scapy(scapy.IP, "len")
    # mask.set_do_not_care_scapy(scapy.IP, "id")
    # mask.set_do_not_care_scapy(scapy.IP, "flags")
    # mask.set_do_not_care_scapy(scapy.IP, "frag")

    # mask.set_do_not_care_scapy(scapy.IP, "ttl")
    # mask.set_do_not_care_scapy(scapy.IP, "src")
    # mask.set_do_not_care_scapy(scapy.IP, "chksum")
    # mask.set_do_not_care_scapy(scapy.UDP, "chksum")
    # mask.set_do_not_care_scapy(scapy.UDP, "len")
    # mask.set_do_not_care_scapy(scapy.IP, "dst")
    if "." in dst_ip:
        if validateDSCP:
            mask.set_care_packet(scapy.IP, "tos")
        mask.set_care_packet(scapy.IP, "dst")
        mask.set_care_packet(scapy.UDP, "dport")
        mask.set_care_packet(scapy.UDP, "sport")
    else:
        if validateDSCP:
            mask.set_care_packet(scapy.IPv6, "tc")
        mask.set_care_packet(scapy.IPv6, "dst")
        mask.set_care_packet(scapy.UDP, "dport")
        mask.set_care_packet(scapy.UDP, "sport")

    logger.debug("check_topo_recv_pkt_raw pkt_base: " + pkt_base.summary())

    if no_packet:
        # verify no packet is received on the exact port!
        testutils.verify_no_packet(ptfadapter, mask, port_id=port, timeout=2)
    else:
        # verify packet is received on the exact port!
        testutils.verify_packet(ptfadapter, mask, port_id=port, timeout=30)

    # (index, rcv_pkt) = testutils.verify_packet_any_port(ptfadapter, mask, ports=ptf_ports, timeout=1)
    # received = False
    # if rcv_pkt:
    #     received = True
    #     #poll more time to see
    #     cnt = testutils.count_matched_packets_all_ports(ptfadapter, mask, ports = ptf_ports, timeout=2)

    #     logger.debug(("index:{} tot_cnt_in_2s:{} rcv_pkt: {}").format(index, cnt+1, scapy.Ether(rcv_pkt).summary()))

    # return received


def check_topo_recv_pkt_vpn(ptfadapter, port=0, dst_ip="", dscp=0,
                            vpnsid="", no_packet=False, no_vlan=True, outer_sip=""):
    # udp port info is fixed and also define and used in trex_agent.py
    outer_src_ip6 = outer_sip if outer_sip != "" else "0::0"
    if no_vlan is False:
        if "." in dst_ip:
            pkt_base = Ether()/Dot1Q()/IPv6(src=outer_src_ip6, dst=vpnsid, nh=4) / \
                IP(dst=dst_ip, tos=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"
        else:
            pkt_base = Ether()/Dot1Q()/IPv6(src=outer_src_ip6, dst=vpnsid, nh=41) / \
                IPv6(dst=dst_ip, tc=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"
    else:
        if "." in dst_ip:
            pkt_base = Ether()/IPv6(src=outer_src_ip6, dst=vpnsid, nh=4) / \
                IP(dst=dst_ip, tos=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"
        else:
            pkt_base = Ether()/IPv6(src=outer_src_ip6, dst=vpnsid, nh=41) / \
                IPv6(dst=dst_ip, tc=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"

    mask = MyMask(pkt_base, ignore_extra_bytes=True, dont_care_all=True)
    ETH_H_LEN = 14
    VLAN_H_LEN = 4
    IP4_H_LEN = 20
    IP6_H_LEN = 40
    IP4_DST_OFFSET = 16
    IP6_SRC_OFFSET = 8
    IP6_DST_OFFSET = 24
    UDP_SPORT_OFFSET = 0
    UDP_DPORT_OFFSET = 2

    vlan_h_len = VLAN_H_LEN
    if no_vlan is True:
        vlan_h_len = 0

    if "." in dst_ip:
        # mask outer sip
        if outer_sip != "":
            mask.set_care((ETH_H_LEN + vlan_h_len + IP6_SRC_OFFSET)*8, 128)
        # mask outer dip
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_DST_OFFSET)*8, 128)
        # mask inner dip
        mask.set_care((ETH_H_LEN + vlan_h_len +
                      IP6_H_LEN + IP4_DST_OFFSET)*8, 32)
        # mask inner udp
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP4_H_LEN + UDP_SPORT_OFFSET)*8, 16)
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP4_H_LEN + UDP_DPORT_OFFSET)*8, 16)
    else:
        # mask outer sip
        if outer_sip != "":
            mask.set_care((ETH_H_LEN + vlan_h_len + IP6_SRC_OFFSET)*8, 128)
        # mask outer dip6
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_DST_OFFSET)*8, 128)
        # mask inner dip6
        mask.set_care((ETH_H_LEN + vlan_h_len +
                      IP6_H_LEN + IP6_DST_OFFSET)*8, 128)
        # mask inner udp
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + UDP_SPORT_OFFSET)*8, 16)
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + UDP_DPORT_OFFSET)*8, 16)

    logger.debug("check_topo_recv_pkt_vpn pkt_base: " + pkt_base.summary())

    if no_packet:
        # verify no packet is received on the exact port!
        testutils.verify_no_packet(ptfadapter, mask, port_id=port, timeout=2)
    else:
        # verify packet is received on the exact port!
        testutils.verify_packet(ptfadapter, mask, port_id=port, timeout=30)


# check that packet is recved on only one of the port
def check_topo_recv_pkt_vpn_one_port_only(ptfadapter, ports=[], dst_ip="", dscp=0,
                                          vpnsid="", no_vlan=True, outer_sip=""):
    # udp port info is fixed and also define and used in trex_agent.py
    outer_src_ip6 = outer_sip if outer_sip != "" else "0::0"
    if no_vlan is False:
        if "." in dst_ip:
            pkt_base = Ether()/Dot1Q()/IPv6(src=outer_src_ip6, dst=vpnsid, nh=4) / \
                IP(dst=dst_ip, tos=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"
        else:
            pkt_base = Ether()/Dot1Q()/IPv6(src=outer_src_ip6, dst=vpnsid, nh=41) / \
                IPv6(dst=dst_ip, tc=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"
    else:
        if "." in dst_ip:
            pkt_base = Ether()/IPv6(src=outer_src_ip6, dst=vpnsid, nh=4) / \
                IP(dst=dst_ip, tos=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"
        else:
            pkt_base = Ether()/IPv6(src=outer_src_ip6, dst=vpnsid, nh=41) / \
                IPv6(dst=dst_ip, tc=(dscp << 2)) / \
                UDP(dport=5000, sport=5001)/"data"

    mask = MyMask(pkt_base, ignore_extra_bytes=True, dont_care_all=True)
    ETH_H_LEN = 14
    VLAN_H_LEN = 4
    IP4_H_LEN = 20
    IP6_H_LEN = 40
    IP4_DST_OFFSET = 16
    IP6_SRC_OFFSET = 8
    IP6_DST_OFFSET = 24
    UDP_SPORT_OFFSET = 0
    UDP_DPORT_OFFSET = 2

    vlan_h_len = VLAN_H_LEN
    if no_vlan is True:
        vlan_h_len = 0

    if "." in dst_ip:
        # mask outer sip
        if outer_sip != "":
            mask.set_care((ETH_H_LEN + vlan_h_len + IP6_SRC_OFFSET)*8, 128)
        # mask outer dip
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_DST_OFFSET)*8, 128)
        # mask inner dip
        mask.set_care((ETH_H_LEN + vlan_h_len +
                      IP6_H_LEN + IP4_DST_OFFSET)*8, 32)
        # mask inner udp
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP4_H_LEN + UDP_SPORT_OFFSET)*8, 16)
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP4_H_LEN + UDP_DPORT_OFFSET)*8, 16)
    else:
        # mask outer sip
        if outer_sip != "":
            mask.set_care((ETH_H_LEN + vlan_h_len + IP6_SRC_OFFSET)*8, 128)
        # mask outer dip6
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_DST_OFFSET)*8, 128)
        # mask inner dip6
        mask.set_care((ETH_H_LEN + vlan_h_len +
                      IP6_H_LEN + IP6_DST_OFFSET)*8, 128)
        # mask inner udp
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + UDP_SPORT_OFFSET)*8, 16)
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + UDP_DPORT_OFFSET)*8, 16)

    logger.debug(
        "check_topo_recv_pkt_vpn_one_port_only pkt_base: " + pkt_base.summary())

    cnt = 0
    for port in ports:
        if cnt == 0:
            # !!this function blocks a long time depending on the packet num
            cnt = testutils.count_matched_packets(ptfadapter, mask, port)
            if cnt > 0:
                logger.debug(
                    "check_topo_recv_pkt_vpn_one_port_only recv pkt:{} on port:{} ".format(cnt, port))
            else:
                logger.debug(
                    "check_topo_recv_pkt_vpn_one_port_only recv pkt:0 on port:{} ".format(port))
        else:
            testutils.verify_no_packet(
                ptfadapter, mask, port_id=port, timeout=2)

    pytest_assert(cnt > 0)


def check_topo_recv_pkt_te(ptfadapter, port=0, dst_ip="", dscp=0, vpnsid="", segment="",
                           no_packet=False, no_vlan=True, outer_sip=""):
    # udp port info is fixed and also define and used in trex_agent.py
    outer_src_ip6 = outer_sip if outer_sip != "" else "0::0"
    if no_vlan is False:
        if "." in dst_ip:
            pkt_base = Ether()/Dot1Q()/IPv6(src=outer_src_ip6,
                                            dst=segment, nh=41)/IPv6(dst=vpnsid,
                                                                     nh=4)/IP(dst=dst_ip,
                                                                              tos=(dscp << 2))/UDP(dport=5000,
                                                                                                   sport=5001)/"data"
        else:
            pkt_base = Ether()/Dot1Q()/IPv6(src=outer_src_ip6,
                                            dst=segment, nh=41)/IPv6(dst=vpnsid,
                                                                     nh=41)/IPv6(dst=dst_ip,
                                                                                 tc=(dscp << 2))/UDP(dport=5000,
                                                                                                     sport=5001)/"data"
    else:
        if "." in dst_ip:
            pkt_base = Ether()/IPv6(src=outer_src_ip6,
                                    dst=segment, nh=41)/IPv6(dst=vpnsid,
                                                             nh=4)/IP(dst=dst_ip,
                                                                      tos=(dscp << 2))/UDP(dport=5000,
                                                                                           sport=5001)/"data"
        else:
            pkt_base = Ether()/IPv6(src=outer_src_ip6,
                                    dst=segment, nh=41)/IPv6(dst=vpnsid,
                                                             nh=41)/IPv6(dst=dst_ip,
                                                                         tc=(dscp << 2))/UDP(dport=5000,
                                                                                             sport=5001)/"data"

    mask = MyMask(pkt_base, ignore_extra_bytes=True, dont_care_all=True)
    ETH_H_LEN = 14
    VLAN_H_LEN = 4
    IP4_H_LEN = 20
    IP6_H_LEN = 40
    IP4_DST_OFFSET = 16
    IP6_SRC_OFFSET = 8
    IP6_DST_OFFSET = 24
    UDP_SPORT_OFFSET = 0
    UDP_DPORT_OFFSET = 2

    vlan_h_len = VLAN_H_LEN
    if no_vlan is True:
        vlan_h_len = 0

    if "." in dst_ip:
        # mask outer sip
        if outer_sip != "":
            mask.set_care((ETH_H_LEN + vlan_h_len + IP6_SRC_OFFSET)*8, 128)
        # mask te dip6
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_DST_OFFSET)*8, 128)
        # mask vpn dip6
        mask.set_care((ETH_H_LEN + vlan_h_len +
                      IP6_H_LEN + IP6_DST_OFFSET)*8, 128)

        # mask inner dip
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + IP4_DST_OFFSET)*8, 32)
        # mask inner udp
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + IP4_H_LEN + UDP_SPORT_OFFSET)*8, 16)
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + IP4_H_LEN + UDP_DPORT_OFFSET)*8, 16)
    else:
        # mask outer sip
        if outer_sip != "":
            mask.set_care((ETH_H_LEN + vlan_h_len + IP6_SRC_OFFSET)*8, 128)
        # mask te dip6
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_DST_OFFSET)*8, 128)
        # mask vpn dip6
        mask.set_care((ETH_H_LEN + vlan_h_len +
                      IP6_H_LEN + IP6_DST_OFFSET)*8, 128)

        # mask inner dip6
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + IP6_DST_OFFSET)*8, 128)
        # mask inner udp
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + IP6_H_LEN + UDP_SPORT_OFFSET)*8, 16)
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      IP6_H_LEN + IP6_H_LEN + UDP_DPORT_OFFSET)*8, 16)

    logger.debug("check_topo_recv_pkt_te pkt_base: " + pkt_base.summary())

    if no_packet:
        # verify no packet is received on the exact port!
        testutils.verify_no_packet(ptfadapter, mask, port_id=port, timeout=2)
    else:
        # verify packet is received on the exact port!
        testutils.verify_packet(ptfadapter, mask, port_id=port, timeout=30)


def check_topo_recv_pkt_srh_te(ptfadapter, port=0, dst_ip="", dscp=0, vpnsid="", segment="",
                               no_packet=False, no_vlan=True, outer_sip=""):
    # udp port info is fixed and also define and used in trex_agent.py
    outer_src_ip6 = outer_sip if outer_sip != "" else "0::0"
    if no_vlan is False:
        if "." in dst_ip:
            pkt_base = Ether()/Dot1Q()/IPv6(src=outer_src_ip6, dst=segment, nh=43)/IPv6ExtHdrSegmentRouting(
                addresses=[vpnsid], nh=4, segleft=1)/IP(dst=dst_ip, tos=(dscp << 2))/UDP(
                    dport=5000, sport=5001)/"data"
        else:
            pkt_base = Ether()/Dot1Q()/IPv6(src=outer_src_ip6, dst=segment, nh=43)/IPv6ExtHdrSegmentRouting(
                addresses=[vpnsid], nh=41, segleft=1)/IPv6(dst=dst_ip, tc=(dscp << 2))/UDP(
                    dport=5000, sport=5001)/"data"
    else:
        if "." in dst_ip:
            pkt_base = Ether()/IPv6(src=outer_src_ip6, dst=segment, nh=43)/IPv6ExtHdrSegmentRouting(addresses=[
                vpnsid], nh=4, segleft=1)/IP(dst=dst_ip, tos=(dscp << 2))/UDP(dport=5000, sport=5001)/"data"
        else:
            pkt_base = Ether()/IPv6(src=outer_src_ip6, dst=segment, nh=43)/IPv6ExtHdrSegmentRouting(addresses=[
                vpnsid], nh=41, segleft=1)/IPv6(dst=dst_ip, tc=(dscp << 2))/UDP(dport=5000, sport=5001)/"data"

    mask = MyMask(pkt_base, ignore_extra_bytes=True, dont_care_all=True)
    ETH_H_LEN = 14
    VLAN_H_LEN = 4
    IP4_H_LEN = 20
    IP6_H_LEN = 40
    IP4_DST_OFFSET = 16
    IP6_SRC_OFFSET = 8
    IP6_DST_OFFSET = 24
    SRH_H_LEN = 24
    SRH_ADDR_OFFSET = 8
    UDP_SPORT_OFFSET = 0
    UDP_DPORT_OFFSET = 2

    vlan_h_len = VLAN_H_LEN
    if no_vlan is True:
        vlan_h_len = 0

    if "." in dst_ip:
        # mask outer sip
        if outer_sip != "":
            mask.set_care((ETH_H_LEN + vlan_h_len + IP6_SRC_OFFSET)*8, 128)
        # mask te dip6
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_DST_OFFSET)*8, 128)
        # mask vpn dip6
        mask.set_care((ETH_H_LEN + vlan_h_len +
                      IP6_H_LEN + SRH_ADDR_OFFSET)*8, 128)

        # mask inner dip
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      SRH_H_LEN + IP4_DST_OFFSET)*8, 32)
        # mask inner udp
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      SRH_H_LEN + IP4_H_LEN + UDP_SPORT_OFFSET)*8, 16)
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      SRH_H_LEN + IP4_H_LEN + UDP_DPORT_OFFSET)*8, 16)
    else:
        # mask outer sip
        if outer_sip != "":
            mask.set_care((ETH_H_LEN + vlan_h_len + IP6_SRC_OFFSET)*8, 128)
        # mask te dip6
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_DST_OFFSET)*8, 128)
        # mask vpn dip6
        mask.set_care((ETH_H_LEN + vlan_h_len +
                      IP6_H_LEN + SRH_ADDR_OFFSET)*8, 128)

        # mask inner dip6
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      SRH_H_LEN + IP6_DST_OFFSET)*8, 128)
        # mask inner udp
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      SRH_H_LEN + IP6_H_LEN + UDP_SPORT_OFFSET)*8, 16)
        mask.set_care((ETH_H_LEN + vlan_h_len + IP6_H_LEN +
                      SRH_H_LEN + IP6_H_LEN + UDP_DPORT_OFFSET)*8, 16)

    logger.debug("check_topo_recv_pkt_srh_te pkt_base: " + pkt_base.summary())

    if no_packet:
        # verify no packet is received on the exact port!
        testutils.verify_no_packet(ptfadapter, mask, port_id=port, timeout=2)
    else:
        # verify packet is received on the exact port!
        testutils.verify_packet(ptfadapter, mask, port_id=port, timeout=30)
