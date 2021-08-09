import pytest
import time
import logging

from collections import namedtuple

from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

pytestmark = [
    pytest.mark.topology('t1', 't2')
]


class NextHopGroup:
    """
    Create a list of next hop paths with given IP, MAC parameters
    """
    def __init__(self, asic, count, iface, ip="172.16", mac="C0:FF:EE:00"):
        IP_MAC = namedtuple('IP_MAC', 'ip mac')
        self.iface = iface
        self.arp_list = []
        self.asic = asic
        self.if_addr = "{}.0.3/16".format(ip)
        self.ip = None

        for i in range(11, count+11):
            moff1 = "{0:x}".format(i/255)
            moff2 = "{0:x}".format(i%255)

            ipoff1 = i / 255
            ipoff2 = i % 255
            self.arp_list.append(IP_MAC(
                "{}.{}.{}".format(ip, ipoff1, ipoff2),
                "{}:{}:{}".format(mac, moff1, moff2)
            ))

        ip_iface = "ip address add {} dev {}".format(self.if_addr, self.iface)

        logging.info("IF ADDR ADD {}".format(ip_iface))
        # add IP address to the eth interface
        result = asic.command(ip_iface)
        pytest_assert(result["rc"] == 0, ip_iface)

    def arps_add(self):
        arp_cmd = "arp -s {} {}"
        for ip_mac in self.arp_list:
            cmd = arp_cmd.format(ip_mac.ip, ip_mac.mac)
            result = self.asic.command(cmd)
            pytest_assert(result["rc"] == 0, cmd)

    def arps_del(self):
        arp_cmd = "arp -d {}"
        for ip_mac in self.arp_list:
            cmd = arp_cmd.format(ip_mac.ip)
            try:
                result = self.asic.command(cmd)
            except:
                pass

    def add_ip_route(self, ip="192.168.5.0/24"):
        self.arps_add()
        self.ip = ip
        ip_route = "ip route add {}".format(self.ip)
        ip_nhop = ""
        for ip_mac in self.arp_list:
            ip_nhop += "nexthop via {} ".format(ip_mac.ip)

        ip_cmd = "{} {}".format(ip_route, ip_nhop)
        logging.info("ROUTE ADD {}".format(ip_cmd))
        result = self.asic.command(ip_cmd)
        pytest_assert(result["rc"] == 0, ip_cmd)

    def clean_up(self):
        # delete ip route
        if self.ip:
            ip_route = "ip route del {}".format(self.ip)
            logging.info("ROUTE DEL {}".format(ip_route))
            try:
                self.asic.command(ip_route)
            except:
                pass

        # delete static ARPs
        self.arps_del()

        # del IP address from the eth interface
        ip_iface = "ip address del {} dev {}".format(self.if_addr, self.iface)
        logging.info("IF ADDR DEL {}".format(ip_iface))
        try:
            self.asic.command(ip_iface)
        except:
            pass


@pytest.mark.parametrize("nhop_path_count", [32])
def test_nhop(nhop_path_count, request, duthost):

    asic = duthost.asic_instance()
    ip_ifaces = asic.get_active_ip_interfaces().keys()
    pytest_assert(len(ip_ifaces), "No IP interfaces found")
    eth_if = ip_ifaces[0]

    logging.info("Adding next hops on {}".format(eth_if))
    marker = "NHOP TEST PATH COUNT {} {}".format(nhop_path_count, eth_if)
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker)
    marker = loganalyzer.init()
    loganalyzer.load_common_config()
    loganalyzer.expect_regex = []

    nhops = NextHopGroup(asic, nhop_path_count, eth_if)

    try:
        nhops.add_ip_route("192.168.5.0/24")
        # bake time to program in ASIC
        time.sleep(3)

    finally:
        nhops.clean_up()

    loganalyzer.analyze(marker)
