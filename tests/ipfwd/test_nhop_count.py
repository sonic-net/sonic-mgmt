import os
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
    def __init__(
        self, duthost, asic, count, iface, ip="172.16", mac="C0:FF:EE:00"
    ):
        IP_MAC = namedtuple('IP_MAC', 'ip mac')
        self.iface = iface
        self.arp_list = []
        self.duthost = duthost
        self.asic = asic
        self.if_addr = "{}.0.3/16".format(ip)
        self.ip = None
        self.fileloc = os.path.join(os.path.sep, "tmp")
        self.filename = os.path.join(self.fileloc, "static_arp.sh")

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
        """
        Create a file with static arp add commands, copy file
        to DUT and run it from DUT
        """
        arp_cmd = "sudo {} arp -s {} {}"
        with open(self.filename, "w") as fn:
            for ip_mac in self.arp_list:
                cmd = arp_cmd.format(self.asic.ns_arg, ip_mac.ip, ip_mac.mac)
                fn.write(cmd + "\n")

        self.duthost.copy(src=self.filename, dest=self.filename, mode=0755)
        result = self.duthost.shell(self.filename)
        pytest_assert(
            result["rc"] == 0,
            "arp add failed on duthost:{}".format(self.filename)
        )
        self.duthost.shell("rm {}".format(self.filename))

    def arps_del(self):
        """
        Create a file with static arp del commands, copy file
        to DUT and run it from DUT
        """
        arp_cmd = "sudo {} arp -d {}"
        with open(self.filename, "w") as fn:
            for ip_mac in self.arp_list:
                cmd = arp_cmd.format(self.asic.ns_arg, ip_mac.ip)
                fn.write(cmd + "\n")

        self.duthost.copy(src=self.filename, dest=self.filename, mode=0755)
        try:
            self.duthost.shell(self.filename)
            self.duthost.shell("rm {}".format(self.filename))
        except:
            pass

        os.remove(self.filename)

    def add_ip_route(self, ip="192.168.5.0/24"):
        """
        Add IP route with ECMP paths via 'vtysh' command
        """
        self.arps_add()
        self.ip = ip
        vty_cmd = "-c 'config term'"

        for ip_mac in self.arp_list:
            vty_cmd += " -c 'ip route {} {}'".format(self.ip, ip_mac.ip)

        vty_cmd += " -c 'exit'"

        result = self.asic.run_vtysh(vty_cmd)
        pytest_assert(
            result["rc"] == 0, "Route add failed:{}".format(vty_cmd)
        )

    def clean_up(self):
        # delete ip route
        if self.ip:
            vty_cmd = "-c 'config term'"

            for ip_mac in self.arp_list:
                vty_cmd += " -c 'no ip route {} {}'".format(self.ip, ip_mac.ip)

            vty_cmd += "-c 'exit'"
            logging.info("ROUTE DEL {}".format(vty_cmd))

            try:
                self.asic.run_vtysh(vty_cmd)
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

def test_nhop(request, duthost):

    default_max_nhop_paths = 32
    nhop_group_limit = 512

    asic = duthost.asic_instance()

    # find out MAX NHOP group count supported on the platform
    result = asic.run_redis_cmd(
        argv = ["redis-cli", "-n", 6, "HGETALL", "SWITCH_CAPABILITY|switch"]
    )
    it = iter(result)
    switch_capability = dict(zip(it, it))
    max_nhop = switch_capability.get("MAX_NEXTHOP_GROUP_COUNT")
    max_nhop = default_max_nhop_paths if max_nhop == None else int(max_nhop)
    nhop_group_count = min(max_nhop, nhop_group_limit)

    # find out any active IP port
    ip_ifaces = asic.get_active_ip_interfaces().keys()
    pytest_assert(len(ip_ifaces), "No IP interfaces found")
    eth_if = ip_ifaces[0]

    logging.info("Adding next hops on {}".format(eth_if))

    # intitialize log analyzer
    marker = "NHOP TEST PATH COUNT {} {}".format(nhop_group_count, eth_if)
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker)
    marker = loganalyzer.init()
    loganalyzer.load_common_config()
    loganalyzer.expect_regex = []

    # create nexthop group
    nhops = NextHopGroup(duthost, asic, nhop_group_count, eth_if)

    # add IP route with the next hop group created
    try:
        nhops.add_ip_route("192.168.5.0/24")
        # bake time to program in ASIC
        time.sleep(3)

    finally:
        nhops.clean_up()

    loganalyzer.analyze(marker)
