import ipaddr
import logging
import os
import pytest
import time

from collections import namedtuple

from tests.common.helpers.assertions import pytest_assert
from tests.common.mellanox_data import is_mellanox_device
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import skip_release

pytestmark = [
    pytest.mark.topology('t1', 't2')
]


class IPRoutes:
    """
    Program IP routes with next hops on to the DUT
    """
    def __init__(self, duthost, asic):
        self.arp_list = []
        self.asic = asic
        self.duthost = duthost

        fileloc = os.path.join(os.path.sep, "tmp")
        self.filename = os.path.join(fileloc, "static_ip.sh")
        self.ip_nhops = []
        self.IP_NHOP = namedtuple("IP_NHOP", "prefix nhop")

    def add_ip_route(self, ip_route, nhop_path_ips):
        """
        Add IP route with ECMP paths
        """
        # add IP route, nhop to list
        self.ip_nhops.append(self.IP_NHOP(ip_route, nhop_path_ips))

    def program_routes(self):
        """
        Create a file with static ip route add commands, copy file
        to DUT and run it from DUT
        """
        with open(self.filename, "w") as fn:
            for ip_nhop in self.ip_nhops:

                ip_route = "sudo {} ip route add {}".format(
                    self.asic.ns_arg, ip_nhop.prefix
                )
                ip_nhop_str = ""

                for ip in ip_nhop.nhop:
                    ip_nhop_str += "nexthop via {} ".format(ip)

                ip_cmd = "{} {}".format(ip_route, ip_nhop_str)
                fn.write(ip_cmd+ "\n")

        # copy file to DUT and run it on DUT
        self.duthost.copy(src=self.filename, dest=self.filename, mode=0755)
        result = self.duthost.shell(self.filename)
        pytest_assert(
            result["rc"] == 0,
           "IP add failed on duthost:{}".format(self.filename)
        )

    def delete_routes(self):
        """
        Create a file with static ip route del commands, copy file
        to DUT and run it from DUT
        """
        with open(self.filename, "w") as fn:
            for ip_nhop in self.ip_nhops:

                ip_route = "sudo {} ip route del {}".format(
                    self.asic.ns_arg, ip_nhop.prefix
                )
                fn.write(ip_route + "\n")

        self.duthost.copy(src=self.filename, dest=self.filename, mode=0755)
        try:
            self.duthost.shell(self.filename)
            self.duthost.shell("rm {}".format(self.filename))
            os.remove(self.filename)
        except:
            pass


class Arp:
    """
    Create IP interface and create a list of ARPs with given IP,
    MAC parameters
    """
    def __init__(
        self, duthost, asic, count, iface, ip=ipaddr.IPAddress("172.16.0.0"),
        mac="C0:FF:EE:00"
    ):
        IP_MAC = namedtuple("IP_MAC", "ip mac")
        self.iface = iface
        self.ip_mac_list = []
        self.duthost = duthost
        self.asic = asic
        self.if_addr = "{}/16".format(ip+3)

        fileloc = os.path.join(os.path.sep, "tmp")
        self.filename = os.path.join(fileloc, "static_arp.sh")

        # create a list of IP-MAC bindings
        for i in range(11, count+11):
            moff1 = "{0:x}".format(i/255)
            moff2 = "{0:x}".format(i%255)

            self.ip_mac_list.append(IP_MAC(
                "{}".format(ip + i),
                "{}:{}:{}".format(mac, moff1, moff2)
            ))

        # add IP address to the eth interface
        ip_iface = "ip address add {} dev {}".format(self.if_addr, self.iface)
        logging.info("IF ADDR ADD {}".format(ip_iface))
        result = asic.command(ip_iface)
        pytest_assert(result["rc"] == 0, ip_iface)

    def arps_add(self):
        """
        Create a file with static arp add commands, copy file
        to DUT and run it from DUT
        """
        arp_cmd = "sudo {} arp -s {} {}"
        with open(self.filename, "w") as fn:
            for ip_mac in self.ip_mac_list:
                cmd = arp_cmd.format(self.asic.ns_arg, ip_mac.ip, ip_mac.mac)
                fn.write(cmd + "\n")

        self.duthost.copy(src=self.filename, dest=self.filename, mode=0755)
        result = self.duthost.shell(self.filename)
        pytest_assert(
            result["rc"] == 0,
            "arp add failed on duthost:{}".format(self.filename)
        )

    def arps_del(self):
        """
        Create a file with static arp del commands, copy file
        to DUT and run it from DUT
        """
        arp_cmd = "sudo {} arp -d {}"
        with open(self.filename, "w") as fn:
            for ip_mac in self.ip_mac_list:
                cmd = arp_cmd.format(self.asic.ns_arg, ip_mac.ip)
                fn.write(cmd + "\n")

        self.duthost.copy(src=self.filename, dest=self.filename, mode=0755)
        try:
            self.duthost.shell(self.filename)
            self.duthost.shell("rm {}".format(self.filename))
            os.remove(self.filename)
        except:
            pass

    def clean_up(self):
        # delete static ARPs
        self.arps_del()

        # del IP address from the eth interface
        ip_iface = "ip address del {} dev {}".format(self.if_addr, self.iface)
        logging.info("IF ADDR DEL {}".format(ip_iface))
        try:
            self.asic.command(ip_iface)
        except:
            pass


def get_crm_info(duthost, asic):
    """
    get CRM info
    """
    get_group_stats = ("{} COUNTERS_DB HMGET CRM:STATS"
        " crm_stats_nexthop_group_used"
        " crm_stats_nexthop_group_available").format(asic.sonic_db_cli)

    result = duthost.command(get_group_stats)
    pytest_assert(result["rc"] == 0, get_group_stats)

    crm_info = {
        "used": int(result["stdout_lines"][0]),
        "available": int(result["stdout_lines"][1])
    }

    get_polling = '{} CONFIG_DB HMGET "CRM|Config" "polling_interval"'.format(
        asic.sonic_db_cli
    )
    result = duthost.command(get_polling)
    pytest_assert(result["rc"] == 0, get_polling)

    crm_info.update({
        "polling": int(result["stdout_lines"][0])
    })

    return crm_info


# code from doc.python.org to generate combinations
# This is used to create unique nexthop groups
def combinations(iterable, r):
    # combinations('ABCD', 2) --> AB AC AD BC BD CD
    # combinations(range(4), 3) --> 012 013 023 123
    pool = tuple(iterable)
    n = len(pool)
    if r > n:
        return
    indices = list(range(r))
    yield tuple(pool[i] for i in indices)
    while True:
        for i in reversed(range(r)):
            if indices[i] != i + n - r:
                break
        else:
            return
        indices[i] += 1
        for j in range(i+1, r):
            indices[j] = indices[j-1] + 1
        yield tuple(pool[i] for i in indices)


def loganalyzer_ignore_regex_list():
    ignore = [
        ".*Unaccounted_ROUTE_ENTRY_TABLE_entries.*"
    ]
    return ignore


def test_nhop(request, duthost):
    """
    Test next hop group resource count. Steps:
    - Add test IP address to an active IP interface
    - Add static ARPs
    - Create unique next hop groups
    - Add IP route and nexthop
    - check CRM resource
    - clean up
    - Verify no erros and crash
    """
    skip_release(duthost, ["201811", "201911"])

    default_max_nhop_paths = 32
    nhop_group_limit = 1024
    # program more than the advertised limit
    extra_nhops = 10

    asic = duthost.asic_instance()

    # find out MAX NHOP group count supported on the platform
    result = asic.run_redis_cmd(
        argv = ["redis-cli", "-n", 6, "HGETALL", "SWITCH_CAPABILITY|switch"]
    )
    it = iter(result)
    switch_capability = dict(zip(it, it))
    max_nhop = switch_capability.get("MAX_NEXTHOP_GROUP_COUNT")
    max_nhop = nhop_group_limit if max_nhop == None else int(max_nhop)
    nhop_group_count = min(max_nhop, nhop_group_limit) + extra_nhops

    # find out an active IP port
    ip_ifaces = asic.get_active_ip_interfaces().keys()
    pytest_assert(len(ip_ifaces), "No IP interfaces found")
    eth_if = ip_ifaces[0]

    # Generate ARP entries
    arp_count = 40
    arplist = Arp(duthost, asic, arp_count, eth_if)
    arplist.arps_add()

    # indices
    indices = range(arp_count)
    ip_indices = combinations(indices, default_max_nhop_paths)

    # intitialize log analyzer
    marker = "NHOP TEST PATH COUNT {} {}".format(nhop_group_count, eth_if)
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker)
    marker = loganalyzer.init()
    loganalyzer.load_common_config()
    loganalyzer.expect_regex = []
    loganalyzer.ignore_regex.extend(loganalyzer_ignore_regex_list())

    ip_prefix = ipaddr.IPAddress("192.168.0.0")

    # list of all IPs available to generate a nexthop group
    ip_list = arplist.ip_mac_list

    crm_before = get_crm_info(duthost, asic)

    # increase CRM polling time
    asic.command("crm config polling interval 10")

    logging.info("Adding {} next hops on {}".format(nhop_group_count, eth_if))

    # create nexthop group
    nhop = IPRoutes(duthost, asic)
    try:
        for i, indx_list in zip(range(nhop_group_count), ip_indices):
            # get a list of unique group of next hop IPs
            ips = [arplist.ip_mac_list[x].ip for x in indx_list]

            ip_route = "{}/31".format(ip_prefix + (2*i))

            # add IP route with the next hop group created
            nhop.add_ip_route(ip_route, ips)

        nhop.program_routes()
        # wait for routes to be synced and programmed
        time.sleep(120)
        crm_after = get_crm_info(duthost, asic)

    finally:
        nhop.delete_routes()
        arplist.clean_up()
        asic.command(
            "crm config polling interval {}".format(crm_before["polling"])
        )

    # check for any errors or crash
    loganalyzer.analyze(marker)

    # verify the test used up all the NHOP group resources
    # skip this check on Mellanox as ASIC resources are shared
    if not is_mellanox_device(duthost):
        pytest_assert(
            crm_after["available"] == 0,
            "Unused NHOP group resource: {}, used:{}".format(
                crm_after["available"], crm_after["used"]
            )
        )
