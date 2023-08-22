import ipaddr
import logging
import os
import pytest
import random
import time

from collections import namedtuple
from collections import defaultdict

from ptf.mask import Mask
import ptf.packet as scapy
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert
from tests.common.cisco_data import is_cisco_device
from tests.common.mellanox_data import is_mellanox_device, get_chip_type
from tests.common.innovium_data import is_innovium_device
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import wait_until
from tests.platform_tests.link_flap.link_flap_utils import toggle_one_link
from tests.common.platform.device_utils import fanout_switch_port_lookup

CISCO_NHOP_GROUP_FILL_PERCENTAGE = 0.92

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

logger = logging.getLogger(__name__)


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
                fn.write(ip_cmd + "\n")

        fn.close()
        # copy file to DUT and run it on DUT
        self.duthost.copy(src=self.filename, dest=self.filename, mode="0755")
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
                ip_route = "sudo {} ip route del {}".format(self.asic.ns_arg, ip_nhop.prefix)
                fn.write(ip_route + "\n")

        fn.close()
        self.duthost.copy(src=self.filename, dest=self.filename, mode="0755")
        try:
            self.duthost.shell(self.filename)
            self.duthost.shell("rm {}".format(self.filename))
            os.remove(self.filename)
        except:  # noqa: E722
            pass


class Arp:
    """
    Create IP interface and create a list of ARPs with given IP,
    MAC parameters
    """
    def __init__(self, duthost, asic, count, iface, ip=ipaddr.IPAddress("172.16.0.0"), mac="C0:FF:EE:00"):
        IP_MAC = namedtuple("IP_MAC", "ip mac")
        self.iface = iface
        self.ip_mac_list = []
        self.duthost = duthost
        self.asic = asic
        self.if_addr = "{}/16".format(ip + 3)

        fileloc = os.path.join(os.path.sep, "tmp")
        self.filename = os.path.join(fileloc, "static_arp.sh")

        # create a list of IP-MAC bindings
        for i in range(11, count + 11):
            moff1 = "{0:x}".format(i // 255)
            moff2 = "{0:x}".format(i % 255)

            self.ip_mac_list.append(IP_MAC(
                "{}".format(ip + i),
                "{}:{}:{}".format(mac, moff1.zfill(2), moff2.zfill(2))
            ))

    def arps_add(self):
        """
        Create a file with static arp add commands, copy file
        to DUT and run it from DUT
        """

        # add IP address to the eth interface
        ip_iface = "ip address add {} dev {}".format(self.if_addr, self.iface)
        logger.info("IF ADDR ADD {}".format(ip_iface))
        result = self.asic.command(ip_iface)
        pytest_assert(result["rc"] == 0, ip_iface)

        arp_cmd = "sudo {} arp -s {} {}"
        with open(self.filename, "w") as fn:
            for ip_mac in self.ip_mac_list:
                cmd = arp_cmd.format(self.asic.ns_arg, ip_mac.ip, ip_mac.mac)
                fn.write(cmd + "\n")

        fn.close()
        self.duthost.copy(src=self.filename, dest=self.filename, mode="0755")
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

        fn.close()
        self.duthost.copy(src=self.filename, dest=self.filename, mode="0755")
        try:
            self.duthost.shell(self.filename)
            self.duthost.shell("rm {}".format(self.filename))
            os.remove(self.filename)
        except:  # noqa: E722
            pass

    def clean_up(self):
        # delete static ARPs
        self.arps_del()

        # del IP address from the eth interface
        ip_iface = "ip address del {} dev {}".format(self.if_addr, self.iface)
        logger.info("IF ADDR DEL {}".format(ip_iface))
        try:
            self.asic.command(ip_iface)
        except:  # noqa: E722
            pass


def get_crm_info(duthost, asic):
    """
    get CRM info
    """
    get_group_stats = ("{} COUNTERS_DB HMGET CRM:STATS"
                       " crm_stats_nexthop_group_used"
                       " crm_stats_nexthop_group_available"
                       " crm_stats_nexthop_group_member_used"
                       " crm_stats_nexthop_group_member_available").format(asic.sonic_db_cli)
    pytest_assert(wait_until(25, 5, 0, lambda: (len(duthost.command(get_group_stats)["stdout_lines"]) >= 2)),
                  get_group_stats)

    result = duthost.command(get_group_stats)
    pytest_assert(result["rc"] == 0 or len(result["stdout_lines"]) < 2, get_group_stats)

    crm_info = {
        "used_nhop_grp": int(result["stdout_lines"][0]),
        "available_nhop_grp": int(result["stdout_lines"][1]),
        "used_nhop_grp_mem": int(result["stdout_lines"][2]),
        "available_nhop_grp_mem": int(result["stdout_lines"][3])
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
        for i in reversed(list(range(r))):
            if indices[i] != i + n - r:
                break
        else:
            return
        indices[i] += 1
        for j in range(i + 1, r):
            indices[j] = indices[j - 1] + 1
        yield tuple(pool[i] for i in indices)


def loganalyzer_ignore_regex_list():
    ignore = [
        ".*Unaccounted_ROUTE_ENTRY_TABLE_entries.*",
        ".*ERR swss#orchagent: :- addAclTable: Failed to.*",
        ".*ERR swss#orchagent: :- create: create status:.*",
        ".*ERR syncd#syncd: [none] SAI_API_ACL:brcm_sai_dnx_create_acl_table:338 create table.*",
        ".*ERR syncd#syncd: [none] SAI_API_ACL:_brcm_sai_dnx_create_acl_table:7807 field group.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_ACL_STAGE:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_DSCP:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_DST_IP:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_SRC_IP:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6:.*",
        ".*ERR syncd#syncd: :- processQuadEvent: attr: SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS:.*",
        ".*ERR syncd#syncd: :- sendApiResponse: api SAI_COMMON_API_CREATE.*",
        ".*ERR swss#orchagent: :- getResAvailableCounters: Failed to get availability for object_type.*",
        ".*brcm_sai_dnx_create_acl_table:.*",
    ]
    return ignore


def build_pkt(dest_mac, ip_addr, ttl, flow_count):
    pkt = testutils.simple_tcp_packet(
          eth_dst=dest_mac,
          eth_src="00:11:22:33:44:55",
          pktlen=100,
          ip_src="19.0.0.100",
          ip_dst=ip_addr,
          ip_ttl=ttl,
          tcp_dport=200 + flow_count,
          tcp_sport=100 + flow_count
    )
    exp_packet = Mask(pkt)
    exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_packet.set_do_not_care_scapy(scapy.Ether, "src")

    exp_packet.set_do_not_care_scapy(scapy.IP, "version")
    exp_packet.set_do_not_care_scapy(scapy.IP, "ihl")
    exp_packet.set_do_not_care_scapy(scapy.IP, "tos")
    exp_packet.set_do_not_care_scapy(scapy.IP, "len")
    exp_packet.set_do_not_care_scapy(scapy.IP, "flags")
    exp_packet.set_do_not_care_scapy(scapy.IP, "id")
    exp_packet.set_do_not_care_scapy(scapy.IP, "frag")
    exp_packet.set_do_not_care_scapy(scapy.IP, "ttl")
    exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
    exp_packet.set_do_not_care_scapy(scapy.IP, "options")

    exp_packet.set_do_not_care_scapy(scapy.TCP, "seq")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "ack")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "reserved")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "dataofs")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "window")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "chksum")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "urgptr")

    exp_packet.set_ignore_extra_bytes()
    return pkt, exp_packet


def test_nhop_group_member_count(duthost, tbinfo):
    """
    Test next hop group resource count. Steps:
    - Add test IP address to an active IP interface
    - Add static ARPs
    - Create unique next hop groups
    - Add IP route and nexthop
    - check CRM resource
    - clean up
    - Verify no errors and crash
    """
    # Set of parameters for Cisco-8000 devices
    if is_cisco_device(duthost):
        default_max_nhop_paths = 2
        polling_interval = 1
        sleep_time = 380
        sleep_time_sync_before = 120
    elif is_innovium_device(duthost):
        default_max_nhop_paths = 3
        polling_interval = 10
        sleep_time = 120
    elif is_mellanox_device(duthost) and get_chip_type(duthost) == 'spectrum1':
        default_max_nhop_paths = 8
        polling_interval = 10
        sleep_time = 120
    else:
        default_max_nhop_paths = 32
        polling_interval = 10
        sleep_time = 120
    nhop_group_limit = 1024
    # program more than the advertised limit
    extra_nhops = 10

    asic = duthost.asic_instance()

    # find out MAX NHOP group count supported on the platform
    result = asic.run_redis_cmd(argv=["redis-cli", "-n", 6, "HGETALL", "SWITCH_CAPABILITY|switch"])
    it = iter(result)
    switch_capability = dict(list(zip(it, it)))
    max_nhop = switch_capability.get("MAX_NEXTHOP_GROUP_COUNT")
    max_nhop = nhop_group_limit if max_nhop is None else int(max_nhop)

    # find out an active IP port
    ip_ifaces = list(asic.get_active_ip_interfaces(tbinfo).keys())
    pytest_assert(len(ip_ifaces), "No IP interfaces found")
    eth_if = ip_ifaces[0]

    # Generate ARP entries
    if is_cisco_device(duthost):
        arp_count = 257
    else:
        arp_count = 40
    arplist = Arp(duthost, asic, arp_count, eth_if)
    arplist.arps_add()

    # indices
    indices = list(range(arp_count))
    ip_indices = combinations(indices, default_max_nhop_paths)
    ip_prefix = ipaddr.IPAddress("192.168.0.0")

    crm_before = get_crm_info(duthost, asic)

    # increase CRM polling time
    asic.command("crm config polling interval {}".format(polling_interval))

    if is_cisco_device(duthost):
        # Waiting for ARP routes to be synced and programmed
        time.sleep(sleep_time_sync_before)
        crm_stat = get_crm_info(duthost, asic)
        nhop_group_count = crm_stat["available_nhop_grp"]
        nhop_group_mem_count = crm_stat["available_nhop_grp_mem"]
        nhop_group_count = int(nhop_group_count * CISCO_NHOP_GROUP_FILL_PERCENTAGE)
        # Consider both available nhop_grp and nhop_grp_mem before creating nhop_groups
        nhop_group_mem_count = int((nhop_group_mem_count) / default_max_nhop_paths * CISCO_NHOP_GROUP_FILL_PERCENTAGE)
        nhop_group_count = min(nhop_group_mem_count, nhop_group_count)
    elif is_innovium_device(duthost):
        crm_stat = get_crm_info(duthost, asic)
        nhop_group_count = crm_stat["available_nhop_grp"]
    else:
        nhop_group_count = min(max_nhop, nhop_group_limit) + extra_nhops
    # initialize log analyzer
    marker = "NHOP TEST PATH COUNT {} {}".format(nhop_group_count, eth_if)
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker)
    marker = loganalyzer.init()
    loganalyzer.load_common_config()
    loganalyzer.expect_regex = []
    loganalyzer.ignore_regex.extend(loganalyzer_ignore_regex_list())

    logger.info("Adding {} next hops on {}".format(nhop_group_count, eth_if))
    # create nexthop group
    nhop = IPRoutes(duthost, asic)
    try:
        for i, indx_list in zip(list(range(nhop_group_count)), ip_indices):
            # get a list of unique group of next hop IPs
            ips = [arplist.ip_mac_list[x].ip for x in indx_list]

            ip_route = "{}/31".format(ip_prefix + (2*i))

            # add IP route with the next hop group created
            nhop.add_ip_route(ip_route, ips)

        nhop.program_routes()
        # wait for routes to be synced and programmed
        time.sleep(sleep_time)
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
    if is_cisco_device(duthost):
        pytest_assert(
            crm_after["available_nhop_grp"] + nhop_group_count == crm_before["available_nhop_grp"],
            "Unused NHOP group resource:{}, used:{}, nhop_group_count:{}, Unused NHOP group resource before:{}".format(
                crm_after["available_nhop_grp"], crm_after["used_nhop_grp"], nhop_group_count,
                crm_before["available_nhop_grp"]

            )
        )
    elif is_mellanox_device(duthost):
        logger.info("skip this check on Mellanox as ASIC resources are shared")
    else:
        pytest_assert(
            crm_after["available_nhop_grp"] == 0,
            "Unused NHOP group resource:{}, used_nhop_grp:{}".format(
                crm_after["available_nhop_grp"], crm_after["used_nhop_grp"]
            )
        )


def test_nhop_group_member_order_capability(duthost, tbinfo, ptfadapter, gather_facts,
                                            enum_rand_one_frontend_asic_index, fanouthosts):
    """
    Test SONiC and SAI Vendor capability are same for ordered ecmp feature
    and SAI vendor is honoring the Ordered nature of nexthop group member
    """
    if is_mellanox_device(duthost):
        # Note: Need remove this check once Mellanox committed Ordered ECMP
        pytest.skip("Ordered ECMP currently not supported on Mellanox DUT")

    asic = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    result = asic.run_redis_cmd(argv=["redis-cli", "-n", 6, "HGETALL", "SWITCH_CAPABILITY|switch"])
    it = iter(result)
    switch_capability = dict(list(zip(it, it)))

    result = asic.run_redis_cmd(argv=["redis-cli", "-n", 0, "HGETALL", "SWITCH_TABLE:switch"])

    it = iter(result)
    switch_table = dict(list(zip(it, it)))

    order_ecmp_capability = switch_capability.get("ORDERED_ECMP_CAPABLE")
    order_ecmp_configured = switch_table.get("ordered_ecmp")
    pytest_assert(order_ecmp_capability == order_ecmp_configured,
                  "Order Ecmp Feature configured and capability not same")

    if order_ecmp_configured == "false":
        pytest.skip("Order ECMP is not configured so skipping the test-case")

    # Check Gather facts IP Interface is active one
    ip_ifaces = list(asic.get_active_ip_interfaces(tbinfo).keys())
    pytest_assert(len(ip_ifaces), "No IP interfaces found")
    pytest_assert(gather_facts['src_router_intf_name'] in ip_ifaces, "Selected IP interfaces is not active")

    # Generate ARP entries
    arp_count = 8
    arplist = Arp(duthost, asic, arp_count, gather_facts['src_router_intf_name'])
    neighbor_mac = [neighbor[1].lower() for neighbor in arplist.ip_mac_list]
    ip_route = "192.168.100.50"
    ip_prefix = ip_route + "/31"
    ip_ttl = 121

    # create nexthop group
    nhop = IPRoutes(duthost, asic)

    recvd_pkt_result = defaultdict(set)

    rtr_mac = asic.get_router_mac()

    def built_and_send_tcp_ip_packet():
        for flow_count in range(50):
            pkt, exp_pkt = build_pkt(rtr_mac, ip_route, ip_ttl, flow_count)
            testutils.send(ptfadapter, gather_facts['dst_port_ids'][0], pkt, 10)
            (_, recv_pkt) = testutils.verify_packet_any_port(test=ptfadapter, pkt=exp_pkt,
                                                             ports=gather_facts['src_port_ids'])

            assert recv_pkt

            # Make sure routing is done
            pytest_assert(scapy.Ether(recv_pkt).ttl == (ip_ttl - 1), "Routed Packet TTL not decremented")
            pytest_assert(scapy.Ether(recv_pkt).src == rtr_mac, "Routed Packet Source Mac is not router MAC")
            pytest_assert(scapy.Ether(recv_pkt).dst.lower() in neighbor_mac,
                          "Routed Packet Destination Mac not valid neighbor entry")

            recvd_pkt_result[flow_count].add(scapy.Ether(recv_pkt).dst)

    # Test/Iteration Scenario 1: Verify After ecmp member remove/add flow order remains same.
    # Test/Iteration Scenario 2: Veirfy Neighbor created in different order but flow order remains same.
    for iter_count in range(2):
        try:
            # create neighbor entry in different order list
            random.seed(iter_count)
            random.shuffle(arplist.ip_mac_list)
            arplist.arps_add()
            ips = [arplist.ip_mac_list[x].ip for x in range(arp_count)]

            # add IP route
            nhop.ip_nhops = []
            nhop.add_ip_route(ip_prefix, ips)

            nhop.program_routes()
            # wait for routes to be synced and programmed
            time.sleep(15)

            ptfadapter.dataplane.flush()

            built_and_send_tcp_ip_packet()

            if iter_count == 0:
                fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, duthost.hostname,
                                                                gather_facts['src_port'][0])
                # Simulate ECMP Acceleration with link flap where ECMP memeber are removed
                # and added back to the group
                # BGP service is stoped so we don't get Route Removal message
                # from FRR and it is just member add/remove trigger
                asic.stop_service("bgp")
                time.sleep(15)
                toggle_one_link(duthost, gather_facts['src_port'][0], fanout, fanout_port)
                time.sleep(15)

                built_and_send_tcp_ip_packet()

            for flow_count, nexthop_selected in recvd_pkt_result.items():
                pytest_assert(len(nexthop_selected) == 1,
                              "Error flow {} received on different nexthop in iteration {}"
                              .format(flow_count, iter_count))
        finally:
            asic.start_service("bgp")
            time.sleep(15)
            nhop.delete_routes()
            arplist.clean_up()

    th_asic_flow_map = {0: 'c0:ff:ee:00:00:10', 1: 'c0:ff:ee:00:00:0b',
                        2: 'c0:ff:ee:00:00:12',
                        3: 'c0:ff:ee:00:00:0d', 4: 'c0:ff:ee:00:00:11',
                        5: 'c0:ff:ee:00:00:0e', 6: 'c0:ff:ee:00:00:0f',
                        7: 'c0:ff:ee:00:00:0c', 8: 'c0:ff:ee:00:00:0e',
                        9: 'c0:ff:ee:00:00:11',
                        10: 'c0:ff:ee:00:00:0c', 11: 'c0:ff:ee:00:00:0f',
                        12: 'c0:ff:ee:00:00:12', 13: 'c0:ff:ee:00:00:0d',
                        14: 'c0:ff:ee:00:00:10',
                        15: 'c0:ff:ee:00:00:0b', 16: 'c0:ff:ee:00:00:11',
                        17: 'c0:ff:ee:00:00:0e', 18: 'c0:ff:ee:00:00:0f',
                        19: 'c0:ff:ee:00:00:0c',
                        20: 'c0:ff:ee:00:00:10', 21: 'c0:ff:ee:00:00:0b',
                        22: 'c0:ff:ee:00:00:12', 23: 'c0:ff:ee:00:00:0d',
                        24: 'c0:ff:ee:00:00:11',
                        25: 'c0:ff:ee:00:00:0e', 26: 'c0:ff:ee:00:00:0f',
                        27: 'c0:ff:ee:00:00:0c', 28: 'c0:ff:ee:00:00:0b', 29: 'c0:ff:ee:00:00:10',
                        30: 'c0:ff:ee:00:00:0d', 31: 'c0:ff:ee:00:00:12',
                        32: 'c0:ff:ee:00:00:0c', 33: 'c0:ff:ee:00:00:0f',
                        34: 'c0:ff:ee:00:00:0e',
                        35: 'c0:ff:ee:00:00:11', 36: 'c0:ff:ee:00:00:0d',
                        37: 'c0:ff:ee:00:00:12', 38: 'c0:ff:ee:00:00:0b', 39: 'c0:ff:ee:00:00:10',
                        40: 'c0:ff:ee:00:00:12', 41: 'c0:ff:ee:00:00:0d',
                        42: 'c0:ff:ee:00:00:10', 43: 'c0:ff:ee:00:00:0b', 44: 'c0:ff:ee:00:00:0e',
                        45: 'c0:ff:ee:00:00:11', 46: 'c0:ff:ee:00:00:0c',
                        47: 'c0:ff:ee:00:00:0f', 48: 'c0:ff:ee:00:00:0d', 49: 'c0:ff:ee:00:00:12'}

    gb_asic_flow_map = {0: 'c0:ff:ee:00:00:0f', 1: 'c0:ff:ee:00:00:10',
                        2: 'c0:ff:ee:00:00:0e', 3: 'c0:ff:ee:00:00:0f', 4: 'c0:ff:ee:00:00:11',
                        5: 'c0:ff:ee:00:00:0f', 6: 'c0:ff:ee:00:00:12',
                        7: 'c0:ff:ee:00:00:0c', 8: 'c0:ff:ee:00:00:0e', 9: 'c0:ff:ee:00:00:10',
                        10: 'c0:ff:ee:00:00:11', 11: 'c0:ff:ee:00:00:0f',
                        12: 'c0:ff:ee:00:00:0c', 13: 'c0:ff:ee:00:00:0f',
                        14: 'c0:ff:ee:00:00:11',
                        15: 'c0:ff:ee:00:00:0c', 16: 'c0:ff:ee:00:00:0e',
                        17: 'c0:ff:ee:00:00:11', 18: 'c0:ff:ee:00:00:11', 19: 'c0:ff:ee:00:00:0c',
                        20: 'c0:ff:ee:00:00:10', 21: 'c0:ff:ee:00:00:0b',
                        22: 'c0:ff:ee:00:00:0d', 23: 'c0:ff:ee:00:00:10', 24: 'c0:ff:ee:00:00:12',
                        25: 'c0:ff:ee:00:00:11', 26: 'c0:ff:ee:00:00:11',
                        27: 'c0:ff:ee:00:00:0c', 28: 'c0:ff:ee:00:00:11', 29: 'c0:ff:ee:00:00:0c',
                        30: 'c0:ff:ee:00:00:12', 31: 'c0:ff:ee:00:00:10',
                        32: 'c0:ff:ee:00:00:11', 33: 'c0:ff:ee:00:00:0c', 34: 'c0:ff:ee:00:00:0c',
                        35: 'c0:ff:ee:00:00:0b', 36: 'c0:ff:ee:00:00:0d',
                        37: 'c0:ff:ee:00:00:10', 38: 'c0:ff:ee:00:00:0e', 39: 'c0:ff:ee:00:00:0d',
                        40: 'c0:ff:ee:00:00:0e', 41: 'c0:ff:ee:00:00:11',
                        42: 'c0:ff:ee:00:00:11', 43: 'c0:ff:ee:00:00:0c', 44: 'c0:ff:ee:00:00:0e',
                        45: 'c0:ff:ee:00:00:0f', 46: 'c0:ff:ee:00:00:0f',
                        47: 'c0:ff:ee:00:00:0c', 48: 'c0:ff:ee:00:00:0e', 49: 'c0:ff:ee:00:00:10'}

    td2_asic_flow_map = {0: 'c0:ff:ee:00:00:10', 1: 'c0:ff:ee:00:00:0b',
                         2: 'c0:ff:ee:00:00:12',
                         3: 'c0:ff:ee:00:00:0d', 4: 'c0:ff:ee:00:00:11',
                         5: 'c0:ff:ee:00:00:0e', 6: 'c0:ff:ee:00:00:0f',
                         7: 'c0:ff:ee:00:00:0c', 8: 'c0:ff:ee:00:00:0e',
                         9: 'c0:ff:ee:00:00:11',
                         10: 'c0:ff:ee:00:00:0c', 11: 'c0:ff:ee:00:00:0f',
                         12: 'c0:ff:ee:00:00:12', 13: 'c0:ff:ee:00:00:0d',
                         14: 'c0:ff:ee:00:00:10',
                         15: 'c0:ff:ee:00:00:0b', 16: 'c0:ff:ee:00:00:11',
                         17: 'c0:ff:ee:00:00:0e', 18: 'c0:ff:ee:00:00:0f',
                         19: 'c0:ff:ee:00:00:0c',
                         20: 'c0:ff:ee:00:00:10', 21: 'c0:ff:ee:00:00:0b',
                         22: 'c0:ff:ee:00:00:12', 23: 'c0:ff:ee:00:00:0d',
                         24: 'c0:ff:ee:00:00:11',
                         25: 'c0:ff:ee:00:00:0e', 26: 'c0:ff:ee:00:00:0f',
                         27: 'c0:ff:ee:00:00:0c', 28: 'c0:ff:ee:00:00:0b', 29: 'c0:ff:ee:00:00:10',
                         30: 'c0:ff:ee:00:00:0d', 31: 'c0:ff:ee:00:00:12',
                         32: 'c0:ff:ee:00:00:0c', 33: 'c0:ff:ee:00:00:0f',
                         34: 'c0:ff:ee:00:00:0e',
                         35: 'c0:ff:ee:00:00:11', 36: 'c0:ff:ee:00:00:0d',
                         37: 'c0:ff:ee:00:00:12', 38: 'c0:ff:ee:00:00:0b', 39: 'c0:ff:ee:00:00:10',
                         40: 'c0:ff:ee:00:00:12', 41: 'c0:ff:ee:00:00:0d',
                         42: 'c0:ff:ee:00:00:10', 43: 'c0:ff:ee:00:00:0b', 44: 'c0:ff:ee:00:00:0e',
                         45: 'c0:ff:ee:00:00:11', 46: 'c0:ff:ee:00:00:0c',
                         47: 'c0:ff:ee:00:00:0f', 48: 'c0:ff:ee:00:00:0d', 49: 'c0:ff:ee:00:00:12'}

    th2_asic_flow_map = {0: 'c0:ff:ee:00:00:10', 1: 'c0:ff:ee:00:00:0b',
                         2: 'c0:ff:ee:00:00:12',
                         3: 'c0:ff:ee:00:00:0d', 4: 'c0:ff:ee:00:00:11',
                         5: 'c0:ff:ee:00:00:0e', 6: 'c0:ff:ee:00:00:0f',
                         7: 'c0:ff:ee:00:00:0c', 8: 'c0:ff:ee:00:00:0e',
                         9: 'c0:ff:ee:00:00:11',
                         10: 'c0:ff:ee:00:00:0c', 11: 'c0:ff:ee:00:00:0f',
                         12: 'c0:ff:ee:00:00:12', 13: 'c0:ff:ee:00:00:0d',
                         14: 'c0:ff:ee:00:00:10',
                         15: 'c0:ff:ee:00:00:0b', 16: 'c0:ff:ee:00:00:11',
                         17: 'c0:ff:ee:00:00:0e', 18: 'c0:ff:ee:00:00:0f',
                         19: 'c0:ff:ee:00:00:0c',
                         20: 'c0:ff:ee:00:00:10', 21: 'c0:ff:ee:00:00:0b',
                         22: 'c0:ff:ee:00:00:12', 23: 'c0:ff:ee:00:00:0d',
                         24: 'c0:ff:ee:00:00:11',
                         25: 'c0:ff:ee:00:00:0e', 26: 'c0:ff:ee:00:00:0f',
                         27: 'c0:ff:ee:00:00:0c', 28: 'c0:ff:ee:00:00:0b', 29: 'c0:ff:ee:00:00:10',
                         30: 'c0:ff:ee:00:00:0d', 31: 'c0:ff:ee:00:00:12',
                         32: 'c0:ff:ee:00:00:0c', 33: 'c0:ff:ee:00:00:0f',
                         34: 'c0:ff:ee:00:00:0e',
                         35: 'c0:ff:ee:00:00:11', 36: 'c0:ff:ee:00:00:0d',
                         37: 'c0:ff:ee:00:00:12', 38: 'c0:ff:ee:00:00:0b', 39: 'c0:ff:ee:00:00:10',
                         40: 'c0:ff:ee:00:00:12', 41: 'c0:ff:ee:00:00:0d',
                         42: 'c0:ff:ee:00:00:10', 43: 'c0:ff:ee:00:00:0b', 44: 'c0:ff:ee:00:00:0e',
                         45: 'c0:ff:ee:00:00:11', 46: 'c0:ff:ee:00:00:0c',
                         47: 'c0:ff:ee:00:00:0f', 48: 'c0:ff:ee:00:00:0d', 49: 'c0:ff:ee:00:00:12'}

    td3_asic_flow_map = {0: 'c0:ff:ee:00:00:10', 1: 'c0:ff:ee:00:00:0b',
                         2: 'c0:ff:ee:00:00:12', 3: 'c0:ff:ee:00:00:0d',
                         4: 'c0:ff:ee:00:00:11', 5: 'c0:ff:ee:00:00:0e',
                         6: 'c0:ff:ee:00:00:0f', 7: 'c0:ff:ee:00:00:0c',
                         8: 'c0:ff:ee:00:00:0e', 9: 'c0:ff:ee:00:00:11',
                         10: 'c0:ff:ee:00:00:0c', 11: 'c0:ff:ee:00:00:0f',
                         12: 'c0:ff:ee:00:00:12', 13: 'c0:ff:ee:00:00:0d',
                         14: 'c0:ff:ee:00:00:10', 15: 'c0:ff:ee:00:00:0b',
                         16: 'c0:ff:ee:00:00:11', 17: 'c0:ff:ee:00:00:0e',
                         18: 'c0:ff:ee:00:00:0f', 19: 'c0:ff:ee:00:00:0c',
                         20: 'c0:ff:ee:00:00:10', 21: 'c0:ff:ee:00:00:0b',
                         22: 'c0:ff:ee:00:00:12', 23: 'c0:ff:ee:00:00:0d',
                         24: 'c0:ff:ee:00:00:11', 25: 'c0:ff:ee:00:00:0e',
                         26: 'c0:ff:ee:00:00:0f', 27: 'c0:ff:ee:00:00:0c',
                         28: 'c0:ff:ee:00:00:0b', 29: 'c0:ff:ee:00:00:10',
                         30: 'c0:ff:ee:00:00:0d', 31: 'c0:ff:ee:00:00:12',
                         32: 'c0:ff:ee:00:00:0c', 33: 'c0:ff:ee:00:00:0f',
                         34: 'c0:ff:ee:00:00:0e', 35: 'c0:ff:ee:00:00:11',
                         36: 'c0:ff:ee:00:00:0d', 37: 'c0:ff:ee:00:00:12',
                         38: 'c0:ff:ee:00:00:0b', 39: 'c0:ff:ee:00:00:10',
                         40: 'c0:ff:ee:00:00:12', 41: 'c0:ff:ee:00:00:0d',
                         42: 'c0:ff:ee:00:00:10', 43: 'c0:ff:ee:00:00:0b',
                         44: 'c0:ff:ee:00:00:0e', 45: 'c0:ff:ee:00:00:11',
                         46: 'c0:ff:ee:00:00:0c', 47: 'c0:ff:ee:00:00:0f',
                         48: 'c0:ff:ee:00:00:0d', 49: 'c0:ff:ee:00:00:12'}

    gr_asic_flow_map = {0: 'c0:ff:ee:00:00:12', 1: 'c0:ff:ee:00:00:10',
                        2: 'c0:ff:ee:00:00:0c',
                        3: 'c0:ff:ee:00:00:0b', 4: 'c0:ff:ee:00:00:0b',
                        5: 'c0:ff:ee:00:00:0b', 6: 'c0:ff:ee:00:00:11',
                        7: 'c0:ff:ee:00:00:12', 8: 'c0:ff:ee:00:00:0d',
                        9: 'c0:ff:ee:00:00:0c',
                        10: 'c0:ff:ee:00:00:0f', 11: 'c0:ff:ee:00:00:0e',
                        12: 'c0:ff:ee:00:00:11', 13: 'c0:ff:ee:00:00:10',
                        14: 'c0:ff:ee:00:00:0b',
                        15: 'c0:ff:ee:00:00:12', 16: 'c0:ff:ee:00:00:0b',
                        17: 'c0:ff:ee:00:00:12', 18: 'c0:ff:ee:00:00:11',
                        19: 'c0:ff:ee:00:00:10', 20: 'c0:ff:ee:00:00:10',
                        21: 'c0:ff:ee:00:00:11', 22: 'c0:ff:ee:00:00:12',
                        23: 'c0:ff:ee:00:00:0b', 24: 'c0:ff:ee:00:00:0c',
                        25: 'c0:ff:ee:00:00:0d',
                        26: 'c0:ff:ee:00:00:0e', 27: 'c0:ff:ee:00:00:0f',
                        28: 'c0:ff:ee:00:00:10', 29: 'c0:ff:ee:00:00:11',
                        30: 'c0:ff:ee:00:00:12', 31: 'c0:ff:ee:00:00:0b',
                        32: 'c0:ff:ee:00:00:12', 33: 'c0:ff:ee:00:00:0b',
                        34: 'c0:ff:ee:00:00:10',
                        35: 'c0:ff:ee:00:00:11', 36: 'c0:ff:ee:00:00:11',
                        37: 'c0:ff:ee:00:00:10', 38: 'c0:ff:ee:00:00:0b',
                        39: 'c0:ff:ee:00:00:12',
                        40: 'c0:ff:ee:00:00:0e', 41: 'c0:ff:ee:00:00:10',
                        42: 'c0:ff:ee:00:00:0d', 43: 'c0:ff:ee:00:00:0e',
                        44: 'c0:ff:ee:00:00:0b', 45: 'c0:ff:ee:00:00:0c',
                        46: 'c0:ff:ee:00:00:11',
                        47: 'c0:ff:ee:00:00:11', 48: 'c0:ff:ee:00:00:11',
                        49: 'c0:ff:ee:00:00:11'}

    # Make sure a givenflow always hash to same nexthop/neighbor. This is done to try to find issue
    # where SAI vendor changes Hash Function across SAI releases. Please note this will not catch the issue every time
    # as there is always probability even after change of Hash Function same nexthop/neighbor is selected.

    # Fill this array after first run of test case which will give neighbor selected
    SUPPORTED_ASIC_TO_NEXTHOP_SELECTED_MAP = {"th": th_asic_flow_map, "gb": gb_asic_flow_map, "gblc": gb_asic_flow_map,
                                              "td2": td2_asic_flow_map, "th2": th2_asic_flow_map,
                                              "td3": td3_asic_flow_map, "gr": gr_asic_flow_map}

    vendor = duthost.facts["asic_type"]
    hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
    dutAsic = None
    for asic, nexthop_map in list(SUPPORTED_ASIC_TO_NEXTHOP_SELECTED_MAP.items()):
        vendorAsic = "{0}_{1}_hwskus".format(vendor, asic)
        if vendorAsic in list(hostvars.keys()) and mgFacts["minigraph_hwsku"] in hostvars[vendorAsic]:
            dutAsic = asic
            break
    # Vendor need to update SUPPORTED_ASIC_TO_NEXTHOP_SELECTED_MAP . To do this we need to run the test case 1st
    # time and see the neighbor picked by flow (pkt) sent above. Once that is determined update the map
    # SUPPORTED_ASIC_TO_NEXTHOP_SELECTED_MAP
    pytest_assert(dutAsic, "Please add ASIC in the SUPPORTED_ASIC_TO_NEXTHOP_SELECTED_MAP \
                            list and update the asic to nexthop mapping")
    for flow_count, nexthop_selected in recvd_pkt_result.items():
        pytest_assert(nexthop_map[flow_count] in nexthop_selected,
                      "Flow {} is not picking expected Neighbor".format(flow_count))
