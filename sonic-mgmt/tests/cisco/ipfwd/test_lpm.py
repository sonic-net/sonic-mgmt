import ipaddr
import logging
import os
import pytest

from collections import namedtuple
from collections import defaultdict

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.cisco_data import is_cisco_device
from tests.common.utilities import wait_until

from tests.cisco.common.utils import skip_if_sim
from tests.cisco.common.utils import Arp
from tests.cisco.common.utils import IPRoutes
from tests.cisco.common.utils import get_crm_info
from tests.cisco.common.utils import combinations

CISCO_NHOP_GROUP_FILL_PERCENTAGE = 0.92

pytestmark = [
    pytest.mark.topology('t1', 't2')
]

logger = logging.getLogger(__name__)

@pytest.fixture(scope='module', autouse=True)
def common_setup_teardown(duthost):
    result = duthost.shell("sudo config platform cisco sdk-debug enable", module_ignore_errors=True)
    logging.info(result['stdout_lines'])
    assert "Enabling sdk-debug on all ASICs" in result['stdout'], "debug shell not started"
    time.sleep(120)

    yield

    result = duthost.shell("sudo config platform cisco sdk-debug disable", module_ignore_errors=True)
    logging.info(result['stdout_lines'])
    assert "Disabling sdk-debug on all ASICs" in result['stdout'], "debug shell is not stopped"
    time.sleep(60)

class LPM:
    """
    Program IP routes with next hops on to the DUT
    """
    def __init__(self, duthost, asic):
        self.asic = asic
        self.duthost = duthost

    def get_lpm_report(self):
        cmd = "show platform npu lpm-db -n asic{}".format(self.asic.asic_index)
        self.lpm_report = self.duthost.shell(cmd)["stdout_lines"] 

    def get_lpm_resource_usage_stats(self):
        keys = ['IPv4 Entries', 'IPv6 Entries', "IPv4 SRAM Entries", "IPv4 HBM Entries", "IPv6 SRAM Entries", "IPv6 HBM Entries",
                "TCAM Occupied Rows", "TCAM Free Rows", "IPv4 TCAM Entries", "IPv6 double TCAM Entries", "IPv6 quad TCAM Entries",
                'L1 Rows', "L1 Entries", "L2 SRAM Rows", "L2 HBM Rows", "L2 SRAM Single Entries", "L2 SRAM Wide Entries",
                "L2 HBM Single Entries", "L2 HBM Wide Entries"]

        self.get_lpm_report()
        result = {}

        for line in self.lpm_report:
            if line:
                line = line.split('|')
                if len(line) < 18:
                    continue 
                line = list(map(str.strip, line))
                if line[1] in keys:
                    counters = line[18]
                    result[line[1]] = counters
                    keys.remove(line[1])
                    if not keys:
                        break
        pytest_assert(keys == [], "Failed to get LPM resource for {}".format(str(keys)))
        return result

def test_lpm_infra(duthost, tbinfo, skip_if_sim):
    """
    Test validate basic LPM output
    - Creates LPM instance
    - Gets LPM report using show platform dshell cmd
    - Parses the LPM report and generates a result
    - Prints the resource usage stats
    """

    asic = duthost.asic_instance()

    # generate LPM report
    lpm = LPM(duthost, asic)
    result = lpm.get_lpm_resource_usage_stats()

    for x in result:
        print("Resource: {} Usage: {}". format(x, result[x]))


def test_basic_lpm_output(duthost, tbinfo, skip_if_sim):
    """
    Test validate basic LPM output
    - Add test IP address to an active IP interface
    - Add static ARPs
    - Create unique next hop groups
    - Add IP route and nexthop
    - Enable debug shell and check LPM output
    - clean up
    """

    default_max_nhop_paths = 2
    polling_interval = 1
    sleep_time = 380
    sleep_time_sync_before = 120

    asic = duthost.asic_instance()

    # find out an active IP port
    ip_ifaces = list(asic.get_active_ip_interfaces(tbinfo).keys())
    pytest_assert(len(ip_ifaces), "No IP interfaces found")
    eth_if = ip_ifaces[0]

    # Generate ARP entries
    arp_count = 8
    arplist = Arp(duthost, asic, arp_count, eth_if)
    #arplist.arps_add()

    # indices
    indices = list(range(arp_count))
    ip_indices = combinations(indices, default_max_nhop_paths)
    ip_prefix = ipaddr.IPAddress("192.168.0.0")

    crm_before = get_crm_info(duthost, asic)


    # Enable debug shell
    #duthost.command("sudo config platform cisco sdk-debug enable")

    # increase CRM polling time
    asic.command("crm config polling interval {}".format(polling_interval))

    # Waiting for ARP routes to be synced and programmed
    time.sleep(sleep_time_sync_before)
    crm_stat = get_crm_info(duthost, asic)
    nhop_group_count = crm_stat["available_nhop_grp"]
    nhop_group_mem_count = crm_stat["available_nhop_grp_mem"]
    nhop_group_count = int(nhop_group_count * CISCO_NHOP_GROUP_FILL_PERCENTAGE)
    # Consider both available nhop_grp and nhop_grp_mem before creating nhop_groups
    nhop_group_mem_count = int((nhop_group_mem_count) / default_max_nhop_paths * CISCO_NHOP_GROUP_FILL_PERCENTAGE)
    nhop_group_count = min(nhop_group_mem_count, nhop_group_count)

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

        # generate LPM report
        lpm = LPM(duthost, asic)
        result = lpm.get_lpm_resource_usage_stats()

        ipv4_entries = result["IPv4 Entries"]
        ipv6_entries = result["IPv6 Entries"]

    finally:
        nhop.delete_routes()
        arplist.clean_up()
        asic.command(
            "crm config polling interval {}".format(crm_before["polling"])
        )
        #duthost.command("sudo config platform cisco sdk-debug disable")
        time.sleep(sleep_time)


    pytest_assert(ipv4_entries != 0 and ipv6_entries != 0,
            "ipv4_entries {} or ipv6_entries {} are not updated correctly".format(ipv4_entries, ipv6_entries))
    
    
def test_lpm_update_with_new_prefix(duthost, tbinfo, skip_if_sim):
    """
    Test validate basic LPM output
    - Add test IP address to an active IP interface
    - Add static ARPs
    - Create unique next hop groups
    - Add IP route and nexthop
    - Enable debug shell and check LPM output
    - clean up
    """

    default_max_nhop_paths = 2
    polling_interval = 1
    sleep_time = 180
    sleep_time_sync_before = 120

    asic = duthost.asic_instance()

    # find out an active IP port
    ip_ifaces = list(asic.get_active_ip_interfaces(tbinfo).keys())
    pytest_assert(len(ip_ifaces), "No IP interfaces found")
    eth_if = ip_ifaces[0]

    # Generate ARP entries
    arp_count = 128
    arplist = Arp(duthost, asic, arp_count, eth_if)
    arplist.arps_add()

    # indices
    indices = list(range(arp_count))
    ip_indices = combinations(indices, default_max_nhop_paths)
    ip_prefix = ipaddr.IPAddress("192.168.0.0")

    crm_before = get_crm_info(duthost, asic)

    # increase CRM polling time
    asic.command("crm config polling interval {}".format(polling_interval))

    # Waiting for ARP routes to be synced and programmed
    time.sleep(sleep_time_sync_before)
    crm_stat = get_crm_info(duthost, asic)
    nhop_group_count = crm_stat["available_nhop_grp"]
    nhop_group_mem_count = crm_stat["available_nhop_grp_mem"]
    nhop_group_count = int(nhop_group_count * CISCO_NHOP_GROUP_FILL_PERCENTAGE)
    # Consider both available nhop_grp and nhop_grp_mem before creating nhop_groups
    nhop_group_mem_count = int((nhop_group_mem_count) / default_max_nhop_paths * CISCO_NHOP_GROUP_FILL_PERCENTAGE)
    nhop_group_count = min(nhop_group_mem_count, nhop_group_count)

    # generate LPM report
    lpm = LPM(duthost, asic)

    result = lpm.get_lpm_resource_usage_stats()

    before_ipv4_entries = result["IPv4 Entries"]
    before_l2_rows = result["L2 SRAM Rows"]
    before_l1_rows = result["L1 Rows"]

    logger.info("Adding {} next hops on {}".format(nhop_group_count, eth_if))
    # create nexthop group
    nhop = IPRoutes(duthost, asic)
    try:
        for i, indx_list in zip(list(range(nhop_group_count)), ip_indices):
            # get a list of unique group of next hop IPs
            ips = [arplist.ip_mac_list[x].ip for x in indx_list]

            ip_route = "{}/31".format(ip_prefix + (8*i))

            # add IP route with the next hop group created
            nhop.add_ip_route(ip_route, ips)

        nhop.program_routes()
        # wait for routes to be synced and programmed
        time.sleep(sleep_time)

        result = lpm.get_lpm_resource_usage_stats()
        after_ipv4_entries = result["IPv4 Entries"]
        after_l2_rows = result["L2 SRAM Rows"]
        after_l1_rows = result["L1 Rows"]

    finally:
        nhop.delete_routes()
        arplist.clean_up()
        asic.command(
            "crm config polling interval {}".format(crm_before["polling"])
        )

    pytest_assert(after_ipv4_entries > before_ipv4_entries and after_l2_rows > before_l2_rows and after_l1_rows > before_l1_rows,
            "after_ipv4_entries {}, before_ipv4_entries {}, after_l2_rows {}, before_l2_rows {}, after_l1_rows {}, before_l1_rows {}".
            format(after_ipv4_entries, before_ipv4_entries, after_l2_rows, before_l2_rows, after_l1_rows, before_l1_rows))

