import logging
import pytest
import ipaddress
from functools import reduce

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils \
    import copy_ptftests_directory     # noqa: F401
from tests.vxlan.vxlan_ecmp_utils import Ecmp_Utils
from tests.vxlan.test_vxlan_ecmp import (   # noqa: F401
    Test_VxLAN,
    fixture_setUp,
    fixture_encap_type)

Logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()


def uniq(lst):
    last = object()
    for item in sorted(lst):
        if item == last:
            continue
        yield item
        last = item


def sort_and_deduplicate(list_of_entries):
    return list(uniq(sorted(list_of_entries, reverse=True)))


def unique_in_list(list1):
    return (reduce(lambda re, x: re+[x] if x not in re else re, list1, []))


@pytest.fixture(name="argument_setup", scope="module")
def _fixture_argument_setup(request):

    request.config.option.total_number_of_endpoints =\
        request.config.option.crm_num_nexthops

    request.config.option.total_number_of_nexthops =\
        request.config.option.crm_num_nexthop_group_members

    request.config.option.ecmp_nhs_per_destination =\
        (request.config.option.crm_num_nexthop_group_members /
            request.config.option.crm_num_nexthop_groups)

    if request.config.option.ecmp_nhs_per_destination <= 1:
        raise RuntimeError(
            "This config will not raise the number of ECMP groups,"
            " pls change the commandline arguments."
            "crm_num_nexthop_group_members/crm_num_nexthop_groups "
            "must be more than 1")


@pytest.fixture(name="setup_neighbors", scope="module")
def fixture_setup_neighbors(setUp, encap_type, minigraph_facts):
    duthost = setUp['duthost']
    a_family = Ecmp_Utils.get_outer_layer_version(encap_type)
    t2_neighbors = Ecmp_Utils.get_all_interfaces_running_bgp(
        duthost,
        minigraph_facts,
        "T2")

    IP_TYPE = {
        'v4': ipaddress.IPv4Address,
        'v6': ipaddress.IPv6Address
    }
    intf = None
    for addr in list(t2_neighbors.keys()):
        if isinstance(ipaddress.ip_address(addr), IP_TYPE[a_family]):
            intf = list(t2_neighbors[addr].keys())[0]
            break
    if not intf:
        raise RuntimeError(
            "Couldn't find an interface to use "
            "for encap_type:{}".format(encap_type))

    if a_family == "v4":
        duthost.shell(
            "sudo config interface ip add {} 200.0.0.1/16".format(intf))
        for count in range(200):
            duthost.shell(
                "sudo arp -s 200.0.{}.2 0a:bb:cc:dd:ee:ff".format(count))
    else:
        duthost.shell(
            "sudo config interface ip add {} DDDD::200:0:0:1/64".format(intf))
        for count in range(200):
            duthost.shell(
                "sudo ip -6 neigh add DDDD::200:0:{}:2 "
                "lladdr 00:11:22:33:44:55 dev {}".format(count, intf))

    # We have setup 201 neighbors so far.
    yield 201

    if a_family == "v4":
        for count in range(200):
            duthost.shell("sudo arp -d 200.0.{}.2".format(count))
        duthost.shell(
            "sudo config interface ip remove {} 200.0.0.1/16".format(intf))
    else:
        for count in range(200):
            duthost.shell(
                "sudo ip -6 neigh del DDDD::200:0:{}:2 "
                "lladdr 00:11:22:33:44:55 dev {}".format(count, intf))
        duthost.shell(
            "sudo config interface ip remove {} DDDD::200:0:0:1/64".format(
                intf))


class Test_VxLAN_Crm(Test_VxLAN):
    '''
        Class for all testcases that verify Critical Resource Monitoring
        counters.
    '''
    # CRM tolerance
    tolerance = 0.90

    def crm_assert(self, crm_output, resource_name, required_increase):
        '''
           Helper function to verify the usage went up as per
           requirement.
        '''
        pytest_assert(
            crm_output[resource_name]['used'] >=
            self.setup['crm'][resource_name]['used'] +
            self.tolerance * required_increase,
            "CRM:{} usage didn't increase as needed:old:{}, "
            "new:{}, diff:{}, expected_diff:{}".format(
                resource_name,
                self.setup['crm'][resource_name]['used'],
                crm_output[resource_name]['used'],
                (self.setup['crm'][resource_name]['used'] -
                    crm_output[resource_name]['used']),
                required_increase))

    def test_crm_16k_routes(self, setUp, encap_type, setup_neighbors):
        '''
            Verify that the CRM counter values for ipv4_route, ipv4_nexthop,
            ipv6_route and ipv6_nexthop are updated as per the vxlan route
            configs.
        '''
        self.setup = setUp
        outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)

        number_of_routes_configured = 0
        set_of_unique_endpoints = set()

        for vnet in list(self.setup[encap_type]['dest_to_nh_map'].keys()):
            number_of_routes_configured += \
                len(list(self.setup[encap_type]['dest_to_nh_map'][vnet].keys()))

            dest_to_nh_map = self.setup[encap_type]['dest_to_nh_map'][vnet]
            for _, nexthops in list(dest_to_nh_map.items()):
                set_of_unique_endpoints = \
                    set_of_unique_endpoints | set(nexthops)

        crm_output = \
            self.setup['duthost'].get_crm_resources()['main_resources']

        self.crm_assert(
            crm_output,
            'ip{}_route'.format(outer_layer_version),
            number_of_routes_configured)
        self.crm_assert(
            crm_output,
            'ip{}_nexthop'.format(outer_layer_version),
            setup_neighbors)

    def nexthop_group_helper(self, encap_type):
        # number of nexthop groups configured:
        #  = number of unique-looking list of nexthops.
        # if destA:[nhA,nhB], and destB:[nhB,nhA], we have 1 nexthop group.
        list_of_nexthop_groups = set()
        for vnet in list(self.setup[encap_type]['dest_to_nh_map'].keys()):
            dest_to_nh_map = self.setup[encap_type]['dest_to_nh_map'][vnet]
            list_of_nexthop_groups = list_of_nexthop_groups | \
                set(tuple(i) for i in unique_in_list(
                    sort_and_deduplicate(list(dest_to_nh_map.values()))))

        number_of_nh_groups = 0
        number_of_nh_group_members = 0
        for nhg in list_of_nexthop_groups:
            if len(nhg) > 1:
                number_of_nh_groups += 1
                number_of_nh_group_members += len(nhg)
        return (number_of_nh_groups, number_of_nh_group_members)

    def test_crm_512_nexthop_groups(self, setUp, encap_type):
        '''
            Verify that the CRM counter values for nexthop_group is updated as
            per the vxlan route configs.
        '''
        self.setup = setUp
        Logger.info("Verifying encap_type:%s", encap_type)
        crm_output = \
            self.setup['duthost'].get_crm_resources()['main_resources']
        (number_of_nh_groups, number_of_group_members) = \
            self.nexthop_group_helper(encap_type)
        self.crm_assert(
            crm_output,
            'nexthop_group',
            number_of_nh_groups)

    def test_crm_128_group_members(self, setUp, encap_type):
        '''
            Verify that the CRM counter values for nexthop_group_member
            is updated as per the vxlan route configs.
        '''
        self.setup = setUp
        Logger.info("Verifying encap_type:%s", encap_type)
        crm_output = \
            self.setup['duthost'].get_crm_resources()['main_resources']
        (number_of_nh_groups, number_of_group_members) = \
            self.nexthop_group_helper(encap_type)
        self.crm_assert(
            crm_output,
            'nexthop_group_member',
            number_of_group_members)
