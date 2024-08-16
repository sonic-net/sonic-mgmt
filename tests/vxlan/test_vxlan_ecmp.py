#! /usr/bin/env python3

'''
    Script to automate the cases listed in VxLAN HLD document:
    https://github.com/sonic-net/SONiC/blob/8ca1ac93c8912fda7b09de9bfd51498e5038c292/doc/vxlan/Overlay%20ECMP%20with%20BFD.md#test-cases

    To test functionality:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s \
        -m individual -p /home/vxr/vxlan/logs/ -c 'vxlan/test_vxlan_ecmp.py'

    To test ECMP with 2 paths per destination:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -m individual \
            -p /home/vxr/vxlan/logs/ -c 'vxlan/test_vxlan_ecmp.py' \
            -e '--nhs_per_destination=2'

    To test ECMP+Scale(for all 4 types of encap):
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -m individual \
    -p /home/vxr/vxlan/logs/ \
    -c 'vxlan/test_vxlan_ecmp.py::Test_VxLAN_route_tests::\
       test_vxlan_single_endpoint' \
    -e '--ecmp_nhs_per_destination=128 --total_number_of_nexthops=32000' \
    -e '--total_number_of_endpoints=1024'

    To keep the temporary config files created in the DUT:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --keep_temp_files \
            -c 'vxlan/test_vxlan_ecmp.py'

    Other options:
        keep_temp_files             : Keep the temporary files created in the
                                      DUT. Default: False
        debug_enabled               : Enable debug mode, for debugging
                                      script. The temp files will
                                      not have timestamped names.
                                      Default: False
        dut_hostid                  : An integer in the range of 1 - 100 to be
                                      used as the host
                                      part of the IP address for DUT. Default:1
        ecmp_nhs_per_destination    : Number of ECMP next-hops per destination.
        total_number_of_endpoints   : Number of Endpoints (a pool of this
                                      number of ip addresses will used for
                                      next-hops). Default:2
        total_number_of_nexthops    : Maximum number of all nexthops for every
                                      destination combined(per encap_type).
        vxlan_port                  : Global vxlan port (UDP port) to be used
                                      for the DUT. Default: 4789
        bfd                         : Set it to True if you want to run all
                                      VXLAN cases with BFD Default: False
        include_long_tests          : Include the entropy, random-hash
                                      testcases, that take longer time.
                                      Default: False
'''

import time
import logging
from datetime import datetime
import json
import re
import pytest
import copy

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa: F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test           # noqa F401
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner
from tests.vxlan.vxlan_ecmp_utils import Ecmp_Utils

Logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()

# This is the list of encapsulations that will be tested in this script.
# v6_in_v4 means: V6 payload is encapsulated inside v4 outer layer.
# This list is used in many locations in the script.
SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v4_in_v6', 'v6_in_v4', 'v6_in_v6']
# Starting prefixes to be used for the destinations and End points.
DESTINATION_PREFIX = 150
NEXTHOP_PREFIX = 100

pytestmark = [
    # This script supports any T1 topology: t1, t1-64-lag, t1-56-lag, t1-lag.
    pytest.mark.topology("t1", "t1-64-lag", "t1-56-lag", "t1-lag")
]


@pytest.fixture(
    name="encap_type",
    scope="module",
    params=SUPPORTED_ENCAP_TYPES)
def fixture_encap_type(request):
    '''
        This fixture forces the script to perform one encap_type at a time.
        So this script doesn't support multiple encap types at the same.
    '''
    return request.param


@pytest.fixture(autouse=True)
def _ignore_route_sync_errlogs(rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(
            [
                ".*Unaccounted_ROUTE_ENTRY_TABLE_entries.*",
                ".*missed_in_asic_db_routes.*",
                ".*Look at reported mismatches above.*",
                ".*Unaccounted_ROUTE_ENTRY_TABLE_entries.*",
                ".*'vnetRouteCheck' status failed.*",
                ".*Vnet Route Mismatch reported.*",
                ".*_M_construct null not valid.*",
            ])
    return


def setup_crm_interval(duthost, interval):
    crm_stdout = duthost.shell("crm show summary")['stdout_lines']
    match = re.search("Polling Interval: ([0-9]*) second", "".join(crm_stdout))

    if match:
        current_polling_seconds = match.group(1)
    else:
        raise RuntimeError(
            "Couldn't parse the crm polling "
            "interval. output:{}".format(crm_stdout))
    duthost.shell("crm config polling interval {}".format(interval))
    return current_polling_seconds


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(duthosts,
                  ptfhost,
                  request,
                  rand_one_dut_hostname,
                  minigraph_facts,
                  tbinfo,
                  encap_type):
    '''
        Setup for the entire script.
        The basic steps in VxLAN configs are:
            1. Configure VxLAN tunnel.
            2. Configure Vnet and its VNI.
            3. Attach the Vnet to an interface(optional).
            4. Configure routes for the Vnet. The setup does all the above.

            The testcases are focused on the "configure routes" step. They add,
            delete, modify, the routes. Some cases modify the underlay itself,
            by add/delete bgp, or shut/start interfaces etc.
    '''

    data = {}
    asic_type = duthosts[rand_one_dut_hostname].facts["asic_type"]
    if asic_type in ["cisco-8000", "mellanox", "vs"]:
        data['tolerance'] = 0.03
    else:
        raise RuntimeError("Pls update this script for your platform.")

    platform = duthosts[rand_one_dut_hostname].facts['platform']
    if platform in ['x86_64-mlnx_msn2700-r0', 'x86_64-mlnx_msn2700a1-r0'] and encap_type in ['v4_in_v6', 'v6_in_v6']:
        pytest.skip("Skipping test. v6 underlay is not supported on Mlnx 2700")

    # Should I keep the temporary files copied to DUT?
    ecmp_utils.Constants['KEEP_TEMP_FILES'] = \
        request.config.option.keep_temp_files

    # Is debugging going on, or is it a production run? If it is a
    # production run, use time-stamped file names for temp files.
    ecmp_utils.Constants['DEBUG'] = request.config.option.debug_enabled

    # The host id in the ip addresses for DUT. It can be anything,
    # but helps to keep as a single number that is easy to identify
    # as DUT.
    ecmp_utils.Constants['DUT_HOSTID'] = request.config.option.dut_hostid

    Logger.info("Constants to be used in the script:%s", ecmp_utils.Constants)

    data['enable_bfd'] = request.config.option.bfd
    data['include_long_tests'] = request.config.option.include_long_tests
    data['monitor_file'] = '/tmp/bfd_responder_monitor_file.txt'
    data['ptfhost'] = ptfhost
    data['tbinfo'] = tbinfo
    data['duthost'] = duthosts[rand_one_dut_hostname]
    data['minigraph_facts'] = \
        data['duthost'].get_extended_minigraph_facts(tbinfo)
    data['dut_mac'] = data['duthost'].facts['router_mac']
    data['vxlan_port'] = request.config.option.vxlan_port
    data['original_crm_interval'] = setup_crm_interval(data['duthost'],
                                                       interval=3)
    time.sleep(4)
    data['crm'] = data['duthost'].get_crm_resources()['main_resources']
    ecmp_utils.configure_vxlan_switch(
        data['duthost'],
        vxlan_port=data['vxlan_port'],
        dutmac=data['dut_mac'])
    data['list_of_bfd_monitors'] = set()
    data['list_of_downed_endpoints'] = set()

    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    encap_type_data = {}
    encap_type_data['selected_interfaces'] = \
        ecmp_utils.select_required_interfaces(
            data['duthost'],
            number_of_required_interfaces=1,
            minigraph_data=minigraph_facts,
            af=outer_layer_version)

    # To store the names of the tunnels, for every outer layer version.
    tunnel_names = {}
    # To track the vnets for every outer_layer_version.
    vnet_af_map = {}
    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    try:
        tunnel_names[outer_layer_version]
    except KeyError:
        tunnel_names[outer_layer_version] = ecmp_utils.create_vxlan_tunnel(
            data['duthost'],
            minigraph_data=minigraph_facts,
            af=outer_layer_version)

    payload_version = ecmp_utils.get_payload_version(encap_type)
    encap_type = "{}_in_{}".format(payload_version, outer_layer_version)

    try:
        encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]
    except KeyError:
        vnet_af_map[outer_layer_version] = ecmp_utils.create_vnets(
            data['duthost'],
            tunnel_name=tunnel_names[outer_layer_version],
            vnet_count=1,     # default scope can take only one vnet.
            vnet_name_prefix="Vnet_" + encap_type,
            scope="default",
            vni_base=10000)
        encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]

    encap_type_data['vnet_intf_map'] = ecmp_utils.setup_vnet_intf(
        selected_interfaces=encap_type_data['selected_interfaces'],
        vnet_list=list(encap_type_data['vnet_vni_map'].keys()),
        minigraph_data=minigraph_facts)
    encap_type_data['intf_to_ip_map'] = ecmp_utils.assign_intf_ip_address(
        selected_interfaces=encap_type_data['selected_interfaces'],
        af=payload_version)
    encap_type_data['t2_ports'] = ecmp_utils.get_t2_ports(
        data['duthost'],
        minigraph_facts)
    encap_type_data['neighbor_config'] = ecmp_utils.configure_vnet_neighbors(
        data['duthost'],
        encap_type_data['intf_to_ip_map'],
        minigraph_data=minigraph_facts,
        af=payload_version)
    encap_type_data['dest_to_nh_map'] = ecmp_utils.create_vnet_routes(
        data['duthost'], list(encap_type_data['vnet_vni_map'].keys()),
        nhs_per_destination=request.config.option.ecmp_nhs_per_destination,
        number_of_available_nexthops=request.config.option.
        total_number_of_endpoints,
        number_of_ecmp_nhs=request.config.option.total_number_of_nexthops,
        dest_af=payload_version,
        dest_net_prefix=DESTINATION_PREFIX,
        nexthop_prefix=NEXTHOP_PREFIX,
        nh_af=outer_layer_version,
        bfd=request.config.option.bfd)

    data[encap_type] = encap_type_data
    for vnet in list(encap_type_data['dest_to_nh_map'].keys()):
        for dest in list(encap_type_data['dest_to_nh_map'][vnet].keys()):
            data['list_of_bfd_monitors'] = data['list_of_bfd_monitors'] |\
                set(encap_type_data['dest_to_nh_map'][vnet][dest])

    # Setting up bfd responder is needed only once per script run.
    loopback_addresses = \
        [str(x['addr']) for x in minigraph_facts['minigraph_lo_interfaces']]
    if request.config.option.bfd:
        ecmp_utils.start_bfd_responder(
            data['ptfhost'],
            data['dut_mac'],
            loopback_addresses,
            monitor_file=data['monitor_file'])
        # Add all endpoint_monitors to the bfd responder monitor.
        ecmp_utils.update_monitor_file(
            data['ptfhost'],
            data['monitor_file'],
            data[encap_type]['t2_ports'],
            list(data['list_of_bfd_monitors']))

    # This data doesn't change per testcase, so we copy
    # it as a seperate file. The test-specific config
    # data will be copied on testase basis.
    data['ptfhost'].copy(content=json.dumps(
        {
            'minigraph_facts': data['minigraph_facts'],
            'tbinfo': data['tbinfo']
        },
        indent=4), dest="/tmp/vxlan_topo_info.json")

    data['downed_endpoints'] = []
    data[encap_type]['dest_to_nh_map_orignal'] = copy.deepcopy(data[encap_type]['dest_to_nh_map']) # noqa F821
    yield data

    # Cleanup code.
    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    payload_version = ecmp_utils.get_payload_version(encap_type)

    ecmp_utils.set_routes_in_dut(
        data['duthost'],
        data[encap_type]['dest_to_nh_map'],
        payload_version,
        "DEL")

    for intf in data[encap_type]['selected_interfaces']:
        redis_string = "INTERFACE"
        if "PortChannel" in intf:
            redis_string = "PORTCHANNEL_INTERFACE"
        data['duthost'].shell("redis-cli -n 4 hdel \"{}|{}\""
                              "vnet_name".format(redis_string, intf))
        data['duthost'].shell(
            "for i in `redis-cli -n 4 --scan --pattern \"NEIGH|{}|*\" `; "
            "do redis-cli -n 4 del $i ; done".format(intf))

    # This script's setup code re-uses same vnets for v4inv4 and v6inv4.
    # There will be same vnet in multiple encap types.
    # So remove vnets *after* removing the routes first.
    for vnet in list(data[encap_type]['vnet_vni_map'].keys()):
        data['duthost'].shell("redis-cli -n 4 del \"VNET|{}\"".format(vnet))

    time.sleep(5)
    for tunnel in list(tunnel_names.values()):
        data['duthost'].shell(
            "redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))

    time.sleep(1)
    if request.config.option.bfd:
        ecmp_utils.stop_bfd_responder(data['ptfhost'])

    setup_crm_interval(data['duthost'], int(data['original_crm_interval']))


@pytest.fixture(scope="module")
def default_routes(setUp, encap_type):
    vnet = list(setUp[encap_type]['vnet_vni_map'].keys())[0]
    return setUp[encap_type]['dest_to_nh_map'][vnet]


@pytest.fixture(scope="module")
def routes_for_cleanup(setUp, encap_type):
    routes = {}

    yield routes

    # prepare for route cleanup by setUp on module finish
    vnet = list(setUp[encap_type]['vnet_vni_map'].keys())[0]
    setUp[encap_type]['dest_to_nh_map'][vnet] = routes


@pytest.fixture(autouse=True)
def _reset_test_routes(
        setUp,
        encap_type,
        default_routes,
        routes_for_cleanup):
    """
    The fixture makes sure each test uses the same route config
    not affected by previous test runs
    """
    vnet = list(setUp[encap_type]['vnet_vni_map'].keys())[0]

    test_routes = {}
    test_routes.update(default_routes)
    setUp[encap_type]['dest_to_nh_map'][vnet] = test_routes

    yield

    test_made_routes = setUp[encap_type]['dest_to_nh_map'][vnet]
    routes_for_cleanup.update(test_made_routes)


class Test_VxLAN():
    '''
        Base class for all VxLAN+BFD tests.
    '''
    vxlan_test_setup = {}

    def dump_self_info_and_run_ptf(self,
                                   tcname,
                                   encap_type,
                                   expect_encap_success,
                                   packet_count=4,
                                   random_dport=True,
                                   random_sport=False,
                                   random_src_ip=False,
                                   tolerance=None,
                                   payload=None,
                                   skip_traffic_test=False):        # noqa F811
        '''
           Just a wrapper for dump_info_to_ptf to avoid entering 30 lines
           everytime.
        '''

        if tolerance is None:
            tolerance = self.vxlan_test_setup['tolerance']
        if ecmp_utils.Constants['DEBUG']:
            config_filename = "/tmp/vxlan_configs.json"
        else:
            config_filename = "/tmp/vxlan_configs." + tcname +\
                "-" + encap_type + "-" + str(time.time()) + ".json"
        self.vxlan_test_setup['ptfhost'].copy(content=json.dumps(
            {
                'vnet_vni_map': self.vxlan_test_setup[encap_type]['vnet_vni_map'],
                'vnet_intf_map': self.vxlan_test_setup[encap_type]['vnet_intf_map'],
                'dest_to_nh_map': self.vxlan_test_setup[encap_type]['dest_to_nh_map'],
                'neighbors': self.vxlan_test_setup[encap_type]['neighbor_config'],
                'intf_to_ip_map': self.vxlan_test_setup[encap_type]['intf_to_ip_map'],
            },
            indent=4), dest=config_filename)

        Logger.info("Recording current DUT state.")
        cmds = [
            "show vxlan tunnel",
            "show vnet route all",
            "show ip bgp summary",
            "show ipv6 bgp summary"]
        if self.vxlan_test_setup['enable_bfd']:
            cmds.append("show bfd summary")
        for cmd in cmds:
            self.vxlan_test_setup['duthost'].shell(cmd)

        ptf_params = {
            "topo_file": "/tmp/vxlan_topo_info.json",
            "config_file": config_filename,
            "t0_ports": ecmp_utils.get_ethernet_ports(
                self.vxlan_test_setup[encap_type]['selected_interfaces'],
                self.vxlan_test_setup['minigraph_facts']),
            "t2_ports": self.vxlan_test_setup[encap_type]['t2_ports'],
            "dut_mac": self.vxlan_test_setup['dut_mac'],
            "vxlan_port": self.vxlan_test_setup['vxlan_port'],
            "expect_encap_success": expect_encap_success,
            "packet_count": packet_count,
            "random_dport": random_dport,
            "random_sport": random_sport,
            "random_src_ip": random_src_ip,
            "tolerance": tolerance,
            "downed_endpoints": list(self.vxlan_test_setup['list_of_downed_endpoints'])
        }
        Logger.info("ptf arguments:%s", ptf_params)
        Logger.info(
            "dest->nh mapping:%s", self.vxlan_test_setup[encap_type]['dest_to_nh_map'])

        if skip_traffic_test is True:
            Logger.info("Skipping traffic test.")
            return
        ptf_runner(self.vxlan_test_setup['ptfhost'],
                   "ptftests",
                   "vxlan_traffic.VxLAN_in_VxLAN" if payload == 'vxlan'
                   else "vxlan_traffic.VXLAN",
                   platform_dir="ptftests",
                   params=ptf_params,
                   qlen=1000,
                   log_file="/tmp/vxlan-tests.{}.{}.{}.log".format(
                       tcname,
                       encap_type,
                       datetime.now().strftime('%Y-%m-%d-%H:%M:%S')),
                   is_python3=True)

    def update_monitor_list(self, bfd_enable, encap_type, ip_address_list):
        '''
            Local function to update the bfd_responder's monitor file that
            tracks which interfaces and ip addresses the bfd_responder will
            work with.
        '''
        if not bfd_enable:
            return
        if isinstance(ip_address_list, str):
            ip_address_list = [ip_address_list]
        self.vxlan_test_setup['list_of_bfd_monitors'] = \
            self.vxlan_test_setup['list_of_bfd_monitors'] | set(ip_address_list)
        ecmp_utils.update_monitor_file(
            self.vxlan_test_setup['ptfhost'],
            self.vxlan_test_setup['monitor_file'],
            self.vxlan_test_setup[encap_type]['t2_ports'],
            list(self.vxlan_test_setup['list_of_bfd_monitors']))

    def update_down_list(self, bfd_enable, encap_type, ip_address_list):
        '''
            Local function to keep track of endpoint monitors that are down.
            The bfd_responder will not be replying to any packet with these
            addresses.
        '''
        if not bfd_enable:
            return
        if isinstance(ip_address_list, str):
            ip_address_list = [ip_address_list]
        self.vxlan_test_setup['list_of_downed_endpoints'] = \
            self.vxlan_test_setup['list_of_downed_endpoints'] | set(ip_address_list)
        self.vxlan_test_setup['list_of_bfd_monitors'] = \
            self.vxlan_test_setup['list_of_bfd_monitors'] - set(ip_address_list)
        ecmp_utils.update_monitor_file(
            self.vxlan_test_setup['ptfhost'],
            self.vxlan_test_setup['monitor_file'],
            self.vxlan_test_setup[encap_type]['t2_ports'],
            list(self.vxlan_test_setup['list_of_bfd_monitors']))


class Test_VxLAN_route_tests(Test_VxLAN):
    '''
        Common class for the basic route test cases.
    '''

    def test_vxlan_single_endpoint(self, setUp, encap_type, skip_traffic_test):     # noqa F811
        '''
            tc1:Create a tunnel route to a single endpoint a.
            Send packets to the route prefix dst.
        '''
        self.vxlan_test_setup = setUp
        self.dump_self_info_and_run_ptf("tc1", encap_type, True, skip_traffic_test=skip_traffic_test)
        self.dump_self_info_and_run_ptf("tc1", encap_type, True,
                                        payload="vxlan", skip_traffic_test=skip_traffic_test)

    def test_vxlan_modify_route_different_endpoint(
            self, setUp, request, encap_type, skip_traffic_test):       # noqa F811
        '''
            tc2: change the route to different endpoint.
            Packets are received only at endpoint b.")
        '''
        self.vxlan_test_setup = setUp
        Logger.info("Choose a vnet")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Choose a destination, which is already present.")
        tc2_dest = list(self.vxlan_test_setup[encap_type]
                        ['dest_to_nh_map'][vnet].keys())[0]

        Logger.info("Create a new endpoint, or endpoint-list.")
        tc2_new_end_point_list = []
        for _ in range(int(request.config.option.ecmp_nhs_per_destination)):
            tc2_new_end_point_list.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))

        Logger.info("Map the destination to the new endpoint(s).")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc2_dest] = \
            tc2_new_end_point_list

        Logger.info("Create the json and apply the config in the DUT swss.")
        # The config looks like:
        # [
        #   {
        #     "VNET_ROUTE_TUNNEL_TABLE:vnet:tc2_dest/32": {
        #       "endpoint": "{tc2_new_end_point_list}"
        #       "endpoint_monitor": "{tc2_new_end_point_list}"
        #     },
        #     "OP": "{}"
        #   }
        # ]
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc2_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            tc2_new_end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            tc2_new_end_point_list)

        Logger.info(
            "Copy the new set of configs to the PTF and run the tests.")
        self.dump_self_info_and_run_ptf("tc2", encap_type, True, skip_traffic_test=skip_traffic_test)

    def test_vxlan_remove_all_route(self, setUp, encap_type, skip_traffic_test):        # noqa F811
        '''
            tc3: remove the tunnel route.
            Send packets to the route prefix dst. packets should not
            be received at any ports with dst ip of b")
        '''
        self.vxlan_test_setup = setUp
        try:
            Logger.info("Remove the existing routes in the DUT.")
            ecmp_utils.set_routes_in_dut(
                self.vxlan_test_setup['duthost'],
                self.vxlan_test_setup[encap_type]['dest_to_nh_map'],
                ecmp_utils.get_payload_version(encap_type),
                "DEL")
            Logger.info("Verify that the traffic is not coming back.")
            self.dump_self_info_and_run_ptf("tc3", encap_type, False, skip_traffic_test=skip_traffic_test)
        finally:
            Logger.info("Restore the routes in the DUT.")
            ecmp_utils.set_routes_in_dut(
                self.vxlan_test_setup['duthost'],
                self.vxlan_test_setup[encap_type]['dest_to_nh_map'],
                ecmp_utils.get_payload_version(encap_type),
                "SET",
                bfd=self.vxlan_test_setup['enable_bfd'])


class Test_VxLAN_ecmp_create(Test_VxLAN):
    '''
        Class for all the ECMP (multiple nexthops per destination)
        create testcases.
    '''

    def test_vxlan_configure_route1_ecmp_group_a(self, setUp, encap_type, skip_traffic_test):       # noqa F811
        '''
            tc4:create tunnel route 1 with two endpoints a = {a1, a2...}. send
            packets to the route 1's prefix dst. packets are received at either
            a1 or a2.
        '''
        self.vxlan_test_setup = setUp

        Logger.info("Choose a vnet.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Create a new list of endpoint(s).")
        tc4_end_point_list = []
        for _ in range(2):
            tc4_end_point_list.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))

        Logger.info("Create a new destination")
        tc4_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)

        Logger.info("Map the new destination and the new endpoint(s).")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = \
            tc4_end_point_list

        Logger.info("Create a new config and Copy to the DUT.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc4_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            tc4_end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'], encap_type, tc4_end_point_list)

        Logger.info("Verify that the new config takes effect and run traffic.")

        self.dump_self_info_and_run_ptf("tc4", encap_type, True, skip_traffic_test=skip_traffic_test)
        # Add vxlan payload testing as well.
        self.dump_self_info_and_run_ptf("tc4", encap_type, True,
                                        payload="vxlan", skip_traffic_test=skip_traffic_test)

    def test_vxlan_remove_ecmp_route1(self, setUp, encap_type, skip_traffic_test):      # noqa F811
        '''
            Remove tunnel route 1. Send multiple packets (varying tuple) to the
            route 1's prefix dst.
        '''
        self.vxlan_test_setup = setUp

        Logger.info("Choose a vnet.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        backup_dest = copy.deepcopy(self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet])

        Logger.info("Create a new list of endpoint(s).")
        ecmp_route1_end_point_list = []
        for _ in range(2):
            ecmp_route1_end_point_list.append(
                ecmp_utils.get_ip_address(
                    af=ecmp_utils.get_outer_layer_version(encap_type),
                    netid=NEXTHOP_PREFIX))

        Logger.info("Create a new destination")
        ecmp_route1_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)

        Logger.info("Map the new destination and the new endpoint(s).")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][ecmp_route1_new_dest] =\
            ecmp_route1_end_point_list

        Logger.info("Create a new config and Copy to the DUT.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            ecmp_route1_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            ecmp_route1_end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            ecmp_route1_end_point_list)

        Logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf("tc5", encap_type, True, skip_traffic_test=skip_traffic_test)

        # Deleting Tunnel route 1
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            ecmp_route1_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            ecmp_route1_end_point_list,
            "DEL")

        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet] =\
            {ecmp_route1_new_dest: ecmp_route1_end_point_list}

        Logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf("tc5", encap_type, False, skip_traffic_test=skip_traffic_test)

        # Restoring dest_to_nh_map to old values
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet] = copy.deepcopy(backup_dest)
        self.dump_self_info_and_run_ptf("tc5", encap_type, True, skip_traffic_test=skip_traffic_test)

    def test_vxlan_configure_route1_ecmp_group_b(self, setUp, encap_type, skip_traffic_test):       # noqa F811
        '''
            tc5: set tunnel route 2 to endpoint group a = {a1, a2}. send
            packets to route 2"s prefix dst. packets are received at either a1
            or a2
        '''
        self.vxlan_test_setup = setUp
        self.setup_route2_ecmp_group_b(encap_type)
        Logger.info("Verify the configs work and traffic flows correctly.")
        self.dump_self_info_and_run_ptf("tc5", encap_type, True, skip_traffic_test=skip_traffic_test)

    def setup_route2_ecmp_group_b(self, encap_type):
        '''
            Function for handling the dependency of tc6 on tc5. This function
            is essentially tc5.
        '''
        if self.vxlan_test_setup[encap_type].get('tc5_dest', None):
            return
        Logger.info("Choose a vnet for testing.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Select an existing endpoint.")
        tc5_end_point_list = \
            list(self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet].values())[0]

        Logger.info("Create a new destination to use.")
        tc5_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)

        Logger.info("Map the new destination to the endpoint.")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc5_new_dest] = \
            tc5_end_point_list

        Logger.info("Create the new config and apply to the DUT.")

        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc5_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            tc5_end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            tc5_end_point_list)

        self.vxlan_test_setup[encap_type]['tc5_dest'] = tc5_new_dest

    def test_vxlan_configure_route2_ecmp_group_b(self, setUp, encap_type, skip_traffic_test):       # noqa F811
        '''
            tc6: set tunnel route 2 to endpoint group b = {b1, b2}. send
            packets to route 2"s prefix dst. packets are received at either
            b1 or b2.
        '''
        self.vxlan_test_setup = setUp
        self.setup_route2_ecmp_group_b(encap_type)

        Logger.info("Choose a vnet for testing.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Create a new list of endpoints.")
        tc6_end_point_list = []
        for _ in range(2):
            tc6_end_point_list.append(
                ecmp_utils.get_ip_address(
                    af=ecmp_utils.get_outer_layer_version(encap_type),
                    netid=NEXTHOP_PREFIX))

        Logger.info("Choose one of the existing destinations.")
        tc6_new_dest = self.vxlan_test_setup[encap_type]['tc5_dest']

        Logger.info("Map the destination to the new endpoints.")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc6_new_dest] = \
            tc6_end_point_list

        Logger.info("Create the config and apply on the DUT.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc6_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            tc6_end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            tc6_end_point_list)
        Logger.info("Verify that the traffic works.")

        self.dump_self_info_and_run_ptf("tc6", encap_type, True, skip_traffic_test=skip_traffic_test)

    @pytest.mark.skipif(
        "config.option.bfd is False",
        reason="This test will be run only if '--bfd=True' is provided.")
    def test_vxlan_bfd_health_state_change_a2down_a1up(
            self, setUp, encap_type, skip_traffic_test):        # noqa F811
        '''
            Set BFD state for a1' to UP and a2' to Down. Send multiple packets
            (varying tuple) to the route 1's prefix dst. Packets are received
            only at endpoint a1. Verify advertise table is present.
        '''
        self.vxlan_test_setup = setUp

        Logger.info("Choose a vnet.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for _ in range(2):
            end_point_list.append(
                ecmp_utils.get_ip_address(
                    af=ecmp_utils.get_outer_layer_version(encap_type),
                    netid=NEXTHOP_PREFIX))

        Logger.info("Create a new destination")
        tc4_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)

        Logger.info("Map the new destination and the new endpoint(s).")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = \
            end_point_list

        Logger.info("Create a new config and Copy to the DUT.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc4_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        # Only a1 is up, bfd-responder will not respond to a2.
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            end_point_list[0])
        self.update_down_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            end_point_list[1])

        Logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf("tc_a2down_a1up", encap_type, True, skip_traffic_test=skip_traffic_test)

    @pytest.mark.skipif(
        "config.option.bfd is False",
        reason="This test will be run only if '--bfd=True' is provided.")
    def test_vxlan_bfd_health_state_change_a1a2_down(self, setUp, encap_type, skip_traffic_test):       # noqa F811
        '''
            Set BFD state for a1' to Down and a2' to Down. Send multiple
            packets (varying tuple) to the route 1's prefix dst. Packets
            are not received at any ports. Verify advertise table is removed.
        '''
        self.vxlan_test_setup = setUp

        Logger.info("Choose a vnet.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for _ in range(2):
            end_point_list.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))

        Logger.info("Create a new destination")
        tc4_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)

        Logger.info("Map the new destination and the new endpoint(s).")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = \
            end_point_list

        Logger.info("Create a new config and Copy to the DUT.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc4_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        # No adding to the monitor_list.
        self.update_down_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            end_point_list)

        Logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf(
            "a1a2_down",
            encap_type,
            True,
            packet_count=4,
            skip_traffic_test=skip_traffic_test)

    @pytest.mark.skipif(
        "config.option.bfd is False",
        reason="This test will be run only if '--bfd=True' is provided.")
    def test_vxlan_bfd_health_state_change_a2up_a1down(
            self, setUp, encap_type, skip_traffic_test):        # noqa F811
        '''
            Set BFD state for a2' to UP. Send packets to the route 1's prefix
            dst. Packets are received only at endpoint a2. Verify advertise
            table is present
        '''
        self.vxlan_test_setup = setUp

        Logger.info("Choose a vnet.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for _ in range(2):
            end_point_list.append(
                ecmp_utils.get_ip_address(
                    af=ecmp_utils.get_outer_layer_version(encap_type),
                    netid=NEXTHOP_PREFIX))

        Logger.info("Create a new destination")
        tc4_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)

        Logger.info("Map the new destination and the new endpoint(s).")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = \
            end_point_list

        Logger.info("Create a new config and Copy to the DUT.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc4_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        # Only a2 is up, but a1 is down.
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            end_point_list[1])
        self.update_down_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            end_point_list[0])

        Logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf("a2up_a1down", encap_type, True, skip_traffic_test=skip_traffic_test)

    def test_vxlan_bfd_health_state_change_a1a2_up(self, setUp, encap_type, skip_traffic_test):     # noqa F811
        '''
            Set BFD state for a1' & a2' to UP. Send multiple packets (varying
            tuple) to the route 1's prefix dst. Packets are received at both
            a1 and a2. Verify advertise table is present
        '''
        self.vxlan_test_setup = setUp

        Logger.info("Choose a vnet.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for _ in range(2):
            end_point_list.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))

        Logger.info("Create a new destination")
        tc4_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)

        Logger.info("Map the new destination and the new endpoint(s).")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = \
            end_point_list

        Logger.info("Create a new config and Copy to the DUT.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc4_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            end_point_list)

        Logger.info("Verify that the new config takes effect and run traffic.")

        self.dump_self_info_and_run_ptf("tc4", encap_type, True, skip_traffic_test=skip_traffic_test)

        # perform cleanup by removing all the routes added by this test class.
        # reset to add only the routes added in the setup phase.
        ecmp_utils.set_routes_in_dut(
            self.vxlan_test_setup['duthost'],
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'],
            ecmp_utils.get_payload_version(encap_type),
            "DEL")

        self.vxlan_test_setup[encap_type]['dest_to_nh_map'] = copy.deepcopy(self.vxlan_test_setup[encap_type]['dest_to_nh_map_orignal']) # noqa F821
        ecmp_utils.set_routes_in_dut(
            self.vxlan_test_setup['duthost'],
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'],
            ecmp_utils.get_payload_version(encap_type),
            "SET")


class Test_VxLAN_NHG_Modify(Test_VxLAN):
    '''
       Class for all the next-hop group modification testcases.
    '''

    def setup_route2_single_endpoint(self, encap_type):
        '''
            Function to handle dependency of tc9 on tc8.
        '''
        Logger.info("Pick a vnet for testing.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info(
            "Choose a route 2 destination and a new single endpoint for it.")
        tc8_new_dest = list(
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet].keys())[0]
        tc8_new_nh = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_outer_layer_version(encap_type),
            netid=NEXTHOP_PREFIX)
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc8_new_dest] = \
            [tc8_new_nh]
        Logger.info(
            "Using destinations: dest:%s => nh:%s",
            tc8_new_dest,
            tc8_new_nh)

        Logger.info("Map the destination and new endpoint.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc8_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            [tc8_new_nh],
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            tc8_new_nh)

        Logger.info("Apply the new config in the DUT and run traffic test.")
        self.vxlan_test_setup[encap_type]['tc8_dest'] = tc8_new_dest

    def setup_route2_shared_endpoints(self, encap_type):
        '''
            Function to handle dependency of tc10 on tc9
        '''
        self.setup_route2_single_endpoint(encap_type)

        Logger.info("Choose a vnet for testing.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info(
            "Select 2 already existing destinations. "
            "They must have 2 different nexthops.")
        tc9_new_dest1 = self.vxlan_test_setup[encap_type]['tc8_dest']
        nh1 = self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1][0]

        nh2 = None
        for dest in list(self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet].keys()):
            nexthops = self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][dest]
            for nh in nexthops:
                if nh == nh1:
                    continue
                else:
                    nh2 = nh
                    break
        if nh2:
            Logger.info(
                "Using destinations: dest:%s, nexthops:%s, %s",
                tc9_new_dest1,
                nh1,
                nh2)
        else:
            raise RuntimeError(
                "Couldnot find different nexthop for this test."
                "The current list: {}".format(
                    self.vxlan_test_setup[encap_type]['dest_to_nh_map']))

        Logger.info(
            "Use the selected nexthops(tunnel endpoints)."
            "They are guaranteed to be different.")
        tc9_new_nhs = [nh1, nh2]

        Logger.info("Map the destination 1 to the combined list.")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1] = \
            tc9_new_nhs

        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc9_new_dest1,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            tc9_new_nhs,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            tc9_new_nhs)

        self.vxlan_test_setup[encap_type]['tc9_dest'] = tc9_new_dest1

    def setup_route2_shared_different_endpoints(self, encap_type):
        '''
            Function to handle dependency of tc9.2 on tc9
        '''
        self.setup_route2_single_endpoint(encap_type)

        Logger.info("Choose a vnet for testing.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info(
            "Select 2 already existing destinations. "
            "They must have 2 different nexthops.")
        tc9_new_dest1 = self.vxlan_test_setup[encap_type]['tc8_dest']
        old_nh = \
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1][0]

        tc9_new_nh = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_outer_layer_version(encap_type),
            netid=NEXTHOP_PREFIX)
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1] = \
            [tc9_new_nh]

        nh1 = None
        nh2 = None
        for dest in list(self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet].keys()):
            nexthops = self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][dest]
            for nh in nexthops:
                if nh == old_nh:
                    continue
                else:
                    if not nh1:
                        nh1 = nh
                    elif not nh2:
                        if nh != nh1:
                            nh2 = nh
                            break
        if nh2:
            Logger.info(
                "Using destinations: dest:%s, nexthops:%s, %s",
                tc9_new_dest1,
                nh1,
                nh2)
        else:
            raise RuntimeError(
                "Couldnot find different nexthop for this test."
                "The current list: {}".format(
                    self.vxlan_test_setup[encap_type]['dest_to_nh_map']))

        Logger.info(
            "Use the selected nexthops(tunnel endpoints)."
            "They are guaranteed to be different.")
        tc9_new_nhs = [nh1, nh2]

        Logger.info("Map the destination 1 to the combined list.")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1] = \
            tc9_new_nhs
        self.vxlan_test_setup[encap_type]['tc9_dest'] = tc9_new_dest1
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc9_new_dest1,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            tc9_new_nhs,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            tc9_new_nhs)

    def test_vxlan_remove_route2(self, setUp, encap_type, skip_traffic_test):       # noqa F811
        '''
            tc7:send packets to route 1's prefix dst. by removing route 2 from
            group a, no change expected to route 1.
        '''
        self.vxlan_test_setup = setUp

        Logger.info("Pick a vnet for testing.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info(
            "Setup: Create two destinations with the same endpoint group.")
        tc7_end_point_list = []
        for _ in range(2):
            tc7_end_point_list.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))

        tc7_destinations = []
        for _ in range(2):
            tc7_destinations.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_payload_version(encap_type),
                netid=DESTINATION_PREFIX))
        dest_nh_map = self.vxlan_test_setup[encap_type]['dest_to_nh_map']
        Logger.info("Map the new destinations to the same endpoint list.")
        for i in range(2):
            dest_nh_map[vnet][tc7_destinations[i]] = \
                tc7_end_point_list

        Logger.info("Apply the setup configs to the DUT.")
        payload_af = ecmp_utils.get_payload_version(encap_type)
        for i in range(2):
            ecmp_utils.create_and_apply_config(
                self.vxlan_test_setup['duthost'],
                vnet,
                tc7_destinations[i],
                ecmp_utils.HOST_MASK[payload_af],
                tc7_end_point_list,
                "SET",
                bfd=self.vxlan_test_setup['enable_bfd'])

        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            tc7_end_point_list)
        Logger.info("Verify the setup works.")
        self.dump_self_info_and_run_ptf("tc7", encap_type, True, skip_traffic_test=skip_traffic_test)
        Logger.info("End of setup.")

        Logger.info("Remove one of the routes.")
        Logger.info("Pick one out of the two TC7 destinations.")
        tc7_removed_dest = tc7_destinations[0]
        tc7_removed_endpoint = \
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc7_removed_dest]
        del self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc7_removed_dest]

        Logger.info("Remove the chosen dest/endpoint from the DUT.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc7_removed_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            tc7_removed_endpoint,
            "DEL")

        Logger.info("Verify the rest of the traffic still works.")
        self.dump_self_info_and_run_ptf("tc7", encap_type, True, skip_traffic_test=skip_traffic_test)

        # perform cleanup by removing all the routes added by this test class.
        # reset to add only the routes added in the setup phase.
        ecmp_utils.set_routes_in_dut(
            self.vxlan_test_setup['duthost'],
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'],
            ecmp_utils.get_payload_version(encap_type),
            "DEL")

        self.vxlan_test_setup[encap_type]['dest_to_nh_map'] = copy.deepcopy(self.vxlan_test_setup[encap_type]['dest_to_nh_map_orignal']) # noqa F821
        ecmp_utils.set_routes_in_dut(
            self.vxlan_test_setup['duthost'],
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'],
            ecmp_utils.get_payload_version(encap_type),
            "SET")

    def test_vxlan_route2_single_nh(self, setUp, encap_type, skip_traffic_test):        # noqa F811
        '''
            tc8: set tunnel route 2 to single endpoint b1.
            Send packets to route 2's prefix dst.
        '''
        self.vxlan_test_setup = setUp
        self.setup_route2_single_endpoint(encap_type)
        self.dump_self_info_and_run_ptf("tc8", encap_type, True, skip_traffic_test=skip_traffic_test)
        self.dump_self_info_and_run_ptf("tc8", encap_type, True,
                                        payload="vxlan", skip_traffic_test=skip_traffic_test)

    def test_vxlan_route2_shared_nh(self, setUp, encap_type, skip_traffic_test):        # noqa F811
        '''
            tc9: set tunnel route 2 to shared endpoints a1 and b1.
            Send packets to route 2's
            prefix dst.
        '''
        self.vxlan_test_setup = setUp
        self.setup_route2_shared_endpoints(encap_type)
        self.dump_self_info_and_run_ptf("tc9", encap_type, True, skip_traffic_test=skip_traffic_test)

    def test_vxlan_route2_shared_different_nh(self, setUp, encap_type, skip_traffic_test):      # noqa F811
        '''
            tc9.2: set tunnel route 2 to 2 completely different
            shared(no-reuse) endpoints a1 and b1. send packets
            to route 2's prefix dst.
        '''
        self.vxlan_test_setup = setUp
        self.setup_route2_shared_different_endpoints(encap_type)
        self.dump_self_info_and_run_ptf("tc9.2", encap_type, True, skip_traffic_test=skip_traffic_test)

    def test_vxlan_remove_ecmp_route2(self, setUp, encap_type, skip_traffic_test):      # noqa F811
        '''
            tc10: remove tunnel route 2. send packets to route 2's prefix dst.
        '''
        self.vxlan_test_setup = setUp
        self.setup_route2_shared_endpoints(encap_type)
        Logger.info("Backup the current route config.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]
        full_map = self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet].copy()
        payload_af = ecmp_utils.get_payload_version(encap_type)

        Logger.info(
            "This is to keep track if the selected route "
            "should be deleted in the end.")
        del_needed = False
        try:
            Logger.info("Choose a vnet for testing.")

            Logger.info("Choose a destination and its nhs to delete.")
            tc10_dest = self.vxlan_test_setup[encap_type]['tc9_dest']
            tc10_nhs = \
                self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest]
            Logger.info(
                "Using destination: dest:%s, nh:%s",
                tc10_dest,
                tc10_nhs)

            Logger.info("Delete the dest and nh in the DUT.")
            ecmp_utils.create_and_apply_config(
                self.vxlan_test_setup['duthost'],
                vnet,
                tc10_dest,
                ecmp_utils.HOST_MASK[payload_af],
                tc10_nhs,
                "DEL")

            del_needed = True

            Logger.info(
                "We should pass only the deleted entry to the ptf call,"
                "and expect encap to fail.")
            Logger.info(
                "Clear out the mappings, and keep only "
                "the deleted dest and nhs.")
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet] = {}
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest] =\
                tc10_nhs

            Logger.info("The deleted route should fail to receive traffic.")
            self.dump_self_info_and_run_ptf("tc10", encap_type, False, skip_traffic_test=skip_traffic_test)

            # all others should be working.
            # Housekeeping:
            Logger.info("Restore the mapping of dest->nhs.")
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet] = full_map.copy()
            Logger.info("Remove the deleted entry alone.")
            del self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest]
            del_needed = False

            Logger.info("Check the traffic is working in the other routes.")
            self.dump_self_info_and_run_ptf("tc10", encap_type, True, skip_traffic_test=skip_traffic_test)

        except BaseException:
            self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet] = full_map.copy()
            Logger.info("Remove the deleted entry alone.")
            if del_needed:
                del self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest]
            raise


@pytest.mark.skipif(
    "config.option.include_long_tests is False",
    reason="This test will be run only if "
           "'--include_long_tests=True' is provided.")
class Test_VxLAN_ecmp_random_hash(Test_VxLAN):
    '''
        Class for testing different tcp ports for payload.
    '''

    def test_vxlan_random_hash(self, setUp, encap_type, skip_traffic_test):     # noqa F811
        '''
            tc11: set tunnel route 3 to endpoint group c = {c1, c2, c3}.
            Ensure c1, c2, and c3 matches to underlay default route.
            Send 1000 pkt with random hash to route 3's prefix dst.
        '''
        self.vxlan_test_setup = setUp

        Logger.info("Chose a vnet for testing.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Create a new destination and 3 nhs for it.")
        tc11_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)

        tc11_new_nhs = []
        for _ in range(3):
            tc11_new_nhs.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))

        # the topology always provides the default routes for any ip address.
        # so it is already taken care of.

        Logger.info("Map the new dest and nhs.")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][tc11_new_dest] =\
            tc11_new_nhs
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            tc11_new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            tc11_new_nhs,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            tc11_new_nhs)

        Logger.info(
            "Apply the config in the DUT and verify traffic. "
            "The random hash and ECMP check is already taken care of in the "
            "VxLAN PTF script.")
        self.dump_self_info_and_run_ptf(
            "tc11",
            encap_type,
            True,
            packet_count=1000,
            skip_traffic_test=skip_traffic_test)


@pytest.mark.skipif(
    "config.option.include_long_tests is False",
    reason="This test will be run only if "
           "'--include_long_tests=True' is provided.")
class Test_VxLAN_underlay_ecmp(Test_VxLAN):
    '''
        Class for all test cases that modify the underlay default route.
    '''
    @pytest.mark.parametrize("ecmp_path_count", [1, 2])
    def test_vxlan_modify_underlay_default(
            self, setUp, minigraph_facts, encap_type, ecmp_path_count, skip_traffic_test):      # noqa F811
        '''
            tc12: modify the underlay default route nexthop/s. send packets to
            route 3's prefix dst.
        '''
        self.vxlan_test_setup = setUp
        '''
        First step: pick one or two of the interfaces connected to t2, and
        bring them down. verify that the encap is still working, and ptf
        receives the traffic.  Bring them back up.
        After that, bring down all the other t2 interfaces, other than
        the ones used in the first step. This will force a modification
        to the underlay default routes nexthops.
        '''

        all_t2_intfs = list(ecmp_utils.get_portchannels_to_neighbors(
            self.vxlan_test_setup['duthost'],
            "T2",
            minigraph_facts))

        if not all_t2_intfs:
            all_t2_intfs = ecmp_utils.get_ethernet_to_neighbors(
                "T2",
                minigraph_facts)
        Logger.info("Dumping T2 link info: %s", all_t2_intfs)
        if not all_t2_intfs:
            raise RuntimeError(
                "No interface found connected to t2 neighbors. "
                "pls check the testbed, aborting.")

        # Keep a copy of the internal housekeeping list of t2 ports.
        # This is the full list of DUT ports connected to T2 neighbors.
        # It is one of the arguments to the ptf code.
        all_t2_ports = list(self.vxlan_test_setup[encap_type]['t2_ports'])

        # A distinction in this script between ports and interfaces:
        # Ports are physical (Ethernet) only.
        # Interfaces have IP address(Ethernet or PortChannel).
        try:
            selected_intfs = []
            # Choose some intfs based on the parameter ecmp_path_count.
            # when ecmp_path_count == 1, it is non-ecmp. The switching
            # happens between ecmp and non-ecmp. Otherwise, the switching
            # happens within ecmp only.
            for i in range(ecmp_path_count):
                selected_intfs.append(all_t2_intfs[i])

            for intf in selected_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface shutdown {}".format(intf))
            downed_ports = ecmp_utils.get_corresponding_ports(
                selected_intfs,
                minigraph_facts)
            self.vxlan_test_setup[encap_type]['t2_ports'] = \
                list(set(all_t2_ports) - set(downed_ports))
            downed_bgp_neighbors = ecmp_utils.get_downed_bgp_neighbors(
                selected_intfs, minigraph_facts)
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost'],
                    down_list=downed_bgp_neighbors),
                "BGP neighbors didn't come up after all "
                "interfaces have been brought up.")
            time.sleep(10)
            self.dump_self_info_and_run_ptf(
                "tc12",
                encap_type,
                True,
                packet_count=1000,
                skip_traffic_test=skip_traffic_test)

            Logger.info(
                "Reverse the action: bring up the selected_intfs"
                " and shutdown others.")
            for intf in selected_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            Logger.info("Shutdown other interfaces.")
            remaining_interfaces = list(
                set(all_t2_intfs) - set(selected_intfs))
            for intf in remaining_interfaces:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface shutdown {}".format(intf))
            downed_bgp_neighbors = ecmp_utils.get_downed_bgp_neighbors(
                remaining_interfaces,
                minigraph_facts)
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost'],
                    down_list=downed_bgp_neighbors),
                "BGP neighbors didn't come up after all interfaces have been"
                "brought up.")
            self.vxlan_test_setup[encap_type]['t2_ports'] = \
                ecmp_utils.get_corresponding_ports(
                    selected_intfs,
                    minigraph_facts)

            '''
            Need to update the bfd_responder to listen only on the sub-set of
            T2 ports that are active. If we still receive packets on the
            downed ports, we have a problem!
            '''
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            time.sleep(10)
            self.dump_self_info_and_run_ptf(
                "tc12",
                encap_type,
                True,
                packet_count=1000,
                skip_traffic_test=skip_traffic_test)

            Logger.info("Recovery. Bring all up, and verify traffic works.")
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            Logger.info("Wait for all bgp is up.")
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost']),
                "BGP neighbors didn't come up after "
                "all interfaces have been brought up.")
            Logger.info("Verify traffic flows after recovery.")
            self.vxlan_test_setup[encap_type]['t2_ports'] = all_t2_ports
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            time.sleep(10)
            self.dump_self_info_and_run_ptf(
                "tc12",
                encap_type,
                True,
                packet_count=1000,
                skip_traffic_test=skip_traffic_test)

        except Exception:
            # If anything goes wrong in the try block, atleast bring the intf
            # back up.
            self.vxlan_test_setup[encap_type]['t2_ports'] = all_t2_ports
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost']),
                "BGP neighbors didn't come up after all interfaces "
                "have been brought up.")
            raise

    def test_vxlan_remove_add_underlay_default(self,
                                               setUp,
                                               minigraph_facts,
                                               encap_type,
                                               skip_traffic_test):      # noqa F811
        '''
           tc13: remove the underlay default route.
           tc14: add the underlay default route.
        '''
        self.vxlan_test_setup = setUp
        Logger.info(
            "Find all the underlay default routes' interfaces. This means all "
            "T2 interfaces.")
        all_t2_intfs = list(ecmp_utils.get_portchannels_to_neighbors(
            self.vxlan_test_setup['duthost'],
            "T2",
            minigraph_facts))
        if not all_t2_intfs:
            all_t2_intfs = ecmp_utils.get_ethernet_to_neighbors(
                "T2",
                minigraph_facts)
        Logger.info("Dumping T2 link info: %s", all_t2_intfs)
        if not all_t2_intfs:
            raise RuntimeError(
                "No interface found connected to t2 neighbors."
                "Pls check the testbed, aborting.")
        try:
            Logger.info("Bring down the T2 interfaces.")
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface shutdown {}".format(intf))
            downed_bgp_neighbors = ecmp_utils.get_downed_bgp_neighbors(
                all_t2_intfs,
                minigraph_facts)
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost'],
                    down_list=downed_bgp_neighbors),
                "BGP neighbors have not reached the required state after "
                "T2 intf are shutdown.")
            Logger.info("Verify that traffic is not flowing through.")
            self.dump_self_info_and_run_ptf("tc13", encap_type, False, skip_traffic_test=skip_traffic_test)

            # tc14: Re-add the underlay default route.
            Logger.info("Bring up the T2 interfaces.")
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            Logger.info("Wait for all bgp is up.")
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost']),
                "BGP neighbors didn't come up after all interfaces"
                " have been brought up.")
            Logger.info("Verify the traffic is flowing through, again.")
            self.dump_self_info_and_run_ptf(
                "tc14",
                encap_type,
                True,
                packet_count=1000,
                skip_traffic_test=skip_traffic_test)
        except Exception:
            Logger.info(
                "If anything goes wrong in the try block,"
                " atleast bring the intf back up.")
            for intf in all_t2_intfs:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            pytest_assert(
                wait_until(
                    300,
                    30,
                    0,
                    ecmp_utils.bgp_established,
                    self.vxlan_test_setup['duthost']),
                "BGP neighbors didn't come up after all"
                " interfaces have been brought up.")
            raise

    def test_underlay_specific_route(self, setUp, minigraph_facts, encap_type, skip_traffic_test):      # noqa F811
        '''
            Create a more specific underlay route to c1.
            Verify c1 packets are received only on the c1's nexthop interface
        '''
        self.vxlan_test_setup = setUp
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]
        endpoint_nhmap = self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet]
        backup_t2_ports = self.vxlan_test_setup[encap_type]['t2_ports']
        # Gathering all T2 Neighbors
        all_t2_neighbors = ecmp_utils.get_all_bgp_neighbors(
            minigraph_facts,
            "T2")

        # Choosing a specific T2 Neighbor to add static route
        t2_neighbor = list(all_t2_neighbors.keys())[0]

        # Gathering PTF indices corresponding to specific T2 Neighbor
        ret_list = ecmp_utils.gather_ptf_indices_t2_neighbor(
            minigraph_facts,
            all_t2_neighbors,
            t2_neighbor,
            encap_type)
        outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
        '''
            Addition & Modification of static routes - endpoint_nhmap will be
            prefix to endpoint mapping. Static routes are added towards
            endpoint with T2 VM's ip as nexthop
        '''
        gateway = all_t2_neighbors[t2_neighbor][outer_layer_version].lower()
        for _, nexthops in list(endpoint_nhmap.items()):
            for nexthop in nexthops:
                if outer_layer_version == "v6":
                    vtysh_config_commands = []
                    vtysh_config_commands.append("ipv6 route {}/{} {}".format(
                        nexthop,
                        "64",
                        gateway))
                    vtysh_config_commands.append("ipv6 route {}/{} {}".format(
                        nexthop,
                        "68",
                        gateway))
                    self.vxlan_test_setup['duthost'].copy(
                        content="\n".join(vtysh_config_commands),
                        dest="/tmp/specific_route_v6.txt")
                    self.vxlan_test_setup['duthost'].command(
                        "docker cp /tmp/specific_route_v6.txt bgp:/")
                    self.vxlan_test_setup['duthost'].command(
                        "vtysh -f /specific_route_v6.txt")
                elif outer_layer_version == "v4":
                    static_route = []
                    static_route.append(
                        "sudo config route add prefix {}/{} nexthop {}".format(
                            ".".join(nexthop.split(".")[:-1])+".0", "24",
                            gateway))
                    static_route.append(
                        "sudo config route add prefix {}/{} nexthop {}".format(
                            nexthop,
                            ecmp_utils.HOST_MASK[outer_layer_version],
                            gateway))

                    self.vxlan_test_setup['duthost'].shell_cmds(cmds=static_route)
        self.vxlan_test_setup[encap_type]['t2_ports'] = ret_list

        '''
            Traffic verification to see if specific route is preferred before
            deletion of static route
        '''
        self.dump_self_info_and_run_ptf(
            "underlay_specific_route",
            encap_type,
            True,
            skip_traffic_test=skip_traffic_test)
        # Deletion of all static routes
        gateway = all_t2_neighbors[t2_neighbor][outer_layer_version].lower()
        for _, nexthops in list(endpoint_nhmap.items()):
            for nexthop in nexthops:
                if ecmp_utils.get_outer_layer_version(encap_type) == "v6":
                    vtysh_config_commands = []
                    vtysh_config_commands.append(
                        "no ipv6 route {}/{} {}".format(
                            nexthop, "64", gateway))
                    vtysh_config_commands.append(
                        "no ipv6 route {}/{} {}".format(
                            nexthop, "68", gateway))
                    self.vxlan_test_setup['duthost'].copy(
                        content="\n".join(vtysh_config_commands),
                        dest="/tmp/specific_route_v6.txt")
                    self.vxlan_test_setup['duthost'].command(
                        "docker cp /tmp/specific_route_v6.txt bgp:/")
                    self.vxlan_test_setup['duthost'].command(
                        "vtysh -f /specific_route_v6.txt")

                elif ecmp_utils.get_outer_layer_version(encap_type) == "v4":
                    static_route = []
                    static_route.append(
                        "sudo config route del prefix {}/{} nexthop {}".format(
                            ".".join(
                                nexthop.split(".")[:-1])+".0", "24", gateway))
                    static_route.append(
                        "sudo config route del prefix {}/{} nexthop {}".format(
                            nexthop,
                            ecmp_utils.HOST_MASK[outer_layer_version],
                            gateway))

                    self.vxlan_test_setup['duthost'].shell_cmds(cmds=static_route)
        self.vxlan_test_setup[encap_type]['t2_ports'] = backup_t2_ports

        Logger.info(
            "Allow some time for recovery of default route"
            " after deleting the specific route.")
        time.sleep(10)

        '''
        Traffic verification to see if default route is preferred after
        deletion of static route
        '''
        self.dump_self_info_and_run_ptf(
            "underlay_specific_route",
            encap_type,
            True,
            skip_traffic_test=skip_traffic_test)

    def test_underlay_portchannel_shutdown(self,
                                           setUp,
                                           minigraph_facts,
                                           encap_type,
                                           skip_traffic_test):      # noqa F811
        '''
            Bring down one of the port-channels.
            Packets are equally recieved at c1, c2 or c3
        '''
        self.vxlan_test_setup = setUp

        # Verification of traffic before shutting down port channel
        self.dump_self_info_and_run_ptf("tc12", encap_type, True, skip_traffic_test=skip_traffic_test)

        # Gathering all portchannels
        all_t2_portchannel_intfs = \
            list(ecmp_utils.get_portchannels_to_neighbors(
                self.vxlan_test_setup['duthost'],
                "T2",
                minigraph_facts))
        all_t2_portchannel_members = {}
        for each_pc in all_t2_portchannel_intfs:
            all_t2_portchannel_members[each_pc] =\
                minigraph_facts['minigraph_portchannels'][each_pc]['members']

        selected_portchannel = list(all_t2_portchannel_members.keys())[0]

        try:
            # Shutting down the ethernet interfaces
            for intf in all_t2_portchannel_members[selected_portchannel]:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface shutdown {}".format(intf))

            all_t2_ports = list(self.vxlan_test_setup[encap_type]['t2_ports'])
            downed_ports = ecmp_utils.get_corresponding_ports(
                all_t2_portchannel_members[selected_portchannel],
                minigraph_facts)
            self.vxlan_test_setup[encap_type]['t2_ports'] = \
                list(set(all_t2_ports) - set(downed_ports))

            # Verification of traffic
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            time.sleep(10)
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, skip_traffic_test=skip_traffic_test)

            for intf in all_t2_portchannel_members[selected_portchannel]:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            self.vxlan_test_setup[encap_type]['t2_ports'] = all_t2_ports
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            time.sleep(10)
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, skip_traffic_test=skip_traffic_test)
        except BaseException:
            for intf in all_t2_portchannel_members[selected_portchannel]:
                self.vxlan_test_setup['duthost'].shell(
                    "sudo config interface startup {}".format(intf))
            self.vxlan_test_setup[encap_type]['t2_ports'] = all_t2_ports
            ecmp_utils.update_monitor_file(
                self.vxlan_test_setup['ptfhost'],
                self.vxlan_test_setup['monitor_file'],
                self.vxlan_test_setup[encap_type]['t2_ports'],
                list(self.vxlan_test_setup['list_of_bfd_monitors']))
            raise


@pytest.mark.skipif(
    "config.option.include_long_tests is False",
    reason="This test will be run only if"
           "'--include_long_tests=True' is provided.")
class Test_VxLAN_entropy(Test_VxLAN):
    '''
        Class for all test cases that modify the payload traffic
        properties - tcp source port, destination port and source IP address.
    '''

    def verify_entropy(
            self,
            encap_type,
            random_sport=False,
            random_dport=True,
            random_src_ip=False,
            tolerance=None,
            skip_traffic_test=False):       # noqa F811
        '''
            Function to be reused by the entropy testcases. Sets up a couple of
            endpoints on the top of the existing ones, and performs the traffic
            test, with different payload variants.
        '''

        Logger.info("Choose a vnet.")
        vnet = list(self.vxlan_test_setup[encap_type]['dest_to_nh_map'].keys())[0]
        Logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for _ in range(2):
            end_point_list.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))
        Logger.info("Create a new destination")
        new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)
        Logger.info("Map the new destination and the new endpoint(s).")
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'][vnet][new_dest] = \
            end_point_list
        Logger.info("Create a new config and Copy to the DUT.")
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            new_dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            end_point_list,
            "SET",
            bfd=self.vxlan_test_setup['enable_bfd'])
        self.update_monitor_list(
            self.vxlan_test_setup['enable_bfd'],
            encap_type,
            end_point_list)
        Logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf(
            "entropy",
            encap_type,
            True,
            random_sport=random_sport,
            random_dport=random_dport,
            random_src_ip=random_src_ip,
            packet_count=1000,
            tolerance=tolerance,
            skip_traffic_test=skip_traffic_test)

    def test_verify_entropy(self, setUp, encap_type, skip_traffic_test):            # noqa F811
        '''
        Verification of entropy - Create tunnel route 4 to endpoint group A.
        Send packets (fixed tuple) to route 4's prefix dst
        '''
        self.vxlan_test_setup = setUp
        self.verify_entropy(
            encap_type,
            random_dport=True,
            random_sport=True,
            random_src_ip=True,
            tolerance=0.75,         # More tolerance since this varies entropy a lot.
            skip_traffic_test=skip_traffic_test)

    def test_vxlan_random_dst_port(self, setUp, encap_type, skip_traffic_test):     # noqa F811
        '''
        Verification of entropy - Change the udp dst port of original packet to
        route 4's prefix dst
        '''
        self.vxlan_test_setup = setUp
        self.verify_entropy(encap_type, tolerance=0.03)

    def test_vxlan_random_src_port(self, setUp, encap_type, skip_traffic_test):     # noqa F811
        '''
        Verification of entropy - Change the udp src port of original packet
        to route 4's prefix dst
        '''
        self.vxlan_test_setup = setUp
        self.verify_entropy(
            encap_type,
            random_dport=False,
            random_sport=True,
            tolerance=0.03,
            skip_traffic_test=skip_traffic_test)

    def test_vxlan_varying_src_ip(self, setUp, encap_type, skip_traffic_test):      # noqa F811
        '''
        Verification of entropy - Change the udp src ip of original packet to
        route 4's prefix dst
        '''
        self.vxlan_test_setup = setUp
        self.verify_entropy(
            encap_type,
            random_dport=False,
            random_src_ip=True,
            tolerance=0.03,
            skip_traffic_test=skip_traffic_test)
