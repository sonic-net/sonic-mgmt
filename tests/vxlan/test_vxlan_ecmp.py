#! /usr/bin/env python3

'''
    Script to automate the cases listed in VxLAN HLD document:
    https://github.com/sonic-net/SONiC/blob/8ca1ac93c8912fda7b09de9bfd51498e5038c292/doc/vxlan/Overlay%20ECMP%20with%20BFD.md#test-cases

    To test functionality:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/    -c 'vxlan/test_vxlan_ecmp.py'

    To test ECMP with 2 paths per destination:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/    -c 'vxlan/test_vxlan_ecmp.py' -e '--nhs_per_destination=2'

    To test ECMP+Scale(for all 4 types of encap):
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/    -c  'vxlan/test_vxlan_ecmp.py::Test_VxLAN_route_tests::test_vxlan_single_endpoint' \
                    -e '--ecmp_nhs_per_destination=128' -e '--total_number_of_nexthops=32000' -e '--total_number_of_endpoints=1024'

    To keep the temporary config files created in the DUT:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --keep_temp_files -c 'vxlan/test_vxlan_ecmp.py'

    Other options:
        keep_temp_files             : Keep the temporary files created in the DUT. Default: False
        debug_enabled               : Enable debug mode, for debugging script. The temp files will not have timestamped names. Default: False
        dut_hostid                  : An integer in the range of 1 - 100 to be used as the host part of the IP address for DUT. Default: 1
        ecmp_nhs_per_destination    : Number of ECMP next-hops per destination.
        total_number_of_endpoints   : Number of Endpoints (a pool of this number of ip addresses will used for next-hops). Default:2
        total_number_of_nexthops    : Maximum number of all nexthops for every destination combined(per encap_type).
        vxlan_port                                : Global vxlan port (UDP port) to be used for the DUT. Default: 4789
        bfd                         : Set it to True if you want to run all VXLAN cases with BFD
'''

import time
import logging
from datetime import datetime
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner
from vxlan_ecmp_utils import Ecmp_Utils
ecmp_utils = Ecmp_Utils()
logger = logging.getLogger(__name__)
import json
from ptf.mask import Mask
import ptf.packet as scapy
from scapy.all import *
import traceback


# This is the list of encapsulations that will be tested in this script.
# v6_in_v4 means: V6 payload is encapsulated inside v4 outer layer.
# This list is used in many locations in the script.
SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v4_in_v6', 'v6_in_v4', 'v6_in_v6']
# Starting prefixes to be used for the destinations and End points.
DESTINATION_PREFIX = 150
NEXTHOP_PREFIX = 100

pytestmark = [
    # This script supports any T1 topology: t1, t1-64-lag, t1-lag.
    pytest.mark.topology("t1", "t1-64-lag", "t1-lag"),
    pytest.mark.sanity_check(post_check=True)
]


@pytest.fixture(scope="module", params=SUPPORTED_ENCAP_TYPES)
def encap_type(request):
    yield request.param


@pytest.fixture(scope="module")
def setUp(duthosts, ptfhost, request, rand_one_dut_hostname, minigraph_facts,
          tbinfo, encap_type):
    
    asic_type = duthosts[rand_one_dut_hostname].facts["asic_type"]
    if asic_type == "cisco-8000":
        ECMP_TOLERANCE = 0.01

    # Should I keep the temporary files copied to DUT?
    ecmp_utils.Constants['KEEP_TEMP_FILES'] = request.config.option.keep_temp_files

    # Is debugging going on, or is it a production run? If it is a
    # production run, use time-stamped file names for temp files.
    ecmp_utils.Constants['DEBUG'] = request.config.option.debug_enabled

    # The host id in the ip addresses for DUT. It can be anything,
    # but helps to keep as a single number that is easy to identify
    # as DUT.
    ecmp_utils.Constants['DUT_HOSTID'] = request.config.option.dut_hostid

    logger.info("ecmp_utils.Constants to be used in the script:%s", ecmp_utils.Constants)

    SUPPORTED_ENCAP_TYPES = [encap_type]

    data = {}
    data['tolerance'] = ECMP_TOLERANCE
    data['ptfhost'] = ptfhost
    data['tbinfo'] = tbinfo
    data['duthost'] = duthosts[rand_one_dut_hostname]
    data['minigraph_facts'] = data['duthost'].get_extended_minigraph_facts(tbinfo)
    data['dut_mac'] = data['duthost'].facts['router_mac']
    data['vxlan_port'] = request.config.option.vxlan_port
    data['crm'] =data['duthost'].get_crm_resources()['main_resources']
    ecmp_utils.configure_vxlan_switch(data['duthost'], vxlan_port=data['vxlan_port'], dutmac=data['dut_mac'])

    selected_interfaces = {}
    for encap_type in SUPPORTED_ENCAP_TYPES:
        outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
        selected_interfaces[encap_type] = ecmp_utils.select_required_interfaces(
            data['duthost'],
            number_of_required_interfaces=1,
            minigraph_data=minigraph_facts,
            af=outer_layer_version)

    # To store the names of the tunnels, for every outer layer version.
    tunnel_names = {}
    # To track the vnets for every outer_layer_version.
    vnet_af_map = {}
    for encap_type in SUPPORTED_ENCAP_TYPES:
        outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
        try:
            tunnel_names[outer_layer_version]
        except KeyError:
            tunnel_names[outer_layer_version] = ecmp_utils.create_vxlan_tunnel(data['duthost'], minigraph_data=minigraph_facts, af=outer_layer_version)

        payload_version = ecmp_utils.get_payload_version(encap_type)
        encap_type = "{}_in_{}".format(payload_version, outer_layer_version)
        encap_type_data = {}
        encap_type_data['selected_interfaces'] = selected_interfaces[encap_type]

        try:
            encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]
        except KeyError:
            vnet_af_map[outer_layer_version] = ecmp_utils.create_vnets(data['duthost'],
                                                            tunnel_name=tunnel_names[outer_layer_version],
                                                            vnet_count=1, # default scope can take only one vnet.
                                                            vnet_name_prefix="Vnet_" + encap_type,
                                                            scope="default",
                                                            vni_base=10000)
            encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]

        encap_type_data['vnet_intf_map'] = ecmp_utils.setup_vnet_intf(data['duthost'],
                                                           selected_interfaces=encap_type_data['selected_interfaces'],
                                                           vnet_list=encap_type_data['vnet_vni_map'].keys(),
                                                           minigraph_data=minigraph_facts)
        encap_type_data['intf_to_ip_map'] = ecmp_utils.assign_intf_ip_address(selected_interfaces=encap_type_data['selected_interfaces'], af=payload_version)
        encap_type_data['t2_ports'] = ecmp_utils.get_t2_ports(data['duthost'], minigraph_facts)
        encap_type_data['neighbor_config'] = ecmp_utils.configure_vnet_neighbors(data['duthost'], encap_type_data['intf_to_ip_map'], minigraph_data=minigraph_facts, af=payload_version)
        encap_type_data['dest_to_nh_map'] = ecmp_utils.create_vnet_routes(data['duthost'], encap_type_data['vnet_vni_map'].keys(),
                                                               nhs_per_destination=request.config.option.ecmp_nhs_per_destination,
                                                               number_of_available_nexthops=request.config.option.total_number_of_endpoints,
                                                               number_of_ecmp_nhs=request.config.option.total_number_of_nexthops,
                                                               dest_af=payload_version,
                                                               dest_net_prefix=DESTINATION_PREFIX,
                                                               nexthop_prefix=NEXTHOP_PREFIX,
                                                               nh_af=outer_layer_version,
                                                               bfd = request.config.option.bfd)

        
        data[encap_type] = encap_type_data
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(data['duthost'], data['ptfhost'], data['tbinfo'])
        except Exception:
            print(traceback.format_exc())
    # This data doesn't change per testcase, so we copy
    # it as a seperate file. The test-specific config
    # data will be copied on testase basis.
    data['ptfhost'].copy(content=json.dumps(
        {
            'minigraph_facts':    data['minigraph_facts'],
            'tbinfo' : data['tbinfo']
        },
        indent=4), dest="/tmp/vxlan_topo_info.json")

    yield data

    # Cleanup code.
    for encap_type in SUPPORTED_ENCAP_TYPES:
        outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
        payload_version = ecmp_utils.get_payload_version(encap_type)

        encap_type = "{}_in_{}".format(payload_version, outer_layer_version)
        ecmp_utils.set_routes_in_dut(data['duthost'], data[encap_type]['dest_to_nh_map'], payload_version, "DEL")

        for intf in data[encap_type]['selected_interfaces']:
            redis_string = "INTERFACE"
            if "PortChannel" in intf:
                redis_string = "PORTCHANNEL_INTERFACE"
            data['duthost'].shell("redis-cli -n 4 hdel \"{}|{}\" vnet_name".format(redis_string, intf))

    # This script's setup code re-uses same vnets for v4inv4 and v6inv4.
    # There will be same vnet in multiple encap types.
    # So remove vnets *after* removing the routes first.
    for encap_type in SUPPORTED_ENCAP_TYPES:
         for vnet in data[encap_type]['vnet_vni_map'].keys():
             data['duthost'].shell("redis-cli -n 4 del \"VNET|{}\"".format(vnet))

    time.sleep(5)
    for tunnel in tunnel_names.values():
        data['duthost'].shell("redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))

    time.sleep(1)
    if request.config.option.bfd:
        data['ptfhost'].command('supervisorctl stop bfd_responder')
        data['ptfhost'].file(path=ecmp_utils.BFD_RESPONDER_SCRIPT_DEST_PATH, state="absent")

class Test_VxLAN:

    def dump_self_info_and_run_ptf(self, tcname, encap_type, expect_encap_success, packet_count=4, random_dport = True, random_sport = False, varying_src_ip = False, tolerance = None, downed_endpoints = []):
        '''
           Just a wrapper for dump_info_to_ptf to avoid entering 30 lines everytime.
        '''
        if tolerance is None:
            tolerance = self.setup['tolerance'] 
        if ecmp_utils.Constants['DEBUG']:
            config_filename = "/tmp/vxlan_configs.json"
        else:
            config_filename = "/tmp/vxlan_configs." + tcname + "-" + encap_type + "-" + str(time.time()) + ".json"
        self.setup['ptfhost'].copy(content=json.dumps(
            {
                'vnet_vni_map' : self.setup[encap_type]['vnet_vni_map'],
                'vnet_intf_map' : self.setup[encap_type]['vnet_intf_map'],
                'dest_to_nh_map': self.setup[encap_type]['dest_to_nh_map'],
                'neighbors' : self.setup[encap_type]['neighbor_config'],
                'intf_to_ip_map': self.setup[encap_type]['intf_to_ip_map'],
            },
            indent=4), dest=config_filename)
        ptf_runner(self.setup['ptfhost'],
                   "ptftests",
                   "vxlan_traffic.VXLAN",
                   platform_dir="ptftests",
                   params={
                       "topo_file": "/tmp/vxlan_topo_info.json",
                       "config_file": config_filename,
                       "t0_ports":ecmp_utils.get_ethernet_ports(self.setup[encap_type]['selected_interfaces'], self.setup['minigraph_facts']),
                       "t2_ports":self.setup[encap_type]['t2_ports'],
                       "dut_mac":self.setup['dut_mac'],
                       "vxlan_port": self.setup['vxlan_port'],
                       "expect_encap_success":expect_encap_success,
                       "packet_count":packet_count,
                       "random_dport":random_dport,
                       "random_sport":random_sport,
                       "varying_src_ip":varying_src_ip,
                       "tolerance": tolerance,
                       "downed_endpoints": downed_endpoints
                       },
                   qlen=1000,
                   log_file="/tmp/vxlan-tests.{}.{}.{}.log".format(tcname, encap_type, datetime.now().strftime('%Y-%m-%d-%H:%M:%S')))


@pytest.fixture
def ignore_route_sync_errlogs(rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend([".*Unaccounted_ROUTE_ENTRY_TABLE_entries.*"])
    return

class Test_VxLAN_route_tests(Test_VxLAN):
    def test_vxlan_single_endpoint(self, setUp, encap_type):
        '''
            tc1:Create a tunnel route to a single endpoint a. Send packets to the route prefix dst.
        '''
        self.setup = setUp
        self.dump_self_info_and_run_ptf("tc1", encap_type, True)

    def test_vxlan_modify_route_different_endpoint(self, setUp, request, encap_type):
        '''
            tc2: change the route to different endpoint. packets are received only at endpoint b.")
        '''
        self.setup = setUp
        logger.info("Choose a vnet")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Choose a destination, which is already present.")
        tc2_dest = self.setup[encap_type]['dest_to_nh_map'][vnet].keys()[0]

        logger.info("Create a new endpoint, or endpoint-list.")
        tc2_new_end_point_list = []
        for i in range(int(request.config.option.ecmp_nhs_per_destination)):
            tc2_new_end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Map the destination to the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc2_dest] = tc2_new_end_point_list

        logger.info("Create the json and apply the config in the DUT swss.")
        # The config looks like:
        # [
        #   {
        #     "VNET_ROUTE_TUNNEL_TABLE:vnet:tc2_dest/32": {
        #       "endpoint": "{tc2_new_end_point_list}"
        #     },
        #     "OP": "{}"
        #   }
        # ]
        tc2_full_config = '[\n' + ecmp_utils.create_single_route(vnet, tc2_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc2_new_end_point_list, "SET") + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc2_full_config, "vnet_route_tc2_"+encap_type)

        logger.info("Copy the new set of configs to the PTF and run the tests.")
        self.dump_self_info_and_run_ptf("tc2", encap_type, True)

    def test_vxlan_remove_all_route(self, setUp, encap_type):
        '''
            tc3: remove the tunnel route. send packets to the route prefix dst. packets should not be received at any ports with dst ip of b")
        '''
        self.setup = setUp
        try:
            logger.info("Remove the existing routes in the DUT.")
            ecmp_utils.set_routes_in_dut(self.setup['duthost'], self.setup[encap_type]['dest_to_nh_map'], ecmp_utils.get_payload_version(encap_type), "DEL")
            logger.info("Verify that the traffic is not coming back.")
            self.dump_self_info_and_run_ptf("tc3", encap_type, False)
        finally:
            logger.info("Restore the routes in the DUT.")
            ecmp_utils.set_routes_in_dut(self.setup['duthost'], self.setup[encap_type]['dest_to_nh_map'], ecmp_utils.get_payload_version(encap_type), "SET")

class Test_VxLAN_ecmp_create(Test_VxLAN):
    def test_vxlan_configure_route1_ecmp_group_a(self, setUp, encap_type, request):
        '''
            tc4:create tunnel route 1 with two endpoints a = {a1, a2...}. send packets to the route 1's prefix dst. packets are received at either a1 or a2.
        '''
        self.setup = setUp

        logger.info("Choose a vnet.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Create a new list of endpoint(s).")
        tc4_end_point_list = []
        for i in range(2):
            tc4_end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Create a new destination")
        tc4_new_dest = ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX)

        logger.info("Map the new destination and the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = tc4_end_point_list

        logger.info("Create a new config and Copy to the DUT.")
        tc4_config = '[\n' + ecmp_utils.create_single_route(vnet, tc4_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc4_end_point_list, "SET", bfd = request.config.option.bfd) + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc4_config, "vnet_route_tc4_"+encap_type)
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'])
        except Exception:
            print(traceback.format_exc())
        
        logger.info("Verify that the new config takes effect and run traffic.")
        
        self.dump_self_info_and_run_ptf("tc4", encap_type, True)
        
    def test_vxlan_configure_route1_ecmp_group_b(self, setUp, encap_type, request):
        '''
            tc5: set tunnel route 2 to endpoint group a = {a1, a2}. send packets to route 2"s prefix dst. packets are received at either a1 or a2
        '''
        self.setup = setUp
        self.setup_route2_ecmp_group_b(encap_type, request)
        logger.info("Verify the configs work and traffic flows correctly.")
        self.dump_self_info_and_run_ptf("tc5", encap_type, True)

    def setup_route2_ecmp_group_b(self, encap_type, request):
        if self.setup[encap_type].get('tc5_dest', None):
            return
        logger.info("Choose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]
        
        logger.info("Select an existing endpoint.")
        tc5_end_point_list = self.setup[encap_type]['dest_to_nh_map'][vnet].values()[0]

        logger.info("Create a new destination to use.")
        tc5_new_dest = ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX)

        logger.info("Map the new destination to the endpoint.")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc5_new_dest] = tc5_end_point_list

        logger.info("Create the new config and apply to the DUT.")
        tc5_config = '[\n' + ecmp_utils.create_single_route(vnet, tc5_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc5_end_point_list, "SET", bfd = request.config.option.bfd) + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc5_config, "vnet_route_tc5_"+encap_type)
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'])
        except Exception:
            print(traceback.format_exc())

        self.setup[encap_type]['tc5_dest'] = tc5_new_dest

    def test_vxlan_configure_route2_ecmp_group_b(self, setUp, encap_type, request):
        '''
            tc6: set tunnel route 2 to endpoint group b = {b1, b2}. send packets to route 2"s prefix dst. packets are received at either b1 or b2.
        '''
        self.setup = setUp
        self.setup_route2_ecmp_group_b(encap_type, request)

        logger.info("Choose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Create a new list of endpoints.")
        tc6_end_point_list = []
        for i in range(2):
            tc6_end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Choose one of the existing destinations.")
        tc6_new_dest = self.setup[encap_type]['tc5_dest']

        logger.info("Map the destination to the new endpoints.")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc6_new_dest] = tc6_end_point_list

        logger.info("Create the config and apply on the DUT.")
        tc6_config = '[\n' + ecmp_utils.create_single_route(vnet, tc6_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc6_end_point_list, "SET", bfd = request.config.option.bfd) + '\n]'
        
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc6_config, "vnet_route_tc6_"+encap_type)
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'])
        except Exception:
            print(traceback.format_exc())
        logger.info("Verify that the traffic works.")

        self.dump_self_info_and_run_ptf("tc6", encap_type, True)
    
    def test_vxlan_bfd_health_state_change_a2down_a1up(self, setUp, encap_type, request):
        '''
            Set BFD state for a1' to UP and a2' to Down. Send multiple packets (varying tuple) to the route 1's prefix dst.
            Packets are received only at endpoint a1. Verify advertise table is present
        '''
        self.setup = setUp

        logger.info("Choose a vnet.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for i in range(2):
            end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Create a new destination")
        tc4_new_dest = ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX)

        logger.info("Map the new destination and the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = end_point_list

        logger.info("Create a new config and Copy to the DUT.")
        tc4_config = '[\n' + ecmp_utils.create_single_route(vnet, tc4_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], end_point_list, "SET", bfd = request.config.option.bfd) + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc4_config, "vnet_route_tc4_"+encap_type)
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'], delete_member_a2 = end_point_list[1])
        except Exception:
            print(traceback.format_exc())
        logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf("tc4", encap_type, True, downed_endpoints=[end_point_list[1]])
        
    def test_vxlan_bfd_health_state_change_a1a2_down(self, setUp, encap_type, request):
        '''
            Set BFD state for a1' to Down and a2' to Down. Send multiple packets (varying tuple) to the route 1's prefix dst.
            Packets are not received at any ports. Verify advertise table is removed
        '''
        self.setup = setUp
        logger.info("Choose a vnet.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]
        
        logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for i in range(2):
            end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))
        
        logger.info("Create a new destination")
        new_dest = ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX)

        logger.info("Map the new destination and the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][new_dest] = end_point_list
 
        logger.info("Create a new config and Copy to the DUT.")
        tc4_config = '[\n' + ecmp_utils.create_single_route(vnet, new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], end_point_list, "SET", bfd = request.config.option.bfd) + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc4_config, "vnet_route_tc4_"+encap_type)
        
        #Bringing down both the end points
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'], delete_member_a1 = end_point_list[0], delete_member_a2 = end_point_list[1])
        except Exception:
            print(traceback.format_exc())   

        #Updating endpoints to ensure traffic goes to downed endpoints
        self.setup[encap_type]['dest_to_nh_map'] = {vnet:{new_dest:end_point_list}}
        
        #Verification of Traffic towards downed endpoints
        logger.info("Verify that there is no traffic towards downed endpoints")
        self.dump_self_info_and_run_ptf("tc4", encap_type, False)

    def test_vxlan_bfd_health_state_change_a2up_a1down(self, setUp, encap_type, request):
        '''
            Set BFD state for a2' to UP. Send packets to the route 1's prefix dst.
            Packets are received only at endpoint a2. Verify advertise table is present
        '''
        self.setup = setUp

        logger.info("Choose a vnet.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for i in range(2):
            end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Create a new destination")
        tc4_new_dest = ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX)

        logger.info("Map the new destination and the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = end_point_list

        logger.info("Create a new config and Copy to the DUT.")
        tc4_config = '[\n' + ecmp_utils.create_single_route(vnet, tc4_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], end_point_list, "SET", bfd = request.config.option.bfd) + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc4_config, "vnet_route_tc4_"+encap_type)
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'], delete_member_a1 = end_point_list[0])
        except Exception:
            print(traceback.format_exc())

        logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf("tc4", encap_type, True, downed_endpoints=[end_point_list[0]])

    def test_vxlan_bfd_health_state_change_a1a2_up(self, setUp, encap_type, request):
        '''
            Set BFD state for a1' & a2' to UP. Send multiple packets (varying tuple) to the route 1's prefix dst.
            Packets are received at both a1 and a2. Verify advertise table is present
        '''
        self.setup = setUp

        logger.info("Choose a vnet.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for i in range(2):
            end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Create a new destination")
        tc4_new_dest = ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX)

        logger.info("Map the new destination and the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = end_point_list

        logger.info("Create a new config and Copy to the DUT.")
        tc4_config = '[\n' + ecmp_utils.create_single_route(vnet, tc4_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], end_point_list, "SET", bfd = request.config.option.bfd) + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc4_config, "vnet_route_tc4_"+encap_type)
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'])
        except Exception:
            print(traceback.format_exc())

        logger.info("Verify that the new config takes effect and run traffic.")
        
        self.dump_self_info_and_run_ptf("tc4", encap_type, True)

class Test_VxLAN_NHG_Modify(Test_VxLAN):

    def setup_route2_single_endpoint(self, encap_type):
        if self.setup[encap_type].get('tc8_dest', None):
            return

        logger.info("Pick a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Choose a route 2 destination and a new single endpoint for it.")
        tc8_new_dest = self.setup[encap_type]['dest_to_nh_map'][vnet].keys()[0]
        tc8_new_nh = ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX)
        logger.info("Using destinations: dest:{} => nh:{}".format(tc8_new_dest, tc8_new_nh))

        logger.info("Map the destination and new endpoint.")
        tc8_config = '[\n' + ecmp_utils.create_single_route(vnet, tc8_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], [tc8_new_nh], "SET") + '\n]'
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc8_new_dest] = [tc8_new_nh]

        logger.info("Apply the new config in the DUT and run traffic test.")
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc8_config, "vnet_route_tc8_"+encap_type)
        self.setup[encap_type]['tc8_dest'] = tc8_new_dest

    def setup_route2_shared_endpoints(self, encap_type, request):
        if self.setup[encap_type].get('tc9_dest', None):
            return
        self.setup_route2_single_endpoint(encap_type)

        logger.info("Choose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Select 2 already existing destinations. They must have 2 different nexthops.")
        tc9_new_dest1 = self.setup[encap_type]['tc8_dest']
        nh1 = self.setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1][0]

        nh2 = None
        for dest in self.setup[encap_type]['dest_to_nh_map'][vnet].keys():
            nexthops = self.setup[encap_type]['dest_to_nh_map'][vnet][dest]
            for nh in nexthops:
                if nh == nh1:
                    continue
                else:
                    nh2 = nh
                    break
        if nh2:
            logger.info("Using destinations: dest:{}, nexthops:{}, {}".format(tc9_new_dest1, nh1, nh2))
        else:
            raise RuntimeError("Couldnot find different nexthop for this test. The current list: {}".format(self.setup[encap_type]['dest_to_nh_map']))

        logger.info("Use the selected nexthops(tunnel endpoints). They are guaranteed to be different.")
        tc9_new_nhs = [nh1, nh2]

        logger.info("Map the destination 1 to the combined list.")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1] = tc9_new_nhs
        tc9_config = '[\n' + ecmp_utils.create_single_route(vnet, tc9_new_dest1, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc9_new_nhs, "SET", bfd = request.config.option.bfd) + '\n]'

        logger.info("Apply the new config to the DUT and send traffic.")
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc9_config, "vnet_route_tc9_"+encap_type)
        try:   
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'])
        except Exception:
            print(traceback.format_exc())
        self.setup[encap_type]['tc9_dest'] = tc9_new_dest1

    def setup_route2_shared_different_endpoints(self, encap_type):
        if self.setup[encap_type].get('tc9_dest', None):
            return
        self.setup_route2_single_endpoint(encap_type)

        logger.info("Choose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Select 2 already existing destinations. They must have 2 different nexthops.")
        tc9_new_dest1 = self.setup[encap_type]['tc8_dest']
        old_nh = self.setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1][0]

        nh1 = None
        nh2 = None
        for dest in self.setup[encap_type]['dest_to_nh_map'][vnet].keys():
            nexthops = self.setup[encap_type]['dest_to_nh_map'][vnet][dest]
            for nh in nexthops:
                if nh == old_nh:
                    next
                else:
                    if not nh1:
                        nh1 = nh
                    elif not nh2:
                        if nh != nh1:
                            nh2 = nh
                            break
        if nh2:
            logger.info("Using destinations: dest:{}, nexthops:{}, {}".format(tc9_new_dest1, nh1, nh2))
        else:
            raise RuntimeError("Couldnot find different nexthop for this test. The current list: {}".format(self.setup[encap_type]['dest_to_nh_map']))

        logger.info("Use the selected nexthops(tunnel endpoints). They are guaranteed to be different.")
        tc9_new_nhs = [nh1, nh2]

        logger.info("Map the destination 1 to the combined list.")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1] = tc9_new_nhs
        tc9_config = '[\n' + ecmp_utils.create_single_route(vnet, tc9_new_dest1, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc9_new_nhs, "SET") + '\n]'

        logger.info("Apply the new config to the DUT and send traffic.")
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc9_config, "vnet_route_tc9_"+encap_type)
        self.setup[encap_type]['tc9_dest'] = tc9_new_dest1


    def test_vxlan_remove_route2(self, setUp, encap_type):
        '''
            tc7:send packets to route 1's prefix dst. by removing route 2 from group a, no change expected to route 1.
        '''
        self.setup = setUp

        logger.info("Pick a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Setup: Create two destinations with the same endpoint group.")
        tc7_end_point_list = []
        for i in range(2):
            tc7_end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        tc7_destinations = []
        for i in range(2):
            tc7_destinations.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX))

        logger.info("Map the new destinations to the same endpoint list.")
        for i in range(2):
            self.setup[encap_type]['dest_to_nh_map'][vnet][tc7_destinations[i]] = tc7_end_point_list

        logger.info("Apply the setup configs to the DUT.")
        for i in range(2):
            tc7_setup_config = '[\n' + ecmp_utils.create_single_route(vnet, tc7_destinations[i], ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc7_end_point_list, "SET") + '\n]'
            ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc7_setup_config, "vnet_route_tc7_"+encap_type)

        logger.info("Verify the setup works.")
        self.dump_self_info_and_run_ptf("tc7", encap_type, True)
        logger.info("End of setup.")

        logger.info("Remove one of the routes.")
        logger.info("Pick one out of the two TC7 destinations.")
        tc7_removed_dest = tc7_destinations[0]
        tc7_removed_endpoint = self.setup[encap_type]['dest_to_nh_map'][vnet][tc7_removed_dest]
        del self.setup[encap_type]['dest_to_nh_map'][vnet][tc7_removed_dest]

        logger.info("Remove the chosen dest/endpoint from the DUT.")
        tc7_config = '[\n' + ecmp_utils.create_single_route(vnet, tc7_removed_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc7_removed_endpoint, "DEL") + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc7_config, "vnet_route_tc7_"+encap_type)
        
        logger.info("Verify the rest of the traffic still works.")
        self.dump_self_info_and_run_ptf("tc7", encap_type, True)

    def test_vxlan_route2_single_nh(self, setUp, encap_type):
        '''
            tc8: set tunnel route 2 to single endpoint b1. send packets to route 2's prefix dst.
        '''
        self.setup = setUp
        self.setup_route2_single_endpoint(encap_type)
        self.dump_self_info_and_run_ptf("tc8", encap_type, True)

    def test_vxlan_route2_shared_nh(self, setUp, encap_type, request):
        '''
            tc9: set tunnel route 2 to shared endpoints a1 and b1. send packets to route 2's prefix dst.
        '''
        self.setup = setUp
        self.setup_route2_shared_endpoints(encap_type, request)
        self.dump_self_info_and_run_ptf("tc9", encap_type, True)

    def test_vxlan_route2_shared_different_nh(self, setUp, encap_type):
        '''
            tc9.2: set tunnel route 2 to 2 completely different shared(no-reuse) endpoints a1 and b1. send packets to route 2's prefix dst.
        '''
        self.setup = setUp
        self.setup_route2_shared_different_endpoints(encap_type)
        self.dump_self_info_and_run_ptf("tc9.2", encap_type, True)

    def test_vxlan_remove_ecmp_route2(self, setUp, encap_type, request):
        '''
            tc10: remove tunnel route 2. send packets to route 2's prefix dst.
        '''
        self.setup = setUp
        self.setup_route2_shared_endpoints(encap_type, request)
        logger.info("Backup the current route config.")
        full_map = dict(self.setup[encap_type]['dest_to_nh_map'])
        
        logger.info("This is to keep track if the selected route should be deleted in the end.")
        del_needed = False
        try:
            logger.info("Choose a vnet for testing.")
            vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

            logger.info("Choose a destination and its nhs to delete.")
            tc10_dest = self.setup[encap_type]['tc9_dest']
            tc10_nhs = self.setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest]
            logger.info("Using destination: dest:{}, nh:{}".format(tc10_dest, tc10_nhs))

            logger.info("Delete the dest and nh in the DUT.")
            tc10_config = '[\n' + ecmp_utils.create_single_route(vnet, tc10_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc10_nhs, "DEL", bfd = request.config.option.bfd) + '\n]'
            ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc10_config, "vnet_route_tc10_"+encap_type)
            try:
                if request.config.option.bfd:
                    ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'])
            except Exception:
                print(traceback.format_exc())

            del_needed = True

            logger.info("We should pass only the deleted entry to the ptf call, and expect encap to fail.")
            logger.info("Clear out the mappings, and keep only the deleted dest and nhs.")
            self.setup[encap_type]['dest_to_nh_map'][vnet] = {}
            self.setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest] = tc10_nhs

            logger.info("The deleted route should fail to receive traffic.")
            self.dump_self_info_and_run_ptf("tc10", encap_type, False)

            # all others should be working.
            # Housekeeping:
            logger.info("Restore the mapping of dest->nhs.")
            self.setup[encap_type]['dest_to_nh_map'] = dict(full_map)
            logger.info("Remove the deleted entry alone.")
            del self.setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest]
            del_needed = False

            logger.info("Check the traffic is working in the other routes.")
            self.dump_self_info_and_run_ptf("tc10", encap_type, True)
            
        except:
            self.setup[encap_type]['dest_to_nh_map'] = dict(full_map)
            logger.info("Remove the deleted entry alone.")
            if del_needed:
                del self.setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest]
            raise

    def test_vxlan_remove_ecmp_route1(self, setUp, encap_type, request):
        '''
            Remove tunnel route 1. Send multiple packets (varying tuple) to the route 1's prefix dst.
        '''
        self.setup = setUp
        
        logger.info("Choose a vnet.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]
        
        logger.info("Create a new list of endpoint(s).")
        ecmp_route1_end_point_list = []
        for i in range(2):
            ecmp_route1_end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Create a new destination")
        ecmp_route1_new_dest = ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX)

        logger.info("Map the new destination and the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][ecmp_route1_new_dest] = ecmp_route1_end_point_list

        logger.info("Create a new config and Copy to the DUT.")
        ecmp_route1_config = '[\n' + ecmp_utils.create_single_route(vnet, ecmp_route1_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], ecmp_route1_end_point_list, "SET", bfd = request.config.option.bfd) + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], ecmp_route1_config, "vnet_route_tc4_"+encap_type)
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'])
        except Exception:
            print(traceback.format_exc())
        logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf("tc4", encap_type, True)

        logger.info("Deleting Tunnel route 1")
        del_ecmp_route1_config = '[\n' + ecmp_utils.create_single_route(vnet, ecmp_route1_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], ecmp_route1_end_point_list, "DEL", bfd = request.config.option.bfd) + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], del_ecmp_route1_config, "vnet_route_tc4_"+encap_type)
        
        logger.info("Establishing BFD sessions")
        try:
            if request.config.option.bfd:
                ecmp_utils.ptf_config(self.setup['duthost'], self.setup['ptfhost'], self.setup['tbinfo'])
        except Exception:
            print(traceback.format_exc())
        logger.info("Updating the setup dict with newly created endpoint")
        self.setup[encap_type]['dest_to_nh_map'][vnet] = {ecmp_route1_new_dest: ecmp_route1_end_point_list}

        logger.info("Verify that traffic towards deleted tunnel route fails.")
        self.dump_self_info_and_run_ptf("tc4", encap_type, False)

class Test_VxLAN_ecmp_random_hash(Test_VxLAN):
    def test_vxlan_random_hash(self, setUp, encap_type):
        '''
            tc11: set tunnel route 3 to endpoint group c = {c1, c2, c3}. ensure c1, c2, and c3 matches to underlay default route. send 1000 pkt with random hash to route 3's prefix dst.
        '''
        self.setup = setUp

        logger.info("Chose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Create a new destination and 3 nhs for it.")
        tc11_new_dest = ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX)
        tc11_new_nhs = []
        for i in range(3):
            tc11_new_nhs.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        # the topology always provides the default routes for any ip address.
        # so it is already taken care of.

        logger.info("Map the new dest and nhs.")
        tc11_config = '[\n' + ecmp_utils.create_single_route(vnet, tc11_new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], tc11_new_nhs, "SET") + '\n]'
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc11_new_dest] = tc11_new_nhs

        logger.info("Apply the config in the DUT and verify traffic. The random hash and ECMP check is already taken care of in the VxLAN PTF script.")
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], tc11_config, "vnet_route_tc11_"+encap_type)
        self.dump_self_info_and_run_ptf("tc11", encap_type, True, packet_count=1000)

@pytest.mark.usefixtures("ignore_route_sync_errlogs")
class Test_VxLAN_underlay_ecmp(Test_VxLAN):
    @pytest.mark.parametrize("ecmp_path_count", [1, 2])
    def test_vxlan_modify_underlay_default(self, setUp, minigraph_facts, encap_type, ecmp_path_count):
        '''
            tc12: modify the underlay default route nexthop/s. send packets to route 3's prefix dst.
        '''
        self.setup = setUp
        # First step: pick one or two of the interfaces connected to t2, and bring them down.
        # verify that the encap is still working, and ptf receives the traffic.
        # Bring them back up.
        # After that, bring down all the other t2 interfaces, other than the ones used in the first step.
        # This will force a modification to the underlay default routes nexthops.

        all_t2_intfs = list(ecmp_utils.get_portchannels_to_neighbors(self.setup['duthost'], "T2", minigraph_facts))
        if not all_t2_intfs:
            all_t2_intfs = get_ethernet_to_neighbors("T2", minigraph_facts)
        logger.info("Dumping T2 link info: {}".format(all_t2_intfs))
        if not all_t2_intfs:
            raise RuntimeError("No interface found connected to t2 neighbors. pls check the testbed, aborting.")

        # Keep a copy of the internal housekeeping list of t2 ports.
        # This is the full list of DUT ports connected to T2 neighbors.
        # It is one of the arguments to the ptf code.
        all_t2_ports = list(self.setup[encap_type]['t2_ports'])

        # A distinction in this script between ports and interfaces:
        # Ports are physical (Ethernet) only.
        # Interfaces have IP address(Ethernet or PortChannel).
        try:
            selected_intfs = []
            # Choose some intfs based on the parameter ecmp_path_count.
            # when ecmp_path_count == 1, it is non-ecmp. The switching happens between ecmp and non-ecmp.
            # Otherwise, the switching happens within ecmp only.
            for i in range(ecmp_path_count):
                selected_intfs.append(all_t2_intfs[i])

            for intf in selected_intfs:
                self.setup['duthost'].shell("sudo config interface shutdown {}".format(intf))
            downed_ports = ecmp_utils.get_corresponding_ports(selected_intfs, minigraph_facts)
            self.setup[encap_type]['t2_ports'] = list(set(all_t2_ports) - set(downed_ports))
            downed_bgp_neighbors = ecmp_utils.get_downed_bgp_neighbors(selected_intfs, minigraph_facts)
            pytest_assert(wait_until(300, 30, 0, ecmp_utils.bgp_established, self.setup['duthost'], down_list=downed_bgp_neighbors), "BGP neighbors didn't come up after all interfaces have been brought up.")
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, packet_count=1000)

            logger.info("Reverse the action: bring up the selected_intfs and shutdown others.")
            for intf in selected_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))
            logger.info("Shutdown other interfaces.")
            remaining_interfaces = list(set(all_t2_intfs) - set(selected_intfs))
            for intf in remaining_interfaces:
                self.setup['duthost'].shell("sudo config interface shutdown {}".format(intf))
            downed_bgp_neighbors = ecmp_utils.get_downed_bgp_neighbors(remaining_interfaces, minigraph_facts)
            pytest_assert(wait_until(300, 30, 0, ecmp_utils.bgp_established, self.setup['duthost'], down_list=downed_bgp_neighbors), "BGP neighbors didn't come up after all interfaces have been brought up.")
            self.setup[encap_type]['t2_ports'] = ecmp_utils.get_corresponding_ports(selected_intfs, minigraph_facts)
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, packet_count=1000)

            logger.info("Recovery. Bring all up, and verify traffic works.")
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))
            logger.info("Wait for all bgp is up.")
            pytest_assert(wait_until(300, 30, 0, ecmp_utils.bgp_established, self.setup['duthost']), "BGP neighbors didn't come up after all interfaces have been brought up.")
            logger.info("Verify traffic flows after recovery.")
            self.setup[encap_type]['t2_ports'] = all_t2_ports
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, packet_count=1000)

        except Exception:
            # If anything goes wrong in the try block, atleast bring the intf back up.
            self.setup[encap_type]['t2_ports'] = all_t2_ports
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))
            pytest_assert(wait_until(300, 30, 0, ecmp_utils.bgp_established, self.setup['duthost']), "BGP neighbors didn't come up after all interfaces have been brought up.")
            raise

    def test_vxlan_remove_add_underlay_default(self, setUp, minigraph_facts, encap_type):
        '''
           tc13: remove the underlay default route.
           tc14: add the underlay default route.
        '''
        self.setup = setUp
        logger.info("Find all the underlay default routes' interfaces. This means all T2 interfaces.")
        all_t2_intfs = list(ecmp_utils.get_portchannels_to_neighbors(self.setup['duthost'], "T2", minigraph_facts))
        if not all_t2_intfs:
            all_t2_intfs = ecmp_utils.get_ethernet_to_neighbors("T2", minigraph_facts)
        logger.info("Dumping T2 link info: {}".format(all_t2_intfs))
        if not all_t2_intfs:
            raise RuntimeError("No interface found connected to t2 neighbors. pls check the testbed, aborting.")
        try:
            logger.info("Bring down the T2 interfaces.")
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface shutdown {}".format(intf))
            downed_bgp_neighbors = ecmp_utils.get_downed_bgp_neighbors(all_t2_intfs, minigraph_facts)
            pytest_assert(wait_until(300, 30, 0, ecmp_utils.bgp_established, self.setup['duthost'], down_list=downed_bgp_neighbors),
                          "BGP neighbors have not reached the required state after T2 intf are shutdown.")
            logger.info("Verify that traffic is not flowing through.")
            self.dump_self_info_and_run_ptf("tc13", encap_type, False)
            '''
               tc14: Re-add the underlay default route.
            '''
            logger.info("Bring up the T2 interfaces.")
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))
            logger.info("Wait for all bgp is up.")
            pytest_assert(wait_until(300, 30, 0, ecmp_utils.bgp_established, self.setup['duthost']), "BGP neighbors didn't come up after all interfaces have been brought up.")
            logger.info("Verify the traffic is flowing through, again.")
            self.dump_self_info_and_run_ptf("tc14", encap_type, True, packet_count=1000)
        except Exception:
            logger.info("If anything goes wrong in the try block, atleast bring the intf back up.")
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))
            pytest_assert(wait_until(300, 30, 0, ecmp_utils.bgp_established, self.setup['duthost']), "BGP neighbors didn't come up after all interfaces have been brought up.")
            raise

    def test_underlay_specific_route(self, setUp, minigraph_facts, encap_type):
        '''
        Create a more specific underlay route to c1.
        Verify c1 packets are received only on the c1's nexthop interface
        '''
        self.setup = setUp
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]
        endpoint_nhmap = self.setup[encap_type]['dest_to_nh_map'][vnet]
        backup_t2_ports = self.setup[encap_type]['t2_ports']
        #Gathering all T2 Neighbors
        all_t2_neighbors = ecmp_utils.get_all_bgp_neighbors(minigraph_facts, "T2")

        #Choosing a specific T2 Neighbor to add static route
        t2_neighbor = all_t2_neighbors.keys()[0]
        
        #Gathering PTF indices corresponding to specific T2 Neighbor
        ret_list = ecmp_utils.gather_ptf_indices_t2_neighbor(minigraph_facts, all_t2_neighbors, t2_neighbor, encap_type)
        
        #Addition & Modification of static routes - endpoint_nhmap will be prefix to endpoint mapping.
        #Static routes are added towards endpoint with T2 VM's ip as nexthop
        for destination, nexthops in endpoint_nhmap.items():
            for nexthop in nexthops:
                add_static_route = []
                if ecmp_utils.get_outer_layer_version(encap_type) == "v6":
                    add_static_route.append("sudo config route add prefix {}/{} nexthop {}".format(nexthop, "64", all_t2_neighbors[t2_neighbor][ecmp_utils.get_outer_layer_version(encap_type)].lower()))
                    add_static_route.append("sudo config route add prefix {}/{} nexthop {}".format(nexthop, "68", all_t2_neighbors[t2_neighbor][ecmp_utils.get_outer_layer_version(encap_type)].lower()))
                elif ecmp_utils.get_outer_layer_version(encap_type) == "v4":
                    add_static_route.append("sudo config route add prefix {}/{} nexthop {}".format(".".join(nexthop.split(".")[:-1])+".0", "24", all_t2_neighbors[t2_neighbor][ecmp_utils.get_outer_layer_version(encap_type)].lower()))
                    add_static_route.append("sudo config route add prefix {}/{} nexthop {}".format(nexthop, ecmp_utils.HOST_MASK[ecmp_utils.get_outer_layer_version(encap_type)], all_t2_neighbors[t2_neighbor][ecmp_utils.get_outer_layer_version(encap_type)].lower()))
                self.setup['duthost'].shell_cmds(cmds = add_static_route)
                self.setup[encap_type]['t2_ports'] = ret_list
        #Traffic verification to see if specific route is preferred before deletion of static route
        self.dump_self_info_and_run_ptf("underlay_specific_route", encap_type, True)

        #Deletion of all static routes
        for destination, nexthops in endpoint_nhmap.items():
            for nexthop in nexthops:
                del_static_route = []
                if ecmp_utils.get_outer_layer_version(encap_type) == "v6":
                    del_static_route.append("sudo config route del prefix {}/{} nexthop {}".format(nexthop, "64", all_t2_neighbors[t2_neighbor][ecmp_utils.get_outer_layer_version(encap_type)].lower()))
                    del_static_route.append("sudo config route del prefix {}/{} nexthop {}".format(nexthop, "68", all_t2_neighbors[t2_neighbor][ecmp_utils.get_outer_layer_version(encap_type)].lower()))
                elif ecmp_utils.get_outer_layer_version(encap_type) == "v4":
                    del_static_route.append("sudo config route del prefix {}/{} nexthop {}".format(".".join(nexthop.split(".")[:-1])+".0", "24", all_t2_neighbors[t2_neighbor][ecmp_utils.get_outer_layer_version(encap_type)].lower()))
                    del_static_route.append("sudo config route del prefix {}/{} nexthop {}".format(nexthop, ecmp_utils.HOST_MASK[ecmp_utils.get_outer_layer_version(encap_type)], all_t2_neighbors[t2_neighbor][ecmp_utils.get_outer_layer_version(encap_type)].lower()))
                self.setup['duthost'].shell_cmds(cmds = del_static_route)
                self.setup[encap_type]['t2_ports'] = backup_t2_ports
        
        #Traffic verification to see if default route is preferred after deletion of static route
        self.dump_self_info_and_run_ptf("underlay_specific_route", encap_type, True)


    def test_underlay_portchannel_shutdown(self, setUp, minigraph_facts, encap_type):
        '''
            Bring down one of the port-channels.
            Packets are equally recieved at c1, c2 or c3
        '''
        self.setup = setUp
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]
        endpoint_nhmap = self.setup[encap_type]['dest_to_nh_map'][vnet]
        
        #Verification of traffic before shutting down port channel
        self.dump_self_info_and_run_ptf("tc12", encap_type, True, packet_count=1000)
        
        #Gathering all portchannels
        all_t2_portchannel_intfs = list(ecmp_utils.get_portchannels_to_neighbors(self.setup['duthost'], "T2", minigraph_facts))
        all_t2_portchannel_members = {}
        for each_pc in all_t2_portchannel_intfs:
            all_t2_portchannel_members[each_pc] = minigraph_facts['minigraph_portchannels'][each_pc]['members']
        
        selected_portchannel = all_t2_portchannel_members.keys()[0]

        #Shutting down the ethernet interfaces
        for intf in all_t2_portchannel_members[selected_portchannel]:
            self.setup['duthost'].shell("sudo config interface shutdown {}".format(intf))
        
        all_t2_ports = list(self.setup[encap_type]['t2_ports'])
        downed_ports = ecmp_utils.get_corresponding_ports(all_t2_portchannel_members[selected_portchannel], minigraph_facts)
        self.setup[encap_type]['t2_ports'] = list(set(all_t2_ports) - set(downed_ports))

        #Verification of traffic
        self.dump_self_info_and_run_ptf("tc12", encap_type, True, packet_count=1000)

        
class Test_VxLAN_entrophy(Test_VxLAN):
    def verify_entropy(self, setup, encap_type,random_sport = False, random_dport = True, varying_src_ip = False, tolerance = None):
        logger.info("Choose a vnet.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]
        logger.info("Create a new list of endpoint(s).")
        end_point_list = []
        for i in range(2):
            end_point_list.append(ecmp_utils.get_ip_address(af=ecmp_utils.get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))
        logger.info("Create a new destination")
        new_dest = ecmp_utils.get_ip_address(af=ecmp_utils.get_payload_version(encap_type), netid=DESTINATION_PREFIX)
        logger.info("Map the new destination and the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][new_dest] = end_point_list
        logger.info("Create a new config and Copy to the DUT.")
        config = '[\n' + ecmp_utils.create_single_route(vnet, new_dest, ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)], end_point_list, "SET") + '\n]'
        ecmp_utils.apply_config_in_swss(self.setup['duthost'], config, "vnet_route_tc4_"+encap_type)
        logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf("entropy", encap_type, True, random_sport = random_sport, random_dport = random_dport, varying_src_ip = varying_src_ip, packet_count = 400, tolerance = tolerance)
    def test_verify_entropy(self, setUp, encap_type):
        '''
        Verification of entrophy - Create tunnel route 4 to endpoint group A Send packets (fixed tuple) to route 4's prefix dst
        '''
        self.setup = setUp
        self.verify_entropy(self.setup, encap_type, random_dport = True, random_sport = True, varying_src_ip = True, tolerance = 0.03)

    def test_vxlan_random_dst_port(self, setUp, encap_type):
        '''
        Verification of entrophy - Change the udp dst port of original packet to route 4's prefix dst
        '''
        self.setup = setUp
        self.verify_entropy(self.setup, encap_type, tolerance = 0.03)

    def test_vxlan_random_src_port(self, setUp, encap_type):
        '''
        Verification of entrophy - Change the udp src port of original packet to route 4's prefix dst
        '''
        self.setup = setUp
        self.verify_entropy(self.setup, encap_type, random_dport = False, random_sport = True, tolerance = 0.03)

    def test_vxlan_varying_src_ip(self, setUp, encap_type):
        '''
        Verification of entrophy - Change the udp src ip of original packet to route 4's prefix dst
        '''
        self.setup = setUp
        self.verify_entropy(self.setup, encap_type, random_dport = False, varying_src_ip = True, tolerance = 0.03)

class Test_VxLAN_Crm:
    
    def test_crm_16k_routes(self, setUp, encap_type, duthosts, rand_one_dut_hostname):
        self.setup = setUp
        crm_output = self.setup['duthost'].get_crm_resources()['main_resources']
        outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
        if outer_layer_version == "v6":
            pytest_assert(crm_output['ipv6_route']['used'] >= (self.setup['crm']['ipv6_route']['used'] + 16000))
            pytest_assert(crm_output['ipv6_nexthop']['used'] >= (self.setup['crm']['ipv6_nexthop']['used'] + 16000))
        elif outer_layer_version == "v4":
            pytest_assert(crm_output['ipv4_route']['used'] >= (self.setup['crm']['ipv4_route']['used'] + 16000))
            pytest_assert(crm_output['ipv4_nexthop']['used'] >= (self.setup['crm']['ipv4_nexthop']['used'] + 16000))
    
    def test_crm_512_nexthop_groups(self, setUp, encap_type, duthosts, rand_one_dut_hostname):
        self.setup = setUp
        crm_output = self.setup['duthost'].get_crm_resources()['main_resources']
        outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
        pytest_assert(crm_output['nexthop_group']['used'] >= (self.setup['crm']['nexthop_group']['used'] + 16000))
    
    def test_crm_128_group_memebers(self, setUp, encap_type, duthosts, rand_one_dut_hostname):
        self.setup = setUp
        crm_output = self.setup['duthost'].get_crm_resources()['main_resources']
        pytest_assert(crm_output['nexthop_group_member']['used'] >= (self.setup['crm']['nexthop_group_member']['used'] + 16000))
        
