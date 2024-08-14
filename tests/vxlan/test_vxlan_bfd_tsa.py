#! /usr/bin/env python3
'''
    These tests check the Vxlam ecmp with BFD TSA/TSB functionality. Further details are
    provided with each test.
'''

import time
import logging
from datetime import datetime
import json
import re
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa: F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test           # noqa F401
from tests.ptf_runner import ptf_runner
from tests.vxlan.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.config_reload import config_system_checks_passed
Logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()

# This is the list of encapsulations that will be tested in this script.
SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v6_in_v4', 'v4_in_v6', 'v6_in_v6']
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
                ".*[SX_API_INTERNAL.ERR].*",
                ".*Failed to start dhcp_relay.service.*",
                ".*Invalid VRF name.*"
            ])
    return


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

            The testcases are focused on the "configure routes" step. They add,
            delete, modify, the routes.
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

    data['ptfhost'] = ptfhost
    data['tbinfo'] = tbinfo
    data['duthost'] = duthosts[rand_one_dut_hostname]
    data['minigraph_facts'] = \
        data['duthost'].get_extended_minigraph_facts(tbinfo)
    data['dut_mac'] = data['duthost'].facts['router_mac']
    data['monitor_file'] = '/tmp/bfd_responder_monitor_file.txt'
    time.sleep(4)
    ecmp_utils.configure_vxlan_switch(
        data['duthost'],
        vxlan_port=4789,
        dutmac=data['dut_mac'])
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

    # Setting up bfd responder is needed only once per script run.
    loopback_addresses = \
        [str(x['addr']) for x in minigraph_facts['minigraph_lo_interfaces']]
    ecmp_utils.start_bfd_responder(
        data['ptfhost'],
        data['dut_mac'],
        loopback_addresses,
        monitor_file=data['monitor_file'])

    data[encap_type] = encap_type_data
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
    yield data

    # Cleanup code.
    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    payload_version = ecmp_utils.get_payload_version(encap_type)

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


class Test_VxLAN_BFD_TSA():
    '''
        Class for all the Vxlan tunnel cases where primary and secondary next hops are configured.
    '''
    def dump_self_info_and_run_ptf(self,
                                   tcname,
                                   encap_type,
                                   expect_encap_success,
                                   down_ep_list=[],
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
            "vxlan_port": 4789,
            "expect_encap_success": expect_encap_success,
            "packet_count": packet_count,
            "random_dport": random_dport,
            "random_sport": random_sport,
            "random_src_ip": random_src_ip,
            "tolerance": tolerance,
            "downed_endpoints": down_ep_list
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

    def update_monitor_list(self, encap_type, ip_address_list):
        '''
            Local function to update the bfd_responder's monitor file that
            tracks which interfaces and ip addresses the bfd_responder will
            work with.
        '''
        if isinstance(ip_address_list, str):
            ip_address_list = [ip_address_list]
        ecmp_utils.update_monitor_file(
            self.vxlan_test_setup['ptfhost'],
            self.vxlan_test_setup['monitor_file'],
            self.vxlan_test_setup[encap_type]['t2_ports'],
            set(ip_address_list))

    def create_vnet_route(self, encap_type):
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]

        Logger.info("Choose a destination, which is already present.")
        dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)
        Logger.info("Create a new endpoint, or endpoint-list.")
        end_point_list = []
        for _ in range(4):
            end_point_list.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))

        ax = {vnet: {dest: end_point_list}}
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'] = ax

        Logger.info("Create the json and apply the config in the DUT swss.")
        # The config looks like:
        # [
        #   {
        #     "VNET_ROUTE_TUNNEL_TABLE:vnet:dest/32": {
        #       "endpoint": "{end_point_list}"
        #       "endpoint_monitor": "{end_point_list}"
        #     },
        #     "OP": "{}"
        #   }
        # ]
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            end_point_list,
            "SET",
            True)
        self.update_monitor_list(
            encap_type,
            end_point_list)
        return dest, end_point_list

    def delete_vnet_route(self,
                          encap_type,
                          dest):
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]
        ecmp_utils.create_and_apply_config(
            self.vxlan_test_setup['duthost'],
            vnet,
            dest,
            ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
            [],
            "DEL",
            True)

    def apply_tsa(self):
        duthost = self.vxlan_test_setup['duthost']
        duthost.shell('sudo TSA')
        duthost.shell('sudo config save -y')

    def apply_tsb(self):
        duthost = self.vxlan_test_setup['duthost']
        duthost.shell('sudo TSB')
        duthost.shell('sudo config save -y')

    def in_maintainence(self):
        duthost = self.vxlan_test_setup['duthost']
        result = duthost.shell('sudo TSC')['stdout_lines']
        match = re.search("System Mode: Maintenance", "".join(result))
        if match:
            return True
        return False

    def verfiy_bfd_down(self, ep_list):
        duthost = self.vxlan_test_setup['duthost']
        result = duthost.shell('show bfd summary')['stdout_lines']
        if ep_list == []:
            match = re.search("Total number of BFD sessions: 0", "".join(result))
            if not match:
                return False
        else:
            for ep in ep_list:
                found = False
                for line in result:
                    if ep in line:
                        found = True
                        break
                if found:
                    return False
        return True

    def test_tsa_case1(self, setUp, encap_type, skip_traffic_test):     # noqa F811
        '''
            tc1: This test checks the basic TSA removal of BFD sessions.
            1) Create Vnet route with 4 endpoints and BFD monitors.
            2) send packets to the route prefix dst. packets are received at all 4 endpoints.
            3) apply TSA.
            4) check TSC is maintainence.
            5) Verify BFD sessions are down.
            6) apply TSB.
            7) check TSC is Normal.
            8) send packets to the route prefix dst. packets are received at all 4 endpoints.
            9) Delete route.
        '''
        self.vxlan_test_setup = setUp

        dest, ep_list = self.create_vnet_route(encap_type)

        self.dump_self_info_and_run_ptf("test1", encap_type, True, [], skip_traffic_test=skip_traffic_test)

        self.apply_tsa()
        pytest_assert(self.in_maintainence())
        self.verfiy_bfd_down(ep_list)

        self.apply_tsb()
        pytest_assert(not self.in_maintainence())

        self.dump_self_info_and_run_ptf("test1b", encap_type, True, [], skip_traffic_test=skip_traffic_test)

        self.delete_vnet_route(encap_type, dest)

    def test_tsa_case2(self, setUp, encap_type, skip_traffic_test):    # noqa F811
        '''
            tc2: This test checks the basic route application while in TSA.
            1) apply TSA.
            2) check TSC is maintainence.
            3) Verify BFD sessions are down.
            4) Create Vnet route with 4 endpoints and BFD monitors.
            5) apply TSB.
            6) check TSC is Normal.
            7) send packets to the route prefix dst. packets are received at all 4 endpoints.
            8) Delete route.
        '''
        self.vxlan_test_setup = setUp

        self.apply_tsa()
        pytest_assert(self.in_maintainence())
        self.verfiy_bfd_down([])

        dest, ep_list = self.create_vnet_route(encap_type)

        self.apply_tsb()
        pytest_assert(not self.in_maintainence())

        self.dump_self_info_and_run_ptf("test2", encap_type, True, [], skip_traffic_test=skip_traffic_test)

        self.delete_vnet_route(encap_type, dest)

    def test_tsa_case3(self, setUp, encap_type, skip_traffic_test):     # noqa F811
        '''
            tc3: This test checks for lasting impact of TSA and TSB.
            1) apply TSA.
            2) check TSC is maintainence.
            3) Verify BFD sessions are down.
            4) apply TSB.
            5) check TSC is Normal.
            6) Create Vnet route with 4 endpoints and BFD monitors.
            7) send packets to the route prefix dst. packets are received at all 4 endpoints.
            8) Delete route.
        '''
        self.vxlan_test_setup = setUp

        self.apply_tsa()
        pytest_assert(self.in_maintainence())
        self.verfiy_bfd_down([])

        self.apply_tsb()
        pytest_assert(not self.in_maintainence())

        dest, ep_list = self.create_vnet_route(encap_type)

        self.dump_self_info_and_run_ptf("test3", encap_type, True, [], skip_traffic_test=skip_traffic_test)

        self.delete_vnet_route(encap_type, dest)

    def test_tsa_case4(self, setUp, encap_type, skip_traffic_test):     # noqa F811
        '''
            tc4: This test checks basic Vnet route state retention during config reload.
            1) Create Vnet route with 4 endpoints and BFD monitors.
            2) save Config.
            3) send packets to the route prefix dst. packets are received at all 4 endpoints.
            4) perform config reload.
            5) readd the vnet routes.
            6) send packets to the route prefix dst. packets are received at all 4 endpoints.
            7) Delete route.
        '''
        self.vxlan_test_setup = setUp
        duthost = self.vxlan_test_setup['duthost']

        dest, ep_list = self.create_vnet_route(encap_type)

        duthost.shell("sudo config save -y",
                      executable="/bin/bash", module_ignore_errors=True)

        self.dump_self_info_and_run_ptf("test4", encap_type, True, [], skip_traffic_test=skip_traffic_test)

        duthost.shell("sudo config reload -y",
                      executable="/bin/bash", module_ignore_errors=True)
        assert wait_until(300, 20, 0, config_system_checks_passed, duthost, [])

        # readd routes as they are removed by config reload
        ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=4789, dutmac=self.vxlan_test_setup['dut_mac'])
        dest, ep_list = self.create_vnet_route(encap_type)

        self.dump_self_info_and_run_ptf("test4b", encap_type, True, [], skip_traffic_test=skip_traffic_test)

        self.delete_vnet_route(encap_type, dest)

    def test_tsa_case5(self, setUp, encap_type, skip_traffic_test):    # noqa F811
        '''
            tc4: This test checks TSA state retention w.r.t BFD accross config reload.
            1) Create Vnet route with 4 endpoints and BFD monitors.
            2) save Config.
            3) send packets to the route prefix dst. packets are received at all 4 endpoints.
            4) apply TSA.
            5) check TSC is maintainence.
            6) Verify BFD sessions are down.
            7) perform config reload.
            8) readd the vnet routes.
            9) apply TSB.
            10) check TSC is Normal.
            11) send packets to the route prefix dst. packets are received at all 4 endpoints.
            12) Delete route.
        '''
        self.vxlan_test_setup = setUp
        duthost = self.vxlan_test_setup['duthost']

        dest, ep_list = self.create_vnet_route(encap_type)

        duthost.shell("sudo config save -y",
                      executable="/bin/bash", module_ignore_errors=True)

        self.dump_self_info_and_run_ptf("test5", encap_type, True, [], skip_traffic_test=skip_traffic_test)

        self.apply_tsa()
        pytest_assert(self.in_maintainence())
        self.verfiy_bfd_down(ep_list)

        duthost.shell("sudo config reload -y",
                      executable="/bin/bash", module_ignore_errors=True)
        assert wait_until(300, 20, 0, config_system_checks_passed, duthost, [])

        # readd routes as they are removed by config reload
        ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=4789, dutmac=self.vxlan_test_setup['dut_mac'])
        dest, ep_list = self.create_vnet_route(encap_type)

        self.apply_tsb()
        pytest_assert(not self.in_maintainence())

        self.dump_self_info_and_run_ptf("test5b", encap_type, True, [], skip_traffic_test=skip_traffic_test)

        self.delete_vnet_route(encap_type, dest)

    def test_tsa_case6(self, setUp, encap_type, skip_traffic_test):     # noqa F811
        '''
            tc6: This test checks that the BFD doesnt come up while device
            is in TSA and remains down accross config reload.
            1) apply TSA.
            2) check TSC is maintainence.
            3) Verify BFD sessions are down.
            4) Create Vnet route with 4 endpoints and BFD monitors.
            5) save Config.
            6) readd the vnet routes.
            7) Verify BFD sessions are down.
            8) perform config reload.
            9) apply TSB.
            10) check TSC is Normal.
            11) send packets to the route prefix dst. packets are received at all 4 endpoints.
            12) Delete route.
        '''
        self.vxlan_test_setup = setUp
        duthost = self.vxlan_test_setup['duthost']

        self.apply_tsa()
        pytest_assert(self.in_maintainence())
        self.verfiy_bfd_down([])

        dest, ep_list = self.create_vnet_route(encap_type)

        duthost.shell("sudo config save -y",
                      executable="/bin/bash", module_ignore_errors=True)

        self.verfiy_bfd_down(ep_list)

        duthost.shell("sudo config reload -y",
                      executable="/bin/bash", module_ignore_errors=True)
        assert wait_until(300, 20, 0, config_system_checks_passed, duthost, [])

        # readd routes as they are removed by config reload
        ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=4789, dutmac=self.vxlan_test_setup['dut_mac'])
        dest, ep_list = self.create_vnet_route(encap_type)

        self.apply_tsb()
        pytest_assert(not self.in_maintainence())

        self.dump_self_info_and_run_ptf("test6", encap_type, True, [], skip_traffic_test=skip_traffic_test)

        self.delete_vnet_route(encap_type, dest)
