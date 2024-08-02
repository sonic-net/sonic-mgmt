#! /usr/bin/env python3
'''
    These tests check the Vxlam ecmp nexthop group switch over functionality. Further details are
    provided with each test.
'''

import time
import logging
from datetime import datetime
import json
import pytest

from tests.common.fixtures.ptfhost_utils \
    import copy_ptftests_directory     # noqa: F401
from tests.ptf_runner import ptf_runner
from tests.vxlan.vxlan_ecmp_utils import Ecmp_Utils

Logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()

# This is the list of encapsulations that will be tested in this script.
SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v6_in_v4']
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
    if platform == 'x86_64-mlnx_msn2700-r0' and encap_type in ['v4_in_v6', 'v6_in_v6']:
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


class Test_VxLAN_ECMP_Priority_endpoints():
    '''
        Class for all the Vxlan tunnel cases where primary and secondary next hops are configured.
    '''
    def dump_self_info_and_run_ptf(self,
                                   tcname,
                                   encap_type,
                                   expect_encap_success,
                                   packet_count=4,
                                   random_dport=True,
                                   random_sport=False,
                                   random_src_ip=False,
                                   tolerance=None,
                                   payload=None):
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

    def test_vxlan_priority_single_pri_sec_switchover(self, setUp, encap_type):
        '''
            tc1:create tunnel route 1 with two endpoints a = {a1, b1}. a1 is primary, b1 is secondary.
            1) both a1,b1 are UP.
            2) send packets to the route 1's prefix dst. packets are received at a1.
            3) bring a1 down.
            4) send packets to the route 1's prefix dst. packets are received at b1.
            5) bring both a1 and b1 down.
            6) No traffic is forwarded.
        '''
        self.vxlan_test_setup = setUp

        Logger.info("Choose a vnet.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]
        Logger.info("Create a new list of endpoint(s).")
        tc1_end_point_list = []
        for _ in range(2):
            tc1_end_point_list.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))

        Logger.info("Create a new destination")
        tc1_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)

        Logger.info("Create a new priority endpoint config and Copy to the DUT.")
        ax = {vnet: {tc1_new_dest: tc1_end_point_list}}
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'] = ax
        Logger.info("Create the json and apply the config in the DUT swss.")
        # The config looks like:
        # [
        #   {
        #     "VNET_ROUTE_TUNNEL_TABLE:vnet:tcx_new_dest/32": {
        #       "endpoint": "{tcx_end_point_list}"
        #       "endpoint_monitor": "{tcx_end_point_list}",
        #       "primary" : "{}",
        #       "adv_prefix" : "{}/{}",
        #     },
        #     "OP": "{}"
        #   }
        # ]
        try:
            ecmp_utils.create_and_apply_priority_config(
                self.vxlan_test_setup['duthost'],
                vnet,
                tc1_new_dest,
                ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                tc1_end_point_list,
                [tc1_end_point_list[0]],
                "SET")
            # both primary secondary are up.
            # only primary should recieve traffic.
            time.sleep(2)
            down_list = tc1_end_point_list[1]
            if isinstance(down_list, str):
                down_list = [down_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(down_list)
            # setting both primary and secondary as up. only primary will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc1_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc1_end_point_list[0], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc1_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc1_end_point_list[1], "up")
            time.sleep(10)
            # verifying overlay_dmac
            result = \
                self.vxlan_test_setup['duthost'].shell(
                    "sonic-db-cli APPL_DB HGET 'VNET_MONITOR_TABLE:{}:{}/{}' 'overlay_dmac'".format(
                        tc1_end_point_list[0],
                        tc1_new_dest,
                        ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)]))
            assert str(result['stdout']) == ecmp_utils.OVERLAY_DMAC

            self.dump_self_info_and_run_ptf("test1", encap_type, True)

            # Single primary-secondary switchover.
            # Endpoint list = [A, A`], Primary[A] | Active NH=[A] |
            # Action: A went Down | Result NH=[A`]
            # NH has a single primary endpoint which upon failing is replaced by the single Backup endpoint
            Logger.info("Single primary-secondary switchover.")
            time.sleep(2)
            down_list = tc1_end_point_list[0]
            if isinstance(down_list, str):
                down_list = [down_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(down_list)
            # setting primary down. only secondary will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc1_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc1_end_point_list[0], "down")
            time.sleep(10)
            self.dump_self_info_and_run_ptf("test1", encap_type, True)

            # Single primary recovery.
            # Endpoint list = [A, A`], Primary[A] | Active NH=[A`] |
            # Action: A is back up | ResultNH=[A]
            # NH has a single backup endpoint which upon recovery of primary is replaced.
            Logger.info("Single primary recovery.")
            time.sleep(2)
            down_list = tc1_end_point_list[1]
            if isinstance(down_list, str):
                down_list = [down_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(down_list)
            # setting primary up. only primary will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc1_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc1_end_point_list[0], "up")
            time.sleep(10)
            self.dump_self_info_and_run_ptf("test1", encap_type, True)

            # Single primary backup Failure.
            # Endpoint list = [A, A`]. Primary[A]| Active  NH=[A`]  A is DOWN  |
            # Action: A` goes Down | result NH=[]
            # No active Endpoint results in route being removed.
            Logger.info("Single primary & backup Failure.")
            down_list = tc1_end_point_list
            if isinstance(down_list, str):
                down_list = [down_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(down_list)
            # setting both down. no traffic is recieved.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc1_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc1_end_point_list[1], "down")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc1_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc1_end_point_list[0], "down")

            time.sleep(10)
            self.dump_self_info_and_run_ptf("test1", encap_type, True)
            ecmp_utils.create_and_apply_priority_config(
                self.vxlan_test_setup['duthost'],
                vnet,
                tc1_new_dest,
                ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                tc1_end_point_list,
                [tc1_end_point_list[0]],
                "DEL")

        except Exception:
            ecmp_utils.create_and_apply_priority_config(
                self.vxlan_test_setup['duthost'],
                vnet,
                tc1_new_dest,
                ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                tc1_end_point_list,
                [tc1_end_point_list[0]],
                "DEL")

    def test_vxlan_priority_multi_pri_sec_switchover(self, setUp, encap_type):
        '''
            tc2:create tunnel route 1 with 6 endpoints a = {A, B, A`, B`}. A,B
            are primary, A`,B` are secondary.
            1) All eps are up.A,B,A`,B`
            2) send packets to the route 1's prefix dst. packets are received at A,B.
            3) bring A down.
            4) send packets to the route 1's prefix dst. packets are received at B.
            5) bring B down.
            6) send packets to the route 1's prefix dst. packets are recieved at A`,B`.
            7) bring B` down.
            8) send packets to the route 1's prefix dst. packets are recieved at A`.
            9) bring A up.
            10) send packets to the route 1's prefix dst. packets are recieved at A.
            11) bring B, A`, B` up.
            12) send packets to the route 1's prefix dst. packets are recieved at A,B.
            13) Bring all endpoints down.
            14) no traffic being passed.
            15) bring A, B, A`,B` up.
            16) send packets to the route 1's prefix dst. packets are recieved at A,B.
            17) Bring all endpoints down.
            18) no traffic being passed.
            19) bring A`,B` up.
            20) send packets to the route 1's prefix dst. packets are recieved at A`,B`.
            21) bring A,B up.
            22) send packets to the route 1's prefix dst. packets are recieved at A, B.
        '''

        self.vxlan_test_setup = setUp

        Logger.info("Choose a vnet.")
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]
        Logger.info("Create a new list of endpoint(s).")
        tc2_end_point_list = []
        for _ in range(4):
            tc2_end_point_list.append(ecmp_utils.get_ip_address(
                af=ecmp_utils.get_outer_layer_version(encap_type),
                netid=NEXTHOP_PREFIX))

        Logger.info("Create a new destination")
        tc2_new_dest = ecmp_utils.get_ip_address(
            af=ecmp_utils.get_payload_version(encap_type),
            netid=DESTINATION_PREFIX)
        ax = {vnet: {tc2_new_dest: tc2_end_point_list}}
        self.vxlan_test_setup[encap_type]['dest_to_nh_map'] = ax
        Logger.info("Map the new destination and the new endpoint(s).")

        # The config looks like:
        # [
        #   {
        #     "VNET_ROUTE_TUNNEL_TABLE:vnet:tcx_new_dest/32": {
        #       "endpoint": "{tcx_end_point_list}"
        #       "endpoint_monitor": "{tcx_end_point_list}",
        #       "primary" : "{tcx_end_point_list[0:len/2]}",
        #       "adv_prefix" : "{tcx_new_dest}/{32}",
        #     },
        #     "OP": "{}"
        #   }
        # ]
        try:
            primary_nhg = tc2_end_point_list[0:2]
            secondary_nhg = tc2_end_point_list[2:4]
            Logger.info("Create a new priority endpoint config and Copy to the DUT.")
            ecmp_utils.create_and_apply_priority_config(
                self.vxlan_test_setup['duthost'],
                vnet,
                tc2_new_dest,
                ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                tc2_end_point_list,
                primary_nhg,
                "SET")

            time.sleep(5)
            # Bringing all endpoints UP.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc2_end_point_list[0], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc2_end_point_list[1], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc2_end_point_list[2], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              tc2_end_point_list[3], "up")

            # check all primary Eps are operational
            inactive_list = list(secondary_nhg)
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            time.sleep(10)
            # ensure that the traffic is distributed to all 3 primary Endpoints.
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups. Single primary failure.
            # Endpoint list = [A, B, A`, B`], Primary = [A, B] | active NH = [A, B] |
            # Action: A goes Down | Result NH=[B]
            # One of the primaries goes down. The others stay active.
            time.sleep(2)
            inactive_list = list(secondary_nhg)
            inactive_list.append(primary_nhg[0])
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting A down. B,C getting traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[0], "down")
            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups.  All primary failure.
            # Endpoint list = [A, B, A`, B`] Primary = [A, B] | A is Down. active NH = [B] |
            # Action: B goes Down.  | Result: NH=[A`, B`]
            # All the primaries are down. The backup endpoints are added to the NH group.
            time.sleep(2)
            inactive_list = list(primary_nhg)
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting C down, now all backups are up and recieving traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[1], "down")
            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups. Backup Failure.
            # Endpoint list = [A, B, A`, B`] Primary = [A, B] |
            # A, B already Down. Active NH = [A`, B`] |
            # Action: B` goes Down. | Result: NH=[A`]
            # All the primaries are down. Failure of a backup endpoint shall result in its removal from NH.
            time.sleep(2)
            inactive_list = list(primary_nhg)
            inactive_list.append(secondary_nhg[1])
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting C` down, now A` and B` are up and recieving traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[1], "down")
            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups. Single primary recovery.
            # Endpoint list = [A, B, A`, B`] Primary = [A, B] | Active NH = [A`] |
            # Action: A is Up. B still Down | Result: NH=[A]
            # Primary takes precedence and is added to the NH. All the backups are removed.
            time.sleep(2)
            inactive_list = list([primary_nhg[1]])
            inactive_list += secondary_nhg
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting A up. only A will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[0], "up")
            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups. Multiple primary & backup recovery.
            # Edpoint list = [A, B, A`, B`] Primary = [A, B] | Active NH = [A] |
            # Action: A is Up. B also come up along with A` and B` | Result: NH=[A, B]
            # Primary endpoints take precedence and are added to the NH.
            time.sleep(2)
            inactive_list = list(secondary_nhg)
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting B, C and C` up. only A,B,C will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[1], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[1], "up")

            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups. Multiple primary & backup all failure.
            # Edpoint list = [A, B, A`, B`] Primary = [A, B] | Active NH = [A,B] |
            # Action: All A, B, A`, B`, go down. | Result: NH=[]
            # Route is removed, No traffic forwarded.
            time.sleep(2)
            inactive_list = list(tc2_end_point_list)
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting B, C and C` up. only A,B,C will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[0], "down")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[1], "down")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[0], "down")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[1], "down")
            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups. Multiple primary & backup recovery.
            # Edpoint list = [A, B, A`, B`] Primary = [A, B] | Active NH = [] |
            # Action: A, B come up along with A` and B` | Result: NH=[A, B]
            # Primary endpoints take precedence and are added to the NH.
            time.sleep(2)
            inactive_list = list(secondary_nhg)
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting B, C and C` up. only A,B,C will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[0], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[1], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[0], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[1], "up")

            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups. Multiple primary & backup all failure 2.
            # Edpoint list = [A, B, A`, B`] Primary = [A, B] | Active NH = [A,B] |
            # Action: All A, B, A`, B`, go down. | Result: NH=[]
            # Route is removed, No traffic forwarded.
            time.sleep(2)
            inactive_list = list(tc2_end_point_list)
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting B, C and C` up. only A,B,C will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[0], "down")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[1], "down")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[0], "down")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[1], "down")
            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups. Multiple primary & backup recovery of secondary.
            # Edpoint list = [A, B, A`, B`] Primary = [A, B] | Active NH = [] |
            # Action: bring up  A` and B` | Result: NH=[A`, B`]
            # Primary endpoints take precedence and are added to the NH.
            time.sleep(2)
            inactive_list = list(primary_nhg)
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting B, C and C` up. only A,B,C will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[0], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              secondary_nhg[1], "up")

            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)

            # Multiple primary backups. Multiple primary & backup recovery of primary after secondary.
            # Edpoint list = [A, B, A`, B`] Primary = [A, B] | Active NH = [A`, B`] |
            # Action: bring up  A and B | Result: NH=[A, B]
            # Primary endpoints take precedence and are added to the NH.
            time.sleep(2)
            inactive_list = list(secondary_nhg)
            if isinstance(inactive_list, str):
                inactive_list = [inactive_list]
            self.vxlan_test_setup['list_of_downed_endpoints'] = set(inactive_list)
            # setting B, C and C` up. only A,B,C will recieve traffic.
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[0], "up")
            ecmp_utils.set_vnet_monitor_state(self.vxlan_test_setup['duthost'],
                                              tc2_new_dest,
                                              ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                                              primary_nhg[1], "up")

            time.sleep(10)
            self.dump_self_info_and_run_ptf("test2", encap_type, True)
            ecmp_utils.create_and_apply_priority_config(
                self.vxlan_test_setup['duthost'],
                vnet,
                tc2_new_dest,
                ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                tc2_end_point_list,
                primary_nhg,
                "DEL")

        except Exception:
            ecmp_utils.create_and_apply_priority_config(
                self.vxlan_test_setup['duthost'],
                vnet,
                tc2_new_dest,
                ecmp_utils.HOST_MASK[ecmp_utils.get_payload_version(encap_type)],
                tc2_end_point_list,
                primary_nhg,
                "DEL")
