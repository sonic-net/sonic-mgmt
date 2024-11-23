#! /usr/bin/env python3
'''
    These tests check the Vnet route precedence over bgp learnt route. Further details are
    provided with each test.
'''

import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert as py_assert
import ptf.testutils as testutils
from ptf import mask
from scapy.all import Ether, IP, VXLAN, IPv6, UDP
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from collections import defaultdict


Logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()
WAIT_TIME = 2
WAIT_TIME_EXTRA = 5

# This is the list of encapsulations that will be tested in this script.
SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v6_in_v4']
SUPPORTED_ROUTES_TYPES = ['precise_route', 'subnet_route']
SUPPORTED_MONITOR_TYPES = ['custom', 'BFD']
SUPPORTED_INIT_NEXTHOP_STATE = ['initially_up', 'initially_down']

pytestmark = [
    # This script supports any T1 topology: t1, t1-64-lag, t1-56-lag, t1-lag.
    pytest.mark.topology("t1")
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

@pytest.fixture(
    name="route_type",
    scope="module",
    params=SUPPORTED_ROUTES_TYPES)
def fixture_route_type(request):
    '''
        This fixture forces the script to perform one route type at a time.
        So this script doesn't support multiple route types at the same time.
    '''
    return request.param

@pytest.fixture(
    name="monitor_type",
    scope="module",
    params=SUPPORTED_MONITOR_TYPES)
def fixture_monitor_type(request):
    '''
        This fixture forces the script to perform one monitor_type at a time.
        So this script doesn't support multiple monitor types at the same time.
    '''
    return request.param

@pytest.fixture(
    name="init_nh_state",
    scope="module",
    params=SUPPORTED_INIT_NEXTHOP_STATE)
def fixture_init_nh_state(request):
    '''
        This fixture sets the initial nexthop state for the tests. It can be UP or DOWN.
        It ensures that the script tests one nexthop state at a time.
    '''
    return request.param

@pytest.fixture(autouse=True)
def _ignore_route_sync_errlogs(duthosts, rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        IgnoreRegex = [
            ".*Unaccounted_ROUTE_ENTRY_TABLE_entries.*",
            ".*missed_in_asic_db_routes.*",
            ".*Look at reported mismatches above.*",
            ".*Unaccounted_ROUTE_ENTRY_TABLE_entries.*",
            ".*'vnetRouteCheck' status failed.*",
            ".*Vnet Route Mismatch reported.*",
            ".*_M_construct null not valid.*",
            ".*construction from null is not valid.*",
            ".*meta_sai_validate_route_entry.*",

        ]
        # Ignore in KVM test
        KVMIgnoreRegex = [
            ".*doTask: Logic error: basic_string: construction from null is not valid.*",
        ]
        duthost = duthosts[rand_one_dut_hostname]
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(IgnoreRegex)
        if duthost.facts["asic_type"] == "vs":
            loganalyzer[rand_one_dut_hostname].ignore_regex.extend(KVMIgnoreRegex)
    return

@pytest.fixture(scope='module')
def prepare_test_port(rand_selected_dut, tbinfo):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    if tbinfo["topo"]["type"] == "mx":
        dut_port = rand_selected_dut.acl_facts()["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["ports"][0]
    else:
        dut_port = list(mg_facts['minigraph_portchannels'].keys())[0]
    if not dut_port:
        pytest.skip('No portchannels found')
    if "Ethernet" in dut_port:
        dut_eth_port = dut_port
    elif "PortChannel" in dut_port:
        dut_eth_port = mg_facts["minigraph_portchannels"][dut_port]["members"][0]
    ptf_src_port = mg_facts["minigraph_ptf_indices"][dut_eth_port]

    topo = tbinfo["topo"]["type"]
    # Get the list of upstream ports
    upstream_ports = defaultdict(list)
    upstream_port_ids = []
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if (topo == "t1" and "T2" in neighbor["name"]) or (topo == "t0" and "T1" in neighbor["name"]) or \
                (topo == "m0" and "M1" in neighbor["name"]) or (topo == "mx" and "M0" in neighbor["name"]):
            upstream_ports[neighbor['namespace']].append(interface)
            upstream_port_ids.append(port_id)

    return ptf_src_port, upstream_port_ids, dut_port

@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(duthosts,
                  request,
                  rand_one_dut_hostname,
                  minigraph_facts,
                  tbinfo,
                  nbrhosts,
                  ptfadapter,
                  prepare_test_port,
                  encap_type):
    '''
        Setup for the entire script.
        The basic steps in VxLAN configs are:
            1. Configure VxLAN tunnel.
            2. Configure Vnet and its VNI.

            The testcases are focused on the "configure routes" step. They add,
            delete, modify, the routes while testing the advertisement.
    '''
    data = {}
    nbrnames =list(nbrhosts.keys())
    data['t2'] = []
    data['t0'] = []
    for name in nbrnames:
        if 'T2' in name:
            data['t2'].append(nbrhosts[name])
        if 'T0' in name:
            data['t0'].append(nbrhosts[name])
    
    ptf_src_port, ptf_dst_ports, dut_port = prepare_test_port

    data['ptfadapter'] = ptfadapter
    data['ptf_src_ports'] = ptf_src_port
    data['ptf_dst_ports'] = ptf_dst_ports
    data['dut_port'] = dut_port
    data['tbinfo'] = tbinfo
    data['duthost'] = duthosts[rand_one_dut_hostname]
    data['minigraph_facts'] = \
        data['duthost'].get_extended_minigraph_facts(tbinfo)

    if data['minigraph_facts']['minigraph_lo_interfaces'][0]['prefixlen'] == 32:
        data['loopback_v4'] = data['minigraph_facts']['minigraph_lo_interfaces'][0]['addr']
        data['loopback_v6'] = data['minigraph_facts']['minigraph_lo_interfaces'][1]['addr']
    else:
        data['loopback_v4'] = data['minigraph_facts']['minigraph_lo_interfaces'][1]['addr']
        data['loopback_v6'] = data['minigraph_facts']['minigraph_lo_interfaces'][0]['addr']
    asic_type = duthosts[rand_one_dut_hostname].facts["asic_type"]
    if asic_type not in ["cisco-8000", "mellanox"]:
        raise RuntimeError("Pls update this script for your platform.")

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

    data['dut_mac'] = data['duthost'].facts['router_mac']
    time.sleep(WAIT_TIME)
    data["vxlan_port"] = 4789
    ecmp_utils.configure_vxlan_switch(
        data['duthost'],
        vxlan_port=data["vxlan_port"],
        dutmac=data['dut_mac'])
    data['active_routes'] = []
    # Copy the bfd_notifier.py script to the DUT
    src_path = "vxlan/bfd_notifier.py"
    dest_path = "/tmp/bfd_notifier.py"
    data['duthost'].copy(src=src_path, dest=dest_path)

    outer_layer_version = ecmp_utils.get_outer_layer_version(encap_type)
    encap_type_data = {}
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
            vni_base=10000,
            advertise_prefix='true')
        encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]
    data[encap_type] = encap_type_data

    yield data

    # Cleanup code.
    if encap_type == 'v4_in_v4':
        prefix_mask = 24
        prefix_type = 'v4'
    else:
        prefix_mask = 64
        prefix_type = 'v6'
    if 'active_routes' in data:
        for routes in data['active_routes']:
            ecmp_utils.set_routes_in_dut(data['duthost'],
                            routes,
                            prefix_type,
                            'DEL',
                            bfd=False,
                            mask=prefix_mask)

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

prefix_offset = 19


class Test_VNET_BGP_route_Precedence():
    '''
        Class for all the tests where VNET and BGP learnt routes are tested.
    '''
    def create_bgp_profile(self, name, community):
        #sonic-db-cli APPL_DB HSET "BGP_PROFILE_TABLE:FROM_SDN_SLB_ROUTES" "community_id" "1234:1235"
        self.duthost.shell("sonic-db-cli APPL_DB HSET 'BGP_PROFILE_TABLE:{}' 'community_id' '{}'"
                      .format(name, community))

    def remove_bgp_profile(self, name):
        #sonic-db-cli APPL_DB DEL "BGP_PROFILE_TABLE:FROM_SDN_SLB_ROUTES"
        self.duthost.shell("sonic-db-cli APPL_DB DEL 'BGP_PROFILE_TABLE:{}' "
                      .format(name))

    def generate_vnet_routes(self,encap_type, num_routes, postfix='',nhcount=4,fixed_route=False, nh_prefix="202"):
        nexthops = []
        global prefix_offset
        prefix_offset = prefix_offset + 1
        if nhcount > 4:
            py_assert("Nexthops more than 4 are not suppored.")

        for i in range(1, nhcount+1):
            nexthops.append(f'{nh_prefix}.1.1.{i}')

        if num_routes > 250:
            py_assert("Routes more than 250 are not suppored.")
        routes_adv = {}
        routes_prefix = {}
        vnet = list(self.vxlan_test_setup[encap_type]['vnet_vni_map'].keys())[0]
        routes_adv[vnet] = {}
        routes_prefix[vnet] = {}
        if fixed_route:
            if self.prefix_type == 'v4':
                routes_prefix[vnet][f"{prefix_offset}.131.131.1"] = nexthops.copy()
                routes_adv[vnet][f"{prefix_offset}.131.131.1"] = f"{prefix_offset}.131.131.0" 
                return routes_adv, routes_prefix
            else:
                routes_prefix[vnet][f"dcfa:{prefix_offset}:131::"] = nexthops.copy()
                routes_adv[vnet][f"dcfa:{prefix_offset}:131::"] = f"dcfa:{prefix_offset}:131::" 
                return routes_adv, routes_prefix
        count =0;
        if self.prefix_type == 'v4':
            for i in range(1,250):
                key1 = f"{prefix_offset}.{i}.0.{postfix}" if postfix != "" else f"{prefix_offset}.{i}.0.0"
                key2 = f"{prefix_offset}.{i}.0.0"
                routes_prefix[vnet][key1] = nexthops.copy()
                routes_adv[vnet][key1] = key2
                count = count + 1
                if count >= num_routes:
                    return routes_adv, routes_prefix
        else:
            for i in range(1,250):
                key1 = f"dc4a:{prefix_offset}:{i}::{postfix}" if postfix != "" else f"dc4a:{prefix_offset}:{i}::"
                key2 = f"dc4a:{prefix_offset}:{i}::"
                routes_prefix[vnet][key1] = nexthops.copy()
                routes_adv[vnet][key1] = key2
                count = count + 1
                if count >= num_routes:
                    return routes_adv, routes_prefix
        return routes_adv, routes_prefix

    def remove_vnet_route(self, routes):
        routes_copy = routes.copy()
        if routes in self.vxlan_test_setup['active_routes']:
            self.vxlan_test_setup['active_routes'].remove(routes)           
        ecmp_utils.set_routes_in_dut(self.duthost,
                          routes_copy,
                          self.prefix_type,
                          'DEL',
                          bfd=False,
                          mask=self.prefix_mask)

    def add_monitored_vnet_route(self, routes, routes_adv, profile, monitor_type):
        self.vxlan_test_setup['active_routes'].append(routes)            
        if monitor_type == 'custom':
            for vnet in routes:
                for prefix in routes[vnet]:
                    tc1_end_point_list = routes[vnet][prefix]
                    ecmp_utils.create_and_apply_priority_config(
                            self.duthost,
                            vnet,
                            prefix,
                            self.prefix_mask,
                            tc1_end_point_list,
                            tc1_end_point_list[0:2],
                            "SET",
                            profile,
                            adv_pfx=routes_adv[vnet][prefix],
                            adv_pfx_mask=self.adv_mask)
        else:       
            for vnet in routes:
                for prefix in routes[vnet]:
                    ecmp_utils.set_routes_in_dut(self.duthost,
                            routes,
                            self.prefix_type,
                            'SET',
                            bfd=True,
                            mask=self.prefix_mask,
                            profile=profile,
                            adv_pfx=routes_adv[vnet][prefix],
                            adv_pfx_mask=self.adv_mask)

    def verify_nighbor_has_routes(self, routes, routes_adv, community=""):
        t2_device = self.vxlan_test_setup['t2'][0]
        for vnet in routes:
            for prefix in routes[vnet]:
                route = f'{routes_adv[vnet][prefix]}/{self.adv_mask}'
                result = t2_device['host'].get_route(route)
                py_assert( route in result['vrfs']['default']['bgpRouteEntries'],
                           "Route not propogated to the T2")
                if community != "":
                    py_assert( community in str(result), "community not propogated." )
        return

    def verify_nighbor_doesnt_have_routes(self, routes,  routes_adv,community="" ):
        t2_device = self.vxlan_test_setup['t2'][0]
        for vnet in routes:
            for prefix in routes[vnet]:
                adv_pfx = routes_adv[vnet][prefix]
                route = f'{adv_pfx}/{self.adv_mask}'
                result = t2_device['host'].get_route(route)
                if community != "":
                    py_assert( community not in str(result), "community is still getting propogated along with route.")
                    return
                else:
                    py_assert( route not in result['vrfs']['default']['bgpRouteEntries'],
                               "Route is still propogating to the T2")
        return

    def add_bgp_route_to_neighbor_tor(self, tor, routes, routes_adv):
        if self.prefix_type == 'v4':
            type = 'ipv4'
            type1 = 'ip'
        else:
            type = 'ipv6'
            type1 = 'ipv6'
        # add a route in the neighbor TOR eos device
        for vnet in routes:
            for prefix in routes[vnet]:
                adv = routes_adv[vnet][prefix]
                result = tor['host'].run_command("show run | grep 'router bgp'")
                bgp_id_cmd = result['stdout'][0]
                cmds = ["configure",
                        "interface loopback 10",
                        "{} address {}/{}".format(type1, prefix, self.adv_mask),
                        "exit",
                        bgp_id_cmd,
                        "address-family {}".format(type),
                        "network {}/{}".format(adv, self.adv_mask),
                        "exit"
                        ]
                tor['host'].run_command_list(cmds)
                Logger.info("Route %s with prefix %s added to :%s", prefix, adv, tor['host'].hostname)
        return

    def remove_bgp_route_from_neighbor_tor(self, tor, routes, routes_adv):
        if self.prefix_type == 'v4':
            type = 'ipv4'
            type1 = 'ip'
        else:
            type = 'ipv6'
            type1 = 'ipv6'
        # add a route in the neighbor TOR eos device
        for vnet in routes:
            for prefix in routes[vnet]:
                adv_pfx = routes_adv[vnet][prefix]
                result = tor['host'].run_command("show run | grep 'router bgp'")
                bgp_id_cmd = result['stdout'][0]
                cmds = ["configure",
                        "interface loopback 10",
                        "no {} address {}/{}".format(type1, prefix, self.prefix_mask),
                        "exit",
                        bgp_id_cmd,
                        "address-family {}".format(type),
                        "no network {}/{}".format(adv_pfx, self.adv_mask),
                        "exit"
                        ]
                tor['host'].run_command_list(cmds)
                Logger.info("Route %s removed from :%s", prefix, tor['host'].hostname)

    def get_asic_db_bfd_session_id(self):
        cmd = "python /tmp/bfd_notifier.py"
        output = self.duthost.shell(cmd)
        assert output['rc'] == 0, f"Command failed with error: {output['stderr']}"
        result = eval(output['stdout'])
        return result        

    def update_bfds_state(self, bfd_ids, state):
        bfd_ids = list(bfd_ids)
        bfd_ids_str = ", ".join(bfd_ids)
        cmd = f'python /tmp/bfd_notifier.py --set "{bfd_ids_str}" "{state}"'
        output = self.duthost.shell(cmd)
        assert output['rc'] == 0, f"Command failed with error: {output['stderr']}"
        return

    def update_monitors_state(self, routes, state):
        if state == "Up":
            state = "up"
        else:
            state = "down"
        for vnet in routes:
            for prefix in routes[vnet]:
                for nh in routes[vnet][prefix]:
                    ecmp_utils.set_vnet_monitor_state(self.duthost,
                                            prefix,
                                            self.prefix_mask,
                                            nh,
                                            state)
        return

    def create_expected_packet(self, setUp_vnet, duthost, encap_type, inner_packet):
        outer_ip_src = setUp_vnet['loopback_v4'] if 'in_v4' in encap_type else setUp_vnet['loopback_v6']
        vxlan_vni = list(setUp_vnet[encap_type]['vnet_vni_map'].values())[0]

        if 'v4_in_v4' == encap_type:
            exp_pkt = testutils.simple_vxlan_packet(
                eth_src=duthost.facts['router_mac'],
                ip_src=outer_ip_src,
                ip_dst="0.0.0.0",  # We don't care about the outer dest IP
                udp_dport=setUp_vnet['vxlan_port'],
                vxlan_vni=vxlan_vni,
                inner_frame=inner_packet.copy()
            )
        elif 'v4_in_v6' == encap_type:
            exp_pkt = testutils.simple_vxlanv6_packet(
                eth_src=duthost.facts['router_mac'],
                ipv6_src=outer_ip_src,
                ipv6_dst="::",  # We don't care about the outer dest IP
                udp_dport=setUp_vnet['vxlan_port'],
                vxlan_vni=vxlan_vni,
                inner_frame=inner_packet.copy()
            )
        elif 'v6_in_v4' == encap_type:
            exp_pkt = testutils.simple_vxlan_packet(
                eth_src=duthost.facts['router_mac'],
                ip_src=outer_ip_src,
                ip_dst="0.0.0.0",  # We don't care about the outer dest IP
                udp_dport=setUp_vnet['vxlan_port'],
                vxlan_vni=vxlan_vni,
                inner_frame=inner_packet.copy()
            )
        elif 'v6_in_v6' == encap_type:
            exp_pkt = testutils.simple_vxlanv6_packet(
                eth_src=duthost.facts['router_mac'],
                ipv6_src=outer_ip_src,
                ipv6_dst="::",  # We don't care about the outer dest IP
                udp_dport=setUp_vnet['vxlan_port'],
                vxlan_vni=vxlan_vni,
                inner_frame=inner_packet.copy()
            )
        else:
            raise ValueError(f"Unsupported encap_type: {encap_type}")

        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(Ether, "dst")

        if 'in_v4' in encap_type:
            exp_pkt.set_do_not_care_scapy(IP, "ihl")
            exp_pkt.set_do_not_care_scapy(IP, "len")
            exp_pkt.set_do_not_care_scapy(IP, "id")
            exp_pkt.set_do_not_care_scapy(IP, "flags")
            exp_pkt.set_do_not_care_scapy(IP, "frag")
            exp_pkt.set_do_not_care_scapy(IP, "ttl")
            exp_pkt.set_do_not_care_scapy(IP, "proto")
            exp_pkt.set_do_not_care_scapy(IP, "chksum")
            exp_pkt.set_do_not_care_scapy(IP, "ttl")
            exp_pkt.set_do_not_care_scapy(IP, "dst")
            exp_pkt.set_do_not_care_scapy(IP, "tos")
            exp_pkt.set_do_not_care_scapy(UDP, 'sport')
            exp_pkt.set_do_not_care_scapy(UDP, 'len')
            exp_pkt.set_do_not_care_scapy(UDP, 'chksum')
        elif 'in_v6' in encap_type:
            exp_pkt.set_do_not_care_scapy(IPv6, "plen")
            exp_pkt.set_do_not_care_scapy(IPv6, "hlim")
            exp_pkt.set_do_not_care_scapy(IPv6, "nh")
            exp_pkt.set_do_not_care_scapy(IPv6, "dst")
            exp_pkt.set_do_not_care_scapy(IPv6, "tc")
            exp_pkt.set_do_not_care_scapy(UDP, 'sport')
            exp_pkt.set_do_not_care_scapy(UDP, 'len')
            exp_pkt.set_do_not_care_scapy(UDP, 'chksum')

        exp_pkt.set_do_not_care_scapy(VXLAN, 'flags')
        exp_pkt.set_do_not_care_scapy(VXLAN, 'reserved1')
        exp_pkt.set_do_not_care_scapy(VXLAN, 'reserved2')

        total_size = exp_pkt.size
        # We also dont care about the inner IP header checksum and TTL fields for both IPv4 and IPv6

        if 'v4_in' in encap_type:
            inner_ether_hdr_start = total_size - len(exp_pkt.exp_pkt[VXLAN][Ether])
            inner_ether_hdr_end = total_size - len(exp_pkt.exp_pkt[VXLAN][IP])
            for iter in range(inner_ether_hdr_start, inner_ether_hdr_end):
                exp_pkt.mask[iter] = 0x00

            exp_pkt.mask[inner_ether_hdr_end + 8] = 0x00  # TTL is changed
            exp_pkt.mask[inner_ether_hdr_end + 10] = 0x00  # checksum is changed
            exp_pkt.mask[inner_ether_hdr_end + 11] = 0x00  # checksum is changed
        elif 'v6_in' in encap_type:
            inner_ether_hdr_start = total_size - len(exp_pkt.exp_pkt[VXLAN][Ether])
            inner_ether_hdr_end = total_size - len(exp_pkt.exp_pkt[VXLAN][IPv6])
            for iter in range(inner_ether_hdr_start, inner_ether_hdr_end):
                exp_pkt.mask[iter] = 0x00

            exp_pkt.mask[inner_ether_hdr_end + 7] = 0x00  # Hop Limit (TTL) is changed
            exp_pkt.mask[inner_ether_hdr_end + 8] = 0x00  # checksum is changed
            exp_pkt.mask[inner_ether_hdr_end + 9] = 0x00  # checksum is changed
            exp_pkt.mask[inner_ether_hdr_end + 10] = 0x00  # checksum is changed
            exp_pkt.mask[inner_ether_hdr_end + 11] = 0x00  # checksum is changed

        if inner_packet is None:
            exp_pkt.set_ignore_extra_bytes()
        return exp_pkt

    def create_inner_packet(self,setUp_vnet, duthost, encap_type, routes):
        for vnet in routes:
            for prefix in routes[vnet]:
                dstip = prefix
            if 'v4_in' in encap_type:
                ipSrc = "170.170.170.170/32"
            else:
                ipSrc = "9999:AAAA:BBBB:CCCC:DDDD:EEEE:EEEE:7777/128"
            
            if 'v4_in' in encap_type:
                pkt = testutils.simple_udp_packet(
                    eth_dst=duthost.facts['router_mac'],
                    ip_src=ipSrc,
                    ip_dst=dstip,
                    ip_id=0,
                    ip_ihl=5,
                    ip_ttl=121,
                    udp_sport=1234,
                    udp_dport=4321
                )
            else:
                pkt = testutils.simple_udpv6_packet(
                    eth_dst=duthost.facts['router_mac'],
                    ipv6_src=ipSrc,
                    ipv6_dst=dstip,
                    ipv6_hlim=121,
                    udp_sport=1234,
                    udp_dport=4321                )
            return pkt

    def verify_tunnel_route_with_traffic(self, setup_vnet, duthost, encap_type, routes):
        pkt = self.create_inner_packet(setup_vnet, duthost, encap_type, routes)
        exp_pkt = self.create_expected_packet(setup_vnet, duthost, encap_type, pkt)
        setup_vnet['ptfadapter'].dataplane.flush()
        testutils.send(setup_vnet['ptfadapter'], setup_vnet['ptf_src_ports'], pkt=pkt)
        testutils.verify_packet_any_port(test=setup_vnet['ptfadapter'], pkt=exp_pkt, ports=setup_vnet['ptf_dst_ports'],timeout=10)

    def test_vnet_route_after_bgp(self, setUp, encap_type, monitor_type, init_nh_state, duthost):
        '''
        ADD BGP ROUTE on TOR
        Add VNET route
        Configure monitor (BFD or custom) with nexthop state (UP)
        Test with traffic
        Remove VNET route
        Remove BGP route
        '''
        if monitor_type == 'custom' and init_nh_state == 'initially_up':
            pytest.skip("Test not required for custom monitor and initially up nexthop state.")
        
        self.vxlan_test_setup = setUp
        self.duthost = duthost
       
        if monitor_type == 'BFD':
            profile = "FROM_SDN_SLB_ROUTES"
            community = "1234:4321"
        else:
            profile = "FROM_SDN_APPLIANCE_ROUTES"
            community = "6789:9876"
        self.create_bgp_profile(profile, community)

         # Determine the prefix type and mask based on encap_type and route_type
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
            self.prefix_mask = 24
            self.adv_mask = 24
        else:
            self.prefix_type = 'v6'
            self.adv_mask = 64
            self.prefix_mask = 64
        # generate routes
        routes_adv, routes = self.generate_vnet_routes(encap_type, 1, '1', 4)
        # Step 0: if init_nh_state is UP, add another route with same nexthops and bring up the sessions
        # This way the nexthops would be UP when the VNET route is added and this explores the 2nd path of
        # route installation.
        if init_nh_state == "initially_up":
            adv_fixed, fixed_route = self.generate_vnet_routes(encap_type, 1, '1', 4,True)
            self.add_monitored_vnet_route(fixed_route, adv_fixed, profile,monitor_type=monitor_type)
            time.sleep(WAIT_TIME)
            if monitor_type == 'BFD':
                bfd_ids = self.get_asic_db_bfd_session_id()
                self.update_bfds_state(bfd_ids.values(), "Up")
            elif monitor_type == 'custom':
                self.update_monitors_state(fixed_route, "Up")
            time.sleep(WAIT_TIME)            

        # Step 1: Add a route on the TOR
        tor = self.vxlan_test_setup['t0'][0]
        self.add_bgp_route_to_neighbor_tor(tor, routes, routes_adv)
        time.sleep(WAIT_TIME_EXTRA)
        # Check the route is propagated to the DUT
        for vnet in routes:
            for prefix in routes[vnet]:
                route = f'{routes_adv[vnet][prefix]}/{self.adv_mask}'
                result = self.duthost.shell(f"show ip route {route}" if self.prefix_type == 'v4' else f"show ipv6 route {route}")
                py_assert(route in result['stdout'], f"Route {route} not propagated to the DUT")

        # Verify the DUT has vnet_route_check.py and route_check passing
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        # Step 2: Create a route with the same prefix with monitoring
        self.add_monitored_vnet_route(routes, routes_adv, profile, monitor_type)
        time.sleep(WAIT_TIME)
        
        # Step3: bring up the monitoring sessions
        monitor_state = "Up"
        if monitor_type == 'BFD':
            bfd_ids = self.get_asic_db_bfd_session_id()
            self.update_bfds_state(bfd_ids.values(), monitor_state)
        elif monitor_type == 'custom':
            self.update_monitors_state(routes, monitor_state)
        # Verify the DUT has vnet_route_check.py and route_check passing
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")
        
        self.verify_nighbor_has_routes(routes, routes_adv, community)
        # Step 4: Test the traffic flow based on nexthop state
        time.sleep(WAIT_TIME_EXTRA)
        self.verify_tunnel_route_with_traffic(self.vxlan_test_setup, self.duthost, encap_type, routes)

        # Step 5: remove the VNET route
        self.remove_vnet_route(routes)
        time.sleep(WAIT_TIME)
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        # we expect the route_check not to fail as the vnet route is removed and BGP learnt route is readded. 
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        # Step 6: remove the BGP route
        self.remove_bgp_route_from_neighbor_tor(tor, routes, routes_adv)
        time.sleep(WAIT_TIME)
        self.verify_nighbor_doesnt_have_routes(routes, routes_adv, community)
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")
        
        if init_nh_state == "initially_up":
            self.remove_vnet_route(fixed_route)
            py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
            py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        self.remove_bgp_profile(profile)
        return

    def test_vnet_route_before_bgp_after_ep_up(self, setUp, encap_type, monitor_type, init_nh_state, duthost):
        '''
        Add VNET route
        Configure monitor (BFD or custom) with nexthop state (UP)
        Add BGP ROUTE on TOR
        Test with traffic
        Remove VNET ROUTE
        Remove BGP route
        '''
        if monitor_type == 'custom' and init_nh_state == 'initially_up':
            pytest.skip("Test not required for custom monitor and initially up nexthop state.")

        self.vxlan_test_setup = setUp
        self.duthost = duthost
       
        if monitor_type == 'BFD':
            profile = "FROM_SDN_SLB_ROUTES"
            community = "1234:4321"
        else:
            profile = "FROM_SDN_APPLIANCE_ROUTES"
            community = "6789:9876"
        self.create_bgp_profile(profile, community)

         # Determine the prefix type and mask based on encap_type and route_type
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
            self.prefix_mask = 24
            self.adv_mask = 24
        else:
            self.prefix_type = 'v6'
            self.adv_mask = 64
            self.prefix_mask = 64
        # generate routes
        routes_adv, routes = self.generate_vnet_routes(encap_type, 1, '1', 4)
        # Step 0: if init_nh_state is UP, add another route with same nexthops and bring up the sessions
        # This way the nexthops would be UP when the VNET route is added and this explores the 2nd path of
        # route installation.
        if init_nh_state == "initially_up":
            adv_fixed, fixed_route = self.generate_vnet_routes(encap_type, 1, '1', 4,True)
            self.add_monitored_vnet_route(fixed_route, adv_fixed, profile,monitor_type=monitor_type)
            time.sleep(WAIT_TIME)
            if monitor_type == 'BFD':
                bfd_ids = self.get_asic_db_bfd_session_id()
                self.update_bfds_state(bfd_ids.values(), "Up")
            elif monitor_type == 'custom':
                self.update_monitors_state(fixed_route, "Up")
            time.sleep(WAIT_TIME)            

        # Step 1: Create a route with the same prefix with monitoring
        self.add_monitored_vnet_route(routes, routes_adv, profile, monitor_type)
        time.sleep(WAIT_TIME)
        
        # Step 2: bring up the monitoring sessions
        monitor_state = "Up"
        if monitor_type == 'BFD':
            bfd_ids = self.get_asic_db_bfd_session_id()
            self.update_bfds_state(bfd_ids.values(), monitor_state)
        elif monitor_type == 'custom':
            self.update_monitors_state(routes, monitor_state)
        
        # Step 3: Add a route on the TOR
        tor = self.vxlan_test_setup['t0'][0]
        self.add_bgp_route_to_neighbor_tor(tor, routes, routes_adv)
        time.sleep(WAIT_TIME_EXTRA)

        # Verify the DUT has vnet_route_check.py and route_check passing
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")
        
        self.verify_nighbor_has_routes(routes, routes_adv, community)
        # Step 4: Test the traffic flow based on nexthop state
        time.sleep(WAIT_TIME_EXTRA)
        self.verify_tunnel_route_with_traffic(self.vxlan_test_setup, self.duthost, encap_type, routes)

        # Step 5: remove the VNET route
        self.remove_vnet_route(routes)
        time.sleep(WAIT_TIME)
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        # we expect the route_check not to fail as the vnet route is removed and BGP learnt route is readded. 
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        # Step 6: remove the BGP route
        self.remove_bgp_route_from_neighbor_tor(tor, routes, routes_adv)
        time.sleep(WAIT_TIME)
        self.verify_nighbor_doesnt_have_routes(routes, routes_adv, community)
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")
        
        if init_nh_state == "initially_up":
            self.remove_vnet_route(fixed_route)
            py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
            py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        self.remove_bgp_profile(profile)
        return

    def test_vnet_route_bgp_removal_before_ep(self, setUp, encap_type, monitor_type, init_nh_state, duthost):
        '''
        ADD BGP ROUTE on TOR
        Add VNET route
        Remove BGP route
        Configure monitor (BFD or custom) with nexthop state (UP)
        Test with traffic
        Remove VNET route
        '''
        if monitor_type == 'custom' and init_nh_state == 'initially_up':
            pytest.skip("Test not required for custom monitor and initially up nexthop state.")

        self.vxlan_test_setup = setUp
        self.duthost = duthost

        if monitor_type == 'BFD':
            profile = "FROM_SDN_SLB_ROUTES"
            community = "1234:4321"
        else:
            profile = "FROM_SDN_APPLIANCE_ROUTES"
            community = "6789:9876"
        self.create_bgp_profile(profile, community)

         # Determine the prefix type and mask based on encap_type and route_type
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
            self.prefix_mask = 24
            self.adv_mask = 24
        else:
            self.prefix_type = 'v6'
            self.adv_mask = 64
            self.prefix_mask = 64
        # generate routes
        routes_adv, routes = self.generate_vnet_routes(encap_type, 1, '1', 4)
        # Step 0: if init_nh_state is UP, add another route with same nexthops and bring up the sessions
        # This way the nexthops would be UP when the VNET route is added and this explores the 2nd path of
        # route installation.
        if init_nh_state == "initially_up":
            adv_fixed, fixed_route = self.generate_vnet_routes(encap_type, 1, '1', 4,True)
            self.add_monitored_vnet_route(fixed_route, adv_fixed, profile,monitor_type=monitor_type)
            time.sleep(WAIT_TIME)
            if monitor_type == 'BFD':
                bfd_ids = self.get_asic_db_bfd_session_id()
                self.update_bfds_state(bfd_ids.values(), "Up")
            elif monitor_type == 'custom':
                self.update_monitors_state(fixed_route, "Up")
            time.sleep(WAIT_TIME)            

        # Step 1: Add a route on the TOR
        tor = self.vxlan_test_setup['t0'][0]
        self.add_bgp_route_to_neighbor_tor(tor, routes, routes_adv)
        time.sleep(WAIT_TIME_EXTRA)
        # Check the route is propagated to the DUT
        for vnet in routes:
            for prefix in routes[vnet]:
                route = f'{routes_adv[vnet][prefix]}/{self.adv_mask}'
                result = self.duthost.shell(f"show ip route {route}" if self.prefix_type == 'v4' else f"show ipv6 route {route}")
                py_assert(route in result['stdout'], f"Route {route} not propagated to the DUT")

        # Verify the DUT has vnet_route_check.py and route_check passing
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        # Step 2: Create a route with the same prefix with monitoring
        self.add_monitored_vnet_route(routes, routes_adv, profile, monitor_type)
        time.sleep(WAIT_TIME)

        # Step 3: Remove the BGP route
        self.remove_bgp_route_from_neighbor_tor(tor, routes, routes_adv)
        time.sleep(WAIT_TIME_EXTRA)
        if init_nh_state == "initially_up":
            self.verify_nighbor_has_routes(routes, routes_adv, community)
        else:
            self.verify_nighbor_doesnt_have_routes(routes, routes_adv, community)
        # Step 4: Bring up the monitoring sessions
        monitor_state = "Up"
        if monitor_type == 'BFD':
            bfd_ids = self.get_asic_db_bfd_session_id()
            self.update_bfds_state(bfd_ids.values(), monitor_state)
        elif monitor_type == 'custom':
            self.update_monitors_state(routes, monitor_state)

        # Verify the DUT has vnet_route_check.py and route_check passing
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")
        
        self.verify_nighbor_has_routes(routes, routes_adv, community)
        # Step 5: Test the traffic flow based on nexthop state
        time.sleep(WAIT_TIME_EXTRA)
        self.verify_tunnel_route_with_traffic(self.vxlan_test_setup, self.duthost, encap_type, routes)

        # Step 6: Remove the VNET route
        self.remove_vnet_route(routes)
        time.sleep(WAIT_TIME)
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        # we expect the route_check not to fail as the vnet route is removed and BGP learnt route is readded. 
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        if init_nh_state == "initially_up":
            self.remove_vnet_route(fixed_route)
            py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
            py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        self.remove_bgp_profile(profile)
        return

    def test_vnet_route_after_bgp_with_early_bgp_removal(self, setUp, encap_type, monitor_type, duthost):
        '''
        Add VNET route
        Add BGP ROUTE on TOR
        Configure monitor (BFD or custom) with nexthop state (UP)
        Test with traffic
        Remove BGP route
        Test with traffic
        Remove VNET route
        '''

        self.vxlan_test_setup = setUp
        self.duthost = duthost
       
        if monitor_type == 'BFD':
            profile = "FROM_SDN_SLB_ROUTES"
            community = "1234:4321"
            nh_prefix = "203"
        else:
            profile = "FROM_SDN_APPLIANCE_ROUTES"
            community = "6789:9876"
            nh_prefix = "202"
        self.create_bgp_profile(profile, community)

         # Determine the prefix type and mask based on encap_type and route_type
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
            self.prefix_mask = 24
            self.adv_mask = 24
        else:
            self.prefix_type = 'v6'
            self.adv_mask = 64
            self.prefix_mask = 64
        # generate routes
        routes_adv, routes = self.generate_vnet_routes(encap_type, 1, '1', 4, nh_prefix=nh_prefix)

        # Step 1: Create a route with the same prefix with monitoring
        self.add_monitored_vnet_route(routes, routes_adv, profile, monitor_type)
        time.sleep(WAIT_TIME)
        
        # Step 2: Add a route on the TOR
        tor = self.vxlan_test_setup['t0'][0]
        self.add_bgp_route_to_neighbor_tor(tor, routes, routes_adv)
        time.sleep(WAIT_TIME_EXTRA)
        # Check the route is propagated to the DUT
        for vnet in routes:
            for prefix in routes[vnet]:
                route = f'{routes_adv[vnet][prefix]}/{self.adv_mask}'
                result = self.duthost.shell(f"show ip route {route}" if self.prefix_type == 'v4' else f"show ipv6 route {route}")
                py_assert(route in result['stdout'], f"Route {route} not propagated to the DUT")

        # Verify the DUT has route_check passing. vnet route_check would fail because monitors are down.
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        # Step 3: bring up the monitoring sessions
        monitor_state = "Up"
        if monitor_type == 'BFD':
            bfd_ids = self.get_asic_db_bfd_session_id()
            self.update_bfds_state(bfd_ids.values(), monitor_state)
        elif monitor_type == 'custom':
            self.update_monitors_state(routes, monitor_state)
        time.sleep(WAIT_TIME_EXTRA)
        # Verify the DUT has vnet_route_check.py and route_check passing
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")
        
        self.verify_nighbor_has_routes(routes, routes_adv, community)
        # Step 4: Test the traffic flow based on nexthop state
        time.sleep(WAIT_TIME_EXTRA)
        self.verify_tunnel_route_with_traffic(self.vxlan_test_setup, self.duthost, encap_type, routes)

        # Step 5: Remove the BGP route
        self.remove_bgp_route_from_neighbor_tor(tor, routes, routes_adv)

        # Step 6: Test the traffic flow based on nexthop state
        time.sleep(WAIT_TIME_EXTRA)
        self.verify_tunnel_route_with_traffic(self.vxlan_test_setup, self.duthost, encap_type, routes)

        # Step 7: remove the VNET route
        self.remove_vnet_route(routes)
        time.sleep(WAIT_TIME)
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        # we expect the route_check not to fail as the vnet route is removed and BGP learnt route is readded. 
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")
        
        self.remove_bgp_profile(profile)
        return

    def test_vnet_route_after_bgp_multi_flap(self, setUp, encap_type, monitor_type, init_nh_state, duthost):
        '''
        ADD BGP ROUTE on TOR
        Add VNET route
        Configure monitor (BFD or custom) with nexthop state (UP)
        Test with traffic
        flap the bfd/monitor sessions.
        Test with traffic
        Remove VNET route
        Remove BGP route
        '''
        if monitor_type == 'custom' and init_nh_state == 'initially_up':
            pytest.skip("Test not supported for custom monitor and initially up nexthop state.")

        self.vxlan_test_setup = setUp
        self.duthost = duthost
       
        if monitor_type == 'BFD':
            profile = "FROM_SDN_SLB_ROUTES"
            community = "1234:4321"
        else:
            profile = "FROM_SDN_APPLIANCE_ROUTES"
            community = "6789:9876"
        self.create_bgp_profile(profile, community)

         # Determine the prefix type and mask based on encap_type and route_type
        if encap_type == 'v4_in_v4':
            self.prefix_type = 'v4'
            self.prefix_mask = 24
            self.adv_mask = 24
        else:
            self.prefix_type = 'v6'
            self.adv_mask = 64
            self.prefix_mask = 64
        # generate routes
        routes_adv, routes = self.generate_vnet_routes(encap_type, 1, '1', 4)
        # Step 0: if init_nh_state is UP, add another route with same nexthops and bring up the sessions
        # This way the nexthops would be UP when the VNET route is added and this explores the 2nd path of
        # route installation.
        if init_nh_state == "initially_up":
            adv_fixed, fixed_route = self.generate_vnet_routes(encap_type, 1, '1', 4,True)
            self.add_monitored_vnet_route(fixed_route, adv_fixed, profile,monitor_type=monitor_type)
            time.sleep(WAIT_TIME)
            if monitor_type == 'BFD':
                bfd_ids = self.get_asic_db_bfd_session_id()
                self.update_bfds_state(bfd_ids.values(), "Up")
            elif monitor_type == 'custom':
                self.update_monitors_state(fixed_route, "Up")
            time.sleep(WAIT_TIME)            

        # Step 1: Add a route on the TOR
        tor = self.vxlan_test_setup['t0'][0]
        self.add_bgp_route_to_neighbor_tor(tor, routes, routes_adv)
        time.sleep(WAIT_TIME_EXTRA)
        # Check the route is propagated to the DUT
        for vnet in routes:
            for prefix in routes[vnet]:
                route = f'{routes_adv[vnet][prefix]}/{self.adv_mask}'
                result = self.duthost.shell(f"show ip route {route}" if self.prefix_type == 'v4' else f"show ipv6 route {route}")
                py_assert(route in result['stdout'], f"Route {route} not propagated to the DUT")

        # Verify the DUT has vnet_route_check.py and route_check passing
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        # Step 2: Create a route with the same prefix with monitoring
        self.add_monitored_vnet_route(routes, routes_adv, profile, monitor_type)
        time.sleep(WAIT_TIME)
        
        # Step3: bring up the monitoring sessions
        monitor_state = "Up"
        if monitor_type == 'BFD':
            bfd_ids = self.get_asic_db_bfd_session_id()
            self.update_bfds_state(bfd_ids.values(), monitor_state)
        elif monitor_type == 'custom':
            self.update_monitors_state(routes, monitor_state)

        # Verify the DUT has vnet_route_check.py and route_check passing
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")
        
        self.verify_nighbor_has_routes(routes, routes_adv, community)
        # Step 4: Test the traffic flow based on nexthop state
        time.sleep(WAIT_TIME_EXTRA)
        self.verify_tunnel_route_with_traffic(self.vxlan_test_setup, self.duthost, encap_type, routes)

        # Step 5: flap the monitoring sessions
        for i in range(5):
            monitor_state = "Down"
            if monitor_type == 'BFD':
                self.update_bfds_state(bfd_ids.values(), monitor_state)
                time.sleep(WAIT_TIME)
                monitor_state = "Up"
                self.update_bfds_state(bfd_ids.values(), monitor_state)
            elif monitor_type == 'custom':
                self.update_monitors_state(routes, monitor_state)
                time.sleep(WAIT_TIME)
                monitor_state = "Up"
                self.update_monitors_state(routes, monitor_state)
            time.sleep(WAIT_TIME_EXTRA)
        # step 6: Test the traffic flow.
        self.verify_tunnel_route_with_traffic(self.vxlan_test_setup, self.duthost, encap_type, routes)

        # Step 7: remove the VNET route
        self.remove_vnet_route(routes)
        time.sleep(WAIT_TIME)
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        # we expect the route_check not to fail as the vnet route is removed and BGP learnt route is readded. 
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        # Step 7: remove the BGP route
        self.remove_bgp_route_from_neighbor_tor(tor, routes, routes_adv)
        time.sleep(WAIT_TIME)
        self.verify_nighbor_doesnt_have_routes(routes, routes_adv, community)
        py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
        py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")
        
        if init_nh_state == "initially_up":
            self.remove_vnet_route(fixed_route)
            py_assert(self.duthost.shell("sudo vnet_route_check.py")['stdout'] == '', "vnet_route_check.py failed.")
            py_assert(self.duthost.shell("route_check.py")['stdout'] == '', "route_check.py failed.")

        self.remove_bgp_profile(profile)
        return



