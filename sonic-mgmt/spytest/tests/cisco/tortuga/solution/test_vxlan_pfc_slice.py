"""
PFC Slice Congestion Tests for VXLAN EVPN Multi-Homing.

What is tested:
    PFC (Priority Flow Control) and ECN behavior under slice-level congestion in
    VXLAN EVPN topology. Validates PFC pause generation, VoQ backpressure, and
    ECN marking when traffic converges on a specific ASIC slice (vs single port).
    Covers egress leaf, spine, and ingress leaf slice congestion points with
    IPv4/IPv6, L2/L3 traffic, and PFC-only vs ECN-only vs normal modes.

Test plan:
    https://cisco-my.sharepoint.com/:x:/r/personal/bhavani_cisco_com/_layouts/15/Doc.aspx?sourcedoc=%7B90D47002-114B-4270-81F5-E8CF3590414B%7D&file=G200-AIML-Solution-testplan.xlsx&wdLOR=cE774C1C2-3963-4848-A637-26D7633BFBE0&fromShare=true&action=default&mobileredirect=true

Link to wiki with topology, details of scenarios being tested, validations and steps to run the test:
    https://ciscoteams.atlassian.net/wiki/spaces/WHITEBOX/pages/902465570/PFC+Automation+Port+and+Slice+Congestion+Testing

Topology:
    4 Spine + 4 Leaf (4S4L), same as VXLAN Multi-Homing. Config: vxlan_pfc_slice_input_file.yaml.

"""
import os
import re
import yaml
import pytest
from spytest import st, tgapi
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as pc_obj
from spytest.tgen import tg
import vxlan_helper as vxlan_obj
import profile
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
import random

from test_vxlan_pfc import TestPortCongestion


if os.environ.get('platform', 'q200') == 'g200':
    pfc_dpb_types_egress_leaf_egress_port = ['2x400G']
    #pfc_dpb_types_spine_egress_port = ['2x400G', '4x200G', '1x800G', '8x100G']
    pfc_dpb_types_spine_egress_port = ['2x400G', '4x200G', '8x100G']
    pfc_dpb_types_spine_egress_port = ['2x400G']
    #pfc_dpb_types_ingress_leaf_egress_port = ['2x400G', '4x200G', '1x800G', '8x100G']
    pfc_dpb_types_ingress_leaf_egress_port = ['2x400G', '4x200G', '8x100G']
    pfc_dpb_types_ingress_leaf_egress_port = ['2x400G']
else:
    pfc_dpb_types_egress_leaf_egress_port = ['1x100G', '1x25G', '1x10G']
    pfc_dpb_types_spine_egress_port = ['1x100G', '1x25G', '1x10G']
    pfc_dpb_types_ingress_leaf_egress_port = ['1x100G', '1x25G', '1x10G']

# Full 8 combos: (protocol, queue, traffictype)
_PFC_FULL_COMBOS = [
    ("ipv4", 3, "l2"), ("ipv4", 3, "l3"), ("ipv4", 4, "l2"), ("ipv4", 4, "l3"),
    ("ipv6", 3, "l2"), ("ipv6", 3, "l3"), ("ipv6", 4, "l2"), ("ipv6", 4, "l3"),
]
# Subset: 2 groups of 4; alternating tests use A or B so all 8 are covered across scenarios (same as PC)
_PFC_GROUP_A = [("ipv4", 3, "l2"), ("ipv4", 4, "l3"), ("ipv6", 3, "l2"), ("ipv6", 4, "l3")]
_PFC_GROUP_B = [("ipv4", 3, "l3"), ("ipv4", 4, "l2"), ("ipv6", 3, "l3"), ("ipv6", 4, "l2")]


def pytest_generate_tests(metafunc):
    """Dynamically parametrize TestSliceCongestion: PFC_RUN=full for all 8, else 4 with A/B alternation (same as PC)."""
    if metafunc.cls is None or metafunc.cls.__name__ != "TestSliceCongestion":
        return
    needed = {"protocol", "queue", "traffictype"}
    if not needed.issubset(set(metafunc.fixturenames)):
        return
    pfc_run = os.environ.get("PFC_RUN", "subset")
    if pfc_run == "full":
        combos = _PFC_FULL_COMBOS
    else:
        # Alternate A/B by test name (deterministic) so all 8 combos covered across the 9 tests
        idx = sum(ord(c) for c in metafunc.function.__name__) % 2
        combos = _PFC_GROUP_A if idx == 0 else _PFC_GROUP_B
    metafunc.parametrize("protocol,queue,traffictype", combos)


@pytest.fixture(scope="module", autouse=True)
def initialize_variables():
    global vars, nodes, tgen_handles, test_cfg, CONFIGS_FILE, pf

    CONFIGS_FILE = 'vxlan_pfc_slice_input_file.yaml'

    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        test_cfg = yaml.load(f, Loader=yaml.FullLoader)

    test_cfg['nodes'] = {'leaf': [], 'spine': [], 'all': [], 'l2l3vni': []}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            test_cfg['nodes']['leaf'].append(dut)
        else:
            test_cfg['nodes']['spine'].append(dut)
        test_cfg['nodes']['all'].append(dut)

        if test_cfg.get(dut) and \
           'l2vni' in test_cfg[dut].keys() and \
           'l3vni' in test_cfg[dut].keys():
            test_cfg['nodes']['l2l3vni'].append(dut)

    if not test_cfg.get('testcases'): 
        test_cfg['testcases'] = dict()
        test_cfg['global'] = dict()

    # setting platform specific variables (use CLI to detect platform when env not set, same as multihoming)
    if not st.getenv('platform'):
        if basic_obj.get_hwsku('leaf0') == "Cisco-HF6100-64ED":
            platform = 'g200'
        else:
            platform = 'q200'
        os.environ['platform'] = platform
    else:
        platform = st.getenv('platform')

    if platform == 'g200':
        test_cfg['global']['ndf_exp_tx_pkts'] = 300
        test_cfg['global']['bum_triggers_retries'] = 4
        test_cfg['global']['del_add_bgp_retries'] = 10
        test_cfg['global']['proc_restart_retries'] = 7
        test_cfg['global']['config_reload'] = 7
        test_cfg['global']['plus_bringup_time'] = 12
        test_cfg['global']['traffic_stop_protocol_sleep'] = 15
        test_cfg['global']['traffic_start_protocol_sleep'] = 15
        test_cfg['global']['bfd_enable'] = st.getenv('bfd', True)
        test_cfg['global']['qos_enable'] = st.getenv('qos', True)
        test_cfg['global']['restart_tgen_per_class'] = False
        # TODO test_cfg['global']['dpb_types'] = ['1x800G', '2x400G', '4x200G', '8x100G']
        test_cfg['global']['dpb_types'] = ['2x400G']
    else:
        test_cfg['global']['ndf_exp_tx_pkts'] = 150
        test_cfg['global']['bum_triggers_retries'] = 2
        test_cfg['global']['del_add_bgp_retries'] = 5
        test_cfg['global']['proc_restart_retries'] = 5
        test_cfg['global']['config_reload'] = 5
        test_cfg['global']['plus_bringup_time'] = 0
        test_cfg['global']['traffic_stop_protocol_sleep'] = 15
        test_cfg['global']['traffic_start_protocol_sleep'] = 15
        test_cfg['global']['bfd_enable'] = st.getenv('bfd', True)
        test_cfg['global']['qos_enable'] = st.getenv('qos', True)
        test_cfg['global']['restart_tgen_per_class'] = False
        test_cfg['global']['dpb_types'] = ['1x50', '1x25G', '1x10G']

    vars = st.get_testbed_vars()
    nodes = st.get_dut_names()
    pf = profile.VxlanPFCProfile(
        input_file=CONFIGS_FILE,
        vars=vars,
        leaf_nodes=test_cfg['nodes']['leaf'],
        spine_nodes=test_cfg['nodes']['spine'],
        l2l3vni_nodes=test_cfg['nodes']['l2l3vni'],
        test_cfg=test_cfg,
    )

@pytest.fixture(scope="module", autouse=True)
def copy_default_config_db():
    cmd = "sudo cp /etc/sonic/config_db.json config_db.json.orig"
    for dut in st.get_dut_names():
        st.config(dut, cmd, skip_error_check=True)

@pytest.fixture(scope="module", autouse=True)
def copy_spytest_helper():
    for dut in st.get_dut_names():
        st.config(dut, "cp /etc/spytest/remote/spytest-helper.py /etc/sonic/spytest-helper.py ")
        st.config(dut, " ls -lrt  /etc/spytest/remote/")
        st.config(dut, " ls -lrt /etc/sonic/")
    yield
    for dut in st.get_dut_names():
        st.config(dut,"rm /etc/sonic/spytest-helper.py")


@pytest.fixture(scope="module", autouse=True)
def vxlan_multi_homing_config(initial_dpb_config):
    """
    DUT-side config only (follow MH example). IXIA/TGEN config via tgen_preconfig.
    """
    global tgen_handles

    if st.getenv('skip_cfg', 'false') == 'false':
        pf.configure_sonic()

        for node in test_cfg['nodes']['l2l3vni']:
            vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")
            vxlan_obj.config_dut(node, "bgp", "do write")

    yield
    if st.getenv('skip_uncfg', 'false') == 'false':
        pf.configure_sonic(config=False)

        for node in test_cfg['nodes']['all']:
            vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")


@pytest.fixture(scope="module")
def initial_dpb_config(request):
    """
    Initial DPB configuration to ensure interfaces match what's in the testbed vars.
    This must run before vxlan_multi_homing_config (pf.configure_sonic).
    """
    if st.getenv('config_dpb', 'true') == 'true':
        try:
            # Get all interfaces from testbed vars
            all_intfs_need_dpb = False
            dpb_pattern = r'Ethernet\d+_\d+_\d+'
            
            # Check if any interface in vars has the breakout suffix pattern
            for key, value in vars.items():
                if isinstance(value, str) and re.match(dpb_pattern, value):
                    all_intfs_need_dpb = True
                    st.log("Detected breakout interface {} in testbed vars, DPB configuration needed".format(value))
                    break
            
            if all_intfs_need_dpb:
                # Assume 2x400G is the target DPB type (hardcoded for now, can be made configurable)
                dpb_type = '2x400G'
                st.log("Configuring initial DPB setting: {}".format(dpb_type))
                
                # Check if DPB is already configured on one node as a representative
                dut = 'leaf0'
                node_intfs = vxlan_obj.get_dut_interfaces(vars)
                intfs_status = vxlan_obj.get_interfaces_status(dut)
                
                # Check if all expected breakout interfaces exist and have correct speed
                all_match = True
                for intf_dict in [node_intfs[dut].get('underlay_dict', {}), node_intfs[dut].get('dut_port_dict', {})]:
                    for intf in intf_dict.values():
                        if not re.match(dpb_pattern, intf):
                            continue  # Not a breakout interface
                        found = False
                        for status in intfs_status:
                            if status['interface'] == intf:
                                found = True
                                if '400' not in status.get('speed', ''):
                                    st.log("Interface {} has wrong speed: {}".format(intf, status.get('speed')))
                                    all_match = False
                                break
                        if not found:
                            st.log("Interface {} not found in interface status".format(intf))
                            all_match = False
                            break
                    if not all_match:
                        break
                
                if not all_match:
                    st.log("DPB configuration needed, applying {}".format(dpb_type))
                    try:
                        pf.change_underlay_dpb(dpb_type=dpb_type)
                        st.log("DPB configuration completed successfully")
                    except Exception as err:
                        if "already configured" not in str(err):
                            raise err
                        st.log("DPB already configured: {}".format(err))
                else:
                    st.log("DPB already configured correctly, setting current_dpb_type")
                    test_cfg['global']['current_dpb_type'] = dpb_type
            else:
                st.log("No breakout interfaces detected in testbed, skipping initial DPB configuration")
        except Exception as err:
            st.error("Initial DPB configuration failed: {}".format(err))
            import traceback
            st.error("Traceback: {}".format(traceback.format_exc()))
            # Don't fail the test run, as this might not be critical
            pass
    else:
        st.log("DPB configuration disabled via config_dpb env var")

def tgen_preconfig(**kwargs):
    leaf_nodes = test_cfg['nodes']['l2l3vni']
    svi_dict_v4 = {}
    svi_dict_v6 ={}
    stream_handles = {}

    global g_v4_host_info_dict
    global g_v6_host_info_dict

    if st.getenv('skip_tgen', 'false') == 'true':
        return stream_handles        
    l2vni_intf_dict = vxlan_obj.get_interfaces(vars, leaf_nodes, 'l2vni')
    
    # Debug: Check if l2vni_intf_dict is empty for any node
    st.log("DEBUG: l2vni_intf_dict = {}".format(l2vni_intf_dict))
    for node in leaf_nodes:
        if node not in l2vni_intf_dict or not l2vni_intf_dict[node]:
            st.error("ERROR: l2vni_intf_dict for node {} is empty or missing!".format(node))
            st.log("Available nodes in l2vni_intf_dict: {}".format(list(l2vni_intf_dict.keys())))
            # Try to get more info about why this happened
            node_intfs = vxlan_obj.get_dut_interfaces(vars)
            st.log("DUT interfaces for node {}: {}".format(node, node_intfs.get(node, 'NOT FOUND')))
            int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
            st.log("Config interfaces for node {}: {}".format(node, int_config_dict.get(node, 'NOT FOUND')))
            # Check the L2VNI config from test_cfg
            if node in test_cfg and 'l2vni' in test_cfg[node]:
                st.log("L2VNI config for node {} from test_cfg: {}".format(node, test_cfg[node]['l2vni']))

    stream_handles["tg_handle"] = tgapi.get_handles(vars, list(vars['tgen_ports'].keys()))['tg']

    # configure fcoe on ports
    if test_cfg['global']['qos_enable']:
        tg_ports = list(stream_handles["tg_handle"].tg_port_handle.keys())
        vxlan_obj.config_tgen_fcoe(stream_handles["tg_handle"], tg_ports)
    
    #port channel interfaces 
    # getting list of port_channels in config file
    port_channel = dict()
    for node, config in test_cfg.items():
        if not config: continue
        if node not in test_cfg['nodes']['all']: continue
        for pc_channel in test_cfg[node].get('port_channels', []):
            pc_num = pc_channel['port_channel_num']
            if pc_num not in port_channel:
                port_channel[pc_num] = dict()
            port_channel[pc_num][node] = pc_channel['member_ids']

    def get_port_channel_match(tgn_port, port_channel):
        """check if tgn port is part of  any of the port channels and create port channel info"""
        pc_match = False
        for pc_num , pc_info in port_channel.items():
            port_list = list()
            node_list = list()
            for node, member_ids in pc_info.items():
                for member_id in member_ids:
                    peer_port_id = vxlan_obj.get_peer_port_id(member_id, vars, node)
                    node_list.append(vxlan_obj.get_device_id(node, vars))
                    port_list.append(peer_port_id)
                    if tgn_port == peer_port_id:
                        pc_match = True 
            if pc_match:
                return {'num': pc_num, 'nodes': node_list, 'ports': port_list}
        else:
            return pc_match

    # search for port channel ports in l2vi_int_dict and replace with portchannel info dict
    pc_list = list()
    new_l2vni_intf_dict = dict()
    for node in sorted(l2vni_intf_dict.keys()):
        new_l2vni_intf_dict[node] = list()
        for tgn_port in l2vni_intf_dict[node]:
            port_channel_match = get_port_channel_match(tgn_port, port_channel)
            if port_channel_match:
                if port_channel_match['num'] not in pc_list:

                    pc_list.append(port_channel_match['num'])
                    port_channel_name =  'PortChannel{}_{}'.format(port_channel_match['num'], 
                                                                     ''.join(port_channel_match['nodes']))
                    tgn_port =  {'name': port_channel_name, 
                                 'ports': port_channel_match['ports'], 
                                 'port_channel_num': port_channel_match['num']}
                    new_l2vni_intf_dict[node].append(tgn_port)
            else:
                new_l2vni_intf_dict[node].append(tgn_port)
    
    l2vni_intf_dict = new_l2vni_intf_dict
    test_cfg["l2vni_intf_dict"] = l2vni_intf_dict

    # generate vlans on each port (which vlans are on which tgen port per YAML members)
    # Use device id from port (e.g. T1D5P3 -> D5 from peer_port_id D5T1P3) for matching so we get
    # correct vlans regardless of testbed node name -> device_id mapping.
    port_vlan_dict = {}
    for node, ports in l2vni_intf_dict.items():
        node_id = vxlan_obj.get_device_id(node, vars)
        for port in ports:
            if type(port) == dict:
                # port channel type
                peer_port_id = 'PortChannel{}'.format(port['port_channel_num'])
                port_key = port['name']
            else:
                peer_port_id = vxlan_obj.get_peer_port_id(port, vars)
                port_key = port
            # For tgen ports (e.g. T1D5P3), peer_port_id is D5T1P3; device id in port is D5.
            # Use it for member match so node_id vs port device id mismatch (e.g. leaf0->D3) doesn't drop vlans.
            if 'T1' in str(peer_port_id):
                port_device_id = peer_port_id.split('T1')[0]
            else:
                port_device_id = node_id

            port_vlan_dict[port_key] = list()
            for item in test_cfg[node]['l2vni']:
                for member in item['members']:
                    if port_device_id + member == peer_port_id or member == peer_port_id:
                        port_vlan_dict[port_key].append(item['vlan_id'])
    
    ###Get topology Handles###
    topo_handles = vxlan_obj.create_topology_handles(l2vni_intf_dict)
    
    for node, config in test_cfg.items():
        if node in test_cfg['nodes']['l2l3vni']:

            if kwargs.get('custom_svi_ip'):
                svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv4', ip_start = "10.2.0.1")
                svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv6', ip_start = "1000:2::1")
            else:
                svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv4')
                svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv6')
    g_v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4, port_vlan_dict=port_vlan_dict, 
                                                     skip_nodes=[])
    g_v6_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v6, port_vlan_dict = port_vlan_dict, 
                                                     version="ipv6", skip_nodes=[])

    ###CREATE DEVICE GROUPS###
    
    #ipv4
    out_v4 = vxlan_obj.create_device_groups(topo_handles,g_v4_host_info_dict)
    v4_node_device_handles = out_v4[0]
    #ipv6
    out_v6 = vxlan_obj.create_device_groups(topo_handles,g_v6_host_info_dict,version ="ipv6")
    v6_node_device_handles = out_v6[0]
    
    v4_device_handles = {}
    v6_device_handles = {}
    
    for node, interfaces in v4_node_device_handles.items():
        for interface,values in interfaces.items():
            v4_device_handles[interface] =values
    for node, interfaces in v6_node_device_handles.items():
        for interface,values in interfaces.items():
            v6_device_handles[interface] =values
    ### start all protocols ###
    # Find a node with non-empty l2vni_intf_dict
    selected_node = None
    for node in leaf_nodes:
        if l2vni_intf_dict.get(node):
            selected_node = node
            st.log("Using node {} for TGEN handle (has {} interfaces)".format(node, len(l2vni_intf_dict[node])))
            break
    
    if not selected_node:
        st.error("Cannot start protocols: all nodes have empty l2vni_intf_dict!")
        st.error("leaf_nodes = {}".format(leaf_nodes))
        st.error("l2vni_intf_dict = {}".format(l2vni_intf_dict))
        raise Exception("All nodes have empty l2vni_intf_dict - no TGEN interfaces found")
    
    tg_handle = topo_handles[selected_node][l2vni_intf_dict[selected_node][0]]['tg_handle']

    start_protocol = vxlan_obj.start_stop_protocols(tg_handle,action='start')
    # fail only if it is not 0, Otherwise say started successfully
    if start_protocol == 0:
        st.report_tgen_fail('start protocols failed!')
    else:
        st.log("protocols started successfully")
        
    ### choose traffic item endpoints###
    l2_traffic_endpoints = vxlan_obj.find_l2_traffic_endpoints(g_v4_host_info_dict)
    # get vrf - vlan mapping from configs
    vrf_vlan_dict = dict()
    for item in test_cfg['leaf0']['l3vni']:
       vrf_vlan_dict[item['vrf_id']] = item['vlan_bindings']

    l3_traffic_endpoints = vxlan_obj.find_l3_traffic_endpoints(g_v4_host_info_dict, vrf_vlan_dict = vrf_vlan_dict)
    ### create traffic item endpoints###
    
    stream_handles['l2_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,
                                                            endpoints=l2_traffic_endpoints,
                                                            topo_handles=topo_handles, 
                                                            multi_dst = 'vlan', name_prfx='L2',
                                                            rate_percent=test_cfg['global']['l2l3']['rate_percent'],
                                                            pkts_per_burst=test_cfg['global']['l2l3']['pkts_per_burst'])

    #BUM
    cntr = 1
    ###Disable all streams###
    streams = []
    for traffic_type, item in stream_handles.items():
        if traffic_type in ['l2_v4','l3_v4','l2_v6','l3_v6','bum_MH','bum_SH']:
            for key, value in item.items():
                streams.append(value['stream_id'])
    tg_handle.tg_traffic_config(mode = 'disable', stream_id = streams)

    stream_handles["topo_handles"] = topo_handles
    stream_handles["v4_device_handles"] = v4_device_handles
    stream_handles["v6_device_handles"] = v6_device_handles

    return stream_handles

@pytest.fixture(scope = "function", autouse=True)
def pretest(request):
    result = True
    
    for dut in test_cfg['nodes']['l2l3vni']:
        st.log("Pretest : Check vteps on leaf_nodes node: {}".format(dut))
        try:
            exp_data = vxlan_obj.get_expected_vxlan_remotevtep(dut)
            vxlan_obj.verify_vxlan_remotevtep(dut, exp_data)
            st.log('Verify Vxlan-VNI map on {}: Pass'.format(dut))
        except Exception as err:
            st.log('Verify EVPN ES-EVI on {}: Fail\n{}'.format(dut, err))
            result = False

    if result:
        st.log("Pretest : Pass")
    else:
        st.log("Pretest : Fail")
        vxlan_obj.get_cli_out(test_cfg['nodes']['l2l3vni'])
        vxlan_obj.collect_diags()
        st.banner("Pretest : Fail. Skipping testcase.")
    return result

@pytest.fixture(scope="function", autouse=True)       
def fail_on_core(request):
    cores = vxlan_obj.check_core()
    if cores:
        st.banner("core present in dut before the start of the test, core copied and failing test")
        st.report_fail("test_case_failed")
    yield
    cores = vxlan_obj.check_core()
    if cores:
        st.banner("core generated during the test, core copied and failing test")
        st.report_fail("test_case_failed")

def reset_preconf_tgen(kill=True):

    global test_cfg, tgen_handles, vars
    if kill:
        for tgen in vars['tgen_list']:
            tgobj =  tgapi.get_tgen_obj_dict()[tgen]
            #tgobj.clean_all()
            tgobj.tg_disconnect()
        st.wait(120)
        tg.connect_tgen()
    tgen_handles = tgen_preconfig()
    return True

@pytest.fixture(scope = 'function', autouse=True)
def tgen_health_check(request):
    test_cfg['tgen_tc_status'] = {'last_tc': request.node.name, request.node.name: True}
    yield
    st.log('Last failure {} : {} : {}'.format(request.node.name, st.get_result(), st.getwa().last_error))
    if st.getwa().last_error and st.getwa().last_error.startswith('TG'):
        st.banner('TGen Failure detected ({}), reseting tgen'.format(st.getwa().last_error))
        reset_preconf_tgen()
        test_cfg['tgen_tc_status'][request.node.name] = False


@pytest.fixture(scope = 'class', autouse=True)
def tgen_health_check_class(request):
    if test_cfg['global'].get('restart_tgen_force', 'first') == 'first':
        st.banner('Configuring IXIA')
        reset_preconf_tgen(kill=False)
        test_cfg['global']['restart_tgen_force'] = False
    elif test_cfg['global']['restart_tgen_force'] == True:
        st.banner('Restarting and Reconfiguring IXIA')
        reset_preconf_tgen()
        test_cfg['global']['restart_tgen_force'] = False
    elif test_cfg['global']['restart_tgen_per_class']:
        if test_cfg['tgen_tc_status'][test_cfg['tgen_tc_status']['last_tc']] == True:
            #if the prev testcase tgen failed and did reset then dont reset
            st.banner('Restarting and Reconfiguring IXIA as restart tgen per class flag is set')
            reset_preconf_tgen()
    yield
    st.log('Last failure {} : {} : {}'.format(request.node.name, st.get_result(), st.getwa().last_error))
    if st.getwa().last_error and st.getwa().last_error.startswith('TG'):

        # module result is set to TGenFail if the fixture 
        # for the class fails due to tgen failure
        # this will result in skipping all remaining tests in the module.
        # Reset the module result to pass after tgen recovery
        test_cfg['global']['restart_tgen_force'] = True
        from spytest import framework
        res, desc = framework.get_current_result('module')
        st.log('Current Module Result: {} Desc: {}'.format(res, desc))
        framework.set_current_result(res=None, scope='module')
        res, desc = framework.get_current_result('module')
        st.log('New Module Result set: {} Desc: {}'.format(res, desc))
        st.log(st.getwa().abort_module_msg)
        st.log(st.getwa().abort_module_res)
        st.getwa().abort_module_msg = None
        st.getwa().abort_module_res = None

@pytest.fixture(scope = 'class', autouse=True)
def config_random_dpb_underlay(request):
    if st.getenv('config_dpb', 'true') == 'true':
        try:
            dpb_type = random.choice(test_cfg['global']['dpb_types'])
            st.log("Configuring new DPB setting on underlay links: {})".format(dpb_type))
            pf.change_underlay_dpb(dpb_type=dpb_type)
        except Exception as err:
            if not "already configured" in str(err):
                raise err

def find_tgen_port_name(port, dut=None):  
    """
    Find the "tgen port channel name" given the port channel name / number
    """
    if not (str(port).startswith('PortChannel') or str(port).isdigit()):
        port_id = vxlan_obj.get_peer_port_id(port, vars, dut)
        return port_id

    duts = [dut] if dut else tgen_handles['topo_handles'].keys()
    match = re.match('^PortChannel([0-9]+)' , str(port))
    port_channel_num = match.group(1) if match else str(port)
    for dut in duts:
        for tgen_port , handles in tgen_handles['topo_handles'][dut].items():
            if tgen_port.startswith('PortChannel{}_'.format(port_channel_num)):
                return tgen_port
    else:
        return None

class TestSliceCongestion(TestPortCongestion):
    
    def build_egress_leaf_traffic_items(self, protocol, queue, traffictype):
        """
        Build 8 traffic streams that converge at leaf1's egress ports to TGEN.
        Traffic distribution:
          - Streams 1-5: TGEN  to  leaf0  to  spine0  to  leaf1  to  TGEN (8 egress ports P1,P3-P9)
          - Stream 6: TGEN  to  leaf0 (P6)  to  spine1  to  leaf1  to  TGEN
          - Stream 7: TGEN  to  leaf2  to  spine1  to  leaf1  to  TGEN
          - Stream 8: TGEN  to  leaf2-leaf3 PortChannel  to  spine2  to  leaf1  to  TGEN
        Congestion: All 8 streams egress through leaf1's 8 ports to TGEN
        """
        q = str(queue)
        return [
            # Streams 1-5: TGEN  to  leaf0  to  spine0  to  leaf1  to  TGEN
            {
                'name': 'PFC_egress_leaf1_1',
                'path': [{'T1': 'P1'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P1'}, {'T1': 'P1'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_egress_leaf1_2',
                'path': [{'T1': 'P3'}, {'leaf0': 'P1'}, {'spine0': 'P2'},
                        {'leaf1': 'P3'}, {'T1': 'P3'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_egress_leaf1_3',
                'path': [{'T1': 'P4'}, {'leaf0': 'P1'}, {'spine0': 'P3'},
                        {'leaf1': 'P4'}, {'T1': 'P4'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_egress_leaf1_4',
                'path': [{'T1': 'P5'}, {'leaf0': 'P1'}, {'spine0': 'P4'},
                        {'leaf1': 'P5'}, {'T1': 'P5'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_egress_leaf1_5',
                'path': [{'T1': 'P6'}, {'leaf0': 'P1'}, {'spine0': 'P5'},
                        {'leaf1': 'P6'}, {'T1': 'P6'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_egress_leaf1_6',
                'path': [{'T1': 'P7'}, {'leaf0': 'P1'}, {'spine1': 'P1'},
                        {'leaf1': 'P7'}, {'T1': 'P7'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            # Stream 7: TGEN  to  leaf2  to  spine1  to  leaf1  to  TGEN
            {
                'name': 'PFC_egress_leaf1_7',
                'path': [{'T1': 'P1'}, {'leaf2': 'P1'}, {'spine1': 'P1'},
                        {'leaf1': 'P8'}, {'T1': 'P8'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_egress_leaf1_8',
                'path': [{'T1': 'P8'}, {'leaf0': 'P1'}, {'spine1': 'P1'},
                        {'leaf1': 'P9'}, {'T1': 'P9'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_egress_leaf1_9',
                'path': [{'T1': 'P9'}, {'leaf0': 'P1'}, {'spine1': 'P1'},
                        {'leaf1': 'P9'}, {'T1': 'P9'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            }
        ]

    def build_ingress_leaf_traffic_items(self, protocol, queue, traffictype):
        q = str(queue)
        return [
            # 8 separate 400G traffic streams from leaf0 to leaf1
            # PortChannel1 uses T1P2 (1/1/49 â†” 1/1/4) - NO traffic through it
            # Traffic uses T1P1, T1P3-T1P9 (8x400G ports: 2/1/9-16 on leaf0, 2/1/17-24 on leaf1)
            {
                'name': 'PFC_l0_to_l1_1',
                'path': [{'T1': 'P1'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P1'}, {'T1': 'P1'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_2',
                'path': [{'T1': 'P3'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P3'}, {'T1': 'P3'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_3',
                'path': [{'T1': 'P4'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P4'}, {'T1': 'P4'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_4',
                'path': [{'T1': 'P5'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P5'}, {'T1': 'P5'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_5',
                'path': [{'T1': 'P6'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P6'}, {'T1': 'P6'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_6',
                'path': [{'T1': 'P7'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P7'}, {'T1': 'P7'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_7',
                'path': [{'T1': 'P8'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P8'}, {'T1': 'P8'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_8',
                'path': [{'T1': 'P9'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P9'}, {'T1': 'P9'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            }
        ]

    def build_spine_traffic_items(self, protocol, queue, traffictype):
        q = str(queue)
        return [
            # 8 total streams converging on spine0  to  leaf1
            # Streams 1-7: Same as ingress leaf's first 7 (leaf0  to  spine0  to  leaf1)
            # Stream 8: leaf2 T1P1 (orphan) vlan2  to  spine0  to  leaf1 P9 vlan2
            {
                'name': 'PFC_l0_to_l1_1',
                'path': [{'T1': 'P1'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P1'}, {'T1': 'P1'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_2',
                'path': [{'T1': 'P3'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P3'}, {'T1': 'P3'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_3',
                'path': [{'T1': 'P4'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P4'}, {'T1': 'P4'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_4',
                'path': [{'T1': 'P5'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P5'}, {'T1': 'P5'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_5',
                'path': [{'T1': 'P6'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P6'}, {'T1': 'P6'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_6',
                'path': [{'T1': 'P7'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P7'}, {'T1': 'P7'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l0_to_l1_7',
                'path': [{'T1': 'P8'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P8'}, {'T1': 'P8'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l2_to_l1_8',
                'path': [{'T1': 'P1'}, {'leaf2': 'P1'}, {'spine0': 'P1'},
                        {'leaf1': 'P9'}, {'T1': 'P9'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            }
        ]

    def run_congestion_test(self, *, tc_id, banner, traffic_items, congestion_point, post_check_callable, breakout_type=None):
        """Single place that performs the shared flow; calls the supplied post-check."""
        st.banner(banner)
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)

        tc_cfg['traffic_items'] = traffic_items
        tc_cfg['congestion_point'] = congestion_point

        if breakout_type:
            st.log("Configuring DPB type {} in the underlay".format(breakout_type))
            try:
                pf.change_underlay_dpb(dpb_type=breakout_type)
                verify_base_setup(retry=15)
            except Exception as err:
                if not "already configured" in str(err):
                    raise err

        # process traffic items to find DUTs and port info
        self.process_traffic_items(tc_cfg)

        st.log("Determining DUT interface speeds for congestion test")
        dut = tc_cfg['dut_list'][0]
        node_intfs = vxlan_obj.get_dut_interfaces(vars)
        intfs_status = vxlan_obj.get_interfaces_status(dut)
        dut_underlay_int = list(node_intfs[dut]['underlay_dict'].values())[0]
        dut_tgen_portid = vxlan_obj.get_peer_port_id(list(node_intfs[dut]['tgen_port_dict'].keys())[0], vars)
        dut_tgen_int = vars[dut_tgen_portid]
        for status in intfs_status:
            if status['interface'] == dut_underlay_int:
                tc_cfg['congestion_bw'] = int(status['speed'][:-1])
            if status['interface'] == dut_tgen_int:
                tc_cfg['tgen_bw'] = int(status['speed'][:-1])

        if not tc_cfg.get('congestion_bw') or not tc_cfg.get('tgen_bw'):
            raise Exception("Could not determine DUT interface speeds for congestion test")

        per_stream_bw = tc_cfg['congestion_bw'] / len(tc_cfg['traffic_items'])
        if per_stream_bw < tc_cfg['tgen_bw']:
            per_stream_bw = per_stream_bw * 1.2 # add 20% margin
        elif per_stream_bw == tc_cfg['tgen_bw']:
            per_stream_bw = per_stream_bw 
        else:
            raise Exception("Tgen bandwidth {}Gbps is less than required per " \
                "stream bandwidth {}Gbps".format(tc_cfg['tgen_bw'], per_stream_bw))
        st.log("Setting per-stream bandwidth to {}Gbps".format(per_stream_bw))
        for traffic_item in tc_cfg['traffic_items']:
            traffic_item['max_bw'] = per_stream_bw

        # same common steps you already repeat in each test:
        self.setup_traffic_path(tc_cfg, breakout_type=breakout_type)
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)

        
        if self.pre_congestion_check(tc_cfg):
            st.log("Pre-congestion check : Pass")
        else:
            st.banner("Pre-congestion check failed!!!!!!")
        

        # trigger congestion
        self.trigger_congestion(tc_cfg)

        # delegate to the right post-check (unchanged logic)
        if post_check_callable(tc_cfg):
            vxlan_obj.report_result(True, tc_id, "PFC/VoQ Congestion check Pass")
        else:
            vxlan_obj.report_result(False, tc_id, "Post-congestion check failed")

    def process_traffic_items(self, tc_cfg):
        global vars, tgen_handles
        st.log("Processing traffic paths find node and port information")
        tc_cfg['dut_list'] = list()

        for traffic_item in tc_cfg['traffic_items']:
            hops = []
            for idx in range(0, len(traffic_item['path']) - 1):
                nhop = {}
                hop = traffic_item['path'][idx]
                next_hop = traffic_item['path'][idx + 1]
                node = next(iter(hop))
                next_node = next(iter(next_hop))
                port_num = hop[node]

                if node not in vars['dut_list'] and node not in vars['tgen_list']:
                    raise Exception("Invalid node {} in traffic path".format(node))
                if next_node not in vars['dut_list'] and next_node not in vars['tgen_list']:
                    raise Exception("Invalid node {} in traffic path".format(next_node))

                in_node_id = vxlan_obj.get_device_id(node, vars)
                eg_node_id = vxlan_obj.get_device_id(next_node, vars)

                if st.get_device_type(node) == 'sonic' and node not in tc_cfg['dut_list']:
                    tc_cfg['dut_list'].append(node)

                nhop['in_node'] = node
                nhop['eg_node'] = next_node

                if 'PortChannel' in port_num:
                    if st.get_device_type(nhop['eg_node']) == 'TGEN':
                        nhop['eg_intf'] = find_tgen_port_name(port_num, nhop['in_node'])
                        nhop['in_intf'] = port_num
                    else:
                        nhop['in_intf'] = find_tgen_port_name(port_num, nhop['eg_node'])
                        nhop['eg_intf'] = port_num

                    if not (nhop['in_intf'] or nhop['eg_intf']):
                        raise Exception("Invalid port id {} in traffic path".format(nhop['in_intf']))
                    nhop['in_port_id'] = nhop['in_intf']
                    nhop['eg_port_id'] = nhop['eg_intf']
                else:
                    nhop['in_port_id'] = in_node_id + eg_node_id + port_num
                    nhop['eg_port_id'] = eg_node_id + in_node_id + port_num

                    if not vars.get(nhop['in_port_id']):
                        raise Exception("Invalid port id {} in traffic path".format(nhop['in_port_id']))
                    if not vars.get(nhop['eg_port_id']):
                        raise Exception("Invalid port id {} in traffic path".format(nhop['eg_port_id']))

                    nhop['in_intf'] = vars[nhop['in_port_id']]
                    nhop['eg_intf'] = vars[nhop['eg_port_id']]

                hops.append(nhop)

            traffic_item['hops'] = hops

            if traffic_item['protocol'] == 'ipv4':
                traffic_item['device_handles'] = tgen_handles['v4_device_handles']
            elif traffic_item['protocol'] == 'ipv6':
                traffic_item['device_handles'] = tgen_handles['v6_device_handles']
            else:
                raise Exception("Invalid protocol {} in traffic item".format(traffic_item['protocol']))

    def setup_traffic_path(self, tc_cfg, breakout_type=None):
        """
            process input variables to create traffic items
            create traffic items on Ixia    
            shutdown non-congestion paths
        """
        st.log('Pre-test Traffic path Setup')

        # Setup traffic endpoints
        idx = 1
        tc_cfg['streams'] = dict()
        for traffic_item in tc_cfg['traffic_items']:
            traffic_endpoints = dict()
            src_info = traffic_item['hops'][0]
            dst_info = traffic_item['hops'][-1]
            
            traffic_endpoints['traffic_item_{}'.format(idx)] = {
                'src_int': src_info['in_port_id'],
                'src_vlan': traffic_item['src_vlan'],
                'dst_int': dst_info['eg_port_id']   ,
                'dst_vlan': traffic_item['dst_vlan'],
            }
        
            # Create Ixia traffic items
            st.log("Creating Traffic stream {}. Enpdoints : {}".format(traffic_item['name'], traffic_endpoints))
    
            queue_val = tc_cfg['traffic_items'][0]['queue']
            if queue_val == '3':
                traffic_pfc_queue_val = 1
            elif queue_val == '4':
                traffic_pfc_queue_val = 2

            if traffic_item['protocol'] == 'ipv4' and queue_val == '3':
                pr_val = 'd'
            if traffic_item['protocol'] == 'ipv4' and queue_val == '4':
                pr_val = '11'
               
            if traffic_item['protocol'] == 'ipv6' and queue_val == '3':
                pr_val = '13'
            if traffic_item['protocol'] == 'ipv6' and queue_val == '4':
                pr_val = '17'
            
            # set rate to 5% of tgen bw initially
            rate_bps = tc_cfg['tgen_bw'] * 1000000000 * (5/100)
            
            # Set frame size to 1500 for slice congestion tests, default 500 otherwise
            if 'slice' in tc_cfg.get('tc_id', ''):
                pkt_size = 1500
            else:
                pkt_size = 500
                
            tc_cfg['streams'][idx] = vxlan_obj.create_traffic_item(
                device_handles = traffic_item['device_handles'],
                endpoints = traffic_endpoints,
                topo_handles = tgen_handles['topo_handles'],
                name_prfx = traffic_item['name'], priority_val=pr_val, pfc_queue_val=traffic_pfc_queue_val,
                transmit_mode = 'continuous', version = traffic_item['protocol'],
                rate_bps=rate_bps, frame_size=pkt_size, bidirectional=int(traffic_item['bidirectional']))[1]
            
            traffic_item['stream_id'] = tc_cfg['streams'][idx]['stream_id']
            
            # Enable UDP destination port randomization for ECMP distribution (slice congestion only)
            if 'slice' in tc_cfg.get('tc_id', ''):
                st.log("Enabling UDP dest port randomization for stream {} (seed={}) for ECMP".format(
                    traffic_item['name'], idx))
                tg = tgen_handles['tg_handle']
                ixNet = vxlan_obj.get_ixnet()
                streamname = traffic_item['stream_id']
                trafficitem = ixNet.getFilteredList('/traffic', 'trafficItem', '-name', streamname)[0]
                confElement = ixNet.getList(trafficitem, 'configElement')[0]
                
                # Check if UDP stack exists, if not add it
                stackList = ixNet.getList(confElement, 'stack')
                udp_stack = None
                for stack in stackList:
                    if ixNet.getAttribute(stack, '-stackTypeId') == 'udp':
                        udp_stack = stack
                        break
                
                # If no UDP stack, we need to add it after IP layer
                if not udp_stack:
                    if traffic_item['protocol'] == 'ipv4':
                        stackIP = ixNet.getFilteredList(confElement, 'stack', '-stackTypeId', 'ipv4')[0]
                    else:
                        stackIP = ixNet.getFilteredList(confElement, 'stack', '-stackTypeId', 'ipv6')[0]
                    
                    # Get UDP protocol template from root and append it after IP
                    all_templates = ixNet.getList(ixNet.getRoot() + '/traffic', 'protocolTemplate')
                    udp_template = None
                    for template in all_templates:
                        if ixNet.getAttribute(template, '-stackTypeId') == 'udp':
                            udp_template = template
                            break
                    
                    if not udp_template:
                        st.error("Could not find UDP protocol template")
                        raise Exception("UDP protocol template not found")
                    
                    ixNet.execute('appendProtocol', stackIP, udp_template)
                    ixNet.commit()
                    st.log("Added UDP protocol stack to traffic item")
                    
                    # Get the newly added UDP stack
                    stackList = ixNet.getList(confElement, 'stack')
                    for stack in stackList:
                        if ixNet.getAttribute(stack, '-stackTypeId') == 'udp':
                            udp_stack = stack
                            break
                    
                    if not udp_stack:
                        st.error("Failed to add UDP stack to traffic item")
                        raise Exception("UDP stack not found after appendProtocol")
                
                st.log("Configuring UDP ports for stream {} (UDP stack: {})".format(traffic_item['name'], udp_stack))
                
                # Configure UDP destination port with increment pattern for ECMP diversity
                udpDstPort = ixNet.getFilteredList(udp_stack, 'field', '-fieldTypeId', 'udp.header.dstPort')[0]
                ixNet.setAttribute(udpDstPort, '-auto', 'false')
                ixNet.commit()
                
                # Calculate start value based on stream index for diversity (each stream gets different range)
                start_port = 1001 + (idx * 10000)
                ixNet.setAttribute(udpDstPort, '-valueType', 'increment')
                ixNet.setAttribute(udpDstPort, '-startValue', str(start_port))
                ixNet.setAttribute(udpDstPort, '-stepValue', '1')
                ixNet.setAttribute(udpDstPort, '-countValue', '10000')
                ixNet.commit()
                
                # Set UDP source port to fixed value
                udpSrcPort = ixNet.getFilteredList(udp_stack, 'field', '-fieldTypeId', 'udp.header.srcPort')[0]
                ixNet.setAttribute(udpSrcPort, '-auto', 'false')
                ixNet.setAttribute(udpSrcPort, '-singleValue', '1000')
                ixNet.commit()
                
                st.log("Configured UDP for stream {}: dst_port=Inc({}, 1, 10000), src_port=1000".format(
                    traffic_item['name'], start_port))
            
            idx += 1
        
        st.log("Shutting down alternate paths (non-slice uplinks) to force traffic through congestion slice")
        dut_interfaces = vxlan_obj.get_dut_interfaces(vars)
        tc_cfg['shut_intf'] = dict()
        
        # Determine multi-homing peer (for EVPN multi-homing scenarios)
        mh_peer_map = {'leaf0': 'leaf1', 'leaf1': 'leaf0', 'leaf2': 'leaf3', 'leaf3': 'leaf2'}
        mh_peer = mh_peer_map.get(tc_cfg['congestion_point'])
        
        for node in tc_cfg['dut_list']:
            # Start with all underlay interfaces
            all_underlay = list(dut_interfaces[node]['underlay_dict'].values())
            
            # For slice congestion: shut down alternate paths on the congestion_point AND its multi-homing peer
            if node == tc_cfg['congestion_point'] and 'congestion_slice_ports' in tc_cfg:
                # Check if this is egress leaf TGEN-side slice congestion (remote_node = None)
                remote_node = tc_cfg.get('congestion_remote_node')
                
                if remote_node is None:
                    # Egress leaf TGEN-side slice congestion: Keep ALL underlay UP, congestion is on TGEN-facing slice
                    tc_cfg['shut_intf'][node] = []
                    st.log("Node {}: EGRESS LEAF with TGEN-side slice congestion (slice ports: {}), keeping ALL underlay UP".format(
                        node, tc_cfg['congestion_slice_ports']))
                else:
                    # Ingress leaf or spine underlay slice congestion: Shut down non-slice underlay ports
                    tc_cfg['shut_intf'][node] = [intf for intf in all_underlay if intf not in tc_cfg['congestion_slice_ports']]
                    st.log("Node {}: Keeping slice ports UP: {}, shutting down alternate paths: {}".format(
                        node, tc_cfg['congestion_slice_ports'], tc_cfg['shut_intf'][node]))
            elif node == mh_peer and mh_peer in tc_cfg['dut_list']:
                # For slice congestion: Keep ALL uplinks UP on multi-homing peer for egress traffic distribution
                # This allows full ECMP from target_spine  to  mh_peer
                if 'congestion_slice_ports' in tc_cfg and 'congestion_remote_node' in tc_cfg:
                    remote_node = tc_cfg['congestion_remote_node']  # Can be spine (ingress leaf test) or leaf (spine test)
                    
                    if remote_node is None:
                        # Egress leaf TGEN-side slice congestion: Keep ALL underlay UP, congestion is on egress TGEN ports
                        tc_cfg['shut_intf'][node] = []
                        st.log("Node {}: Multi-homing peer with EGRESS-side slice congestion, keeping ALL underlay UP (congestion on TGEN ports)".format(node))
                    else:
                        # Underlay slice congestion: Find interfaces connected to remote_node (keep ALL of these UP)
                        # For ingress leaf: remote_node = spine (e.g., spine0)
                        # For spine: remote_node = target leaf (e.g., leaf1)
                        remote_node_intfs = []
                        
                        # Get interfaces on mh_peer that connect to remote_node
                        try:
                            # Use underlay_dict to find connections to remote_node
                            node_id = vars.dut_ids[node]
                            remote_id = vars.dut_ids[remote_node]
                            prefix = node_id + remote_id  # e.g., "D6D1" for leaf1 to spine0 or "D5D6" for leaf0 to leaf1
                            
                            leaf_underlay_dict = dut_interfaces[node]['underlay_dict']
                            for port_id, physical_port in leaf_underlay_dict.items():
                                if port_id.startswith(prefix) and physical_port:
                                    remote_node_intfs.append(physical_port)
                            
                            st.log("Found {} interfaces from {} to {}: {}".format(
                                len(remote_node_intfs), node, remote_node, remote_node_intfs))
                        except Exception as e:
                            st.log("Could not determine remote_node interfaces on {}, error: {}".format(node, str(e)))
                        
                        # For underlay slice: shut down only NON-remote_node uplinks (keep all remote_node links UP)
                        tc_cfg['shut_intf'][node] = [intf for intf in all_underlay if intf not in remote_node_intfs]
                        st.log("Node {}: Multi-homing peer, keeping ALL {} links UP: {}, shutting down alternate paths: {}".format(
                            node, remote_node, remote_node_intfs, tc_cfg['shut_intf'][node]))
                else:
                    # For non-slice congestion tests: shut down ALL uplinks on multi-homing peer
                    tc_cfg['shut_intf'][node] = all_underlay
                    st.log("Node {}: Multi-homing peer of {}, shutting down ALL uplinks: {}".format(
                        node, tc_cfg['congestion_point'], tc_cfg['shut_intf'][node]))
            else:
                # For non-congestion nodes: don't shut down anything
                tc_cfg['shut_intf'][node] = []
                st.log("Node {}: Not a congestion point or MH peer, leaving all interfaces up".format(node))
            
            if tc_cfg['shut_intf'][node]:
                intf_obj.interface_shutdown(dut=node, interfaces=tc_cfg['shut_intf'][node])
        
    def pre_congestion_check(self, tc_cfg):
        st.log("Pre-Congestion Check")
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)

        st.log("Checking traffic before triggering congestion")
        

        result = vxlan_obj.check_traffic(tc_cfg['streams'], regenerate_traffic_items=True, 
                                stop_proto_wait=test_cfg['global']['traffic_stop_protocol_sleep'],
                                start_proto_wait=test_cfg['global']['traffic_start_protocol_sleep'])


        if not result:
            st.error("Traffic check failed in pre-congestion check")
            return result
        # Queue counters should be not be 0 pre-congestion 
        ret = True
        
        # For egress leaf TGEN-side slice congestion: Skip underlay checks (ECMP makes paths unpredictable)
        # Only check TGEN-facing interfaces where congestion actually occurs
        is_egress_tgen_congestion = (tc_cfg.get('congestion_remote_node') is None and 
                                      'congestion_slice_ports' in tc_cfg)
        
        for traffic_item in tc_cfg['traffic_items']:
            st.log("Checking traffic path of traffic item {}".format(traffic_item['name']))
            for hop in traffic_item['hops'][1:]:
                hop_node = hop['in_node']
                hop_intf = hop['in_intf']
                
                # Skip underlay interface checks for egress leaf TGEN-side congestion
                # (Underlay paths are ECMP-distributed and don't match hardcoded paths)
                if is_egress_tgen_congestion:
                    # Check if this hop is an underlay interface (DUT-to-DUT, not DUT-to-TGEN)
                    next_node = hop['eg_node']
                    is_underlay_hop = (next_node in vars.get('dut_list', []))
                    
                    if is_underlay_hop:
                        st.log("Skipping underlay interface check for {} {} (ECMP path)".format(hop_node, hop_intf))
                        continue
                
                queue_counters = vxlan_obj.get_queue_counters(hop_node, hop_intf)
                queue_name = "UC{}".format(int(traffic_item['queue']))
                if self.check_queue_increased(queue_counters, queue_name):
                    st.log("Pre-congestion queue counters increased on {} {}: Pass".format(hop_node, hop_intf))
                else:
                    st.error("Pre-congestion queue counters did not increase on {} {}: Fail".format(hop_node, hop_intf))
                    ret = False

        # PFC counters should be 0 pre-congestion 
        # Check ALL slice interfaces (spine-facing) for TX PFC = 0
        if 'congestion_slice_ports' in tc_cfg:
            st.log("Checking PFC counters on ALL slice interfaces (should be zero pre-congestion)")
            for slice_intf in tc_cfg['congestion_slice_ports']:
                pfc = vxlan_obj.get_pfc_count(tc_cfg['congestion_point'], slice_intf)
                if self.check_pfc_counters_increased(pfc, slice_intf, direction="tx", queue=tc_cfg['traffic_items'][0]['queue']):
                    st.error("Pre-congestion PFC counters incremented on {} {} (slice interface): Fail".format(
                        tc_cfg['congestion_point'], slice_intf))
                    ret = False
                else:
                    st.log("Pre-congestion PFC counters NOT incremented on {} {} (slice interface): Pass".format(
                        tc_cfg['congestion_point'], slice_intf))
        
        # Check ALL TGEN-facing interfaces for RX PFC = 0 (no backpressure to TGEN)
        st.log("Checking PFC counters on ALL TGEN-facing interfaces (should be zero pre-congestion)")
        tgen_intfs = set()
        for traffic_item in tc_cfg['traffic_items']:
            # First hop is TGEN, second hop is the ingress DUT interface
            if len(traffic_item['hops']) > 1:
                ingress_hop = traffic_item['hops'][1]
                tgen_intfs.add((ingress_hop['in_node'], ingress_hop['in_intf']))
        
        for node, intf in tgen_intfs:
            # Skip TGEN nodes (they don't have PFC counters)
            if node.startswith('T'):
                st.log("Skipping PFC check on TGEN node {}".format(node))
                continue
            
            pfc = vxlan_obj.get_pfc_count(node, intf)
            # Check RX PFC (backpressure received from downstream)
            if self.check_pfc_counters_increased(pfc, intf, direction="rx", queue=tc_cfg['traffic_items'][0]['queue']):
                st.error("Pre-congestion PFC RX counters incremented on {} {} (TGEN-facing): Fail".format(node, intf))
                ret = False
            else:
                st.log("Pre-congestion PFC RX counters NOT incremented on {} {} (TGEN-facing): Pass".format(node, intf))

        return ret
       
    def trigger_congestion(self, tc_cfg):
        st.log("Trigger Congestion")
        st.log('Clearing counters on leaf0, leaf1, leaf2')
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)
        st.banner("Increasing traffic to trigger congestion")
        
        tg = tgen_handles['tg_handle'] 
        streams = tc_cfg['traffic_items']
        
        # Slice congestion tests use 99% rate for all streams
        # Regular leaf congestion tests use absolute bandwidth
        is_slice_congestion = 'congestion_slice_ports' in tc_cfg
        
        for idx, stream in enumerate(streams, start=1):
            stream_id = stream['stream_id']
            
            if is_slice_congestion:
                # All streams: 99% line rate to trigger congestion
                rate_percent = 99
                st.log("Setting stream ID {} ({}) rate to 99%".format(stream_id, stream['name']))
                
                tg.tg_traffic_config(
                    mode="modify",
                    stream_id=stream_id,
                    rate_percent=rate_percent
                )
            else:
                # Use absolute bandwidth for regular leaf congestion
                rate_bps = stream['max_bw'] * 1000000000 
                st.log("Setting stream ID {} rate to {} bps".format(stream_id, rate_bps))
                tg.tg_traffic_config(
                    mode="modify",
                    stream_id=stream_id,
                    rate_bps=rate_bps
                )
        
        # Apply traffic changes and regenerate packets (critical for slice congestion after topology changes)
        st.log("Applying traffic configuration changes and regenerating traffic")
        tg.tg_test_control(action='apply_on_the_fly_changes')

    def trigger_congestion_egress(self, tc_cfg):
        """
        Trigger congestion for EGRESS LEAF slice congestion test ONLY.
        Uses 95% rate for first 8 streams, 6% for 9th stream (9 streams converging at leaf1 egress).
        """
        st.log("Trigger Congestion (Egress Leaf - 95% for streams 1-8, 6% for stream 9)")
        st.log('Clearing counters on all DUTs')
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)
        st.log("Increasing traffic to trigger congestion (95% for streams 1-8, 6% for stream 9)")
        
        tg = tgen_handles['tg_handle'] 
        streams = tc_cfg['traffic_items']
        
        # Egress leaf congestion: Use 95% rate for first 8 streams, 6% for 9th stream
        is_slice_congestion = 'congestion_slice_ports' in tc_cfg
        
        for idx, stream in enumerate(streams, start=1):
            stream_id = stream['stream_id']
            
            if is_slice_congestion:
                # First 8 streams: 95% line rate, 9th stream: 6% line rate
                if idx < 8:
                    rate_percent = 100
                    st.log("Setting stream ID {} ({}) rate to 100% (egress leaf case, stream {})".format(
                        stream_id, stream['name'], idx))
                elif idx == 8:
                    rate_percent = 99.95
                    st.log("Setting stream ID {} ({}) rate to 99.95% (egress leaf case, stream {})".format(
                        stream_id, stream['name'], idx))
                else:
                    rate_percent = 1
                    st.log("Setting stream ID {} ({}) rate to 1% (egress leaf case, stream {})".format(
                        stream_id, stream['name'], idx))
                
                tg.tg_traffic_config(
                    mode="modify",
                    stream_id=stream_id,
                    rate_percent=rate_percent
                )
            else:
                # Use absolute bandwidth for regular leaf congestion
                rate_bps = stream['max_bw'] * 1000000000 
                st.log("Setting stream ID {} rate to {} bps".format(stream_id, rate_bps))
                tg.tg_traffic_config(
                    mode="modify",
                    stream_id=stream_id,
                    rate_bps=rate_bps
                )
        
        # Apply traffic changes and regenerate packets
        st.log("Applying traffic configuration changes and regenerating traffic")
        tg.tg_test_control(action='apply_on_the_fly_changes')

    def trigger_congestion_spine(self, tc_cfg):
        """
        Trigger congestion for SPINE slice congestion test ONLY.
        Uses 99% rate for all streams (8 from leaf0, 1 from leaf2, 1 from leaf3).
        """
        st.log("Trigger Congestion (Spine - 99% rate)")
        st.log('Clearing counters on all DUTs')
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)
        st.log("Increasing traffic to trigger congestion (99% for spine)")
        
        tg = tgen_handles['tg_handle'] 
        streams = tc_cfg['traffic_items']
        
        # Spine congestion: Use 99% rate for all streams
        is_slice_congestion = 'congestion_slice_ports' in tc_cfg
        
        for idx, stream in enumerate(streams, start=1):
            stream_id = stream['stream_id']
            
            if is_slice_congestion:
                # All streams: 99% line rate for spine
                rate_percent = 99
                st.log("Setting stream ID {} ({}) rate to 99% (spine case)".format(stream_id, stream['name']))
                
                tg.tg_traffic_config(
                    mode="modify",
                    stream_id=stream_id,
                    rate_percent=rate_percent
                )
            else:
                # Use absolute bandwidth for regular leaf congestion
                rate_bps = stream['max_bw'] * 1000000000 
                st.log("Setting stream ID {} rate to {} bps".format(stream_id, rate_bps))
                tg.tg_traffic_config(
                    mode="modify",
                    stream_id=stream_id,
                    rate_bps=rate_bps
                )
        
        # Apply traffic changes and regenerate packets
        st.log("Applying traffic configuration changes and regenerating traffic")
        tg.tg_test_control(action='apply_on_the_fly_changes')

    def post_congestion_check_spine(self, tc_cfg, ecn_mode='normal'):
        """
        Post-congestion check specifically for SPINE congestion.
        Only checks hops AFTER the spine (spine to leaf and beyond).
        Does NOT check leaf to spine hops (before congestion point).
        
        Traffic path: T1  to  leaf0  to  spine0 (CONGESTION)  to  leaf1  to  T1
        Checks: spine0 to leaf1 and leaf1 to T1 (skips T1 to leaf0 to spine0)
        """
        ret_val = True
        
        st.log("Post-Congestion Check for SPINE (testcase={}, ecn_mode={})".format(test_cfg['tc_id'], ecn_mode))

        # Disable PFC or ECN based on mode
        if ecn_mode == 'ecn_only':
            queue_val = tc_cfg['traffic_items'][0]['queue']
            for ti in tc_cfg['traffic_items']:
                # Determine which hop to use for disabling PFC (egress from congestion point)
                for hop in ti['hops']:
                    if hop['in_node'] == tc_cfg['congestion_point']:
                        congestion_node = hop['in_node']
                        iface = hop['in_intf']
                        st.log("Disabling PFC on congestion node {} for EGRESS interface {}".format(congestion_node, iface))
                        if "PortChannel" in iface:
                            members = pc_obj.get_portchannel_members(hop['in_node'], iface)
                            for i in members:
                                st.log("Turning PFC off on {} {}".format(congestion_node, i))
                                st.config(congestion_node, "config interface pfc priority {} {} off".format(i, queue_val))
                        else:
                            st.config(congestion_node, "config interface pfc priority {} {} off".format(iface, queue_val))
                        break
        elif ecn_mode == 'pfc_only':
            st.log("Configuring ecnconfig to disable ECN marking on congestion point {}".format(tc_cfg['congestion_point']))
            st.config(tc_cfg['congestion_point'], "sudo ecnconfig -p AZURE_LOSSLESS -gdrop 0")

        # Start traffic
        st.log("Starting over congestion traffic")
        vxlan_obj.check_traffic(tc_cfg['streams'], regenerate_traffic_items=True, action='start', stop_start_protocols=True)
        
        # Verify PFC counters on INGRESS interfaces to spine0 (backpressure from source leafs)
        # For spine congestion: Check interfaces where traffic ENTERS spine0 (from leaf0, leaf2, etc.)
        pfc_success_count = 0
        pfc_total_checked = 0
        st.log("Checking if PFC counters on INGRESS interfaces to spine0 have incremented (backpressure from source leafs)")
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)
        
        # Get ingress interfaces to spine0 that are ACTUALLY used by traffic items
        # Only check interfaces where traffic is actually flowing (from traffic items' hops)
        spine0_ingress_intfs = []
        checked_interfaces = set()  # To avoid duplicates
        all_traffic_item_intfs = []  # For debugging - show all traffic items and their interfaces
        
        for traffic_item in tc_cfg['traffic_items']:
            # Find the hop where traffic enters spine0 (eg_node == spine0)
            for hop in traffic_item['hops']:
                if hop['eg_node'] == tc_cfg['congestion_point']:
                    # This is the ingress hop to spine0
                    # hop['eg_intf'] is the interface on spine0 (where traffic enters)
                    spine0_intf = hop['eg_intf']
                    all_traffic_item_intfs.append((traffic_item['name'], hop['in_node'], spine0_intf))
                    
                    # Only add if not already checked (avoid duplicates)
                    if spine0_intf not in checked_interfaces:
                        checked_interfaces.add(spine0_intf)
                        spine0_ingress_intfs.append(spine0_intf)
                        st.log("Found ingress interface: {} (from {} to spine0, traffic item: {})".format(
                            spine0_intf, hop['in_node'], traffic_item['name']))
                    break
        
        # Log all traffic items and their interfaces for debugging
        st.log("All {} traffic items and their ingress interfaces to spine0:".format(len(all_traffic_item_intfs)))
        for ti_name, source_leaf, intf in all_traffic_item_intfs:
            st.log("  {}: {} -> {} (spine0)".format(ti_name, source_leaf, intf))
        
        st.log("Found {} unique ingress interfaces to spine0 used by traffic: {}".format(
            len(spine0_ingress_intfs), spine0_ingress_intfs))
        
        if not spine0_ingress_intfs:
            st.error("No ingress interfaces to spine0 found in traffic items - cannot check PFC counters")
            ret_val = False
        
        try:
            # Get dut_interfaces for spine0 to leaf1 interfaces (needed for queue/VOQ checks)
            dut_interfaces = vxlan_obj.get_dut_interfaces(vars)
            spine0_id = vars.dut_ids['spine0']
            spine0_underlay_dict = dut_interfaces['spine0']['underlay_dict']
            
            # Also get spine0 to leaf1 interfaces for queue and VOQ checks (egress interfaces)
            leaf1_id = vars.dut_ids['leaf1']
            prefix = spine0_id + leaf1_id  # e.g., "D1D6" for spine0 to leaf1
            spine0_to_leaf1_intfs = []
            for port_id, physical_port in spine0_underlay_dict.items():
                if port_id.startswith(prefix) and physical_port:
                    spine0_to_leaf1_intfs.append(physical_port)
            st.log("Found {} spine0 to leaf1 egress interfaces for queue/VOQ checks: {}".format(
                len(spine0_to_leaf1_intfs), spine0_to_leaf1_intfs))
        except Exception as e:
            st.error("Could not determine spine0 to leaf1 egress interfaces, error: {}".format(str(e)))
            spine0_to_leaf1_intfs = []  # Initialize to avoid NameError
        
        # Check PFC counters on ALL ingress interfaces to spine0 (TX direction - sending backpressure)
        # For spine congestion: spine0 sends PFC backpressure OUT to source leafs (TX direction)
        should_increment = (ecn_mode == 'normal' or ecn_mode == 'pfc_only')
        queue = tc_cfg['traffic_items'][0]['queue']  # All traffic items use same queue
        
        for intf in spine0_ingress_intfs:
            pfc = vxlan_obj.get_pfc_count('spine0', intf)
            pfc_total_checked += 1
            
            if should_increment:
                # Check TX direction - spine0 sending PFC frames to source leafs (backpressure)
                if self.check_pfc_counters_increased(pfc, intf, direction="tx", queue=queue):
                    st.log("PFC counters incremented on spine0 {} (ingress/TX - backpressure): Pass".format(intf))
                    pfc_success_count += 1
                else:
                    st.log("PFC counters NOT incremented on spine0 {} (ingress/TX): (not required for all)".format(intf))
            else:
                if self.check_pfc_counters_increased(pfc, intf, direction="tx", queue=queue):
                    st.error("PFC counters expected to NOT increment, incremented on spine0 {} (ingress/TX): Fail".format(intf))
                    ret_val = False
                else:
                    st.log("PFC counters stayed 0 on spine0 {} (ingress/TX): Pass".format(intf))
        
        # Check if at least 1 ingress interface showed PFC counter increases
        if ecn_mode == 'normal' or ecn_mode == 'pfc_only':
            st.log("PFC counter check summary: {}/{} spine0 INGRESS interfaces showed PFC increases (backpressure)".format(pfc_success_count, pfc_total_checked))
            if pfc_success_count < 1:
                st.error("SPINE CONGESTION: Need at least 1 spine0 INGRESS interface with PFC increases (backpressure), got {}: FAIL".format(pfc_success_count))
                ret_val = False
            else:
                st.log("SPINE CONGESTION: At least {} spine0 INGRESS interface(s) showed PFC increases (backpressure): PASS".format(pfc_success_count))

        # Queue counter checking - ALL spine0 to leaf1 interfaces
        if ecn_mode != 'ecn_only':
            st.log("Checking Queue counters on ALL spine0 to leaf1 egress interfaces")
            queue_name = "UC{}".format(int(tc_cfg['traffic_items'][0]['queue']))
            
            for intf in spine0_to_leaf1_intfs:
                queue_counters = vxlan_obj.get_queue_counters('spine0', intf)
                if self.check_queue_increased(queue_counters, queue_name):
                    st.log("Queue counters increased on spine0 {} (egress): Pass".format(intf))
                else:
                    st.error("Queue counters NOT increased on spine0 {} (egress): Fail".format(intf))
                    ret_val = False

        # VOQ counter checking - ALL spine0 to leaf1 interfaces
        st.log("Checking if VoQ counters on ALL spine0 to leaf1 EGRESS interfaces have incremented")
        queue = tc_cfg['traffic_items'][0]['queue']
        
        for intf in spine0_to_leaf1_intfs:
            voq = vxlan_obj.get_voq_queue_counters('spine0', intf, queue)
            st.log("spine0 {} VOQ counters -> {}".format(intf, voq))
            
            if self.check_voq_counters_nonzero(voq, 'spine0', intf):
                st.log("VoQ counters incremented on spine0 {} (egress): Pass".format(intf))
            else:
                st.error("VoQ counters not incremented on spine0 {} (egress): Fail".format(intf))
                ret_val = False

        # NPU rate check - check both Rx (ingress) and Tx (egress) on spine0
        st.log("Checking NPU rates on spine0")
        
        # Get both Rx and Tx rates from spine0
        st.log("Getting Rx and Tx rates from congestion node: {}".format(tc_cfg['congestion_point']))
        npu_rate_check = vxlan_obj.get_npu_rate_check(tc_cfg['congestion_point'])
        total_rx = float([e.get('total_rx_g') or e.get('TOTAL_RX_G') for e in npu_rate_check if (e.get('total_rx_g') or e.get('TOTAL_RX_G'))][0])
        tx_rate = float([e.get('total_tx_g') or e.get('TOTAL_TX_G') for e in npu_rate_check if (e.get('total_tx_g') or e.get('TOTAL_TX_G'))][0])
        
        expected_bw = float(tc_cfg.get('congestion_bw'))
        tol = expected_bw * 0.02  # 2% tolerance
        st.log('Spine0 ({}) Total Rx : {}, Expected Bandwidth: {}, tolerance: {} (2%)'.format(tc_cfg['congestion_point'], total_rx, expected_bw, tol))
        st.log('Spine0 ({}) Tx : {}, Expected Bandwidth: {}, tolerance: {} (2%)'.format(tc_cfg['congestion_point'], tx_rate, expected_bw, tol))
        
        # Check: Tx should be within 2% of expected_bw, Rx should be LESS than expected_bw
        tx_within_tolerance = abs(tx_rate - expected_bw) <= tol
        rx_is_throttled = total_rx < expected_bw
        
        if tx_within_tolerance and rx_is_throttled:
            st.log("NPU rate check PASS: Tx ({:.2f} Gbps) is within 2% of expected ({:.2f} Gbps), and Rx ({:.2f} Gbps) is throttled (< {:.2f} Gbps)".format(
                tx_rate, expected_bw, total_rx, expected_bw))
        else:
            st.error("NPU rate check FAIL:")
            if not tx_within_tolerance:
                st.error("  - Tx rate ({:.2f} Gbps) is NOT within 2% of expected ({:.2f} Gbps). Difference: {:.2f} Gbps".format(
                    tx_rate, expected_bw, abs(tx_rate - expected_bw)))
            if not rx_is_throttled:
                st.error("  - Rx rate ({:.2f} Gbps) is NOT throttled (should be < {:.2f} Gbps)".format(
                    total_rx, expected_bw))
            ret_val = False
        
        # VOQ counters ECN marking - check all 8 egress ports from spine0
        st.log("Checking VOQ ECN marking - at least 1 out of 8 egress ports should have ECN counters increasing")
        
        should_increase_ecn = True
        ecn_ports_increasing = 0
        
        # Get queue from first traffic item
        queue = tc_cfg['traffic_items'][0]['queue']
        
        # Check all slice egress ports (8 ports from spine0 to leaf1)
        slice_ports = tc_cfg.get('congestion_slice_ports', [])
        if not slice_ports:
            # Fallback to spine0_to_leaf1_intfs if congestion_slice_ports not available
            if 'spine0_to_leaf1_intfs' in locals() and spine0_to_leaf1_intfs:
                slice_ports = spine0_to_leaf1_intfs
                st.log("Using spine0_to_leaf1_intfs as fallback: {}".format(slice_ports))
        
        if not slice_ports:
            st.error("No congestion_slice_ports or spine0 to leaf1 interfaces found in tc_cfg")
            ret_val = False
        else:
            # Step 1: Remove duplicates using set()
            unique_ports = list(set(slice_ports))
            st.log("After deduplication: {} unique ports: {}".format(len(unique_ports), unique_ports))
            
            # Step 2: Get slice_id and all ports in that slice using first port
            if unique_ports:
                first_port = unique_ports[0]
                try:
                    slice_id, all_slice_ports = self.get_slice_for_port(tc_cfg['congestion_point'], first_port)
                    st.log("Port {} belongs to slice {} with {} ports: {}".format(
                        first_port, slice_id, len(all_slice_ports), all_slice_ports))
                    # Step 3: Replace slice_ports with all ports in the slice
                    slice_ports = all_slice_ports
                    st.log("Updated slice_ports to all {} ports in slice {}: {}".format(
                        len(slice_ports), slice_id, slice_ports))
                except Exception as e:
                    st.error("Failed to get slice for port {}: {}".format(first_port, str(e)))
                    st.log("Using deduplicated ports as fallback: {}".format(unique_ports))
                    slice_ports = unique_ports
            
            st.log("Checking ECN counters on {} slice egress ports: {}".format(
                len(slice_ports), slice_ports))
            
            for port in slice_ports:
                st.log("Checking ECN counters on {} {} (slice egress port)".format(
                    tc_cfg['congestion_point'], port))
                
                if self.check_ecn_counters_increasing(tc_cfg['congestion_point'], port, 
                                                      queue, 
                                                      should_increase=should_increase_ecn):
                    ecn_ports_increasing += 1
                    st.log("ECN counters increasing on {} {}: YES".format(tc_cfg['congestion_point'], port))
                else:
                    st.log("ECN counters increasing on {} {}: NO".format(tc_cfg['congestion_point'], port))
        
        # Check if at least 1 port has ECN counters increasing
        if 'unique_slice_ports' in locals():
            total_ports_checked = len(unique_slice_ports)
        else:
            total_ports_checked = len(slice_ports) if slice_ports else 0
        
        st.log("ECN check summary: {}/{} ports have ECN counters increasing".format(
            ecn_ports_increasing, total_ports_checked))
        
        if ecn_ports_increasing >= 1:
            st.log("ECN marking check PASS: At least 1 port ({}/{}) has ECN counters increasing".format(
                ecn_ports_increasing, total_ports_checked))
        else:
            st.error("ECN marking check FAIL: None of the {} ports have ECN counters increasing".format(
                total_ports_checked))
            ret_val = False
        
        vxlan_obj.check_traffic(tc_cfg['streams'], regenerate_traffic_items=False, action='stop')
        return ret_val

    def post_congestion_check_egress(self, tc_cfg, ecn_mode='normal'):
        """
        Post-congestion check specifically for EGRESS LEAF slice congestion.
        Only checks PFC counters on the congestion point (last node in path).
        
        Parameters:
        -----------
        tc_cfg : dict
            Test configuration
        ecn_mode : str
            'normal' - check both PFC and ECN with normal logic
            'ecn_only' - disable PFC, check only ECN
            'pfc_only' - disable ECN marking, check only PFC
        """
        ret_val = True
        st.log("Post-Congestion Check for EGRESS LEAF (testcase={}, ecn_mode={})".format(test_cfg['tc_id'], ecn_mode))

        # Disable PFC or ECN based on mode
        if ecn_mode == 'ecn_only':
            queue_val = tc_cfg['traffic_items'][0]['queue']
            for ti in tc_cfg['traffic_items']:
                # Determine which hop to use for disabling PFC
                for hop in ti['hops']:
                    if hop['eg_node'] == tc_cfg['congestion_point']:
                        congestion_node = hop['eg_node']
                        iface = hop['eg_intf']
                        st.log("Disabling PFC on congestion node {} for interface {}".format(congestion_node, iface))
                        if "PortChannel" in iface:
                            members = pc_obj.get_portchannel_members(hop['eg_node'], iface)
                            for i in members:
                                st.log("Turning PFC off on {} {}".format(congestion_node, i))
                                st.config(congestion_node, "config interface pfc priority {} {} off".format(i, queue_val))
                        else:
                            st.config(congestion_node, "config interface pfc priority {} {} off".format(iface, queue_val))
                        break
        elif ecn_mode == 'pfc_only':
            st.log("Configuring ecnconfig to disable ECN marking on congestion point {}".format(tc_cfg['congestion_point']))
            st.config(tc_cfg['congestion_point'], "sudo ecnconfig -p AZURE_LOSSLESS -gdrop 0")

        # Start traffic
        st.log("Starting over congestion traffic")
        vxlan_obj.check_traffic(tc_cfg['streams'], regenerate_traffic_items=True, action='start', stop_start_protocols=True)
        
        # Verify PFC counters increment/behavior - ONLY on ingress ports (where traffic enters from spines)
        # For egress leaf case: check PFC on ingress side (spine  to  leaf1), not egress side (leaf1  to  TGEN)
        # Similar to spine case: collect all ingress interfaces first, then check them all
        congestion_point = tc_cfg['congestion_point']
        st.log("Checking if PFC counters on {} INGRESS interfaces (where traffic enters from spines) have incremented".format(congestion_point))
        
        # Get ingress interfaces to leaf1 that are ACTUALLY used by traffic items
        # Only check interfaces where traffic is actually flowing (from traffic items' hops)
        leaf1_ingress_intfs = []
        checked_interfaces = set()  # To avoid duplicates
        all_traffic_item_intfs = []  # For debugging - show all traffic items and their interfaces
        
        for traffic_item in tc_cfg['traffic_items']:
            # Find the hop where traffic enters leaf1 (eg_node == leaf1)
            for hop in traffic_item['hops']:
                # Skip TGEN nodes (they don't have PFC counters)
                if hop['eg_node'].startswith('T') or hop['in_node'].startswith('T'):
                    continue
                
                # Find hop where traffic enters congestion point (eg_node == congestion_point means traffic enters leaf1)
                if hop['eg_node'] != congestion_point:
                    continue
                
                # This is the ingress interface on leaf1 where traffic comes in from spine
                # hop['eg_intf'] is the interface on leaf1 (eg_node) where traffic enters
                leaf1_intf = hop['eg_intf']
                all_traffic_item_intfs.append((traffic_item['name'], hop['in_node'], leaf1_intf))
                
                # Only add if not already checked (avoid duplicates)
                if leaf1_intf not in checked_interfaces:
                    checked_interfaces.add(leaf1_intf)
                    leaf1_ingress_intfs.append(leaf1_intf)
                    st.log("Found ingress interface: {} (from {} to {}, traffic item: {})".format(
                        leaf1_intf, hop['in_node'], congestion_point, traffic_item['name']))
                break
        
        # Log all traffic items and their interfaces for debugging
        st.log("All {} traffic items and their ingress interfaces to {}:".format(len(all_traffic_item_intfs), congestion_point))
        for ti_name, source_node, intf in all_traffic_item_intfs:
            st.log("  {}: {} -> {} ({})".format(ti_name, source_node, intf, congestion_point))
        
        st.log("Found {} unique ingress interfaces to {} used by traffic: {}".format(
            len(leaf1_ingress_intfs), congestion_point, leaf1_ingress_intfs))
        
        if not leaf1_ingress_intfs:
            st.error("No ingress interfaces to {} found in traffic items - cannot check PFC counters".format(congestion_point))
            ret_val = False
        else:
            # Check PFC counters on ALL ingress interfaces to leaf1 (TX direction - sending backpressure)
            # For egress leaf congestion: leaf1 sends PFC backpressure OUT to spines (TX direction)
            should_increment = (ecn_mode == 'normal' or ecn_mode == 'pfc_only')
            queue = tc_cfg['traffic_items'][0]['queue']  # All traffic items use same queue
            pfc_success_count = 0
            pfc_total_checked = 0
            
            for intf in leaf1_ingress_intfs:
                # Expand PortChannel if needed
                if "PortChannel" in intf:
                    physical_intfs = pc_obj.get_portchannel_members(congestion_point, intf)
                else:
                    physical_intfs = [intf]
                
                for physical_intf in physical_intfs:
                    pfc = vxlan_obj.get_pfc_count(congestion_point, physical_intf)
                    pfc_total_checked += 1
                    
                    if should_increment:
                        # Check TX direction - leaf1 sending PFC frames to spines (backpressure)
                        if self.check_pfc_counters_increased(pfc, physical_intf, direction="tx", queue=queue):
                            st.log("PFC counters incremented on {} {} (ingress/TX - backpressure): Pass".format(congestion_point, physical_intf))
                            pfc_success_count += 1
                        else:
                            st.log("PFC counters NOT incremented on {} {} (ingress/TX): (not required for all)".format(congestion_point, physical_intf))
                    else:
                        # ecn_only mode - PFC should NOT increase
                        if self.check_pfc_counters_increased(pfc, physical_intf, direction="tx", queue=queue):
                            st.error("PFC counters expected to NOT increment, incremented on {} {} (ingress/TX): Fail".format(congestion_point, physical_intf))
                            ret_val = False
                        else:
                            st.log("PFC counters stayed 0 on {} {} (ingress/TX): Pass".format(congestion_point, physical_intf))
            
            # Check if at least 1 ingress interface showed PFC counter increases
            if ecn_mode == 'normal' or ecn_mode == 'pfc_only':
                st.log("PFC counter check summary: {}/{} {} INGRESS interfaces showed PFC increases (backpressure)".format(
                    pfc_success_count, pfc_total_checked, congestion_point))
                if pfc_success_count < 1:
                    st.error("EGRESS LEAF CONGESTION: Need at least 1 {} INGRESS interface with PFC increases (backpressure), got {}: FAIL".format(
                        congestion_point, pfc_success_count))
                    ret_val = False
                else:
                    st.log("EGRESS LEAF CONGESTION: At least {} {} INGRESS interface(s) showed PFC increases (backpressure): PASS".format(
                        pfc_success_count, congestion_point))

        # Queue counter checking (only for normal and pfc_only modes) - use slice ports only
        if ecn_mode != 'ecn_only':
            # Get slice ports (8 egress ports on leaf1 towards IXIA)
            slice_ports = tc_cfg.get('congestion_slice_ports', [])
            if not slice_ports:
                st.error("No congestion_slice_ports found in tc_cfg for queue counter check")
                ret_val = False
            else:
                st.log("Checking Queue counters on {} slice egress ports (congestion point: {}): {}".format(
                    len(slice_ports), congestion_point, slice_ports))
                
                # Get queue from first traffic item (all use same queue)
                queue_name = "UC{}".format(int(tc_cfg['traffic_items'][0]['queue']))
                
                for physical_intf in slice_ports:
                    if not physical_intf:
                        continue
                    queue_counters = vxlan_obj.get_queue_counters(congestion_point, physical_intf)
                    if self.check_queue_increased(queue_counters, queue_name):
                        st.log("Post-congestion queue counters increased on {} {}: Pass".format(congestion_point, physical_intf))
                    else:
                        st.error("Post-congestion queue counters NOT increased on {} {}: Fail".format(congestion_point, physical_intf))
                        ret_val = False

        # VOQ counter checking - use same slice ports as queue counters
        # Get slice ports (8 egress ports on leaf1 towards IXIA)
        slice_ports = tc_cfg.get('congestion_slice_ports', [])
        if not slice_ports:
            st.error("No congestion_slice_ports found in tc_cfg for VoQ counter check")
            ret_val = False
        else:
            st.log("Checking if VoQ counters on {} slice egress ports (congestion point: {}): {}".format(
                len(slice_ports), congestion_point, slice_ports))
            
            # Get queue from first traffic item (all use same queue)
            queue = tc_cfg['traffic_items'][0]['queue']
            
            for physical_intf in slice_ports:
                if not physical_intf:
                    continue
                voq = vxlan_obj.get_voq_queue_counters(congestion_point, physical_intf, queue)
                st.log("{} {} VOQ counters -> {}".format(congestion_point, physical_intf, voq))
                if self.check_voq_counters_nonzero(voq, congestion_point, physical_intf):
                    st.log("VoQ counters incremented on {} {}: Pass".format(congestion_point, physical_intf))
                else:
                    st.error("VoQ counters not incremented on {} {}: Fail".format(congestion_point, physical_intf))
                    ret_val = False

        # NPU rate check
        st.log("Checking NPU rates")
        congestion_point = tc_cfg['congestion_point']
        
        # For egress: Get Rx rate from congestion point (leaf1) where traffic enters
        # NOT from source nodes (leaf0, leaf2) - we want to see incoming rate at leaf1
        st.log("Getting Rx rates from congestion node {} (where traffic enters)".format(congestion_point))
        npu_rate_check = vxlan_obj.get_npu_rate_check(congestion_point)
        total_rx = float([e.get('total_rx_g') or e.get('TOTAL_RX_G') for e in npu_rate_check if (e.get('total_rx_g') or e.get('TOTAL_RX_G'))][0])
        st.log('Rx rate on congestion node {}: {}'.format(congestion_point, total_rx))
            
        st.log("Getting Tx rates from congestion node: {}".format(congestion_point))
        tx_rate = float([e.get('total_tx_g') or e.get('TOTAL_TX_G') for e in npu_rate_check if (e.get('total_tx_g') or e.get('TOTAL_TX_G'))][0])
            
        expected_bw = float(tc_cfg.get('congestion_bw'))
        tol = expected_bw * 0.02  # 2% tolerance
        st.log('Congestion node ({}) Rx : {}, Expected Bandwidth: {}, tolerance: {} (2%)'.format(congestion_point, total_rx, expected_bw, tol))
        st.log('Congestion node ({}) Tx : {}, Expected Bandwidth: {}, tolerance: {} (2%)'.format(congestion_point, tx_rate, expected_bw, tol))

        # For egress port congestion: Rx should be > expected_bw, Tx within 2% of expected_bw
        tx_within_tolerance = abs(tx_rate - expected_bw) <= tol
        rx_is_greater = total_rx > expected_bw
        
        if tx_within_tolerance and rx_is_greater:
            st.log("NPU rate check PASS (egress port): Tx ({:.2f} Gbps) is within 2% of expected ({:.2f} Gbps), and Rx ({:.2f} Gbps) is greater than expected ({:.2f} Gbps)".format(
                tx_rate, expected_bw, total_rx, expected_bw))
        else:
            st.error("NPU rate check FAIL (egress port):")
            if not tx_within_tolerance:
                st.error("  - Tx rate ({:.2f} Gbps) is NOT within 2% of expected ({:.2f} Gbps). Difference: {:.2f} Gbps".format(
                    tx_rate, expected_bw, abs(tx_rate - expected_bw)))
            if not rx_is_greater:
                st.error("  - Rx rate ({:.2f} Gbps) is NOT greater than expected ({:.2f} Gbps)".format(
                    total_rx, expected_bw))
            ret_val = False

        # CGM validation - check on ingress interfaces to leaf1 (where traffic enters from spines)
        # Check multiple ingress interfaces and pass if ANY show flip-flop (similar to PFC check)
        if ecn_mode != 'ecn_only':
            st.log("Checking CGM on {} ingress interfaces (where traffic enters from spines) - checking multiple interfaces".format(congestion_point))
            queue = tc_cfg['traffic_items'][0]['queue']
            
            # Always collect ALL ingress interfaces independently for CGM check
            # Don't reuse PFC list - collect fresh to ensure we get all interfaces
            cgm_ingress_intfs = []
            checked_cgm_intfs = set()
            all_cgm_traffic_item_intfs = []  # For debugging
            
            for traffic_item in tc_cfg['traffic_items']:
                # Find ALL hops where traffic enters leaf1 (eg_node == congestion_point)
                for hop in traffic_item['hops']:
                    if hop['eg_node'].startswith('T') or hop['in_node'].startswith('T'):
                        continue
                    # Find hop where traffic enters congestion point
                    if hop['eg_node'] == congestion_point:
                        all_cgm_traffic_item_intfs.append((traffic_item.get('name', 'unknown'), hop['in_node'], hop['eg_intf']))
                        # Only add if not already checked (avoid duplicates)
                        if hop['eg_intf'] not in checked_cgm_intfs:
                            checked_cgm_intfs.add(hop['eg_intf'])
                            cgm_ingress_intfs.append(hop['eg_intf'])
                            st.log("CGM: Found ingress interface {} (from {} to {}, traffic item: {})".format(
                                hop['eg_intf'], hop['in_node'], congestion_point, traffic_item.get('name', 'unknown')))
                        break  # Found the ingress interface for this traffic item, move to next
            
            # Log all traffic items and their interfaces for debugging
            st.log("CGM: All {} traffic items and their ingress interfaces to {}:".format(len(all_cgm_traffic_item_intfs), congestion_point))
            for ti_name, source_node, intf in all_cgm_traffic_item_intfs:
                st.log("  {}: {} -> {} ({})".format(ti_name, source_node, intf, congestion_point))
            
            leaf1_ingress_intfs = cgm_ingress_intfs
            st.log("CGM: Collected {} unique ingress interfaces to {}: {}".format(
                len(leaf1_ingress_intfs), congestion_point, leaf1_ingress_intfs))
            
            if not leaf1_ingress_intfs:
                st.error("No ingress interfaces to {} found for CGM check".format(congestion_point))
                ret_val = False
            else:
                st.log("Checking CGM flip-flop on {} ingress interfaces: {}".format(
                    len(leaf1_ingress_intfs), leaf1_ingress_intfs))
                
                cgm_success_count = 0
                cgm_found = False  # Flag to break out of outer loop
                for intf in leaf1_ingress_intfs:
                    if cgm_found:
                        break  # Already found flip-flop, no need to check more interfaces
                    # Expand PortChannel if needed
                    if "PortChannel" in intf:
                        physical_intfs = pc_obj.get_portchannel_members(congestion_point, intf)
                    else:
                        physical_intfs = [intf]
                    
                    for physical_intf in physical_intfs:
                        if self.verify_cgm_flipflop(congestion_point, physical_intf, str(queue)):
                            st.log("CGM flip-flop seen on {} {} (ingress from spine): Pass".format(congestion_point, physical_intf))
                            cgm_success_count += 1
                            cgm_found = True  # Set flag to break outer loop
                            break  # Found flip-flop on this interface, break inner loop
                        else:
                            st.log("No CGM flip-flop seen on {} {} (ingress from spine) - checking other interfaces".format(
                                congestion_point, physical_intf))
                
                # Pass if at least 1 ingress interface showed flip-flop
                if cgm_success_count >= 1:
                    st.log("CGM check PASS: At least 1 ingress interface ({}/{}) showed flip-flop (Xon/Xoff)".format(
                        cgm_success_count, len(leaf1_ingress_intfs)))
                else:
                    st.error("CGM check FAIL: None of the {} ingress interfaces showed flip-flop (Xon/Xoff)".format(
                        len(leaf1_ingress_intfs)))
                    ret_val = False
            
        # VOQ counters ECN marking
        st.log("Checking VOQ ECN marking - at least 1 out of 8 egress ports should have ECN counters increasing")
        
        should_increase_ecn = True
        ecn_ports_increasing = 0
        
        # Get queue from first traffic item
        queue = tc_cfg['traffic_items'][0]['queue']
        
        # Check all slice egress ports (8 ports from congestion_point to remote node)
        slice_ports = tc_cfg.get('congestion_slice_ports', [])
        if not slice_ports:
            st.error("No congestion_slice_ports found in tc_cfg")
            ret_val = False
        else:
            # Step 1: Remove duplicates using set()
            unique_ports = list(set(slice_ports))
            st.log("After deduplication: {} unique ports: {}".format(len(unique_ports), unique_ports))
            
            # Step 2: Get slice_id and all ports in that slice using first port
            if unique_ports:
                first_port = unique_ports[0]
                try:
                    slice_id, all_slice_ports = self.get_slice_for_port(tc_cfg['congestion_point'], first_port)
                    st.log("Port {} belongs to slice {} with {} ports: {}".format(
                        first_port, slice_id, len(all_slice_ports), all_slice_ports))
                    # Step 3: Replace slice_ports with all ports in the slice
                    slice_ports = all_slice_ports
                    st.log("Updated slice_ports to all {} ports in slice {}: {}".format(
                        len(slice_ports), slice_id, slice_ports))
                except Exception as e:
                    st.error("Failed to get slice for port {}: {}".format(first_port, str(e)))
                    st.log("Using deduplicated ports as fallback: {}".format(unique_ports))
                    slice_ports = unique_ports
            
            st.log("Checking ECN counters on {} slice egress ports: {}".format(
                len(slice_ports), slice_ports))
            for port in slice_ports:
                st.log("Checking ECN counters on {} {} (slice egress port)".format(
                    tc_cfg['congestion_point'], port))
                if self.check_ecn_counters_increasing(tc_cfg['congestion_point'], port,
                                                      queue,
                                                      should_increase=should_increase_ecn):
                    ecn_ports_increasing += 1
                    st.log("ECN counters increasing on {} {}: YES".format(tc_cfg['congestion_point'], port))
                else:
                    st.log("ECN counters increasing on {} {}: NO".format(tc_cfg['congestion_point'], port))
        
        if ecn_ports_increasing >= 1:
            st.log("ECN marking check PASS: At least 1 port ({}/{}) has ECN counters increasing".format(
                ecn_ports_increasing, len(slice_ports)))
        else:
            st.error("ECN marking check FAIL: None of the {} ports have ECN counters increasing".format(
                len(slice_ports)))
            ret_val = False

        if ecn_mode != 'ecn_only':
            st.log("Stopping congestion traffic and Checking traffic stats")
            # Stop all streams first
            vxlan_obj.check_traffic(tc_cfg['streams'], action="stop", 
                                    stop_proto_wait=test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait=test_cfg['global']['traffic_start_protocol_sleep'])
            # Check only first 8 streams (exclude stream 9) for validation
            streams_subset = dict(list(tc_cfg['streams'].items())[:8])
            result = vxlan_obj.check_traffic(streams_subset, action="check", min_perc=99,
                                    stop_proto_wait=test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait=test_cfg['global']['traffic_start_protocol_sleep'])

            if not result:
                st.error("Traffic check failed in Post congestion check")
                ret_val = False

        return ret_val

    def post_congestion_check(self, tc_cfg, ecn_mode='normal'):
        """
        Unified post-congestion check method with parameters to handle different scenarios.
        
        Parameters:
        -----------
        tc_cfg : dict
            Test configuration
        ecn_mode : str
            'normal' - check both PFC and ECN with normal logic
            'ecn_only' - disable PFC, check only ECN
            'pfc_only' - disable ECN marking, check only PFC
        """
        ret_val = True
        st.log("Post-Congestion Check (testcase={}, ecn_mode={})".format(test_cfg['tc_id'], ecn_mode))


        # Disable PFC or ECN based on mode
        if ecn_mode == 'ecn_only':
            queue_val = tc_cfg['traffic_items'][0]['queue']
            for ti in tc_cfg['traffic_items']:
                # Determine which hop to use for disabling PFC
                for hop in ti['hops']:
                    if hop['eg_node'] == tc_cfg['congestion_point']:
                
                        congestion_node = hop['eg_node']
                        iface = hop['eg_intf']

                        st.log("Disabling PFC on congestion node {} for interface {}".format(congestion_node, iface))

                        # Handle PortChannel or /lag interfaces specially
                        if "PortChannel" in iface:
                            members = pc_obj.get_portchannel_members(hop['eg_node'], iface)
                            for i in members:
                                st.log("Turning PFC off on {} {}".format(congestion_node, i))
                                st.config(congestion_node, "config interface pfc priority {} {} off".format(i, queue_val))
                        else:
                            st.config(congestion_node, "config interface pfc priority {} {} off".format(iface, queue_val))
                        break

        elif ecn_mode == 'pfc_only':
            st.log("Configuring ecnconfig to disable ECN marking on congestion point {}".format(tc_cfg['congestion_point']))
            st.config(tc_cfg['congestion_point'], "sudo ecnconfig -p AZURE_LOSSLESS -gdrop 0")

        # Start traffic
        st.log("Starting over congestion traffic")
        vxlan_obj.check_traffic(tc_cfg['streams'], regenerate_traffic_items=True, action='start', stop_start_protocols=True)
        
        # Verify PFC counters increment/behavior
        checked_ints = list()
        st.log("Checking if PFC counters on interfaces in congestion path have incremented")
        
        
        for traffic_item in tc_cfg['traffic_items']:
            #hops_to_check = traffic_item['hops'][pfc_hops_slice]
            # Ensure hops_to_check is iterable
            # if not isinstance(hops_to_check, list):
            #    hops_to_check = [hops_to_check] if hops_to_check else []
            
            for hop in traffic_item['hops']:
                # Skip TGEN nodes (they don't have PFC counters)
                if hop['eg_node'].startswith('T'):
                    st.log("Skipping PFC check on TGEN node {}".format(hop['eg_node']))
                    continue
                
                if (hop['eg_node'], hop['eg_intf']) in checked_ints:
                    continue
                checked_ints.append((hop['eg_node'], hop['eg_intf']))
                if "PortChannel" in hop['eg_intf']:
                    intfs = pc_obj.get_portchannel_members(hop['eg_node'], hop['eg_intf'])
                else:
                    intfs = [hop['eg_intf']]    

                for intf in intfs:
                    pfc = vxlan_obj.get_pfc_count(hop['eg_node'], intf)
                
                    # Determine expected PFC behavior
                    should_increment = (ecn_mode == 'normal' or ecn_mode == 'pfc_only')
                
                    if should_increment:
                        if self.check_pfc_counters_increased(pfc, intf, direction="tx", queue=traffic_item['queue']):
                            st.log("PFC counters incremented on {} {}: Pass".format(hop['eg_node'], hop['eg_intf']))
                        else:
                            st.error("PFC counters NOT incremented on {} {}: Fail".format(hop['eg_node'], hop['eg_intf']))
                            ret_val = False
                    else:
                        # ecn_only mode - PFC should NOT increase
                        if self.check_pfc_counters_increased(pfc, intf, direction="tx", queue=traffic_item['queue']):
                            st.error("PFC counters expected to NOT increment, incremented on {} {}: Fail".format(hop['eg_node'], hop['eg_intf']))
                            ret_val = False
                        else:
                            st.log("PFC counters stayed 0 on {} {} : Pass".format(hop['eg_node'], hop['eg_intf']))
                
                if hop['eg_node'] == tc_cfg['congestion_point']:
                    break

        # Queue counter checking (only for normal and pfc_only modes)
        if ecn_mode != 'ecn_only':
            st.log("Checking Queue counters")
            for traffic_item in tc_cfg['traffic_items']:
                st.log("Checking traffic path of traffic item {}".format(traffic_item['name']))
                for hop in traffic_item['hops'][1:]:
                    queue_counters = vxlan_obj.get_queue_counters(hop['in_node'], hop['in_intf'])
                    queue_name = "UC{}".format(int(traffic_item['queue']))
                    if self.check_queue_increased(queue_counters, queue_name):
                        st.log("Post-congestion queue counters are expected to increase on {} {}: Pass".format(hop['in_node'], hop['in_intf']))
                    else:
                        st.error("Post-congestion queue counters are expected to increase on {} {}: Fail".format(hop['in_node'], hop['in_intf']))
                        ret_val = False

        # VOQ counter checking 
        checked_ints = list()
        st.log("Checking if VoQ counters on interfaces in congestion path have incremented")
        for traffic_item in tc_cfg['traffic_items']:
            for hop in traffic_item['hops'][1:]:
                if (hop['in_node'], hop['in_intf']) in checked_ints:
                    continue
                checked_ints.append((hop['in_node'], hop['in_intf']))
                voq = vxlan_obj.get_voq_queue_counters(hop['in_node'], hop['in_intf'], traffic_item['queue'])

                st.log("{} {} VOQ counters -> {}".format(hop['in_node'], hop['in_intf'], voq))
                if self.check_voq_counters_nonzero(voq, hop['in_node'], hop['in_intf']):
                    st.log("VoQ counters incremented on {} {}: Pass".format(hop['in_node'], hop['in_intf']))
                else:
                    st.error("VoQ counters not incremented on {} {}: Fail".format(hop['in_node'], hop['in_intf']))
                    ret_val = False

        # NPU rate check
        st.log("Checking NPU rates")
        
        checked_nodes = list()
        rx_vals = []
        # getting the rx/tx rates from all traffic ingresss leaf nodes
        st.log("Getting Rx rates from all ingress leaf nodes")
        for traffic_item in tc_cfg['traffic_items']:
            hop = traffic_item['hops'][0]
            if hop['eg_node'] in checked_nodes:
                continue
            checked_nodes.append(hop['eg_node'])
            npu_rate_check = vxlan_obj.get_npu_rate_check(hop['eg_node'])
            got_rx_rate = float([e.get('total_rx_g') or e.get('TOTAL_RX_G') for e in npu_rate_check if (e.get('total_rx_g') or e.get('TOTAL_RX_G'))][0])
            st.log('Rx rate on node {} {}: {}'.format(hop['eg_node'], hop['eg_intf'], got_rx_rate))
            rx_vals.append(got_rx_rate)
        total_rx = round(sum(float(x) for x in rx_vals), 2)
            
        st.log("Getting Tx rates from congestion node: {}".format(tc_cfg['congestion_point']))
        npu_rate_check = vxlan_obj.get_npu_rate_check(tc_cfg['congestion_point'])
        tx_rate = float([e.get('total_tx_g') or e.get('TOTAL_TX_G') for e in npu_rate_check if (e.get('total_tx_g') or e.get('TOTAL_TX_G'))][0])
            
        expected_bw = float(tc_cfg.get('congestion_bw'))
        tol = expected_bw * 0.02  # 2% tolerance
        st.log('Ingress nodes ({}) Total Rx : {}, Expected Bandwidth: {}, tolerance: {} (2%)'.format(checked_nodes, total_rx, expected_bw, tol))
        st.log('Congestion nodes ({}) Tx : {}, Expected Bandwidth: {}, tolerance: {} (2%)'.format(tc_cfg['congestion_point'], tx_rate, expected_bw, tol))

        # Check: Tx should be within 2% of expected_bw, Rx should be LESS than expected_bw
        tx_within_tolerance = abs(tx_rate - expected_bw) <= tol
        rx_is_throttled = total_rx < expected_bw
        
        if tx_within_tolerance and rx_is_throttled:
            st.log("NPU rate check PASS: Tx ({:.2f} Gbps) is within 1% of expected ({:.2f} Gbps), and Rx ({:.2f} Gbps) is throttled (< {:.2f} Gbps)".format(
                tx_rate, expected_bw, total_rx, expected_bw))
        else:
            st.error("NPU rate check FAIL:")
            if not tx_within_tolerance:
                st.error("  - Tx rate ({:.2f} Gbps) is NOT within 1% of expected ({:.2f} Gbps). Difference: {:.2f} Gbps".format(
                    tx_rate, expected_bw, abs(tx_rate - expected_bw)))
            if not rx_is_throttled:
                st.error("  - Rx rate ({:.2f} Gbps) is NOT throttled (should be < {:.2f} Gbps)".format(
                    total_rx, expected_bw))
            ret_val = False

        # CGM validation
        if ecn_mode != 'ecn_only':
            st.log("Checking CGM")
            traffic_item = tc_cfg['traffic_items'][0]
            queue = traffic_item['queue']
            hop = traffic_item['hops'][0]
            if self.verify_cgm_flipflop(hop['eg_node'], hop['eg_intf'], str(queue)):
                st.log("CGM flip-flop seen on {} {}".format(hop['eg_node'], hop['eg_intf']))
            else:
                st.error("No CGM flip-flop seen on {} {}".format(hop['eg_node'], hop['eg_intf']))
                ret_val = False
            
        # VOQ counters ECN marking
        st.log("Checking VOQ ECN marking - at least 1 out of 8 egress ports should have ECN counters increasing")
        
        should_increase_ecn = True
        ecn_ports_increasing = 0
        
        # Get queue from first traffic item
        queue = tc_cfg['traffic_items'][0]['queue']
        
        # Check all slice egress ports (8 ports from congestion_point to remote node)
        slice_ports = tc_cfg.get('congestion_slice_ports', [])
        if not slice_ports:
            st.error("No congestion_slice_ports found in tc_cfg")
            ret_val = False
        else:
            # Step 1: Remove duplicates using set()
            unique_ports = list(set(slice_ports))
            st.log("After deduplication: {} unique ports: {}".format(len(unique_ports), unique_ports))
            
            # Step 2: Get slice_id and all ports in that slice using first port
            if unique_ports:
                first_port = unique_ports[0]
                try:
                    slice_id, all_slice_ports = self.get_slice_for_port(tc_cfg['congestion_point'], first_port)
                    st.log("Port {} belongs to slice {} with {} ports: {}".format(
                        first_port, slice_id, len(all_slice_ports), all_slice_ports))
                    # Step 3: Replace slice_ports with all ports in the slice
                    slice_ports = all_slice_ports
                    st.log("Updated slice_ports to all {} ports in slice {}: {}".format(
                        len(slice_ports), slice_id, slice_ports))
                except Exception as e:
                    st.error("Failed to get slice for port {}: {}".format(first_port, str(e)))
                    st.log("Using deduplicated ports as fallback: {}".format(unique_ports))
                    slice_ports = unique_ports
            
            st.log("Checking ECN counters on {} slice egress ports: {}".format(
                len(slice_ports), slice_ports))
            
            for port in slice_ports:
                st.log("Checking ECN counters on {} {} (slice port)".format(
                    tc_cfg['congestion_point'], port))
                
                if self.check_ecn_counters_increasing(tc_cfg['congestion_point'], port, 
                                                      queue, 
                                                      should_increase=should_increase_ecn):
                    ecn_ports_increasing += 1
                    st.log("ECN counters increasing on {} {}: YES".format(tc_cfg['congestion_point'], port))
                else:
                    st.log("ECN counters increasing on {} {}: NO".format(tc_cfg['congestion_point'], port))
        
        # Check if at least 1 port has ECN counters increasing
        st.log("ECN check summary: {}/{} ports have ECN counters increasing".format(
            ecn_ports_increasing, len(slice_ports)))
        
        if ecn_ports_increasing >= 1:
            st.log("ECN marking check PASS: At least 1 port ({}/{}) has ECN counters increasing".format(
                ecn_ports_increasing, len(slice_ports)))
        else:
            st.error("ECN marking check FAIL: None of the {} ports have ECN counters increasing".format(
                len(slice_ports)))
            ret_val = False

        # TOD remove # Clear counters and stop traffic
        #for node in tc_cfg['dut_list']:
        #    self.clear_all_counters(node)

        if ecn_mode != 'ecn_only':
            st.log("Stopping congestion traffic and Checking traffic stats")
            result = vxlan_obj.check_traffic(tc_cfg['streams'], action="stop_check", min_perc=99,
                                    stop_proto_wait=test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait=test_cfg['global']['traffic_start_protocol_sleep'])

            if not result:
                st.error("Traffic check failed in pre-congestion check")
                ret_val = False

        return ret_val

    @pytest.fixture
    def cleanup_congestion_configs(self):
        global stream_handles
        yield
        tc_id = test_cfg.get('tc_id')
        tc_cfg = vxlan_obj.get_tc_params(tc_id) 
        st.log("Unshut uplink interface shut down to force congestion")
        if tc_cfg.get('shut_intf'):
            for node in tc_cfg['dut_list']:
                intf_obj.interface_noshutdown(dut=node, interfaces=tc_cfg['shut_intf'][node])

        streams_info = {k: v for k, v in tc_cfg.get('streams', {}).items() if isinstance(k, int) and isinstance(v, dict)and 'stream_id' in v and 'tg_handle' in v}
        if streams_info:
            vxlan_obj.check_traffic(streams_info, regenerate_traffic_items=False, action='stop', stop_start_protocols=False)     
        if tc_cfg.get('streams'):
            for cntr, stream in tc_cfg['streams'].items():
                if isinstance(stream, dict) and stream.get('stream_id'):
                    st.log("Deleting traffic stream id {}".format(stream['stream_id']))
                    tgen_handles['tg_handle'].tg_traffic_config(mode = 'remove', stream_id = stream['stream_id'])

        st.log("Reenabling back PFC on congestion point interfaces")
        queue_val = tc_cfg['traffic_items'][0]['queue']
        for ti in tc_cfg['traffic_items']:
            hop = ti['hops'][-2]
            congestion_node = hop['eg_node']
            st.config(congestion_node, "config interface pfc priority {} {} on".format(hop['eg_intf'], queue_val))

        for ti in tc_cfg['traffic_items']:
            hop = ti['hops'][-3]
            congestion_node = hop['eg_node']
            st.config(congestion_node, "config interface pfc priority {} {} on".format(hop['eg_intf'], queue_val))
        
        for node in tc_cfg['dut_list']:
            vxlan_obj.config_dut(node, 'sonic', "sudo config qos reload")


    @pytest.fixture(scope="class", autouse=True)
    def setup_slice_congestion_bgp(self):
        """Configure BGP route-map for ECMP load balancing on all leafs"""
        st.log("Configuring BGP route-map for slice congestion tests")
        
        leaf_nodes = ['leaf0', 'leaf1', 'leaf2', 'leaf3']
        
        # Get ASN for each leaf
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        
        for leaf in leaf_nodes:
            if leaf not in bgp_info:
                continue
            asn = bgp_info[leaf]['as_num']
            
            # Configure route-map
            cmd = "route-map anycast_ip permit 10\n"
            cmd += "set extcommunity bandwidth num-multipaths\n"
            cmd += "exit\n"
            
            # Apply to IPv4 and IPv6 address families
            cmd += "router bgp {}\n".format(asn)
            cmd += "address-family ipv4 unicast\n"
            cmd += "neighbor TRANSIT route-map anycast_ip out\n"
            cmd += "exit-address-family\n"
            cmd += "address-family ipv6 unicast\n"
            cmd += "neighbor TRANSIT route-map anycast_ip out\n"
            cmd += "exit-address-family\n"
            cmd += "end\nexit\n"
            
            st.log("Applying BGP route-map on {}".format(leaf))
            st.config(leaf, cmd, type='vtysh')
        
        st.log("BGP route-map configuration complete for slice congestion tests")
        
        yield
        
        # Cleanup: Remove route-map configuration
        st.log("Removing BGP route-map configuration")
        for leaf in leaf_nodes:
            if leaf not in bgp_info:
                continue
            asn = bgp_info[leaf]['as_num']
            
            cmd = "router bgp {}\n".format(asn)
            cmd += "address-family ipv4 unicast\n"
            cmd += "no neighbor TRANSIT route-map anycast_ip out\n"
            cmd += "exit-address-family\n"
            cmd += "address-family ipv6 unicast\n"
            cmd += "no neighbor TRANSIT route-map anycast_ip out\n"
            cmd += "exit-address-family\n"
            cmd += "exit\n"
            cmd += "no route-map anycast_ip\n"
            cmd += "end\nexit\n"
            
            st.config(leaf, cmd, type='vtysh')
        st.log("BGP route-map cleanup complete")
    
    
    def get_slice_for_port(self, dut, port):
        """Returns slice_id and all ports in that slice for the given port."""
        npu_global = vxlan_obj.get_npu_global(dut)
        slice_map = {}
        
        # Handle dict format (from template parser) - this is the PRIMARY format
        if isinstance(npu_global, dict):
            interfaces = npu_global.get('interfaces', [])
            if not interfaces and 'interfaces' not in npu_global:
                # Maybe interfaces is at top level or different structure
                interfaces = npu_global if isinstance(npu_global, list) else []
            for intf_info in interfaces:
                if isinstance(intf_info, dict):
                    # Interface name can be in 'iface', 'port', or 'Port' key
                    intf = intf_info.get('iface') or intf_info.get('port') or intf_info.get('Port')
                    slice_id = intf_info.get('slice') or intf_info.get('Slice')
                    if intf and slice_id is not None:
                        try:
                            slice_id = int(slice_id)
                            # Filter: slice must be < 256 (physical slices only)
                            if slice_id != 255 and slice_id < 256:
                                if slice_id not in slice_map:
                                    slice_map[slice_id] = []
                                if intf not in slice_map[slice_id]:  # Avoid duplicates
                                    slice_map[slice_id].append(intf)
                        except (ValueError, TypeError):
                            continue
        # Handle list format (direct list of interfaces)
        elif isinstance(npu_global, list):
            for intf_info in npu_global:
                if isinstance(intf_info, dict):
                    # Interface name is in 'iface' key, not 'port'
                    intf = intf_info.get('iface') or intf_info.get('port') or intf_info.get('Port')
                    slice_id = intf_info.get('slice') or intf_info.get('Slice')
                    if intf and slice_id is not None:
                        try:
                            slice_id = int(slice_id)
                            # Filter: slice must be < 256 (physical slices only, not Port table slice IDs)
                            if slice_id != 255 and slice_id < 256:
                                if slice_id not in slice_map:
                                    slice_map[slice_id] = []
                                if intf not in slice_map[slice_id]:  # Avoid duplicates
                                    slice_map[slice_id].append(intf)
                        except (ValueError, TypeError):
                            continue
        # Handle string format (raw output - fallback)
        elif isinstance(npu_global, str):
            in_first_table = True
            for line in npu_global.split('\n'):
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if not parts:
                    continue
                
                if parts[0] == 'Port' and len(parts) > 1 and parts[1] == 'sai_lane':
                    in_first_table = False
                    continue
                
                if parts[0] in ['Interface', 'Note:', 'Asic', 'Device', 'SMS', 'HBM']:
                    continue
                
                if len(parts) >= 2 and parts[0].startswith('Ethernet'):
                    intf = parts[0]
                    try:
                        # First table: slice at index 1, Second table: slice at index 2
                        slice_idx = 1 if in_first_table else 2
                        if len(parts) > slice_idx:
                            slice_id = int(parts[slice_idx])
                            if slice_id != 255 and slice_id < 256:
                                if slice_id not in slice_map:
                                    slice_map[slice_id] = []
                                if intf not in slice_map[slice_id]:
                                    slice_map[slice_id].append(intf)
                    except (ValueError, IndexError):
                        continue
        else:
            st.error("Unexpected type for npu_global: {} (type: {})".format(type(npu_global).__name__, type(npu_global)))
            raise Exception("get_npu_global returned unexpected type: {}".format(type(npu_global).__name__))
        
        for slice_id, ports in slice_map.items():
            if port in ports:
                st.log("Port {} on {} belongs to slice {} with ports: {}".format(port, dut, slice_id, ports))
                return slice_id, ports
        
        raise Exception("Could not find slice for port {} on {}".format(port, dut))
    
    def test_egress_leaf_slice_congestion(self, protocol, queue, traffictype, cleanup_congestion_configs):
        orig_ti = self.build_egress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_egress_leaf_slice_congestion_test(
            tc_id='test_egress_leaf_slice_congestion',
            banner="TEST: Egress Leaf Slice Congestion",
            original_traffic_items=orig_ti,
            congestion_point='leaf1',  # Changed from leaf2 to leaf1 for 8-stream convergence
            breakout_type=None,
            ecn_mode='normal',
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )
    
    def test_spine_slice_congestion(self, protocol, queue, traffictype, cleanup_congestion_configs):
        orig_ti = self.build_spine_traffic_items(protocol, queue, traffictype)
        self.run_spine_slice_congestion_test(
            tc_id='test_spine_slice_congestion',
            banner="TEST: Spine Slice Congestion",
            original_traffic_items=orig_ti,
            congestion_point='spine0',
            breakout_type=None,
            ecn_mode='normal',
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )
    
    def test_ingress_leaf_slice_congestion(self, protocol, queue, traffictype, cleanup_congestion_configs):
        orig_ti = self.build_ingress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_ingress_leaf_slice_congestion_test(
            tc_id='test_ingress_leaf_slice_congestion',
            banner="TEST: Ingress Leaf Slice Congestion",
            original_traffic_items=orig_ti,
            congestion_point='leaf0',
            breakout_type=None,
            ecn_mode='normal',
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )
    
    
    def test_egress_leaf_slice_congestion_ecn_only(self, protocol, queue, traffictype, cleanup_congestion_configs):
        orig_ti = self.build_egress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_egress_leaf_slice_congestion_test(
            tc_id='test_egress_leaf_slice_congestion_ecn_only',
            banner="TEST: Egress Leaf Slice Congestion (ECN only)",
            original_traffic_items=orig_ti,
            congestion_point='leaf1',  # Changed from leaf2 to leaf1 for 8-stream convergence
            breakout_type=None,
            ecn_mode='ecn_only',
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )
    
    def test_spine_slice_congestion_ecn_only(self, protocol, queue, traffictype, cleanup_congestion_configs):
        orig_ti = self.build_spine_traffic_items(protocol, queue, traffictype)
        self.run_spine_slice_congestion_test(
            tc_id='test_spine_slice_congestion_ecn_only',
            banner="TEST: Spine Slice Congestion (ECN only)",
            original_traffic_items=orig_ti,
            congestion_point='spine0',
            breakout_type=None,
            ecn_mode='ecn_only',
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )
    
    def test_ingress_leaf_slice_congestion_ecn_only(self, protocol, queue, traffictype, cleanup_congestion_configs):
        orig_ti = self.build_ingress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_ingress_leaf_slice_congestion_test(
            tc_id='test_ingress_leaf_slice_congestion_ecn_only',
            banner="TEST: Ingress Leaf Slice Congestion (ECN only)",
            original_traffic_items=orig_ti,
            congestion_point='leaf0',
            breakout_type=None,
            ecn_mode='ecn_only',
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )

    
    def test_egress_leaf_slice_congestion_pfc_only(self, protocol, queue, traffictype, cleanup_congestion_configs):
        orig_ti = self.build_egress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_egress_leaf_slice_congestion_test(
            tc_id='test_egress_leaf_slice_congestion_pfc_only',
            banner="TEST: Egress Leaf Slice Congestion (PFC only)",
            original_traffic_items=orig_ti,
            congestion_point='leaf1',  # Changed from leaf2 to leaf1 for 8-stream convergence
            breakout_type=None,
            ecn_mode='pfc_only',
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )
    
    def test_spine_slice_congestion_pfc_only(self, protocol, queue, traffictype, cleanup_congestion_configs):
        orig_ti = self.build_spine_traffic_items(protocol, queue, traffictype)
        self.run_spine_slice_congestion_test(
            tc_id='test_spine_slice_congestion_pfc_only',
            banner="TEST: Spine Slice Congestion (PFC only)",
            original_traffic_items=orig_ti,
            congestion_point='spine0',
            breakout_type=None,
            ecn_mode='pfc_only',
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )
    
    def test_ingress_leaf_slice_congestion_pfc_only(self, protocol, queue, traffictype, cleanup_congestion_configs):
        orig_ti = self.build_ingress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_ingress_leaf_slice_congestion_test(
            tc_id='test_ingress_leaf_slice_congestion_pfc_only',
            banner="TEST: Ingress Leaf Slice Congestion (PFC only)",
            original_traffic_items=orig_ti,
            congestion_point='leaf0',
            breakout_type=None,
            ecn_mode='pfc_only',
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )
    
    def ensure_egress_bgp_sessions(self, target_spine, destination_leaf):
        """
        Ensure BGP sessions are configured on spine to destination_leaf egress links.
        """
        st.banner(f"Ensuring BGP sessions on {target_spine}  to  {destination_leaf} egress links")
        
        # Get all ports connecting target_spine to destination_leaf from YAML topology
        node_intfs = vxlan_obj.get_dut_interfaces(vars)
        spine_underlay_dict = node_intfs[target_spine]['underlay_dict']
        
        # Find all ports from spine to destination leaf
        spine_id = vars.dut_ids[target_spine]
        dest_id = vars.dut_ids[destination_leaf]
        prefix = spine_id + dest_id  # e.g., "D1D6" for spine0 to leaf1
        
        egress_ports = []
        for port_id, physical_port in spine_underlay_dict.items():
            if port_id.startswith(prefix) and physical_port:
                egress_ports.append(physical_port)
        
        if not egress_ports:
            st.log(f"No egress ports found from {target_spine} to {destination_leaf}")
            return
        
        st.log(f"Found {len(egress_ports)} egress ports from {target_spine} to {destination_leaf}: {egress_ports}")
        
        # Expand to include both _1 and _2 lanes for breakout ports
        egress_ports_expanded = []
        base_ports_seen = set()
        
        for port in egress_ports:
            if port.endswith('_1') or port.endswith('_2'):
                base_port = port.rsplit('_', 1)[0]
                if base_port not in base_ports_seen:
                    base_ports_seen.add(base_port)
                    egress_ports_expanded.append(base_port + '_1')
                    egress_ports_expanded.append(base_port + '_2')
            else:
                egress_ports_expanded.append(port)
        
        st.log(f"Expanded egress ports (with both lanes): {egress_ports_expanded}")
        
        # Now ensure BGP on both spine and destination leaf sides
        self.ensure_slice_bgp_sessions(target_spine, egress_ports_expanded)
        
        # Find corresponding ports on destination leaf
        leaf_underlay_dict = node_intfs[destination_leaf]['underlay_dict']
        reverse_prefix = dest_id + spine_id  # e.g., "D6D1" for leaf1â†spine0
        
        leaf_ports = []
        for port_id, physical_port in leaf_underlay_dict.items():
            if port_id.startswith(reverse_prefix) and physical_port:
                leaf_ports.append(physical_port)
        
        # Expand leaf ports too
        leaf_ports_expanded = []
        base_ports_seen = set()
        
        for port in leaf_ports:
            if port.endswith('_1') or port.endswith('_2'):
                base_port = port.rsplit('_', 1)[0]
                if base_port not in base_ports_seen:
                    base_ports_seen.add(base_port)
                    leaf_ports_expanded.append(base_port + '_1')
                    leaf_ports_expanded.append(base_port + '_2')
            else:
                leaf_ports_expanded.append(port)
        
        st.log(f"Corresponding ports on {destination_leaf}: {leaf_ports_expanded}")
        self.ensure_slice_bgp_sessions(destination_leaf, leaf_ports_expanded)
    
    def ensure_slice_bgp_sessions(self, congestion_point, slice_ports):
        """
        Ensure BGP sessions are configured on all slice ports (including both _1 and _2 lanes).
        """
        st.banner(f"Ensuring BGP sessions are configured on all slice ports on {congestion_point}")
        
        # Step 1: Deduplicate and auto-discover both _1 and _2 lanes
        # Build a base set of port names without lane suffixes
        base_ports = set()
        for port in slice_ports:
            if port.endswith('_1') or port.endswith('_2'):
                base_port = port.rsplit('_', 1)[0]
                base_ports.add(base_port)
            else:
                # Non-breakout port, add as-is
                base_ports.add(port)
        
        # Build final list with both _1 and _2 lanes
        slice_ports_final = []
        for base_port in sorted(base_ports):
            # Check if this is a breakout port
            if any(p.startswith(base_port + '_') for p in slice_ports):
                # Add both _1 and _2 lanes
                slice_ports_final.append(base_port + '_1')
                slice_ports_final.append(base_port + '_2')
            else:
                # Non-breakout port
                slice_ports_final.append(base_port)
        
        st.log(f"Original slice ports: {slice_ports}")
        st.log(f"Expanded slice ports (with both lanes): {slice_ports_final}")
        
        # Get BGP AS number for the congestion point
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        node_as = bgp_info[congestion_point]['as_num']
        
        # Get current BGP neighbor list
        st.log(f"Checking BGP neighbors on {congestion_point}")
        output = st.show(congestion_point, "show bgp summary", type='vtysh', skip_tmpl=False, skip_error_check=True)
        
        # Parse existing neighbors
        existing_neighbors = set()
        if isinstance(output, list):
            for entry in output:
                if 'neighbor' in entry and entry['neighbor']:
                    existing_neighbors.add(entry['neighbor'])
        
        st.log(f"Existing BGP neighbors on {congestion_point}: {existing_neighbors}")
        st.log(f"Required slice ports: {slice_ports_final}")
        
        # Find missing neighbors
        missing_neighbors = [port for port in slice_ports_final if port not in existing_neighbors]
        
        if not missing_neighbors:
            st.log(f"All {len(slice_ports_final)} slice ports already have BGP neighbors configured. No action needed.")
            return
        
        st.log(f"Found {len(missing_neighbors)} slice ports missing BGP neighbors: {missing_neighbors}")
        
        # Configure missing BGP neighbors
        frr_cfg = f'router bgp {node_as}\n'
        ll_cfg = ''
        qos_cfg = ''
        
        for intf in missing_neighbors:
            st.log(f"Adding BGP neighbor for {intf}")
            frr_cfg += f' neighbor {intf} interface peer-group TRANSIT\n'
            ll_cfg += f'sudo config interface ipv6 enable use-link-local-only {intf}\n'
            if test_cfg['global']['qos_enable']:
                qos_cfg += f'sudo config qos reload --ports {intf}\n'
        
        frr_cfg += 'end\n'
        frr_cfg += 'exit\n'
        
        # Apply configurations
        st.log(f"Configuring link-local IPv6 on {len(missing_neighbors)} interfaces on {congestion_point}")
        st.config(congestion_point, ll_cfg, skip_error_check=True, conf=True)
        
        if test_cfg['global']['qos_enable']:
            st.log(f"Configuring QoS on {len(missing_neighbors)} interfaces on {congestion_point}")
            st.config(congestion_point, qos_cfg, skip_error_check=True, conf=True)
        
        st.log(f"Configuring BGP neighbors for {len(missing_neighbors)} interfaces on {congestion_point}")
        st.config(congestion_point, frr_cfg, type='vtysh', skip_error_check=True, conf=True)
        
        # Verify BGP sessions come up
        st.wait(5, "Waiting for BGP sessions to establish")
        
        # Re-check BGP neighbors
        output = st.show(congestion_point, "show bgp summary", type='vtysh', skip_tmpl=False, skip_error_check=True)
        new_neighbors = set()
        if isinstance(output, list):
            for entry in output:
                if 'neighbor' in entry and entry['neighbor']:
                    new_neighbors.add(entry['neighbor'])
        
        st.log(f"BGP neighbors after configuration: {new_neighbors}")
        
        # Check if all slice ports are now configured
        still_missing = [port for port in slice_ports if port not in new_neighbors]
        
        if still_missing:
            st.warn(f"Some slice ports still missing BGP neighbors after configuration: {still_missing}")
        else:
            st.log(f"All {len(slice_ports)} slice ports now have BGP neighbors configured")
    
    def run_ingress_leaf_slice_congestion_test(self, *, tc_id, banner, original_traffic_items, congestion_point,
                                                breakout_type, ecn_mode='normal', run_pre_congestion_check=False):
        """
        Run slice congestion test for INGRESS LEAF case.
        Traffic: T1  to  leaf (congestion)  to  spine  to  leaf  to  T1
        Target: spine (next node after congestion leaf)
        """
        st.banner(banner)
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        tc_cfg['tc_id'] = tc_id  # Store tc_id in tc_cfg for later reference
        tc_cfg['congestion_point'] = congestion_point
        
        if breakout_type:
            try:
                pf.change_underlay_dpb(dpb_type=breakout_type)
                verify_base_setup(retry=15)
            except Exception as err:
                if not "already configured" in str(err):
                    raise err
        
        # Find the congestion port from path
        node_intfs = vxlan_obj.get_dut_interfaces(vars)
        underlay_dict = node_intfs[congestion_point]['underlay_dict']
        
        # Take first uplink port from underlay
        congestion_port = None
        for port_id, physical_port in underlay_dict.items():
            if physical_port:
                congestion_port = physical_port
                break
        
        if not congestion_port:
            raise Exception("Could not find any underlay port for {}".format(congestion_point))
        
        st.log("Using congestion port: {} on {}".format(congestion_port, congestion_point))
        
        # Find target spine (next node after ingress leaf in path)
        # Path: T1  to  leaf0 (congestion)  to  spine0 (target)  to  leaf1  to  T1
        target_spine = None
        for traffic_item in original_traffic_items:
            path = traffic_item['path']
            for i in range(len(path) - 1):
                node_name = list(path[i].keys())[0]
                next_node_name = list(path[i + 1].keys())[0]
                if node_name == congestion_point and 'spine' in next_node_name:
                    target_spine = next_node_name
                    break
            if target_spine:
                break
        
        if not target_spine:
            raise Exception("Could not find target spine from traffic path")
        
        st.log("Target spine for ingress leaf slice congestion: {}".format(target_spine))
        
        # Find ALL interfaces on ingress leaf that connect to target_spine
        # Port ID format: D{source}D{dest}P{num}, e.g., D5D1P1 = leaf0 to spine0 port 1
        # Collect both _1 and _2 lane ports for full slice coverage
        slice_ports = []
        target_spine_id = vars.dut_ids[target_spine]
        congestion_point_id = vars.dut_ids[congestion_point]
        prefix = congestion_point_id + target_spine_id  # e.g., "D5D1"
        
        for port_id, physical_port in underlay_dict.items():
            if port_id.startswith(prefix):
                slice_ports.append(physical_port)
        
        if len(slice_ports) < 2:
            raise Exception("Need at least 2 ports from {} to {} for slice congestion, only found: {}".format(
                congestion_point, target_spine, slice_ports))
        
        tc_cfg['congestion_slice_ports'] = slice_ports
        tc_cfg['congestion_remote_node'] = target_spine
        
        st.log("Slice congestion: keeping {} ports UP from {} to {}: {}".format(
            len(slice_ports), congestion_point, target_spine, slice_ports))
        
        # Find the corresponding remote slice ports on target_spine
        remote_underlay_dict = node_intfs[target_spine]['underlay_dict']
        remote_slice_ports = []
        remote_prefix = target_spine_id + congestion_point_id  # e.g., "D1D5" (reverse direction)
        
        for port_id, physical_port in remote_underlay_dict.items():
            if port_id.startswith(remote_prefix):
                remote_slice_ports.append(physical_port)
        
        st.log("Remote slice ports on {}: {}".format(target_spine, remote_slice_ports))
        
        # Ensure BGP sessions are configured on all slice ports (both _1 and _2 lanes) on BOTH sides
        self.ensure_slice_bgp_sessions(congestion_point, slice_ports)
        self.ensure_slice_bgp_sessions(target_spine, remote_slice_ports)
        
        # Use original items (don't replicate - causes TGEN duplicate stream issues)
        tc_cfg['traffic_items'] = original_traffic_items
        tc_cfg['slice_multiplier'] = len(slice_ports)
        self.process_traffic_items(tc_cfg)
        
        # NEW: Ensure BGP sessions on spine to destination_leaf egress links
        # Extract destination leaf from traffic paths
        destination_leafs = set()
        for traffic_item in original_traffic_items:
            path = traffic_item['path']
            # Find the destination leaf in the path (after target_spine)
            for i in range(len(path) - 1):
                node_name = list(path[i].keys())[0]
                next_node_name = list(path[i + 1].keys())[0]
                if node_name == target_spine and 'leaf' in next_node_name:
                    destination_leafs.add(next_node_name)
                    break
        
        # Ensure BGP on spine to each destination leaf
        for dest_leaf in destination_leafs:
            st.log(f"Ensuring BGP sessions on {target_spine}  to  {dest_leaf} egress path")
            self.ensure_egress_bgp_sessions(target_spine, dest_leaf)
        
        st.log("Using {} original traffic items for slice congestion, will increase bandwidth for {} slice ports".format(
            len(original_traffic_items), len(slice_ports)))
        
        # Calculate bandwidth for congestion
        dut = tc_cfg['dut_list'][0]
        
        # Get interface speeds from the congestion point
        intfs_status = vxlan_obj.get_interfaces_status(congestion_point)
        
        # Also get TGEN interface speed from the source DUT
        dut_intfs_status = vxlan_obj.get_interfaces_status(dut)
        dut_tgen_portid = vxlan_obj.get_peer_port_id(list(node_intfs[dut]['tgen_port_dict'].keys())[0], vars)
        dut_tgen_int = vars[dut_tgen_portid]
        
        for status in dut_intfs_status:
            if status['interface'] == dut_tgen_int:
                tc_cfg['tgen_bw'] = int(status['speed'][:-1])
                break
        
        if not tc_cfg.get('tgen_bw'):
            raise Exception("Could not determine TGEN interface speed")
        
        # Calculate total slice bandwidth
        total_slice_bw = 0
        for physical_port in slice_ports:
            for status in intfs_status:
                if status['interface'] == physical_port:
                    total_slice_bw += int(status['speed'][:-1])
                    break
        
        if total_slice_bw == 0:
            raise Exception("Could not determine slice bandwidth for ports: {}".format(slice_ports))
        
        st.log("Slice ({} -> {}) total bandwidth: {} Gbps across {} ports".format(
            congestion_point, target_spine, total_slice_bw, len(slice_ports)))
        
        # Set congestion_bw for post_congestion_check (in Gbps to match NPU rate check units)
        tc_cfg['congestion_bw'] = total_slice_bw
        
        # Divide bandwidth equally across all streams (Note: actual rate set to 99% in trigger_congestion)
        per_stream_bw = (total_slice_bw * 0.99) / len(tc_cfg['traffic_items'])
        if per_stream_bw > tc_cfg['tgen_bw']:
            per_stream_bw = tc_cfg['tgen_bw'] * 0.99
        
        for traffic_item in tc_cfg['traffic_items']:
            traffic_item['max_bw'] = per_stream_bw
        self.setup_traffic_path(tc_cfg, breakout_type=breakout_type)
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)
        
        if run_pre_congestion_check:
            if self.pre_congestion_check(tc_cfg):
                st.log("Pre-congestion check: PASS")
            else:
                st.banner("Pre-congestion check failed!!!!!!")
        else:
            st.log("Skipping pre-congestion check (run_pre_congestion_check=False)")
        
        self.trigger_congestion(tc_cfg)
        
        if self.post_congestion_check(tc_cfg, ecn_mode=ecn_mode):
            vxlan_obj.report_result(True, tc_id, "PFC/VoQ Slice Congestion check PASS")
        else:
            vxlan_obj.report_result(False, tc_id, "Post-congestion check failed")
    
    def run_egress_leaf_slice_congestion_test(self, *, tc_id, banner, original_traffic_items, congestion_point,
                                              breakout_type, ecn_mode='normal', run_pre_congestion_check=False):
        """
        Run slice congestion test for EGRESS LEAF case.
        
        Architecture:
        - Multiple traffic streams from different sources converge at egress leaf
        - Traffic: T1  to  leaf{0,2}  to  spine{0,1}  to  leaf1 (congestion)  to  T1
        - Congestion: All streams exit through leaf1's TGEN-facing ports (ONE slice)
        - Keep ALL underlay paths UP (no spine shutdowns) - traffic converges from all directions
        - Congest at the EGRESS side: leaf1  to  TGEN (8 ports in same slice)
        """
        st.banner(banner)
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        tc_cfg['tc_id'] = tc_id
        tc_cfg['congestion_point'] = congestion_point
        
        if breakout_type:
            try:
                pf.change_underlay_dpb(dpb_type=breakout_type)
                verify_base_setup(retry=15)
            except Exception as err:
                if not "already configured" in str(err):
                    raise err
        
        # Get node interfaces
        node_intfs = vxlan_obj.get_dut_interfaces(vars)
        
        # Find TGEN-facing ports on congestion_point (egress leaf)
        tgen_port_dict = node_intfs[congestion_point]['tgen_port_dict']
        
        if not tgen_port_dict:
            raise Exception("Could not find TGEN ports for {}".format(congestion_point))
        
        st.log("Found {} TGEN port mappings on {}: {}".format(
            len(tgen_port_dict), congestion_point, tgen_port_dict))
        
        # Convert TGEN port IDs to physical interfaces on the switch
        # Port ID format: 'T1D6P1' (TGEN  to  leaf1) maps to TGEN port '2/1/17'
        # Reverse format: 'D6T1P1' (leaf1  to  TGEN) maps to physical interface 'Ethernet1_61_1'
        physical_tgen_intfs = []
        congestion_point_id = vars.dut_ids[congestion_point]
        tgen_id = 'T1'  # TGEN device ID
        
        for port_id, tgen_port in tgen_port_dict.items():
            # Reverse the port ID to get DUT-side interface
            # 'T1D6P1'  to  'D6T1P1'
            reverse_port_id = congestion_point_id + tgen_id + 'P' + port_id.split('P')[-1]  # e.g., 'D6T1P1'
            if reverse_port_id in vars:
                physical_intf = vars[reverse_port_id]
                physical_tgen_intfs.append(physical_intf)
                st.log("Port ID {} (TGEN: {}) maps to physical interface {}".format(
                    port_id, tgen_port, physical_intf))
            else:
                st.log("Warning: Could not find physical interface for reverse port ID {}".format(reverse_port_id))
        
        if not physical_tgen_intfs:
            raise Exception("Could not determine physical TGEN interfaces on {}".format(congestion_point))
        
        # Determine which slice these physical interfaces belong to
        # All traffic egresses through TGEN ports, which should be in ONE slice
        first_tgen_intf = physical_tgen_intfs[0]
        slice_id, all_slice_ports = self.get_slice_for_port(congestion_point, first_tgen_intf)
        
        st.log("First TGEN interface {} on {} is in slice {}, which contains ports: {}".format(
            first_tgen_intf, congestion_point, slice_id, all_slice_ports))
        
        # Get the physical TGEN interfaces that are in this slice
        slice_tgen_ports = [intf for intf in physical_tgen_intfs if intf in all_slice_ports]
        
        if len(slice_tgen_ports) < 2:
            raise Exception("Need at least 2 TGEN interfaces in the same slice on {}, found {} interfaces in slice {}: {}".format(
                congestion_point, len(slice_tgen_ports), slice_id, slice_tgen_ports))
        
        st.log("EGRESS LEAF SLICE CONGESTION: {} TGEN interfaces on {} are in slice {}: {}".format(
            len(slice_tgen_ports), congestion_point, slice_id, slice_tgen_ports))
        
        # Store slice information (physical interfaces)
        tc_cfg['congestion_slice_ports'] = slice_tgen_ports
        tc_cfg['congestion_slice_id'] = slice_id
        
        # For egress leaf slice: NO spine shutdowns! We want traffic from ALL paths to converge
        # The congestion happens at leaf1 to TGEN egress, not at spine to leaf1 ingress
        tc_cfg['congestion_remote_node'] = None  # No remote node - congestion is local egress
        
        st.log("Egress leaf slice congestion: {} streams will converge and exit through {} TGEN interfaces in slice {}".format(
            len(original_traffic_items), len(slice_tgen_ports), slice_id))
        
        # Use original traffic items
        tc_cfg['traffic_items'] = original_traffic_items
        
        st.log("Using {} traffic streams converging at {} and exiting through {} TGEN interfaces in slice {}".format(
            len(original_traffic_items), congestion_point, len(slice_tgen_ports), slice_id))
        
        # Calculate bandwidth for congestion (based on egress TGEN slice ports)
        intfs_status = vxlan_obj.get_interfaces_status(congestion_point)
        
        # Calculate total slice bandwidth (sum of all TGEN interfaces in the slice)
        total_slice_bw = 0
        for physical_port in slice_tgen_ports:
            for status in intfs_status:
                if status['interface'] == physical_port:
                    port_speed = int(status['speed'][:-1])
                    total_slice_bw += port_speed
                    st.log("Slice TGEN interface {} has speed {} Gbps".format(physical_port, port_speed))
                    break
        
        if total_slice_bw == 0:
            raise Exception("Could not determine slice bandwidth for TGEN interfaces: {}".format(slice_tgen_ports))
        
        # Determine single TGEN interface speed (for per-stream limit)
        tc_cfg['tgen_bw'] = int(intfs_status[0]['speed'][:-1]) if intfs_status else 400
        
        st.log("Egress leaf slice ({} to TGEN slice {}) total bandwidth: {} Gbps across {} interfaces".format(
            congestion_point, slice_id, total_slice_bw, len(slice_tgen_ports)))
        
        # Set congestion_bw for post_congestion_check
        tc_cfg['congestion_bw'] = total_slice_bw
        
        # Divide bandwidth equally across all streams (Note: actual rate set to 95% in trigger_congestion_egress)
        per_stream_bw = (total_slice_bw * 0.95) / len(tc_cfg['traffic_items'])
        if per_stream_bw > tc_cfg['tgen_bw']:
            per_stream_bw = tc_cfg['tgen_bw'] * 0.95
        
        st.log("Per-stream bandwidth: {} Gbps (total {} Gbps / {} streams)".format(
            per_stream_bw, total_slice_bw, len(tc_cfg['traffic_items'])))
        
        for traffic_item in tc_cfg['traffic_items']:
            traffic_item['max_bw'] = per_stream_bw
        
        # Ensure BGP sessions on all slice ports (for ECMP load balancing)
        # Expand the slice ports to include both _1 and _2 lanes for 200G breakout
        slice_ports_expanded = []
        for physical_port in slice_tgen_ports:
            slice_ports_expanded.append(physical_port)
            # If this is a 200G interface (e.g., Ethernet1_61_1), add the _2 lane
            if physical_port.endswith('_1'):
                base_port = physical_port.rsplit('_', 1)[0]
                lane_2_port = base_port + '_2'
                slice_ports_expanded.append(lane_2_port)
        
        st.log(f"Ensuring BGP sessions on {congestion_point} for EGRESS slice ports: {slice_ports_expanded}")
        self.ensure_slice_bgp_sessions(congestion_point, slice_ports_expanded)
        
        # Use original traffic items
        tc_cfg['traffic_items'] = original_traffic_items
        tc_cfg['slice_multiplier'] = len(slice_tgen_ports)
        self.process_traffic_items(tc_cfg)
        
        # Ensure BGP sessions on the underlay paths (like spine scenario)
        # Traffic: TGEN  to  leaf{0,2}  to  spine{0,1}  to  leaf1 (congestion)  to  TGEN
        # Need to ensure: 1) leaf{0,2}  to  spine{0,1} and 2) spine{0,1}  to  leaf1
        
        # Find all source leafs and intermediate spines from traffic paths
        source_leafs = set()
        intermediate_spines = set()
        for traffic_item in original_traffic_items:
            path = traffic_item['path']
            # Path structure: [{'T1': 'P1'}, {'leaf0': 'P1'}, {'spine0': 'P1'}, {'leaf1': 'P1'}, {'T1': 'P1'}]
            for i in range(len(path)):
                node_name = list(path[i].keys())[0]
                if 'leaf' in node_name and node_name != congestion_point:
                    # This is a source leaf (before spines)
                    source_leafs.add(node_name)
                elif 'spine' in node_name:
                    # This is an intermediate spine (between source and egress leaf)
                    intermediate_spines.add(node_name)
        
        st.log(f"Egress leaf slice: source leafs = {source_leafs}, intermediate spines = {intermediate_spines}")
        
        # Ensure BGP sessions on each source_leaf  to  spine path
        for src_leaf in source_leafs:
            for spine in intermediate_spines:
                st.log(f"Ensuring BGP sessions on {src_leaf}  to  {spine} ingress path")
                self.ensure_egress_bgp_sessions(src_leaf, spine)
        
        # Ensure BGP sessions on each spine  to  egress_leaf path
        for spine in intermediate_spines:
            st.log(f"Ensuring BGP sessions on {spine}  to  {congestion_point} egress path")
            self.ensure_egress_bgp_sessions(spine, congestion_point)
        
        self.setup_traffic_path(tc_cfg, breakout_type=breakout_type)
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)
        
        if run_pre_congestion_check:
            # EGRESS LEAF SLICE: Start with 5% traffic rate for pre-congestion check
            st.log("Setting initial traffic rate to 5% for egress leaf slice congestion test")
            tg = tgen_handles['tg_handle']
            for stream in tc_cfg['traffic_items']:
                stream_id = stream['stream_id']
                tg.tg_traffic_config(
                    mode="modify",
                    stream_id=stream_id,
                    rate_percent=5
                )
                st.log("Set stream {} to 5% rate for pre-congestion check".format(stream['name']))
            
            tg.tg_test_control(action='apply_on_the_fly_changes')
            st.wait(5)  # Wait for traffic rate change to take effect
            
            if self.pre_congestion_check(tc_cfg):
                st.log("Pre-congestion check: PASS")
            else:
                st.banner("Pre-congestion check failed!!!!!!")
        else:
            st.log("Skipping pre-congestion check (run_pre_congestion_check=False)")
        
        self.trigger_congestion_egress(tc_cfg)
        if self.post_congestion_check_egress(tc_cfg, ecn_mode=ecn_mode):
            vxlan_obj.report_result(True, tc_id, "PFC/VoQ Egress Leaf Slice Congestion check PASS")
        else:
            vxlan_obj.report_result(False, tc_id, "Post-congestion check failed")
    
    def run_spine_slice_congestion_test(self, *, tc_id, banner, original_traffic_items, congestion_point,
                                        breakout_type, ecn_mode='normal', run_pre_congestion_check=False):
        """
        Run slice congestion test for SPINE case.
        Traffic: T1  to  leaf  to  spine (congestion)  to  leaf (target)  to  T1
        Target: destination leaf (next node after congestion spine)
        """
        st.banner(banner)
        test_cfg['tc_id'] = tc_id
        tc_cfg = vxlan_obj.get_tc_params(tc_id)
        tc_cfg['tc_id'] = tc_id
        tc_cfg['congestion_point'] = congestion_point
        
        if breakout_type:
            try:
                pf.change_underlay_dpb(dpb_type=breakout_type)
                verify_base_setup(retry=15)
            except Exception as err:
                if not "already configured" in str(err):
                    raise err
        
        # Find the congestion port from path
        node_intfs = vxlan_obj.get_dut_interfaces(vars)
        underlay_dict = node_intfs[congestion_point]['underlay_dict']
        
        # Find target leaf (next node after spine in path)
        # Path: T1  to  leaf0  to  spine0 (congestion)  to  leaf1 (target)  to  T1
        target_leaf = None
        for traffic_item in original_traffic_items:
            path = traffic_item['path']
            for i in range(len(path) - 1):
                node_name = list(path[i].keys())[0]
                next_node_name = list(path[i + 1].keys())[0]
                if node_name == congestion_point and 'leaf' in next_node_name:
                    target_leaf = next_node_name
                    break
            if target_leaf:
                break
        
        if not target_leaf:
            raise Exception("Could not find target leaf from traffic path")
        
        st.log("Target leaf for spine slice congestion: {}".format(target_leaf))
        
        # Find first port from underlay that connects to target_leaf, then get its slice
        target_leaf_id = vars.dut_ids[target_leaf]
        congestion_point_id = vars.dut_ids[congestion_point]
        prefix = congestion_point_id + target_leaf_id  # e.g., "D1D6" for spine0 to leaf1
        
        # Find first port from underlay that connects to target_leaf
        congestion_port = None
        for port_id, physical_port in underlay_dict.items():
            if port_id.startswith(prefix) and physical_port:
                congestion_port = physical_port
                break
        
        if not congestion_port:
            raise Exception("Could not find any underlay port from {} to {} for {}".format(
                congestion_point, target_leaf, congestion_point))
        
        st.log("Using congestion port: {} on {}".format(congestion_port, congestion_point))

        # Get ALL ports from spine0 to leaf1 directly from underlay_dict
        slice_ports = []
        for port_id, physical_port in underlay_dict.items():
            if port_id.startswith(prefix) and physical_port:
                slice_ports.append(physical_port)
        
        if len(slice_ports) < 2:
            raise Exception("Need at least 2 ports from {} to {} for slice congestion, only found: {}".format(
                congestion_point, target_leaf, slice_ports))
        
        st.log("Found {} ports from {} to {}: {}".format(len(slice_ports), congestion_point, target_leaf, slice_ports))
        
        st.log("Found {} slice ports from {} to {}: {}".format(
            len(slice_ports), congestion_point, target_leaf, slice_ports))
        
        tc_cfg['congestion_slice_ports'] = slice_ports
        tc_cfg['congestion_remote_node'] = target_leaf
        
        st.log("Spine slice congestion: keeping {} ports UP from {} to {}: {}".format(
            len(slice_ports), congestion_point, target_leaf, slice_ports))
        # Find the corresponding remote slice ports on target_leaf
        remote_underlay_dict = node_intfs[target_leaf]['underlay_dict']
        remote_slice_ports = []
        remote_prefix = target_leaf_id + congestion_point_id  # e.g., "D6D1" (reverse direction)
        
        for port_id, physical_port in remote_underlay_dict.items():
            if port_id.startswith(remote_prefix):
                remote_slice_ports.append(physical_port)
        
        st.log("Remote slice ports on {}: {}".format(target_leaf, remote_slice_ports))
        
        # Ensure BGP sessions on all slice ports on BOTH sides
        self.ensure_slice_bgp_sessions(congestion_point, slice_ports)
        self.ensure_slice_bgp_sessions(target_leaf, remote_slice_ports)
        
        # Use original items (don't replicate - causes TGEN duplicate stream issues)
        tc_cfg['traffic_items'] = original_traffic_items
        tc_cfg['slice_multiplier'] = len(slice_ports)
        self.process_traffic_items(tc_cfg)
        
        # Ensure BGP sessions on ingress leafs  to  spine links
        source_leafs = set()
        for traffic_item in original_traffic_items:
            path = traffic_item['path']
            # Find source leaf in the path (before spine)
            for i in range(len(path) - 1):
                node_name = list(path[i].keys())[0]
                next_node_name = list(path[i + 1].keys())[0]
                if 'leaf' in node_name and next_node_name == congestion_point:
                    source_leafs.add(node_name)
                    break
        
        # Ensure BGP on each source_leaf  to  spine
        for src_leaf in source_leafs:
            st.log(f"Ensuring BGP sessions on {src_leaf}  to  {congestion_point} ingress path")
            self.ensure_egress_bgp_sessions(src_leaf, congestion_point)
        
        st.log("Using {} original traffic items for spine slice congestion, will increase bandwidth for {} slice ports".format(
            len(original_traffic_items), len(slice_ports)))
        
        # Calculate bandwidth for congestion
        dut = tc_cfg['dut_list'][0]
        
        # Get interface speeds from the congestion point
        intfs_status = vxlan_obj.get_interfaces_status(congestion_point)
        
        # Also get TGEN interface speed from the source DUT
        dut_intfs_status = vxlan_obj.get_interfaces_status(dut)
        dut_tgen_portid = vxlan_obj.get_peer_port_id(list(node_intfs[dut]['tgen_port_dict'].keys())[0], vars)
        dut_tgen_int = vars[dut_tgen_portid]
        
        for status in dut_intfs_status:
            if status['interface'] == dut_tgen_int:
                tc_cfg['tgen_bw'] = int(status['speed'][:-1])
                break
        
        if not tc_cfg.get('tgen_bw'):
            raise Exception("Could not determine TGEN interface speed")
        
        # Calculate total slice bandwidth
        total_slice_bw = 0
        for physical_port in slice_ports:
            for status in intfs_status:
                if status['interface'] == physical_port:
                    total_slice_bw += int(status['speed'][:-1])
                    break
        
        if total_slice_bw == 0:
            raise Exception("Could not determine slice bandwidth for ports: {}".format(slice_ports))
        
        st.log("Spine slice ({} -> {}) total bandwidth: {} Gbps across {} ports".format(
            congestion_point, target_leaf, total_slice_bw, len(slice_ports)))
        
        # Set congestion_bw for post_congestion_check (in Gbps to match NPU rate check units)
        tc_cfg['congestion_bw'] = total_slice_bw
        
        # Divide bandwidth equally across all streams (Note: actual rate set to 99% in trigger_congestion_spine)
        per_stream_bw = (total_slice_bw * 0.99) / len(tc_cfg['traffic_items'])
        if per_stream_bw > tc_cfg['tgen_bw']:
            per_stream_bw = tc_cfg['tgen_bw'] * 0.99
        
        for traffic_item in tc_cfg['traffic_items']:
            traffic_item['max_bw'] = per_stream_bw
        self.setup_traffic_path_spine(tc_cfg, breakout_type=breakout_type)
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)
        
        if run_pre_congestion_check:
            if self.pre_congestion_check(tc_cfg):
                st.log("Pre-congestion check: PASS")
            else:
                st.banner("Pre-congestion check failed!!!!!!")
        else:
            st.log("Skipping pre-congestion check (run_pre_congestion_check=False)")
        
        # Shutdown all except 1 of leaf2 to spine0 interfaces (for spine congestion only)
        # Store shutdown list for cleanup later
        leaf2_shutdown_interfaces = []
        try:
            if 'leaf2' in source_leafs:
                st.log("Shutting down all except 1 leaf2 to spine0 interface for spine congestion test")
                try:
                    leaf2_underlay_dict = node_intfs['leaf2']['underlay_dict']
                    spine0_id = vars.dut_ids['spine0']
                    leaf2_id = vars.dut_ids['leaf2']
                    prefix = leaf2_id + spine0_id  # e.g., "D7D1" for leaf2 to spine0
                    
                    leaf2_to_spine0_intfs = []
                    for port_id, physical_port in leaf2_underlay_dict.items():
                        if port_id.startswith(prefix) and physical_port:
                            leaf2_to_spine0_intfs.append(physical_port)
                    
                    if len(leaf2_to_spine0_intfs) > 1:
                        # Keep the first interface up, shutdown the rest
                        keep_up = leaf2_to_spine0_intfs[0]
                        shutdown_list = leaf2_to_spine0_intfs[1:]
                        leaf2_shutdown_interfaces = shutdown_list.copy()  # Store for cleanup
                        
                        st.log("Keeping leaf2 to spine0 interface UP: {}".format(keep_up))
                        st.log("Shutting down {} leaf2 to spine0 interfaces: {}".format(
                            len(shutdown_list), shutdown_list))
                        
                        for intf in shutdown_list:
                            st.config('leaf2', "config interface shutdown {}".format(intf))
                            st.log("Shut down leaf2 interface: {}".format(intf))
                        
                        st.wait(1)  # Wait for interfaces to shutdown
                        st.log("Shutdown complete: {} leaf2 to spine0 interfaces shut down, 1 kept up".format(
                            len(shutdown_list)))
                    else:
                        st.log("Only {} leaf2 to spine0 interface found, no shutdown needed".format(
                            len(leaf2_to_spine0_intfs)))
                except Exception as e:
                    st.error("Error shutting down leaf2 to spine0 interfaces: {}".format(str(e)))
                    # Continue anyway - don't fail the test
            
            self.trigger_congestion_spine(tc_cfg)
            
            if self.post_congestion_check_spine(tc_cfg, ecn_mode=ecn_mode):
                vxlan_obj.report_result(True, tc_id, "PFC/VoQ Spine Slice Congestion check PASS")
            else:
                vxlan_obj.report_result(False, tc_id, "Post-congestion check failed")
        finally:
            # Restore all leaf2 to spine0 interfaces that were shut down (cleanup)
            if leaf2_shutdown_interfaces:
                st.log("Restoring {} leaf2 to spine0 interfaces that were shut down for test".format(
                    len(leaf2_shutdown_interfaces)))
                try:
                    for intf in leaf2_shutdown_interfaces:
                        st.config('leaf2', "config interface startup {}".format(intf))
                        st.log("Restored leaf2 interface: {}".format(intf))
                    st.wait(5)  # Wait for interfaces to come back up
                    st.log("Cleanup complete: {} leaf2 to spine0 interfaces restored".format(
                        len(leaf2_shutdown_interfaces)))
                except Exception as e:
                    st.error("Error restoring leaf2 to spine0 interfaces during cleanup: {}".format(str(e)))
                    # Log error but don't fail - cleanup errors shouldn't fail the test

    def setup_traffic_path_spine(self, tc_cfg, breakout_type=None):
        """
        SPINE CONGESTION ONLY: Setup traffic path for spine slice congestion test.
        This is a separate function to avoid affecting ingress/egress leaf tests.
        
        Shutdown logic for spine test:
        - Shut down all leaf0, leaf1, leaf2, leaf3 interfaces to OTHER 3 spines (spine1, spine2, spine3)
        - Keep ALL spine0 interfaces to all leafs UP
        """
        st.log('Pre-test Traffic path Setup (SPINE CONGESTION)')

        # Setup traffic endpoints (same as original)
        idx = 1
        tc_cfg['streams'] = dict()
        for traffic_item in tc_cfg['traffic_items']:
            traffic_endpoints = dict()
            src_info = traffic_item['hops'][0]
            dst_info = traffic_item['hops'][-1]
            
            traffic_endpoints['traffic_item_{}'.format(idx)] = {
                'src_int': src_info['in_port_id'],
                'src_vlan': traffic_item['src_vlan'],
                'dst_int': dst_info['eg_port_id']   ,
                'dst_vlan': traffic_item['dst_vlan'],
            }
        
            # Create Ixia traffic items
            st.log("Creating Traffic stream {}. Enpdoints : {}".format(traffic_item['name'], traffic_endpoints))
    
            queue_val = tc_cfg['traffic_items'][0]['queue']
            if queue_val == '3':
                traffic_pfc_queue_val = 1
            elif queue_val == '4':
                traffic_pfc_queue_val = 2

            if traffic_item['protocol'] == 'ipv4' and queue_val == '3':
                pr_val = 'd'
            if traffic_item['protocol'] == 'ipv4' and queue_val == '4':
                pr_val = '11'
               
            if traffic_item['protocol'] == 'ipv6' and queue_val == '3':
                pr_val = '13'
            if traffic_item['protocol'] == 'ipv6' and queue_val == '4':
                pr_val = '17'
            
            # set rate to 5% of tgen bw initially
            rate_bps = tc_cfg['tgen_bw'] * 1000000000 * (5/100)
            
            # Set frame size to 1500 for slice congestion tests, default 500 otherwise
            if 'slice' in tc_cfg.get('tc_id', ''):
                pkt_size = 1500
            else:
                pkt_size = 500
                
            tc_cfg['streams'][idx] = vxlan_obj.create_traffic_item(
                device_handles = traffic_item['device_handles'],
                endpoints = traffic_endpoints,
                topo_handles = tgen_handles['topo_handles'],
                name_prfx = traffic_item['name'], priority_val=pr_val, pfc_queue_val=traffic_pfc_queue_val,
                transmit_mode = 'continuous', version = traffic_item['protocol'],
                rate_bps=rate_bps, frame_size=pkt_size, bidirectional=int(traffic_item['bidirectional']))[1]
            
            traffic_item['stream_id'] = tc_cfg['streams'][idx]['stream_id']
            
            # Enable UDP destination port randomization for ECMP distribution
            if 'slice' in tc_cfg.get('tc_id', ''):
                st.log("Enabling UDP dest port randomization for stream {} (seed={}) for ECMP".format(
                    traffic_item['name'], idx))
                tg = tgen_handles['tg_handle']
                ixNet = vxlan_obj.get_ixnet()
                streamname = traffic_item['stream_id']
                trafficitem = ixNet.getFilteredList('/traffic', 'trafficItem', '-name', streamname)[0]
                confElement = ixNet.getList(trafficitem, 'configElement')[0]
                
                # Check if UDP stack exists, if not add it
                stackList = ixNet.getList(confElement, 'stack')
                udp_stack = None
                for stack in stackList:
                    if ixNet.getAttribute(stack, '-stackTypeId') == 'udp':
                        udp_stack = stack
                        break
                
                # If no UDP stack, we need to add it after IP layer
                if not udp_stack:
                    if traffic_item['protocol'] == 'ipv4':
                        stackIP = ixNet.getFilteredList(confElement, 'stack', '-stackTypeId', 'ipv4')[0]
                    else:
                        stackIP = ixNet.getFilteredList(confElement, 'stack', '-stackTypeId', 'ipv6')[0]
                    
                    # Get UDP protocol template from root and append it after IP
                    all_templates = ixNet.getList(ixNet.getRoot() + '/traffic', 'protocolTemplate')
                    udp_template = None
                    for template in all_templates:
                        if ixNet.getAttribute(template, '-stackTypeId') == 'udp':
                            udp_template = template
                            break
                    
                    if not udp_template:
                        st.error("Could not find UDP protocol template")
                        raise Exception("UDP protocol template not found")
                    
                    ixNet.execute('appendProtocol', stackIP, udp_template)
                    ixNet.commit()
                    st.log("Added UDP protocol stack to traffic item")
                    
                    # Get the newly added UDP stack
                    stackList = ixNet.getList(confElement, 'stack')
                    for stack in stackList:
                        if ixNet.getAttribute(stack, '-stackTypeId') == 'udp':
                            udp_stack = stack
                            break
                    
                    if not udp_stack:
                        st.error("Failed to add UDP stack to traffic item")
                        raise Exception("UDP stack not found after appendProtocol")
                
                st.log("Configuring UDP ports for stream {} (UDP stack: {})".format(traffic_item['name'], udp_stack))
                
                # Configure UDP destination port with increment pattern for ECMP diversity
                udpDstPort = ixNet.getFilteredList(udp_stack, 'field', '-fieldTypeId', 'udp.header.dstPort')[0]
                ixNet.setAttribute(udpDstPort, '-auto', 'false')
                ixNet.commit()
                
                # Calculate start value based on stream index for diversity (each stream gets different range)
                start_port = 1001 + (idx * 10000)
                ixNet.setAttribute(udpDstPort, '-valueType', 'increment')
                ixNet.setAttribute(udpDstPort, '-startValue', str(start_port))
                ixNet.setAttribute(udpDstPort, '-stepValue', '1')
                ixNet.setAttribute(udpDstPort, '-countValue', '10000')
                ixNet.commit()
                
                # Set UDP source port to fixed value
                udpSrcPort = ixNet.getFilteredList(udp_stack, 'field', '-fieldTypeId', 'udp.header.srcPort')[0]
                ixNet.setAttribute(udpSrcPort, '-auto', 'false')
                ixNet.setAttribute(udpSrcPort, '-singleValue', '1000')
                ixNet.commit()
                
                st.log("Configured UDP for stream {}: dst_port=Inc({}, 1, 10000), src_port=1000".format(
                    traffic_item['name'], start_port))
            
            idx += 1
        
        # SPINE CONGESTION SPECIFIC SHUTDOWN LOGIC
        st.log("SPINE CONGESTION: Shutting down leaf interfaces to non-target spines (spine1, spine2, spine3)")
        dut_interfaces = vxlan_obj.get_dut_interfaces(vars)
        tc_cfg['shut_intf'] = dict()
        
        # Target spine for congestion (spine0)
        target_spine = tc_cfg.get('congestion_point', 'spine0')
        
        # All leafs that need their non-spine0 uplinks shut
        leaf_nodes = ['leaf0', 'leaf1', 'leaf2', 'leaf3']
        
        for node in tc_cfg['dut_list']:
            if node in leaf_nodes:
                # For each leaf: shut down interfaces to spine1, spine2, spine3 (keep spine0 UP)
                all_underlay = list(dut_interfaces[node]['underlay_dict'].values())
                
                # Find interfaces connected to target_spine (spine0) - these stay UP
                target_spine_intfs = []
                try:
                    node_id = vars.dut_ids[node]
                    spine_id = vars.dut_ids[target_spine]
                    prefix = node_id + spine_id  # e.g., "D5D1" for leaf0 to spine0
                    
                    leaf_underlay_dict = dut_interfaces[node]['underlay_dict']
                    for port_id, physical_port in leaf_underlay_dict.items():
                        if port_id.startswith(prefix) and physical_port:
                            target_spine_intfs.append(physical_port)
                    
                    st.log("SPINE CONGESTION: {} interfaces to {} (keeping UP): {}".format(
                        node, target_spine, target_spine_intfs))
                except Exception as e:
                    st.log("Could not determine target_spine interfaces on {}, error: {}".format(node, str(e)))
                
                # Shut down all interfaces EXCEPT those to spine0
                tc_cfg['shut_intf'][node] = [intf for intf in all_underlay if intf not in target_spine_intfs]
                st.log("SPINE CONGESTION: {} shutting down non-spine0 uplinks: {}".format(
                    node, tc_cfg['shut_intf'][node]))
            elif node == target_spine:
                # Spine0: Keep ALL interfaces UP (no shutdowns)
                tc_cfg['shut_intf'][node] = []
                st.log("SPINE CONGESTION: {} is congestion point, keeping ALL interfaces UP".format(node))
            else:
                # Other spines: no shutdowns
                tc_cfg['shut_intf'][node] = []
                st.log("SPINE CONGESTION: {} leaving all interfaces up".format(node))
            
            if tc_cfg['shut_intf'][node]:
                intf_obj.interface_shutdown(dut=node, interfaces=tc_cfg['shut_intf'][node])

