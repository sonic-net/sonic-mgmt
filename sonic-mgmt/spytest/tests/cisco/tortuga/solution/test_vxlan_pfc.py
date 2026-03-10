"""
PFC Port Congestion Tests for VXLAN EVPN Multi-Homing.

What is tested:
    PFC (Priority Flow Control) and ECN behavior under port-level congestion in
    VXLAN EVPN topology. Validates PFC pause generation, VoQ backpressure, and
    ECN marking at egress leaf, spine, and ingress leaf congestion points.
    Covers IPv4/IPv6, L2/L3 traffic, lossless queues 3 and 4, and PFC-only vs
    ECN-only vs normal modes.

Test plan:
    https://cisco-my.sharepoint.com/:x:/r/personal/bhavani_cisco_com/_layouts/15/Doc.aspx?sourcedoc=%7B90D47002-114B-4270-81F5-E8CF3590414B%7D&file=G200-AIML-Solution-testplan.xlsx&wdLOR=cE774C1C2-3963-4848-A637-26D7633BFBE0&fromShare=true&action=default&mobileredirect=true

Link to wiki with topology, details of scenarios being tested, validations and steps to run the test:
    https://ciscoteams.atlassian.net/wiki/spaces/WHITEBOX/pages/902465570/PFC+Automation+Port+and+Slice+Congestion+Testing
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
# Subset: 2 groups of 4; alternating tests use A or B so all 8 are covered across scenarios
_PFC_GROUP_A = [("ipv4", 3, "l2"), ("ipv4", 4, "l3"), ("ipv6", 3, "l2"), ("ipv6", 4, "l3")]
_PFC_GROUP_B = [("ipv4", 3, "l3"), ("ipv4", 4, "l2"), ("ipv6", 3, "l3"), ("ipv6", 4, "l2")]


def pytest_generate_tests(metafunc):
    """Dynamically parametrize TestPortCongestion: PFC_RUN=full for 72, else 36 with A/B alternation."""
    if metafunc.cls is None or metafunc.cls.__name__ != "TestPortCongestion":
        return
    needed = {"protocol", "queue", "traffictype", "breakout_type"}
    if not needed.issubset(set(metafunc.fixturenames)):
        return
    pfc_run = os.environ.get("PFC_RUN", "subset")
    if pfc_run == "full":
        combos = _PFC_FULL_COMBOS
    else:
        # Alternate A/B by test name (deterministic) so all 8 combos covered across the 9 tests
        idx = sum(ord(c) for c in metafunc.function.__name__) % 2
        combos = _PFC_GROUP_A if idx == 0 else _PFC_GROUP_B
    if "egress_leaf" in metafunc.function.__name__:
        bt_list = pfc_dpb_types_egress_leaf_egress_port
    elif "spine" in metafunc.function.__name__:
        bt_list = pfc_dpb_types_spine_egress_port
    else:
        bt_list = pfc_dpb_types_ingress_leaf_egress_port
    argvalues = [(p, q, t, b) for (p, q, t) in combos for b in bt_list]
    metafunc.parametrize("protocol,queue,traffictype,breakout_type", argvalues)


@pytest.fixture(scope="module", autouse=True)
def initialize_variables():
    global vars, nodes, tgen_handles, test_cfg, CONFIGS_FILE, pf

    CONFIGS_FILE = 'vxlan_pfc_input_file.yaml'

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

    # generate vlans on each port
    port_vlan_dict = {}
    for node , ports in l2vni_intf_dict.items():
        node_id = vxlan_obj.get_device_id(node, vars)
        for port in ports:
            if type(port) == dict:
                # port channel type
                peer_port_id = 'PortChannel{}'.format(port['port_channel_num'])
                port = port['name']
            else:
                peer_port_id = vxlan_obj.get_peer_port_id(port, vars)

            port_vlan_dict[port] = list()
            for item in test_cfg[node]['l2vni']:
                for member in item['members']:
                    if node_id+member == peer_port_id or member == peer_port_id:
                        port_vlan_dict[port].append(item['vlan_id'])
    
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


class TestPortCongestion():

    def build_egress_leaf_traffic_items(self, protocol, queue, traffictype):
        q = str(queue)
        return [
            {
                'name': 'PFC_l0_to_l2_1',
                'path': [{'T1': 'P1'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf2': 'P1'}, {'T1': 'P1'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l1_to_l2_2',
                'path': [{'T1': 'P1'}, {'leaf1': 'P1'}, {'spine1': 'P1'},
                        {'leaf2': 'P1'}, {'T1': 'P1'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
        ]

    def build_ingress_leaf_traffic_items(self, protocol, queue, traffictype):
        q = str(queue)
        return [
            {
                'name': 'PFC_l0_to_l2_1',
                'path': [{'T1': 'P1'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf2': 'P1'}, {'T1': 'P1'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
            'name': 'PFC_l0PC_to_l2_2',
            'path': [
                {'T1': 'PortChannel1'}, 
                {'leaf0': 'P1'},
                {'spine0': 'P1'},
                {'leaf2': 'P1'},
                {'T1': 'P1'}           
            ],
            'type': traffictype, 'bidirectional': False, 'protocol': protocol,
            'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
            'queue': q,
        },
            
        ]

    def build_spine_traffic_items(self, protocol, queue, traffictype):
        q = str(queue)
        return [
            {
                'name': 'PFC_l0_to_l2_1',
                'path': [{'T1': 'P1'}, {'leaf0': 'P1'}, {'spine0': 'P1'},
                        {'leaf2': 'P1'}, {'T1': 'P1'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
            {
                'name': 'PFC_l1_to_l2_2',
                'path': [{'T1': 'P1'}, {'leaf1': 'P1'}, {'spine0': 'P1'},
                        {'leaf2': 'P1'}, {'T1': 'P2'}],
                'type': traffictype, 'bidirectional': False, 'protocol': protocol,
                'src_vlan': 2, 'dst_vlan': 2, 'src_tag': True, 'dst_tag': True,
                'queue': q,
            },
        ]

    def test_egress_leaf_egress_port_congestion_pfc_only(self, protocol, queue, traffictype, breakout_type, cleanup_congestion_configs):
        ti = self.build_egress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_congestion_test(
            tc_id='test_egress_leaf_egress_port_congestion_pfc_only',
            banner="TEST: Egress Leaf Egress port congestion",
            traffic_items=ti,
            congestion_point='leaf2',                 
            breakout_type=breakout_type,
            post_check_callable=lambda tc_cfg: self.post_congestion_check(tc_cfg, ecn_mode='pfc_only'),
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )

    def test_spine_egress_port_congestion_pfc_only(self, protocol, queue, traffictype, breakout_type, cleanup_congestion_configs):
        ti = self.build_spine_traffic_items(protocol, queue, traffictype)
        self.run_congestion_test(
            tc_id='test_spine_egress_port_congestion_pfc_only',
            banner="TEST: Spine Egress port congestion",
            traffic_items=ti,
            congestion_point='spine0',                 
            breakout_type=breakout_type,
            post_check_callable=lambda tc_cfg: self.post_congestion_check(tc_cfg, ecn_mode='pfc_only'),
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )

    def test_ingress_leaf_egress_port_congestion_pfc_only(self, protocol, queue, traffictype, breakout_type, cleanup_congestion_configs):
        ti = self.build_ingress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_congestion_test(
            tc_id='test_ingress_leaf_egress_port_congestion_pfc_only',
            banner="TEST: Ingress Leaf Egress port congestion",
            traffic_items=ti,
            congestion_point='leaf0',                 
            breakout_type=breakout_type,
            post_check_callable=lambda tc_cfg: self.post_congestion_check(tc_cfg, ecn_mode='pfc_only'),
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )


    def test_egress_leaf_egress_port_congestion(self, protocol, queue, traffictype, breakout_type, cleanup_congestion_configs):
        ti = self.build_egress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_congestion_test(
            tc_id='test_egress_leaf_egress_port_congestion',
            banner="TEST: Egress Leaf Egress port congestion",
            traffic_items=ti,
            congestion_point='leaf2',                 
            breakout_type=breakout_type,
            post_check_callable=lambda tc_cfg: self.post_congestion_check(tc_cfg, ecn_mode='normal'),
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )

    def test_spine_egress_port_congestion(self, protocol, queue, traffictype, breakout_type, cleanup_congestion_configs):
        ti = self.build_spine_traffic_items(protocol, queue, traffictype)
        self.run_congestion_test(
            tc_id='test_spine_egress_port_congestion',
            banner="TEST: Spine Egress port congestion",
            traffic_items=ti,
            congestion_point='spine0',                 
            breakout_type=breakout_type,
            post_check_callable=lambda tc_cfg: self.post_congestion_check(tc_cfg, ecn_mode='normal'),
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )

    def test_ingress_leaf_egress_port_congestion(self, protocol, queue, traffictype, breakout_type, cleanup_congestion_configs):
        ti = self.build_ingress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_congestion_test(
            tc_id='test_ingress_leaf_egress_port_congestion',
            banner="TEST: Ingress Leaf Egress port congestion",
            traffic_items=ti,
            congestion_point='leaf0',                 
            breakout_type=breakout_type,
            post_check_callable=lambda tc_cfg: self.post_congestion_check(tc_cfg, ecn_mode='normal'),
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )

    def test_egress_leaf_egress_port_congestion_ecn_only(self, protocol, queue, traffictype, breakout_type, cleanup_congestion_configs):
        ti = self.build_egress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_congestion_test(
            tc_id='test_egress_leaf_egress_port_congestion_ecn_only',
            banner="TEST: Egress Leaf Egress port congestion (ECN only)",
            traffic_items=ti,
            congestion_point='leaf2',
            breakout_type=breakout_type,
            post_check_callable=lambda tc_cfg: self.post_congestion_check(tc_cfg, ecn_mode='ecn_only'),
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )

    def test_spine_egress_port_congestion_ecn_only(self, protocol, queue, traffictype, breakout_type, cleanup_congestion_configs):
        ti = self.build_spine_traffic_items(protocol, queue, traffictype)
        self.run_congestion_test(
            tc_id='test_spine_egress_port_congestion_ecn_only',
            banner="TEST: Spine Egress port congestion (ECN only)",
            traffic_items=ti,
            congestion_point='spine0',
            breakout_type=breakout_type,
            post_check_callable=lambda tc_cfg: self.post_congestion_check(tc_cfg, ecn_mode='ecn_only'),
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )

    def test_ingress_leaf_egress_port_congestion_ecn_only(self, protocol, queue, traffictype, breakout_type, cleanup_congestion_configs):
        ti = self.build_ingress_leaf_traffic_items(protocol, queue, traffictype)
        self.run_congestion_test(
            tc_id='test_ingress_leaf_egress_port_congestion_ecn_only',
            banner="TEST: Ingress Leaf Egress port congestion (ECN only)",
            traffic_items=ti,
            congestion_point='leaf0',                 
            breakout_type=breakout_type,
            post_check_callable=lambda tc_cfg: self.post_congestion_check(tc_cfg, ecn_mode='ecn_only'),
            run_pre_congestion_check=(protocol == 'ipv4' and queue == 3 and traffictype == 'l2')
        )


    def run_congestion_test(self, *, tc_id, banner, traffic_items, congestion_point, post_check_callable, breakout_type=None, run_pre_congestion_check=False):
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

        if run_pre_congestion_check:
            if self.pre_congestion_check(tc_cfg):
                st.log("Pre-congestion check : Pass")
            else:
                vxlan_obj.report_result(False, tc_id, "Pre-congestion check failed")
        else:
            st.log("Skipping pre-congestion check (run_pre_congestion_check=False)")

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
            tc_cfg['streams'][idx] = vxlan_obj.create_traffic_item(
                device_handles = traffic_item['device_handles'],
                endpoints = traffic_endpoints,
                topo_handles = tgen_handles['topo_handles'],
                name_prfx = traffic_item['name'], priority_val=pr_val, pfc_queue_val=traffic_pfc_queue_val,
                transmit_mode = 'continuous', version = traffic_item['protocol'],
                rate_bps=rate_bps, bidirectional=int(traffic_item['bidirectional']))[1]
            
            traffic_item['stream_id'] = tc_cfg['streams'][idx]['stream_id']
            idx += 1
        
        st.log("Shutting down other uplinks to force traffic to take congestion path")
        dut_interfaces = vxlan_obj.get_dut_interfaces(vars)
        tc_cfg['shut_intf'] = dict()
        for node in tc_cfg['dut_list']:
            tc_cfg['shut_intf'][node] = list(dut_interfaces[node]['underlay_dict'].values())
            for traffic_item in tc_cfg['traffic_items']:
                for hop in traffic_item['hops']:
                    if node == hop['in_node'] and hop['in_intf'] in tc_cfg['shut_intf'][node]:
                        tc_cfg['shut_intf'][node].remove(hop['in_intf'])
                    if node == hop['eg_node'] and hop['eg_intf'] in tc_cfg['shut_intf'][node]:
                        tc_cfg['shut_intf'][node].remove(hop['eg_intf'])
            
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
        for traffic_item in tc_cfg['traffic_items']:
            st.log("Checking traffic path of traffic item {}".format(traffic_item['name']))
            for hop in traffic_item['hops'][1:]:
                queue_counters = vxlan_obj.get_queue_counters(hop['in_node'], hop['in_intf'])
                queue_name = "UC{}".format(int(traffic_item['queue']))
                if self.check_queue_increased(queue_counters, queue_name):
                    st.log("Pre-congestion queue counters increased on {} {}: Pass".format(hop['in_node'], hop['in_intf']))
                else:
                    st.error("Pre-congestion queue counters did not increase on {} {}: Fail".format(hop['in_node'], hop['in_intf']))
                    ret = False

        # PFC counters should be 0 pre-congestion 
        checked_ints = list()
        for traffic_item in tc_cfg['traffic_items']:
            for hop in traffic_item['hops'][1:]:
                if (hop['in_node'], hop['in_intf']) in checked_ints:
                    if hop['in_node'] == tc_cfg['congestion_point']:
                        break
                    continue
                checked_ints.append((hop['in_node'], hop['in_intf']))
                pfc = vxlan_obj.get_pfc_count(hop['in_node'], hop['in_intf'])
                if self.check_pfc_counters_increased(pfc, hop['in_intf'], direction="tx", queue=traffic_item['queue']):
                    st.error("Pre-congestion PFC counters incremented on {} {}: Fail".format(hop['in_node'], hop['in_intf']))
                    ret = False
                else:
                    st.log("Pre-congestion PFC counters NOT incremented on {} {}: Pass".format(hop['in_node'], hop['in_intf']))
                if hop['in_node'] == tc_cfg['congestion_point']:
                    break

        return ret

    def trigger_congestion(self, tc_cfg):
        st.log("Trigger Congestion")
        st.log('Clearing counters on leaf0, leaf1, leaf2')
        for node in tc_cfg['dut_list']:
            self.clear_all_counters(node)
        st.log("Increasing traffic to trigger congestion")
        tg = tgen_handles['tg_handle'] 
        streams = tc_cfg['traffic_items']
        for stream in streams:
            stream_id = stream['stream_id']
            rate_bps = stream['max_bw'] * 1000000000 
            st.log("Setting stream ID {} rate to {} bps".format(stream_id, rate_bps))
            tg.tg_traffic_config(
                mode="modify",
                stream_id=stream_id,
                rate_bps=rate_bps
            )
        st.wait(1)

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
        
        st.wait(20)
        
        # Verify PFC counters increment/behavior
        checked_ints = list()
        st.log("Checking if PFC counters on interfaces in congestion path have incremented")
        for traffic_item in tc_cfg['traffic_items']:
            #hops_to_check = traffic_item['hops'][pfc_hops_slice]
            # Ensure hops_to_check is iterable
            # if not isinstance(hops_to_check, list):
            #    hops_to_check = [hops_to_check] if hops_to_check else []
            
            for hop in traffic_item['hops']:
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
        tol = expected_bw * 0.005
        st.log('Ingress nodes ({}) Total Rx : {}, Expected Bandwidth: {}, tolerance: {}'.format(checked_nodes, total_rx, expected_bw, tol))
        st.log('Congestion nodes ({}) Tx : {}, Expected Bandwidth: {}, tolerance: {}'.format(tc_cfg['congestion_point'], tx_rate, expected_bw, tol))

        if ecn_mode == 'ecn_only':
            # For egress leaf ECN only, traffic should not be throttled
            if total_rx > expected_bw:
                st.log("Traffic not throttled. Total Rx: {} > Expected Bandwidth: {}: Pass".format(got_rx_rate, expected_bw))
            else:
                st.error("Traffic throttled. Total Rx: {} not > Expected Bandwidth: {}: Fail".format(got_rx_rate, expected_bw))
                ret_val = False
        else:
            # For egress leaf normal/pfc_only, traffic should be throttled
            if (total_rx - expected_bw) <= tol and (tx_rate - expected_bw) <= tol:
                st.log("Traffic throttled. Ingress node {} Total Rx: ~= Expected Bandwidth: {}: " \
                    "and Congestion node {} Tx: ~= Expected Bandwidth: Pass".format(total_rx, expected_bw, tx_rate, expected_bw))
            else:
                st.error("Traffic throttled. Ingress node {} Total Rx: ~= Expected Bandwidth: {}: " \
                    "or Congestion node {} Tx: ~= Expected Bandwidth: Fail".format(total_rx, expected_bw, tx_rate, expected_bw))
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
        st.log("Checking VOQ ECN marking")
        traffic_item = tc_cfg['traffic_items'][0]
        
        for hop in traffic_item['hops']:
            if hop['in_node'] == tc_cfg['congestion_point']:
                break
        
        should_increase_ecn = True
        if not self.check_ecn_counters_increasing(hop['in_node'], hop['in_intf'], traffic_item['queue'], 
                                                   should_increase=should_increase_ecn):
            ret_val = False

        # TOD remove # Clear counters and stop traffic
        #for node in tc_cfg['dut_list']:
        #    self.clear_all_counters(node)

        if ecn_mode != 'ecn_only':
            st.log("Stopping congestion traffic and Checking traffic stats")
            result = vxlan_obj.check_traffic(tc_cfg['streams'], action="stop_check", 
                                    stop_proto_wait=test_cfg['global']['traffic_stop_protocol_sleep'],
                                    start_proto_wait=test_cfg['global']['traffic_start_protocol_sleep'])

            if not result:
                st.error("Traffic check failed in pre-congestion check")
                ret_val = False

        return ret_val

    def clear_all_counters(self, dut):
        vxlan_obj.clear_counters([dut])
        vxlan_obj.clear_queue_counters(dut)
        vxlan_obj.clear_pfc_counters(dut)

    def check_queue_increased(self, queue_counters, queue_name="UC3"):
        """
        Check if counters increased for a given queue.
        Returns True if pkts or bytes > 0, else False.
        """
        for q in queue_counters:
            if q["queue"] == queue_name:
                pkts = int(q.get("pkts", 0))
                bytes_count = int(q.get("bytes", 0))
                if pkts > 0 or bytes_count > 0:
                    st.log("Counters increased for {}: pkts={}, bytes={}".format(
                        queue_name, pkts, bytes_count))
                    return True
                else:
                    st.log("Counters not increased for {}".format(queue_name))
                    return False
        st.log("Queue {} not found in counters".format(queue_name))
        return False

    def check_pfc_counters_increased(self, pfc_counters, port, direction="tx", queue=0):
        """
        Check if PFC counters are non-zero for a given port, direction, and queue.

        Args:
            pfc_counters (dict): Output of get_pfc_count()
            port (str): Port name, e.g. 'Ethernet1_31'
            direction (str): 'tx' or 'rx'
            queue (int): Queue index (0 to 7)

        Returns:
            bool: True if the counter is > 0, else False
        """
        key = "{}_pfc_{}".format(direction, queue)
        if port in pfc_counters and key in pfc_counters[port]:
            val = int(pfc_counters[port][key])
            if val > 0:
                st.log("PFC counters increased on {} {} queue {} : {}".format(
                    port, direction.upper(), queue, val))
                return True
            else:
                st.log("PFC counter is zero on {} {} queue {}".format(
                    port, direction.upper(), queue))
          
                return False
        else:
            st.log("Counter {} not found for port {}".format(key, port))
            return False

    def verify_cgm_flipflop(self, dut, intf, tc, max_rounds=5, checks_per_round=10, interval=1):
        import re

        for round_num in range(1, max_rounds + 1):
            states = []
            for i in range(checks_per_round):
                cmd = "sudo show platform npu rx interface_cgm -t {} -i {}".format(tc, intf)
                cgm = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
                state = re.search(r'\bXon|Xoff\b', cgm)
                got_val = state.group(0) if state else None
                states.append(got_val)
                st.wait(interval)
            st.log("Round {} states observed: {}".format(round_num, states))
            if "Xon" in states and "Xoff" in states:
                st.log("PASS: In round {}, Both Xon and Xoff observed on {} (TC {})".format(round_num, intf, tc))
                return True
            else:
                st.log("Round {}: Only saw {}. retrying...".format(round_num, set(states)))

        st.log("FAIL: Did not observe both Xon and Xoff on {} (TC {}) after {} rounds".format(intf, tc, max_rounds))
        return False

    def check_voq_counters_nonzero(self, voq, dut, intf, stat_key="SAI_QUEUE_STAT_PACKETS"):
        """
        Validate that a specific VOQ stat counter (default: SAI_QUEUE_STAT_PACKETS) is non-zero.
        Logs success or error accordingly.
        """
        pkt_val = 0
        for entry in voq:
            if entry.get("stat_key") == stat_key:
                try:
                    pkt_val = int(entry.get("stat_val", "0"))
                except ValueError:
                    pkt_val = 0
                break

        if pkt_val == 0:
            st.error("VOQ counters did not increase : Fail, {} = 0 for {} {}".format(stat_key, dut, intf))
            return False
        else:
            st.log(" Got {} non-zero ({}) for {} {}".format(stat_key, pkt_val, dut, intf))
            return True
    
    def check_ecn_counters_increasing(self, in_node, in_intf, queue, *, wait_sec=2, should_increase=True):
        voq_queue_counters1 = vxlan_obj.get_voq_queue_counters(in_node, in_intf, queue)
        ecn_val1 = next((int(e['stat_val']) for e in voq_queue_counters1 if e.get('stat_key') == 'SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'), 0)
        st.wait(wait_sec)
        voq_queue_counters2 = vxlan_obj.get_voq_queue_counters(in_node, in_intf, queue)
        ecn_val2 = next((int(e['stat_val']) for e in voq_queue_counters2 if e.get('stat_key') == 'SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS'), 0)

        st.log('ECN Marked packet count : Sample1: {} :: Sample2: {}'.format(ecn_val1, ecn_val2))
        if should_increase:
            if ecn_val2 > ecn_val1:
                st.log("ECN markers increasing : Pass")
                return True
            else:
                st.error("ECN markers NOT increasing: Fail")
                return False
        else:
            if ecn_val2 == ecn_val1:
                st.log("ECN markers NOT increasing: Pass")
                return True
            else:
                st.error("ECN markers increasing: Fail")
                return False

    @pytest.fixture
    def cleanup_congestion_configs(self):
        global stream_handles
        yield
        tc_id = test_cfg['tc_id'] 
        tc_cfg = vxlan_obj.get_tc_params(tc_id) 
        st.log("Unshut uplink interface shut down to force congestion")
        if tc_cfg.get('shut_intf'):
            for node in tc_cfg['dut_list']:
                intf_obj.interface_noshutdown(dut=node, interfaces=tc_cfg['shut_intf'][node])

        streams_info = {k: v for k, v in tc_cfg['streams'].items() if isinstance(k, int) and isinstance(v, dict)and 'stream_id' in v and 'tg_handle' in v}
        vxlan_obj.check_traffic(streams_info, regenerate_traffic_items=False, action='stop', stop_start_protocols=True)     
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

        st.wait(5)
