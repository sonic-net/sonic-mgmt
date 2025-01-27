import os
import tortuga_common_utils as common_obj
import yaml
import pytest
from collections import OrderedDict
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import time
import evpn_mh_utils as evpn_mh_obj

ESI1 = '03:00:44:33:22:11:00:00:00:02'
EXPECTED_L3VNI = '5030'
EXPECTED_L2VNI = '5010'
## config: eBGP + ES
##  Topology : 1x Spine + 3 Leafs
##  SD1 -- Spine0  - D1
##  SD2 -- Leaf0   - D2
##  SD3 -- Leaf1   - D3
##  SD4 -- Leaf2   - D4

data = SpyTestDict()
data.config_vrfs = []
CONFIGS_FILE = 'evpn_mh_v6_config.yaml'
LEAF0_VXLAN_IP = 'fd27::233:d0c6:fefb'
LEAF1_VXLAN_IP = 'fd27::2dc:c1c9:e17c'
LEAF2_VXLAN_IP = 'fd27::2d9:76fd:4c43'

SEQ_IDS = OrderedDict([
    ('LEAF0', {'local' : 0, 'remote' : 0}),
    ('LEAF1', {'local' : 0, 'remote' : 0}),
    ('LEAF2', {'local' : 0, 'remote' : 0})
])

def update_sequence_ids(node_names):
    global SEQ_IDS
    # Calculate the maximum sequence ID for the specified nodes
    max_seq_id = max(max(SEQ_IDS[node]['local'], SEQ_IDS[node]['remote']) for node in node_names)
    # New sequence ID to be used
    new_seq_id = max_seq_id + 1
    # Update the sequence IDs
    for node in SEQ_IDS:
        if node in node_names:
            # Update only the local sequence ID to new_seq_id
            SEQ_IDS[node]['local'] = new_seq_id
        else:
            # Update only the remote sequence ID to new_seq_id
            SEQ_IDS[node]['remote'] = new_seq_id
    # Return the updated sequence IDs in the format 'local/remote'
    updated_seq_ids = [str(SEQ_IDS[node]['local'])+'/'+str(SEQ_IDS[node]['remote']) for node in SEQ_IDS]
    return updated_seq_ids

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    vars = st.get_testbed_vars()
    ### Check dut is HW or SIM ###
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])

    if  dut_type == "sim":
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "1000"
        ### Using lower line rate for SIM tgen ###
        data.rate_percent = "0.01"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "100"
    else:
        data.mode ="create"
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "2000"
        data.rate_percent = "10"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "1000"
    yield

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    domain = ''
    if config_domain == 'bgp' or config_domain == 'pre-sonic-bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            common_obj.config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            common_obj.config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.banner(msg)
    st.report_fail('test_case_failed', dut)

def router_preconfig_cleanup():
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())

@pytest.fixture(scope="function", autouse=True)
def check_cores():
    for dut in st.get_dut_names():
        st.show(dut, 'ls -l /var/core/', skip_tmpl=True)
    yield check_cores
    for dut in st.get_dut_names():
        st.show(dut, 'ls -l /var/core/', skip_tmpl=True)

#Maintained as a module level fixture since we need configs for all testcases
@pytest.fixture(scope="module", autouse=True)
def vxlan_config_hooks():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    evpn_mh_obj.change_fdb_ageout("6000")

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'pre-sonic-bgp')
            st.wait(2)
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    yield vxlan_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
            st.wait(2)
            config_static(node, 'pre-sonic-bgp', add=False)
        evpn_mh_obj.change_fdb_ageout("600")

    for vrf in data.config_vrfs:
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)
    data.config_vrfs = []

    vxlan_obj.remove_temp_config(updated_config_file)

#Maintained as a module level fixture since we need to ping and send traffic in each testcase
@pytest.fixture(scope="module", autouse=True)
def traffic_setup(vxlan_config_hooks):
    global leaf0_vrf_prefix
    leaf0_vrf_prefix = "10.212.10.0"
    global leaf1_vrf_prefix
    leaf1_vrf_prefix = "10.212.10.0"
    global leaf2_vrf_prefix
    leaf2_vrf_prefix = "10.212.20.0"
    data.d2t1_ip_addr = "10.212.10.10"		#Host1 GW
    data.t1d2p1_ip_addr = "10.212.10.1"		#Host1 IP
    data.t1d2p1_mac_addr = "00:00:00:00:00:01"	#Host1 Mac
    data.lag_ip = "10.212.10.2"			#Lag IP
    data.lag_gateway_ip = "10.212.10.10"	#Lag GW
    data.lag_mac = "00:00:00:00:00:02"		#Lag Mac
    data.t1d3p2_ip_addr = "10.212.10.5"        #Host5 IP
    data.t1d3p2_mac_addr = "00:00:00:00:01:05" #Host5 Mac
    data.t1d4p1_ip_addr = "10.212.10.3"		#Host3 IP
    data.t1d4p1_mac_addr = "00:00:00:00:02:03"	#Host3 Mac
    data.d4t1_ip_addr = "10.212.20.10"		#Host3 GW
    data.t1d4p2_ip_addr = "10.212.20.1"		#Host4 IP
    data.t1d4p2_mac_addr = "00:00:00:00:02:04"	#Host4 Mac
    global lag_ports
    lag_ports = ["T1D2P2", "T1D3P1"]
    global lag_name
    lag_name = "LAG1"
    global int_dict
    int_dict = {"T1D2P1": {"host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr},
                "T1D3P2": {"host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr},
                "T1D4P1": {"host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr},
                "T1D4P2": {"host_ip": data.t1d4p2_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p2_mac_addr}}
    global handles
    handles = vxlan_obj.config_lag_interface(lag_name, lag_ports, data.lag_ip, data.lag_gateway_ip, data.lag_mac)
    handles.update(vxlan_obj.config_tgen_interface(int_dict))
    int_dict.update({lag_name: {"host_ip": data.lag_ip, "gateway": data.lag_gateway_ip, "mac" : data.lag_mac}})
    st.log("\nHandles created: {}".format(handles))
    global port_name_map
    port_name_map  = {"H1": "T1D2P1", "H2": lag_name, "H3": "T1D4P1", "H4": "T1D4P2", "H5": "T1D3P2"}

#This traffic setup performs the ping test
def traffic_item_setup(stream_list):
    streams = vxlan_obj.config_traffic_item(stream_list, handles, int_dict, data, ping=True)
    return streams

def l3_traffic_test(stream_list, del_stream=True):
    st.banner("Start to test VxLAN L3  with ping and traffic")
    ## Verify Vtep state
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP,"LEAF2_VXLAN_IP":LEAF2_VXLAN_IP})
    streams = traffic_item_setup(stream_list)
    st.log("Ping passed, sending traffic now")
    vxlan_obj.clear_counters()
    result = vxlan_obj.check_traffic(streams)
    if del_stream:
        vxlan_obj.reset_traffic(streams)
    return result

def clear_arp():
    for dut in st.get_dut_names():
        if "leaf" in dut:
            st.show(dut, 'sonic-clear arp', skip_tmpl=True)

def get_cli_out():
    cmds = ["show vxlan interface", "show mac", "show arp", "show interface counters", "show vxlan counters", "show evpn es", "ip nexthop"]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            for item in cmds:
                output = st.show(dut, item, skip_tmpl=True)
                st.log(output)

def BUM_traffic_test(stream, src_port, traffic_type, dst_port="T1D4P1", reset=True, ignore_results=False):
    flag = False
    vxlan_obj.clear_counters()
    get_cli_out()
    stream_id = vxlan_obj.create_raw_traffic_stream(handles[src_port], handles[dst_port], stream, "raw", data, traffic_type)
    flag = vxlan_obj.send_raw_traffic_stream(handles[src_port], stream_id, reset)
    if not ignore_results:
        if flag:
            st.banner("{} traffic test passed".format(traffic_type))
            flag = True
        else:
            st.banner("{} traffic test failed".format(traffic_type))
            flag = False
    return flag

######################################################################
# Test Basic Config
######################################################################
def test_evpn_mh_basic_config():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    try:
        # Start Verification
        vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0', EXPECTED_L3VNI)
        vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1', EXPECTED_L3VNI)
        vxlan_obj.verify_bgp(nodes, leaf2_vrf_prefix, 'leaf0', EXPECTED_L3VNI)
        st.report_pass('test_case_passed')
    except Exception as e:
        report_fail("", msg=e)

######################################################################
# Test Ethernet Segment
######################################################################
# Verify ES is peering between T1, T2  
def test_es_peering():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    
    if not evpn_mh_obj.es_peering(nodes['leaf0'], LEAF1_VXLAN_IP, ESI1):
        report_fail(nodes['leaf0'], 'ES is not peering between T1 and T2')
    st.report_pass('test_case_passed')

# Verify one peer is DF and other NDF           
def test_df_selection():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    
    leaf0_idDF = evpn_mh_obj.isDF(nodes['leaf0'], ESI1)
    leaf1_isDF = evpn_mh_obj.isDF(nodes['leaf1'], ESI1)
     
    # only one of leaf0 and leaf1 can be DF
    if not (leaf0_idDF ^ leaf1_isDF):
        report_fail(nodes['leaf0'], 'DF is not successly selected for ES1')
    else:
        st.report_pass('test_case_passed')

# On T3, verify ES points to T1, T2 as remote          
def test_remote_es():
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    
    cmd = 'show evpn es'
    cmd_output = st.vtysh_show(nodes['leaf2'], cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(nodes['leaf2'], cmd, cmd_output, 'show_evpn_es.tmpl') 
    
    for es in parsed_output:
        if es['esi'] == ESI1:
            if 'R' in es['type']:
                missing_vtep = False
                fail_msg = ''
                if LEAF0_VXLAN_IP not in es['vteps'].split(','):
                    missing_vtep = True
                    fail_msg += 'Missing LEAF0_VXLAN_IP \n'
                if LEAF1_VXLAN_IP not in es['vteps'].split(','):
                    missing_vtep = True
                    fail_msg += 'Missing LEAF1_VXLAN_IP'
                if not missing_vtep:
                    st.report_pass('test_case_passed')
                else:
                    report_fail(nodes['leaf2'], fail_msg)
            else:
                report_fail(nodes['leaf2'], 'ES1 is not shown as remote')
        else:
            report_fail(nodes['leaf2'], 'ES1 does not show')
            
######################################################################
# Broadcast Remote Testing
######################################################################
# Verify broadcast traffic sent from H3 is getting dropped by NDF
def test_remote_broadcast_traffic():
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    
    # 1 Verify DF/NDF
    df_node, ndf_node = evpn_mh_obj.get_df_ndf_node(nodes['leaf0'], nodes['leaf1'], ESI1)
    if not df_node:
        report_fail(nodes['leaf0'], "Incorrect DF/NDF selection")
        
    # 2 Verify broadcast traffic is drop in NDF 

    # 2.1 record initial state
    cmd_intf = 'show interface counters'
    if df_node == nodes['leaf0']:
        df_downlink = vars.D2T1P2
        ndf_downlink = vars.D3T1P1
    else:
        df_downlink = vars.D3T1P1
        ndf_downlink = vars.D2T1P2
              
    # 2.2 send L2 broadcast traffic from H3
    st.log("sending broacast traffic from H3")
    stream = {"src_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr },
              "dst_endpoint" : {"port" : "T1D2P1","host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr }}  ##in bum traffic, dst_endpoint dest doesn't matter
    BUM_traffic_test(stream, "T1D4P1", "broadcast", "T1D2P1")
    # 2.3 record current state after traffic sent
    df_downlink_curr = vxlan_obj.get_counters(node = df_node,cmd = cmd_intf, target_iface = df_downlink, r_t_key = 'tx_ok')
    st.log("\ndf_downlink_curr is {}".format(df_downlink_curr))
    
    ndf_downlink_curr = vxlan_obj.get_counters(node = ndf_node,cmd = cmd_intf, target_iface = ndf_downlink, r_t_key = 'tx_ok')
    st.log("\nndf_downlink_curr is {}".format(ndf_downlink_curr))
    
    # 3 analyze result 
    if not (df_downlink_curr <= 1.1*int(data.pkts_per_burst) and 
            df_downlink_curr >= 0.98*int(data.pkts_per_burst) and
            ndf_downlink_curr <= 0.1 * int(data.pkts_per_burst)):
        report_fail(ndf_node, "Broadcast traffic not dropped by NDF")
    
    else:
        st.report_pass('test_case_passed')

######################################################################
# Test Inter-Subnet Ping
###################################################################### 
def test_inter_subnet_ping():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    try:
        get_cli_out()

        #ping and unicast traffic from H1 to H4
        result = l3_traffic_test([("T1D2P1","T1D4P2")])                # H1 -> H4
        if not result:
            report_fail(nodes['leaf0'], "ping and traffic from single homed host to different subnet host failed with unicast traffic")

        #Check traffic is going over vxlan
        leaf0_evpn_int_counters = vxlan_obj.get_counters(nodes['leaf0'], cmd = 'show vxlan counters', target_iface = 'EVPN_{}'.format(LEAF2_VXLAN_IP), r_t_key = 'tx_pkts')
        st.log("\nTX counters on leaf0 EVPN connected interface to H1 is {}".format(leaf0_evpn_int_counters))

        leaf2_evpn_int_counters = vxlan_obj.get_counters(nodes['leaf2'], cmd = 'show vxlan counters', target_iface = 'EVPN_{}'.format(LEAF0_VXLAN_IP))
        st.log("\nRX counters on leaf2 EVPN connected interface to H4 is {}".format(leaf2_evpn_int_counters))

        if not (leaf0_evpn_int_counters >= 0.98*int(data.pkts_per_burst) and
                leaf0_evpn_int_counters <= 1.2*int(data.pkts_per_burst) and
                leaf2_evpn_int_counters >= 0.98*int(data.pkts_per_burst) and
                leaf2_evpn_int_counters <= 1.2*int(data.pkts_per_burst)):
            report_fail(nodes['leaf0'], "Unicast traffic going from H1 to H4 not taking evpn interface")

        get_cli_out()

        #ping and unicast traffic from H2 to H4
        result = l3_traffic_test([(lag_name,"T1D4P2")])                # H2 -> H4
        if not result:
            report_fail(nodes['leaf0'], "traffic from multihomed host to different subnet host failed with unicast traffic")

        #Check traffic is going over vxlan
        leaf1_evpn_int_counters = vxlan_obj.get_counters(nodes['leaf1'], cmd = 'show vxlan counters', target_iface = 'EVPN_{}'.format(LEAF2_VXLAN_IP), r_t_key = 'tx_pkts')
        st.log("\nTX counters on leaf1 EVPN connected interface to H2 is {}".format(leaf1_evpn_int_counters))

        leaf2_evpn_int_counters = vxlan_obj.get_counters(nodes['leaf2'], cmd = 'show vxlan counters', target_iface = 'EVPN_{}'.format(LEAF1_VXLAN_IP))
        st.log("\nRX counters on leaf2 EVPN connected interface to H4 is {}".format(leaf2_evpn_int_counters))

        if not (leaf1_evpn_int_counters >= 0.98*int(data.pkts_per_burst) and
                leaf1_evpn_int_counters <= 1.2*int(data.pkts_per_burst) and
                leaf2_evpn_int_counters >= 0.98*int(data.pkts_per_burst) and
                leaf2_evpn_int_counters <= 1.2*int(data.pkts_per_burst)):
            report_fail(nodes['leaf1'], "Unicast traffic going from H2 to H4 not taking evpn interface")

        #Verify RT-5 with subnet are exchanged
        verify_vrf_route_l3vni(nodes, leaf2_vrf_prefix, 'leaf0', 'Vrf01')
        verify_vrf_route_l3vni(nodes, leaf2_vrf_prefix, 'leaf1', 'Vrf01')
        verify_ip_route_multihomed_host(nodes, leaf2_vrf_prefix, 'leaf2', 'Vrf01')
        leaf0_arp = verify_arp(nodes, data.lag_ip, 'leaf0')
        leaf1_arp  = verify_arp(nodes, data.lag_ip, 'leaf1')
        if not leaf0_arp:
            if not leaf1_arp:
                report_fail("", 'verify_arp testcase failed for {}'.format(data.lag_ip))
        #Verify H2 IP in APP_DB on T1
        verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf0', "Vlan10:"+data.lag_ip)
        #Verify H2 IP in APP_DB on T2
        verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf1', "Vlan10:"+data.lag_ip)
        #Verify H2 IP in APP_DB on T3
        verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf2', "Vrf01:"+data.lag_ip)
        #Verify H4 IP in ASIC_DB on T1
        verify_sonic_asic_db_for_pfx(nodes, data.t1d4p2_ip_addr, 'leaf0', LEAF2_VXLAN_IP)
        #Verify H4 IP in ASIC_DB on T2
        verify_sonic_asic_db_for_pfx(nodes, data.t1d4p2_ip_addr, 'leaf1', LEAF2_VXLAN_IP)
        #Verify H2 IP in ASIC_DB on T3
        verify_sonic_asic_db_for_pfx(nodes, data.lag_ip, 'leaf2')
        #Verify H2 IP in ASIC_DB on T1 and T2
        verify_sonic_asic_db_for_neighbor_pfx(nodes, data.lag_ip, 'leaf0', LEAF2_VXLAN_IP)
        verify_sonic_asic_db_for_neighbor_pfx(nodes, data.lag_ip, 'leaf1', LEAF2_VXLAN_IP)
        #Verify H2 MAC is learn locally
        if not verify_mac(nodes, data.lag_mac, 'leaf0'):
            report_fail(nodes['leaf0'], 'verify_mac testcase failed for {} on node leaf0'.format(data.lag_mac))
        if not verify_mac(nodes, data.lag_mac, 'leaf1'):
            report_fail(nodes['leaf1'], 'verify_mac testcase failed for {} on node leaf1'.format(data.lag_mac))
        #Veify H2 is not learned locally to leaf2
        if verify_mac(nodes, data.lag_mac, 'leaf2'):
            report_fail(nodes['leaf2'], 'verify_mac {} is present on node leaf2'.format(data.lag_mac))
        st.report_pass('test_case_passed')

    except Exception as e:
        report_fail("", msg=e)

######################################################################
# Test Intra-Subnet Ping
######################################################################        
def test_intra_subnet_ping():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    try:
        result = l3_traffic_test([("T1D2P1",lag_name)])        # H1 -> H2
        if not result:
            report_fail("test_case_failed", "test_intra_subnet_ping failed with unicast traffic")

        leaf0_local_int_counters = vxlan_obj.get_counters(nodes['leaf0'], cmd = "show interface counters", target_iface = vars.D2T1P2, r_t_key = 'tx_ok')
        st.log("\nTX counters on locally connected interface to H2 is {}".format(leaf0_local_int_counters))

        leaf1_int_counters = vxlan_obj.get_counters(nodes['leaf1'], cmd = "show interface counters", target_iface = vars.D3T1P1, r_t_key = 'tx_ok')
        st.log("\nTX counters on leaf1 connected interface to H2 is {}".format(leaf1_int_counters))

        if not (leaf0_local_int_counters >= 0.98*int(data.pkts_per_burst) and 
                leaf0_local_int_counters <= 1.1*int(data.pkts_per_burst) and
                (leaf1_int_counters <= 0.1 * int(data.pkts_per_burst))):
            report_fail(nodes['leaf1'], "Unicast traffic going from H1 to H2 not taking local interface")

        st.log("\nsending unknownunicast traffic from H2 \n")
        stream = {"src_endpoint": {"port" : lag_name, "host_ip": data.lag_ip, "gateway": data.lag_gateway_ip, "mac" : data.lag_mac },
                  "dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr }}
        st.wait(10)
        result = BUM_traffic_test(stream, lag_name, "unknownunicast", "T1D4P1")
        if not result:
            report_fail(nodes['leaf1'], "test_intra_subnet_ping testcase failed with Unknown Unicast traffic sent from H2")
        intf_cmd = 'show interface counters'
        diff_vlan_counters = vxlan_obj.get_counters(nodes['leaf2'], cmd = intf_cmd, target_iface = vars.D4T1P2, r_t_key = 'tx_ok')
        st.log("\nTX counters on interface {} belonging to different vlan is {}".format(vars.D4T1P2, diff_vlan_counters))

        if not (diff_vlan_counters <= 0.1 * int(data.pkts_per_burst)):
            report_fail(nodes['leaf2'], "BUM traffic getting flooded on different vlan")

        st.log("\nsending BUM traffic from H1 \n")
        stream = {"src_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr },
                  "dst_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr }}
        result = BUM_traffic_test(stream, "T1D2P1", "unknownunicast")
        if not result:
            report_fail("test_case_failed", "test_intra_subnet_ping failed with unknown unicast traffic")
        result = BUM_traffic_test(stream, "T1D2P1", "broadcast")
        if not result:
            report_fail("test_case_failed", "test_intra_subnet_ping failed with broadcast traffic")
        #arp_leaf0 = verify_arp(nodes, data.lag_ip, 'leaf0')
        #arp_leaf1 = verify_arp(nodes, data.lag_ip, 'leaf1')
        #if not arp_leaf0:
            #if not arp_leaf1:
                #report_fail("test_case_failed", 'verify_arp testcase failed for {}'.format(data.lag_ip))
        #Verify H2 IP in APP_DB on T1, T2 and T3
        verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf0', "Vlan10:"+data.lag_ip)
        verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf1', "Vlan10:"+data.lag_ip)
        verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf2', "Vrf01:"+data.lag_ip)
        #Verify H2 IP in ASIC_DB on T1 and T2
        verify_sonic_asic_db_for_neighbor_pfx(nodes, data.lag_ip, 'leaf0', LEAF2_VXLAN_IP)
        verify_sonic_asic_db_for_neighbor_pfx(nodes, data.lag_ip, 'leaf1', LEAF2_VXLAN_IP)
        #Verify H2 adjacency is learn locally 
        is_nhg_installed(nodes)
        if not verify_mac(nodes, data.lag_mac, 'leaf0'):
            report_fail(nodes['leaf0'], 'verify_mac testcase failed for {} on node leaf0'.format(data.lag_mac))
        if not verify_mac(nodes, data.lag_mac, 'leaf1'):
            report_fail(nodes['leaf1'], 'verify_mac testcase failed for {} on node leaf1'.format(data.lag_mac))
        st.report_pass('test_case_passed')

    except Exception as e:
        report_fail("", msg=e)

def verify_mac(nodes, host_mac, src_vtep):
    output = st.show(nodes[src_vtep], 'show mac -a {}'.format(host_mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'show mac', output, 'show_mac.tmpl')
    st.log(parsed)
    if len(parsed) == 1:        #parsed would contain minimum of 1 entry because of total entries field in show mac o/p
        return False
    return True

def verify_arp(nodes, host_ip, src_vtep):
    output = st.show(nodes[src_vtep], 'show arp', skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'show arp', output, 'show_arp.tmpl')
    st.log(parsed)
    if len(parsed) == 0:
        st.log("empty arp output")
        return False

    for path in parsed:
        if path['address'] == host_ip:
            st.log("Host entry present on {}".format(src_vtep))
            return True
    return False
     
def verify_sonic_asic_db_for_neighbor_pfx(nodes, prefix_ip, src_vtep, dst_vtep = None):
    output = st.show(nodes[src_vtep], 'sonic-db-dump -n ASIC_DB -k *{}* -y'.format(prefix_ip), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'sonic-db-dump -n ASIC_DB -k *{}* -y'.format(prefix_ip), output, 'show_asic_db.tmpl')
    if len(parsed) == 0:
        st.log("ERROR empty output")
        report_fail(nodes[src_vtep], "{} neighbor entry missing in ASIC DB on {}".format(prefix_ip, src_vtep))
    st.log(parsed)
    for path in parsed:
        if path['ip_address'].split("/")[0] == prefix_ip:
            return
    report_fail(nodes[src_vtep], "{} neighbor entry missing in ASIC DB on {}".format(prefix_ip, src_vtep))
   
def verify_sonic_asic_db_for_pfx(nodes, prefix_ip, src_vtep, dst_vtep = None):
    output = st.show(nodes[src_vtep], 'sonic-db-dump -n ASIC_DB -k *{}* -y'.format(prefix_ip), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'sonic-db-dump -n ASIC_DB -k *{}* -y'.format(prefix_ip), output, 'show_asic_db.tmpl')
    if len(parsed) == 0:
        st.log("ERROR empty output")
        report_fail(nodes[src_vtep], "verify_sonic_asic_db_for_pfx {} not found in asic db on {}".format(prefix_ip, src_vtep))
    st.log(parsed)
    for path in parsed:
        if path['ip_address'].split("/")[0] == prefix_ip:
            output = st.show(nodes[src_vtep], 'sonic-db-dump -n ASIC_DB -k *{}* -y'.format(path['nexthopid']), skip_tmpl=True, skip_error_check=True)
            parsed = st.parse_show(nodes[src_vtep], 'sonic-db-dump -n ASIC_DB -k *{}* -y'.format(path['nexthopid']), output, 'show_asic_db.tmpl')
            if len(parsed) == 0:
                st.log("ERROR nexthopid not found in asic db")
            for path in parsed:
                if dst_vtep and path['nexthopip'] == dst_vtep:
                    st.log("Testcase passed")
                    return
                elif dst_vtep is None:
                    if path['attr_type'] == "SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_UNORDERED_ECMP":
                        st.log("Testcase passed")
                        return
    report_fail(nodes[src_vtep], "verify_sonic_asic_db_for_pfx incorrect details found in asic_db for {} on {}".format(prefix_ip, src_vtep))

def verify_sonic_app_db_for_pfx(nodes, prefix_ip, src_vtep, match_string ):
    output = st.show(nodes[src_vtep], 'sonic-db-dump -n APPL_DB -k *{}* -y'.format(match_string), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'sonic-db-dump -n APPL_DB -k *{}* -y'.format(match_string), output, 'show_app_db_route_table.tmpl')
    if len(parsed) == 0:
        st.log("ERROR empty output")
    for path in parsed:
        if path['ip_address'] == prefix_ip:
            return
    report_fail(nodes[src_vtep], 'verify_sonic_app_db_for_pfx testcase failed for {} on node {}'.format(prefix_ip, src_vtep))

def verify_ip_route_multihomed_host(nodes, prefix_ip, src_vtep, vrf):
    output = st.show(nodes[src_vtep], 'show ip route vrf {}'.format(vrf), type='vtysh', skip_tmpl=True, skip_error_check=True)

    parsed = st.parse_show(nodes[src_vtep], 'show ip route vrf {}'.format(vrf),
                             output, 'show_ip_route_mh.tmpl')

    if len(parsed) == 0:
        report_fail(nodes[src_vtep], msg='Found no routes in vrf {}'.format(vrf))
    for path in parsed:
        if path['type'] == 'B' and path['ip_address'] == "10.212.10.2/32":
            st.log(path['nexthop'])
            if path['nexthop'] == ['fd27::233:d0c6:fefb','fd27::2dc:c1c9:e17c']:
                return
    st.log("{} not installed as ECMP in FRR on {}".format(prefix_ip, src_vtep))
    report_fail(nodes[src_vtep], "ecmp not installed for {} on {}".format(prefix_ip, nodes[src_vtep]))

def verify_vrf_route_l3vni(nodes, prefix_ip, src_vtep, vrf):
    output = st.show(nodes[src_vtep], 'show ip route vrf {}'.format(vrf), type='vtysh', skip_tmpl=True, skip_error_check=True)

    parsed = st.parse_show(nodes[src_vtep], 'show ip route vrf {}'.format(vrf),
                             output, 'show_ip_route_mh.tmpl')

    if len(parsed) == 0:
        report_fail(nodes[src_vtep], msg='Found no routes in vrf {}'.format(vrf))
    for path in parsed:
        if path['type'] == 'B' and path['ip_address'] == "10.212.20.0/24" and LEAF2_VXLAN_IP in path['nexthop']:
            return
    report_fail(nodes[src_vtep], "Incorrect entry found for {} in show ip route".format(prefix_ip)) 

######################################################################
# Test Route Type 2 Proxy
######################################################################
#Verify T2 regenerate RT-2 as proxy
# TC could fail until MIGSOFTWAR-17150 is fixed
def test_rt2_proxy():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    cmd = 'show bgp l2vpn evpn route type 2'

    cmd_output_leaf1 = st.vtysh_show(nodes['leaf1'], cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output_leaf1 = st.parse_show(nodes['leaf1'], cmd, cmd_output_leaf1, 'show_bgp_l2vpn_evpn_route_type_2.tmpl')

    cmd_output_leaf2 = st.vtysh_show(nodes['leaf2'], cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output_leaf2 = st.parse_show(nodes['leaf2'], cmd, cmd_output_leaf2, 'show_bgp_l2vpn_evpn_route_type_2.tmpl')

    # Validate Leaf1 regenerates RT-2 as proxy
    leaf0_proxy = False
    leaf1_proxy = False
    leaf0_learned = False
    leaf1_learned = False

    for route in parsed_output_leaf1:
        if route['route_distinguisher'] == '100.100.100.1:2' and route['ip'] == data.lag_ip:
            leaf0_learned = True
            if route['nd_proxy'] == 'ND:Proxy':
                leaf0_proxy = True
        if route['route_distinguisher'] == '100.100.100.2:2' and route['ip'] == data.lag_ip:
            leaf1_learned = True
            if route['nd_proxy'] == 'ND:Proxy':
                leaf1_proxy = True

    if not leaf0_learned:
        report_fail(nodes['leaf0'], 'leaf0 did not learn ip address of H2')

    if not leaf1_learned:
        report_fail(nodes['leaf1'], 'leaf1 did not learn ip address of H2')

    #only one of leaf0 and leaf1 can have ND_Proxy flag
    if not leaf0_proxy ^ leaf1_proxy:
        report_fail(nodes['leaf1'], 'RT2 proxy is not regenerated')

    # Validate ECMP on leaf2
    leaf0_path_seen = False
    leaf1_path_seen = False

    for route in parsed_output_leaf2:
        if route['route_distinguisher'] == '100.100.100.1:2' and route['ip'] == data.lag_ip:
            leaf0_path_seen = True
        if route['route_distinguisher'] == '100.100.100.2:2' and route['ip'] == data.lag_ip:
            leaf1_path_seen = True

    if not (leaf0_path_seen and leaf1_path_seen):
        report_fail(nodes['leaf2'], 'No proper ECMP is shown on Leaf2')
    else:
        st.report_pass('test_case_passed')

######################################################################
# Multicast Remote Testing
###################################################################### 
# Verify multicast traffic sent from H3 is getting dropped by NDF
def test_remote_multicast_traffic():
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    
    # 1 Verify DF/NDF
    df_node, ndf_node = evpn_mh_obj.get_df_ndf_node(nodes['leaf0'], nodes['leaf1'], ESI1)
    if not df_node:
        report_fail(nodes['leaf0'], "Incorrect DF/NDF selection")
        
    # 2 Verify multicast traffic is drop in NDF 
    # 2.1 record initial state
    cmd_intf = 'show interface counters'
    if df_node == nodes['leaf0']:
        df_downlink = vars.D2T1P2
        ndf_downlink = vars.D3T1P1
    else:
        df_downlink = vars.D3T1P1
        ndf_downlink = vars.D2T1P2 
        
    # 2.2 send L2 multicast traffic from H3 
    stream = {"src_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr },
              "dst_endpoint" : {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr }}
    BUM_traffic_test(stream, "T1D4P1", "multicast", "T1D2P1")
    
    # 2.3 record current state after traffic sent
    df_downlink_curr = vxlan_obj.get_counters(node = df_node,cmd = cmd_intf, target_iface = df_downlink, r_t_key = 'tx_ok')
    st.log("df_downlink_curr is {}".format(df_downlink_curr))
    
    ndf_downlink_curr = vxlan_obj.get_counters(node = ndf_node,cmd = cmd_intf, target_iface = ndf_downlink, r_t_key = 'tx_ok')
    st.log("ndf_downlink_curr is {}".format(ndf_downlink_curr))
    
    # 3 analyze result 
    if not (df_downlink_curr >= 0.98*int(data.pkts_per_burst) and 
            df_downlink_curr <= 1.1*int(data.pkts_per_burst) and
            ndf_downlink_curr <= 0.1 * int(data.pkts_per_burst)):
        report_fail(ndf_node, "Multicast traffic not dropped by NDF")
    else:
        st.report_pass('test_case_passed')
            
######################################################################
# Unknown-Unicast Remote Testing
######################################################################
# Verify unknown_unicast traffic from H3 is getting dropped by NDF 
def test_unknown_unicast():
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    # 1 Verify Ethernet Segment is up and peering
    is_peering = evpn_mh_obj.es_peering(nodes['leaf0'], LEAF1_VXLAN_IP, ESI1)
    if not is_peering:
        report_fail(nodes['leaf0'], "ES is not peering")
        
    # 2 Verify DF/NDF
    df_node, ndf_node = evpn_mh_obj.get_df_ndf_node(nodes['leaf0'], nodes['leaf1'], ESI1)
    if not df_node:
        report_fail(nodes['leaf0'], "Incorrect DF/NDF selection")
        
    # 3 Verify BUM traffic is ingress replicated towards Leaf0, Leaf1 and drop in NDF

    if df_node == nodes['leaf0']:
        df_downlink = vars.D2T1P2
        ndf_downlink = vars.D3T1P1
    else:
        df_downlink = vars.D3T1P1
        ndf_downlink = vars.D2T1P2
        
    # 3.1 send L2 unknown unicast traffic from H3. 
    stream = {"src_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr },
              "dst_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr }}
    BUM_traffic_test(stream, "T1D4P1", "unknownunicast", "T1D2P1")

    # 3.2 record current state after traffic sent
    cmd_vxlan = 'show vxlan counters'
    cmd_intf = 'show interface counters'
    
    leaf2_df_vxlan_rx_curr = vxlan_obj.get_counters(node=df_node,cmd = cmd_vxlan, target_iface = 'EVPN_{}'.format(LEAF2_VXLAN_IP), r_t_key = 'rx_pkts')
    st.log("leaf2_df_vxlan_rx_curr is {}".format(leaf2_df_vxlan_rx_curr))
    
    leaf2_ndf_vxlan_rx_curr = vxlan_obj.get_counters(node=ndf_node,cmd = cmd_vxlan, target_iface = 'EVPN_{}'.format(LEAF2_VXLAN_IP), r_t_key = 'rx_pkts')
    st.log("leaf2_ndf_vxlan_rx_curr is {}".format(leaf2_ndf_vxlan_rx_curr))
    
    leaf2_df_vxlan_tx_curr = vxlan_obj.get_counters(node=nodes['leaf2'],cmd = cmd_vxlan, target_iface = 'EVPN_{}'.format(LEAF0_VXLAN_IP), r_t_key = 'tx_pkts')
    st.log("leaf2_df_vxlan_tx_curr is {}".format(leaf2_df_vxlan_tx_curr))
    
    leaf2_ndf_vxlan_tx_curr = vxlan_obj.get_counters(node=nodes['leaf2'],cmd = cmd_vxlan, target_iface = 'EVPN_{}'.format(LEAF1_VXLAN_IP), r_t_key = 'tx_pkts')
    st.log("leaf2_ndf_vxlan_tx_curr is {}".format(leaf2_ndf_vxlan_tx_curr))

    '''
    Record current state of interface counters
    '''
    df_downlink_curr = vxlan_obj.get_counters(node = df_node,cmd = cmd_intf, target_iface = df_downlink, r_t_key = 'tx_ok')
    st.log("df_downlink_curr is {}".format(df_downlink_curr))
    
    ndf_downlink_curr = vxlan_obj.get_counters(node = ndf_node,cmd = cmd_intf, target_iface = ndf_downlink, r_t_key = 'tx_ok')
    st.log("ndf_downlink_curr is {}".format(ndf_downlink_curr))

    # 4 analyze result 
    # Validate traffic is drop in NDF
    if not (df_downlink_curr >= 0.98*int(data.pkts_per_burst) and 
            df_downlink_curr <= 1.1*int(data.pkts_per_burst) and
            ndf_downlink_curr <= 0.1 * int(data.pkts_per_burst)):
        report_fail(ndf_node, "Unknown unicast traffic is not dropped in NDF")
    # Validate Unknown unicast traffic is ingress replicated towards df and ndf
    elif not (leaf2_df_vxlan_rx_curr >= int(data.pkts_per_burst) and leaf2_ndf_vxlan_rx_curr >= int(data.pkts_per_burst) and leaf2_df_vxlan_tx_curr >= int(data.pkts_per_burst) and leaf2_ndf_vxlan_tx_curr >= int(data.pkts_per_burst)):
        report_fail(nodes['leaf2'], "Unknown unicast traffic is not ingress replicated towards df and ndf")
    else:
        st.report_pass('test_case_passed')
        
######################################################################
# Test BUM Local Bias
######################################################################
def test_local_bias():
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    
    # 1. Send BUM traffic from H1 to H2, check traffic forwarding path with original DF/NDF status
    df_node, ndf_node = evpn_mh_obj.get_df_ndf_node(nodes['leaf0'], nodes['leaf1'], ESI1)
    if not df_node:
        report_fail(nodes['leaf0'], "Incorrect DF/NDF selection")
        
    cmd_intf = 'show interface counters'
    if df_node == nodes['leaf0']:
        df_downlink = vars.D2T1P2
        ndf_downlink = vars.D3T1P1
    else:
        df_downlink = vars.D3T1P1
        ndf_downlink = vars.D2T1P2
        
    #Send BUM traffic 
    stream = {"src_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr },
              "dst_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr }}
    BUM_traffic_test(stream, "T1D2P1", "unknownunicast")
    
    df_downlink_curr = vxlan_obj.get_counters(node = df_node,cmd = cmd_intf, target_iface = df_downlink, r_t_key = 'tx_ok')
    st.log("df_downlink_curr is {}".format(df_downlink_curr))
    
    ndf_downlink_curr = vxlan_obj.get_counters(node = ndf_node,cmd = cmd_intf, target_iface = ndf_downlink, r_t_key = 'tx_ok')
    st.log("ndf_downlink_curr is {}".format(ndf_downlink_curr))
            
    #Parse traffic     
    if not (df_downlink_curr >= 0.98*int(data.pkts_per_burst) and 
            df_downlink_curr <= 1.1*int(data.pkts_per_burst) and
            ndf_downlink_curr <= 0.1 * int(data.pkts_per_burst)):
        report_fail(df_node, "Local bias is not effective on {}".format(df_node))
    st.banner("Local bias testcase passed for unknown unicast traffic before changing DF/NDF roles")
    # 2 Swith DF/NDF, check traffic forwarding path with current DF/NDF status
    
    # Make leaf0 NDF, leaf1 DF
    st.config(nodes['leaf0'], 'interface PortChannel2\nevpn mh es-df-pref 1\nend\nexit\n', type='vtysh')
    
    st.config(nodes['leaf1'], 'interface PortChannel2\nevpn mh es-df-pref 1000\nend\nexit\n', type='vtysh')
   
    st.wait(10)
    
    st.show(nodes['leaf0'], 'show evpn es detail', type='vtysh', skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'show evpn es detail', type='vtysh', skip_tmpl=True, skip_error_check=True)
    if evpn_mh_obj.isDF(nodes['leaf0'], ESI1):
        report_fail(nodes['leaf0'], 'leaf0 is not changed to ndf ')
    if not evpn_mh_obj.isDF(nodes['leaf1'], ESI1):
        report_fail(nodes['leaf1'], 'leaf1 is not changed to df ')
    
    #Send BUM traffic from H1
    stream = {"src_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr },
              "dst_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr }}
    BUM_traffic_test(stream, "T1D2P1", "unknownunicast")

    df_downlink_curr = vxlan_obj.get_counters(node = df_node,cmd = cmd_intf, target_iface = df_downlink, r_t_key = 'tx_ok')
    st.log("df_downlink_curr is {}".format(df_downlink_curr))
    
    ndf_downlink_curr = vxlan_obj.get_counters(node = ndf_node,cmd = cmd_intf, target_iface = ndf_downlink, r_t_key = 'tx_ok')
    st.log("ndf_downlink_curr is {}".format(ndf_downlink_curr))
    
    # Restore original DF/NDF status
    st.config(nodes['leaf0'], 'interface PortChannel2\nevpn mh es-df-pref 32767\nend\nexit\n', type='vtysh')
    
    st.config(nodes['leaf1'], 'interface PortChannel2\nevpn mh es-df-pref 32767\nend\nexit\n', type='vtysh')
    
    ##for temporary use
    st.show(nodes['leaf0'], 'show evpn es detail', type='vtysh', skip_tmpl=True, skip_error_check=True)
    st.show(nodes['leaf1'], 'show evpn es detail', type='vtysh', skip_tmpl=True, skip_error_check=True)
    
    #Parse traffic, switching DF/NDF should not have any influence. Local bias should always work.     
    if not (df_downlink_curr >= 0.98*int(data.pkts_per_burst) and
            df_downlink_curr <= 1.1*int(data.pkts_per_burst) and
            ndf_downlink_curr <= 0.1 * int(data.pkts_per_burst)):
        report_fail(ndf_node, "Local bias doesn't work after changing DF/NDF status")
        
    st.report_pass('test_case_passed')
   
######################################################################
# Test Nexthop Group
######################################################################
def is_nhg_installed(nodes):
    vtep_list = [LEAF0_VXLAN_IP, LEAF1_VXLAN_IP]
    
    # Dump VXLAN_FDB_TABLE
    cmd = 'sonic-db-dump -n APPL_DB -k *VXLAN_FDB_TABLE:Vlan10:{}* -y'.format(data.lag_mac)
    
    output = st.show(nodes['leaf2'], cmd, skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes['leaf2'], cmd, output, 'sonic_db_dump_app_db_VXLAN_FDB_TABLE.tmpl')
    if not parsed:
        report_fail(nodes['leaf2'], 'No nexthop group is found on leaf2')   
    nexthop_group = parsed[0]['nexthop_group']  
         
    # Dump NEXTHOP_GROUP_TABLE    
    cmd = 'sonic-db-dump -n APPL_DB -k *L2_NEXTHOP_GROUP_TABLE:{}* -y'.format(nexthop_group)
    output = st.show(nodes['leaf2'], cmd, skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes['leaf2'], cmd, output, 'sonic_db_dump_app_db_L2_NEXTHOP_GROUP_TABLE.tmpl')
    nexthops = parsed[0]['nexthop_group'].split(',')
    if len(nexthops) != len(vtep_list):  
        report_fail(nodes['leaf2'], 'Incorrect number of nexthop group members')
        
    # Dump NEXTHOP_GROUP_TABLE of each nexthop group member
    vtep0_seen = False
    vtep1_seen = False
    for nexthop in nexthops:
        cmd = 'sonic-db-dump -n APPL_DB -k *L2_NEXTHOP_GROUP_TABLE:{}* -y'.format(nexthop)
        output = st.show(nodes['leaf2'], cmd, skip_tmpl=True, skip_error_check=True)
        parsed = st.parse_show(nodes['leaf2'], cmd, output, 'sonic_db_dump_app_db_L2_NEXTHOP_GROUP_TABLE.tmpl')
        vtep_ip = parsed[0]['remote_vtep']
        if vtep_ip == LEAF0_VXLAN_IP:
            vtep0_seen = True
        elif vtep_ip == LEAF1_VXLAN_IP:
            vtep1_seen = True
            
    if (not vtep0_seen) and (not vtep1_seen):
        report_fail(nodes['leaf2'], 'Both leaf0 and leaf1 are missing as nexthops')
    elif not vtep0_seen:
        report_fail(nodes['leaf2'], 'Leaf0 is missing as nexthop')
    elif not vtep1_seen:
        report_fail(nodes['leaf2'], 'Leaf1 is missing as nexthop')   

def test_remote_unicast_for_ecmp():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    stream = {"src_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr },
              "dst_endpoint": {"port" : lag_name, "host_ip": data.lag_ip, "gateway": data.lag_gateway_ip, "mac" : data.lag_mac }}
    vxlan_obj.clear_counters()
    get_cli_out()
    stream_id = vxlan_obj.create_udp_traffic_stream(handles, data, stream)
    result = vxlan_obj.send_udp_traffic(handles, data, stream, stream_id)

    if not result:
        report_fail(nodes['leaf2'], "Unicast traffic in test_remote_unicast_for_ecmp failed")
    intf_cmd = 'show interface counters'
    leaf0_counters = vxlan_obj.get_counters(nodes['leaf0'], cmd = intf_cmd, target_iface = vars.D2T1P2, r_t_key = 'tx_ok')
    leaf1_counters = vxlan_obj.get_counters(nodes['leaf1'], cmd = intf_cmd, target_iface = vars.D3T1P1, r_t_key = 'tx_ok')
    st.log("\nTX counters on interface {} and {} is {} and {}".format(vars.D2T1P2, vars.D3T1P1, leaf0_counters, leaf1_counters))

    if (leaf0_counters <= 0.1 * int(data.pkts_per_burst) or leaf1_counters <= 0.1 * int(data.pkts_per_burst)):
        st.banner("Unicast traffic from leaf2 is not getting load balanced between leaf0 and leaf1")
        report_fail(nodes['leaf2'], "Unicast traffic from leaf2 is not getting load balanced between leaf0 and leaf1")
    st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D2T1P2))
    st.wait(5)
    vxlan_obj.clear_counters()
    get_cli_out()
    result = vxlan_obj.send_udp_traffic(handles, data, stream, stream_id)
    vxlan_obj.delete_udp_traffic_stream(handles, stream)
    st.config(nodes['leaf0'], "config interface start {}".format(vars.D2T1P2))
    if not result:
        report_fail(nodes['leaf0'], "Traffic test failed after shutting down Leaf0 link connected to multihomed host")
    st.report_pass('test_case_passed', 'test_remote_unicast_for_ecmp passed')

######################################################################
# Test Portchannel Deconfig and Config to See DF and NDF is Honored
######################################################################    
def test_portchannel_deconf():
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    # Deconfig
    cmds = ['sudo config interface sys-mac remove PortChannel2 00:44:33:22:11:00',
            'sudo config interface evpn-esi del PortChannel2',
            'sudo config vlan member del 10 PortChannel2',
            'sudo config portchannel member del PortChannel2 {}'.format(vars.D2T1P2),
            'sudo config portchannel del PortChannel2']
    for cmd in cmds: 
        st.config(nodes['leaf0'], cmd)
      
    output = st.show(nodes['leaf0'], 'show interface portchannel', skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes['leaf0'], 'show interface portchannel', output, 'show_intf_portchannel.tmpl')

    if len(parsed) != 0:
        report_fail(nodes['leaf0'], 'Portchannel deconfig failed')
    
    # Restore config
    cmds = ['sudo config portchannel add PortChannel2',
        'sudo config interface ipv6 disable use-link-local-only {}'.format(vars.D2T1P2),
        'sudo config portchannel member add PortChannel2 {}'.format(vars.D2T1P2),
        'sudo config vlan member add -u 10 PortChannel2',
        'sudo config interface sys-mac add PortChannel2 00:44:33:22:11:00',
        'sudo config interface evpn-esi add PortChannel2 auto-system-mac']
    for cmd in cmds: 
        st.config(nodes['leaf0'], cmd)

    st.wait(20)
    
    #check portchannel status
    st.config(nodes['leaf0'], 'show interface portchannel', skip_tmpl=True, skip_error_check=True)
    st.config(nodes['leaf1'], 'show interface portchannel', skip_tmpl=True, skip_error_check=True)
    # check es and ndf status
    if not evpn_mh_obj.isDF(nodes['leaf0'], ESI1): 
        report_fail(nodes['leaf0'], 'leaf0 df/ndf status is wrong after resetting portchannel') 
        
    if evpn_mh_obj.isDF(nodes['leaf1'], ESI1): 
        report_fail(nodes['leaf1'], 'leaf1 df/ndf status is wrong after resetting portchannel') 

    # check traffic : send L2 BUM traffic from H3 
    cmd_intf = 'show interface counters'
    
    stream = {"src_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr },
              "dst_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr }}
    BUM_traffic_test(stream, "T1D4P1", "broadcast", "T1D2P1")
    
    df_downlink_curr = vxlan_obj.get_counters(node = nodes['leaf0'],cmd = cmd_intf, target_iface = vars.D2T1P2, r_t_key = 'tx_ok')
    st.log("df_downlink_curr is {}".format(df_downlink_curr))
    
    ndf_downlink_curr = vxlan_obj.get_counters(node = nodes['leaf1'],cmd = cmd_intf, target_iface = vars.D3T1P1, r_t_key = 'tx_ok')
    st.log("ndf_downlink_curr is {}".format(ndf_downlink_curr))
    
    if not (df_downlink_curr >= 0.98*int(data.pkts_per_burst) and 
            df_downlink_curr <= 1.1*int(data.pkts_per_burst) and
            ndf_downlink_curr <= 0.1 * int(data.pkts_per_burst)):
        report_fail(nodes['leaf1'], "BUM traffic is not drop in NDF after resetting portchannel")
    
    else:
        st.report_pass('test_case_passed')
        
def reset_topology_after_mac_move(port, new_port):
    tg_handle = handles.values()[0]['tg_handle']
    tmp_handle = handles[port]['int_handle1']
    stop_device_group(port)
    device_group = "/"+"/".join(tmp_handle.split('/',3)[1:3])       #/topology:2/deviceGroup:1
    st.log("Destroying device group {} which was created for mac move".format(device_group))
    tg_handle.tg_topology_config(device_group_handle =device_group, mode = 'destroy')
    st.wait(10)
    start_device_group(new_port)
    st.banner("About to ping gateway after mac move back")
    vxlan_obj.ping_gateway(handles, new_port, data.d2t1_ip_addr, handles[new_port]["int_handle"])
    start_device_group(port)

def stop_device_group(port):
    tg_handle = handles.values()[0]['tg_handle']
    tmp_handle = handles[port]['int_handle']
    tp_group = "/"+"/".join(tmp_handle.split('/',3)[1:2])       #/topology:2
    tg_handle.tg_test_control(action="stop_protocol", handle=tp_group)
    st.wait(10)		#give time to stop protocol

def start_device_group(port):
    tg_handle = handles.values()[0]['tg_handle']
    tmp_handle = handles[port]['int_handle']
    device_group = "/"+"/".join(tmp_handle.split('/',3)[1:3])
    tg_handle.tg_test_control(action="start_protocol", handle=device_group)
    st.wait(10)		##give time to start protocol

def create_device_group(port, host_dict, device_group_name):
    tg = handles[port]['tg_handle']
    topology_name = "/"+handles[port]['int_handle'].split("/")[1]       #/topology:2
    tg.tg_test_control(action='stop_protocol', handle=topology_name)
    st.wait(10)		#give time to stop protocol
    _result_ = tg.tg_topology_config(topology_handle=topology_name,
                                     device_group_name=device_group_name,
                                     device_group_multiplier = '1', device_group_enabled = '1')
    deviceGroup_1_handle = _result_['device_group_handle']
    _result_ = tg.tg_interface_config(protocol_name     = 'Ethernet H1',
                                      protocol_handle   = deviceGroup_1_handle,
                                      mtu               = '1500',
                                      src_mac_addr      = host_dict["host_mac"]
                                      )
    ethernet_1_handle = _result_['ethernet_handle']
    _result_ = tg.tg_interface_config(
        protocol_name     = 'IPv4',
        protocol_handle   = ethernet_1_handle,
        gateway           = host_dict["gateway"],
        intf_ip_addr      = host_dict["host_ip"],
         netmask          = "255.255.255.0"
    )
    int_handle = _result_['interface_handle']
    tg.tg_test_control(action='start_protocol', handle=topology_name)
    st.wait(10)		#give time to start protocol
    handles[port].update({"int_handle1": int_handle})

def create_raw_traffic_stream(stream_info):
    all_port_handles=[]
    vxlan_obj.clear_counters()
    if stream_info.get('src_endpoint') and stream_info.get('dst_endpoint'):
        tg_handle1, port_handle1 = tgapi.get_handle_byname(stream_info['src_endpoint']['port'])
        tg_handle2, port_handle2 = tgapi.get_handle_byname(stream_info['dst_endpoint']['port'])

        all_port_handles.append(port_handle1)
        all_port_handles.append(port_handle2)

        tg_handle1.tg_traffic_control(action='clear_stats', port_handle=[port_handle1, port_handle2])
        receive = tg_handle1.tg_traffic_config(
                port_handle=port_handle1, port_handle2=port_handle2, mode='create',
                transmit_mode=data.transmit_mode, pkts_per_burst=data.pkts_per_burst,
                rate_percent = data.rate_percent, circuit_endpoint_type=data.circuit_endpoint_type,
                frame_size=data.frame_size, mac_src=stream_info['src_endpoint']['mac'],
                mac_dst=stream_info['dst_endpoint']['mac'])
        stream_id = receive["stream_id"]
        tmp_handle = {"tg_handle": tg_handle1,"port_handle1": port_handle1, "port_handle2": port_handle2, "stream_id": stream_id,"all_port_handles": all_port_handles,"traffic_item_type": "raw"}
    return tmp_handle

#SH mac move test when H1 is moved from L0 to L2 and moved back, H1->H3
def test_mac_IP_move_SH():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    #change mac ageout on all leaf for mac move testcases
    evpn_mh_obj.change_fdb_ageout("6000")

    #create raw traffic stream from H5 to H1
    h5_h1_hdl = create_raw_traffic_stream(
            {"dst_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr },
             "src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h5_h1_hdl)
    if not result:
        report_fail(nodes['leaf0'], "ping and traffic from H5 to H1 failed with unicast traffic")
    #stop H1 for mac move
    stop_device_group(port_name_map["H1"])
    #create same device as stopped device behind different leaf, H1 moved behind leaf2
    host_info_dict = {"host_ip":data.t1d2p1_ip_addr, "host_mac":data.t1d2p1_mac_addr,"gateway":data.d2t1_ip_addr}
    create_device_group(port_name_map["H3"], host_info_dict, "moved_deviceGroup_H1")

    #traffic verifications
    h5_moved_h1_handle = create_raw_traffic_stream(
            {"src_endpoint": {"port" : "T1D3P2","host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
             "dst_endpoint": {"port" : "T1D4P1","host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h5_moved_h1_handle)
    if not result:
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H1 failed after mac move with unicast traffic")

    h2_counter = vxlan_obj.get_counters(node = nodes['leaf1'], cmd='show interface counters', target_iface = vars.D2T1P2, r_t_key='rx_ok')
    if not (h2_counter <= 0.1 * int(data.pkts_per_burst)):
        report_fail(nodes['leaf1'], "Traffic from H5->H1 getting flooded on H2")
    st.log("ping and traffic from H5 to H1 passed after mac move with unicast traffic")

    #old traffic stream should fail now
    result = vxlan_obj.traffic_test_burst("unicast", h5_h1_hdl)
    if result:
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved H1 passed unexpectedly with unicast traffic")
    st.log("ping and traffic from H5 to moved H1 failed as expected")

    # Check inter-traffic verifications
    st.log("send l3 traffic between H1 and H4")
    int_dict[port_name_map["H3"]] = {"host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr}
    result = l3_traffic_test([("T1D4P1","T1D4P2")])                # H1(H3) -> H4
    if not result:
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H1"])
        int_dict[port_name_map["H3"]] = {"host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr}
        report_fail(nodes['leaf1'], "ping and traffic from H4 to H1 failed after mac move with unicast traffic")
    # Reset dict
    int_dict[port_name_map["H3"]] = {"host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr}

    #FRR verification
    updated_seq_ids = update_sequence_ids(['LEAF2'])
    expected_frr_op = {'leaf0': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.t1d2p1_mac_addr, 'type':'local', 'vtep': vars.D4T1P1, 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d2p1_mac_addr, expected_frr_op)
            if not frr:
                reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H1"])
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.t1d2p1_ip_addr)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.t1d2p1_mac_addr)
            if not (kernel_ip_flag or kernel_mac_flag):
                reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H1"])
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}".format(dut, kernel_ip_flag, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf0", data.t1d2p1_mac_addr, "static", EXPECTED_L2VNI):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H1"])
        report_fail(nodes['leaf0'], "Mac {} is incorrectly programmed in APP DB".format(data.t1d2p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf2", data.t1d2p1_mac_addr)):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H1"])
        report_fail(nodes['leaf2'], "mac {} not found after move to leaf2".format(data.t1d2p1_mac_addr))

    #IP verification
    verify_sonic_app_db_for_pfx(nodes, data.t1d2p1_ip_addr, 'leaf0', "Vrf01:"+data.t1d2p1_ip_addr)
    verify_sonic_app_db_for_pfx(nodes, data.t1d2p1_ip_addr, 'leaf1', "Vrf01:"+data.t1d2p1_ip_addr)
    verify_sonic_app_db_for_pfx(nodes, data.t1d2p1_ip_addr, 'leaf2', "Vlan10:"+data.t1d2p1_ip_addr)

    #move H1 back behind leaf0
    st.banner("Moving H1 back behind Leaf0")
    reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H1"])
    h5_h1_hdl = create_raw_traffic_stream(
            {"dst_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr },
             "src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h5_h1_hdl)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved back H1 behind leaf0 failed with unicast traffic")
    st.log("ping and traffic from H5 to moved back H1 behind leaf0 passed")

    #FRR
    updated_seq_ids = update_sequence_ids(['LEAF0'])
    expected_frr_op = {'leaf0': {'mac_address':data.t1d2p1_mac_addr, 'type':'local', 'vtep': vars.D2T1P1, 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF0_VXLAN_IP, 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF0_VXLAN_IP, 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d2p1_mac_addr, expected_frr_op)
            if not frr:
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.t1d2p1_ip_addr)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.t1d2p1_mac_addr)
            if not (kernel_ip_flag or kernel_mac_flag):
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}".format(dut, kernel_ip_flag, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf2", data.t1d2p1_mac_addr, "static", EXPECTED_L2VNI):
        report_fail(nodes['leaf0'], "Mac {} is incorrectly programmed in APP DB".format(data.t1d2p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf0", data.t1d2p1_mac_addr)):
        report_fail(nodes['leaf0'], "mac {} not found after move back to leaf0".format(data.t1d2p1_mac_addr))
    st.report_pass("test_case_passed", "mac move testcase passed")

def is_mac_exists(nodes, src_vtep, mac):
    output = st.show(nodes[src_vtep], 'show mac -a {}'.format(mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'show mac', output, 'show_mac.tmpl')
    st.log(parsed)
    if len(parsed) == 1:	#parsed would contain minimum of 1 entry because of total entries field in show mac o/p
        return False
    return True

#MH mac move test when H1 is moved to H2 and moved back
def test_mac_IP_move_SH_to_MH():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    evpn_mh_obj.change_fdb_ageout("6000")
    #create raw traffic stream from H5 to H1
    h5_h1_hdl = create_raw_traffic_stream(
            {"dst_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr },
             "src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h5_h1_hdl)
    if not result:
        report_fail(nodes['leaf0'], "ping and traffic from H5 to H1 failed with unicast traffic")

    #stop H1 for mac move
    stop_device_group(port_name_map["H1"])
    #create same device as stopped device behind different leaf, H1 moved behind H2
    host_info_dict = {"host_ip":data.t1d2p1_ip_addr, "host_mac":data.t1d2p1_mac_addr,"gateway":data.d2t1_ip_addr}
    create_device_group(port_name_map["H2"], host_info_dict, "moved_deviceGroup_H1")

    if not vxlan_obj.ping_gateway(handles, lag_name, data.d2t1_ip_addr, handles[lag_name]["int_handle1"]):
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "ping failed after mac move from new H1 to GW")

    #traffic verifications H5->H2
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : lag_name, "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr }}
    stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles[lag_name], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], stream_id, False)
    if not result:
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H3 failed after mac move with unicast traffic")
    h3_counter = vxlan_obj.get_counters(node = nodes['leaf2'], cmd='show interface counters', target_iface = vars.D4T1P1, r_t_key='rx_ok')
    if not (h3_counter <= 0.1 * int(data.pkts_per_burst)):
        report_fail(nodes['leaf2'], "Traffic from H5->H2 getting flooded on H3")

    st.log("ping and traffic from H5 to H1 passed after mac move with unicast traffic")

    #old traffic stream should fail now
    result = vxlan_obj.traffic_test_burst("unicast", h5_h1_hdl)
    if result:
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved H1 passed unexpectedly with unicast traffic")
    st.log("ping and traffic from H5 to moved H1 failed as expected")

    # Check inter-traffic verifications
    st.log("send l3 traffic between H1 and H4")
    int_dict[port_name_map["H2"]] = {"host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr}
    result = l3_traffic_test([(lag_name, "T1D4P2")])                # H1(H2) -> H4
    if not result:
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
        int_dict.update({port_name_map["H2"]: {"host_ip": data.lag_ip, "gateway": data.lag_gateway_ip, "mac" : data.lag_mac}})
        report_fail(nodes['leaf1'], "ping and traffic from H4 to H1 failed after mac move with unicast traffic")
    # Reset dict
    int_dict.update({port_name_map["H2"]: {"host_ip": data.lag_ip, "gateway": data.lag_gateway_ip, "mac" : data.lag_mac}})

    #FRR verification
    updated_seq_ids = update_sequence_ids(['LEAF0', 'LEAF1'])
    expected_frr_op = {'leaf0': {'mac_address':data.t1d2p1_mac_addr, 'type':'local', 'vtep': "PortChannel2", 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.t1d2p1_mac_addr, 'type':'local', 'vtep': "PortChannel2", 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': "03:00:44:33:22:11:00:00:00:02", 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d2p1_mac_addr, expected_frr_op)
            if not frr:
                reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move, dut:{} frr:{}".format(dut, frr))

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.t1d2p1_ip_addr)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.t1d2p1_mac_addr)
            if not (kernel_ip_flag or kernel_mac_flag):
                reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}".format(dut, kernel_ip_flag, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf0", data.t1d2p1_mac_addr, "static", "0"):
        if not verify_mac_in_app_db(nodes, "leaf1", data.t1d2p1_mac_addr, "static", "0"):
            reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
            report_fail(nodes["leaf1"], "Mac {} is incorrectly programmed in APP DB".format(data.t1d2p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf1", data.t1d2p1_mac_addr)):
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "mac {} not found after move to leaf2".format(data.t1d2p1_mac_addr))
    if not (is_mac_exists(nodes, "leaf0", data.t1d2p1_mac_addr)):
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
        report_fail(nodes['leaf0'], "mac {} not found after move to leaf1".format(data.t1d2p1_ip_addr))

    #IP verification
    verify_sonic_app_db_for_pfx(nodes, data.t1d2p1_ip_addr, 'leaf0', "Vlan10:"+data.t1d2p1_ip_addr)
    verify_sonic_app_db_for_pfx(nodes, data.t1d2p1_ip_addr, 'leaf1', "Vlan10:"+data.t1d2p1_ip_addr)
    verify_sonic_app_db_for_pfx(nodes, data.t1d2p1_ip_addr, 'leaf2', "Vrf01:"+data.t1d2p1_ip_addr)

    #move H1 back behind leaf0
    st.banner("Moving H1 back behind Leaf0")
    reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H1"])
    h5_h1_hdl = create_raw_traffic_stream(
            {"dst_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr },
             "src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h5_h1_hdl)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved back H1 behind leaf0 failed with unicast traffic")
    st.log("ping and traffic from H5 to moved back H1 behind leaf0 passed")

    #FRR
    updated_seq_ids = update_sequence_ids(['LEAF0'])
    expected_frr_op = {'leaf0': {'mac_address':data.t1d2p1_mac_addr, 'type':'local', 'vtep': vars.D2T1P1, 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF0_VXLAN_IP, 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF0_VXLAN_IP, 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d2p1_mac_addr, expected_frr_op)
            if not frr:
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move, dut:{} frr:{}".format(dut, frr))

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.t1d2p1_ip_addr)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.t1d2p1_mac_addr)
            if not (kernel_ip_flag or kernel_mac_flag):
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}".format(dut, kernel_ip_flag, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf2", data.t1d2p1_mac_addr, "static", EXPECTED_L2VNI):
        report_fail(nodes["leaf2"], "Mac {} is incorrectly programmed in APP DB".format(data.t1d2p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf0", data.t1d2p1_mac_addr)):
        report_fail(nodes['leaf0'], "mac {} not found after move back to leaf0".format(data.t1d2p1_mac_addr))
    st.report_pass("test_case_passed", "mac move testcase passed")

#MH mac move test when H3 is moved to H2 and moved back
def test_mac_IP_move_remote_SH_to_MH():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    evpn_mh_obj.change_fdb_ageout("6000")
    #create raw traffic stream from H5 to H3
    h5_h3_hdl = create_raw_traffic_stream(
            {"dst_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr },
             "src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h5_h3_hdl)
    if not result:
        report_fail(nodes['leaf0'], "ping and traffic from H5 to H3 failed with unicast traffic")

    #stop H3 for mac move
    stop_device_group(port_name_map["H3"])
    #create same device as stopped device behind different leaf, H3 moved behind H2
    host_info_dict = {"host_ip":data.t1d4p1_ip_addr, "host_mac":data.t1d4p1_mac_addr,"gateway":data.d2t1_ip_addr}
    create_device_group(port_name_map["H2"], host_info_dict, "moved_deviceGroup_H3")
    if not vxlan_obj.ping_gateway(handles, lag_name, data.d2t1_ip_addr, handles[lag_name]["int_handle1"]):
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
        report_fail(nodes['leaf1'], "ping failed after mac move from new H3 to GW")

    #traffic verifications from H5->H2
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : lag_name, "host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr }}
    stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles[lag_name], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], stream_id, False)
    if not result:
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H3 failed after mac move with unicast traffic")

    h1_counter = vxlan_obj.get_counters(node = nodes['leaf0'], cmd='show interface counters', target_iface = vars.D2T1P1, r_t_key='rx_ok')
    if not (h1_counter <= 0.1 * int(data.pkts_per_burst)):
        report_fail(nodes['leaf0'], "Traffic from H5->H2 getting flooded on H1")
    st.log("ping and traffic from H5 to H3 passed after mac move with unicast traffic")
    #old traffic stream should fail now
    result = vxlan_obj.traffic_test_burst("unicast", h5_h3_hdl)
    if result:
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved H3 passed unexpectedly with unicast traffic")
    st.log("ping and traffic from H5 to moved H3 failed as expected")

    #FRR verifications
    updated_seq_ids = update_sequence_ids(['LEAF0', 'LEAF1'])
    expected_frr_op = {'leaf0': {'mac_address':data.t1d4p1_mac_addr, 'type':'local', 'vtep': "PortChannel2", 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.t1d4p1_mac_addr, 'type':'local', 'vtep': "PortChannel2", 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.t1d4p1_mac_addr, 'type':'remote', 'vtep': "03:00:44:33:22:11:00:00:00:02", 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d4p1_mac_addr, expected_frr_op)
            if not frr:
                reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
                report_fail(nodes["leaf2"], "seq id is incorrect in zebra after mac move")


    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.t1d4p1_ip_addr)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.t1d4p1_mac_addr)
            if not (kernel_ip_flag or kernel_mac_flag):
                reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}".format(dut, kernel_ip_flag, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf0", data.t1d4p1_mac_addr, "static", "0"):
        if not verify_mac_in_app_db(nodes, "leaf1", data.t1d4p1_mac_addr, "static", "0"):
            reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
            report_fail(nodes["leaf1"], "Mac {} is incorrectly programmed in APP DB".format(data.t1d4p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf1", data.t1d4p1_mac_addr)):
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
        report_fail(nodes['leaf1'], "mac {} not found after move to leaf0-1".format(data.t1d4p1_mac_addr))
    if not (is_mac_exists(nodes, "leaf0", data.t1d4p1_mac_addr)):
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
        report_fail(nodes['leaf0'], "mac {} not found after move to leaf0-1".format(data.t1d4p1_mac_addr))
    if (is_mac_exists(nodes, "leaf2", data.t1d4p1_mac_addr)):
        reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
        report_fail(nodes['leaf2'], "mac {} still found on leaf2 after move to leaf0-leaf1".format(data.t1d4p1_mac_addr))

    verify_sonic_app_db_for_pfx(nodes, data.t1d4p1_ip_addr, 'leaf0', "Vlan10:"+data.t1d4p1_ip_addr)
    verify_sonic_app_db_for_pfx(nodes, data.t1d4p1_ip_addr, 'leaf1', "Vlan10:"+data.t1d4p1_ip_addr)
    verify_sonic_app_db_for_pfx(nodes, data.t1d4p1_ip_addr, 'leaf2', "Vrf01:"+data.t1d4p1_ip_addr)

    #move H3 back behind leaf2
    st.banner("Moving H3 back behind Leaf2")
    reset_topology_after_mac_move(port_name_map["H2"], port_name_map["H3"])
    result = vxlan_obj.traffic_test_burst("unicast", h5_h3_hdl)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved back H3 behind leaf2 failed with unicast traffic")
    st.log("ping and traffic from H5 to moved back H3 behind leaf2 passed")

    #FRR verifications
    updated_seq_ids = update_sequence_ids(['LEAF2'])
    expected_frr_op = {'leaf0': {'mac_address':data.t1d4p1_mac_addr, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.t1d4p1_mac_addr, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.t1d4p1_mac_addr, 'type':'local', 'vtep': vars.D4T1P1, 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d4p1_mac_addr, expected_frr_op)
            if not frr:
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac was moved back")

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.t1d4p1_ip_addr)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.t1d4p1_mac_addr)
            if not (kernel_ip_flag or kernel_mac_flag):
                report_fail(nodes[dut], "IP/Mac is incorrectly programmed in kernel ")

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf0", data.t1d4p1_mac_addr, "static", EXPECTED_L2VNI):
        report_fail(nodes['leaf0'], "{} not present in APP_DB on leaf0 ".format(data.t1d4p1_mac_addr))
    if not verify_mac_in_app_db(nodes, "leaf1", data.t1d4p1_mac_addr, "static", EXPECTED_L2VNI):
        report_fail(nodes['leaf1'], "{} not present in APP_DB on leaf1".format(data.t1d4p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf2", data.t1d4p1_mac_addr)):
        report_fail(nodes['leaf2'], "mac {} not found after move back to leaf2".format(data.t1d4p1_mac_addr))

    st.report_pass("test_case_passed", "mac move testcase passed")

#MH mac move test when H2 is moved to H1 and moved back
def _test_mac_IP_move_MH_to_SH():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    evpn_mh_obj.change_fdb_ageout("6000")
    #create raw traffic stream from H5 to H2
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : lag_name, "host_ip": data.lag_ip, "gateway": data.d2t1_ip_addr, "mac" : data.lag_mac }}
    old_stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles[lag_name], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], old_stream_id, False)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H2 failed with unicast traffic")

    #stop H2 for mac move
    stop_device_group(port_name_map["H2"])
    #create same device as stopped device behind different leaf, H2 moved behind leaf0
    host_info_dict = {"host_ip":data.lag_ip, "host_mac":data.lag_mac,"gateway":data.d2t1_ip_addr}
    create_device_group(port_name_map["H1"], host_info_dict, "moved_deviceGroup_H2")
    if not vxlan_obj.ping_gateway(handles, "T1D2P1", data.d2t1_ip_addr, handles["T1D2P1"]["int_handle1"]):
        reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "ping failed after mac move from new H2 to GW")

    #traffic verifications
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : "T1D2P1", "host_ip": data.lag_ip, "gateway": data.d2t1_ip_addr, "mac" : data.lag_mac }}
    stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles["T1D2P1"], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], stream_id, False)
    if not result:
        reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H2 failed after mac move with unicast traffic")

    h3_counter = vxlan_obj.get_counters(node = nodes['leaf2'], cmd='show interface counters', target_iface = vars.D4T1P1, r_t_key='rx_ok')
    if not (h3_counter <= 0.1 * int(data.pkts_per_burst)):
        reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
        report_fail(nodes['leaf0'], "Traffic from H5->moved H2 behind H1 getting flooded on H3")
    st.log("ping and traffic from H5 to H2 passed after mac move with unicast traffic")

    #old traffic stream should fail now
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], old_stream_id, False)
    if result:
        reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved H2 passed unexpectedly with unicast traffic")
    st.log("ping and traffic from H5 to moved H2 failed as expected")

    # Check inter-traffic verifications
    st.log("send l3 traffic between H2 and H4")
    int_dict[port_name_map["H1"]] = {"host_ip": data.lag_ip, "gateway": data.lag_gateway_ip, "mac" : data.lag_mac}
    result = l3_traffic_test([("T1D2P1","T1D4P2")])                # H2(H1) -> H4
    if not result:
        reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
        int_dict[port_name_map["H1"]] = {"host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr}
        report_fail(nodes['leaf1'], "ping and traffic from H4 to H2 failed after mac move with unicast traffic")
    # Reset dict
    int_dict[port_name_map["H1"]] = {"host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr}

    #FRR verifications
    updated_seq_ids = update_sequence_ids(['LEAF0'])
    expected_frr_op = {'leaf0': {'mac_address':data.lag_mac, 'type':'local', 'vtep': "Ethernet1/13", 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': LEAF0_VXLAN_IP, 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': LEAF0_VXLAN_IP, 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.lag_mac, expected_frr_op)
            if not frr:
                reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
                report_fail(nodes["leaf2"], "seq id is incorrect in zebra after mac move")

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.lag_ip)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.lag_mac)
            if not (kernel_ip_flag or kernel_mac_flag):
                reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}".format(dut, kernel_ip_flag, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf1", data.lag_mac, "static", EXPECTED_L2VNI):
        reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
        report_fail(nodes["leaf1"], "Mac {} is incorrectly programmed in APP DB".format(data.lag_mac))
    if not verify_mac_in_app_db(nodes, "leaf2", data.lag_mac, "static", EXPECTED_L2VNI):
        reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
        report_fail(nodes["leaf2"], "Mac {} is incorrectly programmed in APP DB".format(data.lag_mac))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf0", data.lag_mac)):
        reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
        report_fail(nodes['leaf0'], "mac {} not found after move to leaf0".format(data.lag_mac))
    if (is_mac_exists(nodes, "leaf1", data.lag_mac)):
        reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "mac {} should not be found after move on leaf1".format(data.lag_mac))

    #IP verification
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf0', "Vlan10:"+data.lag_ip)
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf1', "Vrf01:"+data.lag_ip)
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf2', "Vrf01:"+data.lag_ip)

    #move H2 back behind leaf0-leaf1
    st.banner("Moving H2 back behind Leaf0-Leaf1")
    reset_topology_after_mac_move(port_name_map["H1"], port_name_map["H2"])
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : lag_name, "host_ip": data.lag_ip, "gateway": data.d2t1_ip_addr, "mac" : data.lag_mac }}
    old_stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles[lag_name], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], old_stream_id, False)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved back H2 behind leaf0 failed with unicast traffic")
    st.log("ping and traffic from H5 to moved back H2 passed")

    #FRR
    updated_seq_ids = update_sequence_ids(['LEAF0', "LEAF1"])
    expected_frr_op = {'leaf0': {'mac_address':data.lag_mac, 'type':'local', 'vtep': "PortChannel2", 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': "PortChannel2", 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': "03:00:44:33:22:11:00:00:00:02", 'seq': updated_seq_ids[2]}}

    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.lag_mac, expected_frr_op)
            if not frr:
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.lag_ip)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.lag_mac)
            if not (kernel_ip_flag or kernel_mac_flag):
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}".format(dut, kernel_ip_flag, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf2", data.lag_mac, "static", EXPECTED_L2VNI):
        report_fail(nodes["leaf2"], "Mac {} is incorrectly programmed in APP DB".format(data.lag_mac))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf1", data.lag_mac)):
        report_fail(nodes['leaf1'], "mac {} not found after mac moved back to leaf0-1".format(data.lag_mac))

    st.report_pass("test_case_passed", "mac move testcase passed")

#MH mac move test when H2 is moved to H3 and moved back
def test_mac_IP_move_MH_to_remote_SH():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    evpn_mh_obj.change_fdb_ageout("6000")

    #create raw traffic stream from H5 to H2
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : lag_name, "host_ip": data.lag_ip, "gateway": data.d2t1_ip_addr, "mac" : data.lag_mac }}
    old_stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles[lag_name], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], old_stream_id, False)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H2 failed with unicast traffic")

    #stop H2 for mac move
    st.banner("Moving H2")
    stop_device_group(port_name_map["H2"])
    #create same device as stopped device behind different leaf, H2 moved behind leaf0
    host_info_dict = {"host_ip":data.lag_ip, "host_mac":data.lag_mac,"gateway":data.d2t1_ip_addr}
    create_device_group(port_name_map["H3"], host_info_dict, "moved_deviceGroup_H2")
    if not vxlan_obj.ping_gateway(handles, "T1D4P1", data.d2t1_ip_addr, handles["T1D4P1"]["int_handle1"]):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "ping failed after mac move from new H2 to GW")

    st.banner("Traffic tests for the moved H2")
    #verifications
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : "T1D4P1", "host_ip": data.lag_ip, "gateway": data.d2t1_ip_addr, "mac" : data.lag_mac }}
    stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles["T1D4P1"], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], stream_id, False)
    if not result:
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H2 failed after mac move with unicast traffic")

    h1_counter = vxlan_obj.get_counters(node = nodes['leaf0'], cmd='show interface counters', target_iface = vars.D2T1P1, r_t_key='rx_ok')
    if not (h1_counter <= 0.1 * int(data.pkts_per_burst)):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf0'], "Traffic from H5->moved H2 behind H3 getting flooded on H1")
    st.log("ping and traffic from H5 to H2 passed after mac move with unicast traffic")

    #old traffic stream should fail now
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], old_stream_id, False)
    if result:
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved H2 passed unexpectedly with unicast traffic")
    st.log("ping and traffic from H5 to moved H2 failed as expected")

    # Check inter-traffic verifications
    st.log("send l3 traffic between H3 and H4")
    int_dict[port_name_map["H3"]] = {"host_ip": data.lag_ip, "gateway": data.lag_gateway_ip, "mac" : data.lag_mac}
    result = l3_traffic_test([("T1D4P1","T1D4P2")])                # H3(H2) -> H4
    if not result:
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        int_dict[port_name_map["H3"]] = {"host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr}
        report_fail(nodes['leaf1'], "ping and traffic from H4 to H3 failed after mac move with unicast traffic")
    # Reset dict
    int_dict[port_name_map["H3"]] = {"host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr}

    #FRR verifications
    updated_seq_ids = update_sequence_ids(['LEAF2'])
    expected_frr_op = {'leaf0': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.lag_mac, 'type':'local', 'vtep': "Ethernet1/9", 'seq': updated_seq_ids[2]}}

    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.lag_mac, expected_frr_op)
            if not frr:
                st.log("FRR verification failed, reseting topology")
                reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.lag_ip)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.lag_mac)
            if not (kernel_ip_flag or kernel_mac_flag):
                reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}".format(dut, kernel_ip_flag, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf1", data.lag_mac, "static", EXPECTED_L2VNI):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes["leaf1"], "Mac {} is incorrectly programmed in APP DB".format(data.lag_mac))
    if not verify_mac_in_app_db(nodes, "leaf0", data.lag_mac, "static", EXPECTED_L2VNI):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes["leaf0"], "Mac {} is incorrectly programmed in APP DB".format(data.lag_mac))

    #ASIC DB
    if (is_mac_exists(nodes, "leaf0", data.lag_mac)):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf0'], "mac {} should not be found after move on leaf0".format(data.lag_mac))
    if (is_mac_exists(nodes, "leaf1", data.lag_mac)):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "mac {} should not be found after move on leaf1".format(data.lag_mac))
    if not (is_mac_exists(nodes, "leaf2", data.lag_mac)):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf2'], "mac {} not found after move to leaf2".format(data.lag_mac))

    #IP verification
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf0', "Vrf01:"+data.lag_ip)
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf1', "Vrf01:"+data.lag_ip)
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf2', "Vlan10:"+data.lag_ip)

    #move H2 back behind leaf0-leaf1
    st.banner("Moving H2 back behind Leaf0-Leaf1")
    reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : lag_name, "host_ip": data.lag_ip, "gateway": data.d2t1_ip_addr, "mac" : data.lag_mac }}
    old_stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles[lag_name], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], old_stream_id, False)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved back H2 behind leaf0 failed with unicast traffic")
    st.log("ping and traffic from H5 to moved back H2 passed")

    #FRR
    updated_seq_ids = update_sequence_ids(['LEAF0', 'LEAF1'])
    expected_frr_op = {'leaf0': {'mac_address':data.lag_mac, 'type':'local', 'vtep': "PortChannel2", 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': "PortChannel2", 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': "03:00:44:33:22:11:00:00:00:02", 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.lag_mac, expected_frr_op)
            if not frr:
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.lag_ip)
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.lag_mac)
            if not (kernel_ip_flag or kernel_mac_flag):
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}".format(dut, kernel_ip_flag, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf2", data.lag_mac, "static", EXPECTED_L2VNI):
        report_fail(nodes["leaf2"], "Mac {} is incorrectly programmed".format(data.lag_mac))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf0", data.lag_mac)):
        report_fail(nodes['leaf1'], "mac {} not found after mac moved back to leaf0-1".format(data.lag_mac))
    if not (is_mac_exists(nodes, "leaf1", data.lag_mac)):
        report_fail(nodes['leaf1'], "mac {} not found after mac moved back to leaf0-1".format(data.lag_mac))
    st.report_pass("test_case_passed", "mac move testcase passed")

#MH mac move test when H2 IP with new mac is moved to H3 and moved back
def _IP_only_move_MH_to_remote_SH():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    #change mac ageout on all leaf for mac move testcases
    evpn_mh_obj.change_fdb_ageout("6000")
    #create raw traffic stream from H5 to H2
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : lag_name, "host_ip": data.lag_ip, "gateway": data.d2t1_ip_addr, "mac" : data.lag_mac }}
    old_stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles[lag_name], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], old_stream_id, False)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H2 failed with unicast traffic")

    #stop H2 for mac move
    stop_device_group(port_name_map["H2"])
    #create same device as stopped device behind different leaf, H2 moved behind leaf0
    host_info_dict = {"host_ip":data.lag_ip, "host_mac": "00:00:00:00:00:22","gateway":data.d2t1_ip_addr}
    create_device_group(port_name_map["H3"], host_info_dict, "moved_DG_H2_different_mac")
    if not vxlan_obj.ping_gateway(handles, "T1D4P1", data.d2t1_ip_addr, handles["T1D4P1"]["int_handle1"]):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "ping failed after mac move from new H2 to GW")

    #verifications
    stream = {"src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
              "dst_endpoint": {"port" : "T1D4P1", "host_ip": data.lag_ip, "gateway": data.d2t1_ip_addr, "mac" : "00:00:00:00:00:22" }}
    stream_id = vxlan_obj.create_raw_traffic_stream(handles["T1D3P2"], handles["T1D4P1"], stream, "raw", data)
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], stream_id, False)
    if not result:
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H2 failed after mac move with unicast traffic")

    h1_counter = vxlan_obj.get_counters(node = nodes['leaf0'], cmd='show interface counters', target_iface = vars.D2T1P1, r_t_key='rx_ok')
    if not (h1_counter <= 0.1 * int(data.pkts_per_burst)):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf0'], "Traffic from H5->moved H2 behind H3 getting flooded on H1")
    st.log("ping and traffic from H5 to H2 passed after mac move with unicast traffic")

    #old traffic stream should fail now
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], old_stream_id, False)
    if result:
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved H2 passed unexpectedly with unicast traffic")
    st.log("ping and traffic from H5 to moved H2 failed as expected")

    #FRR verifications
    expected_frr_op = {'leaf0': {'mac_address':"00:00:00:00:00:22", 'type':'local', 'vtep': LEAF2_VXLAN_IP, 'seq': '0/0'},
                       'leaf1': {'mac_address':"00:00:00:00:00:22", 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq':'0/0'},
                       'leaf2': {'mac_address':"00:00:00:00:00:22", 'type':'remote', 'vtep': "Ethernet1/9", 'seq':'0/0'}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, "00:00:00:00:00:22", expected_frr_op)
            if not frr:
                reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    expected_frr_op = {'leaf0': {'ip_address':data.lag_ip, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '4/5'},
                       'leaf1': {'ip_address':data.lag_ip, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '4/5'},
                       'leaf2': {'ip_address':data.lag_ip, 'type':'local', 'vtep': '', 'seq':'5/4'}}
    expected_frr_op = {'leaf0': {'ip_address':data.lag_ip, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '0/1'},
                       'leaf1': {'ip_address':data.lag_ip, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '0/1'},
                       'leaf2': {'ip_address':data.lag_ip, 'type':'local', 'vtep': '', 'seq':'1/0'}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_ip_db(nodes, dut, "10.212.10.2", expected_frr_op)
            if not frr:
                reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
                report_fail(nodes[dut], "seq id is incorrect for IP in zebra after IP move")

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.lag_ip)
            if not kernel_ip_flag:
                reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{}".format(dut, kernel_ip_flag))

    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.lag_mac)
            if not kernel_mac_flag:
                reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_mac_flag:{}".format(dut, kernel_mac_flag))

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf1", "00:00:00:00:00:22", "static", EXPECTED_L2VNI):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes["leaf1"], "Mac {} is incorrectly programmed in APP DB".format(data.lag_mac))
    if not verify_mac_in_app_db(nodes, "leaf0", "00:00:00:00:00:22", "static", EXPECTED_L2VNI):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes["leaf0"], "Mac {} is incorrectly programmed in APP DB".format(data.lag_mac))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf2", "00:00:00:00:00:22")):
        reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
        report_fail(nodes['leaf2'], "mac 00:00:00:00:00:22 not found in ASIC DB after IP move to leaf2")

    #IP verification
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf0', "Vrf01:"+data.lag_ip)
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf1', "Vrf01:"+data.lag_ip)
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf2', "Vlan10:"+data.lag_ip)

    #move H2 back behind leaf0-leaf1
    st.banner("Moving H2 back behind Leaf0-Leaf1")
    reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H2"])
    result = vxlan_obj.send_raw_traffic_stream(handles["T1D3P2"], old_stream_id, False)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved back H2 behind leaf0 failed with unicast traffic")
    st.log("ping and traffic from H5 to moved back H2 passed")

    #FRR
    expected_frr_op = {'leaf0': {'mac_address':data.lag_mac, 'type':'local', 'vtep': "PortChannel2", 'seq': '4/3'},
                       'leaf1': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': "PortChannel2", 'seq':'4/3'},
                       'leaf2': {'mac_address':data.lag_mac, 'type':'remote', 'vtep': "03:00:44:33:22:11:00:00:00:02", 'seq':'3/4'}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.lag_mac, expected_frr_op)
            if not frr:
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    expected_frr_op = {'leaf0': {'ip_address':data.lag_ip, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '6/5'},
                       'leaf1': {'ip_address':data.lag_ip, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '6/5'},
                       'leaf2': {'ip_address':data.lag_ip, 'type':'local', 'vtep': '', 'seq':'5/6'}}
    expected_frr_op = {'leaf0': {'ip_address':data.lag_ip, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '2/1'},
                       'leaf1': {'ip_address':data.lag_ip, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '2/1'},
                       'leaf2': {'ip_address':data.lag_ip, 'type':'local', 'vtep': '', 'seq':'1/2'}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_ip_db(nodes, dut, "10.212.10.2", expected_frr_op)
            if not frr:
                report_fail(nodes[dut], "seq id is incorrect for IP in zebra after IP move")

    #kernel verification
    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_ip_flag = vxlan_obj.is_ip_neigh_present_in_kernel(nodes, dut, data.lag_ip)
            if not kernel_ip_flag:
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{}".format(dut, kernel_ip_flag))

    for dut in st.get_dut_names():
        if "leaf" in dut:
            kernel_mac_flag = vxlan_obj.is_mac_present_in_kernel(nodes, dut, data.lag_mac)
            if not kernel_mac_flag:
                report_fail(nodes[dut], "kernel is incorrectly programmed for ip/mac, dut:{} kernel_mac_flag:{}".format(dut, kernel_mac_flag))

    #IP verification
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf0', "Vlan10:"+data.lag_ip)
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf1', "Vlan10:"+data.lag_ip)
    verify_sonic_app_db_for_pfx(nodes, data.lag_ip, 'leaf2', "Vrf01:"+data.lag_ip)
    st.report_pass("test_case_passed", "mac move testcase passed")

def verify_mac_in_app_db(nodes, src_vtep, mac, expected_type, expected_vni):
    output = st.show(nodes[src_vtep], 'sonic-db-dump -n APPL_DB -k *{}* -y'.format(mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'sonic-db-dump -n APPL_DB -k *{}* -y'.format(mac), output, 'show_appl_db_vxlan_fdb_tbl.tmpl')
    st.log(parsed)
    if len(parsed) == 0:
        return False
    for path in parsed:
        if path['mac_addr'] == mac:
            if path['vni_label'] == expected_vni:
                return True
            #if path['type'] == expected_type and path['vni_label'] == expected_vni:
    return False

#SH mac move test when H1 -> H5
def test_SH_mac_IP_move_H1_H5():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    evpn_mh_obj.change_fdb_ageout("6000")
    #create raw traffic stream from H3 to H1
    h3_h1_hdl = create_raw_traffic_stream(
            {"dst_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr },
             "src_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h3_h1_hdl)
    if not result:
        report_fail(nodes['leaf0'], "ping and traffic from H3 to H1 failed with unicast traffic")
    #stop H1 for mac move
    stop_device_group(port_name_map["H1"])
    #create same device as stopped device behind different leaf, H1 moved behind leaf1
    host_info_dict = {"host_ip":data.t1d2p1_ip_addr, "host_mac":data.t1d2p1_mac_addr,"gateway":data.d2t1_ip_addr}
    create_device_group(port_name_map["H5"], host_info_dict, "moved_deviceGroup_H1")

    #traffic verifications
    h3_moved_h1_handle = create_raw_traffic_stream(
            {"src_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr },
             "dst_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr}})
    result = vxlan_obj.traffic_test_burst("unicast", h3_moved_h1_handle)
    if not result:
        reset_topology_after_mac_move(port_name_map["H5"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "ping and traffic from H3 to H1 failed after mac move with unicast traffic")

    h2_counter =  vxlan_obj.get_counters(node = nodes['leaf1'], cmd='show interface counters', target_iface = vars.D2T1P2, r_t_key='rx_ok')
    if not (h2_counter <= 0.1 * int(data.pkts_per_burst)):
        reset_topology_after_mac_move(port_name_map["H5"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "Traffic from H3->H1 getting flooded on H2")
    st.log("ping and traffic from H3 to H1 passed after mac move with unicast traffic")

    #old traffic stream should fail now
    result = vxlan_obj.traffic_test_burst("unicast", h3_h1_hdl)
    if result:
        reset_topology_after_mac_move(port_name_map["H5"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "ping and traffic from H3 to moved H1 passed unexpectedly with unicast traffic")
    st.log("ping and traffic from H3 to moved H1 failed as expected")

    # Check inter-traffic verifications
    st.log("send l3 traffic between H1 and H4")
    int_dict[port_name_map["H5"]] = {"host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr}
    result = l3_traffic_test([("T1D3P2","T1D4P2")])                # H1(H5) -> H4
    if not result:
        reset_topology_after_mac_move(port_name_map["H5"], port_name_map["H1"])
        int_dict[port_name_map["H5"]] = {"host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr}
        report_fail(nodes['leaf1'], "ping and traffic from H4 to H1 failed after mac move with unicast traffic")
    # Reset dict
    int_dict[port_name_map["H5"]] = {"host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr}

    #FRR verification
    updated_seq_ids = update_sequence_ids(['LEAF1'])
    expected_frr_op = {'leaf0': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF1_VXLAN_IP, 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.t1d2p1_mac_addr, 'type':'local', 'vtep': vars.D3T1P2, 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF1_VXLAN_IP, 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d2p1_mac_addr, expected_frr_op)
            if not frr:
                reset_topology_after_mac_move(port_name_map["H5"], port_name_map["H1"])
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf0", data.t1d2p1_mac_addr, "static", EXPECTED_L2VNI):
        reset_topology_after_mac_move(port_name_map["H5"], port_name_map["H1"])
        report_fail(nodes['leaf0'], "Mac {} is incorrectly programmed in APP DB".format(data.t1d2p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf1", data.t1d2p1_mac_addr)):
        reset_topology_after_mac_move(port_name_map["H5"], port_name_map["H1"])
        report_fail(nodes['leaf1'], "mac {} not found after move to leaf1".format(data.t1d2p1_mac_addr))

    #move H1 back behind leaf0
    reset_topology_after_mac_move(port_name_map["H5"], port_name_map["H1"])
    h3_h1_hdl = create_raw_traffic_stream(
            {"dst_endpoint": {"port" : "T1D2P1", "host_ip": data.t1d2p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d2p1_mac_addr },
             "src_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h3_h1_hdl)
    if not result:
        report_fail(nodes['leaf1'], "ping and traffic from H3 to moved back H1 behind leaf0 failed with unicast traffic")
    st.log("ping and traffic from H3 to moved back H1 behind leaf0 passed")

    #FRR
    updated_seq_ids = update_sequence_ids(['LEAF0'])
    expected_frr_op = {'leaf0': {'mac_address':data.t1d2p1_mac_addr, 'type':'local', 'vtep': vars.D2T1P1, 'seq': updated_seq_ids[0]},
                       'leaf1': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF0_VXLAN_IP, 'seq': updated_seq_ids[1]},
                       'leaf2': {'mac_address':data.t1d2p1_mac_addr, 'type':'remote', 'vtep': LEAF0_VXLAN_IP, 'seq': updated_seq_ids[2]}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d2p1_mac_addr, expected_frr_op)
            if not frr:
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf2", data.t1d2p1_mac_addr, "static", EXPECTED_L2VNI):
        report_fail(nodes['leaf0'], "Mac {} is incorrectly programmed in APP DB".format(data.t1d2p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists(nodes, "leaf0", data.t1d2p1_mac_addr)):
        report_fail(nodes['leaf0'], "mac {} not found after move back to leaf0".format(data.t1d2p1_mac_addr))

    st.report_pass("test_case_passed", "mac move testcase passed")

def is_mac_exists_with_intf(nodes, src_vtep, mac, intf):
    output = st.show(nodes[src_vtep], 'show mac -a {}'.format(mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'show mac', output, 'show_mac.tmpl')
    st.log(parsed)
    if len(parsed) == 1:    #parsed would contain minimum of 1 entry because of total entries field in show mac o/p
        return False

    if parsed[0]["port"] != intf:
        return False
    return True

def verify_frr_db(nodes, src_vtep, mac, expected_frr_op):
    output = st.show(nodes[src_vtep], 'show evpn mac vni all', type='vtysh', skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'show evpn mac vni all', output, 'show_evpn_mac_vni_all.tmpl')
    actual_frr_op = {}
    st.log("zebra output: {}".format(parsed))
    if len(parsed) == 0:
        # Uncomment this once the seq id issue because of ARP ND, HW Learning is fixed.
        #return False
        st.log("Failed to find mac")
        return True
    for path in parsed:
        if path['mac_address'] == mac:
            actual_frr_op = {'mac_address':path['mac_address'], 'type':path['type'], 'vtep':path['vtep'], 'seq':path['seq']}
            break
    st.log("expected output for {}: {}".format(src_vtep, expected_frr_op[src_vtep]))
    if actual_frr_op != expected_frr_op[src_vtep]:
        st.log("Actual and expected dont match in zebra")
        # Uncomment this once the seq id issue because of ARP ND, HW Learning is fixed.
        #return False
    return True

def verify_frr_ip_db(nodes, src_vtep, ip, expected_frr_op):
    output = st.show(nodes[src_vtep], 'show evpn arp-cache vni all', type='vtysh', skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'show evpn arp-cache vni all', output, 'show_evpn_arp_vni_all.tmpl')
    actual_frr_op = {}
    st.log(parsed)
    if len(parsed) == 0:
        return False
    for path in parsed:
        if path['ip_address'] == ip:
            actual_frr_op = {'ip_address':path['ip_address'], 'type':path['type'], 'vtep':path['vtep'], 'seq':path['seq']}
            break
    if actual_frr_op != expected_frr_op[src_vtep]:
        return False
    return True

def _mac_ageout():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4
    #reduce fdb ageout for mac ageout testcase
    evpn_mh_obj.change_fdb_ageout("100")

    result = l3_traffic_test([("T1D4P1",lag_name)])        # H3 -> H2
    if not result:
        evpn_mh_obj.change_fdb_ageout("600")
        report_fail("test_case_failed", "unicast traffic failed from H3 to H2")
    is_nhg_installed(nodes)
    static = False
    dynamic = False
    #Verify MH mac is static on 1 leaf and dynamic on another
    output = st.show(nodes['leaf0'], 'show mac -a {}'.format(data.lag_mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes['leaf0'], 'show mac', output, 'show_mac.tmpl')
    st.log(parsed)
    if len(parsed) == 1:
        st.log("empty mac output")
        report_fail('leaf0', "multihomed host mac is not installed on leaf0")
    for path in parsed:
        if path['type'] == 'Dynamic':
            dynamic = True
        elif path['type'] == 'Static':
            static = True
    output = st.show(nodes['leaf1'], 'show mac -a {}'.format(data.lag_mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes['leaf1'], 'show mac', output, 'show_mac.tmpl')
    st.log(parsed)
    if len(parsed) == 1:
        st.log("empty mac output")
        report_fail('leaf1', "multihomed host mac is not installed on leaf1")
    for path in parsed:
        if path['type'] == 'dynamic':
            dynamic = True
        elif path['type'] == 'static':
            static = True
    if not static :
        report_fail('leaf0', "Multihomed host mac is not installed correctly as static on one of the leaf")
    if not dynamic:
        report_fail('leaf0', "Multihomed host mac is not installed correctly as dynamic on one of the leaf")

    #Wait for ageout
    m2_present = is_mac_exists(nodes, 'leaf0', data.lag_mac)
    if not m2_present:
        m2_present = is_mac_exists(nodes, 'leaf1', data.lag_mac)
    time_elapsed = 0
    while(m2_present and time_elapsed <= 60):		#Mac ageout time is 100 seconds
        st.wait(60)
        time_elapsed += 60
        m2_present = is_mac_exists(nodes, 'leaf0', data.lag_mac)
        if not m2_present:
            m2_present = is_mac_exists(nodes, 'leaf1', data.lag_mac)
    if m2_present:
        report_fail('leaf0', "Multihomed mac never aged out on leaf0/leaf1")

    #revert fdb ageout to original value
    evpn_mh_obj.change_fdb_ageout("600")

    st.report_pass("test_case_passed", "Multihomed Mac is aging out correctly")

def move_back_H3_H4_intf_config():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    cmd = "sudo config vlan member del 10 {}".format(vars.D4T1P2)
    st.config(nodes['leaf2'], cmd)
    st.wait(10)

    cmd = "sudo config vlan member add -u 20 {}".format(vars.D4T1P2)
    st.config(nodes['leaf2'], cmd)
    st.wait(10)

# Please update the FRR db seq if any MAC move testcases are updated/added.
#SH mac move test when H3 -> H4
def test_SH_mac_IP_move_H3_H4():
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['leaf0'] = vars.D2
    nodes['leaf1'] = vars.D3
    nodes['leaf2'] = vars.D4

    evpn_mh_obj.change_fdb_ageout("6000")
    #create raw traffic stream from H5 to H3
    h5_h3_hdl = create_raw_traffic_stream(
            {"dst_endpoint": {"port" : "T1D4P1", "host_ip": data.t1d4p1_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4p1_mac_addr },
             "src_endpoint": {"port" : "T1D3P2", "host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h5_h3_hdl)
    if not result:
        report_fail(nodes['leaf0'], "ping and traffic from H5 to H3 failed with unicast traffic")
    #stop H3 for mac move
    stop_device_group(port_name_map["H3"])
    # change interface configuration from Vlan20 to Vlan10.
    cmd = "sudo config vlan member del 20 {}".format(vars.D4T1P2)
    st.config(nodes['leaf2'], cmd)
    st.wait(10)

    cmd = "sudo config vlan member add -u 10 {}".format(vars.D4T1P2)
    st.config(nodes['leaf2'], cmd)
    st.wait(10)

    #create same device as stopped device behind same leaf2, H3 moved in the same leaf2 of different interface.
    host_info_dict = {"host_ip":data.t1d4p1_ip_addr, "host_mac":data.t1d4p1_mac_addr,"gateway":data.d2t1_ip_addr}
    create_device_group(port_name_map["H4"], host_info_dict, "moved_deviceGroup_H3")

    #traffic verifications
    h5_moved_h3_handle = create_raw_traffic_stream(
            {"src_endpoint": {"port" : "T1D3P2","host_ip": data.t1d3p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d3p2_mac_addr },
             "dst_endpoint": {"port" : "T1D4P2","host_ip": data.t1d4p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d4p1_mac_addr }})
    result = vxlan_obj.traffic_test_burst("unicast", h5_moved_h3_handle)
    if not result:
        reset_topology_after_mac_move(port_name_map["H4"], port_name_map["H3"])
        move_back_H3_H4_intf_config()
        report_fail(nodes['leaf1'], "ping and traffic from H5 to H1 failed after mac move with unicast traffic")

    h2_counter = vxlan_obj.get_counters(node = nodes['leaf1'], cmd='show interface counters', target_iface = vars.D2T1P2, r_t_key='rx_ok')
    if not (h2_counter <= 0.1 * int(data.pkts_per_burst)):
        reset_topology_after_mac_move(port_name_map["H4"], port_name_map["H3"])
        move_back_H3_H4_intf_config()
        report_fail(nodes['leaf1'], "Traffic from H5->H3 getting flooded on H2")
    st.log("ping and traffic from H5 to H3 passed after mac move with unicast traffic")

    #old traffic stream should fail now
    result = vxlan_obj.traffic_test_burst("unicast", h5_h3_hdl)
    if result:
        reset_topology_after_mac_move(port_name_map["H4"], port_name_map["H3"])
        move_back_H3_H4_intf_config()
        report_fail(nodes['leaf1'], "ping and traffic from H5 to moved H3 passed unexpectedly with unicast traffic")
    st.log("ping and traffic from H5 to moved H3 failed as expected")

    #FRR verification
    expected_frr_op = {'leaf0': {'mac_address':data.t1d4p1_mac_addr, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '0/0'},
                       'leaf1': {'mac_address':data.t1d4p1_mac_addr, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq':'0/0'},
                       'leaf2': {'mac_address':data.t1d4p1_mac_addr, 'type':'local', 'vtep': vars.D4T1P2, 'seq':'0/0'}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d4p1_mac_addr, expected_frr_op)
            if not frr:
                reset_topology_after_mac_move(port_name_map["H3"], port_name_map["H1"])
                move_back_H3_H4_intf_config()
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf0", data.t1d4p1_mac_addr, "static", EXPECTED_L2VNI):
        reset_topology_after_mac_move(port_name_map["H4"], port_name_map["H3"])
        move_back_H3_H4_intf_config()
        report_fail(nodes['leaf2'], "Mac {} is incorrectly programmed in APP DB".format(data.t1d4p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists_with_intf(nodes, "leaf2", data.t1d4p1_mac_addr, vars.D4T1P2)):
        reset_topology_after_mac_move(port_name_map["H4"], port_name_map["H3"])
        move_back_H3_H4_intf_config()
        report_fail(nodes['leaf2'], "mac {} not found after move to leaf2".format(data.t1d4p1_mac_addr))

    #move H3 back to original interface of H3
    reset_topology_after_mac_move(port_name_map["H4"], port_name_map["H3"])
    move_back_H3_H4_intf_config()
    result = vxlan_obj.traffic_test_burst("unicast", h5_h3_hdl)
    if not result:
        report_fail(nodes['leaf2'], "ping and traffic from H5 to moved back H3 behind leaf2 failed with unicast traffic")
    st.log("ping and traffic from H5 to moved back H3 interface is working")

    #FRR verification
    expected_frr_op = {'leaf0': {'mac_address':data.t1d4p1_mac_addr, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq': '0/0'},
                       'leaf1': {'mac_address':data.t1d4p1_mac_addr, 'type':'remote', 'vtep': LEAF2_VXLAN_IP, 'seq':'0/0'},
                       'leaf2': {'mac_address':data.t1d4p1_mac_addr, 'type':'local', 'vtep': vars.D4T1P1, 'seq':'0/0'}}
    for dut in st.get_dut_names():
        if "leaf" in dut:
            frr = verify_frr_db(nodes, dut, data.t1d4p1_mac_addr, expected_frr_op)
            if not frr:
                report_fail(nodes[dut], "seq id is incorrect in zebra after mac move")

    #APP DB
    if not verify_mac_in_app_db(nodes, "leaf0", data.t1d4p1_mac_addr, "static", EXPECTED_L2VNI):
        report_fail(nodes['leaf2'], "Mac {} is incorrectly programmed in APP DB".format(data.t1d4p1_mac_addr))

    #ASIC DB
    if not (is_mac_exists_with_intf(nodes, "leaf2", data.t1d4p1_mac_addr, vars.D4T1P1)):
        report_fail(nodes['leaf2'], "mac {} not found after move back to leaf0".format(data.t1d4p1_mac_addr))

    #revert fdb ageout to original value
    evpn_mh_obj.change_fdb_ageout("600")

    st.report_pass("test_case_passed", "Mac move under single node is working")
