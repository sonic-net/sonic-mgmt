"""
PFC Test over L2VNI (VXLAN L2 Bridged Traffic)

Tests Priority Flow Control (PFC) behavior with L2VNI stretched VLAN traffic.
Unlike L3VNI where traffic is routed, L2VNI traffic is bridged across the VXLAN fabric.

Topology: 2x Spine + 2 Leafs
    SD1 -- Spine0   - D1
    SD2 -- Spine1   - D2
    SD3 -- Leaf0    - D3
    SD4 -- Leaf1    - D4

Traffic Path (L2 Bridged):
    IXIA (T1D3P1) --> Leaf0 --> Spine --> Leaf1 --> IXIA (T1D4P1)
    Both endpoints are in same VLAN 100 (stretched via VNI 2727)
"""

import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import tests.cisco.tortuga.vxlan.vxlan_utils as vxlan_obj
import qos_test_utils as common_util
import traffic_stream_ixia_api as stream_api
import qos_test_utils
import time

# Use the L2VNI config file from vxlan directory
CONFIGS_FILE = '../../qos/pfc/vxlan_pfc_l2vni_2x2.yaml'

data = SpyTestDict()

# L2VNI uses same subnet on both ends (bridged traffic)
data.t1d3_ip6_addr = "2001::1"
data.t1d3_mac_addr = "00:0a:01:00:11:01"
data.t1d4_ip6_addr = "2001::2"
data.t1d4_mac_addr = "00:0a:01:00:12:01"
data.d3t1_ip6_addr = "2001::254"  # Gateway (not really used for L2)
data.d4t1_ip6_addr = "2001::254"  # Same gateway (L2 bridged)

# Traffic parameters (matching what vxlan_obj expects)
data.traffic_run_time = 60
data.tc = 3  # Traffic Class for PFC-enabled lossless queue
data.config_vrfs = []
data.circuit_endpoint_type = "ipv6"
data.frame_size = "1000"
data.transmit_mode = "continuous"
data.pkts_per_burst = "100"
data.rate_percent = "90"
data.vlan_id = "100"
data.mask = "64"
data.counters_threshold = 10
data.tgen_stats_threshold = 20
data.tgen_rate_pps = '1000'
data.tgen_l3_len = '500'
data.clear_parallel = True

# VTEP IPs for L2VNI topology
LEAF0_VTEP_IP = 'fd27::280:10f1:25f'
LEAF1_VTEP_IP = 'fd27::22d:b87f:214b'


def get_nodes():
    """Get node mapping using shared utility."""
    return qos_test_utils.get_nodes()


def config_node(node, config, type='', skip_errors=False):
    if type:
        st.config(node, config, type=type, skip_error_check=skip_errors, conf=True)
    else:
        st.config(node, config, skip_error_check=skip_errors, conf=True)


def config_static(node, config_domain, add=True):
    """Configure or deconfigure static configs from YAML template."""
    nodes = get_nodes()
    domain = 'vtysh' if config_domain == 'bgp' else ''
    # Use skip_errors=True for sonic config to handle pre-existing state
    skip_errors = (config_domain != 'bgp')

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain, skip_errors=skip_errors)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain, skip_errors=True)


def shutdown_links_for_congestion(nodes):
    """
    Shutdown redundant links to create congestion.
    Forces traffic through single path between Leaf0-Spine0-Leaf1.
    """
    vars = st.get_testbed_vars()
    st.banner("Shutting down redundant links to create congestion")
    
    # Shut Spine1 links to force all traffic through Spine0
    st.log(f"Shutting down {vars.D3D2P1} on Leaf0 (to Spine1)")
    st.config(nodes['leaf0'], f"sudo config interface shutdown {vars.D3D2P1}")
    st.log(f"Shutting down {vars.D4D2P1} on Leaf1 (to Spine1)")
    st.config(nodes['leaf1'], f"sudo config interface shutdown {vars.D4D2P1}")

    # Shut Leaf0↔Leaf1 direct link if it exists (prevents bypassing spine)
    qos_test_utils.shutdown_leaf_to_leaf_links(nodes)
    
    st.wait(5)


def startup_links_after_test(nodes):
    """Bring back up the links that were shutdown."""
    vars = st.get_testbed_vars()
    st.banner("Bringing up links after test")
    
    st.config(nodes['leaf0'], f"sudo config interface startup {vars.D3D2P1}")
    st.config(nodes['leaf1'], f"sudo config interface startup {vars.D4D2P1}")
    
    st.wait(5)


@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    """Module-level setup: reload QoS config."""
    st.banner("Reloading QoS configuration on all DUTs")
    vars = st.get_testbed_vars()
    for dut in st.get_dut_names():
        stream_api.init_qos_on_dut(dut)
        qos_test_utils.cleanup_config(dut)

    # Set traffic parameters based on HW or SIM
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])
    if dut_type == "sim":
        data.rate_percent = "0.005"
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "100"
        data.frame_size = "100"
    else:
        data.rate_percent = "99"
        data.transmit_mode = "continuous"
        data.frame_size = "1000"
        data.pkts_per_burst = "2000"
    
    # Always set circuit_endpoint_type for IPv6 traffic
    data.circuit_endpoint_type = "ipv6"
    
    yield


@pytest.fixture(scope="function", autouse=True)
def l2vni_config_hooks():
    """Function-level fixture to configure L2VNI topology."""
    global updated_config_file
    vars = st.get_testbed_vars()
    nodes = get_nodes()
    
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE, vars)
    
    # Apply sonic and BGP configs
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node in config_list.keys():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    
    # Wait for BGP to converge
    st.wait(60)
    
    yield
    
    # Teardown
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node in reversed(list(config_list.keys())):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
    
    vxlan_obj.remove_temp_config(updated_config_file)


def setup_l2_traffic_stream(data, tc):
    """
    Setup L2 bridged traffic stream at high line rate.
    Both endpoints are in same VLAN (stretched via VXLAN).
    """
    vars = st.get_testbed_vars()
    
    # Get DSCP value for the target TC
    nodes = get_nodes()
    dscp = common_util.convert_tc_to_dscp(nodes['leaf0'], tc)
    st.log(f"Using DSCP {dscp} for TC {tc}")
    
    # Configure TGEN interfaces
    int_dict = {
        'T1D3P1': {
            'host_ip': data.t1d3_ip6_addr,
            'gateway': data.d3t1_ip6_addr,
            'mac': data.t1d3_mac_addr
        },
        'T1D4P1': {
            'host_ip': data.t1d4_ip6_addr,
            'gateway': data.d4t1_ip6_addr,
            'mac': data.t1d4_mac_addr
        }
    }
    
    handles = vxlan_obj.config_tgen_interface(int_dict, 'ipv6')
    
    # Configure traffic with PFC-enabled DSCP
    data.ip_dscp = int(dscp)
    data.traffic_class = int(dscp) << 2
    
    stream_list = [('T1D3P1', 'T1D4P1')]
    data.addr_family = 'ipv6'
    streams = vxlan_obj.config_traffic_item(stream_list, handles, int_dict, data, ping=True, dscp=int(dscp))
    for key, item in streams.items():
        stream_api.set_pfc_priority_group(item['tg_handle'], item['traffic_result'], tc)
    
    return streams


def run_traffic_and_capture_pfc(streams_dict, nodes, pfc_interfaces, tc, run_time):
    """Run traffic and capture PFC counters before/after."""
    stream_ids = []
    tg = None
    
    # Collect stream handles
    for traffic_item, values in streams_dict.items():
        tg = values['tg_handle']
        stream_id = values['stream_id']
        stream_ids.append(stream_id)
        st.log(f"Applying stream: {traffic_item}")
        tg.tg_traffic_control(action='apply', stream_handle=stream_id)
    
    # Capture PFC before
    st.banner("Capturing PFC counters BEFORE traffic")
    pfc_before = qos_test_utils.capture_pfc_counters(nodes, pfc_interfaces, tc)
    
    # Clear counters
    st.banner("Clearing counters on all DUTs")
    for dut in st.get_dut_names():
        st.config(dut, "sonic-clear counters\nsonic-clear pfccounters", skip_error_check=True)
    st.wait(5)
    
    # Start traffic
    st.banner(f"Starting L2 bridged traffic for {run_time} seconds")
    tg.tg_traffic_control(action='run')
    st.wait(run_time)
    
    # Stop traffic
    st.banner("Stopping traffic")
    tg.tg_traffic_control(action='stop')
    st.wait(5)
    
    # Capture PFC after
    st.banner("Capturing PFC counters AFTER traffic")
    pfc_after = qos_test_utils.capture_pfc_counters(nodes, pfc_interfaces, tc)
    
    # Print deltas
    qos_test_utils.print_pfc_counter_deltas(pfc_before, pfc_after)
    
    # Get traffic stats
    flag = True
    for traffic_item, values in streams_dict.items():
        tg = values['tg_handle']
        stream_id = values['stream_id']
        port_handle = values['port_handle']
        
        traffic_stat = tgapi.get_traffic_stats(tg, mode='traffic_item',
                                               port_handle=port_handle,
                                               direction='tx',
                                               stream_handle=stream_id)
        
        tx_pkts = traffic_stat['tx']['total_packets']
        rx_pkts = traffic_stat['rx']['total_packets']
        
        st.log(f"TX: {tx_pkts}, RX: {rx_pkts}")
        
        if tx_pkts > 0:
            loss_pct = ((tx_pkts - rx_pkts) / tx_pkts) * 100
            st.log(f"Packet Loss: {loss_pct:.2f}%")
        
        if rx_pkts < 0.98 * tx_pkts:
            st.log("Traffic test FAILED - too much loss")
            flag = False
    
    return flag, pfc_before, pfc_after


def test_pfc_l2vni_basic():
    """
    Test PFC with L2VNI bridged traffic at high line rate.
    
    Traffic Path (L2 Bridged - same VLAN stretched via VXLAN):
        IXIA (2001::1) --> Leaf0 [VLAN 100] --> VNI 2727 --> Leaf1 [VLAN 100] --> IXIA (2001::2)
    
    With Spine1 links shut, traffic goes through single Spine0 path.
    At 99% line rate, this should trigger PFC from Spine0 to Leaf0.
    """
    vars = st.get_testbed_vars()
    st.log('Started test_pfc_l2vni_basic')
    nodes = get_nodes()
    
    try:
        # Verify VTEP state
        st.banner("Verifying VTEP state")
        vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP)
        
        # Shutdown redundant links to create congestion path
        shutdown_links_for_congestion(nodes)
        
        # Setup traffic stream with PFC-enabled TC
        st.banner(f"Setting up L2 traffic stream with TC {data.tc}")
        streams_dict = setup_l2_traffic_stream(data, data.tc)
        st.log(f"Streams configured: {streams_dict}")
        
        # Define PFC interfaces to monitor
        pfc_interfaces = {
            'leaf0': [vars.D3T1P1, vars.D3D1P1],
            'spine0': [vars.D1D3P1, vars.D1D4P1],
            'leaf1': [vars.D4D1P1, vars.D4T1P1]
        }
        
        # Run traffic and capture PFC
        result, pfc_before, pfc_after = run_traffic_and_capture_pfc(
            streams_dict, nodes, pfc_interfaces, data.tc, data.traffic_run_time
        )
        
        # Show queue counters for relevant interfaces
        st.banner("Queue counters after traffic")
        for node_name, intfs in pfc_interfaces.items():
            for intf in intfs:
                st.show(nodes[node_name], f"show queue counters {intf}", skip_tmpl=True)
        
        if result:
            st.report_pass("test_case_passed", "test_pfc_l2vni_basic passed")
        else:
            st.report_fail("test_case_failed", "test_pfc_l2vni_basic failed")
    
    except Exception as e:
        st.error(f"Exception: {str(e)}")
        st.report_fail("test_case_failed", str(e))
    
    finally:
        # Cleanup
        if 'streams_dict' in dir() and streams_dict:
            qos_test_utils.remove_traffic_streams(streams_dict)
        
        startup_links_after_test(nodes)
