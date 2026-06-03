import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import tests.cisco.tortuga.vxlan.vxlan_utils as vxlan_obj
import qos_test_utils as common_util
import traffic_stream_ixia_api as stream_api
import qos_test_utils
import time

## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  DUT #1 -- Spine0  - D1
##  DUT #2 -- Spine1  - D2
##  DUT #3 -- Leaf0   - D3
##  DUT #4 -- Leaf1   - D4

## tgen Stream Config
data = SpyTestDict()
data.config_vrfs = []

data.my_dut_list = None
data.local = None
data.remote = None

NO_OF_RETRIES = 9

def get_nodes():
    """Get or initialize the nodes dictionary. Caches in data for reuse."""
    nodes = qos_test_utils.get_nodes()
    return nodes


def shutdown_links_for_congestion(nodes):
    """
    Shutdown redundant links to create congestion on single path.
    Shuts down one link each on Leaf0→Spine0 and Leaf1→Spine0.
    Shuts down both links on Leaf0→Spine1 and Leaf1→Spine1.
    This forces all traffic through a single Spine0 link (D3D1P1 and D4D1P1).
    """
    vars = st.get_testbed_vars()
    st.banner("Shutting down redundant links to create congestion")
    
    # Shut one link to Spine0 (keep P1 up for traffic)
    st.log(f"Shutting down {vars.D3D1P2} on Leaf0 (to Spine0)")
    st.config(nodes['leaf0'], f"sudo config interface shutdown {vars.D3D1P2}")
    st.log(f"Shutting down {vars.D4D1P2} on Leaf1 (to Spine0)")
    st.config(nodes['leaf1'], f"sudo config interface shutdown {vars.D4D1P2}")
    
    # Shut all links to Spine1 to force traffic through Spine0
    st.log(f"Shutting down {vars.D3D2P1} on Leaf0 (to Spine1)")
    st.config(nodes['leaf0'], f"sudo config interface shutdown {vars.D3D2P1}")
    if hasattr(vars, 'D3D2P2'):
        st.log(f"Shutting down {vars.D3D2P2} on Leaf0 (to Spine1)")
        st.config(nodes['leaf0'], f"sudo config interface shutdown {vars.D3D2P2}")
    st.log(f"Shutting down {vars.D4D2P1} on Leaf1 (to Spine1)")
    st.config(nodes['leaf1'], f"sudo config interface shutdown {vars.D4D2P1}")
    if hasattr(vars, 'D4D2P2'):
        st.log(f"Shutting down {vars.D4D2P2} on Leaf1 (to Spine1)")
        st.config(nodes['leaf1'], f"sudo config interface shutdown {vars.D4D2P2}")

    # Shut Leaf0↔Leaf1 direct link if it exists (prevents bypassing spine)
    qos_test_utils.shutdown_leaf_to_leaf_links(nodes)
    
    st.wait(5)  # Allow routing to converge


def startup_links_after_test(nodes):
    """
    Bring back up the links that were shutdown for congestion testing.
    """
    vars = st.get_testbed_vars()
    st.banner("Bringing up links after congestion test")
    
    # Bring up Spine0 links
    st.log(f"Starting up {vars.D3D1P2} on Leaf0 (to Spine0)")
    st.config(nodes['leaf0'], f"sudo config interface startup {vars.D3D1P2}")
    st.log(f"Starting up {vars.D4D1P2} on Leaf1 (to Spine0)")
    st.config(nodes['leaf1'], f"sudo config interface startup {vars.D4D1P2}")
    
    # Bring up Spine1 links
    st.log(f"Starting up {vars.D3D2P1} on Leaf0 (to Spine1)")
    st.config(nodes['leaf0'], f"sudo config interface startup {vars.D3D2P1}")
    if hasattr(vars, 'D3D2P2'):
        st.log(f"Starting up {vars.D3D2P2} on Leaf0 (to Spine1)")
        st.config(nodes['leaf0'], f"sudo config interface startup {vars.D3D2P2}")
    st.log(f"Starting up {vars.D4D2P1} on Leaf1 (to Spine1)")
    st.config(nodes['leaf1'], f"sudo config interface startup {vars.D4D2P1}")
    if hasattr(vars, 'D4D2P2'):
        st.log(f"Starting up {vars.D4D2P2} on Leaf1 (to Spine1)")
        st.config(nodes['leaf1'], f"sudo config interface startup {vars.D4D2P2}")
    
    st.wait(5) 

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    vars = st.get_testbed_vars()
    ### Check dut is HW or SIM ###
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])

    ### Reload QoS config on all DUTs to ensure QoS maps are bound to all interfaces ###
    st.banner("Reloading QoS configuration on all DUTs")
    for dut in st.get_dut_names():
        stream_api.init_qos_on_dut(dut)
        qos_test_utils.cleanup_config(dut)

    if  dut_type == "sim":
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "100"
        ### Using lower line rate for SIM tgen ###
        data.rate_percent = "0.005"
        data.circuit_endpoint_type = "ipv6"
        data.frame_size = "100"
    else:
        data.mode ="create"
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "2000"
        data.rate_percent = "10"
        data.circuit_endpoint_type = "ipv6"
        data.frame_size = "1000"
    yield

data.d3t1_ip_addr = "100.100.100.254"
data.t1d3_ip_addr = "100.100.100.200"
data.d3t1_ip6_addr = "2002:db8:1::1"
data.t1d3_ip6_addr = "2002:db8:1::2"
data.t1d3_mac_addr = "00:0a:01:00:11:01"

data.d4t1_ip_addr = "100.100.101.254"
data.t1d4_ip_addr = "100.100.101.200"
data.d4t1_ip6_addr = "2003:db8:1::1"
data.t1d4_ip6_addr = "2003:db8:1::2"
data.t1d4_mac_addr = "00:0a:01:00:12:01"
data.mask = "24"
data.counters_threshold = 10
data.tgen_stats_threshold = 20
data.tgen_rate_pps = '1000'
data.tgen_l3_len = '500'
data.traffic_run_time = 60  # Run traffic for 60 seconds
data.clear_parallel = True
data.tc = 3  # Traffic Class for PFC-enabled lossless queue

# Links are obtained from testbed vars:
# D3D1P1, D3D1P2 = Leaf0 (D3) to Spine0 (D1) ports
# D3D2P1, D3D2P2 = Leaf0 (D3) to Spine1 (D2) ports
# D4D1P1, D4D1P2 = Leaf1 (D4) to Spine0 (D1) ports
# D4D2P1, D4D2P2 = Leaf1 (D4) to Spine1 (D2) ports

REMOTE_VTEP_COUNT = '1'
SPINE0_VTEP_IP = '2001:db8:1::1'
LEAF0_VTEP_IP  = '2001:db8:1::2'
LEAF1_VTEP_IP  = '2001:db8:1::3'

# Path relative to vxlan_utils.py (/tests/cisco/tortuga/vxlan/)
CONFIGS_FILE = '../../qos/pfc/vxlan_pfc_l3vni.yaml'

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        # Use skip_error_check=True for sonic config to handle pre-existing state
        st.config(node, config, skip_error_check=True, conf=True)

def config_static(node, config_domain, add=True):
    nodes = get_nodes()

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)


def run_traffic_continuous(streams_dict, run_time=60):
    """
    Run traffic at 99% line rate in continuous mode and collect stats.
    
    Args:
        streams_dict: Dictionary of traffic streams from traffic_setup()
        run_time: How long to run traffic in seconds (default 60)
    
    Returns:
        tuple: (bool, list) - (True if all passed, list of failure reason strings)
    """
    flag = True
    failure_reasons = []
    
    for traffic_item, values in streams_dict.items():
        tg = values['tg_handle']
        stream_id = values['stream_id']
        port_handle = values['port_handle']
        
        # Apply the traffic configuration
        st.banner(f"Applying traffic for {traffic_item}")
        tg.tg_traffic_control(action='apply', stream_handle=stream_id)
        
        # Start traffic
        st.banner(f"Starting continuous traffic at 99% line rate for {run_time} seconds")
        tg.tg_traffic_control(action='run', stream_handle=stream_id)
        
        # Let traffic run
        st.wait(run_time)
        
        # Stop traffic
        st.banner("Stopping traffic")
        tg.tg_traffic_control(action='stop', stream_handle=stream_id)
        st.wait(5)  # Allow stats to settle
        
        # Get traffic statistics
        traffic_stat = tgapi.get_traffic_stats(tg, mode='traffic_item', 
                                                port_handle=port_handle, 
                                                direction='tx', 
                                                stream_handle=stream_id)
        
        # Print detailed traffic statistics
        st.banner(f"TRAFFIC STATISTICS FOR {traffic_item}")
        st.log(f"========== TX Statistics ==========")
        st.log(f"Total Packets TX: {traffic_stat['tx']['total_packets']}")
        st.log(f"Total Bytes TX: {traffic_stat['tx'].get('total_bytes', 'N/A')}")
        st.log(f"TX Rate (pps): {traffic_stat['tx'].get('total_pkt_rate', 'N/A')}")
        st.log(f"TX Rate (bps): {traffic_stat['tx'].get('line_rate', 'N/A')}")
        
        st.log(f"========== RX Statistics ==========")
        st.log(f"Total Packets RX: {traffic_stat['rx']['total_packets']}")
        st.log(f"Total Bytes RX: {traffic_stat['rx'].get('total_bytes', 'N/A')}")
        st.log(f"RX Rate (pps): {traffic_stat['rx'].get('total_pkt_rate', 'N/A')}")
        st.log(f"RX Rate (bps): {traffic_stat['rx'].get('line_rate', 'N/A')}")
        
        # Calculate loss
        tx_pkts = traffic_stat['tx']['total_packets']
        rx_pkts = traffic_stat['rx']['total_packets']
        if tx_pkts > 0:
            loss_pct = ((tx_pkts - rx_pkts) / tx_pkts) * 100
            st.log(f"========== Loss Statistics ==========")
            st.log(f"Packet Loss: {tx_pkts - rx_pkts} packets")
            st.log(f"Packet Loss %: {loss_pct:.2f}%")
        
        # Check pass/fail (allow 2% tolerance)
        if rx_pkts >= 0.98 * tx_pkts and rx_pkts <= 1.02 * tx_pkts:
            st.banner(f"TRAFFIC TEST FOR {traffic_item} PASSED")
        else:
            loss_pct_val = ((tx_pkts - rx_pkts) / tx_pkts * 100) if tx_pkts > 0 else 100
            reason = f"{traffic_item}: {loss_pct_val:.2f}% loss (TX={tx_pkts}, RX={rx_pkts}, drop={tx_pkts - rx_pkts})"
            failure_reasons.append(reason)
            st.banner(f"TRAFFIC TEST FOR {traffic_item} FAILED")
            flag = False
    
    return flag, failure_reasons


def setup_multi_stream_traffic(data, stream_configs, addr_family='ipv6', tc=3, bidirectional=1):
    """
    Setup multiple traffic streams for fan-in congestion testing.
    
    Args:
        data: SpyTestDict with traffic parameters (rate_percent, transmit_mode, etc.)
        stream_configs: List of dicts with stream config:
            [{'src_port': 'T1D3P1', 'src_ip': '...', 'src_gw': '...', 'src_mac': '...',
              'dst_port': 'T1D4P1', 'dst_ip': '...', 'dst_gw': '...', 'dst_mac': '...'}, ...]
        addr_family: 'ipv4' or 'ipv6'
    
    Returns:
        dict: Stream handles for each configured stream
    """
    # Build int_dict with all unique ports
    int_dict = {}
    for cfg in stream_configs:
        if cfg['src_port'] not in int_dict:
            int_dict[cfg['src_port']] = {
                'host_ip': cfg['src_ip'],
                'gateway': cfg['src_gw'],
                'mac': cfg['src_mac']
            }
        if cfg['dst_port'] not in int_dict:
            int_dict[cfg['dst_port']] = {
                'host_ip': cfg['dst_ip'],
                'gateway': cfg['dst_gw'],
                'mac': cfg['dst_mac']
            }
    
    # Configure TGEN interfaces
    handles = vxlan_obj.config_tgen_interface(int_dict, addr_family)
    
    # Build stream list
    stream_list = [(cfg['src_port'], cfg['dst_port']) for cfg in stream_configs]
    
    # Configure traffic items
    dscp = common_util.convert_tc_to_dscp(get_nodes()['leaf0'], tc)
    data.addr_family = addr_family
    streams = vxlan_obj.config_traffic_item(stream_list, handles, int_dict, data, ping=True, dscp=int(dscp), bidirectional=bidirectional)
    for key, item in streams.items():
        stream_api.set_pfc_priority_group(item['tg_handle'], item['traffic_result'], tc)
    
    return streams


def run_multi_stream_traffic(streams_dict, run_time=60):
    """
    Run multiple traffic streams simultaneously and collect stats.
    All streams start together and run for the specified duration.
    
    Args:
        streams_dict: Dictionary of traffic streams
        run_time: How long to run traffic in seconds
    
    Returns:
        tuple: (bool, list) - (True if all passed, list of failure reason strings)
    """
    flag = True
    failure_reasons = []
    stream_ids = []
    tg = None
    
    # Collect all stream IDs first
    st.banner("Applying all traffic streams")
    for traffic_item, values in streams_dict.items():
        tg = values['tg_handle']
        stream_id = values['stream_id']
        stream_ids.append(stream_id)
        st.log(f"Applying stream: {traffic_item} -> {stream_id}")
        tg.tg_traffic_control(action='apply', stream_handle=stream_id)
    
    
    # Start ALL streams at once (no stream_handle = start all)
    st.banner(f"Starting ALL {len(stream_ids)} streams SIMULTANEOUSLY for {run_time} seconds")
    tg.tg_traffic_control(action='run')
    
    # Let traffic run, then collect stats while still flowing for live rates
    stats_wait = max(run_time - 5, run_time // 2)
    st.wait(stats_wait)

    # Collect mid-traffic stats — rates are non-zero only while traffic is running
    st.banner("Collecting stats while traffic is running (live rates)")
    mid_stats = tg.tg_traffic_stats(mode='traffic_item')
    if 'traffic_item' in mid_stats:
        for ti_key, ti_val in mid_stats['traffic_item'].items():
            if ti_key == 'aggregate':
                continue
            tx_info = ti_val.get('tx', {})
            rx_info = ti_val.get('rx', {})
            tx_rate_pps = tx_info.get('total_pkt_rate', '0')
            rx_rate_pps = rx_info.get('total_pkt_rate', '0')
            tx_rate_mbps = tx_info.get('total_pkt_mbit_rate', '0')
            rx_rate_mbps = rx_info.get('total_pkt_mbit_rate', '0')
            tx_l1_bps = tx_info.get('l1_bit_rate', '0')
            rx_l1_bps = rx_info.get('l1_bit_rate', '0')
            loss_pct = rx_info.get('loss_percent', 'N/A')
            st.log(f"  {ti_key}: TX {tx_rate_pps} pps (L2={float(tx_rate_mbps)/1e3:.2f} Gbps, L1={float(tx_l1_bps)/1e9:.2f} Gbps) | "
                   f"RX {rx_rate_pps} pps (L2={float(rx_rate_mbps)/1e3:.2f} Gbps, L1={float(rx_l1_bps)/1e9:.2f} Gbps) | "
                   f"Loss={loss_pct}%")

    # Stop ALL streams
    st.banner("Stopping all streams")
    tg.tg_traffic_control(action='stop')
    
    st.wait(5)  # Allow stats to settle
    
    # Collect and print stats for each stream
    for traffic_item, values in streams_dict.items():
        tg = values['tg_handle']
        stream_id = values['stream_id']
        port_handle = values['port_handle']
        
        traffic_stat = tgapi.get_traffic_stats(tg, mode='traffic_item',
                                                port_handle=port_handle,
                                                direction='tx',
                                                stream_handle=stream_id)
        
        st.banner(f"TRAFFIC STATISTICS FOR {traffic_item}")
        st.log(f"========== TX Statistics ==========")
        st.log(f"Total Packets TX: {traffic_stat['tx']['total_packets']}")
        st.log(f"Total Bytes TX: {traffic_stat['tx'].get('total_bytes', 'N/A')}")
        st.log(f"TX Rate (pps): {traffic_stat['tx'].get('total_pkt_rate', 'N/A')}")
        
        st.log(f"========== RX Statistics ==========")
        st.log(f"Total Packets RX: {traffic_stat['rx']['total_packets']}")
        st.log(f"Total Bytes RX: {traffic_stat['rx'].get('total_bytes', 'N/A')}")
        st.log(f"RX Rate (pps): {traffic_stat['rx'].get('total_pkt_rate', 'N/A')}")
        
        # Calculate effective rates (Gbps)
        tx_bytes = traffic_stat['tx'].get('total_bytes', 0)
        rx_bytes = traffic_stat['rx'].get('total_bytes', 0)
        if run_time > 0 and tx_bytes:
            tx_gbps = float(tx_bytes) * 8 / (run_time * 1e9)
            st.log(f"========== Effective Rates ==========")
            st.log(f"Effective TX Rate: {tx_gbps:.2f} Gbps")
            if rx_bytes:
                rx_gbps = float(rx_bytes) * 8 / (run_time * 1e9)
                st.log(f"Effective RX Rate: {rx_gbps:.2f} Gbps")
        
        # Calculate loss
        tx_pkts = traffic_stat['tx']['total_packets']
        rx_pkts = traffic_stat['rx']['total_packets']
        if tx_pkts > 0:
            loss_pct = ((tx_pkts - rx_pkts) / tx_pkts) * 100
            st.log(f"========== Loss Statistics ==========")
            st.log(f"Packet Loss: {tx_pkts - rx_pkts} packets")
            st.log(f"Packet Loss %: {loss_pct:.2f}%")
        
        # Check pass/fail
        if rx_pkts >= 0.98 * tx_pkts and rx_pkts <= 1.02 * tx_pkts:
            st.banner(f"STREAM {traffic_item} PASSED")
        else:
            loss_pct_val = ((tx_pkts - rx_pkts) / tx_pkts * 100) if tx_pkts > 0 else 100
            reason = f"{traffic_item}: {loss_pct_val:.2f}% loss (TX={tx_pkts}, RX={rx_pkts}, drop={tx_pkts - rx_pkts})"
            failure_reasons.append(reason)
            st.banner(f"STREAM {traffic_item} FAILED")
            flag = False
    
    return flag, failure_reasons


@pytest.fixture(scope="function", autouse=True)
def vxlan_config_hooks():
    nodes = get_nodes()
    vars = st.get_testbed_vars()

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE, vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    st.wait(60)
    yield vxlan_config_hooks

    if updated_config_file and os.path.exists(updated_config_file):
        with open(updated_config_file) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in reversed(config_list.items()):
                config_static(node, 'bgp', add=False)
                st.wait(2)
                config_static(node, 'sonic', add=False)

    for vrf in data.config_vrfs:
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)
    data.config_vrfs = []

    vxlan_obj.remove_temp_config(updated_config_file)

def verify_vtep_state(nodes):
    '''
    Verify VXLAN tunnel state
    '''
    for node in ['leaf0', 'leaf1']:
        dut = nodes[node]
        expected_sip = LEAF0_VTEP_IP if node == 'leaf0' else LEAF1_VTEP_IP
        expected_dip = LEAF1_VTEP_IP if node == 'leaf0' else LEAF0_VTEP_IP
        
        output = st.config(dut, "show vxlan remotevtep")
        output_parsed = st.parse_show(dut, "show vxlan remotevtep", output, "show_vxlan_remote.tmpl")
        iter = 0
        for vtep in output_parsed:
            start_time = time.time()
            while vtep['tun_status'] != 'oper_up' and iter < NO_OF_RETRIES:
                iter += 1
                st.wait(10)
                output = st.config(dut, "show vxlan remotevtep")
                output_parsed = st.parse_show(dut, "show vxlan remotevtep", output, "show_vxlan_remote.tmpl")
                vtep = output_parsed[0]
            
            if iter == NO_OF_RETRIES:
                end_time = time.time()
                iter = 0
                if vtep['tun_status'] == 'oper_down':
                    st.log("Tunnel State is not Up after {} secs".format(end_time - start_time))
                    report_fail(dut, msg='Tunnel State is not up. Status : oper_down')
                else:
                    st.log("Tunnel State is not set after {} secs".format(end_time - start_time))
                    report_fail(dut, msg='Tunnel State is not set')
            
            if vtep['tun_status'] == 'oper_up':
                end_time = time.time()
                st.log("Tunnel State is up after {} secs Status : oper_up".format(end_time - start_time), dut)

            if vtep['src_vtep'] == expected_sip:
                st.log("Source vtep validated", dut)
            else:
                report_fail(dut, msg='Source vtep is not as expected. Found {} Expected {}'.format(vtep['src_vtep'], expected_sip))

            if vtep['dst_vtep'] == expected_dip:
                st.log("Destination vtep validated", dut)
            else:
                report_fail(dut, msg='Destination vtep is not as expected. Found {} Expected {}'.format(vtep['dst_vtep'], expected_dip))

            if vtep['total_count'] == REMOTE_VTEP_COUNT:
                st.log("All remote VTEPs detected", dut)
            else:
                report_fail(dut, msg='Remote Vteps discovered count not as expected. Found {} Expected {}'.format(vtep['total_count'], REMOTE_VTEP_COUNT))

def configure_and_validate_basic_l3vni(overlay_afamily):
    vars = st.get_testbed_vars()
    nodes = get_nodes()

    if overlay_afamily == 'ipv6':
        leaf0_vlan_ip = '2002:db8:1::1/64'
        leaf1_vlan_ip = '2003:db8:1::1/64'
    else:
        leaf0_vlan_ip = '100.100.100.254/24'
        leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    # a. add vrf
    vxlan_obj.config_vrf(nodes['leaf0'], vrf)
    vxlan_obj.config_vrf(nodes['leaf1'], vrf)

    # b. add vlan
    vxlan_obj.config_vlan(nodes['leaf0'], leaf0_vlan, members=[vars.D3T1P1], vrf=vrf)
    vxlan_obj.config_vlan(nodes['leaf1'], leaf1_vlan, members=[vars.D4T1P1], vrf=vrf)

    # c. add dummy vlan
    vxlan_obj.config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf)
    vxlan_obj.config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf)

    # d. add vlan to vni map / e. add vrf to vni map
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

    # f. add IP address on vlan
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    # Start Verification
    if overlay_afamily == 'ipv6':
        leaf0_vrf_prefix = '2002:db8:1::'
        leaf1_vrf_prefix = '2003:db8:1::'
    else:
        leaf0_vrf_prefix = '100.100.100.0'
        leaf1_vrf_prefix = '100.100.101.0'

    vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
    vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')

def deconfigure_basic_l3vni(overlay_afamily):
    vars = st.get_testbed_vars()
    nodes = get_nodes()

    if overlay_afamily == 'ipv6':
        leaf0_vlan_ip = '2002:db8:1::1/64'
        leaf1_vlan_ip = '2003:db8:1::1/64'
    else:
        leaf0_vlan_ip = '100.100.100.254/24'
        leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    # f. remove IP address on vlan
    st.config(nodes['leaf0'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    # e. delete vrf to vni map / d. delete vlan to vni map
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)

    # c. remove dummy vlan
    vxlan_obj.config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf, add=False)
    vxlan_obj.config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf, add=False)

    # b. remove vlan
    vxlan_obj.config_vlan(nodes['leaf0'], leaf0_vlan, members=[vars.D3T1P1], vrf=vrf, add=False)
    vxlan_obj.config_vlan(nodes['leaf1'], leaf1_vlan, members=[vars.D4T1P1], vrf=vrf, add=False)

    # a. track vrf for cleanup
    data.config_vrfs.append(vrf)


# =============================================================================
# Test Case - Direct copy of test_l3vni_v6_v6_vtep_basic_config
# =============================================================================
def test_pfc_vxlan_basic():
    """
    Test: Basic IPv6 traffic over VXLAN L3VNI (IPv6 VTEP underlay)
    
    This is a direct copy of test_l3vni_v6_v6_vtep_basic_config from the working test.
    
    Traffic Path:
        IXIA(2002:db8:1::2) → Leaf0(D3) → Spine(D1) → Leaf1(D4) → IXIA(2003:db8:1::2)
    """
    st.log('Started test_pfc_vxlan_basic')
    nodes = get_nodes()

    try:
        # Configure and Validate basic l3vni configs and route exchanges
        configure_and_validate_basic_l3vni('ipv6')

        # Run traffic test
        data.d3t1_ip6_addr = "2002:db8:1::1"
        data.t1d3_ip6_addr = "2002:db8:1::2"
        data.d4t1_ip6_addr = "2003:db8:1::1"
        data.t1d4_ip6_addr = "2003:db8:1::2"
    
        st.banner("Start to test VxLAN V6 L3 with ping and traffic")
    
        # Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)

        # Override traffic parameters for PFC testing: 99% line rate, continuous mode
        data.rate_percent = "99"
        data.transmit_mode = "continuous"

        # Setup and run traffic at 99% line rate
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv6')
        st.log(streams_dict)
        result, failure_reasons = run_traffic_continuous(streams_dict, run_time=data.traffic_run_time)

        if result:
            st.report_pass("test_case_passed", "test_pfc_vxlan_basic passed")
        else:
            fail_summary = "; ".join(failure_reasons) if failure_reasons else "unknown"
            st.report_fail("test_case_failed", f"test_pfc_vxlan_basic failed: {fail_summary}")

    except Exception as e:
        report_fail("", msg=str(e))
    finally:
        # Remove traffic streams from IXIA
        if 'streams_dict' in dir() and streams_dict:
            qos_test_utils.remove_traffic_streams(streams_dict)

        # Show interface counters on each DUT
        st.banner("Show interface counters on all DUTs")
        for dut in st.get_dut_names():
            st.show(dut, "show int count", skip_tmpl=True)

        # Deconfigure basic l3vni configs
        deconfigure_basic_l3vni('ipv6')

def configure_multi_vni_for_pfc(nodes, vrfs_config, svi_ips):
    """
    Configure multiple VNIs with separate member ports for each leaf.
    Unlike config_multiple_vni, this properly handles different ports per leaf.
    
    vrfs_config format:
    {
        'Vrf02': {
            'vlan': '2',
            'leaf0_members': [vars.D3T1P1],
            'leaf1_members': [vars.D4T1P2],
            'vni': '2000',
            'dummy_vlan': '200'
        },
        ...
    }
    """
    # a. Add VRFs (delete first if stale from a previous interrupted run)
    for vrf in vrfs_config.keys():
        for leaf in ['leaf0', 'leaf1']:
            st.config(nodes[leaf], f"sudo config vrf del {vrf}", skip_error_check=True)
        vxlan_obj.config_vrf(nodes['leaf0'], vrf)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf)

    # b. Add VLANs with correct member ports for each leaf
    for vrf, cfg in vrfs_config.items():
        vxlan_obj.config_vlan(nodes['leaf0'], cfg['vlan'], members=cfg['leaf0_members'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], cfg['vlan'], members=cfg['leaf1_members'], vrf=vrf)

    # c. Add dummy VLANs (for L3VNI)
    for vrf, cfg in vrfs_config.items():
        vxlan_obj.config_vlan(nodes['leaf0'], cfg['dummy_vlan'], vrf=vrf)
        vxlan_obj.config_vlan(nodes['leaf1'], cfg['dummy_vlan'], vrf=vrf)

    # d/e. Add VLAN to VNI map and VRF to VNI map
    for vrf, cfg in vrfs_config.items():
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', cfg['vni'], vrf=vrf, vlan=cfg['dummy_vlan'])
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', cfg['vni'], vrf=vrf, vlan=cfg['dummy_vlan'])

    # f. Add IP addresses on VLANs
    for leaf, ip_list in svi_ips.items():
        for v in ip_list:
            st.config(nodes[leaf], 'sudo config interface ip add {} {}'.format('Vlan' + v['vlan'], v['ip']))


def deconfigure_multi_vni_for_pfc(nodes, vrfs_config, svi_ips):
    """
    Deconfigure multiple VNIs - reverse of configure_multi_vni_for_pfc.
    """
    # f. Remove IP addresses on VLANs
    for leaf, ip_list in svi_ips.items():
        for v in ip_list:
            st.config(nodes[leaf], 'sudo config interface ip rem {} {}'.format('Vlan' + v['vlan'], v['ip']))

    # e/d. Remove VNI maps
    for vrf, cfg in vrfs_config.items():
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', cfg['vni'], vrf=vrf, vlan=cfg['dummy_vlan'], add=False)
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', cfg['vni'], vrf=vrf, vlan=cfg['dummy_vlan'], add=False)

    # c. Remove dummy VLANs
    for vrf, cfg in vrfs_config.items():
        vxlan_obj.config_vlan(nodes['leaf0'], cfg['dummy_vlan'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], cfg['dummy_vlan'], vrf=vrf, add=False)

    # b. Remove VLANs
    for vrf, cfg in vrfs_config.items():
        vxlan_obj.config_vlan(nodes['leaf0'], cfg['vlan'], members=cfg['leaf0_members'], vrf=vrf, add=False)
        vxlan_obj.config_vlan(nodes['leaf1'], cfg['vlan'], members=cfg['leaf1_members'], vrf=vrf, add=False)

    # a. Defer VRF removal to fixture cleanup (after BGP config is removed)
    # VRFs cannot be deleted while BGP VRF config exists
    for vrf in vrfs_config.keys():
        data.config_vrfs.append(vrf)


def test_pfc_vxlan_4stream():
    """
    Test PFC with 4 streams for fan-in congestion over VXLAN L3VNI.
    Requires 4 IXIA ports per leaf (T1D3P1-P4, T1D4P1-P4).
    
    Four bidirectional streams between Leaf0 and Leaf1 at 99% line rate each:
        Stream 1: IXIA (T1D3P1) ↔ Leaf0 ↔ Spine ↔ Leaf1 ↔ IXIA (T1D4P1) via VNI 2000 (Vrf02)
        Stream 2: IXIA (T1D3P2) ↔ Leaf0 ↔ Spine ↔ Leaf1 ↔ IXIA (T1D4P2) via VNI 3000 (Vrf03)
        Stream 3: IXIA (T1D3P3) ↔ Leaf0 ↔ Spine ↔ Leaf1 ↔ IXIA (T1D4P3) via VNI 4000 (Vrf04)
        Stream 4: IXIA (T1D3P4) ↔ Leaf0 ↔ Spine ↔ Leaf1 ↔ IXIA (T1D4P4) via VNI 2000 (Vrf02)
    
    P1 and P4 share Vrf02/VLAN 2 on both leaves.
    With one link shut between Leaf0-Spine0 and Spine0-Leaf1, the remaining
    single link becomes the congestion point. Link speeds are queried at runtime.
    
    Traffic uses TC 3 (PFC-enabled) DSCP to test lossless behavior.
    """
    vars = st.get_testbed_vars()
    st.log('Started test_pfc_vxlan_4stream')

    if not hasattr(vars, 'D3T1P4') or not hasattr(vars, 'D4T1P4'):
        st.log("Testbed does not have 4 IXIA ports per leaf (D3T1P4/D4T1P4 missing) - skipping test_pfc_vxlan_4stream")
        st.report_unsupported("test_case_unsupported", "Requires 4 IXIA ports per leaf (T1D3P4/T1D4P4)")
        return

    nodes = get_nodes()

    # Print expected packet paths for each stream using actual testbed interface names
    st.banner("EXPECTED PACKET PATHS (per stream, bidirectional)")
    stream_paths = [
        ("Stream 1 (Vrf02/VNI 2000)", vars.D3T1P1, vars.D3D1P1, vars.D1D3P1, vars.D1D4P1, vars.D4D1P1, vars.D4T1P1),
        ("Stream 2 (Vrf03/VNI 3000)", vars.D3T1P2, vars.D3D1P1, vars.D1D3P1, vars.D1D4P1, vars.D4D1P1, vars.D4T1P2),
        ("Stream 3 (Vrf04/VNI 4000)", vars.D3T1P3, vars.D3D1P1, vars.D1D3P1, vars.D1D4P1, vars.D4D1P1, vars.D4T1P3),
        ("Stream 4 (Vrf02/VNI 2000)", vars.D3T1P4, vars.D3D1P1, vars.D1D3P1, vars.D1D4P1, vars.D4D1P1, vars.D4T1P4),
    ]
    for label, leaf0_ixia, leaf0_up, spine0_from, spine0_to, leaf1_up, leaf1_ixia in stream_paths:
        st.log(f"  {label}:")
        st.log(f"    FWD: IXIA --> {leaf0_ixia} [Leaf0] --> {leaf0_up} [Leaf0] --> {spine0_from} [Spine0] --> {spine0_to} [Spine0] --> {leaf1_up} [Leaf1] --> {leaf1_ixia} [Leaf1] --> IXIA")
        st.log(f"    REV: IXIA --> {leaf1_ixia} [Leaf1] --> {leaf1_up} [Leaf1] --> {spine0_to} [Spine0] --> {spine0_from} [Spine0] --> {leaf0_up} [Leaf0] --> {leaf0_ixia} [Leaf0] --> IXIA")
    ixia_spd = common_util.get_if_speed(nodes['leaf0'], vars.D3T1P1)
    uplink_spd = common_util.get_if_speed(nodes['leaf0'], vars.D3D1P1)
    st.log(f"  IXIA port speed: {ixia_spd}G, Leaf-Spine link speed: {uplink_spd}G")
    st.log(f"  Congestion point: {leaf0_up} [Leaf0] --> {spine0_from} [Spine0] (single {uplink_spd}G link after shutdown)")

    # Configure 3 VRFs; P1 and P4 share Vrf02 on both leaves
    vrfs_config = {
        'Vrf02': {
            'vlan': '2',
            'leaf0_members': [vars.D3T1P1, vars.D3T1P4],
            'leaf1_members': [vars.D4T1P1, vars.D4T1P4],
            'vni': '2000',
            'dummy_vlan': '200'
        },
        'Vrf03': {
            'vlan': '3',
            'leaf0_members': [vars.D3T1P2],
            'leaf1_members': [vars.D4T1P2],
            'vni': '3000',
            'dummy_vlan': '300'
        },
        'Vrf04': {
            'vlan': '4',
            'leaf0_members': [vars.D3T1P3],
            'leaf1_members': [vars.D4T1P3],
            'vni': '4000',
            'dummy_vlan': '400'
        }
    }

    svi_ips = {
        'leaf0': [
            {'vlan': '2', 'ip': '2002:db8:1::1/64', 'vni': '2000'},
            {'vlan': '3', 'ip': '2003:db8:1::1/64', 'vni': '3000'},
            {'vlan': '4', 'ip': '2004:db8:1::1/64', 'vni': '4000'}
        ],
        'leaf1': [
            {'vlan': '2', 'ip': '2112:db8:1::1/64', 'vni': '2000'},
            {'vlan': '3', 'ip': '2113:db8:1::1/64', 'vni': '3000'},
            {'vlan': '4', 'ip': '2114:db8:1::1/64', 'vni': '4000'}
        ]
    }

    try:
        # Start configuration with proper per-leaf member ports
        configure_multi_vni_for_pfc(nodes, vrfs_config, svi_ips)

        # Show VxLAN tunnel configuration before traffic
        st.banner("VxLAN Tunnel Configuration on Leaf Switches")
        for leaf in ['leaf0', 'leaf1']:
            st.log(f"=== VxLAN config on {leaf} ===")
            st.show(nodes[leaf], "show vxlan tunnel", skip_tmpl=True)
            st.show(nodes[leaf], "show vxlan name VXLAN", skip_tmpl=True)
            st.show(nodes[leaf], "show vxlan vlanvnimap", skip_tmpl=True)
            st.show(nodes[leaf], "show vxlan remotevtep", skip_tmpl=True)

        # Start Verification
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv6')
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv6')

        st.banner("Start to test VxLAN V6 L3 with 4 bidirectional streams for PFC congestion testing")

        # Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)

        # Shutdown redundant links to create congestion on single uplink path
        shutdown_links_for_congestion(nodes)

        # Verify link states: only D3D1P1/D4D1P1 should be UP to Spine0
        expected_up = {
            'leaf0': [vars.D3D1P1],
            'leaf1': [vars.D4D1P1]
        }
        l2l = qos_test_utils.get_leaf_to_leaf_interfaces()
        expected_down = {
            'leaf0': [vars.D3D1P2, vars.D3D2P1] + 
                      ([vars.D3D2P2] if hasattr(vars, 'D3D2P2') else [])
                      + l2l.get('leaf0', []),
            'leaf1': [vars.D4D1P2, vars.D4D2P1] +
                      ([vars.D4D2P2] if hasattr(vars, 'D4D2P2') else [])
                      + l2l.get('leaf1', [])
        }
        qos_test_utils.verify_link_states(nodes, expected_up, expected_down)

        # Get DSCP value for TC 3 (PFC-enabled lossless queue)
        dscp = common_util.convert_tc_to_dscp(nodes['leaf0'], data.tc)
        st.log(f"Using DSCP {dscp} for TC {data.tc} (PFC-enabled)")
        data.ip_dscp = int(dscp)
        data.traffic_class = int(dscp) << 2

        # Override traffic parameters: 99% line rate per stream, continuous mode
        data.rate_percent = "99"
        data.transmit_mode = "continuous"

        # Define 4 bidirectional streams: P1/P4 share Vrf02, P2→Vrf03, P3→Vrf04
        stream_configs = [
            {
                'src_port': 'T1D3P1',
                'src_ip': '2002:db8:1::2',
                'src_gw': '2002:db8:1::1',
                'src_mac': '00:0a:01:00:11:01',
                'dst_port': 'T1D4P1',
                'dst_ip': '2112:db8:1::2',
                'dst_gw': '2112:db8:1::1',
                'dst_mac': '00:0a:01:00:12:01'
            },
            {
                'src_port': 'T1D3P2',
                'src_ip': '2003:db8:1::2',
                'src_gw': '2003:db8:1::1',
                'src_mac': '00:0a:01:00:11:02',
                'dst_port': 'T1D4P2',
                'dst_ip': '2113:db8:1::2',
                'dst_gw': '2113:db8:1::1',
                'dst_mac': '00:0a:01:00:12:02'
            },
            {
                'src_port': 'T1D3P3',
                'src_ip': '2004:db8:1::2',
                'src_gw': '2004:db8:1::1',
                'src_mac': '00:0a:01:00:11:03',
                'dst_port': 'T1D4P3',
                'dst_ip': '2114:db8:1::2',
                'dst_gw': '2114:db8:1::1',
                'dst_mac': '00:0a:01:00:12:03'
            },
            {
                'src_port': 'T1D3P4',
                'src_ip': '2002:db8:1::3',
                'src_gw': '2002:db8:1::1',
                'src_mac': '00:0a:01:00:11:04',
                'dst_port': 'T1D4P4',
                'dst_ip': '2112:db8:1::3',
                'dst_gw': '2112:db8:1::1',
                'dst_mac': '00:0a:01:00:12:04'
            }
        ]

        st.banner(f"Setting up 4 bidirectional traffic streams at 99% line rate each with DSCP {dscp} (TC {data.tc})")
        streams_dict = setup_multi_stream_traffic(data, stream_configs, 'ipv6')
        st.log(streams_dict)

        # Define relevant interfaces for PFC counter capture
        # Traffic path: IXIA → Leaf0 → Spine0 → Leaf1 → IXIA
        pfc_interfaces = {
            'leaf0': [vars.D3T1P1, vars.D3T1P2, vars.D3T1P3, vars.D3T1P4, vars.D3D1P1],  # IXIA ports + uplink to spine
            'spine0': [vars.D1D3P1, vars.D1D4P1],  # Downlinks to leaf0 and leaf1
            'leaf1': [vars.D4D1P1, vars.D4T1P1, vars.D4T1P2, vars.D4T1P3, vars.D4T1P4]   # Uplink to spine + IXIA ports
        }

        # PRE-FLIGHT: Verify PFC is enabled on TC 3 across the entire traffic path
        # This catches the Spine0 PFC misconfiguration that caused the previous failure
        pfc_ok = qos_test_utils.verify_pfc_priority_on_interfaces(nodes, pfc_interfaces, data.tc)
        if not pfc_ok:
            st.error("PFC priority is NOT enabled on all traffic-path interfaces - test will likely fail")
            st.error("Check QoS config on Spine0 - it needs PFC enabled on TC 3")
            # Don't abort — still run to capture data, but log the warning prominently

        # PRE-FLIGHT: Dump QoS maps on all DUTs in the traffic path
        qos_test_utils.dump_qos_maps(nodes, ['leaf0', 'spine0', 'leaf1'])

        # Clear all counters on all DUTs before test
        st.banner("Clearing all counters on all DUTs before starting traffic")
        clear_cmds = "sonic-clear counters\nsonic-clear dropcounters\n" \
                    "sonic-clear pfccounters\nsonic-clear queuecounters"
        for dut in st.get_dut_names():
            st.log(f"Clearing counters on {dut}")
            st.config(dut, clear_cmds, skip_error_check=True)
        st.wait(10)

        # Capture PFC counters BEFORE traffic
        st.banner("Capturing PFC counters BEFORE traffic")
        pfc_before = qos_test_utils.capture_pfc_counters(nodes, pfc_interfaces, data.tc)
        for node_name, intfs in pfc_before.items():
            for intf, counts in intfs.items():
                st.log(f"{node_name} {intf}: TX={counts['tx']}, RX={counts['rx']}")

        # Capture drop counters BEFORE traffic
        st.banner("Capturing drop counters BEFORE traffic")
        drops_before = qos_test_utils.capture_drop_counters(nodes, pfc_interfaces)

        # Dump queue counters BEFORE traffic on relevant interfaces
        st.banner("Queue counters BEFORE traffic")
        for node_name, intfs in pfc_interfaces.items():
            for intf in intfs:
                st.show(nodes[node_name], f"show queue counters {intf}", skip_tmpl=True)

        # Run all 4 streams simultaneously
        result, failure_reasons = run_multi_stream_traffic(streams_dict, run_time=data.traffic_run_time)

        # Capture PFC counters AFTER traffic
        st.banner("Capturing PFC counters AFTER traffic")
        pfc_after = qos_test_utils.capture_pfc_counters(nodes, pfc_interfaces, data.tc)

        # Capture drop counters AFTER traffic
        st.banner("Capturing drop counters AFTER traffic")
        drops_after = qos_test_utils.capture_drop_counters(nodes, pfc_interfaces)

        # Dump queue counters AFTER traffic on relevant interfaces
        st.banner("Queue counters AFTER traffic")
        for node_name, intfs in pfc_interfaces.items():
            for intf in intfs:
                st.show(nodes[node_name], f"show queue counters {intf}", skip_tmpl=True)

        # Print only deltas for relevant interfaces
        qos_test_utils.print_pfc_counter_deltas(pfc_before, pfc_after, "PFC Counter Deltas (After - Before Traffic)")
        qos_test_utils.print_drop_counter_deltas(drops_before, drops_after, "Drop Counter Deltas (After - Before Traffic)")

    except Exception as e:
        result = False
        failure_reasons = [f"Exception: {str(e)}"]
        st.error(f"Exception occurred: {str(e)}")
    finally:
        # Remove traffic streams from IXIA
        if 'streams_dict' in dir() and streams_dict:
            qos_test_utils.remove_traffic_streams(streams_dict)

        # Bring links back up
        startup_links_after_test(nodes)

        # Deconfigure using our custom function that handles separate per-leaf members
        deconfigure_multi_vni_for_pfc(nodes, vrfs_config, svi_ips)

    # Report pass/fail AFTER cleanup with specific failure reasons
    if result:
        st.report_pass("test_case_passed", "test_pfc_vxlan_4stream passed")
    else:
        fail_summary = "; ".join(failure_reasons) if failure_reasons else "unknown"
        st.report_fail("test_case_failed", f"test_pfc_vxlan_4stream failed: {fail_summary}")


def test_pfc_vxlan_00_v4_basic():
    """
    Test: Basic IPv4 traffic over VXLAN L3VNI (IPv6 VTEP underlay) with PFC
    
    Based on test_l3vni_v4_v6_vtep_basic_config from test_l3vni_v6_vtep.py
    
    Note: This test is named with "00" prefix to run FIRST, before IPv6 tests.
    Running IPv4 first avoids TGEN topology conflicts from prior IPv6 sessions.
    
    Traffic Path:
        IXIA(100.100.100.200) → Leaf0(D3) → Spine(D1) → Leaf1(D4) → IXIA(100.100.101.200)
    """
    st.log('Started test_pfc_vxlan_00_v4_basic')
    nodes = get_nodes()

    try:
        # Configure and Validate basic l3vni configs and route exchanges
        configure_and_validate_basic_l3vni('ipv4')

        # IPv4 host addresses
        data.d3t1_ip_addr = "100.100.100.254"
        data.t1d3_ip_addr = "100.100.100.200"
        data.t1d3_mac_addr = "00:0a:01:00:11:01"

        data.d4t1_ip_addr = "100.100.101.254"
        data.t1d4_ip_addr = "100.100.101.200"
        data.t1d4_mac_addr = "00:0a:01:00:12:01"
        data.circuit_endpoint_type = "ipv4"

        st.banner("Start to test VxLAN V4 L3 with ping and traffic")

        # Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)

        # Override traffic parameters for PFC testing: 99% line rate, continuous mode
        data.rate_percent = "99"
        data.transmit_mode = "continuous"

        # Setup and run traffic at 99% line rate
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv4')
        st.log(streams_dict)
        result, failure_reasons = run_traffic_continuous(streams_dict, run_time=data.traffic_run_time)

        if result:
            st.report_pass("test_case_passed", "test_pfc_vxlan_00_v4_basic passed")
        else:
            fail_summary = "; ".join(failure_reasons) if failure_reasons else "unknown"
            st.report_fail("test_case_failed", f"test_pfc_vxlan_00_v4_basic failed: {fail_summary}")

    except Exception as e:
        report_fail("", msg=str(e))
    finally:
        # Remove traffic streams from IXIA
        if 'streams_dict' in dir() and streams_dict:
            qos_test_utils.remove_traffic_streams(streams_dict)

        # Show interface counters on each DUT
        st.banner("Show interface counters on all DUTs")
        for dut in st.get_dut_names():
            st.show(dut, "show int count", skip_tmpl=True)

        # Deconfigure basic l3vni configs
        deconfigure_basic_l3vni('ipv4')


def test_pfc_vxlan_fanin_same_egress():
    """
    Fan-in test: 2 unidirectional streams from 2 Leaf0 IXIA ports, both
    destined to the SAME Leaf1 IXIA port (T1D4P1).  This creates 2:1
    oversubscription at Leaf1's egress to IXIA, forcing PFC to propagate
    back through Spine0 to Leaf0.

    Link speeds are queried dynamically at runtime via get_if_speed().

    VRF layout (1 VRF, 2 Leaf0 source ports + 1 Leaf1 exit in same VLAN):
        Vrf02 (VNI 2000): Leaf0 P1+P2 → Leaf1 P1

    Traffic is unidirectional (bidirectional=0) so both streams can safely
    share T1D4P1 as destination without reverse-traffic contention.
    Using a single VRF avoids the untagged-VLAN conflict that occurs when
    two VRFs try to claim the same physical port in different VLANs.

    Expected PFC chain:
        Leaf1 (egress congestion on T1D4P1 — 2×400G into 1×400G)
           → Leaf1 sends PFC TX on D4D1P1 (uplink to Spine0)
           → Spine0 receives PFC RX on D1D4P1
           → Spine0 sends PFC TX on D1D3P1 + D1D3P2 (downlinks to Leaf0)
           → Leaf0 receives PFC RX on D3D1P1 + D3D1P2
           → Leaf0 sends PFC TX on D3T1P1/P2 (back to IXIA)

    Traffic (unidirectional, fan-in at Leaf1 egress):
        Stream 1: IXIA(T1D3P1) → Leaf0 → Spine0 → Leaf1 → IXIA(T1D4P1) via Vrf02/VNI 2000
        Stream 2: IXIA(T1D3P2) → Leaf0 → Spine0 → Leaf1 → IXIA(T1D4P1) via Vrf02/VNI 2000
    """
    vars = st.get_testbed_vars()
    st.log('Started test_pfc_vxlan_fanin_same_egress')
    nodes = get_nodes()

    # 1 VRF with 2 src ports on Leaf0 + 1 dst port on Leaf1, all in same VLAN
    # A port can only be untagged in one VLAN, so sharing T1D4P1 across
    # multiple VRFs with different VLANs would fail
    vrfs_config = {
        'Vrf02': {
            'vlan': '2',
            'leaf0_members': [vars.D3T1P1, vars.D3T1P2],
            'leaf1_members': [vars.D4T1P1],
            'vni': '2000',
            'dummy_vlan': '200'
        }
    }

    svi_ips = {
        'leaf0': [
            {'vlan': '2', 'ip': '2002:db8:1::1/64', 'vni': '2000'}
        ],
        'leaf1': [
            {'vlan': '2', 'ip': '2112:db8:1::1/64', 'vni': '2000'}
        ]
    }

    try:
        # Load test parameters from input JSON2 (rate, frame size, etc.)
        fanin_params = common_util.get_qos_test_dict(
            '../pfc/pfc_vxlan_input.json2', 'PFC_VXLAN_FANIN')
        if fanin_params is None:
            fanin_params = {}
            st.log("WARNING: pfc_vxlan_input.json2 not found, using defaults")

        # Shutdown links FIRST to establish the intended single-path topology
        # before any VRF/VLAN/VNI config is applied
        # Keep BOTH Leaf0→Spine0 links UP, shut everything else
        st.banner("Shutting links for fan-in test (keeping both Leaf0→Spine0 UP)")
        # Shut Leaf1→Spine0 P2 (keep only D4D1P1)
        st.log(f"Shutting down {vars.D4D1P2} on Leaf1 (to Spine0)")
        st.config(nodes['leaf1'], f"sudo config interface shutdown {vars.D4D1P2}")
        # Shut ALL Spine1 links
        st.log(f"Shutting down {vars.D3D2P1} on Leaf0 (to Spine1)")
        st.config(nodes['leaf0'], f"sudo config interface shutdown {vars.D3D2P1}")
        if hasattr(vars, 'D3D2P2'):
            st.log(f"Shutting down {vars.D3D2P2} on Leaf0 (to Spine1)")
            st.config(nodes['leaf0'], f"sudo config interface shutdown {vars.D3D2P2}")
        st.log(f"Shutting down {vars.D4D2P1} on Leaf1 (to Spine1)")
        st.config(nodes['leaf1'], f"sudo config interface shutdown {vars.D4D2P1}")
        if hasattr(vars, 'D4D2P2'):
            st.log(f"Shutting down {vars.D4D2P2} on Leaf1 (to Spine1)")
            st.config(nodes['leaf1'], f"sudo config interface shutdown {vars.D4D2P2}")
        # Shut leaf-to-leaf
        qos_test_utils.shutdown_leaf_to_leaf_links(nodes)
        st.wait(5)

        # Verify: Leaf0→Spine0 BOTH UP, Leaf1→Spine0 only P1 UP
        expected_up = {
            'leaf0': [vars.D3D1P1, vars.D3D1P2],
            'leaf1': [vars.D4D1P1]
        }
        l2l = qos_test_utils.get_leaf_to_leaf_interfaces()
        expected_down = {
            'leaf0': [vars.D3D2P1] +
                     ([vars.D3D2P2] if hasattr(vars, 'D3D2P2') else []) +
                     l2l.get('leaf0', []),
            'leaf1': [vars.D4D1P2, vars.D4D2P1] +
                      ([vars.D4D2P2] if hasattr(vars, 'D4D2P2') else []) +
                      l2l.get('leaf1', [])
        }
        qos_test_utils.verify_link_states(nodes, expected_up, expected_down)

        # Now configure VRFs/VLANs/VNIs over the single-path topology
        configure_multi_vni_for_pfc(nodes, vrfs_config, svi_ips)

        # Verify VTEP and BGP over the final topology
        st.banner("VxLAN Tunnel Configuration on Leaf Switches")
        for leaf in ['leaf0', 'leaf1']:
            st.show(nodes[leaf], "show vxlan tunnel", skip_tmpl=True)
            st.show(nodes[leaf], "show vxlan vlanvnimap", skip_tmpl=True)
            st.show(nodes[leaf], "show vxlan remotevtep", skip_tmpl=True)

        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv6')
        verify_vtep_state(nodes)

        # Query actual link speeds
        st.banner("Querying interface speeds from DUTs")
        link_speeds = qos_test_utils.get_link_speeds(nodes, {
            'leaf0': [vars.D3T1P1, vars.D3D1P1],
            'leaf1': [vars.D4T1P1],
            'spine0': [vars.D1D4P1]
        })
        ixia_speed = link_speeds['leaf0'][vars.D3T1P1]
        leaf_spine_speed = link_speeds['leaf0'][vars.D3D1P1]
        leaf1_ixia_speed = link_speeds['leaf1'][vars.D4T1P1]
        rate_frac = int(fanin_params.get('rate_percent', '95')) / 100.0
        total_ixia_bw = 2 * ixia_speed * rate_frac
        total_leaf0_spine0_bw = 2 * leaf_spine_speed
        oversub_ratio = total_ixia_bw / leaf1_ixia_speed if leaf1_ixia_speed else 0

        # Get DSCP for TC 3
        dscp = common_util.convert_tc_to_dscp(nodes['leaf0'], data.tc)
        st.log(f"Using DSCP {dscp} for TC {data.tc}")
        data.ip_dscp = int(dscp)
        data.traffic_class = int(dscp) << 2
        data.rate_percent = fanin_params.get('rate_percent', '95')
        data.frame_size = fanin_params.get('frame_size', '1350')
        data.transmit_mode = "continuous"
        data.circuit_endpoint_type = "ipv6"

        # Print expected paths with actual speeds
        st.banner("EXPECTED PACKET PATHS (2 streams fan-in to single Leaf1 IXIA port)")
        st.log(f"  Stream 1 (Vrf02/VNI 2000):")
        st.log(f"    IXIA --> {vars.D3T1P1} [Leaf0] --> Spine0 --> {vars.D4D1P1} [Leaf1] --> {vars.D4T1P1} --> IXIA")
        st.log(f"  Stream 2 (Vrf02/VNI 2000):")
        st.log(f"    IXIA --> {vars.D3T1P2} [Leaf0] --> Spine0 --> {vars.D4D1P1} [Leaf1] --> {vars.D4T1P1} --> IXIA")
        st.log(f"  IXIA port speed: {ixia_speed}G, Leaf-Spine link speed: {leaf_spine_speed}G")
        st.log(f"  Leaf0→Spine0: {vars.D3D1P1} + {vars.D3D1P2} (2x{leaf_spine_speed}G = {qos_test_utils.format_speed(total_leaf0_spine0_bw)}, BOTH UP)")
        st.log(f"  Leaf1 egress: {vars.D4T1P1} ({leaf1_ixia_speed}G, bottleneck)")
        st.log(f"  Congestion: 2x{ixia_speed}G IXIA ({qos_test_utils.format_speed(total_ixia_bw)}) → {leaf1_ixia_speed}G Leaf1 egress = {oversub_ratio:.1f}:1 oversubscription")
        st.log(f"  Expected PFC: Leaf1 TX on {vars.D4D1P1} → Spine0 RX on {vars.D1D4P1} → Spine0 TX on {vars.D1D3P1}/{vars.D1D3P2} → Leaf0 RX on {vars.D3D1P1}/{vars.D3D1P2}")

        # 2 streams: different src ports, SAME dst port (T1D4P1), SAME VRF/VLAN
        # Both sources use IPs in the Vrf02 subnet (2002:db8:1::/64)
        stream_configs = [
            {
                'src_port': 'T1D3P1',
                'src_ip': '2002:db8:1::2',
                'src_gw': '2002:db8:1::1',
                'src_mac': '00:0a:01:00:11:01',
                'dst_port': 'T1D4P1',
                'dst_ip': '2112:db8:1::2',
                'dst_gw': '2112:db8:1::1',
                'dst_mac': '00:0a:01:00:12:01'
            },
            {
                'src_port': 'T1D3P2',
                'src_ip': '2002:db8:1::3',
                'src_gw': '2002:db8:1::1',
                'src_mac': '00:0a:01:00:11:02',
                'dst_port': 'T1D4P1',
                'dst_ip': '2112:db8:1::2',
                'dst_gw': '2112:db8:1::1',
                'dst_mac': '00:0a:01:00:12:01'
            }
        ]

        st.banner(f"Setting up 2 unidirectional streams at {data.rate_percent}% line rate (frame={data.frame_size}B), fan-in to {vars.D4T1P1} ({leaf1_ixia_speed}G), DSCP {dscp} (TC {data.tc})")
        streams_dict = setup_multi_stream_traffic(data, stream_configs, 'ipv6', bidirectional=0)
        st.log(streams_dict)

        # PFC interfaces to monitor
        pfc_interfaces = {
            'leaf0': [vars.D3T1P1, vars.D3T1P2, vars.D3D1P1, vars.D3D1P2],
            'spine0': [vars.D1D3P1, vars.D1D3P2, vars.D1D4P1],
            'leaf1': [vars.D4D1P1, vars.D4T1P1]
        }

        # Pre-flight checks
        qos_test_utils.verify_pfc_priority_on_interfaces(nodes, pfc_interfaces, data.tc)
        qos_test_utils.dump_qos_maps(nodes, ['leaf0', 'spine0', 'leaf1'])

        # Clear counters
        st.banner("Clearing all counters on all DUTs")
        clear_cmds = "sonic-clear counters\nsonic-clear dropcounters\n" \
                    "sonic-clear pfccounters\nsonic-clear queuecounters"
        for dut in st.get_dut_names():
            st.config(dut, clear_cmds, skip_error_check=True)
        st.wait(10)

        # Capture BEFORE
        pfc_before = qos_test_utils.capture_pfc_counters(nodes, pfc_interfaces, data.tc)
        drops_before = qos_test_utils.capture_drop_counters(nodes, pfc_interfaces)

        # Queue counters BEFORE
        st.banner("Queue counters BEFORE traffic")
        for node_name, intfs in pfc_interfaces.items():
            for intf in intfs:
                st.show(nodes[node_name], f"show queue counters {intf}", skip_tmpl=True)

        # Run traffic
        result, failure_reasons = run_multi_stream_traffic(streams_dict, run_time=data.traffic_run_time)

        # Capture AFTER
        pfc_after = qos_test_utils.capture_pfc_counters(nodes, pfc_interfaces, data.tc)
        drops_after = qos_test_utils.capture_drop_counters(nodes, pfc_interfaces)

        # Queue counters AFTER
        st.banner("Queue counters AFTER traffic")
        for node_name, intfs in pfc_interfaces.items():
            for intf in intfs:
                st.show(nodes[node_name], f"show queue counters {intf}", skip_tmpl=True)

        # Print deltas
        qos_test_utils.print_pfc_counter_deltas(pfc_before, pfc_after, "PFC Counter Deltas (Fan-in 2:1 Leaf1 Egress)")
        qos_test_utils.print_drop_counter_deltas(drops_before, drops_after, "Drop Counter Deltas (Fan-in 2:1 Leaf1 Egress)")

        # Check expected PFC behavior — Leaf1 egress is the congestion point
        st.banner("PFC BEHAVIOR ANALYSIS")

        def _pfc_delta(node, intf, direction):
            return pfc_after.get(node, {}).get(intf, {}).get(direction, 0) - \
                   pfc_before.get(node, {}).get(intf, {}).get(direction, 0)

        st.log("=== Leaf1 IXIA egress port (congestion point) ===")
        leaf1_ixia_tx = _pfc_delta('leaf1', vars.D4T1P1, 'tx')
        leaf1_ixia_rx = _pfc_delta('leaf1', vars.D4T1P1, 'rx')
        st.log(f"  Leaf1 {vars.D4T1P1} PFC TX: {leaf1_ixia_tx}  RX: {leaf1_ixia_rx}")

        st.log("=== Leaf1 uplink to Spine0 (TX PFC = pushing back to Spine0) ===")
        leaf1_tx = _pfc_delta('leaf1', vars.D4D1P1, 'tx')
        leaf1_rx = _pfc_delta('leaf1', vars.D4D1P1, 'rx')
        st.log(f"  Leaf1 {vars.D4D1P1} PFC TX: {leaf1_tx} {'(pushing back to Spine0!)' if leaf1_tx > 0 else '(none)'}  RX: {leaf1_rx}")

        st.log("=== Spine0 (RX PFC from Leaf1, TX PFC = pushing back to Leaf0) ===")
        d1d4p1_tx = _pfc_delta('spine0', vars.D1D4P1, 'tx')
        d1d4p1_rx = _pfc_delta('spine0', vars.D1D4P1, 'rx')
        st.log(f"  Spine0 {vars.D1D4P1} PFC TX: {d1d4p1_tx}  RX: {d1d4p1_rx} {'(Leaf1 pushback!)' if d1d4p1_rx > 0 else ''}")
        for p in [vars.D1D3P1, vars.D1D3P2]:
            tx = _pfc_delta('spine0', p, 'tx')
            rx = _pfc_delta('spine0', p, 'rx')
            st.log(f"  Spine0 {p} PFC TX: {tx} {'(pushing back to Leaf0!)' if tx > 0 else '(none)'}  RX: {rx}")

        st.log("=== Leaf0 uplinks to Spine0 (RX PFC = Spine0 pushing back) ===")
        for p in [vars.D3D1P1, vars.D3D1P2]:
            rx = _pfc_delta('leaf0', p, 'rx')
            tx = _pfc_delta('leaf0', p, 'tx')
            st.log(f"  Leaf0 {p} PFC RX: {rx} {'(Spine0 pushback!)' if rx > 0 else '(none)'}  TX: {tx}")

        st.log("=== Leaf0 IXIA-facing ports (TX PFC = pushback to IXIA) ===")
        for p in [vars.D3T1P1, vars.D3T1P2]:
            tx = _pfc_delta('leaf0', p, 'tx')
            st.log(f"  Leaf0 {p} PFC TX: {tx} {'(pushing back to IXIA)' if tx > 0 else ''}")

        # Summary — check full PFC chain: Leaf1 → Spine0 → Leaf0
        leaf1_pushed_spine = _pfc_delta('leaf1', vars.D4D1P1, 'tx')
        spine0_rx_from_leaf1 = _pfc_delta('spine0', vars.D1D4P1, 'rx')
        spine0_tx_total = _pfc_delta('spine0', vars.D1D3P1, 'tx') + _pfc_delta('spine0', vars.D1D3P2, 'tx')
        leaf0_rx_total = _pfc_delta('leaf0', vars.D3D1P1, 'rx') + _pfc_delta('leaf0', vars.D3D1P2, 'rx')
        if leaf1_pushed_spine > 0 and spine0_tx_total > 0 and leaf0_rx_total > 0:
            st.log("SUCCESS: Full PFC chain — Leaf1 → Spine0 → Leaf0 → IXIA!")
        elif leaf1_pushed_spine > 0 and spine0_tx_total == 0:
            st.log("PARTIAL: Leaf1 pushed back to Spine0 but Spine0 did NOT relay PFC to Leaf0")
        elif _pfc_delta('leaf0', vars.D3T1P1, 'tx') > 0 and spine0_tx_total == 0:
            st.log("OBSERVATION: Leaf0 pushed back to IXIA but Spine0 did NOT generate PFC")
        else:
            st.log("OBSERVATION: No significant PFC detected")

    except Exception as e:
        result = False
        failure_reasons = [f"Exception: {str(e)}"]
        st.error(f"Exception occurred: {str(e)}")
    finally:
        if 'streams_dict' in dir() and streams_dict:
            qos_test_utils.remove_traffic_streams(streams_dict)
        startup_links_after_test(nodes)
        deconfigure_multi_vni_for_pfc(nodes, vrfs_config, svi_ips)

    if result:
        st.report_pass("test_case_passed", "test_pfc_vxlan_fanin_same_egress passed")
    else:
        fail_summary = "; ".join(failure_reasons) if failure_reasons else "unknown"
        st.report_fail("test_case_failed", f"test_pfc_vxlan_fanin_same_egress failed: {fail_summary}")
