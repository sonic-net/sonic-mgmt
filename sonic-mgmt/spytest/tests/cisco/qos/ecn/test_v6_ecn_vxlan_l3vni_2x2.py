"""
ECN Marking Accuracy Test over L3VNI with PFC XOFF Backpressure

Simplified ECN test that uses PFC XOFF frames from the egress TGEN to create
backpressure-induced congestion (instead of traffic oversubscription).

Unlike L2VNI where traffic is bridged, L3VNI traffic is routed through
VRF/L3VNI via different subnets on each leaf.

Topology: 2x Spine + 2 Leafs
    SD1 -- Spine0   - D1
    SD2 -- Spine1   - D2
    SD3 -- Leaf0    - D3 (ingress leaf)
    SD4 -- Leaf1    - D4 (egress leaf)

Traffic Path (L3 Routed via VRF):
    T1D3P1 (data 99%) --> Leaf0 (Vrf01/VLAN 2) --> VXLAN --> Leaf1 (Vrf01/VLAN 3) <-- T1D4P1 (XOFF)

Congestion Mechanism:
    1. T1D4P1 sends continuous PFC XOFF frames for TC3 to pause Leaf1's egress
    2. Backpressure propagates: Leaf1 -> Spine0 -> Leaf0
    3. Congestion builds at each hop, triggering ECN CE marking

Congestion Points Tested:
    A. Ingress leaf egress (Leaf0 -> Spine0/1) - ECN disabled on spine0, spine1, leaf1
    B. Spine egress (Spine0/1 -> Leaf1)        - ECN disabled on leaf0, leaf1
    C. Egress leaf TGEN (Leaf1 -> T1D4P1)      - ECN disabled on leaf0, spine0, spine1

ECN Verification:
    - Pass criteria: Traffic flows and ECN counters match expected behavior

"""

import os
import time
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import tests.cisco.tortuga.vxlan.vxlan_utils as vxlan_obj
import traffic_stream_ixia_api as stream_api
import qos_test_utils as qos_utils
import gamut_qos_utils as gamut_utils
import vxlan_ecn_base as base
from vxlan_ecn_base import (
    ECN_NOT_ECT, ECN_ECT_01, ECN_ECT_10, ECN_CE,
    ECN_MARKING_NODES, CONGESTION_TO_MARKING_ROLE, PFC_XOFF_NODES,
    get_nodes, config_node, get_xoff_rate, get_pfc_rx_count,
    config_static,
)

CONFIGS_FILE = '../../qos/ecn/vxlan_ecn_l3vni_2x1.yaml'

data = SpyTestDict()

# L3VNI uses different subnets on each leaf (routed traffic)
# Ingress TGEN port on leaf0 (VLAN 2 / 2002:db8:1::/64)
data.t1d3p1_ip6_addr = "2002:db8:1::2"
data.t1d3p1_mac_addr = "00:0a:01:00:11:01"
data.d3t1_ip6_addr = "2002:db8:1::1"  # Gateway on leaf0 Vlan2

# Optional second ingress TGEN port on leaf0 (used only by the 2-to-1
# natural-congestion test that runs when fabric egress speed == 2x ingress
# speed). Same subnet/VLAN as T1D3P1 so they share the gateway.
data.t1d3p2_ip6_addr = "2002:db8:1::3"
data.t1d3p2_mac_addr = "00:0a:01:00:11:02"

# Egress TGEN port on leaf1 (VLAN 3 / 2003:db8:1::/64)
data.t1d4p1_ip6_addr = "2003:db8:1::2"
data.t1d4p1_mac_addr = "00:0a:01:00:12:01"
data.d4t1_ip6_addr = "2003:db8:1::1"  # Gateway on leaf1 Vlan3

# Traffic parameters
data.traffic_run_time = 60
data.tc = 3  # Traffic Class for PFC-enabled lossless queue
data.frame_size = "1350"
data.rate_percent = "99"
data.vlan_id = "2"  # Ingress VLAN on leaf0
data.mask = "64"
data.addr_family = 'ipv6'
data.capture_count=100
data.node_meta = {}  # Per-node metadata: {node_name: {'platform_type': ...}}
data.topology = {}   # Role-aware per-node port descriptor (built in module_setup)
data.ecn_results = {}  # Bundles from each traffic run, keyed by (congestion_point, ect)
data.ecn_natural_results = {}  # Natural-congestion bundles, keyed by (congestion_point, ect, rate_pct)

# VTEP IPs for L3VNI topology
LEAF0_VTEP_IP = '2001:db8:1::2'
LEAF1_VTEP_IP = '2001:db8:1::3'

# ECN/ECT and congestion-point mappings are imported from vxlan_ecn_base.

# Module-level state
updated_config_file = None
port_speed_gbps = None
topo_info = None
platform_type = None  # 'n9164e' for Gamut, 'laguna' for HF6100-64ED (G200), 'carib' for HF6100-32D (Q200), 'generic' otherwise


def _l3vni_resolve_gateway_nd(handles, int_dict):
    """L3VNI post-NGPF hook: ping each TGEN's local gateway to force ND.

    L3VNI requires gateway MAC resolution via ND before end-to-end ping works.
    Failures here are non-fatal; the end-to-end ping will catch real issues.
    """
    st.banner("Pinging local gateways to force IPv6 ND resolution (L3VNI requirement)")
    for port, info in int_dict.items():
        gateway = info['gateway']
        st.log("Pinging gateway {} from {} to trigger ND...".format(gateway, port))
        gw_ping_ok = vxlan_obj.ping_gateway(handles, port, gateway, handles[port]['int_handle'])
        if gw_ping_ok:
            st.log("Gateway ping from {} to {} succeeded - ND resolved".format(port, gateway))
        else:
            st.log("WARNING: Gateway ping from {} to {} failed - ND may not be resolved".format(port, gateway))
            # Don't fail yet - the end-to-end ping will catch this


def dump_l3vni_diagnostics(nodes, phase=""):
    """
    Dump L3VNI state for debugging - VRF routes, EVPN, VXLAN status.
    """
    st.banner("{} L3VNI DIAGNOSTICS".format(phase))
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        st.log("--- {} ---".format(node_name))
        # Check VRF routes
        st.log("{}: show ipv6 route vrf Vrf01".format(node_name))
        st.config(dut, "vtysh -c 'show ipv6 route vrf Vrf01'", skip_error_check=True)
        # Check EVPN Type-5 routes
        st.log("{}: show bgp l2vpn evpn route type prefix".format(node_name))
        st.config(dut, "vtysh -c 'show bgp l2vpn evpn route type prefix'", skip_error_check=True)
        # Check EVPN VNI
        st.log("{}: show evpn vni 1000".format(node_name))
        st.config(dut, "vtysh -c 'show evpn vni 1000'", skip_error_check=True)
        # Check remote VTEP status
        st.log("{}: show vxlan remotevtep".format(node_name))
        st.show(dut, "show vxlan remotevtep", skip_tmpl=True, skip_error_check=True)


def verify_l3vni_asic_entries(nodes):
    """
    Verify L3VNI ASIC programming (VNI-to-VRF mapping).
    
    Returns True if entries are present, False otherwise.
    Note: No longer attempts recovery - just reports status.
    """
    all_good = True
    
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        
        # Check ASIC_DB for VNI_TO_VIRTUAL_ROUTER_ID entries
        output = st.config(dut,
            "sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY:*'",
            skip_error_check=True)
        has_vrf_entry = False
        entry_keys = [line.strip() for line in output.split('\n')
                      if line.strip().startswith('ASIC_STATE:')]
        for key in entry_keys:
            val = st.config(dut,
                "sonic-db-cli ASIC_DB HGETALL '{}'".format(key),
                skip_error_check=True)
            if 'VIRTUAL_ROUTER' in val:
                has_vrf_entry = True
                break
        
        if has_vrf_entry:
            st.log("{}: L3VNI ASIC entries confirmed present".format(node_name))
        else:
            st.log("WARNING: {}: L3VNI ASIC entries MISSING".format(node_name))
            all_good = False
    
    return all_good


def _l3vni_pre_ngpf_diagnostics(nodes):
    """L3VNI pre-NGPF debug hook.

    Print VRF / VXLAN / EVPN / FDB / MAC / drop-counter state on both leaves
    just before TGEN NGPF setup, plus a leaf0->leaf1 ping6 through Vrf01.
    Used by run_ecn_xoff_test() via the pre_ngpf_diagnostics_hook contract
    in vxlan_ecn_base.
    """
    st.banner("PRE-PING: Verifying L3VNI routing and VXLAN state")
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        st.log("--- {}: show ipv6 route vrf Vrf01 ---".format(node_name))
        st.config(dut, "vtysh -c 'show ipv6 route vrf Vrf01'", skip_error_check=True)
        st.log("--- {}: show vxlan remotevtep ---".format(node_name))
        st.config(dut, "show vxlan remotevtep", skip_error_check=True)
        st.log("--- {}: show bgp l2vpn evpn summary ---".format(node_name))
        st.config(dut, "vtysh -c 'show bgp l2vpn evpn summary'", skip_error_check=True)
        st.log("--- {}: show bgp l2vpn evpn route type prefix ---".format(node_name))
        st.config(dut, "vtysh -c 'show bgp l2vpn evpn route type prefix'", skip_error_check=True)
        st.log("--- {}: show vlan brief ---".format(node_name))
        st.config(dut, "show vlan brief", skip_error_check=True)
        st.log("--- {}: show mac address-table ---".format(node_name))
        st.config(dut, "show mac", skip_error_check=True)
        st.log("--- {}: show vxlan vlanvnimap ---".format(node_name))
        st.config(dut, "show vxlan vlanvnimap", skip_error_check=True)
        st.log("--- {}: show dropcounters counts ---".format(node_name))
        st.config(dut, "show dropcounters counts", skip_error_check=True)
        st.log("--- {}: fdbshow ---".format(node_name))
        st.config(dut, "fdbshow", skip_error_check=True)

    # DUT-to-DUT ping through VRF to verify tunnel data plane
    st.log("--- leaf0: ping leaf1 SVI through Vrf01 ---")
    st.config(nodes['leaf0'], "ping6 -c 3 -I Vrf01 2003:db8:1::1", skip_error_check=True)


def run_ecn_xoff_test(congestion_point, test_name, ect=ECN_ECT_10,
                      skip_pfc_xoff_stream=False):
    """Thin wrapper: delegate to base runner with L3VNI hooks/flags."""
    return base.run_ecn_xoff_test(
        data, congestion_point, test_name, ect=ect,
        port_speed_gbps=port_speed_gbps,
        vtep_ips=(LEAF0_VTEP_IP, LEAF1_VTEP_IP),
        diagnostics_hook=dump_l3vni_diagnostics,
        pre_ngpf_diagnostics_hook=_l3vni_pre_ngpf_diagnostics,
        setup_tgen_post_handles_hook=_l3vni_resolve_gateway_nd,
        clear_wred_pre_traffic=False,
        save_config_nodes=['leaf0', 'leaf1', 'spine0'],
        skip_pfc_xoff_stream=skip_pfc_xoff_stream,
    )


def verify_vtep_state(nodes):
    '''
    Verify VXLAN tunnel state
    '''
    REMOTE_VTEP_COUNT = '1'
    NO_OF_RETRIES=12
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
                    st.report_fail("test_case_failed", 'Tunnel State is not up. Status : oper_down')
                else:
                    st.log("Tunnel State is not set after {} secs".format(end_time - start_time))
                    st.report_fail("test_case_failed", 'Tunnel State is not set')
            
            if vtep['tun_status'] == 'oper_up':
                end_time = time.time()
                st.log("Tunnel State is up after {} secs Status : oper_up".format(end_time - start_time), dut)

            if vtep['src_vtep'] == expected_sip:
                st.log("Source vtep validated", dut)
            else:
                st.report_fail("test_case_failed", 'Source vtep is not as expected. Found {} Expected {}'.format(vtep['src_vtep'], expected_sip))

            if vtep['dst_vtep'] == expected_dip:
                st.log("Destination vtep validated", dut)
            else:
                st.report_fail("test_case_failed", 'Destination vtep is not as expected. Found {} Expected {}'.format(vtep['dst_vtep'], expected_dip))

            if vtep['total_count'] == REMOTE_VTEP_COUNT:
                st.log("All remote VTEPs detected", dut)
            else:
                st.report_fail("test_case_failed", 'Remote Vteps discovered count not as expected. Found {} Expected {}'.format(vtep['total_count'], REMOTE_VTEP_COUNT))


@pytest.fixture(scope="module", autouse=True)
def module_setup():
    """
    Module-level setup for ECN XOFF tests over L3VNI.

    Steps:
        1. Initialize QoS (does config reload on Gamut - must be FIRST)
        2. Clean up any existing config
        3. Apply VXLAN/BGP config for L3VNI
        4. Wait for BGP EVPN convergence
        5. Verify L3VNI ASIC programming
        6. Get port speed for XOFF rate calculation
        7. Validate testbed topology
        8. Verify ECN enabled
        9. Detect platform type
    """
    global updated_config_file, port_speed_gbps, topo_info, platform_type

    vars = st.get_testbed_vars()
    nodes = get_nodes()

    # Step 1: Initialize QoS (MUST be first - does config reload on Gamut which may restart FRR)
    st.banner("STEP 1: Initializing QoS configuration")
    for dut in st.get_dut_names():
        stream_api.init_qos_on_dut(dut)
        qos_utils.load_config_db(dut)

    # Step 2: Clean up any existing config (AFTER init_qos_on_dut since that may restart FRR
    # and reload frr.conf, undoing any cleanup done before)
    st.banner("STEP 2: Cleaning up any existing VXLAN/BGP configuration")
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        qos_utils.cleanup_config(dut)

    # Remove any leftover VRF BGP instances (must be after QoS init which restarts FRR)
    # TODO REMOVE qos_utils.cleanup_leftover_vrf_bgp(nodes)

    # Step 3: Get port speed for XOFF rate calculation
    st.banner("STEP 3: Getting port speed for XOFF rate calculation")
    speeds = qos_utils.get_link_speeds(nodes, {'leaf1': [vars.D4T1P1]})
    port_speed_gbps = speeds['leaf1'][vars.D4T1P1]
    st.log("Port speed: {} Gbps, XOFF rate will be {} fps".format(
        port_speed_gbps, get_xoff_rate(port_speed_gbps)))

    # Step 4: Validate testbed topology
    st.banner("STEP 4: Validating ECN testbed topology for WRED counter interfaces")
    topo_info = qos_utils.validate_ecn_testbed_topology()
    if not topo_info['valid']:
        st.log("WARNING: Testbed topology validation issue: {}".format(
            topo_info.get('error')))
        st.log("Continuing with minimal port set for WRED counters...")

    # Build role-aware per-node descriptor for use by snapshot helpers.
    # No behavior change yet; consumers will be added in subsequent phases.
    data.topology = qos_utils.build_node_topology(vars)
    qos_utils.populate_topology_speeds(data.topology, nodes)
    st.log("Per-node topology descriptor:")
    for node_name, entry in data.topology.items():
        st.log("  {} role={} tgen={} ingress={} egress={} speeds={}".format(
            node_name, entry['role'], entry['tgen_port'],
            entry['ingress_ports'], entry['egress_ports'],
            entry.get('port_speeds', {})))

    # Step 5: Detect platform type per node and build port mappings for Gamut
    st.banner("STEP 5: Detecting platform type per node")
    for node_name, dut in nodes.items():
        node_platform = qos_utils.detect_platform(dut)
        data.node_meta[node_name] = {'platform_type': node_platform, 'port_mapping': {}}
        st.log("{}: platform_type={}".format(node_name, node_platform))
        
        # Build port mapping for Gamut nodes
        if node_platform == 'n9164e':
            st.log("{}: Building Gamut port name -> port ID mapping...".format(node_name))
            port_mapping = gamut_utils.gamut_build_port_mapping(dut)
            data.node_meta[node_name]['port_mapping'] = port_mapping
            st.log("{}: {} ports mapped".format(node_name, len(port_mapping)))
            # enable queue wredcounters
            st.config(dut, "sudo counterpoll wredqueue enable", skip_tmpl=True, trace_log=1)
    
    # Keep global for backward compatibility (use leaf0 as reference)
    platform_type = data.node_meta['leaf0']['platform_type']
    st.log("Reference platform type (from leaf0): {}".format(platform_type))

    # Remove any leftover VRF BGP instances (must be after QoS init which restarts FRR)
    qos_utils.cleanup_leftover_vrf_bgp(nodes)

    st.banner("STEP 6: Generate L2VNI VXLAN/BGP configuration")
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE, vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node in config_list.keys():
            config_static(node, 'sonic', config_list)
            st.wait(5)
            config_static(node, 'bgp', config_list)

    # Wait for BGP to converge
    st.banner("STEP 7: Waiting for BGP convergence")
    st.wait(20)

    # Step 8: Wait for BGP EVPN convergence
    st.banner("STEP 8: Waiting for BGP underlay & EVPN convergence")
    if not qos_utils.wait_for_bgp_underlay_established(nodes, max_wait=180):
        st.log("WARNING: BGP underlay sessions may not be fully established")
        # TODO any point in proceeding? Declare failure

    # Wait for VXLAN tunnels - else TODO fail
    st.banner("Waiting for VXLAN tunnels to establish")
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        for attempt in range(12):
            output = st.config(dut, "show vxlan remotevtep")
            if 'oper_up' in output or '2001:db8:1::' in output:
                st.log("{}: VXLAN tunnel UP".format(node_name))
                break
            st.log("{}: Waiting for VXLAN tunnel... attempt {}/12".format(
                node_name, attempt + 1))
            st.wait(10)

    # DUMP full connectivity and BGP session details for debugging
    qos_utils.dump_vxlan_debug_info(nodes, "BGP session details")

    # Step 9: Verify L3VNI ASIC programming
    st.banner("STEP 9: Verifying L3VNI ASIC programming")
    verify_l3vni_asic_entries(nodes)

    # redundant, but clean(er)
    verify_vtep_state(nodes)

    yield

    # Module cleanup
    st.banner("MODULE CLEANUP: Removing VXLAN/BGP configuration")
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node in reversed(list(config_list.keys())):
            config_static(node, 'bgp', config_list, add=False)
            st.wait(3)
            config_static(node, 'sonic', config_list, add=False)

    vxlan_obj.remove_temp_config(updated_config_file)


# =============================================================================
# Helper to run a test and report pass/fail
# =============================================================================

def _run_and_report(banner_text, congestion_point, test_name, ect=ECN_ECT_10):
    st.banner(banner_text)
    bundle = run_ecn_xoff_test(congestion_point, test_name, ect=ect)
    # Stash result bundle for later validator umbrella tests.
    data.ecn_results[(congestion_point, int(ect))] = bundle
    if bundle.get('passed'):
        st.report_pass("test_case_passed", "{} passed".format(test_name))
    else:
        st.report_fail("test_case_failed", "{} failed: {}".format(
            test_name, bundle.get('reason', '')))


# =============================================================================
# ECN Test Cases - ECT(10) at 3 Congestion Points
# =============================================================================

def test_ecn_l3vni_ect10_ingress_leaf_egress():
    """
    Test ECN marking at ingress leaf egress (Leaf0 -> Spine0/1).

    ECN disabled on: spine0, spine1, leaf1
    ECN marking expected at: leaf0
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Ingress Leaf Egress ECT(10) (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l3vni_ect10_ingress_leaf_egress",
        ect=ECN_ECT_10
    )


def test_ecn_l3vni_ect10_spine_egress():
    """
    Test ECN marking at spine egress (Spine0/1 -> Leaf1).

    ECN disabled on: leaf0, leaf1
    ECN marking expected at: spine0, spine1
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Spine Egress ECT(10) (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l3vni_ect10_spine_egress",
        ect=ECN_ECT_10
    )


def test_ecn_l3vni_ect10_egress_leaf_tgen():
    """
    Test ECN marking at egress leaf TGEN port (Leaf1 -> T1D4P1).

    ECN disabled on: leaf0, spine0, spine1
    ECN marking expected at: leaf1
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Egress Leaf TGEN ECT(10) (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l3vni_ect10_egress_leaf_tgen",
        ect=ECN_ECT_10
    )


# =============================================================================
# ECN Test Cases - ECT(01) at 3 Congestion Points
# =============================================================================

def test_ecn_l3vni_ect01_ingress_leaf_egress():
    """
    Test ECN marking at ingress leaf egress (Leaf0 -> Spine0/1) with ECT(1).

    ECN disabled on: spine0, spine1, leaf1
    ECN marking expected at: leaf0
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Ingress Leaf Egress ECT(01) (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l3vni_ect01_ingress_leaf_egress",
        ect=ECN_ECT_01
    )


def test_ecn_l3vni_ect01_spine_egress():
    """
    Test ECN marking at spine egress (Spine0/1 -> Leaf1) with ECT(1).

    ECN disabled on: leaf0, leaf1
    ECN marking expected at: spine0, spine1
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Spine Egress ECT(01) (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l3vni_ect01_spine_egress",
        ect=ECN_ECT_01
    )


def test_ecn_l3vni_ect01_egress_leaf_tgen():
    """
    Test ECN marking at egress leaf TGEN port (Leaf1 -> T1D4P1) with ECT(1).

    ECN disabled on: leaf0, spine0, spine1
    ECN marking expected at: leaf1
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Egress Leaf TGEN ECT(01) (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l3vni_ect01_egress_leaf_tgen",
        ect=ECN_ECT_01
    )


# =============================================================================
# ECN Test Cases - Not-ECT (00) at 3 Congestion Points (no marking expected)
# =============================================================================

def test_ecn_l3vni_noect_ingress_leaf_egress():
    """
    Test with Not-ECT at ingress leaf egress (Leaf0 -> Spine0/1).

    ECN disabled on: spine0, spine1, leaf1
    No ECN marking expected (Not-ECT traffic should not be marked)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Ingress Leaf Egress NotECT (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l3vni_noect_ingress_leaf_egress",
        ect=ECN_NOT_ECT
    )


def test_ecn_l3vni_noect_spine_egress():
    """
    Test with Not-ECT at spine egress (Spine0/1 -> Leaf1).

    ECN disabled on: leaf0, leaf1
    No ECN marking expected (Not-ECT traffic should not be marked)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Spine Egress NotECT (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l3vni_noect_spine_egress",
        ect=ECN_NOT_ECT
    )


def test_ecn_l3vni_noect_egress_leaf_tgen():
    """
    Test with Not-ECT at egress leaf TGEN port (Leaf1 -> T1D4P1).

    ECN disabled on: leaf0, spine0, spine1
    No ECN marking expected (Not-ECT traffic should not be marked)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Egress Leaf TGEN NotECT (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l3vni_noect_egress_leaf_tgen",
        ect=ECN_NOT_ECT
    )


# =============================================================================
# ECN Test Cases - Already CE (11) at 3 Congestion Points (log only, no marking)
# =============================================================================

def test_ecn_l3vni_ce_ingress_leaf_egress():
    """
    Test with CE at ingress leaf egress (Leaf0 -> Spine0/1).

    ECN disabled on: spine0, spine1, leaf1
    Already CE traffic - should remain CE (log only)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Ingress Leaf Egress CE (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l3vni_ce_ingress_leaf_egress",
        ect=ECN_CE
    )


def test_ecn_l3vni_ce_spine_egress():
    """
    Test with CE at spine egress (Spine0/1 -> Leaf1).

    ECN disabled on: leaf0, leaf1
    Already CE traffic - should remain CE (log only)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Spine Egress CE (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l3vni_ce_spine_egress",
        ect=ECN_CE
    )


def test_ecn_l3vni_ce_egress_leaf_tgen():
    """
    Test with CE at egress leaf TGEN port (Leaf1 -> T1D4P1).

    ECN disabled on: leaf0, spine0, spine1
    Already CE traffic - should remain CE (log only)
    """
    _run_and_report(
        "TEST: ECN L3VNI XOFF - Egress Leaf TGEN CE (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l3vni_ce_egress_leaf_tgen",
        ect=ECN_CE
    )


# =============================================================================
# Natural-congestion (no PFC XOFF stream from TGEN) test
# =============================================================================

def test_ecn_l3vni_ect10_ingress_leaf_egress_no_pfc():
    """ECT(10) at ingress_leaf_egress with NO PFC XOFF stream from TGEN.

    Two iterations:
      99% rate -> congested via VXLAN encap overhead (expect ECN marks + PFC TX)
      90% rate -> uncongested (expect no marks, no PFC TX, full throughput)

    Both bundles are stashed in data.ecn_natural_results for the umbrella
    validator test_l3vni_validate_natural_congestion to consume.
    """
    st.banner("TEST: ECN L3VNI no-PFC natural congestion @ 99%% then 90%%")
    orig_rate = data.rate_percent
    orig_frame_size = data.frame_size
    test_passed = True
    fail_reason = ''

    # Optimization: if the fabric egress port is faster than the TGEN
    # ingress port, the ingress leaf can never be congested by a single
    # ingress flow + VXLAN encap overhead (~5%%). The 99%% iteration is
    # then equivalent in classification to the 90%% iteration -- both
    # uncongested. Skip the redundant 90%% run.
    ingress_bw, egress_bw = base.ingress_leaf_speeds(data.topology)
    rates = [99, 90]
    if ingress_bw and egress_bw and egress_bw > ingress_bw:
        st.log("Skipping 90%% iteration: fabric egress {}G > ingress {}G "
               "(99%% is also uncongested; redundant)".format(egress_bw, ingress_bw))
        rates = [99]

    # Frame-size selection: when fabric egress is exactly 2x the TGEN ingress
    # speed, the leaf cannot be congested by large-MTU frames at line rate
    # (encap overhead is dwarfed by the speed delta). Drop to 64B so the
    # PPS pressure / lookup pressure rises enough to exercise the path.
    # Same-speed (and any other ratio) keeps the default 1350B frame.
    if ingress_bw and egress_bw and egress_bw == 2 * ingress_bw:
        data.frame_size = "64"
        st.log("Using 64B frames: fabric egress {}G == 2x ingress {}G".format(
            egress_bw, ingress_bw))
    else:
        st.log("Using default {}B frames (ingress={}G, egress={}G)".format(
            orig_frame_size, ingress_bw, egress_bw))

    try:
        for rate in rates:
            data.rate_percent = str(rate)
            tname = "test_ecn_l3vni_ect10_ingress_leaf_egress_no_pfc_rate{}".format(rate)
            st.banner("Iteration: rate={}%% ({})".format(rate, tname))
            bundle = run_ecn_xoff_test(
                'ingress_leaf_egress', tname,
                ect=ECN_ECT_10, skip_pfc_xoff_stream=True,
            )
            data.ecn_natural_results[
                ('ingress_leaf_egress', int(ECN_ECT_10), int(rate))
            ] = bundle
            if not bundle.get('passed'):
                test_passed = False
                fail_reason = "{}: {}".format(tname, bundle.get('reason', ''))
    finally:
        data.rate_percent = orig_rate
        data.frame_size = orig_frame_size

    if test_passed:
        st.report_pass("test_case_passed", "natural-congestion runner completed")
    else:
        st.report_fail("test_case_failed", fail_reason or "see runner errors")


# =============================================================================
# Natural-congestion 2-to-1 test (runs only when fabric_egress == 2 * ingress)
# =============================================================================

def _toggle_d3t1p2_vlan2(nodes, vars, add):
    """Add or remove D3T1P2 from Vlan2 on leaf0.

    Vlan2 SVI on leaf0 already carries 2002:db8:1::1/64, so the TGEN port
    just needs to be a tagged-untagged member of the VLAN -- no new DUT IP
    config required.
    """
    dut = nodes['leaf0']
    op = "add" if add else "del"
    st.banner(f"{'Adding' if add else 'Removing'} {vars.D3T1P2} {'to' if add else 'from'} Vlan2 on leaf0")
    st.config(dut,
              f"sudo config vlan member {op} {'-u ' if add else ''}2 {vars.D3T1P2}",
              skip_error_check=True)


def _patch_topology_add_second_ingress(vars, nodes, add):
    """Temporarily add/remove vars.D3T1P2 to leaf0.ingress_ports + all_ports.

    Makes the per-node snapshot include the second ingress port so the test
    log shows both ingress streams' counters / PG watermarks / PFC TX.
    Speed is queried and stamped onto port_speeds.
    """
    leaf0_entry = data.topology.get('leaf0')
    if not leaf0_entry:
        return
    port = vars.D3T1P2
    ingress = leaf0_entry.setdefault('ingress_ports', [])
    all_ports = leaf0_entry.setdefault('all_ports', [])
    port_speeds = leaf0_entry.setdefault('port_speeds', {})
    if add:
        if port not in ingress:
            ingress.append(port)
        if port not in all_ports:
            all_ports.append(port)
        try:
            sp = qos_utils.get_if_speed(nodes['leaf0'], port)
            port_speeds[port] = int(sp) if sp else 0
        except Exception as e:
            st.log(f"topology patch: speed query for {port} failed: {e}")
            port_speeds[port] = 0
        st.log(f"topology patch: leaf0 ingress_ports now {ingress}, "
               f"port_speeds[{port}]={port_speeds.get(port)}")
    else:
        if port in ingress:
            ingress.remove(port)
        if port in all_ports:
            all_ports.remove(port)
        port_speeds.pop(port, None)
        st.log(f"topology unpatch: leaf0 ingress_ports now {ingress}")


def test_ecn_l3vni_ect10_ingress_leaf_egress_no_pfc_2to1():
    """ECT(10) natural congestion at ingress_leaf_egress with TWO ingress streams.

    Runs only when the fabric egress port speed (leaf0 -> spine) is
    exactly 2x the TGEN ingress port speed (TGEN -> leaf0). In that case
    a single 99% ingress flow cannot congest the leaf's fabric egress;
    two ingress streams at 99% each (sharing the same egress port) can.

    On non-2:1 topologies the test is skipped with a clear log message.

    Standalone pass/fail (no validator umbrella):
        PASS iff bundle completed without exception AND tx_frames > 0.
    """
    vars = st.get_testbed_vars()
    nodes = get_nodes()

    ingress_bw, egress_bw = base.ingress_leaf_speeds(data.topology)
    if not (ingress_bw and egress_bw and egress_bw == 2 * ingress_bw):
        msg = (f"Skipping: requires fabric egress == 2x ingress; "
               f"got ingress={ingress_bw}G egress={egress_bw}G")
        st.log(msg)
        pytest.skip(msg)

    if not hasattr(vars, 'D3T1P2'):
        msg = "Skipping: testbed has no D3T1P2 (second leaf0 TGEN port required)"
        st.log(msg)
        pytest.skip(msg)

    st.banner("TEST: ECN L3VNI 2-to-1 natural congestion @ 99%% per stream "
              f"(ingress={ingress_bw}G, egress={egress_bw}G)")

    vlan_added = False
    topo_patched = False
    bundle = None
    try:
        _toggle_d3t1p2_vlan2(nodes, vars, add=True)
        vlan_added = True
        _patch_topology_add_second_ingress(vars, nodes, add=True)
        topo_patched = True
        st.wait(2)

        bundle = base.run_ecn_xoff_test(
            data, 'ingress_leaf_egress',
            "test_ecn_l3vni_ect10_ingress_leaf_egress_no_pfc_2to1",
            ect=ECN_ECT_10,
            port_speed_gbps=port_speed_gbps,
            vtep_ips=(LEAF0_VTEP_IP, LEAF1_VTEP_IP),
            diagnostics_hook=dump_l3vni_diagnostics,
            pre_ngpf_diagnostics_hook=_l3vni_pre_ngpf_diagnostics,
            setup_tgen_post_handles_hook=_l3vni_resolve_gateway_nd,
            clear_wred_pre_traffic=False,
            save_config_nodes=['leaf0', 'leaf1', 'spine0'],
            skip_pfc_xoff_stream=True,
            stream_setup_fn=base.setup_tgen_interfaces_and_streams_2to1,
        )
    finally:
        if topo_patched:
            try:
                _patch_topology_add_second_ingress(vars, nodes, add=False)
            except Exception as cleanup_err:
                st.log(f"Topology unpatch failed: {cleanup_err}")
        if vlan_added:
            try:
                _toggle_d3t1p2_vlan2(nodes, vars, add=False)
            except Exception as cleanup_err:
                st.log(f"Cleanup of D3T1P2 vlan2 membership failed: {cleanup_err}")

    if bundle is None:
        st.report_fail("test_case_failed", "runner returned no bundle")
        return

    tx_frames = int(bundle.get('tx_frames') or 0)
    rx_frames = int(bundle.get('rx_frames') or 0)
    total_marked = int(bundle.get('total_ecn_marked') or 0)

    # ---- Inspect snapshot for backpressure correctness ----
    # Expectations on a healthy ingress-leaf-egress congestion:
    #   * leaf0 (ingress leaf): pfc_tx > 0  (PFC propagated back to TGEN)
    #   * leaf0 (ingress leaf): tx_drops == 0 on the lossless TC
    #     (any tx_drops mean PFC backpressure failed to hold the queue)
    snap = bundle.get('snapshot_summary') or {}
    leaf0_totals = (snap.get('leaf0') or {}).get('totals') or {}
    leaf0_pfc_tx = int(leaf0_totals.get('pfc_tx') or 0)
    leaf0_tx_drops = int(leaf0_totals.get('tx_drops') or 0)
    leaf0_queue_drops = int(leaf0_totals.get('queue_drop_pkts') or 0)
    leaf0_pg_drops = int(leaf0_totals.get('pg_drop') or 0)

    st.log(f"2-to-1 result: passed={bundle.get('passed')} tx={tx_frames} "
           f"rx={rx_frames} ecn_marked={total_marked} "
           f"leaf0_pfc_tx={leaf0_pfc_tx} leaf0_tx_drops={leaf0_tx_drops} "
           f"leaf0_queue_drops_uc{data.tc}={leaf0_queue_drops} "
           f"leaf0_pg_drops={leaf0_pg_drops} "
           f"reason='{bundle.get('reason', '')}'")

    if not bundle.get('passed'):
        st.report_fail("test_case_failed",
                       f"runner failed: {bundle.get('reason', '')}")
        return
    if tx_frames <= 0:
        st.report_fail("test_case_failed", "no traffic transmitted (tx_frames=0)")
        return

    failures = []
    if leaf0_tx_drops > 0 or leaf0_queue_drops > 0:
        failures.append(
            f"ingress leaf has egress drops on lossless TC{data.tc}: "
            f"tx_drops={leaf0_tx_drops} queue_drop_pkts={leaf0_queue_drops} "
            "(PFC backpressure failed to hold the queue)")
    if leaf0_pfc_tx <= 0:
        failures.append(
            f"ingress leaf did not generate PFC TX back to TGEN "
            f"(leaf0_pfc_tx={leaf0_pfc_tx}); expected XOFF when buffer fills")

    if failures:
        msg = "; ".join(failures)
        st.error(f"2-to-1 backpressure check FAILED: {msg}")
        st.report_fail("test_case_failed", msg)
        return

    st.report_pass("test_case_passed",
                   f"2-to-1 ingress run completed: tx={tx_frames} "
                   f"rx={rx_frames} ecn_marked={total_marked} "
                   f"leaf0_pfc_tx={leaf0_pfc_tx}")


# =============================================================================
# Validator umbrella tests
# =============================================================================
# Loop the bundles in data.ecn_results and emit one sub-report per
# (congestion_point, ect) iteration via st.report_tc_pass/fail. The
# function-level pass/fail flips if any sub-report failed.
# =============================================================================

import validators_vxlan_ecn as validators
from vxlan_ecn_base import ect_label


def _run_validator_umbrella(criterion_label, validate_fn):
    """Loop ecn_results, call validate_fn(bundle), emit per-node sub-reports.

    Each validator returns a list of verdict dicts. We emit one tc sub-report
    per (bundle, verdict) pair with tcid '{label}_{cp}_{ect}_{node}'.
    """
    overall_pass = True
    if not data.ecn_results:
        st.report_fail("test_case_failed",
                       "{}: no ecn_results stashed (no traffic ran)".format(
                           criterion_label))
        return

    for (cp, ect), bundle in sorted(data.ecn_results.items()):
        base_tcid = "{}_{}_{}".format(criterion_label, cp, ect_label(ect))
        if bundle.get('exception'):
            st.report_tc_fail(base_tcid + "_all", "test_case_failed",
                              "runner exception: {}".format(bundle.get('exception')))
            overall_pass = False
            continue
        try:
            verdicts = validate_fn(bundle)
        except Exception as ve:
            st.report_tc_fail(base_tcid + "_all", "test_case_failed",
                              "validator error: {}".format(ve))
            overall_pass = False
            continue
        if not verdicts:
            st.report_tc_fail(base_tcid + "_all", "test_case_failed",
                              "validator returned no verdicts")
            overall_pass = False
            continue
        for v in verdicts:
            node = v.get('node', 'all')
            tcid = "{}_{}".format(base_tcid, node)
            passed = bool(v.get('passed'))
            reason = v.get('reason', '')
            st.log("[{}] {} ({} {}): {} -- {} -- {}".format(
                criterion_label, tcid,
                v.get('role', '?'), v.get('platform', '?'),
                "PASS" if passed else "FAIL", reason, v.get('metrics', {})))
            if passed:
                st.report_tc_pass(tcid, "test_case_passed")
            else:
                st.report_tc_fail(tcid, "test_case_failed", reason)
                overall_pass = False

    if overall_pass:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed", "see sub-test failures")


def test_l3vni_validate_ecn_marking():
    """Umbrella validator: ECN marking counter check across all 12 iterations."""
    _run_validator_umbrella("L3vniEcnMark", validators.validate_ecn_marking)


def test_l3vni_validate_throughput():
    """Umbrella validator: end-to-end throughput across all 12 iterations."""
    _run_validator_umbrella("L3vniThroughput", validators.validate_throughput)


def test_l3vni_validate_lossless_no_drops():
    """Umbrella validator: no queue drops on lossless TC across all iterations."""
    _run_validator_umbrella("L3vniLosslessNoDrops", validators.validate_lossless_no_drops)


def test_l3vni_validate_pfc_xoff():
    """Umbrella validator: PFC XOFF received at congestion point."""
    _run_validator_umbrella("L3vniPfcXoff", validators.validate_pfc_xoff)


def test_l3vni_validate_pg_drops():
    """Umbrella validator: no priority-group drops across nodes."""
    _run_validator_umbrella("L3vniPgDrops", validators.validate_pg_drops)


def test_l3vni_validate_natural_congestion():
    """Umbrella validator: natural-congestion runs (no PFC XOFF stream).

    Iterates data.ecn_natural_results (keyed by (cp, ect, rate_pct)) and
    emits one sub-report per (iteration, marking-node).
    """
    label = "L3vniNaturalCongestion"
    overall_pass = True
    if not data.ecn_natural_results:
        st.report_fail("test_case_failed",
                       "{}: no ecn_natural_results stashed".format(label))
        return

    for (cp, ect, rate), bundle in sorted(data.ecn_natural_results.items()):
        base_tcid = "{}_{}_{}_{}pct".format(label, cp, ect_label(ect), rate)
        if bundle.get('exception'):
            st.report_tc_fail(base_tcid + "_all", "test_case_failed",
                              "runner exception: {}".format(bundle.get('exception')))
            overall_pass = False
            continue
        try:
            verdicts = validators.validate_natural_congestion(bundle)
        except Exception as ve:
            st.report_tc_fail(base_tcid + "_all", "test_case_failed",
                              "validator error: {}".format(ve))
            overall_pass = False
            continue
        if not verdicts:
            st.report_tc_fail(base_tcid + "_all", "test_case_failed",
                              "validator returned no verdicts")
            overall_pass = False
            continue
        for v in verdicts:
            tcid = "{}_{}".format(base_tcid, v.get('node', 'all'))
            passed = bool(v.get('passed'))
            reason = v.get('reason', '')
            st.log("[{}] {} ({} {}): {} -- {} -- {}".format(
                label, tcid, v.get('role', '?'), v.get('platform', '?'),
                "PASS" if passed else "FAIL", reason, v.get('metrics', {})))
            if passed:
                st.report_tc_pass(tcid, "test_case_passed")
            else:
                st.report_tc_fail(tcid, "test_case_failed", reason)
                overall_pass = False

    if overall_pass:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed", "see sub-test failures")

