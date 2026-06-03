"""
ECN Marking Accuracy Test over L2VNI with PFC XOFF Backpressure

Simplified ECN test that uses PFC XOFF frames from the egress TGEN to create
backpressure-induced congestion (instead of traffic oversubscription).

Topology: 2x Spine + 2 Leafs
    SD1 -- Spine0   - D1
    SD2 -- Spine1   - D2
    SD3 -- Leaf0    - D3 (ingress leaf)
    SD4 -- Leaf1    - D4 (egress leaf)

Traffic Path (L2 Bridged):
    T1D3P1 (data 99%) --> Leaf0 --> Spine0 --> Leaf1 <-- T1D4P1 (XOFF)

Congestion Mechanism:
    1. T1D4P1 sends continuous PFC XOFF frames for TC3 to pause Leaf1's egress
    2. Backpressure propagates: Leaf1 -> Spine0 -> Leaf0
    3. Congestion builds at each hop, triggering ECN CE marking

Congestion Points Tested:
    A. Ingress leaf egress (Leaf0 -> Spine0/1) - ECN disabled on spine0, spine1, leaf1
    B. Spine egress (Spine0/1 -> Leaf1)        - ECN disabled on leaf0, leaf1
    C. Egress leaf TGEN (Leaf1 -> T1D4P1)      - ECN disabled on leaf0, spine0, spine1

ECN Verification:
    - Pass criteria: Traffic flows and PFC XOFF received

"""

import os
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

# Use the L2VNI config file from vxlan directory
CONFIGS_FILE = '../../qos/ecn/vxlan_ecn_l2vni_2x1.yaml'

data = SpyTestDict()

# L2VNI uses same subnet on both ends (bridged traffic)
data.t1d3p1_ip6_addr = "2001::1"
data.t1d3p1_mac_addr = "00:0a:01:00:11:01"
data.t1d4p1_ip6_addr = "2001::2"
data.t1d4p1_mac_addr = "00:0a:01:00:12:01"
data.d3t1_ip6_addr = "2001::254"  # Gateway (not really used for L2)
data.d4t1_ip6_addr = "2001::254"  # Same gateway (L2 bridged)

# Traffic parameters
data.traffic_run_time = 60
data.tc = 3  # Traffic Class for PFC-enabled lossless queue
data.frame_size = "1350"
data.rate_percent = "99"
data.vlan_id = "100"
data.mask = "64"
data.addr_family = 'ipv6'
data.capture_count=100
data.node_meta = {}  # Per-node metadata: {node_name: {'platform_type': ...}}
data.topology = {}   # Role-aware per-node port descriptor (built in module_setup)
data.ecn_results = {}  # Bundles from each traffic run, keyed by (congestion_point, ect)
data.ecn_natural_results = {}  # Natural-congestion bundles, keyed by (congestion_point, ect, rate_pct)

# VTEP IPs for L2VNI topology (from original test)
LEAF0_VTEP_IP = 'fd27::280:10f1:25f'
LEAF1_VTEP_IP = 'fd27::22d:b87f:214b'

# ECN/ECT and congestion-point mappings are imported from vxlan_ecn_base.

# Module-level state
updated_config_file = None
port_speed_gbps = None
topo_info = None
platform_type = None  # 'n9164e' for Gamut, 'laguna' for HF6100-64ED (G200), 'carib' for HF6100-32D (Q200), 'generic' otherwise


def dump_l2vni_diagnostics(nodes, phase=""):
    """
    Dump L2VNI state for debugging - MAC tables, EVPN, VXLAN status.
    """
    st.banner("{} L2VNI DIAGNOSTICS".format(phase))
    for node_name in ['leaf0', 'leaf1']:
        dut = nodes[node_name]
        st.log("--- {} ---".format(node_name))
        # Check MAC table
        st.log("{}: show mac".format(node_name))
        st.show(dut, "show mac", skip_tmpl=True, skip_error_check=True)
        # Check EVPN MAC learning
        st.log("{}: show evpn mac vni 2727".format(node_name))
        st.config(dut, "vtysh -c 'show evpn mac vni 2727'", skip_error_check=True)
        # Check remote VTEP status
        st.log("{}: show vxlan remotevtep".format(node_name))
        st.show(dut, "show vxlan remotevtep", skip_tmpl=True, skip_error_check=True)


def run_ecn_xoff_test(congestion_point, test_name, ect=ECN_ECT_10,
                      skip_pfc_xoff_stream=False):
    """Thin wrapper: delegate to base runner with L2VNI hooks/flags."""
    return base.run_ecn_xoff_test(
        data, congestion_point, test_name, ect=ect,
        port_speed_gbps=port_speed_gbps,
        vtep_ips=(LEAF0_VTEP_IP, LEAF1_VTEP_IP),
        diagnostics_hook=dump_l2vni_diagnostics,
        skip_pfc_xoff_stream=skip_pfc_xoff_stream,
    )


@pytest.fixture(scope="module", autouse=True)
def module_setup():
    """
    Module-level setup for ECN XOFF tests.

    Steps:
        1. Initialize QoS (does config reload on Gamut - must be FIRST)
        2. Clean up any existing config
        3. Apply VXLAN/BGP config
        4. Wait for BGP EVPN convergence
        5. Get port speed for XOFF rate calculation
        6. Validate testbed topology (get port info for WRED counters)
        7. Verify ECN enabled
        8. Detect platform and build Gamut port mapping if needed
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

    # Step 3: Get port speed for XOFF rate calculation
    st.banner("STEP 3: Getting port speed for XOFF rate calculation")
    speeds = qos_utils.get_link_speeds(nodes, {'leaf1': [vars.D4T1P1]})
    port_speed_gbps = speeds['leaf1'][vars.D4T1P1]
    st.log("Port speed: {} Gbps, XOFF rate will be {} fps".format(
        port_speed_gbps, get_xoff_rate(port_speed_gbps)))
 
    # Step 4: Validate testbed topology (get port info for WRED counters)
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

    # Step 6: Generate L2VNI VXLAN/BGP configuration (merged from l2vni_config_hooks)
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
    st.wait(60)

    # DUMP full connectivity and BGP session details for debugging
    qos_utils.dump_vxlan_debug_info(nodes, "BGP session details")

    yield

    # Module cleanup - reload config_list since we're in a new scope
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
# ECN Test Cases - ECT(0) at 3 Congestion Points
# =============================================================================

def test_ecn_l2vni_ect10_ingress_leaf_egress():
    """
    Test ECN marking at ingress leaf egress (Leaf0 -> Spine0/1).

    ECN disabled on: spine0, spine1, leaf1
    ECN marking expected at: leaf0
    """
    _run_and_report(
        "TEST: ECN XOFF - Ingress Leaf Egress ECT(10) (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l2vni_ect10_ingress_leaf_egress",
        ect=ECN_ECT_10
    )


def test_ecn_l2vni_ect10_spine_egress():
    """
    Test ECN marking at spine egress (Spine0/1 -> Leaf1).

    ECN disabled on: leaf0, leaf1
    ECN marking expected at: spine0, spine1
    """
    _run_and_report(
        "TEST: ECN XOFF - Spine Egress ECT(10) (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l2vni_ect10_spine_egress",
        ect=ECN_ECT_10
    )


def test_ecn_l2vni_ect10_egress_leaf_tgen():
    """
    Test ECN marking at egress leaf TGEN port (Leaf1 -> T1D4P1).

    ECN disabled on: leaf0, spine0, spine1
    ECN marking expected at: leaf1
    """
    _run_and_report(
        "TEST: ECN XOFF - Egress Leaf TGEN ECT(10) (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l2vni_ect10_egress_leaf_tgen",
        ect=ECN_ECT_10
    )


# =============================================================================
# ECN Test Cases - ECT(1) at 3 Congestion Points
# =============================================================================

def test_ecn_l2vni_ect01_ingress_leaf_egress():
    """
    Test ECN marking at ingress leaf egress (Leaf0 -> Spine0/1) with ECT(1).

    ECN disabled on: spine0, spine1, leaf1
    ECN marking expected at: leaf0
    """
    _run_and_report(
        "TEST: ECN XOFF - Ingress Leaf Egress ECT(1) (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l2vni_ect01_ingress_leaf_egress",
        ect=ECN_ECT_01
    )


def test_ecn_l2vni_ect01_spine_egress():
    """
    Test ECN marking at spine egress (Spine0/1 -> Leaf1) with ECT(1).

    ECN disabled on: leaf0, leaf1
    ECN marking expected at: spine0, spine1
    """
    _run_and_report(
        "TEST: ECN XOFF - Spine Egress ECT(1) (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l2vni_ect01_spine_egress",
        ect=ECN_ECT_01
    )


def test_ecn_l2vni_ect01_egress_leaf_tgen():
    """
    Test ECN marking at egress leaf TGEN port (Leaf1 -> T1D4P1) with ECT(1).

    ECN disabled on: leaf0, spine0, spine1
    ECN marking expected at: leaf1
    """
    _run_and_report(
        "TEST: ECN XOFF - Egress Leaf TGEN ECT(1) (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l2vni_ect01_egress_leaf_tgen",
        ect=ECN_ECT_01
    )


# =============================================================================
# ECN Test Cases - Not-ECT (00) at 3 Congestion Points (no marking expected)
# =============================================================================

def test_ecn_l2vni_noect_ingress_leaf_egress():
    """
    Test with Not-ECT at ingress leaf egress (Leaf0 -> Spine0/1).

    ECN disabled on: spine0, spine1, leaf1
    No ECN marking expected (Not-ECT traffic should not be marked)
    """
    _run_and_report(
        "TEST: ECN XOFF - Ingress Leaf Egress NotECT (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l2vni_noect_ingress_leaf_egress",
        ect=ECN_NOT_ECT
    )


def test_ecn_l2vni_noect_spine_egress():
    """
    Test with Not-ECT at spine egress (Spine0/1 -> Leaf1).

    ECN disabled on: leaf0, leaf1
    No ECN marking expected (Not-ECT traffic should not be marked)
    """
    _run_and_report(
        "TEST: ECN XOFF - Spine Egress NotECT (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l2vni_noect_spine_egress",
        ect=ECN_NOT_ECT
    )


def test_ecn_l2vni_noect_egress_leaf_tgen():
    """
    Test with Not-ECT at egress leaf TGEN port (Leaf1 -> T1D4P1).

    ECN disabled on: leaf0, spine0, spine1
    No ECN marking expected (Not-ECT traffic should not be marked)
    """
    _run_and_report(
        "TEST: ECN XOFF - Egress Leaf TGEN NotECT (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l2vni_noect_egress_leaf_tgen",
        ect=ECN_NOT_ECT
    )


# =============================================================================
# ECN Test Cases - Already CE (11) at 3 Congestion Points (log only, no marking)
# =============================================================================

def test_ecn_l2vni_ce_ingress_leaf_egress():
    """
    Test with CE at ingress leaf egress (Leaf0 -> Spine0/1).

    ECN disabled on: spine0, spine1, leaf1
    Already CE traffic - should remain CE (log only)
    """
    _run_and_report(
        "TEST: ECN XOFF - Ingress Leaf Egress CE (Leaf0 -> Spine0/1)",
        'ingress_leaf_egress',
        "test_ecn_l2vni_ce_ingress_leaf_egress",
        ect=ECN_CE
    )


def test_ecn_l2vni_ce_spine_egress():
    """
    Test with CE at spine egress (Spine0/1 -> Leaf1).

    ECN disabled on: leaf0, leaf1
    Already CE traffic - should remain CE (log only)
    """
    _run_and_report(
        "TEST: ECN XOFF - Spine Egress CE (Spine0/1 -> Leaf1)",
        'spine_egress',
        "test_ecn_l2vni_ce_spine_egress",
        ect=ECN_CE
    )


def test_ecn_l2vni_ce_egress_leaf_tgen():
    """
    Test with CE at egress leaf TGEN port (Leaf1 -> T1D4P1).

    ECN disabled on: leaf0, spine0, spine1
    Already CE traffic - should remain CE (log only)
    """
    _run_and_report(
        "TEST: ECN XOFF - Egress Leaf TGEN CE (Leaf1 -> T1D4P1)",
        'egress_leaf_tgen',
        "test_ecn_l2vni_ce_egress_leaf_tgen",
        ect=ECN_CE
    )


# =============================================================================
# Natural-congestion (no PFC XOFF stream from TGEN) test
# =============================================================================

def test_ecn_l2vni_ect10_ingress_leaf_egress_no_pfc():
    """ECT(10) at ingress_leaf_egress with NO PFC XOFF stream from TGEN.

    Two iterations:
      99% rate -> congested via VXLAN encap overhead (expect ECN marks + PFC TX)
      90% rate -> uncongested (expect no marks, no PFC TX, full throughput)

    Both bundles are stashed in data.ecn_natural_results for the umbrella
    validator test_l2vni_validate_natural_congestion to consume.
    """
    st.banner("TEST: ECN L2VNI no-PFC natural congestion @ 99%% then 90%%")
    orig_rate = data.rate_percent
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

    try:
        for rate in rates:
            data.rate_percent = str(rate)
            tname = "test_ecn_l2vni_ect10_ingress_leaf_egress_no_pfc_rate{}".format(rate)
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

    if test_passed:
        st.report_pass("test_case_passed", "natural-congestion runner completed")
    else:
        st.report_fail("test_case_failed", fail_reason or "see runner errors")


# =============================================================================
# Validator umbrella tests
# =============================================================================
# These run AFTER the 12 traffic-running tests above. Each umbrella test
# loops over the stashed bundles in data.ecn_results and emits one
# sub-report per (congestion_point, ect) iteration via
# st.report_tc_pass/fail. The function-level pass/fail flips if any
# sub-report failed.
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


def test_l2vni_validate_ecn_marking():
    """Umbrella validator: ECN marking counter check across all 12 iterations."""
    _run_validator_umbrella("L2vniEcnMark", validators.validate_ecn_marking)


def test_l2vni_validate_throughput():
    """Umbrella validator: end-to-end throughput across all 12 iterations."""
    _run_validator_umbrella("L2vniThroughput", validators.validate_throughput)


def test_l2vni_validate_lossless_no_drops():
    """Umbrella validator: no queue drops on lossless TC across all iterations."""
    _run_validator_umbrella("L2vniLosslessNoDrops", validators.validate_lossless_no_drops)


def test_l2vni_validate_pfc_xoff():
    """Umbrella validator: PFC XOFF received at congestion point."""
    _run_validator_umbrella("L2vniPfcXoff", validators.validate_pfc_xoff)


def test_l2vni_validate_pg_drops():
    """Umbrella validator: no priority-group drops across nodes."""
    _run_validator_umbrella("L2vniPgDrops", validators.validate_pg_drops)


def test_l2vni_validate_natural_congestion():
    """Umbrella validator: natural-congestion runs (no PFC XOFF stream).

    Iterates data.ecn_natural_results (keyed by (cp, ect, rate_pct)) and
    emits one sub-report per (iteration, marking-node).
    """
    label = "L2vniNaturalCongestion"
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

