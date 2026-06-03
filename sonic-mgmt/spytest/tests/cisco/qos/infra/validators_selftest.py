#!/usr/bin/env python3
"""
Mock self-test for the qos validator modules.

Builds synthetic TrafficRunResult-shaped bundles and runs every validator
against expected pass and fail scenarios. Also stubs the spytest 'st'
module enough to drive the umbrella-test logic end to end.

Run:
    cd .../qos && python3 validators_selftest.py

Exit 0 on success, non-zero on first failure.
"""

import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


# ---------------------------------------------------------------------------
# Recorder used by the umbrella simulation. Validators themselves are pure
# and do not touch this -- only the simulated _run_validator_umbrella below
# does.
# ---------------------------------------------------------------------------

class _StRecorder(object):
    def __init__(self):
        self.tc_pass = []
        self.tc_fail = []
        self.func_pass = None
        self.func_fail = None
        self.logs = []

    def reset(self):
        self.__init__()

    def report_tc_pass(self, tcid, msgid, *a):
        self.tc_pass.append((tcid, msgid, a))

    def report_tc_fail(self, tcid, msgid, *a):
        self.tc_fail.append((tcid, msgid, a))

    def report_pass(self, msgid, *a):
        self.func_pass = (msgid, a)

    def report_fail(self, msgid, *a):
        self.func_fail = (msgid, a)


_st = _StRecorder()

# ---------------------------------------------------------------------------
# Pre-inject a stub 'vxlan_ecn_base' so validators_*.py can import the ECN
# constants without dragging in spytest+tgen+etc.
# ---------------------------------------------------------------------------

ECN_NOT_ECT, ECN_ECT_01, ECN_ECT_10, ECN_CE = 0, 1, 2, 3
_LBL = {0: "NotEct", 1: "Ect01", 2: "Ect10", 3: "Ce"}


def ect_label(ect):
    return _LBL.get(int(ect), "Ect{}".format(ect))


_fake_base = types.ModuleType("vxlan_ecn_base")
_fake_base.ECN_NOT_ECT = ECN_NOT_ECT
_fake_base.ECN_ECT_01 = ECN_ECT_01
_fake_base.ECN_ECT_10 = ECN_ECT_10
_fake_base.ECN_CE = ECN_CE
_fake_base.ect_label = ect_label
sys.modules["vxlan_ecn_base"] = _fake_base

# ---------------------------------------------------------------------------
# Validator imports (direct, pure)
# ---------------------------------------------------------------------------

import validators_vxlan_ecn as V

v_ecn = type('NS', (), {'validate': staticmethod(V.validate_ecn_marking)})
v_thr = type('NS', (), {'validate': staticmethod(V.validate_throughput)})
v_drops = type('NS', (), {'validate': staticmethod(V.validate_lossless_no_drops)})
v_pfc = type('NS', (), {'validate': staticmethod(V.validate_pfc_xoff)})
v_pg = type('NS', (), {'validate': staticmethod(V.validate_pg_drops)})

# ---------------------------------------------------------------------------
# Mock bundle factory
# ---------------------------------------------------------------------------

CONGESTION_POINTS = [
    'spine_egress',
    'leaf_ingress',
    'egress_leaf_tgen',
]

ECTS = [ECN_NOT_ECT, ECN_ECT_01, ECN_ECT_10, ECN_CE]


def make_node(rx=0, tx=0, rxd=0, txd=0, pfc_rx=0, pfc_tx=0,
              q_pkts=0, q_drop=0, ecn_marked=0,
              pg_drop=0, pg_drop_per_pg=None):
    return {
        'totals': {
            'rx_packets':       rx,
            'tx_packets':       tx,
            'rx_drops':         rxd,
            'tx_drops':         txd,
            'pfc_rx':           pfc_rx,
            'pfc_tx':           pfc_tx,
            'queue_packets':    q_pkts,
            'queue_drop_pkts':  q_drop,
            'ecn_marked_pkts':  ecn_marked,
            'pg_drop':          pg_drop,
            'pg_drop_per_pg':   pg_drop_per_pg or {},
        }
    }


def make_bundle_pass(cp, ect, npu='gamut'):
    """Build a happy-path bundle: marking node has ECN marks (when applicable),
    PFC XOFF observed, no drops, throughput visible."""
    marking_node = {
        'spine_egress':       'spine0',
        'leaf_ingress':       'leaf0',
        'egress_leaf_tgen':   'leaf1',
    }[cp]

    # ECN marking expectations
    if ect in (ECN_ECT_01, ECN_ECT_10):
        ecn_marking_value = 100
        marking_role = 'congestion_point'
    elif ect == ECN_CE:
        ecn_marking_value = 100 if npu in ('laguna', 'carib') else 0
        marking_role = 'congestion_point' if npu in ('laguna', 'carib') else 'none'
    else:  # NOT_ECT
        ecn_marking_value = 0
        marking_role = 'none'

    snap = {
        'leaf0':  make_node(rx=10000, tx=10000, pfc_tx=50, pfc_rx=50),
        'spine0': make_node(rx=10000, tx=10000),
        'spine1': make_node(rx=10000, tx=10000),
        'leaf1':  make_node(rx=9500,  tx=9500),
    }
    # Stamp ECN marks on the marking node only
    if ecn_marking_value:
        snap[marking_node]['totals']['ecn_marked_pkts'] = ecn_marking_value

    bundle = {
        'passed':                  True,
        'reason':                  'ok',
        'congestion_point':        cp,
        'ect':                     ect,
        'test_name':               'mock_{}_{}'.format(cp, ect_label(ect)),
        'marking_role':            marking_role,
        'marking_nodes':           [marking_node] if ecn_marking_value or ect == ECN_CE else [],
        'marking_node_platforms':  [npu] if (ecn_marking_value or ect == ECN_CE) else [],
        'snapshot_summary':        snap,
        'pfc_info':                {},
        'pfc_xoff_nodes':          ['leaf0'],
        'congestion_pfc_delta':    50,
        'capture_results':         {},
        'tx_frames':               10000,
        'rx_frames':               9500,
        'wred_summary':            {},
        'ecn_marked_per_node':     {marking_node: ecn_marking_value},
        'total_ecn_marked':        ecn_marking_value,
        'wred_total_packets':      10000,
        'wred_total_ecn_marked':   ecn_marking_value,
        'captured_frames':         10,
        'basic_pass':              True,
        'ecn_counter_pass':        True,
        'capture_pass':            True,
        'exception':               None,
    }
    return bundle


def make_bundle_fail(cp, ect, fail_kind, npu='gamut'):
    """Mutate a passing bundle to inject a single failure of fail_kind."""
    b = make_bundle_pass(cp, ect, npu=npu)
    if fail_kind == 'no_ecn_marks':
        # Wipe ECN counters (only meaningful for ECT01/ECT10/CE-on-laguna-or-carib)
        for n in b['snapshot_summary']:
            b['snapshot_summary'][n]['totals']['ecn_marked_pkts'] = 0
        b['ecn_marked_per_node'] = {}
        b['total_ecn_marked'] = 0
        b['wred_total_ecn_marked'] = 0
    elif fail_kind == 'unexpected_ecn_marks':
        # Force NOT_ECT to show marks => fail
        b['snapshot_summary']['leaf1']['totals']['ecn_marked_pkts'] = 100
        b['ecn_marked_per_node'] = {'leaf1': 100}
        b['total_ecn_marked'] = 100
        b['wred_total_ecn_marked'] = 100
    elif fail_kind == 'no_throughput':
        b['rx_frames'] = 0
        b['wred_total_packets'] = 0
        b['wred_total_ecn_marked'] = 0
        b['captured_frames'] = 0
        for n in b['snapshot_summary']:
            b['snapshot_summary'][n]['totals']['rx_packets'] = 0
            b['snapshot_summary'][n]['totals']['tx_packets'] = 0
            b['snapshot_summary'][n]['totals']['ecn_marked_pkts'] = 0
    elif fail_kind == 'queue_drops':
        b['snapshot_summary']['leaf0']['totals']['queue_drop_pkts'] = 7
    elif fail_kind == 'no_pfc_xoff':
        b['congestion_pfc_delta'] = 0
        for n in b['snapshot_summary']:
            b['snapshot_summary'][n]['totals']['pfc_rx'] = 0
            b['snapshot_summary'][n]['totals']['pfc_tx'] = 0
    elif fail_kind == 'pg_drops':
        b['snapshot_summary']['leaf0']['totals']['pg_drop'] = 9
        b['snapshot_summary']['leaf0']['totals']['pg_drop_per_pg'] = {3: 9}
    else:
        raise ValueError("unknown fail_kind {}".format(fail_kind))
    return b


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

_failures = []


def expect(cond, label):
    if cond:
        print("  PASS  {}".format(label))
    else:
        print("  FAIL  {}".format(label))
        _failures.append(label)


def case(name, validator_fn, bundle, expected_pass):
    verdicts = validator_fn(bundle)
    if not isinstance(verdicts, list):
        label = "{} -> validator did not return a list (got {})".format(
            name, type(verdicts).__name__)
        expect(False, label)
        return
    if not verdicts:
        label = "{} -> validator returned empty list".format(name)
        expect(False, label)
        return
    aggregate = all(v.get('passed') for v in verdicts)
    reasons = "; ".join(
        "{}={}/{}".format(v.get('node', '?'),
                          "P" if v.get('passed') else "F",
                          v.get('reason', ''))
        for v in verdicts)
    label = "{} -> expected {} got {} ({} verdicts: {})".format(
        name, "PASS" if expected_pass else "FAIL",
        "PASS" if aggregate else "FAIL",
        len(verdicts), reasons)
    expect(aggregate == expected_pass, label)


# ---------------------------------------------------------------------------
# Per-validator scenarios
# ---------------------------------------------------------------------------

def test_ecn_marking():
    print("\n[validators_ecn_marking]")
    for cp in CONGESTION_POINTS:
        for ect in ECTS:
            case("happy {}/{}".format(cp, ect_label(ect)),
                 v_ecn.validate, make_bundle_pass(cp, ect),
                 expected_pass=True)
    # Negative: ECT_10 with no marks
    case("no_ecn_marks ECT_10",
         v_ecn.validate, make_bundle_fail('spine_egress', ECN_ECT_10, 'no_ecn_marks'),
         expected_pass=False)
    # Negative: NOT_ECT with unexpected marks
    case("unexpected_ecn_marks NOT_ECT",
         v_ecn.validate, make_bundle_fail('spine_egress', ECN_NOT_ECT, 'unexpected_ecn_marks'),
         expected_pass=False)
    # CE on laguna marking node should expect marks (G200 CE-quirk NPU)
    case("CE on laguna with marks (PASS)",
         v_ecn.validate, make_bundle_pass('spine_egress', ECN_CE, npu='laguna'),
         expected_pass=True)
    case("CE on laguna missing marks (FAIL)",
         v_ecn.validate, make_bundle_fail('spine_egress', ECN_CE, 'no_ecn_marks', npu='laguna'),
         expected_pass=False)
    # CE on carib marking node should expect marks (Q200 CE-quirk NPU)
    case("CE on carib with marks (PASS)",
         v_ecn.validate, make_bundle_pass('spine_egress', ECN_CE, npu='carib'),
         expected_pass=True)
    # ECMP-sibling exemption: two marking nodes (spine0+spine1), single flow
    # hashes to one. Sibling with 0 marks must pass; only "all marking siblings
    # zero" should fail.
    b = make_bundle_pass('spine_egress', ECN_ECT_10, npu='laguna')
    b['marking_nodes'] = ['spine0', 'spine1']
    b['marking_node_platforms'] = ['laguna', 'laguna']
    # spine0 has marks, spine1 has 0 -- ECMP sibling absorbed flow; both PASS.
    b['snapshot_summary']['spine0']['totals']['ecn_marked_pkts'] = 100
    b['snapshot_summary']['spine1']['totals']['ecn_marked_pkts'] = 0
    b['ecn_marked_per_node'] = {'spine0': 100, 'spine1': 0}
    b['total_ecn_marked'] = 100
    case("ECMP sibling: spine0 marks, spine1 0 (PASS)",
         v_ecn.validate, b, expected_pass=True)
    # Both marking siblings 0 -- still FAIL.
    b2 = make_bundle_pass('spine_egress', ECN_ECT_10, npu='laguna')
    b2['marking_nodes'] = ['spine0', 'spine1']
    b2['marking_node_platforms'] = ['laguna', 'laguna']
    b2['snapshot_summary']['spine0']['totals']['ecn_marked_pkts'] = 0
    b2['snapshot_summary']['spine1']['totals']['ecn_marked_pkts'] = 0
    b2['ecn_marked_per_node'] = {'spine0': 0, 'spine1': 0}
    b2['total_ecn_marked'] = 0
    case("ECMP sibling: both 0 (FAIL)",
         v_ecn.validate, b2, expected_pass=False)
    # Same for CE on CE-quirk NPU.
    b3 = make_bundle_pass('spine_egress', ECN_CE, npu='laguna')
    b3['marking_nodes'] = ['spine0', 'spine1']
    b3['marking_node_platforms'] = ['laguna', 'laguna']
    b3['snapshot_summary']['spine0']['totals']['ecn_marked_pkts'] = 100
    b3['snapshot_summary']['spine1']['totals']['ecn_marked_pkts'] = 0
    b3['ecn_marked_per_node'] = {'spine0': 100, 'spine1': 0}
    b3['total_ecn_marked'] = 100
    case("ECMP sibling CE quirk: spine0 marks, spine1 0 (PASS)",
         v_ecn.validate, b3, expected_pass=True)


def test_throughput():
    print("\n[validators_throughput]")
    case("happy", v_thr.validate, make_bundle_pass('spine_egress', ECN_ECT_10),
         expected_pass=True)
    case("no_throughput", v_thr.validate,
         make_bundle_fail('spine_egress', ECN_ECT_10, 'no_throughput'),
         expected_pass=False)
    # Stale per-node counters but bundle-level evidence positive => PASS.
    # Mirrors runner basic_pass tolerance for stale CLI/ASIC counters.
    b = make_bundle_pass('spine_egress', ECN_ECT_10)
    for n in b['snapshot_summary']:
        b['snapshot_summary'][n]['totals']['rx_packets'] = 0
        b['snapshot_summary'][n]['totals']['tx_packets'] = 0
    # bundle-level rx_frames / wred_total_packets / captured_frames remain > 0
    case("stale_per_node_with_bundle_evidence", v_thr.validate, b,
         expected_pass=True)


def test_lossless_no_drops():
    print("\n[validators_lossless_no_drops]")
    case("happy", v_drops.validate, make_bundle_pass('spine_egress', ECN_ECT_10),
         expected_pass=True)
    case("queue_drops", v_drops.validate,
         make_bundle_fail('spine_egress', ECN_ECT_10, 'queue_drops'),
         expected_pass=False)
    # Empty snapshot
    b = make_bundle_pass('spine_egress', ECN_ECT_10)
    b['snapshot_summary'] = {}
    case("empty snapshot -> FAIL", v_drops.validate, b, expected_pass=False)


def test_pfc_xoff():
    print("\n[validators_pfc_xoff]")
    case("happy", v_pfc.validate, make_bundle_pass('spine_egress', ECN_ECT_10),
         expected_pass=True)
    case("no_pfc_xoff", v_pfc.validate,
         make_bundle_fail('spine_egress', ECN_ECT_10, 'no_pfc_xoff'),
         expected_pass=False)


def test_pg_drops():
    print("\n[validators_pg_drops]")
    case("happy", v_pg.validate, make_bundle_pass('spine_egress', ECN_ECT_10),
         expected_pass=True)
    case("pg_drops", v_pg.validate,
         make_bundle_fail('spine_egress', ECN_ECT_10, 'pg_drops'),
         expected_pass=False)


# ---------------------------------------------------------------------------
# Natural congestion validator -- bundle factory + cases
# ---------------------------------------------------------------------------

v_nat = type('NS', (), {'validate': staticmethod(V.validate_natural_congestion)})


def make_bundle_natural(rate_pct, ingress_g, egress_g, frame_size,
                        ecn_marked, pfc_tx, eleaf_tx_pkts,
                        traffic_run_time=60):
    """Build a synthetic bundle for validate_natural_congestion."""
    ileaf_tgen = 'Ethernet1_T'
    ileaf_fab  = 'Ethernet1_F'
    eleaf_tgen = 'Ethernet2_T'
    eleaf_fab  = 'Ethernet2_F'
    snap = {
        'leaf0': {
            'role':   'ingress_leaf',
            'totals': {
                'rx_packets': 0, 'tx_packets': 0,
                'rx_drops': 0, 'tx_drops': 0,
                'pfc_rx': 0, 'pfc_tx': pfc_tx,
                'queue_packets': 0, 'queue_drop_pkts': 0,
                'ecn_marked_pkts': ecn_marked,
                'pg_drop': 0, 'pg_drop_per_pg': {},
            },
            'ports': {
                ileaf_tgen: {'rx_packets': eleaf_tx_pkts, 'tx_packets': 0},
                ileaf_fab:  {'rx_packets': 0, 'tx_packets': eleaf_tx_pkts},
            },
        },
        'leaf1': {
            'role':   'egress_leaf',
            'totals': {
                'rx_packets': 0, 'tx_packets': 0,
                'rx_drops': 0, 'tx_drops': 0,
                'pfc_rx': 0, 'pfc_tx': 0,
                'queue_packets': 0, 'queue_drop_pkts': 0,
                'ecn_marked_pkts': 0,
                'pg_drop': 0, 'pg_drop_per_pg': {},
            },
            'ports': {
                eleaf_tgen: {'rx_packets': 0, 'tx_packets': eleaf_tx_pkts},
                eleaf_fab:  {'rx_packets': eleaf_tx_pkts, 'tx_packets': 0},
            },
        },
    }
    return {
        'passed': True,
        'congestion_point': 'ingress_leaf_egress',
        'ect': ECN_ECT_10,
        'marking_nodes': ['leaf0'],
        'marking_node_platforms': ['gamut'],
        'snapshot_summary': snap,
        'ingress_load_pct': float(rate_pct),
        'frame_size': int(frame_size),
        'traffic_run_time': int(traffic_run_time),
        'port_speeds_per_node': {
            'leaf0': {ileaf_tgen: ingress_g, ileaf_fab: egress_g},
            'leaf1': {eleaf_tgen: ingress_g, eleaf_fab: egress_g},
        },
        'exception': None,
    }


def test_natural_congestion():
    print("\n[validators_natural_congestion]")

    # Compute per-test pkt counts so effective_tx clears the floor.
    # 400 Gbps * 60 s / ((1350+20)*8 bits) ~= 2.190e9 packets
    same_rate_pkts_99 = int((0.99 * 400e9 * 60) / ((1350 + 20) * 8))
    same_rate_pkts_90 = int((0.90 * 400e9 * 60) / ((1350 + 20) * 8))

    # Congested pass: 99% rate, equal BWs -> demand ~104.2% with 70/1350 overhead
    case("congested PASS (99% same BW)",
         v_nat.validate,
         make_bundle_natural(rate_pct=99, ingress_g=400, egress_g=400,
                             frame_size=1350,
                             ecn_marked=12345, pfc_tx=678,
                             eleaf_tx_pkts=same_rate_pkts_99),
         expected_pass=True)

    # Congested FAIL (no marks)
    case("congested FAIL no marks",
         v_nat.validate,
         make_bundle_natural(rate_pct=99, ingress_g=400, egress_g=400,
                             frame_size=1350,
                             ecn_marked=0, pfc_tx=678,
                             eleaf_tx_pkts=same_rate_pkts_99),
         expected_pass=False)

    # Congested FAIL (no pfc_tx)
    case("congested FAIL no pfc_tx",
         v_nat.validate,
         make_bundle_natural(rate_pct=99, ingress_g=400, egress_g=400,
                             frame_size=1350,
                             ecn_marked=12345, pfc_tx=0,
                             eleaf_tx_pkts=same_rate_pkts_99),
         expected_pass=False)

    # Uncongested PASS (90% rate, equal BWs -> demand ~94.6%, < 100)
    case("uncongested PASS (90% same BW)",
         v_nat.validate,
         make_bundle_natural(rate_pct=90, ingress_g=400, egress_g=400,
                             frame_size=1350,
                             ecn_marked=0, pfc_tx=0,
                             eleaf_tx_pkts=same_rate_pkts_90),
         expected_pass=True)

    # Uncongested FAIL (spurious marks)
    case("uncongested FAIL spurious marks",
         v_nat.validate,
         make_bundle_natural(rate_pct=90, ingress_g=400, egress_g=400,
                             frame_size=1350,
                             ecn_marked=42, pfc_tx=0,
                             eleaf_tx_pkts=same_rate_pkts_90),
         expected_pass=False)

    # Uncongested FAIL (TX rate too low)
    case("uncongested FAIL low TX",
         v_nat.validate,
         make_bundle_natural(rate_pct=90, ingress_g=400, egress_g=400,
                             frame_size=1350,
                             ecn_marked=0, pfc_tx=0,
                             eleaf_tx_pkts=int(same_rate_pkts_90 * 0.5)),
         expected_pass=False)


# ---------------------------------------------------------------------------
# Umbrella simulation -- mimic _run_validator_umbrella but local (no spytest
# data namespace required). This proves the loop+sub-report wiring shape.
# ---------------------------------------------------------------------------

def _simulate_umbrella(criterion_label, validate_fn, ecn_results):
    _st.reset()
    overall_pass = True
    for (cp, ect), bundle in sorted(ecn_results.items()):
        base_tcid = "{}_{}_{}".format(criterion_label, cp, ect_label(ect))
        if bundle.get('exception'):
            _st.report_tc_fail(base_tcid + "_all", "test_case_failed",
                               "runner exception: {}".format(bundle.get('exception')))
            overall_pass = False
            continue
        try:
            verdicts = validate_fn(bundle)
        except Exception as ve:
            _st.report_tc_fail(base_tcid + "_all", "test_case_failed",
                               "validator error: {}".format(ve))
            overall_pass = False
            continue
        if not verdicts:
            _st.report_tc_fail(base_tcid + "_all", "test_case_failed",
                               "validator returned no verdicts")
            overall_pass = False
            continue
        for v in verdicts:
            node = v.get('node', 'all')
            tcid = "{}_{}".format(base_tcid, node)
            if v.get('passed'):
                _st.report_tc_pass(tcid, "test_case_passed")
            else:
                _st.report_tc_fail(tcid, "test_case_failed", v.get('reason', ''))
                overall_pass = False
    if overall_pass:
        _st.report_pass("test_case_passed")
    else:
        _st.report_fail("test_case_failed", "see sub-test failures")
    return overall_pass


def test_umbrella_simulation():
    print("\n[umbrella simulation]")
    # Build a complete L2VNI-shaped 12-iteration result set, all PASS
    ecn_results_all_pass = {}
    for cp in CONGESTION_POINTS:
        for ect in ECTS:
            ecn_results_all_pass[(cp, int(ect))] = make_bundle_pass(cp, ect)

    ok = _simulate_umbrella("L2vniEcnMark", v_ecn.validate, ecn_results_all_pass)
    expect(ok is True, "all-pass umbrella reports overall PASS")
    # ecn_marking emits 1 verdict per snapshot node (4 per bundle).
    # 12 bundles * 4 = 48 sub-PASS reports.
    expect(len(_st.tc_pass) == 48, "ecn_marking: 12*4=48 sub-PASS reports emitted (got {})".format(len(_st.tc_pass)))
    expect(len(_st.tc_fail) == 0, "0 sub-FAIL reports emitted")

    # Inject 1 failure in the bundle set (marking node has no marks)
    ecn_results_one_fail = dict(ecn_results_all_pass)
    ecn_results_one_fail[('spine_egress', ECN_ECT_10)] = make_bundle_fail(
        'spine_egress', ECN_ECT_10, 'no_ecn_marks')
    ok = _simulate_umbrella("L2vniEcnMark", v_ecn.validate, ecn_results_one_fail)
    expect(ok is False, "one-fail umbrella reports overall FAIL")
    # 11 bundles * 4 + 3 nodes pass on the failing bundle = 47 PASS, 1 FAIL.
    expect(len(_st.tc_fail) == 1, "1 sub-FAIL emitted (got {})".format(len(_st.tc_fail)))
    expect(len(_st.tc_pass) == 47, "47 sub-PASS emitted (got {})".format(len(_st.tc_pass)))

    # Exception path
    ecn_results_exc = dict(ecn_results_all_pass)
    bad = dict(ecn_results_all_pass[('leaf_ingress', ECN_ECT_01)])
    bad['exception'] = "RuntimeError: TGEN died"
    ecn_results_exc[('leaf_ingress', ECN_ECT_01)] = bad
    ok = _simulate_umbrella("L2vniEcnMark", v_ecn.validate, ecn_results_exc)
    expect(ok is False, "exception-bundle umbrella reports overall FAIL")
    exc_fails = [t for t in _st.tc_fail if 'runner exception' in str(t)]
    expect(len(exc_fails) == 1, "exception sub-fail emitted (got {})".format(len(exc_fails)))

    # Per-node sub-report explosion: lossless validator should emit 4 verdicts
    # per bundle (one per snapshot node). 12 bundles * 4 = 48 sub-PASS.
    ok = _simulate_umbrella("L2vniLosslessNoDrops", v_drops.validate, ecn_results_all_pass)
    expect(ok is True, "lossless all-pass umbrella reports overall PASS")
    expect(len(_st.tc_pass) == 48,
           "lossless: 12*4=48 sub-PASS reports emitted (got {})".format(len(_st.tc_pass)))

    # Lossless with leaf0 dropping -> only the leaf0 sub-report fails per bundle
    ecn_results_one_node_fail = dict(ecn_results_all_pass)
    ecn_results_one_node_fail[('spine_egress', ECN_ECT_10)] = make_bundle_fail(
        'spine_egress', ECN_ECT_10, 'queue_drops')
    ok = _simulate_umbrella("L2vniLosslessNoDrops", v_drops.validate,
                            ecn_results_one_node_fail)
    expect(ok is False, "lossless one-node-fail umbrella reports overall FAIL")
    # 11 bundles all 4 nodes pass + 1 bundle with leaf0 fail (3 pass + 1 fail) = 47/1
    expect(len(_st.tc_fail) == 1, "lossless: 1 sub-FAIL emitted (got {})".format(len(_st.tc_fail)))
    expect(len(_st.tc_pass) == 47, "lossless: 47 sub-PASS emitted (got {})".format(len(_st.tc_pass)))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    test_ecn_marking()
    test_throughput()
    test_lossless_no_drops()
    test_pfc_xoff()
    test_pg_drops()
    test_natural_congestion()
    test_umbrella_simulation()

    print("\n" + "=" * 60)
    if _failures:
        print("FAILED: {} case(s)".format(len(_failures)))
        for f in _failures:
            print("  - {}".format(f))
        return 1
    print("ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
