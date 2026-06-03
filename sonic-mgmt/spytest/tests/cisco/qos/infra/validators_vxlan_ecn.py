"""
Validators for VXLAN ECN tests (L2VNI + L3VNI).

Each validator is a pure function:
    validate_<name>(bundle, rules=None) -> list[verdict]

A verdict is:
    {
        'node':     <node-name> | 'all',
        'role':     <role-tag>,
        'platform': <npu-tag> | 'unknown',
        'passed':   bool,
        'reason':   str,
        'metrics':  dict,
    }

Validators (registry exposed at bottom):
    validate_ecn_marking       -- per snapshot node; marking vs non-marking
    validate_throughput        -- per snapshot node; rx/tx visibility
    validate_lossless_no_drops -- per snapshot node; queue_drop_pkts == 0
    validate_pfc_xoff          -- per snapshot node; xoff_target vs observer
    validate_pg_drops          -- per snapshot node; pg_drop == 0
"""

from vxlan_ecn_base import (
    ECN_NOT_ECT, ECN_ECT_01, ECN_ECT_10, ECN_CE,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _platform_for(node, marking_nodes, marking_platforms):
    for i, n in enumerate(marking_nodes):
        if n == node and i < len(marking_platforms):
            return marking_platforms[i]
    return 'unknown'


def _empty_snap_verdict(reason, role='all', metrics=None):
    return [{
        'node':     'all',
        'role':     role,
        'platform': 'unknown',
        'passed':   False,
        'reason':   reason,
        'metrics':  metrics or {},
    }]


# ---------------------------------------------------------------------------
# ECN marking
# ---------------------------------------------------------------------------

def validate_ecn_marking(bundle, rules=None):
    """ECN marking counter check.

    If marks are expected (ECT(01)/ECT(10), or CE on laguna/carib):
      - marking nodes  -> ecn_marked > 0  (pass), with ECMP-sibling exemption:
          when there is more than one marking node for this congestion role
          and the test uses a single 5-tuple flow, ECMP will hash the flow
          onto exactly one sibling. A marking node with 0 marks PASSES if at
          least one of its marking-node siblings has marks > 0.
      - non-marking    -> ecn_marked == 0 (pass)
    Else (Not-ECT, or CE on non-quirk NPU):
      - every node     -> ecn_marked == 0 (pass)
    """
    ect = int(bundle.get('ect', 0))
    marking_nodes = list(bundle.get('marking_nodes', []) or [])
    marking_platforms = list(bundle.get('marking_node_platforms', []) or [])
    ecn_per_node = dict(bundle.get('ecn_marked_per_node', {}) or {})
    snap = bundle.get('snapshot_summary', {}) or {}

    any_ce_quirk_npu = any(p in ('laguna', 'carib') for p in marking_platforms)
    expect_marks_per_node = (
        ect in (ECN_ECT_01, ECN_ECT_10) or
        (ect == ECN_CE and any_ce_quirk_npu)
    )

    # ECMP-sibling exemption: when multiple marking nodes share this role,
    # a single-flow test will only hash to one. Sum across siblings -- if
    # any sibling marked, the role as a whole is satisfied.
    marking_node_total = 0
    for n in marking_nodes:
        if n in ecn_per_node:
            marking_node_total += int(ecn_per_node.get(n, 0))
        else:
            marking_node_total += int(
                (snap.get(n, {}).get('totals', {}) or {}).get('ecn_marked_pkts', 0))
    multi_marking = len(marking_nodes) > 1

    if not snap:
        return _empty_snap_verdict(
            'no snapshot_summary available',
            metrics={'ect': ect, 'marking_nodes': marking_nodes})

    verdicts = []
    for node in sorted(snap.keys()):
        if node in ecn_per_node:
            n_marks = int(ecn_per_node.get(node, 0))
        else:
            totals = snap[node].get('totals', {}) or {}
            n_marks = int(totals.get('ecn_marked_pkts', 0))

        is_marking = node in marking_nodes
        plat = _platform_for(node, marking_nodes, marking_platforms)
        role = 'marking' if is_marking else 'non_marking'
        metrics = {'ect': ect, 'ecn_marked': n_marks, 'is_marking_node': is_marking}
        if multi_marking and is_marking:
            metrics['marking_role_total'] = marking_node_total
            metrics['marking_siblings'] = list(marking_nodes)

        if expect_marks_per_node and is_marking:
            ce_quirk = (ect == ECN_CE and plat in ('laguna', 'carib'))
            if n_marks > 0:
                reason = ('CE-quirk NPU: {} ECN marked'.format(n_marks)
                          if ce_quirk else '{} ECN marked'.format(n_marks))
                passed = True
            elif multi_marking and marking_node_total > 0:
                # ECMP sibling absorbed the single flow.
                reason = ('ECMP-sibling exemption: 0 ECN marked here, but '
                          'marking-node siblings {} have total {} marked'.format(
                              [s for s in marking_nodes if s != node],
                              marking_node_total))
                passed = True
            else:
                reason = ('CE-quirk NPU: 0 ECN marked (expected > 0)'
                          if ce_quirk else '0 ECN marked (expected > 0)')
                passed = False
        else:
            if n_marks == 0:
                reason = 'no ECN marking (as expected)'
                passed = True
            else:
                reason = 'unexpected ECN marking: {}'.format(n_marks)
                passed = False

        verdicts.append({
            'node':     node,
            'role':     role,
            'platform': plat,
            'passed':   passed,
            'reason':   reason,
            'metrics':  metrics,
        })
    return verdicts


# ---------------------------------------------------------------------------
# Throughput
# ---------------------------------------------------------------------------

def validate_throughput(bundle, rules=None):
    """Throughput check per snapshot node.

    Per-node rule:
      - PASS if snapshot rx_packets > 0 OR tx_packets > 0.
      - Else PASS via bundle-level fallback if any of
        rx_frames / wred_total_packets / wred_total_ecn_marked /
        captured_frames is > 0 (CLI/ASIC counters can be stale on some
        platforms; the runner historically relied on these as alternate
        evidence of traffic).
      - Else FAIL.
    Metrics expose rx/tx/rxd/txd so reduction is visible across the chain.
    """
    snap = bundle.get('snapshot_summary', {}) or {}

    # Bundle-level fallback evidence (mirrors runner basic_pass).
    rx_frames = int(bundle.get('rx_frames', 0))
    wred_total_packets = int(bundle.get('wred_total_packets', 0))
    wred_total_ecn_marked = int(bundle.get('wred_total_ecn_marked', 0))
    captured_frames = int(bundle.get('captured_frames', 0))
    fallback = {
        'rx_frames':             rx_frames,
        'wred_total_packets':    wred_total_packets,
        'wred_total_ecn_marked': wred_total_ecn_marked,
        'captured_frames':       captured_frames,
    }
    fallback_evidence = (rx_frames > 0 or wred_total_packets > 0 or
                         wred_total_ecn_marked > 0 or captured_frames > 0)

    if not snap:
        if fallback_evidence:
            return [{
                'node':     'all',
                'role':     'all',
                'platform': 'unknown',
                'passed':   True,
                'reason':   'throughput observed (no snapshot): {}'.format(fallback),
                'metrics':  fallback,
            }]
        return _empty_snap_verdict(
            'no throughput observed and no snapshot available',
            metrics=fallback)

    verdicts = []
    for node in sorted(snap.keys()):
        totals = snap[node].get('totals', {}) or {}
        rx = int(totals.get('rx_packets', 0))
        tx = int(totals.get('tx_packets', 0))
        rxd = int(totals.get('rx_drops', 0))
        txd = int(totals.get('tx_drops', 0))
        metrics = {'rx_packets': rx, 'tx_packets': tx,
                   'rx_drops': rxd, 'tx_drops': txd,
                   'fallback': fallback}
        if rx > 0 or tx > 0:
            verdicts.append({
                'node':     node,
                'role':     'snapshot',
                'platform': 'unknown',
                'passed':   True,
                'reason':   'traffic observed: rx={} tx={} rxd={} txd={}'.format(
                                rx, tx, rxd, txd),
                'metrics':  metrics,
            })
        elif fallback_evidence:
            verdicts.append({
                'node':     node,
                'role':     'snapshot',
                'platform': 'unknown',
                'passed':   True,
                'reason':   ('snapshot rx=0 tx=0; counters likely stale, '
                             'bundle evidence: {}').format(fallback),
                'metrics':  metrics,
            })
        else:
            verdicts.append({
                'node':     node,
                'role':     'snapshot',
                'platform': 'unknown',
                'passed':   False,
                'reason':   'no traffic observed: rx=0 tx=0 (no fallback evidence)',
                'metrics':  metrics,
            })
    return verdicts


# ---------------------------------------------------------------------------
# Lossless no drops
# ---------------------------------------------------------------------------

def validate_lossless_no_drops(bundle, rules=None):
    """No queue drops on lossless TC at each snapshot node.

    Today rule (per-node): queue_drop_pkts must be 0.
    """
    snap = bundle.get('snapshot_summary', {}) or {}
    if not snap:
        return _empty_snap_verdict('no snapshot_summary available')

    verdicts = []
    for node_name in sorted(snap.keys()):
        totals = (snap[node_name].get('totals', {}) or {})
        qd = int(totals.get('queue_drop_pkts', 0))
        rxd = int(totals.get('rx_drops', 0))
        metrics = {'queue_drop_pkts': qd, 'rx_drops': rxd}
        if qd == 0:
            verdicts.append({
                'node':     node_name,
                'role':     'snapshot',
                'platform': 'unknown',
                'passed':   True,
                'reason':   'no queue drops on lossless TC',
                'metrics':  metrics,
            })
        else:
            verdicts.append({
                'node':     node_name,
                'role':     'snapshot',
                'platform': 'unknown',
                'passed':   False,
                'reason':   'queue drops on lossless TC: {}'.format(qd),
                'metrics':  metrics,
            })
    return verdicts


# ---------------------------------------------------------------------------
# PFC XOFF received at congestion point
# ---------------------------------------------------------------------------

def validate_pfc_xoff(bundle, rules=None):
    """PFC XOFF reception per snapshot node.

    If node is in pfc_xoff_nodes (expected to receive PFC from downstream):
        pass if pfc_rx > 0 else FAIL (with runner-delta fallback)
    Else (node not expected to receive PFC):
        informational PASS, with pfc_rx/pfc_tx in metrics
    """
    delta = int(bundle.get('congestion_pfc_delta', 0))
    xoff_nodes = list(bundle.get('pfc_xoff_nodes', []) or [])
    snap = bundle.get('snapshot_summary', {}) or {}

    if not snap:
        if delta > 0:
            return [{
                'node':     'all',
                'role':     'pfc_xoff',
                'platform': 'unknown',
                'passed':   True,
                'reason':   'PFC XOFF received at {} (delta={})'.format(xoff_nodes, delta),
                'metrics':  {'congestion_pfc_delta': delta,
                             'pfc_xoff_nodes': xoff_nodes},
            }]
        return _empty_snap_verdict(
            'no PFC XOFF received at {} (delta={})'.format(xoff_nodes, delta),
            role='pfc_xoff',
            metrics={'congestion_pfc_delta': delta,
                     'pfc_xoff_nodes': xoff_nodes})

    verdicts = []
    for node in sorted(snap.keys()):
        totals = snap[node].get('totals', {}) or {}
        pfc_rx = int(totals.get('pfc_rx', 0))
        pfc_tx = int(totals.get('pfc_tx', 0))
        is_xoff_target = node in xoff_nodes
        role = 'pfc_xoff_target' if is_xoff_target else 'pfc_observer'
        metrics = {'pfc_rx': pfc_rx, 'pfc_tx': pfc_tx,
                   'is_xoff_target': is_xoff_target}
        if is_xoff_target:
            if pfc_rx > 0:
                verdicts.append({
                    'node':     node,
                    'role':     role,
                    'platform': 'unknown',
                    'passed':   True,
                    'reason':   'PFC XOFF received: pfc_rx={}'.format(pfc_rx),
                    'metrics':  metrics,
                })
            elif delta > 0:
                verdicts.append({
                    'node':     node,
                    'role':     role,
                    'platform': 'unknown',
                    'passed':   True,
                    'reason':   'PFC XOFF received via runner delta={} (snapshot pfc_rx=0)'.format(delta),
                    'metrics':  metrics,
                })
            else:
                verdicts.append({
                    'node':     node,
                    'role':     role,
                    'platform': 'unknown',
                    'passed':   False,
                    'reason':   'no PFC XOFF received: pfc_rx=0 delta=0',
                    'metrics':  metrics,
                })
        else:
            verdicts.append({
                'node':     node,
                'role':     role,
                'platform': 'unknown',
                'passed':   True,
                'reason':   'observer: pfc_rx={} pfc_tx={}'.format(pfc_rx, pfc_tx),
                'metrics':  metrics,
            })
    return verdicts


# ---------------------------------------------------------------------------
# Priority-group drops
# ---------------------------------------------------------------------------

def validate_pg_drops(bundle, rules=None):
    """No PG drops at each snapshot node.

    Today rule (per-node): pg_drop must be 0.
    """
    snap = bundle.get('snapshot_summary', {}) or {}
    if not snap:
        return _empty_snap_verdict('no snapshot_summary available')

    verdicts = []
    for node_name in sorted(snap.keys()):
        totals = (snap[node_name].get('totals', {}) or {})
        pgd = int(totals.get('pg_drop', 0))
        per_pg = totals.get('pg_drop_per_pg', {}) or {}
        nz_per_pg = {pg: int(c) for pg, c in per_pg.items() if int(c) > 0}
        metrics = {'pg_drop': pgd, 'pg_drop_per_pg': nz_per_pg}
        if pgd == 0:
            verdicts.append({
                'node':     node_name,
                'role':     'snapshot',
                'platform': 'unknown',
                'passed':   True,
                'reason':   'no PG drops',
                'metrics':  metrics,
            })
        else:
            verdicts.append({
                'node':     node_name,
                'role':     'snapshot',
                'platform': 'unknown',
                'passed':   False,
                'reason':   'PG drops: {} (per-pg={})'.format(pgd, nz_per_pg),
                'metrics':  metrics,
            })
    return verdicts


# ---------------------------------------------------------------------------
# Natural congestion (no PFC XOFF stream from TGEN)
# ---------------------------------------------------------------------------

# VXLAN-over-IPv6 outer header overhead added by the ingress leaf to every
# inner L2 frame received from TGEN: 14 (outer Eth) + 40 (outer IPv6) +
# 8 (UDP) + 8 (VXLAN) = 70 bytes.
ENCAP_BYTES = 70

# Demand %% above which we declare the egress link congested.
NATURAL_DEMAND_THRESHOLD_PCT = 100.0

# Effective TX rate must be at least this fraction of the offered ingress
# load (uncongested) or of the egress line rate (congested).
EFFECTIVE_TX_FLOOR = 0.90

# Gamut (n9164e) tends to emit a tiny burst of PFC XOFF (typically 2 frames)
# on the first VxLAN-encap packet at flow start, then smooths out. Treat
# pfc_tx counts at/below this threshold as noise for the natural-congestion
# verdict on gamut only. The raw count is still surfaced in metrics.
GAMUT_NOISE_PLATFORMS = ('n9164e', 'gamut')
GAMUT_PFC_TX_NOISE_MAX = 100


def _ingress_egress_speeds(node_name, port_speeds_per_node, topology_entry,
                           node_port_counters=None):
    """Pick the ingress (TGEN-facing) and egress (fabric-facing) speed for
    a leaf node.

    If ``node_port_counters`` is provided (dict port -> {tx_packets,rx_packets}),
    restrict fabric-egress candidates to ports that actually carried traffic.
    This avoids counting admin/oper-down ECMP siblings whose listed speed
    would otherwise distort the demand model.

    Returns (ingress_gbps, egress_gbps). 0 when not derivable.
    """
    speeds = (port_speeds_per_node.get(node_name) or {}) if port_speeds_per_node else {}
    if not speeds:
        return 0, 0
    tgen_port = (topology_entry or {}).get('tgen_port')
    role = (topology_entry or {}).get('role')
    # ingress_leaf: TGEN is its ingress, fabric uplinks are its egress.
    # egress_leaf:  fabric uplinks are its ingress, TGEN is its egress.
    if role == 'ingress_leaf':
        ingress_port = tgen_port
        egress_ports = [p for p in (topology_entry.get('egress_ports') or [])
                        if p and p != tgen_port]
    elif role == 'egress_leaf':
        ingress_port = tgen_port
        egress_ports = [p for p in (topology_entry.get('ingress_ports') or [])
                        if p and p != tgen_port]
    else:
        return 0, 0
    in_g = int(speeds.get(ingress_port, 0)) if ingress_port else 0
    # Prefer fabric ports that actually carried the flow (non-zero rx/tx);
    # falls back to all listed fabric ports if counters are unavailable.
    if node_port_counters:
        active = []
        for p in egress_ports:
            pdata = node_port_counters.get(p) or {}
            if int(pdata.get('tx_packets', 0) or 0) > 0 \
                    or int(pdata.get('rx_packets', 0) or 0) > 0:
                active.append(p)
        if active:
            egress_ports = active
    # Single-flow ECMP hashes onto one fabric link, so use min available
    # among the (filtered) candidates.
    fabric_speeds = [int(speeds.get(p, 0)) for p in egress_ports if speeds.get(p)]
    eg_g = min(fabric_speeds) if fabric_speeds else 0
    return in_g, eg_g


def validate_natural_congestion(bundle, rules=None):
    """Natural-congestion (no PFC XOFF stream) verdict at the marking node.

    Computes whether the ingress leaf's egress fabric link is over-subscribed
    purely from the ingress TGEN load + VXLAN encap overhead:

        overhead_pct = (ENCAP_BYTES / frame_size) * 100
        demand_pct   = ingress_load_pct
                       * (1 + overhead_pct/100)
                       * (ingress_bw / egress_bw)
        congested    = demand_pct > 100

    Then asserts on the marking node (typically leaf0):
      - congested  : ecn_marked > 0  AND  pfc_tx > 0
                     AND effective_tx_gbps >= 0.90 * egress_bw
      - uncongested: ecn_marked == 0 AND  pfc_tx == 0
                     AND effective_tx_gbps >= 0.90 * (ingress_load_pct/100 * ingress_bw)

    Effective TX is measured as the egress leaf's TGEN-facing port TX rate
    (or RX at the same port if TX is not populated by the snapshot).
    """
    snap = bundle.get('snapshot_summary', {}) or {}
    if not snap:
        return _empty_snap_verdict('no snapshot_summary available')

    ingress_load_pct = float(bundle.get('ingress_load_pct', 0) or 0)
    frame_size = int(bundle.get('frame_size', 0) or 0)
    traffic_run_time = int(bundle.get('traffic_run_time', 0) or 0)
    port_speeds_per_node = bundle.get('port_speeds_per_node', {}) or {}
    marking_nodes = list(bundle.get('marking_nodes', []) or [])
    marking_platforms = list(bundle.get('marking_node_platforms', []) or [])

    if frame_size <= 0 or ingress_load_pct <= 0:
        return _empty_snap_verdict(
            'missing frame_size/ingress_load_pct in bundle (frame_size={}, load_pct={})'
            .format(frame_size, ingress_load_pct))

    # Find ingress and egress leaf nodes from topology_min (preferred) or
    # snapshot roles (fallback).
    topology_min = bundle.get('topology_min', {}) or {}
    if topology_min:
        ingress_leaves = [n for n, e in topology_min.items()
                          if (e.get('role') == 'ingress_leaf')]
        egress_leaves  = [n for n, e in topology_min.items()
                          if (e.get('role') == 'egress_leaf')]
        topo_entries = topology_min
    else:
        ingress_leaves = [n for n, e in snap.items()
                          if (e.get('role') == 'ingress_leaf')]
        egress_leaves  = [n for n, e in snap.items()
                          if (e.get('role') == 'egress_leaf')]
        topo_entries = {}
        for n, ports in port_speeds_per_node.items():
            # Fallback: heuristic over snapshot counters (rx+tx total).
            node_ports = (snap.get(n, {}) or {}).get('ports', {}) or {}
            tgen_port = None
            if node_ports:
                best = None
                best_score = -1
                for p, pdata in node_ports.items():
                    rx = int(pdata.get('rx_packets', 0) or 0)
                    tx = int(pdata.get('tx_packets', 0) or 0)
                    if rx + tx > best_score:
                        best = p
                        best_score = rx + tx
                tgen_port = best if best in (ports or {}) else None
            fabric_ports = [p for p in (ports or {}).keys() if p != tgen_port]
            topo_entries[n] = {
                'role': (snap.get(n, {}) or {}).get('role', ''),
                'tgen_port': tgen_port,
                'egress_ports': fabric_ports,
                'ingress_ports': fabric_ports,
            }
    if not ingress_leaves:
        return _empty_snap_verdict('no ingress_leaf found in snapshot/topology')

    # For metrics we focus on the first ingress leaf.
    ileaf = ingress_leaves[0]
    ileaf_ports_snap = (snap.get(ileaf, {}) or {}).get('ports', {}) or {}
    ingress_bw, egress_bw = _ingress_egress_speeds(
        ileaf, port_speeds_per_node, topo_entries.get(ileaf),
        node_port_counters=ileaf_ports_snap)

    if ingress_bw <= 0 or egress_bw <= 0:
        return _empty_snap_verdict(
            'cannot determine ingress/egress speeds for {} (got ingress={} egress={})'
            .format(ileaf, ingress_bw, egress_bw))

    overhead_pct = (ENCAP_BYTES / float(frame_size)) * 100.0
    demand_pct = ingress_load_pct * (1.0 + overhead_pct / 100.0) * (float(ingress_bw) / float(egress_bw))
    congested = demand_pct > NATURAL_DEMAND_THRESHOLD_PCT

    # Effective TX measured at the egress leaf TGEN-facing port (towards
    # the receiving TGEN) using DUT counters.
    effective_tx_gbps = 0.0
    if egress_leaves and traffic_run_time > 0:
        eleaf = egress_leaves[0]
        eleaf_ports = (snap.get(eleaf, {}) or {}).get('ports', {}) or {}
        eleaf_tgen = topo_entries.get(eleaf, {}).get('tgen_port')
        if eleaf_tgen and eleaf_tgen in eleaf_ports:
            tx_pkts = int(eleaf_ports[eleaf_tgen].get('tx_packets', 0) or 0)
            on_wire_bytes = frame_size + 20  # preamble (8) + IPG (12)
            effective_tx_gbps = (tx_pkts * on_wire_bytes * 8.0) / float(traffic_run_time) / 1e9

    # Marking-node assertions.
    verdicts = []
    if not marking_nodes:
        marking_nodes = [ileaf]
    for n in marking_nodes:
        totals = (snap.get(n, {}) or {}).get('totals', {}) or {}
        ecn_marked = int(totals.get('ecn_marked_pkts', 0) or 0)
        pfc_tx = int(totals.get('pfc_tx', 0) or 0)
        platform = _platform_for(n, marking_nodes, marking_platforms)

        # Gamut-specific noise tolerance: small PFC TX bursts at flow start
        # (typically 2 frames on first VxLAN-encap packet) are an n9164e
        # quirk, not real congestion back-pressure. Clamp to 0 for the
        # decision only; raw count is still surfaced in metrics.
        pfc_tx_effective = pfc_tx
        pfc_tx_noise_ignored = False
        if (platform in GAMUT_NOISE_PLATFORMS
                and 0 < pfc_tx <= GAMUT_PFC_TX_NOISE_MAX):
            pfc_tx_effective = 0
            pfc_tx_noise_ignored = True

        metrics = {
            'ingress_load_pct':     ingress_load_pct,
            'frame_size':           frame_size,
            'overhead_pct':         round(overhead_pct, 3),
            'ingress_bw_gbps':      ingress_bw,
            'egress_bw_gbps':       egress_bw,
            'demand_pct':           round(demand_pct, 3),
            'congested':            congested,
            'ecn_marked':           ecn_marked,
            'pfc_tx':               pfc_tx,
            'pfc_tx_effective':     pfc_tx_effective,
            'effective_tx_gbps':    round(effective_tx_gbps, 3),
        }

        if congested:
            tx_floor = EFFECTIVE_TX_FLOOR * float(egress_bw)
            ok = (ecn_marked > 0) and (pfc_tx_effective > 0) and (effective_tx_gbps >= tx_floor)
            if ok:
                reason = ('congested (demand={:.1f}%): ecn={} pfc_tx={} '
                          'tx={:.2f}G >= floor={:.2f}G'
                          .format(demand_pct, ecn_marked, pfc_tx,
                                  effective_tx_gbps, tx_floor))
            else:
                reasons = []
                if ecn_marked == 0:
                    reasons.append('ecn_marked==0')
                if pfc_tx_effective == 0:
                    reasons.append('pfc_tx==0')
                if effective_tx_gbps < tx_floor:
                    reasons.append('tx={:.2f}G < floor={:.2f}G'
                                   .format(effective_tx_gbps, tx_floor))
                reason = ('congested (demand={:.1f}%) but: {}'
                          .format(demand_pct, '; '.join(reasons)))
        else:
            expected_tx_gbps = (ingress_load_pct / 100.0) * float(ingress_bw)
            tx_floor = EFFECTIVE_TX_FLOOR * expected_tx_gbps
            ok = (ecn_marked == 0) and (pfc_tx_effective == 0) and (effective_tx_gbps >= tx_floor)
            if ok:
                reason = ('uncongested (demand={:.1f}%): no marks/xoff, '
                          'tx={:.2f}G >= floor={:.2f}G'
                          .format(demand_pct, effective_tx_gbps, tx_floor))
            else:
                reasons = []
                if ecn_marked > 0:
                    reasons.append('ecn_marked={}'.format(ecn_marked))
                if pfc_tx_effective > 0:
                    reasons.append('pfc_tx={}'.format(pfc_tx))
                if effective_tx_gbps < tx_floor:
                    reasons.append('tx={:.2f}G < floor={:.2f}G'
                                   .format(effective_tx_gbps, tx_floor))
                reason = ('uncongested (demand={:.1f}%) but: {}'
                          .format(demand_pct, '; '.join(reasons)))

        if pfc_tx_noise_ignored:
            reason += ' [ignored gamut PFC TX noise: raw={}]'.format(pfc_tx)

        verdicts.append({
            'node':     n,
            'role':     'ingress_leaf',
            'platform': platform,
            'passed':   bool(ok),
            'reason':   reason,
            'metrics':  metrics,
        })

    return verdicts


# ---------------------------------------------------------------------------
# Registry: short label -> validator function
# ---------------------------------------------------------------------------

VALIDATORS = [
    ('EcnMark',            validate_ecn_marking),
    ('Throughput',         validate_throughput),
    ('LosslessNoDrops',    validate_lossless_no_drops),
    ('PfcXoff',            validate_pfc_xoff),
    ('PgDrops',            validate_pg_drops),
    ('NaturalCongestion',  validate_natural_congestion),
]
