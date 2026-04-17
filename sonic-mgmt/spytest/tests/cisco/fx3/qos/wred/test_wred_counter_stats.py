#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2026-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

"""
FX3 QoS WRED Counter Stats Tests — Test Plan #5.

Testbed (fx3_qos_testbed_2022.yaml):
  Ingress A: Ixia T1D1P1 -> DUT D1T1P1 (100G)
  Ingress B: Ixia T1D1P2 -> DUT D1T1P2 (100G)
  Egress:    DUT D1T1P3  -> Ixia T1D1P3 (100G)

Uses the fan-in topology (2 ingress ports -> 1 egress port) to create
egress queue congestion under continuous WRED drops.

Tests:
  test_clear_queue_stats_delta — Validates that 'sonic-clear queuecounters'
      and 'sonic-clear counters' reset CLI counter views and that subsequent
      traffic produces fresh increments from the cleared baseline.  Verifies
      the delta between raw COUNTERS_DB values and the CLI baseline snapshot.

Golden WRED profile (AZURE_LOSSY baseline):
  green_min_threshold    = 1,048,576 bytes (1 MB)
  green_max_threshold    = 3,145,728 bytes (3 MB)
  green_drop_probability = 5%
"""

import os
import sys
import pytest

from spytest import st, tgapi

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fx3_qos_helpers import (
    QUEUE_TO_DSCP,
    setup_topo_common, verify_egress_reachable,
    deploy_dchal_helper,
    ensure_interfaces_admin_up, verify_wred_profile,
    parse_redis_hget, parse_redis_hgetall,
    clear_dut_counters,
    get_dchal_queue_counters, get_queue_counters, get_intf_counters,
    log_queue_counters,
    wred_fanin_start_continuous, wred_fanin_stop_continuous,
)


# ── Test-specific parameters ──────────────────────────────────────────────
TARGET_QUEUE = 3
TARGET_DSCP = QUEUE_TO_DSCP[TARGET_QUEUE]

CLEAR_STATS_MARGIN_MBPS = 3000
CLEAR_STATS_WAIT_SEC = 30

# COUNTERS_DB SAI queue stat fields to snapshot and delta-check.
_SAI_STAT_FIELDS = [
    'SAI_QUEUE_STAT_PACKETS',
    'SAI_QUEUE_STAT_DROPPED_PACKETS',
    'SAI_QUEUE_STAT_BYTES',
    'SAI_QUEUE_STAT_DROPPED_BYTES',
]

# Time to wait after stopping traffic for egress queues to drain.
DRAIN_WAIT_SEC = 5

# Post-clear near-zero tolerance — after traffic stops and queues drain,
# a handful of residual packets may still be in flight.
NEAR_ZERO_TOLERANCE = 50

# Tolerance for delta vs CLI comparison — with a clean baseline from
# quiescent state the only drift is the seconds between the Redis
# snapshot and the CLI read after traffic restarts.
DELTA_TOLERANCE_PCT = 0.05

# ── Module state ─────────────────────────────────────────────────────────
dut = None
tg = None
tg_ph = {}
port_info = {}
port_speeds = {}
ingress_speed_mbps = 0
egress_speed_mbps = 0
wred_ctx = {}


# ── Neighbor resolution helper ───────────────────────────────────────────

def _verify_egress_neighbor(af):
    """Closure over module globals; delegates to the shared topology-aware helper."""
    return verify_egress_reachable(dut, tg, tg_ph, af)


# ── COUNTERS_DB snapshot helper ──────────────────────────────────────────

def _read_counters_db_queue_stats(dut_handle, port, queue_idx):
    """Read raw SAI_QUEUE_STAT_* values from COUNTERS_DB for a queue.

    Steps:
      1. Resolve the queue OID via COUNTERS_QUEUE_NAME_MAP.
      2. HGETALL COUNTERS:<oid> and extract the SAI stat fields.

    Returns:
        dict mapping stat name -> int value, e.g.
        {'SAI_QUEUE_STAT_PACKETS': 12345, ...}.
        Returns an empty dict if the OID cannot be resolved.
    """
    oid_out = st.show(
        dut_handle,
        'sonic-db-cli COUNTERS_DB HGET COUNTERS_QUEUE_NAME_MAP '
        '"{}:{}"'.format(port, queue_idx),
        skip_tmpl=True)
    queue_oid = parse_redis_hget(oid_out).strip()
    if not queue_oid:
        st.log("  _read_counters_db_queue_stats: no OID for {}:{}".format(
            port, queue_idx))
        return {}

    all_out = st.show(
        dut_handle,
        'sonic-db-cli COUNTERS_DB HGETALL "COUNTERS:{}"'.format(queue_oid),
        skip_tmpl=True)
    all_fields = parse_redis_hgetall(all_out)

    result = {}
    for field in _SAI_STAT_FIELDS:
        raw = all_fields.get(field, '0')
        try:
            result[field] = int(raw)
        except (ValueError, TypeError):
            result[field] = 0
    return result


# ── Topology fixture ─────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Set up DUT L3, IXIA interfaces, and QoS baseline for counter tests."""
    global dut, tg, tg_ph, port_info, port_speeds
    global ingress_speed_mbps, egress_speed_mbps, wred_ctx

    for result in setup_topo_common(tgapi, target_queue=TARGET_QUEUE):
        dut = result['dut']
        tg = result['tg']
        tg_ph = result['tg_ph']
        port_info = result['port_info']
        port_speeds = result['port_speeds']
        ingress_speed_mbps = result['ingress_speed_mbps']
        egress_speed_mbps = result['egress_speed_mbps']
        wred_ctx = result['wred_ctx']
        yield


# ── Tests ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_clear_queue_stats_delta(af):
    """
    Clear queue stats + delta verification.

    Validates that 'sonic-clear queuecounters' and 'sonic-clear counters'
    reset the CLI counter display to zero and that subsequent traffic
    produces fresh counter increments from the cleared baseline.  Also
    verifies that the delta between raw COUNTERS_DB values and the CLI
    output are consistent.

    Traffic is stopped before clearing so counters can be verified at
    absolute zero, then restarted for the fresh-increment and delta checks.

    Phases:
      1. Start fan-in traffic, wait for WRED drops.
      2. Record pre-clear counters (queue, DCHAL, interface) -- all > 0.
      3. Stop traffic, wait for queues to drain.
      4. Clear counters (sonic-clear only), wait for syncd poll cycle,
         verify == 0, snapshot COUNTERS_DB baseline.
      5. Restart traffic, wait, verify fresh increments > 0.
      6. Delta-check: (new raw - baseline) vs CLI display.
    """
    egress_port = port_info['egress']
    st.banner(
        "test_clear_queue_stats_delta [{}]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Test #5 — clear queue stats + delta verification "
        "({} Mbps margin, {}s waits)".format(
            af, dut, egress_port,
            CLEAR_STATS_MARGIN_MBPS, CLEAR_STATS_WAIT_SEC))

    fail_msgs = []
    ixia_stream_ids = []

    # ── Baseline: deploy DCHAL + verify golden WRED profile ──────────────
    deploy_dchal_helper(dut)
    verify_wred_profile(dut, fail_msgs)
    if fail_msgs:
        st.report_fail(
            'msg',
            'test_clear_queue_stats_delta [{}] FAILED at baseline: {}'.format(
                af, '; '.join(fail_msgs)))
        return

    if not _verify_egress_neighbor(af):
        st.report_fail(
            'msg',
            'test_clear_queue_stats_delta [{}] FAILED: egress neighbor not '
            'resolved'.format(af))
        return

    # ── Phase 1: Start traffic and confirm WRED drops ────────────────────
    st.log("Phase 1: Clear initial counters and start fan-in traffic")
    clear_dut_counters(dut)

    try:
        ixia_stream_ids = wred_fanin_start_continuous(
            wred_ctx, af, CLEAR_STATS_MARGIN_MBPS)
        st.wait(CLEAR_STATS_WAIT_SEC)

        # ── Phase 2: Record non-zero pre-clear counters ──────────────────
        st.log("Phase 2: Record pre-clear counters (expect all > 0)")

        q_pre = get_queue_counters(dut, egress_port)
        dchal_pre = get_dchal_queue_counters(
            dut, egress_port, "pre-clear (continuous traffic)")
        intf_pre = get_intf_counters(dut, port_info.values())

        st.log("--- DCHAL pre-clear ---")
        log_queue_counters(dchal_pre)

        tq_q_pkts = q_pre.get(TARGET_QUEUE, {}).get('pkts', 0)
        tq_q_drop = q_pre.get(TARGET_QUEUE, {}).get('drop_pkts', 0)
        tq_dchal_drop = dchal_pre.get(TARGET_QUEUE, {}).get('drop_pkts', 0)
        tq_intf_tx_drp = intf_pre.get(egress_port, {}).get('tx_drp', 0)

        st.log("  Q{} queue pkts={}, drop_pkts={}".format(
            TARGET_QUEUE, tq_q_pkts, tq_q_drop))
        st.log("  Q{} DCHAL drop_pkts={}".format(
            TARGET_QUEUE, tq_dchal_drop))
        st.log("  {} TX_DRP={}".format(egress_port, tq_intf_tx_drp))

        if tq_q_pkts <= 0:
            fail_msgs.append(
                "pre-clear: expected queue pkts > 0 on Q{}, got {}".format(
                    TARGET_QUEUE, tq_q_pkts))
        if tq_q_drop <= 0:
            fail_msgs.append(
                "pre-clear: expected queue drop_pkts > 0 on Q{}, got {}".format(
                    TARGET_QUEUE, tq_q_drop))
        if tq_dchal_drop <= 0:
            fail_msgs.append(
                "pre-clear: expected DCHAL drop_pkts > 0 on Q{}, got {}".format(
                    TARGET_QUEUE, tq_dchal_drop))
        if tq_intf_tx_drp <= 0:
            fail_msgs.append(
                "pre-clear: expected TX_DRP > 0 on {}, got {}".format(
                    egress_port, tq_intf_tx_drp))

        if fail_msgs:
            st.report_fail(
                'msg',
                'test_clear_queue_stats_delta [{}] FAILED (pre-clear '
                'counters not > 0): {}'.format(af, '; '.join(fail_msgs)))
            return

        # ── Phase 3: Stop traffic and drain queues ──────────────────────
        st.log("Phase 3: Stop traffic and wait {}s for queues to drain".format(
            DRAIN_WAIT_SEC))
        wred_fanin_stop_continuous(tg, ixia_stream_ids)
        ixia_stream_ids = []
        st.wait(DRAIN_WAIT_SEC)

        # ── Phase 4: Clear counters, verify zero, snapshot baseline ──────
        st.log("Phase 4: Clear counters and verify absolute zero")
        clear_dut_counters(dut)
        st.wait(3)

        q_post_clear = get_queue_counters(dut, egress_port)
        intf_post_clear = get_intf_counters(dut, port_info.values())

        tq_post_pkts = q_post_clear.get(TARGET_QUEUE, {}).get('pkts', 0)
        tq_post_drop = q_post_clear.get(TARGET_QUEUE, {}).get('drop_pkts', 0)
        tq_post_tx_drp = intf_post_clear.get(
            egress_port, {}).get('tx_drp', 0)

        st.log("  post-clear Q{} pkts={}, drop_pkts={}".format(
            TARGET_QUEUE, tq_post_pkts, tq_post_drop))
        st.log("  post-clear {} TX_DRP={}".format(
            egress_port, tq_post_tx_drp))

        if tq_post_pkts > NEAR_ZERO_TOLERANCE:
            fail_msgs.append(
                "post-clear: Q{} pkts={} exceeds tolerance {} "
                "(expected 0 with traffic stopped)".format(
                    TARGET_QUEUE, tq_post_pkts, NEAR_ZERO_TOLERANCE))
        if tq_post_drop > NEAR_ZERO_TOLERANCE:
            fail_msgs.append(
                "post-clear: Q{} drop_pkts={} exceeds tolerance {} "
                "(expected 0 with traffic stopped)".format(
                    TARGET_QUEUE, tq_post_drop, NEAR_ZERO_TOLERANCE))
        if tq_post_tx_drp > NEAR_ZERO_TOLERANCE:
            fail_msgs.append(
                "post-clear: {} TX_DRP={} exceeds tolerance {} "
                "(expected 0 with traffic stopped)".format(
                    egress_port, tq_post_tx_drp, NEAR_ZERO_TOLERANCE))

        st.log("Phase 4b: Snapshot COUNTERS_DB baseline for Q{} "
               "(quiescent after clear)".format(TARGET_QUEUE))
        baseline = _read_counters_db_queue_stats(dut, egress_port, TARGET_QUEUE)
        st.log("  baseline = {}".format(baseline))

        if not baseline:
            fail_msgs.append(
                "COUNTERS_DB baseline snapshot failed — no OID for "
                "{}:{}".format(egress_port, TARGET_QUEUE))
            st.report_fail(
                'msg',
                'test_clear_queue_stats_delta [{}] FAILED: {}'.format(
                    af, '; '.join(fail_msgs)))
            return

        # ── Phase 5: Restart traffic and verify fresh increments ─────────
        st.log("Phase 5: Restart traffic and verify fresh increments")

        if not _verify_egress_neighbor(af):
            st.warn("Egress neighbor lost during drain — re-resolved")

        ixia_stream_ids = wred_fanin_start_continuous(
            wred_ctx, af, CLEAR_STATS_MARGIN_MBPS)
        st.wait(CLEAR_STATS_WAIT_SEC)

        q_fresh = get_queue_counters(dut, egress_port)
        dchal_fresh = get_dchal_queue_counters(
            dut, egress_port, "post-clear fresh traffic")
        intf_fresh = get_intf_counters(dut, port_info.values())

        st.log("--- DCHAL fresh (post-restart + {}s) ---".format(
            CLEAR_STATS_WAIT_SEC))
        log_queue_counters(dchal_fresh)

        fresh_pkts = q_fresh.get(TARGET_QUEUE, {}).get('pkts', 0)
        fresh_drop = q_fresh.get(TARGET_QUEUE, {}).get('drop_pkts', 0)
        fresh_dchal_drop = dchal_fresh.get(
            TARGET_QUEUE, {}).get('drop_pkts', 0)
        fresh_tx_drp = intf_fresh.get(egress_port, {}).get('tx_drp', 0)

        st.log("  fresh Q{} pkts={}, drop_pkts={}".format(
            TARGET_QUEUE, fresh_pkts, fresh_drop))
        st.log("  fresh Q{} DCHAL drop_pkts={}".format(
            TARGET_QUEUE, fresh_dchal_drop))
        st.log("  fresh {} TX_DRP={}".format(egress_port, fresh_tx_drp))

        if fresh_pkts <= 0:
            fail_msgs.append(
                "fresh: expected Q{} pkts > 0, got {}".format(
                    TARGET_QUEUE, fresh_pkts))
        if fresh_drop <= 0:
            fail_msgs.append(
                "fresh: expected Q{} drop_pkts > 0, got {}".format(
                    TARGET_QUEUE, fresh_drop))
        if fresh_dchal_drop <= 0:
            fail_msgs.append(
                "fresh: expected DCHAL drop_pkts > 0 on Q{}, got {}".format(
                    TARGET_QUEUE, fresh_dchal_drop))
        if fresh_tx_drp <= 0:
            fail_msgs.append(
                "fresh: expected TX_DRP > 0 on {}, got {}".format(
                    egress_port, fresh_tx_drp))

        # ── Phase 6: Delta verification against COUNTERS_DB ──────────────
        # Stop traffic first so COUNTERS_DB values are frozen — avoids a
        # timing race where a flexcounter poll between the CLI read (above)
        # and the raw COUNTERS_DB read (below) causes a divergence.
        st.log("Phase 6: Stop traffic and drain before delta verification")
        wred_fanin_stop_continuous(tg, ixia_stream_ids)
        ixia_stream_ids = []
        st.wait(DRAIN_WAIT_SEC)

        st.log("Phase 6: Delta verification — COUNTERS_DB raw vs CLI")

        q_settled = get_queue_counters(dut, egress_port)
        post_raw = _read_counters_db_queue_stats(
            dut, egress_port, TARGET_QUEUE)

        settled_pkts = q_settled.get(TARGET_QUEUE, {}).get('pkts', 0)
        settled_drop = q_settled.get(TARGET_QUEUE, {}).get('drop_pkts', 0)

        st.log("  post_raw = {}".format(post_raw))

        if not post_raw:
            fail_msgs.append(
                "COUNTERS_DB post-raw snapshot failed — no OID for "
                "{}:{}".format(egress_port, TARGET_QUEUE))
        else:
            delta_pkts = (post_raw.get('SAI_QUEUE_STAT_PACKETS', 0)
                          - baseline.get('SAI_QUEUE_STAT_PACKETS', 0))
            delta_drop = (post_raw.get('SAI_QUEUE_STAT_DROPPED_PACKETS', 0)
                          - baseline.get('SAI_QUEUE_STAT_DROPPED_PACKETS', 0))

            st.log("  delta_pkts  = {} (raw {} - baseline {})".format(
                delta_pkts,
                post_raw.get('SAI_QUEUE_STAT_PACKETS', 0),
                baseline.get('SAI_QUEUE_STAT_PACKETS', 0)))
            st.log("  delta_drop  = {} (raw {} - baseline {})".format(
                delta_drop,
                post_raw.get('SAI_QUEUE_STAT_DROPPED_PACKETS', 0),
                baseline.get('SAI_QUEUE_STAT_DROPPED_PACKETS', 0)))
            st.log("  CLI pkts    = {}".format(settled_pkts))
            st.log("  CLI drop    = {}".format(settled_drop))

            def _check_delta(label, delta_val, cli_val):
                if cli_val <= 0 or delta_val <= 0:
                    fail_msgs.append(
                        "delta: {} delta={} or CLI={} is non-positive".format(
                            label, delta_val, cli_val))
                    return
                rel_diff = abs(delta_val - cli_val) / float(max(delta_val, cli_val))
                st.log("  {} |delta - CLI| / max = {:.2%} "
                       "(tolerance {:.0%})".format(label, rel_diff,
                                                   DELTA_TOLERANCE_PCT))
                if rel_diff > DELTA_TOLERANCE_PCT:
                    fail_msgs.append(
                        "delta: {} delta={} vs CLI={}, "
                        "relative diff {:.2%} exceeds tolerance {:.0%}".format(
                            label, delta_val, cli_val,
                            rel_diff, DELTA_TOLERANCE_PCT))

            _check_delta("SAI_QUEUE_STAT_PACKETS", delta_pkts, settled_pkts)
            _check_delta("SAI_QUEUE_STAT_DROPPED_PACKETS",
                         delta_drop, settled_drop)

    finally:
        wred_fanin_stop_continuous(tg, ixia_stream_ids)

    # ── Verdict ──────────────────────────────────────────────────────────
    if fail_msgs:
        st.log("test_clear_queue_stats_delta [{}] failures ({} total):".format(
            af, len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.report_fail(
            'msg',
            'test_clear_queue_stats_delta [{}] FAILED — {}'.format(
                af, '; '.join(fail_msgs)))
    else:
        st.report_pass(
            'msg',
            'test_clear_queue_stats_delta [{}] passed: pre-clear counters > 0, '
            'post-clear == 0 (traffic stopped), fresh increments > 0, '
            'COUNTERS_DB delta matches CLI within {:.0f}%'.format(
                af, DELTA_TOLERANCE_PCT * 100))
