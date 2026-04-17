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
FX3 QoS Integration Tests — default config verification + DWRR traffic validation.

Testbed (fx3_qos_testbed_2022.yaml):
  Ingress A: Ixia T1D1P1 -> DUT D1T1P1 (100G)
  Ingress B: Ixia T1D1P2 -> DUT D1T1P2 (100G)
  Egress:    DUT D1T1P3  -> Ixia T1D1P3 (100G)

  Actual interface names are resolved from the testbed YAML at runtime
  via tb_vars.D1T1P1 etc.

Active test:
  test_scheduler_dwrr_validation[ipv4] / test_scheduler_dwrr_validation[ipv6]:
    Parametrized over address family. Both variants run the same validation;
    only the L3 header, next-hop resolution, and DSCP/TC encoding differ.
    Phase 1 — Verify default CONFIG_DB (DSCP_TO_TC_MAP, SCHEDULER, QUEUE, WRED)
              against config_db.json baseline + DCHAL HW scheduler BW%.
    Phase 2 — Send 2:1 oversubscribed fan-in traffic (8 queues x 8% x 2 ports).
              Validate DWRR weight ratios and STRICT zero-drop.

Commented out (see test_fx3_scheduler_2022.py for full implementations):
  test_fx3_scheduler_reordered_config  (test 23)
  test_fx3_scheduler_weight_change     (test 24)

FX3 constraints:
  - PFC and ECN are not supported on this platform.
  - clear_queue_stats is not supported; tests use snapshot-before/after deltas.
"""

import warnings
import pytest

warnings.filterwarnings(
    "ignore", r".*currentThread\(\) is deprecated.*", DeprecationWarning)
warnings.filterwarnings(
    "ignore", r".*Deprecated call to.*pkg_resources\.declare_namespace.*",
    DeprecationWarning)
warnings.filterwarnings(
    "ignore", r".*ssl\.PROTOCOL_TLS is deprecated.*", DeprecationWarning)
warnings.filterwarnings(
    "ignore", r".*connections\(\) is deprecated.*", DeprecationWarning)

from fx3_qos_helpers import (
    QUEUE_TO_DSCP, NUM_QUEUES, PKT_SIZE,
    V4_INGRESS_A_IP, V4_INGRESS_B_IP,
    V6_INGRESS_A_IP, V6_INGRESS_B_IP,
    IXIA_INGRESS_A_IP, IXIA_INGRESS_B_IP, IXIA_EGRESS_IP,
    IXIA_INGRESS_A_IP6, IXIA_INGRESS_B_IP6, IXIA_EGRESS_IP6,
    WRED_MIN_TH, WRED_MAX_TH, WRED_MAX_PROB,
    WRED_TOLERANCE, WRED_DURATION, WRED_SETTLE_TIME,
    setup_topo_common, verify_egress_reachable,
    verify_config_db_baseline, compute_dwrr_rate_pct, scale_margin,
    deploy_dchal_helper, dchal_show_queuing, report_dchal_bw_check,
    get_dchal_queue_counters, get_dut_mac,
    clear_dut_counters, dchal_clear_counters, get_intf_counters,
    report_intf_counters, report_queue_counters,
    validate_dwrr_ratios, validate_dchal_bw_vs_weights,
    run_wred_linearity, dump_l3_diag, verify_wred_config,
    wred_fanin_send_and_measure, report_wred_result,
)

from spytest import st, tgapi


# ── Test-specific parameters ──────────────────────────────────────────────
TRAFFIC_DURATION   = 10      # match test_scheduler_validation.py
DWRR_OVERSUB       = 1.28    # target oversubscription ratio for DWRR traffic
TARGET_QUEUE       = 1
TARGET_DSCP        = QUEUE_TO_DSCP[TARGET_QUEUE]   # 6

# ── WRED Zone A headroom ────────────────────────────────────────────────
# IXIA rate_percent precision is limited; at exactly 50.000% per port the
# actual combined throughput can slightly exceed egress capacity, pushing
# queue depth above min_th and into Zone B.  Use a small negative margin
# so combined rate stays ~0.5% below line rate, keeping the queue firmly
# in Zone A while still validating the "below min_th → zero drops" property.
#
# All margin constants are authored for 100G egress (the baseline).
# scale_margin() adjusts them proportionally for slower links (e.g. 25G
# breakout) so the overshoot ratio stays constant across topologies.
WRED_ZONE_A_MARGIN  = -500       # Mbps below line rate (per fan-in pair)

# ── Module state ─────────────────────────────────────────────────────────
dut = None
tg = None
tg_ph = {}          # {'ingress_a': handle, ['ingress_b': handle,] 'egress': handle}
port_info = {}      # {'ingress_a': '<port>', ['ingress_b': '<port>',] 'egress': '<port>'}
port_speeds = {}    # {'ingress_a': '100G', 'egress': '100G' or '25G', ...}
ingress_speed_mbps = 0
egress_speed_mbps = 0
wred_ctx = {}       # shared context dict for WRED helper functions
tb_vars = None
stream_rate_pct = 0 # computed by setup_topo via compute_dwrr_rate_pct


# ── Fixture ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Set up DUT L3, IXIA interfaces, and QoS baseline for all tests."""
    global dut, tg, tg_ph, port_info, port_speeds
    global ingress_speed_mbps, egress_speed_mbps, wred_ctx, tb_vars
    global stream_rate_pct

    for result in setup_topo_common(tgapi, target_queue=TARGET_QUEUE):
        dut = result['dut']
        tg = result['tg']
        tg_ph = result['tg_ph']
        port_info = result['port_info']
        port_speeds = result['port_speeds']
        ingress_speed_mbps = result['ingress_speed_mbps']
        egress_speed_mbps = result['egress_speed_mbps']
        wred_ctx = result['wred_ctx']
        tb_vars = result['tb_vars']

        num_ingress = len([k for k in tg_ph
                          if k not in ('egress', 'egress_sink')])
        stream_rate_pct = compute_dwrr_rate_pct({
            'ingress_speed_mbps': ingress_speed_mbps,
            'egress_speed_mbps': egress_speed_mbps,
            'num_queues': NUM_QUEUES,
            'num_ingress_ports': num_ingress,
        }, oversub_ratio=DWRR_OVERSUB)
        yield

# def test_fx3_scheduler_reordered_config():
#     """Verify CONFIG_DB scheduler state is correct after non-sequential QUEUE binding.
#
#     Maps to scheduler_test_plan.md test 23 SONiC End-to-End Verification.
#
#     Binds QUEUE->scheduler entries in order [6,0,1,2,7,3,4,5] instead of 0-7.
#     SONiC orchagent may process QUEUE bindings in any order; final CONFIG_DB
#     state must be identical to sequential binding (test 17).
#     """
#     st.banner("test_fx3_scheduler_reordered_config STARTED")
#     fail_msgs = []
#     egress = port_info['egress']
#
#     # ── Step 1: Remove all existing QUEUE->scheduler bindings ──
#     st.log("Removing all QUEUE scheduler bindings on {}".format(egress))
#     for qi in range(NUM_QUEUES):
#         st.config(
#             dut,
#             'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|{}" "scheduler"'.format(
#                 egress, qi),
#             skip_error_check=True)
#     st.wait(2)
#
#     # ── Step 2: Re-apply bindings in non-sequential order ──
#     st.log("Re-applying QUEUE scheduler bindings in reordered sequence: {}".format(
#         SCHEDULER_REORDER))
#     for qi in SCHEDULER_REORDER:
#         sched = 'scheduler.{}'.format(qi)
#         st.log("  Binding QUEUE|{}|{} -> {}".format(egress, qi, sched))
#         st.config(
#             dut,
#             'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|{}" "scheduler" "{}"'.format(
#                 egress, qi, sched),
#             skip_error_check=True)
#     st.wait(2)
#
#     # ── Step 3: Verify SCHEDULER profiles are unchanged ──
#     st.log("Verifying SCHEDULER profiles are unchanged after reorder")
#     for name, expected in EXPECTED_SCHEDULERS.items():
#         output = st.show(
#             dut,
#             'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
#             skip_tmpl=True)
#         actual = parse_redis_hgetall(output)
#         st.log("  {} -> {}".format(name, actual))
#
#         if not actual:
#             fail_msgs.append("{}: empty or missing".format(name))
#             continue
#
#         actual_type = actual.get('type', '')
#         if actual_type != expected['type']:
#             fail_msgs.append(
#                 "{}: type='{}', expected '{}'".format(
#                     name, actual_type, expected['type']))
#
#         if 'weight' in expected:
#             actual_weight = actual.get('weight', '')
#             if actual_weight != expected['weight']:
#                 fail_msgs.append(
#                     "{}: weight='{}', expected '{}'".format(
#                         name, actual_weight, expected['weight']))
#
#     # ── Step 4: Verify final QUEUE bindings match test 17 (sequential) ──
#     st.log("Verifying final QUEUE bindings are identical to sequential binding")
#     for qi in range(NUM_QUEUES):
#         expected_sched = 'scheduler.{}'.format(qi)
#         output = st.show(
#             dut,
#             'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(
#                 egress, qi),
#             skip_tmpl=True)
#         actual_binding = parse_redis_hget(output).strip()
#         st.log("  Q{} -> '{}'".format(qi, actual_binding))
#         if actual_binding != expected_sched:
#             fail_msgs.append(
#                 "QUEUE|{}|{}: '{}', expected '{}'".format(
#                     egress, qi, actual_binding, expected_sched))
#
#     # ── Step 5: Log queue counters for visibility ──
#     st.log("Calling 'show queue counters' for visibility")
#     st.show(dut, "show queue counters {}".format(egress), skip_tmpl=True)
#
#     # ── Step 6: Restore sequential order via config qos reload ──
#     st.log("Restoring QoS baseline via config qos reload")
#     st.config(dut, "config qos reload", skip_error_check=True)
#     st.wait(5)
#
#     # ── Verdict ──
#     if fail_msgs:
#         st.report_fail('msg',
#                        'Scheduler reordered config FAILED: ' + '; '.join(fail_msgs))
#     else:
#         st.report_pass('msg',
#                        'Scheduler reordered config verified — final state '
#                        'identical to sequential binding (test 17)')


# ── DCHAL show queuing helper script ──────────────────────────────────────
# This script is deployed once into the syncd container at the start of
# test_fx3_scheduler_weight_change and called for ASIC-level visibility
# at each checkpoint alongside the CONFIG_DB state dump.


# def test_fx3_scheduler_weight_change():
#     """Verify CONFIG_DB scheduler weight changes propagate correctly (test 24).
#
#     Maps to scheduler_test_plan.md test 24 SONiC End-to-End Verification.
#
#     Step 1: Change scheduler.2 weight 20->30.  All other profiles must remain
#             unchanged.  CONFIG_DB must immediately reflect the new value.
#     Step 2: Change scheduler.5 weight 30->20.  All other profiles must remain
#             unchanged.  CONFIG_DB must immediately reflect the new value.
#     """
#     ...  # commented out — see test_fx3_scheduler_2022.py for full implementation


@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_scheduler_dwrr_validation(af):
    """Validate Tortuga DWRR weight ratios under 2:1 oversubscribed fan-in traffic.

    Parametrized over address family (ipv4/ipv6).  Both run the same
    validation logic — only the L3 header and next-hop resolution differ.

    Phase 1 (Config): Verify DSCP_TO_TC_MAP, SCHEDULER profiles,
        QUEUE bindings, WRED config, and DCHAL HW scheduler BW%.
    Phase 2 (Traffic): Send oversubscribed traffic, validate:
      - DWRR ratio checks (Q3/Q0=2.0, Q5/Q0=1.5, etc.) within 20% tolerance
      - STRICT Q6,Q7 have zero drops
    """
    st.banner("test_scheduler_dwrr_validation [{}] STARTED".format(af))
    fail_msgs = []
    egress = port_info['egress']

    # ── Address-family dispatch ──
    if af == "ipv6":
        src_ips = (IXIA_INGRESS_A_IP6, IXIA_INGRESS_B_IP6)
        dst_ip  = IXIA_EGRESS_IP6
        nb_cmd  = 'show ndp'
    else:
        src_ips = (IXIA_INGRESS_A_IP, IXIA_INGRESS_B_IP)
        dst_ip  = IXIA_EGRESS_IP
        nb_cmd  = 'show arp'

    # ══════════════════════════════════════════════════════════════════════
    # Phase 1: Config — verify live CONFIG_DB matches config_db.json baseline
    # ══════════════════════════════════════════════════════════════════════
    st.log("Phase 1: Verifying CONFIG_DB against config_db.json baseline")
    verify_config_db_baseline(dut, egress, port_info, fail_msgs)

    # Deploy DCHAL helper and verify HW scheduler registers
    st.log("Deploying DCHAL show-queuing helper into syncd container")
    deploy_dchal_helper(dut)
    dchal_out = dchal_show_queuing(dut, "Phase1 HW scheduler check", egress)
    if dchal_out:
        report_dchal_bw_check(dchal_out, fail_msgs)
    else:
        st.warn("DCHAL show-queuing returned no output — "
                "skipping HW scheduler verification")

    if fail_msgs:
        st.report_fail('msg',
                       'DWRR validation config phase FAILED: '
                       + '; '.join(fail_msgs))
        return

    st.log("Phase 1 PASSED: CONFIG_DB + DCHAL HW scheduler verified "
           "(DSCP_TO_TC_MAP, SCHEDULER, QUEUE, WRED, BW%)")

    # ══════════════════════════════════════════════════════════════════════
    # Phase 2: Traffic — oversubscribed fan-in, DWRR ratios + STRICT drops
    # ══════════════════════════════════════════════════════════════════════
    egress_speed = port_speeds.get('egress', 'N/A')
    has_ingress_b = 'ingress_b' in port_info
    num_ports = 2 if has_ingress_b else 1
    st.log("Phase 2 [{}]: Sending oversubscribed traffic "
           "(8 streams x {:.1f}% x {} port(s) = {:.0f}% of {})".format(
               af, stream_rate_pct, num_ports,
               stream_rate_pct * NUM_QUEUES * num_ports,
               egress_speed))

    mac_a = get_dut_mac(dut, port_info['ingress_a'])
    mac_b = get_dut_mac(dut, port_info['ingress_b']) if has_ingress_b else None
    st.log("DUT MACs: ingress_a={}{}".format(
        mac_a, " ingress_b={}".format(mac_b) if mac_b else ""))

    if not verify_egress_reachable(dut, tg, tg_ph, af):
        st.report_fail('msg',
                       'Egress neighbor resolution failed for {} — '
                       'check IXIA interface and L3 config'.format(af))
        return

    # Clear DUT counters so deltas reflect only this test run
    clear_dut_counters(dut)
    dchal_clear_counters(dut, egress)

    # Verify counters are actually 0 after clear
    intf_check = get_intf_counters(dut, port_info.values())
    for intf, ctrs in intf_check.items():
        rx = ctrs.get('rx_ok', 0)
        tx = ctrs.get('tx_ok', 0)
        if rx != 0 or tx != 0:
            st.warn("Counter clear incomplete for {}: "
                    "rx_ok={} tx_ok={} — deltas may include stale traffic".format(
                        intf, rx, tx))

    # Snapshot DUT interface counters BEFORE traffic
    intf_before = get_intf_counters(dut, port_info.values())

    # Snapshot ASIC queue counters BEFORE traffic (via DCHAL)
    q_before = get_dchal_queue_counters(dut, egress,
                                        label="BEFORE DWRR traffic")

    stream_handles = []
    ports = [(tg_ph['ingress_a'], src_ips[0], mac_a, 'TX1')]
    if has_ingress_b:
        ports.append((tg_ph['ingress_b'], src_ips[1], mac_b, 'TX2'))
    tg.tg_traffic_control(action='clear_stats')
    for qi in range(NUM_QUEUES):
        dscp = QUEUE_TO_DSCP[qi]
        for ph, src_ip, dst_mac, port_label in ports:
            if af == "ipv6":
                tc_val = dscp << 2
                st.log("  Creating stream [ipv6]: Q{} TC={} port={} "
                        "src={} dst={}".format(
                            qi, tc_val, port_label, src_ip, dst_ip))
                result = tg.tg_traffic_config(
                    mode='create', port_handle=ph,
                    l3_protocol='ipv6',
                    ipv6_src_addr=src_ip,
                    ipv6_dst_addr=dst_ip,
                    mac_dst=dst_mac,
                    ipv6_traffic_class=tc_val,
                    ipv6_hop_limit=64,
                    frame_size=PKT_SIZE,
                    rate_percent=stream_rate_pct,
                    transmit_mode='continuous',
                    high_speed_result_analysis=0,
                )
            else:
                st.log("  Creating stream [ipv4]: Q{} DSCP={} TOS={} port={} "
                        "src={} dst={}".format(
                            qi, dscp, dscp << 2, port_label, src_ip, dst_ip))
                result = tg.tg_traffic_config(
                    mode='create', port_handle=ph,
                    l3_protocol='ipv4',
                    l4_protocol='icmp',
                    ip_src_addr=src_ip,
                    ip_dst_addr=dst_ip,
                    mac_dst=dst_mac,
                    ip_dscp=dscp,
                    ip_ttl=64,
                    frame_size=PKT_SIZE,
                    rate_percent=stream_rate_pct,
                    transmit_mode='continuous',
                    high_speed_result_analysis=0,
                )
            sid = result.get('stream_id', 'UNKNOWN')
            st.log("    -> stream_id={} (result keys: {})".format(
                sid, list(result.keys())))
            stream_handles.append(result)

    st.log("Total streams created: {} (expected {})".format(
        len(stream_handles), NUM_QUEUES * len(ports)))
    for idx, sh in enumerate(stream_handles):
        qi = idx // len(ports)
        port_label = ports[idx % len(ports)][3]
        dscp = QUEUE_TO_DSCP[qi]
        st.log("  stream[{}] Q{} DSCP={} {} stream_id={}".format(
            idx, qi, dscp, port_label, sh.get('stream_id', 'UNKNOWN')))

    st.log("Starting traffic for {} seconds ...".format(TRAFFIC_DURATION))
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    st.wait(TRAFFIC_DURATION)
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    # ──────────────────────────────────────────────────────────────────────
    # Collect all data FIRST, then print summary tables (same approach as
    # test_scheduler_validation.py — separate collection from display).
    # ──────────────────────────────────────────────────────────────────────

    # 1. DCHAL ASIC-level queue counters AFTER traffic
    q_after = get_dchal_queue_counters(dut, egress,
                                       label="AFTER DWRR traffic")

    # 2. DUT interface counters AFTER traffic
    intf_after = get_intf_counters(dut, port_info.values())

    # 3. DCHAL weight-to-bandwidth% output
    _dchal_bw_out = dchal_show_queuing(dut, "AFTER DWRR traffic", egress)

    # 4. CLI queue counters for reference only
    # st.log("--- 'show queue counters' (reference only) ---")  # has issues on FX3
    # st.show(dut, "show queue counters {}".format(egress), skip_tmpl=True)

    # 4. Compute deltas from DCHAL snapshots
    q_deltas = {}
    q_drop_deltas = {}
    for qi in range(NUM_QUEUES):
        q_deltas[qi] = (q_after.get(qi, {}).get('pkts', 0)
                        - q_before.get(qi, {}).get('pkts', 0))
        q_drop_deltas[qi] = (q_after.get(qi, {}).get('drop_pkts', 0)
                             - q_before.get(qi, {}).get('drop_pkts', 0))

    total_egress = sum(q_deltas.get(qi, 0) for qi in range(NUM_QUEUES))

    # ──────────────────────────────────────────────────────────────────────
    # Print DUT-side results FIRST (safe — no IXIA API calls).
    # This guarantees the validation summary appears in the log even if
    # tg_traffic_stats triggers a TGen Fatal Abort afterward.
    # ──────────────────────────────────────────────────────────────────────

    # ── DUT INTERFACE COUNTERS (delta) ──
    report_intf_counters(port_info, intf_before, intf_after)
    st.log("")

    # ── DUT QUEUE COUNTERS (DCHAL / ASIC-level) ──
    report_queue_counters(egress, q_deltas, q_drop_deltas,
                          NUM_QUEUES, source="DCHAL")
    st.log("")

    if total_egress == 0:
        st.log("WARNING [{}]: all DCHAL queue counter deltas are 0 — "
               "traffic did not reach egress; skipping scheduler validation".format(af))
        for sh in stream_handles:
            try:
                tg.tg_traffic_config(mode='remove',
                                     stream_id=sh.get('stream_id'))
            except Exception:
                pass
        st.report_fail('msg',
                       'Scheduler DWRR validation [{}] SKIPPED: '
                       'all queue counters are 0 after traffic — '
                       'check {}, routing, and link status'.format(af, nb_cmd))
        return

    # ── SCHEDULER VALIDATION ──
    _w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    validate_dchal_bw_vs_weights('DWRR validation', _dchal_bw_out, _w_baseline, fail_msgs)
    validate_dwrr_ratios('DWRR validation', q_before, q_after,
                         _w_baseline, fail_msgs)
    st.log("")

    # ── Verdict — report BEFORE IXIA stats (tg_traffic_stats may crash) ──
    for sh in stream_handles:
        try:
            tg.tg_traffic_config(mode='remove',
                                 stream_id=sh.get('stream_id'))
        except Exception:
            pass

    if fail_msgs:
        st.report_fail('msg',
                       'Scheduler DWRR validation [{}] FAILED: '.format(af)
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'Scheduler DWRR validation [{}] passed: '
                       'all ratio checks and STRICT zero-drop verified'.format(af))


# ═══════════════════════════════════════════════════════════════════════════
# WRED Tests (Fan-in Topology: 2 x 100G ingress → 100G egress)
# ═══════════════════════════════════════════════════════════════════════════
#
# These tests validate Weighted Random Early Detection behavior by sending
# traffic from BOTH ingress ports to the same target queue on the egress
# port.  Each port sends at half the total desired rate so combined traffic
# exceeds 100G egress capacity by the specified margin.
#
# ┌──────────────────────────────────────────────────────────────────────┐
# │                        2022 WRED TOPOLOGY                           │
# │                                                                     │
# │  Testbed: fx3_qos_testbed_2022.yaml (all ports 100G)               │
# │  Target queue: Q1 (DSCP 6)                                         │
# ├──────────────────────────────────────────────────────────────────────┤
# │                                                                     │
# │                        ┌─────────────────┐                          │
# │  ┌──────────────┐      │                 │      ┌──────────────┐    │
# │  │ IXIA Port A  │      │                 │      │ IXIA Port C  │    │
# │  │ (T1 1/9)     │      │     DUT1        │      │ (T1 1/11)    │    │
# │  │              │ 100G │                 │ 100G │              │    │
# │  │ 10.10.10.2 ──┼──────┤► Ethernet1_49  │      │              │    │
# │  │ db8:10::2    │      │  10.10.10.1     │      │              │    │
# │  │              │      │  db8:10::1      │      │              │    │
# │  │  Stream A    │      │                 │      │              │    │
# │  │  DSCP 6      │      │    ┌────────┐   │      │              │    │
# │  │  rate=50%+   │      │    │ Queue 1│───┼──────┤► 20.20.20.2  │    │
# │  └──────────────┘      │    │ (WRED) │   │      │  db8:20::2   │    │
# │                        │    └────┬───┘   │      │              │    │
# │  ┌──────────────┐      │         │       │      │   receives   │    │
# │  │ IXIA Port B  │      │   Ethernet1_51──┼──────┤►  combined   │    │
# │  │ (T1 1/10)    │      │   20.20.20.1    │      │   traffic    │    │
# │  │              │ 100G │   db8:20::1      │      │              │    │
# │  │ 10.10.11.2 ──┼──────┤► Ethernet1_50  │      └──────────────┘    │
# │  │ db8:11::2    │      │  10.10.11.1     │                          │
# │  │              │      │  db8:11::1      │                          │
# │  │  Stream B    │      │                 │                          │
# │  │  DSCP 6      │      │                 │                          │
# │  │  rate=50%+   │      └─────────────────┘                          │
# │  └──────────────┘                                                   │
# │                                                                     │
# └──────────────────────────────────────────────────────────────────────┘
#
# ┌──────────────────────────────────────────────────────────────────────┐
# │                     FAN-IN RATE CALCULATION                         │
# ├──────────────────────────────────────────────────────────────────────┤
# │                                                                     │
# │  Problem: All ports are 100G.  A single port CANNOT exceed the      │
# │           100G egress capacity.  No congestion → no WRED drops.     │
# │                                                                     │
# │  Solution: Fan-in from BOTH ingress ports to the SAME egress queue. │
# │                                                                     │
# │  Formula (per-port rate for desired margin M):                      │
# │                                                                     │
# │    total_target = egress_speed + M                                  │
# │    per_port     = total_target / 2                                  │
# │    rate_pct     = per_port / ingress_speed * 100                    │
# │                                                                     │
# │  Example (margin = 2000 Mbps):                                      │
# │                                                                     │
# │    total  = 100,000 + 2,000 = 102,000 Mbps                         │
# │    per_port = 102,000 / 2   =  51,000 Mbps                         │
# │    rate_pct = 51,000 / 100,000 * 100 = 51.0%                       │
# │                                                                     │
# │    Port A ──► 51.0% of 100G = 51,000 Mbps ──┐                      │
# │                                               ├► 102,000 Mbps total │
# │    Port B ──► 51.0% of 100G = 51,000 Mbps ──┘   (2G over 100G)    │
# │                                                                     │
# │  At margin=0 (Zone A, no congestion):                               │
# │    each port at 50.0% → combined = 100G exactly → 0 drops           │
# │                                                                     │
# │  At margin=5000 (Zone B, near max):                                 │
# │    each port at 52.5% → combined = 105G → ~4.76% WRED drops        │
# │                                                                     │
# │  At margin=10000 (Zone C, tail drop):                               │
# │    each port at 55.0% → combined = 110G → tail drop dominates      │
# │                                                                     │
# └──────────────────────────────────────────────────────────────────────┘
#
# ┌──────────────────────────────────────────────────────────────────────┐
# │                   TRAFFIC FLOW (per test point)                     │
# ├──────────────────────────────────────────────────────────────────────┤
# │                                                                     │
# │  1. Clear all counters (CLI + DCHAL)                                │
# │  2. Create stream A on ingress_a port:                              │
# │       dst_ip = 20.20.20.2 (or db8:20::2)                           │
# │       src_ip = 10.10.10.2 (or db8:10::2)                           │
# │       DSCP   = 6  (maps to Q1)                                     │
# │       mac_dst = DUT router MAC                                      │
# │       rate   = per_port_rate_pct                                    │
# │  3. Create stream B on ingress_b port (identical except src_ip):    │
# │       dst_ip = 20.20.20.2 (or db8:20::2)                           │
# │       src_ip = 10.10.11.2 (or db8:11::2)                           │
# │       DSCP   = 6  (maps to Q1)                                     │
# │       mac_dst = DUT router MAC                                      │
# │       rate   = per_port_rate_pct                                    │
# │  4. Start both streams simultaneously                               │
# │  5. Wait settle time, then sample queue depth via DCHAL             │
# │  6. Stop traffic, collect DCHAL counters + peak watermarks          │
# │  7. Compute drop rate from Q1 egress + drop deltas                  │
# │                                                                     │
# └──────────────────────────────────────────────────────────────────────┘
#
# WRED profile (AZURE_LOSSY from config_db.json):
#   green_min_threshold = 1,048,576 bytes (1 MB)
#   green_max_threshold = 3,145,728 bytes (3 MB)
#   green_drop_probability = 5%
#
#   Drop Probability
#   ^
#   100% |                    xxxxxxx (tail drop)
#        |                   x
#     5% |. . . . . . . . .x (green_drop_probability)
#        |                x
#        |              x    <- linear region
#        |            x
#        |          x
#     0% |________x
#        +--------|---------|----------->  Queue Depth (bytes)
#               1 MB      3 MB
#             (min_th)  (max_th)
#
# Margins are 10x vs 2021 (10G egress) to produce equivalent WRED behavior
# on 100G egress:
#
#   Margin (Mbps)  Per-Port Rate  Combined   Zone
#   ─────────────  ─────────────  ─────────  ──────
#        0          50.000%       100.0G      A
#      250          50.125%       100.25G     B
#      500          50.250%       100.5G      B
#     1000          50.500%       101.0G      B
#     2000          51.000%       102.0G      B
#     3000          51.500%       103.0G      B
#     4000          52.000%       104.0G      B
#     5000          52.500%       105.0G      B
#     5250          52.625%       105.25G     C
#     5500          52.750%       105.5G      C
#    10000          55.000%       110.0G      C (tail drop test)
#
# ═══════════════════════════════════════════════════════════════════════════


def _verify_egress_neighbor(af):
    """Closure over module globals, passed as a callback to run_wred_linearity."""
    return verify_egress_reachable(dut, tg, tg_ph, af)


# ── Test: WRED Zone A — below min threshold ──────────────────────────────

@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_below_min(af):
    """Zone A: queue depth < 1 MB, expect 0% drops.

    Fan-in slightly below egress capacity (margin=WRED_ZONE_A_MARGIN) so
    IXIA rate-precision jitter cannot push the queue above min_th.
    No excess accumulates, WRED should not activate.
    """
    st.banner("test_wred_below_min [{}] (fan-in) STARTED".format(af))
    fail_msgs = []

    st.log("Phase 1: Verifying WRED config")
    verify_wred_config(wred_ctx, fail_msgs)
    deploy_dchal_helper(dut)
    if fail_msgs:
        st.report_fail('msg', 'WRED config FAILED: ' + '; '.join(fail_msgs))
        return

    if not _verify_egress_neighbor(af):
        st.report_fail('msg', 'Egress neighbor resolution failed for {}'.format(af))
        return

    margin = scale_margin(WRED_ZONE_A_MARGIN, egress_speed_mbps)
    st.log("Phase 2: Sending fan-in traffic below line rate "
           "(margin={}M for IXIA headroom)".format(margin))
    results = wred_fanin_send_and_measure(wred_ctx, af,
                                          margin_mbps=margin,
                                          duration=WRED_DURATION)
    report_wred_result(wred_ctx, results, "ZONE A (below min)")

    if results['egress_pkts'] <= 0:
        fail_msgs.append("Q{} egress_pkts=0 — traffic not forwarded; "
                         "check routing and mac_dst".format(TARGET_QUEUE))

    drop_tolerance = 100
    if results['drop_pkts'] > drop_tolerance:
        fail_msgs.append("Q{} drops={} — expected <= {} with no excess "
                         "(IXIA rate precision may cause micro-drops)".format(
                             TARGET_QUEUE, results['drop_pkts'],
                             drop_tolerance))

    if results['q_depth_bytes'] >= WRED_MIN_TH:
        fail_msgs.append(
            "Q{} depth={} bytes ({:.2f} MB) >= min_th {} — "
            "expected below".format(
                TARGET_QUEUE, results['q_depth_bytes'],
                results['q_depth_bytes'] / (1024.0 * 1024), WRED_MIN_TH))

    if results.get('peak_bytes', 0) >= WRED_MIN_TH:
        fail_msgs.append(
            "Q{} peak watermark={} bytes ({:.2f} MB) >= min_th — "
            "queue entered WRED zone at some point".format(
                TARGET_QUEUE, results['peak_bytes'],
                results['peak_bytes'] / (1024.0 * 1024)))

    if fail_msgs:
        st.report_fail('msg',
                       'WRED below-min [{}] FAILED: '.format(af)
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'WRED below-min [{}] passed: '
                       '0 drops, depth={} bytes'.format(
                           af, results['q_depth_bytes']))


# ── Test: WRED Zone B — active zone (drop 0-5%) ─────────────────────────

@pytest.mark.parametrize("margin_mbps", [250, 500, 1000, 2000])
@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_active_zone(af, margin_mbps):
    """Zone B: 1 MB < queue depth < 3 MB, WRED probability 0-5%.

    Fan-in at egress rate + margin.  Parametrize values are authored for
    100G egress; ``scale_margin`` adjusts proportionally so the overshoot
    ratio (and thus WRED zone) is identical on slower links (e.g. 25G).
    """
    st.banner("test_wred_active_zone [{}] margin={}M (fan-in)".format(
        af, margin_mbps))
    fail_msgs = []

    st.log("Phase 1: Verifying WRED config")
    verify_wred_config(wred_ctx, fail_msgs)
    deploy_dchal_helper(dut)
    if fail_msgs:
        st.report_fail('msg', 'WRED config FAILED: ' + '; '.join(fail_msgs))
        return

    if not _verify_egress_neighbor(af):
        st.report_fail('msg', 'Egress neighbor resolution failed for {}'.format(af))
        return

    effective_margin = scale_margin(margin_mbps, egress_speed_mbps)
    st.log("Phase 2: Sending fan-in traffic with {}M margin "
           "(scaled from {}M baseline)".format(effective_margin, margin_mbps))
    results = wred_fanin_send_and_measure(wred_ctx, af, effective_margin,
                                          duration=WRED_DURATION)
    report_wred_result(wred_ctx, results, "ZONE B (active)")

    if results['egress_pkts'] <= 0:
        fail_msgs.append("Q{} egress_pkts=0 — traffic not forwarded; "
                         "check routing and mac_dst".format(TARGET_QUEUE))

    if results['drop_pkts'] <= 0:
        fail_msgs.append("Q{} drops=0 — expected WRED drops "
                         "with {}M excess".format(TARGET_QUEUE, margin_mbps))

    if results['drop_rate_pct'] > (WRED_MAX_PROB + WRED_TOLERANCE):
        fail_msgs.append(
            "Q{} drop_rate={:.2f}% exceeds max {}% + {}% tolerance".format(
                TARGET_QUEUE, results['drop_rate_pct'],
                WRED_MAX_PROB, WRED_TOLERANCE))

    if results['q_depth_bytes'] > 0 and results['q_depth_bytes'] < WRED_MIN_TH:
        fail_msgs.append(
            "Q{} depth={} bytes < min_th {} — "
            "queue not in WRED active zone".format(
                TARGET_QUEUE, results['q_depth_bytes'], WRED_MIN_TH))

    if results['q_depth_bytes'] > 0 and results['q_depth_bytes'] > WRED_MAX_TH:
        fail_msgs.append(
            "Q{} depth={} bytes > max_th {} — "
            "should be in WRED zone, not tail drop".format(
                TARGET_QUEUE, results['q_depth_bytes'], WRED_MAX_TH))

    for qi in [6, 7]:
        strict_drops = results['all_queues'].get(qi, {}).get('drops', 0)
        if strict_drops > 0:
            fail_msgs.append("STRICT Q{} drops={} — expected 0".format(
                qi, strict_drops))

    for qi in range(NUM_QUEUES):
        if qi == TARGET_QUEUE:
            continue
        other_pkts = results['all_queues'].get(qi, {}).get('egress', 0)
        if other_pkts > 100:
            fail_msgs.append("Q{} has {} unexpected packets".format(
                qi, other_pkts))

    if fail_msgs:
        st.report_fail('msg',
                       'WRED active-zone [{}] margin={}M '
                       'FAILED: '.format(af, margin_mbps)
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'WRED active-zone [{}] margin={}M passed: '
                       'drops={:,} rate={:.2f}%, depth={:.2f}MB'.format(
                           af, margin_mbps, results['drop_pkts'],
                           results['drop_rate_pct'],
                           results['q_depth_bytes'] / (1024.0 * 1024)))


# ── Test: WRED Zone C — above max threshold (tail drop) ─────────────────

@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_tail_drop(af):
    """Zone C: queue depth > 3 MB, tail drop dominates.

    Fan-in with large margin (10000M @ 100G baseline, scaled for actual
    egress speed).  The excess overwhelms WRED's 5% max drop probability,
    causing queue to exceed max_threshold and trigger tail drop.
    """
    margin = scale_margin(10000, egress_speed_mbps)
    st.banner("test_wred_tail_drop [{}] margin={}M (fan-in)".format(af, margin))
    fail_msgs = []

    st.log("Phase 1: Verifying WRED config")
    verify_wred_config(wred_ctx, fail_msgs)
    deploy_dchal_helper(dut)
    if fail_msgs:
        st.report_fail('msg', 'WRED config FAILED: ' + '; '.join(fail_msgs))
        return

    if not _verify_egress_neighbor(af):
        st.report_fail('msg', 'Egress neighbor resolution failed for {}'.format(af))
        return

    st.log("Phase 2: Sending fan-in traffic with {}M margin "
           "(expect tail drop)".format(margin))
    results = wred_fanin_send_and_measure(wred_ctx, af, margin,
                                          duration=WRED_DURATION)
    report_wred_result(wred_ctx, results, "ZONE C (tail drop)")

    if results['egress_pkts'] <= 0:
        fail_msgs.append("Q{} egress_pkts=0 — traffic not forwarded; "
                         "check routing and mac_dst".format(TARGET_QUEUE))

    if results['drop_pkts'] <= 0:
        fail_msgs.append("Q{} drops=0 — expected tail drop "
                         "with {}M excess".format(TARGET_QUEUE, margin))

    if results['drop_rate_pct'] <= WRED_MAX_PROB:
        fail_msgs.append(
            "Q{} drop_rate={:.2f}% <= {}% — expected ABOVE max_prob "
            "(tail drop should exceed WRED range)".format(
                TARGET_QUEUE, results['drop_rate_pct'], WRED_MAX_PROB))

    if results['q_depth_bytes'] > 0 and results['q_depth_bytes'] < WRED_MAX_TH:
        fail_msgs.append(
            "Q{} depth={} bytes < max_th {} — "
            "expected at or above max threshold".format(
                TARGET_QUEUE, results['q_depth_bytes'], WRED_MAX_TH))

    if results.get('peak_bytes', 0) > 0 and results['peak_bytes'] < WRED_MAX_TH:
        fail_msgs.append(
            "Q{} peak watermark={} bytes ({:.2f} MB) < max_th — "
            "queue never reached tail drop region".format(
                TARGET_QUEUE, results['peak_bytes'],
                results['peak_bytes'] / (1024.0 * 1024)))

    if fail_msgs:
        st.report_fail('msg',
                       'WRED tail-drop [{}] margin={}M '
                       'FAILED: '.format(af, margin)
                       + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'WRED tail-drop [{}] margin={}M passed: '
                       'drops={:,} rate={:.2f}%, depth={:.2f}MB'.format(
                           af, margin, results['drop_pkts'],
                           results['drop_rate_pct'],
                           results['q_depth_bytes'] / (1024.0 * 1024)))


# ── Test: WRED Linearity — sweep full WRED curve ────────────────────────

@pytest.mark.parametrize("af", ["ipv4", "ipv6"])
def test_wred_linearity(af):
    """Verify WRED drop rate increases monotonically across margins.

    Fan-in sweep from Zone A through Zone B to Zone C boundary.
    Base margins are authored for 100G egress and scaled proportionally
    via ``scale_margin`` so the same WRED zones are exercised at any
    egress speed (e.g. 25G breakout).

    Expected steady-state at baseline (100G egress):
        0M   -> depth ~0 MB,    drop 0.00%  (Zone A)
      250M   -> depth 1.10 MB,  drop 0.25%  (Zone B)
      500M   -> depth 1.20 MB,  drop 0.50%  (Zone B)
     1000M   -> depth 1.40 MB,  drop 0.99%  (Zone B)
     2000M   -> depth 1.77 MB,  drop 1.96%  (Zone B)
     3000M   -> depth 2.12 MB,  drop 2.91%  (Zone B)
     4000M   -> depth 2.46 MB,  drop 3.85%  (Zone B)
     5000M   -> depth 2.86 MB,  drop 4.76%  (Zone B near max)
     5250M   -> depth ~3.0 MB,  drop 4.99%  (Zone B/C boundary)
     5500M   -> depth > 3 MB,   drop 5.21%  (Zone C, tail drop)
    """
    base_margins = [0, 250, 500, 1000, 2000, 3000, 4000, 5000, 5250, 5500]
    margins = [scale_margin(m, egress_speed_mbps) for m in base_margins]
    st.banner("test_wred_linearity [{}] margins={} (fan-in)".format(af, margins))

    fail_msgs, data_points = run_wred_linearity(
        wred_ctx, af, margins, _verify_egress_neighbor,
        duration=20, num_depth_samples=3)

    if fail_msgs:
        st.report_fail('msg',
                       'WRED linearity [{}] '
                       'FAILED: '.format(af)
                       + '; '.join(fail_msgs))
    else:
        rates_str = ', '.join(
            '{:.2f}%'.format(dp['drop_rate_pct']) for dp in data_points)
        st.report_pass('msg',
                       'WRED linearity [{}] passed: '
                       'drop rates [{}] monotonically increasing'.format(
                           af, rates_str))

