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
FX3 QoS WRED Drop Probability Test.

Topology mode is inferred from the testbed YAML structure
(ixia / peer_link / breakout) via the shared ``setup_topo_common`` helper.

(test_wred_drop_probability):
  Test WRED (Weighted Random Early Detection) drop probability behavior
  under fan-in congestion.  Uses the fan-in topology (2 ingress ports ->
  1 egress port) to create egress queue congestion on queue 3.
  Validates baseline WRED_PROFILE|AZURE_LOSSY, boundary rejection (gdrop=200),
  CONFIG_DB state at gdrop=100 with equal-weight DWRR, zero drops at low
  rate, and WRED drops under queue-3-targeted oversubscription via DCHAL
  ASIC counters.
"""

import copy
import os
import sys
import pytest

from spytest import st, tgapi

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fx3_qos_helpers import (
    QUEUE_TO_DSCP, IXIA_INGRESS_A_IP, IXIA_INGRESS_B_IP, IXIA_EGRESS_IP,
    NUM_QUEUES, PKT_SIZE,
    setup_topo_common, compute_single_queue_rate_pct,
    deploy_dchal_helper, get_dut_mac,
    dchal_show_queuing, parse_dchal_queue_stats, parse_dchal_egress_bw,
    parse_redis_hget, load_config_db_baseline,
    verify_wred_profile, verify_queue_bindings,
    verify_scheduler_profiles,
)


# ── Test-specific parameters ──────────────────────────────────────────────
TARGET_QUEUE       = 3
STREAM_RATE_PPS    = 100
TRAFFIC_DURATION   = 5
WRED_OVERSUB       = 1.50    # target oversubscription for single-queue WRED
CONGESTION_DURATION = 10


# ── Module-level topology state (populated by fixture) ────────────────────
dut = None
tg = None
tg_ph = {}
port_info = {}
port_speeds = {}
ingress_speed_mbps = 0
egress_speed_mbps = 0
wred_ctx = None
tg_stream_rate_pct = 0  # computed by setup_topo via compute_single_queue_rate_pct


@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Set up topology via shared setup_topo_common helper."""
    global dut, tg, tg_ph, port_info, port_speeds
    global ingress_speed_mbps, egress_speed_mbps, wred_ctx
    global tg_stream_rate_pct

    for result in setup_topo_common(tgapi, target_queue=TARGET_QUEUE):
        dut = result['dut']
        tg = result['tg']
        tg_ph = result['tg_ph']
        port_info = result['port_info']
        port_speeds = result['port_speeds']
        ingress_speed_mbps = result['ingress_speed_mbps']
        egress_speed_mbps = result['egress_speed_mbps']
        wred_ctx = result['wred_ctx']

        num_ingress = len([k for k in tg_ph
                          if k not in ('egress', 'egress_sink')])
        tg_stream_rate_pct = compute_single_queue_rate_pct({
            'ingress_speed_mbps': ingress_speed_mbps,
            'egress_speed_mbps': egress_speed_mbps,
            'num_ingress_ports': num_ingress,
        }, oversub_ratio=WRED_OVERSUB)
        yield


def test_wred_drop_probability():
    """
    Test WRED drop probability behavior under fan-in congestion.

    Uses the fan-in topology (2 ingress ports -> 1 egress port) to create
    egress queue congestion for WRED testing.

    Steps:
        1: Verify baseline WRED_PROFILE|AZURE_LOSSY and queue bindings.
        2: Attempt gdrop=200 -> expect rejection (valid range: 0-100).
        3: Convert all 8 schedulers to equal-weight DWRR (schedulers 6/7
                converted from STRICT) and set gdrop=100 on the shared
                AZURE_LOSSY profile.  Verify CONFIG_DB state via helpers
                and ASIC-level Bandwidth% via DCHAL.  Equal weights give
                each queue 12.5% of the egress port bandwidth.
        4: Low-rate DSCP-3 traffic (no congestion) -> verify zero WRED
                drops via DCHAL ASIC counters.
        5: High-rate fan-in traffic targeting queue 3 only (2 streams at
                50% line rate from both ingress ports = 100% into a queue
                that drains at 12.5%).  Verify WRED drops on Q3 via DCHAL.
        6: Restore QoS baseline via 'config qos reload' and verify full
                baseline restoration (WRED profile, schedulers, queue
                bindings) using helpers.
    """
    st.banner("test_wred_drop_probability STARTED")
    fail_msgs = []
    egress = port_info['egress']

    deploy_dchal_helper(dut)

    has_ingress_b = 'ingress_b' in port_info
    mac_a = get_dut_mac(dut, port_info['ingress_a'])
    mac_b = get_dut_mac(dut, port_info['ingress_b']) if has_ingress_b else None
    st.log("DUT MACs: ingress_a={}{}".format(
        mac_a, " ingress_b={}".format(mac_b) if mac_b else ""))

    # Step 1: Verify baseline WRED_PROFILE|AZURE_LOSSY and queue bindings
    st.log("Step 1: Verifying baseline WRED_PROFILE|AZURE_LOSSY and Q3 binding")
    verify_wred_profile(dut, fail_msgs)
    verify_queue_bindings(dut, egress, fail_msgs)

    # Step 2: Attempt drop_probability=200 (expect rejection)
    st.log("Step 2: Attempting drop_probability=200 (expect rejection)")
    st.config(dut, "sudo ecnconfig -p AZURE_LOSSY -gdrop 200",
              skip_error_check=True)
    st.wait(2)

    out = st.show(
        dut,
        'sonic-db-cli CONFIG_DB HGET "WRED_PROFILE|AZURE_LOSSY" '
        '"green_drop_probability"', skip_tmpl=True)
    gdrop_after_200 = parse_redis_hget(out).strip()
    st.log("  green_drop_probability after gdrop 200 = '{}'".format(
        gdrop_after_200))
    if gdrop_after_200 == '200':
        fail_msgs.append(
            "Step 2: gdrop 200 was accepted (expected rejection)")

    # Step 3: All 8 queues equal-weight DWRR + gdrop=100
    baseline = load_config_db_baseline()
    step3_baseline = copy.deepcopy(baseline)
    for qi in range(NUM_QUEUES):
        step3_baseline['SCHEDULER']['scheduler.{}'.format(qi)] = {
            'type': 'DWRR', 'weight': '20'
        }

    st.log("Step 3: Converting all 8 queues to equal-weight DWRR")
    for qi in range(NUM_QUEUES):
        st.config(dut,
                  'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.{}" '
                  '"type" "DWRR" "weight" "20"'.format(qi))
    st.wait(2)

    verify_scheduler_profiles(dut, fail_msgs, baseline=step3_baseline)

    # Changing the SCHEDULER entry's type field alone does not trigger
    # orchagent to re-bind the scheduler to its Scheduler Group (SG),
    # so the ASIC keeps the old bindings.  Delete + re-create forces it.
    st.log("Step 3: Re-binding QUEUE->scheduler entries to force "
           "ASIC reprogramming")
    for qi in range(NUM_QUEUES):
        st.config(dut,
                  'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|{}" '
                  '"scheduler"'.format(egress, qi))
    st.wait(2)
    for qi in range(NUM_QUEUES):
        st.config(dut,
                  'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|{}" '
                  '"scheduler" "scheduler.{}"'.format(egress, qi, qi))
    st.wait(3)

    verify_queue_bindings(dut, egress, fail_msgs, baseline=step3_baseline)

    # ASIC-level DWRR verification via DCHAL Bandwidth%
    st.wait(5)
    dchal_p3 = dchal_show_queuing(dut, "Step 3: ASIC verification", egress)
    bw_map = parse_dchal_egress_bw(dchal_p3)

    st.log("Step 3: DCHAL Bandwidth% = {}".format(bw_map))

    expected_bw = 100.0 / NUM_QUEUES
    asic_dwrr_ok = True
    for qi in range(NUM_QUEUES):
        actual_bw = bw_map.get(qi, {}).get('bw_pct', -1)
        if actual_bw is None or actual_bw < 0 or abs(actual_bw - expected_bw) > 3:
            asic_dwrr_ok = False

    if asic_dwrr_ok:
        st.log("Step 3: ASIC confirmed all 8 queues at equal Bandwidth%")
    else:
        st.warn("Step 3: ASIC Bandwidth% does not reflect equal-weight "
                "DWRR (got {}). CONFIG_DB change may not have propagated "
                "to hardware. WRED test continues but queue isolation "
                "is not guaranteed.".format(bw_map))

    st.log("Step 3: Setting WRED green_drop_probability=100 (max)")
    st.config(dut, "sudo ecnconfig -p AZURE_LOSSY -gdrop 100")
    st.wait(2)

    step3_baseline['WRED_PROFILE']['AZURE_LOSSY']['green_drop_probability'] = '100'
    verify_wred_profile(dut, fail_msgs, baseline=step3_baseline)

    # Step 4: Low-rate DSCP-3 traffic (no congestion)
    st.log("Step 4: Low-rate DSCP-3 traffic (no congestion expected)")
    dchal_p4_before = dchal_show_queuing(
        dut, "Step 4: before traffic", egress)
    dchal_p4_before_stats = parse_dchal_queue_stats(dchal_p4_before)

    tg.tg_traffic_control(action='clear_stats')
    stream_p4 = tg.tg_traffic_config(
        mode='create',
        port_handle=tg_ph['ingress_a'],
        l3_protocol='ipv4',
        ip_src_addr=IXIA_INGRESS_A_IP,
        ip_dst_addr=IXIA_EGRESS_IP,
        mac_dst=mac_a,
        ip_dscp=QUEUE_TO_DSCP[3],
        frame_size=PKT_SIZE,
        rate_pps=STREAM_RATE_PPS,
        transmit_mode='continuous',
    )

    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run', max_wait_timer=30)
    st.wait(TRAFFIC_DURATION)
    tg.tg_traffic_control(action='stop', max_wait_timer=30)
    st.wait(2)

    dchal_p4_after = dchal_show_queuing(
        dut, "Step 4: after traffic", egress)
    dchal_p4_after_stats = parse_dchal_queue_stats(dchal_p4_after)

    q3_tx_delta = (dchal_p4_after_stats.get(3, {}).get('tx_pkts', 0)
                   - dchal_p4_before_stats.get(3, {}).get('tx_pkts', 0))
    q3_wred_delta = (dchal_p4_after_stats.get(3, {}).get('wred_drop_pkts', 0)
                     - dchal_p4_before_stats.get(3, {}).get('wred_drop_pkts', 0))
    st.log("  DCHAL Q3 Tx delta: {}, WRED drop delta: {}".format(
        q3_tx_delta, q3_wred_delta))

    if q3_wred_delta > 0:
        fail_msgs.append("Step 4: Q3 WRED drops={} at low rate "
                         "(expected 0)".format(q3_wred_delta))

    try:
        tg.tg_traffic_config(mode='remove',
                             stream_id=stream_p4.get('stream_id'))
    except Exception:
        pass

    # Step 5: High-rate fan-in traffic to queue 3 for WRED congestion
    num_tx_ports = 2 if has_ingress_b else 1
    total_pct = tg_stream_rate_pct * num_tx_ports
    st.log("Step 5: High-rate fan-in traffic targeting Q3 only")
    st.log("  Rate: {} stream(s) x {:.1f}% = {:.0f}% of egress capacity "
           "-> {:.0f}% oversubscription".format(
               num_tx_ports, tg_stream_rate_pct, total_pct, total_pct - 100))

    st.show(dut, "show arp {}".format(IXIA_EGRESS_IP), skip_tmpl=True)

    dchal_p5_before = dchal_show_queuing(
        dut, "Step 5: before traffic", egress)
    dchal_p5_before_stats = parse_dchal_queue_stats(dchal_p5_before)

    tg.tg_traffic_control(action='clear_stats')

    stream_handles_p5 = []
    dscp_q3 = QUEUE_TO_DSCP[3]
    ports = [(tg_ph['ingress_a'], IXIA_INGRESS_A_IP, mac_a)]
    if has_ingress_b:
        ports.append((tg_ph['ingress_b'], IXIA_INGRESS_B_IP, mac_b))
    for ph, src_ip, dst_mac in ports:
        result = tg.tg_traffic_config(
            mode='create',
            port_handle=ph,
            l3_protocol='ipv4',
            ip_src_addr=src_ip,
            ip_dst_addr=IXIA_EGRESS_IP,
            mac_dst=dst_mac,
            ip_dscp=dscp_q3,
            frame_size=PKT_SIZE,
            rate_percent=tg_stream_rate_pct,
            transmit_mode='continuous',
        )
        stream_handles_p5.append(result)

    st.log("  Starting congested traffic for {} seconds ...".format(
        CONGESTION_DURATION))
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run', max_wait_timer=30)

    mid_traffic_wait = 3
    st.wait(mid_traffic_wait)

    dchal_p5_mid = dchal_show_queuing(
        dut, "Step 5: mid-traffic (live congestion)", egress)
    dchal_p5_mid_stats = parse_dchal_queue_stats(dchal_p5_mid)

    q3_mid_depth = dchal_p5_mid_stats.get(3, {}).get('q_depth_bytes', 0)
    green_min = step3_baseline['WRED_PROFILE']['AZURE_LOSSY'].get(
        'green_min_threshold', '0')
    green_max = step3_baseline['WRED_PROFILE']['AZURE_LOSSY'].get(
        'green_max_threshold', '0')
    st.log("  Step 5 mid-traffic: Q3 depth = {} bytes "
           "(green_min={}, green_max={})".format(
               q3_mid_depth, green_min, green_max))
    if q3_mid_depth >= int(green_max):
        st.log("  Step 5 mid-traffic: Q3 depth ABOVE green_max_threshold "
               "-> 100% drop zone (tail drop)")
    elif q3_mid_depth >= int(green_min):
        st.log("  Step 5 mid-traffic: Q3 depth between thresholds "
               "-> WRED probabilistic drop zone")
    else:
        st.log("  Step 5 mid-traffic: Q3 depth BELOW green_min_threshold "
               "-> no WRED drops expected at this instant")

    remaining_wait = CONGESTION_DURATION - mid_traffic_wait
    if remaining_wait > 0:
        st.wait(remaining_wait)

    tg.tg_traffic_control(action='stop', max_wait_timer=30)
    st.wait(2)

    dchal_p5_after = dchal_show_queuing(
        dut, "Step 5: after traffic (queues drained)", egress)
    dchal_p5_after_stats = parse_dchal_queue_stats(dchal_p5_after)

    st.log("  Step 5: Q3 counter analysis (after - before)")
    q3_tx_delta = (dchal_p5_after_stats.get(3, {}).get('tx_pkts', 0)
                   - dchal_p5_before_stats.get(3, {}).get('tx_pkts', 0))
    q3_wred_delta = (dchal_p5_after_stats.get(3, {}).get('wred_drop_pkts', 0)
                     - dchal_p5_before_stats.get(3, {}).get('wred_drop_pkts', 0))
    st.log("    Q3 Tx delta:        {}".format(q3_tx_delta))
    st.log("    Q3 WRED drop delta: {}".format(q3_wred_delta))
    if q3_tx_delta > 0:
        drop_pct = (q3_wred_delta / float(q3_tx_delta)) * 100
        st.log("    Q3 WRED drop rate:  {:.2f}%".format(drop_pct))

    if q3_wred_delta > 0:
        st.log("  Step 5 PASS: DCHAL confirms {} WRED drops on Q3".format(
            q3_wred_delta))
    else:
        fail_msgs.append("Step 5: Q3 WRED drops=0 despite {}% into Q3 "
                         "(egress limited to {}G)".format(
                             total_pct, egress_speed_mbps / 1000))

    for sh in stream_handles_p5:
        try:
            tg.tg_traffic_config(mode='remove',
                                 stream_id=sh.get('stream_id'))
        except Exception:
            pass

    # Step 6: Restore QoS baseline
    st.log("Step 6: Restoring QoS baseline via config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)

    verify_wred_profile(dut, fail_msgs)
    verify_scheduler_profiles(dut, fail_msgs)
    verify_queue_bindings(dut, egress, fail_msgs)

    # ── Verdict ──────────────────────────────────────────────────────────
    if fail_msgs:
        st.report_fail('msg', '; '.join(fail_msgs))
    else:
        st.report_pass(
            'msg',
            'WRED drop probability verified: gdrop 200 rejected, '
            'gdrop 100 accepted, zero drops at low rate, '
            'WRED drops confirmed under fan-in congestion')
