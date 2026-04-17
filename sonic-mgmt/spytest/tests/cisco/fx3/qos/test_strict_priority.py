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
FX3 QoS Strict Priority Tests — verify STRICT scheduler queues with PIR enforcement.

Topology is auto-detected by setup_topo_common (from fx3_qos_helpers):
  ixia      -- D1T1:3.  2 ingress + 1 egress, all IXIA on DUT1.
  peer_link -- D1T1:2 + D1D2:1 + D2T1:1.  Egress is the peer link to DUT2.
  breakout  -- D1T1:1 + D1D2:1 + D2T1:1.  1 ingress, 4x25G breakout egress.

Test matrix (for each frame size and PIR value):
  - Two streams of the same high TC  (both at STRICT queue 6)
  - Two streams of different TCs      (high=7, low=6 — priority preemption)
  - Two streams of the same low TC   (both at STRICT queue 7)

Each case verifies that actual packet loss matches the theoretical expectation
within tolerance, given the configured PIR and available egress bandwidth.
"""

import pytest

from fx3_qos_helpers import (
    setup_topo_common,
    IXIA_INGRESS_A_IP, IXIA_INGRESS_B_IP, IXIA_EGRESS_IP,
    get_dut_mac, parse_speed_to_mbps,
    clear_dut_counters, deploy_dchal_helper,
    get_dchal_queue_counters, log_queue_counters,
)

from spytest import st, tgapi


# ── Test parameters (previously loaded from sp_input_short.json2) ─────────
# Traffic classes under test (STRICT queues on FX3)
TC_PAIR = [6, 7]

# DSCP values that map to each queue under the default AZURE dscp_to_tc_map
QUEUE_TO_DSCP = {
    0: 0, 1: 6, 2: 2, 3: 3, 4: 4, 5: 46, 6: 48, 7: 49,
}

# PIR values as percent of egress line rate
PIRS = [60]

# Stream rate pairs as percent of egress line rate: [stream_high%, stream_low%]
STREAM_RATES = [[40, 40], [80, 20], [80, 80]]

# Frame sizes to test
FRAME_SIZES = [1350, 8192]

# Traffic duration in seconds
TRAFFIC_DURATION = 45

# Loss deviation tolerance (percent) — within this, result is PASS
LOSS_TOLERANCE = 5.0

# Extended tolerance — within this, result is PASS with warning
LOSS_TOLERANCE_WARN = 18.0


# ── Module state ─────────────────────────────────────────────────────────
dut = None
tg = None
tg_ph = {}
port_info = {}
port_speeds = {}       # {'ingress_a': 100, 'egress': 25} — Gbps
tb_vars = None
topo_mode = 'ixia'
egress_speed_gbps = 100
pass_ctr = 0
fail_ctr = 0

# IXIA IPs keyed by role for stream creation
IXIA_IPV4 = {
    'ingress_a': IXIA_INGRESS_A_IP,
    'ingress_b': IXIA_INGRESS_B_IP,
    'egress':    IXIA_EGRESS_IP,
}


# ── Fixture ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Set up DUT L3, IXIA interfaces, QoS baseline via setup_topo_common."""
    global dut, tg, tg_ph, port_info, tb_vars, port_speeds
    global topo_mode, egress_speed_gbps

    for result in setup_topo_common(tgapi, target_queue=TC_PAIR[0]):
        dut = result['dut']
        tg = result['tg']
        tg_ph = result['tg_ph']
        port_info = result['port_info']
        tb_vars = result['tb_vars']
        topo_mode = result['mode']

        raw_speeds = result['port_speeds']
        port_speeds = {}
        for role, spd_str in raw_speeds.items():
            mbps = parse_speed_to_mbps(spd_str)
            port_speeds[role] = mbps // 1000 if mbps else 100

        egress_speed_gbps = port_speeds.get('egress', 100)

        deploy_dchal_helper(dut)

        st.log("setup_topo: mode={}, egress_speed={}G, port_info={}".format(
            topo_mode, egress_speed_gbps, port_info))
        yield


# ── Helpers ──────────────────────────────────────────────────────────────

def gbps_to_scheduler_rate(gbps):
    """Convert Gbps to bytes/sec for SONiC SCHEDULER CIR/PIR (SAI_METER_TYPE_BYTES)."""
    return int(gbps * 125000000)


def report_pass_or_fail(gbps, avail, loss, s_info, pir, frame_size):
    """Compare actual loss against theoretical expectation.

    gbps:  total stream rate in Gbps (sum if same-TC pair)
    avail: available bandwidth in Gbps for this stream
    loss:  actual loss percent from queue counters (-1 means no data)
    s_info: formatted info string for logging
    """
    global pass_ctr, fail_ctr

    info1 = 'PIR(gbps) {:.2f} Frame Len {} '.format(pir, frame_size)

    if loss < 0:
        st.log('FAIL: ' + info1 + s_info +
               ' (DCHAL returned no queue data — cannot compute loss)')
        fail_ctr += 1
        return

    diff = gbps - avail
    if diff <= 0:
        expected_loss_percnt = 0
    else:
        expected_loss_percnt = diff * 100.0 / gbps
    delta = loss - expected_loss_percnt
    if delta <= 0:
        delta_percnt = 0
    elif expected_loss_percnt == 0:
        delta_percnt = delta
    else:
        delta_percnt = delta * 100.0 / expected_loss_percnt

    if delta_percnt <= LOSS_TOLERANCE:
        st.log('PASS: ' + info1 + s_info + ' Exp Loss% {:.2f}'.format(
            expected_loss_percnt))
        pass_ctr += 1
    elif delta_percnt <= LOSS_TOLERANCE_WARN:
        st.log('PASS: ' + info1 + s_info + ' Exp Loss% {:.2f}'.format(
            expected_loss_percnt))
        st.banner('Warning: delta % is {:.2f}'.format(delta_percnt))
        pass_ctr += 1
    else:
        st.log('FAIL: ' + info1 + s_info + ' Exp Loss% {:.2f}'.format(
            expected_loss_percnt))
        fail_ctr += 1


def run_traffic_test(rate_pair_gbps, tc_pair, frame_size, pir_gbps):
    """Send 2 STRICT-priority streams and validate loss via DUT queue counters.

    In breakout mode with a single ingress port, both streams are sent from
    the same port with different DSCP values.  The DUT queues them into
    separate STRICT queues based on DSCP-to-TC mapping.
    """
    if tc_pair[0] < tc_pair[1]:
        high, low = 1, 0
    else:
        high, low = 0, 1

    ingress_roles = sorted(k for k in port_info if k != 'egress')
    ingress_speed = port_speeds.get(ingress_roles[0], 100)
    router_mac = get_dut_mac(dut, port_info[ingress_roles[0]])
    egress_intf = port_info['egress']

    dscp_high = QUEUE_TO_DSCP[tc_pair[high]]
    dscp_low = QUEUE_TO_DSCP[tc_pair[low]]

    rate_pct_high = rate_pair_gbps[high] * 100.0 / ingress_speed
    rate_pct_low = rate_pair_gbps[low] * 100.0 / ingress_speed

    if len(ingress_roles) >= 2:
        ph_high = tg_ph[ingress_roles[0]]
        ph_low = tg_ph[ingress_roles[1]]
        src_ip_high = IXIA_IPV4.get(ingress_roles[0], IXIA_INGRESS_A_IP)
        src_ip_low = IXIA_IPV4.get(ingress_roles[1], IXIA_INGRESS_B_IP)
        mac_high = get_dut_mac(dut, port_info[ingress_roles[0]])
        mac_low = get_dut_mac(dut, port_info[ingress_roles[1]])
    else:
        ph_high = tg_ph[ingress_roles[0]]
        ph_low = tg_ph[ingress_roles[0]]
        src_ip_high = IXIA_IPV4.get(ingress_roles[0], IXIA_INGRESS_A_IP)
        src_ip_low = src_ip_high
        mac_high = router_mac
        mac_low = router_mac

    st.log("  Stream HIGH: TC={} DSCP={} rate={:.2f}G ({:.1f}%) src={} frame={}".format(
        tc_pair[high], dscp_high, rate_pair_gbps[high], rate_pct_high,
        src_ip_high, frame_size))
    st.log("  Stream LOW:  TC={} DSCP={} rate={:.2f}G ({:.1f}%) src={} frame={}".format(
        tc_pair[low], dscp_low, rate_pair_gbps[low], rate_pct_low,
        src_ip_low, frame_size))

    clear_dut_counters(dut)
    tg.tg_traffic_control(action='clear_stats')

    q_before = get_dchal_queue_counters(dut, egress_intf, "SP before")

    res_high = tg.tg_traffic_config(
        mode='create', port_handle=ph_high,
        l3_protocol='ipv4', l4_protocol='icmp',
        ip_src_addr=src_ip_high,
        ip_dst_addr=IXIA_EGRESS_IP,
        mac_dst=mac_high,
        ip_dscp=dscp_high,
        ip_ttl=64,
        frame_size=frame_size,
        rate_percent=rate_pct_high,
        transmit_mode='continuous',
        high_speed_result_analysis=0,
    )
    res_low = tg.tg_traffic_config(
        mode='create', port_handle=ph_low,
        l3_protocol='ipv4', l4_protocol='icmp',
        ip_src_addr=src_ip_low,
        ip_dst_addr=IXIA_EGRESS_IP,
        mac_dst=mac_low,
        ip_dscp=dscp_low,
        ip_ttl=64,
        frame_size=frame_size,
        rate_percent=rate_pct_low,
        transmit_mode='continuous',
        high_speed_result_analysis=0,
    )

    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    st.wait(TRAFFIC_DURATION)
    tg.tg_traffic_control(action='stop')
    st.wait(5)

    q_after = get_dchal_queue_counters(dut, egress_intf, "SP after")

    st.log("  Queue counters BEFORE:")
    log_queue_counters(q_before)
    st.log("  Queue counters AFTER:")
    log_queue_counters(q_after)

    for sh in [res_high, res_low]:
        try:
            tg.tg_traffic_config(mode='remove', stream_id=sh.get('stream_id'))
        except Exception:
            pass

    dchal_empty = (not q_before) and (not q_after)
    if dchal_empty:
        st.error("DCHAL returned no queue data — loss results are unreliable. "
                 "Verify deploy_dchal_helper() ran and /tmp/dchal_qi.py exists "
                 "inside the syncd container.")

    def _queue_loss_pct(qi):
        tx = (q_after.get(qi, {}).get('pkts', 0)
              - q_before.get(qi, {}).get('pkts', 0))
        drops = (q_after.get(qi, {}).get('drop_pkts', 0)
                 - q_before.get(qi, {}).get('drop_pkts', 0))
        total = tx + drops
        if total <= 0:
            return -1.0 if dchal_empty else 0.0
        return drops * 100.0 / total

    if tc_pair[high] == tc_pair[low]:
        qi = tc_pair[high]
        loss_percent = _queue_loss_pct(qi)
        total_gbps = rate_pair_gbps[0] + rate_pair_gbps[1]
        s_info = 'TC {} Streams(gbps) ({:.2f},{:.2f}) Loss% {:.2f}'.format(
            qi, rate_pair_gbps[0], rate_pair_gbps[1], loss_percent)
        report_pass_or_fail(total_gbps, pir_gbps, loss_percent, s_info,
                            pir_gbps, frame_size)
    else:
        loss_high = _queue_loss_pct(tc_pair[high])
        loss_low = _queue_loss_pct(tc_pair[low])

        s_info = 'TC {} Stream(gbps) {:.2f} Loss% {:.2f}'.format(
            tc_pair[high], rate_pair_gbps[high], loss_high)
        report_pass_or_fail(rate_pair_gbps[high], pir_gbps, loss_high, s_info,
                            pir_gbps, frame_size)

        remaining_gbps = egress_speed_gbps - min(
            rate_pair_gbps[high], pir_gbps)
        if remaining_gbps > pir_gbps:
            remaining_gbps = pir_gbps

        s_info = 'TC {} Stream(gbps) {:.2f} Loss% {:.2f}'.format(
            tc_pair[low], rate_pair_gbps[low], loss_low)
        report_pass_or_fail(rate_pair_gbps[low], remaining_gbps, loss_low,
                            s_info, pir_gbps, frame_size)


def apply_pir(pir_pct):
    """Configure STRICT scheduler profiles at the given PIR (percent of egress).

    Reloads QoS baseline, then adds STRICT scheduler entries for both TCs
    under test and binds them to the egress interface queues.
    """
    pir_gbps = pir_pct * egress_speed_gbps / 100.0
    pir_bps = str(gbps_to_scheduler_rate(pir_gbps))
    egress_intf = port_info['egress']

    st.config(dut, 'config qos reload', skip_error_check=True)

    for tc in TC_PAIR:
        sched_name = 'sp_tc{}_{}'.format(tc, pir_bps)
        st.config(dut,
                  'sonic-db-cli CONFIG_DB HSET "SCHEDULER|{}" '
                  '"type" "STRICT" "meter_type" "bytes" '
                  '"cir" "{}" "pir" "{}"'.format(
                      sched_name, pir_bps, pir_bps),
                  skip_error_check=True)
        st.config(dut,
                  'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|{}" '
                  '"scheduler" "{}"'.format(egress_intf, tc, sched_name),
                  skip_error_check=True)

    st.wait(5)
    return pir_gbps


# ── Test ─────────────────────────────────────────────────────────────────

def test_one_dev_strict_priority(setup_topo):
    """Verify STRICT scheduler queues enforce PIR across TC combinations.

    Test matrix: for each (tc_pair, pir, stream_rate_pair, frame_size),
    send two concurrent streams and validate loss against theoretical
    expectation.
    """
    global pass_ctr, fail_ctr

    st.banner('test_one_dev_strict_priority STARTED (mode={})'.format(topo_mode))
    pass_ctr = 0
    fail_ctr = 0

    tc0 = TC_PAIR[0]
    tc1 = TC_PAIR[1]

    for tc_pair in [(tc0, tc0), (tc0, tc1), (tc1, tc1)]:
        for pir_pct in PIRS:
            pir_gbps = apply_pir(pir_pct)

            # Convert stream rate percentages to absolute Gbps
            gbps_table = []
            for rate_pair in STREAM_RATES:
                gbps_table.append((
                    int(rate_pair[0]) * egress_speed_gbps / 100.0,
                    int(rate_pair[1]) * egress_speed_gbps / 100.0,
                ))

            for gbps_pair in gbps_table:
                for frame_size in FRAME_SIZES:
                    st.banner(
                        'SP: TC=({},{}) PIR={:.1f}G rates=({:.1f},{:.1f})G '
                        'frame={}'.format(
                            tc_pair[0], tc_pair[1], pir_gbps,
                            gbps_pair[0], gbps_pair[1], frame_size))
                    run_traffic_test(gbps_pair, tc_pair, int(frame_size),
                                     pir_gbps)

    st.config(dut, 'config qos clear', skip_error_check=True)

    final_msg = 'Test Cases: Passed={} Failed={}'.format(pass_ctr, fail_ctr)
    if fail_ctr > 0:
        st.report_fail('msg', final_msg)
    else:
        st.report_pass('msg', final_msg)
