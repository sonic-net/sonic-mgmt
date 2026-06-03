"""
Test: Strict Priority (SP) and Deficit Weighted Round Robin (DWRR) scheduling.

Ported from OCI test_sp_dwrr.py to tortuga infrastructure.
Uses IPv4 with 2-spine/2-leaf topology (single leaf D3 under test).

Phase 1 - SP only:
  Two streams of the same high-priority TC are sent to an egress port
  with a configured PIR (policer). Verify total egress rate is capped at PIR.

Phase 2 - SP + DWRR:
  Add lossless (TC3) and best-effort (TC5) streams to the existing SP traffic.
  Verify:
    - TC3 (lossless) has zero packet loss (PFC backpressure)
    - SP TC stays at its PIR
    - TC5 (best-effort / DWRR) gets the remaining bandwidth
  Run two iterations swapping TC3 and TC5 input rates.
"""

import os
import sys
import pytest
import qos_test_utils as common_util
import traffic_stream_ixia_api as stream_api
import qos_test_utils

from spytest import st, tgapi, SpyTestDict

TOLERANCE_PERCENT = 4.0
TRAFFIC_RUN_TIME = 30
LEAF = 'D3'

# TC assignments
TC_SP = 7       # Strict priority TC
TC_LOSSLESS = 3 # Lossless TC (PFC-enabled)
TC_BE = 5       # Best-effort / DWRR TC

# All TCs used in this test that need lossless PG mapping
LOSSLESS_TCS = [TC_LOSSLESS]




@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tb_dict, vars, test_info

    st.log("setup topology Started")

    tb_dict = st.ensure_min_topology("D1D3:2", "D1D4:2", "D2D3:1", "D2D4:1",
                                     "D3T1:3", "D4T1:1")
    vars = st.get_testbed_vars()

    test_info = SpyTestDict()
    test_info['leaf'] = LEAF
    test_info['dut'] = tb_dict[LEAF]
    test_info['src'] = ['T1' + LEAF + 'P1', 'T1' + LEAF + 'P2']
    test_info['src_dut_if1'] = tb_dict[LEAF + 'T1P1']
    test_info['src_dut_if2'] = tb_dict[LEAF + 'T1P2']
    test_info['dst'] = 'T1' + LEAF + 'P3'
    test_info['dut_if'] = tb_dict[LEAF + 'T1P3']
    test_info['if_speed'] = common_util.get_if_speed(test_info['dut'],
                                                     test_info['dut_if'])

    qos_test_utils.cleanup_config(test_info['dut'])
    stream_api.init_qos_on_dut(test_info['dut'])
    stream_api.config_one_leaf(tb_dict, test_info)
    st.log("setup topology Done")

    yield

def configure_scheduler(tc, pir_gbps):
    """Configure a strict-priority scheduler for a TC on the egress interface."""
    pir_bytes = stream_api.gbps_to_bytes(pir_gbps)
    name = f'{test_info["dst"]}_{tc}{pir_bytes}'
    cfg = (f'config scheduler add --type STRICT --cir {pir_bytes} '
           f'--pir {pir_bytes} {name}\n'
           f'config queue queue-list update --scheduler {name} '
           f'{test_info["dut_if"]} {tc}\n')
    st.config(test_info['dut'], cfg, skip_tmpl=True)


def create_stream(src_port, dst_port, tc, gbps):
    """Create a traffic stream at the given rate."""
    frame_size = 1350
    pps = stream_api.gbps_to_pps(gbps, frame_size)
    s = stream_api.create_traffic_stream(tb_dict, src_port, dst_port,
                                         frame_size, pps, tc)
    if s is None:
        st.error(f'Stream creation failed: {src_port} -> {dst_port} TC{tc}')
    return s


def get_rx_gbps(item_stats, stream):
    """Extract Rx rate in Gbps from traffic stats for a stream."""
    sid = stream['stream_id']
    if sid not in item_stats:
        st.error(f'Stream {sid} not found in stats. Available: {list(item_stats.keys())}')
        return 0.0
    bits = float(item_stats[sid]['rx'].get('total_pkt_bit_rate', 0))
    return bits / 1e9


def get_loss_percent(item_stats, stream):
    """Extract loss percent from traffic stats for a stream."""
    sid = stream['stream_id']
    if sid not in item_stats:
        st.error(f'Stream {sid} not found in stats. Available: {list(item_stats.keys())}')
        return 100.0
    return float(item_stats[sid]['rx']['loss_percent'])


def test_sp_and_dwrr():
    """
    Test strict priority policing and DWRR bandwidth sharing.

    Phase 1: Two TC7 streams at 5% line rate each, PIR = 8% line rate.
             Expect total egress capped at PIR.

    Phase 2: Add TC3 (lossless, PFC) and TC5 (best-effort) streams.
             Expect TC3 zero loss, TC7 capped at PIR, TC5 gets remainder.
             Run two iterations swapping TC3/TC5 input rates.
    """
    dut = test_info['dut']
    if_speed = test_info['if_speed']
    sp_pir_gbps = 0.08 * if_speed  # 8% of line rate as PIR for SP TC

    st.config(dut, 'sonic-clear queuecounters', skip_tmpl=True)

    # Configure scheduler for TC7 with PIR
    configure_scheduler(TC_SP, sp_pir_gbps)

    # =========================================================================
    # Phase 1: Strict Priority only - two TC7 streams
    # =========================================================================
    stream_gbps = 0.05 * if_speed  # 5% of line rate per TC7 stream
    st.banner(f'Phase 1: Strict Priority - 2x TC7 streams at {stream_gbps:.0f} Gbps, PIR={sp_pir_gbps:.0f} Gbps')
    tc7_s1 = create_stream(test_info['src'][0], test_info['dst'],
                           TC_SP, stream_gbps)
    tc7_s2 = create_stream(test_info['src'][1], test_info['dst'],
                           TC_SP, stream_gbps)
    if not all([tc7_s1, tc7_s2]):
        st.report_fail('msg', 'Failed to create traffic streams')

    stream_api.start_traffic_stream()
    st.wait(TRAFFIC_RUN_TIME)
    stats = stream_api.collect_traffic_stream_stats()
    stream_api.stop_traffic_stream()
    st.show(dut, f'show queue counters {test_info["dut_if"]}', skip_tmpl=True)

    if 'traffic_item' not in stats:
        st.report_fail('msg', 'Failed to get traffic stats for Phase 1')

    item_stats = stats['traffic_item']
    total_rx = get_rx_gbps(item_stats, tc7_s1) + get_rx_gbps(item_stats, tc7_s2)
    phase1_pass = True
    if not qos_test_utils.validate_value(total_rx, sp_pir_gbps,
                                         TOLERANCE_PERCENT):
        st.error(f'Phase 1 FAIL: TC7 total expected ~{sp_pir_gbps:.1f} Gbps, '
                 f'got {total_rx:.2f} Gbps')
        phase1_pass = False
    else:
        st.log(f'Phase 1 PASS: TC7 total Rx {total_rx:.2f} Gbps '
               f'(PIR {sp_pir_gbps:.1f} Gbps)')

    # TC7 streams are kept alive for reuse in Phase 2.
    # All streams are created once; only rates are modified per iteration.

    # =========================================================================
    # Phase 2: SP + DWRR - add TC3 (lossless) and TC5 (best-effort)
    # =========================================================================
    st.banner("Phase 2: SP + DWRR - TC7 + TC3 (lossless) + TC5 (best-effort)")
    initial_tc3_gbps = 0.30 * if_speed
    initial_tc5_gbps = 0.40 * if_speed
    tc3_s1 = create_stream(test_info['src'][0], test_info['dst'],
                           TC_LOSSLESS, initial_tc3_gbps)
    tc3_s2 = create_stream(test_info['src'][1], test_info['dst'],
                           TC_LOSSLESS, initial_tc3_gbps)
    tc5_s1 = create_stream(test_info['src'][0], test_info['dst'],
                           TC_BE, initial_tc5_gbps)
    tc5_s2 = create_stream(test_info['src'][1], test_info['dst'],
                           TC_BE, initial_tc5_gbps)

    # Rate pairs for 2 iterations: (tc3_rate, tc5_rate) as percent of line rate
    rate_pairs = [(0.30, 0.40), (0.40, 0.30)]

    pass_ctr = 0
    for iteration, (tc3_pct, tc5_pct) in enumerate(rate_pairs):
        tc3_gbps = tc3_pct * if_speed
        tc5_gbps = tc5_pct * if_speed

        st.banner(f'Iteration {iteration + 1}: TC3=2x{tc3_gbps:.0f}G, '
                  f'TC5=2x{tc5_gbps:.0f}G, TC7=2x{stream_gbps:.0f}G')

        # Modify TC3/TC5 rates for this iteration
        stream_api.modify_stream_rate(tc3_s1, tc3_gbps)
        stream_api.modify_stream_rate(tc3_s2, tc3_gbps)
        stream_api.modify_stream_rate(tc5_s1, tc5_gbps)
        stream_api.modify_stream_rate(tc5_s2, tc5_gbps)

        # Snapshot PFC Tx counters before traffic
        pre_pfc1 = common_util.get_pfc_tx_count(dut, test_info['src_dut_if1'],
                                                 TC_LOSSLESS)
        pre_pfc2 = common_util.get_pfc_tx_count(dut, test_info['src_dut_if2'],
                                                 TC_LOSSLESS)

        st.config(dut, 'sonic-clear queuecounters', skip_tmpl=True)
        stream_api.clear_all_stats()
        stream_api.start_traffic_stream()
        st.wait(TRAFFIC_RUN_TIME // 2)
        qos_test_utils.dump_counters(
            dut,
            [test_info['src_dut_if1'], test_info['src_dut_if2'], test_info['dut_if']])
        st.wait(TRAFFIC_RUN_TIME - TRAFFIC_RUN_TIME // 2)
        stats = stream_api.collect_traffic_stream_stats()
        stream_api.stop_traffic_stream()
        st.show(dut, f'show queue counters {test_info["dut_if"]}', skip_tmpl=True)

        if 'traffic_item' not in stats:
            st.error('Failed to get traffic stats')
            continue

        item_stats = stats['traffic_item']
        rc = 0
        diag = ''

        # Check TC3 (lossless) - expect zero loss
        loss3_1 = get_loss_percent(item_stats, tc3_s1)
        loss3_2 = get_loss_percent(item_stats, tc3_s2)
        tc3_rx = get_rx_gbps(item_stats, tc3_s1) + get_rx_gbps(item_stats, tc3_s2)
        pfc1 = common_util.get_pfc_tx_count(dut, test_info['src_dut_if1'],
                                            TC_LOSSLESS) - pre_pfc1
        pfc2 = common_util.get_pfc_tx_count(dut, test_info['src_dut_if2'],
                                            TC_LOSSLESS) - pre_pfc2
        if not qos_test_utils.validate_value(loss3_1, 0.0, 1.0) or \
           not qos_test_utils.validate_value(loss3_2, 0.0, 1.0):
            diag += (f'[FAIL] TC3: loss too high '
                     f'({loss3_1:.3f}%, {loss3_2:.3f}%) '
                     f'PFC Tx Count: {test_info["src_dut_if1"]}={pfc1} '
                     f'{test_info["src_dut_if2"]}={pfc2} ')
            rc = -1
        else:
            diag += (f'[PASS] TC3: Zero Loss, RX {tc3_rx:.2f} Gbps '
                     f'PFC Tx Count: {test_info["src_dut_if1"]}={pfc1} '
                     f'{test_info["src_dut_if2"]}={pfc2} ')

        # Check TC7 (SP) - expect capped at PIR
        tc7_rx = get_rx_gbps(item_stats, tc7_s1) + get_rx_gbps(item_stats, tc7_s2)
        if not qos_test_utils.validate_value(tc7_rx, sp_pir_gbps,
                                             TOLERANCE_PERCENT):
            diag += (f'[FAIL] TC7: expected ~{sp_pir_gbps:.1f} Gbps, '
                     f'got {tc7_rx:.2f} Gbps ')
            rc = -1
        else:
            diag += f'[PASS] TC7: {tc7_rx:.2f} Gbps (PIR OK) '

        # Check TC5 (BE/DWRR) - expect remaining bandwidth
        remaining_bw = if_speed - (tc3_rx + tc7_rx)
        tc5_rx = get_rx_gbps(item_stats, tc5_s1) + get_rx_gbps(item_stats, tc5_s2)
        if not qos_test_utils.validate_value(tc5_rx, remaining_bw,
                                             TOLERANCE_PERCENT):
            diag += (f'[FAIL] TC5: expected ~{remaining_bw:.2f} Gbps, '
                     f'got {tc5_rx:.2f} Gbps')
            rc = -1
        else:
            diag += (f'[PASS] TC5: {tc5_rx:.2f} Gbps, '
                     f'TC5/TC3 Ratio: {(tc5_rx / tc3_rx):.2f}'
                     if tc3_rx > 0 else f'[PASS] TC5: {tc5_rx:.2f} Gbps')

        if rc == 0:
            pass_ctr += 1
            st.log(f'Iteration {iteration + 1}: PASS - {diag}')
        else:
            st.error(f'Iteration {iteration + 1}: FAIL - {diag}')

    # Clean up all streams
    stream_api.delete_traffic_stream(tc7_s1)
    stream_api.delete_traffic_stream(tc7_s2)
    stream_api.delete_traffic_stream(tc3_s1)
    stream_api.delete_traffic_stream(tc3_s2)
    stream_api.delete_traffic_stream(tc5_s1)
    stream_api.delete_traffic_stream(tc5_s2)

    # Final verdict
    total_checks = 1 + len(rate_pairs)  # Phase 1 + Phase 2 iterations
    pass_total = (1 if phase1_pass else 0) + pass_ctr
    msg = f'SP+DWRR Test: Passed={pass_total} Failed={total_checks - pass_total}'
    if pass_total == total_checks:
        st.report_pass('msg', msg)
    else:
        st.report_fail('msg', msg)
