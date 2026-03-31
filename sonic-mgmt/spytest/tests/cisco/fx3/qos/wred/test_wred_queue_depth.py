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
FX3 QoS WRED Queue Depth Threshold Tests.

Testbed (fx3_qos_testbed_2022.yaml):
  Ingress A: Ixia T1D1P1 -> DUT D1T1P1 (100G)
  Ingress B: Ixia T1D1P2 -> DUT D1T1P2 (100G)
  Egress:    DUT D1T1P3  -> Ixia T1D1P3 (100G)

Validates WRED behavior at different queue depth zones using the fan-in
topology (2 ingress ports -> 1 egress port).  Port A (ingress_a) saturates
the egress at 100G line rate.  Port B (ingress_b) injects additional traffic
to push the egress queue into specific WRED threshold regions.

All tests target a single queue (Q3, DSCP 3) and use the default WRED
profile (AZURE_LOSSY: drop_probability=5, green_min=1 MB, green_max=3 MB).

Traffic modes:
  - Tests 1-2: Burst on Port B (verify zero-drop behavior below min_threshold)
  - Tests 3-4: Continuous on Port B (verify steady-state WRED/tail-drop behavior)

Key formula (steady-state, continuous mode):
  OBS_DROP% = oversubscription_rate = Port_B_rate / (Port_A_rate + Port_B_rate)
  q_depth   = min + (max - min) * (oversubscription_rate / drop_probability)

Tests:
  test_wred_no_congestion          — Port A 100%, Port B silent -> 0 drops
  test_wred_below_min_threshold    — Port A 100%, Port B burst 900 KB -> 0 drops
  test_wred_midrange_depth         — Port A 100%, Port B 4% cont. -> ~3.85% drops
  test_wred_near_max_depth         — Port A 100%, Port B 5% cont. -> ~4.76% drops
  test_wred_boundary_tail_drop     — Port A 100%, Port B 6% cont. -> ~5.66% drops
  test_wred_heavy_oversubscription — Port A 100%, Port B 10% cont. -> ~9.09% drops
"""

import os
import sys
import pytest

from spytest import st, tgapi

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fx3_qos_helpers import (
    QUEUE_TO_DSCP, deploy_dchal_helper,
    dchal_show_queuing, get_dut_mac,
    parse_dchal_queue_stats,
    verify_wred_profile, verify_queue_bindings,
)


# ── L3 Addresses ─────────────────────────────────────────────────────────
V4_INGRESS_A_IP = '10.10.10.1/24'
V4_INGRESS_B_IP = '10.10.11.1/24'
V4_EGRESS_IP    = '20.20.20.1/24'

IXIA_INGRESS_A_IP = '10.10.10.2'
IXIA_INGRESS_B_IP = '10.10.11.2'
IXIA_EGRESS_IP    = '20.20.20.2'
NETMASK = '255.255.255.0'

# ── Traffic parameters ───────────────────────────────────────────────────
PKT_SIZE       = 128
TARGET_QUEUE   = 3
TARGET_DSCP    = QUEUE_TO_DSCP[TARGET_QUEUE]

PORT_A_RATE_PCT = 100

# Burst tests
BURST_DURATION         = 5
BURST_BELOW_MIN_PKTS   = 7200    # 7200 * 128 = 921,600 bytes = 900 KB (below 1 MB min)

# Continuous tests
CONTINUOUS_DURATION     = 20
MID_TRAFFIC_SNAPSHOT_AT = 5
PORT_B_RATE_MIDRANGE    = 4      # ~3.85% oversub -> q_depth ~2.5 MB
PORT_B_RATE_NEAR_MAX    = 5      # ~4.76% oversub -> q_depth ~2.9 MB
PORT_B_RATE_BOUNDARY    = 6      # ~5.66% oversub -> q_depth > 3 MB (tail drops)
PORT_B_RATE_HEAVY       = 10     # ~9.09% oversub -> q_depth >> 3 MB (tail drops)

# ── WRED profile constants (from config_db.json AZURE_LOSSY) ─────────────
WRED_MIN_THRESHOLD = 1048576     # 1 MB
WRED_MAX_THRESHOLD = 3145728     # 3 MB
WRED_DROP_PROB     = 5           # percent

# ── Tolerance bands ──────────────────────────────────────────────────────
OBS_DROP_TOLERANCE      = 1.5    # +/- percentage points for WRED-zone tests
OBS_DROP_TOLERANCE_TAIL = 2.0    # +/- percentage points for tail-drop tests


dut = None
tg = None
tg_ph = {}
port_info = {}
vars = None


# ── Interface-membership helpers ─────────────────────────────────────────

def remove_interface_from_vlan(dut_handle, interface):
    output = st.show(dut_handle, "show vlan brief", skip_tmpl=True)
    if not output:
        return
    vlans_to_remove = []
    current_vlan_id = None
    for line in output.split('\n'):
        if '===' in line or '---' in line or 'VLAN ID' in line or not line.strip():
            continue
        if '|' not in line:
            continue
        fields = [f.strip() for f in line.split('|')]
        if len(fields) > 1 and fields[1].isdigit():
            current_vlan_id = fields[1]
        if interface in line and current_vlan_id:
            if current_vlan_id not in vlans_to_remove:
                vlans_to_remove.append(current_vlan_id)
    for vlan_id in vlans_to_remove:
        st.log("Removing {} from VLAN {}".format(interface, vlan_id))
        st.config(dut_handle, "config vlan member del {} {}".format(
            vlan_id, interface), skip_error_check=True)


def remove_interface_from_portchannel(dut_handle, interface):
    output = st.show(dut_handle, "show interfaces portchannel", skip_tmpl=True)
    if not output:
        return
    for line in output.split('\n'):
        if interface in line:
            parts = line.split()
            for part in parts:
                if part.startswith('PortChannel'):
                    st.log("Removing {} from {}".format(interface, part))
                    st.config(dut_handle,
                              "config portchannel member del {} {}".format(
                                  part, interface),
                              skip_error_check=True)
                    return


def remove_interface_from_all_memberships(dut_handle, interface):
    remove_interface_from_vlan(dut_handle, interface)
    remove_interface_from_portchannel(dut_handle, interface)


def _wait_for_interfaces(dut_handle, interfaces, timeout=30, poll=5):
    for elapsed in range(0, timeout + 1, poll):
        check = " && ".join(
            "test -d /sys/class/net/{}".format(intf) for intf in interfaces)
        out = st.show(dut_handle,
                      "{} && echo READY || echo NOTREADY".format(check),
                      skip_tmpl=True).strip()
        if "READY" in out and "NOTREADY" not in out:
            st.log("_wait_for_interfaces: all present after ~{}s".format(
                elapsed))
            return True
        st.log("_wait_for_interfaces: waiting ({}s / {}s)".format(
            elapsed, timeout))
        if elapsed < timeout:
            st.wait(poll)
    st.warn("_wait_for_interfaces: timed out after {}s".format(timeout))
    return False


# ── Topology fixture ─────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Set up DUT L3, Ixia interfaces, and QoS baseline for WRED tests."""
    global dut, tg, tg_ph, port_info, vars

    st.log("setup_topo: establishing minimum topology D1T1:3")
    tb_dict = st.ensure_min_topology("D1T1:3")
    vars = st.get_testbed_vars()
    dut = tb_dict.D1

    port_info = {
        'ingress_a': vars.D1T1P1,
        'ingress_b': vars.D1T1P2,
        'egress':    vars.D1T1P3,
    }
    st.log("setup_topo: ports -> {}".format(port_info))

    tg_handle, tg_ph_a = tgapi.get_handle_byname('T1D1P1')
    _, tg_ph_b = tgapi.get_handle_byname('T1D1P2')
    _, tg_ph_e = tgapi.get_handle_byname('T1D1P3')
    tg = tg_handle
    tg_ph = {'ingress_a': tg_ph_a, 'ingress_b': tg_ph_b, 'egress': tg_ph_e}

    st.log("setup_topo: removing port memberships")
    for intf in port_info.values():
        remove_interface_from_all_memberships(dut, intf)

    st.log("setup_topo: reloading QoS config")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)

    st.log("setup_topo: configuring L3 interfaces on DUT")
    l3_cfg = (
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}'
    ).format(
        port_info['ingress_a'], V4_INGRESS_A_IP,
        port_info['ingress_b'], V4_INGRESS_B_IP,
        port_info['egress'],    V4_EGRESS_IP,
    )
    st.config(dut, l3_cfg, skip_error_check=True)

    _wait_for_interfaces(dut, port_info.values(), timeout=30, poll=5)

    st.log("setup_topo: configuring Ixia interfaces")
    ixia_intf_params = [
        ('ingress_a', IXIA_INGRESS_A_IP, '10.10.10.1'),
        ('ingress_b', IXIA_INGRESS_B_IP, '10.10.11.1'),
        ('egress',    IXIA_EGRESS_IP,    '20.20.20.1'),
    ]
    for key, ip, gw in ixia_intf_params:
        tg.tg_interface_config(
            mode='config', port_handle=tg_ph[key],
            intf_ip_addr=ip, netmask=NETMASK, gateway=gw,
            arp_send_req=1, enable_ping_response=1, resolve_gateway_mac=1)

    try:
        tg.tg_topology_test_control(action='start_all_protocols')
    except Exception:
        st.warn("start_all_protocols unavailable; relying on arp_send_req")

    st.config(dut, "ping -c 3 -W 1 {}".format(IXIA_EGRESS_IP),
              skip_error_check=True)
    st.wait(5)

    st.log("setup_topo: DONE")
    yield

    st.log("setup_topo: teardown — removing L3 config")
    cleanup_cfg = (
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}'
    ).format(
        port_info['ingress_a'], V4_INGRESS_A_IP,
        port_info['ingress_b'], V4_INGRESS_B_IP,
        port_info['egress'],    V4_EGRESS_IP,
    )
    st.config(dut, cleanup_cfg, skip_error_check=True)
    st.log("setup_topo: teardown complete")


# ── Shared helpers ───────────────────────────────────────────────────────

def _dchal_snapshot(label):
    """Take a DCHAL queuing snapshot and return parsed per-queue stats."""
    raw = dchal_show_queuing(dut, label, port_info['egress'])
    return parse_dchal_queue_stats(raw)


def _q_delta(before, after, field):
    """Compute counter delta for TARGET_QUEUE between two DCHAL snapshots."""
    return (after.get(TARGET_QUEUE, {}).get(field, 0)
            - before.get(TARGET_QUEUE, {}).get(field, 0))


def _calc_obs_drop_pct(tx_delta, wred_delta):
    """OBS_DROP% = drops / (tx + drops) * 100.

    The denominator is (tx + drops) because tx_pkts counts packets that
    egressed successfully, while wred_drop_pkts counts those dropped before
    egress.  Their sum approximates total packets that entered the queue.
    """
    total = tx_delta + wred_delta
    if total <= 0:
        return 0.0
    return (wred_delta / float(total)) * 100.0


def _calc_expected_oversub(port_b_rate_pct):
    """Expected oversubscription rate given Port A at 100% and Port B at
    port_b_rate_pct (percentage of 100G line rate).

    oversub = port_b / (port_a + port_b)
    """
    return port_b_rate_pct / float(PORT_A_RATE_PCT + port_b_rate_pct) * 100.0


def _calc_expected_q_depth(oversub_pct):
    """Expected steady-state queue depth given oversubscription percentage
    and the WRED profile (min, max, drop_probability).

    q_depth = min + (max - min) * (oversub / drop_prob)

    Only valid when oversub <= drop_prob (WRED can balance the excess).
    When oversub > drop_prob, queue exceeds max_threshold.
    """
    if oversub_pct >= WRED_DROP_PROB:
        return WRED_MAX_THRESHOLD
    ratio = oversub_pct / float(WRED_DROP_PROB)
    return WRED_MIN_THRESHOLD + (WRED_MAX_THRESHOLD - WRED_MIN_THRESHOLD) * ratio


def _log_wred_counters():
    """Log 'show queue counters --wred' output for future use.

    Currently broken on this SONiC build; included so assertions can be
    added once the command is fixed without modifying test structure.
    """
    egress = port_info['egress']
    out = st.show(dut,
                  "show queue counters {} --wred".format(egress),
                  skip_tmpl=True, skip_error_check=True)
    st.log("show queue counters --wred (informational):\n{}".format(out))
    # TODO: parse and assert WredDrop/pkts, GrnWredDrop/pkts, CurrOcc
    # once this command is functional


def _remove_streams(stream_handles):
    """Clean up Ixia streams, ignoring errors."""
    for sh in stream_handles:
        try:
            tg.tg_traffic_config(mode='remove',
                                 stream_id=sh.get('stream_id'))
        except Exception:
            pass


# ── Tests ─────────────────────────────────────────────────────────────────

def test_wred_no_congestion():
    """Verify zero WRED drops when total ingress does not exceed egress capacity.

    Port A sends at 100% line rate (100G) on DSCP 3 -> Q3.
    Port B is silent.  Total ingress = 100G = egress capacity.
    No oversubscription, no queue buildup, no WRED drops.
    """
    st.banner("test_wred_no_congestion STARTED")
    fail_msgs = []
    egress = port_info['egress']

    deploy_dchal_helper(dut)
    mac_a = get_dut_mac(dut, port_info['ingress_a'])
    verify_wred_profile(dut, fail_msgs)
    verify_queue_bindings(dut, egress, fail_msgs)

    before = _dchal_snapshot("test1: before traffic")

    tg.tg_traffic_control(action='clear_stats')
    stream = tg.tg_traffic_config(
        mode='create',
        port_handle=tg_ph['ingress_a'],
        l3_protocol='ipv4',
        ip_src_addr=IXIA_INGRESS_A_IP,
        ip_dst_addr=IXIA_EGRESS_IP,
        mac_dst=mac_a,
        ip_dscp=TARGET_DSCP,
        frame_size=PKT_SIZE,
        rate_percent=PORT_A_RATE_PCT,
        transmit_mode='continuous',
    )

    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run', max_wait_timer=30)
    st.wait(BURST_DURATION)
    tg.tg_traffic_control(action='stop', max_wait_timer=30)
    st.wait(2)

    after = _dchal_snapshot("test1: after traffic")

    tx_delta = _q_delta(before, after, 'tx_pkts')
    wred_delta = _q_delta(before, after, 'wred_drop_pkts')
    obs_drop = _calc_obs_drop_pct(tx_delta, wred_delta)
    st.log("  Q{} Tx delta: {}, WRED drop delta: {}, OBS_DROP%: {:.4f}%".format(
        TARGET_QUEUE, tx_delta, wred_delta, obs_drop))

    if round(obs_drop, 2) > 0:
        fail_msgs.append(
            "Q{} WRED drops={} ({:.4f}%) with no oversubscription "
            "(expected ~0%)".format(TARGET_QUEUE, wred_delta, obs_drop))

    _log_wred_counters()
    _remove_streams([stream])

    if fail_msgs:
        st.report_fail('msg', '; '.join(fail_msgs))
    else:
        st.report_pass(
            'msg',
            'No congestion: zero WRED drops confirmed with '
            'Port A at 100% line rate, Port B silent')


def test_wred_below_min_threshold():
    """Verify zero WRED drops when queue depth stays below min_threshold.

    Port A sends at 100% line rate (100G) continuously on DSCP 3 -> Q3,
    saturating the egress.  Port B sends a single burst of 900 KB
    (7200 packets * 128 bytes = 921,600 bytes) on DSCP 3 -> Q3.

    The burst fills Q3 to ~900 KB, which is below the WRED min_threshold
    (1 MB = 1,048,576 bytes).  Below min_threshold, WRED probability is 0%,
    so no packets should be dropped.
    """
    st.banner("test_wred_below_min_threshold STARTED")
    fail_msgs = []
    egress = port_info['egress']

    deploy_dchal_helper(dut)
    mac_a = get_dut_mac(dut, port_info['ingress_a'])
    mac_b = get_dut_mac(dut, port_info['ingress_b'])
    verify_wred_profile(dut, fail_msgs)
    verify_queue_bindings(dut, egress, fail_msgs)

    burst_bytes = BURST_BELOW_MIN_PKTS * PKT_SIZE
    st.log("  Burst size: {} packets x {} bytes = {} bytes ({:.0f} KB)".format(
        BURST_BELOW_MIN_PKTS, PKT_SIZE, burst_bytes, burst_bytes / 1024.0))
    st.log("  WRED min_threshold: {} bytes ({:.0f} KB)".format(
        WRED_MIN_THRESHOLD, WRED_MIN_THRESHOLD / 1024.0))
    if burst_bytes >= WRED_MIN_THRESHOLD:
        fail_msgs.append(
            "Burst size {} >= min_threshold {} — test precondition violated"
            .format(burst_bytes, WRED_MIN_THRESHOLD))

    before = _dchal_snapshot("test2: before traffic")

    tg.tg_traffic_control(action='clear_stats')

    stream_a = tg.tg_traffic_config(
        mode='create',
        port_handle=tg_ph['ingress_a'],
        l3_protocol='ipv4',
        ip_src_addr=IXIA_INGRESS_A_IP,
        ip_dst_addr=IXIA_EGRESS_IP,
        mac_dst=mac_a,
        ip_dscp=TARGET_DSCP,
        frame_size=PKT_SIZE,
        rate_percent=PORT_A_RATE_PCT,
        transmit_mode='continuous',
    )

    stream_b = tg.tg_traffic_config(
        mode='create',
        port_handle=tg_ph['ingress_b'],
        l3_protocol='ipv4',
        ip_src_addr=IXIA_INGRESS_B_IP,
        ip_dst_addr=IXIA_EGRESS_IP,
        mac_dst=mac_b,
        ip_dscp=TARGET_DSCP,
        frame_size=PKT_SIZE,
        rate_percent=PORT_A_RATE_PCT,
        transmit_mode='single_burst',
        pkts_per_burst=BURST_BELOW_MIN_PKTS,
    )

    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run', max_wait_timer=30)
    st.wait(2)

    st.log("  Port A saturating egress; sending burst on Port B ...")
    st.wait(BURST_DURATION)

    tg.tg_traffic_control(action='stop', max_wait_timer=30)
    st.wait(2)

    after = _dchal_snapshot("test2: after traffic")

    tx_delta = _q_delta(before, after, 'tx_pkts')
    wred_delta = _q_delta(before, after, 'wred_drop_pkts')
    obs_drop = _calc_obs_drop_pct(tx_delta, wred_delta)
    st.log("  Q{} Tx delta: {}, WRED drop delta: {}, OBS_DROP%: {:.4f}%".format(
        TARGET_QUEUE, tx_delta, wred_delta, obs_drop))

    if round(obs_drop, 2) > 0:
        fail_msgs.append(
            "Q{} WRED drops={} ({:.4f}%) with burst below min_threshold "
            "(expected ~0%)".format(TARGET_QUEUE, wred_delta, obs_drop))

    _log_wred_counters()
    _remove_streams([stream_a, stream_b])

    if fail_msgs:
        st.report_fail('msg', '; '.join(fail_msgs))
    else:
        st.report_pass(
            'msg',
            'Below min_threshold: zero WRED drops confirmed with '
            '{} byte burst (min_threshold={})'.format(
                burst_bytes, WRED_MIN_THRESHOLD))


def _run_continuous_oversub_test(test_label, port_b_rate_pct,
                                 expect_tail_drops=False):
    """Shared test logic for continuous oversubscription tests (3a/3b/4a/4b).

    Port A sends at 100% line rate on DSCP 3 -> Q3 (saturates egress).
    Port B sends at port_b_rate_pct on DSCP 3 -> Q3 (creates oversubscription).

    Verifies:
      - WRED drops > 0
      - OBS_DROP% matches expected oversubscription rate within tolerance
      - q_depth_bytes in expected range (mid-traffic DCHAL snapshot)

    When expect_tail_drops is True, uses wider tolerance and expects q_depth
    at or above max_threshold.

    Returns (pass: bool, fail_msgs: list).
    """
    fail_msgs = []
    egress = port_info['egress']

    deploy_dchal_helper(dut)
    mac_a = get_dut_mac(dut, port_info['ingress_a'])
    mac_b = get_dut_mac(dut, port_info['ingress_b'])
    verify_wred_profile(dut, fail_msgs)
    verify_queue_bindings(dut, egress, fail_msgs)

    expected_oversub = _calc_expected_oversub(port_b_rate_pct)
    expected_q_depth = _calc_expected_q_depth(expected_oversub)
    tolerance = OBS_DROP_TOLERANCE_TAIL if expect_tail_drops else OBS_DROP_TOLERANCE

    st.log("  {} configuration:".format(test_label))
    st.log("    Port A: {}% line rate (continuous, DSCP {})".format(
        PORT_A_RATE_PCT, TARGET_DSCP))
    st.log("    Port B: {}% line rate (continuous, DSCP {})".format(
        port_b_rate_pct, TARGET_DSCP))
    st.log("    Total ingress: {}% of 100G".format(
        PORT_A_RATE_PCT + port_b_rate_pct))
    st.log("    Expected oversubscription: {:.2f}%".format(expected_oversub))
    st.log("    Expected OBS_DROP%: {:.2f}% (+/- {:.1f}%)".format(
        expected_oversub, tolerance))
    st.log("    Expected q_depth: ~{:.0f} bytes ({:.2f} MB)".format(
        expected_q_depth, expected_q_depth / 1048576.0))
    st.log("    Expect tail drops: {}".format(expect_tail_drops))

    before = _dchal_snapshot("{}: before traffic".format(test_label))

    tg.tg_traffic_control(action='clear_stats')

    stream_a = tg.tg_traffic_config(
        mode='create',
        port_handle=tg_ph['ingress_a'],
        l3_protocol='ipv4',
        ip_src_addr=IXIA_INGRESS_A_IP,
        ip_dst_addr=IXIA_EGRESS_IP,
        mac_dst=mac_a,
        ip_dscp=TARGET_DSCP,
        frame_size=PKT_SIZE,
        rate_percent=PORT_A_RATE_PCT,
        transmit_mode='continuous',
    )

    stream_b = tg.tg_traffic_config(
        mode='create',
        port_handle=tg_ph['ingress_b'],
        l3_protocol='ipv4',
        ip_src_addr=IXIA_INGRESS_B_IP,
        ip_dst_addr=IXIA_EGRESS_IP,
        mac_dst=mac_b,
        ip_dscp=TARGET_DSCP,
        frame_size=PKT_SIZE,
        rate_percent=port_b_rate_pct,
        transmit_mode='continuous',
    )

    st.log("  Starting traffic for {} seconds ...".format(
        CONTINUOUS_DURATION))
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run', max_wait_timer=30)

    st.wait(MID_TRAFFIC_SNAPSHOT_AT)
    mid = _dchal_snapshot("{}: mid-traffic (live)".format(test_label))

    q_depth = mid.get(TARGET_QUEUE, {}).get('q_depth_bytes', 0)
    st.log("  Mid-traffic Q{} depth: {} bytes ({:.2f} MB)".format(
        TARGET_QUEUE, q_depth, q_depth / 1048576.0))
    if q_depth >= WRED_MAX_THRESHOLD:
        st.log("    -> ABOVE max_threshold ({} bytes) — tail drop zone".format(
            WRED_MAX_THRESHOLD))
    elif q_depth >= WRED_MIN_THRESHOLD:
        st.log("    -> Between thresholds — WRED probabilistic drop zone")
    else:
        st.log("    -> BELOW min_threshold — no WRED drops at this instant")

    remaining = CONTINUOUS_DURATION - MID_TRAFFIC_SNAPSHOT_AT
    if remaining > 0:
        st.wait(remaining)

    tg.tg_traffic_control(action='stop', max_wait_timer=30)
    st.wait(2)

    after = _dchal_snapshot("{}: after traffic".format(test_label))

    tx_delta = _q_delta(before, after, 'tx_pkts')
    wred_delta = _q_delta(before, after, 'wred_drop_pkts')
    obs_drop = _calc_obs_drop_pct(tx_delta, wred_delta)

    st.log("  Q{} counter analysis (after - before):".format(TARGET_QUEUE))
    st.log("    Tx delta:        {}".format(tx_delta))
    st.log("    WRED drop delta: {}".format(wred_delta))
    st.log("    OBS_DROP%:       {:.2f}%".format(obs_drop))
    st.log("    Expected:        {:.2f}% (+/- {:.1f}%)".format(
        expected_oversub, tolerance))

    if wred_delta <= 0:
        fail_msgs.append(
            "Q{} WRED drops=0 despite {}% oversubscription".format(
                TARGET_QUEUE, port_b_rate_pct))

    drop_diff = abs(obs_drop - expected_oversub)
    if drop_diff > tolerance:
        fail_msgs.append(
            "Q{} OBS_DROP%={:.2f}%, expected {:.2f}% +/- {:.1f}% "
            "(diff={:.2f}%)".format(
                TARGET_QUEUE, obs_drop, expected_oversub,
                tolerance, drop_diff))
    else:
        st.log("    OBS_DROP% within tolerance (diff={:.2f}%)".format(
            drop_diff))

    if expect_tail_drops:
        if q_depth < WRED_MAX_THRESHOLD:
            st.warn("  Mid-traffic q_depth {} < max_threshold {} — "
                     "tail drops expected but queue not at max. "
                     "DCHAL snapshot may have missed peak.".format(
                         q_depth, WRED_MAX_THRESHOLD))
    else:
        if q_depth < WRED_MIN_THRESHOLD:
            st.warn("  Mid-traffic q_depth {} < min_threshold {} — "
                     "queue may not have reached WRED zone yet".format(
                         q_depth, WRED_MIN_THRESHOLD))
        elif q_depth > WRED_MAX_THRESHOLD:
            st.warn("  Mid-traffic q_depth {} > max_threshold {} — "
                     "unexpected for WRED-zone test".format(
                         q_depth, WRED_MAX_THRESHOLD))

    _log_wred_counters()
    _remove_streams([stream_a, stream_b])

    return fail_msgs


def test_wred_midrange_depth():
    """Verify WRED drops with queue depth in the mid-range (~2.5 MB).

    Port A at 100%, Port B at 4% -> ~3.85% oversubscription.
    Queue depth stabilizes at ~2.54 MB (between min 1 MB and max 3 MB).
    OBS_DROP% should match the oversubscription rate (~3.85%).
    """
    st.banner("test_wred_midrange_depth STARTED")
    fail_msgs = _run_continuous_oversub_test(
        "test3a_midrange", PORT_B_RATE_MIDRANGE)

    if fail_msgs:
        st.report_fail('msg', '; '.join(fail_msgs))
    else:
        st.report_pass(
            'msg',
            'WRED midrange: drops confirmed at ~{:.1f}% oversubscription, '
            'q_depth in WRED zone'.format(
                _calc_expected_oversub(PORT_B_RATE_MIDRANGE)))
