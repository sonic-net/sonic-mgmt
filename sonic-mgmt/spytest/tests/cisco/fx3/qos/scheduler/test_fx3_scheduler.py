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
FX3 QoS Scheduler Tests — testbed end-to-end verification (IPv4 + IPv6 dual-stack).

Testbed (fx3_qos_testbed_2022.yaml):
  Ingress A: Ixia 1/9  -> DUT Ethernet1_49 (100G)
  Ingress B: Ixia 1/10 -> DUT Ethernet1_50 (100G)
  Egress:    DUT Ethernet1_51 -> Ixia 1/11 (100G)

(test_fx3_scheduler_reordered_config)  — maps to test_plan test 23
  Remove all QUEUE->scheduler bindings, then re-apply in non-sequential order
  [6,0,1,2,7,3,4,5].  Verify CONFIG_DB, DCHAL BW%, and Tx-pkt ratios are
  identical to sequential binding.  Restores via 'config qos reload'.

(test_fx3_scheduler_weight_change)  — maps to test_plan test 24
  Baseline → scheduler.2 weight 20->30 + queue rebind → scheduler.5 weight
  30->20 + queue rebind → restore.  Verify CONFIG_DB, DCHAL BW%, and traffic
  ratios at each step.  All other profiles must be unchanged.

(test_fx3_bind_unbind_rebind_cycle)  — maps to SAI test_tortuga_bind_unbind_rebind_cycle
  Unbind Q0 (HDEL QUEUE|0), then rebind Q0 to scheduler.4 (w=40).  Verify
  CONFIG_DB, DCHAL BW%, and traffic ratios after each state change.

(test_fx3_change_sg6_strict_to_dwrr)  — maps to SAI test_tortuga_change_bound_sg6_strict_to_dwrr
  Change scheduler.6 from STRICT → DWRR(w=20) and re-bind QUEUE|6.  Verify
  DCHAL and 7-queue traffic (Q6 DWRR ~10%, Q7 sole STRICT).  Requires explicit
  QUEUE re-bind because sai_set(SCHEDULING_TYPE) is SW-only on FX3.

(test_fx3_sg5_dwrr_to_strict)  — maps to SAI test_tortuga_sg5_DWRR_to_STRICT
  Change scheduler.5 from DWRR(w=30) → STRICT.  Uses HDEL+HSET to force a
  delete event so orchagent re-binds via the NULL→OID path and
  program_dwrr_queues_scheduling_to_hw recalibrates Q0-Q4 BW%.

(test_fx3_unbind_dwrr_sg2)  — maps to SAI test_tortuga_unbind_dwrr_sg2
  Unbind Q2 entirely (HDEL QUEUE|2).  Verify remaining DWRR queues
  Q0/Q1/Q3/Q4/Q5 redistribute DCHAL BW% and traffic ratios.

FX3 constraints:
  - PFC and ECN are not supported on this platform.
  - clear_queue_stats is not supported; tests use snapshot-before/after deltas.
  - sai_set(SCHEDULING_TYPE) is SW-only; HW reprogramming only happens on
    set_queue_attribute(SCHEDULER_PROFILE_ID) re-bind.
"""

import pytest

from fx3_qos_helpers import (
    validate_dchal_bw_vs_weights,
    dchal_show_queuing,
    deploy_dchal_helper, get_dchal_queue_counters,
    parse_redis_hgetall, parse_redis_hget,
    get_dut_mac,
    validate_dwrr_ratios,
    ensure_interfaces_admin_up, verify_queue_counters,
    clear_dut_counters, get_intf_counters, report_intf_counters,
    tg_port_speed_gbps, compute_dwrr_stream_rate_pct,
    log_queue_counters,
)

from spytest import st, tgapi


# ── L3 Addresses ─────────────────────────────────────────────────────────
# All addressing is keyed by the port role used in port_info / tg_ph.
# To add ingress_c: append one entry to each dict below — no other changes needed.
#
# DUT-side IPv4/IPv6 (assigned to DUT interfaces)
DUT_IPV4 = {
    'ingress_a': '10.10.10.1/24',
    'ingress_b': '10.10.11.1/24',
    # 'ingress_c': '10.10.12.1/24',
    'egress':    '20.20.20.1/24',
}
DUT_IPV6 = {
    'ingress_a': '2001:db8:a::1/64',
    'ingress_b': '2001:db8:b::1/64',
    # 'ingress_c': '2001:db8:d::1/64',
    'egress':    '2001:db8:c::1/64',
}

# Ixia-side IPv4 (traffic source/dest IPs on Ixia ports)
IXIA_IPV4 = {
    'ingress_a': '10.10.10.2',
    'ingress_b': '10.10.11.2',
    # 'ingress_c': '10.10.12.2',
    'egress':    '20.20.20.2',
}
# Ixia-side IPv6
IXIA_IPV6 = {
    'ingress_a': '2001:db8:a::2',
    'ingress_b': '2001:db8:b::2',
    # 'ingress_c': '2001:db8:d::2',
    'egress':    '2001:db8:c::2',
}

# Ixia source MACs for IPv6 streams (one per port role)
IXIA_SRC_MAC = {
    'ingress_a': '00:11:01:00:00:01',
    'ingress_b': '00:11:02:00:00:01',
    # 'ingress_c': '00:11:03:00:00:01',
    'egress':    '00:11:04:00:00:01',
}

# DUT-side gateway IPs seen from Ixia (= DUT interface IPs without prefix)
IXIA_GWV4 = {role: ip.split('/')[0] for role, ip in DUT_IPV4.items()}
IXIA_GWV6 = {role: ip.split('/')[0] for role, ip in DUT_IPV6.items()}

NETMASK       = '255.255.255.0'
V6_PREFIX_LEN = '64'

# Convenience aliases kept for backward-compat in log strings
IXIA_EGRESS_IP    = IXIA_IPV4['egress']
IXIA_V6_EGRESS_IP = IXIA_IPV6['egress']

# ── Traffic parameters ───────────────────────────────────────────────────
PKT_SIZE           = 128
NUM_QUEUES         = 8
TRAFFIC_DURATION   = 10
# Computed at runtime by compute_stream_rate_pct() in setup_topo, based on the
# actual Ixia ingress/egress port speeds.  See the Traffic rate helpers section.
STREAM_RATE_PCT    = 15  # placeholder — overwritten by setup_topo

# ── Golden data ──────────────────────────────────────────────────────────
# DSCP value that maps to each queue under the default AZURE map (TC N = Q N).
QUEUE_TO_DSCP = {
    0: 0,  1: 6,  2: 2,  3: 3,  4: 4,  5: 46,  6: 48,  7: 49,
}

# IPv6 Traffic Class byte for each queue: TC = DSCP << 2
# (DSCP occupies the upper 6 bits of the 8-bit IPv6 TC field, same as IPv4 ToS)
# e.g. DSCP 46 → TC byte = 46 << 2 = 184
QUEUE_TO_IPV6_TC = {qi: dscp << 2 for qi, dscp in QUEUE_TO_DSCP.items()}

# Expected SCHEDULER profiles after 'config qos reload' on FX3.
# CONFIG_DB keys are SCHEDULER|scheduler.N (not generic SONiC sched_qN).
# Source: scheduler_test_plan.md Reference Configuration (test 17).
EXPECTED_SCHEDULERS = {
    'scheduler.0': {'type': 'DWRR', 'weight': '20'},
    'scheduler.1': {'type': 'DWRR', 'weight': '20'},
    'scheduler.2': {'type': 'DWRR', 'weight': '20'},
    'scheduler.3': {'type': 'DWRR', 'weight': '40'},
    'scheduler.4': {'type': 'DWRR', 'weight': '40'},
    'scheduler.5': {'type': 'DWRR', 'weight': '30'},
    'scheduler.6': {'type': 'STRICT'},
    'scheduler.7': {'type': 'STRICT'},
}

# Bind order for test 23 (non-sequential): SG6, SG0, SG1, SG2, SG7, SG3, SG4, SG5.
# Final CONFIG_DB state must be identical to sequential binding (test 17).
SCHEDULER_REORDER = [6, 0, 1, 2, 7, 3, 4, 5]


# ── Module state ─────────────────────────────────────────────────────────
dut = None
tg = None
tg_ph = {}                # {'ingress_a': handle, ...}
port_info = {}            # {'ingress_a': 'Ethernet1_49', 'egress': 'Ethernet1_51', ...}
tb_vars = None
port_speeds = {}          # {'ingress_a': 100, 'egress': 100} — Gbps, set by setup_topo


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


# ── Fixture ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def setup_topo():
    """Set up DUT L3 dual-stack (IPv4 + IPv6), Ixia interfaces, and QoS baseline.

    Requires D1T1:3 topology: 2 ingress TGen ports + 1 egress TGen port.
    """
    global dut, tg, tg_ph, port_info, tb_vars, STREAM_RATE_PCT

    st.log("setup_topo: establishing minimum topology D1T1:3")
    tb_vars = st.ensure_min_topology("D1T1:3")
    dut = tb_vars.D1

    port_info = {
        'ingress_a': tb_vars.D1T1P1,
        'ingress_b': tb_vars.D1T1P2,
        'egress':    tb_vars.D1T1P3,
    }
    st.log("setup_topo: ports -> {}".format(port_info))

    tg_handle, tg_ph_a = tgapi.get_handle_byname('T1D1P1')
    _, tg_ph_b = tgapi.get_handle_byname('T1D1P2')
    _, tg_ph_e = tgapi.get_handle_byname('T1D1P3')
    tg = tg_handle
    tg_ph = {'ingress_a': tg_ph_a, 'ingress_b': tg_ph_b, 'egress': tg_ph_e}

    # ── Stream rate + port speeds ─────────────────────────────────────────
    _dwrr_weights = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}  # FX3 baseline
    _ingress_phs = [tg_ph[k] for k in tg_ph if k != 'egress']
    STREAM_RATE_PCT = compute_dwrr_stream_rate_pct(tg, _ingress_phs, tg_ph_e, _dwrr_weights)
    for _role, _ph in tg_ph.items():
        port_speeds[_role] = tg_port_speed_gbps(tg, _ph)

    # ── Remove ports from VLAN / PortChannel ──
    st.log("setup_topo: removing port memberships")
    for intf in port_info.values():
        remove_interface_from_all_memberships(dut, intf)

    # ── Reload QoS to ensure FX3 baseline ──
    st.log("setup_topo: reloading QoS config")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)

    # ── L3 dual-stack on DUT ──
    # Loop over all roles in DUT_IPV4 (ingress_* + egress). Adding ingress_c
    # to the address dicts above is the only change needed for a 3rd port.
    st.log("setup_topo: configuring IPv4 + IPv6 L3 interfaces on DUT")
    l3_cmds = []
    for role in sorted(DUT_IPV4):
        intf = port_info[role]
        l3_cmds.append('config interface ip add {} {}'.format(intf, DUT_IPV4[role]))
        l3_cmds.append('config interface ip add {} {}'.format(intf, DUT_IPV6[role]))
    st.config(dut, '\n'.join(l3_cmds), skip_error_check=True)
    st.wait(10)

    # ── Ixia IPv4 interfaces ──
    st.log("setup_topo: configuring Ixia IPv4 interfaces")
    intf_handles = []
    for role in sorted(IXIA_IPV4):
        result = tg.tg_interface_config(
            mode='config', port_handle=tg_ph[role],
            intf_ip_addr=IXIA_IPV4[role], netmask=NETMASK,
            gateway=IXIA_GWV4[role],
            arp_send_req=1, enable_ping_response=1, resolve_gateway_mac=1)
        if result and result.get('handle'):
            intf_handles.append(result['handle'])

    # ── Ixia IPv6 interfaces ──
    st.log("setup_topo: configuring Ixia IPv6 interfaces")
    v6_intf_handles = []
    for role in sorted(IXIA_IPV6):
        result = tg.tg_interface_config(
            mode='config', port_handle=tg_ph[role],
            ipv6_intf_addr=IXIA_IPV6[role], ipv6_prefix_length=V6_PREFIX_LEN,
            ipv6_gateway=IXIA_GWV6[role],
            src_mac_addr=IXIA_SRC_MAC[role],
            arp_send_req='1')
        if result and result.get('handle'):
            v6_intf_handles.append(result['handle'])

    # Start protocol stacks
    try:
        tg.tg_topology_test_control(action='start_all_protocols')
    except Exception:
        st.warn("start_all_protocols unavailable; relying on arp_send_req")

    st.wait(30)

    # Force ARP/NDP from all Ixia interfaces
    for h in intf_handles + v6_intf_handles:
        try:
            tg.tg_arp_control(handle=h, arp_target='all')
        except Exception as e:
            st.warn("tg_arp_control failed for handle {}: {}".format(h, e))
    st.wait(5)

    st.config(dut, "ping -c 5 -W 2 {}".format(IXIA_EGRESS_IP),
        skip_error_check=True)
    st.wait(5)

    # ── Ensure DUT interfaces are admin up and queue counters accessible ──
    st.log("setup_topo: ensuring interfaces admin up")
    ensure_interfaces_admin_up(dut, port_info.values())
    missing = verify_queue_counters(dut, port_info.values())
    if missing:
        st.warn("setup_topo: queue counters missing for: {}".format(missing))

    log_topology_summary()
    yield

    # ── Teardown ──
    st.log("setup_topo: teardown — removing dual-stack L3 config")
    cleanup_cmds = []
    for role in sorted(DUT_IPV4):
        intf = port_info[role]
        cleanup_cmds.append('config interface ip remove {} {}'.format(intf, DUT_IPV4[role]))
        cleanup_cmds.append('config interface ip remove {} {}'.format(intf, DUT_IPV6[role]))
    st.config(dut, '\n'.join(cleanup_cmds), skip_error_check=True)
    st.log("setup_topo: teardown complete")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ── Scheduler test library ────────────────────────────────────────────────────
#    Shared helpers for all FX3 scheduler test cases in this file.
#    These are intentionally kept here (not in fx3_qos_helpers.py) because they
#    depend on module-level test state (dut, tg, tg_ph, port_info, constants).
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def log_scheduler_state(label):
    """Dump all 8 SCHEDULER profiles from CONFIG_DB to the log."""
    st.log("--- Scheduler state [{}] ---".format(label))
    for i in range(8):
        name = "scheduler.{}".format(i)
        out = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
            skip_tmpl=True)
        st.log("  {} -> {}".format(name, parse_redis_hgetall(out)))


def verify_scheduler_weights(label, expected_weights, fail_msgs):
    """Check CONFIG_DB weight for every DWRR profile; append failures to fail_msgs."""
    st.log("{}: verifying scheduler weights in CONFIG_DB".format(label))
    for name, expected in sorted(expected_weights.items()):
        out = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGET "SCHEDULER|{}" "weight"'.format(name),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        status = "OK" if actual == expected else "MISMATCH"
        st.log("  {} weight='{}' expected='{}' {}".format(
            name, actual, expected, status))
        if actual != expected:
            fail_msgs.append(
                "{}: {} weight='{}', expected '{}'".format(
                    label, name, actual, expected))


def log_topology_summary():
    """Print a formatted topology table once setup_topo is complete.

    Shows DUT interface names, Ixia IP assignments, port speeds, and the
    computed STREAM_RATE_PCT with the congestion math — gives full context
    to anyone reading the log without access to the testbed YAML.
    """
    W    = 80
    SEP  = "=" * W
    DASH = "-" * W
    topo_rows = [
        (role,
         port_info.get(role, '?'), port_speeds.get(role, '?'),
         DUT_IPV4.get(role, '?'), IXIA_IPV4.get(role, '?'),
         DUT_IPV6.get(role, '?'), IXIA_IPV6.get(role, '?'))
        for role in sorted(DUT_IPV4)
    ]
    ingress_spds   = [port_speeds[r] for r in port_speeds if r != 'egress']
    egress_spd     = port_speeds.get('egress', 100)
    n_ingress      = len(ingress_spds)
    n_queues       = 6  # DWRR queues used in traffic check
    total_load_pct = STREAM_RATE_PCT * n_ingress * n_queues

    st.log("")
    st.log(SEP)
    st.log("  ACTIVE TOPOLOGY")
    st.log(DASH)
    st.log("  {:<12} {:<22} {:>6}   {:<20} {:<20}".format(
        "Role", "DUT Interface", "Speed", "DUT IPv4 (/24)", "Ixia IPv4"))
    st.log("  {:<38}         {:<20} {:<20}".format(
        "", "DUT IPv6 (/64)", "Ixia IPv6"))
    st.log("  " + DASH)
    for role, dut_intf, spd, v4_dut, v4_ixia, v6_dut, v6_ixia in topo_rows:
        st.log("  {:<12} {:<22} {:>5}G   {:<20} {:<20}".format(
            role, dut_intf, spd, v4_dut, v4_ixia))
        st.log("  {:<38}         {:<20} {:<20}".format("", v6_dut, v6_ixia))
    st.log("  " + DASH)
    st.log("  Ingress : {}  ({} port(s), total {}G)".format(
        " + ".join("{}G".format(s) for s in ingress_spds), n_ingress, sum(ingress_spds)))
    st.log("  Egress  : {}G".format(egress_spd))
    st.log("  Stream  : {}% per stream  × {} DWRR queues  × {} ingress port(s)  =  {}% total egress load".format(
        STREAM_RATE_PCT, n_queues, n_ingress, total_load_pct))
    st.log(SEP)
    st.log("")


def record_checkpoint(checkpoint_summary, label, weight_map, dchal_bw,
                      tx_share, tx_deltas, total_egress, ok, note=''):
    """Store per-checkpoint data for the final summary table."""
    checkpoint_summary[label] = {
        'weight_map':   weight_map,
        'dchal_bw':     dchal_bw,
        'tx_share':     tx_share,
        'tx_deltas':    tx_deltas,
        'total_egress': total_egress,
        'ok':           ok,
        'note':         note,
    }


def print_scheduler_summary(checkpoint_summary):
    """Print the end-of-test summary table covering all recorded checkpoints."""
    SEP  = "=" * 92
    DASH = "-" * 92
    st.log("")
    st.log(SEP)
    st.log("  END-OF-TEST SUMMARY: Weight → BW% mapping across all checkpoints")
    st.log(SEP)

    for label, data in checkpoint_summary.items():
        wm           = data['weight_map']
        dchal_bw     = data.get('dchal_bw', {})
        tx_share     = data.get('tx_share', {})
        tx_deltas    = data.get('tx_deltas', {})
        total_egress = data.get('total_egress', 0)
        total_w      = sum(wm.values())
        ok_tag       = "PASS" if data['ok'] else "FAIL"
        note         = data.get('note', '')
        note_str     = "  <- {}".format(note) if note else ''

        st.log("  Checkpoint : {}  [{}]{}".format(label, ok_tag, note_str))
        st.log("  Total DWRR weight: {}".format(total_w))
        st.log("  {:<8} {:<8} {:<8} {:>14} {:>18} {:>12} {:>10}".format(
            "Queue", "Type", "Weight", "Expected BW%",
            "DCHAL BW% (hw reg)", "Tx Share%", "Result"))
        st.log("  " + DASH[:82])

        mismatched_queues = []
        for qi in sorted(wm):
            w         = wm[qi]
            exp_pct   = w / float(total_w) * 100
            dchal_pct = (dchal_bw.get(qi) or {}).get('bw_pct')
            tx_pct    = tx_share.get(qi)
            dchal_str = "{:.0f}%".format(dchal_pct) if dchal_pct is not None else "N/A"
            tx_str    = "{:.1f}%".format(tx_pct)    if tx_pct    is not None else "N/A"
            if tx_pct is not None:
                lo    = exp_pct * 0.80
                hi    = exp_pct * 1.20
                q_tag = "OK" if lo <= tx_pct <= hi else "MISMATCH"
                if q_tag == "MISMATCH":
                    mismatched_queues.append(qi)
            else:
                q_tag = "N/A"
            st.log("  Q{:<7} {:<8} {:<8} {:>13.1f}% {:>18} {:>11}  {:>8}".format(
                qi, "DWRR", w, exp_pct, dchal_str, tx_str, q_tag))

        # Show STRICT queues explicitly in the table
        for qi in sorted(QUEUE_TO_DSCP):
            if qi not in wm:
                dchal_pct = (dchal_bw.get(qi) or {}).get('bw_pct')
                dchal_str = "{:.0f}%".format(dchal_pct) if dchal_pct is not None else "0%"
                st.log("  Q{:<7} {:<8} {:<8} {:>13} {:>18} {:>11}  {:>8}".format(
                    qi, "STRICT", "-", "0% (drain first)", dchal_str, "N/A", "N/A"))
        st.log("  " + DASH[:82])

        # delta calculation detail for mismatched queues
        if mismatched_queues and total_egress > 0:
            st.log("  Mismatch detail (total Tx delta = {:,} pkts):".format(total_egress))
            st.log("  {:<8} {:<8} {:<8} {:>20} {:>12} {:>12} {:>12} {:>12}".format(
                "Queue", "Type", "Weight",
                "Tx Delta (pkts)", "Actual %",
                "Expected %", "Lo (80%)", "Hi (120%)"))
            st.log("  " + DASH[:90])
            for qi in mismatched_queues:
                w       = wm[qi]
                delta   = tx_deltas.get(qi, 0)
                exp_pct = w / float(total_w) * 100
                act_pct = delta / float(total_egress) * 100
                lo      = exp_pct * 0.80
                hi      = exp_pct * 1.20
                st.log("  Q{:<7} {:<8} {:<8} {:>20,} {:>11.1f}% {:>11.1f}% {:>11.1f}% {:>11.1f}%".format(
                    qi, "DWRR", w, delta, act_pct, exp_pct, lo, hi))
                st.log("         calc: {:,} / {:,} * 100 = {:.1f}%  (expected {:.1f}%,  diff {:+.1f}%)".format(
                    delta, total_egress, act_pct, exp_pct, act_pct - exp_pct))
            st.log("  " + DASH[:90])
        st.log("")

    st.log("  Queue types: DWRR = weighted fair share  |  STRICT = drain first, always")
    st.log(SEP)


def scheduler_traffic_check(label, weight_map, fail_msgs, checkpoint_summary,
                             macs, dchal_bw=None, note='', strict_queues=(6, 7),
                             rate_pct=None):
    """Send congested DWRR traffic for *weight_map* queues and validate Tx-pkt ratios.

    N DWRR queues × M ingress ports × rate_pct% = >100% of egress (computed at runtime)
    → every queue is congested → Tx ratios proportional to DWRR weights.
    Appends failures to fail_msgs; records checkpoint data in checkpoint_summary.

    macs:         dict {role: dut_mac}  e.g. {'ingress_a': '00:...', 'ingress_b': '00:...'}
    strict_queues: queue indices expected to have zero drops (default (6,7)).
    rate_pct:     per-stream Tx rate (%); defaults to module STREAM_RATE_PCT.
                  Override when weight_map has more queues than the module baseline
                  to avoid saturating the ingress port and starving the last queue.
    Adding ingress_c requires only adding entries to IXIA_IPV4/IXIA_IPV6/IXIA_SRC_MAC
    and port_info/tg_ph — this function scales automatically.
    """
    _rate = rate_pct if rate_pct is not None else STREAM_RATE_PCT
    egress = port_info['egress']
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    # Build stream source list from all active ingress roles
    ports = [
        (tg_ph[r], IXIA_IPV4[r], macs[r])
        for r in _ingress_roles
    ]
    _topo_str = ", ".join(
        "{}={}({}G)".format(r, port_info.get(r, '?'), port_speeds.get(r, '?'))
        for r in _ingress_roles
    ) + "  →  egress={}({}G)".format(
        port_info.get('egress', '?'), port_speeds.get('egress', '?'))
    st.banner(
        "TRAFFIC CHECK [IPv4]: {}\n"
        "  Topology : {}\n"
        "  IPv4     : src [{}]  →  dst {}\n"
        "  Weights  : {}\n"
        "  Streams  : {} queues x {} ports x {}% rate = {}% egress load (congested)".format(
            label,
            _topo_str,
            ", ".join(IXIA_IPV4[r] for r in _ingress_roles),
            IXIA_EGRESS_IP,
            "  ".join("Q{}={}".format(k, weight_map[k]) for k in sorted(weight_map)),
            len(weight_map), len(ports), _rate,
            len(weight_map) * len(ports) * _rate)
    )
    stream_handles = []
    clear_dut_counters(dut)
    intf_before = get_intf_counters(dut, port_info.values())
    q_before = get_dchal_queue_counters(dut, egress, label)
    # st.log("  Queue counters BEFORE traffic:")
    # log_queue_counters(q_before)
    tg.tg_traffic_control(action='clear_stats')
    for qi in sorted(weight_map):
        dscp = QUEUE_TO_DSCP[qi]
        for ph, src_ip, dst_mac in ports:
            result = tg.tg_traffic_config(
                mode='create', port_handle=ph,
                l3_protocol='ipv4',
                l4_protocol='icmp',
                ip_src_addr=src_ip,
                ip_dst_addr=IXIA_EGRESS_IP,
                mac_dst=dst_mac,
                ip_dscp=dscp,
                ip_ttl=64,
                frame_size=PKT_SIZE,
                rate_percent=_rate,
                transmit_mode='continuous',
                high_speed_result_analysis=0,
            )
            stream_handles.append(result)
    st.log("  Sending {} streams ({}x queues × {}x ports) at {}% for {}s".format(
        len(stream_handles), len(weight_map), len(ports),
        _rate, TRAFFIC_DURATION))
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    st.wait(TRAFFIC_DURATION)
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    q_after = get_dchal_queue_counters(dut, egress, label)
    # st.log("  Queue counters AFTER traffic:")
    # log_queue_counters(q_after)
    intf_after = get_intf_counters(dut, port_info.values())
    report_intf_counters(port_info, intf_before, intf_after)

    total_egress = sum(
        (q_after.get(qi, {}).get('pkts', 0) - q_before.get(qi, {}).get('pkts', 0))
        for qi in weight_map
    )

    # compute per-queue Tx share% and deltas for the summary table
    tx_share  = {}
    tx_deltas = {}
    if total_egress > 0:
        for qi in weight_map:
            delta = max(0, q_after.get(qi, {}).get('pkts', 0)
                           - q_before.get(qi, {}).get('pkts', 0))
            tx_deltas[qi] = delta
            tx_share[qi]  = delta / float(total_egress) * 100

    pre_fail_count = len(fail_msgs)
    if total_egress == 0:
        fail_msgs.append(
            "{}: no egress traffic observed (all queue Tx deltas = 0)".format(label))
    else:
        validate_dwrr_ratios(label, q_before, q_after, weight_map, fail_msgs,
                             strict_queues=strict_queues)

    # record for final summary (ok = no new failures added this call)
    record_checkpoint(checkpoint_summary, label, weight_map, dchal_bw or {},
                      tx_share, tx_deltas, total_egress,
                      ok=(len(fail_msgs) == pre_fail_count), note=note)

    for sh in stream_handles:
        try:
            sid = sh.get('stream_id') if sh is not None else None
            if sid:
                tg.tg_traffic_config(mode='remove', stream_id=sid)
        except Exception:
            pass


def scheduler_traffic_check_v6(label, weight_map, fail_msgs, checkpoint_summary,
                                macs, dchal_bw=None, note='', strict_queues=(6, 7),
                                rate_pct=None):
    """IPv6 variant of scheduler_traffic_check — same congestion logic, IPv6 streams.

    Sends IPv6 traffic with Traffic Class byte = DSCP << 2, which maps identically
    to the AZURE dscp_to_tc_map used for IPv4.  All other validation logic
    (queue counter deltas, validate_dwrr_ratios, record_checkpoint) is unchanged.

    N DWRR queues × M ingress ports × STREAM_RATE_PCT% = >100% egress load → congested.
    (N is len(weight_map); STREAM_RATE_PCT is calibrated for the baseline 6-queue case
    but produces sufficient egress congestion for 5- and 7-queue variants as well.)

    macs: dict {role: dut_mac}  e.g. {'ingress_a': '00:...', 'ingress_b': '00:...'}
    strict_queues: queue indices expected to have zero drops (default (6,7)).
    rate_pct: override per-stream rate%; if None uses module STREAM_RATE_PCT.
    """
    _rate = rate_pct if rate_pct is not None else STREAM_RATE_PCT
    egress = port_info['egress']
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    # Build stream source list from all active ingress roles
    ports = [
        (tg_ph[r], IXIA_IPV6[r], macs[r], IXIA_SRC_MAC[r], IXIA_GWV6[r])
        for r in _ingress_roles
    ]
    _topo_str = ", ".join(
        "{}={}({}G)".format(r, port_info.get(r, '?'), port_speeds.get(r, '?'))
        for r in _ingress_roles
    ) + "  →  egress={}({}G)".format(
        port_info.get('egress', '?'), port_speeds.get('egress', '?'))
    st.banner(
        "TRAFFIC CHECK [IPv6]: {}\n"
        "  Topology : {}\n"
        "  IPv6     : src [{}]  →  dst {}\n"
        "  Weights  : {}\n"
        "  Streams  : {} queues x {} ports x {}% rate = {}% egress load (congested)".format(
            label,
            _topo_str,
            ", ".join(IXIA_IPV6[r] for r in _ingress_roles),
            IXIA_V6_EGRESS_IP,
            "  ".join("Q{}={}".format(k, weight_map[k]) for k in sorted(weight_map)),
            len(weight_map), len(ports), _rate,
            len(weight_map) * len(ports) * _rate)
    )
    stream_handles = []
    clear_dut_counters(dut)
    intf_before = get_intf_counters(dut, port_info.values())
    q_before = get_dchal_queue_counters(dut, egress, label)
    # st.log("  Queue counters BEFORE traffic:")
    # log_queue_counters(q_before)
    tg.tg_traffic_control(action='clear_stats')
    for qi in sorted(weight_map):
        tc = QUEUE_TO_IPV6_TC[qi]
        for ph, src_ip, dst_mac, src_mac, disc_gw in ports:
            result = tg.tg_traffic_config(
                mode='create', port_handle=ph,
                l3_protocol='ipv6',
                l4_protocol='icmp',
                ipv6_src_addr=src_ip,
                ipv6_dst_addr=IXIA_V6_EGRESS_IP,
                mac_src=src_mac,
                mac_dst=dst_mac,
                mac_discovery_gw=disc_gw,
                ipv6_traffic_class=tc,
                ipv6_hop_limit=64,
                frame_size=PKT_SIZE,
                rate_percent=_rate,
                transmit_mode='continuous',
                high_speed_result_analysis=0,
            )
            stream_handles.append(result)
    st.log("  Sending {} IPv6 streams ({}x queues × {}x ports) at {}% for {}s".format(
        len(stream_handles), len(weight_map), len(ports),
        _rate, TRAFFIC_DURATION))
    tg.tg_traffic_control(action='apply')
    tg.tg_traffic_control(action='run')
    st.wait(TRAFFIC_DURATION)
    tg.tg_traffic_control(action='stop')
    st.wait(2)

    q_after = get_dchal_queue_counters(dut, egress, label)
    # st.log("  Queue counters AFTER traffic:")
    # log_queue_counters(q_after)
    intf_after = get_intf_counters(dut, port_info.values())
    report_intf_counters(port_info, intf_before, intf_after)

    total_egress = sum(
        (q_after.get(qi, {}).get('pkts', 0) - q_before.get(qi, {}).get('pkts', 0))
        for qi in weight_map
    )

    tx_share  = {}
    tx_deltas = {}
    if total_egress > 0:
        for qi in weight_map:
            delta = max(0, q_after.get(qi, {}).get('pkts', 0)
                           - q_before.get(qi, {}).get('pkts', 0))
            tx_deltas[qi] = delta
            tx_share[qi]  = delta / float(total_egress) * 100

    pre_fail_count = len(fail_msgs)
    if total_egress == 0:
        fail_msgs.append(
            "{}: no IPv6 egress traffic observed (all queue Tx deltas = 0)".format(label))
    else:
        validate_dwrr_ratios(label, q_before, q_after, weight_map, fail_msgs,
                             strict_queues=strict_queues)

    record_checkpoint(checkpoint_summary, label, weight_map, dchal_bw or {},
                      tx_share, tx_deltas, total_egress,
                      ok=(len(fail_msgs) == pre_fail_count), note=note)

    for sh in stream_handles:
        try:
            sid = sh.get('stream_id') if sh is not None else None
            if sid:
                tg.tg_traffic_config(mode='remove', stream_id=sid)
        except Exception:
            pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_fx3_scheduler_reordered_config(setup_topo):
    """Verify CONFIG_DB state, DCHAL BW%, and traffic ratios after non-sequential QUEUE binding.

    Maps to SAI test_tortuga_scheduler_reordered_config and scheduler_test_plan.md test 23.

    Binds QUEUE->scheduler entries in order [6,0,1,2,7,3,4,5] instead of 0-7.
    SONiC orchagent may process QUEUE bindings in any order; the final hardware
    state must be identical to sequential binding:
      - CONFIG_DB SCHEDULER profiles unchanged (type/weight)
      - CONFIG_DB QUEUE bindings correct for all 8 queues
      - DCHAL BW%: STRICT(Q6,Q7)=0%, DWRR BW% proportional to weights, sum≈100%
      - Live traffic: IPv4 + IPv6 Tx-pkt ratios proportional to DWRR weights
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_fx3_scheduler_reordered_config  [IPv4 + IPv6  dual-stack]\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Stream   : {}% per stream  \u00d7 6 DWRR queues  \u00d7 {} ingress = {}% total egress load\n"
        "  Bind order: {} (non-sequential; final state must == sequential)".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'),
            STREAM_RATE_PCT, len(_ingress_roles),
            STREAM_RATE_PCT * len(_ingress_roles) * 6,
            SCHEDULER_REORDER)
    )
    fail_msgs = []
    checkpoint_summary = {}

    # ── Setup ────────────────────────────────────────────────────────────
    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    st.log("DUT ingress MACs:")
    for role in _ingress_roles:
        st.log("  {:<12}  {}  MAC {}".format(role, port_info[role], macs[role]))
    deploy_dchal_helper(dut)

    # FX3 baseline DWRR weight map (Q6=STRICT, Q7=STRICT — excluded)
    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}

    # ── Step 1: Remove all existing QUEUE->scheduler bindings ────────────
    st.banner("STEP 1: Remove all QUEUE->scheduler bindings on {}".format(egress))
    for qi in range(NUM_QUEUES):
        st.config(
            dut,
            'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|{}" "scheduler"'.format(
                egress, qi),
            skip_error_check=True)
    st.wait(2)

    # ── Step 2: Re-apply bindings in non-sequential order ────────────────
    st.banner("STEP 2: Re-apply QUEUE bindings in order {}".format(SCHEDULER_REORDER))
    for qi in SCHEDULER_REORDER:
        sched = 'scheduler.{}'.format(qi)
        st.log("  Binding QUEUE|{}|{} -> {}".format(egress, qi, sched))
        st.config(
            dut,
            'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|{}" "scheduler" "{}"'.format(
                egress, qi, sched),
            skip_error_check=True)
    st.wait(2)

    # ── Step 3: Verify SCHEDULER profiles unchanged (type + weight) ──────
    # Equivalent to SAI _apply_verify_and_cleanup: verify OID bindings
    st.banner("STEP 3: Verify SCHEDULER profiles (type/weight) in CONFIG_DB")
    for name, expected in EXPECTED_SCHEDULERS.items():
        output = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
            skip_tmpl=True)
        actual = parse_redis_hgetall(output)
        st.log("  {} -> {}".format(name, actual))
        if not actual:
            fail_msgs.append("{}: empty or missing".format(name))
            continue
        actual_type = actual.get('type', '')
        if actual_type != expected['type']:
            fail_msgs.append("{}: type='{}', expected '{}'".format(
                name, actual_type, expected['type']))
        if 'weight' in expected:
            actual_weight = actual.get('weight', '')
            if actual_weight != expected['weight']:
                fail_msgs.append("{}: weight='{}', expected '{}'".format(
                    name, actual_weight, expected['weight']))

    # ── Step 4: Verify final QUEUE bindings match sequential (test 17) ───
    st.log("Verifying final QUEUE bindings are identical to sequential binding")
    for qi in range(NUM_QUEUES):
        expected_sched = 'scheduler.{}'.format(qi)
        output = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(
                egress, qi),
            skip_tmpl=True)
        actual_binding = parse_redis_hget(output).strip()
        st.log("  Q{} -> '{}'".format(qi, actual_binding))
        if actual_binding != expected_sched:
            fail_msgs.append("QUEUE|{}|{}: '{}', expected '{}'".format(
                egress, qi, actual_binding, expected_sched))

    if fail_msgs:
        st.log("=" * 72)
        st.log("  CONFIG_DB FAILURES ({} total) — aborting before traffic:".format(
            len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg',
            'Scheduler reordered config FAILED at CONFIG_DB checks — see above')
        return

    log_scheduler_state("After reorder bind")

    # ── Step 5: DCHAL BW% — equivalent to SAI _verify_dchal_dwrr_percentages
    # Checks: STRICT(Q6,Q7)=0%, DWRR>0%, higher weight→higher%, sum≈100%
    st.banner("STEP 5: DCHAL Bandwidth% after reordered bind")
    _dchal_out = dchal_show_queuing(dut, "Reordered bind", egress)
    _dchal_bw = validate_dchal_bw_vs_weights(
        "Reordered bind", _dchal_out, w_baseline, fail_msgs)

    # ── Step 6: IPv4 traffic — Tx-pkt ratios must match DWRR weights ─────
    scheduler_traffic_check(
        "Reordered bind [IPv4]", w_baseline, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw,
        note="bind order [6,0,1,2,7,3,4,5] — same weights as sequential")

    # ── Step 7: IPv6 traffic ──────────────────────────────────────────────
    scheduler_traffic_check_v6(
        "Reordered bind [IPv6]", w_baseline, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw,
        note="bind order [6,0,1,2,7,3,4,5] — same weights as sequential")

    # ── Restore ───────────────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Final summary ─────────────────────────────────────────────────────
    print_scheduler_summary(checkpoint_summary)

    # ── Verdict ───────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  SCHEDULER REORDERED CONFIG — FAILURES ({} total):".format(
            len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Scheduler reordered config FAILED ({} failures) — see above'.format(
                len(fail_msgs)))
    else:
        st.log("  SCHEDULER REORDERED CONFIG — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  Bind order [6,0,1,2,7,3,4,5]: CONFIG_DB, DCHAL BW%, "
               "and traffic ratios identical to sequential binding")
        st.log("=" * 72)
        st.report_pass('msg',
            'Scheduler reordered config PASSED (IPv4 + IPv6): '
            'CONFIG_DB, DCHAL BW%, and Tx-pkt ratios correct after '
            'non-sequential bind order [6,0,1,2,7,3,4,5]')


def test_fx3_scheduler_weight_change(setup_topo):
    """Verify CONFIG_DB scheduler weight changes are reflected in hardware for
    both IPv4 and IPv6 traffic (test 24 — dual-stack).

    At each checkpoint, both IPv4 and IPv6 Tx-pkt ratios are validated against
    the active DWRR weights.

    Baseline:  scheduler.2=20  scheduler.5=30
    Step 1:    HSET scheduler.2 weight 20->30  + queue rebind → IPv4 + IPv6 verify
    Step 2:    HSET scheduler.5 weight 30->20  + queue rebind → IPv4 + IPv6 verify
    Restore:   config qos reload               → IPv4 + IPv6 verify
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    st.banner(
        "test_fx3_scheduler_weight_change  [IPv4 + IPv6  dual-stack]\n"
        "  DUT     : {}\n"
        "  Ingress : {}\n"
        "  Egress  : {}  ({}G)\n"
        "  Stream  : {}% per stream  \u00d7 6 DWRR queues  \u00d7 {} ingress = {}% total egress load\n"
        "  Plan    : Baseline \u2192 Step1 [sched.2: 20\u219230+rebind] \u2192 "
        "Step2 [sched.5: 30\u219220+rebind] \u2192 Restore".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            port_info['egress'], port_speeds.get('egress', '?'),
            STREAM_RATE_PCT,
            len(_ingress_roles),
            STREAM_RATE_PCT * len(_ingress_roles) * 6)
    )
    fail_msgs = []
    checkpoint_summary = {}

    # ── Setup ─────────────────────────────────────────────────────
    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    st.log("DUT ingress MACs:")
    for role in _ingress_roles:
        st.log("  {:<12}  {}  MAC {}".format(role, port_info[role], macs[role]))
    deploy_dchal_helper(dut)

    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    w_step1    = {0: 20, 1: 20, 2: 30, 3: 40, 4: 40, 5: 30}  # scheduler.2: 20->30
    w_step2    = {0: 20, 1: 20, 2: 30, 3: 40, 4: 40, 5: 20}  # scheduler.5: 30->20

    # ── Baseline ──────────────────────────────────────────────────────────
    st.banner("BASELINE")
    verify_scheduler_weights("Baseline",
        {'scheduler.{}'.format(k): str(v) for k, v in w_baseline.items()},
        fail_msgs)
    if fail_msgs:
        st.log("=" * 72)
        st.log("  BASELINE FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Scheduler weight change FAILED at baseline — see failures above')
        return
    log_scheduler_state("Baseline")
    _dchal_out = dchal_show_queuing(dut, "Baseline", port_info['egress'])
    _dchal_bw_baseline = validate_dchal_bw_vs_weights("Baseline", _dchal_out, w_baseline, fail_msgs)
    scheduler_traffic_check("Baseline [IPv4]", w_baseline, fail_msgs, checkpoint_summary,
                            macs, dchal_bw=_dchal_bw_baseline, note="FX3 default weights")
    scheduler_traffic_check_v6("Baseline [IPv6]", w_baseline, fail_msgs, checkpoint_summary,
                               macs, dchal_bw=_dchal_bw_baseline, note="FX3 default weights")

    # ── Step 1: scheduler.2  weight 20 -> 30 ──────────────────────────────
    st.banner("STEP 1: scheduler.2  weight 20 -> 30")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.2" "weight" "30"',
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|2" "scheduler" "scheduler.2"'.format(
            port_info['egress']),
        skip_error_check=True)
    st.wait(2)
    verify_scheduler_weights("Step 1",
        {'scheduler.{}'.format(k): str(v) for k, v in w_step1.items()},
        fail_msgs)
    log_scheduler_state("Step 1")
    _dchal_out = dchal_show_queuing(dut, "Step 1", port_info['egress'])
    _dchal_bw_step1 = validate_dchal_bw_vs_weights("Step 1", _dchal_out, w_step1, fail_msgs)
    scheduler_traffic_check("Step 1 [IPv4]", w_step1, fail_msgs, checkpoint_summary,
                            macs, dchal_bw=_dchal_bw_step1, note="sched.2: 20→30")
    scheduler_traffic_check_v6("Step 1 [IPv6]", w_step1, fail_msgs, checkpoint_summary,
                               macs, dchal_bw=_dchal_bw_step1, note="sched.2: 20→30")

    # ── Step 2: scheduler.5  weight 30 -> 20 ──────────────────────────────
    st.banner("STEP 2: scheduler.5  weight 30 -> 20")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.5" "weight" "20"',
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|5" "scheduler" "scheduler.5"'.format(
            port_info['egress']),
        skip_error_check=True)
    st.wait(2)
    verify_scheduler_weights("Step 2",
        {'scheduler.{}'.format(k): str(v) for k, v in w_step2.items()},
        fail_msgs)
    log_scheduler_state("Step 2")
    _dchal_out = dchal_show_queuing(dut, "Step 2", port_info['egress'])
    _dchal_bw_step2 = validate_dchal_bw_vs_weights("Step 2", _dchal_out, w_step2, fail_msgs)
    scheduler_traffic_check("Step 2 [IPv4]", w_step2, fail_msgs, checkpoint_summary,
                            macs, dchal_bw=_dchal_bw_step2, note="sched.5: 30→20 (sched.2 still 30)")
    scheduler_traffic_check_v6("Step 2 [IPv6]", w_step2, fail_msgs, checkpoint_summary,
                               macs, dchal_bw=_dchal_bw_step2, note="sched.5: 30→20 (sched.2 still 30)")

    # ── Verify STRICT schedulers unchanged throughout ──────────────────────
    st.log("Verifying STRICT schedulers (6, 7) have no weight field")
    for name in ('scheduler.6', 'scheduler.7'):
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
            skip_tmpl=True)
        actual = parse_redis_hgetall(out)
        st.log("  {} -> {}".format(name, actual))
        if actual.get('type', '') != 'STRICT':
            fail_msgs.append(
                "{} type='{}', expected 'STRICT'".format(name, actual.get('type', '')))
        if 'weight' in actual:
            fail_msgs.append(
                "{} unexpectedly has weight='{}'".format(name, actual['weight']))

    # ── Restore baseline ───────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")
    _dchal_out = dchal_show_queuing(dut, "Restore", port_info['egress'])
    _dchal_bw_restore = validate_dchal_bw_vs_weights("Restore", _dchal_out, w_baseline, fail_msgs)
    scheduler_traffic_check("Restore [IPv4]", w_baseline, fail_msgs, checkpoint_summary,
                            macs, dchal_bw=_dchal_bw_restore, note="config qos reload → back to baseline")
    scheduler_traffic_check_v6("Restore [IPv6]", w_baseline, fail_msgs, checkpoint_summary,
                               macs, dchal_bw=_dchal_bw_restore, note="config qos reload → back to baseline")

    # ── Final summary ─────────────────────────────────────────────────────
    print_scheduler_summary(checkpoint_summary)

    # ── Verdict ───────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  SCHEDULER WEIGHT CHANGE — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg', 'Scheduler weight change FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  SCHEDULER WEIGHT CHANGE — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  scheduler.2 20->30, scheduler.5 30->20, all others unchanged")
        st.log("=" * 72)
        st.report_pass('msg',
            'Scheduler weight change PASSED (IPv4 + IPv6): '
            'scheduler.2 20->30, scheduler.5 30->20, all others unchanged')


def test_fx3_bind_unbind_rebind_cycle(setup_topo):
    """Unbind Q0, then rebind Q0 to scheduler.4 (w=40); verify DCHAL and traffic ratios.

    Maps to SAI test_tortuga_bind_unbind_rebind_cycle and
    scheduler_test_plan.md test 20.

    Steps:
      1. Verify FX3 baseline CONFIG_DB bindings
      2. HDEL QUEUE|<egress>|0 scheduler  — Q0 unbound
      3. Verify CONFIG_DB Q0 has no scheduler binding
      4. Log DCHAL + validate Q1-Q5 BW% ratios (Q0 excluded — drops to HW fallback token)
         IPv4 + IPv6 traffic check for Q1-Q5 proportional ratios
      5. HSET QUEUE|<egress>|0 scheduler=scheduler.4  — rebind Q0 to w=40
      6. Verify CONFIG_DB Q0 binding = scheduler.4
      7. DCHAL check: Q0 now ~w=40 proportion (same as Q3, Q4)
      8. IPv4 traffic: weight_map {0:40, 1:20, 2:20, 3:40, 4:40, 5:30}
      9. IPv6 traffic
     10. Restore: config qos reload
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_fx3_bind_unbind_rebind_cycle  [IPv4 + IPv6  dual-stack]\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Plan     : Baseline → Unbind Q0 → Rebind Q0 to scheduler.4 (w=40) "
        "→ DCHAL + traffic → Restore".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'))
    )
    fail_msgs = []
    checkpoint_summary = {}

    # ── Setup ─────────────────────────────────────────────────────────────
    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    st.log("DUT ingress MACs:")
    for role in _ingress_roles:
        st.log("  {:<12}  {}  MAC {}".format(role, port_info[role], macs[role]))
    deploy_dchal_helper(dut)

    # FX3 baseline weight map (Q6=STRICT, Q7=STRICT — not in DWRR pool)
    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    # After rebind Q0 → scheduler.4 (w=40)
    w_rebind   = {0: 40, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}

    # ── Step 1: Verify FX3 baseline QUEUE bindings ────────────────────────
    st.banner("STEP 1: Verify FX3 baseline QUEUE bindings on {}".format(egress))
    for qi in range(NUM_QUEUES):
        expected_sched = 'scheduler.{}'.format(qi)
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        st.log("  Q{} -> '{}'  expected '{}'  {}".format(
            qi, actual, expected_sched, "OK" if actual == expected_sched else "MISMATCH"))
        if actual != expected_sched:
            fail_msgs.append("Baseline: QUEUE|{}|{} = '{}', expected '{}'".format(
                egress, qi, actual, expected_sched))

    if fail_msgs:
        st.log("=" * 72)
        st.log("  BASELINE FAILURES — aborting:")
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg', 'Bind/unbind/rebind cycle FAILED at baseline — see above')
        return

    # ── Step 2: Unbind Q0 ─────────────────────────────────────────────────
    st.banner("STEP 2: Unbind Q0 — HDEL QUEUE|{}|0 scheduler".format(egress))
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|0" "scheduler"'.format(egress),
        skip_error_check=True)
    st.wait(2)

    # ── Step 3: Verify Q0 unbound ─────────────────────────────────────────
    st.banner("STEP 3: Verify Q0 has no scheduler binding in CONFIG_DB")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|0" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q0 = parse_redis_hget(out).strip()
    st.log("  Q0 binding after HDEL: '{}'  (expected empty)".format(actual_q0))
    if actual_q0:
        fail_msgs.append("After unbind: QUEUE|{}|0 still has scheduler='{}'".format(
            egress, actual_q0))

    # Verify Q1-Q7 bindings are unchanged
    for qi in range(1, NUM_QUEUES):
        expected_sched = 'scheduler.{}'.format(qi)
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        if actual != expected_sched:
            fail_msgs.append("After Q0 unbind: Q{} binding='{}', expected '{}' (should be unchanged)".format(
                qi, actual, expected_sched))

    # ── Step 4: Log DCHAL after Q0 unbind ────────────────────────────────
    st.banner("STEP 4: DCHAL state after Q0 unbind (Q0 reverts to default weight)")
    _dchal_out_unbind = dchal_show_queuing(dut, "After Q0 unbind", egress)
    # Q0 Bandwidth%=0 after unbind (FX3 ASIC drops it to minimum fallback token=81).
    # Validate Q1–Q5 still maintain their expected proportional ratios (Q0 excluded).
    w_unbind_q1_q5 = {1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    validate_dchal_bw_vs_weights("After Q0 unbind (Q1-Q5 only)", _dchal_out_unbind,
                                 w_unbind_q1_q5, fail_msgs)
    scheduler_traffic_check("After Q0 unbind [IPv4]", w_unbind_q1_q5, fail_msgs,
                            checkpoint_summary, macs, dchal_bw=None,
                            note="Q0 unbound — validating Q1-Q5 ratios only")
    scheduler_traffic_check_v6("After Q0 unbind [IPv6]", w_unbind_q1_q5, fail_msgs,
                               checkpoint_summary, macs, dchal_bw=None,
                               note="Q0 unbound — validating Q1-Q5 ratios only")

    # ── Step 5: Rebind Q0 to scheduler.4 (w=40) ───────────────────────────
    st.banner("STEP 5: Rebind Q0 to scheduler.4 (w=40)")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|0" "scheduler" "scheduler.4"'.format(egress),
        skip_error_check=True)
    st.wait(2)

    # ── Step 6: Verify CONFIG_DB Q0 = scheduler.4 ─────────────────────────
    st.banner("STEP 6: Verify CONFIG_DB Q0 binding = scheduler.4")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|0" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q0 = parse_redis_hget(out).strip()
    st.log("  Q0 binding after rebind: '{}'  expected 'scheduler.4'  {}".format(
        actual_q0, "OK" if actual_q0 == 'scheduler.4' else "MISMATCH"))
    if actual_q0 != 'scheduler.4':
        fail_msgs.append("After rebind: QUEUE|{}|0 = '{}', expected 'scheduler.4'".format(
            egress, actual_q0))

    # Confirm scheduler.4 still has its original weight (not modified by rebind)
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.4"',
        skip_tmpl=True)
    actual_s4 = parse_redis_hgetall(out)
    st.log("  scheduler.4 profile: {}".format(actual_s4))
    if actual_s4.get('type') != 'DWRR' or actual_s4.get('weight') != '40':
        fail_msgs.append(
            "scheduler.4 profile unexpected after Q0 rebind: {}".format(actual_s4))

    log_scheduler_state("After Q0 rebind to scheduler.4")

    # ── Step 7: DCHAL check after rebind ─────────────────────────────────
    st.banner("STEP 7: DCHAL Bandwidth% after rebind (Q0 should be ~w=40 proportion)")
    _dchal_out = dchal_show_queuing(dut, "After Q0 rebind", egress)
    _dchal_bw = validate_dchal_bw_vs_weights(
        "After Q0 rebind", _dchal_out, w_rebind, fail_msgs)

    # ── Step 8: IPv4 traffic ───────────────────────────────────────────────
    scheduler_traffic_check(
        "Rebind Q0→sched.4 [IPv4]", w_rebind, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw,
        note="Q0 rebound to scheduler.4 (w=40): Q0/Q3/Q4 share equally")

    # ── Step 9: IPv6 traffic ───────────────────────────────────────────────
    scheduler_traffic_check_v6(
        "Rebind Q0→sched.4 [IPv6]", w_rebind, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw,
        note="Q0 rebound to scheduler.4 (w=40): Q0/Q3/Q4 share equally")

    # ── Restore ────────────────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Final summary ──────────────────────────────────────────────────────
    print_scheduler_summary(checkpoint_summary)

    # ── Verdict ────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  BIND/UNBIND/REBIND CYCLE — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Bind/unbind/rebind cycle FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  BIND/UNBIND/REBIND CYCLE — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  Q0 unbind → rebind to scheduler.4 (w=40): DCHAL and traffic ratios correct")
        st.log("=" * 72)
        st.report_pass('msg',
            'Bind/unbind/rebind cycle PASSED (IPv4 + IPv6): '
            'Q0 unbound then rebound to scheduler.4 (w=40); '
            'DCHAL BW% and Tx-pkt ratios match expected weights')


def test_fx3_change_sg6_strict_to_dwrr(setup_topo):
    """Change scheduler.6 from STRICT to DWRR(w=20); verify DCHAL and 7-queue traffic.

    Steps:
      1. Verify FX3 baseline — scheduler.6 is STRICT
      2. Change scheduler.6: STRICT → DWRR (w=20) + re-bind QUEUE|6
      3. Verify CONFIG_DB scheduler.6 type=DWRR weight=20; scheduler.7 unchanged STRICT
      4. DCHAL check — Q6 DWRR ~10%, Q7 STRICT 0%, sum≈100%
      5. IPv4 traffic: weight_map {0:20, 1:20, 2:20, 3:40, 4:40, 5:30, 6:20}
      6. IPv6 traffic
      7. Restore: config qos reload
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_fx3_change_sg6_strict_to_dwrr  [IPv4 + IPv6  dual-stack]\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Plan     : Baseline → STRICT→DWRR(w=20) → DCHAL + 7-queue traffic → Restore".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'))
    )
    fail_msgs = []
    checkpoint_summary = {}

    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    # After SG6 STRICT→DWRR(w=20): Q6 joins DWRR pool, Q7 remains STRICT
    w_sg6_dwrr = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30, 6: 20}

    # ── Step 1: Verify FX3 baseline — scheduler.6 is STRICT ──────────────
    st.banner("STEP 1: Verify FX3 baseline — scheduler.6 is STRICT")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.6"',
        skip_tmpl=True)
    actual_s6 = parse_redis_hgetall(out)
    st.log("  scheduler.6 baseline: {}".format(actual_s6))
    if actual_s6.get('type') != 'STRICT':
        fail_msgs.append("Baseline: scheduler.6 type='{}', expected 'STRICT'".format(
            actual_s6.get('type', '')))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg', 'Change SG6 STRICT→DWRR FAILED at baseline — scheduler.6 not STRICT')
        return

    # ── Step 2: Change scheduler.6: STRICT → DWRR (w=20) ─────────────────
    st.banner("STEP 2: Change scheduler.6: STRICT → DWRR (w=20) + re-bind")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.6" "type" "DWRR"',
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.6" "weight" "20"',
        skip_error_check=True)
    # Re-bind: write QUEUE entry to trigger orchagent → set_queue_scheduler → DCHAL HW
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|6" "scheduler" "scheduler.6"'.format(
            port_info['egress']),
        skip_error_check=True)
    st.wait(2)

    # ── Step 3: Verify CONFIG_DB scheduler.6 type=DWRR weight=20 ──────────
    st.banner("STEP 3: Verify CONFIG_DB scheduler.6 type=DWRR weight=20")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.6"',
        skip_tmpl=True)
    actual_s6 = parse_redis_hgetall(out)
    st.log("  scheduler.6 after change: {}".format(actual_s6))
    if actual_s6.get('type') != 'DWRR' or actual_s6.get('weight') != '20':
        fail_msgs.append(
            "scheduler.6 after change: {}, expected type=DWRR weight=20".format(actual_s6))
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.7"',
        skip_tmpl=True)
    actual_s7 = parse_redis_hgetall(out)
    st.log("  scheduler.7 (must be unchanged STRICT): {}".format(actual_s7))
    if actual_s7.get('type') != 'STRICT':
        fail_msgs.append(
            "scheduler.7 unexpectedly changed: {}, expected STRICT".format(actual_s7))
    log_scheduler_state("After SG6 STRICT→DWRR")

    # ── Step 4: DCHAL check ────────────────────────────────────────────────
    st.banner("STEP 4: DCHAL check — Q6 DWRR ~10%, Q7 STRICT 0%, sum≈100%")
    _dchal_out = dchal_show_queuing(dut, "SG6 STRICT→DWRR", egress)
    _dchal_bw = validate_dchal_bw_vs_weights(
        "SG6 STRICT→DWRR", _dchal_out, w_sg6_dwrr, fail_msgs)

    # ── Step 5: IPv4 traffic ───────────────────────────────────────────────
    scheduler_traffic_check(
        "SG6 STRICT→DWRR [IPv4]", w_sg6_dwrr, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw, strict_queues=(7,),
        note="Q6 now DWRR w=20; only Q7 remains STRICT")

    # ── Step 6: IPv6 traffic ───────────────────────────────────────────────
    scheduler_traffic_check_v6(
        "SG6 STRICT→DWRR [IPv6]", w_sg6_dwrr, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw, strict_queues=(7,),
        note="Q6 now DWRR w=20; only Q7 remains STRICT")

    # ── Restore ────────────────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Final summary ──────────────────────────────────────────────────────
    print_scheduler_summary(checkpoint_summary)

    # ── Verdict ────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  CHANGE SG6 STRICT→DWRR — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Change SG6 STRICT→DWRR FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  CHANGE SG6 STRICT→DWRR — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  scheduler.6 STRICT→DWRR(w=20): DCHAL and traffic ratios correct")
        st.log("=" * 72)
        st.report_pass('msg',
            'Change SG6 STRICT→DWRR PASSED (IPv4 + IPv6): '
            'scheduler.6 changed to DWRR(w=20); DCHAL BW% and Tx-pkt ratios correct '
            'for 7-queue DWRR pool with Q7 as sole STRICT queue')


def test_fx3_sg5_dwrr_to_strict(setup_topo):
    """Change scheduler.5 from DWRR(w=30) to STRICT; verify DCHAL and 5-queue traffic.

    Steps:
      1. Verify FX3 baseline — scheduler.5 is DWRR weight=30
      2. Change scheduler.5: DWRR(w=30) → STRICT + re-bind QUEUE|5
      3. Verify CONFIG_DB scheduler.5 type=STRICT, no weight field
      4. DCHAL check — Q5 STRICT (prio=3), Q6/Q7 STRICT, Q0-Q4 DWRR redistribute
      5. IPv4 traffic: weight_map {0:20, 1:20, 2:20, 3:40, 4:40} (5-queue DWRR pool)
      6. IPv6 traffic
      7. Restore: config qos reload
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_fx3_sg5_dwrr_to_strict  [IPv4 + IPv6  dual-stack]\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Plan     : Baseline → DWRR→STRICT → DCHAL + 5-queue traffic → Restore".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'))
    )
    fail_msgs = []
    checkpoint_summary = {}

    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    # After SG5 DWRR→STRICT: Q5 joins STRICT chain (Q7>Q6>Q5), DWRR pool = Q0-Q4 only
    w_sg5_strict = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40}

    # ── Step 1: Verify baseline ────────────────────────────────────────────
    st.banner("STEP 1: Verify FX3 baseline — scheduler.5 is DWRR weight=30")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.5"',
        skip_tmpl=True)
    actual_s5 = parse_redis_hgetall(out)
    st.log("  scheduler.5 baseline: {}".format(actual_s5))
    if actual_s5.get('type') != 'DWRR' or actual_s5.get('weight') != '30':
        fail_msgs.append("Baseline: scheduler.5={}, expected type=DWRR weight=30".format(actual_s5))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg', 'SG5 DWRR→STRICT FAILED at baseline — scheduler.5 not DWRR(w=30)')
        return

    # ── Step 2: Change scheduler.5: DWRR(w=30) → STRICT ──────────────────
    st.banner("STEP 2: Change scheduler.5: DWRR(w=30) → STRICT + re-bind")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.5" "type" "STRICT"',
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "SCHEDULER|scheduler.5" "weight"',
        skip_error_check=True)
    # Unbind Q5 first (HDEL generates a real deletion event for the orchagent so it
    # processes the unbind, setting Q5's SAI scheduler_profile_id to NULL).
    # The subsequent HSET then creates a NEW field (Redis returns 1, not 0) triggering
    # a fresh bind with old=NULL → new=sched5_oid (different-OID path). This correctly
    # calls program_dwrr_queues_scheduling_to_hw with Q5 excluded from the DWRR pool,
    # so Q0-Q4 DCHAL BW% are recalibrated to the new total_weight=140 percentages.
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|5" "scheduler"'.format(port_info['egress']),
        skip_error_check=True)
    st.wait(1)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|5" "scheduler" "scheduler.5"'.format(
            port_info['egress']),
        skip_error_check=True)
    st.wait(2)

    # ── Step 3: Verify CONFIG_DB scheduler.5 type=STRICT, no weight ───────
    st.banner("STEP 3: Verify CONFIG_DB scheduler.5 type=STRICT, no weight; "
              "scheduler.6/7 unchanged; QUEUE|5 binding intact")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.5"',
        skip_tmpl=True)
    actual_s5 = parse_redis_hgetall(out)
    st.log("  scheduler.5 after change: {}".format(actual_s5))
    if actual_s5.get('type') != 'STRICT':
        fail_msgs.append(
            "scheduler.5 type='{}' after change, expected 'STRICT'".format(
                actual_s5.get('type', '')))
    if 'weight' in actual_s5:
        fail_msgs.append(
            "scheduler.5 still has weight='{}' after STRICT change".format(
                actual_s5.get('weight')))

    # Verify scheduler.6 and scheduler.7 are still STRICT and unmodified
    for sname in ('scheduler.6', 'scheduler.7'):
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(sname),
            skip_tmpl=True)
        actual = parse_redis_hgetall(out)
        st.log("  {} (must be unchanged STRICT): {}".format(sname, actual))
        if actual.get('type') != 'STRICT':
            fail_msgs.append(
                "{} unexpectedly changed: {}, expected STRICT".format(sname, actual))

    # Confirm QUEUE|5 binding is still present after HDEL+HSET sequence
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|5" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q5 = parse_redis_hget(out).strip()
    st.log("  QUEUE|{}|5 binding after HDEL+HSET: '{}'  expected 'scheduler.5'  {}".format(
        egress, actual_q5, "OK" if actual_q5 == 'scheduler.5' else "MISMATCH"))
    if actual_q5 != 'scheduler.5':
        fail_msgs.append(
            "QUEUE|{}|5 binding='{}' after re-bind, expected 'scheduler.5'".format(
                egress, actual_q5))

    log_scheduler_state("After SG5 DWRR→STRICT")

    # ── Step 4: DCHAL check ────────────────────────────────────────────────
    st.banner("STEP 4: DCHAL check — Q5 STRICT prio=3; DWRR pool is Q0-Q4 only")
    _dchal_out = dchal_show_queuing(dut, "SG5 DWRR→STRICT", egress)
    _dchal_bw = validate_dchal_bw_vs_weights(
        "SG5 DWRR→STRICT", _dchal_out, w_sg5_strict, fail_msgs)

    # ── Step 5: IPv4 traffic ───────────────────────────────────────────────
    scheduler_traffic_check(
        "SG5 DWRR→STRICT [IPv4]", w_sg5_strict, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw, strict_queues=(5, 6, 7),
        note="Q5 now STRICT; STRICT chain Q7>Q6>Q5; DWRR pool is Q0-Q4 only")

    # ── Step 6: IPv6 traffic ───────────────────────────────────────────────
    scheduler_traffic_check_v6(
        "SG5 DWRR→STRICT [IPv6]", w_sg5_strict, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw, strict_queues=(5, 6, 7),
        note="Q5 now STRICT; STRICT chain Q7>Q6>Q5; DWRR pool is Q0-Q4 only")

    # ── Restore ────────────────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Final summary ──────────────────────────────────────────────────────
    print_scheduler_summary(checkpoint_summary)

    # ── Verdict ────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  SG5 DWRR→STRICT — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'SG5 DWRR→STRICT FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  SG5 DWRR→STRICT — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  scheduler.5 DWRR(w=30)→STRICT: STRICT chain Q7>Q6>Q5; Q0-Q4 DWRR redistribute")
        st.log("=" * 72)
        st.report_pass('msg',
            'SG5 DWRR→STRICT PASSED (IPv4 + IPv6): scheduler.5 changed to STRICT; '
            'DCHAL and traffic ratios correct for Q0-Q4 DWRR pool')


def test_fx3_unbind_dwrr_sg2(setup_topo):
    """Unbind Q2 from its scheduler; verify remaining DWRR queues Q0/Q1/Q3/Q4/Q5 redistribute.

    Steps:
      1. Verify FX3 baseline — Q2 is bound to scheduler.2
      2. Unbind Q2 — HDEL QUEUE|<egress>|2 scheduler
      3. Verify Q2 has no scheduler binding; Q0/Q1/Q3/Q4/Q5 unchanged
      4. DCHAL check — Q2 drops to ~0% (fallback token); Q0/Q1/Q3/Q4/Q5 redistribute
      5. IPv4 traffic: weight_map {0:20, 1:20, 3:40, 4:40, 5:30} (Q2 excluded)
      6. IPv6 traffic
      7. Restore: config qos reload
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_fx3_unbind_dwrr_sg2  [IPv4 + IPv6  dual-stack]\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Plan     : Baseline → Unbind Q2 → DCHAL + Q0/Q1/Q3/Q4/Q5 traffic → Restore".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'))
    )
    fail_msgs = []
    checkpoint_summary = {}

    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    # After unbind Q2: remaining DWRR queues are Q0/Q1/Q3/Q4/Q5
    w_unbind_q2 = {0: 20, 1: 20, 3: 40, 4: 40, 5: 30}

    # ── Step 1: Verify baseline ────────────────────────────────────────────
    st.banner("STEP 1: Verify FX3 baseline — Q2 is bound to scheduler.2")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|2" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q2 = parse_redis_hget(out).strip()
    st.log("  Q2 baseline binding: '{}'  expected 'scheduler.2'".format(actual_q2))
    if actual_q2 != 'scheduler.2':
        fail_msgs.append("Baseline: QUEUE|{}|2 = '{}', expected 'scheduler.2'".format(
            egress, actual_q2))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg', 'Unbind DWRR SG2 FAILED at baseline — Q2 not bound to scheduler.2')
        return

    # ── Step 2: Unbind Q2 ─────────────────────────────────────────────────
    st.banner("STEP 2: Unbind Q2 — HDEL QUEUE|{}|2 scheduler".format(egress))
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|2" "scheduler"'.format(egress),
        skip_error_check=True)
    st.wait(2)

    # ── Step 3: Verify Q2 unbound; others unchanged ────────────────────────
    st.banner("STEP 3: Verify Q2 has no scheduler binding in CONFIG_DB")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|2" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q2 = parse_redis_hget(out).strip()
    st.log("  Q2 binding after HDEL: '{}'  (expected empty)".format(actual_q2))
    if actual_q2:
        fail_msgs.append("After unbind: QUEUE|{}|2 still has scheduler='{}'".format(
            egress, actual_q2))
    for qi in [0, 1, 3, 4, 5, 6, 7]:
        expected_sched = 'scheduler.{}'.format(qi)
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        if actual != expected_sched:
            fail_msgs.append("After Q2 unbind: Q{} binding='{}', expected '{}' (should be unchanged)".format(
                qi, actual, expected_sched))

    # ── Step 4: DCHAL check after Q2 unbind ──────────────────────────────
    st.banner("STEP 4: DCHAL check — Q2 at default ~0%; Q0/Q1/Q3/Q4/Q5 redistribute")
    _dchal_out = dchal_show_queuing(dut, "After Q2 unbind", egress)
    validate_dchal_bw_vs_weights("After Q2 unbind (Q0/Q1/Q3/Q4/Q5 only)", _dchal_out,
                                 w_unbind_q2, fail_msgs)

    # ── Step 5: IPv4 traffic ───────────────────────────────────────────────
    scheduler_traffic_check(
        "After Q2 unbind [IPv4]", w_unbind_q2, fail_msgs, checkpoint_summary,
        macs, dchal_bw=None,
        note="Q2 unbound — validating Q0/Q1/Q3/Q4/Q5 ratios only")

    # ── Step 6: IPv6 traffic ───────────────────────────────────────────────
    scheduler_traffic_check_v6(
        "After Q2 unbind [IPv6]", w_unbind_q2, fail_msgs, checkpoint_summary,
        macs, dchal_bw=None,
        note="Q2 unbound — validating Q0/Q1/Q3/Q4/Q5 ratios only")

    # ── Restore ────────────────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Final summary ──────────────────────────────────────────────────────
    print_scheduler_summary(checkpoint_summary)

    # ── Verdict ────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  UNBIND DWRR SG2 — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Unbind DWRR SG2 FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  UNBIND DWRR SG2 — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  Q2 unbound; DCHAL BW% and Tx-pkt ratios for remaining DWRR queues "
               "(Q0/Q1/Q3/Q4/Q5) match expected weights")
        st.log("=" * 72)
        st.report_pass('msg',
            'Unbind DWRR SG2 PASSED (IPv4 + IPv6): '
            'Q2 unbound; DCHAL BW% and Tx-pkt ratios for remaining DWRR queues '
            '(Q0/Q1/Q3/Q4/Q5) match expected weights')


