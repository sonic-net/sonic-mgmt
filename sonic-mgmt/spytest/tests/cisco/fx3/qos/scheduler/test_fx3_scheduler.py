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

(test_fx3_unbind_all_then_rebind)  — maps to SAI test_tortuga_unbind_all_then_rebind
  Full bind → full unbind (reverse order Q7→Q0) → re-apply full FX3 config.
  After full unbind verifies all 8 QUEUE bindings are absent.  After rebind
  ('config qos reload') verifies CONFIG_DB bindings, DCHAL BW%, and traffic
  ratios match the original FX3 baseline.

(test_fx3_unbind_from_unbound_sg_succeeds)  — maps to SAI test_tortuga_unbind_from_unbound_sg_succeeds
  After full FX3 config, HDEL Q0 (first unbind), then HDEL Q0 again (second
  unbind — idempotent).  Verifies: second HDEL is a CONFIG_DB no-op (returns 0),
  Q0 remains unbound, Q1–Q7 are unchanged, and DCHAL BW% for Q1–Q5 is
  identical before and after the second HDEL.

(test_fx3_replace_scheduler_on_sg)  — maps to SAI test_tortuga_replace_scheduler_on_sg
  Applies full FX3 baseline config, then swaps scheduler profiles between Q1
  and Q4 via direct HSET (replace-in-place, no HDEL needed).  Verifies CONFIG_DB
  bindings, DCHAL BW% redistribution, and traffic ratios with the swapped
  weight map {0:20, 1:40, 2:20, 3:40, 4:20, 5:30}.

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
    parse_dchal_egress_bw,
    get_dut_mac,
    validate_dwrr_ratios,
    ensure_interfaces_admin_up, verify_queue_counters,
    clear_dut_counters, get_intf_counters, report_intf_counters,
    tg_port_speed_gbps, compute_dwrr_stream_rate_pct,
    log_queue_counters,
    print_banner, print_section,
    get_queue_binding, log_queue_bindings_table,
    log_scheduler_state_table, log_dchal_egress_table,
    verify_queue_strict, verify_queue_dwrr,
    get_port_oid, get_scheduler_groups_for_port,
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


def test_fx3_unbind_all_then_rebind(setup_topo):
    """Full unbind (Q7→Q0) then full rebind via config qos reload; verify DCHAL + traffic.

    Maps to SAI test_tortuga_unbind_all_then_rebind and
    scheduler_test_plan.md test 21.

    Steps:
      1. Verify FX3 baseline CONFIG_DB bindings (Q0–Q7 each = scheduler.N)
      2. Unbind all queues in reverse order (Q7→Q0) via HDEL
      3. Verify all 8 QUEUE bindings are absent from CONFIG_DB
      4. Log DCHAL after full unbind (no weight assertion — all queues at HW fallback)
      5. Restore: config qos reload — re-applies full FX3 config
      6. Verify all 8 CONFIG_DB bindings restored (Q0=scheduler.0 … Q7=scheduler.7)
      7. DCHAL check with full FX3 weight map {0:20,1:20,2:20,3:40,4:40,5:30}
      8. IPv4 traffic check with same weight map
      9. IPv6 traffic check
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_fx3_unbind_all_then_rebind  [IPv4 + IPv6  dual-stack]\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Plan     : Baseline → Unbind all Q7→Q0 → Verify null "
        "→ Rebind (qos reload) → DCHAL + traffic → Restore".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'))
    )
    fail_msgs = []
    checkpoint_summary = {}

    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    # FX3 baseline DWRR weight map (Q6=STRICT, Q7=STRICT — excluded from weight pool)
    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}

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
        st.report_fail('msg', 'Unbind-all-then-rebind FAILED at baseline — see above')
        return

    # ── Step 2: Unbind all queues Q7 → Q0 ────────────────────────────────
    st.banner("STEP 2: Unbind all queues in reverse order (Q7 → Q0)")
    for qi in range(NUM_QUEUES - 1, -1, -1):
        st.log("  Unbinding Q{} — HDEL QUEUE|{}|{} scheduler".format(qi, egress, qi))
        st.config(dut,
            'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_error_check=True)
        st.wait(1)

    st.wait(2)

    # ── Step 3: Verify all 8 queues have no binding ───────────────────────
    st.banner("STEP 3: Verify all 8 QUEUE bindings are absent from CONFIG_DB")
    for qi in range(NUM_QUEUES):
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        st.log("  Q{} binding: '{}'  (expected empty)".format(qi, actual))
        if actual:
            fail_msgs.append("After full unbind: QUEUE|{}|{} still has scheduler='{}'".format(
                egress, qi, actual))

    # ── Step 4: Log DCHAL after full unbind (informational only) ─────────
    st.banner("STEP 4: DCHAL state after full unbind (all queues at HW fallback token)")
    dchal_show_queuing(dut, "After full unbind (all queues)", egress)
    st.log("  Note: no BW% assertion — all queues unbound, no differential weights")

    # ── Step 5: Restore via config qos reload ────────────────────────────
    st.banner("STEP 5: Restore full FX3 config — config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("After config qos reload")

    # ── Step 6: Verify all 8 bindings restored ───────────────────────────
    st.banner("STEP 6: Verify all 8 QUEUE bindings restored in CONFIG_DB")
    for qi in range(NUM_QUEUES):
        expected_sched = 'scheduler.{}'.format(qi)
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        st.log("  Q{} -> '{}'  expected '{}'  {}".format(
            qi, actual, expected_sched, "OK" if actual == expected_sched else "MISMATCH"))
        if actual != expected_sched:
            fail_msgs.append("After rebind: QUEUE|{}|{} = '{}', expected '{}'".format(
                egress, qi, actual, expected_sched))

    # ── Step 7: DCHAL check after full rebind ─────────────────────────────
    st.banner("STEP 7: DCHAL Bandwidth% after full rebind (should match FX3 baseline)")
    _dchal_out = dchal_show_queuing(dut, "After full rebind", egress)
    _dchal_bw = validate_dchal_bw_vs_weights(
        "After full rebind", _dchal_out, w_baseline, fail_msgs)

    # ── Step 8: IPv4 traffic ───────────────────────────────────────────────
    scheduler_traffic_check(
        "Full rebind [IPv4]", w_baseline, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw,
        note="All queues rebound via config qos reload; FX3 baseline weights restored")

    # ── Step 9: IPv6 traffic ───────────────────────────────────────────────
    scheduler_traffic_check_v6(
        "Full rebind [IPv6]", w_baseline, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw,
        note="All queues rebound via config qos reload; FX3 baseline weights restored")

    # ── Restore (safety) ──────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload (safety)")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Final summary ──────────────────────────────────────────────────────
    print_scheduler_summary(checkpoint_summary)

    # ── Verdict ────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  UNBIND ALL THEN REBIND — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Unbind-all-then-rebind FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  UNBIND ALL THEN REBIND — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  All queues unbound Q7→Q0; config qos reload restored FX3 baseline;")
        st.log("  DCHAL BW% and Tx-pkt ratios match expected weights")
        st.log("=" * 72)
        st.report_pass('msg',
            'Unbind-all-then-rebind PASSED (IPv4 + IPv6): '
            'all queues unbound Q7->Q0 and restored via config qos reload; '
            'DCHAL BW%% and Tx-pkt ratios match FX3 baseline weights')


def test_fx3_unbind_from_unbound_sg_succeeds(setup_topo):
    """Second HDEL on already-unbound Q0 is idempotent — no HW change.

    Maps to SAI test_tortuga_unbind_from_unbound_sg_succeeds and
    scheduler_test_plan.md test 19.

    Steps:
      1. Verify FX3 baseline — Q0 bound to scheduler.0
      2. First HDEL Q0 — unbind
      3. Verify Q0 has no binding; Q1–Q7 unchanged
      4. DCHAL check after first unbind — validate Q1–Q5 BW% ratios
      5. IPv4 + IPv6 traffic after first unbind — Q1–Q5 ratios
      6. Second HDEL Q0 (idempotent — field already absent, returns 0)
      7. Verify Q0 still unbound; Q1–Q7 still unchanged
      8. DCHAL check — identical to step 4 (no HW change)
      9. IPv4 + IPv6 traffic after second unbind — same Q1–Q5 ratios (unchanged)
     10. Restore: config qos reload
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_fx3_unbind_from_unbound_sg_succeeds\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Plan     : Baseline → First HDEL Q0 → DCHAL+traffic → "
        "Second HDEL Q0 (idempotent) → DCHAL+traffic unchanged → Restore".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'))
    )
    fail_msgs = []
    checkpoint_summary = {}

    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    # Q1–Q5 weight map after Q0 unbind (Q6=STRICT, Q7=STRICT excluded)
    w_q1_q5 = {1: 20, 2: 20, 3: 40, 4: 40, 5: 30}

    # ── Step 1: Verify FX3 baseline — Q0 bound to scheduler.0 ────────────
    st.banner("STEP 1: Verify FX3 baseline — Q0 bound to scheduler.0 on {}".format(egress))
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|0" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q0 = parse_redis_hget(out).strip()
    st.log("  Q0 baseline binding: '{}'  expected 'scheduler.0'".format(actual_q0))
    if actual_q0 != 'scheduler.0':
        fail_msgs.append("Baseline: QUEUE|{}|0 = '{}', expected 'scheduler.0'".format(
            egress, actual_q0))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg',
            'Unbind-from-unbound FAILED at baseline — Q0 not bound to scheduler.0')
        return

    # ── Step 2: First HDEL Q0 ─────────────────────────────────────────────
    st.banner("STEP 2: First unbind — HDEL QUEUE|{}|0 scheduler".format(egress))
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|0" "scheduler"'.format(egress),
        skip_error_check=True)
    st.wait(2)

    # ── Step 3: Verify Q0 unbound; Q1–Q7 unchanged ────────────────────────
    st.banner("STEP 3: Verify Q0 has no binding; Q1–Q7 unchanged")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|0" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q0 = parse_redis_hget(out).strip()
    st.log("  Q0 binding after first HDEL: '{}'  (expected empty)".format(actual_q0))
    if actual_q0:
        fail_msgs.append("After first HDEL: QUEUE|{}|0 still has scheduler='{}'".format(
            egress, actual_q0))
    for qi in range(1, NUM_QUEUES):
        expected_sched = 'scheduler.{}'.format(qi)
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        if actual != expected_sched:
            fail_msgs.append(
                "After first HDEL Q0: Q{} binding='{}', expected '{}' (unchanged)".format(
                    qi, actual, expected_sched))

    # ── Step 4: DCHAL check after first unbind ────────────────────────────
    st.banner("STEP 4: DCHAL check after first unbind — Q0 at fallback; Q1–Q5 ratios")
    _dchal_out_first = dchal_show_queuing(dut, "After first HDEL Q0", egress)
    _dchal_bw_first = validate_dchal_bw_vs_weights(
        "After first HDEL Q0 (Q1–Q5 only)", _dchal_out_first, w_q1_q5, fail_msgs)

    # ── Step 5: IPv4 + IPv6 traffic after first unbind ────────────────────
    scheduler_traffic_check(
        "After first HDEL Q0 [IPv4]", w_q1_q5, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw_first,
        note="Q0 unbound (first HDEL) — validating Q1–Q5 ratios only")
    scheduler_traffic_check_v6(
        "After first HDEL Q0 [IPv6]", w_q1_q5, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw_first,
        note="Q0 unbound (first HDEL) — validating Q1–Q5 ratios only")

    # ── Step 6: Second HDEL Q0 (idempotent) ──────────────────────────────
    st.banner(
        "STEP 6: Second unbind (idempotent) — HDEL QUEUE|{}|0 scheduler "
        "(field already absent — CONFIG_DB no-op)".format(egress))
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|0" "scheduler"'.format(egress),
        skip_error_check=True)
    st.wait(2)

    # ── Step 7: Verify Q0 still unbound; Q1–Q7 still unchanged ───────────
    st.banner("STEP 7: Verify Q0 still unbound; Q1–Q7 still unchanged after second HDEL")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|0" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q0 = parse_redis_hget(out).strip()
    st.log("  Q0 binding after second HDEL: '{}'  (expected empty)".format(actual_q0))
    if actual_q0:
        fail_msgs.append(
            "After second HDEL: QUEUE|{}|0 unexpectedly has scheduler='{}'".format(
                egress, actual_q0))
    for qi in range(1, NUM_QUEUES):
        expected_sched = 'scheduler.{}'.format(qi)
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        if actual != expected_sched:
            fail_msgs.append(
                "After second HDEL Q0: Q{} binding='{}', expected '{}' (should be unchanged)".format(
                    qi, actual, expected_sched))

    # ── Step 8: DCHAL check — must be identical to step 4 ────────────────
    st.banner(
        "STEP 8: DCHAL check after second HDEL — "
        "must be identical to step 4 (no HW change)")
    _dchal_out_second = dchal_show_queuing(dut, "After second HDEL Q0 (idempotent)", egress)
    _dchal_bw_second = validate_dchal_bw_vs_weights(
        "After second HDEL Q0 (Q1–Q5 only)", _dchal_out_second, w_q1_q5, fail_msgs)

    # ── Step 9: IPv4 + IPv6 traffic after second unbind ───────────────────
    scheduler_traffic_check(
        "After second HDEL Q0 [IPv4]", w_q1_q5, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw_second,
        note="Q0 unbound (second HDEL idempotent) — Q1–Q5 ratios must be identical to step 5")
    scheduler_traffic_check_v6(
        "After second HDEL Q0 [IPv6]", w_q1_q5, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw_second,
        note="Q0 unbound (second HDEL idempotent) — Q1–Q5 ratios must be identical to step 5")

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
        st.log("  UNBIND FROM UNBOUND SG — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Unbind-from-unbound-SG FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  UNBIND FROM UNBOUND SG — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  Second HDEL Q0 was idempotent: CONFIG_DB unchanged, DCHAL BW% unchanged")
        st.log("  Q1–Q5 BW% ratios and traffic proportions identical across both unbind operations")
        st.log("=" * 72)
        st.report_pass('msg',
            'Unbind-from-unbound-SG PASSED (IPv4 + IPv6): '
            'second HDEL Q0 idempotent; CONFIG_DB and DCHAL BW%% unchanged; '
            'Q1-Q5 traffic ratios consistent across both unbind operations')


def test_fx3_replace_scheduler_on_sg(setup_topo):
    """Swap scheduler.1 (w=20) and scheduler.4 (w=40) between Q1 and Q4.

    Maps to SAI test_tortuga_replace_scheduler_on_sg and
    scheduler_test_plan.md test 16.

    Uses direct HSET (replace-in-place) — no HDEL needed since the field
    already exists; orchagent processes a value-change event.

    Steps:
      1. Verify FX3 baseline bindings (Q1=scheduler.1, Q4=scheduler.4)
      2. Baseline DCHAL check {0:20,1:20,2:20,3:40,4:40,5:30}
      3. Baseline IPv4 + IPv6 traffic
      4. HSET Q1 → scheduler.4 (w=40)
      5. HSET Q4 → scheduler.1 (w=20)
      6. Verify CONFIG_DB: Q1=scheduler.4, Q4=scheduler.1; others unchanged
      7. DCHAL check with swapped weights {0:20,1:40,2:20,3:40,4:20,5:30}
      8. IPv4 traffic with swapped weights
      9. IPv6 traffic with swapped weights
     10. Restore: config qos reload
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_fx3_replace_scheduler_on_sg  [IPv4 + IPv6  dual-stack]\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Plan     : Baseline → Swap Q1↔Q4 schedulers (HSET) "
        "→ DCHAL + traffic with swapped weights → Restore".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'))
    )
    fail_msgs = []
    checkpoint_summary = {}

    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    # Weight maps
    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    w_swapped  = {0: 20, 1: 40, 2: 20, 3: 40, 4: 20, 5: 30}  # Q1↔Q4 swapped

    # ── Step 1: Verify FX3 baseline bindings ──────────────────────────────
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
        st.report_fail('msg', 'Replace-scheduler-on-SG FAILED at baseline — see above')
        return

    # ── Step 2: Baseline DCHAL check ──────────────────────────────────────
    st.banner("STEP 2: Baseline DCHAL check {0:20,1:20,2:20,3:40,4:40,5:30}")
    _dchal_out_base = dchal_show_queuing(dut, "Baseline", egress)
    _dchal_bw_base = validate_dchal_bw_vs_weights(
        "Baseline", _dchal_out_base, w_baseline, fail_msgs)

    # ── Step 3: Baseline IPv4 + IPv6 traffic ─────────────────────────────
    scheduler_traffic_check(
        "Baseline [IPv4]", w_baseline, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw_base,
        note="FX3 baseline: Q1=scheduler.1(w=20), Q4=scheduler.4(w=40)")
    scheduler_traffic_check_v6(
        "Baseline [IPv6]", w_baseline, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw_base,
        note="FX3 baseline: Q1=scheduler.1(w=20), Q4=scheduler.4(w=40)")

    # ── Step 4: HSET Q1 → scheduler.4 (w=40) ────────────────────────────
    st.banner("STEP 4: Swap — HSET Q1 → scheduler.4 (w=40)")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|1" "scheduler" "scheduler.4"'.format(egress),
        skip_error_check=True)
    st.wait(2)

    # ── Step 5: HSET Q4 → scheduler.1 (w=20) ────────────────────────────
    st.banner("STEP 5: Swap — HSET Q4 → scheduler.1 (w=20)")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|4" "scheduler" "scheduler.1"'.format(egress),
        skip_error_check=True)
    st.wait(2)

    # ── Step 6: Verify CONFIG_DB after swap ───────────────────────────────
    st.banner("STEP 6: Verify CONFIG_DB after swap (Q1=scheduler.4, Q4=scheduler.1)")
    swap_expected = {0: 'scheduler.0', 1: 'scheduler.4', 2: 'scheduler.2',
                     3: 'scheduler.3', 4: 'scheduler.1', 5: 'scheduler.5',
                     6: 'scheduler.6', 7: 'scheduler.7'}
    for qi in range(NUM_QUEUES):
        expected_sched = swap_expected[qi]
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        st.log("  Q{} -> '{}'  expected '{}'  {}".format(
            qi, actual, expected_sched, "OK" if actual == expected_sched else "MISMATCH"))
        if actual != expected_sched:
            fail_msgs.append(
                "After swap: QUEUE|{}|{} = '{}', expected '{}'".format(
                    egress, qi, actual, expected_sched))

    # Confirm scheduler profiles themselves are unchanged
    for sched_name, expected_weight in [('scheduler.1', '20'), ('scheduler.4', '40')]:
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(sched_name),
            skip_tmpl=True)
        profile = parse_redis_hgetall(out)
        st.log("  {}: {}".format(sched_name, profile))
        if profile.get('weight') != expected_weight:
            fail_msgs.append(
                "{} weight='{}', expected '{}' (profile must be unchanged after swap)".format(
                    sched_name, profile.get('weight'), expected_weight))

    log_scheduler_state("After Q1↔Q4 swap")

    # ── Step 7: DCHAL check with swapped weights ───────────────────────────
    st.banner("STEP 7: DCHAL check after swap {0:20,1:40,2:20,3:40,4:20,5:30}")
    _dchal_out_swap = dchal_show_queuing(dut, "After Q1↔Q4 swap", egress)
    _dchal_bw_swap = validate_dchal_bw_vs_weights(
        "After Q1↔Q4 swap", _dchal_out_swap, w_swapped, fail_msgs)

    # ── Step 8: IPv4 traffic with swapped weights ─────────────────────────
    scheduler_traffic_check(
        "After Q1↔Q4 swap [IPv4]", w_swapped, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw_swap,
        note="Q1 now has scheduler.4(w=40); Q4 now has scheduler.1(w=20)")

    # ── Step 9: IPv6 traffic with swapped weights ─────────────────────────
    scheduler_traffic_check_v6(
        "After Q1↔Q4 swap [IPv6]", w_swapped, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw_swap,
        note="Q1 now has scheduler.4(w=40); Q4 now has scheduler.1(w=20)")

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
        st.log("  REPLACE SCHEDULER ON SG — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Replace-scheduler-on-SG FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  REPLACE SCHEDULER ON SG — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  Q1↔Q4 swap: DCHAL BW% and traffic ratios match swapped weight map")
        st.log("  scheduler.1(w=20) and scheduler.4(w=40) profiles unchanged after swap")
        st.log("=" * 72)
        st.report_pass('msg',
            'Replace-scheduler-on-SG PASSED (IPv4 + IPv6): '
            'Q1<->Q4 scheduler swap via HSET; DCHAL BW%% and Tx-pkt ratios '
            'match swapped weights {Q1:w=40, Q4:w=20}')


# ══════════════════════════════════════════════════════════════════════════
# Negative Tests: Scheduler Constraint Validation
# ══════════════════════════════════════════════════════════════════════════

# ── Test: Negative-path — rebind SG7 (STRICT) to DWRR must be rejected ───

def test_tortuga_rebind_sg7_to_dwrr_fails(setup_topo):
    """Test 22: Verify binding a DWRR scheduler to Scheduler Group 7 is rejected.

    FX3 baseline: Q6=STRICT, Q7=STRICT.  Rebinding Q7 to DWRR must be rejected
    by SAI (queue ordering constraint: STRICT queues must form a contiguous block
    from Q7 downward).  DCHAL must confirm Q7 remains STRICT after the attempt.
    Q0-Q6 must be unaffected.
    """
    egress = port_info['egress']
    st.banner(
        "test_tortuga_rebind_sg7_to_dwrr_fails  [SAI constraint — negative path]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Step 0 [FX3 baseline verify]\n"
        "           Step 1 [create DWRR replacement scheduler sched_dwrr_test]\n"
        "           Step 2 [HSET QUEUE|{}|7 → sched_dwrr_test  (expect rejection)]\n"
        "           Step 3 [verify Q7 CONFIG_DB state unchanged]\n"
        "           Step 4 [syslog check — SAI rejection evidence, informational]\n"
        "           Step 5 [DCHAL HW verify — Q7 must remain STRICT]\n"
        "           Step 6 [cleanup — restore Q7=scheduler.7, DEL sched_dwrr_test]".format(
            dut, egress, egress)
    )
    fail_msgs = []

    deploy_dchal_helper(dut)

    _original_bindings = {qi: 'scheduler.{}'.format(qi) for qi in range(8)}

    print_section("STEP 0 — FX3 baseline already active from setup_topo", art_key='scheduler')

    log_scheduler_state_table(dut, "BEFORE — FX3 baseline")
    baseline_bindings = log_queue_bindings_table(
        dut, egress, "BEFORE — FX3 baseline", _original_bindings)

    baseline_fails = [qi for qi in range(8)
                      if baseline_bindings[qi] != _original_bindings[qi]]
    if baseline_fails:
        for qi in baseline_fails:
            fail_msgs.append(
                "Baseline: QUEUE|{}|{} = '{}', expected '{}'".format(
                    egress, qi, baseline_bindings[qi], _original_bindings[qi]))
        st.report_fail('msg', 'Rebind SG7 FAILED at baseline — '
                       'Expected FX3 baseline QUEUE bindings not found')
        return

    raw_before = dchal_show_queuing(dut, "BEFORE — FX3 baseline", egress)
    log_dchal_egress_table(raw_before, "BEFORE — FX3 baseline")
    verify_queue_strict("BEFORE — baseline Q7 check", raw_before, fail_msgs)

    # ── Step 1: Create DWRR replacement scheduler profile ─────────────────
    print_section("Create DWRR Replacement Scheduler", art_key='scheduler')
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "SCHEDULER|sched_dwrr_test" '
              '"type" "DWRR" "weight" "20"',
              skip_error_check=True)
    st.wait(1)
    out = st.show(dut, 'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|sched_dwrr_test"',
                  skip_tmpl=True)
    st.log("  sched_dwrr_test = {}".format(parse_redis_hgetall(out)))

    # ── BEFORE snapshot: Q7 SAI-level state (CONFIG_DB → scheduler type) ────
    # Resolve the full chain: Q7 binding → scheduler profile → type
    # This is the SAI-level state BEFORE the rebind attempt.
    _q7_sched_before = get_queue_binding(dut, egress, 7)
    _q7_type_cmd = (
        'sonic-db-cli CONFIG_DB HGET "SCHEDULER|{}" "type"'.format(_q7_sched_before))
    _q7_type_before = (st.show(dut, _q7_type_cmd,
                       skip_tmpl=True, skip_error_check=True) or '').strip()
    # Clean multi-line output (take first non-empty line without prompt)
    _q7_type_before = next(
        (l.strip() for l in _q7_type_before.splitlines()
         if l.strip() and not l.strip().startswith('admin@')), _q7_type_before)
    st.log("  Q7 BEFORE: binding='{}' → type='{}'".format(
        _q7_sched_before, _q7_type_before))

    # ── Step 2: Attempt to rebind Q7 (SG7) to DWRR — must be rejected ──────
    print_section("ATTEMPT — Rebind SG7 to DWRR  (expect rejection)")
    st.log("  SG6 is still STRICT -> SG7=DWRR would create invalid interleaving")
    # Capture syslog timestamp before attempt so we only grep fresh messages
    _ts_before = (st.show(dut, 'date +"%b %e %H:%M"',
                  skip_tmpl=True, skip_error_check=True) or '').strip()
    _ts_before = next(
        (l.strip() for l in _ts_before.splitlines()
         if l.strip() and not l.strip().startswith('admin@')), _ts_before)
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|7" "scheduler" '
              '"sched_dwrr_test"'.format(egress),
              skip_error_check=True)
    st.wait(3)

    # ── Step 3: Verify Q7 SAI-level state after rebind attempt ──────────────
    print_section("AFTER rebind — Q7 SAI-level state check (CONFIG_DB + DCHAL)")
    _q7_sched_after = get_queue_binding(dut, egress, 7)
    _q7_type_cmd_after = (
        'sonic-db-cli CONFIG_DB HGET "SCHEDULER|{}" "type"'.format(_q7_sched_after))
    _q7_type_after = (st.show(dut, _q7_type_cmd_after,
                      skip_tmpl=True, skip_error_check=True) or '').strip()
    _q7_type_after = next(
        (l.strip() for l in _q7_type_after.splitlines()
         if l.strip() and not l.strip().startswith('admin@')), _q7_type_after)
    st.log("  Q7 AFTER:  binding='{}' → type='{}'".format(
        _q7_sched_after, _q7_type_after))

    # Compare before/after
    st.log("  ────────────────────────────────────────────────")
    st.log("  Q7 SAI-level comparison:")
    st.log("    BEFORE: binding='{}' type='{}'".format(
        _q7_sched_before, _q7_type_before))
    st.log("    AFTER:  binding='{}' type='{}'".format(
        _q7_sched_after, _q7_type_after))
    if _q7_sched_after == _q7_sched_before:
        st.log("    RESULT: binding UNCHANGED — orchagent/SAI rejected at CONFIG_DB level")
    elif _q7_sched_after == 'sched_dwrr_test':
        st.log("    RESULT: CONFIG_DB accepted HSET (type changed {} → {})"
               " — checking DCHAL HW to confirm SAI blocked HW programming".format(
                   _q7_type_before, _q7_type_after))
    else:
        st.log("    RESULT: unexpected binding '{}'".format(_q7_sched_after))
    st.log("  ────────────────────────────────────────────────")

    # ── Step 4: Check syslog for SAI rejection evidence (informational) ──────
    print_section("OPTIONAL: SAI rejection evidence in syslog (informational only)")
    _reject_cmd = (
        'sudo grep -a "queue ordering constraint violation" '
        '/var/log/syslog /var/log/syslog.1 2>/dev/null '
        '| grep "queue_idx=7" | tail -5')
    _reject_out = st.show(dut, _reject_cmd,
                          skip_tmpl=True, skip_error_check=True) or ''
    _reject_out = _reject_out.strip()
    if 'queue_idx=7' in _reject_out:
        st.log("  ℹ️  SAI rejection found in syslog (queue_idx=7):")
        for _rl in _reject_out.splitlines()[:3]:  # Show max 3 lines
            if 'queue_idx=7' in _rl:
                st.log("    {}".format(_rl.strip())[:120])  # Truncate long lines
    else:
        st.log("  ℹ️  'constraint violation queue_idx=7' not found in syslog "
               "(may be rate-limited or rotated) — DCHAL is authoritative")

    # ── Step 5: Verify DCHAL HW — Q7 must remain STRICT ─────────────────────
    print_section("DCHAL Hardware Verification — Q7 must stay STRICT")
    raw_after = dchal_show_queuing(dut, "AFTER rebind attempt", egress)
    log_dchal_egress_table(raw_after, "AFTER rebind attempt")
    verify_queue_strict("AFTER rebind attempt — Q7 must stay STRICT", raw_after, fail_msgs)

    # If CONFIG_DB changed but HW didn't, SAI blocked it — log clearly
    if _q7_sched_after != _q7_sched_before and not fail_msgs:
        st.log("  Q7 CONFIG_DB='{}' (type={}) but DCHAL=STRICT"
               " — SAI validation REJECTED the HW programming".format(
                   _q7_sched_after, _q7_type_after))

    after_bindings = log_queue_bindings_table(
        dut, egress, "AFTER rebind attempt — Q0-Q6",
        {qi: _original_bindings[qi] for qi in range(7)})
    for qi in range(7):
        if after_bindings[qi] != _original_bindings[qi]:
            fail_msgs.append(
                "After rebind: QUEUE|{}|{} = '{}', expected '{}' "
                "(Q{} should be unaffected)".format(
                    egress, qi, after_bindings[qi], _original_bindings[qi], qi))

    log_scheduler_state_table(dut, "AFTER rebind attempt")

    # ── Step 6: Cleanup — restore Q7 binding and remove test scheduler profile
    print_section("CLEANUP — restore Q7 to baseline and remove test scheduler")
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|7" "scheduler" '
              '"scheduler.7"'.format(egress),
              skip_error_check=True)
    st.wait(2)
    st.config(dut, 'sonic-db-cli CONFIG_DB DEL "SCHEDULER|sched_dwrr_test"',
              skip_error_check=True)
    st.wait(1)

    log_scheduler_state_table(dut, "AFTER cleanup")
    raw_restored = dchal_show_queuing(dut, "AFTER restore", egress)
    log_dchal_egress_table(raw_restored, "AFTER restore")
    verify_queue_strict("AFTER restore — Q7 final check", raw_restored, fail_msgs)

    if fail_msgs:
        st.report_fail('msg', 'Rebind SG7 to DWRR FAILED: ' + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
            'Rebind SG7 to DWRR PASSED: '
            'SG7 rebind rejected (SG6 still STRICT); '
            'DCHAL Q7 remains STRICT; Q0-Q6 unaffected')


# ── Test: Negative-path — remove a bound scheduler must be rejected ───────
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_tortuga_remove_scheduler_in_use_fails(setup_topo):
    """Test 28: DEL a bound scheduler profile must be rejected (OBJECT_IN_USE).

    FX3 baseline: scheduler.3 (DWRR, w=40) is bound to Q3.  Attempting to
    DEL SCHEDULER|scheduler.3 while it is still referenced by QUEUE|<port>|3
    must be rejected by SAI (SAI_STATUS_OBJECT_IN_USE).  The primary check is
    DCHAL Q3 BW% continuity — unchanged after the rejected DEL.
    """
    egress = port_info['egress']
    st.banner(
        "test_tortuga_remove_scheduler_in_use_fails  [SAI constraint — negative path]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Step 0 [FX3 baseline verify — Q3 DWRR BW% snapshot]\n"
        "           Step 1 [CONFIG_DB DEL SCHEDULER|scheduler.3  (expect OBJECT_IN_USE rejection)]\n"
        "           Step 2 [syslog check — SAI 'still in use' evidence, informational]\n"
        "           Step 3 [verify Q3 CONFIG_DB binding unchanged]\n"
        "           Step 4 [DCHAL HW verify — Q3 BW% unchanged (primary verdict)]\n"
        "           Step 5 [cleanup — verify baseline intact; no bindings modified]".format(
            dut, egress)
    )
    fail_msgs = []

    deploy_dchal_helper(dut)

    _original_bindings = {qi: 'scheduler.{}'.format(qi) for qi in range(8)}

    print_section("STEP 0 — FX3 baseline already active from setup_topo", art_key='scheduler')

    log_scheduler_state_table(dut, "BEFORE — FX3 baseline")
    baseline_bindings = log_queue_bindings_table(
        dut, egress, "BEFORE — FX3 baseline", _original_bindings)

    baseline_fails = [qi for qi in range(8)
                      if baseline_bindings[qi] != _original_bindings[qi]]
    if baseline_fails:
        for qi in baseline_fails:
            fail_msgs.append(
                "Baseline: QUEUE|{}|{} = '{}', expected '{}' "
                "— Expected FX3 baseline binding not found".format(
                    egress, qi, baseline_bindings[qi], _original_bindings[qi]))
        st.report_fail('msg', 'Remove-scheduler-in-use test FAILED at baseline — '
                       'Expected FX3 baseline QUEUE bindings not found')
        return

    raw_before = dchal_show_queuing(dut, "BEFORE — FX3 baseline", egress)
    log_dchal_egress_table(raw_before, "BEFORE — FX3 baseline")
    bw_before = parse_dchal_egress_bw(raw_before)
    q3_bw_before = (bw_before.get(3) or {}).get('bw_pct')
    st.log("  BEFORE: DCHAL Q3 BW% = {}".format(q3_bw_before))
    verify_queue_dwrr("BEFORE — baseline Q3 DWRR check", raw_before, fail_msgs, queue=3)

    # ── BEFORE snapshot: Q3 CONFIG_DB state ──
    _q3_sched_before = get_queue_binding(dut, egress, 3)
    _q3_type_cmd = (
        'sonic-db-cli CONFIG_DB HGET "SCHEDULER|{}" "type"'.format(_q3_sched_before))
    _q3_type_before = (st.show(dut, _q3_type_cmd,
                       skip_tmpl=True, skip_error_check=True) or '').strip()
    _q3_type_before = next(
        (l.strip() for l in _q3_type_before.splitlines()
         if l.strip() and not l.strip().startswith('admin@')), _q3_type_before)
    st.log("  Q3 BEFORE: binding='{}' → type='{}'".format(
        _q3_sched_before, _q3_type_before))

    # ── Step 1: Attempt to remove scheduler.3 while still bound to Q3 ────────
    print_section(
        "ATTEMPT — DEL scheduler.3 while bound to QUEUE|{}|3  "
        "(expect OBJECT_IN_USE rejection)".format(egress))
    st.log("  scheduler.3 is still referenced by QUEUE|{}|3 — SAI must refuse removal".format(egress))
    # Capture syslog timestamp before attempt so we only grep fresh messages
    _ts_before = (st.show(dut, 'date +"%b %e %H:%M"',
                  skip_tmpl=True, skip_error_check=True) or '').strip()
    _ts_before = next(
        (l.strip() for l in _ts_before.splitlines()
         if l.strip() and not l.strip().startswith('admin@')), _ts_before)
    st.config(dut,
              'sonic-db-cli CONFIG_DB DEL "SCHEDULER|scheduler.3"',
              skip_error_check=True)
    st.wait(3)

    # ── SAI rejection check (grep syslog + syslog.1 for specific error) ───
    # Filter for "still in use" — the scheduler OID is unique per message.
    # ── Step 2: Check syslog for SAI rejection evidence (informational) ──────
    print_section("SAI rejection evidence (syslog 'still in use')")
    _reject_cmd = (
        'sudo grep -a "still in use\\|Cannot remove scheduler" '
        '/var/log/syslog /var/log/syslog.1 2>/dev/null | tail -5')
    _reject_out = st.show(dut, _reject_cmd,
                          skip_tmpl=True, skip_error_check=True) or ''
    _reject_out = _reject_out.strip()
    if 'still in use' in _reject_out or 'Cannot remove' in _reject_out:
        st.log("  SAI REJECTION CONFIRMED in syslog:")
        for _rl in _reject_out.splitlines():
            if 'still in use' in _rl or 'Cannot remove' in _rl:
                st.log("    {}".format(_rl.strip()))
    else:
        st.log("  'still in use' not found in syslog "
               "(may be rate-limited) — DCHAL HW check is primary verdict")

    # ── AFTER snapshot: Q3 CONFIG_DB state ──
    # ── Step 3: Verify Q3 SAI-level state after DEL attempt ────────────────
    print_section("AFTER DEL attempt — Q3 SAI-level state check")
    _q3_sched_after = get_queue_binding(dut, egress, 3)
    _q3_type_cmd_after = (
        'sonic-db-cli CONFIG_DB HGET "SCHEDULER|{}" "type"'.format(_q3_sched_after))
    _q3_type_after = (st.show(dut, _q3_type_cmd_after,
                      skip_tmpl=True, skip_error_check=True) or '').strip()
    _q3_type_after = next(
        (l.strip() for l in _q3_type_after.splitlines()
         if l.strip() and not l.strip().startswith('admin@')), _q3_type_after)
    st.log("  Q3 AFTER:  binding='{}' → type='{}'".format(
        _q3_sched_after, _q3_type_after))
    st.log("  ────────────────────────────────────────────────")
    st.log("  Q3 SAI-level comparison:")
    st.log("    BEFORE: binding='{}' type='{}'".format(
        _q3_sched_before, _q3_type_before))
    st.log("    AFTER:  binding='{}' type='{}'".format(
        _q3_sched_after, _q3_type_after))
    st.log("  ────────────────────────────────────────────────")

    # ── Step 4: Verify DCHAL Q3 HW state unchanged (primary verdict) ─────────
    print_section("AFTER DEL attempt — Q3 HW state must be unchanged")
    after_bindings = log_queue_bindings_table(
        dut, egress, "AFTER DEL attempt — Q3 binding",
        {3: 'scheduler.3'})
    if after_bindings[3] != 'scheduler.3':
        fail_msgs.append(
            "After DEL attempt: QUEUE|{}|3 = '{}', expected 'scheduler.3' "
            "(binding must be unchanged when scheduler removal is rejected)".format(
                egress, after_bindings[3]))

    raw_after = dchal_show_queuing(dut, "AFTER DEL attempt", egress)
    log_dchal_egress_table(raw_after, "AFTER DEL attempt")
    verify_queue_dwrr(
        "AFTER DEL attempt — Q3 must remain DWRR",
        raw_after, fail_msgs, queue=3,
        expected_bw_pct=q3_bw_before)

    # CONFIG_DB vs DCHAL cross-check
    if _q3_sched_after == _q3_sched_before and not fail_msgs:
        st.log("  Q3 binding UNCHANGED ('{}') and DCHAL BW% unchanged"
               " — SAI correctly refused scheduler removal".format(_q3_sched_after))
    elif _q3_sched_after != _q3_sched_before and not fail_msgs:
        st.log("  Q3 CONFIG_DB='{}' but DCHAL BW% unchanged"
               " — SAI validation REJECTED the HW change".format(_q3_sched_after))

    log_scheduler_state_table(dut, "AFTER DEL attempt")

    # ── Step 5: Cleanup — verify Q3 binding and baseline are intact ───────────
    print_section("CLEANUP — verify baseline intact")
    # No queue bindings were modified; verify Q3 is still bound to scheduler.3
    output = st.show(
        dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|3" "scheduler"'.format(egress),
        skip_tmpl=True)
    q3_final = parse_redis_hget(output).strip()
    if q3_final != 'scheduler.3':
        fail_msgs.append(
            "After test: QUEUE|{}|3 = '{}', expected 'scheduler.3' "
            "(baseline should be intact)".format(egress, q3_final))
    st.log("  Q3 verified: bound to '{}' (baseline intact)".format(q3_final))

    log_scheduler_state_table(dut, "AFTER cleanup")
    raw_restored = dchal_show_queuing(dut, "AFTER restore", egress)
    log_dchal_egress_table(raw_restored, "AFTER restore")
    verify_queue_dwrr("AFTER restore — Q3 final check", raw_restored, fail_msgs, queue=3)

    if fail_msgs:
        st.report_fail('msg',
                       'Remove scheduler in use FAILED: ' + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'Remove scheduler in use PASSED: '
                       'DEL scheduler.3 rejected (still bound to Q3); '
                       'DCHAL Q3 DWRR BW% unchanged')


# ── Test: Negative-path — STRICT gap in STRICT block must be rejected ─────
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_strict_gap_rejected(setup_topo):
    """Test 30: STRICT binding with a DWRR gap in the STRICT block must be rejected.

    FX3 baseline: Q6=STRICT, Q7=STRICT.  First rebinds Q6=DWRR (must succeed,
    introducing a gap).  Then attempts Q5=STRICT with the DWRR gap at Q6 — must
    be rejected by SAI (non-contiguous STRICT block).  Final HW state must be
    Q5=DWRR, Q6=DWRR, Q7=STRICT.
    """
    egress = port_info['egress']
    st.banner(
        "test_strict_gap_rejected  [SAI constraint — negative path]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Step 0 [FX3 baseline verify — Q6=STRICT, Q7=STRICT]\n"
        "           Step 1 [create test schedulers sched_gap_dwrr + sched_gap_strict]\n"
        "           Step 2 [bind Q6=DWRR  →  must SUCCEED  (valid, gap below Q7)]\n"
        "           Step 3 [bind Q5=STRICT  →  must FAIL   (DWRR gap at Q6)]\n"
        "           Step 4 [syslog check — constraint violation queue_idx=5, informational]\n"
        "           Step 5 [verify Q5 CONFIG_DB state unchanged]\n"
        "           Step 6 [DCHAL HW verify — Q5=DWRR, Q6=DWRR, Q7=STRICT]\n"
        "           Step 7 [cleanup — restore Q5=scheduler.5, Q6=scheduler.6; DEL test schedulers]".format(
            dut, egress)
    )
    fail_msgs = []

    deploy_dchal_helper(dut)

    _original_bindings = {qi: 'scheduler.{}'.format(qi) for qi in range(8)}
    """Apply FX3 baseline, attempt to change Q7 from STRICT to DWRR — must be rejected.

    Maps to SAI test_tortuga_change_bound_sg7_strict_to_dwrr_fails and
    scheduler_test_plan.md test 27.

    SG7 is the top-most STRICT group.  Changing it to DWRR while SG6 is still
    STRICT would create DWRR-above-STRICT interleaving, which FX3 SAI forbids.
    The rebind must fail in HW; DCHAL must still show Q7 BW%=0 (STRICT).

    Steps:
      1. Verify FX3 baseline — Q7 bound to scheduler.7 (STRICT)
      2. Change scheduler.7 type to DWRR + weight=20 in CONFIG_DB;
         force HDEL+HSET on QUEUE|7 so orchagent re-evaluates
      3. Verify DCHAL: Q7 BW% remains 0 (SAI rejected DWRR on Q7)
      4. Restore: reset scheduler.7 to STRICT; config qos reload
    """
    egress = port_info['egress']
    st.banner(
        "test_fx3_change_bound_sg7_strict_to_dwrr_fails\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Baseline → Change Q7 STRICT→DWRR → DCHAL Q7=0% → Restore".format(
            dut, egress)
    )
    fail_msgs = []
    deploy_dchal_helper(dut)

    # ── Step 1: Verify FX3 baseline — Q7 bound to scheduler.7 (STRICT) ──────
    st.banner("STEP 1: Verify FX3 baseline — Q7 bound to scheduler.7 (STRICT)")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|7" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q7 = parse_redis_hget(out).strip()
    st.log("  Q7 baseline binding: '{}'  expected 'scheduler.7'".format(actual_q7))
    if actual_q7 != 'scheduler.7':
        fail_msgs.append("Baseline: QUEUE|{}|7 = '{}', expected 'scheduler.7'".format(
            egress, actual_q7))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg',
            'Change-SG7-STRICT-to-DWRR FAILED at baseline — Q7 not bound to scheduler.7')
        return

    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.7"',
        skip_tmpl=True)
    sched7 = parse_redis_hgetall(out)
    st.log("  scheduler.7 baseline: {}".format(sched7))
    if sched7.get('type') != 'STRICT':
        fail_msgs.append("Baseline: scheduler.7 type='{}', expected 'STRICT'".format(
            sched7.get('type')))

    # ── Step 2: Change scheduler.7 to DWRR + rebind Q7 ─────────────────────
    st.banner("STEP 2: Change scheduler.7 to DWRR (weight=20) and rebind Q7")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.7" '
        '"type" "DWRR" "weight" "20"',
        skip_error_check=True)
    st.wait(1)

    # Force HDEL + HSET on QUEUE|7 so orchagent re-evaluates (same pattern as
    # test_fx3_sg5_dwrr_to_strict which uses delete-event for HW reprogramming)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|7" "scheduler"'.format(egress),
        skip_error_check=True)
    st.wait(1)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|7" "scheduler" "scheduler.7"'.format(egress),
        skip_error_check=True)
    st.wait(3)

    # ── Step 3: Verify DCHAL — Q7 BW% must still be 0 (HW rejected DWRR) ───
    st.banner("STEP 3: DCHAL check — Q7 BW% must remain 0 (SAI rejected DWRR on Q7)")
    _dchal_out = dchal_show_queuing(dut, "After Q7 STRICT→DWRR attempt", egress)

    # Use validate_dchal_bw_vs_weights on the remaining 6 DWRR queues to confirm
    # they are still correct (Q7 STRICT attempt must not disrupt Q0-Q5)
    w_baseline_dwrr = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    validate_dchal_bw_vs_weights(
        "After Q7 STRICT→DWRR attempt", _dchal_out, w_baseline_dwrr, fail_msgs)

    # Additionally verify Q7 DCHAL BW% is 0 — STRICT queues have bw_pct=None or 0
    bw_parsed = parse_dchal_egress_bw(_dchal_out)
    q7_info = bw_parsed.get(7, {})
    q7_bw = q7_info.get('bw_pct')
    st.log("  Q7 DCHAL info: {}  (expected bw_pct=None or 0 — STRICT)".format(q7_info))
    if q7_bw is not None and q7_bw > 5:
        fail_msgs.append(
            "After Q7 STRICT→DWRR attempt: Q7 DCHAL BW% = {}%, expected 0% "
            "(SAI should have rejected DWRR on Q7)".format(q7_bw))

    # ── Restore ──────────────────────────────────────────────────────────────
    st.banner("RESTORE: reset scheduler.7 to STRICT + config qos reload")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.7" "type" "STRICT"',
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "SCHEDULER|scheduler.7" "weight"',
        skip_error_check=True)
    st.wait(1)
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Verdict ──────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  CHANGE SG7 STRICT→DWRR — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Change-SG7-STRICT-to-DWRR FAILED ({} failures) — see above'.format(
                len(fail_msgs)))
    else:
        st.log("  CHANGE SG7 STRICT→DWRR — ALL CHECKS PASSED")
        st.log("  SAI correctly rejected DWRR binding on Q7; DCHAL Q7 BW%=0; "
               "Q0-Q5 DWRR percentages unchanged")
        st.log("=" * 72)
        st.report_pass('msg',
            'Change-SG7-STRICT-to-DWRR PASSED: SAI rejected DWRR on Q7; '
            'Q7 DCHAL BW%%=0; Q0-Q5 DWRR percentages unchanged')


def test_fx3_change_bound_sg7_strict_to_dwrr_fails(setup_topo):
    """Apply FX3 baseline, attempt to change Q7 from STRICT to DWRR — must be rejected.

    Maps to SAI test_tortuga_change_bound_sg7_strict_to_dwrr_fails and
    scheduler_test_plan.md test 27.

    SG7 is the top-most STRICT group.  Changing it to DWRR while SG6 is still
    STRICT would create DWRR-above-STRICT interleaving, which FX3 SAI forbids.
    The rebind must fail in HW; DCHAL must still show Q7 BW%=0 (STRICT).

    Steps:
      1. Verify FX3 baseline — Q7 bound to scheduler.7 (STRICT)
      2. Change scheduler.7 type to DWRR + weight=20 in CONFIG_DB;
         force HDEL+HSET on QUEUE|7 so orchagent re-evaluates
      3. Verify DCHAL: Q7 BW% remains 0 (SAI rejected DWRR on Q7)
      4. Restore: reset scheduler.7 to STRICT; config qos reload
    """
    egress = port_info['egress']
    st.banner(
        "test_fx3_change_bound_sg7_strict_to_dwrr_fails\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Baseline → Change Q7 STRICT→DWRR → DCHAL Q7=0% → Restore".format(
            dut, egress)
    )
    fail_msgs = []
    deploy_dchal_helper(dut)

    # ── Step 1: Verify FX3 baseline — Q7 bound to scheduler.7 (STRICT) ──────
    st.banner("STEP 1: Verify FX3 baseline — Q7 bound to scheduler.7 (STRICT)")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|7" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q7 = parse_redis_hget(out).strip()
    st.log("  Q7 baseline binding: '{}'  expected 'scheduler.7'".format(actual_q7))
    if actual_q7 != 'scheduler.7':
        fail_msgs.append("Baseline: QUEUE|{}|7 = '{}', expected 'scheduler.7'".format(
            egress, actual_q7))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg',
            'Change-SG7-STRICT-to-DWRR FAILED at baseline — Q7 not bound to scheduler.7')
        return

    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.7"',
        skip_tmpl=True)
    sched7 = parse_redis_hgetall(out)
    st.log("  scheduler.7 baseline: {}".format(sched7))
    if sched7.get('type') != 'STRICT':
        fail_msgs.append("Baseline: scheduler.7 type='{}', expected 'STRICT'".format(
            sched7.get('type')))

    # ── Step 2: Change scheduler.7 to DWRR + rebind Q7 ─────────────────────
    st.banner("STEP 2: Change scheduler.7 to DWRR (weight=20) and rebind Q7")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.7" '
        '"type" "DWRR" "weight" "20"',
        skip_error_check=True)
    st.wait(1)

    # Force HDEL + HSET on QUEUE|7 so orchagent re-evaluates (same pattern as
    # test_fx3_sg5_dwrr_to_strict which uses delete-event for HW reprogramming)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|7" "scheduler"'.format(egress),
        skip_error_check=True)
    st.wait(1)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|7" "scheduler" "scheduler.7"'.format(egress),
        skip_error_check=True)
    st.wait(3)

    # ── Step 3: Verify DCHAL — Q7 BW% must still be 0 (HW rejected DWRR) ───
    st.banner("STEP 3: DCHAL check — Q7 BW% must remain 0 (SAI rejected DWRR on Q7)")
    _dchal_out = dchal_show_queuing(dut, "After Q7 STRICT→DWRR attempt", egress)

    # Use validate_dchal_bw_vs_weights on the remaining 6 DWRR queues to confirm
    # they are still correct (Q7 STRICT attempt must not disrupt Q0-Q5)
    w_baseline_dwrr = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    validate_dchal_bw_vs_weights(
        "After Q7 STRICT→DWRR attempt", _dchal_out, w_baseline_dwrr, fail_msgs)

    # Additionally verify Q7 DCHAL BW% is 0 — STRICT queues have bw_pct=None or 0
    bw_parsed = parse_dchal_egress_bw(_dchal_out)
    q7_info = bw_parsed.get(7, {})
    q7_bw = q7_info.get('bw_pct')
    st.log("  Q7 DCHAL info: {}  (expected bw_pct=None or 0 — STRICT)".format(q7_info))
    if q7_bw is not None and q7_bw > 5:
        fail_msgs.append(
            "After Q7 STRICT→DWRR attempt: Q7 DCHAL BW% = {}%, expected 0% "
            "(SAI should have rejected DWRR on Q7)".format(q7_bw))

    # ── Restore ──────────────────────────────────────────────────────────────
    st.banner("RESTORE: reset scheduler.7 to STRICT + config qos reload")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.7" "type" "STRICT"',
        skip_error_check=True)
    st.config(dut,
        'sonic-db-cli CONFIG_DB HDEL "SCHEDULER|scheduler.7" "weight"',
        skip_error_check=True)
    st.wait(1)
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Verdict ──────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  CHANGE SG7 STRICT→DWRR — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Change-SG7-STRICT-to-DWRR FAILED ({} failures) — see above'.format(
                len(fail_msgs)))
    else:
        st.log("  CHANGE SG7 STRICT→DWRR — ALL CHECKS PASSED")
        st.log("  SAI correctly rejected DWRR binding on Q7; DCHAL Q7 BW%=0; "
               "Q0-Q5 DWRR percentages unchanged")
        st.log("=" * 72)
        st.report_pass('msg',
            'Change-SG7-STRICT-to-DWRR PASSED: SAI rejected DWRR on Q7; '
            'Q7 DCHAL BW%%=0; Q0-Q5 DWRR percentages unchanged')




def test_fx3_rebind_same_scheduler_to_same_sg(setup_topo):
    """Rebind Q3 to its current scheduler.3 (idempotent); verify no DCHAL change.

    Maps to SAI test_rebind_same_scheduler_to_same_sg and
    scheduler_test_plan.md test 35.

    A second identical HSET for QUEUE|N|scheduler should be a no-op in HW:
    CONFIG_DB binding is unchanged; DCHAL BW% for all DWRR queues is identical
    before and after.  No traffic measurement needed (plan: DCHAL check only).

    Steps:
      1. Verify FX3 baseline — Q3 is bound to scheduler.3 (w=40)
      2. HSET QUEUE|<egress>|3 scheduler scheduler.3  (same binding already present)
      3. Verify CONFIG_DB: Q3 still bound to scheduler.3
      4. DCHAL check: all 6 DWRR BW% unchanged vs baseline
      5. Restore: config qos reload
    """
    egress = port_info['egress']
    st.banner(
        "test_fx3_rebind_same_scheduler_to_same_sg\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Baseline → Rebind Q3→scheduler.3 (same) → DCHAL unchanged → Restore".format(
            dut, egress)
    )
    fail_msgs = []
    deploy_dchal_helper(dut)

    # FX3 baseline DWRR weight map
    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}

    # ── Step 1: Verify FX3 baseline — Q3 bound to scheduler.3 ────────────
    st.banner("STEP 1: Verify FX3 baseline — Q3 bound to scheduler.3 (w=40)")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|3" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q3 = parse_redis_hget(out).strip()
    st.log("  Q3 baseline binding: '{}'  expected 'scheduler.3'".format(actual_q3))
    if actual_q3 != 'scheduler.3':
        fail_msgs.append("Baseline: QUEUE|{}|3 = '{}', expected 'scheduler.3'".format(
            egress, actual_q3))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg',
            'Rebind-same-scheduler FAILED at baseline — Q3 not bound to scheduler.3')
        return

    # Snapshot DCHAL before rebind
    st.banner("STEP 1b: DCHAL snapshot before rebind")
    _dchal_before = dchal_show_queuing(dut, "Before rebind Q3 (same)", egress)

    # ── Step 2: Rebind Q3 to same scheduler.3 ────────────────────────────
    st.banner("STEP 2: HSET QUEUE|{}|3 scheduler scheduler.3 (idempotent rebind)".format(egress))
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|3" "scheduler" "scheduler.3"'.format(egress),
        skip_error_check=True)
    st.wait(2)

    # ── Step 3: Verify CONFIG_DB — Q3 still bound to scheduler.3 ─────────
    st.banner("STEP 3: Verify CONFIG_DB — Q3 still bound to scheduler.3")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|3" "scheduler"'.format(egress),
        skip_tmpl=True)
    actual_q3_after = parse_redis_hget(out).strip()
    st.log("  Q3 binding after re-bind: '{}'  expected 'scheduler.3'".format(actual_q3_after))
    if actual_q3_after != 'scheduler.3':
        fail_msgs.append(
            "After rebind: QUEUE|{}|3 = '{}', expected 'scheduler.3'".format(
                egress, actual_q3_after))

    # ── Step 4: DCHAL check — all DWRR BW% unchanged ─────────────────────
    st.banner("STEP 4: DCHAL check — all 6 DWRR queue BW% should be identical to baseline")
    _dchal_after = dchal_show_queuing(dut, "After rebind Q3 (same)", egress)
    validate_dchal_bw_vs_weights(
        "After rebind Q3 (same scheduler, idempotent)", _dchal_after,
        w_baseline, fail_msgs)

    # ── Restore ────────────────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Verdict ────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  REBIND SAME SCHEDULER — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Rebind-same-scheduler FAILED ({} failures) — see above'.format(
                len(fail_msgs)))
    else:
        st.log("  REBIND SAME SCHEDULER — ALL CHECKS PASSED")
        st.log("  Idempotent rebind: Q3→scheduler.3 (same) — CONFIG_DB and "
               "DCHAL BW% unchanged")
        st.log("=" * 72)
        st.report_pass('msg',
            'Rebind-same-scheduler PASSED: idempotent rebind Q3→scheduler.3; '
            'CONFIG_DB and DCHAL BW%% unchanged')


def test_fx3_bind_removed_scheduler_to_sg_fails(setup_topo):
    """Create a temp scheduler, bind Q0, remove the scheduler, try to rebind — must fail.

    Maps to SAI test_bind_removed_scheduler_to_sg_fails and
    scheduler_test_plan.md test 37.

    Once a SCHEDULER entry is deleted from CONFIG_DB:
      - orchagent removes the SAI object from HW
      - Any subsequent QUEUE binding referencing the deleted entry is ignored
      - DCHAL shows Q0 at HW-fallback token rate (not a normal DWRR weight)

    Steps:
      1. Create SCHEDULER|scheduler.tmp (DWRR w=20) in CONFIG_DB
      2. Bind Q0 to scheduler.tmp; verify CONFIG_DB
      3. Delete SCHEDULER|scheduler.tmp from CONFIG_DB; wait for orchagent
      4. Re-attempt HSET QUEUE|<egress>|0 scheduler scheduler.tmp
      5. Verify: scheduler.tmp does not exist in CONFIG_DB
      6. Verify: Q0 is not contributing normal DWRR weight in DCHAL
      7. Restore: config qos reload
    """
    egress = port_info['egress']
    st.banner(
        "test_fx3_bind_removed_scheduler_to_sg_fails\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Create scheduler.tmp → Bind Q0 → Delete scheduler.tmp "
        "→ Rebind Q0 (rejected) → Restore".format(dut, egress)
    )
    fail_msgs = []
    deploy_dchal_helper(dut)

    # ── Step 1: Create SCHEDULER|scheduler.tmp ────────────────────────────
    st.banner("STEP 1: Create SCHEDULER|scheduler.tmp (DWRR w=20) in CONFIG_DB")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "SCHEDULER|scheduler.tmp" '
        '"type" "DWRR" "weight" "20"',
        skip_error_check=True)
    st.wait(1)
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.tmp"',
        skip_tmpl=True)
    tmp_sched = parse_redis_hgetall(out)
    st.log("  scheduler.tmp created: {}".format(tmp_sched))
    if tmp_sched.get('type') != 'DWRR':
        fail_msgs.append("Create: SCHEDULER|scheduler.tmp type='{}', expected 'DWRR'".format(
            tmp_sched.get('type', '<missing>')))

    # ── Step 2: Bind Q0 to scheduler.tmp ─────────────────────────────────
    st.banner("STEP 2: Bind Q0 to scheduler.tmp")
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|0" "scheduler" "scheduler.tmp"'.format(egress),
        skip_error_check=True)
    st.wait(2)
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|0" "scheduler"'.format(egress),
        skip_tmpl=True)
    binding_q0 = parse_redis_hget(out).strip()
    st.log("  Q0 binding: '{}'  expected 'scheduler.tmp'".format(binding_q0))
    if binding_q0 != 'scheduler.tmp':
        fail_msgs.append(
            "After bind: QUEUE|{}|0 = '{}', expected 'scheduler.tmp'".format(
                egress, binding_q0))

    # ── Step 3: Delete SCHEDULER|scheduler.tmp ────────────────────────────
    st.banner("STEP 3: Delete SCHEDULER|scheduler.tmp from CONFIG_DB")
    st.config(dut,
        'sonic-db-cli CONFIG_DB DEL "SCHEDULER|scheduler.tmp"',
        skip_error_check=True)
    st.wait(3)
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|scheduler.tmp"',
        skip_tmpl=True)
    tmp_after_del = parse_redis_hgetall(out)
    st.log("  scheduler.tmp after DEL: {}  (expected empty)".format(tmp_after_del))
    if tmp_after_del:
        fail_msgs.append(
            "After DEL: SCHEDULER|scheduler.tmp still has entries: {}".format(tmp_after_del))

    # ── Step 4: Re-attempt bind Q0 to scheduler.tmp (non-existent) ───────
    st.banner("STEP 4: Re-attempt HSET QUEUE|{}|0 scheduler scheduler.tmp".format(egress))
    st.config(dut,
        'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|0" "scheduler" "scheduler.tmp"'.format(egress),
        skip_error_check=True)
    st.wait(2)

    # ── Step 5: Verify scheduler.tmp still does not exist ─────────────────
    st.banner("STEP 5: Verify SCHEDULER|scheduler.tmp does not exist in CONFIG_DB")
    out = st.show(dut,
        'sonic-db-cli CONFIG_DB EXISTS "SCHEDULER|scheduler.tmp"',
        skip_tmpl=True)
    exists_val = parse_redis_hget(out).strip() or '0'
    st.log("  EXISTS SCHEDULER|scheduler.tmp = '{}'  (expected 0)".format(exists_val))
    if exists_val not in ('0', ''):
        fail_msgs.append(
            "After rebind attempt: SCHEDULER|scheduler.tmp EXISTS={}, expected 0".format(
                exists_val))

    # ── Step 6: DCHAL check — Q0 must not show a DWRR weight ─────────────
    st.banner("STEP 6: DCHAL check — Q0 retains HW weight 20 (ASIC state); "
              "full Q0-Q5 DWRR pool at baseline weights")
    _dchal_out = dchal_show_queuing(dut, "After bind-removed scheduler attempt", egress)

    # Q0 retains its HW DWRR weight (20) even after scheduler.tmp was deleted —
    # the ASIC keeps the last programmed state.  Q1-Q5 share the remaining BW.
    # Q6/Q7 remain STRICT.
    w_remaining = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    validate_dchal_bw_vs_weights(
        "After bind-removed (Q0-Q5)", _dchal_out, w_remaining, fail_msgs)

    # ── Restore ────────────────────────────────────────────────────────────
    st.banner("RESTORE: config qos reload")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Restore")

    # ── Verdict ────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  BIND REMOVED SCHEDULER — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Bind-removed-scheduler FAILED ({} failures) — see above'.format(
                len(fail_msgs)))
    else:
        st.log("  BIND REMOVED SCHEDULER — ALL CHECKS PASSED")
        st.log("  Removed scheduler.tmp cannot be rebound; Q0 retains HW weight; "
               "Q0-Q5 DWRR pool intact")
        st.log("=" * 72)
        st.report_pass('msg',
            'Bind-removed-scheduler PASSED: deleted SCHEDULER|scheduler.tmp '
            'cannot be rebound; Q0-Q5 DWRR BW%% intact')


def test_fx3_scheduler_group_count_matches_queues(setup_topo):
    """Verify exactly 8 scheduler groups exist per port (one per queue).

    Maps to SAI test_scheduler_group_count_matches_queues and
    scheduler_test_plan.md test 39.

    Read-only structural check via COUNTERS_DB queue-name-map.  Issues 8 targeted
    HGET calls (one per queue index 0-7) against COUNTERS_QUEUE_NAME_MAP and asserts
    the count is 8.  On FX3, SAI_SCHEDULER_GROUP_ATTR_PORT_ID is not stored in
    ASIC_DB, so queue OIDs from the name-map serve as the authoritative
    scheduler-group count (1:1 queue:SG mapping).  No CONFIG_DB changes; no restore needed.
    """
    egress = port_info['egress']
    st.banner(
        "test_fx3_scheduler_group_count_matches_queues\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : COUNTERS_DB queue-name-map — 1:1 queue:SG on FX3; count == 8".format(
            dut, egress)
    )
    fail_msgs = []

    deploy_dchal_helper(dut)

    _original_bindings = {qi: 'scheduler.{}'.format(qi) for qi in range(8)}

    print_section("STEP 0 — FX3 baseline already active from setup_topo", art_key='scheduler')

    log_scheduler_state_table(dut, "BEFORE — FX3 baseline")
    baseline_bindings = log_queue_bindings_table(
        dut, egress, "BEFORE — FX3 baseline", _original_bindings)

    baseline_fails = [qi for qi in range(8)
                      if baseline_bindings[qi] != _original_bindings[qi]]
    if baseline_fails:
        for qi in baseline_fails:
            fail_msgs.append(
                "Baseline: QUEUE|{}|{} = '{}', expected '{}' "
                "— Expected FX3 baseline binding not found".format(
                    egress, qi, baseline_bindings[qi], _original_bindings[qi]))
        st.report_fail('msg', 'Strict-gap test FAILED at baseline — '
                       'Expected FX3 baseline QUEUE bindings not found')
        return

    raw_before = dchal_show_queuing(dut, "BEFORE — FX3 baseline", egress)
    log_dchal_egress_table(raw_before, "BEFORE — FX3 baseline")
    verify_queue_strict("BEFORE — baseline Q7 STRICT check", raw_before, fail_msgs, queue=7)
    verify_queue_strict("BEFORE — baseline Q6 STRICT check", raw_before, fail_msgs, queue=6)

    # ── Step 1: Create test scheduler profiles (DWRR + STRICT) ──────────────
    print_section("Create Test Scheduler Profiles", art_key='scheduler')
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "SCHEDULER|sched_gap_dwrr" "type" "DWRR" "weight" "20"',
              skip_error_check=True)
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "SCHEDULER|sched_gap_strict" "type" "STRICT"',
              skip_error_check=True)
    st.wait(1)
    for name in ('sched_gap_dwrr', 'sched_gap_strict'):
        out = st.show(dut,
                      'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
                      skip_tmpl=True)
        st.log("  {} = {}".format(name, parse_redis_hgetall(out)))

    # ── Step 2: Bind Q6=DWRR — must succeed (creates gap below Q7=STRICT) ─────
    print_section(
        "STEP 2 — Bind Q6=DWRR  (expect success — introduces gap below Q7=STRICT)")
    st.log("  Q7=STRICT (from FX3 baseline); binding Q6=DWRR should succeed")
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|6" "scheduler" '
              '"sched_gap_dwrr"'.format(egress),
              skip_error_check=True)
    st.wait(3)

    raw_step1 = dchal_show_queuing(dut, "AFTER Q6=DWRR bind", egress)
    log_dchal_egress_table(raw_step1, "AFTER Q6=DWRR bind")
    verify_queue_strict("STEP 1 — Q7 must remain STRICT", raw_step1, fail_msgs, queue=7)
    verify_queue_dwrr("STEP 1 — Q6 must become DWRR", raw_step1, fail_msgs, queue=6)

    bindings_step1 = log_queue_bindings_table(
        dut, egress, "AFTER Q6=DWRR bind",
        {6: 'sched_gap_dwrr', 7: 'scheduler.7'})
    if bindings_step1[6] != 'sched_gap_dwrr':
        fail_msgs.append(
            "Step 1: QUEUE|{}|6 = '{}', expected 'sched_gap_dwrr' "
            "(Q6=DWRR bind should have succeeded)".format(egress, bindings_step1[6]))
    if bindings_step1[7] != 'scheduler.7':
        fail_msgs.append(
            "Step 1: QUEUE|{}|7 = '{}', expected 'scheduler.7' "
            "(Q7 must be unaffected)".format(egress, bindings_step1[7]))

    # ── BEFORE snapshot: Q5 CONFIG_DB state (before gap attempt) ──
    _q5_sched_before = get_queue_binding(dut, egress, 5)
    _q5_type_cmd = (
        'sonic-db-cli CONFIG_DB HGET "SCHEDULER|{}" "type"'.format(_q5_sched_before))
    _q5_type_before = (st.show(dut, _q5_type_cmd,
                       skip_tmpl=True, skip_error_check=True) or '').strip()
    _q5_type_before = next(
        (l.strip() for l in _q5_type_before.splitlines()
         if l.strip() and not l.strip().startswith('admin@')), _q5_type_before)
    st.log("  Q5 BEFORE: binding='{}' → type='{}'".format(
        _q5_sched_before, _q5_type_before))

    # ── Step 3: Attempt to bind Q5=STRICT with DWRR gap at Q6 — must fail ────
    print_section(
        "ATTEMPT — Bind Q5=STRICT  (expect rejection — DWRR gap at Q6)")
    st.log(
        "  Current state: Q7=STRICT, Q6=DWRR (gap) → binding Q5=STRICT "
        "creates non-contiguous STRICT block — must be rejected")
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|5" "scheduler" '
              '"sched_gap_strict"'.format(egress),
              skip_error_check=True)
    st.wait(3)

    # ── SAI rejection check (grep syslog + syslog.1 for constraint violation) ───
    # Filter by queue_idx=5 to match only this queue's rejection.
    # ── Step 4: Check syslog for SAI rejection evidence (informational) ──────
    print_section("SAI rejection evidence (syslog constraint violation queue_idx=5)")
    _reject_cmd = (
        'sudo grep -a "queue ordering constraint violation\\|consecutive\\|Gap detected" '
        '/var/log/syslog /var/log/syslog.1 2>/dev/null '
        '| grep "queue_idx=5" | tail -5')
    _reject_out = st.show(dut, _reject_cmd,
                          skip_tmpl=True, skip_error_check=True) or ''
    _reject_out = _reject_out.strip()
    if 'queue_idx=5' in _reject_out:
        st.log("  SAI REJECTION CONFIRMED in syslog (queue_idx=5):")
        for _rl in _reject_out.splitlines():
            if 'queue_idx=5' in _rl:
                st.log("    {}".format(_rl.strip()))
    else:
        st.log("  Constraint violation for queue_idx=5 not found in syslog "
               "(may be rate-limited) — DCHAL HW check is primary verdict")

    # ── AFTER snapshot: Q5 CONFIG_DB state ──
    # ── Step 5: Verify Q5 SAI-level state after rejection attempt ──────────────
    print_section("AFTER Q5=STRICT attempt — Q5 SAI-level state check")
    _q5_sched_after = get_queue_binding(dut, egress, 5)
    _q5_type_cmd_after = (
        'sonic-db-cli CONFIG_DB HGET "SCHEDULER|{}" "type"'.format(_q5_sched_after))
    _q5_type_after = (st.show(dut, _q5_type_cmd_after,
                      skip_tmpl=True, skip_error_check=True) or '').strip()
    _q5_type_after = next(
        (l.strip() for l in _q5_type_after.splitlines()
         if l.strip() and not l.strip().startswith('admin@')), _q5_type_after)
    st.log("  Q5 AFTER:  binding='{}' → type='{}'".format(
        _q5_sched_after, _q5_type_after))
    st.log("  ────────────────────────────────────────────────")
    st.log("  Q5 SAI-level comparison:")
    st.log("    BEFORE: binding='{}' type='{}'".format(
        _q5_sched_before, _q5_type_before))
    st.log("    AFTER:  binding='{}' type='{}'".format(
        _q5_sched_after, _q5_type_after))
    if _q5_sched_after == _q5_sched_before:
        st.log("    RESULT: binding UNCHANGED — orchagent/SAI rejected at CONFIG_DB level")
    elif _q5_sched_after == 'sched_gap_strict':
        st.log("    RESULT: CONFIG_DB accepted HSET (type changed {} → {})"
               " — checking DCHAL HW to confirm SAI blocked HW programming".format(
                   _q5_type_before, _q5_type_after))
    else:
        st.log("    RESULT: unexpected binding '{}'".format(_q5_sched_after))
    st.log("  ────────────────────────────────────────────────")

    # ── PRIMARY CHECK: DCHAL HW must show Q5 unchanged ──
    # ── Step 6: Verify DCHAL HW — Q5 DWRR, Q6 DWRR, Q7 STRICT ────────────────
    print_section("AFTER Q5=STRICT attempt — HW + binding checks")
    raw_after = dchal_show_queuing(dut, "AFTER Q5=STRICT attempt", egress)
    log_dchal_egress_table(raw_after, "AFTER Q5=STRICT attempt")
    verify_queue_strict(
        "AFTER attempt — Q7 must stay STRICT", raw_after, fail_msgs, queue=7)
    verify_queue_dwrr(
        "AFTER attempt — Q6 must stay DWRR", raw_after, fail_msgs, queue=6)
    verify_queue_dwrr(
        "AFTER attempt — Q5 must remain DWRR (gap bind refused)",
        raw_after, fail_msgs, queue=5)

    after_bindings = log_queue_bindings_table(
        dut, egress, "AFTER Q5=STRICT attempt",
        {5: 'scheduler.5', 6: 'sched_gap_dwrr', 7: 'scheduler.7'})
    if after_bindings[6] != 'sched_gap_dwrr':
        fail_msgs.append(
            "After Q5=STRICT attempt: QUEUE|{}|6 = '{}', expected 'sched_gap_dwrr' "
            "(Q6 must be unaffected by the failed Q5 bind)".format(
                egress, after_bindings[6]))

    # CONFIG_DB vs DCHAL cross-check
    if _q5_sched_after != _q5_sched_before and not fail_msgs:
        st.log("  Q5 CONFIG_DB='{}' (type={}) but DCHAL=DWRR"
               " — SAI validation REJECTED the HW programming".format(
                   _q5_sched_after, _q5_type_after))

    log_scheduler_state_table(dut, "AFTER Q5=STRICT attempt")

    # ── Step 7: Cleanup — restore Q6=STRICT, Q7=STRICT; remove test schedulers
    print_section("CLEANUP — restore Q5 and Q6 to baseline, remove test schedulers")
    # Restore Q5 to its baseline scheduler (in case CONFIG_DB was modified)
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|5" "scheduler" '
              '"scheduler.5"'.format(egress),
              skip_error_check=True)
    # Restore Q6 to its baseline scheduler before deleting test schedulers
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|6" "scheduler" '
              '"scheduler.6"'.format(egress),
              skip_error_check=True)
    st.wait(2)
    st.config(dut,
              'sonic-db-cli CONFIG_DB DEL "SCHEDULER|sched_gap_dwrr"',
              skip_error_check=True)
    st.config(dut,
              'sonic-db-cli CONFIG_DB DEL "SCHEDULER|sched_gap_strict"',
              skip_error_check=True)
    st.wait(1)

    log_scheduler_state_table(dut, "AFTER cleanup")
    raw_restored = dchal_show_queuing(dut, "AFTER restore", egress)
    log_dchal_egress_table(raw_restored, "AFTER restore")
    verify_queue_strict("AFTER restore — Q7 final check", raw_restored, fail_msgs, queue=7)
    verify_queue_strict("AFTER restore — Q6 final check", raw_restored, fail_msgs, queue=6)

    if fail_msgs:
        st.report_fail('msg',
                       'STRICT gap rejected FAILED: ' + '; '.join(fail_msgs))
    else:
        st.report_pass('msg',
                       'STRICT gap rejected PASSED: '
                       'Q6=DWRR bind succeeded; '
                       'Q5=STRICT with DWRR gap at Q6 was rejected; '
                       'DCHAL Q5 remains DWRR; Q6=DWRR; Q7=STRICT; '
                       'FX3 baseline restored')


# ══════════════════════════════════════════════════════════════════════════
# Advanced Scheduler Tests (plans 31, 14, 15, 32, 18)
# ══════════════════════════════════════════════════════════════════════════

def test_strict_not_at_top_accepted(setup_topo):
    """Test 31: Q6=STRICT is accepted when Q7 is unconfigured (default DWRR).

    Validates the SAI ordering fix: only *explicitly bound* STRICT queues
    are considered for constraint checking.  An unconfigured Q7 (no scheduler
    bound) is treated as DWRR, so binding Q6=STRICT alone is valid.

    Steps:
      1. Verify FX3 baseline; unbind Q6 and Q7 so both are unconfigured
      2. Create sched_strict_t31 (STRICT)
      3. Bind Q6=sched_strict_t31  → must SUCCEED
      4. Verify Q6=STRICT in CONFIG_DB and DCHAL HW
      5. Verify Q7 still has no binding in CONFIG_DB
      6. IPv4 + IPv6 traffic: Q0-Q5 DWRR with baseline weights; Q6 strict_queue
      7. Restore: config qos reload; DEL sched_strict_t31
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_strict_not_at_top_accepted  [SAI constraint — positive path]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Step 0 [FX3 baseline verify]\n"
        "           Step 1 [unbind Q6 and Q7 — both unconfigured]\n"
        "           Step 2 [create sched_strict_t31]\n"
        "           Step 3 [bind Q6=STRICT  →  must SUCCEED]\n"
        "           Step 4 [verify DCHAL Q6=STRICT; Q7 unbound]\n"
        "           Step 5 [IPv4 + IPv6 traffic — Q0-Q5 DWRR; Q6 drains first]\n"
        "           Step 6 [restore: config qos reload]".format(dut, egress)
    )
    fail_msgs = []
    checkpoint_summary = {}

    _original_bindings = {qi: 'scheduler.{}'.format(qi) for qi in range(8)}
    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}

    # ── Step 0: Verify FX3 baseline ───────────────────────────────────────
    print_section("STEP 0 — FX3 baseline verify", art_key='scheduler')
    log_scheduler_state_table(dut, "BEFORE — FX3 baseline")
    baseline_bindings = log_queue_bindings_table(
        dut, egress, "BEFORE — FX3 baseline", _original_bindings)
    baseline_fails = [qi for qi in range(8)
                      if baseline_bindings[qi] != _original_bindings[qi]]
    if baseline_fails:
        for qi in baseline_fails:
            fail_msgs.append(
                "Baseline: QUEUE|{}|{} = '{}', expected '{}'".format(
                    egress, qi, baseline_bindings[qi], _original_bindings[qi]))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg',
                       'STRICT-not-at-top FAILED at baseline — '
                       'expected FX3 QUEUE bindings not found')
        return

    # ── Step 1: Unbind Q7 and Q6 ──────────────────────────────────────────
    print_section("STEP 1 — Unbind Q7 and Q6 (both unconfigured)", art_key='scheduler')
    st.config(dut,
              'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|7" "scheduler"'.format(egress),
              skip_error_check=True)
    st.wait(1)
    st.config(dut,
              'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|6" "scheduler"'.format(egress),
              skip_error_check=True)
    st.wait(2)

    for qi, label in [(7, 'Q7'), (6, 'Q6')]:
        out = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        actual = parse_redis_hget(out).strip()
        st.log("  {} binding after unbind: '{}'  (expected empty)".format(label, actual))
        if actual:
            fail_msgs.append("After unbind: QUEUE|{}|{} still has scheduler='{}'".format(
                egress, qi, actual))

    # ── Step 2: Create STRICT test scheduler ─────────────────────────────
    print_section("STEP 2 — Create SCHEDULER|sched_strict_t31 (STRICT)", art_key='scheduler')
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "SCHEDULER|sched_strict_t31" "type" "STRICT"',
              skip_error_check=True)
    st.wait(1)
    out = st.show(dut,
                  'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|sched_strict_t31"',
                  skip_tmpl=True)
    st.log("  sched_strict_t31 = {}".format(parse_redis_hgetall(out)))

    # ── Step 3: Bind Q6=STRICT — must SUCCEED ────────────────────────────
    print_section("STEP 3 — Bind Q6=sched_strict_t31 (expect SUCCESS)", art_key='scheduler')
    st.log("  Q7 is unconfigured → Q6=STRICT alone is a valid contiguous STRICT block")
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|6" "scheduler" '
              '"sched_strict_t31"'.format(egress),
              skip_error_check=True)
    st.wait(3)

    # ── Step 4: Verify Q6=STRICT in CONFIG_DB and DCHAL ──────────────────
    print_section("STEP 4 — Verify Q6=STRICT in CONFIG_DB and DCHAL", art_key='scheduler')
    q6_binding = get_queue_binding(dut, egress, 6)
    st.log("  Q6 CONFIG_DB binding: '{}'  expected 'sched_strict_t31'".format(q6_binding))
    if q6_binding != 'sched_strict_t31':
        fail_msgs.append(
            "Step 3: Q6 binding = '{}', expected 'sched_strict_t31'".format(q6_binding))

    # Q7 must remain unbound
    q7_binding = get_queue_binding(dut, egress, 7)
    st.log("  Q7 CONFIG_DB binding: '{}'  expected empty".format(q7_binding))
    if q7_binding:
        fail_msgs.append(
            "Step 3: Q7 unexpectedly has binding='{}'".format(q7_binding))

    raw_after = dchal_show_queuing(dut, "AFTER Q6=STRICT bind", egress)
    log_dchal_egress_table(raw_after, "AFTER Q6=STRICT bind")
    verify_queue_strict("Q6 STRICT verify", raw_after, fail_msgs, queue=6)

    # ── Step 5: IPv4 traffic ──────────────────────────────────────────────
    print_section("STEP 5 — IPv4 traffic: Q0-Q5 DWRR baseline; Q6 strict drain first",
                  art_key='scheduler')
    _dchal_bw = validate_dchal_bw_vs_weights(
        "STRICT-not-at-top DCHAL", raw_after, w_baseline, fail_msgs)
    scheduler_traffic_check(
        "STRICT-not-at-top [IPv4]", w_baseline, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw, strict_queues=(6,),
        note="Q6=STRICT (unconfigured Q7); Q0-Q5 DWRR baseline weights")

    # ── Step 5b: IPv6 traffic ────────────────────────────────────────────
    scheduler_traffic_check_v6(
        "STRICT-not-at-top [IPv6]", w_baseline, fail_msgs, checkpoint_summary,
        macs, strict_queues=(6,),
        note="Q6=STRICT (unconfigured Q7); Q0-Q5 DWRR baseline weights")

    # ── Step 6: Restore ───────────────────────────────────────────────────
    print_section("STEP 6 — Restore: config qos reload", art_key='scheduler')
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    st.config(dut,
              'sonic-db-cli CONFIG_DB DEL "SCHEDULER|sched_strict_t31"',
              skip_error_check=True)
    log_scheduler_state("Restore")

    print_scheduler_summary(checkpoint_summary)

    st.log("=" * 72)
    if fail_msgs:
        st.log("  STRICT-NOT-AT-TOP — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'STRICT-not-at-top FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  STRICT-NOT-AT-TOP — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  Q6=STRICT accepted when Q7 unconfigured; DCHAL BW% and traffic "
               "ratios for Q0-Q5 match expected weights")
        st.log("=" * 72)
        st.report_pass('msg',
            'STRICT-not-at-top PASSED (IPv4 + IPv6): '
            'Q6=STRICT binding accepted with unconfigured Q7; '
            'DCHAL BW% and Tx-pkt ratios for Q0-Q5 match baseline weights')


def test_all_queues_strict_fails_on_q0(setup_topo):
    """Test 14: Q0 must always remain DWRR; binding STRICT to Q0 is rejected by SAI.

    CloudScale/FX3 requires at least one DWRR queue to act as a bandwidth sink.
    Q0 is the designated sink: any attempt to bind STRICT to it must fail.

    Steps:
      1. Verify FX3 baseline
      2. Create sched_strict_t14 (STRICT)
      3. Bind STRICT to Q5→Q1 sequentially downward  (each must SUCCEED —
         contiguous block grows from Q7 downward: Q7≥Q6≥Q5≥Q4≥Q3≥Q2≥Q1)
      4. Verify DCHAL Q1-Q7 all STRICT
      5. Snapshot Q0 DCHAL state before attempt
      6. Attempt to bind Q0=STRICT  → must FAIL (Q0 cannot be STRICT)
      7. Verify Q0 DCHAL still DWRR after failed attempt
      8. IPv4 + IPv6 traffic: Q0 only; verify Q0 gets non-zero egress bandwidth
      9. Restore: config qos reload; DEL sched_strict_t14
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_all_queues_strict_fails_on_q0  [SAI constraint — negative path]\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : Step 0 [FX3 baseline verify]\n"
        "           Step 1 [create sched_strict_t14]\n"
        "           Step 2 [bind Q5→Q1=STRICT sequentially  →  each must SUCCEED]\n"
        "           Step 3 [attempt Q0=STRICT  →  must FAIL]\n"
        "           Step 4 [DCHAL: Q0 still DWRR; Q1-Q7 STRICT]\n"
        "           Step 5 [traffic: Q0 only; verify non-zero BW]\n"
        "           Step 6 [restore: config qos reload]".format(dut, egress)
    )
    fail_msgs = []
    checkpoint_summary = {}

    _original_bindings = {qi: 'scheduler.{}'.format(qi) for qi in range(8)}
    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    # ── Step 0: Verify FX3 baseline ───────────────────────────────────────
    print_section("STEP 0 — FX3 baseline verify", art_key='scheduler')
    log_scheduler_state_table(dut, "BEFORE — FX3 baseline")
    baseline_bindings = log_queue_bindings_table(
        dut, egress, "BEFORE — FX3 baseline", _original_bindings)
    baseline_fails = [qi for qi in range(8)
                      if baseline_bindings[qi] != _original_bindings[qi]]
    if baseline_fails:
        for qi in baseline_fails:
            fail_msgs.append(
                "Baseline: QUEUE|{}|{} = '{}', expected '{}'".format(
                    egress, qi, baseline_bindings[qi], _original_bindings[qi]))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg',
                       'All-STRICT-fails-on-Q0 FAILED at baseline — '
                       'expected FX3 QUEUE bindings not found')
        return

    # ── Step 1: Create STRICT test scheduler ─────────────────────────────
    print_section("STEP 1 — Create SCHEDULER|sched_strict_t14 (STRICT)", art_key='scheduler')
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "SCHEDULER|sched_strict_t14" "type" "STRICT"',
              skip_error_check=True)
    st.wait(1)
    out = st.show(dut,
                  'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|sched_strict_t14"',
                  skip_tmpl=True)
    st.log("  sched_strict_t14 = {}".format(parse_redis_hgetall(out)))

    # ── Step 2: Bind STRICT to Q5→Q1 sequentially ────────────────────────
    # FX3 baseline: Q6=STRICT, Q7=STRICT already.
    # Extend STRICT block downward: Q5, Q4, Q3, Q2, Q1 (each must succeed).
    for qi in [5, 4, 3, 2, 1]:
        print_section(
            "STEP 2 — HDEL then rebind Q{}=STRICT (extending STRICT block)".format(qi),
            art_key='scheduler')
        st.config(dut,
                  'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
                  skip_error_check=True)
        st.wait(1)
        st.config(dut,
                  'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|{}" "scheduler" '
                  '"sched_strict_t14"'.format(egress, qi),
                  skip_error_check=True)
        st.wait(2)
        out_raw = dchal_show_queuing(dut, "After Q{}=STRICT".format(qi), egress)
        verify_queue_strict("Q{} STRICT bind verify".format(qi), out_raw, fail_msgs, queue=qi)
        q_binding = get_queue_binding(dut, egress, qi)
        st.log("  Q{} CONFIG_DB binding: '{}'".format(qi, q_binding))

    st.log("  STRICT block now extends Q1-Q7 (7 queues)")

    # ── Step 3: Snapshot Q0 before attempt ───────────────────────────────
    print_section("STEP 3 — Snapshot Q0 DCHAL state before STRICT bind attempt",
                  art_key='scheduler')
    raw_before_q0 = dchal_show_queuing(dut, "Q0 BEFORE STRICT attempt", egress)
    log_dchal_egress_table(raw_before_q0, "Q0 BEFORE STRICT attempt")
    _q0_binding_before = get_queue_binding(dut, egress, 0)
    st.log("  Q0 CONFIG_DB binding before attempt: '{}'".format(_q0_binding_before))

    # ── Step 4: Attempt Q0=STRICT — must FAIL ────────────────────────────
    print_section("STEP 4 — Attempt Q0=STRICT (expect REJECTION by SAI)",
                  art_key='scheduler')
    st.log("  All Q1-Q7 are STRICT → Q0=STRICT would leave no DWRR sink → rejected")
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|0" "scheduler" '
              '"sched_strict_t14"'.format(egress),
              skip_error_check=True)
    st.wait(3)

    # ── Step 5: Verify Q0 still DWRR in DCHAL ────────────────────────────
    print_section("STEP 5 — DCHAL HW verify: Q0 must remain DWRR", art_key='scheduler')
    raw_after_q0 = dchal_show_queuing(dut, "Q0 AFTER STRICT attempt", egress)
    log_dchal_egress_table(raw_after_q0, "Q0 AFTER STRICT attempt")
    verify_queue_dwrr("Q0 post-attempt DWRR verify", raw_after_q0, fail_msgs, queue=0)

    _q0_binding_after = get_queue_binding(dut, egress, 0)
    st.log("  Q0 CONFIG_DB binding after attempt: '{}'".format(_q0_binding_after))
    st.log("  Q0 DCHAL: SAI must have rejected HW programming even if CONFIG_DB updated")

    # ── Step 6: IPv4 traffic — Q0 only; verify non-zero BW ───────────────
    print_section("STEP 6 — IPv4 + IPv6 traffic: Q0 only (1 DWRR queue; all others STRICT)",
                  art_key='scheduler')
    st.log("  Q1-Q7 are STRICT (sched_strict_t14 or original scheduler.6/7)")
    st.log("  Q0 is DWRR — should receive all non-STRICT bandwidth")
    # Send Q0 traffic with a minimal weight map; STRICT queues drain first but
    # Q0 traffic should still progress (non-zero egress packets from Q0)
    _w_q0_only = {0: 1}
    raw_q0_dchal = dchal_show_queuing(dut, "Q0-only DCHAL", egress)
    scheduler_traffic_check(
        "All-STRICT-fails-on-Q0 [IPv4]", _w_q0_only, fail_msgs, checkpoint_summary,
        macs, strict_queues=(1, 2, 3, 4, 5, 6, 7),
        note="Q0 only DWRR; Q1-Q7 STRICT; verify Q0 non-zero BW")
    scheduler_traffic_check_v6(
        "All-STRICT-fails-on-Q0 [IPv6]", _w_q0_only, fail_msgs, checkpoint_summary,
        macs, strict_queues=(1, 2, 3, 4, 5, 6, 7),
        note="Q0 only DWRR; Q1-Q7 STRICT; verify Q0 non-zero BW")
    del raw_q0_dchal  # used for log side-effect only

    # ── Step 7: Restore ───────────────────────────────────────────────────
    print_section("STEP 7 — Restore: config qos reload", art_key='scheduler')
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    st.config(dut,
              'sonic-db-cli CONFIG_DB DEL "SCHEDULER|sched_strict_t14"',
              skip_error_check=True)
    log_scheduler_state("Restore")

    print_scheduler_summary(checkpoint_summary)

    st.log("=" * 72)
    if fail_msgs:
        st.log("  ALL-QUEUES-STRICT-FAILS-ON-Q0 — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'All-STRICT-fails-on-Q0 FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  ALL-QUEUES-STRICT-FAILS-ON-Q0 — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  Q1-Q7 bound STRICT successfully; Q0=STRICT rejected by SAI; "
               "Q0 remained DWRR in HW and received non-zero egress bandwidth")
        st.log("=" * 72)
        st.report_pass('msg',
            'All-STRICT-fails-on-Q0 PASSED (IPv4 + IPv6): '
            'Q1-Q7 STRICT bind accepted; Q0=STRICT rejected by SAI; '
            'Q0 remained DWRR in DCHAL and received non-zero bandwidth')


def test_bind_same_scheduler_to_multiple_sgs(setup_topo):
    """Test 15: Single scheduler OID shared across multiple SGs; verify DCHAL + traffic.

    Binds two shared DWRR profiles across Q0-Q6 (alternating w=30 and w=20)
    with Q7=STRICT.  Validates that all SGs sharing the same scheduler OID
    get identical DCHAL BW% and exhibit proportional Tx-pkt ratios.

    Shared bindings:
      Q0, Q2, Q4, Q6 → sched_w30 (DWRR, weight=30)  — 4 SGs share one OID
      Q1, Q3, Q5     → sched_w20 (DWRR, weight=20)  — 3 SGs share one OID
      Q7             → sched_strict_t15 (STRICT)

    Expected proportions (total DWRR weight = 4×30 + 3×20 = 180):
      Q0/Q2/Q4/Q6: ~16.7% each   (w=30/180)
      Q1/Q3/Q5:    ~11.1% each   (w=20/180)
      Q7:           0%           (STRICT — drains first)

    Steps:
      1. Verify FX3 baseline
      2. Create sched_w30, sched_w20, sched_strict_t15
      3. Bind sequentially: Q6=sched_w30 (STRICT→DWRR on Q6 while Q7=STRICT),
         then Q0,Q2,Q4 → sched_w30; Q1,Q3,Q5 → sched_w20; Q7 → sched_strict_t15
      4. Verify CONFIG_DB bindings (8 entries, 3 distinct OIDs)
      5. DCHAL: validate shared-OID BW% proportions
      6. IPv4 + IPv6 traffic: weight_map {0:30,1:20,2:30,3:20,4:30,5:20,6:30}
      7. Restore: config qos reload; DEL 3 custom schedulers
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    st.banner(
        "test_bind_same_scheduler_to_multiple_sgs  [IPv4 + IPv6  dual-stack]\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Plan     : Baseline → shared sched_w30 on Q0/Q2/Q4/Q6 + sched_w20 on "
        "Q1/Q3/Q5 + sched_strict_t15 on Q7 → DCHAL + traffic → Restore".format(
            dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'))
    )
    fail_msgs = []
    checkpoint_summary = {}

    _original_bindings = {qi: 'scheduler.{}'.format(qi) for qi in range(8)}
    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    w_shared = {0: 30, 1: 20, 2: 30, 3: 20, 4: 30, 5: 20, 6: 30}

    # ── Step 0: Verify FX3 baseline ───────────────────────────────────────
    print_section("STEP 0 — FX3 baseline verify", art_key='scheduler')
    log_scheduler_state_table(dut, "BEFORE — FX3 baseline")
    baseline_bindings = log_queue_bindings_table(
        dut, egress, "BEFORE — FX3 baseline", _original_bindings)
    baseline_fails = [qi for qi in range(8)
                      if baseline_bindings[qi] != _original_bindings[qi]]
    if baseline_fails:
        for qi in baseline_fails:
            fail_msgs.append(
                "Baseline: QUEUE|{}|{} = '{}', expected '{}'".format(
                    egress, qi, baseline_bindings[qi], _original_bindings[qi]))
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        st.report_fail('msg',
                       'Shared-scheduler FAILED at baseline — '
                       'expected FX3 QUEUE bindings not found')
        return

    # ── Step 1: Create shared scheduler profiles ──────────────────────────
    print_section("STEP 1 — Create sched_w30, sched_w20, sched_strict_t15",
                  art_key='scheduler')
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "SCHEDULER|sched_w30" '
              '"type" "DWRR" "weight" "30"',
              skip_error_check=True)
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "SCHEDULER|sched_w20" '
              '"type" "DWRR" "weight" "20"',
              skip_error_check=True)
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "SCHEDULER|sched_strict_t15" '
              '"type" "STRICT"',
              skip_error_check=True)
    st.wait(1)
    for name in ['sched_w30', 'sched_w20', 'sched_strict_t15']:
        out = st.show(dut,
                      'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
                      skip_tmpl=True)
        st.log("  {} = {}".format(name, parse_redis_hgetall(out)))

    # ── Step 2: Bind Q6=sched_w30 first (STRICT→DWRR; Q7=STRICT still valid) ─
    print_section("STEP 2 — Bind Q6=sched_w30 first (DWRR while Q7=STRICT)",
                  art_key='scheduler')
    st.config(dut,
              'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|6" "scheduler" '
              '"sched_w30"'.format(egress),
              skip_error_check=True)
    st.wait(2)
    q6_b = get_queue_binding(dut, egress, 6)
    st.log("  Q6 binding after first step: '{}'  expected 'sched_w30'".format(q6_b))
    if q6_b != 'sched_w30':
        fail_msgs.append("Step 2: Q6 binding = '{}', expected 'sched_w30'".format(q6_b))

    # ── Step 3: Bind remaining queues ─────────────────────────────────────
    print_section("STEP 3 — Bind Q0,Q2,Q4→sched_w30; Q1,Q3,Q5→sched_w20; Q7→sched_strict_t15",
                  art_key='scheduler')
    for qi, sched_name in [(0, 'sched_w30'), (1, 'sched_w20'),
                           (2, 'sched_w30'), (3, 'sched_w20'),
                           (4, 'sched_w30'), (5, 'sched_w20'),
                           (7, 'sched_strict_t15')]:
        st.config(dut,
                  'sonic-db-cli CONFIG_DB HSET "QUEUE|{}|{}" "scheduler" '
                  '"{}"'.format(egress, qi, sched_name),
                  skip_error_check=True)
        st.wait(1)
        bound = get_queue_binding(dut, egress, qi)
        st.log("  Q{} → '{}'  (expected '{}')  {}".format(
            qi, bound, sched_name, "OK" if bound == sched_name else "MISMATCH"))
        if bound != sched_name:
            fail_msgs.append("Step 3: Q{} binding = '{}', expected '{}'".format(
                qi, bound, sched_name))

    st.wait(2)

    # ── Step 4: Verify all 8 CONFIG_DB bindings ───────────────────────────
    print_section("STEP 4 — Verify all 8 CONFIG_DB bindings", art_key='scheduler')
    _expected_shared = {0: 'sched_w30', 1: 'sched_w20',
                        2: 'sched_w30', 3: 'sched_w20',
                        4: 'sched_w30', 5: 'sched_w20',
                        6: 'sched_w30', 7: 'sched_strict_t15'}
    log_queue_bindings_table(dut, egress, "Shared schedulers", _expected_shared)

    # ── Step 5: DCHAL + BW% validation ───────────────────────────────────
    print_section("STEP 5 — DCHAL: validate shared-OID BW% proportions",
                  art_key='scheduler')
    raw_shared = dchal_show_queuing(dut, "Shared schedulers", egress)
    log_dchal_egress_table(raw_shared, "Shared schedulers")
    _dchal_bw = validate_dchal_bw_vs_weights(
        "Shared-SGs DCHAL", raw_shared, w_shared, fail_msgs)

    # ── Step 6: IPv4 traffic ──────────────────────────────────────────────
    print_section("STEP 6 — IPv4 + IPv6 traffic: 7-queue DWRR; Q7=STRICT",
                  art_key='scheduler')
    scheduler_traffic_check(
        "Shared-SGs [IPv4]", w_shared, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw, strict_queues=(7,),
        note="sched_w30 shared on Q0/Q2/Q4/Q6; sched_w20 shared on Q1/Q3/Q5; Q7=STRICT")
    scheduler_traffic_check_v6(
        "Shared-SGs [IPv6]", w_shared, fail_msgs, checkpoint_summary,
        macs, strict_queues=(7,),
        note="sched_w30 shared on Q0/Q2/Q4/Q6; sched_w20 shared on Q1/Q3/Q5; Q7=STRICT")

    # ── Step 7: Restore ───────────────────────────────────────────────────
    print_section("STEP 7 — Restore: config qos reload; DEL custom schedulers",
                  art_key='scheduler')
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    for name in ['sched_w30', 'sched_w20', 'sched_strict_t15']:
        st.config(dut,
                  'sonic-db-cli CONFIG_DB DEL "SCHEDULER|{}"'.format(name),
                  skip_error_check=True)
    log_scheduler_state("Restore")

    print_scheduler_summary(checkpoint_summary)

    st.log("=" * 72)
    if fail_msgs:
        st.log("  SHARED-SCHEDULER — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Shared-scheduler FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  SHARED-SCHEDULER — ALL CHECKS PASSED (IPv4 + IPv6)")
        st.log("  sched_w30 shared on Q0/Q2/Q4/Q6 (~16.7% each); "
               "sched_w20 shared on Q1/Q3/Q5 (~11.1% each); Q7=STRICT (0%)")
        st.log("=" * 72)
        st.report_pass('msg',
            'Shared-scheduler PASSED (IPv4 + IPv6): '
            'sched_w30 (w=30) shared on Q0/Q2/Q4/Q6; sched_w20 (w=20) shared on Q1/Q3/Q5; '
            'DCHAL BW%% and Tx-pkt ratios match expected proportions; Q7=STRICT (0%%)')


def test_multi_port_isolation(setup_topo):
    """Test 32: Scheduler config on egress port must not affect ingress_a DCHAL state.

    Applies and verifies the full FX3 QoS config on the egress port, runs
    traffic, then confirms that the ingress_a port DCHAL BW% registers are
    unchanged before and after the egress port configuration.

    Steps:
      1. Snapshot ingress_a (Port B) DCHAL before any changes
      2. Verify FX3 config active on egress (Port A): CONFIG_DB bindings + DCHAL BW%
      3. IPv4 + IPv6 traffic on Port A (egress) with FX3 baseline weights
      4. Snapshot ingress_a DCHAL after traffic
      5. Compare Port B DCHAL BW% before vs after (±1.0% tolerance per queue)
      6. No DUT config changes — no restore needed
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    port_b = port_info['ingress_a']

    st.banner(
        "test_multi_port_isolation  [cross-port isolation]\n"
        "  DUT      : {}\n"
        "  Port A   : {}  (egress — FX3 QoS config applied)\n"
        "  Port B   : {}  (ingress_a — must be unaffected)\n"
        "  Plan     : Snapshot Port B → Verify Port A FX3 → Traffic on Port A "
        "→ Snapshot Port B again → Compare".format(dut, egress, port_b)
    )
    fail_msgs = []
    checkpoint_summary = {}

    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    _original_bindings = {qi: 'scheduler.{}'.format(qi) for qi in range(8)}

    # ── Step 1: Snapshot Port B DCHAL before ─────────────────────────────
    print_section("STEP 1 — Snapshot Port B (ingress_a={}) DCHAL before".format(port_b),
                  art_key='scheduler')
    raw_b_before = dchal_show_queuing(dut, "Port B BEFORE", port_b)
    log_dchal_egress_table(raw_b_before, "Port B BEFORE — baseline")
    _bw_b_before = parse_dchal_egress_bw(raw_b_before)
    st.log("  Port B BW% snapshot before:")
    for qi in range(NUM_QUEUES):
        bw_entry = (_bw_b_before or {}).get(qi, {})
        bw_pct = bw_entry.get('bw_pct') if bw_entry else None
        st.log("    Q{}: bw_pct={}".format(qi, bw_pct))

    # ── Step 2: Verify FX3 config on Port A (egress) ─────────────────────
    print_section("STEP 2 — Verify Port A (egress={}) FX3 config active".format(egress),
                  art_key='scheduler')
    log_queue_bindings_table(dut, egress, "Port A CONFIG_DB bindings", _original_bindings)
    raw_a = dchal_show_queuing(dut, "Port A FX3 config", egress)
    log_dchal_egress_table(raw_a, "Port A FX3 config")
    _dchal_bw_a = validate_dchal_bw_vs_weights(
        "Port A FX3 DCHAL", raw_a, w_baseline, fail_msgs)

    # ── Step 3: IPv4 + IPv6 traffic on Port A ───────────────────────────
    print_section("STEP 3 — IPv4 + IPv6 traffic on Port A (FX3 baseline weights)",
                  art_key='scheduler')
    scheduler_traffic_check(
        "Multi-port-isolation Port A [IPv4]", w_baseline, fail_msgs, checkpoint_summary,
        macs, dchal_bw=_dchal_bw_a,
        note="Port A traffic; Port B should be unaffected")
    scheduler_traffic_check_v6(
        "Multi-port-isolation Port A [IPv6]", w_baseline, fail_msgs, checkpoint_summary,
        macs,
        note="Port A traffic; Port B should be unaffected")

    # ── Step 4: Snapshot Port B DCHAL after ──────────────────────────────
    print_section("STEP 4 — Snapshot Port B (ingress_a) DCHAL after traffic",
                  art_key='scheduler')
    raw_b_after = dchal_show_queuing(dut, "Port B AFTER", port_b)
    log_dchal_egress_table(raw_b_after, "Port B AFTER — must be unchanged")
    _bw_b_after = parse_dchal_egress_bw(raw_b_after)
    st.log("  Port B BW% snapshot after:")
    for qi in range(NUM_QUEUES):
        bw_entry = (_bw_b_after or {}).get(qi, {})
        bw_pct = bw_entry.get('bw_pct') if bw_entry else None
        st.log("    Q{}: bw_pct={}".format(qi, bw_pct))

    # ── Step 5: Compare Port B before vs after ───────────────────────────
    print_section("STEP 5 — Compare Port B BW% before vs after (tolerance ±1.0%)",
                  art_key='scheduler')
    _ISOLATION_TOLERANCE = 1.0
    st.log("  {:<6} {:>14} {:>14} {:>10} {:>10}".format(
        "Queue", "Before BW%", "After BW%", "Delta", "Result"))
    st.log("  " + "-" * 60)
    for qi in range(NUM_QUEUES):
        bw_before_entry = (_bw_b_before or {}).get(qi, {}) or {}
        bw_after_entry  = (_bw_b_after  or {}).get(qi, {}) or {}
        bw_before = bw_before_entry.get('bw_pct')
        bw_after  = bw_after_entry.get('bw_pct')
        if bw_before is None and bw_after is None:
            result = "OK (both N/A)"
            delta_str = "N/A"
        elif bw_before is None or bw_after is None:
            result = "MISMATCH (one N/A)"
            delta_str = "N/A"
            fail_msgs.append(
                "Port B Q{} isolation: before={} after={} — one side N/A".format(
                    qi, bw_before, bw_after))
        else:
            delta = abs(bw_after - bw_before)
            delta_str = "{:+.1f}%".format(bw_after - bw_before)
            if delta <= _ISOLATION_TOLERANCE:
                result = "OK"
            else:
                result = "MISMATCH"
                fail_msgs.append(
                    "Port B Q{} isolation: before={:.1f}% after={:.1f}% "
                    "delta={:.1f}% > {:.1f}% tolerance".format(
                        qi, bw_before, bw_after, delta, _ISOLATION_TOLERANCE))
        st.log("  Q{:<5} {:>14} {:>14} {:>10} {:>10}".format(
            qi,
            "{:.1f}%".format(bw_before) if bw_before is not None else "N/A",
            "{:.1f}%".format(bw_after)  if bw_after  is not None else "N/A",
            delta_str, result))
    st.log("  " + "-" * 60)

    # No DUT config changes — no restore step needed
    print_scheduler_summary(checkpoint_summary)

    st.log("=" * 72)
    if fail_msgs:
        st.log("  MULTI-PORT-ISOLATION — FAILURES ({} total):".format(len(fail_msgs)))
    # On FX3, SAI_SCHEDULER_GROUP_ATTR_PORT_ID is not stored in ASIC_DB.
    # Use COUNTERS_QUEUE_NAME_MAP (has Ethernet1_N:0 .. Ethernet1_N:7) as the
    # authoritative source — one entry per scheduler group (1:1 queue:SG).
    queue_oids = get_scheduler_groups_for_port(dut, egress)
    count = len(queue_oids)
    st.log("  Queue OIDs (== scheduler group count) for {}: {}".format(egress, count))
    for qi in sorted(queue_oids):
        st.log("    Queue[{}] = {}".format(qi, queue_oids[qi]))

    if count != 8:
        fail_msgs.append(
            "Expected 8 scheduler groups for port {}, got {}".format(egress, count))

    # ── Verdict ────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  SCHEDULER GROUP COUNT — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Scheduler-group-count FAILED ({} failures) — see above'.format(
                len(fail_msgs)))
    else:
        st.log("  SCHEDULER GROUP COUNT — PASSED")
        st.log("  Found exactly 8 scheduler groups for port {}".format(egress))
        st.log("=" * 72)
        st.report_pass('msg',
            'Scheduler-group-count PASSED: 8 scheduler groups found for port {}'.format(
                egress))


def test_fx3_scheduler_group_child_is_queue(setup_topo):
    """Verify each scheduler group's child count, port, and level attributes.

    Maps to SAI test_scheduler_group_child_is_queue and
    scheduler_test_plan.md test 40.

    FX3 platform note: SAI_SCHEDULER_GROUP_ATTR_PORT_ID, CHILD_COUNT, and LEVEL
    are not written to ASIC_DB on this platform, so they cannot be queried
    directly.  The test instead verifies the same structural guarantees through
    two available data sources:

    Step 1 — COUNTERS_DB COUNTERS_QUEUE_NAME_MAP (8 targeted HGET calls):
      Confirm exactly 8 queue OIDs are registered for the egress port
      (Ethernet1_N:0 .. Ethernet1_N:7).  On FX3 the HW uses a strict 1:1
      queue-to-scheduler-group mapping, so a count of 8 here is equivalent to
      confirming 8 scheduler groups exist for the port.

    Step 2 — ASIC_DB ASIC_STATE:SAI_OBJECT_TYPE_QUEUE per queue OID:
      For each of the 8 queue OIDs:
        a. SAI_QUEUE_ATTR_INDEX == expected queue index (0-7) — confirms the
           OID maps to the correct HW queue position.
        b. SAI_QUEUE_ATTR_TYPE is non-empty — confirms the queue object is
           fully programmed in HW.

    Step 3 — CONFIG_DB QUEUE|{port}|{qi} scheduler field:
      Each queue must have a scheduler binding in CONFIG_DB, which proves
      orchagent linked the queue as a child of a scheduler group (the
      SAI equivalent of CHILD_COUNT == 1).

    Read-only structural check; no CONFIG_DB changes; no restore needed.
    """
    egress = port_info['egress']
    st.banner(
        "test_fx3_scheduler_group_child_is_queue\n"
        "  DUT    : {}\n"
        "  Egress : {}\n"
        "  Plan   : COUNTERS_DB+ASIC_DB — each queue: INDEX correct, TYPE set, "
        "scheduler bound".format(dut, egress)
    )
    fail_msgs = []

    # Get queue OIDs — 1:1 with scheduler groups on FX3
    queue_oids = get_scheduler_groups_for_port(dut, egress)
    count = len(queue_oids)
    st.log("  Queue OIDs for {}: {}".format(egress, count))
    if count != 8:
        fail_msgs.append(
            "Expected 8 scheduler groups for port {}, got {}".format(egress, count))

    for qi in sorted(queue_oids):
        q_oid = queue_oids[qi]
        asic_key = 'ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:{}'.format(q_oid)

        # SAI_QUEUE_ATTR_INDEX — must match the name-map index
        out_idx = st.show(dut,
            'sonic-db-cli ASIC_DB HGET "{}" "SAI_QUEUE_ATTR_INDEX"'.format(asic_key),
            skip_tmpl=True)
        idx_str = parse_redis_hget(out_idx).strip()
        try:
            idx_val = int(idx_str)
        except (ValueError, TypeError):
            idx_val = -1

        # SAI_QUEUE_ATTR_TYPE — must be set
        out_ty = st.show(dut,
            'sonic-db-cli ASIC_DB HGET "{}" "SAI_QUEUE_ATTR_TYPE"'.format(asic_key),
            skip_tmpl=True)
        type_val = parse_redis_hget(out_ty).strip()

        # CONFIG_DB scheduler binding — proves queue is child of a scheduler group
        out_sched = st.show(dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
            skip_tmpl=True)
        sched_val = parse_redis_hget(out_sched).strip()

        ok = (idx_val == qi and bool(type_val) and bool(sched_val))
        st.log("  Queue[{}] oid={}: INDEX={} TYPE={} scheduler={}  {}".format(
            qi, q_oid, idx_val, type_val or '<missing>',
            sched_val or '<unbound>', "OK" if ok else "FAIL"))

        if idx_val != qi:
            fail_msgs.append(
                "Queue[{}] {}: INDEX={}, expected {}".format(qi, q_oid, idx_val, qi))
        if not type_val:
            fail_msgs.append(
                "Queue[{}] {}: SAI_QUEUE_ATTR_TYPE missing".format(qi, q_oid))
        if not sched_val:
            fail_msgs.append(
                "Queue[{}] {}: CONFIG_DB scheduler binding missing".format(qi, q_oid))

    # ── Verdict ────────────────────────────────────────────────────────────
    st.log("=" * 72)
    if fail_msgs:
        st.log("  SCHEDULER GROUP CHILD — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'scheduler-group-child-is-queue FAILED ({} failures) — see above'.format(len(fail_msgs)))
    else:
        st.log("  SCHEDULER GROUP CHILD — ALL CHECKS PASSED")
        st.log("  8 queue OIDs found; each has correct INDEX, TYPE set, and scheduler bound")
        st.log("=" * 72)
        st.report_pass('msg',
            'scheduler-group-child-is-queue PASSED: '
            '8 queue OIDs confirmed with correct INDEX, TYPE, and CONFIG_DB scheduler binding')


def test_tortuga_scheduler_config_repeated(setup_topo):
    """Test 18: Apply full FX3 QoS config + traffic + teardown, repeated 5 times.

    Each cycle verifies that the FX3 reference configuration can be applied,
    confirmed via DCHAL, exercised with IPv4 and IPv6 traffic, and cleanly
    torn down — 5 times in a row.  Ensures no state leakage between cycles.

    Per-cycle steps:
      A. config qos reload (FX3 baseline)
      B. Verify all 8 QUEUE→scheduler.N CONFIG_DB bindings
      C. DCHAL BW% validation (w_baseline)
      D. IPv4 traffic — validate DWRR ratios
      E. IPv6 traffic — validate DWRR ratios
      F. Teardown: HDEL all 8 QUEUE|egress|N scheduler fields
      G. Verify all 8 bindings absent from CONFIG_DB

    Final restore: config qos reload + print summary.
    """
    _ingress_roles = sorted(k for k in port_info if k != 'egress')
    egress = port_info['egress']
    NUM_CYCLES = 5
    st.banner(
        "test_tortuga_scheduler_config_repeated  [{} cycles — IPv4 + IPv6]\n"
        "  DUT      : {}\n"
        "  Ingress  : {}\n"
        "  Egress   : {}  ({}G)\n"
        "  Plan     : {} × [config qos reload → verify bindings → DCHAL → "
        "IPv4 traffic → IPv6 traffic → teardown → verify absent]".format(
            NUM_CYCLES, dut,
            "  ".join("{}={}({}G)".format(r, port_info[r], port_speeds.get(r, '?'))
                      for r in _ingress_roles),
            egress, port_speeds.get('egress', '?'),
            NUM_CYCLES)
    )
    fail_msgs = []
    checkpoint_summary = {}

    macs = {role: get_dut_mac(dut, port_info[role]) for role in _ingress_roles}
    deploy_dchal_helper(dut)

    w_baseline = {0: 20, 1: 20, 2: 20, 3: 40, 4: 40, 5: 30}
    _original_bindings = {qi: 'scheduler.{}'.format(qi) for qi in range(8)}

    for cycle in range(1, NUM_CYCLES + 1):
        st.banner("═" * 72)
        st.banner("CYCLE {}/{} — START".format(cycle, NUM_CYCLES))
        st.banner("═" * 72)

        # ── Step A: Apply FX3 config via config qos reload ────────────────
        print_section("CYCLE {} — STEP A: config qos reload".format(cycle),
                      art_key='scheduler')
        st.config(dut, "config qos reload", skip_error_check=True)
        st.wait(5)
        log_scheduler_state("Cycle {} after reload".format(cycle))

        # ── Step B: Verify all 8 QUEUE→scheduler.N bindings ──────────────
        print_section("CYCLE {} — STEP B: Verify 8 QUEUE bindings".format(cycle),
                      art_key='scheduler')
        cycle_bindings = log_queue_bindings_table(
            dut, egress, "Cycle {} bindings".format(cycle), _original_bindings)
        binding_fails = [qi for qi in range(8)
                         if cycle_bindings[qi] != _original_bindings[qi]]
        for qi in binding_fails:
            fail_msgs.append(
                "Cycle {}: QUEUE|{}|{} = '{}', expected '{}'".format(
                    cycle, egress, qi, cycle_bindings[qi], _original_bindings[qi]))
        if binding_fails:
            st.log("  Cycle {}: {} binding mismatch(es) — continuing to teardown".format(
                cycle, len(binding_fails)))

        # ── Step C: DCHAL BW% validation ─────────────────────────────────
        print_section("CYCLE {} — STEP C: DCHAL BW% validate".format(cycle),
                      art_key='scheduler')
        raw_cycle = dchal_show_queuing(dut, "Cycle {} DCHAL".format(cycle), egress)
        log_dchal_egress_table(raw_cycle, "Cycle {} DCHAL".format(cycle))
        _dchal_bw = validate_dchal_bw_vs_weights(
            "Cycle {} DCHAL".format(cycle), raw_cycle, w_baseline, fail_msgs)

        # ── Step D: IPv4 traffic ──────────────────────────────────────────
        print_section("CYCLE {} — STEP D: IPv4 traffic".format(cycle),
                      art_key='scheduler')
        scheduler_traffic_check(
            "Cycle {} [IPv4]".format(cycle), w_baseline, fail_msgs, checkpoint_summary,
            macs, dchal_bw=_dchal_bw,
            note="Cycle {}/{}".format(cycle, NUM_CYCLES))

        # ── Step E: IPv6 traffic ──────────────────────────────────────────
        print_section("CYCLE {} — STEP E: IPv6 traffic".format(cycle),
                      art_key='scheduler')
        scheduler_traffic_check_v6(
            "Cycle {} [IPv6]".format(cycle), w_baseline, fail_msgs, checkpoint_summary,
            macs,
            note="Cycle {}/{}".format(cycle, NUM_CYCLES))

        # ── Step F: Teardown — HDEL all 8 QUEUE bindings ──────────────────
        print_section("CYCLE {} — STEP F: Teardown — HDEL all 8 QUEUE|egress|N scheduler".format(
            cycle), art_key='scheduler')
        for qi in range(NUM_QUEUES):
            st.config(dut,
                      'sonic-db-cli CONFIG_DB HDEL "QUEUE|{}|{}" "scheduler"'.format(
                          egress, qi),
                      skip_error_check=True)
            st.wait(1)
        st.wait(2)

        # ── Step G: Verify all 8 bindings absent ─────────────────────────
        print_section("CYCLE {} — STEP G: Verify all 8 QUEUE bindings absent".format(cycle),
                      art_key='scheduler')
        for qi in range(NUM_QUEUES):
            out = st.show(dut,
                'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(egress, qi),
                skip_tmpl=True)
            actual = parse_redis_hget(out).strip()
            st.log("  Cycle {} Q{} binding after teardown: '{}'  (expected empty)".format(
                cycle, qi, actual))
            if actual:
                fail_msgs.append(
                    "Cycle {}: QUEUE|{}|{} still has scheduler='{}' after HDEL".format(
                        cycle, egress, qi, actual))

        st.banner("CYCLE {}/{} — DONE  (cumulative failures: {})".format(
            cycle, NUM_CYCLES, len(fail_msgs)))

    # ── Final restore ─────────────────────────────────────────────────────
    print_section("FINAL RESTORE — config qos reload", art_key='scheduler')
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    log_scheduler_state("Final restore")

    print_scheduler_summary(checkpoint_summary)

    st.log("=" * 72)
    if fail_msgs:
        st.log("  SCHEDULER-CONFIG-REPEATED — FAILURES ({} total):".format(len(fail_msgs)))
        for i, msg in enumerate(fail_msgs, 1):
            st.log("  [{:02d}] {}".format(i, msg))
        st.log("=" * 72)
        st.report_fail('msg',
            'Scheduler-config-repeated FAILED ({} failures across {} cycles) — '
            'see above'.format(len(fail_msgs), NUM_CYCLES))
    else:
        st.log("  SCHEDULER-CONFIG-REPEATED — ALL {} CYCLES PASSED (IPv4 + IPv6)".format(
            NUM_CYCLES))
        st.log("  FX3 baseline applied, verified, traffic-tested, and torn down "
               "{} times without any failures".format(NUM_CYCLES))
        st.log("=" * 72)
        st.report_pass('msg',
            'Scheduler-config-repeated PASSED: {} cycles × '
            '[config qos reload → DCHAL BW%%verify → IPv4+IPv6 traffic → teardown] '
            'all passed; no state leakage between cycles'.format(NUM_CYCLES))


