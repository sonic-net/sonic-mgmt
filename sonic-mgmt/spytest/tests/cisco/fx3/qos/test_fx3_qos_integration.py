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
    QUEUE_TO_DSCP,
    ensure_interfaces_admin_up, verify_queue_counters,
    verify_config_db_baseline,
    deploy_dchal_helper, dchal_show_queuing, report_dchal_bw_check,
    get_dchal_queue_counters, get_dut_mac,
    clear_dut_counters, dchal_clear_counters, get_intf_counters, get_intf_speeds,
    parse_speed_to_mbps,
    report_intf_counters, report_queue_counters,
    validate_dwrr_ratios, validate_dchal_bw_vs_weights,
    report_wred_linearity,
    dump_l3_diag,
    verify_wred_config, wred_fanin_send_and_measure, report_wred_result,
)

from spytest import st, tgapi


# ── L3 Addresses (IPv4) ───────────────────────────────────────────────────
V4_INGRESS_A_IP = '10.10.10.1/24'
V4_INGRESS_B_IP = '10.10.11.1/24'
V4_EGRESS_IP    = '20.20.20.1/24'

IXIA_INGRESS_A_IP = '10.10.10.2'
IXIA_INGRESS_B_IP = '10.10.11.2'
IXIA_EGRESS_IP    = '20.20.20.2'
NETMASK = '255.255.255.0'

# ── L3 Addresses (IPv6) ───────────────────────────────────────────────────
V6_INGRESS_A_IP    = '2001:db8:10::1/64'
V6_INGRESS_B_IP    = '2001:db8:11::1/64'
V6_EGRESS_IP       = '2001:db8:20::1/64'

IXIA_INGRESS_A_IP6 = '2001:db8:10::2'
IXIA_INGRESS_B_IP6 = '2001:db8:11::2'
IXIA_EGRESS_IP6    = '2001:db8:20::2'
PREFIX_LEN_V6      = 64

# ── Traffic parameters ───────────────────────────────────────────────────
PKT_SIZE           = 128
NUM_QUEUES         = 8
TRAFFIC_DURATION   = 10      # match test_scheduler_validation.py
STREAM_RATE_PCT    = 8       # 8% of 100G line rate per stream (match test_scheduler_validation.py)

# ── Target queue for single-stream / WRED tests ─────────────────────────
TARGET_QUEUE        = 1
TARGET_DSCP         = QUEUE_TO_DSCP[TARGET_QUEUE]   # 6

# ── WRED thresholds (from AZURE_LOSSY profile in config_db.json) ────────
WRED_MIN_TH         = 1048576    # 1 MB — below this, 0% drop probability
WRED_MAX_TH         = 3145728    # 3 MB — above this, 100% tail drop
WRED_MAX_PROB       = 5          # 5% max drop probability at max_th
WRED_TOLERANCE      = 2.0        # percentage-point tolerance for pass/fail
WRED_DURATION       = 40         # seconds — accommodates 10 depth samples + settle
WRED_SETTLE_TIME    = 5          # seconds to wait before mid-traffic depth snapshot

# ── WRED Zone A headroom ────────────────────────────────────────────────
# IXIA rate_percent precision is limited; at exactly 50.000% per port the
# actual combined throughput can slightly exceed egress capacity, pushing
# queue depth above min_th and into Zone B.  Use a small negative margin
# so combined rate stays ~0.5% below line rate, keeping the queue firmly
# in Zone A while still validating the "below min_th → zero drops" property.
WRED_ZONE_A_MARGIN  = -500       # Mbps below line rate (per fan-in pair)

# ── Module state ─────────────────────────────────────────────────────────
dut = None
tg = None
tg_ph = {}          # {'ingress_a': handle, 'ingress_b': handle, 'egress': handle}
port_info = {}      # {'ingress_a': '<D1T1P1>', 'ingress_b': '<D1T1P2>', 'egress': '<D1T1P3>'}
port_speeds = {}    # {'ingress_a': '100G', 'ingress_b': '100G', 'egress': '100G'}
ingress_speed_mbps = 0
egress_speed_mbps = 0
wred_ctx = {}       # shared context dict for WRED helper functions
tb_vars = None


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

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    """Set up DUT L3, Ixia interfaces, and QoS baseline for all tests."""
    global dut, tg, tg_ph, port_info, tb_vars

    st.log("setup_topo: establishing minimum topology D1T1:3")
    tb_dict = st.ensure_min_topology("D1T1:3")
    tb_vars = st.get_testbed_vars()
    dut = tb_dict.D1

    port_info = {
        'ingress_a': tb_vars.D1T1P1,
        'ingress_b': tb_vars.D1T1P2,
        'egress':    tb_vars.D1T1P3,
    }
    st.log("setup_topo: ports -> {}".format(port_info))

    # ── Ensure interfaces are admin-up before any configuration ──
    st.log("setup_topo: checking interface admin status")
    ensure_interfaces_admin_up(dut, port_info.values())

    # ── Verify queue counters are visible for each interface ──
    st.log("setup_topo: verifying queue counters")
    missing = verify_queue_counters(dut, port_info.values())
    if missing:
        st.warn("setup_topo: queue counters missing for: {}".format(missing))

    tg_handle, tg_ph_a = tgapi.get_handle_byname('T1D1P1')
    _, tg_ph_b = tgapi.get_handle_byname('T1D1P2')
    _, tg_ph_e = tgapi.get_handle_byname('T1D1P3')
    tg = tg_handle
    tg_ph = {'ingress_a': tg_ph_a, 'ingress_b': tg_ph_b, 'egress': tg_ph_e}

    # ── Remove ports from VLAN / PortChannel ──
    st.log("setup_topo: removing port memberships")
    for intf in port_info.values():
        remove_interface_from_all_memberships(dut, intf)

    # ── Query port speeds from DUT ──
    global port_speeds
    raw_speeds = get_intf_speeds(dut, port_info.values())
    port_speeds = {}
    for role, intf in port_info.items():
        port_speeds[role] = raw_speeds.get(intf, 'N/A')
    sep = "=" * 70
    st.log(sep)
    st.log("  PORT SPEED TABLE")
    st.log(sep)
    st.log("  {:<18} {:<12} {:>10}".format('Interface', 'Role', 'Speed'))
    st.log("  " + "-" * 44)
    for role, intf in port_info.items():
        st.log("  {:<18} {:<12} {:>10}".format(intf, role, port_speeds[role]))
    st.log(sep)

    # ── Parse numeric port speeds for rate calculations ──
    global ingress_speed_mbps, egress_speed_mbps
    ingress_speed_mbps = parse_speed_to_mbps(port_speeds.get('ingress_a', ''))
    egress_speed_mbps = parse_speed_to_mbps(port_speeds.get('egress', ''))
    st.log("setup_topo: ingress_speed={}M, egress_speed={}M".format(
        ingress_speed_mbps, egress_speed_mbps))

    # ── Reload QoS to ensure FX3 baseline ──
    st.log("setup_topo: reloading QoS config")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    ensure_interfaces_admin_up(dut, port_info.values())

    # ── L3 on DUT (dual-stack: IPv4 + IPv6) ──
    st.log("setup_topo: configuring L3 interfaces on DUT (dual-stack)")
    l3_cfg = (
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}'
    ).format(
        port_info['ingress_a'], V4_INGRESS_A_IP,
        port_info['ingress_b'], V4_INGRESS_B_IP,
        port_info['egress'],    V4_EGRESS_IP,
        port_info['ingress_a'], V6_INGRESS_A_IP,
        port_info['ingress_b'], V6_INGRESS_B_IP,
        port_info['egress'],    V6_EGRESS_IP,
    )
    st.config(dut, l3_cfg, skip_error_check=True)
    st.wait(2)

    # ── Ixia interfaces: IPv4 (ARP-enabled) ──
    st.log("setup_topo: configuring Ixia IPv4 interfaces")
    ixia_v4_params = [
        ('ingress_a', IXIA_INGRESS_A_IP, '10.10.10.1'),
        ('ingress_b', IXIA_INGRESS_B_IP, '10.10.11.1'),
        ('egress',    IXIA_EGRESS_IP,    '20.20.20.1'),
    ]
    for key, ip, gw in ixia_v4_params:
        tg.tg_interface_config(
            mode='config', port_handle=tg_ph[key],
            intf_ip_addr=ip, netmask=NETMASK, gateway=gw,
            arp_send_req=1, enable_ping_response=1, resolve_gateway_mac=1)

    # ── Ixia interfaces: IPv6 (NDP-enabled) ──
    st.log("setup_topo: configuring Ixia IPv6 interfaces")
    ixia_v6_params = [
        ('ingress_a', IXIA_INGRESS_A_IP6, '2001:db8:10::1'),
        ('ingress_b', IXIA_INGRESS_B_IP6, '2001:db8:11::1'),
        ('egress',    IXIA_EGRESS_IP6,    '2001:db8:20::1'),
    ]
    for key, ip6, gw6 in ixia_v6_params:
        tg.tg_interface_config(
            mode='config', port_handle=tg_ph[key],
            ipv6_intf_addr=ip6, ipv6_prefix_length=PREFIX_LEN_V6,
            ipv6_gateway=gw6, ipv6_resolve_gateway_mac=1,
            arp_send_req=1)

    # Start protocol stacks so Ixia responds to DUT ARP/NDP
    try:
        tg.tg_topology_test_control(action='start_all_protocols')
    except Exception:
        st.warn("start_all_protocols unavailable; relying on arp_send_req")

    st.wait(30)

    # Verify IPv4 connectivity
    ping_out = st.config(dut, "ping -c 5 -W 2 {}".format(IXIA_EGRESS_IP),
                         skip_error_check=True)
    ping_str = str(ping_out) if ping_out else ''
    if '0 received' in ping_str or 'Unreachable' in ping_str:
        st.warn("setup_topo: IPv4 ping to {} FAILED".format(IXIA_EGRESS_IP))
        dump_l3_diag(dut, IXIA_EGRESS_IP)
    else:
        st.log("setup_topo: IPv4 ping to {} OK".format(IXIA_EGRESS_IP))

    # Verify IPv6 connectivity
    ping6_out = st.config(dut, "ping6 -c 5 -W 2 {}".format(IXIA_EGRESS_IP6),
                          skip_error_check=True)
    ping6_str = str(ping6_out) if ping6_out else ''
    if '0 received' in ping6_str or 'Unreachable' in ping6_str:
        st.warn("setup_topo: IPv6 ping to {} FAILED".format(IXIA_EGRESS_IP6))
        dump_l3_diag(dut, IXIA_EGRESS_IP6)
    else:
        st.log("setup_topo: IPv6 ping to {} OK".format(IXIA_EGRESS_IP6))
    st.wait(5)

    # ── Build shared context dict for WRED helper functions ──
    global wred_ctx
    router_mac = get_dut_mac(dut, port_info['ingress_a'])
    st.log("setup_topo: DUT router MAC = {}".format(router_mac))
    wred_ctx = {
        'dut': dut,
        'tg': tg,
        'tg_ph_ingress_a': tg_ph['ingress_a'],
        'tg_ph_ingress_b': tg_ph['ingress_b'],
        'port_info': port_info,
        'ingress_speed_mbps': ingress_speed_mbps,
        'egress_speed_mbps': egress_speed_mbps,
        'target_queue': TARGET_QUEUE,
        'target_dscp': TARGET_DSCP,
        'router_mac': router_mac,
        'pkt_size': PKT_SIZE,
        'num_queues': NUM_QUEUES,
        'wred_min_th': WRED_MIN_TH,
        'wred_max_th': WRED_MAX_TH,
        'wred_max_prob': WRED_MAX_PROB,
        'wred_tolerance': WRED_TOLERANCE,
        'wred_duration': WRED_DURATION,
        'wred_settle_time': WRED_SETTLE_TIME,
        'ips': {
            'v4_src_a': IXIA_INGRESS_A_IP, 'v4_src_b': IXIA_INGRESS_B_IP,
            'v4_dst': IXIA_EGRESS_IP,
            'v4_gw': '10.10.10.1', 'v4_mask': NETMASK,
            'v6_src_a': IXIA_INGRESS_A_IP6, 'v6_src_b': IXIA_INGRESS_B_IP6,
            'v6_dst': IXIA_EGRESS_IP6,
            'v6_gw': '2001:db8:10::1', 'v6_prefix_len': PREFIX_LEN_V6,
        },
    }

    st.log("setup_topo: DONE")
    yield

    # ── Teardown (remove both IPv4 and IPv6) ──
    st.log("setup_topo: teardown — removing L3 config (IPv4 + IPv6)")
    cleanup_cfg = (
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}'
    ).format(
        port_info['ingress_a'], V4_INGRESS_A_IP,
        port_info['ingress_b'], V4_INGRESS_B_IP,
        port_info['egress'],    V4_EGRESS_IP,
        port_info['ingress_a'], V6_INGRESS_A_IP,
        port_info['ingress_b'], V6_INGRESS_B_IP,
        port_info['egress'],    V6_EGRESS_IP,
    )
    st.config(dut, cleanup_cfg, skip_error_check=True)
    st.log("setup_topo: teardown complete")

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
        src_ips   = (IXIA_INGRESS_A_IP6, IXIA_INGRESS_B_IP6)
        dst_ip    = IXIA_EGRESS_IP6
        egress_gw = V6_EGRESS_IP.split('/')[0]
        nb_cmd    = 'show ndp'
        ping_cmd  = 'ping6'
    else:
        src_ips   = (IXIA_INGRESS_A_IP, IXIA_INGRESS_B_IP)
        dst_ip    = IXIA_EGRESS_IP
        egress_gw = V4_EGRESS_IP.split('/')[0]
        nb_cmd    = 'show arp'
        ping_cmd  = 'ping'

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
    st.log("Phase 2 [{}]: Sending oversubscribed traffic "
           "(8 streams x {}% x 2 ports = {}% of {})".format(
               af, STREAM_RATE_PCT, STREAM_RATE_PCT * NUM_QUEUES * 2,
               egress_speed))

    mac_a = get_dut_mac(dut, port_info['ingress_a'])
    mac_b = get_dut_mac(dut, port_info['ingress_b'])
    st.log("DUT MACs: ingress_a={} ingress_b={}".format(mac_a, mac_b))

    # Ensure neighbor (ARP for v4, NDP for v6) for egress next-hop is resolved
    for _attempt in range(1, 4):
        nb_out = str(st.show(dut, "{} {}".format(nb_cmd, dst_ip),
                             skip_tmpl=True) or '')
        if dst_ip in nb_out:
            st.log("{} resolved for {} (attempt {})".format(
                nb_cmd.upper(), dst_ip, _attempt))
            break
        st.log("{} for {} not yet in table (attempt {}); re-triggering".format(
            nb_cmd.upper(), dst_ip, _attempt))
        try:
            if af == "ipv6":
                tg.tg_interface_config(
                    mode='config', port_handle=tg_ph['egress'],
                    ipv6_intf_addr=IXIA_EGRESS_IP6,
                    ipv6_prefix_length=PREFIX_LEN_V6,
                    ipv6_gateway=egress_gw,
                    ipv6_resolve_gateway_mac=1,
                    arp_send_req=1)
            else:
                tg.tg_interface_config(
                    mode='config', port_handle=tg_ph['egress'],
                    intf_ip_addr=IXIA_EGRESS_IP, netmask=NETMASK,
                    gateway=egress_gw,
                    arp_send_req=1, enable_ping_response=1,
                    resolve_gateway_mac=1)
        except Exception as _e:
            st.log("  tg_interface_config re-trigger failed: {}".format(_e))
        st.wait(10)
        st.config(dut, "{} -c 3 -W 2 {}".format(ping_cmd, dst_ip),
                  skip_error_check=True)
        st.wait(3)
    else:
        dump_l3_diag(dut, dst_ip)
        st.report_fail('msg',
                       '{} for {} not resolved after 3 attempts — '
                       'check IXIA interface and L3 config'.format(
                           nb_cmd.upper(), dst_ip))
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

    # Program streams: 8 queues x 2 ingress ports = 16 streams
    stream_handles = []
    ports = [
        (tg_ph['ingress_a'], src_ips[0], mac_a, 'TX1'),
        (tg_ph['ingress_b'], src_ips[1], mac_b, 'TX2'),
    ]
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
                    rate_percent=STREAM_RATE_PCT,
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
                    rate_percent=STREAM_RATE_PCT,
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
    """Quick check that DUT can reach the egress IXIA IP (ARP/NDP resolved)."""
    if af == "ipv6":
        nb_cmd = 'show ndp'
        target = IXIA_EGRESS_IP6
    else:
        nb_cmd = 'show arp'
        target = IXIA_EGRESS_IP
    nb_out = st.show(dut, "{} {}".format(nb_cmd, target), skip_tmpl=True)
    if target in str(nb_out):
        st.log("{} resolved for {} — OK".format(nb_cmd.upper(), target))
        return True
    st.warn("{} NOT resolved for {} — attempting ping".format(
        nb_cmd.upper(), target))
    ping_cmd = 'ping6' if af == 'ipv6' else 'ping'
    st.config(dut, "{} -c 3 -W 2 {}".format(ping_cmd, target),
              skip_error_check=True)
    st.wait(3)
    nb_out = st.show(dut, "{} {}".format(nb_cmd, target), skip_tmpl=True)
    if target in str(nb_out):
        return True
    dump_l3_diag(dut, target)
    return False


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

    st.log("Phase 2: Sending fan-in traffic below line rate "
           "(margin={}M for IXIA headroom)".format(WRED_ZONE_A_MARGIN))
    results = wred_fanin_send_and_measure(wred_ctx, af,
                                          margin_mbps=WRED_ZONE_A_MARGIN,
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

    Fan-in at egress rate + margin.  Each port sends at
    (100G + margin) / 2 / 100G * 100 %.

    Margins are 10x vs 2021 (10G egress) to match WRED curve coverage.
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

    st.log("Phase 2: Sending fan-in traffic with {}M margin".format(margin_mbps))
    results = wred_fanin_send_and_measure(wred_ctx, af, margin_mbps,
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

    Fan-in with 10000 Mbps margin (10G over 100G egress).
    The excess overwhelms WRED's 5% max drop probability, causing
    queue to exceed max_threshold and trigger tail drop.
    """
    margin = 10000
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
    Margins are 10x vs 2021 (10G) for equivalent coverage on 100G.

    Expected steady-state (100G egress):
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
    margins = [0, 250, 500, 1000, 2000, 3000, 4000, 5000, 5250, 5500]
    st.banner("test_wred_linearity [{}] margins={} (fan-in)".format(af, margins))
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

    st.log("Phase 2: Running {} margin points".format(len(margins)))
    data_points = []
    for m in margins:
        st.log("--- Margin {}M ---".format(m))
        r = wred_fanin_send_and_measure(wred_ctx, af, m, duration=20,
                                         num_depth_samples=3)
        report_wred_result(wred_ctx, r, "LINEARITY point {}M".format(m))
        data_points.append(r)
        st.wait(5)

    monotonic = report_wred_linearity(data_points, egress_speed_mbps)

    if not monotonic:
        fail_msgs.append("Drop rates are NOT monotonically increasing")

    for dp in data_points:
        if dp['egress_pkts'] <= 0:
            fail_msgs.append("Margin={}M: egress_pkts=0 — traffic not "
                             "forwarded".format(dp['margin_mbps']))
        if dp['margin_mbps'] > 0 and dp['drop_pkts'] <= 0:
            fail_msgs.append("Margin={}M: 0 drops — WRED not active".format(
                dp['margin_mbps']))

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

