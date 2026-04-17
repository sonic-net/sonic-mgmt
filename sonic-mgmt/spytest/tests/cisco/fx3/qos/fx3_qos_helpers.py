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
FX3 QoS helper library — shared utilities and golden data for FX3 QoS tests.

Golden Data (default global config):
  - QUEUE_TO_DSCP          : DSCP value per queue (TC N = Q N)
  - EXPECTED_SCHEDULERS    : expected SCHEDULER profiles after 'config qos reload'
  - TORTUGA_CONFIG         : per-queue type/weight tuple
  - GOLDEN_WRED_PROFILE    : expected WRED_PROFILE|AZURE_LOSSY fields
  - WRED_BOUND_QUEUES      : queues 0-6 that bind to AZURE_LOSSY
  - GOLDEN_DSCP_TO_TC      : full 64-entry AZURE DSCP-to-TC map

Configuration Verification (individual, composable):
  - verify_dscp_to_tc_map()      : DSCP_TO_TC_MAP|AZURE (64 entries)
  - verify_port_qos_map()        : PORT_QOS_MAP dscp_to_tc_map bindings
  - verify_scheduler_profiles()  : SCHEDULER|scheduler.N (type + weight)
  - verify_queue_bindings()      : QUEUE|<intf>|N (scheduler + wred_profile)
  - verify_wred_profile()        : WRED_PROFILE|AZURE_LOSSY fields

  Each returns True/False and appends failures to fail_msgs.
  Call individually to map to specific test cases, or use the combined:
  - verify_config_db_baseline()  : runs all 5 checks under a FX3 QoS banner

Display:
  - print_banner()               : prominent banner (=== >>> title <<< ===)
  - print_section()              : section header (=== title ===)

Other Helpers:
  - ensure_interfaces_admin_up() : check admin status + startup if needed
  - verify_queue_counters()      : confirm 'show queue counters' returns rows
  - load_config_db_baseline()    : load config_db.json as dict (golden baseline)
  - unbind_wred_from_queues()    : HDEL wred_profile from WRED-bound queues (0-6)
  - validate_scheduler()         : DWRR ratio + STRICT zero-drop validation

DCHAL:
  - DCHAL_QI_SCRIPT / deploy_dchal_helper() / dchal_show_queuing()

Parsers:
  - parse_redis_hgetall() / parse_redis_hget()
  - get_queue_counters() / get_dut_mac()
  - parse_dchal_queue_counters() / get_dchal_queue_counters()
  - parse_dchal_egress_bw() / validate_dchal_bw_vs_weights()
  - validate_queue_counters_vs_weights()
  - validate_queue_counters()
  - parse_dchal_queue_stats()


Usage:
  from fx3_qos_helpers import (
      QUEUE_TO_DSCP, EXPECTED_SCHEDULERS, TORTUGA_CONFIG,
      GOLDEN_WRED_PROFILE, WRED_BOUND_QUEUES, GOLDEN_DSCP_TO_TC,
      print_banner, print_section,
      verify_dscp_to_tc_map, verify_port_qos_map,
      verify_scheduler_profiles, verify_queue_bindings,
      verify_wred_profile, verify_config_db_baseline,
      ensure_interfaces_admin_up, verify_queue_counters,
      validate_scheduler,
      deploy_dchal_helper, dchal_show_queuing,
      get_queue_counters, get_dut_mac, parse_dchal_queue_stats
  )
"""

import ast
import base64
import json
import math
import os
import re

from spytest import st

# Path to the baseline config_db.json (same directory as this helper module).
_CONFIG_DB_JSON = os.path.join(os.path.dirname(__file__), 'config_db.json')


# ── FX3 QoS testbed L3 addresses ─────────────────────────────────────────
# Shared by all test modules.  The ingress and egress subnet addresses are
# the same regardless of topology mode (ixia / peer_link / breakout).

# DUT-side IPs (with prefix)
V4_INGRESS_A_IP = '10.10.10.1/24'
V4_INGRESS_B_IP = '10.10.11.1/24'
V4_EGRESS_IP    = '20.20.20.1/24'
V6_INGRESS_A_IP = '2001:db8:10::1/64'
V6_INGRESS_B_IP = '2001:db8:11::1/64'
V6_EGRESS_IP    = '2001:db8:20::1/64'

# IXIA-side IPs (no prefix)
IXIA_INGRESS_A_IP  = '10.10.10.2'
IXIA_INGRESS_B_IP  = '10.10.11.2'
IXIA_EGRESS_IP     = '20.20.20.2'
IXIA_INGRESS_A_IP6 = '2001:db8:10::2'
IXIA_INGRESS_B_IP6 = '2001:db8:11::2'
IXIA_EGRESS_IP6    = '2001:db8:20::2'

NETMASK       = '255.255.255.0'
PREFIX_LEN_V6 = 64

# ── Peer-link / breakout transit subnet (dut1 <-> dut2) ──────────────────
# Used in multi-DUT topologies (peer_link / breakout).  The egress
# subnet (20.20.20.0/24) lives on dut2's IXIA port; dut1 reaches it via
# a static route through this transit subnet.
V4_TRANSIT_DUT1_IP   = '30.30.30.1/24'
V4_TRANSIT_DUT2_IP   = '30.30.30.2/24'
V6_TRANSIT_DUT1_IP   = '2001:db8:30::1/64'
V6_TRANSIT_DUT2_IP   = '2001:db8:30::2/64'
V4_TRANSIT_DUT2_BARE = '30.30.30.2'
V6_TRANSIT_DUT2_BARE = '2001:db8:30::2'

# ── Traffic / WRED defaults ─────────────────────────────────────────────
NUM_QUEUES       = 8
PKT_SIZE         = 128
WRED_MIN_TH      = 1048576     # 1 MB — below this, 0% drop probability
WRED_MAX_TH      = 3145728     # 3 MB — above this, 100% tail drop
WRED_MAX_PROB    = 5           # 5% max drop probability at max_th
WRED_TOLERANCE   = 2.0         # percentage-point tolerance for pass/fail
WRED_DURATION    = 40          # seconds per margin point
WRED_SETTLE_TIME = 5           # seconds before mid-traffic depth snapshot


# ── Golden data (default global config) ──────────────────────────────────

# DSCP value that maps to each queue under the default AZURE map (TC N = Q N).
# Source: scheduler_test_plan.md DSCP-to-Queue Mapping table;
#         test_scheduler_validation.py QUEUE_TO_DSCP.
QUEUE_TO_DSCP = {
    0: 0,  1: 6,  2: 2,  3: 3,  4: 4,  5: 46,  6: 48,  7: 49,
}

# Expected SCHEDULER profiles after 'config qos reload' on FX3 Tortuga.
# CONFIG_DB keys are SCHEDULER|scheduler.N (not generic SONiC sched_qN).
# Source: scheduler_test_plan.md Reference Configuration (test 17);
#         test_scheduler_validation.py TORTUGA_CONFIG.
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

# Tortuga per-queue scheduler type and weight (matches test_scheduler_validation.py).
TORTUGA_CONFIG = {
    0: ('DWRR', 20),
    1: ('DWRR', 20),
    2: ('DWRR', 20),
    3: ('DWRR', 40),
    4: ('DWRR', 40),
    5: ('DWRR', 30),
    6: ('STRICT', None),
    7: ('STRICT', None),
}

# Expected WRED_PROFILE|AZURE_LOSSY fields after 'config qos reload' on FX3.
# Source: qos_fx3.j2 generate_wred_profiles() (non-GR2 branch).
# CONFIG_DB stores all values as strings.
GOLDEN_WRED_PROFILE = {
    'ecn':                    'ecn_none',
    'wred_green_enable':      'true',
    'green_min_threshold':    '1048576',
    'green_max_threshold':    '3145728',
    'green_drop_probability': '5',
}

# Queues 0-6 bind to AZURE_LOSSY; queue 7 (strict priority) has no WRED.
WRED_BOUND_QUEUES = range(7)

# Full 64-entry AZURE DSCP-to-TC map (string keys/values to match CONFIG_DB).
# Source: dscp_to_tc_test_plan.md Default DSCP-to-TC Map table.
GOLDEN_DSCP_TO_TC = {
    '0':  '0', '1':  '1', '2':  '2', '3':  '3', '4':  '4', '5':  '2',
    '6':  '1', '7':  '1', '8':  '0', '9':  '0', '10': '0', '11': '0',
    '12': '0', '13': '0', '14': '0', '15': '0', '16': '0', '17': '0',
    '18': '0', '19': '0', '20': '0', '21': '0', '22': '0', '23': '0',
    '24': '0', '25': '0', '26': '0', '27': '0', '28': '0', '29': '0',
    '30': '0', '31': '0', '32': '0', '33': '0', '34': '0', '35': '0',
    '36': '0', '37': '0', '38': '0', '39': '0', '40': '0', '41': '0',
    '42': '0', '43': '0', '44': '0', '45': '0', '46': '5', '47': '1',
    '48': '6', '49': '7', '50': '1', '51': '1', '52': '1', '53': '1',
    '54': '1', '55': '1', '56': '1', '57': '1', '58': '1', '59': '1',
    '60': '1', '61': '1', '62': '1', '63': '1',
}


# ── Interface admin-state helper ──────────────────────────────────────────

def ensure_interfaces_admin_up(dut, interfaces):
    """Check admin status and run 'config interface startup' for any that are down.

    Parses 'show interfaces status <intf>' for each interface.  If the Admin
    column reads 'down', issues 'config interface startup' and waits briefly.
    """
    for intf in interfaces:
        output = st.show(dut, "show interfaces status {}".format(intf),
                         skip_tmpl=True)
        admin_down = False
        for line in output.splitlines():
            if intf in line and 'down' in line.lower():
                cols = line.split()
                for i, col in enumerate(cols):
                    if col.lower() == 'down':
                        admin_down = True
                        break
                break
        if admin_down:
            st.log("ensure_interfaces_admin_up: {} admin is down — "
                   "running 'config interface startup'".format(intf))
            st.config(dut, "config interface startup {}".format(intf),
                      skip_error_check=True)
        else:
            st.log("ensure_interfaces_admin_up: {} admin is already up".format(
                intf))
    st.wait(2)


def verify_queue_counters(dut, interfaces):
    """Run 'show queue counters' on each interface and confirm rows are present.

    Logs the full counter table for each interface.  Returns a list of
    interface names for which no counter rows (ALLn) were found — an empty
    list means all interfaces have valid queue counter output.
    """
    missing = []
    for intf in interfaces:
        output = st.show(dut, "show queue counters {}".format(intf),
                         skip_tmpl=True)
        st.log("verify_queue_counters: {}\n{}".format(intf, output))
        has_rows = False
        for line in output.splitlines():
            if intf in line and 'ALL' in line:
                has_rows = True
                break
        if not has_rows:
            st.log("verify_queue_counters: WARNING — no queue counter rows "
                   "found for {}".format(intf))
            missing.append(intf)
        else:
            st.log("verify_queue_counters: {} OK — queue counter rows present".format(
                intf))
    return missing


# ── Interface-membership helpers ──────────────────────────────────────────

def remove_interface_from_vlan(dut_handle, interface):
    """Remove *interface* from every VLAN it belongs to on *dut_handle*."""
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
    """Remove *interface* from the first PortChannel it belongs to."""
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
    """Remove *interface* from any VLAN and PortChannel memberships."""
    remove_interface_from_vlan(dut_handle, interface)
    remove_interface_from_portchannel(dut_handle, interface)


def _wait_for_interfaces(dut_handle, interfaces, timeout=30, poll=5):
    """Poll until all *interfaces* are present in /sys/class/net/ on the DUT."""
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


# ── Baseline config_db.json loader ────────────────────────────────────────

def load_config_db_baseline():
    """Load and return the baseline config_db.json as a dict.

    The file lives alongside this helper module at
    tests/cisco/fx3/qos/config_db.json.
    """
    with open(_CONFIG_DB_JSON, 'r') as fh:
        return json.load(fh)


_ART_FX3_QOS = r"""
  _____ __  __ _____    ___        ____
 |  ___|\  \/ /|___ /   / _ \  ___ / ___|
 | |_    \  /   |_ \  | | | |/ _ \\___ \
 |  _|   /  \  ___) | | |_| | (_) |___) |
 |_|    /_/\_\|____/   \__\_\\___/|____/
"""

_ART_DSCP_TC = r"""
 ____   ____   ____ ____           _______  ____
|  _ \/ ___| / ___|  _ \          |_   _| / ___|
| | | \___ \| |   | |_) |  ______   | |  | |
| |_| |___) | |___|  __/  |_____|   | |  | |___
|____/|____/ \____|_|               |_|   \____|
"""

_ART_SCHEDULER = r"""
 ____       _              _       _
/ ___|  ___| |__   ___  __| |_   _| | ___ _ __
\___ \ / __| '_ \ / _ \/ _` | | | | |/ _ \ '__|
 ___) | (__| | | |  __/ (_| | |_| | |  __/ |
|____/ \___|_| |_|\___|\__,_|\__,_|_|\___|_|
"""

_ART_QUEUE = r"""
  ___
 / _ \ _   _  ___ _   _  ___
| | | | | | |/ _ \ | | |/ _ \
| |_| | |_| |  __/ |_| |  __/
 \__\_\\__,_|\___|\__,_|\___|
"""

_ART_WRED = r"""
__        ______  _____ ____
\ \      / /  _ \| ____|  _ \
 \ \ /\ / /| |_) |  _| | | | |
  \ V  V / |  _ <| |___| |_| |
   \_/\_/  |_| \_\_____|____/
"""

_SECTION_ART = {
    'dscp_to_tc': _ART_DSCP_TC,
    'scheduler':  _ART_SCHEDULER,
    'queue':      _ART_QUEUE,
    'wred':       _ART_WRED,
}


def print_banner(title, width=74, char='='):
    """Print the FX3 QoS ASCII art banner followed by a title line."""
    border = char * width
    st.log(border)
    for line in _ART_FX3_QOS.strip().splitlines():
        st.log(line)
    st.log("")
    st.log("  " + title)
    st.log(border)


def print_section(title, width=70, char='=', art_key=None):
    """Print a section header with optional ASCII art.

    art_key: one of 'dscp_to_tc', 'scheduler', 'queue', 'wred'
             to display the matching ASCII art above the title.
    """
    st.log(char * width)
    if art_key and art_key in _SECTION_ART:
        for line in _SECTION_ART[art_key].strip().splitlines():
            st.log("  " + line)
        st.log("")
    st.log("  " + title)
    st.log(char * width)


# ── Individual configuration verification functions ───────────────────
#
# Each verify_* function:
#   1. Fetches data from the DUT (all queries first)
#   2. Prints a clean table
#   3. Appends failure descriptions to fail_msgs
#   4. Returns True if section passed, False otherwise
#
# Test cases can call these individually or use verify_config_db_baseline()
# which calls them all under a main "FX3 QoS" banner.
# ──────────────────────────────────────────────────────────────────────

def verify_dscp_to_tc_map(dut, fail_msgs, baseline=None):
    """Verify DSCP_TO_TC_MAP|AZURE against baseline config_db.json.

    Returns True if all 64 entries match.
    """
    if baseline is None:
        baseline = load_config_db_baseline()

    st.log("  Fetching DSCP_TO_TC_MAP|AZURE ...")
    expected_map = baseline.get('DSCP_TO_TC_MAP', {}).get('AZURE', {})
    output = st.show(
        dut,
        'sonic-db-cli CONFIG_DB HGETALL "DSCP_TO_TC_MAP|AZURE"',
        skip_tmpl=True)
    actual_map = parse_redis_hgetall(output)

    print_section("DSCP_TO_TC_MAP|AZURE  ({} entries, expected {})".format(
        len(actual_map), len(expected_map)), art_key='dscp_to_tc')
    st.log("  {:<6} {:>10} {:>10} {:>8}".format(
        'DSCP', 'Expected', 'Actual', 'Status'))
    st.log("  " + "-" * 40)
    mismatches = 0
    for dscp in sorted(expected_map, key=lambda x: int(x)):
        exp_tc = expected_map[dscp]
        act_tc = actual_map.get(dscp, '(nil)')
        ok = act_tc == exp_tc
        tag = 'OK' if ok else '** FAIL'
        st.log("  {:<6} {:>10} {:>10} {:>8}".format(
            dscp, exp_tc, act_tc, tag))
        if not ok:
            mismatches += 1
            fail_msgs.append(
                "DSCP {} -> TC {}, expected {}".format(dscp, act_tc, exp_tc))
    if len(actual_map) != len(expected_map):
        mismatches += 1
        fail_msgs.append(
            "DSCP_TO_TC_MAP has {} entries, expected {}".format(
                len(actual_map), len(expected_map)))
    st.log("  DSCP_TO_TC_MAP: {} mismatches out of {} entries".format(
        mismatches, len(expected_map)))
    return mismatches == 0


def verify_port_qos_map(dut, port_info, fail_msgs):
    """Verify PORT_QOS_MAP dscp_to_tc_map binding on ingress interfaces.

    port_info: dict whose keys contain 'ingress' (e.g. 'ingress',
    'ingress_a', 'ingress_b').  All non-egress ports are checked.
    Returns True if all bindings are AZURE.
    """
    st.log("  Fetching PORT_QOS_MAP bindings ...")
    ingress_labels = [k for k in port_info if 'ingress' in k]
    if not ingress_labels:
        ingress_labels = [k for k in port_info if k != 'egress']
    results = []
    for label in ingress_labels:
        intf = port_info[label]
        output = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGET "PORT_QOS_MAP|{}" '
            '"dscp_to_tc_map"'.format(intf),
            skip_tmpl=True)
        results.append((intf, parse_redis_hget(output)))

    print_section("PORT_QOS_MAP (dscp_to_tc_map binding)")
    st.log("  {:<20} {:>14} {:>8}".format('Interface', 'Actual', 'Status'))
    st.log("  " + "-" * 46)
    passed = True
    for intf, bound_map in results:
        ok = bound_map and 'AZURE' in bound_map.upper()
        tag = 'OK' if ok else '** FAIL'
        st.log("  {:<20} {:>14} {:>8}".format(intf, bound_map or '(nil)', tag))
        if not ok:
            passed = False
            fail_msgs.append(
                "{} dscp_to_tc_map = '{}', expected AZURE".format(
                    intf, bound_map))
    return passed


def verify_scheduler_profiles(dut, fail_msgs, baseline=None,
                              egress_intf=None):
    """Verify SCHEDULER|scheduler.N profiles against baseline config_db.json.

    When *egress_intf* is provided, also reads DCHAL egress queuing output
    and validates hardware bandwidth percentages against TORTUGA_CONFIG.

    Returns True if all profiles match (type and weight).
    """
    if baseline is None:
        baseline = load_config_db_baseline()

    expected_scheds = baseline.get('SCHEDULER', {})
    st.log("  Fetching SCHEDULER profiles ({}) ...".format(
        len(expected_scheds)))
    sched_actuals = {}
    for name in sorted(expected_scheds):
        output = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
            skip_tmpl=True)
        sched_actuals[name] = parse_redis_hgetall(output)

    print_section("SCHEDULER profiles ({} profiles)".format(
        len(expected_scheds)), art_key='scheduler')
    st.log("  {:<16} {:>8} {:>8} {:>8} {:>8} {:>8}".format(
        'Profile', 'ExpType', 'ActType', 'ExpWt', 'ActWt', 'Status'))
    st.log("  " + "-" * 62)
    passed = True
    for name in sorted(expected_scheds):
        expected = expected_scheds[name]
        actual = sched_actuals[name]
        if not actual:
            st.log("  {:<16} {:>8} {:>8} {:>8} {:>8} {:>8}".format(
                name, expected.get('type', '-'), '(nil)',
                expected.get('weight', '-'), '-', '** FAIL'))
            fail_msgs.append("SCHEDULER|{}: empty or missing".format(name))
            passed = False
            continue

        exp_type = expected.get('type', '-')
        act_type = actual.get('type', '-')
        exp_wt = expected.get('weight', '-')
        act_wt = actual.get('weight', '-')
        ok = True
        for field, exp_val in expected.items():
            if actual.get(field, '') != exp_val:
                ok = False
                fail_msgs.append(
                    "SCHEDULER|{} {}: '{}', expected '{}'".format(
                        name, field, actual.get(field, ''), exp_val))
        tag = 'OK' if ok else '** FAIL'
        st.log("  {:<16} {:>8} {:>8} {:>8} {:>8} {:>8}".format(
            name, exp_type, act_type, exp_wt, act_wt, tag))
        if not ok:
            passed = False

    if egress_intf:
        st.log("")
        st.log("  DCHAL HW scheduler verification for {} ...".format(
            egress_intf))
        deploy_dchal_helper(dut)
        dchal_out = dchal_show_queuing(
            dut, "scheduler HW verify", egress_intf)
        report_dchal_bw_check(dchal_out, fail_msgs)

    return passed


def verify_queue_bindings(dut, egress_intf, fail_msgs, baseline=None):
    """Verify QUEUE|<egress>|N scheduler and wred_profile bindings.

    Returns True if all 8 queue bindings match baseline.
    """
    if baseline is None:
        baseline = load_config_db_baseline()

    expected_queues = baseline.get('QUEUE', {})
    st.log("  Fetching QUEUE bindings on {} ...".format(egress_intf))
    queue_actuals = {}
    for qi in range(8):
        key = "{}|{}".format(egress_intf, qi)
        sched_out = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}" "scheduler"'.format(key),
            skip_tmpl=True)
        wred_out = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGET "QUEUE|{}" "wred_profile"'.format(
                key),
            skip_tmpl=True)
        queue_actuals[qi] = {
            'scheduler': parse_redis_hget(sched_out).strip() or '-',
            'wred_profile': parse_redis_hget(wred_out).strip() or '-',
        }

    print_section("QUEUE bindings on {} (scheduler + wred_profile)".format(
        egress_intf), art_key='queue')
    st.log("  {:<6} {:>14} {:>14} {:>14} {:>14} {:>8}".format(
        'Queue', 'ExpSched', 'ActSched', 'ExpWRED', 'ActWRED', 'Status'))
    st.log("  " + "-" * 76)
    passed = True
    for qi in range(8):
        key = "{}|{}".format(egress_intf, qi)
        expected_q = expected_queues.get(key, {})
        if not expected_q:
            st.log("  Q{:<4} (not in baseline JSON — skipped)".format(qi))
            continue

        exp_sched = expected_q.get('scheduler', '-')
        exp_wred = expected_q.get('wred_profile', '-')
        act_sched = queue_actuals[qi]['scheduler']
        act_wred = queue_actuals[qi]['wred_profile']
        ok = True

        if 'scheduler' in expected_q and act_sched != exp_sched:
            ok = False
            fail_msgs.append(
                "QUEUE|{} scheduler: '{}', expected '{}'".format(
                    key, act_sched, exp_sched))

        if 'wred_profile' in expected_q:
            if act_wred != exp_wred:
                ok = False
                fail_msgs.append(
                    "QUEUE|{} wred_profile: '{}', expected '{}'".format(
                        key, act_wred, exp_wred))
        else:
            if act_wred and act_wred not in ('-', 'None', ''):
                ok = False
                fail_msgs.append(
                    "QUEUE|{} wred_profile: '{}', expected empty/unset"
                    .format(key, act_wred))

        tag = 'OK' if ok else '** FAIL'
        st.log("  Q{:<4} {:>14} {:>14} {:>14} {:>14} {:>8}".format(
            qi, exp_sched, act_sched, exp_wred, act_wred, tag))
        if not ok:
            passed = False
    return passed


def verify_wred_profile(dut, fail_msgs, baseline=None, wred_profile=None):
    """Verify WRED_PROFILE|AZURE_LOSSY fields against expected values.

    When *wred_profile* is provided, it is used as the expected values directly.
    Otherwise the expected values come from the *baseline* config_db.json.

    Returns True if all fields match.
    """
    if wred_profile is not None:
        expected_wred = wred_profile
    else:
        if baseline is None:
            baseline = load_config_db_baseline()
        expected_wred = baseline.get('WRED_PROFILE', {}).get('AZURE_LOSSY', {})
    st.log("  Fetching WRED_PROFILE|AZURE_LOSSY ...")
    output = st.show(
        dut,
        'sonic-db-cli CONFIG_DB HGETALL "WRED_PROFILE|AZURE_LOSSY"',
        skip_tmpl=True)
    actual_wred = parse_redis_hgetall(output)

    print_section("WRED_PROFILE|AZURE_LOSSY", art_key='wred')
    st.log("  {:<28} {:>14} {:>14} {:>8}".format(
        'Field', 'Expected', 'Actual', 'Status'))
    st.log("  " + "-" * 68)
    passed = True
    if not actual_wred:
        st.log("  (empty or missing)")
        fail_msgs.append("WRED_PROFILE|AZURE_LOSSY: empty or missing")
        return False
    for field in sorted(expected_wred):
        exp_val = expected_wred[field]
        act_val = actual_wred.get(field, '(nil)')
        ok = act_val.lower() == exp_val.lower()
        tag = 'OK' if ok else '** FAIL'
        st.log("  {:<28} {:>14} {:>14} {:>8}".format(
            field, exp_val, act_val, tag))
        if not ok:
            passed = False
            fail_msgs.append(
                "WRED_PROFILE {}: '{}', expected '{}'".format(
                    field, act_val, exp_val))
    return passed


def verify_config_db_baseline(dut, egress_intf, port_info, fail_msgs):
    """Verify live CONFIG_DB matches the baseline config_db.json.

    Prints formatted tables showing expected vs actual for each section
    under a main FX3 QoS banner.

    Checks:
      1. DSCP_TO_TC_MAP|AZURE  (all 64 entries)
      2. PORT_QOS_MAP|<intf>   (dscp_to_tc_map binding on ingress ports)
      3. SCHEDULER|scheduler.N (type and weight for all 8 profiles)
      4. QUEUE|<egress>|N      (scheduler and wred_profile bindings)
      5. WRED_PROFILE|AZURE_LOSSY (all fields)

    Each section can also be called independently via verify_dscp_to_tc_map(),
    verify_port_qos_map(), verify_scheduler_profiles(), verify_queue_bindings(),
    verify_wred_profile().
    """
    baseline = load_config_db_baseline()

    print_banner("FX3 QoS — Configuration Verification")
    st.log("")

    verify_dscp_to_tc_map(dut, fail_msgs, baseline)
    st.log("")
    verify_port_qos_map(dut, port_info, fail_msgs)
    st.log("")
    verify_scheduler_profiles(dut, fail_msgs, baseline,
                              egress_intf=egress_intf)
    st.log("")
    verify_queue_bindings(dut, egress_intf, fail_msgs, baseline)
    st.log("")
    verify_wred_profile(dut, fail_msgs, baseline)
    st.log("")

    if fail_msgs:
        print_banner("FX3 QoS — Configuration FAILED ({} issues)".format(
            len(fail_msgs)), char='!')
    else:
        print_banner("FX3 QoS — Configuration PASSED (all sections OK)")


# ── DCHAL wrapper script ─────────────────────────────────────────────────
#
# Deployed once into /tmp/dchal_qi.py inside the syncd container via
# deploy_dchal_helper().  Uses show_queuing_intf.py already present in
# /usr/share/sonic/dchalshell/ which calls 'insshell regdump dump' directly.
#
# On some image versions (e.g. 2021 DUT) interface_pb2 (gRPC protobuf module)
# is absent, so resolve_port()'s primary gRPC path raises ModuleNotFoundError
# (an ImportError subclass) instead of RuntimeError, bypassing the built-in
# platform.json fallback.  We catch ImportError here and invoke the fallback
# (_resolve_sport_from_json + PortInfo) directly.
#
# _resolve_sport_from_json may itself raise RuntimeError when the interface
# is not present in platform.json (e.g. on some DUTs).  In that
# case we print a clear error and exit 0 so the test can continue — DCHAL
# output is for visibility, not a hard gate.
DCHAL_QI_SCRIPT = """\
import json, os, re, sys
sys.path.insert(0, '/usr/share/sonic/dchalshell')
sys.path.insert(0, '/usr/share/sonic/dchalshell/commands')
import show_queuing_intf
from show_queuing_intf import (
    collect_queuing_data, format_output,
    PortInfo, _resolve_sport_from_json,
)

def _name_variants(name):
    variants = [name]
    # Ethernet1_51 -> Ethernet1/51
    if '_' in name:
        variants.append(name.replace('_', '/', 1))
    # Ethernet1/51 -> Ethernet1_51
    if '/' in name:
        variants.append(name.replace('/', '_', 1))
    # Ethernet1_51 -> Ethernet51  (drop slot prefix)
    m = re.match(r'(Ethernet)\\d+[_/](\\d+)$', name)
    if m:
        variants.append(m.group(1) + m.group(2))
    # Ethernet1_51 -> Ethernet200  (lookup by lanes in platform.json)
    pj_path = '/usr/share/sonic/device/x86_64-cisco_8102_c8d48-r0/platform.json'
    alt_paths = [
        '/usr/share/sonic/platform/platform.json',
        '/usr/share/sonic/hwsku/platform.json',
    ]
    pj = None
    for p in [pj_path] + alt_paths:
        if os.path.isfile(p):
            try:
                with open(p) as f:
                    pj = json.load(f)
                break
            except Exception:
                pass
    if pj and 'interfaces' in pj:
        for pj_name, pj_info in pj['interfaces'].items():
            alias = pj_info.get('alias', '')
            if alias in variants or pj_name in variants:
                if pj_name not in variants:
                    variants.append(pj_name)
                if alias and alias not in variants:
                    variants.append(alias)
    return variants

if len(sys.argv) < 2:
    print('DCHAL_SKIP: no interface argument provided')
    sys.exit(0)

intf = sys.argv[1]
names_to_try = _name_variants(intf)
pi = None
last_err = None

for try_name in names_to_try:
    try:
        pi = show_queuing_intf.resolve_port(try_name)
        break
    except ImportError:
        try:
            sport, num_lanes = _resolve_sport_from_json(try_name)
            pi = PortInfo(intf_name=try_name, slot=1, unit=0, slice_id=0,
                          asic_port=sport, fp_port=sport, num_lanes=num_lanes)
            break
        except Exception as e:
            last_err = e
    except Exception as e:
        last_err = e

if pi is None:
    print('DCHAL_SKIP: cannot resolve {} (tried {}) — {}'.format(
        intf, names_to_try, last_err))
    sys.exit(0)

qd = collect_queuing_data(pi)
print(format_output(qd))
"""


DCHAL_AQM_SCRIPT = """\
import json, os, re, sys
sys.path.insert(0, '/usr/share/sonic/dchalshell')
sys.path.insert(0, '/usr/share/sonic/dchalshell/commands')
try:
    import show_queuing_intf
    from show_queuing_intf import (
        PortInfo, _resolve_sport_from_json, insshell_read, _entry_map,
    )
except ImportError as _ie:
    print('DCHAL_AQM_SKIP: import failed — {}'.format(_ie))
    sys.exit(0)

_NUM_QUEUES = 8
_AQM_MAX_PROB_DIVISOR = 0x7ff

_TBL_AQM_OQ_PROFILE_MAP = "tah_sun_bax_dhs_aqm_oqueue_profile_map"
_TBL_AQM_PROFILE         = "tah_sun_bax_dhs_aqm_profile"
_TBL_AQM_UC_OQUEUE       = "tah_sun_bax_dhs_aqm_uc_oqueue"
_TBL_ACCT_UC_OQ_COUNT    = "tah_sun_bax_dhs_acct_uc_oqueue_count"

def _name_variants(name):
    variants = [name]
    if '_' in name:
        variants.append(name.replace('_', '/', 1))
    if '/' in name:
        variants.append(name.replace('/', '_', 1))
    m = re.match(r'(Ethernet)\\d+[_/](\\d+)$', name)
    if m:
        variants.append(m.group(1) + m.group(2))
    pj_path = '/usr/share/sonic/device/x86_64-cisco_8102_c8d48-r0/platform.json'
    alt_paths = [
        '/usr/share/sonic/platform/platform.json',
        '/usr/share/sonic/hwsku/platform.json',
    ]
    pj = None
    for p in [pj_path] + alt_paths:
        if os.path.isfile(p):
            try:
                with open(p) as f:
                    pj = json.load(f)
                break
            except Exception:
                pass
    if pj and 'interfaces' in pj:
        for pj_name, pj_info in pj['interfaces'].items():
            alias = pj_info.get('alias', '')
            if alias in variants or pj_name in variants:
                if pj_name not in variants:
                    variants.append(pj_name)
                if alias and alias not in variants:
                    variants.append(alias)
    return variants

def collect_aqm(asic_port):
    oq_base = asic_port * _NUM_QUEUES
    r = {'asic_port': asic_port}
    fields = ['aqm','mode','min_thr','max_thr','max_prob','max_prob_cfg',
              'ecn_enable','drop_en','q_depth','mfair','qold']
    for f in fields:
        r[f] = [0] * _NUM_QUEUES
    r['oqueue_idx'] = [oq_base + q for q in range(_NUM_QUEUES)]
    prof_entries = insshell_read(_TBL_AQM_OQ_PROFILE_MAP, oq_base, _NUM_QUEUES)
    prof_map = _entry_map(prof_entries)
    for q in range(_NUM_QUEUES):
        e = prof_map.get(oq_base + q, {})
        r['aqm'][q] = e.get('aqm', 0)
    unique_profiles = set(r['aqm'])
    profile_data = {}
    for pid in unique_profiles:
        entries = insshell_read(_TBL_AQM_PROFILE, pid, 1)
        if entries:
            profile_data[pid] = entries[0]
    for q in range(_NUM_QUEUES):
        prof = profile_data.get(r['aqm'][q], {})
        r['mode'][q]       = prof.get('mode', 0)
        r['min_thr'][q]    = prof.get('min_thr', 0)
        r['max_thr'][q]    = prof.get('max_thr_qdes', prof.get('max_thr', 0))
        mp = prof.get('max_prob', 0)
        r['max_prob'][q]   = mp
        r['max_prob_cfg'][q] = round(mp * 100.0 / _AQM_MAX_PROB_DIVISOR) if _AQM_MAX_PROB_DIVISOR else 0
        r['ecn_enable'][q] = prof.get('ecn_enable', 0)
        r['drop_en'][q]    = prof.get('drop_en', 0)
    uc_entries = insshell_read(_TBL_AQM_UC_OQUEUE, oq_base, _NUM_QUEUES)
    uc_map = _entry_map(uc_entries)
    for q in range(_NUM_QUEUES):
        e = uc_map.get(oq_base + q, {})
        r['mfair'][q] = e.get('mfair', 0)
        r['qold'][q]  = e.get('qold', 0)
    depth_entries = insshell_read(_TBL_ACCT_UC_OQ_COUNT, oq_base, _NUM_QUEUES)
    depth_map = _entry_map(depth_entries)
    for q in range(_NUM_QUEUES):
        e = depth_map.get(oq_base + q, {})
        r['q_depth'][q] = e.get('num_cell', 0)
    return r

if len(sys.argv) < 2:
    print('DCHAL_AQM_SKIP: no interface argument')
    sys.exit(0)

intf = sys.argv[1]
names_to_try = _name_variants(intf)
pi = None
last_err = None
for try_name in names_to_try:
    try:
        pi = show_queuing_intf.resolve_port(try_name)
        break
    except ImportError:
        try:
            sport, num_lanes = _resolve_sport_from_json(try_name)
            pi = PortInfo(intf_name=try_name, slot=1, unit=0, slice_id=0,
                          asic_port=sport, fp_port=sport, num_lanes=num_lanes)
            break
        except Exception as e:
            last_err = e
    except Exception as e:
        last_err = e

if pi is None:
    print('DCHAL_AQM_SKIP: cannot resolve {} — {}'.format(intf, last_err))
    sys.exit(0)

try:
    data = collect_aqm(pi.asic_port)
except Exception as e:
    print('DCHAL_AQM_ERROR: {}'.format(e))
    sys.exit(0)

print('AQM_JSON:' + json.dumps(data))
"""


DCHAL_WRED_VARIANCE_SCRIPT = """\
import sys, os, json
sys.path.insert(0, '/usr/share/sonic/dchalshell')
sys.path.insert(0, '/usr/share/sonic/dchalshell/commands')
try:
    import grpc
    import qos_pb2
    import qos_pb2_grpc
    channel = grpc.insecure_channel('127.0.0.1:50057')
    stub = qos_pb2_grpc.qosStub(channel)
    inp = qos_pb2.variance_input()
    inp.feature = qos_pb2.DCHAL_QOS_WRED
    inp.detail = qos_pb2.NO
    res = stub.Get_hal_variance_info(inp)
    if res.variance_result:
        mismatches = []
        for entry in res.variance_result:
            mismatches.append({
                'intf': entry.ifstr,
                'table': entry.regstr,
                'field': entry.fieldstr,
                'expected': hex(entry.expected),
                'actual': hex(entry.actual),
            })
        print('WRED_VARIANCE:' + json.dumps(mismatches))
    else:
        print('WRED_VARIANCE:[]')
except Exception as e:
    print('WRED_VARIANCE_ERROR: {}'.format(e))
"""


def deploy_dchal_helper(dut):
    """Deploy DCHAL scripts into /tmp/ inside the syncd container.

    Deploys dchal_qi.py (queuing), dchal_aqm.py (AQM hw-info),
    and dchal_wred_var.py (WRED variance).
    Safe to call multiple times — idempotent.
    """
    for name, script in [('dchal_qi.py', DCHAL_QI_SCRIPT),
                         ('dchal_aqm.py', DCHAL_AQM_SCRIPT),
                         ('dchal_wred_var.py', DCHAL_WRED_VARIANCE_SCRIPT),
                         ('dchal_peak.py', DCHAL_PEAK_SCRIPT)]:
        encoded = base64.b64encode(script.encode()).decode()
        st.config(dut,
                  "sudo docker exec syncd sh -c "
                  "'echo {} | base64 -d > /tmp/{}'".format(encoded, name),
                  skip_error_check=True)


def dchal_dump_platform_intfs(dut):
    """Diagnostic: list interface names from platform.json inside syncd.

    Useful for figuring out the correct naming convention when DCHAL
    reports 'cannot resolve' for an interface.
    """
    cmd = (
        "sudo docker exec syncd python3 -c \""
        "import json, glob, os; "
        "paths = glob.glob('/usr/share/sonic/*/platform.json') "
        "+ ['/usr/share/sonic/platform/platform.json']; "
        "[print('FILE:', p) or "
        "[print('  ', k, '->', v.get('alias','')) "
        "for k,v in sorted(json.load(open(p)).get('interfaces',{}).items())] "
        "for p in paths if os.path.isfile(p)]"
        "\""
    )
    out = st.show(dut, cmd, skip_tmpl=True, skip_error_check=True)
    st.log("=== platform.json interface names ===\n{}".format(out))
    return out


def dchal_show_queuing(dut, label, interface):
    """Run the deployed DCHAL show-queuing script and return raw output.

    Logs a banner and the full ASIC output at each call.  The returned string
    can be passed directly to parse_dchal_egress_bw() or
    validate_dchal_bw_vs_weights().
    """
    st.log("=== DCHAL queuing [{}] for {} ===".format(label, interface))
    out = st.show(
        dut,
        "sudo docker exec syncd python3 /tmp/dchal_qi.py {}".format(interface),
        skip_tmpl=True, skip_error_check=True) or ''
    st.log(out)
    return out


DCHAL_PEAK_SCRIPT = """\
import json, os, re, sys
sys.path.insert(0, '/usr/share/sonic/dchalshell')
sys.path.insert(0, '/usr/share/sonic/dchalshell/commands')
try:
    import show_queuing_intf
    from show_queuing_intf import PortInfo, _resolve_sport_from_json
    import show_peak_stats
except ImportError as _ie:
    print('DCHAL_PEAK_SKIP: import failed — {}'.format(_ie))
    sys.exit(0)

def _name_variants(name):
    variants = [name]
    if '_' in name:
        variants.append(name.replace('_', '/', 1))
    if '/' in name:
        variants.append(name.replace('/', '_', 1))
    m = re.match(r'(Ethernet)\\d+[_/](\\d+)$', name)
    if m:
        variants.append(m.group(1) + m.group(2))
    pj_path = '/usr/share/sonic/device/x86_64-cisco_8102_c8d48-r0/platform.json'
    alt_paths = [
        '/usr/share/sonic/platform/platform.json',
        '/usr/share/sonic/hwsku/platform.json',
    ]
    pj = None
    for p in [pj_path] + alt_paths:
        if os.path.isfile(p):
            try:
                with open(p) as f:
                    pj = json.load(f)
                break
            except Exception:
                pass
    if pj and 'interfaces' in pj:
        for pj_name, pj_info in pj['interfaces'].items():
            alias = pj_info.get('alias', '')
            if alias in variants or pj_name in variants:
                if pj_name not in variants:
                    variants.append(pj_name)
                if alias and alias not in variants:
                    variants.append(alias)
    return variants

if len(sys.argv) < 2:
    print('DCHAL_PEAK_SKIP: no interface argument')
    sys.exit(0)

intf = sys.argv[1]
names_to_try = _name_variants(intf)
pi = None
last_err = None
for try_name in names_to_try:
    try:
        pi = show_queuing_intf.resolve_port(try_name)
        break
    except ImportError:
        try:
            sport, num_lanes = _resolve_sport_from_json(try_name)
            pi = PortInfo(intf_name=try_name, slot=1, unit=0, slice_id=0,
                          asic_port=sport, fp_port=sport, num_lanes=num_lanes)
            break
        except Exception as e:
            last_err = e
    except Exception as e:
        last_err = e

if pi is None:
    print('DCHAL_PEAK_SKIP: cannot resolve {} — {}'.format(intf, last_err))
    sys.exit(0)

try:
    pd = show_peak_stats.collect_peak_data(asic_port=pi.asic_port)
    print(show_peak_stats.format_peak_output(pd, asic_port=pi.asic_port))
    uc = pd.uc_queue_peak[pi.asic_port]
    mc = pd.mc_queue_peak[pi.asic_port]
    peak_json = {
        'asic_port': pi.asic_port,
        'uc_peak': uc,
        'mc_peak': mc,
        'mem_cells': pd.mem_peak_cell,
        'mem_bytes': pd.mem_peak_cell * 416,
    }
    print('PEAK_JSON:' + json.dumps(peak_json))
except Exception as e:
    print('DCHAL_PEAK_ERROR: {}'.format(e))
"""


def dchal_peak_stats(dut, interface, label="peak stats"):
    """Run DCHAL peak stats script and return parsed per-queue peak data.

    Uses the same pattern as dchal_qi.py — deploys a standalone script
    that imports show_peak_stats directly and calls collect_peak_data().

    Returns dict:
      {'uc_peak': [Q0..Q7 in cells], 'mc_peak': [Q0..Q7 in cells],
       'mem_cells': int, 'mem_bytes': int}
    or None on failure.
    """
    st.log("=== DCHAL peak stats [{}] for {} ===".format(label, interface))
    out = st.show(
        dut,
        "sudo docker exec syncd python3 /tmp/dchal_peak.py {}".format(
            interface),
        skip_tmpl=True, skip_error_check=True)
    st.log(out)
    for line in (out or '').splitlines():
        if line.startswith('PEAK_JSON:'):
            try:
                return json.loads(line[len('PEAK_JSON:'):])
            except (json.JSONDecodeError, ValueError):
                st.log("  Peak JSON parse error")
                return None
        if 'DCHAL_PEAK_SKIP' in line or 'DCHAL_PEAK_ERROR' in line:
            st.log("  Peak stats failed: {}".format(line))
            return None
    return _parse_peak_stats(out)


def _parse_peak_stats(output):
    """Parse DCHAL peak stats output into per-queue peak dict.

    Looks for the 'Queue Peak counters' section and extracts the UC-> row.
    The UC-> row has 8 values in Q7..Q0 order (right to left).
    Also extracts Mem Cells and bytes from Memory Peak section.
    """
    if not output:
        return None
    result = {
        'uc_peak': [0] * 8,
        'mc_peak': [0] * 8,
        'mem_cells': 0,
        'mem_bytes': 0,
    }
    in_queue_section = False
    for line in output.splitlines():
        stripped = line.strip()
        if 'Queue Peak counters' in stripped:
            in_queue_section = True
            continue
        if in_queue_section and stripped.startswith('UC->'):
            vals = [v.strip() for v in stripped.replace('UC->', '').split()
                    if v.strip() and v.strip() != '|']
            nums = []
            for v in vals:
                try:
                    nums.append(int(v))
                except ValueError:
                    pass
            if len(nums) >= 8:
                for q in range(8):
                    result['uc_peak'][q] = nums[7 - q]
        if in_queue_section and stripped.startswith('MC->'):
            vals = [v.strip() for v in stripped.replace('MC->', '').split()
                    if v.strip() and v.strip() != '|']
            nums = []
            for v in vals:
                try:
                    nums.append(int(v))
                except ValueError:
                    pass
            if len(nums) >= 8:
                for q in range(8):
                    result['mc_peak'][q] = nums[7 - q]
        if 'Mem Cells' in stripped:
            parts = stripped.split(':')
            if len(parts) >= 2:
                cell_part = parts[1].strip().split()
                if cell_part:
                    try:
                        result['mem_cells'] = int(cell_part[0])
                    except ValueError:
                        pass
                for p in cell_part:
                    if p.endswith('bytes)'):
                        try:
                            result['mem_bytes'] = int(
                                p.replace('bytes)', '').replace('(', ''))
                        except ValueError:
                            pass
    return result


_CELL_SIZE = 416


def report_peak_stats(peak_data, target_queue=None):
    """Print formatted peak watermark summary."""
    if not peak_data:
        st.log("  Peak stats not available")
        return
    sep = "=" * 70
    st.log(sep)
    st.log("  QUEUE PEAK WATERMARKS (max depth during test)")
    st.log(sep)
    st.log("  {:>5} {:>12} {:>14} {:>14}".format(
        'Queue', 'Peak Cells', 'Peak Bytes', 'Peak MB'))
    st.log("  " + "-" * 50)
    for q in range(8):
        cells = peak_data['uc_peak'][q]
        bytes_val = cells * _CELL_SIZE
        mb_val = bytes_val / (1024.0 * 1024)
        marker = '  <-- target' if target_queue is not None and q == target_queue else ''
        st.log("  Q{:<4} {:>12,} {:>14,} {:>13.2f}MB{}".format(
            q, cells, bytes_val, mb_val, marker))
    st.log("  " + "-" * 50)
    st.log("  Mem peak: {:,} cells ({:,} bytes, {:.2f} MB)".format(
        peak_data['mem_cells'],
        peak_data['mem_bytes'],
        peak_data['mem_bytes'] / (1024.0 * 1024) if peak_data['mem_bytes'] else 0))
    st.log(sep)


def dchal_aqm_hw_info(dut, interface):
    """Run DCHAL AQM hw-info script and return parsed per-queue AQM dict.

    Returns dict with keys per-queue arrays (Q0..Q7):
      aqm, mode, min_thr, max_thr, max_prob, max_prob_cfg,
      ecn_enable, drop_en, q_depth, mfair, qold
    Returns None if DCHAL fails.
    """
    st.log("=== DCHAL AQM hw-info for {} ===".format(interface))
    out = st.show(
        dut,
        "sudo docker exec syncd python3 /tmp/dchal_aqm.py {}".format(interface),
        skip_tmpl=True, skip_error_check=True)
    st.log(out)
    for line in (out or '').splitlines():
        if line.startswith('AQM_JSON:'):
            try:
                return json.loads(line[len('AQM_JSON:'):])
            except (json.JSONDecodeError, ValueError):
                st.log("  AQM JSON parse error")
                return None
        if 'DCHAL_AQM_SKIP' in line or 'DCHAL_AQM_ERROR' in line:
            st.log("  AQM collection failed: {}".format(line))
            return None
    return None


def dchal_wred_variance(dut):
    """Run DCHAL WRED variance check and return list of mismatches.

    Returns [] if no variance (ASIC matches expected), or a list of dicts
    with keys: intf, table, field, expected, actual.
    Returns None on error.
    """
    st.log("=== DCHAL WRED variance check ===")
    out = st.show(
        dut,
        "sudo docker exec syncd python3 /tmp/dchal_wred_var.py",
        skip_tmpl=True, skip_error_check=True)
    st.log(out)
    for line in (out or '').splitlines():
        if line.startswith('WRED_VARIANCE:'):
            try:
                return json.loads(line[len('WRED_VARIANCE:'):])
            except (json.JSONDecodeError, ValueError):
                st.log("  WRED variance JSON parse error")
                return None
        if 'WRED_VARIANCE_ERROR' in line:
            st.log("  WRED variance check failed: {}".format(line))
            return None
    return None


def report_aqm_hw_info(aqm_data, fail_msgs=None):
    """Print formatted AQM HW register summary and optionally validate.

    Logs a table showing per-queue AQM mode, thresholds, drop probability,
    ECN, and queue depth from ASIC registers.
    """
    if not aqm_data:
        st.log("  AQM HW data not available — skipping")
        return

    sep = "=" * 78
    st.log(sep)
    st.log("  AQM HW REGISTERS (ASIC-level WRED config)")
    st.log(sep)
    st.log("  {:>5} {:>6} {:>10} {:>10} {:>10} {:>5} {:>5} {:>8}".format(
        'Queue', 'Mode', 'MinThr', 'MaxThr', 'MaxProb%',
        'ECN', 'Drop', 'Depth'))
    st.log("  " + "-" * 72)
    for q in range(8):
        mode = aqm_data.get('mode', [0]*8)[q]
        min_t = aqm_data.get('min_thr', [0]*8)[q]
        max_t = aqm_data.get('max_thr', [0]*8)[q]
        prob_cfg = aqm_data.get('max_prob_cfg', [0]*8)[q]
        ecn = aqm_data.get('ecn_enable', [0]*8)[q]
        drop = aqm_data.get('drop_en', [0]*8)[q]
        depth = aqm_data.get('q_depth', [0]*8)[q]
        st.log("  Q{:<4} {:>6} {:>10} {:>10} {:>9}% {:>5} {:>5} {:>8}".format(
            q, mode, min_t, max_t, prob_cfg, ecn, drop, depth))
    st.log(sep)


def report_wred_variance(mismatches, fail_msgs=None):
    """Print WRED variance results and add failures if mismatches found."""
    sep = "=" * 78
    st.log(sep)
    st.log("  WRED VARIANCE CHECK (expected vs actual HW registers)")
    st.log(sep)
    if mismatches is None:
        st.log("  Variance check unavailable (gRPC error)")
        st.log(sep)
        return
    if not mismatches:
        st.log("  No variance found — ASIC registers match expected values")
        st.log(sep)
        return
    st.log("  {:>12} {:>40} {:>16} {:>10} {:>10}".format(
        'Interface', 'Table', 'Field', 'Expected', 'Actual'))
    st.log("  " + "-" * 92)
    for m in mismatches:
        st.log("  {:>12} {:>40} {:>16} {:>10} {:>10}".format(
            m.get('intf', ''), m.get('table', ''),
            m.get('field', ''), m.get('expected', ''),
            m.get('actual', '')))
    st.log(sep)
    if fail_msgs is not None:
        fail_msgs.append("WRED variance: {} register mismatch(es) found".format(
            len(mismatches)))


# ── FX3 / Sundown1 WRED HW constants ─────────────────────────────────────
#  Source: hal/inc/int_inc/cloudscale/sundown/qos/qos.h
#          hal/src/cloudscale/qos/queue.c  hal_cscale_qos_queue_wred_params_adjust()
#          hal/src/shell/commands/qos.py   _AQM_MAX_PROB_DIVISOR

_WRED_CELL_SIZE   = 416        # bytes per BAX cell  (HAL_SUNDOWN1_QOS_CELL_SIZE)
_WRED_OCC_RANGE   = 64         # 2^AQM_OCC_RANGE = 2^6  (HAL_SUNDOWN1_QOS_AQM_OCC_RANGE)
_WRED_MAX_PROB_HW = 0x7FF      # 2047  (HAL_CSCALE_QOS_AQM_MAX_PROB)


def _wred_bytes_to_hw_thr(bytes_val):
    """Convert CONFIG_DB bytes threshold to DCHAL HW QDES units.

    Formula (from hal_cscale_qos_queue_wred_params_adjust):
        hw_thr = floor(bytes / CELL_SIZE) / OCC_RANGE
               = floor(bytes / 416) / 64
    """
    return int(bytes_val) // _WRED_CELL_SIZE // _WRED_OCC_RANGE


def _wred_prob_to_hw(percent):
    """Convert CONFIG_DB drop_probability (0-100%) to HW max_prob register.

    Formula:
        max_prob = floor(percent * 2047 / 100)
    """
    return int(percent) * _WRED_MAX_PROB_HW // 100


def verify_wred_config_values_prog_in_dchal(dut, interface, qid,
                                            min_threshold, max_threshold,
                                            drop_probability):
    """Verify that CONFIG_DB WRED values are correctly programmed in DCHAL HW.

    Converts CONFIG_DB byte thresholds and drop probability to the expected
    DCHAL register values using FX3/Sundown1 HAL formulas, then reads back
    the live ASIC AQM registers and compares them queue by queue.

    Conversion formulas (hal_cscale_qos_queue_wred_params_adjust):
      min_thr   = floor(min_threshold_bytes / 416) // 64
      max_thr   = floor(max_threshold_bytes / 416) // 64
      max_prob  = floor(drop_probability_pct * 2047 / 100)

    Args:
      dut              : spytest DUT handle
      interface        : egress interface string (e.g. 'Ethernet1_51')
      qid              : queue index 0-7 to validate
      min_threshold    : CONFIG_DB green_min_threshold (bytes, int or str)
      max_threshold    : CONFIG_DB green_max_threshold (bytes, int or str)
      drop_probability : CONFIG_DB green_drop_probability (percent, int or str)

    Returns:
       0  — all three values match HW
      -1  — min_thr mismatch
      -2  — max_thr mismatch
      -3  — drop_prob (max_prob) mismatch
    """
    # ── Step 1: Convert CONFIG_DB values to expected HW register values ──
    exp_min_thr  = _wred_bytes_to_hw_thr(min_threshold)
    exp_max_thr  = _wred_bytes_to_hw_thr(max_threshold)
    exp_max_prob = _wred_prob_to_hw(drop_probability)

    sep = "=" * 72
    st.log(sep)
    st.log("  verify_wred_config_values_prog_in_dchal: {} Q{}".format(
        interface, qid))
    st.log(sep)
    st.log("  CONFIG_DB input:")
    st.log("    green_min_threshold    = {} bytes".format(min_threshold))
    st.log("    green_max_threshold    = {} bytes".format(max_threshold))
    st.log("    green_drop_probability = {}%".format(drop_probability))
    st.log("")
    st.log("  Expected HW registers (formula: bytes/416//64, prob*2047//100):")
    st.log("    min_thr   = {}".format(exp_min_thr))
    st.log("    max_thr   = {}".format(exp_max_thr))
    st.log("    max_prob  = {}".format(exp_max_prob))
    st.log(sep)

    # ── Step 2: Read live DCHAL AQM HW registers ──────────────────────────
    deploy_dchal_helper(dut)
    aqm_data = dchal_aqm_hw_info(dut, interface)

    if aqm_data is None:
        st.log("  ERROR: DCHAL AQM data unavailable for {} — cannot verify".format(
            interface))
        return -1

    act_min_thr  = aqm_data.get('min_thr',  [0] * 8)[qid]
    act_max_thr  = aqm_data.get('max_thr',  [0] * 8)[qid]
    act_max_prob = aqm_data.get('max_prob', [0] * 8)[qid]

    # ── Step 3: Print comparison table ───────────────────────────────────
    st.log(sep)
    st.log("  DCHAL AQM register comparison for Q{}:".format(qid))
    st.log(sep)
    st.log("  {:>14} {:>12} {:>12} {:>8}".format(
        'Field', 'Expected', 'Actual', 'Status'))
    st.log("  " + "-" * 50)

    min_ok  = (act_min_thr == exp_min_thr)
    max_ok  = (act_max_thr == exp_max_thr)
    prob_ok = (act_max_prob == exp_max_prob)

    st.log("  {:>14} {:>12} {:>12} {:>8}".format(
        'min_thr', exp_min_thr, act_min_thr, 'OK' if min_ok else '** FAIL'))
    st.log("  {:>14} {:>12} {:>12} {:>8}".format(
        'max_thr', exp_max_thr, act_max_thr, 'OK' if max_ok else '** FAIL'))
    st.log("  {:>14} {:>12} {:>12} {:>8}".format(
        'max_prob', exp_max_prob, act_max_prob, 'OK' if prob_ok else '** FAIL'))
    st.log(sep)

    # ── Step 4: Return result code ────────────────────────────────────────
    if not min_ok:
        st.log("  RESULT: FAIL — min_thr mismatch (expected {}, got {})".format(
            exp_min_thr, act_min_thr))
        return -1
    if not max_ok:
        st.log("  RESULT: FAIL — max_thr mismatch (expected {}, got {})".format(
            exp_max_thr, act_max_thr))
        return -2
    if not prob_ok:
        st.log("  RESULT: FAIL — max_prob mismatch (expected {}, got {})".format(
            exp_max_prob, act_max_prob))
        return -3

    st.log("  RESULT: PASS — all WRED HW registers match CONFIG_DB")
    return 0


def unbind_wred_from_queues(dut, egress_intf, wait_secs=5):
    """Remove the wred_profile field from each WRED-bound queue in CONFIG_DB.

    Deletes the ``wred_profile`` hash field from
    ``QUEUE|<egress_intf>|<q>`` for every queue in WRED_BOUND_QUEUES
    (0-6).  Waits *wait_secs* afterwards for orchagent to propagate
    the change through SAI and into DCHAL HW.

    This is the config-path equivalent of test-plan step 19.6:
        redis-cli -n 4 HDEL "QUEUE|<intf>|<q>" wred_profile

    Args:
        dut:         spytest DUT handle
        egress_intf: egress interface string (e.g. 'Ethernet1_49')
        wait_secs:   seconds to wait for orchagent propagation (default 5)
    """
    for q in WRED_BOUND_QUEUES:
        key = "QUEUE|{}|{}".format(egress_intf, q)
        st.log("  unbind_wred_from_queues: HDEL \"{}\" wred_profile".format(key))
        st.config(
            dut,
            'sonic-db-cli CONFIG_DB HDEL "{}" "wred_profile"'.format(key),
            skip_error_check=True)
    st.log("  unbind_wred_from_queues: waiting {}s for orchagent".format(
        wait_secs))
    st.wait(wait_secs)


# ── Redis / CONFIG_DB parsers ─────────────────────────────────────────────

def parse_redis_hgetall(output):
    """Parse sonic-db-cli HGETALL output into a dict.

    Newer sonic-db-cli prints the whole hash as one Python dict line, e.g.
    ``{'0': '0', '1': '1', ...}``.  Older paths emit redis-cli-style numbered
    lines or alternating key/value lines.  Shell captures may append a prompt
    line after the dict; that must not be paired as a bogus key/value.
    """
    for raw_line in output.strip().splitlines():
        line = raw_line.strip()
        if line.startswith('{') and line.endswith('}'):
            try:
                parsed = ast.literal_eval(line)
            except (ValueError, SyntaxError):
                continue
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}

    result = {}
    cleaned = []
    for raw_line in output.strip().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.endswith('$') and '@' in line:
            continue
        m = re.match(r'^\d+\)\s*(.*)$', line)
        val = m.group(1) if m else line
        val = val.strip('"').strip("'")
        cleaned.append(val)

    for i in range(0, len(cleaned) - 1, 2):
        result[cleaned[i]] = cleaned[i + 1]
    return result


def parse_redis_hget(output):
    """Parse sonic-db-cli HGET output into a single string value.

    Returns '' for nil/empty responses.  Filters out shell prompts
    (e.g. 'admin@sonic:~$') that appear when the key has no value.
    """
    for raw_line in output.strip().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if '@' in line and line.rstrip().endswith('$'):
            continue
        for ch in ('"', "'"):
            if line.startswith(ch) and line.endswith(ch):
                line = line[1:-1]
        return line
    return ''


def get_first_asic_wred_profile_oid(dut_handle):
    """Return the ``oid:0x...`` string for the first WRED object in ASIC_DB, or ''.

    Used to obtain the expected *bound* WRED profile OID before unbind tests.
    """
    out = st.show(
        dut_handle,
        "sonic-db-cli ASIC_DB KEYS '*SAI_OBJECT_TYPE_WRED*'",
        skip_tmpl=True)
    for line in str(out).splitlines():
        line = line.strip()
        if 'SAI_OBJECT_TYPE_WRED' in line and line.startswith('ASIC_STATE'):
            parts = line.split(':')
            return ':'.join(parts[-2:]) if len(parts) >= 2 else line
    return ''


def get_queue_wred_oid(dut_handle, port, queue_idx):
    """Return ``SAI_QUEUE_ATTR_WRED_PROFILE_ID`` for a specific port/queue from ASIC_DB.

    Resolves the queue object id via ``COUNTERS_QUEUE_NAME_MAP`` in COUNTERS_DB,
    then reads ``SAI_QUEUE_ATTR_WRED_PROFILE_ID`` for that queue.

    Returns:
        WRED profile OID (e.g. ``oid:0x1300...``) when bound, ``oid:0x0`` when
        unbound, or ``''`` if the queue OID could not be resolved.
    """
    oid_out = st.show(
        dut_handle,
        'sonic-db-cli COUNTERS_DB HGET COUNTERS_QUEUE_NAME_MAP '
        '"{}:{}"'.format(port, queue_idx),
        skip_tmpl=True)
    queue_oid = parse_redis_hget(oid_out).strip()
    if not queue_oid:
        st.log("  get_queue_wred_oid: no OID for {}:{}".format(port, queue_idx))
        return ''

    asic_key = "ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:{}".format(queue_oid)
    wred_out = st.show(
        dut_handle,
        'sonic-db-cli ASIC_DB HGET "{}" '
        '"SAI_QUEUE_ATTR_WRED_PROFILE_ID"'.format(asic_key),
        skip_tmpl=True)
    return parse_redis_hget(wred_out).strip()


def verify_queues_wred_binding(dut_handle, port, queues, expected_oid,
                               fail_msgs, label):
    """Check ``SAI_QUEUE_ATTR_WRED_PROFILE_ID`` for each queue index on *port*.

    Appends mismatches to *fail_msgs*.  Returns the number of queues that matched
    *expected_oid*.
    """
    matched = 0
    for q in queues:
        actual = get_queue_wred_oid(dut_handle, port, q)
        if actual == expected_oid:
            st.log("  {} Q{} WRED={} — OK".format(label, q, actual))
            matched += 1
        else:
            fail_msgs.append(
                "{}: Q{} WRED expected='{}', actual='{}'".format(
                    label, q, expected_oid, actual))
    return matched


# ── Queue counter / MAC helpers ───────────────────────────────────────────

def get_queue_counters(dut_handle, interface):
    """Return {qi: {'pkts': int, 'bytes': int, 'drop_pkts': int, 'drop_bytes': int}}
    from 'show queue counters'.  Returns an empty dict if output cannot be parsed.
    """
    output = st.show(dut_handle, "show queue counters {}".format(interface),
                     skip_tmpl=True)
    st.log("Raw queue counters output:\n{}".format(output))
    counters = {}
    for line in output.splitlines():
        if interface not in line:
            continue
        cols = line.split()
        if len(cols) < 6:
            continue
        m = re.match(r'ALL(\d+)', cols[1])
        if not m:
            continue
        try:
            qi = int(m.group(1))
            counters[qi] = {
                'pkts':       int(cols[2].replace(',', '')),
                'bytes':      int(cols[3].replace(',', '')),
                'drop_pkts':  int(cols[4].replace(',', '')),
                'drop_bytes': int(cols[5].replace(',', '')),
            }
        except (ValueError, IndexError):
            continue
    return counters


def parse_dchal_queue_counters(dchal_output):
    """Parse DCHAL show-queuing output into per-queue counter dict.

    Returns {qi: {'pkts': int, 'bytes': int, 'drop_pkts': int, 'drop_bytes': int}}
    matching the same format as get_queue_counters() so they are interchangeable.

    Parses the QOS GROUP N blocks::

        +-------------------------------------------------------------+
        |                         QOS GROUP 0                         |
        +-------------------------------------------------------------+
        |                   Tx Pkts |       50800151|              0|
        |                   Tx Byts |     6502419328|              0|
        | WRED/AFD & Tail Drop Pkts |       51803821|              0|
        | WRED/AFD & Tail Drop Byts |     6630889088|              0|
        +-------------------------------------------------------------+
    """
    def _parse_val(text):
        """Extract first integer from a pipe-delimited DCHAL table cell."""
        vals = []
        for p in text.split('|'):
            p = p.strip()
            if p and p != '-':
                try:
                    vals.append(int(p.replace(',', '')))
                except ValueError:
                    pass
        return vals[0] if vals else 0

    counters = {}
    current_qi = None
    for line in dchal_output.splitlines():
        stripped = line.strip()

        if 'QOS GROUP' in stripped:
            qg_match = re.search(r'QOS GROUP\s+(\d+)', stripped)
            if qg_match:
                current_qi = int(qg_match.group(1))
                counters.setdefault(current_qi, {
                    'pkts': 0, 'bytes': 0,
                    'drop_pkts': 0, 'drop_bytes': 0,
                    'q_depth_bytes': 0})
            else:
                current_qi = None
            continue

        if current_qi is None:
            continue

        if 'Tx Pkts' in stripped and 'Drop' not in stripped:
            counters[current_qi]['pkts'] = _parse_val(
                stripped.split('Tx Pkts')[-1])
        elif 'Tx Byts' in stripped and 'Drop' not in stripped:
            counters[current_qi]['bytes'] = _parse_val(
                stripped.split('Tx Byts')[-1])
        elif 'Drop Pkts' in stripped:
            counters[current_qi]['drop_pkts'] = _parse_val(
                stripped.split('Drop Pkts')[-1])
        elif 'Drop Byts' in stripped:
            counters[current_qi]['drop_bytes'] = _parse_val(
                stripped.split('Drop Byts')[-1])
        elif 'Q Depth' in stripped:
            counters[current_qi]['q_depth_bytes'] = _parse_val(
                stripped.split('Q Depth Byts')[-1])

    return counters


def get_dchal_queue_counters(dut_handle, interface, label="DCHAL snapshot"):
    """Get per-queue counters via DCHAL (ASIC-level, more reliable than
    'show queue counters' on FX3).

    Returns {qi: {'pkts': int, 'bytes': int, 'drop_pkts': int,
                  'drop_bytes': int, 'q_depth_bytes': int}}
    Returns {} if DCHAL produces no output — does NOT fall back to
    'show queue counters' which is unreliable on FX3.
    """
    dchal_out = dchal_show_queuing(dut_handle, label, interface)
    counters = parse_dchal_queue_counters(dchal_out)
    if not counters:
        st.log("WARNING: DCHAL returned no queue data for {} [{}] — "
               "returning empty counters. "
               "'show queue counters' will NOT be used as fallback "
               "(unreliable on FX3).".format(interface, label))
        return {}
    return counters


def get_mid_traffic_depth(dut_handle, interface):
    """Capture instantaneous per-queue depth via DCHAL while traffic is flowing.

    Returns {qi: depth_bytes} for each QOS GROUP.
    """
    dchal_out = dchal_show_queuing(dut_handle, "mid-traffic depth", interface)
    counters = parse_dchal_queue_counters(dchal_out)
    return {qi: data.get('q_depth_bytes', 0) for qi, data in counters.items()}


def log_queue_counters(q_snap, all_queues=range(8)):
    """Print per-queue counter snapshot as a formatted table.

    q_snap: {qi: {'pkts': int, 'bytes': int, 'drop_pkts': int, 'drop_bytes': int}}
    Suitable for output from get_dchal_queue_counters() or get_queue_counters().
    """
    st.log("  {:<8} {:>20} {:>16} {:>20} {:>16}".format(
        "Queue", "Tx Pkts", "Tx Bytes", "Drop Pkts", "Drop Bytes"))
    st.log("  " + "-" * 76)
    for qi in all_queues:
        d = q_snap.get(qi, {})
        st.log("  Q{:<7} {:>20,} {:>16,} {:>20,} {:>16,}".format(
            qi,
            d.get('pkts', 0), d.get('bytes', 0),
            d.get('drop_pkts', 0), d.get('drop_bytes', 0)))


def get_dut_mac(dut_handle, interface):
    """Return the MAC address string of a DUT interface."""
    output = st.show(dut_handle, "ip -o link show {}".format(interface),
                     skip_tmpl=True)
    m = re.search(r'link/ether\s+([\da-fA-F:]+)', output)
    if m:
        return m.group(1)
    st.warn("Could not determine MAC for {}; using zeros".format(interface))
    return "00:00:00:00:00:00"

# ── DCHAL per-queue counter parsing ───────────────────────────────────────

def parse_dchal_queue_stats(dchal_output):
    """Parse DCHAL queuing output into per-queue statistics.

    Returns ``{qos_group_int: {'tx_pkts': int, 'tx_bytes': int,
    'wred_drop_pkts': int, 'wred_drop_bytes': int, 'q_depth_bytes': int}}``.

    Extracts unicast column values from each numbered QOS GROUP block (0-7).
    CONTROL and SPAN QOS GROUP sections are ignored to prevent overwriting
    the last numbered group's data.
    """
    stats = {}
    current_qg = None
    for line in dchal_output.splitlines():
        stripped = line.strip()
        if 'QOS GROUP' in stripped:
            m = re.search(r'QOS GROUP\s+(\d+)', stripped)
            if m:
                current_qg = int(m.group(1))
                if current_qg not in stats:
                    stats[current_qg] = {}
            else:
                current_qg = None
            continue
        if current_qg is None:
            continue
        parts = stripped.split('|')
        if len(parts) < 4:
            continue
        label = parts[1].strip()
        unicast_str = parts[2].strip()
        if not unicast_str:
            continue
        try:
            val = int(unicast_str)
        except ValueError:
            continue
        if 'Tx Pkts' in label and 'Drop' not in label:
            stats[current_qg]['tx_pkts'] = val
        elif 'Tx Byts' in label and 'Drop' not in label:
            stats[current_qg]['tx_bytes'] = val
        elif 'WRED' in label and 'Pkts' in label:
            stats[current_qg]['wred_drop_pkts'] = val
        elif 'WRED' in label and 'Byts' in label:
            stats[current_qg]['wred_drop_bytes'] = val
        elif 'Q Depth' in label:
            stats[current_qg]['q_depth_bytes'] = val
    return stats

def clear_dut_counters(dut_handle):
    """Clear interface and queue counters via CLI, with Redis COUNTERS_DB fallback.

    sonic-clear counters/queuecounters save the current counter values as a
    baseline in /tmp/.portstat-iterate and /tmp/.queuestat-iterate.
    'show interfaces counters' and 'show queue counters' then display
    deltas from that baseline.  We must NOT delete these files — doing so
    would cause the CLI to show raw cumulative values instead of zeros.
    """
    st.config(dut_handle, "sonic-clear counters", skip_error_check=True,
              sudo=False)
    st.config(dut_handle, "sonic-clear queuecounters", skip_error_check=True,
              sudo=False)

    st.config(dut_handle,
              "sonic-db-cli COUNTERS_DB EVAL "
              "\"local keys = redis.call('KEYS','USER_WATERMARKS*') "
              "for _,k in ipairs(keys) do redis.call('DEL',k) end "
              "return #keys\" 0",
              skip_error_check=True)

    st.log("DUT counters cleared (CLI + Redis watermarks)")


def dchal_clear_counters(dut_handle, interface):
    """Clear ASIC-level queue counters and peak watermarks via dchalshell.

    Runs two dchalshell commands inside the syncd container:
      - qos clear counters interface <intf>         (TX + WRED/drop)
      - qos clear counters buffers interface <intf>  (peak watermarks)
    """
    st.config(dut_handle,
              "sudo docker exec syncd bash -c "
              "\"cd /usr/share/sonic/dchalshell && "
              "echo 'qos clear counters interface {}' "
              "| ./dchalshell\"".format(interface),
              skip_error_check=True)
    st.config(dut_handle,
              "sudo docker exec syncd bash -c "
              "\"cd /usr/share/sonic/dchalshell && "
              "echo 'qos clear counters buffers interface {}' "
              "| ./dchalshell\"".format(interface),
              skip_error_check=True)
    st.log("DCHAL counters cleared for {} (queue + peak buffers)".format(
        interface))


def get_intf_counters(dut_handle, interfaces):
    """Return {intf: {'rx_ok': int, 'tx_ok': int, 'tx_drp': int}}
    from 'show interfaces counters'.

    Column layout (whitespace-split):
      [0]Intf [1]State [2]RX_OK [3]RX_RATE [4]RX_UNIT [5]RX_UTIL
      [6]RX_ERR [7]RX_DRP [8]RX_OVR
      [9]TX_OK [10]TX_RATE [11]TX_UNIT [12]TX_UTIL
      [13]TX_ERR [14]TX_DRP [15]TX_OVR

    *interfaces* is an iterable of interface names to capture.
    """
    intf_list = list(interfaces)
    output = st.show(dut_handle, "show interfaces counters", skip_tmpl=True)
    counters = {}
    for line in output.splitlines():
        cols = line.split()
        if len(cols) < 16:
            continue
        line_intf = cols[0]
        if line_intf not in intf_list:
            continue
        try:
            rx_ok  = int(cols[2].replace(',', ''))
            tx_ok  = int(cols[9].replace(',', ''))
            tx_drp = int(cols[14].replace(',', ''))
        except (IndexError, ValueError):
            continue
        counters[line_intf] = {
            'rx_ok': rx_ok, 'tx_ok': tx_ok, 'tx_drp': tx_drp}
    return counters


def get_intf_speeds(dut_handle, interfaces):
    """Return {intf: speed_str} from 'show interfaces status'.

    Parses the Speed column for each requested interface.
    E.g. {'Ethernet1_49': '100G', 'Ethernet1_1': '10G'}
    """
    intf_list = list(interfaces)
    output = st.show(dut_handle, "show interfaces status", skip_tmpl=True)
    speeds = {}
    for line in output.splitlines():
        for intf in intf_list:
            if intf not in line:
                continue
            cols = line.split()
            if len(cols) < 3:
                continue
            for col in cols:
                if re.match(r'^\d+[GMK]$', col, re.IGNORECASE):
                    speeds[intf] = col
                    break
    return speeds


def parse_speed_to_mbps(speed_str):
    """Convert a speed string to Mbps.

    '100G' -> 100000, '10G' -> 10000, '25G' -> 25000,
    '1000M' -> 1000, '100M' -> 100.
    Returns 0 if the string cannot be parsed.
    """
    m = re.match(r'^(\d+)\s*([GMK])', speed_str, re.IGNORECASE)
    if not m:
        return 0
    value = int(m.group(1))
    unit = m.group(2).upper()
    if unit == 'G':
        return value * 1000
    elif unit == 'M':
        return value
    elif unit == 'K':
        return value // 1000
    return 0


def tg_port_speed_gbps(tg_handle, port_handle):
    """Return the line speed in Gbps for a TGen *port_handle*.

    Reads tg_handle.tg_port_speed (set from testbed config, in Mbps e.g. 100000).
    Falls back to 100 Gbps — correct for all FX3 100GE ports.

    NOTE: tg_traffic_stats(mode='aggregate') must NOT be used here.  Calling it
    before any traffic streams are configured triggers a fatal Tcl abort in the
    Ixia HLTAPI parser ('can't read matched_str') that kills the TG session and
    bypasses Python exception handling entirely.
    """
    try:
        speed_str = str(getattr(tg_handle, 'tg_port_speed', '') or '').strip()
        if speed_str:
            m = re.search(r'(\d+)', speed_str)
            if m:
                val = int(m.group(1))
                # testbed encodes speed in Mbps (100000 → 100G); small values
                # are already in Gbps (100 → 100G).
                return val // 1000 if val >= 1000 else val
    except Exception:
        pass
    return 100


def compute_dwrr_stream_rate_pct(tg_handle, ingress_phs, egress_ph, weight_map,
                                 margin=1.3, egress_speed_gbps=None):
    """Return the per-stream Tx rate (% of line rate) needed to congest every DWRR queue.

    Accepts any number of ingress port handles with any mix of line speeds.  Each
    ingress port sends traffic at *rate_pct*% of its own line rate, so the total
    ingress bandwidth for one queue is::

        total_ingress_bw = sum(speed_i for each ingress port)
        arrival_per_queue = rate_pct/100 * total_ingress_bw

    For validate_dwrr_ratios to produce meaningful results every DWRR queue must
    be congested, meaning arrival > its weighted share of the egress link::

        arrival_per_queue > max_weight/sum_weights * egress_bw
        rate_pct > max_weight/sum_weights * egress_bw / total_ingress_bw * 100

    After applying *margin* and rounding up, the result is capped at 90% to avoid
    saturating the ingress ports themselves.

    Parameters
    ----------
    tg_handle   : tg object returned by tgapi.get_handle_byname
    ingress_phs : list of port handles for all ingress ports (any count, any speed)
    egress_ph   : port handle for the egress port (pass None if no TGen on egress)
    weight_map  : dict {queue_index: weight} — only DWRR queues
    margin      : headroom factor above the minimum (default 1.3 = 30%)
    egress_speed_gbps : override egress speed in Gbps (e.g. 25 for breakout);
                        when None, auto-detected from egress_ph or defaults to 100

    Returns
    -------
    int  — stream rate percent (at least 10%, at most 90%)
    """
    ingress_speeds = [tg_port_speed_gbps(tg_handle, ph) for ph in ingress_phs]
    if egress_speed_gbps is not None:
        egress_gbps = egress_speed_gbps
    elif egress_ph:
        egress_gbps = tg_port_speed_gbps(tg_handle, egress_ph)
    else:
        egress_gbps = 100
    total_ingress_gbps = sum(ingress_speeds)

    max_w    = max(weight_map.values())
    sum_w    = sum(weight_map.values())
    min_pct  = (max_w / float(sum_w)) * (egress_gbps / float(total_ingress_gbps)) * 100
    rate_pct = max(10, min(90, int(math.ceil(min_pct * margin))))

    st.log(
        "compute_dwrr_stream_rate_pct: {} ingress port(s) {}G  egress={}G  "
        "max_w={}/sum_w={}  congestion_floor={:.1f}%  "
        "-> STREAM_RATE_PCT={}% (margin={:.1f}x)".format(
            len(ingress_phs),
            "+".join(str(s) for s in ingress_speeds),
            egress_gbps, max_w, sum_w,
            min_pct, rate_pct, margin)
    )
    return rate_pct


def report_intf_counters(port_info, intf_before, intf_after):
    """Print DUT INTERFACE COUNTERS (delta) table.

    port_info: {'ingress_a': 'Ethernet1_49', 'ingress_b': 'Ethernet1_50',
                'egress': 'Ethernet1_51'}
    """
    sep = "=" * 70
    st.log(sep)
    st.log("  DUT INTERFACE COUNTERS (delta)")
    st.log(sep)
    st.log("  {:<18} {:>5}  {:>14} {:>14} {:>14}".format(
        'Interface', 'Role', 'RX OK', 'TX OK', 'TX DRP'))
    st.log("  " + "-" * 63)
    role_map = {v: k for k, v in port_info.items()}
    role_labels = {'ingress': 'Ingress', 'ingress_a': 'TX1-in',
                   'ingress_b': 'TX2-in', 'egress': 'Egress'}
    for intf in port_info.values():
        bef = intf_before.get(intf, {})
        aft = intf_after.get(intf, {})
        d_rx = aft.get('rx_ok', 0) - bef.get('rx_ok', 0)
        d_tx = aft.get('tx_ok', 0) - bef.get('tx_ok', 0)
        d_drp = aft.get('tx_drp', 0) - bef.get('tx_drp', 0)
        role_key = role_map.get(intf, '')
        role = role_labels.get(role_key, role_key)
        st.log("  {:<18} {:>5}  {:>14,} {:>14,} {:>14,}".format(
            intf, role, d_rx, d_tx, d_drp))


# ── DCHAL Bandwidth% validation ───────────────────────────────────────────

def parse_dchal_egress_bw(dchal_output):
    """Parse DCHAL Egress Queuing output into per-queue HW scheduling info.

    Returns {qos_group: {'bw_pct': int_or_None, 'prio': int_or_None}}.
      - DWRR queues have bw_pct set, prio is None.
      - STRICT queues have prio set, bw_pct is None.

    Scans for the 'QoS-Group# Bandwidth% PrioLevel ...' table header.
    """
    result = {}
    in_table = False
    data_started = False
    for line in dchal_output.splitlines():
        stripped = line.strip()
        if 'QoS-Group#' in stripped and 'Bandwidth%' in stripped:
            in_table = True
            data_started = False
            continue
        if not in_table:
            continue
        if 'Min' in stripped and 'Max' in stripped and 'Units' in stripped:
            continue
        if stripped.startswith('---'):
            data_started = True
            continue
        if data_started:
            if not stripped or stripped.startswith('+'):
                break
            parts = stripped.split()
            if len(parts) < 3 or not parts[0].isdigit():
                continue
            qg = int(parts[0])
            bw_val = None
            prio_val = None
            if parts[1] != '-':
                try:
                    bw_val = int(parts[1])
                except ValueError:
                    pass
            if parts[2] != '-':
                try:
                    prio_val = int(parts[2])
                except ValueError:
                    pass
            result[qg] = {'bw_pct': bw_val, 'prio': prio_val}
    return result


def report_dchal_bw_check(dchal_output, fail_msgs):
    """Print DCHAL HW SCHEDULER table and validate against config_db.json weights.

    Verifies:
      - DWRR queues: Bandwidth% matches weight/total_weight*100 (±1.5%)
      - DWRR sum: all BW% values sum to ~100% (±10%)
      - STRICT queues: PrioLevel is set (not None)
    """
    hw = parse_dchal_egress_bw(dchal_output)
    if not hw:
        st.warn("DCHAL: no Egress Queuing data parsed — skipping HW scheduler check")
        return

    dwrr_weights = {qi: w for qi, (stype, w) in TORTUGA_CONFIG.items()
                    if stype == 'DWRR'}
    total_w = sum(dwrr_weights.values())

    sep = "=" * 70
    st.log(sep)
    st.log("  DCHAL HW SCHEDULER vs config_db.json")
    st.log(sep)
    st.log("  {:<6} {:<8} {:>6} {:>10} {:>10} {:>8}  {}".format(
        'Queue', 'Type', 'Weight', 'Expect%', 'DCHAL BW%', 'Prio', 'Status'))
    st.log("  " + "-" * 63)

    for qi in range(8):
        stype, weight = TORTUGA_CONFIG[qi]
        info = hw.get(qi, {})
        actual_bw = info.get('bw_pct')
        actual_prio = info.get('prio')

        if stype == 'DWRR':
            expected_pct = weight / total_w * 100
            wt_str = str(weight)
            exp_str = '{:.1f}%'.format(expected_pct)
            bw_str = '{}%'.format(actual_bw) if actual_bw is not None else '?'
            prio_str = '-'
            if actual_bw is None:
                status = 'FAIL'
                fail_msgs.append(
                    "DCHAL Q{} (DWRR wt {}) missing BW% in HW".format(qi, weight))
            elif abs(actual_bw - expected_pct) > 1.5:
                status = 'FAIL'
                fail_msgs.append(
                    "DCHAL Q{} BW%={}, expected ~{:.1f}% "
                    "(weight {}/{})".format(qi, actual_bw, expected_pct,
                                            weight, total_w))
            else:
                status = 'OK'
        else:
            wt_str = '-'
            exp_str = '-'
            bw_str = '-'
            prio_str = str(actual_prio) if actual_prio is not None else '?'
            if actual_prio is None:
                status = 'FAIL'
                fail_msgs.append(
                    "DCHAL Q{} (STRICT) missing PrioLevel in HW".format(qi))
            else:
                status = 'OK'

        st.log("  Q{:<4} {:<8} {:>6} {:>10} {:>10} {:>8}  {}".format(
            qi, stype, wt_str, exp_str, bw_str, prio_str, status))

    bw_sum = sum(hw.get(qi, {}).get('bw_pct', 0) or 0 for qi in dwrr_weights)
    st.log("  " + "-" * 63)
    st.log("  DWRR BW% sum = {}% (expected ~100%, tolerance +-10%)".format(bw_sum))
    if abs(bw_sum - 100) > 10:
        fail_msgs.append(
            "DCHAL DWRR BW% sum={}, expected ~100%".format(bw_sum))


def validate_dchal_bw_vs_weights(label, dchal_output, weight_map, fail_msgs):
    """Validate DCHAL Bandwidth% values against a dynamic weight_map.

    Used by test_fx3_scheduler_2022.py which changes weights at runtime.
    Unlike report_dchal_bw_check (uses hardcoded TORTUGA_CONFIG), this
    function accepts an arbitrary weight_map so step-by-step weight changes
    can be verified against the expected ASIC BW% at each checkpoint.

    Tolerances applied:
      - Per-queue BW%: abs(actual - expected) <= 2.0% (FX3 ASIC granularity)
      - DWRR BW% sum:  abs(sum - 100) <= 10%  (matches SAI API test tolerance;
                       transient 1% fallback during HDEL can lower sum slightly)

    Returns the parsed bw dict (or None if no data), so callers can pass it
    to record_checkpoint for summary logging.
    """
    bw = parse_dchal_egress_bw(dchal_output)
    if not bw:
        st.log("[{}] DCHAL: no Bandwidth% data parsed — skipping weight validation".format(label))
        return bw
    total_w = sum(weight_map.values())
    st.log("[{}] DCHAL Bandwidth% parsed={}, weight_map={}, total_weight={}".format(
        label, bw, weight_map, total_w))
    for qg, w in sorted(weight_map.items()):
        expected_pct = w / total_w * 100
        actual_pct = (bw.get(qg) or {}).get('bw_pct')
        if actual_pct is None:
            fail_msgs.append(
                "[{}] DCHAL QoS-Group {} (weight {}) missing from Bandwidth% output".format(
                    label, qg, w))
            continue
        if abs(actual_pct - expected_pct) > 2.0:
            fail_msgs.append(
                "[{}] DCHAL QoS-Group {} Bandwidth%={}, expected ~{:.1f}% "
                "(weight={}, total_weight={})".format(
                    label, qg, actual_pct, expected_pct, w, total_w))

    bw_sum = sum((bw.get(qg) or {}).get('bw_pct', 0) or 0 for qg in weight_map)
    if abs(bw_sum - 100) > 10:
        fail_msgs.append(
            "[{}] DCHAL DWRR Bandwidth% sum={}, expected ~100% (tolerance ±10)".format(
                label, bw_sum))
    return bw


def validate_queue_counters_vs_weights(label, q_before, q_after, weight_map, fail_msgs):
    """Validate that queue counter deltas are proportional to DWRR weights.

    Requires congested traffic (total ingress rate > egress port capacity) to
    produce meaningful DWRR differentiation.  At low (non-congested) rates all
    queues drain freely and counters will be approximately equal regardless of
    weight.

    weight_map: {qos_group_int: weight_int} — only the DWRR queues under test.

    Rules applied for each queue pair (qi, qj):
      - Equal weights   → counter ratio qi/qj should be 0.70 … 1.43 (within 30%).
      - wi > wj         → delta(qi) >= delta(qj) × 0.80  (allow 20% slack).
      - wi < wj         → delta(qi) <= delta(qj) × 1.20  (allow 20% slack).

    If all deltas are zero (counters unavailable or traffic not reaching DUT)
    the proportional check is skipped with a warning.
    """
    deltas = {qg: max(0, q_after.get(qg, {}).get('pkts', 0)
                      - q_before.get(qg, {}).get('pkts', 0))
              for qg in weight_map}

    st.log("[{}] Queue counter deltas (pkts): {}".format(
        label, {qg: deltas[qg] for qg in sorted(weight_map)}))

    if not any(deltas.values()):
        st.log("[{}] All queue counter deltas are 0 — "
               "skipping proportional check".format(label))
        return

    checked = set()
    for qi, wi in sorted(weight_map.items()):
        for qj, wj in sorted(weight_map.items()):
            if (qj, qi) in checked or qi == qj:
                continue
            checked.add((qi, qj))
            di, dj = deltas[qi], deltas[qj]
            if di == 0 or dj == 0:
                continue

            if wi == wj:
                # Equal weights: counters should be similar
                ratio = min(di, dj) / max(di, dj)
                if ratio < 0.70:
                    fail_msgs.append(
                        "[{}] Q{} and Q{} have equal weight ({}) but counter "
                        "ratio={:.2f} (expected >= 0.70); "
                        "Q{}={} Q{}={}".format(
                            label, qi, qj, wi, ratio, qi, di, qj, dj))
                else:
                    st.log("  [{}] Q{}/Q{} equal-weight OK: "
                           "ratio={:.2f} (weights {}/{})".format(
                               label, qi, qj, ratio, wi, wj))
            elif wi > wj:
                # qi has more weight — should have higher counter
                if di < dj * 0.80:
                    fail_msgs.append(
                        "[{}] Q{}(w={}) delta={} < Q{}(w={}) delta={} × 0.80 "
                        "— expected Q{} to dominate".format(
                            label, qi, wi, di, qj, wj, dj, qi))
                else:
                    st.log("  [{}] Q{}>Q{} weight ordering OK: "
                           "Q{}={} Q{}={} (weights {}/{})".format(
                               label, qi, qj, qi, di, qj, dj, wi, wj))
            else:
                # qi has less weight — should have lower counter
                if di > dj * 1.20:
                    fail_msgs.append(
                        "[{}] Q{}(w={}) delta={} > Q{}(w={}) delta={} × 1.20 "
                        "— expected Q{} to dominate".format(
                            label, qi, wi, di, qj, wj, dj, qj))
                else:
                    st.log("  [{}] Q{}<Q{} weight ordering OK: "
                           "Q{}={} Q{}={} (weights {}/{})".format(
                               label, qi, qj, qi, di, qj, dj, wi, wj))


def validate_queue_counters(label, q_before, q_after, fail_msgs,
                            weight_map=None,
                            check_zeros=None,
                            check_nonzero=None,
                            check_no_drops=None):
    """Validate per-queue counter deltas (before/after a traffic window).

    Combines four independent checks into one call, any of which can be
    selectively enabled via their respective arguments:

    Args:
        label (str):        Descriptive label for log/fail messages.
        q_before (dict):    Counter snapshot before traffic —
                            {qi: {'pkts': int, 'drop_pkts': int, ...}}
                            from get_dchal_queue_counters() or get_queue_counters().
        q_after (dict):     Counter snapshot after traffic — same format.
        fail_msgs (list):   Failure descriptions are appended here.
        weight_map (dict):  {qi: weight} for DWRR proportionality check.
                            Pass None (default) to skip proportionality check.
        check_zeros (list): Queue indices whose tx_pkts delta must be == 0.
                            Typical use: STRICT queues when STRICT traffic is
                            not being injected.
        check_nonzero (list): Queue indices whose tx_pkts delta must be > 0.
                            Typical use: DWRR queues under active traffic.
        check_no_drops (list): Queue indices whose drop_pkts delta must be == 0.
                            Typical use: STRICT queues (must never be tail-dropped
                            when given absolute priority).

    Returns:
        dict: {qi: tx_delta} — per-queue tx packet deltas (informational).
    """
    # Compute tx_pkts and drop_pkts deltas for all queues that appear in
    # either snapshot.
    all_queues = sorted(set(q_before) | set(q_after))
    tx_deltas   = {}
    drop_deltas = {}
    for qi in all_queues:
        b = q_before.get(qi, {})
        a = q_after.get(qi, {})
        tx_deltas[qi]   = max(0, a.get('pkts', 0)      - b.get('pkts', 0))
        drop_deltas[qi] = max(0, a.get('drop_pkts', 0) - b.get('drop_pkts', 0))

    # ── Log delta table ───────────────────────────────────────────────────
    sep = "=" * 72
    st.log(sep)
    st.log("  QUEUE COUNTER DELTAS [{}]".format(label))
    st.log(sep)
    st.log("  {:<8} {:>20} {:>20}".format("Queue", "Tx Pkts Delta", "Drop Pkts Delta"))
    st.log("  " + "-" * 50)
    for qi in all_queues:
        st.log("  Q{:<7} {:>20,} {:>20,}".format(qi, tx_deltas[qi], drop_deltas[qi]))
    st.log(sep)

    # ── Check 1: check_zeros — tx_pkts delta must be 0 ───────────────────
    if check_zeros:
        for qi in check_zeros:
            delta = tx_deltas.get(qi, 0)
            st.log("  [{}] Q{} (check_zeros): tx delta={} (expected 0)".format(
                label, qi, delta))
            if delta != 0:
                fail_msgs.append(
                    "[{}] Q{} tx_pkts delta={} — expected 0 "
                    "(queue must not carry traffic in this scenario)".format(
                        label, qi, delta))

    # ── Check 2: check_nonzero — tx_pkts delta must be > 0 ───────────────
    if check_nonzero:
        for qi in check_nonzero:
            delta = tx_deltas.get(qi, 0)
            st.log("  [{}] Q{} (check_nonzero): tx delta={} (expected > 0)".format(
                label, qi, delta))
            if delta <= 0:
                fail_msgs.append(
                    "[{}] Q{} tx_pkts delta={} — expected > 0 "
                    "(traffic must reach this queue)".format(
                        label, qi, delta))

    # ── Check 3: check_no_drops — drop_pkts delta must be 0 ──────────────
    if check_no_drops:
        for qi in check_no_drops:
            drops = drop_deltas.get(qi, 0)
            st.log("  [{}] Q{} (check_no_drops): drop delta={} (expected 0)".format(
                label, qi, drops))
            if drops != 0:
                fail_msgs.append(
                    "[{}] Q{} drop_pkts delta={} — expected 0 "
                    "(this queue must not drop packets)".format(
                        label, qi, drops))

    # ── Check 4: weight proportionality ──────────────────────────────────
    if weight_map:
        # Re-package deltas into the format expected by the existing helper.
        _q_delta_snap = {qi: {'pkts': tx_deltas.get(qi, 0)} for qi in weight_map}
        _zero_snap    = {qi: {'pkts': 0} for qi in weight_map}
        validate_queue_counters_vs_weights(
            label, _zero_snap, _q_delta_snap, weight_map, fail_msgs)

    return tx_deltas


# ── DWRR ratio / scheduler validation (from test_scheduler_validation.py) ──

TORTUGA_DWRR_RATIO_CHECKS = [
    (1, 0, 1.0, 'w20/w20'),
    (2, 0, 1.0, 'w20/w20'),
    (3, 0, 2.0, 'w40/w20'),
    (4, 1, 2.0, 'w40/w20'),
    (4, 3, 1.0, 'w40/w40'),
    (5, 0, 1.5, 'w30/w20'),
]

DWRR_TOLERANCE = 0.20


def validate_scheduler(q_deltas, q_drop_deltas, fail_msgs):
    """Check DWRR weight ratios and STRICT zero-drop invariants.

    Same logic as test_scheduler_validation.py validate_scheduler(), adapted
    for SpyTest (st.log instead of print, fail_msgs instead of sys.exit).

    q_deltas:      {qi: pkt_count_delta} for queues 0-7.
    q_drop_deltas: {qi: drop_pkt_delta}  for queues 0-7.
    fail_msgs:     list to append failure descriptions to.

    DWRR ratio checks (±20% tolerance):
      Q1/Q0 = 1.0 (w20/w20), Q2/Q0 = 1.0 (w20/w20),
      Q3/Q0 = 2.0 (w40/w20), Q4/Q1 = 2.0 (w40/w20),
      Q4/Q3 = 1.0 (w40/w40), Q5/Q0 = 1.5 (w30/w20).

    STRICT zero-drop: Q6, Q7 must have 0 drop_pkts.
    """
    tol = DWRR_TOLERANCE

    st.log("  DWRR Weight Ratios (tolerance {:.0%}):".format(tol))
    for qi_num, qi_den, expected, ratio_label in TORTUGA_DWRR_RATIO_CHECKS:
        num = q_deltas.get(qi_num, 0)
        den = q_deltas.get(qi_den, 0)
        if den == 0:
            actual = float('inf') if num > 0 else 0.0
            ok = False
        else:
            actual = num / den
            ok = abs(actual - expected) <= tol * expected
        tag = 'PASS' if ok else '** FAIL'
        desc = "Q{}/Q{} ({})".format(qi_num, qi_den, ratio_label)
        st.log("    {:<18s} expected {:.2f}  actual {:.2f}  {}".format(
            desc, expected, actual, tag))
        if not ok:
            fail_msgs.append(
                "{}: expected {:.2f}, actual {:.2f}".format(
                    desc, expected, actual))

    st.log("")
    st.log("  STRICT Priority (zero drops expected):")
    for qi in (6, 7):
        drops = q_drop_deltas.get(qi, 0)
        ok = drops == 0
        tag = 'PASS' if ok else '** FAIL'
        desc = "Q{} (STRICT)".format(qi)
        st.log("    {:<18s} drops {:>14,}  {}".format(desc, drops, tag))
        if not ok:
            fail_msgs.append(
                "{}: {} drop_pkts (expected 0)".format(desc, drops))


def validate_dwrr_ratios(label, q_before, q_after, weight_map, fail_msgs,
                         strict_queues=(6, 7), tolerance=DWRR_TOLERANCE):
    """Validate each DWRR queue's Tx share against its weight proportion.

    For each queue:
      expected_share% = w_i / sum(all weights) * 100
      actual_share%   = delta_i / total_egress * 100
      pass if abs(actual_share - expected_share) <= tolerance * expected_share

    This is the packet-counter equivalent of validate_dchal_bw_vs_weights():
    both check the same invariant — one via ASIC register readout, one via
    live Tx packet deltas under congested traffic.

    label:         checkpoint label for log messages.
    q_before:      {qi: {'pkts': int, 'drop_pkts': int}} snapshot before traffic.
    q_after:       {qi: {'pkts': int, 'drop_pkts': int}} snapshot after traffic.
    weight_map:    {qi: weight_int} — DWRR queues to check.
    fail_msgs:     list to append failure descriptions to.
    strict_queues: queue indices expected to have zero drops.
    tolerance:     fractional tolerance (default 0.20 = ±20% of expected share).
    """
    SEP  = "=" * 72
    DASH = "-" * 72
    total_w = sum(weight_map.values())

    # ── Header ───────────────────────────────────────────────────────────
    st.log(SEP)
    st.log("  DWRR TX-SHARE VALIDATION  —  {}".format(label))
    st.log("  Tolerance  : {:.0%}  (±{:.0%} of expected share)".format(tolerance, tolerance))
    st.log("  Total weight: {}  ({})".format(
        total_w,
        "  ".join("Q{}={}".format(q, w) for q, w in sorted(weight_map.items()))))
    st.log(SEP)

    # ── Build deltas ─────────────────────────────────────────────────────
    deltas      = {}
    drop_deltas = {}
    st.log("  {:<8} {:<8} {:>16} {:>16} {:>14} {:>14}".format(
        "Queue", "Weight", "Before (pkts)", "After (pkts)", "Tx Delta", "Drop Delta"))
    st.log("  " + DASH)
    for qi in sorted(weight_map):
        before_pkts = q_before.get(qi, {}).get('pkts', 0)
        after_pkts  = q_after.get(qi, {}).get('pkts', 0)
        before_drop = q_before.get(qi, {}).get('drop_pkts', 0)
        after_drop  = q_after.get(qi, {}).get('drop_pkts', 0)
        deltas[qi]      = max(0, after_pkts - before_pkts)
        drop_deltas[qi] = max(0, after_drop - before_drop)
        st.log("  Q{:<7} {:<8} {:>16,} {:>16,} {:>14,} {:>14,}".format(
            qi, weight_map[qi], before_pkts, after_pkts, deltas[qi], drop_deltas[qi]))

    total_egress = sum(deltas.values())
    st.log("  " + DASH)
    st.log("  Total Tx delta: {:,} pkts".format(total_egress))
    st.log("")

    if not any(deltas.values()):
        st.log("  WARNING: all queue Tx deltas are 0 — skipping share validation")
        st.log(SEP)
        return

    # ── Per-queue share validation ────────────────────────────────────────
    st.log("  {:<8} {:<8} {:>14} {:>14} {:>20} {}".format(
        "Queue", "Weight", "Expected %", "Actual %", "Acceptable Range", "Result"))
    st.log("  " + DASH)
    pass_count = 0
    fail_count = 0
    for qi, wi in sorted(weight_map.items()):
        expected_pct = wi / float(total_w) * 100
        actual_pct   = deltas[qi] / float(total_egress) * 100
        lo = expected_pct * (1.0 - tolerance)
        hi = expected_pct * (1.0 + tolerance)
        ok  = lo <= actual_pct <= hi
        tag = 'PASS' if ok else '** FAIL **'
        if ok:
            pass_count += 1
        else:
            fail_count += 1
        st.log("  Q{:<7} {:<8} {:>13.1f}% {:>13.1f}%  [{:.1f}% .. {:.1f}%]   {}".format(
            qi, wi, expected_pct, actual_pct, lo, hi, tag))
        if not ok:
            direction = "low" if actual_pct < expected_pct else "high"
            fail_msgs.append(
                "[{}] Q{} (w={}): Tx share={:.1f}%, expected {:.1f}%  "
                "acceptable [{:.1f}% .. {:.1f}%]  "
                "(delta={:,}, total={:,})  actual Tx share is {}".format(
                    label, qi, wi, actual_pct, expected_pct, lo, hi,
                    deltas[qi], total_egress, direction))

    st.log("  " + DASH)
    st.log("  DWRR share result : {} passed,  {} failed".format(pass_count, fail_count))
    st.log("")

    # ── Strict-priority drop check ───────────────────────────────────────
    if strict_queues:
        st.log("  Strict-Priority Queues (zero drops expected):")
        st.log("  " + DASH)
        st.log("  {:<10} {:>16} {:>16} {:>14} {}".format(
            "Queue", "Before (drop)", "After (drop)", "Drop Delta", "Result"))
        st.log("  " + DASH)
        for qi in sorted(strict_queues):
            before_drop = q_before.get(qi, {}).get('drop_pkts', 0)
            after_drop  = q_after.get(qi, {}).get('drop_pkts', 0)
            drops = max(0, after_drop - before_drop)
            ok  = drops == 0
            tag = 'PASS' if ok else '** FAIL **'
            st.log("  Q{:<9} {:>16,} {:>16,} {:>14,} {}".format(
                qi, before_drop, after_drop, drops, tag))
            if not ok:
                fail_msgs.append(
                    "[{}] Q{} (STRICT): {:,} drop_pkts (expected 0)".format(
                        label, qi, drops))
        st.log("  " + DASH)

    st.log(SEP)


# ── Traffic report helpers ─────────────────────────────────────────────
#
# Formatted output tables for IXIA stats, DUT queue counters,
# scheduler validation, and end-to-end summary.
# Designed to match the reference output from test_scheduler_validation.py.

def report_ixia_port_stats(tg_handle, tg_ports, num_queues):
    """Print IXIA PORT STATS table.

    tg_ports: list of (port_handle, role_label) e.g.
              [(ph_a, 'TX1'), (ph_b, 'TX2'), (ph_e, 'RX')]
    num_queues: number of queues (8) to compute per-DSCP estimate.

    Returns:
        (total_tx_pkts, total_rx_pkts, rx_port_pkts, rx_port_name)
    """
    sep = "=" * 70
    st.log(sep)
    st.log("  IXIA PORT STATS")
    st.log(sep)
    st.log("  {:<9}{:<10} {:>14} {:>14}".format(
        'Port', 'Role', 'TX pkts', 'RX pkts'))
    st.log("  " + "-" * 50)

    total_tx = 0
    total_rx = 0
    rx_pkts = 0
    rx_port_name = ''
    for ph, role in tg_ports:
        try:
            stats = tg_handle.tg_traffic_stats(
                port_handle=ph, mode='aggregate')
            agg = stats.get(ph, {}).get('aggregate', {})
            tx = int(agg.get('tx', {}).get('total_pkts', 0))
            rx = int(agg.get('rx', {}).get('total_pkts', 0))
            port_name = agg.get('port_name', ph)
        except Exception as exc:
            st.log("  WARNING: tg_traffic_stats failed for {} ({}): {}".format(
                ph, role, exc))
            tx, rx, port_name = 0, 0, ph
        st.log("  {:<9}{:<10} {:>14,} {:>14,}".format(
            port_name, role, tx, rx))
        total_tx += tx
        total_rx += rx
        if role.startswith('RX'):
            rx_pkts = rx
            rx_port_name = port_name

    num_tx_ports = sum(1 for _, r in tg_ports if r.startswith('TX'))
    if num_tx_ports > 0 and num_queues > 0:
        per_dscp = total_tx // (num_tx_ports * num_queues)
        st.log("")
        st.log("  Combined TX per DSCP (est): ~{:,} pkts".format(per_dscp))

    return total_tx, total_rx, rx_pkts, rx_port_name


def report_queue_counters(egress_intf, q_deltas, q_drop_deltas,
                          num_queues=8, source="show queue counters"):
    """Print DUT QUEUE COUNTERS table.

    Returns total_egress (sum of all queue egress deltas).
    *source* is displayed in the banner to identify where the data came from
    (e.g. 'DCHAL' or 'show queue counters').
    """
    sep = "=" * 70
    st.log(sep)
    st.log("  DUT QUEUE COUNTERS via {}: {} (delta)".format(
        source, egress_intf))
    st.log(sep)
    hdr = "  {:<6} {:>4}  {:<7} {:>3}  {:>14} {:>14} {:>7}".format(
        'Queue', 'DSCP', 'Sched', 'Wt', 'Egress pkts', 'Drop pkts', 'Thru')
    st.log(hdr)
    st.log("  " + "-" * 63)
    total_egress = sum(q_deltas.get(qi, 0) for qi in range(num_queues))
    for qi in range(num_queues):
        dscp = QUEUE_TO_DSCP[qi]
        stype, weight = TORTUGA_CONFIG[qi]
        wt_str = str(weight) if weight else '-'
        egress = q_deltas.get(qi, 0)
        drops = q_drop_deltas.get(qi, 0)
        q_input = egress + drops
        thru = (egress / q_input * 100) if q_input else 0
        st.log("  Q{:<4} {:>4}  {:<7} {:>3}  {:>14,} {:>14,} {:>6.1f}%".format(
            qi, dscp, stype, wt_str, egress, drops, thru))
    return total_egress


def report_wred_linearity(data_points, egress_speed_mbps=10000,
                          wred_profile=GOLDEN_WRED_PROFILE):
    """Print formatted WRED linearity summary table with zone-based validation.

    *data_points* is a list of dicts, each with keys:
      margin_mbps, rate_pct, q_depth_bytes, egress_pkts, drop_pkts,
      total_pkts, drop_rate_pct
    *egress_speed_mbps* is used internally (sanity check only).
    *wred_profile* is an optional dict with green_min_threshold,
      green_max_threshold, and green_drop_probability keys (string values).
      Defaults to GOLDEN_WRED_PROFILE when None.

    Validation is zone-based (proves WRED is working, not just traffic
    conservation):
      Zone A  depth < min_th   : no WRED, drops must be ~0
      Zone B  min_th <= depth <= max_th : WRED active, prob 0-5%
      Zone C  depth > max_th   : tail drop, prob capped at 100%

    Returns True only if every data point passes its zone check and
    WRED Prob increases monotonically with margin.
    """
    egr_spd = egress_speed_mbps if egress_speed_mbps > 0 else 10000
    min_th_bytes = int(wred_profile.get('green_min_threshold', '1048576'))
    max_th_bytes = int(wred_profile.get('green_max_threshold', '3145728'))
    max_prob = float(wred_profile.get('green_drop_probability', '5'))
    min_th_mb = min_th_bytes / (1024.0 * 1024)
    max_th_mb = max_th_bytes / (1024.0 * 1024)

    fanin = bool(data_points and
                 data_points[0].get('rate_pct_per_port') is not None)
    if fanin:
        tbl_w = 88
    else:
        tbl_w = 68
    sep = "=" * (tbl_w + 2)
    st.log(sep)
    st.log("  WRED LINEARITY SUMMARY (egress {}M)".format(egr_spd))
    st.log(sep)
    if fanin:
        st.log("  {:>8} {:>9} {:>9} {:>9} {:>9} {:>10} {:>10} {:>6} {:>8}".format(
            'Margin', 'Port A', 'Port B', 'Rate%',
            'Avg Depth', 'Est. Prob', 'WRED Drop', 'Zone', 'Status'))
    else:
        st.log("  {:>8} {:>9} {:>9} {:>10} {:>10} {:>6} {:>8}".format(
            'Margin', 'Rate%', 'Avg Depth',
            'Est. Prob', 'WRED Drop', 'Zone', 'Status'))
    st.log("  " + "-" * tbl_w)
    prev_wred_prob = -1.0
    all_passed = True
    any_drops = False
    for dp in data_points:
        margin = dp['margin_mbps']
        rate = dp['rate_pct']
        drop_rate = dp['drop_rate_pct']

        samples = dp.get('depth_samples', [])
        if samples:
            avg_depth = sum(samples) / len(samples)
        else:
            avg_depth = dp['q_depth_bytes']
        peak = dp.get('peak_bytes', 0)
        depth_mb = avg_depth / (1024.0 * 1024)
        peak_mb = peak / (1024.0 * 1024)

        if depth_mb < min_th_mb:
            zone = 'A'
        elif depth_mb <= max_th_mb:
            zone = 'B'
        else:
            zone = 'C*' if dp.get('rebaselined', False) else 'C'

        if drop_rate > 0:
            any_drops = True

        is_zone_c = zone.startswith('C')

        all_samples_in_c = (samples and
                            all(s > max_th_bytes for s in samples))
        peak_in_c = dp.get('peak_bytes', 0) >= max_th_bytes

        if is_zone_c and not (all_samples_in_c and peak_in_c
                              and drop_rate > 0):
            reasons_skip = []
            if not all_samples_in_c:
                reasons_skip.append("not all depth samples > max_th")
            if not peak_in_c:
                reasons_skip.append("peak < max_th")
            if drop_rate <= 0:
                reasons_skip.append("no drops")
            st.log("  {:>7}M  Zone {} skipped: {}".format(
                margin, zone, ', '.join(reasons_skip)))
            continue

        if depth_mb <= min_th_mb:
            wred_prob = 0.0
        elif depth_mb >= max_th_mb:
            wred_prob = 100.0
        else:
            wred_prob = max_prob * (depth_mb - min_th_mb) / (max_th_mb - min_th_mb)

        if is_zone_c:
            wred_drop_display = 100.0
        else:
            wred_drop_display = drop_rate

        reasons = []
        if zone == 'A':
            if drop_rate > 0.5:
                reasons.append("WRED Drop {:.2f}% in Zone A".format(drop_rate))
        elif zone == 'B':
            if wred_prob <= 0 and margin > 0:
                reasons.append("Est. Prob=0 in Zone B")
            if wred_prob > max_prob + 0.5:
                reasons.append("Est. Prob {:.2f}% exceeds max {}%".format(
                    wred_prob, max_prob))
            if drop_rate <= 0 and margin > 0:
                reasons.append("WRED Drop=0 in Zone B")

        if wred_prob < prev_wred_prob - 0.5:
            reasons.append("est. prob not monotonic")

        if reasons:
            tag = 'FAIL'
            all_passed = False
        else:
            tag = 'OK'

        if fanin:
            pp = dp.get('rate_pct_per_port', rate / 2.0)
            st.log("  {:>7}M {:>8.3f}% {:>8.3f}% {:>8.3f}% "
                   "{:>7.2f}MB {:>9.2f}% {:>9.2f}% {:>6} {:>8}".format(
                       margin, pp, pp, rate,
                       depth_mb, wred_prob, wred_drop_display, zone, tag))
        else:
            st.log("  {:>7}M {:>8.3f}% {:>7.2f}MB {:>9.2f}% {:>9.2f}% "
                   "{:>6} {:>8}".format(
                       margin, rate, depth_mb, wred_prob,
                       wred_drop_display, zone, tag))
        if reasons:
            st.log("         -> {}".format(', '.join(reasons)))
        prev_wred_prob = wred_prob
    st.log(sep)
    if fanin:
        st.log("  Port A/B = per-port IXIA rate (each 100G ingress port)")
        st.log("  Rate%    = combined rate (Port A + Port B) as % of egress")
    st.log("  Avg Depth = mid-traffic queue depth (average of sampled snapshots)")
    st.log("  Est. Prob  = estimated WRED probability from avg queue depth:")
    st.log("               {}% x (depth - {:.0f}MB) / ({:.0f}MB - {:.0f}MB), "
           "capped at 100%".format(int(max_prob), min_th_mb, max_th_mb, min_th_mb))
    st.log("  WRED Drop  = WRED drop probability")
    st.log("               Zone A/B: from DCHAL drop_pkts / (tx + drop) x 100")
    st.log("               Zone C: 100% (tail drop confirmed when ALL depth")
    st.log("               samples > max_th AND peak watermark >= max_th)")
    st.log("  C* = Zone C with DCHAL counters re-baselined mid-traffic")
    st.log("       (Zone A/B ramp-up drops excluded from measurement)")
    st.log("  WRED profile: AZURE_LOSSY (from config_db.json)")
    st.log("    green_min_threshold = {} bytes ({:.2f} MB)".format(
        min_th_bytes, min_th_mb))
    st.log("    green_max_threshold = {} bytes ({:.2f} MB)".format(
        max_th_bytes, max_th_mb))
    st.log("    green_drop_probability = {}%".format(int(max_prob)))
    st.log("  Zone A: depth < {:.0f}MB (below min_th, no WRED drops)".format(min_th_mb))
    st.log("  Zone B: {:.0f}MB <= depth <= {:.0f}MB (WRED active, "
           "prob 0-{}%)".format(min_th_mb, max_th_mb, int(max_prob)))
    st.log("  Zone C: depth > {:.0f}MB (above max_th, tail drop)".format(max_th_mb))
    st.log("  Status: PASS when Est. Prob follows WRED curve and")
    st.log("          WRED Drop confirms actual ASIC drops")
    st.log(sep)

    if not any_drops:
        st.log("  WRED NOT ACTIVE: all WRED Drop rates are 0% — "
               "check port state and WRED config")
        all_passed = False
    elif all_passed:
        st.log("  Zone validation: PASSED (Est. Prob follows WRED curve, "
               "WRED Drop confirms actual drops)")
    else:
        st.log("  Zone validation: FAILED")
    st.log(sep)

    if any_drops and len(data_points) >= 3:
        _print_wred_diagrams(data_points, egr_spd, wred_profile=wred_profile)

    return all_passed


def run_wred_linearity(ctx, af, margins, verify_egress_neighbor_fn,
                       duration=20, num_depth_samples=3, cooldown=5,
                       wred_profile=GOLDEN_WRED_PROFILE):
    """Run a full WRED linearity sweep and return (fail_msgs, data_points).

    Orchestrates config verification, neighbor resolution, fan-in traffic
    at each margin point, monotonicity checking, and per-point sanity
    validation.  Designed for reuse across multiple WRED linearity tests.

    Parameters:
        ctx: shared WRED context dict (dut, tg, port handles, speeds, etc.)
        af: address family — 'ipv4' or 'ipv6'
        margins: list of margin values in Mbps to sweep (e.g.
            [0, 250, 500, 1000, 2000, 3000, 4000, 5000, 5250, 5500])
        verify_egress_neighbor_fn: callable(af) -> bool that checks
            ARP/NDP resolution for the egress next-hop.  Test modules
            supply their own since the target IP is test-specific.
        duration: seconds to send traffic per margin point (default 20)
        num_depth_samples: number of mid-traffic ASIC queue depth
            snapshots per margin point (default 3)
        cooldown: seconds to wait between margin points for the queue
            to drain (default 5)
        wred_profile: optional dict with green_min_threshold,
            green_max_threshold, and green_drop_probability keys
            (string values).  Defaults to GOLDEN_WRED_PROFILE when None.

    Returns:
        (fail_msgs, data_points) where:
          fail_msgs — list of failure description strings (empty on success)
          data_points — list of per-margin measurement dicts from
                        wred_fanin_send_and_measure()
    """
    _dut = ctx['dut']
    egress_speed_mbps = ctx['egress_speed_mbps']
    fail_msgs = []

    st.log("Phase 1: Verifying WRED config")
    verify_wred_config(ctx, fail_msgs, wred_profile=wred_profile)
    deploy_dchal_helper(_dut)
    if fail_msgs:
        return fail_msgs, []

    if not verify_egress_neighbor_fn(af):
        fail_msgs.append(
            'Egress neighbor resolution failed for {}'.format(af))
        return fail_msgs, []

    st.log("Phase 2: Running {} margin points".format(len(margins)))
    data_points = []
    for m in margins:
        st.log("--- Margin {}M ---".format(m))
        r = wred_fanin_send_and_measure(ctx, af, m, duration=duration,
                                        num_depth_samples=num_depth_samples)
        report_wred_result(ctx, r, "LINEARITY point {}M".format(m))
        data_points.append(r)
        st.wait(cooldown)

    monotonic = report_wred_linearity(data_points, egress_speed_mbps,
                                      wred_profile=wred_profile)

    if not monotonic:
        fail_msgs.append("Drop rates are NOT monotonically increasing")

    for dp in data_points:
        if dp['egress_pkts'] <= 0:
            fail_msgs.append("Margin={}M: egress_pkts=0 — traffic not "
                             "forwarded".format(dp['margin_mbps']))
        if dp['margin_mbps'] > 0 and dp['drop_pkts'] <= 0:
            fail_msgs.append("Margin={}M: 0 drops — WRED not active".format(
                dp['margin_mbps']))

    return fail_msgs, data_points


def _print_wred_diagrams(data_points, egr_spd, wred_profile=GOLDEN_WRED_PROFILE):
    """Print ASCII diagrams: WRED prob vs margin, WRED prob vs queue depth.

    Each data point is plotted as '* <label>' where label shows the
    margin or depth value for easy identification.

    WRED prob is computed from measured queue depth:
      prob = max_prob * (depth - min_th) / (max_th - min_th)
    This shows the actual WRED drop probability the ASIC applied,
    rather than the overall measured drop rate.

    *wred_profile* is an optional dict with threshold/probability keys.
      Defaults to GOLDEN_WRED_PROFILE when None.
    """
    sep = "=" * 78
    min_th_bytes = int(wred_profile.get('green_min_threshold', '1048576'))
    max_th_bytes = int(wred_profile.get('green_max_threshold', '3145728'))
    max_prob = float(wred_profile.get('green_drop_probability', '5'))
    min_th_mb = min_th_bytes / (1024.0 * 1024)
    max_th_mb = max_th_bytes / (1024.0 * 1024)
    sorted_pts = sorted(data_points, key=lambda d: d['margin_mbps'])

    def _avg_depth(dp):
        samples = dp.get('depth_samples', [])
        if samples:
            return sum(samples) / len(samples)
        return dp['q_depth_bytes']

    def _wred_prob(dp):
        depth_mb = _avg_depth(dp) / (1024.0 * 1024)
        if depth_mb <= min_th_mb:
            return 0.0
        elif depth_mb >= max_th_mb:
            return max_prob
        return max_prob * (depth_mb - min_th_mb) / (max_th_mb - min_th_mb)

    st.log("")
    st.log(sep)
    st.log("  WRED Prob (%) vs Margin (Mbps)")
    st.log(sep)
    max_wp = max(_wred_prob(dp) for dp in sorted_pts)
    if max_wp <= 0:
        max_wp = max(dp['drop_rate_pct'] for dp in sorted_pts)
    if max_wp > 0:
        for dp in reversed(sorted_pts):
            wp = _wred_prob(dp)
            margin = dp['margin_mbps']
            bar_len = int(wp / max_wp * 50) if max_wp > 0 else 0
            bar = '.' * bar_len + '*'
            st.log("  {:>5.2f}% |{:<52s} {:>4}M".format(
                wp, bar, margin))
        st.log("         +" + "-" * 55 + ">")
        st.log("         0%{:>50s}".format("{:.1f}%".format(max_wp)))
        st.log("                        WRED Prob (actual)")
    st.log(sep)

    st.log("")
    st.log(sep)
    st.log("  WRED Prob (%) vs Queue Depth (MB)")
    st.log(sep)
    if max_wp > 0:
        for dp in reversed(sorted_pts):
            wp = _wred_prob(dp)
            depth_mb = _avg_depth(dp) / (1024.0 * 1024)
            bar_len = int(wp / max_wp * 50) if max_wp > 0 else 0
            bar = '.' * bar_len + '*'
            st.log("  {:>5.2f}% |{:<52s} {:.2f}MB".format(
                wp, bar, depth_mb))
        st.log("         +" + "-" * 55 + ">")
        st.log("         0%{:>50s}".format("{:.1f}%".format(max_wp)))
        st.log("                        WRED Prob (actual)")
        st.log("")
        st.log("  Avg Queue Depth (MB) vs WRED Prob (%) — measured WRED curve")
        st.log("  " + "-" * 72)
        for dp in sorted_pts:
            wp = _wred_prob(dp)
            depth_mb = _avg_depth(dp) / (1024.0 * 1024)
            bar_len = int(depth_mb / 4.0 * 50)
            bar = '.' * bar_len + '*'
            zone = 'A' if depth_mb < min_th_mb else (
                'C' if depth_mb > max_th_mb else 'B')
            st.log("  {:>5.2f}% |{:<52s} {:.2f}MB [{}]".format(
                wp, bar, depth_mb, zone))
        st.log("         +" + "-" * 55 + ">")
        st.log("         0MB       {:.0f}MB                    {:.0f}MB       4MB".format(
            min_th_mb, max_th_mb))
        st.log("                    |                      |")
        st.log("                  min_th                max_th")
        st.log("                  ({}B)              ({}B)".format(
            min_th_bytes, max_th_bytes))
        st.log("                        Avg Queue Depth")
    st.log(sep)


# ═══════════════════════════════════════════════════════════════════════════
# Reusable WRED / rate-computation helpers (ctx-based)
#
# All functions below accept a *ctx* dict built by the test fixture.
# Required ctx keys (vary by function — each docstring lists its needs):
#   dut, tg, tg_ph_ingress, port_info,
#   ingress_speed_mbps, egress_speed_mbps,
#   target_queue, target_dscp, router_mac,
#   pkt_size, num_queues,
#   wred_min_th, wred_max_th, wred_max_prob,
#   wred_tolerance, wred_duration, wred_settle_time,
#   ips  (dict: v4_src, v4_dst, v4_gw, v4_mask,
#               v6_src, v6_dst, v6_gw, v6_prefix_len)
# ═══════════════════════════════════════════════════════════════════════════


def get_dut2_mac(dut_handle, peer_ip):
    """Read a peer MAC from the DUT ARP table by IP address."""
    output = st.show(dut_handle, "show arp", skip_tmpl=True)
    for line in output.splitlines():
        if peer_ip in line:
            cols = line.split()
            for col in cols:
                if ':' in col and len(col) == 17:
                    return col
    return None


def compute_rate_pct(ctx, margin_mbps):
    """Return IXIA rate_percent to achieve (egress_speed + margin) on ingress.

    ctx keys: ingress_speed_mbps, egress_speed_mbps
    Clamped to [0.1, 99.0] to stay within IXIA safe operating range.
    """
    ingress = ctx['ingress_speed_mbps']
    egress = ctx['egress_speed_mbps']
    if ingress == 0 or egress == 0:
        st.warn("port speed unknown (ingress={}M, egress={}M) — "
                "defaulting to 11% rate".format(ingress, egress))
        return 11.0
    target = egress + margin_mbps
    rate = target / ingress * 100
    if rate > 99.0:
        st.warn("compute_rate_pct: {:.2f}% exceeds 99% — clamping".format(rate))
        rate = 99.0
    return max(0.1, rate)


_BASELINE_EGRESS_MBPS = 100000  # reference speed margins are authored for


def scale_margin(margin_mbps, egress_speed_mbps):
    """Scale an absolute margin proportionally to egress speed.

    All WRED margin values (250, 500, 1000 ... Mbps) are authored for a
    100 GbE egress.  On slower links (e.g. 25G breakout) the same absolute
    margin would produce a much larger *proportional* overshoot, pushing the
    queue out of the intended WRED zone.

    Scaling keeps the overshoot ratio constant::

        effective = margin * egress_speed / 100G

    Examples (margin=2000M):
        100G egress -> 2000M  (2.0% excess)
         25G egress ->  500M  (2.0% excess)
    """
    if egress_speed_mbps == _BASELINE_EGRESS_MBPS or egress_speed_mbps <= 0:
        return margin_mbps
    return int(round(margin_mbps * egress_speed_mbps / _BASELINE_EGRESS_MBPS))


def compute_fanin_rate_pct(ctx, margin_mbps):
    """Return per-port IXIA rate_percent for fan-in WRED test.

    Total target = egress_speed + margin, split evenly across ingress ports.
    The margin is used as-is — callers should pre-scale with ``scale_margin``
    when the margin was authored for a different egress speed.
    ctx keys: ingress_speed_mbps, egress_speed_mbps, num_ingress_ports
    Clamped to [0.1, 99.0] to stay within IXIA safe operating range.
    """
    ingress = ctx['ingress_speed_mbps']
    egress = ctx['egress_speed_mbps']
    num_ports = ctx.get('num_ingress_ports', 2)
    if ingress == 0 or egress == 0:
        st.warn("port speed unknown (ingress={}M, egress={}M) — "
                "defaulting to 50% rate".format(ingress, egress))
        return 50.0
    target_total = egress + margin_mbps
    per_port = target_total / float(num_ports)
    rate = per_port / ingress * 100
    if rate > 99.0:
        st.warn("compute_fanin_rate_pct: {:.2f}% exceeds 99% — "
                "clamping".format(rate))
        rate = 99.0
    return max(0.1, rate)


def compute_dwrr_rate_pct(ctx, oversub_ratio=1.28):
    """Return per-stream rate_percent that produces *exactly* ``oversub_ratio``
    total offered load relative to egress capacity.

    Formula::

        rate = oversub_ratio * egress / (num_queues * num_ingress_ports * ingress) * 100

    Baseline: 2×100 G ingress → 100 G egress, 8 queues, 1.28× → 8 % per stream.
    Breakout: 1×100 G ingress →  25 G egress, 8 queues, 1.28× → 4 % per stream.

    ctx keys: ingress_speed_mbps, egress_speed_mbps, num_queues, num_ingress_ports
    """
    ingress = ctx['ingress_speed_mbps']
    egress = ctx['egress_speed_mbps']
    nq = ctx['num_queues']
    num_ports = ctx.get('num_ingress_ports', 1)
    if ingress == 0 or egress == 0:
        st.warn("Port speeds unknown — defaulting to 8% per stream")
        return 8.0
    target_total = egress * oversub_ratio
    per_stream = target_total / (nq * num_ports)
    rate = per_stream / ingress * 100
    st.log("compute_dwrr_rate_pct: oversub={:.2f}x  egress={}M  "
           "{} port(s) @ {}M ingress  {} queues  -> {:.2f}% per stream".format(
               oversub_ratio, egress, num_ports, ingress, nq, rate))
    return rate


def compute_single_queue_rate_pct(ctx, oversub_ratio=1.50):
    """Return per-port rate_percent for single-queue congestion (e.g. WRED).

    Same principle as :func:`compute_dwrr_rate_pct` but with exactly one
    stream per ingress port (all targeting the same queue).

    Baseline: 2×100 G → 100 G, 1.50× → 75 % per port.
    Breakout: 1×100 G →  25 G, 1.50× → 37.5 % per port.

    ctx keys: ingress_speed_mbps, egress_speed_mbps, num_ingress_ports
    Clamped to [0.1, 99.0] to stay within IXIA safe operating range.
    """
    ingress = ctx['ingress_speed_mbps']
    egress = ctx['egress_speed_mbps']
    num_ports = ctx.get('num_ingress_ports', 1)
    if ingress == 0 or egress == 0:
        st.warn("Port speeds unknown — defaulting to 75% per stream")
        return 75.0
    target_total = egress * oversub_ratio
    per_port = target_total / num_ports
    rate = per_port / ingress * 100
    st.log("compute_single_queue_rate_pct: oversub={:.2f}x  egress={}M  "
           "{} port(s) @ {}M ingress  -> {:.2f}% per port".format(
               oversub_ratio, egress, num_ports, ingress, rate))
    if rate > 99.0:
        st.warn("compute_single_queue_rate_pct: {:.2f}% exceeds 99% — "
                "clamping".format(rate))
        rate = 99.0
    return max(0.1, rate)


def resolve_ingress_neighbor(ctx, af):
    """Ensure DUT ARP/NDP table has the IXIA ingress IP resolved.

    ctx keys: dut, tg, tg_ph_ingress, ips
    Returns True on success, False on failure (calls dump_l3_diag).
    """
    _dut = ctx['dut']
    _tg = ctx['tg']
    _ph = ctx['tg_ph_ingress']
    ips = ctx['ips']

    if af == "ipv6":
        nb_cmd, ping_cmd = 'show ndp', 'ping6'
        target_ip = ips['v6_src']
        gw = ips['v6_gw']
        prefix_len = ips['v6_prefix_len']
    else:
        nb_cmd, ping_cmd = 'show arp', 'ping'
        target_ip = ips['v4_src']
        gw = ips['v4_gw']
        mask = ips['v4_mask']

    for _attempt in range(1, 4):
        nb_out = st.show(_dut, "{} {}".format(nb_cmd, target_ip),
                         skip_tmpl=True)
        if target_ip in nb_out:
            st.log("{} resolved for {} (attempt {})".format(
                nb_cmd.upper(), target_ip, _attempt))
            return True
        st.log("{} for {} not resolved (attempt {}); re-triggering".format(
            nb_cmd.upper(), target_ip, _attempt))
        try:
            if af == "ipv6":
                _tg.tg_interface_config(
                    mode='config', port_handle=_ph,
                    ipv6_intf_addr=target_ip,
                    ipv6_prefix_length=prefix_len,
                    ipv6_gateway=gw,
                    ipv6_resolve_gateway_mac=1, arp_send_req=1)
            else:
                _tg.tg_interface_config(
                    mode='config', port_handle=_ph,
                    intf_ip_addr=target_ip, netmask=mask,
                    gateway=gw,
                    arp_send_req=1, enable_ping_response=1,
                    resolve_gateway_mac=1)
        except Exception as _e:
            st.log("  tg_interface_config re-trigger failed: {}".format(_e))
        st.wait(10)
        st.config(_dut, "{} -c 3 -W 2 {}".format(ping_cmd, target_ip),
                  skip_error_check=True)
        st.wait(3)

    dump_l3_diag(_dut, target_ip)
    return False


def verify_wred_config(ctx, fail_msgs, wred_profile=None):
    """Phase 1 common: verify WRED profile, queue binding, ASIC AQM, variance.

    ctx keys: dut, port_info, target_queue, wred_max_prob
    Also uses module-level: GOLDEN_WRED_PROFILE, TORTUGA_CONFIG, WRED_BOUND_QUEUES
    """
    if wred_profile is None:
        wred_profile = GOLDEN_WRED_PROFILE
    _dut = ctx['dut']
    egress = ctx['port_info']['egress']
    tq = ctx['target_queue']
    sep = "=" * 70

    verify_wred_profile(_dut, fail_msgs, wred_profile=wred_profile)

    if tq not in WRED_BOUND_QUEUES:
        fail_msgs.append("Q{} is not in WRED_BOUND_QUEUES {}".format(
            tq, list(WRED_BOUND_QUEUES)))
    else:
        st.log("  Q{} is in WRED_BOUND_QUEUES — OK".format(tq))

    q_wred = st.show(
        _dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "wred_profile"'.format(
            egress, tq),
        skip_tmpl=True)
    q_wred_str = str(q_wred).strip() if q_wred else ''
    if 'AZURE_LOSSY' not in q_wred_str:
        fail_msgs.append("Q{} wred_profile='{}', expected AZURE_LOSSY".format(
            tq, q_wred_str))
    else:
        st.log("  Q{} wred_profile=AZURE_LOSSY — OK".format(tq))

    stype, weight = TORTUGA_CONFIG[tq]
    st.log(sep)
    st.log("  TARGET QUEUE CONTEXT")
    st.log(sep)
    st.log("  Queue:      Q{}".format(tq))
    st.log("  DSCP:       {}".format(ctx['target_dscp']))
    st.log("  Scheduler:  {} (weight={})".format(
        stype, weight if weight else 'N/A'))
    st.log("  WRED:       AZURE_LOSSY (min={}B, max={}B, drop_prob={}%)".format(
        wred_profile.get('green_min_threshold', '?'),
        wred_profile.get('green_max_threshold', '?'),
        wred_profile.get('green_drop_probability', '?')))
    st.log(sep)

    aqm_data = dchal_aqm_hw_info(_dut, egress)
    report_aqm_hw_info(aqm_data, fail_msgs)
    if aqm_data:
        drop_en = aqm_data.get('drop_en', [0]*8)
        prob_cfg = aqm_data.get('max_prob_cfg', [0]*8)
        ecn_en = aqm_data.get('ecn_enable', [0]*8)
        hw_min = aqm_data.get('min_thr', [0]*8)[tq]
        hw_max = aqm_data.get('max_thr', [0]*8)[tq]

        if drop_en[tq] != 1:
            fail_msgs.append(
                "AQM Q{} drop_en={} — expected 1 (WRED enabled)".format(
                    tq, drop_en[tq]))
        if prob_cfg[tq] != ctx['wred_max_prob']:
            st.warn("AQM Q{} max_prob_cfg={}% — expected {}% "
                     "(HW rounding may differ)".format(
                         tq, prob_cfg[tq], ctx['wred_max_prob']))
        if ecn_en[tq] != 0:
            fail_msgs.append(
                "AQM Q{} ecn_enable={} — expected 0 (ecn_none)".format(
                    tq, ecn_en[tq]))

        exp_min_bytes = int(wred_profile.get(
            'green_min_threshold', '1048576'))
        exp_max_bytes = int(wred_profile.get(
            'green_max_threshold', '3145728'))

        st.log("  AQM Q{} min_thr: HW={} (config={}B={:.2f}MB)".format(
            tq, hw_min, exp_min_bytes,
            exp_min_bytes / (1024.0 * 1024)))
        st.log("  AQM Q{} max_thr: HW={} (config={}B={:.2f}MB)".format(
            tq, hw_max, exp_max_bytes,
            exp_max_bytes / (1024.0 * 1024)))

        if hw_min <= 0:
            fail_msgs.append(
                "AQM Q{} min_thr=0 — WRED min threshold not "
                "programmed in HW".format(tq))
        if hw_max <= 0:
            fail_msgs.append(
                "AQM Q{} max_thr=0 — WRED max threshold not "
                "programmed in HW".format(tq))
        if hw_min > 0 and hw_max > 0:
            exp_ratio = float(exp_max_bytes) / exp_min_bytes
            hw_ratio = float(hw_max) / hw_min
            st.log("  AQM Q{} threshold ratio: HW={:.2f} expected={:.2f} "
                   "(max/min)".format(tq, hw_ratio, exp_ratio))
            if abs(hw_ratio - exp_ratio) > 0.5:
                fail_msgs.append(
                    "AQM Q{} threshold ratio HW={:.2f} vs "
                    "expected={:.2f} — mismatch".format(
                        tq, hw_ratio, exp_ratio))

    variance = dchal_wred_variance(_dut)
    report_wred_variance(variance, fail_msgs)


def wred_send_and_measure(ctx, af, margin_mbps, duration=None,
                          num_depth_samples=10):
    """Send single-stream traffic to target queue and measure WRED behavior.

    ctx keys: dut, tg, tg_ph_ingress, port_info,
              ingress_speed_mbps, egress_speed_mbps,
              target_queue, target_dscp, router_mac,
              pkt_size, num_queues, wred_duration, wred_settle_time, ips

    Returns dict with: margin_mbps, rate_pct, q_depth_bytes, depth_samples,
      peak_cells, peak_bytes, egress_pkts, drop_pkts, total_pkts,
      drop_rate_pct, all_queues
    """
    _dut = ctx['dut']
    _tg = ctx['tg']
    _ph = ctx['tg_ph_ingress']
    egress = ctx['port_info']['egress']
    tq = ctx['target_queue']
    td = ctx['target_dscp']
    mac = ctx['router_mac']
    pkt_sz = ctx['pkt_size']
    nq = ctx['num_queues']
    settle = ctx['wred_settle_time']
    ips = ctx['ips']

    if duration is None:
        duration = ctx['wred_duration']
    rate_pct = compute_rate_pct(ctx, margin_mbps)

    if af == "ipv6":
        src_ip, dst_ip = ips['v6_src'], ips['v6_dst']
    else:
        src_ip, dst_ip = ips['v4_src'], ips['v4_dst']

    st.log("DUT1 router MAC (mac_dst for IXIA): {}".format(mac))

    clear_dut_counters(_dut)
    dchal_clear_counters(_dut, egress)
    intf_before = get_intf_counters(_dut, ctx['port_info'].values())
    q_before = get_dchal_queue_counters(_dut, egress,
                                        label="BEFORE WRED traffic")

    _tg.tg_traffic_control(action='clear_stats')
    if af == "ipv6":
        tc_val = td << 2
        result = _tg.tg_traffic_config(
            mode='create', port_handle=_ph,
            l3_protocol='ipv6',
            ipv6_src_addr=src_ip, ipv6_dst_addr=dst_ip,
            mac_dst=mac,
            ipv6_traffic_class=tc_val, ipv6_hop_limit=64,
            frame_size=pkt_sz, rate_percent=rate_pct,
            transmit_mode='continuous', high_speed_result_analysis=0)
    else:
        result = _tg.tg_traffic_config(
            mode='create', port_handle=_ph,
            l3_protocol='ipv4', l4_protocol='icmp',
            ip_src_addr=src_ip, ip_dst_addr=dst_ip,
            mac_dst=mac,
            ip_dscp=td, ip_ttl=64,
            frame_size=pkt_sz, rate_percent=rate_pct,
            transmit_mode='continuous', high_speed_result_analysis=0)

    stream_id = result.get('stream_id', 'UNKNOWN')
    st.log("  stream_id={} Q{} DSCP={} rate={:.3f}%".format(
        stream_id, tq, td, rate_pct))

    st.log("Starting traffic for {} seconds ...".format(duration))
    _tg.tg_traffic_control(action='apply')
    _tg.tg_traffic_control(action='run')

    max_th = ctx.get('wred_max_th', 3145728)
    depth_samples = []
    q_depth = 0
    rebaselined = False
    try:
        st.wait(settle)

        sample_interval = 1
        dchal_cmd_time = 2
        for i in range(1, num_depth_samples + 1):
            dm = get_mid_traffic_depth(_dut, egress)
            d = dm.get(tq, 0)
            depth_samples.append(d)
            st.log("  Depth sample {}/{}: Q{} = {:,} bytes "
                   "({:.2f} MB)".format(i, num_depth_samples, tq,
                                        d, d / (1024.0 * 1024)))

            if i == 1 and d > max_th:
                st.log("  Queue in Zone C (>{:,}B) — re-baselining "
                       "DCHAL counters to exclude Zone A/B ramp-up".format(
                           max_th))
                dchal_clear_counters(_dut, egress)
                q_before = get_dchal_queue_counters(
                    _dut, egress, label="RE-BASELINE (Zone C only)")
                rebaselined = True

            if i < num_depth_samples:
                st.wait(sample_interval)

        q_depth = max(depth_samples) if depth_samples else 0
        avg_depth = (sum(depth_samples) / len(depth_samples)) \
            if depth_samples else 0
        st.log("  Depth trajectory: {}".format(
            ', '.join('{:,}'.format(s) for s in depth_samples)))
        st.log("  Q{} depth — max: {:,} bytes ({:.2f} MB), "
               "avg: {:,} bytes ({:.2f} MB){}".format(
                   tq,
                   q_depth, q_depth / (1024.0 * 1024),
                   int(avg_depth), avg_depth / (1024.0 * 1024),
                   " [re-baselined for Zone C]" if rebaselined else ""))

        aqm_mid = dchal_aqm_hw_info(_dut, egress)
        if aqm_mid:
            aqm_depth = aqm_mid.get('q_depth', [0]*8)[tq]
            aqm_mfair = aqm_mid.get('mfair', [0]*8)[tq]
            aqm_qold = aqm_mid.get('qold', [0]*8)[tq]
            st.log("  AQM mid-traffic Q{}: depth_cells={}, mfair={}, "
                   "qold={}".format(tq, aqm_depth, aqm_mfair, aqm_qold))

        elapsed = (settle
                   + num_depth_samples * dchal_cmd_time
                   + (num_depth_samples - 1) * sample_interval
                   + dchal_cmd_time)
        remaining = duration - elapsed
        if remaining > 0:
            st.wait(remaining)
        else:
            st.log("  (sampling took ~{}s, exceeding {}s duration — "
                   "traffic already ran long enough)".format(
                       elapsed, duration))
    finally:
        try:
            _tg.tg_traffic_control(action='stop')
        except Exception:
            pass
        st.wait(2)

    q_after = get_dchal_queue_counters(_dut, egress,
                                       label="AFTER WRED traffic")
    intf_after = get_intf_counters(_dut, ctx['port_info'].values())
    peak_data = dchal_peak_stats(_dut, egress, label="WRED peak watermarks")
    report_peak_stats(peak_data, target_queue=tq)

    try:
        _tg.tg_traffic_config(mode='remove', stream_id=stream_id)
    except Exception:
        pass

    report_intf_counters(ctx['port_info'], intf_before, intf_after)

    q_deltas = {}
    q_drop_deltas = {}
    all_queues = {}
    for qi in range(nq):
        eg = (q_after.get(qi, {}).get('pkts', 0)
              - q_before.get(qi, {}).get('pkts', 0))
        dr = (q_after.get(qi, {}).get('drop_pkts', 0)
              - q_before.get(qi, {}).get('drop_pkts', 0))
        q_deltas[qi] = eg
        q_drop_deltas[qi] = dr
        all_queues[qi] = {'egress': eg, 'drops': dr}

    report_queue_counters(egress, q_deltas, q_drop_deltas,
                          nq, source="DCHAL")

    q1_egress = q_deltas.get(tq, 0)
    q1_drops = q_drop_deltas.get(tq, 0)
    q1_total = q1_egress + q1_drops
    drop_rate = (q1_drops / q1_total * 100) if q1_total > 0 else 0.0

    peak_cells = 0
    peak_bytes = 0
    if peak_data:
        peak_cells = peak_data['uc_peak'][tq]
        peak_bytes = peak_cells * _CELL_SIZE

    return {
        'margin_mbps':    margin_mbps,
        'rate_pct':       rate_pct,
        'q_depth_bytes':  q_depth,
        'depth_samples':  depth_samples,
        'peak_cells':     peak_cells,
        'peak_bytes':     peak_bytes,
        'egress_pkts':    q1_egress,
        'drop_pkts':      q1_drops,
        'total_pkts':     q1_total,
        'drop_rate_pct':  drop_rate,
        'all_queues':     all_queues,
        'rebaselined':    rebaselined,
    }


def wred_fanin_send_and_measure(ctx, af, margin_mbps, duration=None,
                                num_depth_samples=10):
    """Send fan-in traffic from ingress port(s) and measure WRED behavior.

    Creates one stream per ingress port, each at the per-port share of the
    total desired rate.  Supports 1-port (breakout) or 2-port fan-in.

    ctx keys: dut, tg, tg_ph_ingress_a, tg_ph_ingress_b (may be None),
              port_info, ingress_speed_mbps, egress_speed_mbps,
              num_ingress_ports, target_queue, target_dscp, router_mac,
              pkt_size, num_queues, wred_duration, wred_settle_time,
              ips  (v4_src_a, v4_src_b, v4_dst, v6_src_a, v6_src_b, v6_dst, ...)

    Returns same dict shape as wred_send_and_measure.
    """
    _dut = ctx['dut']
    _tg = ctx['tg']
    _ph_a = ctx['tg_ph_ingress_a']
    _ph_b = ctx.get('tg_ph_ingress_b')
    egress = ctx['port_info']['egress']
    tq = ctx['target_queue']
    td = ctx['target_dscp']
    mac = ctx['router_mac']
    pkt_sz = ctx['pkt_size']
    nq = ctx['num_queues']
    settle = ctx['wred_settle_time']
    ips = ctx['ips']

    if duration is None:
        duration = ctx['wred_duration']
    rate_pct = compute_fanin_rate_pct(ctx, margin_mbps)

    if af == "ipv6":
        src_a, src_b = ips['v6_src_a'], ips['v6_src_b']
        dst_ip = ips['v6_dst']
    else:
        src_a, src_b = ips['v4_src_a'], ips['v4_src_b']
        dst_ip = ips['v4_dst']

    streams_spec = [('A', _ph_a, src_a)]
    if _ph_b is not None:
        streams_spec.append(('B', _ph_b, src_b))

    num_streams = len(streams_spec)
    st.log("DUT router MAC (mac_dst for IXIA): {}".format(mac))
    st.log("Fan-in: {} stream(s) x {:.3f}% = {:.3f}% total toward {}".format(
        num_streams, rate_pct, rate_pct * num_streams, egress))

    clear_dut_counters(_dut)
    dchal_clear_counters(_dut, egress)
    intf_before = get_intf_counters(_dut, ctx['port_info'].values())
    q_before = get_dchal_queue_counters(_dut, egress,
                                        label="BEFORE WRED fan-in traffic")

    _tg.tg_traffic_control(action='clear_stats')

    stream_ids = []
    for label, ph, src_ip in streams_spec:
        if af == "ipv6":
            tc_val = td << 2
            result = _tg.tg_traffic_config(
                mode='create', port_handle=ph,
                l3_protocol='ipv6',
                ipv6_src_addr=src_ip, ipv6_dst_addr=dst_ip,
                mac_dst=mac,
                ipv6_traffic_class=tc_val, ipv6_hop_limit=64,
                frame_size=pkt_sz, rate_percent=rate_pct,
                transmit_mode='continuous', high_speed_result_analysis=0)
        else:
            result = _tg.tg_traffic_config(
                mode='create', port_handle=ph,
                l3_protocol='ipv4', l4_protocol='icmp',
                ip_src_addr=src_ip, ip_dst_addr=dst_ip,
                mac_dst=mac,
                ip_dscp=td, ip_ttl=64,
                frame_size=pkt_sz, rate_percent=rate_pct,
                transmit_mode='continuous', high_speed_result_analysis=0)
        sid = result.get('stream_id', 'UNKNOWN')
        stream_ids.append(sid)
        st.log("  stream_{} id={} Q{} DSCP={} rate={:.3f}%".format(
            label, sid, tq, td, rate_pct))

    max_th = ctx.get('wred_max_th', 3145728)
    st.log("Starting fan-in traffic for {} seconds ...".format(duration))
    _tg.tg_traffic_control(action='apply')
    _tg.tg_traffic_control(action='run')

    depth_samples = []
    q_depth = 0
    rebaselined = False
    try:
        st.wait(settle)

        sample_interval = 1
        dchal_cmd_time = 2
        for i in range(1, num_depth_samples + 1):
            dm = get_mid_traffic_depth(_dut, egress)
            d = dm.get(tq, 0)
            depth_samples.append(d)
            st.log("  Depth sample {}/{}: Q{} = {:,} bytes "
                   "({:.2f} MB)".format(i, num_depth_samples, tq,
                                        d, d / (1024.0 * 1024)))

            if i == 1 and d > max_th:
                st.log("  Queue in Zone C (>{:,}B) — re-baselining "
                       "DCHAL counters to exclude Zone A/B ramp-up".format(
                           max_th))
                dchal_clear_counters(_dut, egress)
                q_before = get_dchal_queue_counters(
                    _dut, egress, label="RE-BASELINE (Zone C only)")
                rebaselined = True

            if i < num_depth_samples:
                st.wait(sample_interval)

        q_depth = max(depth_samples) if depth_samples else 0
        avg_depth = (sum(depth_samples) / len(depth_samples)) \
            if depth_samples else 0
        st.log("  Depth trajectory: {}".format(
            ', '.join('{:,}'.format(s) for s in depth_samples)))
        st.log("  Q{} depth — max: {:,} bytes ({:.2f} MB), "
               "avg: {:,} bytes ({:.2f} MB){}".format(
                   tq,
                   q_depth, q_depth / (1024.0 * 1024),
                   int(avg_depth), avg_depth / (1024.0 * 1024),
                   " [re-baselined for Zone C]" if rebaselined else ""))

        aqm_mid = dchal_aqm_hw_info(_dut, egress)
        if aqm_mid:
            aqm_depth = aqm_mid.get('q_depth', [0]*8)[tq]
            aqm_mfair = aqm_mid.get('mfair', [0]*8)[tq]
            aqm_qold = aqm_mid.get('qold', [0]*8)[tq]
            st.log("  AQM mid-traffic Q{}: depth_cells={}, mfair={}, "
                   "qold={}".format(tq, aqm_depth, aqm_mfair, aqm_qold))

        elapsed = (settle
                   + num_depth_samples * dchal_cmd_time
                   + (num_depth_samples - 1) * sample_interval
                   + dchal_cmd_time)
        remaining = duration - elapsed
        if remaining > 0:
            st.wait(remaining)
        else:
            st.log("  (sampling took ~{}s, exceeding {}s duration — "
                   "traffic already ran long enough)".format(
                       elapsed, duration))
    finally:
        try:
            _tg.tg_traffic_control(action='stop')
        except Exception:
            pass
        st.wait(2)

    q_after = get_dchal_queue_counters(_dut, egress,
                                       label="AFTER WRED fan-in traffic")
    intf_after = get_intf_counters(_dut, ctx['port_info'].values())
    peak_data = dchal_peak_stats(_dut, egress, label="WRED peak watermarks")
    report_peak_stats(peak_data, target_queue=tq)

    for sid in stream_ids:
        try:
            _tg.tg_traffic_config(mode='remove', stream_id=sid)
        except Exception:
            pass

    report_intf_counters(ctx['port_info'], intf_before, intf_after)

    q_deltas = {}
    q_drop_deltas = {}
    all_queues = {}
    for qi in range(nq):
        eg = (q_after.get(qi, {}).get('pkts', 0)
              - q_before.get(qi, {}).get('pkts', 0))
        dr = (q_after.get(qi, {}).get('drop_pkts', 0)
              - q_before.get(qi, {}).get('drop_pkts', 0))
        q_deltas[qi] = eg
        q_drop_deltas[qi] = dr
        all_queues[qi] = {'egress': eg, 'drops': dr}

    report_queue_counters(egress, q_deltas, q_drop_deltas,
                          nq, source="DCHAL")

    q1_egress = q_deltas.get(tq, 0)
    q1_drops = q_drop_deltas.get(tq, 0)
    q1_total = q1_egress + q1_drops
    drop_rate = (q1_drops / q1_total * 100) if q1_total > 0 else 0.0

    peak_cells = 0
    peak_bytes = 0
    if peak_data:
        peak_cells = peak_data['uc_peak'][tq]
        peak_bytes = peak_cells * _CELL_SIZE

    return {
        'margin_mbps':    margin_mbps,
        'rate_pct':       rate_pct * num_streams,
        'rate_pct_per_port': rate_pct,
        'q_depth_bytes':  q_depth,
        'depth_samples':  depth_samples,
        'peak_cells':     peak_cells,
        'peak_bytes':     peak_bytes,
        'egress_pkts':    q1_egress,
        'drop_pkts':      q1_drops,
        'total_pkts':     q1_total,
        'drop_rate_pct':  drop_rate,
        'all_queues':     all_queues,
        'rebaselined':    rebaselined,
    }


def wred_fanin_start_continuous(ctx, af, margin_mbps):
    """Create and run fan-in traffic without stopping (for mid-traffic WRED tests).

    Two continuous streams (one per ingress port) at the same combined rate as
    :func:`wred_fanin_send_and_measure` for *margin_mbps*.  Does not clear DUT
    counters — the caller should do that before calling when a clean baseline
    is required.  Clears IXIA statistics before creating streams.

    Args:
        ctx: Same context dict as :func:`wred_fanin_send_and_measure`.
        af: ``\"ipv4\"`` or ``\"ipv6\"``.
        margin_mbps: Mbps above line rate (same semantics as fan-in measure).

    Returns:
        List of IXIA ``stream_id`` strings; pass to :func:`wred_fanin_stop_continuous`.
    """
    _tg = ctx['tg']
    _ph_a = ctx['tg_ph_ingress_a']
    _ph_b = ctx['tg_ph_ingress_b']
    egress = ctx['port_info']['egress']
    tq = ctx['target_queue']
    td = ctx['target_dscp']
    mac = ctx['router_mac']
    pkt_sz = ctx['pkt_size']
    ips = ctx['ips']

    rate_pct = compute_fanin_rate_pct(ctx, margin_mbps)

    if af == "ipv6":
        src_a, src_b = ips['v6_src_a'], ips['v6_src_b']
        dst_ip = ips['v6_dst']
    else:
        src_a, src_b = ips['v4_src_a'], ips['v4_src_b']
        dst_ip = ips['v4_dst']

    streams_spec = [('A', _ph_a, src_a)]
    if _ph_b is not None:
        streams_spec.append(('B', _ph_b, src_b))
    num_streams = len(streams_spec)

    st.log("wred_fanin_start_continuous: egress={} Q{} DSCP={} margin={} Mbps "
           "-> {:.3f}% per port ({:.3f}% combined, {} stream(s))".format(
               egress, tq, td, margin_mbps, rate_pct,
               rate_pct * num_streams, num_streams))

    _tg.tg_traffic_control(action='clear_stats')

    stream_ids = []
    for label, ph, src_ip in streams_spec:
        if af == "ipv6":
            tc_val = td << 2
            result = _tg.tg_traffic_config(
                mode='create', port_handle=ph,
                l3_protocol='ipv6',
                ipv6_src_addr=src_ip, ipv6_dst_addr=dst_ip,
                mac_dst=mac,
                ipv6_traffic_class=tc_val, ipv6_hop_limit=64,
                frame_size=pkt_sz, rate_percent=rate_pct,
                transmit_mode='continuous', high_speed_result_analysis=0)
        else:
            result = _tg.tg_traffic_config(
                mode='create', port_handle=ph,
                l3_protocol='ipv4', l4_protocol='icmp',
                ip_src_addr=src_ip, ip_dst_addr=dst_ip,
                mac_dst=mac,
                ip_dscp=td, ip_ttl=64,
                frame_size=pkt_sz, rate_percent=rate_pct,
                transmit_mode='continuous', high_speed_result_analysis=0)
        sid = result.get('stream_id', 'UNKNOWN')
        stream_ids.append(sid)
        st.log("  stream_{} id={} Q{} DSCP={} rate={:.3f}%".format(
            label, sid, tq, td, rate_pct))

    _tg.tg_traffic_control(action='apply')
    _tg.tg_traffic_control(action='run')
    return stream_ids


def wred_fanin_stop_continuous(tg, stream_ids):
    """Stop fan-in traffic and remove streams from *tg*.

    Safe to call with an empty *stream_ids* list.
    """
    if not stream_ids:
        return
    try:
        tg.tg_traffic_control(action='stop')
    except Exception:
        pass
    st.wait(2)
    for sid in stream_ids:
        try:
            tg.tg_traffic_config(mode='remove', stream_id=sid)
        except Exception:
            pass


def report_wred_result(ctx, results, zone_label):
    """Print a formatted WRED result summary for one measurement.

    ctx keys: target_queue, target_dscp, egress_speed_mbps,
              wred_min_th, wred_max_th
    """
    tq = ctx['target_queue']
    td = ctx['target_dscp']
    egr_spd = ctx['egress_speed_mbps']
    min_th = ctx['wred_min_th']
    max_th = ctx['wred_max_th']

    if egr_spd <= 0:
        egr_spd = 10000

    sep = "=" * 70
    stype, weight = TORTUGA_CONFIG[tq]
    st.log(sep)
    st.log("  WRED {} — Q{} (DSCP {}, {} wt={})".format(
        zone_label, tq, td,
        stype, weight if weight else 'N/A'))
    st.log(sep)
    samples = results.get('depth_samples', [])
    if samples:
        avg_depth = sum(samples) / len(samples)
    else:
        avg_depth = results['q_depth_bytes']
    depth = int(avg_depth)
    depth_mb = depth / (1024.0 * 1024)
    if depth == 0:
        measured_zone = "N/A (no depth data)"
    elif depth < min_th:
        measured_zone = "Zone A (below min, no WRED)"
    elif depth <= max_th:
        measured_zone = "Zone B (WRED active)"
    else:
        measured_zone = "Zone C (above max, tail drop)"
    expected = results['margin_mbps'] / (egr_spd + results['margin_mbps']) * 100
    samples_str = ', '.join('{:,}'.format(s) for s in samples) if samples else 'N/A'
    st.log("  Margin:           {:>14d} Mbps".format(results['margin_mbps']))
    st.log("  IXIA rate:        {:>14.3f}%".format(results['rate_pct']))
    st.log("  Q depth (mid):    {:>14,} bytes ({:.2f} MB)".format(
        depth, depth_mb))
    peak_bytes = results.get('peak_bytes', 0)
    peak_mb = peak_bytes / (1024.0 * 1024)
    if peak_bytes == 0:
        peak_zone = "N/A"
    elif peak_bytes < min_th:
        peak_zone = "Zone A (never entered WRED)"
    elif peak_bytes <= max_th:
        peak_zone = "Zone B (WRED managed peak)"
    else:
        peak_zone = "Zone C (hit tail drop)"
    st.log("  Measured zone:    {}".format(measured_zone))
    st.log("  Depth samples:    {}".format(samples_str))
    st.log("  Peak watermark:   {:>14,} bytes ({:.2f} MB)".format(
        peak_bytes, peak_mb))
    st.log("  Peak zone:        {}".format(peak_zone))
    st.log("  Egress packets:   {:>14,}".format(results['egress_pkts']))
    st.log("  Drop packets:     {:>14,}".format(results['drop_pkts']))
    st.log("  Total input:      {:>14,}".format(results['total_pkts']))
    st.log("  Drop rate:        {:>14.2f}%".format(results['drop_rate_pct']))
    st.log("  Expected rate:    {:>14.2f}% (based on {}M egress)".format(
        expected, egr_spd))
    st.log(sep)


def report_scheduler_validation(q_deltas, q_drop_deltas, fail_msgs):
    """Print SCHEDULER VALIDATION section.

    Calls validate_scheduler() internally.
    """
    sep = "=" * 70
    st.log(sep)
    st.log("  SCHEDULER VALIDATION")
    st.log(sep)
    st.log("  Tortuga config: Q0-Q2 DWRR w=20, Q3-Q4 w=40, "
           "Q5 w=30, Q6-Q7 STRICT")
    st.log("")
    validate_scheduler(q_deltas, q_drop_deltas, fail_msgs)


def dump_l3_diag(dut_handle, target_ip):
    """Dump ARP table, IP route, and interface status for troubleshooting.

    Called when ping or ARP resolution fails to provide root-cause context
    in the test log.
    """
    sep = "=" * 70
    st.log(sep)
    st.log("  L3 DIAGNOSTIC DUMP (target: {})".format(target_ip))
    st.log(sep)

    st.log("--- ARP table ---")
    st.show(dut_handle, "show arp", skip_tmpl=True)

    st.log("--- IP route to {} ---".format(target_ip))
    st.show(dut_handle, "show ip route {}".format(target_ip), skip_tmpl=True)

    st.log("--- Interface status ---")
    st.show(dut_handle, "show interfaces status", skip_tmpl=True)

    st.log("--- IP interfaces ---")
    st.show(dut_handle, "show ip interface", skip_tmpl=True)

    st.log(sep)


def report_end_to_end(total_ixia_tx, total_egress, ixia_rx,
                      rx_port_name=''):
    """Print End-to-end summary section."""
    rx_label = "IXIA RX"
    if rx_port_name:
        rx_label = "IXIA RX ({})".format(rx_port_name)
    st.log("")
    st.log("  End-to-end:")
    st.log("    Total IXIA TX:           {:>14,} pkts".format(total_ixia_tx))
    st.log("    DUT queue egress total:  {:>14,} pkts".format(total_egress))
    st.log("    {:<25}{:>14,} pkts".format(rx_label + ":", ixia_rx))


# ── Topology mode inference ────────────────────────────────────────────

def _infer_topo_mode():
    """Derive the QoS topology mode from the testbed YAML structure.

    Inspects the testbed *before* ``ensure_min_topology`` to determine the
    mode from the physical topology alone — no explicit ``qos_egress_mode``
    parameter is needed in the YAML.

    Detection logic:
      1. ``st.get_testbed_vars()`` — if ``D1D2P1`` exists, there is a
         DUT-to-DUT link (multi-DUT topology).
      2. ``st.get_breakout(D1)`` — if D1 has any breakout-annotated links
         the mode is ``breakout``; otherwise ``peer_link``.
      3. No D2 at all → ``ixia`` (single-DUT, all-IXIA egress).

    Returns:
        str: ``'ixia'``, ``'peer_link'``, or ``'breakout'``.
    """
    tb_preview = st.get_testbed_vars()
    has_dut2 = hasattr(tb_preview, 'D1D2P1')

    if has_dut2:
        breakout_list = st.get_breakout(tb_preview.D1)
        if breakout_list:
            mode = 'breakout'
        else:
            mode = 'peer_link'
    else:
        mode = 'ixia'

    st.log("_infer_topo_mode: detected mode='{}' (has_dut2={})".format(
        mode, has_dut2))
    return mode


# ── Shared topology setup ──────────────────────────────────────────────

def setup_topo_common(tgapi_module, target_queue):
    """Shared topology setup: DUT L3, IXIA interfaces, QoS baseline, WRED ctx.

    The topology mode is **inferred** from the testbed YAML structure by
    ``_infer_topo_mode()`` — no explicit parameter is needed:

      * ``ixia``      -- D1T1:3.  Egress is a 3rd IXIA port on dut1.
      * ``peer_link`` -- D1T1:2 + D1D2:1 + D2T1:1.  Egress is the peer
                         link to dut2; dut2 forwards to its IXIA port.
      * ``breakout``  -- D1T1:1 + D1D2:1 + D2T1:1.  Same as peer_link
                         but with a single IXIA ingress and the peer
                         port broken out (e.g. 4x25G).

    This is a generator (uses ``yield``), **not** a pytest fixture.  Each
    test module wraps it in its own ``@pytest.fixture`` to populate
    module-level globals.

    Args:
        tgapi_module: The ``tgapi`` module (``from spytest import tgapi``).
        target_queue: Queue index under test (e.g. 1 or 3).

    Yields:
        dict with keys ``dut``, ``tg``, ``tg_ph``, ``port_info``,
        ``port_speeds``, ``ingress_speed_mbps``, ``egress_speed_mbps``,
        ``wred_ctx``, ``tb_vars``, ``mode``.
    """
    mode = _infer_topo_mode()

    # ── Phase 1: Topology and port assignment ─────────────────────────────
    dut2 = None
    dut2_port_info = {}

    if mode == 'breakout':
        st.log("setup_topo: establishing topology D1T1:1 D1D2:1 D2T1:1")
        tb_dict = st.ensure_min_topology("D1T1:1", "D1D2:1", "D2T1:1")
        tb_vars = st.get_testbed_vars()
        dut = tb_dict.D1
        dut2 = tb_dict.D2

        parent_d1 = tb_vars.D1D2P1
        parent_d2 = tb_vars.D2D1P1

        for _dut, _parent, _label in [(dut, parent_d1, 'dut1'),
                                       (dut2, parent_d2, 'dut2')]:
            blist = st.get_breakout(_dut)
            for port, bmode in (blist or []):
                cli_mode = bmode if bmode.endswith('G') else bmode + 'G'
                st.log("setup_topo [breakout]: applying breakout {} "
                       "on {} port {}".format(cli_mode, _label, port))
                st.config(_dut,
                          'config interface breakout {} "{}" -yfl'.format(
                              port, cli_mode),
                          skip_error_check=True)
        st.wait(5)

        egress_sub = '{}_1'.format(parent_d1)
        peer_sub = '{}_1'.format(parent_d2)
        st.log("setup_topo [breakout]: sub-ports egress={} peer={}".format(
            egress_sub, peer_sub))

        st.config(dut, 'config interface startup {}'.format(egress_sub),
                  skip_error_check=True)
        st.config(dut2, 'config interface startup {}'.format(peer_sub),
                  skip_error_check=True)
        st.wait(5)

        port_info = {
            'ingress_a': tb_vars.D1T1P1,
            'egress':    egress_sub,
        }
        dut2_port_info = {
            'peer':  peer_sub,
            'egress_ixia': tb_vars.D2T1P1,
        }
        tg_handle, tg_ph_a = tgapi_module.get_handle_byname('T1D1P1')
        _, tg_ph_d2_e = tgapi_module.get_handle_byname('T1D2P1')
        tg = tg_handle
        tg_ph = {
            'ingress_a': tg_ph_a,
            'egress': tg_ph_d2_e,
            'egress_sink': tg_ph_d2_e,
        }
    elif mode == 'peer_link':
        d1t1_count = sum(1 for k in st.get_testbed_vars()
                         if k.startswith('D1T1P'))
        topo_args = ["D1T1:{}".format(d1t1_count), "D1D2:1", "D2T1:1"]
        st.log("setup_topo: establishing topology {}".format(
            " ".join(topo_args)))
        tb_dict = st.ensure_min_topology(*topo_args)
        tb_vars = st.get_testbed_vars()
        dut = tb_dict.D1
        dut2 = tb_dict.D2
        port_info = {
            'ingress_a': tb_vars.D1T1P1,
            'ingress_b': tb_vars.D1T1P2,
            'egress':    tb_vars.D1D2P1,
        }
        dut2_port_info = {
            'peer':  tb_vars.D2D1P1,
            'egress_ixia': tb_vars.D2T1P1,
        }
        tg_handle, tg_ph_a = tgapi_module.get_handle_byname('T1D1P1')
        _, tg_ph_b = tgapi_module.get_handle_byname('T1D1P2')
        _, tg_ph_d2_e = tgapi_module.get_handle_byname('T1D2P1')
        tg = tg_handle
        tg_ph = {
            'ingress_a': tg_ph_a,
            'ingress_b': tg_ph_b,
            'egress': tg_ph_d2_e,
            'egress_sink': tg_ph_d2_e,
        }
    else:
        st.log("setup_topo: establishing topology D1T1:3")
        tb_dict = st.ensure_min_topology("D1T1:3")
        tb_vars = st.get_testbed_vars()
        dut = tb_dict.D1
        port_info = {
            'ingress_a': tb_vars.D1T1P1,
            'ingress_b': tb_vars.D1T1P2,
            'egress':    tb_vars.D1T1P3,
        }
        tg_handle, tg_ph_a = tgapi_module.get_handle_byname('T1D1P1')
        _, tg_ph_b = tgapi_module.get_handle_byname('T1D1P2')
        _, tg_ph_e = tgapi_module.get_handle_byname('T1D1P3')
        tg = tg_handle
        tg_ph = {
            'ingress_a': tg_ph_a,
            'ingress_b': tg_ph_b,
            'egress': tg_ph_e,
        }

    st.log("setup_topo: mode={} ports={}".format(mode, port_info))
    if dut2_port_info:
        st.log("setup_topo: dut2 ports={}".format(dut2_port_info))

    # ── Phase 2: Interface preparation (both DUTs) ────────────────────────
    all_dut1_ports = list(port_info.values())
    ensure_interfaces_admin_up(dut, all_dut1_ports)

    missing = verify_queue_counters(dut, all_dut1_ports)
    if missing:
        st.warn("setup_topo: queue counters missing for: {}".format(missing))

    for intf in all_dut1_ports:
        remove_interface_from_all_memberships(dut, intf)

    if dut2:
        all_dut2_ports = list(dut2_port_info.values())
        ensure_interfaces_admin_up(dut2, all_dut2_ports)
        for intf in all_dut2_ports:
            remove_interface_from_all_memberships(dut2, intf)

    # ── Phase 3: Port speeds ──────────────────────────────────────────────
    raw_speeds = get_intf_speeds(dut, all_dut1_ports)
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

    ingress_speed_mbps = parse_speed_to_mbps(port_speeds.get('ingress_a', ''))
    egress_speed_mbps = parse_speed_to_mbps(port_speeds.get('egress', ''))
    st.log("setup_topo: ingress_speed={}M, egress_speed={}M".format(
        ingress_speed_mbps, egress_speed_mbps))

    # ── Phase 4: QoS reload ──────────────────────────────────────────────
    st.log("setup_topo: reloading QoS config on dut1")
    st.config(dut, "config qos reload", skip_error_check=True)
    st.wait(5)
    ensure_interfaces_admin_up(dut, all_dut1_ports)

    if dut2:
        st.log("setup_topo: reloading QoS config on dut2")
        st.config(dut2, "config qos reload", skip_error_check=True)
        st.wait(5)
        ensure_interfaces_admin_up(dut2, list(dut2_port_info.values()))

    _wait_for_interfaces(dut, all_dut1_ports, timeout=30, poll=5)
    if dut2:
        _wait_for_interfaces(dut2, list(dut2_port_info.values()),
                             timeout=30, poll=5)

    # ── Phase 5: L3 configuration ────────────────────────────────────────
    if mode == 'peer_link':
        _setup_l3_peer_link(dut, dut2, port_info, dut2_port_info,
                            tg, tg_ph, tgapi_module)
    elif mode == 'breakout':
        _setup_l3_breakout(dut, dut2, port_info, dut2_port_info,
                           tg, tg_ph, tgapi_module)
    else:
        _setup_l3_ixia(dut, port_info, tg, tg_ph)

    # ── Phase 6: Build WRED context and yield ─────────────────────────────
    router_mac = get_dut_mac(dut, port_info['ingress_a'])
    st.log("setup_topo: DUT router MAC = {}".format(router_mac))
    wred_ctx = build_wred_ctx(
        dut, tg, tg_ph, port_info,
        ingress_speed_mbps, egress_speed_mbps,
        router_mac, target_queue=target_queue)

    st.log("setup_topo: DONE (mode={})".format(mode))
    yield {
        'dut': dut,
        'dut2': dut2,
        'tg': tg,
        'tg_ph': tg_ph,
        'port_info': port_info,
        'dut2_port_info': dut2_port_info,
        'port_speeds': port_speeds,
        'ingress_speed_mbps': ingress_speed_mbps,
        'egress_speed_mbps': egress_speed_mbps,
        'wred_ctx': wred_ctx,
        'tb_vars': tb_vars,
        'mode': mode,
    }

    # ── Teardown ──────────────────────────────────────────────────────────
    if mode == 'peer_link':
        _teardown_l3_peer_link(dut, dut2, port_info, dut2_port_info)
    elif mode == 'breakout':
        _teardown_l3_breakout(dut, dut2, port_info, dut2_port_info)
    else:
        _teardown_l3_ixia(dut, port_info)


def _setup_l3_ixia(dut, port_info, tg, tg_ph):
    """L3 setup for ixia mode: all three ports on dut1, all connected to IXIA."""
    st.log("setup_topo [ixia]: configuring L3 on DUT (dual-stack)")
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

    st.log("setup_topo [ixia]: configuring IXIA IPv4 interfaces")
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

    st.log("setup_topo [ixia]: configuring IXIA IPv6 interfaces")
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

    try:
        tg.tg_topology_test_control(action='start_all_protocols')
    except Exception:
        st.warn("start_all_protocols unavailable; relying on arp_send_req")

    st.wait(30)

    _verify_ping(dut, IXIA_EGRESS_IP, 'IPv4')
    _verify_ping(dut, IXIA_EGRESS_IP6, 'IPv6', cmd='ping6')
    st.wait(5)


def _setup_l3_peer_link(dut, dut2, port_info, dut2_port_info,
                         tg, tg_ph, tgapi_module):
    """L3 setup for peer_link mode: transit subnet between DUTs, egress on dut2.

    Traffic path:
      IXIA(ingress) -> dut1(route) -> peer link(egress, queuing measured here)
      -> dut2(route) -> dut2 IXIA port -> IXIA(sink)
    """
    peer_d1 = port_info['egress']
    peer_d2 = dut2_port_info['peer']
    d2_ixia_port = dut2_port_info['egress_ixia']

    # ── dut1: ingress L3 + transit L3 on peer port + static route ──
    st.log("setup_topo [peer_link]: configuring L3 on dut1 (dual-stack)")
    d1_l3 = (
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}'
    ).format(
        port_info['ingress_a'], V4_INGRESS_A_IP,
        port_info['ingress_b'], V4_INGRESS_B_IP,
        peer_d1,                V4_TRANSIT_DUT1_IP,
        port_info['ingress_a'], V6_INGRESS_A_IP,
        port_info['ingress_b'], V6_INGRESS_B_IP,
        peer_d1,                V6_TRANSIT_DUT1_IP,
    )
    st.config(dut, d1_l3, skip_error_check=True)
    st.wait(2)

    st.log("setup_topo [peer_link]: adding static routes on dut1")
    st.config(dut, 'sudo ip route add 20.20.20.0/24 via {}'.format(
        V4_TRANSIT_DUT2_BARE), skip_error_check=True)
    st.config(dut, 'sudo ip -6 route add 2001:db8:20::/64 via {}'.format(
        V6_TRANSIT_DUT2_BARE), skip_error_check=True)
    st.wait(2)

    # ── dut2: transit L3 on peer port + egress L3 on IXIA port ──
    st.log("setup_topo [peer_link]: configuring L3 on dut2 (dual-stack)")
    d2_l3 = (
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}'
    ).format(
        peer_d2,       V4_TRANSIT_DUT2_IP,
        d2_ixia_port,  V4_EGRESS_IP,
        peer_d2,       V6_TRANSIT_DUT2_IP,
        d2_ixia_port,  V6_EGRESS_IP,
    )
    st.config(dut2, d2_l3, skip_error_check=True)
    st.wait(2)

    # ── IXIA: ingress interfaces on dut1 ports ──
    st.log("setup_topo [peer_link]: configuring IXIA ingress IPv4 interfaces")
    for key, ip, gw in [('ingress_a', IXIA_INGRESS_A_IP, '10.10.10.1'),
                         ('ingress_b', IXIA_INGRESS_B_IP, '10.10.11.1')]:
        tg.tg_interface_config(
            mode='config', port_handle=tg_ph[key],
            intf_ip_addr=ip, netmask=NETMASK, gateway=gw,
            arp_send_req=1, enable_ping_response=1, resolve_gateway_mac=1)

    st.log("setup_topo [peer_link]: configuring IXIA ingress IPv6 interfaces")
    for key, ip6, gw6 in [('ingress_a', IXIA_INGRESS_A_IP6, '2001:db8:10::1'),
                           ('ingress_b', IXIA_INGRESS_B_IP6, '2001:db8:11::1')]:
        tg.tg_interface_config(
            mode='config', port_handle=tg_ph[key],
            ipv6_intf_addr=ip6, ipv6_prefix_length=PREFIX_LEN_V6,
            ipv6_gateway=gw6, ipv6_resolve_gateway_mac=1,
            arp_send_req=1)

    # ── IXIA: egress sink on dut2's IXIA port ──
    st.log("setup_topo [peer_link]: configuring IXIA egress sink (dut2)")
    tg.tg_interface_config(
        mode='config', port_handle=tg_ph['egress_sink'],
        intf_ip_addr=IXIA_EGRESS_IP, netmask=NETMASK, gateway='20.20.20.1',
        arp_send_req=1, enable_ping_response=1, resolve_gateway_mac=1)
    tg.tg_interface_config(
        mode='config', port_handle=tg_ph['egress_sink'],
        ipv6_intf_addr=IXIA_EGRESS_IP6, ipv6_prefix_length=PREFIX_LEN_V6,
        ipv6_gateway='2001:db8:20::1', ipv6_resolve_gateway_mac=1,
        arp_send_req=1)

    try:
        tg.tg_topology_test_control(action='start_all_protocols')
    except Exception:
        st.warn("start_all_protocols unavailable; relying on arp_send_req")

    st.wait(30)

    # Verify connectivity: dut1 -> dut2 (transit), dut2 -> IXIA (egress)
    _verify_ping(dut, V4_TRANSIT_DUT2_BARE, 'dut1->dut2 transit IPv4')
    _verify_ping(dut2, IXIA_EGRESS_IP, 'dut2->IXIA egress IPv4')
    _verify_ping(dut, IXIA_EGRESS_IP, 'dut1->IXIA end-to-end IPv4')
    _verify_ping(dut, V6_TRANSIT_DUT2_BARE, 'dut1->dut2 transit IPv6',
                 cmd='ping6')
    _verify_ping(dut2, IXIA_EGRESS_IP6, 'dut2->IXIA egress IPv6',
                 cmd='ping6')
    _verify_ping(dut, IXIA_EGRESS_IP6, 'dut1->IXIA end-to-end IPv6',
                 cmd='ping6')
    st.wait(5)


def _teardown_l3_ixia(dut, port_info):
    """Remove L3 config for ixia mode."""
    st.log("setup_topo: teardown [ixia] — removing L3 config")
    cleanup = (
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
    st.config(dut, cleanup, skip_error_check=True)
    st.log("setup_topo: teardown [ixia] complete")


def _teardown_l3_peer_link(dut, dut2, port_info, dut2_port_info):
    """Remove L3 config + static routes for peer_link mode."""
    st.log("setup_topo: teardown [peer_link] — removing L3 + routes")
    peer_d1 = port_info['egress']
    peer_d2 = dut2_port_info['peer']
    d2_ixia_port = dut2_port_info['egress_ixia']

    st.config(dut, 'sudo ip route del 20.20.20.0/24 via {}'.format(
        V4_TRANSIT_DUT2_BARE), skip_error_check=True)
    st.config(dut, 'sudo ip -6 route del 2001:db8:20::/64 via {}'.format(
        V6_TRANSIT_DUT2_BARE), skip_error_check=True)

    d1_cleanup = (
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}'
    ).format(
        port_info['ingress_a'], V4_INGRESS_A_IP,
        port_info['ingress_b'], V4_INGRESS_B_IP,
        peer_d1,                V4_TRANSIT_DUT1_IP,
        port_info['ingress_a'], V6_INGRESS_A_IP,
        port_info['ingress_b'], V6_INGRESS_B_IP,
        peer_d1,                V6_TRANSIT_DUT1_IP,
    )
    st.config(dut, d1_cleanup, skip_error_check=True)

    d2_cleanup = (
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}'
    ).format(
        peer_d2,       V4_TRANSIT_DUT2_IP,
        d2_ixia_port,  V4_EGRESS_IP,
        peer_d2,       V6_TRANSIT_DUT2_IP,
        d2_ixia_port,  V6_EGRESS_IP,
    )
    st.config(dut2, d2_cleanup, skip_error_check=True)
    st.log("setup_topo: teardown [peer_link] complete")


def _setup_l3_breakout(dut, dut2, port_info, dut2_port_info,
                        tg, tg_ph, tgapi_module):
    """L3 setup for breakout mode: single ingress, breakout sub-port egress via dut2.

    Traffic path:
      IXIA(ingress) -> dut1(route) -> breakout sub-port(25G, queuing measured)
      -> dut2(route) -> dut2 IXIA port -> IXIA(sink)
    """
    egress_sub = port_info['egress']
    peer_sub = dut2_port_info['peer']
    d2_ixia_port = dut2_port_info['egress_ixia']

    st.log("setup_topo [breakout]: configuring L3 on dut1 (dual-stack)")
    d1_l3 = (
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}'
    ).format(
        port_info['ingress_a'], V4_INGRESS_A_IP,
        egress_sub,             V4_TRANSIT_DUT1_IP,
        port_info['ingress_a'], V6_INGRESS_A_IP,
        egress_sub,             V6_TRANSIT_DUT1_IP,
    )
    st.config(dut, d1_l3, skip_error_check=True)
    st.wait(2)

    st.log("setup_topo [breakout]: adding static routes on dut1")
    st.config(dut, 'sudo ip route add 20.20.20.0/24 via {}'.format(
        V4_TRANSIT_DUT2_BARE), skip_error_check=True)
    st.config(dut, 'sudo ip -6 route add 2001:db8:20::/64 via {}'.format(
        V6_TRANSIT_DUT2_BARE), skip_error_check=True)
    st.wait(2)

    st.log("setup_topo [breakout]: configuring L3 on dut2 (dual-stack)")
    d2_l3 = (
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}\n'
        'config interface ip add {} {}'
    ).format(
        peer_sub,      V4_TRANSIT_DUT2_IP,
        d2_ixia_port,  V4_EGRESS_IP,
        peer_sub,      V6_TRANSIT_DUT2_IP,
        d2_ixia_port,  V6_EGRESS_IP,
    )
    st.config(dut2, d2_l3, skip_error_check=True)
    st.wait(2)

    st.log("setup_topo [breakout]: configuring IXIA ingress IPv4")
    tg.tg_interface_config(
        mode='config', port_handle=tg_ph['ingress_a'],
        intf_ip_addr=IXIA_INGRESS_A_IP, netmask=NETMASK, gateway='10.10.10.1',
        arp_send_req=1, enable_ping_response=1, resolve_gateway_mac=1)

    st.log("setup_topo [breakout]: configuring IXIA ingress IPv6")
    tg.tg_interface_config(
        mode='config', port_handle=tg_ph['ingress_a'],
        ipv6_intf_addr=IXIA_INGRESS_A_IP6, ipv6_prefix_length=PREFIX_LEN_V6,
        ipv6_gateway='2001:db8:10::1', ipv6_resolve_gateway_mac=1,
        arp_send_req=1)

    st.log("setup_topo [breakout]: configuring IXIA egress sink (dut2)")
    tg.tg_interface_config(
        mode='config', port_handle=tg_ph['egress_sink'],
        intf_ip_addr=IXIA_EGRESS_IP, netmask=NETMASK, gateway='20.20.20.1',
        arp_send_req=1, enable_ping_response=1, resolve_gateway_mac=1)
    tg.tg_interface_config(
        mode='config', port_handle=tg_ph['egress_sink'],
        ipv6_intf_addr=IXIA_EGRESS_IP6, ipv6_prefix_length=PREFIX_LEN_V6,
        ipv6_gateway='2001:db8:20::1', ipv6_resolve_gateway_mac=1,
        arp_send_req=1)

    try:
        tg.tg_topology_test_control(action='start_all_protocols')
    except Exception:
        st.warn("start_all_protocols unavailable; relying on arp_send_req")

    st.wait(30)

    _verify_ping(dut, V4_TRANSIT_DUT2_BARE, 'dut1->dut2 transit IPv4')
    _verify_ping(dut2, IXIA_EGRESS_IP, 'dut2->IXIA egress IPv4')
    _verify_ping(dut, IXIA_EGRESS_IP, 'dut1->IXIA end-to-end IPv4')
    _verify_ping(dut, V6_TRANSIT_DUT2_BARE, 'dut1->dut2 transit IPv6',
                 cmd='ping6')
    _verify_ping(dut2, IXIA_EGRESS_IP6, 'dut2->IXIA egress IPv6',
                 cmd='ping6')
    _verify_ping(dut, IXIA_EGRESS_IP6, 'dut1->IXIA end-to-end IPv6',
                 cmd='ping6')
    st.wait(5)


def _teardown_l3_breakout(dut, dut2, port_info, dut2_port_info):
    """Remove L3 config and static routes.

    Port breakout is intentionally **not** reverted here because the
    reverse breakout (4x25G -> 1x100G) triggers the same SAI port-deletion
    bug that prevents orchagent from removing sub-ports from ASIC_DB.
    The DUTs are left in breakout state; a reboot with the original
    config_db.json is required to fully restore 1x100G.
    """
    st.log("setup_topo: teardown [breakout] — removing L3 + routes")
    egress_sub = port_info['egress']
    peer_sub = dut2_port_info['peer']
    d2_ixia_port = dut2_port_info['egress_ixia']

    st.config(dut, 'sudo ip route del 20.20.20.0/24 via {}'.format(
        V4_TRANSIT_DUT2_BARE), skip_error_check=True)
    st.config(dut, 'sudo ip -6 route del 2001:db8:20::/64 via {}'.format(
        V6_TRANSIT_DUT2_BARE), skip_error_check=True)

    d1_cleanup = (
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}'
    ).format(
        port_info['ingress_a'], V4_INGRESS_A_IP,
        egress_sub,             V4_TRANSIT_DUT1_IP,
        port_info['ingress_a'], V6_INGRESS_A_IP,
        egress_sub,             V6_TRANSIT_DUT1_IP,
    )
    st.config(dut, d1_cleanup, skip_error_check=True)

    d2_cleanup = (
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}\n'
        'config interface ip remove {} {}'
    ).format(
        peer_sub,      V4_TRANSIT_DUT2_IP,
        d2_ixia_port,  V4_EGRESS_IP,
        peer_sub,      V6_TRANSIT_DUT2_IP,
        d2_ixia_port,  V6_EGRESS_IP,
    )
    st.config(dut2, d2_cleanup, skip_error_check=True)

    st.banner("WARNING: DUTs are still in 4x25G breakout. Reverse breakout "
              "is skipped due to a SAI port-deletion bug. A reboot with the "
              "original config_db.json is required before running tests that "
              "expect the default 1x100G port map.")
    st.log("setup_topo: teardown [breakout] complete")


def _verify_ping(dut_handle, target, label, cmd='ping'):
    """Ping helper used during setup to verify connectivity."""
    ping_out = st.config(dut_handle, "{} -c 5 -W 2 {}".format(cmd, target),
                         skip_error_check=True)
    ping_str = str(ping_out) if ping_out else ''
    if '0 received' in ping_str or 'Unreachable' in ping_str:
        st.warn("setup_topo: {} ping to {} FAILED".format(label, target))
        dump_l3_diag(dut_handle, target)
    else:
        st.log("setup_topo: {} ping to {} OK".format(label, target))


# ── WRED context builder ────────────────────────────────────────────────

def build_wred_ctx(dut, tg, tg_ph, port_info,
                   ingress_speed_mbps, egress_speed_mbps,
                   router_mac, target_queue=3):
    """Build the shared context dict consumed by WRED helper functions.

    Bakes in the FX3 QoS testbed L3 addresses and AZURE_LOSSY WRED
    defaults so callers only need to pass runtime-discovered values.

    In peer_link mode the ``'egress'`` handle points to the IXIA sink port
    on dut2 (same handle as ``'egress_sink'``), so downstream helpers can
    still verify received traffic.

    Returns:
        dict suitable for passing as ``ctx`` to run_wred_linearity(),
        wred_fanin_send_and_measure(), and related helpers.
    """
    tg_ph_egress = tg_ph.get('egress')
    num_ingress = 2 if 'ingress_b' in tg_ph else 1
    return {
        'dut': dut,
        'tg': tg,
        'tg_ph_ingress_a': tg_ph['ingress_a'],
        'tg_ph_ingress_b': tg_ph.get('ingress_b'),
        'tg_ph_egress': tg_ph_egress,
        'port_info': port_info,
        'ingress_speed_mbps': ingress_speed_mbps,
        'egress_speed_mbps': egress_speed_mbps,
        'num_ingress_ports': num_ingress,
        'target_queue': target_queue,
        'target_dscp': QUEUE_TO_DSCP[target_queue],
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
            'v4_src_a': IXIA_INGRESS_A_IP,
            'v4_src_b': IXIA_INGRESS_B_IP,
            'v4_dst': IXIA_EGRESS_IP,
            'v4_gw': '10.10.10.1',
            'v4_mask': NETMASK,
            'v6_src_a': IXIA_INGRESS_A_IP6,
            'v6_src_b': IXIA_INGRESS_B_IP6,
            'v6_dst': IXIA_EGRESS_IP6,
            'v6_gw': '2001:db8:10::1',
            'v6_prefix_len': PREFIX_LEN_V6,
        },
    }



# ═══════════════════════════════════════════════════════════════════════════
# Redis Direct Query Functions (CONFIG_DB)
# ═══════════════════════════════════════════════════════════════════════════

def get_queue_binding(dut, egress_intf, qi):
    """Return CONFIG_DB QUEUE|<intf>|N scheduler field value (stripped).

    Used for spot-checking a single queue binding without fetching all 8.
    """
    out = st.show(
        dut,
        'sonic-db-cli CONFIG_DB HGET "QUEUE|{}|{}" "scheduler"'.format(
            egress_intf, qi),
        skip_tmpl=True)
    return parse_redis_hget(out).strip()


def log_queue_bindings_table(dut, egress_intf, label, expected_bindings=None):
    """Fetch and log all 8 QUEUE|<intf>|N scheduler bindings as a table.

    If *expected_bindings* ({qi: 'scheduler.N'}) is provided, an Expected
    and Status column are added — mismatches are flagged with '** FAIL'.
    Returns {qi: actual_binding} dict (does NOT append to fail_msgs;
    caller decides whether the bindings are informational or a hard check).
    """
    actual = {}
    for qi in range(8):
        actual[qi] = get_queue_binding(dut, egress_intf, qi)

    print_section("Queue Bindings — {} [{}]".format(egress_intf, label),
                  art_key='queue')
    if expected_bindings:
        st.log("  {:<6} {:>16} {:>16} {:>8}".format(
            'Queue', 'Expected', 'Actual', 'Status'))
        st.log("  " + "-" * 52)
        for qi in range(8):
            exp = expected_bindings.get(qi, '?')
            act = actual[qi]
            tag = 'OK' if act == exp else '** FAIL'
            st.log("  Q{:<4} {:>16} {:>16} {:>8}".format(qi, exp, act, tag))
    else:
        st.log("  {:<6} {:>16}".format('Queue', 'Binding'))
        st.log("  " + "-" * 26)
        for qi in range(8):
            st.log("  Q{:<4} {:>16}".format(qi, actual[qi]))
    return actual


def log_scheduler_state_table(dut, label):
    """Fetch and log all 8 SCHEDULER profiles as a formatted table.

    Compares each profile against EXPECTED_SCHEDULERS and marks
    mismatches.  Returns {name: {field: value}} dict.
    """
    profiles = {}
    for i in range(8):
        name = "scheduler.{}".format(i)
        out = st.show(
            dut,
            'sonic-db-cli CONFIG_DB HGETALL "SCHEDULER|{}"'.format(name),
            skip_tmpl=True)
        profiles[name] = parse_redis_hgetall(out)

    print_section("Scheduler Profiles [{}]".format(label), art_key='scheduler')
    st.log("  {:<16} {:>8} {:>8} {:>8}".format(
        'Profile', 'Type', 'Weight', 'Status'))
    st.log("  " + "-" * 46)
    for i in range(8):
        name = "scheduler.{}".format(i)
        info = profiles[name]
        stype = info.get('type', '(nil)')
        weight = info.get('weight', '-')
        exp = EXPECTED_SCHEDULERS.get(name, {})
        ok = all(info.get(k, '') == v for k, v in exp.items())
        st.log("  {:<16} {:>8} {:>8} {:>8}".format(
            name, stype, weight, 'OK' if ok else '** FAIL'))
    return profiles


def log_dchal_egress_table(dchal_output, label):
    """Print just the Egress Queuing config table from DCHAL output.

    Emits lines from 'Egress Queuing for ...' through the
    'Raw HW tokens' line, then stops — skipping the per-queue
    counter boxes which are noisy when comparing BEFORE/AFTER state.
    """
    st.log("=== DCHAL Egress Config Table [{}] ===".format(label))
    in_table = False
    for line in dchal_output.splitlines():
        stripped = line.strip()
        if 'Egress Queuing for' in stripped:
            in_table = True
        if not in_table:
            continue
        st.log(line)
        # Stop after the Raw HW tokens line.  If no tokens line exists
        # (e.g. all-SP queues, or DCHAL_SKIP), stop at first counter box.
        if stripped.startswith('Raw HW tokens'):
            break
        if stripped.startswith('+---') and in_table and 'Egress' not in line:
            break


def verify_queue_strict(label, dchal_output, fail_msgs, queue=7):
    """Assert the given queue has PrioLevel (STRICT) and no BW% in DCHAL output.

    Logs a check table showing PrioLevel and BW% for the queue.
    Returns the full parse_dchal_egress_bw() dict.
    """
    bw_data = parse_dchal_egress_bw(dchal_output)
    qdata = bw_data.get(queue, {})
    q_prio = qdata.get('prio')
    q_bw = qdata.get('bw_pct')

    sep = "=" * 60
    st.log(sep)
    st.log("  Q{} STRICT CHECK  --  {}".format(queue, label))
    st.log(sep)
    st.log("  {:<14} {:>14} {:>10}".format('Property', 'Value', 'Status'))
    st.log("  " + "-" * 42)

    prio_ok = q_prio is not None
    bw_ok = q_bw is None
    st.log("  {:<14} {:>14} {:>10}".format(
        'PrioLevel',
        str(q_prio) if q_prio is not None else '(missing)',
        'OK' if prio_ok else '** FAIL'))
    st.log("  {:<14} {:>14} {:>10}".format(
        'BW%',
        str(q_bw) if q_bw is not None else '(none)',
        'OK' if bw_ok else '** FAIL'))
    st.log(sep)

    if not prio_ok:
        fail_msgs.append(
            "{}: DCHAL Q{} missing PrioLevel -- SG{} was NOT kept STRICT "
            "(rebind to DWRR succeeded when it should have failed)".format(
                label, queue, queue))
    if not bw_ok:
        fail_msgs.append(
            "{}: DCHAL Q{} BW%={} -- Q{} must be STRICT with no BW%".format(
                label, queue, q_bw, queue))
    return bw_data


def verify_queue_dwrr(label, dchal_output, fail_msgs, queue, expected_bw_pct=None):
    """Assert the given queue has BW% (DWRR mode) and no PrioLevel in DCHAL output.

    Symmetric twin to verify_queue_strict.  Logs a check table showing
    BW% and PrioLevel for the queue.

    Args:
        label:            Checkpoint label for log output.
        dchal_output:     Raw string from dchal_show_queuing().
        fail_msgs:        List to append failure strings to.
        queue:            Queue index to check (0-7).
        expected_bw_pct:  If given, also verifies abs(actual - expected) <= 2
                          (integer percentage tolerance matching HW rounding).

    Returns the full parse_dchal_egress_bw() dict.
    """
    bw_data = parse_dchal_egress_bw(dchal_output)
    qdata = bw_data.get(queue, {})
    q_prio = qdata.get('prio')
    q_bw = qdata.get('bw_pct')

    sep = "=" * 60
    st.log(sep)
    st.log("  Q{} DWRR CHECK  --  {}".format(queue, label))
    st.log(sep)
    st.log("  {:<18} {:>14} {:>10}".format('Property', 'Value', 'Status'))
    st.log("  " + "-" * 46)

    bw_ok = q_bw is not None
    prio_ok = q_prio is None    # DWRR queues must NOT have a PrioLevel

    bw_status = 'OK' if bw_ok else '** FAIL'
    if bw_ok and expected_bw_pct is not None:
        bw_status = 'OK' if abs(q_bw - expected_bw_pct) <= 2 else '** FAIL'

    st.log("  {:<18} {:>14} {:>10}".format(
        'BW%',
        str(q_bw) if q_bw is not None else '(missing)',
        bw_status))
    if expected_bw_pct is not None:
        st.log("  {:<18} {:>14}".format('  expected BW%', str(expected_bw_pct)))
    st.log("  {:<18} {:>14} {:>10}".format(
        'PrioLevel',
        str(q_prio) if q_prio is not None else '(none)',
        'OK' if prio_ok else '** FAIL'))
    st.log(sep)

    if not bw_ok:
        fail_msgs.append(
            "{}: DCHAL Q{} missing BW% -- Q{} is not in DWRR mode".format(
                label, queue, queue))
    elif expected_bw_pct is not None and abs(q_bw - expected_bw_pct) > 2:
        fail_msgs.append(
            "{}: DCHAL Q{} BW%={}, expected ~{}% (tolerance ±2)".format(
                label, queue, q_bw, expected_bw_pct))
    if not prio_ok:
        fail_msgs.append(
            "{}: DCHAL Q{} has PrioLevel={} -- Q{} must be DWRR with no PrioLevel".format(
                label, queue, q_prio, queue))
    return bw_data


def get_port_oid(dut_h, interface):
    """Return the ASIC_DB OID (e.g. 'oid:0x1000...') for a DUT interface name."""
    out = st.show(dut_h,
        'sonic-db-cli COUNTERS_DB HGET "COUNTERS_PORT_NAME_MAP" "{}"'.format(interface),
        skip_tmpl=True)
    lines = [l.strip() for l in out.splitlines() if l.strip() and l.strip().startswith('oid:')]
    if lines:
        return lines[0]
    # fallback: last non-empty token
    tokens = out.split()
    for tok in reversed(tokens):
        if tok.startswith('oid:'):
            return tok
    return None


def get_queue_oids_for_port(dut_h, interface):
    """Return {queue_index_int: queue_oid_str} for queues 0-7 on interface.

    Uses individual HGET calls against COUNTERS_QUEUE_NAME_MAP for
    'Ethernet1_N:0' .. 'Ethernet1_N:7' to avoid dumping the full map.
    """
    result = {}
    for qi in range(8):
        out = st.show(dut_h,
            'sonic-db-cli COUNTERS_DB HGET "COUNTERS_QUEUE_NAME_MAP" "{}:{}"'.format(
                interface, qi),
            skip_tmpl=True)
        oid = parse_redis_hget(out).strip()
        if oid.startswith('oid:'):
            result[qi] = oid
    return result


def get_scheduler_groups_for_port(dut_h, interface):
    """Return queue OID dict {index: oid} for interface (FX3 1:1 queue:SG mapping).

    On this platform SAI_SCHEDULER_GROUP_ATTR_PORT_ID is not stored in ASIC_DB,
    so scheduler groups are identified via COUNTERS_QUEUE_NAME_MAP.
    """
    return get_queue_oids_for_port(dut_h, interface)


# Seconds to wait after a CONFIG_DB change for orchagent propagation
_ORCHAGENT_DELAY = 5


# New scheduler helper functions
def get_scheduler_param(key):
    """Return the SAI attribute name, value string, or constraint for *key*.

    Keys and their values:
      'ATTR_TYPE'   -> "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE"
      'ATTR_WEIGHT' -> "SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT"
      'ATTR_METER'  -> "SAI_SCHEDULER_ATTR_METER_TYPE"
      'ATTR_MIN_BW' -> "SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE"
      'ATTR_MAX_BW' -> "SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE"
      'VAL_DWRR'    -> "SAI_SCHEDULING_TYPE_DWRR"
      'VAL_STRICT'  -> "SAI_SCHEDULING_TYPE_STRICT"
      'VAL_WRR'     -> "SAI_SCHEDULING_TYPE_WRR"
      'VAL_BYTES'   -> "SAI_METER_TYPE_BYTES"
      'WEIGHT_MIN'  -> 1    (minimum valid weight for FX3/CloudScale)
      'WEIGHT_MAX'  -> 255  (maximum valid weight, SAI u8 limit)
    """
    _params = {
        'ATTR_TYPE':   "SAI_SCHEDULER_ATTR_SCHEDULING_TYPE",
        'ATTR_WEIGHT': "SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT",
        'ATTR_METER':  "SAI_SCHEDULER_ATTR_METER_TYPE",
        'ATTR_MIN_BW': "SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE",
        'ATTR_MAX_BW': "SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE",
        'VAL_DWRR':    "SAI_SCHEDULING_TYPE_DWRR",
        'VAL_STRICT':  "SAI_SCHEDULING_TYPE_STRICT",
        'VAL_WRR':     "SAI_SCHEDULING_TYPE_WRR",
        'VAL_BYTES':   "SAI_METER_TYPE_BYTES",
        'WEIGHT_MIN':  1,
        'WEIGHT_MAX':  255,
    }
    if key not in _params:
        raise KeyError("get_scheduler_param: unknown key {!r}".format(key))
    return _params[key]


def asic_db_get_sched_oids(dut):
    """Return all SAI_OBJECT_TYPE_SCHEDULER OID keys currently in ASIC_DB."""
    out = st.show(
        dut,
        'sonic-db-cli ASIC_DB KEYS "*SAI_OBJECT_TYPE_SCHEDULER:*"',
        skip_tmpl=True)
    keys = [
        line.strip()
        for line in out.strip().splitlines()
        if "SAI_OBJECT_TYPE_SCHEDULER" in line
    ]
    st.log("  ASIC_DB scheduler OIDs ({}): {}".format(len(keys), keys))
    return keys


def asic_db_get_sched_attrs(dut, oid_key):
    """Read ASIC_DB HGETALL for *oid_key* and return as a dict."""
    out = st.show(
        dut,
        'sonic-db-cli ASIC_DB HGETALL "{}"'.format(oid_key),
        skip_tmpl=True)
    attrs = parse_redis_hgetall(out)
    st.log("  ASIC_DB {}: {}".format(oid_key, attrs))
    return attrs


def config_db_create_scheduler(dut, name, sched_type, weight=None, cir=None, pir=None):
    """Write SCHEDULER|<name> to CONFIG_DB and wait for orchagent propagation."""
    fields = ['"type" "{}"'.format(sched_type)]
    if weight is not None:
        fields.append('"weight" "{}"'.format(weight))
    if cir is not None:
        fields.append('"cir" "{}"'.format(cir))
    if pir is not None:
        fields.append('"pir" "{}"'.format(pir))
    cmd = 'sonic-db-cli CONFIG_DB HSET "SCHEDULER|{}" {}'.format(
        name, " ".join(fields))
    st.log("  CONFIG_DB: {}".format(cmd))
    st.config(dut, cmd, skip_error_check=True)
    st.wait(_ORCHAGENT_DELAY)


def config_db_delete_scheduler(dut, name):
    """Delete SCHEDULER|<name> from CONFIG_DB and wait for orchagent propagation."""
    cmd = 'sonic-db-cli CONFIG_DB DEL "SCHEDULER|{}"'.format(name)
    st.log("  CONFIG_DB: {}".format(cmd))
    st.config(dut, cmd, skip_error_check=True)
    st.wait(_ORCHAGENT_DELAY)


def asic_db_find_new_oid(oids_before, oids_after):
    """Return the first OID key that appeared in *oids_after* but not *oids_before*."""
    new_keys = [k for k in oids_after if k not in oids_before]
    if new_keys:
        st.log("  ASIC_DB new scheduler OID: {}".format(new_keys[0]))
    else:
        st.log("  ASIC_DB no new scheduler OID found")
    return new_keys[0] if new_keys else None


# ── Egress reachability verification ─────────────────────────────────────

def verify_egress_reachable(dut_handle, tg, tg_ph, af):
    """Verify that the DUT can forward traffic to the IXIA egress destination.

    Uses ``_infer_topo_mode()`` to decide the strategy:

      * **ixia** -- The IXIA egress port is directly connected to the DUT.
        Checks the DUT's ARP/NDP table and, if needed, re-triggers IXIA
        interface config + ping up to 3 times.
      * **peer_link / breakout** -- The IXIA egress is behind dut2.  The DUT
        reaches it via a static route, so dut1's ARP table won't contain the
        IXIA IP.  Verifies reachability with an end-to-end ping.

    Args:
        dut_handle: Primary DUT (dut1) handle.
        tg:         Traffic generator handle.
        tg_ph:      Dict of TG port handles (must include ``'egress'``).
        af:         ``'ipv4'`` or ``'ipv6'``.

    Returns:
        True if reachable, False otherwise.
    """
    mode = _infer_topo_mode()
    ping_cmd = 'ping6' if af == 'ipv6' else 'ping'

    if af == 'ipv6':
        target = IXIA_EGRESS_IP6
        nb_cmd = 'show ndp'
    else:
        target = IXIA_EGRESS_IP
        nb_cmd = 'show arp'

    if mode in ('peer_link', 'breakout'):
        ping_out = st.config(dut_handle,
                             "{} -c 5 -W 2 {}".format(ping_cmd, target),
                             skip_error_check=True)
        ping_str = str(ping_out) if ping_out else ''
        if '0 received' not in ping_str and 'Unreachable' not in ping_str:
            st.log("verify_egress_reachable [{}]: ping to {} OK".format(
                mode, target))
            return True
        st.warn("verify_egress_reachable [{}]: ping to {} FAILED".format(
            mode, target))
        dump_l3_diag(dut_handle, target)
        return False

    # ── ixia mode: ARP/NDP table check with IXIA re-trigger ──
    egress_gw = (V6_EGRESS_IP.split('/')[0] if af == 'ipv6'
                 else V4_EGRESS_IP.split('/')[0])

    for attempt in range(1, 4):
        nb_out = str(st.show(dut_handle, "{} {}".format(nb_cmd, target),
                             skip_tmpl=True) or '')
        if target in nb_out:
            st.log("verify_egress_reachable: {} resolved (attempt {})".format(
                target, attempt))
            return True

        st.log("verify_egress_reachable: {} not in {} table (attempt {}); "
               "re-triggering".format(target, nb_cmd.upper(), attempt))
        try:
            if af == 'ipv6':
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
        except Exception as exc:
            st.log("  tg_interface_config re-trigger failed: {}".format(exc))
        st.wait(10)
        st.config(dut_handle, "{} -c 3 -W 2 {}".format(ping_cmd, target),
                  skip_error_check=True)
        st.wait(3)

    dump_l3_diag(dut_handle, target)
    return False
