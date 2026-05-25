import ast
import json
import logging
import os
import re
import time
import math
import pytest

from collections import defaultdict
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.syslog_helpers import (
    disable_swss_rsyslog_rate_limit,
    restore_swss_rsyslog_rate_limit,
)
from .utils import MacToInt, IntToMac, fdb_cleanup, get_crm_resources, send_arp_request, get_fdb_dynamic_mac_count

TOTAL_FDB_ENTRIES = 12000
FDB_POPULATE_SLEEP_TIMEOUT = 2
BASE_MAC_ADDRESS = "02:11:22:{:02x}:00:00"

LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 10,
    'confident': 50,
    'thorough': 100,
    'diagnose': 200
}

# Storm sender (PTF-side script) constants
STORM_SENDER_SCRIPT = "fdb_mac_move_storm.py"
STORM_SENDER_LOCAL_PATH = os.path.join(os.path.dirname(__file__), "files", STORM_SENDER_SCRIPT)
STORM_SENDER_REMOTE_PATH = "/tmp/" + STORM_SENDER_SCRIPT
STORM_SENDER_LOG = "/tmp/fdb_mac_move_storm.log"
# MAC_MOVE_GUARD counts moves per individual MAC, so the storm rotates a tiny
# pool of source MACs to ensure each one accumulates well over the configured
# threshold within the detect_interval.
STORM_NUM_MACS = 4
STORM_MAC_BASE = "02:11:22:33:00:00"
STORM_REPORT_INTERVAL = 10
# Dedicated VLAN used by the DISABLE_LEARN_ON_MAC_WITH_ACL test. Storm frames
# are 802.1Q-tagged with this VID so the OUTER_VLAN_ID qualifier at the
# PRE_INGRESS / VFP stage sees the VID directly, instead of relying on the
# DUT's port-PVID classification (which is keyed on incoming VID = 0 for
# untagged frames in some Broadcom VFP key configurations).
STORM_VLAN_TAG = 100

# MAC_MOVE_GUARD configuration applied during the tests
MAC_MOVE_GUARD_THRESHOLD = 100
MAC_MOVE_GUARD_DETECT_INTERVAL = 10
MAC_MOVE_GUARD_ACTION_INTERVAL = 60
# Longer action_interval for the DISABLE_MAC_MOVE test so the post-storm pin
# verification and the auto-release verification both have comfortable margins.
DISABLE_MAC_MOVE_ACTION_INTERVAL = 120
# Action interval used by the DISABLE_LEARN_ON_MAC_WITH_ACL test. Kept high so
# the bad MAC is not auto-released while we drive the storm and observe
# orchagent quiescence. The test reconfigures this to a small value after the
# storm is stopped to drive the cleanup phase.
DISABLE_LEARN_ON_MAC_ACTION_INTERVAL = 600
# Short action_interval reapplied after the storm is stopped to force the
# bad-MAC tracking entry / ACL entry to age out promptly.
DISABLE_LEARN_ON_MAC_CLEANUP_ACTION_INTERVAL = 30
# Number of ARPs to send when probing whether a MAC can move; a single packet
# can be lost or update FDB slowly, leading to false PASS for a pin assertion.
MMG_MOVE_ATTEMPT_BURST = 5
# Settle time after a burst of ARPs before we read the FDB.
MMG_FDB_SETTLE_SECONDS = 5


def _build_mmg_config(action, action_interval):
    return {
        "MAC_MOVE_GUARD": {
            "GLOBAL": {
                "enabled": "true",
                "threshold": str(MAC_MOVE_GUARD_THRESHOLD),
                "detect_interval": str(MAC_MOVE_GUARD_DETECT_INTERVAL),
                "action": action,
                "action_interval": str(action_interval),
            }
        }
    }


MAC_MOVE_GUARD_CONFIG = _build_mmg_config("DISABLE_PORT", MAC_MOVE_GUARD_ACTION_INTERVAL)
DISABLE_MAC_MOVE_GUARD_CONFIG = _build_mmg_config("DISABLE_MAC_MOVE",
                                                  DISABLE_MAC_MOVE_ACTION_INTERVAL)
DISABLE_LEARN_ON_MAC_GUARD_CONFIG = _build_mmg_config(
    "DISABLE_LEARN_ON_MAC_WITH_ACL", DISABLE_LEARN_ON_MAC_ACTION_INTERVAL)
DISABLE_LEARN_ON_MAC_CLEANUP_GUARD_CONFIG = _build_mmg_config(
    "DISABLE_LEARN_ON_MAC_WITH_ACL",
    DISABLE_LEARN_ON_MAC_CLEANUP_ACTION_INTERVAL)
MMG_CONFIG_REMOTE_PATH = "/tmp/mac_move_guard.json"
MMG_TIMEOUT = 300

# STATE_DB table name written by macmoveguardorch for every tracked bad MAC.
# Mirrors STATE_MAC_MOVE_GUARD_TABLE_NAME from macmoveguardorch.h.
MMG_BAD_MAC_TABLE = "MAC_MOVE_GUARD"

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]


def get_fdb_dict(ptfadapter, vlan_table, dummay_mac_count):
    """
    :param ptfadapter: PTF adapter object
    :param vlan_table: VLAN table map: VLAN subnet -> list of VLAN members
    :return: FDB table map : VLAN member -> MAC addresses set
    """

    fdb = {}
    vlan = list(vlan_table.keys())[0]

    for member in vlan_table[vlan]:
        if 'port_index' not in member or 'tagging_mode' not in member:
            continue
        if not member['port_index']:
            continue

        port_index = member['port_index'][0]

        fdb[port_index] = {}

        dummy_macs = []
        base_mac = BASE_MAC_ADDRESS.format(port_index)
        for i in range(dummay_mac_count):
            mac_address = IntToMac(MacToInt(base_mac) + i)
            dummy_macs.append(mac_address)
        fdb[port_index] = dummy_macs
    return fdb


def test_fdb_mac_move(ptfadapter, duthosts, fanouthosts, rand_one_dut_hostname, ptfhost,
                      get_function_completeness_level, rotate_syslog):

    # Perform FDB clean up before each test
    fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)

    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = "debug"
    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    duthost = duthosts[rand_one_dut_hostname]
    conf_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    # reinitialize data plane due to above changes on PTF interfaces
    ptfadapter.reinit()

    router_mac = duthost.facts['router_mac']

    port_index_to_name = {v: k for k, v in list(conf_facts['port_index_map'].items())}

    # Only take interfaces that are in ptf topology
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    available_ports_idx = []
    for idx, name in list(ptf_ports_available_in_topo.items()):
        if idx in port_index_to_name and conf_facts['PORT'][port_index_to_name[idx]].get('admin_status',
                                                                                         'down') == 'up':
            available_ports_idx.append(idx)

    vlan_table = {}
    interface_table = defaultdict(set)
    config_portchannels = conf_facts.get('PORTCHANNEL', {})

    # if DUT has more than one VLANs, use the first vlan
    name = list(conf_facts['VLAN'].keys())[0]
    vlan = conf_facts['VLAN'][name]
    vlan_id = int(vlan['vlanid'])
    vlan_table[vlan_id] = []

    for ifname in list(conf_facts['VLAN_MEMBER'][name].keys()):
        if 'tagging_mode' not in conf_facts['VLAN_MEMBER'][name][ifname]:
            continue
        tagging_mode = conf_facts['VLAN_MEMBER'][name][ifname]['tagging_mode']
        port_index = []
        if ifname in config_portchannels:
            for member in config_portchannels[ifname]['members']:
                if conf_facts['port_index_map'][member] in available_ports_idx:
                    port_index.append(conf_facts['port_index_map'][member])
            if port_index:
                interface_table[ifname].add(vlan_id)
        elif conf_facts['port_index_map'][ifname] in available_ports_idx:
            port_index.append(conf_facts['port_index_map'][ifname])
            interface_table[ifname].add(vlan_id)
        if port_index:
            vlan_table[vlan_id].append({'port_index': port_index, 'tagging_mode': tagging_mode})

    vlan = list(vlan_table.keys())[0]
    vlan_member_count = len(vlan_table[vlan])
    total_fdb_entries = min(TOTAL_FDB_ENTRIES, (
            get_crm_resources(duthost, "fdb_entry", "available") - get_crm_resources(duthost, "fdb_entry", "used")))
    dummay_mac_count = int(math.floor(total_fdb_entries / vlan_member_count))

    fdb = get_fdb_dict(ptfadapter, vlan_table, dummay_mac_count)
    port_list = list(fdb.keys())
    dummy_mac_list = list(fdb.values())

    for loop_time in range(0, loop_times):
        port_index_start = (0 + loop_time) % len(port_list)

        # Use actual port numbers from port_list instead of calculating indices
        for i in range(len(port_list)):
            port_index = port_list[(port_index_start + i) % len(port_list)]
            dummy_mac_set = dummy_mac_list[(port_index_start + i) % len(port_list)]
            for dummy_mac in dummy_mac_set:
                send_arp_request(ptfadapter, port_index, dummy_mac, router_mac, vlan_id)

        time.sleep(FDB_POPULATE_SLEEP_TIMEOUT)
        pytest_assert(
            wait_until(20, 1, 0, lambda: get_fdb_dynamic_mac_count(duthost) > vlan_member_count),
            (
                "FDB Table Add failed. Expected FDB dynamic MAC count to be greater than {}."
            ).format(vlan_member_count)
        )
        # Flush dataplane
        ptfadapter.dataplane.flush()
        time.sleep(10)
        fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)
        # Wait for 10 seconds before starting next loop
        time.sleep(10)


def _select_two_vlan_member_ptf_ports(conf_facts, ptfhost, mg_facts):
    """Pick two PTF port indices that are members of the first VLAN, admin-up
    on the DUT, and reachable from the PTF host.

    Returns (ptf_idx_a, ptf_idx_b, vlan_id, ptf_iface_a, ptf_iface_b,
             dut_port_a, dut_port_b).

    Source of truth for DUT-port -> PTF-port-index is
    ``mg_facts['minigraph_ptf_indices']``. PTF interface names are conventionally
    ``eth<idx>``; ``ifaces_map`` (when present in extra_vars) is used as an
    override.
    """
    dut_to_ptf = mg_facts.get('minigraph_ptf_indices', {}) or {}
    pytest_assert(dut_to_ptf,
                  "minigraph_ptf_indices is empty; cannot map DUT ports to PTF ports")

    extra_vars = ptfhost.host.options['variable_manager'].extra_vars or {}
    ifaces_map = extra_vars.get("ifaces_map") or {}

    config_portchannels = conf_facts.get('PORTCHANNEL', {})
    vlans = conf_facts.get('VLAN', {})
    vlan_members = conf_facts.get('VLAN_MEMBER', {})
    pytest_assert(vlans and vlan_members,
                  "DUT has no VLAN/VLAN_MEMBER configuration; cannot run MAC-move storm")

    vlan_name = list(vlans.keys())[0]
    vlan_id = int(vlans[vlan_name]['vlanid'])

    def _is_up(port_name):
        return conf_facts.get('PORT', {}).get(port_name, {}).get('admin_status', 'down') == 'up'

    members = []  # list of (ptf_idx, dut_port_name)
    for ifname in list(vlan_members.get(vlan_name, {}).keys()):
        if 'tagging_mode' not in vlan_members[vlan_name][ifname]:
            continue
        if ifname in config_portchannels:
            for member in config_portchannels[ifname].get('members', []):
                if not _is_up(member):
                    continue
                pi = dut_to_ptf.get(member)
                if pi is not None:
                    members.append((pi, member))
        else:
            if not _is_up(ifname):
                continue
            pi = dut_to_ptf.get(ifname)
            if pi is not None:
                members.append((pi, ifname))

    pytest_assert(len(members) >= 2,
                  "Need at least 2 active VLAN member ports for MAC-move storm; "
                  "vlan={} got={}".format(vlan_name, members))

    (ptf_a, dut_a), (ptf_b, dut_b) = members[0], members[1]
    iface_a = ifaces_map.get(ptf_a) or "eth{}".format(ptf_a)
    iface_b = ifaces_map.get(ptf_b) or "eth{}".format(ptf_b)
    return ptf_a, ptf_b, vlan_id, iface_a, iface_b, dut_a, dut_b


def _start_storm_sender(ptfhost, iface_a, iface_b, router_mac, vlan_tag=None):
    """Copy the storm script to ptfhost and launch it in background. Returns the pid.

    If ``vlan_tag`` is provided, frames are 802.1Q-tagged with that VID.
    """
    ptfhost.copy(src=STORM_SENDER_LOCAL_PATH, dest=STORM_SENDER_REMOTE_PATH, mode="0755")
    ptfhost.shell("rm -f {}".format(STORM_SENDER_LOG), module_ignore_errors=True)
    vlan_arg = "--vlan-tag {} ".format(vlan_tag) if vlan_tag is not None else ""
    cmd = (
        "nohup python3 {script} --iface-a {ia} --iface-b {ib} --router-mac {rmac} "
        "--num-macs {n} --mac-base {base} --report-interval {ri} {vlan}"
        "> {log} 2>&1 & echo $!"
    ).format(
        script=STORM_SENDER_REMOTE_PATH, ia=iface_a, ib=iface_b, rmac=router_mac,
        n=STORM_NUM_MACS, base=STORM_MAC_BASE, ri=STORM_REPORT_INTERVAL,
        vlan=vlan_arg,
        log=STORM_SENDER_LOG,
    )
    res = ptfhost.shell(cmd)
    pid = res['stdout_lines'][-1].strip()
    pytest_assert(pid.isdigit(), "Failed to launch MAC-move storm sender: {}".format(res['stdout']))
    # Confirm the process is actually alive
    alive = ptfhost.shell("kill -0 {}".format(pid), module_ignore_errors=True)
    pytest_assert(alive.get('rc', 1) == 0,
                  "MAC-move storm sender (pid {}) is not running; log:\n{}".format(
                      pid, ptfhost.shell("cat " + STORM_SENDER_LOG,
                                         module_ignore_errors=True).get('stdout', '')))
    return pid


def _stop_storm_sender(ptfhost, pid):
    ptfhost.shell("kill {} 2>/dev/null || true".format(pid), module_ignore_errors=True)
    # Give it a moment to exit cleanly, then force-kill if still around
    time.sleep(2)
    ptfhost.shell("kill -9 {} 2>/dev/null || true".format(pid), module_ignore_errors=True)


def _apply_mac_move_guard_config(duthost, config):
    """Write the MAC_MOVE_GUARD|GLOBAL entry into CONFIG_DB via sonic-cfggen."""
    duthost.copy(content=json.dumps(config, indent=2),
                 dest=MMG_CONFIG_REMOTE_PATH)
    res = duthost.shell("sonic-cfggen -j {} --write-to-db".format(MMG_CONFIG_REMOTE_PATH))
    pytest_assert(res.get('rc') == 0,
                  "sonic-cfggen failed to apply MAC_MOVE_GUARD config: {}".format(res))


def _remove_mac_move_guard_config(duthost):
    duthost.shell('sonic-db-cli CONFIG_DB DEL "MAC_MOVE_GUARD|GLOBAL"',
                  module_ignore_errors=True)
    duthost.shell("rm -f {}".format(MMG_CONFIG_REMOTE_PATH), module_ignore_errors=True)


def _add_vlan_with_tagged_members(duthost, vlan_id, members):
    """Create ``vlan_id`` and add each entry in ``members`` as a tagged member.

    ``members`` are the names returned by :func:`_vlan_member_parent` - either
    a physical port or a PortChannel - i.e. the entities that appear in
    VLAN_MEMBER rows.
    """
    duthost.shell("config vlan add {}".format(vlan_id))
    for m in members:
        # `config vlan member add` adds as tagged by default (omit -u).
        duthost.shell("config vlan member add {} {}".format(vlan_id, m))


def _remove_vlan_with_tagged_members(duthost, vlan_id, members):
    for m in members:
        duthost.shell("config vlan member del {} {}".format(vlan_id, m),
                      module_ignore_errors=True)
    duthost.shell("config vlan del {}".format(vlan_id),
                  module_ignore_errors=True)


def _get_port_oper_status(duthost, port_name):
    """Return APPL_DB PORT_TABLE oper_status for the given DUT port (or '' if unset)."""
    res = duthost.shell(
        'sonic-db-cli APPL_DB HGET "PORT_TABLE:{}" oper_status'.format(port_name),
        module_ignore_errors=True)
    return (res.get('stdout') or '').strip()


def _disabled_ports(duthost, port_names):
    """Return the subset of port_names whose APPL_DB oper_status is 'down'."""
    return [p for p in port_names if _get_port_oper_status(duthost, p) == 'down']


def _vlan_member_parent(conf_facts, physical_port):
    """Return the VLAN_MEMBER name covering ``physical_port`` (the port itself
    or the PortChannel that contains it). FDB entries reference this name."""
    portchannels = conf_facts.get('PORTCHANNEL', {})
    for vlan_members in conf_facts.get('VLAN_MEMBER', {}).values():
        for ifname in vlan_members:
            if ifname == physical_port:
                return ifname
            if ifname in portchannels and physical_port in \
                    portchannels[ifname].get('members', []):
                return ifname
    return physical_port


def _fdb_port_for_mac(duthost, mac):
    """Return the FDB port name for ``mac`` from `show mac`, or None if absent."""
    facts = duthost.fdb_facts().get('ansible_facts', {}) or {}
    mac_lower = mac.lower()
    for k, entries in facts.items():
        if k.lower() == mac_lower and entries:
            return entries[0].get('port')
    return None


def _learn_mac_on_port(ptfadapter, duthost, mac, ptf_port, expected_parent,
                       router_mac, vlan_id, description):
    """Send a burst of ARPs from ``ptf_port`` and assert the FDB learns ``mac``
    on ``expected_parent``. Used as a pre-flight sanity / negative control
    before applying the MAC_MOVE_GUARD config."""
    ptfadapter.dataplane.flush()
    for _ in range(MMG_MOVE_ATTEMPT_BURST):
        send_arp_request(ptfadapter, ptf_port, mac, router_mac, vlan_id)
        time.sleep(0.1)
    pytest_assert(
        wait_until(MMG_FDB_SETTLE_SECONDS * 2, 1, 0,
                   lambda: _fdb_port_for_mac(duthost, mac) == expected_parent),
        "{}: MAC {} expected on {} but FDB shows {}"
        .format(description, mac, expected_parent, _fdb_port_for_mac(duthost, mac))
    )


def test_fdb_mac_move_guard_disable_port(duthosts, fanouthosts, rand_one_dut_hostname,
                                         ptfhost, tbinfo):
    """
    Validate the MAC_MOVE_GUARD feature end-to-end:

      1. Configure MAC_MOVE_GUARD (GLOBAL) with action=DISABLE_PORT,
         threshold=100, detect_interval=10s, action_interval=60s.
      2. Drive a MAC-move storm from PTF on two VLAN-member ports so the
         per-MAC move count crosses the configured threshold.
      3. Verify that one of the two DUT ports is disabled by the guard.
      4. Stop the storm and verify the disabled port auto-recovers after
         action_interval (60s).
    """

    fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)

    duthost = duthosts[rand_one_dut_hostname]
    conf_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    router_mac = duthost.facts['router_mac']

    ptf_a, ptf_b, vlan_id, iface_a, iface_b, dut_a, dut_b = \
        _select_two_vlan_member_ptf_ports(conf_facts, ptfhost, mg_facts)
    candidate_ports = [dut_a, dut_b]
    logger.info("MAC_MOVE_GUARD test on vlan {}: PTF {} ({}) <-> DUT {}, "
                "PTF {} ({}) <-> DUT {}"
                .format(vlan_id, ptf_a, iface_a, dut_a, ptf_b, iface_b, dut_b))

    _apply_mac_move_guard_config(duthost, MAC_MOVE_GUARD_CONFIG)
    logger.info("Applied MAC_MOVE_GUARD config: {}".format(MAC_MOVE_GUARD_CONFIG))

    pid = None
    try:
        pid = _start_storm_sender(ptfhost, iface_a, iface_b, router_mac)
        logger.info("MAC-move storm sender started on ptfhost (pid={})".format(pid))

        # Phase 1: wait for the guard to disable one of the two ports.
        pytest_assert(
            wait_until(MMG_TIMEOUT, 1, 0,
                       lambda: bool(_disabled_ports(duthost, candidate_ports))),
            "MAC_MOVE_GUARD did not disable any of {} within {}s"
            .format(candidate_ports, MMG_TIMEOUT)
        )
        first_disabled = _disabled_ports(duthost, candidate_ports)
        # The guard disables exactly one of the two ports on which the moves are seen.
        disabled_port = first_disabled[0]
        disable_time = time.time()
        logger.info("MAC_MOVE_GUARD disabled port: {}".format(disabled_port))

        # Phase 2: stop the storm and verify the disabled port auto-recovers
        # after action_interval. The storm is paused so the recovery window is
        # observable - otherwise the per-MAC threshold would be re-crossed
        # within milliseconds of the port coming back up.
        _stop_storm_sender(ptfhost, pid)
        pid = None
        recovery_remaining = max(
            5, MMG_TIMEOUT - int(time.time() - disable_time))
        pytest_assert(
            wait_until(recovery_remaining, 2, 0,
                       lambda: _get_port_oper_status(duthost, disabled_port) == 'up'),
            "Port {} did not recover to oper-up within {}s of being disabled"
            .format(disabled_port, MMG_TIMEOUT)
        )
        logger.info("Port {} recovered to oper-up after action_interval"
                    .format(disabled_port))
    finally:
        if pid is not None:
            _stop_storm_sender(ptfhost, pid)
        tail = ptfhost.shell("tail -n 20 {} || true".format(STORM_SENDER_LOG),
                             module_ignore_errors=True)
        logger.info("storm sender log tail:\n{}".format(tail.get('stdout', '')))
        _remove_mac_move_guard_config(duthost)
        # Force any guard-disabled port back to admin-up so subsequent tests see a clean state.
        for p in candidate_ports:
            duthost.shell("config interface startup {}".format(p),
                          module_ignore_errors=True)
        fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)


def test_fdb_mac_move_guard_disable_mac_move(ptfadapter, duthosts, fanouthosts,
                                             rand_one_dut_hostname, ptfhost, tbinfo):
    """
    Validate the MAC_MOVE_GUARD DISABLE_MAC_MOVE action:

      1. Configure MAC_MOVE_GUARD with action=DISABLE_MAC_MOVE,
         threshold=100, detect_interval=10s, action_interval=120s.
      2. Drive a MAC-move storm so the per-MAC move count crosses the threshold.
      3. Stop the storm and read the FDB binding for one of the storm MACs;
         this is the port the guard pinned it to.
      4. Send a single ARP from the OPPOSITE port using the same MAC; verify
         the FDB entry remains on the pinned port (move suppressed).
      5. After action_interval expires, send another ARP from the OPPOSITE
         port; verify the FDB entry now follows to that port (pin released).
    """

    fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)

    duthost = duthosts[rand_one_dut_hostname]
    conf_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    router_mac = duthost.facts['router_mac']

    ptf_a, ptf_b, vlan_id, iface_a, iface_b, dut_a, dut_b = \
        _select_two_vlan_member_ptf_ports(conf_facts, ptfhost, mg_facts)
    parent_a = _vlan_member_parent(conf_facts, dut_a)
    parent_b = _vlan_member_parent(conf_facts, dut_b)
    pytest_assert(parent_a != parent_b,
                  "Selected VLAN members map to the same FDB-visible interface "
                  "({}); cannot exercise MAC moves".format(parent_a))
    logger.info("DISABLE_MAC_MOVE test on vlan {}: PTF {} ({}) <-> DUT {} (fdb={}), "
                "PTF {} ({}) <-> DUT {} (fdb={})"
                .format(vlan_id, ptf_a, iface_a, dut_a, parent_a,
                        ptf_b, iface_b, dut_b, parent_b))

    ptfadapter.reinit()

    # Pre-flight sanity (negative control): with no guard configured, prove the
    # rig can actually move a MAC between the two PTF ports. If this fails, the
    # downstream pin check would pass for the wrong reason (no move was ever
    # possible to begin with).
    sanity_mac = IntToMac(MacToInt(STORM_MAC_BASE) + STORM_NUM_MACS + 1)
    _learn_mac_on_port(ptfadapter, duthost, sanity_mac, ptf_a, parent_a,
                       router_mac, vlan_id, "pre-flight learn on parent_a")
    _learn_mac_on_port(ptfadapter, duthost, sanity_mac, ptf_b, parent_b,
                       router_mac, vlan_id, "pre-flight move to parent_b")
    logger.info("Pre-flight sanity passed: MAC {} freely moves between {} and {}"
                .format(sanity_mac, parent_a, parent_b))

    _apply_mac_move_guard_config(duthost, DISABLE_MAC_MOVE_GUARD_CONFIG)
    logger.info("Applied MAC_MOVE_GUARD config: {}".format(DISABLE_MAC_MOVE_GUARD_CONFIG))

    pid = None
    try:
        pid = _start_storm_sender(ptfhost, iface_a, iface_b, router_mac)
        logger.info("MAC-move storm sender started on ptfhost (pid={})".format(pid))

        # Storm long enough for the per-MAC threshold to be crossed for all MACs.
        time.sleep(MAC_MOVE_GUARD_DETECT_INTERVAL + 5)
        _stop_storm_sender(ptfhost, pid)
        pid = None
        pin_time = time.time()
        # Allow FDB to settle after the storm stops.
        time.sleep(FDB_POPULATE_SLEEP_TIMEOUT)

        # Find a storm MAC that is now pinned to one of our two FDB-visible ports.
        target_mac, pinned_port = None, None
        for i in range(STORM_NUM_MACS):
            mac = IntToMac(MacToInt(STORM_MAC_BASE) + i)
            port = _fdb_port_for_mac(duthost, mac)
            if port in (parent_a, parent_b):
                target_mac, pinned_port = mac, port
                break
        pytest_assert(target_mac is not None,
                      "None of the storm MACs are bound to {}/{} in FDB after storm"
                      .format(parent_a, parent_b))
        logger.info("MAC {} pinned to FDB port {}".format(target_mac, pinned_port))

        # Pick the OPPOSITE port for the move attempts.
        if pinned_port == parent_a:
            other_ptf, other_parent = ptf_b, parent_b
        else:
            other_ptf, other_parent = ptf_a, parent_a

        # Phase 1: try to move the MAC; it must remain pinned. Send a small
        # burst (not a single packet) so that one drop or a slow FDB update
        # cannot make the test pass for the wrong reason.
        ptfadapter.dataplane.flush()
        for _ in range(MMG_MOVE_ATTEMPT_BURST):
            send_arp_request(ptfadapter, other_ptf, target_mac, router_mac, vlan_id)
            time.sleep(0.1)
        time.sleep(MMG_FDB_SETTLE_SECONDS)
        port_after_attempt = _fdb_port_for_mac(duthost, target_mac)
        pytest_assert(
            port_after_attempt == pinned_port,
            "MAC {} should remain pinned to {} (DISABLE_MAC_MOVE) but FDB shows {} "
            "after burst of {} ARPs from {}"
            .format(target_mac, pinned_port, port_after_attempt,
                    MMG_MOVE_ATTEMPT_BURST, other_parent)
        )
        logger.info("MAC {} remains pinned to {} after burst of {} ARPs from {}"
                    .format(target_mac, pinned_port, MMG_MOVE_ATTEMPT_BURST, other_parent))

        # Phase 2: wait for action_interval to expire, then verify the pin is released.
        elapsed = time.time() - pin_time
        remaining = DISABLE_MAC_MOVE_ACTION_INTERVAL - elapsed + 5
        if remaining > 0:
            logger.info("Sleeping {:.0f}s for action_interval to elapse".format(remaining))
            time.sleep(remaining)

        for _ in range(MMG_MOVE_ATTEMPT_BURST):
            send_arp_request(ptfadapter, other_ptf, target_mac, router_mac, vlan_id)
            time.sleep(0.1)
        pytest_assert(
            wait_until(20, 1, 0,
                       lambda: _fdb_port_for_mac(duthost, target_mac) == other_parent),
            "MAC {} did not move to {} after action_interval; FDB shows {}"
            .format(target_mac, other_parent, _fdb_port_for_mac(duthost, target_mac))
        )
        logger.info("MAC {} moved to {} after pin release".format(target_mac, other_parent))
    finally:
        if pid is not None:
            _stop_storm_sender(ptfhost, pid)
        tail = ptfhost.shell("tail -n 20 {} || true".format(STORM_SENDER_LOG),
                             module_ignore_errors=True)
        logger.info("storm sender log tail:\n{}".format(tail.get('stdout', '')))
        _remove_mac_move_guard_config(duthost)
        fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)


def _parse_sonic_db_cli_hash(raw):
    """Parse the stdout of ``sonic-db-cli ... HGETALL``.

    sonic-db-cli emits HGETALL as a Python-dict repr (single-quoted, see
    ``formatDictReply`` in swss-common/redisreply.cpp), e.g.
    ``{'action': 'DISABLE_LEARN_ON_MAC', 'acl_entry_id': '0x8000abcd'}``.
    That is NOT valid JSON, so ``json.loads`` would fail. ``ast.literal_eval``
    handles both Python dict repr and JSON-like input (for hash field values,
    which are always strings here, JSON happens to be a Python literal too).
    Returns an empty dict on parse failure (raw is also logged so the caller
    can see what came back).
    """
    s = (raw or '').strip()
    if not s:
        return {}
    try:
        val = ast.literal_eval(s)
    except (ValueError, SyntaxError):
        logger.warning("Could not parse sonic-db-cli hash output: %r", s[:500])
        return {}
    return val if isinstance(val, dict) else {}


def _state_db_bad_macs(duthost):
    """Return a dict {key: hgetall_dict} for every row currently present in
    STATE_DB:MAC_MOVE_GUARD_BAD_MAC_TABLE. Empty dict if nothing is tracked.

    The key is the STATE_DB row key without the table prefix, e.g.
    ``0x10000000000be:02:11:22:33:00:00``.
    """
    keys_res = duthost.shell(
        "sonic-db-cli STATE_DB KEYS '{}|*'".format(MMG_BAD_MAC_TABLE),
        module_ignore_errors=True)
    out = (keys_res.get('stdout') or '').strip()
    if not out:
        return {}
    rows = {}
    for full_key in out.splitlines():
        full_key = full_key.strip()
        if not full_key.startswith(MMG_BAD_MAC_TABLE + "|"):
            continue
        row_key = full_key[len(MMG_BAD_MAC_TABLE) + 1:]
        hg = duthost.shell(
            'sonic-db-cli STATE_DB HGETALL "{}"'.format(full_key),
            module_ignore_errors=True)
        rows[row_key] = _parse_sonic_db_cli_hash(hg.get('stdout'))
    return rows


def _asic_db_key_exists(duthost, key):
    res = duthost.shell(
        'sonic-db-cli ASIC_DB EXISTS "{}"'.format(key),
        module_ignore_errors=True)
    return (res.get('stdout') or '').strip() == '1'


def _asic_db_hgetall(duthost, key):
    res = duthost.shell(
        'sonic-db-cli ASIC_DB HGETALL "{}"'.format(key),
        module_ignore_errors=True)
    return _parse_sonic_db_cli_hash(res.get('stdout'))


def _syslog_line_count(duthost):
    res = duthost.shell("sudo wc -l /var/log/syslog | awk '{print $1}'",
                        module_ignore_errors=True)
    try:
        return int((res.get('stdout') or '0').strip())
    except ValueError:
        return 0


def _count_syslog_matches_in_range(duthost, start_line, end_line, regex):
    """Count /var/log/syslog lines in the inclusive 1-indexed range
    [start_line, end_line] that match ``regex`` (a precompiled
    :class:`re.Pattern`).

    Returns 0 if the range is empty (``end_line < start_line``). If the
    file rotated and ``end_line`` is now below ``start_line`` (line
    numbering reset), the caller should handle that by re-anchoring; this
    helper just reports zero matches for the empty range.

    The regex is applied in Python rather than via ``grep`` on the DUT so
    the pattern text never appears in the remote shell command. SONiC's
    sudo / sshd audit logging echoes executed commands back into
    /var/log/syslog; if the pattern were on the command line, every poll
    would log its own search string and the next poll would match it,
    producing a spurious +1 in the match count per iteration.
    """
    if end_line < start_line:
        return 0
    cmd = "sudo sed -n '{},{}p' /var/log/syslog 2>/dev/null".format(
        start_line, end_line)
    res = duthost.shell(cmd, module_ignore_errors=True)
    out = res.get('stdout') or ''
    return sum(1 for line in out.splitlines() if regex.search(line))


#  Quiescence window: once the ACL entry takes effect, orchagent should stop
#  emitting "BAD MAC ... continues to move" for the tracked MAC. The test
#  polls syslog and considers the system quiescent if no new matching lines
#  appear for this many consecutive seconds.
LEARN_DISABLE_LOG_QUIESCE_SECONDS = 60

# Upper bound on how long to wait for orchagent to reach the quiescent state
# while the storm is still running. Sized for slow platforms and long FDB
# notification queues; well below DISABLE_LEARN_ON_MAC_ACTION_INTERVAL so the
# bad MAC cannot age out underneath us.
LEARN_DISABLE_QUIESCE_TIMEOUT_SECONDS = 300

# Polling cadence for the quiescence loop.
LEARN_DISABLE_QUIESCE_POLL_SECONDS = 5


def test_fdb_mac_move_guard_disable_mac_learning(duthosts, fanouthosts,
                                                 rand_one_dut_hostname,
                                                 ptfhost, tbinfo):
    """
    Validate the MAC_MOVE_GUARD DISABLE_LEARN_ON_MAC_WITH_ACL action:

      1. Configure MAC_MOVE_GUARD with action=DISABLE_LEARN_ON_MAC_WITH_ACL
         and a long action_interval so the bad MAC cannot age out while we
         observe orchagent behaviour.
      2. Drive a MAC-move storm so a per-MAC threshold is crossed and at
         least one bad MAC is published to STATE_DB.
      3. Verify the shared learn-disable ACL table exists in ASIC_DB with
         the expected stage / match fields / action.
      4. Verify the per-MAC ACL entry referenced by the STATE_DB row exists
         in ASIC_DB and matches the bad MAC / VLAN.
      5. With the storm still running, poll syslog for "BAD MAC ...
         continues to move" lines for the tracked MAC and wait until no new
         such lines have appeared for a full quiescence window. This proves
         that once the ACL entry takes effect, orchagent stops re-flagging
         the MAC.
      6. Stop the storm. Reconfigure MAC_MOVE_GUARD with a short
         action_interval so the bad-MAC tracking entry / ACL entry age out
         promptly, then verify both have been removed.
    """

    fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)

    duthost = duthosts[rand_one_dut_hostname]
    conf_facts = duthost.config_facts(host=duthost.hostname,
                                      source="persistent")['ansible_facts']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    router_mac = duthost.facts['router_mac']

    ptf_a, ptf_b, _selected_vlan_id, iface_a, iface_b, dut_a, dut_b = \
        _select_two_vlan_member_ptf_ports(conf_facts, ptfhost, mg_facts)
    # The storm tags frames with STORM_VLAN_TAG; the DUT classifies them into
    # that VLAN at ingress (provided the ports are tagged members), so all FDB
    # moves, STATE_DB rows, and the ACL entry are scoped to STORM_VLAN_TAG -
    # not whatever VLAN port-selection happened to pick.
    vlan_id = STORM_VLAN_TAG
    vlan100_members = sorted(set([
        _vlan_member_parent(conf_facts, dut_a),
        _vlan_member_parent(conf_facts, dut_b),
    ]))
    logger.info("DISABLE_LEARN_ON_MAC test on vlan %d (tagged), PTF %d (%s) <-> DUT %s, "
                "PTF %d (%s) <-> DUT %s; tagged members: %s",
                vlan_id, ptf_a, iface_a, dut_a, ptf_b, iface_b, dut_b,
                vlan100_members)

    _add_vlan_with_tagged_members(duthost, vlan_id, vlan100_members)
    logger.info("Created VLAN %d with tagged members %s", vlan_id, vlan100_members)

    _apply_mac_move_guard_config(duthost, DISABLE_LEARN_ON_MAC_GUARD_CONFIG)
    logger.info("Applied MAC_MOVE_GUARD config: %s",
                DISABLE_LEARN_ON_MAC_GUARD_CONFIG)

    # Disable rsyslog rate-limiting in swss container(s) so the quiet-tail
    # assertion in PHASE 4 is not skewed by dropped "continues to move" lines.
    rate_limit_edited = disable_swss_rsyslog_rate_limit(duthost)
    logger.info("Disabled swss rsyslog rate-limiting on containers: %s",
                rate_limit_edited)

    pid = None
    try:
        pid = _start_storm_sender(ptfhost, iface_a, iface_b, router_mac,
                                  vlan_tag=STORM_VLAN_TAG)
        logger.info("MAC-move storm sender started on ptfhost (pid=%s, vlan_tag=%d)",
                    pid, STORM_VLAN_TAG)

        # Phase 1: wait for at least one bad MAC to be published to STATE_DB.
        logger.info("===== PHASE 1: waiting (up to %ds) for a bad MAC to "
                    "appear in STATE_DB:%s =====",
                    MMG_TIMEOUT, MMG_BAD_MAC_TABLE)
        pytest_assert(
            wait_until(MMG_TIMEOUT, 2, 0,
                       lambda: bool(_state_db_bad_macs(duthost))),
            "MAC_MOVE_GUARD did not publish any bad MAC to STATE_DB:{} "
            "within {}s".format(MMG_BAD_MAC_TABLE, MMG_TIMEOUT)
        )
        rows = _state_db_bad_macs(duthost)
        # Pick a DISABLE_LEARN_ON_MAC_WITH_ACL row that actually has an ACL
        # entry OID.
        target_row_key, target_row = None, None
        for k, v in rows.items():
            if v.get('action') == 'DISABLE_LEARN_ON_MAC_WITH_ACL' \
                    and v.get('acl_entry_id') \
                    and v.get('acl_entry_id') != '0x0':
                target_row_key, target_row = k, v
                break
        pytest_assert(
            target_row is not None,
            "No DISABLE_LEARN_ON_MAC_WITH_ACL bad-MAC row with a non-null "
            "acl_entry_id found in STATE_DB:{}; rows={}"
            .format(MMG_BAD_MAC_TABLE, rows)
        )
        # STATE_DB row key is "<bv_id_hex>:<mac>"; the MAC is everything after
        # the first colon, lower-case (matches MacAddress::to_string()).
        target_mac = target_row_key.split(":", 1)[1]
        acl_table_oid = target_row.get('acl_table_id')
        acl_entry_oid = target_row.get('acl_entry_id')
        logger.info("Bad MAC %s tracked with acl_table_id=%s acl_entry_id=%s",
                    target_mac, acl_table_oid, acl_entry_oid)
        logger.info("===== PHASE 1: DONE (bad MAC selected: %s) =====",
                    target_mac)

        # Phase 2: verify the shared ACL table exists in ASIC_DB with the
        # expected match fields and FLOOD action.
        logger.info("===== PHASE 2: verifying ACL table %s in ASIC_DB =====",
                    acl_table_oid)
        # ASIC_DB encodes SAI object IDs as "oid:0x...." (see sai_serialize_object_id)
        # whereas MAC_MOVE_GUARD stores them in STATE_DB as bare hex.
        table_key = ("ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE:oid:" +
                     acl_table_oid)
        pytest_assert(_asic_db_key_exists(duthost, table_key),
                      "ACL table {} not present in ASIC_DB".format(table_key))
        table_attrs = _asic_db_hgetall(duthost, table_key)
        # SET_DO_NOT_LEARN is only supported at PRE_INGRESS; macmoveguardorch
        # programs the table with SAI_ACL_STAGE_PRE_INGRESS and binds it to
        # SAI_SWITCH_ATTR_PRE_INGRESS_ACL.
        pytest_assert(
            table_attrs.get('SAI_ACL_TABLE_ATTR_ACL_STAGE')
            == 'SAI_ACL_STAGE_PRE_INGRESS',
            "ACL table {} stage is not PRE_INGRESS: {}"
            .format(table_key, table_attrs)
        )
        for fld in ('SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC',
                    'SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID'):
            pytest_assert(
                table_attrs.get(fld) == 'true',
                "ACL table {} missing match field {}: {}"
                .format(table_key, fld, table_attrs)
            )
        # macmoveguardorch installs the table with action_list =
        # { SAI_ACL_ACTION_TYPE_SET_DO_NOT_LEARN }.
        action_type_list = table_attrs.get(
            'SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST', '')
        pytest_assert(
            'SAI_ACL_ACTION_TYPE_SET_DO_NOT_LEARN' in action_type_list,
            "ACL table {} action-type list missing SET_DO_NOT_LEARN: {}"
            .format(table_key, action_type_list)
        )
        logger.info("===== PHASE 2: DONE (ACL table attributes verified) =====")

        # Phase 3: verify the per-MAC ACL entry exists in ASIC_DB and matches
        # the bad MAC / VLAN.
        logger.info("===== PHASE 3: verifying ACL entry %s in ASIC_DB =====",
                    acl_entry_oid)
        entry_key = ("ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:oid:" +
                     acl_entry_oid)
        pytest_assert(_asic_db_key_exists(duthost, entry_key),
                      "ACL entry {} not present in ASIC_DB".format(entry_key))
        entry_attrs = _asic_db_hgetall(duthost, entry_key)
        # SAI_ACL_ENTRY_ATTR_TABLE_ID is serialized as "oid:0x..." in ASIC_DB.
        expected_table_id = "oid:" + acl_table_oid
        pytest_assert(
            entry_attrs.get('SAI_ACL_ENTRY_ATTR_TABLE_ID') == expected_table_id,
            "ACL entry {} TABLE_ID {} != STATE_DB acl_table_id {}"
            .format(entry_key,
                    entry_attrs.get('SAI_ACL_ENTRY_ATTR_TABLE_ID'),
                    expected_table_id)
        )
        # SRC_MAC attribute is stored as "<mac>&mask=<mask>"; just check the
        # target MAC appears in it.
        src_mac_attr = entry_attrs.get(
            'SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC', '')
        pytest_assert(
            target_mac.lower() in src_mac_attr.lower(),
            "ACL entry {} SRC_MAC field {} does not match bad MAC {}"
            .format(entry_key, src_mac_attr, target_mac)
        )
        vlan_attr = entry_attrs.get(
            'SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID', '')
        pytest_assert(
            str(vlan_id) in vlan_attr,
            "ACL entry {} OUTER_VLAN_ID field {} does not match vlan {}"
            .format(entry_key, vlan_attr, vlan_id)
        )
        pytest_assert(
            'SAI_ACL_ENTRY_ATTR_ACTION_SET_DO_NOT_LEARN' in entry_attrs,
            "ACL entry {} missing ACTION_SET_DO_NOT_LEARN: {}"
            .format(entry_key, entry_attrs)
        )
        logger.info("ACL entry %s for bad MAC %s verified in ASIC_DB",
                    acl_entry_oid, target_mac)
        logger.info("===== PHASE 3: DONE (ACL entry attributes verified) =====")

        # Phase 4: with the storm still running, poll syslog and wait until
        # orchagent has emitted no new "BAD MAC ... continues to move" lines
        # for the tracked MAC for a full LEARN_DISABLE_LOG_QUIESCE_SECONDS
        # window. That proves the ACL entry has taken effect.
        logger.info("===== PHASE 4: waiting for orchagent to go quiet on "
                    "'continues to move' for %s (no new line for %ds; "
                    "overall timeout %ds, storm still running) =====",
                    target_mac, LEARN_DISABLE_LOG_QUIESCE_SECONDS,
                    LEARN_DISABLE_QUIESCE_TIMEOUT_SECONDS)

        log_regex = re.compile("BAD MAC " + target_mac + ".*continues to move")
        # Incremental cursor: only the new line range [last_line+1, cur_line]
        # is fetched each iteration, so we transfer just the syslog delta
        # rather than re-pulling everything since the baseline.
        last_line = _syslog_line_count(duthost)
        match_total = 0
        last_change_ts = time.time()
        quiesce_deadline = last_change_ts + \
            LEARN_DISABLE_QUIESCE_TIMEOUT_SECONDS
        quiesced = False
        while time.time() < quiesce_deadline:
            time.sleep(LEARN_DISABLE_QUIESCE_POLL_SECONDS)
            cur_line = _syslog_line_count(duthost)
            # Guard against log rotation (cur_line < last_line). Treat the
            # new file's lines from 1..cur_line as the next range to scan;
            # we may miss anything that was in the rotated-away tail, but
            # we won't run sed against bogus line numbers.
            if cur_line < last_line:
                logger.warning("syslog appears to have rotated "
                               "(line count %d -> %d); re-anchoring",
                               last_line, cur_line)
                last_line = 0
            new_matches = _count_syslog_matches_in_range(
                duthost, last_line + 1, cur_line, log_regex)
            last_line = cur_line
            now = time.time()
            if new_matches > 0:
                match_total += new_matches
                logger.info("'continues to move' for %s: +%d new "
                            "(total %d, elapsed %.0fs)", target_mac,
                            new_matches, match_total,
                            now - last_change_ts)
                last_change_ts = now
                continue
            silent_for = now - last_change_ts
            logger.info("'continues to move' for %s: no new matches "
                        "(total %d, silent for %.0fs/%ds)",
                        target_mac, match_total, silent_for,
                        LEARN_DISABLE_LOG_QUIESCE_SECONDS)
            if silent_for >= LEARN_DISABLE_LOG_QUIESCE_SECONDS:
                quiesced = True
                break
        pytest_assert(
            quiesced,
            "Orchagent never went quiet on 'continues to move' for {} "
            "within {}s (total matches {}, silent for {:.0f}s)".format(
                target_mac, LEARN_DISABLE_QUIESCE_TIMEOUT_SECONDS,
                match_total, time.time() - last_change_ts)
        )
        logger.info("===== PHASE 4: DONE (no new 'continues to move' for "
                    "%s for %ds) =====", target_mac,
                    LEARN_DISABLE_LOG_QUIESCE_SECONDS)

        # Phase 5: stop the storm, then reconfigure MAC_MOVE_GUARD with a
        # short action_interval so the tracking entry / ACL entry age out
        # promptly, and verify they are removed.
        logger.info("===== PHASE 5: stopping storm sender (pid=%s) =====",
                    pid)
        _stop_storm_sender(ptfhost, pid)
        pid = None
        logger.info("===== PHASE 5: DONE (storm stopped) =====")

        logger.info("===== PHASE 6: reapplying MAC_MOVE_GUARD with "
                    "action_interval=%ds and waiting for cleanup =====",
                    DISABLE_LEARN_ON_MAC_CLEANUP_ACTION_INTERVAL)
        _apply_mac_move_guard_config(
            duthost, DISABLE_LEARN_ON_MAC_CLEANUP_GUARD_CONFIG)
        logger.info("Reapplied MAC_MOVE_GUARD config: %s",
                    DISABLE_LEARN_ON_MAC_CLEANUP_GUARD_CONFIG)

        # Allow the new action_interval (plus a generous grace period for
        # the orchagent recovery tick) for the entry to age out.
        cleanup_timeout = DISABLE_LEARN_ON_MAC_CLEANUP_ACTION_INTERVAL + 60
        pytest_assert(
            wait_until(cleanup_timeout, 5, 0,
                       lambda: not _asic_db_key_exists(duthost, entry_key)),
            "ACL entry {} for bad MAC {} was not removed from ASIC_DB "
            "within {}s after reconfiguring action_interval={}s"
            .format(entry_key, target_mac, cleanup_timeout,
                    DISABLE_LEARN_ON_MAC_CLEANUP_ACTION_INTERVAL)
        )
        pytest_assert(
            wait_until(cleanup_timeout, 5, 0,
                       lambda: target_row_key not in _state_db_bad_macs(duthost)),
            "Bad-MAC row {} was not removed from STATE_DB:{} within {}s "
            "after reconfiguring action_interval={}s".format(
                target_row_key, MMG_BAD_MAC_TABLE, cleanup_timeout,
                DISABLE_LEARN_ON_MAC_CLEANUP_ACTION_INTERVAL)
        )
        logger.info("ACL entry %s and STATE_DB row %s cleaned up after "
                    "reconfigured action_interval", acl_entry_oid,
                    target_row_key)
        logger.info("===== PHASE 6: DONE (cleanup verified) =====")
    finally:
        if pid is not None:
            _stop_storm_sender(ptfhost, pid)
        tail = ptfhost.shell("tail -n 20 {} || true".format(STORM_SENDER_LOG),
                             module_ignore_errors=True)
        logger.info("storm sender log tail:\n%s", tail.get('stdout', ''))
        _remove_mac_move_guard_config(duthost)
        restore_swss_rsyslog_rate_limit(duthost, rate_limit_edited)
        _remove_vlan_with_tagged_members(duthost, vlan_id, vlan100_members)
        fdb_cleanup(duthosts, rand_one_dut_hostname, fanouthosts)
