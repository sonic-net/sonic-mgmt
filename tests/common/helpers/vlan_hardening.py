"""
Shared L2 hardening helpers for topology-aware port handling, VLAN IDs, log ignores, and PortChannel settling.
"""
import logging
import re
import shlex

import pytest
import ptf.testutils as testutils

from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# Common to all L2 hardening tests: VLAN member add/del churn is known to
# trigger this benign orchagent message (same ignore-regex used in
# tests/vlan/test_vlan.py).
BASE_LOGANALYZER_IGNORE_REGEX = [
    ".*ERR swss#orchagent: :- update: Failed to get port by bridge port ID.*",
]

# Ignore transient Broadcom-DNX syncd errors during PortChannel membership transitions.
DNX_PORTCHANNEL_CHURN_IGNORE_REGEX = [
    ".*ERR syncd#syncd: .*_brcm_sai_dnx_irpp_port_core_get.*getting core and pp port failed.*",
    ".*ERR syncd#syncd: .*_brcm_sai_dnx_pg_stat_get.*port pp_port core get failed.*",
    ".*ERR syncd#syncd: .*_brcm_sai_dnx_get_ingress_priority_group_stats_mode.*PG stat get failed.*",
    ".*ERR syncd#syncd: :- collectData: Failed to get stats of Priority Group Counter.*",
    ".*ERR syncd#syncd: .*brcm_sai_fdb_event_handler_for_multi_die_system.*[Aa]ging FDB.*",
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    # Ignore benign orchagent bridge-port churn and transient Broadcom-DNX syncd noise during PortChannel transitions.
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(
            BASE_LOGANALYZER_IGNORE_REGEX + DNX_PORTCHANNEL_CHURN_IGNORE_REGEX)

    yield


def get_config_facts(duthost):
    # Fetch a fresh view of running CONFIG_DB as structured facts.
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


def state_db_vlan_member_tagging_mode(asic, vlan_key, port):
    # Return the STATE_DB tagging mode for a VLAN member, or None if not present/programmed yet.
    res = asic.run_redis_cli_cmd("-n 6 hget \"VLAN_MEMBER_TABLE|{}|{}\" tagging_mode".format(vlan_key, port))
    return res['stdout'].strip().strip('"') or None


def get_vlan_members(config_facts, vlan_name):
    # CONFIG_DB VLAN_MEMBER from config_facts is nested by VLAN name, not flat `Vlan|port` keys.
    return config_facts.get('VLAN_MEMBER', {}).get(vlan_name, {})


def pick_free_vlan_id(config_facts, candidate_range):
    # Return the first unused VLAN ID from `candidate_range`.
    existing = set()
    for vlan_name in config_facts.get('VLAN', {}):
        try:
            existing.add(int(vlan_name.replace('Vlan', '')))
        except ValueError:
            continue
    for candidate in candidate_range:
        if candidate not in existing:
            return candidate
    pytest.fail("Could not find a free VLAN id in range {}".format(candidate_range))


def wait_for_ports_up(duthost, ports, timeout=40, interval=2):
    # Wait until all ports are oper-up instead of using a fixed sleep, failing the test if they
    # never come up rather than letting callers proceed against a port that isn't ready.
    def _all_up():
        status = duthost.get_interfaces_status()
        return all(status.get(p, {}).get('oper', '').lower() == 'up' for p in ports)

    if not wait_until(timeout, interval, 0, _all_up):
        pytest.fail("Timed out waiting for ports {} to become oper-up after {}s".format(ports, timeout))


def verify_flood_to_all_ports(ptfadapter, pkt, ptf_indices, timeout=5):
    # Verify `pkt` reaches every expected PTF port without asserting on other traffic.
    for idx in ptf_indices:
        testutils.verify_packet(ptfadapter, pkt, idx, timeout=timeout)


def get_portchannel_for_port(mg_facts, port):
    # Return the PortChannel containing `port`, or None.
    for pc_name, pc_info in mg_facts['minigraph_portchannels'].items():
        if port in pc_info['members']:
            return pc_name
    return None


def get_routed_ip_prefixes(interface_table, port):
    # Return the CONFIG_DB INTERFACE-table IP prefix keys configured on `port`.
    return [key for key in interface_table.get(port, {}) if '/' in key]


def run_in_asic_netns(duthost, asic, script):
    # Run a shell script in an ASIC's namespace when needed, otherwise in the default namespace.
    if asic.namespace != DEFAULT_NAMESPACE:
        return duthost.shell("sudo ip netns exec {} bash -c {}".format(asic.namespace, shlex.quote(script)))
    return duthost.shell(script)


def _find_bridge_port(duthost, asic, port):
    # Return (bridge_port_oid, admin_state) for the ASIC_DB BRIDGE_PORT object bound to `port`,
    # or (None, None) if it can't be resolved.
    oid_res = asic.run_redis_cli_cmd("-n 2 hget COUNTERS_PORT_NAME_MAP {}".format(port))
    oid = oid_res['stdout'].strip().strip('"')
    if not oid:
        logger.warning("Could not resolve SAI OID for port %s via COUNTERS_PORT_NAME_MAP", port)
        return None, None

    # Use SCAN/read -r and HMGET to avoid blocking Redis, parsing keys incorrectly, and extra round trips.
    scan_cmd = (
        "cursor=0; "
        "while :; do "
        "res=$(redis-cli -n 1 SCAN \"$cursor\" MATCH 'ASIC_STATE:SAI_OBJECT_TYPE_BRIDGE_PORT:*' COUNT 100); "
        "cursor=$(echo \"$res\" | head -n1); "
        "echo \"$res\" | tail -n +2 | while IFS= read -r k; do "
        "[ -z \"$k\" ] && continue; "
        "vals=$(redis-cli -n 1 HMGET \"$k\" SAI_BRIDGE_PORT_ATTR_PORT_ID SAI_BRIDGE_PORT_ATTR_ADMIN_STATE); "
        "p=$(printf '%s\\n' \"$vals\" | sed -n 1p); "
        "a=$(printf '%s\\n' \"$vals\" | sed -n 2p); "
        "echo \"$k|$p|$a\"; "
        "done; "
        "[ \"$cursor\" = \"0\" ] && break; "
        "done"
    )
    scan_res = run_in_asic_netns(duthost, asic, scan_cmd)

    for line in scan_res['stdout_lines']:
        parts = line.split('|')
        if len(parts) != 3:
            continue
        key, port_id, admin_state = parts
        if port_id.strip() == oid:
            # key looks like "ASIC_STATE:SAI_OBJECT_TYPE_BRIDGE_PORT:oid:0x...".
            bridge_port_oid = key.split("SAI_OBJECT_TYPE_BRIDGE_PORT:", 1)[-1].strip()
            admin_state = admin_state.strip().lower()
            if admin_state == 'true':
                return bridge_port_oid, True
            elif admin_state == 'false':
                return bridge_port_oid, False
            logger.warning(
                "Unexpected SAI_BRIDGE_PORT_ATTR_ADMIN_STATE value %r for port %s (oid %s)",
                admin_state, port, oid)
            return bridge_port_oid, None

    logger.warning("No BRIDGE_PORT object in ASIC_DB is bound to port %s (oid %s)", port, oid)
    return None, None


def get_bridge_port_admin_state(duthost, asic, port):
    # Return ASIC_DB bridge-port admin state; wait for this before relying on FDB learning after VLAN member creation.
    _bridge_port_oid, admin_state = _find_bridge_port(duthost, asic, port)
    return admin_state


def _get_vlan_oid(duthost, asic, vlan_id):
    # Return the ASIC_DB OID (raw "oid:0x...") of the VLAN object whose SAI_VLAN_ATTR_VLAN_ID
    # equals `vlan_id`, or None if it can't be found.
    scan_cmd = (
        "cursor=0; "
        "while :; do "
        "res=$(redis-cli -n 1 SCAN \"$cursor\" MATCH 'ASIC_STATE:SAI_OBJECT_TYPE_VLAN:*' COUNT 100); "
        "cursor=$(echo \"$res\" | head -n1); "
        "echo \"$res\" | tail -n +2 | while IFS= read -r k; do "
        "[ -z \"$k\" ] && continue; "
        "vid=$(redis-cli -n 1 hget \"$k\" SAI_VLAN_ATTR_VLAN_ID); "
        "echo \"$k|$vid\"; "
        "done; "
        "[ \"$cursor\" = \"0\" ] && break; "
        "done"
    )
    scan_res = run_in_asic_netns(duthost, asic, scan_cmd)
    for line in scan_res['stdout_lines']:
        parts = line.split('|')
        if len(parts) != 2:
            continue
        key, vid = parts
        if vid.strip() == str(vlan_id):
            return key.split("SAI_OBJECT_TYPE_VLAN:", 1)[-1].strip()
    return None


def mac_learned_on_port(duthost, asic, port, mac, vlan_id):
    # Check ASIC_DB directly for MAC learning on `port` within `vlan_id`; avoids unstable CLI
    # parsing and lagging STATE_DB. The FDB key embeds the VLAN's bvid OID, which is checked
    # against Vlan{vlan_id}'s own OID so a MAC learned on the same port in a *different* VLAN
    # (tagged ports can belong to several at once) doesn't produce a false positive.
    bridge_port_oid, _admin_state = _find_bridge_port(duthost, asic, port)
    if bridge_port_oid is None:
        return False

    vlan_oid = _get_vlan_oid(duthost, asic, vlan_id)
    if vlan_oid is None:
        return False

    mac_upper = mac.upper()
    scan_cmd = (
        "cursor=0; "
        "while :; do "
        "res=$(redis-cli -n 1 SCAN \"$cursor\" "
        "MATCH 'ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*\"mac\":\"{}\"*' COUNT 100); "
        "cursor=$(echo \"$res\" | head -n1); "
        "echo \"$res\" | tail -n +2 | while IFS= read -r k; do "
        "[ -z \"$k\" ] && continue; "
        "bp=$(redis-cli -n 1 hget \"$k\" SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID); "
        "echo \"$k|$bp\"; "
        "done; "
        "[ \"$cursor\" = \"0\" ] && break; "
        "done"
    ).format(mac_upper)
    scan_res = run_in_asic_netns(duthost, asic, scan_cmd)

    for line in scan_res['stdout_lines']:
        parts = line.split('|')
        if len(parts) != 2:
            continue
        key, bridge_port_id = parts
        if bridge_port_id.strip() != bridge_port_oid:
            continue
        bvid_match = re.search(r'"bvid":"(oid:0x[0-9a-fA-F]+)"', key)
        if bvid_match and bvid_match.group(1) == vlan_oid:
            return True

    return False


def _borrow_port_t0(duthost, exclude_ports):
    # Pick and borrow a current VLAN member port, saving exact membership for restore.
    config_facts = get_config_facts(duthost)
    vlan_members = config_facts.get('VLAN_MEMBER', {})

    for vlan_name, members in vlan_members.items():
        for port, member_info in members.items():
            if port in exclude_ports:
                continue
            vlan_id = vlan_name.replace('Vlan', '')
            tagging_mode = member_info.get('tagging_mode', 'untagged')
            return {
                "port": port,
                "kind": "t0_vlan_member",
                "orig_vlan_id": vlan_id,
                "orig_tagging_mode": tagging_mode,
            }

    return None


def _take_portchannel_member(duthost, asic, port, portchannel):
    # Remove `port` from `portchannel`, bring it up standalone, and roll back on failure.
    # Catches BaseException, not just Exception: wait_for_ports_up() now fails via pytest.fail(),
    # whose Failed exception is a BaseException, not an Exception -- narrower except here would
    # let that path skip rollback and strand the port outside its PortChannel on shared hardware.
    try:
        asic.config_portchannel_member(portchannel, port, "del")
        asic.startup_interface(port)
        wait_for_ports_up(duthost, [port])
    except BaseException:
        logger.error(
            "Failed while pulling %s out of PortChannel %s during borrow; attempting rollback.",
            port, portchannel)
        try:
            asic.config_portchannel_member(portchannel, port, "add")
        except Exception as restore_exc:
            logger.error(
                "Rollback re-add of %s to PortChannel %s also failed: %s; "
                "manual intervention may be required.", port, portchannel, restore_exc)
        raise
    return {"port": port, "kind": "t2_portchannel_member", "portchannel": portchannel}


def _take_routed_port(duthost, port, interface_table):
    # Remove routed IPs from `port` so it can be used as a plain L2 VLAN port.
    ip_prefixes = get_routed_ip_prefixes(interface_table, port)
    for prefix in ip_prefixes:
        duthost.shell("config interface ip remove {} {}".format(port, prefix))
    return {"port": port, "kind": "t2_routed_port", "ip_prefixes": ip_prefixes}


def port_sort_key(name):
    # Sort by the first embedded number so names like `Ethernet1/1` or `EthernetBP0`
    # (not just `Ethernet<int>`) sort sensibly instead of raising on int().
    match = re.search(r'(\d+)', name)
    return int(match.group(1)) if match else float('inf')


def _borrow_port_generic(duthost, tbinfo, enum_frontend_asic_index, exclude_ports):
    # Borrow an external test port using the least disruptive available option, restoring it afterward.
    asic = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asic.get_extended_minigraph_facts(tbinfo)
    external_ports = [p for p in mg_facts['minigraph_ports'].keys() if 'BP' not in p]
    ports = sorted(external_ports, key=port_sort_key)

    intf_status = asic.show_interface(command='status')['ansible_facts']['int_status']
    config_facts = get_config_facts(duthost)
    interface_table = config_facts.get('INTERFACE', {})
    # Use live CONFIG_DB PortChannel membership, not static minigraph data, for accurate sibling checks.
    live_pc_members = config_facts.get('PORTCHANNEL_MEMBER', {})
    port_to_portchannel = {
        port: pc_name
        for pc_name, members in live_pc_members.items()
        for port in members
    }

    candidates = [
        port for port in ports
        if port not in exclude_ports and intf_status.get(port, {}).get('admin_state') == 'up'
    ]

    def is_routed(port):
        return any('/' in key for key in interface_table.get(port, {}))

    # Tier 1: plain standalone port.
    for port in candidates:
        if is_routed(port) or port_to_portchannel.get(port):
            continue
        return {"port": port, "kind": "standalone_port"}

    # Tier 2: PortChannel member with at least one live sibling member.
    for port in candidates:
        if is_routed(port):
            continue
        portchannel = port_to_portchannel.get(port)
        if not portchannel:
            continue
        po_members = live_pc_members.get(portchannel, {})
        if len(po_members) <= 1:
            continue
        return _take_portchannel_member(duthost, asic, port, portchannel)

    # Tier 3: sole member of its PortChannel.
    for port in candidates:
        if is_routed(port):
            continue
        portchannel = port_to_portchannel.get(port)
        if not portchannel:
            continue
        logger.warning(
            "Borrowing %s, the ONLY member of PortChannel %s: no other safe candidate port was "
            "available on this DUT/topology. This will bounce PortChannel %s -- and any BGP/routing "
            "session over it -- for the duration of this test; it is restored at teardown.",
            port, portchannel, portchannel)
        return _take_portchannel_member(duthost, asic, port, portchannel)

    # Tier 4: bare routed port, no PortChannel at all.
    for port in candidates:
        if not is_routed(port):
            continue
        prefixes = get_routed_ip_prefixes(interface_table, port)
        logger.warning(
            "Borrowing %s by removing its routed IP(s) %s: no PortChannel-based candidate was "
            "available on this DUT/topology (e.g. a pure BGP-fabric testbed where every external "
            "port is a live point-to-point uplink). This drops whatever BGP/routing session rides "
            "on %s entirely for the duration of this test; its IP(s) are restored at teardown.",
            port, prefixes, port)
        return _take_routed_port(duthost, port, interface_table)

    return None


def borrow_port(duthost, tbinfo, enum_frontend_asic_index, exclude_ports=None):
    # Borrow one standalone VLAN test port for the current topology, or None if unavailable.
    exclude_ports = exclude_ports or set()
    if tbinfo['topo']['type'] == 't0':
        return _borrow_port_t0(duthost, exclude_ports)
    return _borrow_port_generic(duthost, tbinfo, enum_frontend_asic_index, exclude_ports)


def borrow_ports(duthost, tbinfo, enum_frontend_asic_index, count):
    # Borrow up to `count` distinct standalone test ports and return their descriptors.
    borrowed = []
    exclude_ports = set()
    for _ in range(count):
        descriptor = borrow_port(duthost, tbinfo, enum_frontend_asic_index, exclude_ports=exclude_ports)
        if descriptor is None:
            break
        borrowed.append(descriptor)
        exclude_ports.add(descriptor["port"])
    return borrowed


def release_prior_membership(duthost, borrowed):
    # Release any existing VLAN membership on a borrowed port before test use.
    if borrowed["kind"] == "t0_vlan_member":
        duthost.shell("config vlan member del {} {}".format(borrowed["orig_vlan_id"], borrowed["port"]))


def restore_borrowed_port(duthost, enum_frontend_asic_index, borrowed):
    # Best-effort restore of a borrowed port to its original VLAN or PortChannel state.
    if borrowed is None:
        return

    kind = borrowed["kind"]
    port = borrowed["port"]

    if kind == "t0_vlan_member":
        untagged_flag = " --untagged" if borrowed["orig_tagging_mode"] == "untagged" else ""
        duthost.shell(
            "config vlan member add {} {}{}".format(borrowed["orig_vlan_id"], port, untagged_flag),
            module_ignore_errors=True)
    elif kind == "standalone_port":
        pass
    elif kind == "t2_portchannel_member":
        portchannel = borrowed.get("portchannel")
        if portchannel:
            try:
                asic = duthost.asic_instance(enum_frontend_asic_index)
                asic.config_portchannel_member(portchannel, port, "add")
            except Exception as exc:
                logger.error(
                    "Failed to restore %s to PortChannel %s during teardown: %s; "
                    "manual intervention may be required.", port, portchannel, exc)
    elif kind == "t2_routed_port":
        for prefix in borrowed.get("ip_prefixes", []):
            duthost.shell("config interface ip add {} {}".format(port, prefix), module_ignore_errors=True)
    else:
        logger.error("Unknown borrowed-port kind %r for port %s during teardown; nothing restored.", kind, port)


def ptf_indices_for_ports(duthost, ptfhost, tbinfo, enum_frontend_asic_index, ports):
    # Map selected DUT ports to wired PTF port indices, omitting unwired ports.
    if tbinfo['topo']['type'] == 't0':
        conf_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
        port_index_map = conf_facts['port_index_map']
        # Treat an unpopulated ifaces_map as no wired ports instead of iterating over None.
        ptf_ifaces_map = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map") or {}
        return {
            port: port_index_map[port]
            for port in ports
            if port in port_index_map and port_index_map[port] in ptf_ifaces_map
        }

    asic = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asic.get_extended_minigraph_facts(tbinfo)
    ptf_indices = mg_facts['minigraph_ptf_indices']
    return {port: ptf_indices[port] for port in ports if port in ptf_indices}
