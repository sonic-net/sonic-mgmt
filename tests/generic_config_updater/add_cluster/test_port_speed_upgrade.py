"""
Test module for 100G -> 400G port speed upgrade via Generic Config Updater (GCU).

The test selects one downstream linecard with a 400G oper-up portchannel member,
downgrades that port to 100G using a PORT-only apply-patch, then upgrades it
back to 400G. The upgrade patch restores the 400G PORT entry together with the
selected port's cluster-related CONFIG_DB entries from the original running
configuration. Post-upgrade checks cover DB consistency, interface status,
buffer profiles, telemetry, ACL counters, and traffic. The DUT is restored via
config reload after the test completes.
"""


import logging
import random
import re
import pytest
from tests.generic_config_updater.add_cluster.helpers import get_cfg_info_from_dut
from tests.generic_config_updater.add_cluster.helpers import acl_asic_shell_wrappper
from .platform_constants import SPEED_FEC_MAP
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import (
    get_downstream_neigh_type,
    get_upstream_neigh_type,
    wait_until,
    is_ipv4_address,
    is_ipv6_address,
)
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.config_reload import config_reload
from tests.common.helpers.telemetry_helper import setup_streaming_telemetry_context
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.gu_utils import delete_tmpfile, expect_op_success, generate_tmpfile, apply_patch
from tests.common.helpers.constants import DEFAULT_ASIC_ID, NAMESPACE_PREFIX
from tests.common.helpers.dut_utils import verify_orchagent_running_or_assert
from tests.generic_config_updater.add_cluster.helpers import (
    format_sonic_buffer_pg_dict,
    format_sonic_interface_dict,
    remove_dataacl_table_single_dut,
    send_and_verify_traffic,
)

pytestmark = [
    pytest.mark.topology("t2")
]

logger = logging.getLogger(__name__)
allure.logger = logger

# -----------------------------
# Speed and ACL constants
# -----------------------------
SPEED_100G = "100000"
SPEED_400G = "400000"

PORT_SPEED_UPGRADE_SUPPORTED_SPEEDS_MAP = {
    'x86_64-88_lc0_36fh-r0': [SPEED_100G, SPEED_400G],
}

PORT_SPEED_UPGRADE_SPEED_LANES_MAP = {
    'x86_64-88_lc0_36fh-r0': {
        SPEED_100G: 4,
        SPEED_400G: 8,
    }
}

ACL_TABLE_NAME = "L3_TRANSPORT_TEST"
ACL_TABLE_TYPE_L3 = "L3"
ACL_TABLE_STAGE_EGRESS = "egress"
ACL_RULE_FILE_PATH = "generic_config_updater/add_cluster/acl/acl_rule_src_dst_port.json"
ACL_RULE_DST_FILE = "/tmp/test_add_cluster_acl_rule.json"
ACL_RULE_VERIFY_LIST = ["RULE_100", "RULE_200"]

# Selective loganalyzer ignores for expected transient errors during port speed GCU apply.
# Teardown uses blanket ignore via config_reload(..., ignore_loganalyzer=...).
# See also: tests/generic_config_updater/test_multiasic_addcluster.py
LOGANALYZER_IGNORE_REGEX = [
    ".*doPortTask: Unsupported port .* speed.*",
    ".*createEntry: Failed to start PFC Watchdog on port.*",
    ".*Unable to find key NPU_SI_SETTINGS_SYNC_STATUS.*",
    ".*ERR pmon#.*CmisManagerTask.*no suitable app for the port appl.*",
    ".*ERR syncd[0-9]*#syncd: SAI_LOG\\|SAI_API_QUEUE: Invalid queue counter.*",
]


def _restore_dut_via_minigraph(duthost, loganalyzer=None):
    """
    Restore the DUT to the original minigraph configuration.

    Used for teardown and for recovery when setup or the test leaves the DUT in
    a bad state (for example telemetry start-limit-hit after GCU speed changes).

    Args:
        duthost: DUT host object.
        loganalyzer: Optional loganalyzer fixture for reload-time syslog ignores.
    """
    config_reload(
        duthost,
        config_source="minigraph",
        safe_reload=True,
        wait_for_bgp=True,
        ignore_loganalyzer=loganalyzer,
    )


# -----------------------------
# Port selection helpers
# -----------------------------


def _get_downstream_neighbor_types(tbinfo):
    """
    Return downstream neighbor type strings for the T2 topology.
    """
    downstream_neigh_types = get_downstream_neigh_type(tbinfo, is_upper=True)
    if downstream_neigh_types:
        return [
            item.strip() for item in downstream_neigh_types.split(',') if item.strip()
        ]
    return ["T1"]


def _pick_primary_downstream_hostname(duthosts, tbinfo):
    """
    Pick a frontend DUT that has downstream neighbors in the minigraph.

    Uses the same neighbor-type matching as enum_downstream_dut_hostname but
    scans only DUTs in the current host pattern (for example yy39-lc1, yy39-lc2).

    Args:
        duthosts: DUT hosts fixture.
        tbinfo: Testbed info fixture.

    Returns:
        str: Hostname of a qualifying downstream-facing frontend DUT.
    """
    downstream_nbr_type = _get_downstream_neighbor_types(tbinfo)
    selected_hostname = None

    for dut in duthosts.frontend_nodes:
        minigraph_neighbors = dut.get_extended_minigraph_facts(tbinfo)['minigraph_neighbors']
        for neighbor in minigraph_neighbors.values():
            if any(downstream_type in neighbor['name'] for downstream_type in downstream_nbr_type):
                selected_hostname = dut.hostname
                break
        if selected_hostname is not None:
            break

    if selected_hostname is None:
        pytest.fail(
            "Did not find a dut in duthosts for topo type {} that has downstream nbr type {}".format(
                tbinfo["topo"]["type"], downstream_nbr_type
            )
        )
    return selected_hostname


def _pick_primary_upstream_hostname(duthosts, tbinfo):
    """
    Pick a frontend DUT that has upstream neighbors in the minigraph.

    Same logic as enum_upstream_dut_hostname, scoped to the current host pattern.

    Args:
        duthosts: DUT hosts fixture.
        tbinfo: Testbed info fixture.

    Returns:
        str: Hostname of a qualifying upstream-facing frontend DUT.
    """
    upstream_nbr_type = get_upstream_neigh_type(tbinfo, is_upper=True)
    if upstream_nbr_type is None:
        upstream_nbr_type = "T3"

    selected_hostname = None
    for dut in duthosts.frontend_nodes:
        minigraph_neighbors = dut.get_extended_minigraph_facts(tbinfo)['minigraph_neighbors']
        for neighbor in minigraph_neighbors.values():
            if upstream_nbr_type in neighbor['name']:
                selected_hostname = dut.hostname
                break
        if selected_hostname is not None:
            break

    if selected_hostname is None:
        pytest.fail(
            "Did not find a dut in duthosts for topo type {} that has upstream nbr type {}".format(
                tbinfo["topo"]["type"], upstream_nbr_type
            )
        )
    return selected_hostname


def _pick_traffic_source(duthosts, test_dut_hostname, original_upstream):
    """
    Return the DUT hostname to use as the secondary traffic source.

    Prefer the original upstream DUT when it differs from the test DUT. When the
    test DUT is the upstream, pick the first frontend node with a different hostname.

    Args:
        duthosts: Frontend DUT hosts fixture.
        test_dut_hostname: Hostname of the DUT under test.
        original_upstream: Hostname of the upstream DUT from testbed enumeration.

    Returns:
        str or None: Traffic-source DUT hostname, or None if no candidate exists.
    """
    if test_dut_hostname != original_upstream:
        return original_upstream
    for node in duthosts.frontend_nodes:
        if node.hostname != test_dut_hostname:
            return node.hostname
    return None


def _get_external_portchannel_member_ports(config_facts, duthost=None):
    """
    Return member ports of external (non-backplane) portchannels in an ASIC namespace.

    On chassis-packet platforms, portchannels containing Ethernet-BP members are
    treated as internal and excluded.

    Args:
        config_facts: Running config facts for the target ASIC namespace.
        duthost: Optional DUT host; used to detect chassis-packet switch type.

    Returns:
        set: Ethernet port names that are external portchannel members.
    """
    is_chassis_packet = duthost and duthost.facts.get('switch_type') == 'chassis-packet'
    internal_portchannels = set()
    if is_chassis_packet:
        for portchannel, member_port, _member_value in _iter_portchannel_members(config_facts):
            if member_port.startswith("Ethernet-BP"):
                internal_portchannels.add(portchannel)

    member_ports = set()
    for portchannel, member_port, _member_value in _iter_portchannel_members(config_facts):
        if portchannel in internal_portchannels:
            continue
        if is_chassis_packet and member_port.startswith("Ethernet-BP"):
            continue
        member_ports.add(member_port)
    return member_ports


def _iter_portchannel_members(config_facts):
    """
    Iterate PORTCHANNEL_MEMBER entries as (portchannel, member_port, value).

    Supports both ansible config_facts nested form and raw CONFIG_DB key form.
    """
    for key, value in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
        if '|' in key:
            portchannel, member_port = key.split('|', 1)
            yield portchannel, member_port, value
        else:
            for member_port, member_value in value.items():
                yield key, member_port, member_value


def _get_external_portchannel_members(config_facts, portchannel):
    """
    Return external member ports for a PortChannel.

    Args:
        config_facts: Running config facts for the target ASIC namespace.
        portchannel: PortChannel name.

    Returns:
        list: Sorted non-BP Ethernet member ports.
    """
    members = [
        member_port
        for pc_name, member_port, _member_value in _iter_portchannel_members(config_facts)
        if pc_name == portchannel and not member_port.startswith("Ethernet-BP")
    ]
    return sorted(members)


def get_eligible_front_panel_ports(config_facts, duthost=None, required_speed=None, portchannel_only=True):
    """
    Return front-panel ports from the PORT table, optionally filtered by speed.

    When portchannel_only is True (default), only external portchannel member ports
    with role Ext (or no role) and admin_status up are returned.

    Args:
        config_facts: Running config facts for the target ASIC namespace.
        duthost: Optional DUT host passed to portchannel member resolution.
        required_speed: Optional speed in Mbps (string) to filter ports.
        portchannel_only: When True, restrict to portchannel member ports.

    Returns:
        list: Matching Ethernet port names.
    """
    port_channel_members = _get_external_portchannel_member_ports(config_facts, duthost=duthost)

    eligible_ports = []
    for port, port_cfg in config_facts.get("PORT", {}).items():
        if not port.startswith("Ethernet"):
            continue
        if portchannel_only:
            if port not in port_channel_members:
                continue
        elif port in port_channel_members:
            continue
        port_role = port_cfg.get('role')
        if port_role and port_role != 'Ext':
            continue
        if required_speed is not None:
            port_speed = str(port_cfg.get('speed', ''))
            if not port_speed or int(port_speed) != int(required_speed):
                continue
        if port_cfg.get('admin_status', 'up') != 'up':
            continue
        eligible_ports.append(port)

    logging.info(
        f"Eligible ports (portchannel_only={portchannel_only}, required_speed={required_speed}): "
        f"{eligible_ports}"
    )
    return eligible_ports


def _downlink_candidates(duthosts, tbinfo, primary_downstream_hostname):
    """
    Return downstream-facing frontend DUTs, primary listed first.

    The primary downstream is preferred when it has qualifying 400G ports, but
    other downstream linecards are scanned before the test skips.

    Args:
        duthosts: Frontend DUT hosts fixture.
        tbinfo: Testbed info fixture.
        primary_downstream_hostname: Hostname of the enumerated downstream DUT.

    Returns:
        list: DUT host objects ordered with the primary downstream first.
    """
    reference_dut = duthosts[primary_downstream_hostname]
    downstream_nbr_type = _get_downstream_neighbor_types(tbinfo)
    downstream_duts = []
    for dut in duthosts.frontend_nodes:
        minigraph_neighbors = dut.get_extended_minigraph_facts(tbinfo)['minigraph_neighbors']
        if any(
            any(downstream_type in neighbor['name'] for downstream_type in downstream_nbr_type)
            for neighbor in minigraph_neighbors.values()
        ):
            downstream_duts.append(dut)
    return [reference_dut] + [
        dut for dut in downstream_duts if dut.hostname != primary_downstream_hostname
    ]


def _build_dut_context(duthost, tbinfo, asic_index):
    """
    Build per-ASIC namespace prefixes and configuration facts for a DUT.

    Args:
        duthost: DUT host object.
        tbinfo: Testbed info fixture.
        asic_index: Frontend ASIC index, or DEFAULT_ASIC_ID for single-ASIC.

    Returns:
        dict: Context with asic_index, asic_namespace, CLI/netns prefixes, and facts.
    """
    if asic_index is None or asic_index == DEFAULT_ASIC_ID:
        asic_namespace = None
        cli_ns_prefix = ''
        ip_netns_prefix = ''
    else:
        asic_namespace = f'{NAMESPACE_PREFIX}{asic_index}'
        cli_ns_prefix = f'-n {asic_namespace}'
        ip_netns_prefix = f'sudo ip netns exec {asic_namespace}'

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo, namespace=asic_namespace)
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running", namespace=asic_namespace
    )['ansible_facts']
    return {
        "asic_index": asic_index if asic_index is not None else DEFAULT_ASIC_ID,
        "asic_namespace": asic_namespace,
        "cli_namespace_prefix": cli_ns_prefix,
        "ip_netns_namespace_prefix": ip_netns_prefix,
        "mg_facts": mg_facts,
        "config_facts": config_facts,
    }


def _get_asic_interface_status_map(duthost, asic_namespace=None):
    """
    Return parsed show interface status for all ports on an ASIC in one CLI call.

    Args:
        duthost: DUT host object.
        asic_namespace: Optional ASIC namespace (for example, asic0).

    Returns:
        dict: Mapping of Ethernet port name to parsed status row.
    """
    if asic_namespace:
        cmd = f"show interface status -n {asic_namespace}"
    else:
        cmd = "show interface status"
    rows = duthost.show_and_parse(cmd)
    return {
        row['interface']: row for row in rows
        if row.get('interface')
    }


def get_port_show_interface_status(duthost, port, asic_namespace=None):
    """
    Return the parsed show interface status row for a single port.

    Args:
        duthost: DUT host object.
        port: Ethernet port name.
        asic_namespace: Optional ASIC namespace (for example, asic0).

    Returns:
        dict: Parsed interface status fields (speed, lanes, fec, oper, admin, etc.).
    """
    if asic_namespace:
        cmd = f"show interface status {port} -n {asic_namespace}"
    else:
        cmd = f"show interface status {port}"
    result = duthost.show_and_parse(cmd)
    pytest_assert(result, f"No show interface status output for port {port}")
    return result[0]


def _is_port_oper_up(duthost, port, asic_namespace=None, status_map=None):
    """
    Check whether a port is admin up and oper up.

    Args:
        duthost: DUT host object.
        port: Ethernet port name.
        asic_namespace: Optional ASIC namespace.
        status_map: Optional pre-fetched map from _get_asic_interface_status_map().

    Returns:
        bool: True when both admin and oper status are up.
    """
    if status_map is None:
        status = get_port_show_interface_status(duthost, port, asic_namespace)
    else:
        status = status_map.get(port)
        if not status:
            return False
    return status.get('oper', '').lower() == 'up' and status.get('admin', '').lower() == 'up'


def _filter_oper_up_ports(eligible_ports, status_map):
    """
    Return eligible ports that are admin up and oper up using a pre-fetched status map.

    Args:
        eligible_ports: Candidate Ethernet port names from config_facts.
        status_map: Parsed show interface status keyed by port name.

    Returns:
        list: Ports that are oper up.
    """
    oper_up_ports = []
    for port in eligible_ports:
        status = status_map.get(port)
        if not status:
            continue
        if status.get('oper', '').lower() == 'up' and status.get('admin', '').lower() == 'up':
            oper_up_ports.append(port)
    return oper_up_ports


def _collect_upgrade_test_options(duthosts, candidates, tbinfo, enum_upstream_dut_hostname):
    """
    Select one downlink DUT and port for the 100G -> 400G upgrade scenario.

    Scans frontend ASICs on each downstream candidate (primary first) for 400G
    portchannel member ports that are admin up and oper up. Picks a random ASIC
    with qualifying ports, then a random port on that ASIC.

    Args:
        duthosts: Frontend DUT hosts fixture.
        candidates: Downlink DUT candidates ordered by hwsku preference.
        tbinfo: Testbed info fixture.
        enum_upstream_dut_hostname: Enumerated upstream DUT hostname.

    Returns:
        dict or None: Selected test context, or None when no qualifying port exists.
    """
    for candidate in candidates:
        if not _has_port_speed_upgrade_platform_data(candidate):
            logging.info(
                f"Skipping {candidate.hostname}: platform {candidate.facts['platform']} "
                "does not have required 100G speed/lane data"
            )
            continue
        if candidate.is_multi_asic:
            asic_indices = [a.asic_index for a in candidate.frontend_asics]
        else:
            asic_indices = [DEFAULT_ASIC_ID]

        asic_options = {}
        for asic_index in asic_indices:
            ctx = _build_dut_context(candidate, tbinfo, asic_index)
            eligible_ports = get_eligible_front_panel_ports(
                ctx["config_facts"],
                duthost=candidate,
                required_speed=SPEED_400G,
                portchannel_only=True,
            )
            if not eligible_ports:
                continue
            status_map = _get_asic_interface_status_map(
                candidate, ctx["asic_namespace"]
            )
            oper_up_ports = _filter_oper_up_ports(eligible_ports, status_map)
            if oper_up_ports:
                asic_options[asic_index] = {
                    "ctx": ctx,
                    "ports": oper_up_ports,
                }

        if not asic_options:
            logging.info(
                f"No 400G oper-up portchannel ports on {candidate.hostname} "
                f"(hwsku={candidate.facts['hwsku']})"
            )
            continue

        traffic_source = _pick_traffic_source(
            duthosts, candidate.hostname, enum_upstream_dut_hostname
        )
        if traffic_source is None:
            continue

        selected_asic_index = random.choice(list(asic_options.keys()))
        selected = asic_options[selected_asic_index]
        selected_port = random.choice(selected["ports"])
        ctx = selected["ctx"]
        port_alias = ctx["mg_facts"]['minigraph_port_name_to_alias_map'].get(
            selected_port, selected_port
        )
        return {
            "enum_downstream_dut_hostname": candidate.hostname,
            "enum_upstream_dut_hostname": enum_upstream_dut_hostname,
            "traffic_source_dut_hostname": traffic_source,
            "enum_rand_one_frontend_asic_index": ctx["asic_index"],
            "enum_rand_one_asic_namespace": ctx["asic_namespace"],
            "ip_netns_namespace_prefix": ctx["ip_netns_namespace_prefix"],
            "cli_namespace_prefix": ctx["cli_namespace_prefix"],
            "selected_random_port": selected_port,
            "selected_random_port_alias": port_alias,
            "mg_facts": ctx["mg_facts"],
            "config_facts": ctx["config_facts"],
            "original_port_config": dict(ctx["config_facts"]["PORT"][selected_port]),
        }

    return None


# -----------------------------
# CONFIG_DB / platform speed helpers
# -----------------------------


def get_port_fec(duthost, cli_namespace_prefix, selected_random_port):
    """
    Read port FEC from CONFIG_DB.

    Args:
        duthost: DUT host object.
        cli_namespace_prefix: sonic-db-cli namespace prefix.
        selected_random_port: Ethernet port name.

    Returns:
        str: FEC value from CONFIG_DB.
    """
    cmd = 'sonic-db-cli {} CONFIG_DB hget \'PORT|{}\' fec'.format(
        cli_namespace_prefix, selected_random_port)
    return duthost.shell(cmd, module_ignore_errors=True)['stdout']


def get_port_lanes(duthost, cli_namespace_prefix, selected_random_port):
    """
    Read port lane list from CONFIG_DB.

    Args:
        duthost: DUT host object.
        cli_namespace_prefix: sonic-db-cli namespace prefix.
        selected_random_port: Ethernet port name.

    Returns:
        list: Lane indices as strings.
    """
    out = duthost.shell('sonic-db-cli {} CONFIG_DB hget \'PORT|{}\' lanes'.format(
        cli_namespace_prefix, selected_random_port))
    return out["stdout_lines"][0].split(',')


def get_supported_port_fecs(duthost, cli_namespace_prefix, selected_random_port):
    """
    Read supported FEC values for a port from STATE_DB.

    Args:
        duthost: DUT host object.
        cli_namespace_prefix: sonic-db-cli namespace prefix.
        selected_random_port: Ethernet port name.

    Returns:
        list: Supported FEC mode strings.
    """
    cmd = "sonic-db-cli {} STATE_DB HGET \"PORT_TABLE|{}\" \"supported_fecs\"".format(
        cli_namespace_prefix, selected_random_port)
    output = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    valid_fecs = output.split(',')
    pytest_assert(valid_fecs, "Failed to get any valid port fec to change to.")
    return valid_fecs


def get_target_fec(duthost, cli_namespace_prefix, selected_random_port, target_speed):
    """
    Pick a valid FEC for the target speed using platform and STATE_DB data.

    Args:
        duthost: DUT host object.
        cli_namespace_prefix: sonic-db-cli namespace prefix.
        selected_random_port: Ethernet port name.
        target_speed: Target speed in Mbps (string).

    Returns:
        str: Selected FEC mode for the target speed.
    """
    supported_statedb_fecs = get_supported_port_fecs(
        duthost, cli_namespace_prefix, selected_random_port)
    supported_fecs_per_speed = get_fec_for_speed(duthost, target_speed)
    pytest_assert(supported_fecs_per_speed, f"Failed to find any fec for speed {target_speed}.")
    for fec in supported_fecs_per_speed:
        if fec in supported_statedb_fecs:
            return fec
    return random.choice(supported_fecs_per_speed)


def get_num_lanes_per_speed(duthost, speed):
    """
    Return the number of lanes required for a speed on the DUT platform.

    Args:
        duthost: DUT host object.
        speed: Speed in Mbps (string).

    Returns:
        int or None: Lane count from PORT_SPEED_UPGRADE_SPEED_LANES_MAP.
    """
    return PORT_SPEED_UPGRADE_SPEED_LANES_MAP.get(duthost.facts['platform'], {}).get(speed, None)


def get_test_speeds(duthost):
    """
    Return supported test speeds for the DUT platform.

    Args:
        duthost: DUT host object.

    Returns:
        list or None: Supported speed strings from PORT_SPEED_UPGRADE_SUPPORTED_SPEEDS_MAP.
    """
    return PORT_SPEED_UPGRADE_SUPPORTED_SPEEDS_MAP.get(duthost.facts['platform'], None)


def _has_port_speed_upgrade_platform_data(duthost):
    """
    Return True when the DUT platform has data required for the 100G setup state.
    """
    test_speeds = get_test_speeds(duthost) or []
    return SPEED_100G in test_speeds and get_num_lanes_per_speed(duthost, SPEED_100G) is not None


def get_fec_for_speed(duthost, speed):
    """
    Return platform FEC options for a given speed.

    Args:
        duthost: DUT host object (unused; kept for consistency with sibling tests).
        speed: Speed in Mbps (string).

    Returns:
        list or None: FEC modes from SPEED_FEC_MAP.
    """
    return SPEED_FEC_MAP.get(speed, None)


# -----------------------------
# GCU patch helpers
# -----------------------------


def _escape_json_pointer_key(key):
    """
    Escape a CONFIG_DB key segment for use in a JSON patch path.

    Args:
        key: CONFIG_DB key segment.

    Returns:
        str: JSON Pointer escaped key.
    """
    return key.replace('/', '~1')


def _get_portchannel_for_member(config_facts, port):
    """
    Return the PortChannel containing a member port, if any.

    Args:
        config_facts: Running config facts for the selected ASIC namespace.
        port: Ethernet port name.

    Returns:
        str or None: PortChannel name containing the port.
    """
    for portchannel, member_port, _member_value in _iter_portchannel_members(config_facts):
        if member_port == port:
            return portchannel
    return None


def _get_portchannel_member_value(config_facts, portchannel, port):
    """
    Return the PORTCHANNEL_MEMBER value for a selected member port.

    Args:
        config_facts: Running config facts for the selected ASIC namespace.
        portchannel: PortChannel name containing the port.
        port: Ethernet port name.

    Returns:
        dict: PORTCHANNEL_MEMBER value for the selected member.
    """
    portchannel_members = config_facts.get("PORTCHANNEL_MEMBER", {})
    if portchannel in portchannel_members:
        return portchannel_members.get(portchannel, {}).get(port, {})
    return portchannel_members.get(f"{portchannel}|{port}", {})


def _append_portchannel_add_ops(json_patch, json_namespace, config_facts, port):
    """
    Append chassis-packet PortChannel add operations for the selected port.

    Only the selected PORTCHANNEL_MEMBER entry is restored here. PortChannel
    base and interface objects are shared by all members and are intentionally
    left untouched by this selected-port speed upgrade patch.
    """
    portchannel = _get_portchannel_for_member(config_facts, port)
    if not portchannel:
        return

    pc_member_key = f"{portchannel}|{port}"
    pc_member_value = _get_portchannel_member_value(config_facts, portchannel, port)

    json_patch.append({
        "op": "add",
        "path": f"{json_namespace}/PORTCHANNEL_MEMBER/{_escape_json_pointer_key(pc_member_key)}",
        "value": pc_member_value,
    })


def build_cluster_port_restore_ops(config_facts, mg_facts, json_namespace, port):
    """
    Build add operations that restore cluster-related config for a selected port.

    Args:
        config_facts: Original running config facts for the selected ASIC namespace.
        mg_facts: Extended minigraph facts for the selected ASIC namespace.
        json_namespace: JSON patch namespace prefix, e.g. /asic0 or empty string.
        port: Selected Ethernet port.

    Returns:
        list: JSON patch add operations for the selected port's cluster config.
    """
    json_patch = []
    _append_portchannel_add_ops(json_patch, json_namespace, config_facts, port)

    bgp_neigh_name, bgp_neigh_intfs, _bgp_neigh_ipv4, _bgp_neigh_ipv6 = get_interface_neighbor_and_intfs(
        mg_facts, port
    )

    for bgp_neigh_intf in bgp_neigh_intfs:
        bgp_neigh_intf = bgp_neigh_intf.lower()
        if bgp_neigh_intf in config_facts.get("BGP_NEIGHBOR", {}):
            json_patch.append({
                "op": "add",
                "path": f"{json_namespace}/BGP_NEIGHBOR/{bgp_neigh_intf}",
                "value": config_facts["BGP_NEIGHBOR"][bgp_neigh_intf],
            })

    if port in config_facts.get("DEVICE_NEIGHBOR", {}):
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR/{port}",
            "value": config_facts["DEVICE_NEIGHBOR"][port],
        })

    if bgp_neigh_name in config_facts.get("DEVICE_NEIGHBOR_METADATA", {}):
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA/{bgp_neigh_name}",
            "value": config_facts["DEVICE_NEIGHBOR_METADATA"][bgp_neigh_name],
        })

    interface_dict = {
        _escape_json_pointer_key(key): value
        for key, value in format_sonic_interface_dict(config_facts.get("INTERFACE", {})).items()
        if key == port or key.startswith(f"{port}|")
    }
    for iface_key, iface_value in interface_dict.items():
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/INTERFACE/{iface_key}",
            "value": iface_value,
        })

    buffer_pg_dict = {
        key: value
        for key, value in format_sonic_buffer_pg_dict(config_facts.get("BUFFER_PG", {})).items()
        if key == port or key.startswith(f"{port}|")
    }
    for bp_key, bp_value in buffer_pg_dict.items():
        if isinstance(bp_value, dict) and 'pg_lossless' in bp_value.get('profile', ''):
            continue
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/BUFFER_PG/{bp_key}",
            "value": bp_value,
        })

    if port in config_facts.get("PORT_QOS_MAP", {}):
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/PORT_QOS_MAP/{port}",
            "value": config_facts["PORT_QOS_MAP"][port],
        })

    if port in config_facts.get("PFC_WD", {}):
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/PFC_WD/{port}",
            "value": config_facts["PFC_WD"][port],
        })

    cable_length = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {}).get(port)
    if cable_length is not None:
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/CABLE_LENGTH/AZURE/{port}",
            "value": cable_length,
        })

    return json_patch


def _dedupe_patch_ops(json_patch):
    """
    Return patch operations with duplicate paths removed while preserving order.
    """
    deduped = []
    seen_paths = set()
    for operation in json_patch:
        path = operation.get("path")
        if path in seen_paths:
            continue
        deduped.append(operation)
        seen_paths.add(path)
    return deduped


def build_cluster_ports_restore_ops(config_facts, mg_facts, json_namespace, ports):
    """
    Build restore operations for the selected port(s).

    Args:
        config_facts: Original running config facts for the selected ASIC namespace.
        mg_facts: Extended minigraph facts for the selected ASIC namespace.
        json_namespace: JSON patch namespace prefix, e.g. /asic0 or empty string.
        ports: Selected Ethernet port name(s).

    Returns:
        list: JSON patch add operations for selected ports.
    """
    json_patch = []
    for port in ports:
        json_patch.extend(
            build_cluster_port_restore_ops(config_facts, mg_facts, json_namespace, port)
        )
    return _dedupe_patch_ops(json_patch)


def validate_patch_scoped_to_ports(json_patch, ports):
    """
    Assert selected-port table operations do not target unrelated ports.

    Args:
        json_patch: JSON patch operations to validate.
        ports: Selected Ethernet ports.
    """
    allowed_ports = set(ports)
    selected_port_tables = [
        "PORT",
        "INTERFACE",
        "BUFFER_PG",
        "PORT_QOS_MAP",
        "PFC_WD",
        "DEVICE_NEIGHBOR",
        "PORTCHANNEL_MEMBER",
    ]
    for operation in json_patch:
        path = operation.get("path", "")
        path_parts = path.strip('/').split('/')
        if len(path_parts) < 2:
            continue

        table_index = 1 if path_parts[0].startswith(NAMESPACE_PREFIX) else 0
        if table_index >= len(path_parts):
            continue
        if path_parts[table_index] == "CABLE_LENGTH":
            if len(path_parts) <= table_index + 2:
                continue
            target_port = path_parts[table_index + 2]
            pytest_assert(
                target_port in allowed_ports,
                "Patch operation {} targets {}, expected one of selected ports {}".format(
                    operation, target_port, sorted(allowed_ports)
                )
            )
            continue
        if path_parts[table_index] not in selected_port_tables:
            continue
        if table_index + 1 >= len(path_parts):
            continue

        key = path_parts[table_index + 1].replace('~1', '/')
        if path_parts[table_index] == "PORTCHANNEL_MEMBER":
            target_port = key.split('|', 1)[1] if '|' in key else key
        else:
            target_port = key.split('|', 1)[0]
        pytest_assert(
            target_port in allowed_ports,
            "Patch operation {} targets {}, expected one of selected ports {}".format(
                operation, target_port, sorted(allowed_ports)
            )
        )


def build_port_config_for_400g_upgrade(duthost, cli_namespace_prefix, selected_random_port,
                                       port_config_100g, original_port_config):
    """
    Build a full 400G PORT block from the current 100G PORT config.

    Args:
        duthost: DUT host object.
        cli_namespace_prefix: sonic-db-cli namespace prefix.
        selected_random_port: Ethernet port name.
        port_config_100g: Full PORT table value used for the 100G setup state.
        original_port_config: Original full 400G PORT table value.

    Returns:
        dict: Full PORT block preserving non-speed fields from the 100G config.
    """
    port_config_400g = dict(port_config_100g)
    for field in ["speed", "lanes"]:
        if field in original_port_config:
            port_config_400g[field] = original_port_config[field]
        else:
            port_config_400g.pop(field, None)

    target_fec = get_target_fec(
        duthost, cli_namespace_prefix, selected_random_port, SPEED_400G
    )
    if target_fec == "N/A":
        port_config_400g.pop("fec", None)
    elif target_fec:
        port_config_400g["fec"] = target_fec
    return port_config_400g


def build_port_config_for_speed(duthost, base_port_config, target_speed,
                                cli_namespace_prefix, selected_random_port):
    """
    Build a full CONFIG_DB PORT entry for the target speed.

    Preserves non-speed fields from base_port_config (alias, admin_status, index,
    etc.) and updates speed, lanes, and fec for the requested rate. Lane assignment
    starts at the port's current first lane index.

    Args:
        duthost: DUT host object.
        base_port_config: Original PORT table dict for the interface.
        target_speed: Target speed in Mbps (string).
        cli_namespace_prefix: sonic-db-cli namespace prefix.
        selected_random_port: Ethernet port name.

    Returns:
        dict: Complete PORT table value suitable for a GCU add operation.
    """
    port_config = dict(base_port_config)
    current_lanes = get_port_lanes(duthost, cli_namespace_prefix, selected_random_port)
    start_lane = int(current_lanes[0])
    target_num_lanes = get_num_lanes_per_speed(duthost, target_speed)
    pytest_assert(
        target_num_lanes is not None,
        f"Could not determine num lanes for speed {target_speed}"
    )
    port_config["lanes"] = ",".join(
        str(i) for i in range(start_lane, start_lane + target_num_lanes)
    )
    port_config["speed"] = target_speed

    target_fec = get_target_fec(
        duthost, cli_namespace_prefix, selected_random_port, target_speed
    )
    if target_fec == "N/A":
        port_config.pop("fec", None)
    elif target_fec:
        port_config["fec"] = target_fec
    return port_config


def apply_patch_port_configs(duthost, enum_rand_one_asic_namespace, port_configs,
                             config_facts=None, mg_facts=None, dry_run=False):
    """
    Apply a GCU patch that updates one or more member port speeds.

    Args:
        duthost: DUT host object.
        enum_rand_one_asic_namespace: ASIC namespace (for example, asic0), or None.
        port_configs: Mapping of Ethernet port name to full PORT table dict.
        config_facts: Optional original running config facts for cluster restore.
        mg_facts: Optional minigraph facts for neighbor resolution.
        dry_run: When True, log the patch without applying it.
    """
    ports = list(port_configs.keys())
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace
    json_patch = []
    if config_facts is not None and mg_facts is not None:
        json_patch.extend(
            build_cluster_ports_restore_ops(config_facts, mg_facts, json_namespace, ports)
        )

    for port, port_config in port_configs.items():
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/PORT/{port}",
            "value": port_config,
        })
    validate_patch_scoped_to_ports(json_patch, ports)

    tmpfile = generate_tmpfile(duthost)
    try:
        logger.info(f"Applying port speed patch for {ports}. Dry-run {dry_run}")
        logger.info(f"Patch content: {json_patch}")
        if not dry_run:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


# -----------------------------
# Verification helpers
# -----------------------------


def verify_port_show_interface_status(duthost, port, asic_namespace, expected_speed,
                                      expected_lanes, expected_fec, require_oper_up=False):
    """
    Verify speed, lanes, and FEC from show interface status.

    Args:
        duthost: DUT host object.
        port: Ethernet port name.
        asic_namespace: ASIC namespace, or None for default namespace.
        expected_speed: Expected speed in Mbps (string).
        expected_lanes: Expected comma-separated lane string.
        expected_fec: Expected FEC value, or None/N/A when absent.
        require_oper_up: When True, wait for and assert oper state is up. Leave
            False after a speed downgrade when oper-down is expected.

    Returns:
        None
    """
    if require_oper_up:
        pytest_assert(
            wait_until(
                300, 20, 0,
                lambda: _is_port_oper_up(duthost, port, asic_namespace)
            ),
            f"Port {port} not oper up"
        )

    status = get_port_show_interface_status(duthost, port, asic_namespace)
    displayed_speed = status.get('speed', '').replace('G', '000').replace('M', '')
    pytest_assert(
        displayed_speed == expected_speed,
        f"Port {port} speed mismatch: expected {expected_speed}, got {status.get('speed')}"
    )
    pytest_assert(
        status.get('lanes') == expected_lanes,
        f"Port {port} lanes mismatch: expected {expected_lanes}, got {status.get('lanes')}"
    )
    expected_fec_display = (expected_fec or 'N/A').upper()
    actual_fec = status.get('fec', 'N/A').upper()
    pytest_assert(
        actual_fec == expected_fec_display,
        f"Port {port} fec mismatch: expected {expected_fec_display}, got {actual_fec}"
    )
    if require_oper_up:
        pytest_assert(
            status.get('oper', '').lower() == 'up',
            f"Port {port} oper state is not up: {status.get('oper')}"
        )
    logger.info(
        f"show interface status for {port}: speed={status.get('speed')} "
        f"lanes={status.get('lanes')} fec={status.get('fec')} oper={status.get('oper')}"
    )


def verify_port_speed_in_dbs(duthost, cli_namespace_prefix, port, expected_speed):
    """
    Verify port speed in CONFIG_DB and APPL_DB.

    Args:
        duthost: DUT host object.
        cli_namespace_prefix: sonic-db-cli namespace prefix.
        port: Ethernet port name.
        expected_speed: Expected speed in Mbps (string).

    Returns:
        None
    """
    cmd = "sonic-db-cli {} CONFIG_DB HGET \"PORT|{}\" \"speed\"".format(
        cli_namespace_prefix, port)
    port_speed_config_db = duthost.shell(cmd, module_ignore_errors=True)['stdout']

    cmd = "sonic-db-cli {} APPL_DB HGET \"PORT_TABLE:{}\" \"speed\"".format(
        cli_namespace_prefix, port)
    port_speed_appl_db = duthost.shell(cmd, module_ignore_errors=True)['stdout']

    logger.info(
        "Port speed values: CONFIG_DB={} APPL_DB={}".format(
            port_speed_config_db, port_speed_appl_db)
    )
    pytest_assert(
        port_speed_config_db == port_speed_appl_db,
        "Speeds in CONFIG_DB and APPL_DB do not match!"
    )
    pytest_assert(
        port_speed_config_db == expected_speed,
        "CONFIG_DB speed {} does not match expected {}".format(
            port_speed_config_db, expected_speed)
    )
    pytest_assert(
        port_speed_appl_db == expected_speed,
        "APPL_DB speed {} does not match expected {}".format(
            port_speed_appl_db, expected_speed)
    )


def get_interface_neighbor_and_intfs(mg_facts, selected_random_port):
    """
    Resolve BGP neighbor name and addresses for a port or its portchannel.

    Args:
        mg_facts: Extended minigraph facts for the ASIC namespace.
        selected_random_port: Ethernet port or portchannel member name.

    Returns:
        tuple: (neighbor_name, neighbor_addr_list, neighbor_ipv4, neighbor_ipv6)
    """
    vm_neighbors = mg_facts['minigraph_neighbors']
    dut_interface = selected_random_port
    if (port_channel := mg_facts.get('minigraph_portchannels', {}).get(dut_interface)) is not None:
        dut_interface = port_channel['members'][0]
    neighbor_name = vm_neighbors[dut_interface]['name']
    neighbor_info = mg_facts['minigraph_bgp']
    neighbor_addr = []
    neighbor_ipv4_addr = ""
    neighbor_ipv6_addr = ""
    for neigh in neighbor_info:
        if neigh['name'] == neighbor_name:
            neighbor_addr.append(neigh['addr'])
            if is_ipv4_address(neigh['addr']):
                neighbor_ipv4_addr = neigh['addr']
            elif is_ipv6_address(neigh['addr']):
                neighbor_ipv6_addr = neigh['addr']
    neighbor_addr = list(set(neighbor_addr))
    logger.info(
        "Found neighbor {} with interfaces {} for duthost port {}. "
        "IPV4 interface: {} IPV6 interface: {}".format(
            neighbor_name, neighbor_addr, selected_random_port,
            neighbor_ipv4_addr, neighbor_ipv6_addr)
    )
    return neighbor_name, neighbor_addr, neighbor_ipv4_addr, neighbor_ipv6_addr


# -----------------------------
# swss / orchagent restart checks
# -----------------------------


def get_orchagent_pid(duthost, asic_index):
    """
    Return the orchagent process ID inside the swss container for an ASIC.

    Args:
        duthost: DUT host object.
        asic_index: Frontend ASIC index.

    Returns:
        str: orchagent PID, or empty string if not found.
    """
    if duthost.is_multi_asic:
        cmd = f'docker exec swss{asic_index} pgrep orchagent'
    else:
        cmd = 'docker exec swss pgrep orchagent'
    result = duthost.shell(cmd, module_ignore_errors=True)
    return (result.get('stdout') or '').strip()


def get_swss_container_started_at(duthost, asic_index):
    """
    Return the docker StartedAt timestamp for the swss container on an ASIC.

    Args:
        duthost: DUT host object.
        asic_index: Frontend ASIC index.

    Returns:
        str: Container StartedAt value from docker inspect.
    """
    container = f'swss{asic_index}' if duthost.is_multi_asic else 'swss'
    # Escape Go template braces so Ansible/Jinja does not treat them as template syntax.
    cmd = r"docker inspect -f \{{\{{.State.StartedAt\}}\}} {}".format(container)
    result = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(
        not result.get('failed', False),
        f"Failed to get swss container StartedAt for {container}: {result.get('msg', result)}"
    )
    return (result.get('stdout') or '').strip()


def assert_no_swss_or_orchagent_restart(duthost, asic_index, orchagent_pid_before, swss_started_at_before):
    """
    Assert swss and orchagent were not restarted during a GCU port speed change.

    Args:
        duthost: DUT host object.
        asic_index: Frontend ASIC index under test.
        orchagent_pid_before: orchagent PID captured before the patch.
        swss_started_at_before: swss StartedAt timestamp captured before the patch.

    Returns:
        None
    """
    orchagent_pid_after = get_orchagent_pid(duthost, asic_index)
    pytest_assert(
        orchagent_pid_after == orchagent_pid_before,
        f"orchagent restarted: pid before={orchagent_pid_before}, after={orchagent_pid_after}"
    )
    swss_started_at_after = get_swss_container_started_at(duthost, asic_index)
    pytest_assert(
        swss_started_at_after == swss_started_at_before,
        f"swss container restarted: started_at before={swss_started_at_before}, "
        f"after={swss_started_at_after}"
    )


# -----------------------------
# ACL setup
# -----------------------------


def setup_acl_config(duthost, ip_netns_namespace_prefix):
    """
    Install egress L3 ACL table and rules used by traffic verification.

    Args:
        duthost: DUT host object.
        ip_netns_namespace_prefix: ip netns exec prefix for the target ASIC.

    Returns:
        None
    """
    logger.info("Adding acl config.")
    remove_dataacl_table_single_dut("DATAACL", duthost)
    duthost.copy(src=ACL_RULE_FILE_PATH, dest=ACL_RULE_DST_FILE)
    cmds = [
        "config acl add table {} {} -s {}".format(
            ACL_TABLE_NAME, ACL_TABLE_TYPE_L3, ACL_TABLE_STAGE_EGRESS),
        "acl-loader update full --table_name {} {}".format(ACL_TABLE_NAME, ACL_RULE_DST_FILE)
    ]
    acl_asic_shell_wrappper(duthost, cmds)
    acl_tables = duthost.command("{} show acl table".format(ip_netns_namespace_prefix))["stdout_lines"]
    acl_rules = duthost.command("{} show acl rule".format(ip_netns_namespace_prefix))["stdout_lines"]
    logging.info('\n'.join(acl_tables))
    logging.info('\n'.join(acl_rules))


def verify_traffic_acl_counters(duthost, ip_netns_namespace_prefix, traffic_scenario,
                                acl_rule_names=None, acl_table_name=None):
    """
    Verify packet counts for ACL rules in the test-installed table only.

    Only rules under ``acl_table_name`` (default ``L3_TRANSPORT_TEST``) are checked.
    Platform ACL rules in other tables (for example BFD) are ignored.
    """
    if acl_rule_names is None:
        acl_rule_names = ACL_RULE_VERIFY_LIST
    if acl_table_name is None:
        acl_table_name = ACL_TABLE_NAME

    acl_counters = duthost.show_and_parse(
        '{} aclshow -a'.format(ip_netns_namespace_prefix)
    )
    counters_by_rule = {
        entry["rule name"]: entry["packets count"]
        for entry in acl_counters
        if entry.get("table name") == acl_table_name
    }
    expected_count = str(traffic_scenario["count"])
    match_rule = traffic_scenario.get("match_rule")

    for rule_name in acl_rule_names:
        actual_count = counters_by_rule.get(rule_name, "0")
        expected = expected_count if rule_name == match_rule else "0"
        pytest_assert(
            actual_count == expected,
            "ACL rule {} in table {} packet count mismatch: found {}, expected {}".format(
                rule_name, acl_table_name, actual_count, expected)
        )


def _gnmi_counters_available(ptfhost, cmd, port):
    """
    Return True when gNMI returns COUNTERS_DB data for the selected port.
    """
    output = ptfhost.shell(cmd, module_ignore_errors=True)
    stdout = output.get('stdout', '')
    stderr = output.get('stderr', '')
    logger.info("GNMI Server output for %s: stdout=%s stderr=%s", port, stdout, stderr)
    return re.search("SAI_PORT_STAT_IF_IN_ERRORS", str(stdout)) is not None


# -----------------------------
# Fixtures
# -----------------------------


@pytest.fixture(scope="function")
def port_speed_upgrade_context(duthosts, tbinfo):
    """
    Select the DUT, ASIC, and port used by the port speed upgrade test.

    Scans downstream-facing frontend linecards in the current host pattern
    (for example yy39-lc1, yy39-lc2), picks one 400G oper-up PortChannel, and
    returns the runtime context shared by setup and loganalyzer fixtures.

    Args:
        duthosts: DUT hosts fixture.
        tbinfo: Testbed info fixture.

    Returns:
        dict: Selected test context with DUT, ASIC, port, and saved PORT config.
    """
    primary_downstream_hostname = _pick_primary_downstream_hostname(duthosts, tbinfo)
    primary_upstream_hostname = _pick_primary_upstream_hostname(duthosts, tbinfo)

    candidates = _downlink_candidates(duthosts, tbinfo, primary_downstream_hostname)
    selected_context = _collect_upgrade_test_options(
        duthosts, candidates, tbinfo, primary_upstream_hostname
    )
    if selected_context is None:
        pytest.skip(
            "No downstream DUT has a 400G admin-up "
            "oper-up portchannel member on any frontend ASIC, or no usable traffic-source DUT"
        )

    logging.info(
        f"Selected DUT={selected_context['enum_downstream_dut_hostname']} "
        f"asic={selected_context['enum_rand_one_asic_namespace']} "
        f"port={selected_context['selected_random_port']} "
        f"({selected_context['selected_random_port_alias']}) at 400G; "
        f"traffic_source_dut={selected_context['traffic_source_dut_hostname']}"
    )
    return selected_context


@pytest.fixture(autouse=True)
def ignore_port_speed_loganalyzer_exceptions(duthosts, port_speed_upgrade_context, loganalyzer):
    """
    Ignore expected yang/orchagent errors during transient port speed changes.

    Uses the same DUT selected for the test (port_speed_upgrade_context), not a
    separate enum_downstream_dut_hostname fixture.

    Args:
        duthosts: DUT hosts fixture.
        port_speed_upgrade_context: Selected port speed upgrade test context.
        loganalyzer: Loganalyzer plugin fixture.
    """
    duthost = duthosts[port_speed_upgrade_context["enum_downstream_dut_hostname"]]
    if loganalyzer and duthost.hostname in loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(LOGANALYZER_IGNORE_REGEX)


@pytest.fixture(scope="function")
def setup_port_speed_upgrade(request, duthosts, port_speed_upgrade_context, loganalyzer,
                             ignore_port_speed_loganalyzer_exceptions):
    """
    Prepare the 100G starting state for the port speed upgrade test.

    Downgrades the selected 400G oper-up port to 100G via a PORT-only GCU patch
    and verifies show interface status. Yields the selected test context to the
    test function.

    Teardown and setup failure recovery restore the DUT via minigraph config reload.

    Args:
        duthosts: DUT hosts fixture.
        port_speed_upgrade_context: Selected port speed upgrade test context.
        loganalyzer: Loganalyzer plugin fixture.
        ignore_port_speed_loganalyzer_exceptions: Ensures loganalyzer ignores are
            registered before the downgrade patch is applied.

    Yields:
        dict: Runtime context with DUT, ASIC, port, and saved PORT config.
    """
    selected_context = port_speed_upgrade_context
    duthost = duthosts[selected_context["enum_downstream_dut_hostname"]]
    port = selected_context["selected_random_port"]
    asic_namespace = selected_context["enum_rand_one_asic_namespace"]
    cli_namespace_prefix = selected_context["cli_namespace_prefix"]
    original_port_config = selected_context["original_port_config"]

    def cleanup():
        # Restore original minigraph configuration after mutation. Register this
        # before applying the downgrade patch so partial setup failures recover too.
        with allure.step("Restore DUT configuration via minigraph config reload"):
            _restore_dut_via_minigraph(duthost, loganalyzer)

    port_config_100g = build_port_config_for_speed(
        duthost, original_port_config, SPEED_100G, cli_namespace_prefix, port
    )

    request.addfinalizer(cleanup)

    with allure.step("Downgrade port from 400G to 100G using PORT-only GCU patch"):
        apply_patch_port_configs(
            duthost, asic_namespace, {port: port_config_100g}, dry_run=False
        )

    with allure.step("Verify 100G speed, lanes, and fec via show interface status (oper may be down)"):
        verify_port_show_interface_status(
            duthost, port, asic_namespace, SPEED_100G,
            port_config_100g["lanes"], port_config_100g.get("fec"),
            require_oper_up=False
        )

    selected_context["port_config_100g"] = port_config_100g
    yield selected_context


# -----------------------------
# Test definitions
# -----------------------------


def test_port_speed_upgrade(tbinfo, duthosts, ptfadapter, setup_port_speed_upgrade,
                            ptfhost, gnxi_path, localhost):
    """
    Validate 100G -> 400G port speed upgrade via Generic Config Updater (GCU).

    The setup fixture downgrades a selected 400G oper-up port to 100G using a
    PORT-only apply-patch. This test upgrades the port back to 400G, confirms
    swss/orchagent were not restarted, validates DB and CLI state, buffer
    profiles, telemetry, ACL counters, and bidirectional traffic scenarios.

    Args:
        tbinfo: Testbed info fixture.
        duthosts: DUT hosts fixture.
        ptfadapter: PTF adapter fixture.
        setup_port_speed_upgrade: Fixture that prepares the 100G starting state.
        ptfhost: PTF host fixture.
        gnxi_path: gNMI client path on the PTF host.
        localhost: Ansible localhost fixture.

    Returns:
        None
    """
    runtime = setup_port_speed_upgrade
    enum_downstream_dut_hostname = runtime["enum_downstream_dut_hostname"]
    traffic_source_dut_hostname = runtime["traffic_source_dut_hostname"]
    enum_rand_one_frontend_asic_index = runtime["enum_rand_one_frontend_asic_index"]
    enum_rand_one_asic_namespace = runtime["enum_rand_one_asic_namespace"]
    ip_netns_namespace_prefix = runtime["ip_netns_namespace_prefix"]
    cli_namespace_prefix = runtime["cli_namespace_prefix"]
    selected_random_port = runtime["selected_random_port"]
    mg_facts = runtime["mg_facts"]
    config_facts = runtime["config_facts"]
    original_port_config = runtime["original_port_config"]
    port_config_100g = runtime["port_config_100g"]

    bgp_neigh_name, bgp_neigh_intfs, bgp_neigh_ipv4, bgp_neigh_ipv6 = get_interface_neighbor_and_intfs(
        mg_facts, selected_random_port)
    duthost = duthosts[enum_downstream_dut_hostname]
    duthost_up = duthosts[traffic_source_dut_hostname]
    logger.info(
        f"test_port_speed_upgrade on test_dut={enum_downstream_dut_hostname} "
        f"traffic_source_dut={traffic_source_dut_hostname}"
    )

    # Pick source ASIC indices for downstream->downstream and upstream->downstream traffic.
    asic_id = enum_rand_one_frontend_asic_index
    asic_id_src = None
    asic_id_src_up = None
    for asic in duthost.get_asic_ids():
        if asic != asic_id:
            asic_id_src = asic
            break
    for asic in duthost_up.get_asic_ids():
        asic_id_src_up = asic
        break

    pytest_assert(
        asic_id_src is not None,
        "Couldn't find an asic id for downstream traffic. Reserved asic id: {}. "
        "Available: {}".format(asic_id, duthost.get_asic_ids())
    )
    pytest_assert(
        asic_id_src_up is not None,
        "Couldn't find an asic id for upstream traffic. Available: {}".format(
            duthost_up.get_asic_ids()
        )
    )

    initial_speed = original_port_config["speed"]
    initial_cable_length = config_facts["CABLE_LENGTH"]["AZURE"][selected_random_port]
    initial_pg_lossless_profile_name = 'pg_lossless_{}_{}_profile'.format(
        initial_speed, initial_cable_length
    )
    port_config_400g = build_port_config_for_400g_upgrade(
        duthost, cli_namespace_prefix, selected_random_port,
        port_config_100g, original_port_config
    )

    # Capture swss/orchagent state before the 400G upgrade patch is applied.
    orchagent_pid_before = get_orchagent_pid(duthost, enum_rand_one_frontend_asic_index)
    swss_started_at_before = get_swss_container_started_at(
        duthost, enum_rand_one_frontend_asic_index
    )

    with allure.step("Upgrade port from 100G to 400G using GCU patch with cluster config"):
        apply_patch_port_configs(
            duthost, enum_rand_one_asic_namespace,
            {selected_random_port: port_config_400g},
            config_facts=config_facts, mg_facts=mg_facts,
            dry_run=False
        )

    with allure.step("Verify swss container and orchagent were not restarted"):
        assert_no_swss_or_orchagent_restart(
            duthost, enum_rand_one_frontend_asic_index,
            orchagent_pid_before, swss_started_at_before
        )
        verify_orchagent_running_or_assert(duthost)

    with allure.step("Verify 400G speed updated in DBs and port is oper up"):
        verify_port_speed_in_dbs(
            duthost, cli_namespace_prefix, selected_random_port, initial_speed
        )
        verify_port_show_interface_status(
            duthost, selected_random_port, enum_rand_one_asic_namespace,
            initial_speed, port_config_400g["lanes"],
            port_config_400g.get("fec"), require_oper_up=True
        )
        pytest_assert(
            wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost),
            "Not all admin-up ports are operationally up"
        )

    with allure.step("Verify pg lossless profile created and assigned to port"):
        current_buffer_profile_info = get_cfg_info_from_dut(
            duthost, 'BUFFER_PROFILE', enum_rand_one_asic_namespace
        )
        pytest_assert(
            initial_pg_lossless_profile_name in current_buffer_profile_info,
            "Expected buffer profile {} was not created in CONFIG_DB.".format(
                initial_pg_lossless_profile_name
            )
        )
        cmd = "sonic-db-cli {} APPL_DB keys BUFFER_PROFILE_TABLE:*".format(
            cli_namespace_prefix
        )
        current_buffer_profile_info_appl_db = duthost.shell(cmd)["stdout"]
        pytest_assert(
            initial_pg_lossless_profile_name in current_buffer_profile_info_appl_db,
            "Expected buffer profile {} was not created in APPL_DB.".format(
                initial_pg_lossless_profile_name
            )
        )

    with allure.step("Verify telemetry data for port after port speed upgrade"):
        with setup_streaming_telemetry_context(False, duthost, localhost, ptfhost, gnxi_path):
            env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
            duthost.shell(
                'sonic-db-cli CONFIG_DB hset "%s|gnmi" user_auth none' % (env.gnmi_config_table),
                module_ignore_errors=False
            )
            duthost.shell(
                'docker exec %s supervisorctl reload' % (env.gnmi_container),
                module_ignore_errors=False
            )
            cmd = (
                f'. /root/env-python3/bin/activate && cd {gnxi_path}gnmi_cli_py '
                f'&& python py_gnmicli.py -g -t {duthost.mgmt_ip} -p {env.gnmi_port} '
                f'-m get -x COUNTERS/{selected_random_port} -xt COUNTERS_DB '
                f'-o ndastreamingservertest'
            )
            pytest_assert(
                wait_until(60, 5, 0, _gnmi_counters_available, ptfhost, cmd, selected_random_port),
                "COUNTERS not found in gnmi_output for port {}".format(selected_random_port)
            )

    setup_acl_config(duthost, ip_netns_namespace_prefix)

    # Traffic scenarios with and without ACL rule matches (upstream and downstream sourced).
    traffic_scenarios = [
        {"direction": "upstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
        {"direction": "upstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 1234, "dport": 50, "verify": True, "expect_error": False, "match_rule": None},
        {"direction": "downstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
        {"direction": "downstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 1234, "dport": 50, "verify": True, "expect_error": False, "match_rule": None}
    ]

    for traffic_scenario in traffic_scenarios:
        logger.info("Starting Data Traffic Scenario: {}".format(traffic_scenario))
        if traffic_scenario["direction"] == "upstream->downstream":
            src_duthost = duthost_up
            src_asic_index = asic_id_src_up
        elif traffic_scenario["direction"] == "downstream->downstream":
            src_duthost = duthost
            src_asic_index = asic_id_src
        else:
            pytest.fail(
                "Unsupported direction for traffic scenario {}.".format(
                    traffic_scenario["direction"]
                )
            )

        duthost.shell('{} aclshow -c'.format(ip_netns_namespace_prefix))
        send_and_verify_traffic(
            tbinfo, src_duthost, duthost, src_asic_index, asic_id, ptfadapter,
            dst_ip=traffic_scenario["dst_ip"],
            dscp=traffic_scenario["dscp"],
            count=traffic_scenario["count"],
            sport=traffic_scenario["sport"],
            dport=traffic_scenario["dport"],
            verify=traffic_scenario["verify"],
            expect_error=traffic_scenario["expect_error"]
        )
        verify_traffic_acl_counters(
            duthost, ip_netns_namespace_prefix, traffic_scenario,
            acl_rule_names=ACL_RULE_VERIFY_LIST
        )
