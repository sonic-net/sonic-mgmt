import ast
import ipaddress
import json
import logging
import os
import re
import time
import pytest
import re
import requests
import shlex
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import get_downstream_neigh_type, wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.config_reload import config_reload
from tests.common.gu_utils import (
    apply_patch,
    create_checkpoint,
    delete_checkpoint,
    delete_tmpfile,
    expect_op_success,
    generate_tmpfile,
    get_gcu_timeout,
    rollback_or_reload,
)
from tests.generic_config_updater.add_cluster.helpers import add_static_route, \
    clear_static_route, clear_traffic_counters, get_active_interfaces, get_cfg_info_from_dut, \
    get_external_portchannel_members, get_portchannel_member_value, get_portchannel_min_links, \
    get_portchannel_status_map, \
    get_exabgp_port_for_neighbor, remove_dataacl_table_single_dut, remove_static_route, \
    send_and_verify_traffic, verify_routev4_existence, format_sonic_interface_dict, \
    format_sonic_buffer_pg_dict

pytestmark = [
    pytest.mark.topology("t2", "lrh", "urh")
]

logger = logging.getLogger(__name__)
allure.logger = logger


# -----------------------------
# Attributes used by test for static route, acl config
# -----------------------------

EXABGP_BASE_PORT = 5000
NHIPV4 = '10.10.246.254'
STATIC_DST_IP = '1.1.1.1'

ACL_TABLE_NAME = "L3_TRANSPORT_TEST"
ACL_TABLE_STAGE_EGRESS = "egress"
ACL_TABLE_TYPE_L3 = "L3"
ACL_RULE_FILE_PATH = "generic_config_updater/add_cluster/acl/acl_rule_src_dst_port.json"
ACL_RULE_DST_FILE = "/tmp/test_add_cluster_acl_rule.json"
ACL_RULE_SKIP_VERIFICATION_LIST = [""]
PORTCHANNEL_UP_WAIT_TIME = 300
PORTCHANNEL_UP_WAIT_INTERVAL = 20
LAG_STATE_WAIT_TIME = 120
LAG_STATE_WAIT_INTERVAL = 5
ASIC_DB_WAIT_TIME = 60
ASIC_DB_WAIT_INTERVAL = 5
PORT_COUNTER_WAIT_TIME = 60
PORT_COUNTER_WAIT_INTERVAL = 5
PORTCHANNEL_TRAFFIC_COUNT = 10
PORTCHANNEL_HASH_ATTEMPTS = 64
PORTCHANNEL_TRAFFIC_DST_IPS = (
    "198.18.252.251",
    "198.18.252.252",
    "198.18.252.253",
    "198.18.252.254",
)
COUNTERS_DB_TX_FIELDS = (
    "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
    "SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS",
    "SAI_PORT_STAT_IF_OUT_OCTETS",
    "SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS",
)
INTERNAL_PORT_PREFIXES = ("Ethernet-BP", "Ethernet-IB", "Ethernet-Rec")
LOGANALYZER_IGNORE_REGEX = [
    ".*createEntry: Failed to start PFC Watchdog on port.*",
]

# -----------------------------
# Helper functions that validate apply-patch changes
# -----------------------------


def escape_json_pointer_key(key):
    """
    Escape one CONFIG_DB key segment for use in a JSON patch path.
    """
    return key.replace('~', '~0').replace('/', '~1')


def _get_downstream_neighbor_types(tbinfo):
    """
    Return downstream neighbor type strings for the topology.
    """
    try:
        downstream_neigh_types = get_downstream_neigh_type(tbinfo, is_upper=True)
    except TypeError:
        downstream_neigh_types = None
        for topo_attr in (tbinfo["topo"]["name"], tbinfo["topo"]["type"]):
            downstream_neigh_types = get_downstream_neigh_type(topo_attr, is_upper=True)
            if downstream_neigh_types:
                break

    if downstream_neigh_types:
        if isinstance(downstream_neigh_types, (list, tuple, set)):
            return [
                str(item).strip() for item in downstream_neigh_types if str(item).strip()
            ]
        return [
            item.strip() for item in downstream_neigh_types.split(',') if item.strip()
        ]
    return ["T1"]


def _pick_primary_downstream_hostname(duthosts, tbinfo):
    """
    Pick a frontend DUT that has downstream neighbors in the minigraph.
    """
    downstream_nbr_type = _get_downstream_neighbor_types(tbinfo)
    for dut in duthosts.frontend_nodes:
        minigraph_neighbors = dut.get_extended_minigraph_facts(tbinfo)['minigraph_neighbors']
        for neighbor in minigraph_neighbors.values():
            if any(downstream_type in neighbor['name'] for downstream_type in downstream_nbr_type):
                return dut.hostname

    pytest.fail(
        "Did not find a dut in duthosts for topo type {} that has downstream nbr type {}".format(
            tbinfo["topo"]["type"], downstream_nbr_type
        )
    )


def _ordered_frontend_asic_indices(duthost, preferred_asic_index):
    """
    Return frontend ASIC IDs with the enum-selected ASIC first.
    """
    if duthost.is_multi_asic:
        asic_indices = duthost.get_frontend_asic_ids()
    else:
        asic_indices = [DEFAULT_ASIC_ID]

    if preferred_asic_index in asic_indices:
        return [preferred_asic_index] + [
            asic_index for asic_index in asic_indices if asic_index != preferred_asic_index
        ]
    return asic_indices


def _get_namespace_prefixes(duthost, asic_index):
    """
    Return namespace, CLI prefix, and ip-netns prefix for an ASIC ID.
    """
    asic_namespace = duthost.get_namespace_from_asic_id(asic_index)
    if asic_namespace is None:
        return None, '', ''
    return asic_namespace, '-n {}'.format(asic_namespace), 'sudo ip netns exec {}'.format(asic_namespace)


def _select_staged_portchannel(config_facts, portchannel_status_map=None):
    """
    Select one external PortChannel where a member can be staged back later.

    The staged flow needs an original min_links value greater than one so the
    first add-cluster patch can withhold one member and reduce min_links by one.
    """
    for portchannel in sorted(config_facts.get("PORTCHANNEL", {})):
        members = get_external_portchannel_members(config_facts, portchannel)
        portchannel_members = config_facts.get("PORTCHANNEL_MEMBER", {}).get(portchannel, {})
        if len(members) != len(portchannel_members):
            logger.info("Skipping PortChannel %s: contains internal members", portchannel)
            continue
        if len(members) < 2:
            continue
        if (
            portchannel_status_map is not None and
            portchannel_status_map.get(portchannel) != "up"
        ):
            logger.info(
                "Skipping PortChannel %s: status is %s, expected up",
                portchannel,
                portchannel_status_map.get(portchannel),
            )
            continue

        original_min_links = get_portchannel_min_links(config_facts, portchannel)
        if original_min_links is None:
            logger.info("Skipping PortChannel %s: min_links is not configured", portchannel)
            continue
        try:
            original_min_links_int = int(original_min_links)
        except (TypeError, ValueError):
            logger.info("Skipping PortChannel %s: min_links=%s is not an integer",
                        portchannel, original_min_links)
            continue
        if original_min_links_int <= 1:
            logger.info("Skipping PortChannel %s: min_links=%s cannot be reduced by one",
                        portchannel, original_min_links)
            continue

        withheld_member = members[-1]
        return {
            "portchannel": portchannel,
            "withheld_member": withheld_member,
            "remaining_members": [member for member in members if member != withheld_member],
            "original_min_links": str(original_min_links),
            "staged_min_links": str(original_min_links_int - 1),
        }
    return None


def _stage_portchannel_config(pc_dict, staged_portchannel):
    """
    Return PortChannel config with selected PortChannel min_links reduced.
    """
    if not staged_portchannel:
        return pc_dict

    portchannel = staged_portchannel["portchannel"]
    if portchannel not in pc_dict:
        return pc_dict

    pc_dict = pc_dict.copy()
    pc_dict[portchannel] = pc_dict[portchannel].copy()
    pc_dict[portchannel]["min_links"] = staged_portchannel["staged_min_links"]
    return pc_dict


def _filter_staged_portchannel_member_dict(portchannel_member_dict, staged_portchannel):
    """
    Return PortChannel member dict without the member staged for later add.
    """
    if not staged_portchannel:
        return portchannel_member_dict

    withheld_key = "{}|{}".format(
        staged_portchannel["portchannel"],
        staged_portchannel["withheld_member"]
    )
    return {
        key: value
        for key, value in portchannel_member_dict.items()
        if key != withheld_key
    }


def _is_port_scoped_key(key, port):
    """
    Return True if a table key is scoped to the selected physical port.
    """
    return key.split('|', 1)[0] == port


def _filter_port_scoped_entries(table_dict, port):
    """
    Return a table dictionary without entries scoped to a physical port.
    """
    return {
        key: value
        for key, value in table_dict.items()
        if not _is_port_scoped_key(key, port)
    }


def _queue_key_matches_port(queue_key, port):
    """
    Return True if a QUEUE key belongs to the selected physical port.
    """
    if queue_key.startswith("QUEUE|"):
        queue_key = queue_key.split('|', 1)[1]
    return port in queue_key.split('|')


def _format_sonic_queue_dict(queue_dict):
    """
    Convert QUEUE config_facts into CONFIG_DB key/value form.
    """
    formatted_queue_dict = {}
    for key, value in queue_dict.items():
        nested_queue_table = (
            isinstance(value, dict) and
            value and
            all(
                isinstance(nested_value, dict)
                for nested_value in value.values()
            )
        )
        if nested_queue_table:
            for nested_key, nested_value in value.items():
                queue_key = "{}|{}".format(key, nested_key)
                if queue_key.startswith("QUEUE|"):
                    queue_key = queue_key.split('|', 1)[1]
                formatted_queue_dict[queue_key] = nested_value
            continue

        queue_key = key
        if queue_key.startswith("QUEUE|"):
            queue_key = queue_key.split('|', 1)[1]
        formatted_queue_dict[queue_key] = value
    return formatted_queue_dict


def _filter_queue_port_entries(queue_dict, port):
    """
    Return QUEUE entries without entries scoped to a physical port.
    """
    return {
        key: value
        for key, value in _format_sonic_queue_dict(queue_dict).items()
        if not _queue_key_matches_port(key, port)
    }


def _is_queue_for_internal_port(queue_key):
    """
    Return True if a QUEUE key belongs to an internal chassis port.
    """
    return any(
        key_part.startswith(("Ethernet-IB", "Ethernet-Rec", "Ethernet-BP"))
        for key_part in queue_key.split('|')
    )


def _filter_staged_raw_portchannel_members(portchannel_members, staged_portchannel):
    """
    Return raw PORTCHANNEL_MEMBER config without the staged member.
    """
    if not staged_portchannel:
        return portchannel_members

    portchannel = staged_portchannel["portchannel"]
    withheld_member = staged_portchannel["withheld_member"]
    filtered_members = {}
    for key, value in portchannel_members.items():
        if '|' in key:
            if key == "{}|{}".format(portchannel, withheld_member):
                continue
            filtered_members[key] = value
            continue

        if key == portchannel and isinstance(value, dict):
            remaining_members = {
                member: member_value
                for member, member_value in value.items()
                if member != withheld_member
            }
            if remaining_members:
                filtered_members[key] = remaining_members
            continue

        filtered_members[key] = value
    return filtered_members


def _get_member_neighbor_name(config_facts, mg_facts, member):
    """
    Return the minigraph neighbor name for a physical member port.
    """
    device_neighbor = config_facts.get("DEVICE_NEIGHBOR", {}).get(member, {})
    if isinstance(device_neighbor, dict) and device_neighbor.get("name"):
        return device_neighbor["name"]

    minigraph_neighbor = mg_facts.get("minigraph_neighbors", {}).get(member, {})
    if isinstance(minigraph_neighbor, dict):
        return minigraph_neighbor.get("name")
    return None


def _is_neighbor_metadata_used_by_other_port(config_facts, neighbor_name, member):
    """
    Return True if another physical port still references the neighbor metadata.
    """
    if not neighbor_name:
        return False
    for port, neighbor_info in config_facts.get("DEVICE_NEIGHBOR", {}).items():
        if port == member or not isinstance(neighbor_info, dict):
            continue
        if neighbor_info.get("name") == neighbor_name:
            return True
    return False


def _filter_staged_member_restore_config(config_facts, mg_facts, staged_portchannel):
    """
    Return config_facts for first-stage restore without the withheld member port.
    """
    if not staged_portchannel:
        return config_facts

    member = staged_portchannel["withheld_member"]
    filtered_config = dict(config_facts)
    for table_name in ["INTERFACE", "BUFFER_PG", "PORT_QOS_MAP", "PFC_WD"]:
        if table_name in filtered_config:
            filtered_config[table_name] = _filter_port_scoped_entries(
                filtered_config[table_name],
                member
            )

    if "QUEUE" in filtered_config:
        filtered_config["QUEUE"] = _filter_queue_port_entries(
            filtered_config["QUEUE"],
            member
        )

    if "PORTCHANNEL_MEMBER" in filtered_config:
        filtered_config["PORTCHANNEL_MEMBER"] = _filter_staged_raw_portchannel_members(
            filtered_config["PORTCHANNEL_MEMBER"],
            staged_portchannel
        )

    if "CABLE_LENGTH" in filtered_config:
        filtered_cable_length = {}
        for cable_length_group, cable_length_ports in filtered_config["CABLE_LENGTH"].items():
            if isinstance(cable_length_ports, dict):
                filtered_cable_length[cable_length_group] = _filter_port_scoped_entries(
                    cable_length_ports,
                    member
                )
            else:
                filtered_cable_length[cable_length_group] = cable_length_ports
        filtered_config["CABLE_LENGTH"] = filtered_cable_length

    if "DEVICE_NEIGHBOR" in filtered_config:
        filtered_config["DEVICE_NEIGHBOR"] = {
            key: value
            for key, value in filtered_config["DEVICE_NEIGHBOR"].items()
            if key != member
        }

    neighbor_name = _get_member_neighbor_name(config_facts, mg_facts, member)
    if (neighbor_name and
            not _is_neighbor_metadata_used_by_other_port(config_facts, neighbor_name, member) and
            "DEVICE_NEIGHBOR_METADATA" in filtered_config):
        filtered_config["DEVICE_NEIGHBOR_METADATA"] = {
            key: value
            for key, value in filtered_config["DEVICE_NEIGHBOR_METADATA"].items()
            if key != neighbor_name
        }

    return filtered_config


def _apply_json_patch(duthost, json_patch, description):
    """
    Apply a JSON patch through GCU and assert success.
    """
    tmpfile = generate_tmpfile(duthost)
    try:
        logger.info("Applying patch: %s", description)
        _log_json_patch_content(description, json_patch)
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def _log_json_patch_content(description, json_patch):
    """
    Log JSON patch content in a PR-friendly format for test evidence.
    """
    logger.info(
        "Patch content for %s:\n%s",
        description,
        json.dumps(json_patch, indent=2, sort_keys=True)
    )


def _portchannel_member_exists(duthost, cli_namespace_prefix, portchannel, member):
    """
    Return True if a PortChannel member key exists in CONFIG_DB.
    """
    cmd = "sonic-db-cli {} CONFIG_DB EXISTS 'PORTCHANNEL_MEMBER|{}|{}'".format(
        cli_namespace_prefix, portchannel, member
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    return output["stdout"].strip() == "1"


def _get_portchannel_min_links_from_dut(duthost, cli_namespace_prefix, portchannel):
    """
    Read PortChannel min_links from running CONFIG_DB.
    """
    cmd = "sonic-db-cli {} CONFIG_DB HGET 'PORTCHANNEL|{}' min_links".format(
        cli_namespace_prefix, portchannel
    )
    return duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip()


def _get_config_db_keys(duthost, cli_namespace_prefix, pattern):
    """
    Return CONFIG_DB keys matching a sonic-db-cli KEYS pattern.
    """
    cmd = "sonic-db-cli {} CONFIG_DB KEYS '{}'".format(cli_namespace_prefix, pattern)
    output = duthost.shell(cmd, module_ignore_errors=True)
    return [
        key.strip()
        for key in output["stdout"].splitlines()
        if key.strip()
    ]


def _get_port_admin_status_from_dut(duthost, cli_namespace_prefix, port):
    """
    Read a port's admin_status from running CONFIG_DB.
    """
    cmd = "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' admin_status".format(
        cli_namespace_prefix,
        port
    )
    return duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip()


def verify_staged_portchannel_member_state(duthost,
                                           cli_namespace_prefix,
                                           staged_portchannel,
                                           member_should_exist,
                                           expected_min_links):
    """
    Verify staged PortChannel member presence and PortChannel min_links.
    """
    portchannel = staged_portchannel["portchannel"]
    member = staged_portchannel["withheld_member"]
    member_exists = _portchannel_member_exists(
        duthost, cli_namespace_prefix, portchannel, member
    )
    pytest_assert(
        member_exists == member_should_exist,
        "PortChannel member {}|{} existence mismatch. Expected {} found {}".format(
            portchannel, member, member_should_exist, member_exists
        )
    )

    actual_min_links = _get_portchannel_min_links_from_dut(
        duthost, cli_namespace_prefix, portchannel
    )
    pytest_assert(
        actual_min_links == str(expected_min_links),
        "PortChannel {} min_links mismatch. Expected {} found {}".format(
            portchannel, expected_min_links, actual_min_links
        )
    )


def verify_staged_member_default_state(duthost, cli_namespace_prefix, staged_portchannel):
    """
    Verify the staged physical member remains in removed/default admin-down state.
    """
    portchannel = staged_portchannel["portchannel"]
    member = staged_portchannel["withheld_member"]
    expected_empty_patterns = [
        "PORTCHANNEL_MEMBER|{}|{}".format(portchannel, member),
        "INTERFACE|{}".format(member),
        "INTERFACE|{}|*".format(member),
        "PORT_QOS_MAP|{}".format(member),
        "QUEUE|{}|*".format(member),
        "QUEUE|*|{}|*".format(member),
    ]
    for pattern in expected_empty_patterns:
        keys = _get_config_db_keys(duthost, cli_namespace_prefix, pattern)
        pytest_assert(
            not keys,
            "Expected no CONFIG_DB keys for staged member pattern {}, found {}".format(
                pattern,
                keys
            )
        )
        logger.info("Verified no CONFIG_DB keys for staged member pattern %s", pattern)

    actual_admin_status = _get_port_admin_status_from_dut(
        duthost,
        cli_namespace_prefix,
        member
    )
    pytest_assert(
        actual_admin_status == "down",
        "Expected staged member {} admin_status down before final restore, found {}".format(
            member,
            actual_admin_status
        )
    )
    logger.info(
        "Verified staged member %s remains admin_status down before final restore",
        member
    )


def wait_for_portchannel_up_or_log(duthost, asic_namespace, portchannel):
    """
    Wait for a PortChannel to become up and log an error on timeout.

    This check is intentionally non-fatal. The test verifies that GCU restored
    the intended config; LACP peer state may depend on external topology state.
    """
    last_result = {"stdout": "", "stderr": "", "rc": None}
    last_status = {}

    def _is_portchannel_up():
        nonlocal last_result, last_status
        last_status, last_result = get_portchannel_status_map(
            duthost,
            asic_namespace,
            portchannels_to_check={portchannel},
        )
        logger.info("PortChannel %s status while waiting for up: %s",
                    portchannel, last_status.get(portchannel))
        return last_status.get(portchannel) == "up"

    if wait_until(PORTCHANNEL_UP_WAIT_TIME, PORTCHANNEL_UP_WAIT_INTERVAL, 0, _is_portchannel_up):
        return True

    logger.error(
        "PortChannel %s did not come up after staged add-cluster restore. "
        "Last status=%s rc=%s stdout=%s stderr=%s",
        portchannel,
        last_status.get(portchannel),
        last_result.get("rc"),
        last_result.get("stdout", ""),
        last_result.get("stderr", ""),
    )
    return False


def _normalize_acl_ports(value):
    """
    Return ACL table ports as a normalized list.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [
            port.strip()
            for port in value.split(',')
            if port.strip()
        ]
    return list(value)


def _parse_counter_value(counter_value):
    """
    Parse a SONiC counter value into an integer.
    """
    if counter_value is None:
        return None
    try:
        return int(str(counter_value).replace(',', ''))
    except ValueError:
        return None


def _db_hget(duthost, cli_namespace_prefix, db_name, key, field):
    """
    Return one Redis DB hash field value, or None on command failure.
    """
    cmd = "sonic-db-cli {} {} HGET {} {}".format(
        cli_namespace_prefix,
        db_name,
        shlex.quote(key),
        shlex.quote(field),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to read %s field %s/%s: rc=%s stdout=%s stderr=%s",
            db_name,
            key,
            field,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None
    return output.get("stdout", "").strip()


def _db_hgetall(duthost, cli_namespace_prefix, db_name, key):
    """
    Return one Redis DB hash as a dictionary, or None on command/parse failure.
    """
    cmd = "sonic-db-cli {} {} HGETALL {}".format(
        cli_namespace_prefix,
        db_name,
        shlex.quote(key),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to read %s hash %s: rc=%s stdout=%s stderr=%s",
            db_name,
            key,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None

    lines = output.get("stdout_lines", [])
    if len(lines) == 1:
        try:
            parsed_output = ast.literal_eval(lines[0])
        except (SyntaxError, ValueError):
            parsed_output = None
        if isinstance(parsed_output, dict):
            return {
                str(hash_key): str(hash_value)
                for hash_key, hash_value in parsed_output.items()
            }

    if not lines:
        return {}
    if len(lines) % 2:
        logger.warning(
            "Failed to parse %s hash %s HGETALL output: %s",
            db_name,
            key,
            lines,
        )
        return None
    return dict(zip(lines[0::2], lines[1::2]))


def _db_keys(duthost, cli_namespace_prefix, db_name, pattern):
    """
    Return Redis keys matching a pattern.
    """
    cmd = "sonic-db-cli {} {} KEYS {}".format(
        cli_namespace_prefix,
        db_name,
        shlex.quote(pattern),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to query %s keys %s: rc=%s stdout=%s stderr=%s",
            db_name,
            pattern,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None
    return output.get("stdout_lines", [])


def _db_key_exists(duthost, cli_namespace_prefix, db_name, key):
    """
    Return True when a Redis DB key exists.
    """
    cmd = "sonic-db-cli {} {} EXISTS {}".format(
        cli_namespace_prefix,
        db_name,
        shlex.quote(key),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to query %s key %s: rc=%s stdout=%s stderr=%s",
            db_name,
            key,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return False
    return output.get("stdout", "").strip().lower() in ("1", "true")


def _get_counters_db_port_oid(duthost, cli_namespace_prefix, port):
    """
    Return SAI object ID for a port from COUNTERS_DB.
    """
    port_oid = _db_hget(
        duthost,
        cli_namespace_prefix,
        "COUNTERS_DB",
        "COUNTERS_PORT_NAME_MAP",
        port,
    )
    pytest_assert(
        port_oid,
        "COUNTERS_DB missing COUNTERS_PORT_NAME_MAP entry for {}".format(port),
    )
    return port_oid


def _get_counters_db_counter_value(duthost, cli_namespace_prefix, port):
    """
    Return one usable TX counter field/value for a port from COUNTERS_DB.
    """
    port_oid = _get_counters_db_port_oid(
        duthost,
        cli_namespace_prefix,
        port,
    )
    counter_hash = _db_hgetall(
        duthost,
        cli_namespace_prefix,
        "COUNTERS_DB",
        "COUNTERS:{}".format(port_oid),
    )
    pytest_assert(
        counter_hash,
        "COUNTERS_DB missing readable COUNTERS hash for {} ({})".format(
            port,
            port_oid,
        ),
    )
    for field in COUNTERS_DB_TX_FIELDS:
        counter_value = _parse_counter_value(counter_hash.get(field))
        if counter_value is not None:
            return field, counter_value
    pytest_assert(
        False,
        "COUNTERS_DB for {} ({}) lacks TX fields {}; available fields={}".format(
            port,
            port_oid,
            COUNTERS_DB_TX_FIELDS,
            sorted(counter_hash.keys()),
        ),
    )


def _get_portstat_counter(duthost, port, counter_name):
    """
    Return one counter from ``portstat -j`` output.
    """
    output = duthost.shell(
        "portstat -ji {}".format(shlex.quote(port)),
        module_ignore_errors=True,
    )
    if output["rc"]:
        logger.info(
            "Failed to read portstat for %s: rc=%s stdout=%s stderr=%s",
            port,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None

    stdout = output.get("stdout", "")
    json_start = stdout.find("{")
    if json_start == -1:
        logger.info("portstat output for %s has no JSON payload: %s", port, stdout)
        return None

    try:
        port_stats = json.loads(stdout[json_start:])
    except ValueError:
        logger.exception("Failed to parse portstat JSON for %s: %s", port, stdout)
        return None

    return _parse_counter_value(port_stats.get(port, {}).get(counter_name))


def _get_member_counter_snapshot(duthost, cli_namespace_prefix, member):
    """
    Return portstat and COUNTERS_DB TX counter values for one member.
    """
    counters_db_field, counters_db_value = _get_counters_db_counter_value(
        duthost,
        cli_namespace_prefix,
        member,
    )
    snapshot = {
        "portstat_TX_OK": _get_portstat_counter(duthost, member, "TX_OK"),
        "counters_db_field": counters_db_field,
        "counters_db_value": counters_db_value,
    }
    pytest_assert(
        snapshot["portstat_TX_OK"] is not None,
        "portstat TX_OK counter is not readable for {}".format(member),
    )
    pytest_assert(
        snapshot["counters_db_value"] is not None,
        "COUNTERS_DB TX counter is not readable for {}".format(member),
    )
    return snapshot


def _runner_member_selected(member_state):
    """
    Return True when teamd reports the member selected and link-up.
    """
    runner_state = member_state.get("runner", {})
    link_state = member_state.get("link", {})
    selected = runner_state.get("selected")
    link_up = link_state.get("up")

    if isinstance(selected, bool):
        selected_ok = selected
    else:
        selected_ok = str(selected).lower() in ("true", "yes", "1")

    if link_up is None:
        return selected_ok
    if isinstance(link_up, bool):
        return selected_ok and link_up
    return selected_ok and str(link_up).lower() in ("true", "yes", "1")


def _expected_staged_portchannel_members(staged_portchannel):
    """
    Return all PortChannel members expected after staged restore.
    """
    return sorted(
        staged_portchannel["remaining_members"] +
        [staged_portchannel["withheld_member"]]
    )


def verify_staged_teamd_lag_member_state(duthost, staged_portchannel):
    """
    Verify teamdctl/lag_facts reports the staged member selected.
    """
    portchannel = staged_portchannel["portchannel"]
    member = staged_portchannel["withheld_member"]
    expected_members = _expected_staged_portchannel_members(staged_portchannel)
    last_summary = {}

    def _lag_state_matches():
        nonlocal last_summary
        lag_facts = duthost.lag_facts(
            host=duthost.hostname,
        )['ansible_facts']['lag_facts']
        lag_info = lag_facts.get("lags", {}).get(portchannel)
        if not lag_info:
            last_summary = {"missing_portchannel": portchannel}
            return False

        po_config = lag_info.get("po_config", {})
        po_stats = lag_info.get("po_stats", {})
        configured_ports = set(po_config.get("ports", {}).keys())
        member_stats = po_stats.get("ports", {})
        missing_members = sorted(set(expected_members) - configured_ports)
        min_ports = po_config.get("runner", {}).get("min_ports")
        member_state = member_stats.get(member, {})

        last_summary = {
            "po_intf_stat": lag_info.get("po_intf_stat"),
            "configured_ports": sorted(configured_ports),
            "missing_members": missing_members,
            "min_ports": min_ports,
            "withheld_member_state": member_state,
        }
        logger.info("teamd/lag_facts summary for %s: %s", portchannel, last_summary)
        return (
            lag_info.get("po_intf_stat") == "Up" and
            not missing_members and
            member in member_stats and
            _runner_member_selected(member_state)
        )

    pytest_assert(
        wait_until(
            LAG_STATE_WAIT_TIME,
            LAG_STATE_WAIT_INTERVAL,
            0,
            _lag_state_matches,
        ),
        "teamd/lag_facts did not report staged member {} restored in {}; "
        "last_state={}".format(member, portchannel, last_summary),
    )
    if str(last_summary.get("min_ports")) != str(staged_portchannel["original_min_links"]):
        logger.error(
            "teamd/lag_facts runner min_ports for %s is %s after CONFIG_DB "
            "min_links restore; expected %s. Continuing because CONFIG_DB "
            "min_links is verified directly.",
            portchannel,
            last_summary.get("min_ports"),
            staged_portchannel["original_min_links"],
        )


def verify_staged_asic_db_lag_member_state(duthost, cli_namespace_prefix,
                                           staged_portchannel):
    """
    Verify ASIC_DB has enabled SAI LAG_MEMBER objects for staged LAG members.
    """
    portchannel = staged_portchannel["portchannel"]
    member = staged_portchannel["withheld_member"]
    expected_members = _expected_staged_portchannel_members(staged_portchannel)
    last_summary = {}

    def _lag_members_ready():
        nonlocal last_summary
        member_port_oids = {
            member_name: _db_hget(
                duthost,
                cli_namespace_prefix,
                "COUNTERS_DB",
                "COUNTERS_PORT_NAME_MAP",
                member_name,
            )
            for member_name in expected_members
        }
        missing_oids = sorted(
            member_name
            for member_name, port_oid in member_port_oids.items()
            if not port_oid
        )
        if missing_oids:
            last_summary = {"missing_counter_oids": missing_oids}
            return False

        lag_member_keys = _db_keys(
            duthost,
            cli_namespace_prefix,
            "ASIC_DB",
            "ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:*",
        )
        if lag_member_keys is None:
            last_summary = {"lag_member_keys": None}
            return False

        lag_members_by_port = {}
        for lag_member_key in lag_member_keys:
            port_oid = _db_hget(
                duthost,
                cli_namespace_prefix,
                "ASIC_DB",
                lag_member_key,
                "SAI_LAG_MEMBER_ATTR_PORT_ID",
            )
            if port_oid not in member_port_oids.values():
                continue

            matching_member = [
                member_name
                for member_name, member_oid in member_port_oids.items()
                if member_oid == port_oid
            ][0]
            lag_members_by_port[matching_member] = {
                "key": lag_member_key,
                "lag_id": _db_hget(
                    duthost,
                    cli_namespace_prefix,
                    "ASIC_DB",
                    lag_member_key,
                    "SAI_LAG_MEMBER_ATTR_LAG_ID",
                ),
                "egress_disable": _db_hget(
                    duthost,
                    cli_namespace_prefix,
                    "ASIC_DB",
                    lag_member_key,
                    "SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE",
                ),
            }

        missing_members = sorted(
            set(expected_members) - set(lag_members_by_port.keys())
        )
        disabled_members = sorted(
            member_name
            for member_name, member_info in lag_members_by_port.items()
            if str(member_info.get("egress_disable", "")).lower() == "true"
        )
        lag_ids = {
            member_info["lag_id"]
            for member_info in lag_members_by_port.values()
            if member_info.get("lag_id")
        }
        lag_key_exists = False
        if len(lag_ids) == 1:
            lag_key_exists = _db_key_exists(
                duthost,
                cli_namespace_prefix,
                "ASIC_DB",
                "ASIC_STATE:SAI_OBJECT_TYPE_LAG:{}".format(list(lag_ids)[0]),
            )

        last_summary = {
            "portchannel": portchannel,
            "member_port_oids": member_port_oids,
            "lag_members_by_port": lag_members_by_port,
            "missing_members": missing_members,
            "disabled_members": disabled_members,
            "lag_ids": sorted(lag_ids),
            "lag_key_exists": lag_key_exists,
        }
        logger.info("ASIC_DB LAG summary for %s: %s", portchannel, last_summary)
        return (
            not missing_members and
            not disabled_members and
            member in lag_members_by_port and
            len(lag_ids) == 1 and
            lag_key_exists
        )

    pytest_assert(
        wait_until(
            ASIC_DB_WAIT_TIME,
            ASIC_DB_WAIT_INTERVAL,
            0,
            _lag_members_ready,
        ),
        "ASIC_DB did not expose enabled SAI LAG_MEMBER objects for {}; "
        "last_state={}".format(portchannel, last_summary),
    )


def verify_staged_counters_db_readable(duthost, cli_namespace_prefix,
                                       staged_portchannel):
    """
    Verify COUNTERS_DB exposes the staged member and, when present, LAG counters.
    """
    portchannel = staged_portchannel["portchannel"]
    member = staged_portchannel["withheld_member"]
    member_field, member_counter = _get_counters_db_counter_value(
        duthost,
        cli_namespace_prefix,
        member,
    )
    logger.info(
        "COUNTERS_DB staged member %s counter %s=%s",
        member,
        member_field,
        member_counter,
    )

    lag_oid = _db_hget(
        duthost,
        cli_namespace_prefix,
        "COUNTERS_DB",
        "COUNTERS_LAG_NAME_MAP",
        portchannel,
    )
    if not lag_oid:
        logger.info(
            "COUNTERS_DB has no COUNTERS_LAG_NAME_MAP entry for %s; "
            "validated member counters only",
            portchannel,
        )
        return

    lag_counter_hash = _db_hgetall(
        duthost,
        cli_namespace_prefix,
        "COUNTERS_DB",
        "COUNTERS:{}".format(lag_oid),
    )
    pytest_assert(
        lag_counter_hash is not None,
        "Failed to read COUNTERS_DB LAG hash for {} ({})".format(
            portchannel,
            lag_oid,
        ),
    )
    logger.info(
        "COUNTERS_DB PortChannel %s counter fields: %s",
        portchannel,
        sorted(lag_counter_hash.keys()),
    )


def _get_interface_neighbor_and_intfs(mg_facts, selected_port):
    """
    Resolve BGP neighbor name and addresses for one DUT interface.
    """
    vm_neighbors = mg_facts.get("minigraph_neighbors", {})
    pytest_assert(
        selected_port in vm_neighbors,
        "No minigraph neighbor found for {}".format(selected_port),
    )
    neighbor_name = vm_neighbors[selected_port]['name']
    neighbor_addr = []
    neighbor_ipv4_addr = ""
    neighbor_ipv6_addr = ""

    for neighbor_info in mg_facts.get("minigraph_bgp", []):
        if neighbor_info.get("name") != neighbor_name:
            continue
        addr = neighbor_info.get("addr")
        if not addr:
            continue
        neighbor_addr.append(addr)
        try:
            parsed_addr = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if parsed_addr.version == 4:
            neighbor_ipv4_addr = addr
        elif parsed_addr.version == 6:
            neighbor_ipv6_addr = addr

    neighbor_addr = sorted(set(neighbor_addr))
    logger.info(
        "Found neighbor %s with addresses %s for DUT port %s. IPv4=%s IPv6=%s",
        neighbor_name,
        neighbor_addr,
        selected_port,
        neighbor_ipv4_addr,
        neighbor_ipv6_addr,
    )
    return neighbor_name, neighbor_addr, neighbor_ipv4_addr, neighbor_ipv6_addr


def _select_ptf_source_port(duthost, asic_namespace, mg_facts,
                            excluded_interfaces):
    """
    Select a frontend PTF source port that is not in the tested PortChannel.
    """
    status_map = {
        row['interface']: row
        for row in duthost.show_and_parse(
            "show interface status -n {}".format(asic_namespace)
            if asic_namespace else "show interface status"
        )
        if row.get('interface')
    }
    for interface, ptf_index in sorted(
        mg_facts.get("minigraph_ptf_indices", {}).items(),
        key=lambda item: item[1],
    ):
        if interface in excluded_interfaces:
            continue
        if interface.startswith(INTERNAL_PORT_PREFIXES):
            continue
        status = status_map.get(interface, {})
        if status:
            if status.get("admin", "").lower() != "up":
                continue
            if status.get("oper", "").lower() != "up":
                continue
        logger.info(
            "Selected PTF source interface %s ptf_index=%s",
            interface,
            ptf_index,
        )
        return interface, ptf_index

    pytest_assert(
        False,
        "No oper-up frontend PTF source port found outside {}".format(
            sorted(excluded_interfaces)
        ),
    )


def _wait_for_staged_member_counters(duthost, cli_namespace_prefix,
                                     member, counter_baseline,
                                     min_tx_packets):
    """
    Wait for show/COUNTERS_DB TX counters on the staged member.
    """
    last_summary = {}

    def _counters_match():
        nonlocal last_summary
        portstat_tx_ok = _get_portstat_counter(duthost, member, "TX_OK")
        counters_db_field, counters_db_value = _get_counters_db_counter_value(
            duthost,
            cli_namespace_prefix,
            member,
        )
        portstat_delta = None
        counters_db_delta = None
        if portstat_tx_ok is not None:
            portstat_delta = (
                portstat_tx_ok - counter_baseline["portstat_TX_OK"]
            )
        if counters_db_value is not None:
            counters_db_delta = (
                counters_db_value - counter_baseline["counters_db_value"]
            )
        last_summary = {
            "baseline": counter_baseline,
            "portstat_TX_OK": portstat_tx_ok,
            "portstat_TX_OK_delta": portstat_delta,
            "counters_db_field": counters_db_field,
            "counters_db_value": counters_db_value,
            "counters_db_delta": counters_db_delta,
            "expected_min_packets": min_tx_packets,
        }
        logger.info("Staged member counter summary for %s: %s", member, last_summary)
        return (
            portstat_delta is not None and
            counters_db_delta is not None and
            portstat_delta >= min_tx_packets and
            counters_db_delta >= min_tx_packets
        )

    pytest_assert(
        wait_until(
            PORT_COUNTER_WAIT_TIME,
            PORT_COUNTER_WAIT_INTERVAL,
            0,
            _counters_match,
        ),
        "Staged member {} counters did not increase as expected; "
        "last_state={}".format(member, last_summary),
    )


def _change_static_route_no_proxy(operation, tbinfo, neighbor_ip,
                                  exabgp_port, route_ip, mask='32',
                                  aspath=65500, nhipv4=NHIPV4):
    """
    Announce or withdraw a PTF ExaBGP route without using proxy env settings.
    """
    common_config = tbinfo['topo']['properties']['configuration_properties'].get(
        'common',
        {},
    )
    ptf_ip = tbinfo['ptf_ip']
    dst_prefix = "{}/{}".format(route_ip, mask)
    nexthop = common_config.get('nhipv4', nhipv4)
    url = "http://{}:{}".format(ptf_ip, exabgp_port)
    data = {
        "command": "{} route {} next-hop {} as-path [ {} ]".format(
            operation,
            dst_prefix,
            nexthop,
            aspath,
        )
    }
    logger.info(
        "%s route through PTF ExaBGP: url=%s dst_prefix=%s nexthop=%s "
        "aspath=%s neighbor=%s",
        operation.capitalize(),
        url,
        dst_prefix,
        nexthop,
        aspath,
        neighbor_ip,
    )
    session = requests.Session()
    session.trust_env = False
    response = session.post(url, data=data, timeout=10)
    pytest_assert(
        response.status_code == 200,
        "{} route request failed: url={} status={} body={}".format(
            operation,
            url,
            response.status_code,
            response.text[:500],
        ),
    )


def _add_static_route_no_proxy(tbinfo, neighbor_ip, exabgp_port, route_ip):
    """
    Announce a static route through PTF ExaBGP without proxy env settings.
    """
    _change_static_route_no_proxy(
        "announce",
        tbinfo,
        neighbor_ip,
        exabgp_port,
        route_ip,
    )


def _remove_static_route_no_proxy(tbinfo, neighbor_ip, exabgp_port, route_ip):
    """
    Withdraw a static route through PTF ExaBGP without proxy env settings.
    """
    _change_static_route_no_proxy(
        "withdraw",
        tbinfo,
        neighbor_ip,
        exabgp_port,
        route_ip,
    )


def _select_unused_portchannel_traffic_dst_ip(duthost, asic_index):
    """
    Select a route prefix that is absent before dataplane validation starts.
    """
    for dst_ip in PORTCHANNEL_TRAFFIC_DST_IPS:
        if verify_routev4_existence(
            duthost,
            asic_index,
            dst_ip,
            should_exist=False,
        ):
            logger.info(
                "Selected unused PortChannel traffic destination %s",
                dst_ip,
            )
            return dst_ip
        logger.info(
            "PortChannel traffic destination candidate %s already exists",
            dst_ip,
        )

    pytest_assert(
        False,
        "No unused PortChannel traffic destination found from candidates {}".format(
            PORTCHANNEL_TRAFFIC_DST_IPS,
        ),
    )


def _clear_static_route_no_proxy(tbinfo, duthost, route_ip):
    """
    Withdraw an existing ExaBGP route without relying on proxy env settings.
    """
    config_facts_localhost = duthost.config_facts(
        host=duthost.hostname,
        source='running',
        verbose=False,
        namespace=None,
    )['ansible_facts']
    for asic_index in range(duthost.facts.get('num_asic')):
        output = duthost.shell(
            "sudo ip netns exec asic{} show ip route | grep {}".format(
                asic_index,
                route_ip,
            ),
            module_ignore_errors=True,
        )['stdout']
        ip_address = re.search(r'via (\d+\.\d+\.\d+\.\d+)', output)
        if not ip_address:
            continue
        neighbor_ip = ip_address.group(1)
        if neighbor_ip not in config_facts_localhost['BGP_NEIGHBOR']:
            logger.warning(
                "Next-hop %s is not a direct BGP neighbor. "
                "Skipping route withdrawal for %s",
                neighbor_ip,
                route_ip,
            )
            continue
        neighbor_name = config_facts_localhost['BGP_NEIGHBOR'][neighbor_ip]['name']
        exabgp_port = get_exabgp_port_for_neighbor(
            tbinfo,
            neighbor_name,
            EXABGP_BASE_PORT,
        )
        _remove_static_route_no_proxy(
            tbinfo,
            neighbor_ip,
            exabgp_port,
            route_ip,
        )
        wait_until(
            10,
            1,
            0,
            verify_routev4_existence,
            duthost,
            asic_index,
            route_ip,
            should_exist=False,
        )


def verify_staged_portchannel_member_dataplane(duthost, tbinfo, ptfadapter,
                                               asic_index, asic_namespace,
                                               cli_namespace_prefix,
                                               mg_facts,
                                               staged_portchannel):
    """
    Verify PTF traffic can hash to the staged-restored LAG member.
    """
    portchannel = staged_portchannel["portchannel"]
    member = staged_portchannel["withheld_member"]
    expected_members = _expected_staged_portchannel_members(staged_portchannel)
    ptf_indices = mg_facts.get("minigraph_ptf_indices", {})
    pytest_assert(
        member in ptf_indices,
        "No PTF index found for staged member {}".format(member),
    )
    member_ptf_index = ptf_indices[member]
    source_interface, source_ptf_index = _select_ptf_source_port(
        duthost,
        asic_namespace,
        mg_facts,
        set(expected_members),
    )
    neighbor_name, _neighbor_addrs, neighbor_ipv4, _neighbor_ipv6 = (
        _get_interface_neighbor_and_intfs(mg_facts, member)
    )
    pytest_assert(
        neighbor_ipv4,
        "No IPv4 BGP neighbor found for staged member {}".format(member),
    )
    exabgp_port = get_exabgp_port_for_neighbor(
        tbinfo,
        neighbor_name,
        EXABGP_BASE_PORT,
    )
    traffic_dst_ip = _select_unused_portchannel_traffic_dst_ip(
        duthost,
        asic_index,
    )
    route_added = False

    try:
        _add_static_route_no_proxy(
            tbinfo,
            neighbor_ipv4,
            exabgp_port,
            traffic_dst_ip,
        )
        route_added = True
        pytest_assert(
            wait_until(
                30,
                3,
                0,
                verify_routev4_existence,
                duthost,
                asic_index,
                traffic_dst_ip,
                should_exist=True,
            ),
            "Static route {} did not appear on {} asic {}".format(
                traffic_dst_ip,
                duthost.hostname,
                asic_index,
            ),
        )

        logger.info(
            "Sending PTF traffic from %s(ptf=%s) to %s member %s(ptf=%s)",
            source_interface,
            source_ptf_index,
            portchannel,
            member,
            member_ptf_index,
        )
        clear_traffic_counters(duthost, asic_index)
        counter_baseline = _get_member_counter_snapshot(
            duthost,
            cli_namespace_prefix,
            member,
        )
        logger.info(
            "Staged member counter baseline for %s: %s",
            member,
            counter_baseline,
        )
        last_error = None
        matched_member = False
        for attempt in range(PORTCHANNEL_HASH_ATTEMPTS):
            src_ip = "30.0.0.{}".format(10 + attempt)
            sport = 5000
            dport = 0x50 + attempt
            try:
                send_and_verify_traffic(
                    tbinfo,
                    duthost,
                    duthost,
                    asic_index,
                    asic_index,
                    ptfadapter,
                    ptf_sport=source_ptf_index,
                    ptf_dst_ports=[member_ptf_index],
                    ptf_dst_interfaces=[member],
                    src_ip=src_ip,
                    dst_ip=traffic_dst_ip,
                    count=PORTCHANNEL_TRAFFIC_COUNT,
                    sport=sport,
                    dport=dport,
                    verify=True,
                    expect_error=False,
                    clear_stats=False,
                )
                logger.info(
                    "PTF traffic selected staged LAG member %s on hash "
                    "attempt %s using src_ip=%s tcp_sport=%s tcp_dport=%s",
                    member,
                    attempt + 1,
                    src_ip,
                    sport,
                    dport,
                )
                matched_member = True
                break
            except AssertionError as exc:
                last_error = str(exc)
                logger.info(
                    "PTF traffic did not select staged member %s on hash "
                    "attempt %s using src_ip=%s tcp_sport=%s tcp_dport=%s: %s",
                    member,
                    attempt + 1,
                    src_ip,
                    sport,
                    dport,
                    last_error,
                )

        pytest_assert(
            matched_member,
            "PTF traffic did not hash to staged member {} of {} after {} "
            "attempts while varying src_ip/tcp_dport. Last error={}".format(
                member,
                portchannel,
                PORTCHANNEL_HASH_ATTEMPTS,
                last_error,
            ),
        )
        _wait_for_staged_member_counters(
            duthost,
            cli_namespace_prefix,
            member,
            counter_baseline,
            PORTCHANNEL_TRAFFIC_COUNT,
        )
    finally:
        if route_added:
            _remove_static_route_no_proxy(
                tbinfo,
                neighbor_ipv4,
                exabgp_port,
                traffic_dst_ip,
            )
            pytest_assert(
                wait_until(
                    30,
                    3,
                    0,
                    verify_routev4_existence,
                    duthost,
                    asic_index,
                    traffic_dst_ip,
                    should_exist=False,
                ),
                "Static route {} remained on {} asic {} after withdrawal".format(
                    traffic_dst_ip,
                    duthost.hostname,
                    asic_index,
                ),
            )


def verify_staged_acl_feature_bindings(duthost, asic_namespace,
                                       ip_netns_namespace_prefix,
                                       config_facts, staged_portchannel):
    """
    Verify existing ACL/Mirror tables bound to the LAG or staged member remain present.
    """
    portchannel = staged_portchannel["portchannel"]
    member = staged_portchannel["withheld_member"]
    bound_tables = {}
    for table_name, table_config in config_facts.get("ACL_TABLE", {}).items():
        table_ports = _normalize_acl_ports(table_config.get("ports"))
        if portchannel in table_ports or member in table_ports:
            bound_tables[table_name] = {
                "type": table_config.get("type"),
                "ports": table_ports,
            }

    if not bound_tables:
        logger.info(
            "No ACL/Everflow/ERSPAN ACL_TABLE binding found for %s or %s; "
            "skipping feature binding read-back",
            portchannel,
            member,
        )
        return

    acl_facts = duthost.acl_facts(
        namespace=asic_namespace,
    )["ansible_facts"]["ansible_acl_facts"]
    show_cmd = "{} show acl table".format(ip_netns_namespace_prefix).strip()
    show_output = duthost.command(show_cmd, module_ignore_errors=True)
    pytest_assert(
        not show_output["rc"],
        "Failed to run '{}': rc={} stdout={} stderr={}".format(
            show_cmd,
            show_output.get("rc"),
            show_output.get("stdout", ""),
            show_output.get("stderr", ""),
        ),
    )

    for table_name, table_info in bound_tables.items():
        pytest_assert(
            table_name in acl_facts,
            "ACL table {} bound to {} not present in acl_facts".format(
                table_name,
                table_info,
            ),
        )
        actual_ports = _normalize_acl_ports(acl_facts[table_name].get("ports"))
        missing_ports = sorted(set(table_info["ports"]) - set(actual_ports))
        pytest_assert(
            not missing_ports,
            "ACL table {} missing expected bindings {}. actual_ports={}".format(
                table_name,
                missing_ports,
                actual_ports,
            ),
        )
        pytest_assert(
            table_name in show_output.get("stdout", ""),
            "ACL table {} missing from show acl table output".format(table_name),
        )
        logger.info(
            "Validated ACL/Mirror binding for table %s type=%s ports=%s",
            table_name,
            table_info["type"],
            table_info["ports"],
        )


def verify_staged_portchannel_operational_state(duthost, tbinfo, ptfadapter,
                                                asic_index,
                                                asic_namespace,
                                                cli_namespace_prefix,
                                                ip_netns_namespace_prefix,
                                                mg_facts, config_facts,
                                                staged_portchannel):
    """
    Verify staged PortChannel member state through teamd, ASIC_DB, counters and PTF.
    """
    wait_for_portchannel_up_or_log(
        duthost,
        asic_namespace,
        staged_portchannel["portchannel"],
    )
    verify_staged_teamd_lag_member_state(duthost, staged_portchannel)
    verify_staged_asic_db_lag_member_state(
        duthost,
        cli_namespace_prefix,
        staged_portchannel,
    )
    verify_staged_counters_db_readable(
        duthost,
        cli_namespace_prefix,
        staged_portchannel,
    )
    verify_staged_acl_feature_bindings(
        duthost,
        asic_namespace,
        ip_netns_namespace_prefix,
        config_facts,
        staged_portchannel,
    )
    verify_staged_portchannel_member_dataplane(
        duthost,
        tbinfo,
        ptfadapter,
        asic_index,
        asic_namespace,
        cli_namespace_prefix,
        mg_facts,
        staged_portchannel,
    )


def verify_bgp_peers_removed_from_asic(duthost, namespace):
    logger.info("{}: Verifying bgp_neighbors info is removed.".format(duthost.hostname))
    cur_bgp_neighbors = get_cfg_info_from_dut(duthost, "BGP_NEIGHBOR", namespace)
    cur_device_neighbor = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR", namespace)
    cur_device_neighbor_metadata = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR_METADATA", namespace)
    pytest_assert(not cur_bgp_neighbors,
                  "Bgp neighbors info removal via apply-patch failed."
                  )
    pytest_assert(not cur_device_neighbor,
                  "Device neighbor info removal via apply-patch failed."
                  )
    pytest_assert(not cur_device_neighbor_metadata,
                  "Device neighbor metadata info removal via apply-patch failed."
                  )


# -----------------------------
# Helper functions that modify configuration via apply-patch
# -----------------------------


def remove_external_portchannels_for_chassis_packet(config_facts,
                                                    duthost,
                                                    json_namespace,
                                                    cli_namespace_prefix,
                                                    run_and_check):
    """
    Remove external PortChannels (non-BP) for chassis-packet switches.
    For chassis-packet switches, we need to preserve internal PortChannels with BP members.
    """
    # Identify external PortChannels (those without internal ports as members)
    # Internal ports: "Ethernet-BP*" (backplane)
    external_portchannels = set()
    for pc_name, members in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
        has_internal_port = False
        for member_port in members.keys():
            # BP ports are internal
            if member_port.startswith("Ethernet-BP"):
                has_internal_port = True
                break
        # If no internal ports, it's an external PortChannel
        if not has_internal_port:
            external_portchannels.add(pc_name)

    logger.info(f"External PortChannels to remove: {external_portchannels}")
    internal_pcs = set(config_facts.get('PORTCHANNEL', {}).keys()) - external_portchannels
    logger.info(f"Internal PortChannels to preserve: {internal_pcs}")

    # PORTCHANNEL_INTERFACE - Remove only external PortChannel interfaces
    # Handle both base entry (PortChannel150) and IP prefix entries (PortChannel150|10.0.0.128/31)
    pc_if_entries_to_delete = []
    for pc_if_key, pc_if_value in config_facts.get("PORTCHANNEL_INTERFACE", {}).items():
        pc_name = pc_if_key.split('|')[0] if '|' in pc_if_key else pc_if_key
        if pc_name in external_portchannels:
            # Add base PortChannel entry to delete list
            pc_if_entries_to_delete.append(pc_if_key)

            # If value is a dict with IP prefixes, add those to delete list too
            if isinstance(pc_if_value, dict) and pc_if_value:
                for ip_prefix in pc_if_value.keys():
                    pc_if_ip_key = f"{pc_if_key}|{ip_prefix}"
                    pc_if_entries_to_delete.append(pc_if_ip_key)
        else:
            logger.info(f"Preserving internal PORTCHANNEL_INTERFACE: {pc_if_key}")

    # Now delete all collected entries
    logger.info(f"PORTCHANNEL_INTERFACE entries to delete: {pc_if_entries_to_delete}")
    for entry_key in pc_if_entries_to_delete:
        cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORTCHANNEL_INTERFACE|{entry_key}'"
        run_and_check(json_namespace, cmd, f"Deleting external PORTCHANNEL_INTERFACE {entry_key}")

    # PORTCHANNEL_MEMBER - Remove only external PortChannel members
    for pc_name in config_facts.get("PORTCHANNEL_MEMBER", {}).keys():
        if pc_name in external_portchannels:
            for member in config_facts["PORTCHANNEL_MEMBER"][pc_name].keys():
                cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORTCHANNEL_MEMBER|{pc_name}|{member}'"
                run_and_check(json_namespace, cmd, f"Deleting external PORTCHANNEL_MEMBER {pc_name}|{member}")
        else:
            logger.info(f"Preserving internal PORTCHANNEL_MEMBER: {pc_name}")

    # PORTCHANNEL - Remove only external PortChannels
    for pc_name in config_facts.get("PORTCHANNEL", {}).keys():
        if pc_name in external_portchannels:
            cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORTCHANNEL|{pc_name}'"
            run_and_check(json_namespace, cmd, f"Deleting external PORTCHANNEL {pc_name}")
        else:
            logger.info(f"Preserving internal PORTCHANNEL: {pc_name}")

    return external_portchannels


def remove_cluster_via_sonic_db_cli_chassis_packet(config_facts,
                                                   config_facts_localhost,
                                                   mg_facts,
                                                   duthost,
                                                   enum_rand_one_asic_namespace,
                                                   cli_namespace_prefix):
    """
    Remove cluster information directly from CONFIG_DB using sonic-db-cli commands,
    bypassing YANG validation but safely and persistently.

    Performs same cleanup as apply_patch_remove_cluster:
    - ACL_TABLE
    - BGP_NEIGHBOR
    - DEVICE_NEIGHBOR
    - DEVICE_NEIGHBOR_METADATA
    - PORTCHANNEL
    - PORTCHANNEL_INTERFACE
    - PORTCHANNEL_MEMBER
    - INTERFACE
    - BUFFER_PG
    - CABLE_LENGTH
    - PORT_QOS_MAP
    - QUEUE
    - PORT
    """

    json_namespace = '' if enum_rand_one_asic_namespace is None else enum_rand_one_asic_namespace
    logger.info(f"Starting cluster removal for ASIC namespace: {json_namespace} (chassis-packet mode)")

    active_interfaces = get_active_interfaces(config_facts, duthost)
    asic_interface_keys = []
    external_portchannels = set()

    def run_and_check(ns, cmd, desc):
        """Run a shell command on DUT and check for success."""
        logger.info(f"[{ns}] {desc}: {cmd}")
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res["rc"] != 0:
            logger.warning(f"[WARN] Command failed: {cmd}\nstdout: {res['stdout']}\nstderr: {res['stderr']}")
            return False
        return True

    ######################
    # ASIC NAMESPACE
    ######################
    if json_namespace:
        logger.info(f"Cleaning up ASIC namespace: {json_namespace}")

        # BGP_NEIGHBOR, DEVICE_NEIGHBOR, DEVICE_NEIGHBOR_METADATA
        for table in ["BGP_NEIGHBOR", "DEVICE_NEIGHBOR", "DEVICE_NEIGHBOR_METADATA"]:
            cmd = (
                f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys '{table}*' "
                f"| xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
            )
            run_and_check(json_namespace, cmd, f"Clearing table {table}")

        # INTERFACE
        if "INTERFACE" in config_facts:
            for interface_key in config_facts["INTERFACE"].keys():
                # Skip Rec and BP interfaces
                if (interface_key.startswith("Ethernet-Rec") or
                        interface_key.startswith("Ethernet-BP")):
                    continue
                for key, _value in config_facts["INTERFACE"][interface_key].items():
                    asic_interface_keys.append(interface_key + '|' + key)
                asic_interface_keys.append(interface_key)
            for iface in asic_interface_keys:
                run_and_check(json_namespace,
                              f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'INTERFACE|{iface}'",
                              f"Deleting INTERFACE {iface}")

        # ACL
        for acl_table in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
            cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hdel 'ACL_TABLE|{acl_table}' ports@"
            run_and_check(json_namespace, cmd, f"Removing ACL_TABLE {acl_table} ports")

        # PortChannel handling: Selective removal (preserving internal BP PortChannels)
        external_portchannels = remove_external_portchannels_for_chassis_packet(
            config_facts, duthost, json_namespace, cli_namespace_prefix, run_and_check
        )

        # CABLE_LENGTH - Skip BP interfaces for chassis-packet
        initial = config_facts["CABLE_LENGTH"]["AZURE"]
        lowest = min(int(v.rstrip("m")) for v in initial.values())
        for iface in active_interfaces:
            # Never modify BP interfaces for chassis-packet switches
            if iface.startswith("Ethernet-BP"):
                logger.info(f"Skipping cable length change for BP interface: {iface}")
                continue
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hset \
                            'CABLE_LENGTH|AZURE' {iface} '{lowest}m'",
                          f"Set cable length for {iface}"
                          )
        # PORT - Set admin status to down, but skip BP interfaces for chassis-packet
        for iface in active_interfaces:
            # Extra safety check: Never set BP interfaces to down for chassis-packet switches
            if iface.startswith("Ethernet-BP"):
                logger.info(f"Skipping admin down for BP interface: {iface}")
                continue
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hset 'PORT|{iface}' admin_status down",
                          f"Set {iface} admin down")

        # BUFFER_PG handling: Selective removal (preserving BP interfaces)
        buffer_pg_keys = config_facts.get("BUFFER_PG", {}).keys()
        for bp_key in buffer_pg_keys:
            interface = bp_key.split('|')[0]
            exclusion_prefixes = ["Ethernet-IB", "Ethernet-Rec", "Ethernet-BP"]
            if not any(interface.startswith(prefix) for prefix in exclusion_prefixes):
                run_and_check(json_namespace,
                              f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'BUFFER_PG|{bp_key}'",
                              f"Deleting BUFFER_PG {bp_key}")

        # QUEUE - only for external interfaces
        queue_dict = _format_sonic_queue_dict(config_facts.get("QUEUE", {}))
        for queue_key in queue_dict:
            if not _is_queue_for_internal_port(queue_key):
                cmd = (
                    f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB "
                    f"del 'QUEUE|{queue_key}'"
                )
                run_and_check(json_namespace, cmd, f"Deleting QUEUE {queue_key}")

        # PORT_QOS_MAP - only for external interfaces (BP check only for chassis-packet)
        for iface in active_interfaces:
            if not iface.startswith("Ethernet-BP"):
                run_and_check(json_namespace,
                              f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORT_QOS_MAP|{iface}'",
                              f"Deleting PORT_QOS_MAP for {iface}")

    ######################
    # LOCALHOST NAMESPACE
    ######################
    logger.info("Cleaning up localhost namespace")
    # BGP_NEIGHBOR
    for entry in config_facts["BGP_NEIGHBOR"].keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'BGP_NEIGHBOR|{entry}'",
                      f"Deleting localhost BGP_NEIGHBOR {entry}")
    # DEVICE_NEIGHBOR_METADATA
    for entry in config_facts["DEVICE_NEIGHBOR_METADATA"].keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'DEVICE_NEIGHBOR_METADATA|{entry}'",
                      f"Deleting localhost DEVICE_NEIGHBOR_METADATA {entry}")
    # INTERFACE
    localhost_interface_keys = []
    for key in asic_interface_keys:
        if key.startswith('Ethernet-Rec'):
            continue
        parts = key.split('|')
        if len(parts) == 2:
            port = parts[0]
            alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
            key_to_remove = "{}|{}".format(alias, parts[1])
        else:
            key_to_remove = mg_facts['minigraph_port_name_to_alias_map'].get(key, key)
        localhost_interface_keys.append(key_to_remove)
    for iface in localhost_interface_keys:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'INTERFACE|{iface}'",
                      f"Deleting localhost INTERFACE {iface}")
    # PORTCHANNEL_INTERFACE - Remove only external PortChannels
    # Handle both base entry and IP prefix entries
    localhost_pc_if_entries_to_delete = []
    for entry, entry_value in config_facts.get("PORTCHANNEL_INTERFACE", {}).items():
        pc_name = entry.split('|')[0] if '|' in entry else entry
        if pc_name in external_portchannels:
            # Add base PortChannel entry to delete list
            localhost_pc_if_entries_to_delete.append(entry)

            # If value is a dict with IP prefixes, add those to delete list too
            if isinstance(entry_value, dict) and entry_value:
                for ip_prefix in entry_value.keys():
                    pc_if_ip_key = f"{entry}|{ip_prefix}"
                    localhost_pc_if_entries_to_delete.append(pc_if_ip_key)
        else:
            logger.info(f"Preserving localhost internal PORTCHANNEL_INTERFACE: {entry}")

    # Now delete all collected localhost entries
    logger.info(f"Localhost PORTCHANNEL_INTERFACE entries to delete: {localhost_pc_if_entries_to_delete}")
    for entry_key in localhost_pc_if_entries_to_delete:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL_INTERFACE|{entry_key}'",
                      f"Deleting localhost PORTCHANNEL_INTERFACE {entry_key}")

    # PORTCHANNEL_MEMBER - Remove only external PortChannels
    localhost_pc_member_dict = config_facts_localhost.get("PORTCHANNEL_MEMBER", {})
    for pc_key in config_facts.get("PORTCHANNEL", {}).keys():
        if pc_key in external_portchannels and pc_key in localhost_pc_member_dict:
            for member_key, _value in localhost_pc_member_dict[pc_key].items():
                key_to_remove = pc_key + '|' + member_key
                run_and_check("localhost",
                              f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL_MEMBER|{key_to_remove}'",
                              f"Deleting localhost PORTCHANNEL_MEMBER {key_to_remove}")
        elif pc_key not in external_portchannels:
            logger.info(f"Preserving localhost internal PORTCHANNEL_MEMBER: {pc_key}")

    # ACL localhost - need to remove only the entries from asic namespace
    for acl_table in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB hdel 'ACL_TABLE|{acl_table}' ports@",
                      f"Removing localhost ACL_TABLE {acl_table} ports")

    # PORTCHANNEL - Remove only external PortChannels
    for entry in config_facts.get("PORTCHANNEL", {}).keys():
        if entry in external_portchannels:
            run_and_check("localhost",
                          f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL|{entry}'",
                          f"Deleting localhost PORTCHANNEL {entry}")
        else:
            logger.info(f"Preserving localhost internal PORTCHANNEL: {entry}")


def apply_patch_remove_cluster_chassis_packet(config_facts,
                                              config_facts_localhost,
                                              mg_facts,
                                              duthost,
                                              enum_rand_one_asic_namespace,
                                              cli_namespace_prefix):
    """
    Apply patch to remove cluster information for chassis-packet switches.

    For chassis-packet switches, we preserve internal BP (backplane) interfaces and PortChannels.
    Only external PortChannels and non-BP interfaces are removed.

    Changes are perfomed to below tables:
    ACL_TABLE, BGP_NEIGHBOR, DEVICE_NEIGHBOR, DEVICE_NEIGHBOR_METADATA,
    PORTCHANNEL, PORTCHANNEL_INTERFACE, PORTCHANNEL_MEMBER,
    INTERFACE, BUFFER_PG, CABLE_LENGTH, PORT, PORT_QOS_MAP, QUEUE
    """

    logger.info("Removing cluster for namespace {} via apply-patch (chassis-packet mode)."
                .format(enum_rand_one_asic_namespace))

    json_patch_asic = []
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace

    # find active ports
    active_interfaces = get_active_interfaces(config_facts, duthost)
    asic_interface_keys = []
    asic_interface_ip_prefix_keys = []

    # Identify external PortChannels (those without BP members)
    external_portchannels = set()
    for pc_name, members in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
        has_internal_port = False
        for member_port in members.keys():
            if (member_port.startswith("Ethernet-IB") or
                    member_port.startswith("Ethernet-Rec") or
                    member_port.startswith("Ethernet-BP")):
                has_internal_port = True
                break
        if not has_internal_port:
            external_portchannels.add(pc_name)
    logger.info(f"External PortChannels to remove: {external_portchannels}")
    internal_pcs = set(config_facts.get('PORTCHANNEL', {}).keys()) - external_portchannels
    logger.info(f"Internal PortChannels to preserve: {internal_pcs}")

    # W/A: TABLE:ACL_TABLE removing whole table instead of detaching ports
    json_patch_asic = [
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/DATAACL"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/EVERFLOW"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/EVERFLOWV6"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/BGP_NEIGHBOR"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA"
        }
    ]

    # Remove PORTCHANNEL_MEMBER - only for external PortChannels
    portchannel_member_dict = config_facts.get("PORTCHANNEL_MEMBER", {})
    for pc_name in portchannel_member_dict.keys():
        if pc_name in external_portchannels:
            for member_port in portchannel_member_dict[pc_name].keys():
                json_patch_asic.append({
                    "op": "remove",
                    "path": f"{json_namespace}/PORTCHANNEL_MEMBER/{pc_name}|{member_port}"
                })

    # Remove PORTCHANNEL_INTERFACE - only for external PortChannels
    portchannel_interface_dict = config_facts.get("PORTCHANNEL_INTERFACE", {})
    for pc_if_key in portchannel_interface_dict.keys():
        pc_name = pc_if_key.split('|')[0] if '|' in pc_if_key else pc_if_key
        if pc_name in external_portchannels:
            json_patch_asic.append({
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL_INTERFACE/{pc_if_key.replace('/', '~1')}"
            })

    # Remove BUFFER_PG - only for non-BP interfaces (preserve BP, IB, Rec)
    buffer_pg_dict = config_facts.get("BUFFER_PG", {})
    for buffer_pg_key in buffer_pg_dict.keys():
        interface = buffer_pg_key.split('|')[0]
        if not any(interface.startswith(prefix) for prefix in ["Ethernet-IB", "Ethernet-Rec", "Ethernet-BP"]):
            json_patch_asic.append({
                "op": "remove",
                "path": f"{json_namespace}/BUFFER_PG/{buffer_pg_key.replace('/', '~1')}"
            })

    # Remove QUEUE - only for non-BP interfaces (preserve BP, IB, Rec)
    queue_dict = _format_sonic_queue_dict(config_facts.get("QUEUE", {}))
    for queue_key in queue_dict:
        if not _is_queue_for_internal_port(queue_key):
            json_patch_asic.append({
                "op": "remove",
                "path": "{}/QUEUE/{}".format(
                    json_namespace,
                    escape_json_pointer_key(queue_key)
                )
            })

    # table INTERFACE - Skip BP and Rec interfaces (chassis-packet specific)
    if 'INTERFACE' in config_facts:
        asic_interface_dict = config_facts["INTERFACE"]
        for interface_key in asic_interface_dict.keys():
            if interface_key.startswith("Ethernet-Rec") or interface_key.startswith("Ethernet-BP"):
                continue
            for key, _value in asic_interface_dict[interface_key].items():
                key_to_remove = interface_key + '|' + key.replace("/", "~1")
                asic_interface_ip_prefix_keys.append(key_to_remove)
            asic_interface_keys.append(interface_key)

        for key in asic_interface_ip_prefix_keys:
            json_patch_asic.append({
                "op": "remove",
                "path": f"{json_namespace}/INTERFACE/{key}"
            })

    # table PORT_QOS_MAP changes - skip BP interfaces
    for interface in active_interfaces:
        if not any(interface.startswith(prefix) for prefix in ["Ethernet-IB", "Ethernet-Rec", "Ethernet-BP"]):
            json_patch_asic.append({
                "op": "remove",
                "path": "{}/PORT_QOS_MAP/{}".format(json_namespace, interface)
            })

    # table PORT changes - Set admin status to down, but skip BP interfaces
    for interface in active_interfaces:
        if not interface.startswith("Ethernet-BP"):
            json_patch_asic.append({
                "op": "add",
                "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
                "value": "down"
            })

    # table CABLE_LENGTH changes - Skip BP interfaces
    initial_cable_length_table = config_facts["CABLE_LENGTH"]["AZURE"]
    cable_length_values = [int(v.rstrip("m")) for v in initial_cable_length_table.values()]
    lowest = min(cable_length_values)
    for interface in active_interfaces:
        if not interface.startswith("Ethernet-BP"):
            json_patch_asic.append({
                "op": "add",
                "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, interface),
                "value": f"{lowest}m"
            })

    # Apply ASIC namespace patch
    json_patch = json_patch_asic
    tmpfile = generate_tmpfile(duthost)
    try:
        description = (
            "remove cluster info (1/2) all except PORTCHANNEL, INTERFACE name "
            "- chassis-packet mode"
        )
        logger.info("Applying patch (1/2) to %s.", description)
        _log_json_patch_content(description, json_patch)
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        verify_bgp_peers_removed_from_asic(duthost, enum_rand_one_asic_namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)

    # W/A TABLE:PORTCHANNEL, INTERFACE names needs to be removed in separate gcu apply operation
    json_patch_extra = []

    # Remove PORTCHANNEL - only external ones
    for pc_name in config_facts["PORTCHANNEL"].keys():
        if pc_name in external_portchannels:
            json_patch_extra.append({
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL/{pc_name}"
            })

    # Remove INTERFACE names
    interface_paths_to_remove = [f"{json_namespace}/INTERFACE/"]
    interface_keys_to_remove = [asic_interface_keys]
    for path, keys in zip(interface_paths_to_remove, interface_keys_to_remove):
        for k in keys:
            json_patch_extra.append({
                "op": "remove",
                "path": path + k
            })

    tmpfile_pc = generate_tmpfile(duthost)
    try:
        description = (
            "remove cluster info (2/2) PORTCHANNEL, INTERFACE name "
            "- chassis-packet mode"
        )
        logger.info("Applying patch (2/2) to %s.", description)
        _log_json_patch_content(description, json_patch_extra)
        output = apply_patch(duthost, json_data=json_patch_extra, dest_file=tmpfile_pc)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile_pc)


def remove_cluster_via_sonic_db_cli(config_facts,
                                    config_facts_localhost,
                                    mg_facts,
                                    duthost,
                                    enum_rand_one_asic_namespace,
                                    cli_namespace_prefix):
    """
    Remove cluster information directly from CONFIG_DB using sonic-db-cli commands,
    bypassing YANG validation but safely and persistently.

    Performs same cleanup as apply_patch_remove_cluster:
    - ACL_TABLE
    - BGP_NEIGHBOR
    - DEVICE_NEIGHBOR
    - DEVICE_NEIGHBOR_METADATA
    - PORTCHANNEL
    - PORTCHANNEL_INTERFACE
    - PORTCHANNEL_MEMBER
    - INTERFACE
    - BUFFER_PG
    - CABLE_LENGTH
    - PORT_QOS_MAP
    - QUEUE
    - PORT
    """

    json_namespace = '' if enum_rand_one_asic_namespace is None else enum_rand_one_asic_namespace
    logger.info(f"Starting cluster removal for ASIC namespace: {json_namespace}")

    active_interfaces = get_active_interfaces(config_facts)
    asic_interface_keys = []
    success = True

    def run_and_check(ns, cmd, desc):
        """Run a shell command on DUT and check for success."""
        logger.info(f"[{ns}] {desc}: {cmd}")
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res["rc"] != 0:
            logger.warning(f"[WARN] Command failed: {cmd}\nstdout: {res['stdout']}\nstderr: {res['stderr']}")
            return False
        return True

    ######################
    # ASIC NAMESPACE
    ######################
    if json_namespace:
        logger.info(f"Cleaning up ASIC namespace: {json_namespace}")

        # BGP_NEIGHBOR, DEVICE_NEIGHBOR, DEVICE_NEIGHBOR_METADATA
        for table in ["BGP_NEIGHBOR", "DEVICE_NEIGHBOR", "DEVICE_NEIGHBOR_METADATA"]:
            cmd = (
                f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys '{table}*' "
                f"| xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
            )
            run_and_check(json_namespace, cmd, f"Clearing table {table}")

        # INTERFACE
        for interface_key in config_facts["INTERFACE"].keys():
            if interface_key.startswith("Ethernet-Rec"):
                continue
            for key, _value in config_facts["INTERFACE"][interface_key].items():
                asic_interface_keys.append(interface_key + '|' + key)
            asic_interface_keys.append(interface_key)
        for iface in asic_interface_keys:
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'INTERFACE|{iface}'",
                          f"Deleting INTERFACE {iface}")

        # PORTCHANNEL_INTERFACE, PORTCHANNEL_MEMBER
        for table in ["PORTCHANNEL_INTERFACE", "PORTCHANNEL_MEMBER"]:
            cmd = (
                f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys '{table}*' "
                f"| xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
            )
            run_and_check(json_namespace, cmd, f"Clearing table {table}")

        # ACL
        for acl_table in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
            cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hdel 'ACL_TABLE|{acl_table}' ports@"
            run_and_check(json_namespace, cmd, f"Removing ACL_TABLE {acl_table} ports")

        # PORTCHANNEL
        cmd = (
            f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys 'PORTCHANNEL*' "
            f"| xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
        )
        run_and_check(json_namespace, cmd, "Clearing table PORTCHANNEL")

        # CABLE_LENGTH
        initial = config_facts["CABLE_LENGTH"]["AZURE"]
        lowest = min(int(v.rstrip("m")) for v in initial.values())
        for iface in active_interfaces:
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hset \
                            'CABLE_LENGTH|AZURE' {iface} '{lowest}m'",
                          f"Set cable length for {iface}"
                          )
        # PORT
        for iface in active_interfaces:
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hset 'PORT|{iface}' admin_status down",
                          f"Set {iface} admin down")
        # BUFFER_PG
        cmd = (
            f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys 'BUFFER_PG*' "
            f"| xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
        )
        run_and_check(json_namespace, cmd, "Clearing table BUFFER_PG")

        # QUEUE
        cmd = (
            f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB "
            f"keys 'QUEUE|*' | xargs -r -n1 sudo sonic-db-cli "
            f"{cli_namespace_prefix} CONFIG_DB del"
        )
        run_and_check(json_namespace, cmd, "Clearing table QUEUE")

        # PORT_QOS_MAP
        for iface in active_interfaces:
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORT_QOS_MAP|{iface}'",
                          f"Deleting PORT_QOS_MAP for {iface}")

    ######################
    # LOCALHOST NAMESPACE
    ######################
    logger.info("Cleaning up localhost namespace")
    # BGP_NEIGHBOR
    for entry in config_facts["BGP_NEIGHBOR"].keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'BGP_NEIGHBOR|{entry}'",
                      f"Deleting localhost BGP_NEIGHBOR {entry}")
    # DEVICE_NEIGHBOR_METADATA
    for entry in config_facts["DEVICE_NEIGHBOR_METADATA"].keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'DEVICE_NEIGHBOR_METADATA|{entry}'",
                      f"Deleting localhost DEVICE_NEIGHBOR_METADATA {entry}")
    # INTERFACE
    localhost_interface_keys = []
    for key in asic_interface_keys:
        if key.startswith('Ethernet-Rec'):
            continue
        parts = key.split('|')
        if len(parts) == 2:
            port = parts[0]
            alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
            key_to_remove = "{}|{}".format(alias, parts[1])
        else:
            key_to_remove = mg_facts['minigraph_port_name_to_alias_map'].get(key, key)
        localhost_interface_keys.append(key_to_remove)
    for iface in localhost_interface_keys:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'INTERFACE|{iface}'",
                      f"Deleting localhost INTERFACE {iface}")
    # PORTCHANNEL_INTERFACE
    for entry in config_facts.get("PORTCHANNEL_INTERFACE", {}).keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL_INTERFACE|{entry}'",
                      f"Deleting localhost PORTCHANNEL_INTERFACE {entry}")
    # PORTCHANNEL_MEMBER
    pc_keys = config_facts.get("PORTCHANNEL", {}).keys()
    localhost_pc_member_dict = config_facts_localhost.get("PORTCHANNEL_MEMBER", {})
    localhost_pc_member_keys = []
    for pc_key in pc_keys:
        if pc_key in localhost_pc_member_dict:
            for key, _value in localhost_pc_member_dict[pc_key].items():
                key_to_remove = pc_key + '|' + key
                localhost_pc_member_keys.append(key_to_remove)
    for entry in localhost_pc_member_keys:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL_MEMBER|{entry}'",
                      f"Deleting localhost PORTCHANNEL_MEMBER {entry}")
    # ACL localhost - need to remove only the entries from asic namespace
    for acl_table in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB hdel 'ACL_TABLE|{acl_table}' ports@",
                      f"Removing localhost ACL_TABLE {acl_table} ports")
    # PORTCHANNEL
    for entry in config_facts.get("PORTCHANNEL", {}).keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL|{entry}'",
                      f"Deleting localhost PORTCHANNEL {entry}")

    # Partial Verification
    logger.info("Verifying that asic tables were cleared...")
    tables_to_check = [
        "BGP_NEIGHBOR", "DEVICE_NEIGHBOR", "DEVICE_NEIGHBOR_METADATA",
        "PORTCHANNEL_INTERFACE", "PORTCHANNEL_MEMBER", "PORTCHANNEL"
    ]
    for table in tables_to_check:
        cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys '{table}*'"
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res["stdout"].strip():
            logger.warning(f"{table} still contains entries: {res['stdout']}")
            success = False
        else:
            logger.info(f"{table} is empty")

    if success:
        logger.info("Cluster removal completed successfully.")
    else:
        logger.warning("Cluster removal incomplete — verification failure.")


def apply_patch_remove_cluster(config_facts,
                               config_facts_localhost,
                               mg_facts,
                               duthost,
                               enum_rand_one_asic_namespace,
                               cli_namespace_prefix):
    """
    Apply patch to remove cluster information for a given ASIC namespace.

    Changes are perfomed to below tables:

    ACL_TABLE
    BGP_NEIGHBOR
    DEVICE_NEIGHBOR
    DEVICE_NEIGHBOR_METADATA
    PORTCHANNEL
    PORTCHANNEL_INTERFACE
    PORTCHANNEL_MEMBER
    INTERFACE
    BUFFER_PG
    CABLE_LENGTH
    PORT
    PORT_QOS_MAP
    QUEUE

    """

    logger.info("Removing cluster for namespace {} via apply-patch.".format(enum_rand_one_asic_namespace))

    ######################
    # ASIC NAMESPACE
    ######################
    json_patch_asic = []
    logger.info("{}: Removing cluster info for namespace {}".format(duthost.hostname, enum_rand_one_asic_namespace))
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace

    asic_paths_list = []

    # find active ports
    active_interfaces = get_active_interfaces(config_facts)
    asic_interface_keys = []
    asic_interface_ip_prefix_keys = []
    localhost_interface_keys = []
    localhost_ip_prefix_interface_keys = []
    localhost_pc_member_keys = []
    localhost_pc_interface_keys = []

    # W/A: TABLE:ACL_TABLE removing whole table instead of detaching ports
    # https://github.com/sonic-net/sonic-buildimage/issues/24295

    # op: remove
    json_patch_asic = [
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/DATAACL"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/EVERFLOW"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/EVERFLOWV6"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/BGP_NEIGHBOR"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA"
        },
    ]
    if config_facts.get("QUEUE"):
        json_patch_asic.append({
            "op": "remove",
            "path": f"{json_namespace}/QUEUE"
        })
    json_patch_asic.append({
        "op": "remove",
        "path": f"{json_namespace}/BUFFER_PG"
    })

    if 'PORTCHANNEL' in config_facts:
        json_patch_asic.append(
            {
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL_MEMBER"
            }
        )
        json_patch_asic.append(
            {
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL_INTERFACE"
            }
        )

    # table INTERFACE
    if 'INTERFACE' in config_facts:
        asic_interface_dict = config_facts["INTERFACE"]
        for interface_key in asic_interface_dict.keys():
            if interface_key.startswith("Ethernet-Rec"):
                continue
            for key, _value in asic_interface_dict[interface_key].items():
                key_to_remove = interface_key + '|' + key.replace("/", "~1")
                asic_interface_ip_prefix_keys.append(key_to_remove)
            asic_interface_keys.append(interface_key)

        for key in asic_interface_ip_prefix_keys:
            asic_paths_list.append(f"{json_namespace}/INTERFACE/" + key)

        for path in asic_paths_list:
            json_patch_asic.append({
                "op": "remove",
                "path": path
            })

    # table PORT_QOS_MAP changes
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "remove",
            "path": "{}/PORT_QOS_MAP/{}".format(json_namespace, interface)
        })

    # table PORT changes
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
            "value": "down"
        })

    # table CABLE_LENGTH changes
    initial_cable_length_table = config_facts["CABLE_LENGTH"]["AZURE"]
    cable_length_values = [int(v.rstrip("m")) for v in initial_cable_length_table.values()]
    lowest = min(cable_length_values)
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, interface),
            "value": f"{lowest}m"
        })
    ######################
    # LOCALHOST NAMESPACE
    ######################
    json_patch_localhost = []
    logger.info("{}: Removing cluster info for namespace localhost".format(duthost.hostname))

    # INTERFACE TABLE: in localhost replace the interface name with the interface alias
    # INTERFACE ip-prefix
    if 'INTERFACE' in config_facts:
        for key in asic_interface_ip_prefix_keys:
            parts = key.split('|')
            port = parts[0]
            alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
            key_to_remove = "{}|{}".format(alias, parts[1])
            key_to_remove = key_to_remove.replace("/", "~1")
            localhost_ip_prefix_interface_keys.append(key_to_remove)
        # INTERFACE name
        for key in asic_interface_keys:
            key_to_remove = mg_facts['minigraph_port_name_to_alias_map'].get(key, key)
            key_to_remove = key_to_remove.replace("/", "~1")
            localhost_interface_keys.append(key_to_remove)

    # PORTCHANNEL_MEMBER keys
    if 'PORTCHANNEL' in config_facts:
        pc_keys = config_facts.get("PORTCHANNEL", {}).keys()

        localhost_pc_member_dict = config_facts_localhost.get("PORTCHANNEL_MEMBER", {})
        for pc_key in pc_keys:
            if pc_key in localhost_pc_member_dict:
                for key, _value in localhost_pc_member_dict[pc_key].items():
                    key_to_remove = pc_key + '|' + key.replace("/", "~1")
                    localhost_pc_member_keys.append(key_to_remove)
        # PORTCHANNEL_INTERFACE keys
        localhost_pc_interface_dict = config_facts_localhost.get("PORTCHANNEL_INTERFACE", {})
        for pc_key in pc_keys:
            if pc_key in localhost_pc_interface_dict:
                for key, _value in localhost_pc_interface_dict[pc_key].items():
                    key_to_remove = pc_key + '|' + key.replace("/", "~1")
                    localhost_pc_interface_keys.append(key_to_remove)
                localhost_pc_interface_keys.append(pc_key)

    # ACL TABLE
    acl_ports_localhost = config_facts_localhost["ACL_TABLE"]["DATAACL"]["ports"]
    acl_ports_asic = config_facts["ACL_TABLE"]["DATAACL"]["ports"]
    acl_ports_localhost_post_removal = [p for p in acl_ports_localhost if p not in acl_ports_asic]
    if acl_ports_localhost_post_removal:
        json_patch_localhost = [
            {
                "op": "add",
                "path": "/localhost/ACL_TABLE/DATAACL/ports",
                "value": acl_ports_localhost_post_removal
            },
            {
                "op": "add",
                "path": "/localhost/ACL_TABLE/EVERFLOW/ports",
                "value": acl_ports_localhost_post_removal
            },
            {
                "op": "add",
                "path": "/localhost/ACL_TABLE/EVERFLOWV6/ports",
                "value": acl_ports_localhost_post_removal
            }
        ]
    localhost_paths_list = []
    localhost_paths_to_remove = ["/localhost/BGP_NEIGHBOR/",
                                 "/localhost/DEVICE_NEIGHBOR_METADATA/"
                                 ]
    localhost_keys_to_remove = [
        config_facts["BGP_NEIGHBOR"].keys() if config_facts.get("BGP_NEIGHBOR") else [],
        config_facts["DEVICE_NEIGHBOR_METADATA"].keys() if config_facts.get("DEVICE_NEIGHBOR_METADATA") else [],
    ]
    if 'INTERFACE' in config_facts:
        localhost_paths_to_remove.append("/localhost/INTERFACE/")
        localhost_keys_to_remove.append(localhost_ip_prefix_interface_keys)
    if 'PORTCHANNEL' in config_facts:
        localhost_paths_to_remove.append("/localhost/PORTCHANNEL_MEMBER/")
        localhost_paths_to_remove.append("/localhost/PORTCHANNEL_INTERFACE/")
        localhost_keys_to_remove.append(localhost_pc_member_keys)
        localhost_keys_to_remove.append(localhost_pc_interface_keys)

    for path, keys in zip(localhost_paths_to_remove, localhost_keys_to_remove):
        for k in keys:
            localhost_paths_list.append(path + k)
    for path in localhost_paths_list:
        json_patch_localhost.append({
            "op": "remove",
            "path": path
        })

    #####################################
    # combine localhost and ASIC patch data
    #####################################
    json_patch = json_patch_localhost + json_patch_asic
    tmpfile = generate_tmpfile(duthost)
    try:
        description = (
            "remove cluster info (1/2) all except PORTCHANNEL, INTERFACE name"
        )
        logger.info("Applying patch (1/2) to %s.", description)
        _log_json_patch_content(description, json_patch)
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        verify_bgp_peers_removed_from_asic(duthost, enum_rand_one_asic_namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)

    # W/A TABLE:PORTCHANNEL, INTERFACE names needs to be removed in separate gcu apply operation
    # https://github.com/sonic-net/sonic-buildimage/issues/24338
    json_patch_extra = []
    if 'PORTCHANNEL' in config_facts:
        json_patch_extra = [
            {
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL"
            }
        ]
        for key, _value in config_facts.get("PORTCHANNEL", {}).items():
            json_patch_extra.append({
                "op": "remove",
                "path": "/localhost/PORTCHANNEL/{}".format(key),
            })
    interface_paths_list = []
    interface_paths_to_remove = [f"{json_namespace}/INTERFACE/", "/localhost/INTERFACE/"]
    interface_keys_to_remove = [asic_interface_keys, localhost_interface_keys]
    for path, keys in zip(interface_paths_to_remove, interface_keys_to_remove):
        for k in keys:
            interface_paths_list.append(path + k)
    for path in interface_paths_list:
        json_patch_extra.append({
            "op": "remove",
            "path": path
        })

    tmpfile_pc = generate_tmpfile(duthost)
    try:
        description = "remove cluster info (2/2) PORTCHANNEL, INTERFACE name"
        logger.info("Applying patch (2/2) to %s.", description)
        _log_json_patch_content(description, json_patch_extra)
        output = apply_patch(duthost, json_data=json_patch_extra, dest_file=tmpfile_pc)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile_pc)


def apply_patch_add_cluster(config_facts,
                            config_facts_localhost,
                            mg_facts,
                            duthost,
                            enum_rand_one_asic_namespace,
                            staged_portchannel=None):
    """
    Apply patch to add cluster information for a given ASIC namespace.

    Changes are perfomed to below tables:

    ACL_TABLE
    BGP_NEIGHBOR
    DEVICE_NEIGHBOR
    DEVICE_NEIGHBOR_METADATA
    PORTCHANNEL
    PORTCHANNEL_INTERFACE
    PORTCHANNEL_MEMBER
    INTERFACE
    BUFFER_PG
    CABLE_LENGTH
    PORT
    PORT_QOS_MAP
    QUEUE
    """

    logger.info("Adding cluster for namespace {} via apply-patch.".format(enum_rand_one_asic_namespace))

    ######################
    # ASIC NAMESPACE
    ######################
    json_patch_asic = []
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace
    pc_dict = {}
    staged_restore_config = _filter_staged_member_restore_config(
        config_facts,
        mg_facts,
        staged_portchannel
    )
    interface_dict = format_sonic_interface_dict(
        staged_restore_config.get("INTERFACE", {})
    )
    portchannel_interface_dict = format_sonic_interface_dict(
        config_facts.get("PORTCHANNEL_INTERFACE", {})
    )
    portchannel_member_dict = format_sonic_interface_dict(
        staged_restore_config.get("PORTCHANNEL_MEMBER", {}),
        single_entry=False
    )
    buffer_pg_dict = format_sonic_buffer_pg_dict(
        staged_restore_config.get("BUFFER_PG", {})
    )
    queue_dict = _format_sonic_queue_dict(staged_restore_config.get("QUEUE", {}))
    pc_dict = {
        k: {ik: iv for ik, iv in v.items() if ik != "members"}
        for k, v in config_facts.get("PORTCHANNEL", {}).items()
    }
    pc_dict = _stage_portchannel_config(pc_dict, staged_portchannel)

    # find active ports
    active_interfaces = get_active_interfaces(staged_restore_config)

    # PORTCHANNEL info needs to be added in separate gcu apply operation
    # https://github.com/sonic-net/sonic-buildimage/issues/24338
    if pc_dict:
        json_patch_pc = [
            {
                "op": "add",
                "path": f"{json_namespace}/PORTCHANNEL",
                "value": pc_dict
            }
        ]
        for pc_key, pc_value in pc_dict.items():
            json_patch_pc.append({
                "op": "add",
                "path": "/localhost/PORTCHANNEL/{}".format(pc_key),
                "value": pc_value
            })
        tmpfile_pc = generate_tmpfile(duthost)
        try:
            description = "add cluster info (1/2) PORTCHANNEL"
            logger.info("Applying patch (1/2) to %s.", description)
            _log_json_patch_content(description, json_patch_pc)
            output = apply_patch(duthost, json_data=json_patch_pc, dest_file=tmpfile_pc)
            expect_op_success(duthost, output)
        finally:
            delete_tmpfile(duthost, tmpfile_pc)

    # op: add
    json_patch_asic = [
        {
            "op": "add",
            "path": f"{json_namespace}/BGP_NEIGHBOR",
            "value": config_facts["BGP_NEIGHBOR"]
        },
        {
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR",
            "value": staged_restore_config["DEVICE_NEIGHBOR"]
        },
        {
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA",
            "value": staged_restore_config["DEVICE_NEIGHBOR_METADATA"]
        },
        {
            "op": "add",
            "path": f"{json_namespace}/INTERFACE",
            "value": interface_dict
        },
        {
            "op": "add",
            "path": f"{json_namespace}/BUFFER_PG",
            "value": buffer_pg_dict
        },
        {
            "op": "add",
            "path": f"{json_namespace}/PORT_QOS_MAP",
            "value": staged_restore_config["PORT_QOS_MAP"]
        }
    ]
    if queue_dict:
        json_patch_asic.append({
            "op": "add",
            "path": f"{json_namespace}/QUEUE",
            "value": queue_dict
        })

    if 'PORTCHANNEL' in config_facts:
        json_patch_asic.append({
            "op": "add",
            "path": f"{json_namespace}/PORTCHANNEL_MEMBER",
            "value": portchannel_member_dict
        })
        json_patch_asic.append({
            "op": "add",
            "path": f"{json_namespace}/PORTCHANNEL_INTERFACE",
            "value": portchannel_interface_dict
        })

    # table PORT changes
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
            "value": "up"
        })

    # table CABLE_LENGTH changes
    initial_cable_length_table = staged_restore_config["CABLE_LENGTH"]["AZURE"]
    cable_length_values = [int(v.rstrip("m")) for v in initial_cable_length_table.values()]
    highest = max(cable_length_values)
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, interface),
            "value": f"{highest}m"
        })

    # table ACL_TABLE changes
    json_patch_asic.append({
        "op": "add",
        "path": f"{json_namespace}/ACL_TABLE/DATAACL",
        "value": config_facts["ACL_TABLE"]["DATAACL"]
    })
    json_patch_asic.append({
        "op": "add",
        "path": f"{json_namespace}/ACL_TABLE/EVERFLOW",
        "value": config_facts["ACL_TABLE"]["EVERFLOW"]
    })
    json_patch_asic.append({
        "op": "add",
        "path": f"{json_namespace}/ACL_TABLE/EVERFLOWV6",
        "value": config_facts["ACL_TABLE"]["EVERFLOWV6"]
    })

    ######################
    # LOCALHOST NAMESPACE
    ######################

    json_patch_localhost = []

    # INTERFACE keys: in localhost replace the interface name with the interface alias
    localhost_interface_dict = {}
    for key, value in interface_dict.items():
        if key.startswith('Ethernet-Rec'):
            continue
        parts = key.split('|')
        updated_key = key
        if len(parts) == 2:
            port = parts[0]
            alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
            updated_key = "{}|{}".format(alias, parts[1])
        else:
            updated_key = mg_facts['minigraph_port_name_to_alias_map'].get(key, key)
        updated_key = updated_key.replace("/", "~1")
        localhost_interface_dict[updated_key] = value

    # identify the keys to add
    localhost_add_paths_list = []
    localhost_add_values_list = []
    for k, v in list(config_facts["BGP_NEIGHBOR"].items()):
        localhost_add_paths_list.append('/localhost/BGP_NEIGHBOR/{}'.format(k))
        localhost_add_values_list.append(v)
    for k, v in list(staged_restore_config["DEVICE_NEIGHBOR"].items()):
        localhost_add_paths_list.append('/localhost/DEVICE_NEIGHBOR/{}'.format(k))
        localhost_add_values_list.append(v)
    for k, v in list(staged_restore_config["DEVICE_NEIGHBOR_METADATA"].items()):
        localhost_add_paths_list.append('/localhost/DEVICE_NEIGHBOR_METADATA/{}'.format(k))
        localhost_add_values_list.append(v)
    for k, v in list(localhost_interface_dict.items()):
        localhost_add_paths_list.append("/localhost/INTERFACE/{}".format(k))
        localhost_add_values_list.append(v)

    if 'PORTCHANNEL' in config_facts:
        # PORTCHANNEL INTERFACE
        localhost_pc_interface_dict = {}
        for key, value in portchannel_interface_dict.items():
            updated_key = key.replace('/', '~1')
            localhost_pc_interface_dict[updated_key] = value
        # PORTCHANNEL_MEMBER keys
        localhost_pc_member_dict = {}
        for key, value in portchannel_member_dict.items():
            parts = key.split('|')
            updated_key = key
            if len(parts) == 2:
                port = parts[1]
                alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
                updated_key = "{}|{}".format(parts[0], alias)
            updated_key = updated_key.replace("/", "~1")
            localhost_pc_member_dict[updated_key] = value
        # for k, v in list(pc_dict.items()):
        #     localhost_add_paths_list.append("/localhost/PORTCHANNEL/{}".format(k))
        #     localhost_add_values_list.append(v)
        for k, v in list(localhost_pc_interface_dict.items()):
            localhost_add_paths_list.append("/localhost/PORTCHANNEL_INTERFACE/{}".format(k))
            localhost_add_values_list.append(v)
        for k, v in list(localhost_pc_member_dict.items()):
            localhost_add_paths_list.append("/localhost/PORTCHANNEL_MEMBER/{}".format(k))
            localhost_add_values_list.append(v)

    for path, value in zip(localhost_add_paths_list, localhost_add_values_list):
        json_patch_localhost.append({
            "op": "add",
            "path": path,
            "value": value
        })

    json_patch_localhost.append({
        "op": "add",
        "path": "/localhost/ACL_TABLE/DATAACL/ports",
        "value": config_facts_localhost["ACL_TABLE"]["DATAACL"]["ports"]
    })
    json_patch_localhost.append({
        "op": "add",
        "path": "/localhost/ACL_TABLE/EVERFLOW/ports",
        "value": config_facts_localhost["ACL_TABLE"]["EVERFLOW"]["ports"]
    })
    json_patch_localhost.append({
        "op": "add",
        "path": "/localhost/ACL_TABLE/EVERFLOWV6/ports",
        "value": config_facts_localhost["ACL_TABLE"]["EVERFLOWV6"]["ports"]
    })

    #####################################
    # combine localhost and ASIC patch data
    #####################################
    json_patch = json_patch_localhost + json_patch_asic
    tmpfile = generate_tmpfile(duthost)
    try:
        description = "add cluster info (2/2) all except PORTCHANNEL"
        logger.info("Applying patch (2/2) to %s.", description)
        _log_json_patch_content(description, json_patch)
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def apply_patch_add_cluster_chassis_packet(config_facts,
                                           config_facts_localhost,
                                           mg_facts,
                                           duthost,
                                           enum_rand_one_asic_namespace,
                                           staged_portchannel=None):
    """
    Apply patch to add cluster information for chassis-packet switches.

    For chassis-packet switches:
    - Excludes BP (backplane) interfaces
    - Only adds external PortChannels (those without BP members)
    - Skips localhost namespace patches

    Changes are perfomed to below tables:

    ACL_TABLE
    BGP_NEIGHBOR
    DEVICE_NEIGHBOR
    DEVICE_NEIGHBOR_METADATA
    PORTCHANNEL
    PORTCHANNEL_INTERFACE
    PORTCHANNEL_MEMBER
    INTERFACE
    BUFFER_PG
    CABLE_LENGTH
    PORT
    PORT_QOS_MAP
    QUEUE
    """
    logger.info("Adding cluster for namespace {} via apply-patch (chassis-packet mode).".format(
        enum_rand_one_asic_namespace))

    ######################
    # ASIC NAMESPACE
    ######################
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace

    # Identify external PortChannels (those without BP members)
    # Exclude PortChannels with BP (backplane) members - these are internal
    external_portchannels = set()
    for pc_name, members in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
        has_internal_port = False
        for member_port in members.keys():
            # BP ports are internal for chassis-packet
            if member_port.startswith("Ethernet-BP"):
                has_internal_port = True
                break
        # If no internal ports, it's an external PortChannel
        if not has_internal_port:
            external_portchannels.add(pc_name)

    logger.info(f"External PortChannels to add back: {external_portchannels}")
    internal_pcs = set(config_facts.get('PORTCHANNEL', {}).keys()) - external_portchannels
    logger.info(f"Internal PortChannels to skip: {internal_pcs}")

    # Filter config_facts to only include external interfaces and PortChannels
    # Filter INTERFACE - exclude BP interfaces
    filtered_interface = {k: v for k, v in config_facts.get("INTERFACE", {}).items()
                          if not k.split('|')[0].startswith("Ethernet-BP")}

    # Filter PORTCHANNEL_INTERFACE - only external PortChannels
    filtered_pc_interface = {k: v for k, v in config_facts.get("PORTCHANNEL_INTERFACE", {}).items()
                             if (k.split('|')[0] if '|' in k else k) in external_portchannels}

    # Filter PORTCHANNEL_MEMBER - only external PortChannels
    filtered_pc_member = {k: v for k, v in config_facts.get("PORTCHANNEL_MEMBER", {}).items()
                          if k in external_portchannels}

    # Filter BUFFER_PG - exclude BP interfaces
    filtered_buffer_pg = {k: v for k, v in config_facts.get("BUFFER_PG", {}).items()
                          if not k.split('|')[0].startswith("Ethernet-BP")}

    # Filter QUEUE - exclude BP interfaces
    filtered_queue = {
        k: v
        for k, v in _format_sonic_queue_dict(
            config_facts.get("QUEUE", {})
        ).items()
        if not _is_queue_for_internal_port(k)
    }

    # Filter PORTCHANNEL - only external PortChannels
    filtered_portchannel = {k: v for k, v in config_facts.get("PORTCHANNEL", {}).items()
                            if k in external_portchannels}

    staged_restore_config = dict(config_facts)
    staged_restore_config["INTERFACE"] = filtered_interface
    staged_restore_config["PORTCHANNEL_INTERFACE"] = filtered_pc_interface
    staged_restore_config["PORTCHANNEL_MEMBER"] = filtered_pc_member
    staged_restore_config["BUFFER_PG"] = filtered_buffer_pg
    staged_restore_config["QUEUE"] = filtered_queue
    staged_restore_config["PORTCHANNEL"] = filtered_portchannel
    staged_restore_config = _filter_staged_member_restore_config(
        staged_restore_config,
        mg_facts,
        staged_portchannel
    )

    # Now build the dictionaries from filtered data
    interface_dict = format_sonic_interface_dict(
        staged_restore_config.get("INTERFACE", {})
    )
    portchannel_interface_dict = format_sonic_interface_dict(
        staged_restore_config.get("PORTCHANNEL_INTERFACE", {})
    )
    portchannel_member_dict = format_sonic_interface_dict(
        staged_restore_config.get("PORTCHANNEL_MEMBER", {}),
        single_entry=False
    )
    buffer_pg_dict = format_sonic_buffer_pg_dict(
        staged_restore_config.get("BUFFER_PG", {})
    )
    queue_dict = _format_sonic_queue_dict(staged_restore_config.get("QUEUE", {}))
    pc_dict = {
        k: {ik: iv for ik, iv in v.items() if ik != "members"}
        for k, v in staged_restore_config.get("PORTCHANNEL", {}).items()
    }
    pc_dict = _stage_portchannel_config(pc_dict, staged_portchannel)

    # find active ports
    active_interfaces = get_active_interfaces(staged_restore_config, duthost)

    # Build single patch with correct operation order
    # Order is critical for YANG validation:
    # 1. PORTCHANNEL_MEMBER
    # 2. PORTCHANNEL_INTERFACE base entries
    # 3. PORTCHANNEL_INTERFACE IP entries
    # 4. PORTCHANNEL base (comes LAST!)

    #####################################
    # Single combined patch for PortChannel configuration
    #####################################
    json_patch_asic_pc = []

    # STEP 1: Add PORTCHANNEL_MEMBER entries
    for pc_member_key, pc_member_value in portchannel_member_dict.items():
        json_patch_asic_pc.append({
            "op": "add",
            "path": f"{json_namespace}/PORTCHANNEL_MEMBER/{pc_member_key}",
            "value": pc_member_value
        })

    # STEP 2: Add PORTCHANNEL_INTERFACE base entries (no IP addresses)
    for pc_if_key, pc_if_value in portchannel_interface_dict.items():
        if '|' not in pc_if_key:  # Base entries only
            json_patch_asic_pc.append({
                "op": "add",
                "path": f"{json_namespace}/PORTCHANNEL_INTERFACE/{pc_if_key}",
                "value": pc_if_value
            })

    # STEP 3: Add PORTCHANNEL_INTERFACE IP entries with proper JSON Pointer escaping
    for pc_if_key, pc_if_value in portchannel_interface_dict.items():
        if '|' in pc_if_key:  # IP address entries
            # Escape '/' as '~1' in the JSON Pointer path per RFC 6901
            escaped_key = pc_if_key.replace('/', '~1')
            json_patch_asic_pc.append({
                "op": "add",
                "path": f"{json_namespace}/PORTCHANNEL_INTERFACE/{escaped_key}",
                "value": pc_if_value
            })

    # STEP 4: Add PORTCHANNEL base entries (comes LAST!)
    for pc_key, pc_value in pc_dict.items():
        json_patch_asic_pc.append({
            "op": "add",
            "path": f"{json_namespace}/PORTCHANNEL/{pc_key}",
            "value": pc_value
        })

    #####################################
    # Second patch: BGP_NEIGHBOR and everything else
    #####################################
    json_patch_asic_rest = []

    # STEP 5: Add BGP_NEIGHBOR (can now validate against committed PORTCHANNEL_INTERFACE)
    for bgp_key, bgp_value in config_facts["BGP_NEIGHBOR"].items():
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/BGP_NEIGHBOR/{bgp_key}",
            "value": bgp_value
        })

    # STEP 6: Add DEVICE_NEIGHBOR and DEVICE_NEIGHBOR_METADATA
    for dev_key, dev_value in staged_restore_config["DEVICE_NEIGHBOR"].items():
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR/{dev_key}",
            "value": dev_value
        })

    for dev_meta_key, dev_meta_value in staged_restore_config["DEVICE_NEIGHBOR_METADATA"].items():
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA/{dev_meta_key}",
            "value": dev_meta_value
        })

    # STEP 7: Add INTERFACE entries (skip BP interfaces) with proper JSON Pointer escaping
    for iface_key, iface_value in interface_dict.items():
        # Escape '/' as '~1' in the JSON Pointer path per RFC 6901
        escaped_iface_key = iface_key.replace('/', '~1')
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/INTERFACE/{escaped_iface_key}",
            "value": iface_value
        })

    # STEP 8: Add BUFFER_PG entries (skip BP interfaces and pg_lossless profiles)
    # Filter out pg_lossless profiles (e.g., pg_lossless_100000_300m_profile) as they are
    # automatically created by orchagent on DUT. Include other BUFFER_PG entries.
    for bp_key, bp_value in buffer_pg_dict.items():
        # Skip if profile contains "pg_lossless" - orchagent will create these
        if isinstance(bp_value, dict) and 'profile' in bp_value:
            if 'pg_lossless' in bp_value['profile']:
                logger.debug(f"Skipping BUFFER_PG {bp_key} with pg_lossless profile: {bp_value['profile']}")
                continue

        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/BUFFER_PG/{bp_key}",
            "value": bp_value
        })

    # STEP 9: Add PORT_QOS_MAP entries (skip BP interfaces)
    for port_qos_key, port_qos_value in staged_restore_config.get(
        "PORT_QOS_MAP",
        {}
    ).items():
        if port_qos_key.startswith("Ethernet-BP"):
            continue
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/PORT_QOS_MAP/{port_qos_key}",
            "value": port_qos_value
        })

    # STEP 10: Add QUEUE entries (skip BP interfaces)
    for queue_key, queue_value in queue_dict.items():
        if _is_queue_for_internal_port(queue_key):
            continue
        json_patch_asic_rest.append({
            "op": "add",
            "path": "{}/QUEUE/{}".format(
                json_namespace,
                escape_json_pointer_key(queue_key)
            ),
            "value": queue_value
        })

    # STEP 11: Set PORT admin status to up (skip BP interfaces)
    for interface in active_interfaces:
        if interface.startswith("Ethernet-BP"):
            continue
        json_patch_asic_rest.append({
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
            "value": "up"
        })

    # STEP 12: Set CABLE_LENGTH (skip BP interfaces)
    initial_cable_length_table = staged_restore_config["CABLE_LENGTH"]["AZURE"]
    cable_length_values = [int(v.rstrip("m")) for v in initial_cable_length_table.values()]
    highest = max(cable_length_values)
    for interface in active_interfaces:
        if interface.startswith("Ethernet-BP"):
            continue
        json_patch_asic_rest.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, interface),
            "value": f"{highest}m"
        })

    # STEP 13: Add/Replace ACL_TABLE changes
    for acl_table_name in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
        if acl_table_name in config_facts.get("ACL_TABLE", {}):
            json_patch_asic_rest.append({
                "op": "add",
                "path": f"{json_namespace}/ACL_TABLE/{acl_table_name}/ports",
                "value": config_facts["ACL_TABLE"][acl_table_name]["ports"]
            })

    #####################################
    # Apply patches in correct order
    #####################################
    tmpfile_pc = generate_tmpfile(duthost)
    try:
        description = "add cluster info (1/2) PortChannel configuration - ASIC namespace"
        logger.info("Applying patch (1/2) to %s.", description)
        _log_json_patch_content(description, json_patch_asic_pc)
        output = apply_patch(duthost, json_data=json_patch_asic_pc, dest_file=tmpfile_pc)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile_pc)

    tmpfile_rest = generate_tmpfile(duthost)
    try:
        description = (
            "add cluster info (2/2) BGP_NEIGHBOR and remaining config "
            "- ASIC namespace"
        )
        logger.info("Applying patch (2/2) to %s.", description)
        _log_json_patch_content(description, json_patch_asic_rest)
        output = apply_patch(duthost, json_data=json_patch_asic_rest, dest_file=tmpfile_rest)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile_rest)


def _append_staged_member_port_restore_ops(json_patch, config_facts, mg_facts,
                                           json_namespace, member):
    """
    Append ASIC namespace operations that restore one physical member port.
    """
    if member in config_facts.get("PORT", {}):
        json_patch.append({
            "op": "add",
            "path": "{}/PORT/{}".format(json_namespace, member),
            "value": config_facts["PORT"][member],
        })
    else:
        json_patch.append({
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, member),
            "value": "up",
        })

    if member in config_facts.get("DEVICE_NEIGHBOR", {}):
        json_patch.append({
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR/{}".format(json_namespace, member),
            "value": config_facts["DEVICE_NEIGHBOR"][member],
        })

    neighbor_name = _get_member_neighbor_name(config_facts, mg_facts, member)
    if (neighbor_name in config_facts.get("DEVICE_NEIGHBOR_METADATA", {}) and
            not _is_neighbor_metadata_used_by_other_port(config_facts, neighbor_name, member)):
        json_patch.append({
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR_METADATA/{}".format(json_namespace, neighbor_name),
            "value": config_facts["DEVICE_NEIGHBOR_METADATA"][neighbor_name],
        })

    interface_dict = format_sonic_interface_dict(config_facts.get("INTERFACE", {}))
    for iface_key, iface_value in interface_dict.items():
        if not _is_port_scoped_key(iface_key, member):
            continue
        json_patch.append({
            "op": "add",
            "path": "{}/INTERFACE/{}".format(
                json_namespace,
                escape_json_pointer_key(iface_key)
            ),
            "value": iface_value,
        })

    buffer_pg_dict = format_sonic_buffer_pg_dict(config_facts.get("BUFFER_PG", {}))
    for bp_key, bp_value in buffer_pg_dict.items():
        if not _is_port_scoped_key(bp_key, member):
            continue
        if isinstance(bp_value, dict) and 'pg_lossless' in bp_value.get('profile', ''):
            continue
        json_patch.append({
            "op": "add",
            "path": "{}/BUFFER_PG/{}".format(
                json_namespace,
                escape_json_pointer_key(bp_key)
            ),
            "value": bp_value,
        })

    if member in config_facts.get("PORT_QOS_MAP", {}):
        json_patch.append({
            "op": "add",
            "path": "{}/PORT_QOS_MAP/{}".format(json_namespace, member),
            "value": config_facts["PORT_QOS_MAP"][member],
        })

    queue_dict = _format_sonic_queue_dict(config_facts.get("QUEUE", {}))
    for queue_key, queue_value in queue_dict.items():
        if not _queue_key_matches_port(queue_key, member):
            continue
        json_patch.append({
            "op": "add",
            "path": "{}/QUEUE/{}".format(
                json_namespace,
                escape_json_pointer_key(queue_key)
            ),
            "value": queue_value,
        })

    if member in config_facts.get("PFC_WD", {}):
        json_patch.append({
            "op": "add",
            "path": "{}/PFC_WD/{}".format(json_namespace, member),
            "value": config_facts["PFC_WD"][member],
        })

    cable_length = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {}).get(member)
    if cable_length is not None:
        json_patch.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, member),
            "value": cable_length,
        })


def _append_staged_member_localhost_restore_ops(json_patch, config_facts, mg_facts,
                                                portchannel, member, member_value,
                                                original_min_links):
    """
    Append localhost namespace operations for one restored member port.
    """
    member_alias = mg_facts['minigraph_port_name_to_alias_map'].get(member, member)

    if member in config_facts.get("DEVICE_NEIGHBOR", {}):
        json_patch.append({
            "op": "add",
            "path": "/localhost/DEVICE_NEIGHBOR/{}".format(member),
            "value": config_facts["DEVICE_NEIGHBOR"][member],
        })

    neighbor_name = _get_member_neighbor_name(config_facts, mg_facts, member)
    if (neighbor_name in config_facts.get("DEVICE_NEIGHBOR_METADATA", {}) and
            not _is_neighbor_metadata_used_by_other_port(config_facts, neighbor_name, member)):
        json_patch.append({
            "op": "add",
            "path": "/localhost/DEVICE_NEIGHBOR_METADATA/{}".format(neighbor_name),
            "value": config_facts["DEVICE_NEIGHBOR_METADATA"][neighbor_name],
        })

    interface_dict = format_sonic_interface_dict(config_facts.get("INTERFACE", {}))
    for iface_key, iface_value in interface_dict.items():
        if not _is_port_scoped_key(iface_key, member):
            continue
        parts = iface_key.split('|')
        if len(parts) == 2:
            localhost_iface_key = "{}|{}".format(member_alias, parts[1])
        else:
            localhost_iface_key = member_alias
        json_patch.append({
            "op": "add",
            "path": "/localhost/INTERFACE/{}".format(
                escape_json_pointer_key(localhost_iface_key)
            ),
            "value": iface_value,
        })

    localhost_member_key = "{}|{}".format(portchannel, member_alias)
    json_patch.extend([
        {
            "op": "add",
            "path": "/localhost/PORTCHANNEL_MEMBER/{}".format(
                escape_json_pointer_key(localhost_member_key)
            ),
            "value": member_value
        },
        {
            "op": "add",
            "path": "/localhost/PORTCHANNEL/{}/min_links".format(portchannel),
            "value": original_min_links
        }
    ])


def apply_patch_add_staged_portchannel_member(config_facts,
                                              config_facts_localhost,
                                              mg_facts,
                                              duthost,
                                              enum_rand_one_asic_namespace,
                                              staged_portchannel):
    """
    Add the withheld PortChannel member and restore the original min_links.
    """
    if not staged_portchannel:
        return

    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace
    portchannel = staged_portchannel["portchannel"]
    member = staged_portchannel["withheld_member"]
    original_min_links = staged_portchannel["original_min_links"]
    member_key = "{}|{}".format(portchannel, member)
    member_value = get_portchannel_member_value(config_facts, portchannel, member)
    json_patch = []
    _append_staged_member_port_restore_ops(
        json_patch,
        config_facts,
        mg_facts,
        json_namespace,
        member
    )
    json_patch.extend([
        {
            "op": "add",
            "path": "{}/PORTCHANNEL_MEMBER/{}".format(
                json_namespace,
                escape_json_pointer_key(member_key)
            ),
            "value": member_value
        },
        {
            "op": "add",
            "path": "{}/PORTCHANNEL/{}/min_links".format(
                json_namespace,
                portchannel
            ),
            "value": original_min_links
        }
    ])

    if duthost.facts.get('switch_type') != 'chassis-packet':
        _append_staged_member_localhost_restore_ops(
            json_patch,
            config_facts,
            mg_facts,
            portchannel,
            member,
            member_value,
            original_min_links
        )

    _apply_json_patch(
        duthost,
        json_patch,
        "add staged PortChannel member {} and restore {} min_links".format(
            member_key,
            portchannel
        )
    )


# -----------------------------
# Setup Fixtures/functions
# -----------------------------

@pytest.fixture(scope="module", params=[False, True])
def acl_config_scenario(request):
    return request.param


# Setting to false due to kvm data traffic issue failing the test case. Need to be enabled after investigation.
# Issue: https://github.com/sonic-net/sonic-mgmt/issues/21775
@pytest.fixture(scope="module", params=[False])
def data_traffic_scenario(request):
    return request.param


@pytest.fixture(scope="module")
def add_cluster_asic_context(tbinfo,
                             duthosts,
                             enum_rand_one_frontend_asic_index):
    """
    Select the ASIC context used by test_add_cluster.

    The downstream DUT is preserved from the existing enum fixture. Within that
    DUT, prefer the enum-selected ASIC and otherwise choose a frontend ASIC that
    has a multi-member PortChannel suitable for staged member restoration.
    """
    enum_downstream_dut_hostname = _pick_primary_downstream_hostname(duthosts, tbinfo)
    duthost = duthosts[enum_downstream_dut_hostname]
    config_facts_localhost = duthost.config_facts(
        host=duthost.hostname,
        source="running",
        namespace=None
    )['ansible_facts']

    first_context = None
    for asic_index in _ordered_frontend_asic_indices(duthost, enum_rand_one_frontend_asic_index):
        asic_namespace, cli_namespace_prefix, ip_netns_namespace_prefix = _get_namespace_prefixes(
            duthost,
            asic_index
        )
        config_facts = duthost.config_facts(
            host=duthost.hostname,
            source="running",
            namespace=asic_namespace
        )['ansible_facts']
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo, namespace=asic_namespace)
        portchannel_status_map, _ = get_portchannel_status_map(
            duthost,
            asic_namespace,
        )
        staged_portchannel = _select_staged_portchannel(
            config_facts,
            portchannel_status_map,
        )
        context = {
            "enum_downstream_dut_hostname": enum_downstream_dut_hostname,
            "enum_rand_one_frontend_asic_index": asic_index,
            "enum_rand_one_asic_namespace": asic_namespace,
            "cli_namespace_prefix": cli_namespace_prefix,
            "ip_netns_namespace_prefix": ip_netns_namespace_prefix,
            "config_facts": config_facts,
            "config_facts_localhost": config_facts_localhost,
            "mg_facts": mg_facts,
            "staged_portchannel": staged_portchannel,
        }
        if first_context is None:
            first_context = context
        if staged_portchannel:
            logger.info(
                "Selected add-cluster staged PortChannel context: dut=%s asic=%s namespace=%s "
                "portchannel=%s withheld_member=%s original_min_links=%s staged_min_links=%s",
                enum_downstream_dut_hostname,
                asic_index,
                asic_namespace,
                staged_portchannel["portchannel"],
                staged_portchannel["withheld_member"],
                staged_portchannel["original_min_links"],
                staged_portchannel["staged_min_links"],
            )
            return context

    pytest_assert(first_context is not None, "No frontend ASIC context found for {}".format(
        enum_downstream_dut_hostname
    ))
    logger.info(
        "No frontend ASIC on downstream DUT %s has a multi-member PortChannel with min_links > 1. "
        "Running add-cluster with the original full restore flow on ASIC %s.",
        enum_downstream_dut_hostname,
        first_context["enum_rand_one_frontend_asic_index"] if first_context else None,
    )
    return first_context


@pytest.fixture(scope="module")
def enum_rand_one_asic_namespace(add_cluster_asic_context):
    return add_cluster_asic_context["enum_rand_one_asic_namespace"]


@pytest.fixture(scope="module")
def cli_namespace_prefix(add_cluster_asic_context):
    return add_cluster_asic_context["cli_namespace_prefix"]


@pytest.fixture(scope="module")
def ip_netns_namespace_prefix(add_cluster_asic_context):
    return add_cluster_asic_context["ip_netns_namespace_prefix"]


@pytest.fixture(scope="module")
def config_facts(add_cluster_asic_context):
    return add_cluster_asic_context["config_facts"]


@pytest.fixture(scope="module")
def config_facts_localhost(add_cluster_asic_context):
    return add_cluster_asic_context["config_facts_localhost"]


@pytest.fixture(scope="module")
def mg_facts(add_cluster_asic_context):
    return add_cluster_asic_context["mg_facts"]


def setup_acl_config(duthost, ip_netns_namespace_prefix):
    logger.info("Adding acl config.")
    remove_dataacl_table_single_dut("DATAACL", duthost)
    duthost.command("{} config acl add table {} {} -s {}".format(
        ip_netns_namespace_prefix, ACL_TABLE_NAME, ACL_TABLE_TYPE_L3, ACL_TABLE_STAGE_EGRESS))
    duthost.copy(src=ACL_RULE_FILE_PATH, dest=ACL_RULE_DST_FILE)
    duthost.shell("{} acl-loader update full --table_name {} {}".format(
        ip_netns_namespace_prefix, ACL_TABLE_NAME, ACL_RULE_DST_FILE))
    acl_tables = duthost.command("{} show acl table".format(ip_netns_namespace_prefix))["stdout_lines"]
    acl_rules = duthost.command("{} show acl rule".format(ip_netns_namespace_prefix))["stdout_lines"]
    logging.info(('\n'.join(acl_tables)))
    logging.info(('\n'.join(acl_rules)))


def remove_acl_config(duthost, ip_netns_namespace_prefix):
    logger.info("Removing acl config.")
    config_reload(duthost, config_source="minigraph", safe_reload=True)
    acl_tables = duthost.command("{} show acl table".format(ip_netns_namespace_prefix))["stdout_lines"]
    acl_rules = duthost.command("{} show acl rule".format(ip_netns_namespace_prefix))["stdout_lines"]
    logging.info(('\n'.join(acl_tables)))
    logging.info(('\n'.join(acl_rules)))


@pytest.fixture(scope="module")
def setup_static_route(tbinfo, duthosts, add_cluster_asic_context,
                       rand_bgp_neigh_ip_name):
    enum_downstream_dut_hostname = add_cluster_asic_context["enum_downstream_dut_hostname"]
    enum_rand_one_frontend_asic_index = add_cluster_asic_context["enum_rand_one_frontend_asic_index"]
    duthost = duthosts[enum_downstream_dut_hostname]
    bgp_neigh_ip, bgp_neigh_name = rand_bgp_neigh_ip_name
    logger.info("Adding static route {} to be routed via bgp neigh {}.".format(STATIC_DST_IP, bgp_neigh_ip))
    exabgp_port = get_exabgp_port_for_neighbor(tbinfo, bgp_neigh_name, EXABGP_BASE_PORT)
    route_exists = verify_routev4_existence(duthost, enum_rand_one_frontend_asic_index,
                                            STATIC_DST_IP, should_exist=True)
    if route_exists:
        logger.warning("Route exists already - will try to clear")
        clear_static_route(tbinfo, duthost, STATIC_DST_IP)
    add_static_route(tbinfo, bgp_neigh_ip, exabgp_port, ip=STATIC_DST_IP, nhipv4=NHIPV4)
    wait_until(10, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=True)

    yield

    logger.info("Removing static route {} .".format(STATIC_DST_IP))
    remove_static_route(tbinfo, bgp_neigh_ip, exabgp_port, ip=STATIC_DST_IP, nhipv4=NHIPV4)
    wait_until(10, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=False)


@pytest.fixture(scope="function")
def initialize_random_variables(enum_upstream_dut_hostname,
                                add_cluster_asic_context,
                                rand_bgp_neigh_ip_name):
    enum_downstream_dut_hostname = add_cluster_asic_context["enum_downstream_dut_hostname"]
    enum_rand_one_frontend_asic_index = add_cluster_asic_context["enum_rand_one_frontend_asic_index"]
    enum_rand_one_asic_namespace = add_cluster_asic_context["enum_rand_one_asic_namespace"]
    ip_netns_namespace_prefix = add_cluster_asic_context["ip_netns_namespace_prefix"]
    cli_namespace_prefix = add_cluster_asic_context["cli_namespace_prefix"]
    return enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, cli_namespace_prefix, rand_bgp_neigh_ip_name


@pytest.fixture(scope="function")
def initialize_facts(mg_facts,
                     config_facts,
                     config_facts_localhost):
    return mg_facts, config_facts, config_facts_localhost


@pytest.fixture(scope="function")
def ignore_add_cluster_loganalyzer_exceptions(duthosts, add_cluster_asic_context, loganalyzer):
    """
    Ignore expected transient PFC watchdog errors on the DUT under add-cluster.
    """
    duthost = duthosts[add_cluster_asic_context["enum_downstream_dut_hostname"]]
    if loganalyzer and duthost.hostname in loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(LOGANALYZER_IGNORE_REGEX)
    yield


@pytest.fixture(scope="function")
def setup_add_cluster(tbinfo,
                      duthosts,
                      localhost,
                      initialize_random_variables,
                      initialize_facts,
                      loganalyzer,
                      ignore_add_cluster_loganalyzer_exceptions,
                      acl_config_scenario,
                      setup_static_route,
                      add_cluster_asic_context,
                      data_traffic_scenario,
                      request):
    """
    This setup fixture prepares the Downstream LC by applying a patch to remove
    and then re-add the cluster configuration.

    The purpose is to prepare the DUT host for test cases that validate functionality
    after adding a cluster via apply-patch.
    The fixture reads the running configuration and constructs patches to remove
    the current config from a running namespace.
    After verifying successful removal, it re-adds the configuration and validates that it was successfully restored.

    **Setup steps - applied to the Downstream LC:**
    1. Save the original configuration.
    2. Remove the cluster from a randomly selected namespace.
    3. Verify BGP information, route table, and interface details to ensure everything has been removed as expected.
    4. Perform data verification in the upstream → downlink direction, targeting a static route, which should now fail.
    5. Save the configuration and reboot the system so that it initializes clear from cluster information
    6. Re-add the cluster to the randomly selected namespace.
    7. Verify BGP information, route table, and interface details to ensure everything is restored as expected.
    8. Add ACL configuration based on the test parameter value.

    **Teardown steps:**
    The setup logic already re-applies the initial cluster configuration for the namespace.
    The only recovery needed during teardown is for the ACL configuration:
    1. Restore the ACL configuration to its initial values.
    """

    # initial test env
    enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, cli_namespace_prefix, \
        rand_bgp_neigh_ip_name = initialize_random_variables
    mg_facts, config_facts, config_facts_localhost = initialize_facts
    staged_portchannel = add_cluster_asic_context["staged_portchannel"]
    duthost = duthosts[enum_downstream_dut_hostname]
    # Check if the device is a modular chassis and the topology is T2
    is_chassis = duthost.get_facts().get("modular_chassis")
    if not (is_chassis and tbinfo['topo']['type'] == 't2' and
            (duthost.facts['switch_type'] == "voq" or
             duthost.facts['switch_type'] == "chassis-packet")):
        pytest.skip("Test is Applicable for T2 VOQ or Chassis-Packet Chassis Setup")
    duthost_src = duthosts[enum_upstream_dut_hostname]
    asic_id = enum_rand_one_frontend_asic_index
    asic_id_src = None
    all_asic_ids = duthost_src.get_asic_ids()
    for asic in all_asic_ids:
        if duthost_src == duthost and asic == asic_id:
            continue
        asic_id_src = asic
        break
    bgp_neigh_ip, _bgp_neigh_name = rand_bgp_neigh_ip_name
    pytest_assert(
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic. \
            Reserved asic id: {}. All available asic ids: {}".format(
            asic_id, all_asic_ids
        )
    )
    initial_buffer_pg_info = get_cfg_info_from_dut(
        duthost,
        'BUFFER_PG',
        enum_rand_one_asic_namespace
    )
    initial_queue_info = get_cfg_info_from_dut(
        duthost,
        'QUEUE',
        enum_rand_one_asic_namespace
    )
    with allure.step("Verification before removing cluster"):
        for host_device in duthosts:
            if host_device.is_supervisor_node():
                continue
            logger.info(host_device.shell('show ip bgp summary -d all'))
            logger.info(host_device.shell('show ipv6 bgp summary -d all'))
        route_exists = verify_routev4_existence(duthost, asic_id, STATIC_DST_IP, should_exist=True)
        route_exists_src = verify_routev4_existence(duthost_src, asic_id_src, STATIC_DST_IP, should_exist=True)
        pytest_assert(route_exists, "Static route {} doesn't exist on downstream DUT before cluster removal."
                      .format(STATIC_DST_IP))
        pytest_assert(route_exists_src, "Static route {} doesn't exist on upstream DUT before cluster removal."
                      .format(STATIC_DST_IP))
        if data_traffic_scenario:
            ptfadapter = request.getfixturevalue("ptfadapter")
            logger.info("Sending traffic from upstream DUT to downstream DUT before cluster removal.")
            send_and_verify_traffic(tbinfo, duthost_src, duthost, asic_id_src, asic_id,
                                    ptfadapter, dst_ip=STATIC_DST_IP, count=10, expect_error=False)

    with allure.step("Removing cluster info for namespace"):
        # disable loganalyzer during cluster removal
        logger.info("Disabling loganalyzer before starting cluster removal.")
        if loganalyzer and loganalyzer[duthost.hostname]:
            loganalyzer[duthost.hostname].add_start_ignore_mark()

        # Check switch type to determine which removal functions to use
        is_chassis_packet = duthost.facts.get('switch_type') == 'chassis-packet'
        logger.info(f"Switch type: {duthost.facts.get('switch_type')} - "
                    f"Using chassis-packet functions: {is_chassis_packet}")

        if len(config_facts["BUFFER_PG"]) <= 6:  # num of active interfaces = num of pg lossless profiles
            if is_chassis_packet:
                logger.info("Removal method gcu - min setup (chassis-packet).")
                apply_patch_remove_cluster_chassis_packet(config_facts,
                                                          config_facts_localhost,
                                                          mg_facts,
                                                          duthost,
                                                          enum_rand_one_asic_namespace,
                                                          cli_namespace_prefix)
            else:
                logger.info("Removal method gcu - min setup (non-chassis-packet).")
                apply_patch_remove_cluster(config_facts,
                                           config_facts_localhost,
                                           mg_facts,
                                           duthost,
                                           enum_rand_one_asic_namespace,
                                           cli_namespace_prefix)
        else:
            if is_chassis_packet:
                logger.info("Removal method sonic-db-cli - mid-max setup (chassis-packet).")
                remove_cluster_via_sonic_db_cli_chassis_packet(config_facts,
                                                               config_facts_localhost,
                                                               mg_facts,
                                                               duthost,
                                                               enum_rand_one_asic_namespace,
                                                               cli_namespace_prefix)
            else:
                logger.info("Removal method sonic-db-cli - mid-max setup (non-chassis-packet).")
                remove_cluster_via_sonic_db_cli(config_facts,
                                                config_facts_localhost,
                                                mg_facts,
                                                duthost,
                                                enum_rand_one_asic_namespace,
                                                cli_namespace_prefix)

        # Verify routes removed
        wait_until(5, 1, 0, verify_routev4_existence, duthost,
                   enum_rand_one_frontend_asic_index, bgp_neigh_ip, should_exist=False)
        wait_until(5, 1, 0, verify_routev4_existence, duthost,
                   enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=False)

        # re-enabling loganalyzer during cluster removal
        logger.info("Re-enabling loganalyzer after cluster removal.")
        if loganalyzer and loganalyzer[duthost.hostname]:
            loganalyzer[duthost.hostname].add_end_ignore_mark()
    with allure.step("Reload the system with config reload"):
        duthost.shell("config save -y")
        config_reload(duthost, config_source='config_db', safe_reload=True)
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "All critical services should be fully started!")
        pytest_assert(wait_until(1200, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up on are operationally up")

    with allure.step("Verify config after reload"):
        tmpfile = generate_tmpfile(duthost)
        output = apply_patch(duthost, json_data=[], dest_file=tmpfile)
        expect_op_success(duthost, output)

    with allure.step("Adding cluster info for namespace"):
        # Check switch type to determine which add function to use
        is_chassis_packet = duthost.facts.get('switch_type') == 'chassis-packet'
        if is_chassis_packet:
            apply_patch_add_cluster_chassis_packet(config_facts,
                                                   config_facts_localhost,
                                                   mg_facts,
                                                   duthost,
                                                   enum_rand_one_asic_namespace,
                                                   staged_portchannel=staged_portchannel)
        else:
            apply_patch_add_cluster(config_facts,
                                    config_facts_localhost,
                                    mg_facts,
                                    duthost,
                                    enum_rand_one_asic_namespace,
                                    staged_portchannel=staged_portchannel)
        # Verify routes added
        wait_until(5, 1, 0, verify_routev4_existence,
                   duthost, enum_rand_one_frontend_asic_index, bgp_neigh_ip, should_exist=True)
        wait_until(5, 1, 0, verify_routev4_existence,
                   duthost, enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=True)
        # Verify buffer pg
        buffer_pg_info_add_interfaces = get_cfg_info_from_dut(
            duthost,
            'BUFFER_PG',
            enum_rand_one_asic_namespace
        )
        if not staged_portchannel:
            pytest_assert(
                buffer_pg_info_add_interfaces == initial_buffer_pg_info,
                "Didn't find expected BUFFER_PG info in CONFIG_DB after "
                "adding back the interfaces."
            )
            queue_info_add_interfaces = get_cfg_info_from_dut(
                duthost,
                'QUEUE',
                enum_rand_one_asic_namespace
            )
            pytest_assert(queue_info_add_interfaces == initial_queue_info,
                          "Didn't find expected QUEUE info in CONFIG_DB "
                          "after adding back the interfaces.")

    if staged_portchannel:
        with allure.step("Verify add-cluster first stage before adding withheld PortChannel member"):
            verify_staged_portchannel_member_state(
                duthost,
                cli_namespace_prefix,
                staged_portchannel,
                member_should_exist=False,
                expected_min_links=staged_portchannel["staged_min_links"]
            )
            verify_staged_member_default_state(
                duthost,
                cli_namespace_prefix,
                staged_portchannel
            )
            wait_for_portchannel_up_or_log(
                duthost,
                enum_rand_one_asic_namespace,
                staged_portchannel["portchannel"]
            )

        with allure.step("Add withheld PortChannel member and restore original min_links"):
            apply_patch_add_staged_portchannel_member(
                config_facts,
                config_facts_localhost,
                mg_facts,
                duthost,
                enum_rand_one_asic_namespace,
                staged_portchannel
            )

        with allure.step("Verify withheld PortChannel member and original min_links restored"):
            verify_staged_portchannel_member_state(
                duthost,
                cli_namespace_prefix,
                staged_portchannel,
                member_should_exist=True,
                expected_min_links=staged_portchannel["original_min_links"]
            )
            buffer_pg_info_after_staged_member = get_cfg_info_from_dut(
                duthost,
                'BUFFER_PG',
                enum_rand_one_asic_namespace
            )
            pytest_assert(
                buffer_pg_info_after_staged_member == initial_buffer_pg_info,
                "Didn't find expected BUFFER_PG info in CONFIG_DB after "
                "adding staged PortChannel member."
            )
            queue_info_after_staged_member = get_cfg_info_from_dut(
                duthost,
                'QUEUE',
                enum_rand_one_asic_namespace
            )
            pytest_assert(queue_info_after_staged_member == initial_queue_info,
                          "Didn't find expected QUEUE info in CONFIG_DB "
                          "after adding staged PortChannel member.")
            pytest_assert(
                wait_for_portchannel_up_or_log(
                    duthost,
                    enum_rand_one_asic_namespace,
                    staged_portchannel["portchannel"]
                ),
                "PortChannel {} did not come up after adding staged member".format(
                    staged_portchannel["portchannel"]
                )
            )

        with allure.step("Verify staged PortChannel member operational state"):
            ptfadapter = request.getfixturevalue("ptfadapter")
            verify_staged_portchannel_operational_state(
                duthost,
                tbinfo,
                ptfadapter,
                enum_rand_one_frontend_asic_index,
                enum_rand_one_asic_namespace,
                cli_namespace_prefix,
                ip_netns_namespace_prefix,
                mg_facts,
                config_facts,
                staged_portchannel
            )

    if acl_config_scenario:
        setup_acl_config(duthost, ip_netns_namespace_prefix)

    yield

    if acl_config_scenario:
        remove_acl_config(duthost, ip_netns_namespace_prefix)


# -----------------------------
# Test Definitions
# -----------------------------

def test_add_cluster(tbinfo,
                     duthosts,
                     initialize_random_variables,
                     loganalyzer,
                     acl_config_scenario,
                     cli_namespace_prefix,
                     setup_add_cluster,
                     data_traffic_scenario,
                     request):
    """
    Validates the functionality of the Downstream Linecard after adding a cluster.

    Performs lossless data traffic scenarios for both ACL and non-ACL cases.
    Verifies successful data transmission, queue counters, and ACL rule match counters.
    """

    # initial test env
    enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, cli_namespace_prefix, \
        rand_bgp_neigh_ip_name = initialize_random_variables
    duthost = duthosts[enum_downstream_dut_hostname]
    duthost_up = duthosts[enum_upstream_dut_hostname]
    asic_id = enum_rand_one_frontend_asic_index
    asic_id_src = None
    asic_id_src_up = None
    for asic in duthost.get_asic_ids():
        if asic == asic_id:
            continue
        asic_id_src = asic
        break
    for asic in duthost_up.get_asic_ids():
        asic_id_src_up = asic
        break

    pytest_assert(
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic. \
            Reserved asic id: {}. All available asic ids: {}".format(
            asic_id, duthost.get_asic_ids()
        )
    )
    pytest_assert(
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic from upstream. \
            All available asic ids: {}".format(
            duthost_up.get_asic_ids()
        )
    )

    if data_traffic_scenario:
        ptfadapter = request.getfixturevalue("ptfadapter")
        # Traffic scenarios applied in non-acl, acl scenario
        traffic_scenarios = [
            {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
             "sport": 1234, "dport": 50, "verify": True, "expect_error": False},
            {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
             "sport": 1234, "dport": 50, "verify": True, "expect_error": False}
        ]
        if acl_config_scenario:
            traffic_scenarios = [
                {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
                {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 1234, "dport": 8080, "verify": True, "expect_error": True, "match_rule": "RULE_200"},
                {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 1234, "dport": 50, "verify": True, "expect_error": False, "match_rule": None},
                {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
                {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 1234, "dport": 8080, "verify": True, "expect_error": True, "match_rule": "RULE_200"},
                {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
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
                pytest_assert("Unsupported direction for traffic scenario {}.".format(traffic_scenario["direction"]))

            if acl_config_scenario:
                duthost.shell('{} aclshow -c'.format(ip_netns_namespace_prefix))

            send_and_verify_traffic(tbinfo, src_duthost, duthost, src_asic_index, asic_id,
                                    ptfadapter,
                                    dst_ip=traffic_scenario["dst_ip"],
                                    dscp=traffic_scenario["dscp"],
                                    count=traffic_scenario["count"],
                                    sport=traffic_scenario["sport"],
                                    dport=traffic_scenario["dport"],
                                    verify=traffic_scenario["verify"],
                                    expect_error=traffic_scenario["expect_error"])

            if acl_config_scenario:
                acl_counters = duthost.show_and_parse('{} aclshow -a'.format(ip_netns_namespace_prefix))
                for acl_counter in acl_counters:
                    if acl_counter["rule name"] in ACL_RULE_SKIP_VERIFICATION_LIST:
                        continue
                    pytest_assert(acl_counter["packets count"] == str(traffic_scenario["count"])
                                  if acl_counter["rule name"] == traffic_scenario["match_rule"]
                                  else acl_counter["packets count"] == '0',
                                  "Acl rule {} statistics are not as expected. Found value {}"
                                  .format(acl_counter["rule name"], acl_counter["packets count"]))


# ===========================================================================
# GCU Add-MOR SCALING TEST
# ===========================================================================
#
# Purpose
# -------
# Measure how ``config apply-patch`` elapsed time scales with the number of
# MORs (T1 neighbors) re-added in a single patch.  The GCU patch sorter's
# cost grows super-linearly with the number of moves in a patch, so this is
# a baseline instrument for catching sorter regressions that a fixed-size
# patch would miss.
#
# Design
# ------
# 1. Full cluster is present at test entry.
# 2. Pick N external PortChannels (= N MORs) via ``_select_n_mors()``.
# 3. Remove just those N MORs with targeted ``sonic-db-cli`` deletes in
#    ``_cli_remove_selected_mors()`` (setup, untimed).  A GCU/JSON-patch
#    remove was tried first but hit YANG cascade-delete edge cases, and the
#    existing ``remove_cluster_via_sonic_db_cli()`` helper wildcard-deletes
#    the whole ASIC, which is too coarse for a per-N measurement.
# 4. Strip those PortChannels from any referring ``ports`` leaf-list via
#    ``_scan_pc_references()`` / ``_cli_remove_pc_references()`` so the
#    add-back patch does not trip leafref validation.
# 5. Build one incremental JSON patch that re-adds exactly those N MORs
#    (``_build_scaling_add_patch()``) and apply it in a single
#    ``apply_patch()`` call — TIMED.
# 6. Verify BGP peers on those N MORs come back up.
# 7. record_property() the metric so CI can graph it.
# 8. Teardown: ``config rollback`` restores full state.
#
# The ADD path deliberately builds its own patch instead of reusing
# ``apply_patch_add_cluster*()``: those helpers rebuild the *entire* cluster
# from ``config_facts``, so the measured time would not vary with N.  A
# scaling measurement needs a patch whose size is a function of N alone.
# ===========================================================================

# Tiered N values:
#   - Nightly: fast regression + one near-production data point.
#   - Weekly:  full-scale capacity ("how many MORs in 1 hour" number).
#   - Sanity:  validates the test itself; opt-in only.
# Selected with -m markers; each pytest run instantiates one (n_mors, tier).
NIGHTLY_MOR_COUNTS = [5, 20]
WEEKLY_MOR_COUNTS = [24, 30]
SANITY_MOR_COUNTS = [1]

# test_max_mors_under_budget sweeps to find the largest N that fits under a
# FIXED absolute ceiling — the operational 1-hour target.
DEFAULT_TIME_BUDGET_S = 3600

# ---------------------------------------------------------------------------
# Time budget
# ---------------------------------------------------------------------------
# The budget is DERIVED FROM THE PLATFORM, not hard-coded.  GCU's cost model is
#
#     elapsed ~= fixed_overhead + moves * loads_per_move * loadData_cost
#
# because the sorter validates every move by re-loading the whole config into
# YANG (FullConfigMoveValidator + NoDependencyMoveValidator => 2 loads/move).
# loadData_cost is a property of the box and of how big its config is, so a
# constant "N seconds per MOR" calibrated on one line card is wrong everywhere
# else and drifts as the config grows.  We therefore measure loadData on the
# DUT and predict, in the same spirit as test_apply_patch_perf.py.
#
# ``expected_moves`` is approximated by the number of ops in the add-patch.
# For an ADD-dominated patch like ours the sorter emits at most one move per
# added key, so op-count is an UPPER bound on moves -- it already carries
# slack, which is why SCALING_SAFETY_MULTIPLIER is 2 here rather than the 5
# used by test_apply_patch_perf.py (that test computes exact move counts).
#
# Caveat, deliberately recorded: with the loadData caching fix (upstream
# #4476) loads no longer scale per-move -- they collapse to ~2 for the whole
# patch.  Against fixed GCU this budget is therefore generous, and acts as a
# catastrophic-regression gate rather than a tight one.  Asserting on sorter
# move count directly is the hardware-independent successor to this; tracked
# separately.
SCALING_LOADS_PER_MOVE = 2
SCALING_SAFETY_MULTIPLIER = 2
# Fixed per-invocation cost (CLI startup, YANG init, ConfigDB write, SSH)
# that is present even for a 1-op patch.  Floor only; never scaled by N.
SCALING_MIN_OVERHEAD_S = 60
# Used only if the on-DUT loadData measurement fails.  Deliberately generous.
FALLBACK_LOADDATA_TIME_S = 1.0

# A loadData() that "took" less than this did not really run (the helper
# swallows internal exceptions and the shell still exits 0), so the reading is
# discarded in favour of the fallback rather than used to build a tiny budget.
MIN_PLAUSIBLE_LOADDATA_S = 0.05
# Keep the budget strictly below apply_patch()'s own timeout, so that
# "exceeded budget" is always reachable and is never pre-empted by the fuse.
FUSE_MARGIN_S = 120

# Legacy constants, retained ONLY as the fallback path when calibration is
# unavailable.  Measured on a modular-chassis line card: ~1.47 s per change at
# ~34 changes/MOR, i.e. ~50 s/MOR.
PER_MOR_BUDGET_S = 60
BUDGET_FLOOR_S = 300


def _measure_loaddata_baseline(duthost, namespace=None):
    """Measure the cost of one SonicYang.loadData() call on this DUT.

    Read-only: loads the on-disk config into YANG in a throwaway interpreter.
    It does not touch CONFIG_DB and does not mutate the device, so it is safe
    to run before the measurement without disturbing what we are timing.

    Returns seconds as a float, or None if the measurement could not be made.
    """
    cfg_path = ("/etc/sonic/config_db.json" if namespace is None
                else "/etc/sonic/config_db{}.json".format(
                    namespace.replace("asic", "")))
    script = r"""
import json, time, sonic_yang
sy = sonic_yang.SonicYang('/usr/local/yang-models', print_log_enabled=False)
sy.loadYangModel()
with open('%s') as f:
    config = json.load(f)
try:
    sy.loadData(config)          # warm up caches / lazy imports
except Exception:
    pass
sy2 = sonic_yang.SonicYang('/usr/local/yang-models', print_log_enabled=False)
sy2.loadYangModel()
start = time.time()
try:
    sy2.loadData(config)
except Exception:
    pass
print("LOADDATA_TIME={:.6f}".format(time.time() - start))
""" % cfg_path
    out = duthost.shell("python3 -c '{}'".format(script.replace("'", "'\\''")),
                        module_ignore_errors=True)
    if out["rc"] != 0:
        logger.warning("loadData baseline measurement failed (rc=%s): %s",
                       out["rc"], out.get("stderr", ""))
        return None
    for line in out["stdout"].splitlines():
        if line.startswith("LOADDATA_TIME="):
            measured = float(line.split("=")[1])
            logger.info("Measured single loadData() cost: %.3fs", measured)
            return measured
    logger.warning("loadData baseline produced no LOADDATA_TIME line")
    return None


def _predicted_elapsed_s(n_ops, loaddata_time):
    """Expected apply-patch wall time for a patch of *n_ops* ops, no safety."""
    return (SCALING_MIN_OVERHEAD_S +
            n_ops * SCALING_LOADS_PER_MOVE * loaddata_time)


def _time_budget_for(n_mors, n_ops=None, loaddata_time=None, fuse_s=None):
    """Time budget for the scaling assertion.

    Precedence:
      1. GCU_TIME_BUDGET_S -- absolute override, used verbatim (debugging).
      2. Platform-derived, when we have both an op count and a loadData
         measurement:  overhead + n_ops * 2 * loadData * safety.
      3. Fallback to the legacy per-MOR constant.

    The result is always clamped below the apply-patch fuse (when known) so
    the budget assertion can actually fire instead of being pre-empted by a
    TimeoutError.
    """
    override = os.environ.get("GCU_TIME_BUDGET_S")
    if override is not None:
        return int(override)

    if n_ops and loaddata_time:
        # Mirrors test_apply_patch_perf.py:216-217 -- the safety multiplier
        # scales the per-move work only; fixed overhead is added un-scaled.
        budget = int(SCALING_MIN_OVERHEAD_S +
                     n_ops * SCALING_LOADS_PER_MOVE * loaddata_time *
                     SCALING_SAFETY_MULTIPLIER)
        basis = "platform-derived ({} ops, {:.3f}s/load)".format(
            n_ops, loaddata_time)
    else:
        budget = max(BUDGET_FLOOR_S, PER_MOR_BUDGET_S * int(n_mors))
        basis = "legacy per-MOR constant (calibration unavailable)"

    if fuse_s:
        capped = min(budget, int(fuse_s) - FUSE_MARGIN_S)
        if capped < budget:
            logger.info("Budget %ds capped to %ds to stay under the "
                        "apply-patch fuse (%ds)", budget, capped, fuse_s)
        budget = capped

    logger.info("Time budget for N=%s: %ds [%s]", n_mors, budget, basis)
    return budget


# loadData cost is a property of (device, namespace) and is stable across a
# run, so measure it once rather than per parametrization.
_LOADDATA_CACHE = {}


def _get_loaddata_time(duthost, namespace):
    """Memoised _measure_loaddata_baseline, falling back when unmeasurable."""
    key = (duthost.hostname, namespace)
    if key not in _LOADDATA_CACHE:
        measured = _measure_loaddata_baseline(duthost, namespace)
        if measured is None:
            measured = FALLBACK_LOADDATA_TIME_S
            logger.warning("Using fallback loadData cost %.1fs for %s",
                           measured, key)
        elif measured < MIN_PLAUSIBLE_LOADDATA_S:
            # loadData() raising internally still exits the shell 0, so a
            # near-zero reading means "it did not really run", not "it is
            # fast".  Trusting it would produce a tiny budget and false
            # failures on a healthy apply.
            logger.warning(
                "loadData baseline %.4fs is implausibly small (<%.2fs); "
                "treating as a failed measurement and using fallback %.1fs",
                measured, MIN_PLAUSIBLE_LOADDATA_S, FALLBACK_LOADDATA_TIME_S)
            measured = FALLBACK_LOADDATA_TIME_S
        _LOADDATA_CACHE[key] = measured
    return _LOADDATA_CACHE[key]


def _is_transport_drop(exc):
    """True only for a transport / hardware-proxy drop, never a GCU rejection.

    Deliberately narrow.  Classifying on free-form exception text is fragile,
    so a failed assertion -- which is what expect_op_success raises when GCU
    ran and reported failure -- is never treated as a transport drop,
    regardless of wording.  Note that expect_op_success goes through
    pytest_assert, so the exception is pytest's ``Failed``, not AssertionError;
    both are excluded.  Anything unrecognised defaults to a real failure.
    """
    if isinstance(exc, (AssertionError, pytest.fail.Exception)):
        return False
    lowered = repr(exc).lower()
    return ("connectiondroppedbydevice" in lowered or
            "hardware proxy" in lowered or
            "hwproxy" in lowered)


def _dut_side_elapsed_s(output):
    """Exact DUT-side duration of the apply-patch command, or None.

    gu_utils.apply_patch() runs 'config apply-patch' via Ansible with
    module_async=True and polls async_result.ready() on a 10-second interval.
    A wall-clock measurement taken around that call is therefore quantised to
    ~10s, which is coarser than the whole per-MOR cost we are trying to
    measure: a real slope of ~0.4s/MOR is completely invisible between N=1 and
    N=5.  Ansible's command/shell module reports the command's own duration in
    'delta' (verified present in the async result, accurate to ~5ms), so use
    that as the measurement and keep wall clock only as a fallback.

    Note the result is a pytest_ansible ModuleResult, which is mapping-like but
    is NOT a dict subclass -- hence duck typing rather than isinstance().
    """
    try:
        delta = output["delta"]
    except (TypeError, KeyError, IndexError):
        return None
    if not delta:
        return None
    try:
        hours, minutes, seconds = str(delta).split(":")
        return int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    except (ValueError, TypeError):
        logger.warning("could not parse apply-patch delta %r", delta)
        return None


# GCU prints the sorter's verdict on stdout, e.g.
#   "Patch Applier: The asic0 patch was converted into 26 changes:"
# Note the terminator: generic_updater.py uses ':' when the count is non-zero
# (it introduces the list of changes) and '.' only when it is zero.
# The change count is the hardware-independent measure of how much work the
# patch actually costs: the GCU performance work this test guards collapses
# the change count rather than making each change cheaper, so a regression
# shows up here even on a box whose absolute timings differ.
_CHANGES_RE = re.compile(
    r"The (\S+) patch was converted into (\d+) changes?[.:]")


def _sorter_change_counts(output):
    """Map namespace -> number of changes the sorter emitted, from stdout."""
    try:
        stdout = output["stdout"]
    except (TypeError, KeyError, IndexError):
        return {}
    if not stdout:
        return {}
    counts = {ns: int(count) for ns, count in _CHANGES_RE.findall(str(stdout))}
    if not counts:
        logger.debug("no sorter change counts in apply-patch stdout: %s",
                     str(stdout)[:4000])
    return counts


SCALING_CHECKPOINT = "gcu_scaling"


def _is_internal_port_scaling(port_name):
    """Backplane/internal ports never make up a MOR."""
    return (port_name.startswith("Ethernet-BP") or
            port_name.startswith("Ethernet-IB") or
            port_name.startswith("Ethernet-Rec"))


def _select_n_mors(config_facts, n):
    """Pick N external PortChannels from config_facts.

    Returns a dict:
        {
          "portchannels": [pc_name, ...],
          "member_ports": [ethernet_name, ...],
          "bgp_neigh_ips": [ip_addr, ...],
          "device_neigh_names": [neighbor_name, ...],
        }

    Deterministic (alphabetical) selection so runs are comparable across GCU
    versions.  Raises ValueError if the ASIC has fewer than N external PCs.
    """
    pc_members = config_facts.get("PORTCHANNEL_MEMBER", {})
    device_neighbors = config_facts.get("DEVICE_NEIGHBOR", {})
    bgp_neighbors = config_facts.get("BGP_NEIGHBOR", {})

    external_pcs = [
        pc for pc, members in pc_members.items()
        if all(not _is_internal_port_scaling(p) for p in members.keys())
    ]
    if len(external_pcs) < n:
        raise ValueError(
            "ASIC has only {} external PortChannels; requested {}".format(
                len(external_pcs), n))

    selected_pcs = sorted(external_pcs)[:n]
    member_ports = []
    for pc in selected_pcs:
        member_ports.extend(pc_members[pc].keys())

    # Dedupe: multiple member ports on the same PortChannel share one peer
    # (e.g., Ethernet0+Ethernet8 -> ARISTA01T1). Emitting the same remove op
    # twice trips GCU YANG validation ("can't remove a non-existent object").
    seen = set()
    device_neigh_names = []
    for p in member_ports:
        if p not in device_neighbors:
            continue
        name = device_neighbors[p].get("name")
        if name and name not in seen:
            seen.add(name)
            device_neigh_names.append(name)
    bgp_neigh_ips = [
        ip for ip, cfg in bgp_neighbors.items()
        if cfg.get("name") in device_neigh_names
    ]
    return {
        "portchannels": selected_pcs,
        "member_ports": member_ports,
        "bgp_neigh_ips": bgp_neigh_ips,
        "device_neigh_names": device_neigh_names,
    }


def _verify_bgp_up_scaling(duthost, namespace, bgp_neigh_ips, timeout=180):
    """Poll until every peer in *bgp_neigh_ips* reports state ``established``.

    Address-family agnostic.  ``_select_n_mors`` picks BGP_NEIGHBOR entries by
    neighbour *name*, which on a dual-stack T2 returns BOTH the IPv4 and the
    IPv6 peer for each neighbour.  An earlier implementation parsed only
    ``show ip bgp summary``; IPv6 peers can never appear there, so they stayed
    permanently un-established and the poll burned its full timeout on every
    healthy run.

    ``bgp_facts`` drives ``show ip bgp neighbors``, whose ``BGP neighbor is
    <addr>`` blocks cover every peer regardless of family (see
    ansible/library/bgp_facts.py -- it matches both regex_ipv4 and regex_ipv6),
    and reports a lower-cased ``state`` per peer.  One call, both families.

    Returns True on success; the caller decides whether to fail or just warn.

    Both sides are lower-cased before comparison: CONFIG_DB preserves the
    minigraph's spelling of an IPv6 neighbour (often upper-case hex, e.g.
    ``FC00::72``) while bgp_facts lower-cases every key it emits, so an exact
    match would never succeed on such a testbed and the poll would burn its
    full timeout while reporting healthy peers as down.  The repo's own
    helpers normalise for the same reason (see sonic_asic.py, multi_asic.py).
    """
    wanted = {ip.lower() for ip in bgp_neigh_ips}
    if not wanted:
        # Nothing to verify.  Callers must not treat this as "converged".
        return True

    asic = duthost.asic_instance_from_namespace(namespace)

    def _all_established():
        try:
            neighbors = asic.bgp_facts()["ansible_facts"]["bgp_neighbors"]
        except Exception as exc:
            # bgp_facts fails the module if vtysh is briefly unavailable
            # (e.g. bgp container still restarting).  Retry within timeout.
            logger.warning("bgp_facts unavailable, retrying: %r", exc)
            return False
        neighbors = {str(k).lower(): v for k, v in neighbors.items()}
        established = {ip for ip in wanted
                       if neighbors.get(ip, {}).get("state") == "established"}
        missing = wanted - established
        if missing:
            logger.debug("BGP not yet established: %s", sorted(missing))
        return not missing

    return wait_until(timeout, 10, 0, _all_established)


@pytest.fixture(scope="function")
def scaling_checkpoint(duthosts, enum_downstream_dut_hostname):
    """Per-test checkpoint + rollback so each parametrization starts clean."""
    duthost = duthosts[enum_downstream_dut_hostname]
    create_checkpoint(duthost, cp=SCALING_CHECKPOINT)
    yield SCALING_CHECKPOINT
    try:
        rollback_or_reload(duthost, cp=SCALING_CHECKPOINT)
    finally:
        delete_checkpoint(duthost, cp=SCALING_CHECKPOINT)


def _record_platform_metadata(duthost, config_facts, selection, record_property):
    """Emit per-run metadata so results can be sliced across platforms."""
    facts = duthost.facts or {}
    record_property("gcu_sonic_version",
                    facts.get("asic_type", "") + "/" + str(facts.get("num_asic", "")))
    try:
        img = duthost.shell("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version",
                            module_ignore_errors=True)["stdout"].strip()
        record_property("gcu_sonic_image", img)
    except Exception:
        # Best-effort metadata capture; a missing sonic_version.yml or
        # shell error shouldn't fail the scaling measurement itself.
        pass
    record_property("gcu_hwsku", facts.get("hwsku", ""))
    record_property("gcu_switch_type", facts.get("switch_type", ""))
    record_property("gcu_platform", facts.get("platform", ""))
    # PC composition: how many are single-port vs multi-port among selected.
    pc_members = config_facts.get("PORTCHANNEL_MEMBER", {})
    single = sum(1 for pc in selection["portchannels"]
                 if len(pc_members.get(pc, {})) == 1)
    multi = len(selection["portchannels"]) - single
    record_property("gcu_pc_single_port", single)
    record_property("gcu_pc_multi_port", multi)


def _cli_remove_selected_mors(duthost, selection, namespace):
    """Surgically delete ONLY the N selected MORs from CONFIG_DB via
    ``sonic-db-cli del`` (no wildcards, no YANG-cascade risk, no reliance
    on existing helpers).

    Order matters: children (BGP_NEIGHBOR, DEVICE_NEIGHBOR) before parent
    (DEVICE_NEIGHBOR_METADATA); PORTCHANNEL_INTERFACE and PORTCHANNEL_MEMBER
    before PORTCHANNEL.  Both asic-namespace and localhost tables are cleaned.
    ``module_ignore_errors=True`` because some entries may exist on only one
    side (asic vs localhost) or may have been auto-removed by prior ops.

    Scope note (INTERFACE table): this test targets ``PORTCHANNEL``-based
    MORs on T2/lt2 topologies, where port members are grouped under
    ``PORTCHANNEL_INTERFACE`` — not ``INTERFACE`` (which is used for
    L3-on-port designs).  We therefore deliberately do not strip
    ``INTERFACE|{port}`` entries.  The rollback fixture undoes any stray
    state at teardown regardless.

    Persistence note: we intentionally do NOT ``config save`` after the
    CLI removals.  Persisting would defeat the ``config rollback`` in
    ``scaling_checkpoint`` teardown, which is the primary cleanup path.

    Safe by construction: our fixture takes a checkpoint before this runs
    and calls ``config rollback`` in teardown, so any intermediate state
    (including a partially-removed MOR if a command errors) is undone.
    """
    ns_flag = "" if namespace is None else "-n {}".format(namespace)
    failures = []

    def run(where, cmd, desc):
        """Run a delete and surface (but do not raise on) a non-zero rc.

        rc alone cannot prove a delete happened -- ``del`` of an absent key
        still returns 0, and the ``keys | xargs del`` pipelines return xargs'
        rc -- so failures collected here are advisory.  The authoritative gate
        is _verify_selected_mors_removed(), which checks the keys are actually
        gone before the timer starts.
        """
        logger.info("[%s] %s: %s", where, desc, cmd)
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res["rc"] != 0:
            logger.warning("[%s] delete returned rc=%s: %s\nstdout: %s\nstderr: %s",
                           where, res["rc"], cmd, res["stdout"], res["stderr"])
            failures.append((where, desc, res["rc"]))
        return res["rc"] == 0

    for ip in selection["bgp_neigh_ips"]:
        run("asic", "sudo sonic-db-cli {} CONFIG_DB del 'BGP_NEIGHBOR|{}'"
            .format(ns_flag, ip), "del BGP_NEIGHBOR " + ip)
        run("localhost", "sudo sonic-db-cli CONFIG_DB del 'BGP_NEIGHBOR|{}'"
            .format(ip), "del localhost BGP_NEIGHBOR " + ip)

    for port in selection["member_ports"]:
        run("asic", "sudo sonic-db-cli {} CONFIG_DB del 'DEVICE_NEIGHBOR|{}'"
            .format(ns_flag, port), "del DEVICE_NEIGHBOR " + port)
        run("localhost", "sudo sonic-db-cli CONFIG_DB del 'DEVICE_NEIGHBOR|{}'"
            .format(port), "del localhost DEVICE_NEIGHBOR " + port)

    for name in selection["device_neigh_names"]:
        run("asic",
            "sudo sonic-db-cli {} CONFIG_DB del 'DEVICE_NEIGHBOR_METADATA|{}'"
            .format(ns_flag, name),
            "del DEVICE_NEIGHBOR_METADATA " + name)
        run("localhost",
            "sudo sonic-db-cli CONFIG_DB del 'DEVICE_NEIGHBOR_METADATA|{}'"
            .format(name),
            "del localhost DEVICE_NEIGHBOR_METADATA " + name)

    for pc in selection["portchannels"]:
        # PORTCHANNEL_INTERFACE: both the bare PC key and the PC|ip compound
        # keys.  These are two separate deletes on purpose.  A single
        # 'PORTCHANNEL_INTERFACE|{pc}*' glob would be prefix-matched, not
        # delimiter-matched, so selecting PortChannel1 would also wipe
        # PortChannel10/PortChannel100's interface keys.  Those PCs are not in
        # our selection, so the add-patch never restores them and the
        # selected-only verifier never notices -- they would stay missing
        # until the checkpoint rollback at teardown.  Bound both forms by the
        # '|' delimiter instead: an exact key for the bare row, and a
        # '{pc}|*' glob for the IP rows.
        run("asic",
            "sudo sonic-db-cli {ns} CONFIG_DB del 'PORTCHANNEL_INTERFACE|{pc}'"
            .format(ns=ns_flag, pc=pc),
            "del PORTCHANNEL_INTERFACE " + pc)
        run("asic",
            "sudo sonic-db-cli {ns} CONFIG_DB keys 'PORTCHANNEL_INTERFACE|{pc}|*' "
            "| xargs -r -n1 sudo sonic-db-cli {ns} CONFIG_DB del"
            .format(ns=ns_flag, pc=pc),
            "del PORTCHANNEL_INTERFACE " + pc + "|*")
        run("localhost",
            "sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL_INTERFACE|{pc}'"
            .format(pc=pc),
            "del localhost PORTCHANNEL_INTERFACE " + pc)
        run("localhost",
            "sudo sonic-db-cli CONFIG_DB keys 'PORTCHANNEL_INTERFACE|{pc}|*' "
            "| xargs -r -n1 sudo sonic-db-cli CONFIG_DB del".format(pc=pc),
            "del localhost PORTCHANNEL_INTERFACE " + pc + "|*")

        # PORTCHANNEL_MEMBER: PC|Ethernet* keys.
        run("asic",
            "sudo sonic-db-cli {ns} CONFIG_DB keys 'PORTCHANNEL_MEMBER|{pc}|*' "
            "| xargs -r -n1 sudo sonic-db-cli {ns} CONFIG_DB del"
            .format(ns=ns_flag, pc=pc),
            "del PORTCHANNEL_MEMBER " + pc + "|*")
        run("localhost",
            "sudo sonic-db-cli CONFIG_DB keys 'PORTCHANNEL_MEMBER|{pc}|*' "
            "| xargs -r -n1 sudo sonic-db-cli CONFIG_DB del".format(pc=pc),
            "del localhost PORTCHANNEL_MEMBER " + pc + "|*")

        # PORTCHANNEL parent last.
        run("asic",
            "sudo sonic-db-cli {} CONFIG_DB del 'PORTCHANNEL|{}'"
            .format(ns_flag, pc), "del PORTCHANNEL " + pc)
        run("localhost",
            "sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL|{}'".format(pc),
            "del localhost PORTCHANNEL " + pc)

    # Per-port scalars (safe if absent). PORT stays — we do NOT delete PORT
    # entries; admin_status flipped to down instead so add-back can re-enable.
    for port in selection["member_ports"]:
        run("asic",
            "sudo sonic-db-cli {} CONFIG_DB del 'PORT_QOS_MAP|{}'"
            .format(ns_flag, port), "del PORT_QOS_MAP " + port)
        run("asic",
            "sudo sonic-db-cli {} CONFIG_DB hdel 'CABLE_LENGTH|AZURE' {}"
            .format(ns_flag, port), "hdel CABLE_LENGTH " + port)
        run("asic",
            "sudo sonic-db-cli {ns} CONFIG_DB keys 'BUFFER_PG|{p}|*' "
            "| xargs -r -n1 sudo sonic-db-cli {ns} CONFIG_DB del"
            .format(ns=ns_flag, p=port), "del BUFFER_PG " + port + "|*")
        run("asic",
            "sudo sonic-db-cli {} CONFIG_DB hset 'PORT|{}' admin_status down"
            .format(ns_flag, port), "admin_status down " + port)

    if failures:
        logger.warning("%d delete command(s) returned non-zero rc; "
                       "_verify_selected_mors_removed() will decide whether "
                       "this actually mattered: %s", len(failures), failures)
    return failures


def _verify_selected_mors_removed(duthost, selection, namespace,
                                  config_facts, config_facts_localhost,
                                  pc_refs=None):
    """Assert the selected MORs are really gone from CONFIG_DB.

    This runs AFTER _cli_remove_selected_mors and BEFORE the timer starts, and
    it is the precondition the whole measurement rests on.

    Why it is required: the restore patch uses RFC 6902 ``add``, and ``add`` on
    an already-present member is a replace/no-op rather than an error.  So if a
    delete silently failed, that part of the timed patch does no work and the
    run reports an artificially FAST time -- a wrong number, published as if it
    were valid.  Checking the keys are absent is the only sound gate: a
    ``del`` of a missing key still exits 0, and the ``keys | xargs del``
    pipelines report xargs' rc, so return codes prove nothing.

    Every condition checked here is *derived from the pre-removal snapshot*
    (``config_facts`` / ``config_facts_localhost``) rather than hardcoded, so
    the gate covers exactly what ``_build_scaling_add_patch`` will re-add and
    nothing more.  An entry that was already absent before setup ran is not
    required to be absent now -- it contributes no op to the timed patch, so
    it cannot understate the workload.

    ``pc_refs`` is the list returned by ``_scan_pc_references`` (the rows whose
    ``ports`` leaf-list references our PCs).  Those are restored by a
    ``replace`` op rather than an ``add``, but the no-op hazard is identical:
    replacing a list with the value it already holds costs nothing and silently
    shrinks the measured workload.  Pass it so the gate covers them too.

    Returns a list of leftover keys (empty when the removal was clean).
    """
    ns_flag = "" if namespace is None else "-n {}".format(namespace)

    def _run(cmd, what):
        out = duthost.shell(cmd, module_ignore_errors=True)
        if out["rc"] != 0:
            # Treat an unreadable DB as a hard problem rather than "clean".
            raise RuntimeError(
                "could not read {} (rc={}): {}".format(
                    what, out["rc"], out.get("stderr", "")))
        return out["stdout"]

    def _keys(pattern, scope="asic"):
        flag = ns_flag if scope == "asic" else ""
        out = _run("sudo sonic-db-cli {} CONFIG_DB keys '{}'".format(flag, pattern),
                   "CONFIG_DB keys '{}' ({})".format(pattern, scope))
        return {k.strip() for k in out.splitlines() if k.strip()}

    leftovers = []

    def _flag(key, scope="asic"):
        leftovers.append(key if scope == "asic" else "localhost:" + key)

    ports = list(selection["member_ports"])
    pcs = list(selection["portchannels"])
    dev_names = list(selection["device_neigh_names"])
    bgp_ips = list(selection["bgp_neigh_ips"])

    # ---- ASIC scope ----
    bgp_keys = _keys("BGP_NEIGHBOR|*")
    for ip in bgp_ips:
        key = "BGP_NEIGHBOR|{}".format(ip)
        if key in bgp_keys:
            _flag(key)

    dn_keys = _keys("DEVICE_NEIGHBOR|*")
    for port in ports:
        key = "DEVICE_NEIGHBOR|{}".format(port)
        if key in dn_keys:
            _flag(key)

    # DEVICE_NEIGHBOR_METADATA is a parent the patch re-adds per neighbour.
    dnm_keys = _keys("DEVICE_NEIGHBOR_METADATA|*")
    dnm_snap = config_facts.get("DEVICE_NEIGHBOR_METADATA", {})
    for name in dev_names:
        key = "DEVICE_NEIGHBOR_METADATA|{}".format(name)
        if name in dnm_snap and key in dnm_keys:
            _flag(key)

    pc_keys = _keys("PORTCHANNEL|*")
    pcm_keys = _keys("PORTCHANNEL_MEMBER|*")
    pci_keys = _keys("PORTCHANNEL_INTERFACE|*")
    for pc in pcs:
        if "PORTCHANNEL|{}".format(pc) in pc_keys:
            _flag("PORTCHANNEL|{}".format(pc))
        leftovers.extend(k for k in pcm_keys
                         if k.startswith("PORTCHANNEL_MEMBER|{}|".format(pc)))
        leftovers.extend(k for k in pci_keys
                         if k == "PORTCHANNEL_INTERFACE|{}".format(pc) or
                         k.startswith("PORTCHANNEL_INTERFACE|{}|".format(pc)))

    # Per-port scalars.  These scale with N and are all re-added by the timed
    # patch, so an un-removed one silently converts a timed add into a no-op.
    qos_keys = _keys("PORT_QOS_MAP|*")
    qos_snap = config_facts.get("PORT_QOS_MAP", {})
    for port in ports:
        key = "PORT_QOS_MAP|{}".format(port)
        if port in qos_snap and key in qos_keys:
            _flag(key)

    buf_keys = _keys("BUFFER_PG|*")
    buf_snap = config_facts.get("BUFFER_PG", {})
    for port in ports:
        for pg_range in buf_snap.get(port, {}):
            key = "BUFFER_PG|{}|{}".format(port, pg_range)
            if key in buf_keys:
                _flag(key)

    # CABLE_LENGTH is a single hash whose *fields* are per-port; Redis drops
    # the hash entirely once the last field goes, so an empty read is clean.
    cable_snap = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {})
    wanted_cable = [p for p in ports if p in cable_snap]
    if wanted_cable:
        cable_fields = {
            f.strip() for f in _run(
                "sudo sonic-db-cli {} CONFIG_DB hkeys 'CABLE_LENGTH|AZURE'"
                .format(ns_flag), "CABLE_LENGTH|AZURE fields").splitlines()
            if f.strip()}
        for port in wanted_cable:
            if port in cable_fields:
                _flag("CABLE_LENGTH|AZURE:{}".format(port))

    # PORT rows are never deleted -- admin_status is flipped down instead, and
    # the patch flips it back up.  If the flip did not take, that op is a
    # no-op, so the transition is part of the precondition.  One shell round
    # trip for all N ports.
    if ports:
        admin_out = _run(
            "for p in {ports}; do printf '%s=' \"$p\"; "
            "sudo sonic-db-cli {ns} CONFIG_DB hget \"PORT|$p\" admin_status; "
            "done".format(ports=" ".join(ports), ns=ns_flag),
            "PORT admin_status")
        admin = {}
        for line in admin_out.splitlines():
            if "=" in line:
                name, _, val = line.partition("=")
                admin[name.strip()] = val.strip()
        for port in ports:
            if admin.get(port) != "down":
                _flag("PORT|{}:admin_status={}".format(
                    port, admin.get(port) or "<unset>"))

    # ---- localhost scope ----
    # The patch re-adds localhost rows too (conditioned on the localhost
    # snapshot), so the same no-op hazard applies there.  Gated on snapshot
    # presence: entries that legitimately never existed are not required.
    local = config_facts_localhost or {}
    if local:
        l_bgp = _keys("BGP_NEIGHBOR|*", scope="localhost")
        for ip in bgp_ips:
            key = "BGP_NEIGHBOR|{}".format(ip)
            if ip in local.get("BGP_NEIGHBOR", {}) and key in l_bgp:
                _flag(key, scope="localhost")

        l_dn = _keys("DEVICE_NEIGHBOR|*", scope="localhost")
        for port in ports:
            key = "DEVICE_NEIGHBOR|{}".format(port)
            if port in local.get("DEVICE_NEIGHBOR", {}) and key in l_dn:
                _flag(key, scope="localhost")

        l_dnm = _keys("DEVICE_NEIGHBOR_METADATA|*", scope="localhost")
        for name in dev_names:
            key = "DEVICE_NEIGHBOR_METADATA|{}".format(name)
            if (name in local.get("DEVICE_NEIGHBOR_METADATA", {}) and
                    key in l_dnm):
                _flag(key, scope="localhost")

    # localhost PortChannel tables are deleted unconditionally during setup
    # and re-added unconditionally by the patch, so absence is required
    # regardless of the snapshot.  A row that never existed is absent anyway,
    # so this cannot produce a false positive.
    l_pc = _keys("PORTCHANNEL|*", scope="localhost")
    l_pcm = _keys("PORTCHANNEL_MEMBER|*", scope="localhost")
    l_pci = _keys("PORTCHANNEL_INTERFACE|*", scope="localhost")
    for pc in pcs:
        if "PORTCHANNEL|{}".format(pc) in l_pc:
            _flag("PORTCHANNEL|{}".format(pc), scope="localhost")
        for k in l_pcm:
            if k.startswith("PORTCHANNEL_MEMBER|{}|".format(pc)):
                _flag(k, scope="localhost")
        for k in l_pci:
            if (k == "PORTCHANNEL_INTERFACE|{}".format(pc) or
                    k.startswith("PORTCHANNEL_INTERFACE|{}|".format(pc))):
                _flag(k, scope="localhost")

    # ---- ports leaf-list referrers (ACL_TABLE / PBH_TABLE / MIRROR_SESSION) ----
    # _cli_remove_pc_references strips our PCs out of each referring row's
    # ``ports`` leaf-list, and _build_scaling_add_patch puts them back with a
    # ``replace`` carrying the ORIGINAL list.  If a strip silently failed the
    # replace rewrites the value that is already there, so that op is a no-op
    # and the measurement is understated -- the same hazard the table checks
    # above guard against.  The referrer count does not scale with N (it is a
    # handful of fixed ACL rows), so at low N it is a large share of the ops:
    # on a T2 LC it is 6 of the 36 ops at N=1.  Redis stores the leaf-list in
    # the ``ports@`` field as a comma-separated string.
    for ref in (pc_refs or []):
        scope = ref["scope"]
        flag = ns_flag if scope == "asic" else ""
        rowkey = "{}|{}".format(ref["table"], ref["key"])
        raw = _run(
            "sudo sonic-db-cli {} CONFIG_DB hget '{}' 'ports@'".format(
                flag, rowkey),
            "{} ports@ ({})".format(rowkey, scope))
        current = {p.strip() for p in raw.split(",") if p.strip()}
        for pc in pcs:
            if pc in current:
                _flag("{}:ports@ still lists {}".format(rowkey, pc),
                      scope=scope)

    if leftovers:
        logger.error("Removal incomplete -- %d condition(s) unmet: %s",
                     len(leftovers), sorted(leftovers))
    else:
        logger.info("Removal verified: every snapshot-derived precondition "
                    "for the timed patch is satisfied")
    return leftovers


def _probe_parent_tables_present(duthost, namespace):
    """After ``_cli_remove_selected_mors`` runs, probe the DUT to see
    whether the parent hashes we restore in ``_build_scaling_add_patch``
    still exist on the asic namespace.

    Redis auto-deletes a hash key when its last field is removed, so if
    our per-port ``hdel``/``del`` cleared out every entry, the parent
    key is gone.  ``jsonpatch`` (RFC 6902) refuses to path into a
    missing intermediate — ``add /CABLE_LENGTH/AZURE/EthernetX`` on an
    empty/missing ``CABLE_LENGTH`` raises ``member 'AZURE' not found
    in {}``.  We use this snapshot to prepend defensive ``add
    /parent = {}`` ops only when the parent is actually gone.

    Returns a dict:
        {"cable_azure": bool,  # CABLE_LENGTH|AZURE key exists
         "port_qos_map": bool, # any PORT_QOS_MAP|* keys exist
         "buffer_pg":    bool} # any BUFFER_PG|* keys exist
    """
    if namespace is None:
        ns_flag = ""
    else:
        ns_flag = "-n " + namespace

    def _exists(pattern):
        cmd = ("sudo sonic-db-cli {} CONFIG_DB keys '{}' | head -n1"
               .format(ns_flag, pattern))
        out = duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip()
        return bool(out)

    return {
        "cable_azure":  _exists("CABLE_LENGTH|AZURE"),
        "port_qos_map": _exists("PORT_QOS_MAP|*"),
        "buffer_pg":    _exists("BUFFER_PG|*"),
    }


def _scan_pc_references(config_facts, config_facts_localhost, pcs):
    """Scan config for tables whose entries carry a ``ports`` leaf-list
    that references one or more of our selected PortChannels.

    Real-world referrers: ACL_TABLE.ports (localhost, and sometimes
    per-asic), PBH_TABLE.ports, MIRROR_SESSION.ports, etc.  YANG treats
    those as leafrefs to PORTCHANNEL_LIST/PORT_LIST, so any entry that
    still references a PC we've removed becomes dangling and blocks the
    re-add patch with ``Invalid value "PortChannelXXX" in "ports"
    element``.

    Returns a list of dicts:
        {"scope": "asic"|"localhost",
         "table": "<TABLE_NAME>",
         "key":   "<row_key>",
         "orig":  [<full port list>],
         "trimmed": [<same list minus our PCs>],
         "removed": [<our PCs that were present>]}
    """
    pc_set = set(pcs)
    refs = []
    for scope, cf in (("asic", config_facts), ("localhost", config_facts_localhost)):
        if not isinstance(cf, dict):
            continue
        for table, entries in cf.items():
            if not isinstance(entries, dict):
                continue
            for key, val in entries.items():
                if not isinstance(val, dict):
                    continue
                port_list = val.get("ports")
                if not isinstance(port_list, list):
                    continue
                hit = [p for p in port_list if p in pc_set]
                if not hit:
                    continue
                refs.append({
                    "scope": scope,
                    "table": table,
                    "key": key,
                    "orig": list(port_list),
                    "trimmed": [p for p in port_list if p not in pc_set],
                    "removed": hit,
                })
    return refs


def _cli_remove_pc_references(duthost, refs, namespace):
    """Strip our selected PCs from every ``ports@`` list captured by
    ``_scan_pc_references``.  Uses ``sonic-db-cli hset`` with the redis
    leaf-list encoding (``ports@`` = comma-joined values).

    Untimed setup step; ``module_ignore_errors=True`` because the
    checkpoint-based rollback in teardown covers any partial state.
    """
    ns_flag = "" if namespace is None else "-n {}".format(namespace)
    for ref in refs:
        scope_flag = ns_flag if ref["scope"] == "asic" else ""
        joined = ",".join(ref["trimmed"])
        redis_key = "{table}|{key}".format(table=ref["table"], key=ref["key"])
        # Write the trimmed leaf-list back.  If trimmed is empty we still
        # write empty string — YANG will accept an empty ports list on the
        # referrer as long as its own presence constraints allow it.
        cmd = ("sudo sonic-db-cli {scope} CONFIG_DB hset '{k}' 'ports@' '{v}'"
               .format(scope=scope_flag, k=redis_key, v=joined))
        logger.info("[%s] strip PC refs from %s|%s: removed=%s",
                    ref["scope"], ref["table"], ref["key"], ref["removed"])
        duthost.shell(cmd, module_ignore_errors=True)


def _build_scaling_add_patch(config_facts, config_facts_localhost, mg_facts,
                             selection, namespace, pc_refs=None,
                             parents_present=None):
    """Build an INCREMENTAL add patch that re-inserts our N selected MORs.

    Uses per-key paths (``add /asic0/PORTCHANNEL/PortChannel121 {..}``)
    rather than bulk table-level replace (``add /asic0/PORTCHANNEL {..}``)
    so we don't accidentally clobber the other 20+ PortChannels already
    in the ASIC config.  That bulk-replace pattern is what
    ``apply_patch_add_cluster()`` does (it was designed for add-from-empty
    in the reverse of test_add_cluster's teardown), and it triggered
    leafref-validation failures on our incremental scenario.

    Ordering: parents before children within each table family, and
    tables ordered so leafref targets exist before referencing entries:
        PORTCHANNEL -> PORTCHANNEL_MEMBER -> PORTCHANNEL_INTERFACE
        port scalars restore (CABLE_LENGTH, PORT_QOS_MAP, BUFFER_PG,
                              admin_status)
        DEVICE_NEIGHBOR_METADATA -> DEVICE_NEIGHBOR -> BGP_NEIGHBOR
    """
    ns = "" if namespace is None else "/" + namespace
    port_alias = mg_facts.get("minigraph_port_name_to_alias_map", {})

    pcs = selection["portchannels"]
    ports = selection["member_ports"]
    bgp_ips = selection["bgp_neigh_ips"]
    dev_names = selection["device_neigh_names"]

    pc_table = config_facts.get("PORTCHANNEL", {})
    pc_intf = config_facts.get("PORTCHANNEL_INTERFACE", {})
    pc_members = config_facts.get("PORTCHANNEL_MEMBER", {})
    dev_neigh = config_facts.get("DEVICE_NEIGHBOR", {})
    dev_meta = config_facts.get("DEVICE_NEIGHBOR_METADATA", {})
    bgp_neigh = config_facts.get("BGP_NEIGHBOR", {})
    cable = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {})
    qos = config_facts.get("PORT_QOS_MAP", {})
    buf_pg = config_facts.get("BUFFER_PG", {})

    dev_meta_local = config_facts_localhost.get("DEVICE_NEIGHBOR_METADATA", {})
    dev_neigh_local = config_facts_localhost.get("DEVICE_NEIGHBOR", {})
    bgp_local = config_facts_localhost.get("BGP_NEIGHBOR", {})
    pc_intf_local = config_facts_localhost.get("PORTCHANNEL_INTERFACE", {})

    patch = []

    # PORTCHANNEL (parent) per-key add
    for pc in pcs:
        val = pc_table.get(pc, {})
        # PORTCHANNEL entries in config_facts include a "members" list we
        # don't want on the wire (real config has it as a separate table).
        clean = {k: v for k, v in val.items() if k != "members"}
        patch.append({"op": "add",
                      "path": f"{ns}/PORTCHANNEL/{pc}", "value": clean})
        patch.append({"op": "add",
                      "path": f"/localhost/PORTCHANNEL/{pc}", "value": clean})

    # PORTCHANNEL_MEMBER (references PORTCHANNEL parent)
    for pc in pcs:
        for member, mval in pc_members.get(pc, {}).items():
            alias = port_alias.get(member, member).replace("/", "~1")
            patch.append({
                "op": "add",
                "path": f"{ns}/PORTCHANNEL_MEMBER/{pc}|{member}",
                "value": mval if isinstance(mval, dict) else {},
            })
            patch.append({
                "op": "add",
                "path": f"/localhost/PORTCHANNEL_MEMBER/{pc}|{alias}",
                "value": mval if isinstance(mval, dict) else {},
            })

    # PORTCHANNEL_INTERFACE (bare key first, then IP subkeys)
    for pc in pcs:
        entry = pc_intf.get(pc, {})
        # bare key with empty value (or entry-level fields if any non-IP keys)
        patch.append({"op": "add",
                      "path": f"{ns}/PORTCHANNEL_INTERFACE/{pc}", "value": {}})
        if pc in pc_intf_local or pc_intf.get(pc):
            patch.append({"op": "add",
                          "path": f"/localhost/PORTCHANNEL_INTERFACE/{pc}",
                          "value": {}})
        if isinstance(entry, dict):
            for ip_key, ip_val in entry.items():
                escaped = ip_key.replace("/", "~1")
                patch.append({
                    "op": "add",
                    "path": f"{ns}/PORTCHANNEL_INTERFACE/{pc}|{escaped}",
                    "value": ip_val if isinstance(ip_val, dict) else {},
                })
                patch.append({
                    "op": "add",
                    "path": f"/localhost/PORTCHANNEL_INTERFACE/{pc}|{escaped}",
                    "value": ip_val if isinstance(ip_val, dict) else {},
                })

    # Restore per-port scalars removed by _cli_remove_selected_mors.
    # These use "add" rather than "replace": the keys may or may not still
    # exist, depending on whether the surgical remove actually deleted them
    # (which is namespace-dependent).  RFC 6902 "replace" requires the
    # target to already exist, whereas "add" overwrites it if present.
    #
    # Empty-parent guard: our per-port ``hdel``/``del`` in
    # _cli_remove_selected_mors can empty the parent hash entirely
    # (CABLE_LENGTH|AZURE, PORT_QOS_MAP|*, BUFFER_PG|*), in which case Redis
    # auto-deletes the key and the parent path disappears from
    # ``show runningconfiguration all``.  jsonpatch
    # (RFC 6902) then refuses ``add /CABLE_LENGTH/AZURE/EthernetX`` with
    # ``member 'AZURE' not found in {}``.  When ``parents_present`` tells
    # us the parent is gone, prepend a defensive ``add /parent = {}`` op.
    # We only emit these when actually missing — an ``add`` on an existing
    # object member REPLACES it, which would clobber unrelated entries.
    if parents_present is not None:
        if not parents_present.get("cable_azure", True):
            patch.append({"op": "add",
                          "path": f"{ns}/CABLE_LENGTH",
                          "value": {"AZURE": {}}})
        if not parents_present.get("port_qos_map", True):
            patch.append({"op": "add",
                          "path": f"{ns}/PORT_QOS_MAP",
                          "value": {}})
        if not parents_present.get("buffer_pg", True):
            patch.append({"op": "add",
                          "path": f"{ns}/BUFFER_PG",
                          "value": {}})

    for port in ports:
        if port in cable:
            patch.append({
                "op": "add",
                "path": f"{ns}/CABLE_LENGTH/AZURE/{port}",
                "value": cable[port],
            })
        if port in qos:
            patch.append({
                "op": "add",
                "path": f"{ns}/PORT_QOS_MAP/{port}",
                "value": qos[port],
            })
        for pg_range, pg_val in buf_pg.get(port, {}).items():
            patch.append({
                "op": "add",
                "path": f"{ns}/BUFFER_PG/{port}|{pg_range}",
                "value": pg_val if isinstance(pg_val, dict) else {},
            })
        # Flip admin_status back to up.
        patch.append({"op": "replace",
                      "path": f"{ns}/PORT/{port}/admin_status",
                      "value": "up"})

    # DEVICE_NEIGHBOR_METADATA (parent) - both asic and localhost.
    for name in dev_names:
        if name in dev_meta:
            patch.append({
                "op": "add",
                "path": f"{ns}/DEVICE_NEIGHBOR_METADATA/{name}",
                "value": dev_meta[name],
            })
        if name in dev_meta_local:
            patch.append({
                "op": "add",
                "path": f"/localhost/DEVICE_NEIGHBOR_METADATA/{name}",
                "value": dev_meta_local[name],
            })

    # DEVICE_NEIGHBOR (child references METADATA)
    for port in ports:
        if port in dev_neigh:
            patch.append({
                "op": "add",
                "path": f"{ns}/DEVICE_NEIGHBOR/{port}",
                "value": dev_neigh[port],
            })
        if port in dev_neigh_local:
            patch.append({
                "op": "add",
                "path": f"/localhost/DEVICE_NEIGHBOR/{port}",
                "value": dev_neigh_local[port],
            })

    # BGP_NEIGHBOR (child references METADATA)
    for ip in bgp_ips:
        if ip in bgp_neigh:
            patch.append({"op": "add",
                          "path": f"{ns}/BGP_NEIGHBOR/{ip}",
                          "value": bgp_neigh[ip]})
        if ip in bgp_local:
            patch.append({"op": "add",
                          "path": f"/localhost/BGP_NEIGHBOR/{ip}",
                          "value": bgp_local[ip]})

    # Restore referrer ``ports`` leaf-lists.  These were stripped in
    # ``_cli_remove_pc_references`` during untimed setup so the surgical
    # PORTCHANNEL remove wouldn't leave dangling leafrefs.  We now put
    # our PCs back into every referring row so its ``ports`` list matches
    # the pre-test state.  ``replace`` (not ``add``) because the row
    # itself already exists.
    for ref in (pc_refs or []):
        scope_prefix = ns if ref["scope"] == "asic" else "/localhost"
        patch.append({
            "op": "replace",
            "path": f"{scope_prefix}/{ref['table']}/{ref['key']}/ports",
            "value": ref["orig"],
        })

    return patch


def _run_scaling_measurement(duthost, tbinfo, config_facts, config_facts_localhost,
                             mg_facts, enum_rand_one_asic_namespace, n_mors,
                             record_property):
    """Core measurement: remove N MORs, time the add-back, verify, cleanup.

    Returns dict with keys:
        selection, apply_elapsed_s, e2e_elapsed_s, success, hwproxy_to,
        bgp_up, ns_label
    Raises pytest.skip for unsupported topologies / insufficient PCs.
    """
    if not duthost.get_facts().get("modular_chassis"):
        pytest.skip("Scaling test only runs on modular chassis")
    if tbinfo["topo"]["type"] not in ("t2", "lt2"):
        pytest.skip("Scaling test only runs on t2 / lt2 topology")
    switch_type = duthost.facts.get("switch_type")
    if switch_type not in ("voq", "chassis-packet"):
        pytest.skip("Unsupported switch_type={}".format(switch_type))

    selection = None
    try:
        selection = _select_n_mors(config_facts, n_mors)
    except ValueError as exc:
        pytest.skip(str(exc))

    ns_label = enum_rand_one_asic_namespace or "host"
    logger.info("Scaling: n=%d ns=%s pcs=%s",
                n_mors, ns_label, selection["portchannels"])

    _record_platform_metadata(duthost, config_facts, selection, record_property)

    # ---- Setup: targeted remove of N MORs (untimed) ----
    # Surgical CLI-based removal: only touches our N selected MORs, no
    # wildcards on whole tables. GCU/JSON-patch remove was tried first but
    # hit YANG cascade-delete edge cases ("can't remove a non-existent
    # object"); the existing remove_cluster_via_sonic_db_cli helper was
    # rejected because it wildcard-deletes the whole ASIC.  Our fixture
    # rolls back via `config rollback` regardless of intermediate state.
    remove_failures = _cli_remove_selected_mors(
        duthost, selection, enum_rand_one_asic_namespace)

    # Also strip our PCs from any referrer's ``ports`` leaf-list (ACL_TABLE,
    # PBH_TABLE, MIRROR_SESSION, etc.) so the incremental ADD patch below
    # doesn't hit ``Invalid value "PortChannelXXX" in "ports" element``.
    pc_refs = _scan_pc_references(config_facts, config_facts_localhost,
                                  selection["portchannels"])
    if pc_refs:
        logger.info("Found %d ports-referrer rows to strip: %s",
                    len(pc_refs),
                    [(r["scope"], r["table"], r["key"]) for r in pc_refs])
        _cli_remove_pc_references(duthost, pc_refs, enum_rand_one_asic_namespace)

    # Precondition for a valid measurement: what we are about to time the
    # re-add of must actually be gone.  If a delete silently failed, the
    # corresponding RFC 6902 ``add`` becomes a no-op and the run reports an
    # artificially fast time.  See _verify_selected_mors_removed.
    leftovers = _verify_selected_mors_removed(
        duthost, selection, enum_rand_one_asic_namespace,
        config_facts, config_facts_localhost, pc_refs)
    pytest_assert(
        not leftovers,
        "Setup incomplete: {} precondition(s) unmet, so part of the timed "
        "patch would be a no-op and the measurement would be invalid. "
        "Unmet: {}{}".format(
            len(leftovers), sorted(leftovers),
            "" if not remove_failures else
            " | non-zero rc from {} removal command(s): {}".format(
                len(remove_failures), remove_failures)))
    if remove_failures:
        # Verification passed, so these did not affect the measurement, but
        # they are still worth surfacing rather than discarding.
        logger.warning(
            "%d removal command(s) returned non-zero rc yet every "
            "precondition is satisfied; treating as benign: %s",
            len(remove_failures), remove_failures)

    # Empty-parent guard: snapshot which parent hashes survived the CLI
    # removal.  If a parent (CABLE_LENGTH|AZURE, PORT_QOS_MAP|*,
    # BUFFER_PG|*) is empty post-removal, Redis has auto-deleted it and an
    # RFC-6902 add into its child path will fail.  _build_scaling_add_patch
    # uses this to prepend defensive parent-add ops only when needed.
    parents_present = _probe_parent_tables_present(
        duthost, enum_rand_one_asic_namespace)
    logger.info("Scaling parent-table probe: %s", parents_present)

    # ---- Timed: incremental add-patch built from selection ----
    add_patch = _build_scaling_add_patch(config_facts, config_facts_localhost,
                                         mg_facts, selection,
                                         enum_rand_one_asic_namespace,
                                         pc_refs=pc_refs,
                                         parents_present=parents_present)
    n_ops = len(add_patch)
    logger.info("Scaling add patch: %d ops for n=%d",
                n_ops, len(selection["portchannels"]))

    # apply_patch() fuses on a per-platform timeout (gu_utils.get_gcu_timeout).
    # If this patch cannot finish inside the fuse the run cannot yield a valid
    # number: it would abort mid-apply and -- before this change -- was
    # silently reported as a pass.  Skip explicitly, naming the reason.
    #
    # The feasibility estimate deliberately does NOT reuse the op-count model
    # used for the budget.  That model treats every patch op as a sorter move
    # needing its own validation loads, which is a safe OVER-estimate for a
    # ceiling but far too pessimistic as a gate: it would skip N values that
    # are known to complete (e.g. N=14 measured at ~840s would be predicted at
    # ~2300s and skipped).  Feasibility therefore uses the per-MOR cost
    # observed on real runs; the op-count model stays where over-estimating is
    # harmless.
    fuse_s = get_gcu_timeout(duthost)
    loaddata_time = _get_loaddata_time(duthost, enum_rand_one_asic_namespace)
    predicted_s = _predicted_elapsed_s(n_ops, loaddata_time)
    feasibility_s = max(BUDGET_FLOOR_S, PER_MOR_BUDGET_S * int(n_mors))
    logger.info("N=%s: %d ops, loadData %.3fs -> budget model ~%.0fs; "
                "empirical feasibility estimate ~%ds; platform fuse %ds",
                n_mors, n_ops, loaddata_time, predicted_s, feasibility_s,
                fuse_s)
    if feasibility_s > fuse_s - FUSE_MARGIN_S:
        pytest.skip(
            "N={} is not measurable on {}: needs ~{}s (observed {}s/MOR) but "
            "apply-patch fuses at {}s".format(
                n_mors, duthost.facts.get("platform"), feasibility_s,
                PER_MOR_BUDGET_S, fuse_s))

    tmpfile = generate_tmpfile(duthost)
    apply_start = time.time()
    success = False
    hwproxy_to = False
    fuse_tripped = False
    failure_repr = None
    output = None
    try:
        output = apply_patch(duthost, json_data=add_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        success = True
    except TimeoutError as exc:
        # apply_patch's own fuse.  This is NOT a transport problem: it means
        # GCU did not finish within what this platform allows, which is
        # precisely the regression this test exists to catch.  It must never
        # be reported as a pass.
        fuse_tripped = True
        failure_repr = repr(exc)
        logger.error("apply_patch fuse fired after ~%ds: %r", fuse_s, exc)
    except (Exception, pytest.fail.Exception) as exc:
        # pytest.fail.Exception (Failed) derives from BaseException, not
        # Exception, so it must be named explicitly: expect_op_success reports
        # a GCU rejection via pytest_assert, and without this the most common
        # real failure would bypass this handler entirely, leaving success and
        # failure_repr unset and skipping every record_property below.
        # pytest.skip.Exception is deliberately NOT caught.
        failure_repr = repr(exc)
        if _is_transport_drop(exc):
            hwproxy_to = True
        logger.error("add_cluster failed: %r", exc)
    finally:
        # Stop the clock before cleanup: removing the temp file is a separate
        # SSH round-trip and is not part of what apply-patch costs.
        apply_wall_elapsed_s = time.time() - apply_start
        delete_tmpfile(duthost, tmpfile)

    # Prefer the DUT-reported duration: the wall-clock figure also contains the
    # patch-file copy and is rounded up to apply_patch()'s 10s poll interval.
    dut_elapsed_s = _dut_side_elapsed_s(output)
    if dut_elapsed_s is None:
        apply_elapsed_s = apply_wall_elapsed_s
        timing_source = "wall_clock"
    else:
        apply_elapsed_s = dut_elapsed_s
        timing_source = "dut_delta"
    change_counts = _sorter_change_counts(output)
    n_changes = sum(change_counts.values()) if change_counts else None
    logger.info(
        "apply-patch timing: source=%s dut=%s wall=%.3fs changes=%s",
        timing_source,
        "n/a" if dut_elapsed_s is None else "{:.3f}s".format(dut_elapsed_s),
        apply_wall_elapsed_s,
        change_counts or "n/a")

    # ---- BGP convergence: recorded for information, never gates the budget.
    # The budget is calibrated on apply-patch cost, so gating on a number that
    # also contains convergence time would not be comparing like with like.
    bgp_up = False
    bgp_checked = bool(success and selection["bgp_neigh_ips"])
    if bgp_checked:
        bgp_up = _verify_bgp_up_scaling(
            duthost, enum_rand_one_asic_namespace, selection["bgp_neigh_ips"])
    e2e_elapsed_s = time.time() - apply_start

    return {
        "selection": selection,
        "ns_label": ns_label,
        "apply_elapsed_s": apply_elapsed_s,
        "apply_wall_elapsed_s": apply_wall_elapsed_s,
        "timing_source": timing_source,
        "change_counts": change_counts,
        "n_changes": n_changes,
        "e2e_elapsed_s": e2e_elapsed_s,
        "success": success,
        "hwproxy_to": hwproxy_to,
        "fuse_tripped": fuse_tripped,
        "failure_repr": failure_repr,
        "bgp_up": bgp_up,
        "bgp_checked": bgp_checked,
        "n_ops": n_ops,
        "loaddata_time": loaddata_time,
        "predicted_s": predicted_s,
        "feasibility_s": feasibility_s,
        "fuse_s": fuse_s,
    }


@pytest.mark.gcu_scaling_nightly
@pytest.mark.parametrize("n_mors", NIGHTLY_MOR_COUNTS)
def test_add_mor_scaling_nightly(
    tbinfo, duthosts, enum_downstream_dut_hostname,
    enum_rand_one_asic_namespace, config_facts, config_facts_localhost,
    mg_facts, scaling_checkpoint, record_property, n_mors,
):
    """Nightly Add-MOR scaling measurement. See NIGHTLY_MOR_COUNTS."""
    duthost = duthosts[enum_downstream_dut_hostname]
    _run_and_publish(duthost, tbinfo, config_facts, config_facts_localhost,
                     mg_facts, enum_rand_one_asic_namespace, n_mors,
                     "nightly", record_property)


@pytest.mark.gcu_scaling_weekly
@pytest.mark.parametrize("n_mors", WEEKLY_MOR_COUNTS)
def test_add_mor_scaling_weekly(
    tbinfo, duthosts, enum_downstream_dut_hostname,
    enum_rand_one_asic_namespace, config_facts, config_facts_localhost,
    mg_facts, scaling_checkpoint, record_property, n_mors,
):
    """Weekly full-scale Add-MOR capacity measurement. See WEEKLY_MOR_COUNTS."""
    duthost = duthosts[enum_downstream_dut_hostname]
    _run_and_publish(duthost, tbinfo, config_facts, config_facts_localhost,
                     mg_facts, enum_rand_one_asic_namespace, n_mors,
                     "weekly", record_property)


@pytest.mark.gcu_scaling_sanity
@pytest.mark.parametrize("n_mors", SANITY_MOR_COUNTS)
def test_add_mor_scaling_sanity(
    tbinfo, duthosts, enum_downstream_dut_hostname,
    enum_rand_one_asic_namespace, config_facts, config_facts_localhost,
    mg_facts, scaling_checkpoint, record_property, n_mors,
):
    """One-time sanity: validate the scaling test itself. Not for nightly."""
    duthost = duthosts[enum_downstream_dut_hostname]
    _run_and_publish(duthost, tbinfo, config_facts, config_facts_localhost,
                     mg_facts, enum_rand_one_asic_namespace, n_mors,
                     "sanity", record_property)


def _run_and_publish(duthost, tbinfo, config_facts, config_facts_localhost,
                     mg_facts, namespace, n_mors, tier, record_property):
    """Shared runner: measure, publish metrics, apply pass/fail policy.

    Policy:
      - A transport / hardware-proxy drop is recorded but does NOT fail the
        test.  The underlying SSH chattiness is a separate issue; failing on
        it would block nightly signal on something this test does not measure.
      - apply_patch's own timeout ("fuse") DOES fail the test.  It means GCU
        did not finish inside what this platform allows, which is exactly the
        regression this test exists to detect.  It was previously misfiled as
        a hardware-proxy timeout and silently passed.
      - Real GCU failures DO fail the test.
      - Apply time exceeding the budget fails the test (that IS the metric).
        e2e is published for information but never gated, because the budget
        is calibrated on apply-patch cost and e2e also contains BGP
        convergence -- gating on it would not compare like with like.
      - BGP check is soft -- logged only.
    """
    result = _run_scaling_measurement(
        duthost, tbinfo, config_facts, config_facts_localhost,
        mg_facts, namespace, n_mors, record_property)

    budget = _time_budget_for(n_mors,
                              n_ops=result["n_ops"],
                              loaddata_time=result["loaddata_time"],
                              fuse_s=result["fuse_s"])

    record_property("gcu_tier", tier)
    record_property("gcu_n_mors", n_mors)
    record_property("gcu_apply_elapsed_s", round(result["apply_elapsed_s"], 3))
    record_property("gcu_apply_wall_elapsed_s",
                    round(result["apply_wall_elapsed_s"], 3))
    record_property("gcu_timing_source", result["timing_source"])
    if result["n_changes"] is not None:
        record_property("gcu_sorter_changes", result["n_changes"])
        record_property("gcu_sorter_changes_by_ns",
                        ",".join("{}={}".format(ns, c) for ns, c
                                 in sorted(result["change_counts"].items())))
    record_property("gcu_e2e_elapsed_s", round(result["e2e_elapsed_s"], 3))
    record_property("gcu_success", result["success"])
    record_property("gcu_hwproxy_to", result["hwproxy_to"])
    record_property("gcu_fuse_tripped", result["fuse_tripped"])
    record_property("gcu_ns", result["ns_label"])
    record_property("gcu_pcs", ",".join(result["selection"]["portchannels"]))
    record_property("gcu_bgp_up", result["bgp_up"])
    record_property("gcu_bgp_checked", result["bgp_checked"])
    record_property("gcu_patch_ops", result["n_ops"])
    record_property("gcu_loaddata_s", round(result["loaddata_time"], 4))
    record_property("gcu_predicted_s", round(result["predicted_s"], 1))
    record_property("gcu_time_budget_s", budget)

    logger.info(
        "SCALING RESULT tier=%s n=%d ns=%s ops=%d apply=%.2fs e2e=%.2fs "
        "success=%s hwproxy_to=%s fuse_tripped=%s bgp_up=%s budget=%ds",
        tier, n_mors, result["ns_label"], result["n_ops"],
        result["apply_elapsed_s"], result["e2e_elapsed_s"],
        result["success"], result["hwproxy_to"], result["fuse_tripped"],
        result["bgp_up"], budget)

    pytest_assert(
        not result["fuse_tripped"],
        "Add-MOR N={} did not complete within the apply-patch timeout "
        "({}s) on {}. GCU took longer than this platform allows -- this is a "
        "performance failure, not an infrastructure one.".format(
            n_mors, result["fuse_s"], duthost.facts.get("platform")))

    if result["hwproxy_to"] and not result["success"]:
        logger.warning(
            "Transport/hardware-proxy drop observed (N=%d): %s. Recording "
            "data point; not failing (ANP SSH-chatty rollout owns this).",
            n_mors, result["failure_repr"])
        # The elapsed number is meaningless when the session dropped part-way.
        return

    pytest_assert(
        result["success"],
        "apply-patch failed during Add-MOR scaling (N={}): {}".format(
            n_mors, result["failure_repr"]))
    pytest_assert(
        result["apply_elapsed_s"] <= budget,
        "Add-MOR N={} exceeded apply-time budget: {:.1f}s > {}s "
        "({} ops, {:.3f}s/loadData)".format(
            n_mors, result["apply_elapsed_s"], budget,
            result["n_ops"], result["loaddata_time"]))

    if result["bgp_checked"] and not result["bgp_up"]:
        logger.warning(
            "BGP peers did not all reach Established: %s",
            result["selection"]["bgp_neigh_ips"])


@pytest.mark.gcu_scaling_weekly
def test_max_mors_under_budget(
    tbinfo, duthosts, enum_downstream_dut_hostname,
    enum_rand_one_asic_namespace, config_facts, config_facts_localhost,
    mg_facts, scaling_checkpoint, record_property,
):
    """Find how many MORs fit inside the 1-hour operational budget.

    Sweeps N ascending, stops at the first N that fails or exceeds budget.
    Records ``gcu_max_mors_under_budget`` = the largest N that succeeded
    within the time budget on this testbed.
    """
    duthost = duthosts[enum_downstream_dut_hostname]
    budget = int(os.environ.get("GCU_TIME_BUDGET_S", DEFAULT_TIME_BUDGET_S))
    # The operational hour is only meaningful if apply-patch is even allowed to
    # run that long.  On a platform whose fuse is below the budget, an apply can
    # never legitimately reach it -- the fuse trips first -- so "budget
    # exceeded" would be unreachable and the sweep could only ever end on a
    # failure reason.  Clamp so the capacity boundary can actually be observed.
    sweep_fuse_s = get_gcu_timeout(duthost)
    if budget > sweep_fuse_s - FUSE_MARGIN_S:
        clamped = sweep_fuse_s - FUSE_MARGIN_S
        logger.info("Sweep budget %ds clamped to %ds (platform fuse %ds)",
                    budget, clamped, sweep_fuse_s)
        budget = clamped
    # Ceiling is bounded by the PortChannels a line card actually has; if the
    # sweep runs to the end, the real maximum is ">= 33", not "== 33", and
    # gcu_max_n_stop_reason says so.
    sweep = [1, 5, 10, 20, 24, 30, 33]
    max_n = 0
    max_ports = 0
    last_elapsed = 0.0
    # Why the sweep stopped.  Only budget_exceeded and sweep_exhausted mean
    # "this is the capacity"; everything else means the number is incomplete
    # and must not be read as a platform maximum.
    stop_reason = "sweep_exhausted"
    fatal = None

    for n in sweep:
        try:
            result = _run_scaling_measurement(
                duthost, tbinfo, config_facts, config_facts_localhost,
                mg_facts, enum_rand_one_asic_namespace, n, record_property)
        except pytest.skip.Exception as exc:
            logger.info("Skip at N=%d: %s", n, exc)
            if max_n == 0:
                # Nothing measured yet, so the skip is about the platform or
                # testbed rather than the sweep running out of headroom.
                # Propagate it instead of falling through to the assertion,
                # which would report this as a failure.  Matches how the
                # tiered scaling tests behave.
                pytest.skip(str(exc))
            stop_reason = "not_measurable_at_n{}".format(n)
            break

        # Roll back between iterations so the next one starts from the same
        # pre-state.  A rollback failure is NOT a capacity boundary: it means
        # the DUT is no longer in a known state, so every later reading would
        # be untrustworthy.  Restore has already been attempted inside
        # rollback_or_reload (which falls back to config_reload); we record the
        # failure and re-raise it after publishing, rather than silently
        # reporting the partial sweep as the platform maximum.
        try:
            rollback_or_reload(duthost, cp=SCALING_CHECKPOINT)
        except (Exception, pytest.fail.Exception) as exc:
            # rollback_or_reload signals failure with pytest.fail, which is a
            # BaseException subclass; without naming it here the sweep would
            # abort before publishing stop_reason and the partial result.
            logger.error("rollback between N iterations failed at N=%d: %r",
                         n, exc)
            stop_reason = "rollback_failed"
            fatal = ("Rollback failed after N={}, so the sweep is incomplete "
                     "and the result below is not a platform maximum: "
                     "{!r}".format(n, exc))
            break

        logger.info("[max-N sweep] N=%d apply=%.1fs (%s, wall=%.1fs) "
                    "e2e=%.1fs success=%s",
                    n, result["apply_elapsed_s"], result["timing_source"],
                    result["apply_wall_elapsed_s"], result["e2e_elapsed_s"],
                    result["success"])

        if result["fuse_tripped"]:
            stop_reason = "fuse_tripped"
            fatal = ("apply-patch did not complete within the platform "
                     "timeout ({}s) at N={}. That is a performance failure, "
                     "not the capacity boundary.".format(result["fuse_s"], n))
            break
        if not result["success"]:
            if result["hwproxy_to"]:
                # Transport drop: same policy as the tiered tests -- recorded,
                # not failed, but explicitly not a capacity result either.
                stop_reason = "transport_drop"
                logger.warning("Transport drop at N=%d: %s",
                               n, result["failure_repr"])
                break
            stop_reason = "apply_failed"
            fatal = ("apply-patch failed at N={} ({}). A failure is not a "
                     "capacity boundary.".format(n, result["failure_repr"]))
            break
        if result["apply_elapsed_s"] > budget:
            stop_reason = "budget_exceeded"
            break

        max_n = n
        max_ports = len(result["selection"]["member_ports"])
        last_elapsed = result["apply_elapsed_s"]

    complete = stop_reason in ("budget_exceeded", "sweep_exhausted")
    record_property("gcu_max_mors_under_budget", max_n)
    record_property("gcu_max_ports_under_budget", max_ports)
    record_property("gcu_max_n_last_elapsed_s", round(last_elapsed, 3))
    record_property("gcu_max_n_stop_reason", stop_reason)
    record_property("gcu_max_n_result_complete", complete)
    record_property("gcu_max_n_budget_s", budget)
    # Kept for continuity: existing dashboards key this test's budget off
    # gcu_time_budget_s, the same name the tiered tests emit.  Dropping it
    # would silently empty those series.
    record_property("gcu_time_budget_s", budget)
    logger.info(
        "MAX MORs under %ds apply-time budget: %d MORs (=%d ports, last "
        "apply=%.1fs, stop_reason=%s, complete=%s)",
        budget, max_n, max_ports, last_elapsed, stop_reason, complete)

    if fatal:
        pytest.fail(fatal)
    pytest_assert(
        max_n > 0,
        "Could not add even N=1 MOR within budget {}s".format(budget))
