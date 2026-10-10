"""
Validate adding a removed 400G PortChannel member back with GCU.

The test runs on T2 chassis linecards. It scans frontend linecards and selects
a PortChannel whose external members are all 400G and which has at least two
oper-up members. Setup removes one member's port-scoped cluster config, sets
that port admin down, and lowers the PortChannel min_links to the remaining
member count. The test then restores the removed member and the original
PortChannel min_links with GCU.
"""

import ast
import ipaddress
import json
import logging
import os
import random
import shlex

import pytest
import requests

from tests.common.config_reload import config_reload
from tests.common.gu_utils import (
    apply_patch,
    delete_tmpfile,
    expect_op_success,
    generate_tmpfile,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_ASIC_ID, NAMESPACE_PREFIX
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import wait_until
from tests.generic_config_updater.add_cluster.helpers import (
    clear_traffic_counters,
    find_portchannels_by_member_speed,
    format_sonic_interface_dict,
    get_exabgp_port_for_neighbor,
    get_asic_interface_status_map,
    get_portchannel_member_value,
    get_portchannel_status_map,
    send_and_verify_traffic,
    verify_routev4_existence,
)

pytestmark = [
    pytest.mark.topology("t2")
]

logger = logging.getLogger(__name__)
allure.logger = logger

SPEED_400G = "400000"
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
    "198.18.251.251",
    "198.18.251.252",
    "198.18.251.253",
    "198.18.251.254",
)
EXABGP_BASE_PORT = 5000
NHIPV4 = "10.10.246.254"
COUNTERS_DB_TX_FIELDS = (
    "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
    "SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS",
    "SAI_PORT_STAT_IF_OUT_OCTETS",
    "SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS",
)
INTERNAL_PORT_PREFIXES = ("Ethernet-BP", "Ethernet-IB", "Ethernet-Rec")
LOGANALYZER_IGNORE_REGEX = [
    ".*ERR sonic_yang.*",
    ".*ERR teamd[0-9].*get_dump: Can't get dump for LAG.*",
    ".*ERR swss[0-9]*#orchagent.*removeLag.*",
    ".*ERR swss[0-9]*#orchagent: :- doTask: Failed to process invalid buffer task",
]


def _restore_dut_via_minigraph(duthost, loganalyzer=None):
    """
    Restore the selected DUT with minigraph config reload.
    """
    config_reload(
        duthost,
        config_source="minigraph",
        safe_reload=True,
        wait_for_bgp=True,
        ignore_loganalyzer=loganalyzer,
    )


def _frontend_candidates_for_hwsku(duthosts, selected_hostname):
    """
    Return frontend DUTs with the same HWSKU as the enum-selected DUT.
    """
    selected_dut = duthosts[selected_hostname]
    selected_hwsku = selected_dut.facts.get("hwsku")
    frontend_hostnames = {dut.hostname for dut in duthosts.frontend_nodes}
    ordered_duts = []
    seen_hostnames = set()

    for dut in [selected_dut] + list(duthosts.frontend_nodes):
        if dut.hostname in seen_hostnames:
            continue
        if dut.hostname not in frontend_hostnames:
            continue
        if dut.facts.get("hwsku") != selected_hwsku:
            continue
        ordered_duts.append(dut)
        seen_hostnames.add(dut.hostname)

    return selected_hwsku, ordered_duts


def _build_dut_context(duthost, asic_index):
    """
    Build per-ASIC namespace prefixes and running facts for a DUT.
    """
    if asic_index is None or asic_index == DEFAULT_ASIC_ID:
        asic_namespace = None
        cli_ns_prefix = ''
    else:
        asic_namespace = f'{NAMESPACE_PREFIX}{asic_index}'
        cli_ns_prefix = f'-n {asic_namespace}'

    config_facts = duthost.config_facts(
        host=duthost.hostname,
        source="running",
        namespace=asic_namespace,
    )['ansible_facts']
    selected_asic_index = (
        asic_index if asic_index is not None else DEFAULT_ASIC_ID
    )
    return {
        "asic_index": selected_asic_index,
        "asic_namespace": asic_namespace,
        "cli_namespace_prefix": cli_ns_prefix,
        "config_facts": config_facts,
    }


def _ordered_asic_indices(duthost, preferred_asic_index=None):
    """
    Return frontend ASIC indices, preferred enum-selected ASIC first.
    """
    if duthost.is_multi_asic:
        asic_indices = [asic.asic_index for asic in duthost.frontend_asics]
    else:
        asic_indices = [DEFAULT_ASIC_ID]

    if preferred_asic_index in asic_indices:
        return [preferred_asic_index] + [
            asic_index
            for asic_index in asic_indices
            if asic_index != preferred_asic_index
        ]
    return asic_indices


def _escape_json_pointer_key(key):
    """
    Escape a CONFIG_DB key segment for a JSON patch path.
    """
    return key.replace('~', '~0').replace('/', '~1')


def _iter_buffer_pg_entries(config_facts, port):
    """
    Iterate BUFFER_PG entries for a port as (key, value).

    Supports both ansible config_facts nested form, e.g.
    ``{"Ethernet0": {"0": {...}}}``, and raw CONFIG_DB key form, e.g.
    ``{"Ethernet0|0": {...}}``.
    """
    for key, value in config_facts.get("BUFFER_PG", {}).items():
        if key == port and isinstance(value, dict):
            for pg_key, pg_value in value.items():
                yield f"{port}|{pg_key}", pg_value
        elif key.startswith(f"{port}|"):
            yield key, value


def _queue_key_matches_port(queue_key, port):
    """
    Return True when a QUEUE key belongs to the selected physical port.
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


def _iter_queue_entries(config_facts, port):
    """
    Iterate QUEUE entries for a port as (key, value).
    """
    queue_dict = _format_sonic_queue_dict(config_facts.get("QUEUE", {}))
    for queue_key, queue_value in queue_dict.items():
        if _queue_key_matches_port(queue_key, port):
            yield queue_key, queue_value


def _get_port_interface_entries(config_facts, port):
    """
    Return CONFIG_DB INTERFACE entries for a port.
    """
    return {
        key: value
        for key, value in format_sonic_interface_dict(
            config_facts.get("INTERFACE", {})
        ).items()
        if key == port or key.startswith(f"{port}|")
    }


def _build_port_interface_entries(config_facts, port):
    """
    Return JSON-patch-ready INTERFACE entries for a port.
    """
    return {
        _escape_json_pointer_key(key): value
        for key, value in _get_port_interface_entries(
            config_facts,
            port,
        ).items()
    }


def _wait_for_portchannel_up_or_log(duthost, asic_namespace, portchannel,
                                    operation_description="min_links update"):
    """
    Wait for a PortChannel to become up and log an error on timeout.

    The caller decides whether timeout is fatal for the current stage.
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
        logger.info(
            "PortChannel %s status while waiting for up: %s",
            portchannel,
            last_status.get(portchannel),
        )
        return last_status.get(portchannel) == "up"

    if wait_until(
        PORTCHANNEL_UP_WAIT_TIME,
        PORTCHANNEL_UP_WAIT_INTERVAL,
        0,
        _is_portchannel_up,
    ):
        return True

    logger.error(
        "PortChannel %s did not come up after %s. "
        "Last status=%s rc=%s stdout=%s stderr=%s",
        portchannel,
        operation_description,
        last_status.get(portchannel),
        last_result.get("rc"),
        last_result.get("stdout", ""),
        last_result.get("stderr", ""),
    )
    return False


def _collect_portchannel_member_add_options(candidates, speed,
                                            preferred_asic_index=None,
                                            rng=None):
    """
    Select one T2 chassis PortChannel with at least two oper-up speed members.
    """
    rng = rng or random
    for candidate in candidates:
        asic_options = {}
        ordered_asic_indices = _ordered_asic_indices(
            candidate,
            preferred_asic_index,
        )
        for asic_index in ordered_asic_indices:
            ctx = _build_dut_context(candidate, asic_index)
            status_map = get_asic_interface_status_map(
                candidate,
                ctx["asic_namespace"],
            )
            pc_status_map, _pc_result = get_portchannel_status_map(
                candidate,
                ctx["asic_namespace"],
            )
            portchannel_options = find_portchannels_by_member_speed(
                ctx["config_facts"],
                status_map,
                pc_status_map,
                speed,
                min_member_count=2,
                require_min_links=True,
                require_portchannel_up=True,
            )

            if portchannel_options:
                asic_options[asic_index] = {
                    "ctx": ctx,
                    "portchannels": portchannel_options,
                }

        if not asic_options:
            logger.info(
                "No %s oper-up PortChannel with at least two oper-up "
                "members on %s",
                speed,
                candidate.hostname,
            )
            continue

        selected_asic_index = rng.choice(list(asic_options.keys()))
        selected = asic_options[selected_asic_index]
        selected_portchannel = rng.choice(selected["portchannels"])
        selected_member = rng.choice(selected_portchannel["members"])
        remaining_members = [
            member
            for member in selected_portchannel["members"]
            if member != selected_member
        ]
        ctx = selected["ctx"]
        return {
            "selected_dut_hostname": candidate.hostname,
            "selected_asic_index": ctx["asic_index"],
            "enum_rand_one_asic_namespace": ctx["asic_namespace"],
            "cli_namespace_prefix": ctx["cli_namespace_prefix"],
            "selected_portchannel": selected_portchannel["portchannel"],
            "selected_member_port": selected_member,
            "remaining_member_ports": remaining_members,
            "original_min_links": selected_portchannel["original_min_links"],
            "config_facts": ctx["config_facts"],
        }

    return None


def _apply_patch_with_dry_run(
    duthost,
    json_patch,
    description,
    operation_completed=None,
):
    """
    Dry-run a GCU patch, then apply it when dry-run succeeds.
    """
    tmpfile = generate_tmpfile(duthost)
    try:
        if operation_completed is not None:
            try:
                if operation_completed():
                    logger.info(
                        "Target state already present for %s; skipping patch",
                        description,
                    )
                    return
            except Exception as exc:
                logger.warning(
                    "Unable to verify target state before GCU dry-run for %s: "
                    "%s. Continuing with dry-run.",
                    description,
                    exc,
                )

        logger.info("Dry-running GCU patch for %s", description)
        logger.info("Patch content: %s", json_patch)
        duthost.copy(content=json.dumps(json_patch, indent=4), dest=tmpfile)
        dry_run_cmd = "config apply-patch -d -v {}".format(tmpfile)
        dry_run_output = duthost.shell(dry_run_cmd, module_ignore_errors=True)
        pytest_assert(
            not dry_run_output["rc"],
            "GCU dry-run failed for {}: rc={} stdout={} stderr={}".format(
                description,
                dry_run_output.get("rc"),
                dry_run_output.get("stdout", ""),
                dry_run_output.get("stderr", ""),
            ),
        )

        if operation_completed is not None:
            try:
                completed_after_dry_run = operation_completed()
            except Exception as exc:
                logger.warning(
                    "Unable to verify target state after GCU dry-run for %s: "
                    "%s",
                    description,
                    exc,
                )
            else:
                pytest_assert(
                    not completed_after_dry_run,
                    "GCU dry-run unexpectedly changed target state for "
                    "{}".format(
                        description
                    )
                )

        logger.info("Applying GCU patch for %s", description)
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def build_portchannel_member_remove_ops(config_facts, json_namespace,
                                        portchannel, port):
    """
    Build GCU operations that move one member to default/admin-down state.

    PortChannel-level BGP and interface config stays in place because remaining
    LAG members still use it.
    """
    member_key = f"{portchannel}|{port}"
    json_patch = [{
        "op": "remove",
        "path": (
            f"{json_namespace}/PORTCHANNEL_MEMBER/"
            f"{_escape_json_pointer_key(member_key)}"
        ),
    }]

    if port in config_facts.get("DEVICE_NEIGHBOR", {}):
        json_patch.append({
            "op": "remove",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR/{port}",
        })

    interface_entries = _build_port_interface_entries(config_facts, port)
    for interface_key in sorted(interface_entries, reverse=True):
        json_patch.append({
            "op": "remove",
            "path": f"{json_namespace}/INTERFACE/{interface_key}",
        })

    for bp_key, _bp_value in _iter_buffer_pg_entries(config_facts, port):
        json_patch.append({
            "op": "remove",
            "path": (
                f"{json_namespace}/BUFFER_PG/"
                f"{_escape_json_pointer_key(bp_key)}"
            ),
        })

    if port in config_facts.get("PORT_QOS_MAP", {}):
        json_patch.append({
            "op": "remove",
            "path": f"{json_namespace}/PORT_QOS_MAP/{port}",
        })

    for queue_key, _queue_value in _iter_queue_entries(config_facts, port):
        json_patch.append({
            "op": "remove",
            "path": (
                f"{json_namespace}/QUEUE/"
                f"{_escape_json_pointer_key(queue_key)}"
            ),
        })

    if port in config_facts.get("PFC_WD", {}):
        json_patch.append({
            "op": "remove",
            "path": f"{json_namespace}/PFC_WD/{port}",
        })

    cable_length = config_facts.get("CABLE_LENGTH", {}).get(
        "AZURE",
        {},
    ).get(port)
    if cable_length is not None:
        json_patch.append({
            "op": "remove",
            "path": f"{json_namespace}/CABLE_LENGTH/AZURE/{port}",
        })

    json_patch.append({
        "op": "add",
        "path": f"{json_namespace}/PORT/{port}/admin_status",
        "value": "down",
    })
    return json_patch


def build_portchannel_min_links_ops(json_namespace, portchannel, min_links):
    """
    Build GCU operations that update a PortChannel min_links value.
    """
    return [{
        "op": "add",
        "path": f"{json_namespace}/PORTCHANNEL/{portchannel}/min_links",
        "value": str(min_links),
    }]


def build_portchannel_member_add_ops(config_facts, json_namespace,
                                     portchannel, port, original_min_links):
    """
    Build GCU operations that add back a removed member and restore min_links.
    """
    member_key = f"{portchannel}|{port}"
    json_patch = [{
        "op": "add",
        "path": (
            f"{json_namespace}/PORTCHANNEL_MEMBER/"
            f"{_escape_json_pointer_key(member_key)}"
        ),
        "value": get_portchannel_member_value(
            config_facts,
            portchannel,
            port,
        ),
    }]

    if port in config_facts.get("DEVICE_NEIGHBOR", {}):
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR/{port}",
            "value": config_facts["DEVICE_NEIGHBOR"][port],
        })

    for interface_key, interface_value in sorted(
        _build_port_interface_entries(config_facts, port).items()
    ):
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/INTERFACE/{interface_key}",
            "value": interface_value,
        })

    for bp_key, bp_value in _iter_buffer_pg_entries(config_facts, port):
        json_patch.append({
            "op": "add",
            "path": (
                f"{json_namespace}/BUFFER_PG/"
                f"{_escape_json_pointer_key(bp_key)}"
            ),
            "value": bp_value,
        })

    if port in config_facts.get("PORT_QOS_MAP", {}):
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/PORT_QOS_MAP/{port}",
            "value": config_facts["PORT_QOS_MAP"][port],
        })

    for queue_key, queue_value in _iter_queue_entries(config_facts, port):
        json_patch.append({
            "op": "add",
            "path": (
                f"{json_namespace}/QUEUE/"
                f"{_escape_json_pointer_key(queue_key)}"
            ),
            "value": queue_value,
        })

    if port in config_facts.get("PFC_WD", {}):
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/PFC_WD/{port}",
            "value": config_facts["PFC_WD"][port],
        })

    cable_length = config_facts.get("CABLE_LENGTH", {}).get(
        "AZURE",
        {},
    ).get(port)
    if cable_length is not None:
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/CABLE_LENGTH/AZURE/{port}",
            "value": cable_length,
        })

    port_config = config_facts.get("PORT", {}).get(port, {})
    admin_status_path = f"{json_namespace}/PORT/{port}/admin_status"
    if "admin_status" in port_config:
        json_patch.append({
            "op": "add",
            "path": admin_status_path,
            "value": port_config["admin_status"],
        })
    else:
        json_patch.append({
            "op": "remove",
            "path": admin_status_path,
        })
    json_patch.extend(
        build_portchannel_min_links_ops(
            json_namespace,
            portchannel,
            original_min_links,
        )
    )
    return json_patch


def _config_db_hget(duthost, cli_namespace_prefix, key, field):
    """
    Read one CONFIG_DB hash field from Redis.
    """
    cmd = "sonic-db-cli {} CONFIG_DB HGET {} {}".format(
        cli_namespace_prefix,
        shlex.quote(key),
        shlex.quote(field),
    )
    return duthost.shell(cmd, module_ignore_errors=True)


def _config_db_hgetall_value(duthost, cli_namespace_prefix, key):
    """
    Return one CONFIG_DB hash as a dictionary, or None on query/parse failure.
    """
    cmd = "sonic-db-cli {} CONFIG_DB HGETALL {}".format(
        cli_namespace_prefix,
        shlex.quote(key),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to read CONFIG_DB hash %s: rc=%s stdout=%s stderr=%s",
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
                str(key): str(value)
                for key, value in parsed_output.items()
            }

    if len(lines) % 2:
        logger.warning(
            "Failed to parse CONFIG_DB hash %s HGETALL output: %s",
            key,
            lines,
        )
        return None
    return dict(zip(lines[0::2], lines[1::2]))


def _config_db_hexists_value(duthost, cli_namespace_prefix, key, field):
    """
    Return True/False for CONFIG_DB hash field existence, or None on failure.
    """
    cmd = "sonic-db-cli {} CONFIG_DB HEXISTS {} {}".format(
        cli_namespace_prefix,
        shlex.quote(key),
        shlex.quote(field),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to query CONFIG_DB field %s/%s: rc=%s stdout=%s stderr=%s",
            key,
            field,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None
    return _parse_config_db_bool(
        output.get("stdout", ""),
        "CONFIG_DB field {}/{}".format(key, field),
    )


def _parse_config_db_bool(output, description):
    """
    Parse sonic-db-cli boolean output across redis-cli wrapper variants.
    """
    value = output.strip().lower()
    if value in ("1", "true"):
        return True
    if value in ("0", "false"):
        return False
    logger.warning("Unexpected %s existence output: %s", description, output)
    return None


def _config_db_hget_value(duthost, cli_namespace_prefix, key, field):
    """
    Return one CONFIG_DB hash field value, or None when it cannot be read.
    """
    output = _config_db_hget(duthost, cli_namespace_prefix, key, field)
    if output["rc"]:
        logger.info(
            "Failed to read CONFIG_DB field %s/%s: rc=%s stdout=%s stderr=%s",
            key,
            field,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None
    return output["stdout"].strip()


def _config_db_key_exists_value(duthost, cli_namespace_prefix, key):
    """
    Return True/False for CONFIG_DB key existence, or None on query failure.
    """
    cmd = "sonic-db-cli {} CONFIG_DB EXISTS {}".format(
        cli_namespace_prefix,
        shlex.quote(key),
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output["rc"]:
        logger.info(
            "Failed to query CONFIG_DB key %s: rc=%s stdout=%s stderr=%s",
            key,
            output.get("rc"),
            output.get("stdout", ""),
            output.get("stderr", ""),
        )
        return None
    return _parse_config_db_bool(
        output.get("stdout", ""),
        "CONFIG_DB key {}".format(key),
    )


def _config_db_key_exists(duthost, cli_namespace_prefix, key):
    """
    Return True when a CONFIG_DB key exists.
    """
    key_exists = _config_db_key_exists_value(
        duthost,
        cli_namespace_prefix,
        key,
    )
    pytest_assert(
        key_exists is not None,
        "Failed to query CONFIG_DB key {}".format(key),
    )
    return key_exists


def _normalize_config_db_hash(hash_value):
    """
    Convert expected CONFIG_DB hash values to Redis string form.
    """
    return {
        str(key): str(value)
        for key, value in hash_value.items()
    }


def _expected_port_hash_entries(config_facts, portchannel, port):
    """
    Return selected member CONFIG_DB hash entries restored by the add patch.
    """
    member_key = f"{portchannel}|{port}"
    expected_entries = {
        f"PORTCHANNEL_MEMBER|{member_key}": get_portchannel_member_value(
            config_facts,
            portchannel,
            port,
        ),
    }

    if port in config_facts.get("DEVICE_NEIGHBOR", {}):
        expected_entries[f"DEVICE_NEIGHBOR|{port}"] = (
            config_facts["DEVICE_NEIGHBOR"][port]
        )

    for interface_key, interface_value in _get_port_interface_entries(
        config_facts,
        port,
    ).items():
        expected_entries[f"INTERFACE|{interface_key}"] = interface_value

    for bp_key, bp_value in _iter_buffer_pg_entries(config_facts, port):
        expected_entries[f"BUFFER_PG|{bp_key}"] = bp_value

    if port in config_facts.get("PORT_QOS_MAP", {}):
        expected_entries[f"PORT_QOS_MAP|{port}"] = (
            config_facts["PORT_QOS_MAP"][port]
        )

    for queue_key, queue_value in _iter_queue_entries(config_facts, port):
        expected_entries[f"QUEUE|{queue_key}"] = queue_value

    if port in config_facts.get("PFC_WD", {}):
        expected_entries[f"PFC_WD|{port}"] = config_facts["PFC_WD"][port]

    return expected_entries


def _expected_cable_length(config_facts, port):
    """
    Return selected port cable length from the saved config facts.
    """
    return config_facts.get("CABLE_LENGTH", {}).get("AZURE", {}).get(port)


def _config_db_hash_matches(duthost, cli_namespace_prefix, key,
                            expected_value, should_exist):
    """
    Return True when one CONFIG_DB hash exists/does not exist as expected.
    """
    key_exists = _config_db_key_exists_value(
        duthost,
        cli_namespace_prefix,
        key,
    )
    if key_exists is None:
        return False
    if not should_exist:
        if key_exists:
            logger.info("CONFIG_DB key %s exists but should be absent", key)
        return not key_exists
    if not key_exists:
        logger.info("CONFIG_DB key %s is absent but should exist", key)
        return False

    if not expected_value:
        return True

    actual_value = _config_db_hgetall_value(
        duthost,
        cli_namespace_prefix,
        key,
    )
    if actual_value is None:
        return False

    expected_value = _normalize_config_db_hash(expected_value)
    if actual_value != expected_value:
        logger.info(
            "CONFIG_DB key %s mismatch: expected=%s actual=%s",
            key,
            expected_value,
            actual_value,
        )
        return False
    return True


def _config_db_field_matches(duthost, cli_namespace_prefix, key, field,
                             expected_value, should_exist):
    """
    Return True when one CONFIG_DB hash field exists/does not exist as expected.
    """
    field_exists = _config_db_hexists_value(
        duthost,
        cli_namespace_prefix,
        key,
        field,
    )
    if field_exists is None:
        return False
    if not should_exist:
        if field_exists:
            logger.info(
                "CONFIG_DB field %s/%s exists but should be absent",
                key,
                field,
            )
        return not field_exists
    if not field_exists:
        logger.info("CONFIG_DB field %s/%s is absent but should exist", key, field)
        return False

    actual_value = _config_db_hget_value(
        duthost,
        cli_namespace_prefix,
        key,
        field,
    )
    if actual_value != str(expected_value):
        logger.info(
            "CONFIG_DB field %s/%s mismatch: expected=%s actual=%s",
            key,
            field,
            expected_value,
            actual_value,
        )
        return False
    return True


def _saved_admin_status_expectation(config_facts, port):
    """
    Return whether admin_status existed in saved facts and its saved value.
    """
    port_config = config_facts.get("PORT", {}).get(port, {})
    return "admin_status" in port_config, port_config.get("admin_status")


def _port_scoped_config_matches(duthost, cli_namespace_prefix, config_facts,
                                portchannel, port, should_exist):
    """
    Return True when selected member-scoped CONFIG_DB entries match expectation.
    """
    for key, expected_value in _expected_port_hash_entries(
        config_facts,
        portchannel,
        port,
    ).items():
        if not _config_db_hash_matches(
            duthost,
            cli_namespace_prefix,
            key,
            expected_value,
            should_exist,
        ):
            return False

    cable_length = _expected_cable_length(config_facts, port)
    if cable_length is not None:
        return _config_db_field_matches(
            duthost,
            cli_namespace_prefix,
            "CABLE_LENGTH|AZURE",
            port,
            cable_length,
            should_exist,
        )
    return True


def _portchannel_member_state_matches(
    duthost,
    cli_namespace_prefix,
    config_facts,
    portchannel,
    port,
    member_should_exist,
    expected_admin_status,
    expected_admin_status_exists,
    expected_min_links,
):
    """
    Return True when CONFIG_DB already reflects an expected member state.
    """
    member_key = f"PORTCHANNEL_MEMBER|{portchannel}|{port}"
    member_exists = _config_db_key_exists_value(
        duthost,
        cli_namespace_prefix,
        member_key,
    )
    min_links = _config_db_hget_value(
        duthost,
        cli_namespace_prefix,
        f"PORTCHANNEL|{portchannel}",
        "min_links",
    )
    if member_exists is None or min_links is None:
        return False

    return (
        member_exists == member_should_exist and
        _config_db_field_matches(
            duthost,
            cli_namespace_prefix,
            f"PORT|{port}",
            "admin_status",
            expected_admin_status,
            expected_admin_status_exists,
        ) and
        min_links == str(expected_min_links) and
        _port_scoped_config_matches(
            duthost,
            cli_namespace_prefix,
            config_facts,
            portchannel,
            port,
            member_should_exist,
        )
    )


def verify_portchannel_member_state(duthost, cli_namespace_prefix, config_facts,
                                    portchannel, port, member_should_exist,
                                    expected_admin_status,
                                    expected_admin_status_exists,
                                    expected_min_links):
    """
    Verify member-scoped CONFIG_DB entries, port admin_status, and min_links.
    """
    member_key = f"PORTCHANNEL_MEMBER|{portchannel}|{port}"
    member_exists = _config_db_key_exists(
        duthost,
        cli_namespace_prefix,
        member_key,
    )
    pytest_assert(
        member_exists == member_should_exist,
        "{} existence mismatch: expected {}, got {}".format(
            member_key,
            member_should_exist,
            member_exists,
        ),
    )

    pytest_assert(
        _config_db_field_matches(
            duthost,
            cli_namespace_prefix,
            f"PORT|{port}",
            "admin_status",
            expected_admin_status,
            expected_admin_status_exists,
        ),
        "{} admin_status mismatch: expected_exist={} expected_value={}".format(
            port,
            expected_admin_status_exists,
            expected_admin_status,
        ),
    )

    min_links_output = _config_db_hget(
        duthost,
        cli_namespace_prefix,
        f"PORTCHANNEL|{portchannel}",
        "min_links",
    )
    pytest_assert(
        (
            not min_links_output["rc"] and
            min_links_output["stdout"].strip() == str(expected_min_links)
        ),
        "{} min_links mismatch: expected {}, rc={} stdout={} stderr={}".format(
            portchannel,
            expected_min_links,
            min_links_output.get("rc"),
            min_links_output.get("stdout", ""),
            min_links_output.get("stderr", ""),
        ),
    )

    for key, expected_value in _expected_port_hash_entries(
        config_facts,
        portchannel,
        port,
    ).items():
        pytest_assert(
            _config_db_hash_matches(
                duthost,
                cli_namespace_prefix,
                key,
                expected_value,
                member_should_exist,
            ),
            "{} existence/value mismatch; expected_exist={}".format(
                key,
                member_should_exist,
            ),
        )

    cable_length = _expected_cable_length(config_facts, port)
    if cable_length is not None:
        pytest_assert(
            _config_db_field_matches(
                duthost,
                cli_namespace_prefix,
                "CABLE_LENGTH|AZURE",
                port,
                cable_length,
                member_should_exist,
            ),
            "CABLE_LENGTH|AZURE/{} existence/value mismatch; "
            "expected_exist={}".format(
                port,
                member_should_exist,
            ),
        )


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


def _namespace_command_prefix(asic_namespace):
    """
    Return an ip-netns command prefix for namespace-aware SONiC CLIs.
    """
    if asic_namespace is None:
        return ""
    return "sudo ip netns exec {}".format(asic_namespace)


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
    Return True/False for Redis DB key existence, or None on failure.
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
        return None
    return _parse_config_db_bool(
        output.get("stdout", ""),
        "{} key {}".format(db_name, key),
    )


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
        "COUNTERS_DB missing COUNTERS_PORT_NAME_MAP entry for {}".format(
            port
        ),
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
    raise AssertionError("pytest_assert(False) did not raise")


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

    return _parse_counter_value(
        port_stats.get(port, {}).get(counter_name),
    )


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


def _expected_portchannel_members(runtime):
    """
    Return all PortChannel members expected after member restoration.
    """
    return sorted(
        runtime["remaining_member_ports"] + [runtime["selected_member_port"]]
    )


def verify_teamd_lag_member_state(duthost, portchannel, expected_members,
                                  restored_member, expected_min_links):
    """
    Verify teamdctl/lag_facts reports the restored member selected.
    """
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
        runner_config = po_config.get("runner", {})
        min_ports = runner_config.get("min_ports")
        restored_member_state = member_stats.get(restored_member, {})

        last_summary = {
            "po_intf_stat": lag_info.get("po_intf_stat"),
            "configured_ports": sorted(configured_ports),
            "missing_members": missing_members,
            "min_ports": min_ports,
            "restored_member_state": restored_member_state,
        }
        logger.info("teamd/lag_facts summary for %s: %s", portchannel, last_summary)
        return (
            lag_info.get("po_intf_stat") == "Up" and
            not missing_members and
            str(min_ports) == str(expected_min_links) and
            restored_member in member_stats and
            _runner_member_selected(restored_member_state)
        )

    pytest_assert(
        wait_until(
            LAG_STATE_WAIT_TIME,
            LAG_STATE_WAIT_INTERVAL,
            0,
            _lag_state_matches,
        ),
        "teamd/lag_facts did not report {} restored in {}; last_state={}".format(
            restored_member,
            portchannel,
            last_summary,
        ),
    )


def verify_asic_db_lag_member_state(duthost, cli_namespace_prefix,
                                    portchannel, expected_members,
                                    restored_member):
    """
    Verify ASIC_DB has enabled SAI LAG_MEMBER objects for the expected ports.
    """
    last_summary = {}

    def _lag_members_ready():
        nonlocal last_summary
        member_port_oids = {
            member: _db_hget(
                duthost,
                cli_namespace_prefix,
                "COUNTERS_DB",
                "COUNTERS_PORT_NAME_MAP",
                member,
            )
            for member in expected_members
        }
        missing_oids = sorted(
            member
            for member, port_oid in member_port_oids.items()
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
            lag_id = _db_hget(
                duthost,
                cli_namespace_prefix,
                "ASIC_DB",
                lag_member_key,
                "SAI_LAG_MEMBER_ATTR_LAG_ID",
            )
            egress_disable = _db_hget(
                duthost,
                cli_namespace_prefix,
                "ASIC_DB",
                lag_member_key,
                "SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE",
            )
            matching_member = [
                member
                for member, member_oid in member_port_oids.items()
                if member_oid == port_oid
            ][0]
            lag_members_by_port[matching_member] = {
                "key": lag_member_key,
                "lag_id": lag_id,
                "egress_disable": egress_disable,
            }

        missing_members = sorted(
            set(expected_members) - set(lag_members_by_port.keys())
        )
        disabled_members = sorted(
            member
            for member, member_info in lag_members_by_port.items()
            if str(member_info.get("egress_disable", "")).lower() == "true"
        )
        lag_ids = {
            member_info["lag_id"]
            for member_info in lag_members_by_port.values()
            if member_info.get("lag_id")
        }
        lag_key_exists = None
        if len(lag_ids) == 1:
            lag_id = list(lag_ids)[0]
            lag_key_exists = _db_key_exists(
                duthost,
                cli_namespace_prefix,
                "ASIC_DB",
                "ASIC_STATE:SAI_OBJECT_TYPE_LAG:{}".format(lag_id),
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
            restored_member in lag_members_by_port and
            len(lag_ids) == 1 and
            lag_key_exists is True
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


def verify_counters_db_lag_member_readable(duthost, cli_namespace_prefix,
                                           portchannel, restored_member):
    """
    Verify COUNTERS_DB exposes restored member and, when present, LAG counters.
    """
    member_field, member_counter = _get_counters_db_counter_value(
        duthost,
        cli_namespace_prefix,
        restored_member,
    )
    logger.info(
        "COUNTERS_DB restored member %s counter %s=%s",
        restored_member,
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
        "Found neighbor %s with addresses %s for DUT port %s. "
        "IPv4=%s IPv6=%s",
        neighbor_name,
        neighbor_addr,
        selected_port,
        neighbor_ipv4_addr,
        neighbor_ipv6_addr,
    )
    return neighbor_name, neighbor_addr, neighbor_ipv4_addr, neighbor_ipv6_addr


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
    raise AssertionError("pytest_assert(False) did not raise")


def _select_ptf_source_port(duthost, asic_namespace, mg_facts,
                            excluded_interfaces):
    """
    Select a frontend PTF source port that is not in the tested PortChannel.
    """
    status_map = get_asic_interface_status_map(duthost, asic_namespace)
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
    raise AssertionError("pytest_assert(False) did not raise")


def _wait_for_restored_member_counters(duthost, cli_namespace_prefix,
                                       restored_member, counter_baseline,
                                       min_tx_packets):
    """
    Wait for show/COUNTERS_DB TX counters on the restored member.
    """
    last_summary = {}

    def _counters_match():
        nonlocal last_summary
        portstat_tx_ok = _get_portstat_counter(
            duthost,
            restored_member,
            "TX_OK",
        )
        counters_db_field, counters_db_value = _get_counters_db_counter_value(
            duthost,
            cli_namespace_prefix,
            restored_member,
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
        logger.info(
            "Restored member counter summary for %s: %s",
            restored_member,
            last_summary,
        )
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
        "Restored member {} counters did not increase as expected; "
        "last_state={}".format(restored_member, last_summary),
    )


def verify_restored_member_dataplane(duthost, runtime, tbinfo, ptfadapter):
    """
    Verify PTF traffic can hash to the restored LAG member.
    """
    asic_index = runtime["selected_asic_index"]
    asic_namespace = runtime["enum_rand_one_asic_namespace"]
    cli_namespace_prefix = runtime["cli_namespace_prefix"]
    portchannel = runtime["selected_portchannel"]
    restored_member = runtime["selected_member_port"]
    expected_members = _expected_portchannel_members(runtime)
    mg_facts = duthost.get_extended_minigraph_facts(
        tbinfo,
        namespace=asic_namespace,
    )
    ptf_indices = mg_facts.get("minigraph_ptf_indices", {})
    pytest_assert(
        restored_member in ptf_indices,
        "No PTF index found for restored member {}".format(restored_member),
    )
    restored_member_ptf_index = ptf_indices[restored_member]
    source_interface, source_ptf_index = _select_ptf_source_port(
        duthost,
        asic_namespace,
        mg_facts,
        set(expected_members),
    )
    neighbor_name, _neighbor_addrs, neighbor_ipv4, _neighbor_ipv6 = (
        _get_interface_neighbor_and_intfs(mg_facts, restored_member)
    )
    pytest_assert(
        neighbor_ipv4,
        "No IPv4 BGP neighbor found for restored member {}".format(
            restored_member
        ),
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
            restored_member,
            restored_member_ptf_index,
        )
        clear_traffic_counters(duthost, asic_index)
        counter_baseline = _get_member_counter_snapshot(
            duthost,
            cli_namespace_prefix,
            restored_member,
        )
        logger.info(
            "Restored member counter baseline for %s: %s",
            restored_member,
            counter_baseline,
        )
        last_error = None
        matched_restored_member = False
        for attempt in range(PORTCHANNEL_HASH_ATTEMPTS):
            sport = 5000 + attempt
            try:
                send_and_verify_traffic(
                    tbinfo,
                    duthost,
                    duthost,
                    asic_index,
                    asic_index,
                    ptfadapter,
                    ptf_sport=source_ptf_index,
                    ptf_dst_ports=[restored_member_ptf_index],
                    ptf_dst_interfaces=[restored_member],
                    dst_ip=traffic_dst_ip,
                    count=PORTCHANNEL_TRAFFIC_COUNT,
                    sport=sport,
                    dport=0x50,
                    verify=True,
                    expect_error=False,
                    clear_stats=False,
                )
                logger.info(
                    "PTF traffic selected restored LAG member %s on hash "
                    "attempt %s using tcp_sport=%s",
                    restored_member,
                    attempt + 1,
                    sport,
                )
                matched_restored_member = True
                break
            except AssertionError as exc:
                last_error = str(exc)
                logger.info(
                    "PTF traffic did not select restored member %s on hash "
                    "attempt %s using tcp_sport=%s: %s",
                    restored_member,
                    attempt + 1,
                    sport,
                    last_error,
                )

        pytest_assert(
            matched_restored_member,
            "PTF traffic did not hash to restored member {} of {} after {} "
            "attempts. Last error={}".format(
                restored_member,
                portchannel,
                PORTCHANNEL_HASH_ATTEMPTS,
                last_error,
            ),
        )
        _wait_for_restored_member_counters(
            duthost,
            cli_namespace_prefix,
            restored_member,
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


def verify_acl_feature_bindings(duthost, asic_namespace, config_facts,
                                portchannel, restored_member):
    """
    Verify existing ACL/Mirror tables bound to the LAG or member remain present.
    """
    bound_tables = {}
    for table_name, table_config in config_facts.get("ACL_TABLE", {}).items():
        table_ports = _normalize_acl_ports(table_config.get("ports"))
        if portchannel in table_ports or restored_member in table_ports:
            bound_tables[table_name] = {
                "type": table_config.get("type"),
                "ports": table_ports,
            }

    if not bound_tables:
        logger.info(
            "No ACL/Everflow/ERSPAN ACL_TABLE binding found for %s or %s; "
            "skipping feature binding read-back",
            portchannel,
            restored_member,
        )
        return

    acl_facts = duthost.acl_facts(
        namespace=asic_namespace,
    )["ansible_facts"]["ansible_acl_facts"]
    cmd_prefix = _namespace_command_prefix(asic_namespace)
    show_cmd = "{} show acl table".format(cmd_prefix).strip()
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
        actual_ports = _normalize_acl_ports(
            acl_facts[table_name].get("ports"),
        )
        missing_ports = sorted(
            set(table_info["ports"]) - set(actual_ports)
        )
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
            "ACL table {} missing from show acl table output".format(
                table_name
            ),
        )
        logger.info(
            "Validated ACL/Mirror binding for table %s type=%s ports=%s",
            table_name,
            table_info["type"],
            table_info["ports"],
        )


def verify_post_restore_operational_state(duthost, runtime, tbinfo, ptfadapter):
    """
    Verify restored LAG member state through CLI, teamd, ASIC_DB, counters and PTF.
    """
    asic_namespace = runtime["enum_rand_one_asic_namespace"]
    cli_namespace_prefix = runtime["cli_namespace_prefix"]
    portchannel = runtime["selected_portchannel"]
    restored_member = runtime["selected_member_port"]
    expected_members = _expected_portchannel_members(runtime)

    with allure.step("Verify PortChannel is up via show interfaces portchannel"):
        pytest_assert(
            _wait_for_portchannel_up_or_log(
                duthost,
                asic_namespace,
                portchannel,
                operation_description="member restore",
            ),
            "PortChannel {} did not come up after member restore".format(
                portchannel,
            ),
        )

    with allure.step("Verify restored member selected in teamd state"):
        verify_teamd_lag_member_state(
            duthost,
            portchannel,
            expected_members,
            restored_member,
            runtime["original_min_links"],
        )

    with allure.step("Verify restored LAG member in ASIC_DB"):
        verify_asic_db_lag_member_state(
            duthost,
            cli_namespace_prefix,
            portchannel,
            expected_members,
            restored_member,
        )

    with allure.step("Verify restored member and LAG counters are readable"):
        verify_counters_db_lag_member_readable(
            duthost,
            cli_namespace_prefix,
            portchannel,
            restored_member,
        )

    with allure.step("Verify ACL/Mirror bindings for restored LAG"):
        verify_acl_feature_bindings(
            duthost,
            asic_namespace,
            runtime["config_facts"],
            portchannel,
            restored_member,
        )

    with allure.step("Verify PTF traffic can hash to restored member"):
        verify_restored_member_dataplane(
            duthost,
            runtime,
            tbinfo,
            ptfadapter,
        )


@pytest.fixture(scope="function")
def portchannel_member_add_context(duthosts,
                                   enum_rand_one_per_hwsku_frontend_hostname):
    """
    Select a T2 chassis 400G PortChannel member add scenario.
    """
    seed_env = os.environ.get("PORTCHANNEL_MEMBER_ADD_RANDOM_SEED")
    if seed_env is not None:
        selection_seed = int(seed_env)
    else:
        selection_seed = random.SystemRandom().randrange(2**31)
    rng = random.Random(selection_seed)
    logging.info(
        "Random selection seed: %s "
        "(set PORTCHANNEL_MEMBER_ADD_RANDOM_SEED to reproduce)",
        selection_seed,
    )

    selected_hwsku, candidates = _frontend_candidates_for_hwsku(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
    )
    logging.info(
        "Selecting from frontend HWSKU=%s candidates=%s",
        selected_hwsku,
        [dut.hostname for dut in candidates],
    )
    selected_context = _collect_portchannel_member_add_options(
        candidates,
        SPEED_400G,
        rng=rng,
    )
    if selected_context is None:
        pytest.skip(
            "No T2 chassis frontend DUT with HWSKU {} has a 400G oper-up "
            "PortChannel with at least two oper-up external members".format(
                selected_hwsku
            )
        )

    logging.info(
        "Selected HWSKU=%s DUT=%s asic=%s portchannel=%s removed_member=%s "
        "remaining_members=%s original_min_links=%s",
        selected_hwsku,
        selected_context["selected_dut_hostname"],
        selected_context["enum_rand_one_asic_namespace"],
        selected_context["selected_portchannel"],
        selected_context["selected_member_port"],
        selected_context["remaining_member_ports"],
        selected_context["original_min_links"],
    )
    return selected_context


@pytest.fixture(autouse=True)
def ignore_portchannel_member_add_loganalyzer_exceptions(
    duthosts,
    portchannel_member_add_context,
    loganalyzer,
):
    """
    Ignore expected transient logs on the DUT selected by this test.
    """
    duthost = duthosts[
        portchannel_member_add_context["selected_dut_hostname"]
    ]
    if loganalyzer and duthost.hostname in loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(
            LOGANALYZER_IGNORE_REGEX
        )


@pytest.fixture(scope="function")
def setup_portchannel_member_add(
    request,
    duthosts,
    portchannel_member_add_context,
    loganalyzer,
    ignore_portchannel_member_add_loganalyzer_exceptions,
):
    """
    Remove one PortChannel member and lower min_links before the add test.
    """
    selected_context = portchannel_member_add_context
    duthost = duthosts[selected_context["selected_dut_hostname"]]
    asic_namespace = selected_context["enum_rand_one_asic_namespace"]
    cli_namespace_prefix = selected_context["cli_namespace_prefix"]
    json_namespace = "" if asic_namespace is None else f"/{asic_namespace}"
    portchannel = selected_context["selected_portchannel"]
    port = selected_context["selected_member_port"]
    remaining_min_links = len(selected_context["remaining_member_ports"])
    saved_admin_status_exists, saved_admin_status = (
        _saved_admin_status_expectation(
            selected_context["config_facts"],
            port,
        )
    )

    def cleanup():
        def restored_state_matches():
            return _portchannel_member_state_matches(
                duthost,
                cli_namespace_prefix,
                selected_context["config_facts"],
                portchannel,
                port,
                member_should_exist=True,
                expected_admin_status=saved_admin_status,
                expected_admin_status_exists=saved_admin_status_exists,
                expected_min_links=selected_context["original_min_links"],
            )

        with allure.step(
            "Restore selected PortChannel member config via GCU"
        ):
            try:
                restore_patch = build_portchannel_member_add_ops(
                    selected_context["config_facts"],
                    json_namespace,
                    portchannel,
                    port,
                    selected_context["original_min_links"],
                )
                _apply_patch_with_dry_run(
                    duthost,
                    restore_patch,
                    f"cleanup restore {port} to {portchannel}",
                    operation_completed=restored_state_matches,
                )
                if not restored_state_matches():
                    raise RuntimeError(
                        "GCU cleanup restore for {} member {} completed but "
                        "CONFIG_DB state still does not match saved config".format(
                            portchannel,
                            port,
                        )
                    )
            except Exception:
                logger.exception(
                    "GCU cleanup failed for %s member %s; falling back to "
                    "minigraph config reload",
                    portchannel,
                    port,
                )
                _restore_dut_via_minigraph(duthost, loganalyzer)

    request.addfinalizer(cleanup)

    with allure.step("Remove one 400G PortChannel member via GCU"):
        remove_patch = build_portchannel_member_remove_ops(
            selected_context["config_facts"],
            json_namespace,
            portchannel,
            port,
        )
        _apply_patch_with_dry_run(
            duthost,
            remove_patch,
            f"remove {port} from {portchannel}",
            operation_completed=lambda: _portchannel_member_state_matches(
                duthost,
                cli_namespace_prefix,
                selected_context["config_facts"],
                portchannel,
                port,
                member_should_exist=False,
                expected_admin_status="down",
                expected_admin_status_exists=True,
                expected_min_links=selected_context["original_min_links"],
            ),
        )

    with allure.step(
        "Verify removed member is admin-down before min_links update"
    ):
        verify_portchannel_member_state(
            duthost,
            cli_namespace_prefix,
            selected_context["config_facts"],
            portchannel,
            port,
            member_should_exist=False,
            expected_admin_status="down",
            expected_admin_status_exists=True,
            expected_min_links=selected_context["original_min_links"],
        )

    with allure.step(
        "Set PortChannel min_links to remaining member count via GCU"
    ):
        min_links_patch = build_portchannel_min_links_ops(
            json_namespace,
            portchannel,
            remaining_min_links,
        )
        _apply_patch_with_dry_run(
            duthost,
            min_links_patch,
            f"set {portchannel} min_links to {remaining_min_links}",
            operation_completed=lambda: _portchannel_member_state_matches(
                duthost,
                cli_namespace_prefix,
                selected_context["config_facts"],
                portchannel,
                port,
                member_should_exist=False,
                expected_admin_status="down",
                expected_admin_status_exists=True,
                expected_min_links=remaining_min_links,
            ),
        )
    with allure.step("Verify base PortChannel config after min_links update"):
        verify_portchannel_member_state(
            duthost,
            cli_namespace_prefix,
            selected_context["config_facts"],
            portchannel,
            port,
            member_should_exist=False,
            expected_admin_status="down",
            expected_admin_status_exists=True,
            expected_min_links=remaining_min_links,
        )
        _wait_for_portchannel_up_or_log(
            duthost,
            asic_namespace,
            portchannel,
            operation_description="min_links update",
        )

    yield selected_context


def test_portchannel_400g_member_add(duthosts, setup_portchannel_member_add,
                                     tbinfo, ptfadapter):
    """
    Add a removed 400G PortChannel member and restore original min_links.
    """
    runtime = setup_portchannel_member_add
    duthost = duthosts[runtime["selected_dut_hostname"]]
    cli_namespace_prefix = runtime["cli_namespace_prefix"]
    asic_namespace = runtime["enum_rand_one_asic_namespace"]
    json_namespace = "" if asic_namespace is None else f"/{asic_namespace}"
    portchannel = runtime["selected_portchannel"]
    port = runtime["selected_member_port"]
    saved_admin_status_exists, saved_admin_status = (
        _saved_admin_status_expectation(
            runtime["config_facts"],
            port,
        )
    )

    with allure.step(
        "Add removed member and restore original min_links via GCU"
    ):
        add_patch = build_portchannel_member_add_ops(
            runtime["config_facts"],
            json_namespace,
            portchannel,
            port,
            runtime["original_min_links"],
        )
        _apply_patch_with_dry_run(
            duthost,
            add_patch,
            f"add {port} to {portchannel} and restore min_links",
            operation_completed=lambda: _portchannel_member_state_matches(
                duthost,
                cli_namespace_prefix,
                runtime["config_facts"],
                portchannel,
                port,
                member_should_exist=True,
                expected_admin_status=saved_admin_status,
                expected_admin_status_exists=saved_admin_status_exists,
                expected_min_links=runtime["original_min_links"],
            ),
        )

    with allure.step(
        "Verify added member and original min_links in CONFIG_DB"
    ):
        verify_portchannel_member_state(
            duthost,
            cli_namespace_prefix,
            runtime["config_facts"],
            portchannel,
            port,
            member_should_exist=True,
            expected_admin_status=saved_admin_status,
            expected_admin_status_exists=saved_admin_status_exists,
            expected_min_links=runtime["original_min_links"],
        )
    with allure.step("Verify restored PortChannel operational state"):
        verify_post_restore_operational_state(
            duthost,
            runtime,
            tbinfo,
            ptfadapter,
        )
