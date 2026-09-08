"""Discover the VNET-activated VXLAN tunnel object capacity of a DUT."""

import logging
from ipaddress import IPv4Address, ip_address

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.common.vxlan_ecmp_utils import Ecmp_Utils


pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.asic("cisco-8000", "broadcom", "mellanox"),
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()

TUNNEL_NAME_PREFIX = "VxlanScale"
VNET_NAME_PREFIX = "VnetScale"
SOURCE_IP_BASE = IPv4Address("198.18.128.1")
VNI_BASE = 10000000
VXLAN_PORT = 4789
CONVERGENCE_TIMEOUT = 60
CONVERGENCE_INTERVAL = 2


@pytest.fixture
def configure_vxlan_switch(rand_selected_front_end_dut):
    """Configure and restore the shared VXLAN switch attributes."""
    dut = rand_selected_front_end_dut
    fields = ("vxlan_port", "vxlan_router_mac")
    previous = {
        field: dut.shell(
            "sonic-db-cli APPL_DB HGET 'SWITCH_TABLE:switch' '{}'".format(field)
        )["stdout"].strip()
        for field in fields
    }
    ecmp_utils.Constants["DEBUG"] = False
    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.configure_vxlan_switch(
        dut,
        vxlan_port=VXLAN_PORT,
        dutmac=dut.facts["router_mac"]
    )
    yield
    restore_port = int(previous["vxlan_port"]) if previous["vxlan_port"] else VXLAN_PORT
    restore_mac = previous["vxlan_router_mac"] or dut.facts["router_mac"]
    ecmp_utils.configure_vxlan_switch(
        dut,
        vxlan_port=restore_port,
        dutmac=restore_mac
    )
    for field, value in previous.items():
        if not value:
            dut.shell(
                "sonic-db-cli APPL_DB HDEL 'SWITCH_TABLE:switch' '{}'".format(field)
            )


def _get_keys(dut, database, pattern):
    result = dut.shell("sonic-db-cli {} KEYS '{}'".format(database, pattern))
    return [line.strip() for line in result["stdout_lines"] if line.strip()]


def _count_keys(dut, database, pattern):
    return len(_get_keys(dut, database, pattern))


def _count_asic_vxlan_tunnels(dut):
    result = dut.shell(
        "count=0; "
        "for key in $(sonic-db-cli ASIC_DB KEYS "
        "'ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL:oid*'); do "
        "type=$(sonic-db-cli ASIC_DB HGET \"$key\" SAI_TUNNEL_ATTR_TYPE); "
        "[ \"$type\" = SAI_TUNNEL_TYPE_VXLAN ] && count=$((count + 1)); "
        "done; echo $count"
    )
    return int(result["stdout"].strip())


def _get_vxlan_counts(dut):
    return {
        "config_tunnel": _count_keys(
            dut, "CONFIG_DB", "VXLAN_TUNNEL|{}*".format(TUNNEL_NAME_PREFIX)
        ),
        "app_tunnel": _count_keys(
            dut, "APPL_DB", "VXLAN_TUNNEL_TABLE:{}*".format(TUNNEL_NAME_PREFIX)
        ),
        "config_vnet": _count_keys(
            dut, "CONFIG_DB", "VNET|{}*".format(VNET_NAME_PREFIX)
        ),
        "app_vnet": _count_keys(
            dut, "APPL_DB", "VNET_TABLE:{}*".format(VNET_NAME_PREFIX)
        ),
        "asic_tunnel": _count_asic_vxlan_tunnels(dut),
        "asic_term": _count_keys(
            dut,
            "ASIC_DB",
            "ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY:*"
        ),
        "asic_map": _count_keys(
            dut,
            "ASIC_DB",
            "ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_MAP:oid*"
        ),
        "asic_map_entry": _count_keys(
            dut,
            "ASIC_DB",
            "ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY:oid*"
        ),
        "asic_vr": _count_keys(
            dut,
            "ASIC_DB",
            "ASIC_STATE:SAI_OBJECT_TYPE_VIRTUAL_ROUTER:oid*"
        )
    }


def _expected_counts(baseline, expected):
    counts = {
        "config_tunnel": baseline["config_tunnel"] + expected,
        "app_tunnel": baseline["app_tunnel"] + expected,
        "config_vnet": baseline["config_vnet"] + expected,
        "app_vnet": baseline["app_vnet"] + expected,
        "asic_tunnel": baseline["asic_tunnel"] + expected,
        "asic_term": baseline["asic_term"] + expected,
        "asic_map": baseline["asic_map"] + (4 * expected),
        "asic_map_entry": baseline["asic_map_entry"] + (2 * expected),
        "asic_vr": baseline["asic_vr"]
    }
    return counts


def _has_programmed_vxlan_tunnels(dut, baseline, expected):
    counts = _get_vxlan_counts(dut)
    expected_counts = _expected_counts(baseline, expected)
    db_ready = all(
        counts[key] == expected_counts[key]
        for key in ("config_tunnel", "app_tunnel", "config_vnet", "app_vnet")
    )
    asic_ready = all(
        counts[key] >= expected_counts[key]
        for key in ("asic_tunnel", "asic_term", "asic_map", "asic_map_entry")
    )
    return db_ready and asic_ready


def _has_exact_vxlan_count(dut, baseline, expected):
    return _get_vxlan_counts(dut) == _expected_counts(baseline, expected)


def _has_expected_db_state(counts, baseline, expected):
    return all(
        counts[key] == baseline[key] + expected
        for key in ("config_tunnel", "app_tunnel", "config_vnet", "app_vnet")
    )


def _has_deactivated_vxlan_tunnels(dut, baseline, expected_vnets, expected_tunnels):
    counts = _get_vxlan_counts(dut)
    expected_counts = _expected_counts(baseline, expected_vnets)
    expected_counts["config_tunnel"] = baseline["config_tunnel"] + expected_tunnels
    expected_counts["app_tunnel"] = baseline["app_tunnel"] + expected_tunnels
    return counts == expected_counts


def _has_stable_asic_counts(dut, tracker):
    counts = _get_vxlan_counts(dut)
    current = (
        counts["asic_tunnel"],
        counts["asic_term"],
        counts["asic_map"],
        counts["asic_map_entry"],
        counts["asic_vr"]
    )
    if current == tracker["last"]:
        tracker["stable_polls"] += 1
    else:
        tracker["last"] = current
        tracker["stable_polls"] = 1
    return tracker["stable_polls"] >= 3


def _tunnel_name(index):
    return "{}{:04d}".format(TUNNEL_NAME_PREFIX, index)


def _vnet_name(index):
    return "{}{:04d}".format(VNET_NAME_PREFIX, index)


def _tunnel_config_command(index, source_ip=None, ttl_mode=None):
    fields = "src_ip {}".format(source_ip or SOURCE_IP_BASE + index)
    if ttl_mode:
        fields += " ttl_mode {}".format(ttl_mode)
    return "sonic-db-cli CONFIG_DB HSET 'VXLAN_TUNNEL|{}' {}".format(
        _tunnel_name(index),
        fields
    )


def _get_ttl_mode(dut):
    return "pipe" if dut.facts.get("asic_type") == "cisco-8000" else None


def _vnet_config_command(index):
    return (
        "sonic-db-cli CONFIG_DB HSET 'VNET|{vnet}' "
        "vxlan_tunnel {tunnel} vni {vni} scope default"
    ).format(
        vnet=_vnet_name(index),
        tunnel=_tunnel_name(index),
        vni=VNI_BASE + index
    )


def _remove_vnets(dut, indices):
    indices = list(indices)
    if indices:
        dut.shell_cmds(
            cmds=[
                "sonic-db-cli CONFIG_DB DEL 'VNET|{}'".format(_vnet_name(index))
                for index in indices
            ],
            continue_on_fail=True,
            module_ignore_errors=True
        )


def _remove_tunnels(dut, indices):
    indices = list(indices)
    if indices:
        dut.shell_cmds(
            cmds=[
                "sonic-db-cli CONFIG_DB DEL 'VXLAN_TUNNEL|{}'".format(
                    _tunnel_name(index)
                )
                for index in indices
            ],
            continue_on_fail=True,
            module_ignore_errors=True
        )


def _remove_vxlan_range(dut, baseline, start_index, start_offset, end_offset):
    indices = list(range(start_index + start_offset, start_index + end_offset))
    vnets_removed = False
    try:
        _remove_vnets(dut, indices)
        vnets_removed = wait_until(
            CONVERGENCE_TIMEOUT,
            CONVERGENCE_INTERVAL,
            0,
            _has_deactivated_vxlan_tunnels,
            dut,
            baseline,
            start_offset,
            end_offset
        )
    finally:
        _remove_tunnels(dut, indices)

    fully_removed = wait_until(
        CONVERGENCE_TIMEOUT,
        CONVERGENCE_INTERVAL,
        0,
        _has_exact_vxlan_count,
        dut,
        baseline,
        start_offset
    )
    if not vnets_removed:
        logger.warning(
            "TUNNEL_SCALE_CLEANUP_STAGE tunnel_type=vxlan "
            "vnet_deactivation_converged=false final_restoration=%s",
            fully_removed
        )
    return fully_removed


def _get_next_index(dut):
    key_specs = [
        ("CONFIG_DB", "VXLAN_TUNNEL|{}*".format(TUNNEL_NAME_PREFIX), TUNNEL_NAME_PREFIX),
        ("APPL_DB", "VXLAN_TUNNEL_TABLE:{}*".format(TUNNEL_NAME_PREFIX), TUNNEL_NAME_PREFIX),
        ("CONFIG_DB", "VNET|{}*".format(VNET_NAME_PREFIX), VNET_NAME_PREFIX),
        ("APPL_DB", "VNET_TABLE:{}*".format(VNET_NAME_PREFIX), VNET_NAME_PREFIX)
    ]
    indices = []
    for database, pattern, prefix in key_specs:
        for key in _get_keys(dut, database, pattern):
            suffix = key.rsplit(prefix, 1)[-1]
            if suffix.isdigit():
                indices.append(int(suffix))
    return max(indices, default=-1) + 1


def _get_config_field_values(dut, table, field):
    result = dut.shell(
        "for key in $(sonic-db-cli CONFIG_DB KEYS '{}|*'); do "
        "sonic-db-cli CONFIG_DB HGET \"$key\" {}; done".format(table, field)
    )
    return {line.strip() for line in result["stdout_lines"] if line.strip()}


def _validate_generated_values(dut, start_index, limit):
    generated_ips = {
        str(SOURCE_IP_BASE + index)
        for index in range(start_index, start_index + limit)
    }
    configured_ips = _get_config_field_values(dut, "VXLAN_TUNNEL", "src_ip")
    pytest_assert(
        generated_ips.isdisjoint(configured_ips),
        "Generated VXLAN source IP range overlaps existing VXLAN_TUNNEL configuration"
    )

    generated_vnis = {
        str(VNI_BASE + index)
        for index in range(start_index, start_index + limit)
    }
    configured_vnis = _get_config_field_values(dut, "VNET", "vni")
    pytest_assert(
        generated_vnis.isdisjoint(configured_vnis),
        "Generated VXLAN VNI range overlaps existing VNET configuration"
    )
    pytest_assert(
        VNI_BASE + start_index + limit - 1 <= 16777215,
        "Generated VXLAN VNI range exceeds the 24-bit VNI maximum"
    )


def _get_loopback_ipv4(dut, tbinfo):
    minigraph_facts = dut.get_extended_minigraph_facts(tbinfo)
    for interface in minigraph_facts["minigraph_lo_interfaces"]:
        address = ip_address(interface["addr"])
        if address.version == 4:
            return address
    pytest.fail("No IPv4 loopback address is available for VXLAN preflight")


def _log_vxlan_creation_diagnostics(dut, index, stage):
    commands = {
        "switch_table": "sonic-db-cli APPL_DB HGETALL 'SWITCH_TABLE:switch'",
        "config_tunnel": (
            "sonic-db-cli CONFIG_DB HGETALL 'VXLAN_TUNNEL|{}'"
        ).format(_tunnel_name(index)),
        "app_tunnel": (
            "sonic-db-cli APPL_DB HGETALL 'VXLAN_TUNNEL_TABLE:{}'"
        ).format(_tunnel_name(index)),
        "config_vnet": (
            "sonic-db-cli CONFIG_DB HGETALL 'VNET|{}'"
        ).format(_vnet_name(index)),
        "app_vnet": (
            "sonic-db-cli APPL_DB HGETALL 'VNET_TABLE:{}'"
        ).format(_vnet_name(index)),
        "asic_objects": (
            "for type in TUNNEL TUNNEL_TERM_TABLE_ENTRY TUNNEL_MAP "
            "TUNNEL_MAP_ENTRY; do echo \"=== $type ===\"; "
            "sonic-db-cli ASIC_DB KEYS \"ASIC_STATE:SAI_OBJECT_TYPE_${type}:*\"; "
            "done"
        ),
        "sairedis": "sudo tail -n 300 /var/log/swss/sairedis.rec",
        "syncd": (
            "docker logs --since 10m syncd 2>&1 | "
            "grep -Ei 'vxlan|tunnel|SAI_STATUS|not implemented|unsupported' | "
            "tail -n 200"
        ),
        "orchagent": (
            "sudo grep -Ei 'vxlan|tunnel|SAI_STATUS|not implemented|unsupported' "
            "/var/log/syslog | tail -n 200"
        )
    }
    for name, command in commands.items():
        result = dut.shell(command, module_ignore_errors=True)
        logger.error(
            "VXLAN_CREATION_DIAGNOSTIC stage=%s source=%s\n%s",
            stage,
            name,
            result.get("stdout", "")
        )


def _run_hardware_preflight(dut, baseline, start_index, source_ip):
    logger.warning(
        "TUNNEL_SCALE_PREFLIGHT tunnel_type=vxlan source=local_loopback "
        "start_index=%d",
        start_index
    )
    cleanup_ok = False
    try:
        dut.shell(
            _tunnel_config_command(
                start_index,
                source_ip=source_ip,
                ttl_mode=_get_ttl_mode(dut)
            )
        )
        app_ready = wait_until(
            CONVERGENCE_TIMEOUT,
            CONVERGENCE_INTERVAL,
            0,
            lambda: (
                _count_keys(
                    dut,
                    "APPL_DB",
                    "VXLAN_TUNNEL_TABLE:{}*".format(TUNNEL_NAME_PREFIX)
                )
                == baseline["app_tunnel"] + 1
            )
        )
        if not app_ready:
            _log_vxlan_creation_diagnostics(
                dut, start_index, "preflight_app_propagation"
            )
        pytest_assert(
            app_ready,
            "Loopback-sourced VXLAN preflight did not reach APPL_DB"
        )

        dut.shell(_vnet_config_command(start_index))
        asic_ready = wait_until(
            CONVERGENCE_TIMEOUT,
            CONVERGENCE_INTERVAL,
            0,
            _has_programmed_vxlan_tunnels,
            dut,
            baseline,
            1
        )
        if not asic_ready:
            _log_vxlan_creation_diagnostics(
                dut, start_index, "preflight_asic_programming"
            )
        pytest_assert(
            asic_ready,
            "Loopback-sourced VXLAN preflight did not create the expected ASIC graph"
        )
        counts = _get_vxlan_counts(dut)
        pytest_assert(
            counts["asic_vr"] == baseline["asic_vr"],
            "Default-scope VXLAN preflight unexpectedly changed virtual-router count"
        )
        logger.warning(
            "TUNNEL_SCALE_PREFLIGHT tunnel_type=vxlan passed=true counts=%s",
            counts
        )
    finally:
        cleanup_ok = _remove_vxlan_range(
            dut,
            baseline,
            start_index,
            0,
            1
        )
        logger.warning(
            "TUNNEL_SCALE_PREFLIGHT_CLEANUP tunnel_type=vxlan restored=%s "
            "baseline=%s current=%s",
            cleanup_ok,
            baseline,
            _get_vxlan_counts(dut)
        )
    pytest_assert(cleanup_ok, "VXLAN hardware preflight cleanup did not restore baseline")


def _log_capacity_failure(dut, baseline, programmed, attempted):
    counts = _get_vxlan_counts(dut)
    existing = baseline["config_tunnel"]
    logger.warning(
        "TUNNEL_SCALE_RESULT tunnel_type=vxlan preexisting_generated=%d "
        "additional_programmed=%d maximum_generated_total=%d "
        "first_failed_generated_total=%d counts=%s baseline=%s",
        existing,
        programmed,
        existing + programmed,
        existing + attempted,
        counts,
        baseline
    )
    diagnostics = dut.shell(
        "sudo grep -Ei 'vxlan|tunnel|SAI_STATUS|resource|capacity|table full|no space' "
        "/var/log/syslog | tail -n 200",
        module_ignore_errors=True
    )
    logger.warning("VXLAN capacity diagnostics:\n%s", diagnostics.get("stdout", ""))
    return programmed


def _fail_non_capacity_convergence(dut, baseline, target, stage):
    counts = _get_vxlan_counts(dut)
    logger.error(
        "TUNNEL_SCALE_ERROR tunnel_type=vxlan stage=%s target=%d counts=%s baseline=%s",
        stage,
        target,
        counts,
        baseline
    )
    diagnostics = dut.shell(
        "sudo grep -Ei 'vxlan|tunnel|SAI_STATUS|resource|capacity|table full|no space' "
        "/var/log/syslog | tail -n 200",
        module_ignore_errors=True
    )
    logger.error("VXLAN convergence diagnostics:\n%s", diagnostics.get("stdout", ""))
    pytest.fail(
        "VXLAN {} did not converge at target {}; this is not a hardware "
        "capacity measurement".format(stage, target)
    )


def _create_tunnel_batch(dut, baseline, start_index, batch_start, batch_end):
    dut.shell_cmds(
        cmds=[
            _tunnel_config_command(
                start_index + offset,
                ttl_mode=_get_ttl_mode(dut)
            )
            for offset in range(batch_start, batch_end)
        ]
    )
    return wait_until(
        CONVERGENCE_TIMEOUT,
        CONVERGENCE_INTERVAL,
        0,
        lambda: (
            _count_keys(
                dut,
                "APPL_DB",
                "VXLAN_TUNNEL_TABLE:{}*".format(TUNNEL_NAME_PREFIX)
            )
            == baseline["app_tunnel"] + batch_end
        )
    )


def _activate_vnet_batch(dut, baseline, start_index, batch_start, batch_end):
    dut.shell_cmds(
        cmds=[
            _vnet_config_command(start_index + offset)
            for offset in range(batch_start, batch_end)
        ]
    )
    return wait_until(
        CONVERGENCE_TIMEOUT,
        CONVERGENCE_INTERVAL,
        0,
        _has_programmed_vxlan_tunnels,
        dut,
        baseline,
        batch_end
    )


def _find_exact_boundary(dut, baseline, start_index, batch_start, batch_end):
    logger.warning(
        "TUNNEL_SCALE_REFINEMENT tunnel_type=vxlan batch_start=%d batch_end=%d",
        batch_start + 1,
        batch_end
    )
    pytest_assert(
        _remove_vxlan_range(dut, baseline, start_index, batch_start, batch_end),
        "Failed to restore VXLAN count {} before boundary refinement".format(batch_start)
    )

    for offset in range(batch_start, batch_end):
        target = offset + 1
        tunnel_ready = _create_tunnel_batch(
            dut,
            baseline,
            start_index,
            offset,
            target
        )
        if not tunnel_ready:
            wait_critical_processes(dut)
            _fail_non_capacity_convergence(
                dut,
                baseline,
                target,
                "VXLAN_TUNNEL_TABLE propagation"
            )

        if _activate_vnet_batch(
                dut,
                baseline,
                start_index,
                offset,
                target):
            counts = _get_vxlan_counts(dut)
            if counts["asic_vr"] != baseline["asic_vr"]:
                _fail_non_capacity_convergence(
                    dut,
                    baseline,
                    target,
                    "default-scope VNET virtual-router footprint"
                )
            logger.warning(
                "TUNNEL_SCALE_REFINEMENT_PROGRESS tunnel_type=vxlan "
                "additional_programmed=%d",
                target
            )
            continue

        wait_critical_processes(dut)
        counts = _get_vxlan_counts(dut)
        if not _has_expected_db_state(counts, baseline, target):
            _fail_non_capacity_convergence(
                dut,
                baseline,
                target,
                "VNET_TABLE propagation"
            )
        if target == 1:
            _fail_non_capacity_convergence(
                dut,
                baseline,
                target,
                "VXLAN ASIC footprint calibration"
            )
        return _log_capacity_failure(dut, baseline, offset, target), target

    logger.warning(
        "TUNNEL_SCALE_REFINEMENT_COMPLETE tunnel_type=vxlan additional_programmed=%d",
        batch_end
    )
    return batch_end, None


def test_vxlan_tunnel_scale(
        rand_selected_front_end_dut,
        request,
        record_property,
        tbinfo,
        configure_vxlan_switch):
    """Discover how many distinct VNET-activated VXLAN tunnels can be programmed."""
    dut = rand_selected_front_end_dut
    limit = request.config.getoption("--vxlan-tunnel-scale-limit")
    batch_size = request.config.getoption("--vxlan-tunnel-scale-batch-size")

    pytest_assert(limit > 0, "--vxlan-tunnel-scale-limit must be greater than zero")
    pytest_assert(
        batch_size > 0,
        "--vxlan-tunnel-scale-batch-size must be greater than zero"
    )
    pytest_assert(
        batch_size <= limit,
        "--vxlan-tunnel-scale-batch-size must not exceed --vxlan-tunnel-scale-limit"
    )
    if int(dut.facts["num_asic"]) != 1:
        pytest.skip("VXLAN tunnel scale test currently supports only single-ASIC DUTs")

    stability_tracker = {"last": None, "stable_polls": 0}
    pytest_assert(
        wait_until(
            CONVERGENCE_TIMEOUT,
            CONVERGENCE_INTERVAL,
            CONVERGENCE_INTERVAL,
            _has_stable_asic_counts,
            dut,
            stability_tracker
        ),
        "ASIC VXLAN object counts did not stabilize before capacity discovery"
    )
    baseline = _get_vxlan_counts(dut)
    pytest_assert(
        baseline["config_tunnel"] == baseline["app_tunnel"],
        "Existing generated VXLAN_TUNNEL entries are inconsistent: {}".format(baseline)
    )
    pytest_assert(
        baseline["config_vnet"] == baseline["app_vnet"],
        "Existing generated VNET entries are inconsistent: {}".format(baseline)
    )
    pytest_assert(
        baseline["config_tunnel"] == baseline["config_vnet"],
        "Existing generated VXLAN tunnel and VNET counts are inconsistent: {}".format(
            baseline
        )
    )

    start_index = _get_next_index(dut)
    _validate_generated_values(dut, start_index, limit)
    _run_hardware_preflight(
        dut,
        baseline,
        start_index,
        _get_loopback_ipv4(dut, tbinfo)
    )
    attempted = 0
    programmed = 0
    hit_limit = False
    cleanup_ok = False
    peak_counts = baseline

    logger.warning(
        "TUNNEL_SCALE_START tunnel_type=vxlan limit=%d batch_size=%d "
        "start_index=%d baseline=%s asic_type=%s hwsku=%s "
        "dependency_pattern='VXLAN_TUNNEL+default-scope VNET' "
        "expected_asic_per_tunnel='tunnel:1,term:1,map:4,map_entry:2,vr:0'",
        limit,
        batch_size,
        start_index,
        baseline,
        dut.facts.get("asic_type"),
        dut.facts.get("hwsku")
    )

    try:
        while attempted < limit:
            batch_start = attempted
            batch_end = min(batch_start + batch_size, limit)
            attempted = batch_end

            tunnel_ready = _create_tunnel_batch(
                dut,
                baseline,
                start_index,
                batch_start,
                batch_end
            )
            converged = tunnel_ready and _activate_vnet_batch(
                dut,
                baseline,
                start_index,
                batch_start,
                batch_end
            )
            if not converged:
                programmed, first_failed_target = _find_exact_boundary(
                    dut,
                    baseline,
                    start_index,
                    batch_start,
                    batch_end
                )
                if first_failed_target is not None:
                    attempted = first_failed_target
                    hit_limit = True
                    break
                attempted = batch_end

            programmed = attempted
            peak_counts = _get_vxlan_counts(dut)
            if peak_counts["asic_vr"] != baseline["asic_vr"]:
                _fail_non_capacity_convergence(
                    dut,
                    baseline,
                    programmed,
                    "default-scope VNET virtual-router footprint"
                )
            logger.warning(
                "TUNNEL_SCALE_PROGRESS tunnel_type=vxlan additional_programmed=%d "
                "generated_total=%d counts=%s",
                programmed,
                baseline["config_tunnel"] + programmed,
                peak_counts
            )
    finally:
        cleanup_ok = _remove_vxlan_range(
            dut,
            baseline,
            start_index,
            0,
            attempted
        )
        current = _get_vxlan_counts(dut)
        if cleanup_ok:
            logger.warning(
                "TUNNEL_SCALE_CLEANUP tunnel_type=vxlan restored=true "
                "baseline=%s current=%s",
                baseline,
                current
            )
        else:
            logger.error(
                "VXLAN cleanup did not converge; baseline=%s current=%s",
                baseline,
                current
            )

    wait_critical_processes(dut)

    if hit_limit:
        result = (
            "tunnel_type=vxlan preexisting_generated={} additional_programmed={} "
            "maximum_generated_total={} first_failed_generated_total={}"
        ).format(
            baseline["config_tunnel"],
            programmed,
            baseline["config_tunnel"] + programmed,
            baseline["config_tunnel"] + attempted
        )
        record_property("tunnel_scale_result", result)
        logger.warning(
            "VXLAN generated tunnel capacity is %d objects (%d preexisting plus %d added); "
            "the first unsupported generated total is %d",
            baseline["config_tunnel"] + programmed,
            baseline["config_tunnel"],
            programmed,
            baseline["config_tunnel"] + attempted
        )
    else:
        result = (
            "tunnel_type=vxlan preexisting_generated={} additional_programmed={} "
            "minimum_generated_total={} safety_limit_reached=true"
        ).format(
            baseline["config_tunnel"],
            programmed,
            baseline["config_tunnel"] + programmed
        )
        record_property("tunnel_scale_result", result)
        logger.warning(
            "VXLAN generated tunnel capacity is at least %d objects "
            "(%d preexisting plus %d added); the configured safety limit was reached",
            baseline["config_tunnel"] + programmed,
            baseline["config_tunnel"],
            programmed
        )
        logger.warning(
            "TUNNEL_SCALE_RESULT tunnel_type=vxlan preexisting_generated=%d "
            "additional_programmed=%d minimum_generated_total=%d "
            "peak_counts=%s safety_limit_reached=true",
            baseline["config_tunnel"],
            programmed,
            baseline["config_tunnel"] + programmed,
            peak_counts
        )

    pytest_assert(
        cleanup_ok,
        "Generated VXLAN objects were not fully removed; baseline={} current={}".format(
            baseline,
            _get_vxlan_counts(dut)
        )
    )
