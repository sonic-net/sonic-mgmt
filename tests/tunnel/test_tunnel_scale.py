"""Discover the IP-in-IP tunnel object capacity of a DUT."""

import logging
from ipaddress import IPv4Address

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.stress_test,
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)

TUNNEL_NAME_PREFIX = "TunnelScale"
SOURCE_IP_BASE = IPv4Address("198.18.0.1")
DESTINATION_IP_BASE = IPv4Address("198.19.0.1")
CONVERGENCE_TIMEOUT = 60
CONVERGENCE_INTERVAL = 2


def _count_keys(dut, database, pattern):
    result = dut.shell("sonic-db-cli {} KEYS '{}'".format(database, pattern))
    return len([line for line in result["stdout_lines"] if line.strip()])


def _get_tunnel_counts(dut):
    return {
        "config": _count_keys(dut, "CONFIG_DB", "TUNNEL|{}*".format(TUNNEL_NAME_PREFIX)),
        "app": _count_keys(dut, "APPL_DB", "TUNNEL_DECAP_TABLE:{}*".format(TUNNEL_NAME_PREFIX)),
        "asic_tunnel": _count_keys(
            dut,
            "ASIC_DB",
            "ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL:oid*"
        ),
        "asic_term": _count_keys(
            dut,
            "ASIC_DB",
            "ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY:*"
        )
    }


def _has_programmed_tunnels(dut, baseline, expected):
    counts = _get_tunnel_counts(dut)
    return (
        counts["config"] == baseline["config"] + expected
        and counts["app"] == baseline["app"] + expected
        and counts["asic_tunnel"] >= baseline["asic_tunnel"] + expected
        and counts["asic_term"] >= baseline["asic_term"] + expected
    )


def _has_exact_tunnel_count(dut, baseline, expected):
    counts = _get_tunnel_counts(dut)
    return (
        counts["config"] == baseline["config"] + expected
        and counts["app"] == baseline["app"] + expected
        and counts["asic_tunnel"] == baseline["asic_tunnel"] + expected
        and counts["asic_term"] == baseline["asic_term"] + expected
    )


def _has_removed_tunnels(dut, baseline):
    counts = _get_tunnel_counts(dut)
    return counts == baseline


def _has_stable_asic_counts(dut, tracker):
    counts = _get_tunnel_counts(dut)
    current = (counts["asic_tunnel"], counts["asic_term"])
    if current == tracker["last"]:
        tracker["stable_polls"] += 1
    else:
        tracker["last"] = current
        tracker["stable_polls"] = 1
    return tracker["stable_polls"] >= 3


def _tunnel_config_command(index):
    name = "{}{:04d}".format(TUNNEL_NAME_PREFIX, index)
    source_ip = SOURCE_IP_BASE + index
    destination_ip = DESTINATION_IP_BASE + index
    return (
        "sonic-db-cli CONFIG_DB HSET 'TUNNEL|{name}' "
        "tunnel_type IPINIP src_ip {source_ip} dst_ip {destination_ip} "
        "dscp_mode uniform ecn_mode copy_from_outer "
        "encap_ecn_mode standard ttl_mode pipe"
    ).format(name=name, source_ip=source_ip, destination_ip=destination_ip)


def _tunnel_delete_command(index):
    return "sonic-db-cli CONFIG_DB DEL 'TUNNEL|{}{:04d}'".format(
        TUNNEL_NAME_PREFIX,
        index
    )


def _tunnel_app_delete_command(index):
    return "sonic-db-cli APPL_DB DEL 'TUNNEL_DECAP_TABLE:{}{:04d}'".format(
        TUNNEL_NAME_PREFIX,
        index
    )


def _remove_tunnels(dut, indices):
    indices = list(indices)
    if not indices:
        return
    dut.shell_cmds(
        cmds=[_tunnel_delete_command(index) for index in indices]
        + [_tunnel_app_delete_command(index) for index in indices],
        continue_on_fail=True,
        module_ignore_errors=True
    )


def _get_next_tunnel_index(dut):
    result = dut.shell(
        "sonic-db-cli CONFIG_DB KEYS 'TUNNEL|{0}*'; "
        "sonic-db-cli APPL_DB KEYS 'TUNNEL_DECAP_TABLE:{0}*'".format(TUNNEL_NAME_PREFIX)
    )
    indices = []
    for key in result["stdout_lines"]:
        suffix = key.rsplit(TUNNEL_NAME_PREFIX, 1)[-1]
        if suffix.isdigit():
            indices.append(int(suffix))
    return max(indices, default=-1) + 1


def _log_capacity_failure(dut, programmed, attempted, counts, baseline):
    existing = baseline["config"]
    logger.warning(
        "TUNNEL_SCALE_RESULT tunnel_type=ipinip preexisting_generated=%d additional_programmed=%d "
        "maximum_generated_total=%d first_failed_generated_total=%d "
        "config=%d app=%d asic_tunnel_delta=%d asic_term_delta=%d "
        "final_asic_tunnel_count=%d final_asic_term_count=%d",
        existing,
        programmed,
        existing + programmed,
        existing + attempted,
        counts["config"],
        counts["app"],
        counts["asic_tunnel"] - baseline["asic_tunnel"],
        counts["asic_term"] - baseline["asic_term"],
        counts["asic_tunnel"],
        counts["asic_term"]
    )
    diagnostics = dut.shell(
        "sudo grep -Ei 'tunnel|SAI_STATUS|resource|capacity|table full|no space' "
        "/var/log/syslog | tail -n 100",
        module_ignore_errors=True
    )
    logger.warning("Tunnel capacity diagnostics:\n%s", diagnostics.get("stdout", ""))
    return programmed


def _find_exact_boundary(dut, baseline, start_index, batch_start, batch_end):
    logger.info(
        "Batch ending at %d did not converge; retrying tunnels %d through %d individually",
        batch_end,
        batch_start + 1,
        batch_end
    )
    _remove_tunnels(
        dut,
        range(start_index + batch_start, start_index + batch_end)
    )
    pytest_assert(
        wait_until(
            CONVERGENCE_TIMEOUT,
            CONVERGENCE_INTERVAL,
            0,
            _has_exact_tunnel_count,
            dut,
            baseline,
            batch_start
        ),
        "Failed to restore the last confirmed tunnel count ({}) before boundary refinement".format(
            batch_start
        )
    )

    for offset in range(batch_start, batch_end):
        target = offset + 1
        dut.shell(_tunnel_config_command(start_index + offset))
        if wait_until(
                CONVERGENCE_TIMEOUT,
                CONVERGENCE_INTERVAL,
                0,
                _has_programmed_tunnels,
                dut,
                baseline,
                target):
            logger.info("Individually programmed tunnel %d", target)
            continue

        counts = _get_tunnel_counts(dut)
        wait_critical_processes(dut)
        programmed = _log_capacity_failure(dut, offset, target, counts, baseline)
        return programmed, target

    logger.info(
        "All tunnels in the failed batch converged individually; resuming batch discovery at %d",
        batch_end
    )
    return batch_end, None


def test_ipinip_tunnel_scale(
        rand_selected_dut,
        request,
        record_property):
    """Discover how many distinct IP-in-IP tunnels can be programmed in ASIC_DB."""
    dut = rand_selected_dut
    limit = request.config.getoption("--tunnel-scale-limit")
    batch_size = request.config.getoption("--tunnel-scale-batch-size")

    pytest_assert(limit > 0, "--tunnel-scale-limit must be greater than zero")
    pytest_assert(batch_size > 0, "--tunnel-scale-batch-size must be greater than zero")
    pytest_assert(
        batch_size <= limit,
        "--tunnel-scale-batch-size must not exceed --tunnel-scale-limit"
    )

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
        "ASIC tunnel counts did not stabilize before capacity discovery"
    )
    baseline = _get_tunnel_counts(dut)
    pytest_assert(
        baseline["config"] == baseline["app"],
        "Existing {} entries are inconsistent between CONFIG_DB and APPL_DB: {}".format(
            TUNNEL_NAME_PREFIX,
            baseline
        )
    )
    start_index = _get_next_tunnel_index(dut)
    attempted = 0
    programmed = 0
    hit_limit = False
    cleanup_ok = False

    logger.warning(
        "TUNNEL_SCALE_START tunnel_type=ipinip limit=%d batch_size=%d "
        "start_index=%d baseline=%s",
        limit,
        batch_size,
        start_index,
        baseline
    )

    try:
        while attempted < limit:
            batch_start = attempted
            batch_end = min(batch_start + batch_size, limit)
            commands = [
                _tunnel_config_command(start_index + offset)
                for offset in range(batch_start, batch_end)
            ]
            attempted = batch_end
            dut.shell_cmds(cmds=commands)

            converged = wait_until(
                CONVERGENCE_TIMEOUT,
                CONVERGENCE_INTERVAL,
                0,
                _has_programmed_tunnels,
                dut,
                baseline,
                attempted
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
            logger.warning(
                "TUNNEL_SCALE_PROGRESS tunnel_type=ipinip additional_programmed=%d "
                "generated_total=%d",
                programmed,
                baseline["config"] + programmed
            )
    finally:
        _remove_tunnels(dut, range(start_index, start_index + attempted))
        cleanup_ok = wait_until(
            CONVERGENCE_TIMEOUT,
            CONVERGENCE_INTERVAL,
            0,
            _has_removed_tunnels,
            dut,
            baseline
        )
        if not cleanup_ok:
            logger.error(
                "Tunnel cleanup did not converge; baseline=%s current=%s",
                baseline,
                _get_tunnel_counts(dut)
            )
        else:
            logger.warning(
                "TUNNEL_SCALE_CLEANUP tunnel_type=ipinip restored=true baseline=%s current=%s",
                baseline,
                _get_tunnel_counts(dut)
            )

    wait_critical_processes(dut)
    if hit_limit:
        result = (
            "tunnel_type=ipinip preexisting_generated={} additional_programmed={} "
            "maximum_generated_total={} first_failed_generated_total={}"
        ).format(
            baseline["config"],
            programmed,
            baseline["config"] + programmed,
            baseline["config"] + attempted
        )
        record_property("tunnel_scale_result", result)
        logger.warning(
            "IP-in-IP generated tunnel capacity is %d objects (%d preexisting plus %d added); "
            "the first unsupported generated total is %d",
            baseline["config"] + programmed,
            baseline["config"],
            programmed,
            baseline["config"] + attempted
        )
    else:
        result = (
            "tunnel_type=ipinip preexisting_generated={} additional_programmed={} "
            "minimum_generated_total={} safety_limit_reached=true"
        ).format(
            baseline["config"],
            programmed,
            baseline["config"] + programmed
        )
        record_property("tunnel_scale_result", result)
        logger.warning(
            "IP-in-IP generated tunnel capacity is at least %d objects "
            "(%d preexisting plus %d added); the configured safety limit was reached",
            baseline["config"] + programmed,
            baseline["config"],
            programmed
        )
        logger.warning(
            "TUNNEL_SCALE_RESULT tunnel_type=ipinip preexisting_generated=%d additional_programmed=%d "
            "minimum_generated_total=%d final_asic_tunnel_count=%d "
            "final_asic_term_count=%d safety_limit_reached=true",
            baseline["config"],
            programmed,
            baseline["config"] + programmed,
            baseline["asic_tunnel"] + programmed,
            baseline["asic_term"] + programmed
        )

    pytest_assert(
        cleanup_ok,
        "Generated tunnel objects were not fully removed; baseline={} current={}".format(
            baseline,
            _get_tunnel_counts(dut)
        )
    )
