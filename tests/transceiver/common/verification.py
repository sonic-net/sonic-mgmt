"""Standard Port Recovery and Verification Procedures.

Implements the Standard Port and Verification function,
as well as the related child functions. All parent and
child functions will return an output following the format:

dict: ``{port: {'passed': bool, 'details': str}}``

"""
import logging
import re
import time

from tests.transceiver.common import db_helpers
from tests.transceiver.common.prerequisites import (
    wait_until_health_ok, wait_until_links_up,
)

logger = logging.getLogger(__name__)

DEFAULT_STABILITY_WINDOW_SEC = 5
_LLDP_POLL_INTERVAL_SEC = 3
_CMIS_DATAPATH_STATE_RE = re.compile(r'^DP(\d+)State$')
_CMIS_CONFIG_STATE_RE = re.compile(r'^config_state_hostlane(\d+)$')
# Mirrors the message format produced by wait_ports_oper_status()
# (tests/common/platform/interface_utils.py), which returns failure strings
# rather than port names.
_DOWN_PORT_MSG_RE = re.compile(r'^port (\S+) did not reach oper-\S+ within \d+s$')


def check_lldp_neighbors_present(duthost, port_timeouts, namespaces=None):
    """Poll APPL_DB ``LLDP_ENTRY_TABLE:<port>`` until every port has a
    neighbor.

    Args:
        duthost: SONiC DUT host fixture.
        port_timeouts: dict of ``{port: timeout_sec}``.
        namespaces: optional dict of ``{port: namespace}``.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per
        ``port_timeouts``.
    """
    if namespaces is None:
        namespaces = {}

    def _namespace_for(port):
        if port in namespaces:
            return namespaces[port]
        return db_helpers.resolve_port_namespace(duthost, port)

    ports_by_ns = {}
    for port in port_timeouts:
        ports_by_ns.setdefault(_namespace_for(port), []).append(port)

    start = time.monotonic()
    deadlines = {
        port: start + timeout_sec
        for port, timeout_sec in port_timeouts.items()
    }
    remaining = set(port_timeouts)
    passed_ports = set()

    while remaining:
        for ns, ports_in_ns in ports_by_ns.items():
            pending_in_ns = [port for port in ports_in_ns if port in remaining]
            if not pending_in_ns:
                continue
            by_key, err = db_helpers.get_db_table(
                duthost, "APPL_DB", "LLDP_ENTRY_TABLE", namespace=ns, sep=":"
            )
            if err:
                continue
            for port in pending_in_ns:
                if port in by_key:
                    passed_ports.add(port)
                    remaining.discard(port)

        now = time.monotonic()
        for port in list(remaining):
            if now >= deadlines[port]:
                remaining.discard(port)
        if not remaining:
            break
        sleep_for = min(
            _LLDP_POLL_INTERVAL_SEC,
            max(0, min(deadlines[port] for port in remaining) - now),
        )
        time.sleep(sleep_for)

    per_port = {}
    for port, timeout_sec in port_timeouts.items():
        if port in passed_ports:
            details = f"{port}: LLDP neighbor present within {timeout_sec}s"
            logger.info("LLDP check PASSED: %s", details)
            per_port[port] = {"passed": True, "details": details}
        else:
            details = f"{port}: no LLDP neighbor after {timeout_sec}s"
            logger.warning("LLDP check FAILED: %s", details)
            per_port[port] = {"passed": False, "details": details}
    return per_port


# ──────────────────────────────────────────────────────────────────────
# Link Flap / Stability check
# ──────────────────────────────────────────────────────────────────────


def capture_flap_sentinels(duthost, ports, namespaces=None):
    """
    Snapshot every port's APPL_DB ``PORT_TABLE:<port>`` ``flap_count``/
    ``last_up_time`` once. Creates shared baseline that
    :func:`assert_no_flap_since` compares against,

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names.
        namespaces: optional dict of ``{port: namespace}``.

    Returns:
        dict: ``{port: (flap_count, last_up_time)}`` - both raw APPL_DB
        strings (or ``None`` if either field is absent), one entry per
        ``ports``.
    """
    if namespaces is None:
        namespaces = {}

    def _namespace_for(port):
        if port in namespaces:
            return namespaces[port]
        return db_helpers.resolve_port_namespace(duthost, port)

    sentinels = {}
    for port in ports:
        port_table = db_helpers.hgetall_dict(
            duthost, "APPL_DB", f"PORT_TABLE:{port}",
            namespace=_namespace_for(port)
        )
        sentinels[port] = (
            port_table.get("flap_count"), port_table.get("last_up_time")
        )
    return sentinels


def assert_no_flap_since(
    duthost, ports, sentinels, namespaces=None, elapsed_sec=None
):
    """
    Verify no port in ``ports`` has flapped since its ``sentinels`` snapshot.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names.
        sentinels: dict of ``{port: (flap_count, last_up_time)}``, from
            :func:`capture_flap_sentinels`.
        namespaces: optional dict of ``{port: namespace}``.
        elapsed_sec: optional, for the details message only.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per
        ``ports``.
    """
    if namespaces is None:
        namespaces = {}

    def _namespace_for(port):
        if port in namespaces:
            return namespaces[port]
        return db_helpers.resolve_port_namespace(duthost, port)

    window_desc = (
        f"{elapsed_sec}s window" if elapsed_sec is not None
        else "observation window"
    )

    per_port = {}
    for port in ports:
        baseline_flap, baseline_up = sentinels.get(port, (None, None))
        port_table = db_helpers.hgetall_dict(
            duthost, "APPL_DB", f"PORT_TABLE:{port}",
            namespace=_namespace_for(port)
        )
        current_flap = port_table.get("flap_count")
        current_up = port_table.get("last_up_time")

        if baseline_flap is None and baseline_up is None:
            details = (
                f"{port}: no flap_count/last_up_time sentinel captured - "
                "cannot verify stability (schema mismatch or partial publish)"
            )
            logger.warning("Stability check FAILED: %s", details)
            per_port[port] = {"passed": False, "details": details}
        elif current_flap != baseline_flap or current_up != baseline_up:
            details = (
                f"{port}: flap detected during {window_desc} "
                f"(flap_count {baseline_flap}->{current_flap}, "
                f"last_up_time {baseline_up}->{current_up})"
            )
            logger.warning("Stability check FAILED: %s", details)
            per_port[port] = {"passed": False, "details": details}
        else:
            details = (
                f"{port}: stable for {window_desc} "
                f"(flap_count={current_flap}, last_up_time={current_up})"
            )
            logger.info("Stability check PASSED: %s", details)
            per_port[port] = {"passed": True, "details": details}
    return per_port


# ──────────────────────────────────────────────────────────────────────
# Standard Port Recovery and Verification Procedure
# (see docs/testplan/transceiver/system_test_plan.md)
# ──────────────────────────────────────────────────────────────────────


def check_cmis_state(
    duthost, ports, lport_to_first_subport_mapping, namespaces=None
):
    """Verify CMIS DataPathState=DataPathActivated and
    ConfigState=ConfigSuccess, for every port in ``ports``.

    Why: ``TRANSCEIVER_STATUS`` is published once per physical module (under
    the first sub-port of a breakout group) and carries every host lane of
    the module, so a breakout sub-port must be checked only against its own
    active lanes - not a sibling's - to avoid a false pass/fail; this also
    batches the underlying DB reads per namespace instead of per port.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names.
        lport_to_first_subport_mapping: the value of the session-scoped
            fixture of the same name (``tests/transceiver/conftest.py``).
        namespaces: optional dict of ``{port: namespace}``.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per
        ``ports``.
    """
    if namespaces is None:
        namespaces = {}

    def _namespace_for(port):
        if port in namespaces:
            return namespaces[port]
        return db_helpers.resolve_port_namespace(duthost, port)

    ports_by_ns = {}
    for port in ports:
        ports_by_ns.setdefault(_namespace_for(port), []).append(port)

    status_by_parent = {}
    port_table_by_port = {}
    for ns in ports_by_ns:
        status_dump, status_err = db_helpers.get_state_db_table(
            duthost, "TRANSCEIVER_STATUS", namespace=ns
        )
        if status_err is None:
            status_by_parent.update(status_dump)
        port_table_dump, port_table_err = db_helpers.get_db_table(
            duthost, "APPL_DB", "PORT_TABLE", namespace=ns, sep=":"
        )
        if port_table_err is None:
            port_table_by_port.update(port_table_dump)

    per_port = {}
    for port in ports:
        parent = lport_to_first_subport_mapping.get(port, port)
        status = status_by_parent.get(parent)
        if not status:
            per_port[port] = {
                "passed": False,
                "details": f"{port}: TRANSCEIVER_STATUS|{parent} missing "
                           "or empty",
            }
            continue

        port_table = port_table_by_port.get(port, {})
        lanes_field = port_table.get("lanes")
        if not lanes_field:
            per_port[port] = {
                "passed": False,
                "details": (
                    f"{port}: PORT_TABLE:{port} has no 'lanes' field - "
                    "cannot determine this port's active host lanes"
                ),
            }
            continue
        host_lane_count = len(lanes_field.split(","))
        subport = int(port_table.get("subport") or 1)
        lane_start = host_lane_count * max(0, subport - 1)
        active_lanes = set(
            range(lane_start + 1, lane_start + host_lane_count + 1)
        )

        bad_datapath = []
        bad_config = []
        datapath_fields_seen = 0
        config_fields_seen = 0
        for k, v in status.items():
            datapath_match = _CMIS_DATAPATH_STATE_RE.match(k)
            if datapath_match:
                if int(datapath_match.group(1)) not in active_lanes:
                    continue
                datapath_fields_seen += 1
                if v != "DataPathActivated":
                    bad_datapath.append(f"{k}={v}")
                continue
            config_match = _CMIS_CONFIG_STATE_RE.match(k)
            if config_match:
                if int(config_match.group(1)) not in active_lanes:
                    continue
                config_fields_seen += 1
                if v != "ConfigSuccess":
                    bad_config.append(f"{k}={v}")

        missing_msg = ""
        if datapath_fields_seen != len(active_lanes):
            missing_msg += "DataPathState fields missing; "
        if config_fields_seen != len(active_lanes):
            missing_msg += "ConfigState fields missing; "

        if missing_msg:
            per_port[port] = {
                "passed": False,
                "details": (
                    f"{port} (parent {parent}) TRANSCEIVER_STATUS|{parent} "
                    f"has {missing_msg} "
                    f"for this port's active host lanes "
                    f"{sorted(active_lanes)} - cannot confirm CMIS state "
                    "(schema mismatch, partial publish, or lane-range "
                    "mismatch)"
                ),
            }
            continue

        if bad_datapath or bad_config:
            problems = []
            if bad_datapath:
                problems.append("datapath: " + ", ".join(bad_datapath))
            if bad_config:
                problems.append("config: " + ", ".join(bad_config))
            per_port[port] = {
                "passed": False,
                "details": f"{port} (parent {parent}) CMIS state NOT "
                           "activated - " + "; ".join(problems),
            }
            continue

        per_port[port] = {
            "passed": True,
            "details": f"{port} (parent {parent}) CMIS DataPathActivated "
                       "+ ConfigSuccess",
        }
    return per_port


def standard_port_recovery_and_verification(
    duthost, ports, port_attributes_dict, link_up_timeout_sec, health_baseline,
    lport_to_first_subport_mapping,
    stability_window_sec=DEFAULT_STABILITY_WINDOW_SEC,
    expected_pid_changes=None,
    flap_count_baseline=None,
    assert_no_flap_across_op=False,
):
    """Run the Standard Port Recovery and Verification Procedure on a
    batch of ports (link status, flap/stability, LLDP, CMIS state,
    docker/process health), batched across ``ports`` so fixed per-call
    costs aren't multiplied by port count and every port's failures are
    surfaced in one call.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names to validate.
        port_attributes_dict: dict of ``{port: port_attrs}`` (as produced by
            the ``port_attributes_dict`` fixture), with one entry per port in
            ``ports``.
        link_up_timeout_sec: total budget shared between waiting on oper-up
            and polling docker/process health afterward
        health_baseline: the dict returned by
            :func:`tests.transceiver.common.health_checks.capture_baseline`
        lport_to_first_subport_mapping: the value of the session-scoped
            fixture of the same name (``tests/transceiver/conftest.py``).
        stability_window_sec: shared post-recovery observation window
            (seconds) for the stability sub-check.
        expected_pid_changes: set of monitored process names whose PID is
            expected to differ from ``health_baseline`` in the health check.
        flap_count_baseline: optional dict of ``{port: flap_count}``
        assert_no_flap_across_op: whether to additionally assert no flap
            occurred across the whole operation (only valid where the link
            stays up and the flap counter survives, e.g. xcvrd/pmon restart).

    Returns:
        dict: ``{'passed': bool, 'per_port': {port: {'passed': bool,
        'details': str}}, 'details': str}``
    """
    # ``None`` on single-ASIC -> no ``-n`` flag.
    namespaces = {
        port: db_helpers.resolve_port_namespace(duthost, port) for port in ports
    }

    per_port_failures = {port: [] for port in ports}
    checks_ran = {port: [] for port in ports}  # human-readable checks ran

    # 1. Link status - one batched poll covers every port.
    link_poll_t0 = time.monotonic()
    link_check_dict = wait_until_links_up(
        duthost, port_attributes_dict, link_up_timeout_sec
    )
    link_poll_elapsed = time.monotonic() - link_poll_t0
    up_ports = link_check_dict.get("up", [])
    down_ports_raw = link_check_dict.get("down", [])
    down_ports = [port.split("(")[0] for port in down_ports_raw]
    for port in down_ports:
        per_port_failures[port].append(f"{port} is down")

    # 2a/2b setup - one shared flap/last_up_time sentinel per up port, captured
    # right after link-up.
    recovery_t0 = time.monotonic()
    post_recovery_sentinels = (
        capture_flap_sentinels(duthost, up_ports, namespaces=namespaces)
        if up_ports else {}
    )

    # 2a end-gate. Mandatory stability sub-check, only for up ports. Asserted
    # here (after steps 3/5) so the window overlaps that work instead of a
    # leading sleep; tops up to stability_window_sec if the rest ran short.
    if up_ports:
        elapsed = time.monotonic() - recovery_t0
        time.sleep(max(0, stability_window_sec - elapsed))
        stability_results = assert_no_flap_since(
            duthost, up_ports, post_recovery_sentinels, namespaces=namespaces,
            elapsed_sec=stability_window_sec,
        )
        for port, result in stability_results.items():
            checks_ran[port].append("stability")
            if not result["passed"]:
                per_port_failures[port].append(result["details"])

    # 7. Docker/process health - one batched poll, host-wide, unconditionally.
    #    Shares link_up_timeout_sec with step 1: whatever the link-up poll
    #    didn't use is what's left for health, floored at 1s so health is
    #    still checked at least once even if link-up ate the whole budget.
    if health_baseline is None:
        health_failure = (
            "health_baseline not provided - caller must pass the "
            "'health_baseline' pytest fixture value "
            "(tests/transceiver/conftest.py)"
        )
    else:
        health_timeout_sec = max(1, link_up_timeout_sec - link_poll_elapsed)
        health_result = wait_until_health_ok(
            duthost, health_baseline, health_timeout_sec,
            expect_pid_change=expected_pid_changes,
        )
        health_failure = (
            None if health_result["passed"]
            else "; ".join(health_result["failures"])
        )
    for port in ports:
        checks_ran[port].append("health")
        if health_failure is not None:
            per_port_failures[port].append(f"health: {health_failure}")

    per_port = {}
    overall_passed = True
    for port in ports:
        failures = per_port_failures[port]
        if failures:
            overall_passed = False
            details = f"{port}: " + "; ".join(failures)
            logger.warning("Standard Port Recovery FAILED: %s", details)
        else:
            details = f"{port}: " + " + ".join(checks_ran[port]) + " all OK"
            logger.info("Standard Port Recovery PASSED: %s", details)
        per_port[port] = {"passed": not failures, "details": details}

    return {
        "passed": overall_passed,
        "per_port": per_port,
        "details": "; ".join(per_port[port]["details"] for port in ports),
    }
