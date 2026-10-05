"""Standard Port Recovery and Verification Procedures.

Implements the Standard Port and Verification function,
as well as the related child functions. All parent and
child functions will return an output following the format:

dict: ``{port: {'passed': bool, 'details': str}}``

"""
import logging
import time

from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY, DOM_ATTRIBUTES_KEY, EEPROM_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import db_helpers
from tests.transceiver.common.prerequisites import (
    wait_until_health_ok, wait_until_links_up,
)

logger = logging.getLogger(__name__)

DEFAULT_STABILITY_WINDOW_SEC = 5
_LLDP_POLL_INTERVAL_SEC = 3
_CMIS_POLL_INTERVAL_SEC = 3


def check_lldp_neighbors_present(
    duthost, port_timeouts, namespaces=None, *, expected_peers=None, started_at=None,
):
    """Poll LLDP presence, or matching identity when expected peers are supplied.

    Ports share a start time but expire independently. A positive timeout
    includes database read time: entries returned after a port's deadline
    cannot pass it. Non-positive timeouts perform one immediate check.
    Reads are batched per namespace; an in-flight read is not interrupted.

    Args:
        duthost: SONiC DUT host fixture.
        port_timeouts: dict of ``{port: timeout_sec}``.
        namespaces: optional dict of ``{port: namespace}``.
        expected_peers: optional dict of ``{port: PeerConnection}``. When
            supplied, every requested port needs an expected peer. Require an
            exact system-name match and a port ID matching the logical port
            or its independently resolved alias. Mismatches retry within the
            existing timeout; missing expected peers fail without a DB read.
            Omit to check presence only.
        started_at: shared monotonic start time, captured immediately after
            the batch link-recovery phase. Defaults to helper entry for
            standalone calls.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per
        ``port_timeouts``. Failed entries also include ``failure_reason``
        without the local-port prefix or diagnostic expected-peer suffix,
        for grouping identical failures. Identity mismatches retain both
        expected and observed identities in that reason.
    """
    if started_at is None:
        started_at = time.monotonic()
    ports_by_ns = db_helpers.group_ports_by_namespace(duthost, port_timeouts, namespaces)
    remaining = set(port_timeouts)
    neighbors = {}
    errors = {}
    if expected_peers is not None:
        for port in port_timeouts:
            peer = expected_peers.get(port)
            if peer is None or not peer.device or not peer.port:
                errors[port] = "missing expected LLDP peer device/port; cannot verify identity"
                remaining.discard(port)

    while remaining:
        for ns, ports_in_ns in ports_by_ns.items():
            elapsed = time.monotonic() - started_at
            for port in ports_in_ns:
                if port_timeouts[port] > 0 and elapsed > port_timeouts[port]:
                    remaining.discard(port)
            pending_in_ns = [port for port in ports_in_ns if port in remaining]
            if not pending_in_ns:
                continue
            by_key, err = db_helpers.get_db_table(
                duthost, "APPL_DB", "LLDP_ENTRY_TABLE", namespace=ns, sep=":"
            )
            elapsed = time.monotonic() - started_at
            if err:
                for port in pending_in_ns:
                    errors[port] = f"last read error: APPL_DB LLDP_ENTRY_TABLE read failed (namespace={ns!r}): {err}"
                continue
            for port in pending_in_ns:
                if port_timeouts[port] > 0 and elapsed > port_timeouts[port]:
                    remaining.discard(port)
                    continue
                errors.pop(port, None)
                if port in by_key:
                    neighbor = by_key[port]
                    if expected_peers is not None:
                        peer = expected_peers[port]
                        port_ids = {peer.port}
                        if peer.alias:
                            port_ids.add(peer.alias)
                        device = neighbor.get("lldp_rem_sys_name")
                        port_id = neighbor.get("lldp_rem_port_id")
                        if device != peer.device or port_id not in port_ids:
                            errors[port] = (
                                f"LLDP identity mismatch: observed device={device!r}, port={port_id!r}; "
                                f"expected device={peer.device!r}, port ID in {sorted(port_ids)!r}"
                            )
                            continue
                    neighbors[port] = neighbor
                    remaining.discard(port)

        elapsed = time.monotonic() - started_at
        remaining = {port for port in remaining if elapsed < port_timeouts[port]}
        if remaining:
            time.sleep(min(
                _LLDP_POLL_INTERVAL_SEC,
                min(port_timeouts[port] for port in remaining) - elapsed,
            ))

    per_port = {}
    for port, timeout_sec in port_timeouts.items():
        peer = (expected_peers or {}).get(port)
        expected_detail = (
            f"; expected peer={peer.device}:{peer.port}"
            if peer is not None else ""
        )
        if port in neighbors:
            neighbor = neighbors[port]
            device = neighbor.get("lldp_rem_sys_name") or "unknown"
            port_id = neighbor.get("lldp_rem_port_id") or "unknown"
            description = neighbor.get("lldp_rem_port_desc") or "not advertised"
            check = "identity matched" if expected_peers is not None else "present"
            details = (
                f"{port}: LLDP neighbor {check} within {timeout_sec}s: "
                f"device={device}, port={port_id}, description={description}{expected_detail}"
            )
            logger.info("LLDP check PASSED: %s", details)
            per_port[port] = {"passed": True, "details": details}
        else:
            reason = (
                f"unable to verify LLDP neighbor within {timeout_sec}s; "
                f"{errors[port]}"
                if port in errors
                else f"no LLDP neighbor observed within {timeout_sec}s"
            )
            details = f"{port}: {reason}{expected_detail}"
            logger.warning("LLDP check FAILED: %s", details)
            per_port[port] = {"passed": False, "details": details, "failure_reason": reason}
    return per_port


# ──────────────────────────────────────────────────────────────────────
# Link Flap / Stability check
# ──────────────────────────────────────────────────────────────────────


def capture_flap_sentinels(duthost, ports, namespaces=None):
    """
    Snapshot every port's APPL_DB ``PORT_TABLE:<port>`` ``flap_count``/
    ``last_up_time``/``last_down_time`` once. Creates shared baseline that
    :func:`assert_no_flap_since` compares against.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names.
        namespaces: optional dict of ``{port: namespace}``.

    Returns:
        dict: ``{port: (flap_count, last_up_time, last_down_time)}`` - raw APPL_DB
        strings (or ``None`` for each absent field), one entry per
        ``ports``.
    """
    port_entries = db_helpers.get_appl_db_port_table_entries(duthost, ports, namespaces)
    return {
        port: (
            port_entries[port].get("flap_count"),
            port_entries[port].get("last_up_time"),
            port_entries[port].get("last_down_time"),
        )
        for port in ports
    }


def assert_no_flap_since(
    duthost, ports, sentinels, elapsed_sec=None, *, current_sentinels=None
):
    """
    Verify no port in ``ports`` has flapped since its ``sentinels`` snapshot.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names.
        sentinels: dict of ``{port: (flap_count, last_up_time, last_down_time)}``, from
            :func:`capture_flap_sentinels`.
        elapsed_sec: optional, for the details message only.
        current_sentinels: optional snapshot from :func:`capture_flap_sentinels`;
            captured here when omitted. Counters, when present in either
            snapshot, must be valid and unchanged. When absent from both,
            stability is verified using the available timestamps only.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per
        ``ports``.
    """
    window_desc = (
        f"{elapsed_sec}s window" if elapsed_sec is not None
        else "observation window"
    )

    if current_sentinels is None:
        current_sentinels = capture_flap_sentinels(duthost, ports)
    count_results = check_flap_counts_unchanged(
        duthost, ports,
        {port: values[0] for port, values in sentinels.items()},
        current_sentinels=current_sentinels,
    )
    per_port = {}
    for port in ports:
        baseline_flap, baseline_up, baseline_down = sentinels.get(port, (None, None, None))
        current_flap, current_up, current_down = current_sentinels.get(port, (None, None, None))
        count_failed = (
            (baseline_flap is not None or current_flap is not None)
            and not count_results[port]["passed"]
        )

        if baseline_flap is None and baseline_up is None and baseline_down is None:
            details = (
                f"{port}: no flap_count/last_up_time/last_down_time sentinel captured - "
                "cannot verify stability (schema mismatch or partial publish)"
            )
            logger.warning("Stability check FAILED: %s", details)
            per_port[port] = {"passed": False, "details": details}
        elif (
            count_failed
            or current_up != baseline_up
            or current_down != baseline_down
        ):
            details = (
                f"{port}: stability verification failed during {window_desc} "
                f"(flap_count {baseline_flap}->{current_flap}, "
                f"last_up_time {baseline_up}->{current_up}, "
                f"last_down_time {baseline_down}->{current_down})"
            )
            logger.warning("Stability check FAILED: %s", details)
            per_port[port] = {"passed": False, "details": details}
        else:
            details = (
                f"{port}: stable for {window_desc} "
                f"(flap_count={current_flap}, last_up_time={current_up}, "
                f"last_down_time={current_down})"
            )
            logger.info("Stability check PASSED: %s", details)
            per_port[port] = {"passed": True, "details": details}
    return per_port


# ──────────────────────────────────────────────────────────────────────
# Standard Port Recovery and Verification Procedure
# (see docs/testplan/transceiver/system_test_plan.md)
# ──────────────────────────────────────────────────────────────────────


def check_flap_counts_unchanged(duthost, ports, baseline, *, current_sentinels=None):
    """Compare APPL_DB flap counters with baseline values.

    ``baseline`` maps logical ports to integer counts or decimal strings.
    Missing or invalid baseline/current counters fail verification. Callers
    must not compare across operations that rebuild APPL_DB.
    ``current_sentinels`` is an optional :func:`capture_flap_sentinels`
    snapshot; when omitted, a fresh snapshot is captured here.
    Returns ``{port: {'passed': bool, 'details': str}}``.
    """
    if current_sentinels is None:
        current_sentinels = capture_flap_sentinels(duthost, ports)
    per_port = {}
    for port in ports:
        before = baseline.get(port) if baseline is not None else None
        after = current_sentinels.get(port, (None, None, None))[0]
        try:
            before_count = int(str(before))
            after_count = int(str(after))
            valid = before_count >= 0 and after_count >= 0
        except (TypeError, ValueError):
            valid = False
        if not valid:
            passed = False
            details = (
                f"{port}: missing or invalid flap_count baseline/current "
                f"({before!r}->{after!r}) - cannot verify unchanged flap count"
            )
        else:
            passed = before_count == after_count
            details = (
                f"{port}: flap_count {'unchanged' if passed else 'changed'} "
                f"since baseline ({before_count}->{after_count})"
            )
        per_port[port] = {"passed": passed, "details": details}
    return per_port


def _wait_for_fresh_cmis_status(duthost, requests_by_ns, deadline):
    """Return accepted snapshots and freshness errors under one deadline.

    requests_by_ns maps namespaces to {logical_port: (parent, UTC boundary)}.
    Each accepted snapshot supplies both its timestamp and its state fields.
    """
    pending_by_ns = {
        namespace: port_requests.copy()
        for namespace, port_requests in requests_by_ns.items()
    }
    fresh_status = {}
    errors = {
        port: f"no status observation within the freshness deadline (namespace={namespace!r})"
        for namespace, pending in pending_by_ns.items()
        for port in pending
    }
    while any(pending_by_ns.values()) and time.monotonic() <= deadline:
        for namespace, pending in pending_by_ns.items():
            if time.monotonic() > deadline:
                break
            if not pending:
                continue
            status_dump, status_err = db_helpers.get_state_db_table(
                duthost, db_helpers.TRANSCEIVER_STATUS_TABLE, namespace=namespace
            )
            if time.monotonic() > deadline:
                for port in pending:
                    errors[port] += "; status read completed after the freshness deadline"
                    if status_err is not None:
                        errors[port] += f"; late read error: {status_err}"
                break
            for port, (parent, boundary) in list(pending.items()):
                if status_err is not None:
                    errors[port] = f"status read failed (namespace={namespace!r}): {status_err}"
                    continue
                status = status_dump.get(parent, {})
                raw_time = status.get(db_helpers.STATE_DB_UPDATE_TIME_FIELD)
                update_time = db_helpers.parse_update_time(raw_time)
                if update_time is None:
                    errors[port] = (
                        f"missing or invalid last_update_time={raw_time!r} (namespace={namespace!r})"
                    )
                elif update_time <= boundary:
                    errors[port] = (
                        f"last_update_time={raw_time!r} is not newer than "
                        f"link-up/recovery boundary {boundary} UTC (namespace={namespace!r})"
                    )
                else:
                    fresh_status[port] = status
                    errors.pop(port, None)
                    del pending[port]
        if not any(pending_by_ns.values()):
            break
        remaining_sec = deadline - time.monotonic()
        if remaining_sec <= 0:
            break
        time.sleep(min(_CMIS_POLL_INTERVAL_SEC, remaining_sec))
    return fresh_status, errors


def check_cmis_state(
    duthost, ports, lport_to_first_subport_mapping, namespaces=None,
    *, port_attributes_dict, timeout_sec, not_before_utc=None, link_up_times=None,
):
    """Verify CMIS DataPathState=DataPathActivated and
    ConfigState=ConfigSuccess, for every port in ``ports``.

    Why: ``TRANSCEIVER_STATUS`` is published once per physical module (under
    the first sub-port of a breakout group) and carries every host lane of
    the module, so a breakout sub-port must be checked only against its own
    active lanes - not a sibling's - to avoid a false pass/fail; this also
    batches the underlying DB reads per namespace instead of per port.
    Host lanes come from each port's resolved BASE_ATTRIBUTES.host_lane_mask.

    Call after link recovery. Accept a status publication strictly newer than
    the port's last_up_time and, when supplied, not_before_utc. Already-fresh
    data is evaluated immediately; only stale or missing status requires
    polling. Both DB timestamps use the same second-resolution UTC format.
    Equal timestamps are not fresh.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names.
        lport_to_first_subport_mapping: the value of the session-scoped
            fixture of the same name (``tests/transceiver/conftest.py``).
        namespaces: optional dict of ``{port: namespace}``.
        port_attributes_dict: resolved per-port attributes containing the
            required BASE_ATTRIBUTES.host_lane_mask; no live-lane fallback.
        timeout_sec: shared freshness deadline, including initial DB reads.
            Size this from ``DOM_ATTRIBUTES.dom_info_recover_sec``.
        not_before_utc: optional naive UTC datetime captured on the DUT at the
            operation/recovery boundary. Required to exclude pre-operation
            data when the link stays up.
        link_up_times: optional ``{port: raw last_up_time}`` snapshot captured
            after link recovery. Read from APPL_DB when omitted.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per
        ``ports``.
    """
    deadline = time.monotonic() + timeout_sec
    ports_by_ns = db_helpers.group_ports_by_namespace(
        duthost, ports, namespaces
    )
    if link_up_times is None:
        link_up_times = {
            port: entry.get("last_up_time")
            for port, entry in db_helpers.get_appl_db_port_table_entries(
                duthost, ports, namespaces
            ).items()
        }

    per_port = {}
    active_lanes_by_port = {}
    requests_by_ns = {}
    for namespace, namespace_ports in ports_by_ns.items():
        for port in namespace_ports:
            if port not in lport_to_first_subport_mapping:
                per_port[port] = {
                    "passed": False,
                    "details": f"{port}: missing logical-to-first-subport mapping",
                }
                continue
            raw_link_up = link_up_times.get(port)
            link_up_time = db_helpers.parse_update_time(raw_link_up)
            if link_up_time is None:
                per_port[port] = {
                    "passed": False,
                    "details": f"{port}: missing or invalid last_up_time={raw_link_up!r}",
                }
                continue
            try:
                raw_mask = port_attributes_dict[port][BASE_ATTRIBUTES_KEY]["host_lane_mask"]
                host_lane_mask = int(str(raw_mask), 16)
                if not 0 < host_lane_mask <= 0xFF:
                    raise ValueError(f"host_lane_mask={raw_mask!r} must select lanes 1-8")
            except (KeyError, TypeError, ValueError) as error:
                per_port[port] = {
                    "passed": False,
                    "details": f"{port}: missing or invalid BASE_ATTRIBUTES.host_lane_mask: {error}",
                }
                continue
            active_lanes_by_port[port] = [
                lane for lane in range(1, 9) if host_lane_mask & (1 << (lane - 1))
            ]
            boundary = (
                max(link_up_time, not_before_utc)
                if not_before_utc is not None
                else link_up_time
            )
            requests_by_ns.setdefault(namespace, {})[port] = (
                lport_to_first_subport_mapping[port], boundary,
            )

    fresh_status, freshness_errors = _wait_for_fresh_cmis_status(duthost, requests_by_ns, deadline)
    for port, active_lanes in active_lanes_by_port.items():
        parent = lport_to_first_subport_mapping[port]
        if port in freshness_errors:
            per_port[port] = {
                "passed": False,
                "details": (
                    f"{port}: CMIS telemetry freshness timeout after {timeout_sec}s for "
                    f"{db_helpers.TRANSCEIVER_STATUS_TABLE}|{parent}; "
                    "current CMIS state could not be verified: "
                    f"{freshness_errors[port]}"
                ),
            }
            continue
        status = fresh_status[port]
        problems = []
        for lane in active_lanes:
            for field, expected in (
                (f"DP{lane}State", "DataPathActivated"),
                (f"config_state_hostlane{lane}", "ConfigSuccess"),
            ):
                if field not in status:
                    problems.append(f"{field} missing")
                elif status[field] != expected:
                    problems.append(f"{field}={status[field]} (expected {expected})")
        per_port[port] = {
            "passed": not problems,
            "details": (
                f"{port} (parent {parent}) CMIS state NOT activated - " + "; ".join(problems)
                if problems else f"{port} (parent {parent}) CMIS DataPathActivated + ConfigSuccess"
            ),
        }
    return {port: per_port[port] for port in ports}


def standard_port_recovery_and_verification(
    duthost, ports, port_attributes_dict, link_up_timeout_sec, health_baseline,
    lport_to_first_subport_mapping,
    stability_window_sec=DEFAULT_STABILITY_WINDOW_SEC,
    expected_pid_changes=None,
    flap_count_baseline=None,
    assert_no_flap_across_op=False,
    *, port_peers=None,
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
        flap_count_baseline: dict of ``{port: flap_count}`` (integers or
            decimal strings), required for each linked-up port when
            ``assert_no_flap_across_op`` is True. Obtain counts from the
            first element of each :func:`capture_flap_sentinels` value.
        assert_no_flap_across_op: whether to additionally assert no flap
            occurred across the whole operation (only valid where the link
            stays up and the flap counter survives, e.g. xcvrd/pmon restart).
        port_peers: optional session-scoped map of local ports to
            ``(PeerConnection, error)`` from the fixture of the same name.
            Supplying it enables LLDP device/port identity validation, using
            peer aliases resolved by the fixture. Include expected peers even
            when links stay down; resolution errors or missing entries fail
            the affected ports. Omit for presence-only LLDP verification.
    Returns:
        dict: ``{'passed': bool, 'per_port':
        {port: {'passed': bool, 'details': str}}, 'details': str,
        'post_recovery_sentinels':
        {port: (flap_count, last_up_time, last_down_time)},
        'post_recovery_started_at': float}``

    On failure, ``details`` groups affected ports by check and identical
    failure reason; full diagnostics remain in ``per_port``. A building
    block may supply ``failure_reason`` to separate the cause from display
    context. Otherwise its details, minus a leading local-port prefix, are
    used. Distinct observations are never merged by approximate matching.

    The stability window starts after the baseline snapshot has been read.
    That snapshot also supplies CMIS link-up times without another DB read.
    LLDP budgets share one start time captured immediately after the batch
    link-recovery phase, before the baseline snapshot is read.
    Remote link-state, SI, and BER verification are not yet implemented here.
    DUT UTC time captured at entry also bounds CMIS freshness, so a no-flap
    operation cannot pass using status published before recovery verification.
    """
    verification_t0 = time.monotonic()
    logger.info(
        "Standard Port Recovery starting: %d ports, link/health budget=%ss, "
        "stability window=%ss, no-flap across operation=%s",
        len(ports), link_up_timeout_sec, stability_window_sec, assert_no_flap_across_op,
    )
    recovery_started_at = duthost.get_now_time(utc_timezone=True) if ports else None
    # ``None`` on single-ASIC -> no ``-n`` flag.
    namespaces = {
        port: db_helpers.resolve_port_namespace(duthost, port) for port in ports
    }

    per_port_failures = {port: [] for port in ports}
    checks_ran = {port: ["link"] for port in ports}
    failure_groups = {}

    def record_failure(check, port, details, reason=None):
        per_port_failures[port].append(details)
        reason = details if reason is None else reason
        prefix = f"{port}: "
        if reason.startswith(prefix):
            reason = reason[len(prefix):]
        failure_groups.setdefault((check, reason), []).append(port)

    def record_results(check, results):
        for port, result in results.items():
            checks_ran[port].append(check)
            if not result["passed"]:
                record_failure(check, port, result["details"], result.get("failure_reason"))

    expected_peers = {}
    if port_peers is not None:
        for port in ports:
            peer, error = port_peers.get(port, (None, "missing port_peers entry"))
            if error is not None:
                record_failure("peer resolution", port, f"peer resolution: {error}", error)
            else:
                expected_peers[port] = peer

    link_poll_t0 = time.monotonic()
    link_check_dict = wait_until_links_up(
        duthost, {port: port_attributes_dict[port] for port in ports},
        link_up_timeout_sec,
    )
    lldp_started_at = time.monotonic()
    link_poll_elapsed = lldp_started_at - link_poll_t0
    linked_ports = set(link_check_dict.get("up", []))
    up_ports = [port for port in ports if port in linked_ports]
    logger.debug(
        "Standard Port Recovery link poll completed in %.2fs: %d/%d ports up",
        link_poll_elapsed, len(up_ports), len(ports),
    )
    # Reuse the last poll's diagnostics; do not query the DUT again for logging.
    down_observations = {
        observation.split("(", 1)[0]: observation
        for observation in link_check_dict.get("down", [])
    }
    for port in ports:
        if port not in linked_ports:
            observation = down_observations.get(port, "state unavailable")
            if observation.startswith(f"{port}("):
                observation = observation[len(port):]
            record_failure(
                "link", port,
                f"link not recovered within {link_up_timeout_sec}s; "
                f"expected admin=up/oper=up; last observed {observation}"
            )

    post_recovery_sentinels = (
        capture_flap_sentinels(duthost, up_ports, namespaces) if up_ports else {}
    )
    recovery_t0 = time.monotonic()

    lldp_port_timeouts = {}
    cmis_port_timeouts = {}
    for port in up_ports:
        attrs = port_attributes_dict[port]
        try:
            system_attrs = attrs[SYSTEM_ATTRIBUTES_KEY]
            if system_attrs["verify_lldp_on_link_up"]:
                lldp_port_timeouts[port] = system_attrs["lldp_neighbor_wait_sec"]
        except KeyError as error:
            reason = f"missing required attribute {error}"
            record_failure("LLDP", port, f"LLDP: {reason}", reason)
        try:
            if attrs[EEPROM_ATTRIBUTES_KEY]["cmis_active_optical"]:
                cmis_port_timeouts[port] = attrs[DOM_ATTRIBUTES_KEY]["dom_info_recover_sec"]
        except KeyError as error:
            reason = f"missing required attribute {error}"
            record_failure("CMIS", port, f"CMIS: {reason}", reason)

    logger.debug(
        "Standard Port Recovery eligibility: LLDP=%d, CMIS=%d, stability=%d; "
        "%d ports excluded from these checks because link did not recover",
        len(lldp_port_timeouts), len(cmis_port_timeouts), len(up_ports), len(ports) - len(up_ports),
    )
    if lldp_port_timeouts:
        record_results("LLDP", check_lldp_neighbors_present(
            duthost, lldp_port_timeouts, namespaces=namespaces,
            expected_peers=expected_peers if port_peers is not None else None,
            started_at=lldp_started_at,
        ))
    if cmis_port_timeouts:
        cmis_timeout_sec = max(cmis_port_timeouts.values())
        stage_t0 = time.monotonic()
        cmis_results = check_cmis_state(
            duthost, list(cmis_port_timeouts), lport_to_first_subport_mapping,
            port_attributes_dict=port_attributes_dict,
            namespaces=namespaces, timeout_sec=cmis_timeout_sec,
            not_before_utc=recovery_started_at,
            link_up_times={port: post_recovery_sentinels[port][1] for port in cmis_port_timeouts},
        )
        logger.debug(
            "Standard Port Recovery CMIS completed in %.2fs: %d failed",
            time.monotonic() - stage_t0,
            sum(not result["passed"] for result in cmis_results.values()),
        )
        record_results("CMIS", cmis_results)

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
        stage_t0 = time.monotonic()
        health_result = wait_until_health_ok(
            duthost, health_baseline, health_timeout_sec,
            expect_pid_change=expected_pid_changes,
        )
        health_failure = (
            None if health_result["passed"]
            else "; ".join(health_result["failures"])
        )
        logger.debug(
            "Standard Port Recovery health completed in %.2fs: passed=%s",
            time.monotonic() - stage_t0, health_result["passed"],
        )
    if health_failure is not None:
        logger.warning("Standard Port Recovery host health FAILED: %s", health_failure)
    for port in ports:
        checks_ran[port].append("health")
        if health_failure is not None:
            record_failure("health", port, f"health: {health_failure}", health_failure)

    if up_ports:
        elapsed = time.monotonic() - recovery_t0
        time.sleep(max(0, stability_window_sec - elapsed))
        current_sentinels = capture_flap_sentinels(duthost, up_ports, namespaces)
        stability_results = assert_no_flap_since(
            duthost, up_ports, post_recovery_sentinels,
            elapsed_sec=round(time.monotonic() - recovery_t0, 2),
            current_sentinels=current_sentinels,
        )
        logger.debug(
            "Standard Port Recovery stability completed: observation=%.2fs, %d failed",
            time.monotonic() - recovery_t0,
            sum(not result["passed"] for result in stability_results.values()),
        )
        record_results("stability", stability_results)
        if assert_no_flap_across_op:
            flap_results = check_flap_counts_unchanged(
                duthost, up_ports, flap_count_baseline,
                current_sentinels=current_sentinels,
            )
            logger.debug(
                "Standard Port Recovery no-flap across operation: %d checked, %d failed",
                len(flap_results), sum(not result["passed"] for result in flap_results.values()),
            )
            record_results("no flap across operation", flap_results)

    per_port = {}
    overall_passed = health_failure is None
    for port in ports:
        failures = per_port_failures[port]
        if failures:
            overall_passed = False
            prefix = f"{port}: "
            details = prefix + "; ".join(
                failure[len(prefix):] if failure.startswith(prefix) else failure
                for failure in failures
            )
        else:
            details = f"{port}: " + " + ".join(checks_ran[port]) + " all OK"
        peer = expected_peers.get(port)
        if peer is not None:
            peer_detail = f"expected peer={peer.device}:{peer.port}"
            if peer_detail not in details:
                details += f"; {peer_detail}"
        logger.debug("Standard Port Recovery %s: %s", "FAILED" if failures else "PASSED", details)
        per_port[port] = {"passed": not failures, "details": details}

    failed_count = sum(not result["passed"] for result in per_port.values())
    failure_summary = "\n".join(
        f"[{check}] {len(affected_ports)} port(s) [{', '.join(affected_ports)}]: {reason}"
        for (check, reason), affected_ports in failure_groups.items()
    )
    if not ports and health_failure is not None:
        failure_summary = f"[health] {health_failure}"
    logger.log(
        logging.INFO if overall_passed else logging.WARNING,
        "Standard Port Recovery %s: %d passed, %d failed, %d total; elapsed=%.2fs%s",
        "PASSED" if overall_passed else "FAILED",
        len(per_port) - failed_count, failed_count, len(per_port),
        time.monotonic() - verification_t0,
        f"\n{failure_summary}" if failure_summary else "",
    )

    return {
        "passed": overall_passed,
        "per_port": per_port,
        "details": failure_summary or "; ".join(per_port[port]["details"] for port in ports),
        "post_recovery_sentinels": post_recovery_sentinels,
        "post_recovery_started_at": recovery_t0,
    }
