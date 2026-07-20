"""Standard Port Recovery and Verification Procedure for transceiver System tests.

Lives at the location reserved by
``docs/testplan/transceiver/diagrams/file_organization.md`` for the
"Standard Port Recovery and Verification Procedure".

Implements the subset of the procedure defined in
``docs/testplan/transceiver/system_test_plan.md`` (§ Common Verification
Procedures) that the Link Behavior System tests exercise after restoring a
batch of ports: link status → link flap/stability → LLDP → CMIS state →
docker/process health. Each check returns a result dict (with ``'passed'``
and ``'details'`` keys) and the top-level
:func:`standard_port_recovery_and_verification` runs every step batched
across the whole ``ports`` list - one polling loop / observation window per
step instead of one per port - and aggregates each port's sub-failures into
its own ``details`` string, so a single call surfaces every problem on every
port without multiplying the fixed-wait and host-wide steps by port count.

Remote-Side Link Verification (test-plan step 4, optional/opt-in - enabled by
callers such as disruptive Event Handling and System Recovery tests) and the
optics/media-SI + application-code checks (test-plan step 6) are
intentionally not implemented here; they are added alongside the diagnostics
and event-handling tests that exercise them.

DB reads go through :mod:`tests.transceiver.common.db_helpers`
(``hgetall_dict``). The docker/process health step delegates entirely to
:mod:`tests.transceiver.common.health_checks`, which owns the
xcvrd/syncd/orchagent process check and the ``/var/core`` diff shared with
the rest of the transceiver suite.
"""
import logging
import time

from tests.common.platform.interface_utils import (
    get_lport_to_first_subport_mapping,
    wait_ports_oper_status,
)
from tests.transceiver.attribute_parser.attribute_keys import (
    EEPROM_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import db_helpers, health_checks

logger = logging.getLogger(__name__)

# Minimum continuous uptime (seconds) the health check requires of every
# critical service (pmon, swss, syncd containers and the xcvrd process).
# Per system_test_plan.md "Docker and Process Health Check": services must be
# running for at least 3 minutes. Disruptive tests that deliberately restart a
# service (e.g. xcvrd restart) must dwell long enough for the restarted service
# to clear this floor before calling the health check.
MIN_CRITICAL_SERVICE_UPTIME_SEC = 180

# Post-recovery observation window (seconds) for the mandatory Link
# Flap/Stability "Stability (always)" sub-check in system_test_plan.md, which
# does not pin an exact duration ("a short post-recovery observation window").
# Kept small since this runs once per port on every Standard Port Recovery
# call.
DEFAULT_STABILITY_WINDOW_SEC = 5


def resolve_namespace(duthost, port):
    """Return the ASIC network namespace owning ``port`` (``None`` on single-ASIC).

    Mirrors the resolution used by the EEPROM / link-behavior tests
    (``get_namespace_from_asic_id`` of the port's ASIC instance). Multi-ASIC DBs
    (STATE_DB / APPL_DB, including LLDP) are per-namespace, so every per-port DB
    read in this module scopes to the owning ASIC; on a single-ASIC DUT this is
    ``None`` (``DEFAULT_NAMESPACE``) and ``db_helpers.hgetall_dict`` emits no
    ``-n`` flag.
    """
    return duthost.get_namespace_from_asic_id(
        duthost.get_port_asic_instance(port).asic_index
    )


# ──────────────────────────────────────────────────────────────────────
# Oper-state poll
# ──────────────────────────────────────────────────────────────────────


def wait_for_ports_oper_state(duthost, ports, expected_state, timeout_sec):
    """Poll until every port in ``ports`` reaches ``expected_state`` oper status.

    Thin adapter over :func:`tests.common.platform.interface_utils.wait_ports_oper_status`
    (one ``show interface description`` dump per poll cycle, via ``wait_until``,
    checked against every port in ``ports``) so N ports share one polling
    budget/dump instead of each port paying for its own serial
    ``wait_ports_oper_status([port], ...)`` call.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names, e.g. ``["Ethernet0", "Ethernet4"]``.
        expected_state: ``"up"`` or ``"down"`` (case-insensitive).
        timeout_sec: maximum number of seconds to wait - a shared budget for
            every port in ``ports``, not per port.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per
        ``ports``.
    """
    expected = (expected_state or "").strip().lower()
    fails = wait_ports_oper_status(duthost, ports, expected, timeout_sec)
    # wait_ports_oper_status's failure strings are "port {port} did not reach
    # oper-{status} within {wait_sec}s" (its own format, owned in this repo),
    # so the port token is reliably the second whitespace-separated field.
    fail_by_port = {fail.split(" ", 2)[1]: fail for fail in fails}

    per_port = {}
    for port in ports:
        if port in fail_by_port:
            details = fail_by_port[port]
            logger.warning("Oper-state wait FAILED: %s", details)
            per_port[port] = {"passed": False, "details": details}
        else:
            details = f"{port}: oper={expected} within {timeout_sec}s"
            logger.info("Oper-state wait PASSED: %s", details)
            per_port[port] = {"passed": True, "details": details}
    return per_port


def wait_for_port_oper_state(duthost, port, expected_state, timeout_sec):
    """Single-port convenience wrapper over :func:`wait_for_ports_oper_state`.

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    return wait_for_ports_oper_state(duthost, [port], expected_state, timeout_sec)[port]


# ──────────────────────────────────────────────────────────────────────
# LLDP neighbor poll
# ──────────────────────────────────────────────────────────────────────

_LLDP_POLL_INTERVAL_SEC = 3


def check_lldp_neighbors_present(duthost, port_timeouts, namespaces=None):
    """Poll APPL_DB ``LLDP_ENTRY_TABLE:<port>`` until every port has a neighbor.

    A non-empty ``LLDP_ENTRY_TABLE:<port>`` hash means lldpd has at least
    one neighbor record for ``port``. Used by System tests to confirm the
    far end re-converged after a disruptive operation.

    Polls are interleaved across every port in ``port_timeouts`` - each cycle
    checks every still-pending port and drops the ones that now have a
    neighbor, then sleeps once before the next cycle - so N ports' waits
    overlap instead of summing N serial worst-case timeouts. Each port keeps
    its own ``timeout_sec`` (ports may request different
    ``lldp_neighbor_wait_sec`` values), so a port with a short timeout can
    fail out while others with longer budgets keep polling.

    ``namespaces`` maps port -> ASIC namespace (``None`` on single-ASIC DUTs,
    where LLDP tables are per-namespace); a port missing from ``namespaces``
    (or a caller passing ``None``) has its namespace resolved from the port
    itself, so callers that don't track namespaces (e.g. the post-session
    check) still query the right ASIC.

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
        namespace = namespaces.get(port)
        return namespace if namespace is not None else resolve_namespace(duthost, port)

    start = time.monotonic()
    deadlines = {port: start + max(0, int(timeout_sec)) for port, timeout_sec in port_timeouts.items()}
    remaining = set(port_timeouts)
    passed_ports = set()

    while remaining:
        now = time.monotonic()
        for port in list(remaining):
            entry = db_helpers.hgetall_dict(
                duthost, "APPL_DB", f"LLDP_ENTRY_TABLE:{port}", namespace=_namespace_for(port)
            )
            if entry:
                passed_ports.add(port)
                remaining.discard(port)
            elif now >= deadlines[port]:
                remaining.discard(port)
        if not remaining:
            break
        time.sleep(_LLDP_POLL_INTERVAL_SEC)

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


def check_lldp_neighbor_present(duthost, port, timeout_sec=30, namespace=None):
    """Single-port convenience wrapper over :func:`check_lldp_neighbors_present`.

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    namespaces = {port: namespace} if namespace is not None else None
    return check_lldp_neighbors_present(duthost, {port: timeout_sec}, namespaces=namespaces)[port]


# ──────────────────────────────────────────────────────────────────────
# Link Flap / Stability check
# ──────────────────────────────────────────────────────────────────────


def check_ports_stability(duthost, ports, window_sec, namespaces=None):
    """Verify no port in ``ports`` flaps over one shared post-recovery observation window.

    Implements the "Stability (always)" sub-check of system_test_plan.md's
    Link Flap/Stability Verification step: snapshots every port's APPL_DB
    ``PORT_TABLE:<port>`` ``flap_count``/``last_up_time`` once, waits
    ``window_sec`` a single time (not once per port), then re-reads every
    port and requires both fields to be unchanged. N ports therefore share
    one ``window_sec`` window instead of serializing N x ``window_sec``.

    This sub-check is **forward-looking only** - it observes from recovery
    onward and never compares against a pre-operation baseline - so it holds
    even for operations whose flap counter resets when the port DB is rebuilt
    (``swss``/``syncd`` restart, ``config reload``, reboots, power cycle). The
    test plan's second, operation-scoped sub-check ("no flap across the
    operation", only where the counter survives - e.g. ``xcvrd``/``pmon``
    restart) needs the pre-operation baseline from each test's own Common
    Setup and is asserted by the individual test case, not here.

    ``namespaces`` maps port -> ASIC namespace; a port missing from it (or a
    caller passing ``None``) has its namespace resolved from the port itself.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names.
        window_sec: shared observation window, in seconds.
        namespaces: optional dict of ``{port: namespace}``.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per ``ports``.
    """
    if namespaces is None:
        namespaces = {}

    def _namespace_for(port):
        namespace = namespaces.get(port)
        return namespace if namespace is not None else resolve_namespace(duthost, port)

    def _snapshot_all():
        snapshot = {}
        for port in ports:
            port_table = db_helpers.hgetall_dict(
                duthost, "APPL_DB", f"PORT_TABLE:{port}", namespace=_namespace_for(port)
            )
            snapshot[port] = (port_table.get("flap_count"), port_table.get("last_up_time"))
        return snapshot

    baseline = _snapshot_all()
    time.sleep(window_sec)
    current = _snapshot_all()

    per_port = {}
    for port in ports:
        baseline_flap, baseline_up = baseline[port]
        current_flap, current_up = current[port]

        if baseline_flap is None and baseline_up is None:
            details = (
                f"{port}: PORT_TABLE:{port} has neither flap_count nor last_up_time - "
                "cannot verify stability (schema mismatch or partial publish)"
            )
            logger.warning("Stability check FAILED: %s", details)
            per_port[port] = {"passed": False, "details": details}
        elif current_flap != baseline_flap or current_up != baseline_up:
            details = (
                f"{port}: flap detected during {window_sec}s stability window "
                f"(flap_count {baseline_flap}->{current_flap}, "
                f"last_up_time {baseline_up}->{current_up})"
            )
            logger.warning("Stability check FAILED: %s", details)
            per_port[port] = {"passed": False, "details": details}
        else:
            details = f"{port}: stable for {window_sec}s (flap_count={current_flap}, last_up_time={current_up})"
            logger.info("Stability check PASSED: %s", details)
            per_port[port] = {"passed": True, "details": details}
    return per_port


def check_link_stability(duthost, port, window_sec, namespace=None):
    """Single-port convenience wrapper over :func:`check_ports_stability`.

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    namespaces = {port: namespace} if namespace is not None else None
    return check_ports_stability(duthost, [port], window_sec, namespaces=namespaces)[port]


# ──────────────────────────────────────────────────────────────────────
# Standard Port Recovery and Verification Procedure
# (see docs/testplan/transceiver/system_test_plan.md)
# ──────────────────────────────────────────────────────────────────────


def _resolve_parent_port(duthost, port, shared_state):
    """Return the parent (first sibling) of ``port`` in its breakout group.

    Thin cached wrapper over the repo's shared
    :func:`tests.common.platform.interface_utils.get_lport_to_first_subport_mapping`
    (the same helper the ``lport_to_first_subport_mapping`` session fixture in
    ``tests/transceiver/conftest.py`` uses), rather than a parallel
    reimplementation of the same physical-port grouping. The mapping is cached
    in ``shared_state`` so it is queried at most once per test.
    """
    if "lport_to_first_subport" not in shared_state:
        shared_state["lport_to_first_subport"] = get_lport_to_first_subport_mapping(duthost)
    return shared_state["lport_to_first_subport"].get(port, port)


def _get_transceiver_status(duthost, parent_port, shared_state, namespace=None):
    """Cached fetch of ``STATE_DB TRANSCEIVER_STATUS|<parent_port>`` (per ASIC ns)."""
    cache = shared_state.setdefault("transceiver_status", {})
    if parent_port not in cache:
        cache[parent_port] = db_helpers.hgetall_dict(
            duthost, "STATE_DB", f"TRANSCEIVER_STATUS|{parent_port}", namespace=namespace
        )
    return cache[parent_port]


def check_cmis_state(duthost, port, shared_state, namespace=None):
    """Verify CMIS DataPathState=DataPathActivated and ConfigState=ConfigSuccess.

    ("DataPathActivated" is the literal STATE_DB string, per
    ``docs/testplan/transceiver/test_plan.md``; the CMIS spec's own nibble name
    for the same state, used at the EEPROM layer in ``cmis_helper.py``, is
    "DPActivated".)

    Reads the parent port's ``TRANSCEIVER_STATUS`` once (cached via
    ``shared_state``) and validates every ``host_lane*_datapath_state``
    and ``host_lane*_config_state`` field actually present in the hash, so
    the check adapts to however many host lanes the port's breakout mode
    exposes instead of assuming a fixed lane count. If NEITHER field is present
    at all (schema mismatch or a partial STATE_DB publish), the check fails
    rather than vacuously passing.

    ``namespace`` scopes the STATE_DB read to the owning ASIC; when ``None`` it is
    resolved from ``port`` (a breakout parent shares its subports' ASIC).
    """
    if namespace is None:
        namespace = resolve_namespace(duthost, port)
    parent = _resolve_parent_port(duthost, port, shared_state)
    status = _get_transceiver_status(duthost, parent, shared_state, namespace)
    if not status:
        return {
            "passed": False,
            "details": f"{port}: TRANSCEIVER_STATUS|{parent} missing or empty",
        }

    bad_datapath = []
    bad_config = []
    datapath_fields_seen = 0
    config_fields_seen = 0
    for k, v in status.items():
        if k.startswith("host_lane") and k.endswith("_datapath_state"):
            datapath_fields_seen += 1
            if v != "DataPathActivated":
                bad_datapath.append(f"{k}={v}")
        elif k.startswith("host_lane") and k.endswith("_config_state"):
            config_fields_seen += 1
            if v != "ConfigSuccess":
                bad_config.append(f"{k}={v}")

    if datapath_fields_seen == 0 and config_fields_seen == 0:
        details = (
            f"{port} (parent {parent}) TRANSCEIVER_STATUS|{parent} has no "
            "host_lane*_datapath_state or host_lane*_config_state fields - "
            "cannot confirm CMIS state (schema mismatch or partial publish)"
        )
        return {"passed": False, "details": details}

    if bad_datapath or bad_config:
        problems = []
        if bad_datapath:
            problems.append("datapath: " + ", ".join(bad_datapath))
        if bad_config:
            problems.append("config: " + ", ".join(bad_config))
        details = f"{port} (parent {parent}) CMIS state NOT activated - " + "; ".join(problems)
        return {"passed": False, "details": details}

    return {"passed": True, "details": f"{port} (parent {parent}) CMIS DataPathActivated + ConfigSuccess"}


def standard_port_recovery_and_verification(
    duthost, ports, port_attributes_dict, link_up_timeout_sec, shared_state=None,
    min_uptime_sec=MIN_CRITICAL_SERVICE_UPTIME_SEC,
    stability_window_sec=DEFAULT_STABILITY_WINDOW_SEC,
    expect_pid_change=None,
):
    """Run the Standard Port Recovery and Verification Procedure on a batch of ports.

    Each step below runs batched across every port in ``ports`` - one polling
    loop / observation window / host-wide check per call, not one per port -
    so N ports share fixed costs instead of multiplying them:
      1. Link Status         - one poll (via
                               :func:`wait_for_ports_oper_state`) of every port
                               off the same ``show interface description``
                               dump per cycle; oper-up within ``link_up_timeout_sec``.
      2. Link Flap/Stability - the mandatory "Stability (always)" sub-check,
                               for every port that came up: one shared
                               ``stability_window_sec`` observation window
                               (snapshot all -> sleep once -> re-read all)
                               instead of one window per port.
      3. LLDP                - neighbor learned, for every up port with
                               ``verify_lldp_on_link_up``; per-port polls are
                               interleaved (poll all pending -> drop satisfied
                               -> repeat) so waits overlap instead of summing.
      4. CMIS State          - DataPathActivated + ConfigSuccess, for every up
                               port that is ``cmis_active_optical``; per-parent
                               ``TRANSCEIVER_STATUS`` reads are cached in
                               ``shared_state`` so subports of the same
                               breakout group cost one extra STATE_DB read,
                               not one per subport.
      5. Docker/process health - delegates to
                               :func:`tests.transceiver.common.health_checks.verify_health`,
                               the single owner of the xcvrd/syncd/orchagent
                               process + ``/var/core`` check (also run once per
                               test by the autouse ``_per_test_health_check``
                               fixture), plus the >= 180 s uptime floor from
                               the test plan that fixture does not enforce.
                               Host-wide and port-count-independent: runs
                               exactly once per call regardless of ``len(ports)``,
                               and unconditionally - independent of any port's
                               link state.

    Remote-Side Link Verification (test-plan step 4, optional/opt-in) and the
    optics/media-SI + application-code steps (test-plan step 6) are
    intentionally not implemented here; they land with the event-handling and
    diagnostics tests that exercise them.

    Every port's sub-failures are accumulated and reported together so a
    single call surfaces every problem on every port.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names to validate.
        port_attributes_dict: dict of ``{port: port_attrs}`` (as produced by
            the ``port_attributes_dict`` fixture), with one entry per port in
            ``ports``.
        link_up_timeout_sec: budget for waiting on oper-up - shared across
            every port in ``ports``, not per port.
        shared_state: optional dict shared across calls in the same test so
            the logical->physical port map and per-parent
            ``TRANSCEIVER_STATUS`` queries happen at most once. Must carry a
            ``'health_baseline'`` entry - the dict returned by
            :func:`tests.transceiver.common.health_checks.capture_baseline`,
            captured by the caller before the disruptive action - so step 5
            can diff against it.
        min_uptime_sec: minimum continuous uptime (seconds) required of each
            monitored process (each a representative for its container - see
            ``health_checks.DEFAULT_MONITORED_PROCESSES``) in the step-5
            health check. Defaults to :data:`MIN_CRITICAL_SERVICE_UPTIME_SEC`
            (180, i.e. the test plan's 3-minute floor). Callers that
            deliberately restart a service must dwell long enough for it to
            clear this floor before calling.
        stability_window_sec: shared post-recovery observation window
            (seconds) for the step-2 stability sub-check, applied once across
            every port that came up. Defaults to
            :data:`DEFAULT_STABILITY_WINDOW_SEC` (5) - the test plan does not
            pin an exact duration, only "a short post-recovery observation
            window".
        expect_pid_change: set of monitored process names (see
            ``health_checks.DEFAULT_MONITORED_PROCESSES``) whose PID is
            expected to differ from ``shared_state['health_baseline']`` in
            the step-5 health check - e.g. the process this call's disruptive
            action deliberately restarted (xcvrd/pmon restart scenarios).
            Passed straight through to
            :func:`tests.transceiver.common.health_checks.verify_health`.
            Without it, a process restarted by the caller's own disruptive
            action would fail step 5 as an "unexpected restart" even though
            ``min_uptime_sec`` was satisfied.

    Returns:
        dict: ``{'passed': bool, 'per_port': {port: {'passed': bool, 'details': str}}, 'details': str}``
    """
    if shared_state is None:
        shared_state = {}

    # Owning ASIC namespace per port, resolved once and reused for every
    # per-namespace DB read below (LLDP / TRANSCEIVER_STATUS / stability).
    # ``None`` on single-ASIC -> no ``-n`` flag.
    namespaces = {port: resolve_namespace(duthost, port) for port in ports}

    per_port_failures = {port: [] for port in ports}
    checks_ran = {port: [] for port in ports}  # human-readable checks that ran, per port

    # 1. Link status - one batched poll covers every port.
    link_results = wait_for_ports_oper_state(duthost, ports, "up", link_up_timeout_sec)
    for port in ports:
        checks_ran[port].append("link up")
        if not link_results[port]["passed"]:
            per_port_failures[port].append(link_results[port]["details"])

    up_ports = [port for port in ports if link_results[port]["passed"]]

    # 2. Link Flap/Stability - mandatory "Stability (always)" sub-check, only
    #    for ports that came up (nothing to observe stability of otherwise).
    #    One shared window covers every up port.
    if up_ports:
        stability_results = check_ports_stability(
            duthost, up_ports, stability_window_sec, namespaces=namespaces
        )
        for port, result in stability_results.items():
            checks_ran[port].append("stability")
            if not result["passed"]:
                per_port_failures[port].append(result["details"])

    # 3. LLDP - only for up ports that request it (otherwise LLDP is moot);
    #    per-port timeouts honored, polls interleaved across the batch.
    lldp_port_timeouts = {}
    for port in up_ports:
        sys_attrs = port_attributes_dict.get(port, {}).get(SYSTEM_ATTRIBUTES_KEY, {})
        if sys_attrs.get("verify_lldp_on_link_up", True):
            lldp_port_timeouts[port] = sys_attrs.get("lldp_neighbor_wait_sec", 60)
    if lldp_port_timeouts:
        lldp_results = check_lldp_neighbors_present(
            duthost, lldp_port_timeouts, namespaces=namespaces
        )
        for port, result in lldp_results.items():
            checks_ran[port].append("LLDP")
            if not result["passed"]:
                per_port_failures[port].append(result["details"])

    # 4. CMIS state - only for up ports that are CMIS active-optical.
    #    check_cmis_state caches TRANSCEIVER_STATUS per breakout parent in
    #    shared_state, so looping here costs at most one extra STATE_DB read
    #    per breakout group, not one per subport.
    for port in up_ports:
        eeprom_attrs = port_attributes_dict.get(port, {}).get(EEPROM_ATTRIBUTES_KEY, {})
        if eeprom_attrs.get("cmis_active_optical"):
            cmis_result = check_cmis_state(duthost, port, shared_state, namespace=namespaces.get(port))
            checks_ran[port].append("CMIS state")
            if not cmis_result["passed"]:
                per_port_failures[port].append(cmis_result["details"])

    # 5. Docker and process health check (per system_test_plan.md). Delegates
    #    to health_checks.verify_health - the single owner of the
    #    xcvrd/syncd/orchagent process check and the /var/core diff (also run
    #    automatically once per test by the autouse _per_test_health_check
    #    fixture in tests/transceiver/conftest.py) - passing min_uptime_sec so
    #    it additionally enforces the test plan's >= 3-minute uptime floor,
    #    which that per-test fixture does not check. expect_pid_change is
    #    forwarded as-is so callers whose disruptive action deliberately
    #    restarts a monitored process (e.g. xcvrd/pmon restart) can declare it
    #    and avoid a false "unexpected restart" failure against the baseline.
    #    Host-wide: runs exactly once for the whole batch, unconditionally -
    #    if a port's link didn't come back, knowing whether a critical
    #    service died on the way is exactly the diagnostic we want, for every
    #    port in the batch.
    health_baseline = shared_state.get("health_baseline")
    if health_baseline is None:
        health_failure = (
            "shared_state['health_baseline'] not seeded - caller must call "
            "health_checks.capture_baseline(duthost) before the disruptive action"
        )
    else:
        health_result = health_checks.verify_health(
            duthost, health_baseline, expect_pid_change=expect_pid_change,
            min_uptime_sec=min_uptime_sec,
        )
        health_failure = None if health_result["passed"] else "; ".join(health_result["failures"])
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
