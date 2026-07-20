"""Standard Port Recovery and Verification Procedure for transceiver System tests.

Lives at the location reserved by
``docs/testplan/transceiver/diagrams/file_organization.md`` for the
"Standard Port Recovery and Verification Procedure".

Implements the subset of the procedure defined in
``docs/testplan/transceiver/system_test_plan.md`` (§ Common Verification
Procedures) that the Link Behavior System tests exercise after restoring a
port: link status → link flap/stability → LLDP → CMIS state →
docker/process health. Each check returns a result dict (with ``'passed'``
and ``'details'`` keys) and the top-level
:func:`standard_port_recovery_and_verification` aggregates every sub-failure
into one ``details`` string so a single call surfaces every problem on the
port.

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
    get_dut_interfaces_status,
    get_lport_to_first_subport_mapping,
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

_OPER_POLL_INTERVAL_SEC = 2


def wait_for_port_oper_state(duthost, port, expected_state, timeout_sec):
    """Poll ``show interface description`` until ``port`` reaches ``expected_state``.

    Args:
        duthost: SONiC DUT host fixture.
        port: logical interface name, e.g. ``"Ethernet0"``.
        expected_state: ``"up"`` or ``"down"`` (case-insensitive).
        timeout_sec: maximum number of seconds to wait.

    Returns:
        dict: ``{'passed': bool, 'observed': str, 'details': str}``
    """
    expected = (expected_state or "").strip().lower()
    deadline = time.monotonic() + max(0, int(timeout_sec))
    while True:
        intf_status = get_dut_interfaces_status(duthost)
        observed = (intf_status.get(port, {}) or {}).get("oper", "missing")
        if observed and observed.strip().lower() == expected:
            details = f"{port}: oper={observed} (expected {expected}) within {timeout_sec}s"
            logger.info("Oper-state wait PASSED: %s", details)
            return {"passed": True, "observed": observed, "details": details}
        if time.monotonic() >= deadline:
            break
        time.sleep(_OPER_POLL_INTERVAL_SEC)

    details = (
        f"{port}: oper={observed} (expected {expected}) after {timeout_sec}s timeout"
    )
    logger.warning("Oper-state wait FAILED: %s", details)
    return {"passed": False, "observed": observed, "details": details}


# ──────────────────────────────────────────────────────────────────────
# LLDP neighbor poll
# ──────────────────────────────────────────────────────────────────────

_LLDP_POLL_INTERVAL_SEC = 3


def check_lldp_neighbor_present(duthost, port, timeout_sec=30, namespace=None):
    """Poll APPL_DB ``LLDP_ENTRY_TABLE:<port>`` until a neighbor is learned.

    A non-empty ``LLDP_ENTRY_TABLE:<port>`` hash means lldpd has at least
    one neighbor record for ``port``. Used by System tests to confirm the
    far end re-converged after a disruptive operation.

    ``namespace`` scopes the query to the port's ASIC on a multi-ASIC DUT, where
    LLDP tables are per-namespace; when ``None`` it is resolved from ``port`` so
    callers that don't track namespaces (e.g. the post-session check) still query
    the right ASIC. On a single-ASIC DUT it is ``None`` and no ``-n`` flag is
    emitted.

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    if namespace is None:
        namespace = resolve_namespace(duthost, port)
    deadline = time.monotonic() + max(0, int(timeout_sec))
    while True:
        entry = db_helpers.hgetall_dict(
            duthost, "APPL_DB", f"LLDP_ENTRY_TABLE:{port}", namespace=namespace
        )
        if entry:
            details = f"{port}: LLDP neighbor present within {timeout_sec}s"
            logger.info("LLDP check PASSED: %s", details)
            return {"passed": True, "details": details}
        if time.monotonic() >= deadline:
            break
        time.sleep(_LLDP_POLL_INTERVAL_SEC)

    details = f"{port}: no LLDP neighbor after {timeout_sec}s"
    logger.warning("LLDP check FAILED: %s", details)
    return {"passed": False, "details": details}


# ──────────────────────────────────────────────────────────────────────
# Link Flap / Stability check
# ──────────────────────────────────────────────────────────────────────


def check_link_stability(duthost, port, window_sec, namespace=None):
    """Verify ``port`` does not flap over a short post-recovery observation window.

    Implements the "Stability (always)" sub-check of system_test_plan.md's
    Link Flap/Stability Verification step: snapshots APPL_DB
    ``PORT_TABLE:<port>`` ``flap_count``/``last_up_time`` once, waits
    ``window_sec``, then re-reads and requires both fields to be unchanged.

    This sub-check is **forward-looking only** - it observes from recovery
    onward and never compares against a pre-operation baseline - so it holds
    even for operations whose flap counter resets when the port DB is rebuilt
    (``swss``/``syncd`` restart, ``config reload``, reboots, power cycle). The
    test plan's second, operation-scoped sub-check ("no flap across the
    operation", only where the counter survives - e.g. ``xcvrd``/``pmon``
    restart) needs the pre-operation baseline from each test's own Common
    Setup and is asserted by the individual test case, not here.

    ``namespace`` scopes the APPL_DB read to the owning ASIC; when ``None`` it
    is resolved from ``port``.

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    if namespace is None:
        namespace = resolve_namespace(duthost, port)

    def _snapshot():
        port_table = db_helpers.hgetall_dict(
            duthost, "APPL_DB", f"PORT_TABLE:{port}", namespace=namespace
        )
        return port_table.get("flap_count"), port_table.get("last_up_time")

    baseline_flap, baseline_up = _snapshot()
    time.sleep(window_sec)
    current_flap, current_up = _snapshot()

    if current_flap != baseline_flap or current_up != baseline_up:
        details = (
            f"{port}: flap detected during {window_sec}s stability window "
            f"(flap_count {baseline_flap}->{current_flap}, "
            f"last_up_time {baseline_up}->{current_up})"
        )
        logger.warning("Stability check FAILED: %s", details)
        return {"passed": False, "details": details}

    details = f"{port}: stable for {window_sec}s (flap_count={current_flap}, last_up_time={current_up})"
    logger.info("Stability check PASSED: %s", details)
    return {"passed": True, "details": details}


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
    duthost, port, port_attrs, link_up_timeout_sec, shared_state=None,
    min_uptime_sec=MIN_CRITICAL_SERVICE_UPTIME_SEC,
    stability_window_sec=DEFAULT_STABILITY_WINDOW_SEC,
):
    """Run the Standard Port Recovery and Verification Procedure on one port.

    Steps (per ``system_test_plan.md``):
      1. Link Status         - port oper-up within ``link_up_timeout_sec``.
      2. Link Flap/Stability - the mandatory "Stability (always)" sub-check,
                               iff link came up: no flap / ``last_up_time``
                               change over ``stability_window_sec``.
      3. LLDP                - neighbor learned, iff ``verify_lldp_on_link_up``.
      4. CMIS State          - DataPathActivated + ConfigSuccess, iff the
                               port is ``cmis_active_optical``.
      5. Docker/process health - delegates to
                               :func:`tests.transceiver.common.health_checks.verify_health`,
                               the single owner of the xcvrd/syncd/orchagent
                               process + ``/var/core`` check (also run once per
                               test by the autouse ``_per_test_health_check``
                               fixture), plus the >= 180 s uptime floor from
                               the test plan that fixture does not enforce.
                               Runs unconditionally - independent of link state.

    Remote-Side Link Verification (test-plan step 4, optional/opt-in) and the
    optics/media-SI + application-code steps (test-plan step 6) are
    intentionally not implemented here; they land with the event-handling and
    diagnostics tests that exercise them.

    All sub-failures are accumulated and reported together so a single
    call surfaces every problem on the port.

    Args:
        duthost: SONiC DUT host fixture.
        port: logical interface name to validate.
        port_attrs: per-port attribute dict (entry of ``port_attributes_dict``).
        link_up_timeout_sec: budget for waiting on oper-up.
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
        stability_window_sec: post-recovery observation window (seconds) for
            the step-2 stability sub-check. Defaults to
            :data:`DEFAULT_STABILITY_WINDOW_SEC` (5) - the test plan does not
            pin an exact duration, only "a short post-recovery observation
            window".

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    if shared_state is None:
        shared_state = {}

    # Owning ASIC namespace, resolved once and reused for every per-namespace DB
    # read below (LLDP / TRANSCEIVER_STATUS).
    # ``None`` on single-ASIC -> no ``-n`` flag.
    namespace = resolve_namespace(duthost, port)

    sys_attrs = port_attrs.get(SYSTEM_ATTRIBUTES_KEY, {})
    eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})

    failures = []
    checks_ran = []  # human-readable list of checks that ran, for the pass message

    # 1. Link status.
    link_result = wait_for_port_oper_state(duthost, port, "up", link_up_timeout_sec)
    checks_ran.append("link up")
    if not link_result["passed"]:
        failures.append(link_result["details"])

    # 2. Link Flap/Stability - mandatory "Stability (always)" sub-check, only
    #    if link came up (nothing to observe stability of otherwise).
    if link_result["passed"]:
        stability_result = check_link_stability(
            duthost, port, stability_window_sec, namespace=namespace
        )
        checks_ran.append("stability")
        if not stability_result["passed"]:
            failures.append(stability_result["details"])

    # 3. LLDP - only if requested and link came up (otherwise LLDP is moot).
    if link_result["passed"] and sys_attrs.get("verify_lldp_on_link_up", True):
        lldp_timeout = sys_attrs.get("lldp_neighbor_wait_sec", 60)
        lldp_result = check_lldp_neighbor_present(
            duthost, port, timeout_sec=lldp_timeout, namespace=namespace
        )
        checks_ran.append("LLDP")
        if not lldp_result["passed"]:
            failures.append(lldp_result["details"])

    # 4. CMIS state - only if link came up and port is CMIS active-optical.
    if link_result["passed"] and eeprom_attrs.get("cmis_active_optical"):
        cmis_result = check_cmis_state(duthost, port, shared_state, namespace=namespace)
        checks_ran.append("CMIS state")
        if not cmis_result["passed"]:
            failures.append(cmis_result["details"])

    # 5. Docker and process health check (per system_test_plan.md). Delegates
    #    to health_checks.verify_health - the single owner of the
    #    xcvrd/syncd/orchagent process check and the /var/core diff (also run
    #    automatically once per test by the autouse _per_test_health_check
    #    fixture in tests/transceiver/conftest.py) - passing min_uptime_sec so
    #    it additionally enforces the test plan's >= 3-minute uptime floor,
    #    which that per-test fixture does not check.
    #    Runs unconditionally - if the port's link didn't come back, knowing
    #    whether a critical service died on the way is exactly the diagnostic
    #    we want.
    checks_ran.append("health")
    health_baseline = shared_state.get("health_baseline")
    if health_baseline is None:
        failures.append(
            f"{port} health: shared_state['health_baseline'] not seeded - caller must "
            "call health_checks.capture_baseline(duthost) before the disruptive action"
        )
    else:
        health_result = health_checks.verify_health(
            duthost, health_baseline, min_uptime_sec=min_uptime_sec
        )
        if not health_result["passed"]:
            failures.append(f"{port} health: " + "; ".join(health_result["failures"]))

    if failures:
        details = f"{port}: " + "; ".join(failures)
        logger.warning("Standard Port Recovery FAILED: %s", details)
        return {"passed": False, "details": details}

    details = f"{port}: " + " + ".join(checks_ran) + " all OK"
    logger.info("Standard Port Recovery PASSED: %s", details)
    return {"passed": True, "details": details}
