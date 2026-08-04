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
callers such as disruptive Event Handling and System Recovery tests) and SI
Settings Verification (test-plan step 6, optics + media) are intentionally
not implemented here; they land in a separate PR pending further discussion.

DB reads go through :mod:`tests.transceiver.common.db_helpers`
(``hgetall_dict``, ``get_db_table``). The docker/process health step
delegates entirely to :mod:`tests.transceiver.common.health_checks`, which
owns the xcvrd/syncd/orchagent process check and the ``/var/core`` diff
shared with the rest of the transceiver suite.
"""
import logging
import re
import time

from tests.common.platform.interface_utils import wait_ports_oper_status
from tests.transceiver.attribute_parser.attribute_keys import (
    EEPROM_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import db_helpers, health_checks
from tests.transceiver.common.eeprom_decode import is_cmis_active_optical

logger = logging.getLogger(__name__)

# Post-recovery observation window (seconds) for the mandatory Link
# Flap/Stability "Stability (always)" sub-check in system_test_plan.md, which
# does not pin an exact duration ("a short post-recovery observation window").
# Kept small since this runs once per port on every Standard Port Recovery
# call.
DEFAULT_STABILITY_WINDOW_SEC = 5


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

    Each cycle issues one ``sonic-db-dump`` per distinct namespace among the
    still-pending ports (:func:`db_helpers.get_db_table`), not one ``hgetall``
    per port - a cycle costs O(namespaces) round-trips instead of O(pending
    ports); on a single-ASIC DUT that's one dump total per cycle regardless of
    how many ports are pending. Redis never stores an empty hash, so "port
    present in the dump" is equivalent to the previous per-port ``if entry:``
    truth test. A dump failure for a namespace is treated as "not present yet"
    for that cycle (matching ``hgetall_dict``'s own best-effort semantics) -
    it's retried next cycle, or the port's own deadline times it out below.

    ``namespaces`` maps port -> ASIC namespace (``None`` on single-ASIC DUTs,
    where LLDP tables are per-namespace); a port missing from ``namespaces``
    (or a caller passing ``None``) has its namespace resolved from the port
    itself, so callers that don't track namespaces (e.g. the post-session
    check) still query the right ASIC. Namespaces are resolved once, up
    front - both to avoid re-resolving per port per cycle, and because that
    same pass gives the per-namespace grouping the batched dump needs.

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
        return db_helpers.resolve_namespace(duthost, port)

    ports_by_ns = {}
    for port in port_timeouts:
        ports_by_ns.setdefault(_namespace_for(port), []).append(port)

    start = time.monotonic()
    deadlines = {port: start + max(0, int(timeout_sec)) for port, timeout_sec in port_timeouts.items()}
    remaining = set(port_timeouts)
    passed_ports = set()

    while remaining:
        for ns, ports_in_ns in ports_by_ns.items():
            pending_in_ns = [port for port in ports_in_ns if port in remaining]
            if not pending_in_ns:
                continue
            by_key, err = db_helpers.get_db_table(duthost, "APPL_DB", "LLDP_ENTRY_TABLE", namespace=ns, sep=":")
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
        # Cap the sleep to whatever's left before the earliest still-remaining
        # deadline, so a full _LLDP_POLL_INTERVAL_SEC never overshoots a
        # deadline that falls inside this interval - keeps the reported
        # "no LLDP neighbor after Ns" honest instead of running up to one
        # poll interval past N.
        sleep_for = min(_LLDP_POLL_INTERVAL_SEC, max(0, min(deadlines[port] for port in remaining) - now))
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
    """Snapshot every port's APPL_DB ``PORT_TABLE:<port>`` ``flap_count``/``last_up_time`` once.

    Pure batched read, no sleep - the shared building block both flap-freeness
    windows compose from: pair with :func:`assert_no_flap_since` to check these
    are unchanged after some elapsed time, however that time is produced (a
    flat sleep, as :func:`check_ports_stability` does; or, as
    :func:`standard_port_recovery_and_verification` does, overlapped with other
    work that runs concurrently with the observation instead of prefixing it
    with dead time).

    ``namespaces`` maps port -> ASIC namespace; a port missing from it (or a
    caller passing ``None``) has its namespace resolved from the port itself.

    Returns:
        dict: ``{port: (flap_count, last_up_time)}`` - both raw APPL_DB
        strings (or ``None`` if either field is absent), one entry per ``ports``.
    """
    if namespaces is None:
        namespaces = {}

    def _namespace_for(port):
        if port in namespaces:
            return namespaces[port]
        return db_helpers.resolve_namespace(duthost, port)

    sentinels = {}
    for port in ports:
        port_table = db_helpers.hgetall_dict(
            duthost, "APPL_DB", f"PORT_TABLE:{port}", namespace=_namespace_for(port)
        )
        sentinels[port] = (port_table.get("flap_count"), port_table.get("last_up_time"))
    return sentinels


def assert_no_flap_since(duthost, ports, sentinels, namespaces=None, elapsed_sec=None):
    """Verify no port in ``ports`` has flapped since its ``sentinels`` snapshot.

    Re-reads each port's current APPL_DB ``PORT_TABLE:<port>`` ``flap_count``/
    ``last_up_time`` and requires both to be unchanged vs. the paired entry in
    ``sentinels`` (from :func:`capture_flap_sentinels`) - a pure comparison, no
    sleep. The caller owns how much time elapses between capturing the
    sentinel and calling this; ``elapsed_sec`` is used only to word the
    'passed'/'failed' details message and plays no role in the comparison.

    ``last_up_time`` is a DUT wall-clock string (1s resolution), not a
    monotonic value - used here purely as an equality sentinel, never for
    duration arithmetic. Callers measure elapsed time on their own
    ``time.monotonic()``.

    ``namespaces`` maps port -> ASIC namespace; a port missing from it (or a
    caller passing ``None``) has its namespace resolved from the port itself.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names.
        sentinels: dict of ``{port: (flap_count, last_up_time)}``, from
            :func:`capture_flap_sentinels`.
        namespaces: optional dict of ``{port: namespace}``.
        elapsed_sec: optional, for the details message only.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per ``ports``.
    """
    if namespaces is None:
        namespaces = {}

    def _namespace_for(port):
        if port in namespaces:
            return namespaces[port]
        return db_helpers.resolve_namespace(duthost, port)

    window_desc = f"{elapsed_sec}s window" if elapsed_sec is not None else "observation window"

    per_port = {}
    for port in ports:
        baseline_flap, baseline_up = sentinels.get(port, (None, None))
        port_table = db_helpers.hgetall_dict(
            duthost, "APPL_DB", f"PORT_TABLE:{port}", namespace=_namespace_for(port)
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
            details = f"{port}: stable for {window_desc} (flap_count={current_flap}, last_up_time={current_up})"
            logger.info("Stability check PASSED: %s", details)
            per_port[port] = {"passed": True, "details": details}
    return per_port


def check_ports_stability(duthost, ports, window_sec, namespaces=None):
    """Verify no port in ``ports`` flaps over one shared post-recovery observation window.

    Implements the "Stability (always)" sub-check of system_test_plan.md's
    Link Flap/Stability Verification step, standalone: captures a sentinel
    (:func:`capture_flap_sentinels`), sleeps ``window_sec`` a single time (not
    once per port), then asserts nothing changed (:func:`assert_no_flap_since`).
    N ports therefore share one ``window_sec`` window instead of serializing
    N x ``window_sec``.

    This sub-check is **forward-looking only** - it observes from recovery
    onward and never compares against a pre-operation baseline - so it holds
    even for operations whose flap counter resets when the port DB is rebuilt
    (``swss``/``syncd`` restart, ``config reload``, reboots, power cycle). The
    test plan's second, operation-scoped sub-check ("no flap across the
    operation", only where the counter survives - e.g. ``xcvrd``/``pmon``
    restart) needs the pre-operation baseline from each test's own Common
    Setup and is asserted by the individual test case (or, within this suite,
    by :func:`standard_port_recovery_and_verification`'s
    ``assert_no_flap_across_op``), not here.

    This flat "sleep window_sec, then check" shape is a leading dead-time
    prefix - fine for a caller with nothing else to overlap it with (e.g. a
    standalone stability check, or a fixed-duration steady-state monitor).
    :func:`standard_port_recovery_and_verification` instead anchors its own
    sentinel to right after link-up and only asserts at the end, after its
    other steps have run, so the same observation window overlaps that work
    instead of prefixing it - composing :func:`capture_flap_sentinels` and
    :func:`assert_no_flap_since` directly rather than calling this wrapper.

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
    sentinels = capture_flap_sentinels(duthost, ports, namespaces=namespaces)
    time.sleep(window_sec)
    return assert_no_flap_since(duthost, ports, sentinels, namespaces=namespaces, elapsed_sec=window_sec)


# ──────────────────────────────────────────────────────────────────────
# Standard Port Recovery and Verification Procedure
# (see docs/testplan/transceiver/system_test_plan.md)
# ──────────────────────────────────────────────────────────────────────


# TRANSCEIVER_STATUS field names, verified against a live DUT
# (``redis-cli -n 6 hgetall 'TRANSCEIVER_STATUS|Ethernet0'``) and against the
# xcvrd writer - CmisApi.get_transceiver_status() in sonic-platform-common
# (sonic_platform_base/sonic_xcvr/api/public/cmis.py): datapath state is
# published as "DP<N>State" (value "DataPathActivated"), config state as
# "config_state_hostlane<N>" (value "ConfigSuccess") - NOT
# "host_lane<N>_datapath_state"/"host_lane<N>_config_state".
_CMIS_DATAPATH_STATE_RE = re.compile(r'^DP(\d+)State$')
_CMIS_CONFIG_STATE_RE = re.compile(r'^config_state_hostlane(\d+)$')


def check_cmis_state(duthost, ports, lport_to_first_subport_mapping, namespaces=None):
    """Verify CMIS DataPathState=DataPathActivated and ConfigState=ConfigSuccess, for every port in ``ports``.

    ("DataPathActivated" is the literal STATE_DB string, per
    ``docs/testplan/transceiver/test_plan.md``; the CMIS spec's own nibble name
    for the same state, used at the EEPROM layer in ``cmis_helper.py``, is
    "DPActivated".)

    ``TRANSCEIVER_STATUS`` is published once per physical module, under the
    first sub-port of a breakout group (hence ``lport_to_first_subport_mapping``
    below), and carries every one of the module's host lanes - not just a
    given port's own. Validating a port against every ``DP<N>State``/
    ``config_state_hostlane<N>`` field in the parent's entry would, on a
    breakout DUT, judge it by lanes owned by a *sibling* sub-port (e.g. a
    module split into Ethernet0 on lanes 1-4 and Ethernet4 on lanes 5-8: without
    this restriction, checking Ethernet4 would validate it against lanes 1-4).
    So this also reads each port's own APPL_DB ``PORT_TABLE:<port>`` for
    ``lanes`` (that port's own lane count) and ``subport`` (1-indexed among
    siblings; a non-breakout port reports ``1`` too) and restricts ``<N>`` to
    that port's own active host-lane range, computed the same way xcvrd does
    in ``get_cmis_host_lanes_mask`` (``sonic-xcvrd/xcvrd/cmis/cmis_manager_task.py``):
    ``start = host_lane_count * (subport - 1)``, active lanes
    ``range(start + 1, start + host_lane_count + 1)``. For a non-breakout port
    (``subport == 1``) this range is every lane the module has, so the
    restriction is a no-op there - it only changes behavior for breakout
    sub-ports.

    If NEITHER field is present at all for a port's active lanes (schema
    mismatch, partial STATE_DB publish, or an actual lane-range mismatch), that
    port fails rather than vacuously passing.

    Both TRANSCEIVER_STATUS and PORT_TABLE are read once per distinct
    namespace among ``ports`` (:func:`db_helpers.get_state_db_table` /
    :func:`db_helpers.get_db_table`), not once per port or per breakout
    parent - so N ports sharing M breakout parents across K namespaces cost
    2 x K dumps total, not N (or even M) round-trips. This also means the
    per-call ``status_cache`` a single-port version of this check would need
    to dedup TRANSCEIVER_STATUS reads across a breakout group's subports is
    unnecessary and not part of this function's signature: every port's
    dedup happens for free, once, inside this one call.

    ``namespaces`` maps port -> ASIC namespace; a port missing from it (or a
    caller passing ``None``) has its namespace resolved from the port itself.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names.
        lport_to_first_subport_mapping: the value of the session-scoped
            fixture of the same name (``tests/transceiver/conftest.py``).
        namespaces: optional dict of ``{port: namespace}``.

    Returns:
        dict: ``{port: {'passed': bool, 'details': str}}``, one entry per ``ports``.
    """
    if namespaces is None:
        namespaces = {}

    def _namespace_for(port):
        if port in namespaces:
            return namespaces[port]
        return db_helpers.resolve_namespace(duthost, port)

    ports_by_ns = {}
    for port in ports:
        ports_by_ns.setdefault(_namespace_for(port), []).append(port)

    status_by_parent = {}
    port_table_by_port = {}
    for ns in ports_by_ns:
        status_dump, status_err = db_helpers.get_state_db_table(duthost, "TRANSCEIVER_STATUS", namespace=ns)
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
                "details": f"{port}: TRANSCEIVER_STATUS|{parent} missing or empty",
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
        active_lanes = set(range(lane_start + 1, lane_start + host_lane_count + 1))

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

        if datapath_fields_seen == 0 and config_fields_seen == 0:
            per_port[port] = {
                "passed": False,
                "details": (
                    f"{port} (parent {parent}) TRANSCEIVER_STATUS|{parent} has no "
                    f"DP<N>State or config_state_hostlane<N> fields for this port's "
                    f"active host lanes {sorted(active_lanes)} - cannot confirm CMIS "
                    "state (schema mismatch, partial publish, or lane-range mismatch)"
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
                "details": f"{port} (parent {parent}) CMIS state NOT activated - " + "; ".join(problems),
            }
            continue

        per_port[port] = {
            "passed": True,
            "details": f"{port} (parent {parent}) CMIS DataPathActivated + ConfigSuccess",
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
    """Run the Standard Port Recovery and Verification Procedure on a batch of ports.

    Each step below runs batched across every port in ``ports`` - one polling
    loop / observation window / host-wide check per call, not one per port -
    so N ports share fixed costs instead of multiplying them:
      1. Link Status         - one poll (via
                               :func:`tests.common.platform.interface_utils.wait_ports_oper_status`)
                               of every port off the same ``show interface description``
                               dump per cycle; oper-up within ``link_up_timeout_sec``.
      2. Link Flap/Stability - two sub-checks, for every port that came up,
                               sharing one flap/last_up_time sentinel captured
                               right after step 1 (:func:`capture_flap_sentinels`)
                               so neither re-reads PORT_TABLE for the same value:
                               (a) mandatory "Stability (always)": the sentinel
                               is asserted unchanged (:func:`assert_no_flap_since`)
                               only after steps 3/5 below have run, sleeping
                               only whatever's left of ``stability_window_sec``
                               past their own elapsed time - so the observation
                               overlaps that work (including the often much
                               longer LLDP wait) instead of prefixing it with a
                               dead sleep, while still always covering at least
                               ``stability_window_sec``; (b) "no flap across the
                               operation", only when the caller passes
                               ``assert_no_flap_across_op=True`` (only valid for
                               operations where the link stays up *and* APPL_DB
                               isn't rebuilt, e.g. xcvrd/pmon restart) -
                               compares the same sentinel's ``flap_count``
                               against ``flap_count_baseline``.
      3. LLDP                - neighbor learned, for every up port with
                               ``verify_lldp_on_link_up``; per-port polls are
                               interleaved (poll all pending -> drop satisfied
                               -> repeat) so waits overlap instead of summing.
      5. CMIS State          - DataPathActivated + ConfigSuccess, for every up
                               port that is ``cmis_active_optical``, in one
                               batched :func:`check_cmis_state` call across all
                               of them - TRANSCEIVER_STATUS and PORT_TABLE are
                               each read once per distinct namespace, not once
                               per port or per breakout parent.
      7. Docker/process health - delegates to
                               :func:`tests.transceiver.common.health_checks.verify_health`,
                               the single owner of the xcvrd/syncd/orchagent
                               process + ``/var/core`` check, comparing
                               against the *same* ``health_baseline`` and
                               ``expected_pid_changes`` the autouse
                               ``_per_test_health_check`` fixture already
                               uses - so a mid-test call here and that
                               fixture's own post-test check agree on what
                               counts as a regression, instead of each
                               tracking its own baseline. No uptime floor:
                               unchanged PID (modulo ``expected_pid_changes``)
                               plus no new core files is the whole check.
                               Host-wide and port-count-independent: runs
                               exactly once per call regardless of
                               ``len(ports)``, and unconditionally -
                               independent of any port's link state.

    Remote-Side Link Verification (test-plan step 4, optional/opt-in) and SI
    Settings Verification (test-plan step 6, optics + media) are intentionally
    not implemented here; step 4 lands with the event-handling and
    system-recovery tests that exercise it, and step 6 lands in a separate PR
    pending further discussion.

    Every port's sub-failures are accumulated and reported together so a
    single call surfaces every problem on every port.

    Args:
        duthost: SONiC DUT host fixture.
        ports: list of logical interface names to validate.
        port_attributes_dict: dict of ``{port: port_attrs}`` (as produced by
            the ``port_attributes_dict`` fixture), with one entry per port in
            ``ports``.
        link_up_timeout_sec: budget for waiting on oper-up - shared across
            every port in ``ports``, not per port. Callers size this to match
            the invoking operation (e.g. ``port_startup_wait_sec`` for a port
            startup, the relevant ``<op>_settle_sec`` for a restart / reboot /
            config reload / power cycle).
        health_baseline: the dict returned by
            :func:`tests.transceiver.common.health_checks.capture_baseline` -
            in practice, the value of the ``health_baseline`` pytest fixture
            (``tests/transceiver/conftest.py``), the *same* pre-test baseline
            the autouse ``_per_test_health_check`` fixture already verifies
            against at test teardown. Passing that fixture value here (rather
            than a fresh baseline captured just before this call's disruptive
            action) is what lets step 7 and the per-test post-test check
            agree on one definition of "unchanged since the test started".
        lport_to_first_subport_mapping: the value of the session-scoped
            fixture of the same name (``tests/transceiver/conftest.py``),
            resolved once per session - passed through so step 5 doesn't
            re-query and re-cache the same logical->physical port map here.
        stability_window_sec: shared post-recovery observation window
            (seconds) for the step-2 stability sub-check, applied once across
            every port that came up. Defaults to
            :data:`DEFAULT_STABILITY_WINDOW_SEC` (5) - the test plan does not
            pin an exact duration, only "a short post-recovery observation
            window".
        expected_pid_changes: set of monitored process names (see
            ``health_checks.DEFAULT_MONITORED_PROCESSES``) whose PID is
            expected to differ from ``health_baseline`` in the step-7 health
            check. In practice, the value of the ``expected_pid_changes``
            pytest fixture - the same set a restart-based test already
            populates (e.g. ``expected_pid_changes.add("xcvrd")`` before
            restarting ``pmon``) for the per-test post-test check, passed
            through here so step 7 honors the same declaration instead of
            requiring a second one. Without it, a process restarted by the
            caller's own disruptive action would fail step 7 as an
            "unexpected restart".
        flap_count_baseline: optional dict of ``{port: flap_count}`` captured
            in Common Setup, before the caller's disruptive operation. Only
            consulted when ``assert_no_flap_across_op`` is True; required in
            that case (per port - see the "missing baseline" failure below).
        assert_no_flap_across_op: whether to run sub-check 2b (see step 2
            above). Defaults to False; the caller sets it True only for
            operations where the link is expected to stay up *and* the flap
            counter survives (``xcvrd``/``pmon`` restart) - never for
            operations that rebuild the port DB (``swss``/``syncd`` restart,
            ``config reload``, reboots, power cycle), where the counter
            resets to 0 and this comparison would be meaningless.

    Returns:
        dict: ``{'passed': bool, 'per_port': {port: {'passed': bool, 'details': str}}, 'details': str}``
    """
    # Owning ASIC namespace per port, resolved once and reused for every
    # per-namespace DB read below (LLDP / TRANSCEIVER_STATUS / stability).
    # ``None`` on single-ASIC -> no ``-n`` flag.
    namespaces = {port: db_helpers.resolve_namespace(duthost, port) for port in ports}

    per_port_failures = {port: [] for port in ports}
    checks_ran = {port: [] for port in ports}  # human-readable checks that ran, per port

    # 1. Link status - one batched poll covers every port.
    down_ports = wait_ports_oper_status(duthost, ports, "up", link_up_timeout_sec)
    for port in ports:
        checks_ran[port].append("link up")
    for port in down_ports:
        per_port_failures[port].append(f"port {port} did not reach oper-up within {link_up_timeout_sec}s")

    up_ports = [port for port in ports if port not in down_ports]

    # 2a/2b setup - one shared flap/last_up_time sentinel per up port, captured
    # right after link-up. recovery_t0 anchors 2a's end-gate below (after
    # steps 3/5 run) to this moment rather than to whenever that gate
    # happens to execute, so the observation window it asserts against always
    # covers the full post-recovery period - not just whatever's left after
    # the other steps' own wall-clock time. Serves both 2a (forward-looking,
    # asserted later) and 2b (compared against the caller's pre-op baseline,
    # right below) so neither re-reads PORT_TABLE for the same value.
    recovery_t0 = time.monotonic()
    post_recovery_sentinels = capture_flap_sentinels(duthost, up_ports, namespaces=namespaces) if up_ports else {}

    # 2b. No flap across the operation - only where the flap counter survives
    #     (xcvrd/pmon restart, declared by the caller via
    #     assert_no_flap_across_op). Skipped for DB-rebuilding ops
    #     (swss/syncd restart, config reload, reboot, power cycle) whose
    #     counter resets to 0 - for those, 2a below is the only flap check.
    if assert_no_flap_across_op:
        for port in up_ports:
            checks_ran[port].append("no-flap-across-op")
            baseline_flap = (flap_count_baseline or {}).get(port)
            current_flap, _current_up = post_recovery_sentinels.get(port, (None, None))
            if baseline_flap is None or current_flap is None:
                per_port_failures[port].append(
                    f"{port}: cannot assert across-op no-flap - flap_count baseline/current missing"
                )
            elif current_flap != baseline_flap:
                per_port_failures[port].append(
                    f"{port}: flapped across operation (flap_count {baseline_flap} -> {current_flap})"
                )

    # 3. LLDP - only for up ports that request it (otherwise LLDP is moot);
    #    per-port timeouts honored, polls interleaved across the batch.
    lldp_port_timeouts = {}
    for port in up_ports:
        sys_attrs = port_attributes_dict.get(port, {}).get(SYSTEM_ATTRIBUTES_KEY, {})
        if sys_attrs.get("verify_lldp_on_link_up", True):
            if "lldp_neighbor_wait_sec" not in sys_attrs:
                raise ValueError(
                    f"{port}: 'lldp_neighbor_wait_sec' is not defined in SYSTEM_ATTRIBUTES "
                    "(system.json 'defaults', or a more specific override) - required "
                    "whenever verify_lldp_on_link_up is True"
                )
            lldp_port_timeouts[port] = sys_attrs["lldp_neighbor_wait_sec"]
    if lldp_port_timeouts:
        lldp_results = check_lldp_neighbors_present(
            duthost, lldp_port_timeouts, namespaces=namespaces
        )
        for port, result in lldp_results.items():
            checks_ran[port].append("LLDP")
            if not result["passed"]:
                per_port_failures[port].append(result["details"])

    # 5. CMIS state - only for up ports that are CMIS active-optical, in one
    #    batched check_cmis_state call across all of them: TRANSCEIVER_STATUS
    #    and PORT_TABLE are each read once per distinct namespace, not once
    #    per port or per breakout parent.
    cmis_active_ports = [
        port for port in up_ports
        if is_cmis_active_optical(port_attributes_dict.get(port, {}).get(EEPROM_ATTRIBUTES_KEY, {}))
    ]
    if cmis_active_ports:
        cmis_results = check_cmis_state(
            duthost, cmis_active_ports, lport_to_first_subport_mapping, namespaces=namespaces
        )
        for port, result in cmis_results.items():
            checks_ran[port].append("CMIS state")
            if not result["passed"]:
                per_port_failures[port].append(result["details"])

    # 2a end-gate. Link Flap/Stability - mandatory "Stability (always)"
    # sub-check, only for ports that came up (nothing to observe stability of
    # otherwise). Rather than a leading sleep before steps 3/5, the
    # observation window is anchored to recovery_t0 (captured in the 2a/2b
    # setup above, right after link-up) and only asserted here, after
    # everything else has run - so a flap during the LLDP wait (typically the
    # longest phase) is caught too, and the observation overlaps that work
    # instead of prefixing it with dead time. Sleeping only whatever's left of
    # stability_window_sec past the other steps' own elapsed time still
    # guarantees a total window of at least stability_window_sec either way:
    # if the other steps already took longer, elapsed already exceeds it and
    # no extra sleep is needed; otherwise the remaining sleep tops it up.
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

    # 7. Docker and process health check (per system_test_plan.md). Delegates
    #    to health_checks.verify_health - the single owner of the
    #    xcvrd/syncd/orchagent process check and the /var/core diff - against
    #    the same health_baseline and expected_pid_changes the autouse
    #    _per_test_health_check fixture (tests/transceiver/conftest.py) uses
    #    at test teardown, so this mid-test check and that end-of-test check
    #    agree on what "unchanged since the test started" means. No uptime
    #    floor: unchanged PID (modulo expected_pid_changes) plus no new core
    #    files is the whole check.
    #    Host-wide: runs exactly once for the whole batch, unconditionally -
    #    if a port's link didn't come back, knowing whether a critical
    #    service died on the way is exactly the diagnostic we want, for every
    #    port in the batch.
    if health_baseline is None:
        health_failure = (
            "health_baseline not provided - caller must pass the 'health_baseline' "
            "pytest fixture value (tests/transceiver/conftest.py)"
        )
    else:
        health_result = health_checks.verify_health(
            duthost, health_baseline, expect_pid_change=expected_pid_changes,
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
