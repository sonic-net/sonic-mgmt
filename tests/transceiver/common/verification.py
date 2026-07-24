"""Standard Port Recovery and Verification Procedure for transceiver System tests.

Lives at the location reserved by
``docs/testplan/transceiver/diagrams/file_organization.md`` for the
"Standard Port Recovery and Verification Procedure".

Implements the subset of the procedure defined in
``docs/testplan/transceiver/system_test_plan.md`` (§ Common Verification
Procedures) that the Link Behavior System tests exercise after restoring a
batch of ports: link status → link flap/stability → LLDP → CMIS state → SI
settings → docker/process health. Each check returns a result dict (with
``'passed'`` and ``'details'`` keys) and the top-level
:func:`standard_port_recovery_and_verification` runs every step batched
across the whole ``ports`` list - one polling loop / observation window per
step instead of one per port - and aggregates each port's sub-failures into
its own ``details`` string, so a single call surfaces every problem on every
port without multiplying the fixed-wait and host-wide steps by port count.

Remote-Side Link Verification (test-plan step 4, optional/opt-in - enabled by
callers such as disruptive Event Handling and System Recovery tests) is
intentionally not implemented here; it is added alongside the diagnostics and
event-handling tests that exercise it.

DB reads go through :mod:`tests.transceiver.common.db_helpers`
(``hgetall_dict``). The docker/process health step delegates entirely to
:mod:`tests.transceiver.common.health_checks`, which owns the
xcvrd/syncd/orchagent process check and the ``/var/core`` diff shared with
the rest of the transceiver suite. SI settings verification delegates EEPROM
reads to :mod:`tests.transceiver.common.cli_helpers`.
"""
import logging
import re
import time

from tests.common.platform.interface_utils import wait_ports_oper_status
from tests.transceiver.attribute_parser.attribute_keys import (
    EEPROM_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers, db_helpers, health_checks
from tests.transceiver.common.eeprom_decode import is_cmis_active_optical

logger = logging.getLogger(__name__)

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
# SI Settings check
# ──────────────────────────────────────────────────────────────────────

# optics_si_settings key format: "page.<hex>h_<decimal offset>", e.g.
# "page.11h_223" -> EEPROM upper page 0x11, byte offset 223. The value is the
# expected raw bytes at that region (one list entry per byte).
_OPTICS_SI_KEY_RE = re.compile(r'^page\.([0-9a-fA-F]+)h_(\d+)$', re.IGNORECASE)


def check_optics_si_settings(duthost, port, optics_si_settings):
    """Verify EEPROM bytes at each region named in ``optics_si_settings`` match.

    ``optics_si_settings`` (the ``transceivers``-level attribute) is a dict of
    ``{"page.<hex>h_<decimal offset>": [expected_byte, ...]}``, e.g.
    ``{"page.11h_223": [34, 34, 34, 34, 0, 0, 0, 0, 51, 51, 51, 51]}``. Each
    key names one EEPROM upper-page + byte-offset region; the value is the
    expected raw bytes there, read via ``sfputil read-eeprom`` (see
    :func:`cli_helpers.sfputil_read_eeprom`).

    Skips (passes) if ``optics_si_settings`` is empty/undefined, matching the
    attribute's "test runs if dictionary is non-empty" contract.

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    if not optics_si_settings:
        return {"passed": True, "details": f"{port}: optics_si_settings not defined, skipped"}

    mismatches = []
    for key, expected in optics_si_settings.items():
        match = _OPTICS_SI_KEY_RE.match(key)
        if not match:
            mismatches.append(f"{key}: unrecognized key format (expected 'page.<hex>h_<offset>')")
            continue
        page = int(match.group(1), 16)
        offset = int(match.group(2))
        size = len(expected)
        parsed, err = cli_helpers.sfputil_read_eeprom(duthost, port, offset=offset, size=size, page=page)
        if err:
            mismatches.append(f"{key}: {err}")
            continue
        actual = [parsed.get(offset + i) for i in range(size)]
        if actual != list(expected):
            mismatches.append(f"{key}: expected {list(expected)}, got {actual}")

    if mismatches:
        details = f"{port}: optics SI settings mismatch - " + "; ".join(mismatches)
        logger.warning("Optics SI settings check FAILED: %s", details)
        return {"passed": False, "details": details}

    details = f"{port}: optics SI settings match ({len(optics_si_settings)} region(s))"
    logger.info("Optics SI settings check PASSED: %s", details)
    return {"passed": True, "details": details}


def check_media_si_settings(duthost, port, media_si_settings, namespace=None, require_npu_si_settings_done=True):
    """Verify ``port``'s applied media-side SI settings against APPL_DB.

    If ``require_npu_si_settings_done`` (default ``True``), first gates on
    ``NPU_SI_SETTINGS_SYNC_STATUS`` (``PORT_TABLE|<port>`` in STATE_DB - set
    by xcvrd/orchagent, per
    ``docs/sfp-cmis/Interface-Link-bring-up-sequence.md`` upstream) being
    ``NPU_SI_SETTINGS_DONE``: a value of ``NPU_SI_SETTINGS_DEFAULT`` or
    ``NPU_SI_SETTINGS_NOTIFIED`` means the NPU hasn't finished applying SI
    settings yet, so comparing now would either race a real value or compare
    against stale/default silicon state.

    ``require_npu_si_settings_done=False`` skips this gate entirely and goes
    straight to the comparison. This is for deployments that program media SI
    settings by a path other than the xcvrd/``media_settings.json`` sync
    workflow (e.g. straight from ``config_db.json`` at boot) - on those,
    ``NPU_SI_SETTINGS_SYNC_STATUS`` sits at ``NPU_SI_SETTINGS_DEFAULT``
    permanently, by design, since that sync cycle is never triggered; treating
    it as a not-yet-converged failure would be a permanent false negative.
    In practice, the value of the ``require_npu_si_settings_done``
    SYSTEM_ATTRIBUTES attribute.

    ``media_si_settings`` is a flat dict of field name -> expected value (e.g.
    ``pre3``/``pre2``/``pre1``/``main``/``post1``/``idriver``, following
    ``media_settings.json`` structure); these are compared directly against
    the same-named fields SONiC publishes to ``APPL_DB PORT_TABLE:<port>``
    once the port is up. Nvidia/Mellanox-only in this suite - no vendor
    branch here.

    Skips (passes) if ``media_si_settings`` is empty/undefined, matching the
    attribute's "test runs if dictionary is non-empty" contract.

    ``namespace`` scopes the DB reads to the owning ASIC; when ``None`` it is
    resolved from ``port``.

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    if not media_si_settings:
        return {"passed": True, "details": f"{port}: media_si_settings not defined, skipped"}
    if namespace is None:
        namespace = resolve_namespace(duthost, port)

    if require_npu_si_settings_done:
        state_port_table = db_helpers.hgetall_dict(duthost, "STATE_DB", f"PORT_TABLE|{port}", namespace=namespace)
        sync_status = state_port_table.get("NPU_SI_SETTINGS_SYNC_STATUS")
        if sync_status != "NPU_SI_SETTINGS_DONE":
            details = (
                f"{port}: NPU_SI_SETTINGS_SYNC_STATUS is {sync_status!r}, not 'NPU_SI_SETTINGS_DONE' "
                f"(PORT_TABLE|{port} in STATE_DB) - NPU SI settings sync not complete"
            )
            logger.warning("Media SI settings check FAILED: %s", details)
            return {"passed": False, "details": details}

    port_table = db_helpers.hgetall_dict(duthost, "APPL_DB", f"PORT_TABLE:{port}", namespace=namespace)

    mismatches = []
    for field, expected in media_si_settings.items():
        actual = port_table.get(field)
        if actual is None:
            mismatches.append(f"{field}: missing from PORT_TABLE:{port}")
        elif actual != expected:
            mismatches.append(f"{field}: expected {expected}, got {actual}")

    if mismatches:
        details = f"{port}: media SI settings mismatch - " + "; ".join(mismatches)
        logger.warning("Media SI settings check FAILED: %s", details)
        return {"passed": False, "details": details}

    details = f"{port}: media SI settings match ({len(media_si_settings)} field(s))"
    logger.info("Media SI settings check PASSED: %s", details)
    return {"passed": True, "details": details}


# ──────────────────────────────────────────────────────────────────────
# Standard Port Recovery and Verification Procedure
# (see docs/testplan/transceiver/system_test_plan.md)
# ──────────────────────────────────────────────────────────────────────


def _get_transceiver_status(duthost, parent_port, status_cache, namespace=None):
    """Cached fetch of ``STATE_DB TRANSCEIVER_STATUS|<parent_port>`` (per ASIC ns).

    ``status_cache`` is a plain dict scoped to a single
    :func:`standard_port_recovery_and_verification` call - it must NOT be
    reused across separate calls in the same test, since a port's
    TRANSCEIVER_STATUS can legitimately change between two disruptive
    actions; reusing a stale cache would mask that.
    """
    if parent_port not in status_cache:
        status_cache[parent_port] = db_helpers.hgetall_dict(
            duthost, "STATE_DB", f"TRANSCEIVER_STATUS|{parent_port}", namespace=namespace
        )
    return status_cache[parent_port]


def check_cmis_state(duthost, port, lport_to_first_subport_mapping, status_cache, namespace=None):
    """Verify CMIS DataPathState=DataPathActivated and ConfigState=ConfigSuccess.

    ("DataPathActivated" is the literal STATE_DB string, per
    ``docs/testplan/transceiver/test_plan.md``; the CMIS spec's own nibble name
    for the same state, used at the EEPROM layer in ``cmis_helper.py``, is
    "DPActivated".)

    Reads the parent port's ``TRANSCEIVER_STATUS`` once (cached via
    ``status_cache``) and validates every ``host_lane*_datapath_state``
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
    parent = lport_to_first_subport_mapping.get(port, port)
    status = _get_transceiver_status(duthost, parent, status_cache, namespace)
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
      2. Link Flap/Stability - two sub-checks, for every port that came up:
                               (a) mandatory "Stability (always)": one shared
                               ``stability_window_sec`` observation window
                               (snapshot all -> sleep once -> re-read all)
                               instead of one window per port; (b) "no flap
                               across the operation", only when the caller
                               passes ``assert_no_flap_across_op=True`` (only
                               valid for operations where the link stays up
                               *and* APPL_DB isn't rebuilt, e.g. xcvrd/pmon
                               restart) - compares each port's current
                               ``flap_count`` against ``flap_count_baseline``.
      3. LLDP                - neighbor learned, for every up port with
                               ``verify_lldp_on_link_up``; per-port polls are
                               interleaved (poll all pending -> drop satisfied
                               -> repeat) so waits overlap instead of summing.
      5. CMIS State          - DataPathActivated + ConfigSuccess, for every up
                               port that is ``cmis_active_optical``; per-parent
                               ``TRANSCEIVER_STATUS`` reads are cached for the
                               duration of this call so subports of the same
                               breakout group cost one extra STATE_DB read,
                               not one per subport.
      6. SI Settings         - for every up port: optics SI (EEPROM bytes via
                               :func:`check_optics_si_settings`, iff
                               ``optics_si_settings`` is defined) and media SI
                               (live SerDes TXEQ or APPL_DB, via
                               :func:`check_media_si_settings`, iff
                               ``media_si_settings`` is defined).
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

    Remote-Side Link Verification (test-plan step 4, optional/opt-in) is
    intentionally not implemented here; it lands with the event-handling and
    system-recovery tests that exercise it.

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
    # Per-parent TRANSCEIVER_STATUS cache, scoped to this call only - a port's
    # status can legitimately change between two separate calls in the same
    # test (e.g. two disruptive actions), so this is never persisted or
    # threaded in from the caller.
    transceiver_status_cache = {}

    # Owning ASIC namespace per port, resolved once and reused for every
    # per-namespace DB read below (LLDP / TRANSCEIVER_STATUS / stability).
    # ``None`` on single-ASIC -> no ``-n`` flag.
    namespaces = {port: resolve_namespace(duthost, port) for port in ports}

    per_port_failures = {port: [] for port in ports}
    checks_ran = {port: [] for port in ports}  # human-readable checks that ran, per port

    # 1. Link status - one batched poll covers every port.
    down_ports = wait_ports_oper_status(duthost, ports, "up", link_up_timeout_sec)
    for port in ports:
        checks_ran[port].append("link up")
    for port in down_ports:
        per_port_failures[port].append(f"port {port} did not reach oper-up within {link_up_timeout_sec}s")

    up_ports = [port for port in ports if port not in down_ports]

    # 2a. Link Flap/Stability - mandatory "Stability (always)" sub-check, only
    #     for ports that came up (nothing to observe stability of otherwise).
    #     One shared window covers every up port.
    if up_ports:
        stability_results = check_ports_stability(
            duthost, up_ports, stability_window_sec, namespaces=namespaces
        )
        for port, result in stability_results.items():
            checks_ran[port].append("stability")
            if not result["passed"]:
                per_port_failures[port].append(result["details"])

    # 2b. No flap across the operation - only where the flap counter survives
    #     (xcvrd/pmon restart, declared by the caller via
    #     assert_no_flap_across_op). Skipped for DB-rebuilding ops
    #     (swss/syncd restart, config reload, reboot, power cycle) whose
    #     counter resets to 0 - for those, 2a above is the only flap check.
    if assert_no_flap_across_op:
        for port in up_ports:
            checks_ran[port].append("no-flap-across-op")
            baseline_flap = (flap_count_baseline or {}).get(port)
            port_table = db_helpers.hgetall_dict(
                duthost, "APPL_DB", f"PORT_TABLE:{port}", namespace=namespaces.get(port)
            )
            current_flap = port_table.get("flap_count")
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

    # 5. CMIS state - only for up ports that are CMIS active-optical.
    #    check_cmis_state caches TRANSCEIVER_STATUS per breakout parent in
    #    transceiver_status_cache, so looping here costs at most one extra
    #    STATE_DB read per breakout group, not one per subport.
    for port in up_ports:
        eeprom_attrs = port_attributes_dict.get(port, {}).get(EEPROM_ATTRIBUTES_KEY, {})
        if is_cmis_active_optical(eeprom_attrs):
            cmis_result = check_cmis_state(
                duthost, port, lport_to_first_subport_mapping, transceiver_status_cache,
                namespace=namespaces.get(port),
            )
            checks_ran[port].append("CMIS state")
            if not cmis_result["passed"]:
                per_port_failures[port].append(cmis_result["details"])

    # 6. SI Settings - only for up ports; optics (EEPROM) and media (live
    #    SerDes or APPL_DB, depending on platform) each independently gated on
    #    their own attribute being non-empty.
    for port in up_ports:
        sys_attrs = port_attributes_dict.get(port, {}).get(SYSTEM_ATTRIBUTES_KEY, {})
        optics_si_settings = sys_attrs.get("optics_si_settings")
        if optics_si_settings:
            optics_result = check_optics_si_settings(duthost, port, optics_si_settings)
            checks_ran[port].append("optics SI settings")
            if not optics_result["passed"]:
                per_port_failures[port].append(optics_result["details"])

        media_si_settings = sys_attrs.get("media_si_settings")
        if media_si_settings:
            media_result = check_media_si_settings(
                duthost, port, media_si_settings, namespace=namespaces.get(port),
                require_npu_si_settings_done=sys_attrs.get("require_npu_si_settings_done", True),
            )
            checks_ran[port].append("media SI settings")
            if not media_result["passed"]:
                per_port_failures[port].append(media_result["details"])

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
