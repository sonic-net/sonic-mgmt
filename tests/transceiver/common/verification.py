"""Standard Port Recovery and Verification Procedure for transceiver System tests.

Lives at the location reserved by
``docs/testplan/transceiver/diagrams/file_organization.md`` for the
"Standard Port Recovery and Verification Procedure".

Implements the subset of the procedure defined in
``docs/testplan/transceiver/system_test_plan.md`` (§ Common Verification
Procedures) that the Link Behavior System tests exercise after restoring a
port: link status → LLDP → CMIS state → docker/process health. Each check
returns a result dict (with ``'passed'`` and ``'details'`` keys) and the
top-level :func:`standard_port_recovery_and_verification` aggregates every
sub-failure into one ``details`` string so a single call surfaces every
problem on the port.

The optics/media-SI and application-code checks called out in the test plan
are added alongside the diagnostics tests that exercise them, rather than
shipped here ahead of any caller.

DB reads go through :mod:`tests.transceiver.common.db_helpers`
(``hgetall_dict``).
"""
import logging
import re
import time

from tests.common.platform.interface_utils import (
    get_dut_interfaces_status,
    get_physical_port_indices,
)
from tests.transceiver.attribute_parser.attribute_keys import (
    EEPROM_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import db_helpers

logger = logging.getLogger(__name__)

# Minimum continuous uptime (seconds) the health check requires of every
# critical service (pmon, swss, syncd containers and the xcvrd process).
# Per system_test_plan.md "Docker and Process Health Check": services must be
# running for at least 3 minutes. Disruptive tests that deliberately restart a
# service (e.g. xcvrd restart) must dwell long enough for the restarted service
# to clear this floor before calling the health check.
MIN_CRITICAL_SERVICE_UPTIME_SEC = 180


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
# Standard Port Recovery and Verification Procedure
# (see docs/testplan/transceiver/system_test_plan.md)
# ──────────────────────────────────────────────────────────────────────


def _resolve_parent_port(duthost, port, shared_state):
    """Return the parent (first sibling) of ``port`` in its breakout group.

    For a breakout cage with logical ports Ethernet0..Ethernet<N-1>, every
    member resolves to the parent ``Ethernet0``. The logical->physical map is
    cached in ``shared_state`` so it is queried at most once per test.
    """
    if "logical_to_physical" not in shared_state:
        shared_state["logical_to_physical"] = get_physical_port_indices(duthost)
        phys_to_logicals = {}
        for logical, phys in shared_state["logical_to_physical"].items():
            if phys is None:
                continue
            phys_to_logicals.setdefault(phys, []).append(logical)

        def _eth_index(p):
            digits = "".join(c for c in p if c.isdigit())
            return int(digits) if digits else 0

        shared_state["physical_to_parent"] = {
            phys: min(logicals, key=_eth_index)
            for phys, logicals in phys_to_logicals.items()
        }

    phys = shared_state["logical_to_physical"].get(port)
    if phys is None:
        return port
    return shared_state["physical_to_parent"].get(phys, port)


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
):
    """Run the Standard Port Recovery and Verification Procedure on one port.

    Steps (per ``system_test_plan.md``):
      1. Link Status         - port oper-up within ``link_up_timeout_sec``.
      2. LLDP                - neighbor learned, iff ``verify_lldp_on_link_up``.
      3. CMIS State          - DataPathActivated + ConfigSuccess, iff the
                               port is ``cmis_active_optical``.
      4. Docker/process health - critical containers (pmon, swss, syncd) and
                               xcvrd (inside pmon) all running for >= 180 s,
                               and no NEW core files in ``/var/core`` relative to
                               ``shared_state['core_baseline']`` (pre-existing /
                               stale cores are ignored). Runs unconditionally -
                               independent of link state.

    The optics/media-SI and application-code steps from the test plan are
    intentionally not implemented here; they land with the diagnostics tests
    that exercise them.

    All sub-failures are accumulated and reported together so a single
    call surfaces every problem on the port.

    Args:
        duthost: SONiC DUT host fixture.
        port: logical interface name to validate.
        port_attrs: per-port attribute dict (entry of ``port_attributes_dict``).
        link_up_timeout_sec: budget for waiting on oper-up.
        shared_state: optional dict shared across calls in the same test so
            the logical->physical port map and per-parent
            ``TRANSCEIVER_STATUS`` queries happen at most once. May carry a
            ``'core_baseline'`` set (the ``/var/core`` basenames captured by the
            caller before the disruptive action) so the health check flags only
            cores created during the test; when absent, every core in
            ``/var/core`` is treated as new.
        min_uptime_sec: minimum continuous uptime (seconds) required of the
            critical containers and the xcvrd process in the step-4 health
            check. Defaults to :data:`MIN_CRITICAL_SERVICE_UPTIME_SEC` (180,
            i.e. the test plan's 3-minute floor). Callers that deliberately
            restart a service must dwell long enough for it to clear this
            value before calling.

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

    # 2. LLDP - only if requested and link came up (otherwise LLDP is moot).
    if link_result["passed"] and sys_attrs.get("verify_lldp_on_link_up", True):
        lldp_timeout = sys_attrs.get("lldp_neighbor_wait_sec", 60)
        lldp_result = check_lldp_neighbor_present(
            duthost, port, timeout_sec=lldp_timeout, namespace=namespace
        )
        checks_ran.append("LLDP")
        if not lldp_result["passed"]:
            failures.append(lldp_result["details"])

    # 3. CMIS state - only if link came up and port is CMIS active-optical.
    if link_result["passed"] and eeprom_attrs.get("cmis_active_optical"):
        cmis_result = check_cmis_state(duthost, port, shared_state, namespace=namespace)
        checks_ran.append("CMIS state")
        if not cmis_result["passed"]:
            failures.append(cmis_result["details"])

    # 4. Docker and process health check (per system_test_plan.md):
    #      - critical containers (pmon, swss, syncd) running for >= 3 min
    #      - xcvrd inside pmon running for >= 3 min via supervisorctl
    #      - no NEW core files in /var/core (vs the caller-seeded
    #        shared_state['core_baseline']); stale/pre-existing cores are ignored
    #    One bash script collects everything per port to keep SSH round-trips
    #    to a single call; the parse below is line-based on the structured
    #    output it emits ("CONTAINER|<name>|<state>|<etimes>",
    #    "PROCESS|xcvrd|<supervisorctl_line>", and a "CORES_BEGIN".."CORES_END"
    #    block listing /var/core/* basenames).
    #    Runs unconditionally - if the port's link didn't come back, knowing
    #    whether a critical service died on the way is exactly the diagnostic
    #    we want.
    checks_ran.append("health")
    health_failures = []
    # Pre-existing/stale cores (seeded by the caller before the disruptive
    # action) are subtracted out so only cores created during the test fail it.
    core_baseline = shared_state.get("core_baseline", set())
    # Critical containers to check. swss/syncd are per-ASIC services: on a
    # multi-ASIC DUT they are suffixed (swss0/syncd0, swss1/syncd1, ...) while a
    # single-ASIC DUT keeps the bare names - ``get_docker_name`` yields the right
    # form for each. pmon is a single host-level container (and also hosts
    # xcvrd), so it is checked once regardless of ASIC count.
    containers = ["pmon"]
    for asic in duthost.asics:
        containers.append(asic.get_docker_name("swss"))
        containers.append(asic.get_docker_name("syncd"))
    container_list = " ".join(containers)
    health_script = (
        f"for c in {container_list}; do "
        "  pid=$(docker inspect -f '{{.State.Pid}}' \"$c\" 2>/dev/null || echo 0); "
        "  if [ \"$pid\" -gt 0 ] 2>/dev/null; then "
        "    et=$(ps -o etimes= -p \"$pid\" 2>/dev/null | tr -d ' '); "
        "    echo \"CONTAINER|$c|up|${et:-?}\"; "
        "  else "
        "    echo \"CONTAINER|$c|down|0\"; "
        "  fi; "
        "done; "
        "sv_line=$(docker exec pmon supervisorctl status xcvrd 2>/dev/null | head -1); "
        "echo \"PROCESS|xcvrd|${sv_line:-MISSING}\"; "
        "echo CORES_BEGIN; "
        "find /var/core/ -maxdepth 1 -type f -printf '%f\\n' 2>/dev/null; "
        "echo CORES_END"
    )
    health_out = duthost.shell(health_script, module_ignore_errors=True)
    if health_out.get("rc", 1) != 0:
        health_failures.append(
            f"health probe failed (rc={health_out.get('rc')}, "
            f"stderr={(health_out.get('stderr') or '').strip()})"
        )
    else:
        core_files = []
        in_cores = False
        for raw in (health_out.get("stdout_lines") or []):
            line = raw.rstrip()
            if line == "CORES_BEGIN":
                in_cores = True
                continue
            if line == "CORES_END":
                in_cores = False
                continue
            if in_cores:
                if line.strip():
                    core_files.append(line.strip())
                continue
            parts = line.split("|")
            if parts[0] == "CONTAINER" and len(parts) >= 4:
                name, state, et_str = parts[1], parts[2], parts[3]
                if state != "up":
                    health_failures.append(f"container {name}: not running")
                    continue
                try:
                    et = int(et_str)
                except (ValueError, TypeError):
                    health_failures.append(
                        f"container {name}: unparseable uptime {et_str!r}"
                    )
                    continue
                if et < min_uptime_sec:
                    health_failures.append(
                        f"container {name}: uptime {et}s < {min_uptime_sec}s"
                    )
            elif parts[0] == "PROCESS" and len(parts) >= 3:
                # parts[2:] reassembled in case the supervisorctl line contains
                # a literal '|' (it doesn't today, but be defensive).
                sv_text = "|".join(parts[2:])
                if sv_text == "MISSING":
                    health_failures.append("process xcvrd: supervisorctl unreachable")
                    continue
                if "RUNNING" not in sv_text:
                    health_failures.append(
                        f"process xcvrd: not RUNNING ({sv_text.strip()!r})"
                    )
                    continue
                # Supervisor emits either "uptime H:M:S" or "uptime N day(s), H:M:S".
                m = re.search(r"uptime\s+(?:(\d+)\s+days?,\s+)?(\d+):(\d+):(\d+)", sv_text)
                if not m:
                    health_failures.append(
                        f"process xcvrd: no uptime field ({sv_text.strip()!r})"
                    )
                    continue
                days = int(m.group(1) or 0)
                h, mn, s = int(m.group(2)), int(m.group(3)), int(m.group(4))
                xcvrd_uptime = days * 86400 + h * 3600 + mn * 60 + s
                if xcvrd_uptime < min_uptime_sec:
                    health_failures.append(
                        f"process xcvrd: uptime {xcvrd_uptime}s < {min_uptime_sec}s"
                    )
        new_cores = sorted(set(core_files) - core_baseline)
        if new_cores:
            health_failures.append(
                f"/var/core has new core file(s) since test start: {', '.join(new_cores)}"
            )

    if health_failures:
        failures.append(f"{port} health: " + "; ".join(health_failures))

    if failures:
        details = f"{port}: " + "; ".join(failures)
        logger.warning("Standard Port Recovery FAILED: %s", details)
        return {"passed": False, "details": details}

    details = f"{port}: " + " + ".join(checks_ran) + " all OK"
    logger.info("Standard Port Recovery PASSED: %s", details)
    return {"passed": True, "details": details}
