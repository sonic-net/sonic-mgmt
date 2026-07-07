"""Standard Port Recovery and Verification Procedure for transceiver System tests.

Lives at the location reserved by
``docs/testplan/transceiver/diagrams/file_organization.md`` for the
"Standard Port Recovery and Verification Procedure".

Implements the procedure defined in
``docs/testplan/transceiver/system_test_plan.md`` (§ Common Verification
Procedures) that every disruptive System test runs after restoring a port:
link status → LLDP → CMIS state → SI settings → application code →
docker/process health.  Each check returns a result dict (with ``'passed'`` and
``'details'`` keys) and the top-level
:func:`standard_port_recovery_and_verification` aggregates every sub-failure
into one ``details`` string so a single call surfaces every problem on the port.

DB reads go through :mod:`tests.transceiver.common.db_helpers`
(``hgetall_dict``); CLI command spelling lives in
:mod:`tests.transceiver.common.cli_helpers`.
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
from tests.transceiver.common.cli_parser_helper import parse_read_eeprom

logger = logging.getLogger(__name__)

# Same enumeration ``health_checks.py`` uses, so the recovery core check and the
# autouse per-test health fixture agree on what counts as a core file.
_FIND_CORE_FILES_CMD = "find /var/core/ -maxdepth 1 -type f -printf '%f\\n'"


def list_core_files(duthost):
    """Return the set of core-file basenames currently in ``/var/core/``.

    Callers capture this BEFORE a disruptive action and pass it to
    :func:`standard_port_recovery_and_verification` via
    ``shared_state['core_baseline']`` so the recovery health check flags only
    cores created during the test, not pre-existing/stale ones (e.g. old
    ``zebra``/``orchagent`` cores left in ``/var/core`` from earlier crashes).

    Returns an empty set on command failure so a probe error never masquerades
    as "no cores"; the caller's later diff simply has nothing to subtract.
    """
    result = duthost.shell(_FIND_CORE_FILES_CMD, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        logger.warning(
            "Failed to list /var/core/ (rc=%s): %s",
            result.get("rc"), (result.get("stderr") or "").strip(),
        )
        return set()
    stdout = result.get("stdout", "")
    return set(stdout.splitlines()) if stdout.strip() else set()


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
    observed = "missing"
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


def wait_for_ports_oper_state(duthost, ports, expected_state, timeout_sec):
    """Poll ``show interface description`` ONCE per cycle until every port in
    ``ports`` reaches ``expected_state`` (or ``timeout_sec`` elapses).

    Unlike calling :func:`wait_for_port_oper_state` per port, this issues a
    single ``show interface description`` per poll (via
    ``get_dut_interfaces_status``) and checks the whole batch against that one
    snapshot — so verifying N ports costs one command per cycle, not N. Ports
    drop out of the poll as soon as they reach ``expected_state``; the loop ends
    when all are satisfied or the deadline passes.

    Args:
        duthost: SONiC DUT host fixture.
        ports: iterable of logical interface names to check together.
        expected_state: ``"up"`` or ``"down"`` (case-insensitive).
        timeout_sec: maximum seconds to wait for the whole batch.

    Returns:
        dict: ``{port: {'passed': bool, 'observed': str, 'details': str}}``
    """
    ports = list(ports)
    expected = (expected_state or "").strip().lower()
    deadline = time.monotonic() + max(0, int(timeout_sec))
    observed = {port: "missing" for port in ports}
    pending = set(ports)
    while True:
        intf_status = get_dut_interfaces_status(duthost)  # one `show interface description`
        for port in list(pending):
            state = (intf_status.get(port, {}) or {}).get("oper", "missing")
            observed[port] = state
            if state and state.strip().lower() == expected:
                pending.discard(port)
        if not pending or time.monotonic() >= deadline:
            break
        time.sleep(_OPER_POLL_INTERVAL_SEC)

    results = {}
    for port in ports:
        passed = bool(observed[port]) and observed[port].strip().lower() == expected
        if passed:
            details = f"{port}: oper={observed[port]} (expected {expected}) within {timeout_sec}s"
            logger.info("Oper-state wait PASSED: %s", details)
        else:
            details = f"{port}: oper={observed[port]} (expected {expected}) after {timeout_sec}s timeout"
            logger.warning("Oper-state wait FAILED: %s", details)
        results[port] = {"passed": passed, "observed": observed[port], "details": details}
    return results


# ──────────────────────────────────────────────────────────────────────
# LLDP neighbor poll
# ──────────────────────────────────────────────────────────────────────

_LLDP_POLL_INTERVAL_SEC = 3


def _check_lldp_neighbor_present(duthost, port, timeout_sec=30):
    """Poll APPL_DB ``LLDP_ENTRY_TABLE:<port>`` until a neighbor is learned.

    A non-empty ``LLDP_ENTRY_TABLE:<port>`` hash means lldpd has at least
    one neighbor record for ``port``. Used by System tests to confirm the
    far end re-converged after a disruptive operation.

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    deadline = time.monotonic() + max(0, int(timeout_sec))
    cmd = f'sonic-db-cli APPL_DB hgetall "LLDP_ENTRY_TABLE:{port}"'
    last_stdout = ""
    while True:
        out = duthost.shell(cmd, module_ignore_errors=True)
        last_stdout = (out.get("stdout") or "").strip()
        if out.get("rc", 1) == 0 and last_stdout and last_stdout != "{}":
            details = f"{port}: LLDP neighbor present within {timeout_sec}s"
            logger.info("LLDP check PASSED: %s", details)
            return {"passed": True, "details": details}
        if time.monotonic() >= deadline:
            break
        time.sleep(_LLDP_POLL_INTERVAL_SEC)

    details = f"{port}: no LLDP neighbor after {timeout_sec}s (raw='{last_stdout}')"
    logger.warning("LLDP check FAILED: %s", details)
    return {"passed": False, "details": details}


# ──────────────────────────────────────────────────────────────────────
# Standard Port Recovery and Verification Procedure
# (see docs/testplan/transceiver/system_test_plan.md)
# ──────────────────────────────────────────────────────────────────────


def _to_int_or_none(v):
    """Best-effort coerce ``v`` to an int, supporting "0x.." hex strings.

    Returns ``None`` if the value cannot be parsed. Used by the media-SI
    comparison so that "0x28", "0x00000028" and "40" all compare equal.
    """
    if isinstance(v, int):
        return v
    if not isinstance(v, str):
        return None
    s = v.strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 0)
    except (ValueError, TypeError):
        return None


def _resolve_parent_port(duthost, port, shared_state):
    """Return the parent (first sibling) of ``port`` in its breakout group.

    For an 8x100G breakout on physical port index 1 with logical ports
    Ethernet0..Ethernet7, every member resolves to the parent
    ``Ethernet0``. The logical->physical map is cached in
    ``shared_state`` so it is queried at most once per test.
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


def _get_transceiver_status(duthost, parent_port, shared_state):
    """Cached fetch of ``STATE_DB TRANSCEIVER_STATUS|<parent_port>``."""
    cache = shared_state.setdefault("transceiver_status", {})
    if parent_port not in cache:
        cache[parent_port] = db_helpers.hgetall_dict(
            duthost, "STATE_DB", f"TRANSCEIVER_STATUS|{parent_port}"
        )
    return cache[parent_port]


def _check_cmis_state(duthost, port, shared_state):
    """Verify CMIS DataPathState=DPActivated and ConfigState=ConfigSuccess.

    Reads the parent port's ``TRANSCEIVER_STATUS`` once (cached via
    ``shared_state``) and validates every ``host_lane*_datapath_state``
    and ``host_lane*_config_state`` field present in the hash.
    """
    parent = _resolve_parent_port(duthost, port, shared_state)
    status = _get_transceiver_status(duthost, parent, shared_state)
    if not status:
        return {
            "passed": False,
            "details": f"{port}: TRANSCEIVER_STATUS|{parent} missing or empty",
        }

    bad_datapath = []
    bad_config = []
    for k, v in status.items():
        if k.startswith("host_lane") and k.endswith("_datapath_state"):
            if v != "DataPathActivated":
                bad_datapath.append(f"{k}={v}")
        elif k.startswith("host_lane") and k.endswith("_config_state"):
            if v != "ConfigSuccess":
                bad_config.append(f"{k}={v}")

    if bad_datapath or bad_config:
        problems = []
        if bad_datapath:
            problems.append("datapath: " + ", ".join(bad_datapath))
        if bad_config:
            problems.append("config: " + ", ".join(bad_config))
        details = f"{port} (parent {parent}) CMIS state NOT activated - " + "; ".join(problems)
        return {"passed": False, "details": details}

    return {"passed": True, "details": f"{port} (parent {parent}) CMIS DPActivated + ConfigSuccess"}


def standard_port_recovery_and_verification(
    duthost, port, port_attrs, link_up_timeout_sec, shared_state=None
):
    """Run the Standard Port Recovery and Verification Procedure on one port.

    Steps (per ``system_test_plan.md``):
      1. Link Status         - port oper-up within ``link_up_timeout_sec``.
      2. LLDP                - neighbor learned, iff ``verify_lldp_on_link_up``.
      3. CMIS State          - DataPathActivated + ConfigSuccess, iff the
                               port is ``cmis_active_optical``.
      4. SI settings         - optics SI from ``SYSTEM_ATTRIBUTES.optics_si_settings``
                               compared against EEPROM (one ``sfputil read-eeprom``
                               per page region); media SI from
                               ``SYSTEM_ATTRIBUTES.media_si_settings`` compared
                               against ``APPL_DB PORT_TABLE:<port>``. Either
                               sub-check is skipped when its attribute is empty
                               or missing.
      5. Application code    - if ``SYSTEM_ATTRIBUTES.expected_application_code``
                               is defined (not null), compare against the
                               live ``active_apsel_hostlane*`` value in
                               ``STATE_DB TRANSCEIVER_INFO|<port>`` (one lane
                               per port; the others read ``N/A``).
      6. Docker/process health - critical containers (pmon, swss, syncd) and
                               xcvrd (inside pmon) all running for >= 180 s,
                               and no NEW core files in ``/var/core`` relative to
                               ``shared_state['core_baseline']`` (pre-existing /
                               stale cores are ignored). Runs unconditionally -
                               independent of link state.

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
            ``'core_baseline'`` set (from :func:`list_core_files`, captured
            before the disruptive action) so the health check flags only cores
            created during the test; when absent, every core in ``/var/core``
            is treated as new.

    Returns:
        dict: ``{'passed': bool, 'details': str}``
    """
    if shared_state is None:
        shared_state = {}

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
        lldp_result = _check_lldp_neighbor_present(duthost, port, timeout_sec=lldp_timeout)
        checks_ran.append("LLDP")
        if not lldp_result["passed"]:
            failures.append(lldp_result["details"])

    # 3. CMIS state - only if link came up and port is CMIS active-optical.
    if link_result["passed"] and eeprom_attrs.get("cmis_active_optical"):
        cmis_result = _check_cmis_state(duthost, port, shared_state)
        checks_ran.append("CMIS state")
        if not cmis_result["passed"]:
            failures.append(cmis_result["details"])

    # 4. SI settings - only if defined for the port and link came up. Each
    #    sub-check is skipped independently when its attribute is empty.
    if link_result["passed"]:
        # 4a. Optics SI: expected_settings is a dict whose keys are
        #     "page.<hex>h_<offset_decimal>" (e.g. "page.11h_223") and whose
        #     values are lists of expected byte values. Each region is read
        #     once via `sudo sfputil read-eeprom` and compared element-wise.
        optics_si = sys_attrs.get("optics_si_settings") or {}
        if optics_si:
            checks_ran.append("optics SI")
            optics_failures = []
            optics_key_re = re.compile(r"^page\.([0-9a-fA-F]+)h_(\d+)$")
            for si_key, expected in optics_si.items():
                m = optics_key_re.match(si_key)
                if not m:
                    optics_failures.append(f"optics_si[{si_key}]: unrecognized key format")
                    continue
                if not isinstance(expected, list) or not expected:
                    optics_failures.append(
                        f"optics_si[{si_key}]: value must be a non-empty list of bytes"
                    )
                    continue
                page = int(m.group(1), 16)
                offset = int(m.group(2))
                size = len(expected)
                cmd = f"sudo sfputil read-eeprom -p {port} -n 0x{page:02X} -o {offset} -s {size}"
                result = duthost.command(cmd, module_ignore_errors=True)
                if result.get("rc", 1) != 0:
                    optics_failures.append(
                        f"optics_si[{si_key}]: read-eeprom page=0x{page:02X} "
                        f"offset={offset} size={size} failed (rc={result.get('rc')})"
                    )
                    continue
                byte_map = parse_read_eeprom(result.get("stdout_lines", []))
                actual = [byte_map.get(o) for o in range(offset, offset + size)]
                if any(b is None for b in actual):
                    optics_failures.append(
                        f"optics_si[{si_key}]: missing bytes in read-eeprom output (got {byte_map})"
                    )
                    continue
                expected_int = [int(v) for v in expected]
                if actual != expected_int:
                    optics_failures.append(
                        f"optics_si[{si_key}]: actual={actual} expected={expected_int}"
                    )
            if optics_failures:
                failures.append(f"{port} " + "; ".join(optics_failures))

        # 4b. Media SI: expected_settings keys (pre3/pre2/pre1/main/post1/idriver
        #     etc.) are looked up in APPL_DB PORT_TABLE:<port>. Hex strings are
        #     compared by numeric value so "0x28" == "0x00000028" == "40".
        media_si = sys_attrs.get("media_si_settings") or {}
        if media_si:
            checks_ran.append("media SI")
            port_table = db_helpers.hgetall_dict(duthost, "APPL_DB", f"PORT_TABLE:{port}")
            if not port_table:
                failures.append(f"{port}: APPL_DB PORT_TABLE:{port} missing or empty")
            else:
                media_failures = []
                for si_key, expected in media_si.items():
                    if si_key not in port_table:
                        media_failures.append(f"media_si[{si_key}]: not present in PORT_TABLE")
                        continue
                    actual = port_table[si_key]
                    exp_n = _to_int_or_none(expected)
                    act_n = _to_int_or_none(actual)
                    if exp_n is not None and act_n is not None:
                        if exp_n != act_n:
                            media_failures.append(
                                f"media_si[{si_key}]: actual={actual} expected={expected}"
                            )
                    elif str(actual).strip() != str(expected).strip():
                        media_failures.append(
                            f"media_si[{si_key}]: actual={actual} expected={expected}"
                        )
                if media_failures:
                    failures.append(f"{port} " + "; ".join(media_failures))

        # 5. Application code: STATE_DB TRANSCEIVER_INFO|<port> exposes
        #    active_apsel_hostlane<N> per host lane. Per the SONiC convention
        #    for breakout subports, EXACTLY ONE lane holds the live value
        #    (equal to expected_application_code) and ALL OTHER lanes read
        #    literally 'N/A'. This check enforces that schema strictly:
        #      - 0 or >1 matching lanes => failure
        #      - any non-matching lane with a value other than 'N/A' => failure
        #    Skip the whole check if expected_application_code is not defined
        #    or is None.
        expected_app = sys_attrs.get("expected_application_code")
        if expected_app is not None:
            checks_ran.append("application code")
            app_failures = []
            xcvr_info = db_helpers.hgetall_dict(duthost, "STATE_DB", f"TRANSCEIVER_INFO|{port}")
            if not xcvr_info:
                app_failures.append(f"STATE_DB TRANSCEIVER_INFO|{port} missing or empty")
            else:
                exp_n = _to_int_or_none(expected_app)
                lane_entries = {
                    k: v for k, v in xcvr_info.items()
                    if k.startswith("active_apsel_hostlane")
                }
                if not lane_entries:
                    app_failures.append("no active_apsel_hostlane* entry in TRANSCEIVER_INFO")
                else:
                    matches = []   # lane keys whose value equals expected_app
                    na_lanes = []  # lane keys whose value is exactly 'N/A'
                    bad = []       # "lane=value" for lanes that are neither

                    def _eq_expected(actual_value):
                        # Numeric compare first; fall back to string compare.
                        a_n = _to_int_or_none(actual_value)
                        if exp_n is not None and a_n is not None:
                            return exp_n == a_n
                        return str(actual_value).strip() == str(expected_app).strip()

                    for lane_key, actual in lane_entries.items():
                        if str(actual).strip() == "N/A":
                            na_lanes.append(lane_key)
                        elif _eq_expected(actual):
                            matches.append(lane_key)
                        else:
                            bad.append(f"{lane_key}={actual}")

                    if len(matches) == 0:
                        app_failures.append(
                            f"no lane equals expected={expected_app} "
                            f"(N/A={len(na_lanes)}/{len(lane_entries)}, "
                            f"unexpected=[{', '.join(bad) or '-'}])"
                        )
                    elif len(matches) > 1:
                        app_failures.append(
                            f"expected exactly 1 lane = {expected_app}, got "
                            f"{len(matches)}: {', '.join(matches)}"
                        )
                    if bad:
                        app_failures.append(
                            f"non-'N/A' non-{expected_app} lanes: " + ", ".join(bad)
                        )
            if app_failures:
                failures.append(f"{port} application code: " + "; ".join(app_failures))

    # 6. Docker and process health check (per system_test_plan.md §6):
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
    min_uptime_sec = 180
    # Pre-existing/stale cores (seeded by the caller before the disruptive
    # action) are subtracted out so only cores created during the test fail it.
    core_baseline = shared_state.get("core_baseline", set())
    health_script = (
        "for c in pmon swss syncd; do "
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
