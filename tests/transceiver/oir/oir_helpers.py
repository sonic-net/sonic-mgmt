"""Physical OIR operations and verification primitives.

Backs the Physical OIR test cases in
``docs/testplan/transceiver/online_insertion_removal_testplan.md``.

Operations are operator driven (``oir_method`` ``manual``): each one prints a
prompt on the terminal, blocks until the operator confirms, then waits for the
DUT to observe the new presence state.  Verifiers return per-port failure
strings so the caller can aggregate them into a single ``pytest.fail``, matching
the pattern used across the transceiver suite.
"""
import logging
import select
import sys
import time
from collections import defaultdict

from natsort import natsorted

from tests.common.platform.interface_utils import (
    get_dut_interfaces_status,
    get_physical_to_logical_port_mapping,
    get_pport_presence_data,
)
from tests.common.utilities import wait_until
from tests.transceiver.common import cli_helpers, db_helpers, dmesg_helpers
from tests.transceiver.common.cli_parser_helper import parse_presence, RC_FAILURE
from tests.transceiver.common.scenario_ops import poll_ports_recovered
from tests.transceiver.common.verification import assert_no_flap_since, capture_flap_sentinels
from tests.transceiver.utils.cli_parser_helper import parse_eeprom

logger = logging.getLogger(__name__)

OIR_METHOD_MANUAL = "manual"

# dmesg is scanned only for transceiver/I2C-adjacent subsystems so an unrelated
# kernel warning inside the operation window doesn't fail an OIR test.
KERNEL_ERROR_PATTERN = r"i2c|sfp|xcvr|transceiver|eeprom|optoe"

# xcvrd's presence poll cycle plus CLI latency.
PRESENCE_SETTLE_SEC = 30
POLL_INTERVAL_SEC = 2

PRESENCE_PRESENT = "Present"
PRESENCE_ABSENT = "Not present"
# Case-sensitive and deliberately different per command family.
ABSENT_MSG_SFPUTIL = "SFP EEPROM not detected"
ABSENT_MSG_CLI_INFO = "SFP EEPROM Not detected"

TRANSCEIVER_STATUS_SW = "TRANSCEIVER_STATUS_SW"
# The only transceiver state table that survives a removal.
STATUS_SW_REMOVED = {"cmis_state": "REMOVED", "status": "0", "error": "N/A"}
STATUS_SW_READY = {"cmis_state": "READY", "status": "1", "error": "N/A"}
INSERTED_TABLES = ("TRANSCEIVER_INFO", "TRANSCEIVER_STATUS", "TRANSCEIVER_DOM_SENSOR")


def _reduce_eeprom(output_lines):
    """Reduce an ``... eeprom`` / ``... info`` / ``... dom`` dump to ``{port: status_line}``."""
    return {port: fields.get("status") for port, fields in parse_eeprom(output_lines).items()}


# (label, command builder, lines->{port: status} reducer, empty-cage status,
#  seated status or ``None`` for "anything but the empty-cage status",
#  asic_scoped).  Only the DB-backed ``show`` family takes ``-n <ns>``; sfputil
#  resolves the ASIC from the port name (see cli_helpers' namespace note).
_STATUS_CLIS = (
    ("sfputil show presence", cli_helpers.sfputil_show_presence_cmd,
     parse_presence, PRESENCE_ABSENT, PRESENCE_PRESENT, False),
    ("show interfaces transceiver presence", cli_helpers.show_interfaces_transceiver_presence_cmd,
     parse_presence, PRESENCE_ABSENT, PRESENCE_PRESENT, True),
    ("sfputil show eeprom", cli_helpers.sfputil_show_eeprom_cmd,
     _reduce_eeprom, ABSENT_MSG_SFPUTIL, None, False),
    ("show interfaces transceiver info", cli_helpers.show_interfaces_transceiver_info_cmd,
     _reduce_eeprom, ABSENT_MSG_CLI_INFO, None, True),
    # TC1 step 3: DOM values must read back empty once the cage is empty.
    ("show interfaces transceiver dom", cli_helpers.show_interfaces_transceiver_dom_cmd,
     _reduce_eeprom, ABSENT_MSG_CLI_INFO, None, True),
)


def resolve_pport_to_lports(lport_to_pport, pports):
    """Return ``{physical index: [logical ports]}`` for ``pports``."""
    pport_to_lport = get_physical_to_logical_port_mapping(lport_to_pport)
    return {pport: natsorted(pport_to_lport.get(pport, [])) for pport in pports}


# ──────────────────────────────────────────────────────────────────────
# Operator-driven OIR operations
# ──────────────────────────────────────────────────────────────────────


def prompt_operator(request, action, pports, timeout_min):
    """Print ``action`` on the terminal and block until the operator hits Enter.

    Returns ``None`` once acknowledged, or a failure string if nobody answered
    within ``timeout_min`` minutes.
    """
    port_list = ", ".join(str(pport) for pport in pports)
    logger.info("Waiting for operator: %s on physical port(s) %s", action, port_list)
    banner = (
        "\n" + "=" * 78 + "\n"
        f"  MANUAL OIR ACTION REQUIRED: {action}\n"
        f"  Physical port(s): {port_list}\n"
        f"  Press <Enter> when done (timeout {timeout_min} minute(s))\n"
        + "=" * 78 + "\n"
    )
    capman = request.config.pluginmanager.getplugin("capturemanager")
    # in_=True also restores the real stdin, which the default
    # suspend_global_capture()/global_and_fixture_disabled() leaves captured.
    capman.suspend_global_capture(in_=True)
    try:
        sys.stdout.write(banner)
        sys.stdout.flush()
        # select() rather than a bare input() so an unattended run times out
        # instead of hanging the session forever.
        if not select.select([sys.stdin], [], [], timeout_min * 60)[0]:
            return (f"operator did not confirm '{action}' on physical port(s) {port_list} "
                    f"within {timeout_min} minute(s)")
        # A closed/redirected stdin (e.g. /dev/null) selects readable immediately
        # and returns EOF, which is nobody confirming anything.
        if not sys.stdin.readline():
            return (f"cannot prompt the operator for '{action}' on physical port(s) {port_list} "
                    "- stdin reached EOF (non-interactive session)")
    except (OSError, ValueError) as exc:
        return f"cannot prompt the operator for '{action}' - stdin is not interactive ({exc})"
    finally:
        capman.resume_global_capture()
    return None


def get_pport_presence_all_asics(duthost):
    """Return ``{physical index: present}`` merged across every frontend ASIC.

    ``get_pport_presence_data`` reads a single namespace, so a multi-ASIC DUT's
    non-default-ASIC ports are absent from a bare call.
    """
    presence = {}
    for asic_index in duthost.get_frontend_asic_ids():
        presence.update(get_pport_presence_data(duthost, asic_index))
    return presence


def wait_pport_presence(duthost, pports, present):
    """Poll until every physical port in ``pports`` reports ``present``."""
    latest = {}

    def _settled():
        latest.update(get_pport_presence_all_asics(duthost))
        return all(pport in latest and latest[pport] == present for pport in pports)

    if wait_until(PRESENCE_SETTLE_SEC, POLL_INTERVAL_SEC, 0, _settled):
        return []
    return [
        f"physical port {pport}: presence {latest.get(pport)}, expected {present} "
        f"{PRESENCE_SETTLE_SEC}s after the OIR action"
        for pport in pports if latest.get(pport) != present
    ]


def perform_oir(request, duthost, oir_attrs, pports, present, action=None):
    """Ask the operator to insert/remove ``pports``, then confirm the DUT saw it."""
    action = action or ("INSERT the transceiver(s)" if present else "REMOVE the transceiver(s)")
    err = prompt_operator(request, action, pports, oir_attrs["physical_oir_timeout_min"])
    if err:
        return [err]
    return wait_pport_presence(duthost, pports, present)


# ──────────────────────────────────────────────────────────────────────
# Verification primitives
# ──────────────────────────────────────────────────────────────────────


def verify_presence_clis(duthost, lports, present):
    """Verify the presence / EEPROM / DOM CLIs all agree with the expected seated state.

    Each CLI is run without a port argument (whole-switch dump) and must exit 0;
    the ASIC-scoped ``show`` family is run once per namespace and merged so
    non-default-ASIC ports are covered on a multi-ASIC DUT.  The per-port status
    line is then matched against the expected token.
    """
    failures = []
    namespaces = duthost.get_asic_namespace_list()
    for label, build_cmd, reduce_output, absent_status, present_status, asic_scoped in _STATUS_CLIS:
        status_by_port = {}
        cli_failed = False
        for namespace in (namespaces if asic_scoped else [None]):
            cmd = build_cmd(namespace=namespace) if asic_scoped else build_cmd()
            result = duthost.command(cmd, module_ignore_errors=True)
            if result.get("rc", RC_FAILURE) != 0:
                failures.append(
                    f"[{label}] (namespace {namespace or 'default'}) "
                    f"exited rc={result.get('rc')}, expected 0")
                cli_failed = True
                continue
            status_by_port.update(reduce_output(result.get("stdout_lines", [])))
        if cli_failed:
            continue
        for port in lports:
            actual = status_by_port.get(port)
            if not present:
                if actual != absent_status:
                    failures.append(f"{port} [{label}]: expected '{absent_status}', got {actual!r}")
            elif present_status is not None:
                if actual != present_status:
                    failures.append(f"{port} [{label}]: expected '{present_status}', got {actual!r}")
            elif not actual or actual == absent_status:
                failures.append(f"{port} [{label}]: EEPROM not readable, got {actual!r}")
    return failures


def _transceiver_state_tables(duthost, lports):
    """Return ``({port: {table name}}, errors)`` for the ``TRANSCEIVER_*`` STATE_DB keys.

    Scans each ASIC's STATE_DB that owns a port under test.  A failed scan is
    returned as an error rather than an empty map, so a negative assertion
    ("the tables are gone") cannot pass on a database that was never read.
    """
    namespaces = sorted(
        {db_helpers.resolve_port_namespace(duthost, port) or "" for port in lports})
    tables_by_port = defaultdict(set)
    errors = []
    for namespace in namespaces:
        ns_flag = f" -n {namespace}" if namespace else ""
        out = duthost.shell(
            f"sonic-db-cli{ns_flag} STATE_DB KEYS 'TRANSCEIVER_*'", module_ignore_errors=True)
        if out.get("rc", RC_FAILURE) != 0:
            errors.append(
                f"STATE_DB TRANSCEIVER_* key scan failed in namespace "
                f"{namespace or 'default'} (rc={out.get('rc')}) - table state not verified")
            continue
        for key in out.get("stdout_lines", []):
            table, _, port = key.partition("|")
            if port:
                tables_by_port[port].add(table)
    return tables_by_port, errors


def _check_status_sw(duthost, port, expected):
    entry = db_helpers.hgetall_dict(
        duthost, "STATE_DB", f"{TRANSCEIVER_STATUS_SW}|{port}",
        namespace=db_helpers.resolve_port_namespace(duthost, port),
    )
    mismatches = [
        f"{field}={entry.get(field)!r} (expected {value!r})"
        for field, value in expected.items() if entry.get(field) != value
    ]
    return [f"{port}: {TRANSCEIVER_STATUS_SW} {', '.join(mismatches)}"] if mismatches else []


def capture_state_tables(duthost, lports):
    """Snapshot ``({port: {table}}, errors)`` while the modules are still seated.

    Used as the post-insertion baseline: which flag / VDM / PM tables a module
    publishes is module dependent ("if applicable" in the test plan), so the
    modules themselves define what must come back.
    """
    return _transceiver_state_tables(duthost, lports)


def verify_state_tables_removed(duthost, lports, wait_sec):
    """Every ``TRANSCEIVER_*`` table is deleted bar ``TRANSCEIVER_STATUS_SW``, which
    must report the REMOVED state."""
    def _check():
        tables_by_port, failures = _transceiver_state_tables(duthost, lports)
        for port in lports:
            stale = natsorted(tables_by_port.get(port, set()) - {TRANSCEIVER_STATUS_SW})
            if stale:
                failures.append(f"{port}: STATE_DB table(s) not deleted after removal: {', '.join(stale)}")
            failures += _check_status_sw(duthost, port, STATUS_SW_REMOVED)
        return failures

    return poll_ports_recovered(_check, wait_sec, POLL_INTERVAL_SEC, "STATE_DB removal")


def verify_state_tables_present(duthost, lports, parents, wait_sec, baseline_tables=None):
    """The per-module tables are republished and ``TRANSCEIVER_STATUS_SW`` is READY.

    ``parents`` are the first sub-ports of the modules under test — the keys the
    per-module tables are published under.  ``baseline_tables`` is the
    pre-removal snapshot from :func:`capture_state_tables`; every table a port
    published before the removal (flag, VDM and PM tables included) must return.
    """
    baseline_tables = baseline_tables or {}

    def _check():
        tables_by_port, failures = _transceiver_state_tables(duthost, lports)
        for port in lports:
            expected = set(baseline_tables.get(port, set()))
            if port in parents:
                expected |= set(INSERTED_TABLES)
            missing = natsorted(expected - tables_by_port.get(port, set()))
            if missing:
                failures.append(
                    f"{port}: STATE_DB table(s) not republished after insertion: {', '.join(missing)}"
                )
            failures += _check_status_sw(duthost, port, STATUS_SW_READY)
        return failures

    return poll_ports_recovered(_check, wait_sec, POLL_INTERVAL_SEC, "STATE_DB insertion")


def get_flap_counts(duthost, lports):
    """Return ``{port: flap_count}`` (raw APPL_DB strings) for ``lports``."""
    return {port: sentinel[0] for port, sentinel in capture_flap_sentinels(duthost, lports).items()}


def verify_flap_count_increment(duthost, lports, baseline, expected_increment=1):
    """Verify each port's APPL_DB ``flap_count`` moved by ``expected_increment``."""
    failures = []
    current = get_flap_counts(duthost, lports)
    for port in lports:
        before, after = baseline.get(port), current.get(port)
        if before is None or after is None:
            failures.append(f"{port}: flap_count not published (before={before!r}, after={after!r})")
        elif int(after) - int(before) != expected_increment:
            failures.append(f"{port}: flap_count {before}->{after}, expected +{expected_increment}")
    return failures


def verify_no_link_flap(duthost, oir_attrs_by_port):
    """Verify each port stays stable for its configured observation window."""
    lports_by_timeout = defaultdict(list)
    for port, attrs in oir_attrs_by_port.items():
        lports_by_timeout[attrs["link_flap_monitor_timeout_sec"]].append(port)

    lports = list(oir_attrs_by_port)
    sentinels = capture_flap_sentinels(duthost, lports)
    failures = []
    elapsed_sec = 0
    for monitor_sec in sorted(lports_by_timeout):
        time.sleep(monitor_sec - elapsed_sec)
        monitored_lports = lports_by_timeout[monitor_sec]
        results = assert_no_flap_since(
            duthost, monitored_lports, sentinels, elapsed_sec=monitor_sec)
        failures += [result["details"] for result in results.values() if not result["passed"]]
        elapsed_sec = monitor_sec
    return failures


def verify_other_ports_up(duthost, port_attributes_dict, affected_lports):
    """Verify every inventory port not under OIR stayed oper up."""
    intf_status = get_dut_interfaces_status(duthost)
    return [
        f"{port}: oper {(intf_status.get(port) or {}).get('oper', 'missing')}, expected up "
        "while another port's transceiver was out of its cage"
        for port in natsorted(set(port_attributes_dict) - set(affected_lports))
        if (intf_status.get(port) or {}).get("oper") != "up"
    ]


def capture_kernel_error_watermark(duthost, oir_attrs_by_port):
    """Return ``(watermark, err)`` when any affected port enables monitoring, else ``None``.

    The capture error is preserved rather than collapsed into ``None`` so a
    requested kernel check cannot silently pass without ever running.
    """
    if not any(attrs["monitor_kernel_errors"] for attrs in oir_attrs_by_port.values()):
        return None
    watermark, err = dmesg_helpers.capture_dmesg_uptime_watermark(duthost)
    if err:
        logger.warning("%s", err)
    return watermark, err


def verify_no_kernel_errors(duthost, capture):
    """Verify no transceiver/I2C kernel error was logged since the watermark."""
    if capture is None:
        return []
    watermark, capture_err = capture
    if watermark is None:
        return [("kernel error monitoring is enabled but the dmesg watermark could not be "
                 f"captured, so the OIR window was never scanned: {capture_err or 'unknown error'}")]
    errors, err = dmesg_helpers.scan_new_dmesg_errors(duthost, watermark, set(), KERNEL_ERROR_PATTERN)
    if err:
        return [err]
    return [f"kernel error(s) in dmesg during the OIR: {'; '.join(errors[:3])}"] if errors else []
