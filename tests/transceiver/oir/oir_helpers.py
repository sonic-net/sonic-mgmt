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

from tests.common.helpers.sonic_db import SonicDbCli
from tests.common.platform.interface_utils import (
    get_dut_interfaces_status,
    get_physical_to_logical_port_mapping,
    get_pport_presence_data,
)
from tests.transceiver.attribute_parser.attribute_keys import (
    DOM_ATTRIBUTES_KEY,
    PHYSICAL_OIR_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers, db_helpers, dmesg_helpers
from tests.transceiver.common.cli_parser_helper import (
    ABSENT_MSG_CLI_INFO,
    ABSENT_MSG_SFPUTIL,
    parse_presence,
    PRESENCE_ABSENT,
    PRESENCE_PRESENT,
    RC_FAILURE,
    reduce_eeprom_status,
)
from tests.transceiver.common.port_selectors import select_attribute_ports
from tests.transceiver.common.scenario_ops import poll_ports_recovered
from tests.transceiver.common.verification import assert_no_flap_since, capture_flap_sentinels
from tests.transceiver.dom.dom_helpers import (
    build_dom_sensor_plan,
    dom_field_available,
    read_dom_sensor_data,
    validate_dom_plan_fields,
)

logger = logging.getLogger(__name__)

OIR_METHOD_MANUAL = "manual"

# dmesg is scanned only for transceiver/I2C-adjacent subsystems so an unrelated
# kernel warning inside the operation window doesn't fail an OIR test.
KERNEL_ERROR_PATTERN = r"i2c|sfp|xcvr|transceiver|eeprom|optoe"

# xcvrd's presence poll cycle plus CLI latency.
PRESENCE_SETTLE_SEC = 30
POLL_INTERVAL_SEC = 2

TRANSCEIVER_STATUS_SW = "TRANSCEIVER_STATUS_SW"
# The only transceiver state table that survives a removal.
STATUS_SW_REMOVED = {"cmis_state": "REMOVED", "status": "0", "error": "N/A"}
STATUS_SW_READY = {"cmis_state": "READY", "status": "1", "error": "N/A"}
# Published by every module.  DOM / PM / VDM and the flag tables are module
# dependent (a non-DOM DAC publishes none of them), so they are required only
# when the pre-removal baseline shows the module published them.
INSERTED_TABLES = ("TRANSCEIVER_INFO", "TRANSCEIVER_STATUS")


def _sfputil_show_eeprom_dom_cmd(port=None):
    """Return the sfputil EEPROM dump with DOM values appended."""
    return cli_helpers.sfputil_show_eeprom_cmd(port=port, dom=True)


# (label, command builder, lines->{port: status} reducer, empty-cage status,
#  seated status or ``None`` for "anything but the empty-cage status").
# These whole-switch commands return all frontend ASICs when unqualified.
# ``sfputil show eeprom -d`` covers both the EEPROM dump and TC1 step 3's "DOM
# values read back empty", so the empty cage is proven without a second dump.
_STATUS_CLIS = (
    ("sfputil show presence", cli_helpers.sfputil_show_presence_cmd,
     parse_presence, PRESENCE_ABSENT, PRESENCE_PRESENT),
    ("show interfaces transceiver presence", cli_helpers.show_interfaces_transceiver_presence_cmd,
     parse_presence, PRESENCE_ABSENT, PRESENCE_PRESENT),
    ("sfputil show eeprom -d", _sfputil_show_eeprom_dom_cmd,
     reduce_eeprom_status, ABSENT_MSG_SFPUTIL, None),
    ("show interfaces transceiver info", cli_helpers.show_interfaces_transceiver_info_cmd,
     reduce_eeprom_status, ABSENT_MSG_CLI_INFO, None),
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


def wait_pport_presence(duthost, pports, present):
    """Poll until every physical port in ``pports`` reports ``present``."""
    def _check():
        presence = get_pport_presence_data(duthost)
        failures = []
        for pport in pports:
            if pport not in presence:
                failures.append(
                    f"physical port {pport}: missing from presence output, expected {present}"
                )
            elif presence[pport] != present:
                failures.append(
                    f"physical port {pport}: presence {presence[pport]}, expected {present}"
                )
        return failures

    return poll_ports_recovered(
        _check,
        PRESENCE_SETTLE_SEC,
        POLL_INTERVAL_SEC,
        "physical port presence",
    )


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
    the unqualified commands return all frontend ASICs. The per-port status line
    is then matched against the expected token.
    """
    failures = []
    for label, build_cmd, reduce_output, absent_status, present_status in _STATUS_CLIS:
        result = duthost.command(build_cmd(), module_ignore_errors=True)
        if result.get("rc", RC_FAILURE) != 0:
            failures.append(
                f"[{label}] exited rc={result.get('rc')}, expected 0")
            continue
        status_by_port = reduce_output(result.get("stdout_lines", []))
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
    """Return ``({port: {table name}}, errors)`` for the ``TRANSCEIVER_*`` STATE_DB keys."""
    asics_by_index = {}
    for port in lports:
        asic = duthost.get_port_asic_instance(port)
        asics_by_index[asic.asic_index] = asic

    tables_by_port = defaultdict(set)
    errors = []
    for asic in asics_by_index.values():
        try:
            state_db_cli = SonicDbCli(asic, "STATE_DB")
            keys = state_db_cli.get_keys("TRANSCEIVER_*")
            for key in keys:
                table, _, port = key.partition("|")
                if port:
                    tables_by_port[port].add(table)
        except Exception as exc:
            errors.append(f"Failed to scan STATE_DB for ASIC {asic}: {exc}")

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


def verify_dom_data_recovered(duthost, port_attributes_dict, lport_to_first_subport_mapping,
                              lports, wait_sec):
    """Verify DOM sensor data is republished with fresh, valid values after insertion.

    Only ports whose inventory declares ``DOM_ATTRIBUTES`` are checked (the test
    plan's "if applicable"): a DAC publishes no DOM data at all.  The expected
    field set, the active media lanes and the freshness budget all come from the
    same plan the DOM availability test uses, so both categories agree on what a
    healthy module must publish.
    """
    dom_ports = select_attribute_ports(
        port_attributes_dict,
        DOM_ATTRIBUTES_KEY,
        lport_to_first_subport_mapping,
        explicit_ports=lports,
    ).primary_ports
    if not dom_ports:
        logger.info("No DOM-capable port under test; skipping DOM data verification")
        return []

    plan_by_port = build_dom_sensor_plan(
        port_attributes_dict, dom_ports, lport_to_first_subport_mapping)

    def _check():
        sensor_by_port, read_errors = read_dom_sensor_data(duthost, dom_ports)
        failures = [f"TRANSCEIVER_DOM_SENSOR read: {error}" for error in read_errors]
        port_failures, _, _ = validate_dom_plan_fields(
            duthost,
            dom_ports,
            sensor_by_port,
            plan_by_port,
            dom_field_available,
            include_freshness_only=True,
        )
        return failures + port_failures

    return poll_ports_recovered(_check, wait_sec, POLL_INTERVAL_SEC, "DOM sensor data")


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


def verify_no_link_flap(duthost, port_attributes_dict, lports):
    """Verify each port stays stable for its configured observation window."""
    lports_by_timeout = defaultdict(list)
    for port in lports:
        attrs = port_attributes_dict[port][PHYSICAL_OIR_ATTRIBUTES_KEY]
        lports_by_timeout[attrs["link_flap_monitor_timeout_sec"]].append(port)

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


def capture_kernel_error_watermark(duthost, port_attributes_dict, lports):
    """Return ``(watermark, err)`` when any affected port enables monitoring, else ``None``.

    The capture error is preserved rather than collapsed into ``None`` so a
    requested kernel check cannot silently pass without ever running.
    """
    if not any(
        port_attributes_dict[port][PHYSICAL_OIR_ATTRIBUTES_KEY]["monitor_kernel_errors"]
        for port in lports
    ):
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
