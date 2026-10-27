"""OIR operations and verification primitives.

Backs the Physical OIR and Remote reseat test cases in
``docs/testplan/transceiver/online_insertion_removal_testplan.md``.

Physical OIR operations are operator driven (``oir_method`` ``manual``): each
one prints a prompt on the terminal, blocks until the operator confirms, then
waits for the DUT to observe the new presence state.  A remote reseat simulates
an OIR on the DUT itself with the plan's seven-step procedure, composed from
the shared :mod:`tests.transceiver.common.scenario_ops` operations.  Verifiers
return per-port failure strings so the caller can aggregate them into a single
``pytest.fail``, matching the pattern used across the transceiver suite.
"""
import http.client
import json
import logging
import select
import sys
import time
from collections import defaultdict

from natsort import natsorted

from tests.common.helpers.platform_api import sfp
from tests.common.helpers.sonic_db import SonicDbCli
from tests.common.platform.interface_utils import (
    get_dut_interfaces_status,
    get_physical_to_logical_port_mapping,
    get_pport_presence_data,
    wait_ports_oper_status,
)
from tests.common.utilities import wait_until
from tests.transceiver.attribute_parser.attribute_keys import (
    DOM_ATTRIBUTES_KEY,
    PHYSICAL_OIR_ATTRIBUTES_KEY,
    REMOTE_RESEAT_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
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
from tests.transceiver.common.prerequisites import DOM_POLLING_DISABLED_VALUE, build_dom_polling_failures
from tests.transceiver.common.scenario_ops import (
    perform_ports_shutdown,
    perform_ports_startup,
    perform_sfputil_reset,
    poll_ports_recovered,
    scale_bulk_wait,
    verify_lpmode,
)
from tests.transceiver.common.verification import (
    assert_no_flap_since,
    capture_flap_sentinels,
    check_lldp_neighbors_present,
    standard_port_recovery_and_verification,
)
from tests.transceiver.dom.dom_helpers import (
    read_dom_sensor_data,
    verify_dom_recovered,
    verify_dom_thresholds_after_operation,
)
from tests.transceiver.eeprom import recovery

logger = logging.getLogger(__name__)

OIR_METHOD_MANUAL = "manual"

# dmesg is scanned only for transceiver/I2C-adjacent subsystems so an unrelated
# kernel warning inside the operation window doesn't fail an OIR test.
KERNEL_ERROR_PATTERN = r"i2c|sfp|xcvr|transceiver|eeprom|optoe"

# xcvrd's presence poll cycle plus CLI latency.
PRESENCE_SETTLE_SEC = 30
POLL_INTERVAL_SEC = 2

# Bounds each platform API call.  The server is single threaded, so a call stuck
# in pmon (e.g. on a hung I2C bus) would otherwise block every later call too,
# the hot-swap restoration's included.
PLATFORM_API_TIMEOUT_SEC = 60

# Run with the DUT's python3 by probe_missing_xcvr_api(), as sfputil reads
# modules.  It cannot go through the platform API server, whose JSON encoder
# fails on the bytearray read_eeprom() returns.  The synthetic reader serves the
# module's identifier byte and zeros for every other read, so the platform's
# XcvrApi factory then decides on the identifier alone; it never writes the
# module.  The factory prints, and returns no XcvrApi, when building one
# raises, so its output is captured to tell that from an unsupported identifier.
_XCVR_API_PROBE_PREFIX = "OIR_XCVR_API_PROBE "
_XCVR_API_PROBE = r'''
import contextlib
import io
import json
import sys

result = {"identifier": None, "xcvr_api": None, "output": "",
          "factory_api": None, "factory_output": "", "error": None}
output = io.StringIO()
factory_output = io.StringIO()
try:
    with contextlib.redirect_stdout(output):
        import sonic_platform.platform
        sfp = sonic_platform.platform.Platform().get_chassis().get_sfp(int(sys.argv[1]))
        raw = sfp.read_eeprom(0, 1)
        if raw is None or len(raw) != 1:
            raise ValueError("identifier read returned {!r}".format(raw))
        identifier = raw[0]
        result["identifier"] = identifier
        api = sfp.get_xcvr_api()
        result["xcvr_api"] = type(api).__name__ if api is not None else None

    def read_synthetic(offset, num_bytes):
        data = bytearray(num_bytes)
        if offset == 0 and num_bytes:
            data[0] = identifier
        return data

    with contextlib.redirect_stdout(factory_output):
        factory = type(sfp._xcvr_api_factory)(read_synthetic, lambda offset, num_bytes, write_buffer: True)
        api = factory.create_xcvr_api(**({"bank": sfp.bank} if hasattr(sfp, "bank") else {}))
    result["factory_api"] = type(api).__name__ if api is not None else None
except Exception as exc:
    result["error"] = repr(exc)
result["output"] = output.getvalue()[-1000:]
result["factory_output"] = factory_output.getvalue()[-1000:]
print("OIR_XCVR_API_PROBE " + json.dumps(result))
'''

TRANSCEIVER_STATUS_SW = "TRANSCEIVER_STATUS_SW"
# The only transceiver state table that survives a removal.
STATUS_SW_REMOVED = {"cmis_state": "REMOVED", "status": "0", "error": "N/A"}
STATUS_SW_READY = {"cmis_state": "READY", "status": "1", "error": "N/A"}
# xcvrd's write on an insertion event, whatever the CMIS state machine then does.
# The table outlives a removal, so this, not its presence, shows a new module.
STATUS_SW_INSERTED = {"status": "1", "error": "N/A"}
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

# The _STATUS_CLIS entries plus whether each must report the module present, for
# a seated module the platform builds no XcvrApi for (TC6).  The sfputil CLIs
# read the module itself and see it; the show CLIs report xcvrd's
# TRANSCEIVER_INFO, which such a module never gets.  DOM needs an XcvrApi, so
# the EEPROM dump is taken without it: ``-d`` exits ERROR_NOT_IMPLEMENTED on
# platforms whose get_transceiver_info() needs no XcvrApi.
_UNSUPPORTED_MODULE_CLIS = (
    ("sfputil show presence", cli_helpers.sfputil_show_presence_cmd,
     parse_presence, PRESENCE_ABSENT, PRESENCE_PRESENT, True),
    ("show interfaces transceiver presence", cli_helpers.show_interfaces_transceiver_presence_cmd,
     parse_presence, PRESENCE_ABSENT, PRESENCE_PRESENT, False),
    ("sfputil show eeprom", cli_helpers.sfputil_show_eeprom_cmd,
     reduce_eeprom_status, ABSENT_MSG_SFPUTIL, None, True),
    ("show interfaces transceiver info", cli_helpers.show_interfaces_transceiver_info_cmd,
     reduce_eeprom_status, ABSENT_MSG_CLI_INFO, None, False),
)


def resolve_pport_to_lports(lport_to_pport, pports):
    """Return ``{physical index: [logical ports]}`` for ``pports``."""
    pport_to_lport = get_physical_to_logical_port_mapping(lport_to_pport)
    return {pport: natsorted(pport_to_lport.get(pport, [])) for pport in pports}


def all_ports(pport_to_lports):
    """Return the configured physical ports and all of their logical subports."""
    pports = list(pport_to_lports)
    lports = [port for ports in pport_to_lports.values() for port in ports]
    return pports, lports


def parents_of(lports, lport_to_first_subport_mapping):
    """Return the first sub-ports of the modules ``lports`` belong to."""
    return sorted({lport_to_first_subport_mapping.get(port, port) for port in lports})


# ──────────────────────────────────────────────────────────────────────
# Settle budgets
# ──────────────────────────────────────────────────────────────────────


def bulk_waits(port_attributes_dict, lports):
    """Return the (shutdown, startup) settle budgets scaled to an all-at-once operation.

    The slowest port under test sets the budget: a bulk OIR is only settled once
    every module has settled.
    """
    system_attrs = [port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}) for port in lports]
    return (
        scale_bulk_wait(max(attrs["port_shutdown_wait_sec"] for attrs in system_attrs), len(lports)),
        scale_bulk_wait(max(attrs["port_startup_wait_sec"] for attrs in system_attrs), len(lports)),
    )


def dom_recover_wait(port_attributes_dict, lports, wait_sec):
    """Return ``wait_sec`` plus the slowest port's DOM republish budget.

    ``TRANSCEIVER_DOM_SENSOR`` / ``TRANSCEIVER_FIRMWARE_INFO`` are republished on
    xcvrd's delayed DOM cycle, so both need the settle budget plus that cycle.
    """
    return recovery.dom_republish_wait(port_attributes_dict, wait_sec, lports)


def remaining_wait(deadline):
    """Return the non-negative time remaining before ``deadline``."""
    return max(0, deadline - time.monotonic())


def flap_monitor_sec(port_attributes_dict, lports, attribute_key=PHYSICAL_OIR_ATTRIBUTES_KEY):
    """Return the longest ``link_flap_monitor_timeout_sec`` of ``lports`` in their
    ``attribute_key`` category: a bulk operation is watched until the slowest
    port's window has passed."""
    return max(port_attributes_dict[port][attribute_key]["link_flap_monitor_timeout_sec"] for port in lports)


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
# Remote reseat operation
# ──────────────────────────────────────────────────────────────────────

# The procedure's sleep after the reset; a longer transceiver_reset_i2c_recover_sec wins.
RESEAT_RESET_SLEEP_SEC = 5

_RESEAT_STEPS = {
    1: "disable DOM monitoring",
    2: "port shutdown",
    3: "transceiver reset",
    4: "low power mode",
    5: "high power mode",
    6: "port startup",
    7: "enable DOM monitoring",
}


def _reseat_step_failures(step, failures):
    return [f"step {step} ({_RESEAT_STEPS[step]}): {failure}" for failure in failures]


def set_dom_monitoring(duthost, modules, enable):
    """Enable or disable DOM monitoring on ``modules`` (first subports) and verify
    that CONFIG_DB ``dom_polling`` reflects it."""
    failures = []
    for module in modules:
        err = cli_helpers.set_dom_polling(
            duthost, module, enable, namespace=db_helpers.resolve_port_namespace(duthost, module))
        if err:
            failures.append(err)
    if enable:
        return failures + build_dom_polling_failures(duthost, modules)

    port_table = db_helpers.get_config_db_port_table(duthost)
    for module in modules:
        value = (port_table.get(module) or {}).get("dom_polling")
        if str(value).strip().lower() != DOM_POLLING_DISABLED_VALUE:
            failures.append(f"{module} dom_polling is {value!r}, expected {DOM_POLLING_DISABLED_VALUE!r}")
    return failures


def _set_lpmode(duthost, modules, low_power, settle_sec):
    """Request low (or high) power mode on ``modules``, then poll for up to
    ``settle_sec`` until each module reports it."""
    failures, requested = [], []
    for module in modules:
        elapsed, err = cli_helpers.sfputil_set_lpmode(duthost, module, low_power)
        logger.info("Port %s: lpmode %s took %ss", module, "on" if low_power else "off", elapsed)
        if err:
            failures.append(err)
        else:
            requested.append(module)
    return failures + poll_ports_recovered(
        lambda: [failure for module in requested for failure in verify_lpmode(duthost, module, low_power)],
        settle_sec, POLL_INTERVAL_SEC, "power mode")


def _verify_lldp_present(duthost, lldp_timeouts):
    """Return a failure for each linked-up port in ``lldp_timeouts`` (``{port:
    lldp_neighbor_wait_sec}``) without an LLDP neighbor within its timeout."""
    if not lldp_timeouts:
        return []
    up_ports = set(get_oper_up_ports(duthost, list(lldp_timeouts)))
    results = check_lldp_neighbors_present(
        duthost, {port: timeout for port, timeout in lldp_timeouts.items() if port in up_ports})
    return [result["details"] for result in results.values() if not result["passed"]]


def perform_remote_reseat(duthost, port_attributes_dict, lport_to_first_subport_mapping, lports,
                          shutdown_wait_sec, startup_wait_sec):
    """Remotely reseat the modules of ``lports``.

    Runs the seven steps of the remote reseat procedure, each across every
    module before the next, and checks each step's expected result:

      1. DOM monitoring is disabled.
      2. The ports are shut down and go oper down within ``shutdown_wait_sec``.
      3. The modules reset, followed by a sleep of ``RESEAT_RESET_SLEEP_SEC`` or
         the longer ``transceiver_reset_i2c_recover_sec``.
      4. The modules with ``low_power_mode_supported`` report low power mode,
      5. and then high power mode, within ``transceiver_reset_i2c_recover_sec``.
      6. The ports start up, go oper up within ``startup_wait_sec`` and, where
         ``verify_lldp_on_link_up`` is set, show an LLDP neighbor within
         ``lldp_neighbor_wait_sec``.
      7. DOM monitoring is enabled.

    Steps 6 and 7 run however the earlier steps end, so no port is left down
    or unmonitored.  The reseat must complete within the slowest port's
    ``remote_reseat_timeout_min``, scaled to the bulk operation.

    Returns:
        tuple: ``(failures, dom_baseline)``: the per-step failures, for the
        caller to aggregate, and the :func:`capture_dom_sensor_baseline` data
        read just before step 7.  DOM monitoring is still disabled then, so a
        later ``last_update_time`` can only come from the monitoring step 7
        re-enabled.
    """
    modules = parents_of(lports, lport_to_first_subport_mapping)
    system_attrs = {port: port_attributes_dict[port][SYSTEM_ATTRIBUTES_KEY] for port in lports}
    i2c_recover_sec = max(system_attrs[module]["transceiver_reset_i2c_recover_sec"] for module in modules)
    lpm_modules = [module for module in modules if system_attrs[module]["low_power_mode_supported"]]
    lldp_timeouts = {
        port: attrs["lldp_neighbor_wait_sec"]
        for port, attrs in system_attrs.items() if attrs.get("verify_lldp_on_link_up", True)
    }
    timeout_sec = scale_bulk_wait(
        60 * max(port_attributes_dict[port][REMOTE_RESEAT_ATTRIBUTES_KEY]["remote_reseat_timeout_min"]
                 for port in lports),
        len(lports))
    if len(lpm_modules) < len(modules):
        logger.info("Steps 4 and 5 skip the module(s) without low_power_mode_supported: %s",
                    sorted(set(modules) - set(lpm_modules)))

    logger.info("Remote reseat of %d module(s) across %d port(s)", len(modules), len(lports))
    started_at = time.monotonic()
    failures = []
    dom_baseline = {}
    try:
        failures += _reseat_step_failures(1, set_dom_monitoring(duthost, modules, enable=False))
        failures += _reseat_step_failures(2, perform_ports_shutdown(duthost, lports, shutdown_wait_sec))
        failures += _reseat_step_failures(3, perform_sfputil_reset(
            duthost, modules, [], 0, 0, recover_wait_sec=max(RESEAT_RESET_SLEEP_SEC, i2c_recover_sec)))
        failures += _reseat_step_failures(4, _set_lpmode(duthost, lpm_modules, True, i2c_recover_sec))
        failures += _reseat_step_failures(5, _set_lpmode(duthost, lpm_modules, False, i2c_recover_sec))
    finally:
        try:
            startup_failures = perform_ports_startup(duthost, lports, startup_wait_sec)
            failures += _reseat_step_failures(6, startup_failures + _verify_lldp_present(duthost, lldp_timeouts))
            dom_baseline, errors = capture_dom_sensor_baseline(
                duthost, port_attributes_dict, lport_to_first_subport_mapping, lports)
            failures += [f"DOM sensor baseline before step 7: {error}" for error in errors]
        finally:
            failures += _reseat_step_failures(7, set_dom_monitoring(duthost, modules, enable=True))

    elapsed = time.monotonic() - started_at
    logger.info("Remote reseat of %d module(s) took %.1fs", len(modules), elapsed)
    if elapsed > timeout_sec:
        failures.append(
            f"remote reseat took {elapsed:.0f}s, longer than its {timeout_sec}s timeout (remote_reseat_timeout_min)")
    return failures, dom_baseline


# ──────────────────────────────────────────────────────────────────────
# Verification primitives
# ──────────────────────────────────────────────────────────────────────


def _verify_cli_statuses(duthost, lports, clis):
    """Run each ``(label, command builder, reducer, empty-cage status, seated status,
    expect present)`` CLI without a port argument and match every port's status line.

    Each CLI must exit 0; the unqualified commands return all frontend ASICs.
    """
    failures = []
    for label, build_cmd, reduce_output, absent_status, present_status, expect_present in clis:
        result = duthost.command(build_cmd(), module_ignore_errors=True)
        if result.get("rc", RC_FAILURE) != 0:
            failures.append(
                f"[{label}] exited rc={result.get('rc')}, expected 0")
            continue
        status_by_port = reduce_output(result.get("stdout_lines", []))
        for port in lports:
            actual = status_by_port.get(port)
            if not expect_present:
                if actual != absent_status:
                    failures.append(f"{port} [{label}]: expected '{absent_status}', got {actual!r}")
            elif present_status is not None:
                if actual != present_status:
                    failures.append(f"{port} [{label}]: expected '{present_status}', got {actual!r}")
            elif not actual or actual == absent_status:
                failures.append(f"{port} [{label}]: EEPROM not readable, got {actual!r}")
    return failures


def verify_presence_clis(duthost, lports, present):
    """Verify the presence / EEPROM / DOM CLIs all agree with the expected seated state.

    Each CLI is run without a port argument (whole-switch dump) and must exit 0;
    the unqualified commands return all frontend ASICs. The per-port status line
    is then matched against the expected token.
    """
    return _verify_cli_statuses(duthost, lports, [cli + (present,) for cli in _STATUS_CLIS])


def verify_unsupported_module_clis(duthost, lports):
    """Verify the CLIs of a seated module the platform builds no XcvrApi for (TC6).

    The ``sfputil`` presence and EEPROM (without DOM) CLIs must report the
    module present, and the ``show`` CLIs must report the cage empty; see
    :data:`_UNSUPPORTED_MODULE_CLIS`.
    """
    return _verify_cli_statuses(duthost, lports, _UNSUPPORTED_MODULE_CLIS)


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


def _status_sw_entries(duthost, lports):
    """Return ``({port: TRANSCEIVER_STATUS_SW entry}, errors)``, one STATE_DB read per ASIC namespace."""
    entries, errors = {}, []
    for namespace, ports in db_helpers.group_ports_by_namespace(duthost, lports).items():
        table, err = db_helpers.get_state_db_table(duthost, TRANSCEIVER_STATUS_SW, namespace=namespace)
        if err:
            errors.append(f"{TRANSCEIVER_STATUS_SW} read failed: {err}")
            continue
        entries.update((port, table.get(port, {})) for port in ports)
    return entries, errors


def _check_status_sw(port, entry, expected):
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


def verify_state_tables_removed(duthost, lports, wait_sec, status_sw=STATUS_SW_REMOVED):
    """Every ``TRANSCEIVER_*`` table is deleted bar ``TRANSCEIVER_STATUS_SW``, which
    must match ``status_sw``: the REMOVED state, or xcvrd's insertion write for a
    seated module it cannot build an XcvrApi for."""
    def _check():
        tables_by_port, failures = _transceiver_state_tables(duthost, lports)
        status_sw_entries, status_sw_errors = _status_sw_entries(duthost, lports)
        failures += status_sw_errors
        for port in lports:
            stale = natsorted(tables_by_port.get(port, set()) - {TRANSCEIVER_STATUS_SW})
            if stale:
                failures.append(f"{port}: STATE_DB table(s) not deleted after removal: {', '.join(stale)}")
            if port in status_sw_entries:
                failures += _check_status_sw(port, status_sw_entries[port], status_sw)
        return failures

    return poll_ports_recovered(_check, wait_sec, POLL_INTERVAL_SEC, "STATE_DB removal")


def verify_state_tables_present(duthost, lports, parents, wait_sec, baseline_tables=None, ready=True):
    """The per-module tables are republished and ``TRANSCEIVER_STATUS_SW`` shows the
    module inserted and, if ``ready``, READY.

    ``parents`` are the first sub-ports of the modules under test — the keys the
    per-module tables are published under.  ``baseline_tables`` is the
    pre-removal snapshot from :func:`capture_state_tables`; every table a port
    published before the removal (flag, VDM and PM tables included) must return.
    """
    baseline_tables = baseline_tables or {}

    def _check():
        tables_by_port, failures = _transceiver_state_tables(duthost, lports)
        status_sw_entries, status_sw_errors = _status_sw_entries(duthost, lports)
        failures += status_sw_errors
        for port in lports:
            expected = set(baseline_tables.get(port, set()))
            if port in parents:
                expected |= set(INSERTED_TABLES)
            missing = natsorted(expected - tables_by_port.get(port, set()))
            if missing:
                failures.append(
                    f"{port}: STATE_DB table(s) not republished after insertion: {', '.join(missing)}"
                )
            if port in status_sw_entries:
                failures += _check_status_sw(
                    port, status_sw_entries[port], STATUS_SW_READY if ready else STATUS_SW_INSERTED)
        return failures

    return poll_ports_recovered(_check, wait_sec, POLL_INTERVAL_SEC, "STATE_DB insertion")


def _select_dom_ports(port_attributes_dict, lport_to_first_subport_mapping, lports):
    """Return DOM-capable primary ports from the OIR target set."""
    return select_attribute_ports(
        port_attributes_dict,
        DOM_ATTRIBUTES_KEY,
        lport_to_first_subport_mapping,
        explicit_ports=lports,
    ).primary_ports


def capture_dom_sensor_baseline(duthost, port_attributes_dict,
                                lport_to_first_subport_mapping, lports):
    """Capture pre-removal DOM sensor data for applicable OIR ports."""
    dom_ports = _select_dom_ports(
        port_attributes_dict, lport_to_first_subport_mapping, lports)
    if not dom_ports:
        return {}, []
    return read_dom_sensor_data(duthost, dom_ports)


def verify_dom_data_recovered(duthost, port_attributes_dict, lport_to_first_subport_mapping,
                              lports, baseline_sensor_data, wait_sec):
    """Verify applicable OIR DOM data using the shared recovery orchestration."""
    dom_ports = _select_dom_ports(
        port_attributes_dict, lport_to_first_subport_mapping, lports)
    if not dom_ports:
        logger.info("No DOM-capable port under test; skipping DOM data verification")
        return []

    return verify_dom_recovered(
        duthost,
        port_attributes_dict,
        dom_ports,
        lport_to_first_subport_mapping,
        baseline_sensor_data,
        wait_sec=wait_sec,
    )


def capture_recovery_baseline(duthost, port_attributes_dict, lport_to_first_subport_mapping, lports):
    """Snapshot seated-module STATE_DB tables and applicable DOM sensor data.

    Returns ``(baseline_tables, baseline_sensor_data, failures)``, the baselines
    :func:`verify_insertion` takes.
    """
    baseline_tables, errors = capture_state_tables(duthost, lports)
    baseline_sensor_data, dom_errors = capture_dom_sensor_baseline(
        duthost, port_attributes_dict, lport_to_first_subport_mapping, lports)
    failures = [f"STATE_DB baseline: {error}" for error in errors]
    failures += [f"DOM sensor baseline: {error}" for error in dom_errors]
    return baseline_tables, baseline_sensor_data, failures


def _sfp_api(conn, pport, name, args=None):
    """Call Sfp API ``name`` of ``pport`` through the platform API server.

    After a timeout or a refused connection, ``http.client`` rejects every later
    request on ``conn`` (``CannotSendRequest``) until it is closed, so a failed
    call resets it.  The server answers in HTTP/1.0, so every call opens a new
    TCP connection anyway.
    """
    try:
        return sfp.sfp_api(conn, pport, name, args)
    except (OSError, http.client.HTTPException):
        conn.close()
        raise


def read_xcvr_api(conn, pport, wait_sec=0):
    """Return ``(xcvr_api, serial)`` of the module in ``pport`` via the platform API server.

    ``xcvr_api`` is the server's ``{"__class__", "object_id", ...}`` view of the
    XcvrApi of its long-lived Sfp object, or ``None`` if the platform builds none
    within ``wait_sec``.  xcvrd drops its cached XcvrApi on every removal event;
    the server's Sfp objects never see those events, so the XcvrApi is rebuilt
    here for the module now in the cage.
    """
    _sfp_api(conn, pport, "refresh_xcvr_api")
    wait_until(wait_sec, POLL_INTERVAL_SEC, 0, lambda: _sfp_api(conn, pport, "get_xcvr_api") is not None)
    return _sfp_api(conn, pport, "get_xcvr_api"), _sfp_api(conn, pport, "get_serial")


def read_serial(conn, pport, wait_sec=0):
    """Return the serial number of the module in ``pport``, or ``None`` if it cannot be read.

    For cleanup paths: it never raises, and it reconnects first in case an
    exception left ``conn`` in the middle of a request.
    """
    conn.close()
    try:
        return read_xcvr_api(conn, pport, wait_sec)[1]
    except Exception as exc:
        logger.warning("Physical port %s: cannot read the serial number: %r", pport, exc)
        return None


def wait_module_presence(conn, pport, present=True):
    """Poll the platform's presence signal until it reports ``present`` for ``pport``.

    The ``show`` presence CLI reflects xcvrd's ``TRANSCEIVER_INFO``, which a
    module without an XcvrApi never gets; this signal needs no XcvrApi.  The
    platform API server returns ``None`` when the call raised.
    """
    def _check():
        presence = _sfp_api(conn, pport, "get_presence")
        if presence is None:
            return [f"physical port {pport}: platform presence unreadable (platform API returned None)"]
        if bool(presence) is not present:
            return [f"physical port {pport}: platform presence {presence}, expected {present}"]
        return []

    return poll_ports_recovered(_check, PRESENCE_SETTLE_SEC, POLL_INTERVAL_SEC, "platform presence")


def probe_missing_xcvr_api(duthost, pport):
    """Return the evidence for why the platform builds no XcvrApi for the module in ``pport``.

    Runs :data:`_XCVR_API_PROBE` with the DUT's ``python3``, as ``sfputil``
    reads modules: it reads the identifier byte, retries the XcvrApi in a fresh
    process, and asks the platform's XcvrApi factory whether it builds one for
    that identifier when every other EEPROM read succeeds.  Returns the probe's
    ``{"identifier", "xcvr_api", "output", "factory_api", "factory_output",
    "error"}`` result.
    """
    result = duthost.command(argv=["python3", "-c", _XCVR_API_PROBE, str(pport)], module_ignore_errors=True)
    for line in reversed(result.get("stdout_lines", [])):
        if line.startswith(_XCVR_API_PROBE_PREFIX):
            return json.loads(line[len(_XCVR_API_PROBE_PREFIX):])
    return {"error": f"XcvrApi probe exited rc={result.get('rc')} without a result: "
                     f"{(result.get('stderr') or '')[-500:]}"}


def missing_xcvr_api_failure(probe):
    """Return why ``probe`` is no evidence that the module is unsupported, or ``None`` if it is.

    Only an identifier the platform's factory builds no XcvrApi for, without
    error, even with every other EEPROM read succeeding, shows that the module
    is unsupported.  The factory also returns no XcvrApi when building one
    raises, e.g. on a failed EEPROM read: an error, not an unsupported module.
    """
    if probe.get("error"):
        return f"cannot tell why the swapped-in module has no XcvrApi: {probe['error']}"
    identifier = f"0x{probe['identifier']:02x}"
    if probe.get("xcvr_api"):
        return (f"no XcvrApi for the swapped-in module (identifier {identifier}), "
                f"yet a retry built {probe['xcvr_api']}")
    if probe.get("factory_api"):
        output = (probe.get("output") or "").strip()
        return (f"no XcvrApi for the swapped-in module although the platform builds {probe['factory_api']} "
                f"for its identifier {identifier}: a read or construction error, not an unsupported module"
                + (f" ({output})" if output else ""))
    factory_output = (probe.get("factory_output") or "").strip()
    if factory_output:
        return (f"no XcvrApi for the swapped-in module (identifier {identifier}), and building one from "
                f"identifier {identifier} alone reported: {factory_output}; cannot tell an unsupported "
                "module from a construction error")
    return None


def get_flap_counts(duthost, lports):
    """Return ``{port: flap_count}`` (raw APPL_DB strings) for ``lports``."""
    return {port: sentinel[0] for port, sentinel in capture_flap_sentinels(duthost, lports).items()}


def get_link_peers(duthost, lports, port_peers):
    """Return ``{port: link peer}`` for the ``lports`` cabled to another port of this DUT.

    Such a peer loses and regains its link along with the port.  ``port_peers``
    (the fixture of the same name) holds the peers of LLDP-verified ports only,
    so the peer of any other port goes unnoticed.  A peer in ``lports`` is left
    out, being under OIR itself.
    """
    link_peers = {}
    for port in lports:
        peer, _ = port_peers.get(port, (None, None))
        if peer is not None and peer.device == duthost.hostname and peer.port not in lports:
            link_peers[port] = peer.port
    return link_peers


def with_link_peers(duthost, lports, port_peers):
    """Return ``lports`` followed by their :func:`get_link_peers` link peers."""
    return lports + list(get_link_peers(duthost, lports, port_peers).values())


def _other_ports(duthost, port_attributes_dict, affected_lports, port_peers):
    """Return the inventory ports neither under OIR nor the link peer of a port that is.

    A peer :func:`get_link_peers` misses stays among these ports, where it can
    only cause a reported failure, never hide one.
    """
    return natsorted(set(port_attributes_dict) - set(with_link_peers(duthost, affected_lports, port_peers)))


def get_other_ports_flap_sentinels(duthost, port_attributes_dict, affected_lports, port_peers):
    """Return :func:`capture_flap_sentinels` for every inventory port unrelated to the OIR."""
    return capture_flap_sentinels(duthost, _other_ports(duthost, port_attributes_dict, affected_lports, port_peers))


def verify_flap_count_increment(duthost, lports, baseline, expected_increment=1):
    """Verify each port's APPL_DB ``flap_count`` moved by ``expected_increment``,
    one increment for every port or a ``{port: increment}`` mapping."""
    failures = []
    current = get_flap_counts(duthost, lports)
    for port in lports:
        expected = expected_increment[port] if isinstance(expected_increment, dict) else expected_increment
        before, after = baseline.get(port), current.get(port)
        if before is None or after is None:
            failures.append(f"{port}: flap_count not published (before={before!r}, after={after!r})")
        elif int(after) - int(before) != expected:
            failures.append(f"{port}: flap_count {before}->{after}, expected +{expected}")
    return failures


def verify_link_peers(duthost, peers, status, wait_sec, flap_baseline, expected_increment):
    """The peer-port results for the link ``peers`` on this DUT of the ports under OIR:
    each one reaches oper ``status`` and, given a ``flap_baseline``, its flap count
    moves by ``expected_increment`` (see :func:`verify_flap_count_increment`)."""
    if not peers:
        return []
    failures = wait_ports_oper_status(duthost, peers, status, wait_sec)
    if flap_baseline is not None:
        failures += verify_flap_count_increment(duthost, peers, flap_baseline, expected_increment)
    return [f"link peer {failure}" for failure in failures]


def get_oper_up_ports(duthost, lports):
    """Return the ``lports`` that are oper up."""
    intf_status = get_dut_interfaces_status(duthost)
    return [port for port in lports if (intf_status.get(port) or {}).get("oper") == "up"]


def verify_other_ports_up(duthost, port_attributes_dict, affected_lports, port_peers):
    """Verify every inventory port unrelated to the OIR stayed oper up."""
    intf_status = get_dut_interfaces_status(duthost)
    return [
        f"{port}: oper {(intf_status.get(port) or {}).get('oper', 'missing')}, expected up "
        "while another port's transceiver was out of its cage"
        for port in _other_ports(duthost, port_attributes_dict, affected_lports, port_peers)
        if (intf_status.get(port) or {}).get("oper") != "up"
    ]


def verify_other_ports_no_flap(duthost, baseline):
    """Verify no port in ``baseline`` flapped since it was captured.

    ``baseline`` is :func:`get_other_ports_flap_sentinels`.  Those ports keep
    their module seated and their link peer untouched throughout, so any change
    of their ``flap_count``, ``last_up_time`` or ``last_down_time`` means
    another port's OIR disturbed their link.
    """
    return [
        f"{result['details']} while another port's transceiver was inserted/removed"
        for result in assert_no_flap_since(duthost, list(baseline), baseline).values()
        if not result["passed"]
    ]


def capture_kernel_error_watermark(duthost, port_attributes_dict, lports, attribute_key=PHYSICAL_OIR_ATTRIBUTES_KEY):
    """Return ``(watermark, err)`` when any affected port enables monitoring, else ``None``.

    ``monitor_kernel_errors`` is read from each port's ``attribute_key`` category.
    The capture error is preserved rather than collapsed into ``None`` so a
    requested kernel check cannot silently pass without ever running.
    """
    if not any(
        port_attributes_dict[port][attribute_key]["monitor_kernel_errors"]
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


# ──────────────────────────────────────────────────────────────────────
# Composite verification
# ──────────────────────────────────────────────────────────────────────


def verify_insertion(duthost, port_attributes_dict, lport_to_first_subport_mapping,
                     lports, health_baseline, watermark, wait_sec,
                     *, port_peers, baseline_tables=None, baseline_sensor_data=None,
                     insert_flap_baseline=None, expected_flap_increment=1,
                     attribute_key=PHYSICAL_OIR_ATTRIBUTES_KEY, scenario="after insertion"):
    """Physical OIR TC2 expected results for the ports whose module was just
    inserted, and for their link peers on this DUT.

    A remote reseat simulates a removal and an insertion, so Remote reseat TC1
    checks the same results, reading ``link_flap_monitor_timeout_sec`` from its
    own ``attribute_key`` category and labelling the EEPROM recovery with its
    ``scenario``.  ``insert_flap_baseline`` holds the flap counts of the ports
    and their link peers from before the operation; each must have moved by
    ``expected_flap_increment``.  ``baseline_tables`` / ``baseline_sensor_data``
    come from :func:`capture_recovery_baseline`.
    """
    recovery_start = time.monotonic()
    startup_deadline = recovery_start + wait_sec
    publication_deadline = recovery_start + dom_recover_wait(
        port_attributes_dict, lports, wait_sec)

    # No link flap for link_flap_monitor_timeout_sec: the shared stability
    # sub-check, held for that window.
    port_recovery = standard_port_recovery_and_verification(
        duthost, lports, {port: port_attributes_dict[port] for port in lports},
        link_up_timeout_sec=remaining_wait(startup_deadline),
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        port_peers=port_peers,
        stability_window_sec=flap_monitor_sec(port_attributes_dict, lports, attribute_key),
    )
    failures = []
    if not port_recovery["passed"]:
        failures.append(port_recovery["details"])

    failures += verify_presence_clis(duthost, lports, present=True)
    failures += verify_state_tables_present(
        duthost,
        lports,
        parents_of(lports, lport_to_first_subport_mapping),
        remaining_wait(publication_deadline),
        baseline_tables=baseline_tables,
    )

    # The local port must come up without flapping across the operation itself,
    # which a post-recovery sentinel alone cannot see.
    if insert_flap_baseline is not None:
        failures += verify_flap_count_increment(
            duthost, lports, insert_flap_baseline, expected_increment=expected_flap_increment)
    # The link peers on this DUT come back up, flapping as much as the ports.
    failures += verify_link_peers(
        duthost, list(get_link_peers(duthost, lports, port_peers).values()), "up",
        remaining_wait(startup_deadline), insert_flap_baseline, expected_flap_increment)

    failures += recovery.verify_transceiver_recovery(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        remaining_wait(startup_deadline),
        scenario,
        ports=lports,
        firmware_wait_sec=remaining_wait(publication_deadline),
        # The module was just re-seated, so its EEPROM is physically re-read;
        # always take the live-I2C confirmation pass even on a zero settle.
        live_i2c_confirm=True,
    )

    failures += verify_dom_thresholds_after_operation(
        duthost, port_attributes_dict, parents_of(lports, lport_to_first_subport_mapping),
    )

    # DOM data must be republished with valid, fresh values once the module is
    # back (VDM / PM re-publication is covered by the STATE_DB table check
    # above, which is driven by the pre-operation baseline).
    dom_failures = verify_dom_data_recovered(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        lports,
        baseline_sensor_data or {},
        remaining_wait(publication_deadline),
    )
    if dom_failures:
        failures.append("DOM sensor data:\n  " + "\n  ".join(dom_failures))

    failures += verify_no_kernel_errors(duthost, watermark)
    return failures
