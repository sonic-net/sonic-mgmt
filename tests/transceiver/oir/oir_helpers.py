"""Physical OIR operations and verification primitives.

Backs the Physical OIR test cases in
``docs/testplan/transceiver/online_insertion_removal_testplan.md``.

Operations are operator driven (``oir_method`` ``manual``): each one prints a
prompt on the terminal, blocks until the operator confirms, then waits for the
DUT to observe the new presence state.  Verifiers return per-port failure
strings so the caller can aggregate them into a single ``pytest.fail``, matching
the pattern used across the transceiver suite.
"""
import http.client
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
)
from tests.common.utilities import wait_until
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
    read_dom_sensor_data,
    verify_dom_recovered,
)

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
#  seated status or ``None`` for "anything but the empty-cage status",
#  whether the CLI reads the module itself rather than xcvrd's TRANSCEIVER_INFO).
# These whole-switch commands return all frontend ASICs when unqualified.
# ``sfputil show eeprom -d`` covers both the EEPROM dump and TC1 step 3's "DOM
# values read back empty", so the empty cage is proven without a second dump.
_STATUS_CLIS = (
    ("sfputil show presence", cli_helpers.sfputil_show_presence_cmd,
     parse_presence, PRESENCE_ABSENT, PRESENCE_PRESENT, True),
    ("show interfaces transceiver presence", cli_helpers.show_interfaces_transceiver_presence_cmd,
     parse_presence, PRESENCE_ABSENT, PRESENCE_PRESENT, False),
    ("sfputil show eeprom -d", _sfputil_show_eeprom_dom_cmd,
     reduce_eeprom_status, ABSENT_MSG_SFPUTIL, None, True),
    ("show interfaces transceiver info", cli_helpers.show_interfaces_transceiver_info_cmd,
     reduce_eeprom_status, ABSENT_MSG_CLI_INFO, None, False),
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


def verify_presence_clis(duthost, lports, present, published=None):
    """Verify the presence / EEPROM / DOM CLIs all agree with the expected seated state.

    Each CLI is run without a port argument (whole-switch dump) and must exit 0;
    the unqualified commands return all frontend ASICs. The per-port status line
    is then matched against the expected token.  The ``sfputil`` CLIs read the
    module itself and must report ``present``; the ``show`` CLIs report xcvrd's
    ``TRANSCEIVER_INFO`` and must report ``published`` (default: ``present``),
    which is ``False`` for a seated module xcvrd cannot build an XcvrApi for.
    """
    published = present if published is None else published
    failures = []
    for label, build_cmd, reduce_output, absent_status, present_status, reads_module in _STATUS_CLIS:
        expect_present = present if reads_module else published
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


def verify_state_tables_removed(duthost, lports, wait_sec, status_sw=STATUS_SW_REMOVED):
    """Every ``TRANSCEIVER_*`` table is deleted bar ``TRANSCEIVER_STATUS_SW``, which
    must match ``status_sw``: the REMOVED state, or xcvrd's insertion write for a
    seated module it cannot build an XcvrApi for."""
    def _check():
        tables_by_port, failures = _transceiver_state_tables(duthost, lports)
        for port in lports:
            stale = natsorted(tables_by_port.get(port, set()) - {TRANSCEIVER_STATUS_SW})
            if stale:
                failures.append(f"{port}: STATE_DB table(s) not deleted after removal: {', '.join(stale)}")
            failures += _check_status_sw(duthost, port, status_sw)
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
        for port in lports:
            expected = set(baseline_tables.get(port, set()))
            if port in parents:
                expected |= set(INSERTED_TABLES)
            missing = natsorted(expected - tables_by_port.get(port, set()))
            if missing:
                failures.append(
                    f"{port}: STATE_DB table(s) not republished after insertion: {', '.join(missing)}"
                )
            failures += _check_status_sw(duthost, port, STATUS_SW_READY if ready else STATUS_SW_INSERTED)
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


def is_identifier_readable(conn, pport):
    """Return whether the identifier byte (EEPROM offset 0) of the module in ``pport`` reads back.

    The XcvrApi factory picks the API class from this byte, so a module whose
    identifier reads back yet gets no XcvrApi is unsupported, while an
    unreadable identifier is a read error.  The server returns ``None`` for a
    failed read and a raised call alike, and serializes the ``bytearray`` of a
    successful read as its class name.
    """
    return _sfp_api(conn, pport, "read_eeprom", [0, 1]) is not None


def get_flap_counts(duthost, lports):
    """Return ``{port: flap_count}`` (raw APPL_DB strings) for ``lports``."""
    return {port: sentinel[0] for port, sentinel in capture_flap_sentinels(duthost, lports).items()}


def _other_ports(port_attributes_dict, affected_lports, link_peers):
    """Return the inventory ports neither under OIR nor linked to a port that is.

    ``link_peers`` maps a port to its link peer on this DUT; the peer loses its
    link along with the port, so it is not an unrelated port.
    """
    related = set(affected_lports)
    related.update(link_peers[port] for port in affected_lports if port in link_peers)
    return natsorted(set(port_attributes_dict) - related)


def get_other_ports_flap_counts(duthost, port_attributes_dict, affected_lports, link_peers):
    """Return :func:`get_flap_counts` for every inventory port unrelated to the OIR."""
    return get_flap_counts(duthost, _other_ports(port_attributes_dict, affected_lports, link_peers))


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


def verify_no_link_flap(duthost, port_attributes_dict, lports,
                        sentinels=None, observation_start=None):
    """Verify each port stays stable for its configured observation window."""
    lports_by_timeout = defaultdict(list)
    for port in lports:
        attrs = port_attributes_dict[port][PHYSICAL_OIR_ATTRIBUTES_KEY]
        lports_by_timeout[attrs["link_flap_monitor_timeout_sec"]].append(port)

    if sentinels is None:
        sentinels = capture_flap_sentinels(duthost, lports)
    if observation_start is None:
        observation_start = time.monotonic()

    failures = []
    for monitor_sec in sorted(lports_by_timeout):
        elapsed_sec = time.monotonic() - observation_start
        time.sleep(max(0, monitor_sec - elapsed_sec))
        monitored_lports = lports_by_timeout[monitor_sec]
        results = assert_no_flap_since(
            duthost, monitored_lports, sentinels, elapsed_sec=monitor_sec)
        failures += [result["details"] for result in results.values() if not result["passed"]]
    return failures


def get_oper_up_ports(duthost, lports):
    """Return the ``lports`` that are oper up."""
    intf_status = get_dut_interfaces_status(duthost)
    return [port for port in lports if (intf_status.get(port) or {}).get("oper") == "up"]


def verify_other_ports_up(duthost, port_attributes_dict, affected_lports, link_peers):
    """Verify every inventory port unrelated to the OIR stayed oper up."""
    intf_status = get_dut_interfaces_status(duthost)
    return [
        f"{port}: oper {(intf_status.get(port) or {}).get('oper', 'missing')}, expected up "
        "while another port's transceiver was out of its cage"
        for port in _other_ports(port_attributes_dict, affected_lports, link_peers)
        if (intf_status.get(port) or {}).get("oper") != "up"
    ]


def verify_other_ports_no_flap(duthost, baseline):
    """Verify no port in ``baseline`` flapped since it was captured.

    ``baseline`` is :func:`get_other_ports_flap_counts`.  Those ports keep their
    module seated and their link peer untouched throughout, so any
    ``flap_count`` change (a single down or up transition included) means
    another port's OIR disturbed their link.
    """
    return [
        f"{failure} while another port's transceiver was inserted/removed"
        for failure in verify_flap_count_increment(duthost, list(baseline), baseline, expected_increment=0)
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
