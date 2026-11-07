"""
Test SW-controlled CPO -- DOM publication to STATE_DB.

Runs only when both gates are true:
  1. CPO platform        -- hwsku.json port_type=CPO
  2. SW-control feature  -- sai.profile SAI_INDEPENDENT_MODULE_MODE=1

The laser source (ELS) publishes into its own TRANSCEIVER_ELS_* tables, one
counterpart per optical-engine table. Asserts:
  1. For each table in CPO_ELS_TABLE_SPEC, the required ELS fields are present.
  2. The FLAG tables' CHANGE_COUNT / SET_TIME / CLEAR_TIME companions exist,
     for both the ELS and the optical-engine FLAG tables.
  3. Optical-engine tables (CPO_OE_TABLE_SPEC) carry their required engine
     fields and no longer carry legacy ``els_*`` fields.
  4. Refreshed tables have a ``last_update_time`` no older than 60 s.
  5. Fixed-value fields (e.g. TRANSCEIVER_INFO CPO invariants) match.
  6. The ELS per-lane setpoints are all published in ELS_DOM_THRESHOLD or
     ELS_DOM_SENSOR (they moved between images).
  7. The VDM threshold and flag tables, and the flag companions, exist.

On SIMX, tables in CPO_SIMX_SKIPPED_TABLES (*_DOM_TEMPERATURE, VDM) and the
CDB-backed ELS fields are not checked.

Only one oper-up CPO port (first subport) is checked -- all CPO ports share
the same pmon publication logic so one representative port is sufficient.
"""
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.cpo_dom_field_catalog import (
    CPO_LAST_UPDATE_FUTURE_TOLERANCE_SEC,
    CPO_LAST_UPDATE_MAX_AGE_SEC,
    CPO_ELS_COMPANION_TABLES,
    CPO_OE_COMPANION_TABLES,
    CPO_ELS_TABLE_SPEC,
    CPO_OE_TABLE_SPEC,
    CPO_REFRESHED_TABLES,
    CPO_SIMX_SKIPPED_TABLES,
    CPO_VDM_TABLES,
    ELS_SETPOINT_FIELDS,
    ELS_SETPOINT_TABLES,
    LEGACY_ELS_FIELD_PREFIX,
)
from tests.common.platform.interface_utils import get_lport_to_first_subport_mapping
from tests.common.platform.processes_utils import check_pmon_uptime_minutes
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import wait_until
from tests.platform_tests.mellanox.conftest import CPO_PORT_TYPE
from tests.platform_tests.mellanox.cpo_cli_helpers import dump_transceiver_state_db
from tests.platform_tests.mellanox.software_control_helper import check_sc_sai_attribute_value

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic('mellanox'),
    pytest.mark.topology('any'),
]


def _find_oper_up_cpo_port(duthost, state_db_snapshot):
    """Pick one CPO port that is oper up (its first subport).

    Uses TRANSCEIVER_INFO from the snapshot to identify CPO ports, then
    checks oper status via 'show interface status'.

    Returns:
        str: The first subport of the chosen oper-up CPO logical port.
    """
    info_table = state_db_snapshot.get("TRANSCEIVER_INFO", {})
    cpo_logical_ports = [
        port for port, fields in info_table.items()
        if fields.get("type") == CPO_PORT_TYPE
    ]
    if not cpo_logical_ports:
        return None

    # Get first-subport mapping for CPO logical ports
    mapping = get_lport_to_first_subport_mapping(duthost, cpo_logical_ports)

    # Get oper status in one call
    intf_status = duthost.show_and_parse("show interface status")
    oper_up_ports = {
        entry["interface"]
        for entry in intf_status
        if entry.get("oper", "").lower() == "up"
    }

    # Pick first CPO logical port whose first-subport is oper up
    for lport in sorted(cpo_logical_ports):
        first_subport = mapping.get(lport)
        if first_subport and first_subport in oper_up_ports:
            logger.info("Selected CPO port for test: %s (first subport of %s)",
                        first_subport, lport)
            return first_subport

    # A down port's DOM may be only partially populated, so checking it would
    # produce false failures. Skip the port-dependent checks instead.
    pytest.skip("No oper-up CPO port found among {} CPO ports".format(
        len(cpo_logical_ports)))


@pytest.fixture(scope="module", autouse=True)
def _require_sw_controlled_cpo(
    duthosts, rand_one_dut_hostname,
    is_cpo_supported,
):
    """Skip suite unless CPO + SW control gates hold."""
    duthost = duthosts[rand_one_dut_hostname]
    sw_control = check_sc_sai_attribute_value(duthost)

    missing = []
    if not is_cpo_supported:
        missing.append("CPO platform (hwsku.json port_type=CPO)")
    if not sw_control:
        missing.append("SW control (sai.profile SAI_INDEPENDENT_MODULE_MODE=1)")
    if missing:
        pytest.skip("Test requires: " + "; ".join(missing))


@pytest.fixture(scope="module")
def cpo_state_db_snapshot(duthosts, rand_one_dut_hostname):
    """Bulk snapshot of all TRANSCEIVER_* tables from STATE_DB (one SSH call)."""
    duthost = duthosts[rand_one_dut_hostname]
    pytest_assert(
        wait_until(360, 10, 0, check_pmon_uptime_minutes, duthost),
        "Pmon docker is not ready for test",
    )
    snapshot = dump_transceiver_state_db(duthost)
    pytest_assert(snapshot, "STATE_DB has no TRANSCEIVER_* entries")
    return snapshot


@pytest.fixture(scope="module")
def cpo_test_port(duthosts, rand_one_dut_hostname, cpo_state_db_snapshot):
    """Single oper-up CPO first-subport for validation."""
    duthost = duthosts[rand_one_dut_hostname]
    port = _find_oper_up_cpo_port(duthost, cpo_state_db_snapshot)
    pytest_assert(port, "No CPO port found in STATE_DB TRANSCEIVER_INFO")
    return port


def _is_simx(duthost):
    return "simx" in duthost.facts["platform"]


def _tables_to_check(duthost, tables):
    """Drop tables that are not checked on SIMX (see CPO_SIMX_SKIPPED_TABLES)."""
    if not _is_simx(duthost):
        return list(tables)
    skipped = sorted(t for t in tables if t in CPO_SIMX_SKIPPED_TABLES)
    if skipped:
        logger.info("SIMX: skipping %s", skipped)
    return [t for t in tables if t not in CPO_SIMX_SKIPPED_TABLES]


def _check_fields(port, table_name, fields, required, value_checks):
    """Return a list of failure strings for one (table, port) row."""
    failures = []
    missing = sorted(set(required) - set(fields))
    if missing:
        failures.append(f"{port}: {table_name} -- missing required fields: {missing}")
    for vfield, expected in value_checks.items():
        actual = fields.get(vfield)
        if actual is None:
            failures.append(
                f"{port}: {table_name} -- '{vfield}' missing (expected {expected!r})"
            )
        elif str(actual) != str(expected):
            failures.append(
                f"{port}: {table_name} -- '{vfield}' = {actual!r} (expected {expected!r})"
            )
    return failures


def _check_els_setpoints(port, snapshot):
    """Setpoints must all be in one of ELS_SETPOINT_TABLES (they moved between images)."""
    for table_name in ELS_SETPOINT_TABLES:
        fields = snapshot.get(table_name, {}).get(port, {})
        if set(ELS_SETPOINT_FIELDS) <= set(fields):
            logger.info("[%s] ELS setpoints published in %s", port, table_name)
            return []
    missing = {
        table_name: sorted(set(ELS_SETPOINT_FIELDS)
                           - set(snapshot.get(table_name, {}).get(port, {})))
        for table_name in ELS_SETPOINT_TABLES
    }
    return [f"{port}: ELS setpoints not fully published in any of "
            f"{list(ELS_SETPOINT_TABLES)} -- missing per table: {missing}"]


def _fail_if_any(failures, title):
    """Fail once with every collected failure, instead of stopping at the first."""
    pytest_assert(not failures, f"{title}:\n  - " + "\n  - ".join(failures))


def test_cpo_els_tables_in_state_db(
    duthosts, rand_one_dut_hostname, cpo_state_db_snapshot, cpo_test_port,
):
    """Every laser-source table exists and carries its required fields."""
    duthost = duthosts[rand_one_dut_hostname]
    port = cpo_test_port
    failures = []

    for table_name in _tables_to_check(duthost, CPO_ELS_TABLE_SPEC):
        spec = CPO_ELS_TABLE_SPEC[table_name]
        required_fields = set(spec["els"])
        # CDB-backed fields (e.g. laser_mpd_laneN) are not available on SIMX.
        if not _is_simx(duthost):
            required_fields.update(spec.get("cdb_els", ()))

        fields = cpo_state_db_snapshot.get(table_name, {}).get(port, {})
        with allure.step(f"{table_name}|{port}"):
            if not fields:
                failures.append(f"{port}: STATE_DB key '{table_name}|{port}' does not exist")
                continue
            logger.info("[%s] %s: %d fields published", port, table_name, len(fields))
            logger.debug("[%s] %s fields: %s", port, table_name, sorted(fields))
            failures += _check_fields(
                port, table_name, fields, required_fields, spec.get("value_check", {}),
            )

    with allure.step(f"ELS setpoints|{port}"):
        failures += _check_els_setpoints(port, cpo_state_db_snapshot)

    _fail_if_any(failures, "CPO ELS table validation failed")


def _missing_keys(snapshot, port, tables):
    """One failure string per ``table|port`` key absent from the snapshot."""
    return [
        f"{port}: STATE_DB key '{table_name}|{port}' does not exist"
        for table_name in tables
        if not snapshot.get(table_name, {}).get(port)
    ]


def test_cpo_els_flag_companion_tables_in_state_db(cpo_state_db_snapshot, cpo_test_port):
    """CHANGE_COUNT / SET_TIME / CLEAR_TIME companions of the ELS FLAG tables exist."""
    failures = _missing_keys(cpo_state_db_snapshot, cpo_test_port, CPO_ELS_COMPANION_TABLES)
    _fail_if_any(failures, "CPO ELS companion table validation failed")


def test_cpo_oe_flag_companion_tables_in_state_db(cpo_state_db_snapshot, cpo_test_port):
    """CHANGE_COUNT / SET_TIME / CLEAR_TIME companions of the engine FLAG tables exist."""
    failures = _missing_keys(cpo_state_db_snapshot, cpo_test_port, CPO_OE_COMPANION_TABLES)
    _fail_if_any(failures, "CPO engine companion table validation failed")


def test_cpo_vdm_tables_in_state_db(
    duthosts, rand_one_dut_hostname, cpo_state_db_snapshot, cpo_test_port,
):
    """VDM threshold and flag tables, and the flag companions, exist (not on SIMX)."""
    duthost = duthosts[rand_one_dut_hostname]
    tables = _tables_to_check(duthost, CPO_VDM_TABLES)
    if not tables:
        pytest.skip("SIMX does not emulate VDM")
    with allure.step(f"{len(tables)} VDM tables on {cpo_test_port}"):
        failures = _missing_keys(cpo_state_db_snapshot, cpo_test_port, tables)
    _fail_if_any(failures, "CPO VDM table validation failed")


def test_cpo_oe_tables_in_state_db(
    duthosts, rand_one_dut_hostname, cpo_state_db_snapshot, cpo_test_port,
):
    """Optical-engine tables carry their own fields and no laser-source leftovers."""
    duthost = duthosts[rand_one_dut_hostname]
    port = cpo_test_port
    failures = []

    for table_name in _tables_to_check(duthost, CPO_OE_TABLE_SPEC):
        spec = CPO_OE_TABLE_SPEC[table_name]
        fields = cpo_state_db_snapshot.get(table_name, {}).get(port, {})
        with allure.step(f"{table_name}|{port}"):
            if not fields:
                failures.append(f"{port}: STATE_DB key '{table_name}|{port}' does not exist")
                continue
            leaked = sorted(f for f in fields if f.startswith(LEGACY_ELS_FIELD_PREFIX))
            if leaked and not spec.get("allow_els_prefix"):
                failures.append(
                    f"{port}: {table_name} -- legacy ELS fields still published: {leaked}"
                )
            failures += _check_fields(
                port, table_name, fields, spec["els"], spec.get("value_check", {}),
            )

    _fail_if_any(failures, "CPO engine table validation failed")


def _last_update_age_sec(duthost, table_name, port):
    """Seconds since ``last_update_time`` (UTC) of ``table_name|port``, or None."""
    cmd = (
        'ts=$(sonic-db-cli STATE_DB hget "{t}|{p}" last_update_time); '
        '[ -n "$ts" ] && echo $(( $(date -u +%s) - $(date -u -d "$ts UTC" +%s) ))'
    ).format(t=table_name, p=port)
    out = duthost.shell(cmd, module_ignore_errors=True)["stdout"].strip()
    return int(out) if out.lstrip("-").isdigit() else None


def test_cpo_tables_last_update_time_fresh(duthosts, rand_one_dut_hostname, cpo_test_port):
    """``last_update_time`` of every refreshed table is within the 60 s DOM interval."""
    duthost = duthosts[rand_one_dut_hostname]
    port = cpo_test_port
    tables = _tables_to_check(duthost, CPO_REFRESHED_TABLES)
    stale = {}

    def _all_fresh():
        stale.clear()
        for table_name in tables:
            age = _last_update_age_sec(duthost, table_name, port)
            if (age is None or age > CPO_LAST_UPDATE_MAX_AGE_SEC
                    or age < -CPO_LAST_UPDATE_FUTURE_TOLERANCE_SEC):
                stale[table_name] = age
        return not stale

    # Retry briefly so a read just before the next refresh does not flake.
    with allure.step(f"last_update_time of {len(tables)} tables on {port}"):
        pytest_assert(
            wait_until(30, 5, 0, _all_fresh),
            f"{port}: last_update_time not refreshed within "
            f"{CPO_LAST_UPDATE_MAX_AGE_SEC}s (None = missing, negative = future-dated), "
            f"age per table: {stale}",
        )
