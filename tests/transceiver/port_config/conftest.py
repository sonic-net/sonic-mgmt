"""Port Config test-category conftest (fixtures only).

Per the prerequisite matrix in ``docs/testplan/transceiver/test_plan.md``, the
Port Config category consumes NO session-level prerequisite gates
(``presence_verified`` / ``gold_fw_verified`` / ``links_verified``): every test
is a read-only CONFIG_DB query that does not require a live link or a present
transceiver.  The cross-category per-test health check (xcvrd PID / core files)
from the top-level ``tests/transceiver/conftest.py`` still applies automatically.

All helper functions and constants live in ``utils/`` so this file holds
fixtures only.
"""
import logging

import pytest

from tests.common.platform.interface_utils import (
    get_dut_interfaces_status,
    get_physical_port_indices,
)
from tests.transceiver.port_config.utils.port_config_constants import PORT_FIELD_INDEX
from tests.transceiver.port_config.utils.port_config_db_reader import get_config_db_port_table

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def transceiver_ports(port_attributes_dict):
    """Return the transceiver ports under test, sorted for deterministic output.

    The port list is the keys of ``port_attributes_dict`` (the resolved
    transceiver inventory for this DUT).  Skips the whole category when no
    transceiver ports are configured.
    """
    ports = sorted(port_attributes_dict.keys())
    if not ports:
        pytest.skip("No transceiver ports found in port_attributes_dict")
    return ports


@pytest.fixture(scope="module")
def config_db_port_table(duthost):
    """Read the entire CONFIG_DB PORT table once per module as {port: {field: value}}."""
    port_table = get_config_db_port_table(duthost)
    if not port_table:
        pytest.skip("CONFIG_DB PORT table is empty")
    return port_table


@pytest.fixture(scope="module")
def physical_index_by_port(duthost, transceiver_ports, config_db_port_table):
    """Map each logical port to physical index with CONFIG_DB-first resolution.

    Reuse ``config_db_port_table`` (already bulk-cached once per module) and
    parse PORT.index when available. Fall back to ``get_physical_port_indices``
    only for ports with missing/unparseable index.
    """
    mapping = {}
    missing = []
    for port in transceiver_ports:
        raw = config_db_port_table.get(port, {}).get(PORT_FIELD_INDEX)
        if raw is None:
            mapping[port] = None
            missing.append(port)
            continue
        try:
            mapping[port] = int(str(raw).strip())
        except (TypeError, ValueError):
            mapping[port] = None
            missing.append(port)

    if missing:
        logger.info(
            "Falling back to sonic-db-cli for %d port(s) missing/unparseable CONFIG_DB index",
            len(missing),
        )
        slow_map = get_physical_port_indices(duthost)
        unresolved = []
        for port in missing:
            mapping[port] = slow_map.get(port)
            if mapping[port] is None:
                unresolved.append(port)

        if unresolved:
            logger.warning(
                "Could not resolve physical index for %d port(s): %s",
                len(unresolved),
                ", ".join(sorted(unresolved)),
            )

    return mapping


@pytest.fixture(scope="module", autouse=True)
def _port_config_post_test_check(duthost, transceiver_ports):
    """Post-Test Check from port_config_test_plan.md: confirm ports stay oper-up.

    The plan specifies a single post-test check, run once after all test cases:
    "Confirm all ports in port_attributes_dict remain operationally up." All
    Port Config tests are read-only CONFIG_DB queries so no link disruption is
    expected; this teardown confirms that assumption held.

    Implemented as a module-scoped autouse ``yield`` fixture so the check runs
    once after every Port Config test in the module has finished, matching the
    plan's "once after all test cases have completed" wording.  A port found
    oper-down here fails the teardown so the regression surfaces clearly.
    """
    # Setup phase: snapshot oper-up baseline so we only detect regressions.
    baseline = get_dut_interfaces_status(duthost)
    baseline_up = []
    baseline_missing = []
    for port in transceiver_ports:
        status = baseline.get(port)
        if status is None:
            baseline_missing.append(port)
            continue
        oper = str(status.get("oper", "")).strip().lower()
        if oper == "up":
            baseline_up.append(port)

    if baseline_missing:
        logger.warning(
            "Post-test baseline: %d/%d port(s) missing from 'show interface description': %s",
            len(baseline_missing),
            len(transceiver_ports),
            ", ".join(sorted(baseline_missing)),
        )

    yield

    # Teardown phase: ensure baseline-up ports remain up.
    if not baseline_up:
        logger.info(
            "Post-test check skipped: no transceiver ports were oper-up in baseline"
        )
        return

    intf_status = get_dut_interfaces_status(duthost)
    regressed = []
    for port in baseline_up:
        status = intf_status.get(port)
        oper = str(status.get("oper", "missing") if status else "missing").strip().lower()
        if oper != "up":
            regressed.append("{}(oper={})".format(port, oper or "unknown"))

    if regressed:
        pytest.fail(
            "Post-test check failed: {}/{} port(s) that were oper-up before "
            "Port Config tests are not oper-up after: {}".format(
                len(regressed), len(baseline_up), "; ".join(regressed)
            )
        )
    logger.info(
        "Post-test check passed: all %d baseline oper-up port(s) remained oper-up",
        len(baseline_up),
    )
