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
def physical_index_by_port(duthost):
    """Map each logical port to its physical port index (for subport grouping)."""
    return get_physical_port_indices(duthost)


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
    # Setup phase: nothing to do (per-test health is handled by the top-level
    # transceiver health-check fixture); yield straight to the test cases.
    yield

    # Teardown phase: run once after all Port Config tests in this module.
    intf_status = get_dut_interfaces_status(duthost)
    not_up = []
    for port in transceiver_ports:
        status = intf_status.get(port)
        if status is None:
            not_up.append("{}(missing from 'show interface description')".format(port))
            continue
        oper = str(status.get("oper", "")).strip().lower()
        if oper != "up":
            not_up.append("{}(oper={})".format(port, oper or "unknown"))

    if not_up:
        pytest.fail(
            "Post-test check failed: {}/{} transceiver port(s) not operationally up "
            "after Port Config tests: {}".format(
                len(not_up), len(transceiver_ports), "; ".join(not_up)
            )
        )
    logger.info(
        "Post-test check passed: all %d transceiver port(s) remain oper-up", len(transceiver_ports)
    )
