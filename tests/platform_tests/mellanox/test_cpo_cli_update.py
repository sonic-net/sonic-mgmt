"""
SW-controlled CPO -- ``cpoutil`` CLI tests.

On CPO platforms (``cpo.json`` present) ``sfputil`` is no longer supported and
``sfpshow`` no longer prints ELS data, so the CPO/ELS data is reachable only
through ``cpoutil``.  This suite covers two scenarios:

  * TC-1  ``cpoutil show interface dom -p <cpo_port>`` -- the OE and ELS fields,
          including the platform-specific ones, are present in the ``--json``
          and table output (values are not checked).  The expected fields are
          listed in ``tests/common/platform/cpo_cli_label_catalog.py``.
  * TC-2  ``cpoutil read-eeprom interface -p <cpo_port> --oe | --els`` -- raw
          EEPROM access that replaces ``sfputil read-eeprom``.

``cpoutil`` reads the modules through the platform xcvr API, not STATE_DB, so
the values are live and are not compared with STATE_DB.

The suite runs only when **both** gates are true (skipped otherwise):

  1. CPO platform        -- hwsku.json port_type=CPO
  2. SW-control feature  -- sai.profile SAI_INDEPENDENT_MODULE_MODE=1
"""
import json
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import check_pmon_uptime_minutes
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import wait_until
from tests.platform_tests.mellanox.cpo_cli_helpers import (
    assert_cpoutil_dom_output,
    parse_cpoutil_hexdump,
)
from tests.platform_tests.mellanox.software_control_helper import check_sc_sai_attribute_value

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.asic("mellanox"),
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]

# Commands under test
CMD_CPOUTIL_SHOW_MAP_JSON = "sudo cpoutil show interface map --json"
CMD_CPOUTIL_SHOW_DOM = "sudo cpoutil show interface dom -p {port}"
CMD_CPOUTIL_READ_EEPROM = "sudo cpoutil read-eeprom interface -p {port} {target}"
CMD_CPOUTIL_READ_EEPROM_RANGE = CMD_CPOUTIL_READ_EEPROM + " -n {page} -o {offset} -s {size}"

EEPROM_HEXDUMP_TITLE = "EEPROM hexdump for"


def _run(dut, cmd):
    """Run ``cmd`` and return its stdout; fail the test on a non-zero rc."""
    res = dut.command(cmd, module_ignore_errors=True)
    pytest_assert(
        res.get("rc") == 0,
        f"Run command '{cmd}' failed with rc={res.get('rc')}, "
        f"stdout={res.get('stdout')!r}, stderr={res.get('stderr')!r}",
    )
    return res["stdout"]


# ---------------------------------------------------------------------------
# Module-scoped fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def dut(duthosts, rand_one_dut_hostname):
    return duthosts[rand_one_dut_hostname]


@pytest.fixture(scope="module", autouse=True)
def _require_sw_controlled_cpo(dut, is_cpo_supported):
    """Skip suite unless CPO + SW control hold."""
    sw_control = check_sc_sai_attribute_value(dut)
    missing = []
    if not is_cpo_supported:
        missing.append("CPO platform (hwsku.json port_type=CPO)")
    if not sw_control:
        missing.append("SW control (sai.profile SAI_INDEPENDENT_MODULE_MODE=1)")
    if missing:
        pytest.skip("Test requires: " + "; ".join(missing))


@pytest.fixture(scope="module")
def cpo_test_port(dut):
    """First CPO port reported by cpoutil (it reads every port directly)."""
    pytest_assert(
        wait_until(360, 10, 0, check_pmon_uptime_minutes, dut),
        "Pmon docker is not ready for test",
    )
    ports = sorted(json.loads(_run(dut, CMD_CPOUTIL_SHOW_MAP_JSON)),
                   key=lambda port: int(port[len("Ethernet"):]))
    pytest_assert(ports, f"{CMD_CPOUTIL_SHOW_MAP_JSON}: no CPO port reported")
    return ports[0]


# ===========================================================================
# TC-1: cpoutil show interface dom -p <cpo_port>
# ===========================================================================
def test_tc1_cpoutil_show_interface_dom(dut, cpo_test_port):
    """TC-1: CPO/ELS fields incl. platform-specific are in both output forms."""
    cmd = CMD_CPOUTIL_SHOW_DOM.format(port=cpo_test_port)
    with allure.step(f"Run: {cmd} [--json]"):
        json_output = json.loads(_run(dut, cmd + " --json"))
        text_output = _run(dut, cmd)

    with allure.step("Validate CMIS DOM sentinels + common ELS + platform-specific fields"):
        assert_cpoutil_dom_output(
            cmd_label=cmd,
            port=cpo_test_port,
            json_output=json_output,
            text_output=text_output,
            is_simx="simx" in dut.facts["platform"],
        )


# ===========================================================================
# TC-2: cpoutil read-eeprom interface -p <cpo_port> (replaces sfputil read-eeprom)
# ===========================================================================
@pytest.mark.parametrize("target", ["--oe", "--els"])
def test_tc2a_cpoutil_read_eeprom_interface(dut, cpo_test_port, target):
    """TC-2a: full EEPROM dump of the OE / ELS mapped to the port."""
    cmd = CMD_CPOUTIL_READ_EEPROM.format(port=cpo_test_port, target=target)
    with allure.step(f"Run: {cmd}"):
        out = _run(dut, cmd)
    pytest_assert(
        out.lstrip().startswith(EEPROM_HEXDUMP_TITLE),
        f"{cmd}: output does not start with '{EEPROM_HEXDUMP_TITLE}':\n{out}",
    )
    dump = parse_cpoutil_hexdump(out)
    missing = sorted(set(range(0x80)) - set(dump))
    pytest_assert(
        not missing,
        f"{cmd}: lower page (bytes 0x00-0x7f) not fully dumped; {len(missing)} offsets missing "
        f"(first: {[hex(o) for o in missing[:8]]}):\n{out}",
    )


def test_tc2b_cpoutil_read_eeprom_interface_range(dut, cpo_test_port):
    """TC-2b: a ranged OE read returns exactly the requested bytes and matches
    the full dump on the identifier byte."""
    size = 16
    cmd_full = CMD_CPOUTIL_READ_EEPROM.format(port=cpo_test_port, target="--oe")
    cmd_range = CMD_CPOUTIL_READ_EEPROM_RANGE.format(
        port=cpo_test_port, target="--oe", page=0, offset=0, size=size)

    with allure.step(f"Run: {cmd_range}"):
        out = _run(dut, cmd_range)
        ranged = parse_cpoutil_hexdump(out)
        pytest_assert(
            sorted(ranged) == list(range(size)),
            f"{cmd_range}: expected bytes at offsets 0..{size - 1}, "
            f"got {sorted(ranged)}:\n{out}",
        )

    with allure.step(f"Run: {cmd_full}"):
        full = parse_cpoutil_hexdump(_run(dut, cmd_full))

    # Only byte 0 (SFF-8024 identifier) is compared; the other lower-page
    # bytes carry live status (module state, flags) and may change.
    pytest_assert(
        full.get(0) == ranged[0],
        f"identifier byte differs between ranged read ({ranged[0]:#04x}) "
        f"and full dump ({full.get(0)})",
    )
