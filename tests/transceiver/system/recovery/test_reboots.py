"""System / System Recovery - config reload / reboot / power cycle link recovery validations.

Implements the System Recovery test cases from
    ``docs/testplan/transceiver/system_test_plan.md``:

  * test_system_config_reload_link_recovery — config reload impact.
  * test_system_reboot_link_recovery        — cold / warm / fast reboot link recovery.
  * test_system_power_cycle_link_recovery   — power cycle link recovery.

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every System test)
    `- test_system_config_reload_link_recovery
    `- test_system_reboot_link_recovery[cold|warm|fast]
         |- skip if {reboot_type}_reboot_supported is False (warm/fast)
    `- test_system_power_cycle_link_recovery
         |- skip if power_cycle_supported is False or no PDU controller
       each test:
         |- run_pre_check  (health OK)         <- _per_test_health_check
         |- <body>: _link_recovery -> verify links up -> operation (scenario_ops)
            -> Standard Port Recovery and Verification
         `- run_post_check
  session end
    `- _system_post_session_checks (system/conftest.py)
         |- post_state_restoration()
         |- STATE_DB consistency check
         `- final link + LLDP check

Failure handling: failures are accumulated per test case and reported in a single
pytest.fail at the end, so a single run shows all issues across all ports.
"""
import logging
import time

import pytest

from tests.common.platform.processes_utils import wait_critical_processes
from tests.transceiver.attribute_parser.attribute_keys import (
    SYSTEM_ATTRIBUTES_KEY
)
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.health_checks import (
    DEFAULT_MONITORED_PROCESSES,
    capture_baseline,
)
from tests.transceiver.common.prerequisites import check_links_up
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification
)

logger = logging.getLogger(__name__)


def _system_attributes(port_attributes_dict):
    """Return the (uniform across ports) System attributes from a representative port."""
    assert port_attributes_dict, "port_attributes_dict is empty - nothing to validate"
    return next(iter(port_attributes_dict.values())).get(SYSTEM_ATTRIBUTES_KEY, {})


def _link_recovery(
    duthost, port_attributes_dict, lport_to_first_subport_mapping, expected_pid_changes,
    op_name, settle_attr, operation,
):
    """Run a system-wide disruption and verify all transceiver ports recover cleanly.

    See the module docstring for the full execution tree.  Steps:

      * verify all ports are oper-up before the operation (skip otherwise),
      * run ``operation()`` - a ``scenario_ops`` call shared with
        ``tests/transceiver/eeprom/test_eeprom_scenario.py``,
      * wait for critical processes and capture a fresh post-operation PID
        baseline (core files are still compared against the pre-op baseline),
      * run Standard Port Recovery and Verification for every port within
        ``settle_attr`` seconds.

    All per-port failures are reported in a single ``pytest.fail``
    """
    ports = sorted(port_attributes_dict.keys())
    settle_sec = _system_attributes(port_attributes_dict)[settle_attr]

    logger.info("Verifying link states for %d port(s) before %s", len(ports), op_name)
    if not check_links_up(duthost, port_attributes_dict)["passed"]:
        pytest.skip(f"Validation on Start FAILED: some ports are down, not running {op_name}")

    # The operation restarts every monitored process; tell the autouse per-test
    # health check to expect it rather than flag it as a regression.
    expected_pid_changes.update(DEFAULT_MONITORED_PROCESSES)
    pre_op = capture_baseline(duthost)

    deadline = time.monotonic() + settle_sec
    logger.info("Performing %s on %s, verifying recovery within %ss",
                op_name, duthost.hostname, settle_sec)
    operation()

    wait_critical_processes(duthost, timeout=max(1, int(deadline - time.monotonic())))
    post_op = capture_baseline(duthost)
    health_baseline = {"pid_baselines": post_op["pid_baselines"], "core_files": pre_op["core_files"]}

    logger.info("Running Standard Port Recovery and Verification for %d port(s)", len(ports))
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=settle_sec,
        health_baseline=health_baseline,
        expected_pid_changes=expected_pid_changes,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
    )

    if result["passed"]:
        logger.info("Post-%s validation PASSED: %s", op_name, result["details"])
        return

    logger.warning("Post-%s validation FAILED: %s", op_name, result["details"])
    failed = [r["details"] for r in result["per_port"].values() if not r["passed"]] or [result["details"]]
    pytest.fail(
        f"{op_name.capitalize()} link recovery FAILED on {len(failed)} port(s):\n  - "
        + "\n  - ".join(failed)
    )


@pytest.mark.disable_memory_utilization
@pytest.mark.disable_loganalyzer
def test_system_config_reload_link_recovery(
    duthost, port_attributes_dict, lport_to_first_subport_mapping, expected_pid_changes,
):
    """Config reload the DUT and verify all transceiver ports recover cleanly."""
    _link_recovery(
        duthost, port_attributes_dict, lport_to_first_subport_mapping, expected_pid_changes,
        "config reload", "config_reload_settle_sec",
        lambda: scenario_ops.perform_config_reload(duthost),
    )


@pytest.mark.disable_memory_utilization
@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("reboot_type", ["cold", "warm", "fast"])
def test_system_reboot_link_recovery(
    duthost, localhost, port_attributes_dict, lport_to_first_subport_mapping, expected_pid_changes,
    reboot_type,
):
    """Cold / warm / fast reboot the DUT and verify all transceiver ports recover cleanly."""
    # Cold reboot is always supported; warm/fast are gated by a platform attr.
    if reboot_type != "cold":
        gate = f"{reboot_type}_reboot_supported"
        if not _system_attributes(port_attributes_dict).get(gate, False):
            pytest.skip(f"{gate} is False - skipping {reboot_type} reboot link recovery test")

    operation = getattr(scenario_ops, f"perform_{reboot_type}_reboot")
    _link_recovery(
        duthost, port_attributes_dict, lport_to_first_subport_mapping, expected_pid_changes,
        f"{reboot_type} reboot", f"{reboot_type}_reboot_settle_sec",
        lambda: operation(duthost, localhost),
    )


@pytest.mark.disable_memory_utilization
@pytest.mark.disable_loganalyzer
def test_system_power_cycle_link_recovery(
    duthost, localhost, pdu_controller, port_attributes_dict,
    lport_to_first_subport_mapping, expected_pid_changes,
):
    """Power cycle the DUT via its PDU and verify all transceiver ports recover cleanly."""
    if not _system_attributes(port_attributes_dict).get("power_cycle_supported", False):
        pytest.skip("power_cycle_supported is False - skipping power cycle link recovery test")
    if not pdu_controller:
        pytest.skip(f"No PDU controller for {duthost.hostname} - skipping power cycle link recovery test")

    _link_recovery(
        duthost, port_attributes_dict, lport_to_first_subport_mapping, expected_pid_changes,
        "power cycle", "power_cycle_settle_sec",
        lambda: scenario_ops.perform_power_cycle(duthost, localhost, pdu_controller),
    )
