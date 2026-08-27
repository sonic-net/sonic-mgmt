"""System / System Recovery - cold/warm/fast reboot link recovery validations.

Implements the "cold/warm/fast reboot link recovery" test case from
    ``docs/testplan/transceiver/system_test_plan.md``
    (System Recovery Test Cases).

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every System test)
    `- test_system_cold_warm_fast_reboot_link_recovery
         |- skip if {reboot_type}_reboot_supported is False
         |- run_pre_check  (health OK)         <- _per_test_health_check
         |- <body>: verify links up -> reboot (scenario_ops) -> Standard Port
            Recovery and Verification
         `- run_post_check
  session end
    `- _system_post_session_checks (system/conftest.py)
         |- post_state_restoration()
         |- STATE_DB consistency check
         `- final link + LLDP check

Failure handling: failures are accumulated per test case and reported in a single
pytest.fail at the end, so a single run surfaces all issues across all ports.
"""
import logging

import pytest

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


def _reboot_link_recovery(
    reboot_type, duthost, localhost, port_attributes_dict,
    lport_to_first_subport_mapping, expected_pid_changes,
):
    """Reboot the DUT (cold/warm/fast) and verify all transceiver ports recover cleanly.

    See the module docstring for the full execution tree.  Steps:

      * for warm/fast reboot, skip if ``{reboot_type}_reboot_supported`` is False,
      * verify all ports are oper-up before the reboot,
      * reboot the DUT via the matching ``scenario_ops.perform_{reboot_type}_reboot``
        (shared with ``tests/transceiver/eeprom/test_eeprom_scenario.py``),
      * run Standard Port Recovery and Verification for every port against a
        fresh post-reboot health baseline.

    All (port, step) failures are accumulated and reported in a single
    ``pytest.fail`` so one run surfaces every issue.
    """
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    system_attributes = port_attributes_dict[ports[0]].get(
        SYSTEM_ATTRIBUTES_KEY, {}
    )

    if reboot_type != "cold":
        gate = f"{reboot_type}_reboot_supported"
        if not system_attributes.get(gate, False):
            pytest.skip(f"{gate} is False - skipping {reboot_type} reboot link recovery test")

    # A reboot restarts every monitored process; tell the autouse per-test
    # health check to expect it rather than flag it as a regression.
    expected_pid_changes.update(DEFAULT_MONITORED_PROCESSES)

    default_wait = 400 if reboot_type == 'cold' else 300
    reboot_wait = system_attributes.get(f"{reboot_type}_reboot_settle_sec", default_wait)

    logger.info("Verifying link states for %d port(s) before reboot", len(ports))
    if not check_links_up(duthost, port_attributes_dict)["passed"]:
        logger.warning("Validation on Start FAILED: some ports are down")

    logger.info("%s rebooting %s, verifying recovery within %ss",
                reboot_type.capitalize(), duthost.hostname, reboot_wait)
    operation = getattr(scenario_ops, f"perform_{reboot_type}_reboot")
    operation(duthost, localhost)

    # PID/log baselines are invalidated by the reboot (system_test_plan.md);
    # capture a fresh post-reboot baseline for the health step below.
    health_baseline = capture_baseline(duthost)

    logger.info("Running Standard Port Recovery and Verification for %d port(s)", len(ports))
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=reboot_wait,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )

    failures = []  # collected across every (port, step) tuple
    if not result["passed"]:
        failures.append(f"[post-reboot] {result['details']}")
        logger.warning("Post-reboot validation FAILED: %s", result["details"])
    else:
        logger.info("Post-reboot validation PASSED: %s", result["details"])

    if failures:
        pytest.fail(
            f"{reboot_type.capitalize()} reboot link recovery FAILED on {len(failures)} port(s):\n  - "
            + "\n  - ".join(failures)
        )


@pytest.mark.disable_loganalyzer
def test_system_cold_reboot_link_recovery(
    duthost, localhost, port_attributes_dict, lport_to_first_subport_mapping, expected_pid_changes,
):
    """Cold reboot the DUT and verify all transceiver ports recover cleanly."""
    _reboot_link_recovery(
        'cold', duthost, localhost, port_attributes_dict,
        lport_to_first_subport_mapping, expected_pid_changes,
    )


@pytest.mark.disable_loganalyzer
def test_system_warm_reboot_link_recovery(
    duthost, localhost, port_attributes_dict, lport_to_first_subport_mapping, expected_pid_changes,
):
    """Warm reboot the DUT and verify all transceiver ports recover cleanly."""
    _reboot_link_recovery(
        'warm', duthost, localhost, port_attributes_dict,
        lport_to_first_subport_mapping, expected_pid_changes,
    )


@pytest.mark.disable_loganalyzer
def test_system_fast_reboot_link_recovery(
    duthost, localhost, port_attributes_dict, lport_to_first_subport_mapping, expected_pid_changes,
):
    """Fast reboot the DUT and verify all transceiver ports recover cleanly."""
    _reboot_link_recovery(
        'fast', duthost, localhost, port_attributes_dict,
        lport_to_first_subport_mapping, expected_pid_changes,
    )
