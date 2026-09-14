"""Shared transceiver recovery verification.

Helper module (no test cases) owning the ``static EEPROM content + CMIS
active-optical DataPath + firmware versions`` recovery orchestration used after
any disruptive operation.

The three line items recover on different timelines and from different sources,
so they are scored separately rather than as one pass/fail:

  * static content  — ``TRANSCEIVER_INFO``, link-independent, recovers first.
  * DataPath fields — CMIS active-optical only, needs the links back up.
  * firmware        — ``TRANSCEIVER_FIRMWARE_INFO``, republished by xcvrd's DOM
    thread on a slower, delayed cycle, so it gets its own budget.

Consumers:

  * ``eeprom/test_eeprom_scenario.py`` — S2-S7 reboot / config-reload / daemon
    restart / sfputil-reset scenarios.
  * ``oir/test_physical_oir.py`` — post-insertion recovery.
  * firmware upgrade/downgrade tests, which pass ``expected_active`` /
    ``expected_inactive`` because the installed versions deliberately differ
    from the inventory defaults.

This returns failures instead of calling ``pytest.fail`` so callers can fold the
result into their own aggregation and add scenario-specific checks.
"""
import logging
import time

from tests.transceiver.attribute_parser.attribute_keys import DOM_ATTRIBUTES_KEY
from tests.transceiver.eeprom import datapath
from tests.transceiver.eeprom.eeprom_content import (
    verify_eeprom_static_recovered,
    verify_firmware_info_recovered,
)

logger = logging.getLogger(__name__)


def dom_republish_wait(port_attributes_dict, wait_sec, ports=None):
    """Return ``wait_sec`` plus the slowest target port's DOM republish budget.

    ``TRANSCEIVER_DOM_SENSOR`` / ``TRANSCEIVER_FIRMWARE_INFO`` are republished on
    xcvrd's delayed DOM cycle, so anything sourced from them needs the scenario
    settle budget *plus* that cycle.
    """
    target_ports = list(port_attributes_dict) if ports is None else ports
    return wait_sec + max(
        (port_attributes_dict[port].get(DOM_ATTRIBUTES_KEY, {}).get("dom_info_recover_sec", 0)
         for port in target_ports if port in port_attributes_dict),
        default=0,
    )


def _log_item_result(scenario, label, item_failures, elapsed):
    """Log a recovery line item's outcome + timing so a failure names which item
    (static / DataPath / firmware) failed and how long each took."""
    if item_failures:
        logger.info("Transceiver recovery (%s): %s FAILED after %.1fs (%d port(s))",
                    scenario, label, elapsed, len(item_failures))
    else:
        logger.info("Transceiver recovery (%s): %s verified in %.1fs", scenario, label, elapsed)


def verify_transceiver_recovery(
    duthost,
    port_attributes_dict,
    lport_to_first_subport_mapping,
    wait_sec,
    scenario,
    ports=None,
    firmware_wait_sec=None,
    live_i2c_confirm=None,
    enforce_timeout=False,
    expected_active=None,
    expected_inactive=None,
):
    """Verify EEPROM static content + CMIS DataPath + firmware recovered.

    Args:
        wait_sec: settle budget for the static-content and DataPath items;
            ``<= 0`` does a single snapshot check (the steady-state pre-check).
        scenario: human-readable label for the logs and failure blocks, e.g.
            ``"after cold reboot"``.
        ports: optional subset of ``port_attributes_dict`` to verify. ``None``
            verifies every port in the dict.
        firmware_wait_sec: explicit firmware budget. Defaults to ``wait_sec``
            plus the slowest target port's ``dom_info_recover_sec``, since
            firmware rides xcvrd's delayed DOM cycle.
        live_i2c_confirm: run the live-I2C ``sfputil`` confirmation pass after
            the STATE_DB read. Defaults to ``wait_sec > 0`` so the cheap
            pre-check snapshot skips it and the post-op check performs it.
        enforce_timeout: enforce the ``eeprom_dump_timeout_sec`` SLA on the
            confirmation read. Defaults to ``False`` because every current
            caller reloads the driver or re-seats the module, making the first
            I2C read legitimately slow.
        expected_active: optional expected ``Active Firmware`` version,
            overriding the inventory default. For firmware upgrade/downgrade
            tests, whose expectation changes as the test progresses.
        expected_inactive: optional expected ``Inactive Firmware`` version.

    Returns:
        list[str]: one aggregated failure block per failing line item, or ``[]``
        when everything recovered.
    """
    target_ports = list(port_attributes_dict) if ports is None else list(ports)
    if live_i2c_confirm is None:
        live_i2c_confirm = wait_sec > 0
    if firmware_wait_sec is None:
        firmware_wait_sec = dom_republish_wait(port_attributes_dict, wait_sec, target_ports)

    logger.info("Verifying transceiver recovery (%s): static + DataPath + firmware, "
                "wait=%ss firmware_wait=%ss, %d port(s)",
                scenario, wait_sec, firmware_wait_sec, len(target_ports))
    start = time.monotonic()
    failures = []

    # Link-independent static content: recovers first and is the cheapest signal,
    # so a failure here explains any later item failing too.
    item_start = time.monotonic()
    static_failures = verify_eeprom_static_recovered(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        wait_sec,
        ports=target_ports,
        live_i2c_confirm=live_i2c_confirm,
        enforce_timeout=enforce_timeout,
    )
    _log_item_result(scenario, "static content", static_failures, time.monotonic() - item_start)
    if static_failures:
        failures.append("Static EEPROM content:\n  " + "\n  ".join(static_failures))

    # Dynamic DataPath fields (CMIS active-optical only) recover once links are
    # back up; scored separately from the static content, same settle budget.
    item_start = time.monotonic()
    target_attributes = {
        port: port_attributes_dict[port] for port in target_ports if port in port_attributes_dict
    }
    datapath_failures = datapath.verify_datapath_recovered(
        duthost,
        port_attributes_dict,
        wait_sec,
        ports=datapath.cmis_active_optical_ports(target_attributes),
    )
    _log_item_result(scenario, "DataPath fields", datapath_failures, time.monotonic() - item_start)
    if datapath_failures:
        failures.append("DataPath fields:\n  " + "\n  ".join(datapath_failures))

    item_start = time.monotonic()
    firmware_failures = verify_firmware_info_recovered(
        duthost,
        port_attributes_dict,
        firmware_wait_sec,
        ports=target_ports,
        expected_active=expected_active,
        expected_inactive=expected_inactive,
    )
    _log_item_result(scenario, "firmware versions", firmware_failures, time.monotonic() - item_start)
    if firmware_failures:
        failures.append("Firmware versions:\n  " + "\n  ".join(firmware_failures))

    elapsed = time.monotonic() - start
    if failures:
        logger.info("Transceiver recovery (%s) FAILED after %.1fs", scenario, elapsed)
    else:
        logger.info("Transceiver recovery (%s) verified in %.1fs", scenario, elapsed)
    return failures
