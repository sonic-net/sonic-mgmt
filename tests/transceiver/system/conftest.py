"""System category conftest.

Opts the System test category into the cross-category session-level
prerequisites defined in ``tests/transceiver/conftest.py`` and runs the
post-session checks called out in
``docs/testplan/transceiver/system_test_plan.md``.

Per the prerequisite matrix in ``docs/testplan/transceiver/test_plan.md``,
System consumes all three gates: ``presence_verified``,
``gold_fw_verified``, and ``links_verified``. Requesting them here means
the gates fire once per session before any System test runs, and on
failure every System test is skipped with a clear reason.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import DOM_ATTRIBUTES_KEY, SYSTEM_ATTRIBUTES_KEY
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.port_selectors import select_attribute_ports
from tests.transceiver.common.prerequisites import check_links_up
from tests.transceiver.common.state_management import post_state_restoration
from tests.transceiver.common.verification import check_lldp_neighbors_present
from tests.transceiver.dom.dom_helpers import (
    build_dom_sensor_plan,
    dom_field_available,
    read_dom_sensor_data,
    validate_dom_plan_fields,
)
from tests.transceiver.eeprom.eeprom_content import verify_eeprom_static_recovered

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True, scope="session")
def _system_session_prerequisites(presence_verified, gold_fw_verified, links_verified):
    """Autouse wrapper that pulls in every session-scoped prerequisite gate
    consumed by System tests.

    All three gates are session-scoped fixtures defined in
    ``tests/transceiver/conftest.py``; each one calls ``pytest.skip(...)``
    on failure so every System test is skipped with a clear reason.
    """
    return


# ──────────────────────────────────────────────────────────────────────
# Post-Session Checks (system_test_plan.md).
#
# After the full System suite has run we do, in order:
#   0. State Restoration      - run post_state_restoration() to put the
#                               testbed back into a known-good state
#                               (admin-up + high power mode, with one batched
#                               bounce attempt for remaining down links)
#                               before we verify anything below.
#   1. STATE_DB consistency   - TRANSCEIVER_INFO exists for every modeled port;
#                               TRANSCEIVER_DOM_SENSOR exists for every
#                               DOM-capable primary subport.
#   2. End-to-end link + LLDP - every port back oper-up and (if enabled)
#                               its LLDP neighbor rediscovered after the
#                               disruptive test sequence.
#
# Failures are reported as warnings instead of fixture errors so they
# don't mask the actual test results that are already on the report.
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True, scope="session")
def _system_post_session_checks(
    duthost,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Run the Post-Session State Restoration + Checks from
    system_test_plan.md at session teardown.

    Order matters: restoration runs FIRST so the STATE_DB / link / LLDP
    checks that follow observe the restored steady state, not whatever
    transient mid-failure state the suite happened to end in.
    """
    yield

    if not port_attributes_dict:
        return

    logger.info("System suite: running post-session state restoration on %d port(s)",
                len(port_attributes_dict))

    # 0. State Restoration - admin-up, high power mode, and link recovery.
    try:
        restoration_summary = post_state_restoration(duthost, port_attributes_dict)
    except Exception as e:
        # Defensive: this should never throw, but if it does we don't
        # want to mask the actual test results.
        logger.warning("post_state_restoration raised unexpectedly: %s", e)
        restoration_summary = None

    if restoration_summary:
        actions_taken = (
            restoration_summary["admin_up_restored"]
            or restoration_summary["lpmode_high_restored"]
            or restoration_summary["link_bounced"]
        )
        if actions_taken:
            logger.warning(
                "Post-session restoration actions taken: "
                "startup=%s lpmode_off=%s link_bounced=%s",
                restoration_summary["admin_up_restored"],
                restoration_summary["lpmode_high_restored"],
                restoration_summary["link_bounced"],
            )
        if restoration_summary["still_failing"]:
            logger.warning(
                "Post-session restoration failures:\n%s",
                "\n".join(restoration_summary["still_failing"]),
            )
    logger.info("System suite: running post-session consistency checks on %d port(s)",
                len(port_attributes_dict))

    # 1. STATE_DB consistency.
    eeprom_failures = verify_eeprom_static_recovered(
        duthost,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        wait_sec=0,
        live_i2c_confirm=False,
    )
    expected_dom_ports = select_attribute_ports(
        port_attributes_dict,
        DOM_ATTRIBUTES_KEY,
        lport_to_first_subport_mapping,
    ).primary_ports
    sensor_plan_by_port = build_dom_sensor_plan(
        port_attributes_dict,
        expected_dom_ports,
        lport_to_first_subport_mapping,
    )

    def _check_dom_consistency():
        sensor_by_port, sensor_read_errors = read_dom_sensor_data(
            duthost, expected_dom_ports
        )
        failures, _, _ = validate_dom_plan_fields(
            duthost,
            expected_dom_ports,
            sensor_by_port,
            sensor_plan_by_port,
            dom_field_available,
            include_freshness_only=True,
        )
        return [
            "STATE_DB read: {}".format(error) for error in sensor_read_errors
        ] + failures

    dom_recovery_wait = max(
        (
            port_attributes_dict[port][DOM_ATTRIBUTES_KEY]["dom_info_recover_sec"]
            for port in expected_dom_ports
        ),
        default=0,
    )
    dom_failures = scenario_ops.poll_ports_recovered(
        _check_dom_consistency,
        dom_recovery_wait,
        interval_sec=5,
        label="Post-session DOM",
    )
    if eeprom_failures:
        logger.warning(
            "Post-session EEPROM consistency check FAILED:\n%s",
            "\n".join(eeprom_failures),
        )
    if dom_failures:
        logger.warning(
            "Post-session DOM consistency check FAILED:\n%s",
            "\n".join(dom_failures),
        )
    if not eeprom_failures and not dom_failures:
        logger.info("Post-session: STATE_DB consistency check PASSED")

    # 2. Final link + LLDP.
    link_result = check_links_up(duthost, port_attributes_dict)
    if not link_result["passed"]:
        logger.warning("Post-session link check FAILED: %s", link_result["details"])
    else:
        logger.info("Post-session link check PASSED: %s", link_result["details"])

    # short poll budget here - LLDP should already be settled by now
    lldp_port_timeouts = {
        port: 30
        for port, attrs in port_attributes_dict.items()
        if attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get(
            "verify_lldp_on_link_up", True
        )
    }
    lldp_results = check_lldp_neighbors_present(duthost, lldp_port_timeouts)
    lldp_failed = [port for port, r in lldp_results.items() if not r["passed"]]
    if lldp_failed:
        logger.warning(
            "Post-session LLDP check FAILED for: %s", ", ".join(lldp_failed)
        )
    else:
        logger.info("Post-session LLDP check PASSED")
