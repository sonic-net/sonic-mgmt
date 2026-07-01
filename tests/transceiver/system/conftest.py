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

from tests.transceiver.attribute_parser.attribute_keys import SYSTEM_ATTRIBUTES_KEY
from tests.transceiver.common.prerequisites import check_links_up
from tests.transceiver.common.state_management import post_state_restoration
from tests.transceiver.common.verification import _check_lldp_neighbor_present

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
#                               (admin-up + high power mode + DPActivated)
#                               before we verify anything below.
#   1. STATE_DB consistency   - TRANSCEIVER_INFO and TRANSCEIVER_DOM_SENSOR
#                               entries exist for every port in
#                               port_attributes_dict.
#   2. End-to-end link + LLDP - every port back oper-up and (if enabled)
#                               its LLDP neighbor rediscovered after the
#                               disruptive test sequence.
#
# Failures are reported as warnings instead of fixture errors so they
# don't mask the actual test results that are already on the report.
# ──────────────────────────────────────────────────────────────────────


def _state_db_key_exists(duthost, key):
    cmd = f'sonic-db-cli STATE_DB hgetall "{key}"'
    out = duthost.shell(cmd, module_ignore_errors=True)
    if out.get("rc", 1) != 0:
        return False
    return bool((out.get("stdout") or "").strip())


@pytest.fixture(autouse=True, scope="session")
def _system_post_session_checks(duthost, port_attributes_dict):
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

    # 0. State Restoration  - admin-up, high power mode, DPActivated.
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
            or restoration_summary["datapath_recycled"]
        )
        if actions_taken:
            logger.warning(
                "Post-session restoration actions taken: "
                "startup=%s lpmode_off=%s transceivers_recycled=%s",
                restoration_summary["admin_up_restored"],
                restoration_summary["lpmode_high_restored"],
                restoration_summary["datapath_recycled"],
            )
        if restoration_summary["still_failing"]:
            logger.warning(
                "Post-session restoration: %d port(s) did NOT recover: %s",
                len(restoration_summary["still_failing"]),
                "; ".join(restoration_summary["still_failing"]),
            )

    logger.info("System suite: running post-session consistency checks on %d port(s)",
                len(port_attributes_dict))

    # 1. STATE_DB consistency.
    missing_info = []
    missing_dom = []
    for port in sorted(port_attributes_dict.keys()):
        if not _state_db_key_exists(duthost, f"TRANSCEIVER_INFO|{port}"):
            missing_info.append(port)
        if not _state_db_key_exists(duthost, f"TRANSCEIVER_DOM_SENSOR|{port}"):
            missing_dom.append(port)
    if missing_info:
        logger.warning("Post-session: TRANSCEIVER_INFO missing in STATE_DB for: %s",
                       ", ".join(missing_info))
    if missing_dom:
        logger.warning("Post-session: TRANSCEIVER_DOM_SENSOR missing in STATE_DB for: %s",
                       ", ".join(missing_dom))
    if not missing_info and not missing_dom:
        logger.info("Post-session: STATE_DB consistency check PASSED")

    # 2. Final link + LLDP.
    link_result = check_links_up(duthost, port_attributes_dict)
    if not link_result["passed"]:
        logger.warning("Post-session link check FAILED: %s", link_result["details"])
    else:
        logger.info("Post-session link check PASSED: %s", link_result["details"])

    lldp_failed = []
    for port, attrs in port_attributes_dict.items():
        sys_attrs = attrs.get(SYSTEM_ATTRIBUTES_KEY, {})
        if not sys_attrs.get("verify_lldp_on_link_up", True):
            continue
        # short poll budget here - LLDP should already be settled by now
        r = _check_lldp_neighbor_present(duthost, port, timeout_sec=30)
        if not r["passed"]:
            lldp_failed.append(port)
    if lldp_failed:
        logger.warning("Post-session LLDP check FAILED for: %s", ", ".join(lldp_failed))
    else:
        logger.info("Post-session LLDP check PASSED")
