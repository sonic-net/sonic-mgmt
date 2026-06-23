"""EEPROM - Transceiver Presence Verification (reportable test cases)."""
import pytest
import logging

from tests.transceiver.common.prerequisites import (
    check_presence_show_cli,
    check_presence_sfputil,
)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Transceiver presence verification via sfputil
# ──────────────────────────────────────────────────────────────────────


def test_transceiver_presence_sfputil(duthost, port_attributes_dict):
    """Verify all transceivers in port_attributes_dict are Present via sfputil.

    Uses ``sfputil show presence`` and validates every expected port.
    """
    result = check_presence_sfputil(duthost, port_attributes_dict)

    if not result["passed"]:
        pytest.fail(result["details"])

    logger.info("Presence check (sfputil) PASSED: %s", result["details"])


# ──────────────────────────────────────────────────────────────────────
# Transceiver presence verification via show CLI
# ──────────────────────────────────────────────────────────────────────


def test_transceiver_presence_show_cli(duthost, port_attributes_dict):
    """Verify all transceivers in port_attributes_dict are Present via show CLI.

    Uses ``show interface transceiver presence`` and validates every
    expected port.
    """
    result = check_presence_show_cli(duthost, port_attributes_dict)

    if not result["passed"]:
        pytest.fail(result["details"])

    logger.info("Presence check (show CLI) PASSED: %s", result["details"])
