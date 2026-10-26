"""EEPROM category conftest.

Opts the EEPROM test category into the cross-category session-level
prerequisites defined in ``tests/transceiver/conftest.py``.

Per the prerequisite matrix in ``docs/testplan/transceiver/test_plan.md``,
EEPROM consumes only the ``links_verified`` gate. ``presence_verified``
is intentionally NOT requested because EEPROM owns its own reportable
presence test cases, and ``gold_fw_verified`` is intentionally NOT
requested because EEPROM reads are firmware-version-independent (a
gold-FW mismatch should not skip EEPROM tests session-wide).
"""

import pytest


@pytest.fixture(autouse=True, scope="session")
def _eeprom_session_prerequisites(links_verified):
    """Autouse wrapper that pulls in the session-scoped prerequisite gates
    consumed by EEPROM tests.

    Requesting ``links_verified`` ensures the gate runs once per session
    before any EEPROM test executes; on failure the gate calls
    ``pytest.skip(...)`` and every EEPROM test is skipped with a clear
    reason.
    """
    return
