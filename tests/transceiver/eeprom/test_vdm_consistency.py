"""VDM (Versatile Diagnostics Monitoring) capability consistency test.

Validates that the ``vdm_supported`` capability flag published by xcvrd into
STATE_DB matches the configured expectation in
``ansible/files/transceiver/inventory/attributes/eeprom.json``. A mismatch
indicates either:

  * a misconfigured / stale inventory attribute, or
  * a transceiver that is misreporting its VDM capability via its EEPROM
    (i.e. xcvrd parsed the EEPROM correctly but the module itself is wrong).

The expected value lives in ``EEPROM_ATTRIBUTES.vdm_supported`` (merged from
``defaults``/``deployment_configurations`` in eeprom.json). The runtime value
is read from STATE_DB key ``TRANSCEIVER_INFO|<port>`` field ``vdm_supported``.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import EEPROM_ATTRIBUTES_KEY
from tests.transceiver.common import db_helpers

logger = logging.getLogger(__name__)

# STATE_DB table / field that publishes the xcvrd-parsed VDM capability flag.
STATE_DB_TRANSCEIVER_INFO = "TRANSCEIVER_INFO"
VDM_SUPPORTED_FIELD = "vdm_supported"


def _parse_state_db_bool(value):
    """Parse a STATE_DB string into a Python bool.

    xcvrd writes Python bools into Redis as the strings ``"True"`` / ``"False"``
    (Redis stores everything as strings). We accept the numeric forms ``"1"`` /
    ``"0"`` as well to be robust against future xcvrd changes. Returns ``None``
    for any unrecognized value so the caller can flag it as a parse failure
    rather than silently treating it as ``False``.
    """
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in ("true", "1"):
        return True
    if normalized in ("false", "0"):
        return False
    return None


def test_vdm_supported_consistency(duthost, port_attributes_dict):
    """Verify STATE_DB ``vdm_supported`` matches the configured attribute per port.

    For every port that has ``EEPROM_ATTRIBUTES.vdm_supported`` configured:

    1. Read the expected value from ``port_attributes_dict``.
    2. Look up ``vdm_supported`` for the port in the STATE_DB ``TRANSCEIVER_INFO``
       table, which is read once for all ports via a single ``sonic-db-dump``.
    3. Compare; aggregate any mismatch (or missing/malformed STATE_DB value).

    This test intentionally iterates ALL logical ports (no first-sub-port
    filtering), unlike the per-physical EEPROM reads in ``test_hexdump.py`` and
    ``cmis/test_cdb_background_mode.py`` that filter via ``is_first_subport``:
    STATE_DB ``TRANSCEIVER_INFO`` is populated per-logical-port, so each sub-port
    has its own ``vdm_supported`` entry that must be verified individually.

    Ports without a configured ``vdm_supported`` attribute are skipped (treated
    as "no expectation"); this is the documented behavior in the task spec.

    A non-CMIS port (``cmis_revision`` unset) that nonetheless carries a
    ``vdm_supported`` attribute is flagged as an inventory misconfiguration —
    VDM is CMIS-only and the attribute must not be present for such modules.

    All failures are collected and reported at the end so a single run surfaces
    every offending port instead of stopping at the first one.
    """
    all_failures = []

    # Read the whole TRANSCEIVER_INFO table once (a single sonic-db-dump) and
    # look up each port below, instead of issuing one hget per logical port.
    transceiver_info, err = db_helpers.get_state_db_table(
        duthost, STATE_DB_TRANSCEIVER_INFO
    )
    if err:
        pytest.fail(f"Could not read STATE_DB {STATE_DB_TRANSCEIVER_INFO}: {err}")

    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})

        # VDM is a CMIS-only construct. Per the plan attribute table, non-CMIS
        # transceivers must not carry vdm_supported at all; its presence on a
        # non-CMIS port (cmis_revision unset) is an inventory misconfiguration,
        # so flag it rather than silently honoring it.  Key presence is checked
        # (not just a non-None value) so an explicit ``vdm_supported: null`` on
        # a non-CMIS port is caught too.
        if eeprom_attrs.get("cmis_revision") is None and "vdm_supported" in eeprom_attrs:
            all_failures.append(
                f"{port}: 'vdm_supported' is set on a non-CMIS transceiver "
                f"(cmis_revision unset); VDM is CMIS-only and this attribute must "
                f"not be present for non-CMIS modules"
            )
            continue

        expected_value = eeprom_attrs.get("vdm_supported")
        if expected_value is None:
            logger.debug("Port %s has no vdm_supported attribute, skipping", port)
            continue

        raw_value = transceiver_info.get(port, {}).get(VDM_SUPPORTED_FIELD)
        if raw_value is None:
            # Field (or the whole TRANSCEIVER_INFO|<port> entry) absent; itself a
            # failure per Expected Result #1.
            all_failures.append(
                f"{port}: STATE_DB {STATE_DB_TRANSCEIVER_INFO}|{port} has no "
                f"'{VDM_SUPPORTED_FIELD}' field"
            )
            continue

        actual_value = _parse_state_db_bool(raw_value)
        if actual_value is None:
            all_failures.append(
                f"{port}: STATE_DB vdm_supported has unrecognized value '{raw_value}' "
                f"(expected 'True'/'False')"
            )
            continue

        if actual_value != expected_value:
            all_failures.append(
                f"{port}: vdm_supported mismatch — "
                f"configured={expected_value}, STATE_DB={actual_value}"
            )
        else:
            logger.debug("Port %s vdm_supported=%s matches STATE_DB", port, expected_value)

    if all_failures:
        pytest.fail(
            "VDM consistency verification failures:\n  " + "\n  ".join(all_failures)
        )
