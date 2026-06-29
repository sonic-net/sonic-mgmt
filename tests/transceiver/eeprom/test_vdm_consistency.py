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
from tests.transceiver.common.eeprom_decode import ModuleFamily, classify

logger = logging.getLogger(__name__)

# STATE_DB table / field that publishes the xcvrd-parsed VDM capability flag.
STATE_DB_TRANSCEIVER_INFO = "TRANSCEIVER_INFO"
VDM_SUPPORTED_FIELD = "vdm_supported"


def test_vdm_supported_consistency(duthost, port_attributes_dict):
    """Verify STATE_DB ``vdm_supported`` matches the configured attribute per port.

    ``vdm_supported`` is a CMIS-only field — xcvrd publishes it into STATE_DB for
    CMIS optics only — so the contract is enforced symmetrically by family
    (resolved via the shared ``eeprom_decode.classify``):

    * non-CMIS optic: ``vdm_supported`` must be ABSENT from STATE_DB; if xcvrd
      published it anyway, that is an xcvrd/module regression and is flagged.
      The inventory value (if any) is not validated.
    * CMIS optic: ``vdm_supported`` is MANDATORY in inventory (missing / ``null``
      is a failure), must be present in STATE_DB, and the two must match.

    The STATE_DB ``TRANSCEIVER_INFO`` table is read once for all ports via a
    single ``sonic-db-dump``.

    This test intentionally iterates ALL logical ports (no first-sub-port
    filtering), unlike the per-physical EEPROM reads in ``test_hexdump.py`` and
    ``cmis/test_cdb_background_mode.py`` that filter via ``is_first_subport``:
    STATE_DB ``TRANSCEIVER_INFO`` is populated per-logical-port, so each sub-port
    has its own ``vdm_supported`` entry that must be verified individually.

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
        state_db_entry = transceiver_info.get(port, {})

        # vdm_supported is a CMIS-only field: xcvrd publishes it for CMIS optics
        # only.  CMIS family is resolved via the shared ``eeprom_decode.classify``
        # so this stays in sync with the rest of the suite.  For non-CMIS optics,
        # assert the field is ABSENT from STATE_DB (a non-CMIS optic carrying it
        # is an xcvrd/module regression) and skip the value check.
        if classify(eeprom_attrs) is not ModuleFamily.CMIS:
            if VDM_SUPPORTED_FIELD in state_db_entry:
                all_failures.append(
                    f"{port}: non-CMIS optic unexpectedly has "
                    f"'{VDM_SUPPORTED_FIELD}' in STATE_DB "
                    f"{STATE_DB_TRANSCEIVER_INFO}|{port}"
                )
            else:
                logger.debug("Port %s is non-CMIS, skipping VDM check", port)
            continue

        # CMIS optic: vdm_supported is mandatory in inventory.
        expected_value = eeprom_attrs.get("vdm_supported")
        if expected_value is None:
            all_failures.append(
                f"{port}: CMIS optic has no 'vdm_supported' configured in "
                f"inventory; it is mandatory for all CMIS optics"
            )
            continue

        # ... and xcvrd must publish it in STATE_DB.
        raw_value = state_db_entry.get(VDM_SUPPORTED_FIELD)
        if raw_value is None:
            all_failures.append(
                f"{port}: CMIS optic has no '{VDM_SUPPORTED_FIELD}' field in "
                f"STATE_DB {STATE_DB_TRANSCEIVER_INFO}|{port}"
            )
            continue

        actual_value = db_helpers.parse_state_db_bool(raw_value)
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
