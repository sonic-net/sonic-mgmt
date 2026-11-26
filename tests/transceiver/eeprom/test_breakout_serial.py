import logging
import re
from collections import Counter

import pytest

from tests.transceiver.attribute_parser.attribute_keys import EEPROM_ATTRIBUTES_KEY
from tests.transceiver.common import cli_helpers
from tests.common.platform.interface_utils import is_first_subport

logger = logging.getLogger(__name__)


def test_serial_number_pattern_validation_for_breakout_ports(
    duthost, port_attributes_dict, lport_to_first_subport_mapping
):
    """Validate transceiver serial numbers against breakout deployment regex patterns.

    Breakout model (e.g. a 2x100G breakout cable): the *stem* is the aggregated
    end that occupies ONE physical cage and is split into multiple logical
    sub-ports, while each *leaf* is a separate physical cage carrying a single
    logical port.  The serial number is a property of each physical connector —
    one stem EEPROM plus one EEPROM per leaf.

    Iteration is per physical connector (first sub-port), not per logical port:
    the stem's logical sub-ports all read the SAME stem EEPROM, so validating
    every sub-port would re-issue a redundant ``sfputil show eeprom`` per extra
    stem sub-port for an identical serial.  Filtering to the first sub-port of
    each breakout group (``is_first_subport``) checks the stem once and each
    single-port leaf once — every connector validated exactly once.

    Stem vs leaf is a TOPOLOGY property, derived from the same first-sub-port
    mapping rather than from which attribute happens to be present: a connector
    whose breakout group has >1 logical sub-port is the stem; a single-sub-port
    connector that still carries breakout attributes is a leaf.  (This assumes a
    leaf is always a single logical port, which is the deployment model here.)

    Attribute lookup (EEPROM_ATTRIBUTES only — both patterns live under
    ``transceivers`` per the plan's attribute table):
        breakout_leaf_serial_number_pattern       — leaf serial pattern (e.g. ".*-A$")
        breakout_stem_serial_number_pattern  — stem serial pattern

    Both patterns being present on a port is the NORMAL shared-Vendor-PN case
    (eeprom.json is sharded per-PN, so when the stem and leaf ends share a PN,
    both patterns land on every port of the cable).  The role decides which one
    applies — there is no ambiguity to flag.

    Per-connector logic:
    - Resolve the role from topology, then select the matching pattern
      (stem → breakout_stem_serial_number_pattern, leaf →
      breakout_leaf_serial_number_pattern).
    - If the role's pattern is not defined, the connector is skipped (not a
      breakout port of that role).
    - The serial number is retrieved from 'sfputil show eeprom -p <port>'
      (field 'Vendor SN') and matched with re.fullmatch against the pattern.
    - The retrieved serial number is always logged at INFO level for traceability.

    Test-level skip: if no connector carries the pattern for its role, the test
    is skipped (not failed) — the DUT is simply not a breakout deployment.

    Example patterns:
        Leaf A  : ".*-A$"   — serial number must end with '-A'
        Leaf B  : ".*-B$"   — serial number must end with '-B'
        Stem    : "^IDPA[A-Z]{2}[0-9]{6}[A-Z]?$" or similar — no leaf suffix present
    """
    all_failures = []
    any_port_tested = False   # becomes True when at least one connector is validated

    # Sub-ports per physical connector: count how many logical ports map to each
    # first sub-port.  A first sub-port whose group size is >1 is a stem; a
    # group size of 1 is a (single-port) leaf.
    subport_counts = Counter(lport_to_first_subport_mapping.values())

    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        # One validation per physical connector: skip the stem's non-first
        # sub-ports (they read the identical stem EEPROM); each leaf is its own
        # first sub-port.
        if not is_first_subport(port, lport_to_first_subport_mapping):
            logger.debug("Port %s is not the first breakout sub-port, skipping", port)
            continue

        eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})

        # Step 1 - Resolve the role from topology, then pick the matching pattern.
        # Both breakout_leaf_serial_number_pattern (leaf) and
        # breakout_stem_serial_number_pattern (stem) live under EEPROM_ATTRIBUTES
        # per the plan's attribute table, so look there only.
        leaf_pattern = eeprom_attrs.get("breakout_leaf_serial_number_pattern")
        stem_pattern = eeprom_attrs.get("breakout_stem_serial_number_pattern")

        if subport_counts.get(port, 1) > 1:
            port_role = "stem"
            pattern = stem_pattern
        else:
            port_role = "leaf"
            pattern = leaf_pattern

        if pattern is None:
            logger.debug(
                "Port %s: no %s breakout serial number pattern defined, skipping",
                port, port_role,
            )
            continue

        any_port_tested = True

        logger.debug(
            "Port %s: %s port — expected serial number regex: '%s'",
            port, port_role, pattern,
        )

        # ------------------------------------------------------------------ #
        # Step 2 – Retrieve the serial number via sfputil show eeprom         #
        # ------------------------------------------------------------------ #
        port_eeprom, err = cli_helpers.sfputil_show_eeprom(duthost, port=port)
        if err:
            all_failures.append(f"{port}: {err}")
            continue

        port_fields = port_eeprom.get(port, {})
        if not port_fields:
            all_failures.append(
                f"{port}: no transceiver detected in sfputil show eeprom output"
            )
            continue

        vendor_sn = port_fields.get("Vendor SN")
        if vendor_sn is None:
            all_failures.append(
                f"{port}: 'Vendor SN' field missing in sfputil show eeprom output"
            )
            continue

        # Step 2b – Log the retrieved serial number for debugging traceability
        logger.info(
            "Port %s (%s port): retrieved serial number: '%s'", port, port_role, vendor_sn
        )

        # ------------------------------------------------------------------ #
        # Step 3 – Validate serial number against the expected regex pattern  #
        # ------------------------------------------------------------------ #
        try:
            match = re.fullmatch(pattern, vendor_sn)
        except re.error as exc:
            all_failures.append(
                f"{port}: invalid regex pattern '{pattern}' "
                f"(from {port_role} breakout attribute): {exc}"
            )
            continue

        if not match:
            all_failures.append(
                f"{port}: serial number pattern mismatch ({port_role} port): "
                f"serial number '{vendor_sn}' does not match pattern '{pattern}'"
            )
        else:
            logger.debug(
                "Port %s: serial number '%s' matches %s pattern '%s'",
                port, vendor_sn, port_role, pattern,
            )

    # ------------------------------------------------------------------ #
    # Test-level skip when the DUT has no breakout ports at all           #
    # ------------------------------------------------------------------ #
    if not any_port_tested:
        pytest.skip(
            "No ports with breakout_leaf_serial_number_pattern or "
            "breakout_stem_serial_number_pattern found; "
            "skipping serial number pattern validation"
        )

    if all_failures:
        pytest.fail(
            "Serial number pattern validation failures:\n" + "\n".join(all_failures)
        )
