import logging
import re
import pytest

from tests.transceiver.utils.cli_parser_helper import parse_eeprom, RC_FAILURE

logger = logging.getLogger(__name__)

CMD_SFP_EEPROM_SFPUTIL = "sudo sfputil show eeprom"


def test_serial_number_pattern_validation_for_breakout_ports(duthost, port_attributes_dict):
    """Validate transceiver serial numbers against breakout deployment regex patterns.

    In a breakout deployment one physical cable is split into multiple logical ports
    (leaf ports) that share a common stem transceiver.  Each leaf or stem port carries
    a serial number whose format identifies which side of the cable it belongs to.

    Attribute lookup (searched in BASE_ATTRIBUTES first, then EEPROM_ATTRIBUTES):
        breakout_serial_number_pattern       — present on leaf ports (e.g. ".*-A$")
        breakout_stem_serial_number_pattern  — present on stem ports

    Per-port logic:
    - If neither attribute is found the port is silently skipped (not a breakout port).
    - If breakout_serial_number_pattern is defined  → leaf port; use that pattern.
    - If breakout_stem_serial_number_pattern only    → stem port; use that pattern.
    - If both are defined                            → leaf pattern takes priority.
    - The serial number is retrieved from 'sudo sfputil show eeprom -p <port>'
      (field 'Vendor SN') and matched with re.fullmatch against the chosen pattern.
    - The retrieved serial number is always logged at INFO level for traceability.

    Test-level skip: if no port in port_attributes_dict carries either attribute, the
    test is skipped (not failed) — the DUT is simply not a breakout deployment.

    Aggregates all failures for final reporting.

    Example patterns:
        Leaf A  : ".*-A$"   — serial number must end with '-A'
        Leaf B  : ".*-B$"   — serial number must end with '-B'
        Stem    : "^IDPA[A-Z]{2}[0-9]{6}[A-Z]?$" or similar — no leaf suffix present
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping serial number pattern validation on virtual switch testbed")

    all_failures = []
    any_port_tested = False   # becomes True when at least one port has a pattern defined

    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        base_attrs = port_attrs.get("BASE_ATTRIBUTES", {})
        eeprom_attrs = port_attrs.get("EEPROM_ATTRIBUTES", {})

        # ------------------------------------------------------------------ #
        # Step 1 – Resolve which breakout pattern applies to this port        #
        # Check BASE_ATTRIBUTES first; fall back to EEPROM_ATTRIBUTES.        #
        # ------------------------------------------------------------------ #
        leaf_pattern = (
            base_attrs.get("breakout_serial_number_pattern")
            or eeprom_attrs.get("breakout_serial_number_pattern")
        )
        stem_pattern = (
            base_attrs.get("breakout_stem_serial_number_pattern")
            or eeprom_attrs.get("breakout_stem_serial_number_pattern")
        )

        if leaf_pattern is None and stem_pattern is None:
            logger.debug(
                "Port %s: no breakout serial number pattern defined, skipping", port
            )
            continue

        any_port_tested = True

        # Leaf pattern takes priority when both happen to be defined
        if leaf_pattern is not None:
            pattern = leaf_pattern
            port_role = "leaf"
        else:
            pattern = stem_pattern
            port_role = "stem"

        logger.debug(
            "Port %s: %s port — expected serial number regex: '%s'",
            port, port_role, pattern,
        )

        # ------------------------------------------------------------------ #
        # Step 2 – Retrieve the serial number via sfputil show eeprom         #
        # ------------------------------------------------------------------ #
        cmd = f"{CMD_SFP_EEPROM_SFPUTIL} -p {port}"
        result = duthost.command(cmd, module_ignore_errors=True)
        if result.get('rc', RC_FAILURE) != 0:
            all_failures.append(
                f"{port}: sfputil show eeprom failed with rc={result.get('rc')}, "
                f"stderr: {result.get('stderr', '')}"
            )
            continue

        stdout_lines = result.get('stdout_lines', [])
        if not stdout_lines:
            all_failures.append(f"{port}: sfputil show eeprom returned empty output")
            continue

        port_eeprom = parse_eeprom(stdout_lines)
        port_fields = port_eeprom.get(port, {})
        if not port_fields:
            all_failures.append(
                f"{port}: transceiver not detected in sfputil show eeprom output"
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
            "No ports with breakout_serial_number_pattern or "
            "breakout_stem_serial_number_pattern found; "
            "skipping serial number pattern validation"
        )

    if all_failures:
        pytest.fail(
            "Serial number pattern validation failures:\n" + "\n".join(all_failures)
        )
