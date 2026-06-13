import logging
import pytest

from tests.common.platform.interface_utils import get_lport_to_first_subport_mapping
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers
from tests.transceiver.utils.cmis_helper import (
    extract_ascii_field,
    check_dp_state_activated,
    CMIS_VENDOR_NAME_START,
    CMIS_VENDOR_PN_START,
)

logger = logging.getLogger(__name__)


# SFF-8024 identifier value sets (decimal) used to dispatch test case per-family
# command shape. Sourced from SFF-8024 Table 4-1.
#
# 0x0B is intentionally NOT in the SFF-8472 set: per SFF-8024 Table 4-1 it is
# defined as "DWDM-SFP/SFP+ (not using SFF-8472)", so the A0h/A2h SFF-8472
# access path below does not apply. A 0x0B module falls through to the
# out-of-scope branch and is skipped rather than probed with an interface it
# does not implement.
SFF8024_IDENT_SFF8472 = {0x03}                       # SFP / SFP+ / SFP28 (A0h/A2h)
SFF8024_IDENT_QSFP_NON_CMIS = {0x0C, 0x0D, 0x11}     # QSFP / QSFP+ / QSFP28 (paged)

# Vendor name / part-number field offsets for the non-CMIS families (CMIS
# offsets are imported from cmis_helper). All three families use 16-byte
# space-padded ASCII fields.
#   SFF-8636 (QSFP/QSFP+/QSFP28): page-0 upper page, absolute byte addresses.
#   SFF-8472 (SFP/SFP+/SFP28):    A0h flat memory, byte offsets.
SFF8636_VENDOR_NAME_START = 148   # bytes 148-163
SFF8636_VENDOR_PN_START = 168     # bytes 168-183
SFF8472_VENDOR_NAME_START = 20    # A0h bytes 20-35
SFF8472_VENDOR_PN_START = 40      # A0h bytes 40-55
SFF8472_VENDOR_SPAN = 36          # one A0h read covers vendor name (20-35) + PN (40-55)
VENDOR_FIELD_LEN = 16


def _check_vendor_field(label, expected, page_data, start, length, loc):
    """Return a 0- or 1-element list of failure strings for one ASCII vendor field.

    *expected* of None means the inventory does not pin this field, so it is not
    checked.  *loc* is a short address-space label (e.g. 'page 0h', 'A0h') used
    only in the failure message.
    """
    if expected is None:
        return []
    actual = extract_ascii_field(page_data, start, length)
    if actual is None:
        return [f"{label} bytes incomplete at {loc} byte {start} (0x{start:02X})"]
    if actual != expected:
        return [f"{label}: expected '{expected}', got '{actual}'"]
    return []


def _read_page0_upper(duthost, port):
    """Read 'sfputil show eeprom-hexdump -n 0' → (upper_page_0_bytemap, err).

    Returns ({}, err) if the command failed, ({}, None) if the upper-page-0
    section was absent, or (byte_map, None) on success.
    """
    page0, err = cli_helpers.sfputil_show_eeprom_hexdump(duthost, port, page=0)
    if err:
        return {}, err
    return page0.get("upper_page_0", {}), None


def test_eeprom_hexdump_verification_via_sfputil(duthost, port_attributes_dict):
    """Verify EEPROM hexdump content via 'sfputil show eeprom-hexdump'.

    Stem-port detection (which logical port owns the physical transceiver in a
    breakout group) comes from the standard
    ``tests.common.platform.interface_utils.get_lport_to_first_subport_mapping``
    helper — a port is the stem iff it maps to itself.  Works for 1-, 2-, 4-,
    and 8-lane breakouts without per-platform modulus hacks.

    Per-port host lane count comes from
    ``BASE_ATTRIBUTES.host_lane_count`` (pre-computed by ``config_parser`` from
    the ``transceiver_configuration`` field — e.g. ``2x400G_2xLR4`` → 4 host
    lanes per logical port, ``1x800G_LR8`` → 8) so the DPActivated scan only
    looks at the lanes the module actually hosts and never reports spurious
    failures for non-existent lanes on 4-lane / 2-lane modules.

    For every connected stem port, verifies vendor name and part number against
    port_attributes_dict (BASE_ATTRIBUTES: vendor_name, vendor_pn) for all
    transceiver families, dispatched on the module's management interface:
    - CMIS: page-0 upper page, bytes 0x81-0x90 (name) / 0x94-0xA3 (PN).
    - SFF-8636 (QSFP/QSFP+/QSFP28): page-0 upper page, bytes 148-163 / 168-183.
    - SFF-8472 (SFP/SFP+/SFP28): A0h flat memory, bytes 20-35 / 40-55, read via
      'sfputil read-eeprom --wire-addr A0h' (A0h is not sectioned by the paged
      hexdump parser).
    Additionally, for non-DAC CMIS transceivers (cmis_active_optical = True), runs
    'sfputil show eeprom-hexdump -p <port> -n 0x11' and verifies every lane the
    module hosts reports DPActivated (0x4) in the upper page 11h DataPath state
    registers (offsets 0x80+).
    Aggregates all failures for reporting.

    CMIS upper page 11h DataPath state (2 lanes per byte, nibble-encoded):
        Bytes 0x80+ cover the module's lanes; each nibble == 0x4 means DPActivated.
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping EEPROM hexdump verification on virtual switch testbed")

    # Resolve breakout-group topology once up front — get_lport_to_first_subport_mapping
    # hits the DUT (ansible facts / sonic-db-cli), so we avoid re-querying inside
    # the per-port loop.  Lane count is read from BASE_ATTRIBUTES per port (already
    # in memory via port_attributes_dict — no DUT round-trip).
    lport_to_first = get_lport_to_first_subport_mapping(duthost)

    all_failures = []

    for port, port_attrs in port_attributes_dict.items():
        # Skip breakout sub-ports — EEPROM hexdump commands must target the
        # physical (stem) port that actually hosts the transceiver.  Sub-ports
        # share the same EEPROM and return redundant or misleading results on
        # some platforms.  Stem == port maps to itself in the lport→first-subport
        # mapping.  A port absent from the mapping (rare) is skipped defensively.
        first_subport = lport_to_first.get(port)
        if first_subport is None or first_subport != port:
            logger.debug("Port %s is a breakout sub-port (stem=%s), skipping hexdump check",
                         port, first_subport)
            continue

        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        base_attrs = port_attrs.get(BASE_ATTRIBUTES_KEY, {})
        eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
        expected_vendor_name = base_attrs.get("vendor_name")
        expected_vendor_pn = base_attrs.get("vendor_pn")
        cmis_revision = eeprom_attrs.get("cmis_revision")
        sff_id = eeprom_attrs.get("sff8024_identifier")
        field_failures = []

        # ------------------------------------------------------------------ #
        # Step 1 – vendor name + part number (all transceiver families).      #
        # CMIS and SFF-8636 (QSFP+) expose both fields in the page-0 upper     #
        # page at family-specific byte ranges; SFF-8472 (SFP+) keeps them in   #
        # A0h flat memory, which the paged hexdump parser does not section, so #
        # it is read via 'read-eeprom --wire-addr A0h'.                        #
        # ------------------------------------------------------------------ #
        if cmis_revision is not None:
            page_data, err = _read_page0_upper(duthost, port)
            name_start, pn_start, loc = CMIS_VENDOR_NAME_START, CMIS_VENDOR_PN_START, "page 0h"
        elif sff_id in SFF8024_IDENT_QSFP_NON_CMIS:
            page_data, err = _read_page0_upper(duthost, port)
            name_start, pn_start, loc = SFF8636_VENDOR_NAME_START, SFF8636_VENDOR_PN_START, "page 0h"
        elif sff_id in SFF8024_IDENT_SFF8472:
            page_data, err = cli_helpers.sfputil_read_eeprom(
                duthost, port, wire_addr="A0h",
                offset=SFF8472_VENDOR_NAME_START, size=SFF8472_VENDOR_SPAN,
            )
            name_start, pn_start, loc = SFF8472_VENDOR_NAME_START, SFF8472_VENDOR_PN_START, "A0h"
        else:
            logger.debug(
                "Port %s: sff8024_identifier=%s (cmis_revision unset) is outside the "
                "hexdump vendor-field scope, skipping", port, sff_id,
            )
            continue

        if err:
            all_failures.append(f"{port}: {err}")
            continue
        if not page_data:
            all_failures.append(f"{port}: vendor-field bytes not found in EEPROM output ({loc})")
            continue

        field_failures += _check_vendor_field(
            "Vendor name", expected_vendor_name, page_data, name_start, VENDOR_FIELD_LEN, loc)
        field_failures += _check_vendor_field(
            "Vendor PN", expected_vendor_pn, page_data, pn_start, VENDOR_FIELD_LEN, loc)

        # ------------------------------------------------------------------ #
        # Step 2 – page 11h: DPActivated state (non-DAC CMIS ports only).     #
        # Page 11h / DataPathState is a CMIS-only construct, so this step is  #
        # gated on cmis_revision in addition to the active-optical flag.      #
        # ------------------------------------------------------------------ #
        if cmis_revision is not None and eeprom_attrs.get("cmis_active_optical"):
            num_lanes = base_attrs.get("host_lane_count", 0)
            if not isinstance(num_lanes, int) or num_lanes <= 0:
                field_failures.append(
                    "BASE_ATTRIBUTES.host_lane_count missing or non-positive ({!r}) "
                    "— cannot check DPActivated".format(num_lanes)
                )
            else:
                hexdump_page11, err = cli_helpers.sfputil_show_eeprom_hexdump(
                    duthost, port, page="0x11"
                )
                if err:
                    field_failures.append(err)
                else:
                    upper_page_11 = hexdump_page11.get("upper_page_11", {})
                    if not upper_page_11:
                        field_failures.append("Upper page 11h section not found in hexdump output")
                    else:
                        field_failures.extend(
                            check_dp_state_activated(upper_page_11, num_lanes)
                        )

        if field_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(field_failures))

    if all_failures:
        pytest.fail("EEPROM hexdump verification failures:\n" + "\n".join(all_failures))


def test_identifier_byte_verification_via_sfputil(duthost, port_attributes_dict):
    """Verify the SFF-8024 identifier byte via 'sfputil read-eeprom'.

    For every connected port, reads exactly one identifier byte at offset 0 and
    validates it against the 'sff8024_identifier' value from EEPROM_ATTRIBUTES in
    port_attributes_dict.  The address space is dispatched on the (expected)
    identifier family, mirroring the non-CMIS upper-page test:
      - SFF-8472 (SFP/SFP+/SFP28, id 0x03): read A0h byte 0
        ('sfputil read-eeprom -p <port> --wire-addr A0h -o 0 -s 1').
      - Paged families (QSFP/QSFP+/QSFP28/CMIS): read lower page 0 byte 0
        ('sfputil read-eeprom -p <port> -n 0 -o 0 -s 1').
    Aggregates all failures for reporting.

    Byte 0 — SFF-8024 identifier values (decimal):
        25 (0x19) = QSFP-DD / OSFP (CMIS)
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping identifier byte verification on virtual switch testbed")

    all_failures = []

    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
        expected_identifier = eeprom_attrs.get("sff8024_identifier")
        if expected_identifier is None:
            logger.debug("Port %s has no sff8024_identifier defined, skipping", port)
            continue

        # SFF-8472 transceivers expose the identifier byte at A0h byte 0; paged
        # families (QSFP/QSFP+/QSFP28/CMIS) expose it at lower page 0 byte 0.
        # Dispatch on the expected identifier so SFP/SFP+/SFP28 (0x03) hit the
        # correct address space (plan TC6).
        if expected_identifier in SFF8024_IDENT_SFF8472:
            byte_map, err = cli_helpers.sfputil_read_eeprom(
                duthost, port, wire_addr="A0h", offset=0, size=1,
            )
        else:
            byte_map, err = cli_helpers.sfputil_read_eeprom(
                duthost, port, page=0, offset=0, size=1,
            )
        if err:
            all_failures.append(f"{port}: {err}")
            continue

        actual_identifier = byte_map.get(0)
        if actual_identifier is None:
            all_failures.append(f"{port}: identifier byte at offset 0 not found in sfputil output")
        elif actual_identifier != expected_identifier:
            all_failures.append(
                f"{port}: identifier byte mismatch: "
                f"expected 0x{expected_identifier:02X} ({expected_identifier}), "
                f"got 0x{actual_identifier:02X} ({actual_identifier})"
            )

    if all_failures:
        pytest.fail("Identifier byte verification failures:\n" + "\n".join(all_failures))


def test_upper_page_verification_non_cmis_via_sfputil(duthost, port_attributes_dict):
    """Test case: upper-page read sanity check for non-CMIS optical transceivers.

    Mirrors the Generic spec in ``docs/testplan/transceiver/eeprom_test_plan.md``.
    For every non-CMIS, non-DAC port the test issues two ``sfputil read-eeprom``
    calls per port: a capability-gate read, then (if implemented) the per-family
    upper-page read. The upper-page result must be non-zero.

    Two families share this test case, dispatched by ``sff8024_identifier``:

    a. SFF-8472 (SFP / SFP+ / SFP28 - identifier 0x03):
       - Gate: ``read-eeprom -p <port> --wire-addr A0h -o 0x5C -s 1`` reads
         byte 92 (Diagnostic Monitoring Type). Bit 6 = 0 means DOM is not
         implemented; the port is logged and skipped (not a failure).
       - Upper-page read: ``read-eeprom -p <port> --wire-addr A2h -o 0x60 -s 2``
         reads bytes 96-97 (real-time temperature, A2h diagnostic page). Both
         bytes being zero fails the port.

    b. QSFP+ / QSFP28 non-CMIS (SFF-8436 / SFF-8636 - identifiers 0x0C,
       0x0D, 0x11):
       - Gate: ``read-eeprom -p <port> -n 0 -o 2 -s 1`` reads byte 2
         (Status Indicators). Bit 2 = 1 means flat memory (no upper pages
         1-3); the port is logged and skipped (not a failure).
       - Upper-page read: ``read-eeprom -p <port> -n 3 -o 128 -s 2`` reads
         the temperature high-alarm threshold (SFF-8636 Table 46, page 03h
         bytes 128-129). Both bytes being zero fails the port.

    Ports are silently skipped when:
      - ``EEPROM_ATTRIBUTES.cmis_revision`` is defined (CMIS - covered by
        the existing CMIS-specific tests).
      - ``EEPROM_ATTRIBUTES.cable_type`` equals ``"DAC"`` (no EEPROM upper
        pages on passive DAC).
      - ``sff8024_identifier`` is missing or falls outside the two families
        above (e.g. an OSFP module that should already have been classified
        CMIS - cannot dispatch).

    Aggregates all failures for one consolidated pytest.fail at the end so a
    single run surfaces every misbehaving port.
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping upper-page verification on virtual switch testbed")

    all_failures = []

    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})

        # --- Scope filters per the test plan ---
        if eeprom_attrs.get("cmis_revision") is not None:
            logger.debug("Port %s: cmis_revision defined (CMIS), skipping", port)
            continue

        cable_type = eeprom_attrs.get("cable_type")
        if isinstance(cable_type, str) and cable_type.strip().upper() == "DAC":
            logger.debug("Port %s: cable_type=DAC, skipping", port)
            continue

        sff_id = eeprom_attrs.get("sff8024_identifier")
        if sff_id is None:
            logger.debug("Port %s: sff8024_identifier missing - cannot dispatch, skipping",
                         port)
            continue

        # --- Family dispatch ---
        if sff_id in SFF8024_IDENT_SFF8472:
            # 7a. SFF-8472 (A0h gate + A2h temperature read)
            gate_bytes, err = cli_helpers.sfputil_read_eeprom(
                duthost, port, wire_addr="A0h", offset="0x5C", size=1,
            )
            if err:
                all_failures.append(f"{port}: SFF-8472 DOM gate {err}")
                continue
            gate_b = gate_bytes.get(0x5C)
            if gate_b is None:
                all_failures.append(
                    f"{port}: SFF-8472 DOM gate byte at A0h/0x5C not found in sfputil output"
                )
                continue
            if not (gate_b & (1 << 6)):
                logger.info(
                    "Port %s: SFF-8472 DOM not implemented (A0h/0x5C bit 6 = 0, byte=0x%02X), "
                    "skipping upper-page read",
                    port, gate_b,
                )
                continue

            temp_bytes, err = cli_helpers.sfputil_read_eeprom(
                duthost, port, wire_addr="A2h", offset="0x60", size=2,
            )
            if err:
                all_failures.append(f"{port}: SFF-8472 A2h temp {err}")
                continue
            b_hi = temp_bytes.get(0x60)
            b_lo = temp_bytes.get(0x61)
            if b_hi is None or b_lo is None:
                all_failures.append(
                    f"{port}: SFF-8472 A2h temp bytes incomplete at 0x60-0x61 "
                    f"(got {temp_bytes!r})"
                )
                continue
            if b_hi == 0 and b_lo == 0:
                all_failures.append(
                    f"{port}: SFF-8472 real-time temperature (A2h/0x60-0x61) is zero "
                    f"(0x{b_hi:02X} 0x{b_lo:02X}); DOM page reads as empty"
                )

        elif sff_id in SFF8024_IDENT_QSFP_NON_CMIS:
            # 7b. QSFP+ non-CMIS (flat-memory gate + page 3 threshold read)
            gate_bytes, err = cli_helpers.sfputil_read_eeprom(
                duthost, port, page=0, offset=2, size=1,
            )
            if err:
                all_failures.append(f"{port}: QSFP+ flat-memory gate {err}")
                continue
            gate_b = gate_bytes.get(2)
            if gate_b is None:
                all_failures.append(
                    f"{port}: QSFP+ Status Indicators byte at page 0 offset 2 "
                    f"not found in sfputil output"
                )
                continue
            if gate_b & (1 << 2):
                logger.info(
                    "Port %s: QSFP+ flat memory (page 0 byte 2 bit 2 = 1, byte=0x%02X), "
                    "no upper pages 1-3; skipping upper-page read",
                    port, gate_b,
                )
                continue

            thr_bytes, err = cli_helpers.sfputil_read_eeprom(
                duthost, port, page=3, offset=128, size=2,
            )
            if err:
                all_failures.append(f"{port}: QSFP+ page 3 temp-threshold {err}")
                continue
            b_hi = thr_bytes.get(128)
            b_lo = thr_bytes.get(129)
            if b_hi is None or b_lo is None:
                all_failures.append(
                    f"{port}: QSFP+ page 3 temp-threshold bytes incomplete at 128-129 "
                    f"(got {thr_bytes!r})"
                )
                continue
            if b_hi == 0 and b_lo == 0:
                all_failures.append(
                    f"{port}: QSFP+ page 3 temperature high-alarm threshold "
                    f"(bytes 128-129) is zero (0x{b_hi:02X} 0x{b_lo:02X})"
                )

        else:
            logger.debug(
                "Port %s: sff8024_identifier=0x%02X is neither SFF-8472 nor QSFP+ "
                "non-CMIS - outside Test case scope, skipping",
                port, sff_id,
            )
            continue

    if all_failures:
        pytest.fail("Non-CMIS upper-page verification failures:\n" + "\n".join(all_failures))
