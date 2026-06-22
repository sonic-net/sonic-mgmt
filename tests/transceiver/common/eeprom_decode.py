"""Shared SFF-8024 module-family classification and per-family EEPROM field
decode helpers for transceiver tests.

Centralizes the family dispatch (CMIS / SFF-8636 QSFP / SFF-8472 SFP) and the
per-family vendor-field byte offsets so test modules don't re-paste the
magic-number sets, which would otherwise drift as more per-category tests
(DOM, System, CDB FW) are added.  Each test gets the family from ``classify()``
and dispatches on a small enum instead of open-coding identifier-value sets.
"""
from enum import Enum


class ModuleFamily(Enum):
    """Transceiver management-interface family used to dispatch CLI / memory map."""

    CMIS = "cmis"
    QSFP_NON_CMIS = "qsfp"   # SFF-8436 / SFF-8636
    SFF8472 = "sff8472"      # SFP / SFP+ / SFP28
    UNKNOWN = "unknown"


# SFF-8024 Table 4-1 identifier value sets (decimal).
#
# 0x0B (DWDM-SFP/SFP+) is intentionally NOT in the SFF-8472 set: per SFF-8024
# Table 4-1 it is defined as "DWDM-SFP/SFP+ (not using SFF-8472)", so it must
# not be classified SFF8472 (it would otherwise be probed over an interface it
# does not implement).
SFF8024_IDENT_SFF8472 = {0x03}                       # SFP / SFP+ / SFP28 (A0h/A2h)
SFF8024_IDENT_QSFP_NON_CMIS = {0x0C, 0x0D, 0x11}     # QSFP / QSFP+ / QSFP28 (paged)

# Vendor name / part-number field offsets per management family.
# All families use 16-byte space-padded ASCII vendor fields.
#   CMIS:               page-0 upper page (sfputil 256-byte view, 0x80-0xFF).
#   SFF-8636 (QSFP+):   page-0 upper page, absolute byte addresses.
#   SFF-8472 (SFP+):    A0h flat memory, byte offsets.
VENDOR_FIELD_LEN = 16
CMIS_VENDOR_NAME_START = 0x81      # page 0h bytes 0x81-0x90 (129-144)
CMIS_VENDOR_PN_START = 0x94        # page 0h bytes 0x94-0xA3 (148-163)
SFF8636_VENDOR_NAME_START = 148    # page 0h bytes 148-163
SFF8636_VENDOR_PN_START = 168      # page 0h bytes 168-183
SFF8472_VENDOR_NAME_START = 20     # A0h bytes 20-35
SFF8472_VENDOR_PN_START = 40       # A0h bytes 40-55
SFF8472_VENDOR_SPAN = 36           # one A0h read covers name (20-35) + PN (40-55)


def classify(eeprom_attrs):
    """Return the :class:`ModuleFamily` for a port from its EEPROM_ATTRIBUTES.

    ``cmis_revision`` wins over ``sff8024_identifier`` because CMIS overlays the
    same identifier byte values as legacy QSFP families, so a CMIS module must be
    classified CMIS even though its identifier byte may match a QSFP set.
    """
    if eeprom_attrs.get("cmis_revision") is not None:
        return ModuleFamily.CMIS
    sff_id = eeprom_attrs.get("sff8024_identifier")
    if sff_id in SFF8024_IDENT_QSFP_NON_CMIS:
        return ModuleFamily.QSFP_NON_CMIS
    if sff_id in SFF8024_IDENT_SFF8472:
        return ModuleFamily.SFF8472
    return ModuleFamily.UNKNOWN


def is_dac(eeprom_attrs):
    """True if the port's ``cable_type`` is DAC (passive copper, no upper pages)."""
    cable_type = eeprom_attrs.get("cable_type")
    return isinstance(cable_type, str) and cable_type.strip().upper() == "DAC"


def is_stem_port(port, stem_map):
    """True iff ``port`` is the stem (first sub-port) of its breakout group.

    ``stem_map`` is the ``lport_to_first_subport_mapping`` session fixture: each
    logical port maps to its group's first sub-port, so a port is the stem iff
    it maps to itself.  A port absent from the map is treated as non-stem and
    skipped defensively.
    """
    first = stem_map.get(port)
    return first is not None and first == port


def extract_ascii_field(page_data, start_addr, length):
    """Extract a fixed-width ASCII string from a hexdump page byte map.

    Reads ``length`` bytes starting at ``start_addr``, maps non-printable bytes
    to a space, and strips trailing whitespace.  Returns ``None`` if any
    addressed byte is absent from ``page_data``.
    """
    chars = []
    for addr in range(start_addr, start_addr + length):
        byte_val = page_data.get(addr)
        if byte_val is None:
            return None
        chars.append(chr(byte_val) if 0x20 <= byte_val <= 0x7E else ' ')
    return ''.join(chars).strip()


def check_vendor_field(label, expected, page_data, start, length, loc):
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
