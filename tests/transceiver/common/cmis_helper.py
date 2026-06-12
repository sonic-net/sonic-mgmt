"""CMIS page-level decode helpers and register-map constants.

Holds the CMIS-specific page constants and decoders that are not part of the
SFF-8024 family dispatch: page 11h DataPath state and page 01h CDB capability.
The per-family vendor-field offsets and the family classifier live in
``tests.transceiver.common.eeprom_decode`` instead.
"""

__all__ = [
    # ── Constants: CMIS upper page 11h (DataPath state) ────────────────────
    "CMIS_DP_STATE_START",
    "CMIS_DP_STATE_ACTIVATED",
    "CMIS_DP_STATE_NIBBLE_MASK",
    "CMIS_DP_STATE_LANES_PER_BYTE",

    # ── Constants: CMIS page 01h (CDB capability) ──────────────────────────
    "CMIS_PAGE_01_CDB_CAP_PAGE",
    "CMIS_PAGE_01_CDB_CAP_OFFSET",
    "CMIS_PAGE_01_CDB_BG_MODE_BIT",

    # ── Public helpers ──────────────────────────────────────────────────────
    "check_dp_state_activated",
]

# CMIS upper page 11h: DataPath state registers (2 lanes per byte, nibble-encoded).
# A module that hosts N lanes consumes ceil(N / 2) bytes starting at CMIS_DP_STATE_START;
# the per-test call site passes the actual per-port lane count.
CMIS_DP_STATE_START = 0x80
CMIS_DP_STATE_LANES_PER_BYTE = 2
CMIS_DP_STATE_ACTIVATED = 0x4   # DPActivated nibble value per CMIS spec
CMIS_DP_STATE_NIBBLE_MASK = 0x0F

# CMIS Page 01h: CDB capability register
# CMIS global byte 163 (decimal) = 0xA3 (hex).
# The CMIS standard numbers bytes 0-255 within a page: 0-127 = lower page,
# 128-255 = upper page. Byte 163 is in the upper page at absolute address 0xA3.
# In sfputil's 256-byte page view the upper page starts at 0x80, so
# sfputil offset = 0xA3 directly (= upper-page local offset 0x23 = 35 from 0x80).
# Bit 5 of this byte advertises CDB background mode support.
CMIS_PAGE_01_CDB_CAP_PAGE = 0x01   # Page 01h (Capabilities Advertising)
CMIS_PAGE_01_CDB_CAP_OFFSET = 0xA3   # sfputil offset = CMIS global byte 163 (decimal)
CMIS_PAGE_01_CDB_BG_MODE_BIT = 5      # bit 5: CDB background mode support (1=yes, 0=no)


def check_dp_state_activated(page_11_data, num_lanes):
    """Verify ``num_lanes`` lanes report DPActivated in CMIS page 11h.

    Each byte starting at CMIS_DP_STATE_START encodes two lanes as nibbles
    (bits 3:0 = lower lane, bits 7:4 = upper lane). A nibble value of
    CMIS_DP_STATE_ACTIVATED (0x4) means DPActivated. We check exactly the
    lanes the module hosts (``num_lanes``), not a fixed 8-lane window — this
    avoids spurious "not DPActivated" failures for non-existent lanes on
    4-lane 400G CMIS, 2-lane 200G, etc.

    Returns a list of failure description strings (empty if all lanes are
    DPActivated).
    """
    failures = []
    if num_lanes <= 0:
        failures.append(f"invalid lane count {num_lanes} for DP-state check")
        return failures

    num_bytes = (num_lanes + CMIS_DP_STATE_LANES_PER_BYTE - 1) // CMIS_DP_STATE_LANES_PER_BYTE
    for byte_idx in range(num_bytes):
        addr = CMIS_DP_STATE_START + byte_idx
        byte_val = page_11_data.get(addr)
        if byte_val is None:
            failures.append(f"DataPath state byte missing at page 11h offset 0x{addr:02X}")
            continue
        for nibble_idx in range(CMIS_DP_STATE_LANES_PER_BYTE):
            lane = byte_idx * CMIS_DP_STATE_LANES_PER_BYTE + nibble_idx + 1
            if lane > num_lanes:
                break
            state = (byte_val >> (nibble_idx * 4)) & CMIS_DP_STATE_NIBBLE_MASK
            if state != CMIS_DP_STATE_ACTIVATED:
                failures.append(
                    f"Lane {lane}: expected DPActivated (0x{CMIS_DP_STATE_ACTIVATED:X}), "
                    f"got 0x{state:X} at page 11h offset 0x{addr:02X}"
                )
    return failures
