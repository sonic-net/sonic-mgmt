"""CMIS page-level decode helpers and register-map constants.

Holds the CMIS-specific page constants and decoders that are not part of the
SFF-8024 family dispatch. The per-family vendor-field offsets and the family
classifier live in ``tests.transceiver.common.eeprom_decode`` instead.
"""

__all__ = [
    # ── Constants: CMIS upper page 11h (DataPath state) ────────────────────
    "CMIS_DP_STATE_START",
    "CMIS_DP_STATE_ACTIVATED",
    "CMIS_DP_STATE_DEACTIVATED",
    "CMIS_DP_STATE_NIBBLE_MASK",
    "CMIS_DP_STATE_LANES_PER_BYTE",

    # ── Constants: CMIS page 01h (CDB capability) ──────────────────────────
    "CMIS_PAGE_01_CDB_CAP_PAGE",
    "CMIS_PAGE_01_CDB_CAP_OFFSET",
    "CMIS_PAGE_01_CDB_BG_MODE_BIT",

    # ── Public helpers ──────────────────────────────────────────────────────
    "check_dp_state",
    "check_dp_state_activated",
]

# CMIS upper page 11h: DataPath state registers (2 lanes per byte, nibble-encoded).
# A module that hosts N lanes consumes ceil(N / 2) bytes starting at CMIS_DP_STATE_START;
# the per-test call site passes the actual per-port lane count.
CMIS_DP_STATE_START = 0x80
CMIS_DP_STATE_LANES_PER_BYTE = 2
CMIS_DP_STATE_ACTIVATED = 0x4   # DPActivated nibble value per CMIS spec
CMIS_DP_STATE_DEACTIVATED = 0x1   # DPDeactivated nibble value per CMIS spec
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


def check_dp_state(page_11_data, num_lanes, expected_state, state_label=None):
    """Verify ``num_lanes`` lanes report ``expected_state`` in CMIS page 11h.

    Each byte starting at CMIS_DP_STATE_START encodes two lanes as nibbles
    (bits 3:0 = lower lane, bits 7:4 = upper lane). ``expected_state`` is the
    CMIS DataPath-state nibble value to assert (e.g. CMIS_DP_STATE_ACTIVATED,
    CMIS_DP_STATE_DEACTIVATED). We check exactly the lanes the module hosts
    (``num_lanes``), not a fixed 8-lane window — this avoids spurious failures
    for non-existent lanes on 4-lane 400G CMIS, 2-lane 200G, etc.

    Args:
        page_11_data: ``{address(int): byte_value(int)}`` map for CMIS page 11h.
        num_lanes: number of host lanes the module provisions.
        expected_state: the DataPath-state nibble value every lane must report.
        state_label: optional human-readable name for ``expected_state`` (e.g.
            ``"DPActivated"``) used in failure messages; defaults to the hex value.

    Returns a list of failure description strings (empty if all lanes report
    ``expected_state``).
    """
    expected_desc = (
        f"{state_label} (0x{expected_state:X})" if state_label else f"0x{expected_state:X}"
    )

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
            if state != expected_state:
                failures.append(
                    f"Lane {lane}: expected {expected_desc}, "
                    f"got 0x{state:X} at page 11h offset 0x{addr:02X}"
                )
    return failures


def check_dp_state_activated(page_11_data, num_lanes):
    """Verify ``num_lanes`` lanes report DPActivated in CMIS page 11h.

    Thin wrapper over :func:`check_dp_state` pinned to
    CMIS_DP_STATE_ACTIVATED; preserved as the named entry point for the
    DPActivated check used across the EEPROM tests.
    """
    return check_dp_state(
        page_11_data, num_lanes, CMIS_DP_STATE_ACTIVATED, state_label="DPActivated"
    )
