"""CMIS page-level decode helpers and register-map constants.

Holds the CMIS-specific page constants and decoders that are not part of the
SFF-8024 family dispatch. The per-family vendor-field offsets and the family
classifier live in ``tests.transceiver.common.eeprom_decode`` instead.
"""
from tests.transceiver.common import cli_helpers

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

    # ── Constants: CMIS page 00h lower page (module-level control/status) ──
    "CMIS_PAGE_00_LOW_PWR_ALLOW_REQUEST_HW_OFFSET",
    "CMIS_PAGE_00_LOW_PWR_ALLOW_REQUEST_HW_BIT",

    # ── Constants: CMIS page 01h (advertising - timing fields) ─────────────
    "CMIS_PAGE_01_MAX_DURATION_DP_TX_TURNOFF_OFFSET",
    "CMIS_DP_PATH_TIMINGS_US",

    # ── Public helpers ──────────────────────────────────────────────────────
    "check_dp_state",
    "check_dp_state_activated",
    "read_dp_state_bytes",
    "check_bit_set",
    "read_nibble",
    "read_low_pwr_allow_request_hw",
    "read_max_duration_dp_tx_turnoff_us",
    "decode_dp_path_timing_us",
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

# CMIS Page 00h lower page, byte 26 (decimal): LowPwrAllowRequestHW.
# Lower-page bytes are common across every selected upper page, so this is
# read with the page selector at its default (page 0h).
CMIS_PAGE_00_LOW_PWR_ALLOW_REQUEST_HW_OFFSET = 26
CMIS_PAGE_00_LOW_PWR_ALLOW_REQUEST_HW_BIT = 6

# CMIS Page 01h upper page, byte 168 (decimal): DP_TX_TURNON_DURATION
# (bits 3:0) / DP_TX_TURNOFF_DURATION (bits 7:4) — mirrors
# sonic-platform-common's page01.py CodeRegField definitions.
CMIS_PAGE_01_MAX_DURATION_DP_TX_TURNOFF_OFFSET = 168

# CMIS "DP_PATH_TIMINGS" code table: decodes a 4-bit timing-advertisement
# nibble (DP init/deinit, Tx turn-on/off, module power-up/down durations) to
# microseconds. Mirrors sonic-platform-common's
# sonic_xcvr/codes/public/cmis.py ``Sff8636Codes.DP_PATH_TIMINGS`` table.
# Codes 14/15 are reserved (0 == "no duration advertised").
CMIS_DP_PATH_TIMINGS_US = {
    0: 1, 1: 5, 2: 10, 3: 50, 4: 100, 5: 500, 6: 1000, 7: 5000,
    8: 10000, 9: 60000, 10: 300000, 11: 600000, 12: 3000000, 13: 6000000,
    14: 0, 15: 0,
}


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
    expected_hex = format(expected_state, "X")
    expected_desc = (
        f"{state_label} (0x{expected_hex})" if state_label else f"0x{expected_hex}"
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
            failures.append(
                f"DataPath state byte missing at page 11h offset 0x{format(addr, '02X')}"
            )
            continue
        for nibble_idx in range(CMIS_DP_STATE_LANES_PER_BYTE):
            lane = byte_idx * CMIS_DP_STATE_LANES_PER_BYTE + nibble_idx + 1
            if lane > num_lanes:
                break
            state = (byte_val >> (nibble_idx * 4)) & CMIS_DP_STATE_NIBBLE_MASK
            if state != expected_state:
                failures.append(
                    f"Lane {lane}: expected {expected_desc}, "
                    f"got 0x{format(state, 'X')} at page 11h offset 0x{format(addr, '02X')}"
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


def read_dp_state_bytes(duthost, port, num_lanes):
    """Read the CMIS page 11h DataPath-state bytes covering ``num_lanes`` lanes.

    Returns ``(page_11_data, err)`` where ``page_11_data`` is the
    ``{address(int): byte_value(int)}`` map :func:`check_dp_state` expects.
    """
    if num_lanes <= 0:
        return {}, f"invalid lane count {num_lanes} for DP-state read"
    num_bytes = (num_lanes + CMIS_DP_STATE_LANES_PER_BYTE - 1) // CMIS_DP_STATE_LANES_PER_BYTE
    return cli_helpers.sfputil_read_eeprom(
        duthost, port, offset=CMIS_DP_STATE_START, size=num_bytes, page=0x11,
    )


def check_bit_set(byte_val, bit_index, expected, field_label):
    """Verify bit ``bit_index`` (0 = LSB) of ``byte_val`` equals ``expected`` (0/1).

    Returns a list with one failure string if the bit doesn't match, else ``[]``
    — the same "list of failure strings" shape as :func:`check_dp_state`.
    """
    actual = (byte_val >> bit_index) & 0x1
    if actual != expected:
        return [
            f"{field_label}: expected bit {bit_index}={expected}, got "
            f"{actual} (byte=0x{byte_val:02X})"
        ]
    return []


def read_nibble(byte_val, high):
    """Return the high (bits 7:4, ``high=True``) or low (bits 3:0) nibble of ``byte_val``."""
    return (byte_val >> 4) & 0x0F if high else byte_val & 0x0F


def read_low_pwr_allow_request_hw(duthost, port):
    """Read CMIS page 0h byte 26 (LowPwrAllowRequestHW byte).

    Returns ``(byte_val, err)``; callers extract the bit with
    :func:`check_bit_set` (``CMIS_PAGE_00_LOW_PWR_ALLOW_REQUEST_HW_BIT``).
    """
    data, err = cli_helpers.sfputil_read_eeprom(
        duthost, port,
        offset=CMIS_PAGE_00_LOW_PWR_ALLOW_REQUEST_HW_OFFSET, size=1, page=0x00,
    )
    if err:
        return None, err
    byte_val = data.get(CMIS_PAGE_00_LOW_PWR_ALLOW_REQUEST_HW_OFFSET)
    if byte_val is None:
        return None, (
            "LowPwrAllowRequestHW byte missing at page 0h offset "
            f"{CMIS_PAGE_00_LOW_PWR_ALLOW_REQUEST_HW_OFFSET}"
        )
    return byte_val, None


def decode_dp_path_timing_us(nibble_value):
    """Decode a CMIS DP_PATH_TIMINGS-coded nibble (0-15) to microseconds.

    Mirrors ``codes.DP_PATH_TIMINGS`` in sonic-platform-common
    (``sonic_xcvr/codes/public/cmis.py``) — the CMIS-spec table used to
    decode module timing-advertisement fields (DP init/deinit, Tx
    turn-on/off, module power-up/down durations).
    """
    return CMIS_DP_PATH_TIMINGS_US.get(nibble_value, 0)


def read_max_duration_dp_tx_turnoff_us(duthost, port):
    """Read CMIS page 1h byte 168 bits 7:4 (DP_TX_TURNOFF_DURATION) and
    decode it to microseconds.

    Returns ``(duration_us, err)``.
    """
    data, err = cli_helpers.sfputil_read_eeprom(
        duthost, port,
        offset=CMIS_PAGE_01_MAX_DURATION_DP_TX_TURNOFF_OFFSET, size=1, page=0x01,
    )
    if err:
        return None, err
    byte_val = data.get(CMIS_PAGE_01_MAX_DURATION_DP_TX_TURNOFF_OFFSET)
    if byte_val is None:
        return None, (
            "DP_TX_TURNOFF_DURATION byte missing at page 1h offset "
            f"{CMIS_PAGE_01_MAX_DURATION_DP_TX_TURNOFF_OFFSET}"
        )
    return decode_dp_path_timing_us(read_nibble(byte_val, high=True)), None
