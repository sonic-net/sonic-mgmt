"""
CLI Parser Helper for various transceiver related commands
"""
import re


__all__ = [
    # ── General shell / command-result constants ────────────────────────────
    "RC_FAILURE",

    # ── Constants: CMIS upper page 0h (vendor fields) ──────────────────────
    "CMIS_VENDOR_NAME_START",
    "CMIS_VENDOR_NAME_LEN",
    "CMIS_VENDOR_PN_START",
    "CMIS_VENDOR_PN_LEN",

    # ── Constants: CMIS upper page 11h (DataPath state) ────────────────────
    "CMIS_DP_STATE_START",
    "CMIS_DP_STATE_NUM_BYTES",
    "CMIS_DP_STATE_ACTIVATED",
    "CMIS_DP_STATE_NIBBLE_MASK",

    # ── Constants: CMIS page 01h (CDB capability) ──────────────────────────
    "CMIS_PAGE_01_CDB_CAP_PAGE",
    "CMIS_PAGE_01_CDB_CAP_OFFSET",
    "CMIS_PAGE_01_CDB_BG_MODE_BIT",

    # ── Public functions ────────────────────────────────────────────────────
    "parse_eeprom",
    "parse_fwversion",
    "parse_hexdump",
    "parse_presence",
    "parse_read_eeprom",

    # ── Private functions (opt-in explicitly) ───────────────────────────────
    "_extract_ascii_field",
    "_check_dp_state_activated",
 ]

# Default rc when duthost.command() / duthost.shell() result dict is missing the 'rc' key.
RC_FAILURE = 1

# CMIS upper page 0h: vendor field byte offsets (within the 0x80-0xFF address range)
CMIS_VENDOR_NAME_START = 0x81   # 16 bytes: 0x81-0x90
CMIS_VENDOR_NAME_LEN = 16
CMIS_VENDOR_PN_START = 0x94   # 16 bytes: 0x94-0xA3
CMIS_VENDOR_PN_LEN = 16

# CMIS upper page 11h: DataPath state registers (2 lanes per byte, nibble-encoded)
# Bytes 0x80-0x83 cover lanes 1-8 for an 8-lane (800G) transceiver
CMIS_DP_STATE_START = 0x80
CMIS_DP_STATE_NUM_BYTES = 4     # 4 bytes × 2 lanes/byte = 8 lanes
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


def _extract_ascii_field(page_data, start_addr, length):
    """Extract a fixed-width ASCII string from a hexdump page byte map.

    Reads 'length' bytes starting at 'start_addr', replaces non-printable bytes
    with a space, and strips trailing whitespace — matching CMIS field encoding.
    Returns None if any addressed byte is absent from page_data.
    """
    chars = []
    for addr in range(start_addr, start_addr + length):
        byte_val = page_data.get(addr)
        if byte_val is None:
            return None
        chars.append(chr(byte_val) if 0x20 <= byte_val <= 0x7E else ' ')
    return ''.join(chars).strip()


def _check_dp_state_activated(page_11_data):
    """Verify all lanes report DPActivated in CMIS page 11h DataPath state registers.

    Checks CMIS_DP_STATE_NUM_BYTES bytes starting at CMIS_DP_STATE_START.
    Each byte encodes two lanes as nibbles (bits 3:0 = lower lane, bits 7:4 = upper lane).
    A nibble value of CMIS_DP_STATE_ACTIVATED (0x4) means DPActivated.
    Returns a list of failure description strings (empty if all lanes are DPActivated).
    """
    failures = []
    for byte_idx in range(CMIS_DP_STATE_NUM_BYTES):
        addr = CMIS_DP_STATE_START + byte_idx
        byte_val = page_11_data.get(addr)
        if byte_val is None:
            failures.append(f"DataPath state byte missing at page 11h offset 0x{addr:02X}")
            continue
        for nibble_idx in range(2):
            lane = byte_idx * 2 + nibble_idx + 1
            state = (byte_val >> (nibble_idx * 4)) & CMIS_DP_STATE_NIBBLE_MASK
            if state != CMIS_DP_STATE_ACTIVATED:
                failures.append(
                    f"Lane {lane}: expected DPActivated (0x{CMIS_DP_STATE_ACTIVATED:X}), "
                    f"got 0x{state:X} at page 11h offset 0x{addr:02X}"
                )
    return failures


def parse_eeprom(output_lines):
    """
    @summary: Parse the SFP eeprom information from command output
    @param output_lines: Command output lines
    @return: Returns result in a dictionary
    """
    res = {}
    current_interface = None

    for line in output_lines:
        line = line.strip()
        # Check if the line indicates a new interface
        if re.match(r"^Ethernet\d+: .*", line):
            fields = line.split(":", 1)
            current_interface = fields[0]
            res[current_interface] = {"status": fields[1].strip()}
        elif current_interface:
            # Parse key-value pairs for the current interface
            key_value = line.split(": ", 1)
            if len(key_value) == 2:
                key, value = key_value
                res[current_interface][key] = value.strip()

    return res


def parse_fwversion(output_lines):
    """
    @summary: Parse per-port firmware version information from 'sfputil show fwversion <port>' output.
              Each key-value pair (separated by ': ') is normalized to a snake_case key.
    @param output_lines: Command output lines for a single port
    @return: Returns dict mapping normalized field names to values, e.g.
             {"active_firmware": "114.167.0", "inactive_firmware": "114.167.0"}
    """
    res = {}
    for line in output_lines:
        line = line.strip()
        if ": " in line and not re.match(r"^Ethernet\d+:", line):
            key, value = line.split(": ", 1)
            normalized_key = key.strip().lower().replace(" ", "_")
            res[normalized_key] = value.strip()
    return res


_HEX_LINE_RE = re.compile(r'^\s*([0-9a-fA-F]{8})\s+(.*?)\|')


def parse_read_eeprom(output_lines):
    """
    @summary: Parse 'sfputil read-eeprom' output into a flat {offset: byte_value} map.
              The command emits a minimal hexdump without section headers, e.g.:
                  00000000 19                                               |.|
    @param output_lines: Command output lines
    @return: dict mapping byte offset (int) to byte value (int), e.g. {0: 0x19}
    """

    result = {}
    for line in output_lines:
        m = _HEX_LINE_RE.match(line)
        if m:
            base_addr = int(m.group(1), 16)
            hex_bytes = re.findall(r'[0-9a-fA-F]{2}', m.group(2))
            for i, hb in enumerate(hex_bytes):
                result[base_addr + i] = int(hb, 16)
    return result


# ------------------------------------------------------------------ #
# Module-level constants: compiled once at import time, shared across #
# all parse_hexdump() calls (one per port × one per page section).    #
# ------------------------------------------------------------------ #
_SECTION_MARKERS = [
    (re.compile(r'Lower\s+page\s+0h',  re.IGNORECASE), 'lower_page_0'),
    (re.compile(r'Upper\s+page\s+0h',  re.IGNORECASE), 'upper_page_0'),
    (re.compile(r'Upper\s+page\s+11h', re.IGNORECASE), 'upper_page_11'),
]


def parse_hexdump(output_lines):
    """
    @summary: Parse 'sfputil show eeprom-hexdump' output into a section-keyed byte map.
              Recognises 'Lower page 0h', 'Upper page 0h', and 'Upper page 11h' sections.
    @param output_lines: Command output lines
    @return: dict mapping section name to {address(int): byte_value(int)}, e.g.
             {
                 "lower_page_0":  {0x00: 0x19, ...},
                 "upper_page_0":  {0x80: 0x19, 0x81: 0x50, ...},
                 "upper_page_11": {0x80: 0x44, ...},
             }
    """
    sections = {}
    current_section = None

    for line in output_lines:
        matched_section = False
        for pattern, name in _SECTION_MARKERS:
            if pattern.search(line):           # re.IGNORECASE already baked in
                current_section = name
                sections[current_section] = {}
                matched_section = True
                break
        if matched_section or current_section is None:
            continue
        m = _HEX_LINE_RE.match(line)
        if m:
            base_addr = int(m.group(1), 16)
            hex_bytes = re.findall(r'[0-9a-fA-F]{2}', m.group(2))
            for i, hb in enumerate(hex_bytes):
                sections[current_section][base_addr + i] = int(hb, 16)

    return sections


def parse_presence(output_lines):
    """
    @summary: Parse the transceiver presence information from command output.
              Expects tabular output with 'Port' and 'Presence' columns.
    @param output_lines: Command output lines
    @return: Returns dict mapping port name to presence status string, e.g.
             {"Ethernet0": "Present", "Ethernet4": "Not present"}
    """
    res = {}
    for line in output_lines:
        line = line.strip()
        match = re.match(r"^(Ethernet\d+)\s+(.+)$", line)
        if match:
            port = match.group(1)
            presence = match.group(2).strip()
            res[port] = presence
    return res
