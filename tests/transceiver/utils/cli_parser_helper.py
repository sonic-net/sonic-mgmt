"""
CLI Parser Helper for various transceiver related commands
"""
import re


__all__ = [
    # ── General shell / command-result constants ────────────────────────────
    "RC_FAILURE",

    # ── Public parsers ──────────────────────────────────────────────────────
    "parse_eeprom",
    "parse_hexdump",
    "parse_presence",
    "parse_read_eeprom",
]

# Default rc when duthost.command() / duthost.shell() result dict is missing the 'rc' key.
RC_FAILURE = 1


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


# Primary hex line shape: 8-hex-digit address, hex bytes, then a ``|...|``
# ASCII gutter.  This is what current sfputil emits (matches ``hexdump -C``).
_HEX_LINE_RE_WITH_GUTTER = re.compile(r'^\s*([0-9a-fA-F]{8})\s+(.*?)\|')

# Fallback hex line shape: 8-hex-digit address followed by hex bytes but no
# ASCII gutter.  Used when an sfputil version omits the ``|...|`` column —
# without this fallback parse_read_eeprom / parse_hexdump would silently
# return {} and the tests would emit misleading "byte not found" failures
# rather than parsing the bytes correctly.  We anchor strictly on
# ``<8-hex-addr> <bytes...> <end-of-line>`` so plain log lines can't match
# accidentally (the trailing ``\s*$`` is what rules out trailing-text false
# positives like "00000000 ab something").
_HEX_LINE_RE_NO_GUTTER = re.compile(
    r'^\s*([0-9a-fA-F]{8})\s+((?:[0-9a-fA-F]{2}\s*)+)\s*$'
)


def _match_hex_line(line):
    """Match a hex-dump line under either the with-gutter or no-gutter form.

    Returns the regex Match object on success or None if neither variant
    matches.  Both forms expose the address in group(1) and the hex-byte
    string in group(2) so callers do not need to know which variant matched.
    """
    m = _HEX_LINE_RE_WITH_GUTTER.match(line)
    if m:
        return m
    return _HEX_LINE_RE_NO_GUTTER.match(line)


def parse_read_eeprom(output_lines):
    """
    @summary: Parse 'sfputil read-eeprom' output into a flat {offset: byte_value} map.
              The command emits a minimal hexdump without section headers, e.g.:
                  00000000 19                                               |.|
              The trailing ``|...|`` ASCII gutter is optional — a fallback regex
              also matches address-plus-hex-bytes lines without it so the parser
              stays robust against sfputil emitting an unadorned hexdump.
    @param output_lines: Command output lines
    @return: dict mapping byte offset (int) to byte value (int), e.g. {0: 0x19}
    """

    result = {}
    for line in output_lines:
        m = _match_hex_line(line)
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
        m = _match_hex_line(line)
        if m:
            base_addr = int(m.group(1), 16)
            hex_bytes = re.findall(r'[0-9a-fA-F]{2}', m.group(2))
            for i, hb in enumerate(hex_bytes):
                sections[current_section][base_addr + i] = int(hb, 16)

    return sections


# ``parse_presence`` accepts the standard ``EthernetN`` name as well as the
# ``EthernetN/M`` form used on some chassis platforms (e.g. modular line-card
# breakouts).  The first capture group preserves the full port identifier; the
# second is constrained to the only two presence tokens the CLI emits, so a
# stray non-table line beginning with ``EthernetN`` (e.g. an interleaved log
# line) cannot produce a spurious entry.  The trailing ``\s*$`` anchor rejects
# rows that carry unexpected extra columns.
_PRESENCE_LINE_RE = re.compile(r"^(Ethernet\d+(?:/\d+)?)\s+(Present|Not present)\s*$")


def parse_presence(output_lines):
    """
    @summary: Parse the transceiver presence information from command output.
              Expects tabular output with 'Port' and 'Presence' columns.
              Recognises ``EthernetN`` and ``EthernetN/M`` port-name forms.
    @param output_lines: Command output lines
    @return: Returns dict mapping port name to presence status string, e.g.
             {"Ethernet0": "Present", "Ethernet4": "Not present"}
    """
    res = {}
    for line in output_lines:
        line = line.strip()
        match = _PRESENCE_LINE_RE.match(line)
        if match:
            port = match.group(1)
            presence = match.group(2).strip()
            res[port] = presence
    return res
