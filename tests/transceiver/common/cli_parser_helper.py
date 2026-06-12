"""Shared CLI-output parsers for transceiver tests (presence / hexdump / read-eeprom).

Companion to ``common/cli_helpers.py`` (the command-string builders and parsed
wrappers): a wrapper runs a command and feeds its stdout through one of the
parsers here.  Kept as a separate module so the pure, I/O-free parsing logic can
be unit-tested in isolation and reused without importing the command layer.

Note: the baseline ``parse_eeprom`` parser intentionally remains in
``tests/transceiver/utils/cli_parser_helper.py`` — it pre-dates this suite and
is imported by other (non-EEPROM) transceiver tests, so it is not relocated
here.  These are the parsers newly added by the EEPROM work.
"""
import re


__all__ = [
    # ── General shell / command-result constants ────────────────────────────
    "RC_FAILURE",

    # ── Public parsers ──────────────────────────────────────────────────────
    "parse_hexdump",
    "parse_presence",
    "parse_read_eeprom",
]

# Default rc for a duthost.command()/shell() result that lacks an 'rc' key.
# With module_ignore_errors=True, a module-level failure (exception / unreachable
# / async timeout) is RETURNED as a result dict that may omit 'rc' entirely (see
# the is_failed/exception handling in tests/common/devices/base.py) — a normal
# command that merely exits non-zero always has 'rc'.  Treating a missing 'rc' as
# failure is the safe default for pass/fail decisions, and matches the
# .get('rc', <default>) pattern used widely across tests/.
RC_FAILURE = 1


# Primary hex line shape: 8-hex-digit address, hex bytes, then a ``|...|``
# ASCII gutter.  This is what current sfputil emits (matches ``hexdump -C``), e.g.
#     00000000 11 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
# captures group(1)='00000000' (address) and group(2)='11 80 ... 00 ' (the
# hex-byte text up to the ``|`` gutter).
_HEX_LINE_RE_WITH_GUTTER = re.compile(r'^\s*([0-9a-fA-F]{8})\s+(.*?)\|')

# Fallback hex line shape: 8-hex-digit address followed by hex bytes but no
# ASCII gutter, e.g. ``00000000 11 80 00`` (matches; group(1)='00000000',
# group(2)='11 80 00').  Used when an sfputil version omits the ``|...|``
# column — without this fallback parse_read_eeprom / parse_hexdump would
# silently return {} and the tests would emit misleading "byte not found"
# failures rather than parsing the bytes correctly.  We anchor strictly on
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
    """Parse ``sfputil read-eeprom`` output into a flat ``{offset: byte_value}`` map.

    The command emits a minimal hexdump without section headers, e.g.
    ``00000000 19 ... |.|``.  The trailing ``|...|`` ASCII gutter is optional — a
    fallback regex also matches address-plus-hex-bytes lines without it, so the
    parser stays robust against sfputil emitting an unadorned hexdump.

    Args:
        output_lines: command stdout as a list of lines.

    Returns:
        dict mapping byte offset (int) to byte value (int), e.g. ``{0: 0x19}``.
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
    """Parse ``sfputil show eeprom-hexdump`` output into a section-keyed byte map.

    Recognises the ``Lower page 0h``, ``Upper page 0h``, and ``Upper page 11h``
    section headers and collects each section's bytes under its own key.

    Args:
        output_lines: command stdout as a list of lines.

    Returns:
        dict mapping section name to ``{address(int): byte_value(int)}``, e.g.::

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
    """Parse transceiver presence information from command output.

    Expects tabular output with ``Port`` and ``Presence`` columns, and
    recognises both the ``EthernetN`` and ``EthernetN/M`` port-name forms.

    Args:
        output_lines: command stdout as a list of lines.

    Returns:
        dict mapping port name to presence status string, e.g.
        ``{"Ethernet0": "Present", "Ethernet4": "Not present"}``.
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
