"""
CPO ``cpoutil`` CLI helpers for the SW-controlled CPO suites.

  * ``parse_cpoutil_dom_text``      -- section-aware parser for the table form
                                       of ``cpoutil show interface dom``.
  * ``parse_cpoutil_hexdump``       -- byte parser for ``cpoutil read-eeprom``.
  * ``assert_cpoutil_dom_output``   -- checks the fields of
                                       ``tests/common/platform/cpo_cli_label_catalog.py``
                                       in both the ``--json`` and the table
                                       form of ``cpoutil show interface dom``.

The tests pass already-fetched outputs into the asserts so the CLI is never
re-run inside an assertion path.
"""
import logging
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.cpo_cli_label_catalog import (
    CPO_DOM_CDB_FIELD_GROUPS,
    CPO_DOM_FIELD_GROUPS,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# cpoutil output parsers
# ---------------------------------------------------------------------------

# ``<indent><label>: <value>``; the value is empty on endpoint/section headers.
_CPOUTIL_KV_RE = re.compile(r"^(?P<indent> *)(?P<label>[^:]+?)\s*:\s*(?P<val>.*?)\s*$")
_CPOUTIL_ENDPOINTS = {"OE": "oe", "ELS": "els"}

_HEXDUMP_LINE_RE = re.compile(
    r"^\s*(?P<offset>[0-9a-f]{8})\s+(?P<bytes>(?:[0-9a-f]{2}\s+)+)\|.*\|\s*$",
    re.IGNORECASE,
)

# Per-endpoint ``--json`` dom key that carries the lane number.
_LANE_KEY_RES = {
    "oe": re.compile(r"^rx(?P<n>\d+)power$"),
    "els": re.compile(r"^laser_bias_current_lane(?P<n>\d+)$"),
}


def parse_cpoutil_dom_text(output):
    """Parse the table form into ``{"oe"|"els": {section: {label, ...}}}``.

    Endpoint headers (``OE:`` / ``ELS:``) are indented 4 blanks and section
    headers (``MonitorValues:`` ...) 8 blanks, both without a value.  Labels
    that precede the first section are stored under the ``""`` section.
    """
    parsed = {endpoint: {} for endpoint in _CPOUTIL_ENDPOINTS.values()}
    endpoint = section = None
    for line in output.splitlines():
        m = _CPOUTIL_KV_RE.match(line)
        if not m:
            continue
        indent, label, val = len(m.group("indent")), m.group("label"), m.group("val")
        if indent == 4 and not val and label in _CPOUTIL_ENDPOINTS:
            endpoint, section = _CPOUTIL_ENDPOINTS[label], ""
        elif endpoint and indent == 8 and not val:
            section = label
        elif endpoint and indent >= 8:
            parsed[endpoint].setdefault(section, set()).add(label)
    return parsed


def parse_cpoutil_hexdump(output):
    """Return ``{offset: byte}`` from a ``cpoutil read-eeprom`` hexdump."""
    data = {}
    for line in output.splitlines():
        m = _HEXDUMP_LINE_RE.match(line)
        if not m:
            continue
        base = int(m.group("offset"), 16)
        for i, tok in enumerate(m.group("bytes").split()):
            data[base + i] = int(tok, 16)
    return data


# ---------------------------------------------------------------------------
# cpoutil show interface dom assertion
# ---------------------------------------------------------------------------

def _expand_lanes(fields, lanes):
    """Expand ``{n}`` in keys and labels with every lane in ``lanes``."""
    expanded = {}
    for key, label in fields.items():
        if "{n}" not in key:
            expanded[key] = label
            continue
        for n in lanes:
            expanded[key.format(n=n)] = label.format(n=n)
    return expanded


def _check_group(group, record, text, lanes):
    """Return the fields of one catalog ``FieldGroup`` missing from either output."""
    failures = []
    json_values = record[group.endpoint].get(group.json_group) or {}
    text_labels = text[group.endpoint].get(group.section, set())
    where = f"{group.endpoint.upper()} {group.section or 'header'}"

    for key, label in _expand_lanes(group.fields, lanes).items():
        if key not in json_values:
            failures.append(f"{group.name}: --json {group.endpoint}.{group.json_group} misses '{key}'")
        # The table skips DOM values that are N/A (e.g. TX bias on SIMX).
        elif label not in text_labels and json_values[key] != "N/A":
            failures.append(f"{group.name}: table misses '{label}' under {where}")
    return failures


def assert_cpoutil_dom_output(cmd_label, port, json_output, text_output, is_simx=False):
    """Check ``cpoutil show interface dom -p <port>`` in both output forms.

    Args:
        cmd_label:   CLI name used in error messages.
        port:        Interface the command ran for.
        json_output: Parsed ``--json`` output.
        text_output: Raw table output.
        is_simx:     Skip the CDB-backed fields (SIMX does not answer CDB).
    """
    record = json_output.get(port)
    pytest_assert(record, f"{cmd_label}: port {port} missing from --json keys {list(json_output)}")
    pytest_assert(record.get("present") is True,
                  f"{cmd_label}: CPO EEPROM of {port} not detected: {record}")
    pytest_assert(not record.get("read_errors"),
                  f"{cmd_label}: read errors: {record.get('read_errors')}")
    pytest_assert(f"{port}: CPO EEPROM detected" in text_output,
                  f"{cmd_label}: table header for {port} missing:\n{text_output}")

    text = parse_cpoutil_dom_text(text_output)
    lanes = {}
    for endpoint, lane_re in _LANE_KEY_RES.items():
        lanes[endpoint] = sorted(
            int(m.group("n")) for m in map(lane_re.match, record[endpoint].get("dom") or {}) if m)
        pytest_assert(lanes[endpoint], f"{cmd_label}: no {endpoint.upper()} lanes in --json {endpoint}.dom")

    groups = CPO_DOM_FIELD_GROUPS + ([] if is_simx else CPO_DOM_CDB_FIELD_GROUPS)
    failures = []
    for group in groups:
        failures += _check_group(group, record, text, lanes[group.endpoint])

    pytest_assert(
        not failures,
        f"{cmd_label} CPO field validation failed:\n  - " + "\n  - ".join(failures)
        + f"\ntable output:\n{text_output}",
    )
