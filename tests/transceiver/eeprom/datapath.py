"""EEPROM dynamic DataPath-field helpers (absolute, attribute-derived checks).

Feature-owned half of the scenario-coverage model for the EEPROM category's
dynamic DataPath fields, read from ``show interfaces transceiver info``
(``host_lane_count`` / ``media_lane_count`` and the per-host-lane
``active_apsel_hostlane<n>`` codes; the CLI is a view over STATE_DB
``TRANSCEIVER_INFO``).

These are **absolute** checks against the inventory (EEPROM plan Generic TC 4
step-4, reused by scenario S1 — see
``docs/testplan/transceiver/eeprom_test_plan.md``). Expectations by module class:

  * **non-CMIS** (``cmis_revision`` undefined) — skipped by the caller.
  * **CMIS active optical** (``cmis_active_optical`` true) — each active host
    lane (bit set in ``host_lane_mask``) equals the ``active_apsel_hostlane``
    attribute's pinned code, or is non-``N/A`` when unpinned; inactive lanes
    read ``N/A``.
  * **CMIS passive-copper / flat-memory** (``cmis_active_optical`` false) —
    every ``active_apsel_hostlane<n>`` reads ``N/A``.

``host_lane_count`` / ``media_lane_count`` always equal ``BASE_ATTRIBUTES`` for
both CMIS classes. On admin-down xcvrd clears all these fields to ``N/A``.

The scenario verifiers (:func:`verify_datapath_recovered` /
:func:`verify_datapath_cleared`) iterate the CMIS active-optical ports under test
and **bulk-poll** (one ``show interfaces transceiver info`` per poll — the global
CLI returns all logical ports across all ASICs in one shot — since the CLI can
lag a shut/startup), aggregating per-port failures. They are scenario-agnostic —
an orchestrator calls them after any disruptive operation (shut/no-shut, reboot,
xcvrd restart, ...).
"""
import logging
import re

from tests.common.utilities import wait_until
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import cli_helpers
from tests.transceiver.common.eeprom_decode import is_cmis_active_optical

logger = logging.getLogger(__name__)

# Normalized (STATE_DB-style) per-host-lane apsel field key.
_APSEL_RE = re.compile(r"^active_apsel_hostlane(\d+)$")

# ``show interfaces transceiver info`` labels for the dynamic DataPath fields,
# normalized to the STATE_DB-style keys above.
_CLI_HOST_LANE_COUNT = "Host Lane Count"
_CLI_MEDIA_LANE_COUNT = "Media Lane Count"
_CLI_APSEL_RE = re.compile(
    r"^Active application selected code assigned to host lane (\d+)$")

# The string written for a dynamic DataPath field that is not applicable
# (datapath down, or an inactive host lane).
NA = "N/A"

# Sentinel expected value meaning "active host lane whose apsel code is not
# pinned by inventory": the field must simply be present and non-``N/A``.
_NON_NA = object()

_POLL_INTERVAL_SEC = 2


def _normalize_cli_datapath_fields(cli_fields):
    """Map ``show interfaces transceiver info`` labels to normalized DataPath keys.

    Returns a ``{normalized_field: value}`` dict of only the dynamic DataPath
    fields (lane counts + per-host-lane apsel codes) present in the CLI output.
    """
    normalized = {}
    for label, value in cli_fields.items():
        if label == _CLI_HOST_LANE_COUNT:
            normalized["host_lane_count"] = value
        elif label == _CLI_MEDIA_LANE_COUNT:
            normalized["media_lane_count"] = value
        else:
            match = _CLI_APSEL_RE.match(label)
            if match:
                normalized["active_apsel_hostlane{}".format(match.group(1))] = value
    return normalized


def cmis_active_optical_ports(port_attributes_dict):
    """Return the CMIS active-optical port names — the DataPath "ports under test".

    A scenario shuts / reboots / restarts around this set and the DataPath
    verifiers score it. Reusable across scenarios (shut/no-shut, reboot, xcvrd
    restart, ...).
    """
    return [port for port, attrs in port_attributes_dict.items()
            if attrs and is_cmis_active_optical(attrs.get(EEPROM_ATTRIBUTES_KEY, {}))]


def _iter_targets(port_attributes_dict, ports):
    """Yield ``(port, attrs)`` for each CMIS active-optical port under test.

    ``ports`` (if not None) restricts to that subset; non-CMIS / non-active-optical
    ports are skipped (DataPath fields do not apply to them). When ``ports`` is
    given we iterate it directly (O(len(ports)) dict look-ups) rather than
    scanning every port and doing a membership test, so polling stays cheap on
    large fabrics.
    """
    if ports is None:
        candidates = port_attributes_dict.items()
    else:
        candidates = ((port, port_attributes_dict.get(port)) for port in ports)
    for port, attrs in candidates:
        if not attrs or not is_cmis_active_optical(attrs.get(EEPROM_ATTRIBUTES_KEY, {})):
            continue
        yield port, attrs


def _read_targets_datapath(duthost, targets):
    """Bulk-read normalized DataPath fields for ``targets`` — one CLI call.

    ``targets`` is a list of ``(port, attrs)``. Issues a single
    ``show interfaces transceiver info`` (no namespace flag — the global CLI
    returns all logical ports across all ASICs in one shot) and returns
    ``({port: {normalized_field: value}}, err)`` for the target ports, where
    ``err`` is the CLI/parse error string (or ``None``). ``err`` is surfaced so a
    *persistent* CLI failure is reported as itself, rather than being masked as
    "no dynamic DataPath fields" when the parsed map comes back empty.
    """
    parsed_all, err = cli_helpers.show_interfaces_transceiver_info(duthost)
    if err:
        logger.debug("show interfaces transceiver info failed: %s", err)
        parsed_all = {}
    fields = {port: _normalize_cli_datapath_fields(parsed_all.get(port, {}))
              for port, _ in targets}
    return fields, err


def _stray_flat_apsel_error(eeprom):
    """Return an error string if inventory has flat ``active_apsel_hostlane<n>`` keys.

    The pinned apsel codes must live in the nested ``active_apsel_hostlane`` dict
    (``{"<lane>": code}``), NOT as flat ``active_apsel_hostlane<n>`` keys. Stray
    flat keys are otherwise ignored, so every active lane would silently degrade
    to the unpinned (non-``N/A``) check and a wrong apsel code would pass. This is
    an inventory defect regardless of which check runs, so both the recovered/TC#4
    path and the cleared (shut-side) path call it to fail loudly. Returns ``None``
    when the inventory is well-formed.
    """
    stray_flat = sorted(key for key in eeprom if _APSEL_RE.match(key))
    if stray_flat:
        return (
            "EEPROM_ATTRIBUTES has flat apsel keys {}; pin them under a nested "
            "'active_apsel_hostlane' dict (e.g. {{\"1\": 1}}) instead"
            .format(stray_flat))
    return None


def _expected_datapath_fields(port_attrs, present_fields, active_optical):
    """Derive the expected steady-state value for each present dynamic field.

    Absolute expectation from inventory (no live baseline). ``host_lane_count`` /
    ``media_lane_count`` → ``BASE_ATTRIBUTES`` (as str) for every CMIS module.
    Per-host-lane ``active_apsel_hostlane<n>``:
      * ``active_optical`` True (CMIS active optical): the ``active_apsel_hostlane``
        attribute's code for lane ``n`` when the lane is active (bit ``n-1`` set
        in ``host_lane_mask``) and the attribute pins it; ``_NON_NA`` when active
        but unpinned; ``N/A`` when inactive.
      * ``active_optical`` False (CMIS passive-copper / flat-memory): ``N/A`` for
        every lane (no DataPath application select).

    ``present_fields`` is the keys of dynamic fields currently reported, so the
    expectation is computed only for the lanes actually published.

    Returns ``(expected_map, None)`` or ``(None, "<reason>")`` on an inventory gap.
    """
    base = port_attrs.get(BASE_ATTRIBUTES_KEY, {})
    eeprom = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})

    if "host_lane_count" not in base or "media_lane_count" not in base:
        return None, "host_lane_count/media_lane_count missing from BASE_ATTRIBUTES"
    try:
        host_mask = int(str(base["host_lane_mask"]), 16)
    except (KeyError, ValueError) as exc:
        return None, "cannot resolve host_lane_mask from BASE_ATTRIBUTES ({})".format(exc)

    apsel_attr = eeprom.get("active_apsel_hostlane")  # {"<lane>": code} or None

    stray_err = _stray_flat_apsel_error(eeprom)
    if stray_err:
        return None, stray_err

    expected = {
        "host_lane_count": str(base["host_lane_count"]),
        "media_lane_count": str(base["media_lane_count"]),
    }
    for field in present_fields:
        match = _APSEL_RE.match(field)
        if not match:
            continue
        lane = int(match.group(1))
        if not active_optical:
            # CMIS passive-copper / flat-memory: no DataPath app select.
            expected[field] = NA
            continue
        is_active = bool(host_mask & (1 << (lane - 1)))
        if not is_active:
            expected[field] = NA
        elif apsel_attr is not None and str(lane) in apsel_attr:
            expected[field] = str(apsel_attr[str(lane)])
        else:
            # Active lane whose apsel code is not pinned by inventory.
            expected[field] = _NON_NA
    return expected, None


def _field_matches(actual, expected):
    """Return True if ``actual`` satisfies the ``expected`` value / sentinel."""
    if expected is _NON_NA:
        return actual is not None and actual != NA
    return actual == expected


def _compare_normalized(port_attrs, current, active_optical=True):
    """Return failure strings comparing normalized DataPath fields vs inventory.

    ``active_optical`` defaults to True — the scenario recovery check, whose ports
    are all CMIS active optical; the TC#4 bulk path passes it explicitly per
    module class.
    """
    if not current:
        return ["no dynamic DataPath fields in show interfaces transceiver info"]
    expected, err = _expected_datapath_fields(port_attrs, current, active_optical)
    if err:
        return [err]
    failures = []
    for field, value in expected.items():
        actual = current.get(field)
        if not _field_matches(actual, value):
            want = "non-'N/A'" if value is _NON_NA else "'{}'".format(value)
            failures.append("{}: expected {}, got '{}'".format(field, want, actual))
    return failures


def compare_datapath_fields(port_attrs, cli_fields, active_optical):
    """Compare a port's already-parsed ``show interfaces transceiver info`` fields.

    Pure (no I/O) — used by the EEPROM Generic TC 4 step-4 bulk check, which
    parses one ``show interfaces transceiver info`` per ASIC and passes each
    port's ``{cli_label: value}`` map here. Returns a list of failure strings.
    """
    return _compare_normalized(
        port_attrs, _normalize_cli_datapath_fields(cli_fields), active_optical)


def _cleared_failures(port_attrs, fields):
    """Per-port failures for the cleared (datapath-down) check — all fields ``N/A``.

    An absent/empty dynamic-field set is itself a failure (the fields must read
    ``N/A``, not disappear) rather than a vacuous pass. A mis-formatted inventory
    (flat ``active_apsel_hostlane<n>`` keys) is reported here too, so a port that
    is only exercised by the shut-side check still surfaces the defect.
    """
    stray_err = _stray_flat_apsel_error(port_attrs.get(EEPROM_ATTRIBUTES_KEY, {}))
    if stray_err:
        return [stray_err]
    if not fields:
        return ["no dynamic DataPath fields in show interfaces transceiver info"]
    return ["{}: expected 'N/A', got '{}'".format(field, value)
            for field, value in fields.items() if value != NA]


def _verify_targets(duthost, port_attributes_dict, wait_sec, ports, per_port_failures):
    """Bulk-poll the CMIS active-optical target ports until ``per_port_failures``
    returns ``[]`` for every one; aggregate per-port failure blocks.

    ``per_port_failures(port_attrs, fields) -> list[str]`` is the per-port check.
    Returns ``[]`` once all pass within ``wait_sec``; otherwise one failure block
    per failing port. ``wait_sec == 0`` does a single **snapshot** check (no
    polling) — for a pre-check on ports already at steady state, where there is
    no transition to wait for. Scenario-agnostic (shut/no-shut, reboot, xcvrd
    restart, ...).
    """
    targets = list(_iter_targets(port_attributes_dict, ports))
    if not targets:
        return []

    def _all_ok():
        fields, _ = _read_targets_datapath(duthost, targets)
        return all(not per_port_failures(attrs, fields.get(port, {}))
                   for port, attrs in targets)

    if wait_until(wait_sec, _POLL_INTERVAL_SEC, 0, _all_ok):
        return []

    # Poll exhausted (or a ``wait_sec == 0`` snapshot, where ``wait_until`` never
    # runs the predicate) — read once here to score the per-port failures. If the
    # CLI itself failed, report that error (per port) instead of the generic
    # "no dynamic DataPath fields", which would otherwise mask a real breakage.
    current, err = _read_targets_datapath(duthost, targets)
    failures = []
    for port, attrs in targets:
        if err and not current.get(port):
            port_failures = ["show interfaces transceiver info failed: {}".format(err)]
        else:
            port_failures = per_port_failures(attrs, current.get(port, {}))
        if port_failures:
            failures.append(port + ":\n  " + "\n  ".join(port_failures))
    return failures


def verify_datapath_recovered(duthost, port_attributes_dict, wait_sec, ports=None):
    """Assert every CMIS active-optical port under test has its DataPath fields at
    the inventory-expected steady state (EEPROM Generic TC 4 step-4 absolute
    check) — the template ``verify_<feature>_recovered``.

    Iterates the ports under test (all CMIS active-optical, or the ``ports``
    subset), bulk-polls up to ``wait_sec``, and aggregates per-port failure
    blocks; ``[]`` when all pass. ``wait_sec == 0`` does a single snapshot check
    (a pre-check on already-steady ports, where there is no transition to wait
    for). Reusable after any disruptive operation.
    """
    return _verify_targets(
        duthost, port_attributes_dict, wait_sec, ports, _compare_normalized)


def verify_datapath_cleared(duthost, port_attributes_dict, wait_sec, ports=None):
    """Assert every CMIS active-optical port under test has its DataPath fields
    cleared to ``N/A`` (datapath down) — the shut/no-shut "while down" check.

    Same iterate + bulk-poll + aggregate shape as :func:`verify_datapath_recovered`.
    """
    return _verify_targets(
        duthost, port_attributes_dict, wait_sec, ports, _cleared_failures)
