import logging
import time

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY,
    EEPROM_ATTRIBUTES_KEY,
)
from tests.common.platform.interface_utils import is_first_subport
from tests.transceiver.common import cli_helpers

logger = logging.getLogger(__name__)

# CLI-key → inventory-attribute mapping for fields whose CLI key is IDENTICAL
# in both ``sfputil show eeprom`` and ``show interfaces transceiver info``.
_COMMON_CLI_KEY_TO_INV_KEY = {
    "Vendor Date Code(YYYY-MM-DD Lot)": "vendor_date",
    "Vendor OUI":                       "vendor_oui",
    "Vendor Rev":                       "vendor_rev",
    "Vendor SN":                        "vendor_sn",
    "Vendor PN":                        "vendor_pn",
    "Vendor Name":                      "vendor_name",
}

# Some fields are spelled differently by the two CLIs, or exposed by only one,
# so each test uses its own command-specific mapping (verified on an OSFP
# module):
#   hardware revision: sfputil "Hardware Revision" / show CLI "Module Hardware Rev"
#   CMIS revision:     sfputil "CMIS Revision"     / show CLI "CMIS Rev"
#   firmware versions: reported ONLY by 'show interfaces transceiver info'
#                      ('sfputil show eeprom' does not show firmware), so they
#                      are verified by the show-CLI test only.
# Gating is automatic: a port that doesn't define the attribute in inventory is
# skipped (_resolve_expected returns _MISSING), so these never false-fail.
SFPUTIL_CLI_KEY_TO_INV_KEY = {
    **_COMMON_CLI_KEY_TO_INV_KEY,
    "Hardware Revision": "hardware_rev",
    "CMIS Revision":     "cmis_revision",
}
SHOW_CLI_KEY_TO_INV_KEY = {
    **_COMMON_CLI_KEY_TO_INV_KEY,
    "Module Hardware Rev": "hardware_rev",
    "CMIS Rev":            "cmis_revision",
    "Active Firmware":     "gold_firmware_version",
    "Inactive Firmware":   "inactive_firmware_version",
}

# Sentinel distinguishing "attribute genuinely absent from inventory" from
# "attribute present with an explicit None value".  An inventory entry that is
# explicitly set to None means "must be unset on hardware" and should be
# checked, not silently skipped.
_MISSING = object()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Parse-wrapper adapter for the per-port sfputil path.  Exposes the uniform
# ``(duthost, port, namespace) -> (parsed_by_port, err)`` signature
# ``_validate_port_eeprom_dump`` calls, and intentionally DROPS namespace:
# sfputil resolves the logical port to the owning ASIC's hardware globally, so
# it takes no namespace argument.  (The show-CLI variant does not use a per-port
# adapter — it issues one bulk ``show interfaces transceiver info`` per ASIC
# namespace in ``_run_bulk_eeprom_check``.)
def _parse_via_sfputil(duthost, port, namespace=None):
    return cli_helpers.sfputil_show_eeprom(duthost, port=port)


def _resolve_expected(base_attrs, eeprom_attrs, cdb_fw_attrs, attr_key):
    """Look up ``attr_key`` in BASE, then EEPROM, then CDB_FIRMWARE_UPGRADE attrs.

    The firmware-version fields (``gold_firmware_version`` /
    ``inactive_firmware_version``) live under CDB_FIRMWARE_UPGRADE_ATTRIBUTES,
    so that block is consulted too — otherwise those keys would silently
    resolve to ``_MISSING`` and never be verified.

    Returns ``_MISSING`` when the key is absent from all three blocks so the
    caller can skip the check.  When the key is present (in any block) and its
    value is ``None``, returns ``None`` so the comparison loop will flag a
    mismatch against any non-None actual value.
    """
    if attr_key in base_attrs:
        return base_attrs[attr_key]
    if attr_key in eeprom_attrs:
        return eeprom_attrs[attr_key]
    if attr_key in cdb_fw_attrs:
        return cdb_fw_attrs[attr_key]
    return _MISSING


def _compare_eeprom_fields(port_attrs, port_fields, source_label, key_mapping):
    """Compare a port's parsed CLI fields against inventory; return failures.

    Shared by the per-port timed path (:func:`_validate_port_eeprom_dump`, the
    sfputil variant) and the bulk path (:func:`_run_bulk_eeprom_check`, the
    show-CLI variant).  ``port_fields`` is the ``{cli_field: value}`` map already
    parsed for this port (an empty dict means the port had no parsed output).

    Returns a list of failure strings: a "not detected" entry when
    ``port_fields`` is empty, plus one entry per ``key_mapping`` field whose
    value is missing or mismatched against the inventory expectation resolved by
    :func:`_resolve_expected`.
    """
    eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
    base_attrs = port_attrs.get(BASE_ATTRIBUTES_KEY, {})
    cdb_fw_attrs = port_attrs.get(CDB_FIRMWARE_UPGRADE_ATTRIBUTES_KEY, {})

    if not port_fields:
        return [f"transceiver not detected (no {source_label} output)"]

    failures = []
    for cli_key, attr_key in key_mapping.items():
        expected_value = _resolve_expected(base_attrs, eeprom_attrs, cdb_fw_attrs, attr_key)
        if expected_value is _MISSING:
            continue
        actual_value = port_fields.get(cli_key)
        if actual_value is None:
            failures.append(f"'{cli_key}' field missing in {source_label}")
        elif actual_value != expected_value:
            failures.append(
                f"'{cli_key}': expected '{expected_value}', got '{actual_value}'"
            )
    return failures


def _validate_port_eeprom_dump(
    duthost, port, port_attrs, parse_wrapper, source_label, key_mapping,
    namespace=None,
):
    """Per-port EEPROM dump + timeout enforcement + field validation.

    Used by the sfputil variant, which keeps per-port timing because that path
    hits I2C and the ``eeprom_dump_timeout_sec`` budget is meaningful there.

    Implements Generic full contract for a single port:
      1. Call ``parse_wrapper(duthost, port=port, namespace=namespace)`` once,
         timed with ``time.monotonic()``.  ``parse_wrapper`` is the
         ``_parse_via_sfputil`` adapter, which wraps a ``cli_helpers`` parsed
         accessor and centralizes the rc / empty-output / parse handling via
         ``_run_and_parse``, returning ``(parsed_by_port, err)``.  ``namespace``
         is accepted for the uniform adapter signature; the sfputil adapter
         drops it (sfputil resolves the port globally).
      2. Fail the port when the call's elapsed time exceeds
         ``EEPROM_ATTRIBUTES.eeprom_dump_timeout_sec`` (read directly; the
         inventory ``defaults`` block guarantees it, 5 per the HLD).  Field
         validation still runs so a slow-but-correct dump surfaces both signals.
      3. Delegate field validation to :func:`_compare_eeprom_fields`.

    Args:
        duthost: DUT host fixture.
        port:    logical interface name (e.g. ``"Ethernet0"``).
        port_attrs: the port's entry from ``port_attributes_dict``.
        parse_wrapper: callable
            ``(duthost, port=..., namespace=...) -> (parsed_by_port, err)`` —
            the ``_parse_via_sfputil`` adapter.  Timing the wrapper rather than a
            bare command keeps the rc / empty / parse handling centralized in
            ``_run_and_parse``.
        source_label: human-readable label for failure messages.
        key_mapping: CLI-key → inventory-attribute dict for the command this
            test drives (e.g. ``SFPUTIL_CLI_KEY_TO_INV_KEY``).
        namespace: the port's ASIC network namespace (``asicN``) on a multi-ASIC
            DUT, or ``""`` on single-ASIC.  Forwarded to ``parse_wrapper``.

    Returns:
        list[str]: zero or more per-port failure strings.  Empty list means
        every check (command success, elapsed-time budget, field matches)
        passed for this port.
    """
    eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
    # eeprom_dump_timeout_sec is owned solely by the inventory: eeprom.json's
    # ``defaults`` block seeds it (5 per the HLD) as the lowest-priority layer on
    # every resolved port, so it is always present.  Read it directly (no local
    # fallback) — a missing key means the defaults JSON wasn't loaded / the port
    # wasn't resolved for the eeprom category, which should fail loudly.
    timeout_sec = eeprom_attrs["eeprom_dump_timeout_sec"]

    start = time.monotonic()
    parsed_by_port, err = parse_wrapper(duthost, port=port, namespace=namespace)
    elapsed = time.monotonic() - start

    failures = []
    if err:
        failures.append(err)
        return failures

    # Timeout enforcement (Generic expected result, per eeprom_test_plan.md).
    if elapsed > timeout_sec:
        failures.append(
            f"{source_label} took {format(elapsed, '.2f')}s, exceeding "
            f"eeprom_dump_timeout_sec={timeout_sec}s"
        )

    failures += _compare_eeprom_fields(
        port_attrs, parsed_by_port.get(port, {}), source_label, key_mapping,
    )

    return failures


def _run_per_port_eeprom_check(
    duthost, port_attributes_dict, parse_wrapper, source_label, key_mapping,
    lport_to_first_subport,
):
    """Per-port (timed) check, used by the sfputil variant.

    Iterates the FIRST sub-port of each breakout group, validates via
    ``_validate_port_eeprom_dump``, and aggregates per-port failure blocks for
    one consolidated ``pytest.fail`` at the test level.

    First-sub-port filtering is correct here because the sfputil command reads
    EEPROM bytes off the physical module: every sub-port of a breakout maps to
    the same silicon and returns byte-identical content, so testing only the
    first sub-port adds full coverage with no duplication.  (The per-sub-port
    logical→physical resolution path is exercised separately by
    ``test_hexdump.py::test_sfputil_read_eeprom_per_subport_plumbing``.)  The
    show-CLI variant is DB-backed and per-sub-port, so it uses the all-sub-ports
    bulk path :func:`_run_bulk_eeprom_check` instead.

    Each port's ASIC network namespace is resolved via
    ``get_port_asic_instance`` + ``get_namespace_from_asic_id`` and forwarded to
    the parse wrapper (accepted but unused by the sfputil adapter, which resolves
    the port globally).
    """
    all_failures = []
    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue
        if not is_first_subport(port, lport_to_first_subport):
            logger.debug("Port %s is not the first breakout sub-port, skipping", port)
            continue
        namespace = duthost.get_namespace_from_asic_id(
            duthost.get_port_asic_instance(port).asic_index
        )
        port_failures = _validate_port_eeprom_dump(
            duthost, port, port_attrs, parse_wrapper, source_label, key_mapping,
            namespace=namespace,
        )
        if port_failures:
            all_failures.append(port + ":\n  " + "\n  ".join(port_failures))
    return all_failures


def _run_bulk_eeprom_check(duthost, port_attributes_dict, source_label, key_mapping):
    """Bulk (all-sub-ports) check, used by the show-CLI variant.

    ``show interfaces transceiver info`` reads STATE_DB ``TRANSCEIVER_INFO``,
    which xcvrd populates per logical sub-port, so every sub-port's entry must be
    validated — a non-primary sub-port whose entry is missing or diverged is an
    xcvrd failure mode only this DB-backed path can catch.  Rather than one CLI
    invocation per sub-port (hundreds of Click spawns on a high-radix DUT), this
    issues ONE bulk ``show interfaces transceiver info`` (no port arg) per ASIC
    namespace and then does a per-port dict lookup — the same shape
    ``test_vdm_consistency`` / ``test_transceiver_info_cli`` use.

    Per-namespace iteration via ``get_asic_namespace_list`` (``[None]`` on
    single-ASIC → one barefoot call, ``['asic0', ...]`` on multi-ASIC → one
    ``-n <ns>`` call each) keeps the read correct on a chassis.  Unlike the
    sfputil path this does NOT enforce ``eeprom_dump_timeout_sec`` per port: the
    budget targets the I2C dump latency, which does not apply to a STATE_DB read,
    and one bulk call covers all ports anyway.
    """
    # Merge the per-namespace bulk dumps into one {port: {field: value}} map.
    parsed_by_port = {}
    all_failures = []
    for namespace in duthost.get_asic_namespace_list():
        parsed, err = cli_helpers.show_interfaces_transceiver_info(
            duthost, port=None, namespace=namespace,
        )
        if err:
            all_failures.append(f"[namespace {namespace or 'default'}] {err}")
            continue
        parsed_by_port.update(parsed)

    for port, port_attrs in port_attributes_dict.items():
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue
        port_failures = _compare_eeprom_fields(
            port_attrs, parsed_by_port.get(port, {}), source_label, key_mapping,
        )
        if port_failures:
            all_failures.append(port + ":\n  " + "\n  ".join(port_failures))
    return all_failures


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_eeprom_content_verification_via_sfputil(
    duthost, port_attributes_dict, lport_to_first_subport_mapping
):
    """Verify EEPROM content via ``sfputil show eeprom -p <port>`` per port.

    Implements Generic test case from
    ``docs/testplan/transceiver/eeprom_test_plan.md``.  For every port with
    inventory attributes the test:

      * Runs ``sfputil show eeprom -p <port>`` once, timed.
      * Fails the port when elapsed time exceeds
        ``EEPROM_ATTRIBUTES.eeprom_dump_timeout_sec`` (default 5s per the
        plan).  This is the test case expected result "EEPROM dump completes
        within eeprom_dump_timeout_sec".
      * Compares the parsed EEPROM fields against expected values from
        ``port_attributes_dict``.  Firmware versions are NOT checked here:
        ``sfputil show eeprom`` does not report them, so they are verified by
        the show-CLI variant instead.

    Runs on the first sub-port of each breakout only: this command reads EEPROM
    bytes off the physical module, so non-primary sub-ports return byte-identical
    content.

    Aggregates per-port failure blocks into one ``pytest.fail``.
    """
    all_failures = _run_per_port_eeprom_check(
        duthost, port_attributes_dict,
        parse_wrapper=_parse_via_sfputil,
        source_label="sfputil show eeprom -p <port>",
        key_mapping=SFPUTIL_CLI_KEY_TO_INV_KEY,
        lport_to_first_subport=lport_to_first_subport_mapping,
    )
    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))


def test_eeprom_content_verification_via_show_cli(duthost, port_attributes_dict):
    """Verify EEPROM content via ``show interfaces transceiver info`` (bulk).

    Mirror of :func:`test_eeprom_content_verification_via_sfputil` for the SONiC
    ``show`` CLI variant.  This variant additionally verifies firmware versions
    (``Active Firmware`` / ``Inactive Firmware``), which only this CLI reports.

    Runs on ALL sub-ports (not just the first): ``show interfaces transceiver
    info`` reads STATE_DB ``TRANSCEIVER_INFO``, which xcvrd populates per logical
    sub-port, so every sub-port's entry must be validated — a non-primary
    sub-port whose entry is missing or diverged is an xcvrd failure mode only
    this DB-backed path can catch.

    Uses the bulk path (:func:`_run_bulk_eeprom_check`): one ``show interfaces
    transceiver info`` per ASIC namespace + per-port dict lookups, instead of one
    CLI invocation per sub-port (which would be hundreds of Click spawns on a
    high-radix DUT).  Because it is a STATE_DB read with no I2C, the per-port
    ``eeprom_dump_timeout_sec`` budget is not enforced here (it targets the I2C
    dump latency on the sfputil path).
    """
    all_failures = _run_bulk_eeprom_check(
        duthost, port_attributes_dict,
        source_label="show interfaces transceiver info",
        key_mapping=SHOW_CLI_KEY_TO_INV_KEY,
    )
    if all_failures:
        pytest.fail("EEPROM verification failures:\n" + "\n".join(all_failures))
