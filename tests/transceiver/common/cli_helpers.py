"""Centralized sfputil / show CLI command wrappers for transceiver tests.

Lives at the location reserved by
``docs/testplan/transceiver/diagrams/file_organization.md`` for
"CLI command wrappers (sfputil, config interface)".

Two layers, both driven from the same source of truth for command spelling:

1. **Command-string builders** (``*_cmd``) — pure string assembly, no I/O.
   Useful when the caller needs the raw command (e.g. to embed in a
   bash script run on the DUT, or to inspect the raw output rather
   than the parsed form).

2. **Parsed wrappers** — run the command on the DUT with
   ``module_ignore_errors=True``, check rc, check non-empty stdout,
   feed it through the appropriate ``cli_parser_helper`` parser, and
   return a ``(parsed, err)`` tuple.

   ``err`` is ``None`` on success.  On any rc / empty / parse failure it
   is a short, single-line string describing the failure with rc and
   stderr context, so the caller can write:

       fields, err = cli_helpers.sfputil_show_eeprom(duthost, port)
       if err:
           all_failures.append(f"{port}: {err}")
           continue

   matching the per-port aggregation pattern used across the
   transceiver test suite.

The wrappers intentionally do NOT raise on command failure — every
transceiver test aggregates per-port failures into a single
``pytest.fail`` at the end, and an exception inside the loop would
short-circuit that pattern.
"""
from tests.transceiver.common.cli_parser_helper import (
    parse_fwversion,
    parse_hexdump,
    parse_read_eeprom,
    RC_FAILURE,
)
# parse_eeprom is the pre-existing baseline parser and stays in utils/.
from tests.transceiver.utils.cli_parser_helper import parse_eeprom


# ──────────────────────────────────────────────────────────────────────
# Command-string prefixes — single source of truth for command spelling
#
# Convention: NO ``sudo`` prefix on sfputil invocations.  ``sfputil`` is a
# Click wrapper that handles privilege escalation internally on the
# platforms the transceiver suite runs on, and ``tests/transceiver/common/
# prerequisites.py`` (which uses bare ``sfputil show presence``) is the
# pre-existing convention in this tree.  Picking the bare form here means
# a testbed without passwordless sudo behaves uniformly across the entire
# suite instead of silently splitting "works" from "fails" along the
# sudo-vs-bare seam.  If a future subcommand genuinely needs sudo for raw
# I2C access, prepend it on that single wrapper (not blanket-applied
# here).
# ──────────────────────────────────────────────────────────────────────

SFPUTIL_SHOW_EEPROM = "sfputil show eeprom"
SFPUTIL_SHOW_EEPROM_HEXDUMP = "sfputil show eeprom-hexdump"
SFPUTIL_READ_EEPROM = "sfputil read-eeprom"
SFPUTIL_SHOW_FWVERSION = "sfputil show fwversion"
SFPUTIL_SHOW_PRESENCE = "sfputil show presence"
SHOW_TRANSCEIVER_INFO = "show interfaces transceiver info"
SHOW_TRANSCEIVER_PRESENCE = "show interfaces transceiver presence"
CONFIG_INTERFACE_TRANSCEIVER_DOM = "config interface transceiver dom"

# Max characters of stdout/stderr echoed into a failure message.  Some sfputil
# errors dump the full 500+ port list, which would bury the failure summary in
# the terminal; 200 chars is enough to carry the actual error line (e.g.
# "Error: invalid port ..." / "Root privileges are required") while keeping the
# aggregated per-port failure report readable.
CLI_ERROR_DETAIL_MAX_CHARS = 200


# ──────────────────────────────────────────────────────────────────────
# Multi-ASIC namespace support
#
# The DB-backed ``show interfaces transceiver`` command takes a namespace;
# they accept a ``namespace`` kwarg and
# emit ``-n <ns>`` when it is truthy (``asicN``, from e.g.
# ``duthost.get_namespace_from_asic_id`` / ``asichost.namespace``).  On a
# single-ASIC DUT the value is ``None``/``""`` and no flag is emitted, so the
# command stays byte-identical to the pre-namespace form.  Both commands' ``-n``
# is a Choice type that rejects an unknown value (on a single-ASIC DUT the only
# valid choice is the empty string), hence emitting the flag only when truthy.
#
# The ``sfputil`` family takes NO namespace argument: sfputil reaches the SFP via
# the platform API (global logical-port map) and resolves the correct ASIC's
# hardware from the port name alone, so no ASIC scoping is needed.  (Note
# ``sfputil read-eeprom``/``eeprom-hexdump`` do use ``-n``, but it is the
# ``--page`` option, unrelated to namespaces.)
# ──────────────────────────────────────────────────────────────────────


def _ns_flag(namespace):
    """Return ``" -n <namespace>"`` for a truthy namespace, else ``""``."""
    return f" -n {namespace}" if namespace else ""


def _as_decimal_int(value):
    """Coerce ``value`` (an int or a ``"0x.."``/decimal string) to an int.

    ``sfputil read-eeprom``'s ``-o/--offset`` and ``-s/--size`` are
    ``click.IntRange`` options that accept only decimal integers (unlike
    ``-n/--page``, which takes hex), so a hex string like ``"0x5C"`` from an
    SFF-8472 callsite must be normalized before interpolation.  ``int(value, 0)``
    parses both ``"0x5C"`` (hex) and ``"92"`` (decimal); an int passes through.
    """
    return value if isinstance(value, int) else int(value, 0)


# ──────────────────────────────────────────────────────────────────────
# Command-string builders (pure string assembly, no I/O)
# ──────────────────────────────────────────────────────────────────────


def sfputil_show_eeprom_cmd(port=None):
    """Return ``sfputil show eeprom`` (all ports) or ``... -p <port>``."""
    return f"{SFPUTIL_SHOW_EEPROM} -p {port}" if port else SFPUTIL_SHOW_EEPROM


def sfputil_show_eeprom_hexdump_cmd(port, page=None):
    """Return ``sfputil show eeprom-hexdump -p <port>`` with optional ``-n <page>``."""
    cmd = f"{SFPUTIL_SHOW_EEPROM_HEXDUMP} -p {port}"
    if page is not None:
        cmd += f" -n {page}"
    return cmd


def sfputil_read_eeprom_cmd(port, *, offset, size, page=None, wire_addr=None):
    """Return ``sfputil read-eeprom -p <port> [--wire-addr <A0h|A2h>] -n <page> -o <off> -s <sz>``.

    ``-n/--page`` is a ``required=True`` option on ``sfputil read-eeprom``, so it
    is ALWAYS emitted (defaulting to page 0 when ``page`` is None) — even for a
    ``--wire-addr`` read.  The SFF-8472 A0h/A2h path in particular needs both
    ``--wire-addr`` and ``-n 0`` together (``get_overall_offset_sff8472``
    requires ``page == 0``), so ``wire_addr`` and ``page`` are emitted alongside
    each other rather than as alternatives.

    ``offset`` and ``size`` may be passed as ints or hex strings (e.g.
    ``"0x5C"``); they are normalized to decimal because ``-o/--offset`` and
    ``-s/--size`` are decimal-only ``IntRange`` options.
    """
    cmd = f"{SFPUTIL_READ_EEPROM} -p {port}"
    if wire_addr is not None:
        cmd += f" --wire-addr {wire_addr}"
    # offset/size go to -o/-s (decimal-only IntRange); normalize hex strings.
    cmd += (
        f" -n {0 if page is None else page}"
        f" -o {_as_decimal_int(offset)} -s {_as_decimal_int(size)}"
    )
    return cmd


def sfputil_show_fwversion_cmd(port):
    """Return ``sfputil show fwversion <port>``."""
    return f"{SFPUTIL_SHOW_FWVERSION} {port}"


def sfputil_show_presence_cmd(port=None):
    """Return ``sfputil show presence`` (all ports) or ``... -p <port>``."""
    return f"{SFPUTIL_SHOW_PRESENCE} -p {port}" if port else SFPUTIL_SHOW_PRESENCE


def show_interfaces_transceiver_info_cmd(port=None, namespace=None):
    """Return ``show interfaces transceiver info [-n <ns>] [<port>]``."""
    cmd = SHOW_TRANSCEIVER_INFO + _ns_flag(namespace)
    if port:
        cmd += f" {port}"
    return cmd


def show_interfaces_transceiver_presence_cmd(port=None, namespace=None):
    """Return ``show interfaces transceiver presence [-n <ns>] [<port>]``."""
    cmd = SHOW_TRANSCEIVER_PRESENCE + _ns_flag(namespace)
    if port:
        cmd += f" {port}"
    return cmd


# ──────────────────────────────────────────────────────────────────────
# Parsed wrappers (run + rc check + empty check + parse → (parsed, err))
# ──────────────────────────────────────────────────────────────────────


def _error_detail(result):
    """Build a truncated ``stdout: ...; stderr: ...`` detail from a command result.

    sfputil (and the CDB python snippet) write error text to STDOUT on a
    non-zero exit, so both streams are surfaced; each is truncated to
    ``CLI_ERROR_DETAIL_MAX_CHARS`` because some sfputil errors dump the full
    500+ port list.
    """
    stdout = " ".join(result.get("stdout_lines") or []).strip()
    stderr = (result.get("stderr") or "").strip()
    parts = []
    if stdout:
        parts.append(f"stdout: {stdout[:CLI_ERROR_DETAIL_MAX_CHARS]}")
    if stderr:
        parts.append(f"stderr: {stderr[:CLI_ERROR_DETAIL_MAX_CHARS]}")
    return "; ".join(parts) if parts else "no stdout/stderr"


def _run_and_parse(duthost, cmd, parser=None):
    """Shared run + rc + empty + parse pipeline.

    Returns ``(parsed, err)``:
      - ``(parser(stdout_lines), None)`` on success when ``parser`` is given
      - ``(stdout_lines, None)`` on success when ``parser`` is None
      - ``(None, "<cmd> failed with rc=... (stdout: ...)")`` on non-zero rc
      - ``(None, "<cmd> returned empty output")`` when stdout is empty

    ``cmd`` is echoed verbatim into the error message, so it doubles as the
    human-readable label (e.g. ``sfputil show eeprom -p Ethernet0``).

    sfputil writes its error text to STDOUT (not stderr) on a non-zero exit —
    verified on hardware: ``Error: invalid port ...`` and ``Root privileges are
    required`` both land on stdout with an empty stderr.  The failure message
    therefore surfaces stdout (and stderr too, for any command that does use
    it); both are truncated because some sfputil errors dump the full 500+ port
    list.

    Contract note: on rc 0 this intentionally does NOT gate on the parser
    recognizing any rows — non-zero rc and empty stdout are the only failure
    signals here.  A command that exits 0 while printing an unparseable error
    banner returns ``(parser(stdout_lines), None)`` (typically an empty / rowless
    result); catching that is the caller's responsibility via the suite-wide
    per-port aggregation — the per-port tests treat a missing ``parsed[port]`` /
    field as a failure, and TC8 (``test_error_handling.py``) compares the parsed
    status against the exact ``"Not present"`` / ``"SFP EEPROM not detected"``
    tokens.  Keeping the "recognized row" check in the callers lets this pipeline
    stay generic across the CLIs' differing output shapes.
    """
    result = duthost.command(cmd, module_ignore_errors=True)
    if result.get("rc", RC_FAILURE) != 0:
        return None, f"{cmd} failed with rc={result.get('rc')} ({_error_detail(result)})"
    stdout_lines = result.get("stdout_lines", [])
    if not stdout_lines:
        return None, f"{cmd} returned empty output"
    if parser is None:
        return stdout_lines, None
    return parser(stdout_lines), None


def sfputil_show_eeprom(duthost, port=None):
    """Run ``sfputil show eeprom [-p <port>]`` → ``(eeprom_by_port_dict, err)``.

    Output shape: ``{port_name: {cli_field: value}}`` via ``parse_eeprom``.
    """
    cmd = sfputil_show_eeprom_cmd(port)
    return _run_and_parse(duthost, cmd, parse_eeprom)


def sfputil_show_eeprom_hexdump(duthost, port, page=None):
    """Run ``sfputil show eeprom-hexdump -p <port> [-n <page>]`` → ``(section_dict, err)``.

    Output shape: section-keyed byte map via ``parse_hexdump`` (e.g.
    ``{"upper_page_00": {byte_offset: byte_value}, ...}``).
    """
    cmd = sfputil_show_eeprom_hexdump_cmd(port, page)
    return _run_and_parse(duthost, cmd, parse_hexdump)


def sfputil_read_eeprom(duthost, port, *, offset, size, page=None, wire_addr=None):
    """Run ``sfputil read-eeprom -p <port> ...`` → ``({offset: byte_int}, err)``.

    See ``sfputil_read_eeprom_cmd`` for the argument semantics.  ``page`` and
    ``wire_addr`` are NOT mutually exclusive: ``-n/--page`` is always required by
    sfputil (defaults to 0 here), and the SFF-8472 A0h/A2h path needs both
    ``wire_addr`` and ``page=0`` together.
    """
    cmd = sfputil_read_eeprom_cmd(
        port, offset=offset, size=size, page=page, wire_addr=wire_addr,
    )
    return _run_and_parse(duthost, cmd, parse_read_eeprom)


def sfputil_show_fwversion(duthost, port):
    """Run ``sfputil show fwversion <port>`` → ``({field: value}, err)``.

    Output shape: ``{cli_field: value}`` via ``parse_fwversion`` — the
    ``Key: Value`` block sfputil prints (``Active Firmware`` / ``Inactive
    Firmware`` / ``Running Image`` / ``Committed Image`` / ``Image A/B
    Version`` / ``Factory Image Version``).  ``Running Image`` and ``Committed
    Image`` are bank letters (A/B); the firmware fields are version strings.

    This is the only source of truth for running/committed bank state: those
    fields are NOT exposed by ``show interfaces transceiver info`` (which
    reports only ``Active Firmware`` / ``Inactive Firmware`` versions).
    """
    return _run_and_parse(duthost, sfputil_show_fwversion_cmd(port), parse_fwversion)


_CDB_FW_MGMT_FEATURE_BATCH_PYCODE = (
    "import sonic_platform.platform as P\n"
    "chassis = P.Platform().get_chassis()\n"
    "for idx in {indices}:\n"
    "    try:\n"
    "        info = chassis.get_sfp(idx).get_xcvr_api().get_module_fw_mgmt_feature()['info']\n"
    "        val = next((l.split()[-1] for l in info.splitlines() if 'Abort CMD102h supported' in l), 'UNKNOWN')\n"
    "        print('%d %s' % (idx, val))\n"
    "    except Exception as exc:\n"
    "        print('%d ERROR %s' % (idx, ' '.join(str(exc).split())))\n"
)


def get_module_cdb_abort_support_map(duthost, physical_indices):
    """Return ``{physical_index: (abort_supported, err)}``.

    Each module's result is ``(True|False, None)`` on success, or
    ``(None, "<error>")`` when that module raised, has no CDB, or its flag could
    not be extracted.

    ``physical_indices`` is an iterable of 1-based physical SFP indices (the
    CONFIG_DB ``index`` field / ``get_physical_port_indices`` value), which is
    what ``chassis.get_sfp()`` expects.
    """
    indices = []
    for idx in physical_indices:
        idx = int(idx)
        if idx not in indices:
            indices.append(idx)
    if not indices:
        return {}

    pycode = _CDB_FW_MGMT_FEATURE_BATCH_PYCODE.format(indices=indices)
    result = duthost.shell('python3 -c "{}"'.format(pycode), module_ignore_errors=True)
    if result.get("rc", RC_FAILURE) != 0:
        err = f"Get module firmware features failed with rc={result.get('rc')} ({_error_detail(result)})"
        return {idx: (None, err) for idx in indices}

    results = {}
    for line in result.get("stdout_lines", []):
        parts = line.strip().split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        idx, token = int(parts[0]), parts[1]
        if token == "ERROR":
            detail = parts[2] if len(parts) > 2 else "unknown error"
            results[idx] = (None, f"get_module_fw_mgmt_feature raised: {detail}")
        elif token in ("True", "False"):
            results[idx] = (token == "True", None)
        else:
            results[idx] = (None, "'Abort CMD102h supported' not found in reply")

    for idx in indices:
        results.setdefault(idx, (None, f"no get_module_fw_mgmt_feature output for physical index {idx}"))
    return results


def set_dom_polling(duthost, port, enable):
    """Enable/disable DOM polling on ``port`` via the ``config`` CLI.

    Runs ``config interface transceiver dom <port> (enable|disable)``.  The CLI
    only accepts the first subport / non-breakout port.  Returns ``None`` on
    success, or a short error string.
    """
    action = "enable" if enable else "disable"
    cmd = f"{CONFIG_INTERFACE_TRANSCEIVER_DOM} {port} {action}"
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result.get("rc", RC_FAILURE) != 0:
        return f"{cmd} failed with rc={result.get('rc')} ({_error_detail(result)})"
    return None


def get_dom_polling(duthost, port):
    """Return the CONFIG_DB ``dom_polling`` value for ``port``.

    ``"disabled"`` when DOM polling is off; ``""`` or ``"enabled"`` when on
    (default is on).  Returns ``None`` if the value could not be read.
    """
    cmd = f'sonic-db-cli CONFIG_DB HGET "PORT|{port}" dom_polling'
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result.get("rc", RC_FAILURE) != 0:
        return None
    return (result.get("stdout") or "").strip()


def show_interfaces_transceiver_info(duthost, port=None, namespace=None):
    """Run ``show interfaces transceiver info [-n <ns>] [<port>]`` → ``({port: {field: value}}, err)``."""
    cmd = show_interfaces_transceiver_info_cmd(port, namespace=namespace)
    return _run_and_parse(duthost, cmd, parse_eeprom)
