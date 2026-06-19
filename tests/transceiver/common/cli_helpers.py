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
    """Return ``sfputil read-eeprom -p <port> [-n <page> | --wire-addr <A0h|A2h>] -o <off> -s <sz>``.

    Exactly one of ``page`` or ``wire_addr`` should be provided.  Mixed-mode
    callers (e.g. SFF-8472 vs CMIS paged access) get one builder either way.
    """
    cmd = f"{SFPUTIL_READ_EEPROM} -p {port}"
    if wire_addr is not None:
        cmd += f" --wire-addr {wire_addr}"
    elif page is not None:
        cmd += f" -n {page}"
    cmd += f" -o {offset} -s {size}"
    return cmd


def sfputil_show_fwversion_cmd(port):
    """Return ``sfputil show fwversion <port>``."""
    return f"{SFPUTIL_SHOW_FWVERSION} {port}"


def sfputil_show_presence_cmd(port=None):
    """Return ``sfputil show presence`` (all ports) or ``... -p <port>``."""
    return f"{SFPUTIL_SHOW_PRESENCE} -p {port}" if port else SFPUTIL_SHOW_PRESENCE


def show_interfaces_transceiver_info_cmd(port=None):
    """Return ``show interfaces transceiver info`` (all ports) or ``... <port>``."""
    return f"{SHOW_TRANSCEIVER_INFO} {port}" if port else SHOW_TRANSCEIVER_INFO


def show_interfaces_transceiver_presence_cmd(port=None):
    """Return ``show interfaces transceiver presence`` (all ports) or ``... <port>``."""
    return f"{SHOW_TRANSCEIVER_PRESENCE} {port}" if port else SHOW_TRANSCEIVER_PRESENCE


# ──────────────────────────────────────────────────────────────────────
# Parsed wrappers (run + rc check + empty check + parse → (parsed, err))
# ──────────────────────────────────────────────────────────────────────


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
    """
    result = duthost.command(cmd, module_ignore_errors=True)
    if result.get("rc", RC_FAILURE) != 0:
        stdout = " ".join(result.get("stdout_lines") or []).strip()
        stderr = (result.get("stderr") or "").strip()
        parts = []
        if stdout:
            parts.append(f"stdout: {stdout[:200]}")
        if stderr:
            parts.append(f"stderr: {stderr[:200]}")
        detail = "; ".join(parts) if parts else "no stdout/stderr"
        return None, f"{cmd} failed with rc={result.get('rc')} ({detail})"
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
    ``{"upper_page_0": {byte_offset: byte_value}, ...}``).
    """
    cmd = sfputil_show_eeprom_hexdump_cmd(port, page)
    return _run_and_parse(duthost, cmd, parse_hexdump)


def sfputil_read_eeprom(duthost, port, *, offset, size, page=None, wire_addr=None):
    """Run ``sfputil read-eeprom -p <port> ...`` → ``({offset: byte_int}, err)``.

    See ``sfputil_read_eeprom_cmd`` for the argument semantics (exactly one
    of ``page`` / ``wire_addr``).
    """
    if (page is None) == (wire_addr is None):
        return None, (
            f"sfputil read-eeprom -p {port}: exactly one of 'page' or 'wire_addr' must be provided"
        )
    cmd = sfputil_read_eeprom_cmd(
        port, offset=offset, size=size, page=page, wire_addr=wire_addr,
    )
    return _run_and_parse(duthost, cmd, parse_read_eeprom)


def sfputil_show_fwversion(duthost, port):
    """Run ``sfputil show fwversion <port>`` → ``(stdout_lines, err)``.

    Returns raw ``stdout_lines`` (``parser=None``) on purpose, not for lack of a
    parseable format: the only caller today is the CDB background-mode stress
    loop, which runs this command to exercise the CDB/I2C bus and only checks
    ``err`` (command success) per iteration — it never reads the version fields.
    Firmware-version *content* is validated separately via
    ``show interfaces transceiver info`` (Active / Inactive Firmware), which is
    already parsed by ``parse_eeprom``.  A structured fwversion parser can be
    added here if/when a test needs to assert specific fields.
    """
    return _run_and_parse(duthost, sfputil_show_fwversion_cmd(port))


def show_interfaces_transceiver_info(duthost, port=None):
    """Run ``show interfaces transceiver info [<port>]`` → ``({port: {field: value}}, err)``."""
    cmd = show_interfaces_transceiver_info_cmd(port)
    return _run_and_parse(duthost, cmd, parse_eeprom)
