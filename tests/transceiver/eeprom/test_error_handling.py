import logging
import pytest

from tests.transceiver.common import cli_helpers
from tests.transceiver.utils.cli_parser_helper import parse_presence, RC_FAILURE

# ──────────────────────────────────────────────────────────────────────
# LogAnalyzer suppression.  These tests deliberately drive commands against
# ports with no transceiver installed; the resulting "SFP EEPROM not detected"
# / "SFP EEPROM Not detected" messages would otherwise be picked up by the
# default-enabled loganalyzer fixture and reported as test failures.  The
# patterns below match only what these tests intentionally emit.
# ──────────────────────────────────────────────────────────────────────

_EXPECTED_ABSENCE_LOG_PATTERNS = [
    r".*SFP EEPROM [Nn]ot detected.*",
    # Some platforms also log a structured pmon error when sfputil probes an
    # absent port (handled by sonic_y_cable / sfp_optoe2).  Suppress the
    # common variants seen during sfputil show eeprom/-hexdump/read-eeprom.
    r".*pmon#xcvrd.*SFP.*not\s*present.*",
    r".*pmon#xcvrd.*Failed to read EEPROM.*",
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_absence_messages(duthost, loganalyzer):
    """Tell loganalyzer to ignore the absence-of-transceiver error strings
    that test_absence_message_verification deliberately provokes.

    No-ops when loganalyzer is disabled (e.g. ``--disable_loganalyzer``).
    """
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(_EXPECTED_ABSENCE_LOG_PATTERNS)


logger = logging.getLogger(__name__)


PRESENCE_STATUS_PRESENT = "Present"
PRESENCE_STATUS_NOT_PRESENT = "Not present"

# Expected absence messages per command family (case-sensitive — note the difference)
ABSENT_MSG_SFPUTIL = "SFP EEPROM not detected"   # sfputil family:                     lowercase 'not'
ABSENT_MSG_CLI_INFO = "SFP EEPROM Not detected"   # show interfaces transceiver info:   capital 'Not'


def test_absence_message_verification(duthost, port_attributes_dict):
    """Verify absence error messages for ports with no transceiver installed.

    Step 1 — Derives all empty ports as CONFIG_DB.PORT.keys() − port_attributes_dict.keys()
             (per eeprom_test_plan.md TC8): every physical port configured on the DUT that
             does not carry a transceiver in the inventory.
    Step 2 — For every absent port, attempts all EEPROM / presence operations (sfputil
             and show CLI) and verifies each command returns the expected absence message.

    Expected absence messages are case-sensitive and differ per command family:
        sfputil commands  : "{port}: SFP EEPROM not detected"   (lowercase 'not')
        show transceiver info : "{port}: SFP EEPROM Not detected"  (capital 'Not')
        sfputil hexdump   : "SFP EEPROM not detected"           (no port prefix)
        presence commands : 'Not present' in the Presence column

    Commands verified per absent port:
        1. sfputil show presence -p <port>
        2. show interfaces transceiver presence <port>
        3. sfputil show eeprom -p <port>
        4. show interfaces transceiver info <port>
        5. sfputil show fwversion <port>
        6. sfputil show eeprom-hexdump -p <port>
        7. sfputil read-eeprom -p <port> -n 0 -o 0 -s 1
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping absence message verification on virtual switch testbed")

    # ------------------------------------------------------------------ #
    # Step 1 – Derive empty ports from CONFIG_DB, per eeprom_test_plan.md #
    # TC8: empty ports = all physical ports in the CONFIG_DB PORT table   #
    # minus the ports that carry a transceiver in port_attributes_dict.   #
    # Deriving from CONFIG_DB (rather than 'show ... presence') avoids     #
    # conflating "transceiver absent" with "port not in inventory" and is  #
    # not subject to silently dropping a port if presence parsing breaks.  #
    # ------------------------------------------------------------------ #
    config_facts = duthost.get_running_config_facts()
    config_ports = set(config_facts.get("PORT", {}).keys())
    if not config_ports:
        pytest.skip("CONFIG_DB PORT table is empty; cannot derive empty ports")

    absent_ports = sorted(config_ports - set(port_attributes_dict.keys()))

    if not absent_ports:
        pytest.skip(
            "No empty ports found on DUT (all configured ports are in the transceiver "
            "inventory); skipping absence message verification"
        )

    logger.info("Empty ports derived from CONFIG_DB (%d): %s", len(absent_ports), absent_ports)

    # ------------------------------------------------------------------ #
    # Step 2 – Verify every command returns the expected absence message  #
    # ------------------------------------------------------------------ #
    all_failures = []

    # Helper: run a command and return (stdout_lines, display_string).
    # The display string surfaces rc + stderr alongside truncated stdout so a
    # downstream "expected message not found" failure can be distinguished from
    # a command that actually failed (non-zero rc / stderr-only output) at a
    # glance, without re-running the command in isolation.
    def _run(cmd):
        r = duthost.command(cmd, module_ignore_errors=True)
        lines = r.get('stdout_lines', [])
        stdout_display = ' | '.join(lines)[:200] if lines else '<empty>'
        stderr_display = (r.get('stderr') or '').strip()[:200]
        rc = r.get('rc', RC_FAILURE)
        display = f"rc={rc} stdout={stdout_display}"
        if stderr_display:
            display += f" stderr={stderr_display}"
        return lines, display

    for port in absent_ports:
        field_failures = []

        # --- Check 1: sfputil show presence -p <port> ---
        # Expected: Presence column == "Not present"
        lines, display = _run(cli_helpers.sfputil_show_presence_cmd(port=port))
        status = parse_presence(lines).get(port)
        if status is None:
            field_failures.append(f"[sfputil presence]: '{port}' not in output — got: {display}")
        elif status != PRESENCE_STATUS_NOT_PRESENT:
            field_failures.append(
                f"[sfputil presence]: expected '{PRESENCE_STATUS_NOT_PRESENT}', got '{status}'"
            )

        # --- Check 2: show interfaces transceiver presence <port> ---
        # Expected: Presence column == "Not present"
        lines, display = _run(cli_helpers.show_interfaces_transceiver_presence_cmd(port=port))
        status = parse_presence(lines).get(port)
        if status is None:
            field_failures.append(f"[CLI presence]: '{port}' not in output — got: {display}")
        elif status != PRESENCE_STATUS_NOT_PRESENT:
            field_failures.append(
                f"[CLI presence]: expected '{PRESENCE_STATUS_NOT_PRESENT}', got '{status}'"
            )

        # --- Check 3: sfputil show eeprom -p <port> ---
        # Expected: "{port}: SFP EEPROM not detected"
        expected = f"{port}: {ABSENT_MSG_SFPUTIL}"
        lines, display = _run(cli_helpers.sfputil_show_eeprom_cmd(port=port))
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[sfputil show eeprom]: expected '{expected}' — got: {display}"
            )

        # --- Check 4: show interfaces transceiver info <port> ---
        # Expected: "{port}: SFP EEPROM Not detected"  (capital 'N' in 'Not')
        expected = f"{port}: {ABSENT_MSG_CLI_INFO}"
        lines, display = _run(cli_helpers.show_interfaces_transceiver_info_cmd(port=port))
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[CLI transceiver info]: expected '{expected}' — got: {display}"
            )

        # --- Check 5: sfputil show fwversion <port> ---
        # Expected: "{port}: SFP EEPROM not detected"
        expected = f"{port}: {ABSENT_MSG_SFPUTIL}"
        lines, display = _run(cli_helpers.sfputil_show_fwversion_cmd(port))
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[sfputil show fwversion]: expected '{expected}' — got: {display}"
            )

        # --- Check 6: sfputil show eeprom-hexdump -p <port> ---
        # Expected: "SFP EEPROM not detected"  (no port prefix — unique to this command)
        expected = ABSENT_MSG_SFPUTIL
        lines, display = _run(cli_helpers.sfputil_show_eeprom_hexdump_cmd(port))
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[sfputil show eeprom-hexdump]: expected '{expected}' — got: {display}"
            )

        # --- Check 7: sfputil read-eeprom -p <port> -n 0 -o 0 -s 1 ---
        # Expected: "{port}: SFP EEPROM not detected"
        expected = f"{port}: {ABSENT_MSG_SFPUTIL}"
        lines, display = _run(
            cli_helpers.sfputil_read_eeprom_cmd(port, page=0, offset=0, size=1)
        )
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[sfputil read-eeprom]: expected '{expected}' — got: {display}"
            )

        if field_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(field_failures))

    if all_failures:
        pytest.fail("Absent port message verification failures:\n" + "\n".join(all_failures))
