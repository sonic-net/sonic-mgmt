import logging
import pytest

from tests.transceiver.utils.cli_parser_helper import parse_presence, RC_FAILURE

logger = logging.getLogger(__name__)

CMD_SFP_PRESENCE_SFPUTIL = "sudo sfputil show presence"
CMD_SFP_PRESENCE_CLI = "show interfaces transceiver presence"
CMD_SFP_EEPROM_SFPUTIL = "sudo sfputil show eeprom"
CMD_SFP_EEPROM_CLI = "show interfaces transceiver info"
CMD_SFP_FWVERSION_SFPUTIL = "sudo sfputil show fwversion"
CMD_SFP_HEXDUMP_SFPUTIL = "sudo sfputil show eeprom-hexdump"
CMD_SFP_READ_EEPROM_SFPUTIL = "sudo sfputil read-eeprom"

PRESENCE_STATUS_PRESENT = "Present"
PRESENCE_STATUS_NOT_PRESENT = "Not present"

# Expected absence messages per command family (case-sensitive — note the difference)
ABSENT_MSG_SFPUTIL = "SFP EEPROM not detected"   # sfputil family:                     lowercase 'not'
ABSENT_MSG_CLI_INFO = "SFP EEPROM Not detected"   # show interfaces transceiver info:   capital 'Not'


def test_absence_message_verification(duthost, port_attributes_dict):
    """Verify absence error messages for ports with no transceiver installed.

    Step 1 — Discovers all 'Not present' ports via 'show interfaces transceiver presence'.
    Step 2 — For every absent port, attempts all EEPROM / presence operations (sfputil
             and show CLI) and verifies each command returns the expected absence message.

    Expected absence messages are case-sensitive and differ per command family:
        sfputil commands  : "{port}: SFP EEPROM not detected"   (lowercase 'not')
        show transceiver info : "{port}: SFP EEPROM Not detected"  (capital 'Not')
        sfputil hexdump   : "SFP EEPROM not detected"           (no port prefix)
        presence commands : 'Not present' in the Presence column

    Commands verified per absent port:
        1. sudo sfputil show presence -p <port>
        2. show interfaces transceiver presence <port>
        3. sudo sfputil show eeprom -p <port>
        4. show interfaces transceiver info <port>
        5. sudo sfputil show fwversion <port>
        6. sudo sfputil show eeprom-hexdump -p <port>
        7. sudo sfputil read-eeprom -p <port> -n 0 -o 0 -s 1
    """
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping absence message verification on virtual switch testbed")

    # ------------------------------------------------------------------ #
    # Step 1 – Discover all absent ports via show interfaces transceiver  #
    # ------------------------------------------------------------------ #
    result = duthost.command(CMD_SFP_PRESENCE_CLI, module_ignore_errors=True)
    if result.get('rc', RC_FAILURE) != 0:
        pytest.fail(
            f"Presence discovery CLI failed with rc={result.get('rc')}, "
            f"stderr: {result.get('stderr', '')}"
        )

    stdout_lines = result.get('stdout_lines', [])
    if not stdout_lines:
        pytest.fail("Presence discovery CLI returned empty output")

    all_presence = parse_presence(stdout_lines)
    absent_ports = [port for port, status in all_presence.items()
                    if status == PRESENCE_STATUS_NOT_PRESENT]

    if not absent_ports:
        pytest.skip("No absent ports found on DUT; skipping absence message verification")

    logger.info("Absent ports detected (%d): %s", len(absent_ports), absent_ports)

    # ------------------------------------------------------------------ #
    # Step 2 – Verify every command returns the expected absence message  #
    # ------------------------------------------------------------------ #
    all_failures = []

    # Helper: run a command and return (stdout_lines, truncated_stdout_for_display)
    def _run(cmd):
        r = duthost.command(cmd, module_ignore_errors=True)
        lines = r.get('stdout_lines', [])
        display = ' | '.join(lines)[:200] if lines else '<empty>'
        return lines, display

    for port in absent_ports:
        field_failures = []

        # --- Check 1: sfputil show presence -p <port> ---
        # Expected: Presence column == "Not present"
        cmd = f"{CMD_SFP_PRESENCE_SFPUTIL} -p {port}"
        lines, display = _run(cmd)
        status = parse_presence(lines).get(port)
        if status is None:
            field_failures.append(f"[sfputil presence]: '{port}' not in output — got: {display}")
        elif status != PRESENCE_STATUS_NOT_PRESENT:
            field_failures.append(
                f"[sfputil presence]: expected '{PRESENCE_STATUS_NOT_PRESENT}', got '{status}'"
            )

        # --- Check 2: show interfaces transceiver presence <port> ---
        # Expected: Presence column == "Not present"
        cmd = f"{CMD_SFP_PRESENCE_CLI} {port}"
        lines, display = _run(cmd)
        status = parse_presence(lines).get(port)
        if status is None:
            field_failures.append(f"[CLI presence]: '{port}' not in output — got: {display}")
        elif status != PRESENCE_STATUS_NOT_PRESENT:
            field_failures.append(
                f"[CLI presence]: expected '{PRESENCE_STATUS_NOT_PRESENT}', got '{status}'"
            )

        # --- Check 3: sudo sfputil show eeprom -p <port> ---
        # Expected: "{port}: SFP EEPROM not detected"
        expected = f"{port}: {ABSENT_MSG_SFPUTIL}"
        cmd = f"{CMD_SFP_EEPROM_SFPUTIL} -p {port}"
        lines, display = _run(cmd)
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[sfputil show eeprom]: expected '{expected}' — got: {display}"
            )

        # --- Check 4: show interfaces transceiver info <port> ---
        # Expected: "{port}: SFP EEPROM Not detected"  (capital 'N' in 'Not')
        expected = f"{port}: {ABSENT_MSG_CLI_INFO}"
        cmd = f"{CMD_SFP_EEPROM_CLI} {port}"
        lines, display = _run(cmd)
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[CLI transceiver info]: expected '{expected}' — got: {display}"
            )

        # --- Check 5: sudo sfputil show fwversion <port> ---
        # Expected: "{port}: SFP EEPROM not detected"
        expected = f"{port}: {ABSENT_MSG_SFPUTIL}"
        cmd = f"{CMD_SFP_FWVERSION_SFPUTIL} {port}"
        lines, display = _run(cmd)
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[sfputil show fwversion]: expected '{expected}' — got: {display}"
            )

        # --- Check 6: sudo sfputil show eeprom-hexdump -p <port> ---
        # Expected: "SFP EEPROM not detected"  (no port prefix — unique to this command)
        expected = ABSENT_MSG_SFPUTIL
        cmd = f"{CMD_SFP_HEXDUMP_SFPUTIL} -p {port}"
        lines, display = _run(cmd)
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[sfputil show eeprom-hexdump]: expected '{expected}' — got: {display}"
            )

        # --- Check 7: sudo sfputil read-eeprom -p <port> -n 0 -o 0 -s 1 ---
        # Expected: "{port}: SFP EEPROM not detected"
        expected = f"{port}: {ABSENT_MSG_SFPUTIL}"
        cmd = f"{CMD_SFP_READ_EEPROM_SFPUTIL} -p {port} -n 0 -o 0 -s 1"
        lines, display = _run(cmd)
        if not any(expected in line for line in lines):
            field_failures.append(
                f"[sfputil read-eeprom]: expected '{expected}' — got: {display}"
            )

        if field_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(field_failures))

    if all_failures:
        pytest.fail("Absent port message verification failures:\n" + "\n".join(all_failures))
