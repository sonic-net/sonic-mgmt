"""
CLI Parser Helper for various transceiver related commands
"""
import re


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
