import logging
import pytest
import re
import string


logger = logging.getLogger(__name__)

# Commands to execute on the device
COMMANDS = [
    "show version"
    "docker ps",
    "show platform summary",
    "show interface status",
    "show ip bgp sum",
    "lspci"
]

pytestmark = [
    pytest.mark.topology('any')
]


def is_ascii(text):
    """Check if all characters in text are ASCII."""
    return all(ord(c) < 128 for c in text)


def test_commands_output_is_ascii(duthost_console):
    """
    Run various commands on the device and verify all output is ASCII.
    
    This test runs a set of common commands and checks if any of them
    produce non-ASCII output, which could indicate encoding issues,
    corruption, or unexpected characters.
    """
    non_ascii_outputs = []
    
    for cmd in COMMANDS:
        logger.info(f"Running command: {cmd}")
        try:
            output = duthost_console.send_command(cmd, expect_string=r"[#$>]")
            
            if not is_ascii(output):
                # Find the non-ASCII characters for better reporting
                non_ascii_chars = [c for c in output if ord(c) >= 128]
                non_ascii_positions = [(i, c, ord(c)) for i, c in enumerate(output) if ord(c) >= 128]
                non_ascii_outputs.append({
                    "command": cmd,
                    "non_ascii_chars": non_ascii_chars[:10],  # First 10 non-ASCII chars
                    "positions": non_ascii_positions[:5],     # First 5 positions
                })
        except Exception as e:
            logger.error(f"Error executing command '{cmd}': {str(e)}")
    
    # Generate detailed error message if non-ASCII characters were found
    if non_ascii_outputs:
        error_msg = "Non-ASCII characters detected in command outputs:\n"
        for item in non_ascii_outputs:
            error_msg += f"\nCommand: {item['command']}\n"
            error_msg += f"Non-ASCII chars found: {item['non_ascii_chars']}\n"
            error_msg += "Sample positions (index, char, ord): \n"
            for pos, char, ord_val in item['positions']:
                error_msg += f"  Position {pos}: '{char}' (ord={ord_val})\n"
        
        logger.error(error_msg)
        assert False, error_msg
    
    assert True, "All command outputs contain only ASCII characters"
