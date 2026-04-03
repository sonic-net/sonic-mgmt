import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.disable_memory_utilization
]


def test_console_stress_output(duthost_console):
    """
    Test console stability by reading large output from the DUT through the console.

    This test executes commands that generate large output, forcing the console
    to read and process substantial amounts of data coming FROM the DUT.

    Args:
        duthost_console: Console connection fixture (from tests/conftest.py)

    The test verifies:
    - Console can read large command outputs without hanging
    - Console can process commands that output substantial data
    - Console remains responsive after reading large outputs
    - Output data integrity is preserved through the console (exact content verification)
    """
    # Generate large output using Python script with verifiable structure
    # Each line: "LINE_XXXX: " + 10 blocks of '0123456789' (110 chars per line)
    # Generate 1000 lines = 110,000 chars total
    num_lines = 1000
    output = duthost_console.send_command(
        f"python3 -c \"for i in range({num_lines}): print(f'LINE_{{i:04d}}: ' + '0123456789' * 10)\"",
        max_loops=300
    )

    # Parse output into lines
    lines = output.split('\n')

    # Filter to only lines that match our expected pattern
    pattern_lines = [line.strip() for line in lines if line.strip().startswith('LINE_')]

    # Verify we got the expected number of lines
    pytest_assert(len(pattern_lines) == num_lines,
                  f"Expected {num_lines} lines, got {len(pattern_lines)} lines")

    # Verify exact content of each line
    for line_idx, line in enumerate(pattern_lines):
        expected_line = f"LINE_{line_idx:04d}: " + '0123456789' * 10
        pytest_assert(line == expected_line,
                      f"Line {line_idx}: Content mismatch\n"
                      f"Expected: '{expected_line}'\n"
                      f"Got:      '{line}'")

    # Verify console is still responsive
    response = duthost_console.send_command("echo test_responsive")
    pytest_assert("test_responsive" in response, "Console not responsive after large output")


def test_console_stress_input(duthost_console):
    """
    Test console stability by sending large input to the DUT through the console.

    This test sends a large string via echo command to verify the console
    can handle large input without data loss.

    Args:
        duthost_console: Console connection fixture (from tests/conftest.py)

    The test verifies:
    - Console can accept large command inputs without hanging
    - All input characters are successfully transmitted and echoed back
    - Console remains responsive after large input
    """
    # Generate a large string to send as input
    # Use 100,000 characters: 10,000 repetitions of '0123456789'
    large_string = '0123456789' * 10000  # 100,000 chars

    # Send the large string via echo and capture the output
    output = duthost_console.send_command(
        f"echo '{large_string}'",
        max_loops=300
    )

    # Verify the output matches what we sent
    pytest_assert(output.strip() == large_string,
                  f"Echo output mismatch: expected {len(large_string)} chars, got {len(output.strip())} chars")

    # Verify console is still responsive
    response = duthost_console.send_command("echo test_responsive")
    pytest_assert("test_responsive" in response,
                  "Console not responsive after large input")
