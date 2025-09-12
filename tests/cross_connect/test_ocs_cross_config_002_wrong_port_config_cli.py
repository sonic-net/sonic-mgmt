import pytest
import logging
import random

pytestmark = [
    pytest.mark.disable_loganalyzer,
]

def send_and_verify_command(duthost, cmd: str, expect: str = None):
    """Send command via duthost and verify result"""
    result = duthost.shell(cmd, module_ignore_errors=True)
    if expect:
        assert expect in result['stdout'], f"Expected '{expect}' in response, got: {result['stdout']}"
    return result['stdout']

def pick_ocs_cross(output):
    """Extract OCS cross-connect pairs from command output"""
    pairs = []
    for line in output.split('\n'):
        if 'A-' in line and 'B' in line:
            parts = line.split()
            if parts:
                pair = parts[0]
                if 'A-' in pair and 'B' in pair:
                    pairs.append(pair)
    return pairs

def clear_all_cross_configuration(duthost):
    """Clear all existing cross-connect configurations"""
    result = send_and_verify_command(duthost, 'show ocs cross-connect config')
    existing_pairs = pick_ocs_cross(result)
    
    for pair in existing_pairs:
        send_and_verify_command(duthost, f'config ocs cross-connect delete {pair}', expect="succeeded")

def test_invalid_port_configuration(duthost):
    # Step 0: Clean existing configuration
    logging.info('Step 0: Clean existing OCS cross-connect config')
    clear_all_cross_configuration(duthost)
    
    # Generate out-of-range port pair (e.g., 65A-66B where valid range is 1-64)
    invalid_a_port = 65  # A port number exceeding valid range (1-64)
    invalid_b_port = 66  # B port number exceeding valid range (1-64)
    invalid_port = f"{invalid_a_port}A-{invalid_b_port}B"  # Invalid port pair

    # Step 1: Attempt to configure invalid port pair
    logging.info('Step 1: attempt to config invalid ocs cross-connect')
    config_response = send_and_verify_command(duthost, f'config ocs cross-connect add {invalid_port} update')

    # Verify configuration command failed (should not return "succeeded")
    assert "succeeded" not in config_response, \
        f"Unexpected success when configuring invalid port {invalid_port}"

    # Step 2: Verify invalid port not in configuration table
    logging.info('Step 2: check ocs cross-connect config for invalid port')
    config_table = send_and_verify_command(duthost, f'show ocs cross-connect config')
    assert invalid_port not in config_table, \
        f"Invalid port {invalid_port} unexpectedly found in configuration table"

    # Step 3: Verify invalid port not in status table
    logging.info('Step 3: check ocs cross-connect status for invalid port')
    status_table = send_and_verify_command(duthost, 'show ocs cross-connect status')
    assert invalid_port not in status_table, \
        f"Invalid port {invalid_port} unexpectedly found in status table"

    # Step 4: Test valid cross-connect with update mode
    logging.info('Step 4: Test valid cross-connect with update mode')
    valid_a_port = random.randint(1, 64)
    valid_b_port = random.randint(1, 64)
    valid_port = f"{valid_a_port}A-{valid_b_port}B"

    # Configure with update mode
    send_and_verify_command(duthost, f'config ocs cross-connect add {valid_port} update',
                         expect="succeeded")

    # Verify configuration exists
    config_table = send_and_verify_command(duthost, 'show ocs cross-connect config')
    assert valid_port in config_table, \
        f"Valid port {valid_port} not found in configuration table"

    # Step 5: Cleanup valid configuration
    logging.info('Step 5: Cleanup valid cross-connect')
    send_and_verify_command(duthost, f'config ocs cross-connect delete {valid_port}',
                         expect="succeeded")

    # Verify cleanup
    config_table = send_and_verify_command(duthost, 'show ocs cross-connect config')
    assert valid_port not in config_table, \
        f"Valid port {valid_port} still exists after cleanup"