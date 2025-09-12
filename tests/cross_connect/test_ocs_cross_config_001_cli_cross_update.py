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

def check_cross_connect_config(duthost, expected_port: str = None) -> None:
    """Check OCS cross-connect configuration status"""
    result = send_and_verify_command(duthost, 'show ocs cross-connect config')
    current_pairs = pick_ocs_cross(result)
    
    if expected_port:
        assert len(current_pairs) == 1, f"Should have 1 config, found {len(current_pairs)}"
        assert current_pairs[0] == expected_port, f"Expected {expected_port}, got {current_pairs[0]}"
    else:
        assert len(current_pairs) == 0, f"Should have no config, found: {current_pairs}"

def test_configure_ocs_update(duthost):
    """Test OCS cross-connect configuration in update mode"""
    # Step 0: Clean existing configuration
    logging.info('Step 0: Clean existing OCS cross-connect config')
    clear_all_cross_configuration(duthost)

    # Step 1: Verify initial empty state
    logging.info("Step 1: Verify initial empty config")
    check_cross_connect_config(duthost)

    # Step 2: Add first random cross-connect in update mode
    logging.info("Step 2: Add first cross-connect in update mode")
    port_a, port_b = random.sample(range(1, 65), 2)
    initial_pair = f"{port_a}A-{port_b}B"
    send_and_verify_command(duthost, f'config ocs cross-connect add {initial_pair} update', 
                         expect="succeeded")

    # Step 3: Verify first configuration
    logging.info("Step 3: Verify first configuration")
    check_cross_connect_config(duthost, initial_pair)

    # Step 4: Test update mode with same port pair (should succeed)
    logging.info("Step 4: Test update mode with same port pair")
    send_and_verify_command(duthost, f'config ocs cross-connect add {initial_pair} update', 
                         expect="succeeded")
    check_cross_connect_config(duthost, initial_pair)

    # Step 5: Test update mode with new port pair (should update)
    logging.info("Step 5: Test update mode with new port pair")
    new_port_b = random.choice([p for p in range(1,65) if p != port_b])
    updated_pair = f"{port_a}A-{new_port_b}B"
    send_and_verify_command(duthost, f'config ocs cross-connect add {updated_pair} update', 
                         expect="succeeded")

    # Step 6: Verify configuration is updated
    logging.info("Step 6: Verify config is updated")
    check_cross_connect_config(duthost, updated_pair)

    # Step 7: Cleanup
    logging.info("Step 7: Cleanup configuration")
    send_and_verify_command(duthost, f'config ocs cross-connect delete {updated_pair}', 
                         expect="succeeded")
    check_cross_connect_config(duthost)