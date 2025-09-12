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

def test_configure_ocs_safe(duthost):
    """Test OCS cross-connect configuration in safe mode using CLI only"""
    # Step 0: Clean existing configuration
    logging.info('Step 0: Clean existing OCS cross-connect config')
    clear_all_cross_configuration(duthost)

    # Step 1: Verify initial empty state
    logging.info("Step 1: Verify initial empty config")
    current_config = send_and_verify_command(duthost, 'show ocs cross-connect config')
    remaining_pairs = pick_ocs_cross(current_config)
    assert len(remaining_pairs) == 0, "Initial config not empty"

    # Step 2: Add first random cross-connect in safe mode
    logging.info("Step 2: Add first random cross-connect in safe mode")
    port_a, port_b = random.sample(range(1, 65), 2)
    target_pair = f"{port_a}A-{port_b}B"

    send_and_verify_command(duthost, f'config ocs cross-connect add {target_pair} safe',
                 expect="succeeded")

    # Step 3: Verify first configuration
    logging.info("Step 3: Verify first configuration")
    rtn = send_and_verify_command(duthost, 'show ocs cross-connect config')
    cross_pair = pick_ocs_cross(rtn)
    assert len(cross_pair) == 1 and cross_pair[0] == target_pair, \
        "First configuration verification failed"

    # Step 4: Test safe mode with same port pair (should succeed)
    logging.info("Step 4: Test safe mode with same port pair")
    send_and_verify_command(duthost, f'config ocs cross-connect add {target_pair} safe',
                 expect="succeeded")

    # Step 5: Test safe mode with conflicting port pair (should fail)
    logging.info("Step 5: Test safe mode with conflicting port pair")
    conflict_port = f"{port_a}A-{random.choice([p for p in range(1, 65) if p != port_b])}B"
    rtn = send_and_verify_command(duthost, f'config ocs cross-connect add {conflict_port} safe')
    assert f"existing cross-connect {target_pair}" in rtn, \
        f"Expected conflict error with {target_pair} not found"

    # Step 6: Verify configuration remains unchanged
    logging.info("Step 6: Verify config remains unchanged after conflict")
    rtn = send_and_verify_command(duthost, 'show ocs cross-connect config')
    cross_pair = pick_ocs_cross(rtn)
    assert len(cross_pair) == 1 and cross_pair[0] == target_pair, \
        "Configuration changed unexpectedly"

    # Step 7: Cleanup
    logging.info("Step 7: Cleanup configuration")
    send_and_verify_command(duthost, f'config ocs cross-connect delete {target_pair}',
                 expect="succeeded")