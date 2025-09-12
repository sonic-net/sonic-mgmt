import pytest
import logging
import random
import re

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

def test_configure_ocs_delete(duthost):
    """Test OCS cross-connect deletion functionality with random port pairs"""
    # Step 1: Get existing cross-connect configurations
    logging.info('Step 1: Get existing cross-connect configs')
    existing_config = send_and_verify_command(duthost, 'show ocs cross-connect config')
    used_ports = set()
    
    # Extract used ports from existing config
    port_pattern = re.compile(r'(\d+)[ab]-(\d+)[ab]')
    for match in port_pattern.finditer(existing_config):
        used_ports.add(match.group(1))
        used_ports.add(match.group(2))
    
    # Step 2: Select random available ports (1-64 range)
    available_ports = [str(p) for p in range(1, 65) if str(p) not in used_ports]
    if len(available_ports) < 2:
        pytest.skip("Not enough available ports for testing")
    
    port_a, port_b = random.sample(available_ports, 2)
    target_port = f"{port_a}a-{port_b}b"
    
    # Step 3: Configure random cross-connect
    logging.info('Step 3: Configure random cross-connect')
    send_and_verify_command(duthost, f'config ocs cross-connect add {target_port} update', 
                        expect="succeeded")
    
    # Step 4: Delete the configured cross-connect
    logging.info('Step 4: Delete the cross-connect')
    send_and_verify_command(duthost, f'config ocs cross-connect delete {target_port}', 
                         expect="succeeded")
    
    # Step 5: Verify deletion by checking config
    logging.info('Step 5: Verify deletion')
    rtn = send_and_verify_command(duthost, 'show ocs cross-connect config')
    cross_pair = pick_ocs_cross(rtn)
    
    # Check if the deleted pair still exists
    if target_port in rtn:
        pytest.fail(f"Failed to delete cross-connect {target_port}")
    
    # Additional verification: Try to delete again (should fail)
    logging.info('Step 6: Verify deletion by attempting to delete again')
    second_delete_result = send_and_verify_command(duthost, f'config ocs cross-connect delete {target_port}')
    if ("succeeded" in second_delete_result.lower() or 
        "does not exist" not in second_delete_result.lower()):
        pytest.fail(f"Unexpected response when deleting already-deleted cross-connect {target_port}: {second_delete_result}")