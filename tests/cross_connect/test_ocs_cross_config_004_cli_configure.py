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

def test_configure_ocs_configuration(duthost):
    """Test OCS cross-connect configuration visibility across multiple query interfaces"""
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
    target_port = f"{port_a}A-{port_b}B"

    # Step 3: Configure random cross-connect
    logging.info('Step 3: Configure random cross-connect')
    send_and_verify_command(duthost, f'config ocs cross-connect add {target_port} update',
                 expect="succeeded")

    # Step 4: Verify in cross-connect config
    logging.info('Step 4: Verify in cross-connect config')
    config_rtn = send_and_verify_command(duthost, 'show ocs cross-connect config')
    assert target_port in config_rtn, \
        f"Configured port pair {target_port} not found in cross-connect config"

    # Step 5: Verify in cross-connect status
    logging.info('Step 5: Verify in cross-connect status')
    status_rtn = send_and_verify_command(duthost, 'show ocs cross-connect status')
    assert target_port in status_rtn, \
        f"Configured port pair {target_port} not found in cross-connect status"

    # Step 6: Verify in port status
    logging.info('Step 6: Verify in port status')
    port_status_rtn = send_and_verify_command(duthost, 'show ocs port status')

    # common pick
    for status_line in port_status_rtn.splitlines():
        if "LC UPC" in status_line:
            port_val = status_line.split()
            if len(port_val) == 6:
                val = port_val[4]
                if port_val[0] in [f'{port_a}A', f'{port_b}B']:
                    assert val in [f'{port_a}A', f'{port_b}B'], \
                        f"Configured port pair {target_port} show error in port status"
                    assert 'blocked' not in status_line, \
                        f"Configured port pair {target_port} port status error"

    # Step 7: Clear configuration
    logging.info('Step 7: Clear ocs cross-connect')
    send_and_verify_command(duthost, f'config ocs cross-connect delete {target_port}',
                 expect="succeeded")