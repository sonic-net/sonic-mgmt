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

def expand_port_pairs(config_str):
    """Expand configuration string into individual port pairs"""
    pairs = []
    for part in config_str.split(','):
        if '..' in part:  # Handle range syntax
            a_side, b_side = part.split('-')
            a_start, a_end = [int(p[:-1]) for p in a_side.split('..')]
            b_start, b_end = [int(p[:-1]) for p in b_side.split('..')]
            for a, b in zip(range(a_start, a_end+1), range(b_start, b_end+1)):
                pairs.append(f"{a}A-{b}B")
        else:  # Single pair
            pairs.append(part)
    return pairs

def clear_all_cross_configuration(duthost):
    """Clear all existing cross-connect configurations"""
    result = send_and_verify_command(duthost, 'show ocs cross-connect config')
    existing_pairs = pick_ocs_cross(result)
    
    for pair in existing_pairs:
        send_and_verify_command(duthost, f'config ocs cross-connect delete {pair}', expect="succeeded")

def check_cross_connect_config(duthost, expected_pairs=None):
    """Verify current OCS cross-connect configuration matches expected pairs"""
    result = send_and_verify_command(duthost, 'show ocs cross-connect config')
    current_pairs = pick_ocs_cross(result)
    
    if expected_pairs:
        if not isinstance(expected_pairs, list):
            expected_pairs = [expected_pairs]
        for pair in expected_pairs:
            assert pair in current_pairs, f"Expected pair {pair} not found in configuration"
    else:
        assert len(current_pairs) == 0, "Configuration should be empty but found existing pairs"

def get_available_ports(duthost):
    """Retrieve available ports excluding fixed ranges (24-27, 34-37)"""
    fixed_ranges = set(range(24,28)) | set(range(34,38))
    config = send_and_verify_command(duthost, 'show ocs cross-connect config')
    used_ports = {int(pair.split('-')[0][:-1]) for pair in pick_ocs_cross(config)}
    return [p for p in range(1, 65) if p not in used_ports and p not in fixed_ranges]

def test_configure_ocs_update_batch(duthost):
    """Test batch configuration of OCS cross-connect in update mode"""
    # Clean existing configuration
    logging.info('Step 0: Clean existing OCS cross-connect config')
    clear_all_cross_configuration(duthost)

    # Verify clean state
    logging.info("Step 1: Verify initial empty config")
    check_cross_connect_config(duthost)

    # Prepare test ports
    available_ports = get_available_ports(duthost)
    assert len(available_ports) >= 20, "Insufficient available ports for testing"
    
    # Define test ranges and generate random ports
    excluded_ports = list(range(24,28)) + list(range(34,38))
    random_ports = sorted(random.sample([p for p in available_ports if p not in excluded_ports], 6))
    
    # Define test cases
    test_cases = [
        ("Comma-separated pairs", f"{random_ports[0]}A-{random_ports[1]}B,{random_ports[2]}A-{random_ports[3]}B"),
        ("Fixed range", "24A..27A-24B..27B"),
        ("Mixed mode", f"{random_ports[4]}A-{random_ports[5]}B,34A..37A-34B..37B")
    ]

    # Execute test cases and collect all expected pairs
    all_expected_pairs = []
    for idx, (desc, config) in enumerate(test_cases, start=2):
        logging.info(f"Step {idx}: Testing {desc} in update mode")
        send_and_verify_command(duthost, f'config ocs cross-connect add {config} update', 
                              expect="succeeded")
        all_expected_pairs.extend(expand_port_pairs(config))

    # Final verification - check all expected pairs exist
    logging.info("Step 4: Verify all configured pairs exist")
    result = send_and_verify_command(duthost, 'show ocs cross-connect config')
    current_pairs = pick_ocs_cross(result)
    
    # Verify each expected pair exists in current configuration
    for pair in all_expected_pairs:
        assert pair in current_pairs, f"Configured pair {pair} not found in final configuration"

    # Cleanup
    logging.info("Step 5: Cleanup test configurations")
    for _, config in reversed(test_cases):
        send_and_verify_command(duthost, f'config ocs cross-connect delete {config}', 
                              expect="succeeded")
    check_cross_connect_config(duthost)

    range_update_covering_single_pair(duthost)

def range_update_covering_single_pair(duthost):
    """Independent test scenario: Verify range update can cover single pair"""
    # Clean existing configuration
    logging.info('Step 0: Clean existing OCS cross-connect config')
    clear_all_cross_configuration(duthost)
    check_cross_connect_config(duthost)

    # 1. Configure single pair within the range
    single_pair = "25A-26B"
    send_and_verify_command(duthost, f'config ocs cross-connect add {single_pair}', 
                          expect="succeeded")
    
    # 2. Verify single pair exists by checking config output directly
    result = send_and_verify_command(duthost, 'show ocs cross-connect config')
    assert single_pair in result, f"Single pair {single_pair} not found in configuration"
    
    # 3. Update with range that covers the single pair
    range_config = "24A..27A-24B..27B"
    send_and_verify_command(duthost, f'config ocs cross-connect add {range_config} update', 
                          expect="succeeded")
    
    # 4. 只验证新配置的范围条目是否存在
    expected_pairs = expand_port_pairs(range_config)
    check_cross_connect_config(duthost, expected_pairs)
    
    # 5. Cleanup range configuration
    send_and_verify_command(duthost, f'config ocs cross-connect delete {range_config}', 
                          expect="succeeded")
    check_cross_connect_config(duthost)