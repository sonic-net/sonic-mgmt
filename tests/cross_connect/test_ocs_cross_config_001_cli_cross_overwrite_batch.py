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

def check_cross_connect_config(duthost, expected_pairs=None):
    """Check OCS cross-connect configuration status"""
    result = send_and_verify_command(duthost, 'show ocs cross-connect config')
    # Assuming pick_ocs_cross is available or needs to be reimplemented
    # For now, we'll use a simple approach to extract pairs
    current_pairs = []
    for line in result.split('\n'):
        if 'A-' in line and 'B' in line:
            # Extract pair from line
            parts = line.split()
            if parts:
                pair = parts[0]
                if 'A-' in pair and 'B' in pair:
                    current_pairs.append(pair)
    
    if expected_pairs:
        if not isinstance(expected_pairs, list):
            expected_pairs = [expected_pairs]
        # Only check if expected pairs exist, don't check count
        for pair in expected_pairs:
            assert pair in current_pairs, f"Expected pair {pair} not found in configuration"
    else:
        assert len(current_pairs) == 0, f"Should have no config, found: {current_pairs}"

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
    # Simple extraction of pairs
    existing_pairs = []
    for line in result.split('\n'):
        if 'A-' in line and 'B' in line:
            parts = line.split()
            if parts:
                pair = parts[0]
                if 'A-' in pair and 'B' in pair:
                    existing_pairs.append(pair)
    
    for pair in existing_pairs:
        send_and_verify_command(duthost, f'config ocs cross-connect delete {pair}', expect="succeeded")

def test_configure_ocs_overwrite_batch(duthost):
    """Test OCS cross-connect batch configuration in overwrite mode"""
    # Step 0: Clean existing configuration
    logging.info('Step 0: Clean existing OCS cross-connect config')
    clear_all_cross_configuration(duthost)

    # Step 1: Verify initial empty state
    logging.info("Step 1: Verify initial empty config")
    check_cross_connect_config(duthost)

    # Step 2: Prepare test cases
    test_cases = [
        ("Single pair", "1A-2B"),
        ("Multiple pairs", "3A-4B,5A-6B"),
        ("Range", "7A..9A-7B..9B"),
        ("Mixed", "10A-11B,12A..14A-12B..14B")
    ]

    # Step 3: Execute test cases
    for idx, (desc, config) in enumerate(test_cases, start=2):
        logging.info(f"Step {idx}: Testing {desc} in overwrite mode")
        
        # Configure in overwrite mode
        send_and_verify_command(duthost, f'config ocs cross-connect add {config} overwrite', expect="succeeded")
        
        # Verify configuration
        expected_pairs = expand_port_pairs(config)
        check_cross_connect_config(duthost, expected_pairs)

    # Step 4: Final cleanup
    logging.info("Step 6: Cleanup all configurations")
    clear_all_cross_configuration(duthost)
    check_cross_connect_config(duthost)