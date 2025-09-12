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

def test_configure_ocs_safe_batch(duthost):
    """Test OCS cross-connect batch configuration in safe mode"""
    # Clean existing configuration
    logging.info('Step 0: Clean existing OCS cross-connect config')
    clear_all_cross_configuration(duthost)

    # Verify initial empty state
    logging.info("Step 1: Verify initial empty config")
    result = send_and_verify_command(duthost, 'show ocs cross-connect config')
    assert len(pick_ocs_cross(result)) == 0, "Initial config not empty"

    # Generate sorted unique port list
    ports = sorted(random.sample(range(1, 65), 20))
    
    # Define fixed ranges and excluded ports
    mode2_range = range(24, 28)  # 24-27 (offset 4)
    mode3_range = range(34, 38)  # 34-37 (offset 4)
    excluded_ports = list(mode2_range) + list(mode3_range)
    
    # Generate random ports outside fixed ranges
    available_ports = [p for p in range(1, 65) if p not in excluded_ports]
    random_ports = sorted(random.sample(available_ports, 6))  # 6 ports for mode1 and mode3 single pairs
    
    # Define batch configurations
    batches = [
        # Mode1: Comma-separated random pairs (outside fixed ranges)
        f"{random_ports[0]}A-{random_ports[1]}B,{random_ports[2]}A-{random_ports[3]}B",
        # Mode2: Fixed range (24-27A/B)
        f"24A..27A-24B..27B",
        # Mode3: Mixed mode (single pair + fixed range 34-37A/B)
        f"{random_ports[4]}A-{random_ports[5]}B,34A..37A-34B..37B"
    ]

    # Execute batch configurations
    for i, batch in enumerate(batches, start=2):
        logging.info(f"Step {i}: Execute batch mode {i-1} configuration")
        send_and_verify_command(duthost, f'config ocs cross-connect add {batch} safe', expect="succeeded")

    # Verify final configuration - check each pair individually
    logging.info("Step 5: Verify final configuration - detailed check")
    final_config = send_and_verify_command(duthost, 'show ocs cross-connect config')
    final_pairs = pick_ocs_cross(final_config)
    
    # Verify all expected pairs exist
    expected_pairs = [
        f"{random_ports[0]}A-{random_ports[1]}B",
        f"{random_ports[2]}A-{random_ports[3]}B",
        *[f"{p}A-{p}B" for p in range(24, 28)],  # Mode2 pairs
        f"{random_ports[4]}A-{random_ports[5]}B",
        *[f"{p}A-{p}B" for p in range(34, 38)]   # Mode3 range pairs
    ]
    
    for pair in expected_pairs:
        assert pair in final_pairs, f"Expected pair {pair} not found in configuration"

    # Cleanup in reverse order with verification after each deletion
    logging.info("Step 6: Cleanup configurations with verification")
    for batch in reversed(batches):
        # Delete the batch
        send_and_verify_command(duthost, f'config ocs cross-connect delete {batch}', expect="succeeded")
        
        # Verify the deleted pairs are actually removed
        current_config = send_and_verify_command(duthost, 'show ocs cross-connect config')
        current_pairs = pick_ocs_cross(current_config)
        deleted_pairs = expand_port_pairs(batch)  # Use expand_port_pairs instead of pick_ocs_cross
        for pair in deleted_pairs:
            assert pair not in current_pairs, f"Pair {pair} was not properly deleted"

    # Final verification - check for any remaining configurations
    logging.info("Step 7: Final verification - check for any residual configs")
    empty_config = send_and_verify_command(duthost, 'show ocs cross-connect config')
    remaining_pairs = pick_ocs_cross(empty_config)
    if remaining_pairs:
        pytest.fail(f"Found residual configurations after cleanup: {remaining_pairs}")