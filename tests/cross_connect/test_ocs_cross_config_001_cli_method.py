   
import pytest
import random
import logging


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
]


def clear_all_cross_configuration(duthost):
    """Clean up all existing cross-connect configurations"""
    existed_cross = duthost.show_and_parse('show ocs cross-connect config')
    cross_connect_pair = []
    if len(existed_cross) != 0:
        for each_cross in existed_cross:
            cross_connect_pair.append(each_cross['id'])
    if cross_connect_pair != []:
        for delete_cross in cross_connect_pair:
            duthost.shell(f'sudo config ocs cross-connect delete {delete_cross}')


def test_configure_ocs_methods(duthost):
    """Verify OCS cross-connect configuration mode options and cleanup after test"""
    # Step 1: Clean environment - Query and remove all existing cross-connects
    clear_all_cross_configuration(duthost)

    # Step 2: Verify available configuration modes via help command
    result = duthost.shell('sudo config ocs cross-connect add 1A-1B --help', module_ignore_errors=True)
    response = result['stdout']
    expected_modes = "safe|update|overwrite"
    assert expected_modes in response, \
        f"OCS cross-connect mode options verification failed. " \
        f"Expected '{expected_modes}' in response, actual response: {response}"

    # Step 3: Test each configuration mode with unique random port pairs
    used_pairs = set()
    for mode in ['safe', 'update', 'overwrite']:
        # Generate unique random port pair that hasn't been used yet
        while True:
            port_a, port_b = random.sample(range(1, 65), 2)
            port_pair = f"{port_a}A-{port_b}B"
            if port_pair not in used_pairs:
                used_pairs.add(port_pair)
                break
        
        # Test configuration with current mode and port pair
        cmd = f"sudo config ocs cross-connect add {port_pair} {mode}"
        result = duthost.shell(cmd, module_ignore_errors=True)
        assert result['rc'] == 0 and "succeeded" in result['stdout'].lower(), \
            f"Failed to configure cross-connect in {mode} mode: {result['stderr'] or result['stdout']}"
        
        # Verify the configuration was added
        configured_cross = duthost.show_and_parse('show ocs cross-connect config')
        assert any(cross['id'] == port_pair for cross in configured_cross), \
            f"Failed to verify cross-connect configuration {port_pair} in {mode} mode"
        
        # Immediate cleanup after each test
        result = duthost.shell(f'sudo config ocs cross-connect delete {port_pair}', module_ignore_errors=True)
        assert result['rc'] == 0 and "succeeded" in result['stdout'].lower(), \
            f"Failed to cleanup {port_pair} after {mode} test: {result['stderr'] or result['stdout']}"

    # Step 4: Final verification - Ensure no remaining configurations
    clear_all_cross_configuration(duthost)
    final_cross_configs = duthost.show_and_parse('show ocs cross-connect config')
    assert len(final_cross_configs) == 0, \
        f"Final cleanup verification failed. Remaining configurations: {final_cross_configs}"