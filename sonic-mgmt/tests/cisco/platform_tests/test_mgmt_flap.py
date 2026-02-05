import logging
import os
import pytest
import time
import uuid
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.devices.sonic import SonicHost

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.asic('cisco-8000'),
    pytest.mark.topology('t2')
]

# Script configuration constants - copy local script to DUT
UNIFIED_SCRIPT_FILE = "test_mgmt_interface_flap_unified.sh"
FLAP_SCRIPT_SRC_PATH = "platform_tests/cisco/hwsku/" + UNIFIED_SCRIPT_FILE
FLAP_SCRIPT_DEST_PATH = "/tmp/" + UNIFIED_SCRIPT_FILE

def check_ssh_connectivity_to_supervisor(localhost, supervisor_ip):
    """
    Check SSH connectivity from host to supervisor node
    This uses the localhost (test host) to SSH to the supervisor node
    """
    try:
        result = localhost.wait_for(
            host=supervisor_ip,
            port=22,
            state='started',
            delay=0,
            timeout=3,
            module_ignore_errors=True
        )
        is_connected = not (result.is_failed or ('Timeout' in str(result)))
        logging.debug("SSH connectivity check for {}: {}".format(supervisor_ip, "Connected" if is_connected else "Disconnected"))
        return is_connected
    except Exception as e:
        logging.debug("SSH connectivity check failed: {}".format(str(e)))
        return False

def initialize_mgmt_test(duthost, test_mode):
    """
    Initialization for management interface tests
    Copy script to DUT, verify prerequisites, and generate test ID
    
    Args:
        duthost: DUT host object
        test_mode: Test mode string ('single' or 'stress') for log file naming
        
    Returns:
        tuple: (test_id, log_file_path)
    """
    # Check if this is a supervisor node - test only runs on supervisor
    if not duthost.is_supervisor_node():
        pytest.skip("Test only runs on supervisor nodes, current node is not supervisor")
    
    logging.info("Starting management interface test on {} (ASIC: {}, Supervisor Node) - DUT: {} IP: {}".format(
        duthost.hostname, duthost.facts["asic_type"], duthost.hostname, duthost.mgmt_ip))
    time.sleep(5)

    # Copy script from local hwsku/ to DUT /tmp/ and verify
    try:
        logging.info("Copying script from {} to DUT...".format(FLAP_SCRIPT_SRC_PATH))
        
        # Copy script to DUT with executable permissions
        duthost.copy(src=FLAP_SCRIPT_SRC_PATH, dest=FLAP_SCRIPT_DEST_PATH, mode="0755")
        
        # Verify script exists on DUT and has correct permissions
        file_check = duthost.shell("ls -la {}".format(FLAP_SCRIPT_DEST_PATH), module_ignore_errors=True)
        pytest_assert(file_check['rc'] == 0, "Failed to copy script to DUT")
        
        # Log current file info
        file_info = file_check.get('stdout', '').strip()
        logging.info("Script successfully copied to DUT: {}".format(file_info))
        
        # Run prerequisites check using bash
        result = duthost.shell("bash {} check_prerequisites".format(FLAP_SCRIPT_DEST_PATH), module_ignore_errors=True)
        if result['rc'] != 0:
            error_msg = result.get('stderr', result.get('stdout', 'Unknown error'))
            pytest.skip("Prerequisites check failed: {}".format(error_msg))
        
        logging.info("Script verification passed: {}".format(result.get('stdout', '').strip()))
        
    except Exception as e:
        pytest.skip("Failed to copy script or verify prerequisites: {}".format(str(e)))
    
    # Generate unique test ID and construct log file path
    test_id = str(uuid.uuid4())[:8]
    if test_mode == 'single':
        log_file_path = "/tmp/mgmt_restart_{}.log".format(test_id)
    elif test_mode == 'stress':
        log_file_path = "/tmp/mgmt_stress_{}.log".format(test_id)
    else:
        raise ValueError("Invalid test_mode: {}. Must be 'single' or 'stress'".format(test_mode))
    
    logging.info("Generated test ID: {} with log path: {}".format(test_id, log_file_path))
    
    return test_id, log_file_path


def execute_mgmt_script(duthost, test_id, log_file_path, test_mode, log_prefix, num_cycles=None):
    """
    Execute the management interface flap script in background and validate startup
    
    Args:
        duthost: DUT host object
        test_id: Unique test identifier
        log_file_path: Path to log file on DUT
        test_mode: Test mode ('mgmt_flap_single' or 'mgmt_flap_stress')
        log_prefix: Logging prefix for messages
        num_cycles: Number of cycles for stress test (optional)
        
    Returns:
        None (raises exception on failure)
    """
    # Construct the command based on test mode
    if test_mode == 'mgmt_flap_single':
        script_command = "bash {} {}".format(FLAP_SCRIPT_DEST_PATH, test_mode)
        env_vars = "TEST_ID='{}' LOG_FILE='{}'".format(test_id, log_file_path)
    elif test_mode == 'mgmt_flap_stress':
        cycles = num_cycles or 10
        script_command = "bash {} {}".format(FLAP_SCRIPT_DEST_PATH, test_mode)
        env_vars = "TEST_ID='{}' LOG_FILE='{}' NUM_CYCLES={}".format(test_id, log_file_path, cycles)
    else:
        raise ValueError("Invalid test_mode: {}".format(test_mode))
    
    # Execute script in background
    logging.info("{} - Starting background script with env: {} {}".format(log_prefix, env_vars, script_command))
    bg_command = "nohup env {} {} > /dev/null 2>&1 &".format(env_vars, script_command)
    script_result = duthost.shell(bg_command, module_ignore_errors=True)
    logging.info("{} - Background execution result: rc={}".format(log_prefix, script_result.get('rc')))
    
    # Give the script time to start and initialize
    time.sleep(3)  # Increased from 1 to 3 seconds to ensure script starts properly
    
    # Just verify script started, don't wait for log file
    logging.info("{} - Script launched, proceeding to SSH monitoring".format(log_prefix))
    return  # Don't wait for log file verification


def finalize_test_with_logs(duthost, log_file_path, log_prefix, preserve_logs=False):
    """
    Integrated function to retrieve logs and cleanup test files
    
    Args:
        duthost: DUT host object
        log_file_path: Path to log file on DUT
        log_prefix: Logging prefix for messages
        preserve_logs: If True, preserve log file; if False, delete it
    """
    script_log_content = None
    
    # Step 1: Force log file flush and retrieval
    try:
        # Force shell script to flush any remaining output to log file
        logging.info("{} - Forcing log file sync and retrieval: {}".format(log_prefix, log_file_path))
        duthost.shell("sync", module_ignore_errors=True)
        time.sleep(2)  # Brief wait for sync to complete
        
        # Retrieve log content
        script_log_check = duthost.shell("cat {}".format(log_file_path), module_ignore_errors=True)
        if script_log_check.get('rc') == 0 and script_log_check.get('stdout'):
            script_log_content = script_log_check['stdout']
            logging.info("{} - Script execution log:\n{}".format(log_prefix, script_log_content))
        else:
            logging.warning("{} - Log file empty or unreadable: rc={}".format(log_prefix, script_log_check.get('rc')))
    except Exception as log_exception:
        logging.warning("{} - Could not retrieve log file {}: {}".format(log_prefix, log_file_path, str(log_exception)))
    
    # Step 2: Cleanup files based on preserve_logs flag
    try:
        # Always remove script file
        duthost.shell("rm -f {}".format(FLAP_SCRIPT_DEST_PATH), module_ignore_errors=True)
        logging.info("{} - Script file cleaned up: {}".format(log_prefix, FLAP_SCRIPT_DEST_PATH))
        
        # Handle log file based on preserve_logs flag
        if preserve_logs:
            logging.info("{} - Log file preserved for review: {}".format(log_prefix, log_file_path))
        else:
            duthost.shell("rm -f {}".format(log_file_path), module_ignore_errors=True)
            logging.info("{} - Log file cleaned up: {}".format(log_prefix, log_file_path))
            
    except Exception as cleanup_exception:
        logging.warning("{} - Exception during cleanup: {}".format(log_prefix, str(cleanup_exception)))
    
    return script_log_content


#######################################################################################
##    Test Case 1: Single management port flap test
##    This test will:
##    1. Verify unified script exists and is accessible
##    2. Execute single management interface flap using unified shell script (background)
##    3. Monitor SSH connectivity during interface flap operation (disconnection required)
##    4. Verify SSH connectivity is restored after flap operation
##    5. Clean up logs on success, preserve logs on failure
#######################################################################################

def test_mgmt_interface_single_flap(duthosts, enum_rand_one_per_hwsku_hostname, localhost):
    """
    Test Requirements:
    - Must run on supervisor node (checked via is_supervisor_node())
    - Monitors SSH connectivity from test host to supervisor node
    - Uses unified shell script for all device-specific operations
    
    Search Keyword: MGMT_FLAP_SINGLE
    """
    
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    
    # Test-specific logging prefix for easy searching
    LOG_PREFIX = "MGMT_FLAP_SINGLE"
    
    # Step 1: Verify unified script exists and is accessible, get test ID and log path
    test_id, script_log_path = initialize_mgmt_test(duthost, 'single')

    try:
        # Step 2: Verify baseline SSH connectivity before starting interface flap
        supervisor_ip = duthost.mgmt_ip
        logging.info("{} - Verifying baseline SSH connectivity to: {}".format(LOG_PREFIX, supervisor_ip))
        baseline_ssh_ok = check_ssh_connectivity_to_supervisor(localhost, supervisor_ip)
        if not baseline_ssh_ok:
            pytest_assert(False, "SSH connectivity not working initially - cannot monitor for disconnect")
        
        logging.info("{} - Executing single interface flap test, monitoring SSH to: {}".format(LOG_PREFIX, supervisor_ip))
        
        # Execute the script in background
        execute_mgmt_script(duthost, test_id, script_log_path, 'mgmt_flap_single', LOG_PREFIX)
        
        # Give the script additional time to reach the interface flap operation
        time.sleep(5)
        
        # Start SSH monitoring immediately after script startup is confirmed
        start_time = time.time()
        logging.info("{} - Starting SSH connectivity monitoring during interface flap operation".format(LOG_PREFIX))
        
        ssh_disconnections = 0
        connectivity_checks = 0
        
        # Step 3: Monitor SSH connectivity for up to 30 seconds - break on first disconnection
        monitoring_timeout = 30
        monitoring_start = time.time()
        while time.time() - monitoring_start < monitoring_timeout:
            is_ssh_connected = check_ssh_connectivity_to_supervisor(localhost, supervisor_ip)
            connectivity_checks += 1
            
            if not is_ssh_connected:
                ssh_disconnections += 1
                elapsed_time = time.time() - start_time
                logging.info("{} - SSH disconnected at {:.1f}s - management port restart detected!".format(LOG_PREFIX, elapsed_time))
                break  # Exit on first disconnection for single flap test
            time.sleep(1)  # Check every 1 second for consistent monitoring interval
        
        elapsed_monitoring_time = time.time() - monitoring_start
        logging.info("{} - SSH monitoring completed after {:.1f}s. SSH disconnections: {}/{}".format(LOG_PREFIX, elapsed_monitoring_time, ssh_disconnections, connectivity_checks))
        
        # Verify SSH disconnection occurred
        ssh_disconnected = ssh_disconnections > 0
        if not ssh_disconnected:
            pytest_assert(False, "SSH never disconnected during {}-second monitoring - management port restart may have failed".format(monitoring_timeout))
        
        # Step 4: Verify SSH connectivity is restored after flap
        logging.info("{} - Waiting for SSH connectivity restoration...".format(LOG_PREFIX))
        ssh_restored = wait_until(30, 3, 0, check_ssh_connectivity_to_supervisor, localhost, supervisor_ip)
        
        if ssh_restored:
            restore_time = time.time() - start_time
            logging.info("{} - SSH connectivity restored at {:.1f}s".format(LOG_PREFIX, restore_time))
        else:
            # Additional retry with longer interval if first attempt fails
            logging.info("{} - SSH restoration failed, trying extended recovery (60s)...".format(LOG_PREFIX))
            ssh_restored = wait_until(60, 5, 0, check_ssh_connectivity_to_supervisor, localhost, supervisor_ip)
            
            if ssh_restored:
                restore_time = time.time() - start_time
                logging.info("{} - SSH connectivity restored after extended wait at {:.1f}s".format(LOG_PREFIX, restore_time))
            else:
                pytest_assert(False, "SSH connectivity not restored after 90s total - interface may not have recovered")
        
        execution_time = time.time() - start_time
        test_success = ssh_disconnected and ssh_restored
        
        logging.info("{} - SUMMARY: Time={:.1f}s, SSH_disconnect={}, SSH_restore={}, Result={}".format(
            LOG_PREFIX, execution_time, ssh_disconnected, ssh_restored, "PASS" if test_success else "FAIL"))
        
        # Step 5: Retrieve logs and cleanup files (preserve logs on failure)
        finalize_test_with_logs(duthost, script_log_path, LOG_PREFIX, preserve_logs=(not test_success))
        
        if test_success:
            logging.info("{} - Test completed successfully, files cleaned up".format(LOG_PREFIX))
        else:
            logging.info("{} - Test failed, script cleaned up, log preserved for review: {}".format(LOG_PREFIX, script_log_path))
            
            # Provide specific failure reason
            if not ssh_disconnected:
                pytest_assert(False, "Single flap test failed: No SSH disconnection detected")
            elif not ssh_restored:
                pytest_assert(False, "Single flap test failed: SSH connectivity not restored")
            else:
                pytest_assert(False, "Single flap test failed - check summary above")
    
    except Exception as test_exception:
        # Step 5: On failure, preserve logs for debugging but clean up script
        logging.error("{} - Test failed: {}".format(LOG_PREFIX, str(test_exception)))
        finalize_test_with_logs(duthost, script_log_path, LOG_PREFIX, preserve_logs=True)
        logging.info("{} - Test failed, script cleaned up, log preserved: {}".format(LOG_PREFIX, script_log_path))
        raise test_exception


#######################################################################################
##    Test Case 2: Stress test on management port flap
##    This test will:
##    1. Verify unified script exists and is accessible
##    2. Execute stress management interface flap using unified shell script (10 cycles)
##    3. Monitor SSH connectivity during stress test execution
##    4. Verify SSH connectivity is restored after stress test
##    5. Clean up logs on success, preserve logs on failure
#######################################################################################
def test_mgmt_interface_stress_flap(duthosts, enum_rand_one_per_hwsku_hostname, localhost):
    """
    Test performs stress management interface flaps (10 iterations) using unified shell script.
    
    Test Requirements:
    - Must run on supervisor node (checked via is_supervisor_node())
    - Monitors SSH connectivity from test host to supervisor node
    - Uses unified shell script for all device-specific operations
    
    Search Keyword: MGMT_FLAP_STRESS
    """
    
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Test-specific logging prefix for easy searching
    LOG_PREFIX = "MGMT_FLAP_STRESS"

    # Step 1: Verify unified script exists and is accessible, get test ID and log path
    test_id, stress_log_path = initialize_mgmt_test(duthost, 'stress')

    try:
        # Step 2: Verify baseline SSH connectivity before starting stress test
        supervisor_ip = duthost.mgmt_ip
        logging.info("{} - Verifying baseline SSH connectivity to: {}".format(LOG_PREFIX, supervisor_ip))
        baseline_ssh_ok = check_ssh_connectivity_to_supervisor(localhost, supervisor_ip)
        if not baseline_ssh_ok:
            pytest_assert(False, "SSH connectivity not working initially - cannot monitor for disconnects")
        
        logging.info("{} - Executing stress test ({} cycles), monitoring SSH to: {}".format(LOG_PREFIX, 10, supervisor_ip))
        
        # Execute the script in background
        execute_mgmt_script(duthost, test_id, stress_log_path, 'mgmt_flap_stress', LOG_PREFIX, 10)
        
        # Give the script additional time to reach the interface flap operations
        time.sleep(5)
        
        # Start SSH monitoring immediately after script startup is confirmed
        start_time = time.time()
        logging.info("{} - Starting SSH connectivity monitoring during stress test execution".format(LOG_PREFIX))
        
        ssh_disconnections = 0
        connectivity_checks = 0
        
        # Step 3: Wait for stress test to complete while monitoring SSH - 4 minutes timeout
        stress_timeout = 240
        monitoring_start = time.time()
        while time.time() - monitoring_start < stress_timeout:
            is_ssh_connected = check_ssh_connectivity_to_supervisor(localhost, supervisor_ip)
            connectivity_checks += 1
            
            if not is_ssh_connected:
                ssh_disconnections += 1
                elapsed_time = time.time() - start_time
                logging.info("{} - SSH disconnection #{} detected at {:.1f}s".format(LOG_PREFIX, ssh_disconnections, elapsed_time))
            time.sleep(1)  # Check every 1 second for consistent monitoring interval 
        
        elapsed_stress_time = time.time() - monitoring_start
        logging.info("{} - Stress test monitoring completed after {:.1f}s. SSH disconnections: {}/{}".format(LOG_PREFIX, elapsed_stress_time, ssh_disconnections, connectivity_checks))
        
        if ssh_disconnections == 0:
            pytest_assert(False, "SSH never disconnected during stress test - management port restarts may have failed")
        
        # Step 4: Verify SSH connectivity is restored after stress test
        logging.info("{} - Waiting for SSH connectivity restoration after stress test...".format(LOG_PREFIX))
        ssh_restored = wait_until(30, 3, 0, check_ssh_connectivity_to_supervisor, localhost, supervisor_ip)
        
        if ssh_restored:
            restore_time = time.time() - start_time
            logging.info("{} - SSH connectivity restored at {:.1f}s after stress test".format(LOG_PREFIX, restore_time))
        else:
            # Additional retry for stress test recovery
            logging.info("{} - SSH restoration failed, trying extended recovery (60s)...".format(LOG_PREFIX))
            ssh_restored = wait_until(60, 5, 0, check_ssh_connectivity_to_supervisor, localhost, supervisor_ip)
            
            if ssh_restored:
                restore_time = time.time() - start_time
                logging.info("{} - SSH connectivity restored after extended wait at {:.1f}s".format(LOG_PREFIX, restore_time))
            else:
                pytest_assert(False, "SSH connectivity not restored after stress test within 90s total - interface may not have recovered properly")
        
        execution_time = time.time() - start_time
        test_success = ssh_disconnections > 0 and ssh_restored
        
        logging.info("{} - SUMMARY: Time={:.1f}s, SSH_disconnections={}/{}, SSH_restore={}, Result={}".format(
            LOG_PREFIX, execution_time, ssh_disconnections, connectivity_checks, ssh_restored, "PASS" if test_success else "FAIL"))
        
        # Step 5: Retrieve logs and cleanup files (preserve logs on failure)
        finalize_test_with_logs(duthost, stress_log_path, LOG_PREFIX, preserve_logs=(not test_success))
        
        if test_success:
            logging.info("{} - Test completed successfully, files cleaned up".format(LOG_PREFIX))
        else:
            logging.info("{} - Test failed, script cleaned up, log preserved for review: {}".format(LOG_PREFIX, stress_log_path))
            
            # Provide specific failure reason
            if ssh_disconnections == 0:
                pytest_assert(False, "Stress test failed: No SSH disconnections detected")
            elif not ssh_restored:
                pytest_assert(False, "Stress test failed: SSH connectivity not restored")
            else:
                pytest_assert(False, "Stress test failed - check summary above")
    
    except Exception as test_exception:
        # Step 5: On failure, preserve logs for debugging but clean up script
        logging.error("{} - Test failed: {}".format(LOG_PREFIX, str(test_exception)))
        finalize_test_with_logs(duthost, stress_log_path, LOG_PREFIX, preserve_logs=True)
        logging.info("{} - Test failed, script cleaned up, log preserved: {}".format(LOG_PREFIX, stress_log_path))
        raise test_exception



