"""
Management Interface Flap Test - Console-based Implementation

This module implements a management interface stress flap test
using direct console commands to control the management port via eth_mgmt_ctrl.

Key Features:
- Per-test console connection verification
- Direct console control of management port (shut/noshut) using eth_mgmt_ctrl CLI
- SSH connectivity monitoring to verify port status changes
- Vendor-neutral design with clear pass/fail criteria
- Stress test implementation for comprehensive validation

Test Design:
1. Verify console connection
2. Execute management port shut command via eth_mgmt_ctrl
3. Monitor SSH connectivity loss to verify port is down
4. Execute management port noshut command via eth_mgmt_ctrl
5. Monitor SSH connectivity restoration to verify port is up
6. Verify final port status via console

Console Connection:
- Per-test verification of console connectivity
- Commands are executed directly on device CLI via console with sudo privileges
- Automatic cleanup after test completion

Test Coverage:
- test_mgmt_interface_stress_flap_console: Multiple flap cycles (stress test)
"""

import logging
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup
from tests.common.utilities import wait_until, get_plt_reboot_ctrl

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.asic('cisco-8000'),
    pytest.mark.topology('t2')
]

# CLI tool paths
ETH_MGMT_CTRL_PATH = "/usr/bin/eth_mgmt_ctrl"

# Test configuration constants
TC_NAME = "test_mgmt_flap"
LOG_PREFIX = TC_NAME
SSH_CONN_RESTORE_TIMEOUT = 10    # seconds to wait for SSH restoration
SSH_CONN_MONITOR_TIMEOUT = 10    # seconds to monitor for SSH disconnection
NUM_FLAP_CYCLES = 10             # number of iterations for stress test
STABILIZATION_WAIT_SECONDS = 2   # seconds to wait for state stabilization
RECOVERY_REBOOT_CMD = "sudo reboot"    # console fallback reboot command
RECOVERY_SSH_REBOOT_TIMEOUT = 300      # seconds to wait for DUT SSH startup after reboot
RECOVERY_SSH_REBOOT_DELAY = 10         # seconds between SSH startup checks after reboot
RECOVERY_CRITICAL_PS_CHASSIS_DEFAULT_TIMEOUT = 1000  # align with safe_reboot
RECOVERY_CRITICAL_PS_CHASSIS_EXTENDED_TIMEOUT = 400  # align with safe_reboot
RECOVERY_CRITICAL_PS_REBOOT_POLL_INTERVAL = 20  # seconds between critical-services checks in recovery


def get_recovery_critical_ps_reboot_timeout(duthost):
    """
    Return timeout for recovery critical services/process checks.
    Uses inventory plt_reboot_dict timeout when available.
    """
    timeout = None
    is_modular_chassis = bool(duthost.get_facts().get("modular_chassis"))
    plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, TC_NAME, 'cold')
    if plt_reboot_ctrl:
        timeout = plt_reboot_ctrl.get('timeout')
        reboot_wait = plt_reboot_ctrl.get('wait')
        if timeout is None:
            timeout = RECOVERY_CRITICAL_PS_CHASSIS_DEFAULT_TIMEOUT
            logging.warning("{} - Recovery reboot ctrl timeout is null, using chassis baseline timeout: {}s".format(
                LOG_PREFIX, timeout))
        if is_modular_chassis and reboot_wait is not None:
            timeout = max(timeout, reboot_wait + RECOVERY_CRITICAL_PS_CHASSIS_EXTENDED_TIMEOUT)
        logging.info("{} - Recovery reboot ctrl from lab ({}/cold): {}".format(
            LOG_PREFIX, TC_NAME, plt_reboot_ctrl))
        logging.info("{} - Recovery critical services timeout from lab: {}s".format(
            LOG_PREFIX, timeout))
    else:
        timeout = RECOVERY_CRITICAL_PS_CHASSIS_DEFAULT_TIMEOUT
        logging.warning("{} - Recovery reboot ctrl not found in lab config, using chassis baseline timeout: {}s".format(
            LOG_PREFIX, timeout))

    return timeout


def get_critical_services_status_with_timeout(duthost):
    """
    Return critical services running status.
    """
    try:
        status = duthost.critical_services_status()
        if not isinstance(status, dict):
            logging.warning("{} - critical_services_status() returned unexpected type".format(LOG_PREFIX))
            return None
        return status
    except Exception as service_error:
        logging.warning("{} - Failed to get critical services status: {}".format(
            LOG_PREFIX, str(service_error)))
        return None


def critical_services_fully_started_with_timeout(duthost, dump_not_ready=False):
    """
    Check critical services readiness with bounded command timeout.
    """
    status = get_critical_services_status_with_timeout(duthost)
    if not isinstance(status, dict):
        if dump_not_ready:
            logging.warning("{} - Recovery timeout: critical services status unavailable".format(LOG_PREFIX))
        return False

    all_ready = bool(status) and all(status.values())
    if dump_not_ready and not all_ready:
        not_ready_services = [service_name for service_name, is_ready in sorted(status.items()) if not is_ready]
        if not_ready_services:
            logging.warning("{} - Recovery timeout: critical services not ready: {}".format(
                LOG_PREFIX, ", ".join(not_ready_services)))
    return all_ready


def check_ssh_connectivity_to_supervisor(localhost, supervisor_ip):
    """
    Check SSH connectivity from localhost to supervisor node

    Args:
        localhost: localhost connection object
        supervisor_ip: IP address of supervisor node to test

    Returns:
        bool: True if SSH connection is successful, False otherwise
    """
    try:
        result = localhost.wait_for(
            host=supervisor_ip,
            port=22,
            state='started',
            delay=0,
            timeout=2,  # Reduced timeout for more sensitive detection
            module_ignore_errors=True
        )
        return not (result.is_failed or ('Timeout' in str(result)))
    except Exception:
        return False


def verify_mgmt_port_status_up(duthost_console):
    """
    Verify management port status is UP using console

    Args:
        duthost_console: Console connection to DUT

    Returns:
        bool: True if management port is UP, False otherwise
    """
    try:
        # Get management port status using eth_mgmt_ctrl status-mgmt command
        logging.info("Verifying management port status via console...")
        result = duthost_console.send_command("sudo {} status-mgmt".format(ETH_MGMT_CTRL_PATH))

        # status-mgmt command returns "Up", "Down", "UP", "DOWN", "UNKNOWN", or "NOT_FOUND"
        status = result.strip().upper()  # Convert to uppercase for consistent comparison
        if status == "UP":
            logging.info("Management port is UP")
            return True
        else:
            logging.error("Management port is not UP. status-mgmt output: {}".format(status))
            return False

    except Exception as e:
        logging.error("Failed to check management port status: {}".format(str(e)))
        return False


def check_runtime_console_state(duthost_console):
    """
    Check console connection

    Args:
        duthost_console: Console connection object (from fixture)

    Raises:
        pytest.skip: If console connection verification or CLI tool verification fails

    """
    try:
        # STEP1: Verify console connection
        logging.info("{} - STEP1: Verifying console connection".format(LOG_PREFIX))
        test_result = duthost_console.send_command("echo console_test_$(date +%s)")
        if "console_test_" in test_result:
            logging.info("{} - Console connectivity test passed".format(LOG_PREFIX))
        else:
            logging.warning(
                "{} - Console connectivity test may have issues. Output: {}".format(
                    LOG_PREFIX, test_result
                )
            )
            pytest.skip("Console connectivity test failed - unable to communicate properly with console")

    except Exception as console_test_error:
        logging.error("{} - Console connectivity test failed: {}".format(LOG_PREFIX, str(console_test_error)))
        pytest.skip("Console connectivity test failed: {}".format(str(console_test_error)))


def execute_flap_and_monitor_ssh(duthost_console, localhost, supervisor_ip, num_cycles=1):
    """
    Execute management port flap commands and monitor SSH connectivity

    New Flow:
    1. Check SSH connection
    2. Execute shut command via console
    3. Monitor for SSH disconnection for 1 minute:
       - If disconnect detected: execute noshut immediately
       - If no disconnect after 1 minute: execute noshut anyway (timeout)
    4. Ensure SSH connection is restored

    Args:
        duthost_console: Console connection to DUT
        localhost: localhost connection object for SSH testing
        supervisor_ip: IP address of supervisor node
        num_cycles: Number of flap cycles to perform

    Returns:
        dict: Test results with detailed information
    """
    logging.info(
        "{} - STEP2: Executing {} flap cycle(s) with new flow and monitoring SSH".format(
            LOG_PREFIX, num_cycles
        )
    )

    test_results = {
        'success': False,
        'ssh_restored': False,
        'final_status_ok': False,
        'successful_cycles': 0,
        'total_cycles': num_cycles,
        'ssh_disconnections': 0,
        'connectivity_checks': 0,
        'execution_time': 0,
        'error_message': None
    }

    start_time = time.time()

    try:
        # Step2a: Verify baseline SSH connectivity
        logging.info("{} - STEP2_a: Verifying baseline SSH connectivity to: {}".format(LOG_PREFIX, supervisor_ip))
        baseline_ssh_ok = check_ssh_connectivity_to_supervisor(localhost, supervisor_ip)
        if not baseline_ssh_ok:
            test_results['error_message'] = "SSH connectivity not working initially"
            return test_results
        successful_cycles = 0
        ssh_disconnections = 0
        connectivity_checks = 0

        def sync_results(partial_ssh_restored=False):
            test_results['successful_cycles'] = successful_cycles
            test_results['ssh_disconnections'] = ssh_disconnections
            test_results['connectivity_checks'] = connectivity_checks
            test_results['ssh_restored'] = partial_ssh_restored
            test_results['execution_time'] = time.time() - start_time

        # Execute flap cycles
        for cycle in range(1, num_cycles + 1):
            if num_cycles > 1:
                logging.info("{} - === Cycle {}/{} ===".format(LOG_PREFIX, cycle, num_cycles))

            cycle_start = time.time()
            cycle_prefix = "{} Cycle {}".format(LOG_PREFIX, cycle) if num_cycles > 1 else LOG_PREFIX

            # Step2b: Execute shut command via console
            logging.info("{} - STEP2_b: Executing management port SHUT via console".format(cycle_prefix))
            shut_result = duthost_console.send_command("sudo {} shut".format(ETH_MGMT_CTRL_PATH))

            if "error" in shut_result.lower() or "failed" in shut_result.lower():
                logging.error("{} - SHUT command failed. Output: {}".format(cycle_prefix, shut_result))
                test_results['error_message'] = "SHUT command failed: {}".format(shut_result)
                sync_results()
                return test_results

            # Step2c: Monitor for SSH disconnection
            logging.info(
                "{} - STEP2_c: Monitoring for SSH disconnection for {} seconds...".format(
                    cycle_prefix, SSH_CONN_MONITOR_TIMEOUT
                )
            )

            disconnect_monitor_start = time.time()
            ssh_disconnection_detected = False
            disconnect_detected_time = None

            while time.time() - disconnect_monitor_start < SSH_CONN_MONITOR_TIMEOUT:
                is_ssh_connected = check_ssh_connectivity_to_supervisor(localhost, supervisor_ip)
                connectivity_checks += 1

                if not is_ssh_connected:
                    ssh_disconnection_detected = True
                    ssh_disconnections += 1
                    disconnect_detected_time = time.time() - disconnect_monitor_start
                    logging.info("{} - SSH disconnection detected at {:.1f}s - executing NOSHUT immediately".format(
                        cycle_prefix, disconnect_detected_time))
                    break

                time.sleep(1)  # Check every second for better detection

            if not ssh_disconnection_detected:
                timeout_time = time.time() - disconnect_monitor_start
                logging.warning("{} - No SSH disconnection detected after {:.1f}s timeout".format(
                    cycle_prefix, timeout_time))
                test_results['error_message'] = (
                    "ssh lost failed: no disconnection detected after {:.1f}s".format(
                        timeout_time
                    )
                )
                sync_results()
                return test_results

            # Execute NOSHUT immediately after disconnect detection OR after timeout
            logging.info("{} - STEP2_d: Executing management port NOSHUT via console".format(cycle_prefix))
            noshut_result = duthost_console.send_command("sudo {} noshut".format(ETH_MGMT_CTRL_PATH))

            if "error" in noshut_result.lower() or "failed" in noshut_result.lower():
                logging.error("{} - NOSHUT command failed. Output: {}".format(cycle_prefix, noshut_result))
                test_results['error_message'] = "NOSHUT command failed: {}".format(noshut_result)
                sync_results()
                return test_results

            successful_cycles += 1

            # Step2e: Ensure SSH connection is restored
            logging.info(
                "{} - STEP2_e: Waiting for SSH connection restoration (timeout: {}s)...".format(
                    cycle_prefix, SSH_CONN_RESTORE_TIMEOUT
                )
            )
            restoration_start = time.time()
            ssh_restored_in_cycle = False

            while time.time() - restoration_start < SSH_CONN_RESTORE_TIMEOUT:
                is_ssh_connected = check_ssh_connectivity_to_supervisor(localhost, supervisor_ip)
                connectivity_checks += 1

                if is_ssh_connected:
                    ssh_restored_in_cycle = True
                    restoration_time = time.time() - restoration_start
                    logging.info("{} - SSH connection restored after {:.1f}s".format(cycle_prefix, restoration_time))
                    break

                time.sleep(1)  # Check every second during restoration

            if not ssh_restored_in_cycle:
                test_results['error_message'] = (
                    "SSH connection not restored within {}s for cycle {}".format(
                        SSH_CONN_RESTORE_TIMEOUT, cycle
                    )
                )
                sync_results()
                return test_results

            # Log cycle results
            cycle_time = time.time() - cycle_start
            logging.info(
                "{} - Cycle {} COMPLETED: SSH disconnect detected at {:.1f}s, restored in {:.1f}s total".format(
                    LOG_PREFIX, cycle, disconnect_detected_time, cycle_time
                )
            )

            # Brief rest between cycles in stress test
            if num_cycles > 1 and cycle < num_cycles:
                logging.info("{} - Resting for {}s before next cycle...".format(LOG_PREFIX, STABILIZATION_WAIT_SECONDS))
                time.sleep(STABILIZATION_WAIT_SECONDS)

        # Update test results
        sync_results(partial_ssh_restored=True)  # If we get here, all cycles restored SSH

        # Final verification: Check management port status
        time.sleep(STABILIZATION_WAIT_SECONDS)  # Brief wait for stabilization
        logging.info("{} - STEP2_f: Final verification - checking management port status".format(LOG_PREFIX))
        final_status_ok = verify_mgmt_port_status_up(duthost_console)
        test_results['final_status_ok'] = final_status_ok

        # Determine overall success
        test_results['success'] = (
            test_results['ssh_restored']
            and test_results['final_status_ok']
            and successful_cycles == num_cycles
        )

        # Log final summary
        if ssh_disconnections == 0:
            logging.warning(
                "{} - WARNING: No SSH disconnections detected during any cycle - "
                "management port may not have actually shut down".format(LOG_PREFIX)
            )

        logging.info("{} - Stress test execution completed. Disconnections: {}, Cycles: {}/{}".format(
            LOG_PREFIX, ssh_disconnections, successful_cycles, num_cycles))
        return test_results

    except Exception as e:
        test_results['error_message'] = "Exception during flap execution: {}".format(str(e))
        test_results['execution_time'] = time.time() - start_time
        logging.error("{} - STEP2 FAILED: Exception during flap execution: {}".format(LOG_PREFIX, str(e)))
        return test_results


def cleanup_and_report(duthost_console, test_results, num_cycles, duthost, localhost):
    """
    Clean up console connection and generate summary report

    Args:
        duthost_console: Console connection to clean up
        test_results: Test results dictionary from step 2
        num_cycles: Number of cycles that were executed
        duthost: DUT host object
        localhost: localhost connection object

    Returns:
        str: Error message if test failed, None if test passed
    """
    # Generate test summary report
    logging.info(
        "{} - STEP3 SUMMARY: Time={:.1f}s, Cycles={}/{}, SSH_disconnections={}/{}, "
        "SSH_restore={}, Final_Status={}, Result={}".format(
            LOG_PREFIX,
            test_results['execution_time'],
            test_results['successful_cycles'],
            num_cycles,
            test_results['ssh_disconnections'],
            test_results['connectivity_checks'],
            test_results['ssh_restored'],
            "UP" if test_results['final_status_ok'] else "DOWN",
            "PASS" if test_results['success'] else "FAIL",
        )
    )

    # Determine final result and error message
    error_msg = None
    if test_results['success']:
        logging.info("{} - STEP3 COMPLETED: Test completed successfully".format(LOG_PREFIX))
    else:
        if test_results['ssh_disconnections'] == 0:
            error_msg = "Test failed: No SSH disconnection detected"
        elif not test_results['ssh_restored']:
            error_msg = "Test failed: SSH connectivity not restored"
        elif test_results['successful_cycles'] != num_cycles:
            error_msg = "Test failed: Only {}/{} cycles successful".format(
                test_results['successful_cycles'], num_cycles
            )
        else:
            error_msg = "Test failed - check summary above"

        logging.error("{} - STEP3 COMPLETED: {}".format(LOG_PREFIX, error_msg))

    # If test failed (error_msg exists), execute recovery reboot flow
    if error_msg:
        error_detail = " - {}".format(test_results['error_message']) if test_results['error_message'] else ""
        logging.warning("{} - Test failed{} - executing recovery reboot".format(
            LOG_PREFIX, error_detail))
        recovery_ok = recovery_console_reboot(
            duthost_console,
            duthost,
            localhost,
        )
        if not recovery_ok:
            logging.error("{} - Recovery reboot failed".format(LOG_PREFIX))

    return error_msg


def recovery_console_reboot(duthost_console, duthost, localhost):
    """
    Execute recovery reboot using console-triggered reboot and post checks.

    Returns:
        bool: True if recovery reboot and post checks succeed, False otherwise
    """
    try:
        logging.info("{} - Recovery STEP1: sending console reboot command: {}".format(
            LOG_PREFIX, RECOVERY_REBOOT_CMD))
        try:
            duthost_console.write_channel(RECOVERY_REBOOT_CMD + "\n")
            time.sleep(STABILIZATION_WAIT_SECONDS)
        except Exception as console_reboot_error:
            logging.info("{} - Recovery NOTE: console channel changed during reboot send (non-fatal): {}".format(
                LOG_PREFIX, str(console_reboot_error)))

        logging.info(
            "{} - Recovery STEP2: waiting for DUT SSH startup "
            "(duthost={} mgmt_ip={} localhost={})".format(
                LOG_PREFIX,
                duthost.hostname,
                duthost.mgmt_ip,
                getattr(localhost, "hostname", "localhost"),
            )
        )
        wait_for_startup(duthost, localhost, delay=RECOVERY_SSH_REBOOT_DELAY, timeout=RECOVERY_SSH_REBOOT_TIMEOUT)

        recovery_critical_ps_reboot_timeout = get_recovery_critical_ps_reboot_timeout(duthost)
        logging.info("{} - Recovery STEP3: waiting for critical services and processes (timeout={}s)".format(
            LOG_PREFIX, recovery_critical_ps_reboot_timeout))

        pytest_assert(
            wait_until(200, 10, 0, duthost.is_critical_processes_running_per_asic_or_host, "database"),
            "Recovery reboot failed: Database not start."
        )
        pytest_assert(
            wait_until(20, 5, 0, duthost.is_service_running, "redis", "database"),
            "Recovery reboot failed: Redis DB not start"
        )

        duthost.critical_services_tracking_list()
        critical_services_ready = wait_until(
            recovery_critical_ps_reboot_timeout,
            RECOVERY_CRITICAL_PS_REBOOT_POLL_INTERVAL,
            0,
            critical_services_fully_started_with_timeout,
            duthost,
        )

        if not critical_services_ready:
            critical_services_fully_started_with_timeout(duthost, dump_not_ready=True)
        pytest_assert(
            critical_services_ready,
            "{}: Recovery reboot failed: all critical services should be fully started!".format(
                duthost.hostname
            ),
        )

        logging.info("{} - Recovery COMPLETE: console reboot and post-checks passed".format(LOG_PREFIX))
        return True
    except Exception as reboot_error:
        logging.error("{} - Recovery: console reboot failed: {}".format(LOG_PREFIX, str(reboot_error)))
        return False


@pytest.fixture
def ensure_mgmt_port_noshut(duthost_console):
    """
    Best-effort teardown guard to restore management port state.
    This runs even when the test exits unexpectedly after setup.
    """
    yield
    try:
        logging.info("{} - Finalizer: enforcing management port NOSHUT".format(LOG_PREFIX))
        noshut_result = duthost_console.send_command("sudo {} noshut".format(ETH_MGMT_CTRL_PATH))
        if "error" in noshut_result.lower() or "failed" in noshut_result.lower():
            logging.warning("{} - Finalizer NOSHUT may have failed. Output: {}".format(
                LOG_PREFIX, noshut_result))
        time.sleep(STABILIZATION_WAIT_SECONDS)
    except Exception as finalizer_error:
        logging.warning("{} - Finalizer NOSHUT encountered exception: {}".format(
            LOG_PREFIX, str(finalizer_error)))

# =============================================================
# Test Case: Stress test on management port flap using console
# This test will:
# 1. Verify management port is initially UP via console
# 2. Execute stress management interface flap via console (10 cycles)
# 3. Monitor SSH connectivity during stress test execution
# 4. Verify SSH connectivity is restored after stress test
# =============================================================


def test_mgmt_interface_stress_flap_console(
    duthost_console,
    duthosts,
    enum_supervisor_dut_hostname,
    localhost,
    ensure_mgmt_port_noshut,
):
    """
    Test stress management port flaps (10 iterations) using console commands

    Test Requirements:
    - Must run on supervisor node (checked via enum_supervisor_dut_hostname fixture)
    - Uses console connection to execute eth_mgmt_ctrl commands
    - Monitors SSH connectivity from test host to supervisor node

    Search Keyword: MGMT_FLAP_STRESS_CONSOLE
    """

    duthost = duthosts[enum_supervisor_dut_hostname]

    logging.info(
        "{} - Starting management interface stress test on {} (ASIC: {}, Supervisor Node) - DUT: {} IP: {}".format(
            LOG_PREFIX,
            duthost.hostname,
            duthost.facts["asic_type"],
            duthost.hostname,
            duthost.mgmt_ip,
        )
    )

    # STEP1: Check console echo
    check_runtime_console_state(duthost_console)

    # Step2: Execute stress flaps and monitor SSH
    test_results = {
        'success': False,
        'ssh_restored': False,
        'final_status_ok': False,
        'successful_cycles': 0,
        'total_cycles': NUM_FLAP_CYCLES,
        'ssh_disconnections': 0,
        'connectivity_checks': 0,
        'execution_time': 0,
        'error_message': "Test interrupted before execution completed"
    }
    error_message = None

    try:
        test_results = execute_flap_and_monitor_ssh(
            duthost_console, localhost, duthost.mgmt_ip, num_cycles=NUM_FLAP_CYCLES)
    finally:
        # Always run cleanup/recovery to avoid leaving management port in a bad state.
        error_message = cleanup_and_report(
            duthost_console,
            test_results,
            num_cycles=NUM_FLAP_CYCLES,
            duthost=duthost,
            localhost=localhost,
        )

    # Assert test result
    if error_message:
        pytest_assert(False, "Stress test failed: {}".format(error_message))
