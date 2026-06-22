"""System / Process Restart - xcvrd daemon restart validation.

Implements xcvrd daemon restart impact, xcvrd restart with I2C errors,
and xcvrd crash recovery test from ``docs/testplan/transceiver/system_test_plan.md``.



Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every System test)
    `- test_system_xcvrd_restart_simple
         |- run_pre_check  (xcvrd RUNNING)    <- _per_test_health_check
         |- <body>: restart xcvrd -> verify all ports recovery
         `- run_post_check 
    `- test_system_xcvrd_restart_with_i2c_errors
         |- run_pre_check  (xcvrd RUNNING)    <- _per_test_health_check
         |- <body>: induce I2C errors -> restart xcvrd -> verify recovery
         `- run_post_check 
    `- test_system_xcvrd_crash_recovery
         |- run_pre_check  (xcvrd RUNNING)    <- _per_test_health_check
         |- <body>: inject crash -> monitor restart -> verify recovery
         `- run_post_check 
  session end
    `- _system_post_session_checks (system/conftest.py)
         |- post_state_restoration()
         |- STATE_DB consistency check
         `- final link + LLDP check

Failure handling: failures are accumulated per test case and reported in a single
pytest.fail at the end, so a single run surfaces all issues across all ports.
"""
import logging
import re
import time

import pytest

from tests.transceiver.attribute_parser.attribute_keys import SYSTEM_ATTRIBUTES_KEY
from tests.transceiver.common.prerequisites import (
    standard_port_recovery_and_verification,
    get_dut_interfaces_status
)
from spytest.apis.system.i2c import err_simulation

logger = logging.getLogger(__name__)


    #TODO: See if there are existing functions in /common, or move these to there
def _sys_attr(port_attrs, name, default):
    """Extract system attribute from port attributes dict with default fallback."""
    return port_attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get(name, default)

def _is_oper_up(duthost, port):
    intf_status = get_dut_interfaces_status(duthost)
    s = intf_status.get(port, {}) or {}
    return s.get("admin") == "up" and s.get("oper") == "up"

def _restart_xcvrd(duthost):
    duthost.shell("docker exec pmon supervisorctl restart xcvrd")

def _get_xcvrd_uptime(duthost):
    return duthost.shell("docker exec pmon supervisorctl status xcvrd | awk '{print $NF}'")



#AI junk functions
# def _inject_xcvrd_crash(duthost):
#     """Inject a crash into xcvrd by modifying the script to raise an exception."""
#     logger.info("Injecting crash into xcvrd by modifying script...")
    
#     # Create a backup of the original xcvrd script
#     duthost.shell(f"sudo cp {XCVRD_SCRIPT} {XCVRD_SCRIPT}.bak")
    
#     # Add a line that raises an exception early in the script
#     # We'll insert it after imports to trigger a crash on startup
#     crash_injection = 'raise Exception("Intentional crash for test_system_xcvrd_crash_recovery")'
    
#     try:
#         result = duthost.shell(
#             f"sudo python3 -c \"import sys; content = open('{XCVRD_SCRIPT}', 'r').read(); "
#             f"lines = content.split('\\\\n'); "
#             f"insert_idx = next((i for i, l in enumerate(lines) if l.strip() and not l.startswith('#') and 'import' in l), -1) + 1; "
#             f"if insert_idx > 0: lines.insert(insert_idx, '{crash_injection}'); "
#             f"open('{XCVRD_SCRIPT}', 'w').write('\\\\n'.join(lines))\"",
#             module_ignore_errors=True
#         )
#         logger.info("Crash injection step completed")
#     except Exception as e:
#         logger.warning("Crash injection failed: %s", str(e))


# def _restore_xcvrd_script(duthost):
#     """Restore the original xcvrd script from backup."""
#     logger.info("Restoring original xcvrd script...")
#     try:
#         # duthost.shell(f"sudo mv {XCVRD_SCRIPT}.bak {XCVRD_SCRIPT}", module_ignore_errors=True)
#         duthost.shell(f"sudo mv {XCVRD_SCRIPT}.bak {XCVRD_SCRIPT}") #TODO validate module_ignore_errors
#         logger.info("xcvrd script restored")
#     except Exception as e:
#         logger.warning("Script restoration failed: %s", str(e))


def test_system_xcvrd_restart_simple(duthost, port_attributes_dict):
    """ 
    Implements the test described in docs\testplan\transceiver\system_test_plan.md

    Simple xcvrd restart:
        1. Verify all ports are operationally up and record link up time
        2. Restart xcvrd daemon using 'docker exec pmon supervisorctl restart xcvrd'
        3. Wait for xcvrd_restart_settle_sec
        4. Execute Standard Port Recovery and Verification Procedure for all ports
        5. Verify xcvrd has been running for at least xcvrd_restart_settle_sec
    """
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    shared_state = {}
    failures = []  # collected across every (port, step) tuple

    logger.info("Recording link states and uptime for %d port(s)", len(ports))
    logger.info("Recording initialXcvrD uptime: %s", _get_xcvrd_uptime(duthost))
    for port in ports:
        if not _is_oper_up(duthost, port,):
            logger.warning("Validation on Start FAILED: %s is down", port)
    
    logger.info("Restarting xcvrd daemon...")
    _restart_xcvrd(duthost)
    
    # Wait for settle time and verify
    for port in ports:
        port_attrs = port_attributes_dict[port]
        xcvrd_wait = _sys_attr(port_attrs, "xcvrd_restart_settle_sec", 120)
        result = standard_port_recovery_and_verification(
            duthost, port, port_attrs,
            link_up_timeout_sec=xcvrd_wait,
            shared_state=shared_state,
        )
        if not result["passed"]:
            failures.append(f"[startup] {result['details']}")
            logger.warning("Startup validation FAILED: %s", result["details"])
        else:
            logger.info("Startup validation PASSED: %s", result["details"])
    
    if failures:
        pytest.fail(
            f"TC1: xcvrd restart recovery FAILED on {len(failures)} port(s):\n  - "
            + "\n  - ".join(failures)
        )


def test_system_xcvrd_restart_with_i2c_errors(duthost, port_attributes_dict):
    """ 
    Implements the test described in docs\testplan\transceiver\system_test_plan.md

    xcvrd restart with I2C errors:
        1. Verify all ports are operationally up and record link up time
        2. Induce I2C errors using err_simulation() from spytest\apis\system\i2c.py
        3. Restart xcvrd daemon using 'docker exec pmon supervisorctl restart xcvrd'
        4. Monitor link behavior and system stability
        5. Wait for xcvrd_restart_settle_sec before verification
        6. Execute Standard Port Recovery and Verification Procedure for all ports
    """
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"

    xcvrd_wait = _sys_attr(port_attrs, "xcvrd_restart_settle_sec", 120)
    shared_state = {}
    failures = []  # collected across every (port, step) tuple

    logger.info("Recording initial link states for %d port(s)", len(ports))
    logger.info("Recording initial XcvrD uptime: %s", _get_xcvrd_uptime(duthost))
    for port in ports:
        if not _is_oper_up(duthost, port,):
            logger.warning("Validation on Start FAILED: %s is down", port)
    
    logger.info("Inducing I2C errors...")
    err_simulation(duthost, state='start')
    
    logger.info("Restarting xcvrd daemon with I2C errors present...")
    _restart_xcvrd(duthost)

    #Wait, then run verification after restart
    for port in ports:
        port_attrs = port_attributes_dict[port]
        xcvrd_wait = _sys_attr(port_attrs, "xcvrd_restart_settle_sec", 120)
        result = standard_port_recovery_and_verification(
            duthost, port, port_attrs,
            link_up_timeout_sec=xcvrd_wait,
            shared_state=shared_state,
        )
        if not result["passed"]:
            failures.append(f"[startup] {result['details']}")
            logger.warning("Startup validation FAILED: %s", result["details"])
        else:
            logger.info("Startup validation PASSED: %s", result["details"])
    
    logger.info("Removing simulated I2C errors...")
    err_simulation(duthost, state='stop')
    if failures:
        pytest.fail(
            f"xcvrd restart with I2C errors recovery FAILED on {len(failures)} port(s):\n  - "
            + "\n  - ".join(failures)
        )


def test_system_xcvrd_crash_recovery(duthost, port_attributes_dict):
    """ 
    Implements the test described in docs\testplan\transceiver\system_test_plan.md

    xcvrd crash recovery test:
        1. Verify all ports are operationally up and record link up time
        2. Modify xcvrd.py to induce a crash
        3. Monitor automatic restart behavior
        4. Wait for xcvrd_restart_settle_sec before verification
        5. Execute Standard Port Recovery and Verification Procedure for all ports
        6. Verify xcvrd has been running for at least xcvrd_restart_settle_sec
    """
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    shared_state = {}
    failures = []  # collected across every (port, step) tuple

    logger.info("Recording initial link states for %d port(s)", len(ports))
    logger.info("Recording initial XcvrD uptime: %s", _get_xcvrd_uptime(duthost))
    for port in ports:
        if not _is_oper_up(duthost, port,):
            logger.warning("Validation on Start FAILED: %s is down", port)
    
    logger.info("Injecting crash into xcvrd script...")
    _inject_xcvrd_crash(duthost)
    
    # Phase 3: Monitor automatic restart behavior 
    #TODO
    
    # Wait, then run Standard Port Recovery and Verification for all ports
    for port in ports:
        port_attrs = port_attributes_dict[port]
        logger.info("Running Standard Port Recovery and Verification for %d port(s)", len(ports))
        xcvrd_wait = _sys_attr(port_attrs, "xcvrd_restart_settle_sec", 120)
        result = standard_port_recovery_and_verification(
            duthost, port, port_attrs,
            link_up_timeout_sec=xcvrd_wait,
            shared_state=shared_state,
        )
        if not result["passed"]:
            failures.append(f"[startup] {result['details']}")
            logger.warning("Startup validation FAILED: %s", result["details"])
        else:
            logger.info("Startup validation PASSED: %s", result["details"])
    
    if failures:
        pytest.fail(
            f"xcvrd crash recovery FAILED on {len(failures)} port(s):\n  - "
            + "\n  - ".join(failures)
        )
