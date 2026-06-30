"""System / Process Restart - pmon daemon restart validation.

Implements the pmon restart test from
    ``docs/testplan/transceiver/system_test_plan.md``.

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every System test)
    `- test_system_pmon_restart
         |- <body>: restart pmon -> verify all ports recovery
  session end
    `- _system_post_session_checks (system/conftest.py)
         |- post_state_restoration()
         `- final link + LLDP check

Failure handling: failures are accumulated per test case and reported in a
single ``pytest.fail`` at the end, so a single run surfaces all issues across
all ports.
"""
import logging
import time
import pytest

from tests.transceiver.common.prerequisites import (
    check_links_up
)
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification,
    list_core_files
)
import tests.transceiver.common.process_restart_helpers as prh
from tests.common.platform.processes_utils import check_process_up


logger = logging.getLogger(__name__)

@pytest.mark.disable_loganalyzer
def test_system_pmon_restart(duthost, port_attributes_dict, expected_pid_changes):
    """ 
    Implements the test described in docs\testplan\transceiver\system_test_plan.md

    Simple pmon restart:
        1. Verify all ports are operationally up and record link up time
        2. Restart pmon using 'sudo systemctl restart pmon'
        3. Wait for pmon_restart_settle_sec
        4. Execute Standard Port Recovery and Verification Procedure for all ports
        5. Verify pmon has been running for at least pmon_restart_settle_sec
    """
    expected_pid_changes.add("xcvrd")
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    shared_state = {"core_baseline": list_core_files(duthost)}
    failures = []  # collected across every (port, step) tuple

    logger.info("Recording link states and uptime for %d port(s)", len(ports))
    if not check_links_up(duthost, port_attributes_dict):
        logger.warning("Validation on Start FAILED: %s is down", port)
    else:
        for port in ports:
            logger.info("Recording initial link uptime: %s", 
                        prh.get_db_port_table(duthost,port,attr_filter='last_up_time'))
    
    logger.info("Restarting pmon...")
    prh.restart_process(duthost, 'pmon')
    pmon_wait = prh.sys_attr(port_attributes_dict[ports[0]], "pmon_restart_settle_sec", 120)
    time.sleep(pmon_wait+60) #accounts for minimum timeout behavior of SPRaV
    
    # Wait for settle time and verify
    for port in ports:
        port_attrs = port_attributes_dict[port]
        result = standard_port_recovery_and_verification(
            duthost, port, port_attrs,
            link_up_timeout_sec=pmon_wait,
            shared_state=shared_state,
        )
        if not result["passed"]:
            failures.append(f"[startup] {result['details']}")
            logger.warning("Startup validation FAILED: %s", result["details"])
        else:
            logger.info("Startup validation PASSED: %s", result["details"])
    
    if failures:
        pytest.fail(
            f"pmon restart recovery FAILED on {len(failures)} port(s):\n  - "
            + "\n  - ".join(failures)
        )
