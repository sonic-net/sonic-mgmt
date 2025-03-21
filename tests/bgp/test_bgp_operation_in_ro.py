import pytest
import logging
import time

from ansible.errors import AnsibleConnectionFailure
from pytest_ansible.errors import AnsibleConnectionFailure as PytestAnsibleConnectionFailure
from tests.common.devices.base import RunAnsibleModuleFail
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait
from tests.common.utilities import pdu_reboot
from tests.common.reboot import reboot
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.platform.processes_utils import wait_critical_processes

pytestmark = [
    pytest.mark.topology("t0", "t1"),
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)


def check_disk_ro(duthost):
    try:
        result = duthost.shell("touch ~/disk_check.txt", module_ignore_errors=True)
        return result["rc"] != 0
    finally:
        logger.info("touch file failed as expected")
        return True


def simulate_ro(duthost):
    duthost.shell("echo u > /proc/sysrq-trigger")
    logger.info("Disk turned to RO state; pause for 30s before attempting to ssh")
    assert wait_until(30, 2, 0, check_disk_ro, duthost), "disk not in ro state"

    # Wait for disk remount finish
    time.sleep(10)


def do_pdu_reboot(duthost, localhost, duthosts, pdu_controller):
    if not pdu_reboot(pdu_controller):
        logger.error("Failed to do PDU reboot for {}".format(duthost.hostname))
        return
    return post_reboot_healthcheck(duthost, localhost, duthosts, 20)


def do_reboot(duthost, localhost, duthosts):
    # occasionally reboot command fails with some kernel error messages
    # Hence retry if needed.
    #
    wait_time = 20
    retries = 3
    rebooted = False

    for i in range(retries):
        #
        try:
            # Reboot DUT using reboot function instead of using ssh_remote_run.
            # ssh_remote_run gets blocked due to console messages from reboot on DUT
            # Do not wait for ssh as next step checks if ssh is stopped to ensure DUT is
            # is rebooting.
            reboot(duthost, localhost, wait_for_ssh=False)
            localhost.wait_for(host=duthost.mgmt_ip, port=22, state="stopped", delay=5, timeout=60)
            rebooted = True
            break
        except (AnsibleConnectionFailure, PytestAnsibleConnectionFailure) as e:
            logger.error("DUT not reachable, exception: {} attempt:{}/{}".
                         format(repr(e), i, retries))
        except RunAnsibleModuleFail as e:
            logger.error("DUT did not go down, exception: {} attempt:{}/{}".
                         format(repr(e), i, retries))

        wait(wait_time, msg="Wait {} seconds before retry.".format(wait_time))

    if not rebooted:
        logger.error("Failed to reboot DUT after {} retries".format(retries))
        return False

    return post_reboot_healthcheck(duthost, localhost, duthosts, wait_time)


def post_reboot_healthcheck(duthost, localhost, duthosts, wait_time):
    timeout = 300
    if duthost.get_facts().get("modular_chassis"):
        wait_time = max(wait_time, 600)
        timeout = max(timeout, 420)
        localhost.wait_for(host=duthost.mgmt_ip, port=22, state="started", delay=10, timeout=timeout)
    else:
        localhost.wait_for(host=duthost.mgmt_ip, port=22, state="started", delay=10, timeout=timeout)
    wait(wait_time, msg="Wait {} seconds for system to be stable.".format(wait_time))
    if not wait_until(300, 20, 0, duthost.critical_services_fully_started):
        logger.error("Not all critical services fully started!")
        return False
    # If supervisor node is rebooted in chassis, linecards also will reboot.
    # Check if all linecards are back up.
    if duthost.is_supervisor_node():
        for host in duthosts:
            if host != duthost:
                logger.info("checking if {} critical services are up".format(host.hostname))
                wait_critical_processes(host)
                if not wait_until(300, 20, 0, check_interface_status_of_up_ports, host):
                    logger.error("Not all ports that are admin up on are operationally up")
                    return False
    return True


def test_bgp_operations_in_ro(localhost, duthosts, enum_frontend_dut_hostname, pdu_controller):
    """
    @summary: This test case is to verify the BGP operations can successfully run in Read-Only state
    """
    try:

        duthost = duthosts[enum_frontend_dut_hostname]

        # Simulate disk RO state
        simulate_ro(duthost)

        # Verify BGP operations
        # Run "show ip bgp summary" command
        bgp_show_result = duthost.shell("show ip bgp summary")
        bgp_show_output = bgp_show_result["stdout"]
        pytest_assert(
            bgp_show_result["rc"] == 0,
            "show ip bgp summary return value is not 0, output={}".format(
                bgp_show_output
            ),
        )
        pytest_assert(
            "BGP router identifier" in bgp_show_output,
            "Failed to run 'show ip bgp summary' command, output={}".format(
                bgp_show_output
            ),
        )

        # Run "TSC no-stats" command
        run_tsc_result = duthost.shell("TSC no-stats")
        pytest_assert(
            run_tsc_result["rc"] == 0,
            "TSC no-stats return value is not 0, output={}".format(run_tsc_result["stdout"]),
        )
        pytest_assert(
            "System Mode: Normal" in run_tsc_result["stdout"],
            "Failed to TSC in RO state, output={}".format(run_tsc_result["stdout"])
        )

        # Run "TSA" command
        run_tsa_result = duthost.shell("TSA")
        pytest_assert(
            "System Mode: Normal -> Maintenance" in run_tsa_result["stdout_lines"],
            "Failed to TSA in RO state, output={}".format(run_tsa_result["stdout_lines"])
        )

        # Run "TSB" command
        run_tsb_result = duthost.shell("TSB")
        pytest_assert(
            "System Mode: Maintenance -> Normal" in run_tsb_result["stdout_lines"],
            "Failed to TSB in RO state, output={}".format(run_tsb_result["stdout_lines"])
        )

    finally:
        # Reboot DUT to recover from RO state
        logger.debug("START: reboot {} to restore disk RW state".
                     format(enum_frontend_dut_hostname))
        try:
            if not do_reboot(duthost, localhost, duthosts):
                logger.warning("Failed to reboot {}, try PDU reboot to restore disk RW state".
                               format(enum_frontend_dut_hostname))
                do_pdu_reboot(duthost, localhost, duthosts, pdu_controller)
        except Exception as e:
            logger.warning("Failed to reboot {}, got exception {}, try PDU reboot to restore disk RW state".
                           format(enum_frontend_dut_hostname, e))
            do_pdu_reboot(duthost, localhost, duthosts, pdu_controller)
        logger.debug("END: reboot {} to restore disk RW state".
                     format(enum_frontend_dut_hostname))
