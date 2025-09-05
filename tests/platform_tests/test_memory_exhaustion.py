import logging
import time
import pytest

from tests.common.platform.processes_utils import wait_critical_processes, get_critical_processes_status
from tests.common.reboot import wait_for_startup
from tests.common.utilities import wait_until
from tests.common.errors import RunAnsibleModuleFail

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

SSH_STATE_ABSENT = "absent"
SSH_STATE_STARTED = "started"


class TestMemoryExhaustion:
    """
    This test case is used to verify that DUT will reboot when it runs out of memory.
    """
    def wait_lc_healthy_if_sup(self, duthost, duthosts, localhost):
        # For sup, we also need to ensure linecards are back and healthy for following tests
        is_sup = duthost.get_facts().get("modular_chassis") and duthost.is_supervisor_node()
        if is_sup:
            for lc in duthosts.frontend_nodes:
                wait_for_startup(lc, localhost, delay=10, timeout=300)
                wait_critical_processes(lc)

    @pytest.fixture(autouse=True)
    def tearDown(self, duthosts, enum_rand_one_per_hwsku_hostname,
                 localhost, pdu_controller):
        yield
        # If the SSH connection is not established, or any critical process is exited,
        # try to recover the DUT by PDU reboot.
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        hostname = duthost.hostname
        status, _ = get_critical_processes_status(duthost)
        if not status:
            if pdu_controller is None:
                logging.error("No PDU controller for {}, failed to recover DUT!".format(hostname))
                return
            self.pdu_reboot(pdu_controller)
            # Wait until all critical processes are healthy.
            wait_critical_processes(duthost)
            self.wait_lc_healthy_if_sup(duthost, duthosts, localhost)

    def test_memory_exhaustion(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        hostname = duthost.hostname
        datetime_before_reboot = duthost.get_now_time()

        # Our shell command is designed as 'nohup bash -c "sleep 5 && tail /dev/zero" &' because of:
        #  * `tail /dev/zero` is used to run out of memory completely.
        #  * Since `tail /dev/zero` will cause the DUT reboot, we need to run it in the background
        #    (using &) to avoid pytest getting stuck. `nohup` is also necessary to protect the
        #    background process.
        #  * Some DUTs with few free memory may reboot before ansible receive the result of shell
        #    command, so we add `sleep 5` to ensure ansible receive the result first.
        # Swapping is turned off so the OOM is triggered in a shorter time.

        res = duthost.command("sudo swapoff -a")
        if res['rc']:
            logging.error("Swapoff command failed: {}".format(res))

        cmd = 'nohup bash -c "sleep 5 && tail /dev/zero" &'
        res = duthost.shell(cmd)
        if not res.is_successful:
            pytest.fail('DUT {} run command {} failed'.format(hostname, cmd))

        # Verify DUT triggered OOM reboot.
        self.wait_until_reboot(duthost, datetime_before_reboot)
        # Wait until all critical processes are healthy.
        timeout = 300
        if duthost.sonichost.is_multi_asic:
            timeout = 400
        wait_critical_processes(duthost, timeout)
        self.wait_lc_healthy_if_sup(duthost, duthosts, localhost)

    def wait_until_reboot(self, duthost, datetime_before_reboot, timeout=600):
        def check_dut_rebooted(duthost, datetime_before_reboot):
            try:
                dut_up_datetime = duthost.get_up_time()
            except RunAnsibleModuleFail:
                # We may hit HostUnreachable issue during device reboot, so return False when
                # RunAnsibleModuleFail raised.
                return False
            return dut_up_datetime > datetime_before_reboot
        wait_until(timeout, 10, 0, check_dut_rebooted, duthost, datetime_before_reboot)

    def pdu_reboot(self, pdu_controller):
        hostname = pdu_controller.dut_hostname
        if not pdu_controller.turn_off_outlet():
            logging.error("Turn off the PDU outlets of {} failed".format(hostname))
            return
        time.sleep(10)  # sleep 10 second to ensure there is gap between power off and on
        if not pdu_controller.turn_on_outlet():
            logging.error("Turn on the PDU outlets of {} failed".format(hostname))
