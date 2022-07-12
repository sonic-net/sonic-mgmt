import logging
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import SONIC_SSH_PORT, SONIC_SSH_REGEX

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

SSH_SHUTDOWN_TIMEOUT = 360
SSH_STARTUP_TIMEOUT = 360

SSH_STATE_ABSENT = "absent"
SSH_STATE_STARTED = "started"


class TestMemoryExhaustion:
    """
    This test case is used to verify that DUT will reboot when it runs out of memory.
    """

    @pytest.fixture(autouse=True)
    def teardown(self, duthost, localhost, pdu_controller):
        yield
        # If the SSH connection is not established, or any critical process is exited,
        # try to recover the DUT by PDU reboot.
        dut_ip = duthost.mgmt_ip
        hostname = duthost.hostname
        if not self.check_ssh_state(localhost, dut_ip, SSH_STATE_STARTED):
            if pdu_controller is None:
                logging.error("No PDU controller for {}, failed to recover DUT!".format(hostname))
                return
            self.pdu_reboot(pdu_controller)
            # Waiting for SSH connection startup
            pytest_assert(self.check_ssh_state(localhost, dut_ip, SSH_STATE_STARTED, SSH_STARTUP_TIMEOUT),
                          'Recover {} by PDU reboot failed'.format(hostname))
            # Wait until all critical processes are healthy.
            wait_critical_processes(duthost)

    def test_memory_exhaustion(self, duthost, localhost):
        dut_ip = duthost.mgmt_ip
        hostname = duthost.hostname
        dut_datetime = duthost.get_now_time()

        # Our shell command is designed as 'nohup bash -c "sleep 5 && tail /dev/zero" &' because of:
        #  * `tail /dev/zero` is used to run out of memory completely.
        #  * Since `tail /dev/zero` will cause the DUT reboot, we need to run it in the background
        #    (using &) to avoid pytest getting stuck. `nohup` is also necessary to protect the
        #    background process.
        #  * Some DUTs with few free memory may reboot before ansible receive the result of shell
        #    command, so we add `sleep 5` to ensure ansible receive the result first.
        cmd = 'nohup bash -c "sleep 5 && tail /dev/zero" &'
        res = duthost.shell(cmd)
        if not res.is_successful:
            pytest.fail('DUT {} run command {} failed'.format(hostname, cmd))

        # Waiting for SSH connection shutdown
        pytest_assert(self.check_ssh_state(localhost, dut_ip, SSH_STATE_ABSENT, SSH_SHUTDOWN_TIMEOUT),
                      'DUT {} did not shutdown'.format(hostname))
        # Waiting for SSH connection startup
        pytest_assert(self.check_ssh_state(localhost, dut_ip, SSH_STATE_STARTED, SSH_STARTUP_TIMEOUT),
                      'DUT {} did not startup'.format(hostname))
        # Wait until all critical processes are healthy.
        wait_critical_processes(duthost)
        # Verify DUT uptime is later than the time when the test case started running.
        dut_uptime = duthost.get_up_time()
        pytest_assert(dut_uptime > dut_datetime, "Device {} did not reboot".format(hostname))

    def check_ssh_state(self, localhost, dut_ip, expected_state, timeout=60):
        """
        Check the SSH state of DUT.

        :param localhost: A `tests.common.devices.local.Localhost` Object.
        :param dut_ip: A string, the IP address of DUT.
        :param expected_state: A string, the expected SSH state.
        :param timeout: An integer, the maximum number of seconds to wait for.
        :return: A boolean, True if SSH state is the same as expected
                          , False otherwise.
        """
        res = localhost.wait_for(host=dut_ip,
                                 port=SONIC_SSH_PORT,
                                 state=expected_state,
                                 search_regex=SONIC_SSH_REGEX,
                                 delay=10,
                                 timeout=timeout,
                                 module_ignore_errors=True)
        return not res.is_failed and 'Timeout' not in res.get('msg', '')

    def pdu_reboot(self, pdu_controller):
        hostname = pdu_controller.dut_hostname
        if not pdu_controller.turn_off_outlet():
            logging.error("Turn off the PDU outlets of {} failed".format(hostname))
            return
        time.sleep(10)  # sleep 10 second to ensure there is gap between power off and on
        if not pdu_controller.turn_on_outlet():
            logging.error("Turn on the PDU outlets of {} failed".format(hostname))
