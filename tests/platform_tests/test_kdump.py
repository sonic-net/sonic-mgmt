import logging
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot, SONIC_SSH_PORT, SONIC_SSH_REGEX, wait_for_startup,\
    REBOOT_TYPE_COLD, REBOOT_TYPE_KERNEL_PANIC
from tests.platform_tests.test_reboot import check_interfaces_and_services

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

SSH_SHUTDOWN_TIMEOUT = 360
SSH_STARTUP_TIMEOUT = 420

SSH_STATE_ABSENT = "absent"
SSH_STATE_STARTED = "started"


class TestKernelPanic:
    """
    This test case is used to verify that DUT will load kdump crashkernel on kernel panic.
    """
    def wait_lc_healthy_if_sup(self, duthost, duthosts, localhost, conn_graph_facts, xcvr_skip_list):
        # For sup, we also need to ensure linecards are back and healthy for following tests
        is_sup = duthost.get_facts().get("modular_chassis") and duthost.is_supervisor_node()
        if is_sup:
            for lc in duthosts.frontend_nodes:
                wait_for_startup(lc, localhost, delay=10, timeout=300)
                wait_critical_processes(lc)
                check_interfaces_and_services(lc, conn_graph_facts["device_conn"][lc.hostname],
                                              xcvr_skip_list, reboot_type=REBOOT_TYPE_COLD)

    @pytest.fixture(autouse=True)
    def tearDown(self, duthosts, enum_rand_one_per_hwsku_hostname,
                 localhost, pdu_controller, conn_graph_facts, xcvr_skip_list):
        yield
        # If the SSH connection is not established, or any critical process is exited,
        # try to recover the DUT by PDU reboot.
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
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
            self.wait_lc_healthy_if_sup(duthost, duthosts, localhost, conn_graph_facts, xcvr_skip_list)

    def test_kernel_panic(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                          conn_graph_facts, xcvr_skip_list):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        hostname = duthost.hostname

        out = duthost.command('show kdump config')
        if "Enabled" not in out["stdout"]:
            pytest.skip('DUT {}: Skip test since kdump is not enabled'.format(hostname))

        reboot(duthost, localhost, reboot_type=REBOOT_TYPE_KERNEL_PANIC, safe_reboot=True)

        check_interfaces_and_services(duthost, conn_graph_facts["device_conn"][hostname],
                                      xcvr_skip_list, reboot_type=REBOOT_TYPE_KERNEL_PANIC)
        self.wait_lc_healthy_if_sup(duthost, duthosts, localhost, conn_graph_facts, xcvr_skip_list)

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
