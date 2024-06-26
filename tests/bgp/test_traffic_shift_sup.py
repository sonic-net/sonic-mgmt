import logging
import pexpect
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common import config_reload
from test_traffic_shift import get_traffic_shift_state

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

TS_NORMAL = "System Mode: Normal"
TS_MAINTENANCE = "System Mode: Maintenance"
TS_INCONSISTENT = "System Mode: Not consistent"
TS_NO_NEIGHBORS = "System Mode: No external neighbors"

"""
This test file is specific to T2 chassis topology
It tests TSA/B functionality from supervisor
"""


@pytest.fixture(scope="module")
def check_support(duthosts, enum_supervisor_dut_hostname):
    duthost = duthosts[enum_supervisor_dut_hostname]
    rcli_path = duthost.shell("python3 -c \"import pkgutil ; print(pkgutil.find_loader('rcli'))\"")['stdout']
    if str(rcli_path) == "None":
        pytest.skip("rcli package not installed. TSA/B/C from supervisor is not supported in this image")


class TestTrafficShiftOnSup:
    def setup_dutinfo(self, duthosts, enum_supervisor_dut_hostname, creds):
        self.duthosts = duthosts
        self.duthost = duthosts[enum_supervisor_dut_hostname]
        self.dutip = self.duthost.host.options['inventory_manager'].get_host(self.duthost.hostname).vars['ansible_host']
        self.dutuser, self.dutpass = creds['sonicadmin_user'], creds['sonicadmin_password']

    def config_reload_all_lcs(self):
        for host in self.duthosts:
            if host.is_supervisor_node():
                continue
            config_reload(host)

    def verify_traffic_shift_state_all_lcs(self, ts_state, state):
        for host in self.duthosts:
            if host.is_supervisor_node():
                continue
            pytest_assert(ts_state == get_traffic_shift_state(host, "TSC no-stats"),
                          "Linecard {} is not in {} state".format(host, state))

    def run_cmd_on_sup(self, cmd):
        try:
            # Issue TSA on DUT
            client = pexpect.spawn(
                     "ssh {}@{} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'".format(
                         self.dutuser, self.dutip),
                     timeout=300)
            client.expect(["{}@{}'s password:".format(self.dutuser, self.dutip)])
            client.sendline(self.dutpass)
            client.expect("{}*".format(self.dutuser))
            client.sendline(cmd)
            client.expect("Password .*")
            client.sendline(self.dutpass)
            # For TSA/B, wait for execution to complete
            if "TS" in cmd:
                client.expect(".* config reload on all linecards")
            else:
                time.sleep(30)
        except Exception as e:
            logger.error("Exception caught while executing cmd {}. Error message: {}".format(cmd, e))

    def test_TSA(self, duthosts, enum_supervisor_dut_hostname, check_support, creds):
        """
        Test TSA
        Verify all linecards transition to maintenance state after TSA on supervisor
        """
        self.setup_dutinfo(duthosts, enum_supervisor_dut_hostname, creds)
        try:
            # Issue TSA on DUT
            self.run_cmd_on_sup("sudo TSA")
            # Verify DUT is in maintenance state.
            self.verify_traffic_shift_state_all_lcs(TS_MAINTENANCE, "maintenance")
        except Exception as e:
            # Log exception
            logger.error("Exception caught in TSB test. Error message: {}".format(e))
        finally:
            # Issue TSB on DUT to recover the chassis
            self.run_cmd_on_sup("sudo TSB")

    def test_TSB(self, duthosts, enum_supervisor_dut_hostname, check_support, creds):
        """
        Test TSB
        Verify all linecards transition back to normal state from maintenance after TSB on supervisor
        """
        self.setup_dutinfo(duthosts, enum_supervisor_dut_hostname, creds)
        try:
            # Issue TSA on DUT to move chassis to maintenance
            self.run_cmd_on_sup("sudo TSA")
            self.verify_traffic_shift_state_all_lcs(TS_MAINTENANCE, "maintenance")

            # Recover to Normal state
            self.run_cmd_on_sup("sudo TSB")
            # Verify DUT is in normal state
            self.verify_traffic_shift_state_all_lcs(TS_NORMAL, "normal")
        except Exception as e:
            # Log exception
            logger.error("Exception caught in TSB test. Error message: {}".format(e))

    @pytest.mark.disable_loganalyzer
    def test_TSA_TSB_chassis_with_config_reload(self, duthosts, enum_supervisor_dut_hostname, check_support, creds):
        """
        Test TSA/TSB with config reload
        Verify all linecards remain in Maintenance state after TSA and config reload on supervisor
        Verify all linecards remain in Normal state after TSB and config reload on supervisor
        """
        self.setup_dutinfo(duthosts, enum_supervisor_dut_hostname, creds)
        try:
            # Issue TSA on DUT to move chassis to maintenance
            self.run_cmd_on_sup("sudo TSA")
            self.verify_traffic_shift_state_all_lcs(TS_MAINTENANCE, "maintenance")

            # Save config and perform config reload on all LCs
            self.run_cmd_on_sup("rexec all -c 'sudo config save -y'")
            self.config_reload_all_lcs()

            # Verify DUT is still in maintenance state.
            self.verify_traffic_shift_state_all_lcs(TS_MAINTENANCE, "maintenance")
        finally:
            # Recover to Normal state
            self.run_cmd_on_sup("sudo TSB")
            # Verify DUT is in normal state.
            self.verify_traffic_shift_state_all_lcs(TS_NORMAL, "normal")

            # Save config and perform config reload on all LCs
            self.run_cmd_on_sup("rexec all -c 'sudo config save -y'")
            self.config_reload_all_lcs()

            # Verify DUT is in normal state.
            self.verify_traffic_shift_state_all_lcs(TS_NORMAL, "normal")
