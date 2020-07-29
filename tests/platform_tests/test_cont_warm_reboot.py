"""
Test for continuously warm rebooting the DUT
In between warm reboots, verify:
Reboot cause (should match the trigger cause)
Status of services (Services syncd and swss should be active/running)
Status of interfaces and LAGs (all interface and LAGs should comply with current topology)
Status of transceivers (ports in lab_connection_graph should be present)
Status of BGP neighbors (should be established)
"""
import os
import sys
import json
import pytest
import threading
from check_critical_services import check_critical_services
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait
from tests.common.utilities import wait_until
from tests.common.reboot import check_reboot_cause, reboot_ctrl_dict, logging, reboot, REBOOT_TYPE_WARM
from tests.common.platform.interface_utils import check_interface_information
from tests.common.platform.daemon_utils import check_pmon_daemon_status
from tests.common.platform.transceiver_utils import check_transceiver_basic
from tests.common.plugins.sanity_check import checks

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0-soak')
]

MAX_WAIT_TIME_FOR_INTERFACES = 300
MAX_WAIT_TIME_FOR_REBOOT_CAUSE = 120

class ContinuousReboot:
    def __init__(self, request, duthost, ptfhost, localhost, conn_graph_facts, get_advanced_reboot):
        self.request = request
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.localhost = localhost
        self.conn_graph_facts = conn_graph_facts
        self.continuous_reboot_count = request.config.getoption("--continuous_reboot_count")
        self.continuous_reboot_delay = request.config.getoption("--continuous_reboot_delay")
        self.enable_continuous_io = request.config.getoption("--enable_continuous_io")
        self.image_location = request.config.getoption("--image_location")
        self.image_list = request.config.getoption("--image_list")
        self.get_advanced_reboot = get_advanced_reboot
        self.currentImage = self.duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']

        if self.image_location is None:
            logging.error("Invalid image location specified: {}".format(str(self.image_location)))

    def reboot_and_check(self, interfaces, reboot_type=REBOOT_TYPE_WARM, reboot_kwargs=None):
        """
        Perform the specified type of reboot and check platform status.
        @param interfaces: DUT's interfaces defined by minigraph
        @param reboot_type: The reboot type, pre-defined const that has name convention of REBOOT_TYPE_XXX.
        @param reboot_kwargs: The argument used by reboot_helper
        """
        logging.info("Run %s reboot on DUT" % reboot_type)

        reboot(self.duthost, self.localhost, reboot_type=reboot_type, reboot_helper=None, reboot_kwargs=reboot_kwargs)

        # Perform health-check
        self.check_services()
        self.check_reboot_type(reboot_type)
        self.check_interfaces_and_transceivers(interfaces)
        self.check_neighbors()


    def check_services(self):
        """
        Perform a health check of services
        """
        logging.info("Wait until all critical services are fully started")
        check_critical_services(self.duthost)


    def check_reboot_type(self, reboot_type=None):
        """
        Perform a match of reboot-cause and reboot-trigger
        """
        if reboot_type is not None:
            logging.info("Check reboot cause")
            pytest_assert(wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, check_reboot_cause, self.duthost, reboot_type), \
                "got reboot-cause failed after rebooted by %s" % reboot_type)

            if reboot_ctrl_dict[reboot_type]["test_reboot_cause_only"]:
                logging.info("Further checking skipped for %s test which intends to verify reboot-cause only" % reboot_type)
                return


    def check_interfaces_and_transceivers(self, interfaces):
        """
        Perform a check of transceivers, LAGs and interfaces status
        @param dut: The AnsibleHost object of DUT.
        @param interfaces: DUT's interfaces defined by minigraph
        """
        logging.info("Wait %d seconds for all the transceivers to be detected" % MAX_WAIT_TIME_FOR_INTERFACES)
        pytest_assert(wait_until(MAX_WAIT_TIME_FOR_INTERFACES, 20, check_interface_information, self.duthost, interfaces), \
            "Not all transceivers are detected or interfaces are up in %d seconds" % MAX_WAIT_TIME_FOR_INTERFACES)

        logging.info("Check transceiver status")
        check_transceiver_basic(self.duthost, interfaces)

        logging.info("Check LAGs and interfaces status")
        checks.check_interfaces(self.duthost)


    def check_neighbors(self):
        """
        Perform a BGP neighborship check.
        """
        logging.info("Check BGP neighbors status. Expected state - established")
        bgp_facts = self.duthost.bgp_facts()['ansible_facts']
        mg_facts  = self.duthost.minigraph_facts(host=self.duthost.hostname)['ansible_facts']

        for value in bgp_facts['bgp_neighbors'].values():
            # Verify bgp sessions are established
            pytest_assert(value['state'] == 'established', "BGP session not established")
            # Verify locat ASNs in bgp sessions
            pytest_assert(value['local AS'] == mg_facts['minigraph_bgp_asn'], \
            "Local ASNs not found in BGP session")

        for v in mg_facts['minigraph_bgp']:
            # Compare the bgp neighbors name with minigraph bgp neigbhors name
            pytest_assert(v['name'] == bgp_facts['bgp_neighbors'][v['addr'].lower()]['description'], \
            "BGP neighbor's name does not match minigraph")
            # Compare the bgp neighbors ASN with minigraph
            pytest_assert(v['asn'] == bgp_facts['bgp_neighbors'][v['addr'].lower()]['remote AS'], \
            "BGP neighbor's ASN does not match minigraph")


    def start_cont_warm_reboot(self):
        """
        @summary: This test case is to perform continuous warm reboot in a row
        """
        asic_type = self.duthost.facts["asic_type"]
        if asic_type in ["mellanox"]:
            issu_capability = self.duthost.command("show platform mlnx issu")["stdout"]
            if "disabled" in issu_capability:
                pytest.skip("ISSU is not supported on this DUT, skip this test case")

        # Start advancedReboot script on the ptf host to enable continuous I/O
        advancedReboot = self.get_advanced_reboot(rebootType='warm-reboot', enableContinuousIO=self.enable_continuous_io)
        thr = threading.Thread(target=advancedReboot.runRebootTestcase)
        thr.setDaemon(True)
        thr.start()

        file_template = {
            'install_list': self.image_list, # this list can be modified at runtime to enable testing different images
            'location': self.image_location,
            'CONTINUOUS_IO': True,
        }
        with open("image_install_list.json", "w") as image_file:
            json.dump(file_template, image_file)

        # Start continuous warm reboot on the DUT
        for count in range(self.continuous_reboot_count):
            logging.info("==================== Continuous warm reboot iteration: {}/{} ====================".format \
                (count + 1, self.continuous_reboot_count))
            with open("image_install_list.json", "r") as f:
                install_info = json.load(f)
                image_install_list = install_info.get('install_list').split(",")
                # Use modulus operator to cycle through the image_install_list per reboot iteration
                image = image_install_list[count % len(image_install_list)].strip()
                image_path = install_info.get('location').strip() + image

            if image == "current":
                logging.info("Next image is set to current - skip image installation")
            else:
                advancedReboot.newSonicImage = image_path
                advancedReboot.cleanupOldSonicImages = True
                logging.info("Installing image {} on DUT".format(image_path))
                advancedReboot.imageInstall()
            self.reboot_and_check(self.conn_graph_facts["device_conn"], reboot_type=REBOOT_TYPE_WARM)
            wait(self.continuous_reboot_delay, msg="Wait {}s before next warm-reboot".format(self.continuous_reboot_delay))
        try:
            # Find the pid of continuous I/O script inside ptf container and send a stop, clean signal
            pid_res = self.ptfhost.command("cat /tmp/advanced-reboot-pid.log")
            logging.info("Find PID result: {}".format(pid_res))
            self.ptfhost.command("kill -SIGUSR1 {}".format(pid_res['stdout']))
            res = self.ptfhost.command("rm /tmp/advanced-reboot-pid.log")
            logging.info("File deletion on ptfhost: {}".format(res))
        except RunAnsibleModuleFail as err:
            if 'stderr_lines' in err.results:
                logging.info("Executing cmd: {} failed. Error: {}".format( \
                    str(err.results.get('cmd')), str(err.results.get('stderr_lines'))))
        # Make sure that the cont-IO thread is completed
        thr.join(60)
        if thr.is_alive():
            logging.error("Failed to join continuous I/O thread in 60s")
        logging.info("Continuous warm-reboot test completed")

def test_cont_warm_reboot(request, duthost, ptfhost, localhost, conn_graph_facts, get_advanced_reboot):
    continuous_reboot = ContinuousReboot(request, duthost, ptfhost, localhost, conn_graph_facts, \
        get_advanced_reboot)

    continuous_reboot.start_cont_warm_reboot()
