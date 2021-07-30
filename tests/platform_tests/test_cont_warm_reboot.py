import os
import shutil
import csv
import sys
import time
import json
import traceback
import pytest
import logging
from datetime import datetime
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import get_reboot_cause
from tests.common.fixtures.advanced_reboot import AdvancedReboot

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]

from tests.platform_tests.verify_dut_health import RebootHealthError,\
    check_services, check_interfaces_and_transceivers, check_neighbors,\
    verify_no_coredumps, handle_test_error, wait_until_uptime, get_test_report

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0')
]

MAX_WAIT_TIME_FOR_INTERFACES = 30
MAX_WAIT_TIME_FOR_REBOOT_CAUSE = 120


class ContinuousReboot:
    def __init__(self, request, duthost, ptfhost, localhost, conn_graph_facts):
        self.request = request
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.localhost = localhost
        self.conn_graph_facts = conn_graph_facts
        self.continuous_reboot_count = request.config.getoption("--continuous_reboot_count")
        self.continuous_reboot_delay = request.config.getoption("--continuous_reboot_delay")
        self.reboot_type = request.config.getoption("--reboot_type")
        self.image_location = request.config.getoption("--image_location")
        self.image_list = request.config.getoption("--image_list")
        self.current_image = self.duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
        self.test_report = dict()
        if self.image_location is None:
            logging.error("Invalid image location specified: {}".format(str(self.image_location)))

        self.init_reporting()


    def init_reporting(self):
        self.reboot_count = None
        self.current_image = None
        self.is_new_image = None
        self.test_duration = None
        self.critical_services = None
        self.interfaces = None
        self.lag_interfaces = None
        self.control_plane = None
        self.data_plane = None
        self.sub_test_result = True
        self.test_failures = 0
        self.warm_reboot_count = 0
        self.warm_reboot_pass = 0
        self.warm_reboot_fail = 0
        self.fast_reboot_count = 0
        self.fast_reboot_pass = 0
        self.fast_reboot_fail = 0
        self.pre_existing_cores = 0


    def reboot_and_check(self, tbinfo):
        """
        Perform the specified type of reboot and check platform status.
        @param interfaces: DUT's interfaces defined by minigraph
        @param reboot_type: The reboot type, pre-defined const that has name convention of REBOOT_TYPE_XXX.
        @param reboot_kwargs: The argument used by reboot_helper
        """
        logging.info("Run %s reboot on DUT" % self.reboot_type)
        self.run_reboot_testcase()
        # Wait until uptime reaches allowed value
        wait_until_uptime(self.duthost, self.continuous_reboot_delay)
        # Perform additional post-reboot health-check
        verify_no_coredumps(self.duthost, self.pre_existing_cores)
        self.verify_image()
        check_services(self.duthost)
        self.check_reboot_type()
        check_interfaces_and_transceivers(self.duthost, self.request)
        check_neighbors(self.duthost, tbinfo)
        logging.info("Finished reboot test and health checks..")


    @handle_test_error
    def run_reboot_testcase(self):
        result = self.advancedReboot.runRebootTest()
        if result is not True:
            # Create a failure report
            error = result.get("stderr")
            raise RebootHealthError("Reboot test failed with error: {}".format(error))


    @handle_test_error
    def check_reboot_type(self):
        """
        Perform a match of reboot-cause and reboot-trigger
        """
        logging.info("Check reboot cause")
        reboot_cause = get_reboot_cause(self.duthost)
        if reboot_cause != self.reboot_type:
            raise RebootHealthError("Reboot cause {} did not match the trigger {}".format(reboot_cause, self.reboot_type))


    @handle_test_error
    def verify_image(self):
        self.current_image = self.duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
        if self.is_new_image is True:
            # After boot-up, verify that the required image is running on the DUT
            if self.advancedReboot.binaryVersion != self.current_image:
                raise RebootHealthError("Image installation failed.\
                    Expected: {}. Found: {}".format(self.advancedReboot.binaryVersion, self.current_image))


    def check_test_params(self):
        while True:
            with open(self.input_file, "r") as f:
                try:
                    install_info = json.load(f)
                    if str(install_info.get('STOP_TEST')).lower() == 'true':
                        logging.info("==================== Stop test instruction received.\
                            Terminating test early at {}/{} iteration ====================".format \
                            (self.reboot_count, self.continuous_reboot_count))
                        return False
                    if str(install_info.get('PAUSE_TEST')).lower() == 'true':
                        time.sleep(10)
                        continue
                    reboot_type = str(install_info.get('REBOOT_TYPE')).lower()
                    if reboot_type != 'warm' and reboot_type != 'fast':
                        logging.warn("Unsupported reboot type - {}. Proceeding with {}.".format(reboot_type, self.reboot_type))
                    else:
                        self.reboot_type = reboot_type
                except ValueError:
                    logging.warn("Invalid json file, continuing the reboot test with old list of images")
                break
        logging.info("Copy latest PTF test files to PTF host '{0}'".format(self.ptfhost.hostname))
        self.ptfhost.copy(src="ptftests", dest="/root")
        return True


    def handle_image_installation(self, count):
        with open(self.input_file, "r") as f:
            try:
                install_info = json.load(f)
                image_install_list = install_info.get('install_list').split(",")
                # Use modulus operator to cycle through the image_install_list per reboot iteration
                self.new_image = image_install_list[count % len(image_install_list)].strip()
                image_path = install_info.get('location').strip() + "/" + self.new_image
                file_exists = self.duthost.command("curl -o /dev/null --silent -Iw '%{{http_code}}' {}".format(image_path),\
                    module_ignore_errors=True)["stdout"]
                if file_exists != '200':
                    logging.info("Remote image file {} does not exist. Curl returned: {}".format(image_path, file_exists))
                    logging.warn("Continuing the test with current image")
                    self.new_image = "current"
            except ValueError:
                logging.warn("Invalid json file, continuing the reboot test with old list of images")

        if self.new_image == "current":
            logging.info("Next image is set to current - skip image installation")
            self.advancedReboot.newSonicImage = None
            self.is_new_image = False
        else:
            self.advancedReboot.newSonicImage = image_path
            self.advancedReboot.cleanupOldSonicImages = True
            self.is_new_image = True
            logging.info("Image to be installed on DUT - {}".format(image_path))
        self.advancedReboot.imageInstall()
        if self.advancedReboot.newImage:
            # The image upgrade will delete all the preexisting cores
            self.pre_existing_cores = 0


    def test_set_up(self):
        asic_type = self.duthost.facts["asic_type"]
        if asic_type in ["mellanox"]:
            issu_capability = self.duthost.command("show platform mlnx issu")["stdout"]
            if "disabled" in issu_capability:
                pytest.skip("ISSU is not supported on this DUT, skip this test case")

        self.pre_existing_cores = self.duthost.shell('ls /var/core/ | wc -l')['stdout']
        logging.info("Found {} preexisting core files inside /var/core/".format(self.pre_existing_cores))

        input_data = {
            'install_list': self.image_list, # this list can be modified at runtime to enable testing different images
            'location': self.image_location,
            'REBOOT_TYPE': "warm",
            'PAUSE_TEST': False,
            'STOP_TEST': False
        }

        self.log_dir = os.getcwd() + "continous_reboot"
        dir_name = "continous_reboot_{}".format(datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        self.log_dir = os.path.join(os.getcwd(), dir_name)
        os.makedirs(self.log_dir)

        # test input file for dynamic interaction
        self.input_file = os.path.join(self.log_dir, "continuous_reboot_input.json")
        with open(self.input_file, "w") as image_file:
            json.dump(input_data, image_file, indent=4)

        # test output file for results
        self.reports_file = os.path.join(self.log_dir, "continuous_reboot_report.csv")
        with open(self.reports_file, "w") as report_file:
            header = ["test_id", "image", "is_new_image", "up_time", "test_duration", "result"]
            writer = csv.DictWriter(report_file, fieldnames=header)
            writer.writeheader()


    def create_test_report(self):
        if self.sub_test_result is False:
            self.test_failures = self.test_failures + 1

        if self.reboot_type == "warm":
            self.warm_reboot_count = self.warm_reboot_count + 1
            if self.sub_test_result is False:
                self.warm_reboot_fail = self.warm_reboot_fail + 1
            else:
                self.warm_reboot_pass = self.warm_reboot_pass + 1
        elif self.reboot_type == "fast":
            self.fast_reboot_count = self.fast_reboot_count + 1
            if self.sub_test_result is False:
                self.fast_reboot_fail = self.fast_reboot_fail + 1
            else:
                self.fast_reboot_pass = self.fast_reboot_pass + 1

        test_report = {
            "test_id": self.reboot_count,
            "image": self.current_image,
            "is_new_image": self.is_new_image,
            "up_time": str(self.duthost.get_uptime().total_seconds()) + "s",
            "test_duration": str((self.test_end_time - self.test_start_time).total_seconds())  + "s",
            "result": self.sub_test_result
        }
        with open(self.reports_file, "a") as report_file:
            header = ["test_id", "image", "is_new_image", "up_time", "test_duration", "result"]
            writer = csv.DictWriter(report_file, fieldnames=header)
            writer.writerow(test_report)

        log_files = [
            '/tmp/{0}-reboot.log'.format(self.reboot_type),
            '/tmp/capture.pcap',
            '/tmp/capture_filtered.pcap',
            '/tmp/syslog',
            '/tmp/sairedis.rec',
            '/tmp/swss.rec']

        if self.sub_test_result is True:
            test_dir = os.path.join(self.log_dir, "pass", str(self.reboot_count))
        else:
            test_dir = os.path.join(self.log_dir, "fail", str(self.reboot_count))
        os.makedirs(test_dir)
        for file in log_files:
            try:
                file_exists = os.path.isfile(file)
                if file_exists:
                    shutil.move(file, test_dir)
            except Exception:
                logging.error("Error copying file {}".format(str(file)))
        report_file =  os.path.join(test_dir, "continuous_reboot_report.json")
        test_report["checks"] = self.test_report
        with open(report_file, "w") as report_file:
            json.dump(test_report, report_file, indent=4)

        pytest_assert(self.test_failures == 0, "Continuous reboot test failed {}/{} times".\
            format(self.test_failures, self.reboot_count))


    def start_continuous_reboot(self, request, duthost, ptfhost, localhost, tbinfo, creds):
        self.test_set_up()
        # Start continuous warm/fast reboot on the DUT
        for count in range(self.continuous_reboot_count):
            self.reboot_count = count + 1
            self.sub_test_result = True # set default result to be True, any failure will set this to False
            self.test_start_time = datetime.now()
            logging.info("\n==================== Start continuous reboot iteration: {}/{}. Type: {} ===================="\
                .format(self.reboot_count, self.continuous_reboot_count, self.reboot_type))
            reboot_type = self.reboot_type + "-reboot"
            try:
                self.advancedReboot = AdvancedReboot(request, duthost, ptfhost, localhost, tbinfo, creds,\
                    rebootType=reboot_type, moduleIgnoreErrors=True)
            except Exception:
                self.sub_test_result = False
                self.test_failures = self.test_failures + 1
                logging.error("AdvancedReboot initialization failed with {}".format(traceback.format_exc()))
                logging.info("Waiting 300s for external fix or a signal to end the test...")
                time.sleep(300)
                if not self.check_test_params():
                    break
                continue
            self.handle_image_installation(count)
            self.reboot_and_check(tbinfo)
            self.test_report = get_test_report()
            self.sub_test_result = all([check == True for check in list(self.test_report.values())])
            self.advancedReboot.newSonicImage = None
            self.test_end_time = datetime.now()
            self.create_test_report()
            logging.info("\n==================== End continuous reboot iteration: {}/{}. Result: {} ===================="\
                .format(self.reboot_count, self.continuous_reboot_count, self.sub_test_result))
            if not self.check_test_params():
                break


    def test_teardown(self):
        logging.info("="*50)
        logging.info("----- Total continuous reboots: {}. Pass: {}. Fail: {} ------".format(self.reboot_count,\
            self.reboot_count - self.test_failures, self.test_failures))
        logging.info("------ Total warm reboot tests: {}. Pass: {}. Fail: {} ------". \
            format(self.warm_reboot_count, self.warm_reboot_pass, self.warm_reboot_fail))
        logging.info("------ Total fast reboot tests: {}. Pass: {}. Fail: {} ------". \
            format(self.fast_reboot_count, self.fast_reboot_pass, self.fast_reboot_fail))
        logging.info("-"*50)
        logging.info("Test results summary available at {}".format(self.log_dir + "/continuous_reboot_report.csv"))
        logging.info("Passed tests logs stored at {}".format(self.log_dir + "/pass/"))
        logging.info("Failed tests logs stored at {}".format(self.log_dir + "/fail/"))
        logging.info("="*50)
        pytest_assert(self.test_failures == 0, "Continuous reboot test failed {}/{} times".\
            format(self.test_failures, self.reboot_count))


@pytest.mark.device_type('vs')
def test_continuous_reboot(request, duthosts, rand_one_dut_hostname, ptfhost, localhost, conn_graph_facts, tbinfo, creds):
    """
    @summary: This test performs continuous reboot cycles on images that are provided as an input.
    Supported parameters for this test can be modified at runtime:
        Image Name, Image location - to run new iterations of the test on a new image
        Pause test - for some debug, fixes on DUT to get it to stable state, etc.)
        Stop test - for graceful termination of test.
        Reboot type - To change the type to WARM or FAST at runtime.
    Additionally, the test incorporates running a script (advanced-reboot.py) on PTF container.
    To introducing additional checks (or to modify, remove checks), this test can be PAUSED, and the PTF
    test script can be modified. The newer iterations of this test will start executing latest ptf script.
    In between reboot cycles, the test verifies:
        New image matches the image that the test has installed
        Reboot cause - should match the trigger cause.
        DUT is stable. Ping should work from T1 to servers and from servers to T1
        Control and data plane should be healthy (as defined by advanced-reboot.py script)
        Status of services - services syncd and swss should be active/running
        Status of interfaces and LAGs - all interface and LAGs should comply with current topology
        Status of transceivers - ports in lab_connection_graph should be present
        Status of BGP neighbors - should be established
    """
    duthost = duthosts[rand_one_dut_hostname]
    continuous_reboot = ContinuousReboot(request, duthost, ptfhost, localhost, conn_graph_facts)
    continuous_reboot.start_continuous_reboot(request, duthost, ptfhost, localhost, tbinfo, creds)
    continuous_reboot.test_teardown()
