import os
import logging
import time
import pytest

from tests.common.utilities import check_skip_release
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
]

SYSTEMCTL_SHOW_CMD = "systemctl show process-reboot-cause.service --property='ExecMainPID' --property='ExecMainStatus' --property='Result'"  # noqa: E501
SYSTEMCTL_RESTART_CMD = "systemctl restart process-reboot-cause.service"
JOURNALCTL_CMD = "journalctl -u process-reboot-cause.service _PID={}"

REBOOT_CAUSE_GEN_TIME_CMD = 'date +"%Y_%m_%d_%H_%M_%S"'
REBOOT_CAUSE_HISTORY_DIR = "/host/reboot-cause/history/"
REBOOT_CAUSE_FILE_FORMAT = "reboot-cause-{}.json"
REBOOT_TYPES = ['warm-reboot', 'fast-reboot', 'soft-reboot', 'reboot', 'Power loss', 'Watchdog',  'Unknown', 'Hardware - Other', 'Non-Hardware']  # noqa: E501
BAD_JSON = "{'gen_time:'"
GOOD_JSON = {"gen_time": "9999_99_99_99_99_99", "cause": "", "user": "admin", "time": "N/A", "comment": "N/A"}  # noqa: E501
EXCEPTION_HANDLED_SYSLOG = "Unable to process reload cause file"
REBOOT_CAUSE_TEST_IDENTIFIER = "process-reboot-cause-test"


class TestProcessRebootCause():

    duthost = None
    image_ver = None
    reboot_cause_file = None
    skip = None
    reason = None

    @pytest.fixture(autouse=True)
    def setup_create_and_delete_json_files(self, duthosts, enum_rand_one_per_hwsku_hostname):  # noqa: E501
        if self.duthost is None:
            self.duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        skip, reason = check_skip_release(self.duthost, ["201811", "201911"])
        if skip is True:
            pytest.skip("Skip test 'process-reboot-cause' for {} running image {} due to reason: {}".format(self.dthost.facts['platform'], self.duthost.os_version, reason))  # noqa: E501

        if self.image_ver is None:
            # Get image version on DUT
            self.image_ver = self.duthost.sonichost.os_version

        # Create a dummy JSON file to test
        self.create_json_file()

        yield

        # Remove the JSON file
        self.remove_json_file()

        # Restart process-reboot-cause.service
        self.restart_service()

        self.reboot_cause_file = None

    ##########################
    #                        #
    #      HELPER FNS        #
    #                        #
    ##########################

    def get_service_status(self):
        """
        @summary: Check status of process-reboot-cause.service and return parameters to calling function  # noqa: E501
        """

        status = -1
        main_pid = -1
        result = ""

        systemctl_output = self.duthost.command(SYSTEMCTL_SHOW_CMD)

        for line in systemctl_output["stdout_lines"]:
            if "ExecMainPID" in line:
                main_pid = int(line.split("=")[-1])
            elif "ExecMainStatus" in line:
                status = int(line.split("=")[-1])
            elif "Result" in line:
                result = line.split("=")[-1]

        return main_pid, status, result

    def restart_service(self):
        logging.info("Restarting process-reboot-cause.service")
        _ = self.duthost.command(SYSTEMCTL_RESTART_CMD)

    def create_json_file(self):

        gen_time = self.duthost.command(REBOOT_CAUSE_GEN_TIME_CMD)["stdout_lines"][0]  # noqa: E501
        self.reboot_cause_file = os.path.join(REBOOT_CAUSE_HISTORY_DIR, REBOOT_CAUSE_FILE_FORMAT.format(gen_time))  # noqa: E501

        _ = self.duthost.command("bash -c 'touch {}'".format(self.reboot_cause_file))  # noqa: E501

    def populate_json_file(self, filetype=""):

        logging.info("Writing '{}' to {} on DUT".format(filetype, self.reboot_cause_file))  # noqa: E501
        _ = self.duthost.command("bash -c 'echo {}>{}'".format(filetype, self.reboot_cause_file))  # noqa: E501

    def remove_json_file(self):
        logging.info("Clean up the newly created JSON file: {}".format(self.reboot_cause_file))  # noqa: E501
        _ = self.duthost.command('rm -f {}'.format(self.reboot_cause_file))

    def bad_json_file_assertions(self, status, result, journalctl_output):

        logging.info("OS Version {} has the patched process-reboot-cause file with try-except block".format(self.image_ver))  # noqa: E501
        exception_handled_log = any(EXCEPTION_HANDLED_SYSLOG in line for line in journalctl_output)  # noqa: E501
        logging.info("exception_handled_log: {}".format(journalctl_output))
        pytest_assert(result == "success")
        pytest_assert(status == 0)
        pytest_assert(exception_handled_log)

    def good_json_file_assertions(self, status, result, cause, journalctl_output, statedb_output):  # noqa: E501

        '''
        With a good JSON file, the following assertions must be true:

            1. process-reboot-cause service should have successfully run to completion  # noqa: E501
            2. The status of the service should be 0 (no errors)
            3. The reboot cause on the STATE_DB (expected_reboot_cause) should be the same as the one in the JSON file  # noqa: E501

        For example, this is the reboot cause KVPs as parsed from a good JSON file:  # noqa: E501

        admin@sonic-device:~$ redis-cli -n 6 HGETALL "REBOOT_CAUSE|2024_10_21_15_16_57"  # noqa: E501
            1) "cause"
            2) "reboot"
            3) "time"
            4) "Mon Oct 21 03:15:13 PM UTC 2024"
            5) "user"
            6) "admin"
            7) "comment"
            8) "N/A"

        As we create a dummy JSON file with timestamp: 9999_99_99_99_99_99, we can get the reboot cause for just that entry,  # noqa: E501
        and assert that it is the expected reboot cause rom the JSON file.
        '''
        logging.info("expected reboot cause: {} - statedb output: {}".format(cause, statedb_output))  # noqa: E501

        pytest_assert(result == "success")
        pytest_assert(status == 0)
        pytest_assert(cause == statedb_output)

    def process_reboot_cause_file_runner(self, filetype=""):

        # Populate the newly created reboot-cause file
        self.populate_json_file(filetype)

        # Restart process-reboot-cause.service
        self.restart_service()

        # Wait 5 seconds
        time.sleep(5)

        # Get latest status of the service
        logging.info("Get latest status of the process-reboot-cause.service")
        main_pid, status, result = self.get_service_status()
        journalctl_output = self.duthost.command(JOURNALCTL_CMD.format(main_pid))["stdout_lines"]  # noqa: E501

        # Get STATE_DB kvps created from latest JSON file
        statedb_output = None

        try:
            statedb_output = self.duthost.command('sonic-db-cli STATE_DB HGET "REBOOT_CAUSE|9999_99_99_99_99_99" cause')["stdout_lines"][0].strip()  # noqa: E501
        except IndexError:
            pass

        logging.info("statedb output: {}".format(statedb_output))

        # Remove the dummy reboot cause entry from the STATE_DB
        _ = self.duthost.command('sonic-db-cli STATE_DB DEL "REBOOT_CAUSE|9999_99_99_99_99_99"')  # noqa: E501

        # Return relevant fields
        return main_pid, status, result, journalctl_output, statedb_output

    ##########################
    #                        #
    #      TESTS BEGIN       #
    #                        #
    ##########################

    def test_status_on_boot(self):
        main_pid, status, result = self.get_service_status()

        pytest_assert(main_pid != -1)
        pytest_assert(status == 0)
        pytest_assert(result == "success")

    def test_valid_reboot_causes(self):

        for cause in REBOOT_TYPES:
            logging.info("Testing valid reboot type: {}".format(cause))

            GOOD_JSON["cause"] = cause
            valid_json_str = (str(GOOD_JSON)).replace("'", "\\\"")

            main_pid, status, result, _, statedb_output = self.process_reboot_cause_file_runner(valid_json_str)  # noqa: E501
            logging.info("PID: {} Status: {} Result: {} Cause: {} ".format(main_pid, status, result, cause))  # noqa: E501
            self.good_json_file_assertions(status, result, cause, _, statedb_output)  # noqa: E501

    def test_empty_json_file(self):

        main_pid, status, result, journalctl_output, _ = self.process_reboot_cause_file_runner()  # noqa: E501
        self.bad_json_file_assertions(status, result, journalctl_output)

    def test_malformed_json_file(self):

        main_pid, status, result, journalctl_output, _ = self.process_reboot_cause_file_runner(BAD_JSON)  # noqa: E501
        self.bad_json_file_assertions(status, result, journalctl_output)
