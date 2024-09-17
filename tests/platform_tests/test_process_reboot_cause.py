import os
import json
import logging
import time
import pytest

from retry.api import retry_call
from tests.common.utilities import wait_until, check_skip_release
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import wait_until, check_skip_release
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
]

SYSTEMCTL_SHOW_CMD = "systemctl show process-reboot-cause.service --property='ExecMainPID' --property='ExecMainStatus' --property='Result'"
SYSTEMCTL_RESTART_CMD = "systemctl restart process-reboot-cause.service"
JOURNALCTL_CMD = "journalctl -u process-reboot-cause.service _PID={}"

REBOOT_CAUSE_GEN_TIME_CMD = 'date +"%Y_%m_%d_%H_%M_%S"'
REBOOT_CAUSE_HISTORY_DIR = "/host/reboot-cause/history/"
REBOOT_CAUSE_FILE_FORMAT = "reboot-cause-{}.json"
REBOOT_TYPES = ['warm-reboot', 'fast-reboot', 'soft-reboot', 'reboot', 'Power loss', 'Watchdog',  'Unknown', 'Hardware - Other', 'Non-Hardware']
BAD_JSON = "{'gen_time:'"
GOOD_JSON = {"gen_time": "9999_99_99_99_99_99", "cause": "", "user": "admin", "time": "N/A", "comment": "N/A"}
JSON_DECODE_ERROR = "json.decoder.JSONDecodeError"
EXCEPTION_HANDLED_SYSLOG = "Unable to process reload cause file {}"
REBOOT_CAUSE_TEST_IDENTIFIER = "process-reboot-cause-test"


class TestProcessRebootCause():
    
    duthost = None
    image_ver = None
    image_major_ver = None
    image_minor_ver = None

    @pytest.fixture(scope="function", autouse=True)
    def setup(self, duthosts, enum_rand_one_per_hwsku_hostname):
        if self.duthost == None:
            self.duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        skip, reason = check_skip_release(self.duthost, ["201811", "201911"])
        if skip is True:
            pytest.skip("Skip test 'process-reboot-cause' for {} running image {} due to reason: {}".format(self.duthost.facts['platform'], self.duthost.os_version, reason))
        
        # Get image version on DUT
        self.image_ver = self.duthost.sonichost.os_version

        # Get major and minor version of image
        self.image_major_ver = int(self.image_ver.split('.')[0])
        self.image_minor_ver = int(self.image_ver.split('.')[-1])


    ##########################
    #                        #
    #      HELPER FNS        #
    #                        #
    ##########################


    def get_service_status(self):
        """
        @summary: Check status of process-reboot-cause.service and return parameters to calling function
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


    def create_json_file(self, filetype=""):

        gen_time = self.duthost.command(REBOOT_CAUSE_GEN_TIME_CMD)["stdout_lines"][0]
        reboot_cause_file = os.path.join(REBOOT_CAUSE_HISTORY_DIR, REBOOT_CAUSE_FILE_FORMAT.format(gen_time))

        logging.info("Writing '{}' to {} on DUT".format(filetype, reboot_cause_file))
        _ = self.duthost.command("bash -c 'echo {}>{}'".format(filetype, reboot_cause_file))

        return reboot_cause_file


    def remove_json_file(self, reboot_cause_file):
        logging.info("Clean up the newly created JSON file: {}".format(reboot_cause_file))
        _ = self.duthost.command('rm -f {}'.format(reboot_cause_file))


    def bad_json_file_assertions(self, status, result, journalctl_output):
        
        # Check for exeception if image version < 2023110.20 , 20230531.33 or 20220531.53
        if self.image_major_ver < 20220531 or \
        (self.image_major_ver == 20231110 and self.image_minor_ver < 20) or \
        (self.image_major_ver == 20230531 and self.image_minor_ver < 33) or \
        (self.image_major_ver == 20220531 and self.image_minor_ver < 53):

            logging.info("OS Version {} does not have the patched process-reboot-cause file with try-except block".format(self.image_ver))
            is_json_decode_error = any(JSON_DECODE_ERROR in line for line in journalctl_output)

            pytest_assert(result == "exit-code")
            pytest_assert(status == 1)
            pytest_assert(is_json_decode_error)
        
        else:
            logging.info("OS Version {} has the patched process-reboot-cause file with try-except block".format(self.image_ver))
            message = EXCEPTION_HANDLED_SYSLOG.format(reboot_cause_file)
            exception_handled_log = any(message in line for line in journalctl_output)
            logging.info("exception_handled_log: {}".format(journalctl_output))
            pytest_assert(result == "success")
            pytest_assert(status == 0)
            pytest_assert(exception_handled_log)


    def good_json_file_assertions(self, status, result, cause, journalctl_output, statedb_output):

            excpected_reboot_cause = any(cause in line for line in statedb_output)
            
            pytest_assert(result == "success")
            pytest_assert(status == 0)
            pytest_assert(excpected_reboot_cause)


    def process_reboot_cause_file_runner(self, filetype=""):

        # Create a JSON file
        reboot_cause_file = self.create_json_file(filetype)

        # Restart process-reboot-cause.service
        self.restart_service()

        # Wait 5 seconds
        time.sleep(5)

        # Get latest status of the service
        logging.info("Get latest status of the process-reboot-cause.service")
        main_pid, status, result = self.get_service_status()
        journalctl_output = self.duthost.command(JOURNALCTL_CMD.format(main_pid))["stdout_lines"]

        # Get STATE_DB kvps created from latest JSON file
        statedb_output = self.duthost.command('redis-cli -n 6 HGETALL "REBOOT_CAUSE|9999_99_99_99_99_99"')["stdout_lines"]
        _ = self.duthost.command('redis-cli -n 6 DEL "REBOOT_CAUSE|9999_99_99_99_99_99"')


        # Remove the JSON file
        self.remove_json_file(reboot_cause_file)

        # Restart process-reboot-cause.service
        self.restart_service()

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

            main_pid, status, result, _, statedb_output = self.process_reboot_cause_file_runner(valid_json_str)
            logging.info("PID: {} Status: {} Result: {} Cause: {} ".format(main_pid, status, result, cause))
            self.good_json_file_assertions(status, result, cause, _ , statedb_output)


    def test_empty_json_file(self):

       main_pid, status, result, journalctl_output, _ = self.process_reboot_cause_file_runner()
       self.bad_json_file_assertions(status, result, journalctl_output)


    def test_malformed_json_file(self):

        main_pid, status, result, journalctl_output, _ = self.process_reboot_cause_file_runner(BAD_JSON)
        self.bad_json_file_assertions(status, result, journalctl_output)
