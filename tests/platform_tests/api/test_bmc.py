import os
import logging
import json
import pytest
import random
import re
import secrets
import time
from urllib.parse import urlparse
from datetime import datetime

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import bmc
from tests.common.platform.device_utils import platform_api_conn, start_platform_api_service    # noqa: F401
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from .platform_api_test_base import PlatformApiTestBase
from tests.common.helpers.firmware_helper import show_firmware, FW_TYPE_UPDATE, PLATFORM_COMP_PATH_TEMPLATE


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

BMC_SHORTEST_PASSWD_LEN = 12
BMC_LONGEST_PASSWD_LEN = 20
BMC_DUMP_FILENAME = "bmc_dump_{}.tar.xz"
BMC_DUMP_PATH = "/tmp"
LATEST_BMC_VERSION_IDX = 0
OLD_BMC_VERSION_IDX = 1
EROT_BUSY_MSG = "ERoT is busy"
EROT_STABLE_TIMEOUT = 600
WAIT_TIME = 30
BMC_COMPONENT_NAME = 'BMC'
BMC_UPDATE_COMMAND = "sudo config platform firmware {} chassis component BMC fw -y"
BMC_INSTALL_COMMAND = "sudo config platform firmware {} chassis component BMC fw -y {}"
BMC_GET_STATUS_COMMAND = "curl -k -u {}:{} -X GET https://{}/redfish/v1/Chassis/MGX_ERoT_BMC_0"
BMC_COMPLETE_STATUS = "Completed"

# BMC session test commands
BMC_OPEN_SESSION_COMMAND = "sudo config bmc open-session"
BMC_CLOSE_SESSION_COMMAND = "sudo config bmc close-session --session-id {}"
BMC_RESET_ROOT_PASSWORD_COMMAND = "sudo config bmc reset-root-password"

# Redfish API endpoints (for session tests)
REDFISH_SESSION_SERVICE_ENDPOINT = "/redfish/v1/SessionService/Sessions"
REDFISH_EVENT_SUBSCRIPTIONS_ENDPOINT = "/redfish/v1/EventService/Subscriptions"

# Curl command templates (for session tests)
CURL_TOKEN_AUTH_GET = "curl -k -H \"X-Auth-Token: {}\" -X GET https://{}{}"
CURL_TOKEN_AUTH_GET_WITH_HEADERS = "curl -k -i -H \"X-Auth-Token: {}\" -X GET https://{}{}"
CURL_TOKEN_AUTH_POST = "curl -k -i -H \"X-Auth-Token: {}\" -H \"Content-Type: application/json\" -X POST https://{}{} -d '{}'"
CURL_TOKEN_AUTH_DELETE = "curl -i -k -H \"X-Auth-Token: {}\" -X DELETE https://{}{}"
CURL_BASIC_AUTH_GET = "curl -k -u {}:{} -X GET https://{}{}"
CURL_BASIC_AUTH_GET_WITH_HEADERS = "curl -k -i -u {}:{} -X GET https://{}{}"
CURL_BASIC_AUTH_PATCH = "curl -k -i -u {}:{} -H \"Content-Type: application/json\" -X PATCH https://{}{} -d '{}'"
CURL_BASIC_AUTH_DELETE = "curl -k -u {}:{} -X DELETE https://{}{}"

def pytest_generate_tests(metafunc):
    """
    Generate test parameters based on completeness_level for test_bmc_firmware_update
        If the completeness_level is basic, randomly select one command type from install and update
        If the completeness_level is others, test both install and update command types
            in this case,the test test_bmc_firmware_update will be executed twice times
    """
    if 'bmc_firmware_command_type' in metafunc.fixturenames:
        completeness_level = metafunc.config.getoption("--completeness_level", default="thorough")

        if completeness_level == "basic":
            command_type = random.choice(['install', 'update'])
            metafunc.parametrize("bmc_firmware_command_type", [command_type])
            logger.info(f"BMC firmware update test: basic level, randomly selected command type: {command_type}")
        else:
            metafunc.parametrize("bmc_firmware_command_type", ['install', 'update'])
            logger.info(f"BMC firmware update test: {completeness_level} level, testing both install and update")


class TestBMCApi(PlatformApiTestBase):
    """Platform and Host API test cases for the BMC class"""

    @pytest.fixture(scope="class", autouse=True)
    def skip_if_no_bmc(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """Skip tests if BMC is not present - these tests require BMC"""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        if not bmc.is_bmc_exists(duthost):
            pytest.skip("BMC is not present, skipping BMC platform API tests")

    @pytest.fixture(scope="class")
    def bmc_ip(self, duthosts, enum_rand_one_per_hwsku_hostname, skip_if_no_bmc):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        platform = duthost.shell("sudo show platform summary | grep Platform | awk '{print $2}'")["stdout"]
        bmc_config_file = f"/usr/share/sonic/device/{platform}/bmc.json"
        duthost.fetch(src=bmc_config_file, dest='/tmp')
        with open(f'/tmp/{duthost.hostname}/{bmc_config_file}', "r") as f:
            bmc_config = json.load(f)
        yield bmc_config["bmc_addr"]

    @pytest.fixture(autouse=True)
    def prepare_param(self, creds):
        self.bmc_root_user = creds['sonic_bmc_root_user']
        self.bmc_root_password = creds['sonic_bmc_root_password']

    def _is_bmc_busy(self, duthost, bmc_ip):
        """
        Check if BMC is busy by querying BackgroundCopyStatus from Redfish API

        Args:
            duthost: DUT host object
            bmc_ip: BMC IP address
        Returns:
            bool: True if BMC is busy (BackgroundCopyStatus != "Completed"), False otherwise
        """
        res = duthost.command(
            BMC_GET_STATUS_COMMAND.format(self.bmc_root_user, self.bmc_root_password, bmc_ip))["stdout"]
        pytest_assert(res is not None, "Failed to query BMC status")

        try:
            response_json = json.loads(res)
            background_copy_status = response_json.get("Oem", {}).get("Nvidia", {}).get("BackgroundCopyStatus", "")
            logger.info(f"BMC BackgroundCopyStatus: {background_copy_status}")

            return background_copy_status != BMC_COMPLETE_STATUS
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Failed to parse BMC status response: {e}, response: {res}")
            return True

    def _update_bmc_firmware(self, duthost, fw_image, bmc_ip, method='api',
                             cli_type=None, timeout=EROT_STABLE_TIMEOUT):
        """
        Update BMC firmware with retry mechanism for ERoT busy scenarios

        Args:
            duthost: DUT host object
            fw_image: Path to firmware image file
            bmc_ip: BMC IP address
            method: Update method - 'api' or 'cli' (default: 'api')
            cli_type: CLI command type when method='cli' - FW_TYPE_INSTALL or FW_TYPE_UPDATE
            timeout: Maximum time to wait for update (default: EROT_STABLE_TIMEOUT)

        Returns:
            bool: True if update successful, False otherwise
        """
        start_time = time.time()
        cli_suffix = f" ({cli_type})" if method == 'cli' and cli_type else ""
        logger.info(f"Starting BMC firmware update via {method.upper()}{cli_suffix}")

        while True:
            if time.time() - start_time > timeout:
                logger.warning(f"Timeout after {timeout} seconds while updating BMC firmware")
                return False
            time.sleep(WAIT_TIME)

            if method == 'api':
                ret_code, (message, _) = bmc.update_firmware(duthost, fw_image)

                if EROT_BUSY_MSG in message:
                    logger.info(f"{EROT_BUSY_MSG}, waiting for {WAIT_TIME} seconds")
                    continue
                elif ret_code != 0:
                    logger.warning(f"Failed to update BMC firmware: return code: {ret_code}, message: {message}")
                    return False
                else:
                    logger.info("BMC firmware updated successfully via API!")
                    break

            elif method == 'cli':
                if cli_type is None:
                    logger.error("cli_type must be specified when method='cli'")
                    return False

                is_bmc_busy = self._is_bmc_busy(duthost, bmc_ip)
                if is_bmc_busy:
                    logger.info(f"BMC is busy, waiting for {WAIT_TIME} seconds")
                    continue

                if cli_type == FW_TYPE_UPDATE:
                    res = duthost.command(BMC_UPDATE_COMMAND.format(cli_type))
                else:
                    res = duthost.command(BMC_INSTALL_COMMAND.format(cli_type, fw_image))

                if res['rc'] == 0:
                    logger.info(f"BMC firmware updated successfully via CLI ({cli_type})!")
                else:
                    logger.info(f"Failed to update BMC firmware: {res['stdout']}")
                break
            else:
                logger.error(f"Unknown update method: {method}")
                return False

        if method == 'api':
            logger.info("Requesting BMC reset after successful update by platform api")
            bmc.request_bmc_reset(duthost)

        return True

    def _generate_password(self):
        password_length = random.choice(range(BMC_SHORTEST_PASSWD_LEN, BMC_LONGEST_PASSWD_LEN))
        logger.info(f"Generated password length: {password_length}")
        raw_password = secrets.token_urlsafe(64)
        password = raw_password[:password_length]
        logger.info(f"Generated password: {password}")
        return password

    def _string_to_dict(self, str):
        result = {}
        for line in str.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                result[key.strip()] = value.strip()
        return result

    def _validate_bmc_login(self, duthost, bmc_ip, password, expected_success=True):
        res = duthost.command(f"curl -k -u {self.bmc_root_user}:{password} -X "                       # noqa: E231
                              f"GET https://{bmc_ip}/redfish/v1/AccountService/Accounts")["stdout"]   # noqa: E231
        pytest_assert(res is not None, "Failed to login to BMC")
        if expected_success:
            pytest_assert('error' not in res, f"Failed to login to BMC with password: {password}")
        else:
            pytest_assert('error' in res, f"Successfully login to BMC with password: {password}")

    def _change_bmc_root_password(self, duthost, bmc_ip, password):
        res = duthost.command(f'curl -k -u {self.bmc_root_user}:{self.bmc_root_password} -X PATCH '  # noqa: E231
                              f'https://{bmc_ip}/redfish/v1/AccountService/Accounts/root '           # noqa: E231
                              f'-H "Content-Type: application/json" '                                # noqa: E231
                              f'-d \'{{"Password":"{password}"}}\'')["stdout"]                       # noqa: E231
        pytest_assert(res is not None, f"Failed to change BMC root password to {password}")
        pytest_assert('error' not in res,
                      f"Failed to change BMC root password to {password} with error response: {res}")

    def _validate_bmc_dump_finished(self, duthost, task_id, timestamp):
        ret, msg = bmc.get_bmc_debug_log_dump(duthost, task_id, BMC_DUMP_FILENAME.format(timestamp), BMC_DUMP_PATH)
        if ret == 0 and msg == '':
            logger.info("BMC dump finished!")
            return True
        logger.info(f"Failed to retrieve BMC dump: {msg}")
        return False

    @pytest.fixture
    def cleanup_bmc_subscriptions(self, duthosts, enum_rand_one_per_hwsku_hostname, bmc_ip, prepare_param):
        """Cleanup BMC subscriptions before and after test"""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        # Setup: cleanup before test
        self._cleanup_existing_subscriptions(duthost, bmc_ip)

        yield

        # Teardown: cleanup after test
        self._cleanup_existing_subscriptions(duthost, bmc_ip)

    def _cleanup_existing_subscriptions(self, duthost, bmc_ip):
        """
        Cleanup all existing event subscriptions to ensure clean test environment

        Args:
            duthost: DUT host object
            bmc_ip: BMC IP address
        """
        get_cmd = CURL_BASIC_AUTH_GET.format(
            self.bmc_root_user, self.bmc_root_password, bmc_ip, REDFISH_EVENT_SUBSCRIPTIONS_ENDPOINT)
        get_subs_result = duthost.command(get_cmd, module_ignore_errors=True)

        if get_subs_result["rc"] == 0 and get_subs_result["stdout"]:
            try:
                subs_data = json.loads(get_subs_result["stdout"])
                existing_subs = self._extract_ids_from_members(subs_data)
                for sub_id in existing_subs:
                    delete_cmd = CURL_BASIC_AUTH_DELETE.format(
                        self.bmc_root_user, self.bmc_root_password, bmc_ip,
                        f"{REDFISH_EVENT_SUBSCRIPTIONS_ENDPOINT}/{sub_id}")
                    duthost.command(delete_cmd, module_ignore_errors=True)
                if existing_subs:
                    logger.info(f"Deleted {len(existing_subs)} existing subscriptions")
                    return len(existing_subs)
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.warning(f"Failed to parse subscription list response: {e}, response: {get_subs_result['stdout']}")
                return 0
        return 0

    def _get_bmc_version(self, duthost, timeout=120):
        start_time = time.time()

        while True:
            if time.time() - start_time > timeout:
                logger.warning(f"Timeout after {timeout} seconds while getting BMC version")
                return

            res = duthost.show_and_parse('sudo show platform firmware status')
            for entry in res:
                if entry['component'] == 'BMC':
                    if entry['version'] == 'N/A':
                        continue
                    return entry['version']

    def _generate_platform_file(self, duthost, chassis_name, fw_path, fw_version):
        """
        Generate 'platform_components.json' file for BMC firmware update test case

        This function:
        1. Tries to read existing platform_components.json from duthost
        2. If exists, updates the BMC component section
        3. If not exists, raises an error
        4. Writes the updated content back to duthost

        Args:
            duthost: DUT host object
            chassis_name: Name of the chassis
            fw_path: Path to the firmware file
            fw_version: Version of the firmware
        """
        platform_type = duthost.facts['platform']
        remote_comp_file_path = PLATFORM_COMP_PATH_TEMPLATE.format(platform_type)
        local_comp_file_path = "/tmp/platform_components.json"

        logger.info(f"Checking if '{remote_comp_file_path}' exists on {duthost.hostname}")
        check_result = duthost.stat(path=remote_comp_file_path)

        if check_result['stat']['exists']:

            logger.info(f"Reading existing 'platform_components.json' from {duthost.hostname}: {remote_comp_file_path}")
            output = duthost.command(f"cat {remote_comp_file_path}")["stdout"]
            json_data = json.loads(output)

            if BMC_COMPONENT_NAME not in json_data['chassis'][chassis_name]['component']:
                json_data['chassis'][chassis_name]['component'][BMC_COMPONENT_NAME] = {}

            json_data['chassis'][chassis_name]['component'][BMC_COMPONENT_NAME]['firmware'] = fw_path
            json_data['chassis'][chassis_name]['component'][BMC_COMPONENT_NAME]['version'] = fw_version
            logger.info(f"Updated BMC component: firmware={fw_path}, version={fw_version}")

            logger.info(f"Writing updated 'platform_components.json' to localhost: {local_comp_file_path}")
            with open(local_comp_file_path, 'w') as comp_file:
                json.dump(json_data, comp_file, indent=4)
                logger.info(f"Updated 'platform_components.json':\n{json.dumps(json_data, indent=4)}")

            logger.info(f"Copying 'platform_components.json' to {duthost.hostname}: {remote_comp_file_path}")
            duthost.copy(src=local_comp_file_path, dest=remote_comp_file_path)

            logger.info(f"Removing 'platform_components.json' from localhost: {local_comp_file_path}")
            os.remove(local_comp_file_path)
        else:
            raise RuntimeError(f"{remote_comp_file_path} could not be found on {duthost.hostname}")

    def test_get_name(self, platform_api_conn):        # noqa: F811
        name = bmc.get_name(platform_api_conn)
        pytest_assert(name is not None, "Unable to retrieve BMC name")
        pytest_assert(isinstance(name, str), f"BMC name type appears incorrect: {type(name)}")
        pytest_assert(name == 'BMC', f"BMC name appears incorrect: {name}")

    def test_get_presence(self, platform_api_conn):    # noqa: F811
        presence = bmc.get_presence(platform_api_conn)
        pytest_assert(presence is not None, "Unable to retrieve BMC presence")
        pytest_assert(isinstance(presence, bool), f"BMC presence appears incorrect: {type(presence)}")
        pytest_assert(presence is True, f"BMC is not present: {presence}")

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        model = bmc.get_model(duthost)
        bmc_eeprom_info = duthost.command("sudo show platform bmc eeprom")["stdout"]
        pytest_assert(model is not None, "Unable to retrieve BMC model")
        pytest_assert(model in bmc_eeprom_info, f"BMC model appears incorrect: {model}")

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        serial = bmc.get_serial(duthost)
        bmc_eeprom_info = duthost.command("sudo show platform bmc summary")["stdout"]
        pytest_assert(serial is not None, "Unable to retrieve BMC serial number")
        pytest_assert(str(serial) in bmc_eeprom_info, f"BMC serial number appears incorrect: {serial}")

    def test_get_revision(self, platform_api_conn):    # noqa: F811
        revision = bmc.get_revision(platform_api_conn)
        pytest_assert(revision is not None, "Unable to retrieve BMC revision")
        pytest_assert(revision == 'N/A', f"BMC revision appears incorrect: {revision}")

    def test_get_status(self, platform_api_conn):    # noqa: F811
        status = bmc.get_status(platform_api_conn)
        pytest_assert(status is not None, "Unable to retrieve BMC status")
        pytest_assert(isinstance(status, bool), f"BMC status appears incorrect: {type(status)}")
        pytest_assert(status is True, f"BMC status appears incorrect: {status}")

    def test_is_replaceable(self, platform_api_conn):    # noqa: F811
        replaceable = bmc.is_replaceable(platform_api_conn)
        pytest_assert(replaceable is not None, "Unable to retrieve BMC is_replaceable")
        pytest_assert(isinstance(replaceable, bool), f"BMC replaceable value must be a bool value: {type(replaceable)}")
        pytest_assert(replaceable is False, f"BMC replaceable value appears incorrect: {replaceable}")

    def test_get_eeprom(self, duthosts, enum_rand_one_per_hwsku_hostname):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        eeprom = bmc.get_eeprom(duthost)
        bmc_eeprom_info = self._string_to_dict(duthost.command("sudo show platform bmc eeprom")["stdout"])
        pytest_assert(eeprom is not None, f"Failed to retrieve system EEPROM: {eeprom}")
        pytest_assert(isinstance(eeprom, dict), f"BMC eeprom value must be a dict value: {type(eeprom)}")

        for key, value in bmc_eeprom_info.items():
            pytest_assert(key in eeprom, f"BMC eeprom {key} appears incorrect")
            pytest_assert(eeprom[key] == value, f"BMC eeprom {key} appears incorrect")

    def test_get_version(self, duthosts, enum_rand_one_per_hwsku_hostname):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        version = bmc.get_version(duthost)
        bmc_summary = duthost.command("sudo show platform bmc summary")["stdout"]
        pytest_assert(version is not None, f"Unable to retrieve BMC version: {version}")
        pytest_assert(version in bmc_summary, f"BMC version appears incorrect: {version}")

    def test_reset_root_password(self, duthosts, enum_rand_one_per_hwsku_hostname, bmc_ip):
        """
        Test BMC root password reset with platform API

        Steps:
        1. Reset the BMC root password by BMC platform api reset_root_password
        2. Validate the root password had been reset to the default password by login test using Redfish api
        3. Change the root password to a new value by using Redfish api
        4. Validate login password had been changed by login test using Redfish api
        5. Reset the BMC root password by BMC platform api reset_root_password()
        6. Validate the root password had been reset to the default password by login test using Redfish api
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        bmc.reset_root_password(duthost)
        self._validate_bmc_login(duthost, bmc_ip, self.bmc_root_password)
        temp_password = self._generate_password()
        self._change_bmc_root_password(duthost, bmc_ip, temp_password)
        self._validate_bmc_login(duthost, bmc_ip, temp_password)
        bmc.reset_root_password(duthost)
        self._validate_bmc_login(duthost, bmc_ip, self.bmc_root_password)

    def test_reset_root_password_cli(self, duthosts, enum_rand_one_per_hwsku_hostname, bmc_ip):
        """
        Test CLI command for reset BMC root password

        Steps:
        1. Run command 'config bmc reset-root-password' to ensure the BMC root password is at default state
           and validate the command returns success message
        2. Use curl command with default credentials to change the root password to a new password
           and validate the password change is successful
        3. Use curl command with new credentials to verify the new password works
           and validate the response is successful
        4. Use curl command with old default credentials and validate access is denied
           with authentication failure (HTTP 401)
        5. Run command 'config bmc reset-root-password' and validate the command returns success message
        6. Use curl command with default credentials and validate the password has been reset successfully
        7. Use curl command with the previous new password and validate access is denied
           with authentication failure (HTTP 401)
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        temp_password = self._generate_password()

        try:
            with allure.step("Step 1: Reset password to default state"):
                reset_result = duthost.command(BMC_RESET_ROOT_PASSWORD_COMMAND)
                pytest_assert(reset_result["rc"] == 0, f"Failed to reset BMC root password: {reset_result['stderr']}")
                pytest_assert("BMC root password reset successful" in reset_result["stdout"],
                            f"Unexpected output: {reset_result['stdout']}")
                logger.info("BMC root password reset to default state successfully")

            with allure.step("Step 2: Change password from default to new password"):
                password_data = json.dumps({"Password": temp_password})
                logger.info(f"default password: {self.bmc_root_password}, new password: {temp_password}")
                change_pwd_cmd = CURL_BASIC_AUTH_PATCH.format(
                    self.bmc_root_user, self.bmc_root_password, bmc_ip,
                    "/redfish/v1/AccountService/Accounts/root", password_data)
                change_result = duthost.command(change_pwd_cmd)
                pytest_assert(re.match(r"^HTTP/\S+\s+20\d", change_result["stdout"]),
                            f"Failed to change password: {change_result['stdout']}")
                logger.info("BMC root password changed to new password successfully")

            with allure.step("Step 3: Verify new password works"):
                verify_new_pwd_cmd = CURL_BASIC_AUTH_GET_WITH_HEADERS.format(
                    self.bmc_root_user, temp_password, bmc_ip, REDFISH_SESSION_SERVICE_ENDPOINT)
                verify_result = duthost.command(verify_new_pwd_cmd)
                pytest_assert(re.match(r"^HTTP/\S+\s+20\d", verify_result["stdout"]),
                            f"New password should work, got: {verify_result['stdout']}")
                logger.info("New password verified successfully")

            with allure.step("Step 4: Verify old default password is denied"):
                verify_old_pwd_cmd = CURL_BASIC_AUTH_GET_WITH_HEADERS.format(
                    self.bmc_root_user, self.bmc_root_password, bmc_ip, REDFISH_SESSION_SERVICE_ENDPOINT)
                verify_old_result = duthost.command(verify_old_pwd_cmd, module_ignore_errors=True)
                pytest_assert(re.match(r"^HTTP/\S+\s+401", verify_old_result["stdout"]),
                            f"Old default password should be denied with HTTP 401, got: {verify_old_result['stdout']}")
                logger.info("Old default password is correctly denied")

            with allure.step("Step 5: Reset password back to default"):
                reset_result = duthost.command(BMC_RESET_ROOT_PASSWORD_COMMAND)
                pytest_assert(reset_result["rc"] == 0, f"Failed to reset BMC root password: {reset_result['stderr']}")
                pytest_assert("BMC root password reset successful" in reset_result["stdout"],
                            f"Unexpected output: {reset_result['stdout']}")
                logger.info("BMC root password reset back to default successfully")

            with allure.step("Step 6: Verify default password works again"):
                verify_default_cmd = CURL_BASIC_AUTH_GET_WITH_HEADERS.format(
                    self.bmc_root_user, self.bmc_root_password, bmc_ip, REDFISH_SESSION_SERVICE_ENDPOINT)
                verify_default_result = duthost.command(verify_default_cmd)
                pytest_assert(re.match(r"^HTTP/\S+\s+20\d", verify_default_result["stdout"]),
                            f"Default password should work after reset, got: {verify_default_result['stdout']}")
                logger.info("Default password verified successfully after reset")

            with allure.step("Step 7: Verify previous new password is denied"):
                verify_temp_pwd_cmd = CURL_BASIC_AUTH_GET_WITH_HEADERS.format(
                    self.bmc_root_user, temp_password, bmc_ip, REDFISH_SESSION_SERVICE_ENDPOINT)
                verify_temp_result = duthost.command(verify_temp_pwd_cmd, module_ignore_errors=True)
                pytest_assert(re.match(r"^HTTP/\S+\s+401", verify_temp_result["stdout"]),
                            f"Previous new password should be denied with HTTP 401, got: {verify_temp_result['stdout']}")
                logger.info("Previous new password is correctly denied after reset")
        finally:
            duthost.command(BMC_RESET_ROOT_PASSWORD_COMMAND)

    def test_bmc_dump(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Test BMC dump with API

        Steps:
        1. Trigger the BMC dump by BMC api trigger_bmc_debug_log_dump()
        2. During waiting, check the dump process by BMC api get_bmc_debug_log_dump(task_id, filename, path)
        3. After BMC dump finished, validate the BMC dump file existence
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        bmc_dump_path = BMC_DUMP_PATH + '/' + BMC_DUMP_FILENAME.format(timestamp)
        ret_code, (task_id, err_msg) = bmc.trigger_bmc_debug_log_dump(duthost)
        pytest_assert(ret_code == 0, f"Failed to retrieve BMC dump: {err_msg}")
        logger.info(f"BMC dump task id: {task_id}")
        pytest_assert(self._validate_bmc_dump_finished(duthost, task_id, timestamp), "BMC dump failed")
        pytest_assert(duthost.command(
            f"ls -l {bmc_dump_path}")["rc"] == 0, f"BMC dump file not found: {bmc_dump_path}")

    def test_bmc_firmware_update(self, duthosts, enum_rand_one_per_hwsku_hostname, fw_pkg, bmc_firmware_command_type,
                                 backup_platform_file, bmc_ip, request):
        """
        Test BMC firmware update with platform API and CLI

        Steps:
        1. Check and record the original BMC firmware version
        2. Update the BMC firmware version by command
            'config platform firmware install chassis component BMC fw -y xxx' or
            'config platform firmware update chassis component BMC fw -y xxx'
            depending on completeness_level:
                if the completeness_level is basic, only test one command type randomly
                if the completeness_level is others, test both command types
                in this case,the test test_bmc_firmware_update will be executed twice times
        3. Wait after the installation done
        4. Validate the BMC firmware had been updated to the destination version by command
            'show platform firmware status'
        5. Recover the BMC firmware version to the original one by BMC platform api update_firmware(fw_image)
        6. Wait after the installation done
        7. Validate the BMC firmware had been restored to the original version by command
            'show platform firmware status'
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        bmc_version_origin = self._get_bmc_version(duthost)
        logger.info(f"BMC version origin: {bmc_version_origin}")
        logger.info(f"Testing with command type: {bmc_firmware_command_type}")

        chassis = list(show_firmware(duthost)["chassis"].keys())[0]
        logger.info(f"Chassis: {chassis}")
        fw_pkg_path_new = fw_pkg["chassis"][chassis]["component"]["BMC"][LATEST_BMC_VERSION_IDX]["firmware"]
        fw_version_new = fw_pkg["chassis"][chassis]["component"]["BMC"][LATEST_BMC_VERSION_IDX]["version"]
        fw_pkg_clean_path_new = urlparse(fw_pkg_path_new).path
        fw_pkt_name_new = os.path.basename(fw_pkg_path_new)
        if bmc_firmware_command_type == FW_TYPE_UPDATE:
            logger.info(f"Generate 'platform_components.json' for BMC firmware: {fw_version_new}")
            self._generate_platform_file(duthost, chassis, f"/tmp/{fw_pkt_name_new}", fw_version_new)

        logger.info(f"BMC firmware path: {fw_pkg_clean_path_new}")
        logger.info(f"Copy BMC firmware to localhost: /tmp/{fw_pkt_name_new}")
        duthost.copy(src=fw_pkg_clean_path_new, dest=f"/tmp/{fw_pkt_name_new}")

        logger.info(f"Execute BMC firmware {bmc_firmware_command_type} to {fw_pkt_name_new} and "
                    f"Wait for BMC firmware update to complete")
        res = self._update_bmc_firmware(duthost, f"/tmp/{fw_pkt_name_new}", bmc_ip,
                                        method='cli', cli_type=bmc_firmware_command_type)
        pytest_assert(res, f"Failed to execute BMC firmware {bmc_firmware_command_type} by CLI!")

        bmc_version_latest = self._get_bmc_version(duthost)
        logger.info(f"BMC version after {bmc_firmware_command_type}: {bmc_version_latest}")
        pytest_assert(bmc_version_latest != bmc_version_origin, f"BMC firmware {bmc_firmware_command_type} failed")

        fw_pkg_path_old = fw_pkg["chassis"][chassis]["component"]["BMC"][OLD_BMC_VERSION_IDX]["firmware"]
        fw_pkg_clean_path_old = urlparse(fw_pkg_path_old).path
        fw_pkt_name_old = os.path.basename(fw_pkg_path_old)
        logger.info(f"BMC firmware path: {fw_pkg_clean_path_old}")
        logger.info(f"Copy BMC firmware to localhost: /tmp/{fw_pkt_name_old}")
        duthost.copy(src=fw_pkg_clean_path_old, dest=f"/tmp/{fw_pkt_name_old}")

        logger.info(f"Execute BMC firmware update to {fw_pkt_name_old} and Wait for BMC firmware update to complete")
        res = self._update_bmc_firmware(duthost, f"/tmp/{fw_pkt_name_old}", bmc_ip, method='api')
        pytest_assert(res, "Failed to execute BMC firmware update by API!")

        bmc_version_current = self._get_bmc_version(duthost)
        logger.info(f"BMC version after recovery: {bmc_version_current}")
        pytest_assert(bmc_version_latest != bmc_version_current, "BMC firmware recovery failed")

    def _parse_bmc_session(self, output):
        """Parse BMC session output to extract session ID and token"""
        session_id_match = re.search(r'Session ID:\s*(\S+)', output)
        token_match = re.search(r'Token:\s*(\S+)', output)
        return (
            session_id_match.group(1) if session_id_match else None,
            token_match.group(1) if token_match else None
        )

    def _extract_ids_from_members(self, data):
        """Extract IDs from Redfish Members list (works for both sessions and subscriptions)

        Extracts the last path segment from @odata.id field in each Member.
        Example: "/redfish/v1/SessionService/Sessions/abc123" -> "abc123"
        Filters out empty or invalid IDs.
        """
        ids = set()
        for m in data.get("Members", []):
            odata_id = m.get("@odata.id")
            if odata_id:
                id_segment = odata_id.rstrip("/").split("/")[-1]
                if id_segment:
                    ids.add(id_segment)
        return ids

    def test_bmc_session_open_close(self, duthosts, enum_rand_one_per_hwsku_hostname, bmc_ip, cleanup_bmc_subscriptions):
        """
        Test CLIs commands for open and close BMC session

        Steps:
        1. Open BMC session and cleanup existing subscriptions
        2. Verify session exists via Redfish API
        3. Create event subscription and verify
        4. Close session and verify token becomes invalid
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        session_id = None
        new_session_id = None

        try:
            with allure.step("Open BMC session"):
                open_session_result = duthost.command(BMC_OPEN_SESSION_COMMAND)
                pytest_assert(open_session_result["rc"] == 0, f"Failed to open session: {open_session_result['stderr']}")
                session_id, token = self._parse_bmc_session(open_session_result["stdout"])
                logger.info(f"Session opened: {session_id}")
                pytest_assert(session_id and token, "Session ID or token not returned")

            with allure.step("Verify session exists via Redfish API"):
                get_sessions_cmd = CURL_TOKEN_AUTH_GET.format(token, bmc_ip, REDFISH_SESSION_SERVICE_ENDPOINT)
                sessions_result = duthost.command(get_sessions_cmd)
                try:
                    sessions_data = json.loads(sessions_result["stdout"])
                except json.JSONDecodeError as e:
                    pytest_assert(False, f"Failed to parse sessions response as JSON: {e}, response: {sessions_result['stdout']}")
                member_session_ids = self._extract_ids_from_members(sessions_data)
                pytest_assert(session_id in member_session_ids,
                              f"Session {session_id} not found in Members: {member_session_ids}")

            with allure.step("Create event subscription"):
                subscription_data = json.dumps({"Destination": "https://example.com/events", "Protocol": "Redfish"})
                create_subscription_cmd = CURL_TOKEN_AUTH_POST.format(
                    token, bmc_ip, REDFISH_EVENT_SUBSCRIPTIONS_ENDPOINT, subscription_data)
                subscription_result = duthost.command(create_subscription_cmd)

                # Extract subscription ID from Location header
                location_match = re.search(r'Location:\s*.+/([^/\s]+)', subscription_result["stdout"], re.IGNORECASE)
                subscription_id = location_match.group(1) if location_match else None
                pytest_assert(subscription_id, f"Failed to extract subscription ID")
                logger.info(f"Subscription created: {subscription_id}")

            with allure.step("Close session and verify token becomes invalid"):
                close_result = duthost.command(BMC_CLOSE_SESSION_COMMAND.format(session_id))
                pytest_assert(close_result["rc"] == 0, f"Failed to close session: {close_result['stderr']}")
                logger.info(f"Session {session_id} closed")
                session_id = None  # Mark as closed

                invalid_get_cmd = CURL_TOKEN_AUTH_GET_WITH_HEADERS.format(token, bmc_ip, REDFISH_SESSION_SERVICE_ENDPOINT)
                invalid_get_result = duthost.command(invalid_get_cmd, module_ignore_errors=True)
                pytest_assert(invalid_get_result["stdout"].startswith("HTTP/1.1 401 Unauthorized"),
                             f"GET with invalid token should return HTTP 401 Unauthorized, got: {invalid_get_result['stdout']}")

                invalid_post_result = duthost.command(create_subscription_cmd, module_ignore_errors=True)
                pytest_assert(invalid_post_result["stdout"].startswith("HTTP/1.1 401 Unauthorized"),
                              f"POST with invalid token should return HTTP 401 Unauthorized, got: {invalid_post_result['stdout']}")

            with allure.step("Open new session and cleanup subscription"):
                new_session_result = duthost.command(BMC_OPEN_SESSION_COMMAND)
                pytest_assert(new_session_result["rc"] == 0, f"Failed to open new session: {new_session_result['stderr']}")
                new_session_id, new_token = self._parse_bmc_session(new_session_result["stdout"])
                pytest_assert(new_session_id and new_token, "New session ID or token not returned")
                logger.info(f"New session opened: {new_session_id}")

                # Delete subscription
                delete_result = duthost.command(
                    CURL_TOKEN_AUTH_DELETE.format(new_token, bmc_ip, f"{REDFISH_EVENT_SUBSCRIPTIONS_ENDPOINT}/{subscription_id}"),
                    module_ignore_errors=True)
                pytest_assert(delete_result["stdout"].startswith("HTTP/1.1 200 OK") or 
                             delete_result["stdout"].startswith("HTTP/1.1 204 No Content"),
                              f"DELETE should return HTTP 200 OK or 204 No Content, got: {delete_result['stdout']}")

                # Verify subscription is deleted by checking the specific subscription returns 404
                verify_deleted_cmd = CURL_TOKEN_AUTH_GET_WITH_HEADERS.format(
                    new_token, bmc_ip, f"{REDFISH_EVENT_SUBSCRIPTIONS_ENDPOINT}/{subscription_id}")
                verify_deleted_result = duthost.command(verify_deleted_cmd, module_ignore_errors=True)
                pytest_assert(verify_deleted_result["stdout"].startswith("HTTP/1.1 404 Not Found"),
                              f"GET deleted subscription should return HTTP 404 Not Found, got: {verify_deleted_result['stdout']}")
                logger.info(f"Subscription {subscription_id} deleted and verified (404 status)")

        finally:
            # Cleanup: close any sessions that may still be open
            if new_session_id:
                duthost.command(BMC_CLOSE_SESSION_COMMAND.format(new_session_id), module_ignore_errors=True)
                logger.info(f"Cleanup: closed session {new_session_id}")
            if session_id:
                duthost.command(BMC_CLOSE_SESSION_COMMAND.format(session_id), module_ignore_errors=True)
                logger.info(f"Cleanup: closed session {session_id}")


class TestBMCSessionNonBMC:
    """Test BMC session commands on Non-BMC switches"""

    @pytest.fixture(autouse=True)
    def skip_if_bmc_present_or_unsupported(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """Skip these tests if BMC is present or BMC commands are not supported"""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        if bmc.is_bmc_exists(duthost):
            pytest.skip("BMC is present, skipping Non-BMC switch tests")
        # Check if 'config bmc' command is supported
        check_result = duthost.command("sudo config bmc --help", module_ignore_errors=True)
        output = check_result["stderr"]
        logger.info(f"BMC command check - stdout: {check_result['stdout']}, stderr: {check_result['stderr']}")
        if "No such command" in output:
            pytest.skip("BMC commands are not supported on this image version")

    def test_bmc_commands_on_non_bmc_switch(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Test BMC session commands on a Non-BMC switch

        Expected output: "BMC is not available on this platform"

        Steps:
        1. Run 'config bmc open-session' and verify error returned
        2. Run 'config bmc close-session' and verify error returned
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        expected_error = "BMC is not available"

        with allure.step("Test 'config bmc open-session' returns error"):
            open_result = duthost.command(BMC_OPEN_SESSION_COMMAND, module_ignore_errors=True)
            logger.info(f"open-session output: {open_result['stdout']}")
            pytest_assert(
                expected_error in open_result["stdout"],
                f"Expected '{expected_error}' in stdout, got: {open_result['stdout']}"
            )

        with allure.step("Test 'config bmc close-session' returns error"):
            invalid_session_id = "invalid-session"
            close_result = duthost.command(
                BMC_CLOSE_SESSION_COMMAND.format(invalid_session_id),
                module_ignore_errors=True
            )
            logger.info(f"close-session output: {close_result['stdout']}")
            pytest_assert(
                expected_error in close_result["stdout"],
                f"Expected '{expected_error}' in stdout, got: {close_result['stdout']}"
            )
