import os
import logging
import json
import pytest
import random
import secrets
import time
from urllib.parse import urlparse
from datetime import datetime

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import bmc
from tests.common.platform.device_utils import platform_api_conn, start_platform_api_service    # noqa: F401
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


@pytest.fixture(scope="module", autouse=True)
def is_bmc_present(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not bmc.is_bmc_exists(duthost):
        pytest.skip("BMC is not present, skipping BMC platform API tests")


@pytest.fixture(scope="module")
def bmc_ip(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    platform = duthost.shell("sudo show platform summary | grep Platform | awk '{print $2}'")["stdout"]
    bmc_config_file = f"/usr/share/sonic/device/{platform}/bmc.json"
    duthost.fetch(src=bmc_config_file, dest='/tmp')
    with open(f'/tmp/{duthost.hostname}/{bmc_config_file}', "r") as f:
        bmc_config = json.load(f)
    yield bmc_config["bmc_addr"]


class TestBMCApi(PlatformApiTestBase):
    """Platform and Host API test cases for the BMC class"""

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
                ret_code, message = bmc.update_firmware(duthost, fw_image)

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
