import json
import logging
import os
import pytest
import time
from tests.common.utilities import wait_until
from device_mocker import device_mocker_factory

pytestmark = [
    pytest.mark.topology('any')
]

HEALTH_TABLE_NAME = 'SYSTEM_HEALTH_INFO'

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, 'files')
DUT_CONFIG_FILE = '/usr/share/sonic/device/{}/system_health_monitoring_config.json'
DUT_CONFIG_BACKUP_FILE = '/usr/share/sonic/device/{}/system_health_monitoring_config.json.bak'
DEVICE_CHECK_CONFIG_FILE = 'device_check.json'
EXTERNAL_CHECK_CONFIG_FILE = 'external_check.json'
IGNORE_ASIC_CHECK_CONFIG_FILE = 'ignore_asic_check.json'
IGNORE_FAN_CHECK_CONFIG_FILE = 'ignore_fan_check.json'
IGNORE_PSU_CHECK_CONFIG_FILE = 'ignore_psu_check.json'
IGNORE_DEVICE_CHECK_CONFIG_FILE = 'ignore_device_check.json'
EXTERNAL_CHECKER_MOCK_FILE = 'mock_valid_external_checker.txt'

DEFAULT_BOOT_TIMEOUT = 300
DEFAULT_INTERVAL = 60
FAST_INTERVAL = 10
THERMAL_CHECK_INTERVAL = 70
PSU_CHECK_INTERVAL = FAST_INTERVAL + 5
STATE_DB = 6

SERVICE_EXPECT_STATUS_DICT = {
    'System': 'Running',
    'Process': 'Running',
    'Filesystem': 'Accessible'
}
SUMMARY_OK = 'OK'
SUMMARY_NOT_OK = 'Not OK'

EXPECT_FAN_MISSING = '{} is missing'
EXPECT_FAN_BROKEN = '{} is broken'
EXPECT_FAN_INVALID_SPEED = '{} speed is out of range'
EXPECT_ASIC_HOT = 'ASIC temperature is too hot'
EXPECT_PSU_MISSING = '{} is missing or not available'
EXPECT_PSU_NO_POWER = '{} is out of power'
EXPECT_PSU_HOT = '{} temperature is too hot'
EXPECT_PSU_INVALID_VOLTAGE = '{} voltage is out of range'


def test_service_checker(duthost):
    wait_system_health_boot_up(duthost)
    with ConfigFileContext(duthost, os.path.join(FILES_DIR, IGNORE_DEVICE_CHECK_CONFIG_FILE)):
        cmd = "monit summary -B"
        logging.info('Getting output for command {}'.format(cmd))
        output = duthost.shell(cmd)
        content = output['stdout'].strip()
        lines = content.splitlines()
        status_begin = lines[1].find('Status')
        type_begin = lines[1].find('Type')
        expect_error_dict = {}
        logging.info('Getting service status')
        for line in lines[2:]:
            service_name = line[0:status_begin].strip()
            status = line[status_begin:type_begin].strip()
            service_type = line[type_begin:].strip()
            assert service_type in SERVICE_EXPECT_STATUS_DICT, 'Unknown service type {}'.format(service_type)
            expect_status = SERVICE_EXPECT_STATUS_DICT[service_type]
            if expect_status != status:
                expect_error_dict[service_name] = '{} is not {}'.format(service_name, expect_status)

        logging.info('Waiting {} seconds for healthd to work'.format(DEFAULT_INTERVAL))
        time.sleep(DEFAULT_INTERVAL)
        if expect_error_dict:
            logging.info('Verify data in redis')
            for name, error in expect_error_dict.items():
                value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, name)
                assert value == error, 'Expect error {}, got {}'.format(error, value)

        summary = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, 'summary')
        expect_summary = SUMMARY_OK if not expect_error_dict else SUMMARY_NOT_OK
        assert summary == expect_summary, 'Expect summary {}, got {}'.format(expect_summary, summary)


def test_device_checker(duthost, device_mocker_factory):
    device_mocker = device_mocker_factory(duthost)
    wait_system_health_boot_up(duthost)
    with ConfigFileContext(duthost, os.path.join(FILES_DIR, DEVICE_CHECK_CONFIG_FILE)):
        time.sleep(DEFAULT_INTERVAL)
        mock_result, fan_name = device_mocker.mock_fan_speed(False)
        expect_value = EXPECT_FAN_INVALID_SPEED.format(fan_name)
        if mock_result:
            logging.info('Mocked invalid fan speed for {}, waiting {} seconds for it to take effect'.format(fan_name,
                                                                                                            THERMAL_CHECK_INTERVAL))
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, fan_name)
            assert value and expect_value in value, 'Mock fan invalid speed, expect {}, but got {}'.format(expect_value,
                                                                                                           value)
        mock_result, fan_name = device_mocker.mock_fan_speed(True)
        if mock_result:
            logging.info('Mocked valid fan speed for {}, waiting {} seconds for it to take effect'.format(fan_name,
                                                                                                          THERMAL_CHECK_INTERVAL))
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, fan_name)
            assert not value or expect_value not in value, 'Mock fan valid speed, expect {}, ' \
                                                           'but it still report invalid speed'

        mock_result, fan_name = device_mocker.mock_fan_presence(False)
        expect_value = EXPECT_FAN_MISSING.format(fan_name)
        if mock_result:
            logging.info('Mocked fan absence {}, waiting {} seconds for it to take effect'.format(fan_name,
                                                                                                  THERMAL_CHECK_INTERVAL))
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, fan_name)
            assert value and value == expect_value, 'Mock fan absence, expect {}, but got {}'.format(expect_value,
                                                                                                     value)

        mock_result, fan_name = device_mocker.mock_fan_presence(True)
        if mock_result:
            logging.info('Mocked fan presence for {}, waiting {} seconds for it to take effect'.format(fan_name,
                                                                                                       THERMAL_CHECK_INTERVAL))
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, fan_name)
            assert not value or value != expect_value, 'Mock fan presence, but it still report absence'

        mock_result, fan_name = device_mocker.mock_fan_status(False)
        expect_value = EXPECT_FAN_BROKEN.format(fan_name)
        if mock_result:
            logging.info('Mocked fan broken for {}, waiting {} seconds for it to take effect'.format(fan_name,
                                                                                                     THERMAL_CHECK_INTERVAL))
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, fan_name)
            assert value and value == expect_value, 'Mock fan broken, expect {}, but got {}'.format(expect_value,
                                                                                                    value)
        mock_result, fan_name = device_mocker.mock_fan_status(True)
        if mock_result:
            logging.info('Mocked fan good for {}, waiting {} seconds for it to take effect'.format(fan_name,
                                                                                                   THERMAL_CHECK_INTERVAL))
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, fan_name)
            assert not value or value != expect_value, 'Mock fan normal, but it still report broken'

        mock_result = device_mocker.mock_asic_temperature(False)
        expect_value = EXPECT_ASIC_HOT
        if mock_result:
            logging.info('Mocked ASIC hot, waiting {} seconds for it to take effect'.format(THERMAL_CHECK_INTERVAL))
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, 'ASIC')
            assert value and expect_value in value, 'Mock ASIC temperature hot, expect {}, but got {}'.format(
                expect_value,
                value)

        mock_result = device_mocker.mock_asic_temperature(True)
        if mock_result:
            logging.info('Mocked ASIC cold, waiting {} seconds for it to take effect'.format(THERMAL_CHECK_INTERVAL))
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, 'ASIC')
            assert not value or expect_value not in value, 'Mock ASIC temperature normal, but it is still hot'

        mock_result, psu_name = device_mocker.mock_psu_presence(False)
        expect_value = EXPECT_PSU_MISSING.format(psu_name)
        if mock_result:
            logging.info('Mocked PSU absence for {}, waiting {} seconds for it to take effect'.format(psu_name,
                                                                                                      THERMAL_CHECK_INTERVAL))
            time.sleep(PSU_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, psu_name)
            assert value and expect_value == value, 'Mock PSU absence, expect {}, but got {}'.format(expect_value,
                                                                                                     value)

        mock_result, psu_name = device_mocker.mock_psu_presence(True)
        if mock_result:
            logging.info('Mocked PSU presence for {}, waiting {} seconds for it to take effect'.format(psu_name,
                                                                                                       THERMAL_CHECK_INTERVAL))
            time.sleep(PSU_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, psu_name)
            assert not value or expect_value != value, 'Mock PSU presence, but it is still absence'

        mock_result, psu_name = device_mocker.mock_psu_status(False)
        expect_value = EXPECT_PSU_NO_POWER.format(psu_name)
        if mock_result:
            logging.info('Mocked PSU no power for {}, waiting {} seconds for it to take effect'.format(psu_name,
                                                                                                       THERMAL_CHECK_INTERVAL))
            time.sleep(PSU_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, psu_name)
            assert value and expect_value == value, 'Mock PSU no power, expect {}, but got {}'.format(expect_value,
                                                                                                      value)

        mock_result, psu_name = device_mocker.mock_psu_status(True)
        if mock_result:
            logging.info('Mocked PSU good power for {}, waiting {} seconds for it to take effect'.format(psu_name,
                                                                                                         THERMAL_CHECK_INTERVAL))
            time.sleep(PSU_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, psu_name)
            assert not value or expect_value != value, 'Mock PSU power good, but it is still out of power'

        mock_result, psu_name = device_mocker.mock_psu_temperature(False)
        expect_value = EXPECT_PSU_HOT.format(psu_name)
        if mock_result:
            logging.info('Mocked PSU hot for {}, waiting {} seconds for it to take effect'.format(psu_name,
                                                                                                  THERMAL_CHECK_INTERVAL))
            time.sleep(PSU_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, psu_name)
            assert value and expect_value in value, 'Mock PSU hot, expect {}, but got {}'.format(expect_value,
                                                                                                 value)

        mock_result, psu_name = device_mocker.mock_psu_temperature(True)
        if mock_result:
            logging.info('Mocked PSU cold for {}, waiting {} seconds for it to take effect'.format(psu_name,
                                                                                                   THERMAL_CHECK_INTERVAL))
            time.sleep(PSU_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, psu_name)
            assert not value or expect_value not in value, 'Mock PSU cold, but it is still hot'

        mock_result, psu_name = device_mocker.mock_psu_voltage(False)
        expect_value = EXPECT_PSU_INVALID_VOLTAGE.format(psu_name)
        if mock_result:
            logging.info('Mocked PSU bad voltage for {}, waiting {} seconds for it to take effect'.format(psu_name,
                                                                                                          THERMAL_CHECK_INTERVAL))
            time.sleep(PSU_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, psu_name)
            assert value and expect_value in value, 'Mock PSU invalid voltage, expect {}, but got {}'.format(
                expect_value,
                value)

        mock_result, psu_name = device_mocker.mock_psu_voltage(True)
        if mock_result:
            logging.info('Mocked PSU good voltage for {}, waiting {} seconds for it to take effect'.format(psu_name,
                                                                                                           THERMAL_CHECK_INTERVAL))
            time.sleep(FAST_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, psu_name)
            assert not value or expect_value not in value, 'Mock PSU good voltage, but it is still invalid'


def test_external_checker(duthost):
    wait_system_health_boot_up(duthost)
    with ConfigFileContext(duthost, os.path.join(FILES_DIR, EXTERNAL_CHECK_CONFIG_FILE)):
        duthost.copy(src=os.path.join(FILES_DIR, EXTERNAL_CHECKER_MOCK_FILE),
                     dest=os.path.join('/tmp', EXTERNAL_CHECKER_MOCK_FILE))
        time.sleep(DEFAULT_INTERVAL)
        value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, 'ExternalService')
        assert value == 'Service is not working', 'External checker does not work, value={}'.format(value)
        value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, 'ExternalDevice')
        assert value == 'Device is broken', 'External checker does not work, value={}'.format(value)


def test_system_health_config(duthost, device_mocker_factory):
    device_mocker = device_mocker_factory(duthost)
    wait_system_health_boot_up(duthost)
    logging.info('Ignore fan check, verify there is no error information about fan')
    with ConfigFileContext(duthost, os.path.join(FILES_DIR, IGNORE_FAN_CHECK_CONFIG_FILE)):
        time.sleep(DEFAULT_INTERVAL)
        mock_result, fan_name = device_mocker.mock_fan_presence(False)
        expect_value = EXPECT_FAN_MISSING.format(fan_name)
        if mock_result:
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, fan_name)
            assert not value or expect_value != value, 'Fan check is still performed after it ' \
                                                       'is configured to be ignored'

    logging.info('Ignore ASIC check, verify there is no error information about ASIC')
    with ConfigFileContext(duthost, os.path.join(FILES_DIR, IGNORE_ASIC_CHECK_CONFIG_FILE)):
        time.sleep(FAST_INTERVAL)
        mock_result = device_mocker.mock_asic_temperature(False)
        expect_value = EXPECT_ASIC_HOT
        if mock_result:
            time.sleep(THERMAL_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, 'ASIC')
            assert not value or expect_value not in value, 'ASIC check is still performed after it ' \
                                                           'is configured to be ignored'

    logging.info('Ignore PSU check, verify there is no error information about psu')
    with ConfigFileContext(duthost, os.path.join(FILES_DIR, IGNORE_PSU_CHECK_CONFIG_FILE)):
        time.sleep(FAST_INTERVAL)
        mock_result, psu_name = device_mocker.mock_psu_presence(False)
        expect_value = EXPECT_PSU_MISSING.format(psu_name)
        if mock_result:
            time.sleep(PSU_CHECK_INTERVAL)
            value = redis_get_field_value(duthost, STATE_DB, HEALTH_TABLE_NAME, psu_name)
            assert not value or expect_value != value, 'PSU check is still performed after it ' \
                                                       'is configured to be ignored'


def wait_system_health_boot_up(duthost):
    boot_timeout = get_system_health_config(duthost, 'boot_timeout', DEFAULT_BOOT_TIMEOUT)
    assert wait_until(boot_timeout, 10, redis_table_exists, duthost, STATE_DB, HEALTH_TABLE_NAME), \
        'System health service is not working'


def get_system_health_config(duthost, key, default):
    try:
        platform_str = duthost.facts['platform']
        config_file = DUT_CONFIG_FILE.format(platform_str)
        cmd = 'cat {}'.format(config_file)
        output = duthost.shell(cmd)
        content = output['stdout'].strip()
        json_obj = json.loads(content)
        return json_obj[key]
    except:
        return default


def redis_table_exists(duthost, db_id, key):
    cmd = 'redis-cli --raw -n {} EXISTS \"{}\"'.format(db_id, key)
    logging.info('Checking if table exists in redis with cmd: {}'.format(cmd))
    output = duthost.shell(cmd)
    content = output['stdout'].strip()
    return content != '0'


def redis_get_field_value(duthost, db_id, key, field_name):
    cmd = 'redis-cli --raw -n {} HGET \"{}\" \"{}\"'.format(db_id, key, field_name)
    logging.info('Getting field value from redis with cmd: {}'.format(cmd))
    output = duthost.shell(cmd)
    content = output['stdout'].strip()
    return content


class ConfigFileContext:
    """
    Context class to help replace system health policy file and restore it automatically.
    """

    def __init__(self, dut, src):
        """
        Constructor of ConfigFileContext.
        :param dut: DUT object representing a SONiC switch under test.
        :param src: Local config file path.
        """
        self.dut = dut
        self.src = src
        platform_str = dut.facts['platform']
        self.origin_config = DUT_CONFIG_FILE.format(platform_str)
        self.backup_config = DUT_CONFIG_BACKUP_FILE.format(platform_str)

    def __enter__(self):
        """
        Back up original system health config file and replace it with the given one.
        :return:
        """
        self.dut.command('mv -f {} {}'.format(self.origin_config, self.backup_config))
        self.dut.copy(src=os.path.join(FILES_DIR, self.src), dest=self.origin_config)

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Restore original system health config file.
        :param exc_type: Not used.
        :param exc_val: Not used.
        :param exc_tb: Not used.
        :return:
        """
        self.dut.command('mv -f {} {}'.format(self.backup_config, self.origin_config))
