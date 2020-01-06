import os
import random
import logging
from thermal_control_test_helper import *
from common.mellanox_data import SWITCH_MODELS, FAN_NAMING_RULE, THERMAL_NAMING_RULE

NOT_AVAILABLE = 'N/A'


class SysfsNotExistError(Exception):
    pass


class MockerHelper:
    THERMAL_PATH = '/var/run/hw-management/thermal/'
    LED_PATH = '/var/run/hw-management/led/'
    FAN_NUM = 0
    FAN_NUM_IN_DRAWER = 0
    INIT_FAN_NUM = False

    def __init__(self, dut):
        self.dut = dut
        self.unlink_file_list = {}
        self._extract_num_of_fans_and_fan_drawers()

    def _extract_num_of_fans_and_fan_drawers(self):
        if MockerHelper.INIT_FAN_NUM:
            return

        MockerHelper.INIT_FAN_NUM = True
        get_drawer_num_cmd = 'ls {}fan*_status | wc -l'.format(MockerHelper.THERMAL_PATH)
        output = self.dut.shell(get_drawer_num_cmd)
        content = output['stdout'].strip()
        if not content:
            return
        fan_drawer_num = int(content)

        get_fan_num_cmd = 'ls {}fan*_speed_get | wc -l'.format(MockerHelper.THERMAL_PATH)
        output = self.dut.shell(get_fan_num_cmd)
        content = output['stdout'].strip()
        if not content:
            return
        MockerHelper.FAN_NUM = int(content)
        if MockerHelper.FAN_NUM < fan_drawer_num:
            MockerHelper.FAN_NUM_IN_DRAWER = 2
        else:
            MockerHelper.FAN_NUM_IN_DRAWER = 1

    def mock_thermal_value(self, file_path, value):
        file_path = os.path.join(MockerHelper.THERMAL_PATH, file_path)
        return self.mock_value(file_path, value)

    def mock_led_value(self, file_path, value):
        file_path = os.path.join(MockerHelper.LED_PATH, file_path)
        return self.mock_value(file_path, value)

    def mock_value(self, file_path, value):
        if not self._file_exist(file_path):
            raise SysfsNotExistError('{} not exist'.format(file_path))
        self._unlink(file_path)
        self.dut.shell('echo \'{}\' > {}'.format(value, file_path))

    def read_thermal_value(self, file_path):
        file_path = os.path.join(MockerHelper.THERMAL_PATH, file_path)
        return self.read_value(file_path)

    def read_led_value(self, file_path):
        file_path = os.path.join(MockerHelper.LED_PATH, file_path)
        return self.read_value(file_path)

    def read_value(self, file_path):
        if not self._file_exist(file_path):
            raise SysfsNotExistError('{} not exist'.format(file_path))
        try:
            output = self.dut.command("cat %s" % file_path)
            value = output["stdout"]
            return value.strip()
        except Exception as e:
            assert 0, "Get content from %s failed, exception: %s" % (file_path, repr(e))

    def _unlink(self, file_path):
        if file_path not in self.unlink_file_list:
            readlink_output = self.dut.command('readlink {}'.format(file_path))
            self.unlink_file_list[file_path] = readlink_output["stdout"]
            self.dut.command('unlink {}'.format(file_path))
            self.dut.command('touch {}'.format(file_path))
            self.dut.command('chown admin {}'.format(file_path))

    def _file_exist(self, file_path):
        file_dir = os.path.dirname(file_path)
        file_name = os.path.basename(file_path)
        cmd = 'find {} -name {}'.format(file_dir, file_name)
        output = self.dut.command(cmd)
        return output['stdout'] and output['stdout'].strip() == file_path

    def deinit(self):
        for file_path, link_target in self.unlink_file_list.items():
            self.dut.command('rm -f {}'.format(file_path))
            self.dut.command('ln -s {} {}'.format(link_target, file_path))


class FanDrawerData:
    def __init__(self, mock_helper, naming_rule, index):
        self.index = index
        self.helper = mock_helper
        self.mocked_presence = None
        if 'presence' in naming_rule:
            self.presence_file = naming_rule['presence'].format(index)
        else:
            self.presence_file = None

        if 'led_capability' in naming_rule:
            self.led_capability_file = naming_rule['led_capability'].format(index)
        else:
            self.led_capability_file = None

        if 'led_green' in naming_rule:
            self.led_green_file = naming_rule['led_green'].format(index)
        else:
            self.led_green_file = None

        if 'led_red' in naming_rule:
            self.led_red_file = naming_rule['led_red'].format(index)
        else:
            self.led_red_file = None

        if 'led_orange' in naming_rule:
            self.led_orange_file = naming_rule['led_orange'].format(index)
        else:
            self.led_orange_file = None

    def mock_presence(self, presence):
        if self.presence_file:
            self.helper.mock_thermal_value(self.presence_file, str(presence))
            self.mocked_presence = 'Present' if presence == 1 else 'Not Present'
        else:
            self.mocked_presence = 'Present'

    def get_status_led(self):
        led_capability = self.helper.read_led_value(self.led_capability_file)
        led_capability = led_capability.split()
        real_red_file = self.led_red_file if 'red' in led_capability else self.led_orange_file
        green_led_value = self.helper.read_led_value(self.led_green_file)
        red_led_value = self.helper.read_led_value(real_red_file)
        if green_led_value == '255' and red_led_value == '0':
            return 'green'
        elif green_led_value == '0' and red_led_value == '255':
            return 'red'
        else:
            assert 0, 'Invalid FAN led color for FAN: {}, green={}, red={}'.format(self.name, green_led_value, red_led_value)


class FanData:
    PWM_MAX = 255
    FAN_DIR_PATH = '/run/hw-management/system/fan_dir'

    def __init__(self, mock_helper, naming_rule, index):
        self.index = index
        self.helper = mock_helper
        self.name = naming_rule['name'].format(index)
        self.speed_file = naming_rule['speed'].format(index)
        self.mocked_speed = None
        self.mocked_target_speed = None
        self.mocked_status = None
        self.mocked_direction = None

        if 'target_speed' in naming_rule:
            self.target_speed_file = naming_rule['target_speed'].format(index)
        else:
            self.target_speed_file = None

        if 'max_speed' in naming_rule:
            self.max_speed_file = naming_rule['max_speed'].format(index)
        else:
            self.max_speed_file = None

        if 'status' in naming_rule:
            self.status_file = naming_rule['status'].format(index)
        else:
            self.status_file = None
        
    def mock_speed(self, speed):
        max_speed = self.get_max_speed()
        if max_speed > 0:
            speed_in_rpm = max_speed * speed / 100
            self.helper.mock_thermal_value(self.speed_file, str(speed_in_rpm))
        else:
            self.helper.mock_thermal_value(self.speed_file, str(speed))
        self.mocked_speed = speed

    def mock_target_speed(self, target_speed):
        if self.target_speed_file:
            pwm = int(round(FanData.PWM_MAX * target_speed / 100.0))
            self.helper.mock_thermal_value(self.target_speed_file, str(pwm))
            self.mocked_target_speed = str(target_speed)
        else:
            self.mocked_target_speed = self.helper.read_thermal_value(self.speed_file)

    def mock_status(self, status):
        if self.status_file:
            self.helper.mock_thermal_value(self.status_file, str(status))
            self.mocked_status = 'OK' if status == 1 else 'Not OK'
        else:
            self.mocked_status = 'OK'

    def mock_fan_direction(self, direction):
        try:
            fan_dir_bits = int(self.helper.read_value(FanData.FAN_DIR_PATH))
        except SysfsNotExistError as e:
            self.mocked_direction = NOT_AVAILABLE
            return
        
        if direction:
            fan_dir_bits = fan_dir_bits | (1 << (self.index - 1))
            self.mocked_direction = 'intake'
        else:
            fan_dir_bits = fan_dir_bits & ~(1 << (self.index - 1))
            self.mocked_direction = 'exhaust'
        
        self.helper.mock_value(FanData.FAN_DIR_PATH, fan_dir_bits)

    def get_max_speed(self):
        if self.max_speed_file:
            max_speed = self.helper.read_thermal_value(self.max_speed_file)
            return int(max_speed)
        else:
            return -1

    def get_target_speed(self):
        pwm = self.helper.read_thermal_value(self.target_speed_file)
        pwm = int(pwm)
        target_speed = int(round(pwm * 100.0 / FanData.PWM_MAX))
        return target_speed


class TemperatureData:
    DEFAULT_HIGH_THRESHOLD = 80

    def __init__(self, mock_helper, naming_rules, index):
        self.helper = mock_helper
        self.name = naming_rules['name']
        self.temperature_file = naming_rules['temperature']
        self.high_threshold_file = naming_rules['high_threshold'] if 'high_threshold' in naming_rules else None
        self.high_critical_threshold_file = naming_rules['high_critical_threshold'] if 'high_critical_threshold' in naming_rules else None
        if index is not None:
            self.name = self.name.format(index)
            self.temperature_file = self.temperature_file.format(index)
            if self.high_threshold_file:
                self.high_threshold_file = self.high_threshold_file.format(index)
            if self.high_critical_threshold_file:
                self.high_critical_threshold_file = self.high_critical_threshold_file.format(index)
        self.mocked_temperature = None
        self.mocked_high_threshold = None
        self.mocked_high_critical_threshold = None

    def mock_temperature(self, temperature):
        self.helper.mock_thermal_value(self.temperature_file, str(temperature))
        self.mocked_temperature = temperature

    def get_high_threshold(self):
        if self.high_threshold_file:
            high_threshold = self.helper.read_thermal_value(self.high_threshold_file)
            return int(high_threshold) / 1000
        else:
            return TemperatureData.DEFAULT_HIGH_THRESHOLD

    def mock_high_threshold(self, high_threshold):
        if self.high_threshold_file:
            self.helper.mock_thermal_value(self.high_threshold_file, str(high_threshold))
            self.mocked_high_threshold = high_threshold
        else:
            self.mocked_high_threshold = NOT_AVAILABLE

    def mock_high_critical_threshold(self, high_critical_threshold):
        if self.high_critical_threshold_file:
            self.helper.mock_thermal_value(self.high_critical_threshold_file, str(high_critical_threshold))
            self.mocked_high_critical_threshold = high_critical_threshold
        else:
            self.mocked_high_critical_threshold = NOT_AVAILABLE


@mocker('FanStatusMocker')
class RandomFanStatusMocker(FanStatusMocker):
    PSU_FAN_MAX_SPEED = 10000 # only for generate random data

    def __init__(self, dut):
        super().__init__()
        self.mock_helper = MockerHelper(dut)
        self.expected_data = {}

    def deinit(self):
        self.mock_helper.deinit()

    def mock_data(self):
        fan_index = 1
        drawer_index = 1
        drawer_data = None
        naming_rule = FAN_NAMING_RULE['fan']
        while fan_index <= MockerHelper.FAN_NUM:
            try:
                if fan_index == drawer_index * MockerHelper.FAN_NUM_IN_DRAWER - 1:
                    drawer_data = FanDrawerData(self.mock_helper, naming_rule, drawer_index)
                    drawer_index += 1
                    drawer_data.mock_presence(random.randint(0, 1))
                    
                fan_data = FanData(self.helper, naming_rule, fan_index)
                fan_index += 1
                fan_data.mock_status(random.randint(0, 1))
                fan_data.mock_speed(random.randint(0, 100))
                fan_data.mock_fan_direction(random.randint(0, 1))
                self.expected_data[fan_data.name] = [
                    fan_data.name,
                    '{}%'.format(fan_data.mocked_speed),
                    fan_data.mocked_direction,
                    drawer_data.mocked_presence,
                    fan_data.mocked_status
                ]
            except SysfsNotExistError as e:
                logging.info('Failed to mock fan data for {}'.format(fan_data.name))
                continue

        dut_hwsku = self.helper.dut.facts["hwsku"]
        psu_count = SWITCH_MODELS[dut_hwsku]["psus"]["number"]
        naming_rule = FAN_NAMING_RULE['psu_fan']
        for index in range(1, psu_count + 1):
            try:
                fan_data = FanData(self.helper, naming_rule, index)
                speed = random.randint(0, RandomFanStatusMocker.PSU_FAN_MAX_SPEED)
                mock_data.mock_speed(speed)

                self.expected_data[fan_data.name, ] = [
                    fan_data.name,
                    '{}RPM'.format(fan_data.mocked_speed),
                    NOT_AVAILABLE,
                    'Present',
                    'OK'
                ]
            except SysfsNotExistError as e:
                logging.info('Failed to mock fan data for {} - {}'.format(mock_data.name, e))
                continue

    def check_result(self, actual_data):
        for name, fields in self.expected_data.items():
            if name in actual_data:
                actual_fields = actual_data[name]
                for i, expected_field in enumerate(fields):
                    if expected_field != actual_fields[i]:
                        logging.info('Check fan status for {} failed, ' \
                                     'expected: {}, actual: {}'.format(name, expected_field, actual_fields[i]))
                        return False
            else:
                return False
        return True

    def check_all_fan_speed(self, expected_speed):
        for fan_data in self.expected_data.values():
            if fan_data.target_speed_file:
                target_speed = fan_data.get_target_speed()
                if expected_speed != target_speed:
                    logging.error('{} expected speed={}, actual speed={}'.format(fan_data.name, expected_speed, target_speed))
                    return False
        return True


class RandomThermalStatusMocker(ThermalStatusMocker):
    THERMAL_ALGO_STATUS_FILE_PATH = '/run/hw-management/config/suspend'
    DEFAULT_THRESHOLD_DIFF = 5

    def __init__(self, dut):
        super().__init__()
        self.mock_helper = MockerHelper(dut)
        self.expected_data = {}

    def deinit(self):
        self.mock_helper.deinit()

    def mock_data(self):
        dut_hwsku = self.helper.dut.facts["hwsku"]
        thermal_dict = SWITCH_MODELS[dut_hwsku]["thermals"]
        for category, content in thermal_dict.items():
            number = int(content['number'])
            naming_rule = THERMAL_NAMING_RULE[category]
            if 'start' in content:
                start = int(content['start'])
                for index in range(start, start + number):
                    mock_data = TemperatureData(self.helper, naming_rule, index)
                    self._do_mock(mock_data)
            else: # non index-able thermal
                mock_data = TemperatureData(self.helper, naming_rule, None)
                self._do_mock(mock_data)

    def _do_mock(self, mock_data):
        DEFAULT_THRESHOLD_DIFF = 5
        try:
            high_threshold = mock_data.get_high_threshold()
            if high_threshold != 0:
                temperature = random.randint(0, high_threshold - RandomThermalStatusMocker.DEFAULT_THRESHOLD_DIFF)
                mock_data.mock_temperature(temperature)

                high_threshold = temperature + RandomThermalStatusMocker.DEFAULT_THRESHOLD_DIFF
                mock_data.mock_high_threshold(high_threshold)

                high_critical_threshold = high_threshold + RandomThermalStatusMocker.DEFAULT_THRESHOLD_DIFF
                mock_data.mock_high_critical_threshold(high_critical_threshold)
            else:
                mock_data.mocked_temperature = NOT_AVAILABLE
                mock_data.mocked_high_threshold = NOT_AVAILABLE
                mock_data.mocked_high_critical_threshold = NOT_AVAILABLE

            self.expected_data[mock_data.name] = [
                mock_data.name,
                mock_data.mocked_temperature,
                mock_data.mocked_high_threshold,
                NOT_AVAILABLE,
                mock_data.mocked_high_critical_threshold,
                NOT_AVAILABLE,
                False
            ]
        except SysfsNotExistError as e:
            logging.info('Failed to mock thermal data for {} - {}'.format(mock_data.name, e))

    def check_result(self, actual_data):
        for name, fields in self.expected_data.items():
            if name in actual_data:
                actual_fields = actual_data[name]
                for i, expected_field in enumerate(fields):
                    if expected_field != actual_fields[i]:
                        logging.info('Check thermal status for {} failed, ' \
                                     'expected: {}, actual: {}'.format(name, expected_field, actual_fields[i]))
                        return False
            else:
                return False
        return True

    def check_thermal_algorithm_status(self, expected_status):
        expected_value = '0' if expected_status else '1'
        return expected_value == self.helper.read_value(RandomThermalStatusMocker.THERMAL_ALGO_STATUS_FILE_PATH)


@mocker('SingleFanMocker')
class AbnormalFanMocker(SingleFanMocker):
    SPEED_TOLERANCE = 20
    SPEED_VALUE = 50

    def __init__(self, dut):
        super().__init__()
        self.mock_helper = MockerHelper(dut)
        naming_rule = FAN_NAMING_RULE['fan']
        self.fan_data = FanData(self.helper, naming_rule, 1)
        self.expect_led_color = None
        self.mock_normal()

    def deinit(self):
        self.mock_helper.deinit()

    def check_result(self, actual_data):
        for name, fields in actual_data.items():
            if name == self.fan_data.name:
                actual_color = self.fan_data.get_status_led()
                assert actual_color == self.expect_led_color, 'FAN {} color is {}, expect: {}'.format(name, actual_color, self.expect_led_color)
                return
        
        assert 0, 'Expected data not found'

    def mock_normal(self):
        self.mock_presence()
        self.mock_normal_speed()
        self.expect_led_color = 'green'

    def mock_absence(self):
        self.fan_data.mock_presence(0)
        self.expect_led_color = 'red'

    def mock_presence(self):
        self.fan_data.mock_presence(1)
        self.expect_led_color = 'green'

    def mock_over_speed(self):
        self.fan_data.mock_speed(AbnormalFanMocker.SPEED_VALUE)
        self.fan_data.mock_target_speed(AbnormalFanMocker.SPEED_VALUE + AbnormalFanMocker.SPEED_TOLERANCE + 5)
        self.expect_led_color = 'red'

    def mock_under_speed(self):
        self.fan_data.mock_speed(AbnormalFanMocker.SPEED_VALUE)
        self.fan_data.mock_target_speed(AbnormalFanMocker.SPEED_VALUE - AbnormalFanMocker.SPEED_TOLERANCE - 5)
        self.expect_led_color = 'red'

    def mock_normal_speed(self):
        self.fan_data.mock_speed(AbnormalFanMocker.SPEED_VALUE)
        self.fan_data.mock_target_speed(AbnormalFanMocker.SPEED_VALUE)
        self.expect_led_color = 'green'