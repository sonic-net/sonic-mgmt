import os
import random
import logging
from thermal_control_test_helper import *
from common.mellanox_data import SWITCH_MODELS

NOT_AVAILABLE = 'N/A'

THERMAL_NAMING_RULE = {
    "cpu_core": {
        "name": "CPU Core {} Temp",
        "temperature": "cpu_core{}",
        "high_threshold": "cpu_core{}_max",
        "high_critical_threshold": "cpu_core{}_crit"
    },
    "module": {
        "name": "xSFP module {} Temp",
        "temperature": "module{}_temp_input",
        "high_threshold": "module{}_temp_crit",
        "high_critical_threshold": "module{}_temp_emergency"
    },
    "psu": {
        "name": "PSU-{} Temp",
        "temperature": "psu{}_temp",
        "high_threshold": "psu{}_temp_max"
    },
    "cpu_pack": {
        "name": "CPU Pack Temp",
        "temperature": "cpu_pack",
        "high_threshold": "cpu_pack_max",
        "high_critical_threshold": "cpu_pack_crit"
    },
    "gearbox": {
        "name": "Gearbox {} Temp",
        "temperature": "gearbox{}_temp_input"
    },
    "asic_ambient": {
        "name": "Ambient ASIC Temp",
        "temperature": "asic"
    },
    "port_ambient": {
        "name": "Ambient Port Side Temp",
        "temperature": "port_amb"
    },
    "fan_ambient": {
        "name": "Ambient Fan Side Temp",
        "temperature": "fan_amb"
    },
    "comex_ambient": {
        "name": "Ambient COMEX Temp",
        "temperature": "comex_amb"
    }
}

FAN_NAMING_RULE = {
    "fan": {
        "name": "fan{}",
        "speed": "fan{}_speed_get",
        "presence": "fan{}_status",
        "target_speed": "fan{}_speed_set",
        "max_speed": "fan{}_max",
        "status": "fan{}_fault",
        "led_capability": "led_fan{}_capability",
        "led_green": "led_fan{}_green",
        "led_red": "led_fan{}_red",
        "led_orange": "led_fan{}_orange"
    },
    "psu_fan": {
        "name": "psu_{}_fan_1",
        "speed": "psu{}_fan1_speed_get",
        "power_status": "psu{}_pwr_status"
    }
}

class SysfsNotExistError(Exception):
    """
    Exception when sys fs not exist.
    """
    pass


class MockerHelper:
    """
    Mellanox specified mocker helper.
    """

    # Thermal related sys fs folder path.
    THERMAL_PATH = '/var/run/hw-management/thermal/'

    # LED related sys fs folder path.
    LED_PATH = '/var/run/hw-management/led/'

    # FAN number of DUT.
    FAN_NUM = 0

    # FAN number for each FAN drawer of DUT.
    FAN_NUM_PER_DRAWER = 0

    # Flag indicate if FAN number has been initialize.
    INIT_FAN_NUM = False

    unlink_file_list = {}

    def __init__(self, dut):
        """
        Constructor of mocker helper.
        :param dut: DUT object representing a SONiC switch under test.
        """
        self.dut = dut
        #self.unlink_file_list = {}
        self._extract_num_of_fans_and_fan_drawers()

    def _extract_num_of_fans_and_fan_drawers(self):
        """
        Get FAN number and Fan number for each FAN drawer of this DUT.
        :return:
        """
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
        if MockerHelper.FAN_NUM > fan_drawer_num:
            MockerHelper.FAN_NUM_PER_DRAWER = 2
        else:
            MockerHelper.FAN_NUM_PER_DRAWER = 1

    def mock_thermal_value(self, file_path, value):
        """
        Mock thermal related value whose sys fs folder is at '/var/run/hw-management/thermal/'
        :param file_path: Sys fs file name.
        :param value: Value to write to sys fs file.
        :return:
        """
        file_path = os.path.join(MockerHelper.THERMAL_PATH, file_path)
        self.mock_value(file_path, value)

    def mock_led_value(self, file_path, value):
        """
        Mock led related value whose sys fs folder is at '/var/run/hw-management/led/'
        :param file_path: Sys fs file name.
        :param value: Value to write to sys fs file.
        :return:
        """
        file_path = os.path.join(MockerHelper.LED_PATH, file_path)
        self.mock_value(file_path, value)

    def mock_value(self, file_path, value):
        """
        Unlink existing sys fs file and replace it with a new one. Write given value to the new file.
        :param file_path: Sys fs file path.
        :param value: Value to write to sys fs file.
        :return:
        """
        if not self._file_exist(file_path):
            raise SysfsNotExistError('{} not exist'.format(file_path))
        self._unlink(file_path)
        self.dut.shell('echo \'{}\' > {}'.format(value, file_path))

    def read_thermal_value(self, file_path):
        """
        Read thermal related sys fs file content.
        :param file_path: Sys fs file name.
        :return: Content of sys fs file.
        """
        file_path = os.path.join(MockerHelper.THERMAL_PATH, file_path)
        return self.read_value(file_path)

    def read_led_value(self, file_path):
        """
        Read led related sys fs file content.
        :param file_path: Sys fs file name.
        :return: Content of sys fs file.
        """
        file_path = os.path.join(MockerHelper.LED_PATH, file_path)
        return self.read_value(file_path)

    def read_value(self, file_path):
        """
        Read sys fs file content.
        :param file_path: Sys fs file path.
        :return: Content of sys fs file.
        """
        if not self._file_exist(file_path):
            raise SysfsNotExistError('{} not exist'.format(file_path))
        try:
            output = self.dut.command("cat %s" % file_path)
            value = output["stdout"]
            return value.strip()
        except Exception as e:
            assert 0, "Get content from %s failed, exception: %s" % (file_path, repr(e))

    def _unlink(self, file_path):
        """
        Unlink given sys fs file, record its soft link target.
        :param file_path: Sys fs file path.
        :return:
        """
        if file_path not in self.unlink_file_list:
            readlink_output = self.dut.command('readlink {}'.format(file_path))
            self.unlink_file_list[file_path] = readlink_output["stdout"]
            self.dut.command('unlink {}'.format(file_path))
            self.dut.command('touch {}'.format(file_path))
            self.dut.command('chown admin {}'.format(file_path))

    def _file_exist(self, file_path):
        """
        Check if the file path exists on DUT or not.
        :param file_path: Sys fs file path.
        :return: True if sys fs exists.
        """
        file_dir = os.path.dirname(file_path)
        file_name = os.path.basename(file_path)
        cmd = 'find {} -name {}'.format(file_dir, file_name)
        output = self.dut.command(cmd)
        return output['stdout'] and output['stdout'].strip() == file_path

    def deinit(self):
        """
        Destructor of MockerHelper. Re-link all sys fs files.
        :return:
        """
        for file_path, link_target in self.unlink_file_list.items():
            self.dut.command('rm -f {}'.format(file_path))
            self.dut.command('ln -s {} {}'.format(link_target, file_path))
        self.unlink_file_list.clear()


class FanDrawerData:
    """
    Data mocker of a FAN drawer.
    """

    # FAN direction sys fs path.
    FAN_DIR_PATH = '/run/hw-management/system/fan_dir'

    def __init__(self, mock_helper, naming_rule, index):
        """
        Constructor of FAN drawer data.
        :param mock_helper: Instance of MockHelper.
        :param naming_rule: Naming rule of this kind of Fan drawer.
        :param index: Fan drawer index.
        """
        self.index = index
        self.helper = mock_helper
        dut_hwsku = self.helper.dut.facts["hwsku"]
        if SWITCH_MODELS[dut_hwsku]['fans']['hot_swappable']:
            self.name = 'drawer{}'.format(index)
        else:
            self.name = 'N/A'
        self.fan_data_list = []
        self.mocked_presence = None
        self.mocked_direction = None
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
        """
        Mock presence status of this FAN drawer.
        :param presence: Given presence value. 1 means present, 0 means not present.
        :return:
        """
        dut_hwsku = self.helper.dut.facts["hwsku"]
        always_present = not SWITCH_MODELS[dut_hwsku]['fans']['hot_swappable']
        if always_present:
            self.mocked_presence = 'Present'
        elif self.presence_file:
            self.helper.mock_thermal_value(self.presence_file, str(presence))
            self.mocked_presence = 'Present' if presence == 1 else 'Not Present'
        else:
            self.mocked_presence = 'Present'

    def mock_fan_direction(self, direction):
        """
        Mock direction of this FAN with given direction value.
        :param direction: Direction value. 1 means intake, 0 means exhaust.
        :return:
        """
        try:
            fan_dir_bits = int(self.helper.read_value(FanDrawerData.FAN_DIR_PATH))
        except SysfsNotExistError as e:
            self.mocked_direction = NOT_AVAILABLE
            return

        if direction:
            fan_dir_bits = fan_dir_bits | (1 << (self.index - 1))
            self.mocked_direction = 'intake'
        else:
            fan_dir_bits = fan_dir_bits & ~(1 << (self.index - 1))
            self.mocked_direction = 'exhaust'

        self.helper.mock_value(FanDrawerData.FAN_DIR_PATH, fan_dir_bits)

    def get_status_led(self):
        """
        Get led status from sys fs.
        :return: Led status read from sys fs.
        """
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
            assert 0, 'Invalid FAN led color for FAN: {}, green={}, red={}'.format(self.name, green_led_value,
                                                                                   red_led_value)
    def get_expect_led_color(self):
        if self.mocked_presence == 'Not Present':
            return 'red'

        for fan_data in self.fan_data_list:
            if fan_data.get_expect_led_color():
                return 'red'

        return 'green'

class FanData:
    """
    Data mocker of a FAN.
    """

    # MAX PWM value.
    PWM_MAX = 255

    # Speed tolerance
    SPEED_TOLERANCE = 0.2

    def __init__(self, mock_helper, naming_rule, index):
        """
        Constructor of FAN data.
        :param mock_helper: Instance of MockHelper.
        :param naming_rule: Naming rule of this kind of Fan.
        :param index: Fan index.
        """
        self.index = index
        self.helper = mock_helper
        self.name = naming_rule['name'].format(index)
        self.speed_file = naming_rule['speed'].format(index)
        self.mocked_speed = None
        self.mocked_target_speed = None
        self.mocked_status = None

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
        """
        Mock speed value of this FAN with given speed value.
        :param speed: Speed value in percentage.
        :return:
        """
        max_speed = self.get_max_speed()
        if max_speed > 0:
            speed_in_rpm = max_speed * speed / 100
            self.helper.mock_thermal_value(self.speed_file, str(speed_in_rpm))
        else:
            self.helper.mock_thermal_value(self.speed_file, str(speed))
        self.mocked_speed = speed

    def mock_target_speed(self, target_speed):
        """
        Mock target speed value of this FAN with given target speed value.
        :param target_speed: Target speed value in percentage.
        :return:
        """
        if self.target_speed_file:
            pwm = int(round(FanData.PWM_MAX * target_speed / 100.0))
            self.helper.mock_thermal_value(self.target_speed_file, str(pwm))
            self.mocked_target_speed = str(target_speed)
        else:
            self.mocked_target_speed = self.helper.read_thermal_value(self.speed_file)

    def mock_status(self, status):
        """
        Mock status of this FAN with given status value.
        :param status: Status value. 1 means OK, 0 means Not OK.
        :return:
        """
        if self.status_file:
            self.helper.mock_thermal_value(self.status_file, str(status))
            self.mocked_status = 'OK' if status == 0 else 'Not OK'
        else:
            self.mocked_status = 'OK'

    def get_max_speed(self):
        """
        Get max speed of this FAN.
        :return: Max speed of this FAN or -1 if max speed is not available.
        """
        if self.max_speed_file:
            max_speed = self.helper.read_thermal_value(self.max_speed_file)
            return int(max_speed)
        else:
            return -1

    def get_target_speed(self):
        """
        Get target speed of this FAN.
        :return: Target speed in percentage.
        """
        pwm = self.helper.read_thermal_value(self.target_speed_file)
        pwm = int(pwm)
        target_speed = int(round(pwm * 100.0 / FanData.PWM_MAX))
        return target_speed

    def get_expect_led_color(self):
        """
        Get expect LED color.
        :return: Return the LED color that this FAN expect to have.
        """
        if self.mocked_status == 'Not OK':
            return 'red'

        target_speed = self.get_target_speed()
        mocked_speed = int(self.mocked_speed)
        if mocked_speed > target_speed * (1 + FanData.SPEED_TOLERANCE):
            return 'red'

        if mocked_speed < target_speed * (1 - FanData.SPEED_TOLERANCE):
            return 'red'

        return 'green'

 
class TemperatureData:
    """
    Data mocker of a thermal.
    """

    # Default high threshold value for generating mocked value.
    DEFAULT_HIGH_THRESHOLD = 80

    def __init__(self, mock_helper, naming_rule, index):
        """
        Constructor of FAN data.
        :param mock_helper: Instance of MockHelper.
        :param naming_rule: Naming rule of this kind of thermal.
        :param index: Thermal index.
        """
        self.helper = mock_helper
        self.name = naming_rule['name']
        self.temperature_file = naming_rule['temperature']
        self.high_threshold_file = naming_rule['high_threshold'] if 'high_threshold' in naming_rule else None
        self.high_critical_threshold_file = naming_rule[
            'high_critical_threshold'] if 'high_critical_threshold' in naming_rule else None
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
        """
        Mock temperature value of this thermal with given value.
        :param temperature: Temperature value.
        :return:
        """
        self.helper.mock_thermal_value(self.temperature_file, str(temperature))
        temperature = temperature / float(1000)
        self.mocked_temperature = str(temperature)

    def get_high_threshold(self):
        """
        Get high threshold value of this thermal.
        :return: High threshold value of this thermal.
        """
        if self.high_threshold_file:
            high_threshold = self.helper.read_thermal_value(self.high_threshold_file)
            return int(high_threshold) / float(1000)
        else:
            return TemperatureData.DEFAULT_HIGH_THRESHOLD

    def mock_high_threshold(self, high_threshold):
        """
        Mock temperature high threshold value of this thermal with given value.
        :param high_threshold: High threshold value.
        :return:
        """
        if self.high_threshold_file:
            self.helper.mock_thermal_value(self.high_threshold_file, str(high_threshold))
            self.mocked_high_threshold = str(high_threshold / float(1000))
        else:
            self.mocked_high_threshold = NOT_AVAILABLE

    def mock_high_critical_threshold(self, high_critical_threshold):
        """
        Mock temperature high critical threshold value of this thermal with given value.
        :param high_critical_threshold: High critical threshold value.
        :return:
        """
        if self.high_critical_threshold_file:
            self.helper.mock_thermal_value(self.high_critical_threshold_file, str(high_critical_threshold))
            self.mocked_high_critical_threshold = str(high_critical_threshold / float(1000))
        else:
            self.mocked_high_critical_threshold = NOT_AVAILABLE


@mocker('FanStatusMocker')
class RandomFanStatusMocker(FanStatusMocker):
    """
    Mocker class to help generate random FAN status and check it with actual data.
    """

    # Max PSU FAN speed for generate random data only.
    PSU_FAN_MAX_SPEED = 10000

    def __init__(self, dut):
        """
        Constructor of RandomFanStatusMocker.
        :param dut: DUT object representing a SONiC switch under test.
        """
        FanStatusMocker.__init__(self, dut)
        self.mock_helper = MockerHelper(dut)
        self.expected_data = {}

    def deinit(self):
        """
        Destructor of RandomFanStatusMocker.
        :return:
        """
        self.mock_helper.deinit()

    def mock_data(self):
        """
        Mock random data for all FANs in this DUT.
        :return:
        """
        fan_index = 1
        drawer_index = 1
        drawer_data = None
        presence = 0
        direction = NOT_AVAILABLE
        naming_rule = FAN_NAMING_RULE['fan']
        while fan_index <= MockerHelper.FAN_NUM:
            try:
                if (fan_index - 1) % MockerHelper.FAN_NUM_PER_DRAWER == 0:
                    drawer_data = FanDrawerData(self.mock_helper, naming_rule, drawer_index)
                    drawer_index += 1
                    presence = random.randint(0, 1)
                    drawer_data.mock_presence(presence)
                    drawer_data.mock_fan_direction(random.randint(0, 1))
                    if drawer_data.mocked_presence == 'Present':
                        presence = 1

                fan_data = FanData(self.mock_helper, naming_rule, fan_index)
                drawer_data.fan_data_list.append(fan_data)
                fan_index += 1
                if presence == 1:
                    fan_data.mock_status(random.randint(0, 1))
                    fan_data.mock_speed(random.randint(0, 100))
                    self.expected_data[fan_data.name] = [
                        drawer_data.name,
                        fan_data.name,
                        '{}%'.format(fan_data.mocked_speed),
                        drawer_data.mocked_direction,
                        drawer_data.mocked_presence,
                        fan_data.mocked_status,
                        drawer_data.get_expect_led_color()
                    ]
                else:
                    self.expected_data[fan_data.name] = [
                        drawer_data.name,
                        fan_data.name,
                        'N/A',
                        'N/A',
                        'Not Present',
                        'N/A',
                        'red'
                    ]
            except SysfsNotExistError as e:
                logging.info('Failed to mock fan data: {}'.format(e))
                continue

        dut_hwsku = self.mock_helper.dut.facts["hwsku"]
        psu_count = SWITCH_MODELS[dut_hwsku]["psus"]["number"]
        naming_rule = FAN_NAMING_RULE['psu_fan']
        for index in range(1, psu_count + 1):
            try:
                fan_data = FanData(self.mock_helper, naming_rule, index)
                # PSU fan speed display PWM not percentage, it should not be less than 100
                speed = random.randint(101, RandomFanStatusMocker.PSU_FAN_MAX_SPEED)
                fan_data.mock_speed(speed)

                self.expected_data[fan_data.name] = [
                    'PSU{}'.format(index),
                    fan_data.name,
                    '{}RPM'.format(fan_data.mocked_speed),
                    NOT_AVAILABLE,
                    'Present',
                    'OK'
                ]
            except SysfsNotExistError as e:
                logging.info('Failed to mock fan data for {} - {}'.format(fan_data.name, e))
                continue

    def check_result(self, actual_data):
        """
        Check actual data with mocked data.
        :param actual_data: A dictionary contains actual command line data. Key of the dictionary is FAN name. Value
                            of the dictionary is a list of field values for a line of FAN data.
        :return: True if match else False.
        """
        for name, fields in self.expected_data.items():
            if name in actual_data:
                actual_fields = actual_data[name]
                for i, expected_field in enumerate(fields):
                    if expected_field != actual_fields[i]:
                        logging.error('Check fan status for {} failed, ' \
                                     'expected: {}, actual: {}'.format(name, expected_field, actual_fields[i]))
                        logging.error('Expect data set: {}'.format(self.expected_data))
                        logging.error('Actual data set: {}'.format(actual_data))
                        return False
            else:
                logging.error('Expected FAN data {} not found'.format(fields))
                logging.error('Expect data set: {}'.format(self.expected_data))
                logging.error('Actual data set: {}'.format(actual_data))
                return False
        return True

    def check_all_fan_speed(self, expected_speed):
        """
        Check all FAN speed match the given expect speed.
        :param expected_speed: Expect speed in percentage.
        :return: True if match else False.
        """
        for fan_data in self.expected_data.values():
            if fan_data.target_speed_file:
                target_speed = fan_data.get_target_speed()
                if expected_speed != target_speed:
                    logging.error(
                        '{} expected speed={}, actual speed={}'.format(fan_data.name, expected_speed, target_speed))
                    return False
        return True


@mocker('ThermalStatusMocker')
class RandomThermalStatusMocker(ThermalStatusMocker):
    """
    RandomThermalStatusMocker class to help generate random thermal status and check it with actual data.
    """

    # Thermal algorithm status sys fs path.
    THERMAL_ALGO_STATUS_FILE_PATH = '/run/hw-management/config/suspend'

    # Default threshold diff between high threshold and critical threshold
    DEFAULT_THRESHOLD_DIFF = 5

    def __init__(self, dut):
        """
        Constructor of RandomThermalStatusMocker.
        :param dut: DUT object representing a SONiC switch under test.
        """
        ThermalStatusMocker.__init__(self, dut)
        self.mock_helper = MockerHelper(dut)
        self.expected_data = {}

    def deinit(self):
        """
        Destructor of RandomThermalStatusMocker.
        :return:
        """
        self.mock_helper.deinit()

    def mock_data(self):
        """
        Mock random data for all Thermals in this DUT.
        :return:
        """
        dut_hwsku = self.mock_helper.dut.facts["hwsku"]
        thermal_dict = SWITCH_MODELS[dut_hwsku]["thermals"]
        for category, content in thermal_dict.items():
            number = int(content['number'])
            naming_rule = THERMAL_NAMING_RULE[category]
            if 'start' in content:
                start = int(content['start'])
                for index in range(start, start + number):
                    mock_data = TemperatureData(self.mock_helper, naming_rule, index)
                    self._do_mock(mock_data)
            else:  # non index-able thermal
                mock_data = TemperatureData(self.mock_helper, naming_rule, None)
                self._do_mock(mock_data)

    def _do_mock(self, mock_data):
        """
        Mock random data for a thermal in the DUT.
        :param mock_data: An instance of TemperatureData.
        :return:
        """
        try:
            high_threshold = mock_data.get_high_threshold()
            if high_threshold != 0:
                temperature = random.randint(1, high_threshold - RandomThermalStatusMocker.DEFAULT_THRESHOLD_DIFF)
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
                'False'
            ]
        except SysfsNotExistError as e:
            logging.info('Failed to mock thermal data for {} - {}'.format(mock_data.name, e))

    def check_result(self, actual_data):
        """
        Check actual data with mocked data.
        :param actual_data: A dictionary contains actual command line data. Key of the dictionary is thermal name. Value
                            of the dictionary is a list of field values for a line of thermal data.
        :return: True if match else False.
        """
        for name, fields in self.expected_data.items():
            if name in actual_data:
                actual_fields = actual_data[name]
                for i, expected_field in enumerate(fields):
                    if expected_field != actual_fields[i]:
                        logging.info('Check thermal status for {} failed, ' \
                                     'expected: {}, actual: {}'.format(name, expected_field, actual_fields[i]))
                        logging.error('Expect data set: {}'.format(self.expected_data))
                        logging.error('Actual data set: {}'.format(actual_data))
                        return False
            else:
                logging.error('Expected thermal data {} not found'.format(fields))
                logging.error('Expect data set: {}'.format(self.expected_data))
                logging.error('Actual data set: {}'.format(actual_data))
                return False
        return True

    def check_thermal_algorithm_status(self, expected_status):
        """
        Check if actual thermal algorithm status match given expected value.
        :param expected_status: True if enable else False.
        :return: True if match else False
        """
        expected_value = '0' if expected_status else '1'
        return expected_value == self.mock_helper.read_value(RandomThermalStatusMocker.THERMAL_ALGO_STATUS_FILE_PATH)


@mocker('SingleFanMocker')
class AbnormalFanMocker(SingleFanMocker):
    """
    Mocker to generate abnormal FAN status.
    """

    # Speed tolerance value
    SPEED_TOLERANCE = 20

    # Speed value
    TARGET_SPEED_VALUE = 60

    def __init__(self, dut):
        """
        Constructor of AbnormalFanMocker
        :param dut: DUT object representing a SONiC switch under test.
        """
        SingleFanMocker.__init__(self, dut)
        self.mock_helper = MockerHelper(dut)
        naming_rule = FAN_NAMING_RULE['fan']
        self.fan_data_list = []
        self.fan_drawer_data_list = []
        fan_index = 1
        drawer_index = 1
        while fan_index <= MockerHelper.FAN_NUM:
            if (fan_index - 1) % MockerHelper.FAN_NUM_PER_DRAWER == 0:
                self.fan_drawer_data_list.append(FanDrawerData(self.mock_helper, naming_rule, drawer_index))
                drawer_index += 1
            self.fan_data_list.append(FanData(self.mock_helper, naming_rule, fan_index))
            fan_index += 1
        self.fan_data = self.fan_data_list[0]
        self.fan_drawer_data = self.fan_drawer_data_list[0]
        self.expect_led_color = None
        self.mock_all_normal()

    def deinit(self):
        """
        Destructor of AbnormalFanMocker.
        :return:
        """
        self.mock_helper.deinit()

    def check_result(self, actual_data):
        """
        Check actual data with mocked data.
        :param actual_data: A dictionary contains actual command line data. Key of the dictionary is FAN name. Value
                            of the dictionary is a list of field values for a line of FAN data.
        :return: True if a match line is found.
        """
        for name, fields in actual_data.items():
            if name == self.fan_data.name:
                try:
                    actual_color = self.fan_drawer_data.get_status_led()
                    assert actual_color == self.expect_led_color, 'FAN {} color is {}, expect: {}'.format(name,
                                                                                                        actual_color,
                                                                                                        self.expect_led_color)
                except SysfsNotExistError as e:
                    logging.info('LED check only support on SPC2 and SPC3: {}'.format(e))
                return

        assert 0, 'Expected data not found'

    def is_fan_removable(self):
        """
        :return: True if FAN is removable else False
        """
        dut_hwsku = self.mock_helper.dut.facts["hwsku"]
        return SWITCH_MODELS[dut_hwsku]['fans']['hot_swappable']

    def mock_all_normal(self):
        """
        Change all the mocked FANs status to normal.
        :return:
        """
        for drawer_data in self.fan_drawer_data_list:
            try:
                drawer_data.mock_presence(1)
            except SysfsNotExistError as e:
                logging.info('Failed to mock drawer data: {}'.format(e))

        for fan_data in self.fan_data_list:
            try:
                fan_data.mock_status(0)
                fan_data.mock_speed(AbnormalFanMocker.TARGET_SPEED_VALUE)
                fan_data.mock_target_speed(AbnormalFanMocker.TARGET_SPEED_VALUE)
            except SysfsNotExistError as e:
                logging.info('Failed to mock fan data: {}'.format(e))

    def mock_normal(self):
        """
        Change the mocked FAN status to 'Present' and normal speed.
        :return:
        """
        self.mock_status(0)
        self.mock_presence()
        self.mock_normal_speed()

    def mock_absence(self):
        """
        Change the mocked FAN status to 'Not Present'.
        :return:
        """
        self.fan_drawer_data.mock_presence(0)
        self.expect_led_color = 'red'

    def mock_presence(self):
        """
        Change the mocked FAN status to 'Present'
        :return:
        """
        self.fan_drawer_data.mock_presence(1)
        self.expect_led_color = 'green'

    def mock_status(self, status):
        """
        Change the mocked FAN status to good or bad
        :param status: bool value indicate the target status of the FAN.
        :return:
        """
        self.fan_data.mock_status(0 if status else 1)
        self.expect_led_color = 'green' if status else 'red'

    def mock_over_speed(self):
        """
        Change the mocked FAN speed to faster than target speed and exceed speed tolerance.
        :return:
        """
        self.fan_data.mock_speed(AbnormalFanMocker.TARGET_SPEED_VALUE + AbnormalFanMocker.SPEED_TOLERANCE + 5)
        self.fan_data.mock_target_speed(AbnormalFanMocker.TARGET_SPEED_VALUE)
        self.expect_led_color = 'red'

    def mock_under_speed(self):
        """
        Change the mocked FAN speed to slower than target speed and exceed speed tolerance.
        :return:
        """
        self.fan_data.mock_speed(AbnormalFanMocker.TARGET_SPEED_VALUE - AbnormalFanMocker.SPEED_TOLERANCE - 5)
        self.fan_data.mock_target_speed(AbnormalFanMocker.TARGET_SPEED_VALUE)
        self.expect_led_color = 'red'

    def mock_normal_speed(self):
        """
        Change the mocked FAN speed to a normal value.
        :return:
        """
        self.fan_data.mock_speed(AbnormalFanMocker.TARGET_SPEED_VALUE)
        self.fan_data.mock_target_speed(AbnormalFanMocker.TARGET_SPEED_VALUE)
        self.expect_led_color = 'green'
