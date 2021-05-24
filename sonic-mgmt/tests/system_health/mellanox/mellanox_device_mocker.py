from ..device_mocker import DeviceMocker
from tests.common.mellanox_data import get_platform_data
from tests.platform_tests.mellanox.mellanox_thermal_control_test_helper import MockerHelper, FanDrawerData, FanData, \
    FAN_NAMING_RULE


class AsicData(object):
    TEMPERATURE_FILE = '/run/hw-management/thermal/asic'
    THRESHOLD_FILE = '/run/hw-management/thermal/mlxsw/temp_trip_hot'

    def __init__(self, mock_helper):
        self.helper = mock_helper

    def mock_asic_temperature(self, value):
        self.helper.mock_value(AsicData.TEMPERATURE_FILE, str(value))

    def get_asic_temperature_threshold(self):
        value = self.helper.read_value(AsicData.THRESHOLD_FILE)
        return int(value)


class PsuData(object):
    PSU_STATUS_FILE = '/run/hw-management/thermal/psu{}_status'
    PSU_POWER_STATUS_FILE = '/run/hw-management/thermal/psu{}_pwr_status'
    PSU_TEMPERATURE_FILE = '/run/hw-management/thermal/psu{}_temp'
    PSU_TEMP_THRESHOLD_FILE = '/run/hw-management/thermal/psu{}_temp_max'

    def __init__(self, mock_helper, index):
        self.helper = mock_helper
        self.index = index
        self.name = 'PSU {}'.format(self.index)
        power_status_file = PsuData.PSU_POWER_STATUS_FILE.format(index)
        out = self.helper.dut.stat(path=power_status_file)
        if out['stat']['exists']:
            self.power_on = True
        else:
            self.power_on = False

    def mock_presence(self, status):
        value = 1 if status else 0
        presence_file = PsuData.PSU_STATUS_FILE.format(self.index)
        self.helper.mock_value(presence_file, str(value))

    def mock_status(self, status):
        value = 1 if status else 0
        power_status_file = PsuData.PSU_POWER_STATUS_FILE.format(self.index)
        self.helper.mock_value(power_status_file, str(value))

    def mock_temperature(self, value):
        temperature_file = PsuData.PSU_TEMPERATURE_FILE.format(self.index)
        self.helper.mock_value(temperature_file, str(value))

    def get_psu_temperature_threshold(self):
        threshold_file = PsuData.PSU_TEMP_THRESHOLD_FILE.format(self.index)
        value = self.helper.read_value(threshold_file)
        return int(value)


class MellanoxDeviceMocker(DeviceMocker):
    TARGET_SPEED_VALUE = 60
    SPEED_TOLERANCE = 50
    PSU_NUM = 2

    def __init__(self, dut):
        self.mock_helper = MockerHelper(dut)
        self.asic_data = AsicData(self.mock_helper)
        naming_rule = FAN_NAMING_RULE['fan']
        self.fan_drawer_data = FanDrawerData(self.mock_helper, naming_rule, 1)
        self.fan_data = FanData(self.mock_helper, naming_rule, 1)

        for i in range(MellanoxDeviceMocker.PSU_NUM):
            self.psu_data = PsuData(self.mock_helper, i + 1)
            if self.psu_data.power_on:
                break

    def deinit(self):
        self.mock_helper.deinit()

    def mock_fan_presence(self, status):
        platform_data = get_platform_data(self.mock_helper.dut)
        always_present = not platform_data['fans']['hot_swappable']
        if always_present:
            return False, None

        value = 1 if status else 0
        self.fan_drawer_data.mock_presence(value)
        return True, self.fan_data.name

    def mock_fan_status(self, status):
        value = 0 if status else 1
        self.fan_data.mock_status(value)
        return True, self.fan_data.name

    def mock_fan_speed(self, good):
        if good:
            actual_speed = MellanoxDeviceMocker.TARGET_SPEED_VALUE
        else:
            actual_speed = MellanoxDeviceMocker.TARGET_SPEED_VALUE * (100 - MellanoxDeviceMocker.SPEED_TOLERANCE) / 100 - 10
        self.fan_data.mock_target_speed(MellanoxDeviceMocker.TARGET_SPEED_VALUE)
        self.fan_data.mock_speed(actual_speed)
        return True, self.fan_data.name

    def mock_asic_temperature(self, good):
        threshold = self.asic_data.get_asic_temperature_threshold()
        if good:
            value = threshold - 1000
        else:
            value = threshold + 1000
        self.asic_data.mock_asic_temperature(value)
        return True

    def mock_psu_presence(self, status):
        self.psu_data.mock_presence(1 if status else 0)
        return True, self.psu_data.name

    def mock_psu_status(self, status):
        self.psu_data.mock_status(1 if status else 0)
        return True, self.psu_data.name

    def mock_psu_temperature(self, good):
        threshold = self.psu_data.get_psu_temperature_threshold()
        if good:
            value = threshold - 1000
        else:
            value = threshold + 1000
        self.psu_data.mock_temperature(value)
        return True, self.psu_data.name

    def mock_psu_voltage(self, good):
        # Not Supported for now
        return False, None
