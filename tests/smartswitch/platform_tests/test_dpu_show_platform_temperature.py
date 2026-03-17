import pytest
from datetime import datetime
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure


pytestmark = [
    pytest.mark.topology('dpu', 'smartswitch')
]

# NVIDIA Smartswitch DPU platform
NVIDIA_SMART_SWITCH_DPU_PLATFORM = 'arm64-nvda_bf-bf3comdpu'
# Standalone DPU platform
BF_3_PLATFORM = 'arm64-nvda_bf-9009d3b600cvaa'

SENSORS = {NVIDIA_SMART_SWITCH_DPU_PLATFORM: ['CPU', 'DDR', 'NVME'],
           BF_3_PLATFORM: ['CPU', 'DDR', 'SFP0', 'SFP1']}
SENSOR_ITEMS = ['temperature', 'high th', 'low th', 'crit high th', 'crit low th', 'warning', 'timestamp']
EXPECTED_SENSOR_VALUES = {
    NVIDIA_SMART_SWITCH_DPU_PLATFORM: {
        'CPU': {
            'high th': '95',
            'low th': 'N/A',
            'crit high th': '100',
            'crit low th': 'N/A'
        },
        'DDR': {
            'high th': '95',
            'low th': 'N/A',
            'crit high th': '100',
            'crit low th': 'N/A'
        },
        'NVME': {
            'high th': '100',
            'low th': 'N/A',
            'crit high th': '110',
            'crit low th': 'N/A'
        }
    },
    BF_3_PLATFORM: {
        'CPU': {
            'high th': '95',
            'low th': 'N/A',
            'crit high th': '100',
            'crit low th': 'N/A'
        },
        'DDR': {
            'high th': '95',
            'low th': 'N/A',
            'crit high th': '100',
            'crit low th': 'N/A'
        },
        'SFP0': {
            'high th': 'N/A',
            'low th': 'N/A',
            'crit high th': '105',
            'crit low th': 'N/A'
        },
        'SFP1': {
            'high th': 'N/A',
            'low th': 'N/A',
            'crit high th': '105',
            'crit low th': 'N/A'
        }
    }
}


def test_dpu_show_platform_temperature(duthosts, rand_one_dut_hostname):
    """
    Validate output of command "show platform temperature" on DPU devices
    """
    duthost = duthosts[rand_one_dut_hostname]
    cmd = "show platform temperature"
    platform_temp_parsed = duthost.show_and_parse(cmd)

    platform = duthost.facts['platform']
    expected_sensors = SENSORS[platform]
    expected_sensor_values = EXPECTED_SENSOR_VALUES[platform]

    with allure.step('Validate that all expected sensors available'):
        available_sensors = [sensor_data['sensor'] for sensor_data in platform_temp_parsed]

        for sensor in expected_sensors:
            assert sensor in available_sensors, \
                'Sensor "{}" not available in output of cmd: "{}"'.format(sensor, cmd)

    for sensor_data in platform_temp_parsed:
        sensor = sensor_data['sensor']
        with allure.step('Validate values for sensor "{}"'.format(sensor)):
            for item in SENSOR_ITEMS:
                if item == 'temperature':
                    with allure.step('Validate the value for "temperature"'):
                        temperature = sensor_data['temperature']
                        low_th = expected_sensor_values[sensor]['low th']
                        high_th = expected_sensor_values[sensor]['high th']
                        if low_th != 'N/A':
                            pytest_assert(float(temperature) > float(low_th),
                                          f'Temperature: {temperature} for sensor: {sensor} '
                                          f'should be higher than the low th: {low_th}')
                        if high_th != 'N/A':
                            pytest_assert(float(temperature) < float(high_th),
                                          f'Temperature: {temperature} for sensor: {sensor} '
                                          f'should be lower than the high th: {low_th}')
                elif item == 'warning':
                    with allure.step('Validate the value for "warning"'):
                        assert sensor_data['warning'] == 'False', \
                            f'Sensor: {sensor} has warning "True", but there is no violation in the thresholds.'
                elif item == 'timestamp':
                    with allure.step('Validate the value for "timestamp"'):
                        try:
                            datetime.strptime(sensor_data['timestamp'], '%Y%m%d %H:%M:%S')
                        except ValueError:
                            raise AssertionError(f"Unable to parse timestamp: {sensor_data['timestamp']}")
                else:
                    with allure.step(f'Validate the value for "{item}"'):
                        actual_value = str(sensor_data[item])
                        expected_value = expected_sensor_values[sensor][item]
                        pytest_assert(actual_value == expected_value,
                                      f"{item} value of sensor {sensor} is not as expected, "
                                      f"actual: {actual_value}, expected: {expected_value}")
