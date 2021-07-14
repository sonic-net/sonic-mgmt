import pytest
import logging

# from srltest.library import test_log

# pytestmark_config_check = pytest.mark.srl_skip_config_check
# pytestmark_skip_fib_agent = pytest.mark.srl_skip_fib_agent
# pytestmark = pytest.mark.register(level='regular', owner='falodiya')

from ndk_common import get_expecetd_data, get_ndk_cli_response, get_expected_hwsku_data


pytestmark = [
    pytest.mark.skip,
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('ndk')
]


class TestHotSwap(object):
    """Test hotswap service"""
    expected_data = None
    if expected_data is None:
        expected_data = get_expecetd_data()


def compare_actual_expected_telem_info(actual, min_key, max_key, duthost, device_info, key=None):
    """Compare actual/expected data"""
    msg = ''
    failed = False
    min_expected = get_expected_hwsku_data(duthost.hostname, TestHotSwap.expected_data,
                                           min_key, key='hotswap')
    max_expected = get_expected_hwsku_data(duthost.hostname, TestHotSwap.expected_data,
                                           max_key, key='hotswap')
    if max_expected < actual or actual < min_expected:
        failed = True
        msg = ('{} is {} on dut {} for device info {}, Expected was between {} and {}'
               .format(key, actual, duthost.hostname, device_info,
                       min_expected, max_expected))

    logging.info('{} is {} on dut {} for device info {}, Expected between range {} and {}'
                 .format(key, actual, duthost.hostname, device_info,
                         min_expected, max_expected))
    return failed, msg


def test_hotswap_current_in(duthosts):
    """Tests hotswap current in"""
    msg_list = list()
    for duthost in duthosts.nodes:
        hw_telem_list = get_ndk_cli_response(duthost, 'hwHiTelemShowJson', key='telem_info')
        for hw_telem in hw_telem_list:
            current_in = hw_telem.get('current_in')/1000
            failed, msg = compare_actual_expected_telem_info(current_in, 'min_current_in', 'max_current_in', duthost,
                                                             hw_telem.get('device_info'), key='Current in')
            if failed:
                msg_list.append(msg)

    if len(msg_list):
        pytest.fail(msg_list)


def test_hotswap_voltage_in_out(duthosts):
    """Test get voltage in/out"""
    msg_list = list()
    for duthost in duthosts.nodes:
        hw_telem_list = get_ndk_cli_response(duthost, 'hwHiTelemShowJson', key='telem_info')
        for hw_telem in hw_telem_list:
            voltage_in = hw_telem.get('voltage_in') / 1000
            voltage_out = hw_telem.get('voltage_out') / 1000
            # compare_actual_expected_telem_info(voltage_in)

    if len(msg_list):
        pytest.fail(msg_list)


def test_hotswap_power_in(duthosts):
    """Tests power in """
    msg_list = list()
    for duthost in duthosts.nodes:
        hw_telem_list = get_ndk_cli_response(duthost, 'hwHiTelemShowJson', key='telem_info')
        for hw_telem in hw_telem_list:
            power_in = hw_telem.get('power_in') / 1000
            failed, msg = compare_actual_expected_telem_info(power_in, 'min_power_in', 'max_power_in', duthost,
                                                             hw_telem.get('device_info'), key='Power in')
            if failed:
                msg_list.append(msg)

    if len(msg_list):
        pytest.fail(msg_list)


def test_hotswap_temperature(duthosts):
    """Test hotswap temperature"""
    msg_list = list()
    for duthost in duthosts.nodes:
        hw_telem_list = get_ndk_cli_response(duthost, 'hwHiTelemShowJson', key='telem_info')
        for hw_telem in hw_telem_list:
            temperature = hw_telem.get('temperature') / 1000
            failed, msg = compare_actual_expected_telem_info(temperature, 'min_hotswap_temp', 'max_hotswap_temp',
                                                             duthost,
                                                             hw_telem.get('device_info'), key='Temperature')
            if failed:
                msg_list.append(msg)

    if len(msg_list):
        pytest.fail(msg_list)


def test_hotswap_peak_power_watts(duthosts):
    """Test hotswap peak power watts """
    msg_list = list()
    for duthost in duthosts.nodes:
        hw_telem_list = get_ndk_cli_response(duthost, 'hwHiTelemShowJson', key='telem_info')
        for hw_telem in hw_telem_list:
            power_watts = hw_telem.get('peak_info').get('power_watts') / 1000
            failed, msg = compare_actual_expected_telem_info(power_watts, 'min_power_watts', 'max_power_watts', duthost,
                                                             hw_telem.get('device_info'), key='Peak power watts')
            if failed:
                msg_list.append(msg)

    if len(msg_list):
        pytest.fail(msg_list)


def test_hotswap_sfm_current_in(duthosts):
    """Tests hotswap sfm current in"""
    msg_list = list()
    for duthost in duthosts.supervisor_nodes:
        sfm_num = get_expected_hwsku_data(duthost.hostname, TestHotSwap.expected_data,
                                          'max_sfm_num', default=None)
        for sfm in range(1, sfm_num+1):
            cmd = 'hwHiTelemShowSfmJson {}'.format(sfm)
            hw_telem_list = get_ndk_cli_response(duthost, cmd, key='telem_info')
            for hw_telem in hw_telem_list:
                sfm_current_in = hw_telem.get('current_in')/1000
                failed, msg = compare_actual_expected_telem_info(sfm_current_in, 'sfm_min_current_in',
                                                                 'sfm_max_current_in', duthost,
                                                                 hw_telem.get('device_info'), key='SFM Current in')
                if failed:
                    msg_list.append(msg)

    if len(msg_list):
        pytest.fail(msg_list)


def test_hotswap_sfm_power_in(duthosts):
    """Tests hotswap sfm power in"""
    msg_list = list()
    for duthost in duthosts.supervisor_nodes:
        sfm_num = get_expected_hwsku_data(duthost.hostname, TestHotSwap.expected_data,
                                          'max_sfm_num', default=None)
        for sfm in range(1, sfm_num+1):
            cmd = 'hwHiTelemShowSfmJson {}'.format(sfm)
            hw_telem_list = get_ndk_cli_response(duthost, cmd, key='telem_info')
            for hw_telem in hw_telem_list:
                sfm_power_in = hw_telem.get('power_in')/1000
                failed, msg = compare_actual_expected_telem_info(sfm_power_in, 'sfm_min_power_in',
                                                                 'sfm_max_power_in', duthost,
                                                                 hw_telem.get('device_info'), key='SFM Power in')
                if failed:
                    msg_list.append(msg)

    if len(msg_list):
        pytest.fail(msg_list)


def test_hotswap_sfm_temperature(duthosts):
    """Tests hotswap sfm temperature"""
    msg_list = list()
    for duthost in duthosts.supervisor_nodes:
        sfm_num = get_expected_hwsku_data(duthost.hostname, TestHotSwap.expected_data,
                                          'max_sfm_num', default=None)
        for sfm in range(1, sfm_num + 1):
            cmd = 'hwHiTelemShowSfmJson {}'.format(sfm)
            hw_telem_list = get_ndk_cli_response(duthost, cmd, key='telem_info')
            for hw_telem in hw_telem_list:
                sfm_temperature = hw_telem.get('temperature')/1000
                failed, msg = compare_actual_expected_telem_info(sfm_temperature, 'sfm_min_temperature',
                                                                 'sfm_max_temperature', duthost,
                                                                 hw_telem.get('device_info'), key='SFM temperature')
                if failed:
                    msg_list.append(msg)

    if len(msg_list):
        pytest.fail(msg_list)


def test_hotswap_sfm_power_watts(duthosts):
    """Tests hotswap sfm power watts"""
    msg_list = list()
    for duthost in duthosts.supervisor_nodes:
        sfm_num = get_expected_hwsku_data(duthost.hostname, TestHotSwap.expected_data,
                                          'max_sfm_num', default=None)
        for sfm in range(1, sfm_num + 1):
            cmd = 'hwHiTelemShowSfmJson {}'.format(sfm)
            hw_telem_list = get_ndk_cli_response(duthost, cmd, key='telem_info')
            for hw_telem in hw_telem_list:
                sfm_power_watts = hw_telem.get('peak_info').get('power_watts')/1000
                failed, msg = compare_actual_expected_telem_info(sfm_power_watts, 'sfm_min_power_watts',
                                                                 'sfm_max_power_watts', duthost,
                                                                 hw_telem.get('device_info'), key='SFM power watts')
                if failed:
                    msg_list.append(msg)

    if len(msg_list):
        pytest.fail(msg_list)


def test_hotswap_sfm_voltage_in_out(duthosts):
    """Test sfm voltage in/out"""
    msg_list = list()
    for duthost in duthosts.supervisor_nodes:
        sfm_num = get_expected_hwsku_data(duthost.hostname, TestHotSwap.expected_data,
                                          'max_sfm_num', default=None)
        for sfm in range(1, sfm_num + 1):
            cmd = 'hwHiTelemShowSfmJson {}'.format(sfm)
            hw_telem_list = get_ndk_cli_response(duthost, cmd, key='telem_info')
            min_voltage = get_expected_hwsku_data(duthost.hostname, TestHotSwap.expected_data,
                                                  'sfm_min_voltage', default=None)
            max_volatge = get_expected_hwsku_data(duthost.hostname, TestHotSwap.expected_data,
                                                  'sfm_max_voltage', default=None)
            for hw_telem in hw_telem_list:
                voltage_in = hw_telem.get('voltage_in') / 1000
                voltage_out = hw_telem.get('voltage_out') / 1000
                # if max_current_in <= current_in <= min_current_in:
                #     msg = ('Current in is {} on dut {} for device info {}, Expected was between {} and {}'
                #            .format(current_in, duthost.hostname, hw_telem.get('device_info'),
                #                    min_current_in, max_current_in))
                #     msg_list.append(msg)
                # logging.info('Cuurent in is {} on dut {} for device info {}, Expected between range {} and {}'
                #              .format(current_in, duthost.hostname, hw_telem.get('device_info'),
                #                      min_current_in, max_current_in))
    if len(msg_list):
        pytest.fail(msg_list)
