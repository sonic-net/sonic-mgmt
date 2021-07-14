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


class TestPcon(object):
    """Test pcon service"""
    expected_data = None
    if expected_data is None:
        expected_data = get_expecetd_data()


def compare_actual_expected_pcon_data(actual, pcon_data, key, duthost, pcon_device=None):
    """"Compares Actual and expected data"""
    msg = ''
    failed = False
    expected = get_expected_hwsku_data(duthost.hostname, TestPcon.expected_data, pcon_data, key='pcon')
    if actual != expected:
        failed = True
        msg = ('{} is {} on dut {} for pcon device {}, Expected was {}'
               .format(key, actual, duthost.hostname, pcon_device, expected))

        logging.info('{} is {} on dut {} for pcon device {}, Expected between range {} and {}'
                     .format(key, actual, duthost.hostname, pcon_device, expected))

    return failed, msg


def test_pcon_number_of_device(duthosts):
    """Test number of pcon device"""
    msg_list = list()
    for duthost in duthosts.nodes:
        pcon_device_list = get_ndk_cli_response(duthost, 'hwPconShowChannelsJson', key='device')
        failed, msg = compare_actual_expected_pcon_data(len(pcon_device_list), 'num_pcon_device',
                                                        'Number of pcon', duthost)
        if failed:
            msg_list.append(msg)

    if len(msg_list):
        pytest.fail(msg_list)


def test_pcon_channel_enabled(duthosts):
    """Tests pcon channel enable"""
    msg_list = list()
    for duthost in duthosts.nodes:
        pcon_device_list = get_ndk_cli_response(duthost, 'hwPconShowChannelsJson', key='device')
        for device in pcon_device_list:
            for channel in device.get('channel'):
                if not channel.get('enable'):
                    msg = ('PCON channel is not enabled on dut {} for pcon device {}, Expected was enabled.'
                          .format(duthost.hostname, device))
                    msg_list.append(msg)
                logging.info('PCON channel {} is enabled on dut {} for pcon device {}'
                             .format(channel, channel.get('enable'), duthost.hostname, device))

    if len(msg_list):
        pytest.fail(msg_list)


def test_pcon_voltage(duthosts):
    """Test pcon volatge"""
    msg_list = list()
    for duthost in duthosts.nodes:
        pcon_device_list = get_ndk_cli_response(duthost, 'hwPconShowChannelsJson', key='device')
        for device in pcon_device_list:
            for channel in device.get('channel'):
                if channel.get('master') and channel.get('voltage') <= 0:
                    msg = ('pcon channel {} for device {} is master but volatge is {},'
                           ' Expected was more than 0 on dut {}'
                           .format(channel, device, channel.get('voltage'), duthost.hostname))
                    msg_list.append(msg)
                logging.info('pcon channel {} for device {} is master, voltage is {} on dut {}'
                             .format(channel, device, channel.get('voltage'), duthost.hostname))

    if len(msg_list):
        pytest.fail(msg_list)


def test_pcon_current(duthosts):
    msg_list = list()
    for duthost in duthosts.nodes:
        pcon_device_list = get_ndk_cli_response(duthost, 'hwPconShowChannelsJson', key='device')
        min_pcon_channel_current = get_expected_hwsku_data(duthost.hostname, TestPcon.expected_data,
                                                           'min_pcon_channel_current', key='pcon')

        max_pcon_channel_current = get_expected_hwsku_data(duthost.hostname, TestPcon.expected_data,
                                                           'max_pcon_channel_current', key='pcon')
        for device in pcon_device_list:
            for channel in device.get('channel'):
                if ((channel.get('current') / 1000) < min_pcon_channel_current) \
                        or ((channel.get('current') /1000) > max_pcon_channel_current):
                    msg = ('pcon channel current for device {} on channel {} is {},'
                           ' Expected was between range {} and {} on dut {}'
                           .format(device, channel, channel.get('current'), min_pcon_channel_current,
                                   max_pcon_channel_current, duthost.hostname))
                    msg_list.append(msg)
                logging.info('pcon channel current for device {} on channel {} is {},'
                             ' Expected between {} and {} on dut {}'
                             .format(device, channel, channel.get('current'), min_pcon_channel_current,
                                     max_pcon_channel_current, duthost.hostname))

    if len(msg_list):
        pytest.fail(msg_list)


def test_num_sfm_pcon_device(duthosts):
    """Test number of pcon device per sfm"""
    msg_list = list()
    for duthost in duthosts.supervisor_nodes:
        sfm_num = get_expected_hwsku_data(duthost.hostname, TestPcon.expected_data,
                                          'max_sfm_num', default=None)
        for sfm in range(1, sfm_num+1):
            cmd = 'hwPconShowChannelsSfmJson {}'.format(sfm)
            pcon_device_list_per_sfm = get_ndk_cli_response(duthost, cmd, key='device')
            failed, msg = compare_actual_expected_pcon_data(len(pcon_device_list_per_sfm),
                                                                'num_pcon_device_per_sfm',
                                                                'Number of pcon per sfm', duthost)
            if failed:
                msg_list.append(msg)
    if len(msg_list):
        pytest.fail(msg_list)


def test_sfm_pcon_channel_enable(duthosts):
    """Tests sfm pcon channel enable"""
    msg_list = list()
    for duthost in duthosts.supervisor_nodes:
        sfm_num = get_expected_hwsku_data(duthost.hostname, TestPcon.expected_data,
                                          'max_sfm_num', default=None)
        for num in range(1, sfm_num+1):
            cmd = 'hwPconShowChannelsSfmJson {}'.format(num)
            pcon_device_list = get_ndk_cli_response(duthost, cmd, key='device')
            for device in pcon_device_list:
                for channel in device.get('channel'):
                    if not channel.get('enable'):
                        msg = ('PCON channel is not enabled on dut {} for pcon device {}, Expected was enabled.'
                               .format(duthost.hostname, device))
                        msg_list.append(msg)
                    logging.info('PCON channel {} is enabled on dut {} for pcon device {}'
                                 .format(channel, channel.get('enable'), duthost.hostname, device))

    if len(msg_list):
        pytest.fail(msg_list)


def test_sfm_pcon_voltage(duthosts):
    """Test sfm pcon volatge"""
    msg_list = list()
    for duthost in duthosts.supervisor_nodes:
        sfm_num = get_expected_hwsku_data(duthost.hostname, TestPcon.expected_data,
                                          'max_sfm_num', default=None)
        for num in range(1, sfm_num+1):
            cmd = 'hwPconShowChannelsSfmJson {}'.format(num)
            pcon_device_list = get_ndk_cli_response(duthost, cmd, key='device')
            for device in pcon_device_list:
                for channel in device.get('channel'):
                    if channel.get('master') and channel.get('voltage') <= 0:
                        msg = ('pcon channel {} for device {} is master but volatge is {},'
                               ' Expected was more than 0 on dut {}'
                               .format(channel, device, channel.get('voltage'), duthost.hostname))
                        msg_list.append(msg)
                    logging.info('pcon channel {} for device {} is master, voltage is {} on dut {}'
                                 .format(channel, device, channel.get('voltage'), duthost.hostname))

    if len(msg_list):
        pytest.fail(msg_list)


def test_sfm_pcon_current(duthosts):
    """Test sfm pcon channel current"""
    msg_list = list()
    for duthost in duthosts.supervisor_nodes:
        sfm_num = get_expected_hwsku_data(duthost.hostname, TestPcon.expected_data,
                                          'max_sfm_num', default=None)
        for num in range(1, sfm_num+1):
            cmd = 'hwPconShowChannelsSfmJson {}'.format(num)
            pcon_device_list = get_ndk_cli_response(duthost, cmd, key='device')
            min_pcon_channel_current = get_expected_hwsku_data(duthost.hostname, TestPcon.expected_data,
                                                               'min_pcon_channel_current', key='pcon')

            max_pcon_channel_current = get_expected_hwsku_data(duthost.hostname, TestPcon.expected_data,
                                                               'max_pcon_channel_current', key='pcon')
            for device in pcon_device_list:
                for channel in device.get('channel'):
                    if (channel.get('current')/1000 < min_pcon_channel_current) \
                            or (channel.get('current')/1000 > max_pcon_channel_current):
                        msg = ('pcon channel current for device {} on channel {} is {},'
                               ' Expected was between range {} and {} on dut {}'
                               .format(device, channel, channel.get('current'), min_pcon_channel_current,
                                       max_pcon_channel_current, duthost.hostname))
                        msg_list.append(msg)
                    logging.info('pcon channel current for device {} on channel {} is {},'
                                 ' Expected between {} and {} on dut {}'
                                 .format(device, channel, channel.get('current'), min_pcon_channel_current,
                                         max_pcon_channel_current, duthost.hostname))

    if len(msg_list):
        pytest.fail(msg_list)
