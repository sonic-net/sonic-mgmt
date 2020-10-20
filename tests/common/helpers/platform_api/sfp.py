"""
This module provides an interface to remotely interact with SFP
transceivers connected to the DUT via platform API
"""

import json
import logging

logger = logging.getLogger(__name__)


def sfp_api(conn, index, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/sfp/{}/{}'.format(index, name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing sfp API: "{}", index: {}, arguments: "{}", result: "{}"'.format(name, index, args, res))
    return res


#
# Methods inherited from DeviceBase class
#

def get_name(conn, index):
    return sfp_api(conn, index, 'get_name')


def get_presence(conn, index):
    return sfp_api(conn, index, 'get_presence')


def get_model(conn, index):
    return sfp_api(conn, index, 'get_model')


def get_serial(conn, index):
    return sfp_api(conn, index, 'get_serial')


def get_status(conn, index):
    return sfp_api(conn, index, 'get_status')


#
# Methods defined in SfpBase class
#

# NOTE: The get_change_event() method is not represented here because there is no reliable way
# to test this method in an automated fashion.

def get_transceiver_info(conn, index):
    return sfp_api(conn, index, 'get_transceiver_info')


def get_transceiver_bulk_status(conn, index):
    return sfp_api(conn, index, 'get_transceiver_bulk_status')


def get_transceiver_threshold_info(conn, index):
    return sfp_api(conn, index, 'get_transceiver_threshold_info')


def get_reset_status(conn, index):
    return sfp_api(conn, index, 'get_reset_status')


def get_rx_los(conn, index):
    return sfp_api(conn, index, 'get_rx_los')


def get_tx_fault(conn, index):
    return sfp_api(conn, index, 'get_tx_fault')


def get_tx_disable(conn, index):
    return sfp_api(conn, index, 'get_tx_disable')


def get_tx_disable_channel(conn, index):
    return sfp_api(conn, index, 'get_tx_disable_channel')


def get_lpmode(conn, index):
    return sfp_api(conn, index, 'get_lpmode')


def get_power_override(conn, index):
    return sfp_api(conn, index, 'get_power_override')


def get_temperature(conn, index):
    return sfp_api(conn, index, 'get_temperature')


def get_voltage(conn, index):
    return sfp_api(conn, index, 'get_voltage')


def get_tx_bias(conn, index):
    return sfp_api(conn, index, 'get_tx_bias')


def get_rx_power(conn, index):
    return sfp_api(conn, index, 'get_rx_power')


def get_tx_power(conn, index):
    return sfp_api(conn, index, 'get_tx_power')


def reset(conn, index):
    return sfp_api(conn, index, 'reset')


def tx_disable(conn, index, disable):
    return sfp_api(conn, index, 'tx_disable', [disable])


def tx_disable_channel(conn, index, channel_mask, disable):
    return sfp_api(conn, index, 'tx_disable_channel', [channel_mask, disable])


def set_lpmode(conn, index, lpmode):
    return sfp_api(conn, index, 'set_lpmode', [lpmode])


def set_power_override(conn, index, power_override, power_set):
    return sfp_api(conn, index, 'set_power_override', [power_override, power_set])


def get_position_in_parent(conn, index):
    return sfp_api(conn, index, 'get_position_in_parent')


def is_replaceable(conn, index):
    return sfp_api(conn, index, 'is_replaceable')


def get_num_thermals(conn, index):
    return sfp_api(conn, index, 'get_num_thermals')


def get_all_thermals(conn, index):
    return sfp_api(conn, index, 'get_all_thermals')


def get_thermal(conn, index, thermal_index):
    return sfp_api(conn, index, 'get_thermal', [thermal_index])
