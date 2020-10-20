""" This module provides interface to interact with the chassis of the DUT
    via platform API remotely """

import json
import logging

logger = logging.getLogger(__name__)


def chassis_api(conn, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/{}'.format(name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing chassis API: "{}", arguments: "{}", result: "{}"'.format(name, args, res))
    return res


#
# Methods inherited from DeviceBase class
#

def get_name(conn):
    return chassis_api(conn, 'get_name')


def get_presence(conn):
    return chassis_api(conn, 'get_presence')


def get_model(conn):
    return chassis_api(conn, 'get_model')


def get_serial(conn):
    return chassis_api(conn, 'get_serial')


def get_status(conn):
    return chassis_api(conn, 'get_status')


#
# Methods defined in ChassisBase class
#

# NOTE: The get_change_event() method is not represented here because there is no reliable way
# to test this method in an automated fashion.

def get_base_mac(conn):
    return chassis_api(conn, 'get_base_mac')


def get_system_eeprom_info(conn):
    return chassis_api(conn, 'get_system_eeprom_info')


def get_reboot_cause(conn):
    return chassis_api(conn, 'get_reboot_cause')


def get_num_components(conn):
    return chassis_api(conn, 'get_num_components')


def get_all_components(conn):
    return chassis_api(conn, 'get_all_components')


def get_component(conn, index):
    return chassis_api(conn, 'get_component', [index])


def get_num_modules(conn):
    return chassis_api(conn, 'get_num_modules')


def get_all_modules(conn):
    return chassis_api(conn, 'get_all_modules')


def get_module(conn, index):
    return chassis_api(conn, 'get_module', [index])


def get_num_fans(conn):
    return chassis_api(conn, 'get_num_fans')


def get_all_fans(conn):
    return chassis_api(conn, 'get_all_fans')


def get_fan(conn, index):
    return chassis_api(conn, 'get_fan', [index])


def get_num_fan_drawers(conn):
    return chassis_api(conn, 'get_num_fan_drawers')


def get_all_fan_drawers(conn):
    return chassis_api(conn, 'get_all_fan_drawers')


def get_fan_drawer(conn, index):
    return chassis_api(conn, 'get_fan_drawer', [index])


def get_num_psus(conn):
    return chassis_api(conn, 'get_num_psus')


def get_all_psus(conn):
    return chassis_api(conn, 'get_all_psus')


def get_psu(conn, index):
    return chassis_api(conn, 'get_psu', [index])


def get_num_thermals(conn):
    return chassis_api(conn, 'get_num_thermals')


def get_all_thermals(conn):
    return chassis_api(conn, 'get_all_thermals')


def get_thermal(conn, index):
    return chassis_api(conn, 'get_thermal', [index])


def get_thermal_manager(conn):
    return chassis_api(conn, 'get_thermal_manager')


def get_num_sfps(conn):
    return chassis_api(conn, 'get_num_sfps')


def get_all_sfps(conn):
    return chassis_api(conn, 'get_all_sfps')


def get_sfp(conn, index):
    return chassis_api(conn, 'get_sfp', [index])


def set_status_led(conn, color):
    return chassis_api(conn, 'set_status_led', [color])


def get_status_led(conn):
    return chassis_api(conn, 'get_status_led')


def get_watchdog(conn):
    return chassis_api(conn, 'get_watchdog')


def get_eeprom(conn):
    return chassis_api(conn, 'get_eeprom')


def get_position_in_parent(conn):
    return chassis_api(conn, 'get_position_in_parent')


def is_replaceable(conn):
    return chassis_api(conn, 'is_replaceable')
