"""
This module provides an interface to remotely interact with Modules
of the DUT via platform API
"""

import json
import logging

logger = logging.getLogger(__name__)


def module_api(conn, index, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/module/{}/{}'.format(index, name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing module API: "{}", index: {}, arguments: "{}", result: "{}"'.format(name, index, args, res))
    return res


#
# Methods inherited from DeviceBase class
#

def get_name(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_name')


def get_presence(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_presence')


def get_model(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_model')


def get_serial(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_serial')


def get_status(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_status')


#
# Methods defined in ModuleBase class
#

# NOTE: The get_change_event() method is not represented here because there is no reliable way
# to test this method in an automated fashion.

def get_base_mac(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_base_mac')


def get_system_eeprom_info(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_system_eeprom_info')


def get_num_components(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_num_components')


def get_all_components(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_all_components')


def get_component(conn, mod_idx, comp_idx):
    return module_api(conn, mod_idx, 'get_component', [comp_idx])


def get_num_fans(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_num_fans')


def get_all_fans(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_all_fans')


def get_fan(conn, mod_idx, fan_idx):
    return module_api(conn, mod_idx, 'get_fan', [fan_idx])


def get_num_psus(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_num_psus')


def get_all_psus(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_all_psus')


def get_psu(conn, mod_idx, psu_idx):
    return module_api(conn, mod_idx, 'get_psu', [psu_idx])


def get_num_thermals(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_num_thermals')


def get_all_thermals(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_all_thermals')


def get_thermal(conn, mod_idx, therm_idx):
    return module_api(conn, mod_idx, 'get_thermal', [therm_idx])


def get_thermal_manager(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_thermal_manager')


def get_num_sfps(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_num_sfps')


def get_all_sfps(conn, mod_idx):
    return module_api(conn, mod_idx, 'get_all_sfps')


def get_sfp(conn, mod_idx, sfp_idx):
    return module_api(conn, mod_idx, 'get_sfp', [sfp_idx])
