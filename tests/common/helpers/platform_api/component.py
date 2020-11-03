"""
This module provides an interface to remotely interact with Components
of the DUT via platform API
"""

import json
import logging

logger = logging.getLogger(__name__)


def component_api(conn, index, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/component/{}/{}'.format(index, name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing component API: "{}", index: {}, arguments: "{}", result: "{}"'.format(name, index, args, res))
    return res


#
# Methods inherited from DeviceBase class
#

def get_name(conn, comp_idx):
    return component_api(conn, comp_idx, 'get_name')


def get_presence(conn, comp_idx):
    return component_api(conn, comp_idx, 'get_presence')


def get_model(conn, comp_idx):
    return component_api(conn, comp_idx, 'get_model')


def get_serial(conn, comp_idx):
    return component_api(conn, comp_idx, 'get_serial')


def get_status(conn, comp_idx):
    return component_api(conn, comp_idx, 'get_status')


def get_position_in_parent(conn, comp_idx):
    return component_api(conn, comp_idx, 'get_position_in_parent')


def is_replaceable(conn, comp_idx):
    return component_api(conn, comp_idx, 'is_replaceable')

#
# Methods defined in ComponentBase class
#


def get_description(conn, comp_idx):
    return component_api(conn, comp_idx, 'get_description')


def get_firmware_version(conn, comp_idx):
    return component_api(conn, comp_idx, 'get_firmware_version')


def get_available_firmware_version(conn, comp_idx, image_path):
    return component_api(conn, comp_idx, 'get_available_firmware_version', [image_path])


def get_firmware_update_notification(conn, comp_idx, image_path):
    return component_api(conn, comp_idx, 'get_firmware_update_notification', [image_path])


def install_firmware(conn, comp_idx, image_path):
    return component_api(conn, comp_idx, 'install_firmware', [image_path])


def update_firmware(conn, comp_idx, image_path):
    return component_api(conn, comp_idx, 'update_firmware', [image_path])
