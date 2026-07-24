"""
This module provides an interface to remotely interact with the power
distribution boards (PDB) of the DUT via platform API
"""

import json
import logging

logger = logging.getLogger(__name__)


def pdb_api(conn, pdb_id, name, args=None):
    if args is None:
        args = []
    conn.request('POST', f'/platform/chassis/pdb/{pdb_id}/{name}', json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info(f'Executing PDB API: "{name}", arguments: "{args}", result: "{res}"')
    return res


#
# Methods inherited from DeviceBase class
#

def get_name(conn, index):
    return pdb_api(conn, index, 'get_name')


def get_presence(conn, index):
    return pdb_api(conn, index, 'get_presence')


def get_model(conn, index):
    return pdb_api(conn, index, 'get_model')


def get_serial(conn, index):
    return pdb_api(conn, index, 'get_serial')


def get_revision(conn, index):
    return pdb_api(conn, index, 'get_revision')


def get_status(conn, index):
    return pdb_api(conn, index, 'get_status')


def get_position_in_parent(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_position_in_parent')


def is_replaceable(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'is_replaceable')

#
# Methods defined in PdbBase class
#


def get_input_voltage(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_input_voltage')


def get_input_current(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_input_current')


def get_input_power(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_input_power')


def get_output_voltage(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_output_voltage')


def get_output_current(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_output_current')


def get_output_power(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_output_power')


def get_maximum_supplied_power(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_maximum_supplied_power')


def get_temperature(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_temperature')


def get_num_thermals(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_num_thermals')


def get_all_thermals(conn, pdb_id):
    return pdb_api(conn, pdb_id, 'get_all_thermals')


def get_thermal(conn, pdb_id, index):
    return pdb_api(conn, pdb_id, 'get_thermal', [index])
