"""
This module provides an interface to remotely interact with the liquid cooling leakage
of the DUT via platform API
"""

import json
import logging

logger = logging.getLogger(__name__)


def liquid_cooling_leakage_api(conn, name, args=None):
    if args is None:
        args = []
    conn.request(
        'POST',
        f'/platform/chassis/liquid_cooling/{name}',
        json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info(f'Executing liquid cooling leakage API: "{name}", arguments: "{args}", result: "{res}"')
    return res

def single_liquid_cooling_leakage_api(conn, leak_sensor_id, name, args=None):
    if args is None:
        args = []
    conn.request(
        'POST',
        f'/platform/chassis/liquid_cooling/leak_sensor/{leak_sensor_id}/{name}',
        json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info(f'Executing liquid cooling leakage API: "{name}", \
        leak_sensor_id: "{leak_sensor_id}", arguments: "{args}", result: "{res}"')
    return res


def get_name(conn, leak_sensor_id):
    return single_liquid_cooling_leakage_api(conn, leak_sensor_id, 'get_name')

def is_leak(conn, leak_sensor_id):
    return single_liquid_cooling_leakage_api(conn, leak_sensor_id, 'is_leak')

def get_num_leak_sensors(conn):
    return liquid_cooling_leakage_api(conn, 'get_num_leak_sensors')

def get_leak_sensor_status(conn):
    return liquid_cooling_leakage_api(conn, 'get_leak_sensor_status')

def get_all_leak_sensors(conn):
    return liquid_cooling_leakage_api(conn, 'get_all_leak_sensors')
