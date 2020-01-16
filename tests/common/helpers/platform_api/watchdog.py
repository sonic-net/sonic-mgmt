""" This module provides interface to interact with DUT watchdog remotely """

import json
import logging

logger = logging.getLogger(__name__)

def watchdog_api(conn, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/watchdog/{}'.format(name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing watchdog API: "{}", arguments: "{}", result: "{}"'.format(name, args, res))
    return res


def arm(conn, seconds):
    return watchdog_api(conn, 'arm', [seconds])


def is_armed(conn):
    return watchdog_api(conn, 'is_armed')


def disarm(conn):
    return watchdog_api(conn, 'disarm')


def get_remaining_time(conn):
    return watchdog_api(conn, 'get_remaining_time')

