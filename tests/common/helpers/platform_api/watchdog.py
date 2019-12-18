""" This module provides interface to interact with DUT watchdog remotely """

import json
import logging
import httplib

logger = logging.getLogger(__name__)

PLATFORM_TEST_SERVICE_PORT = 8000


def watchdog_api(duthost, name, args=None):
    if args is None:
        args = []
    conn = httplib.HTTPConnection(duthost.hostname, PLATFORM_TEST_SERVICE_PORT)
    conn.request('POST', '/platform/chassis/watchdog/{}'.format(name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing watchdog API: "{}", arguments: "{}", result: "{}"'.format(name, args, res))
    return res


def arm(duthost, seconds):
    return watchdog_api(duthost, 'arm', [seconds])


def is_armed(duthost):
    return watchdog_api(duthost, 'is_armed')


def disarm(duthost):
    return watchdog_api(duthost, 'disarm')


def get_remaining_time(duthost):
    return watchdog_api(duthost, 'get_remaining_time')
