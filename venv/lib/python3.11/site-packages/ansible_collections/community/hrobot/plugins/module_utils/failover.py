# -*- coding: utf-8 -*-

# Copyright (c), Felix Fontein <felix@fontein.de>, 2019
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    fetch_url_json,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


def get_failover_record(module, ip):
    '''
    Get information record of failover IP.

    See https://robot.your-server.de/doc/webservice/en.html#get-failover-failover-ip
    '''
    url = "{0}/failover/{1}".format(BASE_URL, ip)
    result, error = fetch_url_json(module, url)
    if 'failover' not in result:
        module.fail_json(msg='Cannot interpret result: {0}'.format(json.dumps(result, sort_keys=True)))
    return result['failover']


def get_failover(module, ip):
    '''
    Get current routing target of failover IP.

    The value ``None`` represents unrouted.

    See https://robot.your-server.de/doc/webservice/en.html#get-failover-failover-ip
    '''
    return get_failover_record(module, ip)['active_server_ip']


def set_failover(module, ip, value, timeout=180):
    '''
    Set current routing target of failover IP.

    Return a pair ``(value, changed)``. The value ``None`` for ``value`` represents unrouted.

    See https://robot.your-server.de/doc/webservice/en.html#post-failover-failover-ip
    and https://robot.your-server.de/doc/webservice/en.html#delete-failover-failover-ip
    '''
    url = "{0}/failover/{1}".format(BASE_URL, ip)
    if value is None:
        result, error = fetch_url_json(
            module,
            url,
            method='DELETE',
            timeout=timeout,
            accept_errors=['FAILOVER_ALREADY_ROUTED']
        )
    else:
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = dict(
            active_server_ip=value,
        )
        result, error = fetch_url_json(
            module,
            url,
            method='POST',
            timeout=timeout,
            data=urlencode(data),
            headers=headers,
            accept_errors=['FAILOVER_ALREADY_ROUTED']
        )
    if error is not None:
        return value, False
    else:
        return result['failover']['active_server_ip'], True


def get_failover_state(value):
    '''
    Create result dictionary for failover IP's value.

    The value ``None`` represents unrouted.
    '''
    return dict(
        value=value,
        state='routed' if value else 'unrouted'
    )
