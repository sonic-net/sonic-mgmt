# -*- coding: utf-8 -*-

# Copyright (c), Felix Fontein <felix@fontein.de>, 2019
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import sys

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.urls import fetch_url, open_url

try:
    from urllib.error import HTTPError
except ImportError:
    # Python 2.x fallback:
    from urllib2 import HTTPError

import json
import time

from ansible_collections.community.hrobot.plugins.module_utils.common import (
    PluginException,
    CheckDoneTimeoutException,
)


ROBOT_DEFAULT_ARGUMENT_SPEC = dict(
    hetzner_user=dict(type='str', required=True),
    hetzner_password=dict(type='str', required=True, no_log=True),
    rate_limit_retry_timeout=dict(type='int', default=-1),
)

_ROBOT_DEFAULT_ARGUMENT_SPEC_COMPAT = dict(
    hetzner_user=dict(type='str', required=False),
    hetzner_password=dict(type='str', required=False, no_log=True),
)

_ROBOT_DEFAULT_ARGUMENT_SPEC_COMPAT_DEPRECATED = dict(
    hetzner_user=dict(type='str', required=False, removed_in_version="3.0.0", removed_from_collection="community.hrobot"),
    hetzner_password=dict(type='str', required=False, no_log=True, removed_in_version="3.0.0", removed_from_collection="community.hrobot"),
)


# The API endpoint is fixed.
BASE_URL = "https://robot-ws.your-server.de"


def get_x_www_form_urlenconded_dict_from_list(key, values):
    '''Return a dictionary with keys values'''
    if len(values) == 1:
        return {'{key}[]'.format(key=key): values[0]}
    else:
        return dict(('{key}[{index}]'.format(key=key, index=i), x) for i, x in enumerate(values))


def _format_list(obj):
    if not isinstance(obj, (list, tuple)):
        return to_native(obj)
    return [_format_list(e) for e in obj]


_RATE_LIMITING_ERROR = 'RATE_LIMIT_EXCEEDED'
_RATE_LIMITING_START_DELAY = 5


def format_error_msg(error, rate_limit_timeout=None):
    # Reference: https://robot.hetzner.com/doc/webservice/en.html#errors
    msg = 'Request failed: {0} {1} ({2})'.format(
        error['status'],
        error['code'],
        error['message'],
    )
    if error.get('missing'):
        msg += '. Missing input parameters: {0}'.format(_format_list(error['missing']))
    if error.get('invalid'):
        msg += '. Invalid input parameters: {0}'.format(_format_list(error['invalid']))
    if error.get('max_request') is not None:
        msg += '. Maximum allowed requests: {0}'.format(error['max_request'])
    if error.get('interval') is not None:
        msg += '. Time interval in seconds: {0}'.format(error['interval'])
    if rate_limit_timeout is not None and rate_limit_timeout > 0 and error['code'] == _RATE_LIMITING_ERROR:
        msg += '. Waited a total of {0:.1f} seconds for rate limit errors to go away'.format(rate_limit_timeout)
    return msg


def raw_plugin_open_url_json(plugin, url, method='GET', timeout=10, data=None, headers=None,
                             accept_errors=None, allow_empty_result=False,
                             allowed_empty_result_status_codes=(200, 204), templar=None,
                             rate_limit_timeout=None):
    '''
    Make general request to Hetzner's JSON robot API.
    Does not handle rate limiting especially.
    '''
    accept_errors = accept_errors or ()
    user = plugin.get_option('hetzner_user')
    password = plugin.get_option('hetzner_password')
    if templar is not None:
        if templar.is_template(user):
            user = templar.template(variable=user)
        if templar.is_template(password):
            password = templar.template(variable=password)
    try:
        response = open_url(
            url,
            url_username=user,
            url_password=password,
            force_basic_auth=True,
            data=data,
            headers=headers,
            method=method,
            timeout=timeout,
        )
        status = response.code
        content = response.read()
        reason = response.reason
    except HTTPError as e:
        status = e.code
        reason = e.reason
        try:
            content = e.read()
        except AttributeError:
            content = b''
    except Exception as e:
        raise PluginException('Failed request to Hetzner Robot server endpoint {0}: {1}'.format(url, e))

    if not content:
        if allow_empty_result and status in allowed_empty_result_status_codes:
            return None, None
        raise PluginException(
            "Cannot retrieve content from {0} {1}, HTTP status code {2} ({3})".format(
                method, url, status, reason
            )
        )

    try:
        result = json.loads(content.decode('utf-8'))
        if 'error' in result:
            if result['error']['code'] in accept_errors:
                return result, result['error']['code']
            raise PluginException(format_error_msg(result['error'], rate_limit_timeout=rate_limit_timeout))
        return result, None
    except ValueError:
        raise PluginException('Cannot decode content retrieved from {0}'.format(url))


def raw_fetch_url_json(module, url, method='GET', timeout=10, data=None, headers=None,
                       accept_errors=None, allow_empty_result=False,
                       allowed_empty_result_status_codes=(200, 204),
                       rate_limit_timeout=None):
    '''
    Make general request to Hetzner's JSON robot API.
    Does not handle rate limiting especially.
    '''
    accept_errors = accept_errors or ()
    module.params['url_username'] = module.params['hetzner_user']
    module.params['url_password'] = module.params['hetzner_password']
    module.params['force_basic_auth'] = True
    resp, info = fetch_url(module, url, method=method, timeout=timeout, data=data, headers=headers)
    try:
        # In Python 2, reading from a closed response yields a TypeError.
        # In Python 3, read() simply returns ''
        if sys.version_info[0] > 2 and resp.closed:
            raise TypeError
        content = resp.read()
    except (AttributeError, TypeError):
        content = info.pop('body', None)

    if not content:
        if allow_empty_result and info.get('status') in allowed_empty_result_status_codes:
            return None, None
        module.fail_json(
            msg='Cannot retrieve content from {0} {1}, HTTP status code {2} ({3})'.format(
                method, url, info.get('status'), info.get('msg')
            )
        )

    try:
        result = module.from_json(content.decode('utf8'))
        if 'error' in result:
            if result['error']['code'] in accept_errors:
                return result, result['error']['code']
            module.fail_json(
                msg=format_error_msg(result['error'], rate_limit_timeout=rate_limit_timeout),
                error=result['error'],
            )
        return result, None
    except ValueError:
        module.fail_json(msg='Cannot decode content retrieved from {0}'.format(url))


def _handle_rate_limit(accept_errors, check_done_timeout, call):
    original_accept_errors, accept_errors = accept_errors, accept_errors or ()
    check_done_delay = _RATE_LIMITING_START_DELAY
    if _RATE_LIMITING_ERROR in accept_errors or check_done_timeout == 0:
        return call(original_accept_errors, None)
    accept_errors = [_RATE_LIMITING_ERROR] + list(accept_errors)

    start_time = time.time()
    first = True
    timeout = False
    while True:
        if first:
            elapsed = 0
            first = False
        else:
            elapsed = (time.time() - start_time)
            if check_done_timeout > 0:
                left_time = check_done_timeout - elapsed
                wait = max(min(check_done_delay, left_time), 0)
                timeout = left_time <= check_done_delay
            else:
                wait = check_done_delay
            time.sleep(wait)
        result, error = call(
            original_accept_errors if timeout else accept_errors,
            elapsed,
        )
        if error != _RATE_LIMITING_ERROR:
            return result, error
        if result['error'].get('interval') and check_done_delay > result['error']['interval'] > 0:
            check_done_delay = result['error']['interval']


def plugin_open_url_json(plugin, url, method='GET', timeout=10, data=None, headers=None,
                         accept_errors=None, allow_empty_result=False,
                         allowed_empty_result_status_codes=(200, 204), templar=None):
    '''
    Make general request to Hetzner's JSON robot API.
    '''
    def call(accept_errors_, rate_limit_timeout):
        return raw_plugin_open_url_json(
            plugin,
            url,
            method=method,
            timeout=timeout,
            data=data,
            headers=headers,
            accept_errors=accept_errors_,
            allow_empty_result=allow_empty_result,
            allowed_empty_result_status_codes=allowed_empty_result_status_codes,
            templar=templar,
            rate_limit_timeout=rate_limit_timeout,
        )

    return _handle_rate_limit(
        accept_errors,
        plugin.get_option('rate_limit_retry_timeout'),
        call,
    )


def fetch_url_json(module, url, method='GET', timeout=10, data=None, headers=None,
                   accept_errors=None, allow_empty_result=False,
                   allowed_empty_result_status_codes=(200, 204)):
    '''
    Make general request to Hetzner's JSON robot API.
    '''
    def call(accept_errors_, rate_limit_timeout):
        return raw_fetch_url_json(
            module,
            url,
            method=method,
            timeout=timeout,
            data=data,
            headers=headers,
            accept_errors=accept_errors_,
            allow_empty_result=allow_empty_result,
            allowed_empty_result_status_codes=allowed_empty_result_status_codes,
            rate_limit_timeout=rate_limit_timeout,
        )

    return _handle_rate_limit(
        accept_errors,
        module.params['rate_limit_retry_timeout'],
        call,
    )


def fetch_url_json_with_retries(module, url, check_done_callback, check_done_delay=10, check_done_timeout=180, skip_first=False, **kwargs):
    '''
    Make general request to Hetzner's JSON robot API, with retries until a condition is satisfied.

    The condition is tested by calling ``check_done_callback(result, error)``. If it is not satisfied,
    it will be retried with delays ``check_done_delay`` (in seconds) until a total timeout of
    ``check_done_timeout`` (in seconds) since the time the first request is started is reached.

    If ``skip_first`` is specified, will assume that a first call has already been made and will
    directly start with waiting.
    '''
    start_time = time.time()
    if not skip_first:
        result, error = fetch_url_json(module, url, **kwargs)
        if check_done_callback(result, error):
            return result, error
    while True:
        elapsed = (time.time() - start_time)
        left_time = check_done_timeout - elapsed
        time.sleep(max(min(check_done_delay, left_time), 0))
        result, error = fetch_url_json(module, url, **kwargs)
        if check_done_callback(result, error):
            return result, error
        if left_time < check_done_delay:
            raise CheckDoneTimeoutException(result, error)
