# -*- coding: utf-8 -*-

# Copyright (c) 2025 Felix Fontein <felix@fontein.de>
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import sys

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.urls import fetch_url

import time

from ansible_collections.community.hrobot.plugins.module_utils.common import (  # pylint: disable=unused-import
    CheckDoneTimeoutException,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


API_DEFAULT_ARGUMENT_SPEC = dict(
    hetzner_token=dict(type='str', required=True, no_log=True),
    rate_limit_retry_timeout=dict(type='int', default=-1),
)

_API_DEFAULT_ARGUMENT_SPEC_COMPAT = dict(
    hetzner_token=dict(type='str', required=False, no_log=True),
)

# The API endpoint is fixed.
API_BASE_URL = "https://api.hetzner.com"


_RATE_LIMITING_ERROR = 'rate_limit_exceeded'
_RATE_LIMITING_START_DELAY = 5


def format_api_error_msg(error, rate_limit_timeout=None):
    # Reference: https://docs.hetzner.cloud/reference/hetzner#errors
    msg = 'Request failed: [{0}] {1}'.format(
        error['code'],
        error['message'],
    )
    if error.get('details'):
        msg += ". Details: {0}".format(error['details'])
    return msg


def raw_api_fetch_url_json(
    module,
    url,
    method='GET',
    timeout=10,
    data=None,
    headers=None,
    accept_errors=None,
    # allow_empty_result=False,
    # allowed_empty_result_status_codes=(),
    rate_limit_timeout=None,
):
    '''
    Make general request to Hetzner's API.
    Does not handle rate limiting especially.
    '''
    actual_headers = {
        "Authorization": "Bearer {0}".format(module.params['hetzner_token']),
    }
    if headers:
        actual_headers.update(headers)
    accept_errors = accept_errors or ()

    resp, info = fetch_url(module, url, method=method, timeout=timeout, data=data, headers=actual_headers)
    try:
        # In Python 2, reading from a closed response yields a TypeError.
        # In Python 3, read() simply returns ''
        if sys.version_info[0] > 2 and resp.closed:
            raise TypeError
        content = resp.read()
    except (AttributeError, TypeError):
        content = info.pop('body', None)

    if not content:
        # if allow_empty_result and info.get('status') in allowed_empty_result_status_codes:
        #     return None, info, None
        module.fail_json(
            msg='Cannot retrieve content from {0} {1}, HTTP status code {2} ({3})'.format(
                method, url, info.get('status'), info.get('msg')
            )
        )

    try:
        result = module.from_json(content.decode('utf8'))
        if 'error' in result:
            if result['error']['code'] in accept_errors:
                return result, info, result['error']['code']
            module.fail_json(
                msg=format_api_error_msg(result['error'], rate_limit_timeout=rate_limit_timeout),
                error=result['error'],
            )
        return result, info, None
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
        result, info, error = call(
            original_accept_errors if timeout else accept_errors,
            elapsed,
        )
        if error != _RATE_LIMITING_ERROR:
            return result, info, error
        # TODO: is there a hint how much time we should wait?
        # If yes, adjust check_done_delay accordingly!


def api_fetch_url_json(
    module,
    url,
    method='GET',
    timeout=10,
    data=None,
    headers=None,
    accept_errors=None,
    # allow_empty_result=False,
    # allowed_empty_result_status_codes=(),
):
    '''
    Make general request to Hetzner's API.
    '''
    def call(accept_errors_, rate_limit_timeout):
        return raw_api_fetch_url_json(
            module,
            url,
            method=method,
            timeout=timeout,
            data=data,
            headers=headers,
            accept_errors=accept_errors_,
            # allow_empty_result=allow_empty_result,
            # allowed_empty_result_status_codes=allowed_empty_result_status_codes,
            rate_limit_timeout=rate_limit_timeout,
        )

    return _handle_rate_limit(
        accept_errors,
        module.params['rate_limit_retry_timeout'],
        call,
    )


def deterministic_urlencode(data, **kwargs):
    """
    Same as urlencode(), but the keys are sorted lexicographically.
    """
    result = []
    for key, value in sorted(data.items()):
        result.append(urlencode({key: value}, **kwargs))
    return '&'.join(result)


def api_fetch_url_json_list(
    module,
    url,
    data_key,
    method='GET',
    timeout=10,
    headers=None,
    accept_errors=None,
    page_size=100,
):
    '''
    Completely request a paginated list from Hetzner's API.
    '''
    page = 1
    last_page = None
    result_list = []
    while page is not None and (last_page is None or last_page >= page):
        page_url = '{0}{1}{2}'.format(url, '&' if '?' in url else '?', deterministic_urlencode({"page": str(page), "per_page": page_size}))
        result, dummy, error = api_fetch_url_json(
            module,
            page_url,
            method=method,
            timeout=timeout,
            headers=headers,
            accept_errors=accept_errors,
        )
        # TODO: add coverage!
        if error:  # pragma: no cover
            return result_list, error  # pragma: no cover
        if isinstance(result.get(data_key), list):
            result_list += result[data_key]
        if isinstance(result.get("meta"), dict) and isinstance(result["meta"].get("pagination"), dict):
            pagination = result["meta"]["pagination"]
            if isinstance(pagination.get("last_page"), int):
                last_page = pagination["last_page"]
            if isinstance(pagination.get("next_page"), int):
                page = pagination["next_page"]
            else:
                page += 1
        elif not result.get(data_key):
            break
        else:
            page += 1
    return result_list, None


def api_fetch_url_json_with_retries(module, url, check_done_callback, check_done_delay=10, check_done_timeout=180, skip_first=False, **kwargs):
    '''
    Make general request to Hetzner's API, with retries until a condition is satisfied.

    The condition is tested by calling ``check_done_callback(result, error)``. If it is not satisfied,
    it will be retried with delays ``check_done_delay`` (in seconds) until a total timeout of
    ``check_done_timeout`` (in seconds) since the time the first request is started is reached.

    If ``skip_first`` is specified, will assume that a first call has already been made and will
    directly start with waiting.
    '''
    start_time = time.time()
    if not skip_first:  # pragma: no cover
        raise AssertionError("Code path not yet available")  # pragma: no cover
        # result, error = api_fetch_url_json(module, url, **kwargs)
        # if check_done_callback(result, error):
        #     return result, error
    while True:
        elapsed = (time.time() - start_time)
        left_time = check_done_timeout - elapsed
        time.sleep(max(min(check_done_delay, left_time), 0))
        result, info, error = api_fetch_url_json(module, url, **kwargs)
        if check_done_callback(result, info, error):
            return result, info, error
        if left_time < check_done_delay:
            raise CheckDoneTimeoutException(result, error)


class ApplyActionError(Exception):
    def __init__(self, msg, extracted_ids=None):
        super(ApplyActionError, self).__init__(msg)
        self.extracted_ids = extracted_ids or {}


def api_apply_action(
    module,
    action_url,
    action_data,
    action_check_url_provider,
    method='POST',
    check_done_delay=10,
    check_done_timeout=180,
    accept_errors=None,
):
    headers = {"Content-type": "application/json"} if action_data is not None else {}
    result, dummy, error = api_fetch_url_json(
        module,
        action_url,
        data=module.jsonify(action_data) if action_data is not None else None,
        headers=headers,
        method=method,
        accept_errors=accept_errors,
    )
    if error:
        return None, error
    action_id = result["action"]["id"]
    extracted_ids = {
        res["type"]: res["id"] for res in result["action"]["resources"] or [] if res.get("id") is not None and res.get("type")
    }
    if result["action"]["status"] == "running":
        this_action_url = action_check_url_provider(action_id)

        def action_done_callback(result_, info_, error_):
            if error_ is not None:  # pragma: no cover
                return True  # pragma: no cover
            return result_["action"]["status"] != "running"

        try:
            result, dummy, dummy2 = api_fetch_url_json_with_retries(
                module, this_action_url, action_done_callback, check_done_delay=1, check_done_timeout=60, skip_first=True,
            )
        except CheckDoneTimeoutException as dummy:
            raise ApplyActionError("Timeout", extracted_ids=extracted_ids)
    error = result["action"].get("error")
    if isinstance(error, dict):
        raise ApplyActionError('[{0}] {1}'.format(to_native(error.get("code")), to_native(error.get("message"))), extracted_ids=extracted_ids)
    elif result["action"]["status"] == "error":
        raise ApplyActionError('Unknown error', extracted_ids=extracted_ids)
    return extracted_ids, None
