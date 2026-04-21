# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# Copyright (c) 2020 Markus Bergholz <markuman+spambelongstogoogle@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import json
import sys
import time

from ansible.module_utils.common.text.converters import to_native
from ansible_collections.community.dns.plugins.module_utils.zone_record_api import (
    DNSAPIAuthenticationError,
    DNSAPIError,
)


try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode  # type: ignore


if sys.version_info >= (3, 6):
    import typing

    if typing.TYPE_CHECKING:
        from collections.abc import Collection  # pragma: no cover

        from .http import HTTPHelper  # pragma: no cover
        from .provider import ProviderInformation  # pragma: no cover
        from .record import DNSRecord  # pragma: no cover
        from .zone_record_api import ZoneRecordAPI  # pragma: no cover


ERROR_CODES = {
    200: "Successful response",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    406: "Not acceptable",
    409: "Conflict",
    422: "Unprocessable entity",
    500: "Internal Server Error",
}
UNKNOWN_ERROR = "Unknown Error"


def _get_header_value(
    info,  # type: dict[str, typing.Any]
    header_name,  # type: str
):  # type: (...) -> str | None
    header_name = header_name.lower()
    header_value = info.get(header_name)
    for k, v in info.items():
        if k.lower() == header_name:
            header_value = v
    return header_value


class JSONAPIHelper(object):
    def __init__(
        self,
        http_helper,  # type: HTTPHelper
        token,  # type: str
        api,  # type: str
        debug=False,  # type: bool
    ):  # type: (...) -> None
        """
        Create a new JSON API helper instance with given API key.
        """
        self._api = api  # type: str
        self._http_helper = http_helper  # type: HTTPHelper
        self._token = token  # type: str
        self._debug = debug  # type: bool

    def _build_url(
        self,
        url,  # type: str
        query=None,  # type: dict[str, str] | None
    ):  # type: (...) -> str
        return '{0}{1}{2}'.format(self._api, url, ('?' + urlencode(query)) if query else '')

    def _extract_error_message(
        self,
        result,  # type: bytes | None
    ):  # type: (...) -> str
        if result is None:
            return ''
        return ' with data: {0!r}'.format(result)

    def _validate(
        self,
        result=None,  # type: bytes | None
        info=None,  # type: dict[str, typing.Any] | None
        expected=None,  # type: Collection[int] | None
        method='GET',  # type: str
    ):  # type: (...) -> None
        if info is None:
            raise DNSAPIError('Internal error: info needs to be provided')
        status = info['status']
        url = info['url']
        # Check expected status
        error_code = ERROR_CODES.get(status, UNKNOWN_ERROR)
        if expected is not None:
            if status not in expected:
                more = self._extract_error_message(result)
                raise DNSAPIError(
                    'Expected HTTP status {0} for {1} {2}, but got HTTP status {3} ({4}){5}'.format(
                        ', '.join(['{0}'.format(e) for e in expected]), method, url, status, error_code, more))
        else:
            if status < 200 or status >= 300:
                more = self._extract_error_message(result)
                raise DNSAPIError(
                    'Expected successful HTTP status for {0} {1}, but got HTTP status {2} ({3}){4}'.format(
                        method, url, status, error_code, more))

    def _process_json_result(
        self,
        content,  # type: bytes | None
        info,  # type: dict[str, typing.Any]
        must_have_content=True,  # type: bool | list[int] | tuple[int, ...]
        method='GET',  # type: str
        expected=None,  # type: Collection[int] | None
    ):  # type: (...) -> tuple[dict[str, typing.Any] | list[typing.Any] | None, dict[str, typing.Any]]
        if isinstance(must_have_content, (list, tuple)):
            must_have_content = info['status'] in must_have_content
        # Check for unauthenticated
        if info['status'] == 401:
            message = 'Unauthorized: the authentication parameters are incorrect (HTTP status 401)'
            try:
                body = json.loads(content.decode('utf8'))  # type: ignore
                if body['message']:
                    message = '{0}: {1}'.format(message, body['message'])
            except Exception:
                pass
            raise DNSAPIAuthenticationError(message)
        if info['status'] == 403:
            message = 'Forbidden: you do not have access to this resource (HTTP status 403)'
            try:
                body = json.loads(content.decode('utf8'))  # type: ignore
                if body['message']:
                    message = '{0}: {1}'.format(message, body['message'])
            except Exception:
                pass
            raise DNSAPIAuthenticationError(message)
        # Check Content-Type header
        content_type = _get_header_value(info, 'content-type')
        if content_type != 'application/json' and (content_type is None or not content_type.startswith('application/json;')):
            if must_have_content:
                raise DNSAPIError(
                    '{0} {1} did not yield JSON data, but HTTP status code {2} with Content-Type "{3}" and data: {4}'.format(
                        method, info['url'], info['status'], content_type, to_native(content)))
            self._validate(result=content, info=info, expected=expected, method=method)
            return None, info
        # Decode content as JSON
        try:
            result = json.loads(content.decode('utf8'))  # type: ignore
        except Exception:
            if must_have_content:
                raise DNSAPIError(
                    '{0} {1} did not yield JSON data, but HTTP status code {2} with data: {3}'.format(
                        method, info['url'], info['status'], to_native(content)))
            self._validate(result=content, info=info, expected=expected, method=method)
            return None, info
        self._validate(result=result, info=info, expected=expected, method=method)
        return result, info

    def _request(
        self,
        url,  # type: str
        **kwargs
    ):  # type: (...) -> tuple[bytes | None, dict[str, typing.Any]]
        """Execute a HTTP request and handle common things like rate limiting."""
        number_retries = 10
        countdown = number_retries + 1
        while True:
            content, info = self._http_helper.fetch_url(url, **kwargs)
            countdown -= 1
            if info['status'] == 429:
                if countdown <= 0:
                    break
                try:
                    retry_after = max(min(float(_get_header_value(info, 'retry-after')), 60), 1)  # type: ignore
                except (ValueError, TypeError):
                    retry_after = 10
                time.sleep(retry_after)
                continue
            return content, info
        raise DNSAPIError('Stopping after {0} failed retries with 429 Too Many Attempts'.format(number_retries))

    def _create_headers(self):  # type: (...) -> dict[str, str]
        return {
            'accept': 'application/json',
        }

    def _get(
        self,
        url,  # type: str
        query=None,  # type: dict[str, str] | None
        must_have_content=True,  # type: bool | list[int] | tuple[int, ...]
        expected=None,  # type: Collection[int] | None
    ):  # type: (...) -> tuple[dict[str, typing.Any] | list[typing.Any] | None, dict[str, typing.Any]]
        full_url = self._build_url(url, query)
        if self._debug:
            pass  # pragma: no cover
            # q.q('Request: GET {0}'.format(full_url))
        headers = self._create_headers()
        content, info = self._request(full_url, headers=headers, method='GET')
        return self._process_json_result(content, info, must_have_content=must_have_content, method='GET', expected=expected)

    def _post(
        self,
        url,  # type: str
        data=None,  # type: dict[str, typing.Any] | None
        query=None,  # type: dict[str, str] | None
        must_have_content=True,  # type: bool | list[int] | tuple[int, ...]
        expected=None,  # type: Collection[int] | None
    ):  # type: (...) -> tuple[dict[str, typing.Any] | list[typing.Any] | None, dict[str, typing.Any]]
        full_url = self._build_url(url, query)
        if self._debug:
            pass  # pragma: no cover
            # q.q('Request: POST {0}'.format(full_url))
        headers = self._create_headers()
        encoded_data = None
        if data is not None:
            headers['content-type'] = 'application/json'
            encoded_data = json.dumps(data).encode('utf-8')
        content, info = self._request(full_url, headers=headers, method='POST', data=encoded_data)
        return self._process_json_result(content, info, must_have_content=must_have_content, method='POST', expected=expected)

    def _put(
        self,
        url,  # type: str
        data=None,  # type: dict[str, typing.Any] | None
        query=None,  # type: dict[str, str] | None
        must_have_content=True,  # type: bool | list[int] | tuple[int, ...]
        expected=None,  # type: Collection[int] | None
    ):  # type: (...) -> tuple[dict[str, typing.Any] | list[typing.Any] | None, dict[str, typing.Any]]
        full_url = self._build_url(url, query)
        if self._debug:
            pass  # pragma: no cover
            # q.q('Request: PUT {0}'.format(full_url))
        headers = self._create_headers()
        encoded_data = None
        if data is not None:
            headers['content-type'] = 'application/json'
            encoded_data = json.dumps(data).encode('utf-8')
        content, info = self._request(full_url, headers=headers, method='PUT', data=encoded_data)
        return self._process_json_result(content, info, must_have_content=must_have_content, method='PUT', expected=expected)

    def _delete(
        self,
        url,  # type: str
        query=None,  # type: dict[str, str] | None
        must_have_content=True,  # type: bool | list[int] | tuple[int, ...]
        expected=None,  # type: Collection[int] | None
    ):  # type: (...) -> tuple[dict[str, typing.Any] | list[typing.Any] | None, dict[str, typing.Any]]
        full_url = self._build_url(url, query)
        if self._debug:
            pass  # pragma: no cover
            # q.q('Request: DELETE {0}'.format(full_url))
        headers = self._create_headers()
        content, info = self._request(full_url, headers=headers, method='DELETE')
        return self._process_json_result(content, info, must_have_content=must_have_content, method='DELETE', expected=expected)
