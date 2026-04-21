# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import abc
import sys

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.urls import ConnectionError, NoSSLError, fetch_url, open_url
from ansible_collections.community.dns.plugins.module_utils._six import add_metaclass


try:
    from urllib.error import HTTPError
except ImportError:
    # Python 2.x fallback:
    from urllib2 import HTTPError  # type: ignore


if sys.version_info >= (3, 6):
    import typing

    if typing.TYPE_CHECKING:
        from ansible.module_utils.basic import AnsibleModule  # pragma: no cover


class NetworkError(Exception):
    pass


@add_metaclass(abc.ABCMeta)
class HTTPHelper(object):
    @abc.abstractmethod
    def fetch_url(
        self,
        url,  # type: str
        method='GET',  # type: str
        headers=None,  # type: dict[str, str] | None
        data=None,  # type: bytes | None
        timeout=None,  # type: int | None
    ):  # type: (...) -> tuple[bytes | None, dict[str, typing.Any]]
        """
        Execute a HTTP request and return a tuple (response_content, info).

        In case of errors, either raise NetworkError or terminate the program (for modules only!).
        """


class ModuleHTTPHelper(HTTPHelper):
    def __init__(
        self,
        module,  # type: AnsibleModule
    ):  # type: (...) -> None
        self.module = module  # type: AnsibleModule

    def fetch_url(
        self,
        url,  # type: str
        method='GET',  # type: str
        headers=None,  # type: dict[str, str] | None
        data=None,  # type: bytes | None
        timeout=None,  # type: int | None
    ):  # type: (...) -> tuple[bytes | None, dict[str, typing.Any]]
        response, info = fetch_url(self.module, url, method=method, headers=headers, data=data, timeout=timeout)
        try:
            # In Python 2, reading from a closed response yields a TypeError.
            # In Python 3, read() simply returns ''
            if sys.version_info[0] > 2 and response.closed:
                raise TypeError
            content = response.read()
        except (AttributeError, TypeError):
            content = info.pop('body', None)
        return content, info


class OpenURLHelper(HTTPHelper):
    def fetch_url(
        self,
        url,  # type: str
        method='GET',  # type: str
        headers=None,  # type: dict[str, str] | None
        data=None,  # type: bytes | None
        timeout=None,  # type: int | None
    ):  # type: (...) -> tuple[bytes | None, dict[str, typing.Any]]
        info = {}
        try:
            req = open_url(url, method=method, headers=headers, data=data, timeout=timeout)
            result = req.read()
            info.update({k.lower(): v for k, v in req.info().items()})
            info['status'] = req.code
            info['url'] = req.geturl()
            req.close()
        except HTTPError as e:
            try:
                result = e.read()
            except AttributeError:
                result = ''
            try:
                info.update({k.lower(): v for k, v in e.info().items()})
            except Exception:  # pragma: no cover
                pass  # pragma: no cover
            info['status'] = e.code
        except NoSSLError as e:
            raise NetworkError('Cannot connect via SSL: {0}'.format(to_native(e)))
        except (ConnectionError, ValueError) as e:
            raise NetworkError('Connection error: {0}'.format(to_native(e)))

        return result, info
