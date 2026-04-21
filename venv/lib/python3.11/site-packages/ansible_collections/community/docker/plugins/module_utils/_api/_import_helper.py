# -*- coding: utf-8 -*-
# This code is part of the Ansible collection community.docker, but is an independent component.
# This particular file, and this file only, is based on the Docker SDK for Python (https://github.com/docker/docker-py/)
#
# Copyright (c) 2016-2022 Docker, Inc.
#
# It is licensed under the Apache 2.0 license (see LICENSES/Apache-2.0.txt in this collection)
# SPDX-License-Identifier: Apache-2.0

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import traceback

from ansible_collections.community.docker.plugins.module_utils._six import PY2


REQUESTS_IMPORT_ERROR = None
URLLIB3_IMPORT_ERROR = None
BACKPORTS_SSL_MATCH_HOSTNAME_IMPORT_ERROR = None


try:
    from requests import Session  # noqa: F401, pylint: disable=unused-import
    from requests.adapters import HTTPAdapter  # noqa: F401, pylint: disable=unused-import
    from requests.exceptions import HTTPError, InvalidSchema  # noqa: F401, pylint: disable=unused-import
except ImportError:
    REQUESTS_IMPORT_ERROR = traceback.format_exc()

    class Session(object):
        __attrs__ = []

    class HTTPAdapter(object):
        __attrs__ = []

    class HTTPError(Exception):
        pass

    class InvalidSchema(Exception):
        pass


try:
    from requests.packages import urllib3
    from requests.packages.urllib3 import connection as urllib3_connection  # pylint: disable=unused-import
except ImportError:
    try:
        import urllib3
        from urllib3 import connection as urllib3_connection  # pylint: disable=unused-import
    except ImportError:
        URLLIB3_IMPORT_ERROR = traceback.format_exc()

        class _HTTPConnectionPool(object):
            pass

        class _HTTPConnection(object):
            pass

        class FakeURLLIB3(object):
            def __init__(self):
                self._collections = self
                self.poolmanager = self
                self.connection = self
                self.connectionpool = self

                self.RecentlyUsedContainer = object()
                self.PoolManager = object()
                self.match_hostname = object()
                self.HTTPConnectionPool = _HTTPConnectionPool

        class FakeURLLIB3Connection(object):
            def __init__(self):
                self.HTTPConnection = _HTTPConnection

        urllib3 = FakeURLLIB3()
        urllib3_connection = FakeURLLIB3Connection()


# Monkey-patching match_hostname with a version that supports
# IP-address checking. Not necessary for Python 3.5 and above
if PY2:
    try:
        from backports.ssl_match_hostname import match_hostname
        urllib3.connection.match_hostname = match_hostname
    except ImportError:
        BACKPORTS_SSL_MATCH_HOSTNAME_IMPORT_ERROR = traceback.format_exc()


def fail_on_missing_imports():
    if REQUESTS_IMPORT_ERROR is not None:
        from .errors import MissingRequirementException

        raise MissingRequirementException(
            'You have to install requests',
            'requests', REQUESTS_IMPORT_ERROR)
    if URLLIB3_IMPORT_ERROR is not None:
        from .errors import MissingRequirementException

        raise MissingRequirementException(
            'You have to install urllib3',
            'urllib3', URLLIB3_IMPORT_ERROR)
    if BACKPORTS_SSL_MATCH_HOSTNAME_IMPORT_ERROR is not None:
        from .errors import MissingRequirementException

        raise MissingRequirementException(
            'You have to install backports.ssl-match-hostname',
            'backports.ssl-match-hostname', BACKPORTS_SSL_MATCH_HOSTNAME_IMPORT_ERROR)
