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

from .._import_helper import HTTPAdapter as _HTTPAdapter


class BaseHTTPAdapter(_HTTPAdapter):
    def close(self):
        super(BaseHTTPAdapter, self).close()
        if hasattr(self, 'pools'):
            self.pools.clear()

    # Hotfix for requests 2.32.0 and 2.32.1: its commit
    # https://github.com/psf/requests/commit/c0813a2d910ea6b4f8438b91d315b8d181302356
    # changes requests.adapters.HTTPAdapter to no longer call get_connection() from
    # send(), but instead call _get_connection().
    def _get_connection(self, request, *args, **kwargs):
        return self.get_connection(request.url, kwargs.get('proxies'))

    # Fix for requests 2.32.2+:
    # https://github.com/psf/requests/commit/c98e4d133ef29c46a9b68cd783087218a8075e05
    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        return self.get_connection(request.url, proxies)
