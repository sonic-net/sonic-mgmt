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

""" Resolves OpenSSL issues in some servers:
      https://lukasa.co.uk/2013/01/Choosing_SSL_Version_In_Requests/
      https://github.com/kennethreitz/requests/pull/799
"""

from ansible_collections.community.docker.plugins.module_utils.version import LooseVersion

from .._import_helper import HTTPAdapter, urllib3
from .basehttpadapter import BaseHTTPAdapter


PoolManager = urllib3.poolmanager.PoolManager


class SSLHTTPAdapter(BaseHTTPAdapter):
    '''An HTTPS Transport Adapter that uses an arbitrary SSL version.'''

    __attrs__ = HTTPAdapter.__attrs__ + ['assert_hostname', 'ssl_version']

    def __init__(self, ssl_version=None, assert_hostname=None, **kwargs):
        self.ssl_version = ssl_version
        self.assert_hostname = assert_hostname
        super(SSLHTTPAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        kwargs = {
            'num_pools': connections,
            'maxsize': maxsize,
            'block': block,
        }
        if self.assert_hostname is not None:
            kwargs['assert_hostname'] = self.assert_hostname
        if self.ssl_version and self.can_override_ssl_version():
            kwargs['ssl_version'] = self.ssl_version

        self.poolmanager = PoolManager(**kwargs)

    def get_connection(self, *args, **kwargs):
        """
        Ensure assert_hostname is set correctly on our pool

        We already take care of a normal poolmanager via init_poolmanager

        But we still need to take care of when there is a proxy poolmanager
        """
        conn = super(SSLHTTPAdapter, self).get_connection(*args, **kwargs)
        if self.assert_hostname is not None and conn.assert_hostname != self.assert_hostname:
            conn.assert_hostname = self.assert_hostname
        return conn

    def can_override_ssl_version(self):
        urllib_ver = urllib3.__version__.split('-')[0]
        if urllib_ver is None:
            return False
        if urllib_ver == 'dev':
            return True
        return LooseVersion(urllib_ver) > LooseVersion('1.5')
