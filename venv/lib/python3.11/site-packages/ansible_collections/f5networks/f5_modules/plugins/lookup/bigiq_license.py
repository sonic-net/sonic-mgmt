# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: bigiq_license
    author:
      - Wojciech Wypior (@wojtek0806)
    version_added: "1.0.0"
    short_description: Select a random license key from a pool of biqiq available licenses
    description:
      - Select a random license key from a pool of biqiq available licenses.
      - Requires specifying BIGIQ license pool name and connection parameters.
"""

EXAMPLES = """
- name: Get a regkey license from a license pool
  bigiq_regkey_license:
    key: "{{ lookup('f5networks.f5_modules.bigiq_license', pool_name='foo_pool', username=baz, password=bar, host=192.168.1.1, port=10443}}"
    state: present
    pool: foo_pool

- name: Get a regkey license from a license pool, use default credentials and port, disable SSL verification
  bigiq_regkey_license:
    key: "{{ lookup('f5networks.f5_modules.bigiq_license', pool_name='foo_pool', host=192.168.1.1, validate_certs=false}}"
    state: present
    pool: foo_pool
"""

RETURN = """
  _raw:
    description:
      - random item
"""

import random

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible_collections.f5networks.f5_modules.plugins.module_utils.bigiq import F5RestClient


class LookupModule(LookupBase):
    def __init__(self, loader=None, templar=None, **kwargs):
        super(LookupModule, self).__init__(loader, templar, **kwargs)
        self.username = None
        self.password = None
        self.validate_certs = False
        self.host = None
        self.pool_name = None
        self.port = 443
        self.client = None
        self.params = None

    def _validate_and_merge_params(self, **kwargs):
        self.username = kwargs.pop('username', 'admin')
        self.password = kwargs.pop('password', 'admin')
        self.validate_certs = kwargs.pop('validate_certs', False)
        self.host = kwargs.pop('host', None)
        self.port = kwargs.pop('port', 443)
        self.pool_name = kwargs.pop('pool_name', None)

        if self.host is None:
            raise AnsibleError('A valid hostname or IP for BIGIQ needs to be provided')
        if self.pool_name is None:
            raise AnsibleError('License pool name needs to be specified')
        self.params = dict(
            provider=dict(
                server=self.host,
                server_port=self.port,
                validate_certs=self.validate_certs,
                user=self.username,
                password=self.password
            )
        )

    def _get_pool_uuid(self):
        uri = "https://{0}:{1}/mgmt/cm/device/licensing/pool/regkey/licenses".format(self.host, self.port)
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise AnsibleError(str(ex))
        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise AnsibleError(response['message'])
            else:
                raise AnsibleError(resp.content)
        if 'items' not in response:
            raise AnsibleError('No license pools configured on BIGIQ')

        resource = next((x for x in response['items'] if x['name'] == self.pool_name), None)
        if resource is None:
            raise AnsibleError("Could not find the specified license pool.")
        return resource['id']

    def _get_registation_keys(self, pool_id):
        uri = 'https://{0}:{1}/mgmt/cm/device/licensing/pool/regkey/licenses/{2}/offerings/'.format(
            self.host,
            self.port,
            pool_id,
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise AnsibleError(str(ex))
        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise AnsibleError(response['message'])
            else:
                raise AnsibleError(resp.content)
        regkeys = [x['regKey'] for x in response['items']]

        if not regkeys:
            raise AnsibleError('Failed to obtain registration keys')

        return regkeys

    def run(self, terms, variables=None, **kwargs):
        self._validate_and_merge_params(**kwargs)
        self.client = F5RestClient(**self.params)
        pool_id = self._get_pool_uuid()
        regkeys = self._get_registation_keys(pool_id)
        keys = []
        regkeypool = []
        for key in regkeys:
            uri = 'https://{0}:{1}/mgmt/cm/device/licensing/pool/regkey/licenses/{2}/offerings/{3}/members'.format(
                self.host,
                self.port,
                pool_id,
                key
            )
            resp = self.client.api.get(uri)
            try:
                response = resp.json()
            except ValueError as ex:
                raise AnsibleError(str(ex))

            if 'code' in response and response['code'] == 400:
                if 'message' in response:
                    raise AnsibleError(response['message'])
                else:
                    raise AnsibleError(resp.content)

            if not response['items']:
                keys.append(key)

        result = random.choice(keys)
        regkeypool.append(result)
        return regkeypool
