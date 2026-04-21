#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
module: vault_kv1_get
version_added: 2.5.0
author:
  - Brian Scholer (@briantist)
short_description: Get a secret from HashiCorp Vault's KV version 1 secret store
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Gets a secret from HashiCorp Vault's KV version 1 secret store.
seealso:
  - ref: community.hashi_vault.vault_kv1_get lookup <ansible_collections.community.hashi_vault.vault_kv1_get_lookup>
    description: The official documentation for the C(community.hashi_vault.vault_kv1_get) lookup plugin.
  - module: community.hashi_vault.vault_kv2_get
  - name: KV1 Secrets Engine
    description: Documentation for the Vault KV secrets engine, version 1.
    link: https://www.vaultproject.io/docs/secrets/kv/kv-v1
extends_documentation_fragment:
  - community.hashi_vault.attributes
  - community.hashi_vault.attributes.action_group
  - community.hashi_vault.attributes.check_mode_read_only
  - community.hashi_vault.connection
  - community.hashi_vault.auth
  - community.hashi_vault.engine_mount
options:
  engine_mount_point:
    default: kv
  path:
    description:
      - Vault KV path to be read.
      - This is relative to the I(engine_mount_point), so the mount path should not be included.
    type: str
    required: True
'''

EXAMPLES = r'''
- name: Read a kv1 secret from Vault via the remote host with userpass auth
  community.hashi_vault.vault_kv1_get:
    url: https://vault:8201
    path: hello
    auth_method: userpass
    username: user
    password: '{{ passwd }}'
  register: response
  # equivalent API path is kv/hello

- name: Display the results
  ansible.builtin.debug:
    msg:
      - "Secret: {{ response.secret }}"
      - "Data: {{ response.data }} (same as secret in kv1)"
      - "Metadata: {{ response.metadata }} (response info in kv1)"
      - "Full response: {{ response.raw }}"
      - "Value of key 'password' in the secret: {{ response.secret.password }}"

- name: Read a secret from kv1 with a different mount via the remote host
  community.hashi_vault.vault_kv1_get:
    url: https://vault:8201
    engine_mount_point: custom/kv1/mount
    path: hello
  register: response
  # equivalent API path is custom/kv1/mount/hello

- name: Display the results
  ansible.builtin.debug:
    msg:
      - "Secret: {{ response.secret }}"
      - "Data: {{ response.data }} (same as secret in kv1)"
      - "Metadata: {{ response.metadata }} (response info in kv1)"
      - "Full response: {{ response.raw }}"
'''

RETURN = r'''
raw:
  description: The raw result of the read against the given path.
  returned: success
  type: dict
  sample:
    auth: null
    data:
      Key1: value1
      Key2: value2
    lease_duration: 2764800
    lease_id: ""
    renewable: false
    request_id: e99f145f-f02a-7073-1229-e3f191057a70
    warnings: null
    wrap_info: null
data:
  description: The C(data) field of raw result. This can also be accessed via C(raw.data).
  returned: success
  type: dict
  sample:
    Key1: value1
    Key2: value2
secret:
  description: The C(data) field of the raw result. This is identical to C(data) in the return values.
  returned: success
  type: dict
  sample:
    Key1: value1
    Key2: value2
metadata:
  description: This is a synthetic result. It is the same as C(raw) with C(data) removed.
  returned: success
  type: dict
  sample:
    auth: null
    lease_duration: 2764800
    lease_id: ""
    renewable: false
    request_id: e99f145f-f02a-7073-1229-e3f191057a70
    warnings: null
    wrap_info: null
'''

import traceback

from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        engine_mount_point=dict(type='str', default='kv'),
        path=dict(type='str', required=True),
    )

    module = HashiVaultModule(
        argument_spec=argspec,
        supports_check_mode=True
    )

    engine_mount_point = module.params.get('engine_mount_point')
    path = module.params.get('path')

    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)
    hvac_exceptions = module.helper.get_hvac().exceptions

    try:
        module.authenticator.validate()
        module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_text(e), exception=traceback.format_exc())

    try:
        raw = client.secrets.kv.v1.read_secret(path=path, mount_point=engine_mount_point)
    except hvac_exceptions.Forbidden as e:
        module.fail_json(msg="Forbidden: Permission Denied to path ['%s']." % path, exception=traceback.format_exc())
    except hvac_exceptions.InvalidPath as e:
        if 'Invalid path for a versioned K/V secrets engine' in to_text(e):
            msg = "Invalid path for a versioned K/V secrets engine ['%s']. If this is a KV version 2 path, use community.hashi_vault.vault_kv2_get."
        else:
            msg = "Invalid or missing path ['%s']."

        module.fail_json(msg=msg % (path,), exception=traceback.format_exc())

    metadata = raw.copy()
    data = metadata.pop('data')
    module.exit_json(raw=raw, data=data, secret=data, metadata=metadata)


def main():
    run_module()


if __name__ == '__main__':
    main()
