#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2023, Devon Mar (@devon-mar)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: vault_kv2_write
version_added: 4.2.0
author:
  - Devon Mar (@devon-mar)
short_description: Perform a write operation against a KVv2 secret in HashiCorp Vault
description:
  - Perform a write operation against a KVv2 secret in HashiCorp Vault.
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
seealso:
  - module: community.hashi_vault.vault_write
  - module: community.hashi_vault.vault_kv2_get
  - module: community.hashi_vault.vault_kv2_delete
  - ref: community.hashi_vault.vault_write lookup <ansible_collections.community.hashi_vault.vault_write_lookup>
    description: The official documentation for the C(community.hashi_vault.vault_write) lookup plugin.
  - name: KV2 Secrets Engine
    description: Documentation for the Vault KV secrets engine, version 2.
    link: https://www.vaultproject.io/docs/secrets/kv/kv-v2
extends_documentation_fragment:
  - community.hashi_vault.attributes
  - community.hashi_vault.attributes.action_group
  - community.hashi_vault.connection
  - community.hashi_vault.auth
  - community.hashi_vault.engine_mount
attributes:
  check_mode:
    support: partial
    details:
      - If I(read_before_write) is C(true), full check mode functionality is supported.
      - If I(read_before_write) is C(false), the status will always be C(changed) but a write will not be performed in check mode.
options:
  engine_mount_point:
    type: str
    default: secret
  path:
    type: str
    required: true
    description:
      - Vault KVv2 path to be written to.
      - This is relative to the I(engine_mount_point), so the mount path should not be included.
  data:
    type: dict
    required: true
    description:
      - KVv2 secret data to write.
  cas:
    type: int
    description:
      - Perform a check-and-set operation.
  read_before_write:
    type: bool
    default: false
    description:
      - Read the secret first and write only when I(data) differs from the read data.
      - Requires C(read) permission on the secret if C(true).
      - If C(false), this module will always write to I(path) when not in check mode.
"""

EXAMPLES = r"""
- name: Write/create a secret
  community.hashi_vault.vault_kv2_write:
    url: https://vault:8200
    path: hello
    data:
      foo: bar

- name: Create a secret with CAS (the secret must not exist)
  community.hashi_vault.vault_kv2_write:
    url: https://vault:8200
    path: caspath
    cas: 0
    data:
      foo: bar

- name: Update a secret with CAS
  community.hashi_vault.vault_kv2_write:
    url: https://vault:8200
    path: caspath
    cas: 2
    data:
      hello: world

# This module does not have patch capability built in.
# Patching can be achieved with multiple tasks.

- name: Retrieve current secret
  register: current
  community.hashi_vault.vault_kv2_get:
    url: https://vault:8200
    path: hello

## patch without CAS
- name: Update the secret
  vars:
    values_to_update:
      foo: baz
      hello: goodbye
  community.hashi_vault.vault_kv2_write:
    url: https://vault:8200
    path: hello
    data: >-
      {{
        current.secret
        | combine(values_to_update)
      }}

## patch with CAS
- name: Update the secret
  vars:
    values_to_update:
      foo: baz
      hello: goodbye
  community.hashi_vault.vault_kv2_write:
    url: https://vault:8200
    path: hello
    cas: '{{ current.metadata.version | int }}'
    data: >-
      {{
        current.secret
        | combine(values_to_update)
      }}
"""

RETURN = r"""
raw:
  type: dict
  description: The raw Vault response.
  returned: changed
  sample:
    auth:
    data:
      created_time: "2023-02-21T19:51:50.801757862Z"
      custom_metadata:
      deletion_time: ""
      destroyed: false
      version: 1
    lease_duration: 0
    lease_id: ""
    renewable: false
    request_id: 52eb1aa7-5a38-9a02-9246-efc5bf9581ec
    warnings: null
    wrap_info: null
"""

import traceback

from ansible.module_utils.common.text.converters import to_text
from ..module_utils._hashi_vault_module import HashiVaultModule
from ..module_utils._hashi_vault_common import HashiVaultValueError


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        engine_mount_point=dict(type="str", default="secret"),
        path=dict(type="str", required=True),
        data=dict(type="dict", required=True, no_log=True),
        cas=dict(type="int"),
        read_before_write=dict(type="bool", default=False),
    )

    module = HashiVaultModule(
        argument_spec=argspec,
        supports_check_mode=True,
    )

    mount_point = module.params.get("engine_mount_point")
    path = module.params.get("path")
    cas = module.params.get("cas")
    data = module.params.get("data")
    read_before_write = module.params.get("read_before_write")

    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)
    hvac_exceptions = module.helper.get_hvac().exceptions

    try:
        module.authenticator.validate()
        module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_text(e), exception=traceback.format_exc())

    if read_before_write is True:
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=mount_point
            )
            if "data" not in response or "data" not in response["data"]:
                module.fail_json(
                    msg="Vault response did not contain data: %s" % response
                )
            current_data = response["data"]["data"]
        except hvac_exceptions.InvalidPath:
            current_data = {}
        except hvac_exceptions.Forbidden:
            module.fail_json(
                msg="Permission denied reading %s" % path,
                exception=traceback.format_exc(),
            )
        except hvac_exceptions.VaultError:
            module.fail_json(
                msg="VaultError reading %s" % path,
                exception=traceback.format_exc(),
            )
    else:
        current_data = {}

    changed = current_data != data

    if changed is True and module.check_mode is False:
        args = {
            "path": path,
            "secret": data,
            "mount_point": mount_point,
        }
        if cas is not None:
            args["cas"] = cas

        try:
            raw = client.secrets.kv.v2.create_or_update_secret(**args)
        except hvac_exceptions.InvalidRequest:
            module.fail_json(
                msg="InvalidRequest writing to '%s'" % path,
                exception=traceback.format_exc(),
            )
        except hvac_exceptions.InvalidPath:
            module.fail_json(
                msg="InvalidPath writing to '%s'" % path,
                exception=traceback.format_exc(),
            )
        except hvac_exceptions.Forbidden:
            module.fail_json(
                msg="Permission denied writing to '%s'" % path,
                exception=traceback.format_exc(),
            )

        module.exit_json(changed=True, raw=raw)

    module.exit_json(changed=changed)


def main():
    run_module()


if __name__ == "__main__":
    main()
