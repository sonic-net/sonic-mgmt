#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Martin Chmielewski (@M4rt1nCh)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: vault_database_roles_list
version_added: 6.2.0
author:
  - Martin Chmielewski (@M4rt1nCh)
short_description: Returns a list of available (dynamic) roles
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Returns a list of available (dynamic) roles.
notes:
  - This API returns a member named C(keys).
  - In Ansible, accessing RV(data.keys) or RV(raw.data.keys) will not work because the dict object contains a method named C(keys).
  - Instead, use RV(roles) to access the list of roles, or use the syntax C(data["keys"]) or C(raw.data["keys"]) to access the list via dict member.
extends_documentation_fragment:
  - community.hashi_vault.attributes
  - community.hashi_vault.attributes.action_group
  - community.hashi_vault.attributes.check_mode_read_only
  - community.hashi_vault.connection
  - community.hashi_vault.auth
  - community.hashi_vault.engine_mount
"""

EXAMPLES = r"""
- name: List all roles with the default mount point
  community.hashi_vault.vault_database_roles_list:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
  register: result

- name: Display the result of the operation
  ansible.builtin.debug:
    msg: "{{ result }}"

- name: List all roles with a custom mount point
  community.hashi_vault.vault_database_roles_list:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: db1
  register: result

- name: Display the result of the operation
  ansible.builtin.debug:
    msg: "{{ result }}"
"""

RETURN = r"""
data:
  description: The C(data) field of raw result. This can also be accessed via RV(raw.data).
  returned: success
  type: dict
  contains: &data_contains
    keys:
      description: The list of dynamic role names.
      returned: success
      type: list
      elements: str
      sample: &sample_roles ["dyn_role1", "dyn_role2", "dyn_role3"]
  sample:
    keys: *sample_roles
roles:
  description: The list of dynamic roles or en empty list. This can also be accessed via RV(data.keys) or RV(raw.data.keys).
  returned: success
  type: list
  elements: str
  sample: *sample_roles
raw:
  description: The raw result of the operation.
  returned: success
  type: dict
  contains:
    data:
      description: The data field of the API response.
      returned: success
      type: dict
      contains: *data_contains
  sample:
    auth: null
    data:
      keys: *sample_roles
    username: "SomeUser"
    lease_duration": 0
    lease_id: ""
    renewable: false
    request_id: "123456"
    warnings: null
    wrap_info: null
"""

import traceback

from ansible.module_utils.common.text.converters import to_text

from ..module_utils._hashi_vault_module import HashiVaultModule
from ..module_utils._hashi_vault_common import HashiVaultValueError


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        engine_mount_point=dict(type="str", required=False),
    )

    module = HashiVaultModule(argument_spec=argspec, supports_check_mode=True)

    parameters = {}
    engine_mount_point = module.params.get("engine_mount_point", None)
    if engine_mount_point is not None:
        parameters["mount_point"] = engine_mount_point

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
        raw = client.secrets.database.list_roles(**parameters)
    except hvac_exceptions.Forbidden as e:
        module.fail_json(
            msg="Forbidden: Permission Denied to path ['%s']." % engine_mount_point
            or "database",
            exception=traceback.format_exc(),
        )
    except hvac_exceptions.InvalidPath as e:
        module.fail_json(
            msg="Invalid or missing path ['%s/roles']."
            % (engine_mount_point or "database"),
            exception=traceback.format_exc(),
        )

    data = raw.get("data", {"keys": []})
    roles = data["keys"]

    module.exit_json(data=data, roles=roles, raw=raw, changed=False)


def main():
    run_module()


if __name__ == "__main__":
    main()
