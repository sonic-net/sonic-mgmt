#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Martin Chmielewski (@M4rt1nCh)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: vault_database_role_read
version_added: 6.2.0
author:
  - Martin Chmielewski (@M4rt1nCh)
short_description: Queries a dynamic role definition
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - L(Queries a role definition,L(reads a static role,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/database.html#read-a-role),
    identified by its O(role_name).
notes:
  - This module always reports C(changed) as False as it is a read operation that doesn't modify data.
  - Use C(changed_when) to control that in cases where the operation is known to not change state.
extends_documentation_fragment:
  - community.hashi_vault.attributes
  - community.hashi_vault.attributes.action_group
  - community.hashi_vault.attributes.check_mode_read_only
  - community.hashi_vault.connection
  - community.hashi_vault.auth
  - community.hashi_vault.engine_mount
options:
  role_name:
    description: The role name to be read from Hashicorp Vault.
    type: str
    required: True
"""

EXAMPLES = r"""
- name: Read Role with a default mount point
  community.hashi_vault.vault_database_role_read:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    role_name: SomeRole
  register: result

- name: Display the result of the operation
  ansible.builtin.debug:
    msg: "{{ result }}"

- name: Read Static Role with a custom moint point
  community.hashi_vault.vault_database_role_read:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: db1
    role_name: SomeRole
  register: result

- name: Display the result of the operation
  ansible.builtin.debug:
    msg: "{{ result }}"

"""

RETURN = r"""
data: &data
  description: The C(data) field of raw result. This can also be accessed via RV(raw.data).
  returned: success
  type: dict
  sample: &data_sample
    creation_statements: [
      "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
      "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
    ]
    credential_type: "password"
    db_name: "database"
    default_ttl: 3600
    max_ttl: 86400
    renew_statements: []
    revocation_statements: []
    rollback_statements: []
raw:
  description: The raw result of the operation.
  returned: success
  type: dict
  contains:
    data: *data
  sample:
    auth: null
    data: *data_sample
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
        role_name=dict(type="str", required=True),
    )

    module = HashiVaultModule(argument_spec=argspec, supports_check_mode=True)

    parameters = {}
    engine_mount_point = module.params.get("engine_mount_point", None)
    if engine_mount_point is not None:
        parameters["mount_point"] = engine_mount_point
    parameters["name"] = module.params.get("role_name")

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
        raw = client.secrets.database.read_role(**parameters)
    except hvac_exceptions.Forbidden as e:
        module.fail_json(
            msg="Forbidden: Permission Denied to path ['%s']." % engine_mount_point
            or "database",
            exception=traceback.format_exc(),
        )
    except hvac_exceptions.InvalidPath as e:
        module.fail_json(
            msg="Invalid or missing path ['%s/roles/%s']."
            % (engine_mount_point or "database", parameters["name"]),
            exception=traceback.format_exc(),
        )

    data = raw["data"]

    module.exit_json(data=data, raw=raw, changed=False)


def main():
    run_module()


if __name__ == "__main__":
    main()
