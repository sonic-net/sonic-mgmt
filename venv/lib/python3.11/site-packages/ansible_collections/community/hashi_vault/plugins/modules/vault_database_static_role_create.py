#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Martin Chmielewski (@M4rt1nCh)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: vault_database_static_role_create
version_added: 6.2.0
author:
  - Martin Chmielewski (@M4rt1nCh)
short_description: Create or update a static role
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - L(Creates a new or updates an existing static role,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/database.html#create-static-role).
notes:
  - This module always reports C(changed) status because it cannot guarantee idempotence.
  - Use C(changed_when) to control that in cases where the operation is known to not change state.
attributes:
  check_mode:
    support: partial
    details:
      - In check mode, a sample response will be returned, but the role creation will not be performed in Hashicorp Vault.
extends_documentation_fragment:
  - community.hashi_vault.attributes
  - community.hashi_vault.attributes.action_group
  - community.hashi_vault.connection
  - community.hashi_vault.auth
  - community.hashi_vault.engine_mount
options:
  connection_name:
    description: The connection name under which the role should be created.
    type: str
    required: True
  role_name:
    description: The name of the role that should be created.
    type: str
    required: True
  db_username:
    description: The database username - Note that the user must exist in the target database!
    type: str
    required: True
  rotation_statements:
    description: SQL statements to rotate the password for the given O(db_username)
    type: list
    required: True
    elements: str
  rotation_period:
    description: Password rotation period in seconds (defaults to 24hs)
    type: int
    required: False
    default: 86400
"""

EXAMPLES = r"""
- name: Generate rotation statement
  ansible.builtin.set_fact:
    rotation_statements = ["ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]

- name: Create / update Static Role with the default mount point
  community.hashi_vault.vault_database_static_role_create:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    connection_name: SomeConnection
    role_name: SomeRole
    db_username: '{{ db_username}}'
    rotation_statements: '{{ rotation_statements }}'
  register: response

- name: Display the result of the operation
  ansible.builtin.debug:
    msg: "{{ result }}"

- name: Create / update Static Role with a custom mount point
  community.hashi_vault.vault_database_static_role_create:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: db1
    connection_name: SomeConnection
    role_name: SomeRole
    db_username: '{{ db_username}}'
    rotation_statements: '{{ rotation_statements }}'
  register: response

- name: Display the result of the operation
  ansible.builtin.debug:
    msg: "{{ result }}"
"""

RETURN = r""""""

import traceback

from ansible.module_utils.common.text.converters import to_text

from ..module_utils._hashi_vault_module import HashiVaultModule
from ..module_utils._hashi_vault_common import HashiVaultValueError


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        engine_mount_point=dict(type="str", required=False),
        connection_name=dict(type="str", required=True),
        role_name=dict(type="str", required=True),
        db_username=dict(type="str", required=True),
        rotation_statements=dict(type="list", required=True, elements="str"),
        rotation_period=dict(type="int", required=False, default=86400),
    )

    module = HashiVaultModule(argument_spec=argspec, supports_check_mode=True)

    if module.check_mode is True:
        module.exit_json(changed=True)

    parameters = {}
    engine_mount_point = module.params.get("engine_mount_point", None)
    if engine_mount_point is not None:
        parameters["mount_point"] = engine_mount_point
    parameters["db_name"] = module.params.get("connection_name")
    parameters["name"] = module.params.get("role_name")
    parameters["username"] = module.params.get("db_username")
    parameters["rotation_statements"] = module.params.get("rotation_statements")
    rotation_period = module.params.get("rotation_period", None)
    parameters["rotation_period"] = rotation_period

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
        client.secrets.database.create_static_role(**parameters)
    except hvac_exceptions.Forbidden as e:
        module.fail_json(
            msg="Forbidden: Permission Denied to path ['%s']." % engine_mount_point
            or "database",
            exception=traceback.format_exc(),
        )
    except hvac_exceptions.InvalidPath as e:
        module.fail_json(
            msg="Invalid or missing path ['%s/static-roles/%s']."
            % (engine_mount_point or "database", parameters["name"]),
            exception=traceback.format_exc(),
        )
    except hvac_exceptions.InvalidRequest as e:
        module.fail_json(
            msg="Cannot update static role ['%s/static-roles/%s']. Please verify that the user exists on the database."
            % (engine_mount_point or "database", parameters["name"]),
            exception=traceback.format_exc(),
        )
    else:
        module.exit_json(changed=True)


def main():
    run_module()


if __name__ == "__main__":
    main()
