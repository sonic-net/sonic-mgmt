#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Martin Chmielewski (@M4rt1nCh)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: vault_database_connection_configure
version_added: 6.2.0
author:
  - Martin Chmielewski (@M4rt1nCh)
short_description: Configures the database engine
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Creates a L(new database connection for a database secrets engine,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/database.html#configuration),
    identified by its O(engine_mount_point) in HashiCorp Vault.
notes:
  - The database needs to be created and available to connect before you can configure the database secrets engine using the above configure method.
  - This module always reports C(changed) status because it cannot guarantee idempotence.
  - Use C(changed_when) to control that in cases where the operation is known to not change state.
attributes:
  check_mode:
    support: partial
    details:
      - In check mode, a sample response will be returned, but the create / update will not be performed in Hashicorp Vault.
extends_documentation_fragment:
  - community.hashi_vault.attributes
  - community.hashi_vault.attributes.action_group
  - community.hashi_vault.connection
  - community.hashi_vault.auth
  - community.hashi_vault.engine_mount
options:
  connection_name:
    description: Name of the database connection.
    type: str
    required: True
  plugin_name:
    description: Plugin name used to connect to the database
    type: str
    required: True
  allowed_roles:
    description: Allowed roles
    type: list
    elements: str
    required: True
  connection_url:
    description: Connection URL to the database
    type: str
    required: True
  connection_username:
    description: Username to connect to the database
    type: str
    required: True
  connection_password:
    description: Password to connect to the database
    type: str
    required: True
"""

EXAMPLES = r"""
- name: Create a new Database Connection with the default mount point
  community.hashi_vault.vault_database_connection_configure:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    connection_name: MyName
    plugin_name: postgresql-database-plugin
    connection_url: postgresql://{{'{{username}}'}}:{{'{{password}}'}}@postgres:5432/postgres?sslmode=disable
    connection_username: SomeUser
    connection_password: SomePass
  register: result

- name: Display the result of the operation
  ansible.builtin.debug:
    msg: "{{ result }}"


- name: Create a new Database Connection with a custom mount point
  community.hashi_vault.vault_database_connection_configure:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: db1
    connection_name: MyName
    plugin_name: postgresql-database-plugin
    connection_url: postgresql://{{'{{username}}'}}:{{'{{password}}'}}@postgres:5432/postgres?sslmode=disable
    connection_username: SomeUser
    connection_password: SomePass
  register: result

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
        plugin_name=dict(type="str", required=True),
        allowed_roles=dict(type="list", required=True, elements="str"),
        connection_name=dict(type="str", required=True),
        connection_url=dict(type="str", required=True),
        connection_username=dict(type="str", required=True),
        connection_password=dict(type="str", required=True, no_log=True),
    )

    module = HashiVaultModule(argument_spec=argspec, supports_check_mode=True)

    if module.check_mode is True:
        module.exit_json(changed=True)

    parameters = {}
    engine_mount_point = module.params.get("engine_mount_point", None)
    if engine_mount_point is not None:
        parameters["mount_point"] = engine_mount_point
    parameters["plugin_name"] = module.params.get("plugin_name")
    parameters["allowed_roles"] = module.params.get("allowed_roles")
    parameters["connection_url"] = module.params.get("connection_url")
    parameters["name"] = module.params.get("connection_name")
    parameters["username"] = module.params.get("connection_username")
    parameters["password"] = module.params.get("connection_password")

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
        client.secrets.database.configure(**parameters)
    except hvac_exceptions.Forbidden as e:
        module.fail_json(
            msg="Forbidden: Permission Denied to path ['%s']." % engine_mount_point
            or "database",
            exception=traceback.format_exc(),
        )
    except hvac_exceptions.InvalidPath as e:
        module.fail_json(
            msg="Invalid or missing path ['%s/config/%s']."
            % (engine_mount_point or "database", parameters["name"]),
            exception=traceback.format_exc(),
        )
    except hvac_exceptions.InvalidRequest as e:
        module.fail_json(
            msg="Error creating database connection ['%s/config/%s']. Please analyze the traceback for further details."
            % (engine_mount_point or "database", parameters["name"]),
            exception=traceback.format_exc(),
        )
    else:
        module.exit_json(changed=True)


def main():
    run_module()


if __name__ == "__main__":
    main()
