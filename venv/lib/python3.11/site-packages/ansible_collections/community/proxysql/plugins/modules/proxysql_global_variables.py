#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: proxysql_global_variables
author: "Ben Mildren (@bmildren)"
short_description: Gets or sets the proxysql global variables
description:
   - The M(community.proxysql.proxysql_global_variables) module gets or sets the proxysql global
     variables.
options:
  variable:
    description:
      - Defines which variable should be returned, or if I(value) is specified
        which variable should be updated.
    type: str
    required: true
  value:
    description:
      - Defines a value the variable specified using I(variable) should be set
        to.
    type: str
extends_documentation_fragment:
- community.proxysql.proxysql.managing_config
- community.proxysql.proxysql.connectivity
notes:
- Supports C(check_mode).
'''

EXAMPLES = '''
---
# This example sets the value of a variable, saves the mysql admin variables
# config to disk, and dynamically loads the mysql admin variables config to
# runtime. It uses supplied credentials to connect to the proxysql admin
# interface.

- name: Set the value of a variable
  community.proxysql.proxysql_global_variables:
    login_user: 'admin'
    login_password: 'admin'
    variable: 'mysql-max_connections'
    value: 4096

# This example gets the value of a variable.  It uses credentials in a
# supplied config file to connect to the proxysql admin interface.

- name: Get the value of a variable
  community.proxysql.proxysql_global_variables:
    config_file: '~/proxysql.cnf'
    variable: 'mysql-default_query_delay'
'''

RETURN = '''
stdout:
    description: Returns the mysql variable supplied with it's associated value.
    returned: Returns the current variable and value, or the newly set value
              for the variable supplied..
    type: dict
    "sample": {
        "changed": false,
        "msg": "The variable is already been set to the supplied value",
        "var": {
            "variable_name": "mysql-poll_timeout",
            "variable_value": "3000"
        }
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxysql.plugins.module_utils.mysql import (
    mysql_connect,
    mysql_driver,
    proxysql_common_argument_spec,
    save_config_to_disk,
    load_config_to_runtime,
)
from ansible.module_utils._text import to_native

# ===========================================
# proxysql module specific support methods.
#


def check_config(variable, value, cursor):
    query_string = \
        """SELECT count(*) AS `variable_count`
           FROM global_variables
           WHERE variable_name = %s and variable_value = %s"""

    query_data = \
        [variable, value]

    cursor.execute(query_string, query_data)
    check_count = cursor.fetchone()

    if isinstance(check_count, tuple):
        return int(check_count[0]) > 0

    return (int(check_count['variable_count']) > 0)


def get_config(variable, cursor):

    query_string = \
        """SELECT *
           FROM global_variables
           WHERE variable_name = %s"""

    query_data = \
        [variable, ]

    cursor.execute(query_string, query_data)
    row_count = cursor.rowcount
    resultset = cursor.fetchone()

    if row_count > 0:
        return resultset
    else:
        return False


def set_config(variable, value, cursor):

    query_string = \
        """UPDATE global_variables
           SET variable_value = %s
           WHERE variable_name = %s"""

    query_data = \
        [value, variable]

    cursor.execute(query_string, query_data)
    return True


def manage_config(variable, save_to_disk, load_to_runtime, cursor, state):
    if state:
        if save_to_disk:
            save_config_to_disk(cursor, "VARIABLES", variable)
        if load_to_runtime:
            load_config_to_runtime(cursor, "VARIABLES", variable)

# ===========================================
# Module execution.
#


def main():
    argument_spec = proxysql_common_argument_spec()
    argument_spec.update(
        variable=dict(required=True, type='str'),
        value=dict(),
        save_to_disk=dict(default=True, type='bool'),
        load_to_runtime=dict(default=True, type='bool')
    )

    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=argument_spec
    )

    login_user = module.params["login_user"]
    login_password = module.params["login_password"]
    config_file = module.params["config_file"]
    variable = module.params["variable"]
    value = module.params["value"]
    save_to_disk = module.params["save_to_disk"]
    load_to_runtime = module.params["load_to_runtime"]

    cursor = None
    try:
        cursor, db_conn, version = mysql_connect(module,
                                                 login_user,
                                                 login_password,
                                                 config_file,
                                                 cursor_class='DictCursor')
    except mysql_driver.Error as e:
        module.fail_json(
            msg="unable to connect to ProxySQL Admin Module.. %s" % to_native(e)
        )

    result = {}

    if not value:
        try:
            if get_config(variable, cursor):
                result['changed'] = False
                result['msg'] = \
                    "Returned the variable and it's current value"
                result['var'] = get_config(variable, cursor)
            else:
                module.fail_json(
                    msg="The variable \"%s\" was not found" % variable
                )

        except mysql_driver.Error as e:
            module.fail_json(
                msg="unable to get config.. %s" % to_native(e)
            )
    else:
        try:
            if get_config(variable, cursor):
                if not check_config(variable, value, cursor):
                    if not module.check_mode:
                        result['changed'] = set_config(variable, value, cursor)
                        result['msg'] = \
                            "Set the variable to the supplied value"
                        result['var'] = get_config(variable, cursor)
                        manage_config(variable,
                                      save_to_disk,
                                      load_to_runtime,
                                      cursor,
                                      result['changed'])
                    else:
                        result['changed'] = True
                        result['msg'] = ("Variable would have been set to" +
                                         " the supplied value, however" +
                                         " check_mode is enabled.")
                else:
                    result['changed'] = False
                    result['msg'] = ("The variable is already been set to" +
                                     " the supplied value")
                    result['var'] = get_config(variable, cursor)
            else:
                module.fail_json(
                    msg="The variable \"%s\" was not found" % variable
                )

        except mysql_driver.Error as e:
            module.fail_json(
                msg="unable to set config.. %s" % to_native(e)
            )

    module.exit_json(**result)


if __name__ == '__main__':
    main()
