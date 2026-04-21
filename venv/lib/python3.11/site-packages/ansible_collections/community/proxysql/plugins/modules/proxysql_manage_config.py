#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: proxysql_manage_config

author: "Ben Mildren (@bmildren)"
short_description: Writes the proxysql configuration settings between layers
description:
   - The M(community.proxysql.proxysql_global_variables) module writes the proxysql configuration
     settings between layers. Currently this module will always report a
     changed state, so should typically be used with WHEN however this will
     change in a future version when the CHECKSUM table commands are available
     for all tables in proxysql.
options:
  action:
    description:
      - The supplied I(action) combines with the supplied I(direction) to
        provide the semantics of how we want to move the I(config_settings)
        between the I(config_layers).
    type: str
    choices: [ "LOAD", "SAVE" ]
    required: true
  config_settings:
    description:
      - The I(config_settings) specifies which configuration we're writing.
    type: str
    choices: [ "MYSQL USERS", "MYSQL SERVERS", "MYSQL QUERY RULES",
               "MYSQL VARIABLES", "ADMIN VARIABLES", "SCHEDULER" ]
    required: true
  direction:
    description:
      - FROM - denotes we're reading values FROM the supplied I(config_layer)
               and writing to the next layer.
        TO - denotes we're reading from the previous layer and writing TO the
             supplied I(config_layer)."
    type: str
    choices: [ "FROM", "TO" ]
    required: true
  config_layer:
    description:
      - RUNTIME - represents the in-memory data structures of ProxySQL used by
                  the threads that are handling the requests.
        MEMORY - (sometimes also referred as main) represents the in-memory
                  SQLite3 database.
        DISK - represents the on-disk SQLite3 database.
        CONFIG - is the classical config file. You can only LOAD FROM the
                 config file.
    type: str
    choices: [ "MEMORY", "DISK", "RUNTIME", "CONFIG" ]
    required: true
extends_documentation_fragment:
- community.proxysql.proxysql.connectivity
notes:
- Supports C(check_mode).
'''

EXAMPLES = '''
---
# This example saves the mysql users config from memory to disk. It uses
# supplied credentials to connect to the proxysql admin interface.

- name: Save the mysql users config from memory to disk
  community.proxysql.proxysql_manage_config:
    login_user: 'admin'
    login_password: 'admin'
    action: "SAVE"
    config_settings: "MYSQL USERS"
    direction: "FROM"
    config_layer: "MEMORY"

# This example loads the mysql query rules config from memory to runtime. It
# uses supplied credentials to connect to the proxysql admin interface.

- name: Load the mysql query rules config from memory to runtime
  community.proxysql.proxysql_manage_config:
    config_file: '~/proxysql.cnf'
    action: "LOAD"
    config_settings: "MYSQL QUERY RULES"
    direction: "TO"
    config_layer: "RUNTIME"
'''

RETURN = '''
stdout:
    description: Simply reports whether the action reported a change.
    returned: Currently the returned value with always be changed=True.
    type: dict
    "sample": {
        "changed": true
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxysql.plugins.module_utils.mysql import (
    mysql_connect,
    mysql_driver,
    proxysql_common_argument_spec
)
from ansible.module_utils._text import to_native

# ===========================================
# proxysql module specific support methods.
#


def perform_checks(module):
    if module.params["config_layer"] == 'CONFIG' and \
            (module.params["action"] != 'LOAD' or
             module.params["direction"] != 'FROM'):

        if (module.params["action"] != 'LOAD' and
                module.params["direction"] != 'FROM'):
            msg_string = ("Neither the action \"%s\" nor the direction" +
                          " \"%s\" are valid combination with the CONFIG" +
                          " config_layer")
            module.fail_json(msg=msg_string % (module.params["action"],
                                               module.params["direction"]))

        elif module.params["action"] != 'LOAD':
            msg_string = ("The action \"%s\" is not a valid combination" +
                          " with the CONFIG config_layer")
            module.fail_json(msg=msg_string % module.params["action"])

        else:
            msg_string = ("The direction \"%s\" is not a valid combination" +
                          " with the CONFIG config_layer")
            module.fail_json(msg=msg_string % module.params["direction"])


def manage_config(manage_config_settings, cursor, check_mode):

    if not check_mode:
        query_string = "%s" % ' '.join(manage_config_settings)
        cursor.execute(query_string)

    return True

# ===========================================
# Module execution.
#


def main():
    argument_spec = proxysql_common_argument_spec()
    argument_spec.update(
        action=dict(required=True, choices=['LOAD',
                                            'SAVE']),
        config_settings=dict(required=True, choices=['MYSQL USERS',
                                                     'MYSQL SERVERS',
                                                     'MYSQL QUERY RULES',
                                                     'MYSQL VARIABLES',
                                                     'ADMIN VARIABLES',
                                                     'SCHEDULER']),
        direction=dict(required=True, choices=['FROM',
                                               'TO']),
        config_layer=dict(required=True, choices=['MEMORY',
                                                  'DISK',
                                                  'RUNTIME',
                                                  'CONFIG'])
    )

    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=argument_spec
    )

    perform_checks(module)

    login_user = module.params["login_user"]
    login_password = module.params["login_password"]
    config_file = module.params["config_file"]
    action = module.params["action"]
    config_settings = module.params["config_settings"]
    direction = module.params["direction"]
    config_layer = module.params["config_layer"]

    cursor = None
    try:
        cursor, db_conn, version = mysql_connect(module,
                                                 login_user,
                                                 login_password,
                                                 config_file)
    except mysql_driver.Error as e:
        module.fail_json(
            msg="unable to connect to ProxySQL Admin Module.. %s" % to_native(e)
        )

    result = {}

    manage_config_settings = \
        [action, config_settings, direction, config_layer]

    try:
        result['changed'] = manage_config(manage_config_settings,
                                          cursor, module.check_mode)
    except mysql_driver.Error as e:
        module.fail_json(
            msg="unable to manage config.. %s" % to_native(e)
        )

    module.exit_json(**result)


if __name__ == '__main__':
    main()
