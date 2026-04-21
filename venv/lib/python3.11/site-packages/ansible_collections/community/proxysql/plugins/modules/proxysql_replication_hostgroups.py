#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: proxysql_replication_hostgroups
author: "Ben Mildren (@bmildren)"
short_description: Manages replication hostgroups using the proxysql admin
                   interface
description:
   - Each row in mysql_replication_hostgroups represent a pair of
     writer_hostgroup and reader_hostgroup. ProxySQL will monitor the value of
     read_only for all the servers in specified hostgroups, and based on the
     value of read_only will assign the server to the writer or reader
     hostgroups.
options:
  writer_hostgroup:
    description:
      - Id of the writer hostgroup.
    type: int
    required: true
  reader_hostgroup:
    description:
      - Id of the reader hostgroup.
    type: int
    required: true
  comment:
    description:
      - Text field that can be used for any purposes defined by the user.
    type: str
    default: ""
  state:
    description:
      - When C(present) - adds the replication hostgroup, when C(absent) -
        removes the replication hostgroup.
    type: str
    choices: [ "present", "absent" ]
    default: present
  check_type:
    description:
      - Which check type to use when detecting that the node is a standby.
      - Requires proxysql >= 2.0.1. Otherwise it has no effect.
      - C(read_only|innodb_read_only) and C(read_only&innodb_read_only) requires proxysql >= 2.0.8.
    type: str
    choices: [ "read_only", "innodb_read_only", "super_read_only", "read_only|innodb_read_only", "read_only&innodb_read_only" ]
    default: read_only
    version_added: 1.3.0
extends_documentation_fragment:
- community.proxysql.proxysql.managing_config
- community.proxysql.proxysql.connectivity
notes:
- Supports C(check_mode).
'''

EXAMPLES = '''
---
# This example adds a replication hostgroup, it saves the mysql server config
# to disk, but avoids loading the mysql server config to runtime (this might be
# because several replication hostgroup are being added and the user wants to
# push the config to runtime in a single batch using the
# community.general.proxysql_manage_config module).  It uses supplied credentials
# to connect to the proxysql admin interface.

- name: Add a replication hostgroup
  community.proxysql.proxysql_replication_hostgroups:
    login_user: 'admin'
    login_password: 'admin'
    writer_hostgroup: 1
    reader_hostgroup: 2
    state: present
    load_to_runtime: false

- name: Change check_type
  community.proxysql.proxysql_replication_hostgroups:
    login_user: 'admin'
    login_password: 'admin'
    writer_hostgroup: 1
    reader_hostgroup: 2
    check_type: innodb_read_only
    state: present
    load_to_runtime: false

# This example removes a replication hostgroup, saves the mysql server config
# to disk, and dynamically loads the mysql server config to runtime.  It uses
# credentials in a supplied config file to connect to the proxysql admin
# interface.

- name: Remove a replication hostgroup
  community.proxysql.proxysql_replication_hostgroups:
    config_file: '~/proxysql.cnf'
    writer_hostgroup: 3
    reader_hostgroup: 4
    state: absent
'''

RETURN = '''
stdout:
    description: The replication hostgroup modified or removed from proxysql.
    returned: On create/update will return the newly modified group, on delete
              it will return the deleted record.
    type: dict
    "sample": {
        "changed": true,
        "msg": "Added server to mysql_hosts",
        "repl_group": {
            "comment": "",
            "reader_hostgroup": "1",
            "writer_hostgroup": "2",
            "check_type": "read_only"
        },
        "state": "present"
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


def perform_checks(module):
    if not module.params["writer_hostgroup"] >= 0:
        module.fail_json(
            msg="writer_hostgroup must be a integer greater than or equal to 0"
        )

    if module.params["reader_hostgroup"] < 0:
        module.fail_json(
            msg="reader_hostgroup must be an integer greater than or equal to 0"
        )

    if module.params["reader_hostgroup"] == module.params["writer_hostgroup"]:
        module.fail_json(
            msg="reader_hostgroup and writer_hostgroup must be different integer values")


class ProxySQLReplicationHostgroup(object):

    def __init__(self, module, version):
        self.state = module.params["state"]
        self.save_to_disk = module.params["save_to_disk"]
        self.load_to_runtime = module.params["load_to_runtime"]
        self.writer_hostgroup = module.params["writer_hostgroup"]
        self.reader_hostgroup = module.params["reader_hostgroup"]
        self.comment = module.params["comment"]
        self.check_type = module.params["check_type"]
        self.check_type_support = version.get('major') >= 2
        self.check_mode = module.check_mode

    def check_repl_group_config(self, cursor, keys):
        query_string = \
            """SELECT count(*) AS `repl_groups`
               FROM mysql_replication_hostgroups
               WHERE writer_hostgroup = %s"""

        query_data = \
            [self.writer_hostgroup]

        cursor.execute(query_string, query_data)
        check_count = cursor.fetchone()
        return (int(check_count['repl_groups']) > 0)

    def get_repl_group_config(self, cursor):
        query_string = \
            """SELECT *
               FROM mysql_replication_hostgroups
               WHERE writer_hostgroup = %s"""

        query_data = \
            [self.writer_hostgroup]

        cursor.execute(query_string, query_data)
        repl_group = cursor.fetchone()
        return repl_group

    def create_repl_group_config(self, cursor):
        query_string = \
            """INSERT INTO mysql_replication_hostgroups (
               writer_hostgroup,
               reader_hostgroup,
               comment)
               VALUES (%s, %s, %s)"""

        query_data = \
            [self.writer_hostgroup,
             self.reader_hostgroup,
             self.comment or '']

        cursor.execute(query_string, query_data)

        if self.check_type_support:
            self.update_check_type(cursor)

        return True

    def delete_repl_group_config(self, cursor):
        query_string = \
            """DELETE FROM mysql_replication_hostgroups
               WHERE writer_hostgroup = %s"""

        query_data = \
            [self.writer_hostgroup]

        cursor.execute(query_string, query_data)
        return True

    def manage_config(self, cursor, state):
        if state and not self.check_mode:
            if self.save_to_disk:
                save_config_to_disk(cursor, "SERVERS")
            if self.load_to_runtime:
                load_config_to_runtime(cursor, "SERVERS")

    def create_repl_group(self, result, cursor):
        if not self.check_mode:
            result['changed'] = \
                self.create_repl_group_config(cursor)
            result['msg'] = "Added server to mysql_hosts"
            result['repl_group'] = \
                self.get_repl_group_config(cursor)
            self.manage_config(cursor,
                               result['changed'])
        else:
            result['changed'] = True
            result['msg'] = ("Repl group would have been added to" +
                             " mysql_replication_hostgroups, however" +
                             " check_mode is enabled.")

    def update_repl_group(self, result, cursor):
        current = self.get_repl_group_config(cursor)

        if self.check_type_support and current.get('check_type') != self.check_type:
            result['changed'] = True
            if not self.check_mode:
                result['msg'] = "Updated replication hostgroups"
                self.update_check_type(cursor)
            else:
                result['msg'] = "Updated replication hostgroups in check_mode"

        if current.get('comment') != self.comment:
            result['changed'] = True
            result['msg'] = "Updated replication hostgroups in check_mode"
            if not self.check_mode:
                result['msg'] = "Updated replication hostgroups"
                self.update_comment(cursor)

        if int(current.get('reader_hostgroup')) != self.reader_hostgroup:
            result['changed'] = True
            result['msg'] = "Updated replication hostgroups in check_mode"
            if not self.check_mode:
                result['msg'] = "Updated replication hostgroups"
                self.update_reader_hostgroup(cursor)

        result['repl_group'] = self.get_repl_group_config(cursor)

        self.manage_config(cursor,
                           result['changed'])

    def delete_repl_group(self, result, cursor):
        if not self.check_mode:
            result['repl_group'] = \
                self.get_repl_group_config(cursor)
            result['changed'] = \
                self.delete_repl_group_config(cursor)
            result['msg'] = "Deleted server from mysql_hosts"
            self.manage_config(cursor,
                               result['changed'])
        else:
            result['changed'] = True
            result['msg'] = ("Repl group would have been deleted from" +
                             " mysql_replication_hostgroups, however" +
                             " check_mode is enabled.")

    def update_check_type(self, cursor):
        try:
            query_string = ("UPDATE mysql_replication_hostgroups "
                            "SET check_type = %s "
                            "WHERE writer_hostgroup = %s")

            cursor.execute(query_string, (self.check_type, self.writer_hostgroup))
        except Exception as e:
            pass

    def update_reader_hostgroup(self, cursor):
        query_string = ("UPDATE mysql_replication_hostgroups "
                        "SET reader_hostgroup = %s "
                        "WHERE writer_hostgroup = %s")

        cursor.execute(query_string, (self.reader_hostgroup, self.writer_hostgroup))

    def update_comment(self, cursor):
        query_string = ("UPDATE mysql_replication_hostgroups "
                        "SET comment = %s "
                        "WHERE writer_hostgroup = %s ")

        cursor.execute(query_string, (self.comment, self.writer_hostgroup))


# ===========================================
# Module execution.
#
def main():
    argument_spec = proxysql_common_argument_spec()
    argument_spec.update(
        writer_hostgroup=dict(required=True, type='int'),
        reader_hostgroup=dict(required=True, type='int'),
        check_type=dict(type='str', default='read_only', choices=['read_only',
                                                                  'innodb_read_only',
                                                                  'super_read_only',
                                                                  'read_only|innodb_read_only',
                                                                  'read_only&innodb_read_only']),
        comment=dict(type='str', default=''),
        state=dict(default='present', choices=['present',
                                               'absent']),
        save_to_disk=dict(default=True, type='bool'),
        load_to_runtime=dict(default=True, type='bool')
    )

    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=argument_spec
    )

    perform_checks(module)

    login_user = module.params["login_user"]
    login_password = module.params["login_password"]
    config_file = module.params["config_file"]

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

    proxysql_repl_group = ProxySQLReplicationHostgroup(module, version)
    result = {}

    result['state'] = proxysql_repl_group.state
    result['changed'] = False

    if proxysql_repl_group.state == "present":
        try:
            if not proxysql_repl_group.check_repl_group_config(cursor,
                                                               keys=True):
                proxysql_repl_group.create_repl_group(result,
                                                      cursor)
            else:
                proxysql_repl_group.update_repl_group(result, cursor)

                result['repl_group'] = proxysql_repl_group.get_repl_group_config(cursor)

        except mysql_driver.Error as e:
            module.fail_json(
                msg="unable to modify replication hostgroup.. %s" % to_native(e)
            )

    elif proxysql_repl_group.state == "absent":
        try:
            if proxysql_repl_group.check_repl_group_config(cursor,
                                                           keys=True):
                proxysql_repl_group.delete_repl_group(result, cursor)
            else:
                result['changed'] = False
                result['msg'] = ("The repl group is already absent from the" +
                                 " mysql_replication_hostgroups memory" +
                                 " configuration")

        except mysql_driver.Error as e:
            module.fail_json(
                msg="unable to delete replication hostgroup.. %s" % to_native(e)
            )

    module.exit_json(**result)


if __name__ == '__main__':
    main()
