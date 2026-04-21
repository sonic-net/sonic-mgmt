#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: proxysql_query_rules_fast_routing
author: "Akim Lindberg (@akimrx)"
short_description: Modifies query rules for fast routing policies using the proxysql admin interface
description:
   - The M(community.proxysql.proxysql_query_rules_fast_routing) module modifies query rules for fast
     routing policies and attributes using the proxysql admin interface.
version_added: '1.1.0'
options:
  username:
    description:
      - Filtering criteria matching username, a query will match only if the connection is made with
        the correct username.
    type: str
    required: true
  schemaname:
    description:
      - Filtering criteria matching schemaname, a query will match only if the connection uses
        schemaname as its default schema.
    type: str
    required: true
  flagIN:
    description:
      - Evaluated in the same way as I(flagIN) is in B(mysql_query_rules) and correlates to the
        I(flagOUT/apply) specified in the B(mysql_query_rules) table.
        (see M(community.proxysql.proxysql_query_rules)).
    type: int
    default: 0
  destination_hostgroup:
    description:
      - Route matched queries to this hostgroup. This happens unless there is a
        started transaction and the logged in user has
        I(transaction_persistent) set to C(True) (refer to M(community.proxysql.proxysql_mysql_users)).
    type: int
    required: true
  comment:
    description:
      - Free form text field, usable for a descriptive comment of the query rule.
    type: str
    default: ''
  state:
    description:
      - When C(present), adds the rule. When C(absent), removes the rule.
    type: str
    choices: [ "present", "absent" ]
    default: present
  force_delete:
    description:
      - By default, we avoid deleting more than one schedule in a single batch;
        however, if you need this behaviour and you are not concerned about the
        schedules deleted, you can set I(force_delete) to C(True).
    type: bool
    default: false
extends_documentation_fragment:
- community.proxysql.proxysql.managing_config
- community.proxysql.proxysql.connectivity
notes:
- Supports C(check_mode).
'''

EXAMPLES = '''
---
# This example adds a rule for fast routing
- name: Add a rule
  community.proxysql.proxysql_query_rules_fast_routing:
    login_user: admin
    login_password: admin
    username: 'user_ro'
    schemaname: 'default'
    destination_hostgroup: 1
    comment: 'fast route user_ro to default schema'
    state: present
    save_to_disk: true
    load_to_runtime: true
'''

RETURN = '''
stdout:
    description: The mysql user modified or removed from proxysql.
    returned: On create/update will return the newly modified rule, in all
              other cases will return a list of rules that match the supplied
              criteria.
    type: dict
    "sample": {
        "changed": true,
        "msg": "Added rule to mysql_query_rules_fast_routing",
        "rules": [
            {
                "username": "user_ro",
                "schemaname": "default",
                "destination_hostgroup": 1,
                "flagIN": "0",
                "comment": ""
            }
        ],
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


class ProxyQueryRuleFastRouting(object):

    def __init__(self, module):
        self.state = module.params["state"]
        self.force_delete = module.params["force_delete"]
        self.save_to_disk = module.params["save_to_disk"]
        self.load_to_runtime = module.params["load_to_runtime"]

        config_data_keys = [
            "username",
            "schemaname",
            "flagIN",
            "destination_hostgroup",
            "comment"
        ]

        self.config_data = dict(
            (k, module.params[k])
            for k in config_data_keys
        )

    def check_rule_pk_exists(self, cursor):
        query_string = (
            "SELECT count(*) AS `rule_count` "
            "FROM mysql_query_rules_fast_routing "
            "WHERE username = %s  "
            "AND schemaname = %s "
            "AND flagIN = %s"
        )

        query_data = [
            self.config_data["username"],
            self.config_data["schemaname"],
            self.config_data["flagIN"],
        ]

        cursor.execute(query_string, query_data)
        check_count = cursor.fetchone()
        return (int(check_count['rule_count']) > 0)

    def check_rule_cfg_exists(self, cursor):
        query_string = "SELECT count(*) AS `rule_count` FROM mysql_query_rules_fast_routing"

        cols = 0
        query_data = []

        for col, val in self.config_data.items():
            if val is not None:
                cols += 1
                query_data.append(val)
                if cols == 1:
                    query_string += " WHERE " + col + " = %s"
                else:
                    query_string += " AND " + col + " = %s"

        if cols > 0:
            cursor.execute(query_string, query_data)
        else:
            cursor.execute(query_string)
        check_count = cursor.fetchone()
        return int(check_count['rule_count'])

    def get_rule_config(self, cursor):
        query_string = (
            "SELECT * "
            "FROM mysql_query_rules_fast_routing "
            "WHERE username = %s "
            "AND schemaname = %s "
            "AND flagIN = %s"
        )

        query_data = [
            self.config_data["username"],
            self.config_data["schemaname"],
            self.config_data["flagIN"]
        ]

        for col, val in self.config_data.items():
            if val is not None:
                query_data.append(val)
                query_string += " AND " + col + " = %s"

        cursor.execute(query_string, query_data)
        rule = cursor.fetchall()
        return rule

    def create_rule_config(self, cursor):
        query_string = "INSERT INTO mysql_query_rules_fast_routing ("

        cols = 0
        query_data = []

        for col, val in self.config_data.items():
            if val is not None:
                cols += 1
                query_data.append(val)
                query_string += col + ","

        query_string = query_string[:-1]
        query_string += ") VALUES (" + "%s, " * cols
        query_string = query_string[:-2]
        query_string += ")"

        cursor.execute(query_string, query_data)
        return True

    def update_rule_config(self, cursor):
        query_string = "UPDATE mysql_query_rules_fast_routing"

        cols = 0
        query_data = [
            self.config_data["username"],
            self.config_data["schemaname"],
            self.config_data["flagIN"]
        ]

        for col, val in self.config_data.items():
            if val is not None and col not in ("username", "schemaname", "flagIN"):
                query_data.insert(cols, val)
                cols += 1
                if cols == 1:
                    query_string += " SET " + col + "= %s,"
                else:
                    query_string += " " + col + " = %s,"

        query_string = query_string[:-1]
        query_string += (
            "WHERE username = %s "
            "AND schemaname = %s "
            "AND flagIN = %s"
        )

        cursor.execute(query_string, query_data)
        return True

    def delete_rule_config(self, cursor):
        query_string = "DELETE FROM mysql_query_rules_fast_routing"

        cols = 0
        query_data = []

        for col, val in self.config_data.items():
            if val is not None:
                cols += 1
                query_data.append(val)
                if cols == 1:
                    query_string += " WHERE " + col + " = %s"
                else:
                    query_string += " AND " + col + " = %s"

        if cols > 0:
            cursor.execute(query_string, query_data)
        else:
            cursor.execute(query_string)
        check_count = cursor.rowcount
        return True, int(check_count)

    def manage_config(self, cursor, changed):
        if not changed:
            return

        if self.save_to_disk:
            save_config_to_disk(cursor, "QUERY RULES")
        if self.load_to_runtime:
            load_config_to_runtime(cursor, "QUERY RULES")

    def create_rule(self, check_mode, result, cursor):
        if not check_mode:
            result['changed'] = self.create_rule_config(cursor)
            result['msg'] = "Added rule to mysql_query_rules_fast_routing."
            self.manage_config(cursor, result['changed'])
            result['rules'] = self.get_rule_config(cursor)
        else:
            result['changed'] = True
            result['msg'] = (
                "Rule would have been added to "
                "mysql_query_rules_fast_routing, "
                "however check_mode is enabled."
            )

    def update_rule(self, check_mode, result, cursor):
        if not check_mode:
            result['changed'] = self.update_rule_config(cursor)
            result['msg'] = "Updated rule in mysql_query_rules_fast_routing."
            self.manage_config(cursor, result['changed'])
            result['rules'] = self.get_rule_config(cursor)
        else:
            result['changed'] = True
            result['msg'] = (
                "Rule would have been updated in "
                "mysql_query_rules_fast_routing, "
                "however check_mode is enabled."
            )

    def delete_rule(self, check_mode, result, cursor):
        if not check_mode:
            result['rules'] = self.get_rule_config(cursor)
            result['changed'], result['rows_affected'] = self.delete_rule_config(cursor)
            result['msg'] = "Deleted rule from mysql_query_rules_fast_routing."
            self.manage_config(cursor, result['changed'])
        else:
            result['changed'] = True
            result['msg'] = (
                "Rule would have been deleted from "
                "mysql_query_rules_fast_routing, "
                "however check_mode is enabled."
            )

# ===========================================
# Module execution.
#


def main():
    argument_spec = proxysql_common_argument_spec()
    argument_spec.update(
        username=dict(required=True, type='str'),
        schemaname=dict(required=True, type='str'),
        destination_hostgroup=dict(required=True, type='int'),
        flagIN=dict(default=0, type='int'),
        comment=dict(default='', type='str'),
        state=dict(default='present', choices=['present', 'absent']),
        force_delete=dict(default=False, type='bool'),
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

    cursor = None
    try:
        cursor, db_conn, version = mysql_connect(
            module,
            login_user,
            login_password,
            config_file,
            cursor_class='DictCursor'
        )
    except mysql_driver.Error as e:
        module.fail_json(msg="unable to connect to ProxySQL Admin Module: %s" % to_native(e))

    query_rule = ProxyQueryRuleFastRouting(module)
    result = {}

    result['state'] = query_rule.state

    if query_rule.state == "present":
        try:
            if not query_rule.check_rule_cfg_exists(cursor):
                if query_rule.config_data["username"] and query_rule.config_data["schemaname"] and \
                   query_rule.check_rule_pk_exists(cursor):
                    query_rule.update_rule(module.check_mode, result, cursor)
                else:
                    query_rule.create_rule(module.check_mode, result, cursor)
            else:
                result['changed'] = False
                result['msg'] = (
                    "The rule already exists in "
                    "mysql_query_rules_fast_routing "
                    "and doesn't need to be updated."
                )
                result['rules'] = query_rule.get_rule_config(cursor)

        except mysql_driver.Error as e:
            module.fail_json(msg="unable to modify rule: %s" % to_native(e))

    elif query_rule.state == "absent":
        try:
            existing_rules = query_rule.check_rule_cfg_exists(cursor)
            if existing_rules > 0:
                if existing_rules == 1 or query_rule.force_delete:
                    query_rule.delete_rule(module.check_mode, result, cursor)
                else:
                    module.fail_json(msg=("Operation would delete multiple rules use force_delete to override this."))
            else:
                result['changed'] = False
                result['msg'] = (
                    "The rule is already absent from the "
                    "mysql_query_rules_fast_routing memory "
                    "configuration"
                )
        except mysql_driver.Error as e:
            module.fail_json(msg="unable to remove rule: %s" % to_native(e))

    module.exit_json(**result)


if __name__ == '__main__':
    main()
