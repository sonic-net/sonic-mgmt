#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: proxysql_info
author: "Markus Bergholz (@markuman)"
short_description: Gathers information about proxysql server
description:
   - Gathers information about proxysql server.
   - Caution. The number of tables that returns, depends on the underlying proyxsql server version.
version_added: '1.2.0'
extends_documentation_fragment:
  - community.proxysql.proxysql.connectivity
notes:
  - Supports C(check_mode).
'''

EXAMPLES = '''
- name: Receive information about proxysql setup
  community.proxysql.proxysql_info:
    login_user: admin
    login_password: admin
'''

RETURN = '''
stdout:
    description: The number of tables that returns, depends on the underlying proyxsql server version.
    returned: Always
    type: dict
    sample:
        changed: false
        failed: false
        version:
            description: Version of proxysql.
            sample:
                full: 2.1.1-40-g1c2b7e4
                major: 2
                minor: 1
                release: 1
                suffix: 40
            type: dict
            returned: Always
        tables:
            description: List of tables that exist in the requested proxysql version.
            sample:
                - global_variables
                - mysql_aws_aurora_hostgroups
                - mysql_collations
                - mysql_firewall_whitelist_rules
                - mysql_firewall_whitelist_sqli_fingerprints
                - mysql_firewall_whitelist_users
                - mysql_galera_hostgroups
                - mysql_group_replication_hostgroups
                - mysql_query_rules
                - mysql_query_rules_fast_routing
                - mysql_replication_hostgroups
                - mysql_servers
                - mysql_users
                - proxysql_servers
                - restapi_routes
                - runtime_checksums_values
                - runtime_global_variables
                - runtime_mysql_aws_aurora_hostgroups
                - runtime_mysql_firewall_whitelist_rules
                - runtime_mysql_firewall_whitelist_sqli_fingerprints
                - runtime_mysql_firewall_whitelist_users
                - runtime_mysql_galera_hostgroups
                - runtime_mysql_group_replication_hostgroups
                - runtime_mysql_query_rules
                - runtime_mysql_query_rules_fast_routing
                - runtime_mysql_replication_hostgroups
                - runtime_mysql_servers
                - runtime_mysql_users
                - runtime_proxysql_servers
                - runtime_restapi_routes
                - runtime_scheduler
                - scheduler
            type: list
            returned: Always
        global_variables:
            description: Global variables of requested proxysql.
            type: dict
            returned: Always
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxysql.plugins.module_utils.mysql import (
    mysql_connect,
    mysql_driver,
    proxysql_common_argument_spec,
)
from ansible.module_utils._text import to_native

# ===========================================
# proxysql module specific support methods.
#


def get_tables(cursor):
    result = dict()
    tables = list()

    cursor.execute("show tables")

    for table in cursor.fetchall():
        tables.append(table.get('tables'))
    result['tables'] = tables

    for table in result.get('tables'):
        cursor.execute("select * from {table}".format(table=table))

        if 'global_variables' in table:
            result[table] = dict()
            for item in cursor.fetchall():
                result[table][item.get('variable_name')] = item.get('variable_value')

        else:
            result[table] = cursor.fetchall()

    return result


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=proxysql_common_argument_spec()
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

    result = get_tables(cursor)

    result['version'] = version

    module.exit_json(**result)


if __name__ == '__main__':
    main()
