#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: proxysql_galera_hostgroups
author: "Tomas Palevičius (@tompal3)"
short_description: Manages galera hostgroups using the proxysql admin
                   interface
description:
   - Unlike regular async replication, Galera hostgroup are NOT defined in mysql_replication_hostgroups table.
     Instead there is a separate table that is specifically designed for Galera hostgroups.
     The reason for this is that more advanced topology support is needed in order to accommodate
     the deployment options available for Galera (e.g. controlled number of writers, cluster
     level replication thresholds etc.)
options:
  writer_hostgroup:
    description:
      - Id of the hostgroup that will contain all the Galera nodes that are active writers.
    type: int
    required: true
  backup_writer_hostgroup:
    description:
      - Id of the hostgroup that will contain all the Galera nodes that are standby writers.
    type: int
    required: true
  reader_hostgroup:
    description:
      - Id of the hostgroup that will contain all the Galera nodes that are readers.
    type: int
    required: true
  offline_hostgroup:
    description:
      - Id of the hostgroup all failed nodes will be moved to.
    type: int
    required: true
  active:
    description:
      - Enabled (1) or disabled (0) defined hostgroup configuration.
    type: int
    choices: [0 , 1]
    default: 1
  max_writers:
    description:
      - number of Read-Write instances populated in the writer hostgroup
    type: int
    default: 1
  writer_is_also_reader:
    description:
      - writer_is_also_reader - 0 nodes with `read_only=0` will be placed either in the writer_hostgroup
        and in the backup_writer_hostgroup after a topology change, these will be excluded from the reader_hostgroup
      - writer_is_also_reader - 1 nodes with `read_only=0` will be placed in the writer_hostgroup or
        backup_writer_hostgroup and are all also placed in reader_hostgroup after a topology change
      - writer_is_also_reader - 2 Only the nodes with `read_only=0` which are placed in the in the
        backup_writer_hostgroup are also placed in the reader_hostgroup after a topology change i.e.
        the nodes with `read_only=0` exceeding the defined `max_writers`.
    type: int
    choices: [ 0, 1, 2 ]
    default: 0
  max_transactions_behind :
    description:
      - maximum number of writesets behind the cluster that ProxySQL should allow before shunning
        the node to prevent stale reads
    type: int
    default: 0
  comment:
    description:
      - Text field that can be used for any purposes defined by the user.
    type: str
    default: ""
  state:
    description:
      - When C(present) - adds the galera hostgroup, when C(absent) -
        removes the galera hostgroup.
    type: str
    choices: [ "present", "absent" ]
    default: present
extends_documentation_fragment:
- community.proxysql.proxysql.managing_config
- community.proxysql.proxysql.connectivity
notes:
- Supports C(check_mode).
'''

EXAMPLES = '''
---
# This example adds a new galera hostgroup, it saves the mysql server config
# to disk and loads it to a runtime and also enables the config which has
# maximum of 2 writers from the writers_hostgroup.

- name: Add a galera hostgroup
  community.proxysql.proxysql_galera_hostgroups:
    login_user: "admin"
    login_password: "admin"
    writer_hostgroup: 1
    backup_writer_hostgroup: 2
    reader_hostgroup: 3
    offline_hostgroup: 4
    active: 1
    max_writers: 2
    writer_is_also_reader: 0

# This example disables galera hostgroup by setting active to 0

- name: Disable a galera hostgroup
  community.proxysql.proxysql_galera_hostgroups:
    login_user: "admin"
    login_password: "admin"
    writer_hostgroup: 1
    backup_writer_hostgroup: 2
    reader_hostgroup: 3
    offline_hostgroup: 4
    active: 0

# This example removes a galera hostgroup from configuration,
# saves the mysql server config to disk, and loads the mysql
# server config to runtime. It uses credentials in a supplied
# config file to connect to the proxysql admin interface.

- name: Remove a galera hostgroup
  community.proxysql.proxysql_galera_hostgroups:
      config_file: '/tmp/proxysql.cnf'
      writer_hostgroup: 0
      backup_writer_hostgroup: 1
      reader_hostgroup: 2
      offline_hostgroup: 3
      active: 0
      state: absent
'''

RETURN = '''
stdout:
    description: The galera hostgroup modified or removed from proxysql.
    returned: On create/update will return the newly modified group, on delete
              it will return the deleted record.
    type: dict
    "sample": {
        "changed": true,
        "galera_group": {
            "active": "1",
            "backup_writer_hostgroup": "1",
            "comment": "test",
            "max_transactions_behind": "0",
            "max_writers": "3",
            "offline_hostgroup": "3",
            "reader_hostgroup": "2",
            "writer_hostgroup": "0",
            "writer_is_also_reader": "1"
        },
        "msg": "Updated galera hostgroups in check_mode",
        "state": "present"
    }
'''

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxysql.plugins.module_utils.mysql import (
    mysql_connect,
    mysql_driver,
    proxysql_common_argument_spec,
    save_config_to_disk,
    load_config_to_runtime,
)


def perform_checks(module):
    """ Perform validation of
        module.params variables

    Args:
        module (dict):
    """
    unique_hostgroups = {
        "writer_hostgroup": module.params["writer_hostgroup"],
        "backup_writer_hostgroup": module.params["backup_writer_hostgroup"],
        "reader_hostgroup": module.params["reader_hostgroup"],
        "offline_hostgroup": module.params["offline_hostgroup"]
    }
    positive_or_zero = {
        "max_writers": module.params["max_writers"],
        "max_transactions_behind": module.params["max_transactions_behind"]
    }
    positive_or_zero.update(unique_hostgroups)
    status, hostgroup = check_if_unique(unique_hostgroups)
    if not status:
        module.fail_json(
            msg="%s value is not unique. %s must have unique value" %
            (hostgroup, list(unique_hostgroups.keys()))
        )
    status, hostgroup = check_positive_int(positive_or_zero)
    if not status:
        module.fail_json(
            msg="%s must be an integer greater than or equal to 0" %
            (hostgroup)
        )


def check_if_unique(param_dict):
    """check if dict have unique values

    Args:
        param_dict (dict): dict of unique values to check

    Returns:
        Boolean: True if unique
        hostgroup (string): incorect hostgroup
    """
    unique_values = {}
    for hostgroup, value in param_dict.items():
        if value not in unique_values.values():
            unique_values[hostgroup] = value
        else:
            return False, hostgroup
    return True, None


def check_positive_int(param_dict):
    """check if dict values are positive int or zero

    Args:
        param_dict (dict): dict of unique values to check

    Returns:
        Boolean: True if unique
        hostgroup (string): incorect hostgroup
    """
    for hostgroup, value in param_dict.items():
        if isinstance(value, int):
            if not value < 0:
                return True, None
        return False, hostgroup


class ProxySQLGaleraHostgroup():
    """proxysql galera hostgroup class"""

    def __init__(self, module, version):
        self.state = module.params["state"]
        self.save_to_disk = module.params["save_to_disk"]
        self.load_to_runtime = module.params["load_to_runtime"]

        config_data_keys = [
            "writer_hostgroup",
            "backup_writer_hostgroup",
            "reader_hostgroup",
            "offline_hostgroup",
            "active",
            "max_writers",
            "writer_is_also_reader",
            "max_transactions_behind",
            "comment"
        ]

        self.config_data = dict((k, module.params[k])
                                for k in config_data_keys)

        self.galera_hostgroups_support = version.get("major") >= 2
        self.check_mode = module.check_mode

    def check_galera_group_config(self, cursor):
        query_string = """SELECT count(*) AS `galera_groups`
               FROM mysql_galera_hostgroups
               WHERE writer_hostgroup = %s"""

        query_data = [self.config_data['writer_hostgroup']]

        cursor.execute(query_string, query_data)
        check_count = cursor.fetchone()
        return int(check_count["galera_groups"]) > 0

    def get_galera_group_config(self, cursor):
        query_string = """SELECT *
               FROM mysql_galera_hostgroups
               WHERE writer_hostgroup = %s"""

        query_data = [self.config_data['writer_hostgroup']]

        cursor.execute(query_string, query_data)
        galera_group = cursor.fetchone()
        return galera_group

    def create_galera_group_config(self, cursor):
        query_string = """INSERT INTO mysql_galera_hostgroups (
               writer_hostgroup,
               backup_writer_hostgroup,
               reader_hostgroup,
               offline_hostgroup,
               active,
               max_writers,
               writer_is_also_reader,
               max_transactions_behind,
               comment)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""

        query_data = [
            self.config_data['writer_hostgroup'],
            self.config_data['backup_writer_hostgroup'],
            self.config_data['reader_hostgroup'],
            self.config_data['offline_hostgroup'],
            self.config_data['active'],
            self.config_data['max_writers'],
            self.config_data['writer_is_also_reader'],
            self.config_data['max_transactions_behind'],
            self.config_data['comment']
        ]

        cursor.execute(query_string, query_data)

        return True

    def delete_galera_group_config(self, cursor):
        query_string = """DELETE FROM mysql_galera_hostgroups
               WHERE writer_hostgroup = %s"""

        query_data = [self.config_data['writer_hostgroup']]

        cursor.execute(query_string, query_data)
        return True

    def manage_config(self, cursor, state):
        if state and not self.check_mode:
            if self.save_to_disk:
                save_config_to_disk(cursor, "SERVERS")
            if self.load_to_runtime:
                load_config_to_runtime(cursor, "SERVERS")

    def create_galera_group(self, result, cursor):
        if not self.check_mode:
            result["changed"] = self.create_galera_group_config(cursor)
            result["msg"] = "Galera group have been added to mysql_galera_hostgroups"
            result["galera_group"] = self.get_galera_group_config(cursor)
            self.manage_config(cursor, result["changed"])
        else:
            result["changed"] = True
            result["msg"] = (
                "Galera group would have been added to"
                + " mysql_galera_hostgroups, however"
                + " check_mode is enabled."
            )

    def update_galera_group(self, result, cursor):
        current = self.get_galera_group_config(cursor)

        for key, value in current.items():
            if key != "comment":
                value = int(value)
            if self.config_data.get(key):
                if value != self.config_data[key]:
                    result["changed"] = True
                    result["msg"] = "Updated galera hostgroups in check_mode"
                    if not self.check_mode:
                        result["changed"] = True
                        result["msg"] = "Updated galera hostgroups"
                        self.update_attr(cursor, key)

        result["galera_group"] = self.get_galera_group_config(cursor)

        self.manage_config(cursor, result["changed"])

    def delete_galera_group(self, result, cursor):
        if not self.check_mode:
            result["galera_group"] = self.get_galera_group_config(cursor)
            result["changed"] = self.delete_galera_group_config(cursor)
            result["msg"] = "Deleted galera group from mysql_galera_hostgroup"
            self.manage_config(cursor, result["changed"])
        else:
            result["changed"] = True
            result["msg"] = (
                "galera group would have been deleted from"
                + " mysql_replication_hostgroups, however"
                + " check_mode is enabled."
            )

    def update_attr(self, cursor, attr):
        query_string = """UPDATE mysql_galera_hostgroups
               SET %s = %s
               WHERE writer_hostgroup = %s"""

        query_data = [attr, self.config_data[attr],
                      self.config_data['writer_hostgroup']]

        cursor.execute(query_string, query_data)


# ===========================================
# Module execution.
#


def main():
    argument_spec = proxysql_common_argument_spec()
    argument_spec.update(
        writer_hostgroup=dict(required=True, type="int"),
        backup_writer_hostgroup=dict(required=True, type='int'),
        reader_hostgroup=dict(required=True, type="int"),
        offline_hostgroup=dict(required=True, type="int"),
        active=dict(type="int", default=1, choices=[0, 1]),
        max_writers=dict(type="int", default=1),
        writer_is_also_reader=dict(type="int", default=0, choices=[0, 1, 2]),
        max_transactions_behind=dict(type="int", default=0),
        comment=dict(type="str", default=""),
        state=dict(default="present", choices=["present", "absent"]),
        save_to_disk=dict(default=True, type="bool"),
        load_to_runtime=dict(default=True, type="bool"),
    )

    module = AnsibleModule(supports_check_mode=True,
                           argument_spec=argument_spec)

    perform_checks(module)

    login_user = module.params["login_user"]
    login_password = module.params["login_password"]
    config_file = module.params["config_file"]

    cursor = None
    try:
        cursor, db_conn, version = mysql_connect(
            module, login_user, login_password, config_file, cursor_class="DictCursor"
        )
    except mysql_driver.Error as e:
        module.fail_json(
            msg="unable to connect to ProxySQL Admin Module.. %s" % (
                to_native(e))
        )

    proxysql_galera_group = ProxySQLGaleraHostgroup(module, version)
    result = {}

    result["state"] = proxysql_galera_group.state
    result["changed"] = False

    if not proxysql_galera_group.galera_hostgroups_support:
        result["msg"] = "mysql_galera_hostgroups is only supported with proxysql 2.0.0 and above"
        module.exit_json(**result)

    if proxysql_galera_group.state == "present":
        try:
            if not proxysql_galera_group.check_galera_group_config(cursor):
                proxysql_galera_group.create_galera_group(result, cursor)
            else:
                proxysql_galera_group.update_galera_group(result, cursor)

                result["galera_group"] = proxysql_galera_group.get_galera_group_config(
                    cursor)

        except mysql_driver.Error as e:
            module.fail_json(
                msg="unable to modify galera hostgroup.. %s" % (to_native(e))
            )

    elif proxysql_galera_group.state == "absent":
        try:
            if proxysql_galera_group.check_galera_group_config(cursor):
                proxysql_galera_group.delete_galera_group(result, cursor)
            else:
                result["changed"] = False
                result["msg"] = (
                    "The galera group is already absent from the"
                    + " mysql_galera_hostgroups memory"
                    + " configuration"
                )

        except mysql_driver.Error as e:
            module.fail_json(
                msg="unable to delete galera hostgroup.. %s" % (to_native(e))
            )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
