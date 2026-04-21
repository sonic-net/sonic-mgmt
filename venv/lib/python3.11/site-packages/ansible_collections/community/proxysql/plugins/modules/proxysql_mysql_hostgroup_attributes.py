#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: proxysql_mysql_hostgroup_attributes
author: "Richard Burnison (@burnison)"
short_description: Manages hostgroup attributes using the ProxySQL admin
                   interface
description:
   - Each row in mysql_hostgroup_attributes provides a per-hostgroup override
     of a specific hostgroup. This extension table allows for
     hostgroup-specific configurations, like `max_num_online_servers`, which
     change the behaviour of the given hostgroup in ways that are not otherwise
     possible.

version_added: '1.7.0'

options:
  hostgroup_id:
    description:
      - ID of the hostgroup
    type: int
    required: true

  state:
    description:
      - When C(present) - adds the hostgroup attributes, when C(absent) -
        removes the hostgroup attributes.
    type: str
    choices: [ "present", "absent" ]
    default: present

  max_num_online_servers:
    description:
      - Prevents new connections when the number of ONLINE servers in the
        hostgroup exceeds this number.
    type: int
    default: 1000000

  autocommit:
    description:
      - Not yet implemented (as per ProxySQL documentation).
    type: int
    default: -1

  free_connections_pct:
    description:
      - The percentage of open idle connections for each server in a hostgroup.
    type: int
    default: 10

  init_connect:
    description:
      - Semicolon-delimited string of SQL statements to be executed for each
        back-end connection when initialized.
    type: str
    default: ""

  multiplex:
    description:
      - Enables or disables multiplexing for the specific hostgroup
    type: int
    default: 1

  connection_warming:
    description:
      - Whether ProxySQL will opening new connections until the expected number
        of warm connections is reached
    type: int
    default: 0

  throttle_connections_per_sec:
    description:
      - Maximum number of new connections that can be opened per second.
    type: int
    default: 1000000

  ignore_session_variables:
    description:
      - Not yet implemented (as per ProxySQL documentation).
    type: str
    default: ""

  hostgroup_settings:
    description:
      - Override certain global configurations.
    type: str
    default: ""

  servers_defaults:
    description:
      - Provide default values for discovered servers.
    type: str
    default: ""

  comment:
    description:
      - Text field that can be used for any purposes defined by the user.
    type: str
    default: ""

extends_documentation_fragment:
- community.proxysql.proxysql.managing_config
- community.proxysql.proxysql.connectivity

attributes:
  check_mode:
    description: Do not make any changes to memory, disk, or runtime.
    support: full
'''

EXAMPLES = '''
# This example uses supplied credentials to add a hostgroup override for the
# hostgroup with ID, `1`. The override sets the maximum number of ONLINE
# servers to `1` and provides a short comment. The configuration will be saved
# to disk and memory, but not loaded into runtime.

- name: Add hostgroup overrides to limit servers
  community.proxysql.proxysql_mysql_hostgroup_overrides:
    login_user: admin
    login_password: admin
    hostgroup_id: 1
    state: present
    load_to_runtime: false
    max_num_online_servers: 1
    comment: >-
      Limit connections to the writer hostgroup to prevent split-brains.

# This example uses stored configuration to manage a hostgroup override for the
# hostgroup with ID, `2`. The override limits the number of new connections
# that can be opened to 100/sec. The configuration will be saved to memory and
# runtime but not persisted to disk.

- name: Throttle connections on reader hostgroup
  community.proxysql.proxysql_mysql_hostgroup_overrides:
    config_file: /etc/proxysql/admin.cnf
    hostgroup_id: 2
    state: present
    load_to_runtime: true
    save_to_disk: false
    throttle_connections_per_sec: 100

# This example uses supplied credentials to add a hostgroup override for the
# hostgroup with ID, `2`. The override enables multiplexing and sets the number
# of cached connections to 100%. The configuration will be saved to memory but
# not disk or runtime.

- name: Aggressively reuse and cache connections
  community.proxysql.proxysql_mysql_hostgroup_overrides:
    login_user: admin
    login_password: admin
    hostgroup_id: 2
    load_to_runtime: false
    save_to_disk: false
    multiplex: 1
    free_connections_pct: 100

# This example uses stored configuration to manage a hostgroup override for the
# hostgroup with ID, `42`. The override changes the hostgroup to handle
# warnings and each server added into the hostgroup to have 1000 connections.

- name: Override globals for hostgroup 42
  community.proxysql.proxysql_mysql_hostgroup_overrides:
    config_file: /etc/proxysql/admin.cnf
    hostgroup_id: 42
    hostgroup_settings: >-
      {
        "handle_warnings": 1
      }
    server_settings: >-
      {
        "max_connections": 1000
      }

# This example removes a hostgroup override using the credentials supplied in
# a configuration file.

- name: Remove hostgroup overrides
  community.proxysql.proxysql_mysql_hostgroup_attributes:
    config_file: '~/proxysql.cnf'
    hostgroup_id: 3
    state: absent
'''

RETURN = '''
stdout:
    description: The mysql_hostgroup_override modified or removed from
                 ProxySQL.
    returned: On create/update will return the newly modified group, on delete
              it will return the deleted record.
    type: dict
    "sample": {
        "changed": true,
        "msg": "Added server to mysql_hostgroup_overrides",
        "mysql_hostgroup_attributes": {
            "autocommit": "-1",
            "comment": "",
            "connection_warming": "0",
            "free_connections_pct": "10",
            "hostgroup_id": "21",
            "hostgroup_settings": "",
            "ignore_session_variables": "",
            "init_connect": "",
            "max_num_online_servers": "1000000",
            "multiplex": "1",
            "servers_defaults": "",
            "throttle_connections_per_sec": "1000000"
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


def validate_args(module):
    if not module.params["hostgroup_id"] >= 0:
        module.fail_json(
            msg="hostgroup_id must be a integer greater than or equal to 0"
        )


class ProxySQLHostgroupAttributes(object):
    """
    See https://proxysql.com/documentation/main-runtime/#mysql_hostgroup_attributes.

    CREATE TABLE mysql_hostgroup_attributes (
       hostgroup_id INT NOT NULL PRIMARY KEY,
       max_num_online_servers INT CHECK (max_num_online_servers>=0 AND max_num_online_servers <= 1000000) NOT NULL DEFAULT 1000000,
       autocommit INT CHECK (autocommit IN (-1, 0, 1)) NOT NULL DEFAULT -1,
       free_connections_pct INT CHECK (free_connections_pct >= 0 AND free_connections_pct <= 100) NOT NULL DEFAULT 10,
       init_connect VARCHAR NOT NULL DEFAULT '',
       multiplex INT CHECK (multiplex IN (0, 1)) NOT NULL DEFAULT 1,
       connection_warming INT CHECK (connection_warming IN (0, 1)) NOT NULL DEFAULT 0,
       throttle_connections_per_sec INT CHECK (throttle_connections_per_sec >= 1 AND throttle_connections_per_sec <= 1000000) NOT NULL DEFAULT 1000000,
       ignore_session_variables VARCHAR CHECK (JSON_VALID(ignore_session_variables) OR ignore_session_variables = '') NOT NULL DEFAULT '',
       hostgroup_settings VARCHAR CHECK (JSON_VALID(hostgroup_settings) OR hostgroup_settings = '') NOT NULL DEFAULT '',
       servers_defaults VARCHAR CHECK (JSON_VALID(servers_defaults) OR servers_defaults = '') NOT NULL DEFAULT '',
       comment VARCHAR NOT NULL DEFAULT ''
    )
    """  # noqa: E501

    def __init__(self, module, version):
        self.state = module.params["state"]
        self.save_to_disk = module.params["save_to_disk"]
        self.load_to_runtime = module.params["load_to_runtime"]
        self.check_mode = module.check_mode

        self.hostgroup_id = module.params["hostgroup_id"]
        self.max_num_online_servers = module.params["max_num_online_servers"]
        self.autocommit = module.params["autocommit"]
        self.free_connections_pct = module.params["free_connections_pct"]
        self.init_connect = module.params["init_connect"]
        self.multiplex = module.params["multiplex"]
        self.connection_warming = module.params["connection_warming"]
        self.throttle_connections_per_sec = \
            module.params["throttle_connections_per_sec"]
        self.ignore_session_variables = \
            module.params["ignore_session_variables"]
        self.hostgroup_settings = module.params["hostgroup_settings"]
        self.servers_defaults = module.params["servers_defaults"]
        self.comment = module.params["comment"]

    def check_exists(self, cursor, keys):
        query_string = \
            """SELECT count(*) AS `attributes`
               FROM mysql_hostgroup_attributes
               WHERE hostgroup_id = %s"""

        cursor.execute(query_string, [self.hostgroup_id])
        check_count = cursor.fetchone()
        return (int(check_count['attributes']) > 0)

    def select(self, cursor):
        query_string = \
            """SELECT *
               FROM mysql_hostgroup_attributes
               WHERE hostgroup_id = %s"""

        query_data = [self.hostgroup_id]

        cursor.execute(query_string, query_data)
        repl_group = cursor.fetchone()
        return repl_group

    def create(self, result, cursor):
        if not self.check_mode:
            result['changed'] = self._insert(cursor)
            result['msg'] = "Added entry to mysql_hostgroup_attributes"
            result['mysql_hostgroup_attributes'] = self.select(cursor)
            self.manage_config(cursor, result['changed'])
        else:
            result['changed'] = True
            result['msg'] = ("Hostgroup attributes would have been added to" +
                             " mysql_hostgroup_attributes, however" +
                             " check_mode is enabled.")

    def delete(self, result, cursor):
        if not self.check_mode:
            result['mysql_hostgroup_attributes'] = self.select(cursor)
            result['changed'] = self._delete(cursor)
            result['msg'] = "Deleted entry from mysql_hostgroup_attributes"
            self.manage_config(cursor, result['changed'])
        else:
            result['changed'] = True
            result['msg'] = ("Hostgroup attributes would have been deleted" +
                             " from mysql_hostgroup_attributes, however" +
                             " check_mode is enabled.")

    def update(self, result, cursor):
        if not self.check_mode:
            result['changed'] = self._update(cursor)
            result['msg'] = "Updated entry in mysql_hostgroup_attributes"
            result['mysql_hostgroup_attributes'] = self.select(cursor)
            self.manage_config(cursor, result['changed'])
        else:
            result['changed'] = True
            result['msg'] = ("Hostgroup attributes would have been deleted" +
                             " from mysql_hostgroup_attributes, however" +
                             " check_mode is enabled.")

    def _insert(self, cursor):
        fields = self._as_fields()

        query_string = \
            "INSERT INTO mysql_hostgroup_attributes (" \
            + ", ".join(list(fields.keys())) \
            + ") VALUES (" + ", ".join(["%s" for f in fields.values()]) + ")"

        query_data = list(fields.values())

        cursor.execute(query_string, query_data)

        return True

    def _delete(self, cursor):
        query_string = \
            "DELETE FROM mysql_hostgroup_attributes WHERE hostgroup_id = %s"

        cursor.execute(query_string, [self.hostgroup_id])

        return True

    def _update(self, cursor):
        current = self.select(cursor)
        new = self._as_fields()

        to_update = {
            k: v for k, v in new.items()
            # Use get with default for table changes.
            if str(current.get(k, '')) != str(v)
        }

        if len(to_update) == 0:
            return False

        query = \
            "UPDATE mysql_hostgroup_attributes SET " \
            + ", ".join([f"{k} = %s" for k in to_update.keys()]) \
            + " WHERE hostgroup_id = %s"
        args = [*list(to_update.values()), self.hostgroup_id]
        cursor.execute(query, args)
        return True

    def manage_config(self, cursor, state):
        if state and not self.check_mode:
            if self.save_to_disk:
                save_config_to_disk(cursor, "SERVERS")

            if self.load_to_runtime:
                load_config_to_runtime(cursor, "SERVERS")

    def _as_fields(self):
        return {
            'hostgroup_id': self.hostgroup_id,
            'max_num_online_servers': self.max_num_online_servers,
            'autocommit': self.autocommit,
            'free_connections_pct': self.free_connections_pct,
            'init_connect': self.init_connect,
            'multiplex': self.multiplex,
            'connection_warming': self.connection_warming,
            'throttle_connections_per_sec': self.throttle_connections_per_sec,
            'ignore_session_variables': self.ignore_session_variables,
            'hostgroup_settings': self.hostgroup_settings,
            'servers_defaults': self.servers_defaults,
            'comment': self.comment,
        }


# ===========================================
# Module execution.
#
def main():
    argument_spec = proxysql_common_argument_spec()
    argument_spec.update(
        state=dict(default='present', choices=['present',
                                               'absent']),
        save_to_disk=dict(default=True, type='bool'),
        load_to_runtime=dict(default=True, type='bool'),

        hostgroup_id=dict(required=True, type='int'),
        max_num_online_servers=dict(type='int', default=1000000),
        autocommit=dict(type='int', default=-1),
        free_connections_pct=dict(type='int', default=10),
        init_connect=dict(type='str', default=''),
        multiplex=dict(type='int', default=1),
        connection_warming=dict(type='int', default=0),
        throttle_connections_per_sec=dict(type='int', default=1000000),
        ignore_session_variables=dict(type='str', default=''),
        hostgroup_settings=dict(type='str', default=''),
        servers_defaults=dict(type='str', default=''),
        comment=dict(type='str', default=''),
    )

    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=argument_spec
    )

    validate_args(module)

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
            msg=f"Unable to connect to ProxySQL Admin Module.. {to_native(e)}"
        )

    hostgroup_attributes = ProxySQLHostgroupAttributes(module, version)
    result = {}

    result['state'] = hostgroup_attributes.state
    result['changed'] = False

    if hostgroup_attributes.state == "present":
        try:
            if not hostgroup_attributes.check_exists(cursor, keys=True):
                hostgroup_attributes.create(result, cursor)
            else:
                hostgroup_attributes.update(result, cursor)

        except mysql_driver.Error as e:
            module.fail_json(
                msg="unable to modify hostgroup attributes.. %s" % to_native(e)
            )

    elif hostgroup_attributes.state == "absent":
        try:
            if hostgroup_attributes.check_exists(cursor, keys=True):
                hostgroup_attributes.delete(result, cursor)
            else:
                result['changed'] = False
                result['msg'] = ("The mysql_hostgroup_attributes is absent" +
                                 " from mysql_hostgroup_attributes memory" +
                                 " configuration")

        except mysql_driver.Error as e:
            module.fail_json(
                msg="Unable to delete hostgroup attributes.. %s" % to_native(e)
            )

    module.exit_json(**result)


if __name__ == '__main__':
    main()
