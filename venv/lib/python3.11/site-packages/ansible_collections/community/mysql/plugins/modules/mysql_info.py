#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: mysql_info
short_description: Gather information about MySQL or MariaDB servers
description:
- Gathers information about MySQL or MariaDB servers.

options:
  filter:
    description:
    - Limit the collected information by comma separated string or YAML list.
    - Allowable values are C(version), C(databases), C(settings), C(global_status),
      C(users), C(users_info), C(engines), C(master_status), C(slave_status), C(slave_hosts).
    - By default, collects all subsets.
    - You can use '!' before value (for example, C(!settings)) to exclude it from the information.
    - If you pass including and excluding values to the filter, for example, I(filter=!settings,version),
      the excluding values, C(!settings) in this case, will be ignored.
    type: list
    elements: str
  login_db:
    description:
    - Database name to connect to.
    - It makes sense if I(login_user) is allowed to connect to a specific database only.
    type: str
  exclude_fields:
    description:
    - List of fields which are not needed to collect.
    - "Supports elements: C(db_size), C(db_table_count). Unsupported elements will be ignored."
    type: list
    elements: str
    version_added: '0.1.0'
  return_empty_dbs:
    description:
    - Includes names of empty databases to returned dictionary.
    type: bool
    default: false

notes:
- Compatible with MariaDB or MySQL.
- Calculating the size of a database might be slow, depending on the number and size of tables in it.
  To avoid this, use I(exclude_fields=db_size).
- filters C(users_info) doesn't support MariaDB roles.

attributes:
  check_mode:
    support: full

seealso:
- module: community.mysql.mysql_variables
- module: community.mysql.mysql_db
- module: community.mysql.mysql_user
- module: community.mysql.mysql_replication

author:
- Andrew Klychkov (@Andersson007)
- Sebastian Gumprich (@rndmh3ro)
- Laurent Indermühle (@laurent-indermuehle)

extends_documentation_fragment:
- community.mysql.mysql
'''

EXAMPLES = r'''
# Display info from mysql-hosts group (using creds from ~/.my.cnf to connect):
# ansible mysql-hosts -m mysql_info

# Display only databases and users info:
# ansible mysql-hosts -m mysql_info -a 'filter=databases,users'

# Display all users privileges:
# ansible mysql-hosts -m mysql_info -a 'filter=users_info'

# Display only slave status:
# ansible standby -m mysql_info -a 'filter=slave_status'

# Display all info from databases group except settings:
# ansible databases -m mysql_info -a 'filter=!settings'

# If you encounter the "Please explicitly state intended protocol" error,
# use the login_unix_socket argument
- name: Collect all possible information using passwordless root access
  community.mysql.mysql_info:
    login_user: root
    login_unix_socket: /run/mysqld/mysqld.sock

- name: Get MySQL version with non-default credentials
  community.mysql.mysql_info:
    login_user: mysuperuser
    login_password: mysuperpass
    filter: version

- name: Collect all info except settings and users by root
  community.mysql.mysql_info:
    login_user: root
    login_password: rootpass
    filter: "!settings,!users"

- name: Collect info about databases and version using ~/.my.cnf as a credential file
  become: true
  community.mysql.mysql_info:
    filter:
    - databases
    - version

- name: Collect info about databases and version using ~alice/.my.cnf as a credential file
  become: true
  community.mysql.mysql_info:
    config_file: /home/alice/.my.cnf
    filter:
    - databases
    - version

- name: Collect info about databases including empty and excluding their sizes
  become: true
  community.mysql.mysql_info:
    config_file: /home/alice/.my.cnf
    filter:
    - databases
    exclude_fields: db_size
    return_empty_dbs: true

- name: Clone users from one server to another
  block:
  # Step 1
  - name: Fetch information from a source server
    delegate_to: server_source
    community.mysql.mysql_info:
      filter:
        - users_info
    register: result

  # Step 2
  # Don't work with sha256_password and cache_sha2_password
  - name: Clone users fetched in a previous task to a target server
    community.mysql.mysql_user:
      name: "{{ item.name }}"
      host: "{{ item.host }}"
      plugin: "{{ item.plugin | default(omit) }}"
      plugin_auth_string: "{{ item.plugin_auth_string | default(omit) }}"
      plugin_hash_string: "{{ item.plugin_hash_string | default(omit) }}"
      tls_requires: "{{ item.tls_requires | default(omit) }}"
      priv: "{{ item.priv | default(omit) }}"
      resource_limits: "{{ item.resource_limits | default(omit) }}"
      locked: "{{ item.locked | default(omit) }}"
      column_case_sensitive: true
      state: present
    loop: "{{ result.users_info }}"
    loop_control:
      label: "{{ item.name }}@{{ item.host }}"
    when:
      - item.name != 'root'  # In case you don't want to import admin accounts
      - item.name != 'mariadb.sys'
      - item.name != 'mysql'
      - item.name != 'PUBLIC'  # MariaDB roles are not supported
'''

RETURN = r'''
server_engine:
  description: Database server engine.
  returned: if not excluded by filter
  type: str
  sample: 'MariaDB'
  version_added: '3.10.0'
version:
  description: Database server version.
  returned: if not excluded by filter
  type: dict
  sample: { "version": { "major": 5, "minor": 5, "release": 60, "suffix": "MariaDB", "full": "5.5.60-MariaDB" } }
  contains:
    major:
      description: Major server version.
      returned: if not excluded by filter
      type: int
      sample: 5
    minor:
      description: Minor server version.
      returned: if not excluded by filter
      type: int
      sample: 5
    release:
      description: Release server version.
      returned: if not excluded by filter
      type: int
      sample: 60
    suffix:
      description: Server suffix, for example MySQL, MariaDB, other or none.
      returned: if not excluded by filter
      type: str
      sample: "MariaDB"
    full:
      description: Full server version.
      returned: if not excluded by filter
      type: str
      sample: "5.5.60-MariaDB"
databases:
  description: Information about databases.
  returned: if not excluded by filter
  type: dict
  sample:
  - { "mysql": { "size": 656594, "tables": 31 }, "information_schema": { "size": 73728, "tables": 79 } }
  contains:
    size:
      description: Database size in bytes.
      returned: if not excluded by filter
      type: dict
      sample: { 'size': 656594 }
    tables:
      description: Count of tables and views in that database.
      returned: if not excluded by filter
      type: dict
      sample: { 'tables': 12 }
      version_added: '3.11.0'
settings:
  description: Global settings (variables) information.
  returned: if not excluded by filter
  type: dict
  sample:
  - { "innodb_open_files": 300, innodb_page_size": 16384 }
global_status:
  description: Global status information.
  returned: if not excluded by filter
  type: dict
  sample:
  - { "Innodb_buffer_pool_read_requests": 123, "Innodb_buffer_pool_reads": 32 }
users:
  description: Return a dictionnary of users grouped by host and with global privileges only.
  returned: if not excluded by filter
  type: dict
  sample:
  - { "localhost": { "root": { "Alter_priv": "Y", "Alter_routine_priv": "Y" } } }
users_info:
  description:
    - Information about users accounts.
    - The output can be used as an input of the M(community.mysql.mysql_user) plugin.
    - Useful when migrating accounts to another server or to create an inventory.
    - Does not support proxy privileges. If an account has proxy privileges, they won't appear in the output.
    - Causes issues with authentications plugins C(sha256_password) and C(caching_sha2_password).
      If the output is fed to M(community.mysql.mysql_user), the
      ``plugin_auth_string`` will most likely be unreadable due to non-binary
      characters.
    - The "locked" field was aded in ``community.mysql`` 3.13.
  returned: if not excluded by filter
  type: dict
  sample:
  - { "plugin_auth_string": '*1234567',
      "name": "user1",
      "host": "host.com",
      "plugin": "mysql_native_password",
      "priv": "db1.*:SELECT/db2.*:SELECT",
      "resource_limits": { "MAX_USER_CONNECTIONS": 100 },
      "tls_requires": { "SSL": null },
      "locked": false }
  version_added: '3.8.0'
engines:
  description: Information about the server's storage engines.
  returned: if not excluded by filter
  type: dict
  sample:
  - { "CSV": { "Comment": "CSV storage engine", "Savepoints": "NO", "Support": "YES", "Transactions": "NO", "XA": "NO" } }
master_status:
  description: Master status information.
  returned: if master
  type: dict
  sample:
  - { "Binlog_Do_DB": "", "Binlog_Ignore_DB": "mysql", "File": "mysql-bin.000001", "Position": 769 }
slave_status:
  description: Slave status information.
  returned: if standby
  type: dict
  sample:
  - { "192.168.1.101": { "3306": { "replication_user": { "Connect_Retry": 60, "Exec_Master_Log_Pos": 769,  "Last_Errno": 0 } } } }
slave_hosts:
  description: Slave status information.
  returned: if master
  type: dict
  sample:
  - { "2": { "Host": "", "Master_id": 1, "Port": 3306 } }
connector_name:
  description: Name of the python connector used by the module. When the connector is not identified, returns C(Unknown).
  returned: always
  type: str
  sample:
  - "pymysql"
  version_added: '3.6.0'
connector_version:
  description: Version of the python connector used by the module. When the connector is not identified, returns C(Unknown).
  returned: always
  type: str
  sample:
  - "1.0.2"
  version_added: '3.6.0'
'''

from decimal import Decimal

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.mysql.plugins.module_utils.command_resolver import (
    CommandResolver
)
from ansible_collections.community.mysql.plugins.module_utils.mysql import (
    mysql_connect,
    mysql_common_argument_spec,
    mysql_driver,
    mysql_driver_fail_msg,
    get_connector_name,
    get_connector_version,
    get_server_implementation,
    get_server_version,
)

from ansible_collections.community.mysql.plugins.module_utils.user import (
    privileges_get,
    get_resource_limits,
    get_existing_authentication,
    get_user_implementation,
    user_is_locked,
)
from ansible.module_utils.six import iteritems
from ansible.module_utils._text import to_native


# ===========================================
# MySQL module specific support methods.
#

class MySQL_Info(object):

    """Class for collection MySQL instance information.

    Arguments:
        module (AnsibleModule): Object of AnsibleModule class.
        cursor (pymysql/mysql-python): Cursor class for interaction with
            the database.

    Note:
        If you need to add a new subset:
        1. add a new key with the same name to self.info attr in self.__init__()
        2. add a new private method to get the information
        3. add invocation of the new method to self.__collect()
        4. add info about the new subset to the DOCUMENTATION block
        5. add info about the new subset with an example to RETURN block
    """

    def __init__(self, module, cursor, server_implementation, server_version, user_implementation):
        self.module = module
        self.cursor = cursor
        self.server_implementation = server_implementation
        self.server_version = server_version
        self.user_implementation = user_implementation
        self.command_resolver = CommandResolver(self.server_implementation, self.server_version)
        self.info = {
            'version': {},
            'databases': {},
            'settings': {},
            'global_status': {},
            'engines': {},
            'users': {},
            'users_info': {},
            'master_status': {},
            'slave_hosts': {},
            'slave_status': {},
        }

    def get_info(self, filter_, exclude_fields, return_empty_dbs):
        """Get MySQL instance information based on filter_.

        Arguments:
            filter_ (list): List of collected subsets (e.g., databases, users, etc.),
                when it is empty, return all available information.
        """

        inc_list = []
        exc_list = []

        if filter_:
            partial_info = {}

            for fi in filter_:
                if fi.lstrip('!') not in self.info:
                    self.module.warn('filter element: %s is not allowable, ignored' % fi)
                    continue

                if fi[0] == '!':
                    exc_list.append(fi.lstrip('!'))

                else:
                    inc_list.append(fi)

            if inc_list:
                self.__collect(exclude_fields, return_empty_dbs, set(inc_list))

                for i in self.info:
                    if i in inc_list:
                        partial_info[i] = self.info[i]

            else:
                not_in_exc_list = list(set(self.info) - set(exc_list))
                self.__collect(exclude_fields, return_empty_dbs, set(not_in_exc_list))

                for i in self.info:
                    if i not in exc_list:
                        partial_info[i] = self.info[i]

            return partial_info

        else:
            self.__collect(exclude_fields, return_empty_dbs, set(self.info))
            return self.info

    def __collect(self, exclude_fields, return_empty_dbs, wanted):
        """Collect all possible subsets."""
        if 'version' in wanted or 'settings' in wanted:
            self.__get_global_variables()

        if 'databases' in wanted:
            self.__get_databases(exclude_fields, return_empty_dbs)

        if 'global_status' in wanted:
            self.__get_global_status()

        if 'engines' in wanted:
            self.__get_engines()

        if 'users' in wanted:
            self.__get_users()

        if 'users_info' in wanted:
            self.__get_users_info()

        if 'master_status' in wanted:
            self.__get_master_status()

        if 'slave_status' in wanted:
            self.__get_slave_status()

        if 'slave_hosts' in wanted:
            self.__get_slaves()

    def __get_engines(self):
        """Get storage engines info."""
        res = self.__exec_sql('SHOW ENGINES')

        if res:
            for line in res:
                engine = line['Engine']
                self.info['engines'][engine] = {}

                for vname, val in iteritems(line):
                    if vname != 'Engine':
                        self.info['engines'][engine][vname] = val

    def __convert(self, val):
        """Convert unserializable data."""
        try:
            if isinstance(val, Decimal):
                val = float(val)
            else:
                val = int(val)

        except ValueError:
            pass

        except TypeError:
            pass

        return val

    def __get_global_variables(self):
        """Get global variables (instance settings)."""
        res = self.__exec_sql('SHOW GLOBAL VARIABLES')

        if res:
            for var in res:
                self.info['settings'][var['Variable_name']] = self.__convert(var['Value'])

            # version = ["5", "5," "60-MariaDB]
            version = self.info['settings']['version'].split('.')

            # full_version = "5.5.60-MariaDB"
            full = self.info['settings']['version']

            # release = "60"
            release = version[2].split('-')[0]

            # check if a suffix exists by counting the length
            if len(version[2].split('-')) > 1:
                # suffix = "MariaDB"
                suffix = version[2].split('-', 1)[1]
            else:
                suffix = ""

            self.info['version'] = dict(
                # major = "5"
                major=int(version[0]),
                # minor = "5"
                minor=int(version[1]),
                release=int(release),
                suffix=str(suffix),
                full=str(full),
            )

    def __get_global_status(self):
        """Get global status."""
        res = self.__exec_sql('SHOW GLOBAL STATUS')

        if res:
            for var in res:
                self.info['global_status'][var['Variable_name']] = self.__convert(var['Value'])

    def __get_master_status(self):
        """Get master status if the instance is a master."""
        query = self.command_resolver.resolve_command("SHOW MASTER STATUS")
        res = self.__exec_sql(query)
        if res:
            for line in res:
                for vname, val in iteritems(line):
                    self.info['master_status'][vname] = self.__convert(val)

    def __get_slave_status(self):
        """Get slave status if the instance is a slave."""
        query = self.command_resolver.resolve_command("SHOW SLAVE STATUS")
        res = self.__exec_sql(query)
        if res:
            for line in res:
                host = line.get('Master_Host') or line.get('Source_Host')
                if host not in self.info['slave_status']:
                    self.info['slave_status'][host] = {}

                port = line.get('Master_Port') or line.get('Source_Port')
                if port not in self.info['slave_status'][host]:
                    self.info['slave_status'][host][port] = {}

                user = line.get('Master_User') or line.get('Source_User')
                if user not in self.info['slave_status'][host][port]:
                    self.info['slave_status'][host][port][user] = {}

                for vname, val in iteritems(line):
                    if vname not in ('Master_Host', 'Master_Port', 'Master_User', 'Source_Host', 'Source_Port', 'Source_User'):
                        self.info['slave_status'][host][port][user][vname] = self.__convert(val)

    def __get_slaves(self):
        """Get slave hosts info if the instance is a master."""
        query = self.command_resolver.resolve_command("SHOW SLAVE HOSTS")
        res = self.__exec_sql(query)
        if res:
            for line in res:
                srv_id = line['Server_id']
                if srv_id not in self.info['slave_hosts']:
                    self.info['slave_hosts'][srv_id] = {}

                for vname, val in iteritems(line):
                    if vname != 'Server_id':
                        self.info['slave_hosts'][srv_id][vname] = self.__convert(val)

    def __get_users(self):
        """Get user info."""
        res = self.__exec_sql('SELECT * FROM mysql.user')
        if res:
            for line in res:
                host = line['Host']
                if host not in self.info['users']:
                    self.info['users'][host] = {}

                user = line['User']
                self.info['users'][host][user] = {}

                for vname, val in iteritems(line):
                    if vname not in ('Host', 'User'):
                        self.info['users'][host][user][vname] = self.__convert(val)

    def __get_users_info(self):
        """Get user privileges, passwords, resources_limits, ...

        Query the server to get all the users and return a string
        of privileges that can be used by the mysql_user plugin.
        For instance:

        "users_info": [
            {
                "host": "users_info.com",
                "priv": "*.*: ALL,GRANT",
                "name": "users_info_adm"
            },
            {
                "host": "users_info.com",
                "priv": "`mysql`.*: SELECT/`users_info_db`.*: SELECT",
                "name": "users_info_multi"
            }
        ]
        """
        res = self.__exec_sql('SELECT * FROM mysql.user')
        if not res:
            return None

        output = list()
        for line in res:
            user = line['User']
            host = line['Host']

            # MariaDB roles have no host
            is_role = self.server_implementation == 'mariadb' and not host
            user_priv = privileges_get(self.cursor, user, host, maria_role=is_role)

            if not user_priv:
                self.module.warn("No privileges found for %s on host %s" % (user, host))
                continue

            priv_string = list()
            for db_table, priv in user_priv.items():
                # Proxy privileges are hard to work with because of different quotes or
                # backticks like ''@'', ''@'%' or even ``@``. In addition, MySQL will
                # forbid you to grant a proxy privileges through TCP.
                if set(priv) == {'PROXY', 'GRANT'} or set(priv) == {'PROXY'}:
                    continue

                unquote_db_table = db_table.replace('`', '').replace("'", '')
                priv_string.append('%s:%s' % (unquote_db_table, ','.join(priv)))

            # Only keep *.* USAGE if it's the only user privilege given
            if len(priv_string) > 1 and '*.*:USAGE' in priv_string:
                priv_string.remove('*.*:USAGE')

            resource_limits = get_resource_limits(self.cursor, user, host)
            copy_ressource_limits = dict.copy(resource_limits)

            tls_requires = self.user_implementation.get_tls_requires(
                self.cursor, user, host)

            output_dict = {
                'name': user,
                'host': host,
                'priv': '/'.join(priv_string),
                'resource_limits': copy_ressource_limits,
                'tls_requires': tls_requires,
            }

            # Prevent returning a resource limit if empty
            if resource_limits:
                for key, value in resource_limits.items():
                    if value == 0:
                        del output_dict['resource_limits'][key]
                if len(output_dict['resource_limits']) == 0:
                    del output_dict['resource_limits']

            # Prevent returning tls_require if empty
            if not tls_requires:
                del output_dict['tls_requires']

            authentications = get_existing_authentication(self.cursor, user, host)
            if authentications:
                output_dict.update(authentications[0])

            if line.get('is_role') and line['is_role'] == 'N':
                output_dict['locked'] = user_is_locked(self.cursor, user, host)

            # TODO password_option
            # but both are not supported by mysql_user atm. So no point yet.

            output.append(output_dict)

        self.info['users_info'] = output

    def __get_databases(self, exclude_fields, return_empty_dbs):
        """Get info about databases."""

        def is_field_included(field_name):
            return not exclude_fields or 'db_{}'.format(field_name) not in exclude_fields

        def create_db_info(db_data):
            info = {}
            if is_field_included('size'):
                info['size'] = int(db_data.get('size', 0) or 0)
            if is_field_included('table_count'):
                info['tables'] = int(db_data.get('tables', 0) or 0)
            return info

        # Build the main query
        query_parts = ['SELECT table_schema AS "name"']
        if is_field_included('size'):
            query_parts.append('SUM(data_length + index_length) AS "size"')
        if is_field_included('table_count'):
            query_parts.append('COUNT(table_name) as "tables"')

        query = "{} FROM information_schema.TABLES GROUP BY table_schema".format(", ".join(query_parts))

        # Get and process databases with tables
        databases = self.__exec_sql(query) or []
        for db in databases:
            self.info['databases'][db['name']] = create_db_info(db)

        # Handle empty databases if requested
        if return_empty_dbs:
            empty_databases = self.__exec_sql('SHOW DATABASES') or []
            for db in empty_databases:
                db_name = db['Database']
                if db_name not in self.info['databases']:
                    self.info['databases'][db_name] = create_db_info({})

    def __exec_sql(self, query, ddl=False):
        """Execute SQL.

        Arguments:
            ddl (bool): If True, return True or False.
                Used for queries that don't return any rows
                (mainly for DDL queries) (default False).
        """
        try:
            self.cursor.execute(query)

            if not ddl:
                res = self.cursor.fetchall()
                return res
            return True

        except Exception as e:
            self.module.fail_json(msg="Cannot execute SQL '%s': %s" % (query, to_native(e)))
        return False


# ===========================================
# Module execution.
#


def main():
    argument_spec = mysql_common_argument_spec()
    argument_spec.update(
        login_db=dict(type='str'),
        filter=dict(type='list', elements='str'),
        exclude_fields=dict(type='list', elements='str'),
        return_empty_dbs=dict(type='bool', default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    db = module.params['login_db']
    connect_timeout = module.params['connect_timeout']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    ssl_cert = module.params['client_cert']
    ssl_key = module.params['client_key']
    ssl_ca = module.params['ca_cert']
    check_hostname = module.params['check_hostname']
    config_file = module.params['config_file']
    filter_ = module.params['filter']
    exclude_fields = module.params['exclude_fields']
    return_empty_dbs = module.params['return_empty_dbs']

    if filter_:
        filter_ = [f.strip() for f in filter_]

    if exclude_fields:
        exclude_fields = set([f.strip() for f in exclude_fields])

    if mysql_driver is None:
        module.fail_json(msg=mysql_driver_fail_msg)

    connector_name = get_connector_name(mysql_driver)
    connector_version = get_connector_version(mysql_driver)

    try:
        cursor, db_conn = mysql_connect(module, login_user, login_password,
                                        config_file, ssl_cert, ssl_key, ssl_ca, db,
                                        check_hostname=check_hostname,
                                        connect_timeout=connect_timeout, cursor_class='DictCursor')
    except Exception as e:
        msg = ('unable to connect to database using %s %s, check login_user '
               'and login_password are correct or %s has the credentials. '
               'Exception message: %s' % (connector_name, connector_version, config_file, to_native(e)))
        module.fail_json(msg)

    server_implementation = get_server_implementation(cursor)
    server_version = get_server_version(cursor)
    user_implementation = get_user_implementation(cursor)

    ###############################
    # Create object and do main job

    mysql = MySQL_Info(module, cursor, server_implementation, server_version, user_implementation)

    module.exit_json(changed=False,
                     server_engine='MariaDB' if server_implementation == 'mariadb' else 'MySQL',
                     connector_name=connector_name,
                     connector_version=connector_version,
                     **mysql.get_info(filter_, exclude_fields, return_empty_dbs))


if __name__ == '__main__':
    main()
