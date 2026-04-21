#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Andrew Klychkov <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: mysql_role

short_description: Adds, removes, or updates a MySQL or MariaDB role

description:
   - Adds, removes, or updates a MySQL or MariaDB role.
   - Roles are supported since MySQL 8.0.0 and MariaDB 10.0.5.

version_added: '2.2.0'

options:
  name:
    description:
      - Name of the role to add or remove.
    type: str
    required: true

  admin:
    description:
      - Supported by B(MariaDB).
      - Name of the admin user of the role (the I(login_user), by default).
    type: str

  priv:
    description:
      - "MySQL privileges string in the format: C(db.table:priv1,priv2)."
      - "You can specify multiple privileges by separating each one using
        a forward slash: C(db.table:priv/db.table:priv)."
      - The format is based on MySQL C(GRANT) statement.
      - Database and table names can be quoted, MySQL-style.
      - If column privileges are used, the C(priv1,priv2) part must be
        exactly as returned by a C(SHOW GRANT) statement. If not followed,
        the module will always report changes. It includes grouping columns
        by permission (C(SELECT(col1,col2)) instead of C(SELECT(col1),SELECT(col2))).
      - Can be passed as a dictionary (see the examples).
      - Supports GRANTs for procedures and functions
        (see the examples for the M(community.mysql.mysql_user) module).
    type: raw

  append_privs:
    description:
      - Append the privileges defined by the I(priv) option to the existing ones
        for this role instead of overwriting them. Mutually exclusive with I(subtract_privs).
    type: bool
    default: false

  subtract_privs:
    description:
      - Revoke the privileges defined by the I(priv) option and keep other existing privileges.
        If set, invalid privileges in I(priv) are ignored.
        Mutually exclusive with I(append_privs).
    version_added: '3.2.0'
    type: bool
    default: false

  members:
    description:
      - List of members of the role.
      - For users, use the format C(username@hostname).
        Always specify the hostname part explicitly.
      - For roles, use the format C(rolename).
      - Mutually exclusive with I(admin).
    type: list
    elements: str

  append_members:
    description:
      - Add members defined by the I(members) option to the existing ones
        for this role instead of overwriting them.
      - Mutually exclusive with the I(detach_members) and I(admin) option.
    type: bool
    default: false

  detach_members:
    description:
      - Detaches members defined by the I(members) option from the role
        instead of overwriting all the current members.
      - Mutually exclusive with the I(append_members) and I(admin) option.
    type: bool
    default: false

  set_default_role_all:
    description:
      - Is not supported by MariaDB and is silently ignored when working with MariaDB.
      - If C(yes), runs B(SET DEFAULT ROLE ALL TO) each of the I(members) when changed.
      - If you want to avoid this behavior, set this option to C(no) explicitly.
    type: bool
    default: true

  state:
    description:
      - If C(present) and the role does not exist, creates the role.
      - If C(present) and the role exists, does nothing or updates its attributes.
      - If C(absent), removes the role.
    type: str
    choices: [ absent, present ]
    default: present

  check_implicit_admin:
    description:
      - Check if mysql allows login as root/nopassword before trying supplied credentials.
      - If success, passed I(login_user)/I(login_password) will be ignored.
    type: bool
    default: false

  members_must_exist:
    description:
      - When C(yes), the module fails if any user in I(members) does not exist.
      - When C(no), users in I(members) which don't exist are simply skipped.
    type: bool
    default: true

  column_case_sensitive:
    description:
      - The default is C(false).
      - When C(true), the module will not uppercase the field in the privileges.
      - When C(false), the field names will be upper-cased. This was the default before this
        feature was introduced but since MySQL/MariaDB is case sensitive you should set this
        to C(true) in most cases.
    type: bool
    version_added: '3.8.0'

notes:
  - Roles are supported since MySQL 8.0.0 and MariaDB 10.0.5.
  - Pay attention that the module runs C(SET DEFAULT ROLE ALL TO)
    all the I(members) passed by default when the state has changed.
    If you want to avoid this behavior, set I(set_default_role_all) to C(no).

attributes:
  check_mode:
    support: full

seealso:
  - module: community.mysql.mysql_user
  - name: MySQL role reference
    description: Complete reference of the MySQL role documentation.
    link: https://dev.mysql.com/doc/refman/8.0/en/create-role.html

author:
  - Andrew Klychkov (@Andersson007)
  - Felix Hamme (@betanummeric)
  - kmarse (@kmarse)
  - Laurent Indermühle (@laurent-indermuehle)

extends_documentation_fragment:
  - community.mysql.mysql
'''

EXAMPLES = r'''
# If you encounter the "Please explicitly state intended protocol" error,
# use the login_unix_socket argument, for example, login_unix_socket: /run/mysqld/mysqld.sock

# Example of a .my.cnf file content for setting a root password
# [client]
# user=root
# password=n<_665{vS43y
#
# Example of a privileges dictionary passed through the priv option
# priv:
#   'mydb.*': 'INSERT,UPDATE'
#   'anotherdb.*': 'SELECT'
#   'yetanotherdb.*': 'ALL'
#
# You can also use the string format like in the community.mysql.mysql_user module, for example
# mydb.*:INSERT,UPDATE/anotherdb.*:SELECT/yetanotherdb.*:ALL
#
# For more examples on how to specify privileges, refer to the community.mysql.mysql_user module

# Create a role developers with all database privileges
# and add alice and bob as members.
# The statement 'SET DEFAULT ROLE ALL' to them will be run.
- name: Create role developers, add members
  community.mysql.mysql_role:
    name: developers
    state: present
    priv: '*.*:ALL'
    members:
    - 'alice@%'
    - 'bob@%'

- name: Same as above but do not run SET DEFAULT ROLE ALL TO each member
  community.mysql.mysql_role:
    name: developers
    state: present
    priv: '*.*:ALL'
    members:
    - 'alice@%'
    - 'bob@%'
    set_default_role_all: false

# Assuming that the role developers exists,
# add john to the current members
- name: Add members to an existing role
  community.mysql.mysql_role:
    name: developers
    state: present
    append_members: true
    members:
    - 'joe@localhost'

# Create role readers with the SELECT privilege
# on all tables in the fiction database
- name: Create role developers, add members
  community.mysql.mysql_role:
    name: readers
    state: present
    priv: 'fiction.*:SELECT'

# Assuming that the role readers exists,
# add the UPDATE privilege to the role on all tables in the fiction database
- name: Create role developers, add members
  community.mysql.mysql_role:
    name: readers
    state: present
    priv: 'fiction.*:UPDATE'
    append_privs: true

- name: Create role with the 'SELECT' and 'UPDATE' privileges in db1 and db2
  community.mysql.mysql_role:
    state: present
    name: foo
    priv:
      'db1.*': 'SELECT,UPDATE'
      'db2.*': 'SELECT,UPDATE'

- name: Remove joe from readers
  community.mysql.mysql_role:
    state: present
    name: readers
    members:
    - 'joe@localhost'
    detach_members: true

- name: Remove the role readers if exists
  community.mysql.mysql_role:
    state: absent
    name: readers

- name: Example of using login_unix_socket to connect to the server
  community.mysql.mysql_role:
    name: readers
    state: present
    login_unix_socket: /var/run/mysqld/mysqld.sock

# Pay attention that the admin cannot be changed later
# and will be ignored if a role currently exists.
# To change members, you need to run a separate task using the admin
# of the role as the login_user.
- name: On MariaDB, create the role readers with alice as its admin
  community.mysql.mysql_role:
    state: present
    name: readers
    admin: 'alice@%'

- name: Create the role business, add the role marketing to members
  community.mysql.mysql_role:
    state: present
    name: business
    members:
    - marketing

- name: Ensure the role foo does not have the DELETE privilege
  community.mysql.mysql_role:
    state: present
    name: foo
    subtract_privs: true
    priv:
      'db1.*': DELETE

- name: Add some members to a role and skip not-existent users
  community.mysql.mysql_role:
    state: present
    name: foo
    append_members: true
    members_must_exist: false
    members:
    - 'existing_user@localhost'
    - 'not_existing_user@localhost'

- name: Detach some members from a role and ignore not-existent users
  community.mysql.mysql_role:
    state: present
    name: foo
    detach_members: true
    members_must_exist: false
    members:
    - 'existing_user@localhost'
    - 'not_existing_user@localhost'
'''

RETURN = '''#'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.mysql.plugins.module_utils.mysql import (
    mysql_connect,
    mysql_driver,
    mysql_driver_fail_msg,
    mysql_common_argument_spec
)
from ansible_collections.community.mysql.plugins.module_utils.user import (
    convert_priv_dict_to_str,
    get_user_implementation,
    get_mode,
    user_mod,
    privileges_grant,
    privileges_unpack,
)
from ansible.module_utils._text import to_native
from ansible.module_utils.six import iteritems


def normalize_users(module, users, is_mariadb=False):
    """Normalize passed user names.

    Example of transformation:
    ['user0'] => [('user0', '')] / ['user0'] => [('user0', '%')]
    ['user0@host0'] => [('user0', 'host0')]

    Args:
        module (AnsibleModule): Object of the AnsibleModule class.
        users (list): List of user names.
        is_mariadb (bool): Flag indicating we are working with MariaDB

    Returns:
        list: List of tuples like [('user0', ''), ('user0', 'host0')].
    """
    normalized_users = []

    for user in users:
        try:
            tmp = user.split('@')

            if tmp[0] == '':
                module.fail_json(msg="Member's name cannot be empty.")

            if len(tmp) == 1:
                if not is_mariadb:
                    normalized_users.append((tmp[0], '%'))
                else:
                    normalized_users.append((tmp[0], ''))

            elif len(tmp) == 2:
                normalized_users.append((tmp[0], tmp[1]))

        except Exception as e:
            msg = ('Error occured while parsing the name "%s": %s. '
                   'It must be in the format "username" or '
                   '"username@hostname" ' % (user, to_native(e)))
            module.fail_json(msg=msg)

    return normalized_users


class DbServer():
    """Class to fetch information from a database.

    Args:
        module (AnsibleModule): Object of the AnsibleModule class.
        cursor (cursor): Cursor object of a database Python connector.

    Attributes:
        module (AnsibleModule): Object of the AnsibleModule class.
        cursor (cursor): Cursor object of a database Python connector.
        role_impl (library): Corresponding library depending
            on a server type (MariaDB or MySQL)
        mariadb (bool): True if MariaDB, False otherwise.
        roles_supported (bool): True if roles are supported, False otherwise.
        users (set): Set of users existing in a DB in the form (username, hostname).
    """
    def __init__(self, module, cursor):
        self.module = module
        self.cursor = cursor
        self.role_impl = self.get_implementation()
        self.mariadb = self.role_impl.is_mariadb()
        self.roles_supported = self.role_impl.supports_roles(self.cursor)
        self.users = set(self.__get_users())

    def is_mariadb(self):
        """Get info whether a DB server is a MariaDB instance.

        Returns:
            self.mariadb: Attribute value.
        """
        return self.mariadb

    def supports_roles(self):
        """Get info whether a DB server supports roles.

        Returns:
            self.roles_supported: Attribute value.
        """
        return self.roles_supported

    def get_implementation(self):
        """Get a current server implementation depending on its type.

        Returns:
            library: Depending on a server type (MySQL or MariaDB).
        """
        self.cursor.execute("SELECT VERSION()")

        if 'mariadb' in self.cursor.fetchone()[0].lower():
            import ansible_collections.community.mysql.plugins.module_utils.implementations.mariadb.role as role_impl
        else:
            import ansible_collections.community.mysql.plugins.module_utils.implementations.mysql.role as role_impl

        return role_impl

    def check_users_in_db(self, users):
        """Check if users exist in a database.

        Args:
            users (list): List of tuples (username, hostname) to check.
        """
        for user in users:
            if user not in self.users:
                msg = 'User / role `%s` with host `%s` does not exist' % (user[0], user[1])
                self.module.fail_json(msg=msg)

    def filter_existing_users(self, users):
        for user in users:
            if user in self.users:
                yield user

    def __get_users(self):
        """Get users.

        Returns:
            list: List of tuples (username, hostname).
        """
        self.cursor.execute('SELECT User, Host FROM mysql.user')
        return self.cursor.fetchall()

    def get_users(self):
        """Get set of tuples (username, hostname) existing in a DB.

        Returns:
            self.users: Attribute value.
        """
        return self.users

    def get_grants(self, user, host):
        """Get grants.

        Args:
            user (str): User name
            host (str): Host name

        Returns:
            list: List of tuples like [(grant1,), (grant2,), ... ].
        """
        if host:
            self.cursor.execute('SHOW GRANTS FOR %s@%s', (user, host))
        else:
            self.cursor.execute('SHOW GRANTS FOR %s', (user,))

        return self.cursor.fetchall()


class MySQLQueryBuilder():
    """Class to build and return queries specific to MySQL.

    Args:
        name (str): Role name.
        host (str): Role host.

    Attributes:
        name (str): Role name.
        host (str): Role host.
    """
    def __init__(self, name, host):
        self.name = name
        self.host = host

    def role_exists(self):
        """Return a query to check if a role with self.name and self.host exists in a database.

        Returns:
            tuple: (query_string, tuple_containing_parameters).
        """
        return 'SELECT count(*) FROM mysql.user WHERE user = %s AND host = %s', (self.name, self.host)

    def role_grant(self, user):
        """Return a query to grant a role to a user or a role.

        Args:
            user (tuple): User / role to grant the role to in the form (username, hostname).

        Returns:
            tuple: (query_string, tuple_containing_parameters).
        """
        if user[1]:
            return 'GRANT %s@%s TO %s@%s', (self.name, self.host, user[0], user[1])
        else:
            return 'GRANT %s@%s TO %s', (self.name, self.host, user[0])

    def role_revoke(self, user):
        """Return a query to revoke a role from a user or role.

        Args:
            user (tuple): User / role to revoke the role from in the form (username, hostname).

        Returns:
            tuple: (query_string, tuple_containing_parameters).
        """
        if user[1]:
            return 'REVOKE %s@%s FROM %s@%s', (self.name, self.host, user[0], user[1])
        else:
            return 'REVOKE %s@%s FROM %s', (self.name, self.host, user[0])

    def role_create(self, admin=None):
        """Return a query to create a role.

        Args:
            admin (tuple): Admin user in the form (username, hostname).
                Because it is not supported by MySQL, we ignore it.

        Returns:
            tuple: (query_string, tuple_containing_parameters).
        """
        return 'CREATE ROLE %s', (self.name,)


class MariaDBQueryBuilder():
    """Class to build and return queries specific to MariaDB.

    Args:
        name (str): Role name.

    Attributes:
        name (str): Role name.
    """
    def __init__(self, name):
        self.name = name

    def role_exists(self):
        """Return a query to check if a role with self.name exists in a database.

        Returns:
            tuple: (query_string, tuple_containing_parameters).
        """
        return "SELECT count(*) FROM mysql.user WHERE user = %s AND is_role  = 'Y'", (self.name,)

    def role_grant(self, user):
        """Return a query to grant a role to a user or role.

        Args:
            user (tuple): User / role to grant the role to in the form (username, hostname).

        Returns:
            tuple: (query_string, tuple_containing_parameters).
        """
        if user[1]:
            return 'GRANT %s TO %s@%s', (self.name, user[0], user[1])
        else:
            return 'GRANT %s TO %s', (self.name, user[0])

    def role_revoke(self, user):
        """Return a query to revoke a role from a user or role.

        Args:
            user (tuple): User / role to revoke the role from in the form (username, hostname).

        Returns:
            tuple: (query_string, tuple_containing_parameters).
        """
        if user[1]:
            return 'REVOKE %s FROM %s@%s', (self.name, user[0], user[1])
        else:
            return 'REVOKE %s FROM %s', (self.name, user[0])

    def role_create(self, admin=None):
        """Return a query to create a role.

        Args:
            admin (tuple): Admin user in the form (username, hostname).

        Returns:
            tuple: (query_string, tuple_containing_parameters).
        """
        if not admin:
            return 'CREATE ROLE %s', (self.name,)

        if admin[1]:
            return 'CREATE ROLE %s WITH ADMIN %s@%s', (self.name, admin[0], admin[1])
        else:
            return 'CREATE ROLE %s WITH ADMIN %s', (self.name, admin[0])


class MySQLRoleImpl():
    """Class to work with MySQL role implementation.

    Args:
        module (AnsibleModule): Object of the AnsibleModule class.
        cursor (cursor): Cursor object of a database Python connector.
        name (str): Role name.
        host (str): Role host.

    Attributes:
        module (AnsibleModule): Object of the AnsibleModule class.
        cursor (cursor): Cursor object of a database Python connector.
        name (str): Role name.
        host (str): Role host.
    """
    def __init__(self, module, cursor, name, host):
        self.module = module
        self.cursor = cursor
        self.name = name
        self.host = host

    def set_default_role_all(self, user):
        """Run 'SET DEFAULT ROLE ALL TO' a user.

        Args:
            user (tuple): User / role to run the command against in the form (username, hostname).
        """
        if user[1]:
            self.cursor.execute('SET DEFAULT ROLE ALL TO %s@%s', (user[0], user[1]))
        else:
            self.cursor.execute('SET DEFAULT ROLE ALL TO %s', (user[0],))

    def get_admin(self):
        """Get a current admin of a role.

        Not supported by MySQL, so ignored here.
        """
        pass

    def set_admin(self, admin):
        """Set an admin of a role.

        Not supported by MySQL, so ignored here.

        TODO: Implement the feature if this gets supported.

        Args:
            admin (tuple): Admin user of the role in the form (username, hostname).
        """
        pass


class MariaDBRoleImpl():
    """Class to work with MariaDB role implementation.

    Args:
        module (AnsibleModule): Object of the AnsibleModule class.
        cursor (cursor): Cursor object of a database Python connector.
        name (str): Role name.

    Attributes:
        module (AnsibleModule): Object of the AnsibleModule class.
        cursor (cursor): Cursor object of a database Python connector.
        name (str): Role name.
    """
    def __init__(self, module, cursor, name):
        self.module = module
        self.cursor = cursor
        self.name = name

    def set_default_role_all(self, user):
        """Run 'SET DEFAULT ROLE ALL TO' a user.

        The command is not supported by MariaDB, ignored.

        Args:
            user (tuple): User / role to run the command against in the form (username, hostname).
        """
        pass

    def get_admin(self):
        """Get a current admin of a role.

        Returns:
            tuple: Of the form (username, hostname).
        """
        query = ("SELECT User, Host FROM mysql.roles_mapping "
                 "WHERE Role = %s and Admin_option = 'Y'")

        self.cursor.execute(query, (self.name,))
        return self.cursor.fetchone()

    def set_admin(self, admin):
        """Set an admin of a role.

        TODO: Implement changing when ALTER ROLE statement to
            change role's admin gets supported.

        Args:
            admin (tuple): Admin user of the role in the form (username, hostname).
        """
        admin_user = admin[0]
        admin_host = admin[1]
        current_admin = self.get_admin()

        if (admin_user, admin_host) != current_admin:
            msg = ('The "admin" option value and the current '
                   'roles admin (%s@%s) don not match. Ignored. '
                   'To change the admin, you need to drop and create the '
                   'role again.' % (current_admin[0], current_admin[1]))
            self.module.warn(msg)


class Role():
    """Class to work with MySQL role objects.

    Args:
        module (AnsibleModule): Object of the AnsibleModule class.
        cursor (cursor): Cursor object of a database Python connector.
        name (str): Role name.
        server (DbServer): Object of the DbServer class.

    Attributes:
        module (AnsibleModule): Object of the AnsibleModule class.
        cursor (cursor): Cursor object of a database Python connector.
        name (str): Role name.
        server (DbServer): Object of the DbServer class.
        host (str): Role's host.
        full_name (str): Role's full name.
        exists (bool): Indicates if a role exists or not.
        members (set): Set of current role's members.
    """
    def __init__(self, module, cursor, name, server):
        self.module = module
        self.cursor = cursor
        self.name = name
        self.server = server
        self.is_mariadb = self.server.is_mariadb()

        if self.is_mariadb:
            self.q_builder = MariaDBQueryBuilder(self.name)
            self.role_impl = MariaDBRoleImpl(self.module, self.cursor, self.name)
            self.full_name = '`%s`' % self.name
            self.host = ''
        else:
            self.host = '%'
            self.q_builder = MySQLQueryBuilder(self.name, self.host)
            self.role_impl = MySQLRoleImpl(self.module, self.cursor, self.name, self.host)
            self.full_name = '`%s`@`%s`' % (self.name, self.host)

        self.exists = self.__role_exists()
        self.members = set()

        if self.exists:
            self.members = self.__get_members()

    def __role_exists(self):
        """Check if a role exists.

        Returns:
            bool: True if the role exists, False if it does not.
        """
        self.cursor.execute(*self.q_builder.role_exists())
        return self.cursor.fetchone()[0] > 0

    def add(self, users, privs, check_mode=False, admin=False,
            set_default_role_all=True):
        """Add a role.

        Args:
            users (list): Role members.
            privs (str): String containing privileges.
            check_mode (bool): If True, just checks and does nothing.
            admin (tuple): Role's admin. Contains (username, hostname).
            set_default_role_all (bool): If True, runs SET DEFAULT ROLE ALL TO each member.

        Returns:
            bool: True if the state has changed, False if has not.
        """
        if check_mode:
            if not self.exists:
                return True
            return False

        self.cursor.execute(*self.q_builder.role_create(admin))

        if users:
            self.update_members(users, set_default_role_all=set_default_role_all)

        if privs:
            for db_table, priv in iteritems(privs):
                privileges_grant(self.cursor, self.name, self.host,
                                 db_table, priv, tls_requires=None,
                                 maria_role=self.is_mariadb)

        return True

    def drop(self, check_mode=False):
        """Drop a role.

        Args:
            check_mode (bool): If True, just checks and does nothing.

        Returns:
            bool: True if the state has changed, False if has not.
        """
        if not self.exists:
            return False

        if check_mode and self.exists:
            return True

        self.cursor.execute('DROP ROLE %s', (self.name,))
        return True

    def update_members(self, users, check_mode=False, append_members=False,
                       set_default_role_all=True):
        """Add users to a role.

        Args:
            users (list): Role members.
            check_mode (bool): If True, just checks and does nothing.
            append_members (bool): If True, adds new members passed through users
                not touching current members.
            set_default_role_all (bool): If True, runs SET DEFAULT ROLE ALL TO each member.

        Returns:
            bool: True if the state has changed, False if has not.
        """
        if not users:
            return False

        changed = False
        for user in users:
            if user not in self.members:
                if check_mode:
                    return True

                self.cursor.execute(*self.q_builder.role_grant(user))

                if set_default_role_all:
                    self.role_impl.set_default_role_all(user)

                changed = True

        if append_members:
            return changed

        for user in self.members:
            if user not in users and user != ('root', 'localhost'):
                changed = self.__remove_member(user, check_mode)

        return changed

    def remove_members(self, users, check_mode=False):
        """Remove members from a role.

        Args:
            users (list): Role members.
            check_mode (bool): If True, just checks and does nothing.

        Returns:
            bool: True if the state has changed, False if has not.
        """
        if not users:
            return False

        changed = False
        for user in users:
            if user in self.members:
                changed = self.__remove_member(user, check_mode)

        return changed

    def __remove_member(self, user, check_mode=False):
        """Remove a member from a role.

        Args:
            user (str): Role member to remove.
            check_mode (bool): If True, just returns True and does nothing.

        Returns:
            bool: True if the state has changed, False if has not.
        """
        if check_mode:
            return True

        self.cursor.execute(*self.q_builder.role_revoke(user))

        return True

    def update(self, users, privs, check_mode=False,
               append_privs=False, subtract_privs=False,
               append_members=False, detach_members=False,
               admin=False, set_default_role_all=True):
        """Update a role.

        Update a role if needed.

        Todo: Implement changing of role's admin when ALTER ROLE statement
            to do that gets supported.

        Args:
            users (list): Role members.
            privs (str): String containing privileges.
            check_mode (bool): If True, just checks and does nothing.
            append_privs (bool): If True, adds new privileges passed through privs
                not touching current privileges.
            subtract_privs (bool): If True, revoke the privileges passed through privs
                not touching other existing privileges.
            append_members (bool): If True, adds new members passed through users
                not touching current members.
            detach_members (bool): If True, removes members passed through users from a role.
            admin (tuple): Role's admin. Contains (username, hostname).
            set_default_role_all (bool): If True, runs SET DEFAULT ROLE ALL TO each member.

        Returns:
            bool: True if the state has changed, False if has not.
        """
        changed = False
        members_changed = False

        if users:
            if detach_members:
                members_changed = self.remove_members(users, check_mode=check_mode)

            else:
                members_changed = self.update_members(users, check_mode=check_mode,
                                                      append_members=append_members,
                                                      set_default_role_all=set_default_role_all)

        if privs:
            result = user_mod(cursor=self.cursor, user=self.name, host=self.host,
                              host_all=None, password=None, encrypted=None, plugin=None,
                              plugin_auth_string=None, plugin_hash_string=None, salt=None,
                              new_priv=privs, append_privs=append_privs, subtract_privs=subtract_privs,
                              attributes=None, tls_requires=None, module=self.module, password_expire=None,
                              password_expire_interval=None, role=True, maria_role=self.is_mariadb)
            changed = result['changed']

        if admin:
            self.role_impl.set_admin(admin)

        changed = changed or members_changed

        return changed

    def __get_members(self):
        """Get current role's members.

        Returns:
            set: Members.
        """
        if self.is_mariadb:
            self.cursor.execute('select user, host from mysql.roles_mapping where role = %s', (self.name,))
        else:
            self.cursor.execute('select TO_USER as user, TO_HOST as host from mysql.role_edges where FROM_USER = %s', (self.name,))
        return set(self.cursor.fetchall())


def main():
    argument_spec = mysql_common_argument_spec()
    argument_spec.update(
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        admin=dict(type='str'),
        priv=dict(type='raw'),
        append_privs=dict(type='bool', default=False),
        subtract_privs=dict(type='bool', default=False),
        members=dict(type='list', elements='str'),
        append_members=dict(type='bool', default=False),
        detach_members=dict(type='bool', default=False),
        check_implicit_admin=dict(type='bool', default=False),
        set_default_role_all=dict(type='bool', default=True),
        members_must_exist=dict(type='bool', default=True),
        column_case_sensitive=dict(type='bool', default=None),  # TODO 4.0.0 add default=True
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=(
            ('append_members', 'detach_members'),
            ('admin', 'members'),
            ('admin', 'append_members'),
            ('admin', 'detach_members'),
            ('append_privs', 'subtract_privs'),
        ),
    )

    login_user = module.params['login_user']
    login_password = module.params['login_password']
    name = module.params['name']
    state = module.params['state']
    admin = module.params['admin']
    priv = module.params['priv']
    check_implicit_admin = module.params['check_implicit_admin']
    connect_timeout = module.params['connect_timeout']
    config_file = module.params['config_file']
    append_privs = module.params['append_privs']
    subtract_privs = module.boolean(module.params['subtract_privs'])
    members = module.params['members']
    append_members = module.params['append_members']
    detach_members = module.params['detach_members']
    ssl_cert = module.params['client_cert']
    ssl_key = module.params['client_key']
    ssl_ca = module.params['ca_cert']
    check_hostname = module.params['check_hostname']
    db = ''
    set_default_role_all = module.params['set_default_role_all']
    members_must_exist = module.params['members_must_exist']
    column_case_sensitive = module.params['column_case_sensitive']

    if priv and not isinstance(priv, (str, dict)):
        msg = ('The "priv" parameter must be str or dict '
               'but %s was passed' % type(priv))
        module.fail_json(msg=msg)

    if priv and isinstance(priv, dict):
        priv = convert_priv_dict_to_str(priv)

    if mysql_driver is None:
        module.fail_json(msg=mysql_driver_fail_msg)

    # TODO Release 4.0.0 : Remove this test and variable assignation
    if column_case_sensitive is None:
        column_case_sensitive = False
        module.warn("Option column_case_sensitive is not provided. "
                    "The default is now false, so the column's name will be uppercased. "
                    "The default will be changed to true in community.mysql 4.0.0.")

    cursor = None
    try:
        if check_implicit_admin:
            try:
                cursor, db_conn = mysql_connect(module, 'root', '', config_file,
                                                ssl_cert, ssl_key, ssl_ca, db,
                                                connect_timeout=connect_timeout,
                                                check_hostname=check_hostname,
                                                autocommit=True)
            except Exception:
                pass

        if not cursor:
            cursor, db_conn = mysql_connect(module, login_user, login_password,
                                            config_file, ssl_cert, ssl_key,
                                            ssl_ca, db, connect_timeout=connect_timeout,
                                            check_hostname=check_hostname,
                                            autocommit=True)

    except Exception as e:
        module.fail_json(msg='unable to connect to database, '
                             'check login_user and login_password '
                             'are correct or %s has the credentials. '
                             'Exception message: %s' % (config_file, to_native(e)))

    # Set defaults
    changed = False

    impl = get_user_implementation(cursor)

    if priv is not None:
        try:
            mode = get_mode(cursor)
        except Exception as e:
            module.fail_json(msg=to_native(e))

        try:
            priv = privileges_unpack(priv, mode, column_case_sensitive, ensure_usage=not subtract_privs)
        except Exception as e:
            module.fail_json(msg='Invalid privileges string: %s' % to_native(e))

    server = DbServer(module, cursor)

    # Check if the server supports roles
    if not server.supports_roles():
        msg = ('Roles are not supported by the server. '
               'Minimal versions are MySQL 8.0.0 or MariaDB 10.0.5.')
        module.fail_json(msg=msg)

    if admin:
        if not server.is_mariadb():
            module.fail_json(msg='The "admin" option can be used only with MariaDB.')

        admin = normalize_users(module, [admin])[0]
        server.check_users_in_db([admin])

    if members:
        members = normalize_users(module, members, server.is_mariadb())
        if members_must_exist:
            server.check_users_in_db(members)
        else:
            members = list(server.filter_existing_users(members))

    # Main job starts here
    role = Role(module, cursor, name, server)

    try:
        if state == 'present':
            if not role.exists:
                if subtract_privs:
                    priv = None  # avoid granting unwanted privileges
                if detach_members:
                    members = None  # avoid adding unwanted members
                changed = role.add(members, priv, module.check_mode, admin,
                                   set_default_role_all)

            else:
                changed = role.update(members, priv, module.check_mode, append_privs, subtract_privs,
                                      append_members, detach_members, admin,
                                      set_default_role_all)

        elif state == 'absent':
            changed = role.drop(module.check_mode)

    except Exception as e:
        module.fail_json(msg=to_native(e))

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
