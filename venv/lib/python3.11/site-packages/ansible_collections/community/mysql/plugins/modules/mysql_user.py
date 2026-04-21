#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2012, Mark Theunissen <mark.theunissen@gmail.com>
# Sponsored by Four Kitchens http://fourkitchens.com.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: mysql_user
short_description: Adds or removes a user from a MySQL or MariaDB database
description:
   - Adds or removes a user from a MySQL or MariaDB database.
options:
  name:
    description:
      - Name of the user (role) to add or remove.
    type: str
    required: true
    aliases: ['user']
  password:
    description:
      - Set the user's password. Only for C(mysql_native_password) authentication.
        For other authentication plugins see the combination of I(plugin), I(plugin_hash_string), I(plugin_auth_string).
    type: str
  encrypted:
    description:
      - Indicate that the 'password' field is a `mysql_native_password` hash.
    type: bool
    default: false
  host:
    description:
      - The 'host' part of the MySQL username.
    type: str
    default: localhost
  host_all:
    description:
      - Override the host option, making ansible apply changes
        to all hostnames for a given user.
      - This option cannot be used when creating users.
    type: bool
    default: false
  priv:
    description:
      - "MySQL privileges string in the format: C(db.table:priv1,priv2)."
      - Additionally, there must be no spaces between the table and the privilege as this will yield a non-idempotent check mode.
      - "Multiple privileges can be specified by separating each one using
        a forward slash: C(db.table1:priv/db.table2:priv)."
      - The format is based on MySQL C(GRANT) statement.
      - Database and table names can be quoted, MySQL-style.
      - If column privileges are used, the C(priv1,priv2) part must be
        exactly as returned by a C(SHOW GRANT) statement. If not followed,
        the module will always report changes. It includes grouping columns
        by permission (C(SELECT(col1,col2)) instead of C(SELECT(col1),SELECT(col2))).
      - Can be passed as a dictionary (see the examples).
      - Supports GRANTs for procedures and functions (see the examples).
      - "Note: If you pass the same C(db.table) combination to this parameter
        two or more times with different privileges,
        for example, C('*.*:SELECT/*.*:SHOW VIEW'), only the last one will be applied,
        in this example, it will be C(SHOW VIEW) respectively.
        Use C('*.*:SELECT,SHOW VIEW') instead to apply both."
    type: raw
  append_privs:
    description:
      - Append the privileges defined by priv to the existing ones for this
        user instead of overwriting existing ones. Mutually exclusive with I(subtract_privs).
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
  tls_requires:
    description:
      - Set requirement for secure transport as a dictionary of requirements (see the examples).
      - Valid requirements are SSL, X509, SUBJECT, ISSUER, CIPHER.
      - SUBJECT, ISSUER and CIPHER are complementary, and mutually exclusive with SSL and X509.
      - U(https://mariadb.com/kb/en/securing-connections-for-client-and-server/#requiring-tls).
    type: dict
    version_added: 1.0.0
  sql_log_bin:
    description:
      - Whether binary logging should be enabled or disabled for the connection.
    type: bool
    default: true
  force_context:
    description:
      - Sets the С(mysql) system database as context for the executed statements (it will be used
        as a database to connect to). Useful if you use binlog / replication filters in MySQL as
        per default the statements can not be caught by a binlog / replication filter, they require
        a database to be set to work, otherwise the replication can break down.
      - See U(https://dev.mysql.com/doc/refman/8.0/en/replication-options-binary-log.html#option_mysqld_binlog-ignore-db)
        for a description on how binlog filters work (filtering on the primary).
      - See U(https://dev.mysql.com/doc/refman/8.0/en/replication-options-replica.html#option_mysqld_replicate-ignore-db)
        for a description on how replication filters work (filtering on the replica).
    type: bool
    default: false
    version_added: '3.1.0'
  state:
    description:
      - Whether the user should exist.
      - When C(absent), removes the user.
    type: str
    choices: [ absent, present ]
    default: present
  check_implicit_admin:
    description:
      - Check if mysql allows login as root/nopassword before trying supplied credentials.
      - If success, passed I(login_user)/I(login_password) will be ignored.
    type: bool
    default: false
  update_password:
    description:
      - C(always) will update passwords if they differ. This affects I(password) and the combination of I(plugin), I(plugin_hash_string), I(plugin_auth_string).
      - C(on_create) will only set the password or the combination of I(plugin), I(plugin_hash_string), I(plugin_auth_string) for newly created users.
      - "C(on_new_username) works like C(on_create), but it tries to reuse an existing password: If one different user
        with the same username exists, or multiple different users with the same username and equal C(plugin) and
        C(authentication_string) attribute, the existing C(plugin) and C(authentication_string) are used for the
        new user instead of the I(password), I(plugin), I(plugin_hash_string) or I(plugin_auth_string) argument."
    type: str
    choices: [ always, on_create, on_new_username ]
    default: always
  plugin:
    description:
      - User's plugin to authenticate (``CREATE USER user IDENTIFIED WITH plugin``).
    type: str
    version_added: '0.1.0'
  plugin_hash_string:
    description:
      - User's plugin hash string (``CREATE USER user IDENTIFIED WITH plugin AS plugin_hash_string``).
    type: str
    version_added: '0.1.0'
  plugin_auth_string:
    description:
      - User's plugin auth_string (``CREATE USER user IDENTIFIED WITH plugin BY plugin_auth_string``).
      - If I(plugin) is ``pam`` (MariaDB) or ``auth_pam`` (MySQL) an optional I(plugin_auth_string) can be used to choose a specific PAM service.
      - You need to define a I(salt) to have idempotence on password change with ``caching_sha2_password`` and ``sha256_password`` plugins.
    type: str
    version_added: '0.1.0'
  salt:
    description:
      - Salt used to generate password hash from I(plugin_auth_string).
      - Salt length must be 20 characters.
      - Salt only support ``caching_sha2_password`` or ``sha256_password`` authentication I(plugin).
    type: str
    version_added: '3.10.0'
  resource_limits:
    description:
      - Limit the user for certain server resources. Provided since MySQL 5.6 / MariaDB 10.2.
      - "Available options are C(MAX_QUERIES_PER_HOUR: num), C(MAX_UPDATES_PER_HOUR: num),
        C(MAX_CONNECTIONS_PER_HOUR: num), C(MAX_USER_CONNECTIONS: num), C(MAX_STATEMENT_TIME: num) (supported only for MariaDB since collection version 3.7.0)."
      - Used when I(state=present), ignored otherwise.
    type: dict
    version_added: '0.1.0'
  session_vars:
    description:
      - "Dictionary of session variables in form of C(variable: value) to set at the beginning of module execution."
      - Cannot be used to set global variables, use the M(community.mysql.mysql_variables) module instead.
    type: dict
    version_added: '3.6.0'
  password_expire:
    description:
      - C(never) - I(password) will never expire.
      - C(default) - I(password) is defined using global system variable I(default_password_lifetime) setting.
      - C(interval) - I(password) will expire in days which is defined in I(password_expire_interval).
      - C(now) - I(password) will expire immediately.
    type: str
    choices: [ now, never, default, interval ]
    version_added: '3.9.0'
  password_expire_interval:
    description:
      - Number of days I(password) will expire. Requires I(password_expire=interval).
    type: int
    version_added: '3.9.0'

  column_case_sensitive:
    description:
      - The default is C(false).
      - When C(true), the module will not uppercase the field names in the privileges.
      - When C(false), the field names will be upper-cased. This is the default
      - This feature was introduced because MySQL 8 and above uses case sensitive
        fields names in privileges.
    type: bool
    version_added: '3.8.0'

  locked:
    description:
      - Lock account to prevent connections using it.
      - This is primarily used for creating a user that will act as a DEFINER on stored procedures.
      - If not specified leaves the lock state as is (for a new user creates unlocked).
    type: bool
    version_added: '3.13.0'

  attributes:
    description:
      - "Create, update, or delete user attributes (arbitrary 'key: value' comments) for the user."
      - MySQL server must support the INFORMATION_SCHEMA.USER_ATTRIBUTES table. Provided since MySQL 8.0.
      - To delete an existing attribute, set its value to null.
    type: dict
    version_added: '3.9.0'

notes:
   - Compatible with MySQL or MariaDB.
   - "MySQL server installs with default I(login_user) of C(root) and no password.
     To secure this user as part of an idempotent playbook, you must create at least two tasks:
     1) change the root user's password, without providing any I(login_user)/I(login_password) details,
     2) drop a C(~/.my.cnf) file containing the new root credentials.
     Subsequent runs of the playbook will then succeed by reading the new credentials from the file."
   - Currently, there is only support for the C(mysql_native_password) encrypted password hash module.

attributes:
  check_mode:
    support: full

seealso:
- module: community.mysql.mysql_info
- name: MySQL access control and account management reference
  description: Complete reference of the MySQL access control and account management documentation.
  link: https://dev.mysql.com/doc/refman/8.0/en/access-control.html
- name: MySQL provided privileges reference
  description: Complete reference of the MySQL provided privileges documentation.
  link: https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html

author:
- Jonathan Mainguy (@Jmainguy)
- Benjamin Malynovytch (@bmalynovytch)
- Lukasz Tomaszkiewicz (@tomaszkiewicz)
- kmarse (@kmarse)
- Laurent Indermühle (@laurent-indermuehle)
- E.S. Rosenberg (@Keeper-of-the-Keys)

extends_documentation_fragment:
- community.mysql.mysql
'''

EXAMPLES = r'''
# If you encounter the "Please explicitly state intended protocol" error,
# use the login_unix_socket argument
- name: Removes anonymous user account for localhost
  community.mysql.mysql_user:
    name: ''
    host: localhost
    state: absent
    login_unix_socket: /run/mysqld/mysqld.sock

- name: Removes all anonymous user accounts
  community.mysql.mysql_user:
    name: ''
    host_all: true
    state: absent

- name: Create database user with name 'bob' and password '12345' with all database privileges
  community.mysql.mysql_user:
    name: bob
    password: 12345
    priv: '*.*:ALL'
    state: present

- name: Create database user using hashed password with all database privileges
  community.mysql.mysql_user:
    name: bob
    password: '*EE0D72C1085C46C5278932678FBE2C6A782821B4'
    encrypted: true
    priv: '*.*:ALL'
    state: present

# Set session var wsrep_on=off before creating the user
- name: Create database user with password and all database privileges and 'WITH GRANT OPTION'
  community.mysql.mysql_user:
    name: bob
    password: 12345
    priv: '*.*:ALL,GRANT'
    state: present
    session_vars:
      wsrep_on: 'off'

- name: Create user with password, all database privileges and 'WITH GRANT OPTION' in db1 and db2
  community.mysql.mysql_user:
    state: present
    name: bob
    password: 12345dd
    priv:
      'db1.*': 'ALL,GRANT'
      'db2.*': 'ALL,GRANT'

# Use 'PROCEDURE' instead of 'FUNCTION' to apply GRANTs for a MySQL procedure instead.
- name: Grant a user the right to execute a function
  community.mysql.mysql_user:
    name: readonly
    password: 12345
    priv:
      FUNCTION my_db.my_function: EXECUTE
    state: present

- name: Modify user attributes, creating the attribute 'foo' and removing the attribute 'bar'
  community.mysql.mysql_user:
    name: bob
    attributes:
      foo: "foo"
      bar: null

- name: Modify user to require TLS connection with a valid client certificate
  community.mysql.mysql_user:
    name: bob
    tls_requires:
      x509:
    state: present

- name: Modify user to require TLS connection with a specific client certificate and cipher
  community.mysql.mysql_user:
    name: bob
    tls_requires:
      subject: '/CN=alice/O=MyDom, Inc./C=US/ST=Oregon/L=Portland'
      cipher: 'ECDHE-ECDSA-AES256-SHA384'

- name: Modify user to no longer require SSL
  community.mysql.mysql_user:
    name: bob
    tls_requires:

- name: Ensure no user named 'sally'@'localhost' exists, also passing in the auth credentials
  community.mysql.mysql_user:
    login_user: root
    login_password: 123456
    name: sally
    state: absent

# check_implicit_admin example
- name: >
    Ensure no user named 'sally'@'localhost' exists, also passing in the auth credentials.
    If mysql allows root/nopassword login, try it without the credentials first.
    If it's not allowed, pass the credentials
  community.mysql.mysql_user:
    check_implicit_admin: true
    login_user: root
    login_password: 123456
    name: sally
    state: absent

- name: Ensure no user named 'sally' exists at all
  community.mysql.mysql_user:
    name: sally
    host_all: true
    state: absent

- name: Specify grants composed of more than one word
  community.mysql.mysql_user:
    name: replication
    password: 12345
    priv: "*.*:REPLICATION CLIENT"
    state: present

- name: Revoke all privileges for user 'bob' and password '12345'
  community.mysql.mysql_user:
    name: bob
    password: 12345
    priv: "*.*:USAGE"
    state: present

# Example privileges string format
# mydb.*:INSERT,UPDATE/anotherdb.*:SELECT/yetanotherdb.*:ALL

- name: Example using login_unix_socket to connect to server
  community.mysql.mysql_user:
    name: root
    password: abc123
    login_unix_socket: /var/run/mysqld/mysqld.sock

- name: Example of skipping binary logging while adding user 'bob'
  community.mysql.mysql_user:
    name: bob
    password: 12345
    priv: "*.*:USAGE"
    state: present
    sql_log_bin: false

- name: Create user 'bob' authenticated with plugin 'AWSAuthenticationPlugin'
  community.mysql.mysql_user:
    name: bob
    plugin: AWSAuthenticationPlugin
    plugin_hash_string: RDS
    priv: '*.*:ALL'
    state: present

- name: Create user 'bob' authenticated with plugin 'caching_sha2_password' and static salt
  community.mysql.mysql_user:
    name: bob
    plugin: caching_sha2_password
    plugin_auth_string: password
    salt: 1234567890abcdefghij

- name: Limit bob's resources to 10 queries per hour and 5 connections per hour
  community.mysql.mysql_user:
    name: bob
    resource_limits:
      MAX_QUERIES_PER_HOUR: 10
      MAX_CONNECTIONS_PER_HOUR: 5

- name: Ensure bob does not have the DELETE privilege
  community.mysql.mysql_user:
    name: bob
    subtract_privs: true
    priv:
      'db1.*': DELETE

- name: Create locked user to act as a definer on procedures
  community.mysql.mysql_user:
    name: readonly_procedures_locked
    locked: true
    priv:
      db1.*: SELECT

# Example .my.cnf file for setting the root password
# [client]
# user=root
# password=n<_665{vS43y
'''

RETURN = '''#'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.mysql.plugins.module_utils.database import SQLParseError
from ansible_collections.community.mysql.plugins.module_utils.mysql import (
    mysql_connect,
    mysql_driver,
    mysql_driver_fail_msg,
    mysql_common_argument_spec,
    set_session_vars,
)
from ansible_collections.community.mysql.plugins.module_utils.user import (
    convert_priv_dict_to_str,
    get_mode,
    InvalidPrivsError,
    limit_resources,
    privileges_unpack,
    sanitize_requires,
    user_add,
    user_delete,
    user_exists,
    user_mod,
)
from ansible.module_utils._text import to_native


# ===========================================
# Module execution.
#


def main():
    argument_spec = mysql_common_argument_spec()
    argument_spec.update(
        name=dict(type='str', required=True, aliases=['user'], deprecated_aliases=[
            {
                'name': 'user',
                'version': '5.0.0',
                'collection_name': 'community.mysql',
            }],
        ),
        password=dict(type='str', no_log=True),
        encrypted=dict(type='bool', default=False),
        host=dict(type='str', default='localhost'),
        host_all=dict(type="bool", default=False),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        priv=dict(type='raw'),
        tls_requires=dict(type='dict'),
        append_privs=dict(type='bool', default=False),
        subtract_privs=dict(type='bool', default=False),
        attributes=dict(type='dict'),
        check_implicit_admin=dict(type='bool', default=False),
        update_password=dict(type='str', default='always', choices=['always', 'on_create', 'on_new_username'], no_log=False),
        sql_log_bin=dict(type='bool', default=True),
        plugin=dict(default=None, type='str'),
        plugin_hash_string=dict(default=None, type='str'),
        plugin_auth_string=dict(default=None, type='str'),
        salt=dict(default=None, type='str'),
        resource_limits=dict(type='dict'),
        force_context=dict(type='bool', default=False),
        session_vars=dict(type='dict'),
        column_case_sensitive=dict(type='bool', default=None),  # TODO 4.0.0 add default=True
        password_expire=dict(type='str', choices=['now', 'never', 'default', 'interval'], no_log=True),
        password_expire_interval=dict(type='int', required_if=[('password_expire', 'interval', True)], no_log=True),
        locked=dict(type='bool'),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=(('append_privs', 'subtract_privs'),)
    )
    login_user = module.params["login_user"]
    login_password = module.params["login_password"]
    user = module.params["name"]
    password = module.params["password"]
    encrypted = module.boolean(module.params["encrypted"])
    host = module.params["host"].lower()
    host_all = module.params["host_all"]
    state = module.params["state"]
    priv = module.params["priv"]
    tls_requires = sanitize_requires(module.params["tls_requires"])
    check_implicit_admin = module.params["check_implicit_admin"]
    connect_timeout = module.params["connect_timeout"]
    config_file = module.params["config_file"]
    append_privs = module.boolean(module.params["append_privs"])
    subtract_privs = module.boolean(module.params['subtract_privs'])
    update_password = module.params['update_password']
    attributes = module.params['attributes']
    ssl_cert = module.params["client_cert"]
    ssl_key = module.params["client_key"]
    ssl_ca = module.params["ca_cert"]
    check_hostname = module.params["check_hostname"]
    db = ''
    if module.params["force_context"]:
        db = 'mysql'
    sql_log_bin = module.params["sql_log_bin"]
    plugin = module.params["plugin"]
    plugin_hash_string = module.params["plugin_hash_string"]
    plugin_auth_string = module.params["plugin_auth_string"]
    salt = module.params["salt"]
    resource_limits = module.params["resource_limits"]
    session_vars = module.params["session_vars"]
    column_case_sensitive = module.params["column_case_sensitive"]
    password_expire = module.params["password_expire"]
    password_expire_interval = module.params["password_expire_interval"]
    locked = module.boolean(module.params['locked'])

    if priv and not isinstance(priv, (str, dict)):
        module.fail_json(msg="priv parameter must be str or dict but %s was passed" % type(priv))

    if priv and isinstance(priv, dict):
        priv = convert_priv_dict_to_str(priv)

    if mysql_driver is None:
        module.fail_json(msg=mysql_driver_fail_msg)

    if password_expire_interval and password_expire_interval < 1:
        module.fail_json(msg="password_expire_interval value \
                             should be positive number")

    if salt:
        if not plugin_auth_string:
            module.fail_json(msg="salt requires plugin_auth_string")
        if len(salt) != 20:
            module.fail_json(msg="salt must be 20 characters long")
        if plugin not in ['caching_sha2_password', 'sha256_password']:
            module.fail_json(msg="salt requires caching_sha2_password or sha256_password plugin")

    cursor = None
    try:
        if check_implicit_admin:
            try:
                cursor, db_conn = mysql_connect(module, "root", "", config_file, ssl_cert, ssl_key, ssl_ca, db,
                                                connect_timeout=connect_timeout, check_hostname=check_hostname, autocommit=True)
            except Exception:
                pass

        if not cursor:
            cursor, db_conn = mysql_connect(module, login_user, login_password, config_file, ssl_cert, ssl_key, ssl_ca, db,
                                            connect_timeout=connect_timeout, check_hostname=check_hostname, autocommit=True)
    except Exception as e:
        module.fail_json(msg="unable to connect to database, check login_user and login_password are correct or %s has the credentials. "
                             "Exception message: %s" % (config_file, to_native(e)))

    # TODO Release 4.0.0 : Remove this test and variable assignation
    if column_case_sensitive is None:
        column_case_sensitive = False
        module.warn("Option column_case_sensitive is not provided. "
                    "The default is now false, so the column's name will be uppercased. "
                    "The default will be changed to true in community.mysql 4.0.0.")

    if not sql_log_bin:
        cursor.execute("SET SQL_LOG_BIN=0;")

    if session_vars:
        set_session_vars(module, cursor, session_vars)

    if priv is not None:
        try:
            mode = get_mode(cursor)
        except Exception as e:
            module.fail_json(msg=to_native(e))

        priv = privileges_unpack(priv, mode, column_case_sensitive, ensure_usage=not subtract_privs)
    password_changed = False
    final_attributes = None
    if state == "present":
        if user_exists(cursor, user, host, host_all):
            try:
                if update_password == "always":
                    result = user_mod(cursor, user, host, host_all, password, encrypted,
                                      plugin, plugin_hash_string, plugin_auth_string, salt,
                                      priv, append_privs, subtract_privs, attributes, tls_requires, module,
                                      password_expire, password_expire_interval, locked=locked)

                else:
                    result = user_mod(cursor=cursor, user=user, host=host, host_all=host_all, password=None,
                                      encrypted=encrypted, plugin=None, plugin_hash_string=None, plugin_auth_string=None,
                                      salt=None, new_priv=priv, append_privs=append_privs, subtract_privs=subtract_privs,
                                      attributes=attributes, tls_requires=tls_requires, module=module,
                                      password_expire=password_expire, password_expire_interval=password_expire_interval,
                                      locked=locked)
                changed = result['changed']
                msg = result['msg']
                password_changed = result['password_changed']
                final_attributes = result['attributes']

            except (SQLParseError, InvalidPrivsError, mysql_driver.Error) as e:
                module.fail_json(msg=to_native(e))
        else:
            if host_all:
                module.fail_json(msg="host_all parameter cannot be used when adding a user")
            try:
                if subtract_privs:
                    priv = None  # avoid granting unwanted privileges
                reuse_existing_password = update_password == 'on_new_username'
                result = user_add(cursor, user, host, host_all, password, encrypted,
                                  plugin, plugin_hash_string, plugin_auth_string, salt,
                                  priv, attributes, tls_requires, reuse_existing_password, module,
                                  password_expire, password_expire_interval, locked=locked)
                changed = result['changed']
                password_changed = result['password_changed']
                final_attributes = result['attributes']
                if changed:
                    msg = "User added"

            except (SQLParseError, InvalidPrivsError, mysql_driver.Error) as e:
                module.fail_json(msg=to_native(e))

        if resource_limits:
            changed = limit_resources(module, cursor, user, host, resource_limits, module.check_mode) or changed

    elif state == "absent":
        if user_exists(cursor, user, host, host_all):
            changed = user_delete(cursor, user, host, host_all, module.check_mode)
            msg = "User deleted"
        else:
            changed = False
            msg = "User doesn't exist"
    module.exit_json(changed=changed, user=user, msg=msg, password_changed=password_changed, attributes=final_attributes)


if __name__ == '__main__':
    main()
