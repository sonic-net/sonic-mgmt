#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_user
short_description: Create, alter, or remove a user (role) from a PostgreSQL server instance
description:
- Creates, alters, or removes a user (role) from a PostgreSQL server instance
  ("cluster" in PostgreSQL terminology) and, optionally,
  grants the user access to an existing database or tables.
- A user is a role with login privilege.
- You cannot remove a user while it still has any privileges granted to it in any database.
- Set I(fail_on_user) to C(false) to make the module ignore failures when trying to remove a user.
  In this case, the module reports if changes happened as usual and separately reports
  whether the user has been removed or not.
options:
  name:
    description:
    - Name of the user (role) to add or remove.
    type: str
    required: true
    aliases:
    - user
  password:
    description:
    - Set the user's password, before 1.4 this was required.
    - Password can be passed unhashed or hashed (MD5-hashed).
    - An unhashed password is automatically hashed when saved into the
      database if I(encrypted) is set, otherwise it is saved in
      plain text format.
    - When passing an MD5-hashed password, you must generate it with the format
      C('str["md5"] + md5[ password + username ]'), resulting in a total of
      35 characters. An easy way to do this is
      C(echo "md5`echo -n 'verysecretpasswordJOE' | md5sum | awk '{print $1}'`").
    - Note that if the provided password string is already in MD5-hashed
      format, then it is used as-is, regardless of I(encrypted) option.
    type: str
  login_db:
    description:
    - Name of database to connect to and where user's permissions are granted.
    - The V(db) alias is deprecated and will be removed in version 5.0.0.
    type: str
    default: ''
    aliases:
    - db
  fail_on_user:
    description:
    - If C(true), fails when the user (role) cannot be removed. Otherwise just log and continue.
    default: true
    type: bool
    aliases:
    - fail_on_role
  role_attr_flags:
    description:
    - "PostgreSQL user attributes string in the format: CREATEDB,CREATEROLE,SUPERUSER."
    - Note that '[NO]CREATEUSER' is deprecated.
    - To create a simple role for using it like a group, use C(NOLOGIN) flag.
    - See the full list of supported flags in documentation for your PostgreSQL version.
    type: str
    default: ''
  session_role:
    description:
    - Switch to session role after connecting.
    - The specified session role must be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though the session role
      were the one that had logged in originally.
    type: str
  state:
    description:
    - The user (role) state.
    type: str
    default: present
    choices: [ absent, present ]
  encrypted:
    description:
    - Whether the password is stored hashed in the database.
    - You can specify an unhashed password, and PostgreSQL ensures
      the stored password is hashed when I(encrypted=true) is set.
      If you specify a hashed password, the module uses it as-is,
      regardless of the setting of I(encrypted).
    - "Note: Postgresql 10 and newer does not support unhashed passwords."
    - Previous to Ansible 2.6, this was C(false) by default.
    default: true
    type: bool
  expires:
    description:
    - The date at which the user's password is to expire.
    - If set to C('infinity'), user's password never expires.
    - Note that this value must be a valid SQL date and time type.
    type: str
  no_password_changes:
    description:
    - If C(true), does not inspect the database for password changes.
      If the user already exists, skips all password related checks.
      Useful when C(pg_authid) is not accessible (such as in AWS RDS).
      Otherwise, makes password changes as necessary.
    default: false
    type: bool
  conn_limit:
    description:
    - Specifies the user (role) connection limit.
    type: int
  ssl_mode:
    description:
      - Determines how an SSL session is negotiated with the server.
      - See U(https://www.postgresql.org/docs/current/static/libpq-ssl.html) for more information on the modes.
      - Default of C(prefer) matches libpq default.
    type: str
    default: prefer
    choices: [ allow, disable, prefer, require, verify-ca, verify-full ]
  ca_cert:
    description:
      - Specifies the name of a file containing SSL certificate authority (CA) certificate(s).
      - If the file exists, verifies that the server's certificate is signed by one of these authorities.
    type: str
    aliases: [ ssl_rootcert ]
  comment:
    description:
    - Adds a comment on the user (equivalent to the C(COMMENT ON ROLE) statement).
    - To reset the comment, pass an empty string.
    type: str
    version_added: '0.2.0'
  trust_input:
    description:
    - If C(false), checks whether values of options I(name), I(password), I(expires),
      I(role_attr_flags), I(comment), I(session_role) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections through the options are possible.
    type: bool
    default: true
    version_added: '0.2.0'
  configuration:
    description:
      - Role-specific configuration parameters that would otherwise be set by C(ALTER ROLE user SET variable TO value;).
      - Takes a dict where the key is the name of the configuration parameter. If the key includes special characters
        like C(.) and C(-), it needs to be quoted to ensure the YAML is valid.
      - Sets or updates any parameter in the list that is not present or has the wrong value in the database.
      - Removes any parameter from the user that is not listed here.
      - Parameters that are present in the database but are not included in this list will only be reset, if
        O(reset_unspecified_configuration=true).
      - Inputs to O(user) as well as keys and values in this parameter are quoted by the module. If you require the
        user to contain a C("), you need to double it, otherwise the module will fail. C(") and C(') are not allowed in
        configuration keys and any C(') in the value of a configuration will be escaped by this module.
        Additionally, parameters and values are checked if O(trust_input) is C(false).
    type: dict
    default: {}
    version_added: '3.5.0'
  reset_unspecified_configuration:
    description:
      - If set to C(true), the user's default configuration parameters will be reset in case they are not included in
        O(configuration), otherwise existing parameters will not be modified if not included in O(configuration).
    type: bool
    default: false
    version_added: '3.5.0'
  quote_configuration_values:
    description:
      - Automatically quote the values of configuration variables added via I(configuration). The default is C(true)
        and setting this to C(false) leaves these options open to SQL-injections and makes the user responsible for
        properly quoting values.
      - This is required to be C(false) to modify settings like C(search_path), that need to be unquoted.
      - If this is C(false) you will also need to make sure that strings are properly quoted.
        For example C("'16MB'") for C(work_mem).
      - Set this only to C(false) if you know what you are doing!
    type: bool
    default: true
    version_added: '3.11.0'
notes:
- The module creates a user (role) with login privilege by default.
  Use C(NOLOGIN) I(role_attr_flags) to change this behaviour.
- If you specify C(PUBLIC) as the user (role), then the privilege changes apply to all users (roles).
  You may not specify password or role_attr_flags when the C(PUBLIC) user is specified.
- SCRAM-SHA-256-hashed passwords (SASL Authentication) require PostgreSQL version 10 or newer.
  On the previous versions the whole hashed string is used as a password.
- 'Working with SCRAM-SHA-256-hashed passwords, be sure you use the I(environment:) variable
  C(PGOPTIONS: "-c password_encryption=scram-sha-256") when it is not default
  for your PostgreSQL version (see the provided example).'
- On some systems (such as AWS RDS), C(pg_authid) is not accessible, thus, the module cannot compare
  the current and desired C(password). In this case, the module assumes that the passwords are
  different and changes it reporting that the state has been changed.
  To skip all password related checks for existing users, use I(no_password_changes=true).
- On some systems (such as AWS RDS), C(SUPERUSER) is unavailable. This means the C(SUPERUSER) and
  C(NOSUPERUSER) I(role_attr_flags) should not be specified to preserve idempotency and avoid
  InsufficientPrivilege errors.

attributes:
  check_mode:
    support: full

seealso:
- module: community.postgresql.postgresql_privs
- module: community.postgresql.postgresql_membership
- module: community.postgresql.postgresql_owner
- name: PostgreSQL database roles
  description: Complete reference of the PostgreSQL database roles documentation.
  link: https://www.postgresql.org/docs/current/user-manag.html
- name: PostgreSQL SASL Authentication
  description: Complete reference of the PostgreSQL SASL Authentication.
  link: https://www.postgresql.org/docs/current/sasl-authentication.html
author:
- Ansible Core Team
extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Connect to acme database, create django user
  community.postgresql.postgresql_user:
    login_db: acme
    name: django
    password: ceec4eif7ya
    expires: "Jan 31 2020"

- name: Add a comment on django user
  community.postgresql.postgresql_user:
    login_db: acme
    name: django
    comment: This is a test user

# Connect to default database, create rails user, set its password (MD5- or SHA256-hashed),
# and set flags to allow the user to create databases
# and demote rails from super user status if user exists
# the hash from the corresponding pg_authid entry.
- name: Create rails user, set MD5-hashed password, set flags
  community.postgresql.postgresql_user:
    name: rails
    password: md59543f1d82624df2b31672ec0f7050460
    # password: SCRAM-SHA-256$4096:zFuajwIVdli9mK=NJkcv1Q++$JC4gWIrEHmF6sqRbEiZw5FFW45HUPrpVzNdoM72o730+;fqA4vLN3mCZGbhcbQyvNYY7anCrUTsem1eCh/4YA94=
    role_attr_flags: CREATEDB,NOSUPERUSER
  # When using sha256-hashed password:
  # environment:
  #   PGOPTIONS: "-c password_encryption=scram-sha-256"

- name: Connect to test database, remove test user from cluster
  community.postgresql.postgresql_user:
    login_db: test
    name: test
    state: absent

- name: Connect to acme database and set user's password with no expire date
  community.postgresql.postgresql_user:
    login_db: acme
    name: django
    password: mysupersecretword
    expires: infinity

- name: Connect to test database and remove an existing user's password
  community.postgresql.postgresql_user:
    login_db: test
    user: test
    password: ""

# Create user with a cleartext password if it does not exist or update its password.
# The password will be encrypted with SCRAM algorithm (available since PostgreSQL 10)
- name: Create appclient user with SCRAM-hashed password
  community.postgresql.postgresql_user:
    name: appclient
    password: "secret123"
  environment:
    PGOPTIONS: "-c password_encryption=scram-sha-256"

# Create a user and set a default-configuration that is active when they start a session
- name: Create a user with config-parameter
  community.postgresql.postgresql_user:
    name: appclient
    password: "secret123"
    configuration:
      work_mem: "16MB"

# Make sure user has only specified default configuration parameters
- name: Clear all configuration that is not explicitly defined for user
  community.postgresql.postgresql_user:
    name: appclient
    password: "secret123"
    configuration:
      work_mem: "16MB"
    reset_unspecified_configuration: true

- name: Set search_path for user
  community.postgresql.postgresql_user:
    name: postgres_exporter
    quote_configuration_values: false
    configuration:
      search_path: postgres_exporter, pg_catalog, public
'''

RETURN = r'''
queries:
  description: List of executed queries.
  returned: success
  type: list
  sample: ['CREATE USER "alice"', 'GRANT CONNECT ON DATABASE "acme" TO "alice"']
'''

import hmac
import itertools
import re
import traceback
from base64 import b64decode
from hashlib import md5, sha256

from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils import \
    saslprep
from ansible_collections.community.postgresql.plugins.module_utils.database import (
    SQLParseError,
    check_input,
    pg_quote_identifier,
)
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    HAS_PSYCOPG,
    PSYCOPG_VERSION,
    connect_to_db,
    ensure_required_libs,
    get_comment,
    get_conn_params,
    get_server_version,
    pg_cursor_args,
    postgres_common_argument_spec,
    set_comment,
)
from ansible_collections.community.postgresql.plugins.module_utils.version import \
    LooseVersion

if HAS_PSYCOPG and PSYCOPG_VERSION < LooseVersion("3.0"):
    import psycopg2 as psycopg
elif HAS_PSYCOPG:
    import psycopg

try:
    # pbkdf2_hmac is missing on python 2.6, we can safely assume,
    # that postresql 10 capable instance have at least python 2.7 installed
    from hashlib import pbkdf2_hmac
    pbkdf2_found = True
except ImportError:
    pbkdf2_found = False


FLAGS = ('SUPERUSER', 'CREATEROLE', 'CREATEDB', 'INHERIT', 'LOGIN', 'REPLICATION')
FLAGS_BY_VERSION = {'BYPASSRLS': 90500}

SCRAM_SHA256_REGEX = r'^SCRAM-SHA-256\$(\d+):([A-Za-z0-9+\/=]+)\$([A-Za-z0-9+\/=]+):([A-Za-z0-9+\/=]+)$'

# map to cope with idiosyncrasies of SUPERUSER and LOGIN
PRIV_TO_AUTHID_COLUMN = dict(SUPERUSER='rolsuper', CREATEROLE='rolcreaterole',
                             CREATEDB='rolcreatedb', INHERIT='rolinherit', LOGIN='rolcanlogin',
                             REPLICATION='rolreplication', BYPASSRLS='rolbypassrls')

executed_queries = []

# This is a special list for debugging.
# If you need to fetch information (e.g. results of cursor.fetchall(),
# queries built with cursor.mogrify(), vars values, etc.):
# 1. Put debug_info.append(<information_you_need>) as many times as you need.
# 2. Run integration tests or you playbook with -vvv
# 3. If it's not empty, you'll see the list in the returned json.
debug_info = []


class InvalidFlagsError(Exception):
    pass


class InvalidPrivsError(Exception):
    pass

# ===========================================
# PostgreSQL module specific support methods.
#


def user_exists(cursor, user):
    # The PUBLIC user is a special case that is always there
    if user == 'PUBLIC':
        return True
    query = "SELECT rolname FROM pg_roles WHERE rolname=%(user)s"
    cursor.execute(query, {'user': user})
    return cursor.rowcount > 0


def user_add(cursor, user, password, role_attr_flags, encrypted, expires, conn_limit, module):
    """Create a new database user (role)."""
    # Note: role_attr_flags escaped by parse_role_attrs and encrypted is a
    # literal
    query_password_data = dict(password=password, expires=expires)
    query = ['CREATE USER %(user)s' %
             {"user": _pg_quote_user(user, module)}]
    if password is not None and password != '':
        query.append("WITH %(crypt)s" % {"crypt": encrypted})
        query.append("PASSWORD %(password)s")
    if expires is not None:
        query.append("VALID UNTIL %(expires)s")
    if conn_limit is not None:
        query.append("CONNECTION LIMIT %(conn_limit)s" % {"conn_limit": conn_limit})
    query.append(role_attr_flags)
    query = ' '.join(query)
    executed_queries.append(query)
    cursor.execute(query, query_password_data)
    return True


def get_passwd_encryption(cursor):
    cursor.execute("SHOW password_encryption")
    return cursor.fetchone()["password_encryption"]


def user_should_we_change_password(cursor, current_role_attrs, user, password, encrypted):
    """Check if we should change the user's password.

    Compare the proposed password with the existing one, comparing
    hashes if encrypted. If we can't access it assume yes.
    """

    if current_role_attrs is None:
        # on some databases, E.g. AWS RDS instances, there is no access to
        # the pg_authid relation to check the pre-existing password, so we
        # just assume password is different
        return True

    # Do we actually need to do anything?
    pwchanging = False
    if password is not None:
        current_password = current_role_attrs['rolpassword']
        # Handle SQL_ASCII encoded databases
        if isinstance(current_password, bytes):
            current_password = current_password.decode('ascii')

        # Empty password means that the role shouldn't have a password, which
        # means we need to check if the current password is None.
        if password == '':
            if current_password is not None:
                pwchanging = True
        # If the provided password is a SCRAM hash, compare it directly to the current password
        elif re.match(SCRAM_SHA256_REGEX, password):
            if password != current_password:
                pwchanging = True

        # SCRAM hashes are represented as a special object, containing hash data:
        # `SCRAM-SHA-256$<iteration count>:<salt>$<StoredKey>:<ServerKey>`
        # for reference, see https://www.postgresql.org/docs/current/catalog-pg-authid.html
        elif current_password is not None \
                and pbkdf2_found \
                and re.match(SCRAM_SHA256_REGEX, current_password):

            r = re.match(SCRAM_SHA256_REGEX, current_password)
            try:
                # extract SCRAM params from rolpassword
                it = int(r.group(1))
                salt = b64decode(r.group(2))
                server_key = b64decode(r.group(4))
                # we'll never need `storedKey` as it is only used for server auth in SCRAM
                # storedKey = b64decode(r.group(3))

                # from RFC5802 https://tools.ietf.org/html/rfc5802#section-3
                # SaltedPassword  := Hi(Normalize(password), salt, i)
                # ServerKey       := HMAC(SaltedPassword, "Server Key")
                normalized_password = saslprep.saslprep(to_text(password))
                salted_password = pbkdf2_hmac('sha256', to_bytes(normalized_password), salt, it)

                server_key_verifier = hmac.new(salted_password, digestmod=sha256)
                server_key_verifier.update(b'Server Key')

                if server_key_verifier.digest() != server_key:
                    pwchanging = True
            except Exception:
                # We assume the password is not scram encrypted
                # or we cannot check it properly, e.g. due to missing dependencies
                pwchanging = True

        # When the provided password looks like a MD5-hash, value of
        # 'encrypted' is ignored.
        elif is_pg_passwd_md5(password) or encrypted == 'UNENCRYPTED':
            if password != current_password:
                pwchanging = True
        elif encrypted == 'ENCRYPTED':
            default_pw_encryption = get_passwd_encryption(cursor)

            if default_pw_encryption == 'md5':
                hashed_password = 'md5{0}'.format(md5(to_bytes(password) + to_bytes(user)).hexdigest())
                if hashed_password != current_password:
                    pwchanging = True
            elif default_pw_encryption == 'scram-sha-256':
                # https://github.com/ansible-collections/community.postgresql/issues/688
                # When the current password is not none and is not
                # hashed as scram-sha-256 / not explicitly declared as plain text
                # (if we are here, these conditions should be met)
                # but the default password encryption is scram-sha-256, update the password.
                # Can be relevant when migrating from older version of postgres.
                pwchanging = True

    return pwchanging


def is_pg_passwd_md5(password):
    # 32: MD5 hashes are represented as a sequence of 32 hexadecimal digits
    #  3: The size of the 'md5' prefix
    return True if password.startswith('md5') and len(password) == 32 + 3 else False


def get_role_attrs(db_connection, module, cursor, user):
    current_role_attrs = None

    # Let's first try to get the attrs from pg_authid.
    # Some systems like AWS RDS instances
    # do not allow user to access pg_authid
    try:
        query = "SELECT * FROM pg_authid where rolname=%(user)s"
        cursor.execute(query, {"user": user})
        current_role_attrs = cursor.fetchone()
    except psycopg.ProgrammingError:
        db_connection.rollback()

    # If we succeeded, return it
    if current_role_attrs is not None:
        return current_role_attrs

    # If we haven't succeeded, like in case of AWS RDS,
    # try to get the attrs from the pg_roles table
    try:
        query = "SELECT * FROM pg_roles where rolname=%(user)s"
        cursor.execute(query, {"user": user})
        current_role_attrs = cursor.fetchone()
    except psycopg.ProgrammingError as e:
        db_connection.rollback()
        module.fail_json(msg="Failed to get role details for current user %s: %s" % (user, e))

    return current_role_attrs


def need_to_change_role_attr_flags(role_attr_flags, current_role_attrs):
    # Compare the desired role_attr_flags and current ones.
    # If they don't match, return True which means
    # they need to be updated, False otherwise.

    role_attr_flags_changing = False
    if role_attr_flags:
        role_attr_flags_dict = {}
        for r in role_attr_flags.split(' '):
            if r.startswith('NO'):
                role_attr_flags_dict[r.replace('NO', '', 1)] = False
            else:
                role_attr_flags_dict[r] = True

        for role_attr_name, role_attr_value in role_attr_flags_dict.items():
            if current_role_attrs[PRIV_TO_AUTHID_COLUMN[role_attr_name]] != role_attr_value:
                role_attr_flags_changing = True

    return role_attr_flags_changing


def need_to_change_role_expiration(cursor, expires, current_role_attrs):
    expires_changing = False

    if expires is not None:
        cursor.execute("SELECT %s::timestamptz exp_timestamp", (expires,))
        expires_with_tz = cursor.fetchone()["exp_timestamp"]
        # If the desired expiration date is not equal to
        # what is already set for the role, set this to True
        expires_changing = expires_with_tz != current_role_attrs.get('rolvaliduntil')

    return expires_changing


def need_to_change_conn_limit(conn_limit, current_role_attrs):
    return (conn_limit is not None and conn_limit != current_role_attrs['rolconnlimit'])


def exec_alter_user(module, cursor, statement, params=None):
    changed = False

    if params is None:
        params = {}

    try:
        cursor.execute(statement, params)
        executed_queries.append(statement)
        changed = True
    # We could catch psycopg.errors.ReadOnlySqlTransaction directly,
    # but that was added only in Psycopg 2.8
    except psycopg.InternalError as e:
        if e.diag.sqlstate == "25006":
            # Handle errors due to read-only transactions indicated by pgcode 25006
            # ERROR:  cannot execute ALTER ROLE in a read-only transaction
            changed = False
            module.fail_json(msg=e.diag.message_primary, exception=traceback.format_exc())
            return changed
        else:
            raise psycopg.InternalError(e)
    except psycopg.NotSupportedError as e:
        module.fail_json(msg=e.diag.message_primary, exception=traceback.format_exc())

    return changed


def user_alter(db_connection, module, user, password, role_attr_flags, encrypted, expires, no_password_changes, conn_limit):
    """Change user password and/or attributes. Return True if changed, False otherwise."""
    changed = False

    cursor = db_connection.cursor(**pg_cursor_args)
    # Note: role_attr_flags escaped by parse_role_attrs and encrypted is a literal
    if user == 'PUBLIC':
        if password is not None:
            module.fail_json(msg="cannot change the password for PUBLIC user")
        elif role_attr_flags != '':
            module.fail_json(msg="cannot change the role_attr_flags for PUBLIC user")
        else:
            return False

    # Handle passwords.
    if not no_password_changes and (password is not None or role_attr_flags != '' or expires is not None or conn_limit is not None):
        # Get role's current attributes to check if they match with the desired state
        current_role_attrs = get_role_attrs(db_connection, module, cursor, user)

        # Does password need to changed?
        pwchanging = user_should_we_change_password(cursor, current_role_attrs, user, password, encrypted)

        # Do role attributes need to changed?
        role_attr_flags_changing = need_to_change_role_attr_flags(role_attr_flags, current_role_attrs)

        # Does role expiration date need to changed?
        expires_changing = need_to_change_role_expiration(cursor, expires, current_role_attrs)

        # Does role connection limit need to change?
        conn_limit_changing = need_to_change_conn_limit(conn_limit, current_role_attrs)

        # Now let's check if anything needs to changed. If nothing, just return False
        if not pwchanging and not role_attr_flags_changing and not expires_changing and not conn_limit_changing:
            return False

        # If we are here, something does need to change.
        # Compose a statement and execute it
        alter = ['ALTER USER %(user)s' % {"user": _pg_quote_user(user, module)}]
        if pwchanging:
            if password != '':
                alter.append("WITH %(crypt)s" % {"crypt": encrypted})
                alter.append("PASSWORD %(password)s")
            else:
                alter.append("WITH PASSWORD NULL")
            alter.append(role_attr_flags)
        elif role_attr_flags:
            alter.append('WITH %s' % role_attr_flags)
        if expires is not None:
            alter.append("VALID UNTIL %(expires)s")
        if conn_limit is not None:
            alter.append("CONNECTION LIMIT %(conn_limit)s" % {"conn_limit": conn_limit})

        query_password_data = dict(password=password, expires=expires)
        statement = ' '.join(alter)
        changed = exec_alter_user(module, cursor, statement, query_password_data)

    elif no_password_changes and role_attr_flags != '':
        # Get role's current attributes to check if they match with the desired state
        current_role_attrs = get_role_attrs(db_connection, module, cursor, user)

        # Do role attributes need to changed? If not, just return False right away
        role_attr_flags_changing = need_to_change_role_attr_flags(role_attr_flags, current_role_attrs)
        if not role_attr_flags_changing:
            return False

        # If they need, compose a statement and execute
        alter = ['ALTER USER %(user)s' %
                 {"user": _pg_quote_user(user, module)}]
        if role_attr_flags:
            alter.append('WITH %s' % role_attr_flags)

        statement = ' '.join(alter)

        changed = exec_alter_user(module, cursor, statement)

        # Fetch new role attributes.
        new_role_attrs = get_role_attrs(db_connection, module, cursor, user)

        # Detect any differences between current_ and new_role_attrs.
        changed = current_role_attrs != new_role_attrs

    return changed


def user_delete(cursor, user, module):
    """Try to remove a user. Returns True if successful otherwise False"""
    cursor.execute("SAVEPOINT ansible_pgsql_user_delete")
    try:
        query = 'DROP USER %s' % _pg_quote_user(user, module)
        executed_queries.append(query)
        cursor.execute(query)
    except Exception as e:
        cursor.execute("ROLLBACK TO SAVEPOINT ansible_pgsql_user_delete")
        cursor.execute("RELEASE SAVEPOINT ansible_pgsql_user_delete")
        return False, e

    cursor.execute("RELEASE SAVEPOINT ansible_pgsql_user_delete")
    return True, None


def parse_role_attrs(role_attr_flags, srv_version):
    """
    Parse role attributes string for user creation.
    Format:

        attributes[,attributes,...]

    Where:

        attributes := CREATEDB,CREATEROLE,NOSUPERUSER,...
        [ "[NO]SUPERUSER","[NO]CREATEROLE", "[NO]CREATEDB",
                            "[NO]INHERIT", "[NO]LOGIN", "[NO]REPLICATION",
                            "[NO]BYPASSRLS" ]

    Note: "[NO]BYPASSRLS" role attribute introduced in 9.5
    Note: "[NO]CREATEUSER" role attribute is deprecated.

    """
    flags = frozenset(role.upper() for role in role_attr_flags.split(',') if role)

    valid_flags = frozenset(itertools.chain(FLAGS, get_valid_flags_by_version(srv_version)))
    valid_flags = frozenset(itertools.chain(valid_flags, ('NO%s' % flag for flag in valid_flags)))

    if not flags.issubset(valid_flags):
        raise InvalidFlagsError('Invalid role_attr_flags specified: %s' %
                                ' '.join(flags.difference(valid_flags)))

    return ' '.join(flags)


def get_valid_flags_by_version(srv_version):
    """
    Some role attributes were introduced after certain versions. We want to
    compile a list of valid flags against the current Postgres version.
    """
    return [
        flag
        for flag, version_introduced in FLAGS_BY_VERSION.items()
        if srv_version >= version_introduced
    ]


def add_comment(cursor, user, comment, check_mode):
    """Add comment on user."""
    current_comment = get_comment(cursor, 'role', user)
    # For the resetting comment feature (comment: '') to work correctly
    current_comment = current_comment if current_comment is not None else ''
    if comment != current_comment:
        set_comment(cursor, comment, 'role', user, check_mode, executed_queries)
        return True
    else:
        return False


def compare_user_configurations(current, desired, reset_unspec_config):
    """Compares two configurations and returns a list of values to reset as well as a dict of parameters to update."""
    reset = []
    update = desired.copy()

    # check each item in the current configuration
    for key, value in current.items():
        # we already have the correct setting
        if key in desired and value == desired[key]:
            # so we can remove it from the list
            del update[key]
        # if the key is not in the list of settings we want, and we reset unspecified parameters
        elif key not in desired and reset_unspec_config:
            # we will reset it on the database
            reset.append(key)
        # if the setting is not in the db or has the wrong value, it will get updated

    return {"reset": reset, "update": update}


def parse_user_configuration(module, configs):
    """Parses configuration from a list of 'key=value' strings like returned from the database to a dict."""
    if configs is not None:
        try:
            # parses a list of "key=value" strings to a dict
            return {t[0]: t[1] for t in map(lambda s: s.split("=", 1), configs)}
        except IndexError:
            module.fail_json(
                msg="Expecting a list of strings where each string has the format 'key=value'.")
    else:
        return {}


def user_configuration(cursor, module, user, configuration, reset_unspec_config, quote_values):
    """Updates the user's configuration parameters if necessary."""
    current_config_query = "SELECT rolconfig FROM pg_roles WHERE rolname = %(user)s;"
    cursor.execute(current_config_query, {"user": user})
    current_config = cursor.fetchone()
    changed = False

    if current_config is None:
        module.fail_json(msg="Can't find user %(user)s in 'pg_roles'" % {"user": user})

    current_config_dict = parse_user_configuration(module, current_config['rolconfig'])
    config_updates = compare_user_configurations(current_config_dict, configuration, reset_unspec_config)

    try:
        # It seems psycopg's prepared statements don't work with 'ALTER ROLE' at this point.
        # This is vulnerable to SQL-injections (added to docs) but I don't see a better way to do this.
        for item in config_updates["reset"]:
            query = 'ALTER ROLE %(user)s RESET "%(key)s";' % {"user": _pg_quote_user(user, module), "key": item}
            executed_queries.append(query)
            cursor.execute(query)
            changed = True
        for key, value in config_updates["update"].items():
            if quote_values:
                query = ('ALTER ROLE %(user)s SET "%(key)s" TO \'%(value)s\';' %
                         {"user": _pg_quote_user(user, module), "key": key, "value": value})
            else:
                query = ('ALTER ROLE %(user)s SET "%(key)s" TO %(value)s;' %
                         {"user": _pg_quote_user(user, module), "key": key, "value": value})
            executed_queries.append(query)
            cursor.execute(query)
            changed = True
    except psycopg.ProgrammingError as e:
        module.fail_json("Unable to update configuration for '%(user)s' due to: %(exception)s" %
                         {"user": user, "exception": e})
    return changed


def _pg_quote_user(user, module):
    """correctly escape users, pg_quote_identifiers will fail if the user contains a dot but is not pre-quoted"""
    if user[0] != '"' and user[-1] != '"':
        # we pre-quote users to make sure pg_quote_identifiers doesn't fail on dots
        return pg_quote_identifier('"%s"' % user, 'role')
    elif (user[0] == '"' and user[-1] != '"') or (user[0] != '"' and user[-1] == '"'):
        module.fail_json("The value of the user-field can't contain a double-quote in the end "
                         "if it doesn't start with one and vice-versa.")
    else:
        # user is already quoted, we run it through pg_quote_identifiers to make sure it doesn't contain any lonely
        # double-quotes to prevent SQL-injections
        return pg_quote_identifier(user, 'role')


# ===========================================
# Module execution.
#

def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        user=dict(type='str', required=True, aliases=['name']),
        password=dict(type='str', default=None, no_log=True),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        login_db=dict(type='str', default="", aliases=['db'], deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        fail_on_user=dict(type='bool', default=True, aliases=['fail_on_role']),
        role_attr_flags=dict(type='str', default=''),
        encrypted=dict(type='bool', default=True),
        no_password_changes=dict(type='bool', default=False, no_log=False),
        expires=dict(type='str', default=None),
        conn_limit=dict(type='int', default=None),
        session_role=dict(type='str'),
        comment=dict(type='str', default=None),
        trust_input=dict(type='bool', default=True),
        configuration=dict(type='dict', default={}),
        reset_unspecified_configuration=dict(type='bool', default=False),
        quote_configuration_values=dict(type='bool', default=True),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    user = module.params["user"]
    password = module.params["password"]
    state = module.params["state"]
    fail_on_user = module.params["fail_on_user"]
    no_password_changes = module.params["no_password_changes"]
    if module.params["encrypted"]:
        encrypted = "ENCRYPTED"
    else:
        encrypted = "UNENCRYPTED"
    expires = module.params["expires"]
    conn_limit = module.params["conn_limit"]
    role_attr_flags = module.params["role_attr_flags"]
    comment = module.params["comment"]
    session_role = module.params['session_role']
    configuration = module.params['configuration']
    reset_unspec_config = module.params['reset_unspecified_configuration']
    quote_configuration_values = module.params['quote_configuration_values']

    trust_input = module.params['trust_input']
    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, user, password, expires,
                    role_attr_flags, comment, session_role, comment, configuration)

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params)
    cursor = db_connection.cursor(**pg_cursor_args)

    srv_version = get_server_version(db_connection)

    # sanitize configuration
    if quote_configuration_values:
        for key, value in configuration.items():
            if '"' in key or '\'' in key:
                module.fail_json("The key of a configuration may not contain single or double quotes")
            configuration[key] = value.replace("'", "''")

    try:
        role_attr_flags = parse_role_attrs(role_attr_flags, srv_version)
    except InvalidFlagsError as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    kw = dict(user=user)
    changed = False

    if state == "present":
        if user_exists(cursor, user):
            try:
                changed = user_alter(db_connection, module, user, password,
                                     role_attr_flags, encrypted, expires, no_password_changes, conn_limit)
            except SQLParseError as e:
                module.fail_json(msg=to_native(e), exception=traceback.format_exc())
        else:
            try:
                changed = user_add(cursor, user, password,
                                   role_attr_flags, encrypted, expires, conn_limit, module)
            except psycopg.ProgrammingError as e:
                module.fail_json(msg="Unable to add user with given requirement "
                                     "due to : %s" % to_native(e),
                                 exception=traceback.format_exc())
            except SQLParseError as e:
                module.fail_json(msg=to_native(e), exception=traceback.format_exc())

        if comment is not None:
            try:
                changed = add_comment(cursor, user, comment, module.check_mode) or changed
            except Exception as e:
                module.fail_json(msg='Unable to add comment on role: %s' % to_native(e),
                                 exception=traceback.format_exc())

        # handle user-specific configuration-defaults
        changed = user_configuration(cursor, module, user, configuration, reset_unspec_config,
                                     quote_configuration_values) or changed

    else:
        if user_exists(cursor, user):
            if module.check_mode:
                changed = True
                kw['user_removed'] = True
            else:
                try:
                    changed, err = user_delete(cursor, user, module)
                except SQLParseError as e:
                    module.fail_json(msg=to_native(e), exception=traceback.format_exc())

                if fail_on_user and not changed:
                    msg = "Unable to remove user: %s" % err
                    module.fail_json(msg=msg)
                kw['user_removed'] = changed

    if module.check_mode:
        db_connection.rollback()
    else:
        db_connection.commit()

    cursor.close()
    db_connection.close()

    kw['changed'] = changed
    kw['queries'] = executed_queries
    if debug_info:
        kw['debug_info'] = debug_info
    module.exit_json(**kw)


if __name__ == '__main__':
    main()
