#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# Copyright: (c) 2019, Tobias Birkefeld (@tcraxs) <t@craxs.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_privs
short_description: Grant or revoke privileges on PostgreSQL database objects
description:
- Grant or revoke privileges on PostgreSQL database objects.
- This module is basically a wrapper around most of the functionality of
  PostgreSQL's GRANT and REVOKE statements with detection of changes
  (GRANT/REVOKE I(privs) ON I(type) I(objs) TO/FROM I(roles)).
options:
  login_db:
    description:
    - Name of database to connect to.
    - The V(db) and V(database) aliases are deprecated and will be removed in version 5.0.0.
    required: true
    type: str
    aliases:
    - db
    - database
  state:
    description:
    - If C(present), the specified privileges are granted, if C(absent) they are revoked.
    type: str
    default: present
    choices: [ absent, present ]
  privs:
    description:
    - Comma separated list of privileges to grant/revoke.
    type: str
    aliases:
    - priv
  type:
    description:
    - Type of database object to set privileges on.
    - The C(default_privs) choice is available starting at version 2.7.
    - The C(foreign_data_wrapper) and C(foreign_server) object types are available since Ansible version 2.8.
    - The C(type) choice is available since Ansible version 2.10.
    - The C(procedure) is supported since collection version 1.3.0 and PostgreSQL 11.
    - The C(parameter) is supported since collection version 3.1.0 and PostgreSQL 15.
    - The C(table) also includes views and materialized views. It is inclusive of foreign tables since collection version 3.6.0.
    type: str
    default: table
    choices: [ database, default_privs, foreign_data_wrapper, foreign_server, function,
               group, language, table, tablespace, schema, sequence, type, procedure, parameter ]
  objs:
    description:
    - Comma separated list of database objects to set privileges on.
    - If I(type) is C(table), C(partition table), C(sequence), C(function) or C(procedure),
      the special value C(ALL_IN_SCHEMA) can be provided instead to specify all
      database objects of I(type) in the schema specified via I(schema).
      (This also works with PostgreSQL < 9.0.) (C(ALL_IN_SCHEMA) is available
       for C(function) and C(partition table) since Ansible 2.8).
    - C(procedure) is supported since PostgreSQL 11 and community.postgresql collection 1.3.0.
    - C(parameter) is supported since PostgreSQL 15 and community.postgresql collection 3.1.0.
    - If I(type) is C(database), this parameter can be omitted, in which case
      privileges are set for the database specified via I(database).
    - If I(type) is C(function) or C(procedure), colons (":") in object names will be
      replaced with commas (needed to specify signatures, see examples).
    type: str
    aliases:
    - obj
  schema:
    description:
    - Schema that contains the database objects specified via I(objs).
    - May only be provided if I(type) is C(table), C(sequence), C(function), C(procedure), C(type),
      or C(default_privs). Defaults to C(public) in these cases.
    - Pay attention, for embedded types when I(type=type)
      I(schema) can be C(pg_catalog) or C(information_schema) respectively.
    - If not specified, uses C(public). Not to pass any schema, use C(not-specified).
    type: str
  roles:
    description:
    - Comma separated list of role (user/group) names to set permissions for.
    - Roles C(PUBLIC), C(CURRENT_ROLE), C(CURRENT_USER), C(SESSION_USER) are implicitly defined in PostgreSQL.
    - C(CURRENT_USER) and C(SESSION_USER) implicit roles are supported since collection version 3.1.0 and PostgreSQL 9.5.
    - C(CURRENT_ROLE) implicit role is supported since collection version 3.1.0 and PostgreSQL 14.
    type: str
    required: true
    aliases:
    - role
  fail_on_role:
    description:
    - If C(true), fail when target role (for whom privs need to be granted) does not exist.
      Otherwise just warn and continue.
    default: true
    type: bool
  session_role:
    description:
    - Switch to session_role after connecting.
    - The specified session_role must be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though the session_role were the one that had logged in originally.
    type: str
  target_roles:
    description:
    - A list of existing role (user/group) names to set as the
      default permissions for database objects subsequently created by them.
    - Parameter I(target_roles) is only available with C(type=default_privs).
    type: str
  grant_option:
    description:
    - Whether C(role) may grant/revoke the specified privileges/group memberships to others.
    - Set to C(false) to revoke GRANT OPTION, leave unspecified to make no changes.
    - I(grant_option) only has an effect if I(state) is C(present).
    type: bool
    aliases:
    - admin_option
  trust_input:
    description:
    - If C(false), check whether values of parameters I(roles), I(target_roles), I(session_role),
      I(schema) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via the parameters are possible.
    type: bool
    default: true
    version_added: '0.2.0'

notes:
- Parameters that accept comma separated lists (I(privs), I(objs), I(roles))
  have singular alias names (I(priv), I(obj), I(role)).
- To revoke only C(GRANT OPTION) for a specific object, set I(state) to
  C(present) and I(grant_option) to C(false) (see examples).
- Note that when revoking privileges from a role R, this role  may still have
  access via privileges granted to any role R is a member of including C(PUBLIC).
- Note that when revoking privileges from a role R, you do so as the user
  specified via I(login_user). If R has been granted the same privileges by
  another user also, R can still access database objects via these privileges.
- When revoking privileges, C(RESTRICT) is assumed (see PostgreSQL docs).

seealso:
- module: community.postgresql.postgresql_user
- module: community.postgresql.postgresql_owner
- module: community.postgresql.postgresql_membership
- name: PostgreSQL privileges
  description: General information about PostgreSQL privileges.
  link: https://www.postgresql.org/docs/current/ddl-priv.html
- name: PostgreSQL GRANT command reference
  description: Complete reference of the PostgreSQL GRANT command documentation.
  link: https://www.postgresql.org/docs/current/sql-grant.html
- name: PostgreSQL REVOKE command reference
  description: Complete reference of the PostgreSQL REVOKE command documentation.
  link: https://www.postgresql.org/docs/current/sql-revoke.html

attributes:
  check_mode:
    support: full

extends_documentation_fragment:
- community.postgresql.postgres

author:
- Bernhard Weitzhofer (@b6d)
- Tobias Birkefeld (@tcraxs)
- Daniele Giudice (@RealGreenDragon)
'''

EXAMPLES = r'''
# On database "library":
# GRANT SELECT, INSERT, UPDATE ON TABLE public.books, public.authors
# TO librarian, reader WITH GRANT OPTION
- name: Grant privs to librarian and reader on database library
  community.postgresql.postgresql_privs:
    login_db: library
    state: present
    privs: SELECT,INSERT,UPDATE
    type: table
    objs: books,authors
    schema: public
    roles: librarian,reader
    grant_option: true

- name: Same as above leveraging default values
  community.postgresql.postgresql_privs:
    login_db: library
    privs: SELECT,INSERT,UPDATE
    objs: books,authors
    roles: librarian,reader
    grant_option: true

# REVOKE GRANT OPTION FOR INSERT ON TABLE books FROM reader
# Note that role "reader" will be *granted* INSERT privilege itself if this
# isn't already the case (since state: present).
- name: Revoke privs from reader
  community.postgresql.postgresql_privs:
    login_db: library
    state: present
    priv: INSERT
    obj: books
    role: reader
    grant_option: false

# "public" is the default schema. This also works for PostgreSQL 8.x.
- name: REVOKE INSERT, UPDATE ON ALL TABLES IN SCHEMA public FROM reader
  community.postgresql.postgresql_privs:
    login_db: library
    state: absent
    privs: INSERT,UPDATE
    objs: ALL_IN_SCHEMA
    role: reader

- name: GRANT ALL PRIVILEGES ON SCHEMA public, math TO librarian
  community.postgresql.postgresql_privs:
    login_db: library
    privs: ALL
    type: schema
    objs: public,math
    role: librarian

# Note the separation of arguments with colons.
- name: GRANT ALL PRIVILEGES ON FUNCTION math.add(int, int) TO librarian, reader
  community.postgresql.postgresql_privs:
    login_db: library
    privs: ALL
    type: function
    obj: add(int:int)
    schema: math
    roles: librarian,reader

# Note that group role memberships apply cluster-wide and therefore are not
# restricted to database "library" here.
- name: GRANT librarian, reader TO alice, bob WITH ADMIN OPTION
  community.postgresql.postgresql_privs:
    login_db: library
    type: group
    objs: librarian,reader
    roles: alice,bob
    admin_option: true

# Note that here "db: postgres" specifies the database to connect to, not the
# database to grant privileges on (which is specified via the "objs" param)
- name: GRANT ALL PRIVILEGES ON DATABASE library TO librarian
  community.postgresql.postgresql_privs:
    login_db: postgres
    privs: ALL
    type: database
    obj: library
    role: librarian

# If objs is omitted for type "database", it defaults to the database
# to which the connection is established
- name: GRANT ALL PRIVILEGES ON DATABASE library TO librarian
  community.postgresql.postgresql_privs:
    login_db: library
    privs: ALL
    type: database
    role: librarian

# Available since version 2.7
# Objs must be set, ALL_DEFAULT to TABLES/SEQUENCES/TYPES/FUNCTIONS
# ALL_DEFAULT works only with privs=ALL
# For specific
- name: ALTER DEFAULT PRIVILEGES ON DATABASE library TO librarian
  community.postgresql.postgresql_privs:
    login_db: library
    objs: ALL_DEFAULT
    privs: ALL
    type: default_privs
    role: librarian
    grant_option: true

# Available since version 2.7
# Objs must be set, ALL_DEFAULT to TABLES/SEQUENCES/TYPES/FUNCTIONS
# ALL_DEFAULT works only with privs=ALL
# For specific
- name: ALTER DEFAULT PRIVILEGES ON DATABASE library TO reader, step 1
  community.postgresql.postgresql_privs:
    login_db: library
    objs: TABLES,SEQUENCES
    privs: SELECT
    type: default_privs
    role: reader

- name: ALTER DEFAULT PRIVILEGES ON DATABASE library TO reader, step 2
  community.postgresql.postgresql_privs:
    login_db: library
    objs: TYPES
    privs: USAGE
    type: default_privs
    role: reader

# Available since version 2.8
- name: GRANT ALL PRIVILEGES ON FOREIGN DATA WRAPPER fdw TO reader
  community.postgresql.postgresql_privs:
    login_db: library
    objs: fdw
    privs: ALL
    type: foreign_data_wrapper
    role: reader

# Available since community.postgresql 0.2.0
- name: GRANT ALL PRIVILEGES ON TYPE customtype TO reader
  community.postgresql.postgresql_privs:
    login_db: library
    objs: customtype
    privs: ALL
    type: type
    role: reader

# Available since version 2.8
- name: GRANT ALL PRIVILEGES ON FOREIGN SERVER fdw_server TO reader
  community.postgresql.postgresql_privs:
    login_db: test
    objs: fdw_server
    privs: ALL
    type: foreign_server
    role: reader

# Available since version 2.8
# Grant 'execute' permissions on all functions in schema 'common' to role 'caller'
- name: GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA common TO caller
  community.postgresql.postgresql_privs:
    type: function
    state: present
    privs: EXECUTE
    roles: caller
    objs: ALL_IN_SCHEMA
    schema: common

# Available since collection version 1.3.0
# Grant 'execute' permissions on all procedures in schema 'common' to role 'caller'
# Needs PostreSQL 11 or higher and community.postgresql 1.3.0 or higher
- name: GRANT EXECUTE ON ALL PROCEDURES IN SCHEMA common TO caller
  community.postgresql.postgresql_privs:
    type: procedure
    state: present
    privs: EXECUTE
    roles: caller
    objs: ALL_IN_SCHEMA
    schema: common

# Available since version 2.8
# ALTER DEFAULT PRIVILEGES FOR ROLE librarian IN SCHEMA library GRANT SELECT ON TABLES TO reader
# GRANT SELECT privileges for new TABLES objects created by librarian as
# default to the role reader.
# For specific
- name: ALTER privs
  community.postgresql.postgresql_privs:
    login_db: library
    schema: library
    objs: TABLES
    privs: SELECT
    type: default_privs
    role: reader
    target_roles: librarian

# Available since version 2.8
# ALTER DEFAULT PRIVILEGES FOR ROLE librarian IN SCHEMA library REVOKE SELECT ON TABLES FROM reader
# REVOKE SELECT privileges for new TABLES objects created by librarian as
# default from the role reader.
# For specific
- name: ALTER privs
  community.postgresql.postgresql_privs:
    login_db: library
    state: absent
    schema: library
    objs: TABLES
    privs: SELECT
    type: default_privs
    role: reader
    target_roles: librarian

# Available since community.postgresql 0.2.0
- name: Grant type privileges for pg_catalog.numeric type to alice
  community.postgresql.postgresql_privs:
    type: type
    roles: alice
    privs: ALL
    objs: numeric
    schema: pg_catalog
    login_db: acme

- name: Alter default privileges grant usage on schemas to datascience
  community.postgresql.postgresql_privs:
    login_db: test
    type: default_privs
    privs: usage
    objs: schemas
    role: datascience

# Available since community.postgresql 3.1.0
# Needs PostgreSQL 15 or higher
- name: GRANT SET ON PARAMETER log_destination,log_line_prefix TO logtest
  community.postgresql.postgresql_privs:
    login_db: logtest
    state: present
    privs: SET
    type: parameter
    objs: log_destination,log_line_prefix
    roles: logtest

- name: GRANT ALTER SYSTEM ON PARAMETER primary_conninfo,synchronous_standby_names TO replicamgr
  community.postgresql.postgresql_privs:
    login_db: replicamgr
    state: present
    privs: ALTER_SYSTEM
    type: parameter
    objs: primary_conninfo,synchronous_standby_names
    roles: replicamgr
'''

RETURN = r'''
queries:
  description: List of executed queries.
  returned: success
  type: list
  sample: ['REVOKE GRANT OPTION FOR INSERT ON TABLE "books" FROM "reader";']
'''

import traceback

from ansible.module_utils.common.text.converters import to_native
# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import (
    check_input,
    pg_quote_identifier,
)
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    HAS_PSYCOPG,
    PSYCOPG_VERSION,
    connect_to_db,
    ensure_required_libs,
    get_conn_params,
    get_server_version,
    pg_cursor_args,
    postgres_common_argument_spec,
)
from ansible_collections.community.postgresql.plugins.module_utils.version import \
    LooseVersion

if HAS_PSYCOPG and PSYCOPG_VERSION < LooseVersion("3.0"):
    from psycopg2 import Error as PsycopgError
elif HAS_PSYCOPG:
    from psycopg import Error as PsycopgError

VALID_PRIVS = frozenset(('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'CREATE',
                         'CONNECT', 'TEMPORARY', 'TEMP', 'EXECUTE', 'USAGE', 'ALL', 'SET', 'ALTER_SYSTEM',
                         'MAINTAIN'))
VALID_DEFAULT_OBJS = {'TABLES': ('ALL', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN'),
                      'SEQUENCES': ('ALL', 'SELECT', 'UPDATE', 'USAGE'),
                      'FUNCTIONS': ('ALL', 'EXECUTE'),
                      'TYPES': ('ALL', 'USAGE'),
                      'SCHEMAS': ('CREATE', 'USAGE'), }
VALID_IMPLICIT_ROLES = {'PUBLIC': 0,
                        'CURRENT_USER': 95000,
                        'SESSION_USER': 95000,
                        'CURRENT_ROLE': 140000, }

executed_queries = []


class Error(Exception):
    pass


# We don't have functools.partial in Python < 2.5
def partial(f, *args, **kwargs):
    """Partial function application"""

    def g(*g_args, **g_kwargs):
        new_kwargs = kwargs.copy()
        new_kwargs.update(g_kwargs)
        return f(*(args + g_args), **g_kwargs)

    g.f = f
    g.args = args
    g.kwargs = kwargs
    return g


class Connection(object):
    """Wrapper around a psycopg connection with some convenience methods"""

    def __init__(self, params, module):
        self.database = params.login_db
        self.module = module

        # Ensure psycopg libraries are available before connecting to DB:
        ensure_required_libs(module)
        conn_params = get_conn_params(module, params.__dict__, warn_db_default=False)

        self.connection, dummy = connect_to_db(module, conn_params, autocommit=False)
        self.cursor = self.connection.cursor(**pg_cursor_args)
        self.pg_version = get_server_version(self.connection)

        # implicit roles in current pg version
        self.pg_implicit_roles = tuple(
            implicit_role for implicit_role, version_min in VALID_IMPLICIT_ROLES.items() if self.pg_version >= version_min
        )

    def execute(self, query, input_vars=None):
        try:
            self.cursor.execute(query, input_vars)
        except Exception as e:
            self.module.fail_json(msg="Cannot execute SQL '%s': %s" % (query, to_native(e)))

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    # Methods for implicit roles managements

    def is_implicit_role(self, rolname):
        return rolname.upper() in self.pg_implicit_roles

    # Methods for querying database objects

    def role_exists(self, rolname):
        # check if rolname is a implicit role
        if self.is_implicit_role(rolname):
            return True

        # check if rolname is present in pg_catalog.pg_roles
        query = "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s"
        self.execute(query, (rolname,))
        return self.cursor.rowcount > 0

    # PostgreSQL < 9.0 doesn't support "ALL TABLES IN SCHEMA schema"-like
    # phrases in GRANT or REVOKE statements, therefore alternative methods are
    # provided here.

    def schema_exists(self, schema):
        query = """SELECT count(*) c
                   FROM pg_catalog.pg_namespace WHERE nspname = %s"""
        self.execute(query, (schema,))
        return self.cursor.fetchone()["c"] > 0

    def get_all_tables_in_schema(self, schema):
        if schema:
            if not self.schema_exists(schema):
                raise Error('Schema "%s" does not exist.' % schema)

            query = """SELECT relname
                       FROM pg_catalog.pg_class c
                       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                       WHERE nspname = %s AND relkind in ('r', 'v', 'm', 'p', 'f')"""
            self.execute(query, (schema,))
        else:
            query = ("SELECT relname FROM pg_catalog.pg_class "
                     "WHERE relkind in ('r', 'v', 'm', 'p', 'f')")
            self.execute(query)
        return [t["relname"] for t in self.cursor.fetchall()]

    def get_all_sequences_in_schema(self, schema):
        if schema:
            if not self.schema_exists(schema):
                raise Error('Schema "%s" does not exist.' % schema)
            query = """SELECT relname
                       FROM pg_catalog.pg_class c
                       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                       WHERE nspname = %s AND relkind = 'S'"""
            self.execute(query, (schema,))
        else:
            self.execute("SELECT relname FROM pg_catalog.pg_class WHERE relkind = 'S'")
        return [t["relname"] for t in self.cursor.fetchall()]

    def get_all_functions_in_schema(self, schema):
        if schema:
            if not self.schema_exists(schema):
                raise Error('Schema "%s" does not exist.' % schema)

            query = ("SELECT p.proname, oidvectortypes(p.proargtypes) ptypes "
                     "FROM pg_catalog.pg_proc p "
                     "JOIN pg_namespace n ON n.oid = p.pronamespace "
                     "WHERE nspname = %s")

            if self.pg_version >= 110000:
                query += " and p.prokind = 'f'"

            self.execute(query, (schema,))
        else:
            self.execute("SELECT p.proname, oidvectortypes(p.proargtypes) ptypes FROM pg_catalog.pg_proc p")
        return ["%s(%s)" % (t["proname"], t["ptypes"]) for t in self.cursor.fetchall()]

    def get_all_procedures_in_schema(self, schema):
        if self.pg_version < 110000:
            raise Error("PostgreSQL version must be >= 11 for type=procedure. Exit")

        if schema:
            if not self.schema_exists(schema):
                raise Error('Schema "%s" does not exist.' % schema)

            query = ("SELECT p.proname, oidvectortypes(p.proargtypes) ptypes "
                     "FROM pg_catalog.pg_proc p "
                     "JOIN pg_namespace n ON n.oid = p.pronamespace "
                     "WHERE nspname = %s and p.prokind = 'p'")

            self.execute(query, (schema,))
        else:
            query = ("SELECT p.proname, oidvectortypes(p.proargtypes) ptypes "
                     "FROM pg_catalog.pg_proc p WHERE p.prokind = 'p'")
            self.execute(query)
        return ["%s(%s)" % (t["proname"], t["ptypes"]) for t in self.cursor.fetchall()]

    # Methods for getting access control lists and group membership info

    # To determine whether anything has changed after granting/revoking
    # privileges, we compare the access control lists of the specified database
    # objects before and afterwards. Python's list/string comparison should
    # suffice for change detection, we should not actually have to parse ACLs.
    # The same should apply to group membership information.

    def get_table_acls(self, schema, tables):
        if schema:
            query = """SELECT relacl::text
                       FROM pg_catalog.pg_class c
                       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                       WHERE nspname = %s AND relkind in ('r','p','v','m','f') AND relname = ANY (%s)
                       ORDER BY relname"""
            self.execute(query, (schema, tables))
        else:
            query = ("SELECT relacl::text FROM pg_catalog.pg_class "
                     "WHERE relkind in ('r','p','v','m','f') AND relname = ANY (%s) "
                     "ORDER BY relname")
            self.execute(query)
        return [t["relacl"] for t in self.cursor.fetchall()]

    def get_sequence_acls(self, schema, sequences):
        if schema:
            query = """SELECT relacl::text
                       FROM pg_catalog.pg_class c
                       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                       WHERE nspname = %s AND relkind = 'S' AND relname = ANY (%s)
                       ORDER BY relname"""
            self.execute(query, (schema, sequences))
        else:
            query = ("SELECT relacl::text FROM pg_catalog.pg_class "
                     "WHERE  relkind = 'S' AND relname = ANY (%s) ORDER BY relname")
            self.execute(query)
        return [t["relacl"] for t in self.cursor.fetchall()]

    def get_function_acls(self, schema, function_signatures):
        funcnames = [f.split('(', 1)[0] for f in function_signatures]
        if schema:
            query = """SELECT proacl::text
                       FROM pg_catalog.pg_proc p
                       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                       WHERE nspname = %s AND proname = ANY (%s)
                       ORDER BY proname, proargtypes"""
            self.execute(query, (schema, funcnames))
        else:
            query = ("SELECT proacl::text FROM pg_catalog.pg_proc WHERE proname = ANY (%s) "
                     "ORDER BY proname, proargtypes")
            self.execute(query, (funcnames))
        return [t["proacl"] for t in self.cursor.fetchall()]

    def get_schema_acls(self, schemas):
        query = """SELECT nspacl::text FROM pg_catalog.pg_namespace
                   WHERE nspname = ANY (%s) ORDER BY nspname"""
        self.execute(query, (schemas,))
        return [t["nspacl"] for t in self.cursor.fetchall()]

    def get_language_acls(self, languages):
        query = """SELECT lanacl::text FROM pg_catalog.pg_language
                   WHERE lanname = ANY (%s) ORDER BY lanname"""
        self.execute(query, (languages,))
        return [t["lanacl"] for t in self.cursor.fetchall()]

    def get_tablespace_acls(self, tablespaces):
        query = """SELECT spcacl::text FROM pg_catalog.pg_tablespace
                   WHERE spcname = ANY (%s) ORDER BY spcname"""
        self.execute(query, (tablespaces,))
        return [t["spcacl"] for t in self.cursor.fetchall()]

    def get_database_acls(self, databases):
        query = """SELECT datacl::text FROM pg_catalog.pg_database
                   WHERE datname = ANY (%s) ORDER BY datname"""
        self.execute(query, (databases,))
        return [t["datacl"] for t in self.cursor.fetchall()]

    def get_group_memberships(self, groups):
        query = """SELECT roleid, grantor, member, admin_option
                   FROM pg_catalog.pg_auth_members am
                   JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
                   WHERE r.rolname = ANY(%s)
                   ORDER BY roleid, grantor, member"""
        self.execute(query, (groups,))
        return self.cursor.fetchall()

    def get_default_privs(self, schema, *args):
        if schema:
            query = """SELECT defaclacl::text
                       FROM pg_default_acl a
                       JOIN pg_namespace b ON a.defaclnamespace=b.oid
                       WHERE b.nspname = %s;"""
            self.execute(query, (schema,))
        else:
            self.execute("SELECT defaclacl::text FROM pg_default_acl;")
        return [t["defaclacl"] for t in self.cursor.fetchall()]

    def get_foreign_data_wrapper_acls(self, fdws):
        query = """SELECT fdwacl::text FROM pg_catalog.pg_foreign_data_wrapper
                   WHERE fdwname = ANY (%s) ORDER BY fdwname"""
        self.execute(query, (fdws,))
        return [t["fdwacl"] for t in self.cursor.fetchall()]

    def get_foreign_server_acls(self, fs):
        query = """SELECT srvacl::text FROM pg_catalog.pg_foreign_server
                   WHERE srvname = ANY (%s) ORDER BY srvname"""
        self.execute(query, (fs,))
        return [t["srvacl"] for t in self.cursor.fetchall()]

    def get_type_acls(self, schema, types):
        if schema:
            query = """SELECT t.typacl::text FROM pg_catalog.pg_type t
                       JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
                       WHERE n.nspname = %s AND t.typname = ANY (%s) ORDER BY typname"""
            self.execute(query, (schema, types))
        else:
            query = "SELECT typacl::text FROM pg_catalog.pg_type WHERE typname = ANY (%s) ORDER BY typname"
            self.execute(query)
        return [t["typacl"] for t in self.cursor.fetchall()]

    def get_parameter_acls(self, parameters):
        if self.pg_version < 150000:
            raise Error("PostgreSQL version must be >= 15 for type=parameter. Exit")

        query = """SELECT paracl::text FROM pg_catalog.pg_parameter_acl
                   WHERE parname = ANY (%s) ORDER BY parname"""
        self.cursor.execute(query, (parameters,))
        return [t["paracl"] for t in self.cursor.fetchall()]

    # Manipulating privileges

    def manipulate_privs(self, obj_type, privs, objs, orig_objs, roles, target_roles,
                         state, grant_option, schema_qualifier=None, fail_on_role=True):
        """Manipulate database object privileges.

        :param obj_type: Type of database object to grant/revoke
                         privileges for.
        :param privs: Either a list of privileges to grant/revoke
                      or None if type is "group".
        :param objs: List of database objects to grant/revoke
                     privileges for.
        :param orig_objs: ALL_IN_SCHEMA or None.
        :param roles: List of role names.
        :param target_roles: List of role names to grant/revoke
                             default privileges as.
        :param state: "present" to grant privileges, "absent" to revoke.
        :param grant_option: Only for state "present": If True, set
                             grant/admin option. If False, revoke it.
                             If None, don't change grant option.
        :param schema_qualifier: Some object types ("TABLE", "SEQUENCE",
                                 "FUNCTION") must be qualified by schema.
                                 Ignored for other Types.
        """
        # get_status: function to get current status
        if obj_type == 'table':
            get_status = partial(self.get_table_acls, schema_qualifier)
        elif obj_type == 'sequence':
            get_status = partial(self.get_sequence_acls, schema_qualifier)
        elif obj_type in ('function', 'procedure'):
            get_status = partial(self.get_function_acls, schema_qualifier)
        elif obj_type == 'schema':
            get_status = self.get_schema_acls
        elif obj_type == 'language':
            get_status = self.get_language_acls
        elif obj_type == 'tablespace':
            get_status = self.get_tablespace_acls
        elif obj_type == 'database':
            get_status = self.get_database_acls
        elif obj_type == 'group':
            get_status = self.get_group_memberships
        elif obj_type == 'default_privs':
            get_status = partial(self.get_default_privs, schema_qualifier)
        elif obj_type == 'foreign_data_wrapper':
            get_status = self.get_foreign_data_wrapper_acls
        elif obj_type == 'foreign_server':
            get_status = self.get_foreign_server_acls
        elif obj_type == 'type':
            get_status = partial(self.get_type_acls, schema_qualifier)
        elif obj_type == 'parameter':
            get_status = self.get_parameter_acls
        else:
            raise Error('Unsupported database object type "%s".' % obj_type)

        # Return False (nothing has changed) if there are no objs to work on.
        if not objs:
            return False

        quoted_schema_qualifier = '"%s"' % schema_qualifier.replace('"', '""') if schema_qualifier else None
        # obj_ids: quoted db object identifiers (sometimes schema-qualified)
        if obj_type in ('function', 'procedure'):
            obj_ids = []
            for obj in objs:
                try:
                    f, args = obj.split('(', 1)
                except Exception:
                    raise Error('Illegal function / procedure signature: "%s".' % obj)
                obj_ids.append('%s."%s"(%s' % (quoted_schema_qualifier, f, args))
        elif obj_type in ['table', 'sequence', 'type']:
            obj_ids = ['%s."%s"' % (quoted_schema_qualifier, o) for o in objs]
        else:
            obj_ids = ['"%s"' % o for o in objs]

        # set_what: SQL-fragment specifying what to set for the target roles:
        # Either group membership or privileges on objects of a certain type
        if obj_type == 'group':
            set_what = ','.join(obj_ids)
        elif obj_type == 'default_privs':
            # We don't want privs to be quoted here
            set_what = ','.join(privs)
        else:
            # function types are already quoted above
            if obj_type not in ('function', 'procedure'):
                obj_ids = [pg_quote_identifier(i, 'table') for i in obj_ids]
            # Note: obj_type has been checked against a set of string literals
            # and privs was escaped when it was parsed
            # Note: Underscores are replaced with spaces to support multi-word privs and obj_type
            if orig_objs is not None:
                set_what = '%s ON %s %s' % (','.join(privs).replace('_', ' '), orig_objs, quoted_schema_qualifier)
            else:
                set_what = '%s ON %s %s' % (','.join(privs).replace('_', ' '), obj_type.replace('_', ' '), ','.join(obj_ids))

        # for_whom: SQL-fragment specifying for whom to set the above
        if not roles:
            return False
        for_whom = ','.join(roles)

        # as_who: SQL-fragment specifying to who to set the above
        as_who = None
        if target_roles:
            as_who = ','.join('"%s"' % r for r in target_roles)

        status_before = get_status(objs)

        query = QueryBuilder(state) \
            .for_objtype(obj_type) \
            .with_grant_option(grant_option) \
            .for_whom(for_whom) \
            .as_who(as_who) \
            .for_schema(quoted_schema_qualifier) \
            .set_what(set_what) \
            .for_objs(objs) \
            .build()

        executed_queries.append(query)
        self.execute(query)

        status_after = get_status(objs)

        def nonesorted(e):
            # For python 3+ that can fail trying
            # to compare NoneType elements by sort method.
            if e is None:
                return ''
            # With Psycopg 3 we get a list of dicts, it is easier to sort it as strings
            return str(e)

        status_before.sort(key=nonesorted)
        status_after.sort(key=nonesorted)
        return status_before != status_after


class QueryBuilder(object):
    def __init__(self, state):
        self._grant_option = None
        self._for_whom = None
        self._as_who = None
        self._set_what = None
        self._obj_type = None
        self._state = state
        self._schema = None
        self._objs = None
        self.query = []

    def for_objs(self, objs):
        self._objs = objs
        return self

    def for_schema(self, schema):
        self._schema = ' IN SCHEMA %s' % schema if schema is not None else ''
        return self

    def with_grant_option(self, option):
        self._grant_option = option
        return self

    def for_whom(self, who):
        self._for_whom = who
        return self

    def as_who(self, target_roles):
        self._as_who = target_roles
        return self

    def set_what(self, what):
        self._set_what = what
        return self

    def for_objtype(self, objtype):
        self._obj_type = objtype
        return self

    def build(self):
        if self._state == 'present':
            self.build_present()
        elif self._state == 'absent':
            self.build_absent()
        else:
            self.build_absent()
        return '\n'.join(self.query)

    def add_default_revoke(self):
        for obj in self._objs:
            if self._as_who:
                self.query.append(
                    'ALTER DEFAULT PRIVILEGES FOR ROLE {0}{1} REVOKE ALL ON {2} FROM {3};'.format(self._as_who,
                                                                                                  self._schema, obj,
                                                                                                  self._for_whom))
            else:
                self.query.append(
                    'ALTER DEFAULT PRIVILEGES{0} REVOKE ALL ON {1} FROM {2};'.format(self._schema, obj,
                                                                                     self._for_whom))

    def add_grant_option(self):
        if self._grant_option:
            if self._obj_type == 'group':
                self.query[-1] += ' WITH ADMIN OPTION;'
            else:
                self.query[-1] += ' WITH GRANT OPTION;'
        elif self._grant_option is False:
            self.query[-1] += ';'
            if self._obj_type == 'group':
                self.query.append('REVOKE ADMIN OPTION FOR {0} FROM {1};'.format(self._set_what, self._for_whom))
            elif not self._obj_type == 'default_privs':
                self.query.append('REVOKE GRANT OPTION FOR {0} FROM {1};'.format(self._set_what, self._for_whom))
        else:
            self.query[-1] += ';'

    def add_default_priv(self):
        for obj in self._objs:
            if self._as_who:
                self.query.append(
                    'ALTER DEFAULT PRIVILEGES FOR ROLE {0}{1} GRANT {2} ON {3} TO {4}'.format(self._as_who,
                                                                                              self._schema,
                                                                                              self._set_what,
                                                                                              obj,
                                                                                              self._for_whom))
            else:
                self.query.append(
                    'ALTER DEFAULT PRIVILEGES{0} GRANT {1} ON {2} TO {3}'.format(self._schema,
                                                                                 self._set_what,
                                                                                 obj,
                                                                                 self._for_whom))
            self.add_grant_option()

    def build_present(self):
        if self._obj_type == 'default_privs':
            self.add_default_revoke()
            self.add_default_priv()
        else:
            self.query.append('GRANT {0} TO {1}'.format(self._set_what, self._for_whom))
            self.add_grant_option()

    def build_absent(self):
        if self._obj_type == 'default_privs':
            self.query = []
            for obj in ['TABLES', 'FUNCTIONS', 'SEQUENCES', 'TYPES']:
                if self._as_who:
                    self.query.append(
                        'ALTER DEFAULT PRIVILEGES FOR ROLE {0}{1} REVOKE ALL ON {2} FROM {3};'.format(self._as_who,
                                                                                                      self._schema, obj,
                                                                                                      self._for_whom))
                else:
                    self.query.append(
                        'ALTER DEFAULT PRIVILEGES{0} REVOKE ALL ON {1} FROM {2};'.format(self._schema, obj,
                                                                                         self._for_whom))
        else:
            self.query.append('REVOKE {0} FROM {1};'.format(self._set_what, self._for_whom))


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        login_db=dict(type='str', required=True, aliases=['db', 'database'], deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            },
            {
                'name': 'database',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        state=dict(default='present', choices=['present', 'absent']),
        privs=dict(required=False, aliases=['priv']),
        type=dict(default='table',
                  choices=['table',
                           'sequence',
                           'function',
                           'procedure',
                           'database',
                           'schema',
                           'language',
                           'tablespace',
                           'group',
                           'default_privs',
                           'foreign_data_wrapper',
                           'foreign_server',
                           'type',
                           'parameter', ]),
        objs=dict(required=False, aliases=['obj']),
        schema=dict(required=False),
        roles=dict(required=True, aliases=['role']),
        session_role=dict(required=False),
        target_roles=dict(required=False),
        grant_option=dict(required=False, type='bool',
                          aliases=['admin_option']),
        fail_on_role=dict(type='bool', default=True),
        trust_input=dict(type='bool', default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    fail_on_role = module.params['fail_on_role']

    # Create type object as namespace for module params
    p = type('Params', (), module.params)

    # param "schema": default, allowed depends on param "type"
    if p.type in ['table', 'sequence', 'function', 'procedure', 'type', 'default_privs']:
        if p.objs == 'schemas' or p.schema == 'not-specified':
            p.schema = None
        else:
            p.schema = p.schema or 'public'
    elif p.schema:
        module.fail_json(msg='Argument "schema" is not allowed '
                             'for type "%s".' % p.type)

    # param "objs": ALL_IN_SCHEMA can be used only
    # when param "type" is table, sequence, function or procedure
    if p.objs == 'ALL_IN_SCHEMA' and p.type not in ('table', 'sequence', 'function', 'procedure'):
        module.fail_json(msg='Argument "objs": ALL_IN_SCHEMA can be used only for '
                             'type: table, sequence, function or procedure, '
                             '%s was passed.' % p.type)

    # param "objs": default, required depends on param "type"
    if p.type == 'database':
        p.objs = p.objs or p.login_db
    elif not p.objs:
        module.fail_json(msg='Argument "objs" is required '
                             'for type "%s".' % p.type)

    # param "privs": allowed, required depends on param "type"
    if p.type == 'group':
        if p.privs:
            module.fail_json(msg='Argument "privs" is not allowed '
                                 'for type "group".')
    elif not p.privs:
        module.fail_json(msg='Argument "privs" is required '
                             'for type "%s".' % p.type)

    # Check input
    if not p.trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, p.roles, p.target_roles, p.session_role, p.schema)

    # Connect to Database
    conn = Connection(p, module)

    if p.session_role:
        try:
            conn.cursor.execute('SET ROLE "%s"' % p.session_role)
        except Exception as e:
            module.fail_json(msg="Could not switch to role %s: %s" % (p.session_role, to_native(e)), exception=traceback.format_exc())

    try:
        # privs
        if p.privs:
            privs = frozenset(pr.upper() for pr in p.privs.split(','))
            if not privs.issubset(VALID_PRIVS):
                module.fail_json(msg='Invalid privileges specified: %s' % privs.difference(VALID_PRIVS))
        else:
            privs = None
        # objs:
        orig_objs = None
        if p.objs == 'ALL_IN_SCHEMA':
            if p.type == 'table':
                objs = conn.get_all_tables_in_schema(p.schema)
            elif p.type == 'sequence':
                objs = conn.get_all_sequences_in_schema(p.schema)
            elif p.type == 'function':
                objs = conn.get_all_functions_in_schema(p.schema)
            elif p.type == 'procedure':
                objs = conn.get_all_procedures_in_schema(p.schema)

            if conn.pg_version >= 90000:
                if p.type == 'table':
                    orig_objs = 'ALL TABLES IN SCHEMA'
                elif p.type == 'sequence':
                    orig_objs = 'ALL SEQUENCES IN SCHEMA'
                elif p.type == 'function':
                    orig_objs = 'ALL FUNCTIONS IN SCHEMA'
                elif p.type == 'procedure':
                    orig_objs = 'ALL PROCEDURES IN SCHEMA'

        elif p.type == 'default_privs':
            if p.objs == 'ALL_DEFAULT':
                VALID_DEFAULT_OBJS.pop('SCHEMAS')
                objs = frozenset(VALID_DEFAULT_OBJS.keys())
            else:
                objs = frozenset(obj.upper() for obj in p.objs.split(','))
                if not objs.issubset(VALID_DEFAULT_OBJS):
                    module.fail_json(
                        msg='Invalid Object set specified: %s' % objs.difference(VALID_DEFAULT_OBJS.keys()))
            # Again, do we have valid privs specified for object type:
            valid_objects_for_priv = frozenset(obj for obj in objs if privs.issubset(VALID_DEFAULT_OBJS[obj]))
            if not valid_objects_for_priv == objs:
                module.fail_json(
                    msg='Invalid priv specified. Valid object for priv: {0}. Objects: {1}'.format(
                        valid_objects_for_priv, objs))
        else:
            objs = p.objs.split(',')

            # function signatures are encoded using ':' to separate args
            if p.type in ('function', 'procedure'):
                objs = [obj.replace(':', ',') for obj in objs]

        # roles
        roles = []
        roles_raw = p.roles.split(',')
        for r in roles_raw:
            if conn.role_exists(r):
                if conn.is_implicit_role(r):
                    # Some implicit roles (as PUBLIC) works in uppercase without double quotes and in lowercase with double quotes.
                    # Other implicit roles (as SESSION_USER) works only in uppercase without double quotes.
                    # So the approach that works for all implicit roles is uppercase without double quotes.
                    roles.append('%s' % r.upper())
                else:
                    roles.append('"%s"' % r.replace('"', '""'))
            else:
                if fail_on_role:
                    module.fail_json(msg="Role '%s' does not exist" % r)
                else:
                    module.warn("Role '%s' does not exist, pass it" % r)
        if not roles:
            module.warn("No valid roles provided, nothing to do")
            module.exit_json(changed=False, queries=executed_queries)

        # check if target_roles is set with type: default_privs
        if p.target_roles and not p.type == 'default_privs':
            module.warn('"target_roles" will be ignored '
                        'Argument "type: default_privs" is required for usage of "target_roles".')

        # target roles
        if p.target_roles:
            target_roles = p.target_roles.split(',')
        else:
            target_roles = None

        changed = conn.manipulate_privs(
            obj_type=p.type,
            privs=privs,
            objs=objs,
            orig_objs=orig_objs,
            roles=roles,
            target_roles=target_roles,
            state=p.state,
            grant_option=p.grant_option,
            schema_qualifier=p.schema,
            fail_on_role=fail_on_role,
        )

    except Error as e:
        conn.rollback()
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    except PsycopgError as e:
        conn.rollback()
        module.fail_json(msg=to_native(e))

    if module.check_mode or not changed:
        conn.rollback()
    else:
        conn.commit()

    conn.cursor.close()
    conn.connection.close()

    module.exit_json(changed=changed, queries=executed_queries)


if __name__ == '__main__':
    main()
