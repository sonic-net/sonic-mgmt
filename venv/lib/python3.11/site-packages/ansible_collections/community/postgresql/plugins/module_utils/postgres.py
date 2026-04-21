# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c), Ted Timmons <ted@timmons.me>, 2017.
# Most of this was originally added by other creators in the postgresql_user module.
#
# Simplified BSD License (see simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from datetime import timedelta, datetime
from decimal import Decimal
from os import environ

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import missing_required_lib
from ansible_collections.community.postgresql.plugins.module_utils.version import \
    LooseVersion

psycopg = None  # This line is needed for unit tests
psycopg2 = None  # This line is needed for unit tests
pg_cursor_args = None  # This line is needed for unit tests
PSYCOPG_VERSION = LooseVersion("0.0")  # This line is needed for unit tests

try:
    import psycopg
    from psycopg import ClientCursor
    from psycopg.rows import dict_row

    from psycopg.types.datetime import TimestamptzLoader

    # We need Psycopg 3 to be at least 3.1.0 because we need Client-side-binding cursors
    # When a Linux distribution provides both Psycopg2 and Psycopg 3.0 we will use Psycopg2
    PSYCOPG_VERSION = LooseVersion(psycopg.__version__)
    if PSYCOPG_VERSION < LooseVersion("3.1"):
        raise ImportError
    HAS_PSYCOPG = True
    pg_cursor_args = {"row_factory": psycopg.rows.dict_row}
except ImportError:
    try:
        import psycopg2
        psycopg = psycopg2
        from psycopg2.extras import DictCursor
        PSYCOPG_VERSION = LooseVersion(psycopg2.__version__)
        HAS_PSYCOPG = True
        pg_cursor_args = {"cursor_factory": DictCursor}
    except ImportError:
        HAS_PSYCOPG = False

TYPES_NEED_TO_CONVERT = (Decimal, timedelta)


if PSYCOPG_VERSION >= LooseVersion("3"):
    class InfTimestamptzLoader(TimestamptzLoader):
        def load(self, data):
            if data == b"infinity":
                return datetime.max
            elif data == b"-infinity":
                return datetime.min
            else:
                return super().load(data)

    psycopg.adapters.register_loader("timestamptz", InfTimestamptzLoader)


def postgres_common_argument_spec():
    """
    Return a dictionary with connection options.

    The options are commonly used by most of PostgreSQL modules.
    """
    # Getting a dictionary of environment variables
    env_vars = environ

    return dict(
        login_user=dict(
            default='postgres' if not env_vars.get("PGUSER") else env_vars.get("PGUSER"),
            aliases=['login'], deprecated_aliases=[
                {
                    'name': 'login',
                    'version': '5.0.0',
                    'collection_name': 'community.postgresql',
                }
            ],
        ),
        login_password=dict(default='', no_log=True),
        login_host=dict(default='', aliases=['host'], deprecated_aliases=[
            {
                'name': 'host',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        login_unix_socket=dict(default='', aliases=['unix_socket'], deprecated_aliases=[
            {
                'name': 'unix_socket',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        login_port=dict(
            type='int',
            default=int(env_vars.get("PGPORT", 5432)),
            aliases=['port'], deprecated_aliases=[
                {
                    'name': 'port',
                    'version': '5.0.0',
                    'collection_name': 'community.postgresql',
                }
            ],
        ),
        ssl_mode=dict(
            default='prefer',
            choices=[
                'allow',
                'disable',
                'prefer',
                'require',
                'verify-ca',
                'verify-full'
            ]
        ),
        ca_cert=dict(aliases=['ssl_rootcert']),
        ssl_cert=dict(type='path'),
        ssl_key=dict(type='path'),
        connect_params=dict(default={}, type='dict'),
    )


def ensure_required_libs(module):
    """Check required libraries."""
    if not HAS_PSYCOPG:
        # TODO: Should we raise it as psycopg? That will be a breaking change
        module.fail_json(msg=missing_required_lib('psycopg2'))

    elif PSYCOPG_VERSION < LooseVersion("2.5.1"):
        module.warn("psycopg should be at least 2.5.1 to support all modules functionality")

    if module.params.get('ca_cert') and PSYCOPG_VERSION < LooseVersion('2.4.3'):
        module.fail_json(msg='psycopg2 must be at least 2.4.3 in order to use the ca_cert parameter')


def connect_to_db(module, conn_params, autocommit=False, fail_on_conn=True):
    """Connect to a PostgreSQL database.

    Return a tuple containing a psycopg connection object and error message / None.

    Args:
        module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule class
        conn_params (dict) -- dictionary with connection parameters

    Kwargs:
        autocommit (bool) -- commit automatically (default False)
        fail_on_conn (bool) -- fail if connection failed or just warn and return None (default True)
    """

    db_connection = None
    conn_err = None
    try:
        if PSYCOPG_VERSION >= LooseVersion("3.0"):
            conn_params["autocommit"] = autocommit
            conn_params["cursor_factory"] = ClientCursor
            conn_params["row_factory"] = dict_row
            db_connection = psycopg.connect(**conn_params)
        else:
            db_connection = psycopg2.connect(**conn_params)
            if autocommit:
                if PSYCOPG_VERSION >= LooseVersion("2.4.2"):
                    db_connection.set_session(autocommit=True)
                else:
                    db_connection.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

        # Switch role, if specified:
        if module.params.get('session_role'):
            if PSYCOPG_VERSION >= LooseVersion("3.0"):
                cursor = db_connection.cursor(row_factory=psycopg.rows.dict_row)
            else:
                cursor = db_connection.cursor(cursor_factory=psycopg2.extras.DictCursor)

            try:
                cursor.execute('SET ROLE "%s"' % module.params['session_role'])
            except Exception as e:
                module.fail_json(msg="Could not switch role: %s" % to_native(e))
            finally:
                cursor.close()

        # Ensure proper datestyle, only supported in psycopg 3
        if PSYCOPG_VERSION >= LooseVersion("3.0"):
            cursor = db_connection.cursor(row_factory=psycopg.rows.dict_row)
            try:
                cursor.execute('SET datestyle TO iso')
            except Exception as e:
                module.fail_json(msg="Could not set date style: %s" % to_native(e))
            finally:
                cursor.close()

    except TypeError as e:
        if 'sslrootcert' in e.args[0]:
            module.fail_json(msg='Postgresql server must be at least '
                                 'version 8.4 to support sslrootcert')

        conn_err = to_native(e)

    except Exception as e:
        conn_err = to_native(e)

    if conn_err is not None:
        if fail_on_conn:
            module.fail_json(msg="unable to connect to database: %s" % conn_err)
        else:
            module.warn("PostgreSQL server is unavailable: %s" % conn_err)
            db_connection = None

    return db_connection, conn_err


def exec_sql(obj, query, query_params=None, return_bool=False, add_to_executed=True, dont_exec=False):
    """Execute SQL.

    Auxiliary function for PostgreSQL user classes.

    Returns a query result if possible or a boolean value.

    Args:
        obj (obj) -- must be an object of a user class.
            The object must have module (AnsibleModule class object) and
            cursor (psycopg cursor object) attributes
        query (str) -- SQL query to execute

    Kwargs:
        query_params (dict or tuple) -- Query parameters to prevent SQL injections,
            could be a dict or tuple
        return_bool (bool) -- return True instead of rows if a query was successfully executed.
            It's necessary for statements that don't return any result like DDL queries (default False).
        add_to_executed (bool) -- append the query to obj.executed_queries attribute
        dont_exec (bool) -- used with add_to_executed=True to generate a query, add it
            to obj.executed_queries list and return True (default False)
    """

    if dont_exec:
        # This is usually needed to return queries in check_mode
        # without execution
        query = obj.cursor.mogrify(query, query_params)
        if add_to_executed:
            obj.executed_queries.append(query)

        return True

    try:
        if query_params is not None:
            obj.cursor.execute(query, query_params)
        else:
            obj.cursor.execute(query)

        if add_to_executed:
            if query_params is not None:
                obj.executed_queries.append(obj.cursor.mogrify(query, query_params))
            else:
                obj.executed_queries.append(query)

        if not return_bool:
            res = obj.cursor.fetchall()
            return res
        return True
    except Exception as e:
        obj.module.fail_json(msg="Cannot execute SQL '%s': %s" % (query, to_native(e)))
    return False


def get_conn_params(module, params_dict, warn_db_default=True):
    """Get connection parameters from the passed dictionary.

    Return a dictionary with parameters to connect to PostgreSQL server.

    Args:
        module (AnsibleModule) -- object of ansible.module_utils.basic.AnsibleModule class
        params_dict (dict) -- dictionary with variables

    Kwargs:
        warn_db_default (bool) -- warn that the default DB is used (default True)
    """

    # To use defaults values, keyword arguments must be absent, so
    # check which values are empty and don't include in the return dictionary
    params_map = {
        "login_host": "host",
        "login_user": "user",
        "login_password": "password",
        "login_port": "port",
        "ssl_mode": "sslmode",
        "ca_cert": "sslrootcert",
        "ssl_cert": "sslcert",
        "ssl_key": "sslkey",
    }

    # Might be different in the modules:
    if PSYCOPG_VERSION >= LooseVersion("2.7.0"):
        if params_dict.get('db'):
            params_map['db'] = 'dbname'
        elif params_dict.get('database'):
            params_map['database'] = 'dbname'
        elif params_dict.get('login_db'):
            params_map['login_db'] = 'dbname'
        else:
            if warn_db_default:
                module.warn('Database name has not been passed, '
                            'used default database to connect to.')
    else:
        if params_dict.get('db'):
            params_map['db'] = 'database'
        elif params_dict.get('database'):
            params_map['database'] = 'database'
        elif params_dict.get('login_db'):
            params_map['login_db'] = 'database'
        else:
            if warn_db_default:
                module.warn('Database name has not been passed, '
                            'used default database to connect to.')

    kw = dict((params_map[k], v) for (k, v) in params_dict.items()
              if k in params_map and v != '' and v is not None)

    # If a login_unix_socket is specified, incorporate it here.
    is_localhost = False
    if 'host' not in kw or kw['host'] in [None, 'localhost']:
        is_localhost = True

    if is_localhost and params_dict["login_unix_socket"] != "":
        kw["host"] = params_dict["login_unix_socket"]

    # If connect_params is specified, merge it together
    if params_dict.get("connect_params"):
        kw.update(params_dict["connect_params"])

    return kw


class PgRole():
    def __init__(self, module, cursor, name):
        self.module = module
        self.cursor = cursor
        self.name = name
        self.memberof = self.__fetch_members()

    def __fetch_members(self):
        query = ("SELECT ARRAY(SELECT b.rolname FROM "
                 "pg_catalog.pg_auth_members m "
                 "JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid) "
                 "WHERE m.member = r.oid) "
                 "FROM pg_catalog.pg_roles r "
                 "WHERE r.rolname = %(dst_role)s")

        res = exec_sql(self, query, query_params={'dst_role': self.name},
                       add_to_executed=False)
        if res:
            return res[0]["array"]
        else:
            return []


class PgMembership(object):
    def __init__(self, module, cursor, groups, target_roles, fail_on_role=True):
        self.module = module
        self.cursor = cursor
        self.target_roles = [r.strip() for r in target_roles]
        self.groups = [r.strip() for r in groups]
        self.executed_queries = []
        self.granted = {}
        self.revoked = {}
        self.fail_on_role = fail_on_role
        self.non_existent_roles = []
        self.changed = False
        self.__check_roles_exist()

    def grant(self):
        for group in self.groups:
            self.granted[group] = []

            for role in self.target_roles:
                role_obj = PgRole(self.module, self.cursor, role)
                # If role is in a group now, pass:
                if group in role_obj.memberof:
                    continue

                query = 'GRANT "%s" TO "%s"' % (group, role)
                self.changed = exec_sql(self, query, return_bool=True)

                if self.changed:
                    self.granted[group].append(role)

        return self.changed

    def revoke(self):
        for group in self.groups:
            self.revoked[group] = []

            for role in self.target_roles:
                role_obj = PgRole(self.module, self.cursor, role)
                # If role is not in a group now, pass:
                if group not in role_obj.memberof:
                    continue

                query = 'REVOKE "%s" FROM "%s"' % (group, role)
                self.changed = exec_sql(self, query, return_bool=True)

                if self.changed:
                    self.revoked[group].append(role)

        return self.changed

    def match(self):
        for role in self.target_roles:
            role_obj = PgRole(self.module, self.cursor, role)

            desired_groups = set(self.groups)
            current_groups = set(role_obj.memberof)
            # 1. Get groups that the role is member of but not in self.groups and revoke them
            groups_to_revoke = current_groups - desired_groups
            for group in groups_to_revoke:
                query = 'REVOKE "%s" FROM "%s"' % (group, role)
                self.changed = exec_sql(self, query, return_bool=True)
                if group in self.revoked:
                    self.revoked[group].append(role)
                else:
                    self.revoked[group] = [role]

            # 2. Filter out groups that in self.groups and
            # the role is already member of and grant the rest
            groups_to_grant = desired_groups - current_groups
            for group in groups_to_grant:
                query = 'GRANT "%s" TO "%s"' % (group, role)
                self.changed = exec_sql(self, query, return_bool=True)
                if group in self.granted:
                    self.granted[group].append(role)
                else:
                    self.granted[group] = [role]

        return self.changed

    def __check_roles_exist(self):
        if self.groups:
            existent_groups = self.__roles_exist(self.groups)

            for group in self.groups:
                if group not in existent_groups:
                    if self.fail_on_role:
                        self.module.fail_json(msg="Role %s does not exist" % group)
                    else:
                        self.module.warn("Role %s does not exist, pass" % group)
                        self.non_existent_roles.append(group)

        existent_roles = self.__roles_exist(self.target_roles)
        for role in self.target_roles:
            if role not in existent_roles:
                if self.fail_on_role:
                    self.module.fail_json(msg="Role %s does not exist" % role)
                else:
                    self.module.warn("Role %s does not exist, pass" % role)

                if role not in self.groups:
                    self.non_existent_roles.append(role)

                else:
                    if self.fail_on_role:
                        self.module.exit_json(msg="Role role '%s' is a member of role '%s'" % (role, role))
                    else:
                        self.module.warn("Role role '%s' is a member of role '%s', pass" % (role, role))

        # Update role lists, excluding non existent roles:
        if self.groups:
            self.groups = [g for g in self.groups if g not in self.non_existent_roles]

        self.target_roles = [r for r in self.target_roles if r not in self.non_existent_roles]

    def __roles_exist(self, roles):
        tmp = ["'" + x + "'" for x in roles]
        query = "SELECT rolname FROM pg_roles WHERE rolname IN (%s)" % ','.join(tmp)
        return [x["rolname"] for x in exec_sql(self, query, add_to_executed=False)]


def set_search_path(cursor, search_path):
    """Set session's search_path.

    Args:
        cursor (Psycopg cursor): Database cursor object.
        search_path (str): String containing comma-separated schema names.
    """
    cursor.execute('SET search_path TO %s' % search_path)


def convert_elements_to_pg_arrays(obj):
    """Convert list elements of the passed object
    to PostgreSQL arrays represented as strings.

    Args:
        obj (dict or list): Object whose elements need to be converted.

    Returns:
        obj (dict or list): Object with converted elements.
    """
    if isinstance(obj, dict):
        for (key, elem) in obj.items():
            if isinstance(elem, list):
                obj[key] = list_to_pg_array(elem)

    elif isinstance(obj, list):
        for i, elem in enumerate(obj):
            if isinstance(elem, list):
                obj[i] = list_to_pg_array(elem)

    return obj


def list_to_pg_array(elem):
    """Convert the passed list to PostgreSQL array
    represented as a string.

    Args:
        elem (list): List that needs to be converted.

    Returns:
        elem (str): String representation of PostgreSQL array.
    """
    elem = str(elem).strip('[]')
    elem = '{' + elem + '}'
    return elem


def convert_to_supported(val):
    """Convert unsupported type to appropriate.
    Args:
        val (any) -- Any value fetched from database.
    Returns value of appropriate type.
    """
    if isinstance(val, Decimal):
        return float(val)

    elif isinstance(val, timedelta):
        return str(val)

    return val  # By default returns the same value


def get_server_version(conn):
    """Get server version.

    Args:
        conn (psycopg.Connection) -- Psycopg connection object.

    Returns server version (int).
    """
    if PSYCOPG_VERSION >= LooseVersion("3.0.0"):
        return conn.info.server_version
    else:
        return conn.server_version


def set_autocommit(conn, autocommit):
    """Set autocommit.

    Args:
        conn (psycopg.Connection) -- Psycopg connection object.
        autocommit -- bool.
    """
    if PSYCOPG_VERSION >= LooseVersion("2.4.2"):
        conn.autocommit = autocommit
    else:
        if autocommit:
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        else:
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED)


def get_comment(cursor, obj_type, obj_name):
    """Get DB object's comment.

    Args:
        cursor (Psycopg cursor) -- Database cursor object.
        obj_name (str) -- DB object name to get comment from.
        obj_type (str) -- Object type.

    Returns object's comment (str) if present or None.
    """
    query = ''
    if obj_type == 'role':
        query = ("SELECT pg_catalog.shobj_description(r.oid, 'pg_authid') AS comment "
                 "FROM pg_catalog.pg_roles AS r "
                 "WHERE r.rolname = %(obj_name)s")
    elif obj_type == 'extension':
        query = ("SELECT pg_catalog.obj_description(e.oid, 'pg_extension') AS comment "
                 "FROM pg_catalog.pg_extension AS e "
                 "WHERE e.extname = %(obj_name)s")

    cursor.execute(query, {'obj_name': obj_name})
    return cursor.fetchone()['comment']


def set_comment(cursor, comment, obj_type, obj_name, check_mode=True, executed_queries=None):
    """Get DB object's comment.

    Args:
        cursor (Psycopg cursor) -- Database cursor object.
        comment(str) -- Comment to set on object.
        obj_name (str) -- DB object name to set comment on.
        obj_type (str) -- Object type.
        executed_statements (list) -- List of executed state-modifying statements.
    """
    query = 'COMMENT ON %s "%s" IS ' % (obj_type.upper(), obj_name)

    if not check_mode:
        cursor.execute(query + '%(comment)s', {'comment': comment})

    if executed_queries is not None:
        executed_queries.append(cursor.mogrify(query + '%(comment)s', {'comment': comment}))

    return True
