#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_db
short_description: Add or remove PostgreSQL databases from a remote host
description:
   - Add or remove PostgreSQL databases from a remote host.
options:
  name:
    description:
      - Name of the database to add or remove.
    type: str
    required: true
    aliases: [ db ]
  owner:
    description:
      - Name of the role to set as owner of the database.
    type: str
    default: ''
  template:
    description:
      - Template used to create the database.
    type: str
    default: ''
  encoding:
    description:
      - Encoding of the database.
    type: str
    default: ''
  lc_collate:
    description:
      - Collation order (LC_COLLATE) to use in the database
        must match collation order of template database unless C(template0) is used as template.
    type: str
    default: ''
  lc_ctype:
    description:
      - Character classification (LC_CTYPE) to use in the database (e.g. lower, upper, ...).
      - Must match LC_CTYPE of template database unless C(template0) is used as template.
    type: str
    default: ''
  icu_locale:
    description:
      - Specifies the ICU locale (ICU_LOCALE) for the database default collation order and character classification, overriding the setting locale.
      - The locale provider must be ICU. The default is the setting of locale if specified; otherwise the same setting as the template database.
    type: str
    default: ''
    version_added: '3.4.0'
  locale_provider:
    description:
      - Specifies the provider to use for the default collation in this database (LOCALE_PROVIDER).
      - Possible values are icu (if the server was built with ICU support) or libc.
      - By default, the provider is the same as that of the template.
    type: str
    default: ''
    version_added: '3.4.0'
  session_role:
    description:
    - Switch to session_role after connecting.
    - The specified session_role must be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though the session_role
      were the one that had logged in originally.
    type: str
  state:
    description:
    - The database state.
    - C(present) implies that the database should be created if necessary.
    - C(absent) implies that the database should be removed if present.
    - C(dump) requires a target definition to which the database will be backed up. (Added in Ansible 2.4)
      Note that in some PostgreSQL versions of pg_dump, which is an embedded PostgreSQL utility and is used by the module,
      returns rc 0 even when errors occurred (e.g. the connection is forbidden by pg_hba.conf, etc.),
      so the module returns changed=True but the dump has not actually been done. Please, be sure that your version of
      pg_dump returns rc 1 in this case.
    - C(restore) also requires a target definition from which the database will be restored. (Added in Ansible 2.4).
    - The format of the backup will be detected based on the target name.
    - Supported compression formats for dump and restore determined by target file format C(.pgc) (custom), C(.bz2) (bzip2), C(.gz) (gzip/pigz) and C(.xz) (xz).
    - Supported formats for dump and restore determined by target file format C(.sql) (plain), C(.tar) (tar), C(.pgc) (custom) and C(.dir) (directory)
      For the directory format which is supported since collection version 1.4.0.
    - "Restore program is selected by target file format: C(.tar), C(.pgc), and C(.dir) are handled by pg_restore, other with pgsql."
    - "."
    - DEPRECATED (see the L(discussion,https://github.com/ansible-collections/community.postgresql/issues/820)).
      C(rename) is used to rename the database C(name) to C(target).
      To rename a database, use the M(community.postgresql.postgresql_query) module.
    type: str
    choices: [ absent, dump, present, rename, restore ]
    default: present
  force:
    description:
    - Used to forcefully drop a database when the I(state) is C(absent), ignored otherwise.
    type: bool
    default: False
  target:
    description:
    - File to back up or restore from.
    - Used when I(state) is C(dump) or C(restore).
    type: path
    default: ''
  target_opts:
    description:
    - Additional arguments for pg_dump or restore program (pg_restore or psql, depending on target's format).
    - Used when I(state) is C(dump) or C(restore).
    type: str
    default: ''
  maintenance_db:
    description:
      - The value specifies the initial database (which is also called as maintenance DB) that Ansible connects to.
    type: str
    default: postgres
  conn_limit:
    description:
      - Specifies the database connection limit.
    type: str
    default: ''
  tablespace:
    description:
      - The tablespace to set for the database
        U(https://www.postgresql.org/docs/current/sql-alterdatabase.html).
      - If you want to move the database back to the default tablespace,
        explicitly set this to pg_default.
    type: path
    default: ''
  dump_extra_args:
    description:
      - Provides additional arguments when I(state) is C(dump).
      - Cannot be used with dump-file-format-related arguments like ``--format=d``.
    type: str
    version_added: '0.2.0'
  trust_input:
    description:
    - If C(false), check whether values of parameters I(owner), I(conn_limit), I(encoding),
      I(db), I(template), I(tablespace), I(session_role) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via the parameters are possible.
    type: bool
    default: true
    version_added: '0.2.0'
  comment:
    description:
    - Sets a comment on the database.
    - To reset the comment, pass an empty string.
    type: str
    version_added: '3.3.0'
seealso:
- name: CREATE DATABASE reference
  description: Complete reference of the CREATE DATABASE command documentation.
  link: https://www.postgresql.org/docs/current/sql-createdatabase.html
- name: DROP DATABASE reference
  description: Complete reference of the DROP DATABASE command documentation.
  link: https://www.postgresql.org/docs/current/sql-dropdatabase.html
- name: pg_dump reference
  description: Complete reference of pg_dump documentation.
  link: https://www.postgresql.org/docs/current/app-pgdump.html
- name: pg_restore reference
  description: Complete reference of pg_restore documentation.
  link: https://www.postgresql.org/docs/current/app-pgrestore.html
- module: community.postgresql.postgresql_tablespace
- module: community.postgresql.postgresql_info
- module: community.postgresql.postgresql_ping

notes:
- State C(dump) and C(restore) don't require I(psycopg) since ansible version 2.8.

attributes:
  check_mode:
    support: full

author: "Ansible Core Team"

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Create a new database with name "acme"
  community.postgresql.postgresql_db:
    name: acme
    comment: My test DB

# Note: If a template different from "template0" is specified,
# encoding and locale settings must match those of the template.
- name: Create a new database with name "acme" and specific encoding and locale # settings
  community.postgresql.postgresql_db:
    name: acme
    encoding: UTF-8
    lc_collate: de_DE.UTF-8
    lc_ctype: de_DE.UTF-8
    locale_provider: icu
    icu_locale: de-DE-x-icu
    template: template0

# Note: Default limit for the number of concurrent connections to
# a specific database is "-1", which means "unlimited"
- name: Create a new database with name "acme" which has a limit of 100 concurrent connections
  community.postgresql.postgresql_db:
    name: acme
    conn_limit: "100"

- name: Dump an existing database to a file
  community.postgresql.postgresql_db:
    name: acme
    state: dump
    target: /tmp/acme.sql

- name: Dump an existing database to a file excluding the test table
  community.postgresql.postgresql_db:
    name: acme
    state: dump
    target: /tmp/acme.sql
    dump_extra_args: --exclude-table=test

- name: Dump an existing database to a file (with compression)
  community.postgresql.postgresql_db:
    name: acme
    state: dump
    target: /tmp/acme.sql.gz

- name: Dump a single schema for an existing database
  community.postgresql.postgresql_db:
    name: acme
    state: dump
    target: /tmp/acme.sql
    target_opts: "-n public"

- name: Dump only table1 and table2 from the acme database
  community.postgresql.postgresql_db:
    name: acme
    state: dump
    target: /tmp/table1_table2.sql
    target_opts: "-t table1 -t table2"

- name: Dump an existing database using the directory format
  community.postgresql.postgresql_db:
    name: acme
    state: dump
    target: /tmp/acme.dir

- name: Dump an existing database using the custom format
  community.postgresql.postgresql_db:
    name: acme
    state: dump
    target: /tmp/acme.pgc

# name: acme - the name of the database to connect through which the recovery will take place
- name: Restore database using the tar format
  community.postgresql.postgresql_db:
    name: acme
    state: restore
    target: /tmp/acme.tar

# Note: In the example below, if database foo exists and has another tablespace
# the tablespace will be changed to foo. Access to the database will be locked
# until the copying of database files is finished.
- name: Create a new database called foo in tablespace bar
  community.postgresql.postgresql_db:
    name: foo
    tablespace: bar
'''

RETURN = r'''
executed_commands:
  description: List of commands which tried to run.
  returned: success
  type: list
  sample: ["CREATE DATABASE acme"]
  version_added: '0.2.0'
'''


import os
import subprocess
import traceback

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves import shlex_quote
from ansible_collections.community.postgresql.plugins.module_utils.database import (
    SQLParseError,
    check_input,
)
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    get_conn_params,
    get_server_version,
    pg_cursor_args,
    postgres_common_argument_spec,
    set_comment,
)

executed_commands = []


class NotSupportedError(Exception):
    pass

# ===========================================
# PostgreSQL module specific support methods.
#


def set_owner(cursor, db, owner):
    query = 'ALTER DATABASE "%s" OWNER TO "%s"' % (db, owner)
    executed_commands.append(query)
    cursor.execute(query)
    return True


def set_conn_limit(cursor, db, conn_limit):
    query = 'ALTER DATABASE "%s" CONNECTION LIMIT %s' % (db, conn_limit)
    executed_commands.append(query)
    cursor.execute(query)
    return True


def get_encoding_id(cursor, encoding):
    query = "SELECT pg_char_to_encoding(%(encoding)s) AS encoding_id;"
    cursor.execute(query, {'encoding': encoding})
    return cursor.fetchone()['encoding_id']


def get_db_info(cursor, db):
    server_version = get_server_version(cursor.connection)
    if server_version >= 170000:
        query = """
        SELECT rolname AS owner,
        pg_encoding_to_char(encoding) AS encoding, encoding AS encoding_id,
        datcollate AS lc_collate, datctype AS lc_ctype, datlocale AS icu_locale,
        CASE datlocprovider WHEN 'c' THEN 'libc' WHEN 'i' THEN 'icu' END AS locale_provider,
        pg_database.datconnlimit AS conn_limit, spcname AS tablespace,
        pg_catalog.shobj_description(pg_database.oid, 'pg_database') AS comment
        FROM pg_database
        JOIN pg_roles ON pg_roles.oid = pg_database.datdba
        JOIN pg_tablespace ON pg_tablespace.oid = pg_database.dattablespace
        WHERE datname = %(db)s
        """
    elif server_version >= 150000 and server_version < 170000:
        query = """
        SELECT rolname AS owner,
        pg_encoding_to_char(encoding) AS encoding, encoding AS encoding_id,
        datcollate AS lc_collate, datctype AS lc_ctype, daticulocale AS icu_locale,
        CASE datlocprovider WHEN 'c' THEN 'libc' WHEN 'i' THEN 'icu' END AS locale_provider,
        pg_database.datconnlimit AS conn_limit, spcname AS tablespace,
        pg_catalog.shobj_description(pg_database.oid, 'pg_database') AS comment
        FROM pg_database
        JOIN pg_roles ON pg_roles.oid = pg_database.datdba
        JOIN pg_tablespace ON pg_tablespace.oid = pg_database.dattablespace
        WHERE datname = %(db)s
        """
    else:
        query = """
        SELECT rolname AS owner,
        pg_encoding_to_char(encoding) AS encoding, encoding AS encoding_id,
        datcollate AS lc_collate, datctype AS lc_ctype,
        null::char AS icu_locale, null::text AS locale_provider,
        pg_database.datconnlimit AS conn_limit, spcname AS tablespace,
        pg_catalog.shobj_description(pg_database.oid, 'pg_database') AS comment
        FROM pg_database
        JOIN pg_roles ON pg_roles.oid = pg_database.datdba
        JOIN pg_tablespace ON pg_tablespace.oid = pg_database.dattablespace
        WHERE datname = %(db)s
        """
    cursor.execute(query, {'db': db})
    return cursor.fetchone()


def db_exists(cursor, db):
    query = "SELECT * FROM pg_database WHERE datname=%(db)s"
    cursor.execute(query, {'db': db})
    return cursor.rowcount == 1


def db_dropconns(cursor, db):
    if get_server_version(cursor.connection) >= 90200:
        """ Drop DB connections in Postgres 9.2 and above """
        query_terminate = ("SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity "
                           "WHERE pg_stat_activity.datname=%(db)s AND pid <> pg_backend_pid()")
    else:
        """ Drop DB connections in Postgres 9.1 and below """
        query_terminate = ("SELECT pg_terminate_backend(pg_stat_activity.procpid) FROM pg_stat_activity "
                           "WHERE pg_stat_activity.datname=%(db)s AND procpid <> pg_backend_pid()")
    query_block = ("UPDATE pg_database SET datallowconn = false WHERE datname=%(db)s")
    query = query_block + '; ' + query_terminate

    cursor.execute(query, {'db': db})


def db_delete(cursor, db, force=False):
    if db_exists(cursor, db):
        query = 'DROP DATABASE "%s"' % db
        if force:
            if get_server_version(cursor.connection) >= 130000:
                query = ('DROP DATABASE "%s" WITH (FORCE)' % db)
            else:
                db_dropconns(cursor, db)
        executed_commands.append(query)
        cursor.execute(query)
        return True
    else:
        return False


def db_create(cursor, db, owner, template, encoding, lc_collate, lc_ctype, icu_locale, locale_provider, conn_limit, tablespace, comment, check_mode):

    params = dict(enc=encoding, collate=lc_collate, ctype=lc_ctype, iculocale=icu_locale, localeprovider=locale_provider, conn_limit=conn_limit,
                  tablespace=tablespace)

    icu_supported = get_server_version(cursor.connection) >= 150000

    query_fragments = ['CREATE DATABASE "%s"' % db]
    if owner:
        query_fragments.append('OWNER "%s"' % owner)
    if template:
        query_fragments.append('TEMPLATE "%s"' % template)
    if encoding:
        query_fragments.append('ENCODING %(enc)s')
    if lc_collate:
        query_fragments.append('LC_COLLATE %(collate)s')
    if lc_ctype:
        query_fragments.append('LC_CTYPE %(ctype)s')
    if icu_locale and icu_supported:
        query_fragments.append('ICU_LOCALE %(iculocale)s')
    if locale_provider and icu_supported:
        query_fragments.append('LOCALE_PROVIDER %(localeprovider)s')
    if tablespace:
        query_fragments.append('TABLESPACE "%s"' % tablespace)
    if conn_limit:
        query_fragments.append("CONNECTION LIMIT %(conn_limit)s" % {"conn_limit": conn_limit})
    query = ' '.join(query_fragments)
    executed_commands.append(cursor.mogrify(query, params))
    cursor.execute(query, params)
    if comment:
        set_comment(cursor, comment, 'database', db, check_mode, executed_commands)
    return True


def db_update(cursor, db, owner, encoding, lc_collate, lc_ctype, icu_locale, locale_provider, conn_limit, tablespace, comment, check_mode):
    db_info = get_db_info(cursor, db)

    if (encoding and get_encoding_id(cursor, encoding) != db_info['encoding_id']):
        raise NotSupportedError(
            'Changing database encoding is not supported. '
            'Current encoding: %s' % db_info['encoding']
        )
    elif lc_collate and lc_collate != db_info['lc_collate']:
        raise NotSupportedError(
            'Changing LC_COLLATE is not supported. '
            'Current LC_COLLATE: %s' % db_info['lc_collate']
        )
    elif lc_ctype and lc_ctype != db_info['lc_ctype']:
        raise NotSupportedError(
            'Changing LC_CTYPE is not supported.'
            'Current LC_CTYPE: %s' % db_info['lc_ctype']
        )
    elif icu_locale and icu_locale != db_info['icu_locale']:
        raise NotSupportedError(
            'Changing ICU_LOCALE is not supported.'
            'Current ICU_LOCALE: %s' % db_info['icu_locale']
        )
    elif locale_provider and locale_provider != db_info['locale_provider']:
        raise NotSupportedError(
            'Changing LOCALE_PROVIDER is not supported.'
            'Current LOCALE_PROVIDER: %s' % db_info['locale_provider']
        )

    changed = False

    if db_info['comment'] is None:
        # For the resetting comment feature (comment: '') to work correctly
        db_info['comment'] = ''

    if owner and owner != db_info['owner']:
        changed = set_owner(cursor, db, owner)

    if conn_limit != '' and conn_limit != str(db_info['conn_limit']):
        changed = set_conn_limit(cursor, db, conn_limit)

    if tablespace and tablespace != db_info['tablespace']:
        changed = set_tablespace(cursor, db, tablespace)

    if comment is not None and comment != db_info['comment']:
        changed = set_comment(cursor, comment, 'database', db, check_mode, executed_commands)

    return changed


def db_matches(cursor, db, owner, template, encoding, lc_collate, lc_ctype, icu_locale, locale_provider, conn_limit, tablespace, comment):
    if not db_exists(cursor, db):
        return False
    else:
        db_info = get_db_info(cursor, db)

        if db_info['comment'] is None:
            # For the resetting comment feature (comment: '') to work correctly
            db_info['comment'] = ''

        if (encoding and get_encoding_id(cursor, encoding) != db_info['encoding_id']):
            return False
        elif lc_collate and lc_collate != db_info['lc_collate']:
            return False
        elif lc_ctype and lc_ctype != db_info['lc_ctype']:
            return False
        elif icu_locale and icu_locale != db_info['icu_locale']:
            return False
        elif locale_provider and locale_provider != db_info['locale_provider']:
            return False
        elif owner and owner != db_info['owner']:
            return False
        elif conn_limit != '' and conn_limit != str(db_info['conn_limit']):
            return False
        elif tablespace and tablespace != db_info['tablespace']:
            return False
        elif comment is not None and comment != db_info['comment']:
            return False
        else:
            return True


def db_dump(module, target, target_opts="",
            db=None,
            dump_extra_args=None,
            user=None,
            password=None,
            host=None,
            port=None,
            session_role=None,
            **kw):

    flags = login_flags(db, host, port, user, db_prefix=False)
    cmd = module.get_bin_path('pg_dump', True)
    comp_prog_path = None

    if os.path.splitext(target)[-1] == '.tar':
        flags.append(' --format=t')
    elif os.path.splitext(target)[-1] == '.pgc':
        flags.append(' --format=c')
    elif os.path.splitext(target)[-1] == '.dir':
        flags.append(' --format=d')

    if os.path.splitext(target)[-1] == '.gz':
        if module.get_bin_path('pigz'):
            comp_prog_path = module.get_bin_path('pigz', True)
        else:
            comp_prog_path = module.get_bin_path('gzip', True)
    elif os.path.splitext(target)[-1] == '.bz2':
        comp_prog_path = module.get_bin_path('bzip2', True)
    elif os.path.splitext(target)[-1] == '.xz':
        comp_prog_path = module.get_bin_path('xz', True)

    if session_role:
        flags.append(' --role={0}'.format(shlex_quote(session_role)))

    cmd += "".join(flags)

    if dump_extra_args:
        cmd += " {0} ".format(dump_extra_args)

    if target_opts:
        cmd += " {0} ".format(target_opts)

    if comp_prog_path:
        # Use a fifo to be notified of an error in pg_dump
        # Using shell pipe has no way to return the code of the first command
        # in a portable way.
        fifo = os.path.join(module.tmpdir, 'pg_fifo')
        os.mkfifo(fifo)
        cmd = '{1} <{3} > {2} & {0} >{3}'.format(cmd, comp_prog_path, shlex_quote(target), fifo)
    else:
        if ' --format=d' in cmd:
            cmd = '{0} -f {1}'.format(cmd, shlex_quote(target))
        else:
            cmd = '{0} > {1}'.format(cmd, shlex_quote(target))

    return do_with_password(module, cmd, password)


def db_restore(module, target, target_opts="",
               db=None,
               user=None,
               password=None,
               host=None,
               port=None,
               session_role=None,
               **kw):

    flags = login_flags(db, host, port, user)
    comp_prog_path = None
    cmd = module.get_bin_path('psql', True)
    pg_restore = False

    if os.path.splitext(target)[-1] == '.sql':
        flags.append(' --file={0}'.format(target))

    elif os.path.splitext(target)[-1] == '.tar':
        flags.append(' --format=Tar')
        cmd = module.get_bin_path('pg_restore', True)
        pg_restore = True

    elif os.path.splitext(target)[-1] == '.pgc':
        flags.append(' --format=Custom')
        cmd = module.get_bin_path('pg_restore', True)
        pg_restore = True

    elif os.path.splitext(target)[-1] == '.dir':
        flags.append(' --format=Directory')
        cmd = module.get_bin_path('pg_restore', True)
        pg_restore = True

    elif os.path.splitext(target)[-1] == '.gz':
        comp_prog_path = module.get_bin_path('zcat', True)

    elif os.path.splitext(target)[-1] == '.bz2':
        comp_prog_path = module.get_bin_path('bzcat', True)

    elif os.path.splitext(target)[-1] == '.xz':
        comp_prog_path = module.get_bin_path('xzcat', True)

    if pg_restore and session_role:
        flags.append(' --role={0}'.format(shlex_quote(session_role)))

    cmd += "".join(flags)
    if target_opts:
        cmd += " {0} ".format(target_opts)

    if comp_prog_path:
        env = os.environ.copy()
        if password:
            env = {"PGPASSWORD": password}
        p1 = subprocess.Popen([comp_prog_path, target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.Popen(cmd, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env=env)
        (stdout2, stderr2) = p2.communicate()
        p1.stdout.close()
        p1.wait()
        if p1.returncode != 0:
            stderr1 = p1.stderr.read()
            return p1.returncode, '', stderr1, 'cmd: ****'
        else:
            return p2.returncode, '', stderr2, 'cmd: ****'
    else:
        if any(substring in cmd for substring in ['--format=Directory', '--format=Custom']):
            cmd = '{0} {1}'.format(cmd, shlex_quote(target))
        elif '--file=' not in cmd:
            cmd = '{0} < {1}'.format(cmd, shlex_quote(target))

    return do_with_password(module, cmd, password)


def login_flags(db, host, port, user, db_prefix=True):
    """
    returns a list of connection argument strings each prefixed
    with a space and quoted where necessary to later be combined
    in a single shell string with `"".join(rv)`

    db_prefix determines if "--dbname" is prefixed to the db argument,
    since the argument was introduced in 9.3.
    """
    flags = []
    if db:
        if db_prefix:
            flags.append(' --dbname={0}'.format(shlex_quote(db)))
        else:
            flags.append(' {0}'.format(shlex_quote(db)))
    if host:
        flags.append(' --host={0}'.format(host))
    if port:
        flags.append(' --port={0}'.format(port))
    if user:
        flags.append(' --username={0}'.format(user))
    return flags


def do_with_password(module, cmd, password):
    env = {}
    if password:
        env = {"PGPASSWORD": password}
    executed_commands.append(cmd)
    rc, stderr, stdout = module.run_command(cmd, use_unsafe_shell=True, environ_update=env)
    return rc, stderr, stdout, cmd


def set_tablespace(cursor, db, tablespace):
    query = 'ALTER DATABASE "%s" SET TABLESPACE "%s"' % (db, tablespace)
    executed_commands.append(query)
    cursor.execute(query)
    return True


def rename_db(module, cursor, db, target, check_mode=False):
    source_db = db_exists(cursor, db)
    target_db = db_exists(cursor, target)

    if source_db and target_db:
        module.fail_json(msg='Both the source and the target databases exist.')

    if not source_db and target_db:
        # If the source db doesn't exist and
        # the target db exists, we assume that
        # the desired state has been reached and
        # respectively nothing needs to be changed
        return False

    if not source_db and not target_db:
        module.fail_json(msg='The source and the target databases do not exist.')

    if source_db and not target_db:
        if check_mode:
            return True

        query = 'ALTER DATABASE "%s" RENAME TO "%s"' % (db, target)
        executed_commands.append(query)
        cursor.execute(query)
        return True

# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        db=dict(type='str', required=True, aliases=['name']),
        owner=dict(type='str', default=''),
        template=dict(type='str', default=''),
        encoding=dict(type='str', default=''),
        lc_collate=dict(type='str', default=''),
        lc_ctype=dict(type='str', default=''),
        icu_locale=dict(type='str', default=''),
        locale_provider=dict(type='str', default=''),
        state=dict(type='str', default='present',
                   choices=['absent', 'dump', 'present', 'rename', 'restore']),
        target=dict(type='path', default=''),
        target_opts=dict(type='str', default=''),
        maintenance_db=dict(type='str', default="postgres"),
        session_role=dict(type='str'),
        conn_limit=dict(type='str', default=''),
        tablespace=dict(type='path', default=''),
        dump_extra_args=dict(type='str', default=None),
        trust_input=dict(type='bool', default=True),
        force=dict(type='bool', default=False),
        comment=dict(type='str', default=None),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    db = module.params["db"]
    owner = module.params["owner"]
    template = module.params["template"]
    encoding = module.params["encoding"]
    lc_collate = module.params["lc_collate"]
    lc_ctype = module.params["lc_ctype"]
    icu_locale = module.params["icu_locale"]
    locale_provider = module.params["locale_provider"]
    target = module.params["target"]
    target_opts = module.params["target_opts"]
    state = module.params["state"]
    changed = False
    maintenance_db = module.params['maintenance_db']
    session_role = module.params["session_role"]
    conn_limit = module.params['conn_limit']
    tablespace = module.params['tablespace']
    dump_extra_args = module.params['dump_extra_args']
    trust_input = module.params['trust_input']
    force = module.params['force']
    comment = module.params['comment']

    if state == 'rename':
        module.warn('The rename choice of the state option is deprecated and will be removed '
                    'in version 5.0.0. Use the community.postgresql.postgresql_query module instead.')

        if not target:
            module.fail_json(msg='The "target" option must be defined when the "rename" option is used.')

        if db == target:
            module.fail_json(msg='The "name/db" option and the "target" option cannot be the same.')

        if maintenance_db == db:
            module.fail_json(msg='The "maintenance_db" option and the "name/db" option cannot be the same.')

    # Check input
    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, owner, conn_limit, encoding, db,
                    template, tablespace, session_role, comment)

    raw_connection = state in ("dump", "restore")

    if not raw_connection:
        ensure_required_libs(module)

    if target == "":
        target = "{0}/{1}.sql".format(os.getcwd(), db)
        target = os.path.expanduser(target)

    # Such a transformation is used, since the connection should go to 'maintenance_db'
    params_dict = module.params
    params_dict["db"] = module.params["maintenance_db"]

    # Parameters for connecting to the database
    conn_params = get_conn_params(module, params_dict, warn_db_default=False)

    if not raw_connection:
        db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
        cursor = db_connection.cursor(**pg_cursor_args)

        if session_role:
            try:
                cursor.execute('SET ROLE "%s"' % session_role)
            except Exception as e:
                module.fail_json(msg="Could not switch role: %s" % to_native(e), exception=traceback.format_exc())

    try:
        # Handle check mode
        if module.check_mode:
            if state == "absent":
                changed = db_exists(cursor, db)

            elif state == "present":
                changed = not db_matches(cursor, db, owner, template, encoding, lc_collate, lc_ctype,
                                         icu_locale, locale_provider, conn_limit, tablespace, comment)

            elif state == "rename":
                changed = rename_db(module, cursor, db, target, check_mode=True)

            module.exit_json(changed=changed, db=db, executed_commands=executed_commands)

        # Handle real mode
        if state == "absent":
            changed = db_delete(cursor, db, force)

        elif state == "present":
            if not db_exists(cursor, db):
                changed = db_create(cursor, db, owner, template, encoding, lc_collate,
                                    lc_ctype, icu_locale, locale_provider, conn_limit,
                                    tablespace, comment, module.check_mode)
            else:
                changed = db_update(cursor, db, owner, encoding, lc_collate,
                                    lc_ctype, icu_locale, locale_provider, conn_limit,
                                    tablespace, comment, module.check_mode)

        elif raw_connection:
            # Parameters for performing dump/restore
            conn_params = get_conn_params(module, module.params, warn_db_default=False)

            method = state == "dump" and db_dump or db_restore

            if state == 'dump':
                rc, stdout, stderr, cmd = method(
                    module, target, target_opts, db, dump_extra_args, session_role=session_role, **conn_params
                )
            else:
                rc, stdout, stderr, cmd = method(
                    module, target, target_opts, db, session_role=session_role, **conn_params
                )

            if rc != 0:
                module.fail_json(msg=stderr, stdout=stdout, rc=rc, cmd=cmd)
            else:
                module.exit_json(changed=True, msg=stdout, stderr=stderr, rc=rc, cmd=cmd,
                                 executed_commands=executed_commands)

        elif state == 'rename':
            changed = rename_db(module, cursor, db, target)

    except (SQLParseError, NotSupportedError) as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())
    except SystemExit:
        # Avoid catching this on Python 2.4
        raise
    except Exception as e:
        module.fail_json(msg="Database query failed: %s" % to_native(e), exception=traceback.format_exc())

    if not raw_connection:
        cursor.close()
        db_connection.close()

    module.exit_json(changed=changed, db=db, executed_commands=executed_commands)


if __name__ == '__main__':
    main()
