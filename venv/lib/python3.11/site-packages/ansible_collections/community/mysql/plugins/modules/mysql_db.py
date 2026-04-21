#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2012, Mark Theunissen <mark.theunissen@gmail.com>
# Sponsored by Four Kitchens http://fourkitchens.com.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: mysql_db
short_description: Add or remove MySQL or MariaDB databases from a remote host
description:
- Add or remove MySQL or MariaDB databases from a remote host.
options:
  name:
    description:
    - Name of the database to add or remove.
    - I(name=all) may only be provided if I(state) is C(dump) or C(import).
    - List of databases is provided with I(state=dump), I(state=present) and I(state=absent).
    - If I(name=all) it works like --all-databases option for mysqldump (Added in 2.0).
    required: true
    type: list
    elements: str
    aliases: [db]
  state:
    description:
    - The database state.
    type: str
    default: present
    choices: ['absent', 'dump', 'import', 'present']
  collation:
    description:
    - Collation mode (sorting). This only applies to new table/databases and
      does not update existing ones, this is a limitation of MySQL.
    type: str
    default: ''
  encoding:
    description:
    - Encoding mode to use, examples include C(utf8) or C(latin1_swedish_ci),
      at creation of database, dump or importation of sql script.
    type: str
    default: ''
  target:
    description:
    - Location, on the remote host, of the dump file to read from or write to.
    - Uncompressed SQL files (C(.sql)) as well as bzip2 (C(.bz2)), gzip (C(.gz)),
      xz (Added in 2.0) and zstd (C(.zst)) (Added in 3.12.0) compressed files are supported.
    type: path
  single_transaction:
    description:
    - Execute the dump in a single transaction.
    type: bool
    default: false
  quick:
    description:
    - Option used for dumping large tables.
    type: bool
    default: true
  ignore_tables:
    description:
    - A list of table names that will be ignored in the dump
      of the form database_name.table_name.
    type: list
    elements: str
    default: []
  hex_blob:
    description:
    - Dump binary columns using hexadecimal notation.
    type: bool
    default: false
    version_added: '0.1.0'
  force:
    description:
    - Continue dump or import even if we get an SQL error.
    - Used only when I(state) is C(dump) or C(import).
    type: bool
    default: false
    version_added: '0.1.0'
  master_data:
    description:
      - Option to dump a master replication server to produce a dump file
        that can be used to set up another server as a slave of the master.
      - C(0) to not include master data.
      - C(1) to generate a 'CHANGE MASTER TO' statement
        required on the slave to start the replication process.
      - C(2) to generate a commented 'CHANGE MASTER TO'.
      - Can be used when I(state=dump).
    type: int
    choices: [0, 1, 2]
    default: 0
    version_added: '0.1.0'
  skip_lock_tables:
    description:
      - Skip locking tables for read. Used when I(state=dump), ignored otherwise.
    type: bool
    default: false
    version_added: '0.1.0'
  dump_extra_args:
    description:
      - Provide additional arguments for mysqldump.
        Used when I(state=dump) only, ignored otherwise.
    type: str
    version_added: '0.1.0'
  use_shell:
    description:
      - Used to prevent C(Broken pipe) errors when the imported I(target) file is compressed.
      - If C(yes), the module will internally execute commands via a shell.
      - Used when I(state=import), ignored otherwise.
    type: bool
    default: false
    version_added: '0.1.0'
  unsafe_login_password:
    description:
      - If C(no), the module will safely use a shell-escaped
        version of the I(login_password) value.
      - It makes sense to use C(yes) only if there are special
        symbols in the value and errors C(Access denied) occur.
      - Used only when I(state) is C(import) or C(dump) and
        I(login_password) is passed, ignored otherwise.
    type: bool
    default: false
    version_added: '0.1.0'
  restrict_config_file:
    description:
      - Read only passed I(config_file).
      - When I(state) is C(dump) or C(import),
        by default the module passes I(config_file) parameter
        using C(--defaults-extra-file) command-line argument to C(mysql/mysqldump) utilities
        under the hood that read named option file in addition to usual option files.
      - If this behavior is undesirable, use C(yes) to read only named option file.
    type: bool
    default: false
    version_added: '0.1.0'
  check_implicit_admin:
    description:
      - Check if mysql allows login as root/nopassword before trying supplied credentials.
      - If success, passed I(login_user)/I(login_password) will be ignored.
    type: bool
    default: false
    version_added: '0.1.0'
  config_overrides_defaults:
    description:
      - If C(yes), connection parameters from I(config_file) will override the default
        values of I(login_host) and I(login_port) parameters.
      - Used when I(stat) is C(present) or C(absent), ignored otherwise.
      - It needs Python 3.5+ as the default interpreter on a target host.
    type: bool
    default: false
    version_added: '0.1.0'
  chdir:
    description:
    - Changes the current working directory.
    - Can be useful, for example, when I(state=import) and a dump file contains relative paths.
    type: path
    version_added: '3.4.0'
  pipefail:
    description:
    - Use C(bash) instead of C(sh) and add C(-o pipefail) to catch errors from the
      mysql_dump command when I(state=dump) and compression is used.
    - The default is C(no) to prevent issues on systems without bash as a default interpreter.
    - The default will change to C(yes) in community.mysql 4.0.0.
    type: bool
    default: false
    version_added: '3.4.0'
  sql_log_bin:
    description:
      - Whether binary logging should be enabled or disabled for the connection.
    type: bool
    default: true

seealso:
- module: community.mysql.mysql_info
- module: community.mysql.mysql_variables
- module: community.mysql.mysql_user
- module: community.mysql.mysql_replication
- name: MySQL command-line client reference
  description: Complete reference of the MySQL command-line client documentation.
  link: https://dev.mysql.com/doc/refman/8.0/en/mysql.html
- name: mysqldump reference
  description: Complete reference of the ``mysqldump`` client utility documentation.
  link: https://dev.mysql.com/doc/refman/8.0/en/mysqldump.html
- name: CREATE DATABASE reference
  description: Complete reference of the CREATE DATABASE command documentation.
  link: https://dev.mysql.com/doc/refman/8.0/en/create-database.html
- name: DROP DATABASE reference
  description: Complete reference of the DROP DATABASE command documentation.
  link: https://dev.mysql.com/doc/refman/8.0/en/drop-database.html
author: "Ansible Core Team"
requirements:
   - mysql (command line binary)
   - mysqldump (command line binary)
notes:
   - Compatible with MariaDB or MySQL.
   - Requires the mysql and mysqldump binaries on the remote host.
   - This module is B(not idempotent) when I(state) is C(import),
     and will import the dump file each time if run more than once.
attributes:
  check_mode:
    support: full
extends_documentation_fragment:
- community.mysql.mysql
'''

EXAMPLES = r'''
# If you encounter the "Please explicitly state intended protocol" error,
# use the login_unix_socket argument
- name: Create a new database with name 'bobdata'
  community.mysql.mysql_db:
    name: bobdata
    state: present
    login_unix_socket: /run/mysqld/mysqld.sock

- name: Create new databases with names 'foo' and 'bar'
  community.mysql.mysql_db:
    name:
      - foo
      - bar
    state: present

# Copy database dump file to remote host and restore it to database 'my_db'
- name: Copy database dump file
  copy:
    src: dump.sql.bz2
    dest: /tmp

- name: Restore database
  community.mysql.mysql_db:
    name: my_db
    state: import
    target: /tmp/dump.sql.bz2

- name: Restore database ignoring errors
  community.mysql.mysql_db:
    name: my_db
    state: import
    target: /tmp/dump.sql.bz2
    force: true

- name: Dump multiple databases
  community.mysql.mysql_db:
    state: dump
    name: db_1,db_2
    target: /tmp/dump.sql

- name: Dump multiple databases
  community.mysql.mysql_db:
    state: dump
    name:
      - db_1
      - db_2
    target: /tmp/dump.sql

- name: Dump all databases to hostname.sql
  community.mysql.mysql_db:
    state: dump
    name: all
    target: /tmp/dump.sql

- name: Dump all databases to hostname.sql including master data
  community.mysql.mysql_db:
    state: dump
    name: all
    target: /tmp/dump.sql
    master_data: 1

# Import of sql script with encoding option
- name: >
    Import dump.sql with specific latin1 encoding,
    similar to mysql -u <username> --default-character-set=latin1 -p <password> < dump.sql
  community.mysql.mysql_db:
    state: import
    name: all
    encoding: latin1
    target: /tmp/dump.sql

# Dump of database with encoding option
- name: >
    Dump of Databse with specific latin1 encoding,
    similar to mysqldump -u <username> --default-character-set=latin1 -p <password> <database>
  community.mysql.mysql_db:
    state: dump
    name: db_1
    encoding: latin1
    target: /tmp/dump.sql

- name: Delete database with name 'bobdata'
  community.mysql.mysql_db:
    name: bobdata
    state: absent

- name: Make sure there is neither a database with name 'foo', nor one with name 'bar'
  community.mysql.mysql_db:
    name:
      - foo
      - bar
    state: absent

# Dump database with argument not directly supported by this module
# using dump_extra_args parameter
- name: Dump databases without including triggers
  community.mysql.mysql_db:
    state: dump
    name: foo
    target: /tmp/dump.sql
    dump_extra_args: --skip-triggers

- name: Try to create database as root/nopassword first. If not allowed, pass the credentials
  community.mysql.mysql_db:
    check_implicit_admin: true
    login_user: bob
    login_password: 123456
    name: bobdata
    state: present

- name: Dump a database with compression and catch errors from mysqldump with bash pipefail
  community.mysql.mysql_db:
    state: dump
    name: foo
    target: /tmp/dump.sql.gz
    pipefail: true
'''

RETURN = r'''
db:
  description: Database names in string format delimited by white space.
  returned: always
  type: str
  sample: "foo bar"
db_list:
  description: List of database names.
  returned: always
  type: list
  sample: ["foo", "bar"]
executed_commands:
  description: List of commands which tried to run.
  returned: if executed
  type: list
  sample: ["CREATE DATABASE acme"]
  version_added: '0.1.0'
'''

import os
import subprocess
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.mysql.plugins.module_utils.database import mysql_quote_identifier
from ansible_collections.community.mysql.plugins.module_utils.mysql import (
    mysql_connect,
    mysql_driver,
    mysql_driver_fail_msg,
    mysql_common_argument_spec,
    get_server_implementation,
    get_server_version,
)
from ansible_collections.community.mysql.plugins.module_utils.version import LooseVersion
from ansible.module_utils.six.moves import shlex_quote
from ansible.module_utils._text import to_native

executed_commands = []

# ===========================================
# MySQL module specific support methods.
#


def db_exists(cursor, db):
    res = 0
    for each_db in db:
        res += cursor.execute("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = %s", (each_db,))
    return res == len(db)


def db_delete(cursor, db):
    if not db:
        return False
    for each_db in db:
        query = "DROP DATABASE %s" % mysql_quote_identifier(each_db, 'database')
        executed_commands.append(query)
        cursor.execute(query)
    return True


def db_dump(module, host, user, password, db_name, target, all_databases, port,
            config_file, server_implementation, server_version, socket=None,
            ssl_cert=None, ssl_key=None, ssl_ca=None,
            single_transaction=None, quick=None, ignore_tables=None, hex_blob=None,
            encoding=None, force=False, master_data=0, skip_lock_tables=False,
            dump_extra_args=None, unsafe_password=False, restrict_config_file=False,
            check_implicit_admin=False, pipefail=False):

    cmd_str = 'mysqldump'
    if server_implementation == 'mariadb' and LooseVersion(server_version) >= LooseVersion("10.4.6"):
        cmd_str = 'mariadb-dump'
    try:
        cmd = [module.get_bin_path(cmd_str, True)]
    except Exception as e:
        return 1, "", "Error determining dump command: %s" % str(e)

    # If defined, mysqldump demands --defaults-extra-file be the first option
    if config_file:
        if restrict_config_file:
            cmd.append("--defaults-file=%s" % shlex_quote(config_file))
        else:
            cmd.append("--defaults-extra-file=%s" % shlex_quote(config_file))

    if check_implicit_admin:
        cmd.append("--user=root --password=''")
    else:
        if user is not None:
            cmd.append("--user=%s" % shlex_quote(user))

        if password is not None:
            if not unsafe_password:
                cmd.append("--password=%s" % shlex_quote(password))
            else:
                cmd.append("--password=%s" % password)

    if ssl_cert is not None:
        cmd.append("--ssl-cert=%s" % shlex_quote(ssl_cert))
    if ssl_key is not None:
        cmd.append("--ssl-key=%s" % shlex_quote(ssl_key))
    if ssl_ca is not None:
        cmd.append("--ssl-ca=%s" % shlex_quote(ssl_ca))
    if force:
        cmd.append("--force")
    if socket is not None:
        cmd.append("--socket=%s" % shlex_quote(socket))
    else:
        cmd.append("--host=%s --port=%i" % (shlex_quote(host), port))

    if all_databases:
        cmd.append("--all-databases")
    elif len(db_name) > 1:
        cmd.append("--databases {0}".format(' '.join(db_name)))
    else:
        cmd.append("%s" % shlex_quote(' '.join(db_name)))

    if skip_lock_tables:
        cmd.append("--skip-lock-tables")
    if (encoding is not None) and (encoding != ""):
        cmd.append("--default-character-set=%s" % shlex_quote(encoding))
    if single_transaction:
        cmd.append("--single-transaction=true")
    if quick:
        cmd.append("--quick")
    if ignore_tables:
        for an_ignored_table in ignore_tables:
            cmd.append("--ignore-table={0}".format(an_ignored_table))
    if hex_blob:
        cmd.append("--hex-blob")
    if master_data:
        if (server_implementation == 'mysql' and
                LooseVersion(server_version) >= LooseVersion("8.2.0")):
            cmd.append("--source-data=%s" % master_data)
        else:
            cmd.append("--master-data=%s" % master_data)
    if dump_extra_args is not None:
        cmd.append(dump_extra_args)

    path = None
    if os.path.splitext(target)[-1] == '.gz':
        path = module.get_bin_path('gzip', True)
    elif os.path.splitext(target)[-1] == '.bz2':
        path = module.get_bin_path('bzip2', True)
    elif os.path.splitext(target)[-1] == '.xz':
        path = module.get_bin_path('xz', True)
    elif os.path.splitext(target)[-1] == '.zst':
        path = module.get_bin_path('zstd', True)

    cmd = ' '.join(cmd)

    if path:
        cmd = '%s | %s > %s' % (cmd, path, shlex_quote(target))
        if pipefail:
            cmd = 'set -o pipefail && ' + cmd
    else:
        cmd += " > %s" % shlex_quote(target)

    executed_commands.append(cmd)

    if pipefail:
        rc, stdout, stderr = module.run_command(cmd, use_unsafe_shell=True, executable='bash')
    else:
        rc, stdout, stderr = module.run_command(cmd, use_unsafe_shell=True)

    return rc, stdout, stderr


def db_import(module, host, user, password, db_name, target, all_databases, port, config_file,
              server_implementation, server_version, socket=None, ssl_cert=None, ssl_key=None, ssl_ca=None,
              encoding=None, force=False,
              use_shell=False, unsafe_password=False, restrict_config_file=False,
              check_implicit_admin=False):
    if not os.path.exists(target):
        return module.fail_json(msg="target %s does not exist on the host" % target)

    cmd_str = 'mysql'
    if server_implementation == 'mariadb' and LooseVersion(server_version) >= LooseVersion("10.4.6"):
        cmd_str = 'mariadb'
    try:
        cmd = [module.get_bin_path(cmd_str, True)]
    except Exception as e:
        return 1, "", "Error determining mysql/mariadb command: %s" % str(e)

    # --defaults-file must go first, or errors out
    if config_file:
        if restrict_config_file:
            cmd.append("--defaults-file=%s" % shlex_quote(config_file))
        else:
            cmd.append("--defaults-extra-file=%s" % shlex_quote(config_file))

    if check_implicit_admin:
        cmd.append("--user=root --password=''")
    else:
        if user:
            cmd.append("--user=%s" % shlex_quote(user))

        if password:
            if not unsafe_password:
                cmd.append("--password=%s" % shlex_quote(password))
            else:
                cmd.append("--password=%s" % password)

    if ssl_cert is not None:
        cmd.append("--ssl-cert=%s" % shlex_quote(ssl_cert))
    if ssl_key is not None:
        cmd.append("--ssl-key=%s" % shlex_quote(ssl_key))
    if ssl_ca is not None:
        cmd.append("--ssl-ca=%s" % shlex_quote(ssl_ca))
    if force:
        cmd.append("-f")
    if socket is not None:
        cmd.append("--socket=%s" % shlex_quote(socket))
    else:
        cmd.append("--host=%s" % shlex_quote(host))
        cmd.append("--port=%i" % port)
    if (encoding is not None) and (encoding != ""):
        cmd.append("--default-character-set=%s" % shlex_quote(encoding))
    if not all_databases:
        cmd.append("--one-database")
        cmd.append(shlex_quote(''.join(db_name)))

    comp_prog_path = None
    if os.path.splitext(target)[-1] == '.gz':
        comp_prog_path = module.get_bin_path('gzip', required=True)
    elif os.path.splitext(target)[-1] == '.bz2':
        comp_prog_path = module.get_bin_path('bzip2', required=True)
    elif os.path.splitext(target)[-1] == '.xz':
        comp_prog_path = module.get_bin_path('xz', required=True)
    elif os.path.splitext(target)[-1] == '.zst':
        comp_prog_path = module.get_bin_path('zstd', required=True)
    if comp_prog_path:
        # The line below is for returned data only:
        executed_commands.append('%s -dc %s | %s' % (comp_prog_path, target, cmd))

        if not use_shell:
            p1 = subprocess.Popen([comp_prog_path, '-dc', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p2 = subprocess.Popen(cmd, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (stdout2, stderr2) = p2.communicate()
            p1.stdout.close()
            p1.wait()

            if p1.returncode != 0:
                stderr1 = p1.stderr.read()
                return p1.returncode, '', stderr1
            else:
                return p2.returncode, stdout2, stderr2
        else:
            # Used to prevent 'Broken pipe' errors that
            # occasionaly occur when target files are compressed.
            # FYI: passing the `shell=True` argument to p2 = subprocess.Popen()
            # doesn't solve the problem.
            cmd = " ".join(cmd)
            cmd = "%s -dc %s | %s" % (comp_prog_path, shlex_quote(target), cmd)
            rc, stdout, stderr = module.run_command(cmd, use_unsafe_shell=True)
            return rc, stdout, stderr

    else:
        cmd = ' '.join(cmd)
        cmd += " < %s" % shlex_quote(target)
        executed_commands.append(cmd)
        rc, stdout, stderr = module.run_command(cmd, use_unsafe_shell=True)
        return rc, stdout, stderr


def db_create(cursor, db, encoding, collation):
    if not db:
        return False
    query_params = dict(enc=encoding, collate=collation)
    res = 0
    for each_db in db:
        # Escape '%' since mysql cursor.execute() uses a format string
        query = ['CREATE DATABASE %s' % mysql_quote_identifier(each_db, 'database').replace('%', '%%')]
        if encoding:
            query.append("CHARACTER SET %(enc)s")
        if collation:
            query.append("COLLATE %(collate)s")
        query = ' '.join(query)
        res += cursor.execute(query, query_params)
        try:
            executed_commands.append(cursor.mogrify(query, query_params))
        except AttributeError:
            executed_commands.append(cursor._executed)
        except Exception:
            executed_commands.append(query)
    return res > 0


# ===========================================
# Module execution.
#


def main():
    argument_spec = mysql_common_argument_spec()
    argument_spec.update(
        name=dict(type='list', elements='str', required=True, aliases=['db']),
        encoding=dict(type='str', default=''),
        collation=dict(type='str', default=''),
        target=dict(type='path'),
        state=dict(type='str', default='present', choices=['absent', 'dump', 'import', 'present']),
        single_transaction=dict(type='bool', default=False),
        quick=dict(type='bool', default=True),
        ignore_tables=dict(type='list', elements='str', default=[]),
        hex_blob=dict(default=False, type='bool'),
        force=dict(type='bool', default=False),
        master_data=dict(type='int', default=0, choices=[0, 1, 2]),
        skip_lock_tables=dict(type='bool', default=False),
        dump_extra_args=dict(type='str'),
        use_shell=dict(type='bool', default=False),
        unsafe_login_password=dict(type='bool', default=False, no_log=True),
        restrict_config_file=dict(type='bool', default=False),
        check_implicit_admin=dict(type='bool', default=False),
        config_overrides_defaults=dict(type='bool', default=False),
        chdir=dict(type='path'),
        pipefail=dict(type='bool', default=False),
        sql_log_bin=dict(type='bool', default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if mysql_driver is None:
        module.fail_json(msg=mysql_driver_fail_msg)

    db = module.params["name"]
    if not db:
        module.exit_json(changed=False, db=db, db_list=[])
    db = [each_db.strip() for each_db in db]

    encoding = module.params["encoding"]
    collation = module.params["collation"]
    state = module.params["state"]
    target = module.params["target"]
    socket = module.params["login_unix_socket"]
    login_port = module.params["login_port"]
    if login_port < 0 or login_port > 65535:
        module.fail_json(msg="login_port must be a valid unix port number (0-65535)")
    ssl_cert = module.params["client_cert"]
    ssl_key = module.params["client_key"]
    ssl_ca = module.params["ca_cert"]
    check_hostname = module.params["check_hostname"]
    connect_timeout = module.params['connect_timeout']
    config_file = module.params['config_file']
    login_password = module.params["login_password"]
    unsafe_login_password = module.params["unsafe_login_password"]
    login_user = module.params["login_user"]
    login_host = module.params["login_host"]
    ignore_tables = module.params["ignore_tables"]
    for a_table in ignore_tables:
        if a_table == "":
            module.fail_json(msg="Name of ignored table cannot be empty")
    single_transaction = module.params["single_transaction"]
    quick = module.params["quick"]
    hex_blob = module.params["hex_blob"]
    force = module.params["force"]
    master_data = module.params["master_data"]
    skip_lock_tables = module.params["skip_lock_tables"]
    dump_extra_args = module.params["dump_extra_args"]
    use_shell = module.params["use_shell"]
    restrict_config_file = module.params["restrict_config_file"]
    check_implicit_admin = module.params['check_implicit_admin']
    config_overrides_defaults = module.params['config_overrides_defaults']
    chdir = module.params['chdir']
    pipefail = module.params['pipefail']
    sql_log_bin = module.params["sql_log_bin"]

    if chdir:
        try:
            os.chdir(chdir)
        except Exception as e:
            module.fail_json("Cannot change the current directory to %s: %s" % (chdir, e))

    if len(db) > 1 and state == 'import':
        module.fail_json(msg="Multiple databases are not supported with state=import")
    db_name = ' '.join(db)

    all_databases = False
    if state in ['dump', 'import']:
        if target is None:
            module.fail_json(msg="with state=%s target is required" % state)
        if db == ['all']:
            all_databases = True
    else:
        if db == ['all']:
            module.fail_json(msg="name is not allowed to equal 'all' unless state equals import, or dump.")
    try:
        cursor = None
        if check_implicit_admin:
            try:
                cursor, db_conn = mysql_connect(module, 'root', '', config_file, ssl_cert, ssl_key, ssl_ca,
                                                connect_timeout=connect_timeout, check_hostname=check_hostname,
                                                config_overrides_defaults=config_overrides_defaults)
            except Exception as e:
                check_implicit_admin = False
                pass

        if not cursor:
            cursor, db_conn = mysql_connect(module, login_user, login_password, config_file, ssl_cert, ssl_key, ssl_ca,
                                            connect_timeout=connect_timeout, config_overrides_defaults=config_overrides_defaults,
                                            check_hostname=check_hostname)
    except Exception as e:
        if os.path.exists(config_file):
            module.fail_json(msg="unable to connect to database, check login_user and login_password are correct or %s has the credentials. "
                                 "Exception message: %s" % (config_file, to_native(e)))
        else:
            module.fail_json(msg="unable to find %s. Exception message: %s" % (config_file, to_native(e)))

    if state in ['absent', 'present'] and not sql_log_bin:
        cursor.execute("SET SQL_LOG_BIN=0;")

    server_implementation = get_server_implementation(cursor)
    server_version = get_server_version(cursor)

    changed = False
    if not os.path.exists(config_file):
        config_file = None

    existence_list = []
    non_existence_list = []

    if not all_databases:
        for each_database in db:
            if db_exists(cursor, [each_database]):
                existence_list.append(each_database)
            else:
                non_existence_list.append(each_database)

    if state == "absent":
        if module.check_mode:
            module.exit_json(changed=bool(existence_list), db=db_name, db_list=db)
        try:
            changed = db_delete(cursor, existence_list)
        except Exception as e:
            module.fail_json(msg="error deleting database: %s" % to_native(e))
        module.exit_json(changed=changed, db=db_name, db_list=db, executed_commands=executed_commands)
    elif state == "present":
        if module.check_mode:
            module.exit_json(changed=bool(non_existence_list), db=db_name, db_list=db)
        changed = False
        if non_existence_list:
            try:
                changed = db_create(cursor, non_existence_list, encoding, collation)
            except Exception as e:
                module.fail_json(msg="error creating database: %s" % to_native(e),
                                 exception=traceback.format_exc())
        module.exit_json(changed=changed, db=db_name, db_list=db, executed_commands=executed_commands)
    elif state == "dump":
        if non_existence_list and not all_databases:
            module.fail_json(msg="Cannot dump database(s) %r - not found" % (', '.join(non_existence_list)))
        if module.check_mode:
            module.exit_json(changed=True, db=db_name, db_list=db)
        rc, stdout, stderr = db_dump(module, login_host, login_user,
                                     login_password, db, target, all_databases,
                                     login_port, config_file, server_implementation, server_version,
                                     socket, ssl_cert, ssl_key,
                                     ssl_ca, single_transaction, quick, ignore_tables,
                                     hex_blob, encoding, force, master_data, skip_lock_tables,
                                     dump_extra_args, unsafe_login_password, restrict_config_file,
                                     check_implicit_admin, pipefail)
        if rc != 0:
            module.fail_json(msg="%s" % stderr)
        module.exit_json(changed=True, db=db_name, db_list=db, msg=stdout,
                         executed_commands=executed_commands)
    elif state == "import":
        if module.check_mode:
            module.exit_json(changed=True, db=db_name, db_list=db)
        if non_existence_list and not all_databases:
            try:
                db_create(cursor, non_existence_list, encoding, collation)
            except Exception as e:
                module.fail_json(msg="error creating database: %s" % to_native(e),
                                 exception=traceback.format_exc())
        rc, stdout, stderr = db_import(module, login_host, login_user,
                                       login_password, db, target,
                                       all_databases,
                                       login_port, config_file, server_implementation,
                                       server_version, socket, ssl_cert, ssl_key, ssl_ca,
                                       encoding, force, use_shell, unsafe_login_password,
                                       restrict_config_file, check_implicit_admin)
        if rc != 0:
            module.fail_json(msg="%s" % stderr)
        module.exit_json(changed=True, db=db_name, db_list=db, msg=stdout,
                         executed_commands=executed_commands)


if __name__ == '__main__':
    main()
