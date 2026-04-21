#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Felix Archambault
# Copyright: (c) 2019, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_query
short_description: Run PostgreSQL queries
description:
- Runs arbitrary PostgreSQL queries.
options:
  query:
    description:
    - SQL query string or list of queries to run. Variables can be escaped with psycopg syntax
      U(https://www.psycopg.org/psycopg3/docs/basic/params.html).
    type: raw
  positional_args:
    description:
    - List of values to be passed as positional arguments to the query.
      When the value is a list, it will be converted to PostgreSQL array.
    - Mutually exclusive with I(named_args).
    type: list
    elements: raw
  named_args:
    description:
    - Dictionary of key-value arguments to pass to the query.
      When the value is a list, it will be converted to PostgreSQL array.
    - Mutually exclusive with I(positional_args).
    type: dict
  session_role:
    description:
    - Switch to session_role after connecting. The specified session_role must
      be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though
      the session_role were the one that had logged in originally.
    type: str
  login_db:
    description:
    - Name of database to connect to and run queries against.
    - The V(db) alias is deprecated and will be removed in version 5.0.0.
    type: str
    aliases:
    - db
  autocommit:
    description:
    - Execute in autocommit mode when the query can't be run inside a transaction block
      (e.g., VACUUM).
    - Mutually exclusive with I(check_mode).
    type: bool
    default: false
  encoding:
    description:
    - Set the client encoding for the current session (e.g. C(UTF-8)).
    - The default is the encoding defined by the database.
    type: str
    version_added: '0.2.0'
  trust_input:
    description:
    - If C(false), check whether a value of I(session_role) is potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via I(session_role) are possible.
    type: bool
    default: true
    version_added: '0.2.0'
  search_path:
    description:
    - List of schema names to look in.
    type: list
    elements: str
    version_added: '1.0.0'
seealso:
- module: community.postgresql.postgresql_script
- module: community.postgresql.postgresql_db
- name: PostgreSQL Schema reference
  description: Complete reference of the PostgreSQL schema documentation.
  link: https://www.postgresql.org/docs/current/ddl-schemas.html

attributes:
  check_mode:
    support: full

author:
- Felix Archambault (@archf)
- Andrew Klychkov (@Andersson007)
- Will Rouesnel (@wrouesnel)

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Simple select query to acme db
  community.postgresql.postgresql_query:
    login_db: acme
    query: SELECT version()

# The result of each query will be stored in query_all_results return value
- name: Run several queries against acme db
  community.postgresql.postgresql_query:
    login_db: acme
    query:
    - SELECT version()
    - SELECT id FROM accounts

- name: Select query to db acme with positional arguments and non-default credentials
  community.postgresql.postgresql_query:
    login_db: acme
    login_user: django
    login_password: mysecretpass
    query: SELECT * FROM acme WHERE id = %s AND story = %s
    positional_args:
    - 1
    - test

- name: Select query to test_db with named_args
  community.postgresql.postgresql_query:
    login_db: test_db
    query: SELECT * FROM test WHERE id = %(id_val)s AND story = %(story_val)s
    named_args:
      id_val: 1
      story_val: test

- name: Insert query to test_table in db test_db
  community.postgresql.postgresql_query:
    login_db: test_db
    query: INSERT INTO test_table (id, story) VALUES (2, 'my_long_story')

- name: Use connect_params to add any additional connection parameters that libpg supports
  community.postgresql.postgresql_query:
    connect_params:
      target_session_attrs: read-write
      connect_timeout: 10
    login_host: "host1,host2"
    login_user: "test"
    login_password: "test1234"
    login_db: "test"
    query: 'insert into test (test) values (now())'

- name: Example of using autocommit parameter
  community.postgresql.postgresql_query:
    login_db: test_db
    query: VACUUM
    autocommit: true

- name: >
    Insert data to the column of array type using positional_args.
    Note that we use quotes here, the same as for passing JSON, etc.
  community.postgresql.postgresql_query:
    query: INSERT INTO test_table (array_column) VALUES (%s)
    positional_args:
    - '{1,2,3}'

# Pass list and string vars as positional_args
- name: Set vars
  ansible.builtin.set_fact:
    my_list:
    - 1
    - 2
    - 3
    my_arr: '{1, 2, 3}'

- name: Select from test table by passing positional_args as arrays
  community.postgresql.postgresql_query:
    query: SELECT * FROM test_array_table WHERE arr_col1 = %s AND arr_col2 = %s
    positional_args:
    - '{{ my_list }}'
    - '{{ my_arr|string }}'

# Select from test table looking into app1 schema first, then,
# if the schema doesn't exist or the table hasn't been found there,
# try to find it in the schema public
- name: Select from test using search_path
  community.postgresql.postgresql_query:
    query: SELECT * FROM test_array_table
    search_path:
    - app1
    - public

# If you use a variable in positional_args / named_args that can
# be undefined and you wish to set it as NULL, the constructions like
# "{{ my_var if (my_var is defined) else none | default(none) }}"
# will not work as expected substituting an empty string instead of NULL.
# If possible, we suggest to use Ansible's DEFAULT_JINJA2_NATIVE configuration
# (https://docs.ansible.com/ansible/latest/reference_appendices/config.html#default-jinja2-native).
# Enabling it fixes this problem. If you cannot enable it, the following workaround
# can be used.
# You should precheck such a value and define it as NULL when undefined.
# For example:
- name: When undefined, set to NULL
  set_fact:
    my_var: NULL
  when: my_var is undefined

# Then:
- name: Insert a value using positional arguments
  community.postgresql.postgresql_query:
    query: INSERT INTO test_table (col1) VALUES (%s)
    positional_args:
    - '{{ my_var }}'
'''

RETURN = r'''
query:
    description:
    - Executed query.
    - When reading several queries from a file, it contains only the last one.
    returned: success
    type: str
    sample: 'SELECT * FROM bar'
statusmessage:
    description:
    - Attribute containing the message returned by the command.
    - When reading several queries from a file, it contains a message of the last one.
    returned: success
    type: str
    sample: 'INSERT 0 1'
query_result:
    description:
    - List of dictionaries in column:value form representing returned rows.
    - When running queries from a file, returns result of the last query.
    returned: success
    type: list
    elements: dict
    sample: [{"Column": "Value1"},{"Column": "Value2"}]
query_list:
    description:
    - List of executed queries.
    returned: success
    type: list
    elements: str
    sample: ['SELECT * FROM foo', 'SELECT * FROM bar']
query_all_results:
    description:
    - List containing results of all queries executed (one sublist for every query).
    returned: success
    type: list
    elements: list
    sample: [[{"Column": "Value1"},{"Column": "Value2"}], [{"Column": "Value1"},{"Column": "Value2"}]]
rowcount:
    description:
    - Number of produced or affected rows.
    - When using a script with multiple queries,
      it contains a total number of produced or affected rows.
    returned: changed
    type: int
    sample: 5
execution_time_ms:
    description:
    - A list containing execution time per query in milliseconds.
    - The measurements are done right before and after passing
      the query to the driver for execution.
    returned: success
    type: list
    sample: [7104]
    version_added: '3.10.0'
'''

import re
import time

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import \
    check_input
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    HAS_PSYCOPG,
    PSYCOPG_VERSION,
    TYPES_NEED_TO_CONVERT,
    connect_to_db,
    convert_elements_to_pg_arrays,
    convert_to_supported,
    ensure_required_libs,
    get_conn_params,
    pg_cursor_args,
    postgres_common_argument_spec,
    set_search_path,
)
from ansible_collections.community.postgresql.plugins.module_utils.version import \
    LooseVersion

if HAS_PSYCOPG and PSYCOPG_VERSION < LooseVersion("3.0"):
    from psycopg2 import ProgrammingError as PsycopgProgrammingError
elif HAS_PSYCOPG:
    from psycopg import ProgrammingError as PsycopgProgrammingError


# ===========================================
# Module execution.
#


def execute_and_return_time(cursor, query, args):
    # Measure query execution time in milliseconds as requested in
    # https://github.com/ansible-collections/community.postgresql/issues/787
    start_time = time.perf_counter()

    cursor.execute(query, args)

    # Calculate the execution time rounding it to 4 decimal places
    exec_time_ms = round((time.perf_counter() - start_time) * 1000, 4)
    return cursor, exec_time_ms


def insane_query(string):
    for c in string:
        if c not in (' ', '\n', '', '\t'):
            return False

    return True


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        query=dict(type='raw'),
        login_db=dict(type='str', aliases=['db'], deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        positional_args=dict(type='list', elements='raw'),
        named_args=dict(type='dict'),
        session_role=dict(type='str'),
        autocommit=dict(type='bool', default=False),
        encoding=dict(type='str'),
        trust_input=dict(type='bool', default=True),
        search_path=dict(type='list', elements='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(('positional_args', 'named_args'),),
        supports_check_mode=True,
    )

    query = module.params["query"]
    positional_args = module.params["positional_args"]
    named_args = module.params["named_args"]
    autocommit = module.params["autocommit"]
    encoding = module.params["encoding"]
    session_role = module.params["session_role"]
    trust_input = module.params["trust_input"]
    search_path = module.params["search_path"]

    if query and not isinstance(query, (str, list)):
        module.fail_json(msg="query argument must be of type string or list")

    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, session_role)

    if autocommit and module.check_mode:
        module.fail_json(msg="Using autocommit is mutually exclusive with check_mode")

    query_list = []

    if isinstance(query, str):
        query_list.append(query)
    else:  # if it's a list
        query_list = query

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params)
    if encoding is not None:
        conn_params["client_encoding"] = encoding
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=autocommit)
    cursor = db_connection.cursor(**pg_cursor_args)

    if search_path:
        set_search_path(cursor, '%s' % ','.join([x.strip(' ') for x in search_path]))

    # Prepare args:
    if positional_args:
        args = positional_args
    elif named_args:
        args = named_args
    else:
        args = None

    # Convert elements of type list to strings
    # representing PG arrays
    if args:
        args = convert_elements_to_pg_arrays(args)

    # Set defaults:
    changed = False

    query_all_results = []
    execution_time_ms = []
    rowcount = 0
    statusmessage = ''

    # Execute query:
    for query in query_list:
        try:
            current_query_txt = cursor.mogrify(query, args)

            cursor, exec_time_ms = execute_and_return_time(cursor, query, args)

            execution_time_ms.append(exec_time_ms)

            statusmessage = cursor.statusmessage
            if cursor.rowcount > 0:
                rowcount += cursor.rowcount

            query_result = []
            try:
                for row in cursor.fetchall():
                    # Ansible engine does not support decimals.
                    # An explicit conversion is required on the module's side
                    row = dict(row)
                    for (key, val) in row.items():
                        if isinstance(val, TYPES_NEED_TO_CONVERT):
                            row[key] = convert_to_supported(val)

                    query_result.append(row)

            # Psycopg 3 doesn't fail with 'no results to fetch'
            # This exception will be triggered only in Psycopg 2
            except PsycopgProgrammingError as e:
                if to_native(e) == 'no results to fetch':
                    query_result = {}

            except Exception as e:
                module.fail_json(msg="Cannot fetch rows from cursor: %s" % to_native(e))

            if query_result == []:
                query_result = {}

            query_all_results.append(query_result)

            if 'SELECT' not in statusmessage and 'SHOW' not in statusmessage:
                if re.search(re.compile(r'(UPDATE|INSERT|DELETE)'), statusmessage):
                    s = statusmessage.split()
                    if len(s) == 3:
                        if s[2] != '0':
                            changed = True

                    elif len(s) == 2:
                        if s[1] != '0':
                            changed = True

                    else:
                        changed = True

                else:
                    changed = True

        except Exception as e:
            if not autocommit:
                db_connection.rollback()

            cursor.close()
            db_connection.close()
            module.fail_json(msg="Cannot execute SQL '%s' %s: %s, query list: %s" % (query, args, to_native(e), query_list))

    if module.check_mode:
        db_connection.rollback()
    else:
        if not autocommit:
            db_connection.commit()

    kw = dict(
        changed=changed,
        query=current_query_txt,
        query_list=query_list,
        statusmessage=statusmessage,
        query_result=query_result,
        query_all_results=query_all_results,
        rowcount=rowcount,
        execution_time_ms=execution_time_ms,
    )

    cursor.close()
    db_connection.close()

    module.exit_json(**kw)


if __name__ == '__main__':
    main()
