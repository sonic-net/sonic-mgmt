#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_set
short_description: Change a PostgreSQL server configuration parameter
deprecated:
  removed_in: "5.0.0"
  why: It has been replaced with a better-designed module.
  alternative: Use M(community.postgresql.postgresql_alter_system) instead.
description:
   - "IMPORTANT: If your PostgreSQL server version is 14 or later,
     use the M(community.postgresql.postgresql_alter_system) module instead as it will
     replace this module in future."
   - Allows to change a PostgreSQL server configuration parameter.
   - The module uses ALTER SYSTEM command and applies changes by reload server configuration.
   - ALTER SYSTEM is used for changing server configuration parameters across the entire database cluster.
   - It can be more convenient and safe than the traditional method of manually editing the postgresql.conf file.
   - ALTER SYSTEM writes the given parameter setting to the $PGDATA/postgresql.auto.conf file,
     which is read in addition to postgresql.conf.
   - The module allows to reset parameter to boot_val (cluster initial value) by I(reset=true) or remove parameter
     string from postgresql.auto.conf and reload I(value=default) (for settings with postmaster context restart is required).
   - After change you can see in the ansible output the previous and
     the new parameter value and other information using returned values and M(ansible.builtin.debug) module.
options:
  name:
    description:
    - Name of PostgreSQL server parameter. Pay attention that parameters are case sensitive (see examples below).
    type: str
    required: true
  value:
    description:
    - Parameter value to set.
    - To remove parameter string from postgresql.auto.conf and
      reload the server configuration you must pass I(value=default).
      With I(value=default) the playbook always returns changed is true.
    type: str
  reset:
    description:
    - Restore parameter to initial state (boot_val). Mutually exclusive with I(value).
    type: bool
    default: false
  session_role:
    description:
    - Switch to session_role after connecting. The specified session_role must
      be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though
      the session_role were the one that had logged in originally.
    type: str
  login_db:
    description:
    - Name of database to connect.
    - The V(db) alias is deprecated and will be removed in version 5.0.0.
    type: str
    aliases:
    - db
  trust_input:
    description:
    - If C(false), check whether values of parameters are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections are possible.
    type: bool
    default: true
    version_added: '0.2.0'

notes:
- Supported version of PostgreSQL is 9.4 and later.
  For PostgreSQL version 14 or later, the M(community.postgresql.postgresql_alter_system) module is recommended.
- Pay attention, change setting with 'postmaster' context can return changed is true
  when actually nothing changes because the same value may be presented in
  several different form, for example, 1024MB, 1GB, etc. However in pg_settings
  system view it can be defined like 131072 number of 8kB pages.
  The final check of the parameter value cannot compare it because the server was
  not restarted and the value in pg_settings is not updated yet.
- For some parameters restart of PostgreSQL server is required.
  See official documentation U(https://www.postgresql.org/docs/current/view-pg-settings.html).

attributes:
  check_mode:
    support: full

seealso:
- module: community.postgresql.postgresql_alter_system
- module: community.postgresql.postgresql_info
- name: PostgreSQL server configuration
  description: General information about PostgreSQL server configuration.
  link: https://www.postgresql.org/docs/current/runtime-config.html
- name: PostgreSQL view pg_settings reference
  description: Complete reference of the pg_settings view documentation.
  link: https://www.postgresql.org/docs/current/view-pg-settings.html
- name: PostgreSQL ALTER SYSTEM command reference
  description: Complete reference of the ALTER SYSTEM command documentation.
  link: https://www.postgresql.org/docs/current/sql-altersystem.html

author:
- Andrew Klychkov (@Andersson007)
- Daniele Giudice (@RealGreenDragon)

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Restore wal_keep_segments parameter to initial state
  community.postgresql.postgresql_set:
    name: wal_keep_segments
    reset: true

# Set work_mem parameter to 32MB and show what's been changed and restart is required or not
# (output example: "msg": "work_mem 4MB >> 64MB restart_req: False")
- name: Set work mem parameter
  community.postgresql.postgresql_set:
    name: work_mem
    value: 32mb
  register: set

- name: Print the result if the setting changed
  ansible.builtin.debug:
    msg: "{{ set.name }} {{ set.prev_val_pretty }} >> {{ set.value_pretty }} restart_req: {{ set.restart_required }}"
  when: set.changed
# Ensure that the restart of PostgreSQL server must be required for some parameters.
# In this situation you see the same parameter in prev_val_pretty and value_pretty, but 'changed=True'
# (If you passed the value that was different from the current server setting).

- name: Set log_min_duration_statement parameter to 1 second
  community.postgresql.postgresql_set:
    name: log_min_duration_statement
    value: 1s

- name: Set wal_log_hints parameter to default value (remove parameter from postgresql.auto.conf)
  community.postgresql.postgresql_set:
    name: wal_log_hints
    value: default

- name: Set TimeZone parameter (careful, case sensitive)
  community.postgresql.postgresql_set:
    name: TimeZone
    value: 'Europe/Paris'
'''

RETURN = r'''
name:
  description: Name of PostgreSQL server parameter.
  returned: success
  type: str
  sample: 'shared_buffers'
restart_required:
  description: Information about parameter current state.
  returned: success
  type: bool
  sample: true
prev_val_pretty:
  description: Information about previous state of the parameter.
  returned: success
  type: str
  sample: '4MB'
value_pretty:
  description: Information about current state of the parameter.
  returned: success
  type: str
  sample: '64MB'
value:
  description:
  - Dictionary that contains the current parameter value (at the time of playbook finish).
  - Pay attention that for real change some parameters restart of PostgreSQL server is required.
  - Returns the current value in the check mode.
  returned: success
  type: dict
  sample: { "value": 67108864, "unit": "b" }
context:
  description:
  - PostgreSQL setting context.
  returned: success
  type: str
  sample: user
queries:
  description:
  - List of executed DML queries.
  returned: success
  type: list
  elements: str
  sample: ["ALTER SYSTEM SET shared_preload_libraries = ''"]
  version_added: '3.7.0'
'''

from copy import deepcopy

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import \
    check_input
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    get_conn_params,
    get_server_version,
    pg_cursor_args,
    postgres_common_argument_spec,
)

executed_queries = []

PG_REQ_VER = 90400

# To allow to set value like 1mb instead of 1MB, etc:
LOWERCASE_SIZE_UNITS = ("mb", "gb", "tb")

# GUC_LIST_QUOTE parameters list for each version where they changed (from PG_REQ_VER).
# It is a tuple of tuples as we need to iterate it in order.
PARAMETERS_GUC_LIST_QUOTE = (
    (140000, (
        'local_preload_libraries',
        'search_path',
        'session_preload_libraries',
        'shared_preload_libraries',
        'temp_tablespaces',
        'unix_socket_directories'
    )),
    (90400, (
        'local_preload_libraries',
        'search_path',
        'session_preload_libraries',
        'shared_preload_libraries',
        'temp_tablespaces'
    )),
)


# ===========================================
# PostgreSQL module specific support methods.
#


def param_is_guc_list_quote(server_version, name):
    for guc_list_quote_ver, guc_list_quote_params in PARAMETERS_GUC_LIST_QUOTE:
        if server_version >= guc_list_quote_ver:
            return name in guc_list_quote_params
    return False


def param_guc_list_unquote(value):
    # Unquote GUC_LIST_QUOTE parameter (each element can be quoted or not)
    # Assume the parameter is GUC_LIST_QUOTE (check in param_is_guc_list_quote function)
    return ', '.join([v.strip('" ') for v in value.split(',')])


def param_get(cursor, module, name, is_guc_list_quote):
    query = ("SELECT name, setting, unit, context, boot_val "
             "FROM pg_settings WHERE name = %(name)s")
    try:
        cursor.execute(query, {'name': name})
        info = cursor.fetchone()
        cursor.execute("SHOW %s" % name)
        val = cursor.fetchone()

    except Exception as e:
        module.fail_json(msg="Unable to get %s value due to : %s" % (name, to_native(e)))

    if not info:
        module.fail_json(msg="No such parameter: %s. "
                             "Please check its spelling or presence in your PostgreSQL version "
                             "(https://www.postgresql.org/docs/current/runtime-config.html)" % name)

    current_val = val[name]
    raw_val = info['setting']
    unit = info['unit']
    context = info['context']
    boot_val = info['boot_val']

    if current_val == 'True':
        current_val = 'on'
    elif current_val == 'False':
        current_val = 'off'

    if unit == 'kB':
        if int(raw_val) > 0:
            raw_val = int(raw_val) * 1024
        if int(boot_val) > 0:
            boot_val = int(boot_val) * 1024

        unit = 'b'

    elif unit == 'MB':
        if int(raw_val) > 0:
            raw_val = int(raw_val) * 1024 * 1024
        if int(boot_val) > 0:
            boot_val = int(boot_val) * 1024 * 1024

        unit = 'b'

    if is_guc_list_quote:
        current_val = param_guc_list_unquote(current_val)
        raw_val = param_guc_list_unquote(raw_val)

    return {
        'current_val': current_val,
        'raw_val': raw_val,
        'unit': unit,
        'boot_val': boot_val,
        'context': context,
    }


def pretty_to_bytes(pretty_val):
    # The function returns a value in bytes
    # if the value contains 'B', 'kB', 'MB', 'GB', 'TB'.
    # Otherwise it returns the passed argument.

    # It's sometimes possible to have an empty values
    if not pretty_val:
        return pretty_val

    # If the first char is not a digit, it does not make sense
    # to parse further, so just return a passed value
    if not pretty_val[0].isdigit():
        return pretty_val

    # If the last char is not an alphabetical symbol, it means that
    # it does not contain any suffixes, so no sense to parse further
    if not pretty_val[-1].isalpha():
        try:
            pretty_val = int(pretty_val)

        except ValueError:
            try:
                pretty_val = float(pretty_val)

            except ValueError:
                return pretty_val

        return pretty_val

    # Extract digits
    num_part = []
    for c in pretty_val:
        # When we reach the first non-digit element,
        # e.g. in 1024kB, stop iterating
        if not c.isdigit():
            break
        else:
            num_part.append(c)

    num_part = int(''.join(num_part))

    val_in_bytes = None

    if len(pretty_val) >= 2:
        if 'kB' in pretty_val[-2:]:
            val_in_bytes = num_part * 1024

        elif 'MB' in pretty_val[-2:]:
            val_in_bytes = num_part * 1024 * 1024

        elif 'GB' in pretty_val[-2:]:
            val_in_bytes = num_part * 1024 * 1024 * 1024

        elif 'TB' in pretty_val[-2:]:
            val_in_bytes = num_part * 1024 * 1024 * 1024 * 1024

    # For cases like "1B"
    if not val_in_bytes and 'B' in pretty_val[-1]:
        val_in_bytes = num_part

    if val_in_bytes is not None:
        return val_in_bytes
    else:
        return pretty_val


def param_set(cursor, module, name, value, server_version):
    if isinstance(value, str) and ',' in value and \
            not name.endswith(('_command', '_prefix')) and \
            not (server_version < 140000 and name == 'unix_socket_directories'):
        # Issue https://github.com/ansible-collections/community.postgresql/issues/78
        # Change value from 'one, two, three' -> "'one','two','three'"
        # PR https://github.com/ansible-collections/community.postgresql/pull/400
        # Parameter names ends with '_command' or '_prefix' can contains commas but are not lists
        # PR https://github.com/ansible-collections/community.postgresql/pull/521
        # unix_socket_directories up to PostgreSQL 13 lacks GUC_LIST_INPUT and
        # GUC_LIST_QUOTE options so it is a single value parameter
        value = ','.join(["'" + elem.strip() + "'" for elem in value.split(',')])
        query = "ALTER SYSTEM SET %s = %s" % (name, value)
    else:
        query = "ALTER SYSTEM SET %s = '%s'" % (name, value)

    fail_msg = "Unable to set %s value due to : %s"
    return exec_set_sql(cursor, module, query, name, fail_msg)


def param_set_default(cursor, module, name):
    query = "ALTER SYSTEM SET %s = DEFAULT" % name
    fail_msg = "Unable to set default value for %s due to : %s"
    return exec_set_sql(cursor, module, query, name, fail_msg)


def param_reset(cursor, module, name):
    query = "ALTER SYSTEM RESET %s" % name
    fail_msg = "Unable to reset %s due to : %s"
    return exec_set_sql(cursor, module, query, name, fail_msg)


def exec_set_sql(cursor, module, query, setting_name, fail_msg):
    try:
        executed_queries.append(query)
        cursor.execute(query)
    except Exception as e:
        module.fail_json(msg=fail_msg % (setting_name, to_native(e)))
    return True


# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        name=dict(type='str', required=True),
        login_db=dict(type='str', aliases=['db'], deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        value=dict(type='str'),
        reset=dict(type='bool', default=False),
        session_role=dict(type='str'),
        trust_input=dict(type='bool', default=True),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    name = module.params['name']
    value = module.params['value']
    reset = module.params['reset']
    session_role = module.params['session_role']
    trust_input = module.params['trust_input']

    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, name, value, session_role)

    if value:
        # Convert a value like 1mb (Postgres does not support) to 1MB, etc:
        if len(value) > 2 and value[:-2].isdigit() and value[-2:] in LOWERCASE_SIZE_UNITS:
            value = value.upper()

        # Convert a value like 1b (Postgres does not support) to 1B:
        elif len(value) > 1 and ('b' in value[-1] and value[:-1].isdigit()):
            value = value.upper()

    if name == 'shared_preload_libraries' and value == '':
        msg = ("Due to a PostgreSQL bug in resetting shared_preload_libraries "
               "with ALTER SYSTEM SET, setting it as an empty string "
               "is not supported by the module to avoid crashes. "
               "Use the `value: default` or `reset: true` argument instead. "
               "If you think the bug has been fixed, please let us know.")
        module.fail_json(msg=msg)

    if value is not None and reset:
        module.fail_json(msg="%s: value and reset params are mutually exclusive" % name)

    if value is None and not reset:
        module.fail_json(msg="%s: at least one of value or reset param must be specified" % name)

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
    cursor = db_connection.cursor(**pg_cursor_args)

    kw = {}
    # Check server version (needs 9.4 or later):
    ver = get_server_version(db_connection)
    if ver < PG_REQ_VER:
        module.warn("PostgreSQL is %s version but %s or later is required" % (ver, PG_REQ_VER))
        kw = dict(
            changed=False,
            restart_required=False,
            value_pretty="",
            prev_val_pretty="",
            value={"value": "", "unit": ""},
        )
        kw['name'] = name
        db_connection.close()
        module.exit_json(**kw)

    # Check parameter is GUC_LIST_QUOTE (done once as depend only on server version)
    is_guc_list_quote = param_is_guc_list_quote(ver, name)

    # Set default returned values:
    restart_required = False
    changed = False
    kw['name'] = name
    kw['restart_required'] = False

    # Get info about param state:
    res = param_get(cursor, module, name, is_guc_list_quote)
    current_val = res['current_val']
    raw_val = res['raw_val']
    unit = res['unit']
    boot_val = res['boot_val']
    context = res['context']

    if value == 'True':
        value = 'on'
    elif value == 'False':
        value = 'off'

    kw['prev_val_pretty'] = current_val
    kw['value_pretty'] = deepcopy(kw['prev_val_pretty'])
    kw['context'] = context

    # Do job
    if context == "internal":
        module.fail_json(msg="%s: cannot be changed (internal context). See "
                             "https://www.postgresql.org/docs/current/runtime-config-preset.html" % name)

    if context == "postmaster":
        restart_required = True

    # If check_mode, just compare and exit:
    if module.check_mode:
        if pretty_to_bytes(value) == pretty_to_bytes(current_val):
            kw['changed'] = False

        else:
            kw['value_pretty'] = value
            kw['changed'] = True

        # Anyway returns current raw value in the check_mode:
        kw['value'] = dict(
            value=raw_val,
            unit=unit,
        )
        kw['restart_required'] = restart_required
        kw['queries'] = executed_queries
        module.exit_json(**kw)

    # Set param (value can be an empty string):
    if value is not None and value != current_val:
        if value == 'default':
            changed = param_set_default(cursor, module, name)
        else:
            changed = param_set(cursor, module, name, value, ver)

        kw['value_pretty'] = value

    # Reset param:
    elif reset:
        if raw_val == boot_val:
            # nothing to change, exit:
            kw['value'] = dict(
                value=raw_val,
                unit=unit,
            )
            kw['queries'] = executed_queries
            module.exit_json(**kw)

        changed = param_reset(cursor, module, name)

    # When the setting can be changed w/o restart, apply it
    if not module.check_mode and changed and context != 'postmaster':
        cursor.execute("SELECT pg_reload_conf()")

    cursor.close()
    db_connection.close()

    # Reconnect and recheck current value:
    if context in ('sighup', 'superuser-backend', 'backend', 'superuser', 'user'):
        db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
        cursor = db_connection.cursor(**pg_cursor_args)

        res = param_get(cursor, module, name, is_guc_list_quote)
        # f_ means 'final'
        f_value = res['current_val']
        f_raw_val = res['raw_val']

        if raw_val == f_raw_val:
            changed = False

        else:
            changed = True

        kw['value_pretty'] = f_value
        kw['value'] = dict(
            value=f_raw_val,
            unit=unit,
        )

        cursor.close()
        db_connection.close()

    kw['changed'] = changed
    kw['restart_required'] = restart_required
    kw['queries'] = executed_queries

    if restart_required and changed:
        module.warn("Restart of PostgreSQL is required for setting %s" % name)

    module.exit_json(**kw)


if __name__ == '__main__':
    main()
