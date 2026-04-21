#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_schema
short_description: Add or remove PostgreSQL schema
description:
- Add or remove PostgreSQL schema.
options:
  name:
    description:
    - Name of the schema to add or remove.
    required: true
    type: str
    aliases:
    - schema
  login_db:
    description:
    - Name of the database to connect to and add or remove the schema.
    - The V(db) alias is deprecated and will be removed in version 5.0.0.
    type: str
    default: postgres
    aliases:
    - db
    - database
  owner:
    description:
    - Name of the role to set as owner of the schema.
    type: str
    default: ''
  session_role:
    description:
    - Switch to session_role after connecting.
    - The specified session_role must be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though the session_role
      were the one that had logged in originally.
    type: str
  state:
    description:
    - The schema state.
    type: str
    default: present
    choices: [ absent, present ]
  cascade_drop:
    description:
    - Drop schema with CASCADE to remove child objects.
    type: bool
    default: false
  trust_input:
    description:
    - If C(false), check whether values of parameters I(schema), I(owner), I(session_role) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via the parameters are possible.
    type: bool
    default: true
    version_added: '0.2.0'
  comment:
    description:
    - Sets a comment on the schema.
    - To reset the comment, pass an empty string.
    type: str
    version_added: '3.3.0'
seealso:
- name: PostgreSQL schemas
  description: General information about PostgreSQL schemas.
  link: https://www.postgresql.org/docs/current/ddl-schemas.html
- name: CREATE SCHEMA reference
  description: Complete reference of the CREATE SCHEMA command documentation.
  link: https://www.postgresql.org/docs/current/sql-createschema.html
- name: ALTER SCHEMA reference
  description: Complete reference of the ALTER SCHEMA command documentation.
  link: https://www.postgresql.org/docs/current/sql-alterschema.html
- name: DROP SCHEMA reference
  description: Complete reference of the DROP SCHEMA command documentation.
  link: https://www.postgresql.org/docs/current/sql-dropschema.html

attributes:
  check_mode:
    support: full

author:
- Flavien Chantelot (@Dorn-) <contact@flavien.io>
- Thomas O'Donnell (@andytom)

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Create a new schema with name acme in test database
  community.postgresql.postgresql_schema:
    login_db: test
    name: acme
    comment: 'My test schema'

- name: Create a new schema acme with a user bob who will own it
  community.postgresql.postgresql_schema:
    name: acme
    owner: bob

- name: Drop schema "acme" with cascade
  community.postgresql.postgresql_schema:
    name: acme
    state: absent
    cascade_drop: true
'''

RETURN = r'''
schema:
  description: Name of the schema.
  returned: success
  type: str
  sample: "acme"
queries:
  description: List of executed queries.
  returned: success
  type: list
  sample: ["CREATE SCHEMA \"acme\""]
'''

import traceback

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import (
    SQLParseError,
    check_input,
    pg_quote_identifier,
)
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    get_conn_params,
    pg_cursor_args,
    postgres_common_argument_spec,
    set_comment,
)

executed_queries = []


class NotSupportedError(Exception):
    pass


# ===========================================
# PostgreSQL module specific support methods.
#

def set_owner(cursor, schema, owner):
    query = 'ALTER SCHEMA %s OWNER TO "%s"' % (
            pg_quote_identifier(schema, 'schema'), owner)
    cursor.execute(query)
    executed_queries.append(query)
    return True


def get_schema_info(cursor, schema):
    query = ("SELECT obj_description((SELECT oid "
             "FROM pg_namespace WHERE nspname = %(schema)s), 'pg_namespace') "
             "AS comment, schema_owner AS owner "
             "FROM information_schema.schemata "
             "WHERE schema_name = %(schema)s")
    cursor.execute(query, {'schema': schema})
    return cursor.fetchone()


def schema_exists(cursor, schema):
    query = ("SELECT schema_name FROM information_schema.schemata "
             "WHERE schema_name = %(schema)s")
    cursor.execute(query, {'schema': schema})
    return cursor.rowcount == 1


def schema_delete(cursor, schema, cascade):
    if schema_exists(cursor, schema):
        query = "DROP SCHEMA %s" % pg_quote_identifier(schema, 'schema')
        if cascade:
            query += " CASCADE"
        cursor.execute(query)
        executed_queries.append(query)
        return True
    else:
        return False


def schema_create(cursor, schema, owner, comment):
    if not schema_exists(cursor, schema):
        query_fragments = ['CREATE SCHEMA %s' % pg_quote_identifier(schema, 'schema')]
        if owner:
            query_fragments.append('AUTHORIZATION "%s"' % owner)
        query = ' '.join(query_fragments)
        cursor.execute(query)
        executed_queries.append(query)
        if comment is not None:
            set_comment(cursor, comment, 'schema', schema, False, executed_queries)
        return True
    else:
        schema_info = get_schema_info(cursor, schema)
        changed = False
        if owner and owner != schema_info['owner']:
            changed = set_owner(cursor, schema, owner)

        if comment is not None:
            current_comment = schema_info['comment'] if schema_info['comment'] is not None else ''
            if comment != current_comment:
                changed = set_comment(cursor, comment, 'schema', schema, False, executed_queries) or changed

        return changed


def schema_matches(cursor, schema, owner, comment):
    if not schema_exists(cursor, schema):
        return False
    else:
        schema_info = get_schema_info(cursor, schema)
        if owner and owner != schema_info['owner']:
            return False
        if comment is not None:
            # For the resetting comment feature (comment: '') to work correctly
            current_comment = schema_info['comment'] if schema_info['comment'] is not None else ''
            if comment != current_comment:
                return False

        return True

# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True, aliases=['name']),
        owner=dict(type="str", default=""),
        login_db=dict(type='str', default='postgres', aliases=['db', 'database'], deprecated_aliases=[
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
        cascade_drop=dict(type="bool", default=False),
        state=dict(type="str", default="present", choices=["absent", "present"]),
        session_role=dict(type="str"),
        trust_input=dict(type="bool", default=True),
        comment=dict(type="str", default=None),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    schema = module.params["schema"]
    owner = module.params["owner"]
    state = module.params["state"]
    cascade_drop = module.params["cascade_drop"]
    session_role = module.params["session_role"]
    trust_input = module.params["trust_input"]
    comment = module.params["comment"]

    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, schema, owner, session_role, comment)

    changed = False

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
    cursor = db_connection.cursor(**pg_cursor_args)

    try:
        if module.check_mode:
            if state == "absent":
                changed = schema_exists(cursor, schema)
            elif state == "present":
                changed = not schema_matches(cursor, schema, owner, comment)
            module.exit_json(changed=changed, schema=schema)

        if state == "absent":
            try:
                changed = schema_delete(cursor, schema, cascade_drop)
            except SQLParseError as e:
                module.fail_json(msg=to_native(e), exception=traceback.format_exc())

        elif state == "present":
            try:
                changed = schema_create(cursor, schema, owner, comment)
            except SQLParseError as e:
                module.fail_json(msg=to_native(e), exception=traceback.format_exc())
    except NotSupportedError as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())
    except SystemExit:
        # Avoid catching this on Python 2.4
        raise
    except Exception as e:
        module.fail_json(msg="Database query failed: %s" % to_native(e), exception=traceback.format_exc())

    db_connection.close()
    module.exit_json(changed=changed, schema=schema, queries=executed_queries)


if __name__ == '__main__':
    main()
