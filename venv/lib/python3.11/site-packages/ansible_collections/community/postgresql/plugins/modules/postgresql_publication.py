#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Loic Blot (@nerzhul) <loic.blot@unix-experience.fr>
# Copyright: (c) 2019, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: postgresql_publication
short_description: Add, update, or remove PostgreSQL publication
description:
- Add, update, or remove PostgreSQL publication.
options:
  name:
    description:
    - Name of the publication to add, update, or remove.
    required: true
    type: str
  login_db:
    description:
    - Name of the database to connect to and where
      the publication state will be changed.
    - The V(db) alias is deprecated and will be removed in version 5.0.0.
    aliases: [ db ]
    type: str
  columns:
    description:
    - List of tables and its columns to add to the publication.
    - If no columns are passed for table, it will be published as a whole.
    - Mutually exclusive with I(tables) and I(tables_in_schema).
    type: dict
    version_added: '3.8.0'
  rowfilters:
    description:
    - Optional dictionary of row filters to apply to I(tables) or I(columns) of the publication.
    - Mutually exclusive with I(tables_in_schema).
    type: dict
    version_added: '3.12.0'
  tables:
    description:
    - List of tables to add to the publication.
    - If no value is set all tables are targeted.
    - If the publication already exists for specific tables and I(tables) is not passed,
      nothing will be changed.
    - If you need to add all tables to the publication with the same name,
      drop existent and create new without passing I(tables).
    - Mutually exclusive with I(tables_in_schema) and I(columns).
    type: list
    elements: str
  tables_in_schema:
    description:
    - Specifies a list of schemas to add to the publication to replicate changes
      for all tables in those schemas.
    - If you want to remove all schemas, explicitly pass an empty list C([]).
    - Supported since PostgreSQL 15.
    - Mutually exclusive with I(tables) and I(columns).
    type: list
    elements: str
    version_added: '3.5.0'
  state:
    description:
    - The publication state.
    default: present
    choices: [ absent, present ]
    type: str
  parameters:
    description:
    - Dictionary with optional publication parameters.
    - Available parameters depend on PostgreSQL version.
    type: dict
  owner:
    description:
    - Publication owner.
    - If I(owner) is not defined, the owner will be set as I(login_user) or I(session_role).
    type: str
  cascade:
    description:
    - Drop publication dependencies. Has effect with I(state=absent) only.
    type: bool
    default: false
  session_role:
    description:
    - Switch to session_role after connecting. The specified session_role must
      be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though
      the session_role were the one that had logged in originally.
    type: str
    version_added: '0.2.0'
  trust_input:
    description:
    - If C(false), check whether values of parameters I(name), I(tables), I(owner),
      I(session_role), I(params) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via the parameters are possible.
    type: bool
    default: true
    version_added: '0.2.0'
  comment:
    description:
    - Sets a comment on the publication.
    - To reset the comment, pass an empty string.
    type: str
    version_added: '3.3.0'

notes:
- PostgreSQL version must be 10 or greater.

attributes:
  check_mode:
    support: full

seealso:
- name: CREATE PUBLICATION reference
  description: Complete reference of the CREATE PUBLICATION command documentation.
  link: https://www.postgresql.org/docs/current/sql-createpublication.html
- name: ALTER PUBLICATION reference
  description: Complete reference of the ALTER PUBLICATION command documentation.
  link: https://www.postgresql.org/docs/current/sql-alterpublication.html
- name: DROP PUBLICATION reference
  description: Complete reference of the DROP PUBLICATION command documentation.
  link: https://www.postgresql.org/docs/current/sql-droppublication.html
author:
- Loic Blot (@nerzhul) <loic.blot@unix-experience.fr>
- Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
- George Spanos (@grantanplan) <spanosgeorge@gmail.com>
extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Create a new publication with name "acme" targeting all tables in database "test"
  community.postgresql.postgresql_publication:
    login_db: test
    name: acme
    comment: Made by Ansible

- name: Create publication "acme" publishing only prices and vehicles tables
  community.postgresql.postgresql_publication:
    name: acme
    tables:
    - prices
    - vehicles

- name: Create publication "acme" publishing only prices table and id and name from vehicles tables
  community.postgresql.postgresql_publication:
    name: acme
    columns:
      prices:
      vehicles:
        - id
        - name

- name: Create publication "acme" publishing id and name from vehicles tables, with a row filter
  community.postgresql.postgresql_publication:
    name: acme
    columns:
      vehicles:
        - id
        - name
    rowfilters:
        vehicles: (id > 100)

- name: >
    Assuming publication "acme" exists, publishing id and name from vehicles table with a
    row filter (id > 100), remove and re-add the table to the publication, with the updated row filter
  community.postgresql.postgresql_publication:
    name: acme
    columns:
      vehicles:
        - id
        - name
    rowfilters:
        vehicles: WHERE (id > 100) AND (id < 200)

- name: Create a new publication "acme" for tables in schema "myschema"
  community.postgresql.postgresql_publication:
    login_db: test
    name: acme
    tables_in_schema: myschema

- name: Remove all schemas from "acme" publication
  community.postgresql.postgresql_publication:
    login_db: test
    name: acme
    tables_in_schema: []

- name: >
    Create publication "acme", set user alice as an owner, targeting all tables
    Allowable DML operations are INSERT and UPDATE only
  community.postgresql.postgresql_publication:
    name: acme
    owner: alice
    parameters:
      publish: 'insert,update'

- name: >
    Assuming publication "acme" exists and there are targeted
    tables "prices" and "vehicles", add table "stores" to the publication
  community.postgresql.postgresql_publication:
    name: acme
    tables:
    - prices
    - vehicles
    - stores

- name: Remove publication "acme" if exists in database "test"
  community.postgresql.postgresql_publication:
    login_db: test
    name: acme
    state: absent
'''

RETURN = r'''
exists:
  description:
  - Flag indicates the publication exists or not at the end of runtime.
  returned: success
  type: bool
  sample: true
queries:
  description: List of executed queries.
  returned: success
  type: str
  sample: [ 'DROP PUBLICATION "acme" CASCADE' ]
owner:
  description: Owner of the publication at the end of runtime.
  returned: if publication exists
  type: str
  sample: "alice"
tables:
  description:
  - List of tables in the publication at the end of runtime.
  - If all tables are published, returns empty list.
  returned: if publication exists
  type: list
  sample: ["\"public\".\"prices\"", "\"public\".\"vehicles\""]
alltables:
  description:
  - Flag indicates that all tables are published.
  returned: if publication exists
  type: bool
  sample: false
parameters:
  description: Publication parameters at the end of runtime.
  returned: if publication exists
  type: dict
  sample: {'publish': {'insert': false, 'delete': false, 'update': true}}
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import (
    check_input, pg_quote_identifier)
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db, ensure_required_libs, exec_sql, get_conn_params,
    get_server_version, pg_cursor_args, postgres_common_argument_spec,
    set_comment)

SUPPORTED_PG_VERSION = 10000


################################
# Module functions and classes #
################################

def normalize_table_name(table):
    """Add 'public.' to name of table where a schema identifier is absent
    and add quotes to each element.

    Args:
        table (str): Table name.

    Returns:
        str: Normalized table name.
    """
    if '.' not in table:
        return pg_quote_identifier('public.%s' % table.strip(), 'table')
    else:
        return pg_quote_identifier(table.strip(), 'table')


def transform_tables_representation(tbl_list):
    """Add 'public.' to names of tables where a schema identifier is absent
    and add quotes to each element.

    Args:
        tbl_list (list): List of table names.

    Returns:
        tbl_list (list): Changed list.
    """
    for i, table in enumerate(tbl_list):
        tbl_list[i] = normalize_table_name(table)

    return tbl_list


def transform_columns_keys(columns):
    """Add quotes to each element of the columns list.

    Args:
        columns (dict): Dict with tables and columns.

    Returns:
        columns (dict): Changed dict.
    """
    revmap_columns = {}
    for table in columns:
        revmap_columns[normalize_table_name(table)] = set(c.strip() for c in columns[table]) if columns[table] else None

    return revmap_columns


def transform_rowfilters_keys(rowfilters):
    """Add quotes to each element of the rowfilters list and removes any "WHERE" clauses
    from the filter, since it's not retained in the publication `rowfilter` column

    Args:
        rowfilters (dict): Dict with tables and row filter conditions.

    Returns:
        rowfilters (dict): Changed dict.
    """
    revmap_filters = {}
    for table, fltr in rowfilters.items():
        fltr = fltr.strip()
        if fltr:
            if fltr[:5].lower() == 'where':
                fltr = fltr[5:].strip()
            revmap_filters[normalize_table_name(table)] = RowFilter(fltr)

    return revmap_filters


def pg_quote_column_list(table, columns):
    """Convert a list of columns to a string.

    Args:
        table (str): Table name.
        columns (list): List of columns.

    Returns:
        str: String with columns.
    """
    table = normalize_table_name(table)

    if not columns:
        return table

    quoted_columns = [pg_quote_identifier(col, 'column') for col in columns]
    quoted_sql = "%s (%s)" % (table, ', '.join(quoted_columns))
    return quoted_sql


class RowFilter(str):
    """Represents a row filter `WHERE` clause on a particular `table`

    We overload the `==` and `!=` operators so that when comparing:
        1. any possible quoting on columns is not considered
        2. whitespace is not considered

    This makes possible to identify identical row filters and not perform any
    changes, regardless of insignificant (for Postgres) syntactic differences.
    e.g.
        '(  id > 10)' will be equivalent to '("id" > 10)'
    """
    def __init__(self, rfilter):
        self.rfilter = rfilter

    def __eq__(self, other):
        return (self.rfilter.replace('"', '').replace(' ', '') == other.rfilter.replace('"', '').replace(' ', ''))

    def __ne__(self, other):
        return not self.__eq__(other)


class PgPublication():
    """Class to work with PostgreSQL publication.

    Args:
        module (AnsibleModule): Object of AnsibleModule class.
        cursor (cursor): Cursor object of psycopg library to work with PostgreSQL.
        name (str): The name of the publication.

    Attributes:
        module (AnsibleModule): Object of AnsibleModule class.
        cursor (cursor): Cursor object of psycopg library to work with PostgreSQL.
        name (str): Name of the publication.
        executed_queries (list): List of executed queries.
        attrs (dict): Dict with publication attributes.
        exists (bool): Flag indicates the publication exists or not.
    """

    def __init__(self, module, cursor, name, pg_srv_ver):
        self.module = module
        self.cursor = cursor
        self.name = name
        self.pg_srv_ver = pg_srv_ver
        self.executed_queries = []
        self.attrs = {
            'alltables': False,
            'tables': [],
            'parameters': {},
            'owner': '',
            'schemas': [],
            'columns': {},
            'rowfilters': {},
        }
        self.exists = self.check_pub()

    def get_info(self):
        """Refresh the publication information.

        Returns:
            ``self.attrs``.
        """
        self.exists = self.check_pub()
        return self.attrs

    def check_pub(self):
        """Check the publication and refresh ``self.attrs`` publication attribute.

        Returns:
            True if the publication with ``self.name`` exists, False otherwise.
        """

        pub_info = self.__get_general_pub_info()

        if not pub_info:
            # Publication does not exist:
            return False

        self.attrs['owner'] = pub_info.get('pubowner')
        self.attrs['comment'] = pub_info.get('comment') if pub_info.get('comment') is not None else ''

        # Publication DML operations:
        self.attrs['parameters']['publish'] = {}
        self.attrs['parameters']['publish']['insert'] = pub_info.get('pubinsert', False)
        self.attrs['parameters']['publish']['update'] = pub_info.get('pubupdate', False)
        self.attrs['parameters']['publish']['delete'] = pub_info.get('pubdelete', False)
        if pub_info.get('pubtruncate'):
            self.attrs['parameters']['publish']['truncate'] = pub_info.get('pubtruncate')

        # If alltables flag is False, get the list of targeted tables:
        if not pub_info.get('puballtables'):
            table_info = self.__get_tables_pub_info()
            for i, schema_and_table in enumerate(table_info):
                table_info[i] = pg_quote_identifier(schema_and_table["schema_dot_table"], 'table')

            self.attrs['tables'] = table_info

            if self.pg_srv_ver >= 150000:
                # FOR TABLES IN SCHEMA statement and row filters are supported since PostgreSQL 15
                self.attrs['schemas'] = self.__get_schema_pub_info()
                column_info = self.__get_columns_pub_info()
                columns = {}
                for row in column_info:
                    columns[normalize_table_name(row["schema_dot_table"])] = set(row['columns'])
                self.attrs['columns'] = columns

                filters_info = self.__get_rowfilters_pub_info()
                filters = {}
                for row in filters_info:
                    filters[normalize_table_name(row["schema_dot_table"])] = RowFilter(row['rowfilter'])
                self.attrs['rowfilters'] = filters
        else:
            self.attrs['alltables'] = True

        # Publication exists:
        return True

    def create(self, tables, tables_in_schema, columns, rowfilters, params, owner, comment, check_mode=True):
        """Create the publication.

        Args:
            tables (list): List with names of the tables that need to be added to the publication.
            tables_in_schema (list): List of schema names of the tables that need to be added to the publication.
            params (dict): Dict contains optional publication parameters and their values.
            owner (str): Name of the publication owner.
            comment (str): Comment on the publication.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            changed (bool): True if publication has been created, otherwise False.
        """
        changed = True

        query_fragments = ["CREATE PUBLICATION %s" % pg_quote_identifier(self.name, 'publication')]

        if columns:
            table_strings = []
            for table in columns:
                quoted_cols = pg_quote_column_list(table, columns[table])
                if table in rowfilters:
                    quoted_cols += (" WHERE %s" % rowfilters[table])
                table_strings.append(quoted_cols)
            query_fragments.append("FOR TABLE %s" % ', '.join(table_strings))
        elif tables:
            table_strings = []
            for table in tables:
                tbl_str = pg_quote_identifier(table, 'table')
                if table in rowfilters:
                    tbl_str += " WHERE %s" % rowfilters[table]
                table_strings.append(tbl_str)
            query_fragments.append("FOR TABLE %s" % ', '.join(table_strings))
        elif tables_in_schema:
            tables_in_schema = [pg_quote_identifier(schema, 'schema') for schema in tables_in_schema]
            query_fragments.append("FOR TABLES IN SCHEMA %s" % ', '.join(tables_in_schema))
        else:
            query_fragments.append("FOR ALL TABLES")

        if params:
            params_list = []
            # Make list ["param = 'value'", ...] from params dict:
            for (key, val) in params.items():
                params_list.append("%s = '%s'" % (key, val))

            # Add the list to query_fragments:
            query_fragments.append("WITH (%s)" % ', '.join(params_list))

        changed = self.__exec_sql(' '.join(query_fragments), check_mode=check_mode)

        if owner:
            # If check_mode, just add possible SQL to
            # executed_queries and return:
            self.__pub_set_owner(owner, check_mode=check_mode)

        if comment is not None:
            set_comment(self.cursor, comment, 'publication',
                        self.name, check_mode, self.executed_queries)

        return changed

    def update(self, tables, tables_in_schema, columns, rowfilters, params, owner, comment, check_mode=True):
        """Update the publication.

        Args:
            tables (list): List with names of the tables that need to be presented in the publication.
            tables_in_schema (list): List of schema names of the tables that need to be presented in the publication.
            params (dict): Dict contains optional publication parameters and their values.
            owner (str): Name of the publication owner.
            comment (str): Comment on the publication.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            changed (bool): True if publication has been updated, otherwise False.
        """
        changed = False

        # Add or drop tables from published tables suit:
        if columns and not self.attrs['alltables']:
            need_set_columns = False
            for table in columns:
                if table not in self.attrs['tables']:
                    continue
                elif not columns[table]:
                    all_columns = self.__get_table_columns(table)
                    if all_columns != self.attrs['columns'][table]:
                        need_set_columns = True
                        break
                elif self.attrs['columns'][table] != columns[table]:
                    need_set_columns = True
                    break
                elif columns[table] == self.attrs['columns'][table]:
                    if (table in rowfilters
                            and table in self.attrs['rowfilters']
                            and rowfilters[table] != self.attrs['rowfilters'][table]):
                        need_set_columns = True
                        break

            if need_set_columns:
                changed = self.__pub_set_columns(columns, rowfilters, check_mode=check_mode)
            else:
                # Add new tables to the publication:
                for table in columns:
                    if table not in self.attrs['tables']:
                        changed = self.__pub_add_columns(table, columns[table], rowfilters, check_mode=check_mode)

                # Drop redundant tables from the publication:
                for table in self.attrs['columns']:
                    if table not in columns.keys():
                        changed = self.__pub_drop_table(table, check_mode=check_mode)

        elif columns and self.attrs['alltables']:
            changed = self.__pub_set_columns(columns, rowfilters, check_mode=check_mode)
        if tables and not self.attrs['alltables']:

            # 1. If needs to add table to the publication:
            for tbl in tables:
                if tbl not in self.attrs['tables']:
                    changed = self.__pub_add_table(tbl, rowfilters, check_mode=check_mode)
                elif ((tbl in rowfilters and rowfilters[tbl] != self.attrs['rowfilters'][tbl])
                        or (tbl in self.attrs['rowfilters'] and tbl not in rowfilters)):
                    # If table is part of the publication, but row filter input
                    # doesn't match the actual state of the publication, then drop it and
                    # re-ADD it so that the row filter gets applied.
                    changed = self.__pub_drop_table(tbl, check_mode=check_mode)
                    if changed:
                        changed = self.__pub_add_table(tbl, rowfilters, check_mode=check_mode)

            # 2. if there is a table in targeted tables
            # that's not present in the passed tables:
            for tbl in self.attrs['tables']:
                if tbl not in tables:
                    changed = self.__pub_drop_table(tbl, check_mode=check_mode)

        elif tables and self.attrs['alltables']:
            changed = self.__pub_set_tables(tables, rowfilters, check_mode=check_mode)

        elif tables_in_schema is not None:

            # 1. If needs to add schema to the publication:
            for schema in tables_in_schema:
                if schema not in self.attrs['schemas']:
                    changed = self.__pub_add_schema(schema, check_mode=check_mode)

            # 2. if there is a schema that's already in the publication
            # but not present in the passed schemas we remove it from the publication:
            for schema in self.attrs['schemas']:
                if schema not in tables_in_schema:
                    changed = self.__pub_drop_schema(schema, check_mode=check_mode)

        # Update pub parameters:
        if params:
            for key, val in params.items():
                if self.attrs['parameters'].get(key):

                    # In PostgreSQL 10/11 only 'publish' optional parameter is presented.
                    if key == 'publish':
                        # 'publish' value can be only a string with comma-separated items
                        # of allowed DML operations like 'insert,update' or
                        # 'insert,update,delete', etc.
                        # Make dictionary to compare with current attrs later:
                        val_dict = self.attrs['parameters']['publish'].copy()
                        val_list = val.split(',')
                        for v in val_dict:
                            if v in val_list:
                                val_dict[v] = True
                            else:
                                val_dict[v] = False

                        # Compare val_dict and the dict with current 'publish' parameters,
                        # if they're different, set new values:
                        if val_dict != self.attrs['parameters']['publish']:
                            changed = self.__pub_set_param(key, val, check_mode=check_mode)

                    # Default behavior for other cases:
                    elif self.attrs['parameters'][key] != val:
                        changed = self.__pub_set_param(key, val, check_mode=check_mode)

                else:
                    # If the parameter was not set before:
                    changed = self.__pub_set_param(key, val, check_mode=check_mode)

        # Update pub owner:
        if owner and owner != self.attrs['owner']:
            changed = self.__pub_set_owner(owner, check_mode=check_mode)

        if comment is not None and comment != self.attrs['comment']:
            changed = set_comment(self.cursor, comment, 'publication',
                                  self.name, check_mode, self.executed_queries)

        return changed

    def drop(self, cascade=False, check_mode=True):
        """Drop the publication.

        Kwargs:
            cascade (bool): Flag indicates that publication needs to be deleted
                with its dependencies.
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            changed (bool): True if publication has been updated, otherwise False.
        """
        if self.exists:
            query_fragments = []
            query_fragments.append("DROP PUBLICATION %s" % pg_quote_identifier(self.name, 'publication'))
            if cascade:
                query_fragments.append("CASCADE")

            return self.__exec_sql(' '.join(query_fragments), check_mode=check_mode)

    def __get_general_pub_info(self):
        """Get and return general publication information.

        Returns:
            Dict with publication information if successful, False otherwise.
        """
        # Check pg_publication.pubtruncate exists (supported from PostgreSQL 11):
        pgtrunc_sup = exec_sql(self, ("SELECT 1 FROM information_schema.columns "
                                      "WHERE table_name = 'pg_publication' "
                                      "AND column_name = 'pubtruncate'"), add_to_executed=False)

        if pgtrunc_sup:
            query = ("SELECT obj_description(p.oid, 'pg_publication') AS comment, "
                     "r.rolname AS pubowner, p.puballtables, p.pubinsert, "
                     "p.pubupdate , p.pubdelete, p.pubtruncate FROM pg_publication AS p "
                     "JOIN pg_catalog.pg_roles AS r "
                     "ON p.pubowner = r.oid "
                     "WHERE p.pubname = %(pname)s")
        else:
            query = ("SELECT obj_description(p.oid, 'pg_publication') AS comment, "
                     "r.rolname AS pubowner, p.puballtables, p.pubinsert, "
                     "p.pubupdate , p.pubdelete FROM pg_publication AS p "
                     "JOIN pg_catalog.pg_roles AS r "
                     "ON p.pubowner = r.oid "
                     "WHERE p.pubname = %(pname)s")

        result = exec_sql(self, query, query_params={'pname': self.name}, add_to_executed=False)
        if result:
            return result[0]
        else:
            return False

    def __get_tables_pub_info(self):
        """Get and return tables that are published by the publication.

        Returns:
            List of dicts with published tables.
        """
        query = ("SELECT schemaname || '.' || tablename as schema_dot_table "
                 "FROM pg_publication_tables WHERE pubname = %(pname)s")
        return exec_sql(self, query, query_params={'pname': self.name}, add_to_executed=False)

    def __get_rowfilters_pub_info(self):
        """Get and return any row filters for each table that are published by the publication.

        Returns:
            List of dicts with row filters for each table.
        """
        query = ("SELECT schemaname || '.' || tablename as schema_dot_table, rowfilter "
                 "FROM pg_publication_tables "
                 "WHERE pubname = %(pname)s AND rowfilter is not NULL")
        return exec_sql(self, query, query_params={'pname': self.name}, add_to_executed=False)

    def __get_columns_pub_info(self):
        """Get and return columns that are published by the publication.

        Returns:
            List of dicts with published columns.
        """
        query = ("SELECT schemaname || '.' || tablename as schema_dot_table, attnames as columns "
                 "FROM pg_publication_tables WHERE pubname = %(pname)s")
        return exec_sql(self, query, query_params={'pname': self.name}, add_to_executed=False)

    def __get_schema_pub_info(self):
        """Get and return schemas added to the publication.

        Returns:
            List of schemas.
        """
        query = ("SELECT n.nspname FROM pg_namespace AS n "
                 "JOIN pg_publication_namespace AS pn ON n.oid = pn.pnnspid "
                 "JOIN pg_publication AS p ON p.oid = pn.pnpubid "
                 "WHERE p.pubname = %(pname)s")
        list_of_dicts = exec_sql(self, query, query_params={'pname': self.name},
                                 add_to_executed=False)

        list_of_schemas = []
        for d in list_of_dicts:
            list_of_schemas.extend(d.values())
        return list_of_schemas

    def __get_table_columns(self, table):
        """Get and return columns names of the table.

        Returns:
            Set of columns.
        """
        query = ("SELECT attname as column_name FROM pg_attribute "
                 "WHERE attrelid = %(table)s::regclass and attnum > 0 AND NOT attisdropped;")
        result = exec_sql(self, query, query_params={'table': table}, add_to_executed=False)
        return set([row['column_name'] for row in result])

    def __pub_add_table(self, table, rowfilters, check_mode=False):
        """Add a table to the publication.

        Args:
            table (str): Table name.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            True if successful, False otherwise.
        """
        quoted_tbl = pg_quote_identifier(table, 'table')
        if table in rowfilters:
            quoted_tbl += (" WHERE %s" % rowfilters[table])
        query = ("ALTER PUBLICATION %s ADD TABLE %s" % (pg_quote_identifier(self.name, 'publication'),
                                                        quoted_tbl))
        return self.__exec_sql(query, check_mode=check_mode)

    def __pub_drop_table(self, table, check_mode=False):
        """Drop a table from the publication.

        Args:
            table (str): Table name.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            True if successful, False otherwise.
        """
        query = ("ALTER PUBLICATION %s DROP TABLE %s" % (pg_quote_identifier(self.name, 'publication'),
                                                         pg_quote_identifier(table, 'table')))
        return self.__exec_sql(query, check_mode=check_mode)

    def __pub_set_tables(self, tables, rowfilters, check_mode=False):
        """Set a table suit that need to be published by the publication.

        Args:
            tables (list): List of tables.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            True if successful, False otherwise.
        """
        quoted_tables = []
        for table in tables:
            quoted_tbl = pg_quote_identifier(table, 'table')
            if table in rowfilters:
                quoted_tbl += (" WHERE %s" % rowfilters[table])
                quoted_tables.append(quoted_tbl)
        query = ("ALTER PUBLICATION %s SET TABLE %s" % (pg_quote_identifier(self.name, 'publication'),
                                                        ', '.join(quoted_tables)))
        return self.__exec_sql(query, check_mode=check_mode)

    def __pub_add_columns(self, table, columns, rowfilters, check_mode=False):
        """ Add table with specific columns to the publication.
        Args:
            table (str): Table name.
            columns (list): List of columns.
        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.
        Returns:
            True if successful, False otherwise.
        """
        quoted_cols = pg_quote_column_list(table, columns)
        if table in rowfilters:
            quoted_cols += (" WHERE %s" % rowfilters[table])
        query = ("ALTER PUBLICATION %s ADD TABLE %s" % (pg_quote_identifier(self.name, 'publication'),
                                                        quoted_cols))
        return self.__exec_sql(query, check_mode=check_mode)

    def __pub_set_columns(self, columns_map, rowfilters, check_mode=False):
        """Set columns that need to be published by the publication.
        Args:
            columns_map (dict): Dictionary of all tables and list of columns.
        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.
        Returns:
            True if successful, False otherwise.
        """
        table_list = []
        for table, columns in columns_map.items():
            quoted_cols = pg_quote_column_list(table, columns)
            if table in rowfilters:
                quoted_cols += (" WHERE %s" % rowfilters[table])
            table_list.append(quoted_cols)
        query = (
            "ALTER PUBLICATION %s SET TABLE %s" %
            (pg_quote_identifier(self.name, 'publication'),
             ', '.join(table_list))
        )
        return self.__exec_sql(query, check_mode=check_mode)

    def __pub_add_schema(self, schema, check_mode=False):
        """Add a schema to the publication.

        Args:
            schema (str): Schema name.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            True if truly added, False otherwise.
        """
        query = ("ALTER PUBLICATION %s ADD "
                 "TABLES IN SCHEMA %s" % (pg_quote_identifier(self.name, 'publication'),
                                          pg_quote_identifier(schema, 'schema')))
        return self.__exec_sql(query, check_mode=check_mode)

    def __pub_drop_schema(self, schema, check_mode=False):
        """Drop a schema from the publication.

        Args:
            schema (str): Schema name.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            True if truly dropped, False otherwise.
        """
        query = ("ALTER PUBLICATION %s DROP "
                 "TABLES IN SCHEMA %s" % (pg_quote_identifier(self.name, 'publication'),
                                          pg_quote_identifier(schema, 'schema')))
        return self.__exec_sql(query, check_mode=check_mode)

    def __pub_set_param(self, param, value, check_mode=False):
        """Set an optional publication parameter.

        Args:
            param (str): Name of the parameter.
            value (str): Parameter value.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            True if successful, False otherwise.
        """
        query = ("ALTER PUBLICATION %s SET (%s = '%s')" % (pg_quote_identifier(self.name, 'publication'),
                                                           param, value))
        return self.__exec_sql(query, check_mode=check_mode)

    def __pub_set_owner(self, role, check_mode=False):
        """Set a publication owner.

        Args:
            role (str): Role (user) name that needs to be set as a publication owner.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just make SQL, add it to ``self.executed_queries`` and return True.

        Returns:
            True if successful, False otherwise.
        """
        query = ('ALTER PUBLICATION %s '
                 'OWNER TO "%s"' % (pg_quote_identifier(self.name, 'publication'), role))
        return self.__exec_sql(query, check_mode=check_mode)

    def __exec_sql(self, query, check_mode=False):
        """Execute SQL query.

        Note: If we need just to get information from the database,
            we use ``exec_sql`` function directly.

        Args:
            query (str): Query that needs to be executed.

        Kwargs:
            check_mode (bool): If True, don't actually change anything,
                just add ``query`` to ``self.executed_queries`` and return True.

        Returns:
            True if successful, False otherwise.
        """
        if check_mode:
            self.executed_queries.append(query)
            return True
        else:
            return exec_sql(self, query, return_bool=True)


# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        name=dict(required=True),
        login_db=dict(type='str', aliases=['db'], deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        tables=dict(type='list', elements='str'),
        parameters=dict(type='dict'),
        owner=dict(type='str'),
        cascade=dict(type='bool', default=False),
        session_role=dict(type='str'),
        trust_input=dict(type='bool', default=True),
        comment=dict(type='str', default=None),
        tables_in_schema=dict(type='list', elements='str', default=None),
        columns=dict(type='dict', default=None),
        rowfilters=dict(type='dict', default=None),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[('tables', 'tables_in_schema', "columns"),
                            ('rowfilters', 'tables_in_schema')],
    )

    # Parameters handling:
    name = module.params['name']
    state = module.params['state']
    tables = module.params['tables']
    params = module.params['parameters']
    owner = module.params['owner']
    cascade = module.params['cascade']
    session_role = module.params['session_role']
    trust_input = module.params['trust_input']
    comment = module.params['comment']
    tables_in_schema = module.params['tables_in_schema']
    columns = module.params['columns']
    rowfilters = module.params['rowfilters']

    if not trust_input:
        # Check input for potentially dangerous elements:
        if not params:
            params_list = None
        else:
            params_list = ['%s = %s' % (k, v) for k, v in params.items()]

        check_input(module, name, tables, owner,
                    session_role, params_list, comment)

    if state == 'absent':
        if tables:
            module.warn('parameter "tables" is ignored when "state=absent"')
        if params:
            module.warn('parameter "parameters" is ignored when "state=absent"')
        if owner:
            module.warn('parameter "owner" is ignored when "state=absent"')

    if state == 'present' and cascade:
        module.warn('parameter "cascade" is ignored when "state=present"')

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    # Connect to DB and make cursor object:
    conn_params = get_conn_params(module, module.params)
    # We check publication state without DML queries execution, so set autocommit:
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
    cursor = db_connection.cursor(**pg_cursor_args)

    # Check version:
    pg_srv_ver = get_server_version(cursor.connection)
    if pg_srv_ver < SUPPORTED_PG_VERSION:
        module.fail_json(msg="PostgreSQL server version should be 10.0 or greater")

    if tables_in_schema is not None and pg_srv_ver < 150000:
        module.fail_json(msg="Publication of tables in schema is supported by PostgreSQL 15 or greater")
    if columns and pg_srv_ver < 150000:
        module.fail_json(msg="Publication of columns is supported by PostgreSQL 15 or greater")
    if rowfilters is not None and pg_srv_ver < 150000:
        module.fail_json(msg="Row filtering is supported by PostgreSQL 15 or greater")
    # Nothing was changed by default:
    changed = False

    ###################################
    # Create object and do rock'n'roll:
    publication = PgPublication(module, cursor, name, pg_srv_ver)

    if tables:
        tables = transform_tables_representation(tables)

    if columns:
        columns = transform_columns_keys(columns)

    rowfilters = transform_rowfilters_keys(rowfilters) if rowfilters else {}

    # If module.check_mode=True, nothing will be changed:
    if state == 'present':
        if not publication.exists:
            changed = publication.create(tables, tables_in_schema, columns, rowfilters, params, owner,
                                         comment, check_mode=module.check_mode)

        else:
            changed = publication.update(tables, tables_in_schema, columns, rowfilters, params, owner,
                                         comment, check_mode=module.check_mode)

    elif state == 'absent':
        changed = publication.drop(cascade=cascade, check_mode=module.check_mode)

    # Get final publication info:
    pub_fin_info = {}
    if state == 'present' or (state == 'absent' and module.check_mode):
        pub_fin_info = publication.get_info()
    elif state == 'absent' and not module.check_mode:
        publication.exists = False

    # Connection is not needed any more:
    cursor.close()
    db_connection.close()

    # Update publication info and return ret values:
    module.exit_json(changed=changed, queries=publication.executed_queries, exists=publication.exists, **pub_fin_info)


if __name__ == '__main__':
    main()
