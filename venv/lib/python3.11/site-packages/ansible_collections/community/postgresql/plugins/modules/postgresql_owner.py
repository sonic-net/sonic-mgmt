#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_owner
short_description: Change an owner of PostgreSQL database object
description:
- Change an owner of PostgreSQL database object.
- Also allows to reassign the ownership of database objects owned by a database role to another role.

options:
  new_owner:
    description:
    - Role (user/group) to set as an I(obj_name) owner.
    type: str
    required: true
  obj_name:
    description:
    - Name of a database object to change ownership.
    - Mutually exclusive with I(reassign_owned_by).
    type: str
  obj_type:
    description:
    - Type of a database object.
    - Mutually exclusive with I(reassign_owned_by).
    - I(obj_type=matview) is available since PostgreSQL 9.3.
    - I(obj_type=event_trigger), I(obj_type=procedure), I(obj_type=publication),
      I(obj_type=statistics), and I(obj_type=routine) are available since PostgreSQL 11.
    type: str
    choices: [ aggregate, collation, conversion, database, domain, event_trigger, foreign_data_wrapper,
               foreign_table, function, language, large_object, matview, procedure, publication, routine,
               schema, sequence, server, statistics, table, tablespace, text_search_configuration,
               text_search_dictionary, type, view ]
    aliases:
    - type
  reassign_owned_by:
    description:
    - Caution - the ownership of all the objects within the specified I(db),
      owned by this role(s) will be reassigned to I(new_owner).
    - REASSIGN OWNED is often used to prepare for the removal of one or more roles.
    - REASSIGN OWNED does not affect objects within other databases.
    - Execute this command in each database that contains objects owned by a role that is to be removed.
    - If role(s) exists, always returns changed True.
    - Cannot reassign ownership of objects that are required by the database system.
    - Mutually exclusive with C(obj_type).
    type: list
    elements: str
  fail_on_role:
    description:
    - If C(true), fail when I(reassign_owned_by) role does not exist.
      Otherwise just warn and continue.
    - Mutually exclusive with I(obj_name) and I(obj_type).
    default: true
    type: bool
  login_db:
    description:
    - Name of database to connect to.
    - The V(db) alias is deprecated and will be removed in version 5.0.0.
    type: str
    aliases:
    - db
  session_role:
    description:
    - Switch to session_role after connecting.
      The specified session_role must be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though
      the session_role were the one that had logged in originally.
    type: str
  trust_input:
    description:
    - If C(false), check whether values of parameters I(new_owner), I(obj_name),
      I(reassign_owned_by), I(session_role) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via the parameters are possible.
    type: bool
    default: true
    version_added: '0.2.0'

notes:
- Function Overloading is not supported so when I(obj_type) is C(aggregate), C(function), C(routine), or C(procedure)
  I(obj_name) is considered the only object of same type with this name.
- Despite Function Overloading is not supported, when I(obj_type=aggregate) I(obj_name) must contain also aggregate
  signature because it is required by SQL syntax.
- I(new_owner) must be a superuser if I(obj_type) is C(event_type) or C(foreign_data_wrapper).
- To manage subscriptions ownership use C(community.postgresql.postgresql_subscription) module.

seealso:
- module: community.postgresql.postgresql_user
- module: community.postgresql.postgresql_privs
- module: community.postgresql.postgresql_membership
- module: community.postgresql.postgresql_subscription
- name: PostgreSQL REASSIGN OWNED command reference
  description: Complete reference of the PostgreSQL REASSIGN OWNED command documentation.
  link: https://www.postgresql.org/docs/current/sql-reassign-owned.html

attributes:
  check_mode:
    support: full

author:
- Andrew Klychkov (@Andersson007)
- Daniele Giudice (@RealGreenDragon)

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
# Set owner as alice for function myfunc in database bar by ansible ad-hoc command:
# ansible -m postgresql_owner -a "db=bar new_owner=alice obj_name=myfunc obj_type=function"

- name: The same as above by playbook
  community.postgresql.postgresql_owner:
    login_db: bar
    new_owner: alice
    obj_name: myfunc
    obj_type: function

- name: Set owner as bob for table acme in database bar
  community.postgresql.postgresql_owner:
    login_db: bar
    new_owner: bob
    obj_name: acme
    obj_type: table

- name: Set owner as alice for view test_view in database bar
  community.postgresql.postgresql_owner:
    login_db: bar
    new_owner: alice
    obj_name: test_view
    obj_type: view

- name: Set owner as bob for tablespace ssd in database foo
  community.postgresql.postgresql_owner:
    login_db: foo
    new_owner: bob
    obj_name: ssd
    obj_type: tablespace

- name: Reassign all databases owned by bob to alice and all objects in database bar owned by bob to alice
  community.postgresql.postgresql_owner:
    login_db: bar
    new_owner: alice
    reassign_owned_by: bob

- name: Reassign all databases owned by bob or bill to alice and all objects in database bar owned by bob or bill to alice
  community.postgresql.postgresql_owner:
    login_db: bar
    new_owner: alice
    reassign_owned_by:
    - bob
    - bill
'''

RETURN = r'''
queries:
  description: List of executed queries.
  returned: success
  type: str
  sample: [ 'REASSIGN OWNED BY "bob" TO "alice"' ]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import (
    check_input,
    pg_quote_identifier,
)
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    exec_sql,
    get_conn_params,
    get_server_version,
    pg_cursor_args,
    postgres_common_argument_spec,
)

VALID_OBJ_TYPES = ('aggregate', 'collation', 'conversion', 'database', 'domain', 'event_trigger', 'foreign_data_wrapper',
                   'foreign_table', 'function', 'language', 'large_object', 'matview', 'procedure', 'publication',
                   'routine', 'schema', 'sequence', 'server', 'statistics', 'table', 'tablespace', 'text_search_configuration',
                   'text_search_dictionary', 'type', 'view')


class PgOwnership(object):

    """Class for changing ownership of PostgreSQL objects.

    Arguments:
        module (AnsibleModule): Object of Ansible module class.
        cursor (psycopg.connect.cursor): Cursor object for interaction with the database.
        role (str): Role name to set as a new owner of objects.

    Important:
        If you want to add handling of a new type of database objects:
        1. Add a specific method for this like self.__set_db_owner(), etc.
        2. Add a condition with a check of ownership for new type objects to self.__is_owner()
        3. Add a condition with invocation of the specific method to self.set_owner()
        4. Add the information to the module documentation
        That's all.
    """

    def __init__(self, module, cursor, pg_version, role):
        self.module = module
        self.cursor = cursor
        self.pg_version = pg_version
        self.check_role_exists(role)
        self.role = role
        self.changed = False
        self.executed_queries = []
        self.obj_name = ''
        self.obj_type = ''

    def check_role_exists(self, role, fail_on_role=True):
        """Check the role exists or not.

        Arguments:
            role (str): Role name.
            fail_on_role (bool): If True, fail when the role does not exist.
                Otherwise just warn and continue.
        """
        if not self.__role_exists(role):
            if fail_on_role:
                self.module.fail_json(msg="Role '%s' does not exist" % role)
            else:
                self.module.warn("Role '%s' does not exist, pass" % role)

            return False

        else:
            return True

    def reassign(self, old_owners, fail_on_role):
        """Implements REASSIGN OWNED BY command.

        If success, set self.changed as True.

        Arguments:
            old_owners (list): The ownership of all the objects within
                the current database, and of all shared objects (databases, tablespaces),
                owned by these roles will be reassigned to self.role.
            fail_on_role (bool): If True, fail when a role from old_owners does not exist.
                Otherwise just warn and continue.
        """
        roles = []
        for r in old_owners:
            if self.check_role_exists(r, fail_on_role):
                roles.append('"%s"' % r)

        # Roles do not exist, nothing to do, exit:
        if not roles:
            return False

        old_owners = ','.join(roles)

        query = ['REASSIGN OWNED BY']
        query.append(old_owners)
        query.append('TO "%s"' % self.role)
        query = ' '.join(query)

        self.changed = exec_sql(self, query, return_bool=True)

    def set_owner(self, obj_type, obj_name):
        """Change owner of a database object.

        Arguments:
            obj_type (str): Type of object (like database, table, view, etc.).
            obj_name (str): Object name.
        """
        self.obj_name = obj_name
        self.obj_type = obj_type

        # if a new_owner is the object owner now,
        # nothing to do:
        if self.__is_owner():
            return False

        if obj_type == 'database':
            self.__set_db_owner()

        elif obj_type == 'function':
            self.__set_func_owner()

        elif obj_type == 'sequence':
            self.__set_seq_owner()

        elif obj_type == 'schema':
            self.__set_schema_owner()

        elif obj_type == 'table':
            self.__set_table_owner()

        elif obj_type == 'tablespace':
            self.__set_tablespace_owner()

        elif obj_type == 'view':
            self.__set_view_owner()

        elif obj_type == 'matview':
            self.__set_mat_view_owner()

        elif obj_type == 'procedure':
            self.__set_procedure_owner()

        elif obj_type == 'type':
            self.__set_type_owner()

        elif obj_type == 'aggregate':
            self.__set_aggregate_owner()

        elif obj_type == 'routine':
            self.__set_routine_owner()

        elif obj_type == 'language':
            self.__set_language_owner()

        elif obj_type == 'domain':
            self.__set_domain_owner()

        elif obj_type == 'collation':
            self.__set_collation_owner()

        elif obj_type == 'conversion':
            self.__set_conversion_owner()

        elif obj_type == 'text_search_configuration':
            self.__set_text_search_configuration_owner()

        elif obj_type == 'text_search_dictionary':
            self.__set_text_search_dictionary_owner()

        elif obj_type == 'foreign_data_wrapper':
            self.__set_foreign_data_wrapper_owner()

        elif obj_type == 'server':
            self.__set_server_owner()

        elif obj_type == 'foreign_table':
            self.__set_foreign_table_owner()

        elif obj_type == 'event_trigger':
            self.__set_event_trigger_owner()

        elif obj_type == 'large_object':
            self.__set_large_object_owner()

        elif obj_type == 'publication':
            self.__set_publication_owner()

        elif obj_type == 'statistics':
            self.__set_statistics_owner()

    def __is_owner(self):
        """Return True if self.role is the current object owner."""
        if self.obj_type == 'table':
            query = ("SELECT 1 FROM pg_tables "
                     "WHERE tablename = %(obj_name)s "
                     "AND tableowner = %(role)s")

        elif self.obj_type == 'database':
            query = ("SELECT 1 FROM pg_database AS d "
                     "JOIN pg_roles AS r ON d.datdba = r.oid "
                     "WHERE d.datname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type in ('aggregate', 'function', 'routine', 'procedure'):
            if self.obj_type == 'routine' and self.pg_version < 110000:
                self.module.fail_json(msg="PostgreSQL version must be >= 11 for obj_type=routine.")
            if self.obj_type == 'procedure' and self.pg_version < 110000:
                self.module.fail_json(msg="PostgreSQL version must be >= 11 for obj_type=procedure.")
            query = ("SELECT 1 FROM pg_proc AS f "
                     "JOIN pg_roles AS r ON f.proowner = r.oid "
                     "WHERE f.proname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'sequence':
            query = ("SELECT 1 FROM pg_class AS c "
                     "JOIN pg_roles AS r ON c.relowner = r.oid "
                     "WHERE c.relkind = 'S' AND c.relname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'schema':
            query = ("SELECT 1 FROM information_schema.schemata "
                     "WHERE schema_name = %(obj_name)s "
                     "AND schema_owner = %(role)s")

        elif self.obj_type == 'tablespace':
            query = ("SELECT 1 FROM pg_tablespace AS t "
                     "JOIN pg_roles AS r ON t.spcowner = r.oid "
                     "WHERE t.spcname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'view':
            query = ("SELECT 1 FROM pg_views "
                     "WHERE viewname = %(obj_name)s "
                     "AND viewowner = %(role)s")

        elif self.obj_type == 'matview':
            if self.pg_version < 90300:
                self.module.fail_json(msg="PostgreSQL version must be >= 9.3 for obj_type=matview.")
            query = ("SELECT 1 FROM pg_matviews "
                     "WHERE matviewname = %(obj_name)s "
                     "AND matviewowner = %(role)s")

        elif self.obj_type in ('domain', 'type'):
            query = ("SELECT 1 FROM pg_type AS t "
                     "JOIN pg_roles AS r ON t.typowner = r.oid "
                     "WHERE t.typname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'language':
            query = ("SELECT 1 FROM pg_language AS l "
                     "JOIN pg_roles AS r ON l.lanowner = r.oid "
                     "WHERE l.lanname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'collation':
            query = ("SELECT 1 FROM pg_collation AS c "
                     "JOIN pg_roles AS r ON c.collowner = r.oid "
                     "WHERE c.collname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'conversion':
            query = ("SELECT 1 FROM pg_conversion AS c "
                     "JOIN pg_roles AS r ON c.conowner = r.oid "
                     "WHERE c.conname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'text_search_configuration':
            query = ("SELECT 1 FROM pg_ts_config AS t "
                     "JOIN pg_roles AS r ON t.cfgowner = r.oid "
                     "WHERE t.cfgname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'text_search_dictionary':
            query = ("SELECT 1 FROM pg_ts_dict AS t "
                     "JOIN pg_roles AS r ON t.dictowner = r.oid "
                     "WHERE t.dictname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'foreign_data_wrapper':
            query = ("SELECT 1 FROM pg_foreign_data_wrapper AS f "
                     "JOIN pg_roles AS r ON f.fdwowner = r.oid "
                     "WHERE f.fdwname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'server':
            query = ("SELECT 1 FROM pg_foreign_server AS f "
                     "JOIN pg_roles AS r ON f.srvowner = r.oid "
                     "WHERE f.srvname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'foreign_table':
            query = ("SELECT 1 FROM pg_class AS c "
                     "JOIN pg_roles AS r ON c.relowner = r.oid "
                     "WHERE c.relkind = 'f' AND c.relname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'event_trigger':
            if self.pg_version < 110000:
                self.module.fail_json(msg="PostgreSQL version must be >= 11 for obj_type=event_trigger.")
            query = ("SELECT 1 FROM pg_event_trigger AS e "
                     "JOIN pg_roles AS r ON e.evtowner = r.oid "
                     "WHERE e.evtname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'large_object':
            query = ("SELECT 1 FROM pg_largeobject_metadata AS l "
                     "JOIN pg_roles AS r ON l.lomowner = r.oid "
                     "WHERE l.oid = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'publication':
            if self.pg_version < 110000:
                self.module.fail_json(msg="PostgreSQL version must be >= 11 for obj_type=publication.")
            query = ("SELECT 1 FROM pg_publication AS p "
                     "JOIN pg_roles AS r ON p.pubowner = r.oid "
                     "WHERE p.pubname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        elif self.obj_type == 'statistics':
            if self.pg_version < 110000:
                self.module.fail_json(msg="PostgreSQL version must be >= 11 for obj_type=statistics.")
            query = ("SELECT 1 FROM pg_statistic_ext AS s "
                     "JOIN pg_roles AS r ON s.stxowner = r.oid "
                     "WHERE s.stxname = %(obj_name)s "
                     "AND r.rolname = %(role)s")

        if self.obj_type in ('function', 'aggregate', 'procedure', 'routine'):
            query_params = {'obj_name': self.obj_name.split('(')[0], 'role': self.role}
        else:
            query_params = {'obj_name': self.obj_name, 'role': self.role}

        return exec_sql(self, query, query_params, add_to_executed=False)

    def __set_db_owner(self):
        """Set the database owner."""
        query = 'ALTER DATABASE "%s" OWNER TO "%s"' % (self.obj_name, self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_func_owner(self):
        """Set the function owner."""
        query = 'ALTER FUNCTION %s OWNER TO "%s"' % (self.obj_name, self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_seq_owner(self):
        """Set the sequence owner."""
        query = 'ALTER SEQUENCE %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'sequence'),
                                                     self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_schema_owner(self):
        """Set the schema owner."""
        query = 'ALTER SCHEMA %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'schema'),
                                                   self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_table_owner(self):
        """Set the table owner."""
        query = 'ALTER TABLE %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                  self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_tablespace_owner(self):
        """Set the tablespace owner."""
        query = 'ALTER TABLESPACE "%s" OWNER TO "%s"' % (self.obj_name, self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_view_owner(self):
        """Set the view owner."""
        query = 'ALTER VIEW %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                 self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_mat_view_owner(self):
        """Set the materialized view owner."""
        if self.pg_version < 90300:
            self.module.fail_json(msg="PostgreSQL version must be >= 9.3 for obj_type=matview.")

        query = 'ALTER MATERIALIZED VIEW %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                              self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_procedure_owner(self):
        """Set the procedure owner."""
        if self.pg_version < 110000:
            self.module.fail_json(msg="PostgreSQL version must be >= 11 for obj_type=procedure.")

        query = 'ALTER PROCEDURE %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                      self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_type_owner(self):
        """Set the type owner."""
        query = 'ALTER TYPE %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                 self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_aggregate_owner(self):
        """Set the aggregate owner."""
        query = 'ALTER AGGREGATE %s OWNER TO "%s"' % (self.obj_name, self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_routine_owner(self):
        """Set the routine owner."""
        if self.pg_version < 110000:
            self.module.fail_json(msg="PostgreSQL version must be >= 11 for obj_type=routine.")
        query = 'ALTER ROUTINE %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                    self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_language_owner(self):
        """Set the language owner."""
        query = 'ALTER LANGUAGE %s OWNER TO "%s"' % (self.obj_name, self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_domain_owner(self):
        """Set the domain owner."""
        query = 'ALTER DOMAIN %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                   self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_collation_owner(self):
        """Set the collation owner."""
        query = 'ALTER COLLATION %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                      self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_conversion_owner(self):
        """Set the conversion owner."""
        query = 'ALTER CONVERSION %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                       self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_text_search_configuration_owner(self):
        """Set the text search configuration owner."""
        query = 'ALTER TEXT SEARCH CONFIGURATION %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                                      self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_text_search_dictionary_owner(self):
        """Set the text search dictionary owner."""
        query = 'ALTER TEXT SEARCH DICTIONARY %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                                   self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_foreign_data_wrapper_owner(self):
        """Set the foreign data wrapper owner."""
        query = 'ALTER FOREIGN DATA WRAPPER %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                                 self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_server_owner(self):
        """Set the server owner."""
        query = 'ALTER SERVER %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                   self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_foreign_table_owner(self):
        """Set the foreign table owner."""
        query = 'ALTER FOREIGN TABLE %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                          self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_event_trigger_owner(self):
        """Set the event trigger owner."""
        query = 'ALTER EVENT TRIGGER %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                          self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_large_object_owner(self):
        """Set the large object owner."""
        query = 'ALTER LARGE OBJECT %s OWNER TO "%s"' % (self.obj_name, self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_publication_owner(self):
        """Set the publication owner."""
        if self.pg_version < 110000:
            self.module.fail_json(msg="PostgreSQL version must be >= 11 for obj_type=publication.")
        query = 'ALTER PUBLICATION %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'publication'),
                                                        self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __set_statistics_owner(self):
        """Set the statistics owner."""
        if self.pg_version < 110000:
            self.module.fail_json(msg="PostgreSQL version must be >= 11 for obj_type=statistics.")
        query = 'ALTER STATISTICS %s OWNER TO "%s"' % (pg_quote_identifier(self.obj_name, 'table'),
                                                       self.role)
        self.changed = exec_sql(self, query, return_bool=True)

    def __role_exists(self, role):
        """Return True if role exists, otherwise return False."""
        query_params = {'role': role}
        query = "SELECT 1 FROM pg_roles WHERE rolname = %(role)s"
        return exec_sql(self, query, query_params, add_to_executed=False)


# ===========================================
# Module execution.
#

def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        new_owner=dict(type='str', required=True),
        obj_name=dict(type='str'),
        obj_type=dict(type='str', aliases=['type'], choices=VALID_OBJ_TYPES),
        reassign_owned_by=dict(type='list', elements='str'),
        fail_on_role=dict(type='bool', default=True),
        login_db=dict(type='str', aliases=['db'], deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        session_role=dict(type='str'),
        trust_input=dict(type='bool', default=True),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[
            ['obj_name', 'reassign_owned_by'],
            ['obj_type', 'reassign_owned_by'],
            ['obj_name', 'fail_on_role'],
            ['obj_type', 'fail_on_role'],
        ],
        supports_check_mode=True,
    )

    new_owner = module.params['new_owner']
    obj_name = module.params['obj_name']
    obj_type = module.params['obj_type']
    reassign_owned_by = module.params['reassign_owned_by']
    fail_on_role = module.params['fail_on_role']
    session_role = module.params['session_role']
    trust_input = module.params['trust_input']
    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, new_owner, obj_name, reassign_owned_by, session_role)

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=False)
    cursor = db_connection.cursor(**pg_cursor_args)
    pg_version = get_server_version(db_connection)

    ##############
    # Create the object and do main job:
    pg_ownership = PgOwnership(module, cursor, pg_version, new_owner)

    # if we want to change ownership:
    if obj_name:
        pg_ownership.set_owner(obj_type, obj_name)

    # if we want to reassign objects owned by roles:
    elif reassign_owned_by:
        pg_ownership.reassign(reassign_owned_by, fail_on_role)

    # Rollback if it's possible and check_mode:
    if module.check_mode:
        db_connection.rollback()
    else:
        db_connection.commit()

    cursor.close()
    db_connection.close()

    module.exit_json(
        changed=pg_ownership.changed,
        queries=pg_ownership.executed_queries,
    )


if __name__ == '__main__':
    main()
