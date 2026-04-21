#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Flavien Chantelot (@Dorn-)
# Copyright: (c) 2018, Antoine Levy-Lambert (@antoinell)
# Copyright: (c) 2019, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_tablespace
short_description: Add or remove PostgreSQL tablespaces from remote hosts
description:
- Adds or removes PostgreSQL tablespaces from remote hosts.
options:
  tablespace:
    description:
    - Name of the tablespace to add or remove.
    required: true
    type: str
    aliases:
    - name
  location:
    description:
    - Path to the tablespace directory in the file system.
    - Ensure that the location exists and has right privileges.
    type: path
    aliases:
    - path
  state:
    description:
    - Tablespace state.
    - I(state=present) implies the tablespace must be created if it doesn't exist.
    - I(state=absent) implies the tablespace must be removed if present.
      I(state=absent) is mutually exclusive with I(location), I(owner), i(set).
    - See the Notes section for information about check mode restrictions.
    type: str
    default: present
    choices: [ absent, present ]
  owner:
    description:
    - Name of the role to set as an owner of the tablespace.
    - If this option is not specified, the tablespace owner is a role that creates the tablespace.
    type: str
  set:
    description:
    - Dict of tablespace options to set. Supported from PostgreSQL 9.0.
    - For more information see U(https://www.postgresql.org/docs/current/sql-createtablespace.html).
    - When reset is passed as an option's value, if the option was set previously, it will be removed.
    type: dict
  rename_to:
    description:
    - DEPRECATED (see the L(discussion,https://github.com/ansible-collections/community.postgresql/issues/820)).
      This option will be removed in version 5.0.0.
      To rename a tablespace, use the M(community.postgresql.postgresql_query) module.
    - New name of the tablespace.
    - The new name cannot begin with pg_, as such names are reserved for system tablespaces.
    type: str
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
  trust_input:
    description:
    - If C(false), check whether values of parameters I(tablespace), I(location), I(owner),
      I(rename_to), I(session_role), I(settings_list) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via the parameters are possible.
    type: bool
    default: true
    version_added: '0.2.0'
  comment:
    description:
    - Sets a comment on the tablespace.
    - To reset the comment, pass an empty string.
    type: str
    version_added: '3.3.0'

attributes:
  check_mode:
    support: partial
    details:
      - I(state=absent) and I(state=present) (the second one if the tablespace doesn't exist) do not
        support check mode because the corresponding PostgreSQL DROP and CREATE TABLESPACE commands
        can not be run inside the transaction block.

seealso:
- name: PostgreSQL tablespaces
  description: General information about PostgreSQL tablespaces.
  link: https://www.postgresql.org/docs/current/manage-ag-tablespaces.html
- name: CREATE TABLESPACE reference
  description: Complete reference of the CREATE TABLESPACE command documentation.
  link: https://www.postgresql.org/docs/current/sql-createtablespace.html
- name: ALTER TABLESPACE reference
  description: Complete reference of the ALTER TABLESPACE command documentation.
  link: https://www.postgresql.org/docs/current/sql-altertablespace.html
- name: DROP TABLESPACE reference
  description: Complete reference of the DROP TABLESPACE command documentation.
  link: https://www.postgresql.org/docs/current/sql-droptablespace.html

author:
- Flavien Chantelot (@Dorn-)
- Antoine Levy-Lambert (@antoinell)
- Andrew Klychkov (@Andersson007)
- Daniele Giudice (@RealGreenDragon)

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Create a new tablespace called acme and set bob as an its owner
  community.postgresql.postgresql_tablespace:
    name: acme
    owner: bob
    location: /data/foo
    comment: "Bob's tablespace"

- name: Create a new tablespace called bar with tablespace options
  community.postgresql.postgresql_tablespace:
    name: bar
    set:
      random_page_cost: 1
      seq_page_cost: 1

- name: Reset random_page_cost option
  community.postgresql.postgresql_tablespace:
    name: bar
    set:
      random_page_cost: reset

- name: Drop tablespace called bloat
  community.postgresql.postgresql_tablespace:
    name: bloat
    state: absent
'''

RETURN = r'''
queries:
    description: List of queries that was tried to be executed.
    returned: success
    type: str
    sample: [ "CREATE TABLESPACE bar LOCATION '/incredible/ssd'" ]
tablespace:
    description: Tablespace name.
    returned: success
    type: str
    sample: 'ssd'
owner:
    description: Tablespace owner.
    returned: success
    type: str
    sample: 'Bob'
comment:
    description: Tablespace comment.
    returned: success
    type: str
    sample: 'Test tablespace'
options:
    description: Tablespace options.
    returned: success
    type: dict
    sample: { 'random_page_cost': 1, 'seq_page_cost': 1 }
location:
    description: Path to the tablespace in the file system.
    returned: success
    type: str
    sample: '/incredible/fast/ssd'
newname:
    description: New tablespace name.
    returned: if existent
    type: str
    sample: new_ssd
state:
    description: Tablespace state at the end of execution.
    returned: success
    type: str
    sample: 'present'
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import \
    check_input
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    exec_sql,
    get_conn_params,
    pg_cursor_args,
    postgres_common_argument_spec,
    set_autocommit,
    set_comment,
)


class PgTablespace(object):

    """Class for working with PostgreSQL tablespaces.

    Args:
        module (AnsibleModule) -- object of AnsibleModule class
        cursor (cursor) -- cursor object of psycopg library
        name (str) -- name of the tablespace

    Attrs:
        module (AnsibleModule) -- object of AnsibleModule class
        cursor (cursor) -- cursor object of psycopg library
        name (str) -- name of the tablespace
        exists (bool) -- flag the tablespace exists in the DB or not
        owner (str) -- tablespace owner
        location (str) -- path to the tablespace directory in the file system
        executed_queries (list) -- list of executed queries
        new_name (str) -- new name for the tablespace
        opt_not_supported (bool) -- flag indicates a tablespace option is supported or not
    """

    def __init__(self, module, cursor, name):
        self.module = module
        self.cursor = cursor
        self.name = name
        self.exists = False
        self.owner = ''
        self.settings = {}
        self.location = ''
        self.executed_queries = []
        self.new_name = ''
        self.opt_not_supported = False
        self.comment = None
        # Collect info:
        self.get_info()

    def get_info(self):
        """Get tablespace information."""
        # Check that spcoptions exists:
        opt = exec_sql(self, "SELECT 1 FROM information_schema.columns "
                             "WHERE table_name = 'pg_tablespace' "
                             "AND column_name = 'spcoptions'", add_to_executed=False)

        # For 9.1 version and earlier:
        location = exec_sql(self, "SELECT 1 FROM information_schema.columns "
                                  "WHERE table_name = 'pg_tablespace' "
                                  "AND column_name = 'spclocation'", add_to_executed=False)
        if location:
            location = 'spclocation'
        else:
            location = 'pg_tablespace_location(t.oid)'

        if not opt:
            self.opt_not_supported = True
            query = ("SELECT shobj_description(t.oid, 'pg_tablespace') AS comment, "
                     "r.rolname, (SELECT Null) spcoptions, %s loc_string "
                     "FROM pg_catalog.pg_tablespace AS t "
                     "JOIN pg_catalog.pg_roles AS r "
                     "ON t.spcowner = r.oid " % location)
        else:
            query = ("SELECT shobj_description(t.oid, 'pg_tablespace') AS comment, "
                     "r.rolname, t.spcoptions, %s loc_string "
                     "FROM pg_catalog.pg_tablespace AS t "
                     "JOIN pg_catalog.pg_roles AS r "
                     "ON t.spcowner = r.oid " % location)

        res = exec_sql(self, query + "WHERE t.spcname = %(name)s",
                       query_params={'name': self.name}, add_to_executed=False)

        if not res:
            self.exists = False
            return False

        if res[0]["rolname"]:
            self.exists = True
            self.owner = res[0]["rolname"]

            if res[0]["spcoptions"]:
                # Options exist:
                for i in res[0]["spcoptions"]:
                    i = i.split('=')
                    self.settings[i[0]] = i[1]

            if res[0]["loc_string"]:
                # Location exists:
                self.location = res[0]["loc_string"]

            self.comment = res[0]["comment"] if res[0]["comment"] is not None else ''

    def create(self, location):
        """Create tablespace.

        Return True if success, otherwise, return False.

        args:
            location (str) -- tablespace directory path in the FS
        """
        query = ('CREATE TABLESPACE "%s" LOCATION \'%s\'' % (self.name, location))
        return exec_sql(self, query, return_bool=True)

    def drop(self):
        """Drop tablespace.

        Return True if success, otherwise, return False.
        """
        return exec_sql(self, 'DROP TABLESPACE "%s"' % self.name, return_bool=True)

    def set_owner(self, new_owner):
        """Set tablespace owner.

        Return True if success, otherwise, return False.

        args:
            new_owner (str) -- name of a new owner for the tablespace"
        """
        if new_owner == self.owner:
            return False

        query = 'ALTER TABLESPACE "%s" OWNER TO "%s"' % (self.name, new_owner)
        return exec_sql(self, query, return_bool=True)

    def set_comment(self, comment, check_mode):
        """Set tablespace comment.

        Return True if success, otherwise, return False.

        args:
            comment (str) -- comment to set for the tablespace"
        """
        if comment == self.comment:
            return False

        return set_comment(self.cursor, comment, 'tablespace', self.name,
                           check_mode, self.executed_queries)

    def rename(self, newname):
        """Rename tablespace.

        Return True if success, otherwise, return False.

        args:
            newname (str) -- new name for the tablespace"
        """
        query = 'ALTER TABLESPACE "%s" RENAME TO "%s"' % (self.name, newname)
        self.new_name = newname
        return exec_sql(self, query, return_bool=True)

    def set_settings(self, new_settings):
        """Set tablespace settings (options).

        If some setting has been changed, set changed = True.
        After all settings list is handling, return changed.

        args:
            new_settings (list) -- list of new settings
        """
        # settings must be a dict {'key': 'value'}
        if self.opt_not_supported:
            return False

        changed = False

        # Apply new settings:
        for i in new_settings:
            if new_settings[i] == 'reset':
                if i in self.settings:
                    changed = self.__reset_setting(i)
                    self.settings[i] = None

            elif (i not in self.settings) or (str(new_settings[i]) != self.settings[i]):
                changed = self.__set_setting("%s = '%s'" % (i, new_settings[i]))

        return changed

    def __reset_setting(self, setting):
        """Reset tablespace setting.

        Return True if success, otherwise, return False.

        args:
            setting (str) -- string in format "setting_name = 'setting_value'"
        """
        query = 'ALTER TABLESPACE "%s" RESET (%s)' % (self.name, setting)
        return exec_sql(self, query, return_bool=True)

    def __set_setting(self, setting):
        """Set tablespace setting.

        Return True if success, otherwise, return False.

        args:
            setting (str) -- string in format "setting_name = 'setting_value'"
        """
        query = 'ALTER TABLESPACE "%s" SET (%s)' % (self.name, setting)
        return exec_sql(self, query, return_bool=True)


# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        tablespace=dict(type='str', required=True, aliases=['name']),
        state=dict(type='str', default="present", choices=["absent", "present"]),
        location=dict(type='path', aliases=['path']),
        owner=dict(type='str'),
        set=dict(type='dict'),
        login_db=dict(type='str', aliases=['db'], deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        rename_to=dict(type='str', removed_in_version='5.0.0',
                       removed_from_collection='community.postgresql'),
        session_role=dict(type='str'),
        trust_input=dict(type='bool', default=True),
        comment=dict(type='str', default=None),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    tablespace = module.params["tablespace"]
    state = module.params["state"]
    location = module.params["location"]
    owner = module.params["owner"]
    rename_to = module.params["rename_to"]
    settings = module.params["set"]
    session_role = module.params["session_role"]
    trust_input = module.params["trust_input"]
    comment = module.params["comment"]

    if state == 'absent' and (location or owner or rename_to or settings):
        module.fail_json(msg="state=absent is mutually exclusive location, "
                             "owner, rename_to, and set")

    if not trust_input:
        # Check input for potentially dangerous elements:
        if not settings:
            settings_list = None
        else:
            settings_list = ['%s = %s' % (k, v) for k, v in settings.items()]

        check_input(module, tablespace, location, owner,
                    rename_to, session_role, settings_list, comment)

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=False if module.check_mode else True)
    cursor = db_connection.cursor(**pg_cursor_args)

    # Set defaults:
    autocommit = False
    changed = False

    ##############
    # Create PgTablespace object and do main job:
    tblspace = PgTablespace(module, cursor, tablespace)

    # If tablespace exists with different location, exit:
    if tblspace.exists and location and location != tblspace.location:
        module.fail_json(msg="Tablespace '%s' exists with "
                             "different location '%s'" % (tblspace.name, tblspace.location))

    # Create new tablespace:
    if not tblspace.exists and state == 'present':
        if rename_to:
            module.fail_json(msg="Tablespace %s does not exist, nothing to rename" % tablespace)

        if not location:
            module.fail_json(msg="'location' parameter must be passed with "
                                 "state=present if the tablespace doesn't exist")

        # Because CREATE TABLESPACE can not be run inside the transaction block:
        autocommit = True
        set_autocommit(db_connection, True)

        changed = tblspace.create(location)

    # Drop existing tablespace:
    elif tblspace.exists and state == 'absent':
        # Because DROP TABLESPACE can not be run inside the transaction block:
        autocommit = True
        set_autocommit(db_connection, True)

        changed = tblspace.drop()

    # Rename tablespace:
    elif tblspace.exists and rename_to:
        if tblspace.name != rename_to:
            changed = tblspace.rename(rename_to)

    if state == 'present':
        # Refresh information:
        tblspace.get_info()

    # Change owner, comment and settings:
    if state == 'present' and tblspace.exists:
        if owner:
            changed = tblspace.set_owner(owner) or changed

        if settings:
            changed = tblspace.set_settings(settings) or changed

        if comment is not None:
            changed = tblspace.set_comment(comment, module.check_mode) or changed

        # Update tablespace information in the class
        tblspace.get_info()

    # Rollback if it's possible and check_mode:
    if not autocommit:
        if module.check_mode:
            db_connection.rollback()
        else:
            db_connection.commit()

    cursor.close()
    db_connection.close()

    # Make return values:
    kw = dict(
        changed=changed,
        state='present',
        tablespace=tblspace.name,
        owner=tblspace.owner,
        queries=tblspace.executed_queries,
        options=tblspace.settings,
        location=tblspace.location,
        comment=tblspace.comment,
    )

    if state == 'present':
        kw['state'] = 'present'

        if tblspace.new_name:
            kw['newname'] = tblspace.new_name

    elif state == 'absent':
        kw['state'] = 'absent'

    module.exit_json(**kw)


if __name__ == '__main__':
    main()
