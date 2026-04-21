#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_membership
short_description: Add or remove PostgreSQL roles from groups
description:
- Adds or removes PostgreSQL roles from groups (other roles).
- Users are roles with login privilege.
- Groups are PostgreSQL roles usually without LOGIN privilege.
- "Common use case:"
- 1) add a new group (groups) by M(community.postgresql.postgresql_user) module with I(role_attr_flags=NOLOGIN)
- 2) grant them desired privileges by M(community.postgresql.postgresql_privs) module
- 3) add desired PostgreSQL users to the new group (groups) by this module
options:
  groups:
    description:
    - The list of groups (roles) that need to be granted to or revoked from I(target_roles).
    required: true
    type: list
    elements: str
    aliases:
    - group
    - source_role
    - source_roles
  target_roles:
    description:
    - The list of target roles (groups will be granted to them).
    required: true
    type: list
    elements: str
    aliases:
    - target_role
    - users
    - user
  fail_on_role:
    description:
      - If C(true), fail when group or target_role doesn't exist. If C(false), just warn and continue.
    default: true
    type: bool
  state:
    description:
    - Membership state.
    - I(state=present) implies the I(groups)must be granted to I(target_roles).
    - I(state=absent) implies the I(groups) must be revoked from I(target_roles).
    - I(state=exact) implies that I(target_roles) will be members of only the I(groups)
      (available since community.postgresql 2.2.0).
      Any other groups will be revoked from I(target_roles).
    type: str
    default: present
    choices: [ absent, exact, present ]
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
    - If C(false), check whether values of parameters I(groups),
      I(target_roles), I(session_role) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via the parameters are possible.
    type: bool
    default: true
    version_added: '0.2.0'
seealso:
- module: community.postgresql.postgresql_user
- module: community.postgresql.postgresql_privs
- module: community.postgresql.postgresql_owner
- name: PostgreSQL role membership reference
  description: Complete reference of the PostgreSQL role membership documentation.
  link: https://www.postgresql.org/docs/current/role-membership.html
- name: PostgreSQL role attributes reference
  description: Complete reference of the PostgreSQL role attributes documentation.
  link: https://www.postgresql.org/docs/current/role-attributes.html

attributes:
  check_mode:
    support: full

author:
- Andrew Klychkov (@Andersson007)

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Grant role read_only to alice and bob
  community.postgresql.postgresql_membership:
    group: read_only
    target_roles:
    - alice
    - bob
    state: present

# you can also use target_roles: alice,bob,etc to pass the role list

- name: Revoke role read_only and exec_func from bob. Ignore if roles don't exist
  community.postgresql.postgresql_membership:
    groups:
    - read_only
    - exec_func
    target_role: bob
    fail_on_role: false
    state: absent

- name: >
    Make sure alice and bob are members only of marketing and sales.
    If they are members of other groups, they will be removed from those groups
  community.postgresql.postgresql_membership:
    group:
    - marketing
    - sales
    target_roles:
    - alice
    - bob
    state: exact

- name: Make sure alice and bob do not belong to any groups
  community.postgresql.postgresql_membership:
    group: []
    target_roles:
    - alice
    - bob
    state: exact
'''

RETURN = r'''
queries:
    description: List of executed queries.
    returned: success
    type: str
    sample: [ "GRANT \"user_ro\" TO \"alice\"" ]
granted:
    description: Dict of granted groups and roles.
    returned: if I(state=present)
    type: dict
    sample: { "ro_group": [ "alice", "bob" ] }
revoked:
    description: Dict of revoked groups and roles.
    returned: if I(state=absent)
    type: dict
    sample: { "ro_group": [ "alice", "bob" ] }
state:
    description: Membership state that tried to be set.
    returned: success
    type: str
    sample: "present"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import \
    check_input
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    PgMembership,
    connect_to_db,
    ensure_required_libs,
    get_conn_params,
    pg_cursor_args,
    postgres_common_argument_spec,
)

# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        groups=dict(type='list', elements='str', required=True, aliases=['group', 'source_role', 'source_roles']),
        target_roles=dict(type='list', elements='str', required=True, aliases=['target_role', 'user', 'users']),
        fail_on_role=dict(type='bool', default=True),
        state=dict(type='str', default='present', choices=['absent', 'exact', 'present']),
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
        supports_check_mode=True,
    )

    groups = module.params['groups']
    target_roles = module.params['target_roles']
    fail_on_role = module.params['fail_on_role']
    state = module.params['state']
    session_role = module.params['session_role']
    trust_input = module.params['trust_input']
    if not trust_input:
        # Check input for potentially dangerous elements:
        check_input(module, groups, target_roles, session_role)

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params, warn_db_default=False)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=False)
    cursor = db_connection.cursor(**pg_cursor_args)

    ##############
    # Create the object and do main job:

    pg_membership = PgMembership(module, cursor, groups, target_roles, fail_on_role)

    if state == 'present':
        pg_membership.grant()

    elif state == 'exact':
        pg_membership.match()

    elif state == 'absent':
        pg_membership.revoke()

    # Rollback if it's possible and check_mode:
    if module.check_mode:
        db_connection.rollback()
    else:
        db_connection.commit()

    cursor.close()
    db_connection.close()

    # Make return values:
    return_dict = dict(
        changed=pg_membership.changed,
        state=state,
        groups=pg_membership.groups,
        target_roles=pg_membership.target_roles,
        queries=pg_membership.executed_queries,
    )

    if state == 'present':
        return_dict['granted'] = pg_membership.granted
    elif state == 'absent':
        return_dict['revoked'] = pg_membership.revoked
    elif state == 'exact':
        return_dict['granted'] = pg_membership.granted
        return_dict['revoked'] = pg_membership.revoked

    module.exit_json(**return_dict)


if __name__ == '__main__':
    main()
