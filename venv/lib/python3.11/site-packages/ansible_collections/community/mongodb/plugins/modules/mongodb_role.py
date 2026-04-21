#!/usr/bin/python

# (c) 2022, Rhys Campbell <rhyscampbell@bluewin.ch>

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: mongodb_role
short_description: Adds or removes a role from a MongoDB database
description:
    - Adds or removes a role from a MongoDB database.
    - For further information on the required format for \
      the privileges, authenticationRestriction or roles \
      parameters, see the MongoDB Documentation https://www.mongodb.com/docs/manual/reference/command/createRole/
version_added: "1.5.0"

extends_documentation_fragment:
  - community.mongodb.login_options
  - community.mongodb.ssl_options

options:
  replica_set:
    description:
      - Replica set to connect to (automatically connects to primary for writes).
    type: str
  database:
    description:
      - The name of the database to add/remove the role from.
    required: true
    type: str
    aliases: [db]
  name:
    description:
      - The name of the role to add or remove.
    required: true
    aliases: [user]
    type: str
  privileges:
    type: list
    elements: raw
    description:
      - >
        The privileges to grant the role. A privilege consists of a resource
        and permitted actions.
    default: []
  authenticationRestrictions:
    type: list
    elements: raw
    description:
      - >
          The authentication restrictions the server enforces on the role.
          Specifies a list of IP addresses and CIDR ranges users granted
          this role are allowed to connect to and/or which they can connect from.
          Provide a list of dictionaries with the following
          fields: clientSource (list), serverAddress (list).
          Provide an empty list if you don't want to use the field.
    default: []
  roles:
    type: list
    elements: raw
    description:
      - >
          The database user roles should be provided as a dictionary with the db and role keys.
    default: []
  state:
    description:
      - The database user state.
    default: present
    choices: [absent, present]
    type: str
  debug:
    description:
      - Enable extra debugging output.
    default: false
    type: bool
notes:
    - Requires the pymongo Python package on the remote host, version 4+. This
      can be installed using pip or the OS package manager. Newer mongo server versions require newer
      pymongo versions. @see https://www.mongodb.com/docs/languages/python/pymongo-driver/current/compatibility/
requirements:
  - "pymongo"
author:
    - "Rhys Campbell (@rhysmeister)"
'''

EXAMPLES = '''
- name: Create sales role
  community.mongodb.mongodb_role:
    name: sales
    database: salesdb
    privileges:
      - resource:
          db: salesdb
          collection: ""
        actions:
          - find
    state: present

- name: Create ClusterAdmin Role
  community.mongodb.mongodb_role:
    name: myClusterwideAdmin
    database: admin
    privileges:
      - resource:
          cluster: true
        actions:
          - addShard
      - resource:
          db: config
          collection: ""
        actions:
          - find
          - update
          - insert
          - remove
      - resource:
          db: "users"
          collection: "usersCollection"
        actions:
          - update
          - insert
          - remove
      - resource:
          db: ""
          collection: ""
        actions:
          - find
    roles:
      - role: "read"
        db: "admin"
    state: present

- name: Create ClusterAdmin Role with a login only from 127.0.0.1 restriction
  community.mongodb.mongodb_role:
    name: myClusterwideAdmin
    database: admin
    privileges:
      - resource:
          cluster: true
        actions:
          - addShard
      - resource:
          db: config
          collection: ""
        actions:
          - find
          - update
          - insert
      - resource:
          db: "users"
          collection: "usersCollection"
        actions:
          - update
          - insert
          - remove
      - resource:
          db: ""
          collection: ""
        actions:
          - find
    roles:
      - role: "read"
        db: "admin"
      - role: "read"
        db: "mynewdb"
    authenticationRestrictions:
      - clientSource:
          - "127.0.0.1"
        serverAddress: []
    state: present

- name: Delete sales role
  community.mongodb.mongodb_role:
    name: sales
    database: "salesdb"
    state: absent

- name: Delete myClusterwideAdmin role
  community.mongodb.mongodb_role:
    name: myClusterwideAdmin
    database: admin
    state: absent
'''

RETURN = '''
user:
    description: The name of the role to add or remove.
    returned: success
    type: str
'''

import traceback


from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils._text import to_native
from ansible_collections.community.mongodb.plugins.module_utils.mongodb_common import (
    missing_required_lib,
    mongodb_common_argument_spec,
    mongo_auth,
    PYMONGO_IMP_ERR,
    pymongo_found,
    get_mongodb_client,
)


def role_find(client, role, db_name):
    """Check if the role exists.

    Args:
        client (cursor): Mongodb cursor on admin database.
        user (str): Role to check.
        db_name (str): Role's database.

    Returns:
        dict: when role exists, False otherwise.
    """
    try:
        mongo_role = None
        rolesDoc = {
            'rolesInfo': 1,
            'showAuthenticationRestrictions': True,
            'showPrivileges': True
        }
        for mongo_role in client[db_name].command(rolesDoc)['roles']:
            if mongo_role['role'] == role:
                # NOTE: there is no 'db' field in mongo 2.4.
                if 'db' not in mongo_role:
                    return mongo_role
                # Workaround to make the condition works with AWS DocumentDB,
                # since all users are in the admin database.
                if mongo_role["db"] in [db_name, "admin"]:
                    return mongo_role
    except Exception as excep:
        if hasattr(excep, 'code') and excep.code == 31:  # 31=RoleNotFound
            pass  # Allow return False
        else:
            raise
    return False


def role_add(client, db_name, role, privileges, roles, authenticationRestrictions):
    db = client[db_name]

    try:
        exists = role_find(client, role, db_name)
    except Exception as excep:
        # probably not needed for role create... to clarify
        # We get this exception: "not authorized on admin to execute command"
        # when auth is enabled on a new instance. The localhost exception should
        # allow us to create the first user. If the localhost exception does not apply,
        # then user creation will also fail with unauthorized. So, ignore Unauthorized here.
        if hasattr(excep, 'code') and excep.code == 13:  # 13=Unauthorized
            exists = False
        else:
            raise

    if exists:
        role_add_db_command = 'updateRole'
    else:
        role_add_db_command = 'createRole'

    role_dict = {}

    role_dict["privileges"] = privileges
    role_dict["roles"] = roles
    role_dict["authenticationRestrictions"] = authenticationRestrictions
    db.command(role_add_db_command, role, **role_dict)


def role_remove(module, client, db_name, role):
    exists = role_find(client, role, db_name)
    if exists:
        if module.check_mode:
            module.exit_json(changed=True, role=role)
        db = client[db_name]
        db.command("dropRole", role)
    else:
        module.exit_json(changed=False, role=role)


def check_if_role_changed(client, role, db_name, privileges, authenticationRestrictions, roles):
    role_dict = role_find(client, role, db_name)
    changed = False
    if role_dict:
        reformat_authenticationRestrictions = []
        if 'authenticationRestrictions' in role_dict:
            for item in role_dict['authenticationRestrictions']:
                reformat_authenticationRestrictions.append(item[0])  # seems to be a list of lists of dict, we want a list of dicts
        if ('privileges' in role_dict and
                [{'resource': d['resource'], 'actions': sorted(d['actions'])} for d in role_dict['privileges']] !=
                [{'resource': d['resource'], 'actions': sorted(d['actions'])} for d in privileges] or
                'privileges' not in role_dict and privileges != []):
            changed = True
        elif ('roles' in role_dict and
                sorted(role_dict['roles'], key=lambda x: (x["db"], x["role"])) !=
                sorted(roles, key=lambda x: (x["db"], x["role"])) or
                'roles' not in role_dict and roles != []):
            changed = True
        elif ('authenticationRestrictions' in role_dict and
                sorted(reformat_authenticationRestrictions, key=lambda x: (x.get('clientSource', ''), x.get('serverAddress', ''))) !=
                sorted(authenticationRestrictions, key=lambda x: (x.get('clientSource', ''), x.get('serverAddress', ''))) or
                'authenticationRestrictions' not in role_dict and authenticationRestrictions != []):
            changed = True
    else:
        raise Exception("Role not found")  # TODO replace with proper exception
    return changed


# =========================================
# Module execution.
#

def main():
    argument_spec = mongodb_common_argument_spec()
    argument_spec.update(
        replica_set=dict(default=None),
        database=dict(required=True, aliases=['db']),
        name=dict(required=True, aliases=['user']),
        privileges=dict(default=[], type='list', elements='raw'),
        authenticationRestrictions=dict(default=[], type='list', elements='raw'),
        roles=dict(default=[], type='list', elements='raw'),
        state=dict(default='present', choices=['absent', 'present']),
        debug=dict(type='bool', default=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if not pymongo_found:
        module.fail_json(msg=missing_required_lib('pymongo'),
                         exception=PYMONGO_IMP_ERR)

    try:
        directConnection = False
        if module.params['replica_set'] is None:
            directConnection = True
        client = get_mongodb_client(module, directConnection=directConnection)
        client = mongo_auth(module, client, directConnection=directConnection)
    except Exception as e:
        module.fail_json(msg='Unable to connect to database: %s' % to_native(e))

    changed = None
    role = state = module.params['name']
    state = module.params['state']
    db_name = module.params['database']
    privileges = module.params['privileges']
    roles = module.params['roles']
    authenticationRestrictions = module.params['authenticationRestrictions']
    debug = module.params['debug']
    # TODO _ Functions use a different param order... make consistent
    try:
        if state == 'present':
            if role_find(client, role, db_name) is False:
                if module.check_mode is False:
                    role_add(client, db_name, role, privileges, roles, authenticationRestrictions)
                changed = True
            else:
                if check_if_role_changed(client, role, db_name, privileges, authenticationRestrictions, roles):
                    if module.check_mode is False:
                        role_add(client, db_name, role, privileges, roles, authenticationRestrictions)
                    changed = True
                else:
                    changed = False
        elif state == 'absent':
            if role_find(client, role, db_name):
                if module.check_mode is False:
                    role_remove(module, client, db_name, role)
                changed = True
            else:
                changed = False
        module.exit_json(changed=changed, role=role)
    except Exception as e:
        if debug:
            module.fail_json(msg=str(e), traceback=traceback.format_exc())
        else:
            module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
