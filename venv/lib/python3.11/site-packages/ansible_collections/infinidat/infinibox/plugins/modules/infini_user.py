#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Manage Infinibox users """

# pylint: disable=invalid-name,use-dict-literal,line-too-long,wrong-import-position

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_user
version_added: 2.9.0
short_description: Create, Delete and Modify a User on Infinibox
description:
    - This module creates, deletes or modifies a user on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  user_name:
    description:
      - The new user's Name. Once a user is created, the user_name may not be
        changed from this module. It may be changed from the UI or from
        infinishell.
    required: false
    type: str
  user_email:
    description:
      - The new user's Email address
    required: false
    type: str
  user_password:
    description:
      - The new user's password
    required: false
    type: str
  user_role:
    description:
      - The user's role
    required: false
    choices: [ "admin", "pool_admin", "read_only" ]
    type: str
  user_enabled:
    description:
      - Specify whether to enable the user
    type: bool
    required: false
    default: true
  user_pool:
    description:
      - Use with role==pool_admin. Specify the new user's pool.
    required: false
    type: str
  state:
    description:
      - Creates/Modifies user when present or removes when absent.
      - Use state 'login' to test user credentials.
      - Use state 'reset' to reset a user password.
    required: false
    default: present
    choices: [ "stat", "reset_password", "present", "absent", "login" ]
    type: str

  user_ldap_group_name:
    description:
      - Name of the LDAP user group
    required: false
    type: str
  user_ldap_group_dn:
    description:
      - DN of the LDAP user group
    required: false
    type: str
  user_ldap_group_ldap:
    description:
      - Name of the LDAP
    required: false
    type: str
  user_ldap_group_role:
    description:
      - Role for the LDAP user group
    choices: [ "admin", "pool_admin", "read_only" ]
    required: false
    type: str
  user_ldap_group_pools:
    description:
      - A list of existing pools managed by the LDAP user group
    default: []
    required: false
    type: list
    elements: str
extends_documentation_fragment:
    - infinibox
'''

EXAMPLES = r'''
- name: Create new user
  infini_user:
    user_name: foo_user
    user_email: foo@example.com
    user_password: secret2
    user_role: pool_admin
    user_enabled: false
    pool: foo_pool
    state: present
    password: secret1
    system: ibox001
'''

# RETURN = r''' # '''


from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    api_wrapper,
    infinibox_argument_spec,
    get_system,
    get_user,
    merge_two_dicts,
)


HAS_INFINISDK = True
try:
    from infinisdk.core.exceptions import APICommandFailed
except ImportError:
    HAS_INFINISDK = False


@api_wrapper
def find_user_ldap_group_id(module):
    """
    Find the ID of the LDAP user group by name
    """
    ldap_id = None
    ldap_name = module.params["user_ldap_group_name"]
    path = f"users?name={ldap_name}&type=eq%3ALdap"
    system = get_system(module)
    api_result = system.api.get(path=path)
    if len(api_result.get_json()['result']) > 0:
        result = api_result.get_json()['result'][0]
        ldap_id = result['id']
    return ldap_id


@api_wrapper
def find_ldap_id(module):
    """
    Find the ID of the LDAP by name
    """
    ldap_id = None
    ldap_name = module.params["user_ldap_group_ldap"]
    path = f"config/ldap?name={ldap_name}&fields=id"
    system = get_system(module)
    api_result = system.api.get(path=path)
    if len(api_result.get_json()['result']) > 0:
        result = api_result.get_json()['result'][0]
        ldap_id = result['id']
    return ldap_id


@api_wrapper
def create_user(module, system):
    """ Create user """
    if not module.check_mode:
        user = system.users.create(name=module.params['user_name'],
                                   password=module.params['user_password'],
                                   email=module.params['user_email'],
                                   enabled=module.params['user_enabled'],
                                   )
        # Set the user's role
        user.update_role(module.params['user_role'])
        if module.params['user_pool']:
            if not module.params['user_role'] == 'pool_admin':
                raise AssertionError("user_pool set, but role is not 'pool_admin'")
            # Add the user to the pool's owners
            pool = system.pools.get(name=module.params['user_pool'])
            add_user_to_pool_owners(user, pool)
    changed = True
    return changed


@api_wrapper
def create_ldap_user_group(module):
    """ Create ldap user group """
    ldap_group_name = module.params['user_ldap_group_name']
    ldap_name = module.params['user_ldap_group_ldap']
    ldap_id = find_ldap_id(module)
    ldap_pools = module.params['user_ldap_group_pools']
    if not ldap_id:
        msg = f'Cannot create LDAP group {ldap_group_name}. Cannot find ID for LDAP name {ldap_name}'
        module.fail_json(msg=msg)
    path = "users"
    system = get_system(module)
    data = {
        "name": ldap_group_name,
        "dn": module.params['user_ldap_group_dn'],
        "ldap_id": ldap_id,
        "role": module.params['user_ldap_group_role'],
        "type": "Ldap",
    }
    try:
        system.api.post(path=path, data=data)
    except APICommandFailed as err:
        if err.status_code in [409]:
            msg = f'Cannot create user_ldap_group_name {ldap_group_name}: {err.message}'
            module.fail_json(msg)
    changed = True

    user = get_user(module, system, ldap_group_name)
    for pool_name in ldap_pools:
        # Pylint is not finding Infinibox.pools but Python does.
        pool = system.pools.get(name=pool_name)  # pylint: disable=no-member
        add_user_to_pool_owners(user, pool)

    return changed


def add_user_to_pool_owners(user, pool):
    """
    Find the current list of pool owners and add user using pool.set_owners().
    set_owners() replaces the current owners with the list of new owners. So,
    get owners, add user, then set owners.  Further, we need to know if the
    owners changed.  Use sets of owners to compare.
    """
    changed = False
    pool_fields = pool.get_fields(from_cache=True, raw_value=True)
    pool_owners = pool_fields.get('owners', [])
    pool_owners_set = set(pool_owners)
    new_pool_owners_set = pool_owners_set.copy()
    new_pool_owners_set.add(user.id)
    if pool_owners_set != new_pool_owners_set:
        pool.set_owners([user])
        changed = True
    return changed


def remove_user_from_pool_owners(user, pool):
    """ Remove user from pool owners """
    changed = False
    pool_fields = pool.get_fields(from_cache=True, raw_value=True)
    pool_owners = pool_fields.get('owners', [])
    try:
        pool_owners.remove(user)
        pool.set_owners(pool_owners)
        changed = True
    except ValueError:
        pass  # User is not a pool owner
    return changed


@api_wrapper
def update_user(module, system, user):
    """ Update user """
    if user is None:
        raise AssertionError(f"Cannot update user {module.params['user_name']}. User not found.")

    changed = False
    fields = user.get_fields(from_cache=True, raw_value=True)
    if fields.get('role') != module.params['user_role'].upper():
        user.update_field('role', module.params['user_role'])
        changed = True
    if fields.get('enabled') != module.params['user_enabled']:
        user.update_field('enabled', module.params['user_enabled'])
        changed = True
    if fields.get('email') != module.params['user_email']:
        user.update_field('email', module.params['user_email'])
        changed = True

    if module.params['user_pool']:
        try:
            pool_name = module.params['user_pool']
            pool = system.pools.get(name=pool_name)
        except Exception as err:  # pylint: disable=broad-exception-caught
            module.fail_json(msg=f'Cannot find pool {pool_name}: {err}')
        if add_user_to_pool_owners(user, pool):
            changed = True
    return changed


def update_ldap_user_group(module):
    """ Update ldap user group by deleting and creating the LDAP user"""
    changed = delete_ldap_user_group(module)
    if not changed:
        module.fail_json(msg='Cannot delete LDAP user {ldap_group_name}. Cannot find ID for LDAP group.')
    create_ldap_user_group(module)
    changed = True
    return changed


@api_wrapper
def reset_user_password(module, user):
    """ Reset user's password """
    if user is None:
        module.fail_json(msg=f'Cannot change user {module.params["user_name"]} password. User not found.')
    user.update_password(module.params['user_password'])


@api_wrapper
def delete_user(module, user):
    """ Delete a user """
    if not user:
        return False

    changed = True
    if not module.check_mode:
        # May raise APICommandFailed if mapped, etc.
        user.delete()
    return changed


@api_wrapper
def delete_ldap_user_group(module):
    """ Delete a ldap user group """
    changed = False
    ldap_group_name = module.params['user_ldap_group_name']
    ldap_group_id = find_user_ldap_group_id(module)
    if not ldap_group_id:
        changed = False
        return changed
    path = f"users/{ldap_group_id}?approved=yes"
    system = get_system(module)
    try:
        system.api.delete(path=path)
        changed = True
    except APICommandFailed as err:
        if err.status_code in [404]:
            changed = False
        else:
            msg = f'An error occurred deleting user_ldap_group_name {ldap_group_name}: {err}'
            module.fail_json(msg)
    return changed


def get_user_ldap_group(module):
    """
    Find the LDAP user group by name
    """
    result = None
    user_ldap_group_name = module.params["user_ldap_group_name"]
    path = f"users?name={user_ldap_group_name}&type=eq%3ALdap"
    system = get_system(module)
    api_result = system.api.get(path=path)
    if len(api_result.get_json()['result']) > 0:
        result = api_result.get_json()['result'][0]
    return result


def get_user_fields(user):
    """ Get user's fields """
    pools = user.get_owned_pools()
    pool_names = [pool.get_field('name') for pool in pools]

    fields = user.get_fields(from_cache=True, raw_value=True)
    field_dict = {
        "dn": fields.get('dn', None),
        "email": fields.get('email', None),
        "enabled": fields.get('enabled', None),
        "id": user.id,
        "ldap_id": fields.get('ldap_id', None),
        "pools": pool_names,
        "role": fields.get('role', None),
        "roles": fields.get('roles', []),
        "type": fields.get('type', None),
    }
    return field_dict


def handle_stat(module):
    """ Handle stat for user or LDAP group user """
    user_name = module.params['user_name']
    user_ldap_group_name = module.params['user_ldap_group_name']
    if user_name:
        system = get_system(module)
        user = get_user(module, system)
        user_name = module.params["user_name"]
        if not user:
            module.fail_json(msg=f'User {user_name} not found')
        field_dict = get_user_fields(user)
        msg = f'User {user_name} stat found'
    elif user_ldap_group_name:
        user = get_user_ldap_group(module)
        if not user:
            module.fail_json(msg=f'user_ldap_group_name {user_ldap_group_name} not found')
        field_dict = get_user_fields(user)
        msg = f'User LDAP group {user_ldap_group_name} stat found'
    else:
        msg = 'Neither user_name nor user_ldap_group_name were provided for state stat'
        module.fail_json(msg)

    result = {
        "changed": False,
        "msg": msg,
    }
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    """ Handle making user present """
    user_name = module.params["user_name"]
    user_ldap_group_name = module.params["user_ldap_group_name"]
    changed = False
    msg = 'Message not set'

    if user_name:
        system = get_system(module)
        user = get_user(module, system)
        if not user:
            changed = create_user(module, system)
            msg = f'User {user_name} created'
        else:
            changed = update_user(module, system, user)
            if changed:
                msg = f'User {user_name} updated'
            else:
                msg = f'User {user_name} update required no changes'
    elif user_ldap_group_name:
        ldap_user = get_user_ldap_group(module)
        if not ldap_user:
            changed = create_ldap_user_group(module)
            msg = f'LDAP user group {user_ldap_group_name} created'
        else:
            changed = update_ldap_user_group(module)
            if changed:
                msg = f'LDAP user group {user_ldap_group_name} updated by deleting and recreating with updated parameters'
            else:
                msg = f'LDAP user group {user_ldap_group_name} update not required - no changes'
    else:
        msg = 'Neither user_name nor user_ldap_group_name were provided'
        module.fail_json(msg)

    module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    """ Handle making user absent """
    user_name = module.params['user_name']
    user_ldap_group_name = module.params['user_ldap_group_name']
    if user_name:
        system = get_system(module)
        user = get_user(module, system)
        user_name = module.params["user_name"]
        if not user:
            changed = False
            msg = f"User {user_name} already absent"
        else:
            changed = delete_user(module, user)
            msg = f"User {user_name} removed"
        module.exit_json(changed=changed, msg=msg)
    elif user_ldap_group_name:
        changed = delete_ldap_user_group(module)
        if changed:
            msg = f"LDAP group user {user_ldap_group_name} removed"
        else:
            msg = f"LDAP group user {user_ldap_group_name} already absent"
        module.exit_json(changed=changed, msg=msg)
    else:
        msg = 'Neither user_name nor user_ldap_group_name were provided for state absent'
        module.fail_json(msg)


def handle_reset_password(module):
    """ Reset user password """
    system = get_system(module)
    user = get_user(module, system)
    user_name = module.params["user_name"]
    if not user:
        msg = f'Cannot change password. User {user_name} not found'
        module.fail_json(msg=msg)
    else:
        reset_user_password(module, user)
        msg = f'User {user_name} password changed'
        module.exit_json(changed=True, msg=msg)


def handle_login(module):
    """ Test user credentials by logging in """
    system = get_system(module)
    user_name = module.params["user_name"]
    user_password = module.params['user_password']
    path = "users/login"
    data = {
        "username": user_name,
        "password": user_password,
    }
    try:
        login = system.api.post(path=path, data=data)
    except APICommandFailed:
        msg = f'User {user_name} failed to login'
        module.fail_json(msg=msg)
    if login.status_code == 200:
        msg = f'User {user_name} successfully logged in'
        module.exit_json(changed=False, msg=msg)
    else:
        msg = f'User {user_name} failed to login with status code: {login.status_code}'
        module.fail_json(msg=msg)


def execute_state(module):
    """ Find state and handle it """
    state = module.params['state']
    try:
        if state == 'stat':
            handle_stat(module)
        elif state == 'present':
            handle_present(module)
        elif state == 'absent':
            handle_absent(module)
        elif state == 'reset_password':
            handle_reset_password(module)
        elif state == 'login':
            handle_login(module)
        else:
            module.fail_json(msg=f'Internal handler error. Invalid state: {state}')
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):  # pylint: disable=too-many-branches
    """ Check option logic """
    state = module.params['state']
    user_name = module.params['user_name']
    user_role = module.params['user_role']
    user_pool = module.params['user_pool']
    user_ldap_group_name = module.params['user_ldap_group_name']
    user_ldap_group_role = module.params['user_ldap_group_role']
    if state == 'present':
        if user_role == 'pool_admin' and not user_pool:
            module.fail_json(msg='user_role "pool_admin" requires a user_pool to be provided')
        if user_role != 'pool_admin' and user_pool:
            module.fail_json(msg='Only user_role "pool_admin" should have a user_pool provided')

        if not user_name and not user_ldap_group_name:
            msg = 'For state "present", option user_name or user_ldap_group_name is required'
            module.fail_json(msg=msg)

        if user_name and user_ldap_group_name:
            msg = 'For state "present", option user_name and user_ldap_group_name cannot both be provided'
            module.fail_json(msg=msg)

        if user_name:
            required_user_params = [
                'user_email', 'user_password', 'user_role',
            ]
            for required_param in required_user_params:
                param = module.params[required_param]
                if param is None:
                    msg = f"For state 'present', option {required_param} is required with option user_name"
                    module.fail_json(msg=msg)

        if user_ldap_group_name:
            required_user_ldap_params = [
                'user_ldap_group_dn', 'user_ldap_group_ldap', 'user_ldap_group_role',
            ]
            for required_param in required_user_ldap_params:
                param = module.params[required_param]
                if not param:
                    msg = f'For state "present", option {required_param} is required with option user_ldap_group_name'
                    module.fail_json(msg=msg)
            if user_ldap_group_role == 'pool_admin':
                user_ldap_group_pools = module.params['user_ldap_group_pools']
                if not user_ldap_group_pools:
                    msg = "For state 'present' and user_ldap_group_role 'pool_admin', user_ldap_group_pool must specify one or more pools"
                    module.fail_json(msg=msg)

    elif state in ['reset_password', 'login']:
        if not module.params['user_name'] or not module.params['user_password']:
            msg = f"For state '{state}', user_name and user_password are both required"
            module.fail_json(msg=msg)


def main():
    """ main """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            user_name=dict(required=False),
            user_email=dict(required=False, default=None),
            user_password=dict(required=False, no_log=True, default=None),
            user_role=dict(required=False, choices=['admin', 'pool_admin', 'read_only'], default=None),
            user_enabled=dict(required=False, type='bool', default=True),
            user_pool=dict(required=False, default=None),
            user_ldap_group_name=dict(required=False, default=None),
            user_ldap_group_dn=dict(required=False, default=None),
            user_ldap_group_ldap=dict(required=False, default=None),
            user_ldap_group_role=dict(required=False, choices=['admin', 'pool_admin', 'read_only'], default=None),
            user_ldap_group_pools=dict(required=False, type='list', elements='str', default=[]),
            state=dict(default='present', choices=['stat', 'reset_password', 'present', 'absent', 'login']),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib('infinisdk'))

    check_options(module)
    execute_state(module)


if __name__ == '__main__':
    main()
