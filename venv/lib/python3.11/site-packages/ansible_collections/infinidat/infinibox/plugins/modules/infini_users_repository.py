#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-list-literal,use-dict-literal,line-too-long,wrong-import-position,multiple-statements

"""This module creates, deletes or modifies repositories of users that can log on to an Infinibox."""

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: infini_users_repository
version_added: 2.13.0
short_description:  Create, Delete or Modify respositories of users that can log on to an Infinibox
description:
    - This module creates, deletes or modifies respositories of users that can log on to an Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  ad_auto_discover_servers:
    description:
      - AD auto discover servers
    type: bool
    choices: [true, false]
    required: false
    default: true
  ad_domain_name:
    description:
      - AD domain name
    type: str
    required: false
  bind_password:
    description:
      - The bind user password
    type: str
    required: false
  bind_username:
    description:
      - The bind username
    type: str
    required: false
  servers:
    description:
      - A list of LDAP servers. For an empty list, use [].
    required: false
    type: list
    elements: str
    default: []
  name:
    description:
      - Name of repository
    type: str
    required: true
  ldap_port:
    description:
      - LDAP or AD port to use
    type: int
    required: false
    default: 636
  ldap_servers:
    description:
      - List of LDAP or AD servers
    type: list
    elements: str
    required: false
    default: []
  repository_type:
    description:
      - The type of repository
    choices: ["ActiveDirectory", "LDAP"]
    type: str
    required: False
  schema_group_memberof_attribute:
    description:
      - Schema group memberof attribute
    type: str
    required: false
  schema_group_name_attribute:
    description:
      - Schema group name attribute
    type: str
    required: false
  schema_groups_basedn:
    description:
      - Schema groups base DN
    type: str
    required: false
  schema_group_class:
    description:
      - Schema group class
    type: str
    required: false
  schema_users_basedn:
    description:
      - Schema user base DN
    type: str
    required: false
  schema_user_class:
    description:
      - Schema user class
    type: str
    required: false
  schema_username_attribute:
    description:
      - Schema username attribute
    type: str
    required: false
  state:
    description:
      - Creates/Modifies users repositories when present or removes when absent.
      - When getting the stats for a users repository, the module will test
        connectivity to the repository and report the result in 'test_ok' as true or false.
    required: false
    type: str
    default: present
    choices: [ "stat", "present", "absent" ]
  use_ldaps:
    description:
      - Use SSL (LDAPS)
    type: bool
    choices: ["true", "false"]
    default: true

extends_documentation_fragment:
    - infinibox
"""

EXAMPLES = r"""
- name: Create AD
  infini_users_repository:
    name: PSUS_ANSIBLE_ad
    bind_password: tuFrAxahuYe4
    bind_username: conldap
    ad_domain_name: infinidat.com
    repository_type: ActiveDirectory
    schema_group_class: group
    schema_group_memberof_attribute: memberof
    schema_group_name_attribute: cn
    schema_groups_basedn:
    schema_user_class: user
    schema_username_attribute: sAMAccountName
    state: present
    system: 172.20.67.167
    user: dohlemacher
    password: 123456

- name: Stat AD
  infini_users_repository:
    name: PSUS_ANSIBLE_ad
    state: stat
    user: admin
    password: secret
    system: ibox001

- name: Remove AD
  infini_users_repository:
    name: PSUS_ANSIBLE_ad
    state: absent
    user: admin
    password: secret
    system: ibox001
"""

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    api_wrapper,
    get_system,
    infinibox_argument_spec,
)

HAS_INFINISDK = True
try:
    from infinisdk.core.exceptions import APICommandFailed
except ImportError:
    HAS_INFINISDK = False


@api_wrapper
def get_users_repository(module, disable_fail=False):
    """
    Find and return users repository information
    Use disable_fail when we are looking for an user repository
    and it may or may not exist and neither case is an error.
    """
    system = get_system(module)
    name = module.params["name"]

    path = f"config/ldap?name={name}"
    repo = system.api.get(path=path)

    if repo:
        result = repo.get_result()
        if not disable_fail and not result:
            msg = f"Users repository {name} not found. Cannot stat."
            module.fail_json(msg=msg)
        return result

    if not disable_fail:
        msg = f"Users repository {name} not found. Cannot stat."
        module.fail_json(msg=msg)

    return None


@api_wrapper
def test_users_repository(module, repository_id, disable_fail=False):
    """
    Find and return users repository information
    Use disable_fail when we are looking for an user repository
    and it may or may not exist and neither case is an error.
    """
    system = get_system(module)
    name = module.params['name']
    try:
        path = f"config/ldap/{repository_id}/test"
        result = system.api.post(path=path)
    except APICommandFailed as err:
        if disable_fail:
            return False
        msg = f"Users repository {name} testing failed: {str(err)}"
        module.fail_json(msg=msg)
    if result.response.status_code in [200]:
        return True
    return False


def create_post_data(module):
    """Create data dict for post rest calls"""
    name = module.params["name"]
    repo_type = module.params["repository_type"]
    # search_order
    schema_definition = {
        "group_class": module.params["schema_group_class"],
        "group_memberof_attribute": module.params["schema_group_memberof_attribute"],
        "group_name_attribute": module.params["schema_group_name_attribute"],
        "groups_basedn": module.params["schema_groups_basedn"],
        "user_class": module.params["schema_user_class"],
        "username_attribute": module.params["schema_username_attribute"],
        "users_basedn": module.params["schema_users_basedn"],
    }

    # Create json data
    data = {
        "bind_password": module.params["bind_password"],
        "bind_username": module.params["bind_username"],
        "ldap_port": module.params["ldap_port"],
        "name": name,
        "repository_type": repo_type,
        "schema_definition": schema_definition,
        "use_ldaps": module.params["use_ldaps"],
    }

    # Add type specific fields to data dict
    if repo_type == "ActiveDirectory":
        data["domain_name"] = module.params["ad_domain_name"]
        data["servers"] = []
    else:  # LDAP
        data["domain_name"]: None
        data["servers"] = module.params["ldap_servers"]
    return data


@api_wrapper
def post_users_repository(module):
    """
    Create or update users LDAP or AD repo. The changed variable is found elsewhere.
    Variable 'changed' not returned by design
    """
    system = get_system(module)
    name = module.params["name"]
    data = create_post_data(module)
    path = "config/ldap"
    try:
        system.api.post(path=path, data=data)
    except APICommandFailed as err:
        if err.error_code == "LDAP_NAME_CONFLICT":
            msg = f"Users repository {name} conflicts."
            module.fail_json(msg=msg)
        elif err.error_code == "LDAP_BAD_CREDENTIALS":
            msg = f"Cannot create users repository {name} due to incorrect LDAP credentials: {err}"
            module.fail_json(msg=msg)
        else:
            msg = f"Cannot create users repository {name}: {err}"
            module.fail_json(msg=msg)


@api_wrapper
def delete_users_repository(module):
    """Delete repo."""
    system = get_system(module)
    name = module.params['name']
    changed = False
    if not module.check_mode:
        repo = get_users_repository(module, disable_fail=True)
        if repo and len(repo) == 1:
            path = f"config/ldap/{repo[0]['id']}"
            try:
                system.api.delete(path=path)
                changed = True
            except APICommandFailed as err:
                if err.status_code != 404:
                    msg = f"Deletion of users repository {name} failed: {str(err)}"
                    module.fail_json(msg=msg)
    return changed


def handle_stat(module):
    """Return users repository stat"""
    name = module.params['name']
    repos = get_users_repository(module)

    if len(repos) != 1:
        msg = f"Users repository {name} not found in repository list {repos}. Cannot stat."
        module.fail_json(msg=msg)

    result = repos[0]
    repository_id = result.pop("id")
    result["msg"] = f"Stats for user repository {name}"
    result["repository_id"] = repository_id  # Rename id to repository_id
    result["test_ok"] = test_users_repository(module, repository_id=repository_id, disable_fail=True)
    result["changed"] = False
    module.exit_json(**result)


@api_wrapper
def is_existing_users_repo_equal_to_desired(module):  # pylint: disable=too-many-return-statements,multiple-statements
    """ Compare two user user repositories. Return a bool. """
    newdata = create_post_data(module)
    olddata = get_users_repository(module, disable_fail=True)[0]
    if not olddata:
        return False
    if olddata['bind_username'] != newdata['bind_username']:
        return False
    if olddata['repository_type'] != newdata['repository_type']:
        return False
    if olddata['domain_name'] != newdata['domain_name']:
        return False
    if olddata['ldap_port'] != newdata['ldap_port']:
        return False
    if olddata['name'] != newdata['name']:
        return False
    if olddata['schema_definition'] != newdata['schema_definition']:
        return False
    if olddata['servers'] != newdata['servers']:
        return False
    if olddata['use_ldaps'] != newdata['use_ldaps']:
        return False
    return True


def handle_present(module):
    """Make users repository present"""
    name = module.params['name']
    changed = False
    msg = ""
    if not module.check_mode:
        old_users_repo = None
        old_users_repo_result = get_users_repository(module, disable_fail=True)
        if old_users_repo_result:
            old_users_repo = old_users_repo_result[0]
            if is_existing_users_repo_equal_to_desired(module):
                msg = f"Users repository {name} already exists. No changes required."
                module.exit_json(changed=changed, msg=msg)
            else:
                msg = f"Users repository {name} is being recreated with new settings. "
                delete_users_repository(module)
                old_users_repo = None
                changed = True

        post_users_repository(module)

        new_users_repo = get_users_repository(module)
        changed = new_users_repo != old_users_repo
        if changed:
            if old_users_repo:
                msg = f"{msg}Users repository {name} updated"
            else:
                msg = f"{msg}Users repository {name} created"
        else:
            msg = f"Users repository {name} unchanged since the value is the same as the existing users repository"
    else:
        msg = f"Users repository {name} unchanged due to check_mode"
    module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    """Make users repository absent"""
    name = module.params['name']
    msg = f"Users repository {name} unchanged"
    changed = False
    if not module.check_mode:
        changed = delete_users_repository(module)
        if changed:
            msg = f"Users repository {name} removed"
        else:
            msg = f"Users repository {name} did not exist so removal was unnecessary"
    module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    """Determine which state function to execute and do so"""
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "present":
            handle_present(module)
        elif state == "absent":
            handle_absent(module)
        else:
            module.fail_json(msg=f"Internal handler error. Invalid state: {state}")
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):
    """Verify module options are sane"""
    # ad_domain_name = module.params["ad_domain_name"]
    # bind_password = module.params["bind_password"]
    # bind_username = module.params["bind_username"]
    # ad_domain_name = module.params["ad_domain_name"]
    # ldap_servers = module.params["ldap_servers"]
    name = module.params["name"]
    # ldap_port = module.params["ldap_port"]
    repository_type = module.params["repository_type"]
    # schema_group_memberof_attribute = module.params["schema_group_memberof_attribute"]
    # schema_group_name_attribute = module.params["schema_group_name_attribute"]
    # schema_groups_basedn = module.params["schema_groups_basedn"]
    # schema_user_class = module.params["schema_user_class"]
    # schema_username_attribute = module.params["schema_username_attribute"]
    # schema_users_basedn = module.params["schema_users_basedn"]
    state = module.params["state"]

    if state == "stat":
        pass
    elif state == "present":
        if repository_type:
            common_params = ["bind_password", "bind_username", "schema_group_class",
                             "schema_group_memberof_attribute", "schema_group_name_attribute",
                             "schema_user_class", "schema_username_attribute",]
            if repository_type == "LDAP":  # Creating an LDAP
                req_params = common_params
                missing_params = [param for param in req_params if not is_set_in_params(module, param)]
                if missing_params:
                    msg = f"Cannot create a new LDAP repository named {name} without providing required parameters: {missing_params}"
                    module.fail_json(msg=msg)

                disallowed_params = ["ad_domain_name", "ad_auto_discover_servers"]
                error_params = [param for param in disallowed_params if is_set_in_params(module, param)]
                if error_params:
                    msg = f"Cannot create a new LDAP repository named {name} when providing disallowed parameters: {error_params}"
                    module.fail_json(msg=msg)
            elif repository_type == "ActiveDirectory":
                req_params = common_params
                missing_params = [param for param in req_params if not is_set_in_params(module, param)]
                if missing_params:
                    msg = f"Cannot create a new LDAP repository named {name} without providing required parameters: {missing_params}"
                    module.fail_json(msg=msg)

                disallowed_params = ["ldap_servers"]
                error_params = [param for param in disallowed_params if is_set_in_params(module, param)]
                if error_params:
                    msg = f"Cannot create a new LDAP repository named {name} when providing disallowed parameters: {error_params}"
                    module.fail_json(msg=msg)
            else:
                msg = f"Unsupported respository type: {repository_type}"
                module.fail_json(msg=msg)
        else:
            msg = "Cannot create a new users repository without providing a repository_type"
            module.fail_json(msg=msg)
    elif state == "absent":
        pass
    else:
        module.fail_json(f"Invalid state '{state}' provided")


def is_set_in_params(module, key):
    """A utility function to test if a module param key is set to a truthy value.
    Useful in list comprehensions."""
    is_set = False
    try:
        if module.params[key]:
            is_set = True
    except KeyError:
        pass
    return is_set


def main():
    """Main module function"""
    argument_spec = infinibox_argument_spec()

    argument_spec.update(
        {
            "ad_auto_discover_servers": {"required": False, "choices": [True, False], "type": "bool", "default": True},
            "ad_domain_name": {"required": False, "default": None},
            "bind_password": {"required": False, "default": None, "no_log": True},
            "bind_username": {"required": False, "default": None},
            "ldap_servers": {"required": False, "default": [], "type": "list", "elements": "str"},
            "name": {"required": True},
            "ldap_port": {"required": False, "type": "int", "default": 636},
            "repository_type": {"required": False, "choices": ["LDAP", "ActiveDirectory"], "default": None},
            "schema_group_class": {"required": False, "default": None},
            "schema_group_memberof_attribute": {"required": False, "default": None},
            "schema_group_name_attribute": {"required": False, "default": None},
            "schema_groups_basedn": {"required": False, "default": None},
            "schema_user_class": {"required": False, "default": None},
            "schema_username_attribute": {"required": False, "default": None},
            "schema_users_basedn": {"required": False, "default": None},
            "servers": {"required": False, "default": [], "type": "list", "elements": "str"},
            "state": {"default": "present", "choices": ["stat", "present", "absent"]},
            "use_ldaps": {"required": False, "choices": [True, False], "type": "bool", "default": True},
        }
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib("infinisdk"))

    check_options(module)
    execute_state(module)


if __name__ == "__main__":
    main()
