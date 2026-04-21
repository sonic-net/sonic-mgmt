#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_dsrole
version_added: '1.0.0'
short_description: Configure FlashArray Directory Service Roles
description:
- Set or erase directory services role configurations.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of role
    - If not providied, will be assinged to the same as I(role)
    type: str
    version_added: 1.32.0
  state:
    description:
    - Create or delete directory service role
    type: str
    default: present
    choices: [ absent, present ]
  role:
    description:
    - The directory service role to work on
    type: str
    choices: [ array_admin, ops_admin, readonly, storage_admin ]
  group_base:
    type: str
    description:
    - Specifies where the configured group is located in the directory
      tree. This field consists of Organizational Units (OUs) that combine
      with the base DN attribute and the configured group CNs to complete
      the full Distinguished Name of the groups. The group base should
      specify OU= for each OU and multiple OUs should be separated by commas.
      The order of OUs is important and should get larger in scope from left
      to right.
    - Each OU should not exceed 64 characters in length.
  group:
    type: str
    description:
    - Sets the common Name (CN) of the configured directory service group
      containing users for the FlashBlade. This name should be just the
      Common Name of the group without the CN= specifier.
    - Common Names should not exceed 64 characters in length.
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.39.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete exisitng array_admin directory service role
  purestorage.flasharray.purefa_dsrole:
    role: array_admin
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create observability directory service role with readonly policy
  purestorage.flasharray.purefa_dsrole:
    name: observability
    role: readonly
    group_base: "OU=PureGroups,OU=ReadOnly"
    group: o11y
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update system-defined array_admin directory service role
  purestorage.flasharray.purefa_dsrole:
    role: array_admin
    group_base: "OU=PureGroups,OU=SANManagers"
    group: pureadmins
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update directory service role policy
  purestorage.flasharray.purefa_dsrole:
    name: observability
    role: ops_admin
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

MIN_DSROLE_API_VERSION = "2.30"
POLICY_API_VERSION = "2.36"
CONTEXT_VERSION = "2.42"

HAS_PYPURECLIENT = True
try:
    from pypureclient.flasharray import (
        DirectoryServiceRole,
        DirectoryServiceRolePost,
        Reference,
        ReferenceNoId,
    )
except ImportError:
    HAS_PYPURECLIENT = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)


def update_role(module, array):
    """Update Directory Service Role"""
    changed = False
    api_version = array.get_rest_version()
    # Check for special case of deleting a system-defined role.
    # Here we have to just blank out the group and group_base fields
    if module.params["state"] == "absent":
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.patch_directory_services_roles(
                    names=[module.params["name"]],
                    directory_service_roles=DirectoryServiceRole(
                        group_base="",
                        group="",
                    ),
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_directory_services_roles(
                    names=[module.params["name"]],
                    directory_service_roles=DirectoryServiceRole(
                        group_base="",
                        group="",
                    ),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Deleting system-defined Directory Service Role "
                    "{0} failed.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        module.exit_json(changed=True)

    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        role = list(
            array.get_directory_services_roles(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        role = list(
            array.get_directory_services_roles(names=[module.params["name"]]).items
        )[0]
    if module.params["name"] not in [
        "array_admin",
        "storage_admin",
        "ops_admin",
        "readonly",
    ]:
        if (
            getattr(role, "group_base", None) != module.params["group_base"]
            or getattr(role, "group", None) != module.params["group"]
            or role.role.name != module.params["role"]
        ):
            changed = True
            if not module.check_mode:
                if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                    res = array.patch_directory_services_roles(
                        names=[module.params["name"]],
                        directory_service_roles=DirectoryServiceRole(
                            group_base=module.params["group_base"],
                            group=module.params["group"],
                            role=Reference(name=module.params["role"]),
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.patch_directory_services_roles(
                        names=[module.params["name"]],
                        directory_service_roles=DirectoryServiceRole(
                            group_base=module.params["group_base"],
                            group=module.params["group"],
                            role=Reference(name=module.params["role"]),
                        ),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Update Directory Service Role {0} failed.Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
    else:
        if (
            getattr(role, "group_base", None) != module.params["group_base"]
            or getattr(role, "group", None) != module.params["group"]
        ):
            changed = True
            if not module.check_mode:
                if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                    res = array.patch_directory_services_roles(
                        names=[module.params["name"]],
                        directory_service_roles=DirectoryServiceRole(
                            group_base=module.params["group_base"],
                            group=module.params["group"],
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.patch_directory_services_roles(
                        names=[module.params["name"]],
                        directory_service_roles=DirectoryServiceRole(
                            group_base=module.params["group_base"],
                            group=module.params["group"],
                        ),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Update Directory Service Role {0} failed.Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def delete_role(module, array):
    """Delete Directory Service Role"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.delete_directory_services_roles(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = array.delete_directory_services_roles(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Delete Directory Service Role {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_role(module, array):
    """Create Directory Service Role"""
    changed = False
    api_version = array.get_rest_version()
    if not module.params["group"] == "" or not module.params["group_base"] == "":
        changed = True
        if not module.check_mode:
            if LooseVersion(api_version) >= LooseVersion(POLICY_API_VERSION):
                if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                    res = array.post_directory_services_roles(
                        names=[module.params["name"]],
                        directory_service_roles=DirectoryServiceRolePost(
                            group_base=module.params["group_base"],
                            group=module.params["group"],
                            role=ReferenceNoId(name=module.params["role"]),
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_directory_services_roles(
                        names=[module.params["name"]],
                        directory_service_roles=DirectoryServiceRolePost(
                            group_base=module.params["group_base"],
                            group=module.params["group"],
                            role=ReferenceNoId(name=module.params["role"]),
                        ),
                    )
            else:
                if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                    res = array.post_directory_services_roles(
                        names=[module.params["name"]],
                        directory_service_roles=DirectoryServiceRole(
                            group_base=module.params["group_base"],
                            group=module.params["group"],
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_directory_services_roles(
                        names=[module.params["name"]],
                        directory_service_roles=DirectoryServiceRole(
                            group_base=module.params["group_base"],
                            group=module.params["group"],
                        ),
                    )
            if res.status_code != 200:
                module.fail_json(
                    msg="Create Directory Service Role {0} failed. Error: {1}".format(
                        module.params["role"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str"),
            role=dict(
                type="str",
                choices=["array_admin", "ops_admin", "readonly", "storage_admin"],
            ),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            group_base=dict(type="str"),
            group=dict(type="str"),
            context=dict(type="str", default=""),
        )
    )

    required_if = [["state", "present", ["role"]]]
    required_together = [["group", "group_base"]]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="pypureclient sdk is required for this module")

    state = module.params["state"]
    array = get_array(module)
    if not module.params["name"]:
        module.params["name"] = module.params["role"]
    api_version = array.get_rest_version()
    if LooseVersion(MIN_DSROLE_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="This module requires Purity//FA 6.6.3 and higher. "
            "For older Purity versions please use the ``purefa_dsrole_old`` module"
        )
    role_configured = False
    role = {}
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_directory_services_roles(
            names=[module.params["name"]],
            context_names=[module.params["context"]],
        )
    else:
        res = array.get_directory_services_roles(names=[module.params["name"]])
    if res.status_code == 200:
        role = list(res.items)[0]
    if getattr(role, "group", None) is not None:
        role_configured = True

    if state == "absent" and role_configured:
        if module.params["name"] in [
            "array_admin",
            "storage_admin",
            "ops_admin",
            "readonly",
        ]:
            update_role(module, array)
        else:
            delete_role(module, array)
    elif role_configured and state == "present":
        update_role(module, array)
    elif not role_configured and state == "present":
        # check for system-defined role and update it instead of creating it
        if module.params["name"] in [
            "array_admin",
            "storage_admin",
            "ops_admin",
            "readonly",
        ]:
            update_role(module, array)
        else:
            create_role(module, array)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
