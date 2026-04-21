#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
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
module: purefa_default_protection
version_added: '1.14.0'
short_description:  Manage SafeMode default protection for a Pure Storage FlashArray
description:
- Configure automatic protection group membership for new volumes and copied volumes
  array wide, or at the pod level.
- Requires a minimum of Purity 6.3.4
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  scope:
    description:
    - The scope of the default protection group
    type: str
    choices: [ array, pod ]
    default: array
  name:
    description:
    - The name of the protection group to assign or remove as default for the scope.
    - If I(scope) is I(pod) only the short-name for the pod protection group is needed.
      See examples
    elements: str
    type: list
    required: true
  pod:
    description:
    - name of the pod to apply the default protection to.
    - Only required for I(scope) is I(pod)
    type: str
  state:
    description:
    - Define whether to add or delete the protection group to the default list
    default: present
    choices: [ absent, present ]
    type: str
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.37.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Add protection group foo::bar as default for pod foo
  purestorage.flasharray.purefa_default_protection:
    name: bar
    pod: foo
    scope: pod
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Add protection group foo as default for array
  purestorage.flasharray.purefa_default_protection:
    name: foo
    scope: array
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Remove protection group foo from array default protection
  purestorage.flasharray.purefa_default_protection:
    name: foo
    scope: array
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Clear default protection for the array
  purestorage.flasharray.purefa_default_protection:
    name: ''
    scope: array
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

DEFAULT_API_VERSION = "2.16"
CONTEXT_API_VERSION = "2.38"


def _get_pod(module, array):
    """Return Pod or None"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_pods(
            names=[module.params["pod"]],
            context_names=[module.params["context"]],
        )
    else:
        res = array.get_pods(names=[module.params["pod"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def _get_pg(module, array, pod):
    """Return Protection Group or None"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_protection_groups(
            names=[pod],
            context_names=[module.params["context"]],
        )
    else:
        res = array.get_protection_groups(names=[pod])
    if res.staus_code == 200:
        return list(res.items)[0]
    return None


def create_default(module, array):
    """Create Default Protection"""
    api_version = array.get_rest_version()
    changed = True
    pg_list = []
    if not module.check_mode:
        for pgroup in range(0, len(module.params["name"])):
            if module.params["scope"] == "array":
                pg_list.append(
                    flasharray.DefaultProtectionReference(
                        name=module.params["name"][pgroup], type="protection_group"
                    )
                )
            else:
                pg_list.append(
                    flasharray.DefaultProtectionReference(
                        name=module.params["pod"]
                        + "::"
                        + module.params["name"][pgroup],
                        type="protection_group",
                    )
                )
        if module.params["scope"] == "array":
            protection = flasharray.ContainerDefaultProtection(
                name="", type="", default_protections=pg_list
            )
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_container_default_protections(
                    names=[""],
                    container_default_protection=protection,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_container_default_protections(
                    names=[""], container_default_protection=protection
                )
        else:
            protection = flasharray.ContainerDefaultProtection(
                name=module.params["pod"], type="pod", default_protections=pg_list
            )
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_container_default_protections(
                    names=[module.params["pod"]],
                    container_default_protection=protection,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_container_default_protections(
                    names=[module.params["pod"]],
                    container_default_protection=protection,
                )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to set default protection. Error: {0}".format(
                    res.errors[0].message
                )
            )

    module.exit_json(changed=changed)


def update_default(module, array, current_default):
    """Update Default Protection"""
    api_version = array.get_rest_version()
    changed = False
    current = []
    for default in range(0, len(current_default)):
        if module.params["scope"] == "array":
            current.append(current_default[default].name)
        else:
            current.append(current_default[default].name.split(":")[-1])
    pg_list = []
    if module.params["state"] == "present":
        if current:
            new_list = sorted(list(set(module.params["name"] + current)))
        else:
            new_list = sorted(list(set(module.params["name"])))
    elif current:
        new_list = sorted(list(set(current).difference(module.params["name"])))
    else:
        new_list = []
    if not new_list:
        delete_default(module, array)
    elif new_list == current:
        changed = False
    else:
        changed = True
        if not module.check_mode:
            for pgroup in range(0, len(new_list)):
                if module.params["scope"] == "array":
                    pg_list.append(
                        flasharray.DefaultProtectionReference(
                            name=new_list[pgroup], type="protection_group"
                        )
                    )
                else:
                    pg_list.append(
                        flasharray.DefaultProtectionReference(
                            name=module.params["pod"] + "::" + new_list[pgroup],
                            type="protection_group",
                        )
                    )
                if module.params["scope"] == "array":
                    protection = flasharray.ContainerDefaultProtection(
                        name="", type="", default_protections=pg_list
                    )
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        res = array.patch_container_default_protections(
                            names=[""],
                            container_default_protection=protection,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = array.patch_container_default_protections(
                            names=[""], container_default_protection=protection
                        )
                else:
                    protection = flasharray.ContainerDefaultProtection(
                        name=module.params["pod"],
                        type="pod",
                        default_protections=pg_list,
                    )
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        res = array.patch_container_default_protections(
                            names=[module.params["pod"]],
                            container_default_protection=protection,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = array.patch_container_default_protections(
                            names=[module.params["pod"]],
                            container_default_protection=protection,
                        )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update default protection. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def delete_default(module, array):
    """Delete Default Protection"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        if module.params["scope"] == "array":
            protection = flasharray.ContainerDefaultProtection(
                name="", type="", default_protections=[]
            )
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_container_default_protections(
                    names=[""],
                    container_default_protection=protection,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_container_default_protections(
                    names=[""], container_default_protection=protection
                )
        else:
            protection = flasharray.ContainerDefaultProtection(
                name=module.params["pod"], type="pod", default_protections=[]
            )
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_container_default_protections(
                    names=[module.params["pod"]],
                    container_default_protection=[],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_container_default_protections(
                    names=[module.params["pod"]], container_default_protection=[]
                )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete default protection. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="list", elements="str", required=True),
            pod=dict(type="str"),
            scope=dict(type="str", default="array", choices=["array", "pod"]),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            context=dict(type="str", default=""),
        )
    )

    required_if = [["scope", "pod", ["pod"]]]
    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )
    state = module.params["state"]
    if not HAS_PURESTORAGE:
        module.fail_json(
            msg="py-pure-client sdk is required to support 'count' parameter"
        )
    module.params["name"] = sorted(module.params["name"])
    array = get_array(module)
    api_version = array.get_rest_version()
    if LooseVersion(DEFAULT_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="Default Protection is not supported. Purity//FA 6.3.4, or higher, is required."
        )
    if module.params["scope"] == "pod":
        if not _get_pod(module, array):
            module.fail_json(
                msg="Invalid pod {0} specified.".format(module.params["pod"])
            )
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            ret = array.get_container_default_protections(
                names=[module.params["pod"]],
                context_names=[module.params["context"]],
            )
        else:
            ret = array.get_container_default_protections(names=[module.params["pod"]])
        current_default = list(ret.items)[0].default_protections
    else:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            ret = array.get_container_default_protections(
                context_names=[module.params["context"]]
            )
        else:
            ret = array.get_container_default_protections()
        current_default = list(ret.items)[0].default_protections
    for pgroup in range(0, len(module.params["name"])):
        if module.params["scope"] == "pod":
            pod_name = module.params["pod"] + module.params["name"][pgroup]
        else:
            pod_name = module.params["name"][pgroup]
        if not _get_pg(module, array, pod_name):
            module.fail_json(msg="Protection Group {0} does not exist".format(pod_name))

    if state == "present" and not current_default:
        create_default(module, array)
    elif state == "absent" and not current_default:
        module.exit_json(changed=False)
    elif state == "present" and current_default:
        update_default(module, array, current_default)
    elif state == "absent" and current_default and module.params["name"] != [""]:
        update_default(module, array, current_default)
    elif state == "absent" and current_default and module.params["name"] == [""]:
        delete_default(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
