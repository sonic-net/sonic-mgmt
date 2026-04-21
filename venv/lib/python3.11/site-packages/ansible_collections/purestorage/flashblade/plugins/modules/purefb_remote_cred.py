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
module: purefb_remote_cred
version_added: '1.0.0'
short_description: Create, modify and delete FlashBlade object store remote credentials
description:
- Create, modify and delete object store remote credentials
- You must have a correctly configured remote array or target
- This module is B(not) idempotent when updating existing remote credentials
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Define state of remote credential
    default: present
    choices: [ absent, present ]
    type: str
  name:
    description:
    - The name of the credential
    required: true
    type: str
  access_key:
    description:
    - Access Key ID of the S3 target
    type: str
  secret:
    description:
    - Secret Access Key for the S3 or Azure target
    type: str
  target:
    description:
    - Define whether to initialize the S3 bucket
    required: true
    type: str
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: "1.22.0"
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create remote credential
  purestorage.flashblade.purefb_remote_cred:
    name: cred1
    access_key: "3794fb12c6204e19195f"
    secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    target: target1
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete remote credential
  purestorage.flashblade.purefb_remote_cred:
    name: cred1
    target: target1
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = r"""
"""

HAS_PURITY_FB = True
try:
    from pypureclient.flashblade import (
        ObjectStoreRemoteCredentialsPost,
        ObjectStoreRemoteCredentialsPatch,
    )
except ImportError:
    HAS_PURITY_FB = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

CONTEXT_API_VERSION = "2.17"


def get_connected(module, blade):
    """Return connected device or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        connected_blades = list(
            blade.get_array_connections(context_names=[module.params["context"]]).items
        )
    else:
        connected_blades = list(blade.get_array_connections().items)
    for target in range(len(connected_blades)):
        if (
            connected_blades[target].remote.name == module.params["target"]
            or connected_blades[target].management_address == module.params["target"]
        ) and connected_blades[target].status in [
            "connected",
            "connecting",
            "partially_connected",
        ]:
            return connected_blades[target].remote.name
    if CONTEXT_API_VERSION in api_version:
        connected_targets = list(
            blade.get_targets(context_names=[module.params["context"]]).items
        )
    else:
        connected_targets = list(blade.get_targets().items)
    for target in range(len(connected_targets)):
        if connected_targets[target].name == module.params[
            "target"
        ] and connected_targets[target].status in [
            "connected",
            "connecting",
            "partially_connected",
        ]:
            return connected_targets[target].name
    return None


def get_remote_cred(module, blade):
    """Return Remote Credential or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_object_store_remote_credentials(
            names=[module.params["target"] + "/" + module.params["name"]],
            context_names=[module.params["context"]],
        )
    else:
        res = blade.get_object_store_remote_credentials(
            names=[module.params["target"] + "/" + module.params["name"]]
        )
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def create_credential(module, blade):
    """Create remote credential"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        remote_cred = module.params["target"] + "/" + module.params["name"]
        remote_credentials = ObjectStoreRemoteCredentialsPost(
            access_key_id=module.params["access_key"],
            secret_access_key=module.params["secret"],
        )
        if CONTEXT_API_VERSION in api_version:
            res = blade.post_object_store_remote_credentials(
                names=[remote_cred],
                remote_credentials=remote_credentials,
                context_names=[module.params["context"]],
            )
        else:
            res = blade.post_object_store_remote_credentials(
                names=[remote_cred], remote_credentials=remote_credentials
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create remote credential {0}. Error: {1}".format(
                    remote_cred, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_credential(module, blade):
    """Update remote credential"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        remote_cred = module.params["target"] + "/" + module.params["name"]
        new_attr = ObjectStoreRemoteCredentialsPatch(
            access_key_id=module.params["access_key"],
            secret_access_key=module.params["secret"],
        )
        if CONTEXT_API_VERSION in api_version:
            res = blade.patch_object_store_remote_credentials(
                names=[remote_cred],
                remote_credentials=new_attr,
                context_names=[module.params["context"]],
            )
        else:
            res = blade.patch_object_store_remote_credentials(
                names=[remote_cred], remote_credentials=new_attr
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to update remote credential {0}. Error: {1}".format(
                    remote_cred, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_credential(module, blade):
    """Delete remote credential"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        remote_cred = module.params["target"] + "/" + module.params["name"]
        if CONTEXT_API_VERSION in api_version:
            res = blade.delete_object_store_remote_credentials(
                names=[remote_cred], context_names=[module.params["context"]]
            )
        else:
            res = blade.delete_object_store_remote_credentials(names=[remote_cred])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete remote credential {0}. Error: {1}".format(
                    remote_cred, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
            name=dict(type="str", required=True),
            access_key=dict(type="str", no_log=False),
            secret=dict(type="str", no_log=True),
            target=dict(type="str", required=True),
            context=dict(type="str", default=""),
        )
    )

    required_if = [["state", "present", ["access_key", "secret"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    blade = get_system(module)
    target = get_connected(module, blade)

    if not target:
        module.fail_json(
            msg="Selected target {0} is not connected.".format(module.params["target"])
        )

    remote_cred = get_remote_cred(module, blade)

    if module.params["state"] == "present" and not remote_cred:
        create_credential(module, blade)
    elif module.params["state"] == "present":
        update_credential(module, blade)
    elif module.params["state"] == "absent" and remote_cred:
        delete_credential(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
