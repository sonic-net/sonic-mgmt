#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
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
module: purefb_s3acc
version_added: '1.0.0'
short_description: Create or delete FlashBlade Object Store accounts
description:
- Create or delete object store accounts on a Pure Stoage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete object store account
    default: present
    choices: [ absent, present ]
    type: str
  name:
    description:
    - The name of object store account
    type: str
    required: true
  quota:
    description:
    - The effective quota limit to be applied against the size of the account in bytes.
    - Values can be entered as K, M, T or P
    - If set to '' (empty string), the account is unlimited in size.
    version_added: 1.11.0
    type: str
  hard_limit:
    description:
    - If set to true, the account size, as defined by I(quota_limit), is used as a hard limit quota.
    - If set to false, a hard limit quota will not be applied to the account, but soft quota alerts
      will still be sent if the account has a value set for I(quota_limit).
    version_added: 1.11.0
    type: bool
  default_quota:
    description:
    - The value of this field will be used to configure the I(quota_limit) field of newly created buckets
      associated with this object store account, if the bucket creation does not specify its own value.
    - Values can be entered as K, M, T or P
    - If set to '' (empty string), the bucket default is unlimited in size.
    version_added: 1.11.0
    type: str
  default_hard_limit:
    description:
    - The value of this field will be used to configure the I(hard_limit) field of newly created buckets
      associated with this object store account, if the bucket creation does not specify its own value.
    version_added: 1.11.0
    type: bool
  block_new_public_policies:
    description:
    - If set to true, adding bucket policies that grant public access to a bucket is not allowed.
    type: bool
    version_added: 1.15.0
  block_public_access:
    description:
    - If set to true, access to a bucket with a public policy is restricted to only authenticated
      users within the account that bucket belongs to.
    type: bool
    version_added: 1.15.0
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
- name: Create object store account foo (with no quotas)
  purestorage.flashblade.purefb_s3acc:
    name: foo
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create object store account foo (with quotas)
  purestorage.flashblade.purefb_s3acc:
    name: foo
    quota: 20480000
    hard_limit: true
    default_quota: 1024000
    default_hard_limit: false
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete object store account foo
  purestorage.flashblade.purefb_s3acc:
    name: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import (
        ObjectStoreAccountPatch,
        BucketDefaults,
        PublicAccessConfig,
    )
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule, human_to_bytes
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


PUBLIC_API_VERSION = "2.12"
CONTEXT_API_VERSION = "2.17"


def get_s3acc(module, blade):
    """Return Object Store Account or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_object_store_accounts(
            names=[module.params["name"]], context_names=[module.params["context"]]
        )
    else:
        res = blade.get_object_store_accounts(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def update_s3acc(module, blade):
    """Update Object Store Account"""
    changed = False
    api_version = list(blade.get_versions().items)
    public = False
    if CONTEXT_API_VERSION in api_version:
        acc_settings = list(
            blade.get_object_store_accounts(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        acc_settings = list(
            blade.get_object_store_accounts(names=[module.params["name"]]).items
        )[0]
    if PUBLIC_API_VERSION in api_version:
        public = True
        current_account = {
            "hard_limit": acc_settings.hard_limit_enabled,
            "default_hard_limit": acc_settings.bucket_defaults.hard_limit_enabled,
            "quota": str(acc_settings.quota_limit),
            "default_quota": str(acc_settings.bucket_defaults.quota_limit),
            "block_new_public_policies": acc_settings.public_access_config.block_new_public_policies,
            "block_public_access": acc_settings.public_access_config.block_public_access,
        }
    else:
        current_account = {
            "hard_limit": acc_settings.hard_limit_enabled,
            "default_hard_limit": acc_settings.bucket_defaults.hard_limit_enabled,
            "quota": str(acc_settings.quota_limit),
            "default_quota": str(acc_settings.bucket_defaults.quota_limit),
        }
    if current_account["quota"] == "None":
        current_account["quota"] = ""
    if current_account["default_quota"] == "None":
        current_account["default_quota"] = ""
    if module.params["quota"] is None:
        module.params["quota"] = current_account["quota"]
    if module.params["default_quota"] is None:
        module.params["default_quota"] = current_account["default_quota"]
    if not module.params["default_quota"]:
        module.params["default_quota"] = ""
    if not module.params["quota"]:
        quota = ""
    else:
        quota = str(human_to_bytes(module.params["quota"]))
    if not module.params["default_quota"]:
        default_quota = ""
    else:
        default_quota = str(human_to_bytes(module.params["default_quota"]))
    if module.params["hard_limit"] is None:
        hard_limit = current_account["hard_limit"]
    else:
        hard_limit = module.params["hard_limit"]
    if module.params["default_hard_limit"] is None:
        default_hard_limit = current_account["default_hard_limit"]
    else:
        default_hard_limit = module.params["default_hard_limit"]
    if public:
        if module.params["block_new_public_policies"] is None:
            new_public_policies = current_account["block_new_public_policies"]
        else:
            new_public_policies = module.params["block_new_public_policies"]
        if module.params["block_public_access"] is None:
            public_access = current_account["block_public_access"]
        else:
            public_access = module.params["block_public_access"]
        new_account = {
            "hard_limit": hard_limit,
            "default_hard_limit": default_hard_limit,
            "quota": quota,
            "default_quota": default_quota,
            "block_new_public_policies": new_public_policies,
            "block_public_access": public_access,
        }
    else:
        new_account = {
            "hard_limit": module.params["hard_limit"],
            "default_hard_limit": module.params["default_hard_limit"],
            "quota": quota,
            "default_quota": default_quota,
        }
    if new_account != current_account:
        changed = True
        if not module.check_mode:
            if public:
                osa = ObjectStoreAccountPatch(
                    hard_limit_enabled=new_account["hard_limit"],
                    quota_limit=new_account["quota"],
                    bucket_defaults=BucketDefaults(
                        hard_limit_enabled=new_account["default_hard_limit"],
                        quota_limit=new_account["default_quota"],
                    ),
                    public_access_config=PublicAccessConfig(
                        block_public_access=new_account["block_public_access"],
                        block_new_public_policies=new_account[
                            "block_new_public_policies"
                        ],
                    ),
                )
            else:
                osa = ObjectStoreAccountPatch(
                    hard_limit_enabled=new_account["hard_limit"],
                    quota_limit=new_account["quota"],
                    bucket_defaults=BucketDefaults(
                        hard_limit_enabled=new_account["default_hard_limit"],
                        quota_limit=new_account["default_quota"],
                    ),
                )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_object_store_accounts(
                    object_store_account=osa,
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_object_store_accounts(
                    object_store_account=osa, names=[module.params["name"]]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update account {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )

    module.exit_json(changed=changed)


def create_s3acc(module, blade):
    """Create Object Store Account"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in api_version:
            res = blade.post_object_store_accounts(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = blade.post_object_store_accounts(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Object Store Account {0} creation failed. Error: {1}".format(
                    module.params["name"],
                    res.errors[0].message,
                )
            )
        if module.params["quota"] or module.params["default_quota"]:
            if not module.params["default_quota"]:
                default_quota = ""
            else:
                default_quota = str(human_to_bytes(module.params["default_quota"]))
            if not module.params["quota"]:
                quota = ""
            else:
                quota = str(human_to_bytes(module.params["quota"]))
            if not module.params["hard_limit"]:
                module.params["hard_limit"] = False
            if not module.params["default_hard_limit"]:
                module.params["default_hard_limit"] = False
            osa = ObjectStoreAccountPatch(
                hard_limit_enabled=module.params["hard_limit"],
                quota_limit=quota,
                bucket_defaults=BucketDefaults(
                    hard_limit_enabled=module.params["default_hard_limit"],
                    quota_limit=default_quota,
                ),
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_object_store_accounts(
                    object_store_account=osa,
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_object_store_accounts(
                    object_store_account=osa, names=[module.params["name"]]
                )
            if res.status_code != 200:
                if CONTEXT_API_VERSION in api_version:
                    blade.object_store_accounts.delete_object_store_accounts(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    )
                else:
                    blade.object_store_accounts.delete_object_store_accounts(
                        names=[module.params["name"]]
                    )
                module.fail_json(
                    msg="Failed to set quotas correctly for account {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )
        if PUBLIC_API_VERSION in api_version:
            if not module.params["block_new_public_policies"]:
                module.params["block_new_public_policies"] = False
            if not module.params["block_public_access"]:
                module.params["block_public_access"] = False
            osa = ObjectStoreAccountPatch(
                public_access_config=PublicAccessConfig(
                    block_new_public_policies=module.params[
                        "block_new_public_policies"
                    ],
                    block_public_access=module.params["block_public_access"],
                )
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_object_store_accounts(
                    object_store_account=osa,
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_object_store_accounts(
                    object_store_account=osa, names=[module.params["name"]]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to Public Access config correctly for account {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )

    module.exit_json(changed=changed)


def delete_s3acc(module, blade):
    """Delete Object Store Account"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_object_store_users(
                names=[module.params["name"] + "/*'"],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_object_store_users(names=[module.params["name"] + "/*'"])
        if res.status_code == 200:
            module.fail_json(
                msg="Remove all Users from Object Store Account {0} \
                                 before deletion".format(
                    module.params["name"]
                )
            )
        else:
            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_object_store_accounts(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_object_store_accounts(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Object Store Account {0} deletion failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True, type="str"),
            hard_limit=dict(type="bool"),
            default_hard_limit=dict(type="bool"),
            block_new_public_policies=dict(type="bool"),
            block_public_access=dict(type="bool"),
            quota=dict(type="str"),
            default_quota=dict(type="str"),
            state=dict(default="present", choices=["present", "absent"]),
            context=dict(type="str", default=""),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    blade = get_system(module)

    if module.params["quota"] or module.params["default_quota"]:
        if not HAS_PURESTORAGE:
            module.fail_json(msg="py-pure-client sdk is required for to set quotas")

    upper = False
    for element in module.params["name"]:
        if element.isupper():
            upper = True
            break
    if upper:
        module.warn("Changing account name to lowercase...")
        module.params["name"] = module.params["name"].lower()

    s3acc = get_s3acc(module, blade)

    if state == "absent" and s3acc:
        delete_s3acc(module, blade)
    elif state == "present" and s3acc:
        update_s3acc(module, blade)
    elif not s3acc and state == "present":
        create_s3acc(module, blade)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
