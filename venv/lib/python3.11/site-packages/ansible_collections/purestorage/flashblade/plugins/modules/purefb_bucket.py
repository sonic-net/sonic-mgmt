#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
---
module: purefb_bucket
version_added: "1.0.0"
short_description:  Manage Object Store Buckets on a  Pure Storage FlashBlade.
description:
    - This module managess object store (s3) buckets on Pure Storage FlashBlade.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Bucket Name.
    required: true
    type: str
  account:
    description:
      - Object Store Account for Bucket.
    required: true
    type: str
  versioning:
    description:
      - State of S3 bucket versioning
    required: false
    default: absent
    type: str
    choices: [ "enabled", "suspended", "absent" ]
  state:
    description:
      - Create, delete or modifies a bucket.
    required: false
    default: present
    type: str
    choices: [ "present", "absent" ]
  eradicate:
    description:
      - Define whether to eradicate the bucket on delete or leave in trash.
    required: false
    type: bool
    default: false
  mode:
    description:
      - The type of bucket to be created. Also referred to a VSO Mode.
      - I(multi-site-writable) type can only be used after feature is
        enabled by Pure Technical Support
    type: str
    choices: [ "classic", "multi-site-writable" ]
    version_added: '1.10.0'
  quota:
    description:
      - The effective quota limit applied against the size of the bucket.
      - User byte quota in B, K, M, G, T or P units.
      - Range must be between 1 byte and 9.22 exabytes.
      - Setting to 0 will allow the bucket size to be unlimited.
    type: str
    version_added: '1.12.0'
  hard_limit:
    description:
     - Whether the I(quota) value is enforced or not.
     - If not provided the object store account default value will be used.
    type: bool
    version_added: '1.12.0'
  retention_lock:
    description:
     - Set retention lock level for the bucket
     - Once set to I(ratcheted) can only be lowered by Pure Technical Services
    type: str
    choices: [ "ratcheted", "unlocked" ]
    default: unlocked
    version_added: '1.12.0'
  retention_mode:
    description:
     - The retention mode used to apply locks on new objects if none is specified by the S3 client
     - I(safemode) is available if global Per-Bucket Safemode config is enabled
     - Use "" to clear
     - Once set to I(compliance) this can only be changed by contacting Pure Technical Services
    type: str
    choices: [ "compliance", "governance", "safemode", "" ]
    version_added: '1.12.0'
  object_lock_enabled:
    description:
     - If set to true, then S3 APIs relating to object lock may be used
    type: bool
    default: false
    version_added: '1.12.0'
  freeze_locked_objects:
    description:
     - If set to true, a locked object will be read-only and no new versions of
       the object may be created due to modifications
     - After enabling, can be disabled only by contacting Pure Technical Services
    type: bool
    default: false
    version_added: '1.12.0'
  default_retention:
    description:
     - The retention period, in days, used to apply locks on new objects if
       none is specified by the S3 client
     - Valid values between 1 and 365000
     - Use "" to clear
    type: str
    version_added: '1.12.0'
  block_new_public_policies:
    description:
    - If set to true, adding bucket policies that grant public access to a bucket is not allowed.
    type: bool
    version_added: '1.15.0'
  block_public_access:
    description:
    - If set to true, access to a bucket with a public policy is restricted to only authenticated
      users within the account that bucket belongs to.
    type: bool
    version_added: '1.15.0'
  eradication_mode:
    description:
    - The eradication mode of the bucket.
    type: str
    choices: [ "permission-based", "retention-based" ]
    version_added: '1.17.0'
  manual_eradication:
    description:
    - The manual eradication status of the bucket. If false, the bucket cannot be eradicated after
      it has been destroyed, unless it is empty. If true, the bucket can be eradicated.
    type: bool
    version_added: '1.17.0'
  eradication_delay:
    description:
    - Minimum eradication delay in days. Automatically eradicate destroyed buckets after
      the delay time passes unless automatic eradication is delayed due to other configuration values.
    - Valid values are integer days from 1 to 30. Default is 1.
    type: int
    version_added: '1.17.0'
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

EXAMPLES = """
- name: Create new bucket named foo in account bar
  purestorage.flashblade.purefb_bucket:
    name: foo
    quota: 10G
    hard_limit: false
    account: bar
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Update bucket foo in account bar with new quota
  purestorage.flashblade.purefb_bucket:
    name: foo
    quota: 500B
    hard_limit: true
    account: bar
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Remove quota limits from bucket named foo in account bar
  purestorage.flashblade.purefb_bucket:
    name: foo
    quota: 0
    account: bar
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete bucket named foo in account bar
  purestorage.flashblade.purefb_bucket:
    name: foo
    account: bar
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Change bucket versioning state
  purestorage.flashblade.purefb_bucket:
    name: foo
    account: bar
    versioning: enabled
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Recover deleted bucket named foo in account bar
  purestorage.flashblade.purefb_bucket:
    name: foo
    account: bar
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Eradicate bucket named foo in account bar
  purestorage.flashblade.purefb_bucket:
    name: foo
    account: bar
    state: absent
    eradicate: true
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = """
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import (
        BucketPost,
        ReferenceWritable,
        BucketPatch,
        ObjectLockConfigRequestBody,
        PublicAccessConfig,
        BucketAccessPolicyPost,
        BucketAccessPolicyRulePost,
        BucketAccessPolicyRulePrincipal,
        BucketEradicationConfig,
    )
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)
from ansible_collections.purestorage.flashblade.plugins.module_utils.common import (
    human_to_bytes,
)

SEC_PER_DAY = 86400000
VSO_VERSION = "2.5"
QUOTA_VERSION = "2.8"
MODE_VERSION = "2.12"
WORM_VERSION = "2.13"
CONTEXT_API_VERSION = "2.17"


def get_s3acc(module, blade):
    """Return Object Store Account or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_object_store_accounts(
            context_names=[module.params["context"]],
            names=[module.params["account"]],
        )
    else:
        res = blade.get_object_store_accounts(names=[module.params["account"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def get_bucket(module, blade):
    """Return Bucket or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_buckets(
            context_names=[module.params["context"]],
            names=[module.params["name"]],
        )
    else:
        res = blade.get_buckets(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def create_bucket(module, blade):
    """Create bucket"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if VSO_VERSION in api_version:
            if CONTEXT_API_VERSION in api_version:
                account_defaults = list(
                    blade.get_object_store_accounts(
                        names=[module.params["account"]],
                        context_names=[module.params["context"]],
                    ).items
                )[0]
            else:
                account_defaults = list(
                    blade.get_object_store_accounts(
                        names=[module.params["account"]]
                    ).items
                )[0]
            if QUOTA_VERSION in api_version:
                if not module.params["hard_limit"]:
                    module.params["hard_limit"] = account_defaults.hard_limit_enabled
                if module.params["quota"]:
                    quota = str(human_to_bytes(module.params["quota"]))
                else:
                    if not account_defaults.quota_limit:
                        quota = ""
                    else:
                        quota = str(account_defaults.quota_limit)
                if not module.params["retention_mode"]:
                    module.params["retention_mode"] = ""
                if not module.params["default_retention"]:
                    module.params["default_retention"] = ""
                else:
                    module.params["default_retention"] = str(
                        int(module.params["default_retention"]) * 86400000
                    )
                if module.params["object_lock_enabled"]:
                    bucket = BucketPost(
                        account=ReferenceWritable(name=module.params["account"]),
                        bucket_type=module.params["mode"],
                        hard_limit_enabled=module.params["hard_limit"],
                        quota_limit=quota,
                    )
                else:
                    bucket = BucketPost(
                        account=ReferenceWritable(name=module.params["account"]),
                        bucket_type=module.params["mode"],
                        hard_limit_enabled=module.params["hard_limit"],
                        quota_limit=quota,
                    )
            else:
                bucket = BucketPost(
                    account=ReferenceWritable(name=module.params["account"]),
                    bucket_type=module.params["mode"],
                )
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_buckets(
                    names=[module.params["name"]],
                    bucket=bucket,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_buckets(names=[module.params["name"]], bucket=bucket)
            if res.status_code != 200:
                _delete_bucket(module, blade)
                module.fail_json(
                    msg="Object Store Bucket {0} creation failed. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
            if module.params["versioning"] != "absent":
                if QUOTA_VERSION in api_version:
                    bucket = BucketPatch(
                        retention_lock=module.params["retention_lock"],
                        object_lock_config=ObjectLockConfigRequestBody(
                            default_retention_mode=module.params["retention_mode"],
                            enabled=module.params["object_lock_enabled"],
                            freeze_locked_objects=module.params[
                                "freeze_locked_objects"
                            ],
                            default_retention=module.params["default_retention"],
                        ),
                        versioning=module.params["versioning"],
                    )
                else:
                    bucket = BucketPatch(
                        retention_lock=module.params["retention_lock"],
                        versioning=module.params["versioning"],
                    )
            else:
                if QUOTA_VERSION in api_version:
                    bucket = BucketPatch(
                        retention_lock=module.params["retention_lock"],
                        object_lock_config=ObjectLockConfigRequestBody(
                            default_retention_mode=module.params["retention_mode"],
                            enabled=module.params["object_lock_enabled"],
                            freeze_locked_objects=module.params[
                                "freeze_locked_objects"
                            ],
                            default_retention=module.params["default_retention"],
                        ),
                        versioning="none",
                    )
                else:
                    bucket = BucketPatch(
                        retention_lock=module.params["retention_lock"],
                        versioning="none",
                    )

            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_buckets(
                    names=[module.params["name"]],
                    bucket=bucket,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_buckets(names=[module.params["name"]], bucket=bucket)
            if res.status_code != 200:
                module.fail_json(
                    msg="Object Store Bucket {0} creation update failed. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
        else:
            bucket = BucketPost(
                account=ReferenceWritable(name=module.params["account"]),
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_buckets(
                    names=[module.params["name"]],
                    bucket=bucket,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_buckets(names=[module.params["name"]], bucket=bucket)
            if res.status_code != 200:
                _delete_bucket(module, blade)
                module.fail_json(
                    msg="Object Store Bucket {0} creation failed. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
            if module.params["versioning"] != "absent":
                if CONTEXT_API_VERSION in api_version:
                    res = blade.buckets.patch_buckets(
                        names=[module.params["name"]],
                        bucket=BucketPatch(versioning=module.params["versioning"]),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.buckets.patch_buckets(
                        names=[module.params["name"]],
                        bucket=BucketPatch(versioning=module.params["versioning"]),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Object Store Bucket {0} created but versioning state failed. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        if MODE_VERSION in api_version:
            if not module.params["block_new_public_policies"]:
                module.params["block_new_public_policies"] = False
            if not module.params["block_public_access"]:
                module.params["block_public_access"] = False
            pac = BucketPatch(
                public_access_config=PublicAccessConfig(
                    block_new_public_policies=module.params[
                        "block_new_public_policies"
                    ],
                    block_public_access=module.params["block_public_access"],
                )
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_buckets(
                    bucket=pac,
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_buckets(bucket=pac, names=[module.params["name"]])
            if res.status_code != 200:
                module.warn(
                    msg="Failed to set Public Access config correctly for bucket {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )
            if (
                not module.params["block_public_access"]
                and not module.params["block_new_public_policies"]
            ):
                # To make the bucket truely public we have to create a bucket access policy
                # and rule
                policy = BucketAccessPolicyPost(
                    name=module.params["name"],
                )
                if CONTEXT_API_VERSION in api_version:
                    res = blade.post_buckets_bucket_access_policies(
                        bucket_names=[module.params["name"]],
                        policy=policy,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.post_buckets_bucket_access_policies(
                        bucket_names=[module.params["name"]], policy=policy
                    )
                if res.status_code != 200:
                    module.warn(
                        msg="Failed to set bucket access policy for bucket {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
                rule = BucketAccessPolicyRulePost(
                    actions=["s3:GetObject"],
                    effect="allow",
                    principals=BucketAccessPolicyRulePrincipal(all=True),
                    resources=[module.params["name"] + "/*"],
                )
                if CONTEXT_API_VERSION in api_version:
                    res = blade.post_buckets_bucket_access_policies_rules(
                        bucket_names=[module.params["name"]],
                        rule=rule,
                        names=["default"],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.post_buckets_bucket_access_policies_rules(
                        bucket_names=[module.params["name"]],
                        rule=rule,
                        names=["default"],
                    )
                if res.status_code != 200:
                    module.warn(
                        msg="Failed to set bucket access policy rule for bucket {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        if WORM_VERSION in api_version and module.params["eradication_mode"]:
            if not module.params["eradication_delay"]:
                module.params["eradication_delay"] = SEC_PER_DAY
            else:
                module.params["eradication_delay"] = (
                    module.params["eradication_delay"] * SEC_PER_DAY
                )
            if not module.params["manual_eradication"]:
                module.params["manual_eradication"] = "disabled"
            else:
                module.params["manual_eradication"] = "enabled"
            worm = BucketPatch(
                eradication_config=BucketEradicationConfig(
                    manual_eradication=module.params["manual_eradication"],
                    eradication_mode=module.params["eradication_mode"],
                    eradication_delay=module.params["eradication_delay"],
                )
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_buckets(
                    bucket=worm,
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_buckets(bucket=worm, names=[module.params["name"]])
            if res.status_code != 200:
                module.warn(
                    msg="Failed to set Bucket Eradication config correctly for bucket {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )
    module.exit_json(changed=changed)


def _delete_bucket(module, blade):
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        blade.patch_buckets(
            names=[module.params["name"]],
            bucket=BucketPatch(destroyed=True),
            context_names=[module.params["context"]],
        )
        blade.buckets.delete_buckets(
            names=[module.params["name"]], context_names=[module.params["context"]]
        )
    else:
        blade.patch_buckets(
            names=[module.params["name"]],
            bucket=BucketPatch(destroyed=True),
            context_names=[module.params["context"]],
        )
        blade.buckets.delete_buckets(
            names=[module.params["name"]], context_names=[module.params["context"]]
        )


def delete_bucket(module, blade):
    """Delete Bucket"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in api_version:
            res = blade.patch_buckets(
                names=[module.params["name"]],
                bucket=BucketPatch(destroyed=True),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.patch_buckets(
                names=[module.params["name"]], bucket=BucketPatch(destroyed=True)
            )
        if res.status_code != 200:
            module.warn(
                msg="Deletion for bucket {0} failed. "
                "Error: {1}".format(module.params["name"], res.errors[0].message)
            )
        if module.params["eradicate"]:
            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_buckets(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_buckets(names=[module.params["name"]])
            if res.status_code != 200:
                module.warn(
                    msg="Eradication for bucket {0} failed. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )
    module.exit_json(changed=changed)


def recover_bucket(module, blade):
    """Recover Bucket"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in api_version:
            res = blade.patch_buckets(
                names=[module.params["name"]],
                bucket=BucketPatch(destroyed=False),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.patch_buckets(
                names=[module.params["name"]], bucket=BucketPatch(destroyed=False)
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Object Store Bucket {0} Recovery failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_bucket(module, blade, bucket):
    """Update Bucket"""
    changed = False
    change_pac = False
    change_worm = False
    change_quota = False
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        bucket_detail = list(
            blade.get_buckets(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        bucket_detail = list(blade.get_buckets(names=[module.params["name"]]).items)[0]
    if VSO_VERSION in api_version:
        if module.params["mode"] and bucket_detail.bucket_type != module.params["mode"]:
            module.warn("Changing bucket type is not permitted.")
        if QUOTA_VERSION in api_version:
            if (
                bucket_detail.retention_lock == "ratcheted"
                and getattr(
                    bucket_detail.object_lock_config, "default_retention_mode", None
                )
                == "compliance"
                and module.params["retention_mode"] != "compliance"
            ):
                module.warn(
                    "Changing retention_mode can only be performed by Pure Technical Support."
                )
        if not module.params["object_lock_enabled"] and getattr(
            bucket_detail.object_lock_config, "enabled", False
        ):
            module.warn("Object lock cannot be disabled.")
        if not module.params["freeze_locked_objects"] and getattr(
            bucket_detail.object_lock_config, "freeze_locked_objects", False
        ):
            module.warn("Freeze locked onjects cannot be disabled.")
        default_retention = getattr(
            bucket_detail.object_lock_config, "default_retention"
        )
        if default_retention and default_retention > 1:
            if (
                default_retention / 86400000 > int(module.params["default_retention"])
                and bucket_detail.retention_lock == "ratcheted"
            ):
                module.warn(
                    "Default retention can only be reduced by Pure Technical Support."
                )

    if bucket.versioning != "none":
        if module.params["versioning"] == "absent" and bucket.versioning == "enabled":
            versioning = "suspended"
        else:
            versioning = module.params["versioning"]
        if bucket.versioning != versioning:
            changed = True
            if not module.check_mode:
                if CONTEXT_API_VERSION in api_version:
                    res = blade.patch_buckets(
                        names=[module.params["name"]],
                        bucket=BucketPatch(versioning=versioning),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_buckets(
                        names=[module.params["name"]],
                        bucket=BucketPatch(versioning=versioning),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Object Store Bucket {0} versioning change failed. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
    elif module.params["versioning"] != "absent":
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_buckets(
                    names=[module.params["name"]],
                    bucket=BucketPatch(versioning=module.params["versioning"]),
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_buckets(
                    names=[module.params["name"]],
                    bucket=BucketPatch(versioning=module.params["versioning"]),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Object Store Bucket {0} versioning change failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    if QUOTA_VERSION in api_version:
        current_quota = {
            "quota": bucket_detail.quota_limit,
            "hard": bucket_detail.hard_limit_enabled,
        }
        new_quota = {
            "quota": bucket_detail.quota_limit,
            "hard": bucket_detail.hard_limit_enabled,
        }
        if module.params["quota"]:
            quota = human_to_bytes(module.params["quota"])
            if module.params["quota"] == "0":
                quota = None
                module.params["hard_limit"] = False
            if quota != current_quota["quota"]:
                change_quota = True
                new_quota["quota"] = human_to_bytes(module.params["quota"])
        if (
            module.params["hard_limit"]
            and module.params["hard_limit"] != current_quota["hard"]
        ):
            change_quota = True
            new_quota["hard"] = module.params["hard_limit"]
        if current_quota != new_quota and not module.check_mode:
            if new_quota["quota"] is None or new_quota["quota"] == 0:
                bucket = BucketPatch(
                    quota_limit="",
                    hard_limit_enabled=False,
                )
            else:
                bucket = BucketPatch(
                    quota_limit=str(new_quota["quota"]),
                    hard_limit_enabled=new_quota["hard"],
                )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_buckets(
                    bucket=bucket,
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_buckets(bucket=bucket, names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update quota settings correctly for bucket {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )
    if MODE_VERSION in api_version:
        current_pac = {
            "block_new_public_policies": bucket_detail.public_access_config.block_new_public_policies,
            "block_public_access": bucket_detail.public_access_config.block_public_access,
        }
        if module.params["block_new_public_policies"] is None:
            new_public_policies = current_pac["block_new_public_policies"]
        else:
            new_public_policies = module.params["block_new_public_policies"]
        if module.params["block_public_access"] is None:
            new_public_access = current_pac["block_public_access"]
        else:
            new_public_access = module.params["block_public_access"]
        new_pac = {
            "block_new_public_policies": new_public_policies,
            "block_public_access": new_public_access,
        }
        if current_pac != new_pac:
            change_pac = True
            pac = BucketPatch(
                public_access_config=PublicAccessConfig(
                    block_new_public_policies=new_pac["block_new_public_policies"],
                    block_public_access=new_pac["block_public_access"],
                )
            )
        if change_pac and not module.check_mode:
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_buckets(
                    bucket=pac,
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_buckets(bucket=pac, names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update Public Access config correctly for bucket {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )
    if WORM_VERSION in api_version:
        current_worm = {
            "eradication_delay": bucket_detail.eradication_config.eradication_delay,
            "manual_eradication": bucket_detail.eradication_config.manual_eradication,
            "eradication_mode": bucket_detail.eradication_config.eradication_mode,
        }
        if module.params["eradication_delay"] is None:
            new_delay = current_worm["eradication_delay"]
        else:
            new_delay = module.params["eradication_delay"] * SEC_PER_DAY
        if module.params["manual_eradication"] is None:
            new_manual = current_worm["manual_eradication"]
        else:
            if module.params["manual_eradication"]:
                new_manual = "enabled"
            else:
                new_manual = "disabled"
        if (
            module.params["eradication_mode"]
            and module.params["eradication_mode"] != current_worm["eradication_mode"]
        ):
            new_mode = module.params["eradication_mode"]
        else:
            new_mode = current_worm["eradication_mode"]
        new_worm = {
            "eradication_delay": new_delay,
            "manual_eradication": new_manual,
            "eradication_mode": new_mode,
        }
        if current_worm != new_worm:
            change_worm = True
            worm = BucketPatch(
                public_access_config=BucketEradicationConfig(
                    eradication_delay=new_worm["eradication_delay"],
                    manual_eradication=new_worm["manual_eradication"],
                    eradication_mode=new_worm["eradication_mode"],
                )
            )
        if change_worm and not module.check_mode:
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_buckets(
                    bucket=worm,
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_buckets(bucket=worm, names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update Eradication config correctly for bucket {0}. "
                    "Error: {1}".format(module.params["name"], res.errors[0].message)
                )
    module.exit_json(changed=(changed or change_pac or change_worm or change_quota))


def eradicate_bucket(module, blade):
    """Eradicate Bucket"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in api_version:
            res = blade.delete_buckets(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = blade.delete_buckets(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Object Store Bucket {0} eradication failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            account=dict(required=True),
            eradicate=dict(default="false", type="bool"),
            mode=dict(
                type="str",
                choices=["classic", "multi-site-writable"],
            ),
            retention_mode=dict(
                type="str", choices=["compliance", "governance", "safemode", ""]
            ),
            default_retention=dict(type="str"),
            retention_lock=dict(
                type="str", choices=["ratcheted", "unlocked"], default="unlocked"
            ),
            hard_limit=dict(type="bool"),
            block_new_public_policies=dict(type="bool"),
            block_public_access=dict(type="bool"),
            object_lock_enabled=dict(type="bool", default=False),
            freeze_locked_objects=dict(type="bool", default=False),
            quota=dict(type="str"),
            versioning=dict(
                default="absent", choices=["enabled", "suspended", "absent"]
            ),
            state=dict(default="present", choices=["present", "absent"]),
            eradication_delay=dict(type="int"),
            eradication_mode=dict(
                type="str", choices=["permission-based", "retention-based"]
            ),
            manual_eradication=dict(type="bool"),
            context=dict(type="str", default=""),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required")

    if (
        module.params["eradication_delay"]
        and not 30 >= module.params["eradication_delay"] >= 1
    ):
        module.fail_json(msg="Eradication Delay must be between 1 and 30 days.")

    state = module.params["state"]
    blade = get_system(module)
    api_version = list(blade.get_versions().items)

    # From REST 2.12 classic is no longer the default mode
    if MODE_VERSION in api_version:
        if not module.params["mode"]:
            module.params["mode"] = "multi-site-writable"
    elif not module.params["mode"]:
        module.params["mode"] = "classic"
    bucket = get_bucket(module, blade)
    if not get_s3acc(module, blade):
        module.fail_json(
            msg="Object Store Account {0} does not exist.".format(
                module.params["account"]
            )
        )
    if (
        module.params["quota"]
        and human_to_bytes(module.params["quota"]) > 9223372036854775807
    ):
        module.fail_json(msg="Quota must not exceed 9.22 exabytes")
    if module.params["eradicate"] and state == "present":
        module.warn("Eradicate flag ignored without state=absent")

    if state == "present" and not bucket:
        create_bucket(module, blade)
    elif state == "present" and bucket and bucket.destroyed:
        recover_bucket(module, blade)
    elif state == "absent" and bucket and not bucket.destroyed:
        delete_bucket(module, blade)
    elif state == "present" and bucket:
        update_bucket(module, blade, bucket)
    elif (
        state == "absent" and bucket and bucket.destroyed and module.params["eradicate"]
    ):
        eradicate_bucket(module, blade)
    elif state == "absent" and not bucket:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
