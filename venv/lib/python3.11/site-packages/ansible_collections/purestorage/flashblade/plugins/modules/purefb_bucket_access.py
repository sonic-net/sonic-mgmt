#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2025, Simon Dodsley (simon@purestorage.com)
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
module: purefb_bucket_access
version_added: '1.20.0'
short_description: Manage FlashBlade bucket access policies
description:
- Manage object store bucket policies.
- This modules allows the management of both bucket access and cross-origin
  resource sharing policies and their associated rules.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete policy or rule.
    default: present
    type: str
    choices: [ absent, present ]
  policy_type:
    description:
    - Type of policy
    type: str
    choices: [ access, cors ]
    default: access
  name:
    description:
    - Name of Object Store bucket the policy applies to.
    type: str
    required: true
  rule:
    description:
    - Name of the rule in the Bucket Policy
    - Required if I(state) is I(present)
    type: str
  effect:
    description:
    - Allow S3 requests that match all of the I(actions) item selected.
      Rules are additive.
    type: str
    default: allow
    choices: [ allow, deny ]
  actions:
    description:
    - List of permissions to grant.
    - System-wide policy rules cannot be deleted or modified
    - Currently only s3:GetObject is allowed
    type: list
    elements: str
    default: [ "s3:GetObject" ]
    choices:
      - s3:*
      - s3:AbortMultipartUpload
      - s3:BypassGovernanceRetention
      - s3:CreateBucket
      - s3:DeleteBucket
      - s3:DeleteObject
      - s3:DeleteObjectVersion
      - s3:ExtendSafemodeRetentionPeriod
      - s3:GetBucketAcl
      - s3:GetBucketLocation
      - s3:GetBucketVersioning
      - s3:GetLifecycleConfiguration
      - s3:GetObject
      - s3:GetObjectAcl
      - s3:GetObjectLegalHold
      - s3:GetObjectLockConfiguration
      - s3:GetObjectRetention
      - s3:GetObjectTagging
      - s3:GetObjectVersion
      - s3:GetObjectVersionTagging
      - s3:ListAllMyBuckets
      - s3:ListBucket
      - s3:ListBucketMultipartUploads
      - s3:ListBucketVersions
      - s3:ListMultipartUploadParts
      - s3:PutBucketVersioning
      - s3:PutLifecycleConfiguration
      - s3:PutObject
      - s3:PutObjectLegalHold
      - s3:PutObjectLockConfiguration
      - s3:PutObjectRetention
      - s3:ResolveSafemodeConflicts
  methods:
    description:
    - A list of HTTP methods that are permitted for cross-origin requests to access a bucket.
    - The only currently supported combination of allowed methods is all methods.
    choices:
      - GET
      - PUT
      - HEAD
      - POST
      - DELETE
    type: list
    elements: str
    default: ["GET", "PUT", "HEAD", "POST", "DELETE"]
  headers:
    description:
    - A list of headers that are permitted to be included in cross-origin requests to access a bucket.
    - The only currently supported allowed header is '*'.
    type: list
    elements: str
    default: ["*"]
  origins:
    description:
    - A list of origins (domains) that are permitted to make cross-origin requests to access a bucket.
    - The only currently supported allowed origin is '*'.
    type: list
    elements: str
    default: ["*"]
  resources:
    description:
    - The list of resources which this rule applies to.
    - The only currently supported resource is all objects in a bucket to
      which the parent policy belongs.
    elements: str
    type: list
    default: ["*"]
  principals:
    description:
    - Defines if the rule will apply to all object store users
      regardless of their origin or principal.
    type: bool
    default: true
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
- name: Create a bucket access policy rule for bucket bar
  purestorage.flashblade.purefb_bucket_policy:
    rule: foo
    name: bar
    policy_type: access
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a CORS policy rule for bucket bar
  purestorage.flashblade.purefb_bucket_policy:
    rule: foo
    name: bar
    policy_type: cors
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete bucket policy rule foo from bucket bar
  purestorage.flashblade.purefb_bucket_policy:
    rule: foo
    name: bar
    policy_type: access
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete all bucket policy rules from bucket bar
  purestorage.flashblade.purefb_bucket_policy:
    name: bar
    policy_type: access
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import (
        BucketAccessPolicyRulePost,
        BucketAccessPolicyRulePrincipal,
        CrossOriginResourceSharingPolicyRulePost,
    )
except ImportError:
    HAS_PYPURECLIENT = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

MIN_API_VERSION = "2.12"
CONTEXT_API_VERSION = "2.17"


def delete_cors_policy(module, blade):
    """Delete cross-origin resource sharing policy or rule"""
    api_version = list(blade.get_versions().items)
    changed = True
    if not module.check_mode:
        if module.params["rule"]:
            if CONTEXT_API_VERSION in api_version:
                res = blade.get_buckets_cross_origin_resource_sharing_policies_rules(
                    bucket_names=[module.params["name"]],
                    names=[module.params["rule"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.get_buckets_cross_origin_resource_sharing_policies_rules(
                    bucket_names=[module.params["name"]], names=[module.params["rule"]]
                )
            if res.status_code == 200:
                changed = False
                module.exit_json(changed=changed)

            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_buckets_cross_origin_resource_sharing_policies_rules(
                    names=module.params["rule"],
                    bucket_names=module.params["name"],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_buckets_cross_origin_resource_sharing_policies_rules(
                    names=module.params["rule"], bucket_names=module.params["name"]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete CORS rule {0} for bucket {1}. Error: {2}".format(
                        module.params["rule"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
        else:
            if CONTEXT_API_VERSION in api_version:
                res = blade.get_buckets_cross_origin_resource_sharing_policies(
                    bucket_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.get_buckets_cross_origin_resource_sharing_policies(
                    bucket_names=[module.params["name"]],
                )
            if res.total_item_count == 0:
                changed = False
                module.exit_json(changed=changed)

            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_buckets_cross_origin_resource_sharing_policies(
                    bucket_names=module.params["name"],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_buckets_cross_origin_resource_sharing_policies(
                    bucket_names=module.params["name"]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete CORS policy for bucket {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )

    module.exit_json(changed=changed)


def delete_access_policy(module, blade):
    """Delete bucket access policy or rule"""

    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if module.params["rule"]:
            if CONTEXT_API_VERSION in api_version:
                res = blade.get_buckets_bucket_access_policies_rules(
                    bucket_names=[module.params["name"]],
                    names=[module.params["rule"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.get_buckets_bucket_access_policies_rules(
                    bucket_names=[module.params["name"]], names=[module.params["rule"]]
                )
            if res.status_code != 200:
                changed = False
                module.exit_json(changed=changed)

            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_buckets_bucket_access_policies_rules(
                    names=module.params["rule"],
                    bucket_names=module.params["name"],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_buckets_bucket_access_policies_rules(
                    names=module.params["rule"], bucket_names=module.params["name"]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete access rule {0} for bucket {1}. Error: {2}".format(
                        module.params["rule"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
        else:
            if CONTEXT_API_VERSION in api_version:
                res = blade.get_buckets_bucket_access_policies(
                    bucket_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.get_buckets_bucket_access_policies(
                    bucket_names=[module.params["name"]]
                )
            if res.total_item_count == 0:
                changed = False
                module.exit_json(changed=changed)

            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_buckets_bucket_access_policies(
                    bucket_names=module.params["name"],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_buckets_bucket_access_policies(
                    bucket_names=module.params["name"]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete access policy for bucket {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )

    module.exit_json(changed=changed)


def create_access_policy(module, blade):
    """Create bucket access policy or rule"""
    changed = False
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_buckets_bucket_access_policies(
            bucket_names=[module.params["name"]],
            context_names=[module.params["context"]],
        )
    else:
        res = blade.get_buckets_bucket_access_policies(
            bucket_names=[module.params["name"]]
        )
    if res.total_item_count == 0:
        # Need to create the policy with its first rule
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_buckets_bucket_access_policies(
                    bucket_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_buckets_bucket_access_policies(
                    bucket_names=[module.params["name"]]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create initial bucket access policy for {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    # Create a new rule for the policy
    if not module.check_mode:
        changed = True
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_buckets_bucket_access_policies_rules(
                bucket_names=[module.params["name"]],
                names=[module.params["rule"]],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_buckets_bucket_access_policies_rules(
                bucket_names=[module.params["name"]], names=[module.params["rule"]]
            )
        if res.status_code == 200:
            changed = False
            module.exit_json(changed=changed)

        all_resources = []
        for resource in module.params["resources"]:
            all_resources.append(module.params["name"] + "/" + resource)
        if CONTEXT_API_VERSION in api_version:
            res = blade.post_buckets_bucket_access_policies_rules(
                bucket_names=[module.params["name"]],
                names=module.params["rule"],
                rule=BucketAccessPolicyRulePost(
                    effect=module.params["effect"],
                    resources=all_resources,
                    actions=module.params["actions"],
                    principals=BucketAccessPolicyRulePrincipal(
                        all=module.params["principals"]
                    ),
                ),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.post_buckets_bucket_access_policies_rules(
                bucket_names=[module.params["name"]],
                names=module.params["rule"],
                rule=BucketAccessPolicyRulePost(
                    effect=module.params["effect"],
                    resources=all_resources,
                    actions=module.params["actions"],
                    principals=BucketAccessPolicyRulePrincipal(
                        all=module.params["principals"]
                    ),
                ),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create access policy rule {0} "
                "in policy {1}. Error: {2}".format(
                    module.params["rule"], module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_cors_policy(module, blade):
    """Create CORS policy or rule"""
    changed = False
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_buckets_cross_origin_resource_sharing_policies(
            bucket_names=[module.params["name"]],
            context_names=[module.params["context"]],
        )
    else:
        res = blade.get_buckets_cross_origin_resource_sharing_policies(
            bucket_names=[module.params["name"]]
        )
    if res.total_item_count == 0:
        # Need to create the policy with its first rule
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_buckets_cross_origin_resource_sharing_policies(
                    bucket_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_buckets_cross_origin_resource_sharing_policies(
                    bucket_names=[module.params["name"]]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create initial CORS policy for {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    # Create a new rule for the policy
    if not module.check_mode:
        changed = True
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_buckets_cross_origin_resource_sharing_policies_rules(
                bucket_names=[module.params["name"]],
                names=[module.params["rule"]],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_buckets_cross_origin_resource_sharing_policies_rules(
                bucket_names=[module.params["name"]], names=[module.params["rule"]]
            )
        if res.status_code == 200:
            changed = False
            module.exit_json(changed=changed)

        if CONTEXT_API_VERSION in api_version:
            res = blade.post_buckets_cross_origin_resource_sharing_policies_rules(
                bucket_names=[module.params["name"]],
                names=module.params["rule"],
                rule=CrossOriginResourceSharingPolicyRulePost(
                    allowed_methods=module.params["methods"],
                    allowed_origins=module.params["origins"],
                    allowed_headers=module.params["headers"],
                ),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.post_buckets_cross_origin_resource_sharing_policies_rules(
                bucket_names=[module.params["name"]],
                names=module.params["rule"],
                rule=CrossOriginResourceSharingPolicyRulePost(
                    allowed_methods=module.params["methods"],
                    allowed_origins=module.params["origins"],
                    allowed_headers=module.params["headers"],
                ),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create CORS policy rule {0} "
                "in policy {1}. Error: {2}".format(
                    module.params["rule"], module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            context=dict(type="str", default=""),
            policy_type=dict(
                type="str",
                default="access",
                choices=[
                    "access",
                    "cors",
                ],
            ),
            name=dict(type="str", required=True),
            rule=dict(type="str"),
            resources=dict(type="list", elements="str", default=["*"]),
            effect=dict(
                type="str",
                default="allow",
                choices=[
                    "allow",
                    "deny",
                ],
            ),
            methods=dict(
                type="list",
                elements="str",
                default=["GET", "PUT", "HEAD", "POST", "DELETE"],
                choices=[
                    # Only currently allowed option is:
                    # GET, PUT, HEAD, POST, DELETE
                    "GET",
                    "PUT",
                    "HEAD",
                    "POST",
                    "DELETE",
                ],
            ),
            principals=dict(type="bool", default="True"),
            origins=dict(type="list", elements="str", default=["*"]),
            headers=dict(type="list", elements="str", default=["*"]),
            actions=dict(
                type="list",
                elements="str",
                default="s3:GetObject",
                choices=[
                    "s3:*",
                    "s3:AbortMultipartUpload",
                    "s3:BypassGovernanceRetention",
                    "s3:CreateBucket",
                    "s3:DeleteBucket",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                    "s3:ExtendSafemodeRetentionPeriod",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation",
                    "s3:GetBucketVersioning",
                    "s3:GetLifecycleConfiguration",
                    "s3:GetObject",
                    "s3:GetObjectAcl",
                    "s3:GetObjectLegalHold",
                    "s3:GetObjectLockConfiguration",
                    "s3:GetObjectRetention",
                    "s3:GetObjectTagging",
                    "s3:GetObjectVersion",
                    "s3:GetObjectVersionTagging",
                    "s3:ListAllMyBuckets",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:ListBucketVersions",
                    "s3:ListMultipartUploadParts",
                    "s3:PutBucketVersioning",
                    "s3:PutLifecycleConfiguration",
                    "s3:PutObject",
                    "s3:PutObjectLegalHold",
                    "s3:PutObjectLockConfiguration",
                    "s3:PutObjectRetention",
                    "s3:ResolveSafemodeConflicts",
                ],
            ),
        )
    )

    required_if = [["state", "present", ["rule"]]]
    module = AnsibleModule(
        argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    state = module.params["state"]
    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")
    blade = get_system(module)
    api_version = list(blade.get_versions().items)
    if MIN_API_VERSION not in api_version:
        module.fail_json(
            msg=(
                "Minimum FlashBlade REST version required: {0}".format(MIN_API_VERSION)
            )
        )
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_buckets(
            names=[module.params["name"]],
            destroyed=False,
            context_names=[module.params["context"]],
        )
    else:
        res = blade.get_buckets(names=[module.params["name"]], destroyed=False)
    if res.status_code != 200:
        module.fail_json(
            msg="Bucket {0} does not exist, or is destroyed.".format(
                module.params["name"]
            )
        )
    if module.params["policy_type"] == "access":
        if state == "present":
            create_access_policy(module, blade)
        else:
            delete_access_policy(module, blade)
    else:
        if state == "present":
            create_cors_policy(module, blade)
        else:
            delete_cors_policy(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
