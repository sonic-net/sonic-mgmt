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
module: purefa_offload
version_added: '1.0.0'
short_description: Create, modify and delete NFS, S3 or Azure offload targets
description:
- Create, modify and delete NFS, S3, Azure or GCP offload targets.
- You must have a correctly configured offload app installed and a correctly configured offload network for offload to work.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Define state of offload
    default: present
    choices: [ absent, present ]
    type: str
  name:
    description:
    - The name of the offload target
    required: true
    type: str
  protocol:
    description:
    - Define which protocol the offload engine uses
    - NFS is not a supported protocl from Purity//FA 6.6.0 and higher
    default: nfs
    choices: [ nfs, s3, azure, gcp ]
    type: str
  address:
    description:
    - The IP or FQDN address of the NFS server
    type: str
  share:
    description:
    - NFS export on the NFS server
    type: str
  options:
    description:
    - Additonal mount options for the NFS share
    - Supported mount options include I(port), I(rsize),
      I(wsize), I(nfsvers), and I(tcp) or I(udp)
    required: false
    default: ""
    type: str
  access_key:
    description:
    - Access Key ID of the offload target
    type: str
  container:
    description:
    - Name of the blob container of the Azure target
    default: offload
    type: str
  bucket:
    description:
    - Name of the bucket for the S3 or GCP target
    type: str
  account:
    description:
    - Name of the Azure blob storage account
    type: str
  secret:
    description:
    - Secret Access Key for the offload target
    type: str
  initialize:
    description:
    - Define whether to initialize the offload bucket
    type: bool
    default: true
  placement:
    description:
    - AWS S3 placement strategy
    type: str
    choices: ['retention-based', 'aws-standard-class', 'aws-intelligent-tiering']
    default: retention-based
  profile:
    description:
    - The Offload target profile that will be selected for this target.
    - This option allows more granular configuration for the target on top
      of the protocol parameter
    type: str
    version_added: '1.21.0'
    choices: ['azure', 'gcp', 'nfs', 'nfs-flashblade', 's3-aws', 's3-flashblade', 's3-scality-ring', 's3-wasabi-pay-as-you-go', 's3-wasabi-rcs', 's3-other']
  uri:
    description:
    - The URI used to create a connection between the array and a non-AWS S3 offload target.
    - Storage placement strategies are not supported for non-AWS S3 offload targets.
    - Both the HTTP and HTTPS protocols are allowed.
    type: str
    version_added: '1.32.0'
  auth_region:
    description:
    - The region that will be used for initial authentication request.
    - This parameter is optional and should be used only when region autodetection fails.
    type: str
    version_added: '1.32.0'
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
- name: Create NFS offload target
  purestorage.flasharray.purefa_offload:
    name: nfs-offload
    protocol: nfs
    address: 10.21.200.4
    share: "/offload_target"
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create S3 offload target
  purestorage.flasharray.purefa_offload:
    name: s3-offload
    protocol: s3
    access_key: "3794fb12c6204e19195f"
    bucket: offload-bucket
    secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    placement: aws-standard-class
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create Azure offload target
  purestorage.flasharray.purefa_offload:
    name: azure-offload
    protocol: azure
    secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    container: offload-container
    account: user1
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete offload target
  purestorage.flasharray.purefa_offload:
    name: nfs-offload
    protocol: nfs
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""


HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import (
        OffloadAzure,
        OffloadGoogleCloud,
        OffloadNfs,
        OffloadPost,
        OffloadS3,
    )
except ImportError:
    HAS_PURESTORAGE = False

import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

REGEX_TARGET_NAME = re.compile(r"^[a-zA-Z0-9\-]*$")
MULTIOFFLOAD_LIMIT = 1
PROFILE_API_VERSION = "2.25"
NO_SNAP2NFS_VERSION = "2.27"
CONTEXT_VERSION = "2.38"


def get_target(module, array):
    """Return target or None"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_offloads(
            names=[module.params["name"]], context_names=[module.params["context"]]
        )
    else:
        res = array.get_offloads(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def create_offload(module, array):
    """Create offload target"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        if module.params["protocol"] == "gcp":
            if PROFILE_API_VERSION in api_version and module.params["profile"]:
                bucket = OffloadGoogleCloud(
                    access_key_id=module.params["access_key"],
                    bucket=module.params["bucket"],
                    secret_access_key=module.params["secret"],
                    profile=module.params["profile"],
                )
            else:
                bucket = OffloadGoogleCloud(
                    access_key_id=module.params["access_key"],
                    bucket=module.params["bucket"],
                    secret_access_key=module.params["secret"],
                )
            offload = OffloadPost(google_cloud=bucket)
        if module.params["protocol"] == "azure":
            if PROFILE_API_VERSION in api_version and module.params["profile"]:
                bucket = OffloadAzure(
                    container_name=module.params["container"],
                    secret_access_key=module.params["secret"],
                    account_name=module.params[".bucket"],
                    profile=module.params["profile"],
                )
            else:
                bucket = OffloadAzure(
                    container_name=module.params["container"],
                    secret_access_key=module.params["secret"],
                    account_name=module.params["bucket"],
                )
            offload = OffloadPost(azure=bucket)
        if module.params["protocol"] == "s3":
            if PROFILE_API_VERSION in api_version and module.params["profile"]:
                if module.params["auth_region"]:
                    bucket = OffloadS3(
                        access_key_id=module.params["access_key"],
                        bucket=module.params["bucket"],
                        secret_access_key=module.params["secret"],
                        profile=module.params["profile"],
                        uri=module.params["uri"],
                        auth_region=module.params["auth_region"],
                    )
                else:
                    bucket = OffloadS3(
                        access_key_id=module.params["access_key"],
                        bucket=module.params["bucket"],
                        secret_access_key=module.params["secret"],
                        profile=module.params["profile"],
                        uri=module.params["uri"],
                    )
            else:
                bucket = OffloadS3(
                    access_key_id=module.params["access_key"],
                    bucket=module.params["bucket"],
                    secret_access_key=module.params["secret"],
                    uri=module.params["uri"],
                )
            offload = OffloadPost(s3=bucket)
        if module.params["protocol"] == "nfs":
            if PROFILE_API_VERSION in api_version and module.params["profile"]:
                bucket = OffloadNfs(
                    mount_point=module.params["share"],
                    address=module.params["address"],
                    mount_options=module.params["options"],
                    profile=module.params["profile"],
                )
            else:
                bucket = OffloadNfs(
                    mount_point=module.params["share"],
                    address=module.params["address"],
                    mount_options=module.params["options"],
                )
            offload = OffloadPost(nfs=bucket)
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.post_offloads(
                offload=offload,
                initialize=module.params["initialize"],
                names=[module.params["name"]],
                context_names=[module.params["context"]],
            )
        else:
            res = array.post_offloads(
                offload=offload,
                initialize=module.params["initialize"],
                names=[module.params["name"]],
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create {0} offload {1}. Error: {2}"
                "Please perform diagnostic checks.".format(
                    module.params["protocol"].upper(),
                    module.params["name"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def update_offload(module, array):
    """Update offload target"""
    changed = False
    module.exit_json(changed=changed)


def delete_offload(module, array):
    """Delete offload target"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.delete_offloads(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = array.delete_offloads(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete offload {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
            protocol=dict(
                type="str", default="nfs", choices=["nfs", "s3", "azure", "gcp"]
            ),
            placement=dict(
                type="str",
                default="retention-based",
                choices=[
                    "retention-based",
                    "aws-standard-class",
                    "aws-intelligent-tiering",
                ],
            ),
            profile=dict(
                type="str",
                choices=[
                    "azure",
                    "gcp",
                    "nfs",
                    "nfs-flashblade",
                    "s3-aws",
                    "s3-flashblade",
                    "s3-scality-ring",
                    "s3-wasabi-pay-as-you-go",
                    "s3-wasabi-rcs",
                    "s3-other",
                ],
            ),
            name=dict(type="str", required=True),
            initialize=dict(default=True, type="bool"),
            access_key=dict(type="str", no_log=False),
            secret=dict(type="str", no_log=True),
            bucket=dict(type="str"),
            container=dict(type="str", default="offload"),
            account=dict(type="str"),
            share=dict(type="str"),
            address=dict(type="str"),
            options=dict(type="str", default=""),
            uri=dict(type="str"),
            auth_region=dict(type="str"),
            context=dict(type="str", default=""),
        )
    )

    required_if = []

    if argument_spec["state"] == "present":
        required_if = [
            ("protocol", "nfs", ["address", "share"]),
            ("protocol", "s3", ["access_key", "secret", "bucket"]),
            ["protocol", "gcp", ["access_key", "secret", "bucket"]],
            ("protocol", "azure", ["account", "secret"]),
        ]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()

    if (
        LooseVersion(NO_SNAP2NFS_VERSION) <= LooseVersion(api_version)
        and module.params["protocol"] == "nfs"
    ):
        module.fail_json(
            msg="NFS offload target is not supported from Purity//FA 6.6.0 and higher"
        )
    if (
        (
            module.params["protocol"].lower() == "azure"
            and module.params["profile"] != "azure"
        )
        or (
            module.params["protocol"].lower() == "gcp"
            and module.params["profile"] != "gcp"
        )
        or (
            module.params["protocol"].lower() == "nfs"
            and module.params["profile"] not in ["nfs", "nfs-flashblade"]
        )
        or (
            module.params["protocol"].lower() == "s3"
            and module.params["profile"]
            not in [
                "s3-aws",
                "s3-flashblade",
                "s3-scality-ring",
                "s3-wasabi-pay-as-you-go",
                "s3-wasabi-rcs",
                "s3-other",
            ]
        )
    ):
        module.warn("Specified profile not valid, ignoring...")
        module.params["profile"] = None

    if (
        not re.match(r"^[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9]$", module.params["name"])
        or len(module.params["name"]) > 56
    ):
        module.fail_json(
            msg="Target name invalid. "
            "Target name must be between 1 and 56 characters (alphanumeric and -) in length "
            "and begin and end with a letter or number. The name must include at least one letter."
        )
    if module.params["protocol"] in ["s3", "gcp"]:
        if (
            not re.match(r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$", module.params["bucket"])
            or len(module.params["bucket"]) > 63
        ):
            module.fail_json(
                msg="Bucket name invalid. "
                "Bucket name must be between 3 and 63 characters "
                "(lowercase, alphanumeric, dash or period) in length "
                "and begin and end with a letter or number."
            )

    target = get_target(module, array)
    if module.params["state"] == "present" and not target:
        offloads = list(array.get_offloads().items)
        if len(offloads) >= MULTIOFFLOAD_LIMIT:
            module.fail_json(
                msg="Cannot add offload target {0}. "
                "Offload Target Limit of {1} would be exceeded.".format(
                    module.params["name"], MULTIOFFLOAD_LIMIT
                )
            )
        if offloads and offloads[0].protocol != module.params["protocol"]:
            module.fail_json(msg="Currently all offloads must be of the same type.")
        create_offload(module, array)
    elif module.params["state"] == "present" and target:
        update_offload(module, array)
    elif module.params["state"] == "absent" and target:
        delete_offload(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
