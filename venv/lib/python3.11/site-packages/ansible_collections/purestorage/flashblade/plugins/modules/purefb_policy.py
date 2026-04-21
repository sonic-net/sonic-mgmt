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
module: purefb_policy
version_added: '1.0.0'
short_description: Manage FlashBlade policies
description:
- Manage policies for filesystem, file replica links and object store access.
- To update an existing snapshot policy rule, you must first delete the
  original rule and then add the new rule to replace it. Purity's best-fit
  will try to ensure that any required snapshots deleted on the deletion of
  the first rule will be recovered as long replacement rule is added before
  the snapshot eradication period is exceeded (usuually 24 hours).
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete policy.
    - Copy is applicable only to Object Store Access Policies Rules
    default: present
    type: str
    choices: [ absent, present, copy ]
  target:
    description:
    - Name of policy to copy rule to
    type: str
    version_added: "1.9.0"
  target_rule:
    description:
    - Name of the rule to copy the exisitng rule to.
    - If not defined the existing rule name is used.
    type: str
    version_added: "1.9.0"
  policy_type:
    description:
    - Type of policy
    default: snapshot
    type: str
    choices: [ snapshot, access, nfs, smb_share, smb_client, network, worm ]
    version_added: "1.9.0"
  account:
    description:
    - Name of Object Store account policy applies to.
    - B(Special Case) I(pure policy) is used for the system-wide S3 policies
    type: str
    version_added: "1.9.0"
  rule:
    description:
    - Name of the rule for the Object Store Access Policy
    - Rules in system wide policies cannot be deleted or modified
    type: str
    version_added: "1.9.0"
  effect:
    description:
    - Allow S3 requests that match all of the I(actions) item selected.
      Rules are additive.
    type: str
    default: allow
    choices: [ allow, deny ]
    version_added: "1.9.0"
  actions:
    description:
    - List of permissions to grant.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
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
    version_added: "1.9.0"
  object_resources:
    description:
    - List of bucket names and object paths, with a wildcard (*) to
      specify objects in a bucket; e.g., bucket1, bucket1/*, bucket2,
      bucket2/*.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  source_ips:
    description:
    - List of IPs and subnets from which this rule should allow requests;
      e.g., 10.20.30.40, 10.20.30.0/24, 2001:DB8:1234:5678::/64.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  s3_prefixes:
    description:
    - List of 'folders' (object key prefixes) for which object listings
      may be requested.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  s3_delimiters:
    description:
    - List of delimiter characters allowed in object list requests.
    - Grants permissions to list 'folder names' (prefixes ending in a
      delimiter) instead of object keys.
    - System-wide policy rules cannot be deleted or modified
    type: list
    elements: str
    version_added: "1.9.0"
  ignore_enforcement:
    description:
    - Certain combinations of actions and other rule elements are inherently
      ignored if specified together in a rule.
    - If set to true, operations which attempt to set these combinations will fail.
    - If set to false, such operations will instead be allowed.
    type: bool
    default: true
    version_added: "1.9.0"
  user:
    description:
    - User in the I(account) that the policy is granted to.
    type: str
    version_added: "1.9.0"
  force_delete:
    description:
    - Force the deletion of a Object Store Access Policy is this
      has attached users.
    - WARNING This can have undesired side-effects.
    - System-wide policies cannot be deleted
    type: bool
    default: false
    version_added: "1.9.0"
  name:
    description:
    - Name of the policy
    type: str
  enabled:
    description:
    - State of policy
    type: bool
    default: true
  every:
    description:
    - Interval between snapshots in seconds
    - Range available 300 - 31536000 (equates to 5m to 365d)
    type: int
  keep_for:
    description:
    - How long to keep snapshots for
    - Range available 300 - 31536000 (equates to 5m to 365d)
    - Must not be set less than I(every)
    type: int
  at:
    description:
    - Provide a time in 12-hour AM/PM format, eg. 11AM
    type: str
  timezone:
    description:
    - Time Zone used for the I(at) parameter
    - If not provided, the module will attempt to get the current local timezone from the server
    type: str
  filesystem:
    description:
    - List of filesystems to add to a policy on creation
    - To amend policy members use the I(purestorage.flashblade.purefb_fs) module
    type: list
    elements: str
  replica_link:
    description:
    - List of filesystem replica links to add to a policy on creation
    - To amend policy members use the I(purestorage.flashblade.purefb_fs_replica) module
    type: list
    elements: str
  access:
    description:
    - Specifies access control for the export policy rule
    type: str
    choices: [ root-squash, all-squash, no-squash ]
    default: root-squash
    version_added: "1.9.0"
  anonuid:
    description:
    - Any user whose UID is affected by an I(access) of `root_squash` or `all_squash`
      will have their UID mapped to anonuid.
      The default is null, which means 65534.
      Use "" to clear.
    type: str
    version_added: "1.9.0"
  anongid:
    description:
    - Any user whose GID is affected by an I(access) of `root_squash` or `all_squash`
      will have their GID mapped to anongid.
      The default anongid is null, which means 65534.
      Use "" to clear.
    type: str
    version_added: "1.9.0"
  atime:
    description:
    - After a read operation has occurred, the inode access time is updated only if any
      of the following conditions is true; the previous access time is less than the
      inode modify time, the previous access time is less than the inode change time,
      or the previous access time is more than 24 hours ago.
    - If set to false, disables the update of inode access times after read operations.
    type: bool
    default: true
    version_added: "1.9.0"
  client:
    description:
    - Specifies the clients that will be permitted to access the export.
    - Accepted notation is a single IP address, subnet in CIDR notation, netgroup, or
      anonymous (*).
    type: str
    version_added: "1.9.0"
  fileid_32bit:
    description:
    - Whether the file id is 32 bits or not.
    type: bool
    default: false
    version_added: "1.9.0"
  permission:
    description:
    - Specifies which read-write client access permissions are allowed for the export.
    type: str
    choices: [ rw, ro ]
    default: ro
    version_added: "1.9.0"
  secure:
    description:
    - If true, this prevents NFS access to client connections coming from non-reserved ports.
    - If false, allows NFS access to client connections coming from non-reserved ports.
    - Applies to NFSv3, NFSv4.1, and auxiliary protocols MOUNT and NLM.
    type: bool
    default: false
    version_added: "1.9.0"
  security:
    description:
    - The security flavors to use for accessing files on this mount point.
    - If the server does not support the requested flavor, the mount operation fails.
    - I(sys) trusts the client to specify users identity.
    - I(krb) provides cryptographic proof of a users identity in each RPC request.
    - I(krb5i) adds integrity checking to krb5, to ensure the data has not been tampered with.
    - I(krb5p) adds integrity checking and encryption to krb5.
    type: list
    elements: str
    choices: [ sys, krb5, krb5i, krb5p ]
    default: sys
    version_added: "1.9.0"
  before_rule:
    description:
    - The index of the client rule to insert or move a client rule before.
    type: int
    version_added: "1.9.0"
  rename:
    description:
    - New name for policy
    - Only applies to NFS and SMB policies
    type: str
    version_added: "1.10.0"
  destroy_snapshots:
    description:
    - This parameter must be set to true in order to modify a policy such that local or remote snapshots would be destroyed.
    type: bool
    version_added: '1.11.0'
    default: false
  principal:
    description:
     - The user or group who is the subject of this rule, and their domain
    type: str
    version_added: '1.12.0'
  change:
    description:
     - The state of the SMB share principals Change access permission.
     - Setting to "" will clear the current setting
    type: str
    choices: [ allow, deny, "" ]
    version_added: '1.12.0'
  read:
    description:
     - The state of the SMB share principals Read access permission.
     - Setting to "" will clear the current setting
    type: str
    choices: [ allow, deny, "" ]
    version_added: '1.12.0'
  full_control:
    description:
     - The state of the SMB share principals Full Control access permission.
     - Setting to "" will clear the current setting
    type: str
    choices: [ allow, deny, "" ]
    version_added: '1.12.0'
  smb_encryption:
    description:
     - The status of SMB encryption in a client policy rule
    type: str
    choices: [ disabled, optional, required ]
    default: optional
    version_added: '1.12.0'
  desc:
    description:
    - A description of an object store policy,
      optionally specified when the policy is created.
    - Cannot be modified for an existing policy.
    type: str
    default: ""
    version_added: '1.14.0'
  interfaces:
    description:
    - Specifies which product interfaces the network access policy rule
      applies to, whether it is permitting or denying access.
    type: list
    elements: str
    choices: [ "management-ssh", "management-rest-api", "management-web-ui", "snmp", "local-network-superuser-password-access" ]
    version_added: '1.17.0'
  max_retention:
    description:
      - The maximum retention period of the WORM file system.
      - Between 1 second and 100 years.
      - Cannot be less than the I(min_retention).
      - Valid values are weeks (w), days(d), hours(h), minutes(m) and seconds(s).
    type: str
    version_added: '1.19.0'
  min_retention:
    description:
      - The minimum retention period of the WORM file system.
      - Between 1 second and 100 years.
      - Cannot be greater than the I(max_retention).
      - Valid values are weeks (w), days(d), hours(h), minutes(m) and seconds(s).
    type: str
    version_added: '1.19.0'
  default_retention:
    description:
      - The retention period used for committing files to WORM status.
        Will be applied if no access time is provided, or the access time is less than the current server time.
        Between I(min_retention) and I(max_retention) periods.
      - Valid values are weeks (w), days(d), hours(h), minutes(m) and seconds(s).
    type: str
    version_added: '1.19.0'
  retention_lock:
    description:
      - State of policy attributes after creation.
      - If set to I(locked) then values of the policy attributes are not allowed to change.
      - If set to I(locked) then values of the policy attributes can be changed.
      - Changing from I(unlocked) to I(locked) is allowed, but to change from I(locked) to I(unlocked)
        will require support from Pure Storage Technical Services.
    type: str
    choices: [ locked, unlocked ]
    version_added: '1.19.0'
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
- name: Create a simple snapshot policy with no rules
  purestorage.flashblade.purefb_policy:
    name: test_policy
    policy_type: snapshot
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a snapshot policy and connect to existing filesystems and filesystem replica links
  purestorage.flashblade.purefb_policy:
    name: test_policy_with_members
    policy_type: snapshot
    filesystem:
    - fs1
    - fs2
    replica_link:
    - rl1
    - rl2
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a snapshot policy with rules
  purestorage.flashblade.purefb_policy:
    name: test_policy2
    policy_type: snapshot
    at: 11AM
    keep_for: 86400
    every: 86400
    timezone: Asia/Shanghai
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete filesystem foo from snapshot policy
  purestorage.flashblade.purefb_policy:
    name: test_policy
    policy_type: snapshot
    filesystem: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a snapshot policy
  purestorage.flashblade.purefb_policy:
    name: test_policy
    policy_type: snapshot
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an empty object store access policy
  purestorage.flashblade.purefb_policy:
    name: test_os_policy
    account: test
    policy_type: access
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an empty object store access policy and assign user
  purestorage.flashblade.purefb_policy:
    name: test_os_policy
    account: test
    policy_type: access
    user: fred
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a object store access policy with simple rule
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    policy_type: access
    account: test
    rule: rule1
    actions: "s3:*"
    object_resources: "*"
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an empty SMB client policy
  purestorage.flashblade.purefb_policy:
    name: test_smb_client
    policy_type: smb_client
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an SMB client policy with a client rule
  purestorage.flashblade.purefb_policy:
    name: test_smb_client
    policy_type: smb_client
    client: "10.0.1.0/24"
    permission: rw
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an empty NFS export policy
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    policy_type: nfs
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create an NFS export policy with a client rule
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    policy_type: nfs
    atime: true
    client: "10.0.1.0/24"
    secure: true
    security: [sys, krb5]
    permission: rw
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a new rule for an existing NFS export policy
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    policy_type: nfs
    atime: true
    client: "10.0.2.0/24"
    security: sys
    permission: ro
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a client rule from an NFS export policy
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    client: "10.0.1.0/24"
    policy_type: nfs
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete an NFS export policy and all associated rules
  purestorage.flashblade.purefb_policy:
    name: test_nfs_export
    state: absent
    policy_type: nfs
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a rule from an object store access policy
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    account: test
    policy_type: access
    rule: rule1
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete a user from an object store access policy
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    account: test
    user: fred
    policy_type: access
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete an object store access policy with attached users (USE WITH CAUTION)
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    account: test
    policy_type: access
    force_delete: true
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Delete an object store access policy with no attached users
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    account: test
    policy_type: access
    state: absent
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Copy an object store access policy rule to another exisitng policy
  purestorage.flashblade.purefb_policy:
    name: test_os_policy_rule
    policy_type: access
    account: test
    target: "account2/anotherpolicy"
    target_rule: new_rule1
    state: copy
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Rename an NFS Export Policy
  purestorage.flashblade.purefb_policy:
    name: old_name
    policy_type: nfs
    rename: new_name
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
- name: Create a WORM Data Policy
  purestorage.flashblade.purefb_policy:
    name: worm1
    policy_type: worm
    default_retention: 5d
    min_rentetion: 20h
    max_retention: 1y
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import (
        PolicyRuleObjectAccessCondition,
        PolicyRuleObjectAccessPost,
        PolicyRuleObjectAccess,
        NfsExportPolicy,
        NfsExportPolicyRule,
        Policy,
        PolicyPatch,
        PolicyRule,
        SmbSharePolicyRule,
        SmbSharePolicy,
        SmbClientPolicyRule,
        SmbClientPolicy,
        ObjectStoreAccessPolicyPost,
        NetworkAccessPolicy,
        NetworkAccessPolicyRule,
        WormDataPolicy,
    )
except ImportError:
    HAS_PYPURECLIENT = False

HAS_PYTZ = True
try:
    import pytz
except ImportError:
    HAS_PYTX = False

import os
import re
import platform

from ansible.module_utils.common.process import get_bin_path
from ansible.module_utils.facts.utils import get_file_content
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)
from ansible_collections.purestorage.flashblade.plugins.module_utils.common import (
    convert_time_to_millisecs,
)

NFS_POLICY_API_VERSION = "2.3"
NFS_RENAME_API_VERSION = "2.4"
SMB_POLICY_API_VERSION = "2.10"
SMB_ENCRYPT_API_VERSION = "2.11"
NET_POLICY_API_VERSION = "2.13"
WORM_POLICY_API_VERSION = "2.15"
CONTEXT_API_VERSION = "2.17"


def _convert_to_millisecs(hour_str: str) -> int:
    """Convert a 12-hour formatted time string (e.g., '02AM', '12PM') to milliseconds since midnight."""
    time_part = int(hour_str[:-2])
    period = hour_str[-2:]

    if period == "AM":
        return 0 if time_part == 12 else time_part * 3600000
    else:  # PM
        return 12 * 3600000 if time_part == 12 else (time_part + 12) * 3600000


def _findstr(text, match):
    for line in text.splitlines():
        if match in line:
            found = line
    return found


def _get_local_tz(module, timezone="UTC"):
    """
    We will attempt to get the local timezone of the server running the module and use that.
    If we can't get the timezone then we will set the default to be UTC

    Linnux has been tested and other opersting systems should be OK.
    Failures cause assumption of UTC

    Windows is not supported and will assume UTC
    """
    if platform.system() == "Linux":
        timedatectl = get_bin_path("timedatectl")
        if timedatectl is not None:
            rcode, stdout, stderr = module.run_command(timedatectl)
            if rcode == 0 and stdout:
                line = _findstr(stdout, "Time zone")
                full_tz = line.split(":", 1)[1].rstrip()
                timezone = full_tz.split()[0]
                return timezone
            else:
                module.warn("Incorrect timedatectl output. Timezone will be set to UTC")
        else:
            if os.path.exists("/etc/timezone"):
                timezone = get_file_content("/etc/timezone")
            else:
                module.warn("Could not find /etc/timezone. Assuming UTC")

    elif platform.system() == "SunOS":
        if os.path.exists("/etc/default/init"):
            for line in get_file_content("/etc/default/init", "").splitlines():
                if line.startswith("TZ="):
                    timezone = line.split("=", 1)[1]
                    return timezone
        else:
            module.warn("Could not find /etc/default/init. Assuming UTC")

    elif re.match("^Darwin", platform.platform()):
        systemsetup = get_bin_path("systemsetup")
        if systemsetup is not None:
            rcode, stdout, stderr = module.execute(systemsetup, "-gettimezone")
            if rcode == 0 and stdout:
                timezone = stdout.split(":", 1)[1].lstrip()
            else:
                module.warn("Could not run systemsetup. Assuming UTC")
        else:
            module.warn("Could not find systemsetup. Assuming UTC")

    elif re.match("^(Free|Net|Open)BSD", platform.platform()):
        if os.path.exists("/etc/timezone"):
            timezone = get_file_content("/etc/timezone")
        else:
            module.warn("Could not find /etc/timezone. Assuming UTC")

    elif platform.system() == "AIX":
        aix_oslevel = int(platform.version() + platform.release())
        if aix_oslevel >= 61:
            if os.path.exists("/etc/environment"):
                for line in get_file_content("/etc/environment", "").splitlines():
                    if line.startswith("TZ="):
                        timezone = line.split("=", 1)[1]
                        return timezone
            else:
                module.warn("Could not find /etc/environment. Assuming UTC")
        else:
            module.warn(
                "Cannot determine timezone when AIX os level < 61. Assuming UTC"
            )

    else:
        module.warn("Could not find /etc/timezone. Assuming UTC")

    return timezone


def delete_smb_share_policy(module, blade):
    """Delete SMB Share Policy, or Rule

    If principal is provided then delete the principal rule if it exists.
    """

    changed = False
    versions = list(blade.get_versions().items)
    policy_delete = True
    if module.params["principal"]:
        policy_delete = False
        if CONTEXT_API_VERSION in versions:
            prin_rule = blade.get_smb_share_policies_rules(
                policy_names=[module.params["name"]],
                filter="principal='" + module.params["principal"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            prin_rule = blade.get_smb_share_policies_rules(
                policy_names=[module.params["name"]],
                filter="principal='" + module.params["principal"] + "'",
            )
        if prin_rule.status_code == 200:
            rule = list(prin_rule.items)[0]
            changed = True
            if not module.check_mode:
                if CONTEXT_API_VERSION in versions:
                    res = blade.delete_smb_share_policies_rules(
                        names=[rule.name], context_names=[module.params["context"]]
                    )
                else:
                    res = blade.delete_smb_share_policies_rules(names=[rule.name])
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete rule for principal {0} in policy {1}. "
                        "Error: {2}".format(
                            module.params["principal"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
    if policy_delete:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in versions:
                res = blade.delete_smb_share_policies(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_smb_share_policies(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete SMB share policy {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def rename_smb_share_policy(module, blade):
    """Rename SMB Share Policy"""

    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.patch_smb_share_policies(
                names=[module.params["name"]],
                policy=SmbSharePolicy(name=module.params["rename"]),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.patch_smb_share_policies(
                names=[module.params["name"]],
                policy=SmbSharePolicy(name=module.params["rename"]),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to rename SMB share policy {0} to {1}. Error: {2}".format(
                    module.params["name"],
                    module.params["rename"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def create_smb_share_policy(module, blade):
    """Create SMB Share Policy"""
    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.post_smb_share_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = blade.post_smb_share_policies(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create SMB share policy {0}.Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if not module.params["enabled"]:
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_smb_share_policies(
                    policy=SmbSharePolicy(enabled=False),
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_smb_share_policies(
                    policy=SmbSharePolicy(enabled=False), names=[module.params["name"]]
                )
            if res.status_code != 200:
                if CONTEXT_API_VERSION in versions:
                    blade.delete_smb_share_policies(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    )
                else:
                    blade.delete_smb_share_policies(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to create SMB share policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        if not module.params["principal"]:
            module.fail_json(msg="principal is required to create a new rule")
        else:
            rule = SmbSharePolicyRule(
                principal=module.params["principal"],
                change=module.params["change"],
                read=module.params["read"],
                full_control=module.params["full_control"],
            )
            if CONTEXT_API_VERSION in versions:
                res = blade.post_smb_share_policies_rules(
                    policy_names=[module.params["name"]],
                    rule=rule,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_smb_share_policies_rules(
                    policy_names=[module.params["name"]],
                    rule=rule,
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create rule for policy {0}. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def update_smb_share_policy(module, blade):
    """Update SMB Share Policy Rule"""

    changed = False
    versions = list(blade.get_versions().items)
    if module.params["principal"]:
        if CONTEXT_API_VERSION in versions:
            current_policy_rule = blade.get_smb_share_policies_rules(
                policy_names=[module.params["name"]],
                filter="principal='" + module.params["principal"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            current_policy_rule = blade.get_smb_share_policies_rules(
                policy_names=[module.params["name"]],
                filter="principal='" + module.params["principal"] + "'",
            )
        if (
            current_policy_rule.status_code == 200
            and current_policy_rule.total_item_count == 0
        ):
            rule = SmbSharePolicyRule(
                principal=module.params["principal"],
                change=module.params["change"],
                read=module.params["read"],
                full_control=module.params["full_control"],
            )
            changed = True
            if not module.check_mode:
                if module.params["before_rule"]:
                    before_name = (
                        module.params["name"] + "." + str(module.params["before_rule"])
                    )
                    if CONTEXT_API_VERSION in versions:
                        res = blade.post_smb_share_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            before_rule_name=before_name,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.post_smb_share_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            before_rule_name=before_name,
                        )
                else:
                    if CONTEXT_API_VERSION in versions:
                        res = blade.post_smb_share_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.post_smb_share_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                        )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create rule for principal {0} "
                        "in policy {1}. Error: {2}".format(
                            module.params["principal"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
        else:
            rules = list(current_policy_rule.items)
            old_policy_rule = rules[0]
            current_rule = {
                "principal": sorted(old_policy_rule.principal),
                "read": sorted(old_policy_rule.read),
                "change": sorted(old_policy_rule.change),
                "full_control": sorted(old_policy_rule.full_control),
            }
            if module.params["read"]:
                if module.params["read"] == "":
                    new_read = ""
                else:
                    new_read = module.params["read"]
            else:
                new_read = current_rule["read"]
            if module.params["full_control"]:
                if module.params["full_control"] == "":
                    new_full_control = ""
                else:
                    new_full_control = module.params["full_control"]
            else:
                new_full_control = current_rule["full_control"]
            if module.params["change"]:
                if module.params["change"] == "":
                    new_change = ""
                else:
                    new_change = module.params["change"]
            else:
                new_change = current_rule["change"]
            if module.params["principal"]:
                new_principal = module.params["principal"]
            else:
                new_principal = current_rule["principal"]
            new_rule = {
                "principal": new_principal,
                "read": new_read,
                "change": new_change,
                "full_control": new_full_control,
            }
            if current_rule != new_rule:
                changed = True
                if not module.check_mode:
                    rule = SmbSharePolicyRule(
                        principal=module.params["principal"],
                        change=module.params["change"],
                        read=module.params["read"],
                        full_control=module.params["full_control"],
                    )
                    if CONTEXT_API_VERSION in versions:
                        res = blade.patch_smb_share_policies_rules(
                            names=[
                                module.params["name"] + "." + str(old_policy_rule.index)
                            ],
                            rule=rule,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.patch_smb_share_policies_rules(
                            names=[
                                module.params["name"] + "." + str(old_policy_rule.index)
                            ],
                            rule=rule,
                        )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to update SMB share rule {0}. Error: {1}".format(
                                module.params["name"]
                                + "."
                                + str(old_policy_rule.index),
                                res.errors[0].message,
                            )
                        )
            if (
                module.params["before_rule"]
                and module.params["before_rule"] != old_policy_rule.index
            ):
                changed = True
                if not module.check_mode:
                    before_name = (
                        module.params["name"] + "." + str(module.params["before_rule"])
                    )
                    if CONTEXT_API_VERSION in versions:
                        res = blade.patch_smb_share_policies_rules(
                            names=[
                                module.params["name"] + "." + str(old_policy_rule.index)
                            ],
                            rule=SmbSharePolicyRule(),
                            before_rule_name=before_name,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.patch_smb_share_policies_rules(
                            names=[
                                module.params["name"] + "." + str(old_policy_rule.index)
                            ],
                            rule=SmbSharePolicyRule(),
                            before_rule_name=before_name,
                        )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to move SMB share rule {0}. Error: {1}".format(
                                module.params["name"]
                                + "."
                                + str(old_policy_rule.index),
                                res.errors[0].message,
                            )
                        )
    if CONTEXT_API_VERSION in versions:
        current_policy = list(
            blade.get_smb_share_policies(names=[module.params["name"]]).items,
            context_names=[module.params["context"]],
        )[0]
    else:
        current_policy = list(
            blade.get_smb_share_policies(names=[module.params["name"]]).items
        )[0]
    if current_policy.enabled != module.params["enabled"]:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_smb_share_policies(
                    policy=SmbSharePolicy(enabled=module.params["enabled"]),
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_smb_share_policies(
                    policy=SmbSharePolicy(enabled=module.params["enabled"]),
                    names=[module.params["name"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change state of SMB share policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def delete_smb_client_policy(module, blade):
    """Delete SMB CLient Policy, or Rule

    If client is provided then delete the client rule if it exists.
    """

    changed = False
    versions = list(blade.get_versions().items)
    policy_delete = True
    if module.params["client"]:
        policy_delete = False
        if CONTEXT_API_VERSION in versions:
            res = blade.get_smb_client_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_smb_client_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
            )
        if res.status_code == 200:
            if res.total_item_count == 0:
                pass
            elif res.total_item_count == 1:
                rule = list(res.items)[0]
                if module.params["client"] == rule.client:
                    changed = True
                    if not module.check_mode:
                        if CONTEXT_API_VERSION in versions:
                            res = blade.delete_smb_client_policies_rules(
                                names=[rule.name],
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.delete_smb_client_policies_rules(
                                names=[rule.name]
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to delete rule for client {0} in policy {1}. "
                                "Error: {2}".format(
                                    module.params["client"],
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
            else:
                rules = list(res.items)
                for cli in range(len(rules)):
                    if rules[cli].client == "*":
                        changed = True
                        if not module.check_mode:
                            if CONTEXT_API_VERSION in versions:
                                res = blade.delete_smb_client_policies_rules(
                                    names=[rules[cli].name],
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.delete_smb_client_policies_rules(
                                    names=[rules[cli].name]
                                )
                            if res.status_code != 200:
                                module.fail_json(
                                    msg="Failed to delete rule for client {0} in policy {1}. "
                                    "Error: {2}".format(
                                        module.params["client"],
                                        module.params["name"],
                                        res.errors[0].message,
                                    )
                                )
    if policy_delete:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in versions:
                res = blade.delete_smb_client_policies(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_smb_client_policies(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete SMB client policy {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def rename_smb_client_policy(module, blade):
    """Rename SMB Client Policy"""

    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.patch_smb_client_policies(
                names=[module.params["name"]],
                policy=SmbClientPolicy(name=module.params["rename"]),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.patch_smb_client_policies(
                names=[module.params["name"]],
                policy=SmbClientPolicy(name=module.params["rename"]),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to rename SMB client policy {0} to {1}. Error: {2}".format(
                    module.params["name"],
                    module.params["rename"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def create_smb_client_policy(module, blade):
    """Create SMB Client Policy"""
    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.post_smb_client_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = blade.post_smb_client_policies(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create SMB client policy {0}.Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if not module.params["enabled"]:
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_smb_client_policies(
                    policy=SmbClientPolicy(enabled=False),
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_smb_client_policies(
                    policy=SmbClientPolicy(enabled=False), names=[module.params["name"]]
                )
            if res.status_code != 200:
                if CONTEXT_API_VERSION in versions:
                    blade.delete_smb_client_policies(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    )
                else:
                    blade.delete_smb_client_policies(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to create SMB client policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        if not module.params["client"]:
            module.fail_json(msg="client is required to create a new rule")
        else:
            if SMB_ENCRYPT_API_VERSION in versions:
                rule = SmbClientPolicyRule(
                    client=module.params["client"],
                    permission=module.params["permission"],
                    access=module.params["access"],
                    encryption=module.params["smb_encryption"],
                )
            else:
                rule = SmbClientPolicyRule(
                    client=module.params["client"],
                    access=module.params["access"],
                    permission=module.params["permission"],
                )
            if CONTEXT_API_VERSION in versions:
                res = blade.post_smb_client_policies_rules(
                    policy_names=[module.params["name"]],
                    rule=rule,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_smb_client_policies_rules(
                    policy_names=[module.params["name"]],
                    rule=rule,
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to rule for policy {0}. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def create_network_access_policy(module, blade):
    """Create Network Access Policy"""
    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.post_network_access_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = blade.post_network_access_policies(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create network access policy {0}.Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if not module.params["enabled"]:
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_network_access_policies(
                    policy=SmbClientPolicy(enabled=False),
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_network_access_policies(
                    policy=SmbClientPolicy(enabled=False), names=[module.params["name"]]
                )
            if res.status_code != 200:
                if CONTEXT_API_VERSION in versions:
                    blade.delete_network_access_policies(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    )
                else:
                    blade.delete_network_access_policies(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to create network access policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        if not module.params["client"]:
            module.fail_json(msg="client is required to create a new rule")
        else:
            rule = NetworkAccessPolicyRule(
                client=module.params["client"],
                effect=module.params["effect"],
                interfaces=module.params["interfaces"],
            )
            if CONTEXT_API_VERSION in versions:
                res = blade.post_network_access_policies_rules(
                    policy_names=[module.params["name"]],
                    rule=rule,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_network_access_policies_rules(
                    policy_names=[module.params["name"]],
                    rule=rule,
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to rule for policy {0}. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def create_worm_data_policy(module, blade):
    """Create WORM Data Policy"""
    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        min_retention = convert_time_to_millisecs(module.params["min_retention"])
        max_retention = convert_time_to_millisecs(module.params["max_retention"])
        default_retention = convert_time_to_millisecs(
            module.params["default_retention"]
        )
        if CONTEXT_API_VERSION in versions:
            res = blade.post_worm_data_policies(
                policy=WormDataPolicy(
                    enabled=module.params["enabled"],
                    mode="compliance",
                    min_retention=min_retention,
                    max_retention=max_retention,
                    default_retention=default_retention,
                    retention_lock=module.params["retention_lock"],
                ),
                names=[module.params["name"]],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.post_worm_data_policies(
                policy=WormDataPolicy(
                    enabled=module.params["enabled"],
                    mode="compliance",
                    min_retention=min_retention,
                    max_retention=max_retention,
                    default_retention=default_retention,
                    retention_lock=module.params["retention_lock"],
                ),
                names=[module.params["name"]],
            )
        if res.status_code != 200:
            if CONTEXT_API_VERSION in versions:
                blade.delete_worm_data_policies(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                blade.delete_worm_data_policies(names=[module.params["name"]])
            module.fail_json(
                msg="Failed to create WORM data policy {0}.Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_smb_client_policy(module, blade):
    """Update SMB Client Policy Rule"""

    changed = False
    versions = list(blade.get_versions().items)
    if module.params["client"]:
        if CONTEXT_API_VERSION in versions:
            current_policy_rule = blade.get_smb_client_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            current_policy_rule = blade.get_smb_client_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
            )
        if (
            current_policy_rule.status_code == 200
            and current_policy_rule.total_item_count == 0
        ):
            if SMB_ENCRYPT_API_VERSION in versions:
                rule = SmbClientPolicyRule(
                    client=module.params["client"],
                    permission=module.params["permission"],
                    access=module.params["access"],
                    encryption=module.params["smb_encryption"],
                )
            else:
                rule = SmbClientPolicyRule(
                    client=module.params["client"],
                    permission=module.params["permission"],
                    access=module.params["access"],
                )
            changed = True
            if not module.check_mode:
                if module.params["before_rule"]:
                    before_name = (
                        module.params["name"] + "." + str(module.params["before_rule"])
                    )
                    if CONTEXT_API_VERSION in versions:
                        res = blade.post_smb_client_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            before_rule_name=before_name,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.post_smb_client_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            before_rule_name=before_name,
                        )
                else:
                    if CONTEXT_API_VERSION in versions:
                        res = blade.post_smb_client_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.post_smb_client_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                        )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create rule for client {0} "
                        "in policy {1}. Error: {2}".format(
                            module.params["client"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
        else:
            rules = list(current_policy_rule.items)
            cli_count = None
            done = False
            if module.params["client"] == "*":
                for cli in range(len(rules)):
                    if rules[cli].client == "*":
                        cli_count = cli
                if not cli_count:
                    if SMB_ENCRYPT_API_VERSION in versions:
                        rule = SmbClientPolicyRule(
                            client=module.params["client"],
                            permission=module.params["permission"],
                            access=module.params["access"],
                            encryption=module.params["smb_encryption"],
                        )
                    else:
                        rule = SmbClientPolicyRule(
                            client=module.params["client"],
                            permission=module.params["permission"],
                            access=module.params["access"],
                        )
                    done = True
                    changed = True
                    if not module.check_mode:
                        if module.params["before_rule"]:
                            if CONTEXT_API_VERSION in versions:
                                res = blade.post_smb_client_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                    before_rule_name=(
                                        module.params["name"]
                                        + "."
                                        + str(module.params["before_rule"]),
                                    ),
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.post_smb_client_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                    before_rule_name=(
                                        module.params["name"]
                                        + "."
                                        + str(module.params["before_rule"]),
                                    ),
                                )
                        else:
                            if CONTEXT_API_VERSION in versions:
                                res = blade.post_smb_client_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.post_smb_client_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to create rule for "
                                "client {0} in policy {1}. Error: {2}".format(
                                    module.params["client"],
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
            if not done:
                old_policy_rule = rules[0]
                if SMB_ENCRYPT_API_VERSION in versions:
                    current_rule = {
                        "client": sorted(old_policy_rule.client),
                        "permission": sorted(old_policy_rule.permission),
                        "encryption": old_policy_rule.encryption,
                    }
                else:
                    current_rule = {
                        "client": sorted(old_policy_rule.client),
                        "permission": sorted(old_policy_rule.permission),
                    }
                if SMB_ENCRYPT_API_VERSION in versions:
                    if module.params["smb_encryption"]:
                        new_encryption = module.params["smb_encryption"]
                    else:
                        new_encryption = current_rule["encryption"]
                if module.params["permission"]:
                    new_permission = sorted(module.params["permission"])
                else:
                    new_permission = sorted(current_rule["permission"])
                if module.params["client"]:
                    new_client = sorted(module.params["client"])
                else:
                    new_client = sorted(current_rule["client"])
                if SMB_ENCRYPT_API_VERSION in versions:
                    new_rule = {
                        "client": new_client,
                        "permission": new_permission,
                        "encryption": new_encryption,
                    }
                else:
                    new_rule = {
                        "client": new_client,
                        "permission": new_permission,
                    }
                if current_rule != new_rule:
                    changed = True
                    if not module.check_mode:
                        if SMB_ENCRYPT_API_VERSION in versions:
                            rule = SmbClientPolicyRule(
                                client=module.params["client"],
                                permission=module.params["permission"],
                                encryption=module.params["smb_encryption"],
                            )
                        else:
                            rule = SmbClientPolicyRule(
                                client=module.params["client"],
                                permission=module.params["permission"],
                            )
                        if CONTEXT_API_VERSION in versions:
                            res = blade.patch_smb_client_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=rule,
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.patch_smb_client_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=rule,
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to update SMB client rule {0}. Error: {1}".format(
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index),
                                    res.errors[0].message,
                                )
                            )
                if (
                    module.params["before_rule"]
                    and module.params["before_rule"] != old_policy_rule.index
                ):
                    changed = True
                    if not module.check_mode:
                        before_name = (
                            module.params["name"]
                            + "."
                            + str(module.params["before_rule"])
                        )
                        if CONTEXT_API_VERSION in versions:
                            res = blade.patch_smb_client_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=SmbClientPolicyRule(),
                                before_rule_name=before_name,
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.patch_smb_client_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=SmbClientPolicyRule(),
                                before_rule_name=before_name,
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to move SMB client rule {0}. Error: {1}".format(
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index),
                                    res.errors[0].message,
                                )
                            )
    if CONTEXT_API_VERSION in versions:
        current_policy = list(
            blade.get_smb_client_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        current_policy = list(
            blade.get_smb_client_policies(names=[module.params["name"]]).items
        )[0]
    if current_policy.enabled != module.params["enabled"]:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_smb_client_policies(
                    policy=SmbClientPolicy(enabled=module.params["enabled"]),
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_smb_client_policies(
                    policy=SmbClientPolicy(enabled=module.params["enabled"]),
                    names=[module.params["name"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change state of SMB client policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def delete_nfs_policy(module, blade):
    """Delete NFS Export Policy, or Rule

    If client is provided then delete the client rule if it exists.
    """

    changed = False
    versions = list(blade.get_versions().items)
    policy_delete = True
    if module.params["client"]:
        policy_delete = False
        if CONTEXT_API_VERSION in versions:
            res = blade.get_nfs_export_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_nfs_export_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
            )
        if res.status_code == 200:
            if res.total_item_count == 0:
                pass
            elif res.total_item_count == 1:
                rule = list(res.items)[0]
                if module.params["client"] == rule.client:
                    changed = True
                    if not module.check_mode:
                        if CONTEXT_API_VERSION in versions:
                            res = blade.delete_nfs_export_policies_rules(
                                names=[rule.name],
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.delete_nfs_export_policies_rules(
                                names=[rule.name]
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to delete rule for client {0} in policy {1}. "
                                "Error: {2}".format(
                                    module.params["client"],
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
            else:
                rules = list(res.items)
                for cli in range(len(rules)):
                    if rules[cli].client == "*":
                        changed = True
                        if not module.check_mode:
                            if CONTEXT_API_VERSION in versions:
                                res = blade.delete_nfs_export_policies_rules(
                                    names=[rules[cli].name],
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.delete_nfs_export_policies_rules(
                                    names=[rules[cli].name]
                                )
                            if res.status_code != 200:
                                module.fail_json(
                                    msg="Failed to delete rule for client {0} in policy {1}. "
                                    "Error: {2}".format(
                                        module.params["client"],
                                        module.params["name"],
                                        res.errors[0].message,
                                    )
                                )
    if policy_delete:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in versions:
                res = blade.delete_nfs_export_policies(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_nfs_export_policies(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete export policy {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_network_access_policy(module, blade):
    """Update Networkk Access Policy Rule"""

    changed = False
    versions = list(blade.get_versions().items)
    if module.params["client"]:
        if CONTEXT_API_VERSION in versions:
            current_policy_rule = blade.get_network_access_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            current_policy_rule = blade.get_network_access_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
            )
        if (
            current_policy_rule.status_code == 200
            and current_policy_rule.total_item_count == 0
        ):
            rule = NetworkAccessPolicyRule(
                client=module.params["client"],
                effect=module.params["effect"],
                interfaces=module.params["interfaces"],
            )
            changed = True
            if not module.check_mode:
                if module.params["before_rule"]:
                    before_name = (
                        module.params["name"] + "." + str(module.params["before_rule"])
                    )
                    if CONTEXT_API_VERSION in versions:
                        res = blade.post_network_access_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            before_rule_name=before_name,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.post_network_access_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            before_rule_name=before_name,
                        )
                else:
                    if CONTEXT_API_VERSION in versions:
                        res = blade.post_network_access_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.post_network_access_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                        )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create rule for client {0} "
                        "in policy {1}. Error: {2}".format(
                            module.params["client"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
        else:
            rules = list(current_policy_rule.items)
            cli_count = None
            done = False
            if module.params["client"] == "*":
                for cli in range(len(rules)):
                    if rules[cli].client == "*":
                        cli_count = cli
                if not cli_count:
                    rule = NetworkAccessPolicyRule(
                        client=module.params["client"],
                        effect=module.params["effect"],
                        interfaces=module.params["interfaces"],
                    )
                    done = True
                    changed = True
                    if not module.check_mode:
                        if module.params["before_rule"]:
                            if CONTEXT_API_VERSION in versions:
                                res = blade.post_network_access_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                    before_rule_name=(
                                        module.params["name"]
                                        + "."
                                        + str(module.params["before_rule"]),
                                    ),
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.post_network_access_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                    before_rule_name=(
                                        module.params["name"]
                                        + "."
                                        + str(module.params["before_rule"]),
                                    ),
                                )
                        else:
                            if CONTEXT_API_VERSION in versions:
                                res = blade.post_network_access_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.post_network_access_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to create rule for "
                                "client {0} in policy {1}. Error: {2}".format(
                                    module.params["client"],
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
            if not done:
                old_policy_rule = rules[0]
                current_rule = {
                    "client": sorted(old_policy_rule.client),
                    "effect": old_policy_rule.effect,
                    "interfaces": old_policy_rule.interfaces,
                }
                if module.params["interfaces"]:
                    new_interfaces = module.params["interfaces"]
                else:
                    new_interfaces = current_rule["interfaces"]
                if module.params["effect"]:
                    new_effect = module.params["effect"]
                else:
                    new_effect = current_rule["effect"]
                if module.params["client"]:
                    new_client = sorted(module.params["client"])
                else:
                    new_client = sorted(current_rule["client"])
                new_rule = {
                    "client": new_client,
                    "effect": new_effect,
                    "interfaces": new_interfaces,
                }
                if current_rule != new_rule:
                    changed = True
                    if not module.check_mode:
                        rule = NetworkAccessPolicyRule(
                            client=module.params["client"],
                            effect=module.params["effect"],
                            interfaces=module.params["interfaces"],
                        )
                        if CONTEXT_API_VERSION in versions:
                            res = blade.patch_network_access_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=rule,
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.patch_network_access_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=rule,
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to update network access client rule {0}. Error: {1}".format(
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index),
                                    res.errors[0].message,
                                )
                            )
                if (
                    module.params["before_rule"]
                    and module.params["before_rule"] != old_policy_rule.index
                ):
                    changed = True
                    if not module.check_mode:
                        before_name = (
                            module.params["name"]
                            + "."
                            + str(module.params["before_rule"])
                        )
                        if CONTEXT_API_VERSION in versions:
                            res = blade.patch_network_access_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=NetworkAccessPolicyRule(),
                                before_rule_name=before_name,
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.patch_network_access_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=NetworkAccessPolicyRule(),
                                before_rule_name=before_name,
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to move network access client rule {0}. Error: {1}".format(
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index),
                                    res.errors[0].message,
                                )
                            )
    if CONTEXT_API_VERSION in versions:
        current_policy = list(
            blade.get_network_access_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        current_policy = list(
            blade.get_network_access_policies(names=[module.params["name"]]).items
        )[0]
    if current_policy.enabled != module.params["enabled"]:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_network_access_policies(
                    policy=NetworkAccessPolicy(enabled=module.params["enabled"]),
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_network_access_policies(
                    policy=NetworkAccessPolicy(enabled=module.params["enabled"]),
                    names=[module.params["name"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change state of network access policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def delete_network_access_policy(module, blade):
    """Delete Network Access Policy, or Rule

    If client is provided then delete the client rule if it exists.
    """

    changed = False
    versions = list(blade.get_versions().items)
    policy_delete = True
    if module.params["client"]:
        policy_delete = False
        if CONTEXT_API_VERSION in versions:
            res = blade.get_network_access_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_network_access_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
            )
        if res.status_code == 200:
            if res.total_item_count == 0:
                pass
            elif res.total_item_count == 1:
                rule = list(res.items)[0]
                if module.params["client"] == rule.client:
                    changed = True
                    if not module.check_mode:
                        if CONTEXT_API_VERSION in versions:
                            res = blade.delete_network_access_policies_rules(
                                names=[rule.name],
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.delete_network_access_policies_rules(
                                names=[rule.name]
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to delete rule for client {0} in policy {1}. "
                                "Error: {2}".format(
                                    module.params["client"],
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
            else:
                rules = list(res.items)
                for cli in range(len(rules)):
                    if rules[cli].client == "*":
                        changed = True
                        if not module.check_mode:
                            if CONTEXT_API_VERSION in versions:
                                res = blade.delete_network_access_policies_rules(
                                    names=[rules[cli].name],
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.delete_network_access_policies_rules(
                                    names=[rules[cli].name]
                                )
                            if res.status_code != 200:
                                module.fail_json(
                                    msg="Failed to delete rule for client {0} in policy {1}. "
                                    "Error: {2}".format(
                                        module.params["client"],
                                        module.params["name"],
                                        res.errors[0].message,
                                    )
                                )
    if policy_delete:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in versions:
                res = blade.delete_network_Access_policies(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_network_Access_policies(
                    names=[module.params["name"]]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete network access policy {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def delete_worm_data_policy(module, blade):
    """Delete WORM data Policy"""

    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.delete_worm_data_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = blade.delete_worm_data_policies(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete WORM data policy {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def rename_worm_data_policy(module):
    """Rename WORM Data Policy"""

    changed = False
    module.warn("Renaming of WORM Data policies is not supported")
    module.exit_json(changed=changed)


def rename_network_access_policy(module, blade):
    """Rename Network Access Policy"""

    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.patch_network_access_policies(
                names=[module.params["name"]],
                policy=NfsExportPolicy(name=module.params["rename"]),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.patch_network_access_policies(
                names=[module.params["name"]],
                policy=NfsExportPolicy(name=module.params["rename"]),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to rename network access policy {0} to {1}. Error: {2}".format(
                    module.params["name"],
                    module.params["rename"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def rename_nfs_policy(module, blade):
    """Rename NFS Export Policy"""

    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.patch_nfs_export_policies(
                names=[module.params["name"]],
                policy=NfsExportPolicy(name=module.params["rename"]),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.patch_nfs_export_policies(
                names=[module.params["name"]],
                policy=NfsExportPolicy(name=module.params["rename"]),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to rename NFS export policy {0} to {1}. Error: {2}".format(
                    module.params["name"],
                    module.params["rename"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def update_worm_data_policy(module, blade):
    """Update WORM data policy"""

    changed = False
    versions = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in versions:
        current_policy_config = list(
            blade.get_worm_data_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        current_policy_config = list(
            blade.get_worm_data_policies(names=[module.params["name"]]).items
        )[0]
    current_policy = {
        "default_retention": current_policy_config.default_retention,
        "enabled": current_policy_config.enabled,
        "max_retention": current_policy_config.max_retention,
        "min_retention": current_policy_config.min_retention,
        "retention_lock": current_policy_config.retention_lock,
    }
    new_policy = {
        "default_retention": current_policy_config.default_retention,
        "enabled": current_policy_config.enabled,
        "max_retention": current_policy_config.max_retention,
        "min_retention": current_policy_config.min_retention,
        "retention_lock": current_policy_config.retention_lock,
    }
    if module.params["enabled"] != current_policy["enabled"]:
        new_policy["enabled"] = module.params["enabled"]
    if (
        module.params["retention_lock"]
        and module.params["retention_lock"] != current_policy["retention_lock"]
    ):
        new_policy["retention_lock"] = module.params["retention_lock"]
    if (
        module.params["default_retention"]
        and convert_time_to_millisecs(module.params["default_retention"])
        != current_policy["default_retention"]
    ):
        new_policy["default_retention"] = convert_time_to_millisecs(
            module.params["default_retention"]
        )
    if (
        module.params["max_retention"]
        and convert_time_to_millisecs(module.params["max_retention"])
        != current_policy["max_retention"]
    ):
        new_policy["max_retention"] = convert_time_to_millisecs(
            module.params["max_retention"]
        )
    if (
        module.params["min_retention"]
        and convert_time_to_millisecs(module.params["min_retention"])
        != current_policy["min_retention"]
    ):
        new_policy["min_retention"] = convert_time_to_millisecs(
            module.params["min_retention"]
        )
    if new_policy != current_policy:
        changed = True
        if not module.check_mode:
            worm_policy = WormDataPolicy(
                enabled=new_policy["enabled"],
                retention_lock=new_policy["retention_lock"],
                min_retention=new_policy["min_retention"],
                max_retention=new_policy["max_retention"],
                default_retention=new_policy["default_retention"],
            )
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_worm_data_policies(
                    names=[module.params["name"]],
                    policy=worm_policy,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_worm_data_policies(
                    names=[module.params["name"]], policy=worm_policy
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update WORM data policy {0}. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def update_nfs_policy(module, blade):
    """Update NFS Export Policy Rule"""

    changed = False
    versions = list(blade.get_versions().items)
    if module.params["client"]:
        if CONTEXT_API_VERSION in versions:
            current_policy_rule = blade.get_nfs_export_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            current_policy_rule = blade.get_nfs_export_policies_rules(
                policy_names=[module.params["name"]],
                filter="client='" + module.params["client"] + "'",
            )
        if (
            current_policy_rule.status_code == 200
            and current_policy_rule.total_item_count == 0
        ):
            rule = NfsExportPolicyRule(
                client=module.params["client"],
                permission=module.params["permission"],
                access=module.params["access"],
                anonuid=module.params["anonuid"],
                anongid=module.params["anongid"],
                fileid_32bit=module.params["fileid_32bit"],
                atime=module.params["atime"],
                secure=module.params["secure"],
                security=module.params["security"],
            )
            changed = True
            if not module.check_mode:
                if module.params["before_rule"]:
                    before_name = (
                        module.params["name"] + "." + str(module.params["before_rule"])
                    )
                    if CONTEXT_API_VERSION in versions:
                        res = blade.post_nfs_export_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            before_rule_name=before_name,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.post_nfs_export_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            before_rule_name=before_name,
                        )
                else:
                    if CONTEXT_API_VERSION in versions:
                        res = blade.post_nfs_export_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.post_nfs_export_policies_rules(
                            policy_names=[module.params["name"]],
                            rule=rule,
                        )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create rule for client {0} "
                        "in export policy {1}. Error: {2}".format(
                            module.params["client"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
        else:
            rules = list(current_policy_rule.items)
            cli_count = None
            done = False
            if module.params["client"] == "*":
                for cli in range(len(rules)):
                    if rules[cli].client == "*":
                        cli_count = cli
                if not cli_count:
                    rule = NfsExportPolicyRule(
                        client=module.params["client"],
                        permission=module.params["permission"],
                        access=module.params["access"],
                        anonuid=module.params["anonuid"],
                        anongid=module.params["anongid"],
                        fileid_32bit=module.params["fileid_32bit"],
                        atime=module.params["atime"],
                        secure=module.params["secure"],
                        security=module.params["security"],
                    )
                    done = True
                    changed = True
                    if not module.check_mode:
                        if module.params["before_rule"]:
                            if CONTEXT_API_VERSION in versions:
                                res = blade.post_nfs_export_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                    before_rule_name=(
                                        module.params["name"]
                                        + "."
                                        + str(module.params["before_rule"]),
                                    ),
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.post_nfs_export_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                    before_rule_name=(
                                        module.params["name"]
                                        + "."
                                        + str(module.params["before_rule"]),
                                    ),
                                )
                        else:
                            if CONTEXT_API_VERSION in versions:
                                res = blade.post_nfs_export_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.post_nfs_export_policies_rules(
                                    policy_names=[module.params["name"]],
                                    rule=rule,
                                )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to create rule for "
                                "client {0} in export policy {1}. Error: {2}".format(
                                    module.params["client"],
                                    module.params["name"],
                                    res.errors[0].message,
                                )
                            )
            if not done:
                old_policy_rule = rules[0]
                current_rule = {
                    "anongid": getattr(old_policy_rule, "anongid", None),
                    "anonuid": getattr(old_policy_rule, "anonuid", None),
                    "atime": old_policy_rule.atime,
                    "client": sorted(old_policy_rule.client),
                    "fileid_32bit": old_policy_rule.fileid_32bit,
                    "permission": sorted(old_policy_rule.permission),
                    "secure": old_policy_rule.secure,
                    "security": sorted(old_policy_rule.security),
                }
                if module.params["permission"]:
                    new_permission = sorted(module.params["permission"])
                else:
                    new_permission = sorted(current_rule["permission"])
                if module.params["client"]:
                    new_client = sorted(module.params["client"])
                else:
                    new_client = sorted(current_rule["client"])
                if module.params["security"]:
                    new_security = sorted(module.params["security"])
                else:
                    new_security = sorted(current_rule["security"])
                if module.params["anongid"]:
                    new_anongid = module.params["anongid"]
                else:
                    new_anongid = current_rule["anongid"]
                if module.params["anonuid"]:
                    new_anonuid = module.params["anonuid"]
                else:
                    new_anonuid = current_rule["anonuid"]
                if module.params["atime"] != current_rule["atime"]:
                    new_atime = module.params["atime"]
                else:
                    new_atime = current_rule["atime"]
                if module.params["secure"] != current_rule["secure"]:
                    new_secure = module.params["secure"]
                else:
                    new_secure = current_rule["secure"]
                if module.params["fileid_32bit"] != current_rule["fileid_32bit"]:
                    new_fileid_32bit = module.params["fileid_32bit"]
                else:
                    new_fileid_32bit = current_rule["fileid_32bit"]
                new_rule = {
                    "anongid": new_anongid,
                    "anonuid": new_anonuid,
                    "atime": new_atime,
                    "client": new_client,
                    "fileid_32bit": new_fileid_32bit,
                    "permission": new_permission,
                    "secure": new_secure,
                    "security": new_security,
                }
                if current_rule != new_rule:
                    changed = True
                    if not module.check_mode:
                        rule = NfsExportPolicyRule(
                            client=module.params["client"],
                            permission=module.params["permission"],
                            access=module.params["access"],
                            anonuid=module.params["anonuid"],
                            anongid=module.params["anongid"],
                            fileid_32bit=module.params["fileid_32bit"],
                            atime=module.params["atime"],
                            secure=module.params["secure"],
                            security=module.params["security"],
                        )
                        if CONTEXT_API_VERSION in versions:
                            res = blade.patch_nfs_export_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=rule,
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.patch_nfs_export_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=rule,
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to update NFS export rule {0}. Error: {1}".format(
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index),
                                    res.errors[0].message,
                                )
                            )
                if (
                    module.params["before_rule"]
                    and module.params["before_rule"] != old_policy_rule.index
                ):
                    changed = True
                    if not module.check_mode:
                        before_name = (
                            module.params["name"]
                            + "."
                            + str(module.params["before_rule"])
                        )
                        if CONTEXT_API_VERSION in versions:
                            res = blade.patch_nfs_export_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=NfsExportPolicyRule(),
                                before_rule_name=before_name,
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.patch_nfs_export_policies_rules(
                                names=[
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index)
                                ],
                                rule=NfsExportPolicyRule(),
                                before_rule_name=before_name,
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to move NFS export rule {0}. Error: {1}".format(
                                    module.params["name"]
                                    + "."
                                    + str(old_policy_rule.index),
                                    res.errors[0].message,
                                )
                            )
    if CONTEXT_API_VERSION in versions:
        current_policy = list(
            blade.get_nfs_export_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0]
    else:
        current_policy = list(
            blade.get_nfs_export_policies(names=[module.params["name"]]).items
        )[0]
    if current_policy.enabled != module.params["enabled"]:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_nfs_export_policies(
                    policy=NfsExportPolicy(enabled=module.params["enabled"]),
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_nfs_export_policies(
                    policy=NfsExportPolicy(enabled=module.params["enabled"]),
                    names=[module.params["name"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change state of nfs export policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_nfs_policy(module, blade):
    """Create NFS Export Policy"""
    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.post_nfs_export_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = blade.post_nfs_export_policies(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create nfs export policy {0}.Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if not module.params["enabled"]:
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_nfs_export_policies(
                    policy=NfsExportPolicy(enabled=False),
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_nfs_export_policies(
                    policy=NfsExportPolicy(enabled=False), names=[module.params["name"]]
                )
            if res.status_code != 200:
                if CONTEXT_API_VERSION in versions:
                    blade.delete_nfs_export_policies(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    )
                else:
                    blade.delete_nfs_export_policies(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to create nfs export policy {0}.Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        if module.params["client"]:
            rule = NfsExportPolicyRule(
                client=module.params["client"],
                permission=module.params["permission"],
                access=module.params["access"],
                anonuid=module.params["anonuid"],
                anongid=module.params["anongid"],
                fileid_32bit=module.params["fileid_32bit"],
                atime=module.params["atime"],
                secure=module.params["secure"],
                security=module.params["security"],
            )
            if CONTEXT_API_VERSION in versions:
                res = blade.post_nfs_export_policies_rules(
                    policy_names=[module.params["name"]],
                    rule=rule,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_nfs_export_policies_rules(
                    policy_names=[module.params["name"]],
                    rule=rule,
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to rule for policy {0}. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def delete_os_policy(module, blade):
    """Delete Object Store Access Policy, Rule, or User

    If rule is provided then delete the rule if it exists.
    If user is provided then remove grant from user if granted.
    If no user or rule provided delete the whole policy.
    Cannot delete a policy with attached users, so delete all users
    if the force_delete option is selected.
    """

    changed = False
    versions = list(blade.get_versions().items)
    policy_name = module.params["account"] + "/" + module.params["name"]
    policy_delete = True
    if module.params["rule"]:
        policy_delete = False
        if CONTEXT_API_VERSION in versions:
            res = blade.get_object_store_access_policies_rules(
                policy_names=[policy_name],
                names=[module.params["rule"]],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_object_store_access_policies_rules(
                policy_names=[policy_name], names=[module.params["rule"]]
            )
        if res.status_code == 200 and res.total_item_count != 0:
            changed = True
            if not module.check_mode:
                if CONTEXT_API_VERSION in versions:
                    res = blade.delete_object_store_access_policies_rules(
                        policy_names=[policy_name],
                        names=[module.params["rule"]],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.delete_object_store_access_policies_rules(
                        policy_names=[policy_name], names=[module.params["rule"]]
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete users from policy {0}. Error: {1} - {2}".format(
                            policy_name, res.errors[0].context, res.errors[0].message
                        )
                    )

    if module.params["user"]:
        member_name = module.params["account"] + "/" + module.params["user"]
        policy_delete = False
        if CONTEXT_API_VERSION in versions:
            res = blade.get_object_store_access_policies_object_store_users(
                policy_names=[policy_name],
                member_names=[member_name],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_object_store_access_policies_object_store_users(
                policy_names=[policy_name], member_names=[member_name]
            )
        if res.status_code == 200 and res.total_item_count != 0:
            changed = True
            if not module.check_mode:
                member_name = module.params["account"] + "/" + module.params["user"]
                if CONTEXT_API_VERSION in versions:
                    res = blade.delete_object_store_access_policies_object_store_users(
                        policy_names=[policy_name],
                        member_names=[member_name],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.delete_object_store_access_policies_object_store_users(
                        policy_names=[policy_name], member_names=[member_name]
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete users from policy {0}. Error: {1} - {2}".format(
                            policy_name, res.errors[0].context, res.errors[0].message
                        )
                    )

    if policy_delete:
        if module.params["account"].lower() == "pure:policy":
            module.fail_json(msg="System-Wide policies cannot be deleted.")
        if CONTEXT_API_VERSION in versions:
            policy_users = list(
                blade.get_object_store_access_policies_object_store_users(
                    policy_names=[policy_name], context_names=[module.params["context"]]
                ).items
            )
        else:
            policy_users = list(
                blade.get_object_store_access_policies_object_store_users(
                    policy_names=[policy_name]
                ).items
            )
        if len(policy_users) == 0:
            changed = True
            if not module.check_mode:
                if CONTEXT_API_VERSION in versions:
                    res = blade.delete_object_store_access_policies(
                        names=[policy_name], context_names=[module.params["context"]]
                    )
                else:
                    res = blade.delete_object_store_access_policies(names=[policy_name])
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete policy {0}. Error: {1}".format(
                            policy_name, res.errors[0].message
                        )
                    )
        else:
            if module.params["force_delete"]:
                changed = True
                if not module.check_mode:
                    for user in range(len(policy_users)):
                        if CONTEXT_API_VERSION in versions:
                            res = blade.delete_object_store_access_policies_object_store_users(
                                member_names=[policy_users[user].member.name],
                                policy_names=[policy_name],
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.delete_object_store_access_policies_object_store_users(
                                member_names=[policy_users[user].member.name],
                                policy_names=[policy_name],
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to delete user {0} from policy {1}, "
                                "Error: {2}".format(
                                    policy_users[user].member,
                                    policy_name,
                                    res.errors[0].message,
                                )
                            )
                    if CONTEXT_API_VERSION in versions:
                        res = blade.delete_object_store_access_policies(
                            names=[policy_name],
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.delete_object_store_access_policies(
                            names=[policy_name]
                        )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to delete policy {0}. Error: {1}".format(
                                policy_name, res.errors[0].message
                            )
                        )
            else:
                module.fail_json(
                    msg="Policy {0} cannot be deleted with connected users".format(
                        policy_name
                    )
                )
    module.exit_json(changed=changed)


def create_os_policy(module, blade):
    """Create Object Store Access Policy"""
    changed = True
    policy_name = module.params["account"] + "/" + module.params["name"]
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in versions:
            res = blade.post_object_store_access_policies(
                names=[policy_name],
                policy=ObjectStoreAccessPolicyPost(description=module.params["desc"]),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.post_object_store_access_policies(
                names=[policy_name],
                policy=ObjectStoreAccessPolicyPost(description=module.params["desc"]),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create access policy {0}.".format(policy_name)
            )
        if module.params["rule"]:
            if not module.params["actions"] or not module.params["object_resources"]:
                module.fail_json(
                    msg="Parameters `actions` and `object_resources` "
                    "are required to create a new rule"
                )
            conditions = PolicyRuleObjectAccessCondition(
                source_ips=module.params["source_ips"],
                s3_delimiters=module.params["s3_delimiters"],
                s3_prefixes=module.params["s3_prefixes"],
            )
            if SMB_ENCRYPT_API_VERSION in versions:
                rule = PolicyRuleObjectAccessPost(
                    actions=module.params["actions"],
                    resources=module.params["object_resources"],
                    conditions=conditions,
                    effect=module.params["effect"],
                )
            else:
                rule = PolicyRuleObjectAccessPost(
                    actions=module.params["actions"],
                    resources=module.params["object_resources"],
                    conditions=conditions,
                )
            if CONTEXT_API_VERSION in versions:
                res = blade.post_object_store_access_policies_rules(
                    policy_names=policy_name,
                    names=[module.params["rule"]],
                    enforce_action_restrictions=module.params["ignore_enforcement"],
                    rule=rule,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_object_store_access_policies_rules(
                    policy_names=policy_name,
                    names=[module.params["rule"]],
                    enforce_action_restrictions=module.params["ignore_enforcement"],
                    rule=rule,
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create rule {0} to policy {1}. Error: {2}".format(
                        module.params["rule"], policy_name, res.errors[0].message
                    )
                )
        if module.params["user"]:
            member_name = module.params["account"] + "/" + module.params["user"]
            if CONTEXT_API_VERSION in versions:
                res = blade.post_object_store_access_policies_object_store_users(
                    member_names=[member_name],
                    policy_names=[policy_name],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_object_store_access_policies_object_store_users(
                    member_names=[member_name], policy_names=[policy_name]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to add users to policy {0}. Error: {1} - {2}".format(
                        policy_name, res.errors[0].context, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_os_policy(module, blade):
    """Update Object Store Access Policy"""
    changed = False
    versions = list(blade.get_versions().items)
    policy_name = module.params["account"] + "/" + module.params["name"]
    if module.params["rule"]:
        if CONTEXT_API_VERSION in versions:
            current_policy_rule = blade.get_object_store_access_policies_rules(
                policy_names=[policy_name],
                names=[module.params["rule"]],
                context_names=[module.params["context"]],
            )
        else:
            current_policy_rule = blade.get_object_store_access_policies_rules(
                policy_names=[policy_name], names=[module.params["rule"]]
            )
        if current_policy_rule.status_code != 200:
            changed = True
            if not module.check_mode:
                conditions = PolicyRuleObjectAccessCondition(
                    source_ips=module.params["source_ips"],
                    s3_delimiters=module.params["s3_delimiters"],
                    s3_prefixes=module.params["s3_prefixes"],
                )
                rule = PolicyRuleObjectAccessPost(
                    actions=module.params["actions"],
                    resources=module.params["object_resources"],
                    conditions=conditions,
                )
                if CONTEXT_API_VERSION in versions:
                    res = blade.post_object_store_access_policies_rules(
                        policy_names=policy_name,
                        names=[module.params["rule"]],
                        enforce_action_restrictions=module.params["ignore_enforcement"],
                        rule=rule,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.post_object_store_access_policies_rules(
                        policy_names=policy_name,
                        names=[module.params["rule"]],
                        enforce_action_restrictions=module.params["ignore_enforcement"],
                        rule=rule,
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create rule {0} in policy {1}. Error: {2}".format(
                            module.params["rule"], policy_name, res.errors[0].message
                        )
                    )
        else:
            old_policy_rule = list(current_policy_rule.items)[0]
            current_rule = {
                "actions": old_policy_rule.actions,
                "resources": old_policy_rule.resources,
                "ips": getattr(old_policy_rule.conditions, "source_ips", None),
                "prefixes": getattr(old_policy_rule.conditions, "s3_prefixes", None),
                "delimiters": getattr(
                    old_policy_rule.conditions, "s3_delimiters", None
                ),
            }
            if module.params["actions"]:
                new_actions = sorted(module.params["actions"])
            else:
                new_actions = sorted(current_rule["actions"])
            if module.params["object_resources"]:
                new_resources = sorted(module.params["object_resources"])
            else:
                new_resources = sorted(current_rule["resources"])
            if module.params["s3_prefixes"]:
                new_prefixes = sorted(module.params["s3_prefixes"])
            elif current_rule["prefixes"]:
                new_prefixes = sorted(current_rule["prefixes"])
            else:
                new_prefixes = None
            if module.params["s3_delimiters"]:
                new_delimiters = sorted(module.params["s3_delimiters"])
            elif current_rule["delimiters"]:
                new_delimiters = sorted(current_rule["delimiters"])
            else:
                new_delimiters = None
            if module.params["source_ips"]:
                new_ips = sorted(module.params["source_ips"])
            elif current_rule["ips"]:
                new_ips = sorted(current_rule["source_ips"])
            else:
                new_ips = None
            new_rule = {
                "actions": new_actions,
                "resources": new_resources,
                "ips": new_ips,
                "prefixes": new_prefixes,
                "delimiters": new_delimiters,
            }
            if current_rule != new_rule:
                changed = True
                if not module.check_mode:
                    conditions = PolicyRuleObjectAccessCondition(
                        source_ips=new_rule["ips"],
                        s3_prefixes=new_rule["prefixes"],
                        s3_delimiters=new_rule["delimiters"],
                    )
                    rule = PolicyRuleObjectAccess(
                        actions=new_rule["actions"],
                        resources=new_rule["resources"],
                        conditions=conditions,
                    )
                    if CONTEXT_API_VERSION in versions:
                        res = blade.patch_object_store_access_policies_rules(
                            policy_names=[policy_name],
                            names=[module.params["rule"]],
                            rule=rule,
                            enforce_action_restrictions=module.params[
                                "ignore_enforcement"
                            ],
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.patch_object_store_access_policies_rules(
                            policy_names=[policy_name],
                            names=[module.params["rule"]],
                            rule=rule,
                            enforce_action_restrictions=module.params[
                                "ignore_enforcement"
                            ],
                        )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to update rule {0} in policy {1}. Error: {2}".format(
                                module.params["rule"],
                                policy_name,
                                res.errors[0].message,
                            )
                        )
    if module.params["user"]:
        member_name = module.params["account"] + "/" + module.params["user"]
        if CONTEXT_API_VERSION in versions:
            res = blade.get_object_store_access_policies_object_store_users(
                policy_names=[policy_name],
                member_names=[member_name],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_object_store_access_policies_object_store_users(
                policy_names=[policy_name], member_names=[member_name]
            )
        if res.status_code != 200 or (
            res.status_code == 200 and res.total_item_count == 0
        ):
            changed = True
            if not module.check_mode:
                if CONTEXT_API_VERSION in versions:
                    res = blade.post_object_store_access_policies_object_store_users(
                        member_names=[member_name],
                        policy_names=[policy_name],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.post_object_store_access_policies_object_store_users(
                        member_names=[member_name], policy_names=[policy_name]
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add user {0} to policy {1}. Error: {2}".format(
                            member_name, policy_name, res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def copy_os_policy_rule(module, blade):
    """Copy an existing policy rule to a new policy"""
    changed = True
    versions = list(blade.get_versions().items)
    policy_name = module.params["account"] + "/" + module.params["name"]
    if not module.params["target_rule"]:
        module.params["target_rule"] = module.params["rule"]
    if CONTEXT_API_VERSION in versions:
        res = blade.get_object_store_access_policies_rules(
            policy_names=[module.params["target"]],
            names=[module.params["target_rule"]],
            context_names=[module.params["context"]],
        )
    else:
        res = blade.get_object_store_access_policies_rules(
            policy_names=[module.params["target"]], names=[module.params["target_rule"]]
        )
    if res.status_code == 200:
        module.fail_json(
            msg="Target rule {0} already exists in policy {1}".format(
                module.params["target_rule"], policy_name
            )
        )
    if CONTEXT_API_VERSION in versions:
        current_rule = list(
            blade.get_object_store_access_policies_rules(
                policy_names=[policy_name],
                names=[module.params["rule"]],
                context_names=[module.params["context"]],
            ).items
        )[0]
    else:
        current_rule = list(
            blade.get_object_store_access_policies_rules(
                policy_names=[policy_name], names=[module.params["rule"]]
            ).items
        )[0]
    if not module.check_mode:
        conditions = PolicyRuleObjectAccessCondition(
            source_ips=current_rule.conditions.source_ips,
            s3_delimiters=current_rule.conditions.s3_delimiters,
            s3_prefixes=current_rule.conditions.s3_prefixes,
        )
        rule = PolicyRuleObjectAccessPost(
            actions=current_rule.actions,
            resources=current_rule.resources,
            conditions=conditions,
        )
        if CONTEXT_API_VERSION in versions:
            res = blade.post_object_store_access_policies_rules(
                policy_names=module.params["target"],
                names=[module.params["target_rule"]],
                enforce_action_restrictions=module.params["ignore_enforcement"],
                rule=rule,
                context_names=[module.params["context"]],
            )
        else:
            res = blade.post_object_store_access_policies_rules(
                policy_names=module.params["target"],
                names=[module.params["target_rule"]],
                enforce_action_restrictions=module.params["ignore_enforcement"],
                rule=rule,
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to copy rule {0} from policy {1} to policy {2}. "
                "Error: {3}".format(
                    module.params["rule"],
                    policy_name,
                    module.params["target"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def delete_snap_policy(module, blade):
    """Delete snapshot policy

    If any rule parameters are provided then delete any rules that match
    all of the parameters provided.
    If no rule parameters are provided delete the entire policy
    """

    changed = False
    versions = list(blade.get_versions().items)
    rule_delete = False
    if (
        module.params["at"]
        or module.params["every"]
        or module.params["timezone"]
        or module.params["keep_for"]
    ):
        rule_delete = True
    if rule_delete:
        if CONTEXT_API_VERSION in versions:
            current_rules = list(
                blade.get_policies(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                ).items
            )[0].rules
        else:
            current_rules = list(
                blade.get_policies(names=[module.params["name"]]).items
            )[0].rules
        for rule in range(len(current_rules)):
            current_rule = {
                "at": current_rules[rule].at,
                "every": current_rules[rule].every,
                "keep_for": current_rules[rule].keep_for,
                "time_zone": current_rules[rule].time_zone,
            }
            if not module.params["at"]:
                delete_at = current_rules[rule].at
            else:
                delete_at = _convert_to_millisecs(module.params["at"])
            if module.params["keep_for"]:
                delete_keep_for = module.params["keep_for"]
            else:
                delete_keep_for = int(current_rules[rule].keep_for / 1000)
            if module.params["every"]:
                delete_every = module.params["every"]
            else:
                delete_every = int(current_rules[rule].every / 1000)
            if not module.params["timezone"]:
                delete_tz = current_rules[rule].time_zone
            else:
                delete_tz = module.params["timezone"]
            delete_rule = {
                "at": delete_at,
                "every": delete_every * 1000,
                "keep_for": delete_keep_for * 1000,
                "time_zone": delete_tz,
            }
            if current_rule == delete_rule:
                changed = True
                attr = PolicyPatch(remove_rules=[delete_rule])
                if not module.check_mode:
                    if CONTEXT_API_VERSION in versions:
                        res = blade.patch_policies(
                            destroy_snapshots=module.params["destroy_snapshots"],
                            names=[module.params["name"]],
                            policy=attr,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.patch_policies(
                            destroy_snapshots=module.params["destroy_snapshots"],
                            names=[module.params["name"]],
                            policy=attr,
                        )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to delete policy rule {0}. Error: {1}".format(
                                module.params["name"], res.errors[0].message
                            )
                        )
    else:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in versions:
                res = blade.delete_policies(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_policies(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete policy {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_snap_policy(module, blade):
    """Create snapshot policy"""
    changed = True
    versions = list(blade.get_versions().items)
    if (
        module.params["keep_for"]
        and not module.params["every"]
        or module.params["every"]
        and not module.params["keep_for"]
    ):
        module.fail_json(msg="`keep_for` and `every` are required.")
    if module.params["timezone"] and not module.params["at"]:
        module.fail_json(msg="`timezone` requires `at` to be provided.")
    if module.params["at"] and not module.params["every"]:
        module.fail_json(msg="`at` requires `every` to be provided.")

    if not module.check_mode:
        if module.params["at"] and module.params["every"]:
            if not module.params["every"] % 86400 == 0:
                module.fail_json(
                    msg="At time can only be set if every value is a multiple of 86400"
                )
            if not module.params["timezone"]:
                module.params["timezone"] = _get_local_tz(module)
                if module.params["timezone"] not in pytz.all_timezones_set:
                    module.fail_json(
                        msg="Timezone {0} is not valid".format(
                            module.params["timezone"]
                        )
                    )
        if not module.params["keep_for"]:
            module.params["keep_for"] = 0
        if not module.params["every"]:
            module.params["every"] = 0
        if module.params["keep_for"] < module.params["every"]:
            module.fail_json(
                msg="Retention period cannot be less than snapshot interval."
            )
        if module.params["at"] and not module.params["timezone"]:
            module.params["timezone"] = _get_local_tz(module)
            if module.params["timezone"] not in set(pytz.all_timezones_set):
                module.fail_json(
                    msg="Timezone {0} is not valid".format(module.params["timezone"])
                )

        if module.params["keep_for"]:
            if not 300 <= module.params["keep_for"] <= 34560000:
                module.fail_json(
                    msg="keep_for parameter is out of range (300 to 34560000)"
                )
            if not 300 <= module.params["every"] <= 34560000:
                module.fail_json(
                    msg="every parameter is out of range (300 to 34560000)"
                )
            if module.params["at"]:
                attr = Policy(
                    enabled=module.params["enabled"],
                    rules=[
                        PolicyRule(
                            keep_for=module.params["keep_for"] * 1000,
                            every=module.params["every"] * 1000,
                            at=_convert_to_millisecs(module.params["at"]),
                            time_zone=module.params["timezone"],
                        )
                    ],
                )
            else:
                attr = Policy(
                    enabled=module.params["enabled"],
                    rules=[
                        PolicyRule(
                            keep_for=module.params["keep_for"] * 1000,
                            every=module.params["every"] * 1000,
                        )
                    ],
                )
        else:
            attr = Policy(enabled=module.params["enabled"])
        if CONTEXT_API_VERSION in versions:
            res = blade.post_policies(
                names=[module.params["name"]],
                policy=attr,
                context_names=[module.params["context"]],
            )
        else:
            res = blade.post_policies(names=[module.params["name"]], policy=attr)
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create snapshot policy {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if module.params["filesystem"]:
            for filesystem in module.params["filesystem"]:
                if CONTEXT_API_VERSION in versions:
                    res = blade.get_file_systems(
                        names=[filesystem],
                        destroyed=False,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.get_file_systems(names=[filesystem], destroyed=False)
                if res.status_code != 200:
                    module.fail_json(
                        msg="Filesystems to assign to {0} does not "
                        "exist, or is deleted.".format(module.params["name"])
                    )
                if CONTEXT_API_VERSION in versions:
                    res = blade.post_policies_file_systems(
                        policy_names=[module.params["name"]],
                        member_names=[filesystem],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.post_policies_file_systems(
                        policy_names=[module.params["name"]],
                        member_names=[filesystem],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add filesystem {0} to "
                        "policy {1}. Error: {2}.".format(
                            filesystem, module.params["name"], res.errors[0].message
                        )
                    )
        if module.params["replica_link"]:
            repl_link = []
            for link in module.params["replica_link"]:
                if CONTEXT_API_VERSION in versions:
                    res = blade.get_file_system_replica_links(
                        local_file_system_names=[link],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.get_file_system_replica_links(
                        local_file_system_names=[link]
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Replica Link {0} does not exist.".format(link)
                    )
                else:
                    repl_link = list(res.items)[0]
                if CONTEXT_API_VERSION in versions:
                    res = blade.post_policies_file_system_replica_links(
                        policy_names=[module.params["name"]],
                        local_file_system_names=[link],
                        remote_names=[repl_link.remote.name],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.post_policies_file_system_replica_links(
                        policy_names=[module.params["name"]],
                        local_file_system_names=[link],
                        remote_names=[repl_link.remote.name],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to connect filesystem replicsa link {0} to policy {1}. "
                        "Error: {2}".format(
                            link, module.params["name"], res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def update_snap_policy(module, blade):
    """Update snapshot policy

    Add new rules to the policy using this function.
    Should it be necessary to modify an existing rule these are the rules:

    Due to the 'best fit' nature of Purity we only add new rulkes in this function.
    If you trying to update an existing rule, then this should be done by deleting
    the current rule and then adding the new rule.

    Purity may recover some snapshots as long as the add happens before the eradication delay
    (typically 24h) causes the snapshots to be eradicated.
    """

    changed = False
    versions = list(blade.get_versions().items)
    if (
        module.params["keep_for"]
        and not module.params["every"]
        or module.params["every"]
        and not module.params["keep_for"]
    ):
        module.fail_json(msg="`keep_for` and `every` are required.")
    if module.params["timezone"] and not module.params["at"]:
        module.fail_json(msg="`timezone` requires `at` to be provided.")
    if module.params["at"] and not module.params["every"]:
        module.fail_json(msg="`at` requires `every` to be provided.")
    if CONTEXT_API_VERSION in versions:
        current_rules = list(
            blade.get_policies(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).items
        )[0].rules
    else:
        current_rules = list(blade.get_policies(names=[module.params["name"]]).items)[
            0
        ].rules
    create_new = False
    for rule in range(len(current_rules)):
        current_rule = {
            "at": current_rules[rule].at,
            "every": current_rules[rule].every,
            "keep_for": current_rules[rule].keep_for,
            "time_zone": current_rules[rule].time_zone,
        }
        if not module.params["at"]:
            new_at = current_rules[rule].at
        else:
            new_at = _convert_to_millisecs(module.params["at"])
        if module.params["keep_for"]:
            new_keep_for = module.params["keep_for"]
        else:
            new_keep_for = int(current_rules[rule].keep_for / 1000)
        if module.params["every"]:
            new_every = module.params["every"]
        else:
            new_every = int(current_rules[rule].every / 1000)
        if not module.params["timezone"]:
            new_tz = current_rules[rule].time_zone
        else:
            new_tz = module.params["timezone"]
        new_rule = {
            "at": new_at,
            "every": new_every * 1000,
            "keep_for": new_keep_for * 1000,
            "time_zone": new_tz,
        }
        if current_rule != new_rule:
            create_new = True

    if create_new:
        changed = True
        if not module.check_mode:
            if module.params["at"] and module.params["every"]:
                if not module.params["every"] % 86400 == 0:
                    module.fail_json(
                        msg="At time can only be set if every value is a multiple of 86400"
                    )
                if not module.params["timezone"]:
                    module.params["timezone"] = _get_local_tz(module)
                    if module.params["timezone"] not in pytz.all_timezones_set:
                        module.fail_json(
                            msg="Timezone {0} is not valid".format(
                                module.params["timezone"]
                            )
                        )
            if not module.params["keep_for"]:
                module.params["keep_for"] = 0
            if not module.params["every"]:
                module.params["every"] = 0
            if module.params["keep_for"] < module.params["every"]:
                module.fail_json(
                    msg="Retention period cannot be less than snapshot interval."
                )
            if module.params["at"] and not module.params["timezone"]:
                module.params["timezone"] = _get_local_tz(module)
                if module.params["timezone"] not in set(pytz.all_timezones_set):
                    module.fail_json(
                        msg="Timezone {0} is not valid".format(
                            module.params["timezone"]
                        )
                    )

            if module.params["keep_for"]:
                if not 300 <= module.params["keep_for"] <= 34560000:
                    module.fail_json(
                        msg="keep_for parameter is out of range (300 to 34560000)"
                    )
                if not 300 <= module.params["every"] <= 34560000:
                    module.fail_json(
                        msg="every parameter is out of range (300 to 34560000)"
                    )
                if module.params["at"]:
                    attr = PolicyPatch(
                        enabled=module.params["enabled"],
                        add_rules=[
                            PolicyRule(
                                keep_for=module.params["keep_for"] * 1000,
                                every=module.params["every"] * 1000,
                                at=_convert_to_millisecs(module.params["at"]),
                                time_zone=module.params["timezone"],
                            )
                        ],
                    )
                else:
                    attr = PolicyPatch(
                        enabled=module.params["enabled"],
                        add_rules=[
                            PolicyRule(
                                keep_for=module.params["keep_for"] * 1000,
                                every=module.params["every"] * 1000,
                            )
                        ],
                    )
            else:
                attr = PolicyPatch(enabled=module.params["enabled"])
            if CONTEXT_API_VERSION in versions:
                res = blade.patch_policies(
                    names=[module.params["name"]],
                    policy=attr,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_policies(
                    names=[module.params["name"]],
                    policy=attr,
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update snapshot policy {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )

    if module.params["filesystem"]:
        current_filesystems = []
        if CONTEXT_API_VERSION in versions:
            policy_fs_details = list(
                blade.get_policies_file_systems(
                    policy_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                ).items
            )
        else:
            policy_fs_details = list(
                blade.get_policies_file_systems(
                    policy_names=[module.params["name"]]
                ).items
            )
        for member in range(len(policy_fs_details)):
            current_filesystems.append(policy_fs_details[member].member.name)
        if module.params["state"] == "present":
            difference_set = [
                item
                for item in module.params["filesystem"]
                if item not in current_filesystems
            ]
            for new_fs in difference_set:
                changed = True
                if CONTEXT_API_VERSION in versions:
                    res = blade.get_file_systems(
                        names=[new_fs],
                        destroyed=False,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.get_file_systems(names=[new_fs], destroyed=False)
                if res.status_code != 200:
                    module.fail_json(
                        msg="Filesystem {0} to assign to {1} does not "
                        "exist, or is deleted.".format(new_fs, module.params["name"])
                    )
                if CONTEXT_API_VERSION in versions:
                    res = blade.post_policies_file_systems(
                        policy_names=[module.params["name"]],
                        member_names=[new_fs],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.post_policies_file_systems(
                        policy_names=[module.params["name"]],
                        member_names=[new_fs],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add filesystem {0} to "
                        "policy {1}. Error: {2}.".format(
                            new_fs, module.params["name"], res.errors[0].message
                        )
                    )
        else:
            for old_fs in module.params["filesystem"]:
                if old_fs in current_filesystems:
                    changed = True
                    if CONTEXT_API_VERSION in versions:
                        res = blade.delete_policies_file_systems(
                            policy_names=[module.params["name"]],
                            member_names=[old_fs],
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.delete_policies_file_systems(
                            policy_names=[module.params["name"]],
                            member_names=[old_fs],
                        )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to remove filesystem {0} from "
                            "policy {1}. Error: {2}.".format(
                                old_fs, module.params["name"], res.errors[0].message
                            )
                        )
    if module.params["replica_link"]:
        current_rls = []
        if CONTEXT_API_VERSION in versions:
            policy_rl_details = list(
                blade.get_policies_file_system_replica_links(
                    policy_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                ).items
            )
        else:
            policy_rl_details = list(
                blade.get_policies_file_system_replica_links(
                    policy_names=[module.params["name"]]
                ).items
            )
        for member in range(len(policy_rl_details)):
            current_rls.append(policy_rl_details[member].member.name)
        if module.params["state"] == "present":
            difference_set = [
                item
                for item in module.params["replica_link"]
                if item not in current_rls
            ]
            for new_rl in difference_set:
                changed = True
                if CONTEXT_API_VERSION in versions:
                    res = blade.get_file_systems_replica_links(
                        names=[new_rl], context_names=[module.params["context"]]
                    )
                else:
                    res = blade.get_file_systems_replica_links(names=[new_rl])
                if res.status_code != 200:
                    module.fail_json(
                        msg="Replica link {0} to assign to {1} does not "
                        "exist, or is deleted.".format(new_rl, module.params["name"])
                    )
                if CONTEXT_API_VERSION in versions:
                    res = blade.post_policies_file_system_replica_links(
                        policy_names=[module.params["name"]],
                        member_names=[new_rl],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.post_policies_file_system_replica_links(
                        policy_names=[module.params["name"]],
                        member_names=[new_rl],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add replica link {0} to "
                        "policy {1}. Error: {2}.".format(
                            new_rl, module.params["name"], res.errors[0].message
                        )
                    )
        else:
            for old_rl in module.params["replica_link"]:
                if old_rl in current_rls:
                    changed = True
                    if CONTEXT_API_VERSION in versions:
                        res = blade.delete_policies_file_system_replica_links(
                            policy_names=[module.params["name"]],
                            member_names=[old_rl],
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = blade.delete_policies_file_system_replica_links(
                            policy_names=[module.params["name"]],
                            member_names=[old_rl],
                        )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to remove replica link {0} from "
                            "policy {1}. Error: {2}.".format(
                                old_rl, module.params["name"], res.errors[0].message
                            )
                        )

    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str", default="present", choices=["absent", "present", "copy"]
            ),
            policy_type=dict(
                type="str",
                default="snapshot",
                choices=[
                    "snapshot",
                    "access",
                    "nfs",
                    "smb_share",
                    "smb_client",
                    "network",
                    "worm",
                ],
            ),
            enabled=dict(type="bool", default=True),
            timezone=dict(type="str"),
            name=dict(type="str"),
            at=dict(type="str"),
            every=dict(type="int"),
            keep_for=dict(type="int"),
            filesystem=dict(type="list", elements="str"),
            replica_link=dict(type="list", elements="str"),
            account=dict(type="str"),
            target=dict(type="str"),
            target_rule=dict(type="str"),
            rename=dict(type="str"),
            rule=dict(type="str"),
            user=dict(type="str"),
            effect=dict(type="str", default="allow", choices=["allow", "deny"]),
            actions=dict(
                type="list",
                elements="str",
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
            object_resources=dict(type="list", elements="str"),
            source_ips=dict(type="list", elements="str"),
            s3_prefixes=dict(type="list", elements="str"),
            s3_delimiters=dict(type="list", elements="str"),
            ignore_enforcement=dict(type="bool", default=True),
            force_delete=dict(type="bool", default=False),
            access=dict(
                type="str",
                choices=["root-squash", "all-squash", "no-squash"],
                default="root-squash",
            ),
            anonuid=dict(type="str"),
            anongid=dict(type="str"),
            atime=dict(type="bool", default=True),
            client=dict(type="str"),
            fileid_32bit=dict(type="bool", default=False),
            permission=dict(type="str", choices=["rw", "ro"], default="ro"),
            secure=dict(type="bool", default=False),
            destroy_snapshots=dict(type="bool", default=False),
            security=dict(
                type="list",
                elements="str",
                choices=["sys", "krb5", "krb5i", "krb5p"],
                default=["sys"],
            ),
            before_rule=dict(type="int"),
            principal=dict(type="str"),
            change=dict(type="str", choices=["deny", "allow", ""]),
            read=dict(type="str", choices=["deny", "allow", ""]),
            full_control=dict(type="str", choices=["deny", "allow", ""]),
            smb_encryption=dict(
                type="str",
                default="optional",
                choices=["disabled", "optional", "required"],
            ),
            desc=dict(type="str", default=""),
            interfaces=dict(
                type="list",
                elements="str",
                choices=[
                    "management-ssh",
                    "management-rest-api",
                    "management-web-ui",
                    "snmp",
                    "local-network-superuser-password-access",
                ],
            ),
            default_retention=dict(type="str"),
            min_retention=dict(type="str"),
            max_retention=dict(type="str"),
            retention_lock=dict(type="str", choices=["locked", "unlocked"]),
            context=dict(type="str", default=""),
        )
    )

    required_together = [["keep_for", "every"]]
    required_if = [
        ["policy_type", "access", ["account", "name"]],
        ["policy_type", "nfs", ["name"]],
        ["policy_type", "smb_client", ["name"]],
        ["policy_type", "smb_share", ["name"]],
        ["policy_type", "network", ["interfaces"]],
    ]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    if not HAS_PYTZ:
        module.fail_json(msg="pytz is required for this module")

    state = module.params["state"]
    blade = get_system(module)
    versions = list(blade.get_versions().items)
    if module.params["policy_type"] == "access":
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(
                blade.get_object_store_access_policies(
                    names=[module.params["account"] + "/" + module.params["name"]]
                ).items
            )[0]
        except AttributeError:
            policy = None
        if module.params["user"]:
            member_name = module.params["account"] + "/" + module.params["user"]
            res = blade.get_object_store_users(names=[member_name])
            if res.status_code != 200:
                module.fail_json(
                    msg="User {0} does not exist in account {1}. Error: {2}".format(
                        module.params["user"],
                        module.params["account"],
                        res.errors[0].message,
                    )
                )
        if policy and state == "present":
            update_os_policy(module, blade)
        elif state == "present" and not policy:
            create_os_policy(module, blade)
        elif state == "absent" and policy:
            delete_os_policy(module, blade)
        elif state == "copy" and module.params["target"] and module.params["rule"]:
            if "/" not in module.params["target"]:
                module.fail_json(
                    msg='Incorrect format for target policy. Must be "<account>/<name>"'
                )
            if (
                blade.get_object_store_access_policies(
                    names=[module.params["target"]]
                ).status_code
                != 200
            ):
                module.fail_json(
                    msg="Target policy {0} does not exist".format(
                        module.params["target"]
                    )
                )
            copy_os_policy_rule(module, blade)
    elif module.params["policy_type"] == "nfs":
        new_policy = None
        if NFS_POLICY_API_VERSION not in versions:
            module.fail_json(
                msg=(
                    "Minimum FlashBlade REST version required: {0}".format(
                        NFS_POLICY_API_VERSION
                    )
                )
            )
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(
                blade.get_nfs_export_policies(names=[module.params["name"]]).items
            )[0]
        except AttributeError:
            policy = None
        if module.params["rename"]:
            try:
                new_policy = list(
                    blade.get_nfs_export_policies(names=[module.params["rename"]]).items
                )[0]
            except AttributeError:
                new_policy = None
        if policy and state == "present" and not module.params["rename"]:
            if module.params["before_rule"]:
                res = blade.get_nfs_export_policies_rules(
                    policy_names=[module.params["name"]],
                    names=[
                        module.params["name"] + "." + str(module.params["before_rule"])
                    ],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Rule index {0} does not exist.".format(
                            module.params["before_rule"]
                        )
                    )
            update_nfs_policy(module, blade)
        elif (
            state == "present" and module.params["rename"] and policy and not new_policy
        ):
            rename_nfs_policy(module, blade)
        elif state == "present" and not policy and not module.params["rename"]:
            create_nfs_policy(module, blade)
        elif state == "absent" and policy:
            delete_nfs_policy(module, blade)
    elif module.params["policy_type"] == "smb_client":
        if SMB_POLICY_API_VERSION not in versions:
            module.fail_json(
                msg=(
                    "Minimum FlashBlade REST version required: {0}".format(
                        SMB_POLICY_API_VERSION
                    )
                )
            )
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(
                blade.get_smb_client_policies(names=[module.params["name"]]).items
            )[0]
        except AttributeError:
            policy = None
        if module.params["rename"]:
            try:
                new_policy = list(
                    blade.get_smb_client_policies(names=[module.params["rename"]]).items
                )[0]
            except AttributeError:
                new_policy = None
        if policy and state == "present" and not module.params["rename"]:
            if module.params["before_rule"]:
                res = blade.get_smb_client_policies_rules(
                    policy_names=[module.params["name"]],
                    names=[
                        module.params["name"] + "." + str(module.params["before_rule"])
                    ],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Rule index {0} does not exist.".format(
                            module.params["before_rule"]
                        )
                    )
            update_smb_client_policy(module, blade)
        elif (
            state == "present" and module.params["rename"] and policy and not new_policy
        ):
            rename_smb_client_policy(module, blade)
        elif state == "present" and not policy and not module.params["rename"]:
            create_smb_client_policy(module, blade)
        elif state == "absent" and policy:
            delete_smb_client_policy(module, blade)
    elif module.params["policy_type"] == "smb_share":
        if SMB_POLICY_API_VERSION not in versions:
            module.fail_json(
                msg=(
                    "Minimum FlashBlade REST version required: {0}".format(
                        SMB_POLICY_API_VERSION
                    )
                )
            )
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(
                blade.get_smb_share_policies(names=[module.params["name"]]).items
            )[0]
        except AttributeError:
            policy = None
        if module.params["rename"]:
            try:
                new_policy = list(
                    blade.get_smb_share_policies(names=[module.params["rename"]]).items
                )[0]
            except AttributeError:
                new_policy = None
        if policy and state == "present" and not module.params["rename"]:
            if module.params["before_rule"]:
                res = blade.get_smb_share_policies_rules(
                    policy_names=[module.params["name"]],
                    names=[
                        module.params["name"] + "." + str(module.params["before_rule"])
                    ],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Rule index {0} does not exist.".format(
                            module.params["before_rule"]
                        )
                    )
            update_smb_share_policy(module, blade)
        elif (
            state == "present" and module.params["rename"] and policy and not new_policy
        ):
            rename_smb_share_policy(module, blade)
        elif state == "present" and not policy and not module.params["rename"]:
            create_smb_share_policy(module, blade)
        elif state == "absent" and policy:
            delete_smb_share_policy(module, blade)
    elif module.params["policy_type"] == "network":
        if NET_POLICY_API_VERSION not in versions:
            module.fail_json(
                msg=(
                    "Minimum FlashBlade REST version required: {0}".format(
                        NET_POLICY_API_VERSION
                    )
                )
            )
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(
                blade.get_network_access_policies(names=[module.params["name"]]).items
            )[0]
        except AttributeError:
            policy = None
        if module.params["rename"]:
            try:
                new_policy = list(
                    blade.get_network_access_policies(
                        names=[module.params["rename"]]
                    ).items
                )[0]
            except AttributeError:
                new_policy = None
        if policy and state == "present" and not module.params["rename"]:
            if module.params["before_rule"]:
                res = blade.get_network_access_policies_rules(
                    policy_names=[module.params["name"]],
                    names=[
                        module.params["name"] + "." + str(module.params["before_rule"])
                    ],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Rule index {0} does not exist.".format(
                            module.params["before_rule"]
                        )
                    )
            update_network_access_policy(module, blade)
        elif (
            state == "present" and module.params["rename"] and policy and not new_policy
        ):
            rename_network_access_policy(module, blade)
        elif state == "present" and not policy and not module.params["rename"]:
            create_network_access_policy(module, blade)
        elif state == "absent" and policy:
            delete_network_access_policy(module, blade)
    elif module.params["policy_type"] == "worm":
        if WORM_POLICY_API_VERSION not in versions:
            module.fail_json(
                msg=(
                    "Minimum FlashBlade REST version required: {0}".format(
                        WORM_POLICY_API_VERSION
                    )
                )
            )
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(
                blade.get_worm_data_policies(names=[module.params["name"]]).items
            )[0]
        except AttributeError:
            policy = None
        if module.params["rename"]:
            try:
                new_policy = list(
                    blade.get_worm_data_policies(names=[module.params["rename"]]).items
                )[0]
            except AttributeError:
                new_policy = None
        if policy and state == "present" and not module.params["rename"]:
            if module.params["before_rule"]:
                res = blade.get_worm_data_policies_rules(
                    policy_names=[module.params["name"]],
                    names=[
                        module.params["name"] + "." + str(module.params["before_rule"])
                    ],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Rule index {0} does not exist.".format(
                            module.params["before_rule"]
                        )
                    )
            update_worm_data_policy(module, blade)
        elif (
            state == "present" and module.params["rename"] and policy and not new_policy
        ):
            rename_worm_data_policy(blade)
        elif state == "present" and not policy and not module.params["rename"]:
            create_worm_data_policy(module, blade)
        elif state == "absent" and policy:
            delete_worm_data_policy(module, blade)
    else:
        if not HAS_PYPURECLIENT:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        blade = get_system(module)
        try:
            policy = list(blade.get_policies(names=[module.params["name"]]).items)[0]
        except AttributeError:
            policy = None
        if not policy and state == "present":
            create_snap_policy(module, blade)
        elif policy and state == "present":
            update_snap_policy(module, blade)
        elif policy and state == "absent":
            if module.params["filesystem"] or module.params["replica_link"]:
                update_snap_policy(module, blade)
            else:
                delete_snap_policy(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
