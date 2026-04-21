#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Simon Dodsley (simon@purestorage.com)
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
module: purefa_pg
version_added: '1.0.0'
short_description: Manage protection groups on Pure Storage FlashArrays
description:
- Create, delete or modify protection groups on Pure Storage FlashArrays.
- If a protection group exists and you try to add non-valid types, eg. a host
  to a volume protection group the module will ignore the invalid types.
- Protection Groups on Offload targets are supported.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the protection group.
    type: str
    aliases: [ pgroup ]
    required: true
  state:
    description:
    - Define whether the protection group should exist or not.
    - If specified with I(volume) or I(host) or I(hostgroup) will
      act on those items in the protection group only.
    type: str
    default: present
    choices: [ absent, present ]
  volume:
    description:
    - List of existing volumes to add to protection group.
    - Note that volume are case-sensitive however FlashArray volume names are unique
      and ignore case - you cannot have I(volumea) and I(volumeA)
    type: list
    elements: str
  host:
    description:
    - List of existing hosts to add to protection group.
    - Note that hostnames are case-sensitive however FlashArray hostnames are unique
      and ignore case - you cannot have I(hosta) and I(hostA)
    type: list
    elements: str
  hostgroup:
    description:
    - List of existing hostgroups to add to protection group.
    - Note that hostgroups are case-sensitive however FlashArray hostgroup names are unique
      and ignore case - you cannot have I(groupa) and I(groupA)
    type: list
    elements: str
  eradicate:
    description:
    - Define whether to eradicate the protection group on delete and leave in trash.
    type : bool
    default: false
  enabled:
    description:
    - Define whether to enabled snapshots for the protection group.
    type : bool
    default: true
  target:
    description:
    - List of remote arrays or offload target for replication protection group
      to connect to.
    - Note that all replicated protection groups are asynchronous.
    - Target arrays or offload targets must already be connected to the source array.
    - Maximum number of targets per Portection Group is 4, assuming your
      configuration suppors this.
    type: list
    elements: str
  rename:
    description:
    - Rename a protection group
    - If the source protection group is in a Pod or Volume Group 'container'
      you only need to provide the new protection group name in the same 'container'
    type: str
  safe_mode:
    description:
    - Enables SafeMode restrictions on the protection group
    - B(Once set disabling this can only be performed by Pure Technical Support)
    type: bool
    default: false
    version_added: '1.13.0'
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.33.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new local protection group
  purestorage.flasharray.purefa_pg:
    name: foo
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create new protection group called bar in pod called foo
  purestorage.flasharray.purefa_pg:
    name: "foo::bar"
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create new replicated protection group
  purestorage.flasharray.purefa_pg:
    name: foo
    target:
      - arrayb
      - arrayc
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create new replicated protection group to offload target and remote array
  purestorage.flasharray.purefa_pg:
    name: foo
    target:
      - offload
      - arrayc
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create new protection group with snapshots disabled
  purestorage.flasharray.purefa_pg:
    name: foo
    enabled: false
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete protection group
  purestorage.flasharray.purefa_pg:
    name: foo
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Eradicate protection group foo on offload target where source array is arrayA
  purestorage.flasharray.purefa_pg:
    name: "arrayA:foo"
    target: offload
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Rename protection group foo in pod arrayA to bar
  purestorage.flasharray.purefa_pg:
    name: "arrayA::foo"
    rename: bar
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create protection group for hostgroups
  purestorage.flasharray.purefa_pg:
    name: bar
    hostgroup:
      - hg1
      - hg2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create protection group for hosts
  purestorage.flasharray.purefa_pg:
    name: bar
    host:
      - host1
      - host2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create replicated protection group for volumes
  purestorage.flasharray.purefa_pg:
    name: bar
    volume:
      - vol1
      - vol2
    target: arrayb
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Remove a volume from protection group
  purestorage.flasharray.purefa_pg:
    name: bar
    volume:
      - vol1
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    purefa_argument_spec,
    get_array,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import (
        ProtectionGroup,
        ReplicationSchedule,
        SnapshotSchedule,
    )
except ImportError:
    HAS_PURESTORAGE = False


RETENTION_LOCK_VERSION = "2.13"
CONTEXT_API_VERSION = "2.38"


def get_pod(module, array):
    """Get ActiveCluster Pod"""
    api_version = array.get_rest_version()
    pod_name = module.params["name"].split("::")[0]
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_pods(names=[pod_name], context_names=[module.params["context"]])
    else:
        res = array.get_pods(names=[pod_name])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def get_targets(module, array):
    """Get Offload Targets"""
    api_version = array.get_rest_version()
    targets = []
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        target_details = list(
            array.get_offloads(context_names=[module.params["context"]]).items
        )
    else:
        target_details = list(array.get_offloads().items)

    for targetcnt in range(0, len(target_details)):
        if target_details[targetcnt].status in ["connected", "partially_connected"]:
            targets.append(target_details[targetcnt].name)
    return targets


def get_arrays(module, array):
    """Get Connected Arrays"""
    api_version = array.get_rest_version()
    arrays = []
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        array_details = list(
            array.get_array_connections(context_names=[module.params["context"]]).items
        )
    else:
        array_details = list(array.get_array_connections().items)
    for arraycnt in range(0, len(array_details)):
        if array_details[arraycnt].status in [
            "connected",
            "partially_connected",
        ]:
            arrays.append(array_details[arraycnt].name)
    return arrays


def get_pending_pgroup(module, array):
    """Get Protection Group"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_protection_groups(
            names=[module.params["name"]],
            destroyed=True,
            context_names=[module.params["context"]],
        )
    else:
        res = array.get_protection_groups(names=[module.params["name"]], destroyed=True)
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def get_pgroup(module, array):
    """Get Protection Group"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_protection_groups(
            names=[module.params["name"]],
            destroyed=False,
            context_names=[module.params["context"]],
        )
    else:
        res = array.get_protection_groups(
            names=[module.params["name"]], destroyed=False
        )
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def get_pgroup_sched(module, array):
    """Get Protection Group Schedule"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_protection_groups(
            names=[module.params["name"]],
            destroyed=False,
            context_names=[module.params["context"]],
        )
    else:
        res = array.get_protection_groups(
            names=[module.params["name"]], destroyed=False
        )
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def check_pg_on_offload(module, array):
    """Check if PG already exists on offload target"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        array_name = list(
            array.get_arrays(context_names=[module.params["context"]]).items
        )[0].name
    else:
        array_name = list(array.get_arrays().items)[0].name
    remote_pg = array_name + ":" + module.params["name"]
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_remote_protection_groups(
            names=[remote_pg], context_names=[module.params["context"]]
        )
    else:
        res = array.get_remote_protection_groups(names=[remote_pg])
    if res.status_code == 200:
        return list(res.items)[0].remote.name
    return None


def make_pgroup(module, array):
    """Create Protection Group"""
    api_version = array.get_rest_version()
    changed = True
    if module.params["target"]:
        connected_targets = []
        connected_arrays = get_arrays(module, array)
        connected_targets = get_targets(module, array)
        offload_name = check_pg_on_offload(module, array)
        if offload_name and offload_name in module.params["target"][0:4]:
            module.fail_json(
                msg="Protection Group {0} already exists on offload target {1}.".format(
                    module.params["name"], offload_name
                )
            )

        connected_arrays = connected_arrays + connected_targets
        if not connected_arrays:
            module.fail_json(msg="No connected targets on source array.")
        if set(module.params["target"][0:4]).issubset(connected_arrays):
            if not module.check_mode:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_protection_groups(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_protection_groups(names=[module.params["name"]])
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create protection group {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_protection_groups_targets(
                        group_names=[module.params["name"]],
                        member_names=module.params["target"][0:4],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_protection_groups_targets(
                        group_names=[module.params["name"]],
                        member_names=module.params["target"][0:4],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add targets to protection group {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        else:
            module.fail_json(
                msg="Check all selected targets are connected to the source array."
            )
    else:
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.post_protection_groups(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.post_protection_groups(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create protection group {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    if not module.check_mode:
        if module.params["target"]:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_protection_groups(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                    protection_group=ProtectionGroup(
                        replication_schedule=ReplicationSchedule(
                            enabled=module.params["enabled"]
                        )
                    ),
                )
            else:
                res = array.patch_protection_groups(
                    names=[module.params["name"]],
                    protection_group=ProtectionGroup(
                        replication_schedule=ReplicationSchedule(
                            enabled=module.params["enabled"]
                        )
                    ),
                )
        else:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_protection_groups(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                    protection_group=ProtectionGroup(
                        snapshot_schedule=SnapshotSchedule(
                            enabled=module.params["enabled"]
                        )
                    ),
                )
            else:
                res = array.patch_protection_groups(
                    names=[module.params["name"]],
                    protection_group=ProtectionGroup(
                        snapshot_schedule=SnapshotSchedule(
                            enabled=module.params["enabled"]
                        )
                    ),
                )
        if res.status_code != 200:
            module.fail_json(
                msg="Enabling pgroup {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if module.params["volume"]:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.post_protection_groups_volumes(
                    group_names=[module.params["name"]],
                    member_names=module.params["volume"],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.post_protection_groups_volumes(
                    group_names=[module.params["name"]],
                    member_names=module.params["volume"],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Adding volumes to pgroup {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        if module.params["host"]:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.post_protection_groups_hosts(
                    group_names=[module.params["name"]],
                    member_names=module.params["host"],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.post_protection_groups_hosts(
                    group_names=[module.params["name"]],
                    member_names=module.params["host"],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Adding hosts to pgroup {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        if module.params["hostgroup"]:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.post_protection_groups_host_groups(
                    group_names=[module.params["name"]],
                    member_names=module.params["hostgroup"],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.post_protection_groups_host_groups(
                    group_names=[module.params["name"]],
                    member_names=module.params["hostgroup"],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Adding hostgroups to pgroup {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        if module.params["safe_mode"]:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_protection_groups(
                    context_names=[module.params["context"]],
                    names=[module.params["name"]],
                    protection_group=ProtectionGroup(retention_lock="ratcheted"),
                )
            else:
                res = array.patch_protection_groups(
                    names=[module.params["name"]],
                    protection_group=ProtectionGroup(retention_lock="ratcheted"),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to set SafeMode on pgroup {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def rename_exists(module, array):
    """Determine if rename target already exists"""
    api_version = array.get_rest_version()
    new_name = module.params["rename"]
    if ":" in module.params["name"]:
        container = module.params["name"].split(":")[0]
        new_name = container + ":" + module.params["rename"]
        if "::" in module.params["name"]:
            new_name = container + "::" + module.params["rename"]
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_protection_groups(
            names=[new_name], context_names=[module.params["context"]]
        )
    else:
        res = array.get_protection_groups(names=[new_name])
    if res.status_code == 200:
        return True
    return False


def update_pgroup(module, array):
    """Update Protection Group"""
    api_version = array.get_rest_version()
    changed = renamed = False
    state = module.params["state"]
    if module.params["target"]:
        connected_targets = []
        connected_arrays = get_arrays(module, array)
        connected_targets = get_targets(module, array)
        connected_arrays = connected_arrays + connected_targets
        if not connected_arrays:
            module.fail_json(msg="No targets connected to source array.")
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            current_connects = list(
                array.get_protection_groups_targets(
                    group_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                ).items
            )
        else:
            current_connects = list(
                array.get_protection_groups_targets(
                    group_names=[module.params["name"]]
                ).items
            )
        current_targets = []

        if current_connects:
            for targetcnt in range(0, len(current_connects)):
                current_targets.append(current_connects[targetcnt].member.name)

        if set(module.params["target"][0:4]) != set(current_targets):
            if not set(module.params["target"][0:4]).issubset(connected_arrays):
                module.fail_json(
                    msg="Check all selected targets are connected to the source array."
                )
            changed = True
            if not module.check_mode:
                for target in range(0, len(module.params["target"][0:4])):
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        res = array.post_protection_groups_targets(
                            group_names=[module.params["name"]],
                            context_names=[module.params["context"]],
                            member_names=[module.params["target"][target]],
                        )
                    else:
                        res = array.post_protection_groups_targets(
                            group_names=[module.params["name"]],
                            member_names=[module.params["target"][target]],
                        )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Changing targets for pgroup {0} failed. Error: {1}".format(
                                module.params["name"], res.errors[0].message
                            )
                        )

    if (
        module.params["target"]
        and module.params["enabled"]
        != get_pgroup_sched(module, array).replication_schedule.enabled
    ):
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_protection_groups(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                    protection_group=ProtectionGroup(
                        replication_schedule=ReplicationSchedule(
                            enabled=module.params["enabled"]
                        ),
                    ),
                )
            else:
                res = array.patch_protection_groups(
                    names=[module.params["name"]],
                    protection_group=ProtectionGroup(
                        replication_schedule=ReplicationSchedule(
                            enabled=module.params["enabled"]
                        )
                    ),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Changing replication enabled state of pgroup {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    elif (
        not module.params["target"]
        and module.params["enabled"]
        != get_pgroup_sched(module, array).snapshot_schedule.enabled
    ):
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_protection_groups(
                    names=[module.params["name"]],
                    protection_group=ProtectionGroup(
                        snapshot_schedule=SnapshotSchedule(
                            enabled=module.params["enabled"]
                        ),
                    ),
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_protection_groups(
                    names=[module.params["name"]],
                    protection_group=ProtectionGroup(
                        snapshot_schedule=SnapshotSchedule(
                            enabled=module.params["enabled"]
                        )
                    ),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Changing snapshot enabled state of pgroup {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    if (
        module.params["volume"]
        and get_pgroup(module, array).host_count == 0
        and get_pgroup(module, array).host_group_count == 0
    ):
        if get_pgroup(module, array).volume_count == 0:
            if not module.check_mode:
                changed = True
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_protection_groups_volumes(
                        group_names=[module.params["name"]],
                        member_names=module.params["volume"],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_protection_groups_volumes(
                        group_names=[module.params["name"]],
                        member_names=module.params["volume"],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Adding volumes to pgroup {0} failed. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        else:
            pgvols = []
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                vols = list(
                    array.get_protection_groups_volumes(
                        group_names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    ).items
                )
            else:
                vols = list(
                    array.get_protection_groups_volumes(
                        group_names=[module.params["name"]]
                    ).items
                )
            for vol in range(0, len(vols)):
                pgvols.append(vols[vol].member["name"])
            if state == "present":
                if not all(x in pgvols for x in module.params["volume"]):
                    if not module.check_mode:
                        changed = True
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            res = array.post_protection_groups_volumes(
                                group_names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                member_names=module.params["volume"],
                            )
                        else:
                            res = array.post_protection_groups_volumes(
                                group_names=[module.params["name"]],
                                member_names=module.params["volume"],
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Adding volumes in pgroup {0} failed. Error: {1}".format(
                                    module.params["name"], res.errors[0].message
                                )
                            )
            else:
                if all(x in pgvols for x in module.params["volume"]):
                    if not module.check_mode:
                        changed = True
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            res = array.delete_protection_groups_volumes(
                                group_names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                member_names=module.params["volume"],
                            )
                        else:
                            res = array.delete_protection_groups_volumes(
                                group_names=[module.params["name"]],
                                member_names=module.params["volume"],
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Removing volumes from pgroup {0} failed. Error: {1}".format(
                                    module.params["name"], res.errors[0].message
                                )
                            )

    if (
        module.params["host"]
        and get_pgroup(module, array).volume_count == 0
        and get_pgroup(module, array).host_group_count == 0
    ):
        if get_pgroup(module, array).host_count == 0:
            if not module.check_mode:
                changed = True
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_protection_groups_hosts(
                        group_names=[module.params["name"]],
                        member_names=module.params["host"],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_protection_groups_hosts(
                        group_names=[module.params["name"]],
                        member_names=module.params["host"],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Adding hosts to pgroup {0} failed. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        else:
            pghosts = []
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                hosts = list(
                    array.get_protection_groups_hosts(
                        group_names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    ).items
                )
            else:
                hosts = list(
                    array.get_protection_groups_hosts(
                        group_names=[module.params["name"]]
                    ).items
                )
            for host in range(0, len(hosts)):
                pghosts.append(hosts[host].member["name"])
            if state == "present":
                if not all(x in pghosts for x in module.params["host"]):
                    if not module.check_mode:
                        changed = True
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            res = array.post_protection_groups_hosts(
                                group_names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                member_names=module.params["host"],
                            )
                        else:
                            res = array.post_protection_groups_hosts(
                                group_names=[module.params["name"]],
                                member_names=module.params["host"],
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Adding hosts in pgroup {0} failed. Error: {1}".format(
                                    module.params["name"], res.errors[0].message
                                )
                            )
            else:
                if all(x in pghosts for x in module.params["host"]):
                    if not module.check_mode:
                        changed = True
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            res = array.delete_protection_groups_hosts(
                                group_names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                member_names=module.params["host"],
                            )
                        else:
                            res = array.delete_protection_groups_hosts(
                                group_names=[module.params["name"]],
                                member_names=module.params["host"],
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Removing hosts from pgroup {0} failed. Error: {1}".format(
                                    module.params["name"], res.errors[0].message
                                )
                            )

    if (
        module.params["hostgroup"]
        and get_pgroup(module, array).host_count == 0
        and get_pgroup(module, array).volume_count == 0
    ):
        if get_pgroup(module, array).host_group_count == 0:
            if not module.check_mode:
                changed = True
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_protection_groups_host_groups(
                        group_names=[module.params["name"]],
                        context_names=[module.params["context"]],
                        member_names=module.params["host"],
                    )
                else:
                    res = array.post_protection_groups_host_groups(
                        group_names=[module.params["name"]],
                        member_names=module.params["host"],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Adding hostgroups in pgroup {0} failed. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        else:
            pghostgs = []
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                hostgs = list(
                    array.get_protection_groups_host_groups(
                        group_names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    ).items
                )
            else:
                hostgs = list(
                    array.get_protection_groups_host_groups(
                        group_names=[module.params["name"]]
                    ).items
                )
            for hostg in range(0, len(hostgs)):
                pghostgs.append(hostgs[hostg].member["name"])
            if state == "present":
                if not all(x in pghostgs for x in module.params["hostgroup"]):
                    if not module.check_mode:
                        changed = True
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            res = array.post_protection_groups_host_groups(
                                group_names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                member_names=module.params["hostgroup"],
                            )
                        else:
                            res = array.post_protection_groups_host_groups(
                                group_names=[module.params["name"]],
                                member_names=module.params["hostgroup"],
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Adding hostgroups in pgroup {0} failed. Error: {1}".format(
                                    module.params["name"], res.errors[0].message
                                )
                            )
            else:
                if all(x in pghostgs for x in module.params["hostgroup"]):
                    if not module.check_mode:
                        changed = True
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            res = array.delete_protection_groups_host_groups(
                                group_names=[module.params["name"]],
                                context_names=[module.params["context"]],
                                member_names=module.params["hostgroup"],
                            )
                        else:
                            res = array.delete_protection_groups_host_groups(
                                group_names=[module.params["name"]],
                                member_names=module.params["hostgroup"],
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Removing hostgroups from pgroup {0} failed. Error: {1}".format(
                                    module.params["name"], res.errors[0].message
                                )
                            )
    if module.params["rename"]:
        if not rename_exists(module, array):
            if ":" in module.params["name"]:
                container = module.params["name"].split(":")[0]
                if "::" in module.params["name"]:
                    rename = container + "::" + module.params["rename"]
                else:
                    rename = container + ":" + module.params["rename"]
            else:
                rename = module.params["rename"]
            renamed = True
            if not module.check_mode:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        protection_group=ProtectionGroup(name=rename),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        protection_group=ProtectionGroup(name=rename),
                    )
                module.params["name"] = rename
                if res.status_code != 200:
                    module.fail_json(
                        msg="Rename to {0} failed. Error: {1}".format(
                            rename, res.errors[0].message
                        )
                    )
        else:
            module.warn(
                "Rename failed. Protection group {0} already exists in container. Continuing with other changes...".format(
                    module.params["rename"]
                )
            )
    if LooseVersion(RETENTION_LOCK_VERSION) <= LooseVersion(api_version):
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            current_pg = list(
                array.get_protection_groups(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                ).items
            )[0]
        else:
            current_pg = list(
                array.get_protection_groups(names=[module.params["name"]]).items
            )[0]
        if current_pg.retention_lock == "unlocked" and module.params["safe_mode"]:
            changed = True
            if not module.check_mode:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        context_names=[module.params["context"]],
                        protection_group=ProtectionGroup(retention_lock="ratcheted"),
                    )
                else:
                    res = array.patch_protection_groups(
                        names=[module.params["name"]],
                        protection_group=ProtectionGroup(retention_lock="ratcheted"),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to set SafeMode on protection group {0}. Error: {1}".format(
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
        if current_pg.retention_lock == "ratcheted" and not module.params["safe_mode"]:
            module.warn(
                "Disabling SafeMode on protection group {0} can only be performed by Pure Technical Support".format(
                    module.params["name"]
                )
            )
    changed = changed or renamed
    module.exit_json(changed=changed)


def eradicate_pgroup(module, array):
    """Eradicate Protection Group"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.delete_protection_groups(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = array.delete_protection_groups(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Eradicating pgroup {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_pgroup(module, array):
    """Delete Protection Group"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_protection_groups(
                names=[module.params["name"]],
                context_names=[module.params["context"]],
                protection_group=ProtectionGroup(destroyed=True),
            )
        else:
            res = array.patch_protection_groups(
                names=[module.params["name"]],
                protection_group=ProtectionGroup(destroyed=True),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Deleting pgroup {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if module.params["eradicate"]:
            eradicate_pgroup(module, array)

    module.exit_json(changed=changed)


def recover_pgroup(module, array):
    """Recover deleted protection group"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_protection_groups(
                names=[module.params["name"]],
                context_names=[module.params["context"]],
                protection_group=ProtectionGroup(destroyed=False),
            )
        else:
            res = array.patch_protection_groups(
                names=[module.params["name"]],
                protection_group=ProtectionGroup(destroyed=False),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Recover pgroup {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True, aliases=["pgroup"]),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            volume=dict(type="list", elements="str"),
            host=dict(type="list", elements="str"),
            hostgroup=dict(type="list", elements="str"),
            target=dict(type="list", elements="str"),
            safe_mode=dict(type="bool", default=False),
            eradicate=dict(type="bool", default=False),
            enabled=dict(type="bool", default=True),
            rename=dict(type="str"),
            context=dict(type="str", default=""),
        )
    )

    mutually_exclusive = [["volume", "host", "hostgroup"]]
    module = AnsibleModule(
        argument_spec, mutually_exclusive=mutually_exclusive, supports_check_mode=True
    )
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required.")

    state = module.params["state"]
    array = get_array(module)
    pattern = re.compile("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    if module.params["rename"]:
        if not pattern.match(module.params["rename"]):
            module.fail_json(
                msg="Rename value {0} does not conform to naming convention".format(
                    module.params["rename"]
                )
            )
        if not pattern.match(module.params["name"].split(":")[-1]):
            module.fail_json(
                msg="Protection Group name {0} does not conform to naming convention".format(
                    module.params["name"]
                )
            )
    api_version = array.get_rest_version()
    if module.params["safe_mode"] and LooseVersion(
        RETENTION_LOCK_VERSION
    ) > LooseVersion(api_version):
        module.fail_json(
            msg="API version does not support setting SafeMode on a protection group."
        )
    if ":" in module.params["name"]:
        if "::" in module.params["name"]:
            pgname = module.params["name"].split("::")[1]
        else:
            pgname = module.params["name"].split(":")[1]
        if not pattern.match(pgname):
            module.fail_json(
                msg="Protection Group name {0} does not conform to naming convention".format(
                    pgname
                )
            )
    else:
        if not pattern.match(module.params["name"]):
            module.fail_json(
                msg="Protection Group name {0} does not conform to naming convention".format(
                    module.params["name"]
                )
            )

    pgroup = get_pgroup(module, array)
    xpgroup = get_pending_pgroup(module, array)
    if "::" in module.params["name"]:
        if not get_pod(module, array):
            module.fail_json(
                msg="Pod {0} does not exist.".format(
                    module.params["name"].split("::")[0]
                )
            )

    if module.params["host"]:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            host_exists = array.get_hosts(
                names=module.params["host"], context_names=[module.params["context"]]
            )
        else:
            host_exists = array.get_hosts(names=module.params["host"])
        if host_exists.status_code != 200:
            module.fail_json(
                msg="Host {0} not found. Error: {1}".format(
                    host_exists.errors[0].context, host_exists.errors[0].message
                )
            )

    if module.params["hostgroup"]:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            hg_exists = array.get_host_groups(
                names=module.params["hostgroup"],
                context_names=[module.params["context"]],
            )
        else:
            hg_exists = array.get_host_groups(names=module.params["hostgroup"])
        if hg_exists.status_code != 200:
            module.fail_json(
                msg="Host Group {0} not found. Error: {1}".format(
                    hg_exists.errors[0].context, hg_exists.errors[0].message
                )
            )

    if pgroup and state == "present":
        update_pgroup(module, array)
    elif (
        pgroup
        and state == "absent"
        and (
            module.params["volume"]
            or module.params["host"]
            or module.params["hostgroup"]
        )
    ):
        update_pgroup(module, array)
    elif pgroup and state == "absent":
        delete_pgroup(module, array)
    elif xpgroup and state == "absent" and module.params["eradicate"]:
        eradicate_pgroup(module, array)
    elif (
        not pgroup
        and not xpgroup
        and state == "present"
        and not module.params["rename"]
    ):
        make_pgroup(module, array)
    elif not pgroup and state == "present" and module.params["rename"]:
        module.exit_json(changed=False)
    elif xpgroup and state == "present":
        recover_pgroup(module, array)
    elif pgroup is None and state == "absent":
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
