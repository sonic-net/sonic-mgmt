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
module: purefa_workload
version_added: '1.33.0'
short_description: Manage Fusion Fleet Workloads
description:
- Apply/Rename/Delete Fusion fleet workloads
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  context:
    description:
    - Name of fleet member on which to perform the workload operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
  host:
    type: str
    description:
    - Host to connect to the workload after provisioning
    default: ""
  name:
    description:
    - Name of the workload.
    type: str
    required: true
  state:
    description:
    - Define whether to create or delete a fleet workload.
    - Using the expand option will add volume(s) to the workload.
    - If absent is specified together with a host, rather than deleting the workload, the host will be disconnected from the workload
    default: present
    choices: [ absent, present, expand]
    type: str
  preset:
    description:
    - name of existing preset to use as the basis of the workload
    type: str
  rename:
    description:
    - new name for a workload
    type: str
  eradicate:
    description:
    - whether to eradicate a workload
    type: bool
    default: false
  placement:
    description:
    - name of target on which the workload will be deployed
    type: str
  recommendation:
    description:
    - whether to use the Fusion placement recommendation based
      on the workload preset definitions.
    - This will use the first recommended placement if more than
      one is available
    default: false
    type: bool
  volume_count:
    description:
    - Number of additional volumes to add to an existing workload
    type: int
  volume_configuration:
    description:
    - Name of the volume configuration to use for adding volumes
      to a workload
    type: str
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create a workload using an exisitng preset on a specific placement target and connect to host myhost
  purestorage.flasharray.purefa_workload:
    name: foo
    preset: bar
    host: myhost
    placement: arrayB
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create a workload using an exisitng preset using the recommended target and connect to host myhost
  purestorage.flasharray.purefa_workload:
    name: foo
    preset: bar
    host: myhost
    recommendation: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Add volumes to workload foo based on volume configuration fin and connect to host myhost
  purestorage.flasharray.purefa_workload:
    name: foo
    preset: bar
    volume_configuration: fin
    volume_count: 3
    host: myhost
    state: expand
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Rename an existing workload
  purestorage.flasharray.purefa_workload:
    name: foo
    rename: bar
    state: rename
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disconnect an existing workload from host
  purestorage.flasharray.purefa_workload:
    name: foo
    host: myhost
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete an existing workload
  purestorage.flasharray.purefa_workload:
    name: foo
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Eradicate an existing workload
  purestorage.flasharray.purefa_workload:
    name: foo
    state: absent
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Recover a deleted workload
  purestorage.flasharray.purefa_workload:
    name: foo
    state: present
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Reconnect an existing workload to a host
  purestorage.flasharray.purefa_workload:
    name: foo
    host: myhost
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import (
        WorkloadConfigurationReference,
        WorkloadPatch,
        WorkloadPost,
        WorkloadPlacementRecommendation,
        VolumePost,
        ConnectionPost,
    )
except ImportError:
    HAS_PURESTORAGE = False

import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

VERSION = 1.5
USER_AGENT_BASE = "Ansible"
MIN_REQUIRED_API_VERSION = "2.40"


def _create_volume(module, array):
    """Create an actual volume in a workload"""
    res = array.post_volumes(
        volume=VolumePost(
            workload=WorkloadConfigurationReference(
                name=module.params["name"],
                configuration=module.params["volume_configuration"],
            ),
        ),
        context_names=[module.params["context"]],
    )
    if res.status_code != 200:
        module.fail_json(
            msg="Workload volume creation failed. Error: {0}".format(
                res.errors[0].message
            )
        )


def _disconnect_volumes(module, array):
    """Disconnect host from volumes in the workload"""
    volumes = list(
        array.get_volumes(
            filter="workload.name='{0}'".format(module.params["name"]),
            context_names=[module.params["context"]],
        ).items
    )
    volNames = [vol.name for vol in volumes]

    res = array.delete_connections(
        host_names=[module.params["host"]],
        context_names=[module.params["context"]],
        volume_names=volNames,
    )
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to disconnect volumes from host. Error: {0}:{1}".format(
                res.errors[0].message, res.errors[0].context
            )
        )


def _connect_volumes(module, array):
    """Connect host to volumes in the workload"""
    volumes = list(
        array.get_volumes(
            filter="workload.name='{0}'".format(module.params["name"]),
            context_names=[module.params["context"]],
        ).items
    )
    volNames = [vol.name for vol in volumes]

    res = array.post_connections(
        host_names=[module.params["host"]],
        context_names=[module.params["context"]],
        volume_names=volNames,
        connection=ConnectionPost(),
    )
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to connect volumes to host. Error: {0}:{1}".format(
                res.errors[0].message, res.errors[0].context
            )
        )


def create_workload(module, array, fleet, preset_config):
    """Create fleet workload using existing preset"""
    changed = True
    parameters = preset_config.parameters
    repl_config = preset_config.periodic_replication_configurations
    placement_config = preset_config.placement_configurations
    qos_config = preset_config.qos_configurations
    snap_config = preset_config.snapshot_configurations
    vol_config = preset_config.volume_configurations
    tags = preset_config.workload_tags
    if module.params["recommendation"]:
        # Start the workload calculation for the preset being used
        res = array.post_workloads_placement_recommendations(
            inputs=WorkloadPlacementRecommendation(),
            preset_names=[module.params["preset"]],
            context_names=[module.params["context"]],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Recommendation calculation failure. Error: {0}".format(
                    res.errors[0].message
                )
            )
        workload_calc = list(res.items)[0].name
        # Wait for the workload calulation to complete
        result = list(
            array.get_workloads_placement_recommendations(
                names=[workload_calc], context_names=[module.params["context"]]
            ).items
        )[0]
        while result.status != "completed":
            time.sleep(1)
            result = list(
                array.get_workloads_placement_recommendations(
                    names=[workload_calc], context_names=[module.params["context"]]
                ).items
            )[0]
        # Replace any defined placement with the result from the recommendation
        module.params["placement"] = result.results[0].placements[0].targets[0].name
        module.params["context"] = module.params["placement"]
    if not module.check_mode:
        res = array.post_workloads(
            names=[module.params["name"]],
            preset_names=[module.params["preset"]],
            workload=WorkloadPost(),
            context_names=[module.params["context"]],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create workload {0}. Error: {1}:{2}".format(
                    module.params["name"], res.errors[0].message, res.errors[0].context
                )
            )
        if module.params["host"] != "":
            _connect_volumes(module, array)

    module.exit_json(changed=changed)


def expand_workload(module, array, fleet, volume_configs):
    """Add new volumes to workload"""
    changed = False
    for vol_config in range(0, len(volume_configs)):
        if volume_configs[vol_config].name == module.params["volume_configuration"]:
            for x in range(module.params["volume_count"]):
                changed = True
                _create_volume(module, array)
    if changed:
        if module.params["host"] != "":
            _connect_volumes(module, array)
    else:
        module.fail_json(
            msg="Volume Configuration {0} does not exist for preset {1}.".format(
                module.params["volume_configuration"], module.params["preset"]
            )
        )

    module.exit_json(changed=changed)


def delete_workload(module, array):
    """Delete the workload"""
    changed = True
    if not module.check_mode:
        res = array.patch_workloads(
            names=[module.params["name"]],
            workload=WorkloadPatch(destroyed=True),
            context_names=[module.params["context"]],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Workload deletion failed. Error: {0}".format(res.errors[0].message)
            )
        if module.params["eradicate"]:
            eradicate_workload(module, array)
    module.exit_json(changed=changed)


def eradicate_workload(module, array):
    """Eradicate the workload"""
    changed = True
    if not module.check_mode:
        res = array.delete_workloads(
            names=[module.params["name"]],
            context_names=[module.params["context"]],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Workload eradication failed. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def recover_workload(module, array):
    """Recover the workload and optionally reconnect to host"""
    changed = True
    if not module.check_mode:
        res = array.patch_workloads(
            names=[module.params["name"]],
            workload=WorkloadPatch(destroyed=False),
            context_names=[module.params["context"]],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Workload recovery failed. Error: {0}".format(res.errors[0].message)
            )
        if module.params["host"] != "":
            _connect_volumes(module, array)

    module.exit_json(changed=changed)


def rename_workload(module, array):
    """Rename the workload"""
    changed = True
    if not module.check_mode:
        res = array.patch_workloads(
            names=[module.params["name"]],
            workload=WorkloadPatch(name=module.params["rename"]),
            context_names=[module.params["context"]],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Workload rename failed. Error: {0}".format(res.errors[0].message)
            )
    module.exit_json(changed=changed)


def connect_or_disconnect_volumes(module, array, mode):
    """Connect or disconnect volumes in the workload to a host"""
    changed = False

    res = array.get_connections(
        host_names=[module.params["host"]],
        context_names=[module.params["context"]],
    )
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to get volume connection for host {0}. Error: {1}".format(
                module.params["host"], res.errors[0].message
            )
        )
    volume_connections = [conn.volume.name for conn in list(res.items)]

    res = array.get_volumes(
        filter="workload.name='{0}'".format(module.params["name"]),
        context_names=[module.params["context"]],
    )
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to get volumes for workload {0}. Error: {1}".format(
                module.params["name"], res.errors[0].message
            )
        )
    volumes = list(res.items)

    if mode == "connect":
        for volume in volumes:
            if volume.name not in volume_connections:
                changed = True
    elif mode == "disconnect":
        for volume in volumes:
            if volume.name in volume_connections:
                changed = True

    if not module.check_mode and changed:
        if mode == "connect":
            _connect_volumes(module, array)
        elif mode == "disconnect":
            _disconnect_volumes(module, array)

    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(
                type="str",
                default="present",
                choices=["absent", "present", "expand"],
            ),
            preset=dict(type="str"),
            rename=dict(type="str"),
            eradicate=dict(type="bool", default=False),
            placement=dict(type="str"),
            volume_count=dict(type="int"),
            volume_configuration=dict(type="str"),
            recommendation=dict(type="bool", default=False),
            context=dict(type="str", default=""),
            host=dict(type="str", default=""),
        )
    )

    required_if = [["state", "expand", ["volume_count", "volume_configuration"]]]

    module = AnsibleModule(
        argument_spec, supports_check_mode=True, required_if=required_if
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()
    if LooseVersion(MIN_REQUIRED_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    state = module.params["state"]
    if module.params["volume_count"] and module.params["volume_count"] <= 0:
        module.fail_json(msg="volume_count must be a positive integer.")
    fleet_res = array.get_fleets()
    if fleet_res.status_code != 200:
        module.fail_json(
            msg="Fusion is not enabled on this system "
            "or the array is not a member of a fleet."
        )
    fleet = list(fleet_res.items)[0].name

    workload_destroyed = False
    workload_exists = False
    preset_config = {}
    # Update preset name with fleet prefix
    module.params["preset"] = fleet + ":" + module.params["preset"]
    res = array.get_workloads(
        names=[module.params["name"]], context_names=[module.params["context"]]
    )
    if res.status_code == 200:
        workload_exists = True
        workload_destroyed = list(res.items)[0].destroyed

    if (state == "present" and not workload_destroyed and not workload_exists) or (
        state == "expand" and not workload_destroyed
    ):
        res = array.get_presets_workload(
            names=[module.params["preset"]],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Preset {0} does not exist in fleet {1}".format(
                    module.params["preset"], fleet
                )
            )
        preset_config = list(res.items)[0]
    if (
        state == "present"
        and workload_exists
        and module.params["rename"]
        and not workload_destroyed
    ):
        rename_workload(module, array)
    elif state == "present" and not workload_exists:
        create_workload(module, array, fleet, preset_config)
    elif state == "expand" and workload_exists and not workload_destroyed:
        expand_workload(module, array, fleet, preset_config.volume_configurations)
    elif state == "present" and workload_exists and workload_destroyed:
        recover_workload(module, array)
    elif (
        state == "present"
        and workload_exists
        and not workload_destroyed
        and module.params["host"] != ""
    ):
        connect_or_disconnect_volumes(module, array, "connect")
    elif (
        state == "absent"
        and workload_exists
        and not workload_destroyed
        and module.params["host"] != ""
    ):
        connect_or_disconnect_volumes(module, array, "disconnect")
    elif state == "absent" and workload_exists and not workload_destroyed:
        delete_workload(module, array)
    elif state == "absent" and workload_destroyed and module.params["eradicate"]:
        eradicate_workload(module, array)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
