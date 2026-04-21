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


DOCUMENTATION = """
---
module: purefa_pod_replica
short_description:  Manage ActiveDR pod replica links between Pure Storage FlashArrays
version_added: '1.0.0'
description:
    - This module manages ActiveDR pod replica links between Pure Storage FlashArrays.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - ActiveDR source pod name
    required: true
    type: str
  state:
    description:
      - Creates or modifies a pod replica link
    required: false
    default: present
    type: str
    choices: [ "present", "absent" ]
  target_array:
    description:
      - Remote array name to create replica on.
    required: false
    type: str
  target_pod:
    description:
      - Name of target pod
      - Must not be the same as the local pod.
    type: str
    required: false
  pause:
    description:
      - Pause/unpause a pod replica link
    required: false
    type: bool
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

EXAMPLES = """
- name: Create new pod replica link from foo to bar on arrayB
  purestorage.flasharray.purefa_pod_replica:
    name: foo
    target_array: arrayB
    target_pod: bar
    state: present
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Pause an pod replica link
  purestorage.flasharray.purefa_pod_replica:
    name: foo
    pause: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete pod replica link
  purestorage.flasharray.purefa_pod_replica:
    name: foo
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = """
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import PodReplicaLinkPatch
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

CONTEXT_VERSION = "2.38"


def get_local_pod(module, array):
    """Return Pod or None"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_pods(
            names=[module.params["name"]], context_names=[module.params["context"]]
        )
    else:
        res = array.get_pods(names=[module.params["name"]])
    if res.status_code != 200:
        return None
    return list(res.items)[0]


def get_local_rl(module, array):
    """Return Pod Replica Link or None"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_pod_replica_links(
            local_pod_names=[module.params["name"]],
            context_names=[module.params["context"]],
            total_item_count=True,
        )
    else:
        res = array.get_pod_replica_links(
            local_pod_names=[module.params["name"]], total_item_count=True
        )
    if res.total_item_count == 0:
        return None
    return list(res.items)[0]


def update_rl(module, array, local_rl):
    """Create Pod Replica Link"""
    api_version = array.get_rest_version()
    changed = False
    if module.params["pause"] is not None:
        if local_rl.status != "paused" and module.params["pause"]:
            changed = True
            if not module.check_mode:
                if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                    res = array.patch_pod_replica_links(
                        local_pod_names=module.params["name"],
                        context_names=[module.params["context"]],
                        remote_pod_names=local_rl["remote_pod"]["name"],
                        pod_replica_link=PodReplicaLinkPatch(paused=True),
                    )
                else:
                    res = array.patch_pod_replica_links(
                        local_pod_names=module.params["name"],
                        remote_pod_names=local_rl["remote_pod"]["name"],
                        pod_replica_link=PodReplicaLinkPatch(paused=True),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to pause replica link {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        elif local_rl.status == "paused" and not module.params["pause"]:
            changed = True
            if not module.check_mode:
                if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                    res = array.patch_pod_replica_links(
                        local_pod_names=module.params["name"],
                        context_names=[module.params["context"]],
                        remote_pod_names=local_rl["remote_pod"]["name"],
                        pod_replica_link=PodReplicaLinkPatch(paused=False),
                    )
                else:
                    res = array.patch_pod_replica_links(
                        local_pod_names=module.params["name"],
                        remote_pod_names=local_rl["remote_pod"]["name"],
                        pod_replica_link=PodReplicaLinkPatch(paused=False),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to resume replica link {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def create_rl(module, array):
    """Create Pod Replica Link"""
    api_version = array.get_rest_version()
    changed = True
    if not module.params["target_pod"]:
        module.fail_json(msg="target_pod required to create a new replica link.")
    if not module.params["target_array"]:
        module.fail_json(msg="target_array required to create a new replica link.")
    if array.get_array_connections(total_item_count=True).total_item_count == 0:
        module.fail_json(msg="No connected arrays.")
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_array_connections(
            names=[module.params["target_array"]],
            context_names=[module.params["context"]],
        )
    else:
        res = array.get_array_connections(names=[module.params["target_array"]])
    if res.status_code != 200:
        module.fail_json(
            msg="Target array {0} is not connected to the source array.".format(
                module.params["target_array"]
            )
        )
    connection = list(res.items)[0]
    if connection.status in [
        "connected",
        "connecting",
        "partially_connected",
    ]:
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.post_pod_replica_links(
                    context_names=[module.params["context"]],
                    local_pod_names=[module.params["name"]],
                    remote_names=[module.params["target_array"]],
                    remote_pod_names=[module.params["target_pod"]],
                )
            else:
                res = array.post_pod_replica_links(
                    local_pod_names=[module.params["name"]],
                    remote_names=[module.params["target_array"]],
                    remote_pod_names=[module.params["target_pod"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create replica link {0} to target array {1}. Error: {2}".format(
                        module.params["name"],
                        module.params["target_array"],
                        res.errors[0].message,
                    )
                )
    else:
        module.fail_json(
            msg="Failed to create replica link for pod {0}. Bad status: {1}".format(
                module.params["name"], connection.status
            )
        )
    module.exit_json(changed=changed)


def delete_rl(module, array, local_rl):
    """Delete Pod Replica Link"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.delete_pod_replica_links(
                local_pod_names=[module.params["name"]],
                remote_pod_names=[local_rl["remote_pod"]["name"]],
                context_names=[module.params["context"]],
            )
        else:
            res = array.delete_pod_replica_links(
                local_pod_names=[module.params["name"]],
                remote_pod_names=[local_rl["remote_pod"]["name"]],
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete replica link for pod {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            target_pod=dict(type="str"),
            target_array=dict(type="str"),
            pause=dict(type="bool"),
            state=dict(default="present", choices=["present", "absent"]),
            context=dict(type="str", default=""),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    array = get_array(module)

    local_pod = get_local_pod(module, array)

    if not local_pod:
        module.fail_json(
            msg="Selected local pod {0} does not exist.".format(module.params["name"])
        )

    if local_pod.array_count > 1:
        module.fail_json(
            msg="Local Pod {0} is already stretched to a remote array.".format(
                module.params["name"]
            )
        )

    local_replica_link = get_local_rl(module, array)
    if local_replica_link:
        if local_replica_link.status == "unhealthy":
            module.fail_json(msg="Replca Link unhealthy - please check remote array")
    if state == "present" and not local_replica_link:
        create_rl(module, array)
    elif state == "present" and local_replica_link:
        update_rl(module, array, local_replica_link)
    elif state == "absent" and local_replica_link:
        delete_rl(module, array, local_replica_link)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
