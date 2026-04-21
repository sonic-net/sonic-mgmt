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
module: purefa_endpoint
short_description:  Manage VMware protocol-endpoints on Pure Storage FlashArrays
version_added: '1.0.0'
description:
- Create, delete or eradicate the an endpoint on a Pure Storage FlashArray.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the endpoint.
    type: str
    required: true
  state:
    description:
    - Define whether the endpoint should exist or not.
    default: present
    choices: [ absent, present ]
    type: str
  eradicate:
    description:
    - Define whether to eradicate the endpoint on delete or leave in trash.
    type: bool
    default: false
  rename:
    description:
    - Value to rename the specified endpoint to.
    - Rename only applies to the container the current endpoint is in.
    type: str
  host:
    description:
    - name of host to attach endpoint to
    type: str
  hgroup:
    description:
    - name of hostgroup to attach endpoint to
    type: str
  context:
    description:
    - Name of fleet member on which to perform the volume operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.39.0'
  container_version:
    description:
    - Defines vCenter and EXSi host compatibility of the protocol endpoint
      and its associated container.
    type: int
    choices: [1, 2, 3]
    default: 1
    version_added: '1.39.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new endpoint named foo
  purestorage.flasharray.purefa_endpoint:
    name: test-endpoint
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Delete and eradicate endpoint named foo
  purestorage.flasharray.purefa_endpoint:
    name: foo
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Rename endpoint foor to bar
  purestorage.flasharray.purefa_endpoint:
    name: foo
    rename: bar
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
volume:
    description: A dictionary describing the changed volume.  Only some
        attributes below will be returned with various actions.
    type: dict
    returned: success
    contains:
        source:
            description: Volume name of source volume used for volume copy
            type: str
        serial:
            description: Volume serial number
            type: str
            sample: '361019ECACE43D83000120A4'
        created:
            description: Volume creation time
            type: str
            sample: '2019-03-13T22:49:24Z'
        name:
            description: Volume name
            type: str
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import (
        VolumePost,
        VolumePatch,
        ProtocolEndpoint,
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

CONTEXT_VERSION = "2.38"


def _volfact(module, array, volume_name):
    api_version = array.get_rest_version()
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            volume_data = list(
                array.get_volumes(
                    names=[volume_name], context_names=[module.params["context"]]
                ).items
            )[0]
        else:
            volume_data = list(array.get_volumes(names=[volume_name]).items)[0]
        volfact = {
            "name": volume_data.name,
            "source": getattr(volume_data.source, "name", None),
            "serial": volume_data.serial,
            "created": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(volume_data.created / 1000)
            ),
            "destroyed": volume_data.destroyed,
        }
    else:
        volfact = {}
    return volfact


def get_volume(module, volume, array):
    """Return Volume or None"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_volumes(
            names=[volume], context_names=[module.params["context"]]
        )
    else:
        res = array.get_volumes(names=[volume])
    if res.status_code != 200:
        return None
    return list(res.items)[0]


def create_endpoint(module, array):
    """Create Endpoint"""
    changed = True
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        vg_exists = bool(
            array.get_volume_groups(
                context_names=[module.params["context"]],
                names=[module.params["name"].split("/")[0]],
            ).status_code
            != 200
        )
    else:
        vg_exists = bool(
            array.get_volume_groups(
                names=[module.params["name"].split("/")[0]]
            ).status_code
            != 200
        )
    if "/" in module.params["name"] and not vg_exists:
        module.fail_json(
            msg="Failed to create endpoint {0}. Volume Group does not exist.".format(
                module.params["name"]
            )
        )
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.post_volumes(
                names=[module.params["name"]],
                volume=VolumePost(
                    subtype="protocol_endpoint",
                    protocol_endpoint=ProtocolEndpoint(
                        container_version=str(module.params["container_version"])
                    ),
                ),
                context_names=[module.params["context"]],
            )
        else:
            res = array.post_volumes(
                names=[module.params["name"]],
                volume=VolumePost(
                    subtype="protocol_endpoint",
                    protocol_endpoint=ProtocolEndpoint(
                        container_version=str(module.params["container_version"])
                    ),
                ),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Endpoint {0} creation failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    if module.params["host"]:
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.post_connections(
                    host_names=[module.params["host"]],
                    volume_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.post_connections(
                    host_names=[module.params["host"]],
                    volume_names=[module.params["name"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to attach endpoint {0} to host {1}. Error: {2}".format(
                        module.params["name"],
                        module.params["host"],
                        res.errors[0].message,
                    )
                )
    if module.params["hgroup"]:
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.post_connections(
                    host_group_names=[module.params["hgroup"]],
                    volume_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.post_connections(
                    host_group_names=[module.params["hgroup"]],
                    volume_names=[module.params["name"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to attach endpoint {0} to hostgroup {1}. Error: {2}".format(
                        module.params["name"],
                        module.params["hgroup"],
                        res.errors[0].message,
                    )
                )

    module.exit_json(
        changed=changed, volume=_volfact(module, array, module.params["name"])
    )


def rename_endpoint(module, array):
    """Rename endpoint within a container, ie vgroup or local array"""
    changed = False
    api_version = array.get_rest_version()
    target_name = module.params["rename"]
    if "/" in module.params["rename"] or "::" in module.params["rename"]:
        module.fail_json(msg="Target endpoint cannot include a container name")
    if "/" in module.params["name"]:
        vgroup_name = module.params["name"].split("/")[0]
        target_name = vgroup_name + "/" + module.params["rename"]
    if get_volume(module, target_name, array):
        module.fail_json(msg="Target {0} already exists.".format(target_name))
    changed = True
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.patch_volumes(
                names=[module.params["name"]],
                volume=VolumePatch(name=target_name),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_volumes(
                names=[module.params["name"]], volume=VolumePatch(name=target_name)
            )
    if res.status_code != 200:
        module.fail_json(
            msg="Rename endpoint {0} to {1} failed. Error: {2}".format(
                module.params["name"], module.params["rename"], res.errors[0].message
            )
        )

    module.exit_json(changed=changed, volume=_volfact(module, array, target_name))


def delete_endpoint(module, array):
    """Delete Endpoint"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.patch_volumes(
                names=[module.params["name"]],
                volume=VolumePatch(destroyed=True),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_volumes(
                names=[module.params["name"]], volume=VolumePatch(destroyed=True)
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete endpoint {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].name
                )
            )
        if module.params["eradicate"]:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.delete_volumes(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.delete_volumes(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Eradicate endpoint {0} failed. Erro: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
            module.exit_json(changed=changed, volume=[])
    module.exit_json(
        changed=changed, volume=_volfact(module, array, module.params["name"])
    )


def recover_endpoint(module, array):
    """Recover Deleted Endpoint"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.patch_volumes(
                names=[module.params["name"]],
                volume=VolumePatch(destroyed=False),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_volumes(
                names=[module.params["name"]], volume=VolumePatch(destroyed=False)
            )
        if res.ststus_code != 200:
            module.fail_json(
                msg="Recovery of endpoint {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(
        changed=changed, volume=_volfact(module, array, module.params["name"])
    )


def eradicate_endpoint(module, array):
    """Eradicate Deleted Endpoint"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        if module.params["eradicate"]:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.delete_volumes(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.delete_volumes(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Eradication of endpoint {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed, volume=[])


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            rename=dict(type="str"),
            host=dict(type="str"),
            hgroup=dict(type="str"),
            eradicate=dict(type="bool", default=False),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            context=dict(type="str", default=""),
            container_version=dict(type="int", choices=[1, 2, 3], default=1),
        )
    )

    mutually_exclusive = [["rename", "eradicate"], ["host", "hgroup"]]

    module = AnsibleModule(
        argument_spec, mutually_exclusive=mutually_exclusive, supports_check_mode=True
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this mudule")
    state = module.params["state"]
    array = get_array(module)
    volume = get_volume(module, module.params["name"], array)
    if volume and volume.subtype != "protocol_endpoint":
        module.fail_json(
            msg="Volume {0} is a true volume. Please use the purefa_volume module".format(
                module.params["name"]
            )
        )

    if state == "present" and not volume:
        create_endpoint(module, array)
    elif state == "present" and module.params["rename"]:
        rename_endpoint(module, array)
    elif state == "present" and volume and volume.destroyed:
        recover_endpoint(module, array)
    elif state == "absent":
        delete_endpoint(module, array)
    elif state == "absent" and volume and volume.destroyed:
        eradicate_endpoint(module, array)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
