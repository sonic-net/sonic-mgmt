#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: block_storage
short_description: Manages block storage volumes on Vultr
description:
  - Manage block storage volumes.
version_added: "1.0.0"
author:
  - "René Moser (@resmo)"
  - "Yanis Guenane (@Spredzy)"
options:
  label:
    description:
      - Name of the block storage volume.
    required: true
    aliases: [ name ]
    type: str
  size_gb:
    description:
      - Size of the block storage volume in GB.
      - Required if I(state) is present.
      - If it is larger than the volume's current size, the volume will be resized.
    aliases: [ size ]
    type: int
  block_type:
    description:
      - The type of block storage volume that will be created.
    default: high_perf
    choices: [ high_perf, storage_opt ]
    type: str
    version_added: "1.2.0"
  region:
    description:
      - Region the block storage volume is deployed into.
      - Required if I(state) is present.
    type: str
  state:
    description:
      - State of the block storage volume.
    default: present
    choices: [ present, absent]
    type: str
  attached_to_instance:
    description:
      - The ID of the server instance the volume is attached to.
    type: str
  live:
    description:
      - Whether the volume should be attached/detached without restarting the instance.
    type: bool
    default: false
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
---
- name: Ensure a block storage volume is present
  vultr.cloud.block_storage:
    name: myvolume
    size_gb: 10
    block_type: storage_opt
    region: ams

- name: Ensure a block storage volume is absent
  vultr.cloud.block_storage:
    name: myvolume
    state: absent

- name: Ensure a block storage volume exists and is attached a server instance
  vultr.cloud.block_storage:
    name: myvolume
    attached_to_instance: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    size_gb: 50
    block_type: high_perf

- name: Ensure a block storage volume exists but is not attached to any server instance
  vultr.cloud.block_storage:
    name: myvolume
    attached_to_instance: ""
    size_gb: 50
    block_type: high_perf
"""

RETURN = """
---
vultr_api:
  description: Response from Vultr API with a few additions/modification.
  returned: success
  type: dict
  contains:
    api_account:
      description: Account used in the ini file to select the key.
      returned: success
      type: str
      sample: default
    api_timeout:
      description: Timeout used for the API requests.
      returned: success
      type: int
      sample: 60
    api_retries:
      description: Amount of max retries for the API requests.
      returned: success
      type: int
      sample: 5
    api_retry_max_delay:
      description: Exponential backoff delay in seconds between retries up to this max delay value.
      returned: success
      type: int
      sample: 12
    api_endpoint:
      description: Endpoint used for the API requests.
      returned: success
      type: str
      sample: "https://api.vultr.com/v2"
vultr_block_storage:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    attached_to_instance:
      description: The ID of the server instance the volume is attached to.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    cost:
      description: Cost per month for the volume.
      returned: success
      type: float
      sample: 1.00
    date_created:
      description: Date when the volume was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    id:
      description: ID of the block storage volume.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    label:
      description: Label of the volume.
      returned: success
      type: str
      sample: my volume
    region:
      description: Region the volume was deployed into.
      returned: success
      type: str
      sample: ews
    size_gb:
      description: Information about the volume size in GB.
      returned: success
      type: int
      sample: 50
    block_type:
      description: HDD or NVMe (storage_opt or high_perf)
      returned: success
      type: str
      sample: high_perf
    status:
      description: Status about the deployment of the volume.
      returned: success
      type: str
      sample: active
    mount_id:
      description: Mount ID of the volume.
      returned: success
      type: str
      sample: ewr-2f5d7a314fe44f
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


class AnsibleVultrBlockStorage(AnsibleVultr):
    def update(self, resource):
        current_size = resource["size_gb"]
        desired_size = self.module.params["size_gb"]
        if desired_size < current_size:
            self.module.params["size_gb"] = current_size
            self.module.warn("Shrinking is not supported: current size %s, desired size %s" % (current_size, desired_size))
        return super(AnsibleVultrBlockStorage, self).update(resource=resource)

    def present(self):
        resource = self.create_or_update() or dict()

        instance_to_attach = self.module.params.get("attached_to_instance")
        if instance_to_attach is None:
            # exit and show result if no attach/detach needed.
            self.get_result(resource)

        instance_attached = resource.get("attached_to_instance", "")
        if instance_attached != instance_to_attach:
            self.result["changed"] = True

            mode = "detach" if not instance_to_attach else "attach"
            self.result["diff"]["after"].update({"attached_to_instance": instance_to_attach})

            data = {
                "instance_id": instance_to_attach if instance_to_attach else None,
                "live": self.module.params.get("live"),
            }

            if not self.module.check_mode:
                self.api_query(
                    path="%s/%s/%s" % (self.resource_path, resource[self.resource_key_id], mode),
                    method="POST",
                    data=data,
                )
                resource = self.query_by_id(resource_id=resource[self.resource_key_id])

        self.get_result(resource)


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            label=dict(type="str", required=True, aliases=["name"]),
            size_gb=dict(type="int", aliases=["size"]),
            block_type=dict(type="str", choices=["high_perf", "storage_opt"], default="high_perf"),
            region=dict(type="str"),
            state=dict(type="str", choices=["present", "absent"], default="present"),
            attached_to_instance=dict(type="str"),
            live=dict(type="bool", default=False),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["size_gb", "region"]],
        ],
    )

    vultr = AnsibleVultrBlockStorage(
        module=module,
        namespace="vultr_block_storage",
        resource_path="/blocks",
        ressource_result_key_singular="block",
        resource_create_param_keys=["label", "size_gb", "region", "block_type"],
        resource_update_param_keys=["size_gb"],
        resource_key_name="label",
        # Query details information about block type
        resource_get_details=True,
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
