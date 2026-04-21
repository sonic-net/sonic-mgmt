#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: volume_info

short_description: Gather infos about your Hetzner Cloud Volumes.

description:
    - Gather infos about your Hetzner Cloud Volumes.

author:
    - Lukas Kaemmerling (@LKaemmerling)

options:
    id:
        description:
            - The ID of the Volume you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name of the Volume you want to get.
        type: str
    label_selector:
        description:
            - The label selector for the Volume you want to get.
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud Volume infos
  hetzner.hcloud.volume_info:
  register: output
- name: Print the gathered infos
  debug:
    var: output.hcloud_volume_info
"""

RETURN = """
hcloud_volume_info:
    description: The Volume infos as list
    returned: always
    type: complex
    contains:
        id:
            description: Numeric identifier of the Volume
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the Volume
            returned: always
            type: str
            sample: my-volume
        size:
            description: Size of the Volume
            returned: always
            type: str
            sample: 10
        linux_device:
            description: Path to the device that contains the Volume.
            returned: always
            type: str
            sample: /dev/disk/by-id/scsi-0HC_Volume_12345
            version_added: "0.1.0"
        location:
            description: Name of the location where the Volume resides in
            returned: always
            type: str
            sample: fsn1
        server:
            description: Name of the server where the Volume is attached to
            returned: always
            type: str
            sample: my-server
        delete_protection:
            description: True if the Volume is protected for deletion
            returned: always
            type: bool
            version_added: "0.1.0"
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.volumes import BoundVolume


class AnsibleHCloudVolumeInfo(AnsibleHCloud):
    represent = "hcloud_volume_info"

    hcloud_volume_info: list[BoundVolume] | None = None

    def _prepare_result(self):
        tmp = []

        for volume in self.hcloud_volume_info:
            if volume is None:
                continue

            tmp.append(
                {
                    "id": volume.id,
                    "name": volume.name,
                    "size": volume.size,
                    "location": volume.location.name,
                    "labels": volume.labels,
                    "server": volume.server.name if volume.server is not None else None,
                    "linux_device": volume.linux_device,
                    "delete_protection": volume.protection["delete"],
                }
            )

        return tmp

    def get_volumes(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_volume_info = [self.client.volumes.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_volume_info = [self.client.volumes.get_by_name(self.module.params.get("name"))]
            elif self.module.params.get("label_selector") is not None:
                self.hcloud_volume_info = self.client.volumes.get_all(
                    label_selector=self.module.params.get("label_selector")
                )
            else:
                self.hcloud_volume_info = self.client.volumes.get_all()

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                label_selector={"type": "str"},
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudVolumeInfo.define_module()
    hcloud = AnsibleHCloudVolumeInfo(module)

    hcloud.get_volumes()
    result = hcloud.get_result()

    ansible_info = {"hcloud_volume_info": result["hcloud_volume_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
