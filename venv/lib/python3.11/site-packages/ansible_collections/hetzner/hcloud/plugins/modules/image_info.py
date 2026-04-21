#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: image_info

short_description: Gather infos about your Hetzner Cloud images.


description:
    - Gather infos about your Hetzner Cloud images.

author:
    - Lukas Kaemmerling (@LKaemmerling)

options:
    id:
        description:
            - The ID of the image you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name of the image you want to get.
        type: str
    label_selector:
        description:
            - The label selector for the images you want to get.
        type: str
    type:
        description:
            - The type for the images you want to get.
        default: system
        choices: [ system, snapshot, backup ]
        type: str
    architecture:
        description:
            - The architecture for the images you want to get.
        type: str
        choices: [ x86, arm ]
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud image infos
  hetzner.hcloud.image_info:
  register: output

- name: Print the gathered infos
  debug:
    var: output
"""

RETURN = """
hcloud_image_info:
    description: The image infos as list
    returned: always
    type: complex
    contains:
        id:
            description: Numeric identifier of the image
            returned: always
            type: int
            sample: 1937415
        type:
            description: Type of the image
            returned: always
            type: str
            sample: system
        status:
            description: Status of the image
            returned: always
            type: str
            sample: available
        name:
            description: Name of the image
            returned: always
            type: str
            sample: ubuntu-22.04
        description:
            description: Detail description of the image
            returned: always
            type: str
            sample: Ubuntu 18.04 Standard 64 bit
        os_flavor:
            description: OS flavor of the image
            returned: always
            type: str
            sample: ubuntu
        os_version:
            description: OS version of the image
            returned: always
            type: str
            sample: 18.04
        architecture:
            description: Image is compatible with this architecture
            returned: always
            type: str
            sample: x86
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.images import BoundImage


class AnsibleHCloudImageInfo(AnsibleHCloud):
    represent = "hcloud_image_info"

    hcloud_image_info: list[BoundImage] | None = None

    def _prepare_result(self):
        tmp = []

        for image in self.hcloud_image_info:
            if image is None:
                continue

            tmp.append(
                {
                    "id": image.id,
                    "status": image.status,
                    "type": image.type,
                    "name": image.name,
                    "description": image.description,
                    "os_flavor": image.os_flavor,
                    "os_version": image.os_version,
                    "architecture": image.architecture,
                    "labels": image.labels,
                }
            )
        return tmp

    def get_images(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_image_info = [self.client.images.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None and self.module.params.get("architecture") is not None:
                self.hcloud_image_info = [
                    self.client.images.get_by_name_and_architecture(
                        self.module.params.get("name"),
                        self.module.params.get("architecture"),
                    )
                ]
            elif self.module.params.get("name") is not None:
                self.module.warn(
                    "This module only returns x86 images by default. Please set architecture:x86|arm to hide this message."
                )
                self.hcloud_image_info = [self.client.images.get_by_name(self.module.params.get("name"))]
            else:
                params = {}
                label_selector = self.module.params.get("label_selector")
                if label_selector:
                    params["label_selector"] = label_selector

                image_type = self.module.params.get("type")
                if image_type:
                    params["type"] = image_type

                architecture = self.module.params.get("architecture")
                if architecture:
                    params["architecture"] = architecture

                self.hcloud_image_info = self.client.images.get_all(**params)

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                label_selector={"type": "str"},
                type={"choices": ["system", "snapshot", "backup"], "default": "system", "type": "str"},
                architecture={"choices": ["x86", "arm"], "type": "str"},
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudImageInfo.define_module()
    hcloud = AnsibleHCloudImageInfo(module)

    hcloud.get_images()
    result = hcloud.get_result()

    ansible_info = {"hcloud_image_info": result["hcloud_image_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
