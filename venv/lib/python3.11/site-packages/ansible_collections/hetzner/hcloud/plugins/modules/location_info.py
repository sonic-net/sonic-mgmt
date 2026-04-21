#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: location_info

short_description: Gather infos about your Hetzner Cloud locations.


description:
    - Gather infos about your Hetzner Cloud locations.

author:
    - Lukas Kaemmerling (@LKaemmerling)

options:
    id:
        description:
            - The ID of the location you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name of the location you want to get.
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud location infos
  hetzner.hcloud.location_info:
  register: output

- name: Print the gathered infos
  debug:
    var: output
"""

RETURN = """
hcloud_location_info:
    description: The location infos as list
    returned: always
    type: complex
    contains:
        id:
            description: Numeric identifier of the location
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the location
            returned: always
            type: str
            sample: fsn1
        description:
            description: Detail description of the location
            returned: always
            type: str
            sample: Falkenstein DC Park 1
        country:
            description: Country code of the location
            returned: always
            type: str
            sample: DE
        city:
            description: City of the location
            returned: always
            type: str
            sample: Falkenstein
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.locations import BoundLocation


class AnsibleHCloudLocationInfo(AnsibleHCloud):
    represent = "hcloud_location_info"

    hcloud_location_info: list[BoundLocation] | None = None

    def _prepare_result(self):
        tmp = []

        for location in self.hcloud_location_info:
            if location is None:
                continue

            tmp.append(
                {
                    "id": location.id,
                    "name": location.name,
                    "description": location.description,
                    "city": location.city,
                    "country": location.country,
                }
            )
        return tmp

    def get_locations(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_location_info = [self.client.locations.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_location_info = [self.client.locations.get_by_name(self.module.params.get("name"))]
            else:
                self.hcloud_location_info = self.client.locations.get_all()

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudLocationInfo.define_module()
    hcloud = AnsibleHCloudLocationInfo(module)

    hcloud.get_locations()
    result = hcloud.get_result()

    ansible_info = {"hcloud_location_info": result["hcloud_location_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
