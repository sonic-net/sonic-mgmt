#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: server_type_info

short_description: Gather infos about the Hetzner Cloud server types.


description:
    - Gather infos about your Hetzner Cloud server types.

author:
    - Lukas Kaemmerling (@LKaemmerling)

options:
    id:
        description:
            - The ID of the server type you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name of the server type you want to get.
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud server type infos
  hetzner.hcloud.server_type_info:
  register: output

- name: Print the gathered infos
  debug:
    var: output.hcloud_server_type_info
"""

RETURN = """
hcloud_server_type_info:
    description: The server type infos as list
    returned: always
    type: complex
    contains:
        id:
            description: Numeric identifier of the server type
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the server type
            returned: always
            type: str
            sample: fsn1
        description:
            description: Detail description of the server type
            returned: always
            type: str
            sample: Falkenstein DC Park 1
        category:
            description: Category of Server Type
            returned: always
            type: str
            sample: Shared vCPU
        cores:
            description: Number of cpu cores a server of this type will have
            returned: always
            type: int
            sample: 1
        memory:
            description: Memory a server of this type will have in GB
            returned: always
            type: int
            sample: 1
        disk:
            description: Disk size a server of this type will have in GB
            returned: always
            type: int
            sample: 25
        storage_type:
            description: Type of server boot drive
            returned: always
            type: str
            sample: local
        cpu_type:
            description: Type of cpu
            returned: always
            type: str
            sample: shared
        architecture:
            description: Architecture of cpu
            returned: always
            type: str
            sample: x86
        locations:
            description: List of supported Locations
            returned: always
            type: list
            contains:
                id:
                    description: Numeric identifier of the Location
                    returned: always
                    type: int
                    sample: 1
                name:
                    description: Name of the Location
                    returned: always
                    type: str
                    sample: fsn1
                deprecation:
                    description: Wether the Server Type is deprecated in the Location.
                    returned: when deprecated
                    type: dict
                    contains:
                        announced:
                            description: Date of the deprecation announcement.
                            returned: when deprecated
                            type: str
                            sample: "2025-09-09T09:00:00Z"
                        unavailable_after:
                            description: Date after which the Server Type will be unavailable for new order.
                            returned: when deprecated
                            type: str
                            sample: "2025-12-09T09:00:00Z"
        included_traffic:
            description: |
                Free traffic per month in bytes

                B(Deprecated): This field is deprecated and will be set to C(None) on 5 August 2024.
                See U(https://docs.hetzner.cloud/changelog#2024-07-25-cloud-api-returns-traffic-information-in-different-format).
            returned: always
            type: int
            sample: 21990232555520
        deprecation:
            description: |
              Describes if, when & how the resources was deprecated.
              If this field is set to None the resource is not deprecated. If it has a value, it is considered deprecated.

              B(Deprecated): This field is deprecated and will gradually be phased starting 24 September 2025. Use the locations field instead.
              See U(https://docs.hetzner.cloud/changelog#2025-09-24-per-location-server-types).
            returned: success
            type: dict
            contains:
                announced:
                    description: Date of when the deprecation was announced.
                    returned: success
                    type: str
                    sample: "2021-11-09T09:00:00+00:00"
                unavailable_after:
                    description: |
                      After the time in this field, the resource will not be available from the general listing
                      endpoint of the resource type, and it can not be used in new resources. For example, if this is
                      an image, you can not create new servers with this image after the mentioned date.
                    returned: success
                    type: str
                    sample: "2021-12-01T00:00:00+00:00"

"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.server_types import BoundServerType


class AnsibleHCloudServerTypeInfo(AnsibleHCloud):
    represent = "hcloud_server_type_info"

    hcloud_server_type_info: list[BoundServerType] | None = None

    def _prepare_result(self):
        tmp = []

        for server_type in self.hcloud_server_type_info:
            if server_type is None:
                continue

            tmp.append(
                {
                    "id": server_type.id,
                    "name": server_type.name,
                    "description": server_type.description,
                    "category": server_type.category,
                    "cores": server_type.cores,
                    "memory": server_type.memory,
                    "disk": server_type.disk,
                    "storage_type": server_type.storage_type,
                    "cpu_type": server_type.cpu_type,
                    "architecture": server_type.architecture,
                    "locations": [
                        {
                            "id": o.location.id,
                            "name": o.location.name,
                            "deprecation": (
                                {
                                    "announced": o.deprecation.announced.isoformat(),
                                    "unavailable_after": o.deprecation.unavailable_after.isoformat(),
                                }
                                if o.deprecation is not None
                                else None
                            ),
                        }
                        for o in server_type.locations or []
                    ],
                    "included_traffic": server_type.included_traffic,
                    "deprecation": (
                        {
                            "announced": server_type.deprecation.announced.isoformat(),
                            "unavailable_after": server_type.deprecation.unavailable_after.isoformat(),
                        }
                        if server_type.deprecation is not None
                        else None
                    ),
                }
            )
        return tmp

    def get_server_types(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_server_type_info = [self.client.server_types.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_server_type_info = [self.client.server_types.get_by_name(self.module.params.get("name"))]
            else:
                self.hcloud_server_type_info = self.client.server_types.get_all()

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
    module = AnsibleHCloudServerTypeInfo.define_module()
    hcloud = AnsibleHCloudServerTypeInfo(module)

    hcloud.get_server_types()
    result = hcloud.get_result()

    ansible_info = {"hcloud_server_type_info": result["hcloud_server_type_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
