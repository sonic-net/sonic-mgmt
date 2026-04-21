#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: primary_ip_info

short_description: Gather infos about the Hetzner Cloud Primary IPs.

description:
    - Gather facts about your Hetzner Cloud Primary IPs.

author:
    - Lukas Kaemmerling (@LKaemmerling)
    - Kevin Castner (@kcastner)

options:
    id:
        description:
            - The ID of the Primary IP you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name for the Primary IP you want to get.
        type: str
    label_selector:
        description:
            - The label selector for the Primary IP you want to get.
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud Primary IP infos
  hetzner.hcloud.primary_ip_info:
  register: output

- name: Gather hcloud Primary IP infos by id
  hetzner.hcloud.primary_ip_info:
    id: 673954
  register: output

- name: Gather hcloud Primary IP infos by name
  hetzner.hcloud.primary_ip_info:
    name: srv1-v4
  register: output

- name: Gather hcloud Primary IP infos by label
  hetzner.hcloud.primary_ip_info:
    label_selector: srv03-ips
  register: output

- name: Print the gathered infos
  debug:
    var: output
"""

RETURN = """
hcloud_primary_ip_info:
    description: The Primary IP infos as list
    returned: always
    type: complex
    contains:
        id:
            description: Numeric identifier of the Primary IP
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the Primary IP
            returned: always
            type: str
            sample: my-primary-ip
        ip:
            description: IP address of the Primary IP
            returned: always
            type: str
            sample: 131.232.99.1
        type:
            description: Type of the Primary IP
            returned: always
            type: str
            sample: ipv4
        assignee_id:
            description: Numeric identifier of the ressource where the Primary IP is assigned to.
            returned: always
            type: int
            sample: 19584637
        assignee_type:
            description: Name of the type where the Primary IP is assigned to.
            returned: always
            type: str
            sample: server
        home_location:
            description: Location with datacenter where the Primary IP was created in
            returned: always
            type: str
            sample: fsn1-dc1
        dns_ptr:
            description: Shows the DNS PTR Record for Primary IP.
            returned: always
            type: str
            sample: srv01.example.com
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
        delete_protection:
            description: True if the Primary IP is protected for deletion
            returned: always
            type: bool
        auto_delete:
            description: Delete the Primary IP when the resource it is assigned to is deleted.
            type: bool
            returned: always
            sample: false
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.primary_ips import BoundPrimaryIP


class AnsibleHCloudPrimaryIPInfo(AnsibleHCloud):
    represent = "hcloud_primary_ip_info"

    hcloud_primary_ip_info: list[BoundPrimaryIP] | None = None

    def _prepare_result(self):
        tmp = []

        for primary_ip in self.hcloud_primary_ip_info:
            if primary_ip is None:
                continue

            tmp.append(
                {
                    "id": primary_ip.id,
                    "name": primary_ip.name,
                    "ip": primary_ip.ip,
                    "type": primary_ip.type,
                    "assignee_id": primary_ip.assignee_id if primary_ip.assignee_id is not None else None,
                    "assignee_type": primary_ip.assignee_type,
                    "auto_delete": primary_ip.auto_delete,
                    "home_location": primary_ip.datacenter.name,
                    "dns_ptr": primary_ip.dns_ptr[0]["dns_ptr"] if len(primary_ip.dns_ptr) else None,
                    "labels": primary_ip.labels,
                    "delete_protection": primary_ip.protection["delete"],
                }
            )

        return tmp

    def get_primary_ips(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_primary_ip_info = [self.client.primary_ips.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_primary_ip_info = [self.client.primary_ips.get_by_name(self.module.params.get("name"))]
            elif self.module.params.get("label_selector") is not None:
                self.hcloud_primary_ip_info = self.client.primary_ips.get_all(
                    label_selector=self.module.params.get("label_selector")
                )
            else:
                self.hcloud_primary_ip_info = self.client.primary_ips.get_all()

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                label_selector={"type": "str"},
                name={"type": "str"},
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudPrimaryIPInfo.define_module()
    hcloud = AnsibleHCloudPrimaryIPInfo(module)

    hcloud.get_primary_ips()
    result = hcloud.get_result()

    ansible_info = {"hcloud_primary_ip_info": result["hcloud_primary_ip_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
