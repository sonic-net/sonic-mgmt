#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: server_info

short_description: Gather infos about your Hetzner Cloud servers.


description:
    - Gather infos about your Hetzner Cloud servers.

author:
    - Lukas Kaemmerling (@LKaemmerling)

options:
    id:
        description:
            - The ID of the server you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name of the server you want to get.
        type: str
    label_selector:
        description:
            - The label selector for the server you want to get.
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud server infos
  hetzner.hcloud.server_info:
  register: output

- name: Print the gathered infos
  debug:
    var: output.hcloud_server_info
"""

RETURN = """
hcloud_server_info:
    description: The server infos as list
    returned: always
    type: complex
    contains:
        id:
            description: Numeric identifier of the server
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the server
            returned: always
            type: str
            sample: my-server
        created:
            description: Point in time when the Server was created (in ISO-8601 format)
            returned: always
            type: str
            sample: "2023-11-06T13:36:56+00:00"
        status:
            description: Status of the server
            returned: always
            type: str
            sample: running
        server_type:
            description: Name of the server type of the server
            returned: always
            type: str
            sample: cx22
        ipv4_address:
            description: Public IPv4 address of the server
            returned: always
            type: str
            sample: 116.203.104.109
        ipv6:
            description: IPv6 network of the server
            returned: always
            type: str
            sample: 2a01:4f8:1c1c:c140::/64
        private_networks:
            description: List of private networks the server is attached to (name)
            returned: always
            type: list
            elements: str
            sample: ['my-network', 'another-network']
        private_networks_info:
            description: List of private networks the server is attached to (dict with name and ip)
            returned: always
            type: list
            elements: dict
            sample: [{'name': 'my-network', 'ip': '192.168.1.1'}, {'name': 'another-network', 'ip': '10.185.50.40'}]
        location:
            description: Name of the location of the server
            returned: always
            type: str
            sample: fsn1
        placement_group:
            description: Placement Group of the server
            type: str
            returned: always
            sample: 4711
            version_added: "1.5.0"
        datacenter:
            description: Name of the datacenter of the server
            returned: always
            type: str
            sample: fsn1-dc14
        rescue_enabled:
            description: True if rescue mode is enabled, Server will then boot into rescue system on next reboot
            returned: always
            type: bool
            sample: false
        backup_window:
            description: Time window (UTC) in which the backup will run, or null if the backups are not enabled
            returned: always
            type: bool
            sample: 22-02
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
        delete_protection:
            description: True if server is protected for deletion
            type: bool
            returned: always
            sample: false
            version_added: "0.1.0"
        rebuild_protection:
            description: True if server is protected for rebuild
            type: bool
            returned: always
            sample: false
            version_added: "0.1.0"
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.servers import BoundServer


class AnsibleHCloudServerInfo(AnsibleHCloud):
    represent = "hcloud_server_info"

    hcloud_server_info: list[BoundServer] | None = None

    def _prepare_result(self):
        tmp = []

        for server in self.hcloud_server_info:
            if server is None:
                continue

            tmp.append(
                {
                    "id": server.id,
                    "name": server.name,
                    "created": server.created.isoformat(),
                    "ipv4_address": server.public_net.ipv4.ip if server.public_net.ipv4 is not None else None,
                    "ipv6": server.public_net.ipv6.ip if server.public_net.ipv6 is not None else None,
                    "private_networks": [net.network.name for net in server.private_net],
                    "private_networks_info": [{"name": net.network.name, "ip": net.ip} for net in server.private_net],
                    "image": server.image.name if server.image is not None else None,
                    "server_type": server.server_type.name,
                    "datacenter": server.datacenter.name,
                    "location": server.datacenter.location.name,
                    "placement_group": server.placement_group.name if server.placement_group is not None else None,
                    "rescue_enabled": server.rescue_enabled,
                    "backup_window": server.backup_window,
                    "labels": server.labels,
                    "status": server.status,
                    "delete_protection": server.protection["delete"],
                    "rebuild_protection": server.protection["rebuild"],
                }
            )
        return tmp

    def get_servers(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_server_info = [self.client.servers.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_server_info = [self.client.servers.get_by_name(self.module.params.get("name"))]
            elif self.module.params.get("label_selector") is not None:
                self.hcloud_server_info = self.client.servers.get_all(
                    label_selector=self.module.params.get("label_selector")
                )
            else:
                self.hcloud_server_info = self.client.servers.get_all()

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
    module = AnsibleHCloudServerInfo.define_module()
    hcloud = AnsibleHCloudServerInfo(module)

    hcloud.get_servers()
    result = hcloud.get_result()

    ansible_info = {"hcloud_server_info": result["hcloud_server_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
