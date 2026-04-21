#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: server_network

short_description: Manage the relationship between Hetzner Cloud Networks and servers


description:
    - Create and delete the relationship Hetzner Cloud Networks and servers

author:
    - Lukas Kaemmerling (@lkaemmerling)

options:
    network:
        description:
            - Name or ID of the Hetzner Cloud Networks.
        type: str
        required: true
    server:
        description:
            - Name or ID of the Hetzner Cloud server.
        type: str
        required: true
    ip:
        description:
            - The IP the server should have.
        type: str
    alias_ips:
        description:
            - Alias IPs the server has.
        type: list
        elements: str
    state:
        description:
            - State of the server_network.
        default: present
        choices: [ absent, present ]
        type: str

extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a basic server network
  hetzner.hcloud.server_network:
    network: my-network
    server: my-server
    state: present

- name: Create a server network and specify the ip address
  hetzner.hcloud.server_network:
    network: my-network
    server: my-server
    ip: 10.0.0.1
    state: present

- name: Create a server network and add alias ips
  hetzner.hcloud.server_network:
    network: my-network
    server: my-server
    ip: 10.0.0.1
    alias_ips:
      - 10.1.0.1
      - 10.2.0.1
    state: present

- name: Ensure the server network is absent (remove if needed)
  hetzner.hcloud.server_network:
    network: my-network
    server: my-server
    state: absent
"""

RETURN = """
hcloud_server_network:
    description: The relationship between a server and a network
    returned: always
    type: complex
    contains:
        network:
            description: Name of the Network
            type: str
            returned: always
            sample: my-network
        server:
            description: Name of the server
            type: str
            returned: always
            sample: my-server
        ip:
            description: IP of the server within the Network ip range
            type: str
            returned: always
            sample: 10.0.0.8
        alias_ips:
            description: Alias IPs of the server within the Network ip range
            type: list
            elements: str
            returned: always
            sample: [10.1.0.1, ...]
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import APIException, HCloudException
from ..module_utils.vendor.hcloud.networks import BoundNetwork
from ..module_utils.vendor.hcloud.servers import BoundServer, PrivateNet


class AnsibleHCloudServerNetwork(AnsibleHCloud):
    represent = "hcloud_server_network"

    hcloud_network: BoundNetwork | None = None
    hcloud_server: BoundServer | None = None
    hcloud_server_network: PrivateNet | None = None

    def _prepare_result(self):
        return {
            "network": self.hcloud_network.name,
            "server": self.hcloud_server.name,
            "ip": self.hcloud_server_network.ip,
            "alias_ips": list(sorted(self.hcloud_server_network.alias_ips)),
        }

    def _get_server_and_network(self):
        try:
            self.hcloud_network = self._client_get_by_name_or_id(
                "networks",
                self.module.params.get("network"),
            )
            self.hcloud_server = self._client_get_by_name_or_id(
                "servers",
                self.module.params.get("server"),
            )
            self.hcloud_server_network = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _get_server_network(self):
        for private_net in self.hcloud_server.private_net:
            if private_net.network.id == self.hcloud_network.id:
                self.hcloud_server_network = private_net

    def _create_server_network(self):
        params = {
            "network": self.hcloud_network,
        }

        if self.module.params.get("ip") is not None:
            params["ip"] = self.module.params.get("ip")
        if self.module.params.get("alias_ips") is not None:
            params["alias_ips"] = self.module.params.get("alias_ips")

        if not self.module.check_mode:
            try:
                action = self.hcloud_server.attach_to_network(**params)
                action.wait_until_finished()
            except HCloudException as exception:
                self.fail_json_hcloud(exception)

        self._mark_as_changed()
        self._get_server_and_network()
        self._get_server_network()

    def _update_server_network(self):
        params = {
            "network": self.hcloud_network,
        }
        alias_ips = self.module.params.get("alias_ips")
        if alias_ips is not None and sorted(self.hcloud_server_network.alias_ips) != sorted(alias_ips):
            params["alias_ips"] = alias_ips

            if not self.module.check_mode:
                try:
                    action = self.hcloud_server.change_alias_ips(**params)
                    action.wait_until_finished()
                except APIException as exception:
                    self.fail_json_hcloud(exception)

            self._mark_as_changed()
        self._get_server_and_network()
        self._get_server_network()

    def present_server_network(self):
        self._get_server_and_network()
        self._get_server_network()
        if self.hcloud_server_network is None:
            self._create_server_network()
        else:
            self._update_server_network()

    def delete_server_network(self):
        self._get_server_and_network()
        self._get_server_network()
        if self.hcloud_server_network is not None and self.hcloud_server is not None:
            if not self.module.check_mode:
                try:
                    action = self.hcloud_server.detach_from_network(self.hcloud_server_network.network)
                    action.wait_until_finished()
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)
            self._mark_as_changed()
        self.hcloud_server_network = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                network={"type": "str", "required": True},
                server={"type": "str", "required": True},
                ip={"type": "str"},
                alias_ips={"type": "list", "elements": "str"},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudServerNetwork.define_module()

    hcloud = AnsibleHCloudServerNetwork(module)
    state = module.params["state"]
    if state == "absent":
        hcloud.delete_server_network()
    elif state == "present":
        hcloud.present_server_network()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
