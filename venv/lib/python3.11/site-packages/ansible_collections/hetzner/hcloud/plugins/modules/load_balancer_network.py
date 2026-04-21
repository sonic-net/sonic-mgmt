#!/usr/bin/python

# Copyright: (c) 2020, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: load_balancer_network

short_description: Manage the relationship between Hetzner Cloud Networks and Load Balancers


description:
    - Create and delete the relationship Hetzner Cloud Networks and Load Balancers

author:
    - Lukas Kaemmerling (@lkaemmerling)
version_added: 0.1.0
options:
    network:
        description:
            - Name or ID of the Hetzner Cloud Networks.
        type: str
        required: true
    load_balancer:
        description:
            - Name or ID of the Hetzner Cloud Load Balancer.
        type: str
        required: true
    ip:
        description:
            - The IP the Load Balancer should have.
        type: str
    state:
        description:
            - State of the load_balancer_network.
        default: present
        choices: [ absent, present ]
        type: str

extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a basic Load Balancer network
  hetzner.hcloud.load_balancer_network:
    network: my-network
    load_balancer: my-LoadBalancer
    state: present

- name: Create a Load Balancer network and specify the ip address
  hetzner.hcloud.load_balancer_network:
    network: my-network
    load_balancer: my-LoadBalancer
    ip: 10.0.0.1
    state: present

- name: Ensure the Load Balancer network is absent (remove if needed)
  hetzner.hcloud.load_balancer_network:
    network: my-network
    load_balancer: my-LoadBalancer
    state: absent
"""

RETURN = """
hcloud_load_balancer_network:
    description: The relationship between a Load Balancer and a network
    returned: always
    type: complex
    contains:
        network:
            description: Name of the Network
            type: str
            returned: always
            sample: my-network
        load_balancer:
            description: Name of the Load Balancer
            type: str
            returned: always
            sample: my-LoadBalancer
        ip:
            description: IP of the Load Balancer within the Network ip range
            type: str
            returned: always
            sample: 10.0.0.8
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.load_balancers import BoundLoadBalancer, PrivateNet
from ..module_utils.vendor.hcloud.networks import BoundNetwork


class AnsibleHCloudLoadBalancerNetwork(AnsibleHCloud):
    represent = "hcloud_load_balancer_network"

    hcloud_network: BoundNetwork | None = None
    hcloud_load_balancer: BoundLoadBalancer | None = None
    hcloud_load_balancer_network: PrivateNet | None = None

    def _prepare_result(self):
        return {
            "network": self.hcloud_network.name,
            "load_balancer": self.hcloud_load_balancer.name,
            "ip": self.hcloud_load_balancer_network.ip,
        }

    def _get_load_balancer_and_network(self):
        try:
            self.hcloud_network = self._client_get_by_name_or_id(
                "networks",
                self.module.params.get("network"),
            )
            self.hcloud_load_balancer = self._client_get_by_name_or_id(
                "load_balancers",
                self.module.params.get("load_balancer"),
            )

            self.hcloud_load_balancer_network = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _get_load_balancer_network(self):
        for private_net in self.hcloud_load_balancer.private_net:
            if private_net.network.id == self.hcloud_network.id:
                self.hcloud_load_balancer_network = private_net

    def _create_load_balancer_network(self):
        params = {"network": self.hcloud_network}

        if self.module.params.get("ip") is not None:
            params["ip"] = self.module.params.get("ip")

        if not self.module.check_mode:
            try:
                action = self.hcloud_load_balancer.attach_to_network(**params)
                action.wait_until_finished()
            except HCloudException as exception:
                self.fail_json_hcloud(exception)

        self._mark_as_changed()
        self._get_load_balancer_and_network()
        self._get_load_balancer_network()

    def present_load_balancer_network(self):
        self._get_load_balancer_and_network()
        self._get_load_balancer_network()
        if self.hcloud_load_balancer_network is None:
            self._create_load_balancer_network()

    def delete_load_balancer_network(self):
        self._get_load_balancer_and_network()
        self._get_load_balancer_network()
        if self.hcloud_load_balancer_network is not None and self.hcloud_load_balancer is not None:
            if not self.module.check_mode:
                try:
                    action = self.hcloud_load_balancer.detach_from_network(self.hcloud_load_balancer_network.network)
                    action.wait_until_finished()
                    self._mark_as_changed()
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)

        self.hcloud_load_balancer_network = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                network={"type": "str", "required": True},
                load_balancer={"type": "str", "required": True},
                ip={"type": "str"},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudLoadBalancerNetwork.define_module()

    hcloud = AnsibleHCloudLoadBalancerNetwork(module)
    state = module.params["state"]
    if state == "absent":
        hcloud.delete_load_balancer_network()
    elif state == "present":
        hcloud.present_load_balancer_network()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
