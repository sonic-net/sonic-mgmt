#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: route

short_description: Create and delete cloud routes on the Hetzner Cloud.


description:
    - Create, update and delete cloud routes on the Hetzner Cloud.

author:
    - Lukas Kaemmerling (@lkaemmerling)

options:
    network:
        description:
            - Name or ID of the Hetzner Cloud Network.
        type: str
        required: true
    destination:
        description:
            - Destination network or host of this route.
        type: str
        required: true
    gateway:
        description:
            - Gateway for the route.
        type: str
        required: true
    state:
        description:
            - State of the route.
        default: present
        choices: [ absent, present ]
        type: str

extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a basic route
  hetzner.hcloud.route:
    network: my-network
    destination: 10.100.1.0/24
    gateway: 10.0.1.1
    state: present

- name: Ensure the route is absent
  hetzner.hcloud.route:
    network: my-network
    destination: 10.100.1.0/24
    gateway: 10.0.1.1
    state: absent
"""

RETURN = """
hcloud_route:
    description: One Route of a Network
    returned: always
    type: complex
    contains:
        network:
            description: Name of the Network
            type: str
            returned: always
            sample: my-network
        destination:
            description: Destination network or host of this route
            type: str
            returned: always
            sample: 10.0.0.0/8
        gateway:
            description: Gateway of the route
            type: str
            returned: always
            sample: 10.0.0.1
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.networks import BoundNetwork, NetworkRoute


class AnsibleHCloudRoute(AnsibleHCloud):
    represent = "hcloud_route"

    hcloud_network: BoundNetwork | None = None
    hcloud_route: NetworkRoute | None = None

    def _prepare_result(self):
        return {
            "network": self.hcloud_network.name,
            "destination": self.hcloud_route.destination,
            "gateway": self.hcloud_route.gateway,
        }

    def _get_network(self):
        try:
            self.hcloud_network = self._client_get_by_name_or_id(
                "networks",
                self.module.params.get("network"),
            )
            self.hcloud_route = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _get_route(self):
        destination = self.module.params.get("destination")
        gateway = self.module.params.get("gateway")
        for route in self.hcloud_network.routes:
            if route.destination == destination and route.gateway == gateway:
                self.hcloud_route = route

    def _create_route(self):
        route = NetworkRoute(
            destination=self.module.params.get("destination"), gateway=self.module.params.get("gateway")
        )

        if not self.module.check_mode:
            try:
                action = self.hcloud_network.add_route(route=route)
                action.wait_until_finished()
            except HCloudException as exception:
                self.fail_json_hcloud(exception)

        self._mark_as_changed()
        self._get_network()
        self._get_route()

    def present_route(self):
        self._get_network()
        self._get_route()
        if self.hcloud_route is None:
            self._create_route()

    def delete_route(self):
        self._get_network()
        self._get_route()
        if self.hcloud_route is not None and self.hcloud_network is not None:
            if not self.module.check_mode:
                try:
                    action = self.hcloud_network.delete_route(self.hcloud_route)
                    action.wait_until_finished()
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)
            self._mark_as_changed()
        self.hcloud_route = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                network={"type": "str", "required": True},
                gateway={"type": "str", "required": True},
                destination={"type": "str", "required": True},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudRoute.define_module()

    hcloud = AnsibleHCloudRoute(module)
    state = module.params["state"]
    if state == "absent":
        hcloud.delete_route()
    elif state == "present":
        hcloud.present_route()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
