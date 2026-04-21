#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: subnetwork

short_description: Manage cloud subnetworks on the Hetzner Cloud.


description:
    - Create, update and delete cloud subnetworks on the Hetzner Cloud.

author:
    - Lukas Kaemmerling (@lkaemmerling)

options:
    network:
        description:
            - The name or ID of the Hetzner Cloud Networks.
        type: str
        required: true
    ip_range:
        description:
            - IP range of the subnetwork.
        type: str
        required: true
    type:
        description:
            - Type of subnetwork.
        type: str
        choices: [ server, cloud, vswitch ]
        required: true
    network_zone:
        description:
            - Name of network zone.
        type: str
        required: true
    vswitch_id:
        description:
            - ID of the vSwitch you want to couple with your Network.
            - Required if type == vswitch
        type: int
    state:
        description:
            - State of the subnetwork.
        default: present
        choices: [ absent, present ]
        type: str

extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a basic subnetwork
  hetzner.hcloud.subnetwork:
    network: my-network
    ip_range: 10.0.0.0/16
    network_zone: eu-central
    type: cloud
    state: present

- name: Create a basic subnetwork
  hetzner.hcloud.subnetwork:
    network: my-vswitch-network
    ip_range: 10.0.0.0/24
    network_zone: eu-central
    type: vswitch
    vswitch_id: 123
    state: present

- name: Ensure the subnetwork is absent (remove if needed)
  hetzner.hcloud.subnetwork:
    network: my-network
    ip_range: 10.0.0.0/8
    network_zone: eu-central
    type: cloud
    state: absent
"""

RETURN = """
hcloud_subnetwork:
    description: One Subnet of a Network
    returned: always
    type: complex
    contains:
        network:
            description: Name of the Network
            type: str
            returned: always
            sample: my-network
        ip_range:
            description: IP range of the Network
            type: str
            returned: always
            sample: 10.0.0.0/8
        type:
            description: Type of subnetwork
            type: str
            returned: always
            sample: server
        network_zone:
            description: Name of network zone
            type: str
            returned: always
            sample: eu-central
        vswitch_id:
            description: ID of the vswitch, null if not type vswitch
            type: int
            returned: always
            sample: 123
        gateway:
            description: Gateway of the subnetwork
            type: str
            returned: always
            sample: 10.0.0.1
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.networks import BoundNetwork, NetworkSubnet


class AnsibleHCloudSubnetwork(AnsibleHCloud):
    represent = "hcloud_subnetwork"

    hcloud_network: BoundNetwork | None = None
    hcloud_subnetwork: NetworkSubnet | None = None

    def _prepare_result(self):
        return {
            "network": self.hcloud_network.name,
            "ip_range": self.hcloud_subnetwork.ip_range,
            "type": self.hcloud_subnetwork.type,
            "network_zone": self.hcloud_subnetwork.network_zone,
            "gateway": self.hcloud_subnetwork.gateway,
            "vswitch_id": self.hcloud_subnetwork.vswitch_id,
        }

    def _get_network(self):
        try:
            self.hcloud_network = self._client_get_by_name_or_id(
                "networks",
                self.module.params.get("network"),
            )
            self.hcloud_subnetwork = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _get_subnetwork(self):
        subnet_ip_range = self.module.params.get("ip_range")
        for subnetwork in self.hcloud_network.subnets:
            if subnetwork.ip_range == subnet_ip_range:
                self.hcloud_subnetwork = subnetwork

    def _create_subnetwork(self):
        params = {
            "ip_range": self.module.params.get("ip_range"),
            "type": self.module.params.get("type"),
            "network_zone": self.module.params.get("network_zone"),
        }
        if self.module.params.get("type") == NetworkSubnet.TYPE_VSWITCH:
            self.module.fail_on_missing_params(required_params=["vswitch_id"])
            params["vswitch_id"] = self.module.params.get("vswitch_id")

        if not self.module.check_mode:
            try:
                action = self.hcloud_network.add_subnet(subnet=NetworkSubnet(**params))
                action.wait_until_finished()
            except HCloudException as exception:
                self.fail_json_hcloud(exception)

        self._mark_as_changed()
        self._get_network()
        self._get_subnetwork()

    def present_subnetwork(self):
        self._get_network()
        self._get_subnetwork()
        if self.hcloud_subnetwork is None:
            self._create_subnetwork()

    def delete_subnetwork(self):
        self._get_network()
        self._get_subnetwork()
        if self.hcloud_subnetwork is not None and self.hcloud_network is not None:
            if not self.module.check_mode:
                try:
                    action = self.hcloud_network.delete_subnet(self.hcloud_subnetwork)
                    action.wait_until_finished()
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)
            self._mark_as_changed()
        self.hcloud_subnetwork = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                network={"type": "str", "required": True},
                network_zone={"type": "str", "required": True},
                type={"type": "str", "required": True, "choices": ["server", "cloud", "vswitch"]},
                ip_range={"type": "str", "required": True},
                vswitch_id={"type": "int"},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudSubnetwork.define_module()

    hcloud = AnsibleHCloudSubnetwork(module)
    state = module.params["state"]
    if state == "absent":
        hcloud.delete_subnetwork()
    elif state == "present":
        hcloud.present_subnetwork()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
