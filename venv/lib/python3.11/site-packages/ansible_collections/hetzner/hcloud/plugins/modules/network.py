#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: network

short_description: Create and manage cloud Networks on the Hetzner Cloud.


description:
    - Create, update and manage cloud Networks on the Hetzner Cloud.
    - You need at least hcloud-python 1.3.0.

author:
    - Lukas Kaemmerling (@lkaemmerling)

options:
    id:
        description:
            - The ID of the Hetzner Cloud Networks to manage.
            - Only required if no Network I(name) is given.
        type: int
    name:
        description:
            - The Name of the Hetzner Cloud Network to manage.
            - Only required if no Network I(id) is given or a Network does not exist.
        type: str
    ip_range:
        description:
            - IP range of the Network.
            - Required if Network does not exist.
        type: str
    expose_routes_to_vswitch:
        description:
            - Indicates if the routes from this network should be exposed to the vSwitch connection.
            - The exposing only takes effect if a vSwitch connection is active.
        type: bool
    labels:
        description:
            - User-defined labels (key-value pairs).
        type: dict
    delete_protection:
        description:
            - Protect the Network for deletion.
        type: bool
    state:
        description:
            - State of the Network.
        default: present
        choices: [ absent, present ]
        type: str

extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a basic network
  hetzner.hcloud.network:
    name: my-network
    ip_range: 10.0.0.0/8
    state: present

- name: Ensure the Network is absent (remove if needed)
  hetzner.hcloud.network:
    name: my-network
    state: absent
"""

RETURN = """
hcloud_network:
    description: The Network
    returned: always
    type: complex
    contains:
        id:
            description: ID of the Network
            type: int
            returned: always
            sample: 12345
        name:
            description: Name of the Network
            type: str
            returned: always
            sample: my-volume
        ip_range:
            description: IP range of the Network
            type: str
            returned: always
            sample: 10.0.0.0/8
        expose_routes_to_vswitch:
            description: Indicates if the routes from this network should be exposed to the vSwitch connection.
            type: bool
            returned: always
            sample: false
        delete_protection:
            description: True if Network is protected for deletion
            type: bool
            returned: always
            sample: false
            version_added: "0.1.0"
        labels:
            description: User-defined labels (key-value pairs)
            type: dict
            returned: always
            sample:
                key: value
                mylabel: 123
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.networks import BoundNetwork


class AnsibleHCloudNetwork(AnsibleHCloud):
    represent = "hcloud_network"

    hcloud_network: BoundNetwork | None = None

    def _prepare_result(self):
        return {
            "id": self.hcloud_network.id,
            "name": self.hcloud_network.name,
            "ip_range": self.hcloud_network.ip_range,
            "expose_routes_to_vswitch": self.hcloud_network.expose_routes_to_vswitch,
            "delete_protection": self.hcloud_network.protection["delete"],
            "labels": self.hcloud_network.labels,
        }

    def _get_network(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_network = self.client.networks.get_by_id(self.module.params.get("id"))
            else:
                self.hcloud_network = self.client.networks.get_by_name(self.module.params.get("name"))
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create_network(self):
        self.module.fail_on_missing_params(required_params=["name", "ip_range"])
        params = {
            "name": self.module.params.get("name"),
            "ip_range": self.module.params.get("ip_range"),
            "labels": self.module.params.get("labels"),
        }

        expose_routes_to_vswitch = self.module.params.get("expose_routes_to_vswitch")
        if expose_routes_to_vswitch is not None:
            params["expose_routes_to_vswitch"] = expose_routes_to_vswitch

        try:
            if not self.module.check_mode:
                self.client.networks.create(**params)

                delete_protection = self.module.params.get("delete_protection")
                if delete_protection is not None:
                    self._get_network()
                    action = self.hcloud_network.change_protection(delete=delete_protection)
                    action.wait_until_finished()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)
        self._mark_as_changed()
        self._get_network()

    def _update_network(self):
        try:
            name = self.module.params.get("name")
            if name is not None and self.hcloud_network.name != name:
                self.module.fail_on_missing_params(required_params=["id"])
                if not self.module.check_mode:
                    self.hcloud_network.update(name=name)
                self._mark_as_changed()

            labels = self.module.params.get("labels")
            if labels is not None and labels != self.hcloud_network.labels:
                if not self.module.check_mode:
                    self.hcloud_network.update(labels=labels)
                self._mark_as_changed()

            ip_range = self.module.params.get("ip_range")
            if ip_range is not None and ip_range != self.hcloud_network.ip_range:
                if not self.module.check_mode:
                    action = self.hcloud_network.change_ip_range(ip_range=ip_range)
                    action.wait_until_finished()
                self._mark_as_changed()

            expose_routes_to_vswitch = self.module.params.get("expose_routes_to_vswitch")
            if (
                expose_routes_to_vswitch is not None
                and expose_routes_to_vswitch != self.hcloud_network.expose_routes_to_vswitch
            ):
                if not self.module.check_mode:
                    self.hcloud_network.update(expose_routes_to_vswitch=expose_routes_to_vswitch)
                self._mark_as_changed()

            delete_protection = self.module.params.get("delete_protection")
            if delete_protection is not None and delete_protection != self.hcloud_network.protection["delete"]:
                if not self.module.check_mode:
                    action = self.hcloud_network.change_protection(delete=delete_protection)
                    action.wait_until_finished()
                self._mark_as_changed()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)
        self._get_network()

    def present_network(self):
        self._get_network()
        if self.hcloud_network is None:
            self._create_network()
        else:
            self._update_network()

    def delete_network(self):
        try:
            self._get_network()
            if self.hcloud_network is not None:
                if not self.module.check_mode:
                    self.client.networks.delete(self.hcloud_network)
                self._mark_as_changed()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)
        self.hcloud_network = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                ip_range={"type": "str"},
                expose_routes_to_vswitch={"type": "bool"},
                labels={"type": "dict"},
                delete_protection={"type": "bool"},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["id", "name"]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudNetwork.define_module()

    hcloud = AnsibleHCloudNetwork(module)
    state = module.params["state"]
    if state == "absent":
        hcloud.delete_network()
    elif state == "present":
        hcloud.present_network()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
