#!/usr/bin/python

# Copyright: (c) 2020, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: load_balancer

short_description: Create and manage cloud Load Balancers on the Hetzner Cloud.

description:
    - Create, update and manage cloud Load Balancers on the Hetzner Cloud.
    - To manage the DNS pointer of a Load Balancer, use the M(hetzner.hcloud.rdns) module.

author:
    - Lukas Kaemmerling (@LKaemmerling)
version_added: 0.1.0
options:
    id:
        description:
            - The ID of the Hetzner Cloud Load Balancer to manage.
            - Only required if no Load Balancer I(name) is given
        type: int
    name:
        description:
            - The Name of the Hetzner Cloud Load Balancer to manage.
            - Only required if no Load Balancer I(id) is given or a Load Balancer does not exist.
        type: str
    load_balancer_type:
        description:
            - The Load Balancer Type of the Hetzner Cloud Load Balancer to manage.
            - Required if Load Balancer does not exist.
        type: str
    algorithm:
        description:
            - Algorithm of the Load Balancer.
        type: str
        default: round_robin
        choices: [round_robin, least_connections]
    location:
        description:
            - Location of Load Balancer.
            - Required if no I(network_zone) is given and Load Balancer does not exist.
        type: str
    network_zone:
        description:
            - Network Zone of Load Balancer.
            - Required of no I(location) is given and Load Balancer does not exist.
        type: str
    labels:
        description:
            - User-defined labels (key-value pairs).
        type: dict
    disable_public_interface:
        description:
            - Disables the public interface.
        type: bool
        default: False
    delete_protection:
        description:
            - Protect the Load Balancer for deletion.
        type: bool
    state:
        description:
            - State of the Load Balancer.
        default: present
        choices: [ absent, present ]
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a basic Load Balancer
  hetzner.hcloud.load_balancer:
    name: my-Load Balancer
    load_balancer_type: lb11
    algorithm: round_robin
    location: fsn1
    state: present

- name: Ensure the Load Balancer is absent (remove if needed)
  hetzner.hcloud.load_balancer:
    name: my-Load Balancer
    state: absent
"""

RETURN = """
hcloud_load_balancer:
    description: The Load Balancer instance
    returned: Always
    type: complex
    contains:
        id:
            description: Numeric identifier of the Load Balancer
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the Load Balancer
            returned: always
            type: str
            sample: my-Load-Balancer
        load_balancer_type:
            description: Name of the Load Balancer type of the Load Balancer
            returned: always
            type: str
            sample: cx22
        algorithm:
            description: Algorithm of the Load Balancer.
            returned: always
            type: str
            choices: [round_robin, least_connections]
            sample: round_robin
        ipv4_address:
            description: Public IPv4 address of the Load Balancer
            returned: always
            type: str
            sample: 116.203.104.109
        ipv6_address:
            description: Public IPv6 address of the Load Balancer
            returned: always
            type: str
            sample: 2a01:4f8:1c1c:c140::1
        location:
            description: Name of the location of the Load Balancer
            returned: always
            type: str
            sample: fsn1
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
        delete_protection:
            description: True if Load Balancer is protected for deletion
            type: bool
            returned: always
            sample: false
        disable_public_interface:
            description: True if Load Balancer public interface is disabled
            type: bool
            returned: always
            sample: false
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.load_balancers import (
    BoundLoadBalancer,
    LoadBalancerAlgorithm,
)


class AnsibleHCloudLoadBalancer(AnsibleHCloud):
    represent = "hcloud_load_balancer"

    hcloud_load_balancer: BoundLoadBalancer | None = None

    def _prepare_result(self):
        return {
            "id": self.hcloud_load_balancer.id,
            "name": self.hcloud_load_balancer.name,
            "ipv4_address": self.hcloud_load_balancer.public_net.ipv4.ip,
            "ipv6_address": self.hcloud_load_balancer.public_net.ipv6.ip,
            "private_ipv4_address": (
                self.hcloud_load_balancer.private_net[0].ip if len(self.hcloud_load_balancer.private_net) else None
            ),
            "load_balancer_type": self.hcloud_load_balancer.load_balancer_type.name,
            "algorithm": self.hcloud_load_balancer.algorithm.type,
            "location": self.hcloud_load_balancer.location.name,
            "labels": self.hcloud_load_balancer.labels,
            "delete_protection": self.hcloud_load_balancer.protection["delete"],
            "disable_public_interface": not self.hcloud_load_balancer.public_net.enabled,
        }

    def _get_load_balancer(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_load_balancer = self.client.load_balancers.get_by_id(self.module.params.get("id"))
            else:
                self.hcloud_load_balancer = self.client.load_balancers.get_by_name(self.module.params.get("name"))
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create_load_balancer(self):
        self.module.fail_on_missing_params(required_params=["name", "load_balancer_type"])
        try:
            params = {
                "name": self.module.params.get("name"),
                "algorithm": LoadBalancerAlgorithm(type=self.module.params.get("algorithm", "round_robin")),
                "load_balancer_type": self.client.load_balancer_types.get_by_name(
                    self.module.params.get("load_balancer_type")
                ),
                "labels": self.module.params.get("labels"),
            }

            if self.module.params.get("location") is None and self.module.params.get("network_zone") is None:
                self.module.fail_json(msg="one of the following is required: location, network_zone")
            elif self.module.params.get("location") is not None and self.module.params.get("network_zone") is None:
                params["location"] = self.client.locations.get_by_name(self.module.params.get("location"))
            elif self.module.params.get("location") is None and self.module.params.get("network_zone") is not None:
                params["network_zone"] = self.module.params.get("network_zone")

            if not self.module.check_mode:
                resp = self.client.load_balancers.create(**params)
                resp.action.wait_until_finished()

                delete_protection = self.module.params.get("delete_protection")
                if delete_protection is not None:
                    self._get_load_balancer()
                    action = self.hcloud_load_balancer.change_protection(delete=delete_protection)
                    action.wait_until_finished()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)
        self._mark_as_changed()
        self._get_load_balancer()

    def _update_load_balancer(self):
        try:
            labels = self.module.params.get("labels")
            if labels is not None and labels != self.hcloud_load_balancer.labels:
                if not self.module.check_mode:
                    self.hcloud_load_balancer.update(labels=labels)
                self._mark_as_changed()

            delete_protection = self.module.params.get("delete_protection")
            if delete_protection is not None and delete_protection != self.hcloud_load_balancer.protection["delete"]:
                if not self.module.check_mode:
                    action = self.hcloud_load_balancer.change_protection(delete=delete_protection)
                    action.wait_until_finished()
                self._mark_as_changed()
            self._get_load_balancer()

            disable_public_interface = self.module.params.get("disable_public_interface")
            if disable_public_interface is not None and disable_public_interface != (
                not self.hcloud_load_balancer.public_net.enabled
            ):
                if not self.module.check_mode:
                    if disable_public_interface is True:
                        action = self.hcloud_load_balancer.disable_public_interface()
                        action.wait_until_finished()
                    else:
                        action = self.hcloud_load_balancer.enable_public_interface()
                        action.wait_until_finished()
                self._mark_as_changed()

            load_balancer_type = self.module.params.get("load_balancer_type")
            if (
                load_balancer_type is not None
                and self.hcloud_load_balancer.load_balancer_type.name != load_balancer_type
            ):
                new_load_balancer_type = self.client.load_balancer_types.get_by_name(load_balancer_type)
                if not new_load_balancer_type:
                    self.module.fail_json(msg="unknown load balancer type")
                if not self.module.check_mode:
                    action = self.hcloud_load_balancer.change_type(
                        load_balancer_type=new_load_balancer_type,
                    )
                    action.wait_until_finished()

                self._mark_as_changed()

            algorithm = self.module.params.get("algorithm")
            if algorithm is not None and self.hcloud_load_balancer.algorithm.type != algorithm:
                action = self.hcloud_load_balancer.change_algorithm(algorithm=LoadBalancerAlgorithm(type=algorithm))
                action.wait_until_finished()
                self._mark_as_changed()

            self._get_load_balancer()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def present_load_balancer(self):
        self._get_load_balancer()
        if self.hcloud_load_balancer is None:
            self._create_load_balancer()
        else:
            self._update_load_balancer()

    def delete_load_balancer(self):
        try:
            self._get_load_balancer()
            if self.hcloud_load_balancer is not None:
                if not self.module.check_mode:
                    self.client.load_balancers.delete(self.hcloud_load_balancer)
                self._mark_as_changed()
            self.hcloud_load_balancer = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                load_balancer_type={"type": "str"},
                algorithm={"choices": ["round_robin", "least_connections"], "default": "round_robin"},
                location={"type": "str"},
                network_zone={"type": "str"},
                labels={"type": "dict"},
                delete_protection={"type": "bool"},
                disable_public_interface={"type": "bool", "default": False},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["id", "name"]],
            mutually_exclusive=[["location", "network_zone"]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudLoadBalancer.define_module()

    hcloud = AnsibleHCloudLoadBalancer(module)
    state = module.params.get("state")
    if state == "absent":
        hcloud.delete_load_balancer()
    elif state == "present":
        hcloud.present_load_balancer()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
