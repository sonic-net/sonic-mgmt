#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: load_balancer_target

short_description: Manage Hetzner Cloud Load Balancer targets


description:
    - Create and delete Hetzner Cloud Load Balancer targets

author:
    - Lukas Kaemmerling (@lkaemmerling)
version_added: 0.1.0
options:
    type:
        description:
            - The type of the target.
        type: str
        choices: [ server, label_selector, ip ]
        required: true
    load_balancer:
        description:
            - Name or ID of the Hetzner Cloud Load Balancer.
        type: str
        required: true
    server:
        description:
            - Name or ID of the Hetzner Cloud Server.
            - Required if I(type) is server
        type: str
    label_selector:
        description:
            - A Label Selector that will be used to determine the targets dynamically
            - Required if I(type) is label_selector
        type: str
    ip:
        description:
            - An IP from a Hetzner Dedicated Server, needs to belongs to the same user as the project.
            - Required if I(type) is ip
        type: str
    use_private_ip:
        description:
            - Route the traffic over the private IP of the Load Balancer through a Hetzner Cloud Network.
            - Load Balancer needs to be attached to a network. See M(hetzner.hcloud.load_balancer_network)
        type: bool
        default: False
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
- name: Create a server Load Balancer target
  hetzner.hcloud.load_balancer_target:
    type: server
    load_balancer: my-LoadBalancer
    server: my-server
    state: present

- name: Create a label_selector Load Balancer target
  hetzner.hcloud.load_balancer_target:
    type: label_selector
    load_balancer: my-LoadBalancer
    label_selector: application=backend
    state: present

- name: Create an IP Load Balancer target
  hetzner.hcloud.load_balancer_target:
    type: ip
    load_balancer: my-LoadBalancer
    ip: 127.0.0.1
    state: present

- name: Ensure the Load Balancer target is absent (remove if needed)
  hetzner.hcloud.load_balancer_target:
    type: server
    load_balancer: my-LoadBalancer
    server: my-server
    state: absent
"""

RETURN = """
hcloud_load_balancer_target:
    description: The relationship between a Load Balancer and a network
    returned: always
    type: complex
    contains:
        type:
            description: Type of the Load Balancer Target
            type: str
            returned: always
            sample: server
        load_balancer:
            description: Name of the Load Balancer
            type: str
            returned: always
            sample: my-LoadBalancer
        server:
            description: Name of the Server
            type: str
            returned: if I(type) is server
            sample: my-server
        label_selector:
            description: Label Selector
            type: str
            returned: if I(type) is label_selector
            sample: application=backend
        ip:
            description: IP of the dedicated server
            type: str
            returned: if I(type) is ip
            sample: 127.0.0.1
        use_private_ip:
            description:
                - Route the traffic over the private IP of the Load Balancer through a Hetzner Cloud Network.
                - Load Balancer needs to be attached to a network. See M(hetzner.hcloud.load_balancer_network)
            type: bool
            sample: true
            returned: always
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import APIException, HCloudException
from ..module_utils.vendor.hcloud.load_balancers import (
    BoundLoadBalancer,
    LoadBalancerTarget,
    LoadBalancerTargetIP,
    LoadBalancerTargetLabelSelector,
)
from ..module_utils.vendor.hcloud.servers import BoundServer


class AnsibleHCloudLoadBalancerTarget(AnsibleHCloud):
    represent = "hcloud_load_balancer_target"

    hcloud_load_balancer: BoundLoadBalancer | None = None
    hcloud_load_balancer_target: LoadBalancerTarget | None = None
    hcloud_server: BoundServer | None = None

    def _prepare_result(self):
        result = {
            "type": self.hcloud_load_balancer_target.type,
            "load_balancer": self.hcloud_load_balancer.name,
            "use_private_ip": self.hcloud_load_balancer_target.use_private_ip,
        }

        if self.hcloud_load_balancer_target.type == "server":
            result["server"] = self.hcloud_load_balancer_target.server.name
        elif self.hcloud_load_balancer_target.type == "label_selector":
            result["label_selector"] = self.hcloud_load_balancer_target.label_selector.selector
        elif self.hcloud_load_balancer_target.type == "ip":
            result["ip"] = self.hcloud_load_balancer_target.ip.ip
        return result

    def _get_load_balancer_and_target(self):
        try:
            self.hcloud_load_balancer = self._client_get_by_name_or_id(
                "load_balancers",
                self.module.params.get("load_balancer"),
            )

            if self.module.params.get("type") == "server":
                self.hcloud_server = self._client_get_by_name_or_id(
                    "servers",
                    self.module.params.get("server"),
                )

            self.hcloud_load_balancer_target = None
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _get_load_balancer_target(self):
        for target in self.hcloud_load_balancer.targets:
            if self.module.params.get("type") == "server" and target.type == "server":
                if target.server.id == self.hcloud_server.id:
                    self.hcloud_load_balancer_target = target
            elif self.module.params.get("type") == "label_selector" and target.type == "label_selector":
                if target.label_selector.selector == self.module.params.get("label_selector"):
                    self.hcloud_load_balancer_target = target
            elif self.module.params.get("type") == "ip" and target.type == "ip":
                if target.ip.ip == self.module.params.get("ip"):
                    self.hcloud_load_balancer_target = target

    def _create_load_balancer_target(self):
        params = {"target": None}

        if self.module.params.get("type") == "server":
            self.module.fail_on_missing_params(required_params=["server"])
            params["target"] = LoadBalancerTarget(
                type=self.module.params.get("type"),
                server=self.hcloud_server,
                use_private_ip=self.module.params.get("use_private_ip"),
            )
        elif self.module.params.get("type") == "label_selector":
            self.module.fail_on_missing_params(required_params=["label_selector"])
            params["target"] = LoadBalancerTarget(
                type=self.module.params.get("type"),
                label_selector=LoadBalancerTargetLabelSelector(selector=self.module.params.get("label_selector")),
                use_private_ip=self.module.params.get("use_private_ip"),
            )
        elif self.module.params.get("type") == "ip":
            self.module.fail_on_missing_params(required_params=["ip"])
            params["target"] = LoadBalancerTarget(
                type=self.module.params.get("type"),
                ip=LoadBalancerTargetIP(ip=self.module.params.get("ip")),
                use_private_ip=False,
            )

        if not self.module.check_mode:
            try:
                action = self.hcloud_load_balancer.add_target(**params)
                action.wait_until_finished()
            except APIException as exception:
                if exception.code == "locked" or exception.code == "conflict":
                    self._create_load_balancer_target()
                else:
                    self.fail_json_hcloud(exception)
            except HCloudException as exception:
                self.fail_json_hcloud(exception)

        self._mark_as_changed()
        self._get_load_balancer_and_target()
        self._get_load_balancer_target()

    def present_load_balancer_target(self):
        self._get_load_balancer_and_target()
        self._get_load_balancer_target()
        if self.hcloud_load_balancer_target is None:
            self._create_load_balancer_target()

    def delete_load_balancer_target(self):
        self._get_load_balancer_and_target()
        self._get_load_balancer_target()
        if self.hcloud_load_balancer_target is not None and self.hcloud_load_balancer is not None:
            if not self.module.check_mode:
                target = None
                if self.module.params.get("type") == "server":
                    self.module.fail_on_missing_params(required_params=["server"])
                    target = LoadBalancerTarget(type=self.module.params.get("type"), server=self.hcloud_server)
                elif self.module.params.get("type") == "label_selector":
                    self.module.fail_on_missing_params(required_params=["label_selector"])
                    target = LoadBalancerTarget(
                        type=self.module.params.get("type"),
                        label_selector=LoadBalancerTargetLabelSelector(
                            selector=self.module.params.get("label_selector")
                        ),
                        use_private_ip=self.module.params.get("use_private_ip"),
                    )
                elif self.module.params.get("type") == "ip":
                    self.module.fail_on_missing_params(required_params=["ip"])
                    target = LoadBalancerTarget(
                        type=self.module.params.get("type"),
                        ip=LoadBalancerTargetIP(ip=self.module.params.get("ip")),
                        use_private_ip=False,
                    )
                try:
                    action = self.hcloud_load_balancer.remove_target(target)
                    action.wait_until_finished()
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)
            self._mark_as_changed()
        self.hcloud_load_balancer_target = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                type={"type": "str", "required": True, "choices": ["server", "label_selector", "ip"]},
                load_balancer={"type": "str", "required": True},
                server={"type": "str"},
                label_selector={"type": "str"},
                ip={"type": "str"},
                use_private_ip={"type": "bool", "default": False},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudLoadBalancerTarget.define_module()

    hcloud = AnsibleHCloudLoadBalancerTarget(module)
    state = module.params["state"]
    if state == "absent":
        hcloud.delete_load_balancer_target()
    elif state == "present":
        hcloud.present_load_balancer_target()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
