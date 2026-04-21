#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: firewall_info
short_description: Gather infos about the Hetzner Cloud Firewalls.

description:
    - Gather facts about your Hetzner Cloud Firewalls.

author:
    - Jonas Lammler (@jooola)

options:
    id:
        description:
            - The ID of the Firewall you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name for the Firewall you want to get.
        type: str
    label_selector:
        description:
            - The label selector for the Firewalls you want to get.
        type: str

extends_documentation_fragment:
    - hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Gather hcloud Firewall infos
  hetzner.hcloud.firewall_info:
  register: output

- name: Print the gathered infos
  debug:
    var: output
"""

RETURN = """
hcloud_firewall_info:
    description: List of Firewalls.
    returned: always
    type: list
    elements: dict
    contains:
        id:
            description: Numeric identifier of the firewall.
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the firewall.
            returned: always
            type: str
            sample: my-firewall
        labels:
            description: User-defined labels (key-value pairs).
            returned: always
            type: dict
        rules:
            description: List of rules the firewall contain.
            returned: always
            type: list
            elements: dict
            contains:
                description:
                    description: User defined description of this rule.
                    type: str
                    returned: always
                    sample: allow http from anywhere
                direction:
                    description: The direction of the firewall rule.
                    type: str
                    returned: always
                    sample: in
                protocol:
                    description: The protocol of the firewall rule.
                    type: str
                    returned: always
                    sample: tcp
                port:
                    description: The port or port range allowed by this rule.
                    type: str
                    returned: if RV(hcloud_firewall_info[].rules[].protocol=tcp) or RV(hcloud_firewall_info[].rules[].protocol=udp)
                    sample: "80"
                source_ips:
                    description: List of source CIDRs that are allowed within this rule.
                    type: list
                    elements: str
                    returned: always
                    sample: ["0.0.0.0/0", "::/0"]
                destination_ips:
                    description: List of destination CIDRs that are allowed within this rule.
                    type: list
                    elements: str
                    returned: always
                    sample: []
        applied_to:
            description: List of Resources the Firewall is applied to.
            returned: always
            type: list
            elements: dict
            contains:
                type:
                    description: Type of the resource.
                    type: str
                    choices: [server, label_selector]
                    sample: label_selector
                server:
                    description: ID of the server.
                    type: int
                    sample: 12345
                label_selector:
                    description: Label selector value.
                    type: str
                    sample: env=prod
                applied_to_resources:
                    description: List of Resources the Firewall label selector is applied to.
                    returned: if RV(hcloud_firewall_info[].applied_to[].type=label_selector)
                    type: list
                    elements: dict
                    contains:
                        type:
                            description: Type of resource referenced.
                            type: str
                            choices: [server]
                            sample: server
                        server:
                            description: ID of the Server.
                            type: int
                            sample: 12345
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.firewalls import (
    BoundFirewall,
    FirewallResource,
    FirewallRule,
)


class AnsibleHCloudFirewallInfo(AnsibleHCloud):
    represent = "hcloud_firewall_info"

    hcloud_firewall_info: list[BoundFirewall] | None = None

    def _prepare_result(self):
        tmp = []

        for firewall in self.hcloud_firewall_info:
            if firewall is None:
                continue

            tmp.append(
                {
                    "id": firewall.id,
                    "name": firewall.name,
                    "labels": firewall.labels,
                    "rules": [self._prepare_result_rule(rule) for rule in firewall.rules],
                    "applied_to": [self._prepare_result_applied_to(resource) for resource in firewall.applied_to],
                }
            )

        return tmp

    def _prepare_result_rule(self, rule: FirewallRule):
        return {
            "description": rule.description,
            "direction": rule.direction,
            "protocol": rule.protocol,
            "port": rule.port,
            "source_ips": rule.source_ips,
            "destination_ips": rule.destination_ips,
        }

    def _prepare_result_applied_to(self, resource: FirewallResource):
        result = {
            "type": resource.type,
            "server": resource.server.id if resource.server is not None else None,
            "label_selector": resource.label_selector.selector if resource.label_selector is not None else None,
        }
        if resource.applied_to_resources is not None:
            result["applied_to_resources"] = [
                {
                    "type": item.type,
                    "server": item.server.id if item.server is not None else None,
                }
                for item in resource.applied_to_resources
            ]
        return result

    def get_firewalls(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_firewall_info = [self.client.firewalls.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_firewall_info = [self.client.firewalls.get_by_name(self.module.params.get("name"))]
            elif self.module.params.get("label_selector") is not None:
                self.hcloud_firewall_info = self.client.firewalls.get_all(
                    label_selector=self.module.params.get("label_selector")
                )
            else:
                self.hcloud_firewall_info = self.client.firewalls.get_all()

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
    module = AnsibleHCloudFirewallInfo.define_module()
    hcloud = AnsibleHCloudFirewallInfo(module)

    hcloud.get_firewalls()
    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
