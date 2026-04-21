#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: firewall_resource
short_description: Manage Resources a Hetzner Cloud Firewall is applied to.

description:
    - Add and Remove Resources a Hetzner Cloud Firewall is applied to.

author:
    - Jonas Lammler (@jooola)

version_added: 2.5.0
options:
    firewall:
        description:
            - Name or ID of the Hetzner Cloud Firewall.
        type: str
        required: true
    servers:
        description:
            - List of Server Name or ID.
        type: list
        elements: str
    label_selectors:
        description:
            - List of Label Selector.
        type: list
        elements: str
    state:
        description:
            - State of the firewall resources.
        default: present
        choices: [absent, present]
        type: str

extends_documentation_fragment:
    - hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Apply a firewall to a list of servers
  hetzner.hcloud.firewall_resource:
    firewall: my-firewall
    servers:
      - my-server
      - 3456789
    state: present

- name: Remove a firewall from a list of servers
  hetzner.hcloud.firewall_resource:
    firewall: my-firewall
    servers:
      - my-server
      - 3456789
    state: absent

- name: Apply a firewall to resources using label selectors
  hetzner.hcloud.firewall_resource:
    firewall: my-firewall
    label_selectors:
      - env=prod
    state: present

- name: Remove a firewall from resources using label selectors
  hetzner.hcloud.firewall_resource:
    firewall: my-firewall
    label_selectors:
      - env=prod
    state: absent
"""

RETURN = """
hcloud_firewall_resource:
    description: The Resources a Hetzner Cloud Firewall is applied to.
    returned: always
    type: dict
    contains:
        firewall:
            description:
                - Name of the Hetzner Cloud Firewall.
            type: str
            sample: my-firewall
        servers:
            description:
                - List of Server Name.
            type: list
            elements: str
            sample: [my-server1, my-server2]
        label_selectors:
            description:
                - List of Label Selector.
            type: list
            elements: str
            sample: [env=prod]
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.firewalls import (
    BoundFirewall,
    FirewallResource,
    FirewallResourceLabelSelector,
)
from ..module_utils.vendor.hcloud.servers import BoundServer


class AnsibleHCloudFirewallResource(AnsibleHCloud):
    represent = "hcloud_firewall_resource"

    hcloud_firewall_resource: BoundFirewall | None = None

    def _prepare_result(self):
        servers = []
        label_selectors = []
        for resource in self.hcloud_firewall_resource.applied_to:
            if resource.type == FirewallResource.TYPE_SERVER:
                servers.append(resource.server.name)
            elif resource.type == FirewallResource.TYPE_LABEL_SELECTOR:
                label_selectors.append(resource.label_selector.selector)

        return {
            "firewall": self.hcloud_firewall_resource.name,
            "servers": servers,
            "label_selectors": label_selectors,
        }

    def _get_firewall(self):
        try:
            self.hcloud_firewall_resource = self._client_get_by_name_or_id(
                "firewalls",
                self.module.params.get("firewall"),
            )
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _diff_firewall_resources(self, operator) -> list[FirewallResource]:
        before = self._prepare_result()

        resources: list[FirewallResource] = []

        servers: list[str] | None = self.module.params.get("servers")
        if servers:
            for server_param in servers:
                try:
                    server: BoundServer = self._client_get_by_name_or_id("servers", server_param)
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)

                if operator(server.name, before["servers"]):
                    resources.append(
                        FirewallResource(
                            type=FirewallResource.TYPE_SERVER,
                            server=server,
                        )
                    )

        label_selectors = self.module.params.get("label_selectors")
        if label_selectors:
            for label_selector in label_selectors:
                if operator(label_selector, before["label_selectors"]):
                    resources.append(
                        FirewallResource(
                            type=FirewallResource.TYPE_LABEL_SELECTOR,
                            label_selector=FirewallResourceLabelSelector(selector=label_selector),
                        )
                    )

        return resources

    def present_firewall_resources(self):
        self._get_firewall()
        resources = self._diff_firewall_resources(
            lambda to_add, before: to_add not in before,
        )
        if resources:
            if not self.module.check_mode:
                actions = self.hcloud_firewall_resource.apply_to_resources(resources=resources)
                for action in actions:
                    action.wait_until_finished()

                self.hcloud_firewall_resource.reload()

            self._mark_as_changed()

    def absent_firewall_resources(self):
        self._get_firewall()
        resources = self._diff_firewall_resources(
            lambda to_remove, before: to_remove in before,
        )
        if resources:
            if not self.module.check_mode:
                actions = self.hcloud_firewall_resource.remove_from_resources(resources=resources)
                for action in actions:
                    action.wait_until_finished()

                self.hcloud_firewall_resource.reload()

            self._mark_as_changed()

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec={
                "firewall": {"type": "str", "required": True},
                "servers": {"type": "list", "elements": "str"},
                "label_selectors": {"type": "list", "elements": "str"},
                "state": {
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            },
            required_one_of=[["servers", "label_selectors"]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudFirewallResource.define_module()

    hcloud = AnsibleHCloudFirewallResource(module)
    state = module.params.get("state")
    if state == "absent":
        hcloud.absent_firewall_resources()
    elif state == "present":
        hcloud.present_firewall_resources()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
