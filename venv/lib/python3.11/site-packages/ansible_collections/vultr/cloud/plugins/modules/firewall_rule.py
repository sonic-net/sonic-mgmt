#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: firewall_rule
short_description: Manages firewall rules on Vultr
description:
  - Create and remove firewall rules.
version_added: "1.0.0"
author: "René Moser (@resmo)"
options:
  group:
    description:
      - Name of the firewall group.
    required: true
    type: str
  ip_type:
    description:
      - IP address version
    choices: [ v4, v6 ]
    type: str
    default: v4
  protocol:
    description:
      - Protocol of the firewall rule.
    choices: [ icmp, tcp, udp, gre, esp, ah ]
    type: str
    default: tcp
  subnet:
    description:
      - The network or IP, e.g. 192.0.2.123 or 0.0.0.0.
      - Mutally exclusive with I(source).
    type: str
  subnet_size:
    description:
      - The number of bits for the netmask in CIDR notation, e.g. C(32).
    type: int
  port:
    description:
      - Single port or port range, e.g. C(80) or C(8000:8080).
      - Required if I(protocol) is tcp or udp and I(state=present).
    aliases: [ port_range ]
    type: str
  source:
    description:
      - Possible values are C(cloudflare) or a loadbalancer label.
      - Mutally exclusive with I(subnet).
    type: str
  notes:
    description:
      - Notes of the firewall rule.
    type: str
  state:
    description:
      - State of the firewall rule.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Ensure a firewall rule is present
  vultr.cloud.firewall_rule:
    group: web
    port: 80
    protocol: tcp
    ip_type: v4
    subnet: "0.0.0.0"
    subnet_size: 0
    notes: "open HTTP to the world"

- name: Ensure a firewall rule with port range is present
  vultr.cloud.firewall_rule:
    group: apps
    port: "8000:8999"
    protocol: tcp
    ip_type: v4
    subnet: "10.10.10.0"
    subnet_size: 24

- name: Ensure a firewall rule is absent
  vultr.cloud.firewall_rule:
    group: apps
    port: "443"
    protocol: tcp
    ip_type: v6
    subnet: "::"
    subnet_size: 0
    state: absent
"""

RETURN = """
---
vultr_api:
  description: Response from Vultr API with a few additions/modification.
  returned: success
  type: dict
  contains:
    api_timeout:
      description: Timeout used for the API requests.
      returned: success
      type: int
      sample: 60
    api_retries:
      description: Amount of max retries for the API requests.
      returned: success
      type: int
      sample: 5
    api_retry_max_delay:
      description: Exponential backoff delay in seconds between retries up to this max delay value.
      returned: success
      type: int
      sample: 12
    api_endpoint:
      description: Endpoint used for the API requests.
      returned: success
      type: str
      sample: "https://api.vultr.com/v2"
vultr_firewall_rule:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: ID of the firewall rule.
      returned: success
      type: int
      sample: 1
    action:
      description: Action of the firewall rule.
      returned: success
      type: str
      sample: accept
    protocol:
      description: Protocol of the firewall rule.
      returned: success
      type: str
      sample: tcp
    port:
      description: Port or port range of the firewall rule.
      returned: success
      type: str
      sample: "80"
    source:
      description: Source string of the firewall rule.
      returned: success
      type: str
      sample: cloudflare
    notes:
      description: Supplied description of the firewall rule.
      returned: success
      type: str
      sample: my rule
    subnet:
      description: Subnet of the firewall rule.
      returned: success
      type: str
      sample: 0.0.0.0
    subnet_size:
      description: Size of the subnet of the firewall rule.
      returned: success
      type: int
      sample: 0
    ip_type:
      description: IP type of the firewall rule.
      returned: success
      type: str
      sample: v4
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


class AnsibleVultrFirewallRule(AnsibleVultr):
    def get_firewall_group(self):
        return self.query_filter_list_by_name(
            key_name="description",
            param_key="group",
            path="/firewalls",
            result_key="firewall_groups",
            fail_not_found=True,
        )

    def get_load_balancer(self):
        return self.query_filter_list_by_name(
            key_name="label",
            param_key="source",
            path="/load-balancers",
            result_key="load_balancers",
            fail_not_found=True,
        )

    def configure(self):
        # Set firewall group id to resource path, ensures firewall group exists
        self.resource_path = self.resource_path % self.get_firewall_group()["id"]

        # Set loadbalancer ID for source
        source = self.module.params.get("source")
        if source is not None and source != "cloudflare":
            self.module.params["source"] = self.get_load_balancer()["id"]

        # Warn about port only affects TCP and UDP protocol
        if (
            self.module.params.get("protocol")
            not in (
                "tcp",
                "udp",
            )
            and self.module.params.get("port") is not None
        ):
            self.module.warn(
                "Setting a port (%s) only affects protocols TCP/UDP, but protocol is: %s. Ignoring."
                % (self.module.params.get("port"), self.module.params.get("protocol"))
            )
            self.module.params["port"] = None

    def query(self):
        result = dict()
        for resource in self.query_list():
            for key in (
                "ip_type",
                "protocol",
                "port",
                "source",
                "subnet",
                "subnet_size",
            ):
                param = self.module.params.get(key)

                if param is None:
                    continue

                if resource.get(key) != param:
                    break
            else:
                result = resource

            if result:
                break

        return result

    def update(self, resource):
        return resource


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            notes=dict(type="str"),
            group=dict(type="str", required=True),
            port=dict(type="str", aliases=["port_range"]),
            subnet=dict(type="str"),
            subnet_size=dict(type="int"),
            source=dict(type="str"),
            protocol=dict(
                type="str",
                choices=["icmp", "tcp", "udp", "gre", "esp", "ah"],
                default="tcp",
            ),
            ip_type=dict(type="str", choices=["v4", "v6"], default="v4"),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(("source", "subnet"),),
        mutually_exclusive=(("source", "subnet"),),
        required_together=(("subnet", "subnet_size"),),
        supports_check_mode=True,
    )

    vultr = AnsibleVultrFirewallRule(
        module=module,
        namespace="vultr_firewall_rule",
        resource_path="/firewalls/%s/rules",
        ressource_result_key_singular="firewall_rule",
        resource_key_name="##unused##",
        resource_create_param_keys=[
            "notes",
            "port",
            "subnet",
            "subnet_size",
            "source",
            "protocol",
            "ip_type",
        ],
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
