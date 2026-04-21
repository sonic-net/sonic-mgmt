#!/usr/bin/python
#
# Copyright (c) 2022, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: firewall_rule_info
short_description: Gather information about the Vultr firewall rules
description:
  - Gather information about firewall rules available.
version_added: "1.0.0"
author: "René Moser (@resmo)"
options:
  group:
    description:
      - Name of the firewall group.
    required: true
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Gather Vultr firewall rule information
  vultr.cloud.firewall_rule_info:
    group: my group
  register: result

- name: Print the gathered information
  ansible.builtin.debug:
    var: result.vultr_firewall_rule_info
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
vultr_firewall_rule_info:
  description: Response from Vultr API as list.
  returned: success
  type: list
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


class AnsibleVultrFirewallRuleInfo(AnsibleVultr):
    def get_firewall_group(self):
        return self.query_filter_list_by_name(
            key_name="description",
            param_key="group",
            path="/firewalls",
            result_key="firewall_groups",
            fail_not_found=True,
        )

    def configure(self):
        # Set firewall group id to resource path, ensures firewall group exists
        self.resource_path = self.resource_path % self.get_firewall_group()["id"]


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            group=dict(type="str", required=True),
        )  # type: ignore
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    vultr = AnsibleVultrFirewallRuleInfo(
        module=module,
        namespace="vultr_firewall_rule_info",
        resource_path="/firewalls/%s/rules",
        ressource_result_key_singular="firewall_rule",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
