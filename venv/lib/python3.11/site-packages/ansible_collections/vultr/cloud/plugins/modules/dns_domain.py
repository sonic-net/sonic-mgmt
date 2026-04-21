#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: dns_domain
short_description: Manages DNS domains on Vultr
description:
  - Create and remove DNS domains.
version_added: "1.0.0"
author: "René Moser (@resmo)"
options:
  domain:
    description:
      - The domain name.
    required: true
    aliases: [ name ]
    type: str
  ip:
    description:
      - The default server IP.
      - Use M(vultr.cloud.dns_record) to change it once the domain is created.
      - Required if C(state=present).
    type: str
    aliases: [ server_ip ]
  dns_sec:
    description:
      - Ensure DNSSEC is enabled or disabled.
    type: str
    choices: [ enabled, disabled ]
    default: disabled
  state:
    description:
      - State of the DNS domain.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Ensure a domain exists with DNSSEC
  vultr.cloud.dns_domain:
    name: example.com
    dns_sec: enabled
    server_ip: 10.10.10.10

- name: Ensure a domain is absent
  vultr.cloud.dns_domain:
    name: example.com
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
vultr_dns_domain:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    name:
      description: Name of the DNS Domain.
      returned: success
      type: str
      sample: example.com
    dns_sec:
      description: Whether DNSSEC is enabled or disabled.
      returned: success
      type: str
      sample: disabled
    date_created:
      description: Date the DNS domain was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            domain=dict(type="str", required=True, aliases=["name"]),
            ip=dict(type="str", aliases=["server_ip"]),
            dns_sec=dict(type="str", choices=["enabled", "disabled"], default="disabled"),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ("state", "present", ["ip"]),
        ],
        supports_check_mode=True,
    )

    vultr = AnsibleVultr(
        module=module,
        namespace="vultr_dns_domain",
        resource_path="/domains",
        ressource_result_key_singular="domain",
        resource_create_param_keys=["domain", "dns_sec", "ip"],
        resource_update_param_keys=["domain", "dns_sec"],
        resource_key_name="domain",
        resource_key_id="domain",
        resource_update_method="PUT",
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
