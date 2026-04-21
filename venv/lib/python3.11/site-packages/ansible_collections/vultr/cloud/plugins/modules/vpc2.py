#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: vpc2
short_description: Manages VPCs 2.0 on Vultr
description:
  - Create and remove VPCs 2.0.
version_added: "1.9.0"
author: "René Moser (@resmo)"
options:
  description:
    description:
      - Description of the VPC.
    required: true
    aliases: [ name ]
    type: str
  ip_type:
    description:
      - Type of the IP version.
      - Required if I(state=present).
    default: v4
    choices: [ v4 ]
    type: str
  ip_block:
    description:
      - The subnet of the VPC.
      - Required if I(state=present).
    type: str
  prefix_length:
    description:
      - The number of bits for the netmask in CIDR notation, e.g. 24.
      - Required if I(state=present).
    type: int
  region:
    description:
      - Region the VPC will be related to.
      - Required if I(state=present).
    type: str
  state:
    description:
      - State of the VPC.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Ensure a VPC is present
  vultr.cloud.vpc2:
    description: my VPC.
    ip_block: 10.99.1.0
    prefix_length: 24
    region: ewr

- name: Ensure a VPC is absent
  vultr.cloud.vpc2:
    description: my VPC.
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
vultr_vpc2:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: ID of the VPC.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    description:
      description: Description of the VPC.
      returned: success
      type: str
      sample: my vpc
    ip_block:
      description: Subnet of the VPC.
      returned: success
      type: str
      sample: 10.99.1.0
    prefix_length:
      description: The number of bits for the netmask in CIDR notation.
      returned: success
      type: int
      sample: 24
    date_created:
      description: Date the VPC was created.
      returned: success
      type: str
      sample: "2023-08-20T19:39:20+00:00"
    region:
      description: The region the VPC is located in.
      returned: success
      type: str
      sample: ewr
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            description=dict(type="str", required=True, aliases=["name"]),
            ip_type=dict(type="str", choices=["v4"], default="v4"),
            ip_block=dict(type="str"),
            prefix_length=dict(type="int"),
            region=dict(type="str"),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=(
            (
                "state",
                "present",
                ("ip_type", "ip_block", "prefix_length", "region"),
            ),
        ),
        supports_check_mode=True,
    )

    vultr = AnsibleVultr(
        module=module,
        namespace="vultr_vpc2",
        resource_path="/vpc2",
        ressource_result_key_singular="vpc",
        resource_create_param_keys=[
            "description",
            "ip_type",
            "ip_block",
            "prefix_length",
            "region",
        ],
        resource_update_param_keys=["description"],
        resource_key_name="description",
        resource_update_method="PUT",
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
