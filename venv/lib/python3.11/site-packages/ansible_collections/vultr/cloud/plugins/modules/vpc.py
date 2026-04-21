#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: vpc
short_description: Manages VPCs on Vultr
description:
  - Create and remove VPCs.
version_added: "1.0.0"
author: "René Moser (@resmo)"
options:
  description:
    description:
      - Description of the VPC.
    required: true
    aliases: [ name ]
    type: str
  v4_subnet:
    description:
      - IPv4 subnet of the VPC.
      - Required if I(state=present).
    type: str
  v4_subnet_mask:
    description:
      - IPv4 subnet mask of the VPC.
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
  vultr.cloud.vpc:
    description: my VPC.
    subnet: 10.99.1.0
    subnet_mask: 24
    region: ewr

- name: Ensure a VPC is absent
  vultr.cloud.vpc:
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
vultr_vpc:
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
    v4_subnet:
      description: Subnet of the VPC.
      returned: success
      type: str
      sample: 10.99.1.0
    v4_subnet_maks:
      description: Subnet mask of the VPC.
      returned: success
      type: str
      sample: 10.99.1.0
    date_created:
      description: Date the VPC was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    date_modified:
      description: Date the VPC was modified.
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
            description=dict(type="str", required=True, aliases=["name"]),
            v4_subnet=dict(type="str"),
            v4_subnet_mask=dict(type="int"),
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
                ("v4_subnet", "v4_subnet_mask", "region"),
            ),
        ),
        supports_check_mode=True,
    )

    vultr = AnsibleVultr(
        module=module,
        namespace="vultr_vpc",
        resource_path="/vpcs",
        ressource_result_key_singular="vpc",
        resource_create_param_keys=[
            "description",
            "v4_subnet",
            "v4_subnet_mask",
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
