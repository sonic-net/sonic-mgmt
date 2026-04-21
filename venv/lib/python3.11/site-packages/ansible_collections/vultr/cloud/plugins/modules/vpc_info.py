#!/usr/bin/python
#
# Copyright (c) 2022, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: vpc_info
short_description: Gather information about the Vultr VPCs
description:
  - Gather information about VPCs available.
version_added: "1.0.0"
author:
  - "René Moser (@resmo)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Gather Vultr VPCs information
  vultr.cloud.vpc_info:
  register: result

- name: Print the gathered information
  ansible.builtin.debug:
    var: result.vultr_vpc_info
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
vultr_vpc_info:
  description: Response from Vultr API as list.
  returned: success
  type: list
  contains:
    id:
      description: ID of the VPC.
      returned: success
      type: str
      sample: "cb676a46-66fd-4dfb-b839-443f2e6c0b60"
    description:
      description: Description of the VPC.
      returned: success
      type: str
      sample: myvpc
    date_created:
      description: Date when the VPC was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    region:
      description: Region the VPC was deployed into.
      returned: success
      type: str
      sample: ewr
    v4_subnet:
      description: IPv4 Network address
      returned: success
      type: str
      sample: 192.168.42.0
    v4_subnet_mask:
      description: Ipv4 Network mask
      returned: success
      type: int
      sample: 24
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


def main():
    argument_spec = vultr_argument_spec()

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    vultr = AnsibleVultr(
        module=module,
        namespace="vultr_vpc_info",
        resource_path="/vpcs",
        ressource_result_key_singular="vpc",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
