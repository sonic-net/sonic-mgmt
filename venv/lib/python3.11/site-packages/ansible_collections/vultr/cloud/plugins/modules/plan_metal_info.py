#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, Nate River <vitikc@gmail.com>
# Copyright (c) 2020, Simon Baerlocher <s.baerlocher@sbaerlocher.ch>
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: plan_metal_info
short_description: Gather information about the Vultr bare metal plans
description:
  - Gather information about plans available to boot servers.
version_added: "1.0.0"
author:
  - "Nate River (@vitikc)"
  - "Simon Baerlocher (@sbaerlocher)"
  - "René Moser (@resmo)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Gather Vultr bare metal plans information
  vultr.cloud.plan_metal_info:
  register: result

- name: Print the gathered information
  ansible.builtin.debug:
    var: result.vultr_plan_metal_info
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
vultr_plan_info:
  description: Response from Vultr API as list.
  returned: success
  type: list
  contains:
    id:
      description: ID of the plan.
      returned: success
      type: str
      sample: vbm-4c-32gb
    cpu_count:
      description: Amount of CPUs.
      returned: success
      type: int
      sample: 4
    cpu_threads:
      description: Amount of CPU threads.
      returned: success
      type: int
      sample: 8
    cpu_model:
      description: CPU model.
      returned: success
      type: str
      sample: E3-1270v6
    ram:
      description: Amount of RAM in MB.
      returned: success
      type: int
      sample: 32768
    disk:
      description: Disk size in GB.
      returned: success
      type: int
      sample: 240
    disk_count:
      description: Amount of disks.
      returned: success
      type: int
      sample: 2
    bandwidth:
      description: Bandwidth in MB.
      returned: success
      type: int
      sample: 5120
    monthly_cost:
      description: Monthly cost in $.
      returned: success
      type: int
      sample: 300
    type:
      description: Type of plan.
      returned: success
      type: str
      sample: SSD
    locations:
      description: List of locations the plan is available in.
      returned: success
      type: list
      sample: ["ewr"]
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
        namespace="vultr_plan_metal_info",
        resource_path="/plans-metal",
        ressource_result_key_singular="plan_metal",
        ressource_result_key_plural="plans_metal",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
