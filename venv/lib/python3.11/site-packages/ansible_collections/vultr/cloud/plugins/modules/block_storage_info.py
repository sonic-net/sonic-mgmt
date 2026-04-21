#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: block_storage_info
short_description: Get information about the Vultr block storage
version_added: "1.0.0"
description:
  - Get infos about block storages available.
author:
  - "René Moser (@resmo)"
  - "Yanis Guenane (@Spredzy)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Get Vultr block_storage infos
  vultr.cloud.block_storage_info:
  register: result

- name: Print the infos
  ansible.builtin.debug:
    var: result.vultr_block_storage_info
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
vultr_block_storage_info:
  description: Response from Vultr API as list.
  returned: success
  type: list
  contains:
    attached_to_instance:
      description: The ID of the server instance the volume is attached to.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    cost:
      description: Cost per month for the volume.
      returned: success
      type: float
      sample: 1.00
    date_created:
      description: Date when the volume was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    id:
      description: ID of the block storage volume.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    label:
      description: Label of the volume.
      returned: success
      type: str
      sample: my volume
    region:
      description: Region the volume was deployed into.
      returned: success
      type: str
      sample: ews
    size_gb:
      description: Information about the volume size in GB.
      returned: success
      type: int
      sample: 50
    status:
      description: Status about the deployment of the volume.
      returned: success
      type: str
      sample: active
    mount_id:
      description: Mount ID of the volume.
      returned: success
      type: str
      sample: ewr-2f5d7a314fe44f
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
        namespace="vultr_block_storage_info",
        resource_path="/blocks",
        ressource_result_key_singular="block",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
