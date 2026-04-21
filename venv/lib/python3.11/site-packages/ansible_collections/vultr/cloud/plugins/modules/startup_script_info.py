#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: startup_script_info
short_description: Gather information about the Vultr startup scripts
description:
  - Gather information about startup scripts available.
version_added: "1.0.0"
author:
  - "Yanis Guenane (@Spredzy)"
  - "René Moser (@resmo)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Gather Vultr startup scripts information
  vultr.cloud.startup_script_info:
  register: result

- name: Print the gathered information
  ansible.builtin.debug:
    var: result.vultr_startup_script_info
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
vultr_startup_script_info:
  description: Response from Vultr API.
  returned: success
  type: list
  contains:
    id:
      description: ID of the startup script.
      returned: success
      type: str
      sample: 56e5b8b5-120c-40b1-a087-3abc9cd8df57
    name:
      description: Name of the startup script.
      returned: success
      type: str
      sample: my startup script
    type:
      description: The type of the startup script.
      returned: success
      type: str
      sample: pxe
    date_created:
      description: Date the startup script was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    date_modified:
      description: Date the startup script was modified.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
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
        namespace="vultr_startup_script_info",
        resource_path="/startup-scripts",
        ressource_result_key_singular="startup_script",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
