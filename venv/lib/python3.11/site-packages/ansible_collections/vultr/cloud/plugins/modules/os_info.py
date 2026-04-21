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
module: os_info
short_description: Get information about the Vultr operation systems
description:
  - Get infos about operating systems available to boot servers.
version_added: "1.0.0"
author:
  - "Yanis Guenane (@Spredzy)"
  - "René Moser (@resmo)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Get Vultr OSes infos
  vultr.cloud.os_info:
  register: results

- name: Print the gathered infos
  ansible.builtin.debug:
    var: results.vultr_os_info
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
vultr_os_info:
  description: Response from Vultr API as list.
  returned: available
  type: list
  contains:
    arch:
      description: OS Architecture.
      returned: success
      type: str
      sample: x64
    family:
      description: OS family.
      returned: success
      type: str
      sample: openbsd
    name:
      description: OS name.
      returned: success
      type: str
      sample: OpenBSD 6 x64
    windows:
      description: OS is a MS Windows.
      returned: success
      type: bool
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
        namespace="vultr_os_info",
        resource_path="/os",
        ressource_result_key_singular="os",
        ressource_result_key_plural="os",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
