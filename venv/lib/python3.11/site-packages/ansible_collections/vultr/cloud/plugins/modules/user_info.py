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
module: user_info
short_description: Get information about the Vultr users
version_added: "1.0.0"
description:
  - Get infos about users available.
author:
  - "Yanis Guenane (@Spredzy)"
  - "René Moser (@resmo)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Get Vultr user infos
  vultr.cloud.user_info:
  register: result

- name: Print the infos
  ansible.builtin.debug:
    var: result.vultr_user_info
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
vultr_user_info:
  description: Response from Vultr API as list.
  returned: available
  type: list
  contains:
    id:
      description: ID of the user.
      returned: success
      type: str
      sample: 7d726ffe-9be2-4f88-8cda-fa7eba1da2b5
    api_key:
      description: API key of the user.
      returned: only after resource was created
      type: str
      sample: 567E6K567E6K567E6K567E6K567E6K
    name:
      description: Name of the user.
      returned: success
      type: str
      sample: john
    email:
      description: Email of the user.
      returned: success
      type: str
      sample: "john@example.com"
    api_enabled:
      description: Whether the API is enabled or not.
      returned: success
      type: bool
      sample: true
    acls:
      description: List of ACLs of the user.
      returned: success
      type: list
      sample: [ manage_users, support, upgrade ]
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
        namespace="vultr_user_info",
        resource_path="/users",
        ressource_result_key_singular="user",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
