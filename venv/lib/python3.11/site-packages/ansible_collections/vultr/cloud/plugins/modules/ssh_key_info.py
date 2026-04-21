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
module: ssh_key_info
short_description: Get information about the Vultr SSH keys
description:
  - Get infos about SSH keys available.
version_added: "1.0.0"
author:
  - "Yanis Guenane (@Spredzy)"
  - "René Moser (@resmo)"
extends_documentation_fragment:
  - vultr.cloud.vultr_v2

"""

EXAMPLES = """
- name: Get Vultr SSH keys infos
  vultr.cloud.ssh_key_info:
  register: result

- name: Print the infos
  ansible.builtin.debug:
    var: result.vultr_ssh_key_info
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
vultr_ssh_key_info:
  description: Response from Vultr API as list.
  returned: success
  type: list
  contains:
    id:
      description: ID of the ssh key.
      returned: success
      type: str
      sample: 7d726ffe-9be2-4f88-8cda-fa7eba1da2b5
    name:
      description: Name of the ssh key.
      returned: success
      type: str
      sample: my ssh key
    date_created:
      description: Date the ssh key was created.
      returned: success
      type: str
      sample: "2021-11-07T05:57:59-05:00"
    ssh_key:
      description: SSH public key.
      returned: success
      type: str
      sample: "ssh-rsa AA... someother@example.com"
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
        namespace="vultr_ssh_key_info",
        resource_path="/ssh-keys",
        ressource_result_key_singular="ssh_key",
    )

    vultr.get_result(vultr.query_list())


if __name__ == "__main__":
    main()
