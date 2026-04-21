#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: ssh_key
short_description: Manages ssh keys on Vultr.
description:
  - Create, update and remove ssh keys.
version_added: "1.0.0"
author: "René Moser (@resmo)"
options:
  name:
    description:
      - Name of the ssh key.
    required: true
    type: str
  ssh_key:
    description:
      - SSH public key.
      - Required if C(state=present).
    type: str
  state:
    description:
      - State of the ssh key.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2

"""

EXAMPLES = """
- name: ensure an SSH key is present
  vultr.cloud.ssh_key:
    name: my ssh key
    ssh_key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"

- name: ensure an SSH key is absent
  vultr.cloud.ssh_key:
    name: my ssh key
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
vultr_ssh_key:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: ID of the ssh key.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    name:
      description: Name of the ssh key.
      returned: success
      type: str
      sample: my ssh key
    date_created:
      description: Date the ssh key was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    ssh_key:
      description: SSH public key.
      returned: success
      type: str
      sample: ssh-rsa AA... someother@example.com
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            ssh_key=dict(type="str", no_log=False),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ("state", "present", ["ssh_key"]),
        ],
        supports_check_mode=True,
    )

    vultr = AnsibleVultr(
        module=module,
        namespace="vultr_ssh_key",
        resource_path="/ssh-keys",
        ressource_result_key_singular="ssh_key",
        resource_create_param_keys=["name", "ssh_key"],
        resource_update_param_keys=["name", "ssh_key"],
        resource_key_name="name",
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
