#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: firewall_group
short_description: Manages firewall groups on Vultr
description:
  - Create and remove firewall groups.
version_added: "1.0.0"
author: "René Moser (@resmo)"
options:
  description:
    description:
      - Description of the firewall group.
    required: true
    aliases: [ name ]
    type: str
  state:
    description:
      - State of the firewall group.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: ensure a firewall group is present
  vultr.cloud.firewall_group:
    description: my http firewall.

- name: ensure a firewall group is absent
  vultr.cloud.firewall_group:
    description: my http firewall.
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
vultr_firewall_group:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: ID of the firewall group.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    description:
      description: Description (name) of the firewall group
      returned: success
      type: str
      sample: my firewall group
    date_created:
      description: Date the firewall group was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    date_modified:
      description: Date the firewall group was modified.
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
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    vultr = AnsibleVultr(
        module=module,
        namespace="vultr_firewall_group",
        resource_path="/firewalls",
        ressource_result_key_singular="firewall_group",
        resource_create_param_keys=["description"],
        resource_update_param_keys=["description"],
        resource_key_name="description",
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
