#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: user
short_description: Manages users on Vultr
description:
  - Create, update and remove users.
version_added: "1.0.0"
author: "René Moser (@resmo)"
options:
  name:
    description:
      - Name of the user
    required: true
    type: str
  email:
    description:
      - Email of the user.
      - Required if C(state=present).
    type: str
  password:
    description:
      - Password of the user.
      - Only considered while creating a user or when C(force=true).
    type: str
  force:
    description:
      - Password will only be changed with enforcement.
    default: false
    type: bool
  api_enabled:
    description:
      - Whether the API is enabled or not.
    default: true
    type: bool
  acls:
    description:
      - List of ACLs this users should have.
      - Required if C(state=present).
      - One or more of the choices list, some depend on each other.
    choices:
      - manage_users
      - subscriptions_view
      - subscriptions
      - provisioning
      - billing
      - support
      - abuse
      - dns
      - upgrade
      - objstore
      - loadbalancer
    aliases: [ acl ]
    type: list
    elements: str
  state:
    description:
      - State of the user.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Ensure a user exists
  vultr.cloud.user:
    name: john
    email: john.doe@example.com
    password: s3cr3t
    acls:
    - manage_users
    - subscriptions

- name: Remove a user
  vultr.cloud.user:
    name: john
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
vultr_user:
  description: Response from Vultr API.
  returned: success
  type: dict
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
      sample: [manage_users, support, upgrade]
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec

ACLS = [
    "manage_users",
    "subscriptions_view",
    "subscriptions",
    "provisioning",
    "billing",
    "support",
    "abuse",
    "dns",
    "upgrade",
    "objstore",
    "loadbalancer",
]


class AnsibleVultrUser(AnsibleVultr):
    def create(self):
        # Password is required in create mode.
        self.module.fail_on_missing_params(required_params=["password"])
        return super(AnsibleVultrUser, self).create()

    def update(self, resource):
        # Password is never returned and we can not compare.
        # That is why we update it only if forced
        force = self.module.params.get("force")
        if force:
            self.resource_update_param_keys.append("password")
        return super(AnsibleVultrUser, self).update(resource=resource)


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            email=dict(type="str"),
            password=dict(type="str", no_log=True),
            force=dict(type="bool", default=False),
            api_enabled=dict(type="bool", default=True),
            acls=dict(type="list", elements="str", choices=ACLS, aliases=["acl"]),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ("state", "present", ["email", "acls"]),
        ],
        supports_check_mode=True,
    )

    vultr = AnsibleVultrUser(
        module=module,
        namespace="vultr_user",
        resource_path="/users",
        ressource_result_key_singular="user",
        resource_create_param_keys=["name", "email", "password", "api_enabled", "acls"],
        resource_update_param_keys=["name", "email", "api_enabled", "acls"],
        resource_key_name="name",
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
