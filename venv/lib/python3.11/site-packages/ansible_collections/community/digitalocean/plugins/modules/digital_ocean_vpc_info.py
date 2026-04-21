#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2021, Mark Mercado <mamercad@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_vpc_info
short_description: Gather information about DigitalOcean VPCs
version_added: 1.7.0
description:
  - This module can be used to gather information about DigitalOcean VPCs.
author: "Mark Mercado (@mamercad)"
options:
  members:
    description:
      - Return VPC members (instead of all VPCs).
    type: bool
    default: False
  name:
    description:
      - The name of the VPC.
    type: str
extends_documentation_fragment:
- community.digitalocean.digital_ocean.documentation
"""


EXAMPLES = r"""
- name: Fetch all VPCs
  community.digitalocean.digital_ocean_vpc_info:
  register: my_vpcs

- name: Fetch members of a VPC
  community.digitalocean.digital_ocean_vpc_info:
    members: true
    name: myvpc1
  register: my_vpc_members
"""


RETURN = r"""
data:
  description: All DigitalOcean VPCs, or, members of a VPC (with C(members=True)).
  returned: success
  type: dict
  sample:
    - created_at: '2021-02-06T17:57:22Z'
      default: true
      description: ''
      id: 0db3519b-9efc-414a-8868-8f2e6934688c
      ip_range: 10.116.0.0/20
      name: default-nyc1
      region: nyc1
      urn: do:vpc:0db3519b-9efc-414a-8868-8f2e6934688c
    - links: {}
      members: []
      meta:
        total: 0
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


class DOVPCInfo(object):
    def __init__(self, module):
        self.rest = DigitalOceanHelper(module)
        self.module = module
        # pop the oauth token so we don't include it in the POST data
        self.module.params.pop("oauth_token")
        self.name = self.module.params.pop("name", "")
        self.members = self.module.params.pop("members", False)

    def get_by_name(self):
        page = 1
        while page is not None:
            response = self.rest.get("vpcs?page={0}".format(page))
            json_data = response.json
            if response.status_code == 200:
                for vpc in json_data["vpcs"]:
                    if vpc.get("name", None) == self.name:
                        return vpc
                if (
                    "links" in json_data
                    and "pages" in json_data["links"]
                    and "next" in json_data["links"]["pages"]
                ):
                    page += 1
                else:
                    page = None
        return None

    def get(self):
        if self.module.check_mode:
            return self.module.exit_json(changed=False)

        if not self.members:
            base_url = "vpcs?"
            vpcs = self.rest.get_paginated_data(base_url=base_url, data_key_name="vpcs")
            self.module.exit_json(changed=False, data=vpcs)
        else:
            vpc = self.get_by_name()
            if vpc is not None:
                vpc_id = vpc.get("id", None)
                if vpc_id is not None:
                    response = self.rest.get("vpcs/{0}/members".format(vpc_id))
                    json = response.json
                    if response.status_code != 200:
                        self.module.fail_json(
                            msg="Failed to find VPC named {0}: {1}".format(
                                self.name, json["message"]
                            )
                        )
                    else:
                        self.module.exit_json(changed=False, data=json)
                else:
                    self.module.fail_json(
                        changed=False, msg="Unexpected error, please file a bug"
                    )
            else:
                self.module.fail_json(
                    changed=False,
                    msg="Could not find a VPC named {0}".format(self.name),
                )


def run(module):
    vpcs = DOVPCInfo(module)
    vpcs.get()


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        members=dict(type="bool", default=False),
        name=dict(type="str"),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ["members", True, ["name"]],
        ],
        supports_check_mode=True,
    )

    run(module)


if __name__ == "__main__":
    main()
