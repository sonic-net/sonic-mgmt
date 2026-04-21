#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2021, Mark Mercado <mamercad@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_vpc
short_description: Create and delete DigitalOcean VPCs
version_added: 1.7.0
description:
  - This module can be used to create and delete DigitalOcean VPCs.
author: "Mark Mercado (@mamercad)"
options:
  state:
    description:
      - Whether the VPC should be present (created) or absent (deleted).
    default: present
    choices:
      - present
      - absent
    type: str
  name:
    description:
      - The name of the VPC.
      - Must be unique and contain alphanumeric characters, dashes, and periods only.
    type: str
    required: true
  description:
    description:
      - A free-form text field for describing the VPC's purpose.
      - It may be a maximum of 255 characters.
    type: str
  default:
    description:
      - A boolean value indicating whether or not the VPC is the default network for the region.
      - All applicable resources are placed into the default VPC network unless otherwise specified during their creation.
      - The C(default) field cannot be unset from C(true).
      - If you want to set a new default VPC network, update the C(default) field of another VPC network in the same region.
      - The previous network's C(default) field will be set to C(false) when a new default VPC has been defined.
    type: bool
    default: false
  region:
    description:
      - The slug identifier for the region where the VPC will be created.
    type: str
  ip_range:
    description:
      - The requested range of IP addresses for the VPC in CIDR notation.
      - Network ranges cannot overlap with other networks in the same account and must be in range of private addresses as defined in RFC1918.
      - It may not be smaller than /24 nor larger than /16.
      - If no IP range is specified, a /20 network range is generated that won't conflict with other VPC networks in your account.
    type: str
extends_documentation_fragment:
- community.digitalocean.digital_ocean.documentation

"""


EXAMPLES = r"""
- name: Create a VPC
  community.digitalocean.digital_ocean_vpc:
    state: present
    name: myvpc1
    region: nyc1

- name: Create a VPC (choose IP range)
  community.digitalocean.digital_ocean_vpc:
    state: present
    name: myvpc1
    region: nyc1
    ip_range: 192.168.192.0/24

- name: Update a VPC (make it default)
  community.digitalocean.digital_ocean_vpc:
    state: present
    name: myvpc1
    region: nyc1
    default: true

- name: Update a VPC (change description)
  community.digitalocean.digital_ocean_vpc:
    state: present
    name: myvpc1
    region: nyc1
    description: myvpc

- name: Delete a VPC
  community.digitalocean.digital_ocean_vpc:
    state: absent
    name: myvpc1
"""


RETURN = r"""
data:
  description: A DigitalOcean VPC.
  returned: success
  type: dict
  sample:
    msg: Created VPC myvpc1 in nyc1
    vpc:
      created_at: '2021-06-17T11:43:12.12121565Z'
      default: false
      description: ''
      id: a3b72d97-192f-4984-9d71-08a5faf2e0c7
      ip_range: 10.116.16.0/20
      name: testvpc1
      region: nyc1
      urn: do:vpc:a3b72d97-192f-4984-9d71-08a5faf2e0c7
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


class DOVPC(object):
    def __init__(self, module):
        self.rest = DigitalOceanHelper(module)
        self.module = module
        # pop the oauth token so we don't include it in the POST data
        self.module.params.pop("oauth_token")
        self.name = module.params.get("name", None)
        self.description = module.params.get("description", None)
        self.default = module.params.get("default", False)
        self.region = module.params.get("region", None)
        self.ip_range = module.params.get("ip_range", None)
        self.vpc_id = module.params.get("vpc_id", None)

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

    def create(self):
        if self.module.check_mode:
            return self.module.exit_json(changed=True)

        vpc = self.get_by_name()
        if vpc is not None:  # update
            vpc_id = vpc.get("id", None)
            if vpc_id is not None:
                data = {
                    "name": self.name,
                }
                if self.description is not None:
                    data["description"] = self.description
                if self.default is not False:
                    data["default"] = True
                response = self.rest.put("vpcs/{0}".format(vpc_id), data=data)
                json = response.json
                if response.status_code != 200:
                    self.module.fail_json(
                        msg="Failed to update VPC {0} in {1}: {2}".format(
                            self.name, self.region, json["message"]
                        )
                    )
                else:
                    self.module.exit_json(
                        changed=False,
                        data=json,
                        msg="Updated VPC {0} in {1}".format(self.name, self.region),
                    )
            else:
                self.module.fail_json(
                    changed=False, msg="Unexpected error, please file a bug"
                )

        else:  # create
            data = {
                "name": self.name,
                "region": self.region,
            }
            if self.description is not None:
                data["description"] = self.description
            if self.ip_range is not None:
                data["ip_range"] = self.ip_range

            response = self.rest.post("vpcs", data=data)
            status = response.status_code
            json = response.json
            if status == 201:
                self.module.exit_json(
                    changed=True,
                    data=json,
                    msg="Created VPC {0} in {1}".format(self.name, self.region),
                )
            else:
                self.module.fail_json(
                    changed=False,
                    msg="Failed to create VPC {0} in {1}: {2}".format(
                        self.name, self.region, json["message"]
                    ),
                )

    def delete(self):
        if self.module.check_mode:
            return self.module.exit_json(changed=True)

        vpc = self.get_by_name()
        if vpc is None:
            self.module.fail_json(
                msg="Unable to find VPC {0} in {1}".format(self.name, self.region)
            )
        else:
            vpc_id = vpc.get("id", None)
            if vpc_id is not None:
                response = self.rest.delete("vpcs/{0}".format(str(vpc_id)))
                status = response.status_code
                json = response.json
                if status == 204:
                    self.module.exit_json(
                        changed=True,
                        msg="Deleted VPC {0} in {1} ({2})".format(
                            self.name, self.region, vpc_id
                        ),
                    )
                else:
                    json = response.json
                    self.module.fail_json(
                        changed=False,
                        msg="Failed to delete VPC {0} ({1}): {2}".format(
                            self.name, vpc_id, json["message"]
                        ),
                    )


def run(module):
    state = module.params.pop("state")
    vpc = DOVPC(module)
    if state == "present":
        vpc.create()
    elif state == "absent":
        vpc.delete()


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        state=dict(choices=["present", "absent"], default="present"),
        name=dict(type="str", required=True),
        description=dict(type="str"),
        default=dict(type="bool", default=False),
        region=dict(type="str"),
        ip_range=dict(type="str"),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ["state", "present", ["name", "region"]],
            ["state", "absent", ["name"]],
        ],
        supports_check_mode=True,
    )

    run(module)


if __name__ == "__main__":
    main()
