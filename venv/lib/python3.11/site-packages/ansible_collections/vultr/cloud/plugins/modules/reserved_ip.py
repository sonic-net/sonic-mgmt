#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: reserved_ip
short_description: Manages reserved IPs on Vultr
description:
  - Create, attach, detach and remove reserved IPs.
version_added: "1.0.0"
author:
  - "René Moser (@resmo)"
options:
  label:
    description:
      - Label of the reserved IP.
    required: true
    aliases: [ name ]
    type: str
  instance_name:
    description:
      - Name of the Instance the reserved IP should be attached to.
      - Mutually exclusive with I(instance_id).
    type: str
  instance_id:
    description:
      - ID of the Instance the reserved IP should be attached to.
      - Mutually exclusive with I(instance_name).
    type: str
  region:
    description:
      - Region of the reserved IP will be related to.
    type: str
    required: true
  ip_type:
    description:
      - Type of the IP.
    type: str
    choices: [ v4, v6 ]
    required: true
  state:
    description:
      - State of the reserved IP.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Ensure a reserved IP present and attached to an instance
  vultr.cloud.reserved_ip:
    label: my attached IP
    region: ewr
    ip_type: v4
    instance_name: web-01

- name: Ensure a reserved IP is detached
  vultr.cloud.reserved_ip:
    label: my reserved IP
    region: ewr
    ip_type: v4
    instance_id: ""

- name: Ensure a reserved IP is absent
  vultr.cloud.reserved_ip:
    label: my attached IP
    region: ewr
    ip_type: v4
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
vultr_reserved_ip:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: ID of the reserved IP.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    label:
      description: Name of the reserved IP.
      returned: success
      type: str
      sample: example.com
    region:
      description: Region of the reserved IP is related to.
      returned: success
      type: str
      sample: ewr
    ip_type:
      description: Type of the reserved IP.
      returned: success
      type: str
      sample: v4
    subnet:
      description: Subnet of the reserved IP.
      returned: success
      type: str
      sample: v4
    subnet_size:
      description: Size of the subnet of the reserved IP.
      returned: success
      type: int
      sample: 32
    instance_id:
      description: ID of the Instance the reserved IP is attached to.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b
"""

import urllib

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


class AnsibleVultrReservedIp(AnsibleVultr):
    def configure(self):
        self.instance_id = self.get_instance_id()

    def get_instance_id(self):
        instance_id = self.module.params["instance_id"]
        if instance_id is not None:
            return instance_id

        instance_name = self.module.params["instance_name"]
        if instance_name is not None:
            # Empty string ID means detach instance
            if len(instance_name) == 0:
                return ""

            # URL encode label
            try:
                label = urllib.quote(instance_name)  # type: ignore
            except AttributeError:
                label = urllib.parse.quote(instance_name)  # type: ignore

            # Filter instances by label
            resources = self.api_query(path="/instances?label=%s" % label) or dict()
            if not resources or not resources["instances"]:
                self.module.fail_json(msg="No instance with name found: %s" % instance_name)

            if len(resources["instances"]) > 1:
                self.module.fail_json(msg="More then one instance with name found: %s" % instance_name)

            return resources["instances"][0]["id"]

    def query_list(self, path=None, result_key=None, query_params=None):
        resources = self.api_query(path=self.resource_path) or dict()

        resources_filtered = list()
        for resource in resources[self.ressource_result_key_plural]:
            # Skip IP with different type
            if resource["ip_type"] != self.module.params["ip_type"]:
                continue
            # Skip IP in different region
            if resource["region"] != self.module.params["region"]:
                continue
            resources_filtered.append(resource)

        return resources_filtered

    def create(self):
        resource = super().create() or dict()
        if resource and self.instance_id:
            if not self.module.check_mode:
                # Attach instance
                self.api_query(
                    path="%s/%s/%s"
                    % (
                        self.resource_path,
                        resource[self.resource_key_id],
                        "attach",
                    ),
                    method="POST",
                    data=dict(instance_id=self.instance_id),
                )
                # Refresh
                resource = self.query_by_id(resource_id=resource[self.resource_key_id])
        return resource

    def update(self, resource):
        if self.instance_id is None:
            return resource

        # Detach instance
        elif resource["instance_id"] and not self.instance_id:
            self.result["changed"] = True
            if not self.module.check_mode:
                self.api_query(
                    path="%s/%s/%s" % (self.resource_path, resource[self.resource_key_id], "detach"),
                    method="POST",
                    data=dict(instance_id=self.instance_id),
                )
                # Refresh
                resource = self.query_by_id(resource_id=resource[self.resource_key_id])

        # Attach instance or change attached instance
        elif self.instance_id and resource["instance_id"] != self.instance_id:
            self.result["changed"] = True
            if not self.module.check_mode:
                self.api_query(
                    path="%s/%s/%s" % (self.resource_path, resource[self.resource_key_id], "attach"),
                    method="POST",
                    data=dict(instance_id=self.instance_id),
                )
                # Refresh
                resource = self.query_by_id(resource_id=resource[self.resource_key_id])

        return resource


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            label=dict(type="str", required=True, aliases=["name"]),
            instance_id=dict(type="str"),
            instance_name=dict(type="str"),
            ip_type=dict(type="str", required=True, choices=["v4", "v6"]),
            region=dict(type="str", required=True),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(["instance_id", "instance_name"],),
        supports_check_mode=True,
    )

    vultr = AnsibleVultrReservedIp(
        module=module,
        namespace="vultr_reserved_ip",
        resource_path="/reserved-ips",
        ressource_result_key_singular="reserved_ip",
        resource_create_param_keys=["region", "ip_type", "label"],
        resource_key_name="label",
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
