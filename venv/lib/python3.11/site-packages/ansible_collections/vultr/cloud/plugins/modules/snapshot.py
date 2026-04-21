#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2023, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: snapshot
short_description: Manages snapshots on Vultr
description:
  - Create and remove snapshots.
version_added: "1.7.0"
author: "René Moser (@resmo)"
options:
  description:
    description:
      - Description of the snapshot.
    required: true
    aliases: [ name ]
    type: str
  instance:
    description:
      - The description or ID of the instance from which to take the snapshot.
      - Mutually exclusive with I(url).
      - I(instance) or I(url) is required if I(state=present).
    type: str
  url:
    description:
      - The URL of the snapshot image (RAW) to be uploaded.
      - Mutually exclusive with I(instance).
      - I(instance) or I(url) is required if I(state=present).
    type: str
  state:
    description:
      - State of the snapshot.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
- name: Ensure a snapshot is present
  vultr.cloud.snapshot:
    description: my snapshot of my instance
    instance: my instance

- name: Ensure a snapshot is present
  vultr.cloud.snapshot:
    description: debian 11 generic
    url: https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.raw

- name: Ensure a snapshot is absent
  vultr.cloud.snapshot:
    description: my snapshot of my instance
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
vultr_snapshot:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: ID of the snapshot.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    description:
      description: Description of the snapshot.
      returned: success
      type: str
      sample: my vpc
    date_created:
      description: Date the snapshot was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    size:
      description: Size of the snapshot.
      returned: success
      type: int
      sample: 42949672960
    compressed_size:
      description: Compressed size of the snapshot.
      returned: success
      type: int
      sample: 949678560
    status:
      description: Status of the snapshot.
      returned: success
      type: str
      sample: complete
    os_id:
      description: ID of the OS.
      returned: success
      type: int
      sample: 215
    app_id:
      description: ID of the app.
      returned: success
      type: int
      sample: 0
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


class AnsibleVultrSnapshot(AnsibleVultr):
    def get_instance(self):
        return self.query_filter_list_by_name(
            key_name="label",
            param_key="instance",
            path="/instances",
            result_key="instances",
            fail_not_found=True,
        )

    def create(self):
        param_keys = ("url", "instance")
        if not any(self.module.params.get(x) is not None for x in param_keys):
            self.module.fail_json(msg="missing required arguements, one of the following required: %s" % ", ".join(param_keys))

        if self.module.params.get("url") is not None:
            self.resource_create_param_keys.append("url")
            # Upload by URL has a different endpoint
            self.resource_path = self.resource_path + "/create-from-url"
        else:
            self.module.params["instance_id"] = self.get_instance()["id"]
            self.resource_create_param_keys.append("instance_id")

        resource = super(AnsibleVultrSnapshot, self).create()

        # Reset endpoint
        self.resource_path = "/snapshots"

        if resource:
            resource = self.wait_for_state(resource=resource, key="status", states=["complete"])

        return resource


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            description=dict(type="str", required=True, aliases=["name"]),
            instance=dict(type="str"),
            url=dict(type="str"),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(("instance", "url"),),
        supports_check_mode=True,
    )

    vultr = AnsibleVultrSnapshot(
        module=module,
        namespace="vultr_snapshot",
        resource_path="/snapshots",
        ressource_result_key_singular="snapshot",
        resource_create_param_keys=[
            "description",
        ],
        resource_update_param_keys=[
            "description",
        ],
        resource_key_name="description",
        resource_update_method="PUT",
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
