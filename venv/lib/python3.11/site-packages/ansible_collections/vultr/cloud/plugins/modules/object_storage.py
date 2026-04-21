#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2024, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: object_storage
short_description: Manages object storages on Vultr
description:
  - Manage object storages.
version_added: "1.12.0"
author:
  - "René Moser (@resmo)"
options:
  label:
    description:
      - Name of the object storage.
    required: true
    aliases: [ name ]
    type: str
  cluster:
    description:
      - Cluster hostname where the object storage will be created.
    required: true
    type: str
  state:
    description:
      - State of the object storage.
    default: present
    choices: [ present, absent]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
---
- name: Ensure an object storage is present
  vultr.cloud.object_storage:
    label: my object storage
    cluster: ewr1.vultrobjects.com

- name: Ensure an object storage is absent
  vultr.cloud.object_storage:
    label: my object storage
    cluster: ewr1.vultrobjects.com
    state: absent
"""

RETURN = """
---
vultr_api:
  description: Response from Vultr API with a few additions/modification.
  returned: success
  type: dict
  contains:
    api_account:
      description: Account used in the ini file to select the key.
      returned: success
      type: str
      sample: default
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
vultr_block_storage:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    date_created:
      description: Date the object storage was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    id:
      description: A unique ID for the object storage.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    label:
      description: The user-supplied label for this object storage.
      returned: success
      type: str
      sample: my object storage
    region:
      description: The region for this object storage.
      returned: success
      type: str
      sample: ews
    status:
      description: The status of this object storage.
      returned: success
      type: str
      sample: active
    s3_hostname:
      description: The Cluster hostname for this object storage.
      returned: success
      type: str
      sample: ewr1.vultrobjects.com
    s3_access_key:
      description: The object storage access key.
      returned: success
      type: str
      sample: 00example11223344
    s3_secret_key:
      description: The object storage secret key.
      returned: success
      type: str
      sample: 00example1122334455667788990011
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


class AnsibleVultrObjectStorage(AnsibleVultr):
    def configure(self):
        super(AnsibleVultrObjectStorage, self).configure()
        cluster = self.get_cluster()
        self.module.params["cluster_id"] = cluster["id"]
        # Use region to distinguish labels  between regions
        self.module.params["region"] = cluster["region"]

    def get_cluster(self):
        return self.query_filter_list_by_name(
            key_name="hostname",
            param_key="cluster",
            path="/object-storage/clusters",
            result_key="clusters",
            fail_not_found=True,
        )

    def create_or_update(self):
        resource = super(AnsibleVultrObjectStorage, self).create_or_update()
        if resource:
            resource = self.wait_for_state(resource=resource, key="status", states=["active"])
        return resource


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            label=dict(type="str", required=True, aliases=["name"]),
            cluster=dict(type="str", required=True),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    vultr = AnsibleVultrObjectStorage(
        module=module,
        namespace="vultr_object_storage",
        resource_path="/object-storage",
        ressource_result_key_singular="object_storage",
        resource_create_param_keys=["label", "cluster_id"],
        resource_update_param_keys=["label"],
        resource_key_name="label",
    )

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
