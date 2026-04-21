#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: dns_record
short_description: Manages DNS records on Vultr
description:
  - Create, update and remove DNS records.
version_added: "1.0.0"
author: "René Moser (@resmo)"
options:
  name:
    description:
      - The record name.
    type: str
    default: ""
  domain:
    description:
      - The domain the record is related to.
    type: str
    required: true
  type:
    description:
      - Type of the record.
    default: A
    choices:
    - A
    - AAAA
    - CNAME
    - NS
    - MX
    - SRV
    - TXT
    - CAA
    - SSHFP
    aliases: [ record_type ]
    type: str
  data:
    description:
      - Data of the record.
      - Required if C(state=present).
    type: str
  ttl:
    description:
      - TTL of the record.
    default: 300
    type: int
  priority:
    description:
      - Priority of the record.
    type: int
  multiple:
    description:
      - Whether to use more than one record with similar I(name) including no name and I(type).
      - Only allowed for a few record types, e.g. C(type=A), C(type=NS) or C(type=MX).
      - I(data) will not be updated, instead it is used as a key to find existing records.
    default: false
    type: bool
  state:
    description:
      - State of the DNS record.
    default: present
    choices: [ present, absent ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""


EXAMPLES = """
- name: Ensure an A record exists
  vultr.cloud.dns_record:
    name: www
    domain: example.com
    data: 10.10.10.10
    ttl: 3600

- name: Ensure a second A record exists for round robin LB
  vultr.cloud.dns_record:
    name: www
    domain: example.com
    data: 10.10.10.11
    ttl: 60
    multiple: true

- name: Ensure a CNAME record exists
  vultr.cloud.dns_record:
    name: web
    type: CNAME
    domain: example.com
    data: www.example.com

- name: Ensure MX record exists
  vultr.cloud.dns_record:
    type: MX
    domain: example.com
    data: "{{ item.data }}"
    priority: "{{ item.priority }}"
    multiple: true
  with_items:
    - { data: mx1.example.com, priority: 10 }
    - { data: mx2.example.com, priority: 10 }
    - { data: mx3.example.com, priority: 20 }

- name: Ensure a record is absent
  vultr.cloud.dns_record:
    name: www
    domain: example.com
    state: absent

- name: Ensure one MX record is absent if multiple exists
  vultr.cloud.dns_record:
    record_type: MX
    domain: example.com
    data: mx1.example.com
    multiple: true
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
dns_record:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: The ID of the DNS record.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    name:
      description: The name of the DNS record.
      returned: success
      type: str
      sample: web
    type:
      description: The name of the DNS record.
      returned: success
      type: str
      sample: A
    data:
      description: Data of the DNS record.
      returned: success
      type: str
      sample: 10.10.10.10
    priority:
      description: Priority of the DNS record.
      returned: success
      type: int
      sample: 10
    ttl:
      description: Time to live of the DNS record.
      returned: success
      type: int
      sample: 300
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "SSHFP"]


class AnsibleVultrDnsRecord(AnsibleVultr):
    def query(self):
        multiple = self.module.params.get("multiple")
        name = self.module.params.get("name")
        data = self.module.params.get("data")
        record_type = self.module.params.get("type")

        result = dict()
        for resource in self.query_list():
            if resource.get("type") != record_type:
                continue

            if resource.get("name") == name:
                if not multiple:
                    if result:
                        self.module.fail_json(
                            msg="More than one record with record_type=%s and name=%s params. "
                            "Use multiple=true for more than one record." % (record_type, name)
                        )
                    else:
                        result = resource
                elif resource.get("data") == data:
                    return resource
        return result


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            domain=dict(type="str", required=True),
            name=dict(type="str", default=""),
            state=dict(type="str", choices=["present", "absent"], default="present"),
            ttl=dict(type="int", default=300),
            type=dict(type="str", choices=RECORD_TYPES, default="A", aliases=["record_type"]),
            multiple=dict(type="bool", default=False),
            priority=dict(type="int"),
            data=dict(type="str"),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ("state", "present", ["data"]),
            ("multiple", True, ["data"]),
        ],
        supports_check_mode=True,
    )

    vultr = AnsibleVultrDnsRecord(
        module=module,
        namespace="vultr_dns_record",
        resource_path="/domains/%s/records" % module.params.get("domain"),  # type: ignore
        ressource_result_key_singular="record",
        resource_create_param_keys=["name", "ttl", "data", "priority", "type"],
        resource_update_param_keys=["name", "ttl", "data", "priority"],
        resource_key_name="name",
    )  # type: ignore

    if module.params.get("state") == "absent":  # type: ignore
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
