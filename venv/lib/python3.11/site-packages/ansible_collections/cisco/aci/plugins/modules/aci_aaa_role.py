#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_aaa_role
short_description: Manage AAA roles (aaa:Role)
description:
- Manage AAA roles on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the aaa role.
    type: str
    aliases: [ aaa_role ]
  privileges:
    description:
    - The privilege(s) assigned to a role.
    type: list
    aliases: [ priv ]
    elements: str
    choices: [
      admin,
      aaa,
      tenant-connectivity,
      tenant-protocol,
      vmm-policy,
      tenant-ext-connectivity,
      tenant-ext-protocol,
      tenant-qos,
      tenant-security,
      tenant-network-profile,
      tenant-epg,
      fabric-connectivity,
      fabric-protocol,
      fabric-equipment,
      access-connectivity,
      access-protocol,
      access-equipment,
      access-qos,
      nw-svc-params,
      ops,
      nw-svc-policy,
      site-admin,
      site-policy,
      config-manager,
      custom-privilege-1,
      custom-privilege-2,
      custom-privilege-3,
      custom-privilege-4,
      custom-privilege-5,
      custom-privilege-6,
      custom-privilege-7,
      custom-privilege-8,
      custom-privilege-9,
      custom-privilege-10,
      custom-privilege-11,
      custom-privilege-12,
      custom-privilege-13,
      custom-privilege-14,
      custom-privilege-15,
      custom-privilege-16,
      custom-privilege-17,
      custom-privilege-18,
      custom-privilege-19,
      custom-privilege-20,
      custom-privilege-21,
      custom-privilege-22,
      custom-port-privilege
    ]
  description:
    description:
    - Description of the aaa role.
    type: str
    aliases: [ descr ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci

seealso:
- module: cisco.aci.aci_aaa_domain
- name: Manage AAA domains (aaa:Domain)
  description: More information about the AAA domains class B(aaa:Domain).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""


EXAMPLES = r"""
- name: Add a aaa role
  cisco.aci.aci_aaa_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: anstest
    privileges: aaa
    state: present
  delegate_to: localhost

- name: Add list of aaa roles
  cisco.aci.aci_aaa_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: "{{ item.name }}"
    privileges: "{{ item.privilege }}"
    state: present
  delegate_to: localhost
  with_items:
    - name: anstest1
      privilege: site-admin
    - name: anstest2
      privilege: site-policy

- name: Query a aaa role with name
  cisco.aci.aci_aaa_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: anstest
    state: query
  delegate_to: localhost

- name: Query all aaa roles
  cisco.aci.aci_aaa_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove a aaa role with name
  cisco.aci.aci_aaa_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: anstest
    state: absent
  delegate_to: localhost
"""

RETURN = r"""
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production environment",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC
  returned: failure
  type: dict
  sample:
    {
        "code": "122",
        "text": "unknown managed object class foo"
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment"
            }
        }
    }
previous:
  description: The original configuration from the APIC before the module has started
  returned: info
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
proposed:
  description: The assembled configuration from the user-provided parameters
  returned: info
  type: dict
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment",
                "name": "production"
            }
        }
    }
filter_string:
  description: The filter string used for the request
  returned: failure or debug
  type: str
  sample: ?rsp-prop-include=config-only
method:
  description: The HTTP method used for the request to the APIC
  returned: failure or debug
  type: str
  sample: POST
response:
  description: The HTTP response from the APIC
  returned: failure or debug
  type: str
  sample: OK (30 bytes)
status:
  description: The HTTP status from the APIC
  returned: failure or debug
  type: int
  sample: 200
url:
  description: The HTTP url used for the request to the APIC
  returned: failure or debug
  type: str
  sample: https://10.11.12.13/api/mo/uni/tn-production.json
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec

PRIVILEGES = [
    "admin",
    "aaa",
    "tenant-connectivity",
    "tenant-protocol",
    "vmm-policy",
    "tenant-ext-connectivity",
    "tenant-ext-protocol",
    "tenant-qos",
    "tenant-security",
    "tenant-network-profile",
    "tenant-epg",
    "fabric-connectivity",
    "fabric-protocol",
    "fabric-equipment",
    "access-connectivity",
    "access-protocol",
    "access-equipment",
    "access-qos",
    "nw-svc-params",
    "ops",
    "nw-svc-policy",
    "site-admin",
    "site-policy",
    "config-manager",
    "custom-privilege-1",
    "custom-privilege-2",
    "custom-privilege-3",
    "custom-privilege-4",
    "custom-privilege-5",
    "custom-privilege-6",
    "custom-privilege-7",
    "custom-privilege-8",
    "custom-privilege-9",
    "custom-privilege-10",
    "custom-privilege-11",
    "custom-privilege-12",
    "custom-privilege-13",
    "custom-privilege-14",
    "custom-privilege-15",
    "custom-privilege-16",
    "custom-privilege-17",
    "custom-privilege-18",
    "custom-privilege-19",
    "custom-privilege-20",
    "custom-privilege-21",
    "custom-privilege-22",
    "custom-port-privilege",
]


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        name=dict(type="str", aliases=["aaa_role"]),
        privileges=dict(type="list", aliases=["priv"], elements="str", choices=PRIVILEGES),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "privileges"]],
        ],
    )

    name = module.params.get("name")
    description = module.params.get("description")
    privileges = module.params.get("privileges")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="aaaRole",
            aci_rn="userext/role-{0}".format(name),
            module_object=name,
            target_filter=dict(name=name),
        ),
    )
    aci.get_existing()

    if state == "present":
        formatted_privileges = ",".join(privileges)
        aci.payload(
            aci_class="aaaRole",
            class_config=dict(
                name=name,
                priv=formatted_privileges,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="aaaRole")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
