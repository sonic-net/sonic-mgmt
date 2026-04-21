#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Samita Bhattacharjee (@samitab) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_bd_rogue_exception_mac
short_description: Manage Rogue Exception MAC (fv:RogueExceptionMac)
description:
- Manage Rogue Exception MACs in BD's on Cisco ACI fabrics.
- Only available in APIC version 5.2 or later.
options:
  bd:
    description:
    - The name of the Bridge Domain.
    type: str
    aliases: [ bd_name, bridge_domain ]
  tenant:
    description:
    - The name of the Tenant.
    type: str
    aliases: [ tenant_name ]
  mac:
    description:
    - MAC address to except from Rogue processing.
    type: str
  description:
    description:
    - The description for the Rogue Exception MAC.
    type: str
    aliases: [ descr ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant) and C(bd) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module and M(cisco.aci.aci_bd) can be used for these.
seealso:
- module: cisco.aci.aci_bd
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:RogueExceptionMac).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Create a Rogue Exception MAC
  cisco.aci.aci_bd_rogue_exception_mac:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    bd: database
    mac: "AA:BB:CC:DD:EE:11"
    description: 1st MAC
    state: present
  delegate_to: localhost

- name: Get all Rogue Exception MACs
  cisco.aci.aci_bd_rogue_exception_mac:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Get all Rogue Exception MACs in specified Tenant
  cisco.aci.aci_bd_rogue_exception_mac:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    state: query
  delegate_to: localhost
  register: query_result

- name: Get specific Rogue Exception MAC
  cisco.aci.aci_bd_rogue_exception_mac:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    bd: database
    mac: "AA:BB:CC:DD:EE:11"
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Rogue Exception MAC from a Bridge Domain
  cisco.aci.aci_bd_rogue_exception_mac:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    bd: database
    mac: "AA:BB:CC:DD:EE:11"
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        bd=dict(type="str", aliases=["bd_name", "bridge_domain"]),  # Not required for querying all objects
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        mac=dict(type="str"),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["bd", "mac", "tenant"]],
            ["state", "absent", ["bd", "mac", "tenant"]],
        ],
    )

    aci = ACIModule(module)

    description = module.params.get("description")
    tenant = module.params.get("tenant")
    bd = module.params.get("bd")
    mac = module.params.get("mac")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvBD",
            aci_rn="BD-{0}".format(bd),
            module_object=bd,
            target_filter={"name": bd},
        ),
        subclass_2=dict(
            aci_class="fvRogueExceptionMac",
            aci_rn="rgexpmac-{0}".format(mac),
            module_object=mac,
            target_filter={"mac": mac},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvRogueExceptionMac",
            class_config=dict(
                descr=description,
                mac=mac,
            ),
        )

        aci.get_diff(aci_class="fvRogueExceptionMac")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
