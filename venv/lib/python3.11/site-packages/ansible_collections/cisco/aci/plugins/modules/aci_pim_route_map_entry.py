#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_pim_route_map_entry
short_description: Manage Protocol-Independent Multicast (PIM) Route Map Entry (pim:RouteMapEntry)
description:
- Manage PIM Route Map Entries for the PIM route Map Policies on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  pim_route_map_policy:
    description:
    - The name of the PIM Route Map policy.
    type: str
    aliases: [ route_map_policy_name ]
  order:
    description:
    - The PIM Route Map Entry order.
    type: int
  source_ip:
    description:
    - The Multicast Source IP.
    type: str
  group_ip:
    description:
    - The Multicast Group IP.
    type: str
  rp_ip:
    description:
    - The Multicast Rendezvous Point (RP) IP.
    type: str
    aliases: [ rendezvous_point_ip ]
  action:
    description:
    - The route action.
    - The APIC defaults to C(permit) when unset during creation.
    type: str
    choices: [ permit, deny ]
  description:
    description:
    - The description for the PIM Route Map entry.
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
- cisco.aci.owner

notes:
- The C(tenant) and the C(pim_route_map_policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_pim_route_map_policy) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_pim_route_map_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(pim:RouteMapEntry).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new PIM Route Map Entry
  cisco.aci.aci_pim_route_map_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    pim_route_map_policy: my_pim_route_map_policy
    order: 1
    source_ip: 1.1.1.1/24
    group_ip: 224.0.0.1/24
    rp_ip: 1.1.1.2
    action: permit
    state: present
  delegate_to: localhost

- name: Query a PIM Route Map Entry
  cisco.aci.aci_pim_route_map_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    pim_route_map_policy: my_pim_route_map_policy
    order: 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all PIM Route Map Entries in my_pim_route_map_policy
  cisco.aci.aci_pim_route_map_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    pim_route_map_policy: my_pim_route_map_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a PIM Route Map Entry
  cisco.aci.aci_pim_route_map_entry:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    pim_route_map_policy: my_pim_route_map_policy
    order: 1
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        pim_route_map_policy=dict(type="str", aliases=["route_map_policy_name"]),
        description=dict(type="str", aliases=["descr"]),
        order=dict(type="int"),
        source_ip=dict(type="str"),
        group_ip=dict(type="str"),
        rp_ip=dict(type="str", aliases=["rendezvous_point_ip"]),
        action=dict(type="str", choices=["permit", "deny"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "pim_route_map_policy", "order"]],
            ["state", "present", ["tenant", "pim_route_map_policy", "order"]],
        ],
    )

    tenant = module.params.get("tenant")
    description = module.params.get("description")
    pim_route_map_policy = module.params.get("pim_route_map_policy")
    order = module.params.get("order")
    source_ip = module.params.get("source_ip")
    group_ip = module.params.get("group_ip")
    rp_ip = module.params.get("rp_ip")
    action = module.params.get("action")
    state = module.params.get("state")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="pimRouteMapPol",
            aci_rn="rtmap-{0}".format(pim_route_map_policy),
            module_object=pim_route_map_policy,
            target_filter={"name": pim_route_map_policy},
        ),
        subclass_2=dict(
            aci_class="pimRouteMapEntry",
            aci_rn="rtmapentry-{0}".format(order),
            module_object=order,
            target_filter={"order": order},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="pimRouteMapEntry",
            class_config=dict(
                name=pim_route_map_policy,
                descr=description,
                action=action,
                grp=group_ip,
                order=order,
                rp=rp_ip,
                src=source_ip,
            ),
        )

        aci.get_diff(aci_class="pimRouteMapEntry")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
