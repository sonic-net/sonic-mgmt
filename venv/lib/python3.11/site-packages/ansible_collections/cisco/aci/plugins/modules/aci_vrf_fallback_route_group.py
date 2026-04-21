#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Dev Sinha (@DevSinha13) <devsinh@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_vrf_fallback_route_group
version_added: "2.12.0"
short_description: Manage VRF Fallback Route Groups (fv:FBRGroup, fv:FBRoute, and fv:FBRMember)
description:
- Manage VRF Fallback Route Groups on Cisco ACI fabrics.
- Fallback Route Groups are used to specify routes and next-hop addresses for VRFs.
options:
  tenant:
    description:
    - The name of the Tenant associated with the VRF Fallback Route Group.
    type: str
    aliases: [ tenant_name ]
  vrf:
    description:
    - The name of the VRF associated with the VRF Fallback Route Group.
    type: str
    aliases: [ context, vrf_name ]
  name:
    description:
    - The name of the VRF Fallback Route Group.
    type: str
    aliases: [ vrf_fallback_route_group ]
  prefix_address:
    description:
    - The fallback route (prefix address) for the VRF Fallback Route Group.
    - If not specified, the existing fallback route will remain unchanged.
    - To delete the fallback route, pass an empty string as the attribute value.
    type: str
    aliases: [ fallback_route ]
  fallback_members:
    description:
    - A list of fallback member IP addresses (next-hop addresses) for the VRF Fallback Route Group.
    - Members not in the list will be removed from the configuration.
    - If not specified, the existing fallback members will remain unchanged.
    - To delete all the fallback members, pass an empty list.
    type: list
    elements: str
    aliases: [ next_hop_address ]
  description:
    description:
    - The description for the VRF Fallback Route Group.
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
- The C(tenant) and C(vrf) must exist before using this module.
  Use the M(cisco.aci.aci_tenant) and M(cisco.aci.aci_vrf) modules to create them if needed.
seealso:
- module: cisco.aci.aci_vrf
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:FBRGroup), B(fv:FBRoute), and B(fv:FBRMember).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dev Sinha (@devsinha13)
"""

EXAMPLES = r"""
- name: Create a new VRF Fallback Route Group
  cisco.aci.aci_vrf_fallback_route_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    vrf: vrf_test
    vrf_fallback_route_group: test_fallback_route_group
    fallback_route: 1.1.1.1/24
    fallback_members:
      - 192.168.1.1
      - 192.168.1.2
    description: Test Fallback Route Group
    state: present
  delegate_to: localhost

- name: Update fallback members in an existing VRF Fallback Route Group
  cisco.aci.aci_vrf_fallback_route_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    vrf: vrf_test
    vrf_fallback_route_group: test_fallback_route_group
    fallback_members:
      - 192.168.1.1
      - 192.168.1.3
    state: present
  delegate_to: localhost

- name: Delete children for VRF Fallback Route Group
  cisco.aci.aci_vrf_fallback_route_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    vrf: vrf_test
    vrf_fallback_route_group: test_fallback_route_group
    fallback_route: ""
    fallback_members: []
    state: present
  delegate_to: localhost

- name: Query a VRF Fallback Route Group
  cisco.aci.aci_vrf_fallback_route_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    vrf: vrf_test
    vrf_fallback_route_group: test_fallback_route_group
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all VRF Fallback Route Groups
  cisco.aci.aci_vrf_fallback_route_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a VRF Fallback Route Group
  cisco.aci.aci_vrf_fallback_route_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    vrf: vrf_test
    vrf_fallback_route_group: test_fallback_route_group
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
        vrf=dict(type="str", aliases=["context", "vrf_name"]),
        vrf_fallback_route_group=dict(type="str", aliases=["name"]),
        fallback_route=dict(type="str", aliases=["prefix_address"]),
        fallback_members=dict(type="list", elements="str", aliases=["next_hop_address"]),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "vrf"]],
            ["state", "present", ["tenant", "vrf"]],
        ],
    )

    tenant = module.params.get("tenant")
    vrf = module.params.get("vrf")
    vrf_fallback_route_group = module.params.get("vrf_fallback_route_group")
    fallback_route = module.params.get("fallback_route")
    fallback_members = module.params.get("fallback_members")
    description = module.params.get("description")
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
            aci_class="fvCtx",
            aci_rn="ctx-{0}".format(vrf),
            module_object=vrf,
            target_filter={"name": vrf},
        ),
        subclass_2=dict(
            aci_class="fvFBRGroup",
            aci_rn="fbrg-{0}".format(vrf_fallback_route_group),
            module_object=vrf_fallback_route_group,
            target_filter={"name": vrf_fallback_route_group},
        ),
        child_classes=["fvFBRMember", "fvFBRoute"],
    )

    aci.get_existing()

    if state == "present":

        child_configs = []

        existing_members = []
        existing_route = None

        if isinstance(aci.existing, list) and len(aci.existing) > 0:
            for child in aci.existing[0].get("fvFBRGroup", {}).get("children", {}):
                existing_member = child.get("fvFBRMember", {}).get("attributes", {}).get("rnhAddr")
                if existing_member:
                    existing_members.append(existing_member)
                route = child.get("fvFBRoute", {}).get("attributes", {}).get("fbrPrefix")
                if route:
                    existing_route = route

        if fallback_members is not None:
            fallback_members_set = set(fallback_members)

            existing_members_set = set(existing_members)

            for member in fallback_members_set - existing_members_set:
                child_configs.append(dict(fvFBRMember=dict(attributes=dict(rnhAddr=member))))
            for existing_member in existing_members_set - fallback_members_set:
                child_configs.append(dict(fvFBRMember=dict(attributes=dict(rnhAddr=existing_member, status="deleted"))))

        if fallback_route is not None and fallback_route != existing_route:
            if existing_route:
                # Appending to child_config list not possible because of APIC Error 182: Multiple fallback routes not allowed in one group.
                # A seperate delete request to dn of the fvFBRoute is needed to remove the object prior to adding to child_configs.
                # Failed child_config is displayed in below:
                # child_configs.append(
                #     dict(fvFBRoute=dit(attributes=dict(fbrPrefix=existing_route, status="deleted"))),
                # )
                aci.api_call(
                    "DELETE",
                    "{0}/api/mo/uni/tn-{1}/ctx-{2}/fbrg-{3}/pfx-[{4}].json".format(aci.base_url, tenant, vrf, vrf_fallback_route_group, existing_route),
                )
            if fallback_route:
                child_configs.append(
                    dict(fvFBRoute=dict(attributes=dict(fbrPrefix=fallback_route))),
                )

        aci.payload(
            aci_class="fvFBRGroup",
            class_config=dict(
                descr=description,
                name=vrf_fallback_route_group,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fvFBRGroup")

        aci.post_config()
    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
