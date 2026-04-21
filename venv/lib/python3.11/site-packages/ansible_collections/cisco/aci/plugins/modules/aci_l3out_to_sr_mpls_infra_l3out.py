#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = r"""
---
module: aci_l3out_to_sr_mpls_infra_l3out
short_description: Manage Layer 3 Outside (L3Out) to SR-MPLS Infra L3Outs objects (l3ext:ConsLbl)
description:
- Manage Layer 3 Outside (L3Out) to SR-MPLS Infra L3Outs objects on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - The name of an existing SR MPLS VRF L3Out.
    type: str
    aliases: [ l3out_name, name ]
  infra_l3out:
    description:
    - The name of an existing SR-MPLS Infra L3Out.
    type: str
    aliases: [ infra_l3out_name ]
  external_epg:
    description:
    - The distinguished name (DN) of the external EPG.
    type: str
    aliases: [ external_epg_dn ]
  outbound_route_map:
    description:
    - The distinguished name (DN) of the outbound route map.
    type: str
    aliases: [ outbound_route_map_dn, outbound ]
  inbound_route_map:
    description:
    - The distinguished name (DN) of the inbound route map.
    - Use an empty string to remove the inbound route map.
    type: str
    aliases: [ inbound_route_map_dn, inbound ]
  description:
    description:
    - Description for the L3Out.
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
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The C(tenant) and C(l3out) used must exist before using this module in your playbook.
- The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l3out) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l3ext:ConsLbl).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new l3out to sr-mpls infra l3out
  cisco.aci.aci_l3out_to_sr_mpls_infra_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: prod_l3out
    description: L3Out for Production tenant
    infra_l3out: infra_l3out_name
    external_epg: uni/tn-production/out-l3out_name/instP-external_epg_name
    outbound_route_map: uni/tn-production/prof-outbound_route_map_name
    inbound_route_map: uni/tn-production/prof-inbound_route_map_name
    state: present
  delegate_to: localhost

- name: Delete a l3out to sr-mpls infra l3out
  cisco.aci.aci_l3out_to_sr_mpls_infra_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: prod_l3out
    infra_l3out: infra_l3out_name
    state: absent
  delegate_to: localhost

- name: Query a l3out to sr-mpls infra l3out
  cisco.aci.aci_l3out_to_sr_mpls_infra_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    l3out: prod_l3out
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all l3out to sr-mpls infra l3outs
  cisco.aci.aci_l3out_to_sr_mpls_infra_l3out:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_all_result
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
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        l3out=dict(type="str", aliases=["l3out_name", "name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        infra_l3out=dict(type="str", aliases=["infra_l3out_name"]),
        external_epg=dict(type="str", aliases=["external_epg_dn"]),
        outbound_route_map=dict(type="str", aliases=["outbound_route_map_dn", "outbound"]),
        inbound_route_map=dict(type="str", aliases=["inbound_route_map_dn", "inbound"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["l3out", "tenant", "infra_l3out"]],
            ["state", "present", ["l3out", "tenant", "infra_l3out", "external_epg", "outbound_route_map"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    description = module.params.get("description")
    infra_l3out = module.params.get("infra_l3out")
    external_epg = module.params.get("external_epg")
    outbound_route_map = module.params.get("outbound_route_map")
    inbound_route_map = module.params.get("inbound_route_map")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    # l3extRsProvLblDef, bgpDomainIdAllocator are auto-generated classes, added for query output
    child_classes = ["l3extRsLblToInstP", "l3extRsLblToProfile", "l3extRsProvLblDef", "bgpDomainIdAllocator"]

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="l3extOut",
            aci_rn="out-{0}".format(l3out),
            module_object=l3out,
            target_filter={"name": l3out},
        ),
        subclass_2=dict(
            aci_class="l3extConsLbl",
            aci_rn="conslbl-{0}".format(infra_l3out),
            module_object=infra_l3out,
            target_filter={"name": infra_l3out},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []

        if aci.existing:
            children = aci.existing[0].get("l3extConsLbl", {}).get("children", [])
            for child in children:
                if child.get("l3extRsLblToProfile"):
                    tdn = child.get("l3extRsLblToProfile").get("attributes").get("tDn")
                    direction = child.get("l3extRsLblToProfile").get("attributes").get("direction")
                    route_map = outbound_route_map if direction == "export" else inbound_route_map
                    # Inbound route-map is removed when input is different or an empty string, otherwise ignored.
                    if route_map is not None and tdn != route_map:
                        child_configs.append(dict(l3extRsLblToProfile=dict(attributes=dict(tDn=tdn, direction=direction, status="deleted"))))
                elif child.get("l3extRsLblToInstP"):
                    tdn = child.get("l3extRsLblToInstP").get("attributes").get("tDn")
                    if tdn != external_epg:
                        child_configs.append(dict(l3extRsLblToInstP=dict(attributes=dict(tDn=tdn, status="deleted"))))

        child_configs.append(dict(l3extRsLblToProfile=dict(attributes=dict(tDn=outbound_route_map, direction="export"))))
        child_configs.append(dict(l3extRsLblToInstP=dict(attributes=dict(tDn=external_epg))))

        if inbound_route_map:
            child_configs.append(dict(l3extRsLblToProfile=dict(attributes=dict(tDn=inbound_route_map, direction="import"))))

        aci.payload(
            aci_class="l3extConsLbl",
            class_config=dict(
                name=infra_l3out,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l3extConsLbl")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
