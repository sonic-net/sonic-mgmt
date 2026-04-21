#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Sudhakar Shet Kudtarkar (@kudtarkar1)
# Copyright: (c) 2020, Shreyas Srish <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l2out
short_description: Manage Layer2 Out (L2Out) objects (l2ext:Out)
description:
- Manage Layer2 Out configuration on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
  l2out:
    description:
    - The name of outer layer2.
    type: str
    aliases: [ 'name' ]
  description:
    description:
    - Description for the L2Out.
    type: str
  bd:
    description:
    - Name of the Bridge domain which is associted with the L2Out.
    type: str
  domain:
    description:
    - Name of the external L2 Domain that is being associated with L2Out.
    type: str
  vlan:
    description:
    - The VLAN which is being associated with the L2Out.
    type: int
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
- The C(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l2ext:Out).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sudhakar Shet Kudtarkar (@kudtarkar1)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new L2Out
  cisco.aci.aci_l2out:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l2out: l2out
    description: via Ansible
    bd: bd1
    domain: l2Dom
    vlan: 3200
    state: present
    delegate_to: localhost

- name: Remove an L2Out
  cisco.aci.aci_l2out:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l2out: l2out
    state: absent
    delegate_to: localhost

- name: Query an L2Out
  cisco.aci.aci_l2out:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l2out: l2out
    state: query
    delegate_to: localhost
    register: query_result

- name: Query all L2Outs in a specific tenant
  cisco.aci.aci_l2out:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    state: query
    delegate_to: localhost
    register: query_result
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
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
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
        bd=dict(type="str"),
        l2out=dict(type="str", aliases=["name"]),
        domain=dict(type="str"),
        vlan=dict(type="int"),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str"),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["l2out", "tenant"]],
            ["state", "present", ["bd", "l2out", "tenant", "domain", "vlan"]],
        ],
    )

    bd = module.params.get("bd")
    l2out = module.params.get("l2out")
    description = module.params.get("description")
    domain = module.params.get("domain")
    vlan = module.params.get("vlan")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")
    child_classes = ["l2extRsEBd", "l2extRsL2DomAtt", "l2extLNodeP"]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="l2extOut",
            aci_rn="l2out-{0}".format(l2out),
            module_object=l2out,
            target_filter={"name": l2out},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = [
            dict(l2extRsL2DomAtt=dict(attributes=dict(tDn="uni/l2dom-{0}".format(domain)))),
            dict(l2extRsEBd=dict(attributes=dict(tnFvBDName=bd, encap="vlan-{0}".format(vlan)))),
        ]

        aci.payload(
            aci_class="l2extOut",
            class_config=dict(name=l2out, descr=description, dn="uni/tn-{0}/l2out-{1}".format(tenant, l2out), nameAlias=name_alias),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="l2extOut")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
