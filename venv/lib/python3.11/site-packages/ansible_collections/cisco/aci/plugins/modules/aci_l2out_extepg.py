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
module: aci_l2out_extepg
short_description: Manage External Network Instance (L2Out External EPG) objects (l2ext:InstP).
description:
- Manage External Network Instance (L2Out External EPG) objects on ACI fabrics.
options:
  tenant:
    description:
    - Name of existing tenant.
    type: str
  l2out:
    description:
    - Name of the l2out.
    type: str
  extepg:
    description:
    - Name of the external end point group.
    type: str
    aliases: [ external_epg, extepg_name, name ]
  description:
    description:
    - Description for the l2out.
    type: str
  preferred_group:
    description:
    - This depicts whether this External EPG is part of the Preferred Group and can communicate without contracts.
    - This is convenient for migration scenarios, or when ACI is used for network automation but not for policy.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  qos_class:
    description:
    - The bandwidth level for Quality of service.
    type: str
    choices: [ level1, level2, level3, level4, level5, level6, Unspecified ]
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
- The C(tenant) and C(l2out) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l2out) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l2ext:InstP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sudhakar Shet Kudtarkar (@kudtarkar1)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new L2 external end point group
  cisco.aci.aci_l2out_extepg:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l2out: l2out
    extepg: NewExt
    description: external epg
    preferred_group: false
    state: present
    delegate_to: localhost

- name: Remove an L2 external end point group
  cisco.aci.aci_l2out_extepg:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l2out: l2out
    extepg: NewExt
    state: absent
    delegate_to: localhost

- name: Query the L2 external end point group
  cisco.aci.aci_l2out_extepg:
    host: apic
    username: admin
    password: SomeSecretePassword
    tenant: Auto-Demo
    l2out: l2out
    extepg: NewExt
    state: query
    delegate_to: localhost
    register: query_result

- name: Query all L2 external end point groups in a tenant
  cisco.aci.aci_l2out_extepg:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        l2out=dict(type="str"),
        description=dict(type="str"),
        extepg=dict(type="str", aliases=["external_epg", "extepg_name", "name"]),
        preferred_group=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str"),
        qos_class=dict(type="str", choices=["level1", "level2", "level3", "level4", "level5", "level6", "Unspecified"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["l2out", "tenant", "extepg"]],
            ["state", "present", ["l2out", "tenant", "extepg"]],
        ],
    )

    aci = ACIModule(module)

    l2out = module.params.get("l2out")
    description = module.params.get("description")
    preferred_group = aci.boolean(module.params.get("preferred_group"), "include", "exclude")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    extepg = module.params.get("extepg")
    qos_class = module.params.get("qos_class")

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
        subclass_2=dict(
            aci_class="l2extInstP",
            aci_rn="instP-{0}".format(extepg),
            module_object=extepg,
            target_filter={"name": extepg},
        ),
    )

    aci.get_existing()

    if state == "present":
        config = dict(name=extepg, descr=description, dn="uni/tn-{0}/l2out-{1}/instP-{2}".format(tenant, l2out, extepg), prefGrMemb=preferred_group)
        if qos_class:
            config.update(prio=qos_class)
        aci.payload(
            class_config=config,
            aci_class="l2extInstP",
        )

        aci.get_diff(aci_class="l2extInstP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
