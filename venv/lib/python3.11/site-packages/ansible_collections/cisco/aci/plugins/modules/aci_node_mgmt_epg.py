#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Shreyas Srish <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_node_mgmt_epg
short_description: In band or Out of band management EPGs (mgmt:OoB and mgmt:InB)
description:
- Cisco ACI Fabric Node EPGs
options:
  epg:
    description:
    - The name of the end point group
    type: str
    aliases: [ name ]
  type:
    description:
    - type of management interface
    type: str
    choices: [ in_band, out_of_band ]
    required: true
  bd:
    description:
    - The in-band bridge domain which is used when type is in_band
    type: str
  encap:
    description:
    - The in-band access encapsulation which is used when type is in_band
    type: str
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(mgmt:OoB) and B(mgmt:InB).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add in band mgmt epg
  cisco.aci.aci_node_mgmt_epg:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    epg: default
    type: in_band
    encap: vlan-1
    bd: bd1
    state: present
  delegate_to: localhost

- name: Add out of band mgmt epg
  cisco.aci.aci_node_mgmt_epg:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    epg: default
    type: out_of_band
    state: present
  delegate_to: localhost

- name: Query in band mgmt epg
  cisco.aci.aci_node_mgmt_epg:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    epg: default
    type: in_band
    encap: vlan-1
    bd: bd1
    state: query
  delegate_to: localhost

- name: Query all in band mgmt epg
  cisco.aci.aci_node_mgmt_epg:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    type: in_band
    state: query
  delegate_to: localhost

- name: Query all out of band mgmt epg
  cisco.aci.aci_node_mgmt_epg:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    type: out_of_band
    state: query
  delegate_to: localhost

- name: Remove in band mgmt epg
  cisco.aci.aci_node_mgmt_epg:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    epg: default
    type: in_band
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
     sample: class_map (30 bytes)
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
        type=dict(type="str", choices=["in_band", "out_of_band"], required=True),
        epg=dict(type="str", aliases=["name"]),
        bd=dict(type="str"),
        encap=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True, required_if=[["state", "absent", ["epg"]], ["state", "present", ["epg"]]])

    type = module.params.get("type")
    epg = module.params.get("epg")
    bd = module.params.get("bd")
    encap = module.params.get("encap")
    state = module.params.get("state")

    child_configs = []
    child_class = []
    if type == "in_band":
        child_configs = [
            dict(
                mgmtRsMgmtBD=dict(
                    attributes=dict(
                        tnFvBDName=bd,
                    ),
                ),
            )
        ]

        child_class = ["mgmtRsMgmtBD"]

    class_map = dict(
        in_band=list(
            [
                dict(aci_class="mgmtInB", aci_rn="inb-{0}"),
            ]
        ),
        out_of_band=list(
            [
                dict(aci_class="mgmtOoB", aci_rn="oob-{0}"),
            ]
        ),
    )

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-mgmt",
            module_object="mgmt",
            target_filter={"name": "mgmt"},
        ),
        subclass_1=dict(
            aci_class="mgmtMgmtP",
            aci_rn="mgmtp-default",
            module_object="default",
            target_filter={"name": "default"},
        ),
        subclass_2=dict(
            aci_class=class_map.get(type)[0]["aci_class"],
            aci_rn=class_map.get(type)[0]["aci_rn"].format(epg),
            module_object=epg,
            target_filter={"name": epg},
        ),
        child_classes=child_class,
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=class_map.get(type)[0]["aci_class"],
            class_config=dict(
                name=epg,
                encap=encap,
            ),
            child_configs=child_configs,
        )
        aci.get_diff(aci_class=class_map.get(type)[0]["aci_class"])

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
