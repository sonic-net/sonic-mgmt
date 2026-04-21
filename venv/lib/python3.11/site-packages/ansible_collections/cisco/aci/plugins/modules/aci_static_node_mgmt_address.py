#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Sudhakar Shet Kudtarkar (@kudtarkar1)
# Copyright: (c) 2020, Lionel Hercot <lhercot@cisco.com>
# Copyright: (c) 2020, Shreyas Srish <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_static_node_mgmt_address
short_description: In band or Out of band management IP address (mgmt:RsOoBStNode and mgmt:RsInBStNode)
description:
- Cisco ACI Fabric Node IP address
options:
  epg:
    description:
    - The name of the end point group
    type: str
  pod_id:
    description:
    - The pod number of the leaf, spine or APIC
    type: int
  node_id:
    description:
    - ACI Fabric's node id of a leaf, spine or APIC
    type: int
  ipv4_address:
    description:
    - ipv4 address of in band/out of band mgmt
    type: str
    aliases: [ ip ]
  ipv4_gw:
    description:
    - Gateway address of in band / out of band mgmt network
    type: str
    aliases: [ gw ]
  ipv6_address:
    description:
    -  ipv6 address of in band/out of band  mgmt
    type: str
    aliases: [ ipv6 ]
  ipv6_gw:
    description:
    - GW address of in band/out of band mgmt
    type: str
  type:
    description:
    - type of management interface
    type: str
    choices: [ in_band, out_of_band ]
    required: true
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
  description: More information about the internal APIC classes B(mgmt:RsOoBStNode) and B(mgmt:RsInBStNode).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sudhakar Shet Kudtarkar (@kudtarkar1)
- Lionel Hercot (@lhercot)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add ipv4 address to in band mgmt interface
  cisco.aci.aci_static_node_mgmt_address:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    epg: default
    pod_id: 1
    type: in_band
    node_id: 1102
    ipv4_address: "3.1.1.2/24"
    ipv4_gw: "3.1.1.1"
    state: present
  delegate_to: localhost

- name: Add ipv4 address to out of band mgmt interface
  cisco.aci.aci_static_node_mgmt_address:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    epg: default
    pod_id: 1
    type: out_of_band
    node_id: 1102
    ipv4_address: "3.1.1.2/24"
    ipv4_gw: "3.1.1.1"
    state: present
  delegate_to: localhost

- name: Remove ipv4 address to in band mgmt interface
  cisco.aci.aci_static_node_mgmt_address:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    epg: default
    pod_id: 1
    type: in_band
    node_id: 1102
    ipv4_address: "3.1.1.2/24"
    ipv4_gw: "3.1.1.1"
    state: absent
  delegate_to: localhost

- name: Query the in band mgmt ipv4 address
  cisco.aci.aci_static_node_mgmt_address:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    epg: default
    pod_id: 1
    type: in_band
    node_id: 1102
    ipv4_address: "3.1.1.2/24"
    ipv4_gw: "3.1.1.1"
    state: query
  delegate_to: localhost

- name: Query all addresses in epg out of band25wf
  cisco.aci.aci_static_node_mgmt_address:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    epg: default
    type: out_of_band
    state: query
  delegate_to: localhost

- name: Query all in band addresses
  cisco.aci.aci_static_node_mgmt_address:
    host: "Host IP"
    username: admin
    password: SomeSecretePassword
    type: in_band
    state: query
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
        node_id=dict(type="int"),
        pod_id=dict(type="int"),
        type=dict(type="str", choices=["in_band", "out_of_band"], required=True),
        epg=dict(type="str"),
        ipv4_address=dict(type="str", aliases=["ip"]),
        ipv4_gw=dict(type="str", aliases=["gw"]),
        ipv6_address=dict(type="str", aliases=["ipv6"]),
        ipv6_gw=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", "absent", ["node_id", "epg"]], ["state", "present", ["node_id", "epg", "ipv4_address", "ipv4_gw"]]],
    )

    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    type = module.params.get("type")
    epg = module.params.get("epg")
    ipv4_address = module.params.get("ipv4_address")
    ipv4_gw = module.params.get("ipv4_gw")
    ipv6_address = module.params.get("ipv6_address")
    ipv6_gw = module.params.get("ipv6_gw")
    state = module.params.get("state")

    class_map = dict(
        in_band=list([dict(aci_class="mgmtInb", aci_rn="inb-{0}"), dict(aci_class="mgmtRsInBStNode", aci_rn="rsinBStNode-[{0}]")]),
        out_of_band=list([dict(aci_class="mgmtOob", aci_rn="oob-{0}"), dict(aci_class="mgmtRsOoBStNode", aci_rn="rsooBStNode-[{0}]")]),
    )

    static_path = None
    if pod_id is not None and node_id is not None:
        static_path = "topology/pod-{0}/node-{1}".format(pod_id, node_id)

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
        subclass_3=dict(
            aci_class=class_map.get(type)[1]["aci_class"],
            aci_rn=class_map.get(type)[1]["aci_rn"].format(static_path),
            module_object=static_path,
            target_filter={"name": static_path},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=class_map.get(type)[1]["aci_class"],
            class_config=dict(addr=ipv4_address, gw=ipv4_gw, v6Addr=ipv6_address, v6Gw=ipv6_gw),
        )
        aci.get_diff(aci_class=class_map.get(type)[1]["aci_class"])

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
