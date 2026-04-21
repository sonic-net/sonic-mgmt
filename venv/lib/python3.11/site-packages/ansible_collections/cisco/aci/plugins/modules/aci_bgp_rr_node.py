#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Tim Cragg (@timcragg)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_bgp_rr_node
short_description: Manage BGP Route Reflector objects (bgp:RRNodePEp)
description:
- Manage ACI BGP Route Reflector Nodes.
options:
  node_id:
    description:
    - ID of the Route Reflector Node
    type: int
  pod_id:
    description:
    - Pod the node belongs to
    type: int
  description:
    description:
    - Description of the Route Reflector Node
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
  description: More information about the internal APIC class B(bgp:RRNodePEp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new BGP Route Reflector
  cisco.aci.aci_bgp_rr_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    node_id: 101
    pod_id: 1
    state: present
    delegate_to: localhost

- name: Remove a BGP Route Reflector
  cisco.aci.aci_bgp_rr_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    node_id: 101
    state: absent
    delegate_to: localhost

- name: Query a BGP Route Reflector
  cisco.aci.aci_bgp_rr_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    node_id: 101
    state: query
    delegate_to: localhost
    register: query_result

- name: Query all BGP Route Reflectors
  cisco.aci.aci_bgp_rr_node:
    host: apic
    username: admin
    password: SomeSecretPassword
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
        node_id=dict(type="int"),
        pod_id=dict(type="int"),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["node_id"]],
            ["state", "present", ["node_id", "pod_id"]],
        ],
    )

    node_id = module.params.get("node_id")
    pod_id = module.params.get("pod_id")
    description = module.params.get("description")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="bgpInstPol",
            aci_rn="fabric/bgpInstP-default",
            module_object="default",
            target_filter={"name": "default"},
        ),
        subclass_1=dict(
            aci_class="bgpRRP",
            aci_rn="rr",
            module_object="name",
            target_filter={"name": ""},
        ),
        subclass_2=dict(
            aci_class="bgpRRNodePEp",
            aci_rn="node-{0}".format(node_id),
            module_object=node_id,
            target_filter={"id": node_id},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="bgpRRNodePEp",
            class_config=dict(
                descr=description,
                id=node_id,
                podId=pod_id,
            ),
        )

        aci.get_diff(aci_class="bgpRRNodePEp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
