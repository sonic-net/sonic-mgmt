#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_fabric_node_decommission
version_added: "2.13.0"
short_description: Manage the Commissioning and Decommissioning of the Fabric Node (fabric:RsDecommissionNode)
description:
- Manage the Commissioning and Decommissioning of the Fabric Node on Cisco ACI fabrics.
options:
  pod_id:
    description:
    - The Pod ID for the Fabric Node.
    type: int
  node_id:
    description:
    - The Node ID for the Fabric Node.
    type: int
  remove_from_controller:
    description:
    - Completely deletes the node configuration from the controller during decommissioning.
    - To register the fabric node, use M(cisco.aci.aci_fabric_node).
    - The APIC defaults to O(remove_from_controller=false) when unset during creation.
    type: bool
  state:
    description:
    - Use C(present) for decommissioning the Fabric Node.
    - Use C(absent) for commissioning the Fabric Node.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:RsDecommissionNode).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Decommission the fabric node
  cisco.aci.aci_fabric_node_decommission:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 1
    node_id: 201
    state: present

- name: Query the decommissioned fabric node
  cisco.aci.aci_fabric_node_decommission:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 1
    node_id: 201
    state: query
  register: query_one

- name: Query all decommissioned fabric nodes
  cisco.aci.aci_fabric_node_decommission:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  register: query_all

- name: Commission the fabric node
  cisco.aci.aci_fabric_node_decommission:
    host: apic
    username: admin
    password: SomeSecretPassword
    pod_id: 1
    node_id: 201
    state: absent
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
        pod_id=dict(type="int"),
        node_id=dict(type="int"),
        remove_from_controller=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["pod_id", "node_id"]],
            ["state", "absent", ["pod_id", "node_id"]],
        ],
    )

    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    remove_from_controller = module.params.get("remove_from_controller")
    state = module.params.get("state")

    aci = ACIModule(module)

    target_dn = None
    if pod_id and node_id:
        target_dn = "topology/pod-{0}/node-{1}".format(pod_id, node_id)

    aci.construct_url(
        root_class=dict(
            aci_class="fabricOOServicePol",
            aci_rn="fabric/outofsvc",
        ),
        subclass_1=dict(
            aci_class="fabricRsDecommissionNode",
            aci_rn="rsdecommissionNode-[{0}]".format(target_dn) if target_dn else None,
            target_filter={"tDn": target_dn},
        ),
    )

    aci.get_existing()

    if state == "present":  # Decommission
        aci.payload(
            aci_class="fabricRsDecommissionNode",
            class_config=dict(
                tDn=target_dn,
                removeFromController="yes" if remove_from_controller else "no",
            ),
        )
        aci.get_diff(aci_class="fabricRsDecommissionNode")
        aci.post_config()

    elif state == "absent" and aci.existing:  # Commission
        # The aci.delete_config function removes the object directly from APIC, which can interrupt the commission or decommission process before it finishes.
        # Because of that the Fabric Node may enter a bad state.
        aci.payload(
            aci_class="fabricRsDecommissionNode",
            class_config=dict(
                tDn=target_dn,
                status="deleted",
            ),
        )
        aci.get_diff(aci_class="fabricRsDecommissionNode")
        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
