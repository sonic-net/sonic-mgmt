#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Samita Bhattacharjee (@samiib)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: aci_switch_fabric_config
version_added: "2.13.0"
short_description: Manage Switch Fabric Policy Configuration of Leaf and Spine nodes (fabric:NodeConfig).
description:
- Manage Switch Fabric Policy Configuration of Leaf and Spine nodes (fabric:NodeConfig) on Cisco ACI fabrics.
- This module is only available for APIC version 6.0 and above.
options:
  node_type:
    description:
    - The type of Node.
    type: str
    aliases: [ type, switch_type ]
    choices: [ leaf, spine ]
  node:
    description:
    - The ID of the Node.
    - The value must be between 101 to 4000.
    type: int
    aliases: [ node_id ]
  policy_group:
    description:
    - The name of the Leaf/Spine Fabric Policy Group to associate with the node.
    - The Fabric Policy Group must exist for the settings to be applied.
    type: str
    aliases: [ fabric_policy_group, fabric_policy ]
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
- module: cisco.aci.aci_fabric_switch_policy_group
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:NodeConfig).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samiib)
"""

EXAMPLES = r"""
- name: Add Switch Fabric Policy Configuration to a Leaf node
  cisco.aci.aci_switch_fabric_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    node: 101
    node_type: leaf
    policy_group: ansible_leaf_fabric_policy
    state: present
  delegate_to: localhost

- name: Query Switch Fabric Policy Configuration for a specific node
  cisco.aci.aci_switch_fabric_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    node: 101
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Switch Fabric Policy Configurations
  cisco.aci.aci_switch_fabric_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Switch Fabric Policy Configuration
  cisco.aci.aci_switch_fabric_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    node: 101
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    switch_config_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.constants import (
    SWITCH_CONFIG_FORMAT_MAP,
)


def main():
    moClass = "fabricNodeConfig"
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(switch_config_spec(SWITCH_CONFIG_FORMAT_MAP[moClass]["type"]))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["node"]],
            ["state", "present", ["node", "node_type", "policy_group"]],
        ],
    )

    node = module.params.get("node")
    node_type = module.params.get("node_type")
    policy_group = module.params.get("policy_group")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class=moClass,
            target_filter=dict(node=node),
            aci_rn=SWITCH_CONFIG_FORMAT_MAP[moClass]["rn"].format(node),
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=moClass,
            class_config=dict(
                node=node,
                assocGrp=SWITCH_CONFIG_FORMAT_MAP[moClass][node_type].format(policy_group),
            ),
        )

        aci.get_diff(aci_class=moClass)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
