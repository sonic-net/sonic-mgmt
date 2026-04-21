#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Bruno Calogero <brunocalogero@hotmail.com>
# Copyright: (c) 2023, Gaspard Micol <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_node
short_description: Manage Fabric Node Members (fabric:NodeIdentP)
description:
- Manage Fabric Node Members on Cisco ACI fabrics.
options:
  pod_id:
    description:
    - The pod id of the new Fabric Node Member.
    type: int
  serial:
    description:
    - Serial Number for the new Fabric Node Member.
    type: str
    aliases: [ serial_number ]
  node_id:
    description:
    - Node ID Number for the new Fabric Node Member.
    type: int
  switch:
    description:
    - Switch Name for the new Fabric Node Member.
    type: str
    aliases: [ name, switch_name ]
  description:
    description:
    - Description for the new Fabric Node Member.
    type: str
    aliases: [ descr ]
  role:
    description:
    - Role for the new Fabric Node Member.
    type: str
    aliases: [ role_name ]
    choices: [ leaf, spine, unspecified ]
  node_type:
    description:
    - Type for the new Fabric Node Member.
    type: str
    choices: [ tier_2, remote, virtual, unspecified ]
  remote_leaf_pool_id:
    description:
    - External Pool Id of the remote leaf.
    - I(remote_leaf_pool_id) is incompatible with I(node_type) other than C(remote).
    - I(remote_leaf_pool_id) is required if I(node_type) is C(remote).
    type: str
    aliases: [ pool_id ]
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fabric:NodeIdentP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Bruno Calogero (@brunocalogero)
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add fabric node
  cisco.aci.aci_fabric_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    serial: FDO2031124L
    node_id: 1011
    switch: fab4-sw1011
    state: present
  delegate_to: localhost

- name: Remove fabric node
  cisco.aci.aci_fabric_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    serial: FDO2031124L
    node_id: 1011
    state: absent
  delegate_to: localhost

- name: Query fabric nodes
  cisco.aci.aci_fabric_node:
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
  sample: '?rsp-prop-include=config-only'
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import NODE_TYPE_MAPPING
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


# NOTE: (This problem is also present on the APIC GUI)
# NOTE: When specifying a C(role) the new Fabric Node Member will be created but Role on GUI will be "unknown", hence not what seems to be a module problem


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        description=dict(type="str", aliases=["descr"]),
        node_id=dict(type="int"),  # Not required for querying all objects
        pod_id=dict(type="int"),
        role=dict(type="str", choices=["leaf", "spine", "unspecified"], aliases=["role_name"]),
        node_type=dict(type="str", choices=list(NODE_TYPE_MAPPING.keys())),
        remote_leaf_pool_id=dict(type="str", aliases=["pool_id"]),
        serial=dict(type="str", aliases=["serial_number"]),  # Not required for querying all objects
        switch=dict(type="str", aliases=["name", "switch_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["node_id", "serial"]],
            ["state", "present", ["node_id", "serial"]],
            ["node_type", "remote", ["remote_leaf_pool_id"]],
        ],
    )

    pod_id = module.params.get("pod_id")
    serial = module.params.get("serial")
    node_id = module.params.get("node_id")
    switch = module.params.get("switch")
    description = module.params.get("description")
    role = module.params.get("role")
    node_type = module.params.get("node_type")
    remote_leaf_pool_id = module.params.get("remote_leaf_pool_id")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    if node_type != "remote" and remote_leaf_pool_id:
        module.fail_json(msg="External Pool Id is not compatible with a node type other than 'remote'.")

    node_type = NODE_TYPE_MAPPING.get(node_type)

    aci.construct_url(
        root_class=dict(
            aci_class="fabricNodeIdentP",
            aci_rn="controller/nodeidentpol/nodep-{0}".format(serial),
            module_object=serial,
            target_filter={"serial": serial},
        )
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricNodeIdentP",
            class_config=dict(
                descr=description,
                name=switch,
                nodeId=node_id,
                podId=pod_id,
                # NOTE: Originally we were sending 'rn', but now we need 'dn' for idempotency
                dn="uni/controller/nodeidentpol/nodep-{0}".format(serial),
                role=role,
                nodeType=node_type,
                extPoolId=remote_leaf_pool_id,
                serial=serial,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="fabricNodeIdentP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json(**aci.result)


if __name__ == "__main__":
    main()
