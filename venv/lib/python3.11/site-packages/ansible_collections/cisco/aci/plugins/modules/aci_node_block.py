#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_node_block
short_description: Manage Node Block (infra:NodeBlk)
description:
- Manage Node Blocks on Cisco ACI fabrics.
- A node block is a range of nodes. Each node block begins with the first port and ends with the last port.
options:
  switch_profile:
    description:
    - The name of the Fabric access policy leaf/spine switch profile.
    type: str
    aliases:
    - leaf_profile_name
    - leaf_profile
    - switch_profile_name
    - spine_switch_profile
    - spine_switch_profile_name
  access_port_selector:
    description:
    -  The name of the Fabric access policy leaf/spine switch port selector.
    type: str
    aliases: [ access_port_selector_name, port_selector, port_selector_name ]
  node_block:
    description:
    - The name of the Node Block.
    type: str
    aliases: [ node_block_name, name ]
  description:
    description:
    - The description for the Node Block.
    type: str
    aliases: [ node_block_description ]
  from_port:
    description:
    - The beginning of the port range block for the Node Block.
    type: str
    aliases: [ from, from_port_range ]
  to_port:
    description:
    - The end of the port range block for the Node Block.
    type: str
    aliases: [ to, to_port_range ]
  type_node:
    description:
    - The type of Node Block to be created under respective access port.
    type: str
    choices: [ leaf, spine ]
    aliases: [ type ]
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
-  If Adding a port block on an access leaf switch port selector of I(type) C(leaf),
  The I(switch_profile) and I(access_port_selector) must exist before using this module in your playbook.
  The M(cisco.aci.aci_switch_policy_leaf_profile) and M(cisco.aci.aci_switch_leaf_selector) modules can be used for this.
-  If Adding a port block on an access switch port selector of C(type) C(spine),
  The I(switch_profile) and I(access_port_selector) must exist before using this module in your playbook.
  The M(cisco.aci.aci_access_spine_switch_profile) and M(cisco.aci.aci_access_spine_switch_selector) modules can be used for this.
seealso:
- module: cisco.aci.aci_switch_policy_leaf_profile
- module: cisco.aci.aci_switch_leaf_selector
- module: cisco.aci.aci_access_spine_switch_profile
- module: cisco.aci.aci_access_spine_switch_selector
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(infra:NodeBlk).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new Node Block associated to a switch policy leaf profile selector
  cisco.aci.aci_node_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_profile: my_leaf_switch_profile
    access_port_selector: my_leaf_switch_selector
    node_block: my_node_block
    from_port: 1011
    to_port: 1011
    type_node: leaf
    state: present
  delegate_to: localhost

- name: Add a new Node Block associated to a switch policy spine profile selector
  cisco.aci.aci_node_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_profile: my_spine_switch_profile
    access_port_selector: my_spine_switch_selector
    node_block: my_node_block
    from_port: 1012
    to_port: 1012
    type_node: spine
    state: present
  delegate_to: localhost

- name: Query a Node Block associated to a switch policy leaf profile selector
  cisco.aci.aci_node_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_profile: my_leaf_switch_profile
    access_port_selector: my_leaf_switch_selector
    node_block: my_node_block
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Node Blocks under the switch policy leaf profile selector
  cisco.aci.aci_node_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_profile: my_leaf_switch_profile
    access_port_selector: my_leaf_switch_selector
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Node Blocks
  cisco.aci.aci_node_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Node Block associated to a switch policy leaf profile selector
  cisco.aci.aci_node_block:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_profile: my_leaf_switch_profile
    access_port_selector: my_leaf_switch_selector
    node_block: my_node_block
    type_node: leaf
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        switch_profile=dict(
            type="str",
            aliases=[
                "leaf_profile_name",
                "leaf_profile",
                "switch_profile_name",
                "spine_switch_profile",
                "spine_switch_profile_name",
            ],
        ),  # Not required for querying all objects
        access_port_selector=dict(
            type="str",
            aliases=[
                "access_port_selector_name",
                "port_selector",
                "port_selector_name",
            ],
        ),  # Not required for querying all objects
        node_block=dict(type="str", aliases=["node_block_name", "name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["node_block_description"]),
        from_port=dict(type="str", aliases=["from", "from_port_range"]),
        to_port=dict(type="str", aliases=["to", "to_port_range"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        type_node=dict(type="str", choices=["leaf", "spine"], aliases=["type"]),  # Not required for querying all objects
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["switch_profile", "access_port_selector", "node_block", "type_node"]],
            ["state", "present", ["switch_profile", "access_port_selector", "node_block", "type_node"]],
        ],
    )

    switch_profile = module.params.get("switch_profile")
    access_port_selector = module.params.get("access_port_selector")
    node_block = module.params.get("node_block")
    description = module.params.get("description")
    from_port = module.params.get("from_port")
    to_port = module.params.get("to_port")
    state = module.params.get("state")
    type_node = module.params.get("type_node")

    aci = ACIModule(module)

    if type_node == "spine":
        subclass_1 = dict(
            aci_class="infraSpineP",
            aci_rn="spprof-{0}".format(switch_profile),
            module_object=switch_profile,
            target_filter={"name": switch_profile},
        )
        subclass_2 = dict(
            aci_class="infraSpineS",
            aci_rn="spines-{0}-typ-range".format(access_port_selector),
            module_object=access_port_selector,
            target_filter={"name": access_port_selector},
        )
    else:
        subclass_1 = dict(
            aci_class="infraNodeP",
            aci_rn="nprof-{0}".format(switch_profile),
            module_object=switch_profile,
            target_filter={"name": switch_profile},
        )
        subclass_2 = dict(
            aci_class="infraLeafS",
            aci_rn="leaves-{0}-typ-range".format(access_port_selector),
            module_object=access_port_selector,
            target_filter={"name": access_port_selector},
        )
    aci.construct_url(
        root_class=dict(
            aci_class="infraInfra",
            aci_rn="infra",
        ),
        subclass_1=subclass_1,
        subclass_2=subclass_2,
        subclass_3=dict(
            aci_class="infraNodeBlk",
            aci_rn="nodeblk-{0}".format(node_block),
            module_object=node_block,
            target_filter={"name": node_block},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraNodeBlk",
            class_config=dict(
                descr=description,
                name=node_block,
                from_=from_port,
                to_=to_port,
            ),
        )

        aci.get_diff(aci_class="infraNodeBlk")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
