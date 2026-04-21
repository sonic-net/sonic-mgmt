#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Sabari Jaganathan <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}


DOCUMENTATION = r"""
---
module: aci_interface_config
short_description: Manage Interface Configuration of Access (infra:PortConfig) and Fabric (fabric:PortConfig) Ports is only supported for ACI 5.2(7)+
description:
- Manage Interface Configuration of Access (infra:PortConfig) and Fabric (fabric:PortConfig) Ports is only supported for ACI 5.2(7)+
options:
  policy_group:
    description:
    - The name of the Policy Group being associated with the Port.
    - The I(policy_group) and I(breakout) cannot be configured simultaneously.
    type: str
    aliases: [ policy_group_name ]
  breakout:
    description:
    - The Breakout Map of the interface.
    - The I(policy_group) and I(breakout) cannot be configured simultaneously.
    type: str
    choices: [ 100g-2x, 100g-4x, 10g-4x, 25g-4x, 50g-8x ]
  description:
    description:
    - The description of the Interface Configuration object.
    type: str
    aliases: [ descr ]
  node:
    description:
    - The ID of the Node.
    - The value must be between 101 to 4000.
    type: int
    aliases: [ node_id ]
  pc_member:
    description:
    - The name of the Port Channel Member Policy (lacp:IfPol).
    - A Port Channel Member Policy is used to override LACP port priority and transmit rate of LACP packets.
    type: str
    aliases: [ port_channel_member ]
  port_type:
    description:
    - The type of the interface can be either access or fabric.
    type: str
    default: access
    choices: [ access, fabric ]
  role:
    description:
    - The role of the switch (node) can be either a leaf or a spine.
    - The APIC defaults to leaf when unset during creation.
    type: str
    aliases: [ node_type ]
    choices: [ leaf, spine ]
  admin_state:
    description:
    - The Admin State of the Interface.
    - The APIC defaults to up when unset during creation.
    type: str
    choices: [ up, down ]
  interface_type:
    description:
    - The type of the interface.
    type: str
    default: switch_port
    choices: [ switch_port, pc_or_vpc, fc, fc_port_channel, leaf_fabric, spine_access, spine_fabric ]
  interface:
    description:
    - The address of the interface.
    - The format of the interface value should be 1/1/1 (card/port_id/sub_port) or 1/1 (card/port_id).
    - The Card ID must be in the range of 1 to 255.
    - The Port ID must be in the range of 1 to 128.
    - The Sub Port ID must be in the range of 0 to 64.
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
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(infra:PortConfig).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""
EXAMPLES = r"""
- name: Add an interface with port channel(PC) policy group
  cisco.aci.aci_interface_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    role: leaf
    port_type: access
    interface_type: pc_or_vpc
    policy_group: ans_test_port_channel
    node: 502
    interface: "2/2/2"
    state: present
  delegate_to: localhost

- name: Add an interface with port channel(PC) policy group with a PC member policy override
  cisco.aci.aci_interface_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    role: leaf
    port_type: access
    interface_type: pc_or_vpc
    policy_group: ans_test_port_channel
    pc_member: ans_test_pc_member_policy
    node: 502
    interface: "2/2"
    state: present
  delegate_to: localhost

- name: Breakout the existing interface with "100g-4x"
  cisco.aci.aci_interface_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    role: leaf
    port_type: access
    node: 502
    interface: "2/2/2"
    breakout: "100g-4x"
    state: present
  delegate_to: localhost

- name: Query an access interface with node id
  cisco.aci.aci_interface_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    port_type: access
    node: 201
    state: query
  delegate_to: localhost

- name: Query a fabric interface with node id
  cisco.aci.aci_interface_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    port_type: fabric
    node: 202
    state: query
  delegate_to: localhost

- name: Query all access interfaces
  cisco.aci.aci_interface_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    port_type: access
    state: query
  delegate_to: localhost

- name: Query all fabric interfaces
  cisco.aci.aci_interface_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    port_type: fabric
    state: query
  delegate_to: localhost

- name: Remove a interface
  cisco.aci.aci_interface_config:
    host: apic
    username: admin
    password: SomeSecretPassword
    port_type: access
    node: 201
    interface: "1/1/1"
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec

PORT_TYPE_MAPPING = dict(
    access=dict(
        root_class="infraInfra",
        root_class_rn="infra",
        interface_class="infraPortConfig",
    ),
    fabric=dict(
        root_class="fabricInst",
        root_class_rn="fabric",
        interface_class="fabricPortConfig",
    ),
)

ADMIN_STATE_MAPPING = {"up": "no", "down": "yes"}


POLICY_GROUP_MAPPING = dict(
    switch_port="uni/infra/funcprof/accportgrp-{0}",
    pc_or_vpc="uni/infra/funcprof/accbundle-{0}",
    fc="uni/infra/funcprof/fcaccportgrp-{0}",
    fc_port_channel="uni/infra/funcprof/fcaccbundle-{0}",
    leaf_fabric="uni/fabric/funcprof/leportgrp-{0}",
    spine_access="uni/infra/funcprof/spaccportgrp-{0}",
    spine_fabric="uni/fabric/funcprof/spportgrp-{0}",
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        policy_group=dict(type="str", aliases=["policy_group_name"]),
        breakout=dict(type="str", choices=["100g-2x", "100g-4x", "10g-4x", "25g-4x", "50g-8x"]),
        description=dict(type="str", aliases=["descr"]),
        node=dict(type="int", aliases=["node_id"]),
        pc_member=dict(type="str", aliases=["port_channel_member"]),
        port_type=dict(type="str", default="access", choices=["access", "fabric"]),
        role=dict(type="str", choices=["leaf", "spine"], aliases=["node_type"]),
        admin_state=dict(type="str", choices=["up", "down"]),
        interface_type=dict(
            type="str",
            default="switch_port",
            choices=["switch_port", "pc_or_vpc", "fc", "fc_port_channel", "leaf_fabric", "spine_access", "spine_fabric"],
        ),
        interface=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["node", "interface"]],
            ["state", "present", ["node", "interface"]],
        ],
        mutually_exclusive=[("policy_group", "breakout")],
    )

    policy_group = module.params.get("policy_group")
    breakout = module.params.get("breakout")
    description = module.params.get("description")
    node = module.params.get("node")
    pc_member = module.params.get("pc_member")
    port_type = module.params.get("port_type")
    role = module.params.get("role")
    admin_state = module.params.get("admin_state")
    interface = module.params.get("interface")
    interface_type = module.params.get("interface_type")
    state = module.params.get("state")

    aci = ACIModule(module)

    try:
        if node is not None and int(node) not in range(101, 4001):
            aci.fail_json(msg="Node ID: {0} is invalid; it must be in the range of 101 to 4000.".format(node))

        card, port_id, sub_port = (None, None, None)
        if interface is not None:
            interface_parts = interface.split("/")
            if len(interface_parts) == 3:
                card, port_id, sub_port = interface_parts
            elif len(interface_parts) == 2:
                card, port_id = interface_parts
                sub_port = 0
            else:
                aci.fail_json(msg="Interface: {0} is invalid; The format must be either card/port/sub_port(1/1/1) or card/port(1/1)".format(interface))

            if int(card) not in range(1, 256):
                aci.fail_json(msg="Card ID: {0} is invalid; it must be in the range of 1 to 255.".format(card))

            if int(port_id) not in range(1, 129):
                aci.fail_json(msg="Port ID: {0} is invalid; it must be in the range of 1 to 128.".format(port_id))

            # Sub Port ID - 0 is default value
            if int(sub_port) not in range(0, 65):
                aci.fail_json(msg="Sub Port ID: {0} is invalid; it must be in the range of 0 to 64.".format(sub_port))
    except ValueError as error:
        aci.fail_json(msg="Interface configuration failed due to: {0}".format(error))

    root_class = PORT_TYPE_MAPPING.get(port_type)["root_class"]
    root_class_rn = PORT_TYPE_MAPPING.get(port_type)["root_class_rn"]
    interface_class = PORT_TYPE_MAPPING.get(port_type)["interface_class"]

    aci.construct_url(
        root_class=dict(
            aci_class=root_class,
            aci_rn=root_class_rn,
        ),
        subclass_1=dict(
            aci_class=interface_class,
            aci_rn="portconfnode-{0}-card-{1}-port-{2}-sub-{3}".format(node, card, port_id, sub_port),
            target_filter=dict(node=node),
        ),
    )

    aci.get_existing()

    if breakout is None and policy_group:
        policy_group_dn = POLICY_GROUP_MAPPING.get(interface_type).format(policy_group)
    else:
        # To handle the existing object property
        policy_group_dn = ""

    if state == "present":
        aci.payload(
            aci_class=interface_class,
            class_config=dict(
                assocGrp=policy_group_dn,
                brkoutMap=breakout,
                card=card,
                description=description,
                node=node,
                pcMember=pc_member,
                port=port_id,
                role=role,
                shutdown=ADMIN_STATE_MAPPING.get(admin_state),
                subPort=sub_port,
            ),
        )

        aci.get_diff(aci_class=interface_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
