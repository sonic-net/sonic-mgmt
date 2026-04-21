#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Tim Cragg (@timcragg)
# Copyright: (c) 2025, Shreyas Srish (@shrsr)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_concrete_interface
version_added: "2.12.0"
short_description: Manage L4-L7 Concrete Interfaces (vns:CIf)
description:
- Manage Layer 4 to Layer 7 (L4-L7) Concrete Interfaces.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  logical_device:
    description:
    - The name of an existing logical device.
    type: str
    aliases: [ device_name, device, logical_device_name ]
  concrete_device:
    description:
    - The name of an existing concrete device.
    type: str
    aliases: [ concrete_device_name ]
  name:
    description:
    - The name of the concrete interface.
    type: str
    aliases: [ concrete_interface ]
  pod_id:
    description:
      - The unique identifier for the pod where the concrete interface is located.
    type: int
  node_id:
    description:
      - The unique identifier for the node where the concrete interface is located.
      - For Ports and Port-channels, this is represented as a single node ID.
      - For virtual Port Channels (vPCs), this is represented as a hyphen-separated pair of node IDs, such as "201-202".
    type: str
  interface:
    description:
    - The path to the physical interface.
    - For single ports, this is the port name, e.g. "eth1/15".
    - For Port-channels and vPCs, this is the Interface Policy Group name.
    type: str
    aliases: [ path_ep, interface_name, interface_policy_group, interface_policy_group_name ]
  vnic_name:
    description:
    - The concrete interface vNIC name.
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
notes:
- The I(tenant), I(logical_device) and I(concrete_device) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l4l7_device) and M(cisco.aci.aci_l4l7_concrete_device) modules can be used for this.
seealso:
- module: cisco.aci.aci_l4l7_device
- module: cisco.aci.aci_l4l7_concrete_device
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vns:CIf)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new concrete interface on a single port
  cisco.aci.aci_l4l7_concrete_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    name: my_concrete_interface
    pod_id: 1
    node_id: 201
    interface: eth1/16
    state: present
  delegate_to: localhost

- name: Add a new concrete interface on a vPC
  cisco.aci.aci_l4l7_concrete_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    name: my_concrete_interface
    pod_id: 1
    node_id: 201-202
    interface: my_vpc_ipg
    state: present
  delegate_to: localhost

- name: Query a concrete interface
  cisco.aci.aci_l4l7_concrete_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    name: my_concrete_interface
    pod_id: 1
    node_id: 201-202
    interface: my_vpc_ipg
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all concrete interfaces
  cisco.aci.aci_l4l7_concrete_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a concrete interface
  cisco.aci.aci_l4l7_concrete_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    concrete_device: my_concrete_device
    name: my_concrete_interface
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
        tenant=dict(type="str", aliases=["tenant_name"]),
        logical_device=dict(type="str", aliases=["device_name", "device", "logical_device_name"]),
        concrete_device=dict(type="str", aliases=["concrete_device_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name=dict(type="str", aliases=["concrete_interface"]),
        pod_id=dict(type="int"),
        node_id=dict(type="str"),
        interface=dict(type="str", aliases=["path_ep", "interface_name", "interface_policy_group", "interface_policy_group_name"]),
        vnic_name=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "logical_device", "concrete_device", "name"]],
            ["state", "present", ["tenant", "logical_device", "concrete_device", "name", "pod_id", "node_id", "interface"]],
        ],
    )

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    logical_device = module.params.get("logical_device")
    concrete_device = module.params.get("concrete_device")
    name = module.params.get("name")
    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    interface = module.params.get("interface")
    vnic_name = module.params.get("vnic_name")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsLDevVip",
            aci_rn="lDevVip-{0}".format(logical_device),
            module_object=logical_device,
            target_filter={"name": logical_device},
        ),
        subclass_2=dict(
            aci_class="vnsCDev",
            aci_rn="cDev-{0}".format(concrete_device),
            module_object=concrete_device,
            target_filter={"name": concrete_device},
        ),
        subclass_3=dict(
            aci_class="vnsCIf",
            aci_rn="cIf-[{0}]".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["vnsRsCIfPathAtt"],
    )

    aci.get_existing()

    if state == "present":
        path_dn = "topology/pod-{0}/{1}-{2}/pathep-[{3}]".format(pod_id, "protpaths" if "-" in node_id else "paths", node_id, interface)
        aci.payload(
            aci_class="vnsCIf",
            class_config=dict(
                name=name,
                vnicName=vnic_name,
            ),
            child_configs=[
                dict(
                    vnsRsCIfPathAtt=dict(
                        attributes=dict(tDn=path_dn),
                    ),
                ),
            ],
        )
        aci.get_diff(aci_class="vnsCIf")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
