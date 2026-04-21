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
module: aci_l4l7_service_graph_template_node
version_added: "2.12.0"
short_description: Manage L4-L7 Service Graph Templates Nodes (vns:AbsNode)
description:
- Manage Manage L4-L7 Service Graph Templates Nodes.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  service_graph:
    description:
    - The name of an existing Service Graph.
    type: str
  description:
    description:
    - The description of the Service Graph Template Node.
    type: str
  node:
    description:
    - The name of the Service Graph Template Node.
    type: str
  functional_template_type:
    description:
    - The functional template type for the node.
    - The APIC defaults to C(other) when unset during creation.
    type: str
    choices: [
      adc_one_arm,
      adc_two_arm,
      cloud_native_fw,
      cloud_native_lb,
      cloud_vendor_fw,
      cloud_vendor_lb,
      fw_routed,
      fw_trans,
      other
    ]
    aliases: [ func_template_type ]
  function_type:
    description:
    - The type of function.
    - The APIC defaults to C(go_to) when unset during creation.
    type: str
    choices: [ go_to, go_through, l1, l2 ]
    aliases: [ func_type ]
  device:
    description:
    - The name of an existing logical device.
    type: str
  device_tenant:
    description:
    - The tenant the logical device exists under.
    - This variable is only used if logical device and node exist within different tenants.
    - Intended use case is when the device is in the C(common) tenant but the node is not.
    type: str
  managed:
    description:
    - Whether this device managed by the apic.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  routing_mode:
    description:
    - The routing mode for the node.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ redirect, unspecified ]
  is_copy:
    description:
    - Whether the device is a copy device.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  share_encap:
    description:
    - Whether to share encapsulation across the service graph.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
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
notes:
- The I(tenant), I(service_graph) and I(device) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l4l7_service_graph_template) and M(cisco.aci.aci_l4l7_device) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l4l7_service_graph_template
- module: cisco.aci.aci_l4l7_device
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(vnsAbsNode)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new Service Graph Template Node
  cisco.aci.aci_l4l7_service_graph_template_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: test-graph
    node: test-node
    functional_template_type: adc_one_arm
    function_type: GoTo
    device: test-device
    managed: false
    routing_mode: redirect
    state: present
  delegate_to: localhost

- name: Query a Service Graph Template Node
  cisco.aci.aci_l4l7_service_graph_template_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: test-graph
    node: test-node
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Service Graph Template Nodes
  cisco.aci.aci_l4l7_service_graph_template_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Service Graph Template Node
  cisco.aci.aci_l4l7_service_graph_template_node:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    service_graph: test-graph
    node: test-node
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import L4L7_FUNC_TYPES_MAPPING, L4L7_FUNCTIONAL_TEMPLATE_TYPES_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        service_graph=dict(type="str"),
        node=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        functional_template_type=dict(type="str", aliases=["func_template_type"], choices=list(L4L7_FUNCTIONAL_TEMPLATE_TYPES_MAPPING)),
        function_type=dict(type="str", aliases=["func_type"], choices=list(L4L7_FUNC_TYPES_MAPPING)),
        device=dict(type="str"),
        device_tenant=dict(type="str"),
        managed=dict(type="bool"),
        routing_mode=dict(type="str", choices=["redirect", "unspecified"]),
        is_copy=dict(type="bool"),
        description=dict(type="str"),
        share_encap=dict(type="bool"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "service_graph", "node"]],
            ["state", "present", ["tenant", "service_graph", "node", "device"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    service_graph = module.params.get("service_graph")
    node = module.params.get("node")
    state = module.params.get("state")
    functional_template_type = L4L7_FUNCTIONAL_TEMPLATE_TYPES_MAPPING.get(module.params.get("functional_template_type"))
    function_type = L4L7_FUNC_TYPES_MAPPING.get(module.params.get("function_type"))
    device = module.params.get("device")
    device_tenant = module.params.get("device_tenant")
    managed = aci.boolean(module.params.get("managed"))
    routing_mode = "Redirect" if module.params.get("routing_mode") == "redirect" else module.params.get("routing_mode")
    is_copy = aci.boolean(module.params.get("is_copy"))
    description = module.params.get("description")
    share_encap = aci.boolean(module.params.get("share_encap"))

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsAbsGraph",
            aci_rn="AbsGraph-{0}".format(service_graph),
            module_object=service_graph,
            target_filter={"name": service_graph},
        ),
        subclass_2=dict(
            aci_class="vnsAbsNode",
            aci_rn="AbsNode-{0}".format(node),
            module_object=node,
            target_filter={"name": node},
        ),
        child_classes=["vnsRsNodeToLDev"],
    )

    aci.get_existing()
    if not device_tenant:
        device_tenant = tenant
    dev_tdn = "uni/tn-{0}/lDevVip-{1}".format(device_tenant, device)

    if state == "present":
        aci.payload(
            aci_class="vnsAbsNode",
            class_config=dict(
                name=node,
                funcTemplateType=functional_template_type,
                funcType=function_type,
                managed=managed,
                routingMode=routing_mode,
                isCopy=is_copy,
                descr=description,
                shareEncap=share_encap,
            ),
            child_configs=[
                dict(
                    vnsRsNodeToLDev=dict(
                        attributes=dict(tDn=dev_tdn),
                    ),
                ),
            ],
        )
        aci.get_diff(aci_class="vnsAbsNode")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
