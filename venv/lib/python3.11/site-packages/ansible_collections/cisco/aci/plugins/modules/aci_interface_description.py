#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_description
short_description: Setting and removing description on physical interfaces (infra:HPathS, infra:RsHPathAtt, infra:SHPathS, and infra:RsSHPathAtt)
description:
- Setting and removing description on physical interfaces on Cisco ACI fabrics.
options:
  pod_id:
    description:
    - The pod number.
    - C(pod_id) is usually an integer below C(12)
    type: int
    aliases: [ pod, pod_number ]
  node_id:
    description:
    - The switch ID that the C(interface) belongs to.
    - The C(node_id) value is usually something like '101'.
    type: int
    aliases: [ leaf, spine, node ]
  node_type:
    description:
    - The type of node the C(interface) is configured on.
    type: str
    choices: [ leaf, spine ]
  interface:
    description:
    - The name of the C(interface) that is targeted.
    - Usually an interface name with the following format C(1/7).
    type: str
  fex_id:
    description:
    - The fex ID that the C(interface) belongs to.
    - The C(fex_id) value is usually something like '123'.
    type: int
  description:
    description:
    - The C(description) that should be attached to the C(interface).
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
  description: More information about the internal APIC classes B(infra:HPathS), B(infra:RsHPathAtt), B(infra:SHPathS), and B(infra:RsSHPathAtt).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Set Interface Description
  cisco.aci.aci_interface_description:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    node_type: leaf
    interface: 1/49
    description: foobar
    state: present
  delegate_to: localhost

- name: Remove Interface Description
  cisco.aci.aci_interface_description:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    node_type: leaf
    interface: 1/49
    description: foobar
    state: absent
  delegate_to: localhost

- name: Set Interface Description on Fex
  cisco.aci.aci_interface_description:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    fex_id: 123
    interface: 1/49
    description: foobar
    state: present
  delegate_to: localhost

- name: Remove Interface Description on Fex
  cisco.aci.aci_interface_description:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    fex_id: 123
    interface: 1/49
    description: foobar
    state: absent
  delegate_to: localhost

- name: Query Interface
  cisco.aci.aci_interface_description:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    node_type: leaf
    interface: 1/49
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        pod_id=dict(type="int", aliases=["pod", "pod_number"]),
        node_id=dict(type="int", aliases=["leaf", "spine", "node"]),
        fex_id=dict(type="int"),
        node_type=dict(type="str", choices=["leaf", "spine"]),
        interface=dict(type="str"),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[
            ("node_type", "fex_id"),
        ],
        required_if=[
            ["state", "absent", ["pod_id", "node_id", "interface"]],
            ["state", "present", ["pod_id", "node_id", "interface", "description"]],
        ],
    )

    aci = ACIModule(module)

    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    interface = module.params.get("interface")
    description = module.params.get("description")
    fex_id = module.params.get("fex_id")
    node_type = module.params.get("node_type")
    state = module.params.get("state")

    class_name = "infraHPathS"
    children = ["infraRsHPathAtt"]
    if node_type == "spine":
        class_name = "infraSHPathS"
        children = ["infraRsSHPathAtt"]
    rn = None
    child_configs = None

    if node_id and interface:
        if fex_id:
            rn = "hpaths-{0}_eth{1}_{2}".format(node_id, fex_id, interface.replace("/", "_"))
            child_configs = [
                dict(
                    infraRsHPathAtt=dict(
                        attributes=dict(tDn="topology/pod-{0}/paths-{1}/extpaths-{2}/pathep-[eth{3}]".format(pod_id, node_id, fex_id, interface))
                    )
                ),
            ]
        elif node_type == "spine":
            rn = "shpaths-{0}_eth{1}".format(node_id, interface.replace("/", "_"))
            child_configs = [
                dict(infraRsSHPathAtt=dict(attributes=dict(tDn="topology/pod-{0}/paths-{1}/pathep-[eth{2}]".format(pod_id, node_id, interface)))),
            ]
        elif node_type == "leaf":
            rn = "hpaths-{0}_eth{1}".format(node_id, interface.replace("/", "_"))
            child_configs = [
                dict(infraRsHPathAtt=dict(attributes=dict(tDn="topology/pod-{0}/paths-{1}/pathep-[eth{2}]".format(pod_id, node_id, interface)))),
            ]

    dn = None
    interface_name = None
    infra_mo = None
    if rn:
        dn = "uni/infra/{0}".format(rn)
        interface_name = rn.split("-")[1]
        infra_mo = "infra"

    aci.construct_url(
        root_class=dict(aci_class="infraInfra", aci_rn="infra", module_object=infra_mo, target_filter=dict(name="infra")),
        subclass_1=dict(aci_class=class_name, aci_rn=rn, module_object=dn, target_filter=dict(name=interface_name)),
        child_classes=children,
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=class_name,
            class_config=dict(
                descr=description,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=class_name)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
