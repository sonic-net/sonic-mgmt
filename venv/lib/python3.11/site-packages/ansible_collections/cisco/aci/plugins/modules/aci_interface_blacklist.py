#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_blacklist
short_description: Enabling or Disabling physical interfaces (fabric:RsOosPath)
description:
- Enables or Disables physical interfaces on Cisco ACI fabrics.
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
  description: More information about the internal APIC class B(fabric:RsOosPath).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Disable Interface
  cisco.aci.aci_interface_blacklist:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    interface: 1/49
    state: present
  delegate_to: localhost

- name: Enable Interface
  cisco.aci.aci_interface_blacklist:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    interface: 1/49
    state: absent
  delegate_to: localhost

- name: Disable Interface on Fex
  cisco.aci.aci_interface_blacklist:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    fex_id: 123
    interface: 1/49
    state: present
  delegate_to: localhost

- name: Enable Interface on Fex
  cisco.aci.aci_interface_blacklist:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    fex_id: 123
    interface: 1/49
    state: absent
  delegate_to: localhost

- name: Query Interface
  cisco.aci.aci_interface_blacklist:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
    pod_id: 1
    node_id: 105
    interface: 1/49
    state: query
  delegate_to: localhost

- name: Query All Interfaces
  cisco.aci.aci_interface_blacklist:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: false
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        pod_id=dict(type="int", aliases=["pod", "pod_number"]),
        node_id=dict(type="int", aliases=["leaf", "spine", "node"]),
        fex_id=dict(type="int"),
        interface=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["pod_id", "node_id", "interface"]],
            ["state", "present", ["pod_id", "node_id", "interface"]],
        ],
    )

    aci = ACIModule(module)

    pod_id = module.params.get("pod_id")
    node_id = module.params.get("node_id")
    interface = module.params.get("interface")
    fex_id = module.params.get("fex_id")
    state = module.params.get("state")

    root_module_object = None
    subclass_1_module_object = None
    tdn = None
    rn = None

    if pod_id and node_id and interface:
        root_module_object = "fabric"
        subclass_1_module_object = "outofsvc"
        if fex_id:
            tdn = "topology/pod-{0}/paths-{1}/extpaths-{2}/pathep-[eth{3}]".format(pod_id, node_id, fex_id, interface)
        else:
            tdn = "topology/pod-{0}/paths-{1}/pathep-[eth{2}]".format(pod_id, node_id, interface)
        rn = "rsoosPath-[{0}]".format(tdn)

    aci.construct_url(
        root_class=dict(
            aci_class="fabricInst",
            aci_rn="fabric",
            module_object=root_module_object,
            target_filter={"name": "fabric"},
        ),
        subclass_1=dict(
            aci_class="fabricOOServicePol",
            aci_rn="outofsvc",
            module_object=subclass_1_module_object,
            target_filter={"name": "default"},
        ),
        subclass_2=dict(
            aci_class="fabricRsOosPath",
            aci_rn=rn,
            target_filter={"tDN": tdn},
        ),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fabricRsOosPath",
            class_config=dict(
                lc="blacklist",
            ),
        )

        aci.get_diff(aci_class="fabricRsOosPath")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
