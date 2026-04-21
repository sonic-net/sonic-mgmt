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
module: aci_l4l7_logical_interface
version_added: "2.12.0"
short_description: Manage L4-L7 Logical Interface (vns:LIf)
description:
- Manage Layer 4 to Layer 7 (L4-L7) Logical Interfaces.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  logical_device:
    description:
    - The name of an existing Logical Device.
    type: str
    aliases: [ device_name, device, logical_device_name ]
  logical_interface:
    description:
    - The name of an existing Logical Interface.
    type: str
    aliases: [ name ]
  encap:
    description:
    - The encapsulation of the Logical Interface.
    - It requires the VLAN to be prepended, for example, 'vlan-987'.
    type: str
  enhanced_lag_policy:
    description:
    - Name of the VMM Domain Enhanced Lag Policy.
    type: str
    aliases: [ lag_policy ]
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
- The I(tenant) and I(logical_device) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and M(cisco.aci.aci_l4l7_device) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l4l7_device
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vns:LIf)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new logical interface
  cisco.aci.aci_l4l7_logical_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    logical_interface: my_log_intf
    encap: vlan-987
    state: present
  delegate_to: localhost

- name: Query a logical interface
  cisco.aci.aci_l4l7_logical_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    logical_interface: my_log_intf
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all logical interfaces
  cisco.aci.aci_l4l7_logical_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a logical interface
  cisco.aci.aci_l4l7_logical_interface:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_device
    logical_interface: my_log_intf
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
        logical_interface=dict(type="str", aliases=["name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        encap=dict(type="str"),
        enhanced_lag_policy=dict(type="str", aliases=["lag_policy"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "logical_device", "logical_interface"]],
            ["state", "present", ["tenant", "logical_device", "logical_interface"]],
        ],
    )

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    logical_device = module.params.get("logical_device")
    logical_interface = module.params.get("logical_interface")
    encap = module.params.get("encap")
    enhanced_lag_policy = module.params.get("enhanced_lag_policy")

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
            aci_class="vnsLIf",
            aci_rn="lIf-{0}".format(logical_interface),
            module_object=logical_interface,
            target_filter={"name": logical_interface},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vnsLIf",
            class_config=dict(name=logical_interface, encap=encap, lagPolicyName=enhanced_lag_policy),
        )
        aci.get_diff(aci_class="vnsLIf")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
