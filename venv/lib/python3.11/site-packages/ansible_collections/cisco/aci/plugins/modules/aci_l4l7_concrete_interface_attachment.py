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
module: aci_l4l7_concrete_interface_attachment
version_added: "2.12.0"
short_description: Manage L4-L7 Concrete Interface Attachment (vns:RsCIfAttN)
description:
- Manage Layer 4 to Layer 7 (L4-L7) Concrete Interface Attachment to Logical Interfaces.
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
  concrete_device:
    description:
    - The name of an existing Concrete Device.
    type: str
    aliases: [ concrete_device_name ]
  concrete_interface:
    description:
    - The name of an existing Concrete Interface.
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
- The I(tenant), I(logical_device), I(logical_interface) and I(concrete_device) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l4l7_device), M(cisco.aci.aci_l4l7_logical_interface)
  and M(cisco.aci.aci_l4l7_concrete_device) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l4l7_device
- module: cisco.aci.aci_l4l7_logical_interface
- module: cisco.aci.aci_l4l7_concrete_device
- module: cisco.aci.aci_l4l7_concrete_interface
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vns:RsCIfAttN)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new concrete interface attachment
  cisco.aci.aci_l4l7_concrete_interface_attachment:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_log_device
    logical_interface: my_log_intf
    concrete_device: my_conc_device
    concrete_interface: my_conc_intf
    state: present
  delegate_to: localhost

- name: Query a concrete interface attachment
  cisco.aci.aci_l4l7_concrete_interface_attachment:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_log_device
    logical_interface: my_log_intf
    concrete_device: my_conc_device
    concrete_interface: my_conc_intf
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all concrete interface attachments
  cisco.aci.aci_l4l7_concrete_interface_attachment:
    host: apic
    username: admin
    password: SomeSecretPassword
  delegate_to: localhost
  register: query_result

- name: Delete a concrete interface attachment
  cisco.aci.aci_l4l7_concrete_interface_attachment:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    device: my_log_device
    logical_interface: my_log_intf
    concrete_device: my_conc_device
    concrete_interface: my_conc_intf
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
        logical_interface=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        concrete_device=dict(type="str", aliases=["concrete_device_name"]),
        concrete_interface=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "logical_device", "logical_interface", "concrete_device", "concrete_interface"]],
            ["state", "present", ["tenant", "logical_device", "logical_interface", "concrete_device", "concrete_interface"]],
        ],
        required_together=[
            ["tenant", "logical_device", "concrete_device", "concrete_interface"],
        ],
    )

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    logical_device = module.params.get("logical_device")
    logical_interface = module.params.get("logical_interface")
    concrete_device = module.params.get("concrete_device")
    concrete_interface = module.params.get("concrete_interface")

    aci = ACIModule(module)

    tdn = (
        "uni/tn-{0}/lDevVip-{1}/cDev-{2}/cIf-[{3}]".format(tenant, logical_device, concrete_device, concrete_interface)
        if concrete_interface is not None
        else None
    )

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
        subclass_3=dict(
            aci_class="vnsRsCIfAttN",
            aci_rn="rscIfAttN-[{0}]".format(tdn),
            module_object=tdn,
            target_filter={"tDn": tdn},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vnsRsCIfAttN",
            class_config=dict(tDn=tdn),
        )
        aci.get_diff(aci_class="vnsRsCIfAttN")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
