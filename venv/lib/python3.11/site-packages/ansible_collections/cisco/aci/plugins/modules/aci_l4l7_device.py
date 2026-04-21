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
module: aci_l4l7_device
version_added: "2.12.0"
short_description: Manage L4-L7 Devices (vns:LDevVip)
description:
- Manage Layer 4 to Layer 7 (L4-L7) Devices.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  name:
    description:
    - The name of the L4-L7 device.
    type: str
    aliases: [ device, logical_device, device_name, logical_device_name ]
  context_aware:
    description:
    - Is device Single or Multi context aware.
    - The APIC defaults to C(single) when unset during creation.
    type: str
    choices: [ multi, single ]
  device_type:
    description:
    - The type of the device.
    - The APIC defaults to C(physical) when unset during creation.
    type: str
    choices: [ physical, virtual ]
    aliases: [ dev_type ]
  function_type:
    description:
    - The function type of the device.
    - The APIC defaults to C(go_to) when unset during creation.
    type: str
    choices: [ go_to, go_through, l1, l2 ]
    aliases: [ func_type ]
  managed:
    description:
    - Is the device a managed device.
    - The APIC defaults to true when unset during creation.
    type: bool
  promiscuous_mode:
    description:
    - Enable promiscuous mode.
    - The APIC defaults to false when unset during creation.
    type: bool
    aliases: [ prom_mode ]
  service_type:
    description:
    - The service type running on the device.
    - The APIC defaults to C(others) when unset during creation.
    type: str
    choices: [ adc, fw, others ]
    aliases: [ svc_type ]
  trunking:
    description:
    - Enable trunking.
    - The APIC defaults to false when unset during creation.
    type: bool
  domain:
    description:
    - The domain to bind to the device.
    - The type of domain is controlled by the device_type setting.
    type: str
  active_active_mode:
    description:
    - The active active mode on the device.
    - This is only applicable when C(function_type="l1") or C(function_type="l2").
    - The APIC defaults to false when unset during creation.
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
notes:
- The I(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vns:LDevVip)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new L4-L7 device
  cisco.aci.aci_l4l7_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    name: my_device
    state: present
    domain: phys
    function_type: go_to
    context_aware: single
    managed: false
    device_type: physical
    service_type: adc
    trunking: false
    promiscuous_mode: true
  delegate_to: localhost

- name: Query an L4-L7 device
  cisco.aci.aci_l4l7_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    name: my_device
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all L4-L7 devices
  cisco.aci.aci_l4l7_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete an existing L4-L7 device
  cisco.aci.aci_l4l7_device:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    name: my_device
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import L4L7_FUNC_TYPES_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        name=dict(type="str", aliases=["device", "device_name", "logical_device", "logical_device_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        context_aware=dict(type="str", choices=["single", "multi"]),
        device_type=dict(type="str", aliases=["dev_type"], choices=["physical", "virtual"]),
        function_type=dict(type="str", aliases=["func_type"], choices=list(L4L7_FUNC_TYPES_MAPPING)),
        managed=dict(type="bool"),
        promiscuous_mode=dict(type="bool", aliases=["prom_mode"]),
        service_type=dict(type="str", aliases=["svc_type"], choices=["adc", "fw", "others"]),
        trunking=dict(type="bool"),
        domain=dict(type="str"),
        active_active_mode=dict(type="bool"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "name"]],
            ["state", "present", ["tenant", "name", "device_type", "domain"]],
        ],
    )

    aci = ACIModule(module)

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    name = module.params.get("name")
    context_aware = module.params.get("context_aware")
    device_type = module.params.get("device_type")
    function_type = L4L7_FUNC_TYPES_MAPPING.get(module.params.get("function_type"))
    managed = aci.boolean(module.params.get("managed"))
    promiscuous_mode = aci.boolean(module.params.get("promiscuous_mode"))
    service_type = module.params.get("service_type")
    trunking = aci.boolean(module.params.get("trunking"))
    domain = module.params.get("domain")
    active_active_mode = aci.boolean(module.params.get("active_active_mode"))

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsLDevVip",
            aci_rn="lDevVip-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["vnsRsALDevToPhysDomP", "vnsCDev", "vnsRsALDevToDomP"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if device_type == "virtual":
            dom_class = "vnsRsALDevToDomP"
            tdn = "uni/vmmp-VMware/dom-{0}".format(domain)
        else:
            dom_class = "vnsRsALDevToPhysDomP"
            tdn = "uni/phys-{0}".format(domain)
        child_configs.append({dom_class: {"attributes": {"tDn": tdn}}})

        aci.payload(
            aci_class="vnsLDevVip",
            class_config=dict(
                name=name,
                contextAware="{0}-Context".format(context_aware),
                devtype=device_type.upper(),
                funcType=function_type,
                managed=managed,
                promMode=promiscuous_mode,
                svcType=service_type.upper(),
                trunking=trunking,
                activeActive=active_active_mode,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="vnsLDevVip")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
