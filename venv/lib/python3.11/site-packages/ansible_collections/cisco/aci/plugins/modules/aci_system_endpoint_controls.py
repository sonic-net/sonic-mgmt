#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <timcragg@cisco.com>
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_system_endpoint_controls
short_description: Manage System Endpoint Controls (ep:IpAgingP, ep:ControlP, and ep:LoopProtectP)
description:
- Manage System Endpoint Controls on Cisco ACI fabrics.
options:
  ip_aging:
    description: Configuration container for IP Aging.
    type: dict
    suboptions:
      admin_state:
        description:
        - Whether to enable IP Aging Controls on the fabric.
        type: bool
  roque_ep_control:
    description: Configuration container for Rogue EP Control.
    type: dict
    suboptions:
      admin_state:
        description:
        - Whether to enable Rogue EP Control on the fabric.
        type: bool
      interval:
        description:
        - The rogue endpoint detection interval in seconds.
        type: int
      multiplication_factor:
        description:
        - The rogue endpoint detection multiplication factor.
        type: int
      hold_interval:
        description:
        - The rogue endpoint hold interval in seconds.
        type: int
  ep_loop_protection:
    description: Configuration container for EP Loop Protection.
    type: dict
    suboptions:
      admin_state:
        description:
        - Whether to enable EP Loop Protection on the fabric.
        type: bool
      interval:
        description:
        - The loop protection detection interval in seconds.
        type: int
      multiplication_factor:
        description:
        - The loop protection detection multiplication factor.
        type: int
      action:
        description:
        - The action(s) to take when a loop is detected.
        type: list
        elements: str
        choices: [ bd, port ]
  state:
    description:
    - Use C(present) for updating configuration.
    - Use C(query) for showing current configuration.
    type: str
    choices: [ present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(ep:IpAgingP), B(ep:ControlP), and B(ep:LoopProtectP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Set system endpoint controls settings
  cisco.aci.aci_system_endpoint_controls:
    host: apic
    username: admin
    password: SomeSecretPassword
    admin_state: true
    ip_aging:
      admin_state: true
    roque_ep_control:
      admin_state: true
      interval: 50
      multiplication_factor: 10
      hold_interval: 2000
    ep_loop_protection:
      admin_state: true
      interval: 70
      multiplication_factor: 15
      action: [bd, port]
  delegate_to: localhost

- name: Query system endpoint controls settings
  cisco.aci.aci_system_endpoint_controls:
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import EP_LOOP_PROTECTION_ACTION_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        ip_aging=dict(type="dict", options=dict(admin_state=dict(type="bool"))),
        roque_ep_control=dict(
            type="dict",
            options=dict(
                admin_state=dict(type="bool"),
                interval=dict(type="int"),
                multiplication_factor=dict(type="int"),
                hold_interval=dict(type="int"),
            ),
        ),
        ep_loop_protection=dict(
            type="dict",
            options=dict(
                admin_state=dict(type="bool"),
                interval=dict(type="int"),
                multiplication_factor=dict(type="int"),
                action=dict(type="list", elements="str", choices=["bd", "port"]),
            ),
        ),
        state=dict(type="str", default="present", choices=["present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", "present", ["ip_aging", "roque_ep_control", "ep_loop_protection"], True]],
    )

    aci = ACIModule(module)
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="infraInfra",
            aci_rn="infra",
        ),
        child_classes=["epIpAgingP", "epControlP", "epLoopProtectP"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        ip_aging = module.params.get("ip_aging")
        roque_ep_control = module.params.get("roque_ep_control")
        ep_loop_protection = module.params.get("ep_loop_protection")

        if ip_aging:
            child_configs.append(
                {"epIpAgingP": {"attributes": {"name": "default", "adminSt": aci.boolean(ip_aging.get("admin_state"), "enabled", "disabled")}}}
            )

        if roque_ep_control:
            child_configs.append(
                {
                    "epControlP": {
                        "attributes": {
                            "name": "default",
                            "adminSt": aci.boolean(roque_ep_control.get("admin_state"), "enabled", "disabled"),
                            "rogueEpDetectIntvl": roque_ep_control.get("interval"),
                            "rogueEpDetectMult": roque_ep_control.get("multiplication_factor"),
                            "holdIntvl": roque_ep_control.get("hold_interval"),
                        }
                    }
                }
            )

        if ep_loop_protection:
            actions = None
            if ep_loop_protection.get("action"):
                actions = ",".join(sorted([EP_LOOP_PROTECTION_ACTION_MAPPING.get(action) for action in ep_loop_protection.get("action")]))
            child_configs.append(
                {
                    "epLoopProtectP": {
                        "attributes": {
                            "name": "default",
                            "adminSt": aci.boolean(ep_loop_protection.get("admin_state"), "enabled", "disabled"),
                            "loopDetectIntvl": ep_loop_protection.get("interval"),
                            "loopDetectMult": ep_loop_protection.get("multiplication_factor"),
                            "action": actions,
                        }
                    }
                }
            )

        aci.payload(
            aci_class="infraInfra",
            class_config=dict(),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="infraInfra")

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
