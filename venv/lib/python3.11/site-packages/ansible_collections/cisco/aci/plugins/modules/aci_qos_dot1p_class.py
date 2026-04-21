#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_qos_dot1p_class
short_description: Manage QoS Dot1P Class (qos:Dot1PClass)
description:
- Manage Dot1P Class levels for QoS Custom Policies on Cisco ACI fabrics.
- The class level for Dot1P to prioritize the map.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  qos_custom_policy:
    description:
    - The name of the QoS Custom Policy.
    type: str
    aliases: [ qos_custom_policy_name ]
  priority:
    description:
    - The desired QoS class level to be used.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
    aliases: [ prio ]
  dot1p_from:
    description:
    - The Dot1P range starting value.
    type: str
    choices: [ background, best_effort, excellent_effort, critical_applications, video, voice, internetwork_control, network_control, unspecified ]
  dot1p_to:
    description:
    - The Dot1P range ending value.
    type: str
    choices: [ background, best_effort, excellent_effort, critical_applications, video, voice, internetwork_control, network_control, unspecified ]
  dot1p_target:
    description:
    - The Dot1P target value.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target ]
  target_cos:
    description:
    - The target COS to be driven based on the range of input values of Dot1P coming into the fabric.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ background, best_effort, excellent_effort, critical_applications, video, voice, internetwork_control, network_control, unspecified ]
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
- The I(tenant) and I(qos_custom_policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and the M(cisco.aci.aci_qos_custom_policy) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_qos_custom_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(qos:Dot1PClass).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new QoS dot1P Class
  cisco.aci.aci_qos_dot1p_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    qos_custom_policy: my_qos_custom_policy
    priority: level3
    dot1p_from: best_effort
    dot1p_to: excellent_effort
    dot1p_target: unspecified
    target_cos: unspecified
    state: present
  delegate_to: localhost

- name: Query a QoS dot1P Class
  cisco.aci.aci_qos_dot1p_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    qos_custom_policy: my_qos_custom_policy
    dot1p_from: best_effort
    dot1p_to: excellent_effort
    state: query
  delegate_to: localhost

- name: Query all QoS dot1P Classes in my_qos_custom_policy
  cisco.aci.aci_qos_dot1p_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    qos_custom_policy: my_qos_custom_policy
    state: query
  delegate_to: localhost

- name: Query all QoS dot1P Classes
  cisco.aci.aci_qos_dot1p_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Delete a QoS dot1P Class
  cisco.aci.aci_qos_dot1p_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    qos_custom_policy: my_qos_custom_policy
    dot1p_from: best_effort
    dot1p_to: excellent_effort
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    aci_owner_spec,
    aci_contract_dscp_spec,
)
from ansible_collections.cisco.aci.plugins.module_utils.constants import MATCH_TARGET_COS_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        qos_custom_policy=dict(type="str", aliases=["qos_custom_policy_name"]),
        priority=dict(
            type="str",
            choices=[
                "level1",
                "level2",
                "level3",
                "level4",
                "level5",
                "level6",
                "unspecified",
            ],
            aliases=["prio"],
        ),
        dot1p_from=dict(type="str", choices=list(MATCH_TARGET_COS_MAPPING.keys())),
        dot1p_to=dict(type="str", choices=list(MATCH_TARGET_COS_MAPPING.keys())),
        dot1p_target=aci_contract_dscp_spec(),
        target_cos=dict(type="str", choices=list(MATCH_TARGET_COS_MAPPING.keys())),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "qos_custom_policy", "dot1p_from", "dot1p_to"]],
            ["state", "present", ["tenant", "qos_custom_policy", "dot1p_from", "dot1p_to"]],
        ],
    )

    tenant = module.params.get("tenant")
    qos_custom_policy = module.params.get("qos_custom_policy")
    priority = module.params.get("priority")
    dot1p_from = MATCH_TARGET_COS_MAPPING.get(module.params.get("dot1p_from"))
    dot1p_to = MATCH_TARGET_COS_MAPPING.get(module.params.get("dot1p_to"))
    dot1p_target = module.params.get("dot1p_target")
    target_cos = MATCH_TARGET_COS_MAPPING.get(module.params.get("target_cos"))
    state = module.params.get("state")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="qosCustomPol",
            aci_rn="qoscustom-{0}".format(qos_custom_policy),
            module_object=qos_custom_policy,
            target_filter={"name": qos_custom_policy},
        ),
        subclass_2=dict(
            aci_class="qosDot1PClass",
            aci_rn="dot1P-{0}-{1}".format(dot1p_from, dot1p_to),
            module_object=qos_custom_policy,
            target_filter={"from": dot1p_from, "to": dot1p_to},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="qosDot1PClass",
            class_config={
                "prio": priority,
                "from": dot1p_from,
                "to": dot1p_to,
                "target": dot1p_target,
                "targetCos": target_cos,
            },
        )

        aci.get_diff(aci_class="qosDot1PClass")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
