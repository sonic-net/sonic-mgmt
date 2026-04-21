#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_qos_dscp_class
short_description: Manage QoS DSCP Class (qos:DscpClass)
description:
- Manage QoS Custom Differentiated Services Code Point (DSCP) Class levels for QoS Custom Policies on Cisco ACI fabrics.
- The class level for DSCP to prioritize the map.
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
    - The APIC defaults to C(level3) when unset during creation.
    type: str
    choices: [ level1, level2, level3, level4, level5, level6, unspecified ]
    aliases: [ prio ]
  dscp_from:
    description:
    - The DSCP range starting value.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
  dscp_to:
    description:
    - The DSCP range ending value.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
  dscp_target:
    description:
    - The DSCP target value.
    - The APIC defaults to C(unspecified) when unset during creation.
    type: str
    choices: [ AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, unspecified ]
    aliases: [ target ]
  target_cos:
    description:
    - The target COS to be driven based on the range of input values of DSCP coming into the fabric.
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
  description: More information about the internal APIC class B(qos:DscpClass).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new QoS DSCP Class
  cisco.aci.aci_qos_dscp_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    qos_custom_policy: my_qos_custom_policy
    priority: level3
    dscp_from: AF11
    dscp_to: AF21
    dscp_target: unspecified
    target_cos: best_effort
    state: present
  delegate_to: localhost

- name: Query a QoS DSCP Class
  cisco.aci.aci_qos_dscp_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    qos_custom_policy: my_qos_custom_policy
    dscp_from: AF11
    dscp_to: AF21
    state: query
  delegate_to: localhost

- name: Query all QoS DSCP Classes in my_qos_custom_policy
  cisco.aci.aci_qos_dscp_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    qos_custom_policy: my_qos_custom_policy
    state: query
  delegate_to: localhost

- name: Query all QoS DSCP Classes
  cisco.aci.aci_qos_dscp_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Delete a QoS DSCP Class
  cisco.aci.aci_qos_dscp_class:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    qos_custom_policy: my_qos_custom_policy
    dscp_from: AF11
    dscp_to: AF21
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
    new_dscp_spec = dict((k, aci_contract_dscp_spec()[k]) for k in aci_contract_dscp_spec() if k != "aliases")
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
        dscp_from=new_dscp_spec,
        dscp_to=new_dscp_spec,
        dscp_target=aci_contract_dscp_spec(),
        target_cos=dict(type="str", choices=list(MATCH_TARGET_COS_MAPPING.keys())),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "qos_custom_policy", "dscp_from", "dscp_to"]],
            ["state", "present", ["tenant", "qos_custom_policy", "dscp_from", "dscp_to"]],
        ],
    )

    tenant = module.params.get("tenant")
    qos_custom_policy = module.params.get("qos_custom_policy")
    priority = module.params.get("priority")
    dscp_from = module.params.get("dscp_from")
    dscp_to = module.params.get("dscp_to")
    dscp_target = module.params.get("dscp_target")
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
            aci_class="qosDscpClass",
            aci_rn="dcsp-{0}-{1}".format(dscp_from, dscp_to),
            module_object=qos_custom_policy,
            target_filter={"from": dscp_from, "to": dscp_to},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="qosDscpClass",
            class_config={
                "prio": priority,
                "from": dscp_from,
                "to": dscp_to,
                "target": dscp_target,
                "targetCos": target_cos,
            },
        )

        aci.get_diff(aci_class="qosDscpClass")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
