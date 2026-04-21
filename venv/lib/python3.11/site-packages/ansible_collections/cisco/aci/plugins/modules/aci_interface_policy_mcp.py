#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_mcp
short_description: Manage MCP interface policies (mcp:IfPol)
description:
- Manage MCP interface policies on Cisco ACI fabrics.
options:
  mcp:
    description:
    - The name of the MCP interface.
    type: str
    aliases: [ mcp_interface, name ]
  description:
    description:
    - The description of the MCP interface.
    type: str
    aliases: [ descr ]
  admin_state:
    description:
    - Enable or disable admin state.
    - The APIC defaults to C(true) when unset during creation.
    type: bool
  mcp_mode:
    description:
    - Instance MCP mode
    - The APIC defaults to C(non_strict) when unset during creation.
    type: str
    choices: [ non_strict, strict ]
  grace_period:
    description:
    - For strict mode, grace period timeout in sec during which early loop detection takes place.
    type: int
    aliases: [ gracePeriod ]
  grace_period_millisec:
    description:
    - For strict mode, grace period timeout in millisec during which early loop detection takes place
    type: int
    aliases: [ grace_period_msec, gracePeriodMsec ]
  init_delay_time:
    description:
    - For strict mode, delay time in seconds for mcp to wait before sending BPDUs.
    - This gives time for STP on the external network to converge.
    type: int
    aliases: [ strict_init_delay_time, strictInitDelayTime ]
  tx_frequence:
    description:
    - For strict mode, transmission frequency of MCP packets until grace period on each L2 interface in seconds.
    type: int
    aliases: [ strict_tx_freq, strictTxFreq ]
  tx_frequence_millisec:
    description:
    - For strict mode, transmission frequency of MCP packets until grace period on each L2 interface in milliseconds
    type: int
    aliases: [strict_tx_freq_msec, strictTxFreqMsec ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(mcp:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Dag Wieers (@dagwieers)
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a MCP interface policy
  cisco.aci.aci_interface_policy_mcp:
    host: apic
    username: admin
    password: SomeSecretPassword
    mcp: MCP_OFF
    admin_state: false
    state: present
  delegate_to: localhost

- name: Delete a MCP interface policy
  cisco.aci.aci_interface_policy_mcp:
    host: apic
    username: admin
    password: SomeSecretPassword
    mcp: MCP_OFF
    state: absent
  delegate_to: localhost

- name: Query all MCP interface policies
  cisco.aci.aci_interface_policy_mcp:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific MCP interface policy
  cisco.aci.aci_interface_policy_mcp:
    host: apic
    username: admin
    password: SomeSecretPassword
    mcp: MCP_OFF
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


MATCH_MCP_MODE_MAPPING = {"non_strict": "off", "strict": "on"}


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        mcp=dict(type="str", aliases=["mcp_interface", "name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        admin_state=dict(type="bool"),
        mcp_mode=dict(type="str", choices=list(MATCH_MCP_MODE_MAPPING.keys())),
        grace_period=dict(type="int", aliases=["gracePeriod"]),
        grace_period_millisec=dict(type="int", aliases=["grace_period_msec", "gracePeriodMsec"]),
        init_delay_time=dict(type="int", aliases=["strict_init_delay_time", "strictInitDelayTime"]),
        tx_frequence=dict(type="int", aliases=["strict_tx_freq", "strictTxFreq"]),
        tx_frequence_millisec=dict(type="int", aliases=["strict_tx_freq_msec", "strictTxFreqMsec"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["mcp"]],
            ["state", "present", ["mcp"]],
        ],
    )

    aci = ACIModule(module)

    mcp = module.params.get("mcp")
    description = module.params.get("description")
    admin_state = aci.boolean(module.params.get("admin_state"), "enabled", "disabled")
    mcp_mode = MATCH_MCP_MODE_MAPPING.get(module.params.get("mcp_mode"))
    grace_period = module.params.get("grace_period")
    grace_period_millisec = module.params.get("grace_period_millisec")
    init_delay_time = module.params.get("init_delay_time")
    tx_frequence = module.params.get("tx_frequence")
    tx_frequence_millisec = module.params.get("tx_frequence_millisec")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci.construct_url(
        root_class=dict(
            aci_class="mcpIfPol",
            aci_rn="infra/mcpIfP-{0}".format(mcp),
            module_object=mcp,
            target_filter={"name": mcp},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="mcpIfPol",
            class_config=dict(
                name=mcp,
                descr=description,
                adminSt=admin_state,
                mcpMode=mcp_mode,
                gracePeriod=grace_period,
                gracePeriodMsec=grace_period_millisec,
                strictInitDelayTime=init_delay_time,
                strictTxFreq=tx_frequence,
                strictTxFreqMsec=tx_frequence_millisec,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="mcpIfPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
