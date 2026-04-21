#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Akini Ross (@akinross)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: aci_interface_policy_port_channel_member
version_added: "2.12.0"
short_description: Manage Port Channel Member interface policies (lacp:IfPol)
description:
- Manage Port Channel Member interface policy configuration on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Port Channel Member interface policy.
    type: str
    aliases: [ port_channel_member_interface_policy ]
  description:
    description:
    - The description of the Port Channel Member interface policy.
    type: str
  priority:
    description:
    - The priority of the Port Channel Member interface policy.
    - The APIC defaults to C(32768) when not provided.
    - Accepted values range between C(1) and C(65535).
    type: int
  transmit_rate:
    description:
    - The transmit rate of the Port Channel Member interface policy.
    - The APIC defaults to C(normal) when not provided.
    type: str
    choices: [ normal, fast ]
  name_alias:
    description:
    - The alias for the current object.
    - This relates to the nameAlias field in ACI.
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
  description: More information about the internal APIC class B(lacp:IfPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new Port Channel Member interface policy
  cisco.aci.aci_interface_policy_port_channel_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ansible_port_channel_member_policy
    description: Ansible Port Channel Member interface policy
    priority: 32700
    transmit_rate: fast
    state: present
  delegate_to: localhost

- name: Query a Port Channel Member interface policy
  cisco.aci.aci_interface_policy_port_channel_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: ansible_port_channel_member_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Port Channel Member interface policies
  cisco.aci.aci_interface_policy_port_channel_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Port Channel Member interface policy
  cisco.aci.aci_interface_policy_port_channel_member:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_ntp_policy
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
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["port_channel_member_interface_policy"]),
        description=dict(type="str"),
        priority=dict(type="int"),
        transmit_rate=dict(type="str", choices=["normal", "fast"]),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    name = module.params.get("name")
    description = module.params.get("description")
    priority = module.params.get("priority")
    transmit_rate = module.params.get("transmit_rate")
    name_alias = module.params.get("name_alias")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="lacpIfPol",
            aci_rn="infra/lacpifp-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="lacpIfPol",
            class_config=dict(
                name=name,
                descr=description,
                prio=priority,
                txRate=transmit_rate,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="lacpIfPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
