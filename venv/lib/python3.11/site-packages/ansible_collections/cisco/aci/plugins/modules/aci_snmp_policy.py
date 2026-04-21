#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_snmp_policy
short_description: Manage Syslog groups (snmp:Pol)
description:
- Manage syslog policies.
options:
  admin_state:
    description:
    - Administrative State of the policy
    type: str
    choices: [ enabled, disabled ]
  contact:
    description:
    - SNMP contact
    type: str
  description:
    description:
    - Description of the SNMP policy
    type: str
  location:
    description:
    - SNMP location
    type: str
  name:
    description:
    - Name of the SNMP policy
    type: str
    aliases: [ snmp_policy, snmp_policy_name ]
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
  description: More information about the internal APIC classes B(snmp:Pol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Create an SNMP policy and Set Admin State to Enable
  cisco.aci.aci_snmp_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    admin_state: enabled
    name: my_snmp_policy
    state: present
  delegate_to: localhost

- name: Remove an SNMP policy
  cisco.aci.aci_snmp_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_snmp_policy
    state: absent
  delegate_to: localhost

- name: Query an SNMP policy
  cisco.aci.aci_snmp_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_snmp_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all SNMP policies
  cisco.aci.aci_snmp_policy:
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["snmp_policy", "snmp_policy_name"]),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        contact=dict(type="str"),
        description=dict(type="str"),
        location=dict(type="str"),
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

    aci = ACIModule(module)

    name = module.params.get("name")
    admin_state = module.params.get("admin_state")
    contact = module.params.get("contact")
    description = module.params.get("description")
    location = module.params.get("location")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="snmpPol",
            aci_rn="fabric/snmppol-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=["snmpCommunityP", "snmpClientGrpP"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="snmpPol",
            class_config=dict(name=name, adminSt=admin_state, contact=contact, descr=description, loc=location),
        )

        aci.get_diff(aci_class="snmpPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
