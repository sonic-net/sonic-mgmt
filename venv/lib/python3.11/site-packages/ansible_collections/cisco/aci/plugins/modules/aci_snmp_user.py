#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Tim Cragg (@timcragg)
# Copyright: (c) 2023, Akini Ross (@akinross)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_snmp_user
short_description: Manage SNMP v3 Users (snmp:UserP)
description:
- Manage SNMP v3 Users.
- Note that all properties within the snmpUserP class are Create-only. To modify any property of an existing user, you must delete and re-create it.
options:
  auth_type:
    description:
    - SNMP authentication method
    type: str
    choices: [ hmac-md5-96, hmac-sha1-96, hmac-sha2-224, hmac-sha2-256, hmac-sha2-384, hmac-sha2-512 ]
  auth_key:
    description:
    - SNMP authentication key
    - Providing this option will always result in a change because it is a secure property that cannot be retrieved from APIC.
    type: str
  name:
    description:
    - Name of the SNMP user policy
    type: str
    aliases: [ snmp_user_policy ]
  description:
    description:
    - Description of the SNMP user policy
    type: str
    aliases: [ descr ]
  policy:
    description:
    - Name of an existing SNMP policy
    type: str
    aliases: [ snmp_policy, snmp_policy_name ]
  privacy_type:
    description:
    - SNMP privacy type
    type: str
    choices: [ aes-128, des, none ]
  privacy_key:
    description:
    - SNMP privacy key
    - Providing this option will always result in a change because it is a secure property that cannot be retrieved from APIC.
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
- The C(policy) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_snmp_policy) module can be used for this.
seealso:
- module: cisco.aci.aci_snmp_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(snmp:UserP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create an SNMP user
  cisco.aci.aci_snmp_user:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    name: my_snmp_user
    auth_type: hmac-sha2-256
    auth_key: "{{ hmac_key }}"
    state: present
  delegate_to: localhost

- name: Create an SNMP user with both authentication and privacy
  cisco.aci.aci_snmp_user:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    name: my_snmp_user
    auth_type: hmac-sha1-96
    auth_key: "{{ hmac_key }}"
    privacy_type: aes-128
    privacy_key: "{{ aes_key }}"
    state: present
  delegate_to: localhost

- name: Remove an SNMP user
  cisco.aci.aci_snmp_user:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    name: my_snmp_user
    state: absent
  delegate_to: localhost

- name: Query an SNMP user
  cisco.aci.aci_snmp_user:
    host: apic
    username: admin
    password: SomeSecretPassword
    policy: my_snmp_policy
    name: my_snmp_user
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all SNMP users
  cisco.aci.aci_snmp_user:
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        policy=dict(type="str", aliases=["snmp_policy", "snmp_policy_name"]),
        name=dict(type="str", aliases=["snmp_user_policy"]),
        description=dict(type="str", aliases=["descr"]),
        auth_type=dict(type="str", choices=["hmac-md5-96", "hmac-sha1-96", "hmac-sha2-224", "hmac-sha2-256", "hmac-sha2-384", "hmac-sha2-512"]),
        auth_key=dict(type="str", no_log=True),
        privacy_type=dict(type="str", choices=["aes-128", "des", "none"]),
        privacy_key=dict(type="str", no_log=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["policy", "name"]],
            ["state", "present", ["policy", "name"]],
        ],
    )

    aci = ACIModule(module)

    policy = module.params.get("policy")
    name = module.params.get("name")
    description = module.params.get("description")
    auth_type = module.params.get("auth_type")
    auth_key = module.params.get("auth_key")
    privacy_type = module.params.get("privacy_type")
    privacy_key = module.params.get("privacy_key")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="snmpPol",
            aci_rn="fabric/snmppol-{0}".format(policy),
            module_object=policy,
            target_filter={"name": policy},
        ),
        subclass_1=dict(
            aci_class="snmpUserP",
            aci_rn="user-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="snmpUserP",
            class_config=dict(privType=privacy_type, privKey=privacy_key, authType=auth_type, authKey=auth_key, name=name, descr=description),
        )

        aci.get_diff(aci_class="snmpUserP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
