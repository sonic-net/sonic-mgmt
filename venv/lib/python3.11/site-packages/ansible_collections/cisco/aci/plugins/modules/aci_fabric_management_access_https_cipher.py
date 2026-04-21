#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_management_access_https_cipher
short_description: Manage Fabric Management Access HTTPS SSL Cipher Configuration (comm:Cipher)
description:
- Manage Fabric Management Access HTTPS SSL Cipher Configuration on Cisco ACI fabrics.
options:
  fabric_management_access_policy_name:
    description:
    - The name of the Fabric Management Access policy.
    type: str
    aliases: [ name ]
  id:
    description:
    - The ID of the SSL Cipher Configuration.
    type: str
  cipher_state:
    description:
    - The state of the SSL Cipher Configuration.
    type: str
    choices: [ enabled, disabled ]
  name_alias:
    description:
    - The name alias of the Fabric Management Access HTTPS SSL Cipher Configuration.
    - This relates to the nameAlias property in ACI.
    type: str
  state:
    description:
    - Use C(present) for updating configuration.
    - Use C(query) for showing current configuration.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The C(fabric_management_access_policy_name) must exist before using this module in your playbook.
  The M(cisco.aci.aci_fabric_management_access) module can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(comm:Cipher).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create a Fabric Management Access HTTPS SSL Cipher
  cisco.aci.aci_fabric_management_access_https_cipher:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_management_access_policy_name: fabric_management_access_policy_1
    id: DHE-RSA-AES128-SHA
    cipher_state: enabled
    state: present
  delegate_to: localhost

- name: Query a Fabric Management Access HTTPS SSL Cipher
  cisco.aci.aci_fabric_management_access_https_cipher:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_management_access_policy_name: fabric_management_access_policy_1
    id: DHE-RSA-AES128-SHA
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Fabric Management Access policies
  cisco.aci.aci_fabric_management_access_https_cipher:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Fabric Management Access HTTPS SSL Cipher
  cisco.aci.aci_fabric_management_access_https_cipher:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_management_access_policy_name: fabric_management_access_policy_1
    id: DHE-RSA-AES128-SHA
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        fabric_management_access_policy_name=dict(type="str", aliases=["name"]),  # Not required for querying all objects
        id=dict(type="str"),
        cipher_state=dict(type="str", choices=["enabled", "disabled"]),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["fabric_management_access_policy_name", "id", "cipher_state"]],
            ["state", "absent", ["fabric_management_access_policy_name", "id"]],
        ],
    )

    aci = ACIModule(module)
    aci_class = "commCipher"

    fabric_management_access_policy_name = module.params.get("fabric_management_access_policy_name")
    id_value = module.params.get("id")
    cipher_state = module.params.get("cipher_state")
    name_alias = module.params.get("name_alias")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class=aci_class,
            aci_rn="fabric/comm-{0}".format(fabric_management_access_policy_name),
            module_object=fabric_management_access_policy_name,
            target_filter={"name": fabric_management_access_policy_name},
        ),
        subclass_1=dict(
            aci_class=aci_class,
            aci_rn="https/cph-{0}".format(id_value),
            module_object=id_value,
            target_filter={"id": id_value},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class=aci_class,
            class_config=dict(
                id=id_value,
                state=cipher_state,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
