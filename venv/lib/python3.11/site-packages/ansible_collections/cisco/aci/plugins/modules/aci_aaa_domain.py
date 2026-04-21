#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_aaa_domain
short_description: Manage AAA domains (aaa:Domain)
description:
- Manage AAA domains on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the aaa domain.
    type: str
    aliases: [ aaa_domain ]
  description:
    description:
    - Description of the aaa domain.
    type: str
    aliases: [ descr ]
  restricted_rbac_domain:
    description:
    - C(True) to enable Restricted RBAC Domain on the aaa security domain.
    type: bool
    choices: [ false, true ]
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

seealso:
- module: cisco.aci.aci_aaa_role
- name: Manage AAA roles (aaa:Role)
  description: More information about the AAA roles class B(aaa:Role).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Add an aaa security domain
  cisco.aci.aci_aaa_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: anstest_security_domain
    description: "Anstest Sec Domain Descr"
    state: present
  delegate_to: localhost

- name: Add list of aaa security domain
  cisco.aci.aci_aaa_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: "{{ item.name }}"
    description: "{{ item.description }}"
    state: present
  with_items:
    - name: anstest1
      description: "Anstest Sec Domain Descr 1"
    - name: anstest2
      description: "Anstest Sec Domain Descr 2"
  delegate_to: localhost

- name: Query an aaa security domain with name
  cisco.aci.aci_aaa_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: anstest_security_domain
    state: query
  delegate_to: localhost

- name: Query all aaa security domains
  cisco.aci.aci_aaa_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove an aaa security domain
  cisco.aci.aci_aaa_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: anstest_security_domain
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        name=dict(type="str", aliases=["aaa_domain"]),
        description=dict(type="str", aliases=["descr"]),
        restricted_rbac_domain=dict(type="bool", choices=[False, True]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
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
    restricted_rbac_domain = module.params.get("restricted_rbac_domain")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="aaaDomain",
            aci_rn="userext/domain-{0}".format(name),
            module_object=name,
            target_filter=dict(name=name),
        ),
    )
    aci.get_existing()

    if state == "present":
        restricted_rbac_domain_mapping = {False: "no", True: "yes"}
        restricted_rbac_domain_state = restricted_rbac_domain_mapping.get(restricted_rbac_domain)
        aci.payload(
            aci_class="aaaDomain",
            class_config=dict(
                name=name,
                descr=description,
                restrictedRbacDomain=restricted_rbac_domain_state,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="aaaDomain")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
