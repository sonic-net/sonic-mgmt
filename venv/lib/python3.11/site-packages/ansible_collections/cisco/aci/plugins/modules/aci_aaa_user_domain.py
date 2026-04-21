#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Tim Cragg (@timcragg)
# Copyright: (c) 2022, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_aaa_user_domain
short_description: Manage AAA user domains (aaa:UserDomain)
description:
- Manage AAA user domain configuration on Cisco ACI fabrics.
options:
  aaa_user:
    description:
    - The name of an existing AAA user
    type: str
    aliases: [ user_name ]
  aaa_user_type:
    description:
    - Whether this is a normal user or an appuser.
    type: str
    choices: [ appuser, user ]
    default: user
  name:
    description:
    - The name of the user domain
    type: str
    aliases: [ domain_name, user_domain ]
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
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

notes:
- The C(aaa_user) must exist before using this module in your playbook.
  The M(cisco.aci.aci_aaa_user) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(aaaUserDomain).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Add a security domain to a aaa_user
  cisco.aci.aci_aaa_user_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    name: my_domain
    state: present
  delegate_to: localhost

- name: Remove a security domain from a aaa_user
  cisco.aci.aci_aaa_user_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    name: my_domain
    state: absent
  delegate_to: localhost

- name: Add list of security domains to a aaa_user
  cisco.aci.aci_aaa_user_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    name: "{{ item.name }}"
    state: present
  with_items:
    - name: common
    - name: all
    - name: mgmt
  delegate_to: localhost

- name: Query a security domain from a aaa_user
  cisco.aci.aci_aaa_user_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    name: my_domain
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all security domains of a aaa_user
  cisco.aci.aci_aaa_user_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    state: query
  delegate_to: localhost
  register: query_results

- name: Query all security domains to user associations
  cisco.aci.aci_aaa_user_domain:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_all_domains
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

ACI_MAPPING = dict(
    appuser=dict(
        aci_class="aaaAppUser",
        aci_mo="userext/appuser-",
    ),
    user=dict(
        aci_class="aaaUser",
        aci_mo="userext/user-",
    ),
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        aaa_user=dict(type="str", aliases=["user_name"]),
        name=dict(type="str", aliases=["domain_name", "user_domain"]),
        aaa_user_type=dict(type="str", default="user", choices=["appuser", "user"]),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["aaa_user", "name"]],
            ["state", "present", ["aaa_user", "name"]],
        ],
    )

    aaa_user = module.params.get("aaa_user")
    name = module.params.get("name")
    aaa_user_type = module.params.get("aaa_user_type")
    name_alias = module.params.get("name_alias")
    state = module.params.get("state")

    child_classes = ["aaaUserRole"]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class=ACI_MAPPING.get(aaa_user_type).get("aci_class"),
            aci_rn="{0}{1}".format(ACI_MAPPING.get(aaa_user_type).get("aci_mo"), aaa_user),
            module_object=aaa_user,
            target_filter={"name": aaa_user},
        ),
        subclass_1=dict(
            aci_class="aaaUserDomain",
            aci_rn="userdomain-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=child_classes,
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="aaaUserDomain",
            class_config=dict(
                name=name,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="aaaUserDomain")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
