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
module: aci_aaa_user_role
short_description: Manage AAA user roles (aaa:UserRole)
description:
- Manage AAA User Role configuration on Cisco ACI fabrics.
options:
  aaa_user:
    description:
    - The name of the existing user to add roles and privileges
    type: str
    aliases: [ user_name ]
  aaa_user_type:
    description:
    - Whether this is a normal user or an appuser.
    type: str
    choices: [ appuser, user ]
    default: user
  domain_name:
    description:
    - The name of the security domain
    type: str
    aliases: [ user_domain ]
  name:
    description:
    - Name of the AAA role
    type: str
    aliases: [ role_name, user_role ]
  privilege_type:
    description:
    - Privilege for the role
    type: str
    aliases: [ priv_type ]
    choices: [ read, write ]
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
- The C(aaa_user) and C(domain_name) must exist before using this module in your playbook.
  The M(cisco.aci.aci_aaa_user) and M(cisco.aci.aci_aaa_user_domain) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(aaaUserRole).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Add a user role to a user security domain
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    domain_name: my_domain
    name: my_role
    privilege_type: read
    state: present
  delegate_to: localhost

- name: Add list of user roles to a user domain
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    domain_name: my_domain
    name: "{{ item.name }}"
    privilege_type: "{{ item.privilege_type }}"
    state: present
  with_items:
    - name: aaa
      privilege_type: write
    - name: access-admin
      privilege_type: write
    - name: ops
      privilege_type: write
  delegate_to: localhost

- name: Query a user role from a user security domain
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    domain_name: my_domain
    name: my_role
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all user roles from a user security domain
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    domain_name: my_domain
    state: query
  delegate_to: localhost
  register: query_results

- name: Query all user roles from a user
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    state: query
  delegate_to: localhost
  register: query_all_roles_of_user

- name: Query all user roles
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_all_user_roles

- name: Remove user role from a user domain
  cisco.aci.aci_aaa_user_role:
    host: apic
    username: admin
    password: SomeSecretPassword
    aaa_user: my_user
    domain_name: my_domain
    name: my_role
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

PRIV_TYPE_MAPPING = {
    "read": "readPriv",
    "write": "writePriv",
}


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        aaa_user=dict(type="str", aliases=["user_name"]),
        aaa_user_type=dict(type="str", default="user", choices=["appuser", "user"]),
        domain_name=dict(type="str", aliases=["user_domain"]),
        name=dict(type="str", aliases=["role_name", "user_role"]),
        privilege_type=dict(type="str", aliases=["priv_type"], choices=["read", "write"]),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["aaa_user", "domain_name", "name"]],
            ["state", "present", ["aaa_user", "domain_name", "name"]],
        ],
    )

    aaa_user = module.params.get("aaa_user")
    aaa_user_type = module.params.get("aaa_user_type")
    domain_name = module.params.get("domain_name")
    name = module.params.get("name")
    privilege_type = module.params.get("privilege_type")
    name_alias = module.params.get("name_alias")
    state = module.params.get("state")

    if privilege_type is not None:
        privilege_type = PRIV_TYPE_MAPPING[privilege_type]

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
            aci_rn="userdomain-{0}".format(domain_name),
            module_object=domain_name,
            target_filter={"name": domain_name},
        ),
        subclass_2=dict(
            aci_class="aaaUserRole",
            aci_rn="role-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="aaaUserRole",
            class_config=dict(
                name=name,
                privType=privilege_type,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="aaaUserRole")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
