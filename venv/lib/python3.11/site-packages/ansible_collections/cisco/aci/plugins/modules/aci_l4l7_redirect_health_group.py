#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Tim Cragg (@timcragg)
# Copyright: (c) 2025, Shreyas Srish (@shrsr)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l4l7_redirect_health_group
version_added: "2.12.0"
short_description: Manage L4-L7 Redirect Health Groups (vns:RedirectHealthGroup)
description:
- Manage L4-L7 Redirect Health Groups.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  health_group:
    description:
    - The name of the Health Group.
    type: str
    aliases: [ name ]
  description:
    description:
    - The description of the Health Group.
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
- The I(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(vns:RedirectHealthGroup)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Shreyas Srish (@shrsr)
"""

EXAMPLES = r"""
- name: Add a new Redirect Health Group
  cisco.aci.aci_l4l7_redirect_health_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    health_group: my_health_group
    state: present
  delegate_to: localhost

- name: Delete a Redirect Health Group
  cisco.aci.aci_l4l7_redirect_health_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    health_group: my_health_group
    state: absent
  delegate_to: localhost

- name: Query a Redirect Health Group
  cisco.aci.aci_l4l7_redirect_health_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    health_group: my_health_group
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Redirect Health Groups
  cisco.aci.aci_l4l7_redirect_health_group:
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


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        health_group=dict(type="str", aliases=["name"]),
        description=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "health_group"]],
            ["state", "present", ["tenant", "health_group"]],
        ],
    )

    tenant = module.params.get("tenant")
    state = module.params.get("state")
    health_group = module.params.get("health_group")
    description = module.params.get("description")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="vnsRedirectHealthGroup",
            aci_rn="svcCont/redirectHealthGroup-{0}".format(health_group),
            module_object=health_group,
            target_filter={"name": health_group},
        ),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="vnsRedirectHealthGroup",
            class_config=dict(
                name=health_group,
                descr=description,
            ),
        )
        aci.get_diff(aci_class="vnsRedirectHealthGroup")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
