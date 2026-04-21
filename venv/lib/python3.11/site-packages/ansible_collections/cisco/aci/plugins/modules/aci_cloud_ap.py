#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, nkatarmal-crest (@nirav.katarmal)
# Copyright: (c) 2021, Cindy Zhao (@cizhao)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_cloud_ap
short_description: Manage Cloud Application Profile (AP) (cloud:App)
description:
- Manage Cloud Application Profile (AP) objects on Cisco Cloud ACI
options:
  description:
    description:
    - Description for the cloud application profile.
    aliases: [ descr ]
    type: str
  name:
    description:
    - The name of the cloud application profile.
    aliases: [ app_profile, app_profile_name, ap ]
    type: str
  tenant:
    description:
    - The name of an existing tenant.
    aliases: [ tenant_name ]
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    default: present
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- More information about the internal APIC class B(cloud:App) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Nirav (@nirav)
- Cindy Zhao (@cizhao)
"""

EXAMPLES = r"""
- name: Add a new cloud AP
  cisco.aci.aci_cloud_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    name: intranet
    description: Web Intranet EPG
    state: present
  delegate_to: localhost

- name: Remove a cloud AP
  cisco.aci.aci_cloud_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    tenant: production
    name: intranet
    state: absent
  delegate_to: localhost

- name: Query a cloud AP
  cisco.aci.aci_cloud_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: production
    name: ticketing
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all cloud APs
  cisco.aci.aci_cloud_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all cloud APs with a Specific Name
  cisco.aci.aci_cloud_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    name: ticketing
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all cloud APs of a tenant
  cisco.aci.aci_cloud_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    tenant: production
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
        description=dict(type="str", aliases=["descr"]),
        name=dict(type="str", aliases=["app_profile", "app_profile_name", "ap"]),
        tenant=dict(type="str", aliases=["tenant_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            [
                "state",
                "absent",
                [
                    "name",
                    "tenant",
                ],
            ],
            [
                "state",
                "present",
                [
                    "name",
                    "tenant",
                ],
            ],
        ],
    )

    description = module.params["description"]
    name = module.params["name"]
    tenant = module.params["tenant"]
    state = module.params["state"]
    child_configs = []

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            target_filter={"name": tenant},
            module_object=tenant,
        ),
        subclass_1=dict(
            aci_class="cloudApp",
            aci_rn="cloudapp-{0}".format(name),
            target_filter={"name": name},
            module_object=name,
        ),
        child_classes=[],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="cloudApp",
            class_config=dict(
                descr=description,
                name=name,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="cloudApp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
