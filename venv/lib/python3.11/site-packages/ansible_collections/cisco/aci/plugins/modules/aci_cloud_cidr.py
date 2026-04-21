#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, nkatarmal-crest <nirav.katarmal@crestdatasys.com>
# Copyright: (c) 2020, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_cloud_cidr
short_description: Manage CIDR under Cloud Context Profile (cloud:Cidr)
description:
-  Manage Cloud CIDR on Cisco Cloud ACI.
author:
- Nirav (@nirav)
- Cindy Zhao (@cizhao)
options:
  address:
    description:
    - CIDR ip and its netmask.
    type: str
    aliases: [ cidr ]
  description:
    description:
    - Description of the Cloud CIDR.
    type: str
  name_alias:
    description:
    - An alias for the name of the current object. This relates to the nameAlias field in ACI and is used to rename object without changing the DN.
    type: str
  tenant:
    description:
    - The name of the Tenant.
    type: str
    required: true
  cloud_context_profile:
    description:
    - The name of the Cloud Context Profile.
    type: str
    required: true
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
- This module is only used to manage non_primary Cloud CIDR, see M(cisco.aci.aci_cloud_ctx_profile) to create the primary CIDR.
- More information about the internal APIC class B(cloud:Cidr) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
"""

EXAMPLES = r"""
- name: Create non_primary CIDR
  cisco.aci.aci_cloud_cidr:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    address: 10.10.0.0/16
    cloud_context_profile: ctxProfileName
    state: present
  delegate_to: localhost

- name: Remove non_primary CIDR
  cisco.aci.aci_cloud_cidr:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    address: 10.10.0.0/16
    cloud_context_profile: ctxProfileName
    state: absent
  delegate_to: localhost

- name: Query all CIDRs under given cloud context profile
  cisco.aci.aci_cloud_cidr:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    cloud_context_profile: ctxProfileName
    state: query
  delegate_to: localhost

- name: Query specific CIDR under given cloud context profile
  cisco.aci.aci_cloud_cidr:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenantName
    cloud_context_profile: ctxProfileName
    address: 10.10.0.0/16
    state: query
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

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        address=dict(type="str", aliases=["cidr"]),
        description=dict(type="str"),
        name_alias=dict(type="str"),
        tenant=dict(type="str", required=True),
        cloud_context_profile=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["address"]],
            ["state", "present", ["address"]],
        ],
    )

    address = module.params.get("address")
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")
    tenant = module.params.get("tenant")
    cloud_context_profile = module.params.get("cloud_context_profile")
    state = module.params.get("state")
    child_configs = []

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(aci_class="fvTenant", aci_rn="tn-{0}".format(tenant), target_filter='eq(fvTenant.name, "{0}")'.format(tenant), module_object=tenant),
        subclass_1=dict(
            aci_class="cloudCtxProfile",
            aci_rn="ctxprofile-{0}".format(cloud_context_profile),
            target_filter='eq(cloudCtxProfile.name, "{0}")'.format(cloud_context_profile),
            module_object=cloud_context_profile,
        ),
        subclass_2=dict(
            aci_class="cloudCidr", aci_rn="cidr-[{0}]".format(address), target_filter='eq(cloudCidr.addr, "{0}")'.format(address), module_object=address
        ),
        child_classes=[],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="cloudCidr",
            class_config=dict(
                addr=address,
                descr=description,
                nameAlias=name_alias,
                primary="no",
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="cloudCidr")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
