#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Cindy Zhao <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_cloud_vpn_gateway
short_description:  Manage cloudRouterP in Cloud Context Profile (cloud:RouterP)
description:
- Manage cloudRouterP objects on Cisco Cloud ACI.
notes:
- More information about the internal APIC class B(cloud:RouterP) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Cindy Zhao (@cizhao)
options:
  tenant:
    description:
    - The name of tenant.
    type: str
    required: true
  cloud_context_profile:
    description:
    - The name of cloud context profile.
    type: str
    required: true
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    choices: [ absent, present, query ]
    type: str
    default: query
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner
"""

EXAMPLES = r"""
- name: Enable VpnGateway
  cisco.aci.aci_cloud_vpn_gateway:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    cloud_context_profile: ctx_profile_1
    state: present
  delegate_to: localhost

- name: Disable VpnGateway
  cisco.aci.aci_cloud_vpn_gateway:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    cloud_context_profile: ctx_profile_1
    state: absent
  delegate_to: localhost

- name: Query VpnGateway
  cisco.aci.aci_cloud_vpn_gateway:
    host: apic_host
    username: admin
    password: SomeSecretPassword
    tenant: ansible_test
    cloud_context_profile: ctx_profile_1
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
        tenant=dict(type="str", required=True),
        cloud_context_profile=dict(type="str", required=True),
        state=dict(type="str", default="query", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

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
        subclass_2=dict(aci_class="cloudRouterP", aci_rn="routerp-default", target_filter='eq(cloudRouterP.name, "default")', module_object="default"),
        child_classes=["cloudRsToVpnGwPol", "cloudRsToHostRouterPol", "cloudIntNetworkP"],
    )

    aci.get_existing()

    if state == "present":
        child_configs.append(dict(cloudIntNetworkP=dict(attributes=dict(name="default"))))
        aci.payload(aci_class="cloudRouterP", class_config=dict(name="default"), child_configs=child_configs)

        aci.get_diff(aci_class="cloudRouterP")
        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
