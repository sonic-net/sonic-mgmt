#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_cloud_external_epg
short_description: Manage Cloud External EPG (cloud:ExtEPg)
description:
- Configures WAN router connectivity to the cloud infrastructure.
options:
  description:
    description:
    - configuration item description.
    aliases: [ descr ]
    type: str
  name:
    description:
    - Name of Object cloud_external_epg.
    aliases: [ cloud_external_epg, cloud_external_epg_name, external_epg, external_epg_name, extepg, extepg_name ]
    type: str
  route_reachability:
    description:
    - Route reachability for this EPG.
    choices: [ inter-site, internet, unspecified ]
    type: str
  tenant:
    description:
    - The name of tenant.
    type: str
  ap:
    description:
    - The name of the cloud application profile.
    aliases: [ app_profile, app_profile_name ]
    type: str
  vrf:
    description:
    - The name of the VRF.
    type: str
    aliases: [ context, vrf_name ]
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

notes:
- More information about the internal APIC class B(cloud:ExtEPg) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Anvitha Jain (@anvitha-jain)
"""

EXAMPLES = r"""
- name: Add a new cloud external EPG
  cisco.aci.aci_cloud_external_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenant1
    ap: ap1
    vrf: vrf1
    description: Cloud External EPG description
    name: ext_epg
    route_reachability: internet
    state: present
  delegate_to: localhost

- name: Remove a cloud external EPG
  cisco.aci.aci_cloud_external_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    tenant: tenant1
    ap: ap1
    name: ext_epg
    state: absent
  delegate_to: localhost

- name: Query a cloud external EPG
  cisco.aci.aci_cloud_external_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenant1
    ap: ap1
    name: ext_epg
    state: query
  delegate_to: localhost

- name: query all
  cisco.aci.aci_cloud_external_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenant1
    ap: ap1
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
                    "name_alias": "",
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
                    "name_alias": "",
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
        {
            "description": dict(type="str", aliases=["descr"]),
            "name": dict(type="str", aliases=["cloud_external_epg", "cloud_external_epg_name", "external_epg", "external_epg_name", "extepg", "extepg_name"]),
            "route_reachability": dict(type="str", choices=["inter-site", "internet", "unspecified"]),
            "tenant": dict(type="str"),
            "ap": dict(type="str", aliases=["app_profile", "app_profile_name"]),
            "state": dict(type="str", default="present", choices=["absent", "present", "query"]),
            "vrf": dict(type="str", aliases=["context", "vrf_name"]),
        }
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "tenant", "ap"]],
            ["state", "present", ["name", "tenant", "ap"]],
        ],
    )

    description = module.params.get("description")
    name = module.params.get("name")
    route_reachability = module.params.get("route_reachability")
    tenant = module.params.get("tenant")
    ap = module.params.get("ap")
    state = module.params.get("state")
    child_configs = []
    relation_vrf = module.params.get("vrf")

    if relation_vrf:
        child_configs.append({"cloudRsCloudEPgCtx": {"attributes": {"tnFvCtxName": relation_vrf}}})

    aci = ACIModule(module)
    aci.construct_url(
        root_class={
            "aci_class": "fvTenant",
            "aci_rn": "tn-{0}".format(tenant),
            "target_filter": 'eq(fvTenant.name, "{0}")'.format(tenant),
            "module_object": tenant,
        },
        subclass_1={"aci_class": "cloudApp", "aci_rn": "cloudapp-{0}".format(ap), "target_filter": 'eq(cloudApp.name, "{0}")'.format(ap), "module_object": ap},
        subclass_2={
            "aci_class": "cloudExtEPg",
            "aci_rn": "cloudextepg-{0}".format(name),
            "target_filter": 'eq(cloudExtEPg.name, "{0}")'.format(name),
            "module_object": name,
        },
        child_classes=["fvRsCustQosPol", "cloudRsCloudEPgCtx"],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="cloudExtEPg",
            class_config={
                "descr": description,
                "name": name,
                "routeReachability": route_reachability,
            },
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="cloudExtEPg")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
