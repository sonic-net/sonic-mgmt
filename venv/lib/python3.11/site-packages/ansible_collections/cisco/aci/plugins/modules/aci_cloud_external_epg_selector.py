#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_cloud_external_epg_selector
short_description: Manage Cloud Endpoint Selector for External EPGs (cloud:ExtEPSelector)
description:
- Decides which endpoints belong to the EPGs based on several parameters.
options:
  name:
    description:
    - The name of the Cloud Endpoint selector.
    aliases: [ selector, cloud_external_epg_selector, external_epg_selector, extepg_selector, selector_name ]
    type: str
  subnet:
    description:
    - IP address of the Cloud Subnet.
    aliases: [ ip ]
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
  cloud_external_epg:
    description:
    - Name of Object cloud_external_epg.
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
- More information about the internal APIC class B(cloud:ExtEPSelector) from
  L(the APIC Management Information Model reference,https://developer.cisco.com/docs/apic-mim-ref/).
author:
- Anvitha Jain (@anvitha-jain)
"""

EXAMPLES = r"""
- name: Add a new cloud external EPG selector
  cisco.aci.aci_cloud_external_epg_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenant1
    ap: ap1
    cloud_external_epg: ext_epg
    name: subnet_name
    subnet: 10.0.0.0/16
    state: present
  delegate_to: localhost

- name: Remove a cloud external EPG selector
  cisco.aci.aci_cloud_external_epg_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    tenant: tenant1
    ap: ap1
    cloud_external_epg: ext_epg
    name: subnet_name
    subnet: 10.0.0.0/16
    state: absent
  delegate_to: localhost

- name: Query all cloud external EPG selectors
  cisco.aci.aci_cloud_external_epg_selector:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: tenant1
    ap: ap1
    cloud_external_epg: ext_epg
    state: query
  delegate_to: localhost
"""

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        {
            "name": dict(type="str", aliases=["selector", "cloud_external_epg_selector", "external_epg_selector", "extepg_selector", "selector_name"]),
            "subnet": dict(type="str", aliases=["ip"]),
            "tenant": dict(type="str"),
            "cloud_external_epg": dict(type="str"),
            "ap": dict(type="str", aliases=["app_profile", "app_profile_name"]),
            "state": dict(type="str", default="present", choices=["absent", "present", "query"]),
        }
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["subnet", "tenant", "ap", "cloud_external_epg"]],
            ["state", "present", ["subnet", "tenant", "ap", "cloud_external_epg"]],
        ],
    )

    name = module.params.get("name")
    subnet = module.params.get("subnet")
    tenant = module.params.get("tenant")
    ap = module.params.get("ap")
    cloud_external_epg = module.params.get("cloud_external_epg")
    state = module.params.get("state")
    child_configs = []

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
            "aci_rn": "cloudextepg-{0}".format(cloud_external_epg),
            "target_filter": 'eq(cloudExtEPg.name, "{0}")'.format(cloud_external_epg),
            "module_object": cloud_external_epg,
        },
        subclass_3={
            "aci_class": "cloudExtEPSelector",
            "aci_rn": "extepselector-[{0}]".format(subnet),
            "target_filter": 'eq(cloudExtEPSelector.name, "{0}")'.format(subnet),
            "module_object": subnet,
        },
        child_classes=[],
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="cloudExtEPSelector",
            class_config={
                "name": name,
                "subnet": subnet,
            },
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="cloudExtEPSelector")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
