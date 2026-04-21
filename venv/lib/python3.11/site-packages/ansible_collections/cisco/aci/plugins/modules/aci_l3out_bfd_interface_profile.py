#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Anvitha Jain (@anvjain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_bfd_interface_profile
short_description: Manage L3Out BFD Interface profiles (bfd:IfP)
description:
- Manage L3Out BFD Interface profile configuration on Cisco ACI fabrics
- Only available in APIC version 5.2 or later and for non-cloud APICs
options:
  tenant:
    description:
    - Name of an existing tenant
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - Name of an existing L3Out
    type: str
    aliases: [ l3out_name ]
  l3out_logical_node_profile:
    description:
    - Name of an existing L3Out Logical Node profile
    type: str
    aliases: [ logical_node_profile, logical_node_profile_name ]
  l3out_logical_interface_profile:
    description:
    - Name of an existing L3Out Logical Interface profile
    type: str
    aliases: [ logical_interface_profile, logical_interface_profile_name ]
  name:
    description:
    - Name of the L3Out BFD Interface profile object
    type: str
    aliases: [ bfd_multihop_interface_profile ]
  name_alias:
    description:
    - Name Alias of the L3Out BFD Interface profile object
    type: str
  description:
    description:
    - Description of the L3Out BFD Interface profile object
    type: str
    aliases: [ descr ]
  authentication_type:
    description:
    - Authentication Type of the L3Out BFD Interface profile object
    - APIC sets the default value to none
    type: str
    choices: [ none, sha1 ]
  key:
    description:
    - Authentication Key of the L3Out BFD Interface profile object
    - Providing this option will always result in a change because it is a secure property that cannot be retrieved from APIC.
    type: str
  key_id:
    description:
    - Authentication Key ID of the L3Out BFD Interface profile object
    - APIC sets the default value to 3
    - Allowed range is 1-255
    type: int
  bfd_interface_policy:
    description:
    - The name of the Interface policy
    type: str
    aliases: [ interface_policy, interface_policy_name ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant), c(l3out), C(l3out_logical_node_profile) and C(l3out_logical_interface_profile) must exist before using this module in your playbook
  The M(cisco.aci.aci_tenant) modules can be used for this
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(bfd:IfP)
  link: https://developer.cisco.com/docs/apic-mim-ref/
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- module: cisco.aci.aci_l3out_logical_interface_profile
- module: cisco.aci.aci_interface_policy_bfd
author:
- Anvitha Jain (@anvjain)
"""

EXAMPLES = r"""
- name: Add a new L3Out BFD Interface Profile
  cisco.aci.aci_l3out_bfd_interface_profile:
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
    l3out: ansible_l3out
    l3out_logical_node_profile: ansible_node_profile
    l3out_logical_interface_profile: ansible_interface_profile
    state: present
  delegate_to: localhost

- name: Query a new L3Out BFD Interface Profile
  cisco.aci.aci_l3out_bfd_interface_profile:
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
    l3out: ansible_l3out
    l3out_logical_node_profile: ansible_node_profile
    l3out_logical_interface_profile: ansible_interface_profile
    state: query
  delegate_to: localhost

- name: Query all L3Out BFD Interface Profile
  cisco.aci.aci_l3out_bfd_interface_profile:
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Delete L3Out BFD Interface Profile
  cisco.aci.aci_l3out_bfd_interface_profile:
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
    l3out: ansible_l3out
    l3out_logical_node_profile: ansible_node_profile
    l3out_logical_interface_profile: ansible_interface_profile
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
     sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class "/></imdata>'
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        l3out=dict(type="str", aliases=["l3out_name"]),
        l3out_logical_node_profile=dict(type="str", aliases=["logical_node_profile_name", "logical_node_profile"]),
        l3out_logical_interface_profile=dict(type="str", aliases=["logical_interface_profile_name", "logical_interface_profile"]),
        name=dict(type="str", aliases=["bfd_multihop_interface_profile"]),
        name_alias=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        authentication_type=dict(type="str", choices=["none", "sha1"]),
        key=dict(type="str", no_log=True),
        key_id=dict(type="int"),
        bfd_interface_policy=dict(type="str", aliases=["interface_policy", "interface_policy_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l3out", "l3out_logical_node_profile", "l3out_logical_interface_profile"]],
            ["state", "present", ["tenant", "l3out", "l3out_logical_node_profile", "l3out_logical_interface_profile", "bfd_interface_policy"]],
            ["authentication_type", "sha1", ["key"]],
        ],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    l3out_logical_node_profile = module.params.get("l3out_logical_node_profile")
    l3out_logical_interface_profile = module.params.get("l3out_logical_interface_profile")
    name = module.params.get("name")
    name_alias = module.params.get("name_alias")
    description = module.params.get("description")
    authentication_type = module.params.get("authentication_type")
    key = module.params.get("key")
    key_id = module.params.get("key_id")
    bfd_interface_policy = module.params.get("bfd_interface_policy")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="l3extOut",
            aci_rn="out-{0}".format(l3out),
            module_object=l3out,
            target_filter={"name": l3out},
        ),
        subclass_2=dict(
            aci_class="l3extLNodeP",
            aci_rn="lnodep-{0}".format(l3out_logical_node_profile),
            module_object=l3out_logical_node_profile,
            target_filter={"name": l3out_logical_node_profile},
        ),
        subclass_3=dict(
            aci_class="l3extLIfP",
            aci_rn="lifp-{0}".format(l3out_logical_interface_profile),
            module_object=l3out_logical_interface_profile,
            target_filter={"name": l3out_logical_interface_profile},
        ),
        subclass_4=dict(
            aci_class="bfdIfP",
            aci_rn="bfdIfP",
            module_object="bfdIfP",
            target_filter={"name": name},
        ),
        child_classes=["bfdRsIfPol"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        class_config = dict(
            name=name,
            nameAlias=name_alias,
            descr=description,
            key=key,
            type=authentication_type,
        )

        if key_id and key_id not in range(1, 255):
            module.fail_json(msg='The "key_id" must be a value between 1 and 255')
        else:
            class_config["keyId"] = key_id

        if bfd_interface_policy is not None:
            child_configs.append(dict(bfdRsIfPol=dict(attributes=dict(tnBfdIfPolName=bfd_interface_policy))))

        aci.payload(
            aci_class="bfdIfP",
            class_config=class_config,
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="bfdIfP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
