#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Anvitha Jain (@anvjain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_interface_policy_bfd_multihop
short_description: Manage BFD Multihop Interface policies (bfd:MhIfPol)
description:
- Manage BFD Multihop Interface policy configuration on Cisco ACI fabrics
- Only available in APIC version 5.2 or later
options:
  tenant:
    description:
    - Name of an existing tenant
    type: str
  name:
    description:
    - Name of the BFD Multihop Interface policy
    type: str
    aliases: [ bfd_multihop_interface_policy ]
  description:
    description:
    - Description of the BFD Multihop Interface policy
    type: str
  admin_state:
    description:
    - Admin state of the BFD Multihop Interface policy
    - APIC sets the default value to enabled.
    type: str
    choices: [ enabled, disabled ]
  detection_multiplier:
    description:
    - Detection multiplier of the BFD Multihop Interface policy
    - APIC sets the default value to 3.
    - Allowed range is 1-50.
    type: int
  min_transmit_interval:
    description:
    - Minimum transmit (Tx) interval of the BFD Multihop Interface policy
    - APIC sets the default value to 250
    - Allowed range is 250-999
    type: int
  min_receive_interval:
    description:
    - Minimum receive (Rx) interval of the BFD Multihop Interface policy
    - APIC sets the default value to 250
    - Allowed range is 250-999
    type: int
  state:
    description:
    - Use C(present) or C(absent) for adding or removing
    - Use C(query) for listing an object or multiple objects
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- The C(tenant) must exist before using this module in your playbook
  The M(cisco.aci.aci_tenant) modules can be used for this
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(bfd:MhIfPol)
  link: https://developer.cisco.com/docs/apic-mim-ref/
- module: cisco.aci.aci_tenant
author:
- Anvitha Jain (@anvjain)
"""

EXAMPLES = r"""
- name: Add a new  BFD Multihop Interface policy
  cisco.aci.aci_interface_policy_bfd_multihop:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
    name: ansible_bfd_multihop_interface_policy
    description: Ansible BFD Multihop Interface Policy
    state: present
  delegate_to: localhost

- name: Remove a BFD Multihop Interface policy
  cisco.aci.aci_interface_policy_bfd_multihop:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
    name: ansible_bfd_multihop_interface_policy
    state: absent
  delegate_to: localhost

- name: Query a BFD Multihop Interface policy
  cisco.aci.aci_interface_policy_bfd_multihop:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
    name: ansible_bfd_multihop_interface_policy
    state: query
  delegate_to: localhost

- name: Query all BFD Multihop Interface policies in a specific tenant
  cisco.aci.aci_interface_policy_bfd_multihop:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: ansible_tenant
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
        name=dict(type="str", aliases=["bfd_multihop_interface_policy"]),
        description=dict(type="str"),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        detection_multiplier=dict(type="int"),
        min_transmit_interval=dict(type="int"),
        min_receive_interval=dict(type="int"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "tenant"]],
            ["state", "present", ["name", "tenant"]],
        ],
    )

    name = module.params.get("name")
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    admin_state = module.params.get("admin_state")
    detection_multiplier = module.params.get("detection_multiplier")
    min_transmit_interval = module.params.get("min_transmit_interval")
    min_receive_interval = module.params.get("min_receive_interval")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="bfdMhIfPol",
            aci_rn="bfdMhIfPol-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
    )

    aci.get_existing()

    if state == "present":
        class_config = dict(
            name=name,
            descr=description,
            adminSt=admin_state,
        )

        if detection_multiplier and detection_multiplier not in range(1, 50):
            module.fail_json(msg='The "detection_multiplier" must be a value between 1 and 50')
        else:
            class_config["detectMult"] = detection_multiplier
        if min_transmit_interval and min_transmit_interval not in range(250, 999):
            module.fail_json(msg='The "min_transmit_interval" must be a value between 250 and 999')
        else:
            class_config["minTxIntvl"] = min_transmit_interval
        if min_receive_interval and min_receive_interval not in range(250, 999):
            module.fail_json(msg='The "min_receive_interval" must be a value between 250 and 999')
        else:
            class_config["minRxIntvl"] = min_receive_interval

        aci.payload(
            aci_class="bfdMhIfPol",
            class_config=class_config,
        )

        aci.get_diff(aci_class="bfdMhIfPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
