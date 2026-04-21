#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Eric Girard <@netgirard>
# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = r"""
---
module: aci_access_spine_interface_profile_to_spine_switch_profile
short_description: Bind Fabric Access Spine Interface Profiles to Fabric Acces Spine Switch Profiles (infra:RsSpAccPortP)
description:
- Bind access spine interface selector profiles to access switch policy spine profiles on Cisco ACI fabrics.
options:
  switch_profile:
    description:
    - The name of the Fabric Access Spine Switch Profile to which we add a Spine Interface Selector Profile.
    type: str
    aliases: [ switch_profile_name, spine_switch_profile, spine_switch_profile_name ]
  interface_profile:
    description:
    - The name of the Fabric Access Spine Interface Profile to be added and associated with the Spine Switch Profile.
    type: str
    aliases: [ interface_profile_name, spine_interface_profile, spine_interface_profile_name ]
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
- This module requires an existing I(switch_profile).
  The module M(cisco.aci.aci_access_spine_switch_profile) can be used for this.
- The I(interface_profile) accepts non existing spine interface profile names.
  They appear on APIC GUI with a state of "missing-target".
  The module M(cisco.aci.aci_access_spine_interface_profile) can be used to create them.
seealso:
- module: cisco.aci.aci_access_spine_switch_profile
- module: cisco.aci.aci_access_spine_interface_profile
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(infra:RsSpAccPortP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Eric Girard (@netgirard)
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Associating an interface selector profile to a switch policy spine profile
  cisco.aci.aci_access_spine_interface_profile_to_spine_switch_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_profile: sw_name
    interface_profile: interface_profile_name
    state: present
  delegate_to: localhost

- name: Query an interface selector profile associated with a switch policy spine profile
  cisco.aci.aci_access_spine_interface_profile_to_spine_switch_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_profile: sw_name
    interface_profile: interface_profile_name
    state: query
  delegate_to: localhost

- name: Query all association of interface selector profiles with a switch policy spine profile
  cisco.aci.aci_access_spine_interface_profile_to_spine_switch_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove an interface selector profile associated with a switch policy spine profile
  cisco.aci.aci_access_spine_interface_profile_to_spine_switch_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    switch_profile: sw_name
    interface_profile: interface_profile_name
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


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        switch_profile=dict(
            type="str",
            aliases=[
                "switch_profile_name",
                "spine_switch_profile",
                "spine_switch_profile_name",
            ],
        ),  # Not required for querying all objects
        interface_profile=dict(
            type="str",
            aliases=[
                "interface_profile_name",
                "spine_interface_profile",
                "spine_interface_profile_name",
            ],
        ),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["switch_profile", "interface_profile"]],
            ["state", "present", ["switch_profile", "interface_profile"]],
        ],
    )

    switch_profile = module.params.get("switch_profile")
    interface_profile = module.params.get("interface_profile")
    state = module.params.get("state")

    # Defining the interface profile tDn for clarity
    interface_profile_tDn = "uni/infra/spaccportprof-{0}".format(interface_profile)

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="infraInfra",
            aci_rn="infra",
        ),
        subclass_1=dict(
            aci_class="infraSpineP",
            aci_rn="spprof-{0}".format(switch_profile),
            module_object=switch_profile,
            target_filter={"name": switch_profile},
        ),
        subclass_2=dict(
            aci_class="infraRsSpAccPortP",
            aci_rn="rsspAccPortP-[{0}]".format(interface_profile_tDn),
            module_object=interface_profile,
            target_filter={"tDn": interface_profile_tDn},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="infraRsSpAccPortP",
            class_config=dict(tDn=interface_profile_tDn),
        )

        aci.get_diff(aci_class="infraRsSpAccPortP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
