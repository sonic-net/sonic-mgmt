#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Tim Cragg (@timcragg)
# Copyright: (c) 2024, Akini Ross (@akinross)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_dns_profile
short_description: Manage DNS Profile objects (dns:Profile)
description:
- Manage DNS Profile configuration on Cisco ACI fabrics.
options:
  dns_profile:
    description:
    - Name of the DNS profile.
    type: str
    aliases: [ name, profile_name ]
  management_epg:
    description:
    - Name of the management EPG.
    - Specify C("") to remove the management EPG configuration.
    type: str
    aliases: [ epg ]
  management_epg_type:
    description:
    - The type of the management EPG.
    type: str
    choices: [ inband, ooband ]
    aliases: [ type ]
    default: ooband
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(dns:Profile).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new DNS profile
  cisco.aci.aci_dns_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    dns_profile: my_dns_prof
    state: present
  delegate_to: localhost

- name: Add a new DNS profile with a inband management EPG
  cisco.aci.aci_dns_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    dns_profile: my_dns_prof
    management_epg: ansible_mgmt_epg_inband
    management_epg_type: inband
    state: present
  delegate_to: localhost

- name: Add a new DNS profile with a out-of-band management EPG
  cisco.aci.aci_dns_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    dns_profile: my_dns_prof
    management_epg: ansible_mgmt_epg_ooband
    state: present
  delegate_to: localhost

- name: Remove a management EPG from a DNS profile
  cisco.aci.aci_dns_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    dns_profile: my_dns_prof
    management_epg: ""
    state: present
  delegate_to: localhost

- name: Query a DNS profile
  cisco.aci.aci_dns_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    dns_profile: my_dns_prof
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all DNS profiles
  cisco.aci.aci_dns_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a DNS profile
  cisco.aci.aci_dns_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    dns_profile: my_dns_prof
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
from ansible_collections.cisco.aci.plugins.module_utils.constants import MANAGEMENT_EPG_TYPE


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        dns_profile=dict(type="str", aliases=["name", "profile_name"]),
        management_epg=dict(type="str", aliases=["epg"]),
        management_epg_type=dict(type="str", default="ooband", choices=["inband", "ooband"], aliases=["type"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["dns_profile"]],
            ["state", "present", ["dns_profile"]],
        ],
    )

    dns_profile = module.params.get("dns_profile")
    management_epg = module.params.get("management_epg")
    management_epg_type = MANAGEMENT_EPG_TYPE.get(module.params.get("management_epg_type"))
    state = module.params.get("state")
    child_classes = ["dnsProv", "dnsDomain", "dnsRsProfileToEpg"]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="dnsProfile",
            aci_rn="fabric/dnsp-{0}".format(dns_profile),
            module_object=dns_profile,
            target_filter={"name": dns_profile},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":

        child_configs = []
        if management_epg is not None:
            if management_epg == "":
                child_configs.append(
                    dict(
                        dnsRsProfileToEpg=dict(
                            attributes=dict(
                                tDn="",
                                status="deleted",
                            )
                        )
                    )
                )
            else:
                child_configs.append(
                    dict(
                        dnsRsProfileToEpg=dict(
                            attributes=dict(
                                tDn="uni/tn-mgmt/mgmtp-default/{0}-{1}".format(management_epg_type, management_epg),
                            )
                        )
                    )
                )

        aci.payload(
            aci_class="dnsProfile",
            class_config=dict(name=dns_profile),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="dnsProfile")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
