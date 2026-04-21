#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Tim Cragg (@timcragg)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_dns_provider
short_description: Manage DNS Provider objects (dns:Prov)
description:
- Manage DNS Provider configuration on Cisco ACI fabrics.
options:
  dns_profile:
    description:
    - Name of the DNS profile.
    type: str
    aliases: [ profile_name ]
    required: true
  address:
    description:
    - address of the DNS server
    type: str
    aliases: [ addr, ip_address ]
  preferred:
    description:
    - Whether this is the preferred DNS server
    type: bool
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

notes:
- The C(dns_profile) must exist before using this module in your playbook.
  The M(cisco.aci.aci_dns_profile) modules can be used for this.

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(dnsProv).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new DNS provider
  cisco.aci.aci_dns_provider:
    host: apic
    username: admin
    password: SomeSecretPassword
    dns_profile: my_dns_prof
    address: 10.20.30.40
    state: present
  delegate_to: localhost

- name: Remove a DNS provider
  cisco.aci.aci_dns_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    dns_profile: my_dns_prof
    address: 10.20.30.40
    state: absent
  delegate_to: localhost

- name: Query a DNS provider
  cisco.aci.aci_dns_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    dns_profile: my_dns_prof
    address: 10.20.30.40
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all DNS providers within a DNS profile
  cisco.aci.aci_dns_profile:
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
        dns_profile=dict(type="str", aliases=["profile_name"], required=True),
        address=dict(type="str", aliases=["addr", "ip_address"]),
        preferred=dict(type="bool"),
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

    aci = ACIModule(module)

    dns_profile = module.params.get("dns_profile")
    address = module.params.get("address")
    preferred = aci.boolean(module.params.get("preferred"))
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="dnsProfile",
            aci_rn="fabric/dnsp-{0}".format(dns_profile),
            module_object=dns_profile,
            target_filter={"name": dns_profile},
        ),
        subclass_1=dict(aci_class="dnsProv", aci_rn="prov-{0}".format(address), module_object=address, target_filter={"address": address}),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="dnsProv",
            class_config=dict(addr=address, preferred=preferred),
        )

        aci.get_diff(aci_class="dnsProv")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
