#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Tim Cragg (@timcragg)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: aci_ntp_policy
short_description: Manage NTP policies (datetime:Pol)
description:
- Manage NTP policy configuration on Cisco ACI fabrics.
options:
  name:
    description:
    - Name of the NTP policy
    type: str
    aliases: [ ntp_policy ]
  description:
    description:
    - Description of the NTP policy
    type: str
  admin_state:
    description:
    - Admin state of the policy
    type: str
    choices: [ disabled, enabled ]
  server_state:
    description:
    - Allow switches to act as NTP servers
    type: str
    choices: [ disabled, enabled ]
  auth_state:
    description:
    - Enable authentication
    type: str
    choices: [ disabled, enabled ]
  master_mode:
    description:
    - Enable master mode. Only applicable if server_state is enabled
    type: str
    choices: [ disabled, enabled ]
  stratum:
    description:
    - The NTP stratum value.
    - The APIC defaults to C(8) when not provided.
    - The allowed minimum is C(1) and the allowed maximum is C(15).
    type: int
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(datetime:Pol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new NTP policy
  cisco.aci.aci_ntp_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_ntp_policy
    description: via Ansible
    admin_state: enabled
    state: present
  delegate_to: localhost

- name: Remove a NTP policy
  cisco.aci.aci_ntp_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_ntp_policy
    state: absent
  delegate_to: localhost

- name: Query a NTP policy
  cisco.aci.aci_ntp_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_ntp_policy
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all NTP policies
  cisco.aci.aci_ntp_policy:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["ntp_policy"]),
        description=dict(type="str"),
        admin_state=dict(type="str", choices=["disabled", "enabled"]),
        server_state=dict(type="str", choices=["disabled", "enabled"]),
        auth_state=dict(type="str", choices=["disabled", "enabled"]),
        master_mode=dict(type="str", choices=["disabled", "enabled"]),
        stratum=dict(type="int"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    name = module.params.get("name")
    description = module.params.get("description")
    admin_state = module.params.get("admin_state")
    server_state = module.params.get("server_state")
    auth_state = module.params.get("auth_state")
    master_mode = module.params.get("master_mode")
    stratum = module.params.get("stratum")
    state = module.params.get("state")
    child_classes = ["datetimeNtpProv"]

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="datetimePol",
            aci_rn="fabric/time-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="datetimePol",
            class_config=dict(
                name=name,
                descr=description,
                adminSt=admin_state,
                serverState=server_state,
                authSt=auth_state,
                masterMode=master_mode,
                StratumValue=stratum,
            ),
        )

        aci.get_diff(aci_class="datetimePol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
