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
module: aci_ntp_server
short_description: Manage NTP servers (datetime:NtpProv)
description:
- Manage NTP server (datetimeNtpProv) configuration on Cisco ACI fabrics.
options:
  ntp_policy:
    description:
    - Name of an existing NTP policy
    type: str
    required: true
    aliases: [ policy_name ]
  ntp_server:
    description:
    - Name of the NTP server
    type: str
    aliases: [ server_name ]
  description:
    description:
    - Description of the NTP server
    type: str
  min_poll:
    description:
    - Minimum polling interval
    type: int
  max_poll:
    description:
    - Maximum polling interval
    type: int
  preferred:
    description:
    - Is this the preferred NTP server
    type: bool
  epg_type:
    description:
    - Type of management EPG to use to reach the NTP server, inb or oob
    type: str
    choices: [ inb, oob ]
  epg_name:
    description:
    - Name of the management EPG to reach the NTP server
    type: str
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
- The used C(ntp_policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_ntp_policy) module can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(datetime:NtpProv).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a new NTP server
  cisco.aci.aci_ntp_server:
    host: apic
    username: admin
    password: SomeSecretPassword
    ntp_policy: my_ntp_policy
    ntp_server: 10.20.30.40
    min_poll: 3
    max_poll: 8
    preferred: true
    state: present
  delegate_to: localhost

- name: Remove a NTP server
  cisco.aci.aci_ntp_server:
    host: apic
    username: admin
    password: SomeSecretPassword
    ntp_policy: my_ntp_policy
    ntp_server: 10.20.30.40
    state: absent
  delegate_to: localhost

- name: Query a NTP server
  cisco.aci.aci_ntp_server:
    host: apic
    username: admin
    password: SomeSecretPassword
    ntp_policy: my_ntp_policy
    ntp_server: 10.20.30.40
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all NTP servers within a policy
  cisco.aci.aci_ntp_server:
    host: apic
    username: admin
    password: SomeSecretPassword
    ntp_policy: my_ntp_policy
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
        ntp_policy=dict(type="str", aliases=["policy_name"], required=True),
        ntp_server=dict(type="str", aliases=["server_name"]),
        description=dict(type="str"),
        min_poll=dict(type="int"),
        max_poll=dict(type="int"),
        preferred=dict(type="bool"),
        epg_type=dict(type="str", choices=["inb", "oob"]),
        epg_name=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ntp_server"]],
            ["state", "present", ["ntp_server"]],
        ],
        required_together=[
            ["epg_type", "epg_name"],
        ],
    )
    aci = ACIModule(module)

    ntp_policy = module.params.get("ntp_policy")
    ntp_server = module.params.get("ntp_server")
    description = module.params.get("description")
    min_poll = module.params.get("min_poll")
    max_poll = module.params.get("max_poll")
    preferred = aci.boolean(module.params.get("preferred"))
    epg_type = module.params.get("epg_type")
    epg_name = module.params.get("epg_name")
    state = module.params.get("state")
    child_classes = ["datetimeRsNtpProvToEpg"]

    aci.construct_url(
        root_class=dict(
            aci_class="datetimePol",
            aci_rn="fabric/time-{0}".format(ntp_policy),
            module_object=ntp_policy,
            target_filter={"name": ntp_policy},
        ),
        subclass_1=dict(
            aci_class="datetimeNtpProv",
            aci_rn="ntpprov-{0}".format(ntp_server),
            module_object=ntp_server,
            target_filter={"name": ntp_server},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if epg_type is not None:
            tdn = "uni/tn-mgmt/mgmtp-default/{0}-{1}".format(epg_type, epg_name)
            child_configs.append(dict(datetimeRsNtpProvToEpg=dict(attributes=dict(tDn=tdn))))
        aci.payload(
            aci_class="datetimeNtpProv",
            class_config=dict(
                name=ntp_server,
                descr=description,
                maxPoll=max_poll,
                minPoll=min_poll,
                preferred=preferred,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="datetimeNtpProv")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
