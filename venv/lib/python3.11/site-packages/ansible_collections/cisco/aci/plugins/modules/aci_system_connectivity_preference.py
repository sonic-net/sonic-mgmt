#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, David Neilan (@dneilan-intel) <david.neilan@intel.com>
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
module: aci_system_connectivity_preference
short_description: APIC Connectivity Preferences (mgmt:ConnectivityPrefs)
description:
- Manages APIC Connectivity Preferences on Cisco ACI fabrics.
options:
  interface_preference:
    description:
    - Interface to use for external connection.
    type: str
    choices: [ inband, ooband ]
    aliases: [ interface_pref, int_pref, external_connection ]

  state:
    description:
    - Use C(present) for updating.
    - Use C(query) for listing an object.
    type: str
    choices: [ present, query ]
    default: present

extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(mgmt:ConnectivityPrefs).
  link: https://developer.cisco.com/docs/apic-mim-ref/

author:
- David Neilan (@dneilan-intel)
"""

EXAMPLES = r"""
- name: Configure Out-of-band Connectivity Preference
  cisco.aci.aci_system_connectivity_preference:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_preference: ooband
    state: present
  delegate_to: localhost

- name: Configure In-band Connectivity Preference
  cisco.aci.aci_system_connectivity_preference:
    host: apic
    username: admin
    password: SomeSecretPassword
    interface_preference: inband
    state: present
  delegate_to: localhost

- name: Query Management Connectivity Preference
  cisco.aci.aci_system_connectivity_preference:
    host: apic
    username: admin
    password: SomeSecretPassword
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
            "mgmtConnectivityPrefs": {
                "attributes": {
                    "annotation": "",
                    "childAction": "",
                    "descr": "",
                    "dn": "uni/fabric/connectivityPrefs",
                    "extMngdBy": "",
                    "interfacePref": "inband",
                    "lcOwn": "local",
                    "modTs": "2023-11-14T16:25:32.629+00:00",
                    "name": "default",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": "",
                    "status": "",
                    "uid": "0"
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
      "code": "120",
      "text": "unknown property value foo, name interfacePref, class mgmtConnectivityPrefs [(Dn0)] Dn0=, "
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample:
    {
      "totalCount": "1",
      "imdata": [
          {
              "error": {
                  "attributes": {
                      "code": "120",
                      "text": "unknown property value foo, name interfacePref, class mgmtConnectivityPrefs [(Dn0)] Dn0=, "
                  }
              }
          }
      ]
    }
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "mgmtConnectivityPrefs": {
            "attributes": {
                "interfacePref": "inband"
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
            "mgmtConnectivityPrefs": {
                "attributes": {
                    "annotation": "",
                    "descr": "",
                    "dn": "uni/fabric/connectivityPrefs",
                    "interfacePref": "ooband",
                    "name": "default",
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
        "mgmtConnectivityPrefs": {
            "attributes": {
                "interfacePref": "inband"
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    aci_owner_spec,
)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        interface_preference=dict(
            type="str",
            choices=["ooband", "inband"],
            aliases=["interface_pref", "int_pref", "external_connection"],
        ),
        state=dict(type="str", default="present", choices=["present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["interface_preference"]],
        ],
    )
    aci = ACIModule(module)

    interface_preference = module.params.get("interface_preference")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="mgmtConnectivityPrefs",
            aci_rn="fabric/connectivityPrefs",
        ),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="mgmtConnectivityPrefs",
            class_config=dict(interfacePref=interface_preference),
        )

        aci.get_diff(aci_class="mgmtConnectivityPrefs")

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
