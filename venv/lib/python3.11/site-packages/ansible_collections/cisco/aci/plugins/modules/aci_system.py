#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: aci_system
short_description: Query the ACI system information (top:System)
description:
-  Query the ACI system information on Cisco ACI.
author:
- Lionel Hercot (@lhercot)
options:
  id:
    description:
    - The controller node ID
    aliases: [ controller, node ]
    type: int
  state:
    description:
    - Use C(query) for listing an object or multiple objects.
    choices: [ query ]
    default: query
    type: str

notes:
- This module is used to query system information for both cloud and on-premises controllers.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(top:System).
  link: https://developer.cisco.com/docs/apic-mim-ref/
extends_documentation_fragment:
- cisco.aci.aci
"""

EXAMPLES = r"""
- name: Query all controllers system information
  cisco.aci.aci_system:
    host: apic
    username: userName
    password: somePassword
    validate_certs: false
    state: query
  delegate_to: localhost

- name: Query controller 1 specific system information
  cisco.aci.aci_system:
    host: apic
    username: userName
    password: somePassword
    validate_certs: false
    id: 1
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

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        id=dict(type="int", aliases=["controller", "node"]),
        state=dict(type="str", default="query", choices=["query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    id = module.params.get("id")

    aci = ACIModule(module)
    aci.construct_url(root_class=dict(aci_class="topSystem", target_filter={"id": id}))

    aci.get_existing()

    aci.exit_json()


if __name__ == "__main__":
    main()
