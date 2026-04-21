#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_dhcp_option
short_description: Manage DHCP Option (dhcp:Option)
description:
- Manage DHCP Options for DHCP Option Policies on Cisco ACI fabrics.
- The DHCP option is used to supply DHCP clients with configuration parameters such as a domain, name server, subnet, and network address.
  DHCP provides a framework for passing configuration information to clients on a TCP/IP network.
  The configuration parameters, and other control information, are carried in tagged data items that are stored in the options field of a DHCP message.
  The data items themselves are also called options. You can view, set, unset, and edit DHCP option values.
  When you set an option value, the DHCP server replaces any existing value or creates a new one as needed for the given option name.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  dhcp_option_policy:
    description:
    - The name of an existing DHCP Option Policy.
    type: str
    aliases: [ dhcp_option_policy_name ]
  dhcp_option:
    description:
    - The name of the DHCP Option.
    type: str
    aliases: [ dhcp_option_name, name ]
  data:
    description:
    - The value of the DHCP Option.
    type: str
  id:
    description:
    - The DHCP Option ID.
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

notes:
- The C(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new DHCP Option
  cisco.aci.aci_dhcp_option:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    dhcp_option_policy: my_dhcp_option_policy
    dhcp_option: my_dhcp_option
    id: 1
    data: 82
    state: present
  delegate_to: localhost

- name: Delete an DHCP Option
  cisco.aci.aci_dhcp_option:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    dhcp_option_policy: my_dhcp_option_policy
    dhcp_option: my_dhcp_option
    state: absent
  delegate_to: localhost

- name: Query a DHCP Option
  cisco.aci.aci_dhcp_option:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    dhcp_option_policy: my_dhcp_option_policy
    dhcp_option: my_dhcp_option
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all DHCP Options in my_dhcp_option_policy
  cisco.aci.aci_dhcp_option:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    dhcp_option_policy: my_dhcp_option_policy
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
        tenant=dict(type="str", aliases=["tenant_name"]),
        dhcp_option_policy=dict(type="str", aliases=["dhcp_option_policy_name"]),
        dhcp_option=dict(type="str", aliases=["dhcp_option_name", "name"]),
        data=dict(type="str"),
        id=dict(type="int"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "dhcp_option_policy", "dhcp_option"]],
            ["state", "present", ["tenant", "dhcp_option_policy", "dhcp_option"]],
        ],
    )

    tenant = module.params.get("tenant")
    dhcp_option_policy = module.params.get("dhcp_option_policy")
    dhcp_option = module.params.get("dhcp_option")
    data = module.params.get("data")
    id = module.params.get("id")
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
            aci_class="dhcpOptionPol",
            aci_rn="dhcpoptpol-{0}".format(dhcp_option_policy),
            module_object=dhcp_option_policy,
            target_filter={"name": dhcp_option_policy},
        ),
        subclass_2=dict(
            aci_class="dhcpOption",
            aci_rn="opt-{0}".format(dhcp_option),
            module_object=dhcp_option,
            target_filter={"name": dhcp_option},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="dhcpOption",
            class_config=dict(
                name=dhcp_option,
                data=data,
                id=id,
            ),
        )

        aci.get_diff(aci_class="dhcpOption")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
