#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Tim Cragg (@timcragg)
# Copyright: (c) 2023, Akini Ross (@akinross)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_dhcp_relay
short_description: Manage DHCP relay policies (dhcp:RelayP)
description:
- Manage DHCP relay policy configuration on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    - When tenant is not provided the module will be applied to the global (infra) policy.
    type: str
  name:
    description:
    - Name of the DHCP relay policy
    type: str
    aliases: [ relay_policy ]
  description:
    description:
    - Description of the relay policy
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

notes:
- The C(tenant) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(dhcp:RelayP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new DHCP relay policy
  cisco.aci.aci_dhcp_relay:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Auto-Demo
    name: my_dhcp_relay
    description: via Ansible
    state: present
  delegate_to: localhost

- name: Add a new global (infra) DHCP relay policy
  cisco.aci.aci_dhcp_relay:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_dhcp_relay
    description: via Ansible
    state: present
  delegate_to: localhost

- name: Remove a DHCP relay policy
  cisco.aci.aci_dhcp_relay:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Auto-Demo
    name: my_dhcp_relay
    state: absent
  delegate_to: localhost

- name: Remove a global (infra) DHCP relay policy
  cisco.aci.aci_dhcp_relay:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_dhcp_relay
    state: absent
  delegate_to: localhost

- name: Query a DHCP relay policy
  cisco.aci.aci_dhcp_relay:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Auto-Demo
    name: my_dhcp_relay
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a global (infra) DHCP relay policy
  cisco.aci.aci_dhcp_relay:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: my_dhcp_relay
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all DHCP relay policies in a specific tenant
  cisco.aci.aci_dhcp_relay:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Auto-Demo
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all DHCP relay policies
  cisco.aci.aci_dhcp_relay:
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
        name=dict(type="str", aliases=["relay_policy"]),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str"),
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
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    child_classes = ["dhcpRsProv"]

    if tenant is None:
        root_class = dict(
            aci_class="dhcpRelayP",
            aci_rn="infra/relayp-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        )
        subclass_1 = None
        owner = "infra"
    else:
        root_class = dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        )
        subclass_1 = dict(
            aci_class="dhcpRelayP",
            aci_rn="relayp-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        )
        owner = "tenant"

    aci = ACIModule(module)

    aci.construct_url(root_class=root_class, subclass_1=subclass_1, child_classes=child_classes)

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="dhcpRelayP",
            class_config=dict(name=name, descr=description, owner=owner),
        )

        aci.get_diff(aci_class="dhcpRelayP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
