#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l2out_logical_interface_profile
short_description: Manage Layer 2 Outside (L2Out) interface profiles (l2ext:LIfP)
description:
- Manage interface profiles of L2 outside (BD extension) on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l2out:
    description:
    - Name of an existing L2Out.
    type: str
    aliases: [ l2out_name ]
  node_profile:
    description:
    - Name of the node profile.
    type: str
    default: default
    aliases: [ node_profile_name, logical_node ]
  interface_profile:
    description:
    - Name of the interface profile.
    type: str
    aliases: [ name, interface_profile_name, logical_interface ]
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
- module: cisco.aci.aci_l2out
- module: cisco.aci.aci_l2out_logical_node_profile
- module: cisco.aci.aci_l2out_logical_interface_path
- module: cisco.aci.aci_l2out_extepg
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(l2ext:LIfP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Oleksandr Kreshchenko (@alexkross)
"""

EXAMPLES = r"""
- name: Add new interface profile
  cisco.aci.aci_l2out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l2out: my_l2out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    state: present
  delegate_to: localhost

- name: Delete interface profile
  cisco.aci.aci_l2out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l2out: my_l2out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    state: absent
  delegate_to: localhost

- name: Query an interface profile
  cisco.aci.aci_l2out_logical_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l2out: my_l2out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all interface profiles
  cisco.aci.aci_l2out_logical_interface_profile:
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
    argument_spec.update(  # See comments in aci_static_binding_to_epg module.
        tenant=dict(type="str", aliases=["tenant_name"]),
        l2out=dict(type="str", aliases=["l2out_name"]),
        node_profile=dict(type="str", default="default", aliases=["node_profile_name", "logical_node"]),
        interface_profile=dict(type="str", aliases=["name", "interface_profile_name", "logical_interface"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l2out", "node_profile", "interface_profile"]],
            ["state", "present", ["tenant", "l2out", "node_profile", "interface_profile"]],
        ],
    )

    tenant = module.params.get("tenant")
    l2out = module.params.get("l2out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
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
            aci_class="l2extOut",
            aci_rn="l2out-{0}".format(l2out),
            module_object=l2out,
            target_filter={"name": l2out},
        ),
        subclass_2=dict(
            aci_class="l2extLNodeP",
            aci_rn="lnodep-{0}".format(node_profile),
            module_object=node_profile,
            target_filter={"name": node_profile},
        ),
        subclass_3=dict(
            aci_class="l2extLIfP",
            aci_rn="lifp-{0}".format(interface_profile),
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        ),
    )

    aci.get_existing()

    if state == "present":
        # child_configs = []
        aci.payload(
            aci_class="l2extLIfP",
            class_config=dict(name=interface_profile),
            # child_configs=child_configs
        )

        aci.get_diff(aci_class="l2extLIfP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
