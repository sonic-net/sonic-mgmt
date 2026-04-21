#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_l3out_eigrp_interface_profile
short_description: Manage Layer 3 Outside (L3Out) EIGRP interface profile (eigrp:IfP)
description:
- Manage L3Out logical interface profile EIGRP policies on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  l3out:
    description:
    - The name of an existing L3Out.
    type: str
    aliases: [ l3out_name ]
  node_profile:
    description:
    - The name of the node profile.
    type: str
    aliases: [ node_profile_name, logical_node ]
  interface_profile:
    description:
    - The name of an existing interface profile.
    type: str
    aliases: [ interface_profile_name, logical_interface ]
  eigrp_policy:
    description:
    - The name of an existing EIGRP interface policy.
    type: str
    aliases: [ name, eigrp_policy_name ]
  eigrp_keychain_policy:
    description:
    - The name of an existing EIGRP keychain policy.
    - Pass an empty string to disable Authentification.
    type: str
    aliases: [ keychain_policy, keychain_policy_name  ]
  description:
    description:
    - The description of the EIGRP interface profile.
    type: str
    aliases: [ descr ]
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
- The C(tenant), C(l3out), C(node_profile), C(interface_profile) and C(eigrp_policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_l3out), M(cisco.aci.aci_l3out_logical_node_profile), M(cisco.aci.aci_l3out_logical_interface_profile)
  and M(cisco.aci.aci_interface_policy_eigrp) can be used for this.
- if C(eigrp_keychain_policy) is used, it must exist before using this module in your playbook.
  The M(cisco.aci.aci_keychain_policy) can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_l3out
- module: cisco.aci.aci_l3out_logical_node_profile
- module: cisco.aci.aci_l3out_logical_interface_profile
- module: cisco.aci.aci_interface_policy_eigrp
- module: cisco.aci.aci_keychain_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Add a new interface profile EIGRP policy
  cisco.aci.aci_l3out_eigrp_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    eigrp_policy: my_eigrp_interface_policy
    state: present
  delegate_to: localhost

- name: Add a new interface profile EIGRP policy with authentication
  cisco.aci.aci_l3out_eigrp_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    eigrp_policy: my_eigrp_interface_policy
    eigrp_keychain_policy: my_keychain_policy
    state: present
  delegate_to: localhost

- name: Disable authentification from an interface profile EIGRP policy
  cisco.aci.aci_l3out_eigrp_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    eigrp_policy: my_eigrp_interface_policy
    eigrp_keychain_policy: ""
    state: present
  delegate_to: localhost

- name: Delete an interface profile EIGRP policy
  cisco.aci.aci_l3out_eigrp_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    eigrp_policy: my_eigrp_interface_policy
    state: absent
  delegate_to: localhost

- name: Query an interface profile EIGRP policy
  cisco.aci.aci_l3out_eigrp_interface_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: my_tenant
    l3out: my_l3out
    node_profile: my_node_profile
    interface_profile: my_interface_profile
    eigrp_policy: my_eigrp_interface_policy
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
        l3out=dict(type="str", aliases=["l3out_name"]),
        node_profile=dict(type="str", aliases=["node_profile_name", "logical_node"]),
        interface_profile=dict(type="str", aliases=["interface_profile_name", "logical_interface"]),
        eigrp_policy=dict(type="str", aliases=["name", "eigrp_policy_name"]),
        eigrp_keychain_policy=dict(type="str", aliases=["keychain_policy", "keychain_policy_name"], no_log=False),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["tenant", "l3out", "node_profile", "interface_profile"]],
            ["state", "present", ["tenant", "l3out", "node_profile", "interface_profile", "eigrp_policy"]],
        ],
    )

    tenant = module.params.get("tenant")
    l3out = module.params.get("l3out")
    node_profile = module.params.get("node_profile")
    interface_profile = module.params.get("interface_profile")
    eigrp_policy = module.params.get("eigrp_policy")
    eigrp_keychain_policy = module.params.get("eigrp_keychain_policy")
    description = module.params.get("description")
    state = module.params.get("state")

    aci = ACIModule(module)

    child_classes = ["eigrpRsIfPol", "eigrpAuthIfP"]

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="l3extOut",
            aci_rn="out-{0}".format(l3out),
            module_object=l3out,
            target_filter={"name": l3out},
        ),
        subclass_2=dict(
            aci_class="l3extLNodeP",
            aci_rn="lnodep-{0}".format(node_profile),
            module_object=node_profile,
            target_filter={"name": node_profile},
        ),
        subclass_3=dict(
            aci_class="l3extLIfP",
            aci_rn="lifp-[{0}]".format(interface_profile),
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        ),
        subclass_4=dict(
            aci_class="eigrpIfP",
            aci_rn="eigrpIfP",
            module_object=interface_profile,
            target_filter={"name": interface_profile},
        ),
        child_classes=child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = [dict(eigrpRsIfPol=dict(attributes=dict(tnEigrpIfPolName=eigrp_policy)))]

        if eigrp_keychain_policy is not None:
            if eigrp_keychain_policy == "" and isinstance(aci.existing, list) and len(aci.existing) > 0:
                for child in aci.existing[0].get("eigrpIfP", {}).get("children", {}):
                    if child.get("eigrpAuthIfP"):
                        child_configs.append(
                            dict(
                                eigrpAuthIfP=dict(
                                    attributes=dict(status="deleted"),
                                ),
                            )
                        )
            elif eigrp_keychain_policy != "":
                child_configs.append(
                    dict(
                        eigrpAuthIfP=dict(
                            attributes=dict(),
                            children=[
                                dict(
                                    eigrpRsKeyChainPol=dict(
                                        attributes=dict(
                                            tnFvKeyChainPolName=eigrp_keychain_policy,
                                        ),
                                    )
                                )
                            ],
                        )
                    )
                )

        aci.payload(
            aci_class="eigrpIfP",
            class_config=dict(
                descr=description,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="eigrpIfP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
