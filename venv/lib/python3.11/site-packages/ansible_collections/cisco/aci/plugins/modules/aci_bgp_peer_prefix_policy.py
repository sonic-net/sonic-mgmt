#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_bgp_peer_prefix_policy
short_description: Manage BGP peer prefix policy (bgp:PeerPfxPol)
description:
- Manage BGP peer prefix policies for the Tenants on Cisco ACI fabrics.
options:
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  peer_prefix_policy:
    description:
    - The name of the BGP peer prefix policy.
    type: str
    aliases: [ peer_prefix_policy_name, name ]
  action:
    description:
    - The action to be performed when the maximum prefix limit is reached.
    - The APIC defaults to C(reject) when unset during creation.
    type: str
    choices: [ log, reject, restart, shut ]
  maximum_number_prefix:
    description:
    - The maximum number of prefixes allowed from the peer.
    - The APIC defaults to C(20000) when unset during creation.
    type: int
    aliases: [ max_prefix, max_num_prefix ]
  restart_time:
    description:
    - The period of time in minutes before restarting the peer when the prefix limit is reached.
    - Used only if C(action) is set to C(restart).
    - The APIC defaults to C(infinite) when unset during creation.
    type: str
  threshold:
    description:
    - The threshold percentage of the maximum number of prefixes before a warning is issued.
    - For example, if the maximum number of prefixes is 10 and the threshold is 70%, a warning is issued when the number of prefixes exceeds 7 (70%).
    - The APIC defaults to C(75) when unset during creation.
    type: int
    aliases: [ thresh ]
  description:
    description:
    - Description for the BGP peer prefix policy.
    type: str
    aliases: [ descr ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

notes:
- The C(tenant) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) module can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(bgp:PeerPfxPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Gaspard Micol (@gmicol)
"""

EXAMPLES = r"""
- name: Create a BGP peer prefix policy
  cisco.aci.aci_bgp_peer_prefix_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    peer_prefix_policy: my_bgp_peer_prefix_policy
    action: restart
    restart_time: 10
    max_prefix: 10000
    threshold: 80
    tenant: production
    state: present
  delegate_to: localhost

- name: Delete a BGP peer prefix policy
  cisco.aci.aci_bgp_peer_prefix_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    peer_prefix_policy: my_bgp_peer_prefix_policy
    tenant: production
    state: absent
  delegate_to: localhost

- name: Query all BGP peer prefix policies
  cisco.aci.aci_bgp_peer_prefix_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a specific BGP peer prefix policy
  cisco.aci.aci_bgp_peer_prefix_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    peer_prefix_policy: my_bgp_peer_prefix_policy
    tenant: production
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
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        peer_prefix_policy=dict(type="str", aliases=["peer_prefix_policy_name", "name"]),  # Not required for querying all objects
        action=dict(type="str", choices=["log", "reject", "restart", "shut"]),
        maximum_number_prefix=dict(type="int", aliases=["max_prefix", "max_num_prefix"]),
        restart_time=dict(type="str"),
        threshold=dict(type="int", aliases=["thresh"]),
        description=dict(type="str", aliases=["descr"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        name_alias=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["peer_prefix_policy", "tenant"]],
            ["state", "present", ["peer_prefix_policy", "tenant"]],
        ],
    )

    peer_prefix_policy = module.params.get("peer_prefix_policy")
    action = module.params.get("action")
    maximum_number_prefix = module.params.get("maximum_number_prefix")
    restart_time = module.params.get("restart_time")
    threshold = module.params.get("threshold")
    description = module.params.get("description")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    name_alias = module.params.get("name_alias")

    aci = ACIModule(module)

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="bgpPeerPfxPol",
            aci_rn="bgpPfxP-{0}".format(peer_prefix_policy),
            module_object=peer_prefix_policy,
            target_filter={"name": peer_prefix_policy},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="bgpPeerPfxPol",
            class_config=dict(
                name=peer_prefix_policy,
                action=action,
                maxPfx=maximum_number_prefix,
                restartTime=restart_time,
                thresh=threshold,
                descr=description,
                nameAlias=name_alias,
            ),
        )

        aci.get_diff(aci_class="bgpPeerPfxPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
