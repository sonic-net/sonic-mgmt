#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Samita Bhattacharjee (@samitab) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_bd_to_netflow_monitor_policy
short_description: Bind Bridge Domain to Netflow Monitor Policy (fv:RsBDToNetflowMonitorPol)
description:
- Bind Bridge Domain to Netflow Monitor Policy on Cisco ACI fabrics.
options:
  bd:
    description:
    - The name of the Bridge Domain.
    type: str
    aliases: [ bd_name, bridge_domain ]
  tenant:
    description:
    - The name of the Tenant.
    type: str
    aliases: [ tenant_name ]
  netflow_monitor_policy:
    description:
    - The name of the Netflow Monitor Policy.
    type: str
    aliases: [ netflow_monitor, netflow_monitor_name, name ]
  filter_type:
    description:
    - Choice of filter type while setting NetFlow Monitor Policies.
    type: str
    choices: [ce, ipv4, ipv6, unspecified]
    aliases: [ filter, type ]
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
- The C(bd) and C(netflow_monitor_policy) parameters should exist before using this module.
  The M(cisco.aci.aci_bd) and C(aci_netflow_monitor_policy) can be used for this.
seealso:
- module: cisco.aci.aci_bd
- module: cisco.aci.aci_netflow_monitor_policy
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:RsBDToNetflowMonitorPol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Bind Bridge Domain to Netflow Monitor Policy
  cisco.aci.aci_bd_to_netflow_monitor_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: false
    bd: web_servers
    netflow_monitor_policy: prod_netflow_monitor_policy
    tenant: prod
    filter_type: ipv4
    state: present
  delegate_to: localhost

- name: Query all Bridge Domains bound to Netflow Monitor Policy
  cisco.aci.aci_bd_to_netflow_monitor_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: true
    state: query
  delegate_to: localhost
  register: query_result

- name: Query specific Bridge Domain(s) bound to an Netflow Monitor Policy
  cisco.aci.aci_bd_to_netflow_monitor_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: true
    bd: web_servers
    netflow_monitor_policy: prod_netflow_monitor_policy
    tenant: prod
    state: query
  delegate_to: localhost
  register: query_result

- name: Unbind Bridge Domain from Netflow Monitor Policy
  cisco.aci.aci_bd_to_netflow_monitor_policy:
    host: apic
    username: admin
    password: SomeSecretPassword
    validate_certs: true
    bd: web_servers
    netflow_monitor_policy: prod_netflow_monitor_policy
    tenant: prod
    filter_type: ipv4
    state: absent
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        bd=dict(type="str", aliases=["bd_name", "bridge_domain"]),  # Not required for querying all objects
        netflow_monitor_policy=dict(type="str", aliases=["netflow_monitor", "netflow_monitor_name", "name"]),  # Not required for querying all objects
        filter_type=dict(type="str", choices=["ce", "ipv4", "ipv6", "unspecified"], aliases=["filter", "type"]),  # Not required for querying all objects
        tenant=dict(type="str", aliases=["tenant_name"]),  # Not required for querying all objects
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["bd", "netflow_monitor_policy", "tenant", "filter_type"]],
            ["state", "absent", ["bd", "netflow_monitor_policy", "tenant", "filter_type"]],
        ],
    )

    bd = module.params.get("bd")
    netflow_monitor_policy = module.params.get("netflow_monitor_policy")
    filter_type = module.params.get("filter_type")
    state = module.params.get("state")
    tenant = module.params.get("tenant")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        ),
        subclass_1=dict(
            aci_class="fvBD",
            aci_rn="BD-{0}".format(bd),
            module_object=bd,
            target_filter={"name": bd},
        ),
        subclass_2=dict(
            aci_class="fvRsBDToNetflowMonitorPol",
            aci_rn="rsBDToNetflowMonitorPol-[{0}]-{1}".format(netflow_monitor_policy, filter_type),
            module_object=netflow_monitor_policy,
            target_filter={"tnNetflowMonitorPolName": netflow_monitor_policy},
        ),
    )

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="fvRsBDToNetflowMonitorPol",
            class_config=dict(tnNetflowMonitorPolName=netflow_monitor_policy, fltType=filter_type),
        )

        aci.get_diff(aci_class="fvRsBDToNetflowMonitorPol")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
