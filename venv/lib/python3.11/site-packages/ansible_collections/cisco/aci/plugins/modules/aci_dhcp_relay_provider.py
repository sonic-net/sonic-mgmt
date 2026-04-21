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
module: aci_dhcp_relay_provider
short_description: Manage DHCP relay policy providers (dhcp:RsProv)
description:
- Manage DHCP relay policy providers configuration on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of the tenant the relay_policy is in.
    - When tenant is not provided the module will be applied to the global (infra) policy.
    type: str
  relay_policy:
    description:
    - Name of an existing DHCP relay policy
    type: str
    aliases: [ relay_policy_name ]
  provider_tenant:
    description:
    - Name of the tenant the epg or external_epg is in
    - Required when epg or external_epg is in a different tenant than the relay_policy
    - Required when global (infra) relay_policy is configured with epg or external_epg types
    type: str
  epg_type:
    description:
    - Type of EPG the DHCP server is in
    type: str
    choices: [ epg, l2_external, l3_external, dn ]
  anp:
    description:
    - Application Profile the EPG is in.
    - Only used when epg_type is app_epg.
    type: str
  epg:
    description:
    - Name of the Application EPG the DHCP server is in.
    - Only used when epg_type is epg
    type: str
    aliases: [ app_epg ]
  l2out_name:
    description:
    - Name of the L2out the DHCP server is in.
    - Only used when epg_type is l2_external
    type: str
  l3out_name:
    description:
    - Name of the L3out the DHCP server is in.
    - Only used when epg_type is l3_external.
    type: str
  external_epg:
    description:
    - Name of the external network object the DHCP server is in.
    - Only used when epg_type is l2_external or l3_external.
    type: str
    aliases: [ external_net ]
  dn:
    description:
    - dn of the EPG the DHCP server is in
    - Only used when epg_type is dn
    type: str
  dhcp_server_addr:
    description:
    - DHCP server address
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
- The C(tenant) and C(relay_policy) must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant) and C(cisco.aci.aci_dhcp_relay) modules can be used for this.
seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(dhcp:RsProv).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a new DHCP relay App EPG provider
  cisco.aci.aci_dhcp_relay_provider:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Auto-Demo
    relay_policy: my_dhcp_relay
    epg_type: epg
    anp: my_anp
    epg: my_app_epg
    dhcp_server_addr: 10.20.30.40
    state: present
  delegate_to: localhost

- name: Add a new Global (infra) DHCP relay App EPG provider
  cisco.aci.aci_dhcp_relay_provider:
    host: apic
    username: admin
    password: SomeSecretPassword
    relay_policy: my_dhcp_relay
    provider_tenant: Auto-Demo
    epg_type: epg
    anp: my_anp
    epg: my_app_epg
    dhcp_server_addr: 10.20.30.40
    state: present
  delegate_to: localhost

- name: Add a new DHCP relay L3out provider
  cisco.aci.aci_dhcp_relay_provider:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Auto-Demo
    relay_policy: my_dhcp_relay
    epg_type: l3_external
    l3out_name: my_l3out
    external_net: my_l3out_ext_net
    dhcp_server_addr: 10.20.30.40
    state: present
  delegate_to: localhost

- name: Remove a DHCP relay provider
  cisco.aci.aci_dhcp_relay_provider:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Auto-Demo
    relay_policy: my_dhcp_relay
    epg_type: epg
    anp: my_anp
    epg: my_app_epg
    state: absent
  delegate_to: localhost

- name: Remove a Global (infra) DHCP relay provider
  cisco.aci.aci_dhcp_relay_provider:
    host: apic
    username: admin
    password: SomeSecretPassword
    relay_policy: my_dhcp_relay
    provider_tenant: Auto-Demo
    epg_type: epg
    anp: my_anp
    epg: my_app_epg
    state: absent
  delegate_to: localhost

- name: Query a DHCP relay provider
  cisco.aci.aci_dhcp_relay_provider:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Auto-Demo
    relay_policy: my_dhcp_relay
    epg_type: epg
    anp: my_anp
    epg: my_app_epg
    state: query
  delegate_to: localhost
  register: query_result

- name: Query a Global (infra) DHCP relay provider
  cisco.aci.aci_dhcp_relay_provider:
    host: apic
    username: admin
    password: SomeSecretPassword
    relay_policy: my_dhcp_relay
    provider_tenant: Auto-Demo
    epg_type: epg
    anp: my_anp
    epg: my_app_epg
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all DHCP relay providers in a specific tenant
  cisco.aci.aci_dhcp_relay_provider:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: Auto-Demo
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all DHCP relay providers
  cisco.aci.aci_dhcp_relay_provider:
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
        relay_policy=dict(type="str", aliases=["relay_policy_name"]),
        epg_type=dict(type="str", choices=["epg", "l2_external", "l3_external", "dn"]),
        anp=dict(type="str"),
        epg=dict(type="str", aliases=["app_epg"]),
        l2out_name=dict(type="str"),
        l3out_name=dict(type="str"),
        external_epg=dict(type="str", aliases=["external_net"]),
        dhcp_server_addr=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        tenant=dict(type="str"),
        provider_tenant=dict(type="str"),
        dn=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["relay_policy", "epg_type"]],
            ["state", "present", ["relay_policy", "epg_type"]],
            ["epg_type", "epg", ["anp", "epg"]],
            ["epg_type", "l2_external", ["l2out_name", "external_epg"]],
            ["epg_type", "l3_external", ["l3out_name", "external_epg"]],
            ["epg_type", "l3_external", ["provider_tenant", "tenant"], True],
            ["epg_type", "l2_external", ["provider_tenant", "tenant"], True],
            ["epg_type", "epg", ["provider_tenant", "tenant"], True],
            ["epg_type", "dn", ["dn"]],
        ],
        mutually_exclusive=[
            ["anp", "l2out_name"],
            ["anp", "l3out_name"],
            ["anp", "external_epg"],
            ["anp", "dn"],
            ["epg", "l2out_name"],
            ["epg", "l3out_name"],
            ["epg", "external_epg"],
            ["epg", "dn"],
            ["l2out_name", "l3out_name"],
            ["l2out_name", "dn"],
            ["l3out_name", "dn"],
            ["external_epg", "dn"],
        ],
    )

    relay_policy = module.params.get("relay_policy")
    state = module.params.get("state")
    tenant = module.params.get("tenant")
    epg_type = module.params.get("epg_type")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    l2out_name = module.params.get("l2out_name")
    l3out_name = module.params.get("l3out_name")
    external_epg = module.params.get("external_epg")
    dhcp_server_addr = module.params.get("dhcp_server_addr")
    provider_tenant = module.params.get("provider_tenant")
    dn = module.params.get("dn")

    if provider_tenant is None:
        provider_tenant = tenant

    if epg_type == "epg":
        tdn = "uni/tn-{0}/ap-{1}/epg-{2}".format(provider_tenant, anp, epg)
    elif epg_type == "l2_external":
        tdn = "uni/tn-{0}/l2out-{1}/instP-{2}".format(provider_tenant, l2out_name, external_epg)
    elif epg_type == "l3_external":
        tdn = "uni/tn-{0}/out-{1}/instP-{2}".format(provider_tenant, l3out_name, external_epg)
    elif epg_type == "dn":
        tdn = dn
    else:
        tdn = None

    if tenant is None:
        root_class = dict(
            aci_class="dhcpRelayP",
            aci_rn="infra/relayp-{0}".format(relay_policy),
            module_object=relay_policy,
            target_filter={"name": relay_policy},
        )
        subclass_1 = dict(
            aci_class="dhcpRsProv",
            aci_rn="rsprov-[{0}]".format(tdn),
            module_object=tdn,
            target_filter={"tDn": tdn},
        )
        subclass_2 = None
    else:
        root_class = dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter={"name": tenant},
        )
        subclass_1 = dict(
            aci_class="dhcpRelayP",
            aci_rn="relayp-{0}".format(relay_policy),
            module_object=relay_policy,
            target_filter={"name": relay_policy},
        )
        subclass_2 = dict(
            aci_class="dhcpRsProv",
            aci_rn="rsprov-[{0}]".format(tdn),
            module_object=tdn,
            target_filter={"tDn": tdn},
        )

    aci = ACIModule(module)

    aci.construct_url(root_class=root_class, subclass_1=subclass_1, subclass_2=subclass_2)

    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="dhcpRsProv",
            class_config=dict(addr=dhcp_server_addr, tDn=tdn),
        )

        aci.get_diff(aci_class="dhcpRsProv")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
