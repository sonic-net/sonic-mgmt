#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_aep_to_epg
short_description: Bind EPG to AEP (infra:RsFuncToEpg)
description:
- Bind EPG to AEP.
options:
  aep:
    description:
    - The name of the Attachable Access Entity Profile.
    type: str
    aliases: [ aep_name ]
  tenant:
    description:
    - The name of an existing tenant.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - Name of an existing application network profile, that will contain the EPGs.
    type: str
    aliases: [ app_profile, app_profile_name ]
  epg:
    description:
    - The name of the end point group.
    type: str
    aliases: [ epg_name ]
  encap:
    description:
    - The VLAN associated with this application EPG.
    type: int
    aliases: [ vlan, vlan_id, encap_id ]
  primary_encap:
    description:
    - The primary VLAN associated with this EPG
    type: int
    aliases: [ primary_vlan, primary_vlan_id, primary_encap_id ]
  interface_mode:
    description:
    - Determines how layer 2 tags will be read from and added to frames.
    - Values C(802.1p) and C(native) are identical.
    - Values C(access) and C(untagged) are identical.
    - Values C(regular), C(tagged) and C(trunk) are identical.
    - The APIC defaults to C(trunk) when unset during creation.
    type: str
    choices: [ 802.1p, access, native, regular, tagged, trunk, untagged ]
    aliases: [ mode, mode_name, interface_mode_name ]
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

author:
- Marcel Zehnder (@maercu)
"""

EXAMPLES = r"""
- name: Associate EPG with AEP
  cisco.aci.aci_aep_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    aep: aep1
    tenant: tenant1
    ap: ap1
    epg: epg1
    encap_id: 222
    interface_mode: access
    state: present
  delegate_to: localhost

- name: Associate EPG with AEP
  cisco.aci.aci_aep_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    aep: aep1
    tenant: tenant1
    ap: ap1
    epg: epg1
    encap_id: 222
    interface_mode: access
    state: absent
  delegate_to: localhost

- name: Get specific EPG with AEP association
  cisco.aci.aci_aep_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    aep: aep1
    tenant: tenant1
    ap: ap1
    epg: epg1
    encap_id: 222
    interface_mode: access
    state: query
  delegate_to: localhost
  register: query_result

- name: Get all EPG with AEP association
  cisco.aci.aci_aep_to_epg:
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


from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


INTERFACE_MODE_MAPPING = {
    "802.1p": "native",
    "access": "untagged",
    "native": "native",
    "regular": "regular",
    "tagged": "regular",
    "trunk": "regular",
    "untagged": "untagged",
}


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        aep=dict(type="str", aliases=["aep_name"]),
        tenant=dict(type="str", aliases=["tenant_name"]),
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),
        epg=dict(type="str", aliases=["epg_name"]),
        encap=dict(type="int", aliases=["vlan", "vlan_id", "encap_id"]),
        primary_encap=dict(type="int", aliases=["primary_vlan", "primary_vlan_id", "primary_encap_id"]),
        interface_mode=dict(
            type="str", choices=["802.1p", "access", "native", "regular", "tagged", "trunk", "untagged"], aliases=["mode_name", "mode", "interface_mode_name"]
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["aep", "epg", "ap", "tenant"]],
            ["state", "present", ["interface_mode", "encap", "aep", "epg", "ap", "tenant"]],
        ],
    )

    aep = module.params.get("aep")
    tenant = module.params.get("tenant")
    ap = module.params.get("ap")
    epg = module.params.get("epg")
    encap = module.params.get("encap")
    primary_encap = module.params.get("primary_encap")
    interface_mode = module.params.get("interface_mode")
    state = module.params.get("state")

    if interface_mode is not None:
        interface_mode = INTERFACE_MODE_MAPPING[interface_mode]

    if encap is not None:
        encap = "vlan-{0}".format(encap)

    if primary_encap is not None:
        primary_encap = "vlan-{0}".format(primary_encap)

    epg_mo = None
    if tenant is not None and ap is not None and epg is not None:
        epg_mo = "uni/tn-{0}/ap-{1}/epg-{2}".format(tenant, ap, epg)

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(aci_class="infraAttEntityP", aci_rn="infra/attentp-{0}".format(aep), module_object=aep, target_filter={"name": aep}),
        subclass_1=dict(aci_class="infraGeneric", aci_rn="gen-default", module_object="default", target_filter={"name": "default"}),
        subclass_2=dict(aci_class="infraRsFuncToEpg", aci_rn="rsfuncToEpg-[{0}]".format(epg_mo), module_object=epg_mo, target_filter={"tDn": epg_mo}),
    )

    aci.get_existing()

    if state == "present":
        # Post configuration on infraGeneric (subclass_1) level instead of on
        # infraRsFuncToEpg (subclass_2) level.
        # The reason being that the MO "gen-default" (of class infraGeneric) does not
        # exist until the first EPG to AEP association is created.
        aci.construct_url(
            root_class=dict(aci_class="infraAttEntityP", aci_rn="infra/attentp-{0}".format(aep), module_object=aep, target_filter={"name": aep}),
            subclass_1=dict(aci_class="infraGeneric", aci_rn="gen-default", module_object="default", target_filter={"name": "default"}),
            child_classes=["infraRsFuncToEpg"],
        )

        aci.get_existing()

        child_configs = [dict(infraRsFuncToEpg=dict(attributes=dict(encap=encap, primaryEncap=primary_encap, mode=interface_mode, tDn=epg_mo)))]

        aci.payload(aci_class="infraGeneric", class_config=dict(name="default"), child_configs=child_configs)

        aci.get_diff(aci_class="infraGeneric")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
