#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Samita Bhattacharjee (@samitab) <samitab.cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_external_connection_profile
short_description: Manage Fabric External Connection Profiles (fv:FabricExtConnP).
description:
- Manage Fabric External Connection Profiles (Intrasite/Intersite profiles) on Cisco ACI fabrics.
options:
  description:
    description:
    - Specifies a description of the profile definition.
    type: str
    aliases: [ descr ]
  fabric_id:
    description:
    - The fabric identifier of the Fabric External Connection Profile.
    type: int
    aliases: [ id, fabric ]
  name:
    description:
    - The name of the Fabric External Connection Profile.
    type: str
    aliases: [ profile_name ]
  community:
    description:
    - Global EVPN Route Target of the Fabric External Connection Profile.
    - eg. extended:as2-nn4:5:16
    type: str
    aliases: [ rt, route_target ]
  site_id:
    description:
    - The site identifier of the Fabric External Connection Profile.
    type: int
    aliases: [ sid, site, s_id ]
  peering_type:
    description:
    - The BGP EVPN Peering Type. Use either C(automatic_with_full_mesh) or C(automatic_with_rr).
    type: str
    choices: [ automatic_with_full_mesh, automatic_with_rr ]
    aliases: [ p_type, peer, peer_t ]
  peering_password:
    description:
    - The BGP EVPN Peering Password. Used for setting automatic peering sessions.
    - Providing this option will always result in a change because it is a secure property that cannot be retrieved from APIC.
    type: str
    aliases: [ peer_password, peer_pwd ]
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
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:FabricExtConnP).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add a new Fabric External Connection Profile
  cisco.aci.aci_fabric_external_connection_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_id: 1
    name: ansible_fabric_ext_conn_profile
    description: Fabric External Connection Profile
    community: extended:as2-nn4:5:16
    site_id: 1
    peering_type: automatic_with_rr
    peering_password: SomeSecretPeeringPassword
    state: present
  delegate_to: localhost

- name: Query a Fabric External Connection Profile
  cisco.aci.aci_fabric_external_connection_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_id: 1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Fabric External Connection Profiles
  cisco.aci.aci_fabric_external_connection_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Remove a Fabric External Connection Profile
  cisco.aci.aci_fabric_external_connection_profile:
    host: apic
    username: admin
    password: SomeSecretPassword
    fabric_id: 1
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        description=dict(type="str", aliases=["descr"]),
        fabric_id=dict(type="int", aliases=["id", "fabric"]),
        name=dict(type="str", aliases=["profile_name"]),
        community=dict(type="str", aliases=["rt", "route_target"]),
        site_id=dict(type="int", aliases=["sid", "site", "s_id"]),
        peering_type=dict(type="str", aliases=["p_type", "peer", "peer_t"], choices=["automatic_with_full_mesh", "automatic_with_rr"]),
        peering_password=dict(type="str", aliases=["peer_password", "peer_pwd"], no_log=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["fabric_id"]],
            ["state", "present", ["fabric_id"]],
        ],
    )

    aci = ACIModule(module)

    description = module.params.get("description")
    fabric_id = module.params.get("fabric_id")
    name = module.params.get("name")
    community = module.params.get("community")
    peering_type = module.params.get("peering_type")
    peering_password = module.params.get("peering_password")
    site_id = module.params.get("site_id")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class="fvFabricExtConnP",
            aci_rn="tn-infra/fabricExtConnP-{0}".format(fabric_id),
            module_object=fabric_id,
            target_filter={"id": fabric_id},
        ),
        child_classes=["fvPeeringP"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = None
        if peering_type is not None or peering_password is not None:
            peering_p = {"fvPeeringP": {"attributes": {}}}
            if peering_type is not None:
                peering_p["fvPeeringP"]["attributes"]["type"] = peering_type
            if peering_password is not None:
                peering_p["fvPeeringP"]["attributes"]["password"] = peering_password
            child_configs = [peering_p]

        aci.payload(
            aci_class="fvFabricExtConnP",
            class_config=dict(
                descr=description,
                id=fabric_id,
                name=name,
                rt=community,
                siteId=site_id,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="fvFabricExtConnP")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
