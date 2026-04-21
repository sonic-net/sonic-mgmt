#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_access_span_dst_group
short_description: Manage Access SPAN destination groups (span:DestGrp)
description:
- Manage Access SPAN destination groups on Cisco ACI fabrics.
options:
  destination_group:
    description:
    - The name of the Access SPAN destination group.
    type: str
    aliases: [ name, dst_group ]
  description:
    description:
    - The description of the Access SPAN destination group.
    type: str
    aliases: [ descr ]
  access_interface:
    description:
    - The destination access interface.
    - The I(access_interface) and I(destination_epg) cannot be configured simultaneously.
    type: dict
    suboptions:
      pod:
        description:
        - The pod id part of the destination path.
        type: int
        required: true
        aliases: [ pod_id, pod_number ]
      node:
        description:
        - The node id part of the destination path.
        type: int
        required: true
        aliases: [ node_id ]
      path:
        description:
        - The interface part of the destination path.
        - When path is of type port a interface like C(eth1/7) must be provided.
        - When path is of type direct_port_channel the name of a policy group like C(test_PolGrp) must be provided.
        type: str
        required: true
      mtu:
        description:
        - The MTU truncation size for the packets.
        - The APIC defaults to C(1518) when unset during creation.
        type: int
  destination_epg:
    description:
    - The destination end point group.
    - The I(access_interface) and I(destination_epg) cannot be configured simultaneously.
    type: dict
    suboptions:
      tenant:
        description:
        - The name of the tenant.
        type: str
        required: true
        aliases: [ tenant_name ]
      ap:
        description:
        - The name of application profile.
        type: str
        required: true
        aliases: [ ap_name, app_profile, app_profile_name ]
      epg:
        description:
        - The name of the end point group.
        type: str
        required: true
        aliases: [ epg_name ]
      span_version:
        description:
        - The SPAN version.
        - The APIC defaults to C(version_2) when unset during creation.
        type: str
        choices: [ version_1, version_2 ]
      version_enforced:
        description:
        - Enforce SPAN version.
        type: bool
      source_ip:
        description:
        - The source IP address or prefix.
        type: str
        required: true
      destination_ip:
        description:
        - The destination IP address.
        type: str
        required: true
      flow_id:
        description:
        - The flow ID of the SPAN packet.
        - The APIC defaults to C(1) when unset during creation.
        type: int
      ttl:
        description:
        - The time to live of the span session packets.
        - The APIC defaults to C(64) when unset during creation.
        type: int
      mtu:
        description:
        - The MTU truncation size for the packets.
        - The APIC defaults to C(1518) when unset during creation.
        type: int
      dscp:
        description:
        - The DSCP value for sending the monitored packets using ERSPAN.
        - The APIC defaults to C(unspecified) when unset during creation.
        type: str
        choices: [ CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, EF, VA, AF11, AF12, AF13, AF21, AF22, AF23, AF31, AF32, AF33, AF41, AF42, AF43, unspecified ]
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

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(span:DestGrp).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add a Access SPAN destination group of type EPG
  cisco.aci.aci_access_span_dst_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    destination_group: group1
    description: Test span
    destination_epg:
      tenant: Test1
      ap: ap1
      epg: ep1
      span_version: version_1
      version_enforced: false
      destination_ip: 10.0.0.1
      source_ip: 10.0.2.1
      ttl: 2
      mtu: 1500
      flow_id: 1
      dscp: CS1
    state: present
  delegate_to: localhost

- name: Add a Access SPAN destination group of type access interface port
  cisco.aci.aci_access_span_dst_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    destination_group: group1
    description: Test span
    access_interface:
      pod: 1
      node: 101
      path: 1/1
      mtu: 1500
    state: present
  delegate_to: localhost

- name: Add a Access SPAN destination group of type access interface direct_port_channel
  cisco.aci.aci_access_span_dst_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    destination_group: group1
    description: Test span
    access_interface:
      pod: 1
      node: 101
      path: Switch101_1-ports-1-2_PolGrp
      mtu: 1500
    state: present
  delegate_to: localhost

- name: Remove a Access SPAN destination group
  cisco.aci.aci_access_span_dst_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    destination_group: group1
    state: absent
  delegate_to: localhost

- name: Query a Access SPAN destination group
  cisco.aci.aci_access_span_dst_group:
    host: apic
    username: admin
    password: SomeSecretPassword
    destination_group: group1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Access SPAN destination groups
  cisco.aci.aci_access_span_dst_group:
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
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec, destination_epg_spec


def access_interface_spec():
    return dict(
        pod=dict(type="int", required=True, aliases=["pod_id", "pod_number"]),
        node=dict(type="int", required=True, aliases=["node_id"]),
        path=dict(type="str", required=True),
        mtu=dict(type="int"),
    )


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        destination_group=dict(type="str", aliases=["name", "dst_group"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        access_interface=dict(type="dict", options=access_interface_spec()),
        destination_epg=dict(type="dict", options=destination_epg_spec()),
        name_alias=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["destination_group"]],
            ["state", "present", ["destination_group"]],
            ["state", "present", ["access_interface", "destination_epg"], True],
        ],
        mutually_exclusive=[
            ("access_interface", "destination_epg"),
        ],
    )

    aci = ACIModule(module)

    destination_group = module.params.get("destination_group")
    description = module.params.get("description")
    access_interface = module.params.get("access_interface")
    destination_epg = module.params.get("destination_epg")
    state = module.params.get("state")
    name_alias = module.params.get("name_alias")

    aci.construct_url(
        root_class=dict(
            aci_class="infra",
            aci_rn="infra",
        ),
        subclass_1=dict(
            aci_class="spanDestGrp",
            aci_rn="destgrp-{0}".format(destination_group),
            module_object=destination_group,
            target_filter={"name": destination_group},
        ),
        child_classes=["spanDest", "spanRsDestEpg", "spanRsDestPathEp"],
    )

    aci.get_existing()

    if state == "present":
        if destination_epg:
            attributes = dict(
                tDn="uni/tn-{0}/ap-{1}/epg-{2}".format(destination_epg.get("tenant"), destination_epg.get("ap"), destination_epg.get("epg")),
                ip=destination_epg.get("destination_ip"),
                srcIpPrefix=destination_epg.get("source_ip"),
            )
            if destination_epg.get("span_version") is not None:
                attributes["ver"] = "ver1" if destination_epg.get("span_version") == "version_1" else "ver2"
            if destination_epg.get("version_enforced") is not None:
                attributes["verEnforced"] = "yes" if destination_epg.get("version_enforced") else "no"
            if destination_epg.get("ttl") is not None:
                attributes["ttl"] = str(destination_epg.get("ttl"))
            if destination_epg.get("mtu") is not None:
                attributes["mtu"] = str(destination_epg.get("mtu"))
            if destination_epg.get("flow_id") is not None:
                attributes["flowId"] = str(destination_epg.get("flow_id"))
            if destination_epg.get("dscp") is not None:
                attributes["dscp"] = destination_epg.get("dscp")
            span_rs_dest = dict(spanRsDestEpg=dict(attributes=attributes))

        else:
            attributes = dict(
                tDn="topology/pod-{0}/paths-{1}/pathep-[{2}]".format(access_interface.get("pod"), access_interface.get("node"), access_interface.get("path"))
            )
            if access_interface.get("mtu") is not None:
                attributes["mtu"] = str(access_interface.get("mtu"))
            span_rs_dest = dict(spanRsDestPathEp=dict(attributes=attributes))

        aci.payload(
            aci_class="spanDestGrp",
            class_config=dict(name=destination_group, descr=description, nameAlias=name_alias),
            child_configs=[dict(spanDest=dict(attributes=dict(name=destination_group), children=[span_rs_dest]))],
        )

        aci.get_diff(aci_class="spanDestGrp")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
