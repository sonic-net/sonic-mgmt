#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Bruno Calogero <brunocalogero@hotmail.com>
# Copyright: (c) 2022, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_bulk_static_binding_to_epg
short_description: Bind static paths to EPGs (fv:RsPathAtt)
description:
- Bind static paths to EPGs on Cisco ACI fabrics.
options:
  tenant:
    description:
    - Name of the tenant.
    type: str
    aliases: [ tenant_name ]
  ap:
    description:
    - The name of the application profile.
    type: str
    aliases: [ app_profile, app_profile_name ]
  epg:
    description:
    - The name of the end point group.
    type: str
    aliases: [ epg_name ]
  description:
    description:
    - Description for the static path to EPG binding.
    type: str
    aliases: [ descr ]
  encap_id:
    description:
    - The encapsulation ID associating the C(epg) with the interface path.
    - This acts as the secondary C(encap_id) when using micro-segmentation.
    - Accepted values are any valid encap ID for specified encap, currently ranges between C(1) and C(4096).
    type: int
    aliases: [ vlan, vlan_id ]
  primary_encap_id:
    description:
    - Determines the primary encapsulation ID associating the C(epg)
      with the interface path when using micro-segmentation.
    - Accepted values are any valid encap ID for specified encap, currently ranges between C(1) and C(4096) and C(unknown).
    - C(unknown) is the default value and using C(unknown) disables the Micro-Segmentation.
    type: str
    aliases: [ primary_vlan, primary_vlan_id ]
  deploy_immediacy:
    description:
    - The Deployment Immediacy of Static EPG on PC, VPC or Interface.
    - The APIC defaults to C(lazy) when unset during creation.
    type: str
    choices: [ immediate, lazy ]
  interface_mode:
    description:
    - Determines how layer 2 tags will be read from and added to frames.
    - Values C(802.1p) and C(native) are identical.
    - Values C(access) and C(untagged) are identical.
    - Values C(regular), C(tagged) and C(trunk) are identical.
    - The APIC defaults to C(trunk) when unset during creation.
    type: str
    choices: [ 802.1p, access, native, regular, tagged, trunk, untagged ]
    aliases: [ interface_mode_name, mode ]
  interface_type:
    description:
    - The type of interface for the static EPG deployment.
    type: str
    choices: [ fex, port_channel, switch_port, vpc, fex_port_channel, fex_vpc ]
    default: switch_port
  interface_configs:
    description:
    - List of interface configurations, elements in the form of a dictionary.
    - Module level attributes will be overridden by the path level attributes.
    type: list
    elements: dict
    suboptions:
      description:
        description:
        - Description for the static path to EPG binding.
        type: str
        aliases: [ descr ]
      encap_id:
        description:
        - The encapsulation ID associating the C(epg) with the interface path.
        - This acts as the secondary C(encap_id) when using micro-segmentation.
        - Accepted values are any valid encap ID for specified encap, currently ranges between C(1) and C(4096).
        type: int
        aliases: [ vlan, vlan_id ]
      primary_encap_id:
        description:
        - Determines the primary encapsulation ID associating the C(epg)
          with the interface path when using micro-segmentation.
        - Accepted values are any valid encap ID for specified encap, currently ranges between C(1) and C(4096) and C(unknown).
        - C(unknown) is the default value and using C(unknown) disables the Micro-Segmentation.
        type: str
        aliases: [ primary_vlan, primary_vlan_id ]
      deploy_immediacy:
        description:
        - The Deployment Immediacy of Static EPG on PC, VPC or Interface.
        - The APIC defaults to C(lazy) when unset during creation.
        type: str
        choices: [ immediate, lazy ]
      interface_mode:
        description:
        - Determines how layer 2 tags will be read from and added to frames.
        - Values C(802.1p) and C(native) are identical.
        - Values C(access) and C(untagged) are identical.
        - Values C(regular), C(tagged) and C(trunk) are identical.
        - The APIC defaults to C(trunk) when unset during creation.
        type: str
        choices: [ 802.1p, access, native, regular, tagged, trunk, untagged ]
        aliases: [ interface_mode_name, mode ]
      interface_type:
        description:
        - The type of interface for the static EPG deployment.
        type: str
        choices: [ fex, port_channel, switch_port, vpc, fex_port_channel, fex_vpc ]
      pod_id:
        description:
        - The pod number part of the tDn.
        - C(pod_id) is usually an integer below C(10).
        type: int
        required: true
        aliases: [ pod, pod_number ]
      leafs:
        description:
        - The switch ID(s) that the C(interface) belongs to.
        - When C(interface_type) is C(switch_port), C(port_channel), or C(fex), then C(leafs) is a string of the leaf ID.
        - When C(interface_type) is C(vpc), then C(leafs) is a list with both leaf IDs.
        - The C(leafs) value is usually something like '101' or '101-102' depending on C(connection_type).
        type: list
        elements: str
        required: true
        aliases: [ leaves, nodes, paths, switches ]
      interface:
        description:
        - The C(interface) string value part of the tDn.
        - Usually a policy group like C(test-IntPolGrp) or an interface of the following format C(1/7) depending on C(interface_type).
        type: str
        required: true
      extpaths:
        description:
        - The C(extpaths) integer value part of the tDn.
        - C(extpaths) is only used if C(interface_type) is C(fex), C(fex_vpc) or C(fex_port_channel).
        - When C(interface_type) is C(fex_vpc), then C(extpaths) is a list with both fex IDs.
        - Usually something like C(1011).
        type: list
        elements: str
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
- The C(tenant), C(ap), C(epg) used must exist before using this module in your playbook.
  The M(cisco.aci.aci_tenant), M(cisco.aci.aci_ap), M(cisco.aci.aci_epg) modules can be used for this.
seealso:
- module: cisco.aci.aci_tenant
- module: cisco.aci.aci_ap
- module: cisco.aci.aci_epg
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(fv:RsPathAtt).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Bruno Calogero (@brunocalogero)
- Marcel Zehnder (@maercu)
- Sabari Jaganathan (@sajagana)
"""

EXAMPLES = r"""
- name: Create list of interfaces using module level attributes
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: accessport-code-cert
    ap: accessport_code_app
    epg: accessport_epg1
    encap_id: 221
    interface_mode: trunk
    deploy_immediacy: lazy
    description: "Module level attributes used to create interfaces"
    interface_configs:
      - interface: 1/7
        leafs: 101
        pod: 1
      - interface: 1/7
        leafs: 107
        pod: 7
      - interface: 1/8
        leafs: 108
        pod: 8
        encap_id: 108
    state: present
  delegate_to: localhost

- name: Create/Update list of interfaces using path level attributes
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: accessport-code-cert
    ap: accessport_code_app
    epg: accessport_epg1
    interface_configs:
      - interface: 1/7
        leafs: 101
        pod: 1
        encap_id: 221
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "Path level attributes used to create/update interfaces"
      - interface: 1/7
        leafs: 107
        pod: 7
        encap_id: 221
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "Path level attributes used to create/update interfaces"
      - interface: 1/8
        leafs: 108
        pod: 8
        encap_id: 108
        interface_mode: trunk
        deploy_immediacy: lazy
        description: "Path level attributes used to create/update interfaces"
    state: present
  delegate_to: localhost

- name: Query all interfaces of an EPG
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: accessport-code-cert
    ap: accessport_code_app
    epg: accessport_epg1
    state: query
  delegate_to: localhost

- name: Query all interfaces
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove list of interfaces
  cisco.aci.aci_bulk_static_binding_to_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: accessport-code-cert
    ap: accessport_code_app
    epg: accessport_epg1
    encap_id: 221
    interface_mode: trunk
    deploy_immediacy: lazy
    interface_configs:
      - interface: 1/7
        leafs: 101
        pod: 1
      - interface: 1/7
        leafs: 107
        pod: 7
      - interface: 1/8
        leafs: 108
        pod: 8
        encap_id: 108
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

INTERFACE_MODE_MAPPING = {
    "802.1p": "native",
    "access": "untagged",
    "native": "native",
    "regular": "regular",
    "tagged": "regular",
    "trunk": "regular",
    "untagged": "untagged",
}

INTERFACE_TYPE_MAPPING = {
    "fex": "topology/pod-{pod_id}/paths-{leafs}/extpaths-{extpaths}/pathep-[eth{interface}]",
    "fex_port_channel": "topology/pod-{pod_id}/paths-{leafs}/extpaths-{extpaths}/pathep-[{interface}]",
    "fex_vpc": "topology/pod-{pod_id}/protpaths-{leafs}/extprotpaths-{extpaths}/pathep-[{interface}]",
    "port_channel": "topology/pod-{pod_id}/paths-{leafs}/pathep-[{interface}]",
    "switch_port": "topology/pod-{pod_id}/paths-{leafs}/pathep-[eth{interface}]",
    "vpc": "topology/pod-{pod_id}/protpaths-{leafs}/pathep-[{interface}]",
}

INTERFACE_STATUS_MAPPING = {"absent": "deleted"}


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        tenant=dict(type="str", aliases=["tenant_name"]),
        ap=dict(type="str", aliases=["app_profile", "app_profile_name"]),
        epg=dict(type="str", aliases=["epg_name"]),
        description=dict(type="str", aliases=["descr"]),
        encap_id=dict(type="int", aliases=["vlan", "vlan_id"]),
        primary_encap_id=dict(type="str", aliases=["primary_vlan", "primary_vlan_id"]),
        deploy_immediacy=dict(type="str", choices=["immediate", "lazy"]),
        interface_mode=dict(
            type="str", choices=["802.1p", "access", "native", "regular", "tagged", "trunk", "untagged"], aliases=["interface_mode_name", "mode"]
        ),
        interface_type=dict(type="str", default="switch_port", choices=["fex", "port_channel", "switch_port", "vpc", "fex_port_channel", "fex_vpc"]),
        interface_configs=dict(
            type="list",
            elements="dict",
            options=dict(
                description=dict(type="str", aliases=["descr"]),
                encap_id=dict(type="int", aliases=["vlan", "vlan_id"]),
                primary_encap_id=dict(type="str", aliases=["primary_vlan", "primary_vlan_id"]),
                deploy_immediacy=dict(type="str", choices=["immediate", "lazy"]),
                interface_mode=dict(
                    type="str", choices=["802.1p", "access", "native", "regular", "tagged", "trunk", "untagged"], aliases=["interface_mode_name", "mode"]
                ),
                interface_type=dict(type="str", choices=["fex", "port_channel", "switch_port", "vpc", "fex_port_channel", "fex_vpc"]),
                pod_id=dict(type="int", required=True, aliases=["pod", "pod_number"]),
                leafs=dict(type="list", elements="str", required=True, aliases=["leaves", "nodes", "paths", "switches"]),
                interface=dict(type="str", required=True),
                extpaths=dict(type="list", elements="str"),
            ),
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["ap", "epg", "tenant", "interface_configs"]],
            ["state", "present", ["ap", "epg", "tenant", "interface_configs"]],
        ],
    )

    tenant = module.params.get("tenant")
    ap = module.params.get("ap")
    epg = module.params.get("epg")
    module_description = module.params.get("description")
    module_encap_id = module.params.get("encap_id")
    module_primary_encap_id = module.params.get("primary_encap_id")
    module_deploy_immediacy = module.params.get("deploy_immediacy")
    module_interface_mode = module.params.get("interface_mode")
    module_interface_type = module.params.get("interface_type")
    interface_configs = module.params.get("interface_configs")
    state = module.params.get("state")

    aci = ACIModule(module)
    children = []

    aci.construct_url(
        root_class=dict(
            aci_class="fvTenant",
            aci_rn="tn-{0}".format(tenant),
            module_object=tenant,
            target_filter=dict(name=tenant),
        ),
        subclass_1=dict(
            aci_class="fvAp",
            aci_rn="ap-{0}".format(ap),
            module_object=ap,
            target_filter=dict(name=ap),
        ),
        subclass_2=dict(
            aci_class="fvAEPg",
            aci_rn="epg-{0}".format(epg),
            module_object=epg,
            target_filter=dict(name=epg),
        ),
        child_classes=["fvRsPathAtt"],
    )

    aci.get_existing()

    if state == "present" or state == "absent":
        for interface_config in interface_configs:
            pod_id = interface_config.get("pod_id")
            interface = interface_config.get("interface")
            extpaths = interface_config.get("extpaths")

            description = interface_config.get("description") or module_description
            deploy_immediacy = interface_config.get("deploy_immediacy") or module_deploy_immediacy
            interface_type = interface_config.get("interface_type") or module_interface_type
            encap_id = interface_config.get("encap_id") or module_encap_id
            primary_encap_id = interface_config.get("primary_encap_id") or module_primary_encap_id
            interface_mode = interface_config.get("interface_mode") or module_interface_mode

            if interface_type in ["fex", "fex_vpc", "fex_port_channel"] and extpaths is None:
                aci.fail_json(msg="extpaths is required when interface_type is: {0}".format(interface_type))

            # Process leafs, and support dash-delimited leafs
            leafs = []
            for leaf in interface_config.get("leafs"):
                # Users are likely to use integers for leaf IDs, which would raise an exception when using the join method
                leafs.extend(str(leaf).split("-"))
            if len(leafs) == 1:
                if interface_type in ["vpc", "fex_vpc"]:
                    aci.fail_json(msg='A interface_type of "vpc" requires 2 leafs')
                leafs = leafs[0]
            elif len(leafs) == 2:
                if interface_type not in ["vpc", "fex_vpc"]:
                    aci.fail_json(msg='The interface_types "switch_port", "port_channel", and "fex" do not support using multiple leafs for a single binding')
                leafs = "-".join(leafs)
            else:
                aci.fail_json(msg='The "leafs" parameter must not have more than 2 entries')

            if extpaths is not None:
                # Process extpaths, and support dash-delimited extpaths
                extpaths = []
                for extpath in interface_config.get("extpaths"):
                    # Users are likely to use integers for extpaths IDs, which would raise an exception when using the join method
                    extpaths.extend(str(extpath).split("-"))
                if len(extpaths) == 1:
                    if interface_type == "fex_vpc":
                        aci.fail_json(msg='A interface_type of "fex_vpc" requires 2 extpaths')
                    extpaths = extpaths[0]
                elif len(extpaths) == 2:
                    if interface_type != "fex_vpc":
                        aci.fail_json(msg='The interface_types "fex" and "fex_port_channel" do not support using multiple extpaths for a single binding')
                    extpaths = "-".join(extpaths)
                else:
                    aci.fail_json(msg='The "extpaths" parameter must not have more than 2 entries')

            if encap_id is not None:
                if encap_id not in range(1, 4097):
                    aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096")
                encap_id = "vlan-{0}".format(encap_id)

            if primary_encap_id is not None:
                try:
                    primary_encap_id = int(primary_encap_id)
                    if isinstance(primary_encap_id, int) and primary_encap_id in range(1, 4097):
                        primary_encap_id = "vlan-{0}".format(primary_encap_id)
                    else:
                        aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096 or unknown.")
                except Exception as e:
                    if isinstance(primary_encap_id, str) and primary_encap_id != "unknown":
                        aci.fail_json(msg="Valid VLAN assignments are from 1 to 4096 or unknown. %s" % e)

            static_path = INTERFACE_TYPE_MAPPING[interface_type].format(pod_id=pod_id, leafs=leafs, extpaths=extpaths, interface=interface)

            interface_mode = INTERFACE_MODE_MAPPING.get(interface_mode)

            interface_status = INTERFACE_STATUS_MAPPING.get(state)

            children.append(
                dict(
                    fvRsPathAtt=dict(
                        attributes=dict(
                            descr=description,
                            encap=encap_id,
                            primaryEncap=primary_encap_id,
                            instrImedcy=deploy_immediacy,
                            mode=interface_mode,
                            tDn=static_path,
                            status=interface_status,
                        )
                    )
                )
            )

        aci.payload(
            aci_class="fvAEPg",
            class_config=dict(),
            child_configs=children,
        )

        aci.get_diff(aci_class="fvAEPg")

        aci.post_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
