#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_anp_epg
short_description: Manage Endpoint Groups (EPGs) in schema templates
description:
- Manage EPGs in schema templates on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Anvitha Jain (@anvitha-jain)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  anp:
    description:
    - The name of the ANP.
    type: str
    required: true
  epg:
    description:
    - The name of the EPG to manage.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  description:
    description:
    - The description as displayed on the MSO web interface.
    - The description is supported on versions of MSO that are 3.3 or greater.
    type: str
#  contracts:
#    description:
#    - A list of contracts associated to this ANP.
#    type: list
  bd:
    description:
    - The BD associated to this ANP.
    type: dict
    suboptions:
      name:
        description:
        - The name of the BD to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced BD.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The template that defines the referenced BD.
        type: str
  vrf:
    description:
    - The VRF associated to this ANP.
    type: dict
    suboptions:
      name:
        description:
        - The name of the VRF to associate with.
        required: true
        type: str
      schema:
        description:
        - The schema that defines the referenced VRF.
        - If this parameter is unspecified, it defaults to the current schema.
        type: str
      template:
        description:
        - The template that defines the referenced VRF.
        type: str
  subnets:
    description:
    - The subnets associated to this ANP.
    type: list
    elements: dict
    suboptions:
      subnet:
        description:
        - The IP range in CIDR notation.
        type: str
        required: true
        aliases: [ ip ]
      description:
        description:
        - The description of this subnet.
        type: str
      scope:
        description:
        - The scope of the subnet.
        type: str
        default: private
        choices: [ private, public ]
      shared:
        description:
        - Whether this subnet is shared between VRFs.
        type: bool
        default: false
      no_default_gateway:
        description:
        - Whether this subnet has a default gateway.
        type: bool
        default: false
  useg_epg:
    description:
    - Whether this is a USEG EPG.
    type: bool
#  useg_epg_attributes:
#    description:
#    - A dictionary consisting of USEG attributes.
#    type: dict
  intra_epg_isolation:
    description:
    - Whether intra EPG isolation is enforced.
    - When not specified, this parameter defaults to C(unenforced).
    type: str
    choices: [ enforced, unenforced ]
  intersite_multicast_source:
    description:
    - Whether intersite multicast source is enabled.
    - When not specified, this parameter defaults to C(no).
    type: bool
  proxy_arp:
    description:
    - Whether proxy arp is enabled.
    - When not specified, this parameter defaults to C(no).
    type: bool
  preferred_group:
    description:
    - Whether this EPG is added to preferred group or not.
    - When not specified, this parameter defaults to C(no).
    type: bool
  qos_level:
    description:
    - Quality of Service (QoS) allows you to classify the network traffic in the fabric.
    - It helps prioritize and police the traffic flow to help avoid congestion in the network.
    - The Contract QoS Level parameter is supported on versions of MSO that are 3.1 or greater.
    choices: [ unspecified, level1, level2, level3, level4, level5, level6 ]
    type: str
  epg_type:
    description:
    - The EPG type parameter is supported on versions of MSO that are 3.3 or greater.
    type: str
    choices: [ application, service ]
  deployment_type:
    description:
    - The deployment_type parameter indicates how and where the service is deployed.
    - This parameter is available only when epg_type is service.
    type: str
    choices: [ cloud_native, cloud_native_managed, third_party ]
  access_type:
    description:
    - This parameter indicates how the service will be accessed.
    - It is only available when epg_type is service.
    type: str
    choices: [ private, public, public_and_private ]
  service_type:
    description:
    - The service_type parameter refers to the type of cloud services.
    - Only certain deployment types, and certain access types within each deployment type, are supported for each service type.
    - This parameter is available only when epg_type is service.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_anp
- module: cisco.mso.mso_schema_template_anp_epg_subnet
- module: cisco.mso.mso_schema_template_bd
- module: cisco.mso.mso_schema_template_contract_filter
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new EPG
  cisco.mso.mso_schema_template_anp_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    bd:
      name: bd1
    vrf:
      name: vrf1
    state: present

- name: Add a new EPG with preferred group.
  cisco.mso.mso_schema_template_anp_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    state: present
    preferred_group: true

- name: Remove an EPG
  cisco.mso.mso_schema_template_anp_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    bd:
      name: bd1
    vrf:
      name: vrf1
    state: absent

- name: Query a specific EPG
  cisco.mso.mso_schema_template_anp_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    bd:
      name: bd1
    vrf:
      name: vrf1
    state: query
  register: query_result

- name: Query all EPGs
  cisco.mso.mso_schema_template_anp_epg:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    anp: ANP 1
    epg: EPG 1
    bd:
      name: bd1
    vrf:
      name: vrf1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_reference_spec, mso_epg_subnet_spec
from ansible_collections.cisco.mso.plugins.module_utils.constants import QOS_LEVEL


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        epg=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        description=dict(type="str"),
        bd=dict(type="dict", options=mso_reference_spec()),
        vrf=dict(type="dict", options=mso_reference_spec()),
        display_name=dict(type="str"),
        useg_epg=dict(type="bool"),
        intra_epg_isolation=dict(type="str", choices=["enforced", "unenforced"]),
        intersite_multicast_source=dict(type="bool"),
        proxy_arp=dict(type="bool"),
        subnets=dict(type="list", elements="dict", options=mso_epg_subnet_spec()),
        qos_level=dict(type="str", choices=QOS_LEVEL),
        epg_type=dict(type="str", choices=["application", "service"]),
        deployment_type=dict(type="str", choices=["cloud_native", "cloud_native_managed", "third_party"]),
        service_type=dict(type="str"),
        access_type=dict(type="str", choices=["private", "public", "public_and_private"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        preferred_group=dict(type="bool"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["epg"]],
            ["state", "present", ["epg"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    description = module.params.get("description")
    display_name = module.params.get("display_name")
    bd = module.params.get("bd")
    if bd is not None and bd.get("template") is not None:
        bd["template"] = bd.get("template").replace(" ", "")
    vrf = module.params.get("vrf")
    if vrf is not None and vrf.get("template") is not None:
        vrf["template"] = vrf.get("template").replace(" ", "")
    useg_epg = module.params.get("useg_epg")
    intra_epg_isolation = module.params.get("intra_epg_isolation")
    intersite_multicast_source = module.params.get("intersite_multicast_source")
    proxy_arp = module.params.get("proxy_arp")
    subnets = module.params.get("subnets")
    qos_level = module.params.get("qos_level")
    epg_type = module.params.get("epg_type")
    deployment_type = module.params.get("deployment_type")
    service_type = module.params.get("service_type")
    access_type = module.params.get("access_type")
    state = module.params.get("state")
    preferred_group = module.params.get("preferred_group")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    # Get ANP
    anps = [a.get("name") for a in schema_obj.get("templates")[template_idx]["anps"]]
    if anp not in anps:
        mso.fail_json(msg="Provided anp '{0}' does not exist. Existing anps: {1}".format(anp, ", ".join(anps)))
    anp_idx = anps.index(anp)

    # Get EPG
    epgs = [e.get("name") for e in schema_obj.get("templates")[template_idx]["anps"][anp_idx]["epgs"]]
    if epg is not None and epg in epgs:
        epg_idx = epgs.index(epg)
        mso.existing = schema_obj.get("templates")[template_idx]["anps"][anp_idx]["epgs"][epg_idx]

    if state == "query":
        if epg is None:
            mso.existing = schema_obj.get("templates")[template_idx]["anps"][anp_idx]["epgs"]
        elif not mso.existing:
            mso.fail_json(msg="EPG '{epg}' not found".format(epg=epg))

        if "bdRef" in mso.existing:
            mso.existing["bdRef"] = mso.dict_from_ref(mso.existing["bdRef"])
        if "vrfRef" in mso.existing:
            mso.existing["vrfRef"] = mso.dict_from_ref(mso.existing["vrfRef"])
        mso.exit_json()

    epgs_path = "/templates/{0}/anps/{1}/epgs".format(template, anp)
    epg_path = "/templates/{0}/anps/{1}/epgs/{2}".format(template, anp, epg)
    service_path = "{0}/cloudServiceEpgConfig".format(epg_path)
    ops = []
    cloud_service_epg_config = {}

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=epg_path))

    elif state == "present":
        bd_ref = mso.make_reference(bd, "bd", schema_id, template)
        vrf_ref = mso.make_reference(vrf, "vrf", schema_id, template)
        subnets = mso.make_subnets(subnets, is_bd_subnet=False)

        if display_name is None and not mso.existing:
            display_name = epg

        payload = dict(
            name=epg,
            displayName=display_name,
            uSegEpg=useg_epg,
            intraEpg=intra_epg_isolation,
            mCastSource=intersite_multicast_source,
            proxyArp=proxy_arp,
            # FIXME: Missing functionality
            # uSegAttrs=[],
            subnets=subnets,
            bdRef=bd_ref,
            preferredGroup=preferred_group,
            vrfRef=vrf_ref,
        )
        if description is not None:
            payload.update(description=description)
        if qos_level is not None:
            payload.update(prio=qos_level)
        if epg_type is not None:
            payload.update(epgType=epg_type)

        mso.sanitize(payload, collate=True)

        if mso.existing:
            # Clean contractRef to fix api issue
            for contract in mso.sent.get("contractRelationships"):
                contract["contractRef"] = mso.dict_from_ref(contract.get("contractRef"))
            ops.append(dict(op="replace", path=epg_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=epgs_path + "/-", value=mso.sent))

        if epg_type == "service":
            access_type_map = {
                "private": "Private",
                "public": "Public",
                "public_and_private": "PublicAndPrivate",
            }
            deployment_type_map = {
                "cloud_native": "CloudNative",
                "cloud_native_managed": "CloudNativeManaged",
                "third_party": "Third-party",
            }
            if cloud_service_epg_config != {}:
                cloud_service_epg_config.update(
                    dict(deploymentType=deployment_type_map[deployment_type], serviceType=service_type, accessType=access_type_map[access_type])
                )
                ops.append(dict(op="replace", path=service_path, value=cloud_service_epg_config))
            else:
                cloud_service_epg_config.update(
                    dict(deploymentType=deployment_type_map[deployment_type], serviceType=service_type, accessType=access_type_map[access_type])
                )
                ops.append(dict(op="add", path=service_path, value=cloud_service_epg_config))

    mso.existing = mso.proposed

    if "epgRef" in mso.previous:
        del mso.previous["epgRef"]
    if "bdRef" in mso.previous and mso.previous["bdRef"] != "":
        mso.previous["bdRef"] = mso.dict_from_ref(mso.previous["bdRef"])
    if "vrfRef" in mso.previous and mso.previous["bdRef"] != "":
        mso.previous["vrfRef"] = mso.dict_from_ref(mso.previous["vrfRef"])

    if not module.check_mode and mso.proposed != mso.previous:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
