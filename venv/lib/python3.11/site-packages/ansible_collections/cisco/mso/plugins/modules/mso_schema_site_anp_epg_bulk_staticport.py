#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_anp_epg_bulk_staticport
short_description: Manage site-local EPG static ports in bulk in schema template
description:
- Manage site-local EPG static ports in bulk in schema template on Cisco ACI Multi-Site.
author:
- Anvitha Jain (@anvjain)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  site:
    description:
    - The name of the site.
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
    - The name of the EPG.
    type: str
    required: true
  type:
    description:
    - The path type of the static port
    - vpc is used for a Virtual Port Channel
    - dpc is used for a Direct Port Channel
    - port is used for a single interface
    type: str
    choices: [ port, vpc, dpc ]
    default: port
  pod:
    description:
    - The pod of the static port.
    type: str
  leaf:
    description:
    - The leaf of the static port.
    type: str
  fex:
    description:
    - The fex id of the static port.
    type: str
  path:
    description:
    - The path of the static port.
    type: str
  vlan:
    description:
    - The port encap VLAN id of the static port.
    type: int
  deployment_immediacy:
    description:
    - The deployment immediacy of the static port.
    - C(immediate) means B(Deploy immediate).
    - C(lazy) means B(deploy on demand).
    type: str
    choices: [ immediate, lazy ]
    default: lazy
  mode:
    description:
    - The mode of the static port.
    - C(native) means B(Access (802.1p)).
    - C(regular) means B(Trunk).
    - C(untagged) means B(Access (untagged)).
    type: str
    choices: [ native, regular, untagged ]
    default: untagged
  primary_micro_segment_vlan:
    description:
    - Primary micro-seg VLAN of static port.
    type: int
  static_ports:
    description:
    - List of static port configurations and elements in the form of a dictionary.
    - Module level attributes will be overridden by the path level attributes.
    - Making changes to an item in the list will update the whole payload.
    type: list
    elements: dict
    suboptions:
      type:
        description:
        - The path type of the static port
        - vpc is used for a Virtual Port Channel
        - dpc is used for a Direct Port Channel
        - port is used for a single interface
        type: str
        choices: [ port, vpc, dpc ]
      pod:
        description:
        - The pod of the static port.
        type: str
      leaf:
        description:
        - The leaf of the static port.
        type: str
      fex:
        description:
        - The fex id of the static port.
        type: str
      path:
        description:
        - The path of the static port.
        - Path has to be unique for each static port in a particular leaf.
        type: str
      vlan:
        description:
        - The port encap VLAN id of the static port.
        type: int
      deployment_immediacy:
        description:
        - The deployment immediacy of the static port.
        - C(immediate) means B(Deploy immediate).
        - C(lazy) means B(deploy on demand).
        type: str
        choices: [ immediate, lazy ]
      mode:
        description:
        - The mode of the static port.
        - C(native) means B(Access (802.1p)).
        - C(regular) means B(Trunk).
        - C(untagged) means B(Access (untagged)).
        type: str
        choices: [ native, regular, untagged ]
      primary_micro_segment_vlan:
        description:
        - Primary micro-seg VLAN of the static port.
        type: int
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The ACI MultiSite PATCH API has a deficiency requiring some objects to be referenced by index.
  This can cause silent corruption on concurrent access when changing/removing an object as
  the wrong object may be referenced. This module is affected by this deficiency.
seealso:
- module: cisco.mso.mso_schema_site_anp_epg
- module: cisco.mso.mso_schema_template_anp_epg
deprecated:
  removed_in: 3.0.0
  alternative: Use M(cisco.mso.mso_schema_site_anp_epg_staticport) with option `force_replace=true` instead.
  why: The module has been merged to centralise all static port functionality into M(cisco.mso.mso_schema_site_anp_epg_staticport).
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new static port to a site EPG
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    type: port
    pod: pod-1
    leaf: 101
    path: eth1/1
    vlan: 126
    deployment_immediacy: immediate
    static_ports:
      - path: eth1/2
        leaf: 102
      - path: eth1/3
        vlan: 124
    state: present

- name: Add a new static fex port to a site EPG
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    type: port
    pod: pod-1
    leaf: 101
    path: eth1/1
    vlan: 126
    deployment_immediacy: lazy
    static_ports:
      - path: eth1/2
        leaf: 102
      - path: eth1/3
        vlan: 124
      - fex: 151
    state: present

- name: Add a new static VPC to a site EPG
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    type: port
    pod: pod-1
    leaf: 101
    path: eth1/1
    vlan: 126
    static_ports:
      - path: eth1/2
        leaf: 102
      - path: eth1/3
        vlan: 124
      - fex: 151
      - leaf: 101-102
        path: ansible_polgrp
        vlan: 127
        type: vpc
        mode: untagged
        deployment_immediacy: lazy
    state: present

- name: Remove static ports from a site EPG
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    state: absent

- name: Query all site EPG static ports
  cisco.mso.mso_schema_site_anp_epg_bulk_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_site_anp_epg_bulk_staticport_spec
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        epg=dict(type="str", required=True),
        type=dict(type="str", default="port", choices=["port", "vpc", "dpc"]),
        pod=dict(type="str"),  # This parameter is not required for querying all objects
        leaf=dict(type="str"),  # This parameter is not required for querying all objects
        fex=dict(type="str"),  # This parameter is not required for querying all objects
        path=dict(type="str"),  # This parameter is not required for querying all objects
        vlan=dict(type="int"),  # This parameter is not required for querying all objects
        primary_micro_segment_vlan=dict(type="int"),  # This parameter is not required for querying all objects
        deployment_immediacy=dict(type="str", default="lazy", choices=["immediate", "lazy"]),
        mode=dict(type="str", default="untagged", choices=["native", "regular", "untagged"]),
        static_ports=dict(type="list", elements="dict", options=mso_site_anp_epg_bulk_staticport_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["static_ports"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    module_path_type = module.params.get("type")
    module_pod = module.params.get("pod")
    module_leaf = module.params.get("leaf")
    module_fex = module.params.get("fex")
    module_path = module.params.get("path")
    module_vlan = module.params.get("vlan")
    module_primary_micro_segment_vlan = module.params.get("primary_micro_segment_vlan")
    module_deployment_immediacy = module.params.get("deployment_immediacy")
    module_mode = module.params.get("mode")
    static_ports = module.params.get("static_ports")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    mso_schema = MSOSchema(mso, schema, template, site)
    mso_objects = mso_schema.schema_objects

    # Verifies ANP  and EPG exists at template level
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_epg(epg)

    # Verifies if ANP exists at site level
    mso_schema.set_site_anp(anp, fail_module=False)

    payload = dict()
    ops = []
    op_path = "/sites/{0}-{1}/anps".format(mso_objects.get("site").details.get("siteId"), template)
    mso.existing = []

    # If anp not at site level but exists at template level
    if not mso_objects.get("site_anp"):
        op_path = op_path + "/-"
        payload.update(
            anpRef=dict(
                schemaId=mso_schema.id,
                templateName=template,
                anpName=anp,
            ),
        )
    else:
        mso_schema.set_site_anp_epg(epg, fail_module=False)

    # If epg not at site level (or) anp not at site level payload
    if not mso_objects.get("site_anp_epg") or "anpRef" in payload:
        # EPG at template level but not at site level. Create payload at site level for EPG
        new_epg = dict(
            epgRef=dict(
                schemaId=mso_schema.id,
                templateName=template,
                anpName=anp,
                epgName=epg,
            )
        )

        # If anp not in payload then, anp already exists at site level. New payload will only have new EPG payload
        if "anpRef" not in payload:
            op_path = "{0}/{1}/epgs/-".format(op_path, anp)
            payload = new_epg
        else:
            # If anp in payload, anp exists at site level. Update payload with EPG payload
            payload["epgs"] = [new_epg]
    else:
        # If anp and epg exists at site level
        op_path = "{0}/{1}/epgs/{2}/staticPorts".format(op_path, anp, epg)
        mso.existing = mso_objects.get("site_anp_epg").details.get("staticPorts", [])

    staticport_list = []
    unique_paths = []

    mso.previous = mso.existing

    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = []
            ops.append(dict(op="remove", path=op_path))

    elif state == "present":
        for static_port in static_ports:
            path_type = static_port.get("type") or module_path_type
            pod = static_port.get("pod") or module_pod
            leaf = static_port.get("leaf") or module_leaf
            fex = static_port.get("fex") or module_fex
            path = static_port.get("path") or module_path  # Note :path has to be diffent in each leaf for every static port in the list.
            vlan = static_port.get("vlan") or module_vlan
            primary_micro_segment_vlan = static_port.get("primary_micro_segment_vlan") or module_primary_micro_segment_vlan
            deployment_immediacy = static_port.get("deployment_immediacy") or module_deployment_immediacy
            mode = static_port.get("mode") or module_mode

            required_dict = {"pod": pod, "leaf": leaf, "path": path, "vlan": vlan}
            if None in required_dict.values():
                res = [key for key in required_dict.keys() if required_dict[key] is None]
                mso.fail_json(msg="state is present but all of the following are missing: {0}.".format(", ".join(res)))
            else:
                if path_type == "port" and fex is not None:
                    # Select port path for fex if fex param is used
                    portpath = "topology/{0}/paths-{1}/extpaths-{2}/pathep-[{3}]".format(pod, leaf, fex, path)
                elif path_type == "vpc":
                    portpath = "topology/{0}/protpaths-{1}/pathep-[{2}]".format(pod, leaf, path)
                else:
                    portpath = "topology/{0}/paths-{1}/pathep-[{2}]".format(pod, leaf, path)

            new_leaf = dict(
                deploymentImmediacy=deployment_immediacy,
                mode=mode,
                path=portpath,
                portEncapVlan=vlan,
                type=path_type,
            )

            if primary_micro_segment_vlan:
                new_leaf.update(microSegVlan=primary_micro_segment_vlan)

            # validate and append staticports to staticport_list if path variable is different
            if portpath in unique_paths:
                mso.fail_json(msg="Each leaf in a pod of a static port should have an unique path.")
            else:
                unique_paths.append(portpath)
                staticport_list.append(new_leaf)

        # If payload is empty, anp and EPG already exist at site level
        if not payload:
            payload = staticport_list
        elif "anpRef" not in payload:  # If anp already exists at site level
            payload["staticPorts"] = staticport_list
        else:
            payload["epgs"][0]["staticPorts"] = staticport_list

        mso.proposed = staticport_list
        mso.sent = payload

        if mso.existing:
            ops.append(dict(op="replace", path=op_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=op_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode and mso.proposed != mso.previous:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
