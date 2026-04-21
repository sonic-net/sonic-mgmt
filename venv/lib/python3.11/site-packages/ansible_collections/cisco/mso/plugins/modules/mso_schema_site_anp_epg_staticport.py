#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# Copyright: (c) 2024, Noppanut Ploywong (@noppanut15) <noppanut.connect@gmail.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_anp_epg_staticport
short_description: Manage site-local EPG static ports in schema template
description:
- Manage site-local EPG static ports in schema template on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Akini Ross (@akinross)
- Noppanut Ploywong (@noppanut15)
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
    - C(vpc) is used for a Virtual Port Channel
    - C(dpc) is used for a Direct Port Channel
    - C(port) is used for a single interface
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
  force_replace:
    description:
    - Replaces all the configured static port(s) with the provided static port(s).
    - This option can only be used in combination with the O(static_ports) option.
    - In combination with the O(state=absent) and without any static port configuration all configured static port(s) will be removed.
    type: bool
  static_ports:
    description:
    - A list of Static Ports associated to this EPG.
    - All configured Static Ports will be replaced with the provided Static Ports when used with O(force_replace=true).
    - Only the provided Static Ports will be added, updated or removed when used with O(force_replace=false).
    - In combination with the O(state=query) all provided Static Ports must be found else the task will fail.
    - When I(static_ports) attributes are not provided the module attributes will be used.
    - For each Static Ports provided in the list, the following attributes must be resolved
    - I(static_ports.type)
    - I(static_ports.pod)
    - I(static_ports.leaf)
    - I(static_ports.path)
    - I(static_ports.vlan)
    type: list
    elements: dict
    suboptions:
      type:
        description:
        - The path type of the static port
        - C(vpc) is used for a Virtual Port Channel
        - C(dpc) is used for a Direct Port Channel
        - C(port) is used for a single interface
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
        type: str
      vlan:
        description:
        - The port encapsulation VLAN id of the static port.
        type: int
      deployment_immediacy:
        description:
        - The deployment immediacy of the static port.
        - C(immediate) means B(Deploy immediate).
        - C(lazy) means B(Deploy on demand).
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
        - Primary micro-seg VLAN of static port.
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
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new static port to a site EPG
  cisco.mso.mso_schema_site_anp_epg_staticport:
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
    state: present

- name: Add a new static fex port to a site EPG
  mso_schema_site_anp_epg_staticport:
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
    fex: 151
    path: eth1/1
    vlan: 126
    deployment_immediacy: lazy
    state: present

- name: Add a new static VPC to a site EPG
  mso_schema_site_anp_epg_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    pod: pod-1
    leaf: 101-102
    path: ansible_polgrp
    vlan: 127
    type: vpc
    mode: untagged
    deployment_immediacy: lazy
    state: present

- name: Add two new static port to a site EPG
  cisco.mso.mso_schema_site_anp_epg_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    static_ports:
      - pod: pod-1
        leaf: 101
        path: eth1/1
        vlan: 126
      - pod: pod-2
        leaf: 101
        path: eth2/1
        vlan: 128
    deployment_immediacy: immediate
    state: present

- name: Replace all existing static pors on a site EPG with 2 new static ports
  cisco.mso.mso_schema_site_anp_epg_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    force_replace: true
    static_ports:
      - pod: pod-1
        leaf: 101
        path: eth1/1
        vlan: 126
      - pod: pod-2
        leaf: 101
        path: eth2/1
        vlan: 128
    deployment_immediacy: immediate
    state: present

- name: Query a specific site EPG static port
  cisco.mso.mso_schema_site_anp_epg_staticport:
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
    state: query
  register: query_result

- name: Query a list of static ports
  cisco.mso.mso_schema_site_anp_epg_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    static_ports:
      - pod: pod-1
        leaf: 101
        path: eth1/1
        vlan: 126
      - pod: pod-2
        leaf: 101
        path: eth2/1
        vlan: 128
    state: query
  register: query_result

- name: Query all site EPG static ports
  cisco.mso.mso_schema_site_anp_epg_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    state: query
  register: query_result

- name: Remove a static port from a site EPG
  cisco.mso.mso_schema_site_anp_epg_staticport:
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
    state: absent

- name: Remove two static ports from a site EPG
  cisco.mso.mso_schema_site_anp_epg_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    static_ports:
      - pod: pod-1
        leaf: 101
        path: eth1/1
        vlan: 126
      - pod: pod-2
        leaf: 101
        path: eth2/1
        vlan: 128
    deployment_immediacy: immediate
    state: absent

- name: Remove all existing static pors from a site EPG
  cisco.mso.mso_schema_site_anp_epg_staticport:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    force_replace: true
    state: absent
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
        force_replace=dict(type="bool"),
        type=dict(type="str", default="port", choices=["port", "vpc", "dpc"]),
        pod=dict(type="str"),
        leaf=dict(type="str"),
        fex=dict(type="str"),
        path=dict(type="str"),
        vlan=dict(type="int"),
        primary_micro_segment_vlan=dict(type="int"),
        deployment_immediacy=dict(type="str", default="lazy", choices=["immediate", "lazy"]),
        mode=dict(type="str", default="untagged", choices=["native", "regular", "untagged"]),
        static_ports=dict(type="list", elements="dict", options=mso_site_anp_epg_bulk_staticport_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    path_type = module.params.get("type")
    pod = module.params.get("pod")
    leaf = module.params.get("leaf")
    fex = module.params.get("fex")
    path = module.params.get("path")
    vlan = module.params.get("vlan")
    primary_micro_segment_vlan = module.params.get("primary_micro_segment_vlan")
    deployment_immediacy = module.params.get("deployment_immediacy")
    mode = module.params.get("mode")
    force_replace = module.params.get("force_replace")
    static_ports = module.params.get("static_ports")
    state = module.params.get("state")

    if not static_ports and state in ["present", "absent"]:
        if state == "absent":
            # The state absent requires at least the pod, leaf and path to be provided
            key_list = ["pod", "leaf", "path"]
        else:
            # The state present requires all the key_list to be provided
            key_list = ["pod", "leaf", "path", "vlan"]
        required_missing = [key for key in key_list if module.params.get(key)]
        if len(required_missing) != len(key_list) and not (len(required_missing) == 0 and state == "absent" and force_replace):
            module.fail_json(
                msg="state is present or absent but all of the following are missing: {0}.".format(
                    ", ".join([key for key in key_list if not module.params.get(key)]),
                )
            )

    mso = MSOModule(module)

    mso_schema = MSOSchema(mso, schema, template, site)
    mso_schema.set_template_anp(anp)
    mso_schema.set_template_anp_epg(epg)
    mso_schema.set_site_anp(anp, False)
    mso_schema.set_site_anp_epg(epg, False)

    ops = []

    # Create missing site anp and site epg if not present
    # Logic is only needed for NDO version below 4.x when validate false flag was still available
    # This did not trigger the auto creation of site anp and site epg during template anp and epg creation or ataching site to template
    # Coverage misses this two conditionals when testing on 4.x and above
    if state == "present" and not mso_schema.schema_objects.get("site_anp"):
        ops.append(
            dict(
                op="add",
                path="/sites/{0}-{1}/anps/-".format(mso_schema.schema_objects.get("site").details.get("siteId"), template),
                value=dict(epgRef=dict(schemaId=mso_schema.id, templateName=template, anpName=anp, epgName=epg)),
            )
        )

    if state == "present" and not mso_schema.schema_objects.get("site_anp_epg"):
        ops.append(
            dict(
                op="add",
                path="/sites/{0}-{1}/anps/{2}/epgs/-".format(mso_schema.schema_objects.get("site").details.get("siteId"), template, anp),
                value=dict(anpRef=dict(schemaId=mso_schema.id, templateName=template, anpName=anp)),
            )
        )

    static_ports_path = "/sites/{0}-{1}/anps/{2}/epgs/{3}/staticPorts".format(
        mso_schema.schema_objects.get("site").details.get("siteId"),
        template,
        anp,
        epg,
    )
    static_port_path = "{0}/-".format(static_ports_path)

    full_paths = []
    if static_ports:
        found_static_ports = []
        found_full_paths = []
        set_existing_static_ports(mso, mso_schema, full_paths)
        for static_port in static_ports:
            overwrite_static_path_unprovided_attributes(
                state, mso, static_port, path_type, pod, leaf, fex, path, vlan, primary_micro_segment_vlan, deployment_immediacy, mode
            )
            full_path = get_full_static_path(
                static_port.get("type"), static_port.get("pod"), static_port.get("leaf"), static_port.get("fex"), static_port.get("path")
            )
            mso_schema.set_site_anp_epg_static_port(full_path, False)
            if mso_schema.schema_objects.get("site_anp_epg_static_port") is not None:
                found_static_ports.append(mso_schema.schema_objects["site_anp_epg_static_port"].details)
                found_full_paths.append(full_path)

    elif (path_type and pod and leaf and path) and (vlan or (state == "absent")):
        full_path = get_full_static_path(path_type, pod, leaf, fex, path)
        mso_schema.set_site_anp_epg_static_port(full_path, False)
        if mso_schema.schema_objects.get("site_anp_epg_static_port") is not None:
            mso.existing = mso_schema.schema_objects["site_anp_epg_static_port"].details
            static_port_path = "{0}/{1}".format(static_ports_path, mso_schema.schema_objects["site_anp_epg_static_port"].index)
    else:
        set_existing_static_ports(mso, mso_schema, full_paths)

    if state == "query":
        if static_ports:
            if len(found_static_ports) == len(static_ports):
                mso.existing = found_static_ports
            else:
                configured_static_ports = [
                    get_full_static_path(
                        static_port.get("type"), static_port.get("pod"), static_port.get("leaf"), static_port.get("fex"), static_port.get("path")
                    )
                    for index, static_port in enumerate(static_ports)
                ]
                not_found_static_ports = [
                    "Provided Static Port Path '{0}' not found".format(static_port)
                    for static_port in configured_static_ports
                    if static_port not in found_full_paths
                ]
                mso.fail_json(msg=not_found_static_ports)
        elif not mso.existing and full_path:
            mso.fail_json(msg="Provided Static Port Path '{0}' not found".format(full_path))
        mso.exit_json()

    mso.previous = mso.existing

    if state == "absent" and mso.existing:
        if static_ports and not force_replace:
            mso.proposed = mso.existing.copy()
            remove_index = []
            for found_full_path in found_full_paths:
                if found_full_path in full_paths:
                    index = full_paths.index(found_full_path)
                    remove_index.append(index)
            # The list index should not shift when removing static ports from the list
            # By sorting the indexes found in reverse order, we assure that the highest index is removed first by the NDO backend
            # This logic is to avoid removing the wrong static ports
            for index in reversed(sorted(remove_index)):
                mso.proposed.pop(index)
                ops.append(dict(op="remove", path="{0}/{1}".format(static_ports_path, index)))
            mso.sent = mso.proposed
        elif not force_replace:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=static_port_path))
        else:
            mso.sent = mso.proposed = mso.existing = []
            ops.append(dict(op="remove", path=static_ports_path))

    elif state == "present":
        if static_ports and force_replace:
            mso.sent = mso.proposed = [
                get_static_port_payload(
                    get_full_static_path(
                        static_port.get("type"),
                        static_port.get("pod"),
                        static_port.get("leaf"),
                        static_port.get("fex"),
                        static_port.get("path"),
                    ),
                    static_port.get("deployment_immediacy"),
                    static_port.get("mode"),
                    static_port.get("vlan"),
                    static_port.get("type"),
                    static_port.get("primary_micro_segment_vlan"),
                )
                for static_port in static_ports
            ]
            if mso.existing:
                ops.append(dict(op="replace", path=static_ports_path, value=mso.sent))
            else:
                ops.append(dict(op="add", path=static_ports_path, value=mso.sent))
        elif static_ports:
            mso.sent = mso.proposed = mso.existing.copy()
            for static_port in static_ports:
                full_path = get_full_static_path(
                    static_port.get("type"), static_port.get("pod"), static_port.get("leaf"), static_port.get("fex"), static_port.get("path")
                )
                payload = get_static_port_payload(
                    full_path,
                    static_port.get("deployment_immediacy"),
                    static_port.get("mode"),
                    static_port.get("vlan"),
                    static_port.get("type"),
                    static_port.get("primary_micro_segment_vlan"),
                )
                if full_path not in found_full_paths:
                    ops.append(dict(op="add", path=static_port_path, value=payload))
                    mso.proposed.append(payload)
                else:
                    index = full_paths.index(full_path)
                    mso.proposed[index] = payload
                    ops.append(dict(op="replace", path="{0}/{1}".format(static_ports_path, index), value=payload))
        else:
            payload = get_static_port_payload(full_path, deployment_immediacy, mode, vlan, path_type, primary_micro_segment_vlan)
            mso.sanitize(payload, collate=True)
            if mso.existing:
                ops.append(dict(op="replace", path=static_port_path, value=mso.sent))
            else:
                ops.append(dict(op="add", path=static_port_path, value=mso.sent))
            mso.existing = payload

    mso.existing = mso.proposed

    if not module.check_mode and mso.proposed != mso.previous:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


def set_existing_static_ports(mso, mso_schema, full_paths):
    mso.existing = []
    if mso_schema.schema_objects.get("site_anp_epg"):
        for existing_static_port in mso_schema.schema_objects["site_anp_epg"].details.get("staticPorts"):
            full_paths.append(existing_static_port.get("path"))
            mso.existing.append(existing_static_port)


def get_static_port_payload(full_path, deployment_immediacy, mode, vlan, path_type, primary_micro_segment_vlan):
    payload = dict(
        deploymentImmediacy=deployment_immediacy,
        mode=mode,
        path=full_path,
        portEncapVlan=vlan,
        type=path_type,
    )
    if primary_micro_segment_vlan:
        payload.update(microSegVlan=primary_micro_segment_vlan)
    return payload


def get_full_static_path(path_type, pod, leaf, fex, path):
    if path_type == "port" and fex is not None:
        return "topology/{0}/paths-{1}/extpaths-{2}/pathep-[{3}]".format(pod, leaf, fex, path)
    elif path_type == "vpc":
        return "topology/{0}/protpaths-{1}/pathep-[{2}]".format(pod, leaf, path)
    else:
        return "topology/{0}/paths-{1}/pathep-[{2}]".format(pod, leaf, path)


def overwrite_static_path_unprovided_attributes(state, mso, static_path, path_type, pod, leaf, fex, path, vlan, micro_vlan, deployment_immediacy, mode):
    required_overwrites = []
    if not static_path.get("type"):
        static_path["type"] = path_type
    if not static_path.get("pod"):
        static_path["pod"] = pod
        if not pod:
            required_overwrites.append("pod")
    if not static_path.get("leaf"):
        static_path["leaf"] = leaf
        if not leaf:
            required_overwrites.append("leaf")
    if not static_path.get("fex"):
        static_path["fex"] = fex
    if not static_path.get("path"):
        static_path["path"] = path
        if not path:
            required_overwrites.append("path")
    if not static_path.get("vlan"):
        static_path["vlan"] = vlan
        if not vlan and state != "absent":
            # The vlan is not required when the state is absent
            required_overwrites.append("vlan")
    if not static_path.get("primary_micro_segment_vlan"):
        static_path["primary_micro_segment_vlan"] = micro_vlan
    if not static_path.get("deployment_immediacy"):
        static_path["deployment_immediacy"] = deployment_immediacy
    if not static_path.get("mode"):
        static_path["mode"] = mode

    if required_overwrites:
        mso.fail_json(msg="state is present but all of the following are missing: {0}.".format(", ".join(required_overwrites)))


if __name__ == "__main__":
    main()
