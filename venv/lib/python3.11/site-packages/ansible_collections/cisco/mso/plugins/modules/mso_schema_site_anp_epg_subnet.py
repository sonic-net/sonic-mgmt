#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_anp_epg_subnet
short_description: Manage site-local EPG subnets in schema template
description:
- Manage site-local EPG subnets in schema template on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
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
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
notes:
- The ACI MultiSite PATCH API has a deficiency requiring some objects to be referenced by index.
  This can cause silent corruption on concurrent access when changing/removing on object as
  the wrong object may be referenced. This module is affected by this deficiency.
seealso:
- module: cisco.mso.mso_schema_site_anp_epg
- module: cisco.mso.mso_schema_template_anp_epg_subnet
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new subnet to a site EPG
  cisco.mso.mso_schema_site_anp_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    subnet: 10.0.0.0/24
    state: present

- name: Remove a subnet from a site EPG
  cisco.mso.mso_schema_site_anp_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    subnet: 10.0.0.0/24
    state: absent

- name: Query a specific site EPG subnet
  cisco.mso.mso_schema_site_anp_epg_subnet:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    anp: ANP1
    epg: EPG1
    subnet: 10.0.0.0/24
    state: query
  register: query_result

- name: Query all site EPG subnets
  cisco.mso.mso_schema_site_anp_epg_subnet:
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
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_epg_subnet_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        anp=dict(type="str", required=True),
        epg=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )
    argument_spec.update(mso_epg_subnet_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["subnet"]],
            ["state", "present", ["subnet"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    anp = module.params.get("anp")
    epg = module.params.get("epg")
    subnet = module.params.get("subnet")
    description = module.params.get("description")
    scope = module.params.get("scope")
    shared = module.params.get("shared")
    no_default_gateway = module.params.get("no_default_gateway")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    if not schema_obj.get("sites"):
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get("siteId"), s.get("templateName")) for s in schema_obj.get("sites")]
    if (site_id, template) not in sites:
        mso.fail_json(msg="Provided site/template '{0}-{1}' does not exist. Existing sites/templates: {2}".format(site, template, ", ".join(sites)))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = "{0}-{1}".format(site_id, template)

    # Get ANP
    anp_ref = mso.anp_ref(schema_id=schema_id, template=template, anp=anp)
    anps = [a.get("anpRef") for a in schema_obj.get("sites")[site_idx]["anps"]]
    if anp_ref not in anps:
        mso.fail_json(msg="Provided anp '{0}' does not exist. Existing anps: {1}".format(anp, ", ".join(anps)))
    anp_idx = anps.index(anp_ref)

    # Get EPG
    epg_ref = mso.epg_ref(schema_id=schema_id, template=template, anp=anp, epg=epg)
    epgs = [e.get("epgRef") for e in schema_obj.get("sites")[site_idx]["anps"][anp_idx]["epgs"]]
    if epg_ref not in epgs:
        mso.fail_json(msg="Provided epg '{0}' does not exist. Existing epgs: {1}".format(epg, ", ".join(epgs)))
    epg_idx = epgs.index(epg_ref)

    # Get Subnet
    subnets = [s.get("ip") for s in schema_obj.get("sites")[site_idx]["anps"][anp_idx]["epgs"][epg_idx]["subnets"]]
    if subnet in subnets:
        subnet_idx = subnets.index(subnet)
        # FIXME: Changes based on index are DANGEROUS
        subnet_path = "/sites/{0}/anps/{1}/epgs/{2}/subnets/{3}".format(site_template, anp, epg, subnet_idx)
        mso.existing = schema_obj.get("sites")[site_idx]["anps"][anp_idx]["epgs"][epg_idx]["subnets"][subnet_idx]

    if state == "query":
        if subnet is None:
            mso.existing = schema_obj.get("sites")[site_idx]["anps"][anp_idx]["epgs"][epg_idx]["subnets"]
        elif not mso.existing:
            mso.fail_json(msg="Subnet '{subnet}' not found".format(subnet=subnet))
        mso.exit_json()

    subnets_path = "/sites/{0}/anps/{1}/epgs/{2}/subnets".format(site_template, anp, epg)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=subnet_path))

    elif state == "present":
        if not mso.existing:
            if description is None:
                description = subnet
            if scope is None:
                scope = "private"
            if shared is None:
                shared = False
            if no_default_gateway is None:
                no_default_gateway = False

        payload = dict(
            ip=subnet,
            description=description,
            scope=scope,
            shared=shared,
            noDefaultGateway=no_default_gateway,
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            ops.append(dict(op="replace", path=subnet_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=subnets_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
