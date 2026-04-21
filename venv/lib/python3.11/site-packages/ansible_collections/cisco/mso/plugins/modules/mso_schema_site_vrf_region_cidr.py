#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2020, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_vrf_region_cidr
short_description: Manage site-local VRF region CIDRs in schema template
description:
- Manage site-local VRF region CIDRs in schema template on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
- Lionel Hercot (@lhercot)
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
  vrf:
    description:
    - The name of the VRF.
    type: str
    required: true
  region:
    description:
    - The name of the region.
    type: str
    required: true
  cidr:
    description:
    - The name of the region CIDR to manage.
    type: str
    aliases: [ ip ]
  primary:
    description:
    - Whether this is the primary CIDR.
    type: bool
    default: true
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
- module: cisco.mso.mso_schema_site_vrf_region
- module: cisco.mso.mso_schema_site_vrf_region_cidr_subnet
- module: cisco.mso.mso_schema_template_vrf
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site VRF region CIDR
  cisco.mso.mso_schema_site_vrf_region_cidr:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    cidr: 14.14.14.1/24
    state: present

- name: Remove a site VRF region CIDR
  cisco.mso.mso_schema_site_vrf_region_cidr:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    cidr: 14.14.14.1/24
    state: absent

- name: Query a specific site VRF region CIDR
  cisco.mso.mso_schema_site_vrf_region_cidr:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    cidr: 14.14.14.1/24
    state: query
  register: query_result

- name: Query all site VRF region CIDR
  cisco.mso.mso_schema_site_vrf_region_cidr:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    site: Site1
    template: Template1
    vrf: VRF1
    region: us-west-1
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        site=dict(type="str", required=True),
        template=dict(type="str", required=True),
        vrf=dict(type="str", required=True),
        region=dict(type="str", required=True),
        cidr=dict(type="str", aliases=["ip"]),  # This parameter is not required for querying all objects
        primary=dict(type="bool", default=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["cidr"]],
            ["state", "present", ["cidr"]],
        ],
    )

    schema = module.params.get("schema")
    site = module.params.get("site")
    template = module.params.get("template").replace(" ", "")
    vrf = module.params.get("vrf")
    region = module.params.get("region")
    cidr = module.params.get("cidr")
    primary = module.params.get("primary")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema objects
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    payload = dict()
    op_path = ""
    cidr_path = None
    new_cidr = dict(
        ip=cidr,
        primary=primary,
    )

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    all_sites = schema_obj.get("sites")
    sites = []
    if all_sites is not None:
        sites = [(s.get("siteId"), s.get("templateName")) for s in all_sites]

    # Get VRF
    vrf_ref = mso.vrf_ref(schema_id=schema_id, template=template, vrf=vrf)
    template_vrfs = [a.get("name") for a in schema_obj["templates"][template_idx]["vrfs"]]
    if vrf not in template_vrfs:
        mso.fail_json(msg="Provided vrf '{0}' does not exist. Existing vrfs: {1}".format(vrf, ", ".join(template_vrfs)))

    # if site-template does not exist, create it
    if (site_id, template) not in sites:
        op_path = "/sites/-"
        payload.update(
            siteId=site_id,
            templateName=template,
            vrfs=[
                dict(
                    vrfRef=dict(
                        schemaId=schema_id,
                        templateName=template,
                        vrfName=vrf,
                    ),
                    regions=[dict(name=region, cidrs=[new_cidr])],
                )
            ],
        )

    else:
        # Schema-access uses indexes
        site_idx = sites.index((site_id, template))
        # Path-based access uses site_id-template
        site_template = "{0}-{1}".format(site_id, template)

        # If vrf not at site level but exists at template level
        vrfs = [v.get("vrfRef") for v in schema_obj.get("sites")[site_idx]["vrfs"]]
        if vrf_ref not in vrfs:
            op_path = "/sites/{0}/vrfs/-".format(site_template)
            payload.update(
                vrfRef=dict(
                    schemaId=schema_id,
                    templateName=template,
                    vrfName=vrf,
                ),
                regions=[dict(name=region, cidrs=[new_cidr])],
            )
        else:
            # Update vrf index at site level
            vrf_idx = vrfs.index(vrf_ref)

            # Get Region
            regions = [r.get("name") for r in schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"]]
            if region not in regions:
                op_path = "/sites/{0}/vrfs/{1}/regions/-".format(site_template, vrf)
                payload.update(name=region, cidrs=[new_cidr])
            else:
                region_idx = regions.index(region)

                # Get CIDR
                cidrs = [c.get("ip") for c in schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"][region_idx]["cidrs"]]
                if cidr is not None:
                    if cidr in cidrs:
                        cidr_idx = cidrs.index(cidr)
                        # FIXME: Changes based on index are DANGEROUS
                        cidr_path = "/sites/{0}/vrfs/{1}/regions/{2}/cidrs/{3}".format(site_template, vrf, region, cidr_idx)
                        mso.existing = schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"][region_idx]["cidrs"][cidr_idx]
                    op_path = "/sites/{0}/vrfs/{1}/regions/{2}/cidrs/-".format(site_template, vrf, region)
                    payload = new_cidr

    if state == "query":
        if (site_id, template) not in sites:
            mso.fail_json(msg="Provided site-template association '{0}-{1}' does not exist.".format(site, template))
        elif vrf_ref not in vrfs:
            mso.fail_json(msg="Provided vrf '{0}' does not exist at site level.".format(vrf))
        elif not regions or region not in regions:
            mso.fail_json(msg="Provided region '{0}' does not exist. Existing regions: {1}".format(region, ", ".join(regions)))
        elif cidr is None and not payload:
            mso.existing = schema_obj.get("sites")[site_idx]["vrfs"][vrf_idx]["regions"][region_idx]["cidrs"]
        elif not mso.existing:
            mso.fail_json(msg="CIDR IP '{cidr}' not found".format(cidr=cidr))
        mso.exit_json()

    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing and cidr_path:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=cidr_path))

    elif state == "present":
        mso.sanitize(payload, collate=True)

        if mso.existing and cidr_path:
            ops.append(dict(op="replace", path=cidr_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=op_path, value=mso.sent))

        mso.existing = new_cidr

    if not module.check_mode and mso.previous != mso.existing:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
