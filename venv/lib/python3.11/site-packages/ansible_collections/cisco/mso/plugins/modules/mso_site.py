#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_site
short_description: Manage sites
description:
- Manage sites on Cisco ACI Multi-Site.
author:
- Dag Wieers (@dagwieers)
options:
  apic_password:
    description:
    - The password for the APICs.
    - The apic_password attribute is not supported when using with ND platform.
    - See the ND collection for complete site management.
    type: str
  apic_site_id:
    description:
    - The site ID of the APICs.
    type: str
  apic_username:
    description:
    - The username for the APICs.
    - The apic_username attribute is not supported when using with ND platform.
    - See the ND collection for complete site management.
    type: str
    default: admin
  apic_login_domain:
    description:
    - The AAA login domain for the username for the APICs.
    - The apic_login_domain attribute is not supported when using with ND platform.
    - See the ND collection for complete site management.
    type: str
  site:
    description:
    - The name of the site.
    type: str
    aliases: [ name ]
  labels:
    description:
    - The labels for this site.
    - Labels that do not already exist will be automatically created.
    - The labels attribute is not supported when using with ND platform.
    - See the ND collection for complete site management.
    type: list
    elements: str
  location:
    description:
    - Location of the site.
    - The location attribute is not supported when using with ND platform.
    - See the ND collection for complete site management.
    type: dict
    suboptions:
      latitude:
        description:
        - The latitude of the location of the site.
        type: float
      longitude:
        description:
        - The longitude of the location of the site.
        type: float
  urls:
    description:
    - A list of URLs to reference the APICs.
    - The urls attribute is not supported when using with ND platform.
    - See the ND collection for complete site management.
    type: list
    elements: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new site
  cisco.mso.mso_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    site: north_europe
    description: North European Datacenter
    apic_username: mso_admin
    apic_password: AnotherSecretPassword
    apic_site_id: 12
    urls:
      - 10.2.3.4
      - 10.2.4.5
      - 10.3.5.6
    labels:
      - NEDC
      - Europe
      - Diegem
    location:
      latitude: 50.887318
      longitude: 4.447084
    state: present

- name: Remove a site
  cisco.mso.mso_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    site: north_europe
    state: absent

- name: Query a site
  cisco.mso.mso_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    site: north_europe
    state: query
  register: query_result

- name: Query all sites
  cisco.mso.mso_site:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    location_arg_spec = dict(
        latitude=dict(type="float"),
        longitude=dict(type="float"),
    )

    argument_spec = mso_argument_spec()
    argument_spec.update(
        apic_password=dict(type="str", no_log=True),
        apic_site_id=dict(type="str"),
        apic_username=dict(type="str", default="admin"),
        apic_login_domain=dict(type="str"),
        labels=dict(type="list", elements="str"),
        location=dict(type="dict", options=location_arg_spec),
        site=dict(type="str", aliases=["name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        urls=dict(type="list", elements="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["site"]],
            ["state", "present", ["apic_site_id", "site"]],
        ],
    )

    apic_username = module.params.get("apic_username")
    apic_password = module.params.get("apic_password")
    apic_site_id = module.params.get("apic_site_id")
    site = module.params.get("site")
    location = module.params.get("location")
    if location is not None:
        latitude = module.params.get("location")["latitude"]
        longitude = module.params.get("location")["longitude"]
    state = module.params.get("state")
    urls = module.params.get("urls")
    apic_login_domain = module.params.get("apic_login_domain")

    mso = MSOModule(module)

    site_id = None
    path = "sites"
    api_version = "v1"
    if mso.platform == "nd":
        api_version = "v2"

    # Convert labels
    labels = mso.lookup_labels(module.params.get("labels"), "site")

    # Query for mso.existing object(s)
    if site:
        if mso.platform == "nd":
            site_info = mso.get_obj(path, api_version=api_version, common=dict(name=site))
            path = "sites/manage"
            if site_info:
                # If we found an existing object, continue with it
                site_id = site_info.get("id")
                if site_id is not None and site_id != "":
                    # Checking if site is managed by MSO
                    mso.existing = site_info
                    path = "sites/manage/{id}".format(id=site_id)
        else:
            mso.existing = mso.get_obj(path, name=site)
            if mso.existing:
                # If we found an existing object, continue with it
                site_id = mso.existing.get("id")
                path = "sites/{id}".format(id=site_id)

    else:
        mso.existing = mso.query_objs(path, api_version=api_version)

    if state == "query":
        pass

    elif state == "absent":
        mso.previous = mso.existing
        if mso.existing:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.request(path, method="DELETE", qs=dict(force="true"), api_version=api_version)
                mso.existing = {}

    elif state == "present":
        mso.previous = mso.existing

        if mso.platform == "nd":
            if mso.existing:
                payload = mso.existing
            else:
                if site_info:
                    payload = site_info
                    payload["common"]["siteId"] = apic_site_id
                else:
                    mso.fail_json(msg="Site '{0}' is not a valid Site configured at ND-level. Add Site to ND first.".format(site))

        else:
            payload = dict(
                apicSiteId=apic_site_id,
                id=site_id,
                name=site,
                urls=urls,
                labels=labels,
                username=apic_username,
                password=apic_password,
            )

            if location is not None:
                payload["location"] = dict(
                    lat=latitude,
                    long=longitude,
                )

            if apic_login_domain is not None and apic_login_domain not in ["", "local", "Local"]:
                payload["username"] = "apic#{0}\\{1}".format(apic_login_domain, apic_username)

        mso.sanitize(payload, collate=True)

        if mso.existing:
            if mso.check_changed():
                if module.check_mode:
                    mso.existing = mso.proposed
                else:
                    mso.existing = mso.request(path, method="PUT", data=mso.sent, api_version=api_version)
        else:
            if module.check_mode:
                mso.existing = mso.proposed
            else:
                mso.existing = mso.request(path, method="POST", data=mso.sent, api_version=api_version)

    if "password" in mso.existing:
        mso.existing["password"] = "******"

    mso.exit_json()


if __name__ == "__main__":
    main()
