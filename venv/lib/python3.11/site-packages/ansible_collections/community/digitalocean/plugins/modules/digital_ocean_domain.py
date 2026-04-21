#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_domain
short_description: Create/delete a DNS domain in DigitalOcean
description:
     - Create/delete a DNS domain in DigitalOcean.
author: "Michael Gregson (@mgregson)"
options:
  state:
    description:
    - Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
    type: str
  id:
    description:
    - The droplet id you want to operate on.
    aliases: ['droplet_id']
    type: int
  name:
    description:
    - The name of the droplet - must be formatted by hostname rules, or the name of a SSH key, or the name of a domain.
    type: str
  ip:
    description:
    - An 'A' record for '@' ($ORIGIN) will be created with the value 'ip'.  'ip' is an IP version 4 address.
    type: str
    aliases: ['ip4', 'ipv4']
  ip6:
    description:
    - An 'AAAA' record for '@' ($ORIGIN) will be created with the value 'ip6'.  'ip6' is an IP version 6 address.
    type: str
    aliases: ['ipv6']
  project_name:
    aliases: ["project"]
    description:
    - Project to assign the resource to (project name, not UUID).
    - Defaults to the default project of the account (empty string).
    - Currently only supported when creating domains.
    type: str
    required: false
    default: ""
extends_documentation_fragment:
- community.digitalocean.digital_ocean.documentation

notes:
  - Environment variables DO_OAUTH_TOKEN can be used for the oauth_token.
  - As of Ansible 1.9.5 and 2.0, Version 2 of the DigitalOcean API is used, this removes C(client_id) and C(api_key) options in favor of C(oauth_token).
  - If you are running Ansible 1.9.4 or earlier you might not be able to use the included version of this module as the API version used has been retired.

requirements:
  - "python >= 2.6"
"""


EXAMPLES = r"""
- name: Create a domain
  community.digitalocean.digital_ocean_domain:
    state: present
    name: my.digitalocean.domain
    ip: 127.0.0.1

- name: Create a domain (and associate to Project "test")
  community.digitalocean.digital_ocean_domain:
    state: present
    name: my.digitalocean.domain
    ip: 127.0.0.1
    project: test

# Create a droplet and corresponding domain
- name: Create a droplet
  community.digitalocean.digital_ocean:
    state: present
    name: test_droplet
    size_id: 1gb
    region_id: sgp1
    image_id: ubuntu-14-04-x64
  register: test_droplet

- name: Create a corresponding domain
  community.digitalocean.digital_ocean_domain:
    state: present
    name: "{{ test_droplet.droplet.name }}.my.domain"
    ip: "{{ test_droplet.droplet.ip_address }}"

"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
    DigitalOceanProjects,
)
import time

ZONE_FILE_ATTEMPTS = 5
ZONE_FILE_SLEEP = 3


class DoManager(DigitalOceanHelper, object):
    def __init__(self, module):
        super(DoManager, self).__init__(module)
        self.domain_name = module.params.get("name", None)
        self.domain_ip = module.params.get("ip", None)
        self.domain_id = module.params.get("id", None)

    @staticmethod
    def jsonify(response):
        return response.status_code, response.json

    def all_domains(self):
        resp = self.get_paginated_data(base_url="domains?", data_key_name="domains")
        return resp

    def find(self):
        if self.domain_name is None and self.domain_id is None:
            return None

        domains = self.all_domains()
        for domain in domains:
            if domain["name"] == self.domain_name:
                return domain
        return None

    def add(self):
        params = {"name": self.domain_name, "ip_address": self.domain_ip}
        resp = self.post("domains/", data=params)
        status = resp.status_code
        json = resp.json
        if status == 201:
            return json["domain"]
        else:
            return json

    def all_domain_records(self):
        resp = self.get("domains/%s/records/" % self.domain_name)
        return resp.json

    def domain_record(self):
        resp = self.get("domains/%s" % self.domain_name)
        status, json = self.jsonify(resp)
        return json

    def destroy_domain(self):
        resp = self.delete("domains/%s" % self.domain_name)
        status, json = self.jsonify(resp)
        if status == 204:
            return True
        else:
            return json

    def edit_domain_record(self, record):
        if self.module.params.get("ip"):
            params = {"name": "@", "data": self.module.params.get("ip")}
        if self.module.params.get("ip6"):
            params = {"name": "@", "data": self.module.params.get("ip6")}

        resp = self.put(
            "domains/%s/records/%s" % (self.domain_name, record["id"]), data=params
        )
        status, json = self.jsonify(resp)

        return json["domain_record"]

    def create_domain_record(self):
        if self.module.params.get("ip"):
            params = {"name": "@", "type": "A", "data": self.module.params.get("ip")}
        if self.module.params.get("ip6"):
            params = {
                "name": "@",
                "type": "AAAA",
                "data": self.module.params.get("ip6"),
            }

        resp = self.post("domains/%s/records" % (self.domain_name), data=params)
        status, json = self.jsonify(resp)

        return json["domain_record"]


def run(module):
    do_manager = DoManager(module)
    state = module.params.get("state")

    if module.params.get("project_name"):
        # only load for non-default project assignments
        projects = DigitalOceanProjects(module, do_manager)

    domain = do_manager.find()
    if state == "present":
        if not domain:
            domain = do_manager.add()
            if "message" in domain:
                module.fail_json(changed=False, msg=domain["message"])
            else:
                # We're at the mercy of a backend process which we have no visibility into:
                # https://docs.digitalocean.com/reference/api/api-reference/#operation/create_domain
                #
                # In particular: "Keep in mind that, upon creation, the zone_file field will
                # have a value of null until a zone file is generated and propagated through
                # an automatic process on the DigitalOcean servers."
                #
                # Arguably, it's nice to see the records versus null, so, we'll just try a
                # few times before giving up and returning null.

                domain_name = module.params.get("name")
                project_name = module.params.get("project_name")
                urn = "do:domain:{0}".format(domain_name)

                for i in range(ZONE_FILE_ATTEMPTS):
                    record = do_manager.domain_record()
                    if record is not None and "domain" in record:
                        domain = record.get("domain", None)
                        if domain is not None and "zone_file" in domain:
                            if (
                                project_name
                            ):  # empty string is the default project, skip project assignment
                                (
                                    assign_status,
                                    error_message,
                                    resources,
                                ) = projects.assign_to_project(project_name, urn)
                                module.exit_json(
                                    changed=True,
                                    domain=domain,
                                    msg=error_message,
                                    assign_status=assign_status,
                                    resources=resources,
                                )
                            else:
                                module.exit_json(changed=True, domain=domain)
                    time.sleep(ZONE_FILE_SLEEP)
                if (
                    project_name
                ):  # empty string is the default project, skip project assignment
                    (
                        assign_status,
                        error_message,
                        resources,
                    ) = projects.assign_to_project(project_name, urn)
                    module.exit_json(
                        changed=True,
                        domain=domain,
                        msg=error_message,
                        assign_status=assign_status,
                        resources=resources,
                    )
                else:
                    module.exit_json(changed=True, domain=domain)
        else:
            records = do_manager.all_domain_records()
            if module.params.get("ip"):
                at_record = None
                for record in records["domain_records"]:
                    if record["name"] == "@" and record["type"] == "A":
                        at_record = record

                if not at_record:
                    do_manager.create_domain_record()
                    module.exit_json(changed=True, domain=do_manager.find())
                elif not at_record["data"] == module.params.get("ip"):
                    do_manager.edit_domain_record(at_record)
                    module.exit_json(changed=True, domain=do_manager.find())

            if module.params.get("ip6"):
                at_record = None
                for record in records["domain_records"]:
                    if record["name"] == "@" and record["type"] == "AAAA":
                        at_record = record

                if not at_record:
                    do_manager.create_domain_record()
                    module.exit_json(changed=True, domain=do_manager.find())
                elif not at_record["data"] == module.params.get("ip6"):
                    do_manager.edit_domain_record(at_record)
                    module.exit_json(changed=True, domain=do_manager.find())

            module.exit_json(changed=False, domain=do_manager.domain_record())

    elif state == "absent":
        if not domain:
            module.exit_json(changed=False, msg="Domain not found")
        else:
            delete_event = do_manager.destroy_domain()
            if not delete_event:
                module.fail_json(changed=False, msg=delete_event["message"])
            else:
                module.exit_json(changed=True, event=None)
        delete_event = do_manager.destroy_domain()
        module.exit_json(changed=delete_event)


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        state=dict(choices=["present", "absent"], default="present"),
        name=dict(type="str"),
        id=dict(aliases=["droplet_id"], type="int"),
        ip=dict(type="str", aliases=["ip4", "ipv4"]),
        ip6=dict(type="str", aliases=["ipv6"]),
        project_name=dict(type="str", aliases=["project"], required=False, default=""),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(["id", "name"],),
        mutually_exclusive=[("ip", "ip6")],
    )

    run(module)


if __name__ == "__main__":
    main()
