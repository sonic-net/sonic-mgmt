#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Ansible Project
# Copyright: (c) 2021, Mark Mercado <mamercad@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_cdn_endpoints
short_description: Create, update, and delete DigitalOcean CDN Endpoints
description:
  - Create, update, and delete DigitalOcean CDN Endpoints
author: "Mark Mercado (@mamercad)"
version_added: 1.10.0
options:
  state:
    description:
      - The usual, C(present) to create, C(absent) to destroy
    type: str
    choices: ["present", "absent"]
    default: present
  origin:
    description:
      - The fully qualified domain name (FQDN) for the origin server which provides the content for the CDN.
      - This is currently restricted to a Space.
    type: str
    required: true
  ttl:
    description:
      - The amount of time the content is cached by the CDN's edge servers in seconds.
      - TTL must be one of 60, 600, 3600, 86400, or 604800.
      - Defaults to 3600 (one hour) when excluded.
    type: int
    choices: [60, 600, 3600, 86400, 604800]
    default: 3600
    required: false
  certificate_id:
    description:
      - The ID of a DigitalOcean managed TLS certificate used for SSL when a custom subdomain is provided.
    type: str
    default: ""
    required: false
  custom_domain:
    description:
      - The fully qualified domain name (FQDN) of the custom subdomain used with the CDN endpoint.
    type: str
    default: ""
    required: false
extends_documentation_fragment:
  - community.digitalocean.digital_ocean.documentation
"""


EXAMPLES = r"""
- name: Create DigitalOcean CDN Endpoint
  community.digitalocean.digital_ocean_cdn_endpoints:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    origin: mamercad.nyc3.digitaloceanspaces.com

- name: Update DigitalOcean CDN Endpoint (change ttl to 600, default is 3600)
  community.digitalocean.digital_ocean_cdn_endpoints:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    origin: mamercad.nyc3.digitaloceanspaces.com
    ttl: 600

- name: Delete DigitalOcean CDN Endpoint
  community.digitalocean.digital_ocean_cdn_endpoints:
    state: absent
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    origin: mamercad.nyc3.digitaloceanspaces.com
"""


RETURN = r"""
data:
  description: DigitalOcean CDN Endpoints
  returned: success
  type: dict
  sample:
    data:
      endpoint:
        created_at: '2021-09-05T13:47:23Z'
        endpoint: mamercad.nyc3.cdn.digitaloceanspaces.com
        id: 01739563-3f50-4da4-a451-27f6d59d7573
        origin: mamercad.nyc3.digitaloceanspaces.com
        ttl: 3600
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


class DOCDNEndpoint(object):
    def __init__(self, module):
        self.module = module
        self.rest = DigitalOceanHelper(module)
        # pop the oauth token so we don't include it in the POST data
        self.token = self.module.params.pop("oauth_token")

    def get_cdn_endpoints(self):
        cdns = self.rest.get_paginated_data(
            base_url="cdn/endpoints?", data_key_name="endpoints"
        )
        return cdns

    def get_cdn_endpoint(self):
        cdns = self.rest.get_paginated_data(
            base_url="cdn/endpoints?", data_key_name="endpoints"
        )
        found = None
        for cdn in cdns:
            if cdn.get("origin") == self.module.params.get("origin"):
                found = cdn
                for key in ["ttl", "certificate_id"]:
                    if self.module.params.get(key) != cdn.get(key):
                        return found, True
        return found, False

    def create(self):
        cdn, needs_update = self.get_cdn_endpoint()

        if cdn is not None:
            if not needs_update:
                # Have it already
                self.module.exit_json(changed=False, msg=cdn)
            if needs_update:
                # Check mode
                if self.module.check_mode:
                    self.module.exit_json(changed=True)

                # Update it
                request_params = dict(self.module.params)

                endpoint = "cdn/endpoints"
                response = self.rest.put(
                    "{0}/{1}".format(endpoint, cdn.get("id")), data=request_params
                )
                status_code = response.status_code
                json_data = response.json

                # The API docs are wrong (they say 202 but return 200)
                if status_code != 200:
                    self.module.fail_json(
                        changed=False,
                        msg="Failed to put {0} information due to error [HTTP {1}: {2}]".format(
                            endpoint,
                            status_code,
                            json_data.get("message", "(empty error message)"),
                        ),
                    )

                self.module.exit_json(changed=True, data=json_data)
        else:
            # Check mode
            if self.module.check_mode:
                self.module.exit_json(changed=True)

            # Create it
            request_params = dict(self.module.params)

            endpoint = "cdn/endpoints"
            response = self.rest.post(endpoint, data=request_params)
            status_code = response.status_code
            json_data = response.json

            if status_code != 201:
                self.module.fail_json(
                    changed=False,
                    msg="Failed to post {0} information due to error [HTTP {1}: {2}]".format(
                        endpoint,
                        status_code,
                        json_data.get("message", "(empty error message)"),
                    ),
                )

            self.module.exit_json(changed=True, data=json_data)

    def delete(self):
        cdn, needs_update = self.get_cdn_endpoint()
        if cdn is not None:
            # Check mode
            if self.module.check_mode:
                self.module.exit_json(changed=True)

            # Delete it
            endpoint = "cdn/endpoints/{0}".format(cdn.get("id"))
            response = self.rest.delete(endpoint)
            status_code = response.status_code
            json_data = response.json

            if status_code != 204:
                self.module.fail_json(
                    changed=False,
                    msg="Failed to delete {0} information due to error [HTTP {1}: {2}]".format(
                        endpoint,
                        status_code,
                        json_data.get("message", "(empty error message)"),
                    ),
                )

            self.module.exit_json(
                changed=True,
                msg="Deleted CDN Endpoint {0} ({1})".format(
                    cdn.get("origin"), cdn.get("id")
                ),
            )
        else:
            self.module.exit_json(changed=False)


def run(module):
    state = module.params.pop("state")
    c = DOCDNEndpoint(module)

    # Pop these away (don't need them beyond DOCDNEndpoint)
    module.params.pop("baseurl")
    module.params.pop("validate_certs")
    module.params.pop("timeout")

    if state == "present":
        c.create()
    elif state == "absent":
        c.delete()


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        state=dict(choices=["present", "absent"], default="present"),
        origin=dict(type="str", required=True),
        ttl=dict(
            type="int",
            choices=[60, 600, 3600, 86400, 604800],
            required=False,
            default=3600,
        ),
        certificate_id=dict(type="str", default=""),
        custom_domain=dict(type="str", default=""),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
