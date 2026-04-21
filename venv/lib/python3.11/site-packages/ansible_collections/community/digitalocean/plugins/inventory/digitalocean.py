# -*- coding: utf-8 -*-

# Copyright: (c), Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: digitalocean
author:
  - Janos Gerzson (@grzs)
  - Tadej Borovšak (@tadeboro)
  - Max Truxa (@maxtruxa)
short_description: DigitalOcean Inventory Plugin
version_added: "1.1.0"
description:
  - DigitalOcean (DO) inventory plugin.
  - Acquires droplet list from DO API.
  - Uses configuration file that ends with '(do_hosts|digitalocean|digital_ocean).(yaml|yml)'.
extends_documentation_fragment:
  - community.digitalocean.digital_ocean.documentation
  - constructed
  - inventory_cache
options:
  plugin:
    description:
      - The name of the DigitalOcean Inventory Plugin,
        this should always be C(community.digitalocean.digitalocean).
    required: true
    choices: ['community.digitalocean.digitalocean']
  attributes:
    description: >-
      Droplet attributes to add as host vars to each inventory host.
      Check out the DO API docs for full list of attributes at
      U(https://docs.digitalocean.com/reference/api/api-reference/#operation/list_all_droplets).
    type: list
    elements: str
    default:
      - id
      - name
      - networks
      - region
      - size_slug
  var_prefix:
    description:
      - Prefix of generated varible names (e.g. C(tags) -> C(do_tags))
    type: str
    default: 'do_'
  pagination:
    description:
      - Maximum droplet objects per response page.
      - If the number of droplets related to the account exceeds this value,
        the query will be broken to multiple requests (pages).
      - DigitalOcean currently allows a maximum of 200.
    type: int
    default: 200
  filters:
    description:
      - Filter hosts with Jinja templates.
      - If no filters are specified, all hosts are added to the inventory.
    type: list
    elements: str
    default: []
    version_added: '1.5.0'
"""

EXAMPLES = r"""
# Using keyed groups and compose for hostvars
plugin: community.digitalocean.digitalocean
oauth_token: '{{ lookup("pipe", "./get-do-token.sh") }}'
attributes:
  - id
  - name
  - memory
  - vcpus
  - disk
  - size
  - image
  - networks
  - volume_ids
  - tags
  - region
keyed_groups:
  - key: do_region.slug
    prefix: 'region'
    separator: '_'
  - key: do_tags | lower
    prefix: ''
    separator: ''
compose:
  ansible_host: do_networks.v4 | selectattr('type','eq','public')
    | map(attribute='ip_address') | first
  class: do_size.description | lower
  distro: do_image.distribution | lower
filters:
  - '"kubernetes" in do_tags'
  - 'do_region.slug == "fra1"'
"""

import json
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.inventory.group import to_safe_group_name
from ansible.module_utils._text import to_native
from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    NAME = "community.digitalocean.digitalocean"

    # Constructable methods use the following function to construct group names. By
    # default, characters that are not valid in python variables, are always replaced by
    # underscores. We are overriding this with a function that respects the
    # TRANSFORM_INVALID_GROUP_CHARS configuration option and allows users to control the
    # behavior.
    _sanitize_group_name = staticmethod(to_safe_group_name)

    def verify_file(self, path):
        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(
                (
                    "do_hosts.yaml",
                    "do_hosts.yml",
                    "digitalocean.yaml",
                    "digitalocean.yml",
                    "digital_ocean.yaml",
                    "digital_ocean.yml",
                )
            ):
                valid = True
            else:
                self.display.vvv(
                    "Skipping due to inventory source file name mismatch. "
                    "The file name has to end with one of the following: "
                    "do_hosts.yaml, do_hosts.yml "
                    "digitalocean.yaml, digitalocean.yml, "
                    "digital_ocean.yaml, digital_ocean.yml."
                )
        return valid

    def _template_option(self, option):
        value = self.get_option(option)
        self.templar.available_variables = {}
        return self.templar.template(value)

    def _get_payload(self):
        # request parameters
        api_token = self._template_option("oauth_token")
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(api_token),
        }

        # build url
        pagination = self.get_option("pagination")
        url = "https://api.digitalocean.com/v2"
        if self.get_option("baseurl"):
            url = self.get_option("baseurl")
        url += "/droplets?per_page=" + str(pagination)

        # send request(s)
        self.req = Request(headers=headers, timeout=self.get_option("timeout"))
        payload = []
        try:
            while url:
                self.display.vvv("Sending request to {0}".format(url))
                response = json.load(self.req.get(url))
                payload.extend(response["droplets"])
                url = response.get("links", {}).get("pages", {}).get("next")
        except ValueError:
            raise AnsibleParserError("something went wrong with JSON loading")
        except (URLError, HTTPError) as error:
            raise AnsibleParserError(error)

        return payload

    def _populate(self, records):
        attributes = self.get_option("attributes")
        var_prefix = self.get_option("var_prefix")
        strict = self.get_option("strict")
        host_filters = self.get_option("filters")
        for record in records:
            host_name = record.get("name")
            if not host_name:
                continue

            host_vars = {}
            for k, v in record.items():
                if k in attributes:
                    host_vars[var_prefix + k] = v

            if not self._passes_filters(host_filters, host_vars, host_name, strict):
                self.display.vvv("Host {0} did not pass all filters".format(host_name))
                continue

            # add host to inventory
            self.inventory.add_host(host_name)

            # set variables for host
            for k, v in host_vars.items():
                self.inventory.set_variable(host_name, k, v)

            self._set_composite_vars(
                self.get_option("compose"),
                self.inventory.get_host(host_name).get_vars(),
                host_name,
                strict,
            )

            # set composed and keyed groups
            self._add_host_to_composed_groups(
                self.get_option("groups"), dict(), host_name, strict
            )
            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"), dict(), host_name, strict
            )

    def _passes_filters(self, filters, variables, host, strict=False):
        if filters and isinstance(filters, list):
            for template in filters:
                try:
                    if not self._compose(template, variables):
                        return False
                except Exception as e:
                    if strict:
                        raise AnsibleError(
                            "Could not evaluate host filter {0} for host {1}: {2}".format(
                                template, host, to_native(e)
                            )
                        )
                    # Better be safe and not include any hosts by accident.
                    return False
        return True

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)

        self._read_config_data(path)

        # cache settings
        cache_key = self.get_cache_key(path)
        use_cache = self.get_option("cache") and cache
        update_cache = self.get_option("cache") and not cache

        records = None
        if use_cache:
            try:
                records = self._cache[cache_key]
            except KeyError:
                update_cache = True

        if records is None:
            records = self._get_payload()

        if update_cache:
            self._cache[cache_key] = records

        self._populate(records)
