#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) jasites <jsites@vultr.com>
# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# flake8: noqa: E402

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
name: vultr
short_description: Retrieves list of instances via Vultr v2 API
description:
  - Vultr inventory plugin.
  - Retrieves list of instances via Vultr v2 API.
  - Configuration of this plugin is done with files ending with '(vultr|vultr_hosts|vultr_instances).(yaml|yml)'
version_added: '1.4.0'
author:
  - jasites (@jasites)
extends_documentation_fragment:
  - constructed
  - inventory_cache
options:
  api_endpoint:
    description:
      - URL to API endpint (without trailing slash).
      - Fallback environment variable C(VULTR_API_ENDPOINT).
    type: str
    env:
      - name: VULTR_API_ENDPOINT
    default: https://api.vultr.com/v2
  api_key:
    description:
      - API key of the Vultr API.
      - Fallback environment variable C(VULTR_API_KEY).
    type: str
    env:
      - name: VULTR_API_KEY
    required: true
  api_results_per_page:
    description:
      - When receiving large numbers of instances, specify how many instances should be returned per call to API.
      - This does not determine how many results are returned; all instances are returned according to other filters.
      - Vultr API maximum is 500.
      - Fallback environment variable C(VULTR_API_RESULTS_PER_PAGE).
    type: int
    env:
      - name: VULTR_API_RESULTS_PER_PAGE
    default: 100
  api_timeout:
    description:
      - HTTP timeout to Vultr API.
      - Fallback environment variable C(VULTR_API_TIMEOUT).
    type: int
    env:
      - name: VULTR_API_TIMEOUT
    default: 60
  attributes:
    description:
      - Instance attributes to add as host variables to each host added to inventory.
      - See U(https://www.vultr.com/api/#operation/list-instances) for valid values.
      - The I(internal_ip) attribute was added in version 1.10.0.
    type: list
    elements: str
    default:
      - id
      - region
      - label
      - plan
      - hostname
      - main_ip
      - v6_main_ip
      - tags
      - internal_ip
  filters:
    description:
      - Filter hosts with Jinja2 templates.
      - If not provided, all hosts are added to inventory.
    type: list
    elements: str
    default: []
  instance_type:
    description:
      - Type of instance.
    type: str
    default: cloud
    choices:
      - cloud
      - bare_metal
    version_added: '1.8.0'
  plugin:
    description:
      - Name of Vultr inventory plugin.
      - This should always be C(vultr.cloud.vultr).
    type: str
    choices: ['vultr.cloud.vultr']
    required: true
  variable_prefix:
    description:
      - Prefix of generated variables (e.g. C(id) becomes C(vultr_id)).
    type: str
    default: 'vultr_'
  validate_certs:
    description:
      - Validate SSL certs of the Vultr API.
    type: bool
    default: true
notes:
  - Also see the API documentation on U(https://www.vultr.com/api/).
"""

EXAMPLES = """
---
# File endings vultr{,_{hosts,instances}}.y{,a}ml
# All configuration done via environment variables:
plugin: vultr.cloud.vultr

# Grouping and filtering configuration in inventory file
plugin: vultr.cloud.vultr
api_key: '{{ lookup("pipe"), "./get_vultr_api_key.sh" }}'
keyed_groups:
  - key: vultr_tags | lower
    prefix: ''
    separator: ''
filters:
  - '"vpc" in vultr_tags'
  - 'vultr_plan == "vc2-2c-4gb"'

# Unless you can connect to your servers via it's vultr label,
# we suggest setting ansible_host with compose:
plugin: vultr.cloud.vultr
compose:
  ansible_host: vultr_main_ip

# Respectively for IPv6:
plugin: vultr.cloud.vultr
compose:
  ansible_host: vultr_v6_main_ip

# Prioritize IPv6 over IPv4 if available.
plugin: vultr.cloud.vultr
compose:
  ansible_host: vultr_v6_main_ip or vultr_main_ip

# Use the internal IP
plugin: vultr.cloud.vultr
compose:
  ansible_host: vultr_internal_ip

# Querying the bare metal instances
plugin: vultr.cloud.vultr
instance_type: bare_metal
"""

RETURN = r""" # """

import json

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils._text import to_native
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import Request
from ansible.plugins.inventory import (BaseInventoryPlugin, Cacheable,
                                       Constructable)

from ..module_utils.vultr_v2 import VULTR_USER_AGENT


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = "vultr.cloud.vultr"

    RESOURCES_PER_TYPE = {
        "cloud": {
            "resource": "instances",
            "response": "instances",
        },
        "bare_metal": {
            "resource": "bare-metals",
            "response": "bare_metals",
        },
    }

    def _get_instances(self):
        instances = []
        api_key = self.get_option("api_key")
        if self.templar.is_template(api_key):
            api_key = self.templar.template(api_key)

        headers = {
            "Content-Type": "application/json",
            "User-Agent": VULTR_USER_AGENT,
            "Authorization": "Bearer {0}".format(api_key),
        }

        self.req = Request(
            headers=headers,
            timeout=int(self.get_option("api_timeout")),  # type: ignore
            validate_certs=self.get_option("validate_certs"),  # type: ignore
        )

        instance_type_config = self.get_option("instance_type") or "cloud"
        self.display.vvv("Type is: {0}".format(instance_type_config))

        instance_type = self.RESOURCES_PER_TYPE[instance_type_config]

        api_endpoint = "{0}/{1}?per_page={2}".format(
            self.get_option("api_endpoint"),
            instance_type["resource"],  # type: ignore
            self.get_option("api_results_per_page"),
        )

        cursor = ""
        req_url = api_endpoint
        try:
            while True:
                self.display.vvv("Querying API: {0}".format(req_url))

                page = json.load(self.req.get(req_url))
                instances.extend(page[instance_type["response"]])  # type: ignore
                cursor = page["meta"]["links"]["next"]

                if cursor == "":
                    return instances

                req_url = "{0}&cursor={1}".format(api_endpoint, cursor)

        except (KeyError, ValueError):
            raise AnsibleParserError("Unable to parse JSON response.")
        except (URLError, HTTPError) as err:
            raise AnsibleParserError(err)

    def _populate(self, instances):
        attributes = self.get_option("attributes")
        host_filters = self.get_option("filters")
        strict = self.get_option("strict")
        variable_prefix = self.get_option("variable_prefix")

        for instance in instances:
            instance_label = instance.get("label")

            if not instance_label:
                self.display.warning(msg="instance ID {0} has no label, skipping.".format(instance.get("id")))
                continue

            host_variables = {}
            for k, v in instance.items():
                if k in attributes:
                    host_variables["{0}{1}".format(variable_prefix, k)] = v

            if not self._passes_filters(
                host_filters,
                host_variables,
                instance_label,
                strict,  # type: ignore
            ):
                self.display.vvv("Host {0} excluded by filters".format(instance_label))
                continue

            self.inventory.add_host(instance_label)  # type: ignore

            for var_name, var_val in host_variables.items():
                self.inventory.set_variable(instance_label, var_name, var_val)  # type: ignore

            self._set_composite_vars(
                self.get_option("compose"),
                self.inventory.get_host(instance_label).get_vars(),  # type: ignore
                instance_label,
                strict,  # type: ignore
            )

            self._add_host_to_composed_groups(
                self.get_option("groups"),
                dict(),
                instance_label,
                strict,  # type: ignore
            )

            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"),
                dict(),
                instance_label,
                strict,  # type: ignore
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
                            "Could not evaluate host filter {0} for {1}: {2}".format(
                                template,
                                host,
                                to_native(e),
                            ),
                        )
                    return False
        return True

    def verify_file(self, path):
        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(
                (
                    "vultr.yaml",
                    "vultr.yml",
                    "vultr_hosts.yaml",
                    "vultr_hosts.yml",
                    "vultr_instances.yaml",
                    "vultr_instances.yml",
                )
            ):
                valid = True
            else:
                self.display.vvv(
                    "Skipping due to inventory configuration file name mismatch. "
                    "Valid filename endings: "
                    "vultr.yaml, vultr.yml, vultr_hosts.yaml, vultr_hosts.yml, "
                    "vultr_instances.yaml, vultr_instances.yml"
                )
        return valid

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)

        self._read_config_data(path)

        cache_key = self.get_cache_key(path)
        use_cache = self.get_option("cache") and cache
        update_cache = self.get_option("cache") and not cache

        instances = None
        if use_cache:
            try:
                instances = self._cache[cache_key]
            except KeyError:
                update_cache = True

        if instances is None:
            instances = self._get_instances()

        if update_cache:
            self._cache[cache_key] = instances

        self._populate(instances)
