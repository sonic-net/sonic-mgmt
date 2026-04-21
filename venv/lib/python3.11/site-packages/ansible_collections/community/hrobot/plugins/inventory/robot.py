# -*- coding: utf-8 -*-

# Copyright (c) 2019 Oleksandr Stepanov <alexandrst88@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later


from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
name: robot
author:
  - Oleksandr Stepanov (@alexandrst88)
short_description: Hetzner Robot inventory source
version_added: 1.1.0
description:
  - Reads servers from Hetzner Robot API.
  - Uses a YAML configuration file that ends with C(robot.yml) or C(robot.yaml).
  - The inventory plugin adds all values from U(https://robot.your-server.de/doc/webservice/en.html#get-server) prepended
    with C(hrobot_) to the server's inventory. For example, the variable C(hrobot_dc) contains the data center the server
    is located in.
extends_documentation_fragment:
  - ansible.builtin.constructed
  - ansible.builtin.inventory_cache
  - community.hrobot.robot
  - community.library_inventory_filtering_v1.inventory_filter
notes:
  - The O(hetzner_user) and O(hetzner_password) options can be templated.
options:
  plugin:
    description: Token that ensures this is a source file for the plugin.
    required: true
    choices: ["community.hrobot.robot"]
  hetzner_user:
    env:
      - name: HROBOT_API_USER
  hetzner_password:
    env:
      - name: HROBOT_API_PASSWORD
  simple_filters:
    description:
      - A dictionary of filter value pairs.
      - Available filters are listed here are keys of server like C(status) or C(server_ip).
      - See U(https://robot.your-server.de/doc/webservice/en.html#get-server) for all values that can be used.
      - This option used to be called O(filters) before community.hrobot 2.0.0. It has been renamed from O(filters) to O(simple_filters)
        in community.hrobotdns 1.9.0, and the old name was still available as an alias until community.hrobot 2.0.0. O(filters)
        is now used for something else.
    type: dict
    default: {}
  filters:
    version_added: 2.0.0
"""

EXAMPLES = r"""
---
# Fetch all hosts in Hetzner Robot
plugin: community.hrobot.robot
# Filters all servers in ready state
filters:
  status: ready

---
# Example showing encrypted credentials and using filters
# (This assumes that Mozilla sops was used to encrypt keys/hetzner.sops.yaml, which contains two values
# hetzner_username and hetzner_password. Needs the community.sops collection to decode that file.)
plugin: community.hrobot.robot
hetzner_user: '{{ (lookup("community.sops.sops", "keys/hetzner.sops.yaml") | from_yaml).hetzner_username }}'
hetzner_password: '{{ (lookup("community.sops.sops", "keys/hetzner.sops.yaml") | from_yaml).hetzner_password }}'
filters:
  # Accept all servers in FSN1-DC1 and FSN1-DC2
  - include: >-
      hrobot_dc in ["FSN1-DC1", "FSN1-DC2"]
  # Exclude all servers that did not match any of the above filters
  - exclude: true

---
# Example using constructed features to create groups
plugin: community.hrobot.robot
simple_filters:
  status: ready
  traffic: unlimited
# keyed_groups may be used to create custom groups
strict: false
keyed_groups:
  # Add e.g. groups for every data center
  - key: hrobot_dc
    separator: ""
# Use the IP address to connect to the host
compose:
  server_name_ip: hrobot_server_name ~ '-' ~ hrobot_server_ip
"""

from ansible.errors import AnsibleError
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from ansible.template import Templar
from ansible.utils.display import Display

from ansible_collections.community.library_inventory_filtering_v1.plugins.plugin_utils.inventory_filter import parse_filters, filter_host

from ansible_collections.community.hrobot.plugins.module_utils.common import (
    PluginException,
)
from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    plugin_open_url_json,
)
from ansible_collections.community.hrobot.plugins.plugin_utils.unsafe import make_unsafe

display = Display()


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = 'community.hrobot.robot'

    def verify_file(self, path):
        ''' return true/false if this is possibly a valid file for this plugin to consume '''
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(('robot.yaml', 'robot.yml')):
                valid = True
            else:
                display.debug("robot inventory filename must end with 'robot.yml' or 'robot.yaml'")
        return valid

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)
        servers = {}
        self._read_config_data(path)
        self.load_cache_plugin()
        cache_key = self.get_cache_key(path)

        self.templar = Templar(loader=loader)

        # cache may be True or False at this point to indicate if the inventory is being refreshed
        # get the user's cache option too to see if we should save the cache if it is changing
        user_cache_setting = self.get_option('cache')

        # read if the user has caching enabled and the cache is not being refreshed
        attempt_to_read_cache = user_cache_setting and cache
        # update if the user has caching enabled and the cache is being refreshed; update this value to True if the cache has expired below
        cache_needs_update = user_cache_setting and not cache

        # attempt to read the cache if inventory is not being refreshed and the user has caching enabled
        if attempt_to_read_cache:
            try:
                servers = self._cache[cache_key]
            except KeyError:
                # This occurs if the cache_key is not in the cache or if the cache_key expired, so the cache needs to be updated
                cache_needs_update = True
        elif not cache_needs_update:
            servers = self.get_servers()
        else:
            # This can only happen if the code is modified so that cache=False
            pass  # pragma: no cover

        if cache_needs_update:
            servers = self.get_servers()

            # set the cache
            self._cache[cache_key] = servers

        self.populate(servers)

    def populate(self, servers):
        simple_filters = self.get_option('simple_filters')
        filters = parse_filters(self.get_option('filters'))
        strict = self.get_option('strict')
        server_lists = []
        for server in servers:
            s = server['server']
            server_name = s.get('server_name') or s.get('server_ip') or str(s['server_number'])
            matched = self.filter(s, simple_filters)
            if not matched:
                continue

            facts = {}
            if 'server_ip' in s:
                facts['ansible_host'] = make_unsafe(s['server_ip'])
            for hostvar, hostval in s.items():
                facts["{0}_{1}".format('hrobot', hostvar)] = make_unsafe(hostval)

            if not filter_host(self, server_name, facts, filters):
                continue

            if server_name in server_lists:
                display.warning('Two of your Hetzner servers use the same server name ({0}). '
                                'Please make sure that your server names are unique. '
                                'Only the first server named {0} will be included in the inventory.'.format(server_name))
                continue

            self.inventory.add_host(server_name)
            server_lists.append(server_name)
            for key, value in facts.items():
                self.inventory.set_variable(server_name, key, value)

            # Composed variables
            server_vars = self.inventory.get_host(server_name).get_vars()
            self._set_composite_vars(self.get_option('compose'), server_vars, server_name, strict=strict)

            # Complex groups based on jinja2 conditionals, hosts that meet the conditional are added to group
            self._add_host_to_composed_groups(self.get_option('groups'), server, server_name, strict=strict)

            # Create groups based on variable values and add the corresponding hosts to it
            self._add_host_to_keyed_groups(self.get_option('keyed_groups'), server, server_name, strict=strict)

    def filter(self, server, simple_filters):
        matched = True
        for key, value in simple_filters.items():
            if server.get(key) != value:
                matched = False
                break
        return matched

    def get_servers(self):
        try:
            return plugin_open_url_json(self, '{0}/server'.format(BASE_URL), templar=self.templar)[0]
        except PluginException as e:
            raise AnsibleError(e.error_message)
