# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 T-Systems Multimedia Solutions GmbH
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: icinga_director_inventory
short_description: Returns Ansible inventory from Icinga
description: Returns Ansible inventory from Icinga
author:
- Sebastian Gumprich (@rndmh3ro)
options:
  plugin:
    description: Name of the plugin
    required: true
    choices: ['telekom_mms.icinga_director.icinga_director_inventory']
  url:
    description: Icinga URL to connect to
    required: true
  url_username:
    description:
      - The username for use in HTTP basic authentication.
      - This parameter can be used without `url_password` for sites that allow empty passwords
  url_password:
    description:
      - The password for use in HTTP basic authentication.
      - If the `url_username` parameter is not specified, the `url_password` parameter will not be used.
  force_basic_auth:
    description:
      - Credentials specified with `url_username` and `url_password` should be passed in HTTP Header.
  client_cert:
    description:
      - PEM formatted certificate chain file to be used for SSL client authentication.
      - This file can also include the key as well, and if the key is included, `client_key` is not required.
  client_key:
    description:
      - PEM formatted file that contains your private key to be used for SSL client authentication.
      - If `client_cert` contains both the certificate and key, this option is not required.
  http_agent:
    description:
      - Header to identify as, generally appears in web server logs.
  use_proxy:
    description:
      - If `no`, it will not use a proxy, even if one is defined in an environment variable on the target hosts.
  validate_certs:
    description:
      - If `no`, SSL certificates will not be validated.
      - This should only be used on personally controlled sites using self-signed certificates.
  use_gssapi:
    description:
      - Use GSSAPI to perform the authentication, typically this is for Kerberos or Kerberos through Negotiate authentication.
      - Requires the Python library `gssapi <https://github.com/pythongssapi/python-gssapi>` to be installed.
      - Credentials for GSSAPI can be specified with `url_username`/ `url_password`
      - or with the GSSAPI env var `KRB5CCNAME` that specified a custom Kerberos credential cache.
      - NTLM authentication is `not` supported even if the GSSAPI mech for NTLM has been installed.
extends_documentation_fragment:
  - ansible.builtin.url
  - constructed
"""

EXAMPLES = r"""
plugin: telekom_mms.icinga_director.icinga_director_inventory
url: 'https://example.com'
url_username: foo
url_password: bar
force_basic_auth: False
strict: False

# use the object_name you defined as hostname
compose:
  hostname: object_name

# create a group based on the operating system defined in a custom variable
keyed_groups:
  - prefix: os
    key: vars.HostOS

# create groups based on jinja templates
# here we create a group called "rb" if the host variable "check_period" is "24/7"
groups:
  rb: check_period == "24/7"
"""


from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.inventory.group import to_safe_group_name

from ansible.module_utils.urls import open_url
from urllib.parse import quote
import json


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = "telekom_mms.icinga_director.icinga_director_inventory"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def call_url(self, url_path):
        """
        Execute the request against the API with the provided arguments and return json.
        """

        headers = {
            "Accept": "application/json",
            "X-HTTP-Method-Override": "GET",
        }
        url = self.url + url_path
        rsp = open_url(
            url,
            url_username=self.url_username,
            url_password=self.url_password,
            force_basic_auth=self.force_basic_auth,
            client_cert=self.client_cert,
            client_key=self.client_key,
            http_agent=self.http_agent,
            use_proxy=self.use_proxy,
            validate_certs=self.validate_certs,
            use_gssapi=self.use_gssapi,
            headers=headers,
        )
        content = ""
        if rsp:
            content = json.loads(rsp.read().decode("utf-8"))
            return content

    def verify_file(self, path):
        """Verify the configuration file."""
        if super(InventoryModule, self).verify_file(path):
            endings = (
                "icinga_director_inventory.yaml",
                "icinga_director_inventory.yml",
            )
            if any((path.endswith(ending) for ending in endings)):
                return True
        return False

    def add_hosts_to_groups(self):
        hostgroups = self.set_hostgroups()

        health = self.call_url(url_path="/health")

        # default for deprecated monitoring module
        hostgroup_url_path = "/monitoring/list/hosts"
        hostgroup_name = "hostgroup_name"
        host_name = "host_name"

        for module in health["data"]:
            if module["module"] == "icingadb":
                hostgroup_url_path = "/icingadb/hostgroup"
                hostgroup_name = "name"
                host_name = "name"

        for hostgroup in hostgroups:
            members = self.call_url(
                url_path=hostgroup_url_path
                + "?" + hostgroup_name + "="
                + quote(hostgroup),
            )
            for member in members:
                self.inventory.add_host(member[host_name], group=to_safe_group_name(hostgroup, force=True, silent=True))

    def set_hostgroups(self):
        hostgroup_list = self.call_url(
            url_path="/director/hostgroups",
        )

        hostgroups = []

        for hostgroup in hostgroup_list["objects"]:
            hostgroups.append(hostgroup["object_name"])
            self.inventory.add_group(to_safe_group_name(hostgroup["object_name"], force=True, silent=True))
        return hostgroups

    def parse(self, inventory, loader, path, cache=True):
        """Return dynamic inventory from source"""

        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        # Read the inventory YAML file
        self._read_config_data(path)

        # Store the options from the YAML file
        self.plugin = self.get_option("plugin")
        self.url = self.get_option("url")
        self.url_username = self.get_option("url_username")
        self.url_password = self.get_option("url_password")
        self.force_basic_auth = self.get_option("force_basic_auth")
        self.client_cert = self.get_option("client_cert")
        self.client_key = self.get_option("client_key")
        self.http_agent = self.get_option("http_agent")
        self.use_proxy = self.get_option("use_proxy")
        self.validate_certs = self.get_option("validate_certs")
        self.force_basic_auth = self.get_option("force_basic_auth")
        self.use_gssapi = self.get_option("use_gssapi")
        self.strict = self.get_option("strict")
        self.compose = self.get_option("compose")

        host_list = self.call_url(
            url_path="/director/hosts" + "?resolved",
        )

        for host in host_list["objects"]:
            self.inventory.add_host(host["object_name"], group="all")
            for item in host:
                self.inventory.set_variable(
                    host["object_name"], item, host[item]
                )

            host_vars = self.inventory.get_host(host["object_name"]).get_vars()

            # Add variables created by the user's Jinja2 expressions to the host
            self._set_composite_vars(
                self.compose,
                host_vars,
                host["object_name"],
                strict=self.strict,
            )

            # The following two methods combine the provided variables dictionary with the latest host variables
            # Using these methods after _set_composite_vars() allows groups to be created with the composed variables
            self._add_host_to_composed_groups(
                self.get_option("groups"),
                host_vars,
                host["object_name"],
                strict=self.strict,
            )
            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"),
                host_vars,
                host["object_name"],
                strict=self.strict,
            )

        self.add_hosts_to_groups()
