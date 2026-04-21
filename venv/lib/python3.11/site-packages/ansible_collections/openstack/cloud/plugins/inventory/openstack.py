#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2012, Marco Vito Moscaritolo <marco@agavee.com>
# Copyright (c) 2013, Jesse Keating <jesse.keating@rackspace.com>
# Copyright (c) 2015, Hewlett-Packard Development Company, L.P.
# Copyright (c) 2016, Rackspace Australia
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
name: openstack
author: OpenStack Ansible SIG
short_description: OpenStack inventory source
description:
  - Gather servers from OpenStack clouds and add them as Ansible hosts to your
    inventory.
  - Use YAML configuration file C(openstack.{yaml,yml}) to configure this
    inventory plugin.
  - Consumes cloud credentials from standard YAML configuration files
    C(clouds{,-public}.yaml).
options:
  all_projects:
    description:
      -  Lists servers from all projects
    type: bool
    default: false
  clouds_yaml_path:
    description:
      - Override path to C(clouds.yaml) file.
      - If this value is given it will be searched first.
      - Search paths for cloud credentials are complemented with files
        C(/etc/ansible/openstack.{yaml,yml}).
      - Default search paths are documented in
        U(https://docs.openstack.org/os-client-config/latest/user/configuration.html#config-files).
    type: list
    elements: str
    env:
      - name: OS_CLIENT_CONFIG_FILE
  expand_hostvars:
    description:
      - Enrich server facts with additional queries to OpenStack services. This
        includes requests to Cinder and Neutron which can be time-consuming
        for clouds with many servers.
      - Default value of I(expand_hostvars) is opposite of the default value
        for option C(expand_hostvars) in legacy openstack.py inventory script.
    type: bool
    default: false
  fail_on_errors:
    description:
      - Whether the inventory script fails, returning no hosts, when connection
        to a cloud failed, for example due to bad credentials or connectivity
        issues.
      - When I(fail_on_errors) is C(false) this inventory script will return
        all hosts it could fetch from clouds on a best effort basis.
      - Default value of I(fail_on_errors) is opposite of the default value
        for option C(fail_on_errors) in legacy openstack.py inventory script.
    type: bool
    default: false
  inventory_hostname:
    description:
      - What to register as inventory hostname.
      - When set to C(uuid) the ID of a server will be used and a group will
        be created for a server name.
      - When set to C(name) the name of a server will be used. When multiple
        servers share the same name, then the servers IDs will be used.
      - Default value of I(inventory_hostname) is opposite of the default value
        for option C(use_hostnames) in legacy openstack.py inventory script.
    type: string
    choices: ['name', 'uuid']
    default: 'name'
  legacy_groups:
    description:
      - Automatically create groups from host variables.
    type: bool
    default: true
  only_clouds:
    description:
      - List of clouds in C(clouds.yaml) which will be contacted to use instead
        of using all clouds.
    type: list
    elements: str
    default: []
  plugin:
    description:
      - Token which marks a given YAML configuration file as a valid input file
        for this inventory plugin.
    required: true
    choices: ['openstack', 'openstack.cloud.openstack']
  private:
    description:
      - Use private interfaces of servers, if available, when determining ip
        addresses for Ansible hosts.
      - Using I(private) helps when running Ansible from a server in the cloud
        and one wants to ensure that servers communicate over private networks
        only.
    type: bool
    default: false
  only_ipv4:
    description:
      - Use only ipv4 addresses for ansible_host and ansible_ssh_host.
      - Using I(only_ipv4) helps when running Ansible in a ipv4 only setup.
    type: bool
    default: false
  server_filters:
    description:
      - A dictionary of server filter value pairs.
      - Available parameters can be seen under https://docs.openstack.org/api-ref/compute/#list-servers
    type: dict
    default: {}
  show_all:
    description:
      - Whether all servers should be listed or not.
      - When I(show_all) is C(false) then only servers with a valid ip
        address, regardless it is private or public, will be listed.
    type: bool
    default: false
  use_names:
    description:
      - "When I(use_names) is C(false), its default value, then a server's
         first floating ip address will be used for both facts C(ansible_host)
         and C(ansible_ssh_host). When no floating ip address is attached to a
         server, then its first non-floating ip addresses is used instead. If
         no addresses are attached to a server, then both facts will not be
         defined."
      - "When I(use_names) is C(true), then the server name will be for both
         C(ansible_host) and C(ansible_ssh_host) facts. This is useful for
         jump or bastion hosts where each server name is actually a server's
         FQDN."
    type: bool
    default: false
requirements:
  - "python >= 3.6"
  - "openstacksdk >= 1.0.0"
extends_documentation_fragment:
  - inventory_cache
  - constructed
'''

EXAMPLES = r'''
# Create a file called openstack.yaml, add the following content and run
# $> ansible-inventory --list -vvv -i openstack.yaml
plugin: openstack.cloud.openstack

all_projects: false
expand_hostvars: true
fail_on_errors: true
only_clouds:
  - "devstack-admin"
strict: true
'''

import collections
import sys

from ansible.errors import AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    ensure_compatibility
)

try:
    import openstack
    HAS_SDK = True
except ImportError:
    HAS_SDK = False


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = 'openstack.cloud.openstack'

    def parse(self, inventory, loader, path, cache=True):

        super(InventoryModule, self).parse(inventory, loader, path,
                                           cache=cache)

        if not HAS_SDK:
            raise AnsibleParserError(
                'Could not import Python library openstacksdk')

        try:
            ensure_compatibility(openstack.version.__version__)
        except ImportError as e:
            raise AnsibleParserError(
                'Incompatible openstacksdk library found: {0}'.format(e))

        # Redirect logging to stderr so it does not mix with output, in
        # particular JSON output of ansible-inventory.
        # TODO: Integrate openstack's logging with Ansible's logging.
        if self.display.verbosity > 3:
            openstack.enable_logging(debug=True, stream=sys.stderr)
        else:
            openstack.enable_logging(stream=sys.stderr)

        config = self._read_config_data(path)

        if 'plugin' not in config and 'clouds' not in config:
            raise AnsibleParserError(
                "Invalid OpenStack inventory configuration file found,"
                " missing 'plugin' and 'clouds' keys.")

        # TODO: It it wise to disregard a potential user configuration error?
        if 'clouds' in config:
            self.display.vvvv(
                'Found combined plugin config and clouds config file.')

        servers = self._fetch_servers(path, cache)

        # determine inventory hostnames
        if self.get_option('inventory_hostname') == 'name':
            count = collections.Counter(s['name'] for s in servers)

            inventory = dict(((server['name'], server)
                              if count[server['name']] == 1
                              else (server['id'], server))
                             for server in servers)

        else:  # self.get_option('inventory_hostname') == 'uuid'
            inventory = dict((server['id'], server)
                             for server in servers)

        # drop servers without addresses
        show_all = self.get_option('show_all')
        inventory = dict((k, v)
                         for k, v in inventory.items()
                         if show_all or v['addresses'])

        for hostname, server in inventory.items():
            host_vars = self._generate_host_vars(hostname, server)
            self._add_host(hostname, host_vars)

        if self.get_option('legacy_groups'):
            for hostname, server in inventory.items():
                for group in self._generate_legacy_groups(server):
                    group_name = self.inventory.add_group(group)
                    if group_name == hostname:
                        self.display.vvvv(
                            'Same name for host {0} and group {1}'
                            .format(hostname, group_name))
                        self.inventory.add_host(hostname, group_name)
                    else:
                        self.inventory.add_child(group_name, hostname)

    def _add_host(self, hostname, host_vars):
        # Ref.: https://docs.ansible.com/ansible/latest/dev_guide/
        #       developing_inventory.html#constructed-features

        self.inventory.add_host(hostname, group='all')

        for k, v in host_vars.items():
            self.inventory.set_variable(hostname, k, v)

        strict = self.get_option('strict')

        self._set_composite_vars(
            self.get_option('compose'), host_vars, hostname, strict=True)

        self._add_host_to_composed_groups(
            self.get_option('groups'), host_vars, hostname, strict=strict)

        self._add_host_to_keyed_groups(
            self.get_option('keyed_groups'), host_vars, hostname,
            strict=strict)

    def _fetch_servers(self, path, cache):
        cache_key = self._get_cache_prefix(path)
        user_cache_setting = self.get_option('cache')
        attempt_to_read_cache = user_cache_setting and cache
        cache_needs_update = not cache and user_cache_setting

        servers = None

        if attempt_to_read_cache:
            self.display.vvvv('Reading OpenStack inventory cache key {0}'
                              .format(cache_key))
            try:
                servers = self._cache[cache_key]
            except KeyError:
                self.display.vvvv("OpenStack inventory cache not found")
                cache_needs_update = True

        if not attempt_to_read_cache or cache_needs_update:
            self.display.vvvv('Retrieving servers from Openstack clouds')
            clouds_yaml_path = self.get_option('clouds_yaml_path')
            config_files = openstack.config.loader.CONFIG_FILES
            if clouds_yaml_path:
                config_files = clouds_yaml_path + config_files

            config = openstack.config.loader.OpenStackConfig(
                config_files=config_files)

            only_clouds = self.get_option('only_clouds', [])
            if only_clouds:
                if not isinstance(only_clouds, list):
                    raise AnsibleParserError(
                        'Option only_clouds in OpenStack inventory'
                        ' configuration is not a list')

                cloud_regions = [config.get_one(cloud=cloud)
                                 for cloud in only_clouds]
            else:
                cloud_regions = config.get_all()

            clouds = [openstack.connection.Connection(config=cloud_region)
                      for cloud_region in cloud_regions]

            self.display.vvvv(
                'Found {0} OpenStack cloud(s)'
                .format(len(clouds)))

            self.display.vvvv(
                'Using {0} OpenStack cloud(s)'
                .format(len(clouds)))

            expand_hostvars = self.get_option('expand_hostvars')
            all_projects = self.get_option('all_projects')
            server_filters = self.get_option('server_filters')
            servers = []

            def _expand_server(server, cloud, volumes):
                # calling openstacksdk's compute.servers() with
                # details=True already fetched most facts

                # cloud dict is used for legacy_groups option
                server['cloud'] = dict(name=cloud.name)
                region = cloud.config.get_region_name()
                if region:
                    server['cloud']['region'] = region

                if not expand_hostvars:
                    # do not query OpenStack API for additional data
                    return server

                # TODO: Consider expanding 'flavor', 'image' and
                #       'security_groups' when users still require this
                #       functionality.
                # Ref.: https://opendev.org/openstack/openstacksdk/src/commit/\
                #       289e5c2d3cba0eb1c008988ae5dccab5be05d9b6/openstack/cloud/meta.py#L482

                server['volumes'] = [v for v in volumes
                                     if any(a['server_id'] == server['id']
                                            for a in v['attachments'])]

                return server

            for cloud in clouds:
                if expand_hostvars:
                    volumes = [v.to_dict(computed=False)
                               for v in cloud.block_storage.volumes()]
                else:
                    volumes = []

                try:
                    for server in [
                        # convert to dict before expanding servers
                        # to allow us to attach attributes
                        _expand_server(server.to_dict(computed=False),
                                       cloud,
                                       volumes)
                        for server in cloud.compute.servers(
                            all_projects=all_projects,
                            # details are required because 'addresses'
                            # attribute must be populated
                            details=True,
                            **server_filters)
                    ]:
                        servers.append(server)
                except openstack.exceptions.OpenStackCloudException as e:
                    self.display.warning(
                        'Fetching servers for cloud {0} failed with: {1}'
                        .format(cloud.name, str(e)))
                    if self.get_option('fail_on_errors'):
                        raise

        if cache_needs_update:
            self._cache[cache_key] = servers

        return servers

    def _generate_host_vars(self, hostname, server):
        # populate host_vars with 'ansible_host', 'ansible_ssh_host' and
        # 'openstack' facts

        host_vars = dict(openstack=server)

        if self.get_option('use_names'):
            host_vars['ansible_ssh_host'] = server['name']
            host_vars['ansible_host'] = server['name']
        else:
            # flatten addresses dictionary
            addresses = [a
                         for addresses in (server['addresses'] or {}).values()
                         for a in addresses]

            floating_ip = next(
                (address['addr'] for address in addresses
                 if address['OS-EXT-IPS:type'] == 'floating'),
                None)

            if self.get_option('only_ipv4'):
                fixed_ip = next(
                    (address['addr'] for address in addresses
                     if (address['OS-EXT-IPS:type'] == 'fixed' and address['version'] == 4)),
                    None)

            else:
                fixed_ip = next(
                    (address['addr'] for address in addresses
                     if address['OS-EXT-IPS:type'] == 'fixed'),
                    None)

            ip = floating_ip if floating_ip is not None and not self.get_option('private') else fixed_ip

            if ip is not None:
                host_vars['ansible_ssh_host'] = ip
                host_vars['ansible_host'] = ip

        return host_vars

    def _generate_legacy_groups(self, server):
        groups = []

        # cloud was added by _expand_server()
        cloud = server['cloud']

        cloud_name = cloud['name']
        groups.append(cloud_name)

        region = cloud['region'] if 'region' in cloud else None
        if region is not None:
            groups.append(region)
            groups.append('{cloud}_{region}'.format(cloud=cloud_name,
                                                    region=region))

        metadata = server.get('metadata', {})
        if 'group' in metadata:
            groups.append(metadata['group'])
        for extra_group in metadata.get('groups', '').split(','):
            if extra_group:
                groups.append(extra_group.strip())
        for k, v in metadata.items():
            groups.append('meta-{k}_{v}'.format(k=k, v=v))

        groups.append('instance-{id}'.format(id=server['id']))

        for k in ('flavor', 'image'):
            if 'name' in server[k]:
                groups.append('{k}-{v}'.format(k=k, v=server[k]['name']))

        availability_zone = server['availability_zone']
        if availability_zone:
            groups.append(availability_zone)
            if region:
                groups.append(
                    '{region}_{availability_zone}'
                    .format(region=region,
                            availability_zone=availability_zone))
                groups.append(
                    '{cloud}_{region}_{availability_zone}'
                    .format(cloud=cloud_name,
                            region=region,
                            availability_zone=availability_zone))

        return groups

    def verify_file(self, path):
        if super(InventoryModule, self).verify_file(path):
            for fn in ('openstack', 'clouds'):
                for suffix in ('yaml', 'yml'):
                    maybe = '{fn}.{suffix}'.format(fn=fn, suffix=suffix)
                    if path.endswith(maybe):
                        self.display.vvvv(
                            'OpenStack inventory configuration file found:'
                            ' {0}'.format(maybe))
                        return True
        return False
