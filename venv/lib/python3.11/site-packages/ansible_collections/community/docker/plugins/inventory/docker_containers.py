# -*- coding: utf-8 -*-
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# For the parts taken from the docker inventory script:
# Copyright (c) 2016, Paul Durivage <paul.durivage@gmail.com>
# Copyright (c) 2016, Chris Houseknecht <house@redhat.com>
# Copyright (c) 2016, James Tanner <jtanner@redhat.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type


DOCUMENTATION = r"""
name: docker_containers
short_description: Ansible dynamic inventory plugin for Docker containers
version_added: 1.1.0
author:
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - ansible.builtin.constructed
  - community.docker.docker.api_documentation
  - community.library_inventory_filtering_v1.inventory_filter
description:
  - Reads inventories from the Docker API.
  - Uses a YAML configuration file that ends with V(docker.(yml|yaml\)).
notes:
  - The configuration file must be a YAML file whose filename ends with V(docker.yml) or V(docker.yaml). Other filenames will
    not be accepted.
options:
  plugin:
    description:
      - The name of this plugin, it should always be set to V(community.docker.docker_containers) for this plugin to recognize
        it as its own.
    type: str
    required: true
    choices: [community.docker.docker_containers]

  connection_type:
    description:
      - Which connection type to use the containers.
      - One way to connect to containers is to use SSH (V(ssh)). For this, the options O(default_ip) and O(private_ssh_port)
        are used. This requires that a SSH daemon is running inside the containers.
      - Alternatively, V(docker-cli) selects the P(community.docker.docker#connection) connection plugin, and V(docker-api)
        (default) selects the P(community.docker.docker_api#connection) connection plugin.
      - When V(docker-api) is used, all Docker daemon configuration values are passed from the inventory plugin to the connection
        plugin. This can be controlled with O(configure_docker_daemon).
      - Note that the P(community.docker.docker_api#connection) does B(not work with TCP TLS sockets)!
        See U(https://github.com/ansible-collections/community.docker/issues/605) for more information.
    type: str
    default: docker-api
    choices:
      - ssh
      - docker-cli
      - docker-api

  configure_docker_daemon:
    description:
      - Whether to pass all Docker daemon configuration from the inventory plugin to the connection plugin.
      - Only used when O(connection_type=docker-api).
    type: bool
    default: true
    version_added: 1.8.0

  verbose_output:
    description:
      - Toggle to (not) include all available inspection metadata.
      - Note that all top-level keys will be transformed to the format C(docker_xxx). For example, C(HostConfig) is converted
        to C(docker_hostconfig).
      - If this is V(false), these values can only be used during O(compose), O(groups), and O(keyed_groups).
      - The C(docker) inventory script always added these variables, so for compatibility set this to V(true).
    type: bool
    default: false

  default_ip:
    description:
      - The IP address to assign to ansible_host when the container's SSH port is mapped to interface '0.0.0.0'.
      - Only used if O(connection_type) is V(ssh).
    type: str
    default: 127.0.0.1

  private_ssh_port:
    description:
      - The port containers use for SSH.
      - Only used if O(connection_type) is V(ssh).
    type: int
    default: 22

  add_legacy_groups:
    description:
      - 'Add the same groups as the C(docker) inventory script does. These are the following:'
      - 'C(<container id>): contains the container of this ID.'
      - 'C(<container name>): contains the container that has this name.'
      - 'C(<container short id>): contains the containers that have this short ID (first 13 letters of ID).'
      - 'C(image_<image name>): contains the containers that have the image C(<image name>).'
      - 'C(stack_<stack name>): contains the containers that belong to the stack C(<stack name>).'
      - 'C(service_<service name>): contains the containers that belong to the service C(<service name>).'
      - 'C(<docker_host>): contains the containers which belong to the Docker daemon O(docker_host). Useful if you run this
        plugin against multiple Docker daemons.'
      - 'C(running): contains all containers that are running.'
      - 'C(stopped): contains all containers that are not running.'
      - If this is not set to V(true), you should use keyed groups to add the containers to groups. See the examples for how
        to do that.
    type: bool
    default: false

  filters:
    version_added: 3.5.0
"""

EXAMPLES = '''
---
# Minimal example using local Docker daemon
plugin: community.docker.docker_containers
docker_host: unix:///var/run/docker.sock

---
# Minimal example using remote Docker daemon
plugin: community.docker.docker_containers
docker_host: tcp://my-docker-host:2375

---
# Example using remote Docker daemon with unverified TLS
plugin: community.docker.docker_containers
docker_host: tcp://my-docker-host:2376
tls: true

---
# Example using remote Docker daemon with verified TLS and client certificate verification
plugin: community.docker.docker_containers
docker_host: tcp://my-docker-host:2376
validate_certs: true
ca_path: /somewhere/ca.pem
client_key: /somewhere/key.pem
client_cert: /somewhere/cert.pem

---
# Example using constructed features to create groups
plugin: community.docker.docker_containers
docker_host: tcp://my-docker-host:2375
strict: false
keyed_groups:
  # Add containers with primary network foo to a network_foo group
  - prefix: network
    key: 'docker_hostconfig.NetworkMode'
  # Add Linux hosts to an os_linux group
  - prefix: os
    key: docker_platform

---
# Example using SSH connection with an explicit fallback for when port 22 has not been
# exported: use container name as ansible_ssh_host and 22 as ansible_ssh_port
plugin: community.docker.docker_containers
connection_type: ssh
compose:
  ansible_ssh_host: ansible_ssh_host | default(docker_name[1:], true)
  ansible_ssh_port: ansible_ssh_port | default(22, true)

---
# Only consider containers which have a label 'foo', or whose name starts with 'a'
plugin: community.docker.docker_containers
filters:
  # Accept all containers which have a label called 'foo'
  - include: >-
      "foo" in docker_config.Labels
  # Next accept all containers whose inventory_hostname starts with 'a'
  - include: >-
      inventory_hostname.startswith("a")
  # Exclude all containers that did not match any of the above filters
  - exclude: true
'''

import re

from ansible.errors import AnsibleError
from ansible.module_utils.common.text.converters import to_native
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    RequestException,
)
from ansible_collections.community.docker.plugins.module_utils.util import (
    DOCKER_COMMON_ARGS_VARS,
)
from ansible_collections.community.docker.plugins.plugin_utils.common_api import (
    AnsibleDockerClient,
)

from ansible_collections.community.docker.plugins.module_utils._api.errors import APIError, DockerException
from ansible_collections.community.docker.plugins.plugin_utils.unsafe import make_unsafe
from ansible_collections.community.library_inventory_filtering_v1.plugins.plugin_utils.inventory_filter import parse_filters, filter_host

MIN_DOCKER_API = None


class InventoryModule(BaseInventoryPlugin, Constructable):
    ''' Host inventory parser for ansible using Docker daemon as source. '''

    NAME = 'community.docker.docker_containers'

    def _slugify(self, value):
        return 'docker_%s' % (re.sub(r'[^\w-]', '_', value).lower().lstrip('_'))

    def _populate(self, client):
        strict = self.get_option('strict')

        ssh_port = self.get_option('private_ssh_port')
        default_ip = self.get_option('default_ip')
        hostname = self.get_option('docker_host')
        verbose_output = self.get_option('verbose_output')
        connection_type = self.get_option('connection_type')
        add_legacy_groups = self.get_option('add_legacy_groups')

        try:
            params = {
                'limit': -1,
                'all': 1,
                'size': 0,
                'trunc_cmd': 0,
                'since': None,
                'before': None,
            }
            containers = client.get_json('/containers/json', params=params)
        except APIError as exc:
            raise AnsibleError("Error listing containers: %s" % to_native(exc))

        if add_legacy_groups:
            self.inventory.add_group('running')
            self.inventory.add_group('stopped')

        extra_facts = {}
        if self.get_option('configure_docker_daemon'):
            for option_name, var_name in DOCKER_COMMON_ARGS_VARS.items():
                value = self.get_option(option_name)
                if value is not None:
                    extra_facts[var_name] = value

        filters = parse_filters(self.get_option('filters'))
        for container in containers:
            id = container.get('Id')
            short_id = id[:13]

            try:
                name = container.get('Names', list())[0].lstrip('/')
                full_name = name
            except IndexError:
                name = short_id
                full_name = id

            facts = dict(
                docker_name=make_unsafe(name),
                docker_short_id=make_unsafe(short_id),
            )
            full_facts = dict()

            try:
                inspect = client.get_json('/containers/{0}/json', id)
            except APIError as exc:
                raise AnsibleError("Error inspecting container %s - %s" % (name, str(exc)))

            state = inspect.get('State') or dict()
            config = inspect.get('Config') or dict()
            labels = config.get('Labels') or dict()

            running = state.get('Running')

            groups = []

            # Add container to groups
            image_name = config.get('Image')
            if image_name and add_legacy_groups:
                groups.append('image_{0}'.format(image_name))

            stack_name = labels.get('com.docker.stack.namespace')
            if stack_name:
                full_facts['docker_stack'] = stack_name
                if add_legacy_groups:
                    groups.append('stack_{0}'.format(stack_name))

            service_name = labels.get('com.docker.swarm.service.name')
            if service_name:
                full_facts['docker_service'] = service_name
                if add_legacy_groups:
                    groups.append('service_{0}'.format(service_name))

            ansible_connection = None
            if connection_type == 'ssh':
                # Figure out ssh IP and Port
                try:
                    # Lookup the public facing port Nat'ed to ssh port.
                    network_settings = inspect.get('NetworkSettings') or {}
                    port_settings = network_settings.get('Ports') or {}
                    port = port_settings.get('%d/tcp' % (ssh_port, ))[0]
                except (IndexError, AttributeError, TypeError):
                    port = dict()

                try:
                    ip = default_ip if port['HostIp'] == '0.0.0.0' else port['HostIp']
                except KeyError:
                    ip = ''

                facts.update(dict(
                    ansible_ssh_host=ip,
                    ansible_ssh_port=port.get('HostPort', 0),
                ))
            elif connection_type == 'docker-cli':
                facts.update(dict(
                    ansible_host=full_name,
                ))
                ansible_connection = 'community.docker.docker'
            elif connection_type == 'docker-api':
                facts.update(dict(
                    ansible_host=full_name,
                ))
                facts.update(extra_facts)
                ansible_connection = 'community.docker.docker_api'

            full_facts.update(facts)
            for key, value in inspect.items():
                fact_key = self._slugify(key)
                full_facts[fact_key] = value

            full_facts = make_unsafe(full_facts)

            if ansible_connection:
                for d in (facts, full_facts):
                    if 'ansible_connection' not in d:
                        d['ansible_connection'] = ansible_connection

            if not filter_host(self, name, full_facts, filters):
                continue

            if verbose_output:
                facts.update(full_facts)

            self.inventory.add_host(name)
            for group in groups:
                self.inventory.add_group(group)
                self.inventory.add_host(name, group=group)

            for key, value in facts.items():
                self.inventory.set_variable(name, key, value)

            # Use constructed if applicable
            # Composed variables
            self._set_composite_vars(self.get_option('compose'), full_facts, name, strict=strict)
            # Complex groups based on jinja2 conditionals, hosts that meet the conditional are added to group
            self._add_host_to_composed_groups(self.get_option('groups'), full_facts, name, strict=strict)
            # Create groups based on variable values and add the corresponding hosts to it
            self._add_host_to_keyed_groups(self.get_option('keyed_groups'), full_facts, name, strict=strict)

            # We need to do this last since we also add a group called `name`.
            # When we do this before a set_variable() call, the variables are assigned
            # to the group, and not to the host.
            if add_legacy_groups:
                self.inventory.add_group(id)
                self.inventory.add_host(name, group=id)
                self.inventory.add_group(name)
                self.inventory.add_host(name, group=name)
                self.inventory.add_group(short_id)
                self.inventory.add_host(name, group=short_id)
                self.inventory.add_group(hostname)
                self.inventory.add_host(name, group=hostname)

                if running is True:
                    self.inventory.add_host(name, group='running')
                else:
                    self.inventory.add_host(name, group='stopped')

    def verify_file(self, path):
        """Return the possibly of a file being consumable by this plugin."""
        return (
            super(InventoryModule, self).verify_file(path) and
            path.endswith(('docker.yaml', 'docker.yml')))

    def _create_client(self):
        return AnsibleDockerClient(self, min_docker_api_version=MIN_DOCKER_API)

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        self._read_config_data(path)
        client = self._create_client()
        try:
            self._populate(client)
        except DockerException as e:
            raise AnsibleError(
                'An unexpected Docker error occurred: {0}'.format(e)
            )
        except RequestException as e:
            raise AnsibleError(
                'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(e)
            )
