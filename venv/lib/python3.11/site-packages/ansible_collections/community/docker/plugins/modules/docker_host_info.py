#!/usr/bin/python
#
# Copyright (c) 2019 Piotr Wojciechowski <piotr@it-playground.pl>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_host_info

short_description: Retrieves facts about docker host and lists of objects of the services

description:
  - Retrieves facts about a docker host.
  - Essentially returns the output of C(docker system info).
  - The module also allows to list object names for containers, images, networks and volumes. It also allows to query information
    on disk usage.
  - The output differs depending on API version of the docker daemon.
  - If the docker daemon cannot be contacted or does not meet the API version requirements, the module will fail.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker
  - community.docker.attributes.idempotent_not_modify_state

attributes:
  check_mode:
    support: full
    details:
      - This action does not modify state.
  diff_mode:
    support: N/A
    details:
      - This action does not modify state.

options:
  containers:
    description:
      - Whether to list containers.
    type: bool
    default: false
  containers_all:
    description:
      - By default, only running containers are returned.
      - This corresponds to the C(--all) option to C(docker container list).
    type: bool
    default: false
    version_added: 3.4.0
  containers_filters:
    description:
      - A dictionary of filter values used for selecting containers to list.
      - 'For example, C(until: 24h).'
      - C(label) is a special case of filter which can be a string C(<key>) matching when a label is present, a string C(<key>=<value>)
        matching when a label has a particular value, or a list of strings C(<key>)/C(<key>=<value).
      - See L(the docker documentation,https://docs.docker.com/engine/reference/commandline/container_prune/#filtering) for
        more information on possible filters.
    type: dict
  images:
    description:
      - Whether to list images.
    type: bool
    default: false
  images_filters:
    description:
      - A dictionary of filter values used for selecting images to list.
      - 'For example, C(dangling: true).'
      - C(label) is a special case of filter which can be a string C(<key>) matching when a label is present, a string C(<key>=<value>)
        matching when a label has a particular value, or a list of strings C(<key>)/C(<key>=<value).
      - See L(the docker documentation,https://docs.docker.com/engine/reference/commandline/image_prune/#filtering) for more
        information on possible filters.
    type: dict
  networks:
    description:
      - Whether to list networks.
    type: bool
    default: false
  networks_filters:
    description:
      - A dictionary of filter values used for selecting networks to list.
      - C(label) is a special case of filter which can be a string C(<key>) matching when a label is present, a string C(<key>=<value>)
        matching when a label has a particular value, or a list of strings C(<key>)/C(<key>=<value).
      - See L(the docker documentation,https://docs.docker.com/engine/reference/commandline/network_prune/#filtering) for
        more information on possible filters.
    type: dict
  volumes:
    description:
      - Whether to list volumes.
    type: bool
    default: false
  volumes_filters:
    description:
      - A dictionary of filter values used for selecting volumes to list.
      - C(label) is a special case of filter which can be a string C(<key>) matching when a label is present, a string C(<key>=<value>)
        matching when a label has a particular value, or a list of strings C(<key>)/C(<key>=<value).
      - See L(the docker documentation,https://docs.docker.com/engine/reference/commandline/volume_prune/#filtering) for more
        information on possible filters.
    type: dict
  disk_usage:
    description:
      - Summary information on used disk space by all Docker layers.
      - The output is a sum of images, volumes, containers and build cache.
    type: bool
    default: false
  verbose_output:
    description:
      - When set to V(true) and O(networks), O(volumes), O(images), O(containers), or O(disk_usage) is set to V(true) then
        output will contain verbose information about objects matching the full output of API method. For details see the
        documentation of your version of Docker API at U(https://docs.docker.com/engine/api/).
      - The verbose output in this module contains only subset of information returned by this module for each type of the
        objects.
    type: bool
    default: false

author:
  - Piotr Wojciechowski (@WojciechowskiPiotr)

requirements:
  - "Docker API >= 1.25"
"""

EXAMPLES = r"""
---
- name: Get info on docker host
  community.docker.docker_host_info:
  register: result

- name: Get info on docker host and list images
  community.docker.docker_host_info:
    images: true
  register: result

- name: Get info on docker host and list images matching the filter
  community.docker.docker_host_info:
    images: true
    images_filters:
      label: "mylabel"
  register: result

- name: Get info on docker host and verbose list images
  community.docker.docker_host_info:
    images: true
    verbose_output: true
  register: result

- name: Get info on docker host and used disk space
  community.docker.docker_host_info:
    disk_usage: true
  register: result

- name: Get info on docker host and list containers matching the filter
  community.docker.docker_host_info:
    containers: true
    containers_filters:
      label:
        - key1=value1
        - key2=value2
  register: result

- name: Show host information
  ansible.builtin.debug:
    var: result.host_info
"""

RETURN = r"""
can_talk_to_docker:
  description:
    - Will be V(true) if the module can talk to the docker daemon.
  returned: both on success and on error
  type: bool

host_info:
  description:
    - Facts representing the basic state of the docker host. Matches the C(docker system info) output.
  returned: always
  type: dict
volumes:
  description:
    - List of dict objects containing the basic information about each volume. Keys matches the C(docker volume ls) output
      unless O(verbose_output=true). See description for O(verbose_output).
  returned: When O(volumes=true)
  type: list
  elements: dict
networks:
  description:
    - List of dict objects containing the basic information about each network. Keys matches the C(docker network ls) output
      unless O(verbose_output=true). See description for O(verbose_output).
  returned: When O(networks=true)
  type: list
  elements: dict
containers:
  description:
    - List of dict objects containing the basic information about each container. Keys matches the C(docker container ls)
      output unless O(verbose_output=true). See description for O(verbose_output).
  returned: When O(containers=true)
  type: list
  elements: dict
images:
  description:
    - List of dict objects containing the basic information about each image. Keys matches the C(docker image ls) output unless
      O(verbose_output=true). See description for O(verbose_output).
  returned: When O(images=true)
  type: list
  elements: dict
disk_usage:
  description:
    - Information on summary disk usage by images, containers and volumes on docker host unless O(verbose_output=true). See
      description for O(verbose_output).
  returned: When O(disk_usage=true)
  type: dict
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)

from ansible_collections.community.docker.plugins.module_utils.util import (
    DockerBaseClass,
    clean_dict_booleans_for_docker_api,
)
from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException, APIError
from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import convert_filters


class DockerHostManager(DockerBaseClass):

    def __init__(self, client, results):

        super(DockerHostManager, self).__init__()

        self.client = client
        self.results = results
        self.verbose_output = self.client.module.params['verbose_output']

        listed_objects = ['volumes', 'networks', 'containers', 'images']

        self.results['host_info'] = self.get_docker_host_info()
        # At this point we definitely know that we can talk to the Docker daemon
        self.results['can_talk_to_docker'] = True
        self.client.fail_results['can_talk_to_docker'] = True

        if self.client.module.params['disk_usage']:
            self.results['disk_usage'] = self.get_docker_disk_usage_facts()

        for docker_object in listed_objects:
            if self.client.module.params[docker_object]:
                returned_name = docker_object
                filter_name = docker_object + "_filters"
                filters = clean_dict_booleans_for_docker_api(client.module.params.get(filter_name), True)
                self.results[returned_name] = self.get_docker_items_list(docker_object, filters)

    def get_docker_host_info(self):
        try:
            return self.client.info()
        except APIError as exc:
            self.client.fail("Error inspecting docker host: %s" % to_native(exc))

    def get_docker_disk_usage_facts(self):
        try:
            if self.verbose_output:
                return self.client.df()
            else:
                return dict(LayersSize=self.client.df()['LayersSize'])
        except APIError as exc:
            self.client.fail("Error inspecting docker host: %s" % to_native(exc))

    def get_docker_items_list(self, docker_object=None, filters=None, verbose=False):
        items = None
        items_list = []

        header_containers = ['Id', 'Image', 'Command', 'Created', 'Status', 'Ports', 'Names']
        header_volumes = ['Driver', 'Name']
        header_images = ['Id', 'RepoTags', 'Created', 'Size']
        header_networks = ['Id', 'Driver', 'Name', 'Scope']

        filter_arg = dict()
        if filters:
            filter_arg['filters'] = filters
        try:
            if docker_object == 'containers':
                params = {
                    'limit': -1,
                    'all': 1 if self.client.module.params['containers_all'] else 0,
                    'size': 0,
                    'trunc_cmd': 0,
                    'filters': convert_filters(filters) if filters else None,
                }
                items = self.client.get_json("/containers/json", params=params)
            elif docker_object == 'networks':
                params = {
                    'filters': convert_filters(filters or {})
                }
                items = self.client.get_json("/networks", params=params)
            elif docker_object == 'images':
                params = {
                    'only_ids': 0,
                    'all': 0,
                    'filters': convert_filters(filters) if filters else None,
                }
                items = self.client.get_json("/images/json", params=params)
            elif docker_object == 'volumes':
                params = {
                    'filters': convert_filters(filters) if filters else None,
                }
                items = self.client.get_json('/volumes', params=params)
                items = items['Volumes']
        except APIError as exc:
            self.client.fail("Error inspecting docker host for object '%s': %s" % (docker_object, to_native(exc)))

        if self.verbose_output:
            return items

        for item in items:
            item_record = dict()

            if docker_object == 'containers':
                for key in header_containers:
                    item_record[key] = item.get(key)
            elif docker_object == 'networks':
                for key in header_networks:
                    item_record[key] = item.get(key)
            elif docker_object == 'images':
                for key in header_images:
                    item_record[key] = item.get(key)
            elif docker_object == 'volumes':
                for key in header_volumes:
                    item_record[key] = item.get(key)
            items_list.append(item_record)

        return items_list


def main():
    argument_spec = dict(
        containers=dict(type='bool', default=False),
        containers_all=dict(type='bool', default=False),
        containers_filters=dict(type='dict'),
        images=dict(type='bool', default=False),
        images_filters=dict(type='dict'),
        networks=dict(type='bool', default=False),
        networks_filters=dict(type='dict'),
        volumes=dict(type='bool', default=False),
        volumes_filters=dict(type='dict'),
        disk_usage=dict(type='bool', default=False),
        verbose_output=dict(type='bool', default=False),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
        fail_results=dict(
            can_talk_to_docker=False,
        ),
    )
    if client.module.params['api_version'] is None or client.module.params['api_version'].lower() == 'auto':
        # At this point we know that we can talk to Docker, since we asked it for the API version
        client.fail_results['can_talk_to_docker'] = True

    try:
        results = dict(
            changed=False,
        )

        DockerHostManager(client, results)
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
