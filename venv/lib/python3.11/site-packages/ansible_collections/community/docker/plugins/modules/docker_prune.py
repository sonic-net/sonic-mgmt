#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_prune

short_description: Allows to prune various docker objects

description:
  - Allows to run C(docker container prune), C(docker image prune), C(docker network prune) and C(docker volume prune) through
    the Docker API.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  idempotent:
    support: full

options:
  containers:
    description:
      - Whether to prune containers.
    type: bool
    default: false
  containers_filters:
    description:
      - A dictionary of filter values used for selecting containers to delete.
      - 'For example, C(until: 24h).'
      - See L(the docker documentation,https://docs.docker.com/engine/reference/commandline/container_prune/#filtering) for
        more information on possible filters.
    type: dict
  images:
    description:
      - Whether to prune images.
    type: bool
    default: false
  images_filters:
    description:
      - A dictionary of filter values used for selecting images to delete.
      - 'For example, C(dangling: true).'
      - See L(the docker documentation,https://docs.docker.com/engine/reference/commandline/image_prune/#filtering) for more
        information on possible filters.
    type: dict
  networks:
    description:
      - Whether to prune networks.
    type: bool
    default: false
  networks_filters:
    description:
      - A dictionary of filter values used for selecting networks to delete.
      - See L(the docker documentation,https://docs.docker.com/engine/reference/commandline/network_prune/#filtering) for
        more information on possible filters.
    type: dict
  volumes:
    description:
      - Whether to prune volumes.
    type: bool
    default: false
  volumes_filters:
    description:
      - A dictionary of filter values used for selecting volumes to delete.
      - See L(the docker documentation,https://docs.docker.com/engine/reference/commandline/volume_prune/#filtering) for more
        information on possible filters.
    type: dict
  builder_cache:
    description:
      - Whether to prune the builder cache.
    type: bool
    default: false
  builder_cache_all:
    description:
      - Whether to remove all types of build cache.
    type: bool
    default: false
    version_added: 3.10.0
  builder_cache_filters:
    description:
      - A dictionary of filter values used for selecting images to delete.
      - 'For example, C(until: 10m).'
      - See L(the API documentation,https://docs.docker.com/engine/api/v1.44/#tag/Image/operation/BuildPrune) for more information
        on possible filters.
    type: dict
    version_added: 3.10.0
  builder_cache_keep_storage:
    description:
      - Amount of disk space to keep for cache in format C(<number>[<unit>]).".
      - Number is a positive integer. Unit can be one of V(B) (byte), V(K) (kibibyte, 1024B), V(M) (mebibyte), V(G) (gibibyte),
        V(T) (tebibyte), or V(P) (pebibyte).
      - Omitting the unit defaults to bytes.
    type: str
    version_added: 3.10.0

author:
  - "Felix Fontein (@felixfontein)"

notes:
  - The module always returned C(changed=false) before community.docker 3.5.1.
requirements:
  - "Docker API >= 1.25"
"""

EXAMPLES = r"""
---
- name: Prune containers older than 24h
  community.docker.docker_prune:
    containers: true
    containers_filters:
      # only consider containers created more than 24 hours ago
      until: 24h

- name: Prune containers with labels
  community.docker.docker_prune:
    containers: true
    containers_filters:
      # Prune containers whose "foo" label has value "bar", and
      # whose "bam" label has value "baz". If you only want to
      # compare one label, you can provide it as a string instead
      # of a list with one element.
      label:
        - foo=bar
        - bam=baz
      # Prune containers whose label "bar" does *not* have value
      # "baz". If you want to avoid more than one label, you can
      # provide a list of multiple label-value pairs.
      "label!": bar=baz

- name: Prune everything
  community.docker.docker_prune:
    containers: true
    images: true
    networks: true
    volumes: true
    builder_cache: true

- name: Prune everything (including non-dangling images)
  community.docker.docker_prune:
    containers: true
    images: true
    images_filters:
      dangling: false
    networks: true
    volumes: true
    builder_cache: true
"""

RETURN = r"""
# containers
containers:
  description:
    - List of IDs of deleted containers.
  returned: O(containers=true)
  type: list
  elements: str
  sample: []
containers_space_reclaimed:
  description:
    - Amount of reclaimed disk space from container pruning in bytes.
  returned: O(containers=true)
  type: int
  sample: 0

# images
images:
  description:
    - List of IDs of deleted images.
  returned: O(images=true)
  type: list
  elements: str
  sample: []
images_space_reclaimed:
  description:
    - Amount of reclaimed disk space from image pruning in bytes.
  returned: O(images=true)
  type: int
  sample: 0

# networks
networks:
  description:
    - List of IDs of deleted networks.
  returned: O(networks=true)
  type: list
  elements: str
  sample: []

# volumes
volumes:
  description:
    - List of IDs of deleted volumes.
  returned: O(volumes=true)
  type: list
  elements: str
  sample: []
volumes_space_reclaimed:
  description:
    - Amount of reclaimed disk space from volumes pruning in bytes.
  returned: O(volumes=true)
  type: int
  sample: 0

# builder_cache
builder_cache_space_reclaimed:
  description:
    - Amount of reclaimed disk space from builder cache pruning in bytes.
  returned: O(builder_cache=true)
  type: int
  sample: 0
builder_cache_caches_deleted:
  description:
    - The build caches that were deleted.
  returned: O(builder_cache=true) and API version is 1.39 or later
  type: list
  elements: str
  sample: []
  version_added: 3.10.0
"""

import traceback

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.common.text.formatters import human_to_bytes

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)

from ansible_collections.community.docker.plugins.module_utils.util import clean_dict_booleans_for_docker_api

from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException
from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import convert_filters


def main():
    argument_spec = dict(
        containers=dict(type='bool', default=False),
        containers_filters=dict(type='dict'),
        images=dict(type='bool', default=False),
        images_filters=dict(type='dict'),
        networks=dict(type='bool', default=False),
        networks_filters=dict(type='dict'),
        volumes=dict(type='bool', default=False),
        volumes_filters=dict(type='dict'),
        builder_cache=dict(type='bool', default=False),
        builder_cache_all=dict(type='bool', default=False),
        builder_cache_filters=dict(type='dict'),
        builder_cache_keep_storage=dict(type='str'),  # convert to bytes
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        option_minimal_versions=dict(
            builder_cache=dict(docker_py_version='1.31'),
            builder_cache_all=dict(docker_py_version='1.39'),
            builder_cache_filters=dict(docker_py_version='1.31'),
            builder_cache_keep_storage=dict(docker_py_version='1.39'),
        ),
        # supports_check_mode=True,
    )

    builder_cache_keep_storage = None
    if client.module.params.get('builder_cache_keep_storage') is not None:
        try:
            builder_cache_keep_storage = human_to_bytes(client.module.params.get('builder_cache_keep_storage'))
        except ValueError as exc:
            client.module.fail_json(msg='Error while parsing value of builder_cache_keep_storage: {0}'.format(exc))

    try:
        result = dict()
        changed = False

        if client.module.params['containers']:
            filters = clean_dict_booleans_for_docker_api(client.module.params.get('containers_filters'), allow_sequences=True)
            params = {'filters': convert_filters(filters)}
            res = client.post_to_json('/containers/prune', params=params)
            result['containers'] = res.get('ContainersDeleted') or []
            result['containers_space_reclaimed'] = res['SpaceReclaimed']
            if result['containers'] or result['containers_space_reclaimed']:
                changed = True

        if client.module.params['images']:
            filters = clean_dict_booleans_for_docker_api(client.module.params.get('images_filters'), allow_sequences=True)
            params = {'filters': convert_filters(filters)}
            res = client.post_to_json('/images/prune', params=params)
            result['images'] = res.get('ImagesDeleted') or []
            result['images_space_reclaimed'] = res['SpaceReclaimed']
            if result['images'] or result['images_space_reclaimed']:
                changed = True

        if client.module.params['networks']:
            filters = clean_dict_booleans_for_docker_api(client.module.params.get('networks_filters'), allow_sequences=True)
            params = {'filters': convert_filters(filters)}
            res = client.post_to_json('/networks/prune', params=params)
            result['networks'] = res.get('NetworksDeleted') or []
            if result['networks']:
                changed = True

        if client.module.params['volumes']:
            filters = clean_dict_booleans_for_docker_api(client.module.params.get('volumes_filters'), allow_sequences=True)
            params = {'filters': convert_filters(filters)}
            res = client.post_to_json('/volumes/prune', params=params)
            result['volumes'] = res.get('VolumesDeleted') or []
            result['volumes_space_reclaimed'] = res['SpaceReclaimed']
            if result['volumes'] or result['volumes_space_reclaimed']:
                changed = True

        if client.module.params['builder_cache']:
            filters = clean_dict_booleans_for_docker_api(client.module.params.get('builder_cache_filters'), allow_sequences=True)
            params = {'filters': convert_filters(filters)}
            if client.module.params.get('builder_cache_all'):
                params['all'] = 'true'
            if builder_cache_keep_storage is not None:
                params['keep-storage'] = builder_cache_keep_storage
            res = client.post_to_json('/build/prune', params=params)
            result['builder_cache_space_reclaimed'] = res['SpaceReclaimed']
            if result['builder_cache_space_reclaimed']:
                changed = True
            if 'CachesDeleted' in res:
                # API version 1.39+: return value CachesDeleted (list of str)
                result['builder_cache_caches_deleted'] = res['CachesDeleted']
                if result['builder_cache_caches_deleted']:
                    changed = True

        result['changed'] = changed
        client.module.exit_json(**result)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
