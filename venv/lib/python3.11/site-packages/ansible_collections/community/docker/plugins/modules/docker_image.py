#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_image

short_description: Manage docker images

description:
  - Build, load or pull an image, making the image available for creating containers. Also supports tagging an image, pushing
    an image, and archiving an image to a C(.tar) file.
  - We recommend to use the individual modules M(community.docker.docker_image_build), M(community.docker.docker_image_export),
    M(community.docker.docker_image_load), M(community.docker.docker_image_pull), M(community.docker.docker_image_push),
    M(community.docker.docker_image_remove), and M(community.docker.docker_image_tag) instead of this module.
notes:
  - Building images is done using Docker daemon's API. It is not possible to use BuildKit / buildx this way. Use M(community.docker.docker_image_build)
    to build images with BuildKit.
  - Exporting images is generally not idempotent. It depends on whether the image ID equals the IDs found in the generated tarball's C(manifest.json).
    This was the case with the default storage backend up to Docker 28, but seems to have changed in Docker 29.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: partial
    details:
      - When trying to pull an image, the module assumes this is always changed in check mode.
  diff_mode:
    support: none
  idempotent:
    support: partial
    details:
      - Whether the module is idempotent depends on the exact parameters, in particular of O(force_source) and O(force_tag).
      # TODO: improve idempotent details!

options:
  source:
    description:
      - Determines where the module will try to retrieve the image from.
      - Use V(build) to build the image from a C(Dockerfile). O(build.path) must be specified when this value is used.
      - Use V(load) to load the image from a C(.tar) file. O(load_path) must be specified when this value is used.
      - Use V(pull) to pull the image from a registry.
      - Use V(local) to make sure that the image is already available on the local docker daemon. This means that the module
        does not try to build, pull or load the image.
    type: str
    choices:
      - build
      - load
      - pull
      - local
  build:
    description:
      - Specifies options used for building images.
    type: dict
    suboptions:
      cache_from:
        description:
          - List of image names to consider as cache source.
        type: list
        elements: str
      dockerfile:
        description:
          - Use with O(state=present) and O(source=build) to provide an alternate name for the Dockerfile to use when building
            an image.
          - This can also include a relative path (relative to O(build.path)).
        type: str
      http_timeout:
        description:
          - Timeout for HTTP requests during the image build operation. Provide a positive integer value for the number of
            seconds.
        type: int
      path:
        description:
          - Use with state 'present' to build an image. Will be the path to a directory containing the context and Dockerfile
            for building an image.
        type: path
        required: true
      pull:
        description:
          - When building an image downloads any updates to the FROM image in Dockerfile.
        type: bool
        default: false
      rm:
        description:
          - Remove intermediate containers after build.
        type: bool
        default: true
      network:
        description:
          - The network to use for C(RUN) build instructions.
        type: str
      nocache:
        description:
          - Do not use cache when building an image.
        type: bool
        default: false
      etc_hosts:
        description:
          - Extra hosts to add to C(/etc/hosts) in building containers, as a mapping of hostname to IP address.
          - Instead of an IP address, the special value V(host-gateway) can also be used, which resolves to the host's gateway
            IP and allows building containers to connect to services running on the host.
        type: dict
      args:
        description:
          - Provide a dictionary of C(key:value) build arguments that map to Dockerfile ARG directive.
          - Docker expects the value to be a string. For convenience any non-string values will be converted to strings.
        type: dict
      container_limits:
        description:
          - A dictionary of limits applied to each container created by the build process.
        type: dict
        suboptions:
          memory:
            description:
              - Memory limit for build in format C(<number>[<unit>]). Number is a positive integer. Unit can be V(B) (byte),
                V(K) (kibibyte, 1024B), V(M) (mebibyte), V(G) (gibibyte), V(T) (tebibyte), or V(P) (pebibyte).
              - Omitting the unit defaults to bytes.
              - Before community.docker 3.6.0, no units were allowed.
            type: str
          memswap:
            description:
              - Total memory limit (memory + swap) for build in format C(<number>[<unit>]), or the special values V(unlimited)
                or V(-1) for unlimited swap usage. Number is a positive integer. Unit can be V(B) (byte), V(K) (kibibyte,
                1024B), V(M) (mebibyte), V(G) (gibibyte), V(T) (tebibyte), or V(P) (pebibyte).
              - Omitting the unit defaults to bytes.
              - Before community.docker 3.6.0, no units were allowed, and neither was the special value V(unlimited).
            type: str
          cpushares:
            description:
              - CPU shares (relative weight).
            type: int
          cpusetcpus:
            description:
              - CPUs in which to allow execution.
              - For example, V(0-3) or V(0,1).
            type: str
      use_config_proxy:
        description:
          - If set to V(true) and a proxy configuration is specified in the docker client configuration (by default C($HOME/.docker/config.json)),
            the corresponding environment variables will be set in the container being built.
        type: bool
      target:
        description:
          - When building an image specifies an intermediate build stage by name as a final stage for the resulting image.
        type: str
      platform:
        description:
          - Platform in the format C(os[/arch[/variant]]).
        type: str
        version_added: 1.1.0
      shm_size:
        description:
          - Size of C(/dev/shm) in format C(<number>[<unit>]). Number is positive integer. Unit can be V(B) (byte), V(K) (kibibyte,
            1024B), V(M) (mebibyte), V(G) (gibibyte), V(T) (tebibyte), or V(P) (pebibyte).
          - Omitting the unit defaults to bytes. If you omit the size entirely, Docker daemon uses V(64M).
        type: str
        version_added: 3.6.0
      labels:
        description:
          - Dictionary of key value pairs.
        type: dict
        version_added: 3.6.0
  archive_path:
    description:
      - Use with O(state=present) to archive an image to a C(.tar) file.
    type: path
  load_path:
    description:
      - Use with O(state=present) to load an image from a C(.tar) file.
      - Set O(source=load) if you want to load the image.
    type: path
  force_source:
    description:
      - Use with O(state=present) to build, load or pull an image (depending on the value of the O(source) option) when the
        image already exists.
    type: bool
    default: false
  force_absent:
    description:
      - Use with O(state=absent) to un-tag and remove all images matching the specified name.
    type: bool
    default: false
  force_tag:
    description:
      - Use with O(state=present) to force tagging an image.
    type: bool
    default: false
  name:
    description:
      - 'Image name. Name format will be one of: C(name), C(repository/name), C(registry_server:port/name). When pushing or
        pulling an image the name can optionally include the tag by appending C(:tag_name).'
      - Note that image IDs (hashes) are only supported for O(state=absent), for O(state=present) with O(source=load), and
        for O(state=present) with O(source=local).
    type: str
    required: true
  pull:
    description:
      - Specifies options used for pulling images.
    type: dict
    version_added: 1.3.0
    suboptions:
      platform:
        description:
          - When pulling an image, ask for this specific platform.
          - Note that this value is not used to determine whether the image needs to be pulled. This might change in the future
            in a minor release, though.
        type: str
  push:
    description:
      - Push the image to the registry. Specify the registry as part of the O(name) or O(repository) parameter.
    type: bool
    default: false
  repository:
    description:
      - Use with O(state=present) to tag the image.
      - Expects format C(repository:tag). If no tag is provided, will use the value of the O(tag) parameter or V(latest).
      - If O(push=true), O(repository) must either include a registry, or will be assumed to belong to the default registry
        (Docker Hub).
    type: str
  state:
    description:
      - Make assertions about the state of an image.
      - When V(absent) an image will be removed. Use the force option to un-tag and remove all images matching the provided
        name.
      - When V(present) check if an image exists using the provided name and tag. If the image is not found or the force option
        is used, the image will either be pulled, built or loaded, depending on the O(source) option.
    type: str
    default: present
    choices:
      - absent
      - present
  tag:
    description:
      - Used to select an image when pulling. Will be added to the image when pushing, tagging or building. Defaults to V(latest).
      - If O(name) parameter format is C(name:tag), then tag value from O(name) will take precedence.
    type: str
    default: latest

requirements:
  - "Docker API >= 1.25"

author:
  - Pavel Antonov (@softzilla)
  - Chris Houseknecht (@chouseknecht)
  - Sorin Sbarnea (@ssbarnea)

seealso:
  - module: community.docker.docker_image_build
  - module: community.docker.docker_image_export
  - module: community.docker.docker_image_info
  - module: community.docker.docker_image_load
  - module: community.docker.docker_image_pull
  - module: community.docker.docker_image_push
  - module: community.docker.docker_image_remove
  - module: community.docker.docker_image_tag
"""

EXAMPLES = r"""
---
- name: Pull an image
  community.docker.docker_image:
    name: pacur/centos-7
    source: pull
  # Select platform for pulling. If not specified, will pull whatever docker prefers.
    pull:
      platform: amd64

- name: Tag and push to docker hub
  community.docker.docker_image:
    name: pacur/centos-7:56
    repository: dcoppenhagan/myimage:7.56
    push: true
    source: local

- name: Tag and push to local registry
  community.docker.docker_image:
  # Image will be centos:7
    name: centos
  # Will be pushed to localhost:5000/centos:7
    repository: localhost:5000/centos
    tag: 7
    push: true
    source: local

- name: Add tag latest to image
  community.docker.docker_image:
    name: myimage:7.1.2
    repository: myimage:latest
  # As 'latest' usually already is present, we need to enable overwriting of existing tags:
    force_tag: true
    source: local

- name: Remove image
  community.docker.docker_image:
    state: absent
    name: registry.ansible.com/chouseknecht/sinatra
    tag: v1

- name: Build an image and push it to a private repo
  community.docker.docker_image:
    build:
      path: ./sinatra
    name: registry.ansible.com/chouseknecht/sinatra
    tag: v1
    push: true
    source: build

- name: Archive image
  community.docker.docker_image:
    name: registry.ansible.com/chouseknecht/sinatra
    tag: v1
    archive_path: my_sinatra.tar
    source: local

- name: Load image from archive and push to a private registry
  community.docker.docker_image:
    name: localhost:5000/myimages/sinatra
    tag: v1
    push: true
    load_path: my_sinatra.tar
    source: load

- name: Build image and with build args
  community.docker.docker_image:
    name: myimage
    build:
      path: /path/to/build/dir
      args:
        log_volume: /var/log/myapp
        listen_port: 8080
    source: build

- name: Build image using cache source
  community.docker.docker_image:
    name: myimage:latest
    build:
      path: /path/to/build/dir
    # Use as cache source for building myimage
      cache_from:
        - nginx:latest
        - alpine:3.8
    source: build
"""

RETURN = r"""
image:
  description: Image inspection results for the affected image.
  returned: success
  type: dict
  sample: {}
stdout:
  description: Docker build output when building an image.
  returned: success
  type: str
  sample: ""
  version_added: 1.0.0
"""

import base64
import errno
import json
import os
import traceback

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.common.text.formatters import human_to_bytes

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)

from ansible_collections.community.docker.plugins.module_utils.image_archive import (
    archived_image_manifest,
    api_image_id,
    ImageArchiveInvalidException,
)

from ansible_collections.community.docker.plugins.module_utils.util import (
    clean_dict_booleans_for_docker_api,
    DockerBaseClass,
    is_image_name_id,
    is_valid_tag,
)
from ansible_collections.community.docker.plugins.module_utils.version import LooseVersion

from ansible_collections.community.docker.plugins.module_utils._api.auth import (
    get_config_header,
    resolve_repository_name,
)
from ansible_collections.community.docker.plugins.module_utils._api.constants import (
    DEFAULT_DATA_CHUNK_SIZE,
    CONTAINER_LIMITS_KEYS,
)
from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException, NotFound
from ansible_collections.community.docker.plugins.module_utils._api.utils.build import (
    process_dockerfile,
    tar,
)
from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import (
    format_extra_hosts,
    parse_repository_tag,
)


def convert_to_bytes(value, module, name, unlimited_value=None):
    if value is None:
        return value
    try:
        if unlimited_value is not None and value in ('unlimited', str(unlimited_value)):
            return unlimited_value
        return human_to_bytes(value)
    except ValueError as exc:
        module.fail_json(msg='Failed to convert %s to bytes: %s' % (name, to_native(exc)))


class ImageManager(DockerBaseClass):

    def __init__(self, client, results):
        '''
        Configure a docker_image task.

        :param client: Ansible Docker Client wrapper over Docker client
        :type client: AnsibleDockerClient
        :param results: This task adds its output values to this dictionary
        :type results: dict
        '''

        super(ImageManager, self).__init__()

        self.client = client
        self.results = results
        parameters = self.client.module.params
        self.check_mode = self.client.check_mode

        self.source = parameters['source']
        build = parameters['build'] or dict()
        pull = parameters['pull'] or dict()
        self.archive_path = parameters['archive_path']
        self.cache_from = build.get('cache_from')
        self.container_limits = build.get('container_limits')
        if self.container_limits and 'memory' in self.container_limits:
            self.container_limits['memory'] = convert_to_bytes(
                self.container_limits['memory'], self.client.module, 'build.container_limits.memory')
        if self.container_limits and 'memswap' in self.container_limits:
            self.container_limits['memswap'] = convert_to_bytes(
                self.container_limits['memswap'], self.client.module, 'build.container_limits.memswap', unlimited_value=-1)
        self.dockerfile = build.get('dockerfile')
        self.force_source = parameters['force_source']
        self.force_absent = parameters['force_absent']
        self.force_tag = parameters['force_tag']
        self.load_path = parameters['load_path']
        self.name = parameters['name']
        self.network = build.get('network')
        self.extra_hosts = clean_dict_booleans_for_docker_api(build.get('etc_hosts'))
        self.nocache = build.get('nocache', False)
        self.build_path = build.get('path')
        self.pull = build.get('pull')
        self.target = build.get('target')
        self.repository = parameters['repository']
        self.rm = build.get('rm', True)
        self.state = parameters['state']
        self.tag = parameters['tag']
        self.http_timeout = build.get('http_timeout')
        self.pull_platform = pull.get('platform')
        self.push = parameters['push']
        self.buildargs = build.get('args')
        self.build_platform = build.get('platform')
        self.use_config_proxy = build.get('use_config_proxy')
        self.shm_size = convert_to_bytes(build.get('shm_size'), self.client.module, 'build.shm_size')
        self.labels = clean_dict_booleans_for_docker_api(build.get('labels'))

        # If name contains a tag, it takes precedence over tag parameter.
        if not is_image_name_id(self.name):
            repo, repo_tag = parse_repository_tag(self.name)
            if repo_tag:
                self.name = repo
                self.tag = repo_tag

        # Sanity check: fail early when we know that something will fail later
        if self.repository and is_image_name_id(self.repository):
            self.fail("`repository` must not be an image ID; got: %s" % self.repository)
        if not self.repository and self.push and is_image_name_id(self.name):
            self.fail("Cannot push an image by ID; specify `repository` to tag and push the image with ID %s instead" % self.name)

        if self.state == 'present':
            self.present()
        elif self.state == 'absent':
            self.absent()

    def fail(self, msg):
        self.client.fail(msg)

    def present(self):
        '''
        Handles state = 'present', which includes building, loading or pulling an image,
        depending on user provided parameters.

        :returns None
        '''
        if is_image_name_id(self.name):
            image = self.client.find_image_by_id(self.name, accept_missing_image=True)
        else:
            image = self.client.find_image(name=self.name, tag=self.tag)

        if not image or self.force_source:
            if self.source == 'build':
                if is_image_name_id(self.name):
                    self.fail("Image name must not be an image ID for source=build; got: %s" % self.name)

                # Build the image
                if not os.path.isdir(self.build_path):
                    self.fail("Requested build path %s could not be found or you do not have access." % self.build_path)
                image_name = self.name
                if self.tag:
                    image_name = "%s:%s" % (self.name, self.tag)
                self.log("Building image %s" % image_name)
                self.results['actions'].append("Built image %s from %s" % (image_name, self.build_path))
                self.results['changed'] = True
                if not self.check_mode:
                    self.results.update(self.build_image())

            elif self.source == 'load':
                # Load the image from an archive
                if not os.path.isfile(self.load_path):
                    self.fail("Error loading image %s. Specified path %s does not exist." % (self.name,
                                                                                             self.load_path))
                image_name = self.name
                if self.tag and not is_image_name_id(image_name):
                    image_name = "%s:%s" % (self.name, self.tag)
                self.results['actions'].append("Loaded image %s from %s" % (image_name, self.load_path))
                self.results['changed'] = True
                if not self.check_mode:
                    self.results['image'] = self.load_image()
            elif self.source == 'pull':
                if is_image_name_id(self.name):
                    self.fail("Image name must not be an image ID for source=pull; got: %s" % self.name)

                # pull the image
                self.results['actions'].append('Pulled image %s:%s' % (self.name, self.tag))
                self.results['changed'] = True
                if not self.check_mode:
                    self.results['image'], dummy = self.client.pull_image(self.name, tag=self.tag, platform=self.pull_platform)
            elif self.source == 'local':
                if image is None:
                    name = self.name
                    if self.tag and not is_image_name_id(name):
                        name = "%s:%s" % (self.name, self.tag)
                    self.client.fail('Cannot find the image %s locally.' % name)
            if not self.check_mode and image and image['Id'] == self.results['image']['Id']:
                self.results['changed'] = False
        else:
            self.results['image'] = image

        if self.archive_path:
            self.archive_image(self.name, self.tag)

        if self.push and not self.repository:
            self.push_image(self.name, self.tag)
        elif self.repository:
            self.tag_image(self.name, self.tag, self.repository, push=self.push)

    def absent(self):
        '''
        Handles state = 'absent', which removes an image.

        :return None
        '''
        name = self.name
        if is_image_name_id(name):
            image = self.client.find_image_by_id(name, accept_missing_image=True)
        else:
            image = self.client.find_image(name, self.tag)
            if self.tag:
                name = "%s:%s" % (self.name, self.tag)
        if image:
            if not self.check_mode:
                try:
                    self.client.delete_json('/images/{0}', name, params={'force': self.force_absent})
                except NotFound:
                    # If the image vanished while we were trying to remove it, do not fail
                    pass
                except Exception as exc:
                    self.fail("Error removing image %s - %s" % (name, to_native(exc)))

            self.results['changed'] = True
            self.results['actions'].append("Removed image %s" % (name))
            self.results['image']['state'] = 'Deleted'

    @staticmethod
    def archived_image_action(failure_logger, archive_path, current_image_name, current_image_id):
        '''
        If the archive is missing or requires replacement, return an action message.

        :param failure_logger: a logging function that accepts one parameter of type str
        :type failure_logger: Callable
        :param archive_path: Filename to write archive to
        :type archive_path: str
        :param current_image_name: repo:tag
        :type current_image_name: str
        :param current_image_id: Hash, including hash type prefix such as "sha256:"
        :type current_image_id: str

        :returns: Either None, or an Ansible action message.
        :rtype: str
        '''

        def build_msg(reason):
            return 'Archived image %s to %s, %s' % (current_image_name, archive_path, reason)

        try:
            archived = archived_image_manifest(archive_path)
        except ImageArchiveInvalidException as exc:
            failure_logger('Unable to extract manifest summary from archive: %s' % to_native(exc))
            return build_msg('overwriting an unreadable archive file')

        if archived is None:
            return build_msg('since none present')
        elif current_image_id == api_image_id(archived.image_id) and [current_image_name] == archived.repo_tags:
            return None
        else:
            name = ', '.join(archived.repo_tags)

            return build_msg('overwriting archive with image %s named %s' % (archived.image_id, name))

    def archive_image(self, name, tag):
        '''
        Archive an image to a .tar file. Called when archive_path is passed.

        :param name: Name/repository of the image
        :type name: str
        :param tag: Optional image tag; assumed to be "latest" if None
        :type tag: str | None
        '''

        if not tag:
            tag = "latest"

        if is_image_name_id(name):
            image = self.client.find_image_by_id(name, accept_missing_image=True)
            image_name = name
        else:
            image = self.client.find_image(name=name, tag=tag)
            image_name = "%s:%s" % (name, tag)

        if not image:
            self.log("archive image: image %s not found" % image_name)
            return

        # Will have a 'sha256:' prefix
        image_id = image['Id']

        action = self.archived_image_action(self.client.module.debug, self.archive_path, image_name, image_id)

        if action:
            self.results['actions'].append(action)

        self.results['changed'] = action is not None

        if (not self.check_mode) and self.results['changed']:
            self.log("Getting archive of image %s" % image_name)
            try:
                saved_image = self.client._stream_raw_result(
                    self.client._get(self.client._url('/images/{0}/get', image_name), stream=True),
                    DEFAULT_DATA_CHUNK_SIZE,
                    False,
                )
            except Exception as exc:
                self.fail("Error getting image %s - %s" % (image_name, to_native(exc)))

            try:
                with open(self.archive_path, 'wb') as fd:
                    for chunk in saved_image:
                        fd.write(chunk)
            except Exception as exc:
                self.fail("Error writing image archive %s - %s" % (self.archive_path, to_native(exc)))

        self.results['image'] = image

    def push_image(self, name, tag=None):
        '''
        If the name of the image contains a repository path, then push the image.

        :param name Name of the image to push.
        :param tag Use a specific tag.
        :return: None
        '''

        if is_image_name_id(name):
            self.fail("Cannot push an image ID: %s" % name)

        repository = name
        if not tag:
            repository, tag = parse_repository_tag(name)
        registry, repo_name = resolve_repository_name(repository)

        self.log("push %s to %s/%s:%s" % (self.name, registry, repo_name, tag))

        if registry:
            self.results['actions'].append("Pushed image %s to %s/%s:%s" % (self.name, registry, repo_name, tag))
            self.results['changed'] = True
            if not self.check_mode:
                status = None
                try:
                    changed = False

                    push_repository, push_tag = repository, tag
                    if not push_tag:
                        push_repository, push_tag = parse_repository_tag(push_repository)
                    push_registry, dummy = resolve_repository_name(push_repository)
                    headers = {}
                    header = get_config_header(self.client, push_registry)
                    if not header:
                        # For some reason, from Docker 28.3.3 on not specifying X-Registry-Auth seems to be invalid.
                        # See https://github.com/moby/moby/issues/50614.
                        header = base64.urlsafe_b64encode(b"{}")
                    headers['X-Registry-Auth'] = header
                    response = self.client._post_json(
                        self.client._url("/images/{0}/push", push_repository),
                        data=None,
                        headers=headers,
                        stream=True,
                        params={'tag': push_tag},
                    )
                    self.client._raise_for_status(response)
                    for line in self.client._stream_helper(response, decode=True):
                        self.log(line, pretty_print=True)
                        if line.get('errorDetail'):
                            raise Exception(line['errorDetail']['message'])
                        status = line.get('status')
                        if status in ("Pushing", "Pushed"):
                            changed = True
                    self.results['changed'] = changed
                except Exception as exc:
                    if 'unauthorized' in str(exc):
                        if 'authentication required' in str(exc):
                            self.fail("Error pushing image %s/%s:%s - %s. Try logging into %s first." %
                                      (registry, repo_name, tag, to_native(exc), registry))
                        else:
                            self.fail("Error pushing image %s/%s:%s - %s. Does the repository exist?" %
                                      (registry, repo_name, tag, str(exc)))
                    self.fail("Error pushing image %s: %s" % (repository, to_native(exc)))
                self.results['image'] = self.client.find_image(name=repository, tag=tag)
                if not self.results['image']:
                    self.results['image'] = dict()
                self.results['image']['push_status'] = status

    def tag_image(self, name, tag, repository, push=False):
        '''
        Tag an image into a repository.

        :param name: name of the image. required.
        :param tag: image tag.
        :param repository: path to the repository. required.
        :param push: bool. push the image once it is tagged.
        :return: None
        '''
        repo, repo_tag = parse_repository_tag(repository)
        if not repo_tag:
            repo_tag = "latest"
            if tag:
                repo_tag = tag
        image = self.client.find_image(name=repo, tag=repo_tag)
        found = 'found' if image else 'not found'
        self.log("image %s was %s" % (repo, found))

        if not image or self.force_tag:
            image_name = name
            if not is_image_name_id(name) and tag and not name.endswith(':' + tag):
                image_name = "%s:%s" % (name, tag)
            self.log("tagging %s to %s:%s" % (image_name, repo, repo_tag))
            self.results['changed'] = True
            self.results['actions'].append("Tagged image %s to %s:%s" % (image_name, repo, repo_tag))
            if not self.check_mode:
                try:
                    # Finding the image does not always work, especially running a localhost registry. In those
                    # cases, if we do not set force=True, it errors.
                    params = {
                        'tag': repo_tag,
                        'repo': repo,
                        'force': True,
                    }
                    res = self.client._post(self.client._url('/images/{0}/tag', image_name), params=params)
                    self.client._raise_for_status(res)
                    if res.status_code != 201:
                        raise Exception("Tag operation failed.")
                except Exception as exc:
                    self.fail("Error: failed to tag image - %s" % to_native(exc))
                self.results['image'] = self.client.find_image(name=repo, tag=repo_tag)
                if image and image['Id'] == self.results['image']['Id']:
                    self.results['changed'] = False

        if push:
            self.push_image(repo, repo_tag)

    @staticmethod
    def _extract_output_line(line, output):
        '''
        Extract text line from stream output and, if found, adds it to output.
        '''
        if 'stream' in line or 'status' in line:
            # Make sure we have a string (assuming that line['stream'] and
            # line['status'] are either not defined, falsish, or a string)
            text_line = line.get('stream') or line.get('status') or ''
            output.extend(text_line.splitlines())

    def build_image(self):
        '''
        Build an image

        :return: image dict
        '''
        remote = context = None
        headers = {}
        buildargs = {}
        if self.buildargs:
            for key, value in self.buildargs.items():
                buildargs[key] = to_native(value)

        container_limits = self.container_limits or {}
        for key in container_limits.keys():
            if key not in CONTAINER_LIMITS_KEYS:
                raise DockerException('Invalid container_limits key {key}'.format(key=key))

        dockerfile = self.dockerfile
        if self.build_path.startswith(('http://', 'https://', 'git://', 'github.com/', 'git@')):
            remote = self.build_path
        elif not os.path.isdir(self.build_path):
            raise TypeError("You must specify a directory to build in path")
        else:
            dockerignore = os.path.join(self.build_path, '.dockerignore')
            exclude = None
            if os.path.exists(dockerignore):
                with open(dockerignore) as f:
                    exclude = list(filter(
                        lambda x: x != '' and x[0] != '#',
                        [line.strip() for line in f.read().splitlines()]
                    ))
            dockerfile = process_dockerfile(dockerfile, self.build_path)
            context = tar(self.build_path, exclude=exclude, dockerfile=dockerfile, gzip=False)

        params = {
            't': "%s:%s" % (self.name, self.tag) if self.tag else self.name,
            'remote': remote,
            'q': False,
            'nocache': self.nocache,
            'rm': self.rm,
            'forcerm': self.rm,
            'pull': self.pull,
            'dockerfile': dockerfile,
        }
        params.update(container_limits)

        if self.use_config_proxy:
            proxy_args = self.client._proxy_configs.get_environment()
            for k, v in proxy_args.items():
                buildargs.setdefault(k, v)
        if buildargs:
            params.update({'buildargs': json.dumps(buildargs)})

        if self.cache_from:
            params.update({'cachefrom': json.dumps(self.cache_from)})

        if self.target:
            params.update({'target': self.target})

        if self.network:
            params.update({'networkmode': self.network})

        if self.extra_hosts is not None:
            params.update({'extrahosts': format_extra_hosts(self.extra_hosts)})

        if self.build_platform is not None:
            params['platform'] = self.build_platform

        if self.shm_size is not None:
            params['shmsize'] = self.shm_size

        if self.labels:
            params['labels'] = json.dumps(self.labels)

        if context is not None:
            headers['Content-Type'] = 'application/tar'

        self.client._set_auth_headers(headers)

        response = self.client._post(
            self.client._url('/build'),
            data=context,
            params=params,
            headers=headers,
            stream=True,
            timeout=self.http_timeout,
        )

        if context is not None:
            context.close()

        build_output = []
        for line in self.client._stream_helper(response, decode=True):
            # line = json.loads(line)
            self.log(line, pretty_print=True)
            self._extract_output_line(line, build_output)

            if line.get('error'):
                if line.get('errorDetail'):
                    errorDetail = line.get('errorDetail')
                    self.fail(
                        "Error building %s - code: %s, message: %s, logs: %s" % (
                            self.name,
                            errorDetail.get('code'),
                            errorDetail.get('message'),
                            build_output))
                else:
                    self.fail("Error building %s - message: %s, logs: %s" % (
                        self.name, line.get('error'), build_output))

        return {
            "stdout": "\n".join(build_output),
            "image": self.client.find_image(name=self.name, tag=self.tag),
        }

    def load_image(self):
        '''
        Load an image from a .tar archive

        :return: image dict
        '''
        # Load image(s) from file
        load_output = []
        has_output = False
        try:
            self.log("Opening image %s" % self.load_path)
            with open(self.load_path, 'rb') as image_tar:
                self.log("Loading image from %s" % self.load_path)
                res = self.client._post(self.client._url("/images/load"), data=image_tar, stream=True)
                if LooseVersion(self.client.api_version) >= LooseVersion('1.23'):
                    has_output = True
                    for line in self.client._stream_helper(res, decode=True):
                        self.log(line, pretty_print=True)
                        self._extract_output_line(line, load_output)
                else:
                    self.client._raise_for_status(res)
                    self.client.module.warn(
                        'The API version of your Docker daemon is < 1.23, which does not return the image'
                        ' loading result from the Docker daemon. Therefore, we cannot verify whether the'
                        ' expected image was loaded, whether multiple images where loaded, or whether the load'
                        ' actually succeeded. You should consider upgrading your Docker daemon.'
                    )
        except EnvironmentError as exc:
            if exc.errno == errno.ENOENT:
                self.client.fail("Error opening image %s - %s" % (self.load_path, to_native(exc)))
            self.client.fail("Error loading image %s - %s" % (self.name, to_native(exc)), stdout='\n'.join(load_output))
        except Exception as exc:
            self.client.fail("Error loading image %s - %s" % (self.name, to_native(exc)), stdout='\n'.join(load_output))

        # Collect loaded images
        if has_output:
            # We can only do this when we actually got some output from Docker daemon
            loaded_images = set()
            loaded_image_ids = set()
            for line in load_output:
                if line.startswith('Loaded image:'):
                    loaded_images.add(line[len('Loaded image:'):].strip())
                if line.startswith('Loaded image ID:'):
                    loaded_image_ids.add(line[len('Loaded image ID:'):].strip().lower())

            if not loaded_images and not loaded_image_ids:
                self.client.fail("Detected no loaded images. Archive potentially corrupt?", stdout='\n'.join(load_output))

            if is_image_name_id(self.name):
                expected_image = self.name.lower()
                found_image = expected_image not in loaded_image_ids
            else:
                expected_image = '%s:%s' % (self.name, self.tag)
                found_image = expected_image not in loaded_images
            if found_image:
                self.client.fail(
                    "The archive did not contain image '%s'. Instead, found %s." % (
                        expected_image,
                        ', '.join(sorted(["'%s'" % image for image in loaded_images] + list(loaded_image_ids)))),
                    stdout='\n'.join(load_output))
            loaded_images.remove(expected_image)

            if loaded_images:
                self.client.module.warn(
                    "The archive contained more images than specified: %s" % (
                        ', '.join(sorted(["'%s'" % image for image in loaded_images] + list(loaded_image_ids))), ))

        if is_image_name_id(self.name):
            return self.client.find_image_by_id(self.name, accept_missing_image=True)
        else:
            return self.client.find_image(self.name, self.tag)


def main():
    argument_spec = dict(
        source=dict(type='str', choices=['build', 'load', 'pull', 'local']),
        build=dict(type='dict', options=dict(
            cache_from=dict(type='list', elements='str'),
            container_limits=dict(type='dict', options=dict(
                memory=dict(type='str'),
                memswap=dict(type='str'),
                cpushares=dict(type='int'),
                cpusetcpus=dict(type='str'),
            )),
            dockerfile=dict(type='str'),
            http_timeout=dict(type='int'),
            network=dict(type='str'),
            nocache=dict(type='bool', default=False),
            path=dict(type='path', required=True),
            pull=dict(type='bool', default=False),
            rm=dict(type='bool', default=True),
            args=dict(type='dict'),
            use_config_proxy=dict(type='bool'),
            target=dict(type='str'),
            etc_hosts=dict(type='dict'),
            platform=dict(type='str'),
            shm_size=dict(type='str'),
            labels=dict(type='dict'),
        )),
        archive_path=dict(type='path'),
        force_source=dict(type='bool', default=False),
        force_absent=dict(type='bool', default=False),
        force_tag=dict(type='bool', default=False),
        load_path=dict(type='path'),
        name=dict(type='str', required=True),
        pull=dict(type='dict', options=dict(
            platform=dict(type='str'),
        )),
        push=dict(type='bool', default=False),
        repository=dict(type='str'),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        tag=dict(type='str', default='latest'),
    )

    required_if = [
        ('state', 'present', ['source']),
        ('source', 'build', ['build']),
        ('source', 'load', ['load_path']),
    ]

    def detect_etc_hosts(client):
        return client.module.params['build'] and bool(client.module.params['build'].get('etc_hosts'))

    def detect_build_platform(client):
        return client.module.params['build'] and client.module.params['build'].get('platform') is not None

    def detect_pull_platform(client):
        return client.module.params['pull'] and client.module.params['pull'].get('platform') is not None

    option_minimal_versions = dict()
    option_minimal_versions["build.etc_hosts"] = dict(docker_api_version='1.27', detect_usage=detect_etc_hosts)
    option_minimal_versions["build.platform"] = dict(docker_api_version='1.32', detect_usage=detect_build_platform)
    option_minimal_versions["pull.platform"] = dict(docker_api_version='1.32', detect_usage=detect_pull_platform)

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True,
        option_minimal_versions=option_minimal_versions,
    )

    if not is_valid_tag(client.module.params['tag'], allow_empty=True):
        client.fail('"{0}" is not a valid docker tag!'.format(client.module.params['tag']))

    if client.module.params['source'] == 'build':
        if not client.module.params['build'] or not client.module.params['build'].get('path'):
            client.fail('If "source" is set to "build", the "build.path" option must be specified.')

    try:
        results = dict(
            changed=False,
            actions=[],
            image={}
        )

        ImageManager(client, results)
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
