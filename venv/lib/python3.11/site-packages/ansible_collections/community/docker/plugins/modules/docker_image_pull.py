#!/usr/bin/python
#
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_image_pull

short_description: Pull Docker images from registries

version_added: 3.6.0

description:
  - Pulls a Docker image from a registry.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: partial
    details:
      - When trying to pull an image with O(pull=always), the module assumes this is always changed in check mode.
      - When check mode is combined with diff mode, the pulled image's ID is always shown as V(unknown) in the diff.
  diff_mode:
    support: full
  idempotent:
    support: full

options:
  name:
    description:
      - Image name. Name format must be one of V(name), V(repository/name), or V(registry_server:port/name).
      - The name can optionally include the tag by appending V(:tag_name), or it can contain a digest by appending V(@hash:digest).
    type: str
    required: true
  tag:
    description:
      - Used to select an image when pulling. Defaults to V(latest).
      - If O(name) parameter format is C(name:tag) or C(image@hash:digest), then O(tag) will be ignored.
    type: str
    default: latest
  platform:
    description:
      - Ask for this specific platform when pulling.
    type: str
  pull:
    description:
      - Determines when to pull an image.
      - If V(always), will always pull the image.
      - If V(not_present), will only pull the image if no image of the name exists on the current Docker daemon, or if O(platform)
        does not match.
    type: str
    choices:
      - always
      - not_present
    default: always

requirements:
  - "Docker API >= 1.25"

author:
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.docker.docker_image_pull
  - module: community.docker.docker_image_remove
  - module: community.docker.docker_image_tag
"""

EXAMPLES = r"""
---
- name: Pull an image
  community.docker.docker_image_pull:
    name: pacur/centos-7
    # Select platform for pulling. If not specified, will pull whatever docker prefers.
    platform: amd64
"""

RETURN = r"""
image:
  description: Image inspection results for the affected image.
  returned: success
  type: dict
  sample: {}
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)

from ansible_collections.community.docker.plugins.module_utils.util import (
    DockerBaseClass,
    is_image_name_id,
    is_valid_tag,
)

from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException
from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import (
    parse_repository_tag,
)

from ansible_collections.community.docker.plugins.module_utils._platform import (
    normalize_platform_string,
    compare_platform_strings,
    compose_platform_string,
)


def image_info(image):
    result = {}
    if image:
        result['id'] = image['Id']
    else:
        result['exists'] = False
    return result


class ImagePuller(DockerBaseClass):
    def __init__(self, client):
        super(ImagePuller, self).__init__()

        self.client = client
        self.check_mode = self.client.check_mode

        parameters = self.client.module.params
        self.name = parameters['name']
        self.tag = parameters['tag']
        self.platform = parameters['platform']
        self.pull_mode = parameters['pull']

        if is_image_name_id(self.name):
            self.client.fail("Cannot pull an image by ID")
        if not is_valid_tag(self.tag, allow_empty=True):
            self.client.fail('"{0}" is not a valid docker tag!'.format(self.tag))

        # If name contains a tag, it takes precedence over tag parameter.
        repo, repo_tag = parse_repository_tag(self.name)
        if repo_tag:
            self.name = repo
            self.tag = repo_tag

    def pull(self):
        image = self.client.find_image(name=self.name, tag=self.tag)
        results = dict(
            changed=False,
            actions=[],
            image=image or {},
            diff=dict(before=image_info(image), after=image_info(image)),
        )

        if image and self.pull_mode == 'not_present':
            if self.platform is None:
                return results
            host_info = self.client.info()
            wanted_platform = normalize_platform_string(
                self.platform,
                daemon_os=host_info.get('OSType'),
                daemon_arch=host_info.get('Architecture'),
            )
            image_platform = compose_platform_string(
                os=image.get('Os'),
                arch=image.get('Architecture'),
                variant=image.get('Variant'),
                daemon_os=host_info.get('OSType'),
                daemon_arch=host_info.get('Architecture'),
            )
            if compare_platform_strings(wanted_platform, image_platform):
                return results

        results['actions'].append('Pulled image %s:%s' % (self.name, self.tag))
        if self.check_mode:
            results['changed'] = True
            results['diff']['after'] = image_info(dict(Id='unknown'))
        else:
            results['image'], not_changed = self.client.pull_image(self.name, tag=self.tag, platform=self.platform)
            results['changed'] = not not_changed
            results['diff']['after'] = image_info(results['image'])

        return results


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        tag=dict(type='str', default='latest'),
        platform=dict(type='str'),
        pull=dict(type='str', choices=['always', 'not_present'], default='always'),
    )

    option_minimal_versions = dict(
        platform=dict(docker_api_version='1.32'),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
        option_minimal_versions=option_minimal_versions,
    )

    try:
        results = ImagePuller(client).pull()
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
