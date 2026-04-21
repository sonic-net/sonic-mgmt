#!/usr/bin/python
#
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_image_tag

short_description: Tag Docker images with new names and/or tags

version_added: 3.6.0

description:
  - This module allows to tag Docker images with new names and/or tags.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  idempotent:
    support: full

options:
  name:
    description:
      - 'Image name. Name format will be one of: C(name), C(repository/name), C(registry_server:port/name). When pushing or
        pulling an image the name can optionally include the tag by appending C(:tag_name).'
      - Note that image IDs (hashes) can also be used.
    type: str
    required: true
  tag:
    description:
      - Tag for the image name O(name) that is to be tagged.
      - If O(name)'s format is C(name:tag), then the tag value from O(name) will take precedence.
    type: str
    default: latest
  repository:
    description:
      - List of new image names to tag the image as.
      - Expects format C(repository:tag). If no tag is provided, will use the value of the O(tag) parameter if present, or
        V(latest).
    type: list
    elements: str
    required: true
  existing_images:
    description:
      - Defines the behavior if the image to be tagged already exists and is another image than the one identified by O(name)
        and O(tag).
      - If set to V(keep), the tagged image is kept.
      - If set to V(overwrite), the tagged image is overwritten by the specified one.
    type: str
    choices:
      - keep
      - overwrite
    default: overwrite

requirements:
  - "Docker API >= 1.25"

author:
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.docker.docker_image_push
  - module: community.docker.docker_image_remove
"""

EXAMPLES = r"""
---
- name: Tag Python 3.12 image with two new names
  community.docker.docker_image_tag:
    name: python:3.12
    repository:
      - python-3:3.12
      - local-registry:5000/python-3/3.12:latest
"""

RETURN = r"""
image:
  description: Image inspection results for the affected image.
  returned: success
  type: dict
  sample: {}
tagged_images:
  description:
    - A list of images that got tagged.
  returned: success
  type: list
  elements: str
  sample:
    - python-3:3.12
"""

import traceback

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.common.text.formatters import human_to_bytes

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


def convert_to_bytes(value, module, name, unlimited_value=None):
    if value is None:
        return value
    try:
        if unlimited_value is not None and value in ('unlimited', str(unlimited_value)):
            return unlimited_value
        return human_to_bytes(value)
    except ValueError as exc:
        module.fail_json(msg='Failed to convert %s to bytes: %s' % (name, to_native(exc)))


def image_info(name, tag, image):
    result = dict(name=name, tag=tag)
    if image:
        result['id'] = image['Id']
    else:
        result['exists'] = False
    return result


class ImageTagger(DockerBaseClass):
    def __init__(self, client):
        super(ImageTagger, self).__init__()

        self.client = client
        parameters = self.client.module.params
        self.check_mode = self.client.check_mode

        self.name = parameters['name']
        self.tag = parameters['tag']
        if not is_valid_tag(self.tag, allow_empty=True):
            self.fail('"{0}" is not a valid docker tag'.format(self.tag))

        # If name contains a tag, it takes precedence over tag parameter.
        if not is_image_name_id(self.name):
            repo, repo_tag = parse_repository_tag(self.name)
            if repo_tag:
                self.name = repo
                self.tag = repo_tag

        self.keep_existing_images = parameters['existing_images'] == 'keep'

        # Make sure names in repository are valid images, and add tag if needed
        self.repositories = []
        for i, repository in enumerate(parameters['repository']):
            if is_image_name_id(repository):
                self.fail("repository[%d] must not be an image ID; got: %s" % (i + 1, repository))
            repo, repo_tag = parse_repository_tag(repository)
            if not repo_tag:
                repo_tag = parameters['tag']
            elif not is_valid_tag(repo_tag, allow_empty=False):
                self.fail("repository[%d] must not have a digest; got: %s" % (i + 1, repository))
            self.repositories.append((repo, repo_tag))

    def fail(self, msg):
        self.client.fail(msg)

    def tag_image(self, image, name, tag):
        tagged_image = self.client.find_image(name=name, tag=tag)
        if tagged_image:
            # Idempotency checks
            if tagged_image['Id'] == image['Id']:
                return (
                    False,
                    "target image already exists (%s) and is as expected" % tagged_image['Id'],
                    tagged_image,
                )
            if self.keep_existing_images:
                return (
                    False,
                    "target image already exists (%s) and is not as expected, but kept" % tagged_image['Id'],
                    tagged_image,
                )
            msg = "target image existed (%s) and was not as expected" % tagged_image['Id']
        else:
            msg = "target image did not exist"

        if not self.check_mode:
            try:
                params = {
                    'tag': tag,
                    'repo': name,
                    'force': True,
                }
                res = self.client._post(self.client._url('/images/{0}/tag', image['Id']), params=params)
                self.client._raise_for_status(res)
                if res.status_code != 201:
                    raise Exception("Tag operation failed.")
            except Exception as exc:
                self.fail("Error: failed to tag image as %s:%s - %s" % (name, tag, to_native(exc)))

        return True, msg, tagged_image

    def tag_images(self):
        if is_image_name_id(self.name):
            image = self.client.find_image_by_id(self.name, accept_missing_image=False)
        else:
            image = self.client.find_image(name=self.name, tag=self.tag)
            if not image:
                self.fail("Cannot find image %s:%s" % (self.name, self.tag))

        before = []
        after = []
        tagged_images = []
        results = dict(
            changed=False,
            actions=[],
            image=image,
            tagged_images=tagged_images,
            diff=dict(before=dict(images=before), after=dict(images=after)),
        )
        for repository, tag in self.repositories:
            tagged, msg, old_image = self.tag_image(image, repository, tag)
            before.append(image_info(repository, tag, old_image))
            after.append(image_info(repository, tag, image if tagged else old_image))
            if tagged:
                results['changed'] = True
                results['actions'].append('Tagged image %s as %s:%s: %s' % (image['Id'], repository, tag, msg))
                tagged_images.append('%s:%s' % (repository, tag))
            else:
                results['actions'].append('Not tagged image %s as %s:%s: %s' % (image['Id'], repository, tag, msg))

        return results


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        tag=dict(type='str', default='latest'),
        repository=dict(type='list', elements='str', required=True),
        existing_images=dict(type='str', choices=['keep', 'overwrite'], default='overwrite'),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        results = ImageTagger(client).tag_images()
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
