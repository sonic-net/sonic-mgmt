#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_image_remove

short_description: Remove Docker images

version_added: 3.6.0

description:
  - Remove Docker images from the Docker daemon.
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
  force:
    description:
      - Un-tag and remove all images matching the specified name.
    type: bool
    default: false
  prune:
    description:
      - Delete untagged parent images.
    type: bool
    default: true

requirements:
  - "Docker API >= 1.25"

author:
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.docker.docker_image_load
  - module: community.docker.docker_image_pull
  - module: community.docker.docker_image_tag
"""

EXAMPLES = r"""
---
- name: Remove an image
  community.docker.docker_image_remove:
    name: pacur/centos-7
"""

RETURN = r"""
image:
  description:
    - Image inspection results for the affected image before removal.
    - Empty if the image was not found.
  returned: success
  type: dict
  sample: {}
deleted:
  description:
    - The digests of the images that were deleted.
  returned: success
  type: list
  elements: str
  sample: []
untagged:
  description:
    - The digests of the images that were untagged.
  returned: success
  type: list
  elements: str
  sample: []
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

from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException, NotFound
from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import (
    parse_repository_tag,
)


class ImageRemover(DockerBaseClass):

    def __init__(self, client):
        super(ImageRemover, self).__init__()

        self.client = client
        self.check_mode = self.client.check_mode
        self.diff = self.client.module._diff

        parameters = self.client.module.params
        self.name = parameters['name']
        self.tag = parameters['tag']
        self.force = parameters['force']
        self.prune = parameters['prune']

        if not is_valid_tag(self.tag, allow_empty=True):
            self.fail('"{0}" is not a valid docker tag'.format(self.tag))

        # If name contains a tag, it takes precedence over tag parameter.
        if not is_image_name_id(self.name):
            repo, repo_tag = parse_repository_tag(self.name)
            if repo_tag:
                self.name = repo
                self.tag = repo_tag

    def fail(self, msg):
        self.client.fail(msg)

    def get_diff_state(self, image):
        if not image:
            return dict(exists=False)
        return dict(
            exists=True,
            id=image['Id'],
            tags=sorted(image.get('RepoTags') or []),
            digests=sorted(image.get('RepoDigests') or []),
        )

    def absent(self):
        results = dict(
            changed=False,
            actions=[],
            image={},
            deleted=[],
            untagged=[],
        )

        name = self.name
        if is_image_name_id(name):
            image = self.client.find_image_by_id(name, accept_missing_image=True)
        else:
            image = self.client.find_image(name, self.tag)
            if self.tag:
                name = "%s:%s" % (self.name, self.tag)

        if self.diff:
            results['diff'] = dict(before=self.get_diff_state(image))

        if not image:
            if self.diff:
                results['diff']['after'] = self.get_diff_state(image)
            return results

        results['changed'] = True
        results['actions'].append("Removed image %s" % (name))
        results['image'] = image

        if not self.check_mode:
            try:
                res = self.client.delete_json('/images/{0}', name, params={'force': self.force, 'noprune': not self.prune})
            except NotFound:
                # If the image vanished while we were trying to remove it, do not fail
                res = []
            except Exception as exc:
                self.fail("Error removing image %s - %s" % (name, to_native(exc)))

            for entry in res:
                if entry.get('Untagged'):
                    results['untagged'].append(entry['Untagged'])
                if entry.get('Deleted'):
                    results['deleted'].append(entry['Deleted'])

            results['untagged'] = sorted(results['untagged'])
            results['deleted'] = sorted(results['deleted'])

            if self.diff:
                image_after = self.client.find_image_by_id(image['Id'], accept_missing_image=True)
                results['diff']['after'] = self.get_diff_state(image_after)

        elif is_image_name_id(name):
            results['deleted'].append(image['Id'])
            # TODO: the following is no longer correct with Docker 29+...
            results['untagged'] = sorted((image.get('RepoTags') or []) + (image.get('RepoDigests') or []))
            if not self.force and results['untagged']:
                self.fail('Cannot delete image by ID that is still in use - use force=true')
            if self.diff:
                results['diff']['after'] = self.get_diff_state({})

        elif is_image_name_id(self.tag):
            results['untagged'].append(name)
            if len(image.get('RepoTags') or []) < 1 and len(image.get('RepoDigests') or []) < 2:
                results['deleted'].append(image['Id'])
            if self.diff:
                results['diff']['after'] = self.get_diff_state(image)
                try:
                    results['diff']['after']['digests'].remove(name)
                except ValueError:
                    pass

        else:
            results['untagged'].append(name)
            if len(image.get('RepoTags') or []) < 2 and len(image.get('RepoDigests') or []) < 1:
                results['deleted'].append(image['Id'])
            if self.diff:
                results['diff']['after'] = self.get_diff_state(image)
                try:
                    results['diff']['after']['tags'].remove(name)
                except ValueError:
                    pass

        return results


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        tag=dict(type='str', default='latest'),
        force=dict(type='bool', default=False),
        prune=dict(type='bool', default=True),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        results = ImageRemover(client).absent()
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
