#!/usr/bin/python
#
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_image_push

short_description: Push Docker images to registries

version_added: 3.6.0

description:
  - Pushes a Docker image to a registry.
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
  name:
    description:
      - Image name. Name format must be one of V(name), V(repository/name), or V(registry_server:port/name).
      - The name can optionally include the tag by appending V(:tag_name), or it can contain a digest by appending V(@hash:digest).
    type: str
    required: true
  tag:
    description:
      - Select which image to push. Defaults to V(latest).
      - If O(name) parameter format is C(name:tag) or C(image@hash:digest), then O(tag) will be ignored.
    type: str
    default: latest

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
- name: Push an image
  community.docker.docker_image_push:
    name: registry.example.com:5000/repo/image
    tag: latest
"""

RETURN = r"""
image:
  description: Image inspection results for the affected image.
  returned: success
  type: dict
  sample: {}
"""

import base64
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

from ansible_collections.community.docker.plugins.module_utils._api.auth import (
    get_config_header,
    resolve_repository_name,
)


class ImagePusher(DockerBaseClass):
    def __init__(self, client):
        super(ImagePusher, self).__init__()

        self.client = client
        self.check_mode = self.client.check_mode

        parameters = self.client.module.params
        self.name = parameters['name']
        self.tag = parameters['tag']

        if is_image_name_id(self.name):
            self.client.fail("Cannot push an image by ID")
        if not is_valid_tag(self.tag, allow_empty=True):
            self.client.fail('"{0}" is not a valid docker tag!'.format(self.tag))

        # If name contains a tag, it takes precedence over tag parameter.
        repo, repo_tag = parse_repository_tag(self.name)
        if repo_tag:
            self.name = repo
            self.tag = repo_tag

        if is_image_name_id(self.tag):
            self.client.fail("Cannot push an image by digest")
        if not is_valid_tag(self.tag, allow_empty=False):
            self.client.fail('"{0}" is not a valid docker tag!'.format(self.tag))

    def push(self):
        image = self.client.find_image(name=self.name, tag=self.tag)
        if not image:
            self.client.fail('Cannot find image %s:%s' % (self.name, self.tag))

        results = dict(
            changed=False,
            actions=[],
            image=image,
        )

        push_registry, push_repo = resolve_repository_name(self.name)
        try:
            results['actions'].append('Pushed image %s:%s' % (self.name, self.tag))

            headers = {}
            header = get_config_header(self.client, push_registry)
            if not header:
                # For some reason, from Docker 28.3.3 on not specifying X-Registry-Auth seems to be invalid.
                # See https://github.com/moby/moby/issues/50614.
                header = base64.urlsafe_b64encode(b"{}")
            headers['X-Registry-Auth'] = header
            response = self.client._post_json(
                self.client._url("/images/{0}/push", self.name),
                data=None,
                headers=headers,
                stream=True,
                params={'tag': self.tag},
            )
            self.client._raise_for_status(response)
            for line in self.client._stream_helper(response, decode=True):
                self.log(line, pretty_print=True)
                if line.get('errorDetail'):
                    raise Exception(line['errorDetail']['message'])
                status = line.get('status')
                if status in ("Pushing", "Pushed"):
                    results['changed'] = True
        except Exception as exc:
            if 'unauthorized' in str(exc):
                if 'authentication required' in str(exc):
                    self.client.fail("Error pushing image %s/%s:%s - %s. Try logging into %s first." %
                                     (push_registry, push_repo, self.tag, to_native(exc), push_registry))
                else:
                    self.client.fail("Error pushing image %s/%s:%s - %s. Does the repository exist?" %
                                     (push_registry, push_repo, self.tag, str(exc)))
            self.client.fail("Error pushing image %s:%s: %s" % (self.name, self.tag, to_native(exc)))

        return results


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        tag=dict(type='str', default='latest'),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )

    try:
        results = ImagePusher(client).push()
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
