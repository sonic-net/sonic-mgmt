#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_image_load

short_description: Load docker image(s) from archives

version_added: 1.3.0

description:
  - Load one or multiple Docker images from a C(.tar) archive, and return information on the loaded image(s).
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
    support: none

options:
  path:
    description:
      - The path to the C(.tar) archive to load Docker image(s) from.
    type: path
    required: true

requirements:
  - "Docker API >= 1.25"

author:
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.docker.docker_image_export
  - module: community.docker.docker_image_push
  - module: community.docker.docker_image_remove
  - module: community.docker.docker_image_tag
"""

EXAMPLES = r"""
---
- name: Load all image(s) from the given tar file
  community.docker.docker_image_load:
    path: /path/to/images.tar
  register: result

- name: Print the loaded image names
  ansible.builtin.debug:
    msg: "Loaded the following images: {{ result.image_names | join(', ') }}"
"""

RETURN = r"""
image_names:
  description: List of image names and IDs loaded from the archive.
  returned: success
  type: list
  elements: str
  sample:
    - 'hello-world:latest'
    - 'sha256:e004c2cc521c95383aebb1fb5893719aa7a8eae2e7a71f316a4410784edb00a9'
images:
  description: Image inspection results for the loaded images.
  returned: success
  type: list
  elements: dict
  sample: []
"""

import errno
import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)
from ansible_collections.community.docker.plugins.module_utils.util import (
    DockerBaseClass,
    is_image_name_id,
)

from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException


class ImageManager(DockerBaseClass):
    def __init__(self, client, results):
        super(ImageManager, self).__init__()

        self.client = client
        self.results = results
        parameters = self.client.module.params
        self.check_mode = self.client.check_mode

        self.path = parameters['path']

        self.load_images()

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

    def load_images(self):
        '''
        Load images from a .tar archive
        '''
        # Load image(s) from file
        load_output = []
        try:
            self.log("Opening image {0}".format(self.path))
            with open(self.path, 'rb') as image_tar:
                self.log("Loading images from {0}".format(self.path))
                res = self.client._post(self.client._url("/images/load"), data=image_tar, stream=True)
                for line in self.client._stream_helper(res, decode=True):
                    self.log(line, pretty_print=True)
                    self._extract_output_line(line, load_output)
        except EnvironmentError as exc:
            if exc.errno == errno.ENOENT:
                self.client.fail("Error opening archive {0} - {1}".format(self.path, to_native(exc)))
            self.client.fail("Error loading archive {0} - {1}".format(self.path, to_native(exc)), stdout='\n'.join(load_output))
        except Exception as exc:
            self.client.fail("Error loading archive {0} - {1}".format(self.path, to_native(exc)), stdout='\n'.join(load_output))

        # Collect loaded images
        loaded_images = []
        for line in load_output:
            if line.startswith('Loaded image:'):
                loaded_images.append(line[len('Loaded image:'):].strip())
            if line.startswith('Loaded image ID:'):
                loaded_images.append(line[len('Loaded image ID:'):].strip())

        if not loaded_images:
            self.client.fail("Detected no loaded images. Archive potentially corrupt?", stdout='\n'.join(load_output))

        images = []
        for image_name in loaded_images:
            if is_image_name_id(image_name):
                images.append(self.client.find_image_by_id(image_name))
            elif ':' in image_name:
                image_name, tag = image_name.rsplit(':', 1)
                images.append(self.client.find_image(image_name, tag))
            else:
                self.client.module.warn('Image name "{0}" is neither ID nor has a tag'.format(image_name))

        self.results['image_names'] = loaded_images
        self.results['images'] = images
        self.results['changed'] = True
        self.results['stdout'] = '\n'.join(load_output)


def main():
    client = AnsibleDockerClient(
        argument_spec=dict(
            path=dict(type='path', required=True),
        ),
        supports_check_mode=False,
    )

    try:
        results = dict(
            image_names=[],
            images=[],
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
