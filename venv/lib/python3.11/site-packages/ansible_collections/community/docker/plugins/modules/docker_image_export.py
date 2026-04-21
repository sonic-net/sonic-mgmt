#!/usr/bin/python
#
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_image_export

short_description: Export (archive) Docker images

version_added: 3.7.0

description:
  - Creates an archive (tarball) from one or more Docker images.
  - This can be copied to another machine and loaded with M(community.docker.docker_image_load).
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker

attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  idempotent:
    support: partial
    details:
      - Whether the module is idempotent depends on the storage API used for images,
        which determines how the image ID is computed. The idempotency check needs
        that the image ID equals the ID stored in archive's C(manifest.json).
        This seemed to have worked fine with the default storage backend up to Docker 28,
        but seems to have changed in Docker 29.

options:
  names:
    description:
      - 'One or more image names. Name format will be one of: C(name), C(repository/name), C(registry_server:port/name). When
        pushing or pulling an image the name can optionally include the tag by appending C(:tag_name).'
      - Note that image IDs (hashes) can also be used.
    type: list
    elements: str
    required: true
    aliases:
      - name
  tag:
    description:
      - Tag for the image name O(name) that is to be tagged.
      - If O(name)'s format is C(name:tag), then the tag value from O(name) will take precedence.
    type: str
    default: latest
  path:
    description:
      - The C(.tar) file the image should be exported to.
    type: path
  force:
    description:
      - Export the image even if the C(.tar) file already exists and seems to contain the right image.
    type: bool
    default: false

requirements:
  - "Docker API >= 1.25"

author:
  - Felix Fontein (@felixfontein)

seealso:
  - module: community.docker.docker_image
  - module: community.docker.docker_image_info
  - module: community.docker.docker_image_load
"""

EXAMPLES = r"""
---
- name: Export an image
  community.docker.docker_image_export:
    name: pacur/centos-7
    path: /tmp/centos-7.tar

- name: Export multiple images
  community.docker.docker_image_export:
    names:
      - hello-world:latest
      - pacur/centos-7:latest
    path: /tmp/various.tar
"""

RETURN = r"""
images:
  description: Image inspection results for the affected images.
  returned: success
  type: list
  elements: dict
  sample: []
"""

import traceback

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClient,
    RequestException,
)

from ansible_collections.community.docker.plugins.module_utils.image_archive import (
    load_archived_image_manifest,
    api_image_id,
    ImageArchiveInvalidException,
)

from ansible_collections.community.docker.plugins.module_utils.util import (
    DockerBaseClass,
    is_image_name_id,
    is_valid_tag,
)
from ansible_collections.community.docker.plugins.module_utils._api.constants import (
    DEFAULT_DATA_CHUNK_SIZE,
)
from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException
from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import (
    parse_repository_tag,
)


class ImageExportManager(DockerBaseClass):
    def __init__(self, client):
        super(ImageExportManager, self).__init__()

        self.client = client
        parameters = self.client.module.params
        self.check_mode = self.client.check_mode

        self.path = parameters['path']
        self.force = parameters['force']
        self.tag = parameters['tag']

        if not is_valid_tag(self.tag, allow_empty=True):
            self.fail('"{0}" is not a valid docker tag'.format(self.tag))

        # If name contains a tag, it takes precedence over tag parameter.
        self.names = []
        for name in parameters['names']:
            if is_image_name_id(name):
                self.names.append({'id': name, 'joined': name})
            else:
                repo, repo_tag = parse_repository_tag(name)
                if not repo_tag:
                    repo_tag = self.tag
                self.names.append({'name': repo, 'tag': repo_tag, 'joined': '%s:%s' % (repo, repo_tag)})

        if not self.names:
            self.fail('At least one image name must be specified')

    def fail(self, msg):
        self.client.fail(msg)

    def get_export_reason(self):
        if self.force:
            return 'Exporting since force=true'

        try:
            archived_images = load_archived_image_manifest(self.path)
            if archived_images is None:
                return 'Overwriting since no image is present in archive'
        except ImageArchiveInvalidException as exc:
            self.log('Unable to extract manifest summary from archive: %s' % to_native(exc))
            return 'Overwriting an unreadable archive file'

        left_names = list(self.names)
        for archived_image in archived_images:
            found = False
            for i, name in enumerate(left_names):
                if name['id'] == api_image_id(archived_image.image_id) and [name['joined']] == archived_image.repo_tags:
                    del left_names[i]
                    found = True
                    break
            if not found:
                return 'Overwriting archive since it contains unexpected image %s named %s' % (
                    archived_image.image_id, ', '.join(archived_image.repo_tags)
                )
        if left_names:
            return 'Overwriting archive since it is missing image(s) %s' % (', '.join([name['joined'] for name in left_names]))

        return None

    def write_chunks(self, chunks):
        try:
            with open(self.path, 'wb') as fd:
                for chunk in chunks:
                    fd.write(chunk)
        except Exception as exc:
            self.fail("Error writing image archive %s - %s" % (self.path, to_native(exc)))

    def export_images(self):
        image_names = [name['joined'] for name in self.names]
        image_names_str = ', '.join(image_names)
        if len(image_names) == 1:
            self.log("Getting archive of image %s" % image_names[0])
            try:
                chunks = self.client._stream_raw_result(
                    self.client._get(self.client._url('/images/{0}/get', image_names[0]), stream=True),
                    DEFAULT_DATA_CHUNK_SIZE,
                    False,
                )
            except Exception as exc:
                self.fail("Error getting image %s - %s" % (image_names[0], to_native(exc)))
        else:
            self.log("Getting archive of images %s" % image_names_str)
            try:
                chunks = self.client._stream_raw_result(
                    self.client._get(
                        self.client._url('/images/get'),
                        stream=True,
                        params={'names': image_names},
                    ),
                    DEFAULT_DATA_CHUNK_SIZE,
                    False,
                )
            except Exception as exc:
                self.fail("Error getting images %s - %s" % (image_names_str, to_native(exc)))

        self.write_chunks(chunks)

    def run(self):
        tag = self.tag
        if not tag:
            tag = "latest"

        images = []
        for name in self.names:
            if 'id' in name:
                image = self.client.find_image_by_id(name['id'], accept_missing_image=True)
            else:
                image = self.client.find_image(name=name['name'], tag=name['tag'])
            if not image:
                self.fail("Image %s not found" % name['joined'])
            images.append(image)

            # Will have a 'sha256:' prefix
            name['id'] = image['Id']

        results = {
            'changed': False,
            'images': images,
        }

        reason = self.get_export_reason()
        if reason is not None:
            results['msg'] = reason
            results['changed'] = True

            if not self.check_mode:
                self.export_images()

        return results


def main():
    argument_spec = dict(
        path=dict(type='path'),
        force=dict(type='bool', default=False),
        names=dict(type='list', elements='str', required=True, aliases=['name']),
        tag=dict(type='str', default='latest'),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        results = ImageExportManager(client).run()
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when trying to talk to the Docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
