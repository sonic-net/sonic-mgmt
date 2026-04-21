#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_image_info

short_description: Inspect docker images

description:
  - Provide one or more image names, and the module will inspect each, returning an array of inspection results.
  - If an image does not exist locally, it will not appear in the results. If you want to check whether an image exists locally,
    you can call the module with the image name, then check whether the result list is empty (image does not exist) or has
    one element (the image exists locally).
  - The module will not attempt to pull images from registries. Use M(community.docker.docker_image) with O(community.docker.docker_image#module:source=pull)
    to ensure an image is pulled.
notes:
  - This module was called C(docker_image_facts) before Ansible 2.8. The usage did not change.
extends_documentation_fragment:
  - community.docker.docker.api_documentation
  - community.docker.attributes
  - community.docker.attributes.actiongroup_docker
  - community.docker.attributes.info_module
  - community.docker.attributes.idempotent_not_modify_state

options:
  name:
    description:
      - An image name or a list of image names. Name format will be C(name[:tag]) or C(repository/name[:tag]), where C(tag)
        is optional. If a tag is not provided, V(latest) will be used. Instead of image names, also image IDs can be used.
      - If no name is provided, a list of all images will be returned.
    type: list
    elements: str

requirements:
  - "Docker API >= 1.25"

author:
  - Chris Houseknecht (@chouseknecht)
"""

EXAMPLES = r"""
---
- name: Inspect a single image
  community.docker.docker_image_info:
    name: pacur/centos-7

- name: Inspect multiple images
  community.docker.docker_image_info:
    name:
      - pacur/centos-7
      - sinatra
  register: result

- name: Make sure that both images pacur/centos-7 and sinatra exist locally
  ansible.builtin.assert:
    that:
      - result.images | length == 2
"""

RETURN = r"""
images:
  description:
    - Inspection results for the selected images.
    - The list only contains inspection results of images existing locally.
  returned: always
  type: list
  elements: dict
  sample: [
    {
      "Architecture": "amd64",
      "Author": "",
      "Comment": "",
      "Config": {
        "AttachStderr": false,
        "AttachStdin": false,
        "AttachStdout": false,
        "Cmd": ["/etc/docker/registry/config.yml"],
        "Domainname": "",
        "Entrypoint": ["/bin/registry"],
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "ExposedPorts": {"5000/tcp": {}},
        "Hostname": "e5c68db50333",
        "Image": "c72dce2618dc8f7b794d2b2c2b1e64e0205ead5befc294f8111da23bd6a2c799",
        "Labels": {},
        "OnBuild": [],
        "OpenStdin": false,
        "StdinOnce": false,
        "Tty": false,
        "User": "",
        "Volumes": {"/var/lib/registry": {}},
        "WorkingDir": "",
      },
      "Container": "e83a452b8fb89d78a25a6739457050131ca5c863629a47639530d9ad2008d610",
      "ContainerConfig": {
        "AttachStderr": false,
        "AttachStdin": false,
        "AttachStdout": false,
        "Cmd": ["/bin/sh", "-c", '#(nop) CMD ["/etc/docker/registry/config.yml"]'],
        "Domainname": "",
        "Entrypoint": ["/bin/registry"],
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "ExposedPorts": {"5000/tcp": {}},
        "Hostname": "e5c68db50333",
        "Image": "c72dce2618dc8f7b794d2b2c2b1e64e0205ead5befc294f8111da23bd6a2c799",
        "Labels": {},
        "OnBuild": [],
        "OpenStdin": false,
        "StdinOnce": false,
        "Tty": false,
        "User": "",
        "Volumes": {"/var/lib/registry": {}},
        "WorkingDir": "",
      },
      "Created": "2016-03-08T21:08:15.399680378Z",
      "DockerVersion": "1.9.1",
      "GraphDriver": {
        "Data": null,
        "Name": "aufs",
      },
      "Id": "53773d8552f07b730f3e19979e32499519807d67b344141d965463a950a66e08",
      "Name": "registry:2",
      "Os": "linux",
      "Parent": "f0b1f729f784b755e7bf9c8c2e65d8a0a35a533769c2588f02895f6781ac0805",
      "RepoDigests": [],
      "RepoTags": ["registry:2"],
      "Size": 0,
      "VirtualSize": 165808884,
    },
  ]
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
)
from ansible_collections.community.docker.plugins.module_utils._api.errors import DockerException, NotFound
from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import parse_repository_tag


class ImageManager(DockerBaseClass):

    def __init__(self, client, results):

        super(ImageManager, self).__init__()

        self.client = client
        self.results = results
        self.name = self.client.module.params.get('name')
        self.log("Gathering facts for images: %s" % (str(self.name)))

        if self.name:
            self.results['images'] = self.get_facts()
        else:
            self.results['images'] = self.get_all_images()

    def fail(self, msg):
        self.client.fail(msg)

    def get_facts(self):
        '''
        Lookup and inspect each image name found in the names parameter.

        :returns array of image dictionaries
        '''

        results = []

        names = self.name
        if not isinstance(names, list):
            names = [names]

        for name in names:
            if is_image_name_id(name):
                self.log('Fetching image %s (ID)' % (name))
                image = self.client.find_image_by_id(name, accept_missing_image=True)
            else:
                repository, tag = parse_repository_tag(name)
                if not tag:
                    tag = 'latest'
                self.log('Fetching image %s:%s' % (repository, tag))
                image = self.client.find_image(name=repository, tag=tag)
            if image:
                results.append(image)
        return results

    def get_all_images(self):
        results = []
        params = {
            'only_ids': 0,
            'all': 0,
        }
        images = self.client.get_json("/images/json", params=params)
        for image in images:
            try:
                inspection = self.client.get_json('/images/{0}/json', image['Id'])
            except NotFound:
                inspection = None
            except Exception as exc:
                self.fail("Error inspecting image %s - %s" % (image['Id'], to_native(exc)))
            results.append(inspection)
        return results


def main():
    argument_spec = dict(
        name=dict(type='list', elements='str'),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        results = dict(
            changed=False,
            images=[]
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
