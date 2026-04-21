#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_config

short_description: Manage docker configs

description:
  - Create and remove Docker configs in a Swarm environment. Similar to C(docker config create) and C(docker config rm).
  - Adds to the metadata of new configs C(ansible_key), an encrypted hash representation of the data, which is then used in
    future runs to test if a config has changed. If C(ansible_key) is not present, then a config will not be updated unless
    the O(force) option is set.
  - Updates to configs are performed by removing the config and creating it again.
extends_documentation_fragment:
  - community.docker.docker
  - community.docker.docker.docker_py_2_documentation
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
      - If O(force=true) the module is not idempotent.

options:
  data:
    description:
      - The value of the config.
      - Mutually exclusive with O(data_src). One of O(data) and O(data_src) is required if O(state=present).
    type: str
  data_is_b64:
    description:
      - If set to V(true), the data is assumed to be Base64 encoded and will be decoded before being used.
      - To use binary O(data), it is better to keep it Base64 encoded and let it be decoded by this option.
    type: bool
    default: false
  data_src:
    description:
      - The file on the target from which to read the config.
      - Mutually exclusive with O(data). One of O(data) and O(data_src) is required if O(state=present).
    type: path
    version_added: 1.10.0
  labels:
    description:
      - A map of key:value meta data, where both the C(key) and C(value) are expected to be a string.
      - If new meta data is provided, or existing meta data is modified, the config will be updated by removing it and creating
        it again.
    type: dict
  force:
    description:
      - Use with O(state=present) to always remove and recreate an existing config.
      - If V(true), an existing config will be replaced, even if it has not been changed.
    type: bool
    default: false
  rolling_versions:
    description:
      - If set to V(true), configs are created with an increasing version number appended to their name.
      - Adds a label containing the version number to the managed configs with the name C(ansible_version).
    type: bool
    default: false
    version_added: 2.2.0
  versions_to_keep:
    description:
      - When using O(rolling_versions), the number of old versions of the config to keep.
      - Extraneous old configs are deleted after the new one is created.
      - Set to V(-1) to keep everything or V(0) or V(1) to keep only the current one.
    type: int
    default: 5
    version_added: 2.2.0
  name:
    description:
      - The name of the config.
    type: str
    required: true
  state:
    description:
      - Set to V(present), if the config should exist, and V(absent), if it should not.
    type: str
    default: present
    choices:
      - absent
      - present
  template_driver:
    description:
      - Set to V(golang) to use a Go template in O(data) or a Go template file in O(data_src).
    type: str
    choices:
      - golang
    version_added: 2.5.0

requirements:
  - "L(Docker SDK for Python,https://docker-py.readthedocs.io/en/stable/) >= 2.6.0"
  - "Docker API >= 1.30"

author:
  - Chris Houseknecht (@chouseknecht)
  - John Hu (@ushuz)
"""

EXAMPLES = r"""
---
- name: Create config foo (from a file on the control machine)
  community.docker.docker_config:
    name: foo
    # If the file is JSON or binary, Ansible might modify it (because
    # it is first decoded and later re-encoded). Base64-encoding the
    # file directly after reading it prevents this to happen.
    data: "{{ lookup('file', '/path/to/config/file') | b64encode }}"
    data_is_b64: true
    state: present

- name: Create config foo (from a file on the target machine)
  community.docker.docker_config:
    name: foo
    data_src: /path/to/config/file
    state: present

- name: Change the config data
  community.docker.docker_config:
    name: foo
    data: Goodnight everyone!
    labels:
      bar: baz
      one: '1'
    state: present

- name: Add a new label
  community.docker.docker_config:
    name: foo
    data: Goodnight everyone!
    labels:
      bar: baz
      one: '1'
      # Adding a new label will cause a remove/create of the config
      two: '2'
    state: present

- name: No change
  community.docker.docker_config:
    name: foo
    data: Goodnight everyone!
    labels:
      bar: baz
      one: '1'
      # Even though 'two' is missing, there is no change to the existing config
    state: present

- name: Update an existing label
  community.docker.docker_config:
    name: foo
    data: Goodnight everyone!
    labels:
      bar: monkey # Changing a label will cause a remove/create of the config
      one: '1'
    state: present

- name: Force the (re-)creation of the config
  community.docker.docker_config:
    name: foo
    data: Goodnight everyone!
    force: true
    state: present

- name: Remove config foo
  community.docker.docker_config:
    name: foo
    state: absent
"""

RETURN = r"""
config_id:
  description:
    - The ID assigned by Docker to the config object.
  returned: success and O(state=present)
  type: str
  sample: 'hzehrmyjigmcp2gb6nlhmjqcv'
config_name:
  description:
    - The name of the created config object.
  returned: success and O(state=present)
  type: str
  sample: 'awesome_config'
  version_added: 2.2.0
"""

import base64
import hashlib
import traceback

try:
    from docker.errors import DockerException, APIError
except ImportError:
    # missing Docker SDK for Python handled in ansible.module_utils.docker.common
    pass

from ansible_collections.community.docker.plugins.module_utils.common import (
    AnsibleDockerClient,
    RequestException,
)
from ansible_collections.community.docker.plugins.module_utils.util import (
    DockerBaseClass,
    compare_generic,
    sanitize_labels,
)
from ansible.module_utils.common.text.converters import to_native, to_bytes


class ConfigManager(DockerBaseClass):

    def __init__(self, client, results):

        super(ConfigManager, self).__init__()

        self.client = client
        self.results = results
        self.check_mode = self.client.check_mode

        parameters = self.client.module.params
        self.name = parameters.get('name')
        self.state = parameters.get('state')
        self.data = parameters.get('data')
        if self.data is not None:
            if parameters.get('data_is_b64'):
                self.data = base64.b64decode(self.data)
            else:
                self.data = to_bytes(self.data)
        data_src = parameters.get('data_src')
        if data_src is not None:
            try:
                with open(data_src, 'rb') as f:
                    self.data = f.read()
            except Exception as exc:
                self.client.fail('Error while reading {src}: {error}'.format(src=data_src, error=to_native(exc)))
        self.labels = parameters.get('labels')
        self.force = parameters.get('force')
        self.rolling_versions = parameters.get('rolling_versions')
        self.versions_to_keep = parameters.get('versions_to_keep')
        self.template_driver = parameters.get('template_driver')

        if self.rolling_versions:
            self.version = 0
        self.data_key = None
        self.configs = []

    def __call__(self):
        self.get_config()
        if self.state == 'present':
            self.data_key = hashlib.sha224(self.data).hexdigest()
            self.present()
            self.remove_old_versions()
        elif self.state == 'absent':
            self.absent()

    def get_version(self, config):
        try:
            return int(config.get('Spec', {}).get('Labels', {}).get('ansible_version', 0))
        except ValueError:
            return 0

    def remove_old_versions(self):
        if not self.rolling_versions or self.versions_to_keep < 0:
            return
        if not self.check_mode:
            while len(self.configs) > max(self.versions_to_keep, 1):
                self.remove_config(self.configs.pop(0))

    def get_config(self):
        ''' Find an existing config. '''
        try:
            configs = self.client.configs(filters={'name': self.name})
        except APIError as exc:
            self.client.fail("Error accessing config %s: %s" % (self.name, to_native(exc)))

        if self.rolling_versions:
            self.configs = [
                config
                for config in configs
                if config['Spec']['Name'].startswith('{name}_v'.format(name=self.name))
            ]
            self.configs.sort(key=self.get_version)
        else:
            self.configs = [
                config for config in configs if config['Spec']['Name'] == self.name
            ]

    def create_config(self):
        ''' Create a new config '''
        config_id = None
        # We ca not see the data after creation, so adding a label we can use for idempotency check
        labels = {
            'ansible_key': self.data_key
        }
        if self.rolling_versions:
            self.version += 1
            labels['ansible_version'] = str(self.version)
            self.name = '{name}_v{version}'.format(name=self.name, version=self.version)
        if self.labels:
            labels.update(self.labels)

        try:
            if not self.check_mode:
                # only use templating argument when self.template_driver is defined
                kwargs = {}
                if self.template_driver:
                    kwargs['templating'] = {
                        'name': self.template_driver
                    }
                config_id = self.client.create_config(self.name, self.data, labels=labels, **kwargs)
                self.configs += self.client.configs(filters={'id': config_id})
        except APIError as exc:
            self.client.fail("Error creating config: %s" % to_native(exc))

        if isinstance(config_id, dict):
            config_id = config_id['ID']

        return config_id

    def remove_config(self, config):
        try:
            if not self.check_mode:
                self.client.remove_config(config['ID'])
        except APIError as exc:
            self.client.fail("Error removing config %s: %s" % (config['Spec']['Name'], to_native(exc)))

    def present(self):
        ''' Handles state == 'present', creating or updating the config '''
        if self.configs:
            config = self.configs[-1]
            self.results['config_id'] = config['ID']
            self.results['config_name'] = config['Spec']['Name']
            data_changed = False
            template_driver_changed = False
            attrs = config.get('Spec', {})
            if attrs.get('Labels', {}).get('ansible_key'):
                if attrs['Labels']['ansible_key'] != self.data_key:
                    data_changed = True
            else:
                if not self.force:
                    self.client.module.warn("'ansible_key' label not found. Config will not be changed unless the force parameter is set to 'true'")
            # template_driver has changed if it was set in the previous config
            # and now it differs, or if it was not set but now it is.
            if attrs.get('Templating', {}).get('Name'):
                if attrs['Templating']['Name'] != self.template_driver:
                    template_driver_changed = True
            elif self.template_driver:
                template_driver_changed = True
            labels_changed = not compare_generic(self.labels, attrs.get('Labels'), 'allow_more_present', 'dict')
            if self.rolling_versions:
                self.version = self.get_version(config)
            if data_changed or template_driver_changed or labels_changed or self.force:
                # if something changed or force, delete and re-create the config
                if not self.rolling_versions:
                    self.absent()
                config_id = self.create_config()
                self.results['changed'] = True
                self.results['config_id'] = config_id
                self.results['config_name'] = self.name
        else:
            self.results['changed'] = True
            self.results['config_id'] = self.create_config()
            self.results['config_name'] = self.name

    def absent(self):
        ''' Handles state == 'absent', removing the config '''
        if self.configs:
            for config in self.configs:
                self.remove_config(config)
            self.results['changed'] = True


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        data=dict(type='str'),
        data_is_b64=dict(type='bool', default=False),
        data_src=dict(type='path'),
        labels=dict(type='dict'),
        force=dict(type='bool', default=False),
        rolling_versions=dict(type='bool', default=False),
        versions_to_keep=dict(type='int', default=5),
        template_driver=dict(type='str', choices=['golang']),
    )

    required_if = [
        ('state', 'present', ['data', 'data_src'], True),
    ]

    mutually_exclusive = [
        ('data', 'data_src'),
    ]

    option_minimal_versions = dict(
        template_driver=dict(docker_py_version='5.0.3', docker_api_version='1.37'),
    )

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if,
        mutually_exclusive=mutually_exclusive,
        min_docker_version='2.6.0',
        min_docker_api_version='1.30',
        option_minimal_versions=option_minimal_versions,
    )
    sanitize_labels(client.module.params['labels'], 'labels', client)

    try:
        results = dict(
            changed=False,
        )

        ConfigManager(client, results)()
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when Docker SDK for Python tried to talk to the docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
