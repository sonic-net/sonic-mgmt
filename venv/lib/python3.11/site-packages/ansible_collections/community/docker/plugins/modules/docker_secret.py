#!/usr/bin/python
#
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_secret

short_description: Manage docker secrets

description:
  - Create and remove Docker secrets in a Swarm environment. Similar to C(docker secret create) and C(docker secret rm).
  - Adds to the metadata of new secrets C(ansible_key), an encrypted hash representation of the data, which is then used in
    future runs to test if a secret has changed. If C(ansible_key) is not present, then a secret will not be updated unless
    the O(force) option is set.
  - Updates to secrets are performed by removing the secret and creating it again.
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
      - The value of the secret.
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
      - The file on the target from which to read the secret.
      - Mutually exclusive with O(data). One of O(data) and O(data_src) is required if O(state=present).
    type: path
    version_added: 1.10.0
  labels:
    description:
      - A map of key:value meta data, where both key and value are expected to be strings.
      - If new meta data is provided, or existing meta data is modified, the secret will be updated by removing it and creating
        it again.
    type: dict
  force:
    description:
      - Use with O(state=present) to always remove and recreate an existing secret.
      - If V(true), an existing secret will be replaced, even if it has not changed.
    type: bool
    default: false
  rolling_versions:
    description:
      - If set to V(true), secrets are created with an increasing version number appended to their name.
      - Adds a label containing the version number to the managed secrets with the name C(ansible_version).
    type: bool
    default: false
    version_added: 2.2.0
  versions_to_keep:
    description:
      - When using O(rolling_versions), the number of old versions of the secret to keep.
      - Extraneous old secrets are deleted after the new one is created.
      - Set to V(-1) to keep everything or to V(0) or V(1) to keep only the current one.
    type: int
    default: 5
    version_added: 2.2.0
  name:
    description:
      - The name of the secret.
    type: str
    required: true
  state:
    description:
      - Set to V(present), if the secret should exist, and V(absent), if it should not.
    type: str
    default: present
    choices:
      - absent
      - present

requirements:
  - "L(Docker SDK for Python,https://docker-py.readthedocs.io/en/stable/) >= 2.1.0"
  - "Docker API >= 1.25"

author:
  - Chris Houseknecht (@chouseknecht)
"""

EXAMPLES = r"""
---
- name: Create secret foo (from a file on the control machine)
  community.docker.docker_secret:
    name: foo
    # If the file is JSON or binary, Ansible might modify it (because
    # it is first decoded and later re-encoded). Base64-encoding the
    # file directly after reading it prevents this to happen.
    data: "{{ lookup('file', '/path/to/secret/file') | b64encode }}"
    data_is_b64: true
    state: present

- name: Create secret foo (from a file on the target machine)
  community.docker.docker_secret:
    name: foo
    data_src: /path/to/secret/file
    state: present

- name: Change the secret data
  community.docker.docker_secret:
    name: foo
    data: Goodnight everyone!
    labels:
      bar: baz
      one: '1'
    state: present

- name: Add a new label
  community.docker.docker_secret:
    name: foo
    data: Goodnight everyone!
    labels:
      bar: baz
      one: '1'
      # Adding a new label will cause a remove/create of the secret
      two: '2'
    state: present

- name: No change
  community.docker.docker_secret:
    name: foo
    data: Goodnight everyone!
    labels:
      bar: baz
      one: '1'
      # Even though 'two' is missing, there is no change to the existing secret
    state: present

- name: Update an existing label
  community.docker.docker_secret:
    name: foo
    data: Goodnight everyone!
    labels:
      bar: monkey # Changing a label will cause a remove/create of the secret
      one: '1'
    state: present

- name: Force the removal/creation of the secret
  community.docker.docker_secret:
    name: foo
    data: Goodnight everyone!
    force: true
    state: present

- name: Remove secret foo
  community.docker.docker_secret:
    name: foo
    state: absent
"""

RETURN = r"""
secret_id:
  description:
    - The ID assigned by Docker to the secret object.
  returned: success and O(state=present)
  type: str
  sample: 'hzehrmyjigmcp2gb6nlhmjqcv'
secret_name:
  description:
    - The name of the created secret object.
  returned: success and O(state=present)
  type: str
  sample: 'awesome_secret'
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


class SecretManager(DockerBaseClass):

    def __init__(self, client, results):

        super(SecretManager, self).__init__()

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

        if self.rolling_versions:
            self.version = 0
        self.data_key = None
        self.secrets = []

    def __call__(self):
        self.get_secret()
        if self.state == 'present':
            self.data_key = hashlib.sha224(self.data).hexdigest()
            self.present()
            self.remove_old_versions()
        elif self.state == 'absent':
            self.absent()

    def get_version(self, secret):
        try:
            return int(secret.get('Spec', {}).get('Labels', {}).get('ansible_version', 0))
        except ValueError:
            return 0

    def remove_old_versions(self):
        if not self.rolling_versions or self.versions_to_keep < 0:
            return
        if not self.check_mode:
            while len(self.secrets) > max(self.versions_to_keep, 1):
                self.remove_secret(self.secrets.pop(0))

    def get_secret(self):
        ''' Find an existing secret. '''
        try:
            secrets = self.client.secrets(filters={'name': self.name})
        except APIError as exc:
            self.client.fail("Error accessing secret %s: %s" % (self.name, to_native(exc)))

        if self.rolling_versions:
            self.secrets = [
                secret
                for secret in secrets
                if secret['Spec']['Name'].startswith('{name}_v'.format(name=self.name))
            ]
            self.secrets.sort(key=self.get_version)
        else:
            self.secrets = [
                secret for secret in secrets if secret['Spec']['Name'] == self.name
            ]

    def create_secret(self):
        ''' Create a new secret '''
        secret_id = None
        # We cannot see the data after creation, so adding a label we can use for idempotency check
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
                secret_id = self.client.create_secret(self.name, self.data, labels=labels)
                self.secrets += self.client.secrets(filters={'id': secret_id})
        except APIError as exc:
            self.client.fail("Error creating secret: %s" % to_native(exc))

        if isinstance(secret_id, dict):
            secret_id = secret_id['ID']

        return secret_id

    def remove_secret(self, secret):
        try:
            if not self.check_mode:
                self.client.remove_secret(secret['ID'])
        except APIError as exc:
            self.client.fail("Error removing secret %s: %s" % (secret['Spec']['Name'], to_native(exc)))

    def present(self):
        ''' Handles state == 'present', creating or updating the secret '''
        if self.secrets:
            secret = self.secrets[-1]
            self.results['secret_id'] = secret['ID']
            self.results['secret_name'] = secret['Spec']['Name']
            data_changed = False
            attrs = secret.get('Spec', {})
            if attrs.get('Labels', {}).get('ansible_key'):
                if attrs['Labels']['ansible_key'] != self.data_key:
                    data_changed = True
            else:
                if not self.force:
                    self.client.module.warn("'ansible_key' label not found. Secret will not be changed unless the force parameter is set to 'true'")
            labels_changed = not compare_generic(self.labels, attrs.get('Labels'), 'allow_more_present', 'dict')
            if self.rolling_versions:
                self.version = self.get_version(secret)
            if data_changed or labels_changed or self.force:
                # if something changed or force, delete and re-create the secret
                if not self.rolling_versions:
                    self.absent()
                secret_id = self.create_secret()
                self.results['changed'] = True
                self.results['secret_id'] = secret_id
                self.results['secret_name'] = self.name
        else:
            self.results['changed'] = True
            self.results['secret_id'] = self.create_secret()
            self.results['secret_name'] = self.name

    def absent(self):
        ''' Handles state == 'absent', removing the secret '''
        if self.secrets:
            for secret in self.secrets:
                self.remove_secret(secret)
            self.results['changed'] = True


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        data=dict(type='str', no_log=True),
        data_is_b64=dict(type='bool', default=False),
        data_src=dict(type='path'),
        labels=dict(type='dict'),
        force=dict(type='bool', default=False),
        rolling_versions=dict(type='bool', default=False),
        versions_to_keep=dict(type='int', default=5),
    )

    required_if = [
        ('state', 'present', ['data', 'data_src'], True),
    ]

    mutually_exclusive = [
        ('data', 'data_src'),
    ]

    client = AnsibleDockerClient(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if,
        mutually_exclusive=mutually_exclusive,
        min_docker_version='2.1.0',
    )
    sanitize_labels(client.module.params['labels'], 'labels', client)

    try:
        results = dict(
            changed=False,
            secret_id='',
            secret_name=''
        )

        SecretManager(client, results)()
        client.module.exit_json(**results)
    except DockerException as e:
        client.fail('An unexpected docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except RequestException as e:
        client.fail(
            'An unexpected requests error occurred when Docker SDK for Python tried to talk to the docker daemon: {0}'.format(to_native(e)),
            exception=traceback.format_exc())


if __name__ == '__main__':
    main()
