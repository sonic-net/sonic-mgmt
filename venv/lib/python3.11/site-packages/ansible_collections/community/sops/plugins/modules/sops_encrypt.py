#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
author: Felix Fontein (@felixfontein)
module: sops_encrypt
short_description: Encrypt data with SOPS
version_added: '0.1.0'
description:
  - Allows to encrypt binary data (Base64 encoded), text data, JSON or YAML data with SOPS.
options:
  path:
    description:
      - The SOPS encrypt file.
    type: path
    required: true
  force:
    description:
      - Force rewriting the encrypted file.
    type: bool
    default: false
  content_text:
    description:
      - The data to encrypt. Must be a Unicode text.
      - Please note that the module might not be idempotent if the text can be parsed as JSON or YAML.
      - Exactly one of O(content_text), O(content_binary), O(content_json), and O(content_yaml) must be specified.
    type: str
  content_binary:
    description:
      - The data to encrypt. Must be L(Base64 encoded,https://en.wikipedia.org/wiki/Base64) binary data.
      - Please note that the module might not be idempotent if the data can be parsed as JSON or YAML.
      - Exactly one of O(content_text), O(content_binary), O(content_json), and O(content_yaml) must be specified.
    type: str
  content_json:
    description:
      - The data to encrypt. Must be a JSON dictionary.
      - Exactly one of O(content_text), O(content_binary), O(content_json), and O(content_yaml) must be specified.
    type: dict
  content_yaml:
    description:
      - The data to encrypt. Must be a YAML dictionary.
      - Please note that Ansible only allows to pass data that can be represented as a JSON dictionary.
      - Exactly one of O(content_text), O(content_binary), O(content_json), and O(content_yaml) must be specified.
    type: dict
extends_documentation_fragment:
  - ansible.builtin.files
  - community.sops.sops
  - community.sops.sops.encrypt_specific
  - community.sops.attributes
  - community.sops.attributes.files
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  safe_file_operations:
    support: full
  idempotent:
    support: full
seealso:
  - plugin: community.sops.sops
    plugin_type: lookup
    description: The sops lookup can be used decrypt SOPS-encrypted files.
"""

EXAMPLES = r"""
---
- name: Encrypt a secret text
  community.sops.sops_encrypt:
    path: text-data.sops
    content_text: This is a secret text.

- name: Encrypt the contents of a file
  community.sops.sops_encrypt:
    path: binary-data.sops
    content_binary: "{{ lookup('ansible.builtin.file', '/path/to/file', rstrip=false) | b64encode }}"

- name: Encrypt some datastructure as YAML
  community.sops.sops_encrypt:
    path: stuff.sops.yaml
    content_yaml: "{{ result }}"
"""

RETURN = r"""#"""


import base64
import json
import os
import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.sops.plugins.module_utils.io import write_file
from ansible_collections.community.sops.plugins.module_utils.sops import Sops, SopsError, get_sops_argument_spec

try:
    import yaml
    YAML_IMP_ERR = None
    HAS_YAML = True
except ImportError:
    YAML_IMP_ERR = traceback.format_exc()
    HAS_YAML = False
    yaml = None


def get_data_type(module):
    if module.params['content_text'] is not None:
        return 'binary'
    if module.params['content_binary'] is not None:
        return 'binary'
    if module.params['content_json'] is not None:
        return 'json'
    if module.params['content_yaml'] is not None:
        return 'yaml'
    module.fail_json(msg='Internal error: unknown content type')


def compare_encoded_content(module, binary_data, content):
    if module.params['content_text'] is not None:
        return content == module.params['content_text'].encode('utf-8')
    if module.params['content_binary'] is not None:
        return content == binary_data
    if module.params['content_json'] is not None:
        # Compare JSON
        try:
            return json.loads(content) == module.params['content_json']
        except Exception:
            # Treat parsing errors as content not equal
            return False
    if module.params['content_yaml'] is not None:
        # Compare YAML
        try:
            return yaml.safe_load(content) == module.params['content_yaml']
        except Exception:
            # Treat parsing errors as content not equal
            return False
    module.fail_json(msg='Internal error: unknown content type')


def get_encoded_type_content(module, binary_data):
    if module.params['content_text'] is not None:
        return 'binary', module.params['content_text'].encode('utf-8')
    if module.params['content_binary'] is not None:
        return 'binary', binary_data
    if module.params['content_json'] is not None:
        return 'json', json.dumps(module.params['content_json']).encode('utf-8')
    if module.params['content_yaml'] is not None:
        return 'yaml', yaml.safe_dump(module.params['content_yaml']).encode('utf-8')
    module.fail_json(msg='Internal error: unknown content type')


def main():
    argument_spec = dict(
        path=dict(type='path', required=True),
        force=dict(type='bool', default=False),
        content_text=dict(type='str', no_log=True),
        content_binary=dict(type='str', no_log=True),
        content_json=dict(type='dict', no_log=True),
        content_yaml=dict(type='dict', no_log=True),
    )
    argument_spec.update(get_sops_argument_spec(add_encrypt_specific=True))
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[
            ('content_text', 'content_binary', 'content_json', 'content_yaml'),
        ],
        required_one_of=[
            ('content_text', 'content_binary', 'content_json', 'content_yaml'),
        ],
        supports_check_mode=True,
        add_file_common_args=True,
    )

    # Check YAML
    if module.params['content_yaml'] is not None and not HAS_YAML:
        module.fail_json(msg=missing_required_lib('pyyaml'), exception=YAML_IMP_ERR)

    # Decode binary data
    binary_data = None
    if module.params['content_binary'] is not None:
        try:
            binary_data = base64.b64decode(module.params['content_binary'])
        except Exception as e:
            module.fail_json(msg='Cannot decode Base64 encoded data: {0}'.format(e))

    path = module.params['path']
    directory = os.path.dirname(path) or None
    changed = False

    def get_option_value(argument_name):
        return module.params.get(argument_name)

    try:
        if module.params['force'] or not os.path.exists(path):
            # Simply encrypt
            changed = True
        else:
            # Change detection: check if encrypted data equals new data
            decrypted_content = Sops.decrypt(
                path, decode_output=False, output_type=get_data_type(module), rstrip=False,
                get_option_value=get_option_value, module=module,
            )
            if not compare_encoded_content(module, binary_data, decrypted_content):
                changed = True

        if changed and not module.check_mode:
            input_type, input_data = get_encoded_type_content(module, binary_data)
            output_type = None
            if path.endswith('.json'):
                output_type = 'json'
            elif path.endswith(('.yml', '.yaml')):
                output_type = 'yaml'
            data = Sops.encrypt(
                data=input_data, cwd=directory, input_type=input_type, output_type=output_type,
                filename=os.path.relpath(path, directory) if directory is not None else path,
                get_option_value=get_option_value, module=module,
            )
            write_file(module, data)
    except SopsError as e:
        module.fail_json(msg=to_text(e))

    file_args = module.load_file_common_arguments(module.params)
    changed = module.set_fs_attributes_if_different(file_args, changed)

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
