# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
name: decrpyt
short_description: Decrypt SOPS-encrypted data
version_added: 1.1.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Decrypt SOPS-encrypted data.
  - Allows to decrypt data that has been provided by an arbitrary source.
  - Note that due to Ansible lazy-evaluating expressions, it is better to use M(ansible.builtin.set_fact) to store the result
    of an evaluation in a fact to avoid recomputing the value every time the expression is used.
options:
  _input:
    description:
      - The data to decrypt.
    type: string
    required: true
  rstrip:
    description:
      - Whether to remove trailing newlines and spaces.
    type: bool
    default: true
  input_type:
    description:
      - Tell SOPS how to interpret the encrypted data.
      - There is no auto-detection since we do not have a filename. By default SOPS is told to treat the input as YAML. If
        that is wrong, please set this option to the correct value.
      - The value V(ini) is available since community.sops 1.9.0.
    type: str
    choices:
      - binary
      - json
      - yaml
      - dotenv
      - ini
    default: yaml
  output_type:
    description:
      - Tell SOPS how to interpret the decrypted file.
      - Please note that the output is always text or bytes, depending on the value of O(decode_output). To parse the resulting
        JSON or YAML, use corresponding filters such as P(ansible.builtin.from_json#filter) and P(ansible.builtin.from_yaml#filter).
      - The value V(ini) is available since community.sops 1.9.0.
    type: str
    choices:
      - binary
      - json
      - yaml
      - dotenv
      - ini
    default: yaml
  decode_output:
    description:
      - Whether to decode the output to bytes.
      - When O(output_type=binary), and the file is not known to contain UTF-8 encoded text, this should better be set to
        V(false) to prevent mangling the data with UTF-8 decoding.
    type: bool
    default: true
extends_documentation_fragment:
  - community.sops.sops
seealso:
  - plugin: community.sops.sops
    plugin_type: lookup
  - plugin: community.sops.sops
    plugin_type: vars
  - module: community.sops.load_vars
"""

EXAMPLES = r"""
---
- name: Decrypt file fetched from URL
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Fetch file from URL
      ansible.builtin.uri:
        url: https://raw.githubusercontent.com/getsops/sops/master/functional-tests/res/comments.enc.yaml
        return_content: true
      register: encrypted_content

    - name: Show encrypted data
      debug:
        msg: "{{ encrypted_content.content | ansible.builtin.from_yaml }}"

    - name: Decrypt data and decode decrypted YAML
      set_fact:
        decrypted_data: "{{ encrypted_content.content | community.sops.decrypt | ansible.builtin.from_yaml }}"

    - name: Show decrypted data
      debug:
        msg: "{{ decrypted_data }}"
"""

RETURN = r"""
_value:
  description:
    - Decrypted data as text (O(decode_output=true), default) or binary string (O(decode_output=false)).
  type: string
"""

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_bytes, to_native
from ansible.utils.display import Display

from ansible_collections.community.sops.plugins.module_utils.sops import Sops, SopsError


_VALID_TYPES = set(['binary', 'json', 'yaml', 'dotenv', 'ini'])


def decrypt_filter(data, input_type='yaml', output_type='yaml', sops_binary='sops', rstrip=True, decode_output=True,
                   aws_profile=None, aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None,
                   config_path=None, enable_local_keyservice=True, keyservice=None, age_key=None, age_keyfile=None, age_ssh_private_keyfile=None):
    '''Decrypt sops-encrypted data.'''

    # Check parameters
    if input_type not in _VALID_TYPES:
        raise AnsibleFilterError('input_type must be one of {expected}; got "{value}"'.format(
            expected=', '.join(sorted(_VALID_TYPES)), value=input_type))
    if output_type not in _VALID_TYPES:
        raise AnsibleFilterError('output_type must be one of {expected}; got "{value}"'.format(
            expected=', '.join(sorted(_VALID_TYPES)), value=output_type))

    # Create option value querier
    def get_option_value(argument_name):
        if argument_name == 'sops_binary':
            return sops_binary
        if argument_name == 'age_key':
            return age_key
        if argument_name == 'age_keyfile':
            return age_keyfile
        if argument_name == 'age_ssh_private_keyfile':
            return age_ssh_private_keyfile
        if argument_name == 'aws_profile':
            return aws_profile
        if argument_name == 'aws_access_key_id':
            return aws_access_key_id
        if argument_name == 'aws_secret_access_key':
            return aws_secret_access_key
        if argument_name == 'aws_session_token':
            return aws_session_token
        if argument_name == 'config_path':
            return config_path
        if argument_name == 'enable_local_keyservice':
            return enable_local_keyservice
        if argument_name == 'keyservice':
            return keyservice
        raise AssertionError('internal error: should not be reached')

    # Decode
    data = to_bytes(data)
    try:
        output = Sops.decrypt(
            None, content=data, display=Display(), rstrip=rstrip, decode_output=decode_output,
            input_type=input_type, output_type=output_type, get_option_value=get_option_value)
    except SopsError as e:
        raise AnsibleFilterError(to_native(e))

    return output


class FilterModule:
    '''Ansible jinja2 filters'''

    def filters(self):
        return {
            'decrypt': decrypt_filter,
        }
