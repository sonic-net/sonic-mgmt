# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import random

from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
from ansible_collections.community.docker.plugins.module_utils._six import PY2


def generate_insecure_key():
    '''Do NOT use this for cryptographic purposes!'''
    while True:
        # Generate a one-byte key. Right now the functions below do not use more
        # than one byte, so this is sufficient.
        if PY2:
            key = chr(random.randint(0, 255))
        else:
            key = bytes([random.randint(0, 255)])
        # Return anything that is not zero
        if key != b'\x00':
            return key


def scramble(value, key):
    '''Do NOT use this for cryptographic purposes!'''
    if len(key) < 1:
        raise ValueError('Key must be at least one byte')
    value = to_bytes(value)
    if PY2:
        k = ord(key[0])
        value = b''.join([chr(k ^ ord(b)) for b in value])
    else:
        k = key[0]
        value = bytes([k ^ b for b in value])
    return '=S=' + to_native(base64.b64encode(value))


def unscramble(value, key):
    '''Do NOT use this for cryptographic purposes!'''
    if len(key) < 1:
        raise ValueError('Key must be at least one byte')
    if not value.startswith(u'=S='):
        raise ValueError('Value does not start with indicator')
    value = base64.b64decode(value[3:])
    if PY2:
        k = ord(key[0])
        value = b''.join([chr(k ^ ord(b)) for b in value])
    else:
        k = key[0]
        value = bytes([k ^ b for b in value])
    return to_text(value)
