#!/usr/bin/python
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_privatekey_pipe
short_description: Generate OpenSSL private keys without disk access
version_added: 1.3.0
description:
  - This module allows one to (re)generate OpenSSL private keys without disk access.
  - This allows to read and write keys to vaults without having to write intermediate versions to disk.
  - Make sure to not write the result of this module into logs or to the console, as it contains private key data! Use the
    C(no_log) task option to be sure.
  - Note that this module is implemented as an L(action plugin,https://docs.ansible.com/ansible/latest/plugins/action.html)
    and will always be executed on the controller.
author:
  - Yanis Guenane (@Spredzy)
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._attributes.flow
  - community.crypto._module_privatekey
attributes:
  action:
    support: full
  async:
    support: none
    details:
      - This action runs completely on the controller.
  check_mode:
    support: full
    details:
      - Since community.crypto 3.0.0, the module ignores check mode and always behaves as if check mode is not active.
options:
  content:
    description:
      - The current private key data.
      - Needed for idempotency. If not provided, the module will always return a change, and all idempotence-related options
        are ignored.
    type: str
  content_base64:
    description:
      - Set to V(true) if the content is base64 encoded.
    type: bool
    default: false
  return_current_key:
    description:
      - Set to V(true) to return the current private key when the module did not generate a new one.
      - Note that in case of check mode, when this option is not set to V(true), the module always returns the current key
        (if it was provided) and Ansible will replace it by C(VALUE_SPECIFIED_IN_NO_LOG_PARAMETER).
    type: bool
    default: false
  regenerate:
    description:
      - Allows to configure in which situations the module is allowed to regenerate private keys. The module will always generate
        a new key if the destination file does not exist.
      - By default, the key will be regenerated when it does not match the module's options, except when the key cannot be
        read or the passphrase does not match. Please note that this B(changed) for Ansible 2.10. For Ansible 2.9, the behavior
        was as if V(full_idempotence) is specified.
      - If set to V(never), the module will fail if the key cannot be read or the passphrase is not matching, and will never
        regenerate an existing key.
      - If set to V(fail), the module will fail if the key does not correspond to the module's options.
      - If set to V(partial_idempotence), the key will be regenerated if it does not conform to the module's options. The
        key is B(not) regenerated if it cannot be read (broken file), the key is protected by an unknown passphrase, or when
        they key is not protected by a passphrase, but a passphrase is specified.
      - If set to V(full_idempotence), the key will be regenerated if it does not conform to the module's options. This is
        also the case if the key cannot be read (broken file), the key is protected by an unknown passphrase, or when they
        key is not protected by a passphrase, but a passphrase is specified. Make sure you have a B(backup) when using this
        option!
      - If set to V(always), the module will always regenerate the key.
      - Note that if O(format_mismatch) is set to V(convert) and everything matches except the format, the key will always
        be converted, except if O(regenerate) is set to V(always).
seealso:
  - module: community.crypto.openssl_privatekey
  - module: community.crypto.openssl_privatekey_info
"""

EXAMPLES = r"""
---
- name: Generate an OpenSSL private key with the default values (4096 bits, RSA)
  community.crypto.openssl_privatekey_pipe:
  register: output
  no_log: true # make sure that private key data is not accidentally revealed in logs!
- name: Show generated key
  ansible.builtin.debug:
    msg: "{{ output.privatekey }}"
  # DO NOT OUTPUT KEY MATERIAL TO CONSOLE OR LOGS IN PRODUCTION!


# The following example needs CNCF SOPS (https://github.com/getsops/sops) set up and
# the community.sops collection installed. See also
# https://docs.ansible.com/ansible/latest/collections/community/sops/docsite/guide.html

- name: Generate or update a CNCF SOPS encrypted key
  block:
    - name: Update SOPS-encrypted key with the community.sops collection
      community.crypto.openssl_privatekey_pipe:
        content: "{{ lookup('community.sops.sops', 'private_key.pem.sops') }}"
        size: 2048
      register: output
      no_log: true # make sure that private key data is not accidentally revealed in logs!

    - name: Update encrypted key when openssl_privatekey_pipe reported a change
      community.sops.sops_encrypt:
        path: private_key.pem.sops
        content_text: "{{ output.privatekey }}"
      when: output is changed
  always:
    - name: Make sure that output (which contains the private key) is overwritten
      ansible.builtin.set_fact:
        output: ''
"""

RETURN = r"""
size:
  description: Size (in bits) of the TLS/SSL private key.
  returned: changed or success
  type: int
  sample: 4096
type:
  description: Algorithm used to generate the TLS/SSL private key.
  returned: changed or success
  type: str
  sample: RSA
curve:
  description: Elliptic curve used to generate the TLS/SSL private key.
  returned: changed or success, and O(type) is V(ECC)
  type: str
  sample: secp256r1
fingerprint:
  description:
    - The fingerprint of the public key. Fingerprint will be generated for each C(hashlib.algorithms) available.
  returned: changed or success
  type: dict
  sample:
    md5: "84:75:71:72:8d:04:b5:6c:4d:37:6d:66:83:f5:4c:29"
    sha1: "51:cc:7c:68:5d:eb:41:43:88:7e:1a:ae:c7:f8:24:72:ee:71:f6:10"
    sha224: "b1:19:a6:6c:14:ac:33:1d:ed:18:50:d3:06:5c:b2:32:91:f1:f1:52:8c:cb:d5:75:e9:f5:9b:46"
    sha256: "41:ab:c7:cb:d5:5f:30:60:46:99:ac:d4:00:70:cf:a1:76:4f:24:5d:10:24:57:5d:51:6e:09:97:df:2f:de:c7"
    sha384: "85:39:50:4e:de:d9:19:33:40:70:ae:10:ab:59:24:19:51:c3:a2:e4:0b:1c:b1:6e:dd:b3:0c:d9:9e:6a:46:af:da:18:f8:ef:ae:2e:c0:9a:75:2c:9b:b3:0f:3a:5f:3d"
    sha512: "fd:ed:5e:39:48:5f:9f:fe:7f:25:06:3f:79:08:cd:ee:a5:e7:b3:3d:13:82:87:1f:84:e1:f5:c7:28:77:53:94:86:56:38:69:f0:d9:35:22:01:1e:a6:60:...:0f:9b"
privatekey:
  description:
    - The generated private key's content.
    - Please note that if the result is not changed, the current private key will only be returned if the O(return_current_key)
      option is set to V(true).
    - Will be Base64-encoded if the key is in raw format.
  returned: changed, or O(return_current_key) is V(true)
  type: str
"""
