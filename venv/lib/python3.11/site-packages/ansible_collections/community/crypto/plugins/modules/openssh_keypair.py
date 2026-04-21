#!/usr/bin/python
# Copyright (c) 2018, David Kainz <dkainz@mgit.at> <dave.jokain@gmx.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssh_keypair
author: "David Kainz (@lolcube)"
short_description: Generate OpenSSH private and public keys
description:
  - This module allows one to (re)generate OpenSSH private and public keys. It uses ssh-keygen to generate keys. One can generate
    V(rsa), V(dsa), V(rsa1), V(ed25519) or V(ecdsa) private keys.
requirements:
  - ssh-keygen (if O(backend=openssh))
  - cryptography >= 3.3 (if O(backend=cryptography))
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto._attributes
  - community.crypto._attributes.files
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  safe_file_operations:
    support: full
  idempotent:
    support: partial
    details:
      - The module is not idempotent if O(force=true) or O(regenerate=always).
options:
  state:
    description:
      - Whether the private and public keys should exist or not, taking action if the state is different from what is stated.
    type: str
    default: present
    choices: [present, absent]
  size:
    description:
      - 'Specifies the number of bits in the private key to create. For RSA keys, the minimum size is 1024 bits and the default
        is 4096 bits. Generally, 2048 bits is considered sufficient. DSA keys must be exactly 1024 bits as specified by FIPS
        186-2. For ECDSA keys, size determines the key length by selecting from one of three elliptic curve sizes: 256, 384
        or 521 bits. Attempting to use bit lengths other than these three values for ECDSA keys will cause this module to
        fail. Ed25519 keys have a fixed length and the size will be ignored.'
    type: int
  type:
    description:
      - The algorithm used to generate the SSH private key. V(rsa1) is for protocol version 1. V(rsa1) is deprecated and may
        not be supported by every version of ssh-keygen.
    type: str
    default: rsa
    choices: ['rsa', 'dsa', 'rsa1', 'ecdsa', 'ed25519']
  force:
    description:
      - Should the key be regenerated even if it already exists.
    type: bool
    default: false
  path:
    description:
      - Name of the files containing the public and private key. The file containing the public key will have the extension
        C(.pub).
    type: path
    required: true
  comment:
    description:
      - Provides a new comment to the public key.
    type: str
  passphrase:
    description:
      - Passphrase used to decrypt an existing private key or encrypt a newly generated private key.
      - Passphrases are not supported for O(type=rsa1).
      - Can only be used when O(backend=cryptography), or when O(backend=auto) and a required C(cryptography) version is installed.
    type: str
    version_added: 1.7.0
  private_key_format:
    description:
      - Used when O(backend=cryptography) to select a format for the private key at the provided O(path).
      - When set to V(auto) this module will match the key format of the installed OpenSSH version.
      - For OpenSSH < 7.8 private keys will be in PKCS1 format except ed25519 keys which will be in OpenSSH format.
      - For OpenSSH >= 7.8 all private key types will be in the OpenSSH format.
      - Using this option when O(regenerate=partial_idempotence) or O(regenerate=full_idempotence) will cause a new keypair
        to be generated if the private key's format does not match the value of O(private_key_format). This module will not
        however convert existing private keys between formats.
    type: str
    default: auto
    choices:
      - auto
      - pkcs1
      - pkcs8
      - ssh
    version_added: 1.7.0
  backend:
    description:
      - Selects between the V(cryptography) library or the OpenSSH binary V(opensshbin).
      - V(auto) will default to V(opensshbin) unless the OpenSSH binary is not installed or when using O(passphrase).
    type: str
    default: auto
    choices:
      - auto
      - cryptography
      - opensshbin
    version_added: 1.7.0
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
      - If set to V(always), the module will always regenerate the key. This is equivalent to setting O(force) to V(true).
      - Note that adjusting the comment and the permissions can be changed without regeneration. Therefore, even for V(never),
        the task can result in changed.
    type: str
    choices:
      - never
      - fail
      - partial_idempotence
      - full_idempotence
      - always
    default: partial_idempotence
    version_added: '1.0.0'
notes:
  - In case the ssh key is broken or password protected, the module will fail. Set the O(force) option to V(true) if you want
    to regenerate the keypair.
  - In the case a custom O(mode), O(group), O(owner), or other file attribute is provided it will be applied to both key files.
"""

EXAMPLES = r"""
---
- name: Generate an OpenSSH keypair with the default values (4096 bits, rsa)
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_rsa

- name: Generate an OpenSSH keypair with the default values (4096 bits, rsa) and encrypted private key
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_rsa
    passphrase: super_secret_password

- name: Generate an OpenSSH rsa keypair with a different size (2048 bits)
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_rsa
    size: 2048

- name: Force regenerate an OpenSSH keypair if it already exists
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_rsa
    force: true

- name: Regenerate SSH keypair only if format or options mismatch
  community.crypto.openssh_keypair:
    path: /home/devops/.ssh/id_ed25519
    type: ed25519
    regenerate: full_idempotence
    private_key_format: ssh

- name: Generate an OpenSSH keypair with a different algorithm (dsa)
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_dsa
    type: dsa
"""

RETURN = r"""
size:
  description: Size (in bits) of the SSH private key.
  returned: changed or success
  type: int
  sample: 4096
type:
  description: Algorithm used to generate the SSH private key.
  returned: changed or success
  type: str
  sample: rsa
filename:
  description: Path to the generated SSH private key file.
  returned: changed or success
  type: str
  sample: /tmp/id_ssh_rsa
fingerprint:
  description: The fingerprint of the key.
  returned: changed or success
  type: str
  sample: SHA256:r4YCZxihVjedH2OlfjVGI6Y5xAYtdCwk8VxKyzVyYfM
public_key:
  description: The public key of the generated SSH private key.
  returned: changed or success
  type: str
  sample: ssh-rsa AAAAB3Nza(...omitted...)veL4E3Xcw==
comment:
  description: The comment of the generated key.
  returned: changed or success
  type: str
  sample: test@comment
"""

import typing as t

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils._openssh.backends.keypair_backend import (
    select_backend,
)


def main() -> t.NoReturn:
    module = AnsibleModule(
        argument_spec={
            "state": {
                "type": "str",
                "default": "present",
                "choices": ["present", "absent"],
            },
            "size": {"type": "int"},
            "type": {
                "type": "str",
                "default": "rsa",
                "choices": ["rsa", "dsa", "rsa1", "ecdsa", "ed25519"],
            },
            "force": {"type": "bool", "default": False},
            "path": {"type": "path", "required": True},
            "comment": {"type": "str"},
            "regenerate": {
                "type": "str",
                "default": "partial_idempotence",
                "choices": [
                    "never",
                    "fail",
                    "partial_idempotence",
                    "full_idempotence",
                    "always",
                ],
            },
            "passphrase": {"type": "str", "no_log": True},
            "private_key_format": {
                "type": "str",
                "default": "auto",
                "no_log": False,
                "choices": ["auto", "pkcs1", "pkcs8", "ssh"],
            },
            "backend": {
                "type": "str",
                "default": "auto",
                "choices": ["auto", "cryptography", "opensshbin"],
            },
        },
        supports_check_mode=True,
        add_file_common_args=True,
    )

    keypair = select_backend(module=module, backend=module.params["backend"])

    keypair.execute()


if __name__ == "__main__":
    main()
