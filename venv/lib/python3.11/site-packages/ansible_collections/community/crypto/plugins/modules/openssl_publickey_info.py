#!/usr/bin/python
# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_publickey_info
short_description: Provide information for OpenSSL public keys
description:
  - This module allows one to query information on OpenSSL public keys.
  - It uses the cryptography python library to interact with OpenSSL.
version_added: 1.7.0
author:
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._attributes.info_module
  - community.crypto._attributes.idempotent_not_modify_state
  - community.crypto._cryptography_dep.minimum
options:
  path:
    description:
      - Remote absolute path where the public key file is loaded from.
    type: path
  content:
    description:
      - Content of the public key file.
      - Either O(path) or O(content) must be specified, but not both.
    type: str

  select_crypto_backend:
    description:
      - Determines which crypto backend to use.
      - The default choice is V(auto), which tries to use C(cryptography) if available.
      - If set to V(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
      - Note that with community.crypto 3.0.0, all values behave the same.
        This option will be deprecated in a later version.
        We recommend to not set it explicitly.
    type: str
    default: auto
    choices: [auto, cryptography]

seealso:
  - module: community.crypto.openssl_publickey
  - module: community.crypto.openssl_privatekey_info
  - plugin: community.crypto.openssl_publickey_info
    plugin_type: filter
    description: A filter variant of this module.
"""

EXAMPLES = r"""
---
- name: Generate an OpenSSL private key with the default values (4096 bits, RSA)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem

- name: Create public key from private key
  community.crypto.openssl_publickey:
    privatekey_path: /etc/ssl/private/ansible.com.pem
    path: /etc/ssl/ansible.com.pub

- name: Get information on public key
  community.crypto.openssl_publickey_info:
    path: /etc/ssl/ansible.com.pub
  register: result

- name: Dump information
  ansible.builtin.debug:
    var: result
"""

RETURN = r"""
fingerprints:
  description:
    - Fingerprints of public key.
    - For every hash algorithm available, the fingerprint is computed.
  returned: success
  type: dict
  sample: "{'sha256': 'd4:b3:aa:6d:c8:04:ce:4e:ba:f6:29:4d:92:a3:94:b0:c2:ff:bd:bf:33:63:11:43:34:0f:51:b0:95:09:2f:63', 'sha512':
    'f7:07:4a:f0:b0:f0:e6:8b:95:5f:f9:e6:61:0a:32:68:f1..."
type:
  description:
    - The key's type.
    - One of V(RSA), V(DSA), V(ECC), V(Ed25519), V(X25519), V(Ed448), or V(X448).
    - Will start with V(unknown) if the key type cannot be determined.
  returned: success
  type: str
  sample: RSA
public_data:
  description:
    - Public key data. Depends on key type.
  returned: success
  type: dict
  contains:
    size:
      description:
        - Bit size of modulus (RSA) or prime number (DSA).
      type: int
      returned: When RV(type=RSA) or RV(type=DSA)
    modulus:
      description:
        - The RSA key's modulus.
      type: int
      returned: When RV(type=RSA)
    exponent:
      description:
        - The RSA key's public exponent.
      type: int
      returned: When RV(type=RSA)
    p:
      description:
        - The C(p) value for DSA.
        - This is the prime modulus upon which arithmetic takes place.
      type: int
      returned: When RV(type=DSA)
    q:
      description:
        - The C(q) value for DSA.
        - This is a prime that divides C(p - 1), and at the same time the order of the subgroup of the multiplicative group
          of the prime field used.
      type: int
      returned: When RV(type=DSA)
    g:
      description:
        - The C(g) value for DSA.
        - This is the element spanning the subgroup of the multiplicative group of the prime field used.
      type: int
      returned: When RV(type=DSA)
    curve:
      description:
        - The curve's name for ECC.
      type: str
      returned: When RV(type=ECC)
    exponent_size:
      description:
        - The maximum number of bits of a private key. This is basically the bit size of the subgroup used.
      type: int
      returned: When RV(type=ECC)
    x:
      description:
        - The C(x) coordinate for the public point on the elliptic curve.
      type: int
      returned: When RV(type=ECC)
    y:
      description:
        - For RV(type=ECC), this is the C(y) coordinate for the public point on the elliptic curve.
        - For RV(type=DSA), this is the publicly known group element whose discrete logarithm w.r.t. C(g) is the private key.
      type: int
      returned: When RV(type=DSA) or RV(type=ECC)
"""

import typing as t

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.publickey_info import (
    PublicKeyParseError,
    select_backend,
)


def main() -> t.NoReturn:
    module = AnsibleModule(
        argument_spec={
            "path": {"type": "path"},
            "content": {"type": "str", "no_log": True},
            "select_crypto_backend": {
                "type": "str",
                "default": "auto",
                "choices": ["auto", "cryptography"],
            },
        },
        required_one_of=(["path", "content"],),
        mutually_exclusive=(["path", "content"],),
        supports_check_mode=True,
    )

    result = {
        "can_load_key": False,
        "can_parse_key": False,
        "key_is_consistent": None,
    }

    if module.params["content"] is not None:
        data = module.params["content"].encode("utf-8")
    else:
        try:
            with open(module.params["path"], "rb") as f:
                data = f.read()
        except (IOError, OSError) as e:
            module.fail_json(
                msg=f"Error while reading public key file from disk: {e}",
                **result,  # type: ignore
            )

    module_backend = select_backend(module=module, content=data)

    try:
        result.update(module_backend.get_info())
        module.exit_json(**result)
    except PublicKeyParseError as exc:
        result.update(exc.result)
        module.fail_json(msg=exc.error_message, **result)  # type: ignore
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
