# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: openssl_publickey_info
short_description: Retrieve information from OpenSSL public keys in PEM format
version_added: 2.10.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Provided a public key in OpenSSL PEM format, retrieve information.
  - This is a filter version of the M(community.crypto.openssl_publickey_info) module.
options:
  _input:
    description:
      - The content of the OpenSSL PEM public key.
    type: string
    required: true
seealso:
  - module: community.crypto.openssl_publickey_info
"""

EXAMPLES = r"""
---
- name: Show the type of a public key
  ansible.builtin.debug:
    msg: >-
      {{
        (
          lookup('ansible.builtin.file', '/path/to/public-key.pem')
          | community.crypto.openssl_publickey_info
        ).type
      }}
"""

RETURN = r"""
_value:
  description:
    - Information on the public key.
  type: dict
  contains:
    fingerprints:
      description:
        - Fingerprints of public key.
        - For every hash algorithm available, the fingerprint is computed.
      returned: success
      type: dict
      sample: "{'sha256': 'd4:b3:aa:6d:c8:04:ce:4e:ba:f6:29:4d:92:a3:94:b0:c2:ff:bd:bf:33:63:11:43:34:0f:51:b0:95:09:2f:63',
        'sha512': 'f7:07:4a:f0:b0:f0:e6:8b:95:5f:f9:e6:61:0a:32:68:f1..."
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
          returned: When RV(_value.type=RSA) or RV(_value.type=DSA)
        modulus:
          description:
            - The RSA key's modulus.
          type: int
          returned: When RV(_value.type=RSA)
        exponent:
          description:
            - The RSA key's public exponent.
          type: int
          returned: When RV(_value.type=RSA)
        p:
          description:
            - The C(p) value for DSA.
            - This is the prime modulus upon which arithmetic takes place.
          type: int
          returned: When RV(_value.type=DSA)
        q:
          description:
            - The C(q) value for DSA.
            - This is a prime that divides C(p - 1), and at the same time the order of the subgroup of the multiplicative
              group of the prime field used.
          type: int
          returned: When RV(_value.type=DSA)
        g:
          description:
            - The C(g) value for DSA.
            - This is the element spanning the subgroup of the multiplicative group of the prime field used.
          type: int
          returned: When RV(_value.type=DSA)
        curve:
          description:
            - The curve's name for ECC.
          type: str
          returned: When RV(_value.type=ECC)
        exponent_size:
          description:
            - The maximum number of bits of a private key. This is basically the bit size of the subgroup used.
          type: int
          returned: When RV(_value.type=ECC)
        x:
          description:
            - The C(x) coordinate for the public point on the elliptic curve.
          type: int
          returned: When RV(_value.type=ECC)
        y:
          description:
            - For RV(_value.type=ECC), this is the C(y) coordinate for the public point on the elliptic curve.
            - For RV(_value.type=DSA), this is the publicly known group element whose discrete logarithm with respect to C(g)
              is the private key.
          type: int
          returned: When RV(_value.type=DSA) or RV(_value.type=ECC)
"""

import typing as t
from collections.abc import Callable

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.publickey_info import (
    PublicKeyParseError,
    get_publickey_info,
)
from ansible_collections.community.crypto.plugins.plugin_utils._filter_module import (
    FilterModuleMock,
)


def openssl_publickey_info_filter(data: str | bytes) -> dict[str, t.Any]:
    """Extract information from OpenSSL PEM public key."""
    if not isinstance(data, (str, bytes)):
        raise AnsibleFilterError(
            f"The community.crypto.openssl_publickey_info input must be a text type, not {type(data)}"
        )

    module = FilterModuleMock({})
    try:
        return get_publickey_info(module=module, content=to_bytes(data))
    except PublicKeyParseError as exc:
        raise AnsibleFilterError(exc.error_message) from exc
    except OpenSSLObjectError as exc:
        raise AnsibleFilterError(str(exc)) from exc


class FilterModule:
    """Ansible jinja2 filters"""

    def filters(self) -> dict[str, Callable]:
        return {
            "openssl_publickey_info": openssl_publickey_info_filter,
        }
