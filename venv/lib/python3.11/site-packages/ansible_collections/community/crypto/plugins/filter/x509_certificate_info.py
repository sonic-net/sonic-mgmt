# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: x509_certificate_info
short_description: Retrieve information from X.509 certificates in PEM format
version_added: 2.10.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Provided a X.509 certificate in PEM format, retrieve information.
  - This is a filter version of the M(community.crypto.x509_certificate_info) module.
options:
  _input:
    description:
      - The content of the X.509 certificate in PEM format.
    type: string
    required: true
extends_documentation_fragment:
  - community.crypto._name_encoding
seealso:
  - module: community.crypto.x509_certificate_info
  - plugin: community.crypto.to_serial
    plugin_type: filter
"""

EXAMPLES = r"""
---
- name: Show the Subject Alt Names of the certificate
  ansible.builtin.debug:
    msg: >-
      {{
        (
          lookup('ansible.builtin.file', '/path/to/cert.pem')
          | community.crypto.x509_certificate_info
        ).subject_alt_name | join(', ')
      }}
"""

RETURN = r"""
_value:
  description:
    - Information on the certificate.
  type: dict
  contains:
    expired:
      description: Whether the certificate is expired (in other words, C(notAfter) is in the past).
      returned: success
      type: bool
    basic_constraints:
      description: Entries in the C(basic_constraints) extension, or V(none) if extension is not present.
      returned: success
      type: list
      elements: str
      sample: ["CA:TRUE", "pathlen:1"]
    basic_constraints_critical:
      description: Whether the C(basic_constraints) extension is critical.
      returned: success
      type: bool
    extended_key_usage:
      description: Entries in the C(extended_key_usage) extension, or V(none) if extension is not present.
      returned: success
      type: list
      elements: str
      sample: [Biometric Info, DVCS, Time Stamping]
    extended_key_usage_critical:
      description: Whether the C(extended_key_usage) extension is critical.
      returned: success
      type: bool
    extensions_by_oid:
      description: Returns a dictionary for every extension OID.
      returned: success
      type: dict
      contains:
        critical:
          description: Whether the extension is critical.
          returned: success
          type: bool
        value:
          description:
            - The Base64 encoded value (in DER format) of the extension.
            - B(Note) that depending on the C(cryptography) version used, it is not possible to extract the ASN.1 content
              of the extension, but only to provide the re-encoded content of the extension in case it was parsed by C(cryptography).
              This should usually result in exactly the same value, except if the original extension value was malformed.
          returned: success
          type: str
          sample: "MAMCAQU="
      sample: {"1.3.6.1.5.5.7.1.24": {"critical": false, "value": "MAMCAQU="}}
    key_usage:
      description: Entries in the C(key_usage) extension, or V(none) if extension is not present.
      returned: success
      type: str
      sample: [Key Agreement, Data Encipherment]
    key_usage_critical:
      description: Whether the C(key_usage) extension is critical.
      returned: success
      type: bool
    subject_alt_name:
      description:
        - Entries in the C(subject_alt_name) extension, or V(none) if extension is not present.
        - See O(name_encoding) for how IDNs are handled.
      returned: success
      type: list
      elements: str
      sample: ["DNS:www.ansible.com", "IP:1.2.3.4"]
    subject_alt_name_critical:
      description: Whether the C(subject_alt_name) extension is critical.
      returned: success
      type: bool
    ocsp_must_staple:
      description: V(true) if the OCSP Must Staple extension is present, V(none) otherwise.
      returned: success
      type: bool
    ocsp_must_staple_critical:
      description: Whether the C(ocsp_must_staple) extension is critical.
      returned: success
      type: bool
    issuer:
      description:
        - The certificate's issuer.
        - Note that for repeated values, only the last one will be returned.
      returned: success
      type: dict
      sample: {"organizationName": "Ansible", "commonName": "ca.example.com"}
    issuer_ordered:
      description: The certificate's issuer as an ordered list of tuples.
      returned: success
      type: list
      elements: list
      sample: [["organizationName", "Ansible"], ["commonName": "ca.example.com"]]
    subject:
      description:
        - The certificate's subject as a dictionary.
        - Note that for repeated values, only the last one will be returned.
      returned: success
      type: dict
      sample: {"commonName": "www.example.com", "emailAddress": "test@example.com"}
    subject_ordered:
      description: The certificate's subject as an ordered list of tuples.
      returned: success
      type: list
      elements: list
      sample: [["commonName", "www.example.com"], ["emailAddress": "test@example.com"]]
    not_after:
      description: C(notAfter) date as ASN.1 TIME.
      returned: success
      type: str
      sample: '20190413202428Z'
    not_before:
      description: C(notBefore) date as ASN.1 TIME.
      returned: success
      type: str
      sample: '20190331202428Z'
    public_key:
      description: Certificate's public key in PEM format.
      returned: success
      type: str
      sample: "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A..."
    public_key_type:
      description:
        - The certificate's public key's type.
        - One of V(RSA), V(DSA), V(ECC), V(Ed25519), V(X25519), V(Ed448), or V(X448).
        - Will start with V(unknown) if the key type cannot be determined.
      returned: success
      type: str
      sample: RSA
    public_key_data:
      description:
        - Public key data. Depends on the public key's type.
      returned: success
      type: dict
      contains:
        size:
          description:
            - Bit size of modulus (RSA) or prime number (DSA).
          type: int
          returned: When RV(_value.public_key_type=RSA) or RV(_value.public_key_type=DSA)
        modulus:
          description:
            - The RSA key's modulus.
          type: int
          returned: When RV(_value.public_key_type=RSA)
        exponent:
          description:
            - The RSA key's public exponent.
          type: int
          returned: When RV(_value.public_key_type=RSA)
        p:
          description:
            - The C(p) value for DSA.
            - This is the prime modulus upon which arithmetic takes place.
          type: int
          returned: When RV(_value.public_key_type=DSA)
        q:
          description:
            - The C(q) value for DSA.
            - This is a prime that divides C(p - 1), and at the same time the order of the subgroup of the multiplicative
              group of the prime field used.
          type: int
          returned: When RV(_value.public_key_type=DSA)
        g:
          description:
            - The C(g) value for DSA.
            - This is the element spanning the subgroup of the multiplicative group of the prime field used.
          type: int
          returned: When RV(_value.public_key_type=DSA)
        curve:
          description:
            - The curve's name for ECC.
          type: str
          returned: When RV(_value.public_key_type=ECC)
        exponent_size:
          description:
            - The maximum number of bits of a private key. This is basically the bit size of the subgroup used.
          type: int
          returned: When RV(_value.public_key_type=ECC)
        x:
          description:
            - The C(x) coordinate for the public point on the elliptic curve.
          type: int
          returned: When RV(_value.public_key_type=ECC)
        y:
          description:
            - For RV(_value.public_key_type=ECC), this is the C(y) coordinate for the public point on the elliptic curve.
            - For RV(_value.public_key_type=DSA), this is the publicly known group element whose discrete logarithm with respect
              to C(g) is the private key.
          type: int
          returned: When RV(_value.public_key_type=DSA) or RV(_value.public_key_type=ECC)
    public_key_fingerprints:
      description:
        - Fingerprints of certificate's public key.
        - For every hash algorithm available, the fingerprint is computed.
      returned: success
      type: dict
      sample: "{'sha256': 'd4:b3:aa:6d:c8:04:ce:4e:ba:f6:29:4d:92:a3:94:b0:c2:ff:bd:bf:33:63:11:43:34:0f:51:b0:95:09:2f:63',
        'sha512': 'f7:07:4a:f0:b0:f0:e6:8b:95:5f:f9:e6:61:0a:32:68:f1..."
    fingerprints:
      description:
        - Fingerprints of the DER-encoded form of the whole certificate.
        - For every hash algorithm available, the fingerprint is computed.
      returned: success
      type: dict
      sample: "{'sha256': 'd4:b3:aa:6d:c8:04:ce:4e:ba:f6:29:4d:92:a3:94:b0:c2:ff:bd:bf:33:63:11:43:34:0f:51:b0:95:09:2f:63',
        'sha512': 'f7:07:4a:f0:b0:f0:e6:8b:95:5f:f9:e6:61:0a:32:68:f1..."
    signature_algorithm:
      description: The signature algorithm used to sign the certificate.
      returned: success
      type: str
      sample: sha256WithRSAEncryption
    serial_number:
      description:
        - The certificate's serial number.
        - This return value is an B(integer). If you need the serial numbers as a colon-separated hex string, such as C(11:22:33),
          you need to convert it to that form with P(community.crypto.to_serial#filter).
      returned: success
      type: int
      sample: 1234
    version:
      description: The certificate version.
      returned: success
      type: int
      sample: 3
    subject_key_identifier:
      description:
        - The certificate's subject key identifier.
        - The identifier is returned in hexadecimal, with V(:) used to separate bytes.
        - Is V(none) if the C(SubjectKeyIdentifier) extension is not present.
      returned: success
      type: str
      sample: '00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33'
    authority_key_identifier:
      description:
        - The certificate's authority key identifier.
        - The identifier is returned in hexadecimal, with V(:) used to separate bytes.
        - Is V(none) if the C(AuthorityKeyIdentifier) extension is not present.
      returned: success
      type: str
      sample: '00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33'
    authority_cert_issuer:
      description:
        - The certificate's authority cert issuer as a list of general names.
        - Is V(none) if the C(AuthorityKeyIdentifier) extension is not present.
        - See O(name_encoding) for how IDNs are handled.
      returned: success
      type: list
      elements: str
      sample: ["DNS:www.ansible.com", "IP:1.2.3.4"]
    authority_cert_serial_number:
      description:
        - The certificate's authority cert serial number.
        - Is V(none) if the C(AuthorityKeyIdentifier) extension is not present.
        - This return value is an B(integer). If you need the serial numbers as a colon-separated hex string, such as C(11:22:33),
          you need to convert it to that form with P(community.crypto.to_serial#filter).
      returned: success
      type: int
      sample: 12345
    ocsp_uri:
      description: The OCSP responder URI, if included in the certificate. Will be V(none) if no OCSP responder URI is included.
      returned: success
      type: str
    issuer_uri:
      description: The Issuer URI, if included in the certificate. Will be V(none) if no issuer URI is included.
      returned: success
      type: str
"""

import typing as t
from collections.abc import Callable

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate_info import (
    get_certificate_info,
)
from ansible_collections.community.crypto.plugins.plugin_utils._filter_module import (
    FilterModuleMock,
)


def x509_certificate_info_filter(
    data: str | bytes, name_encoding: t.Literal["ignore", "idna", "unicode"] = "ignore"
) -> dict[str, t.Any]:
    """Extract information from X.509 PEM certificate."""
    if not isinstance(data, (str, bytes)):
        raise AnsibleFilterError(
            f"The community.crypto.x509_certificate_info input must be a text type, not {type(data)}"
        )
    if not isinstance(name_encoding, (str, bytes)):
        raise AnsibleFilterError(
            f"The name_encoding option must be of a text type, not {type(name_encoding)}"
        )
    name_encoding = t.cast(
        t.Literal["ignore", "idna", "unicode"], to_text(name_encoding)
    )
    if name_encoding not in ("ignore", "idna", "unicode"):
        raise AnsibleFilterError(
            f'The name_encoding option must be one of the values "ignore", "idna", or "unicode", not "{name_encoding}"'
        )

    module = FilterModuleMock({"name_encoding": name_encoding})
    try:
        return get_certificate_info(module=module, content=to_bytes(data))
    except OpenSSLObjectError as exc:
        raise AnsibleFilterError(str(exc)) from exc


class FilterModule:
    """Ansible jinja2 filters"""

    def filters(self) -> dict[str, Callable]:
        return {
            "x509_certificate_info": x509_certificate_info_filter,
        }
