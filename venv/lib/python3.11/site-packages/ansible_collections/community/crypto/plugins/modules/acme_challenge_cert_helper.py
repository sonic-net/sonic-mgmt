#!/usr/bin/python
# Copyright (c) 2018 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: acme_challenge_cert_helper
author: "Felix Fontein (@felixfontein)"
short_description: Prepare certificates required for ACME challenges such as C(tls-alpn-01)
description:
  - Prepares certificates for ACME challenges such as C(tls-alpn-01).
  - The raw data is provided by the M(community.crypto.acme_certificate) module, and needs to be converted to a certificate
    to be used for challenge validation. This module provides a simple way to generate the required certificates.
seealso:
  - name: Automatic Certificate Management Environment (ACME)
    description: The specification of the ACME protocol (RFC 8555).
    link: https://tools.ietf.org/html/rfc8555
  - name: ACME TLS ALPN Challenge Extension
    description: The specification of the C(tls-alpn-01) challenge (RFC 8737).
    link: https://www.rfc-editor.org/rfc/rfc8737.html
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._cryptography_dep.minimum
attributes:
  check_mode:
    support: none
    details:
      - This action does not modify state.
  diff_mode:
    support: N/A
    details:
      - This action does not modify state.
  idempotent:
    support: none
    details:
      - The certificates returned are never the same, since the Not Before and Not After timestamps
        depend on the invocation's timestamp.
options:
  challenge:
    description:
      - The challenge type.
    type: str
    required: true
    choices:
      - tls-alpn-01
  challenge_data:
    description:
      - The RV(community.crypto.acme_certificate#module:challenge_data) entry provided by M(community.crypto.acme_certificate)
        for the challenge.
    type: dict
    required: true
  private_key_src:
    description:
      - Path to a file containing the private key file to use for this challenge certificate.
      - Mutually exclusive with O(private_key_content).
    type: path
  private_key_content:
    description:
      - Content of the private key to use for this challenge certificate.
      - Mutually exclusive with O(private_key_src).
    type: str
  private_key_passphrase:
    description:
      - Phassphrase to use to decode the private key.
    type: str
    version_added: 1.6.0
"""

EXAMPLES = r"""
---
- name: Create challenges for a given CRT for sample.com
  community.crypto.acme_certificate:
    account_key_src: /etc/pki/cert/private/account.key
    challenge: tls-alpn-01
    csr: /etc/pki/cert/csr/sample.com.csr
    dest: /etc/httpd/ssl/sample.com.crt
    modify_account: false
  register: sample_com_challenge

- name: Create certificates for challenges
  community.crypto.acme_challenge_cert_helper:
    challenge: tls-alpn-01
    challenge_data: "{{ item.value['tls-alpn-01'] }}"
    private_key_src: /etc/pki/cert/key/sample.com.key
  loop: "{{ sample_com_challenge.challenge_data | dictsort }}"
  register: sample_com_challenge_certs

- name: Install challenge certificates
  # We need to set up HTTPS such that for the domain,
  # regular_certificate is delivered for regular connections,
  # except if ALPN selects the "acme-tls/1"; then, the
  # challenge_certificate must be delivered.
  # This can for example be achieved with very new versions
  # of NGINX; search for ssl_preread and
  # ssl_preread_alpn_protocols for information on how to
  # route by ALPN protocol.
  ...:
    domain: "{{ item.domain }}"
    challenge_certificate: "{{ item.challenge_certificate }}"
    regular_certificate: "{{ item.regular_certificate }}"
    private_key: /etc/pki/cert/key/sample.com.key
  loop: "{{ sample_com_challenge_certs.results }}"

- name: Create certificate for a given CSR for sample.com
  community.crypto.acme_certificate:
    account_key_src: /etc/pki/cert/private/account.key
    challenge: tls-alpn-01
    csr: /etc/pki/cert/csr/sample.com.csr
    dest: /etc/httpd/ssl/sample.com.crt
    data: "{{ sample_com_challenge }}"
    modify_account: false
"""

RETURN = r"""
domain:
  description:
    - The domain the challenge is for. The certificate should be provided if this is specified in the request's the C(Host)
      header.
  returned: always
  type: str
identifier_type:
  description:
    - The identifier type for the actual resource identifier.
  returned: always
  type: str
  choices:
    - dns
    - ip
identifier:
  description:
    - The identifier for the actual resource. Will be a domain name if RV(identifier_type=dns), or an IP address if RV(identifier_type=ip).
  returned: always
  type: str
challenge_certificate:
  description:
    - The challenge certificate in PEM format.
  returned: always
  type: str
regular_certificate:
  description:
    - A self-signed certificate for the challenge domain.
    - If no existing certificate exists, can be used to set-up https in the first place if that is needed for providing the
      challenge.
  returned: always
  type: str
"""

import base64
import datetime
import ipaddress
import typing as t

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ModuleFailException,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.io import read_file
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
    set_not_valid_after,
    set_not_valid_before,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    get_now_datetime,
)


try:
    import cryptography
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.asymmetric.dh
    import cryptography.hazmat.primitives.asymmetric.ec
    import cryptography.hazmat.primitives.asymmetric.padding
    import cryptography.hazmat.primitives.asymmetric.rsa
    import cryptography.hazmat.primitives.asymmetric.utils
    import cryptography.hazmat.primitives.asymmetric.x448
    import cryptography.hazmat.primitives.asymmetric.x25519
    import cryptography.hazmat.primitives.hashes
    import cryptography.hazmat.primitives.serialization
    import cryptography.x509
    import cryptography.x509.oid
except ImportError:
    pass


# Convert byte string to ASN1 encoded octet string
def encode_octet_string(octet_string: bytes) -> bytes:
    if len(octet_string) >= 128:
        raise ModuleFailException(
            "Cannot handle octet strings with more than 128 bytes"
        )
    return bytes([0x4, len(octet_string)]) + octet_string


def main() -> t.NoReturn:
    module = AnsibleModule(
        argument_spec={
            "challenge": {"type": "str", "required": True, "choices": ["tls-alpn-01"]},
            "challenge_data": {"type": "dict", "required": True},
            "private_key_src": {"type": "path"},
            "private_key_content": {"type": "str", "no_log": True},
            "private_key_passphrase": {"type": "str", "no_log": True},
        },
        required_one_of=(["private_key_src", "private_key_content"],),
        mutually_exclusive=(["private_key_src", "private_key_content"],),
    )

    assert_required_cryptography_version(
        module, minimum_cryptography_version=COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION
    )

    try:
        # Get parameters
        challenge: t.Literal["tls-alpn-01"] = module.params["challenge"]
        challenge_data: dict[str, t.Any] = module.params["challenge_data"]

        # Get hold of private key
        private_key_content_str: str | None = module.params["private_key_content"]
        private_key_passphrase: str | None = module.params["private_key_passphrase"]
        if private_key_content_str is None:
            private_key_content = read_file(module.params["private_key_src"])
        else:
            private_key_content = to_bytes(private_key_content_str)
        try:
            private_key = (
                cryptography.hazmat.primitives.serialization.load_pem_private_key(
                    private_key_content,
                    password=(
                        to_bytes(private_key_passphrase)
                        if private_key_passphrase is not None
                        else None
                    ),
                )
            )
        except Exception as e:
            raise ModuleFailException(f"Error while loading private key: {e}") from e
        if isinstance(
            private_key,
            (
                cryptography.hazmat.primitives.asymmetric.dh.DHPrivateKey,
                cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey,
                cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey,
            ),
        ):
            raise ModuleFailException(
                f"Cannot use private key type {type(private_key)}"
            )

        # Some common attributes
        domain = to_text(challenge_data["resource"])
        identifier_type, identifier = to_text(
            challenge_data.get("resource_original", "dns:" + challenge_data["resource"])
        ).split(":", 1)
        subject = issuer = cryptography.x509.Name([])
        now = get_now_datetime(with_timezone=CRYPTOGRAPHY_TIMEZONE)
        not_valid_before = now
        not_valid_after = now + datetime.timedelta(days=10)
        san: cryptography.x509.GeneralName
        if identifier_type == "dns":
            san = cryptography.x509.DNSName(identifier)
        elif identifier_type == "ip":
            san = cryptography.x509.IPAddress(ipaddress.ip_address(identifier))
        else:
            raise ModuleFailException(
                f'Unsupported identifier type "{identifier_type}"'
            )

        # Generate regular self-signed certificate
        cert_builder = (
            cryptography.x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(cryptography.x509.random_serial_number())
            .add_extension(
                cryptography.x509.SubjectAlternativeName([san]),
                critical=False,
            )
        )
        cert_builder = set_not_valid_before(cert_builder, not_valid_before)
        cert_builder = set_not_valid_after(cert_builder, not_valid_after)
        regular_certificate = cert_builder.sign(
            private_key,
            cryptography.hazmat.primitives.hashes.SHA256(),
        )

        # Process challenge
        if challenge == "tls-alpn-01":
            value = base64.b64decode(challenge_data["resource_value"])
            cert_builder = (
                cryptography.x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(cryptography.x509.random_serial_number())
                .add_extension(
                    cryptography.x509.SubjectAlternativeName([san]),
                    critical=False,
                )
                .add_extension(
                    cryptography.x509.UnrecognizedExtension(
                        cryptography.x509.ObjectIdentifier("1.3.6.1.5.5.7.1.31"),
                        encode_octet_string(value),
                    ),
                    critical=True,
                )
            )
            cert_builder = set_not_valid_before(cert_builder, not_valid_before)
            cert_builder = set_not_valid_after(cert_builder, not_valid_after)
            challenge_certificate = cert_builder.sign(
                private_key,
                cryptography.hazmat.primitives.hashes.SHA256(),
            )
        else:
            raise AssertionError("Can never be reached")  # pragma: no cover

        module.exit_json(
            changed=True,
            domain=domain,
            identifier_type=identifier_type,
            identifier=identifier,
            challenge_certificate=challenge_certificate.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM
            ),
            regular_certificate=regular_certificate.public_bytes(
                cryptography.hazmat.primitives.serialization.Encoding.PEM
            ),
        )
    except ModuleFailException as e:
        e.do_fail(module=module)


if __name__ == "__main__":
    main()
