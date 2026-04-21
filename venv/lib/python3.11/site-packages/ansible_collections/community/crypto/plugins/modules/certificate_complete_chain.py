#!/usr/bin/python
# Copyright (c) 2018, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: certificate_complete_chain
author: "Felix Fontein (@felixfontein)"
short_description: Complete certificate chain given a set of untrusted and root certificates
description:
  - This module completes a given chain of certificates in PEM format by finding intermediate certificates from a given set
    of certificates, until it finds a root certificate in another given set of certificates.
  - This can for example be used to find the root certificate for a certificate chain returned by M(community.crypto.acme_certificate).
  - Note that this module does I(not) check for validity of the chains. It only checks that issuer and subject match, and
    that the signature is correct. It ignores validity dates and key usage completely. If you need to verify that a generated
    chain is valid, please use C(openssl verify ...).
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._attributes.idempotent_not_modify_state
  - community.crypto._cryptography_dep.minimum
attributes:
  check_mode:
    support: full
    details:
      - This action does not modify state.
  diff_mode:
    support: N/A
    details:
      - This action does not modify state.
options:
  input_chain:
    description:
      - A concatenated set of certificates in PEM format forming a chain.
      - The module will try to complete this chain.
    type: str
    required: true
  root_certificates:
    description:
      - A list of filenames or directories.
      - A filename is assumed to point to a file containing one or more certificates in PEM format. All certificates in this
        file will be added to the set of root certificates.
      - If a directory name is given, all files in the directory and its subdirectories will be scanned and tried to be parsed
        as concatenated certificates in PEM format.
      - Symbolic links will be followed.
    type: list
    elements: path
    required: true
  intermediate_certificates:
    description:
      - A list of filenames or directories.
      - A filename is assumed to point to a file containing one or more certificates in PEM format. All certificates in this
        file will be added to the set of root certificates.
      - If a directory name is given, all files in the directory and its subdirectories will be scanned and tried to be parsed
        as concatenated certificates in PEM format.
      - Symbolic links will be followed.
    type: list
    elements: path
    default: []
"""


EXAMPLES = r"""
---
# Given a leaf certificate for www.ansible.com and one or more intermediate
# certificates, finds the associated root certificate.
- name: Find root certificate
  community.crypto.certificate_complete_chain:
    input_chain: "{{ lookup('ansible.builtin.file', '/etc/ssl/csr/www.ansible.com-fullchain.pem') }}"
    root_certificates:
      - /etc/ca-certificates/
  register: www_ansible_com
- name: Write root certificate to disk
  ansible.builtin.copy:
    dest: /etc/ssl/csr/www.ansible.com-root.pem
    content: "{{ www_ansible_com.root }}"

# Given a leaf certificate for www.ansible.com, and a list of intermediate
# certificates, finds the associated root certificate.
- name: Find root certificate
  community.crypto.certificate_complete_chain:
    input_chain: "{{ lookup('ansible.builtin.file', '/etc/ssl/csr/www.ansible.com.pem') }}"
    intermediate_certificates:
      - /etc/ssl/csr/www.ansible.com-chain.pem
    root_certificates:
      - /etc/ca-certificates/
  register: www_ansible_com
- name: Write complete chain to disk
  ansible.builtin.copy:
    dest: /etc/ssl/csr/www.ansible.com-completechain.pem
    content: "{{ ''.join(www_ansible_com.complete_chain) }}"
- name: Write root chain (intermediates and root) to disk
  ansible.builtin.copy:
    dest: /etc/ssl/csr/www.ansible.com-rootchain.pem
    content: "{{ ''.join(www_ansible_com.chain) }}"
"""


RETURN = r"""
root:
  description:
    - The root certificate in PEM format.
  returned: success
  type: str
chain:
  description:
    - The chain added to the given input chain. Includes the root certificate.
    - Returned as a list of PEM certificates.
  returned: success
  type: list
  elements: str
complete_chain:
  description:
    - The completed chain, including leaf, all intermediates, and root.
    - Returned as a list of PEM certificates.
  returned: success
  type: list
  elements: str
"""

import os
import typing as t

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto.pem import (
    split_pem_list,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)


try:
    import cryptography
    import cryptography.exceptions
    import cryptography.hazmat.primitives.asymmetric.ec
    import cryptography.hazmat.primitives.asymmetric.padding
    import cryptography.hazmat.primitives.asymmetric.rsa
    import cryptography.hazmat.primitives.asymmetric.utils
    import cryptography.hazmat.primitives.hashes
    import cryptography.hazmat.primitives.serialization
    import cryptography.x509
    import cryptography.x509.oid
except ImportError:
    pass


class Certificate:
    """
    Stores PEM with parsed certificate.
    """

    def __init__(self, pem: str, cert: cryptography.x509.Certificate) -> None:
        if not (pem.endswith("\n") or pem.endswith("\r")):
            pem = pem + "\n"
        self.pem = pem
        self.cert = cert


def is_parent(
    module: AnsibleModule,
    cert: Certificate,
    potential_parent: Certificate,
) -> bool:
    """
    Tests whether the given certificate has been issued by the potential parent certificate.
    """
    # Check issuer
    if cert.cert.issuer != potential_parent.cert.subject:
        return False
    # Check signature
    public_key = potential_parent.cert.public_key()
    try:
        if isinstance(
            public_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
        ):
            if cert.cert.signature_hash_algorithm is None:
                raise AssertionError(  # pragma: no cover
                    "signature_hash_algorithm should be present for RSA certificates"
                )
            public_key.verify(
                cert.cert.signature,
                cert.cert.tbs_certificate_bytes,
                cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
                cert.cert.signature_hash_algorithm,
            )
        elif isinstance(
            public_key,
            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
        ):
            if cert.cert.signature_hash_algorithm is None:
                raise AssertionError(  # pragma: no cover
                    "signature_hash_algorithm should be present for EC certificates"
                )
            public_key.verify(
                cert.cert.signature,
                cert.cert.tbs_certificate_bytes,
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                    cert.cert.signature_hash_algorithm
                ),
            )
        elif isinstance(
            public_key,
            (
                cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey,
                cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey,
            ),
        ):
            public_key.verify(cert.cert.signature, cert.cert.tbs_certificate_bytes)
        else:
            # Unknown public key type
            module.warn(f'Unknown public key type "{public_key}"')
            return False
        return True
    except cryptography.exceptions.InvalidSignature:
        return False
    except cryptography.exceptions.UnsupportedAlgorithm:
        module.warn(f'Unsupported algorithm "{cert.cert.signature_hash_algorithm}"')
        return False
    except Exception as e:
        module.fail_json(msg=f"Unknown error on signature validation: {e}")


def parse_pem_list(
    module: AnsibleModule,
    text: str,
    source: bytes | str | os.PathLike,
    fail_on_error: bool = True,
) -> list[Certificate]:
    """
    Parse concatenated PEM certificates. Return list of ``Certificate`` objects.
    """
    result: list[Certificate] = []
    for cert_pem in split_pem_list(text):
        # Try to load PEM certificate
        try:
            cert = cryptography.x509.load_pem_x509_certificate(to_bytes(cert_pem))
            result.append(Certificate(cert_pem, cert))
        except Exception as e:
            msg = f"Cannot parse certificate #{len(result) + 1} from {to_text(source)!r}: {e}"
            if fail_on_error:
                module.fail_json(msg=msg)
            else:
                module.warn(msg)
    return result


def load_pem_list(
    module: AnsibleModule, path: bytes | str | os.PathLike, fail_on_error: bool = True
) -> list[Certificate]:
    """
    Load concatenated PEM certificates from file. Return list of ``Certificate`` objects.
    """
    try:
        with open(path, "rb") as f:
            return parse_pem_list(
                module,
                f.read().decode("utf-8"),
                source=path,
                fail_on_error=fail_on_error,
            )
    except Exception as e:
        msg = f"Cannot read certificate file {to_text(path)!r}: {e}"
        if fail_on_error:
            module.fail_json(msg=msg)
        else:
            module.warn(msg)
            return []


class CertificateSet:
    """
    Stores a set of certificates. Allows to search for parent (issuer of a certificate).
    """

    def __init__(self, module: AnsibleModule) -> None:
        self.module = module
        self.certificates: set[Certificate] = set()
        self.certificates_by_issuer: dict[cryptography.x509.Name, list[Certificate]] = (
            {}
        )
        self.certificate_by_cert: dict[cryptography.x509.Certificate, Certificate] = {}

    def _load_file(self, path: bytes | str | os.PathLike) -> None:
        certs = load_pem_list(self.module, path, fail_on_error=False)
        for cert in certs:
            self.certificates.add(cert)
            if cert.cert.subject not in self.certificates_by_issuer:
                self.certificates_by_issuer[cert.cert.subject] = []
            self.certificates_by_issuer[cert.cert.subject].append(cert)
            self.certificate_by_cert[cert.cert] = cert

    def load(self, path: str | os.PathLike) -> None:
        """
        Load lists of PEM certificates from a file or a directory.
        """
        b_path = to_bytes(path, errors="surrogate_or_strict")
        if os.path.isdir(b_path):
            for directory, dummy, files in os.walk(b_path, followlinks=True):
                for file in files:
                    self._load_file(os.path.join(directory, file))
        else:
            self._load_file(b_path)

    def find_parent(self, cert: Certificate) -> Certificate | None:
        """
        Search for the parent (issuer) of a certificate. Return ``None`` if none was found.
        """
        potential_parents = self.certificates_by_issuer.get(cert.cert.issuer, [])
        for potential_parent in potential_parents:
            if is_parent(self.module, cert, potential_parent):
                return potential_parent
        return None


def format_cert(cert: Certificate) -> str:
    """
    Return human readable representation of certificate for error messages.
    """
    return str(cert.cert)


def check_cycle(
    module: AnsibleModule,
    occured_certificates: set[cryptography.x509.Certificate],
    next_certificate: Certificate,
) -> None:
    """
    Make sure that next_certificate is not in occured_certificates so far, and add it.
    """
    next_cert = next_certificate.cert
    if next_cert in occured_certificates:
        module.fail_json(msg="Found cycle while building certificate chain")
    occured_certificates.add(next_cert)


def main() -> t.NoReturn:
    module = AnsibleModule(
        argument_spec={
            "input_chain": {"type": "str", "required": True},
            "root_certificates": {"type": "list", "required": True, "elements": "path"},
            "intermediate_certificates": {
                "type": "list",
                "default": [],
                "elements": "path",
            },
        },
        supports_check_mode=True,
    )

    assert_required_cryptography_version(
        module, minimum_cryptography_version=COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION
    )

    # Load chain
    chain = parse_pem_list(module, module.params["input_chain"], source="input chain")
    if len(chain) == 0:
        module.fail_json(msg="Input chain must contain at least one certificate")

    # Check chain
    for i, parent in enumerate(chain):
        if i > 0 and not is_parent(module, chain[i - 1], parent):
            module.fail_json(
                msg=(
                    f"Cannot verify input chain: certificate #{i + 1}: {format_cert(parent)} is not issuer of certificate #{i}: {format_cert(chain[i - 1])}"
                )
            )

    # Load intermediate certificates
    intermediates = CertificateSet(module)
    for path in module.params["intermediate_certificates"]:
        intermediates.load(path)

    # Load root certificates
    roots = CertificateSet(module)
    for path in module.params["root_certificates"]:
        roots.load(path)

    # Try to complete chain
    current: Certificate | None = chain[-1]
    completed = []
    occured_certificates = {cert.cert for cert in chain}
    if current and current.cert in roots.certificate_by_cert:
        # Do not try to complete the chain when it is already ending with a root certificate
        current = None
    while current:
        root = roots.find_parent(current)
        if root:
            check_cycle(module, occured_certificates, root)
            completed.append(root)
            break
        intermediate = intermediates.find_parent(current)
        if intermediate:
            check_cycle(module, occured_certificates, intermediate)
            completed.append(intermediate)
            current = intermediate
        else:
            module.fail_json(
                msg=f"Cannot complete chain. Stuck at certificate {format_cert(current)}"
            )

    # Return results
    complete_chain = chain + completed
    module.exit_json(
        changed=False,
        root=complete_chain[-1].pem,
        chain=[cert.pem for cert in completed],
        complete_chain=[cert.pem for cert in complete_chain],
    )


if __name__ == "__main__":
    main()
