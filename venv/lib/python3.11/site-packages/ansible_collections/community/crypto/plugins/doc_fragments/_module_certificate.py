# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this doc fragment is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations


class ModuleDocFragment:
    # Standard files documentation fragment
    DOCUMENTATION = r"""
description:
  - This module allows one to (re)generate OpenSSL certificates.
  - It uses the cryptography python library to interact with OpenSSL.
attributes:
  diff_mode:
    support: full
  idempotent:
    support: partial
    details:
      - If relative timestamps are used and O(ignore_timestamps=false), the module is not idempotent.
      - The option O(force=true) generally disables idempotency.
requirements:
  - cryptography >= 3.3 (if using V(selfsigned) or V(ownca) provider)
options:
  force:
    description:
      - Generate the certificate, even if it already exists.
    type: bool
    default: false

  csr_path:
    description:
      - Path to the Certificate Signing Request (CSR) used to generate this certificate.
      - This is mutually exclusive with O(csr_content).
    type: path
  csr_content:
    description:
      - Content of the Certificate Signing Request (CSR) used to generate this certificate.
      - This is mutually exclusive with O(csr_path).
    type: str

  privatekey_path:
    description:
      - Path to the private key to use when signing the certificate.
      - This is mutually exclusive with O(privatekey_content).
    type: path
  privatekey_content:
    description:
      - Content of the private key to use when signing the certificate.
      - This is mutually exclusive with O(privatekey_path).
    type: str

  privatekey_passphrase:
    description:
      - The passphrase for the O(privatekey_path) resp. O(privatekey_content).
      - This is required if the private key is password protected.
    type: str

  ignore_timestamps:
    description:
      - Whether the "not before" and "not after" timestamps should be ignored for idempotency checks.
      - It is better to keep the default value V(true) when using relative timestamps (like V(+0s) for now).
    type: bool
    default: true
    version_added: 2.0.0

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

notes:
  - All ASN.1 TIME values should be specified following the YYYYMMDDHHMMSSZ pattern.
  - Date specified should be UTC. Minutes and seconds are mandatory.
  - For security reason, when you use V(ownca) provider, you should NOT run M(community.crypto.x509_certificate) on a target
    machine, but on a dedicated CA machine. It is recommended not to store the CA private key on the target machine. Once
    signed, the certificate can be moved to the target machine.
seealso:
  - module: community.crypto.openssl_csr
  - module: community.crypto.openssl_csr_pipe
  - module: community.crypto.openssl_dhparam
  - module: community.crypto.openssl_pkcs12
  - module: community.crypto.openssl_privatekey
  - module: community.crypto.openssl_privatekey_pipe
  - module: community.crypto.openssl_publickey
"""

    BACKEND_ACME_DOCUMENTATION = r"""
description:
  - This module allows one to (re)generate OpenSSL certificates.
requirements:
  - acme-tiny >= 4.0.0 (if using the V(acme) provider)
options:
  acme_accountkey_path:
    description:
      - The path to the accountkey for the V(acme) provider.
      - This is only used by the V(acme) provider.
    type: path

  acme_challenge_path:
    description:
      - The path to the ACME challenge directory that is served on U(http://<HOST>:80/.well-known/acme-challenge/)
      - This is only used by the V(acme) provider.
    type: path

  acme_chain:
    description:
      - Include the intermediate certificate to the generated certificate
      - This is only used by the V(acme) provider.
      - Note that this is only available for older versions of C(acme-tiny).
        New versions include the chain automatically, and setting O(acme_chain) to V(true) results in an error.
    type: bool
    default: false

  acme_directory:
    description:
      - "The ACME directory to use. You can use any directory that supports the ACME protocol, such as Let's Encrypt."
      - "Let's Encrypt recommends using their staging server while developing jobs. U(https://letsencrypt.org/docs/staging-environment/)."
    type: str
    default: https://acme-v02.api.letsencrypt.org/directory
"""

    BACKEND_OWNCA_DOCUMENTATION = r"""
description:
  - The V(ownca) provider is intended for generating an OpenSSL certificate signed with your own
    CA (Certificate Authority) certificate (self-signed certificate).
options:
  ownca_path:
    description:
      - Remote absolute path of the CA (Certificate Authority) certificate.
      - This is only used by the V(ownca) provider.
      - This is mutually exclusive with O(ownca_content).
    type: path
  ownca_content:
    description:
      - Content of the CA (Certificate Authority) certificate.
      - This is only used by the V(ownca) provider.
      - This is mutually exclusive with O(ownca_path).
    type: str

  ownca_privatekey_path:
    description:
      - Path to the CA (Certificate Authority) private key to use when signing the certificate.
      - This is only used by the V(ownca) provider.
      - This is mutually exclusive with O(ownca_privatekey_content).
    type: path
  ownca_privatekey_content:
    description:
      - Content of the CA (Certificate Authority) private key to use when signing the certificate.
      - This is only used by the V(ownca) provider.
      - This is mutually exclusive with O(ownca_privatekey_path).
    type: str

  ownca_privatekey_passphrase:
    description:
      - The passphrase for the O(ownca_privatekey_path) resp. O(ownca_privatekey_content).
      - This is only used by the V(ownca) provider.
    type: str

  ownca_digest:
    description:
      - The digest algorithm to be used for the V(ownca) certificate.
      - This is only used by the V(ownca) provider.
    type: str
    default: sha256

  ownca_version:
    description:
      - The version of the V(ownca) certificate.
      - Nowadays it should almost always be V(3).
      - This is only used by the V(ownca) provider.
    type: int
    default: 3
    choices:
      - 3

  ownca_not_before:
    description:
      - The point in time the certificate is valid from.
      - Time can be specified either as relative time or as absolute timestamp.
      - Time will always be interpreted as UTC.
      - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer
        + C([w | d | h | m | s]) (for example V(+32w1d2h)).
      - If this value is not specified, the certificate will start being valid from now.
      - Note that this value is B(not used to determine whether an existing certificate should be regenerated).
        This can be changed by setting the O(ignore_timestamps) option to V(false). Please note that you should
        avoid relative timestamps when setting O(ignore_timestamps=false).
      - This is only used by the V(ownca) provider.
    type: str
    default: +0s

  ownca_not_after:
    description:
      - The point in time at which the certificate stops being valid.
      - Time can be specified either as relative time or as absolute timestamp.
      - Time will always be interpreted as UTC.
      - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer
        + C([w | d | h | m | s]) (for example V(+32w1d2h)).
      - If this value is not specified, the certificate will stop being valid 10 years from now.
      - Note that this value is B(not used to determine whether an existing certificate should be regenerated).
        This can be changed by setting the O(ignore_timestamps) option to V(false). Please note that you should
        avoid relative timestamps when setting O(ignore_timestamps=false).
      - This is only used by the V(ownca) provider.
      - On macOS 10.15 and onwards, TLS server certificates must have a validity period of 825 days or fewer.
        Please see U(https://support.apple.com/en-us/HT210176) for more details.
    type: str
    default: +3650d

  ownca_create_subject_key_identifier:
    description:
      - Whether to create the Subject Key Identifier (SKI) from the public key.
      - A value of V(create_if_not_provided) (default) only creates a SKI when the CSR does not
        provide one.
      - A value of V(always_create) always creates a SKI. If the CSR provides one, that one is
        ignored.
      - A value of V(never_create) never creates a SKI. If the CSR provides one, that one is used.
      - This is only used by the V(ownca) provider.
    type: str
    choices: [create_if_not_provided, always_create, never_create]
    default: create_if_not_provided

  ownca_create_authority_key_identifier:
    description:
      - Create a Authority Key Identifier from the CA's certificate. If the CSR provided
        a authority key identifier, it is ignored.
      - The Authority Key Identifier is generated from the CA certificate's Subject Key Identifier,
        if available. If it is not available, the CA certificate's public key will be used.
      - This is only used by the V(ownca) provider.
    type: bool
    default: true
"""

    BACKEND_SELFSIGNED_DOCUMENTATION = r"""
notes:
  - For the V(selfsigned) provider, O(csr_path) and O(csr_content) are optional. If not provided, a
    certificate without any information (Subject, Subject Alternative Names, Key Usage, etc.) is created.

options:
  # NOTE: descriptions in options are overwritten, not appended. For that reason, the texts provided
  #       here for csr_path and csr_content are not visible to the user. That's why this information is
  #       added to the notes (see above).

  # csr_path:
  #   description:
  #     - This is optional for the V(selfsigned) provider. If not provided, a certificate
  #       without any information (Subject, Subject Alternative Names, Key Usage, etc.) is
  #       created.

  # csr_content:
  #   description:
  #     - This is optional for the V(selfsigned) provider. If not provided, a certificate
  #       without any information (Subject, Subject Alternative Names, Key Usage, etc.) is
  #       created.

  selfsigned_version:
    description:
      - Version of the V(selfsigned) certificate.
      - Nowadays it should almost always be V(3).
      - This is only used by the V(selfsigned) provider.
    type: int
    default: 3
    choices:
      - 3

  selfsigned_digest:
    description:
      - Digest algorithm to be used when self-signing the certificate.
      - This is only used by the V(selfsigned) provider.
    type: str
    default: sha256

  selfsigned_not_before:
    description:
      - The point in time the certificate is valid from.
      - Time can be specified either as relative time or as absolute timestamp.
      - Time will always be interpreted as UTC.
      - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer
        + C([w | d | h | m | s]) (for example V(+32w1d2h)).
      - If this value is not specified, the certificate will start being valid from now.
      - Note that this value is B(not used to determine whether an existing certificate should be regenerated).
        This can be changed by setting the O(ignore_timestamps) option to V(false). Please note that you should
        avoid relative timestamps when setting O(ignore_timestamps=false).
      - This is only used by the V(selfsigned) provider.
    type: str
    default: +0s
    aliases:
      - selfsigned_notBefore

  selfsigned_not_after:
    description:
      - The point in time at which the certificate stops being valid.
      - Time can be specified either as relative time or as absolute timestamp.
      - Time will always be interpreted as UTC.
      - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer
        + C([w | d | h | m | s]) (for example V(+32w1d2h)).
      - If this value is not specified, the certificate will stop being valid 10 years from now.
      - Note that this value is B(not used to determine whether an existing certificate should be regenerated).
        This can be changed by setting the O(ignore_timestamps) option to V(false). Please note that you should
        avoid relative timestamps when setting O(ignore_timestamps=false).
      - This is only used by the V(selfsigned) provider.
      - On macOS 10.15 and onwards, TLS server certificates must have a validity period of 825 days or fewer.
        Please see U(https://support.apple.com/en-us/HT210176) for more details.
    type: str
    default: +3650d
    aliases:
      - selfsigned_notAfter

  selfsigned_create_subject_key_identifier:
    description:
      - Whether to create the Subject Key Identifier (SKI) from the public key.
      - A value of V(create_if_not_provided) (default) only creates a SKI when the CSR does not
        provide one.
      - A value of V(always_create) always creates a SKI. If the CSR provides one, that one is
        ignored.
      - A value of V(never_create) never creates a SKI. If the CSR provides one, that one is used.
      - This is only used by the V(selfsigned) provider.
    type: str
    choices: [create_if_not_provided, always_create, never_create]
    default: create_if_not_provided
"""
