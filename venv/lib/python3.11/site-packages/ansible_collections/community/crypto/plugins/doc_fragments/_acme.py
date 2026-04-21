# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this doc fragment is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations


class ModuleDocFragment:
    # Basic documentation fragment without account data
    BASIC = r"""
notes:
  - Although the defaults are chosen so that the module can be used with the L(Let's Encrypt,https://letsencrypt.org/) CA,
    the module can in principle be used with any CA providing an ACME endpoint.
  - So far, the ACME modules have only been tested by the developers against Let's Encrypt (staging and production),
    ZeroSSL (production), and L(Pebble testing server,https://github.com/letsencrypt/Pebble).
    We have got community feedback that they also work with Sectigo ACME Service for InCommon and with HARICA.
    If you experience problems with another ACME server, please
    L(create an issue, https://github.com/ansible-collections/community.crypto/issues/new/choose)
    to help us supporting it. Feedback that an ACME server not mentioned does work is also appreciated.
requirements:
  - either C(openssl)
  - or L(cryptography,https://cryptography.io/) >= 3.3
options:
  acme_version:
    description:
      - The ACME version of the endpoint.
      - Must be V(2) for standardized ACME v2 endpoints.
      - The value V(1) is no longer supported since community.crypto 3.0.0.
    type: int
    default: 2
    choices:
      - 2
  acme_directory:
    description:
      - The ACME directory to use. This is the entry point URL to access the ACME CA server API.
      - For safety reasons the default is set to the Let's Encrypt staging server (for the ACME v1 protocol). This will create
        technically correct, but untrusted certificates.
      - "For Let's Encrypt, all staging endpoints can be found here: U(https://letsencrypt.org/docs/staging-environment/)."
      - For B(Let's Encrypt), the production directory URL for ACME v2 is U(https://acme-v02.api.letsencrypt.org/directory).
      - For B(ZeroSSL), the production directory URL for ACME v2 is U(https://acme.zerossl.com/v2/DV90).
      - For B(Sectigo), the production directory URL for ACME v2 is U(https://acme-qa.secure.trust-provider.com/v2/DV).
      - For B(HARICA), the production directory URL for ACME v2 is U(https://acme.harica.gr/XXX/directory) with XXX being specific to your account.
      - The notes for this module contain a list of ACME services this module has been tested against.
    required: true
    type: str
  validate_certs:
    description:
      - Whether calls to the ACME directory will validate TLS certificates.
      - B(Warning:) Should B(only ever) be set to V(false) for testing purposes, for example when testing against a local
        Pebble server.
    type: bool
    default: true
  select_crypto_backend:
    description:
      - Determines which crypto backend to use.
      - The default choice is V(auto), which tries to use C(cryptography) if available, and falls back to C(openssl).
      - If set to V(openssl), will try to use the C(openssl) binary.
      - If set to V(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
    type: str
    default: auto
    choices: [auto, cryptography, openssl]
  request_timeout:
    description:
      - The time Ansible should wait for a response from the ACME API.
      - This timeout is applied to all HTTP(S) requests (HEAD, GET, POST).
    type: int
    default: 10
    version_added: 2.3.0
"""

    # Account data documentation fragment
    ACCOUNT = r"""
notes:
  - If a new enough version of the C(cryptography) library is available (see Requirements for details), it will be used instead
    of the C(openssl) binary. This can be explicitly disabled or enabled with the O(select_crypto_backend) option. Note that
    using the C(openssl) binary will be slower and less secure, as private key contents always have to be stored on disk (see
    O(account_key_content)).
options:
  account_key_src:
    description:
      - Path to a file containing the ACME account RSA or Elliptic Curve key.
      - "For Elliptic Curve keys only the following curves are supported: V(secp256r1), V(secp384r1), and V(secp521r1)."
      - 'Private keys can be created with the M(community.crypto.openssl_privatekey) or M(community.crypto.openssl_privatekey_pipe)
        modules. If the requisite (cryptography) is not available, keys can also be created directly with the C(openssl) command
        line tool: RSA keys can be created with C(openssl genrsa ...). Elliptic curve keys can be created with C(openssl ecparam
        -genkey ...). Any other tool creating private keys in PEM format can be used as well.'
      - Mutually exclusive with O(account_key_content).
      - Required if O(account_key_content) is not used.
    type: path
    aliases:
      - account_key
  account_key_content:
    description:
      - Content of the ACME account RSA or Elliptic Curve key.
      - "For Elliptic Curve keys only the following curves are supported: V(secp256r1), V(secp384r1), and V(secp521r1)."
      - Mutually exclusive with O(account_key_src).
      - Required if O(account_key_src) is not used.
      - B(Warning:) the content will be written into a temporary file, which will be deleted by Ansible when the module completes.
        Since this is an important private key — it can be used to change the account key, or to revoke your certificates
        without knowing their private keys —, this might not be acceptable.
      - In case C(cryptography) is used, the content is not written into a temporary file. It can still happen that it is
        written to disk by Ansible in the process of moving the module with its argument to the node where it is executed.
    type: str
  account_key_passphrase:
    description:
      - Phassphrase to use to decode the account key.
      - B(Note:) this is not supported by the C(openssl) backend, only by the C(cryptography) backend.
    type: str
    version_added: 1.6.0
  account_uri:
    description:
      - If specified, assumes that the account URI is as given. If the account key does not match this account, or an account
        with this URI does not exist, the module fails.
    type: str
"""

    # No account data documentation fragment
    NO_ACCOUNT = r"""
notes:
  - "If a new enough version of the C(cryptography) library
     is available (see Requirements for details), it will be used
     instead of the C(openssl) binary. This can be explicitly disabled
     or enabled with the O(select_crypto_backend) option. Note that using
     the C(openssl) binary will be slower."
options: {}
"""

    CERTIFICATE = r"""
options:
  csr:
    description:
      - File containing the CSR for the new certificate.
      - Can be created with M(community.crypto.openssl_csr).
      - The CSR may contain multiple Subject Alternate Names, but each one will lead to an individual challenge that must
        be fulfilled for the CSR to be signed.
      - 'B(Note): the private key used to create the CSR B(must not) be the account key. This is a bad idea from a security
        point of view, and the CA should not accept the CSR. The ACME server should return an error in this case.'
      - Precisely one of O(csr) or O(csr_content) must be specified.
    type: path
  csr_content:
    description:
      - Content of the CSR for the new certificate.
      - Can be created with M(community.crypto.openssl_csr_pipe).
      - The CSR may contain multiple Subject Alternate Names, but each one will lead to an individual challenge that must
        be fulfilled for the CSR to be signed.
      - 'B(Note): the private key used to create the CSR B(must not) be the account key. This is a bad idea from a security
        point of view, and the CA should not accept the CSR. The ACME server should return an error in this case.'
      - Precisely one of O(csr) or O(csr_content) must be specified.
    type: str
"""
