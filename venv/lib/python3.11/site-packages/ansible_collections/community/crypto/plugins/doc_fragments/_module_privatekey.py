# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this doc fragment is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations


class ModuleDocFragment:
    # Standard files documentation fragment
    DOCUMENTATION = r"""
description:
  - One can generate L(RSA,https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29), L(DSA,https://en.wikipedia.org/wiki/Digital_Signature_Algorithm),
    L(ECC,https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) or L(EdDSA,https://en.wikipedia.org/wiki/EdDSA) private
    keys.
  - Keys are generated in PEM format.
attributes:
  diff_mode:
    support: full
  idempotent:
    support: partial
    details:
      - The option O(regenerate=always) generally disables idempotency.
requirements:
  - cryptography >= 3.3
options:
  size:
    description:
      - Size (in bits) of the TLS/SSL key to generate.
    type: int
    default: 4096
  type:
    description:
      - The algorithm used to generate the TLS/SSL private key.
    type: str
    default: RSA
    choices: [DSA, ECC, Ed25519, Ed448, RSA, X25519, X448]
  curve:
    description:
      - Note that not all curves are supported by all versions of C(cryptography).
      - For maximal interoperability, V(secp384r1) or V(secp256r1) should be used.
      - We use the curve names as defined in the L(IANA registry for TLS,https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
      - Please note that all curves except V(secp224r1), V(secp256k1), V(secp256r1), V(secp384r1), and V(secp521r1) are discouraged
        for new private keys.
    type: str
    choices:
      - secp224r1
      - secp256k1
      - secp256r1
      - secp384r1
      - secp521r1
      - secp192r1
      - brainpoolP256r1
      - brainpoolP384r1
      - brainpoolP512r1
      - sect163k1
      - sect163r2
      - sect233k1
      - sect233r1
      - sect283k1
      - sect283r1
      - sect409k1
      - sect409r1
      - sect571k1
      - sect571r1
  passphrase:
    description:
      - The passphrase for the private key.
    type: str
  cipher:
    description:
      - The cipher to encrypt the private key. This is only used when O(passphrase) is provided.
      - Must be V(auto).
    type: str
    default: auto
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
  format:
    description:
      - Determines which format the private key is written in. By default, PKCS1 (traditional OpenSSL format) is used for
        all keys which support it. Please note that not every key can be exported in any format.
      - The value V(auto) selects a format based on the key format. The value V(auto_ignore) does the same, but for existing
        private key files, it will not force a regenerate when its format is not the automatically selected one for generation.
      - Note that if the format for an existing private key mismatches, the key is B(regenerated) by default. To change this
        behavior, use the O(format_mismatch) option.
    type: str
    default: auto_ignore
    choices: [pkcs1, pkcs8, raw, auto, auto_ignore]
  format_mismatch:
    description:
      - Determines behavior of the module if the format of a private key does not match the expected format, but all other
        parameters are as expected.
      - If set to V(regenerate) (default), generates a new private key.
      - If set to V(convert), the key will be converted to the new format instead.
    type: str
    default: regenerate
    choices: [regenerate, convert]
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
      - Note that if O(format_mismatch) is set to V(convert) and everything matches except the format, the key will always
        be converted, except if O(regenerate) is set to V(always).
    type: str
    choices:
      - never
      - fail
      - partial_idempotence
      - full_idempotence
      - always
    default: full_idempotence
seealso:
  - module: community.crypto.x509_certificate
  - module: community.crypto.x509_certificate_pipe
  - module: community.crypto.openssl_csr
  - module: community.crypto.openssl_csr_pipe
  - module: community.crypto.openssl_dhparam
  - module: community.crypto.openssl_pkcs12
  - module: community.crypto.openssl_publickey
"""
