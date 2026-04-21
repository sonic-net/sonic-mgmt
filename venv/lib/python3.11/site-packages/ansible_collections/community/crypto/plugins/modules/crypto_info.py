#!/usr/bin/python
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: crypto_info
author: "Felix Fontein (@felixfontein)"
short_description: Retrieve cryptographic capabilities
version_added: 2.1.0
description:
  - Retrieve information on cryptographic capabilities.
  - The current version retrieves information on the L(Python cryptography library, https://cryptography.io/) available to
    Ansible modules, and on the OpenSSL binary C(openssl) found in the path.
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._attributes.info_module
  - community.crypto._attributes.idempotent_not_modify_state
options: {}
"""

EXAMPLES = r"""
---
- name: Retrieve information
  community.crypto.crypto_info:
    account_key_src: /etc/pki/cert/private/account.key
  register: crypto_information

- name: Show retrieved information
  ansible.builtin.debug:
    var: crypto_information
"""

RETURN = r"""
python_cryptography_installed:
  description: Whether the L(Python cryptography library, https://cryptography.io/) is installed.
  returned: always
  type: bool
  sample: true

python_cryptography_import_error:
  description: Import error when trying to import the L(Python cryptography library, https://cryptography.io/).
  returned: when RV(python_cryptography_installed=false)
  type: str

python_cryptography_capabilities:
  description: Information on the installed L(Python cryptography library, https://cryptography.io/).
  returned: when RV(python_cryptography_installed=true)
  type: dict
  contains:
    version:
      description: The library version.
      type: str
    curves:
      description:
        - List of all supported elliptic curves.
        - Theoretically this should be non-empty for version 0.5 and higher, depending on the libssl version used.
      type: list
      elements: str
    has_ec:
      description:
        - Whether elliptic curves are supported.
        - Theoretically this should be the case for version 0.5 and higher, depending on the libssl version used.
      type: bool
    has_ec_sign:
      description:
        - Whether signing with elliptic curves is supported.
        - Theoretically this should be the case for version 1.5 and higher, depending on the libssl version used.
      type: bool
    has_ed25519:
      description:
        - Whether Ed25519 keys are supported.
        - Theoretically this should be the case for version 2.6 and higher, depending on the libssl version used.
      type: bool
    has_ed25519_sign:
      description:
        - Whether signing with Ed25519 keys is supported.
        - Theoretically this should be the case for version 2.6 and higher, depending on the libssl version used.
      type: bool
    has_ed448:
      description:
        - Whether Ed448 keys are supported.
        - Theoretically this should be the case for version 2.6 and higher, depending on the libssl version used.
      type: bool
    has_ed448_sign:
      description:
        - Whether signing with Ed448 keys is supported.
        - Theoretically this should be the case for version 2.6 and higher, depending on the libssl version used.
      type: bool
    has_dsa:
      description:
        - Whether DSA keys are supported.
        - Theoretically this should be the case for version 0.5 and higher.
      type: bool
    has_dsa_sign:
      description:
        - Whether signing with DSA keys is supported.
        - Theoretically this should be the case for version 1.5 and higher.
      type: bool
    has_rsa:
      description:
        - Whether RSA keys are supported.
        - Theoretically this should be the case for version 0.5 and higher.
      type: bool
    has_rsa_sign:
      description:
        - Whether signing with RSA keys is supported.
        - Theoretically this should be the case for version 1.4 and higher.
      type: bool
    has_x25519:
      description:
        - Whether X25519 keys are supported.
        - Theoretically this should be the case for version 2.0 and higher, depending on the libssl version used.
      type: bool
    has_x25519_serialization:
      description:
        - Whether serialization of X25519 keys is supported.
        - Theoretically this should be the case for version 2.5 and higher, depending on the libssl version used.
      type: bool
    has_x448:
      description:
        - Whether X448 keys are supported.
        - Theoretically this should be the case for version 2.5 and higher, depending on the libssl version used.
      type: bool

openssl_present:
  description: Whether the OpenSSL binary C(openssl) is installed and can be found in the PATH.
  returned: always
  type: bool
  sample: true

openssl:
  description: Information on the installed OpenSSL binary.
  returned: when RV(openssl_present=true)
  type: dict
  contains:
    path:
      description: Path of the OpenSSL binary.
      type: str
      sample: /usr/bin/openssl
    version:
      description: The OpenSSL version.
      type: str
      sample: 1.1.1m
    version_output:
      description: The complete output of C(openssl version).
      type: str
      sample: 'OpenSSL 1.1.1m  14 Dec 2021\n'
"""

import traceback
import typing as t

from ansible.module_utils.basic import AnsibleModule


CRYPTOGRAPHY_VERSION: str | None
CRYPTOGRAPHY_IMP_ERR: str | None
try:
    import cryptography
    import cryptography.hazmat.primitives.asymmetric
    from cryptography.exceptions import UnsupportedAlgorithm

    try:
        # While UnsupportedAlgorithm got added in cryptography 0.1, InternalError
        # only got added in 0.2, so let's guard the import
        from cryptography.exceptions import InternalError as CryptographyInternalError
    except ImportError:
        CryptographyInternalError = Exception  # type: ignore
except ImportError:
    UnsupportedAlgorithm = Exception  # type: ignore
    CryptographyInternalError = Exception  # type: ignore
    HAS_CRYPTOGRAPHY = False
    CRYPTOGRAPHY_VERSION = None  # pylint: disable=invalid-name
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()  # pylint: disable=invalid-name
else:
    HAS_CRYPTOGRAPHY = True
    CRYPTOGRAPHY_VERSION = cryptography.__version__  # pylint: disable=invalid-name
    CRYPTOGRAPHY_IMP_ERR = None  # pylint: disable=invalid-name


CURVES = (
    ("secp224r1", "SECP224R1"),
    ("secp256k1", "SECP256K1"),
    ("secp256r1", "SECP256R1"),
    ("secp384r1", "SECP384R1"),
    ("secp521r1", "SECP521R1"),
    ("secp192r1", "SECP192R1"),
    ("sect163k1", "SECT163K1"),
    ("sect163r2", "SECT163R2"),
    ("sect233k1", "SECT233K1"),
    ("sect233r1", "SECT233R1"),
    ("sect283k1", "SECT283K1"),
    ("sect283r1", "SECT283R1"),
    ("sect409k1", "SECT409K1"),
    ("sect409r1", "SECT409R1"),
    ("sect571k1", "SECT571K1"),
    ("sect571r1", "SECT571R1"),
    ("brainpoolP256r1", "BrainpoolP256R1"),
    ("brainpoolP384r1", "BrainpoolP384R1"),
    ("brainpoolP512r1", "BrainpoolP512R1"),
)


def add_crypto_information(module: AnsibleModule) -> dict[str, t.Any]:
    result: dict[str, t.Any] = {}
    result["python_cryptography_installed"] = HAS_CRYPTOGRAPHY
    if not HAS_CRYPTOGRAPHY:
        result["python_cryptography_import_error"] = CRYPTOGRAPHY_IMP_ERR
        return result

    # Test for DSA
    has_dsa = False
    has_dsa_sign = False
    try:
        # added in 0.5 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dsa/
        from cryptography.hazmat.primitives.asymmetric import dsa

        has_dsa = True
        try:
            # added later in 1.5
            dsa.DSAPrivateKey.sign  # noqa: B018 # pylint: disable=pointless-statement
            has_dsa_sign = True
        except AttributeError:
            pass
    except ImportError:
        pass

    # Test for RSA
    has_rsa = False
    has_rsa_sign = False
    try:
        # added in 0.5 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        from cryptography.hazmat.primitives.asymmetric import rsa

        has_rsa = True
        try:
            # added later in 1.4
            rsa.RSAPrivateKey.sign  # noqa: B018 # pylint: disable=pointless-statement
            has_rsa_sign = True
        except AttributeError:
            pass
    except ImportError:
        pass

    # Test for Ed25519
    has_ed25519 = False
    has_ed25519_sign = False
    try:
        # added in 2.6 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            ed25519.Ed25519PrivateKey.from_private_bytes(b"")
        except ValueError:
            pass

        has_ed25519 = True
        try:
            # added with the primitive in 2.6
            ed25519.Ed25519PrivateKey.sign  # noqa: B018 # pylint: disable=pointless-statement
            has_ed25519_sign = True
        except AttributeError:
            pass
    except (ImportError, UnsupportedAlgorithm):
        pass

    # Test for Ed448
    has_ed448 = False
    has_ed448_sign = False
    try:
        # added in 2.6 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed448/
        from cryptography.hazmat.primitives.asymmetric import ed448

        try:
            ed448.Ed448PrivateKey.from_private_bytes(b"")
        except ValueError:
            pass

        has_ed448 = True
        try:
            # added with the primitive in 2.6
            ed448.Ed448PrivateKey.sign  # noqa: B018 # pylint: disable=pointless-statement
            has_ed448_sign = True
        except AttributeError:
            pass
    except (ImportError, UnsupportedAlgorithm):
        pass

    # Test for X25519
    has_x25519 = False
    has_x25519_full = False
    try:
        # added in 2.0 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/
        from cryptography.hazmat.primitives.asymmetric import x25519

        try:
            # added later in 2.5
            x25519.X25519PrivateKey.private_bytes  # noqa: B018 # pylint: disable=pointless-statement
            full = True
        except AttributeError:
            full = False

        try:
            if full:
                x25519.X25519PrivateKey.from_private_bytes(b"")
            else:
                # Some versions do not support serialization and deserialization - use generate() instead
                x25519.X25519PrivateKey.generate()
        except ValueError:
            pass

        has_x25519 = True
        has_x25519_full = full
    except (ImportError, UnsupportedAlgorithm):
        pass

    # Test for X448
    has_x448 = False
    try:
        # added in 2.5 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x448/
        from cryptography.hazmat.primitives.asymmetric import x448

        try:
            x448.X448PrivateKey.from_private_bytes(b"")
        except ValueError:
            pass

        has_x448 = True
    except (ImportError, UnsupportedAlgorithm):
        pass

    # Test for ECC
    has_ec = False
    has_ec_sign = False
    curves = []
    try:
        # added in 0.5 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
        from cryptography.hazmat.primitives.asymmetric import ec

        has_ec = True
        try:
            # added later in 1.5
            ec.EllipticCurvePrivateKey.sign  # noqa: B018 # pylint: disable=pointless-statement
            has_ec_sign = True
        except AttributeError:
            pass
    except ImportError:
        pass
    else:
        for curve_name, constructor_name in CURVES:
            ecclass = ec.__dict__.get(constructor_name)
            if ecclass:
                try:
                    ec.generate_private_key(curve=ecclass())
                    curves.append(curve_name)
                except UnsupportedAlgorithm:
                    pass
                except (  # pylint: disable=duplicate-except,bad-except-order
                    CryptographyInternalError
                ):
                    # On Fedora 41, some curves result in InternalError. This is probably because
                    # Fedora's cryptography is linked against the system libssl, which has the
                    # curves removed.
                    pass

    # Compose result
    info = {
        "version": CRYPTOGRAPHY_VERSION,
        "curves": curves,
        "has_ec": has_ec,
        "has_ec_sign": has_ec_sign,
        "has_ed25519": has_ed25519,
        "has_ed25519_sign": has_ed25519_sign,
        "has_ed448": has_ed448,
        "has_ed448_sign": has_ed448_sign,
        "has_dsa": has_dsa,
        "has_dsa_sign": has_dsa_sign,
        "has_rsa": has_rsa,
        "has_rsa_sign": has_rsa_sign,
        "has_x25519": has_x25519,
        "has_x25519_serialization": has_x25519 and has_x25519_full,
        "has_x448": has_x448,
    }
    result["python_cryptography_capabilities"] = info
    return result


def add_openssl_information(module: AnsibleModule) -> dict[str, t.Any]:
    openssl_binary = module.get_bin_path("openssl")
    result: dict[str, t.Any] = {
        "openssl_present": openssl_binary is not None,
    }
    if openssl_binary is None:
        return result

    openssl_result = {
        "path": openssl_binary,
    }
    result["openssl"] = openssl_result

    rc, out, _err = module.run_command([openssl_binary, "version"])
    if rc == 0:
        openssl_result["version_output"] = out
        parts = out.split(None, 2)
        if len(parts) > 1:
            openssl_result["version"] = parts[1]

    return result


INFO_FUNCTIONS = (
    add_crypto_information,
    add_openssl_information,
)


def main() -> t.NoReturn:
    module = AnsibleModule(argument_spec={}, supports_check_mode=True)
    result: dict[str, t.Any] = {}
    for fn in INFO_FUNCTIONS:
        result.update(fn(module))
    module.exit_json(**result)


if __name__ == "__main__":
    main()
