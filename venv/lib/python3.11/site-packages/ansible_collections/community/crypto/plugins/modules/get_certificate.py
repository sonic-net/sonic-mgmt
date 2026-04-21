#!/usr/bin/python
# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: get_certificate
author: "John Westcott IV (@john-westcott-iv)"
short_description: Get a certificate from a host:port
description:
  - Makes a secure connection and returns information about the presented certificate.
  - The module uses the cryptography Python library.
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._attributes.idempotent_not_modify_state
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
options:
  host:
    description:
      - The host to get the cert for (IP is fine).
    type: str
    required: true
  ca_cert:
    description:
      - A PEM file containing one or more root certificates; if present, the cert will be validated against these root certs.
      - Note that this only validates the certificate is signed by the chain; not that the cert is valid for the host presenting
        it.
    type: path
  port:
    description:
      - The port to connect to.
    type: int
    required: true
  server_name:
    description:
      - Server name used for SNI (L(Server Name Indication,https://en.wikipedia.org/wiki/Server_Name_Indication)) when hostname
        is an IP or is different from server name.
    type: str
    version_added: 1.4.0
  proxy_host:
    description:
      - Proxy host used when get a certificate.
    type: str
  proxy_port:
    description:
      - Proxy port used when get a certificate.
    type: int
    default: 8080
  starttls:
    description:
      - Requests a secure connection for protocols which require clients to initiate encryption.
      - Only available for V(mysql) currently.
    type: str
    choices:
      - mysql
    version_added: 1.9.0
  timeout:
    description:
      - The timeout in seconds.
    type: int
    default: 10
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
  ciphers:
    description:
      - SSL/TLS Ciphers to use for the request.
      - When a list is provided, all ciphers are joined in order with V(:).
      - See the L(OpenSSL Cipher List Format,https://www.openssl.org/docs/manmaster/man1/openssl-ciphers.html#CIPHER-LIST-FORMAT)
        for more details.
      - The available ciphers is dependent on the Python and OpenSSL/LibreSSL versions.
    type: list
    elements: str
    version_added: 2.11.0
  asn1_base64:
    description:
      - Whether to encode the ASN.1 values in the RV(extensions) return value with Base64 or not.
      - The documentation claimed for a long time that the values are Base64 encoded, but they never were. For compatibility
        this option is set to V(false).
      - The default value was changed from V(false) to V(true) incommunity.crypto 3.0.0.
    type: bool
    default: true
    version_added: 2.12.0
  tls_ctx_options:
    description:
      - TLS context options (TLS/SSL OP flags) to use for the request.
      - See the L(List of SSL OP Flags,https://wiki.openssl.org/index.php/List_of_SSL_OP_Flags) for more details.
      - The available TLS context options is dependent on the Python and OpenSSL/LibreSSL versions.
    type: list
    elements: raw
    version_added: 2.21.0
  get_certificate_chain:
    description:
      - If set to V(true), will obtain the certificate chain next to the certificate itself.
      - The chain as returned by the server can be found in RV(unverified_chain), and the chain that passed validation in
        RV(verified_chain).
      - B(Note) that this needs B(Python 3.10 or newer). Also note that only Python 3.13 or newer officially supports this.
        The module uses internal APIs of Python 3.10, 3.11, and 3.12 to achieve the same. It can be that future versions of
        Python 3.10, 3.11, or 3.12 break this.
    type: bool
    default: false
    version_added: 2.21.0

notes:
  - When using ca_cert on OS X it has been reported that in some conditions the validate will always succeed.
requirements:
  - "Python >= 3.10 when O(get_certificate_chain=true)"

seealso:
  - plugin: community.crypto.to_serial
    plugin_type: filter
"""

RETURN = r"""
cert:
  description: The certificate retrieved from the port.
  returned: success
  type: str
expired:
  description: Boolean indicating if the cert is expired.
  returned: success
  type: bool
extensions:
  description: Extensions applied to the cert.
  returned: success
  type: list
  elements: dict
  contains:
    critical:
      returned: success
      type: bool
      description: Whether the extension is critical.
    asn1_data:
      returned: success
      type: str
      description:
        - The ASN.1 content of the extension.
        - If O(asn1_base64=true) this will be Base64 encoded, otherwise the raw binary value will be returned.
        - Please note that the raw binary value might not survive JSON serialization to the Ansible controller, and also might
          cause failures when displaying it. See U(https://github.com/ansible/ansible/issues/80258) for more information.
        - B(Note) that depending on the C(cryptography) version used, it is not possible to extract the ASN.1 content of the
          extension, but only to provide the re-encoded content of the extension in case it was parsed by C(cryptography).
          This should usually result in exactly the same value, except if the original extension value was malformed.
    name:
      returned: success
      type: str
      description: The extension's name.
issuer:
  description: Information about the issuer of the cert.
  returned: success
  type: dict
not_after:
  description: Expiration date of the cert.
  returned: success
  type: str
not_before:
  description: Issue date of the cert.
  returned: success
  type: str
serial_number:
  description:
    - The serial number of the cert.
    - This return value is an B(integer). If you need the serial numbers as a colon-separated hex string, such as C(11:22:33),
      you need to convert it to that form with P(community.crypto.to_serial#filter).
  returned: success
  type: int
signature_algorithm:
  description: The algorithm used to sign the cert.
  returned: success
  type: str
subject:
  description: Information about the subject of the cert (C(OU), C(CN), and so on).
  returned: success
  type: dict
version:
  description: The version number of the certificate.
  returned: success
  type: str
verified_chain:
  description:
    - The verified certificate chain retrieved from the port.
    - The first entry is always RV(cert).
    - The last certificate the root certificate the chain is traced to. If O(ca_cert) is provided this certificate is part
      of that store; otherwise it is part of the store used by default by Python.
    - Note that RV(unverified_chain) generally does not contain the root certificate, and might contain other certificates
      that are not part of the validated chain.
  returned: success and O(get_certificate_chain=true)
  type: list
  elements: str
  version_added: 2.21.0
unverified_chain:
  description:
    - The certificate chain retrieved from the port.
    - The first entry is always RV(cert).
  returned: success and O(get_certificate_chain=true)
  type: list
  elements: str
  version_added: 2.21.0
"""

EXAMPLES = r"""
---
- name: Get the cert from an RDP port
  community.crypto.get_certificate:
    host: "1.2.3.4"
    port: 3389
  delegate_to: localhost
  run_once: true
  register: cert

- name: Get a cert from an https port
  community.crypto.get_certificate:
    host: "www.google.com"
    port: 443
  delegate_to: localhost
  run_once: true
  register: cert

- name: How many days until cert expires
  ansible.builtin.debug:
    msg: "cert expires in: {{ expire_days }} days."
  vars:
    expire_days: >-
      {{ (
        (cert.not_after | ansible.builtin.to_datetime('%Y%m%d%H%M%SZ')) -
        (ansible_date_time.iso8601 | ansible.builtin.to_datetime('%Y-%m-%dT%H:%M:%SZ'))
      ).days }}

- name: Allow legacy insecure renegotiation to get a cert from a legacy device
  community.crypto.get_certificate:
    host: "legacy-device.domain.com"
    port: 443
    ciphers:
      - HIGH
    tls_ctx_options:
      - OP_ALL
      - OP_NO_SSLv3
      - OP_CIPHER_SERVER_PREFERENCE
      - OP_ENABLE_MIDDLEBOX_COMPAT
      - OP_NO_COMPRESSION
      - 4 # OP_LEGACY_SERVER_CONNECT
  delegate_to: localhost
  run_once: true
  register: legacy_cert
"""

import atexit
import base64
import ssl
import sys
import typing as t
from os.path import isfile
from socket import create_connection, setdefaulttimeout, socket
from ssl import (
    CERT_NONE,
    CERT_REQUIRED,
    DER_cert_to_PEM_cert,
    create_default_context,
)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
    cryptography_get_extensions_from_cert,
    cryptography_oid_to_name,
    get_not_valid_after,
    get_not_valid_before,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    get_now_datetime,
)


MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    import cryptography
    import cryptography.exceptions
    import cryptography.x509
except ImportError:
    pass


def send_starttls_packet(sock: socket, server_type: t.Literal["mysql"]) -> None:
    if server_type == "mysql":
        ssl_request_packet = (
            b"\x20\x00\x00\x01\x85\xae\x7f\x00"
            + b"\x00\x00\x00\x01\x21\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
        )

        sock.recv(
            8192
        )  # discard initial handshake from server for this naive implementation
        sock.send(ssl_request_packet)


def main() -> t.NoReturn:
    module = AnsibleModule(
        argument_spec={
            "ca_cert": {"type": "path"},
            "host": {"type": "str", "required": True},
            "port": {"type": "int", "required": True},
            "proxy_host": {"type": "str"},
            "proxy_port": {"type": "int", "default": 8080},
            "server_name": {"type": "str"},
            "timeout": {"type": "int", "default": 10},
            "select_crypto_backend": {
                "type": "str",
                "default": "auto",
                "choices": ["auto", "cryptography"],
            },
            "starttls": {"type": "str", "choices": ["mysql"]},
            "ciphers": {"type": "list", "elements": "str"},
            "asn1_base64": {"type": "bool", "default": True},
            "tls_ctx_options": {"type": "list", "elements": "raw"},
            "get_certificate_chain": {"type": "bool", "default": False},
        },
    )

    ca_cert: str | None = module.params.get("ca_cert")
    host: str = module.params.get("host")
    port: int = module.params.get("port")
    proxy_host: str | None = module.params.get("proxy_host")
    proxy_port: int | None = module.params.get("proxy_port")
    timeout: int = module.params.get("timeout")
    server_name: str | None = module.params.get("server_name")
    start_tls_server_type: t.Literal["mysql"] | None = module.params.get("starttls")
    ciphers: list[str] | None = module.params.get("ciphers")
    asn1_base64: bool = module.params["asn1_base64"]
    tls_ctx_options: list[str | bytes | int] | None = module.params["tls_ctx_options"]
    get_certificate_chain: bool = module.params["get_certificate_chain"]

    if get_certificate_chain and sys.version_info < (3, 10):
        module.fail_json(
            msg="get_certificate_chain=true can only be used with Python 3.10 (Python 3.13+ officially supports this). "
            f"The Python version used to run the get_certificate module is {sys.version}"
        )

    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )

    result: dict[str, t.Any] = {
        "changed": False,
    }

    if timeout:
        setdefaulttimeout(timeout)

    if ca_cert and not isfile(ca_cert):
        module.fail_json(msg="ca_cert file does not exist")

    verified_chain = None
    unverified_chain = None

    try:
        if proxy_host:
            connect = f"CONNECT {host}:{port} HTTP/1.0\r\n\r\n"
            sock = socket()
            atexit.register(sock.close)
            sock.connect((proxy_host, proxy_port))
            sock.send(connect.encode())
            sock.recv(8192)
        else:
            sock = create_connection((host, port))
            atexit.register(sock.close)

        if ca_cert:
            ctx = create_default_context(cafile=ca_cert)
            ctx.check_hostname = False
            ctx.verify_mode = CERT_REQUIRED
        else:
            ctx = create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = CERT_NONE

        if start_tls_server_type is not None:
            send_starttls_packet(sock, start_tls_server_type)

        if ciphers is not None:
            ciphers_joined = ":".join(ciphers)
            ctx.set_ciphers(ciphers_joined)

        if tls_ctx_options is not None:
            # Clear default ctx options
            ctx.options = 0  # type: ignore

            # For each item in the tls_ctx_options list
            for tls_ctx_option in tls_ctx_options:
                # If the item is a string_type
                if isinstance(tls_ctx_option, (str, bytes)):
                    # Convert tls_ctx_option to a native string
                    tls_ctx_option_str = to_text(tls_ctx_option)
                    # Get the tls_ctx_option_str attribute from ssl
                    tls_ctx_option_attr = getattr(ssl, tls_ctx_option_str, None)
                    # If tls_ctx_option_attr is an integer
                    if isinstance(tls_ctx_option_attr, int):
                        # Set tls_ctx_option_int to the attribute value
                        tls_ctx_option_int = tls_ctx_option_attr
                    # If tls_ctx_option_attr is not an integer
                    else:
                        module.fail_json(
                            msg=f"Failed to determine the numeric value for {tls_ctx_option_str}"
                        )
                # If the item is an integer
                elif isinstance(tls_ctx_option, int):
                    # Set tls_ctx_option_int to the item value
                    tls_ctx_option_int = tls_ctx_option
                # If the item is not a string nor integer
                else:
                    module.fail_json(
                        msg=f"tls_ctx_options must be a string or integer, got {tls_ctx_option!r}"
                    )
                    tls_ctx_option_int = (  # type: ignore[unreachable]
                        0  # make pylint happy; this code is actually unreachable
                    )

                try:
                    # Add the int value of the item to ctx options
                    # (pylint does not yet notice that module.fail_json cannot return)
                    ctx.options |= tls_ctx_option_int  # pylint: disable=possibly-used-before-assignment
                except Exception:
                    module.fail_json(
                        msg=f"Failed to add {tls_ctx_option_str or tls_ctx_option_int} to CTX options"
                    )

        tls_sock = ctx.wrap_socket(sock, server_hostname=server_name or host)
        cert_der = tls_sock.getpeercert(True)
        if cert_der is None:
            raise Exception("Unexpected error: no peer certificate has been returned")
        cert: str = DER_cert_to_PEM_cert(cert_der)

        if get_certificate_chain:
            if sys.version_info < (3, 13):
                # The official way to access this has been added in https://github.com/python/cpython/pull/109113/files.
                # We are basically doing the same for older Python versions. The internal API needed for this was added
                # in https://github.com/python/cpython/commit/666991fc598bc312d72aff0078ecb553f0a968f1, which was first
                # released in Python 3.10.0.
                def _convert_chain(chain):
                    if not chain:
                        return []
                    return [
                        c.public_bytes(
                            ssl._ssl.ENCODING_DER  # pylint: disable=protected-access
                        )
                        for c in chain
                    ]

                ssl_obj = (
                    tls_sock._sslobj  # pylint: disable=protected-access
                )  # This is of type ssl._ssl._SSLSocket
                verified_der_chain = _convert_chain(ssl_obj.get_verified_chain())
                unverified_der_chain = _convert_chain(ssl_obj.get_unverified_chain())
            else:
                # This works with Python 3.13+

                # Unfortunately due to a bug (https://github.com/python/cpython/issues/118658) some early pre-releases of
                # Python 3.13 do not return lists of byte strings, but lists of _ssl.Certificate objects. This is going to
                # be fixed by https://github.com/python/cpython/pull/118669. For now we convert the certificates ourselves
                # if they are not byte strings to work around this.
                def _convert_chain(chain: list[bytes]) -> list[bytes]:
                    return [
                        (
                            c
                            if isinstance(c, bytes)
                            else c.public_bytes(
                                ssl._ssl.ENCODING_DER  # pylint: disable=protected-access
                            )
                        )
                        for c in chain
                    ]

                verified_der_chain = _convert_chain(tls_sock.get_verified_chain())
                unverified_der_chain = _convert_chain(tls_sock.get_unverified_chain())

            verified_chain = [DER_cert_to_PEM_cert(c) for c in verified_der_chain]
            unverified_chain = [DER_cert_to_PEM_cert(c) for c in unverified_der_chain]

    except Exception as e:
        if proxy_host:
            module.fail_json(
                msg=f"Failed to get cert via proxy {proxy_host}:{proxy_port} from {host}:{port}, error: {e}"
            )
        else:
            module.fail_json(msg=f"Failed to get cert from {host}:{port}, error: {e}")

    result["cert"] = cert

    x509 = cryptography.x509.load_pem_x509_certificate(to_bytes(cert))
    result["subject"] = {}
    for attribute in x509.subject:
        result["subject"][cryptography_oid_to_name(attribute.oid, short=True)] = (
            attribute.value
        )

    result["expired"] = get_not_valid_after(x509) < get_now_datetime(
        with_timezone=CRYPTOGRAPHY_TIMEZONE
    )

    result["extensions"] = []
    for dotted_number, entry in cryptography_get_extensions_from_cert(x509).items():
        oid = cryptography.x509.oid.ObjectIdentifier(dotted_number)
        ext: dict[str, t.Any] = {
            "critical": entry["critical"],
            "asn1_data": entry["value"],
            "name": cryptography_oid_to_name(oid, short=True),
        }
        if not asn1_base64:
            ext["asn1_data"] = base64.b64decode(entry["value"])  # type: ignore
        result["extensions"].append(ext)

    result["issuer"] = {}
    for attribute in x509.issuer:
        result["issuer"][cryptography_oid_to_name(attribute.oid, short=True)] = (
            attribute.value
        )

    result["not_after"] = get_not_valid_after(x509).strftime("%Y%m%d%H%M%SZ")
    result["not_before"] = get_not_valid_before(x509).strftime("%Y%m%d%H%M%SZ")

    result["serial_number"] = x509.serial_number
    result["signature_algorithm"] = cryptography_oid_to_name(
        x509.signature_algorithm_oid
    )

    # We need the -1 offset to get the same values as pyOpenSSL
    if x509.version == cryptography.x509.Version.v1:
        result["version"] = 1 - 1
    elif x509.version == cryptography.x509.Version.v3:
        result["version"] = 3 - 1
    else:
        result["version"] = "unknown"  # type: ignore[unreachable]

    if verified_chain is not None:
        result["verified_chain"] = verified_chain
    if unverified_chain is not None:
        result["unverified_chain"] = unverified_chain

    module.exit_json(**result)


if __name__ == "__main__":
    main()
