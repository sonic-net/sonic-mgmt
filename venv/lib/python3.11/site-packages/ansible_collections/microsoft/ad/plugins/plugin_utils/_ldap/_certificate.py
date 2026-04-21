# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import os.path
import secrets
import ssl
import tempfile
import typing as t

# Cryptography is used for the TLS channel binding data and to convert PKCS8/12
# certs to a PEM file required by OpenSSL.
try:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    HAS_CRYPTOGRAPHY = True
except Exception:
    HAS_CRYPTOGRAPHY = False


class _PrivateKey(t.Protocol):
    def private_bytes(
        self,
        encoding: "serialization.Encoding",
        format: "serialization.PrivateFormat",
        encryption_algorithm: "serialization.KeySerializationEncryption",
    ) -> bytes:
        ...


def get_tls_server_end_point_data(
    certificate: t.Optional[bytes],
) -> t.Optional[bytes]:
    """Get the TLS channel binding data.

    Gets the TLS channel binding data for tls-server-end-point used in
    Negotiate authentication.

    Args:
        tls_sock: The SSLSocket to get the binding data for.

    Returns:
        Optional[bytes]: The tls-server-end-point data used in the channel
        bindings application data value. Can return None if the cryptography
        isn't installed or it failed to get the certificate info.
    """
    if not HAS_CRYPTOGRAPHY or not certificate:
        return None

    cert = x509.load_der_x509_certificate(certificate)
    try:
        hash_algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        hash_algorithm = None

    # If the cert signature algorithm is unknown, md5, or sha1 then use sha256
    # otherwise use the signature algorithm of the cert itself.
    if not hash_algorithm or hash_algorithm.name in ["md5", "sha1"]:
        digest = hashes.Hash(hashes.SHA256())
    else:
        digest = hashes.Hash(hash_algorithm)

    digest.update(certificate)
    return b"tls-server-end-point:" + digest.finalize()


def load_trust_certificate(
    context: ssl.SSLContext,
    certificate: str,
) -> None:
    """Loads a certificate as a trusted CA.

    Loads the supplied certificate info into the SSLContext to trust. The
    certificate can be in the following 3 forms:

        file path: The path to a PEM or DER encoded certificate
        dir path: The path to a directory containing multiple CA PEM files in
            a specific OpenSSL format (see c_rehash in OpenSSL).
        string: A PEM encoded certificate as a string.

    Args:
        context: The SSLContext to load the cert into.
        certificate: The certificate info to trust.
    """
    if os.path.exists(certificate):
        if os.path.isdir(certificate):
            # It is important the caller does not delete the dir because the
            # lookup happens during the handshake and not now.
            context.load_verify_locations(capath=certificate)

        else:
            # cafile only works for PEM encoded certs, whereas cadata can
            # load DER encoded certs.
            with open(certificate, mode="rb") as fd:
                data = fd.read()

            if data.startswith(b"-----BEGIN CERTIFICATE-----"):
                context.load_verify_locations(cafile=certificate)
            else:
                context.load_verify_locations(cadata=data)

    else:
        context.load_verify_locations(cadata=certificate)


def load_client_certificate(
    context: ssl.SSLContext,
    certificate: str,
    key: t.Optional[str] = None,
    password: t.Optional[str] = None,
) -> None:
    """Loads a certificate to use with client authentication.

    Loads the supplied certificate that can be used for client authentication.
    This function is a wrapper around load_cert_chain and offers the ability to
    load a cert/key from a string or load a PFX formatted certificate with an
    optional password.

    The certificate argument can either be a string of the PEM encoded
    certificate and/or key. It can also be the path to a file of a PEM, DEF, or
    PKCS12 (pfx) certificate and/or key. The key argument can be used to
    specify the certificate key if it is not bundled with the certificate
    argument.

    Args:
        context: The SSLContext to load the cert info.
        certificate: The certificate as a string or filepath.
        key: The optional key as a string or filepath.
        password: The password that is used to decrypt the key or pfx file.
    """
    b_password = password.encode("utf-8", errors="surrogateescape") if password else None

    if os.path.isfile(certificate):
        with open(certificate, mode="rb") as fd:
            cert_data = fd.read()

        der_cert = _try_load_der_cert(cert_data)
        if der_cert:
            certificate = der_cert

        else:
            pfx_cert = _try_load_pfx_cert(cert_data, b_password)
            if pfx_cert:
                certificate, key, b_password = pfx_cert

    if key and os.path.isfile(key):
        with open(key, mode="rb") as fd:
            key_data = fd.read()

        der_key = _try_load_der_key(key_data, b_password)
        if der_key:
            key, b_password = der_key

    # Specifying an empty b"" stops OpenSSL from prompting for the password if
    # it was required. Instead it will just fail to load.
    b_password = b_password or b""

    # load_cert_chain does not expose a way to load a certificate/key from
    # memory so a temporary directory is used in the cases where a pfx or
    # string supplied cert is used.
    if certificate.startswith("-----") or (key and key.startswith("-----")):
        with tempfile.TemporaryDirectory() as tmpdir:
            if certificate.startswith("-----"):
                cert_path = os.path.join(tmpdir, "cert.pem")
                with open(cert_path, mode="w") as fd:
                    fd.write(certificate)

                certificate = cert_path

            if key and key.startswith("-----"):
                key_path = os.path.join(tmpdir, "key.pem")
                with open(key_path, mode="w") as fd:
                    fd.write(key)

                key = key_path

            context.load_cert_chain(certfile=certificate, keyfile=key, password=b_password)

        return

    context.load_cert_chain(certfile=certificate, keyfile=key, password=b_password)


def _try_load_der_cert(
    data: bytes,
) -> t.Optional[str]:
    if not HAS_CRYPTOGRAPHY:
        return None

    try:
        cert = x509.load_der_x509_certificate(data)
    except ValueError:
        return None
    else:
        return cert.public_bytes(encoding=serialization.Encoding.PEM).decode()


def _try_load_der_key(
    data: bytes,
    password: t.Optional[bytes],
) -> t.Optional[t.Tuple[str, bytes]]:
    if not HAS_CRYPTOGRAPHY:
        return None

    try:
        key = serialization.load_der_private_key(data, password=password)
    except ValueError:
        return None
    else:
        return _serialize_key_with_password(key, password)


def _try_load_pfx_cert(
    data: bytes,
    password: t.Optional[bytes],
) -> t.Optional[t.Tuple[str, str, bytes]]:
    if not HAS_CRYPTOGRAPHY:
        return None

    try:
        pfx = pkcs12.load_key_and_certificates(data, password)
    except ValueError:
        pfx = None

    if not pfx or not pfx[0] or not pfx[1]:
        return None

    password = password or secrets.token_bytes(32)

    certificate = pfx[1].public_bytes(encoding=serialization.Encoding.PEM).decode()
    key, password = _serialize_key_with_password(pfx[0], password)

    return certificate, key, password


def _serialize_key_with_password(
    key: _PrivateKey,
    password: t.Optional[bytes],
) -> t.Tuple[str, bytes]:
    password = password or secrets.token_bytes(32)

    return (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        ).decode(),
        password,
    )
