# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""LDAP Helpers.

This contains the code needed to perform LDAP operations for plugins in this
collection. It should only be used by plugins in this collection as the
interface is not final and could be subject to change.
"""

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import socket
import ssl
import typing as t

try:
    import sansldap

    LDAP_IMP_ERR = None
except Exception as e:
    LDAP_IMP_ERR = e

from ._authentication import ClientCertificate, NegotiateCredential, SimpleCredential
from ._certificate import load_client_certificate, load_trust_certificate
from ._lookup import lookup_ldap_server
from .client import Credential, SyncLDAPClient

from ansible.errors import AnsibleError


def create_ldap_connection(
    auth_protocol: t.Optional[str] = None,
    ca_cert: t.Optional[str] = None,
    cert_validation: t.Optional[str] = None,
    certificate: t.Optional[str] = None,
    certificate_key: t.Optional[str] = None,
    certificate_password: t.Optional[str] = None,
    connection_timeout: int = 5,
    encrypt: bool = True,
    password: t.Optional[str] = None,
    port: t.Optional[int] = None,
    server: t.Optional[str] = None,
    tls_mode: t.Optional[str] = None,
    username: t.Optional[str] = None,
    **kwargs: t.Any,  # Catches any other module option not needed here
) -> SyncLDAPClient:
    """Creates the LDAP client.

    Creates the LDAP client using the options specified. The options here
    correspond to the options defined in the ldap_connection doc fragment.

    Args:
        auth_protocol: The authentication protocol to use, can be simple,
            certificate, negotiate, kerberos, or ntlm.
        ca_cert: The CA PEM path to use for certificate verification.
        cert_validation: Controls the certificate verification behavior, can
            be always, ignore, or ignore_hostname.
        certificate: The client certificate PEM file (optionally key) to use for
            certificate authentication.
        certificate_key: The client certificate PEM key to use for certificate
            authentication.
        certificate_password: The password used to decrypt the client
            certificate key if it is encrypted.
        connection_timeout: The timeout in seconds to wait for connecting to a
            host.
        encrypt: The connection should be encrypted, whether through TLS or
            with authentication encryption.
        password: The password to authenticate with.
        port: The LDAP port to use.
        server: The LDAP server to connect to.
        tls_mode: The TLS mode, can be ldaps or start_tls.
        username: The username to authenticate with.

    Returns:
        LDAPClient: The LDAP client.
    """
    if LDAP_IMP_ERR:
        raise ImportError(str(LDAP_IMP_ERR)) from LDAP_IMP_ERR

    if not server:
        server, lookup_port = lookup_ldap_server()
        if not port:
            port = lookup_port

    if port is None:
        port = 636 if tls_mode == "ldaps" else 389

    if tls_mode is None and port == 636:
        tls_mode = "ldaps"

    ssl_context: t.Optional[ssl.SSLContext] = None
    if tls_mode:
        ssl_context = ssl.create_default_context()
        if ca_cert:
            load_trust_certificate(ssl_context, ca_cert)

        if cert_validation == "ignore":
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.VerifyMode.CERT_NONE

        elif cert_validation == "ignore_hostname":
            ssl_context.check_hostname = False

    if not auth_protocol:
        auth_protocol = "certificate" if certificate and ssl_context else "negotiate"

    credential: t.Optional[Credential] = None
    if auth_protocol == "simple":
        if encrypt and not ssl_context:
            raise ValueError("Cannot use simple auth with encryption.")

        credential = SimpleCredential(username, password)

    elif auth_protocol == "certificate":
        if not ssl_context:
            raise ValueError("TLS must be used for certificate authentication")

        if not certificate:
            raise ValueError("A certificate must be specified for certificate authentication")

        load_client_certificate(
            ssl_context,
            certificate,
            key=certificate_key,
            password=certificate_password,
        )

        # If the client establishes the SSL/TLS-protected connection by means of connecting on a protected LDAPS port,
        # then the connection is considered to be immediately authenticated (bound) as the credentials represented
        # by the client certificate. An EXTERNAL bind is not allowed, and the bind will be rejected with an error.
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81
        if tls_mode == "start_tls":
            credential = ClientCertificate()

    else:
        credential = NegotiateCredential(
            username,
            password,
            protocol=auth_protocol,
            encrypt=encrypt,
        )

    protocol = sansldap.LDAPClient()
    tls_sock: t.Optional[ssl.SSLSocket] = None
    try:
        sock = socket.create_connection((server, port), timeout=connection_timeout)
    except OSError as e:
        raise AnsibleError(f"Failed to connect to {server}:{port}: {e}") from e
    sock.settimeout(None)  # Set socket into blocking mode

    if ssl_context and tls_mode == "ldaps":
        tls_sock = sock = ssl_context.wrap_socket(sock, server_hostname=server)

    try:
        if ssl_context and tls_mode == "start_tls":
            SyncLDAPClient.start_tls(protocol, sock)
            tls_sock = sock = ssl_context.wrap_socket(sock, server_hostname=server)

        client = SyncLDAPClient(server, protocol, sock)
    except Exception:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # The socket has already been shutdown for some other reason
            pass
        sock.close()
        raise

    try:
        if credential:
            credential.authenticate(client, tls_sock=tls_sock)

        return client
    except Exception:
        client.close()
        raise
