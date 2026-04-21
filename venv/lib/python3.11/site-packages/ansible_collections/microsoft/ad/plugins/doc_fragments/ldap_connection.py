# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment:

    # associated with plugin_utils._ldap.create_ldap_connection
    DOCUMENTATION = r"""
options:
  auth_protocol:
    description:
    - The authentication protocol to use when connecting to the LDAP host.
    - Defaults to C(certificate) if LDAPS/StartTLS is used and I(certificate)
      has been specified. Otherwise it defaults to C(negotiate).
    - C(simple) is simple authentication where the user and password are sent
      in plaintext. It does not support any encryption so either must be used
      with LDAPS, or StartTLS. If using over a plaintext LDAP connection
      without TLS, C(encrypt=False) must be specified to explicitly opt into no
      encryption.
    - C(certificate) is TLS client certificate authentication. It can only be
      used with LDAPS or StartTLS. See I(certificate) for more
      information on how to specify the client certificate used for
      authentication.
    - C(negotiate) will attempt to negotiate Kerberos authentication with a
      fallback to NTLM. If Kerberos is available the Kerberos credential cache
      can be used if no username or password is specified.
    - C(kerberos) will use Kerberos authentication with no NTLM fallback.
    - C(ntlm) will use NTLM authentication with no Kerberos attempt.
    - C(negotiate), C(kerberos), and C(ntlm) support encryption over LDAP.
    - Kerberos support requires the C(pyspnego[kerberos]) extras to be
      installed.
    - See R(LDAP authentication,ansible_collections.microsoft.ad.docsite.guide_ldap_connection.authentication)
      for more information.
    - This option can be set using a Jinja2 template value.
    choices:
    - simple
    - certificate
    - negotiate
    - kerberos
    - ntlm
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_AUTH_PROTOCOL
  ca_cert:
    description:
    - Can be the path to a CA certificate PEM or DER file, directory of PEM
      certificates, or the CA certificate PEM string that is used for
      certificate validation.
    - If omitted, the default CA store used for validation is dependent on
      the current Python settings.
    - This option can be set using a Jinja2 template value.
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_CA_CERT
  cert_validation:
    description:
    - The certificate validation behaviour when using a TLS connection.
    - This can be set to C(always), C(ignore), C(ignore_hostname).
    - C(always) will perform certificate hostname and CA validation.
    - C(ignore) will ignore any certificate errors.
    - C(ignore_hostname) will validate the CA trust chain but will ignore any
      hostname checks performed by TLS.
    - See R(Certificate validation,ansible_collections.microsoft.ad.docsite.guide_ldap_connection.cert_validation)
      for more information.
    - This option can be set using a Jinja2 template value.
    choices:
    - always
    - ignore
    - ignore_hostname
    default: always
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_CERT_VALIDATION
  certificate:
    description:
    - The certificate or certificate with key bundle that is used for
      certificate authentication.
    - The value can either be a path to a file containing the certificate or
      string of the PEM encoded certificate.
    - If using a path to a certificate file, the file can be a PEM encoded
      certificate, a PEM encoded certificate and key bundle, a DER encoded
      certificate, or a PFX/PKCS12 encoded certificate and key bundle.
    - Use I(certificate_key) if the certificate specified does not contain the
      key.
    - Use I(certificate_password) if the key is encrypted with a password.
    - This option can be set using a Jinja2 template value.
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_CERTIFICATE
  certificate_key:
    description:
    - The certificate key that is used for certificate authentication.
    - The value can either be a path to a file containing the key in the PEM or
      DER encoded form, or it can be the string of a PEM encoded key.
    - Use I(certificate_password) if the key is encrypted with a password.
    - This option can be set using a Jinja2 template value.
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_CERTIFICATE_KEY
  certificate_password:
    description:
    - The password used to decrypt the certificate key specified by
      I(certificate) or I(certificate_key).
    - This option can be set using a Jinja2 template value.
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_CERTIFICATE_PASSWORD
  connection_timeout:
    description:
    - The timeout in seconds to wait until the connection is established before
      failing.
    - This option can be set using a Jinja2 template value.
    default: 5
    type: int
    env:
    - name: MICROSOFT_AD_LDAP_CONNECTION_TIMEOUT
  encrypt:
    description:
    - Whether encryption is required for the connection.
    - Encryption can either be performed using the authentication protocol or
      through TLS.
    - The I(auth_protocol) C(negotiate), C(kerberos), and C(ntlm) all support
      encryption over LDAP whereas C(simple) does not.
    - If using C(auth_protocol=simple) over LDAP without TLS then this must be
      set to C(False). As no encryption is used, all traffic will be in
      plaintext and should be avoided.
    - This option can be set using a Jinja2 template value.
    default: true
    type: bool
    env:
    - name: MICROSOFT_AD_LDAP_ENCRYPT
  password:
    description:
    - The password to authenticate with.
    - If I(auth_protocol) is C(simple) and no password is specified, the
      bind will be performed as an unauthenticated bind.
    - If I(auth_protocol) is C(negotiate), C(kerberos), or C(ntlm) and no
      password is specified, it will attempt to use the local cached credential
      specified by I(username) if available.
    - This option can be set using a Jinja2 template value.
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_PASSWORD
  port:
    description:
    - The LDAP port to use for the connection.
    - Port 389 is used for LDAP and port 686 is used for LDAPS.
    - Defaults to port C(636) if C(tls_mode=ldaps) otherwise C(389).
    - This option can be set using a Jinja2 template value.
    type: int
    env:
    - name: MICROSOFT_AD_LDAP_PORT
  server:
    description:
    - The domain controller/server to connect to.
    - If not specified the server will be derived from the current krb5.conf
      C(default_realm) setting and with an SRV DNS lookup.
    - See R(Server lookup,ansible_collections.microsoft.ad.docsite.guide_ldap_connection.server_lookup)
      for more information.
    - This option can be set using a Jinja2 template value.
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_SERVER
  tls_mode:
    description:
    - The TLS operation to use.
    - If an explicit I(port) is set to C(636) then this defaults to C(ldaps).
    - C(ldaps) will connect over LDAPS (port 636).
    - C(start_tls) will connect over LDAP (port 389) and perform the StartTLS
      operation before the authentication bind.
    - It is recommended to use C(ldaps) over C(start_tls) if TLS is going to be
      used.
    - This option can be set using a Jinja2 template value.
    choices:
    - ldaps
    - start_tls
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_TLS_MODE
  username:
    description:
    - The username to authenticate with.
    - If I(auth_protocol) is C(simple) and no username is specified, anonymous
      authentication is used.
    - If I(auth_protocol) is C(negotiate), C(kerberos), or C(ntlm) and no
      username is specified, it will attempt to use the local cached credential
      if available, for example one retrieved by C(kinit).
    - This option can be set using a Jinja2 template value.
    type: str
    env:
    - name: MICROSOFT_AD_LDAP_USERNAME
notes:
- See R(LDAP connection help,ansible_collections.microsoft.ad.docsite.guide_ldap_connection)
  for more information about LDAP connections.
requirements:
- dnspython - For option server lookup support
- pyspnego >= 0.8.0
- pyspnego[kerberos] - For Kerberos and server lookup support
- sansldap
- dpapi-ng - For LAPS decryption support
"""
