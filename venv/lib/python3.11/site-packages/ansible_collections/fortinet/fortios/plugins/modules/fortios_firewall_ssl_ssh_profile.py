#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_firewall_ssl_ssh_profile
short_description: Configure SSL/SSH protocol options in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and ssl_ssh_profile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    firewall_ssl_ssh_profile:
        description:
            - Configure SSL/SSH protocol options.
        default: null
        type: dict
        suboptions:
            allowlist:
                description:
                    - Enable/disable exempting servers by FortiGuard allowlist.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            block_blacklisted_certificates:
                description:
                    - Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blacklist.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            block_blocklisted_certificates:
                description:
                    - Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blocklist.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            caname:
                description:
                    - CA certificate used by SSL Inspection. Source vpn.certificate.local.name vpn.certificate.hsm-local.name.
                type: str
            comment:
                description:
                    - Optional comments.
                type: str
            dot:
                description:
                    - Configure DNS over TLS options.
                type: dict
                suboptions:
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    quic:
                        description:
                            - QUIC inspection status .
                        type: str
                        choices:
                            - 'inspect'
                            - 'bypass'
                            - 'block'
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    udp_not_quic:
                        description:
                            - Action to be taken when matched UDP packet is not QUIC.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        description:
                            - Action based on the SSL version used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'inspect'
                    untrusted_server_cert:
                        description:
                            - Action based on server certificate is not issued by a trusted CA.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            ech_outer_sni:
                description:
                    - ClientHelloOuter SNIs to be blocked.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - ClientHelloOuter SNI name.
                        required: true
                        type: str
                    sni:
                        description:
                            - ClientHelloOuter SNI to be blocked.
                        type: str
            ftps:
                description:
                    - Configure FTPS options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    min_allowed_ssl_version:
                        description:
                            - Minimum SSL version to be allowed.
                        type: str
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: list
                        elements: int
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        description:
                            - Action based on the SSL version used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'inspect'
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    untrusted_server_cert:
                        description:
                            - Action based on server certificate is not issued by a trusted CA.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            https:
                description:
                    - Configure HTTPS options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cert_probe_failure:
                        description:
                            - Action based on certificate probe failure.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    encrypted_client_hello:
                        description:
                            - Block/allow session based on existence of encrypted-client-hello.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    min_allowed_ssl_version:
                        description:
                            - Minimum SSL version to be allowed.
                        type: str
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: list
                        elements: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    quic:
                        description:
                            - QUIC inspection status .
                        type: str
                        choices:
                            - 'inspect'
                            - 'bypass'
                            - 'block'
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    udp_not_quic:
                        description:
                            - Action to be taken when matched UDP packet is not QUIC.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        description:
                            - Action based on the SSL version used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'inspect'
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    untrusted_server_cert:
                        description:
                            - Action based on server certificate is not issued by a trusted CA.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            imaps:
                description:
                    - Configure IMAPS options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: list
                        elements: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        description:
                            - Action based on the SSL version used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'inspect'
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    untrusted_server_cert:
                        description:
                            - Action based on server certificate is not issued by a trusted CA.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            mapi_over_https:
                description:
                    - Enable/disable inspection of MAPI over HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Name.
                required: true
                type: str
            pop3s:
                description:
                    - Configure POP3S options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: list
                        elements: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        description:
                            - Action based on the SSL version used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'inspect'
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    untrusted_server_cert:
                        description:
                            - Action based on server certificate is not issued by a trusted CA.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            rpc_over_https:
                description:
                    - Enable/disable inspection of RPC over HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            server_cert:
                description:
                    - Certificate used by SSL Inspection to replace server certificate. Source vpn.certificate.local.name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Certificate list. Source vpn.certificate.local.name.
                        required: true
                        type: str
            server_cert_mode:
                description:
                    - Re-sign or replace the server"s certificate.
                type: str
                choices:
                    - 're-sign'
                    - 'replace'
            smtps:
                description:
                    - Configure SMTPS options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: list
                        elements: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        description:
                            - Action based on the SSL version used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'inspect'
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    untrusted_server_cert:
                        description:
                            - Action based on server certificate is not issued by a trusted CA.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            ssh:
                description:
                    - Configure SSH options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Level of SSL inspection.
                        type: str
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: list
                        elements: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssh_algorithm:
                        description:
                            - Relative strength of encryption algorithms accepted during negotiation.
                        type: str
                        choices:
                            - 'compatible'
                            - 'high-encryption'
                    ssh_policy_check:
                        description:
                            - Enable/disable SSH policy check.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    ssh_tun_policy_check:
                        description:
                            - Enable/disable SSH tunnel policy check.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_version:
                        description:
                            - Action based on SSH version being unsupported.
                        type: str
                        choices:
                            - 'bypass'
                            - 'block'
            ssl:
                description:
                    - Configure SSL options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    cert_probe_failure:
                        description:
                            - Action based on certificate probe failure.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    encrypted_client_hello:
                        description:
                            - Block/allow session based on existence of encrypted-client-hello.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    inspect_all:
                        description:
                            - Level of SSL inspection.
                        type: str
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    min_allowed_ssl_version:
                        description:
                            - Minimum SSL version to be allowed.
                        type: str
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        description:
                            - Action based on the SSL version used being unsupported.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'inspect'
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    untrusted_server_cert:
                        description:
                            - Action based on server certificate is not issued by a trusted CA.
                        type: str
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
            ssl_anomalies_log:
                description:
                    - Enable/disable logging SSL anomalies.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_anomaly_log:
                description:
                    - Enable/disable logging of SSL anomalies.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_exempt:
                description:
                    - Servers to exempt from SSL inspection.
                type: list
                elements: dict
                suboptions:
                    address:
                        description:
                            - IPv4 address object. Source firewall.address.name firewall.addrgrp.name.
                        type: str
                    address6:
                        description:
                            - IPv6 address object. Source firewall.address6.name firewall.addrgrp6.name.
                        type: str
                    fortiguard_category:
                        description:
                            - FortiGuard category ID.
                        type: int
                    id:
                        description:
                            - ID number. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    regex:
                        description:
                            - Exempt servers by regular expression.
                        type: str
                    type:
                        description:
                            - Type of address object (IPv4 or IPv6) or FortiGuard category.
                        type: str
                        choices:
                            - 'fortiguard-category'
                            - 'address'
                            - 'address6'
                            - 'wildcard-fqdn'
                            - 'regex'
                    wildcard_fqdn:
                        description:
                            - Exempt servers by wildcard FQDN. Source firewall.wildcard-fqdn.custom.name firewall.wildcard-fqdn.group.name.
                        type: str
            ssl_exemption_ip_rating:
                description:
                    - Enable/disable IP based URL rating.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_exemption_log:
                description:
                    - Enable/disable logging of SSL exemptions.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_exemptions_log:
                description:
                    - Enable/disable logging SSL exemptions.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_handshake_log:
                description:
                    - Enable/disable logging of TLS handshakes.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_negotiation_log:
                description:
                    - Enable/disable logging of SSL negotiation events.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server:
                description:
                    - SSL server settings used for client certificate request.
                type: list
                elements: dict
                suboptions:
                    ftps_client_cert_request:
                        description:
                            - Action based on client certificate request during the FTPS handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ftps_client_certificate:
                        description:
                            - Action based on received client certificate during the FTPS handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https_client_cert_request:
                        description:
                            - Action based on client certificate request during the HTTPS handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https_client_certificate:
                        description:
                            - Action based on received client certificate during the HTTPS handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    id:
                        description:
                            - SSL server ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    imaps_client_cert_request:
                        description:
                            - Action based on client certificate request during the IMAPS handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    imaps_client_certificate:
                        description:
                            - Action based on received client certificate during the IMAPS handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ip:
                        description:
                            - IPv4 address of the SSL server.
                        type: str
                    pop3s_client_cert_request:
                        description:
                            - Action based on client certificate request during the POP3S handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    pop3s_client_certificate:
                        description:
                            - Action based on received client certificate during the POP3S handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps_client_cert_request:
                        description:
                            - Action based on client certificate request during the SMTPS handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps_client_certificate:
                        description:
                            - Action based on received client certificate during the SMTPS handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl_other_client_cert_request:
                        description:
                            - Action based on client certificate request during an SSL protocol handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl_other_client_certificate:
                        description:
                            - Action based on received client certificate during an SSL protocol handshake.
                        type: str
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
            ssl_server_cert_log:
                description:
                    - Enable/disable logging of server certificate information.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            supported_alpn:
                description:
                    - Configure ALPN option.
                type: str
                choices:
                    - 'http1-1'
                    - 'http2'
                    - 'all'
                    - 'none'
            untrusted_caname:
                description:
                    - Untrusted CA certificate used by SSL Inspection. Source vpn.certificate.local.name vpn.certificate.hsm-local.name.
                type: str
            use_ssl_server:
                description:
                    - Enable/disable the use of SSL server table for SSL offloading.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            whitelist:
                description:
                    - Enable/disable exempting servers by FortiGuard whitelist.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure SSL/SSH protocol options.
  fortinet.fortios.fortios_firewall_ssl_ssh_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_ssl_ssh_profile:
          allowlist: "enable"
          block_blacklisted_certificates: "disable"
          block_blocklisted_certificates: "disable"
          caname: "<your_own_value> (source vpn.certificate.local.name vpn.certificate.hsm-local.name)"
          comment: "Optional comments."
          dot:
              cert_validation_failure: "allow"
              cert_validation_timeout: "allow"
              client_certificate: "bypass"
              expired_server_cert: "allow"
              proxy_after_tcp_handshake: "enable"
              quic: "inspect"
              revoked_server_cert: "allow"
              sni_server_cert_check: "enable"
              status: "disable"
              udp_not_quic: "allow"
              unsupported_ssl_cipher: "allow"
              unsupported_ssl_negotiation: "allow"
              unsupported_ssl_version: "allow"
              untrusted_server_cert: "allow"
          ech_outer_sni:
              -
                  name: "default_name_24"
                  sni: "<your_own_value>"
          ftps:
              allow_invalid_server_cert: "enable"
              cert_validation_failure: "allow"
              cert_validation_timeout: "allow"
              client_cert_request: "bypass"
              client_certificate: "bypass"
              expired_server_cert: "allow"
              invalid_server_cert: "allow"
              min_allowed_ssl_version: "ssl-3.0"
              ports: "<your_own_value>"
              revoked_server_cert: "allow"
              sni_server_cert_check: "enable"
              status: "disable"
              unsupported_ssl: "bypass"
              unsupported_ssl_cipher: "allow"
              unsupported_ssl_negotiation: "allow"
              unsupported_ssl_version: "allow"
              untrusted_cert: "allow"
              untrusted_server_cert: "allow"
          https:
              allow_invalid_server_cert: "enable"
              cert_probe_failure: "allow"
              cert_validation_failure: "allow"
              cert_validation_timeout: "allow"
              client_cert_request: "bypass"
              client_certificate: "bypass"
              encrypted_client_hello: "allow"
              expired_server_cert: "allow"
              invalid_server_cert: "allow"
              min_allowed_ssl_version: "ssl-3.0"
              ports: "<your_own_value>"
              proxy_after_tcp_handshake: "enable"
              quic: "inspect"
              revoked_server_cert: "allow"
              sni_server_cert_check: "enable"
              status: "disable"
              udp_not_quic: "allow"
              unsupported_ssl: "bypass"
              unsupported_ssl_cipher: "allow"
              unsupported_ssl_negotiation: "allow"
              unsupported_ssl_version: "allow"
              untrusted_cert: "allow"
              untrusted_server_cert: "allow"
          imaps:
              allow_invalid_server_cert: "enable"
              cert_validation_failure: "allow"
              cert_validation_timeout: "allow"
              client_cert_request: "bypass"
              client_certificate: "bypass"
              expired_server_cert: "allow"
              invalid_server_cert: "allow"
              ports: "<your_own_value>"
              proxy_after_tcp_handshake: "enable"
              revoked_server_cert: "allow"
              sni_server_cert_check: "enable"
              status: "disable"
              unsupported_ssl: "bypass"
              unsupported_ssl_cipher: "allow"
              unsupported_ssl_negotiation: "allow"
              unsupported_ssl_version: "allow"
              untrusted_cert: "allow"
              untrusted_server_cert: "allow"
          mapi_over_https: "enable"
          name: "default_name_89"
          pop3s:
              allow_invalid_server_cert: "enable"
              cert_validation_failure: "allow"
              cert_validation_timeout: "allow"
              client_cert_request: "bypass"
              client_certificate: "bypass"
              expired_server_cert: "allow"
              invalid_server_cert: "allow"
              ports: "<your_own_value>"
              proxy_after_tcp_handshake: "enable"
              revoked_server_cert: "allow"
              sni_server_cert_check: "enable"
              status: "disable"
              unsupported_ssl: "bypass"
              unsupported_ssl_cipher: "allow"
              unsupported_ssl_negotiation: "allow"
              unsupported_ssl_version: "allow"
              untrusted_cert: "allow"
              untrusted_server_cert: "allow"
          rpc_over_https: "enable"
          server_cert:
              -
                  name: "default_name_111 (source vpn.certificate.local.name)"
          server_cert_mode: "re-sign"
          smtps:
              allow_invalid_server_cert: "enable"
              cert_validation_failure: "allow"
              cert_validation_timeout: "allow"
              client_cert_request: "bypass"
              client_certificate: "bypass"
              expired_server_cert: "allow"
              invalid_server_cert: "allow"
              ports: "<your_own_value>"
              proxy_after_tcp_handshake: "enable"
              revoked_server_cert: "allow"
              sni_server_cert_check: "enable"
              status: "disable"
              unsupported_ssl: "bypass"
              unsupported_ssl_cipher: "allow"
              unsupported_ssl_negotiation: "allow"
              unsupported_ssl_version: "allow"
              untrusted_cert: "allow"
              untrusted_server_cert: "allow"
          ssh:
              inspect_all: "disable"
              ports: "<your_own_value>"
              proxy_after_tcp_handshake: "enable"
              ssh_algorithm: "compatible"
              ssh_policy_check: "disable"
              ssh_tun_policy_check: "disable"
              status: "disable"
              unsupported_version: "bypass"
          ssl:
              allow_invalid_server_cert: "enable"
              cert_probe_failure: "allow"
              cert_validation_failure: "allow"
              cert_validation_timeout: "allow"
              client_cert_request: "bypass"
              client_certificate: "bypass"
              encrypted_client_hello: "allow"
              expired_server_cert: "allow"
              inspect_all: "disable"
              invalid_server_cert: "allow"
              min_allowed_ssl_version: "ssl-3.0"
              revoked_server_cert: "allow"
              sni_server_cert_check: "enable"
              unsupported_ssl: "bypass"
              unsupported_ssl_cipher: "allow"
              unsupported_ssl_negotiation: "allow"
              unsupported_ssl_version: "allow"
              untrusted_cert: "allow"
              untrusted_server_cert: "allow"
          ssl_anomalies_log: "disable"
          ssl_anomaly_log: "disable"
          ssl_exempt:
              -
                  address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                  address6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
                  fortiguard_category: "0"
                  id: "167"
                  regex: "<your_own_value>"
                  type: "fortiguard-category"
                  wildcard_fqdn: "<your_own_value> (source firewall.wildcard-fqdn.custom.name firewall.wildcard-fqdn.group.name)"
          ssl_exemption_ip_rating: "enable"
          ssl_exemption_log: "disable"
          ssl_exemptions_log: "disable"
          ssl_handshake_log: "disable"
          ssl_negotiation_log: "disable"
          ssl_server:
              -
                  ftps_client_cert_request: "bypass"
                  ftps_client_certificate: "bypass"
                  https_client_cert_request: "bypass"
                  https_client_certificate: "bypass"
                  id: "181"
                  imaps_client_cert_request: "bypass"
                  imaps_client_certificate: "bypass"
                  ip: "<your_own_value>"
                  pop3s_client_cert_request: "bypass"
                  pop3s_client_certificate: "bypass"
                  smtps_client_cert_request: "bypass"
                  smtps_client_certificate: "bypass"
                  ssl_other_client_cert_request: "bypass"
                  ssl_other_client_certificate: "bypass"
          ssl_server_cert_log: "disable"
          supported_alpn: "http1-1"
          untrusted_caname: "<your_own_value> (source vpn.certificate.local.name vpn.certificate.hsm-local.name)"
          use_ssl_server: "disable"
          whitelist: "enable"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_firewall_ssl_ssh_profile_data(json):
    option_list = [
        "allowlist",
        "block_blacklisted_certificates",
        "block_blocklisted_certificates",
        "caname",
        "comment",
        "dot",
        "ech_outer_sni",
        "ftps",
        "https",
        "imaps",
        "mapi_over_https",
        "name",
        "pop3s",
        "rpc_over_https",
        "server_cert",
        "server_cert_mode",
        "smtps",
        "ssh",
        "ssl",
        "ssl_anomalies_log",
        "ssl_anomaly_log",
        "ssl_exempt",
        "ssl_exemption_ip_rating",
        "ssl_exemption_log",
        "ssl_exemptions_log",
        "ssl_handshake_log",
        "ssl_negotiation_log",
        "ssl_server",
        "ssl_server_cert_log",
        "supported_alpn",
        "untrusted_caname",
        "use_ssl_server",
        "whitelist",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["https", "ports"],
        ["ftps", "ports"],
        ["imaps", "ports"],
        ["pop3s", "ports"],
        ["smtps", "ports"],
        ["ssh", "ports"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def firewall_ssl_ssh_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_ssl_ssh_profile_data = data["firewall_ssl_ssh_profile"]

    filtered_data = filter_firewall_ssl_ssh_profile_data(firewall_ssl_ssh_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "ssl-ssh-profile", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "ssl-ssh-profile", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["firewall_ssl_ssh_profile"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "ssl-ssh-profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "ssl-ssh-profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "ssl-ssh-profile", mkey=converted_data["name"], vdom=vdom
        )
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_firewall(data, fos, check_mode):

    if data["firewall_ssl_ssh_profile"]:
        resp = firewall_ssl_ssh_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_ssl_ssh_profile")
        )
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssl": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "inspect_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "certificate-inspection"},
                        {"value": "deep-inspection"},
                    ],
                },
                "client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "inspect", "v_range": [["v7.0.1", "v7.0.3"]]},
                    ],
                },
                "unsupported_ssl_cipher": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "unsupported_ssl_negotiation": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "expired_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "revoked_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "untrusted_server_cert": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_timeout": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_failure": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "sni_server_cert_check": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "strict"},
                        {"value": "disable"},
                    ],
                },
                "cert_probe_failure": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "encrypted_client_hello": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "min_allowed_ssl_version": {
                    "v_range": [["v7.0.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ssl-3.0"},
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3"},
                    ],
                },
                "client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "invalid_server_cert": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "allow_invalid_server_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "untrusted_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
            },
        },
        "https": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "certificate-inspection"},
                        {"value": "deep-inspection"},
                    ],
                },
                "quic": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "inspect", "v_range": [["v7.4.2", ""]]},
                        {"value": "bypass", "v_range": [["v7.4.2", ""]]},
                        {"value": "block", "v_range": [["v7.4.2", ""]]},
                        {"value": "disable", "v_range": [["v7.4.1", "v7.4.1"]]},
                        {"value": "enable", "v_range": [["v7.4.1", "v7.4.1"]]},
                    ],
                },
                "udp_not_quic": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "inspect", "v_range": [["v7.0.1", "v7.0.3"]]},
                    ],
                },
                "unsupported_ssl_cipher": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "unsupported_ssl_negotiation": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "expired_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "revoked_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "untrusted_server_cert": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_timeout": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_failure": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "sni_server_cert_check": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "strict"},
                        {"value": "disable"},
                    ],
                },
                "cert_probe_failure": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "encrypted_client_hello": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "min_allowed_ssl_version": {
                    "v_range": [["v7.0.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ssl-3.0"},
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3"},
                    ],
                },
                "client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "invalid_server_cert": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "allow_invalid_server_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "untrusted_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
            },
        },
        "ftps": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "deep-inspection"}],
                },
                "client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "inspect", "v_range": [["v7.0.1", "v7.0.3"]]},
                    ],
                },
                "unsupported_ssl_cipher": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "unsupported_ssl_negotiation": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "expired_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "revoked_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "untrusted_server_cert": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_timeout": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_failure": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "sni_server_cert_check": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "strict"},
                        {"value": "disable"},
                    ],
                },
                "min_allowed_ssl_version": {
                    "v_range": [["v7.0.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ssl-3.0"},
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3"},
                    ],
                },
                "client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "invalid_server_cert": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "allow_invalid_server_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "untrusted_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
            },
        },
        "imaps": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "deep-inspection"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "inspect", "v_range": [["v7.0.1", "v7.0.3"]]},
                    ],
                },
                "unsupported_ssl_cipher": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "unsupported_ssl_negotiation": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "expired_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "revoked_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "untrusted_server_cert": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_timeout": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_failure": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "sni_server_cert_check": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "strict"},
                        {"value": "disable"},
                    ],
                },
                "client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "invalid_server_cert": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "allow_invalid_server_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "untrusted_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
            },
        },
        "pop3s": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "deep-inspection"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "inspect", "v_range": [["v7.0.1", "v7.0.3"]]},
                    ],
                },
                "unsupported_ssl_cipher": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "unsupported_ssl_negotiation": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "expired_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "revoked_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "untrusted_server_cert": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_timeout": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_failure": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "sni_server_cert_check": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "strict"},
                        {"value": "disable"},
                    ],
                },
                "client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "invalid_server_cert": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "allow_invalid_server_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "untrusted_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
            },
        },
        "smtps": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "deep-inspection"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "inspect", "v_range": [["v7.0.1", "v7.0.3"]]},
                    ],
                },
                "unsupported_ssl_cipher": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "unsupported_ssl_negotiation": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "expired_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "revoked_server_cert": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "untrusted_server_cert": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_timeout": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_failure": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "sni_server_cert_check": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "strict"},
                        {"value": "disable"},
                    ],
                },
                "client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "invalid_server_cert": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "allow_invalid_server_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "untrusted_cert": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
            },
        },
        "ssh": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "ports": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "deep-inspection"}],
                },
                "inspect_all": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "deep-inspection"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "unsupported_version": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "bypass"}, {"value": "block"}],
                },
                "ssh_tun_policy_check": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "ssh_algorithm": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "compatible"}, {"value": "high-encryption"}],
                },
                "ssh_policy_check": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
        },
        "dot": {
            "v_range": [["v7.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "deep-inspection"}],
                },
                "quic": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "inspect", "v_range": [["v7.4.2", ""]]},
                        {"value": "bypass", "v_range": [["v7.4.2", ""]]},
                        {"value": "block", "v_range": [["v7.4.2", ""]]},
                        {"value": "disable", "v_range": [["v7.4.1", "v7.4.1"]]},
                        {"value": "enable", "v_range": [["v7.4.1", "v7.4.1"]]},
                    ],
                },
                "udp_not_quic": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "proxy_after_tcp_handshake": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "client_certificate": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "unsupported_ssl_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "inspect", "v_range": [["v7.0.1", "v7.0.3"]]},
                    ],
                },
                "unsupported_ssl_cipher": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "unsupported_ssl_negotiation": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "block"}],
                },
                "expired_server_cert": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "revoked_server_cert": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "untrusted_server_cert": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_timeout": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "cert_validation_failure": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "block"},
                        {"value": "ignore"},
                    ],
                },
                "sni_server_cert_check": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "enable"},
                        {"value": "strict"},
                        {"value": "disable"},
                    ],
                },
            },
        },
        "allowlist": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "block_blocklisted_certificates": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_exempt": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "fortiguard-category"},
                        {"value": "address"},
                        {"value": "address6"},
                        {"value": "wildcard-fqdn"},
                        {"value": "regex"},
                    ],
                },
                "fortiguard_category": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "address": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "address6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "wildcard_fqdn": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "regex": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ech_outer_sni": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "required": True,
                },
                "sni": {"v_range": [["v7.4.4", ""]], "type": "string"},
            },
            "v_range": [["v7.4.4", ""]],
        },
        "server_cert_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "re-sign"}, {"value": "replace"}],
        },
        "use_ssl_server": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "caname": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "untrusted_caname": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "server_cert": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ssl_server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "https_client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "smtps_client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "pop3s_client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "imaps_client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "ftps_client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "ssl_other_client_certificate": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "https_client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "smtps_client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "pop3s_client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "imaps_client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "ftps_client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
                "ssl_other_client_cert_request": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "bypass"},
                        {"value": "inspect"},
                        {"value": "block"},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ssl_exemption_ip_rating": {
            "v_range": [["v7.0.6", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_exemption_log": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_anomaly_log": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_negotiation_log": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_server_cert_log": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_handshake_log": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "rpc_over_https": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mapi_over_https": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "supported_alpn": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "http1-1"},
                {"value": "http2"},
                {"value": "all"},
                {"value": "none"},
            ],
        },
        "ssl_anomalies_log": {
            "v_range": [["v6.0.0", "v7.0.1"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_exemptions_log": {
            "v_range": [["v6.0.0", "v7.0.1"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "whitelist": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "block_blacklisted_certificates": {
            "v_range": [["v6.2.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "firewall_ssl_ssh_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_ssl_ssh_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_ssl_ssh_profile"]["options"][attribute_name][
                "required"
            ] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "firewall_ssl_ssh_profile"
        )

        is_error, has_changed, result, diff = fortios_firewall(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
