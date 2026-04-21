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
module: fortios_ztna_traffic_forward_proxy
short_description: Configure ZTNA traffic forward proxy in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify ztna feature and traffic_forward_proxy category.
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
    ztna_traffic_forward_proxy:
        description:
            - Configure ZTNA traffic forward proxy.
        default: null
        type: dict
        suboptions:
            auth_portal:
                description:
                    - Enable/disable authentication portal.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            auth_virtual_host:
                description:
                    - Virtual host for authentication portal. Source firewall.access-proxy-virtual-host.name.
                type: str
            client_cert:
                description:
                    - Enable/disable to request client certificate.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                description:
                    - Comment.
                type: str
            decrypted_traffic_mirror:
                description:
                    - Decrypted traffic mirror. Source firewall.decrypted-traffic-mirror.name.
                type: str
            empty_cert_action:
                description:
                    - Action of an empty client certificate.
                type: str
                choices:
                    - 'accept'
                    - 'block'
                    - 'accept-unmanageable'
            h3_support:
                description:
                    - Enable/disable HTTP3/QUIC support .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            host:
                description:
                    - Virtual or real host name. Source firewall.access-proxy-virtual-host.name.
                type: str
            interface:
                description:
                    - interface name Source system.interface.name.
                type: str
            log_blocked_traffic:
                description:
                    - Enable/disable logging of blocked traffic.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - ZTNA proxy name.
                required: true
                type: str
            port:
                description:
                    - Accept incoming traffic on one or more ports (0 - 65535).
                type: str
            quic:
                description:
                    - QUIC setting.
                type: dict
                suboptions:
                    ack_delay_exponent:
                        description:
                            - ACK delay exponent (1 - 20).
                        type: int
                    active_connection_id_limit:
                        description:
                            - Active connection ID limit (1 - 8).
                        type: int
                    active_migration:
                        description:
                            - Enable/disable active migration .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    grease_quic_bit:
                        description:
                            - Enable/disable grease QUIC bit .
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    max_ack_delay:
                        description:
                            - Maximum ACK delay in milliseconds (1 - 16383).
                        type: int
                    max_datagram_frame_size:
                        description:
                            - Maximum datagram frame size in bytes (1 - 1500).
                        type: int
                    max_idle_timeout:
                        description:
                            - Maximum idle timeout milliseconds (1 - 60000).
                        type: int
                    max_udp_payload_size:
                        description:
                            - Maximum UDP payload size in bytes (1200 - 1500).
                        type: int
            ssl_accept_ffdhe_groups:
                description:
                    - Enable/disable FFDHE cipher suite for SSL key exchange.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_algorithm:
                description:
                    - Permitted encryption algorithms for SSL sessions according to encryption strength.
                type: str
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
                    - 'custom'
            ssl_certificate:
                description:
                    - Name of the certificate to use for SSL handshake.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Certificate list. Source vpn.certificate.local.name.
                        required: true
                        type: str
            ssl_cipher_suites:
                description:
                    - SSL/TLS cipher suites acceptable from a client, ordered by priority.
                type: list
                elements: dict
                suboptions:
                    cipher:
                        description:
                            - Cipher suite name.
                        type: str
                        choices:
                            - 'TLS-AES-128-GCM-SHA256'
                            - 'TLS-AES-256-GCM-SHA384'
                            - 'TLS-CHACHA20-POLY1305-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                            - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-RSA-WITH-SEED-CBC-SHA'
                            - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                            - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-RSA-WITH-RC4-128-MD5'
                            - 'TLS-RSA-WITH-RC4-128-SHA'
                            - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                            - 'TLS-RSA-WITH-DES-CBC-SHA'
                    priority:
                        description:
                            - SSL/TLS cipher suites priority. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    versions:
                        description:
                            - SSL/TLS versions that the cipher suite can be used with.
                        type: list
                        elements: str
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl_client_fallback:
                description:
                    - Enable/disable support for preventing Downgrade Attacks on client connections (RFC 7507).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_client_rekey_count:
                description:
                    - Maximum length of data in MB before triggering a client rekey (0 = disable).
                type: int
            ssl_client_renegotiation:
                description:
                    - Allow, deny, or require secure renegotiation of client sessions to comply with RFC 5746.
                type: str
                choices:
                    - 'allow'
                    - 'deny'
                    - 'secure'
            ssl_client_session_state_max:
                description:
                    - Maximum number of client to FortiProxy SSL session states to keep.
                type: int
            ssl_client_session_state_timeout:
                description:
                    - Number of minutes to keep client to FortiProxy SSL session state.
                type: int
            ssl_client_session_state_type:
                description:
                    - How to expire SSL sessions for the segment of the SSL connection between the client and the FortiGate.
                type: str
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            ssl_dh_bits:
                description:
                    - Bit-size of Diffie-Hellman (DH) prime used in DHE-RSA negotiation .
                type: str
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
            ssl_hpkp:
                description:
                    - Enable/disable including HPKP header in response.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
                    - 'report-only'
            ssl_hpkp_age:
                description:
                    - Number of seconds the client should honor the HPKP setting.
                type: int
            ssl_hpkp_backup:
                description:
                    - Certificate to generate backup HPKP pin from. Source vpn.certificate.local.name vpn.certificate.ca.name.
                type: str
            ssl_hpkp_include_subdomains:
                description:
                    - Indicate that HPKP header applies to all subdomains.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_hpkp_primary:
                description:
                    - Certificate to generate primary HPKP pin from. Source vpn.certificate.local.name vpn.certificate.ca.name.
                type: str
            ssl_hpkp_report_uri:
                description:
                    - URL to report HPKP violations to.
                type: str
            ssl_hsts:
                description:
                    - Enable/disable including HSTS header in response.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_hsts_age:
                description:
                    - Number of seconds the client should honor the HSTS setting.
                type: int
            ssl_hsts_include_subdomains:
                description:
                    - Indicate that HSTS header applies to all subdomains.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_http_location_conversion:
                description:
                    - Enable to replace HTTP with HTTPS in the reply"s Location HTTP header field.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_http_match_host:
                description:
                    - Enable/disable HTTP host matching for location conversion.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_max_version:
                description:
                    - Highest SSL/TLS version acceptable from a client.
                type: str
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_min_version:
                description:
                    - Lowest SSL/TLS version acceptable from a client.
                type: str
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_mode:
                description:
                    - Apply SSL offloading between the client and the FortiGate (half) or from the client to the FortiGate and from the FortiGate to the
                       server (full).
                type: str
                choices:
                    - 'half'
                    - 'full'
            ssl_pfs:
                description:
                    - Select the cipher suites that can be used for SSL perfect forward secrecy (PFS). Applies to both client and server sessions.
                type: str
                choices:
                    - 'require'
                    - 'deny'
                    - 'allow'
            ssl_send_empty_frags:
                description:
                    - Enable/disable sending empty fragments to avoid CBC IV attacks (SSL 3.0 & TLS 1.0 only). May need to be disabled for compatibility with
                       older systems.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_server_algorithm:
                description:
                    - Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                type: str
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
                    - 'custom'
                    - 'client'
            ssl_server_cipher_suites:
                description:
                    - SSL/TLS cipher suites to offer to a server, ordered by priority.
                type: list
                elements: dict
                suboptions:
                    cipher:
                        description:
                            - Cipher suite name.
                        type: str
                        choices:
                            - 'TLS-AES-128-GCM-SHA256'
                            - 'TLS-AES-256-GCM-SHA384'
                            - 'TLS-CHACHA20-POLY1305-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                            - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-RSA-WITH-SEED-CBC-SHA'
                            - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                            - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-RSA-WITH-RC4-128-MD5'
                            - 'TLS-RSA-WITH-RC4-128-SHA'
                            - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                            - 'TLS-RSA-WITH-DES-CBC-SHA'
                    priority:
                        description:
                            - SSL/TLS cipher suites priority. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    versions:
                        description:
                            - SSL/TLS versions that the cipher suite can be used with.
                        type: list
                        elements: str
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl_server_max_version:
                description:
                    - Highest SSL/TLS version acceptable from a server. Use the client setting by default.
                type: str
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
                    - 'client'
            ssl_server_min_version:
                description:
                    - Lowest SSL/TLS version acceptable from a server. Use the client setting by default.
                type: str
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
                    - 'client'
            ssl_server_renegotiation:
                description:
                    - Enable/disable secure renegotiation to comply with RFC 5746.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_server_session_state_max:
                description:
                    - Maximum number of FortiGate to Server SSL session states to keep.
                type: int
            ssl_server_session_state_timeout:
                description:
                    - Number of minutes to keep FortiGate to Server SSL session state.
                type: int
            ssl_server_session_state_type:
                description:
                    - How to expire SSL sessions for the segment of the SSL connection between the server and the FortiGate.
                type: str
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            status:
                description:
                    - Enable/disable the traffic forward proxy for ZTNA traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            svr_pool_multiplex:
                description:
                    - Enable/disable server pool multiplexing. Share connected server in HTTP, HTTPS, and web-portal api-gateway.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            svr_pool_server_max_concurrent_request:
                description:
                    - Maximum number of concurrent requests that servers in server pool could handle .
                type: int
            svr_pool_server_max_request:
                description:
                    - Maximum number of requests that servers in server pool handle before disconnecting .
                type: int
            svr_pool_ttl:
                description:
                    - Time-to-live in the server pool for idle connections to servers.
                type: int
            user_agent_detect:
                description:
                    - Enable/disable to detect device type by HTTP user-agent if no client certificate provided.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            vip:
                description:
                    - Virtual IP name. Source firewall.vip.name.
                type: str
            vip6:
                description:
                    - Virtual IPv6 name. Source firewall.vip6.name.
                type: str
"""

EXAMPLES = """
- name: Configure ZTNA traffic forward proxy.
  fortinet.fortios.fortios_ztna_traffic_forward_proxy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      ztna_traffic_forward_proxy:
          auth_portal: "disable"
          auth_virtual_host: "myhostname (source firewall.access-proxy-virtual-host.name)"
          client_cert: "disable"
          comment: "Comment."
          decrypted_traffic_mirror: "<your_own_value> (source firewall.decrypted-traffic-mirror.name)"
          empty_cert_action: "accept"
          h3_support: "enable"
          host: "myhostname (source firewall.access-proxy-virtual-host.name)"
          interface: "<your_own_value> (source system.interface.name)"
          log_blocked_traffic: "disable"
          name: "default_name_13"
          port: "<your_own_value>"
          quic:
              ack_delay_exponent: "3"
              active_connection_id_limit: "2"
              active_migration: "enable"
              grease_quic_bit: "enable"
              max_ack_delay: "25"
              max_datagram_frame_size: "1500"
              max_idle_timeout: "30000"
              max_udp_payload_size: "1500"
          ssl_accept_ffdhe_groups: "enable"
          ssl_algorithm: "high"
          ssl_certificate:
              -
                  name: "default_name_27 (source vpn.certificate.local.name)"
          ssl_cipher_suites:
              -
                  cipher: "TLS-AES-128-GCM-SHA256"
                  priority: "<you_own_value>"
                  versions: "ssl-3.0"
          ssl_client_fallback: "disable"
          ssl_client_rekey_count: "0"
          ssl_client_renegotiation: "allow"
          ssl_client_session_state_max: "1000"
          ssl_client_session_state_timeout: "30"
          ssl_client_session_state_type: "disable"
          ssl_dh_bits: "768"
          ssl_hpkp: "disable"
          ssl_hpkp_age: "5184000"
          ssl_hpkp_backup: "<your_own_value> (source vpn.certificate.local.name vpn.certificate.ca.name)"
          ssl_hpkp_include_subdomains: "disable"
          ssl_hpkp_primary: "<your_own_value> (source vpn.certificate.local.name vpn.certificate.ca.name)"
          ssl_hpkp_report_uri: "<your_own_value>"
          ssl_hsts: "disable"
          ssl_hsts_age: "5184000"
          ssl_hsts_include_subdomains: "disable"
          ssl_http_location_conversion: "enable"
          ssl_http_match_host: "enable"
          ssl_max_version: "ssl-3.0"
          ssl_min_version: "ssl-3.0"
          ssl_mode: "half"
          ssl_pfs: "require"
          ssl_send_empty_frags: "enable"
          ssl_server_algorithm: "high"
          ssl_server_cipher_suites:
              -
                  cipher: "TLS-AES-128-GCM-SHA256"
                  priority: "<you_own_value>"
                  versions: "ssl-3.0"
          ssl_server_max_version: "ssl-3.0"
          ssl_server_min_version: "ssl-3.0"
          ssl_server_renegotiation: "enable"
          ssl_server_session_state_max: "100"
          ssl_server_session_state_timeout: "60"
          ssl_server_session_state_type: "disable"
          status: "enable"
          svr_pool_multiplex: "enable"
          svr_pool_server_max_concurrent_request: "0"
          svr_pool_server_max_request: "0"
          svr_pool_ttl: "15"
          user_agent_detect: "disable"
          vip: "<your_own_value> (source firewall.vip.name)"
          vip6: "<your_own_value> (source firewall.vip6.name)"
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


def filter_ztna_traffic_forward_proxy_data(json):
    option_list = [
        "auth_portal",
        "auth_virtual_host",
        "client_cert",
        "comment",
        "decrypted_traffic_mirror",
        "empty_cert_action",
        "h3_support",
        "host",
        "interface",
        "log_blocked_traffic",
        "name",
        "port",
        "quic",
        "ssl_accept_ffdhe_groups",
        "ssl_algorithm",
        "ssl_certificate",
        "ssl_cipher_suites",
        "ssl_client_fallback",
        "ssl_client_rekey_count",
        "ssl_client_renegotiation",
        "ssl_client_session_state_max",
        "ssl_client_session_state_timeout",
        "ssl_client_session_state_type",
        "ssl_dh_bits",
        "ssl_hpkp",
        "ssl_hpkp_age",
        "ssl_hpkp_backup",
        "ssl_hpkp_include_subdomains",
        "ssl_hpkp_primary",
        "ssl_hpkp_report_uri",
        "ssl_hsts",
        "ssl_hsts_age",
        "ssl_hsts_include_subdomains",
        "ssl_http_location_conversion",
        "ssl_http_match_host",
        "ssl_max_version",
        "ssl_min_version",
        "ssl_mode",
        "ssl_pfs",
        "ssl_send_empty_frags",
        "ssl_server_algorithm",
        "ssl_server_cipher_suites",
        "ssl_server_max_version",
        "ssl_server_min_version",
        "ssl_server_renegotiation",
        "ssl_server_session_state_max",
        "ssl_server_session_state_timeout",
        "ssl_server_session_state_type",
        "status",
        "svr_pool_multiplex",
        "svr_pool_server_max_concurrent_request",
        "svr_pool_server_max_request",
        "svr_pool_ttl",
        "user_agent_detect",
        "vip",
        "vip6",
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
        ["ssl_cipher_suites", "versions"],
        ["ssl_server_cipher_suites", "versions"],
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


def ztna_traffic_forward_proxy(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    ztna_traffic_forward_proxy_data = data["ztna_traffic_forward_proxy"]

    filtered_data = filter_ztna_traffic_forward_proxy_data(
        ztna_traffic_forward_proxy_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("ztna", "traffic-forward-proxy", filtered_data, vdom=vdom)
        current_data = fos.get("ztna", "traffic-forward-proxy", vdom=vdom, mkey=mkey)
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
    data_copy["ztna_traffic_forward_proxy"] = filtered_data
    fos.do_member_operation(
        "ztna",
        "traffic-forward-proxy",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("ztna", "traffic-forward-proxy", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "ztna", "traffic-forward-proxy", mkey=converted_data["name"], vdom=vdom
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


def fortios_ztna(data, fos, check_mode):

    if data["ztna_traffic_forward_proxy"]:
        resp = ztna_traffic_forward_proxy(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("ztna_traffic_forward_proxy")
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
        "name": {"v_range": [["v7.6.0", ""]], "type": "string", "required": True},
        "vip": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "host": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "decrypted_traffic_mirror": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "log_blocked_traffic": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auth_portal": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auth_virtual_host": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "vip6": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "status": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "interface": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
        "port": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
        "client_cert": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "user_agent_detect": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "empty_cert_action": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "accept"},
                {"value": "block"},
                {"value": "accept-unmanageable"},
            ],
        },
        "svr_pool_multiplex": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "svr_pool_ttl": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
        "svr_pool_server_max_request": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "integer",
        },
        "svr_pool_server_max_concurrent_request": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "integer",
        },
        "comment": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
        "h3_support": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "quic": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "dict",
            "children": {
                "max_idle_timeout": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "max_udp_payload_size": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "active_connection_id_limit": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "ack_delay_exponent": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "max_ack_delay": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
                "max_datagram_frame_size": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                },
                "active_migration": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "grease_quic_bit": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "ssl_mode": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "half"}, {"value": "full"}],
        },
        "ssl_certificate": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.0", "v7.6.0"]],
        },
        "ssl_dh_bits": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "768"},
                {"value": "1024"},
                {"value": "1536"},
                {"value": "2048"},
                {"value": "3072"},
                {"value": "4096"},
            ],
        },
        "ssl_algorithm": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "high"},
                {"value": "medium"},
                {"value": "low"},
                {"value": "custom"},
            ],
        },
        "ssl_cipher_suites": {
            "type": "list",
            "elements": "dict",
            "children": {
                "priority": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                    "required": True,
                },
                "cipher": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [
                        {"value": "TLS-AES-128-GCM-SHA256"},
                        {"value": "TLS-AES-256-GCM-SHA384"},
                        {"value": "TLS-CHACHA20-POLY1305-SHA256"},
                        {"value": "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-DHE-DSS-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-AES-256-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-RSA-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-RSA-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-RSA-WITH-AES-256-CBC-SHA256"},
                        {"value": "TLS-RSA-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
                        {"value": "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-SEED-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-SEED-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-RSA-WITH-SEED-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-RSA-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-RSA-WITH-RC4-128-SHA"},
                        {"value": "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-3DES-EDE-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-RC4-128-MD5"},
                        {"value": "TLS-RSA-WITH-RC4-128-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-DES-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-DES-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-DES-CBC-SHA"},
                    ],
                },
                "versions": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "list",
                    "options": [
                        {"value": "ssl-3.0"},
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v7.6.0", "v7.6.0"]],
        },
        "ssl_server_algorithm": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "high"},
                {"value": "medium"},
                {"value": "low"},
                {"value": "custom"},
                {"value": "client"},
            ],
        },
        "ssl_server_cipher_suites": {
            "type": "list",
            "elements": "dict",
            "children": {
                "priority": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "integer",
                    "required": True,
                },
                "cipher": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "string",
                    "options": [
                        {"value": "TLS-AES-128-GCM-SHA256"},
                        {"value": "TLS-AES-256-GCM-SHA384"},
                        {"value": "TLS-CHACHA20-POLY1305-SHA256"},
                        {"value": "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-DHE-DSS-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-AES-256-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-RSA-WITH-AES-128-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-AES-256-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-AES-128-CBC-SHA256"},
                        {"value": "TLS-RSA-WITH-AES-128-GCM-SHA256"},
                        {"value": "TLS-RSA-WITH-AES-256-CBC-SHA256"},
                        {"value": "TLS-RSA-WITH-AES-256-GCM-SHA384"},
                        {"value": "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
                        {"value": "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-SEED-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-SEED-CBC-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-RSA-WITH-SEED-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-RSA-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256"},
                        {"value": "TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384"},
                        {"value": "TLS-ECDHE-RSA-WITH-RC4-128-SHA"},
                        {"value": "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-3DES-EDE-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-RC4-128-MD5"},
                        {"value": "TLS-RSA-WITH-RC4-128-SHA"},
                        {"value": "TLS-DHE-RSA-WITH-DES-CBC-SHA"},
                        {"value": "TLS-DHE-DSS-WITH-DES-CBC-SHA"},
                        {"value": "TLS-RSA-WITH-DES-CBC-SHA"},
                    ],
                },
                "versions": {
                    "v_range": [["v7.6.0", "v7.6.0"]],
                    "type": "list",
                    "options": [
                        {"value": "ssl-3.0"},
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v7.6.0", "v7.6.0"]],
        },
        "ssl_pfs": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "require"}, {"value": "deny"}, {"value": "allow"}],
        },
        "ssl_min_version": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
            ],
        },
        "ssl_max_version": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
            ],
        },
        "ssl_server_min_version": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
                {"value": "client"},
            ],
        },
        "ssl_server_max_version": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
                {"value": "client"},
            ],
        },
        "ssl_accept_ffdhe_groups": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_send_empty_frags": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_client_fallback": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_client_renegotiation": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}, {"value": "secure"}],
        },
        "ssl_client_session_state_type": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "time"},
                {"value": "count"},
                {"value": "both"},
            ],
        },
        "ssl_client_session_state_timeout": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "integer",
        },
        "ssl_client_session_state_max": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "integer",
        },
        "ssl_client_rekey_count": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "integer",
        },
        "ssl_server_renegotiation": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_server_session_state_type": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "time"},
                {"value": "count"},
                {"value": "both"},
            ],
        },
        "ssl_server_session_state_timeout": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "integer",
        },
        "ssl_server_session_state_max": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "integer",
        },
        "ssl_http_location_conversion": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_http_match_host": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_hpkp": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "enable"},
                {"value": "report-only"},
            ],
        },
        "ssl_hpkp_primary": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
        "ssl_hpkp_backup": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
        "ssl_hpkp_age": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
        "ssl_hpkp_report_uri": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "string"},
        "ssl_hpkp_include_subdomains": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_hsts": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_hsts_age": {"v_range": [["v7.6.0", "v7.6.0"]], "type": "integer"},
        "ssl_hsts_include_subdomains": {
            "v_range": [["v7.6.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
    },
    "v_range": [["v7.6.0", ""]],
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
        "ztna_traffic_forward_proxy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["ztna_traffic_forward_proxy"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["ztna_traffic_forward_proxy"]["options"][attribute_name][
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
            fos, versioned_schema, "ztna_traffic_forward_proxy"
        )

        is_error, has_changed, result, diff = fortios_ztna(
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
