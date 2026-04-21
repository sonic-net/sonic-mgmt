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
module: fortios_firewall_access_proxy6
short_description: Configure IPv6 access proxy in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and access_proxy6 category.
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
    firewall_access_proxy6:
        description:
            - Configure IPv6 access proxy.
        default: null
        type: dict
        suboptions:
            add_vhost_domain_to_dnsdb:
                description:
                    - Enable/disable adding vhost/domain to dnsdb for ztna dox tunnel.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            api_gateway:
                description:
                    - Set IPv4 API Gateway.
                type: list
                elements: dict
                suboptions:
                    application:
                        description:
                            - SaaS application controlled by this Access Proxy.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - SaaS application name.
                                required: true
                                type: str
                    h2_support:
                        description:
                            - HTTP2 support, default=Enable.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    h3_support:
                        description:
                            - HTTP3/QUIC support, default=Disable.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    http_cookie_age:
                        description:
                            - Time in minutes that client web browsers should keep a cookie. Default is 60 minutes. 0 = no time limit.
                        type: int
                    http_cookie_domain:
                        description:
                            - Domain that HTTP cookie persistence should apply to.
                        type: str
                    http_cookie_domain_from_host:
                        description:
                            - Enable/disable use of HTTP cookie domain from host field in HTTP.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    http_cookie_generation:
                        description:
                            - Generation of HTTP cookie to be accepted. Changing invalidates all existing cookies.
                        type: int
                    http_cookie_path:
                        description:
                            - Limit HTTP cookie persistence to the specified path.
                        type: str
                    http_cookie_share:
                        description:
                            - Control sharing of cookies across API Gateway. Use of same-ip means a cookie from one virtual server can be used by another.
                               Disable stops cookie sharing.
                        type: str
                        choices:
                            - 'disable'
                            - 'same-ip'
                    https_cookie_secure:
                        description:
                            - Enable/disable verification that inserted HTTPS cookies are secure.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        description:
                            - API Gateway ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ldb_method:
                        description:
                            - Method used to distribute sessions to real servers.
                        type: str
                        choices:
                            - 'static'
                            - 'round-robin'
                            - 'weighted'
                            - 'first-alive'
                            - 'http-host'
                    persistence:
                        description:
                            - Configure how to make sure that clients connect to the same server every time they make a request that is part of the same
                               session.
                        type: str
                        choices:
                            - 'none'
                            - 'http-cookie'
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
                    realservers:
                        description:
                            - Select the real servers that this Access Proxy will distribute traffic to.
                        type: list
                        elements: dict
                        suboptions:
                            addr_type:
                                description:
                                    - Type of address.
                                type: str
                                choices:
                                    - 'ip'
                                    - 'fqdn'
                            address:
                                description:
                                    - Address or address group of the real server. Source firewall.address.name firewall.addrgrp.name.
                                type: str
                            domain:
                                description:
                                    - Wildcard domain name of the real server.
                                type: str
                            external_auth:
                                description:
                                    - Enable/disable use of external browser as user-agent for SAML user authentication.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            health_check:
                                description:
                                    - Enable to check the responsiveness of the real server before forwarding traffic.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            health_check_proto:
                                description:
                                    - Protocol of the health check monitor to use when polling to determine server"s connectivity status.
                                type: str
                                choices:
                                    - 'ping'
                                    - 'http'
                                    - 'tcp-connect'
                            holddown_interval:
                                description:
                                    - Enable/disable holddown timer. Server will be considered active and reachable once the holddown period has expired (30
                                       seconds).
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            http_host:
                                description:
                                    - HTTP server domain name in HTTP header.
                                type: str
                            id:
                                description:
                                    - Real server ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            ip:
                                description:
                                    - IP address of the real server.
                                type: str
                            mappedport:
                                description:
                                    - Port for communicating with the real server.
                                type: str
                            port:
                                description:
                                    - Port for communicating with the real server.
                                type: int
                            ssh_client_cert:
                                description:
                                    - Set access-proxy SSH client certificate profile. Source firewall.access-proxy-ssh-client-cert.name.
                                type: str
                            ssh_host_key:
                                description:
                                    - One or more server host key.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - Server host key name. Source firewall.ssh.host-key.name.
                                        required: true
                                        type: str
                            ssh_host_key_validation:
                                description:
                                    - Enable/disable SSH real server host key validation.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            status:
                                description:
                                    - Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is
                                       sent.
                                type: str
                                choices:
                                    - 'active'
                                    - 'standby'
                                    - 'disable'
                            translate_host:
                                description:
                                    - Enable/disable translation of hostname/IP from virtual server to real server.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tunnel_encryption:
                                description:
                                    - Tunnel encryption.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            type:
                                description:
                                    - TCP forwarding server type.
                                type: str
                                choices:
                                    - 'tcp-forwarding'
                                    - 'ssh'
                            verify_cert:
                                description:
                                    - Enable/disable certificate verification of the real server.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            weight:
                                description:
                                    - Weight of the real server. If weighted load balancing is enabled, the server with the highest weight gets more
                                       connections.
                                type: int
                    saml_redirect:
                        description:
                            - Enable/disable SAML redirection after successful authentication.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    saml_server:
                        description:
                            - SAML service provider configuration for VIP authentication. Source user.saml.name.
                        type: str
                    service:
                        description:
                            - Service.
                        type: str
                        choices:
                            - 'http'
                            - 'https'
                            - 'tcp-forwarding'
                            - 'samlsp'
                            - 'web-portal'
                            - 'saas'
                    ssl_algorithm:
                        description:
                            - Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                        type: str
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                    ssl_cipher_suites:
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
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                                    - 'tls-1.3'
                    ssl_dh_bits:
                        description:
                            - Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                        type: str
                        choices:
                            - '768'
                            - '1024'
                            - '1536'
                            - '2048'
                            - '3072'
                            - '4096'
                    ssl_max_version:
                        description:
                            - Highest SSL/TLS version acceptable from a server.
                        type: str
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_min_version:
                        description:
                            - Lowest SSL/TLS version acceptable from a server.
                        type: str
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_renegotiation:
                        description:
                            - Enable/disable secure renegotiation to comply with RFC 5746.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_vpn_web_portal:
                        description:
                            - Agentless VPN web portal. Source vpn.ssl.web.portal.name.
                        type: str
                    url_map:
                        description:
                            - URL pattern to match.
                        type: str
                    url_map_type:
                        description:
                            - Type of url-map.
                        type: str
                        choices:
                            - 'sub-string'
                            - 'wildcard'
                            - 'regex'
                    virtual_host:
                        description:
                            - Virtual host. Source firewall.access-proxy-virtual-host.name.
                        type: str
            api_gateway6:
                description:
                    - Set IPv6 API Gateway.
                type: list
                elements: dict
                suboptions:
                    application:
                        description:
                            - SaaS application controlled by this Access Proxy.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - SaaS application name.
                                required: true
                                type: str
                    h2_support:
                        description:
                            - HTTP2 support, default=Enable.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    h3_support:
                        description:
                            - HTTP3/QUIC support, default=Disable.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    http_cookie_age:
                        description:
                            - Time in minutes that client web browsers should keep a cookie. Default is 60 minutes. 0 = no time limit.
                        type: int
                    http_cookie_domain:
                        description:
                            - Domain that HTTP cookie persistence should apply to.
                        type: str
                    http_cookie_domain_from_host:
                        description:
                            - Enable/disable use of HTTP cookie domain from host field in HTTP.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    http_cookie_generation:
                        description:
                            - Generation of HTTP cookie to be accepted. Changing invalidates all existing cookies.
                        type: int
                    http_cookie_path:
                        description:
                            - Limit HTTP cookie persistence to the specified path.
                        type: str
                    http_cookie_share:
                        description:
                            - Control sharing of cookies across API Gateway. Use of same-ip means a cookie from one virtual server can be used by another.
                               Disable stops cookie sharing.
                        type: str
                        choices:
                            - 'disable'
                            - 'same-ip'
                    https_cookie_secure:
                        description:
                            - Enable/disable verification that inserted HTTPS cookies are secure.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        description:
                            - API Gateway ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ldb_method:
                        description:
                            - Method used to distribute sessions to real servers.
                        type: str
                        choices:
                            - 'static'
                            - 'round-robin'
                            - 'weighted'
                            - 'first-alive'
                            - 'http-host'
                    persistence:
                        description:
                            - Configure how to make sure that clients connect to the same server every time they make a request that is part of the same
                               session.
                        type: str
                        choices:
                            - 'none'
                            - 'http-cookie'
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
                    realservers:
                        description:
                            - Select the real servers that this Access Proxy will distribute traffic to.
                        type: list
                        elements: dict
                        suboptions:
                            addr_type:
                                description:
                                    - Type of address.
                                type: str
                                choices:
                                    - 'ip'
                                    - 'fqdn'
                            address:
                                description:
                                    - Address or address group of the real server. Source firewall.address6.name firewall.addrgrp6.name.
                                type: str
                            domain:
                                description:
                                    - Wildcard domain name of the real server.
                                type: str
                            external_auth:
                                description:
                                    - Enable/disable use of external browser as user-agent for SAML user authentication.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            health_check:
                                description:
                                    - Enable to check the responsiveness of the real server before forwarding traffic.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            health_check_proto:
                                description:
                                    - Protocol of the health check monitor to use when polling to determine server"s connectivity status.
                                type: str
                                choices:
                                    - 'ping'
                                    - 'http'
                                    - 'tcp-connect'
                            holddown_interval:
                                description:
                                    - Enable/disable holddown timer. Server will be considered active and reachable once the holddown period has expired (30
                                       seconds).
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            http_host:
                                description:
                                    - HTTP server domain name in HTTP header.
                                type: str
                            id:
                                description:
                                    - Real server ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            ip:
                                description:
                                    - IPv6 address of the real server.
                                type: str
                            mappedport:
                                description:
                                    - Port for communicating with the real server.
                                type: str
                            port:
                                description:
                                    - Port for communicating with the real server.
                                type: int
                            ssh_client_cert:
                                description:
                                    - Set access-proxy SSH client certificate profile. Source firewall.access-proxy-ssh-client-cert.name.
                                type: str
                            ssh_host_key:
                                description:
                                    - One or more server host key.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - Server host key name. Source firewall.ssh.host-key.name.
                                        required: true
                                        type: str
                            ssh_host_key_validation:
                                description:
                                    - Enable/disable SSH real server host key validation.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            status:
                                description:
                                    - Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is
                                       sent.
                                type: str
                                choices:
                                    - 'active'
                                    - 'standby'
                                    - 'disable'
                            translate_host:
                                description:
                                    - Enable/disable translation of hostname/IP from virtual server to real server.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tunnel_encryption:
                                description:
                                    - Tunnel encryption.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            type:
                                description:
                                    - TCP forwarding server type.
                                type: str
                                choices:
                                    - 'tcp-forwarding'
                                    - 'ssh'
                            verify_cert:
                                description:
                                    - Enable/disable certificate verification of the real server.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            weight:
                                description:
                                    - Weight of the real server. If weighted load balancing is enabled, the server with the highest weight gets more
                                       connections.
                                type: int
                    saml_redirect:
                        description:
                            - Enable/disable SAML redirection after successful authentication.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    saml_server:
                        description:
                            - SAML service provider configuration for VIP authentication. Source user.saml.name.
                        type: str
                    service:
                        description:
                            - Service.
                        type: str
                        choices:
                            - 'http'
                            - 'https'
                            - 'tcp-forwarding'
                            - 'samlsp'
                            - 'web-portal'
                            - 'saas'
                    ssl_algorithm:
                        description:
                            - Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                        type: str
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                    ssl_cipher_suites:
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
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                                    - 'tls-1.3'
                    ssl_dh_bits:
                        description:
                            - Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                        type: str
                        choices:
                            - '768'
                            - '1024'
                            - '1536'
                            - '2048'
                            - '3072'
                            - '4096'
                    ssl_max_version:
                        description:
                            - Highest SSL/TLS version acceptable from a server.
                        type: str
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_min_version:
                        description:
                            - Lowest SSL/TLS version acceptable from a server.
                        type: str
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_renegotiation:
                        description:
                            - Enable/disable secure renegotiation to comply with RFC 5746.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_vpn_web_portal:
                        description:
                            - Agentless VPN web portal. Source vpn.ssl.web.portal.name.
                        type: str
                    url_map:
                        description:
                            - URL pattern to match.
                        type: str
                    url_map_type:
                        description:
                            - Type of url-map.
                        type: str
                        choices:
                            - 'sub-string'
                            - 'wildcard'
                            - 'regex'
                    virtual_host:
                        description:
                            - Virtual host. Source firewall.access-proxy-virtual-host.name.
                        type: str
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
            http_supported_max_version:
                description:
                    - Maximum supported HTTP versions. default = HTTP2
                type: str
                choices:
                    - 'http1'
                    - 'http2'
            log_blocked_traffic:
                description:
                    - Enable/disable logging of blocked traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Access Proxy name.
                required: true
                type: str
            svr_pool_multiplex:
                description:
                    - Enable/disable server pool multiplexing . Share connected server in HTTP, HTTPS, and web-portal api-gateway.
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
                    - Virtual IP name. Source firewall.vip6.name.
                type: str
"""

EXAMPLES = """
- name: Configure IPv6 access proxy.
  fortinet.fortios.fortios_firewall_access_proxy6:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_access_proxy6:
          add_vhost_domain_to_dnsdb: "enable"
          api_gateway:
              -
                  application:
                      -
                          name: "default_name_6"
                  h2_support: "enable"
                  h3_support: "enable"
                  http_cookie_age: "60"
                  http_cookie_domain: "<your_own_value>"
                  http_cookie_domain_from_host: "disable"
                  http_cookie_generation: "0"
                  http_cookie_path: "<your_own_value>"
                  http_cookie_share: "disable"
                  https_cookie_secure: "disable"
                  id: "16"
                  ldb_method: "static"
                  persistence: "none"
                  quic:
                      ack_delay_exponent: "3"
                      active_connection_id_limit: "2"
                      active_migration: "enable"
                      grease_quic_bit: "enable"
                      max_ack_delay: "25"
                      max_datagram_frame_size: "1500"
                      max_idle_timeout: "30000"
                      max_udp_payload_size: "1500"
                  realservers:
                      -
                          addr_type: "ip"
                          address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                          domain: "<your_own_value>"
                          external_auth: "enable"
                          health_check: "disable"
                          health_check_proto: "ping"
                          holddown_interval: "enable"
                          http_host: "myhostname"
                          id: "37"
                          ip: "<your_own_value>"
                          mappedport: "<your_own_value>"
                          port: "443"
                          ssh_client_cert: "<your_own_value> (source firewall.access-proxy-ssh-client-cert.name)"
                          ssh_host_key:
                              -
                                  name: "default_name_43 (source firewall.ssh.host-key.name)"
                          ssh_host_key_validation: "disable"
                          status: "active"
                          translate_host: "enable"
                          tunnel_encryption: "enable"
                          type: "tcp-forwarding"
                          verify_cert: "enable"
                          weight: "1"
                  saml_redirect: "disable"
                  saml_server: "<your_own_value> (source user.saml.name)"
                  service: "http"
                  ssl_algorithm: "high"
                  ssl_cipher_suites:
                      -
                          cipher: "TLS-AES-128-GCM-SHA256"
                          priority: "<you_own_value>"
                          versions: "tls-1.0"
                  ssl_dh_bits: "768"
                  ssl_max_version: "tls-1.0"
                  ssl_min_version: "tls-1.0"
                  ssl_renegotiation: "enable"
                  ssl_vpn_web_portal: "<your_own_value> (source vpn.ssl.web.portal.name)"
                  url_map: "<your_own_value>"
                  url_map_type: "sub-string"
                  virtual_host: "myhostname (source firewall.access-proxy-virtual-host.name)"
          api_gateway6:
              -
                  application:
                      -
                          name: "default_name_69"
                  h2_support: "enable"
                  h3_support: "enable"
                  http_cookie_age: "60"
                  http_cookie_domain: "<your_own_value>"
                  http_cookie_domain_from_host: "disable"
                  http_cookie_generation: "0"
                  http_cookie_path: "<your_own_value>"
                  http_cookie_share: "disable"
                  https_cookie_secure: "disable"
                  id: "79"
                  ldb_method: "static"
                  persistence: "none"
                  quic:
                      ack_delay_exponent: "3"
                      active_connection_id_limit: "2"
                      active_migration: "enable"
                      grease_quic_bit: "enable"
                      max_ack_delay: "25"
                      max_datagram_frame_size: "1500"
                      max_idle_timeout: "30000"
                      max_udp_payload_size: "1500"
                  realservers:
                      -
                          addr_type: "ip"
                          address: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
                          domain: "<your_own_value>"
                          external_auth: "enable"
                          health_check: "disable"
                          health_check_proto: "ping"
                          holddown_interval: "enable"
                          http_host: "myhostname"
                          id: "100"
                          ip: "<your_own_value>"
                          mappedport: "<your_own_value>"
                          port: "443"
                          ssh_client_cert: "<your_own_value> (source firewall.access-proxy-ssh-client-cert.name)"
                          ssh_host_key:
                              -
                                  name: "default_name_106 (source firewall.ssh.host-key.name)"
                          ssh_host_key_validation: "disable"
                          status: "active"
                          translate_host: "enable"
                          tunnel_encryption: "enable"
                          type: "tcp-forwarding"
                          verify_cert: "enable"
                          weight: "1"
                  saml_redirect: "disable"
                  saml_server: "<your_own_value> (source user.saml.name)"
                  service: "http"
                  ssl_algorithm: "high"
                  ssl_cipher_suites:
                      -
                          cipher: "TLS-AES-128-GCM-SHA256"
                          priority: "<you_own_value>"
                          versions: "tls-1.0"
                  ssl_dh_bits: "768"
                  ssl_max_version: "tls-1.0"
                  ssl_min_version: "tls-1.0"
                  ssl_renegotiation: "enable"
                  ssl_vpn_web_portal: "<your_own_value> (source vpn.ssl.web.portal.name)"
                  url_map: "<your_own_value>"
                  url_map_type: "sub-string"
                  virtual_host: "myhostname (source firewall.access-proxy-virtual-host.name)"
          auth_portal: "disable"
          auth_virtual_host: "myhostname (source firewall.access-proxy-virtual-host.name)"
          client_cert: "disable"
          decrypted_traffic_mirror: "<your_own_value> (source firewall.decrypted-traffic-mirror.name)"
          empty_cert_action: "accept"
          http_supported_max_version: "http1"
          log_blocked_traffic: "enable"
          name: "default_name_137"
          svr_pool_multiplex: "enable"
          svr_pool_server_max_concurrent_request: "0"
          svr_pool_server_max_request: "0"
          svr_pool_ttl: "15"
          user_agent_detect: "disable"
          vip: "<your_own_value> (source firewall.vip6.name)"
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


def filter_firewall_access_proxy6_data(json):
    option_list = [
        "add_vhost_domain_to_dnsdb",
        "api_gateway",
        "api_gateway6",
        "auth_portal",
        "auth_virtual_host",
        "client_cert",
        "decrypted_traffic_mirror",
        "empty_cert_action",
        "http_supported_max_version",
        "log_blocked_traffic",
        "name",
        "svr_pool_multiplex",
        "svr_pool_server_max_concurrent_request",
        "svr_pool_server_max_request",
        "svr_pool_ttl",
        "user_agent_detect",
        "vip",
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
        ["api_gateway", "ssl_cipher_suites", "versions"],
        ["api_gateway6", "ssl_cipher_suites", "versions"],
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


def firewall_access_proxy6(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_access_proxy6_data = data["firewall_access_proxy6"]

    filtered_data = filter_firewall_access_proxy6_data(firewall_access_proxy6_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "access-proxy6", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "access-proxy6", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_access_proxy6"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "access-proxy6",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "access-proxy6", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "access-proxy6", mkey=converted_data["name"], vdom=vdom
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

    if data["firewall_access_proxy6"]:
        resp = firewall_access_proxy6(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_access_proxy6"))
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
        "name": {"v_range": [["v7.0.1", ""]], "type": "string", "required": True},
        "vip": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "auth_portal": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auth_virtual_host": {"v_range": [["v7.0.4", ""]], "type": "string"},
        "log_blocked_traffic": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "add_vhost_domain_to_dnsdb": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "svr_pool_multiplex": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "svr_pool_ttl": {"v_range": [["v7.2.4", ""]], "type": "integer"},
        "svr_pool_server_max_request": {"v_range": [["v7.2.4", ""]], "type": "integer"},
        "svr_pool_server_max_concurrent_request": {
            "v_range": [["v7.4.1", ""]],
            "type": "integer",
        },
        "decrypted_traffic_mirror": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "api_gateway": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "integer",
                    "required": True,
                },
                "url_map": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "service": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "http"},
                        {"value": "https"},
                        {"value": "tcp-forwarding"},
                        {"value": "samlsp"},
                        {"value": "web-portal", "v_range": [["v7.0.4", ""]]},
                        {"value": "saas", "v_range": [["v7.2.1", ""]]},
                    ],
                },
                "ldb_method": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "static"},
                        {"value": "round-robin"},
                        {"value": "weighted"},
                        {"value": "first-alive"},
                        {"value": "http-host"},
                    ],
                },
                "virtual_host": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "url_map_type": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "sub-string"},
                        {"value": "wildcard"},
                        {"value": "regex"},
                    ],
                },
                "h2_support": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "h3_support": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "quic": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "dict",
                    "children": {
                        "max_idle_timeout": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "max_udp_payload_size": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "active_connection_id_limit": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "ack_delay_exponent": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "max_ack_delay": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "max_datagram_frame_size": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "active_migration": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "grease_quic_bit": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                },
                "realservers": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "addr_type": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "string",
                            "options": [{"value": "ip"}, {"value": "fqdn"}],
                        },
                        "address": {"v_range": [["v7.0.1", ""]], "type": "string"},
                        "ip": {"v_range": [["v7.0.1", ""]], "type": "string"},
                        "domain": {"v_range": [["v7.0.4", ""]], "type": "string"},
                        "port": {"v_range": [["v7.0.1", ""]], "type": "integer"},
                        "mappedport": {"v_range": [["v7.0.1", ""]], "type": "string"},
                        "status": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "active"},
                                {"value": "standby"},
                                {"value": "disable"},
                            ],
                        },
                        "type": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "tcp-forwarding"}, {"value": "ssh"}],
                        },
                        "external_auth": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tunnel_encryption": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "weight": {"v_range": [["v7.0.1", ""]], "type": "integer"},
                        "http_host": {"v_range": [["v7.0.1", ""]], "type": "string"},
                        "health_check": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "health_check_proto": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "ping"},
                                {"value": "http"},
                                {"value": "tcp-connect"},
                            ],
                        },
                        "holddown_interval": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "translate_host": {
                            "v_range": [["v7.2.4", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "ssh_client_cert": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                        },
                        "ssh_host_key_validation": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "ssh_host_key": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v7.0.1", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v7.0.1", ""]],
                        },
                        "verify_cert": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                    "v_range": [["v7.0.1", ""]],
                },
                "application": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.2.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.1", ""]],
                },
                "persistence": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "http-cookie"}],
                },
                "http_cookie_domain_from_host": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "http_cookie_domain": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "http_cookie_path": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "http_cookie_generation": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "integer",
                },
                "http_cookie_age": {"v_range": [["v7.0.1", ""]], "type": "integer"},
                "http_cookie_share": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "same-ip"}],
                },
                "https_cookie_secure": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "saml_server": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "saml_redirect": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "ssl_dh_bits": {
                    "v_range": [["v7.0.1", ""]],
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
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "high"},
                        {"value": "medium"},
                        {"value": "low"},
                    ],
                },
                "ssl_cipher_suites": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "priority": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "cipher": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "TLS-AES-128-GCM-SHA256"},
                                {"value": "TLS-AES-256-GCM-SHA384"},
                                {"value": "TLS-CHACHA20-POLY1305-SHA256"},
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"
                                },
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
                            "v_range": [["v7.0.1", ""]],
                            "type": "list",
                            "options": [
                                {"value": "tls-1.0"},
                                {"value": "tls-1.1"},
                                {"value": "tls-1.2"},
                                {"value": "tls-1.3"},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                    },
                    "v_range": [["v7.0.1", ""]],
                },
                "ssl_min_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3"},
                    ],
                },
                "ssl_max_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3"},
                    ],
                },
                "ssl_renegotiation": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ssl_vpn_web_portal": {"v_range": [["v7.0.4", ""]], "type": "string"},
            },
            "v_range": [["v7.0.1", ""]],
        },
        "api_gateway6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "integer",
                    "required": True,
                },
                "url_map": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "service": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "http"},
                        {"value": "https"},
                        {"value": "tcp-forwarding"},
                        {"value": "samlsp"},
                        {"value": "web-portal", "v_range": [["v7.0.4", ""]]},
                        {"value": "saas", "v_range": [["v7.2.1", ""]]},
                    ],
                },
                "ldb_method": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "static"},
                        {"value": "round-robin"},
                        {"value": "weighted"},
                        {"value": "first-alive"},
                        {"value": "http-host"},
                    ],
                },
                "virtual_host": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "url_map_type": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "sub-string"},
                        {"value": "wildcard"},
                        {"value": "regex"},
                    ],
                },
                "h2_support": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "h3_support": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "quic": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "dict",
                    "children": {
                        "max_idle_timeout": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "max_udp_payload_size": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "active_connection_id_limit": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "ack_delay_exponent": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "max_ack_delay": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "max_datagram_frame_size": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "integer",
                        },
                        "active_migration": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "grease_quic_bit": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                },
                "realservers": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "addr_type": {
                            "v_range": [["v7.0.2", ""]],
                            "type": "string",
                            "options": [{"value": "ip"}, {"value": "fqdn"}],
                        },
                        "address": {"v_range": [["v7.0.1", ""]], "type": "string"},
                        "ip": {"v_range": [["v7.0.1", ""]], "type": "string"},
                        "domain": {"v_range": [["v7.0.4", ""]], "type": "string"},
                        "port": {"v_range": [["v7.0.1", ""]], "type": "integer"},
                        "mappedport": {"v_range": [["v7.0.1", ""]], "type": "string"},
                        "status": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "active"},
                                {"value": "standby"},
                                {"value": "disable"},
                            ],
                        },
                        "type": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "tcp-forwarding"}, {"value": "ssh"}],
                        },
                        "external_auth": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tunnel_encryption": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "weight": {"v_range": [["v7.0.1", ""]], "type": "integer"},
                        "http_host": {"v_range": [["v7.0.1", ""]], "type": "string"},
                        "health_check": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "health_check_proto": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "ping"},
                                {"value": "http"},
                                {"value": "tcp-connect"},
                            ],
                        },
                        "holddown_interval": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "translate_host": {
                            "v_range": [["v7.2.4", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "ssh_client_cert": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                        },
                        "ssh_host_key_validation": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [{"value": "disable"}, {"value": "enable"}],
                        },
                        "ssh_host_key": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v7.0.1", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v7.0.1", ""]],
                        },
                        "verify_cert": {
                            "v_range": [["v7.6.3", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                    },
                    "v_range": [["v7.0.1", ""]],
                },
                "application": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.2.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.1", ""]],
                },
                "persistence": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "http-cookie"}],
                },
                "http_cookie_domain_from_host": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "http_cookie_domain": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "http_cookie_path": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "http_cookie_generation": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "integer",
                },
                "http_cookie_age": {"v_range": [["v7.0.1", ""]], "type": "integer"},
                "http_cookie_share": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "same-ip"}],
                },
                "https_cookie_secure": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "saml_server": {"v_range": [["v7.0.1", ""]], "type": "string"},
                "saml_redirect": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "ssl_dh_bits": {
                    "v_range": [["v7.0.1", ""]],
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
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "high"},
                        {"value": "medium"},
                        {"value": "low"},
                    ],
                },
                "ssl_cipher_suites": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "priority": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "integer",
                            "required": True,
                        },
                        "cipher": {
                            "v_range": [["v7.0.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "TLS-AES-128-GCM-SHA256"},
                                {"value": "TLS-AES-256-GCM-SHA384"},
                                {"value": "TLS-CHACHA20-POLY1305-SHA256"},
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"
                                },
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
                            "v_range": [["v7.0.1", ""]],
                            "type": "list",
                            "options": [
                                {"value": "tls-1.0"},
                                {"value": "tls-1.1"},
                                {"value": "tls-1.2"},
                                {"value": "tls-1.3"},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                    },
                    "v_range": [["v7.0.1", ""]],
                },
                "ssl_min_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3"},
                    ],
                },
                "ssl_max_version": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "options": [
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3"},
                    ],
                },
                "ssl_renegotiation": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ssl_vpn_web_portal": {"v_range": [["v7.0.4", ""]], "type": "string"},
            },
            "v_range": [["v7.0.1", ""]],
        },
        "client_cert": {
            "v_range": [["v7.0.1", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "user_agent_detect": {
            "v_range": [["v7.2.1", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "empty_cert_action": {
            "v_range": [["v7.0.1", "v7.6.0"]],
            "type": "string",
            "options": [
                {"value": "accept"},
                {"value": "block"},
                {"value": "accept-unmanageable", "v_range": [["v7.2.1", "v7.6.0"]]},
            ],
        },
        "http_supported_max_version": {
            "v_range": [["v7.2.4", "v7.4.0"]],
            "type": "string",
            "options": [{"value": "http1"}, {"value": "http2"}],
        },
    },
    "v_range": [["v7.0.1", ""]],
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
        "firewall_access_proxy6": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_access_proxy6"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_access_proxy6"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_access_proxy6"
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
