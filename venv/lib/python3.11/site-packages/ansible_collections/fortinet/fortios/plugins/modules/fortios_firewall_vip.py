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
module: fortios_firewall_vip
short_description: Configure virtual IP for IPv4 in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and vip category.
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
    firewall_vip:
        description:
            - Configure virtual IP for IPv4.
        default: null
        type: dict
        suboptions:
            add_nat46_route:
                description:
                    - Enable/disable adding NAT46 route.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            arp_reply:
                description:
                    - Enable to respond to ARP requests for this virtual IP address. Enabled by default.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            client_cert:
                description:
                    - Enable/disable requesting client certificate.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            color:
                description:
                    - Color of icon on the GUI.
                type: int
            comment:
                description:
                    - Comment.
                type: str
            dns_mapping_ttl:
                description:
                    - DNS mapping TTL (Set to zero to use TTL in DNS response).
                type: int
            empty_cert_action:
                description:
                    - Action for an empty client certificate.
                type: str
                choices:
                    - 'accept'
                    - 'block'
                    - 'accept-unmanageable'
            extaddr:
                description:
                    - External FQDN address name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            extintf:
                description:
                    - Interface connected to the source network that receives the packets that will be forwarded to the destination network. Source system
                      .interface.name.
                type: str
            extip:
                description:
                    - IP address or address range on the external interface that you want to map to an address or address range on the destination network.
                type: str
            extport:
                description:
                    - Incoming port number range that you want to map to a port number range on the destination network.
                type: str
            gratuitous_arp_interval:
                description:
                    - Enable to have the VIP send gratuitous ARPs. 0=disabled. Set from 5 up to 8640000 seconds to enable.
                type: int
            gslb_domain_name:
                description:
                    - Domain to use when integrating with FortiGSLB.
                type: str
            gslb_hostname:
                description:
                    - Hostname to use within the configured FortiGSLB domain.
                type: str
            gslb_public_ips:
                description:
                    - Publicly accessible IP addresses for the FortiGSLB service.
                type: list
                elements: dict
                suboptions:
                    index:
                        description:
                            - Index of this public IP setting. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip:
                        description:
                            - The publicly accessible IP address.
                        type: str
            h2_support:
                description:
                    - Enable/disable HTTP2 support .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            h3_support:
                description:
                    - Enable/disable HTTP3/QUIC support .
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
                    - Control sharing of cookies across virtual servers. Use of same-ip means a cookie from one virtual server can be used by another. Disable
                       stops cookie sharing.
                type: str
                choices:
                    - 'disable'
                    - 'same-ip'
            http_ip_header:
                description:
                    - For HTTP multiplexing, enable to add the original client IP address in the X-Forwarded-For HTTP header.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            http_ip_header_name:
                description:
                    - For HTTP multiplexing, enter a custom HTTPS header name. The original client IP address is added to this header. If empty,
                       X-Forwarded-For is used.
                type: str
            http_multiplex:
                description:
                    - Enable/disable HTTP multiplexing.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            http_multiplex_max_concurrent_request:
                description:
                    - Maximum number of concurrent requests that a multiplex server can handle .
                type: int
            http_multiplex_max_request:
                description:
                    - Maximum number of requests that a multiplex server can handle before disconnecting sessions .
                type: int
            http_multiplex_ttl:
                description:
                    - Time-to-live for idle connections to servers.
                type: int
            http_redirect:
                description:
                    - Enable/disable redirection of HTTP to HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            http_supported_max_version:
                description:
                    - Maximum supported HTTP versions. default = HTTP2
                type: str
                choices:
                    - 'http1'
                    - 'http2'
            https_cookie_secure:
                description:
                    - Enable/disable verification that inserted HTTPS cookies are secure.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            id:
                description:
                    - Custom defined ID.
                type: int
            ipv6_mappedip:
                description:
                    - Range of mapped IPv6 addresses. Specify the start IPv6 address followed by a space and the end IPv6 address.
                type: str
            ipv6_mappedport:
                description:
                    - IPv6 port number range on the destination network to which the external port number range is mapped.
                type: str
            ldb_method:
                description:
                    - Method used to distribute sessions to real servers.
                type: str
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'least-session'
                    - 'least-rtt'
                    - 'first-alive'
                    - 'http-host'
            mapped_addr:
                description:
                    - Mapped FQDN address name. Source firewall.address.name.
                type: str
            mappedip:
                description:
                    - IP address or address range on the destination network to which the external IP address is mapped.
                type: list
                elements: dict
                suboptions:
                    range:
                        description:
                            - Mapped IP range.
                        required: true
                        type: str
            mappedport:
                description:
                    - Port number range on the destination network to which the external port number range is mapped.
                type: str
            max_embryonic_connections:
                description:
                    - Maximum number of incomplete connections.
                type: int
            monitor:
                description:
                    - Name of the health check monitor to use when polling to determine a virtual server"s connectivity status.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Health monitor name. Source firewall.ldb-monitor.name.
                        required: true
                        type: str
            name:
                description:
                    - Virtual IP name.
                required: true
                type: str
            nat_source_vip:
                description:
                    - Enable/disable forcing the source NAT mapped IP to the external IP for all traffic.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            nat44:
                description:
                    - Enable/disable NAT44.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            nat46:
                description:
                    - Enable/disable NAT46.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            one_click_gslb_server:
                description:
                    - Enable/disable one click GSLB server integration with FortiGSLB.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            outlook_web_access:
                description:
                    - Enable to add the Front-End-Https header for Microsoft Outlook Web Access.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            persistence:
                description:
                    - Configure how to make sure that clients connect to the same server every time they make a request that is part of the same session.
                type: str
                choices:
                    - 'none'
                    - 'http-cookie'
                    - 'ssl-session-id'
            portforward:
                description:
                    - Enable/disable port forwarding.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            portmapping_type:
                description:
                    - Port mapping type.
                type: str
                choices:
                    - '1-to-1'
                    - 'm-to-n'
            protocol:
                description:
                    - Protocol to use when forwarding packets.
                type: str
                choices:
                    - 'tcp'
                    - 'udp'
                    - 'sctp'
                    - 'icmp'
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
                    - Select the real servers that this server load balancing VIP will distribute traffic to.
                type: list
                elements: dict
                suboptions:
                    address:
                        description:
                            - Dynamic address of the real server. Source firewall.address.name.
                        type: str
                    client_ip:
                        description:
                            - Only clients in this IP range can connect to this real server.
                        type: str
                    healthcheck:
                        description:
                            - Enable to check the responsiveness of the real server before forwarding traffic.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'vip'
                    holddown_interval:
                        description:
                            - Time in seconds that the system waits before re-activating a previously down active server in the active-standby mode. This is
                               to prevent any flapping issues.
                        type: int
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
                    max_connections:
                        description:
                            - Max number of active connections that can be directed to the real server. When reached, sessions are sent to other real servers.
                        type: int
                    monitor:
                        description:
                            - Name of the health check monitor to use when polling to determine a virtual server"s connectivity status. Source firewall
                              .ldb-monitor.name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Health monitor name. Source firewall.ldb-monitor.name.
                                required: true
                                type: str
                    port:
                        description:
                            - Port for communicating with the real server. Required if port forwarding is enabled.
                        type: int
                    status:
                        description:
                            - Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is sent.
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
                    type:
                        description:
                            - Type of address.
                        type: str
                        choices:
                            - 'ip'
                            - 'address'
                    verify_cert:
                        description:
                            - Enable/disable certificate verification of the real server.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    weight:
                        description:
                            - Weight of the real server. If weighted load balancing is enabled, the server with the highest weight gets more connections.
                        type: int
            server_type:
                description:
                    - Protocol to be load balanced by the virtual server (also called the server load balance virtual IP).
                type: str
                choices:
                    - 'http'
                    - 'https'
                    - 'imaps'
                    - 'pop3s'
                    - 'smtps'
                    - 'ssl'
                    - 'tcp'
                    - 'udp'
                    - 'ip'
                    - 'ssh'
            service:
                description:
                    - Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
                        type: str
            src_filter:
                description:
                    - Source address filter. Each address must be either an IP/subnet (x.x.x.x/n) or a range (x.x.x.x-y.y.y.y). Separate addresses with spaces.
                type: list
                elements: dict
                suboptions:
                    range:
                        description:
                            - Source-filter range.
                        required: true
                        type: str
            src_vip_filter:
                description:
                    - Enable/disable use of "src-filter" to match destinations for the reverse SNAT rule.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            srcintf_filter:
                description:
                    - Interfaces to which the VIP applies. Separate the names with spaces.
                type: list
                elements: dict
                suboptions:
                    interface_name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
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
                    - The name of the certificate to use for SSL handshake. Source vpn.certificate.local.name.
                type: str
            ssl_certificate_dict:
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
                    - Maximum number of client to FortiGate SSL session states to keep.
                type: int
            ssl_client_session_state_timeout:
                description:
                    - Number of minutes to keep client to FortiGate SSL session state.
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
                    - Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
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
                    - Enable/disable VIP.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            type:
                description:
                    - Configure a static NAT, load balance, server load balance, access proxy, DNS translation, or FQDN VIP.
                type: str
                choices:
                    - 'static-nat'
                    - 'load-balance'
                    - 'server-load-balance'
                    - 'dns-translation'
                    - 'fqdn'
                    - 'access-proxy'
            user_agent_detect:
                description:
                    - Enable/disable detecting device type by HTTP user-agent if no client certificate is provided.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            weblogic_server:
                description:
                    - Enable to add an HTTP header to indicate SSL offloading for a WebLogic server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            websphere_server:
                description:
                    - Enable to add an HTTP header to indicate SSL offloading for a WebSphere server.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
"""

EXAMPLES = """
- name: Configure virtual IP for IPv4.
  fortinet.fortios.fortios_firewall_vip:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_vip:
          add_nat46_route: "disable"
          arp_reply: "disable"
          client_cert: "disable"
          color: "0"
          comment: "Comment."
          dns_mapping_ttl: "0"
          empty_cert_action: "accept"
          extaddr:
              -
                  name: "default_name_11 (source firewall.address.name firewall.addrgrp.name)"
          extintf: "<your_own_value> (source system.interface.name)"
          extip: "<your_own_value>"
          extport: "<your_own_value>"
          gratuitous_arp_interval: "0"
          gslb_domain_name: "<your_own_value>"
          gslb_hostname: "myhostname"
          gslb_public_ips:
              -
                  index: "<you_own_value>"
                  ip: "<your_own_value>"
          h2_support: "enable"
          h3_support: "enable"
          http_cookie_age: "60"
          http_cookie_domain: "<your_own_value>"
          http_cookie_domain_from_host: "disable"
          http_cookie_generation: "0"
          http_cookie_path: "<your_own_value>"
          http_cookie_share: "disable"
          http_ip_header: "enable"
          http_ip_header_name: "<your_own_value>"
          http_multiplex: "enable"
          http_multiplex_max_concurrent_request: "0"
          http_multiplex_max_request: "0"
          http_multiplex_ttl: "15"
          http_redirect: "enable"
          http_supported_max_version: "http1"
          https_cookie_secure: "disable"
          id: "38"
          ipv6_mappedip: "<your_own_value>"
          ipv6_mappedport: "<your_own_value>"
          ldb_method: "static"
          mapped_addr: "<your_own_value> (source firewall.address.name)"
          mappedip:
              -
                  range: "<your_own_value>"
          mappedport: "<your_own_value>"
          max_embryonic_connections: "1000"
          monitor:
              -
                  name: "default_name_48 (source firewall.ldb-monitor.name)"
          name: "default_name_49"
          nat_source_vip: "disable"
          nat44: "disable"
          nat46: "disable"
          one_click_gslb_server: "disable"
          outlook_web_access: "disable"
          persistence: "none"
          portforward: "disable"
          portmapping_type: "1-to-1"
          protocol: "tcp"
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
                  address: "<your_own_value> (source firewall.address.name)"
                  client_ip: "<your_own_value>"
                  healthcheck: "disable"
                  holddown_interval: "300"
                  http_host: "myhostname"
                  id: "74"
                  ip: "<your_own_value>"
                  max_connections: "0"
                  monitor:
                      -
                          name: "default_name_78 (source firewall.ldb-monitor.name)"
                  port: "0"
                  status: "active"
                  translate_host: "enable"
                  type: "ip"
                  verify_cert: "enable"
                  weight: "1"
          server_type: "http"
          service:
              -
                  name: "default_name_87 (source firewall.service.custom.name firewall.service.group.name)"
          src_filter:
              -
                  range: "<your_own_value>"
          src_vip_filter: "disable"
          srcintf_filter:
              -
                  interface_name: "<your_own_value> (source system.interface.name)"
          ssl_accept_ffdhe_groups: "enable"
          ssl_algorithm: "high"
          ssl_certificate: "<your_own_value> (source vpn.certificate.local.name)"
          ssl_certificate_dict:
              -
                  name: "default_name_97 (source vpn.certificate.local.name)"
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
          status: "disable"
          type: "static-nat"
          user_agent_detect: "disable"
          uuid: "<your_own_value>"
          weblogic_server: "disable"
          websphere_server: "disable"
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


def filter_firewall_vip_data(json):
    option_list = [
        "add_nat46_route",
        "arp_reply",
        "client_cert",
        "color",
        "comment",
        "dns_mapping_ttl",
        "empty_cert_action",
        "extaddr",
        "extintf",
        "extip",
        "extport",
        "gratuitous_arp_interval",
        "gslb_domain_name",
        "gslb_hostname",
        "gslb_public_ips",
        "h2_support",
        "h3_support",
        "http_cookie_age",
        "http_cookie_domain",
        "http_cookie_domain_from_host",
        "http_cookie_generation",
        "http_cookie_path",
        "http_cookie_share",
        "http_ip_header",
        "http_ip_header_name",
        "http_multiplex",
        "http_multiplex_max_concurrent_request",
        "http_multiplex_max_request",
        "http_multiplex_ttl",
        "http_redirect",
        "http_supported_max_version",
        "https_cookie_secure",
        "id",
        "ipv6_mappedip",
        "ipv6_mappedport",
        "ldb_method",
        "mapped_addr",
        "mappedip",
        "mappedport",
        "max_embryonic_connections",
        "monitor",
        "name",
        "nat_source_vip",
        "nat44",
        "nat46",
        "one_click_gslb_server",
        "outlook_web_access",
        "persistence",
        "portforward",
        "portmapping_type",
        "protocol",
        "quic",
        "realservers",
        "server_type",
        "service",
        "src_filter",
        "src_vip_filter",
        "srcintf_filter",
        "ssl_accept_ffdhe_groups",
        "ssl_algorithm",
        "ssl_certificate",
        "ssl_certificate_dict",
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
        "type",
        "user_agent_detect",
        "uuid",
        "weblogic_server",
        "websphere_server",
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


def remap_attribute_name(data):
    speciallist = {"ssl-certificate-dict": "ssl-certificate"}

    if data in speciallist:
        return speciallist[data]
    return data


def remap_attribute_names(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = remap_attribute_names(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[remap_attribute_name(k)] = remap_attribute_names(v)
        data = new_data

    return data


def firewall_vip(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_vip_data = data["firewall_vip"]

    filtered_data = filter_firewall_vip_data(firewall_vip_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)
    converted_data = remap_attribute_names(converted_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "vip", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "vip", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_vip"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "vip",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "vip", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("firewall", "vip", mkey=converted_data["name"], vdom=vdom)
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

    if data["firewall_vip"]:
        resp = firewall_vip(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_vip"))
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
        "id": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "uuid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "static-nat"},
                {"value": "load-balance"},
                {"value": "server-load-balance"},
                {"value": "dns-translation"},
                {"value": "fqdn"},
                {"value": "access-proxy", "v_range": [["v7.0.0", ""]]},
            ],
        },
        "server_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "http"},
                {"value": "https"},
                {"value": "imaps"},
                {"value": "pop3s"},
                {"value": "smtps"},
                {"value": "ssl"},
                {"value": "tcp"},
                {"value": "udp"},
                {"value": "ip"},
                {"value": "ssh", "v_range": [["v7.0.0", "v7.0.0"]]},
            ],
        },
        "dns_mapping_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ldb_method": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "static"},
                {"value": "round-robin"},
                {"value": "weighted"},
                {"value": "least-session"},
                {"value": "least-rtt"},
                {"value": "first-alive"},
                {"value": "http-host"},
            ],
        },
        "src_filter": {
            "type": "list",
            "elements": "dict",
            "children": {
                "range": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "src_vip_filter": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "service": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "extip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "extaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
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
                "max_idle_timeout": {"v_range": [["v7.4.1", ""]], "type": "integer"},
                "max_udp_payload_size": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "integer",
                },
                "active_connection_id_limit": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "integer",
                },
                "ack_delay_exponent": {"v_range": [["v7.4.1", ""]], "type": "integer"},
                "max_ack_delay": {"v_range": [["v7.4.1", ""]], "type": "integer"},
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
        "nat44": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "nat46": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "add_nat46_route": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "mappedip": {
            "type": "list",
            "elements": "dict",
            "children": {
                "range": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "mapped_addr": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "extintf": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "arp_reply": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "http_redirect": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "persistence": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "http-cookie"},
                {"value": "ssl-session-id"},
            ],
        },
        "nat_source_vip": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "portforward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "status": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "protocol": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "tcp"},
                {"value": "udp"},
                {"value": "sctp"},
                {"value": "icmp"},
            ],
        },
        "extport": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "mappedport": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "gratuitous_arp_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "srcintf_filter": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface_name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "portmapping_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "1-to-1"}, {"value": "m-to-n"}],
        },
        "empty_cert_action": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [
                {"value": "accept"},
                {"value": "block"},
                {"value": "accept-unmanageable"},
            ],
        },
        "user_agent_detect": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "client_cert": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "realservers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "type": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "ip"}, {"value": "address"}],
                },
                "address": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "active"},
                        {"value": "standby"},
                        {"value": "disable"},
                    ],
                },
                "weight": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "holddown_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "healthcheck": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "enable"},
                        {"value": "vip"},
                    ],
                },
                "http_host": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "translate_host": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "max_connections": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "monitor": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", ""]],
                },
                "client_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "verify_cert": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "http_cookie_domain_from_host": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "http_cookie_domain": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "http_cookie_path": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "http_cookie_generation": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "http_cookie_age": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "http_cookie_share": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "same-ip"}],
        },
        "https_cookie_secure": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "http_multiplex": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "http_multiplex_ttl": {"v_range": [["v7.2.4", ""]], "type": "integer"},
        "http_multiplex_max_request": {"v_range": [["v7.2.4", ""]], "type": "integer"},
        "http_multiplex_max_concurrent_request": {
            "v_range": [["v7.4.1", ""]],
            "type": "integer",
        },
        "http_ip_header": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "http_ip_header_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "outlook_web_access": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "weblogic_server": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "websphere_server": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "half"}, {"value": "full"}],
        },
        "ssl_certificate_dict": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.2", ""]],
        },
        "ssl_dh_bits": {
            "v_range": [["v6.0.0", ""]],
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
            "v_range": [["v6.0.0", ""]],
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
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "cipher": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {
                            "value": "TLS-AES-128-GCM-SHA256",
                            "v_range": [["v6.2.0", ""]],
                        },
                        {
                            "value": "TLS-AES-256-GCM-SHA384",
                            "v_range": [["v6.2.0", ""]],
                        },
                        {
                            "value": "TLS-CHACHA20-POLY1305-SHA256",
                            "v_range": [["v6.2.0", ""]],
                        },
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
                        {
                            "value": "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA",
                            "v_range": [["v7.0.1", ""]],
                        },
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
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "ssl-3.0"},
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3", "v_range": [["v6.2.0", ""]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ssl_server_algorithm": {
            "v_range": [["v6.0.0", ""]],
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
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "cipher": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {
                            "value": "TLS-AES-128-GCM-SHA256",
                            "v_range": [["v6.2.0", ""]],
                        },
                        {
                            "value": "TLS-AES-256-GCM-SHA384",
                            "v_range": [["v6.2.0", ""]],
                        },
                        {
                            "value": "TLS-CHACHA20-POLY1305-SHA256",
                            "v_range": [["v6.2.0", ""]],
                        },
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
                        {
                            "value": "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA",
                            "v_range": [["v7.0.1", ""]],
                        },
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
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "ssl-3.0"},
                        {"value": "tls-1.0"},
                        {"value": "tls-1.1"},
                        {"value": "tls-1.2"},
                        {"value": "tls-1.3", "v_range": [["v6.2.0", ""]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "ssl_pfs": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "require"}, {"value": "deny"}, {"value": "allow"}],
        },
        "ssl_min_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3", "v_range": [["v6.2.0", ""]]},
            ],
        },
        "ssl_max_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3", "v_range": [["v6.2.0", ""]]},
            ],
        },
        "ssl_server_min_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3", "v_range": [["v6.2.0", ""]]},
                {"value": "client"},
            ],
        },
        "ssl_server_max_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3", "v_range": [["v6.2.0", ""]]},
                {"value": "client"},
            ],
        },
        "ssl_accept_ffdhe_groups": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_send_empty_frags": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_client_fallback": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_client_renegotiation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}, {"value": "secure"}],
        },
        "ssl_client_session_state_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "time"},
                {"value": "count"},
                {"value": "both"},
            ],
        },
        "ssl_client_session_state_timeout": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "ssl_client_session_state_max": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "ssl_client_rekey_count": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "ssl_server_renegotiation": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_server_session_state_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "time"},
                {"value": "count"},
                {"value": "both"},
            ],
        },
        "ssl_server_session_state_timeout": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "ssl_server_session_state_max": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "ssl_http_location_conversion": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_http_match_host": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_hpkp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "enable"},
                {"value": "report-only"},
            ],
        },
        "ssl_hpkp_primary": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssl_hpkp_backup": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssl_hpkp_age": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ssl_hpkp_report_uri": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssl_hpkp_include_subdomains": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_hsts": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_hsts_age": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ssl_hsts_include_subdomains": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "monitor": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "max_embryonic_connections": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "color": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ipv6_mappedip": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "ipv6_mappedport": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "one_click_gslb_server": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "gslb_hostname": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "gslb_domain_name": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "gslb_public_ips": {
            "type": "list",
            "elements": "dict",
            "children": {
                "index": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                    "required": True,
                },
                "ip": {"v_range": [["v7.4.2", ""]], "type": "string"},
            },
            "v_range": [["v7.4.2", ""]],
        },
        "ssl_certificate": {"v_range": [["v6.0.0", "v7.4.1"]], "type": "string"},
        "http_supported_max_version": {
            "v_range": [["v7.2.4", "v7.4.0"]],
            "type": "string",
            "options": [{"value": "http1"}, {"value": "http2"}],
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
        "firewall_vip": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_vip"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_vip"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_vip"
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
