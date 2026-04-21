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
module: fortios_vpn_ssl_settings
short_description: Configure Agentless VPN in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_ssl feature and settings category.
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

    vpn_ssl_settings:
        description:
            - Configure Agentless VPN.
        default: null
        type: dict
        suboptions:
            algorithm:
                description:
                    - Force the Agentless VPN security level. High allows only high. Medium allows medium and high. Low allows any.
                type: str
                choices:
                    - 'high'
                    - 'medium'
                    - 'default'
                    - 'low'
            auth_session_check_source_ip:
                description:
                    - Enable/disable checking of source IP for authentication session.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_timeout:
                description:
                    - Agentless VPN authentication timeout (1 - 259200 sec (3 days), 0 for no timeout).
                type: int
            authentication_rule:
                description:
                    - Authentication rule for Agentless VPN.
                type: list
                elements: dict
                suboptions:
                    auth:
                        description:
                            - Agentless VPN authentication method restriction.
                        type: str
                        choices:
                            - 'any'
                            - 'local'
                            - 'radius'
                            - 'tacacs+'
                            - 'ldap'
                            - 'peer'
                    cipher:
                        description:
                            - Agentless VPN cipher strength.
                        type: str
                        choices:
                            - 'any'
                            - 'high'
                            - 'medium'
                    client_cert:
                        description:
                            - Enable/disable Agentless VPN client certificate restrictive.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    groups:
                        description:
                            - User groups.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Group name. Source user.group.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID (0 - 4294967295). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    portal:
                        description:
                            - Agentless VPN portal. Source vpn.ssl.web.portal.name.
                        type: str
                    realm:
                        description:
                            - Agentless VPN realm. Source vpn.ssl.web.realm.url-path.
                        type: str
                    source_address:
                        description:
                            - Source address of incoming traffic.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address name. Source firewall.address.name firewall.addrgrp.name system.external-resource.name.
                                required: true
                                type: str
                    source_address_negate:
                        description:
                            - Enable/disable negated source address match.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    source_address6:
                        description:
                            - IPv6 source address of incoming traffic.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - IPv6 address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
                                required: true
                                type: str
                    source_address6_negate:
                        description:
                            - Enable/disable negated source IPv6 address match.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    source_interface:
                        description:
                            - Agentless VPN source interface of incoming traffic.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface name. Source system.interface.name system.zone.name.
                                required: true
                                type: str
                    user_peer:
                        description:
                            - Name of user peer. Source user.peer.name.
                        type: str
                    users:
                        description:
                            - User name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - User name. Source user.local.name.
                                required: true
                                type: str
            auto_tunnel_static_route:
                description:
                    - Enable/disable to auto-create static routes for the SSL-VPN tunnel IP addresses.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            banned_cipher:
                description:
                    - Select one or more cipher technologies that cannot be used in Agentless VPN negotiations. Only applies to TLS 1.2 and below.
                type: list
                elements: str
                choices:
                    - 'RSA'
                    - 'DHE'
                    - 'ECDHE'
                    - 'DSS'
                    - 'ECDSA'
                    - 'AES'
                    - 'AESGCM'
                    - 'CAMELLIA'
                    - '3DES'
                    - 'SHA1'
                    - 'SHA256'
                    - 'SHA384'
                    - 'STATIC'
                    - 'CHACHA20'
                    - 'ARIA'
                    - 'AESCCM'
                    - 'DH'
                    - 'ECDH'
            browser_language_detection:
                description:
                    - Enable/disable overriding the configured system language based on the preferred language of the browser.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            check_referer:
                description:
                    - Enable/disable verification of referer field in HTTP request header.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ciphersuite:
                description:
                    - Select one or more TLS 1.3 ciphersuites to enable. Does not affect ciphers in TLS 1.2 and below. At least one must be enabled. To
                       disable all, set ssl-max-proto-ver to tls1-2 or below.
                type: list
                elements: str
                choices:
                    - 'TLS-AES-128-GCM-SHA256'
                    - 'TLS-AES-256-GCM-SHA384'
                    - 'TLS-CHACHA20-POLY1305-SHA256'
                    - 'TLS-AES-128-CCM-SHA256'
                    - 'TLS-AES-128-CCM-8-SHA256'
            client_sigalgs:
                description:
                    - Set signature algorithms related to client authentication. Affects TLS version <= 1.2 only.
                type: str
                choices:
                    - 'no-rsa-pss'
                    - 'all'
            default_portal:
                description:
                    - Default Agentless VPN portal. Source vpn.ssl.web.portal.name.
                type: str
            deflate_compression_level:
                description:
                    - Compression level (0~9).
                type: int
            deflate_min_data_size:
                description:
                    - Minimum amount of data that triggers compression (200 - 65535 bytes).
                type: int
            dns_server1:
                description:
                    - DNS server 1.
                type: str
            dns_server2:
                description:
                    - DNS server 2.
                type: str
            dns_suffix:
                description:
                    - DNS suffix used for Agentless VPN clients.
                type: str
            dtls_heartbeat_fail_count:
                description:
                    - Number of missing heartbeats before the connection is considered dropped.
                type: int
            dtls_heartbeat_idle_timeout:
                description:
                    - Idle timeout before DTLS heartbeat is sent.
                type: int
            dtls_heartbeat_interval:
                description:
                    - Interval between DTLS heartbeat.
                type: int
            dtls_hello_timeout:
                description:
                    - SSLVPN maximum DTLS hello timeout (10 - 60 sec).
                type: int
            dtls_max_proto_ver:
                description:
                    - DTLS maximum protocol version.
                type: str
                choices:
                    - 'dtls1-0'
                    - 'dtls1-2'
            dtls_min_proto_ver:
                description:
                    - DTLS minimum protocol version.
                type: str
                choices:
                    - 'dtls1-0'
                    - 'dtls1-2'
            dtls_tunnel:
                description:
                    - Enable/disable DTLS to prevent eavesdropping, tampering, or message forgery.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dual_stack_mode:
                description:
                    - 'Agentless web mode: support IPv4 and IPv6 bookmarks in the portal.'
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            encode_2f_sequence:
                description:
                    - Encode 2F sequence to forward slash in URLs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            encrypt_and_store_password:
                description:
                    - Encrypt and store user passwords for Agentless VPN web sessions.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            force_two_factor_auth:
                description:
                    - Enable/disable only PKI users with two-factor authentication for Agentless VPNs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            header_x_forwarded_for:
                description:
                    - Forward the same, add, or remove HTTP header.
                type: str
                choices:
                    - 'pass'
                    - 'add'
                    - 'remove'
            hsts_include_subdomains:
                description:
                    - Add HSTS includeSubDomains response header.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            http_compression:
                description:
                    - Enable/disable to allow HTTP compression over Agentless VPN connections.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            http_only_cookie:
                description:
                    - Enable/disable Agentless VPN support for HttpOnly cookies.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            http_request_body_timeout:
                description:
                    - Agentless VPN session is disconnected if an HTTP request body is not received within this time (1 - 60 sec).
                type: int
            http_request_header_timeout:
                description:
                    - Agentless VPN session is disconnected if an HTTP request header is not received within this time (1 - 60 sec).
                type: int
            https_redirect:
                description:
                    - Enable/disable redirect of port 80 to Agentless VPN port.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            idle_timeout:
                description:
                    - Agentless VPN disconnects if idle for specified time in seconds.
                type: int
            ipv6_dns_server1:
                description:
                    - IPv6 DNS server 1.
                type: str
            ipv6_dns_server2:
                description:
                    - IPv6 DNS server 2.
                type: str
            ipv6_wins_server1:
                description:
                    - IPv6 WINS server 1.
                type: str
            ipv6_wins_server2:
                description:
                    - IPv6 WINS server 2.
                type: str
            login_attempt_limit:
                description:
                    - Agentless VPN maximum login attempt times before block (0 - 10).
                type: int
            login_block_time:
                description:
                    - Time for which a user is blocked from logging in after too many failed login attempts (0 - 86400 sec).
                type: int
            login_timeout:
                description:
                    - Agentless VPN maximum login timeout (10 - 180 sec).
                type: int
            port:
                description:
                    - Agentless VPN access port (1 - 65535).
                type: int
            port_precedence:
                description:
                    - Enable/disable, Enable means that if Agentless VPN connections are allowed on an interface admin GUI connections are blocked on that
                       interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            reqclientcert:
                description:
                    - Enable/disable to require client certificates for all Agentless VPN users.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            route_source_interface:
                description:
                    - Enable to allow SSL-VPN sessions to bypass routing and bind to the incoming interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            saml_redirect_port:
                description:
                    - SAML local redirect port in the machine running FortiClient (0 - 65535). 0 is to disable redirection on FGT side.
                type: int
            server_hostname:
                description:
                    - Server hostname for HTTPS. When set, will be used for Agentless VPN web proxy host header for any redirection.
                type: str
            servercert:
                description:
                    - Name of the server certificate to be used for Agentless VPNs. Source vpn.certificate.local.name.
                type: str
            source_address:
                description:
                    - Source address of incoming traffic.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name system.external-resource.name.
                        required: true
                        type: str
            source_address_negate:
                description:
                    - Enable/disable negated source address match.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            source_address6:
                description:
                    - IPv6 source address of incoming traffic.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IPv6 address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
                        required: true
                        type: str
            source_address6_negate:
                description:
                    - Enable/disable negated source IPv6 address match.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            source_interface:
                description:
                    - Agentless VPN source interface of incoming traffic.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name.
                        required: true
                        type: str
            ssl_client_renegotiation:
                description:
                    - Enable/disable to allow client renegotiation by the server if the tunnel goes down.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssl_insert_empty_fragment:
                description:
                    - Enable/disable insertion of empty fragment.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_max_proto_ver:
                description:
                    - SSL maximum protocol version.
                type: str
                choices:
                    - 'tls1-0'
                    - 'tls1-1'
                    - 'tls1-2'
                    - 'tls1-3'
            ssl_min_proto_ver:
                description:
                    - SSL minimum protocol version.
                type: str
                choices:
                    - 'tls1-0'
                    - 'tls1-1'
                    - 'tls1-2'
                    - 'tls1-3'
            status:
                description:
                    - Enable/disable Agentless VPN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tlsv1_0:
                description:
                    - tlsv1-0
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tlsv1_1:
                description:
                    - tlsv1-1
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tlsv1_2:
                description:
                    - tlsv1-2
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tlsv1_3:
                description:
                    - tlsv1-3
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            transform_backward_slashes:
                description:
                    - Transform backward slashes to forward slashes in URLs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tunnel_addr_assigned_method:
                description:
                    - Method used for assigning address for tunnel.
                type: str
                choices:
                    - 'first-available'
                    - 'round-robin'
            tunnel_connect_without_reauth:
                description:
                    - Enable/disable tunnel connection without re-authorization if previous connection dropped.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tunnel_ip_pools:
                description:
                    - Names of the IPv4 IP Pool firewall objects that define the IP addresses reserved for remote clients.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            tunnel_ipv6_pools:
                description:
                    - Names of the IPv6 IP Pool firewall objects that define the IP addresses reserved for remote clients.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            tunnel_user_session_timeout:
                description:
                    - Number of seconds after which user sessions are cleaned up after tunnel connection is dropped (1 - 86400).
                type: int
            unsafe_legacy_renegotiation:
                description:
                    - Enable/disable unsafe legacy re-negotiation.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            url_obscuration:
                description:
                    - Enable/disable to obscure the host name of the URL of the web browser display.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            user_peer:
                description:
                    - Name of user peer. Source user.peer.name.
                type: str
            web_mode_snat:
                description:
                    - Enable/disable use of IP pools defined in firewall policy while using web-mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wins_server1:
                description:
                    - WINS server 1.
                type: str
            wins_server2:
                description:
                    - WINS server 2.
                type: str
            x_content_type_options:
                description:
                    - Add HTTP X-Content-Type-Options header.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ztna_trusted_client:
                description:
                    - Enable/disable verification of device certificate for SSLVPN ZTNA session.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure Agentless VPN.
  fortinet.fortios.fortios_vpn_ssl_settings:
      vdom: "{{ vdom }}"
      vpn_ssl_settings:
          algorithm: "high"
          auth_session_check_source_ip: "enable"
          auth_timeout: "28800"
          authentication_rule:
              -
                  auth: "any"
                  cipher: "any"
                  client_cert: "enable"
                  groups:
                      -
                          name: "default_name_11 (source user.group.name)"
                  id: "12"
                  portal: "<your_own_value> (source vpn.ssl.web.portal.name)"
                  realm: "<your_own_value> (source vpn.ssl.web.realm.url-path)"
                  source_address:
                      -
                          name: "default_name_16 (source firewall.address.name firewall.addrgrp.name system.external-resource.name)"
                  source_address_negate: "enable"
                  source_address6:
                      -
                          name: "default_name_19 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
                  source_address6_negate: "enable"
                  source_interface:
                      -
                          name: "default_name_22 (source system.interface.name system.zone.name)"
                  user_peer: "<your_own_value> (source user.peer.name)"
                  users:
                      -
                          name: "default_name_25 (source user.local.name)"
          auto_tunnel_static_route: "enable"
          banned_cipher: "RSA"
          browser_language_detection: "enable"
          check_referer: "enable"
          ciphersuite: "TLS-AES-128-GCM-SHA256"
          client_sigalgs: "no-rsa-pss"
          default_portal: "<your_own_value> (source vpn.ssl.web.portal.name)"
          deflate_compression_level: "6"
          deflate_min_data_size: "300"
          dns_server1: "<your_own_value>"
          dns_server2: "<your_own_value>"
          dns_suffix: "<your_own_value>"
          dtls_heartbeat_fail_count: "3"
          dtls_heartbeat_idle_timeout: "3"
          dtls_heartbeat_interval: "3"
          dtls_hello_timeout: "10"
          dtls_max_proto_ver: "dtls1-0"
          dtls_min_proto_ver: "dtls1-0"
          dtls_tunnel: "enable"
          dual_stack_mode: "enable"
          encode_2f_sequence: "enable"
          encrypt_and_store_password: "enable"
          force_two_factor_auth: "enable"
          header_x_forwarded_for: "pass"
          hsts_include_subdomains: "enable"
          http_compression: "enable"
          http_only_cookie: "enable"
          http_request_body_timeout: "30"
          http_request_header_timeout: "20"
          https_redirect: "enable"
          idle_timeout: "300"
          ipv6_dns_server1: "<your_own_value>"
          ipv6_dns_server2: "<your_own_value>"
          ipv6_wins_server1: "<your_own_value>"
          ipv6_wins_server2: "<your_own_value>"
          login_attempt_limit: "2"
          login_block_time: "60"
          login_timeout: "30"
          port: "10443"
          port_precedence: "enable"
          reqclientcert: "enable"
          route_source_interface: "enable"
          saml_redirect_port: "8020"
          server_hostname: "myhostname"
          servercert: "<your_own_value> (source vpn.certificate.local.name)"
          source_address:
              -
                  name: "default_name_72 (source firewall.address.name firewall.addrgrp.name system.external-resource.name)"
          source_address_negate: "enable"
          source_address6:
              -
                  name: "default_name_75 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
          source_address6_negate: "enable"
          source_interface:
              -
                  name: "default_name_78 (source system.interface.name system.zone.name)"
          ssl_client_renegotiation: "disable"
          ssl_insert_empty_fragment: "enable"
          ssl_max_proto_ver: "tls1-0"
          ssl_min_proto_ver: "tls1-0"
          status: "enable"
          tlsv1_0: "enable"
          tlsv1_1: "enable"
          tlsv1_2: "enable"
          tlsv1_3: "enable"
          transform_backward_slashes: "enable"
          tunnel_addr_assigned_method: "first-available"
          tunnel_connect_without_reauth: "enable"
          tunnel_ip_pools:
              -
                  name: "default_name_92 (source firewall.address.name firewall.addrgrp.name)"
          tunnel_ipv6_pools:
              -
                  name: "default_name_94 (source firewall.address6.name firewall.addrgrp6.name)"
          tunnel_user_session_timeout: "30"
          unsafe_legacy_renegotiation: "enable"
          url_obscuration: "enable"
          user_peer: "<your_own_value> (source user.peer.name)"
          web_mode_snat: "enable"
          wins_server1: "<your_own_value>"
          wins_server2: "<your_own_value>"
          x_content_type_options: "enable"
          ztna_trusted_client: "enable"
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


def filter_vpn_ssl_settings_data(json):
    option_list = [
        "algorithm",
        "auth_session_check_source_ip",
        "auth_timeout",
        "authentication_rule",
        "auto_tunnel_static_route",
        "banned_cipher",
        "browser_language_detection",
        "check_referer",
        "ciphersuite",
        "client_sigalgs",
        "default_portal",
        "deflate_compression_level",
        "deflate_min_data_size",
        "dns_server1",
        "dns_server2",
        "dns_suffix",
        "dtls_heartbeat_fail_count",
        "dtls_heartbeat_idle_timeout",
        "dtls_heartbeat_interval",
        "dtls_hello_timeout",
        "dtls_max_proto_ver",
        "dtls_min_proto_ver",
        "dtls_tunnel",
        "dual_stack_mode",
        "encode_2f_sequence",
        "encrypt_and_store_password",
        "force_two_factor_auth",
        "header_x_forwarded_for",
        "hsts_include_subdomains",
        "http_compression",
        "http_only_cookie",
        "http_request_body_timeout",
        "http_request_header_timeout",
        "https_redirect",
        "idle_timeout",
        "ipv6_dns_server1",
        "ipv6_dns_server2",
        "ipv6_wins_server1",
        "ipv6_wins_server2",
        "login_attempt_limit",
        "login_block_time",
        "login_timeout",
        "port",
        "port_precedence",
        "reqclientcert",
        "route_source_interface",
        "saml_redirect_port",
        "server_hostname",
        "servercert",
        "source_address",
        "source_address_negate",
        "source_address6",
        "source_address6_negate",
        "source_interface",
        "ssl_client_renegotiation",
        "ssl_insert_empty_fragment",
        "ssl_max_proto_ver",
        "ssl_min_proto_ver",
        "status",
        "tlsv1_0",
        "tlsv1_1",
        "tlsv1_2",
        "tlsv1_3",
        "transform_backward_slashes",
        "tunnel_addr_assigned_method",
        "tunnel_connect_without_reauth",
        "tunnel_ip_pools",
        "tunnel_ipv6_pools",
        "tunnel_user_session_timeout",
        "unsafe_legacy_renegotiation",
        "url_obscuration",
        "user_peer",
        "web_mode_snat",
        "wins_server1",
        "wins_server2",
        "x_content_type_options",
        "ztna_trusted_client",
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
        ["banned_cipher"],
        ["ciphersuite"],
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


def vpn_ssl_settings(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    vpn_ssl_settings_data = data["vpn_ssl_settings"]

    filtered_data = filter_vpn_ssl_settings_data(vpn_ssl_settings_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("vpn.ssl", "settings", filtered_data, vdom=vdom)
        current_data = fos.get("vpn.ssl", "settings", vdom=vdom, mkey=mkey)
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
    data_copy["vpn_ssl_settings"] = filtered_data
    fos.do_member_operation(
        "vpn.ssl",
        "settings",
        data_copy,
    )

    return fos.set("vpn.ssl", "settings", data=converted_data, vdom=vdom)


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


def fortios_vpn_ssl(data, fos, check_mode):

    if data["vpn_ssl_settings"]:
        resp = vpn_ssl_settings(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("vpn_ssl_settings"))
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
    "v_range": [["v6.0.0", ""]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "reqclientcert": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "user_peer": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "ssl_max_proto_ver": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "tls1-0"},
                {"value": "tls1-1"},
                {"value": "tls1-2"},
                {"value": "tls1-3"},
            ],
        },
        "ssl_min_proto_ver": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "tls1-0"},
                {"value": "tls1-1"},
                {"value": "tls1-2"},
                {"value": "tls1-3"},
            ],
        },
        "banned_cipher": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "RSA"},
                {"value": "DHE"},
                {"value": "ECDHE"},
                {"value": "DSS"},
                {"value": "ECDSA"},
                {"value": "AES"},
                {"value": "AESGCM"},
                {"value": "CAMELLIA"},
                {"value": "3DES"},
                {"value": "SHA1"},
                {"value": "SHA256"},
                {"value": "SHA384"},
                {"value": "STATIC"},
                {"value": "CHACHA20", "v_range": [["v7.0.0", ""]]},
                {"value": "ARIA", "v_range": [["v7.0.0", ""]]},
                {"value": "AESCCM", "v_range": [["v7.0.0", ""]]},
                {"value": "DH", "v_range": [["v6.0.0", "v6.0.11"]]},
                {"value": "ECDH", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ciphersuite": {
            "v_range": [["v7.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "TLS-AES-128-GCM-SHA256"},
                {"value": "TLS-AES-256-GCM-SHA384"},
                {"value": "TLS-CHACHA20-POLY1305-SHA256"},
                {"value": "TLS-AES-128-CCM-SHA256"},
                {"value": "TLS-AES-128-CCM-8-SHA256"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ssl_insert_empty_fragment": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "https_redirect": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "x_content_type_options": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_client_renegotiation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "force_two_factor_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "unsafe_legacy_renegotiation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "servercert": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "algorithm": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "high"},
                {"value": "medium"},
                {"value": "default"},
                {"value": "low"},
            ],
        },
        "idle_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "login_attempt_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "login_block_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "login_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dtls_hello_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dtls_heartbeat_idle_timeout": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "dtls_heartbeat_interval": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "dtls_heartbeat_fail_count": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "dns_suffix": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "url_obscuration": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "http_compression": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "http_only_cookie": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "deflate_compression_level": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "deflate_min_data_size": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "port_precedence": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "header_x_forwarded_for": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "add"}, {"value": "remove"}],
        },
        "source_interface": {
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
        "source_address": {
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
        "source_address_negate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "source_address6": {
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
        "source_address6_negate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "default_portal": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "authentication_rule": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "source_interface": {
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
                "source_address": {
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
                "source_address_negate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "source_address6": {
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
                "source_address6_negate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "users": {
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
                "groups": {
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
                "portal": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "realm": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "client_cert": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "user_peer": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "cipher": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "any"},
                        {"value": "high"},
                        {"value": "medium"},
                    ],
                },
                "auth": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "any"},
                        {"value": "local"},
                        {"value": "radius"},
                        {"value": "tacacs+"},
                        {"value": "ldap"},
                        {"value": "peer", "v_range": [["v7.0.1", ""]]},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "browser_language_detection": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "check_referer": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "http_request_header_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "http_request_body_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_session_check_source_ip": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "hsts_include_subdomains": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "transform_backward_slashes": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "encode_2f_sequence": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "encrypt_and_store_password": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "client_sigalgs": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "no-rsa-pss"}, {"value": "all"}],
        },
        "dual_stack_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "server_hostname": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "tunnel_ip_pools": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.6.2"]],
        },
        "tunnel_ipv6_pools": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v7.6.2"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v7.6.2"]],
        },
        "dns_server1": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "dns_server2": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "wins_server1": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "wins_server2": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "ipv6_dns_server1": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "ipv6_dns_server2": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "ipv6_wins_server1": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "ipv6_wins_server2": {"v_range": [["v6.0.0", "v7.6.2"]], "type": "string"},
        "auto_tunnel_static_route": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dtls_tunnel": {
            "v_range": [["v6.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dtls_max_proto_ver": {
            "v_range": [["v6.2.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "dtls1-0"}, {"value": "dtls1-2"}],
        },
        "dtls_min_proto_ver": {
            "v_range": [["v6.2.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "dtls1-0"}, {"value": "dtls1-2"}],
        },
        "tunnel_connect_without_reauth": {
            "v_range": [["v6.2.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tunnel_user_session_timeout": {
            "v_range": [["v6.2.0", "v7.6.2"]],
            "type": "integer",
        },
        "tunnel_addr_assigned_method": {
            "v_range": [["v7.0.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "first-available"}, {"value": "round-robin"}],
        },
        "saml_redirect_port": {"v_range": [["v7.0.1", "v7.6.2"]], "type": "integer"},
        "ztna_trusted_client": {
            "v_range": [["v7.2.1", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "web_mode_snat": {
            "v_range": [["v7.0.6", "v7.4.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tlsv1_0": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tlsv1_1": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tlsv1_2": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tlsv1_3": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "route_source_interface": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
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
        "vpn_ssl_settings": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_ssl_settings"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_ssl_settings"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "vpn_ssl_settings"
        )

        is_error, has_changed, result, diff = fortios_vpn_ssl(
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
