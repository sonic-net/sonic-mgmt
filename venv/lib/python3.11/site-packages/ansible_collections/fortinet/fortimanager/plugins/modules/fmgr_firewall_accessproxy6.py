#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_firewall_accessproxy6
short_description: Configure IPv6 access proxy.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    firewall_accessproxy6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            add_vhost_domain_to_dnsdb:
                aliases: ['add-vhost-domain-to-dnsdb']
                type: str
                description: Enable/disable adding vhost/domain to dnsdb for ztna dox tunnel.
                choices:
                    - 'disable'
                    - 'enable'
            api_gateway:
                aliases: ['api-gateway']
                type: list
                elements: dict
                description: Api gateway.
                suboptions:
                    application:
                        type: raw
                        description: (list) SaaS application controlled by this Access Proxy.
                    http_cookie_age:
                        aliases: ['http-cookie-age']
                        type: int
                        description: Time in minutes that client web browsers should keep a cookie.
                    http_cookie_domain:
                        aliases: ['http-cookie-domain']
                        type: str
                        description: Domain that HTTP cookie persistence should apply to.
                    http_cookie_domain_from_host:
                        aliases: ['http-cookie-domain-from-host']
                        type: str
                        description: Enable/disable use of HTTP cookie domain from host field in HTTP.
                        choices:
                            - 'disable'
                            - 'enable'
                    http_cookie_generation:
                        aliases: ['http-cookie-generation']
                        type: int
                        description: Generation of HTTP cookie to be accepted.
                    http_cookie_path:
                        aliases: ['http-cookie-path']
                        type: str
                        description: Limit HTTP cookie persistence to the specified path.
                    http_cookie_share:
                        aliases: ['http-cookie-share']
                        type: str
                        description: Control sharing of cookies across API Gateway.
                        choices:
                            - 'disable'
                            - 'same-ip'
                    https_cookie_secure:
                        aliases: ['https-cookie-secure']
                        type: str
                        description: Enable/disable verification that inserted HTTPS cookies are secure.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: API Gateway ID.
                    ldb_method:
                        aliases: ['ldb-method']
                        type: str
                        description: Method used to distribute sessions to real servers.
                        choices:
                            - 'static'
                            - 'round-robin'
                            - 'weighted'
                            - 'first-alive'
                            - 'http-host'
                    persistence:
                        type: str
                        description: Configure how to make sure that clients connect to the same server every time they make a request that is part of ...
                        choices:
                            - 'none'
                            - 'http-cookie'
                    realservers:
                        type: list
                        elements: dict
                        description: Realservers.
                        suboptions:
                            addr_type:
                                aliases: ['addr-type']
                                type: str
                                description: Type of address.
                                choices:
                                    - 'fqdn'
                                    - 'ip'
                            address:
                                type: str
                                description: Address or address group of the real server.
                            domain:
                                type: str
                                description: Wildcard domain name of the real server.
                            health_check:
                                aliases: ['health-check']
                                type: str
                                description: Enable to check the responsiveness of the real server before forwarding traffic.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            health_check_proto:
                                aliases: ['health-check-proto']
                                type: str
                                description: Protocol of the health check monitor to use when polling to determine servers connectivity status.
                                choices:
                                    - 'ping'
                                    - 'http'
                                    - 'tcp-connect'
                            holddown_interval:
                                aliases: ['holddown-interval']
                                type: str
                                description: Enable/disable holddown timer.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            http_host:
                                aliases: ['http-host']
                                type: str
                                description: HTTP server domain name in HTTP header.
                            id:
                                type: int
                                description: Real server ID.
                            ip:
                                type: str
                                description: IP address of the real server.
                            mappedport:
                                type: raw
                                description: (list or str) Port for communicating with the real server.
                            port:
                                type: int
                                description: Port for communicating with the real server.
                            ssh_client_cert:
                                aliases: ['ssh-client-cert']
                                type: str
                                description: Set access-proxy SSH client certificate profile.
                            ssh_host_key:
                                aliases: ['ssh-host-key']
                                type: raw
                                description: (list) One or more server host key.
                            ssh_host_key_validation:
                                aliases: ['ssh-host-key-validation']
                                type: str
                                description: Enable/disable SSH real server host key validation.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            status:
                                type: str
                                description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no...
                                choices:
                                    - 'active'
                                    - 'standby'
                                    - 'disable'
                            type:
                                type: str
                                description: TCP forwarding server type.
                                choices:
                                    - 'tcp-forwarding'
                                    - 'ssh'
                            weight:
                                type: int
                                description: Weight of the real server.
                            translate_host:
                                aliases: ['translate-host']
                                type: str
                                description: Enable/disable translation of hostname/IP from virtual server to real server.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            external_auth:
                                aliases: ['external-auth']
                                type: str
                                description: Enable/disable use of external browser as user-agent for SAML user authentication.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            tunnel_encryption:
                                aliases: ['tunnel-encryption']
                                type: str
                                description: Tunnel encryption.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            verify_cert:
                                aliases: ['verify-cert']
                                type: str
                                description: Enable/disable certificate verification of the real server.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    saml_redirect:
                        aliases: ['saml-redirect']
                        type: str
                        description: Enable/disable SAML redirection after successful authentication.
                        choices:
                            - 'disable'
                            - 'enable'
                    saml_server:
                        aliases: ['saml-server']
                        type: str
                        description: SAML service provider configuration for VIP authentication.
                    service:
                        type: str
                        description: Service.
                        choices:
                            - 'http'
                            - 'https'
                            - 'tcp-forwarding'
                            - 'samlsp'
                            - 'web-portal'
                            - 'saas'
                    ssl_algorithm:
                        aliases: ['ssl-algorithm']
                        type: str
                        description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                    ssl_cipher_suites:
                        aliases: ['ssl-cipher-suites']
                        type: list
                        elements: dict
                        description: Ssl cipher suites.
                        suboptions:
                            cipher:
                                type: str
                                description: Cipher suite name.
                                choices:
                                    - 'TLS-RSA-WITH-RC4-128-MD5'
                                    - 'TLS-RSA-WITH-RC4-128-SHA'
                                    - 'TLS-RSA-WITH-DES-CBC-SHA'
                                    - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-RSA-WITH-SEED-CBC-SHA'
                                    - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                                    - 'TLS-AES-128-GCM-SHA256'
                                    - 'TLS-AES-256-GCM-SHA384'
                                    - 'TLS-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                            priority:
                                type: int
                                description: SSL/TLS cipher suites priority.
                            versions:
                                type: list
                                elements: str
                                description: SSL/TLS versions that the cipher suite can be used with.
                                choices:
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                                    - 'tls-1.3'
                    ssl_dh_bits:
                        aliases: ['ssl-dh-bits']
                        type: str
                        description: Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                        choices:
                            - '768'
                            - '1024'
                            - '1536'
                            - '2048'
                            - '3072'
                            - '4096'
                    ssl_max_version:
                        aliases: ['ssl-max-version']
                        type: str
                        description: Highest SSL/TLS version acceptable from a server.
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_min_version:
                        aliases: ['ssl-min-version']
                        type: str
                        description: Lowest SSL/TLS version acceptable from a server.
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_vpn_web_portal:
                        aliases: ['ssl-vpn-web-portal']
                        type: str
                        description: SSL-VPN web portal.
                    url_map:
                        aliases: ['url-map']
                        type: str
                        description: URL pattern to match.
                    url_map_type:
                        aliases: ['url-map-type']
                        type: str
                        description: Type of url-map.
                        choices:
                            - 'sub-string'
                            - 'wildcard'
                            - 'regex'
                    virtual_host:
                        aliases: ['virtual-host']
                        type: str
                        description: Virtual host.
                    ssl_renegotiation:
                        aliases: ['ssl-renegotiation']
                        type: str
                        description: Enable/disable secure renegotiation to comply with RFC 5746.
                        choices:
                            - 'disable'
                            - 'enable'
                    h2_support:
                        aliases: ['h2-support']
                        type: str
                        description: HTTP2 support, default=Enable.
                        choices:
                            - 'disable'
                            - 'enable'
                    h3_support:
                        aliases: ['h3-support']
                        type: str
                        description: HTTP3/QUIC support, default=Disable.
                        choices:
                            - 'disable'
                            - 'enable'
                    quic:
                        type: dict
                        description: Quic.
                        suboptions:
                            ack_delay_exponent:
                                aliases: ['ack-delay-exponent']
                                type: int
                                description: ACK delay exponent
                            active_connection_id_limit:
                                aliases: ['active-connection-id-limit']
                                type: int
                                description: Active connection ID limit
                            active_migration:
                                aliases: ['active-migration']
                                type: str
                                description: Enable/disable active migration
                                choices:
                                    - 'disable'
                                    - 'enable'
                            grease_quic_bit:
                                aliases: ['grease-quic-bit']
                                type: str
                                description: Enable/disable grease QUIC bit
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max_ack_delay:
                                aliases: ['max-ack-delay']
                                type: int
                                description: Maximum ACK delay in milliseconds
                            max_datagram_frame_size:
                                aliases: ['max-datagram-frame-size']
                                type: int
                                description: Maximum datagram frame size in bytes
                            max_idle_timeout:
                                aliases: ['max-idle-timeout']
                                type: int
                                description: Maximum idle timeout milliseconds
                            max_udp_payload_size:
                                aliases: ['max-udp-payload-size']
                                type: int
                                description: Maximum UDP payload size in bytes
            api_gateway6:
                aliases: ['api-gateway6']
                type: list
                elements: dict
                description: Api gateway6.
                suboptions:
                    application:
                        type: raw
                        description: (list) SaaS application controlled by this Access Proxy.
                    http_cookie_age:
                        aliases: ['http-cookie-age']
                        type: int
                        description: Time in minutes that client web browsers should keep a cookie.
                    http_cookie_domain:
                        aliases: ['http-cookie-domain']
                        type: str
                        description: Domain that HTTP cookie persistence should apply to.
                    http_cookie_domain_from_host:
                        aliases: ['http-cookie-domain-from-host']
                        type: str
                        description: Enable/disable use of HTTP cookie domain from host field in HTTP.
                        choices:
                            - 'disable'
                            - 'enable'
                    http_cookie_generation:
                        aliases: ['http-cookie-generation']
                        type: int
                        description: Generation of HTTP cookie to be accepted.
                    http_cookie_path:
                        aliases: ['http-cookie-path']
                        type: str
                        description: Limit HTTP cookie persistence to the specified path.
                    http_cookie_share:
                        aliases: ['http-cookie-share']
                        type: str
                        description: Control sharing of cookies across API Gateway.
                        choices:
                            - 'disable'
                            - 'same-ip'
                    https_cookie_secure:
                        aliases: ['https-cookie-secure']
                        type: str
                        description: Enable/disable verification that inserted HTTPS cookies are secure.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: API Gateway ID.
                    ldb_method:
                        aliases: ['ldb-method']
                        type: str
                        description: Method used to distribute sessions to real servers.
                        choices:
                            - 'static'
                            - 'round-robin'
                            - 'weighted'
                            - 'first-alive'
                            - 'http-host'
                    persistence:
                        type: str
                        description: Configure how to make sure that clients connect to the same server every time they make a request that is part of ...
                        choices:
                            - 'none'
                            - 'http-cookie'
                    realservers:
                        type: list
                        elements: dict
                        description: Realservers.
                        suboptions:
                            addr_type:
                                aliases: ['addr-type']
                                type: str
                                description: Type of address.
                                choices:
                                    - 'fqdn'
                                    - 'ip'
                            address:
                                type: str
                                description: Address or address group of the real server.
                            domain:
                                type: str
                                description: Wildcard domain name of the real server.
                            health_check:
                                aliases: ['health-check']
                                type: str
                                description: Enable to check the responsiveness of the real server before forwarding traffic.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            health_check_proto:
                                aliases: ['health-check-proto']
                                type: str
                                description: Protocol of the health check monitor to use when polling to determine servers connectivity status.
                                choices:
                                    - 'ping'
                                    - 'http'
                                    - 'tcp-connect'
                            holddown_interval:
                                aliases: ['holddown-interval']
                                type: str
                                description: Enable/disable holddown timer.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            http_host:
                                aliases: ['http-host']
                                type: str
                                description: HTTP server domain name in HTTP header.
                            id:
                                type: int
                                description: Real server ID.
                            ip:
                                type: str
                                description: IPv6 address of the real server.
                            mappedport:
                                type: raw
                                description: (list or str) Port for communicating with the real server.
                            port:
                                type: int
                                description: Port for communicating with the real server.
                            ssh_client_cert:
                                aliases: ['ssh-client-cert']
                                type: str
                                description: Set access-proxy SSH client certificate profile.
                            ssh_host_key:
                                aliases: ['ssh-host-key']
                                type: raw
                                description: (list) One or more server host key.
                            ssh_host_key_validation:
                                aliases: ['ssh-host-key-validation']
                                type: str
                                description: Enable/disable SSH real server host key validation.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            status:
                                type: str
                                description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no...
                                choices:
                                    - 'active'
                                    - 'standby'
                                    - 'disable'
                            type:
                                type: str
                                description: TCP forwarding server type.
                                choices:
                                    - 'tcp-forwarding'
                                    - 'ssh'
                            weight:
                                type: int
                                description: Weight of the real server.
                            translate_host:
                                aliases: ['translate-host']
                                type: str
                                description: Enable/disable translation of hostname/IP from virtual server to real server.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            external_auth:
                                aliases: ['external-auth']
                                type: str
                                description: Enable/disable use of external browser as user-agent for SAML user authentication.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            tunnel_encryption:
                                aliases: ['tunnel-encryption']
                                type: str
                                description: Tunnel encryption.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            verify_cert:
                                aliases: ['verify-cert']
                                type: str
                                description: Enable/disable certificate verification of the real server.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    saml_redirect:
                        aliases: ['saml-redirect']
                        type: str
                        description: Enable/disable SAML redirection after successful authentication.
                        choices:
                            - 'disable'
                            - 'enable'
                    saml_server:
                        aliases: ['saml-server']
                        type: str
                        description: SAML service provider configuration for VIP authentication.
                    service:
                        type: str
                        description: Service.
                        choices:
                            - 'http'
                            - 'https'
                            - 'tcp-forwarding'
                            - 'samlsp'
                            - 'web-portal'
                            - 'saas'
                    ssl_algorithm:
                        aliases: ['ssl-algorithm']
                        type: str
                        description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                    ssl_cipher_suites:
                        aliases: ['ssl-cipher-suites']
                        type: list
                        elements: dict
                        description: Ssl cipher suites.
                        suboptions:
                            cipher:
                                type: str
                                description: Cipher suite name.
                                choices:
                                    - 'TLS-RSA-WITH-RC4-128-MD5'
                                    - 'TLS-RSA-WITH-RC4-128-SHA'
                                    - 'TLS-RSA-WITH-DES-CBC-SHA'
                                    - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-RSA-WITH-SEED-CBC-SHA'
                                    - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                                    - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                                    - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                                    - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                                    - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                                    - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                                    - 'TLS-AES-128-GCM-SHA256'
                                    - 'TLS-AES-256-GCM-SHA384'
                                    - 'TLS-CHACHA20-POLY1305-SHA256'
                                    - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                            priority:
                                type: int
                                description: SSL/TLS cipher suites priority.
                            versions:
                                type: list
                                elements: str
                                description: SSL/TLS versions that the cipher suite can be used with.
                                choices:
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                                    - 'tls-1.3'
                    ssl_dh_bits:
                        aliases: ['ssl-dh-bits']
                        type: str
                        description: Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                        choices:
                            - '768'
                            - '1024'
                            - '1536'
                            - '2048'
                            - '3072'
                            - '4096'
                    ssl_max_version:
                        aliases: ['ssl-max-version']
                        type: str
                        description: Highest SSL/TLS version acceptable from a server.
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_min_version:
                        aliases: ['ssl-min-version']
                        type: str
                        description: Lowest SSL/TLS version acceptable from a server.
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_vpn_web_portal:
                        aliases: ['ssl-vpn-web-portal']
                        type: str
                        description: SSL-VPN web portal.
                    url_map:
                        aliases: ['url-map']
                        type: str
                        description: URL pattern to match.
                    url_map_type:
                        aliases: ['url-map-type']
                        type: str
                        description: Type of url-map.
                        choices:
                            - 'sub-string'
                            - 'wildcard'
                            - 'regex'
                    virtual_host:
                        aliases: ['virtual-host']
                        type: str
                        description: Virtual host.
                    ssl_renegotiation:
                        aliases: ['ssl-renegotiation']
                        type: str
                        description: Enable/disable secure renegotiation to comply with RFC 5746.
                        choices:
                            - 'disable'
                            - 'enable'
                    h2_support:
                        aliases: ['h2-support']
                        type: str
                        description: HTTP2 support, default=Enable.
                        choices:
                            - 'disable'
                            - 'enable'
                    h3_support:
                        aliases: ['h3-support']
                        type: str
                        description: HTTP3/QUIC support, default=Disable.
                        choices:
                            - 'disable'
                            - 'enable'
                    quic:
                        type: dict
                        description: Quic.
                        suboptions:
                            ack_delay_exponent:
                                aliases: ['ack-delay-exponent']
                                type: int
                                description: ACK delay exponent
                            active_connection_id_limit:
                                aliases: ['active-connection-id-limit']
                                type: int
                                description: Active connection ID limit
                            active_migration:
                                aliases: ['active-migration']
                                type: str
                                description: Enable/disable active migration
                                choices:
                                    - 'disable'
                                    - 'enable'
                            grease_quic_bit:
                                aliases: ['grease-quic-bit']
                                type: str
                                description: Enable/disable grease QUIC bit
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max_ack_delay:
                                aliases: ['max-ack-delay']
                                type: int
                                description: Maximum ACK delay in milliseconds
                            max_datagram_frame_size:
                                aliases: ['max-datagram-frame-size']
                                type: int
                                description: Maximum datagram frame size in bytes
                            max_idle_timeout:
                                aliases: ['max-idle-timeout']
                                type: int
                                description: Maximum idle timeout milliseconds
                            max_udp_payload_size:
                                aliases: ['max-udp-payload-size']
                                type: int
                                description: Maximum UDP payload size in bytes
            auth_portal:
                aliases: ['auth-portal']
                type: str
                description: Enable/disable authentication portal.
                choices:
                    - 'disable'
                    - 'enable'
            auth_virtual_host:
                aliases: ['auth-virtual-host']
                type: str
                description: Virtual host for authentication portal.
            client_cert:
                aliases: ['client-cert']
                type: str
                description: Enable/disable to request client certificate.
                choices:
                    - 'disable'
                    - 'enable'
            decrypted_traffic_mirror:
                aliases: ['decrypted-traffic-mirror']
                type: str
                description: Decrypted traffic mirror.
            empty_cert_action:
                aliases: ['empty-cert-action']
                type: str
                description: Action of an empty client certificate.
                choices:
                    - 'block'
                    - 'accept'
                    - 'accept-unmanageable'
            log_blocked_traffic:
                aliases: ['log-blocked-traffic']
                type: str
                description: Enable/disable logging of blocked traffic.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Access Proxy name.
                required: true
            user_agent_detect:
                aliases: ['user-agent-detect']
                type: str
                description: Enable/disable to detect device type by HTTP user-agent if no client certificate provided.
                choices:
                    - 'disable'
                    - 'enable'
            vip:
                type: str
                description: Virtual IP name.
            http_supported_max_version:
                aliases: ['http-supported-max-version']
                type: str
                description: Maximum supported HTTP versions.
                choices:
                    - 'http1'
                    - 'http2'
            svr_pool_multiplex:
                aliases: ['svr-pool-multiplex']
                type: str
                description: Enable/disable server pool multiplexing.
                choices:
                    - 'disable'
                    - 'enable'
            svr_pool_server_max_request:
                aliases: ['svr-pool-server-max-request']
                type: int
                description: Maximum number of requests that servers in server pool handle before disconnecting
            svr_pool_ttl:
                aliases: ['svr-pool-ttl']
                type: int
                description: Time-to-live in the server pool for idle connections to servers.
            svr_pool_server_max_concurrent_request:
                aliases: ['svr-pool-server-max-concurrent-request']
                type: int
                description: Maximum number of concurrent requests that servers in server pool could handle
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure IPv6 access proxy.
      fortinet.fortimanager.fmgr_firewall_accessproxy6:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        firewall_accessproxy6:
          name: "your value" # Required variable, string
          # add_vhost_domain_to_dnsdb: <value in [disable, enable]>
          # api_gateway:
          #   - application: <list or string>
          #     http_cookie_age: <integer>
          #     http_cookie_domain: <string>
          #     http_cookie_domain_from_host: <value in [disable, enable]>
          #     http_cookie_generation: <integer>
          #     http_cookie_path: <string>
          #     http_cookie_share: <value in [disable, same-ip]>
          #     https_cookie_secure: <value in [disable, enable]>
          #     id: <integer>
          #     ldb_method: <value in [static, round-robin, weighted, ...]>
          #     persistence: <value in [none, http-cookie]>
          #     realservers:
          #       - addr_type: <value in [fqdn, ip]>
          #         address: <string>
          #         domain: <string>
          #         health_check: <value in [disable, enable]>
          #         health_check_proto: <value in [ping, http, tcp-connect]>
          #         holddown_interval: <value in [disable, enable]>
          #         http_host: <string>
          #         id: <integer>
          #         ip: <string>
          #         mappedport: <list or string>
          #         port: <integer>
          #         ssh_client_cert: <string>
          #         ssh_host_key: <list or string>
          #         ssh_host_key_validation: <value in [disable, enable]>
          #         status: <value in [active, standby, disable]>
          #         type: <value in [tcp-forwarding, ssh]>
          #         weight: <integer>
          #         translate_host: <value in [disable, enable]>
          #         external_auth: <value in [disable, enable]>
          #         tunnel_encryption: <value in [disable, enable]>
          #         verify_cert: <value in [disable, enable]>
          #     saml_redirect: <value in [disable, enable]>
          #     saml_server: <string>
          #     service: <value in [http, https, tcp-forwarding, ...]>
          #     ssl_algorithm: <value in [high, medium, low]>
          #     ssl_cipher_suites:
          #       - cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          #         priority: <integer>
          #         versions:
          #           - "tls-1.0"
          #           - "tls-1.1"
          #           - "tls-1.2"
          #           - "tls-1.3"
          #     ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          #     ssl_max_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
          #     ssl_min_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
          #     ssl_vpn_web_portal: <string>
          #     url_map: <string>
          #     url_map_type: <value in [sub-string, wildcard, regex]>
          #     virtual_host: <string>
          #     ssl_renegotiation: <value in [disable, enable]>
          #     h2_support: <value in [disable, enable]>
          #     h3_support: <value in [disable, enable]>
          #     quic:
          #       ack_delay_exponent: <integer>
          #       active_connection_id_limit: <integer>
          #       active_migration: <value in [disable, enable]>
          #       grease_quic_bit: <value in [disable, enable]>
          #       max_ack_delay: <integer>
          #       max_datagram_frame_size: <integer>
          #       max_idle_timeout: <integer>
          #       max_udp_payload_size: <integer>
          # api_gateway6:
          #   - application: <list or string>
          #     http_cookie_age: <integer>
          #     http_cookie_domain: <string>
          #     http_cookie_domain_from_host: <value in [disable, enable]>
          #     http_cookie_generation: <integer>
          #     http_cookie_path: <string>
          #     http_cookie_share: <value in [disable, same-ip]>
          #     https_cookie_secure: <value in [disable, enable]>
          #     id: <integer>
          #     ldb_method: <value in [static, round-robin, weighted, ...]>
          #     persistence: <value in [none, http-cookie]>
          #     realservers:
          #       - addr_type: <value in [fqdn, ip]>
          #         address: <string>
          #         domain: <string>
          #         health_check: <value in [disable, enable]>
          #         health_check_proto: <value in [ping, http, tcp-connect]>
          #         holddown_interval: <value in [disable, enable]>
          #         http_host: <string>
          #         id: <integer>
          #         ip: <string>
          #         mappedport: <list or string>
          #         port: <integer>
          #         ssh_client_cert: <string>
          #         ssh_host_key: <list or string>
          #         ssh_host_key_validation: <value in [disable, enable]>
          #         status: <value in [active, standby, disable]>
          #         type: <value in [tcp-forwarding, ssh]>
          #         weight: <integer>
          #         translate_host: <value in [disable, enable]>
          #         external_auth: <value in [disable, enable]>
          #         tunnel_encryption: <value in [disable, enable]>
          #         verify_cert: <value in [disable, enable]>
          #     saml_redirect: <value in [disable, enable]>
          #     saml_server: <string>
          #     service: <value in [http, https, tcp-forwarding, ...]>
          #     ssl_algorithm: <value in [high, medium, low]>
          #     ssl_cipher_suites:
          #       - cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          #         priority: <integer>
          #         versions:
          #           - "tls-1.0"
          #           - "tls-1.1"
          #           - "tls-1.2"
          #           - "tls-1.3"
          #     ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          #     ssl_max_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
          #     ssl_min_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
          #     ssl_vpn_web_portal: <string>
          #     url_map: <string>
          #     url_map_type: <value in [sub-string, wildcard, regex]>
          #     virtual_host: <string>
          #     ssl_renegotiation: <value in [disable, enable]>
          #     h2_support: <value in [disable, enable]>
          #     h3_support: <value in [disable, enable]>
          #     quic:
          #       ack_delay_exponent: <integer>
          #       active_connection_id_limit: <integer>
          #       active_migration: <value in [disable, enable]>
          #       grease_quic_bit: <value in [disable, enable]>
          #       max_ack_delay: <integer>
          #       max_datagram_frame_size: <integer>
          #       max_idle_timeout: <integer>
          #       max_udp_payload_size: <integer>
          # auth_portal: <value in [disable, enable]>
          # auth_virtual_host: <string>
          # client_cert: <value in [disable, enable]>
          # decrypted_traffic_mirror: <string>
          # empty_cert_action: <value in [block, accept, accept-unmanageable]>
          # log_blocked_traffic: <value in [disable, enable]>
          # user_agent_detect: <value in [disable, enable]>
          # vip: <string>
          # http_supported_max_version: <value in [http1, http2]>
          # svr_pool_multiplex: <value in [disable, enable]>
          # svr_pool_server_max_request: <integer>
          # svr_pool_ttl: <integer>
          # svr_pool_server_max_concurrent_request: <integer>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/firewall/access-proxy6',
        '/pm/config/global/obj/firewall/access-proxy6'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_accessproxy6': {
            'type': 'dict',
            'v_range': [['7.2.1', '']],
            'options': {
                'add-vhost-domain-to-dnsdb': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'api-gateway': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'options': {
                        'application': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'http-cookie-age': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'http-cookie-domain': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'http-cookie-domain-from-host': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-cookie-generation': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'http-cookie-path': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'http-cookie-share': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'same-ip'], 'type': 'str'},
                        'https-cookie-secure': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'ldb-method': {
                            'v_range': [['7.2.1', '']],
                            'choices': ['static', 'round-robin', 'weighted', 'first-alive', 'http-host'],
                            'type': 'str'
                        },
                        'persistence': {'v_range': [['7.2.1', '']], 'choices': ['none', 'http-cookie'], 'type': 'str'},
                        'realservers': {
                            'v_range': [['7.2.1', '']],
                            'type': 'list',
                            'options': {
                                'addr-type': {'v_range': [['7.2.1', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                                'address': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'domain': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'health-check': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'health-check-proto': {'v_range': [['7.2.1', '']], 'choices': ['ping', 'http', 'tcp-connect'], 'type': 'str'},
                                'holddown-interval': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'http-host': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'ip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'mappedport': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                'port': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'ssh-client-cert': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'ssh-host-key': {'v_range': [['7.2.1', '']], 'no_log': True, 'type': 'raw'},
                                'ssh-host-key-validation': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'status': {'v_range': [['7.2.1', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                                'type': {'v_range': [['7.2.1', '']], 'choices': ['tcp-forwarding', 'ssh'], 'type': 'str'},
                                'weight': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'external-auth': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'tunnel-encryption': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'verify-cert': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'saml-redirect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'saml-server': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'service': {
                            'v_range': [['7.2.1', '']],
                            'choices': ['http', 'https', 'tcp-forwarding', 'samlsp', 'web-portal', 'saas'],
                            'type': 'str'
                        },
                        'ssl-algorithm': {'v_range': [['7.2.1', '']], 'choices': ['high', 'medium', 'low'], 'type': 'str'},
                        'ssl-cipher-suites': {
                            'v_range': [['7.2.1', '']],
                            'type': 'list',
                            'options': {
                                'cipher': {
                                    'v_range': [['7.2.1', '']],
                                    'choices': [
                                        'TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA', 'TLS-RSA-WITH-DES-CBC-SHA',
                                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA256', 'TLS-RSA-WITH-AES-256-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA', 'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-RSA-WITH-DES-CBC-SHA', 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256', 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA', 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-RSA-WITH-AES-128-GCM-SHA256', 'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA', 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA', 'TLS-AES-128-GCM-SHA256',
                                        'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                                    ],
                                    'type': 'str'
                                },
                                'priority': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'versions': {
                                    'v_range': [['7.2.1', '']],
                                    'type': 'list',
                                    'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'ssl-dh-bits': {'v_range': [['7.2.1', '']], 'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                        'ssl-max-version': {'v_range': [['7.2.1', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'ssl-min-version': {'v_range': [['7.2.1', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'ssl-vpn-web-portal': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'url-map': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'url-map-type': {'v_range': [['7.2.1', '']], 'choices': ['sub-string', 'wildcard', 'regex'], 'type': 'str'},
                        'virtual-host': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'ssl-renegotiation': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h2-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h3-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'quic': {
                            'v_range': [['7.4.1', '']],
                            'type': 'dict',
                            'options': {
                                'ack-delay-exponent': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'active-connection-id-limit': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'active-migration': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'grease-quic-bit': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-ack-delay': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-datagram-frame-size': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-idle-timeout': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-udp-payload-size': {'v_range': [['7.4.1', '']], 'type': 'int'}
                            }
                        }
                    },
                    'elements': 'dict'
                },
                'api-gateway6': {
                    'v_range': [['7.2.1', '']],
                    'type': 'list',
                    'options': {
                        'application': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                        'http-cookie-age': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'http-cookie-domain': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'http-cookie-domain-from-host': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-cookie-generation': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'http-cookie-path': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'http-cookie-share': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'same-ip'], 'type': 'str'},
                        'https-cookie-secure': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                        'ldb-method': {
                            'v_range': [['7.2.1', '']],
                            'choices': ['static', 'round-robin', 'weighted', 'first-alive', 'http-host'],
                            'type': 'str'
                        },
                        'persistence': {'v_range': [['7.2.1', '']], 'choices': ['none', 'http-cookie'], 'type': 'str'},
                        'realservers': {
                            'v_range': [['7.2.1', '']],
                            'type': 'list',
                            'options': {
                                'addr-type': {'v_range': [['7.2.1', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                                'address': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'domain': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'health-check': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'health-check-proto': {'v_range': [['7.2.1', '']], 'choices': ['ping', 'http', 'tcp-connect'], 'type': 'str'},
                                'holddown-interval': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'http-host': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'id': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'ip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'mappedport': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                                'port': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'ssh-client-cert': {'v_range': [['7.2.1', '']], 'type': 'str'},
                                'ssh-host-key': {'v_range': [['7.2.1', '']], 'no_log': True, 'type': 'raw'},
                                'ssh-host-key-validation': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'status': {'v_range': [['7.2.1', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                                'type': {'v_range': [['7.2.1', '']], 'choices': ['tcp-forwarding', 'ssh'], 'type': 'str'},
                                'weight': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'external-auth': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'tunnel-encryption': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'verify-cert': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'saml-redirect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'saml-server': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'service': {
                            'v_range': [['7.2.1', '']],
                            'choices': ['http', 'https', 'tcp-forwarding', 'samlsp', 'web-portal', 'saas'],
                            'type': 'str'
                        },
                        'ssl-algorithm': {'v_range': [['7.2.1', '']], 'choices': ['high', 'medium', 'low'], 'type': 'str'},
                        'ssl-cipher-suites': {
                            'v_range': [['7.2.1', '']],
                            'type': 'list',
                            'options': {
                                'cipher': {
                                    'v_range': [['7.2.1', '']],
                                    'choices': [
                                        'TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA', 'TLS-RSA-WITH-DES-CBC-SHA',
                                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA256', 'TLS-RSA-WITH-AES-256-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA', 'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-RSA-WITH-DES-CBC-SHA', 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256', 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA', 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-RSA-WITH-AES-128-GCM-SHA256', 'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA', 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA', 'TLS-AES-128-GCM-SHA256',
                                        'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                                    ],
                                    'type': 'str'
                                },
                                'priority': {'v_range': [['7.2.1', '']], 'type': 'int'},
                                'versions': {
                                    'v_range': [['7.2.1', '']],
                                    'type': 'list',
                                    'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'ssl-dh-bits': {'v_range': [['7.2.1', '']], 'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                        'ssl-max-version': {'v_range': [['7.2.1', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'ssl-min-version': {'v_range': [['7.2.1', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'ssl-vpn-web-portal': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'url-map': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'url-map-type': {'v_range': [['7.2.1', '']], 'choices': ['sub-string', 'wildcard', 'regex'], 'type': 'str'},
                        'virtual-host': {'v_range': [['7.2.1', '']], 'type': 'str'},
                        'ssl-renegotiation': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h2-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h3-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'quic': {
                            'v_range': [['7.4.1', '']],
                            'type': 'dict',
                            'options': {
                                'ack-delay-exponent': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'active-connection-id-limit': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'active-migration': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'grease-quic-bit': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'max-ack-delay': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-datagram-frame-size': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-idle-timeout': {'v_range': [['7.4.1', '']], 'type': 'int'},
                                'max-udp-payload-size': {'v_range': [['7.4.1', '']], 'type': 'int'}
                            }
                        }
                    },
                    'elements': 'dict'
                },
                'auth-portal': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-virtual-host': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'client-cert': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'decrypted-traffic-mirror': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.2.1', '']], 'choices': ['block', 'accept', 'accept-unmanageable'], 'type': 'str'},
                'log-blocked-traffic': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.2.1', '']], 'required': True, 'type': 'str'},
                'user-agent-detect': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vip': {'v_range': [['7.2.1', '']], 'type': 'str'},
                'http-supported-max-version': {'v_range': [['7.2.2', '']], 'choices': ['http1', 'http2'], 'type': 'str'},
                'svr-pool-multiplex': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'svr-pool-server-max-request': {'v_range': [['7.2.2', '']], 'type': 'int'},
                'svr-pool-ttl': {'v_range': [['7.2.2', '']], 'type': 'int'},
                'svr-pool-server-max-concurrent-request': {'v_range': [['7.4.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxy6'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
