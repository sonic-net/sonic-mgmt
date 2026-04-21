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
module: fmgr_firewall_vip6
short_description: Configure virtual IP for IPv6.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
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
    firewall_vip6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            arp_reply:
                aliases: ['arp-reply']
                type: str
                description: Enable to respond to ARP requests for this virtual IP address.
                choices:
                    - 'disable'
                    - 'enable'
            color:
                type: int
                description: Color of icon on the GUI.
            comment:
                type: str
                description: Comment.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    arp_reply:
                        aliases: ['arp-reply']
                        type: str
                        description: Arp reply.
                        choices:
                            - 'disable'
                            - 'enable'
                    color:
                        type: int
                        description: Color.
                    comment:
                        type: str
                        description: Comment.
                    extip:
                        type: str
                        description: Extip.
                    extport:
                        type: str
                        description: Extport.
                    http_cookie_age:
                        aliases: ['http-cookie-age']
                        type: int
                        description: Http cookie age.
                    http_cookie_domain:
                        aliases: ['http-cookie-domain']
                        type: str
                        description: Http cookie domain.
                    http_cookie_domain_from_host:
                        aliases: ['http-cookie-domain-from-host']
                        type: str
                        description: Http cookie domain from host.
                        choices:
                            - 'disable'
                            - 'enable'
                    http_cookie_generation:
                        aliases: ['http-cookie-generation']
                        type: int
                        description: Http cookie generation.
                    http_cookie_path:
                        aliases: ['http-cookie-path']
                        type: str
                        description: Http cookie path.
                    http_cookie_share:
                        aliases: ['http-cookie-share']
                        type: str
                        description: Http cookie share.
                        choices:
                            - 'disable'
                            - 'same-ip'
                    http_ip_header:
                        aliases: ['http-ip-header']
                        type: str
                        description: Http ip header.
                        choices:
                            - 'disable'
                            - 'enable'
                    http_ip_header_name:
                        aliases: ['http-ip-header-name']
                        type: str
                        description: Http ip header name.
                    http_multiplex:
                        aliases: ['http-multiplex']
                        type: str
                        description: Http multiplex.
                        choices:
                            - 'disable'
                            - 'enable'
                    https_cookie_secure:
                        aliases: ['https-cookie-secure']
                        type: str
                        description: Https cookie secure.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: Id.
                    ldb_method:
                        aliases: ['ldb-method']
                        type: str
                        description: Ldb method.
                        choices:
                            - 'static'
                            - 'round-robin'
                            - 'weighted'
                            - 'least-session'
                            - 'least-rtt'
                            - 'first-alive'
                            - 'http-host'
                    mappedip:
                        type: str
                        description: Mappedip.
                    mappedport:
                        type: str
                        description: Mappedport.
                    max_embryonic_connections:
                        aliases: ['max-embryonic-connections']
                        type: int
                        description: Max embryonic connections.
                    monitor:
                        type: raw
                        description: (list or str) Monitor.
                    outlook_web_access:
                        aliases: ['outlook-web-access']
                        type: str
                        description: Outlook web access.
                        choices:
                            - 'disable'
                            - 'enable'
                    persistence:
                        type: str
                        description: Persistence.
                        choices:
                            - 'none'
                            - 'http-cookie'
                            - 'ssl-session-id'
                    portforward:
                        type: str
                        description: Portforward.
                        choices:
                            - 'disable'
                            - 'enable'
                    protocol:
                        type: str
                        description: Protocol.
                        choices:
                            - 'tcp'
                            - 'udp'
                            - 'sctp'
                    server_type:
                        aliases: ['server-type']
                        type: str
                        description: Server type.
                        choices:
                            - 'http'
                            - 'https'
                            - 'ssl'
                            - 'tcp'
                            - 'udp'
                            - 'ip'
                            - 'imaps'
                            - 'pop3s'
                            - 'smtps'
                    src_filter:
                        aliases: ['src-filter']
                        type: raw
                        description: (list) Src filter.
                    ssl_algorithm:
                        aliases: ['ssl-algorithm']
                        type: str
                        description: Ssl algorithm.
                        choices:
                            - 'high'
                            - 'low'
                            - 'medium'
                            - 'custom'
                    ssl_certificate:
                        aliases: ['ssl-certificate']
                        type: str
                        description: Ssl certificate.
                    ssl_client_fallback:
                        aliases: ['ssl-client-fallback']
                        type: str
                        description: Ssl client fallback.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_client_renegotiation:
                        aliases: ['ssl-client-renegotiation']
                        type: str
                        description: Ssl client renegotiation.
                        choices:
                            - 'deny'
                            - 'allow'
                            - 'secure'
                    ssl_client_session_state_max:
                        aliases: ['ssl-client-session-state-max']
                        type: int
                        description: Ssl client session state max.
                    ssl_client_session_state_timeout:
                        aliases: ['ssl-client-session-state-timeout']
                        type: int
                        description: Ssl client session state timeout.
                    ssl_client_session_state_type:
                        aliases: ['ssl-client-session-state-type']
                        type: str
                        description: Ssl client session state type.
                        choices:
                            - 'disable'
                            - 'time'
                            - 'count'
                            - 'both'
                    ssl_dh_bits:
                        aliases: ['ssl-dh-bits']
                        type: str
                        description: Ssl dh bits.
                        choices:
                            - '768'
                            - '1024'
                            - '1536'
                            - '2048'
                            - '3072'
                            - '4096'
                    ssl_hpkp:
                        aliases: ['ssl-hpkp']
                        type: str
                        description: Ssl hpkp.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'report-only'
                    ssl_hpkp_age:
                        aliases: ['ssl-hpkp-age']
                        type: int
                        description: Ssl hpkp age.
                    ssl_hpkp_backup:
                        aliases: ['ssl-hpkp-backup']
                        type: str
                        description: Ssl hpkp backup.
                    ssl_hpkp_include_subdomains:
                        aliases: ['ssl-hpkp-include-subdomains']
                        type: str
                        description: Ssl hpkp include subdomains.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_hpkp_primary:
                        aliases: ['ssl-hpkp-primary']
                        type: str
                        description: Ssl hpkp primary.
                    ssl_hpkp_report_uri:
                        aliases: ['ssl-hpkp-report-uri']
                        type: str
                        description: Ssl hpkp report uri.
                    ssl_hsts:
                        aliases: ['ssl-hsts']
                        type: str
                        description: Ssl hsts.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_hsts_age:
                        aliases: ['ssl-hsts-age']
                        type: int
                        description: Ssl hsts age.
                    ssl_hsts_include_subdomains:
                        aliases: ['ssl-hsts-include-subdomains']
                        type: str
                        description: Ssl hsts include subdomains.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_http_location_conversion:
                        aliases: ['ssl-http-location-conversion']
                        type: str
                        description: Ssl http location conversion.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_http_match_host:
                        aliases: ['ssl-http-match-host']
                        type: str
                        description: Ssl http match host.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_max_version:
                        aliases: ['ssl-max-version']
                        type: str
                        description: Ssl max version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_min_version:
                        aliases: ['ssl-min-version']
                        type: str
                        description: Ssl min version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_mode:
                        aliases: ['ssl-mode']
                        type: str
                        description: Ssl mode.
                        choices:
                            - 'half'
                            - 'full'
                    ssl_pfs:
                        aliases: ['ssl-pfs']
                        type: str
                        description: Ssl pfs.
                        choices:
                            - 'require'
                            - 'deny'
                            - 'allow'
                    ssl_send_empty_frags:
                        aliases: ['ssl-send-empty-frags']
                        type: str
                        description: Ssl send empty frags.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_server_algorithm:
                        aliases: ['ssl-server-algorithm']
                        type: str
                        description: Ssl server algorithm.
                        choices:
                            - 'high'
                            - 'low'
                            - 'medium'
                            - 'custom'
                            - 'client'
                    ssl_server_max_version:
                        aliases: ['ssl-server-max-version']
                        type: str
                        description: Ssl server max version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'client'
                            - 'tls-1.3'
                    ssl_server_min_version:
                        aliases: ['ssl-server-min-version']
                        type: str
                        description: Ssl server min version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'client'
                            - 'tls-1.3'
                    ssl_server_session_state_max:
                        aliases: ['ssl-server-session-state-max']
                        type: int
                        description: Ssl server session state max.
                    ssl_server_session_state_timeout:
                        aliases: ['ssl-server-session-state-timeout']
                        type: int
                        description: Ssl server session state timeout.
                    ssl_server_session_state_type:
                        aliases: ['ssl-server-session-state-type']
                        type: str
                        description: Ssl server session state type.
                        choices:
                            - 'disable'
                            - 'time'
                            - 'count'
                            - 'both'
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'static-nat'
                            - 'server-load-balance'
                            - 'access-proxy'
                    uuid:
                        type: str
                        description: Uuid.
                    weblogic_server:
                        aliases: ['weblogic-server']
                        type: str
                        description: Weblogic server.
                        choices:
                            - 'disable'
                            - 'enable'
                    websphere_server:
                        aliases: ['websphere-server']
                        type: str
                        description: Websphere server.
                        choices:
                            - 'disable'
                            - 'enable'
                    http_redirect:
                        aliases: ['http-redirect']
                        type: str
                        description: Http redirect.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_client_rekey_count:
                        aliases: ['ssl-client-rekey-count']
                        type: int
                        description: Ssl client rekey count.
                    nat_source_vip:
                        aliases: ['nat-source-vip']
                        type: str
                        description: Nat source vip.
                        choices:
                            - 'disable'
                            - 'enable'
                    add_nat64_route:
                        aliases: ['add-nat64-route']
                        type: str
                        description: Enable/disable adding NAT64 route.
                        choices:
                            - 'disable'
                            - 'enable'
                    embedded_ipv4_address:
                        aliases: ['embedded-ipv4-address']
                        type: str
                        description: Enable/disable use of the lower 32 bits of the external IPv6 address as mapped IPv4 address.
                        choices:
                            - 'disable'
                            - 'enable'
                    ipv4_mappedip:
                        aliases: ['ipv4-mappedip']
                        type: str
                        description: Range of mapped IP addresses.
                    ipv4_mappedport:
                        aliases: ['ipv4-mappedport']
                        type: str
                        description: IPv4 port number range on the destination network to which the external port number range is mapped.
                    nat64:
                        type: str
                        description: Enable/disable DNAT64.
                        choices:
                            - 'disable'
                            - 'enable'
                    nat66:
                        type: str
                        description: Enable/disable DNAT66.
                        choices:
                            - 'disable'
                            - 'enable'
                    realservers:
                        type: list
                        elements: dict
                        description: Realservers.
                        suboptions:
                            client_ip:
                                aliases: ['client-ip']
                                type: str
                                description: Only clients in this IP range can connect to this real server.
                            healthcheck:
                                type: str
                                description: Enable to check the responsiveness of the real server before forwarding traffic.
                                choices:
                                    - 'disable'
                                    - 'enable'
                                    - 'vip'
                            holddown_interval:
                                aliases: ['holddown-interval']
                                type: int
                                description: Time in seconds that the health check monitor continues to monitor an unresponsive server that should be a...
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
                            max_connections:
                                aliases: ['max-connections']
                                type: int
                                description: Max number of active connections that can directed to the real server.
                            monitor:
                                type: raw
                                description: (list or str) Name of the health check monitor to use when polling to determine a virtual servers connecti...
                            port:
                                type: int
                                description: Port for communicating with the real server.
                            status:
                                type: str
                                description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no...
                                choices:
                                    - 'active'
                                    - 'standby'
                                    - 'disable'
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
                    ssl_accept_ffdhe_groups:
                        aliases: ['ssl-accept-ffdhe-groups']
                        type: str
                        description: Enable/disable FFDHE cipher suite for SSL key exchange.
                        choices:
                            - 'disable'
                            - 'enable'
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
                                    - 'ssl-3.0'
                                    - 'tls-1.0'
                                    - 'tls-1.1'
                                    - 'tls-1.2'
                                    - 'tls-1.3'
                    ndp_reply:
                        aliases: ['ndp-reply']
                        type: str
                        description: Enable/disable this FortiGate units ability to respond to NDP requests for this virtual IP address
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_server_renegotiation:
                        aliases: ['ssl-server-renegotiation']
                        type: str
                        description: Enable/disable secure renegotiation to comply with RFC 5746.
                        choices:
                            - 'disable'
                            - 'enable'
                    h2_support:
                        aliases: ['h2-support']
                        type: str
                        description: Enable/disable HTTP2 support
                        choices:
                            - 'disable'
                            - 'enable'
                    h3_support:
                        aliases: ['h3-support']
                        type: str
                        description: Enable/disable HTTP3/QUIC support
                        choices:
                            - 'disable'
                            - 'enable'
                    src_vip_filter:
                        aliases: ['src-vip-filter']
                        type: str
                        description: Enable/disable use of src-filter to match destinations for the reverse SNAT rule.
                        choices:
                            - 'disable'
                            - 'enable'
                    client_cert:
                        aliases: ['client-cert']
                        type: str
                        description: Enable/disable requesting client certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                    empty_cert_action:
                        aliases: ['empty-cert-action']
                        type: str
                        description: Action for an empty client certificate.
                        choices:
                            - 'accept'
                            - 'block'
                            - 'accept-unmanageable'
                    user_agent_detect:
                        aliases: ['user-agent-detect']
                        type: str
                        description: Enable/disable detecting device type by HTTP user-agent if no client certificate is provided.
                        choices:
                            - 'disable'
                            - 'enable'
            extip:
                type: str
                description: IP address or address range on the external interface that you want to map to an address or address range on the destinati...
            extport:
                type: str
                description: Incoming port number range that you want to map to a port number range on the destination network.
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
                description: Control sharing of cookies across virtual servers.
                choices:
                    - 'disable'
                    - 'same-ip'
            http_ip_header:
                aliases: ['http-ip-header']
                type: str
                description: For HTTP multiplexing, enable to add the original client IP address in the XForwarded-For HTTP header.
                choices:
                    - 'disable'
                    - 'enable'
            http_ip_header_name:
                aliases: ['http-ip-header-name']
                type: str
                description: For HTTP multiplexing, enter a custom HTTPS header name.
            http_multiplex:
                aliases: ['http-multiplex']
                type: str
                description: Enable/disable HTTP multiplexing.
                choices:
                    - 'disable'
                    - 'enable'
            https_cookie_secure:
                aliases: ['https-cookie-secure']
                type: str
                description: Enable/disable verification that inserted HTTPS cookies are secure.
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: Custom defined ID.
            ldb_method:
                aliases: ['ldb-method']
                type: str
                description: Method used to distribute sessions to real servers.
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'least-session'
                    - 'least-rtt'
                    - 'first-alive'
                    - 'http-host'
            mappedip:
                type: str
                description: Mapped IP address range in the format startIP-endIP.
            mappedport:
                type: str
                description: Port number range on the destination network to which the external port number range is mapped.
            max_embryonic_connections:
                aliases: ['max-embryonic-connections']
                type: int
                description: Maximum number of incomplete connections.
            monitor:
                type: raw
                description: (list or str) Name of the health check monitor to use when polling to determine a virtual servers connectivity status.
            name:
                type: str
                description: Virtual ip6 name.
                required: true
            outlook_web_access:
                aliases: ['outlook-web-access']
                type: str
                description: Enable to add the Front-End-Https header for Microsoft Outlook Web Access.
                choices:
                    - 'disable'
                    - 'enable'
            persistence:
                type: str
                description: Configure how to make sure that clients connect to the same server every time they make a request that is part of the same...
                choices:
                    - 'none'
                    - 'http-cookie'
                    - 'ssl-session-id'
            portforward:
                type: str
                description: Enable port forwarding.
                choices:
                    - 'disable'
                    - 'enable'
            protocol:
                type: str
                description: Protocol to use when forwarding packets.
                choices:
                    - 'tcp'
                    - 'udp'
                    - 'sctp'
            realservers:
                type: list
                elements: dict
                description: Realservers.
                suboptions:
                    client_ip:
                        aliases: ['client-ip']
                        type: str
                        description: Only clients in this IP range can connect to this real server.
                    healthcheck:
                        type: str
                        description: Enable to check the responsiveness of the real server before forwarding traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'vip'
                    holddown_interval:
                        aliases: ['holddown-interval']
                        type: int
                        description: Time in seconds that the health check monitor continues to monitor an unresponsive server that should be active.
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
                    max_connections:
                        aliases: ['max-connections']
                        type: int
                        description: Max number of active connections that can directed to the real server.
                    monitor:
                        type: raw
                        description: (list or str) Name of the health check monitor to use when polling to determine a virtual servers connectivity status.
                    port:
                        type: int
                        description: Port for communicating with the real server.
                    status:
                        type: str
                        description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic...
                        choices:
                            - 'active'
                            - 'standby'
                            - 'disable'
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
            server_type:
                aliases: ['server-type']
                type: str
                description: Protocol to be load balanced by the virtual server
                choices:
                    - 'http'
                    - 'https'
                    - 'ssl'
                    - 'tcp'
                    - 'udp'
                    - 'ip'
                    - 'imaps'
                    - 'pop3s'
                    - 'smtps'
            src_filter:
                aliases: ['src-filter']
                type: raw
                description: (list) Source IP6 filter
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Permitted encryption algorithms for SSL sessions according to encryption strength.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
            ssl_certificate:
                aliases: ['ssl-certificate']
                type: str
                description: The name of the SSL certificate to use for SSL acceleration.
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
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl_client_fallback:
                aliases: ['ssl-client-fallback']
                type: str
                description: Enable/disable support for preventing Downgrade Attacks on client connections
                choices:
                    - 'disable'
                    - 'enable'
            ssl_client_renegotiation:
                aliases: ['ssl-client-renegotiation']
                type: str
                description: Allow, deny, or require secure renegotiation of client sessions to comply with RFC 5746.
                choices:
                    - 'deny'
                    - 'allow'
                    - 'secure'
            ssl_client_session_state_max:
                aliases: ['ssl-client-session-state-max']
                type: int
                description: Maximum number of client to FortiGate SSL session states to keep.
            ssl_client_session_state_timeout:
                aliases: ['ssl-client-session-state-timeout']
                type: int
                description: Number of minutes to keep client to FortiGate SSL session state.
            ssl_client_session_state_type:
                aliases: ['ssl-client-session-state-type']
                type: str
                description: How to expire SSL sessions for the segment of the SSL connection between the client and the FortiGate.
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
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
            ssl_hpkp:
                aliases: ['ssl-hpkp']
                type: str
                description: Enable/disable including HPKP header in response.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'report-only'
            ssl_hpkp_age:
                aliases: ['ssl-hpkp-age']
                type: int
                description: Number of minutes the web browser should keep HPKP.
            ssl_hpkp_backup:
                aliases: ['ssl-hpkp-backup']
                type: str
                description: Certificate to generate backup HPKP pin from.
            ssl_hpkp_include_subdomains:
                aliases: ['ssl-hpkp-include-subdomains']
                type: str
                description: Indicate that HPKP header applies to all subdomains.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_hpkp_primary:
                aliases: ['ssl-hpkp-primary']
                type: str
                description: Certificate to generate primary HPKP pin from.
            ssl_hpkp_report_uri:
                aliases: ['ssl-hpkp-report-uri']
                type: str
                description: URL to report HPKP violations to.
            ssl_hsts:
                aliases: ['ssl-hsts']
                type: str
                description: Enable/disable including HSTS header in response.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_hsts_age:
                aliases: ['ssl-hsts-age']
                type: int
                description: Number of seconds the client should honour the HSTS setting.
            ssl_hsts_include_subdomains:
                aliases: ['ssl-hsts-include-subdomains']
                type: str
                description: Indicate that HSTS header applies to all subdomains.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_http_location_conversion:
                aliases: ['ssl-http-location-conversion']
                type: str
                description: Enable to replace HTTP with HTTPS in the replys Location HTTP header field.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_http_match_host:
                aliases: ['ssl-http-match-host']
                type: str
                description: Enable/disable HTTP host matching for location conversion.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_max_version:
                aliases: ['ssl-max-version']
                type: str
                description: Highest SSL/TLS version acceptable from a client.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_min_version:
                aliases: ['ssl-min-version']
                type: str
                description: Lowest SSL/TLS version acceptable from a client.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_mode:
                aliases: ['ssl-mode']
                type: str
                description: Apply SSL offloading between the client and the FortiGate
                choices:
                    - 'half'
                    - 'full'
            ssl_pfs:
                aliases: ['ssl-pfs']
                type: str
                description: Select the cipher suites that can be used for SSL perfect forward secrecy
                choices:
                    - 'require'
                    - 'deny'
                    - 'allow'
            ssl_send_empty_frags:
                aliases: ['ssl-send-empty-frags']
                type: str
                description: Enable/disable sending empty fragments to avoid CBC IV attacks
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_algorithm:
                aliases: ['ssl-server-algorithm']
                type: str
                description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
                    - 'client'
            ssl_server_cipher_suites:
                aliases: ['ssl-server-cipher-suites']
                type: list
                elements: dict
                description: Ssl server cipher suites.
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
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl_server_max_version:
                aliases: ['ssl-server-max-version']
                type: str
                description: Highest SSL/TLS version acceptable from a server.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
                    - 'tls-1.3'
            ssl_server_min_version:
                aliases: ['ssl-server-min-version']
                type: str
                description: Lowest SSL/TLS version acceptable from a server.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
                    - 'tls-1.3'
            ssl_server_session_state_max:
                aliases: ['ssl-server-session-state-max']
                type: int
                description: Maximum number of FortiGate to Server SSL session states to keep.
            ssl_server_session_state_timeout:
                aliases: ['ssl-server-session-state-timeout']
                type: int
                description: Number of minutes to keep FortiGate to Server SSL session state.
            ssl_server_session_state_type:
                aliases: ['ssl-server-session-state-type']
                type: str
                description: How to expire SSL sessions for the segment of the SSL connection between the server and the FortiGate.
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            type:
                type: str
                description: Configure a static NAT VIP.
                choices:
                    - 'static-nat'
                    - 'server-load-balance'
                    - 'access-proxy'
            uuid:
                type: str
                description: Universally Unique Identifier
            weblogic_server:
                aliases: ['weblogic-server']
                type: str
                description: Enable to add an HTTP header to indicate SSL offloading for a WebLogic server.
                choices:
                    - 'disable'
                    - 'enable'
            websphere_server:
                aliases: ['websphere-server']
                type: str
                description: Enable to add an HTTP header to indicate SSL offloading for a WebSphere server.
                choices:
                    - 'disable'
                    - 'enable'
            http_redirect:
                aliases: ['http-redirect']
                type: str
                description: Enable/disable redirection of HTTP to HTTPS
                choices:
                    - 'disable'
                    - 'enable'
            ssl_client_rekey_count:
                aliases: ['ssl-client-rekey-count']
                type: int
                description: Maximum length of data in MB before triggering a client rekey
            nat_source_vip:
                aliases: ['nat-source-vip']
                type: str
                description: Enable to perform SNAT on traffic from mappedip to the extip for all egress interfaces.
                choices:
                    - 'disable'
                    - 'enable'
            add_nat64_route:
                aliases: ['add-nat64-route']
                type: str
                description: Enable/disable adding NAT64 route.
                choices:
                    - 'disable'
                    - 'enable'
            embedded_ipv4_address:
                aliases: ['embedded-ipv4-address']
                type: str
                description: Enable/disable use of the lower 32 bits of the external IPv6 address as mapped IPv4 address.
                choices:
                    - 'disable'
                    - 'enable'
            ipv4_mappedip:
                aliases: ['ipv4-mappedip']
                type: str
                description: Range of mapped IP addresses.
            ipv4_mappedport:
                aliases: ['ipv4-mappedport']
                type: str
                description: IPv4 port number range on the destination network to which the external port number range is mapped.
            nat64:
                type: str
                description: Enable/disable DNAT64.
                choices:
                    - 'disable'
                    - 'enable'
            nat66:
                type: str
                description: Enable/disable DNAT66.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_accept_ffdhe_groups:
                aliases: ['ssl-accept-ffdhe-groups']
                type: str
                description: Enable/disable FFDHE cipher suite for SSL key exchange.
                choices:
                    - 'disable'
                    - 'enable'
            ndp_reply:
                aliases: ['ndp-reply']
                type: str
                description: Enable/disable this FortiGate units ability to respond to NDP requests for this virtual IP address
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_renegotiation:
                aliases: ['ssl-server-renegotiation']
                type: str
                description: Enable/disable secure renegotiation to comply with RFC 5746.
                choices:
                    - 'disable'
                    - 'enable'
            h2_support:
                aliases: ['h2-support']
                type: str
                description: Enable/disable HTTP2 support
                choices:
                    - 'disable'
                    - 'enable'
            h3_support:
                aliases: ['h3-support']
                type: str
                description: Enable/disable HTTP3/QUIC support
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
                        description:
                            - Support meta variable
                            - ACK delay exponent
                    active_connection_id_limit:
                        aliases: ['active-connection-id-limit']
                        type: int
                        description:
                            - Support meta variable
                            - Active connection ID limit
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
                        description:
                            - Support meta variable
                            - Maximum ACK delay in milliseconds
                    max_datagram_frame_size:
                        aliases: ['max-datagram-frame-size']
                        type: int
                        description:
                            - Support meta variable
                            - Maximum datagram frame size in bytes
                    max_idle_timeout:
                        aliases: ['max-idle-timeout']
                        type: int
                        description:
                            - Support meta variable
                            - Maximum idle timeout milliseconds
                    max_udp_payload_size:
                        aliases: ['max-udp-payload-size']
                        type: int
                        description:
                            - Support meta variable
                            - Maximum UDP payload size in bytes
            src_vip_filter:
                aliases: ['src-vip-filter']
                type: str
                description: Enable/disable use of src-filter to match destinations for the reverse SNAT rule.
                choices:
                    - 'disable'
                    - 'enable'
            client_cert:
                aliases: ['client-cert']
                type: str
                description: Enable/disable requesting client certificate.
                choices:
                    - 'disable'
                    - 'enable'
            empty_cert_action:
                aliases: ['empty-cert-action']
                type: str
                description: Action for an empty client certificate.
                choices:
                    - 'accept'
                    - 'block'
                    - 'accept-unmanageable'
            user_agent_detect:
                aliases: ['user-agent-detect']
                type: str
                description: Enable/disable detecting device type by HTTP user-agent if no client certificate is provided.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure virtual IP for IPv6.
      fortinet.fortimanager.fmgr_firewall_vip6:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_vip6:
          arp_reply: disable
          color: 1
          comment: "ansible-comment"
          id: 1
          name: "ansible-test-vip6"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the scripts
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_vip6"
          params:
            adom: "ansible"
            vip6: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/vip6',
        '/pm/config/global/obj/firewall/vip6'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_vip6': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                'color': {'type': 'int'},
                'comment': {'type': 'str'},
                'dynamic_mapping': {
                    'type': 'list',
                    'options': {
                        '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                        'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'color': {'type': 'int'},
                        'comment': {'type': 'str'},
                        'extip': {'type': 'str'},
                        'extport': {'type': 'str'},
                        'http-cookie-age': {'type': 'int'},
                        'http-cookie-domain': {'type': 'str'},
                        'http-cookie-domain-from-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-cookie-generation': {'type': 'int'},
                        'http-cookie-path': {'type': 'str'},
                        'http-cookie-share': {'choices': ['disable', 'same-ip'], 'type': 'str'},
                        'http-ip-header': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-ip-header-name': {'type': 'str'},
                        'http-multiplex': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'https-cookie-secure': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'type': 'int'},
                        'ldb-method': {
                            'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive', 'http-host'],
                            'type': 'str'
                        },
                        'mappedip': {'type': 'str'},
                        'mappedport': {'type': 'str'},
                        'max-embryonic-connections': {'type': 'int'},
                        'monitor': {'type': 'raw'},
                        'outlook-web-access': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'persistence': {'choices': ['none', 'http-cookie', 'ssl-session-id'], 'type': 'str'},
                        'portforward': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'protocol': {'choices': ['tcp', 'udp', 'sctp'], 'type': 'str'},
                        'server-type': {'choices': ['http', 'https', 'ssl', 'tcp', 'udp', 'ip', 'imaps', 'pop3s', 'smtps'], 'type': 'str'},
                        'src-filter': {'type': 'raw'},
                        'ssl-algorithm': {'choices': ['high', 'low', 'medium', 'custom'], 'type': 'str'},
                        'ssl-certificate': {'type': 'str'},
                        'ssl-client-fallback': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-client-renegotiation': {'choices': ['deny', 'allow', 'secure'], 'type': 'str'},
                        'ssl-client-session-state-max': {'type': 'int'},
                        'ssl-client-session-state-timeout': {'type': 'int'},
                        'ssl-client-session-state-type': {'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                        'ssl-dh-bits': {'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                        'ssl-hpkp': {'choices': ['disable', 'enable', 'report-only'], 'type': 'str'},
                        'ssl-hpkp-age': {'type': 'int'},
                        'ssl-hpkp-backup': {'type': 'str'},
                        'ssl-hpkp-include-subdomains': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-hpkp-primary': {'type': 'str'},
                        'ssl-hpkp-report-uri': {'type': 'str'},
                        'ssl-hsts': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-hsts-age': {'type': 'int'},
                        'ssl-hsts-include-subdomains': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-http-location-conversion': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-http-match-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-max-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'ssl-min-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                        'ssl-mode': {'choices': ['half', 'full'], 'type': 'str'},
                        'ssl-pfs': {'choices': ['require', 'deny', 'allow'], 'type': 'str'},
                        'ssl-send-empty-frags': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-server-algorithm': {'choices': ['high', 'low', 'medium', 'custom', 'client'], 'type': 'str'},
                        'ssl-server-max-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'], 'type': 'str'},
                        'ssl-server-min-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'], 'type': 'str'},
                        'ssl-server-session-state-max': {'type': 'int'},
                        'ssl-server-session-state-timeout': {'type': 'int'},
                        'ssl-server-session-state-type': {'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                        'type': {'choices': ['static-nat', 'server-load-balance', 'access-proxy'], 'type': 'str'},
                        'uuid': {'type': 'str'},
                        'weblogic-server': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'websphere-server': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-redirect': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-client-rekey-count': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'int'},
                        'nat-source-vip': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'add-nat64-route': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'embedded-ipv4-address': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ipv4-mappedip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'ipv4-mappedport': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'nat64': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'nat66': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'realservers': {
                            'v_range': [['7.0.2', '']],
                            'type': 'list',
                            'options': {
                                'client-ip': {'v_range': [['7.0.2', '']], 'type': 'str'},
                                'healthcheck': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                                'holddown-interval': {'v_range': [['7.0.2', '']], 'type': 'int'},
                                'http-host': {'v_range': [['7.0.2', '']], 'type': 'str'},
                                'id': {'v_range': [['7.0.2', '']], 'type': 'int'},
                                'ip': {'v_range': [['7.0.2', '']], 'type': 'str'},
                                'max-connections': {'v_range': [['7.0.2', '']], 'type': 'int'},
                                'monitor': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                                'port': {'v_range': [['7.0.2', '']], 'type': 'int'},
                                'status': {'v_range': [['7.0.2', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                                'weight': {'v_range': [['7.0.2', '']], 'type': 'int'},
                                'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'ssl-accept-ffdhe-groups': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-cipher-suites': {
                            'v_range': [['7.0.2', '']],
                            'type': 'list',
                            'options': {
                                'cipher': {
                                    'v_range': [['7.0.2', '']],
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
                                'priority': {'v_range': [['7.0.2', '']], 'type': 'int'},
                                'versions': {
                                    'v_range': [['7.0.2', '']],
                                    'type': 'list',
                                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'ndp-reply': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-server-renegotiation': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h2-support': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h3-support': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'src-vip-filter': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'client-cert': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'empty-cert-action': {'v_range': [['7.6.2', '']], 'choices': ['accept', 'block', 'accept-unmanageable'], 'type': 'str'},
                        'user-agent-detect': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'extip': {'type': 'str'},
                'extport': {'type': 'str'},
                'http-cookie-age': {'type': 'int'},
                'http-cookie-domain': {'type': 'str'},
                'http-cookie-domain-from-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'http-cookie-generation': {'type': 'int'},
                'http-cookie-path': {'type': 'str'},
                'http-cookie-share': {'choices': ['disable', 'same-ip'], 'type': 'str'},
                'http-ip-header': {'choices': ['disable', 'enable'], 'type': 'str'},
                'http-ip-header-name': {'type': 'str'},
                'http-multiplex': {'choices': ['disable', 'enable'], 'type': 'str'},
                'https-cookie-secure': {'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'type': 'int'},
                'ldb-method': {'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive', 'http-host'], 'type': 'str'},
                'mappedip': {'type': 'str'},
                'mappedport': {'type': 'str'},
                'max-embryonic-connections': {'type': 'int'},
                'monitor': {'type': 'raw'},
                'name': {'required': True, 'type': 'str'},
                'outlook-web-access': {'choices': ['disable', 'enable'], 'type': 'str'},
                'persistence': {'choices': ['none', 'http-cookie', 'ssl-session-id'], 'type': 'str'},
                'portforward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'protocol': {'choices': ['tcp', 'udp', 'sctp'], 'type': 'str'},
                'realservers': {
                    'type': 'list',
                    'options': {
                        'client-ip': {'type': 'str'},
                        'healthcheck': {'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                        'holddown-interval': {'type': 'int'},
                        'http-host': {'type': 'str'},
                        'id': {'type': 'int'},
                        'ip': {'type': 'str'},
                        'max-connections': {'type': 'int'},
                        'monitor': {'type': 'raw'},
                        'port': {'type': 'int'},
                        'status': {'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                        'weight': {'type': 'int'},
                        'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'server-type': {'choices': ['http', 'https', 'ssl', 'tcp', 'udp', 'ip', 'imaps', 'pop3s', 'smtps'], 'type': 'str'},
                'src-filter': {'type': 'raw'},
                'ssl-algorithm': {'choices': ['high', 'low', 'medium', 'custom'], 'type': 'str'},
                'ssl-certificate': {'type': 'str'},
                'ssl-cipher-suites': {
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'choices': [
                                'TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA', 'TLS-RSA-WITH-DES-CBC-SHA', 'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA', 'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                'TLS-RSA-WITH-AES-256-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA',
                                'TLS-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA', 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA', 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256', 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA',
                                'TLS-AES-128-GCM-SHA256', 'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                            ],
                            'type': 'str'
                        },
                        'priority': {'type': 'int'},
                        'versions': {'type': 'list', 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'ssl-client-fallback': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-client-renegotiation': {'choices': ['deny', 'allow', 'secure'], 'type': 'str'},
                'ssl-client-session-state-max': {'type': 'int'},
                'ssl-client-session-state-timeout': {'type': 'int'},
                'ssl-client-session-state-type': {'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                'ssl-dh-bits': {'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                'ssl-hpkp': {'choices': ['disable', 'enable', 'report-only'], 'type': 'str'},
                'ssl-hpkp-age': {'type': 'int'},
                'ssl-hpkp-backup': {'type': 'str'},
                'ssl-hpkp-include-subdomains': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-hpkp-primary': {'type': 'str'},
                'ssl-hpkp-report-uri': {'type': 'str'},
                'ssl-hsts': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-hsts-age': {'type': 'int'},
                'ssl-hsts-include-subdomains': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-http-location-conversion': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-http-match-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-max-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-min-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-mode': {'choices': ['half', 'full'], 'type': 'str'},
                'ssl-pfs': {'choices': ['require', 'deny', 'allow'], 'type': 'str'},
                'ssl-send-empty-frags': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-algorithm': {'choices': ['high', 'low', 'medium', 'custom', 'client'], 'type': 'str'},
                'ssl-server-cipher-suites': {
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'choices': [
                                'TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA', 'TLS-RSA-WITH-DES-CBC-SHA', 'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA', 'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                'TLS-RSA-WITH-AES-256-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA',
                                'TLS-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA', 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA', 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256', 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA',
                                'TLS-AES-128-GCM-SHA256', 'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                            ],
                            'type': 'str'
                        },
                        'priority': {'type': 'int'},
                        'versions': {'type': 'list', 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'ssl-server-max-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'], 'type': 'str'},
                'ssl-server-min-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'], 'type': 'str'},
                'ssl-server-session-state-max': {'type': 'int'},
                'ssl-server-session-state-timeout': {'type': 'int'},
                'ssl-server-session-state-type': {'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                'type': {'choices': ['static-nat', 'server-load-balance', 'access-proxy'], 'type': 'str'},
                'uuid': {'type': 'str'},
                'weblogic-server': {'choices': ['disable', 'enable'], 'type': 'str'},
                'websphere-server': {'choices': ['disable', 'enable'], 'type': 'str'},
                'http-redirect': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-client-rekey-count': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'int'},
                'nat-source-vip': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'add-nat64-route': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'embedded-ipv4-address': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv4-mappedip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'ipv4-mappedport': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'nat64': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat66': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-accept-ffdhe-groups': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ndp-reply': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-renegotiation': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h2-support': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h3-support': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'quic': {
                    'v_range': [['7.4.2', '']],
                    'type': 'dict',
                    'options': {
                        'ack-delay-exponent': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'active-connection-id-limit': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'active-migration': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'grease-quic-bit': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-ack-delay': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'max-datagram-frame-size': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'max-idle-timeout': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'max-udp-payload-size': {'v_range': [['7.4.2', '']], 'type': 'int'}
                    }
                },
                'src-vip-filter': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-cert': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.6.2', '']], 'choices': ['accept', 'block', 'accept-unmanageable'], 'type': 'str'},
                'user-agent-detect': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip6'),
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
