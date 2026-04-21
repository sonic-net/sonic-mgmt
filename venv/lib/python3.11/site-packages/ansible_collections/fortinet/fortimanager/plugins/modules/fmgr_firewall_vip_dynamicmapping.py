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
module: fmgr_firewall_vip_dynamicmapping
short_description: Configure virtual IP for IPv4.
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
    vip:
        description: The parameter (vip) in requested url.
        type: str
        required: true
    firewall_vip_dynamicmapping:
        description: The top level parameters set.
        required: false
        type: dict
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
            dns_mapping_ttl:
                aliases: ['dns-mapping-ttl']
                type: int
                description: Dns mapping ttl.
            extaddr:
                type: raw
                description: (list or str) Extaddr.
            extintf:
                type: str
                description: Extintf.
            extip:
                type: str
                description: Extip.
            extport:
                type: str
                description: Extport.
            gratuitous_arp_interval:
                aliases: ['gratuitous-arp-interval']
                type: int
                description: Gratuitous arp interval.
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
            mapped_addr:
                aliases: ['mapped-addr']
                type: str
                description: Mapped addr.
            mappedip:
                type: raw
                description: (list) Mappedip.
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
            nat_source_vip:
                aliases: ['nat-source-vip']
                type: str
                description: Nat source vip.
                choices:
                    - 'disable'
                    - 'enable'
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
            portmapping_type:
                aliases: ['portmapping-type']
                type: str
                description: Portmapping type.
                choices:
                    - '1-to-1'
                    - 'm-to-n'
            protocol:
                type: str
                description: Protocol.
                choices:
                    - 'tcp'
                    - 'udp'
                    - 'sctp'
                    - 'icmp'
            realservers:
                type: list
                elements: dict
                description: Realservers.
                suboptions:
                    client_ip:
                        aliases: ['client-ip']
                        type: raw
                        description: (list) Client ip.
                    healthcheck:
                        type: str
                        description: Healthcheck.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'vip'
                    holddown_interval:
                        aliases: ['holddown-interval']
                        type: int
                        description: Holddown interval.
                    http_host:
                        aliases: ['http-host']
                        type: str
                        description: Http host.
                    ip:
                        type: str
                        description: Ip.
                    max_connections:
                        aliases: ['max-connections']
                        type: int
                        description: Max connections.
                    monitor:
                        type: raw
                        description: (list or str) Monitor.
                    port:
                        type: int
                        description: Port.
                    seq:
                        type: int
                        description: Seq.
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'active'
                            - 'standby'
                            - 'disable'
                    weight:
                        type: int
                        description: Weight.
                    address:
                        type: str
                        description: Address.
                    id:
                        type: int
                        description: Id.
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'ip'
                            - 'address'
                    translate_host:
                        aliases: ['translate-host']
                        type: str
                        description: Enable/disable translation of hostname/IP from virtual server to real server.
                        choices:
                            - 'disable'
                            - 'enable'
                    health_check_proto:
                        aliases: ['health-check-proto']
                        type: str
                        description: Health check proto.
                        choices:
                            - 'ping'
                            - 'http'
                    verify_cert:
                        aliases: ['verify-cert']
                        type: str
                        description: Verify cert.
                        choices:
                            - 'disable'
                            - 'enable'
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
                    - 'ssh'
            service:
                type: raw
                description: (list or str) Service.
            src_filter:
                aliases: ['src-filter']
                type: raw
                description: (list) Src filter.
            srcintf_filter:
                aliases: ['srcintf-filter']
                type: raw
                description: (list) Srcintf filter.
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Ssl algorithm.
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
                    - 'custom'
            ssl_certificate:
                aliases: ['ssl-certificate']
                type: str
                description: Ssl certificate.
            ssl_cipher_suites:
                aliases: ['ssl-cipher-suites']
                type: list
                elements: dict
                description: Ssl cipher suites.
                suboptions:
                    cipher:
                        type: str
                        description: Cipher.
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
                    id:
                        type: int
                        description: Id.
                    versions:
                        type: list
                        elements: str
                        description: Versions.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    priority:
                        type: int
                        description: Priority.
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
                    - 'load-balance'
                    - 'server-load-balance'
                    - 'dns-translation'
                    - 'fqdn'
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
            status:
                type: str
                description: Enable/disable VIP.
                choices:
                    - 'disable'
                    - 'enable'
            add_nat46_route:
                aliases: ['add-nat46-route']
                type: str
                description: Enable/disable adding NAT46 route.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6_mappedip:
                aliases: ['ipv6-mappedip']
                type: str
                description: Range of mapped IPv6 addresses.
            ipv6_mappedport:
                aliases: ['ipv6-mappedport']
                type: str
                description: IPv6 port number range on the destination network to which the external port number range is mapped.
            nat44:
                type: str
                description: Enable/disable NAT44.
                choices:
                    - 'disable'
                    - 'enable'
            nat46:
                type: str
                description: Enable/disable NAT46.
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
            http_multiplex_max_request:
                aliases: ['http-multiplex-max-request']
                type: int
                description: Maximum number of requests that a multiplex server can handle before disconnecting sessions
            http_multiplex_ttl:
                aliases: ['http-multiplex-ttl']
                type: int
                description: Time-to-live for idle connections to servers.
            http_supported_max_version:
                aliases: ['http-supported-max-version']
                type: str
                description: Maximum supported HTTP versions.
                choices:
                    - 'http1'
                    - 'http2'
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
            http_multiplex_max_concurrent_request:
                aliases: ['http-multiplex-max-concurrent-request']
                type: int
                description: Maximum number of concurrent requests that a multiplex server can handle
            gslb_domain_name:
                aliases: ['gslb-domain-name']
                type: str
                description: Domain to use when integrating with FortiGSLB.
            gslb_hostname:
                aliases: ['gslb-hostname']
                type: str
                description: Hostname to use within the configured FortiGSLB domain.
            one_click_gslb_server:
                aliases: ['one-click-gslb-server']
                type: str
                description: Enable/disable one click GSLB server integration with FortiGSLB.
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
    - name: Configure dynamic mappings of virtual IP for IPv4
      fortinet.fortimanager.fmgr_firewall_vip_dynamicmapping:
        bypass_validation: false
        adom: ansible
        vip: "ansible-test-vip" # name
        state: present
        firewall_vip_dynamicmapping:
          _scope: # Required
            - name: FGT_AWS # need a valid device name
              vdom: root # need a valid vdom name under the device
          arp_reply: enable
          color: 2
          comment: "ansible-comment"
          id: 1

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the dynamic mappings of virtual IP for IPv4
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_vip_dynamicmapping"
          params:
            adom: "ansible"
            vip: "ansible-test-vip" # name
            dynamic_mapping: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping',
        '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping'
    ]
    url_params = ['adom', 'vip']
    module_primary_key = 'complex:{{module}}["_scope"][0]["name"]+"/"+{{module}}["_scope"][0]["vdom"]'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'vip': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_vip_dynamicmapping': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_scope': {'type': 'list', 'options': {'name': {'type': 'str'}, 'vdom': {'type': 'str'}}, 'elements': 'dict'},
                'arp-reply': {'choices': ['disable', 'enable'], 'type': 'str'},
                'color': {'type': 'int'},
                'comment': {'type': 'str'},
                'dns-mapping-ttl': {'type': 'int'},
                'extaddr': {'type': 'raw'},
                'extintf': {'type': 'str'},
                'extip': {'type': 'str'},
                'extport': {'type': 'str'},
                'gratuitous-arp-interval': {'type': 'int'},
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
                'mapped-addr': {'type': 'str'},
                'mappedip': {'type': 'raw'},
                'mappedport': {'type': 'str'},
                'max-embryonic-connections': {'type': 'int'},
                'monitor': {'type': 'raw'},
                'nat-source-vip': {'choices': ['disable', 'enable'], 'type': 'str'},
                'outlook-web-access': {'choices': ['disable', 'enable'], 'type': 'str'},
                'persistence': {'choices': ['none', 'http-cookie', 'ssl-session-id'], 'type': 'str'},
                'portforward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'portmapping-type': {'choices': ['1-to-1', 'm-to-n'], 'type': 'str'},
                'protocol': {'choices': ['tcp', 'udp', 'sctp', 'icmp'], 'type': 'str'},
                'realservers': {
                    'type': 'list',
                    'options': {
                        'client-ip': {'type': 'raw'},
                        'healthcheck': {'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                        'holddown-interval': {'type': 'int'},
                        'http-host': {'type': 'str'},
                        'ip': {'type': 'str'},
                        'max-connections': {'type': 'int'},
                        'monitor': {'type': 'raw'},
                        'port': {'type': 'int'},
                        'seq': {'type': 'int'},
                        'status': {'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                        'weight': {'type': 'int'},
                        'address': {'v_range': [['6.4.0', '']], 'type': 'str'},
                        'id': {'v_range': [['6.4.0', '']], 'type': 'int'},
                        'type': {'v_range': [['6.4.0', '']], 'choices': ['ip', 'address'], 'type': 'str'},
                        'translate-host': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'health-check-proto': {'v_range': [['7.2.3', '']], 'choices': ['ping', 'http'], 'type': 'str'},
                        'verify-cert': {'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'server-type': {'choices': ['http', 'https', 'ssl', 'tcp', 'udp', 'ip', 'imaps', 'pop3s', 'smtps', 'ssh'], 'type': 'str'},
                'service': {'type': 'raw'},
                'src-filter': {'type': 'raw'},
                'srcintf-filter': {'type': 'raw'},
                'ssl-algorithm': {'choices': ['high', 'medium', 'low', 'custom'], 'type': 'str'},
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
                        'id': {'type': 'int'},
                        'versions': {'type': 'list', 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'elements': 'str'},
                        'priority': {'v_range': [['6.4.0', '']], 'type': 'int'}
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
                'ssl-server-max-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'], 'type': 'str'},
                'ssl-server-min-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'], 'type': 'str'},
                'ssl-server-session-state-max': {'type': 'int'},
                'ssl-server-session-state-timeout': {'type': 'int'},
                'ssl-server-session-state-type': {'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                'type': {'choices': ['static-nat', 'load-balance', 'server-load-balance', 'dns-translation', 'fqdn', 'access-proxy'], 'type': 'str'},
                'uuid': {'type': 'str'},
                'weblogic-server': {'choices': ['disable', 'enable'], 'type': 'str'},
                'websphere-server': {'choices': ['disable', 'enable'], 'type': 'str'},
                'http-redirect': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-client-rekey-count': {'v_range': [['6.2.1', '']], 'no_log': True, 'type': 'int'},
                'status': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'add-nat46-route': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6-mappedip': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'ipv6-mappedport': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'nat44': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat46': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-accept-ffdhe-groups': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-multiplex-max-request': {'v_range': [['7.2.2', '']], 'type': 'int'},
                'http-multiplex-ttl': {'v_range': [['7.2.2', '']], 'type': 'int'},
                'http-supported-max-version': {'v_range': [['7.2.2', '']], 'choices': ['http1', 'http2'], 'type': 'str'},
                'ssl-server-renegotiation': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h2-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h3-support': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-multiplex-max-concurrent-request': {'v_range': [['7.4.1', '']], 'type': 'int'},
                'gslb-domain-name': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'gslb-hostname': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'one-click-gslb-server': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip_dynamicmapping'),
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
