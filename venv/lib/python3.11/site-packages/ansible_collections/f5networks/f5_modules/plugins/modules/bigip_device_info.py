#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# Copyright: (c) 2013, Matt Hite <mhite@hotmail.com>
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_device_info
short_description: Collect information from F5 BIG-IP devices
description:
  - Collect information from F5 BIG-IP devices.
  - This module was called C(bigip_device_facts) before Ansible 2.9. The usage did not change.
version_added: "1.0.0"
options:
  partition:
    description:
      - Specifies the partition to gather the resource information from.
      - The default value for the partition is taken as Common.
    type: str
    default: Common
    version_added: "1.14.0"
  data_increment:
    description:
      - Specifies the paging increment at which device data is gathered from the API.
      - Allows for greater control of the pace at which data is queried from the device.
      - This setting is useful for setups with large configurations which may take a long time with the default values.
      - While there is no limit to the value that can be specified, note that putting very large values with
        C(gather_subset) set to meta choices like C(all) might lead to module or device API crash.
      - F5 recommends using C(data_increment) custom values in tandem with C(partition) and a specific C(gather_subset)
        value for best experience.
    type: int
    default: 10
    version_added: "1.22.0"
  gather_subset:
    description:
      - When supplied, this argument will restrict the information returned to a given subset.
      - You can specify a list of values to include a larger subset.
      - Values can also be used with an initial C(!) to specify that a specific subset
        should not be collected.
    type: list
    elements: str
    required: True
    choices:
      - all
      - monitors
      - profiles
      - apm-access-profiles
      - apm-access-policies
      - as3
      - asm-policy-stats
      - asm-policies
      - asm-server-technologies
      - asm-signature-sets
      - client-ssl-profiles
      - cfe
      - devices
      - device-groups
      - do
      - external-monitors
      - fasthttp-profiles
      - fastl4-profiles
      - gateway-icmp-monitors
      - gtm-pools
      - gtm-servers
      - gtm-wide-ips
      - gtm-a-pools
      - gtm-a-wide-ips
      - gtm-aaaa-pools
      - gtm-aaaa-wide-ips
      - gtm-cname-pools
      - gtm-cname-wide-ips
      - gtm-mx-pools
      - gtm-mx-wide-ips
      - gtm-naptr-pools
      - gtm-naptr-wide-ips
      - gtm-srv-pools
      - gtm-srv-wide-ips
      - gtm-topology-regions
      - http-monitors
      - https-monitors
      - http-profiles
      - iapp-services
      - iapplx-packages
      - icmp-monitors
      - interfaces
      - internal-data-groups
      - irules
      - license
      - ltm-pools
      - snat-pools
      - ltm-policies
      - management-routes
      - nodes
      - oneconnect-profiles
      - packages
      - partitions
      - provision-info
      - remote-syslog
      - route-domains
      - self-ips
      - server-ssl-profiles
      - software-volumes
      - software-images
      - software-hotfixes
      - ssl-certs
      - ssl-keys
      - sync-status
      - system-db
      - system-info
      - ts
      - tcp-monitors
      - tcp-half-open-monitors
      - tcp-profiles
      - traffic-groups
      - trunks
      - udp-profiles
      - users
      - ucs
      - vcmp-guests
      - virtual-addresses
      - virtual-servers
      - vlans
      - "!all"
      - "!as3"
      - "!do"
      - "!ts"
      - "!cfe"
      - "!monitors"
      - "!profiles"
      - "!apm-access-profiles"
      - "!apm-access-policies"
      - "!asm-policy-stats"
      - "!asm-policies"
      - "!asm-server-technologies"
      - "!asm-signature-sets"
      - "!client-ssl-profiles"
      - "!devices"
      - "!device-groups"
      - "!external-monitors"
      - "!fasthttp-profiles"
      - "!fastl4-profiles"
      - "!gateway-icmp-monitors"
      - "!gtm-pools"
      - "!gtm-servers"
      - "!gtm-wide-ips"
      - "!gtm-a-pools"
      - "!gtm-a-wide-ips"
      - "!gtm-aaaa-pools"
      - "!gtm-aaaa-wide-ips"
      - "!gtm-cname-pools"
      - "!gtm-cname-wide-ips"
      - "!gtm-mx-pools"
      - "!gtm-mx-wide-ips"
      - "!gtm-naptr-pools"
      - "!gtm-naptr-wide-ips"
      - "!gtm-srv-pools"
      - "!gtm-srv-wide-ips"
      - "!gtm-topology-regions"
      - "!http-monitors"
      - "!https-monitors"
      - "!http-profiles"
      - "!iapp-services"
      - "!iapplx-packages"
      - "!icmp-monitors"
      - "!interfaces"
      - "!internal-data-groups"
      - "!irules"
      - "!license"
      - "!ltm-pools"
      - "!snat-pools"
      - "!ltm-policies"
      - "!management-routes"
      - "!nodes"
      - "!oneconnect-profiles"
      - "!packages"
      - "!partitions"
      - "!provision-info"
      - "!remote-syslog"
      - "!route-domains"
      - "!self-ips"
      - "!server-ssl-profiles"
      - "!software-volumes"
      - "!software-images"
      - "!software-hotfixes"
      - "!ssl-certs"
      - "!ssl-keys"
      - "!sync-status"
      - "!system-db"
      - "!system-info"
      - "!tcp-monitors"
      - "!tcp-half-open-monitors"
      - "!tcp-profiles"
      - "!traffic-groups"
      - "!trunks"
      - "!udp-profiles"
      - "!users"
      - "!ucs"
      - "!vcmp-guests"
      - "!virtual-addresses"
      - "!virtual-servers"
      - "!vlans"
    aliases: ['include']
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Collect BIG-IP information
  bigip_device_info:
    gather_subset:
      - interfaces
      - vlans
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Collect all BIG-IP information
  bigip_device_info:
    gather_subset:
      - all
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Collect all BIG-IP information except trunks
  bigip_device_info:
    gather_subset:
      - all
      - "!trunks"
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Collect BIG-IP information with custom data_increment and specific partition
  bigip_device_info:
    data_increment: 50
    partition: Foo
    gather_subset:
      - gtm-a-wide-ips
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
apm_access_profiles:
  description: Information about APM Access Profiles.
  returned: When C(apm-access-profiles) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/foo_policy
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: foo_policy
    access_policy:
      description:
        - APM Access Policy attached to this Access Profile.
      returned: queried
      type: str
      sample: foo_policy
apm_access_policies:
  description: Information about APM Access Policies.
  returned: When C(apm-access-policies) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/foo_policy
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: foo_policy
asm_policy_stats:
  description: Miscellaneous ASM policy related information.
  returned: When C(asm-policy-stats) is specified in C(gather_subset).
  type: complex
  contains:
    policies:
      description:
        - The total number of ASM policies on the device.
      returned: queried
      type: int
      sample: 3
    parent_policies:
      description:
        - The total number of ASM parent policies on the device.
      returned: queried
      type: int
      sample: 2
    policies_pending_changes:
      description:
        - The total number of ASM policies with pending changes on the device.
      returned: queried
      type: int
      sample: 2
    policies_active:
      description:
        - The number of ASM policies that are marked as active. From TMOS 13.x and above this setting equals
          to C(policies_attached).
      returned: queried
      type: int
      sample: 3
    policies_attached:
      description:
        - The number of ASM policies that are attached to virtual servers.
      returned: queried
      type: int
      sample: 1
    policies_inactive:
      description:
        - The number of ASM policies that are marked as inactive. From TMOS 13.x and above this setting equals
          to C(policies_unattached).
      returned: queried
      type: int
      sample: 0
    policies_unattached:
      description:
        - The number of ASM policies that are not attached to a virtual server.
      returned: queried
      type: int
      sample: 3
  sample: hash/dictionary of values
asm_policies:
  description: Detailed information for ASM policies present on device.
  returned: When C(asm-policies) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/foo_policy
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: foo_policy
    policy_id:
      description:
        - Generated ID of the ASM policy resource.
      returned: queried
      type: str
      sample: l0Ckxe-7yHsXp8U5tTgbFQ
    active:
      description:
        - Indicates if an ASM policy is active. In TMOS 13.x and above,
          this setting indicates if the policy is bound to any Virtual Server.
      returned: queried
      type: bool
      sample: true
    apply:
      description:
        - In TMOS 13.x and above, this setting indicates if an ASM policy has pending changes that need to be applied.
      returned: queried
      type: bool
      sample: true
    protocol_independent:
      description:
        - Indicates if the ASM policy differentiates between HTTP/WS and HTTPS/WSS URLs.
      returned: queried
      type: bool
      sample: false
    has_parent:
      description:
        - Indicates if the ASM policy is a child of another ASM policy.
      returned: queried
      type: bool
      sample: false
    type:
      description:
        - The type of policy, can be C(Security) or C(Parent).
      returned: queried
      type: str
      sample: security
    virtual_servers:
      description:
        - Virtual server or servers which have this policy assigned to them.
      returned: queried
      type: list
      sample: ['/Common/foo_VS/']
    manual_virtual_servers:
      description:
        - The virtual servers that have Advanced LTM policy configuration which, in turn, have rule(s) built
          with ASM control actions enabled.
      returned: queried
      type: list
      sample: ['/Common/test_VS/']
    allowed_response_codes:
      description:
        - Lists the response status codes between 400 and 599 that the security profile considers legal.
      returned: queried
      type: list
      sample: ['400', '404']
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: Significant Policy Description
    learning_mode:
      description:
        - Determine how the policy is built.
      returned: queried
      type: str
      sample: manual
    enforcement_mode:
      description:
        - Specifies whether blocking is active or inactive for the ASM policy.
      returned: queried
      type: str
      sample: blocking
    trust_xff:
      description:
        - Indicates the system has confidence in an XFF (X-Forwarded-For) header in the request.
      returned: queried
      type: bool
      sample: true
    custom_xff_headers:
      description:
        - List of custom XFF headers trusted by the system.
      returned: queried
      type: str
      sample: asm-proxy1
    case_insensitive:
      description:
        - Indicates if the ASM policy treats file types, URLs, and parameters as case sensitive.
      returned: queried
      type: bool
      sample: true
    signature_staging:
      description:
        - Specifies if the staging feature is active on the ASM policy.
      returned: queried
      type: bool
      sample: true
    place_signatures_in_staging:
      description:
        - Specifies if the system places new or updated signatures in staging
          for the number of days specified in the enforcement readiness period.
      returned: queried
      type: bool
      sample: false
    enforcement_readiness_period:
      description:
        - Period in days both security policy entities and attack signatures
          remain in staging mode before the system suggests to enforce them.
      returned: queried
      type: int
      sample: 8
    path_parameter_handling:
      description:
        - Specifies how the system handles path parameters that are attached to path segments in URIs.
      returned: queried
      type: str
      sample: ignore
    trigger_asm_irule_event:
      description:
        - Indicates if iRule event is enabled.
      returned: queried
      type: str
      sample: disabled
    inspect_http_uploads:
      description:
        - Specifies whether the system should inspect all HTTP uploads.
      returned: queried
      type: bool
      sample: true
    mask_credit_card_numbers_in_request:
      description:
        - Indicates if the system masks credit card numbers.
      returned: queried
      type: bool
      sample: false
    maximum_http_header_length:
      description:
        - Maximum length of an HTTP header name and value that the system processes.
      returned: queried
      type: int
      sample: 8192
    use_dynamic_session_id_in_url:
      description:
        - Specifies how the security policy processes URLs that use dynamic sessions.
      returned: queried
      type: bool
      sample: false
    maximum_cookie_header_length:
      description:
        - Maximum length of a cookie header name and value that the system processes.
      returned: queried
      type: int
      sample: 8192
    application_language:
      description:
        - The language encoding for the web application.
      returned: queried
      type: str
      sample: utf-8
    disallowed_geolocations:
      description:
        - Displays countries that may not access the web application.
      returned: queried
      type: str
      sample: Argentina
    csrf_protection_enabled:
      description:
        - Specifies if CSRF protection is active on the ASM policy.
      returned: queried
      type: bool
      sample: true
    csrf_protection_ssl_only:
      description:
        - Specifies that only HTTPS URLs will be checked for CSRF protection.
      returned: queried
      type: bool
      sample: true
    csrf_protection_expiration_time_in_seconds:
      description:
        - Specifies how long, in seconds, a configured CSRF token is valid before it expires.
      returned: queried
      type: int
      sample: 600
    csrf_urls:
      description:
        - Specifies a list of URLs for CSRF token verification.
        - In version 13.0.0 and later, this has become a sub-collection and a list of dictionaries.
        - In version 12.x, this is a list of simple strings.
      returned: queried
      type: complex
      contains:
        csrf_url_required_parameters:
          description:
            - Indicates whether to ignore or require one of the specified parameters is present
              in a request when checking if the URL entry matches the request.
          returned: queried
          type: str
          sample: ignore
        csrf_url_parameters_list:
          description:
            - List of parameters to look for in a request when checking if the URL entry matches the request.
          returned: queried
          type: list
          sample: ['fooparam']
        csrf_url:
          description:
            - Specifies an URL to protect.
          returned: queried
          type: str
          sample: ['/foo.html']
        csrf_url_method:
          description:
            - Method for the specified URL.
          returned: queried
          type: str
          sample: POST
        csrf_url_enforcement_action:
          description:
            - Indicates the action specified for the system to take when the URL entry matches.
          returned: queried
          type: str
          sample: none
        csrf_url_id:
          description:
            - Specifies the generated ID for the configured CSRF URL resource.
          returned: queried
          type: str
          sample: l0Ckxe-7yHsXp8U5tTgbFQ
        csrf_url_wildcard_order:
          description:
            - Specifies the order in which the wildcard URLs are enforced.
          returned: queried
          type: str
          sample: 1
  sample: hash/dictionary of values
asm_server_technologies:
  description: Detailed information for ASM server technologies present on the device.
  returned: When C(asm-server-technologies) is specified in C(gather_subset).
  type: complex
  contains:
    id:
      description:
        - Displays the generated ID for the server technology resource.
      returned: queried
      type: str
      sample: l0Ckxe-7yHsXp8U5tTgbFQ
    server_technology_name:
      description:
        - Friendly name of the server technology resource.
      returned: queried
      type: str
      sample: Wordpress
    server_technology_references:
      description:
        - List of dictionaries containing API self links of the associated technology resources.
      returned: queried
      type: complex
      contains:
        link:
          description:
            - A self link to an associated server technology.
          returned: queried
          type: str
          sample: https://localhost/mgmt/tm/asm/server-technologies/NQG7CT02OBC2cQWbnP7T-A?ver=13.1.0
  sample: hash/dictionary of values
asm_signature_sets:
  description: Detailed information for ASM signature sets present on device.
  returned: When C(asm-signature-sets) is specified in C(gather_subset).
  type: complex
  contains:
    name:
      description:
        - Name of the signature set.
      returned: queried
      type: str
      sample: WebSphere signatures
    id:
      description:
        - Displays the generated ID for the signature set resource.
      returned: queried
      type: str
      sample: l0Ckxe-7yHsXp8U5tTgbFQ
    type:
      description:
        - The method used to select signatures to be a part of the signature set.
      returned: queried
      type: str
      sample: filter-based
    category:
      description:
        - Displays the category of the signature set.
      returned: queried
      type: str
      sample: filter-based
    is_user_defined:
      description:
        - Specifies this signature set was added by a user.
      returned: queried
      type: bool
      sample: false
    assign_to_policy_by_default:
      description:
        - Indicates whether the system assigns this signature set to a new created security policy by default.
      returned: queried
      type: bool
      sample: true
    default_alarm:
      description:
        - Displays whether the security policy logs the request data in the Statistics
          screen if a request matches a signature that is included in the signature set.
      returned: queried
      type: bool
      sample: true
    default_block:
      description:
        - When the security policy enforcement mode is Blocking, displays
          how the system treats requests that match a signature included in the signature set.
      returned: queried
      type: bool
      sample: true
    default_learn:
      description:
        - Displays whether the security policy learns all requests that match a signature
          that is included in the signature set.
      returned: queried
      type: bool
      sample: true
  sample: hash/dictionary of values
client_ssl_profiles:
  description: Client SSL Profile related information.
  returned: When C(client-ssl-profiles) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/bigip02.internal
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: bigip02.internal
    alert_timeout:
      description:
        - Maximum time period, in seconds, to keep the SSL session active after an alert
          message is sent, or indefinite.
      returned: queried
      type: int
      sample: 0
    allow_non_ssl:
      description:
        - Enables or disables non-SSL connections.
      returned: queried
      type: bool
      sample: true
    authenticate_depth:
      description:
        - Specifies the authenticate depth. This is the client certificate chain maximum traversal depth.
      returned: queried
      type: int
      sample: 9
    authenticate_frequency:
      description:
        - Specifies how often the system authenticates a user.
      returned: queried
      type: str
      sample: once
    ca_file:
      description:
        - Specifies the certificate authority (CA) file name.
      returned: queried
      type: str
      sample: /Common/default-ca.crt
    cache_size:
      description:
        - Specifies the SSL session cache size.
      returned: queried
      type: int
      sample: 262144
    cache_timeout:
      description:
        - Specifies the SSL session cache timeout value.
      returned: queried
      type: int
      sample: 3600
    certificate_file:
      description:
        - Specifies the name of the certificate installed on the traffic
          management system for the purpose of terminating or initiating
          an SSL connection.
      returned: queried
      type: str
      sample: /Common/default.crt
    key_file:
      description:
        - Specifies the name of the key installed on the traffic
          management system for the purpose of terminating or initiating
          an SSL connection.
      returned: queried
      type: str
      sample: /Common/default.key
    chain_file:
      description:
        - Specifies or builds a certificate chain file that a client can
          use to authenticate the profile.
      returned: queried
      type: str
      sample: /Common/ca-chain.crt
    ciphers:
      description:
        - Specifies a list of cipher names.
      returned: queried
      type: str
      sample: ['DEFAULT']
    crl_file:
      description:
        - Specifies the certificate revocation list file name.
      returned: queried
      type: str
      sample: /Common/default.crl
    parent:
      description:
        - Parent of the profile
      returned: queried
      type: str
      sample: /Common/clientssl
    description:
      description:
        - Description of the profile.
      returned: queried
      type: str
      sample: My profile
    modssl_methods:
      description:
        - Enables or disables ModSSL method emulation.
      returned: queried
      type: bool
      sample: false
    peer_certification_mode:
      description:
        - Specifies the peer certificate mode.
      returned: queried
      type: str
      sample: ignore
    sni_require:
      description:
        - When this option is C(true), a client connection that does not
          specify a known server name or does not support SNI extension will
          be rejected.
      returned: queried
      type: bool
      sample: false
    sni_default:
      description:
        - When C(true), this profile is the default SSL profile when the server
          name in a client connection does not match any configured server
          names, or a client connection does not specify any server name at
          all.
      returned: queried
      type: bool
      sample: true
    strict_resume:
      description:
        - Enables or disables strict-resume.
      returned: queried
      type: bool
      sample: true
    profile_mode_enabled:
      description:
        - Specifies the profile mode, which enables or disables SSL
          processing.
      returned: queried
      type: bool
      sample: true
    renegotiation_maximum_record_delay:
      description:
        - Maximum number of SSL records that the traffic
          management system can receive before it renegotiates an SSL
          session.
      returned: queried
      type: int
      sample: 0
    renegotiation_period:
      description:
        - Number of seconds required to renegotiate an SSL
          session.
      returned: queried
      type: int
      sample: 0
    renegotiation:
      description:
        - Specifies whether renegotiations are enabled.
      returned: queried
      type: bool
      sample: true
    server_name:
      description:
        - Specifies the server names to be matched with SNI (server name
          indication) extension information in ClientHello from a client
          connection.
      returned: queried
      type: str
      sample: bigip01
    session_ticket:
      description:
        - Enables or disables session-ticket.
      returned: queried
      type: bool
      sample: false
    unclean_shutdown:
      description:
        - Whether to force the SSL profile to perform a clean shutdown of all SSL
          connections or not
      returned: queried
      type: bool
      sample: false
    retain_certificate:
      description:
        - APM module requires storing certificate in SSL session. When
          C(false), certificate will not be stored in SSL session.
      returned: queried
      type: bool
      sample: true
    secure_renegotiation_mode:
      description:
        - Specifies the secure renegotiation mode.
      returned: queried
      type: str
      sample: require
    handshake_timeout:
      description:
        - Specifies the handshake timeout in seconds.
      returned: queried
      type: int
      sample: 10
    forward_proxy_certificate_extension_include:
      description:
        - Specifies the extensions of the web server certificates to be
          included in the generated certificates using SSL Forward Proxy.
      returned: queried
      type: list
      sample: ["basic-constraints", "subject-alternative-name"]
    forward_proxy_certificate_lifespan:
      description:
        - Specifies the lifespan of the certificate generated using the SSL
          forward proxy feature.
      returned: queried
      type: int
      sample: 30
    forward_proxy_lookup_by_ipaddr_port:
      description:
        - Specifies whether to perform certificate look up by IP address and
          port number.
      returned: queried
      type: bool
      sample: false
    forward_proxy_enabled:
      description:
        - Enables or disables SSL forward proxy feature.
      returned: queried
      type: bool
      sample: true
    forward_proxy_ca_passphrase:
      description:
        - Specifies the passphrase of the key file that is used as the
          certification authority key when SSL forward proxy feature is
          enabled.
      returned: queried
      type: str
    forward_proxy_ca_certificate_file:
      description:
        - Specifies the name of the certificate file that is used as the
          certification authority certificate when SSL forward proxy feature
          is enabled.
      returned: queried
      type: str
    forward_proxy_ca_key_file:
      description:
        - Specifies the name of the key file that is used as the
          certification authority key when SSL forward proxy feature is
          enabled.
      returned: queried
      type: str
  sample: hash/dictionary of values
devices:
  description: Device related information.
  returned: When C(devices) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/bigip02.internal
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: bigip02.internal
    active_modules:
      description:
        - The currently licensed and provisioned modules on the device.
      returned: queried
      type: list
      sample: ["DNS Services (LAB)", "PSM, VE"]
    base_mac_address:
      description:
        - Media Access Control address (MAC address) of the device.
      returned: queried
      type: str
      sample: "fa:16:3e:c3:42:6f"
    build:
      description:
        - The minor version information of the total product version.
      returned: queried
      type: str
      sample: 0.0.1
    chassis_id:
      description:
        - Serial number of the device.
      returned: queried
      type: str
      sample: 11111111-2222-3333-444444444444
    chassis_type:
      description:
        - Displays the chassis type. The possible values are C(individual) and C(viprion).
      returned: queried
      type: str
      sample: individual
    comment:
      description:
        - User comments about the device.
      returned: queried
      type: str
      sample: My device
    configsync_address:
      description:
        - IP address used for configuration synchronization.
      returned: queried
      type: str
      sample: 10.10.10.10
    contact:
      description:
        - Administrator contact information.
      returned: queried
      type: str
      sample: The User
    description:
      description:
        - Description of the device.
      returned: queried
      type: str
      sample: My device
    edition:
      description:
        - Displays the software edition.
      returned: queried
      type: str
      sample: Point Release 7
    failover_state:
      description:
        - Device failover state.
      returned: queried
      type: str
      sample: active
    hostname:
      description:
        - Device hostname
      returned: queried
      type: str
      sample: bigip02.internal
    location:
      description:
        - Specifies the physical location of the device.
      returned: queried
      type: str
      sample: London
    management_address:
      description:
        - IP address of the management interface.
      returned: queried
      type: str
      sample: 3.3.3.3
    marketing_name:
      description:
        - Marketing name of the device platform.
      returned: queried
      type: str
      sample: BIG-IP Virtual Edition
    multicast_address:
      description:
        - Specifies the multicast IP address used for failover.
      returned: queried
      type: str
      sample: 4.4.4.4
    optional_modules:
      description:
        - Modules that are available for the current platform, but are not currently licensed.
      returned: queried
      type: list
      sample: ["App Mode (TMSH Only, No Root/Bash)", "BIG-IP VE, Multicast Routing"]
    platform_id:
      description:
        - Displays the device platform identifier.
      returned: queried
      type: str
      sample: Z100
    primary_mirror_address:
      description:
        - Specifies the IP address used for state mirroring.
      returned: queried
      type: str
      sample: 5.5.5.5
    product:
      description:
        - Displays the software product name.
      returned: queried
      type: str
      sample: BIG-IP
    secondary_mirror_address:
      description:
        - Secondary IP address used for state mirroring.
      returned: queried
      type: str
      sample: 2.2.2.2
    self:
      description:
        - Whether or not this device is the one that was queried for information.
      returned: queried
      type: bool
      sample: true
    software_version:
      description:
        - Displays the software version number.
      returned: queried
      type: str
      sample: 13.1.0.7
    timelimited_modules:
      description:
        - Displays the licensed modules that are time-limited.
      returned: queried
      type: list
      sample: ["IP Intelligence, 3Yr, ...", "PEM URL Filtering, 3Yr, ..."]
    timezone:
      description:
        - Displays the time zone configured on the device.
      returned: queried
      type: str
      sample: UTC
    unicast_addresses:
      description:
        - Specifies the entire set of unicast addresses used for failover.
      returned: queried
      type: complex
      contains:
        effective_ip:
          description:
            - The IP address that peers can use to reach this unicast address IP.
          returned: queried
          type: str
          sample: 5.4.3.5
        effective_port:
          description:
            - The port that peers can use to reach this unicast address.
          returned: queried
          type: int
          sample: 1026
        ip:
          description:
            - The IP address the failover daemon will listen on for packets from its peers.
          returned: queried
          type: str
          sample: 5.4.3.5
        port:
          description:
            - The IP port the failover daemon uses to accept packets from its peers.
          returned: queried
          type: int
          sample: 1026
  sample: hash/dictionary of values
device_groups:
  description: Device group related information.
  returned: When C(device-groups) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/fasthttp
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: fasthttp
    autosync_enabled:
      description:
        - Whether the device group automatically synchronizes configuration data to its members.
      returned: queried
      type: bool
      sample: false
    description:
      description:
        - Description of the device group.
      returned: queried
      type: str
      sample: My device group
    devices:
      description:
        - List of devices in the group. Devices are listed by their C(full_path).
      returned: queried
      type: list
      sample: [/Common/bigip02.internal]
    full_load_on_sync:
      description:
        - Specifies the entire configuration for a device group is sent when configuration
          synchronization is performed.
      returned: queried
      type: bool
      sample: true
    incremental_config_sync_size_maximum:
      description:
        - Specifies the maximum size (in KB) to devote to incremental config sync cached transactions.
      returned: queried
      type: int
      sample: 1024
    network_failover_enabled:
      description:
        - Specifies whether network failover is used.
      returned: queried
      type: bool
      sample: true
    type:
      description:
        - Specifies the type of device group.
      returned: queried
      type: str
      sample: sync-only
    asm_sync_enabled:
      description:
        - Specifies whether to synchronize ASM configurations of device group members.
      returned: queried
      type: bool
      sample: true
  sample: hash/dictionary of values
external_monitors:
  description: External monitor related information.
  returned: When C(external-monitors) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/external
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: external
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: external
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My monitor
    destination:
      description:
        - Specifies the IP address and service port of the resource that is
          the destination of this monitor.
      returned: queried
      type: str
      sample: "*:*"
    args:
      description:
        - Specifies any command-line arguments the script requires.
      returned: queried
      type: str
      sample: arg1 arg2 arg3
    external_program:
      description:
        - Specifies the name of the file for the monitor to use.
      returned: queried
      type: str
      sample: /Common/arg_example
    variables:
      description:
        - Specifies any variables the script requires.
      type: dict
      sample: { "key1": "val", "key_2": "val 2" }
    interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when either the resource is down or the status
          of the resource is unknown.
      returned: queried
      type: int
      sample: 5
    manual_resume:
      description:
        - Specifies whether the system automatically changes the status of a
          resource to B(up) at the next successful monitor check.
      returned: queried
      type: bool
      sample: true
    time_until_up:
      description:
        - Specifies the amount of time, in seconds, after the first
          successful response before a node is marked up.
      returned: queried
      type: int
      sample: 0
    timeout:
      description:
        - Specifies the number of seconds the target has in which to respond
          to the monitor request.
      returned: queried
      type: int
      sample: 16
    up_interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when the resource is up.
      returned: queried
      type: int
      sample: 0
  sample: hash/dictionary of values
fasthttp_profiles:
  description: FastHTTP profile related information.
  returned: When C(fasthttp-profiles) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/fasthttp
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: fasthttp
    client_close_timeout:
      description:
        - Number of seconds after which the system closes a client connection, when
          the system either receives a client FIN packet or sends a FIN packet to the client.
      returned: queried
      type: int
      sample: 5
    oneconnect_idle_timeout_override:
      description:
        - Number of seconds after which a server-side connection in a OneConnect pool
          is eligible for deletion, when the connection has no traffic.
      returned: queried
      type: int
      sample: 0
    oneconnect_maximum_reuse:
      description:
        - Maximum number of times the system can re-use a current connection.
      returned: queried
      type: int
      sample: 0
    oneconnect_maximum_pool_size:
      description:
        - Maximum number of connections to a load balancing pool.
      returned: queried
      type: int
      sample: 2048
    oneconnect_minimum_pool_size:
      description:
        - Minimum number of connections to a load balancing pool.
      returned: queried
      type: int
      sample: 0
    oneconnect_replenish':
      description:
        - When C(true), specifies the system will not keep a steady-state maximum of
          connections to the back-end, unless the number of connections to the pool have
          dropped beneath the C(minimum_pool_size) specified in the profile.
      returned: queried
      type: bool
      sample: true
    oneconnect_ramp_up_increment:
      description:
        - The increment in which the system makes additional connections available, when
          all available connections are in use.
      returned: queried
      type: int
      sample: 4
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: fasthttp
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My profile
    force_http_1_0_response:
      description:
        - When C(true), specifies the server sends responses to clients in the HTTP/1.0
          format.
      returned: queried
      type: bool
      sample: false
    request_header_insert:
      description:
        - A string the system inserts as a header in an HTTP request. If the header
          already exists, the system does not replace it.
      returned: queried
      type: str
      sample: "X-F5-Authentication: foo"
    http_1_1_close_workarounds:
      description:
        - When C(true), specifies the server uses workarounds for HTTP 1.1 close issues.
      returned: queried
      type: bool
      sample: false
    idle_timeout:
      description:
        - Length of time that a connection is idle (has no traffic) before the connection
          is eligible for deletion.
      returned: queried
      type: int
      sample: 300
    insert_xforwarded_for:
      description:
        - Whether the system inserts the X-Forwarded-For header in an HTTP request with the
          client IP address, to use with connection pooling.
      returned: queried
      type: bool
      sample: false
    maximum_header_size:
      description:
        - Maximum amount of HTTP header data the system buffers before making a load
          balancing decision.
      returned: queried
      type: int
      sample: 32768
    maximum_requests:
      description:
        - Maximum number of requests the system can receive on a client-side connection,
          before the system closes the connection.
      returned: queried
      type: int
      sample: 0
    maximum_segment_size_override:
      description:
        - Maximum segment size (MSS) override for server-side connections.
      returned: queried
      type: int
      sample: 0
    receive_window_size:
      description:
        - Amount of data the BIG-IP system can accept without acknowledging the server.
      returned: queried
      type: int
      sample: 0
    reset_on_timeout:
      description:
        - When C(true), specifies the system sends a reset packet (RST) in addition to
          deleting the connection, when a connection exceeds the idle timeout value.
      returned: queried
      type: bool
      sample: true
    server_close_timeout:
      description:
        - Number of seconds after which the system closes a client connection, when the system
          either receives a server FIN packet or sends a FIN packet to the server.
      returned: queried
      type: int
      sample: 5
    server_sack:
      description:
        - Whether the BIG-IP system processes Selective ACK (Sack) packets in cookie responses
          from the server.
      returned: queried
      type: bool
      sample: false
    server_timestamp:
      description:
        - Whether the BIG-IP system processes timestamp request packets in cookie responses
          from the server.
      returned: queried
      type: bool
      sample: false
    unclean_shutdown:
      description:
        - How the system handles closing connections. Values provided may be C(enabled), C(disabled),
          or C(fast).
      returned: queried
      type: str
      sample: enabled
  sample: hash/dictionary of values
fastl4_profiles:
  description: FastL4 profile related information.
  returned: When C(fastl4-profiles) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/fastl4
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: fastl4
    client_timeout:
      description:
        - Specifies late binding client timeout in seconds.
        - This is the number of seconds allowed for a client to transmit enough data to
          select a server pool.
        - If this timeout expires, the timeout-recovery option dictates whether
          to drop the connection or fallback to the normal FastL4 load balancing method
          to pick a server pool.
      returned: queried
      type: int
      sample: 30
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: fastl4
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My profile
    explicit_flow_migration:
      description:
        - Specifies whether to have the iRule code determine exactly when
          the FIX stream drops down to the ePVA hardware.
      returned: queried
      type: bool
      sample: true
    hardware_syn_cookie:
      description:
        - Enables or disables hardware SYN cookie support when PVA10 is present on the system.
        - This option is deprecated in version 13.0.0 and is replaced by C(syn-cookie-enable).
      returned: queried
      type: bool
      sample: false
    idle_timeout:
      description:
        - Specifies the number of seconds a connection is idle before the connection is
          eligible for deletion.
        - Values are in the range of 0 to 4294967295 (inclusive).
        - C(0) is equivalent to the TMUI value "immediate".
        - C(4294967295) is equivalent to the TMUI value "indefinite".
      returned: queried
      type: int
      sample: 300
    dont_fragment_flag:
      description:
        - Describes the Don't Fragment (DF) bit setting in the IP Header of
          the outgoing TCP packet.
        - When C(pmtu), sets the outgoing IP Header DF bit based on the IP pmtu
          setting(tm.pathmtudiscovery).
        - When C(preserve), sets the outgoing packet's IP Header DF bit to be the same as
          the incoming IP Header DF bit.
        - When C(set), sets the outgoing packet's IP Header DF bit.
        - When C(clear), clears the outgoing packet's IP Header DF bit.
      returned: queried
      type: str
      sample: pmtu
    ip_tos_to_client:
      description:
        - Specifies an IP Type of Service (ToS) number for the client-side.
        - This option specifies the ToS level the traffic management
          system assigns to IP packets when sending them to clients.
      returned: queried
      type: str
      sample: 200
    ip_tos_to_server:
      description:
        - Specifies an IP ToS number for the server side.
        - This option specifies the ToS level the traffic management system assigns
          to IP packets when sending them to servers.
      returned: queried
      type: str
      sample: pass-through
    ttl_mode:
      description:
        - Describes the outgoing TCP packet's IP Header TTL mode.
        - When C(proxy), sets the outgoing IP Header TTL value to 255/64 for IPv4/IPv6
          respectively.
        - When C(preserve), sets the outgoing IP Header TTL value to be same as the
          incoming IP Header TTL value.
        - When C(decrement), sets the outgoing IP Header TTL value to be one less than
          the incoming TTL value.
        - When C(set), sets the outgoing IP Header TTL value to a specific value (as
          specified by C(ttl_v4) or C(ttl_v6).
      returned: queried
      type: str
      sample: preserve
    ttl_v4:
      description:
        - Specifies the outgoing packet's IP Header TTL value for IPv4 traffic.
        - Maximum value is 255.
      returned: queried
      type: int
      sample: 200
    ttl_v6:
      description:
        - Specify the outgoing packet's IP Header TTL value for IPv6.
          traffic.
        - Maximum value is 255.
      returned: queried
      type: int
      sample: 300
    keep_alive_interval:
      description:
        - Specifies the keep-alive probe interval, in seconds.
        - A value of 0 indicates keep-alive is disabled.
      returned: queried
      type: int
      sample: 10
    late_binding:
      description:
        - Specifies whether to enable or disable the intelligent selection of a
          back-end server pool.
      returned: queried
      type: bool
      sample: true
    link_qos_to_client:
      description:
        - Specifies a Link Quality of Service (QoS) (VLAN priority) number
          for the client side.
        - This option specifies the QoS level the system assigns to packets
          when sending them to clients.
      returned: queried
      type: int
      sample: 7
    link_qos_to_server:
      description:
        - Specifies a Link QoS (VLAN priority) number for the server side.
        - This option specifies the QoS level the system assigns to
          packets when sending them to servers.
      returned: queried
      type: int
      sample: 5
    loose_close:
      description:
        - Specifies the system closes a loosely-initiated connection
          when it receives the first FIN packet from either the
          client or the server.
      returned: queried
      type: bool
      sample: false
    loose_init:
      description:
        - Specifies the system initializes a connection when it
          receives any Transmission Control Protocol (TCP) packet, rather
          than requiring a SYN packet for connection initiation.
      returned: queried
      type: bool
      sample: true
    mss_override:
      description:
        - Specifies a maximum segment size (MSS) override for server
          connections. Note this is also the MSS advertised to a client
          when a client first connects.
        - C(0) (zero), means the option is disabled. Otherwise, the value will be
          between 256 and 9162.
      returned: queried
      type: int
      sample: 500
    priority_to_client:
      description:
        - Specifies the internal packet priority for the client side.
        - This option specifies the internal packet priority the system
          assigns to packets when sending them to clients.
      returned: queried
      type: int
      sample: 300
    priority_to_server:
      description:
        - Specifies the internal packet priority for the server side.
        - This option specifies the internal packet priority the system
          assigns to packets when sending them to servers.
      returned: queried
      type: int
      sample: 200
    pva_acceleration:
      description:
        - Specifies the Packet Velocity(r) ASIC acceleration policy.
      returned: queried
      type: str
      sample: full
    pva_dynamic_client_packets:
      description:
        - Specifies the number of client packets before dynamic ePVA
          hardware re-offloading occurs.
        - Values are between 0 and 10.
      returned: queried
      type: int
      sample: 8
    pva_dynamic_server_packets:
      description:
        - Specifies the number of server packets before dynamic ePVA
          hardware re-offloading occurs.
        - Values are between 0 and 10.
      returned: queried
      type: int
      sample: 5
    pva_flow_aging:
      description:
        - Specifies if automatic aging from ePVA flow cache is enabled or not.
      returned: queried
      type: bool
      sample: true
    pva_flow_evict:
      description:
        - Specifies if this flow can be evicted upon hash collision with a
          new flow learn snoop request.
      returned: queried
      type: bool
      sample: false
    pva_offload_dynamic:
      description:
        - Specifies whether PVA flow dynamic offloading is enabled or not.
      returned: queried
      type: bool
      sample: true
    pva_offload_state:
      description:
        - Specifies at what stage the ePVA performs hardware offload.
        - When C(embryonic), applies at TCP CSYN or the first client UDP packet.
        - When C(establish), applies TCP 3WAY handshaking or UDP CS round trip are
          confirmed.
      returned: queried
      type: str
      sample: embryonic
    reassemble_fragments:
      description:
        - Specifies whether to reassemble fragments.
      returned: queried
      type: bool
      sample: true
    receive_window:
      description:
        - Specifies the window size to use, in bytes.
        - The maximum is 2^31 for window scale enabling.
      returned: queried
      type: int
      sample: 1000
    reset_on_timeout:
      description:
        - Specifies whether you want to reset connections on timeout.
      returned: queried
      type: bool
      sample: true
    rtt_from_client:
      description:
        - Enables or disables the TCP timestamp options to measure the round
          trip time to the client.
      returned: queried
      type: bool
      sample: false
    rtt_from_server:
      description:
        - Enables or disables the TCP timestamp options to measure the round
          trip time to the server.
      returned: queried
      type: bool
      sample: true
    server_sack:
      description:
        - Specifies whether to support the server sack option in cookie responses
          by default.
      returned: queried
      type: bool
      sample: false
    server_timestamp:
      description:
        - Specifies whether to support the server timestamp option in cookie
          responses by default.
      returned: queried
      type: bool
      sample: true
    software_syn_cookie:
      description:
        - Enables or disables software SYN cookie support when PVA10 is not present
          on the system.
        - This option is deprecated in version 13.0.0 and is replaced by
          C(syn_cookie_enabled).
      returned: queried
      type: bool
      sample: true
    syn_cookie_enabled:
      description:
        - Enables syn-cookies capability on this virtual server.
      returned: queried
      type: bool
      sample: false
    syn_cookie_mss:
      description:
        - Specifies a maximum segment size (MSS) for server connections when
          SYN Cookie is enabled.
      returned: queried
      type: int
      sample: 2000
    syn_cookie_whitelist:
      description:
        - Specifies whether or not to use a SYN Cookie WhiteList when doing
          software SYN Cookies.
      returned: queried
      type: bool
      sample: false
    tcp_close_timeout:
      description:
        - Specifies a TCP close timeout in seconds.
      returned: queried
      type: int
      sample: 100
    generate_init_seq_number:
      description:
        - Specifies whether you want to generate TCP sequence numbers on all
          SYNs that conform with RFC1948, and allow timestamp recycling.
      returned: queried
      type: bool
      sample: true
    tcp_handshake_timeout:
      description:
        - Specifies a TCP handshake timeout in seconds.
      returned: queried
      type: int
      sample: 5
    strip_sack:
      description:
        - Specifies whether you want to block the TCP SackOK option from
          passing to the server on an initiating SYN.
      returned: queried
      type: bool
      sample: true
    tcp_time_wait_timeout:
      description:
        - Specifies a TCP time_wait timeout in milliseconds.
      returned: queried
      type: int
      sample: 60
    tcp_timestamp_mode:
      description:
        - Specifies how you want to handle the TCP timestamp.
      returned: queried
      type: str
      sample: preserve
    tcp_window_scale_mode:
      description:
        - Specifies how you want to handle the TCP window scale.
      returned: queried
      type: str
      sample: preserve
    timeout_recovery:
      description:
        - Specifies late binding timeout recovery mode. This is the action
          to take when late binding timeout occurs on a connection.
        - When C(disconnect), only the L7 iRule actions are acceptable to
          pick a server.
        - When C(fallback), the normal FastL4 load balancing methods are acceptable
          to pick a server.
      returned: queried
      type: str
      sample: fallback
  sample: hash/dictionary of values
gateway_icmp_monitors:
  description: Gateway ICMP monitor related information.
  returned: When C(gateway-icmp-monitors) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/gateway_icmp
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: gateway_icmp
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: gateway_icmp
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My monitor
    adaptive:
      description:
        - Whether adaptive response time monitoring is enabled for this monitor.
      returned: queried
      type: bool
      sample: false
    adaptive_divergence_type:
      description:
        - Specifies whether the adaptive-divergence-value is C(relative) or
          C(absolute).
      returned: queried
      type: str
      sample: relative
    adaptive_divergence_value:
      description:
        - Specifies how far from mean latency each monitor probe is allowed
          to be.
      returned: queried
      type: int
      sample: 25
    adaptive_limit:
      description:
        - Specifies the hard limit, in milliseconds, which the probe is not
          allowed to exceed, regardless of the divergence value.
      returned: queried
      type: int
      sample: 200
    adaptive_sampling_timespan:
      description:
        - Specifies the size of the sliding window, in seconds, which
          records probe history.
      returned: queried
      type: int
      sample: 300
    destination:
      description:
        - Specifies the IP address and service port of the resource that is
          the destination of this monitor.
      returned: queried
      type: str
      sample: "*:*"
    interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when either the resource is down or the status
          of the resource is unknown.
      returned: queried
      type: int
      sample: 5
    manual_resume:
      description:
        - Specifies whether the system automatically changes the status of a
          resource to (B)up at the next successful monitor check.
      returned: queried
      type: bool
      sample: true
    time_until_up:
      description:
        - Specifies the amount of time, in seconds, after the first
          successful response before a node is marked up.
      returned: queried
      type: int
      sample: 0
    timeout:
      description:
        - Specifies the number of seconds the target has in which to respond
          to the monitor request.
      returned: queried
      type: int
      sample: 16
    transparent:
      description:
        - Specifies whether the monitor operates in transparent mode.
      returned: queried
      type: bool
      sample: false
    up_interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when the resource is up.
      returned: queried
      type: int
      sample: 0
  sample: hash/dictionary of values
gtm_pools:
  description:
    - GTM pool related information.
    - Every "type" of pool has the exact same list of possible information. Therefore,
      the list of information here is presented once instead of 6 times.
  returned: When any of C(gtm-pools) or C(gtm-*-pools) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/pool1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: pool1
    alternate_mode:
      description:
        - The load balancing mode the system uses to load balance name resolution
          requests among the members of the pool.
      returned: queried
      type: str
      sample: drop-packet
    dynamic_ratio:
      description:
        - Specifies whether the dynamic ratio load balancing algorithm is enabled for this
          pool.
      returned: queried
      type: bool
      sample: true
    enabled:
      description:
        - Specifies the pool is enabled.
      returned: queried
      type: bool
    disabled:
      description:
        - Specifies the pool is disabled.
      returned: queried
      type: bool
    fallback_mode:
      description:
        - Specifies the load balancing mode the system uses to load balance
          name resolution among the pool members if the preferred and alternate
          modes are unsuccessful in picking a pool.
      returned: queried
      type: str
    load_balancing_mode:
      description:
        - Specifies the preferred load balancing mode the system uses to load
          balance requests across pool members.
      returned: queried
      type: str
    manual_resume:
      description:
        - Whether manual resume is enabled for this pool.
      returned: queried
      type: bool
    max_answers_returned:
      description:
        - Maximum number of available virtual servers the system lists in a
          response.
      returned: queried
      type: int
    members:
      description:
        - Lists of members (and their configurations) in the pool.
      returned: queried
      type: dict
    partition:
      description:
        - Partition on which the pool exists.
      returned: queried
      type: str
    qos_hit_ratio:
      description:
        - Weight of the Hit Ratio performance factor for the QoS dynamic load
          balancing method.
      returned: queried
      type: int
    qos_hops:
      description:
        - Weight of the Hops performance factor when load balancing mode or fallback mode
          is QoS.
      returned: queried
      type: int
    qos_kilobytes_second:
      description:
        - Weight assigned to the Kilobytes per Second performance factor when the load
           balancing option is QoS.
      returned: queried
      type: int
    qos_lcs:
      description:
        - Weight assigned to the Link Capacity performance factor when the load balacing
          option is QoS.
      returned: queried
      type: int
    qos_packet_rate:
      description:
        - Weight assigned to the Packet Rate performance factor when the load balacing
          option is QoS.
      returned: queried
      type: int
    qos_rtt:
      description:
        - Weight assigned to the Round Trip Time performance factor when the load balacing
          option is QoS.
      returned: queried
      type: int
    qos_topology:
      description:
        - Weight assigned to the Topology performance factor when the load balacing option
          is QoS.
      returned: queried
      type: int
    qos_vs_capacity:
      description:
        - Weight assigned to the Virtual Server performance factor when the load balacing
          option is QoS.
      returned: queried
      type: int
    qos_vs_score:
      description:
        - Weight assigned to the Virtual Server Score performance factor when the load balacing
          option is QoS.
      returned: queried
      type: int
    ttl:
      description:
        - Number of seconds the IP address, once found, is valid.
      returned: queried
      type: int
    verify_member_availability:
      description:
        - Whether or not the system verifies the availability of the members before
          sending a connection to them.
      returned: queried
      type: bool
  sample: hash/dictionary of values
gtm_servers:
  description:
    - GTM server related information.
  returned: When C(gtm-servers) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/server1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: server1
    datacenter:
      description:
        - Full name of the datacenter to which this server belongs.
      returned: queried
      type: str
    enabled:
      description:
        - Specifies the server is enabled.
      returned: queried
      type: bool
    disabled:
      description:
        - Specifies the server is disabled.
      returned: queried
      type: bool
    expose_route_domains:
      description:
        - Allow the GTM server to auto-discover the LTM virtual servers from all
          route domains.
      returned: queried
      type: bool
    iq_allow_path:
      description:
        - Whether the GTM uses this BIG-IP system to conduct a path probe before
          delegating traffic to it.
      returned: queried
      type: bool
    iq_allow_service_check:
      description:
        - Whether the GTM uses this BIG-IP system to conduct a service check probe
          before delegating traffic to it.
      returned: queried
      type: bool
    iq_allow_snmp:
      description:
        - Whether the GTM uses this BIG-IP system to conduct an SNMP probe
          before delegating traffic to it.
      returned: queried
      type: bool
    limit_cpu_usage:
      description:
        - For a server configured as a generic host, specifies the percent of CPU
          usage, otherwise this has no effect.
      returned: queried
      type: int
    limit_cpu_usage_status:
      description:
        - Whether C(limit_cpu_usage) is enabled for this server.
      returned: queried
      type: bool
    limit_max_bps:
      description:
        - Maximum allowable data throughput rate in bits per second for this server.
      returned: queried
      type: int
    limit_max_bps_status:
      description:
        - Whether C(limit_max_bps) is enabled for this server.
      returned: queried
      type: bool
    limit_max_connections:
      description:
        - Maximum number of concurrent connections, combined, for this server.
      returned: queried
      type: int
    limit_max_connections_status:
      description:
        - Whether C(limit_max_connections) is enabled for this server.
      type: bool
    limit_max_pps:
      description:
        - Maximum allowable data transfer rate for this server, in packets per second.
      returned: queried
      type: int
    limit_max_pps_status:
      description:
        - Whether C(limit_max_pps) is enabled for this server.
      returned: queried
      type: bool
    limit_mem_available:
      description:
        - For a server configured as a generic host, specifies the available memory
          required by the virtual servers on the server.
        - If available memory falls below this limit, the system marks the server as
          unavailable.
      returned: queried
      type: int
    limit_mem_available_status:
      description:
        - Whether C(limit_mem_available) is enabled for this server.
      returned: queried
      type: bool
    link_discovery:
      description:
        - Specifies whether the system auto-discovers the links for this server.
      returned: queried
      type: str
    monitors:
      description:
        - Specifies health monitors that the system uses to determine whether this
          server is available for load balancing.
      returned: queried
      type: list
      sample: ['/Common/https_443', '/Common/icmp']
    monitor_type:
      description:
        - Whether one or more monitors need to pass, or all monitors need to pass.
      returned: queried
      type: str
      sample: and_list
    product:
      description:
        - Specifies the server type.
      returned: queried
      type: str
    prober_fallback:
      description:
        - The type of prober to use to monitor this server's resources when the
          preferred type is not available.
      returned: queried
      type: str
    prober_preference:
      description:
        - Specifies the type of prober to use to monitor this server's resources.
      returned: queried
      type: str
    virtual_server_discovery:
      description:
        - Whether the system auto-discovers the virtual servers for this server.
      returned: queried
      type: str
    addresses:
      description:
        - Specifies the server IP addresses.
      returned: queried
      type: dict
    devices:
      description:
        - Specifies the names of the devices that represent this server.
      returned: queried
      type: dict
    virtual_servers:
      description:
        - Specifies the virtual servers that are resources for this server.
      returned: queried
      type: dict
  sample: hash/dictionary of values
gtm_wide_ips:
  description:
    - GTM Wide IP related information.
    - Every "type" of Wide IP has the exact same list of possible information. Therefore,
      the list of information here is presented once instead of 6 times.
  returned: When any of C(gtm-wide-ips) or C(gtm-*-wide-ips) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/wide1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: wide1
    description:
      description:
        - Description of the Wide IP.
      returned: queried
      type: str
    enabled:
      description:
        - Whether the Wide IP is enabled.
      returned: queried
      type: bool
    disabled:
      description:
        - Whether the Wide IP is disabled.
      returned: queried
      type: bool
    failure_rcode:
      description:
        - Specifies the DNS RCODE used when C(failure_rcode_response) is C(true).
      returned: queried
      type: int
    failure_rcode_response:
      description:
        - When C(true), specifies the system returns a RCODE response to
          Wide IP requests after exhausting all load balancing methods.
      returned: queried
      type: bool
    failure_rcode_ttl:
      description:
        - Specifies the negative caching TTL of the SOA for the RCODE response.
      returned: queried
      type: int
    last_resort_pool:
      description:
        - Specifies which pool, as listed in Pool List, for the system to use as
          the last resort pool for the Wide IP.
      returned: queried
      type: str
    minimal_response:
      description:
        - Specifies the system forms the smallest allowable DNS response to
          a query.
      returned: queried
      type: str
    persist_cidr_ipv4:
      description:
        - Specifies the number of bits the system uses to identify IPv4 addresses
          when persistence is enabled.
      returned: queried
      type: int
    persist_cidr_ipv6:
      description:
        - Specifies the number of bits the system uses to identify IPv6 addresses
          when persistence is enabled.
      returned: queried
      type: int
    pool_lb_mode:
      description:
        - Specifies the load balancing method used to select a pool in this Wide IP.
      returned: queried
      type: str
    ttl_persistence:
      description:
        - Specifies, in seconds, the length of time for which the persistence
          entry is valid.
      returned: queried
      type: int
    pools:
      description:
        - Specifies the pools this Wide IP uses for load balancing.
      returned: queried
      type: dict
  sample: hash/dictionary of values
gtm_topology_regions:
  description: GTM regions related information.
  returned: When C(gtm-topology-regions) is specified in C(gather_subset)
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/region1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: region1
    region_members:
      description:
        - The list of region members.
      type: complex
      contains:
        negate:
          description:
            - Indicates if the region member is a C(IS-NOT) negative. In a BIG-IP configuration, the
              region members can be C(IS) or C(IS-NOT).
          returned: when configured for the region member.
          type: bool
          sample: true
        subnet:
          description:
            - An IP address and network mask in the CIDR format.
          type: str
          returned: when configured for the region member.
          sample: 10.10.10.0/24
        region:
          description:
            - The name of region already defined in the configuration.
          type: str
          returned: when configured for the region member.
          sample: /Common/region1
        continent:
          description:
            - The name of one of the seven continents in ISO format, along with the C(Unknown) setting.
          type: str
          returned: when configured for the region member.
          sample: AF
        country:
          description:
            - The country name returned as an ISO country code.
            - Valid country codes can be found here https://countrycode.org/.
          type: str
          returned: when configured for the region member.
          sample: US
        state:
          description:
            - The state in a given country.
          type: str
          returned: when configured for the region member.
          sample: "AD/Sant Julia de Loria"
        pool:
          description:
            - The name of a GTM pool already defined in the configuration.
          type: str
          returned: when configured for the region member.
          sample: /Common/pool1
        datacenter:
          description:
            - The name of a GTM data center already defined in the configuration.
          type: str
          returned: when configured for the region member.
          sample: /Common/dc1
        isp:
          description:
            - Specifies an Internet service provider.
          type: str
          returned: when configured for the region member.
          sample: /Common/AOL
        geo_isp:
          description:
            - Specifies a geolocation ISP.
          type: str
          returned: when configured for the region member.
          sample: /Common/FOO_ISP
      sample: hash/dictionary of values
  sample: hash/dictionary of values
http_monitors:
  description: HTTP monitor related information.
  returned: When C(http-monitors) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/http
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: http
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: http
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My monitor
    adaptive:
      description:
        - Whether adaptive response time monitoring is enabled for this monitor.
      returned: queried
      type: bool
      sample: false
    adaptive_divergence_type:
      description:
        - Specifies whether the adaptive-divergence-value is C(relative) or
          C(absolute).
      returned: queried
      type: str
      sample: relative
    adaptive_divergence_value:
      description:
        - Specifies how far from mean latency each monitor probe is allowed
          to be.
      returned: queried
      type: int
      sample: 25
    adaptive_limit:
      description:
        - Specifies the hard limit, in milliseconds, which the probe is not
          allowed to exceed, regardless of the divergence value.
      returned: queried
      type: int
      sample: 200
    adaptive_sampling_timespan:
      description:
        - Specifies the size of the sliding window, in seconds, which
          records probe history.
      returned: queried
      type: int
      sample: 300
    destination:
      description:
        - Specifies the IP address and service port of the resource that is
          the destination of this monitor.
      returned: queried
      type: str
      sample: "*:*"
    interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when either the resource is down or the status
          of the resource is unknown.
      returned: queried
      type: int
      sample: 5
    ip_dscp:
      description:
        - Specifies the differentiated services code point (DSCP).
      returned: queried
      type: int
      sample: 0
    manual_resume:
      description:
        - Specifies whether the system automatically changes the status of a
          resource to (B)up at the next successful monitor check.
      returned: queried
      type: bool
      sample: true
    receive_string:
      description:
        - Specifies the text string the monitor looks for in the
          returned resource.
      returned: queried
      type: str
      sample: check string
    receive_disable_string:
      description:
        - Specifies a text string the monitor looks for in the returned
          resource. If the text string is matched in the returned resource,
          the corresponding node or pool member is marked session disabled.
      returned: queried
      type: str
      sample: check disable string
    reverse:
      description:
        - Specifies whether the monitor operates in reverse mode. When the
          monitor is in reverse mode, a successful check marks the monitored
          object down instead of up.
      returned: queried
      type: bool
      sample: false
    send_string:
      description:
        - Specifies the text string the monitor sends to the target
          object.
      returned: queried
      type: str
      sample: "GET /\\r\\n"
    time_until_up:
      description:
        - Specifies the amount of time, in seconds, after the first
          successful response before a node is marked up.
      returned: queried
      type: int
      sample: 0
    timeout:
      description:
        - Specifies the number of seconds the target has in which to respond
          to the monitor request.
      returned: queried
      type: int
      sample: 16
    transparent:
      description:
        - Specifies whether the monitor operates in transparent mode.
      returned: queried
      type: bool
      sample: false
    up_interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when the resource is up.
      returned: queried
      type: int
      sample: 0
    username:
      description:
        - Specifies the username, if the monitored target requires
          authentication.
      returned: queried
      type: str
      sample: user1
  sample: hash/dictionary of values
https_monitors:
  description: HTTPS monitor related information.
  returned: When C(https-monitors) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/http
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: http
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: http
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My monitor
    adaptive:
      description:
        - Whether adaptive response time monitoring is enabled for this monitor.
      returned: queried
      type: bool
      sample: false
    adaptive_divergence_type:
      description:
        - Specifies whether the adaptive-divergence-value is C(relative) or
          C(absolute).
      returned: queried
      type: str
      sample: relative
    adaptive_divergence_value:
      description:
        - Specifies how far from mean latency each monitor probe is allowed
          to be.
      returned: queried
      type: int
      sample: 25
    adaptive_limit:
      description:
        - Specifies the hard limit, in milliseconds, which the probe is not
          allowed to exceed, regardless of the divergence value.
      returned: queried
      type: int
      sample: 200
    adaptive_sampling_timespan:
      description:
        - Specifies the size of the sliding window, in seconds, which
          records probe history.
      returned: queried
      type: int
      sample: 300
    destination:
      description:
        - Specifies the IP address and service port of the resource that is
          the destination of this monitor.
      returned: queried
      type: str
      sample: "*:*"
    interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when either the resource is down or the status
          of the resource is unknown.
      returned: queried
      type: int
      sample: 5
    ip_dscp:
      description:
        - Specifies the differentiated services code point (DSCP).
      returned: queried
      type: int
      sample: 0
    manual_resume:
      description:
        - Specifies whether the system automatically changes the status of a
          resource to up at the next successful monitor check.
      returned: queried
      type: bool
      sample: true
    receive_string:
      description:
        - Specifies the text string the monitor looks for in the
          returned resource.
      returned: queried
      type: str
      sample: check string
    receive_disable_string:
      description:
        - Specifies a text string the monitor looks for in the returned
          resource. If the text string is matched in the returned resource,
          the corresponding node or pool member is marked session disabled.
      returned: queried
      type: str
      sample: check disable string
    reverse:
      description:
        - Specifies whether the monitor operates in reverse mode. When the
          monitor is in reverse mode, a successful check marks the monitored
          object down instead of up.
      returned: queried
      type: bool
      sample: false
    send_string:
      description:
        - Specifies the text string the monitor sends to the target
          object.
      returned: queried
      type: str
      sample: "GET /\\r\\n"
    ssl_profile:
      description:
        - Specifies the SSL profile to use for the HTTPS monitor.
      returned: queried
      type: str
      sample: /Common/serverssl
    time_until_up:
      description:
        - Specifies the amount of time, in seconds, after the first
          successful response before a node is marked up.
      returned: queried
      type: int
      sample: 0
    timeout:
      description:
        - Specifies the number of seconds the target has in which to respond
          to the monitor request.
      returned: queried
      type: int
      sample: 16
    transparent:
      description:
        - Specifies whether the monitor operates in transparent mode.
      returned: queried
      type: bool
      sample: false
    up_interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when the resource is up.
      returned: queried
      type: int
      sample: 0
    username:
      description:
        - Specifies the username, if the monitored target requires
          authentication.
      returned: queried
      type: str
      sample: user1
  sample: hash/dictionary of values
http_profiles:
  description: HTTP profile related information.
  returned: When C(http-profiles) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/http
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: http
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: http
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My profile
    accept_xff:
      description:
        - Enables or disables trusting the client IP address, and statistics
          from the client IP address, based on the request's X-Forwarded-For
          (XFF) headers, if they exist.
      returned: queried
      type: bool
      sample: true
    allow_truncated_redirects:
      description:
        - Specifies the pass-through behavior when a redirect lacking the
          trailing carriage-return and line feed pair at the end of the headers
          is parsed.
        - When C(false), the system will silently drop the invalid HTTP.
      returned: queried
      type: bool
      sample: false
    excess_client_headers:
      description:
        - Specifies the pass-through behavior when the C(max_header_count) value is
          exceeded by the client.
        - When C(reject), the system rejects the connection.
      returned: queried
      type: str
      sample: reject
    excess_server_headers:
      description:
        - Specifies the pass-through behavior when C(max_header_count) value is
          exceeded by the server.
        - When C(reject), the system rejects the connection.
      returned: queried
      type: str
      sample: reject
    known_methods:
      description:
        - Optimizes the behavior of a known HTTP method in the list.
        - The default methods include the following HTTP/1.1 methods. CONNECT,
          DELETE, GET, HEAD, LOCK, OPTIONS, POST, PROPFIND, PUT, TRACE, UNLOCK.
        - If a known method is deleted from the C(known_methods) list, the
          BIG-IP system applies the C(unknown_method) setting to manage that traffic.
      returned: queried
      type: list
      sample: ['CONNECT', 'DELETE', ...]
    max_header_count:
      description:
        - Specifies the maximum number of headers the system supports.
      returned: queried
      type: int
      sample: 64
    max_header_size:
      description:
        - Specifies the maximum size, in bytes, the system allows for all HTTP
          request headers combined, including the request line.
      returned: queried
      type: int
      sample: 32768
    max_requests:
      description:
        - Specifies the number of requests the system accepts on a per-connection
          basis.
      returned: queried
      type: int
      sample: 0
    oversize_client_headers:
      description:
        - Specifies the pass-through behavior when the C(max_header_size) value
          is exceeded by the client.
      returned: queried
      type: str
      sample: reject
    oversize_server_headers:
      description:
        - Specifies the pass-through behavior when the C(max_header_size) value
          is exceeded by the server.
      returned: queried
      type: str
      sample: reject
    pipeline_action:
      description:
        - Enables or disables HTTP/1.1 pipelining.
      returned: queried
      type: str
      sample: allow
    unknown_method:
      description:
        - Specifies the behavior (allow, reject, or pass through) when an unknown
          HTTP method is parsed.
      returned: queried
      type: str
      sample: allow
    default_connect_handling:
      description:
        - Specifies the behavior of the proxy service when handling outbound requests.
      returned: queried
      type: str
      sample: deny
    hsts_include_subdomains:
      description:
        - When C(true), applies the HSTS policy to the HSTS host and its subdomains.
      returned: queried
      type: bool
      sample: true
    hsts_enabled:
      description:
        - When C(true), enables the HTTP Strict Transport Security settings.
      returned: queried
      type: bool
      sample: true
    insert_xforwarded_for:
      description:
        - When C(true), specifies the system inserts an X-Forwarded-For header in
          an HTTP request with the client IP address, to use with connection pooling.
      returned: queried
      type: bool
      sample: false
    lws_max_columns:
      description:
        - Specifies the maximum column width for any given line, when inserting an HTTP
          header in an HTTP request.
      returned: queried
      type: int
      sample: 80
    onconnect_transformations:
      description:
        - When C(true), specifies the system performs HTTP header transformations
          for the purpose of keeping connections open.
      returned: queried
      type: bool
      sample: true
    proxy_mode:
      description:
        - Specifies the proxy mode for this profile. Either reverse, explicit, or transparent.
      returned: queried
      type: str
      sample: reverse
    redirect_rewrite:
      description:
        - Specifies whether the system rewrites the URIs that are part of HTTP
          redirect (3XX) responses.
      returned: queried
      type: str
      sample: none
    request_chunking:
      description:
        - Specifies how the system handles HTTP content that is chunked by a client.
      returned: queried
      type: str
      sample: preserve
    response_chunking:
      description:
        - Specifies how the system handles HTTP content that is chunked by a server.
      returned: queried
      type: str
      sample: selective
    server_agent_name:
      description:
        - Specifies the string used as the server name in traffic generated by LTM.
      returned: queried
      type: str
      sample: BigIP
    sflow_poll_interval:
      description:
        - The maximum interval in seconds between two pollings.
      returned: queried
      type: int
      sample: 0
    sflow_sampling_rate:
      description:
        - Specifies the ratio of packets observed to the samples generated.
      returned: queried
      type: int
      sample: 0
    via_request:
      description:
        - Specifies whether to Remove, Preserve, or Append Via headers included in
          a client request to an origin web server.
      returned: queried
      type: str
      sample: preserve
    via_response:
      description:
        - Specifies whether to Remove, Preserve, or Append Via headers included in
          an origin web server response to a client.
      returned: queried
      type: str
      sample: preserve
  sample: hash/dictionary of values
iapp_services:
  description: iApp v1 service related information.
  returned: When C(iapp-services) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/service1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: service1
    device_group:
      description:
        - The device group the iApp service is part of.
      returned: queried
      type: str
      sample: /Common/dg1
    inherited_device_group:
      description:
        - Whether the device group is inherited or not.
      returned: queried
      type: bool
      sample: true
    inherited_traffic_group:
      description:
        - Whether the traffic group is inherited or not.
      returned: queried
      type: bool
      sample: true
    strict_updates:
      description:
        - Whether strict updates are enabled or not.
      returned: queried
      type: bool
      sample: true
    template_modified:
      description:
        - Whether template the service is based on is modified from its
          default value, or not.
      returned: queried
      type: bool
      sample: true
    traffic_group:
      description:
        - Traffic group the service is a part of.
      returned: queried
      type: str
      sample: /Common/tg
    tables:
      description:
        - List of the tabular data used to create the service.
      returned: queried
      type: list
      sample: [{"name": "basic__snatpool_members"},...]
    variables:
      description:
        - List of the variable data used to create the service.
      returned: queried
      type: list
      sample: [{"name": "afm__policy"},{"encrypted": "no"},{"value": "/#no_not_use#"},...]
    metadata:
      description:
        - List of the metadata data used to create the service.
      returned: queried
      type: list
      sample: [{"name": "var1"},{"persist": "true"},...]
    lists:
      description:
        - List of the lists data used to create the service.
      returned: queried
      type: list
      sample: [{"name": "irules__irules"},{"value": []},...]
    description:
      description:
        - Description of the service.
      returned: queried
      type: str
      sample: My service
  sample: hash/dictionary of values
icmp_monitors:
  description: ICMP monitor related information.
  returned: When C(icmp-monitors) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/icmp
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: icmp
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: icmp
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My monitor
    adaptive:
      description:
        - Whether adaptive response time monitoring is enabled for this monitor.
      returned: queried
      type: bool
      sample: false
    adaptive_divergence_type:
      description:
        - Specifies whether the adaptive-divergence-value is C(relative) or
          C(absolute).
      returned: queried
      type: str
      sample: relative
    adaptive_divergence_value:
      description:
        - Specifies how far from mean latency each monitor probe is allowed
          to be.
      returned: queried
      type: int
      sample: 25
    adaptive_limit:
      description:
        - Specifies the hard limit, in milliseconds, which the probe is not
          allowed to exceed, regardless of the divergence value.
      returned: queried
      type: int
      sample: 200
    adaptive_sampling_timespan:
      description:
        - Specifies the size of the sliding window, in seconds, which
          records probe history.
      returned: queried
      type: int
      sample: 300
    destination:
      description:
        - Specifies the IP address and service port of the resource that is
          the destination of this monitor.
      returned: queried
      type: str
      sample: "*:*"
    interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when either the resource is down or the status
          of the resource is unknown.
      returned: queried
      type: int
      sample: 5
    manual_resume:
      description:
        - Specifies whether the system automatically changes the status of a
          resource to (B)up at the next successful monitor check.
      type: bool
      sample: true
    time_until_up:
      description:
        - Specifies the amount of time, in seconds, after the first
          successful response before a node is marked up.
      returned: queried
      type: int
      sample: 0
    timeout:
      description:
        - Specifies the number of seconds the target has in which to respond
          to the monitor request.
      returned: queried
      type: int
      sample: 16
    transparent:
      description:
        - Specifies whether the monitor operates in transparent mode.
      returned: queried
      type: bool
      sample: false
    up_interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when the resource is up.
      returned: queried
      type: int
      sample: 0
  sample: hash/dictionary of values
interfaces:
  description: Interface related information.
  returned: When C(interfaces) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/interface1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: interface1
    active_media_type:
      description:
        - Displays the current media setting for the interface.
      returned: queried
      type: str
      sample: 100TX-FD
    flow_control:
      description:
        - Specifies how the system controls the sending of PAUSE frames for
          flow control.
      returned: queried
      type: str
      sample: tx-rx
    description:
      description:
        - Description of the interface.
      returned: queried
      type: str
      sample: My interface
    bundle:
      description:
        - The bundle capability on the port.
      returned: queried
      type: str
      sample: not-supported
    bundle_speed:
      description:
        - The bundle-speed on the port when bundle capability is
          enabled.
      returned: queried
      type: str
      sample: 100G
    enabled:
      description:
        - Whether the interface is enabled or not.
      returned: queried
      type: bool
      sample: true
    if_index:
      description:
        - The index assigned to this interface.
      returned: queried
      type: int
      sample: 32
    mac_address:
      description:
        - Displays the 6-byte ethernet address in non-case-sensitive
          hexadecimal colon notation.
      returned: queried
      type: str
      sample: "00:0b:09:88:00:9a"
    media_sfp:
      description:
        - The settings for an SFP (pluggable) interface.
      returned: queried
      type: str
      sample: auto
    lldp_admin:
      description:
        - Sets the sending or receiving of LLDP packets on that interface.
          Should be one of C(disable), C(txonly), C(rxonly) or C(txrx).
      returned: queried
      type: str
      sample: txonly
    mtu:
      description:
        - Displays the Maximum Transmission Unit (MTU) of the interface,
          which is the maximum number of bytes in a frame without IP
          fragmentation.
      returned: queried
      type: int
      sample: 1500
    prefer_port:
      description:
        - Indicates which side of a combo port the interface uses, if both
          sides of the port have the potential for external links.
      returned: queried
      type: str
      sample: sfp
    sflow_poll_interval:
      description:
        - Specifies the maximum interval in seconds between two
          pollings.
      returned: queried
      type: int
      sample: 0
    sflow_poll_interval_global:
      description:
        - Specifies whether the global interface poll-interval setting
          overrides the object-level poll-interval setting.
      returned: queried
      type: bool
      sample: true
    stp_auto_edge_port:
      description:
        - STP edge port detection.
      returned: queried
      type: bool
      sample: true
    stp_enabled:
      description:
        - Whether STP is enabled or not.
      returned: queried
      type: bool
      sample: false
    stp_link_type:
      description:
        - Specifies the STP link type for the interface.
      returned: queried
      type: str
      sample: auto
  sample: hash/dictionary of values
irules:
  description: iRule related information.
  returned: When C(irules) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/irule1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: irule1
    ignore_verification:
      description:
        - Whether the verification of the iRule should be ignored or not.
      returned: queried
      type: bool
      sample: false
    checksum:
      description:
        - Checksum of the iRule as calculated by BIG-IP.
      returned: queried
      type: str
      sample: d41d8cd98f00b204e9800998ecf8427e
    definition:
      description:
        - The actual definition of the iRule.
      returned: queried
      type: str
      sample: when HTTP_REQUEST ...
    signature:
      description:
        - The calculated signature of the iRule.
      returned: queried
      type: str
      sample: WsYy2M6xMqvosIKIEH/FSsvhtWMe6xKOA6i7f...
  sample: hash/dictionary of values
license:
  description: License related info.
  returned: When C(license) is specified in C(gather_subset).
  type: complex
  contains:
    license_start_date:
      description:
        - Specifies the date on whichthe license was issued.
      returned: queried
      type: str
      sample: 2022/11/21
    license_end_date:
      description:
        - Specifies the date on which the license is no longer valid.
      returned: queried
      type: str
      sample: 2022/12/30
    licensed_on_date:
      description:
        - Specifies the date on which the license was activated.
      returned: queried
      type: str
      sample: 2022/11/22
    licensed_version:
      description:
        - Specifies the version of the device that is using this license.
      returned: queried
      type: str
      sample: 15.1.2
    max_permitted_version:
      description:
        - Specifies the maximum version to which this license can be applied.
      returned: queried
      type: str
      sample: 18.*.*
    min_permitted_version:
      description:
        - Specifies the minimum version to which this license can be applied.
      returned: queried
      type: str
      sample: 5.*.*
    platform_id:
      description:
        - Specifies the platform id for which the license was activated.
      returned: queried
      type: str
      sample: Z100k
    registration_key:
      description:
        - Specifies the registration key associated with the license.
      returned: queried
      type: str
      sample: XXXX-XXXX-XXXX-XXXX-XXXX
    service_check_date:
      description:
        - Specifies the last date the license was last activated.
      returned: queried
      type: str
      sample: 2022/11/30
    active_modules:
      description:
        - Specifies the modules that are activated by the license.
      returned: queried
      type: list
      sample: [{"key":"A123456-9876543", "featureModules":"{}"}, ...]
  sample: hash/dictionary of values
ltm_pools:
  description: List of LTM (Local Traffic Manager) pools.
  returned: When C(ltm-pools) is specified in C(gather_subset).
  type: complex
  contains:
    active_member_count:
      description:
        - The number of active pool members in the pool.
      returned: queried
      type: int
      sample: 3
    all_avg_queue_entry_age:
      description:
        - Average queue entry age, for both the pool and its members.
      returned: queried
      type: int
      sample: 5
    all_max_queue_entry_age_ever:
      description:
        - Maximum queue entry age ever, for both the pool and its members.
      returned: queried
      type: int
      sample: 2
    all_max_queue_entry_age_recently:
      description:
        - Maximum queue entry age recently, for both the pool and its members.
      returned: queried
      type: int
      sample: 5
    all_num_connections_queued_now:
      description:
        - Number of connections queued now, for both the pool and its members.
      returned: queried
      type: int
      sample: 20
    all_num_connections_serviced:
      description:
        - Number of connections serviced, for both the pool and its members.
      returned: queried
      type: int
      sample: 15
    all_queue_head_entry_age:
      description:
        - Queue head entry age, for both the pool and its members.
      returned: queried
      type: int
      sample: 4
    available_member_count:
      description:
        - The number of available pool members in the pool.
      returned: queried
      type: int
      sample: 4
    availability_status:
      description:
        - The availability of the pool.
      returned: queried
      type: str
      sample: offline
    allow_nat:
      description:
        - Whether NATs are automatically enabled or disabled for any connections using this pool.
      returned: queried
      type: bool
      sample: true
    allow_snat:
      description:
        - Whether SNATs are automatically enabled or disabled for any connections using this pool.
      returned: queried
      type: bool
      sample: true
    client_ip_tos:
      description:
        - Whether the system sets a Type of Service (ToS) level within a packet sent to the client,
          based on the targeted pool.
        - Values can range from C(0) to C(255), or be set to C(pass-through) or C(mimic).
      returned: queried
      type: str
      sample: pass-through
    client_link_qos:
      description:
        - Whether the system sets a Quality of Service (QoS) level within a packet sent to the client,
          based on the targeted pool.
        - Values can range from C(0) to C(7), or be set to C(pass-through).
      returned: queried
      type: str
      sample: pass-through
    current_sessions:
      description:
        - Current sessions.
      returned: queried
      type: int
      sample: 2
    description:
      description:
        - Description of the pool.
      returned: queried
      type: str
      sample: my pool
    enabled_status:
      description:
        - The enabled status of the pool.
      returned: queried
      type: str
      sample: enabled
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/pool1
    ignore_persisted_weight:
      description:
        - Specifies not to count the weight of persisted connections on pool members when making load balancing decisions.
      returned: queried
      type: bool
      sample: false
    lb_method:
      description:
        - Load balancing method used by the pool.
      returned: queried
      type: str
      sample: round-robin
    member_count:
      description:
        - Total number of members in the pool.
      returned: queried
      type: int
      sample: 50
    metadata:
      description:
        - Dictionary of arbitrary key/value pairs set on the pool.
      returned: queried
      type: dict
      sample: hash/dictionary of values
    minimum_active_members:
      description:
        - Whether the system load balances traffic according to the priority number assigned to the pool member.
        - This parameter is identical to C(priority_group_activation) and is just an alias for it.
      returned: queried
      type: int
      sample: 2
    minimum_up_members:
      description:
        - The minimum number of pool members that must be up.
      returned: queried
      type: int
      sample: 1
    minimum_up_members_action:
      description:
        - The action to take if the C(minimum_up_members_checking) is enabled and the number of active pool
          members falls below the number specified in C(minimum_up_members).
      returned: queried
      type: str
      sample: failover
    minimum_up_members_checking:
      description:
        - Enables or disables the C(minimum_up_members) feature.
      returned: queried
      type: bool
      sample: false
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: pool1
    pool_avg_queue_entry_age:
      description:
        - Average queue entry age, for the pool only.
      returned: queried
      type: int
      sample: 5
    pool_max_queue_entry_age_ever:
      description:
        - Maximum queue entry age ever, for the pool only.
      returned: queried
      type: int
      sample: 2
    pool_max_queue_entry_age_recently:
      description:
        - Maximum queue entry age recently, for the pool only.
      returned: queried
      type: int
      sample: 5
    pool_num_connections_queued_now:
      description:
        - Number of connections queued now, for the pool only.
      returned: queried
      type: int
      sample: 20
    pool_num_connections_serviced:
      description:
        - Number of connections serviced, for the pool only.
      returned: queried
      type: int
      sample: 15
    pool_queue_head_entry_age:
      description:
        - Queue head entry age, for the pool only.
      returned: queried
      type: int
      sample: 4
    priority_group_activation:
      description:
        - Whether the system load balances traffic according to the priority number assigned to the pool member.
        - This parameter is identical to C(minimum_active_members) and is just an alias for it.
      returned: queried
      type: int
      sample: 2
    queue_depth_limit:
      description:
        - The maximum number of connections that may simultaneously be queued to go to any member of this pool.
      returned: queried
      type: int
      sample: 3
    queue_on_connection_limit:
      description:
        - Enable or disable queuing connections when pool member or node connection limits are reached.
      returned: queried
      type: bool
      sample: true
    queue_time_limit:
      description:
        - Specifies the maximum time, in milliseconds, a connection will remain queued.
      returned: queried
      type: int
      sample: 0
    real_session:
      description:
        - The actual REST API value for the C(session) attribute.
        - This is different from the C(state) return value, as the return value
          can be considered a generalization of all available sessions, instead of the
          specific value of the session.
      returned: queried
      type: str
      sample: monitor-enabled
    real_state:
      description:
        - The actual REST API value for the C(state) attribute.
        - This is different from the C(state) return value, as the return value
          can be considered a generalization of all available states, instead of the
          specific value of the state.
      returned: queried
      type: str
      sample: up
    reselect_tries:
      description:
        - The number of times the system tries to contact a pool member after a passive failure.
      returned: queried
      type: int
      sample: 0
    server_ip_tos:
      description:
        - The Type of Service (ToS) level to use when sending packets to a server.
      returned: queried
      type: str
      sample: pass-through
    server_link_qos:
      description:
        - The Quality of Service (QoS) level to use when sending packets to a server.
      returned: queried
      type: str
      sample: pass-through
    service_down_action:
      description:
        - The action to take if the service specified in the pool is marked down.
      returned: queried
      type: str
      sample: none
    server_side_bits_in:
      description:
        - Number of server-side ingress bits.
      returned: queried
      type: int
      sample: 1000
    server_side_bits_out:
      description:
        - Number of server-side egress bits.
      returned: queried
      type: int
      sample: 200
    server_side_current_connections:
      description:
        - Number of current connections server-side.
      returned: queried
      type: int
      sample: 300
    server_side_max_connections:
      description:
        - Maximum number of connections server-side.
      returned: queried
      type: int
      sample: 40
    server_side_pkts_in:
      description:
        - Number of server-side ingress packets.
      returned: queried
      type: int
      sample: 1098384
    server_side_pkts_out:
      description:
        - Number of server-side egress packets.
      returned: queried
      type: int
      sample: 3484734
    server_side_total_connections:
      description:
        - Total number of server-side connections.
      returned: queried
      type: int
      sample: 24
    slow_ramp_time:
      description:
        - The ramp time for the pool.
        - This provides the ability for a pool member that is newly enabled or marked up
          to receive proportionally less traffic than other members in the pool.
      returned: queried
      type: int
      sample: 10
    status_reason:
      description:
        - If there is a problem with the status of the pool, it is reported here.
      returned: queried
      type: str
      sample: The children pool member(s) are down.
    members:
      description: List of LTM (Local Traffic Manager) pools.
      returned: when members exist in the pool.
      type: complex
      contains:
        address:
          description: IP address of the pool member.
          returned: queried
          type: str
          sample: 1.1.1.1
        connection_limit:
          description: The maximum number of concurrent connections allowed for a pool member.
          returned: queried
          type: int
          sample: 0
        description:
          description: The description of the pool member.
          returned: queried
          type: str
          sample: pool member 1
        dynamic_ratio:
          description:
            - A range of numbers you want the system to use in conjunction with the ratio load balancing method.
          returned: queried
          type: int
          sample: 1
        ephemeral:
          description:
            - Whether the node backing the pool member is ephemeral or not.
          returned: queried
          type: bool
          sample: true
        fqdn_autopopulate:
          description:
            - Whether the node should scale to the IP address set returned by DNS.
          returned: queried
          type: bool
          sample: true
        full_path:
          description:
            - Full name of the resource as known to the BIG-IP.
            - Includes the port in the name.
          returned: queried
          type: str
          sample: "/Common/member:80"
        inherit_profile:
          description:
            - Whether the pool member inherits the encapsulation profile from the parent pool.
          returned: queried
          type: bool
          sample: false
        logging:
          description:
            - Whether the monitor applied should log its actions.
          returned: queried
          type: bool
          sample: false
        monitors:
          description:
            - The Monitors active on the pool member. Monitor names are in their "full_path" form.
          returned: queried
          type: list
          sample: ['/Common/http']
        name:
          description:
            - Relative name of the resource in the BIG-IP.
          returned: queried
          type: str
          sample: "member:80"
        partition:
          description:
            - Partition the member exists on.
          returned: queried
          type: str
          sample: Common
        priority_group:
          description:
            - The priority group within the pool for this pool member.
          returned: queried
          type: int
          sample: 0
        encapsulation_profile:
          description:
            - The encapsulation profile to use for the pool member.
          returned: queried
          type: str
          sample: ip4ip4
        rate_limit:
          description:
            - The maximum number of connections per second allowed for a pool member.
          returned: queried
          type: bool
          sample: false
        ratio:
          description:
            - The weight of the pool for load balancing purposes.
          returned: queried
          type: int
          sample: 1
        session:
          description:
            - Enables or disables the pool member for new sessions.
          returned: queried
          type: str
          sample: monitor-enabled
        state:
          description:
            - Controls the state of the pool member, overriding any monitors.
          returned: queried
          type: str
          sample: down
    total_requests:
      description:
        - Total requests.
      returned: queried
      type: int
      sample: 8
  sample: hash/dictionary of values
ltm_policies:
  description: List of LTM (Local Traffic Manager) policies.
  returned: When C(ltm-policies) is specified in C(gather_subset).
  type: complex
  contains:
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: policy1
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/policy1
    description:
      description:
        - Description of the policy.
      returned: queried
      type: str
      sample: My policy
    strategy:
      description:
        - The match strategy for the policy.
      returned: queried
      type: str
      sample: /Common/first-match
    requires:
      description:
        - Aspects of the system required by this policy.
      returned: queried
      type: list
      sample: ['http']
    controls:
      description:
        - Aspects of the system controlled by this policy.
      returned: queried
      type: list
      sample: ['forwarding']
    status:
      description:
        - Indicates published or draft policy status.
      returned: queried
      type: str
      sample: draft
    rules:
      description:
        - List of LTM (Local Traffic Manager) policy rules.
      returned: when rules are defined in the policy.
      type: complex
      contains:
        actions:
          description:
            - The actions the policy will take when a match is encountered.
          returned: when actions are defined in the rule.
          type: complex
          contains:
            http_reply:
              description:
                - Indicates if the action affects a reply to a given HTTP request.
              returned: when defined in the action.
              type: bool
              sample: true
            redirect:
              description:
                - This action will redirect a request.
              returned: when defined in the action.
              type: bool
              sample: false
            request:
              description:
                - This policy action is performed on connection requests.
              returned: when defined in the action.
              type: bool
              sample: false
            location:
              description:
                - This action will come from the given location.
              returned: when defined in the action.
              type: str
              sample: "tcl:https://[getfield [HTTP::host] \\\":\\\" 1][HTTP::uri]"
          sample: hash/dictionary of values
        conditions:
          description:
            - The conditions a policy will match on.
          returned: when conditions are defined in the rule.
          type: complex
          contains:
            case_insensitive:
              description:
                - Specifies the value matched on is case insensitive.
              returned: when defined in the condition.
              type: bool
              sample: false
            case_sensitive:
              description:
                - Specifies the value matched on is case sensitive.
              returned: when defined in the condition.
              type: bool
              sample: true
            contains_string:
              description:
                - Specifies the value matches if it contains a certain string.
              returned: when defined in the condition.
              type: bool
              sample: true
            external:
              description:
                - Specifies the value matched on is from the external side of a connection.
              returned: when defined in the condition.
              type: bool
              sample: true
            http_basic_auth:
              description:
                - This condition matches on basic HTTP authorization.
              returned: when defined in the condition.
              type: bool
              sample: false
            http_host:
              description:
                - This condition matches on an HTTP host.
              returned: when defined in the condition.
              type: bool
              sample: true
            http_uri:
              description:
                - This condition matches on an HTTP URI.
              returned: when defined in the condition.
              type: bool
              sample: false
            datagroup:
              description:
                - This condition matches on an HTTP URI.
              returned: when defined in the condition.
              type: str
              sample: /Common/policy_using_datagroup
            tcp:
              description:
                - This condition matches on TCP parameters.
              returned: when defined in the condition.
              type: bool
              sample: false
            address:
              description:
                - This condition matches on a TCP address.
              returned: when defined in the condition.
              type: bool
              sample: false
            matches:
              description:
                - This condition matches on an address.
              returned: when defined in the condition.
              type: bool
              sample: false
            proxy_connect:
              description:
                - Specifies the value matched on is proxyConnect.
              returned: when defined in the condition.
              type: bool
              sample: false
            proxy_request:
              description:
                - Specifies the value matched on is proxyRequest.
              returned: when defined in the condition.
              type: bool
              sample: false
            remote:
              description:
                - Specifies the value matched on is remote.
              returned: when defined in the condition.
              type: bool
              sample: false
            request:
              description:
                - This policy matches on a request.
              returned: when defined in the condition.
              type: bool
              sample: true
            username:
              description:
                - Matches on a username.
              returned: when defined in the condition.
              type: bool
              sample: true
            all:
              description:
                - Matches all.
              returned: when defined in the condition.
              type: bool
              sample: true
            values:
              description:
                - The specified values will be matched on.
              returned: when defined in the condition.
              type: list
              sample: ['foo.bar.com', 'baz.cool.com']
          sample: hash/dictionary of values
      sample: hash/dictionary of values
  sample: hash/dictionary of values
management_routes:
  description: Management route related information.
  returned: When C(management-routes) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/default
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: default
    description:
      description:
        - User defined description of the route.
      returned: queried
      type: str
      sample: route-1-external
    gateway:
      description:
        - The gateway IP address through which the system forwards packets to the destination.
      returned: queried
      type: str
      sample: 192.168.0.1
    mtu:
      description:
        - The maximum transmission unit for the management interface.
      returned: queried
      type: str
      sample: 0
    network:
      description:
        - The destination subnet and netmask, also specified as default or default-inet6.
      returned: queried
      type: str
      sample: default
  sample: hash/dictionary of values
nodes:
  description: Node related information.
  returned: When C(nodes) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/5.6.7.8
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: 5.6.7.8
    ratio:
      description:
        - Fixed size ratio used for node during C(Ratio) load balancing.
      returned: queried
      type: int
      sample: 10
    description:
      description:
        - Description of the node.
      returned: queried
      type: str
      sample: My node
    connection_limit:
      description:
        - Maximum number of connections the node can handle.
      returned: queried
      type: int
      sample: 100
    address:
      description:
        - IP address of the node.
      returned: queried
      type: str
      sample: 2.3.4.5
    dynamic_ratio:
      description:
        - Dynamic ratio number for the node used when doing C(Dynamic Ratio) load balancing.
      returned: queried
      type: int
      sample: 200
    rate_limit:
      description:
        - Maximum number of connections per second allowed for the node.
      returned: queried
      type: int
      sample: 1000
    monitor_status:
      description:
        - Status of the node as reported by the monitor(s) associated with it.
        - This value is also used in determining node C(state).
      returned: queried
      type: str
      sample: down
    session_status:
      description:
        - This value is also used in determining node C(state).
      returned: queried
      type: str
      sample: enabled
    availability_status:
      description:
        - The availability of the node.
      returned: queried
      type: str
      sample: offline
    enabled_status:
      description:
        - The enabled status of the node.
      returned: queried
      type: str
      sample: enabled
    status_reason:
      description:
        - If there is a problem with the status of the node, it is reported here.
      returned: queried
      type: str
      sample: /Common/https_443 No successful responses received...
    monitor_rule:
      description:
        - A string representation of the full monitor rule.
      returned: queried
      type: str
      sample: /Common/https_443 and /Common/icmp
    monitors:
      description:
        - A list of the monitors identified in the C(monitor_rule).
      returned: queried
      type: list
      sample: ['/Common/https_443', '/Common/icmp']
    monitor_type:
      description:
        - The C(monitor_type) field related to the C(bigip_node) module, for this nodes
          monitors.
      returned: queried
      type: str
      sample: and_list
    fqdn_name:
      description:
        - FQDN name of the node.
      returned: queried
      type: str
      sample: sample.host.foo.com
    fqdn_auto_populate:
      description:
        - Indicates if the system automatically creates ephemeral nodes using DNS discovered IPs.
      returned: queried
      type: bool
      sample: true
    fqdn_address_type:
      description:
        - The address family of the automatically created ephemeral nodes.
      returned: queried
      type: str
      sample: ipv4
    fqdn_up_interval:
      description:
        - The interval at which a query occurs when the DNS server is up.
      returned: queried
      type: int
      sample: 3600
    fqdn_down_interval:
      description:
        - The interval in which a query occurs when the DNS server is down.
      returned: queried
      type: int
      sample: 15
  sample: hash/dictionary of values
oneconnect_profiles:
  description: OneConnect profile related information.
  returned: When C(oneconnect-profiles) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/oneconnect
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: oneconnect
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: oneconnect
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My profile
    idle_timeout_override:
      description:
        - Specifies the number of seconds that a connection is idle before
          the connection flow is eligible for deletion.
      returned: queried
      type: int
      sample: 1000
    limit_type:
      description:
        - When C(none), simultaneous in-flight requests and responses over TCP
          connections to a pool member are counted toward the limit.
        - When C(idle), idle connections will be dropped as the TCP connection
          limit is reached.
        - When C(strict), the TCP connection limit is honored with no
          exceptions. This means idle connections will prevent new TCP
          connections from being made until they expire, even if they could
          otherwise be reused.
      returned: queried
      type: str
      sample: idle
    max_age:
      description:
        - Specifies the maximum age, in seconds, of a connection
          in the connection reuse pool.
      returned: queried
      type: int
      sample: 100
    max_reuse:
      description:
        - Specifies the maximum number of times a server connection can
          be reused.
      returned: queried
      type: int
      sample: 1000
    max_size:
      description:
        - Specifies the maximum number of connections the system holds
          in the connection reuse pool.
        - If the pool is already full, then the server connection closes after
          the response is completed.
      returned: queried
      type: int
      sample: 1000
    share_pools:
      description:
        - Indicates connections may be shared not only within a virtual
          server, but also among similar virtual servers.
      returned: queried
      type: bool
      sample: true
    source_mask:
      description:
        - Specifies a source IP mask.
        - If no mask is provided, the value C(any6) is used.
      returned: queried
      type: str
      sample: 255.255.255.0
  sample: hash/dictionary of values
partitions:
  description: Partition related information.
  returned: When C(partitions) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: Common
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: Common
    description:
      description:
        - Description of the partition.
      returned: queried
      type: str
      sample: Tenant 1
    default_route_domain:
      description:
        - ID of the route domain that is associated with the IP addresses that reside
          in the partition.
      returned: queried
      type: int
      sample: 0
  sample: hash/dictionary of values
provision_info:
  description: Module provisioning related information.
  returned: When C(provision-info) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: asm
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: asm
    cpu_ratio:
      description:
        - Ratio of CPU allocated to this module.
        - Only relevant if C(level) was specified as C(custom). Otherwise, this value
          will be reported as C(0).
      returned: queried
      type: int
      sample: 0
    disk_ratio:
      description:
        - Ratio of disk allocated to this module.
        - Only relevant if C(level) was specified as C(custom). Otherwise, this value
          will be reported as C(0).
      returned: queried
      type: int
      sample: 0
    memory_ratio:
      description:
        - Ratio of memory allocated to this module.
        - Only relevant if C(level) was specified as C(custom). Otherwise, this value
          will be reported as C(0).
      returned: queried
      type: int
      sample: 0
    level:
      description:
        - Provisioned level of the module on BIG-IP.
        - Valid return values can include C(none), C(minimum), C(nominal), C(dedicated)
          and C(custom).
      returned: queried
      type: int
      sample: 0
  sample: hash/dictionary of values
remote_syslog:
  description: Remote Syslog related information.
  returned: When C(remote-syslog) is specified in C(gather_subset).
  type: complex
  contains:
    servers:
      description: Configured remote syslog servers.
      returned: queried
      type: complex
      contains:
        name:
          description: Name of remote syslog server as configured on the system.
          returned: queried
          type: str
          sample: /Common/foobar1
        remote_port:
          description: Remote port of the remote syslog server.
          returned: queried
          type: int
          sample: 514
        local_ip:
          description: The local IP address of the remote syslog server.
          returned: queried
          type: str
          sample: 10.10.10.10
        remote_host:
          description: The IP address or hostname of the remote syslog server.
          returned: queried
          type: str
          sample: 192.168.1.1
      sample: hash/dictionary of values
  sample: hash/dictionary of values
route_domains:
  description: Route domain related information.
  returned: When C(self-ips) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/rd1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: rd1
    description:
      description:
        - Description of the Route Domain.
      returned: queried
      type: str
      sample: My route domain
    id:
      description:
        - The unique identifying integer representing the route domain.
      returned: queried
      type: int
      sample: 10
    parent:
      description:
        - The route domain the system searches when it cannot find a route in the configured domain.
      returned: queried
      type: str
      sample: 0
    bwc_policy:
      description:
        - The bandwidth controller for the route domain.
      returned: queried
      type: str
      sample: /Common/foo
    connection_limit:
      description:
        - The new connection limit for the route domain.
      returned: queried
      type: int
      sample: 100
    flow_eviction_policy:
      description:
        - The new eviction policy to use with this route domain.
      returned: queried
      type: str
      sample: /Common/default-eviction-policy
    service_policy:
      description:
        - The new service policy to use with this route domain.
      returned: queried
      type: str
      sample: /Common-my-service-policy
    strict:
      description:
        - The new strict isolation setting.
      returned: queried
      type: str
      sample: enabled
    routing_protocol:
      description:
        - List of routing protocols applied to the route domain.
      returned: queried
      type: list
      sample: ['bfd', 'bgp']
    vlans:
      description:
        - List of new VLANs the route domain is applied to.
      returned: queried
      type: list
      sample: ['/Common/http-tunnel', '/Common/socks-tunnel']
  sample: hash/dictionary of values
self_ips:
  description: Self IP related information.
  returned: When C(self-ips) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/self1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: self1
    description:
      description:
        - Description of the Self IP.
      returned: queried
      type: str
      sample: My self-ip
    netmask:
      description:
        - Netmask portion of the IP address, in dotted notation.
      returned: queried
      type: str
      sample: 255.255.255.0
    netmask_cidr:
      description:
        - Netmask portion of the IP address, in CIDR notation.
      returned: queried
      type: int
      sample: 24
    floating:
      description:
        - Whether the Self IP is a floating address or not.
      returned: queried
      type: bool
      sample: true
    traffic_group:
      description:
        - Traffic group the Self IP is associated with.
      returned: queried
      type: str
      sample: /Common/traffic-group-local-only
    service_policy:
      description:
        - Service policy assigned to the Self IP.
      returned: queried
      type: str
      sample: /Common/service1
    vlan:
      description:
        - VLAN associated with the Self IP.
      returned: queried
      type: str
      sample: /Common/vlan1
    allow_access_list:
      description:
        - List of protocols, and optionally their ports, that are allowed to access the
          Self IP. Also known as port-lockdown in the web interface.
        - Items in the list are in the format of "protocol:port". Some items may not
          have a port associated with them and in those cases the port is C(0).
      returned: queried
      type: list
      sample: ['tcp:80', 'egp:0']
    traffic_group_inherited:
      description:
        - Whether or not the traffic group is inherited.
      returned: queried
      type: bool
      sample: false
  sample: hash/dictionary of values
server_ssl_profiles:
  description: Server SSL related information.
  returned: When C(server-ssl-profiles) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: serverssl
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: serverssl
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My profile
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: serverssl
    alert_timeout:
      description:
        - Maximum time period in seconds to keep the SSL
          session active after an alert message is sent, or indefinite.
      returned: queried
      type: str
      sample: 100
    allow_expired_crl:
      description:
        - Use the specified CRL file, even if it has expired.
      returned: queried
      type: bool
      sample: true
    authentication_frequency:
      description:
        - Specifies the frequency of authentication.
      returned: queried
      type: str
      sample: once
    authenticate_depth:
      description:
        - The client certificate chain maximum traversal depth
      returned: queried
      type: int
      sample: 9
    authenticate_name:
      description:
        - Common Name (CN) embedded in a server certificate.
        - The system authenticates a server based on the specified CN.
      returned: queried
      type: str
      sample: foo
    bypass_on_client_cert_fail:
      description:
        - Enables or disables SSL forward proxy bypass on failing to get
          client certificate that the server asks for.
      returned: queried
      type: bool
      sample: true
    bypass_on_handshake_alert:
      description:
        - Enables or disables SSL forward proxy bypass on receiving
          handshake_failure, protocol_version or unsupported_extension alert
          message during the serverside SSL handshake.
      returned: queried
      type: bool
      sample: false
    c3d_ca_cert:
      description:
        - Name of the certificate file used as the
          certification authority certificate when SSL client certificate
          constrained delegation is enabled.
      returned: queried
      type: str
      sample: /Common/cacert.crt
    c3d_ca_key:
      description:
        - Name of the key file used as the
          certification authority key when SSL client certificate
          constrained delegation is enabled.
      returned: queried
      type: str
      sample: /Common/default.key
    c3d_cert_extension_includes:
      description:
        - Extensions of the client certificates to be included
          in the generated certificates using SSL client certificate
          constrained delegation.
      returned: queried
      type: list
      sample: [ "basic-constraints", "extended-key-usage", ... ]
    c3d_cert_lifespan:
      description:
        - Lifespan of the certificate generated using the SSL
          client certificate constrained delegation.
      returned: queried
      type: int
      sample: 24
    ca_file:
      description:
        - Certificate authority file name.
      returned: queried
      type: str
      sample: default.crt
    cache_size:
      description:
        - The SSL session cache size.
      returned: queried
      type: int
      sample: 262144
    cache_timeout:
      description:
        - The SSL session cache timeout value, which is the usable
          lifetime seconds of negotiated SSL session IDs.
      returned: queried
      type: int
      sample: 86400
    cert:
      description:
        - The name of the certificate installed on the traffic
          management system for the purpose of terminating or initiating an
          SSL connection.
      returned: queried
      type: str
      sample: /Common/default.crt
    chain:
      description:
        - Specifies or builds a certificate chain file that a client can use
          to authenticate the profile.
      returned: queried
      type: str
      sample: /Common/default.crt
    cipher_group:
      description:
        - Specifies a cipher group.
      returned: queried
      type: str
    ciphers:
      description:
        - Specifies a cipher name.
      returned: queried
      type: str
      sample: DEFAULT
    crl_file:
      description:
        - Specifies the certificate revocation list file name.
      returned: queried
      type: str
    expire_cert_response_control:
      description:
        - Specifies the BIGIP action when the server certificate has
          expired.
      returned: queried
      type: str
      sample: drop
    handshake_timeout:
      description:
        - Specifies the handshake timeout in seconds.
      returned: queried
      type: str
      sample: 10
    key:
      description:
        - Specifies the name of the key
          installed on the traffic management system for the purpose of
          terminating or initiating an SSL connection.
      returned: queried
      type: str
      sample: /Common/default.key
    max_active_handshakes:
      description:
        - Specifies the maximum number of allowed active SSL handshakes.
      returned: queried
      type: str
      sample: 100
    mod_ssl_methods:
      description:
        - Enables or disables ModSSL methods.
      returned: queried
      type: bool
      sample: true
    mode:
      description:
        - Enables or disables SSL processing.
      returned: queried
      type: bool
      sample: false
    ocsp:
      description:
        - Specifies the name of the OCSP profile for validating
          the status of the server certificate.
      returned: queried
      type: str
    options:
      description:
        - Enables options, including some industry-related workarounds.
      returned: queried
      type: list
      sample: [ "netscape-reuse-cipher-change-bug", "dont-insert-empty-fragments" ]
    peer_cert_mode:
      description:
        - Specifies the peer certificate mode.
      returned: queried
      type: str
      sample: ignore
    proxy_ssl:
      description:
        - Allows further modification of application traffic within
          an SSL tunnel while still allowing the server to perform necessary
          authorization, authentication, auditing steps.
      returned: queried
      type: bool
      sample: true
    proxy_ssl_passthrough:
      description:
        - Allows Proxy SSL to passthrough the traffic when ciphersuite negotiated
          between the client and server is not supported.
      returned: queried
      type: bool
      sample: true
    renegotiate_period:
      description:
        - Number of seconds from the initial connect time
          after which the system renegotiates an SSL session.
      returned: queried
      type: str
      sample: indefinite
    renegotiate_size:
      description:
        - Specifies a throughput size of SSL renegotiation, in megabytes.
      returned: queried
      type: str
      sample: indefinite
    renegotiation:
      description:
        - Whether renegotiations are enabled.
      returned: queried
      type: bool
      sample: true
    retain_certificate:
      description:
        - APM module requires storing certificates in the SSL session. When C(false),
          a certificate will not be stored in the SSL session.
      returned: queried
      type: bool
      sample: false
    generic_alert:
      description:
        - Enables or disables generic-alert.
      returned: queried
      type: bool
      sample: true
    secure_renegotiation:
      description:
        - Specifies the secure renegotiation mode.
      returned: queried
      type: str
      sample: require
    server_name:
      description:
        - Server name to be included in the SNI (server name
          indication) extension during SSL handshake in ClientHello.
      returned: queried
      type: str
    session_mirroring:
      description:
        - Enables or disables the mirroring of sessions to the high availability
          peer.
      returned: queried
      type: bool
      sample: true
    session_ticket:
      description:
        - Enables or disables session-ticket.
      returned: queried
      type: bool
      sample: false
    sni_default:
      description:
        - When C(true), this profile is the default SSL profile when the server
          name in a client connection does not match any configured server
          names, or a client connection does not specify any server name at
          all.
      returned: queried
      type: bool
      sample: true
    sni_require:
      description:
        - When C(true), connections to a server that do not support SNI
          extension will be rejected.
      returned: queried
      type: bool
      sample: false
    ssl_c3d:
      description:
        - Enables or disables SSL Client certificate constrained delegation.
      returned: queried
      type: bool
      sample: true
    ssl_forward_proxy_enabled:
      description:
        - Enables or disables the ssl-forward-proxy feature.
      returned: queried
      type: bool
      sample: false
    ssl_sign_hash:
      description:
        - Specifies the SSL sign hash algorithm which is used to sign and verify
          SSL Server Key Exchange and Certificate Verify messages for the
          specified SSL profiles.
      returned: queried
      type: str
      sample: sha1
    ssl_forward_proxy_bypass:
      description:
        - Enables or disables the ssl-forward-proxy-bypass feature.
      returned: queried
      type: bool
      sample: true
    strict_resume:
      description:
        - Enables or disables the resumption of SSL sessions after an
          unclean shutdown.
      returned: queried
      type: bool
      sample: false
    unclean_shutdown:
      description:
        - Specifies, when C(true), that the SSL profile performs unclean
          shutdowns of all SSL connections. This means underlying TCP
          connections are closed without exchanging the required SSL
          shutdown alerts.
      returned: queried
      type: bool
      sample: true
    untrusted_cert_response_control:
      description:
        - Specifies the BIG-IP action when the server certificate has
          an untrusted CA.
      returned: queried
      type: str
      sample: drop
  sample: hash/dictionary of values
software_hotfixes:
  description: List of software hotfixes.
  returned: When C(software-hotfixes) is specified in C(gather_subset).
  type: complex
  contains:
    name:
      description:
        - Name of the image.
      returned: queried
      type: str
      sample: Hotfix-BIGIP-13.0.0.3.0.1679-HF3.iso
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: Hotfix-BIGIP-13.0.0.3.0.1679-HF3.iso
    build:
      description:
        - Build number of the image.
        - This is usually a sub-string of the C(name).
      returned: queried
      type: str
      sample: 3.0.1679
    checksum:
      description:
        - MD5 checksum of the image.
        - Note that this is the checksum stored inside the ISO. It is not
          the actual checksum of the ISO.
      returned: queried
      type: str
      sample: df1ec715d2089d0fa54c0c4284656a98
    product:
      description:
        - Product contained in the ISO.
      returned: queried
      type: str
      sample: BIG-IP
    id:
      description:
        - ID component of the image.
        - This is usually a sub-string of the C(name).
      returned: queried
      type: str
      sample: HF3
    title:
      description:
        - Human friendly name of the image.
      returned: queried
      type: str
      sample: Hotfix Version 3.0.1679
    verified:
      description:
        - Specifies whether the system has verified this image.
      returned: queried
      type: bool
      sample: true
    version:
      description:
        - Version of software contained in the image.
        - This is a sub-string of the C(name).
      returned: queried
      type: str
      sample: 13.0.0
  sample: hash/dictionary of values
software_images:
  description: List of software images.
  returned: When C(software-images) is specified in C(gather_subset).
  type: complex
  contains:
    name:
      description:
        - Name of the image.
      returned: queried
      type: str
      sample: BIGIP-13.1.0.7-0.0.1.iso
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: BIGIP-13.1.0.7-0.0.1.iso
    build:
      description:
        - Build number of the image.
        - This is usually a sub-string of the C(name).
      returned: queried
      type: str
      sample: 0.0.1
    build_date:
      description:
        - Date of the build.
      returned: queried
      type: str
      sample: "2018-05-05T15:26:30"
    checksum:
      description:
        - MD5 checksum of the image.
        - Note that this is the checksum stored inside the ISO. It is not
          the actual checksum of the ISO.
      returned: queried
      type: str
      sample: df1ec715d2089d0fa54c0c4284656a98
    file_size:
      description:
        - Size of the image, in megabytes.
      returned: queried
      type: int
      sample: 1938
    last_modified:
      description:
        - Last modified date of the ISO.
      returned: queried
      type: str
      sample: "2018-05-05T15:26:30"
    product:
      description:
        - Product contained in the ISO.
      returned: queried
      type: str
      sample: BIG-IP
    verified:
      description:
        - Whether or not the system has verified this image.
      returned: queried
      type: bool
      sample: true
    version:
      description:
        - Version of software contained in the image.
        - This is a sub-string of the C(name).
      returned: queried
      type: str
      sample: 13.1.0.7
  sample: hash/dictionary of values
software_volumes:
  description: List of software volumes.
  returned: When C(software-volumes) is specified in C(gather_subset).
  type: complex
  contains:
    active:
      description:
        - Whether the volume is currently active or not.
        - An active volume contains the currently running version of software.
      returned: queried
      type: bool
      sample: true
    base_build:
      description:
        - Base build version of the software installed in the volume.
        - When a hotfix is installed, this refers to the base version of software
          that the hotfix requires.
      returned: queried
      type: str
      sample: 0.0.6
    build:
      description:
        - Build version of the software installed in the volume.
      returned: queried
      type: str
      sample: 0.0.6
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: HD1.1
    default_boot_location:
      description:
        - Whether this volume is the default boot location or not.
      returned: queried
      type: bool
      sample: true
    name:
      description:
        - Relative name of the resource in the BIG-IP.
        - This usually matches the C(full_name).
      returned: queried
      type: str
      sample: HD1.1
    product:
      description:
        - The F5 product installed in this slot.
        - This should always be BIG-IP.
      returned: queried
      type: str
      sample: BIG-IP
    status:
      description:
        - Status of the software installed, or being installed, in the volume.
        - When C(complete), indicates the software has completed installing.
      returned: queried
      type: str
      sample: complete
    version:
      description:
        - Version of software installed in the volume, excluding the C(build) number.
      returned: queried
      type: str
      sample: 13.1.0.4
  sample: hash/dictionary of values
ssl_certs:
  description: SSL certificate related information.
  returned: When C(ssl-certs) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/cert1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: cert1
    key_type:
      description:
        - Specifies the type of cryptographic key associated with this certificate.
      returned: queried
      type: str
      sample: rsa-private
    key_size:
      description:
        - Specifies the size (in bytes) of the file associated with this file object.
      returned: queried
      type: int
      sample: 2048
    system_path:
      description:
        - Path on the BIG-IP where the cert can be found.
      returned: queried
      type: str
      sample: /config/ssl/ssl.crt/f5-irule.crt
    sha1_checksum:
      description:
        - SHA1 checksum of the certificate.
      returned: queried
      type: str
      sample: 1306e84e1e6a2da53816cefe1f684b80d6be1e3e
    subject:
      description:
        - Specifies X509 information of the certificate's subject.
      returned: queried
      type: str
      sample: "emailAddress=support@f5.com,CN=..."
    last_update_time:
      description:
        - Specifies the last time the file-object was
          updated/modified.
      returned: queried
      type: str
      sample: "2018-05-15T21:11:15Z"
    issuer:
      description:
        - Specifies X509 information of the certificate's issuer.
      returned: queried
      type: str
      sample: "emailAddress=support@f5.com,...CN=support.f5.com,"
    is_bundle:
      description:
        - Specifies whether the certificate file is a bundle (that is,
          whether it contains more than one certificate).
      returned: queried
      type: bool
      sample: false
    fingerprint:
      description:
        - Displays the SHA-256 fingerprint of the certificate.
      returned: queried
      type: str
      sample: "SHA256/88:A3:05:...:59:01:EA:5D:B0"
    expiration_date:
      description:
        - Specifies a string representation of the expiration date of the
          certificate.
      returned: queried
      type: str
      sample: "Aug 13 21:21:29 2031 GMT"
    expiration_timestamp:
      description:
        - Specifies the date this certificate expires. Stored as a
          POSIX time.
      returned: queried
      type: int
      sample: 1944422489
    create_time:
      description:
        - Specifies the time the file-object was created.
      returned: queried
      type: str
      sample: "2018-05-15T21:11:15Z"
    serial_no:
      description:
        - Specifies certificate's serial number
      returned: queried
      type: str
      sample: "1234567890"
    subject_alternative_name:
      description:
        - Displays the Subject Alternative Name for the certificate.
        - The X509v3 Subject Alternative Name is embedded in the certificate for X509 extension purposes.
      returned: queried
      type: str
      sample: "DNS:www.example.com, DNS:www.example.internal.net"
  sample: hash/dictionary of values
ssl_keys:
  description: SSL certificate related information.
  returned: When C(ssl-keys) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/key1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: key1
    key_type:
      description:
        - Specifies the cryptographic type of the key. That is,
          which algorithm this key is compatible with.
      returned: queried
      type: str
      sample: rsa-private
    key_size:
      description:
        - Specifies the size of the cryptographic key associated with this
          file object, in bits.
      returned: queried
      type: int
      sample: 2048
    security_type:
      description:
        - Specifies the type of security used to handle or store the key.
      returned: queried
      type: str
      sample: normal
    system_path:
      description:
        - The path on the filesystem where the key is stored.
      returned: queried
      type: str
      sample: /config/ssl/ssl.key/default.key
    sha1_checksum:
      description:
        - The SHA1 checksum of the key.
      returned: queried
      type: str
      sample: 1fcf7de3dd8e834d613099d8e10b2060cd9ecc9f
  sample: hash/dictionary of values
sync_status:
  description:
    - Configuration Synchronization Status across all Device Groups.
    - Note that the sync-status works across all device groups - a specific device group cannot be queried for its sync-status.
    - In general the device-group with the 'worst' sync-status will be shown.
  returned: When C(sync-status) is specified in C(gather_subset).
  type: complex
  contains:
    color:
      description:
        - Sync status color.
        - Eg. red, blue, green, yellow
      returned: queried
      type: str
      sample: red
    details:
      description:
        - A list of all details provided for the current sync-status of the device
      returned: queried
      type: list
      sample:
        - Optional action: Add a device to the trust domain
    mode:
      description:
        - Device operation mode (high-availability, standalone)
      returned: queried
      type: str
      sample:
        - high-availability
        - standalone
    recommended_action:
      description:
        - The next recommended action to take on the current sync-status.
        - This field might be empty.
      returned: queried
      type: str
      sample: Synchronize bigip-a.example.com to group some-device-group
    status:
      description:
        - Synchronization Status
      returned: queried
      type: str
      sample:
        - Changes Pending
        - In Sync
        - Standalone
        - Disconnected
    summary:
      description: The configuration synchronization status summary
      returned: queried
      type: str
      sample:
        - The device group is awaiting the initial config sync
        - There is a possible change conflict between ...
  sample: hash/dictionary of values
system_db:
  description: System DB related information.
  returned: When C(system-db) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: vendor.wwwurl
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: vendor.wwwurl
    default:
      description:
        - Default value of the key.
      returned: queried
      type: str
      sample: www.f5.com
    scf_config:
      description:
        - Whether the database key would be found in an SCF config or not.
      returned: queried
      type: str
      sample: false
    value:
      description:
        - The value of the key.
      returned: queried
      type: str
      sample: www.f5.com
    value_range:
      description:
        - The accepted range of values for the key.
      returned: queried
      type: str
      sample: string
  sample: hash/dictionary of values
system_info:
  description: Traffic group related information.
  returned: When C(traffic-groups) is specified in C(gather_subset).
  type: complex
  contains:
    base_mac_address:
      description:
        - Media Access Control address (MAC address) of the device.
      returned: queried
      type: str
      sample: "fa:16:3e:c3:42:6f"
    marketing_name:
      description:
        - Marketing name of the device platform.
      returned: queried
      type: str
      sample: BIG-IP Virtual Edition
    time:
      description:
        - Mapping of the current time information to specific time-named keys.
      returned: queried
      type: complex
      contains:
        day:
          description:
            - The current day of the month, in numeric form.
          returned: queried
          type: int
          sample: 7
        hour:
          description:
            - The current hour of the day in 24-hour format.
          returned: queried
          type: int
          sample: 18
        minute:
          description:
            - The current minute of the hour.
          returned: queried
          type: int
          sample: 16
        month:
          description:
            - The current month, in numeric form.
          returned: queried
          type: int
          sample: 6
        second:
          description:
            - The current second of the minute.
          returned: queried
          type: int
          sample: 51
        year:
          description:
            - The current year in 4-digit format.
          returned: queried
          type: int
          sample: 2018
    hardware_information:
      description:
        - Information related to the hardware (drives and CPUs) of the system.
      type: complex
      returned: queried
      contains:
        model:
          description:
            - The model of the hardware.
          returned: queried
          type: str
          sample: Virtual Disk
        name:
          description:
            - The name of the hardware.
          returned: queried
          type: str
          sample: HD1
        type:
          description:
            - The type of hardware.
          returned: queried
          type: str
          sample: physical-disk
        versions:
          description:
            - Hardware specific properties.
          returned: queried
          type: complex
          contains:
            name:
              description:
                - Name of the property.
              returned: queried
              type: str
              sample: Size
            version:
              description:
                - Value of the property.
              returned: queried
              type: str
              sample: 154.00G
    package_edition:
      description:
        - Displays the software edition.
      returned: queried
      type: str
      sample: Point Release 7
    package_version:
      description:
        - A string combining the C(product_build) and C(product_build_date).
      returned: queried
      type: str
      sample: "Build 0.0.1 - Tue May 15 15:26:30 PDT 2018"
    product_code:
      description:
        - Code identifying the product.
      returned: queried
      type: str
      sample: BIG-IP
    product_build:
      description:
        - Build version of the release version.
      returned: queried
      type: str
      sample: 0.0.1
    product_version:
      description:
        - Major product version of the running software.
      returned: queried
      type: str
      sample: 13.1.0.7
    product_built:
      description:
        - UNIX timestamp of when the product was built.
      returned: queried
      type: int
      sample: 180515152630
    product_build_date:
      description:
        - Human readable build date.
      returned: queried
      type: str
      sample: "Tue May 15 15:26:30 PDT 2018"
    product_changelist:
      description:
        - Changelist the product branches from.
      returned: queried
      type: int
      sample: 2557198
    product_jobid:
      description:
        - ID of the job that built the product version.
      returned: queried
      type: int
      sample: 1012030
    chassis_serial:
      description:
        - Serial of the chassis.
      returned: queried
      type: str
      sample: 11111111-2222-3333-444444444444
    host_board_part_revision:
      description:
        - Revision of the host board.
      returned: queried
      type: str
    host_board_serial:
      description:
        - Serial of the host board.
      returned: queried
      type: str
    platform:
      description:
        - Platform identifier.
      returned: queried
      type: str
      sample: Z100
    switch_board_part_revision:
      description:
        - Switch board revision.
      returned: queried
      type: str
    switch_board_serial:
      description:
        - Serial of the switch board.
      returned: queried
      type: str
    uptime:
      description:
        - Time since the system booted, in seconds.
      returned: queried
      type: int
      sample: 603202
  sample: hash/dictionary of values
tcp_monitors:
  description: TCP monitor related information.
  returned: When C(tcp-monitors) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/tcp
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: tcp
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: tcp
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My monitor
    adaptive:
      description:
        - Whether adaptive response time monitoring is enabled for this monitor.
      returned: queried
      type: bool
      sample: false
    adaptive_divergence_type:
      description:
        - Specifies whether the adaptive-divergence-value is C(relative) or
          C(absolute).
      returned: queried
      type: str
      sample: relative
    adaptive_divergence_value:
      description:
        - Specifies how far from mean latency each monitor probe is allowed
          to be.
      returned: queried
      type: int
      sample: 25
    adaptive_limit:
      description:
        - Specifies the hard limit, in milliseconds, which the probe is not
          allowed to exceed, regardless of the divergence value.
      returned: queried
      type: int
      sample: 200
    adaptive_sampling_timespan:
      description:
        - Specifies the size of the sliding window, in seconds, which
          records probe history.
      returned: queried
      type: int
      sample: 300
    destination:
      description:
        - Specifies the IP address and service port of the resource that is
          the destination of this monitor.
      returned: queried
      type: str
      sample: "*:*"
    interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when either the resource is down or the status
          of the resource is unknown.
      returned: queried
      type: int
      sample: 5
    ip_dscp:
      description:
        - Specifies the differentiated services code point (DSCP).
      returned: queried
      type: int
      sample: 0
    manual_resume:
      description:
        - Specifies whether the system automatically changes the status of a
          resource to up at the next successful monitor check.
      returned: queried
      type: bool
      sample: true
    reverse:
      description:
        - Specifies whether the monitor operates in reverse mode. When the
          monitor is in reverse mode, a successful check marks the monitored
          object down instead of up.
      returned: queried
      type: bool
      sample: false
    time_until_up:
      description:
        - Specifies the amount of time, in seconds, after the first
          successful response before a node is marked up.
      returned: queried
      type: int
      sample: 0
    timeout:
      description:
        - Specifies the number of seconds the target has in which to respond
          to the monitor request.
      returned: queried
      type: int
      sample: 16
    transparent:
      description:
        - Specifies whether the monitor operates in transparent mode.
      returned: queried
      type: bool
      sample: false
    up_interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when the resource is up.
      returned: queried
      type: int
      sample: 0
  sample: hash/dictionary of values
tcp_half_open_monitors:
  description: TCP Half-open monitor related information.
  returned: When C(tcp-half-open-monitors) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/tcp
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: tcp
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: tcp
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My monitor
    destination:
      description:
        - Specifies the IP address and service port of the resource that is
          the destination of this monitor.
      returned: queried
      type: str
      sample: "*:*"
    interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when either the resource is down or the status
          of the resource is unknown.
      returned: queried
      type: int
      sample: 5
    manual_resume:
      description:
        - Specifies whether the system automatically changes the status of a
          resource to up at the next successful monitor check.
      returned: queried
      type: bool
      sample: true
    time_until_up:
      description:
        - Specifies the amount of time, in seconds, after the first
          successful response before a node is marked up.
      returned: queried
      type: int
      sample: 0
    timeout:
      description:
        - Specifies the number of seconds the target has in which to respond
          to the monitor request.
      returned: queried
      type: int
      sample: 16
    transparent:
      description:
        - Specifies whether the monitor operates in transparent mode.
      returned: queried
      type: bool
      sample: false
    up_interval:
      description:
        - Specifies, in seconds, the frequency at which the system issues
          the monitor check when the resource is up.
      returned: queried
      type: int
      sample: 0
  sample: hash/dictionary of values
tcp_profiles:
  description: TCP profile related information.
  returned: When C(tcp-profiles) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: tcp
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: /Common/tcp
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: tcp
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My profile
    abc:
      description:
        - Appropriate Byte Counting (RFC 3465)
        - When C(true), increases the congestion window by basing the amount to
          increase on the number of previously unacknowledged bytes that each ACK covers.
      returned: queried
      type: bool
      sample: true
    ack_on_push:
      description:
        - When C(true), specifies significantly improved performance to Microsoft
          Windows and MacOS peers who are writing out on a very small send buffer.
      returned: queried
      type: bool
      sample: false
    auto_proxy_buffer:
      description:
        - When C(true), specifies the system uses the network measurements to set
          the optimal proxy buffer size.
      returned: queried
      type: bool
      sample: true
    auto_receive_window:
      description:
        - When C(true), specifies the system uses the network measurements to
          set the optimal receive window size.
      returned: queried
      type: bool
      sample: false
    auto_send_buffer:
      description:
        - When C(true), specifies the system uses the network measurements to
          set the optimal send buffer size.
      returned: queried
      type: bool
      sample: true
    close_wait:
      description:
        - Specifies the length of time a TCP connection remains in the LAST-ACK
          state before quitting.
        - In addition to a numeric value, the value of this fact may also be one of
          C(immediate) or C(indefinite).
        - When C(immediate), specifies the TCP connection closes immediately
          after entering the LAST-ACK state.
        - When C(indefinite), specifies that TCP connections in the LAST-ACK state
          do not close until they meet the maximum retransmissions timeout.
      returned: queried
      type: str
      sample: indefinite
    congestion_metrics_cache:
      description:
        - When C(true), specifies the system uses a cache for storing congestion
          metrics.
        - Subsequently, because these metrics are already known and cached, the initial
          slow-start ramp for previously-encountered peers improves.
      returned: queried
      type: bool
      sample: true
    congestion_metrics_cache_timeout:
      description:
        - Specifies the number of seconds for which entries in the congestion metrics
          cache are valid.
      returned: queried
      type: int
      sample: 0
    congestion_control:
      description:
        - Specifies the algorithm to use to share network resources among competing
          users to reduce congestion.
        - Return values may include, C(high-speed), C(cdg), C(chd), C(none), C(cubic),
          C(illinois), C(new-reno), C(reno), C(scalable), C(vegas), C(westwood), and
          C(woodside).
      returned: queried
      type: str
      sample: high-speed
    deferred_accept:
      description:
        - When C(true), specifies the system defers allocation of the connection
          chain context until the system has received the payload from the client.
        - Enabling this setting is useful in dealing with 3-way handshake denial-of-service
          attacks.
      returned: queried
      type: bool
      sample: true
    delay_window_control:
      description:
        - Specifies the system uses an estimate of queuing delay as a measure of
          congestion to control, in addition to the normal loss-based control, the amount
          of data sent.
      returned: queried
      type: bool
      sample: true
    delayed_acks:
      description:
        - When checked (enabled), specifies the system can send fewer than one ACK
          (acknowledgment) segment per data segment received.
      returned: queried
      type: bool
      sample: true
    dsack:
      description:
        - D-SACK (RFC 2883)
        - When C(true), specifies the use of the selective ACK (SACK) option to acknowledge
          duplicate segments.
      returned: queried
      type: bool
      sample: true
    early_retransmit:
      description:
        - When C(true), specifies the system uses early retransmit (as specified in
          RFC 5827) to reduce the recovery time for connections that are receive- buffer
          or user-data limited.
      returned: queried
      type: bool
      sample: true
    explicit_congestion_notification:
      description:
        - When C(true), specifies the system uses the TCP flags CWR (congestion window
          reduction) and ECE (ECN-Echo) to notify its peer of congestion and congestion
          counter-measures.
      returned: queried
      type: bool
      sample: true
    enhanced_loss_recovery:
      description:
        - Specifies whether the system uses enhanced loss recovery to recover from random
          packet losses more effectively.
      returned: queried
      type: bool
      sample: true
    fast_open:
      description:
        - When C(true), specifies, the system supports TCP Fast Open, which reduces
          latency by allowing a client to include the first packet of data with the SYN
      returned: queried
      type: bool
      sample: true
    fast_open_cookie_expiration:
      description:
        - Specifies the number of seconds that a Fast Open Cookie delivered to a client
          is valid for SYN packets from that client.
      returned: queried
      type: int
      sample: 1000
    fin_wait_1:
      description:
        - Specifies the length of time that a TCP connection is in the FIN-WAIT-1 or
          CLOSING state before quitting.
      returned: queried
      type: str
      sample: indefinite
    fin_wait_2:
      description:
        - Specifies the length of time a TCP connection is in the FIN-WAIT-2 state
          before quitting.
      returned: queried
      type: str
      sample: 100
    idle_timeout:
      description:
        - Specifies the length of time a connection is idle (has no traffic) before
          the connection is eligible for deletion.
      returned: queried
      type: str
      sample: 300
    initial_congestion_window_size:
      description:
        - Specifies the initial congestion window size for connections to this destination.
      returned: queried
      type: int
      sample: 3
    initial_receive_window_size:
      description:
        - Specifies the initial receive window size for connections to this destination.
      returned: queried
      type: int
      sample: 5
    dont_fragment_flag:
      description:
        - Specifies the Don't Fragment (DF) bit setting in the IP Header of the outgoing
          TCP packet.
      returned: queried
      type: str
      sample: pmtu
    ip_tos:
      description:
        - Specifies the L3 Type of Service (ToS) level the system inserts in TCP
          packets destined for clients.
      returned: queried
      type: str
      sample: mimic
    time_to_live:
      description:
        - Specifies the outgoing TCP packet's IP Header TTL mode.
      returned: queried
      type: str
      sample: proxy
    time_to_live_v4:
      description:
        - Specifies the outgoing packet's IP Header TTL value for IPv4 traffic.
      returned: queried
      type: int
      sample: 255
    time_to_live_v6:
      description:
        - Specifies the outgoing packet's IP Header TTL value for IPv6 traffic.
      returned: queried
      type: int
      sample: 64
    keep_alive_interval:
      description:
        - Specifies how frequently the system sends data over an idle TCP
          connection, to determine whether the connection is still valid.
      returned: queried
      type: str
      sample: 50
    limited_transmit_recovery:
      description:
        - When C(true), specifies the system uses limited transmit recovery
          revisions for fast retransmits (as specified in RFC 3042) to reduce
          the recovery time for connections on a lossy network.
      returned: queried
      type: bool
      sample: true
    link_qos:
      description:
        - Specifies the L2 Quality of Service (QoS) level the system inserts
          in TCP packets destined for clients.
      returned: queried
      type: str
      sample: 200
    max_segment_retrans:
      description:
        - Specifies the maximum number of times that the system resends data segments.
      returned: queried
      type: int
      sample: 8
    max_syn_retrans:
      description:
        - Specifies the maximum number of times the system resends a SYN
          packet when it does not receive a corresponding SYN-ACK.
      returned: queried
      type: int
      sample: 3
    max_segment_size:
      description:
        - Specifies the largest amount of data the system can receive in a
          single TCP segment, not including the TCP and IP headers.
      returned: queried
      type: int
      sample: 1460
    md5_signature:
      description:
        - When C(true), specifies to use RFC2385 TCP-MD5 signatures to protect
          TCP traffic against intermediate tampering.
      returned: queried
      type: bool
      sample: true
    minimum_rto:
      description:
        - Specifies the minimum length of time the system waits for
          acknowledgements of data sent before resending the data.
      returned: queried
      type: int
      sample: 1000
    multipath_tcp:
      description:
        - When C(true), specifies the system accepts Multipath TCP (MPTCP)
          connections, which allow multiple client-side flows to connect to a
          single server-side flow.
      returned: queried
      type: bool
      sample: true
    mptcp_checksum:
      description:
        - When C(true), specifies the system calculates the checksum for
          MPTCP connections.
      returned: queried
      type: bool
      sample: false
    mptcp_checksum_verify:
      description:
        - When C(true), specifies the system verifies the checksum for
          MPTCP connections.
      returned: queried
      type: bool
      sample: false
    mptcp_fallback:
      description:
        - Specifies an action on fallback, that is, when MPTCP transitions
          to regular TCP, because something prevents MPTCP from working correctly.
      returned: queried
      type: str
      sample: reset
    mptcp_fast_join:
      description:
        - When C(true), specifies a FAST join, allowing data to be sent on the
          MP_JOIN_SYN, which can allow a server response to occur in parallel
          with the JOIN.
      returned: queried
      type: bool
      sample: false
    mptcp_idle_timeout:
      description:
        - Specifies the number of seconds that an MPTCP connection is idle
          before the connection is eligible for deletion.
      returned: queried
      type: int
      sample: 300
    mptcp_join_max:
      description:
        - Specifies the highest number of MPTCP connections that can join to
          a given connection.
      returned: queried
      type: int
      sample: 5
    mptcp_make_after_break:
      description:
        - Specifies make-after-break functionality is supported, allowing
          for long-lived MPTCP sessions.
      returned: queried
      type: bool
      sample: false
    mptcp_no_join_dss_ack:
      description:
        - When checked (enabled), specifies no DSS option is sent on the
          JOIN ACK.
      returned: queried
      type: bool
      sample: false
    mptcp_rto_max:
      description:
        - Specifies the number of RTOs (retransmission timeouts) before declaring
          the subflow dead.
      returned: queried
      type: int
      sample: 5
    mptcp_retransmit_min:
      description:
        - Specifies the minimum value (in msec) of the retransmission timer for
          these MPTCP flows.
      returned: queried
      type: int
      sample: 1000
    mptcp_subflow_max:
      description:
        - Specifies the maximum number of MPTCP subflows for a single flow.
      returned: queried
      type: int
      sample: 6
    mptcp_timeout:
      description:
        - Specifies, in seconds, the timeout value to discard long-lived sessions
          that do not have an active flow.
      returned: queried
      type: int
      sample: 3600
    nagle_algorithm:
      description:
        - Specifies whether the system applies Nagle's algorithm to reduce the
          number of short segments on the network.
      returned: queried
      type: bool
      sample: false
    pkt_loss_ignore_burst:
      description:
        - Specifies the probability of performing congestion control when
          multiple packets are lost, even if the Packet Loss Ignore Rate was
          not exceeded.
      returned: queried
      type: int
      sample: 0
    pkt_loss_ignore_rate:
      description:
        - Specifies the threshold of packets lost per million at which the
          system performs congestion control.
      returned: queried
      type: int
      sample: 0
    proxy_buffer_high:
      description:
        - Specifies the proxy buffer level, in bytes, at which the receive window
          is closed.
      returned: queried
      type: int
      sample: 49152
    proxy_buffer_low:
      description:
        - Specifies the proxy buffer level, in bytes, at which the receive window
          is opened.
      returned: queried
      type: int
      sample: 32768
    proxy_max_segment:
      description:
        - When C(true), specifies the system attempts to advertise the same
          maximum segment size (MSS) to the server-side connection as that of the
          client-side connection.
      returned: queried
      type: bool
      sample: true
    proxy_options:
      description:
        - When C(true), specifies the system advertises an option (such as
          time stamps) to the server only when the option is negotiated with the
          client.
      returned: queried
      type: bool
      sample: false
    push_flag:
      description:
        - Specifies how the BIG-IP system receives ACKs.
      returned: queried
      type: str
      sample: default
    rate_pace:
      description:
        - When C(true), specifies the system paces the egress packets to
          avoid dropping packets, allowing for optimum goodput.
      returned: queried
      type: bool
      sample: true
    rate_pace_max_rate:
      description:
        - Specifies the maximum rate in bytes per second to which the system
          paces TCP data transmission.
      returned: queried
      type: int
      sample: 0
    receive_window:
      description:
        - Specifies the maximum advertised RECEIVE window size.
      returned: queried
      type: int
      sample: 65535
    reset_on_timeout:
      description:
        - When C(true), specifies the system sends a reset packet (RST)
          in addition to deleting the connection, when a connection exceeds
          the idle timeout value.
      returned: queried
      type: bool
      sample: true
    retransmit_threshold:
      description:
        - Specifies the number of duplicate ACKs (retransmit threshold) to start
          fast recovery.
      returned: queried
      type: int
      sample: 3
    selective_acks:
      description:
        - When C(true), specifies the system processes data using
          selective ACKs (SACKs) whenever possible, to improve system performance.
      returned: queried
      type: bool
      sample: true
    selective_nack:
      description:
        - When C(true), specifies the system processes data using a selective
          negative acknowledgment (SNACK) whenever possible, to improve system
          performance.
      returned: queried
      type: bool
      sample: true
    send_buffer:
      description:
        - Specifies the SEND window size.
      returned: queried
      type: int
      sample: 65535
    slow_start:
      description:
        - When C(true), specifies the system uses Slow-Start Congestion
          Avoidance as described in RFC3390 in order to ramp up traffic without
          causing excessive congestion on the link.
      returned: queried
      type: bool
      sample: true
    syn_cookie_enable:
      description:
        - Specifies the default (if no DoS profile is associated) number of
          embryonic connections that are allowed on any virtual server,
          before SYN Cookie challenges are enabled for that virtual server.
      returned: queried
      type: bool
      sample: true
    syn_cookie_white_list:
      description:
        - Specifies whether or not to use a SYN Cookie WhiteList when doing
          software SYN Cookies.
      returned: queried
      type: bool
      sample: false
    syn_retrans_to_base:
      description:
        - Specifies the initial RTO (Retransmission TimeOut) base multiplier
          for SYN retransmissions.
      returned: queried
      type: int
      sample: 3000
    tail_loss_probe:
      description:
        - When C(true), specifies the system uses Tail Loss Probe to
          reduce the number of retransmission timeouts.
      returned: queried
      type: bool
      sample: true
    time_wait_recycle:
      description:
        - When C(true), specifies that connections in a TIME-WAIT state are
          reused when the system receives a SYN packet, indicating a request
          for a new connection.
      returned: queried
      type: bool
      sample: true
    time_wait:
      description:
        - Specifies the length of time that a TCP connection remains in the
          TIME-WAIT state before entering the CLOSED state.
      returned: queried
      type: str
      sample: 2000
    timestamps:
      description:
        - When C(true), specifies the system uses the timestamps extension
          for TCP (as specified in RFC 1323) to enhance high-speed network performance.
      returned: queried
      type: bool
      sample: true
    verified_accept:
      description:
        - When C(true), specifies the system can actually communicate with
          the server before establishing a client connection.
      returned: queried
      type: bool
      sample: true
    zero_window_timeout:
      description:
        - Specifies the timeout in milliseconds for terminating a connection
          with an effective zero length TCP transmit window.
      returned: queried
      type: str
      sample: 2000
  sample: hash/dictionary of values
traffic_groups:
  description: Traffic group related information.
  returned: When C(traffic-groups) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/tg1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: tg1
    description:
      description:
        - Description of the traffic group.
      returned: queried
      type: str
      sample: My traffic group
    auto_failback_enabled:
      description:
        - Specifies whether the traffic group fails back to the default
          device.
      returned: queried
      type: bool
      sample: true
    auto_failback_time:
      description:
        - Specifies the time required to fail back.
      returned: queried
      type: int
      sample: 60
    ha_load_factor:
      description:
        - Specifies a number for this traffic group that represents the load
          this traffic group presents to the system relative to other
          traffic groups.
      returned: queried
      type: int
      sample: 1
    ha_order:
      description:
        - This list of devices specifies the order in which the devices will
          become active for the traffic group when a failure occurs.
      returned: queried
      type: list
      sample: ['/Common/device1', '/Common/device2']
    is_floating:
      description:
        - Indicates whether the traffic group can fail over to other devices
          in the device group.
      returned: queried
      type: bool
      sample: false
    mac_masquerade_address:
      description:
        - Specifies a MAC address for the traffic group.
      returned: queried
      type: str
      sample: "00:98:76:54:32:10"
  sample: hash/dictionary of values
trunks:
  description: Trunk related information.
  returned: When C(trunks) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/trunk1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: trunk1
    description:
      description:
        - Description of the Trunk.
      returned: queried
      type: str
      sample: My trunk
    media_speed:
      description:
        - Speed of the media attached to the trunk.
      returned: queried
      type: int
      sample: 10000
    lacp_mode:
      description:
        - The operation mode for LACP.
      returned: queried
      type: str
      sample: passive
    lacp_enabled:
      description:
        - Whether LACP is enabled or not.
      returned: queried
      type: bool
      sample: true
    stp_enabled:
      description:
        - Whether Spanning Tree Protocol (STP) is enabled or not.
      returned: queried
      type: bool
      sample: true
    operational_member_count:
      description:
        - Number of working members associated with the trunk.
      returned: queried
      type: int
      sample: 1
    media_status:
      description:
        - Whether the media that is part of the trunk is up or not.
      returned: queried
      type: bool
      sample: true
    link_selection_policy:
      description:
        - The LACP policy the trunk uses to determine which member link can handle
          new traffic.
      returned: queried
      type: str
      sample: maximum-bandwidth
    lacp_timeout:
      description:
        - The rate at which the system sends the LACP control packets.
      returned: queried
      type: int
      sample: 10
    interfaces:
      description:
        - The list of interfaces that are part of the trunk.
      returned: queried
      type: list
      sample: ['1.2', '1.3']
    distribution_hash:
      description:
        - The basis for the hash that the system uses as the frame distribution algorithm.
        - The system uses this hash to determine which interface to use for forwarding
          traffic.
      returned: queried
      type: str
      sample: src-dst-ipport
    configured_member_count:
      description:
        - The number of configured members that are associated with the trunk.
      returned: queried
      type: int
      sample: 1
  sample: hash/dictionary of values

ucs:
  description: UCS backup related information
  returned: When C(ucs) is specified in C(gather_subset)
  type: complex
  contains:
    file_name:
      description:
        - Name of the UCS backup file.
      returned: queried
      type: str
      sample: backup.ucs
    encrypted:
      description:
        - Whether the file is encrypted or not.
      returned: queried
      type: bool
      sample: false
    file_size:
      description:
        - Size of the UCS file in bytes.
      returned: queried
      type: str
      sample: "3"
    file_created_date:
      description:
        - Date and time when the ucs file was created.
      returned: queried
      type: str
      sample: "2022-03-10T09:30:19Z"
  sample: hash/dictionary of values
  version_added: "1.15.0"

udp_profiles:
  description: UDP profile related information.
  returned: When C(udp-profiles) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: udp
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: /Common/udp
    parent:
      description:
        - Profile from which this profile inherits settings.
      returned: queried
      type: str
      sample: udp
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: My profile
    allow_no_payload:
      description:
        - Allow the passage of datagrams that contain header information, but no essential data.
      returned: queried
      type: bool
      sample: true
    buffer_max_bytes:
      description:
        - Ingress buffer byte limit. Maximum allowed value is 16777215.
      returned: queried
      type: int
      sample: 655350
    buffer_max_packets:
      description:
        - Ingress buffer packet limit. Maximum allowed value is 255.
      returned: queried
      type: int
      sample: 0
    datagram_load_balancing:
      description:
        - Load balance UDP datagram by datagram
      returned: queried
      type: bool
      sample: true
    idle_timeout:
      description:
        - Number of seconds that a connection is idle before
          the connection is eligible for deletion.
        - In addition to a number, may be one of the values C(indefinite) or
          C(immediate).
      returned: queried
      type: bool
      sample: 200
    ip_df_mode:
      description:
        - Describes the Don't Fragment (DF) bit setting in the outgoing UDP
          packet.
        - May be one of C(pmtu), C(preserve), C(set), or C(clear).
        - When C(pmtu), sets the outgoing UDP packet DF big based on the ip
          pmtu setting.
        - When C(preserve), preserves the incoming UDP packet Don't Fragment bit.
        - When C(set), sets the outgoing UDP packet DF bit.
        - When C(clear), clears the outgoing UDP packet DF bit.
      returned: queried
      type: str
      sample: pmtu
    ip_tos_to_client:
      description:
        - The Type of Service level the traffic management
          system assigns to UDP packets when sending them to clients.
        - May be numeric, or the values C(pass-through) or C(mimic).
      returned: queried
      type: str
      sample: mimic
    ip_ttl_mode:
      description:
        - The outgoing UDP packet's TTL mode.
        - Valid modes are C(proxy), C(preserve), C(decrement), and C(set).
        - When C(proxy), sets the IP TTL of IPv4 to the default value of 255 and
          IPv6 to the default value of 64.
        - When C(preserve), sets the IP TTL to the original packet TTL value.
        - When C(decrement), sets the IP TTL to the original packet TTL value minus 1.
        - When C(set), sets the IP TTL with the specified values in C(ip_ttl_v4) and
          C(ip_ttl_v6) values in the same profile.
      returned: queried
      type: str
      sample: proxy
    ip_ttl_v4:
      description:
        - IPv4 TTL.
      returned: queried
      type: int
      sample: 10
    ip_ttl_v6:
      description:
        - IPv6 TTL.
      returned: queried
      type: int
      sample: 100
    link_qos_to_client:
      description:
        - The Quality of Service level the system assigns to
          UDP packets when sending them to clients.
        - May be either numberic or the value C(pass-through).
      returned: queried
      type: str
      sample: pass-through
    no_checksum:
      description:
        - Whether checksum processing is enabled or disabled.
        - Note that if the datagram is IPv6, the system always performs
          checksum processing.
      returned: queried
      type: bool
      sample: true
    proxy_mss:
      description:
        - When C(true), specifies the system advertises the same mss
          to the server as was negotiated with the client.
      returned: queried
      type: bool
      sample: true
  sample: hash/dictionary of values
users:
  description: Details of the users on the system.
  returned: When C(users) is specified in C(gather_subset).
  type: complex
  contains:
    description:
      description:
        - Description of the resource.
      returned: queried
      type: str
      sample: Admin user
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: admin
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: admin
    partition_access:
      description:
        - Partition that user has access to, including user role.
      returned: queried
      type: complex
      contains:
        name:
          description:
            - Name of partition.
          returned: queried
          type: str
          sample: all-partitions
        role:
          description:
            - Role allowed to user on partition.
          returned: queried
          type: str
          sample: auditor
    shell:
      description:
        - The shell assigned to the user account.
      returned: queried
      type: str
      sample: tmsh
vcmp_guests:
  description: vCMP related information.
  returned: When C(vcmp-guests) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: guest1
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: guest1
    allowed_slots:
      description:
        - List of slots the guest is allowed to be assigned to.
      returned: queried
      type: list
      sample: [0, 1, 3]
    assigned_slots:
      description:
        - Slots the guest is assigned to.
      returned: queried
      type: list
      sample: [0]
    boot_priority:
      description:
        - Specifies the boot priority of the guest. A lower number means earlier to boot.
      returned: queried
      type: int
      sample: 65535
    cores_per_slot:
      description:
        - Number of cores the system allocates to the guest.
      returned: queried
      type: int
      sample: 2
    hostname:
      description:
        - FQDN assigned to the guest.
      returned: queried
      type: str
      sample: guest1.localdomain
    hotfix_image:
      description:
        - Hotfix image to install onto any of this guest's newly created virtual disks.
      returned: queried
      type: str
      sample: Hotfix-BIGIP-12.1.3.4-0.0.2-hf1.iso
    initial_image:
      description:
        - Software image to install onto any of this guest's newly created virtual disks.
      returned: queried
      type: str
      sample: BIGIP-12.1.3.4-0.0.2.iso
    mgmt_route:
      description:
        - Management gateway IP address for the guest.
      returned: queried
      type: str
      sample: 2.2.2.1
    mgmt_address:
      description:
        - Management IP address configuration for the guest.
      returned: queried
      type: str
      sample: 2.3.2.3
    mgmt_network:
      description:
        - Accessibility of this vCMP guest's management network.
      returned: queried
      type: str
      sample: bridged
    vlans:
      description:
        - List of VLANs on which the guest is either enabled or disabled.
      returned: queried
      type: list
      sample: ['/Common/vlan1', '/Common/vlan2']
    min_number_of_slots:
      description:
        - Specifies the minimum number of slots the guest must be assigned to.
      returned: queried
      type: int
      sample: 2
    number_of_slots:
      description:
        - Specifies the number of slots the guest should be assigned to.
        - This number is always greater than, or equal to, C(min_number_of_slots).
      returned: queried
      type: int
      sample: 2
    ssl_mode:
      description:
        - The SSL hardware allocation mode for the guest.
      returned: queried
      type: str
      sample: shared
    state:
      description:
        - Specifies the state of the guest.
        - May be one of C(configured), C(provisioned), or C(deployed).
        - Each state implies the actions of all states before it.
      returned: queried
      type: str
      sample: provisioned
    virtual_disk:
      description:
        - The filename of the virtual disk to use for this guest.
      returned: queried
      type: str
      sample: guest1.img
  sample: hash/dictionary of values
virtual_addresses:
  description: Virtual address related information.
  returned: When C(virtual-addresses) is specified in C(gather_subset).
  type: complex
  contains:
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/2.3.4.5
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: 2.3.4.5
    address:
      description:
        - The virtual IP address.
      returned: queried
      type: str
      sample: 2.3.4.5
    arp_enabled:
      description:
        - Whether or not ARP is enabled for the specified virtual address.
      returned: queried
      type: bool
      sample: true
    auto_delete_enabled:
      description:
        - Indicates if the virtual address will be deleted automatically on
          deletion of the last associated virtual server or not.
      returned: queried
      type: bool
      sample: false
    connection_limit:
      description:
        - Concurrent connection limit for one or more virtual
          servers.
      returned: queried
      type: int
      sample: 0
    description:
      description:
        - The description of the virtual address.
      returned: queried
      type: str
      sample: My virtual address
    enabled:
      description:
        - Whether the virtual address is enabled or not.
      returned: queried
      type: bool
      sample: true
    icmp_echo:
      description:
        - Whether the virtual address should reply to ICMP echo requests.
      returned: queried
      type: bool
      sample: true
    floating:
      description:
        - Property derived from the traffic group. A floating virtual
          address is a virtual address for a VLAN that serves as a shared
          address by all devices of a BIG-IP traffic-group.
      returned: queried
      type: bool
      sample: true
    netmask:
      description:
        - Netmask of the virtual address.
      returned: queried
      type: str
      sample: 255.255.255.255
    route_advertisement:
      description:
        - Specifies the route advertisement setting for the virtual address.
      returned: queried
      type: bool
      sample: false
    traffic_group:
      description:
        - Traffic group on which the virtual address is active.
      returned: queried
      type: str
      sample: /Common/traffic-group-1
    spanning:
      description:
        - Whether or not spanning is enabled for the specified virtual address.
      returned: queried
      type: bool
      sample: false
    inherited_traffic_group:
      description:
        - Indicates if the traffic group is inherited from the parent folder.
      returned: queried
      type: bool
      sample: false
  sample: hash/dictionary of values
virtual_servers:
  description: Virtual address related information.
  returned: When C(virtual-addresses) is specified in C(gather_subset).
  type: complex
  contains:
    availability_status:
      description:
        - The availability of the virtual server.
      returned: queried
      type: str
      sample: offline
    full_path:
      description:
        - Full name of the resource as known to the BIG-IP.
      returned: queried
      type: str
      sample: /Common/2.3.4.5
    name:
      description:
        - Relative name of the resource in the BIG-IP.
      returned: queried
      type: str
      sample: 2.3.4.5
    auto_lasthop:
      description:
        - When enabled, allows the system to send return traffic to the MAC address
          that transmitted the request, even if the routing table points to a different
          network or interface.
      returned: queried
      type: str
      sample: default
    bw_controller_policy:
      description:
        - The bandwidth controller for the system to use to enforce a throughput policy
          for incoming network traffic.
      returned: queried
      type: str
      sample: /Common/bw1
    client_side_bits_in:
      description:
        - Number of client-side ingress bits.
      returned: queried
      type: int
      sample: 1000
    client_side_bits_out:
      description:
        - Number of client-side egress bits.
      returned: queried
      type: int
      sample: 200
    client_side_current_connections:
      description:
        - Number of current connections client-side.
      returned: queried
      type: int
      sample: 300
    client_side_evicted_connections:
      description:
        - Number of evicted connections client-side.
      returned: queried
      type: int
      sample: 100
    client_side_max_connections:
      description:
        - Maximum number of connections client-side.
      returned: queried
      type: int
      sample: 40
    client_side_pkts_in:
      description:
        - Number of client-side ingress packets.
      returned: queried
      type: int
      sample: 1098384
    client_side_pkts_out:
      description:
        - Number of client-side egress packets.
      returned: queried
      type: int
      sample: 3484734
    client_side_slow_killed:
      description:
        - Number of slow connections killed, client-side.
      returned: queried
      type: int
      sample: 234
    client_side_total_connections:
      description:
        - Total number of connections.
      returned: queried
      type: int
      sample: 24
    cmp_enabled:
      description:
        - Whether or not clustered multi-processor (CMP) acceleration is enabled.
      returned: queried
      type: bool
      sample: true
    cmp_mode:
      description:
        - The clustered-multiprocessing mode.
      returned: queried
      type: str
      sample: all-cpus
    connection_limit:
      description:
        - Maximum number of concurrent connections you want to allow for the virtual server.
      returned: queried
      type: int
      sample: 100
    description:
      description:
        - The description of the virtual server.
      returned: queried
      type: str
      sample: My virtual
    enabled:
      description:
        - Whether or not the virtual is enabled.
      returned: queried
      type: bool
      sample: true
    ephemeral_bits_in:
      description:
        - Number of ephemeral ingress bits.
      returned: queried
      type: int
      sample: 1000
    ephemeral_bits_out:
      description:
        - Number of ephemeral egress bits.
      returned: queried
      type: int
      sample: 200
    ephemeral_current_connections:
      description:
        - Number of ephemeral current connections.
      returned: queried
      type: int
      sample: 300
    ephemeral_evicted_connections:
      description:
        - Number of ephemeral evicted connections.
      returned: queried
      type: int
      sample: 100
    ephemeral_max_connections:
      description:
        - Maximum number of ephemeral connections.
      returned: queried
      type: int
      sample: 40
    ephemeral_pkts_in:
      description:
        - Number of ephemeral ingress packets.
      returned: queried
      type: int
      sample: 1098384
    ephemeral_pkts_out:
      description:
        - Number of ephemeral egress packets.
      returned: queried
      type: int
      sample: 3484734
    ephemeral_slow_killed:
      description:
        - Number of ephemeral slow connections killed.
      returned: queried
      type: int
      sample: 234
    ephemeral_total_connections:
      description:
        - Total number of ephemeral connections.
      returned: queried
      type: int
      sample: 24
    total_software_accepted_syn_cookies:
      description:
        - SYN Cookies Total Software Accepted.
      returned: queried
      type: int
      sample: 0
    total_hardware_accepted_syn_cookies:
      description:
        - SYN Cookies Total Hardware Accepted.
      returned: queried
      type: int
      sample: 0
    total_hardware_syn_cookies:
      description:
        - SYN Cookies Total Hardware.
      returned: queried
      type: int
      sample: 0
    hardware_syn_cookie_instances:
      description:
        - Hardware SYN Cookie Instances.
      returned: queried
      type: int
      sample: 0
    total_software_rejected_syn_cookies:
      description:
        - Total Software Rejected.
      returned: queried
      type: int
      sample: 0
    software_syn_cookie_instances:
      description:
        - Software SYN Cookie Instances.
      returned: queried
      type: int
      sample: 0
    current_syn_cache:
      description:
        - Current SYN Cache.
      returned: queried
      type: int
      sample: 0
    max_conn_duration:
      description:
        - Max Conn Duration/msec.
      returned: queried
      type: int
      sample: 0
    mean_conn_duration:
      description:
        - Mean Conn Duration/msec.
      returned: queried
      type: int
      sample: 0
    min_conn_duration:
      description:
        - Min Conn Duration/msec.
      returned: queried
      type: int
      sample: 0
    cpu_usage_ratio_last_5_min:
      description:
        - CPU Usage Ratio (%) Last 5 Minutes.
      returned: queried
      type: int
      sample: 0
    cpu_usage_ratio_last_5_sec:
      description:
        - CPU Usage Ratio (%) Last 5 Seconds.
      returned: queried
      type: int
      sample: 0
    cpu_usage_ratio_last_1_min:
      description:
        - CPU Usage Ratio (%) Last 1 Minute.
      returned: queried
      type: int
      sample: 0
    syn_cache_overflow:
      description:
        - SYN Cache Overflow.
      returned: queried
      type: int
      sample: 0
    total_software_syn_cookies:
      description:
        - Total Software SYN Cookies
      returned: queried
      type: int
      sample: 0
    syn_cookies_status:
      description:
        - SYN Cookies Status.
      returned: queried
      type: str
      sample: not-activated
    fallback_persistence_profile:
      description:
        - Fallback persistence profile for the virtual server to use
          when the default persistence profile is not available.
      returned: queried
      type: str
      sample: /Common/fallback1
    persistence_profile:
      description:
        - The persistence profile you want the system to use as the default
          for this virtual server.
      returned: queried
      type: str
      sample: /Common/persist1
    translate_port:
      description:
        - Enables or disables port translation.
      returned: queried
      type: bool
      sample: true
    translate_address:
      description:
        - Enables or disables address translation for the virtual server.
      returned: queried
      type: bool
      sample: true
    vlans:
      description:
        - List of VLANs on which the virtual server is either enabled or disabled.
      returned: queried
      type: list
      sample: ['/Common/vlan1', '/Common/vlan2']
    destination:
      description:
        - Name of the virtual address and service on which the virtual server
          listens for connections.
      returned: queried
      type: str
      sample: /Common/2.2.3.3%1:76
    last_hop_pool:
      description:
        - Name of the last hop pool you want the virtual
          server to use to direct reply traffic to the last hop router.
      returned: queried
      type: str
      sample: /Common/pool1
    nat64_enabled:
      description:
        - Whether or not NAT64 is enabled.
      returned: queried
      type: bool
      sample: true
    source_port_behavior:
      description:
        - Specifies whether the system preserves the source port of the connection.
      returned: queried
      type: str
      sample: preserve
    ip_intelligence_policy:
      description:
        - IP Intelligence policy assigned to the virtual.
      returned: queried
      type: str
      sample: /Common/ip1
    protocol:
      description:
        - IP protocol for which you want the virtual server to direct traffic.
      returned: queried
      type: str
      sample: tcp
    default_pool:
      description:
        - Pool name you want the virtual server to use as the default pool.
      returned: queried
      type: str
      sample: /Common/pool1
    rate_limit_mode:
      description:
        - Indicates whether the rate limit is applied per virtual object,
          per source address, per destination address, or some combination
          thereof.
      returned: queried
      type: str
      sample: object
    rate_limit_source_mask:
      description:
        - Specifies a mask, in bits, to be applied to the source address as
          part of the rate limiting.
      returned: queried
      type: int
      sample: 0
    rate_limit:
      description:
        - Maximum number of connections per second allowed for a virtual server.
      returned: queried
      type: int
      sample: 34
    snat_type:
      description:
        - Specifies the type of source address translation associated
          with the specified virtual server.
      returned: queried
      type: str
      sample: none
    snat_pool:
      description:
        - Specifies the name of a LSN or SNAT pool used by the specified virtual server.
      returned: queried
      type: str
      sample: /Common/pool1
    serverssl_use_sni:
      description:
        - Specifies whether SNI is enabled or disabled on the server-side SSL connection.
      returned: queried
      type: bool
      sample: true
    status_reason:
      description:
        - If there is a problem with the status of the virtual, it is reported here.
      returned: queried
      type: str
      sample: The children pool member(s) either don't have service checking...
    gtm_score:
      description:
        - Specifies a score that is associated with the virtual server.
      returned: queried
      type: int
      sample: 0
    rate_class:
      description:
        - Name of an existing rate class you want the
          virtual server to use to enforce a throughput policy for incoming
          network traffic.
      returned: queried
      type: str
    rate_limit_destination_mask:
      description:
        - Specifies a mask, in bits, to be applied to the destination
          address as part of the rate limiting.
      returned: queried
      type: int
      sample: 32
    source_address:
      description:
        - Specifies an IP address or network from which the virtual server
          will accept traffic.
      returned: queried
      type: str
      sample: 0.0.0./0
    authentication_profile:
      description:
        - Specifies a list of authentication profile names, separated by
          spaces, that the virtual server uses to manage authentication.
      returned: queried
      type: list
      sample: ['/Common/ssl_drldp']
    connection_mirror_enabled:
      description:
        - Whether or not connection mirroring is enabled.
      returned: queried
      type: bool
      sample: true
    irules:
      description:
        - List of iRules that customize the virtual server to direct and manage traffic.
      returned: queried
      type: list
      sample: ['/Common/rule1', /Common/rule2']
    policies:
      description:
        - List of LTM policies attached to the virtual server.
      returned: queried
      type: list
      sample: ['/Common/policy1', /Common/policy2']
    security_log_profiles:
      description:
        - Specifies the log profile applied to the virtual server.
      returned: queried
      type: list
      sample: ['/Common/global-network', '/Common/local-dos']
    type:
      description:
        - Virtual server type.
      returned: queried
      type: str
      sample: standard
    destination_address:
      description:
        - Address portion of the C(destination).
      returned: queried
      type: str
      sample: 2.3.3.2
    destination_port:
      description:
        - Port potion of the C(destination).
      returned: queried
      type: int
      sample: 80
    profiles:
      description:
        - List of the profiles attached to the virtual.
      type: complex
      contains:
        context:
          description:
            - Which side of the connection the profile affects; either C(all),
              C(client-side) or C(server-side).
          returned: queried
          type: str
          sample: client-side
        full_path:
          description:
            - Full name of the resource as known to the BIG-IP.
          returned: queried
          type: str
          sample: /Common/tcp
        name:
          description:
            - Relative name of the resource in the BIG-IP.
          returned: queried
          type: str
          sample: tcp
    per_flow_request_access_policy:
          description:
            - per request policy.
          returned: queried
          type: str
          sample: /Common/my-custom-per-request-policy
    total_requests:
      description:
        - Total requests.
      returned: queried
      type: int
      sample: 8
  sample: hash/dictionary of values
vlans:
  description: List of VLAN information.
  returned: When C(vlans) is specified in C(gather_subset).
  type: complex
  contains:
    auto_lasthop:
      description:
        - Allows the system to send return traffic to the MAC address that transmitted the
          request, even if the routing table points to a different network or interface.
      returned: queried
      type: str
      sample: enabled
    cmp_hash_algorithm:
      description:
        - Specifies how the traffic on the VLAN will be disaggregated.
      returned: queried
      type: str
      sample: default
    description:
      description:
        - Description of the VLAN.
      returned: queried
      type: str
      sample: My vlan
    failsafe_action:
      description:
        - Action for the system to take when the fail-safe mechanism is triggered.
      returned: queried
      type: str
      sample: reboot
    failsafe_enabled:
      description:
        - Whether failsafe is enabled or not.
      returned: queried
      type: bool
      sample: true
    failsafe_timeout:
      description:
        - Number of seconds that an active unit can run without detecting network traffic
          on this VLAN before it starts a failover.
      returned: queried
      type: int
      sample: 90
    if_index:
      description:
        - Index assigned to this VLAN. It is a unique identifier assigned for all objects
          displayed in the SNMP IF-MIB.
      returned: queried
      type: int
      sample: 176
    learning_mode:
      description:
        - Whether switch ports placed in the VLAN are configured for switch learning,
          forwarding only, or dropped.
      returned: queried
      type: str
      sample: enable-forward
    interfaces:
      description:
        - List of tagged or untagged interfaces and trunks that you want to configure for the VLAN.
      returned: queried
      type: complex
      contains:
        full_path:
          description:
            - Full name of the resource as known to the BIG-IP.
          returned: queried
          type: str
          sample: 1.3
        name:
          description:
            - Relative name of the resource in the BIG-IP.
          returned: queried
          type: str
          sample: 1.3
        tagged:
          description:
            - Whether the interface is tagged or not.
          returned: queried
          type: bool
          sample: false
    mtu:
      description:
        - Specific maximum transition unit (MTU) for the VLAN.
      returned: queried
      type: int
      sample: 1500
    sflow_poll_interval:
      description:
        - Maximum interval in seconds between two pollings.
      returned: queried
      type: int
      sample: 0
    sflow_poll_interval_global:
      description:
        - Whether the global VLAN poll-interval setting overrides the object-level
          poll-interval setting.
      returned: queried
      type: bool
      sample: false
    sflow_sampling_rate:
      description:
        - Ratio of packets observed to the samples generated.
      returned: queried
      type: int
      sample: 0
    sflow_sampling_rate_global:
      description:
        - Whether the global VLAN sampling-rate setting overrides the object-level
          sampling-rate setting.
      returned: queried
      type: bool
      sample: true
    source_check_enabled:
      description:
        - Specifies that only connections that have a return route in the routing table are accepted.
      returned: queried
      type: bool
      sample: true
    true_mac_address:
      description:
        - Media access control (MAC) address for the lowest-numbered interface assigned to this VLAN.
      returned: queried
      type: str
      sample: "fa:16:3e:10:da:ff"
    tag:
      description:
        - Tag number for the VLAN.
      returned: queried
      type: int
      sample: 30
  sample: hash/dictionary of values
'''

import datetime
import math
import re
import time
import traceback
from collections import namedtuple
try:
    from packaging.version import Version
except ImportError:
    HAS_PACKAGING = False
    Version = None
    PACKAGING_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_PACKAGING = True
    PACKAGING_IMPORT_ERROR = None

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib, env_fallback
)
from ansible.module_utils.parsing.convert_bool import BOOLEANS_TRUE
from ansible.module_utils.six import (
    iteritems, string_types
)
from ansible.module_utils.urls import urlparse

from ipaddress import ip_interface

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.urls import parseStats
from ..module_utils.icontrol import (
    tmos_version, modules_provisioned, packages_installed
)
from ..module_utils.ipaddress import is_valid_ip
from ..module_utils.teem import send_teem

from concurrent.futures import ThreadPoolExecutor, as_completed


class BaseManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = kwargs.get('client', None)
        self.kwargs = kwargs

        # A list of modules currently provisioned on the device.
        #
        # This list is used by different fact managers to check to see
        # if they should even attempt to gather information. If the module is
        # not provisioned, then it is likely that the REST API will not
        # return valid data.
        #
        # For example, ASM (at the time of this writing 13.x/14.x) will
        # raise an exception if you attempt to query its APIs if it is
        # not provisioned. An example error message is shown below.
        #
        #  {
        #    "code": 400,
        #    "message": "java.net.ConnectException: Connection refused (Connection refused)",
        #    "referer": "172.18.43.40",
        #    "restOperationId": 18164160,
        #    "kind": ":resterrorresponse"
        #  }
        #
        # This list is provided to the specific fact manager by the
        # master ModuleManager of this module.
        self.provisioned_modules = []

        # A list of packages currently installed on the device.
        #
        # This list is used by different fact managers to check to see
        # if they should even attempt to gather information. If the package is
        # not provisioned, then it is likely that the REST API will not
        # return valid data.
        #
        # This list is provided to the specific fact manager by the
        # master ModuleManager of this module.
        self.installed_packages = []

    def exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        return results


class Parameters(AnsibleF5Parameters):
    @property
    def gather_subset(self):
        if isinstance(self._values['gather_subset'], string_types):
            self._values['gather_subset'] = [self._values['gather_subset']]
        elif not isinstance(self._values['gather_subset'], list):
            raise F5ModuleError(
                "The specified gather_subset must be a list."
            )
        tmp = list(set(self._values['gather_subset']))
        tmp.sort()
        self._values['gather_subset'] = tmp

        return self._values['gather_subset']


class BaseParameters(Parameters):
    @property
    def enabled(self):
        return flatten_boolean(self._values['enabled'])

    @property
    def disabled(self):
        return flatten_boolean(self._values['disabled'])

    def _remove_internal_keywords(self, resource):
        resource.pop('kind', None)
        resource.pop('generation', None)
        resource.pop('selfLink', None)
        resource.pop('isSubcollection', None)
        # resource.pop('fullPath', None)

    def to_return(self):
        result = {}
        for returnable in self.returnables:
            result[returnable] = getattr(self, returnable)
        result = self._filter_params(result)
        return result


class ApmAccessProfileFactParameters(BaseParameters):
    api_map = {
        'accessPolicy': 'access_policy',
        'fullPath': 'full_path',
    }

    returnables = [
        'access_policy',
        'full_path',
        'name',
    ]


class ApmAccessProfileFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ApmAccessProfileFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(apm_access_profiles=facts)
        return result

    def _exec_module(self):
        if 'apm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = ApmAccessProfileFactParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/apm/profile/access".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class ApmAccessPolicyFactParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
    }

    returnables = [
        'full_path',
        'name',
    ]


class ApmAccessPolicyFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ApmAccessPolicyFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(apm_access_policies=facts)
        return result

    def _exec_module(self):
        if 'apm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = ApmAccessProfileFactParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/apm/policy/access-policy".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class As3Parameters(BaseParameters):
    api_map = {
    }

    returnables = [

    ]


class As3FactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        self.installed_packages = packages_installed(self.client)
        super(As3FactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(as3_config=facts)
        return result

    def _exec_module(self):
        if 'as3' not in self.installed_packages:
            return []
        facts = self.read_facts()
        return facts

    def read_facts(self):
        collection = self.read_collection_from_device()
        return collection

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/shared/appsvcs/declare".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status == 204 or 'code' in response and response['code'] == 204:
            return []

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'class' not in response:
            return []
        result = dict()
        result['declaration'] = response
        return result


class AsmPolicyStatsParameters(BaseParameters):
    api_map = {

    }

    returnables = [
        'policies',
        'parent_policies',
        'policies_pending_changes',
        'policies_active',
        'policies_attached',
        'policies_inactive',
        'policies_unattached',
    ]

    @property
    def policies(self):
        if self._values['policies'] is None or len(self._values['policies']) == 0:
            return None
        return len(self._values['policies'])

    @property
    def parent_policies(self):
        if self._values['policies'] is None or len(self._values['policies']) == 0:
            return None
        return len([x for x in self._values['policies'] if 'type' in x and x['type'] == "parent"])

    @property
    def policies_pending_changes(self):
        if self._values['policies'] is None or len(self._values['policies']) == 0:
            return None
        return len([x for x in self._values['policies'] if x['isModified'] is True])


class AsmPolicyStatsParametersv13(AsmPolicyStatsParameters):
    @property
    def policies_active(self):
        if self._values['policies'] is None or len(self._values['policies']) == 0:
            return None
        return len([x for x in self._values['policies'] if 'active' in x and x['active']])

    @property
    def policies_inactive(self):
        if self._values['policies'] is None or len(self._values['policies']) == 0:
            return None
        return len([x for x in self._values['policies'] if 'active' in x and x['active'] is not True])

    @property
    def policies_attached(self):
        return self.policies_active

    @property
    def policies_unattached(self):
        return self.policies_inactive


class AsmPolicyStatsParametersv12(AsmPolicyStatsParameters):
    @property
    def policies_active(self):
        if self._values['policies'] is None or len(self._values['policies']) == 0:
            return None
        return len([x for x in self._values['policies'] if x['active'] is True])

    @property
    def policies_inactive(self):
        if self._values['policies'] is None or len(self._values['policies']) == 0:
            return None
        return len([x for x in self._values['policies'] if x['active'] is not True])

    @property
    def policies_attached(self):
        if self._values['policies'] is None or len(self._values['policies']) == 0:
            return None
        return len([x for x in self._values['policies']
                    if x['active'] is True and len(x['virtualServers']) > 0])

    @property
    def policies_unattached(self):
        if self._values['policies'] is None or len(self._values['policies']) == 0:
            return None
        return len([x for x in self._values['policies']
                    if x['active'] is False and len(x['virtualServers']) == 0])


class AsmPolicyStatsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(AsmPolicyStatsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(asm_policy_stats=facts)
        return result

    def _exec_module(self):
        if 'asm' not in self.provisioned_modules:
            return []
        facts = self.read_facts()
        results = facts.to_return()
        return results

    def version_is_less_than_13(self):
        version = tmos_version(self.client)
        if Version(version) < Version('13.0.0'):
            return True
        else:
            return False

    def read_facts(self):
        collection = self.read_collection_from_device()
        if self.version_is_less_than_13():
            params = AsmPolicyStatsParametersv12(params=collection)
        else:
            params = AsmPolicyStatsParametersv13(params=collection)
        return params

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/asm/policies".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)
        return dict(
            policies=response['items']
        )


class AsmPolicyFactParameters(BaseParameters):
    api_map = {
        'hasParent': 'has_parent',
        'protocolIndependent': 'protocol_independent',
        'virtualServers': 'virtual_servers',
        'manualVirtualServers': 'manual_virtual_servers',
        'allowedResponseCodes': 'allowed_response_codes',
        'learningMode': 'learning_mode',
        'enforcementMode': 'enforcement_mode',
        'customXffHeaders': 'custom_xff_headers',
        'caseInsensitive': 'case_insensitive',
        'stagingSettings': 'staging_settings',
        'applicationLanguage': 'application_language',
        'trustXff': 'trust_xff',
        'geolocation-enforcement': 'geolocation_enforcement',
        'disallowedLocations': 'disallowed_locations',
        'signature-settings': 'signature_settings',
        'header-settings': 'header_settings',
        'cookie-settings': 'cookie_settings',
        'policy-builder': 'policy_builder',
        'disallowed-geolocations': 'disallowed_geolocations',
        'whitelist-ips': 'whitelist_ips',
        'fullPath': 'full_path',
        'csrf-protection': 'csrf_protection',
        'isModified': 'apply',
    }

    returnables = [
        'full_path',
        'name',
        'policy_id',
        'active',
        'protocol_independent',
        'has_parent',
        'type',
        'virtual_servers',
        'allowed_response_codes',
        'description',
        'learning_mode',
        'enforcement_mode',
        'custom_xff_headers',
        'case_insensitive',
        'signature_staging',
        'place_signatures_in_staging',
        'enforcement_readiness_period',
        'path_parameter_handling',
        'trigger_asm_irule_event',
        'inspect_http_uploads',
        'mask_credit_card_numbers_in_request',
        'maximum_http_header_length',
        'use_dynamic_session_id_in_url',
        'maximum_cookie_header_length',
        'application_language',
        'trust_xff',
        'disallowed_geolocations',
        'csrf_urls',
        'csrf_protection_enabled',
        'csrf_protection_ssl_only',
        'csrf_protection_expiration_time_in_seconds',
        'apply',
    ]

    def _morph_keys(self, key_map, item):
        for k, v in iteritems(key_map):
            item[v] = item.pop(k, None)
        result = self._filter_params(item)
        return result

    @property
    def active(self):
        return flatten_boolean(self._values['active'])

    @property
    def apply(self):
        return flatten_boolean(self._values['apply'])

    @property
    def case_insensitive(self):
        return flatten_boolean(self._values['case_insensitive'])

    @property
    def has_parent(self):
        return flatten_boolean(self._values['has_parent'])

    @property
    def policy_id(self):
        if self._values['id'] is None:
            return None
        return self._values['id']

    @property
    def manual_virtual_servers(self):
        if 'manual_virtual_servers' in self._values:
            if self._values['manual_virtual_servers'] is None:
                return None
            return self._values['manual_virtual_servers']

    @property
    def signature_staging(self):
        if 'staging_settings' in self._values:
            if self._values['staging_settings'] is None:
                return None
            if 'signatureStaging' in self._values['staging_settings']:
                return flatten_boolean(self._values['staging_settings']['signatureStaging'])
        if 'signature_settings' in self._values:
            if self._values['signature_settings'] is None:
                return None
            if 'signatureStaging' in self._values['signature_settings']:
                return flatten_boolean(self._values['signature_settings']['signatureStaging'])

    @property
    def place_signatures_in_staging(self):
        if 'staging_settings' in self._values:
            if self._values['staging_settings'] is None:
                return None
            if 'placeSignaturesInStaging' in self._values['staging_settings']:
                return flatten_boolean(self._values['staging_settings']['placeSignaturesInStaging'])
        if 'signature_settings' in self._values:
            if self._values['signature_settings'] is None:
                return None
            if 'signatureStaging' in self._values['signature_settings']:
                return flatten_boolean(self._values['signature_settings']['placeSignaturesInStaging'])

    @property
    def enforcement_readiness_period(self):
        if 'staging_settings' in self._values:
            if self._values['staging_settings'] is None:
                return None
            if 'enforcementReadinessPeriod' in self._values['staging_settings']:
                return self._values['staging_settings']['enforcementReadinessPeriod']
        if 'general' in self._values:
            if self._values['general'] is None:
                return None
            if 'signatureStaging' in self._values['general']:
                return self._values['general']['enforcementReadinessPeriod']

    @property
    def path_parameter_handling(self):
        if 'attributes' in self._values:
            if self._values['attributes'] is None:
                return None
            if 'pathParameterHandling' in self._values['attributes']:
                return self._values['attributes']['pathParameterHandling']
        if 'general' in self._values:
            if self._values['general'] is None:
                return None
            if 'pathParameterHandling' in self._values['general']:
                return self._values['general']['pathParameterHandling']

    @property
    def trigger_asm_irule_event(self):
        if 'attributes' in self._values:
            if self._values['attributes'] is None:
                return None
            if 'triggerAsmIruleEvent' in self._values['attributes']:
                return self._values['attributes']['triggerAsmIruleEvent']
        if 'general' in self._values:
            if self._values['general'] is None:
                return None
            if 'triggerAsmIruleEvent' in self._values['general']:
                return self._values['general']['triggerAsmIruleEvent']

    @property
    def inspect_http_uploads(self):
        if 'attributes' in self._values:
            if self._values['attributes'] is None:
                return None
            if 'inspectHttpUploads' in self._values['attributes']:
                return flatten_boolean(self._values['attributes']['inspectHttpUploads'])
        if 'antivirus' in self._values:
            if self._values['antivirus'] is None:
                return None
            if 'inspectHttpUploads' in self._values['antivirus']:
                return flatten_boolean(self._values['antivirus']['inspectHttpUploads'])

    @property
    def mask_credit_card_numbers_in_request(self):
        if 'attributes' in self._values:
            if self._values['attributes'] is None:
                return None
            if 'maskCreditCardNumbersInRequest' in self._values['attributes']:
                return flatten_boolean(self._values['attributes']['maskCreditCardNumbersInRequest'])
        if 'general' in self._values:
            if self._values['general'] is None:
                return None
            if 'maskCreditCardNumbersInRequest' in self._values['general']:
                return flatten_boolean(self._values['general']['maskCreditCardNumbersInRequest'])

    @property
    def maximum_http_header_length(self):
        if 'attributes' in self._values:
            if self._values['attributes'] is None:
                return None
            if 'maximumHttpHeaderLength' in self._values['attributes']:
                if self._values['attributes']['maximumHttpHeaderLength'] == 'any':
                    return 'any'
                return int(self._values['attributes']['maximumHttpHeaderLength'])

        if 'header_settings' in self._values:
            if self._values['header_settings'] is None:
                return None
            if 'maximumHttpHeaderLength' in self._values['header_settings']:
                if self._values['header_settings']['maximumHttpHeaderLength'] == 'any':
                    return 'any'
                return int(self._values['header_settings']['maximumHttpHeaderLength'])

    @property
    def use_dynamic_session_id_in_url(self):
        if 'attributes' in self._values:
            if self._values['attributes'] is None:
                return None
            if 'useDynamicSessionIdInUrl' in self._values['attributes']:
                return flatten_boolean(self._values['attributes']['useDynamicSessionIdInUrl'])
        if 'general' in self._values:
            if self._values['general'] is None:
                return None
            if 'useDynamicSessionIdInUrl' in self._values['general']:
                return flatten_boolean(self._values['general']['useDynamicSessionIdInUrl'])

    @property
    def maximum_cookie_header_length(self):
        if 'attributes' in self._values:
            if self._values['attributes'] is None:
                return None
            if 'maximumCookieHeaderLength' in self._values['attributes']:
                if self._values['attributes']['maximumCookieHeaderLength'] == 'any':
                    return 'any'
                return int(self._values['attributes']['maximumCookieHeaderLength'])
        if 'cookie_settings' in self._values:
            if self._values['cookie_settings'] is None:
                return None
            if 'maximumCookieHeaderLength' in self._values['cookie_settings']:
                if self._values['cookie_settings']['maximumCookieHeaderLength'] == 'any':
                    return 'any'
                return int(self._values['cookie_settings']['maximumCookieHeaderLength'])

    @property
    def trust_xff(self):
        if 'trust_xff' in self._values:
            if self._values['trust_xff'] is None:
                return None
            return flatten_boolean(self._values['trust_xff'])
        if 'general' in self._values:
            if self._values['general'] is None:
                return None
            if 'trustXff' in self._values['general']:
                return flatten_boolean(self._values['general']['trustXff'])

    @property
    def custom_xff_headers(self):
        if 'custom_xff_headers' in self._values:
            if self._values['custom_xff_headers'] is None:
                return None
            return self._values['custom_xff_headers']
        if 'general' in self._values:
            if self._values['general'] is None:
                return None
            if 'customXffHeaders' in self._values['general']:
                return self._values['general']['customXffHeaders']

    @property
    def allowed_response_codes(self):
        if 'allowed_response_codes' in self._values:
            if self._values['allowed_response_codes'] is None:
                return None
            return self._values['allowed_response_codes']
        if 'general' in self._values:
            if self._values['general'] is None:
                return None
            if 'allowedResponseCodes' in self._values['general']:
                return self._values['general']['allowedResponseCodes']

    @property
    def learning_mode(self):
        if 'policy_builder' in self._values:
            if self._values['policy_builder'] is None:
                return None
            if 'learningMode' in self._values['policy_builder']:
                return self._values['policy_builder']['learningMode']

    @property
    def disallowed_locations(self):
        if 'geolocation_enforcement' in self._values:
            if self._values['geolocation_enforcement'] is None:
                return None
            return self._values['geolocation_enforcement']['disallowedLocations']

    @property
    def disallowed_geolocations(self):
        if 'disallowed_geolocations' in self._values:
            if self._values['disallowed_geolocations'] is None:
                return None
            return self._values['disallowed_geolocations']

    @property
    def csrf_protection_enabled(self):
        if 'csrf_protection' in self._values:
            return flatten_boolean(self._values['csrf_protection']['enabled'])

    @property
    def csrf_protection_ssl_only(self):
        if 'csrf_protection' in self._values:
            if 'sslOnly' in self._values['csrf_protection']:
                return flatten_boolean(self._values['csrf_protection']['sslOnly'])

    @property
    def csrf_protection_expiration_time_in_seconds(self):
        if 'csrf_protection' in self._values:
            if 'expirationTimeInSeconds' in self._values['csrf_protection']:
                if self._values['csrf_protection']['expirationTimeInSeconds'] is None:
                    return None
                if self._values['csrf_protection']['expirationTimeInSeconds'] == 'disabled':
                    return 'disabled'
                return int(self._values['csrf_protection']['expirationTimeInSeconds'])

    def format_csrf_collection(self, items):
        result = list()
        key_map = {
            'requiredParameters': 'csrf_url_required_parameters',
            'url': 'csrf_url',
            'method': 'csrf_url_method',
            'enforcementAction': 'csrf_url_enforcement_action',
            'id': 'csrf_url_id',
            'wildcardOrder': 'csrf_url_wildcard_order',
            'parametersList': 'csrf_url_parameters_list'
        }
        for item in items:
            self._remove_internal_keywords(item)
            item.pop('lastUpdateMicros')
            output = self._morph_keys(key_map, item)
            result.append(output)
        return result

    @property
    def csrf_urls(self):
        if 'csrfUrls' in self._values:
            if self._values['csrfUrls'] is None:
                return None
            return self._values['csrfUrls']
        if 'csrf-urls' in self._values:
            if self._values['csrf-urls'] is None:
                return None
            return self.format_csrf_collection(self._values['csrf-urls'])

    @property
    def protocol_independent(self):
        return flatten_boolean(self._values['protocol_independent'])


# TODO include: web-scraping,ip-intelligence,session-tracking,
# TODO login-enforcement,data-guard,redirection-protection,vulnerability-assessment, parentPolicyReference


class AsmPolicyFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(AsmPolicyFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(asm_policies=facts)
        return result

    def _exec_module(self):
        if 'asm' not in self.provisioned_modules:
            return []
        manager = self.get_manager()
        return manager._exec_module()

    def get_manager(self):
        if self.version_is_less_than_13():
            return AsmPolicyFactManagerV12(**self.kwargs)
        else:
            return AsmPolicyFactManagerV13(**self.kwargs)

    def version_is_less_than_13(self):
        version = tmos_version(self.client)
        if Version(version) < Version('13.0.0'):
            return True
        else:
            return False

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = AsmPolicyFactParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + 10
        return result


class AsmPolicyFactManagerV12(AsmPolicyFactManager):
    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/asm/policies".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )

        to_expand = 'policy-builder,geolocation-enforcement,csrf-protection'
        query = '?$top=10&$skip={0}&$expand={1}&$filter=partition+eq+{2}'.format(
            skip,
            to_expand,
            self.module.params['partition']
        )

        resp = self.client.api.get(uri + query)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        return response['items']


class AsmPolicyFactManagerV13(AsmPolicyFactManager):
    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/asm/policies".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        to_expand = 'general,signature-settings,header-settings,cookie-settings,antivirus,' \
                    'policy-builder,csrf-protection,csrf-urls'
        query = '?$top=10&$skip={0}&$expand={1}&$filter=partition+eq+{2}'.format(
            skip,
            to_expand,
            self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        return response['items']


class AsmServerTechnologyFactParameters(BaseParameters):
    api_map = {
        'serverTechnologyName': 'server_technology_name',
        'serverTechnologyReferences': 'server_technology_references',
    }

    returnables = [
        'id',
        'server_technology_name',
        'server_technology_references',
    ]


class AsmServerTechnologyFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(AsmServerTechnologyFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(asm_server_technologies=facts)
        return result

    def _exec_module(self):
        results = []
        if 'asm' not in self.provisioned_modules:
            return results
        if self.version_is_less_than_13():
            return results
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['server_technology_name'])
        return results

    def version_is_less_than_13(self):
        version = tmos_version(self.client)
        if Version(version) < Version('13.0.0'):
            return True
        else:
            return False

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = AsmServerTechnologyFactParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/asm/server-technologies".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class AsmSignatureSetsFactParameters(BaseParameters):
    api_map = {
        'isUserDefined': 'is_user_defined',
        'assignToPolicyByDefault': 'assign_to_policy_by_default',
        'defaultAlarm': 'default_alarm',
        'defaultBlock': 'default_block',
        'defaultLearn': 'default_learn',
    }

    returnables = [
        'name',
        'id',
        'type',
        'category',
        'is_user_defined',
        'assign_to_policy_by_default',
        'default_alarm',
        'default_block',
        'default_learn',
    ]

    @property
    def is_user_defined(self):
        return flatten_boolean(self._values['is_user_defined'])

    @property
    def assign_to_policy_by_default(self):
        return flatten_boolean(self._values['assign_to_policy_by_default'])

    @property
    def default_alarm(self):
        return flatten_boolean(self._values['default_alarm'])

    @property
    def default_block(self):
        return flatten_boolean(self._values['default_block'])

    @property
    def default_learn(self):
        return flatten_boolean(self._values['default_learn'])


# TODO: add the following: filter, systems, signatureReferences


class AsmSignatureSetsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(AsmSignatureSetsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(asm_signature_sets=facts)
        return result

    def _exec_module(self):
        results = []
        if 'asm' not in self.provisioned_modules:
            return results
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['name'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = AsmSignatureSetsFactParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/asm/signature-sets".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = '?$top={0}&$skip={1}'.format(self.module.params['data_increment'], skip)
        resp = self.client.api.get(uri + query)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return None

        return response['items']


class ClientSslProfilesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'alertTimeout': 'alert_timeout',
        'allowNonSsl': 'allow_non_ssl',
        'authenticateDepth': 'authenticate_depth',
        'authenticate': 'authenticate_frequency',
        'caFile': 'ca_file',
        'cacheSize': 'cache_size',
        'cacheTimeout': 'cache_timeout',
        'cert': 'certificate_file',
        'key': 'key_file',
        'chain': 'chain_file',
        'crlFile': 'crl_file',
        'defaultsFrom': 'parent',
        'modSslMethods': 'modssl_methods',
        'peerCertMode': 'peer_certification_mode',
        'sniRequire': 'sni_require',
        'strictResume': 'strict_resume',
        'mode': 'profile_mode_enabled',
        'renegotiateMaxRecordDelay': 'renegotiation_maximum_record_delay',
        'renegotiatePeriod': 'renegotiation_period',
        'serverName': 'server_name',
        'sessionTicket': 'session_ticket',
        'sniDefault': 'sni_default',
        'uncleanShutdown': 'unclean_shutdown',
        'retainCertificate': 'retain_certificate',
        'secureRenegotiation': 'secure_renegotiation_mode',
        'handshakeTimeout': 'handshake_timeout',
        'certExtensionIncludes': 'forward_proxy_certificate_extension_include',
        'certLifespan': 'forward_proxy_certificate_lifespan',
        'certLookupByIpaddrPort': 'forward_proxy_lookup_by_ipaddr_port',
        'sslForwardProxy': 'forward_proxy_enabled',
        'proxyCaPassphrase': 'forward_proxy_ca_passphrase',
        'proxyCaCert': 'forward_proxy_ca_certificate_file',
        'proxyCaKey': 'forward_proxy_ca_key_file'
    }

    returnables = [
        'full_path',
        'name',
        'alert_timeout',
        'allow_non_ssl',
        'authenticate_depth',
        'authenticate_frequency',
        'ca_file',
        'cache_size',
        'cache_timeout',
        'certificate_file',
        'key_file',
        'chain_file',
        'ciphers',
        'crl_file',
        'parent',
        'description',
        'modssl_methods',
        'peer_certification_mode',
        'sni_require',
        'sni_default',
        'strict_resume',
        'profile_mode_enabled',
        'renegotiation_maximum_record_delay',
        'renegotiation_period',
        'renegotiation',
        'server_name',
        'session_ticket',
        'unclean_shutdown',
        'retain_certificate',
        'secure_renegotiation_mode',
        'handshake_timeout',
        'forward_proxy_certificate_extension_include',
        'forward_proxy_certificate_lifespan',
        'forward_proxy_lookup_by_ipaddr_port',
        'forward_proxy_enabled',
        'forward_proxy_ca_passphrase',
        'forward_proxy_ca_certificate_file',
        'forward_proxy_ca_key_file'
    ]

    @property
    def alert_timeout(self):
        if self._values['alert_timeout'] is None:
            return None
        if self._values['alert_timeout'] == 'indefinite':
            return 0
        return int(self._values['alert_timeout'])

    @property
    def renegotiation_maximum_record_delay(self):
        if self._values['renegotiation_maximum_record_delay'] is None:
            return None
        if self._values['renegotiation_maximum_record_delay'] == 'indefinite':
            return 0
        return int(self._values['renegotiation_maximum_record_delay'])

    @property
    def renegotiation_period(self):
        if self._values['renegotiation_period'] is None:
            return None
        if self._values['renegotiation_period'] == 'indefinite':
            return 0
        return int(self._values['renegotiation_period'])

    @property
    def handshake_timeout(self):
        if self._values['handshake_timeout'] is None:
            return None
        if self._values['handshake_timeout'] == 'indefinite':
            return 0
        return int(self._values['handshake_timeout'])

    @property
    def allow_non_ssl(self):
        if self._values['allow_non_ssl'] is None:
            return None
        if self._values['allow_non_ssl'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def forward_proxy_enabled(self):
        if self._values['forward_proxy_enabled'] is None:
            return None
        if self._values['forward_proxy_enabled'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def renegotiation(self):
        if self._values['renegotiation'] is None:
            return None
        if self._values['renegotiation'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def forward_proxy_lookup_by_ipaddr_port(self):
        if self._values['forward_proxy_lookup_by_ipaddr_port'] is None:
            return None
        if self._values['forward_proxy_lookup_by_ipaddr_port'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def unclean_shutdown(self):
        if self._values['unclean_shutdown'] is None:
            return None
        if self._values['unclean_shutdown'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def session_ticket(self):
        if self._values['session_ticket'] is None:
            return None
        if self._values['session_ticket'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def retain_certificate(self):
        if self._values['retain_certificate'] is None:
            return None
        if self._values['retain_certificate'] == 'true':
            return 'yes'
        return 'no'

    @property
    def server_name(self):
        if self._values['server_name'] in [None, 'none']:
            return None
        return self._values['server_name']

    @property
    def forward_proxy_ca_certificate_file(self):
        if self._values['forward_proxy_ca_certificate_file'] in [None, 'none']:
            return None
        return self._values['forward_proxy_ca_certificate_file']

    @property
    def forward_proxy_ca_key_file(self):
        if self._values['forward_proxy_ca_key_file'] in [None, 'none']:
            return None
        return self._values['forward_proxy_ca_key_file']

    @property
    def authenticate_frequency(self):
        if self._values['authenticate_frequency'] is None:
            return None
        return self._values['authenticate_frequency']

    @property
    def ca_file(self):
        if self._values['ca_file'] in [None, 'none']:
            return None
        return self._values['ca_file']

    @property
    def certificate_file(self):
        if self._values['certificate_file'] in [None, 'none']:
            return None
        return self._values['certificate_file']

    @property
    def key_file(self):
        if self._values['key_file'] in [None, 'none']:
            return None
        return self._values['key_file']

    @property
    def chain_file(self):
        if self._values['chain_file'] in [None, 'none']:
            return None
        return self._values['chain_file']

    @property
    def crl_file(self):
        if self._values['crl_file'] in [None, 'none']:
            return None
        return self._values['crl_file']

    @property
    def ciphers(self):
        if self._values['ciphers'] is None:
            return None
        if self._values['ciphers'] == 'none':
            return 'none'
        return self._values['ciphers'].split(' ')

    @property
    def modssl_methods(self):
        if self._values['modssl_methods'] is None:
            return None
        if self._values['modssl_methods'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def strict_resume(self):
        if self._values['strict_resume'] is None:
            return None
        if self._values['strict_resume'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def profile_mode_enabled(self):
        if self._values['profile_mode_enabled'] is None:
            return None
        if self._values['profile_mode_enabled'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def sni_require(self):
        if self._values['sni_require'] is None:
            return None
        if self._values['sni_require'] == 'false':
            return 'no'
        return 'yes'

    @property
    def sni_default(self):
        if self._values['sni_default'] is None:
            return None
        if self._values['sni_default'] == 'false':
            return 'no'
        return 'yes'


class ClientSslProfilesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ClientSslProfilesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(client_ssl_profiles=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = ClientSslProfilesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/client-ssl".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class CFEParameters(BaseParameters):
    api_map = {
    }

    returnables = [

    ]


class CFEFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        self.installed_packages = packages_installed(self.client)
        super(CFEFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(cfe_config=facts)
        return result

    def _exec_module(self):
        if 'cfe' not in self.installed_packages:
            return []
        facts = self.read_facts()
        return facts

    def read_facts(self):
        collection = self.read_collection_from_device()
        return collection

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/shared/cloud-failover/declare".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = {}
        result['declaration'] = response['declaration']
        return result


class DeviceGroupsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'autoSync': 'autosync_enabled',
        'asmSync': 'asm_sync_enabled',
        'devicesReference': 'devices',
        'fullLoadOnSync': 'full_load_on_sync',
        'incrementalConfigSyncSizeMax': 'incremental_config_sync_size_maximum',
        'networkFailover': 'network_failover_enabled'
    }

    returnables = [
        'full_path',
        'name',
        'autosync_enabled',
        'description',
        'devices',
        'full_load_on_sync',
        'incremental_config_sync_size_maximum',
        'network_failover_enabled',
        'type',
        'asm_sync_enabled'
    ]

    @property
    def network_failover_enabled(self):
        if self._values['network_failover_enabled'] is None:
            return None
        if self._values['network_failover_enabled'] == 'enabled':
            return 'yes'
        return 'no'

    @property
    def asm_sync_enabled(self):
        if self._values['asm_sync_enabled'] is None:
            return None
        if self._values['asm_sync_enabled'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def autosync_enabled(self):
        if self._values['autosync_enabled'] is None:
            return None
        if self._values['autosync_enabled'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def full_load_on_sync(self):
        if self._values['full_load_on_sync'] is None:
            return None
        if self._values['full_load_on_sync'] == 'true':
            return 'yes'
        return 'no'

    @property
    def devices(self):
        if self._values['devices'] is None or 'items' not in self._values['devices']:
            return None
        result = [x['fullPath'] for x in self._values['devices']['items']]
        result.sort()
        return result


class DeviceGroupsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(DeviceGroupsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(device_groups=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = DeviceGroupsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/cm/device-group/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class DevicesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'activeModules': 'active_modules',
        'baseMac': 'base_mac_address',
        'chassisId': 'chassis_id',
        'chassisType': 'chassis_type',
        'configsyncIp': 'configsync_address',
        'failoverState': 'failover_state',
        'managementIp': 'management_address',
        'marketingName': 'marketing_name',
        'multicastIp': 'multicast_address',
        'optionalModules': 'optional_modules',
        'platformId': 'platform_id',
        'mirrorIp': 'primary_mirror_address',
        'mirrorSecondaryIp': 'secondary_mirror_address',
        'version': 'software_version',
        'timeLimitedModules': 'timelimited_modules',
        'timeZone': 'timezone',
        'unicastAddress': 'unicast_addresses',
        'selfDevice': 'self'
    }

    returnables = [
        'full_path',
        'name',
        'active_modules',
        'base_mac_address',
        'build',
        'chassis_id',
        'chassis_type',
        'comment',
        'configsync_address',
        'contact',
        'description',
        'edition',
        'failover_state',
        'hostname',
        'location',
        'management_address',
        'marketing_name',
        'multicast_address',
        'optional_modules',
        'platform_id',
        'primary_mirror_address',
        'product',
        'secondary_mirror_address',
        'self',
        'software_version',
        'timelimited_modules',
        'timezone',
        'unicast_addresses',
    ]

    @property
    def active_modules(self):
        if self._values['active_modules'] is None:
            return None
        result = []
        for x in self._values['active_modules']:
            parts = x.split('|')
            result += parts[2:]
        return list(set(result))

    @property
    def self(self):
        result = flatten_boolean(self._values['self'])
        return result

    @property
    def configsync_address(self):
        if self._values['configsync_address'] in [None, 'none']:
            return None
        return self._values['configsync_address']

    @property
    def primary_mirror_address(self):
        if self._values['primary_mirror_address'] in [None, 'any6']:
            return None
        return self._values['primary_mirror_address']

    @property
    def secondary_mirror_address(self):
        if self._values['secondary_mirror_address'] in [None, 'any6']:
            return None
        return self._values['secondary_mirror_address']

    @property
    def unicast_addresses(self):
        if self._values['unicast_addresses'] is None:
            return None
        result = []

        for addr in self._values['unicast_addresses']:
            tmp = {}
            for key in ['effectiveIp', 'effectivePort', 'ip', 'port']:
                if key in addr:
                    renamed_key = self.convert(key)
                    tmp[renamed_key] = addr.get(key, None)
            if tmp:
                result.append(tmp)
        if result:
            return result

    def convert(self, name):
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


class DevicesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(DevicesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(devices=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = DevicesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/cm/device".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class DOParameters(BaseParameters):
    api_map = {
    }

    returnables = [

    ]


class DOFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        self.installed_packages = packages_installed(self.client)
        super(DOFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(do_config=facts)
        return result

    def _exec_module(self):
        if 'do' not in self.installed_packages:
            return []
        facts = self.read_facts()
        return facts

    def read_facts(self):
        collection = self.read_collection_from_device()
        return collection

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/shared/declarative-onboarding/inspect".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = {}
        result['declaration'] = response[0]['declaration']
        return result


class ExternalMonitorsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultsFrom': 'parent',
        'adaptiveDivergenceType': 'adaptive_divergence_type',
        'adaptiveDivergenceValue': 'adaptive_divergence_value',
        'adaptiveLimit': 'adaptive_limit',
        'adaptiveSamplingTimespan': 'adaptive_sampling_timespan',
        'manualResume': 'manual_resume',
        'timeUntilUp': 'time_until_up',
        'upInterval': 'up_interval',
        'run': 'external_program',
        'apiRawValues': 'variables',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'args',
        'destination',
        'external_program',
        'interval',
        'manual_resume',
        'time_until_up',
        'timeout',
        'up_interval',
        'variables',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])

    @property
    def variables(self):
        if self._values['variables'] is None:
            return None
        result = {}
        for k, v in iteritems(self._values['variables']):
            k = k.replace('userDefined ', '').strip()
            result[k] = v
        return result


class ExternalMonitorsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ExternalMonitorsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(external_monitors=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = ExternalMonitorsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/external".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class FastHttpProfilesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'clientCloseTimeout': 'client_close_timeout',
        'connpoolIdleTimeoutOverride': 'oneconnect_idle_timeout_override',
        'connpoolMaxReuse': 'oneconnect_maximum_reuse',
        'connpoolMaxSize': 'oneconnect_maximum_pool_size',
        'connpoolMinSize': 'oneconnect_minimum_pool_size',
        'connpoolReplenish': 'oneconnect_replenish',
        'connpoolStep': 'oneconnect_ramp_up_increment',
        'defaultsFrom': 'parent',
        'forceHttp_10Response': 'force_http_1_0_response',
        'headerInsert': 'request_header_insert',
        'http_11CloseWorkarounds': 'http_1_1_close_workarounds',
        'idleTimeout': 'idle_timeout',
        'insertXforwardedFor': 'insert_xforwarded_for',
        'maxHeaderSize': 'maximum_header_size',
        'maxRequests': 'maximum_requests',
        'mssOverride': 'maximum_segment_size_override',
        'receiveWindowSize': 'receive_window_size',
        'resetOnTimeout': 'reset_on_timeout',
        'serverCloseTimeout': 'server_close_timeout',
        'serverSack': 'server_sack',
        'serverTimestamp': 'server_timestamp',
        'uncleanShutdown': 'unclean_shutdown'
    }

    returnables = [
        'full_path',
        'name',
        'client_close_timeout',
        'oneconnect_idle_timeout_override',
        'oneconnect_maximum_reuse',
        'oneconnect_maximum_pool_size',
        'oneconnect_minimum_pool_size',
        'oneconnect_replenish',
        'oneconnect_ramp_up_increment',
        'parent',
        'description',
        'force_http_1_0_response',
        'request_header_insert',
        'http_1_1_close_workarounds',
        'idle_timeout',
        'insert_xforwarded_for',
        'maximum_header_size',
        'maximum_requests',
        'maximum_segment_size_override',
        'receive_window_size',
        'reset_on_timeout',
        'server_close_timeout',
        'server_sack',
        'server_timestamp',
        'unclean_shutdown'
    ]

    @property
    def request_header_insert(self):
        if self._values['request_header_insert'] in [None, 'none']:
            return None
        return self._values['request_header_insert']

    @property
    def server_timestamp(self):
        return flatten_boolean(self._values['server_timestamp'])

    @property
    def server_sack(self):
        return flatten_boolean(self._values['server_sack'])

    @property
    def reset_on_timeout(self):
        return flatten_boolean(self._values['reset_on_timeout'])

    @property
    def insert_xforwarded_for(self):
        return flatten_boolean(self._values['insert_xforwarded_for'])

    @property
    def http_1_1_close_workarounds(self):
        return flatten_boolean(self._values['http_1_1_close_workarounds'])

    @property
    def force_http_1_0_response(self):
        return flatten_boolean(self._values['force_http_1_0_response'])

    @property
    def oneconnect_replenish(self):
        return flatten_boolean(self._values['oneconnect_replenish'])

    @property
    def idle_timeout(self):
        if self._values['idle_timeout'] is None:
            return None
        elif self._values['idle_timeout'] == 'immediate':
            return 0
        elif self._values['idle_timeout'] == 'indefinite':
            return 4294967295
        return int(self._values['idle_timeout'])


class FastHttpProfilesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(FastHttpProfilesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(fasthttp_profiles=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = FastHttpProfilesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/fasthttp".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class FastL4ProfilesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'clientTimeout': 'client_timeout',
        'defaultsFrom': 'parent',
        'explicitFlowMigration': 'explicit_flow_migration',
        'hardwareSynCookie': 'hardware_syn_cookie',
        'idleTimeout': 'idle_timeout',
        'ipDfMode': 'dont_fragment_flag',
        'ipTosToClient': 'ip_tos_to_client',
        'ipTosToServer': 'ip_tos_to_server',
        'ipTtlMode': 'ttl_mode',
        'ipTtlV4': 'ttl_v4',
        'ipTtlV6': 'ttl_v6',
        'keepAliveInterval': 'keep_alive_interval',
        'lateBinding': 'late_binding',
        'linkQosToClient': 'link_qos_to_client',
        'linkQosToServer': 'link_qos_to_server',
        'looseClose': 'loose_close',
        'looseInitialization': 'loose_init',
        'mssOverride': 'mss_override',
        'priorityToClient': 'priority_to_client',
        'priorityToServer': 'priority_to_server',
        'pvaAcceleration': 'pva_acceleration',
        'pvaDynamicClientPackets': 'pva_dynamic_client_packets',
        'pvaDynamicServerPackets': 'pva_dynamic_server_packets',
        'pvaFlowAging': 'pva_flow_aging',
        'pvaFlowEvict': 'pva_flow_evict',
        'pvaOffloadDynamic': 'pva_offload_dynamic',
        'pvaOffloadState': 'pva_offload_state',
        'reassembleFragments': 'reassemble_fragments',
        'receiveWindowSize': 'receive_window',
        'resetOnTimeout': 'reset_on_timeout',
        'rttFromClient': 'rtt_from_client',
        'rttFromServer': 'rtt_from_server',
        'serverSack': 'server_sack',
        'serverTimestamp': 'server_timestamp',
        'softwareSynCookie': 'software_syn_cookie',
        'synCookieEnable': 'syn_cookie_enabled',
        'synCookieMss': 'syn_cookie_mss',
        'synCookieWhitelist': 'syn_cookie_whitelist',
        'tcpCloseTimeout': 'tcp_close_timeout',
        'tcpGenerateIsn': 'generate_init_seq_number',
        'tcpHandshakeTimeout': 'tcp_handshake_timeout',
        'tcpStripSack': 'strip_sack',
        'tcpTimeWaitTimeout': 'tcp_time_wait_timeout',
        'tcpTimestampMode': 'tcp_timestamp_mode',
        'tcpWscaleMode': 'tcp_window_scale_mode',
        'timeoutRecovery': 'timeout_recovery',
    }

    returnables = [
        'full_path',
        'name',
        'client_timeout',
        'parent',
        'description',
        'explicit_flow_migration',
        'hardware_syn_cookie',
        'idle_timeout',
        'dont_fragment_flag',
        'ip_tos_to_client',
        'ip_tos_to_server',
        'ttl_mode',
        'ttl_v4',
        'ttl_v6',
        'keep_alive_interval',
        'late_binding',
        'link_qos_to_client',
        'link_qos_to_server',
        'loose_close',
        'loose_init',
        'mss_override',  # Maximum Segment Size Override
        'priority_to_client',
        'priority_to_server',
        'pva_acceleration',
        'pva_dynamic_client_packets',
        'pva_dynamic_server_packets',
        'pva_flow_aging',
        'pva_flow_evict',
        'pva_offload_dynamic',
        'pva_offload_state',
        'reassemble_fragments',
        'receive_window',
        'reset_on_timeout',
        'rtt_from_client',
        'rtt_from_server',
        'server_sack',
        'server_timestamp',
        'software_syn_cookie',
        'syn_cookie_enabled',
        'syn_cookie_mss',
        'syn_cookie_whitelist',
        'tcp_close_timeout',
        'generate_init_seq_number',
        'tcp_handshake_timeout',
        'strip_sack',
        'tcp_time_wait_timeout',
        'tcp_timestamp_mode',
        'tcp_window_scale_mode',
        'timeout_recovery',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def strip_sack(self):
        return flatten_boolean(self._values['strip_sack'])

    @property
    def generate_init_seq_number(self):
        return flatten_boolean(self._values['generate_init_seq_number'])

    @property
    def syn_cookie_whitelist(self):
        return flatten_boolean(self._values['syn_cookie_whitelist'])

    @property
    def syn_cookie_enabled(self):
        return flatten_boolean(self._values['syn_cookie_enabled'])

    @property
    def software_syn_cookie(self):
        return flatten_boolean(self._values['software_syn_cookie'])

    @property
    def server_timestamp(self):
        return flatten_boolean(self._values['server_timestamp'])

    @property
    def server_sack(self):
        return flatten_boolean(self._values['server_sack'])

    @property
    def rtt_from_server(self):
        return flatten_boolean(self._values['rtt_from_server'])

    @property
    def rtt_from_client(self):
        return flatten_boolean(self._values['rtt_from_client'])

    @property
    def reset_on_timeout(self):
        return flatten_boolean(self._values['reset_on_timeout'])

    @property
    def explicit_flow_migration(self):
        return flatten_boolean(self._values['explicit_flow_migration'])

    @property
    def reassemble_fragments(self):
        return flatten_boolean(self._values['reassemble_fragments'])

    @property
    def pva_flow_aging(self):
        return flatten_boolean(self._values['pva_flow_aging'])

    @property
    def pva_flow_evict(self):
        return flatten_boolean(self._values['pva_flow_evict'])

    @property
    def pva_offload_dynamic(self):
        return flatten_boolean(self._values['pva_offload_dynamic'])

    @property
    def hardware_syn_cookie(self):
        return flatten_boolean(self._values['hardware_syn_cookie'])

    @property
    def loose_close(self):
        return flatten_boolean(self._values['loose_close'])

    @property
    def loose_init(self):
        return flatten_boolean(self._values['loose_init'])

    @property
    def late_binding(self):
        return flatten_boolean(self._values['late_binding'])

    @property
    def tcp_handshake_timeout(self):
        if self._values['tcp_handshake_timeout'] is None:
            return None
        elif self._values['tcp_handshake_timeout'] == 'immediate':
            return 0
        elif self._values['tcp_handshake_timeout'] == 'indefinite':
            return 4294967295
        return int(self._values['tcp_handshake_timeout'])

    @property
    def idle_timeout(self):
        if self._values['idle_timeout'] is None:
            return None
        elif self._values['idle_timeout'] == 'immediate':
            return 0
        elif self._values['idle_timeout'] == 'indefinite':
            return 4294967295
        return int(self._values['idle_timeout'])

    @property
    def tcp_close_timeout(self):
        if self._values['tcp_close_timeout'] is None:
            return None
        elif self._values['tcp_close_timeout'] == 'immediate':
            return 0
        elif self._values['tcp_close_timeout'] == 'indefinite':
            return 4294967295
        return int(self._values['tcp_close_timeout'])

    @property
    def keep_alive_interval(self):
        if self._values['keep_alive_interval'] is None:
            return None
        elif self._values['keep_alive_interval'] == 'disabled':
            return 0
        return int(self._values['keep_alive_interval'])

    @property
    def ip_tos_to_client(self):
        if self._values['ip_tos_to_client'] is None:
            return None
        try:
            return int(self._values['ip_tos_to_client'])
        except ValueError:
            return self._values['ip_tos_to_client']

    @property
    def ip_tos_to_server(self):
        if self._values['ip_tos_to_server'] is None:
            return None
        try:
            return int(self._values['ip_tos_to_server'])
        except ValueError:
            return self._values['ip_tos_to_server']

    @property
    def link_qos_to_client(self):
        if self._values['link_qos_to_client'] is None:
            return None
        try:
            return int(self._values['link_qos_to_client'])
        except ValueError:
            return self._values['link_qos_to_client']

    @property
    def link_qos_to_server(self):
        if self._values['link_qos_to_server'] is None:
            return None
        try:
            return int(self._values['link_qos_to_server'])
        except ValueError:
            return self._values['link_qos_to_server']

    @property
    def priority_to_client(self):
        if self._values['priority_to_client'] is None:
            return None
        try:
            return int(self._values['priority_to_client'])
        except ValueError:
            return self._values['priority_to_client']

    @property
    def priority_to_server(self):
        if self._values['priority_to_server'] is None:
            return None
        try:
            return int(self._values['priority_to_server'])
        except ValueError:
            return self._values['priority_to_server']


class FastL4ProfilesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(FastL4ProfilesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(fastl4_profiles=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = FastL4ProfilesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/fastl4".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GatewayIcmpMonitorsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultsFrom': 'parent',
        'adaptiveDivergenceType': 'adaptive_divergence_type',
        'adaptiveDivergenceValue': 'adaptive_divergence_value',
        'adaptiveLimit': 'adaptive_limit',
        'adaptiveSamplingTimespan': 'adaptive_sampling_timespan',
        'manualResume': 'manual_resume',
        'timeUntilUp': 'time_until_up',
        'upInterval': 'up_interval',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'adaptive',
        'adaptive_divergence_type',
        'adaptive_divergence_value',
        'adaptive_limit',
        'adaptive_sampling_timespan',
        'destination',
        'interval',
        'manual_resume',
        'time_until_up',
        'timeout',
        'transparent',
        'up_interval',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def transparent(self):
        return flatten_boolean(self._values['transparent'])

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])

    @property
    def adaptive(self):
        return flatten_boolean(self._values['adaptive'])


class GatewayIcmpMonitorsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GatewayIcmpMonitorsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gateway_icmp_monitors=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GatewayIcmpMonitorsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/gateway-icmp".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmXPoolsParameters(BaseParameters):
    api_map = {
        'alternateMode': 'alternate_mode',
        'dynamicRatio': 'dynamic_ratio',
        'fallbackMode': 'fallback_mode',
        'fullPath': 'full_path',
        'loadBalancingMode': 'load_balancing_mode',
        'manualResume': 'manual_resume',
        'maxAnswersReturned': 'max_answers_returned',
        'qosHitRatio': 'qos_hit_ratio',
        'qosHops': 'qos_hops',
        'qosKilobytesSecond': 'qos_kilobytes_second',
        'qosLcs': 'qos_lcs',
        'qosPacketRate': 'qos_packet_rate',
        'qosRtt': 'qos_rtt',
        'qosTopology': 'qos_topology',
        'qosVsCapacity': 'qos_vs_capacity',
        'qosVsScore': 'qos_vs_score',
        'verifyMemberAvailability': 'verify_member_availability',
        'membersReference': 'members'
    }

    returnables = [
        'alternate_mode',
        'dynamic_ratio',
        'enabled',
        'disabled',
        'fallback_mode',
        'full_path',
        'load_balancing_mode',
        'manual_resume',
        'max_answers_returned',
        'members',
        'name',
        'partition',
        'qos_hit_ratio',
        'qos_hops',
        'qos_kilobytes_second',
        'qos_lcs',
        'qos_packet_rate',
        'qos_rtt',
        'qos_topology',
        'qos_vs_capacity',
        'qos_vs_score',
        'ttl',
        'verify_member_availability',
    ]

    @property
    def verify_member_availability(self):
        return flatten_boolean(self._values['verify_member_availability'])

    @property
    def dynamic_ratio(self):
        return flatten_boolean(self._values['dynamic_ratio'])

    @property
    def max_answers_returned(self):
        if self._values['max_answers_returned'] is None:
            return None
        return int(self._values['max_answers_returned'])

    @property
    def members(self):
        result = []
        if self._values['members'] is None or 'items' not in self._values['members']:
            return result
        for item in self._values['members']['items']:
            self._remove_internal_keywords(item)
            if 'disabled' in item:
                item['disabled'] = flatten_boolean(item['disabled'])
                item['enabled'] = flatten_boolean(not item['disabled'])
            if 'enabled' in item:
                item['enabled'] = flatten_boolean(item['enabled'])
                item['disabled'] = flatten_boolean(not item['enabled'])
            if 'fullPath' in item:
                item['full_path'] = item.pop('fullPath')
            if 'memberOrder' in item:
                item['member_order'] = int(item.pop('memberOrder'))
            # Cast some attributes to integer
            for x in ['order', 'preference', 'ratio', 'service']:
                if x in item:
                    item[x] = int(item[x])
            result.append(item)
        return result

    @property
    def qos_hit_ratio(self):
        if self._values['qos_hit_ratio'] is None:
            return None
        return int(self._values['qos_hit_ratio'])

    @property
    def qos_hops(self):
        if self._values['qos_hops'] is None:
            return None
        return int(self._values['qos_hops'])

    @property
    def qos_kilobytes_second(self):
        if self._values['qos_kilobytes_second'] is None:
            return None
        return int(self._values['qos_kilobytes_second'])

    @property
    def qos_lcs(self):
        if self._values['qos_lcs'] is None:
            return None
        return int(self._values['qos_lcs'])

    @property
    def qos_packet_rate(self):
        if self._values['qos_packet_rate'] is None:
            return None
        return int(self._values['qos_packet_rate'])

    @property
    def qos_rtt(self):
        if self._values['qos_rtt'] is None:
            return None
        return int(self._values['qos_rtt'])

    @property
    def qos_topology(self):
        if self._values['qos_topology'] is None:
            return None
        return int(self._values['qos_topology'])

    @property
    def qos_vs_capacity(self):
        if self._values['qos_vs_capacity'] is None:
            return None
        return int(self._values['qos_vs_capacity'])

    @property
    def qos_vs_score(self):
        if self._values['qos_vs_score'] is None:
            return None
        return int(self._values['qos_vs_score'])

    @property
    def availability_state(self):
        if self._values['stats'] is None:
            return None
        try:
            result = self._values['stats']['status']['availabilityState']
            return result['description']
        except AttributeError:
            return None

    @property
    def enabled_state(self):
        if self._values['stats'] is None:
            return None
        try:
            result = self._values['stats']['status']['enabledState']
            return result['description']
        except AttributeError:
            return None

    @property
    def availability_status(self):
        # This fact is a combination of the availability_state and enabled_state
        #
        # The purpose of the fact is to give a higher-level view of the availability
        # of the pool, that can be used in playbooks. If you need further detail,
        # consider using the following facts together.
        #
        # - availability_state
        # - enabled_state
        #
        if self.enabled_state == 'enabled':
            if self.availability_state == 'offline':
                return 'red'
            elif self.availability_state == 'available':
                return 'green'
            elif self.availability_state == 'unknown':
                return 'blue'
            else:
                return 'none'
        else:
            # disabled
            return 'black'

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])


class GtmAPoolsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmAPoolsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_a_pools=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXPoolsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/pool/a".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmAaaaPoolsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmAaaaPoolsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_aaaa_pools=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXPoolsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/pool/aaaa".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmCnamePoolsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmCnamePoolsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_cname_pools=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXPoolsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/pool/cname".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmMxPoolsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmMxPoolsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_mx_pools=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXPoolsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/pool/mx".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmNaptrPoolsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmNaptrPoolsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_naptr_pools=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXPoolsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/pool/naptr".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmSrvPoolsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmSrvPoolsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_srv_pools=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXPoolsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/pool/srv".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmServersParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'exposeRouteDomains': 'expose_route_domains',
        'iqAllowPath': 'iq_allow_path',
        'iqAllowServiceCheck': 'iq_allow_service_check',
        'iqAllowSnmp': 'iq_allow_snmp',
        'limitCpuUsage': 'limit_cpu_usage',
        'limitCpuUsageStatus': 'limit_cpu_usage_status',
        'limitMaxBps': 'limit_max_bps',
        'limitMaxBpsStatus': 'limit_max_bps_status',
        'limitMaxConnections': 'limit_max_connections',
        'limitMaxConnectionsStatus': 'limit_max_connections_status',
        'limitMaxPps': 'limit_max_pps',
        'limitMaxPpsStatus': 'limit_max_pps_status',
        'limitMemAvail': 'limit_mem_available',
        'limitMemAvailStatus': 'limit_mem_available_status',
        'linkDiscovery': 'link_discovery',
        'proberFallback': 'prober_fallback',
        'proberPreference': 'prober_preference',
        'virtualServerDiscovery': 'virtual_server_discovery',
        'devicesReference': 'devices',
        'virtualServersReference': 'virtual_servers',
        'monitor': 'monitors',
    }

    returnables = [
        'datacenter',
        'enabled',
        'disabled',
        'expose_route_domains',
        'iq_allow_path',
        'full_path',
        'iq_allow_service_check',
        'iq_allow_snmp',
        'limit_cpu_usage',
        'limit_cpu_usage_status',
        'limit_max_bps',
        'limit_max_bps_status',
        'limit_max_connections',
        'limit_max_connections_status',
        'limit_max_pps',
        'limit_max_pps_status',
        'limit_mem_available',
        'limit_mem_available_status',
        'link_discovery',
        'monitors',
        'monitor_type',
        'name',
        'product',
        'prober_fallback',
        'prober_preference',
        'virtual_server_discovery',
        'addresses',
        'devices',
        'virtual_servers',
    ]

    def _remove_internal_keywords(self, resource, stats=False):
        if stats:
            resource.pop('kind', None)
            resource.pop('generation', None)
            resource.pop('isSubcollection', None)
            resource.pop('fullPath', None)
        else:
            resource.pop('kind', None)
            resource.pop('generation', None)
            resource.pop('selfLink', None)
            resource.pop('isSubcollection', None)
            resource.pop('fullPath', None)

    def _read_virtual_stats_from_device(self, url):
        uri = "https://{0}:{1}{2}/stats".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            url
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)
        result = parseStats(response)
        try:
            return result['stats']
        except KeyError:
            return {}

    def _process_vs_stats(self, link):
        result = dict()
        item = self._read_virtual_stats_from_device(urlparse(link).path)
        if not item:
            return result
        result['status'] = item['status']['availabilityState']
        result['status_reason'] = item['status']['statusReason']
        result['state'] = item['status']['enabledState']
        result['bits_per_sec_in'] = item['metrics']['bitsPerSecIn']
        result['bits_per_sec_in'] = item['metrics']['bitsPerSecOut']
        result['pkts_per_sec_in'] = item['metrics']['pktsPerSecIn']
        result['pkts_per_sec_out'] = item['metrics']['pktsPerSecOut']
        result['connections'] = item['metrics']['connections']
        result['picks'] = item['picks']
        result['virtual_server_score'] = item['metrics']['vsScore']
        result['uptime'] = item['uptime']
        return result

    @property
    def monitors(self):
        if self._values['monitors'] is None:
            return []
        try:
            result = re.findall(r'/\w+/[^\s}]+', self._values['monitors'])
            return result
        except Exception:
            return [self._values['monitors']]

    @property
    def monitor_type(self):
        if self._values['monitors'] is None:
            return None
        pattern = r'min\s+\d+\s+of'
        matches = re.search(pattern, self._values['monitors'])
        if matches:
            return 'm_of_n'
        else:
            return 'and_list'

    @property
    def limit_mem_available_status(self):
        return flatten_boolean(self._values['limit_mem_available_status'])

    @property
    def limit_max_pps_status(self):
        return flatten_boolean(self._values['limit_max_pps_status'])

    @property
    def limit_max_connections_status(self):
        return flatten_boolean(self._values['limit_max_connections_status'])

    @property
    def limit_max_bps_status(self):
        return flatten_boolean(self._values['limit_max_bps_status'])

    @property
    def limit_cpu_usage_status(self):
        return flatten_boolean(self._values['limit_cpu_usage_status'])

    @property
    def iq_allow_service_check(self):
        return flatten_boolean(self._values['iq_allow_service_check'])

    @property
    def iq_allow_snmp(self):
        return flatten_boolean(self._values['iq_allow_snmp'])

    @property
    def expose_route_domains(self):
        return flatten_boolean(self._values['expose_route_domains'])

    @property
    def iq_allow_path(self):
        return flatten_boolean(self._values['iq_allow_path'])

    @property
    def product(self):
        if self._values['product'] is None:
            return None
        if self._values['product'] in ['single-bigip', 'redundant-bigip']:
            return 'bigip'
        return self._values['product']

    @property
    def devices(self):
        result = []
        if self._values['devices'] is None or 'items' not in self._values['devices']:
            return result
        for item in self._values['devices']['items']:
            self._remove_internal_keywords(item)
            if 'fullPath' in item:
                item['full_path'] = item.pop('fullPath')
            result.append(item)
        return result

    @property
    def virtual_servers(self):
        result = []
        if self._values['virtual_servers'] is None or 'items' not in self._values['virtual_servers']:
            return result
        for item in self._values['virtual_servers']['items']:
            self._remove_internal_keywords(item, stats=True)
            stats = self._process_vs_stats(item['selfLink'])
            self._remove_internal_keywords(item)
            item['stats'] = stats
            if 'disabled' in item:
                if item['disabled'] in BOOLEANS_TRUE:
                    item['disabled'] = flatten_boolean(item['disabled'])
                    item['enabled'] = flatten_boolean(not item['disabled'])
            if 'enabled' in item:
                if item['enabled'] in BOOLEANS_TRUE:
                    item['enabled'] = flatten_boolean(item['enabled'])
                    item['disabled'] = flatten_boolean(not item['enabled'])
            if 'fullPath' in item:
                item['full_path'] = item.pop('fullPath')
            if 'limitMaxBps' in item:
                item['limit_max_bps'] = int(item.pop('limitMaxBps'))
            if 'limitMaxBpsStatus' in item:
                item['limit_max_bps_status'] = item.pop('limitMaxBpsStatus')
            if 'limitMaxConnections' in item:
                item['limit_max_connections'] = int(item.pop('limitMaxConnections'))
            if 'limitMaxConnectionsStatus' in item:
                item['limit_max_connections_status'] = item.pop('limitMaxConnectionsStatus')
            if 'limitMaxPps' in item:
                item['limit_max_pps'] = int(item.pop('limitMaxPps'))
            if 'limitMaxPpsStatus' in item:
                item['limit_max_pps_status'] = item.pop('limitMaxPpsStatus')
            if 'translationAddress' in item:
                item['translation_address'] = item.pop('translationAddress')
            if 'translationPort' in item:
                item['translation_port'] = int(item.pop('translationPort'))
            result.append(item)
        return result

    @property
    def limit_cpu_usage(self):
        if self._values['limit_cpu_usage'] is None:
            return None
        return int(self._values['limit_cpu_usage'])

    @property
    def limit_max_bps(self):
        if self._values['limit_max_bps'] is None:
            return None
        return int(self._values['limit_max_bps'])

    @property
    def limit_max_connections(self):
        if self._values['limit_max_connections'] is None:
            return None
        return int(self._values['limit_max_connections'])

    @property
    def limit_max_pps(self):
        if self._values['limit_max_pps'] is None:
            return None
        return int(self._values['limit_max_pps'])

    @property
    def limit_mem_available(self):
        if self._values['limit_mem_available'] is None:
            return None
        return int(self._values['limit_mem_available'])


class GtmServersFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmServersFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_servers=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmServersParameters(client=self.client, params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/server".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmXWideIpsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'failureRcode': 'failure_rcode',
        'failureRcodeResponse': 'failure_rcode_response',
        'failureRcodeTtl': 'failure_rcode_ttl',
        'lastResortPool': 'last_resort_pool',
        'minimalResponse': 'minimal_response',
        'persistCidrIpv4': 'persist_cidr_ipv4',
        'persistCidrIpv6': 'persist_cidr_ipv6',
        'poolLbMode': 'pool_lb_mode',
        'ttlPersistence': 'ttl_persistence'
    }

    returnables = [
        'full_path',
        'description',
        'enabled',
        'disabled',
        'failure_rcode',
        'failure_rcode_response',
        'failure_rcode_ttl',
        'last_resort_pool',
        'minimal_response',
        'name',
        'persist_cidr_ipv4',
        'persist_cidr_ipv6',
        'pool_lb_mode',
        'ttl_persistence',
        'pools',
    ]

    @property
    def pools(self):
        result = []
        if self._values['pools'] is None:
            return []
        for pool in self._values['pools']:
            del pool['nameReference']
            for x in ['order', 'ratio']:
                if x in pool:
                    pool[x] = int(pool[x])
            result.append(pool)
        return result

    @property
    def failure_rcode_response(self):
        return flatten_boolean(self._values['failure_rcode_response'])

    @property
    def failure_rcode_ttl(self):
        if self._values['failure_rcode_ttl'] is None:
            return None
        return int(self._values['failure_rcode_ttl'])

    @property
    def persist_cidr_ipv4(self):
        if self._values['persist_cidr_ipv4'] is None:
            return None
        return int(self._values['persist_cidr_ipv4'])

    @property
    def persist_cidr_ipv6(self):
        if self._values['persist_cidr_ipv6'] is None:
            return None
        return int(self._values['persist_cidr_ipv6'])

    @property
    def ttl_persistence(self):
        if self._values['ttl_persistence'] is None:
            return None
        return int(self._values['ttl_persistence'])


class GtmAWideIpsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmAWideIpsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_a_wide_ips=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXWideIpsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/a".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmAaaaWideIpsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmAaaaWideIpsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_aaaa_wide_ips=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXWideIpsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/aaaa".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmCnameWideIpsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmCnameWideIpsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_cname_wide_ips=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXWideIpsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/cname".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmMxWideIpsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmMxWideIpsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_mx_wide_ips=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXWideIpsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/mx".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmNaptrWideIpsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmNaptrWideIpsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_naptr_wide_ips=facts)
        return result

    def _exec_module(self):
        results = []
        if 'gtm' not in self.provisioned_modules:
            return []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXWideIpsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/naptr".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmSrvWideIpsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmSrvWideIpsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_srv_wide_ips=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmXWideIpsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/srv".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class GtmTopologyRegionParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'regionMembers': 'region_members',
    }

    returnables = [
        'name',
        'full_path',
        'region_members',
    ]

    def _string_to_dict(self, member):
        result = dict()
        item = member['name'].split(' ', 2)
        if len(item) > 2:
            result['negate'] = 'yes'
            if item[1] == 'geoip-isp':
                result['geo_isp'] = item[2]
            else:
                result[item[1]] = item[2]
            return result
        else:
            if item[0] == 'geoip-isp':
                result['geo_isp'] = item[1]
            else:
                result[item[0]] = item[1]
            return result

    @property
    def region_members(self):
        result = []
        if self._values['region_members'] is None:
            return []
        for member in self._values['region_members']:
            result.append(self._string_to_dict(member))
        return result


class GtmTopologyRegionFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(GtmTopologyRegionFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(gtm_topology_regions=facts)
        return result

    def _exec_module(self):
        if 'gtm' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = GtmTopologyRegionParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/gtm/region".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class HttpMonitorsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultsFrom': 'parent',
        'adaptiveDivergenceType': 'adaptive_divergence_type',
        'adaptiveDivergenceValue': 'adaptive_divergence_value',
        'adaptiveLimit': 'adaptive_limit',
        'adaptiveSamplingTimespan': 'adaptive_sampling_timespan',
        'ipDscp': 'ip_dscp',
        'manualResume': 'manual_resume',
        'recv': 'receive_string',
        'recvDisable': 'receive_disable_string',
        'send': 'send_string',
        'timeUntilUp': 'time_until_up',
        'upInterval': 'up_interval',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'adaptive',
        'adaptive_divergence_type',
        'adaptive_divergence_value',
        'adaptive_limit',
        'adaptive_sampling_timespan',
        'destination',
        'interval',
        'ip_dscp',
        'manual_resume',
        'receive_string',
        'receive_disable_string',
        'reverse',
        'send_string',
        'time_until_up',
        'timeout',
        'transparent',
        'up_interval',
        'username',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def transparent(self):
        return flatten_boolean(self._values['transparent'])

    @property
    def reverse(self):
        return flatten_boolean(self._values['reverse'])

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])

    @property
    def adaptive(self):
        return flatten_boolean(self._values['adaptive'])


class HttpMonitorsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(HttpMonitorsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(http_monitors=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = HttpMonitorsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/http".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = response['items']
        return result


class HttpsMonitorsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultsFrom': 'parent',
        'adaptiveDivergenceType': 'adaptive_divergence_type',
        'adaptiveDivergenceValue': 'adaptive_divergence_value',
        'adaptiveLimit': 'adaptive_limit',
        'adaptiveSamplingTimespan': 'adaptive_sampling_timespan',
        'ipDscp': 'ip_dscp',
        'manualResume': 'manual_resume',
        'recv': 'receive_string',
        'recvDisable': 'receive_disable_string',
        'send': 'send_string',
        'sslProfile': 'ssl_profile',
        'timeUntilUp': 'time_until_up',
        'upInterval': 'up_interval',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'adaptive',
        'adaptive_divergence_type',
        'adaptive_divergence_value',
        'adaptive_limit',
        'adaptive_sampling_timespan',
        'destination',
        'interval',
        'ip_dscp',
        'manual_resume',
        'receive_string',
        'receive_disable_string',
        'reverse',
        'send_string',
        'ssl_profile',
        'time_until_up',
        'timeout',
        'transparent',
        'up_interval',
        'username',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def transparent(self):
        return flatten_boolean(self._values['transparent'])

    @property
    def reverse(self):
        return flatten_boolean(self._values['reverse'])

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])

    @property
    def adaptive(self):
        return flatten_boolean(self._values['adaptive'])


class HttpsMonitorsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(HttpsMonitorsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(https_monitors=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = HttpsMonitorsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/https".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = response['items']
        return result


class HttpProfilesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultsFrom': 'parent',
        'acceptXff': 'accept_xff',
        'explicitProxy': 'explicit_proxy',
        'insertXforwardedFor': 'insert_xforwarded_for',
        'lwsWidth': 'lws_max_columns',
        'oneconnectTransformations': 'onconnect_transformations',
        'proxyType': 'proxy_mode',
        'redirectRewrite': 'redirect_rewrite',
        'requestChunking': 'request_chunking',
        'responseChunking': 'response_chunking',
        'serverAgentName': 'server_agent_name',
        'viaRequest': 'via_request',
        'viaResponse': 'via_response',
        'pipeline': 'pipeline_action',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'accept_xff',
        'allow_truncated_redirects',
        'excess_client_headers',
        'excess_server_headers',
        'known_methods',
        'max_header_count',
        'max_header_size',
        'max_requests',
        'oversize_client_headers',
        'oversize_server_headers',
        'pipeline_action',
        'unknown_method',
        'default_connect_handling',
        'hsts_include_subdomains',
        'hsts_enabled',
        'insert_xforwarded_for',
        'lws_max_columns',
        'onconnect_transformations',
        'proxy_mode',
        'redirect_rewrite',
        'request_chunking',
        'response_chunking',
        'server_agent_name',
        'sflow_poll_interval',
        'sflow_sampling_rate',
        'via_request',
        'via_response',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def accept_xff(self):
        return flatten_boolean(self._values['accept_xff'])

    @property
    def excess_client_headers(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['excessClientHeaders'] is None:
            return None
        return self._values['enforcement']['excessClientHeaders']

    @property
    def excess_server_headers(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['excessServerHeaders'] is None:
            return None
        return self._values['enforcement']['excessServerHeaders']

    @property
    def known_methods(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['knownMethods'] is None:
            return None
        return self._values['enforcement']['knownMethods']

    @property
    def max_header_count(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['maxHeaderCount'] is None:
            return None
        return self._values['enforcement']['maxHeaderCount']

    @property
    def max_header_size(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['maxHeaderSize'] is None:
            return None
        return self._values['enforcement']['maxHeaderSize']

    @property
    def max_requests(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['maxRequests'] is None:
            return None
        return self._values['enforcement']['maxRequests']

    @property
    def oversize_client_headers(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['oversizeClientHeaders'] is None:
            return None
        return self._values['enforcement']['oversizeClientHeaders']

    @property
    def oversize_server_headers(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['oversizeServerHeaders'] is None:
            return None
        return self._values['enforcement']['oversizeServerHeaders']

    @property
    def allow_truncated_redirects(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['truncatedRedirects'] is None:
            return None
        return flatten_boolean(self._values['enforcement']['truncatedRedirects'])

    @property
    def unknown_method(self):
        if self._values['enforcement'] is None:
            return None
        if self._values['enforcement']['unknownMethod'] is None:
            return None
        return self._values['enforcement']['unknownMethod']

    @property
    def default_connect_handling(self):
        if self._values['explicit_proxy'] is None:
            return None
        if self._values['explicit_proxy']['defaultConnectHandling'] is None:
            return None
        return self._values['explicit_proxy']['defaultConnectHandling']

    @property
    def hsts_include_subdomains(self):
        if self._values['hsts'] is None:
            return None
        if self._values['hsts']['includeSubdomains'] is None:
            return None
        return flatten_boolean(self._values['hsts']['includeSubdomains'])

    @property
    def hsts_enabled(self):
        if self._values['hsts'] is None:
            return None
        if self._values['hsts']['mode'] is None:
            return None
        return flatten_boolean(self._values['hsts']['mode'])

    @property
    def hsts_max_age(self):
        if self._values['hsts'] is None:
            return None
        if self._values['hsts']['mode'] is None:
            return None
        return self._values['hsts']['maximumAge']

    @property
    def insert_xforwarded_for(self):
        if self._values['insert_xforwarded_for'] is None:
            return None
        return flatten_boolean(self._values['insert_xforwarded_for'])

    @property
    def onconnect_transformations(self):
        if self._values['onconnect_transformations'] is None:
            return None
        return flatten_boolean(self._values['onconnect_transformations'])

    @property
    def sflow_poll_interval(self):
        if self._values['sflow'] is None:
            return None
        if self._values['sflow']['pollInterval'] is None:
            return None
        return self._values['sflow']['pollInterval']

    @property
    def sflow_sampling_rate(self):
        if self._values['sflow'] is None:
            return None
        if self._values['sflow']['samplingRate'] is None:
            return None
        return self._values['sflow']['samplingRate']


class HttpProfilesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(HttpProfilesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(http_profiles=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = HttpProfilesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/http".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class IappServicesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'deviceGroup': 'device_group',
        'inheritedDevicegroup': 'inherited_device_group',
        'inheritedTrafficGroup': 'inherited_traffic_group',
        'strictUpdates': 'strict_updates',
        'templateModified': 'template_modified',
        'trafficGroup': 'traffic_group',
    }

    returnables = [
        'full_path',
        'name',
        'device_group',
        'inherited_device_group',
        'inherited_traffic_group',
        'strict_updates',
        'template_modified',
        'traffic_group',
        'tables',
        'variables',
        'metadata',
        'lists',
        'description',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def inherited_device_group(self):
        return flatten_boolean(self._values['inherited_device_group'])

    @property
    def inherited_traffic_group(self):
        return flatten_boolean(self._values['inherited_traffic_group'])

    @property
    def strict_updates(self):
        return flatten_boolean(self._values['strict_updates'])

    @property
    def template_modified(self):
        return flatten_boolean(self._values['template_modified'])


class IappServicesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(IappServicesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(iapp_services=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = IappServicesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/sys/application/service".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class IapplxPackagesParameters(BaseParameters):
    api_map = {
        'packageName': 'package_name',
    }

    returnables = [
        'name',
        'version',
        'release',
        'arch',
        'package_name',
        'tags',
    ]


class IapplxPackagesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(IapplxPackagesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(iapplx_packages=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['name'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = IapplxPackagesParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        params = dict(operation='QUERY')
        uri = "https://{0}:{1}/mgmt/shared/iapp/package-management-tasks".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
            raise F5ModuleError(resp.content)

        status = self.wait_for_task(response['id'])
        if status == 'FINISHED':
            uri = "https://{0}:{1}/mgmt/shared/iapp/package-management-tasks/{2}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                response['id']
            )
            resp = self.client.api.get(uri)
            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))
            if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                raise F5ModuleError(resp.content)

        else:
            raise F5ModuleError(
                "An error occurred querying iAppLX packages."
            )
        result = response['queryResponse']
        return result

    def wait_for_task(self, task_id):
        uri = "https://{0}:{1}/mgmt/shared/iapp/package-management-tasks/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            task_id
        )
        for x in range(0, 60):
            resp = self.client.api.get(uri)
            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
                raise F5ModuleError(resp.content)

            if response['status'] in ['FINISHED', 'FAILED']:
                return response['status']
            time.sleep(1)
        return response['status']


class IcmpMonitorsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultsFrom': 'parent',
        'adaptiveDivergenceType': 'adaptive_divergence_type',
        'adaptiveDivergenceValue': 'adaptive_divergence_value',
        'adaptiveLimit': 'adaptive_limit',
        'adaptiveSamplingTimespan': 'adaptive_sampling_timespan',
        'manualResume': 'manual_resume',
        'timeUntilUp': 'time_until_up',
        'upInterval': 'up_interval',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'adaptive',
        'adaptive_divergence_type',
        'adaptive_divergence_value',
        'adaptive_limit',
        'adaptive_sampling_timespan',
        'destination',
        'interval',
        'manual_resume',
        'time_until_up',
        'timeout',
        'transparent',
        'up_interval',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def transparent(self):
        return flatten_boolean(self._values['transparent'])

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])

    @property
    def adaptive(self):
        return flatten_boolean(self._values['adaptive'])


class IcmpMonitorsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(IcmpMonitorsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(icmp_monitors=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = IcmpMonitorsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/icmp".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class InterfacesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'mediaActive': 'active_media_type',
        'flowControl': 'flow_control',
        'bundleSpeed': 'bundle_speed',
        'ifIndex': 'if_index',
        'macAddress': 'mac_address',
        'mediaSfp': 'media_sfp',
        'lldpAdmin': 'lldp_admin',
        'preferPort': 'prefer_port',
        'stpAutoEdgePort': 'stp_auto_edge_port',
        'stp': 'stp_enabled',
        'stpLinkType': 'stp_link_type'
    }

    returnables = [
        'full_path',
        'name',
        'active_media_type',
        'flow_control',
        'description',
        'bundle',
        'bundle_speed',
        'enabled',
        'if_index',
        'mac_address',
        'media_sfp',
        'lldp_admin',
        'mtu',
        'prefer_port',
        'sflow_poll_interval',
        'sflow_poll_interval_global',
        'stp_auto_edge_port',
        'stp_enabled',
        'stp_link_type'
    ]

    @property
    def stp_auto_edge_port(self):
        return flatten_boolean(self._values['stp_auto_edge_port'])

    @property
    def stp_enabled(self):
        return flatten_boolean(self._values['stp_enabled'])

    @property
    def sflow_poll_interval_global(self):
        if self._values['sflow'] is None:
            return None
        if 'pollIntervalGlobal' in self._values['sflow']:
            return self._values['sflow']['pollIntervalGlobal']

    @property
    def sflow_poll_interval(self):
        if self._values['sflow'] is None:
            return None
        if 'pollInterval' in self._values['sflow']:
            return self._values['sflow']['pollInterval']

    @property
    def mac_address(self):
        if self._values['mac_address'] in [None, 'none']:
            return None
        return self._values['mac_address']

    @property
    def enabled(self):
        return flatten_boolean(self._values['enabled'])


class InterfacesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(InterfacesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(interfaces=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = InterfacesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/net/interface".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}".format(self.module.params['data_increment'], skip)
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class InternalDataGroupsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path'
    }

    returnables = [
        'full_path',
        'name',
        'type',
        'records'
    ]


class InternalDataGroupsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(InternalDataGroupsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(internal_data_groups=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = InternalDataGroupsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/data-group/internal".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class IrulesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'ignoreVerification': 'ignore_verification',
    }

    returnables = [
        'full_path',
        'name',
        'ignore_verification',
        'checksum',
        'definition',
        'signature'
    ]

    @property
    def checksum(self):
        if self._values['apiAnonymous'] is None:
            return None
        pattern = r'definition-checksum\s(?P<checksum>\w+)'
        matches = re.search(pattern, self._values['apiAnonymous'])
        if matches:
            return matches.group('checksum')

    @property
    def definition(self):
        if self._values['apiAnonymous'] is None:
            return None
        pattern = r'(definition-(checksum|signature)\s[\w=\/+]+)'
        result = re.sub(pattern, '', self._values['apiAnonymous']).strip()
        if result:
            return result

    @property
    def signature(self):
        if self._values['apiAnonymous'] is None:
            return None
        pattern = r'definition-signature\s(?P<signature>[\w=\/+]+)'
        matches = re.search(pattern, self._values['apiAnonymous'])
        if matches:
            return matches.group('signature')

    @property
    def ignore_verification(self):
        if self._values['ignore_verification'] is None:
            return 'no'
        return 'yes'


class IrulesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(IrulesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(irules=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = IrulesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/rule".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class LicenseParameters(BaseParameters):
    api_map = {

    }

    returnables = [
        'license_start_date',
        'license_end_date',
        'licensed_on_date',
        'licensed_version',
        'max_permitted_version',
        'min_permitted_version',
        'platform_id',
        'registration_key',
        'service_check_date',
        'active_modules'
    ]

    @property
    def license_start_date(self):
        if self._values['license'] is None:
            return None
        if bool(self._values['license'].get('licenseStartDate')):
            return self._values['license']['licenseStartDate']['description']

    @property
    def license_end_date(self):
        if self._values['license'] is None:
            return None
        if bool(self._values['license'].get('licenseEndDate')):
            return self._values['license']['licenseEndDate']['description']

    @property
    def licensed_on_date(self):
        if self._values['license'] is None:
            return None
        if bool(self._values['license'].get('licensedOnDate')):
            return self._values['license']['licensedOnDate']['description']

    @property
    def licensed_version(self):
        if self._values['license'] is None:
            return None
        if bool(self._values['license'].get('licensedVersion')):
            return self._values['license']['licensedVersion']['description']

    @property
    def max_permitted_version(self):
        if self._values['license'] is None:
            return None
        if bool(self._values['license'].get('maxPermittedVersion')):
            return self._values['license']['maxPermittedVersion']['description']

    @property
    def min_permitted_version(self):
        if self._values['license'] is None:
            return None
        if bool(self._values['license'].get('minPermittedVersion')):
            return self._values['license']['minPermittedVersion']['description']

    @property
    def platform_id(self):
        if self._values['license'] is None:
            return None
        if bool(self._values['license'].get('platformId')):
            return self._values['license']['platformId']['description']

    @property
    def registration_key(self):
        if self._values['license'] is None:
            return None
        if bool(self._values['license'].get('registrationKey')):
            return self._values['license']['registrationKey']['description']

    @property
    def service_check_date(self):
        if self._values['license'] is None:
            return None
        if bool(self._values['license'].get('serviceCheckDate')):
            return self._values['license']['serviceCheckDate']['description']

    @property
    def active_modules(self):
        if self._values['license'] is None:
            return None
        result = list()
        license = self._values['license']
        for key in license:
            if key.startswith("http"):
                v = license[key]['nestedStats']['entries']
                for k in v.keys():
                    addons = {
                        k2: v2['description']
                        for k2, v2 in
                        v[k]['nestedStats']['entries'].items()
                    }
                    result.append(addons)
        return result


class LicenseFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(LicenseFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(license=facts)
        return result

    def _exec_module(self):
        facts = self.read_facts()
        result = facts.to_return()
        return result

    def read_facts(self):
        resource = self.read_collection_from_device()
        params = LicenseParameters(params=resource)
        return params

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/license/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = dict()
        try:
            result['license'] = response['entries']['https://localhost/mgmt/tm/sys/license/0']['nestedStats']['entries']
            return result
        except KeyError:
            return None


class LtmPoolsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'allowNat': 'allow_nat',
        'allowSnat': 'allow_snat',
        'ignorePersistedWeight': 'ignore_persisted_weight',
        'ipTosToClient': 'client_ip_tos',
        'ipTosToServer': 'server_ip_tos',
        'linkQosToClient': 'client_link_qos',
        'linkQosToServer': 'server_link_qos',
        'loadBalancingMode': 'lb_method',
        'minActiveMembers': 'minimum_active_members',
        'minUpMembers': 'minimum_up_members',
        'minUpMembersAction': 'minimum_up_members_action',
        'minUpMembersChecking': 'minimum_up_members_checking',
        'queueDepthLimit': 'queue_depth_limit',
        'queueOnConnectionLimit': 'queue_on_connection_limit',
        'queueTimeLimit': 'queue_time_limit',
        'reselectTries': 'reselect_tries',
        'serviceDownAction': 'service_down_action',
        'slowRampTime': 'slow_ramp_time',
        'monitor': 'monitors',
    }

    returnables = [
        'full_path',
        'name',
        'allow_nat',
        'allow_snat',
        'description',
        'ignore_persisted_weight',
        'client_ip_tos',
        'server_ip_tos',
        'client_link_qos',
        'server_link_qos',
        'lb_method',
        'minimum_active_members',
        'minimum_up_members',
        'minimum_up_members_action',
        'minimum_up_members_checking',
        'monitors',
        'queue_depth_limit',
        'queue_on_connection_limit',
        'queue_time_limit',
        'reselect_tries',
        'service_down_action',
        'slow_ramp_time',
        'priority_group_activation',
        'members',
        'metadata',
        'active_member_count',
        'available_member_count',
        'availability_status',
        'enabled_status',
        'status_reason',
        'all_max_queue_entry_age_ever',
        'all_avg_queue_entry_age',
        'all_queue_head_entry_age',
        'all_max_queue_entry_age_recently',
        'all_num_connections_queued_now',
        'all_num_connections_serviced',
        'pool_max_queue_entry_age_ever',
        'pool_avg_queue_entry_age',
        'pool_queue_head_entry_age',
        'pool_max_queue_entry_age_recently',
        'pool_num_connections_queued_now',
        'pool_num_connections_serviced',
        'current_sessions',
        'member_count',
        'total_requests',
        'server_side_bits_in',
        'server_side_bits_out',
        'server_side_current_connections',
        'server_side_max_connections',
        'server_side_pkts_in',
        'server_side_pkts_out',
        'server_side_total_connections',
    ]

    @property
    def active_member_count(self):
        if 'availableMemberCnt' in self._values['stats']:
            return int(self._values['stats']['activeMemberCnt'])
        return None

    @property
    def available_member_count(self):
        if 'availableMemberCnt' in self._values['stats']:
            return int(self._values['stats']['availableMemberCnt'])
        return None

    @property
    def all_max_queue_entry_age_ever(self):
        if 'connqAll' in self._values['stats']:
            return self._values['stats']['connqAll']['ageEdm']
        return None

    @property
    def all_avg_queue_entry_age(self):
        if 'connqAll' in self._values['stats']:
            return self._values['stats']['connqAll']['ageEma']
        return None

    @property
    def all_queue_head_entry_age(self):
        if 'connqAll' in self._values['stats']:
            return self._values['stats']['connqAll']['ageHead']
        return None

    @property
    def all_max_queue_entry_age_recently(self):
        if 'connqAll' in self._values['stats']:
            return self._values['stats']['connqAll']['ageMax']
        return None

    @property
    def all_num_connections_queued_now(self):
        if 'connqAll' in self._values['stats']:
            return self._values['stats']['connqAll']['depth']
        return None

    @property
    def all_num_connections_serviced(self):
        if 'connqAll' in self._values['stats']:
            return self._values['stats']['connqAll']['serviced']
        return None

    @property
    def availability_status(self):
        if 'status' in self._values['stats']:
            return self._values['stats']['status']['availabilityState']
        return None

    @property
    def enabled_status(self):
        if 'status' in self._values['stats']:
            return self._values['stats']['status']['enabledState']
        return None

    @property
    def status_reason(self):
        if 'status' not in self._values['stats']:
            return None
        return self._values['stats']['status']['statusReason']

    @property
    def pool_max_queue_entry_age_ever(self):
        if 'connq' in self._values['stats']:
            return self._values['stats']['connq']['ageEdm']
        return None

    @property
    def pool_avg_queue_entry_age(self):
        if 'connq' in self._values['stats']:
            return self._values['stats']['connq']['ageEma']
        return None

    @property
    def pool_queue_head_entry_age(self):
        if 'connq' in self._values['stats']:
            return self._values['stats']['connq']['ageHead']
        return None

    @property
    def pool_max_queue_entry_age_recently(self):
        if 'connq' in self._values['stats']:
            return self._values['stats']['connq']['ageMax']
        return None

    @property
    def pool_num_connections_queued_now(self):
        if 'connq' in self._values['stats']:
            return self._values['stats']['connq']['depth']
        return None

    @property
    def pool_num_connections_serviced(self):
        if 'connq' in self._values['stats']:
            return self._values['stats']['connq']['serviced']
        return None

    @property
    def current_sessions(self):
        if 'curSessions' in self._values['stats']:
            return self._values['stats']['curSessions']
        return None

    @property
    def member_count(self):
        if 'memberCnt' in self._values['stats']:
            return self._values['stats']['memberCnt']
        return None

    @property
    def total_requests(self):
        if 'totRequests' in self._values['stats']:
            return self._values['stats']['totRequests']
        return None

    @property
    def server_side_bits_in(self):
        if 'serverside' in self._values['stats']:
            return self._values['stats']['serverside']['bitsIn']
        return None

    @property
    def server_side_bits_out(self):
        if 'serverside' in self._values['stats']:
            return self._values['stats']['serverside']['bitsOut']
        return None

    @property
    def server_side_current_connections(self):
        if 'serverside' in self._values['stats']:
            return self._values['stats']['serverside']['curConns']
        return None

    @property
    def server_side_max_connections(self):
        if 'serverside' in self._values['stats']:
            return self._values['stats']['serverside']['maxConns']
        return None

    @property
    def server_side_pkts_in(self):
        if 'serverside' in self._values['stats']:
            return self._values['stats']['serverside']['pktsIn']
        return None

    @property
    def server_side_pkts_out(self):
        if 'serverside' in self._values['stats']:
            return self._values['stats']['serverside']['pktsOut']
        return None

    @property
    def server_side_total_connections(self):
        if 'serverside' in self._values['stats']:
            return self._values['stats']['serverside']['totConns']
        return None

    @property
    def ignore_persisted_weight(self):
        return flatten_boolean(self._values['ignore_persisted_weight'])

    @property
    def minimum_up_members_checking(self):
        return flatten_boolean(self._values['minimum_up_members_checking'])

    @property
    def queue_on_connection_limit(self):
        return flatten_boolean(self._values['queue_on_connection_limit'])

    @property
    def priority_group_activation(self):
        """Returns the TMUI value for "Priority Group Activation"

        This value is identified as ``minActiveMembers`` in the REST API, so this
        is just a convenience key for users of Ansible (where the ``bigip_virtual_server``
        parameter is called ``priority_group_activation``.

        Returns:
            int: Priority number assigned to the pool members.
        """
        return self._values['minimum_active_members']

    @property
    def metadata(self):
        """Returns metadata associated with a pool

        An arbitrary amount of metadata may be associated with a pool. You typically
        see this used in situations where the user wants to annotate a resource, maybe
        in cases where an automation system is responsible for creating the resource.

        The metadata in the API is always stored as a list of dictionaries. We change
        this to be a simple dictionary before it is returned to the user.

        Returns:
            dict: A dictionary of key/value pairs where the key is the metadata name
                  and the value is the metadata value.
        """
        if self._values['metadata'] is None:
            return None
        result = dict([(k['name'], k['value']) for k in self._values['metadata']])
        return result

    @property
    def members(self):
        if not self._values['members']:
            return None
        result = []
        for member in self._values['members']:
            member['connection_limit'] = member.pop('connectionLimit', None)
            member['dynamic_ratio'] = member.pop('dynamicRatio', None)
            member['full_path'] = member.pop('fullPath', None)
            member['inherit_profile'] = member.pop('inheritProfile', None)
            member['priority_group'] = member.pop('priorityGroup', None)
            member['rate_limit'] = member.pop('rateLimit', None)

            if 'fqdn' in member and 'autopopulate' in member['fqdn']:
                if member['fqdn']['autopopulate'] == 'enabled':
                    member['fqdn_autopopulate'] = 'yes'
                elif member['fqdn']['autopopulate'] == 'disabled':
                    member['fqdn_autopopulate'] = 'no'
                del member['fqdn']

            for key in ['ephemeral', 'inherit_profile', 'logging', 'rate_limit']:
                tmp = flatten_boolean(member[key])
                member[key] = tmp

            if 'profiles' in member:
                # Even though the ``profiles`` is a list, there is only ever 1
                member['encapsulation_profile'] = [x['name'] for x in member['profiles']][0]
                del member['profiles']

            if 'monitor' in member:
                monitors = member.pop('monitor')
                if monitors is not None:
                    try:
                        member['monitors'] = re.findall(r'/[\w-]+/[^\s}]+', monitors)
                    except Exception:
                        member['monitors'] = [monitors.strip()]

            session = member.pop('session', None)
            state = member.pop('state', None)

            member['real_session'] = session
            member['real_state'] = state

            if state in ['user-up', 'unchecked', 'fqdn-up-no-addr', 'fqdn-up'] and session in ['user-enabled']:
                member['state'] = 'present'
            elif state in ['user-down'] and session in ['user-disabled']:
                member['state'] = 'forced_offline'
            elif state in ['up', 'checking'] and session in ['monitor-enabled']:
                member['state'] = 'present'
            elif state in ['down'] and session in ['monitor-enabled']:
                member['state'] = 'offline'
            else:
                member['state'] = 'disabled'
            self._remove_internal_keywords(member)
            member = dict([(k, v) for k, v in iteritems(member) if v is not None])
            result.append(member)
        return result

    @property
    def monitors(self):
        if self._values['monitors'] is None:
            return None
        try:
            result = re.findall(r'/[\w-]+/[^\s}]+', self._values['monitors'])
            return result
        except Exception:
            return [self._values['monitors'].strip()]


class LtmPoolsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(LtmPoolsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(ltm_pools=facts)
        return result

    def _exec_module(self):
        results = []
        results = self.read_facts()
        # for item in facts:
        #     attrs = item.to_return()
        #     results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    # def read_facts(self):
    #     logger = logging.getLogger("f5_bigip_device_info")
    #     logger.debug("Starting concurrent read_facts and stats collection for LTM pools.")
    #     results = []
    #     collection = self.increment_read()
    #     for resource in collection:
    #         # Process members directly from the expanded collection
    #         if 'membersReference' in resource and 'items' in resource['membersReference']:
    #             resource['members'] = resource['membersReference']['items']
    #         else:
    #             resource['members'] = []
    #         resource['stats'] = self.read_stats_from_device(resource['fullPath'])
    #         logger.debug(f"Stats collected for pool: {resource['stats']}")
    #         params = LtmPoolsParameters(params=resource)
    #         results.append(params.to_return())
    #     return results

    # def read_facts(self):
    #     results = []
    #     logger = logging.getLogger("f5_bigip_device_info")
    #     logger.debug("Starting concurrent read_facts and stats collection for LTM pools.")
    #     collection = self.increment_read()
    #     for resource in collection:
    #         # attrs = resource
    #         if 'membersReference' in resource and 'items' in resource['membersReference']:
    #             resource['members'] = resource['membersReference']['items']
    #         else:
    #             resource['members'] = []
    #         # members = self.read_member_from_device(attrs['fullPath'])
    #         # attrs['members'] = members
    #         resource['stats'] = self.read_stats_from_device(resource['fullPath'])
    #         params = LtmPoolsParameters(params=resource)
    #         logger.debug(f"Stats collected for pool: {params.to_return()}")
    #         results.append(params.to_return())
    #     logger.debug(f"Total pools collected: {len(results)}")
    #     return results

    def read_facts(self):
        results = []
        collection = self.increment_read()

        def collect_stats(resource):
            # Process members directly from the expanded collection
            if 'membersReference' in resource and 'items' in resource['membersReference']:
                resource['members'] = resource['membersReference']['items']
            else:
                resource['members'] = []
            # Collect stats for each pool
            resource['stats'] = self.read_stats_from_device(resource['fullPath'])
            params = LtmPoolsParameters(params=resource)
            return params.to_return()

        with ThreadPoolExecutor() as executor:
            future_to_resource = {executor.submit(collect_stats, resource): resource for resource in collection}
            for future in as_completed(future_to_resource):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    pass
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        """Read the LTM pools collection from the device

        Note that sub-collection expansion does not work with LTM pools. Therefore,
        one needs to query the ``members`` endpoint separately and add that to the
        list of ``attrs`` before the full set of attributes is sent to the ``Parameters``
        class.

        Returns:
             list: List of ``Pool`` objects
        """
        uri = "https://{0}:{1}/mgmt/tm/ltm/pool".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        if self.module.params['partition'] == 'all':
            query = "?$top={0}&$skip={1}&expandSubcollections=true".format(
                self.module.params['data_increment'], skip)
        else:
            query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}&expandSubcollections=true".format(
                self.module.params['data_increment'], skip, self.module.params['partition']
            )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result

    def read_member_from_device(self, full_path):
        uri = "https://{0}:{1}/mgmt/tm/ltm/pool/{2}/members".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=full_path)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result

    def read_stats_from_device(self, full_path):
        uri = "https://{0}:{1}/mgmt/tm/ltm/pool/{2}/stats".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=full_path)
        )
        try:
            resp = self.client.api.get(uri)
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        except Exception as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or ('code' in response and response['code'] not in [200, 201]):
            raise F5ModuleError(resp.content)

        result = parseStats(response)
        try:
            return result['stats']
        except KeyError:
            return {}


class SnatPoolsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'membersReference': 'members_reference',
    }

    returnables = [
        'full_path',
        'name',
        'description',
        'members',
        'members_reference',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def members(self):
        if self._values['members'] is None:
            return []
        return self._values['members']

    @property
    def members_reference(self):
        if self._values['members_reference'] is None:
            return []
        result = []
        for item in self._values['members_reference']:
            if 'link' in item:
                result.append(item['link'])
        return result


class SnatPoolsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SnatPoolsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(snat_pools=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = SnatPoolsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/snatpool".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class LtmPolicyParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'rulesReference': 'rules',
    }

    returnables = [
        'full_path',
        'name',
        'status',
        'description',
        'strategy',
        'rules',
        'requires',
        'controls',
    ]

    def _handle_conditions(self, conditions):
        result = []
        if conditions is None or 'items' not in conditions:
            return result
        for condition in conditions['items']:
            tmp = dict()
            tmp['case_insensitive'] = flatten_boolean(condition.pop('caseInsensitive', None))
            tmp['case_sensitive'] = flatten_boolean(condition.pop('caseSensitive', None))
            tmp['contains_string'] = flatten_boolean(condition.pop('contains', None))
            tmp['external'] = flatten_boolean(condition.pop('external', None))
            tmp['http_basic_auth'] = flatten_boolean(condition.pop('httpBasicAuth', None))
            tmp['http_host'] = flatten_boolean(condition.pop('httpHost', None))
            tmp['datagroup'] = condition.pop('datagroup', None)
            tmp['tcp'] = flatten_boolean(condition.pop('tcp', None))
            tmp['remote'] = flatten_boolean(condition.pop('remote', None))
            tmp['matches'] = flatten_boolean(condition.pop('matches', None))
            tmp['address'] = flatten_boolean(condition.pop('address', None))
            tmp['present'] = flatten_boolean(condition.pop('present', None))
            tmp['proxy_connect'] = flatten_boolean(condition.pop('proxyConnect', None))
            tmp['proxy_request'] = flatten_boolean(condition.pop('proxyRequest', None))
            tmp['host'] = flatten_boolean(condition.pop('host', None))
            tmp['http_uri'] = flatten_boolean(condition.pop('httpUri', None))
            tmp['request'] = flatten_boolean(condition.pop('request', None))
            tmp['username'] = flatten_boolean(condition.pop('username', None))
            tmp['external'] = flatten_boolean(condition.pop('external', None))
            tmp['values'] = condition.pop('values', None)
            tmp['all'] = flatten_boolean(condition.pop('all', None))
            result.append(self._filter_params(tmp))
        return result

    def _handle_actions(self, actions):
        result = []
        if actions is None or 'items' not in actions:
            return result
        exclude_keys = ["poolReference", "name"]
        for action in actions['items']:
            tmp = dict((k, v) for k, v in iteritems(action) if v != 0 and k not in exclude_keys)
            self._remove_internal_keywords(tmp)
            result.append(self._filter_params(tmp))
        return result

    @property
    def rules(self):
        result = []
        if self._values['rules'] is None or 'items' not in self._values['rules']:
            return result
        for item in self._values['rules']['items']:
            self._remove_internal_keywords(item)
            item['conditions'] = self._handle_conditions(item.pop('conditionsReference', None))
            item['actions'] = self._handle_actions(item.pop('actionsReference', None))
            result.append(item)
        return result


class LtmPolicyFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(LtmPolicyFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(ltm_policies=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = LtmPolicyParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/policy/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class NodesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'connectionLimit': 'connection_limit',
        'dynamicRatio': 'dynamic_ratio',
        'rateLimit': 'rate_limit',
        'monitor': 'monitors'
    }

    returnables = [
        'full_path',
        'name',
        'ratio',
        'description',
        'connection_limit',
        'address',
        'dynamic_ratio',
        'rate_limit',
        'monitor_status',
        'session_status',
        'availability_status',
        'enabled_status',
        'status_reason',
        'monitor_rule',
        'monitors',
        'monitor_type',
        'fqdn_name',
        'fqdn_auto_populate',
        'fqdn_address_type',
        'fqdn_up_interval',
        'fqdn_down_interval',
    ]

    @property
    def fqdn_name(self):
        if self._values['fqdn'] is None:
            return None
        return self._values['fqdn'].get('tmName', None)

    @property
    def fqdn_auto_populate(self):
        if self._values['fqdn'] is None:
            return None
        return flatten_boolean(self._values['fqdn'].get('autopopulate', None))

    @property
    def fqdn_address_type(self):
        if self._values['fqdn'] is None:
            return None
        return self._values['fqdn'].get('addressFamily', None)

    @property
    def fqdn_up_interval(self):
        if self._values['fqdn'] is None:
            return None
        result = self._values['fqdn'].get('interval', None)
        if result:
            try:
                return int(result)
            except ValueError:
                return result

    @property
    def fqdn_down_interval(self):
        if self._values['fqdn'] is None:
            return None
        result = self._values['fqdn'].get('downInterval', None)
        if result:
            try:
                return int(result)
            except ValueError:
                return result

    @property
    def monitors(self):
        if self._values['monitors'] is None:
            return []
        try:
            result = re.findall(r'/\w+/[^\s}]+', self._values['monitors'])
            return result
        except Exception:
            return [self._values['monitors']]

    @property
    def monitor_type(self):
        if self._values['monitors'] is None:
            return None
        pattern = r'min\s+\d+\s+of'
        matches = re.search(pattern, self._values['monitors'])
        if matches:
            return 'm_of_n'
        else:
            return 'and_list'

    @property
    def rate_limit(self):
        if self._values['rate_limit'] is None:
            return None
        elif self._values['rate_limit'] == 'disabled':
            return 0
        else:
            return int(self._values['rate_limit'])

    @property
    def monitor_status(self):
        return self._values['stats']['monitorStatus']

    @property
    def session_status(self):
        return self._values['stats']['sessionStatus']

    @property
    def availability_status(self):
        return self._values['stats']['status']['availabilityState']

    @property
    def enabled_status(self):
        return self._values['stats']['status']['enabledState']

    @property
    def status_reason(self):
        return self._values['stats']['status']['statusReason']

    @property
    def monitor_rule(self):
        return self._values['stats']['monitorRule']


class NodesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(NodesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(nodes=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            attrs = resource
            attrs['stats'] = self.read_stats_from_device(attrs['fullPath'])
            params = NodesParameters(params=attrs)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/node".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result

    def read_stats_from_device(self, full_path):
        uri = "https://{0}:{1}/mgmt/tm/ltm/node/{2}/stats".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=full_path)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = parseStats(response)
        try:
            return result['stats']
        except KeyError:
            return {}


class OneConnectProfilesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'clientTimeout': 'client_timeout',
        'defaultsFrom': 'parent',
        'idleTimeoutOverride': 'idle_timeout_override',
        'limitType': 'limit_type',
        'maxAge': 'max_age',
        'maxReuse': 'max_reuse',
        'maxSize': 'max_size',
        'sharePools': 'share_pools',
        'sourceMask': 'source_mask',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'idle_timeout_override',
        'limit_type',
        'max_age',
        'max_reuse',
        'max_size',
        'share_pools',
        'source_mask',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def idle_timeout_override(self):
        if self._values['idle_timeout_override'] is None:
            return None
        elif self._values['idle_timeout_override'] == 'disabled':
            return 0
        elif self._values['idle_timeout_override'] == 'indefinite':
            return 4294967295
        return int(self._values['idle_timeout_override'])

    @property
    def share_pools(self):
        return flatten_boolean(self._values['share_pools'])


class OneConnectProfilesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(OneConnectProfilesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(oneconnect_profiles=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = OneConnectProfilesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/one-connect".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class PartitionParameters(BaseParameters):
    api_map = {
        'defaultRouteDomain': 'default_route_domain',
        'fullPath': 'full_path',
    }

    returnables = [
        'name',
        'full_path',
        'description',
        'default_route_domain'
    ]


class PartitionFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(PartitionFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(partitions=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = PartitionParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/auth/partition".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class ProvisionInfoParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'cpuRatio': 'cpu_ratio',
        'diskRatio': 'disk_ratio',
        'memoryRatio': 'memory_ratio',
    }

    returnables = [
        'full_path',
        'name',
        'cpu_ratio',
        'disk_ratio',
        'memory_ratio',
        'level'
    ]


class ProvisionInfoFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ProvisionInfoFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(provision_info=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = ProvisionInfoParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/provision".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class RouteDomainParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'bwcPolicy': 'bwc_policy',
        'connectionLimit': 'connection_limit',
        'flowEvictionPolicy': 'flow_eviction_policy',
        'servicePolicy': 'service_policy',
        'routingProtocol': 'routing_protocol',
    }

    returnables = [
        'name',
        'id',
        'full_path',
        'parent',
        'bwc_policy',
        'connection_limit',
        'description',
        'flow_eviction_policy',
        'service_policy',
        'strict',
        'routing_protocol',
        'vlans',
    ]

    @property
    def strict(self):
        return flatten_boolean(self._values['strict'])

    @property
    def connection_limit(self):
        if self._values['connection_limit'] is None:
            return None
        return int(self._values['connection_limit'])

    @property
    def id(self):
        if self._values['id'] is None:
            return None
        return int(self._values['id'])


class RouteDomainFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(RouteDomainFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(route_domains=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = RouteDomainParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/net/route-domain".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class SelfIpsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'trafficGroup': 'traffic_group',
        'servicePolicy': 'service_policy',
        'allowService': 'allow_access_list',
        'inheritedTrafficGroup': 'traffic_group_inherited'
    }

    returnables = [
        'full_path',
        'name',
        'address',
        'description',
        'netmask',
        'netmask_cidr',
        'floating',
        'traffic_group',
        'service_policy',
        'vlan',
        'allow_access_list',
        'traffic_group_inherited'
    ]

    @property
    def address(self):
        parts = self._values['address'].split('/')
        return parts[0]

    @property
    def netmask(self):
        result = None
        parts = self._values['address'].split('/')
        if is_valid_ip(parts[0]):
            ip = ip_interface(u'{0}'.format(self._values['address']))
            result = ip.netmask
        return str(result)

    @property
    def netmask_cidr(self):
        parts = self._values['address'].split('/')
        return int(parts[1])

    @property
    def traffic_group_inherited(self):
        if self._values['traffic_group_inherited'] is None:
            return None
        elif self._values['traffic_group_inherited'] in [False, 'false']:
            # BIG-IP appears to store this as a string. This is a bug, so we handle both
            # cases here.
            return 'no'
        else:
            return 'yes'

    @property
    def floating(self):
        if self._values['floating'] is None:
            return None
        elif self._values['floating'] == 'disabled':
            return 'no'
        else:
            return 'yes'


class SelfIpsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SelfIpsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(self_ips=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = SelfIpsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/net/self".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class ServerSslProfilesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'alertTimeout': 'alert_timeout',
        'allowExpiredCrl': 'allow_expired_crl',
        'authenticate': 'authentication_frequency',
        'authenticateDepth': 'authenticate_depth',
        'authenticateName': 'authenticate_name',
        'bypassOnClientCertFail': 'bypass_on_client_cert_fail',
        'bypassOnHandshakeAlert': 'bypass_on_handshake_alert',
        'c3dCaCert': 'c3d_ca_cert',
        'c3dCaKey': 'c3d_ca_key',
        'c3dCertExtensionIncludes': 'c3d_cert_extension_includes',
        'c3dCertLifespan': 'c3d_cert_lifespan',
        'caFile': 'ca_file',
        'cacheSize': 'cache_size',
        'cacheTimeout': 'cache_timeout',
        'cipherGroup': 'cipher_group',
        'crlFile': 'crl_file',
        'defaultsFrom': 'parent',
        'expireCertResponseControl': 'expire_cert_response_control',
        'genericAlert': 'generic_alert',
        'handshakeTimeout': 'handshake_timeout',
        'maxActiveHandshakes': 'max_active_handshakes',
        'modSslMethods': 'mod_ssl_methods',
        'tmOptions': 'options',
        'peerCertMode': 'peer_cert_mode',
        'proxySsl': 'proxy_ssl',
        'proxySslPassthrough': 'proxy_ssl_passthrough',
        'renegotiatePeriod': 'renegotiate_period',
        'renegotiateSize': 'renegotiate_size',
        'retainCertificate': 'retain_certificate',
        'secureRenegotiation': 'secure_renegotiation',
        'serverName': 'server_name',
        'sessionMirroring': 'session_mirroring',
        'sessionTicket': 'session_ticket',
        'sniDefault': 'sni_default',
        'sniRequire': 'sni_require',
        'sslC3d': 'ssl_c3d',
        'sslForwardProxy': 'ssl_forward_proxy_enabled',
        'sslForwardProxyBypass': 'ssl_forward_proxy_bypass',
        'sslSignHash': 'ssl_sign_hash',
        'strictResume': 'strict_resume',
        'uncleanShutdown': 'unclean_shutdown',
        'untrustedCertResponseControl': 'untrusted_cert_response_control'
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'unclean_shutdown',
        'strict_resume',
        'ssl_forward_proxy_enabled',
        'ssl_forward_proxy_bypass',
        'sni_default',
        'sni_require',
        'ssl_c3d',
        'session_mirroring',
        'session_ticket',
        'mod_ssl_methods',
        'allow_expired_crl',
        'retain_certificate',
        'mode',
        'bypass_on_client_cert_fail',
        'bypass_on_handshake_alert',
        'generic_alert',
        'renegotiation',
        'proxy_ssl',
        'proxy_ssl_passthrough',
        'peer_cert_mode',
        'untrusted_cert_response_control',
        'ssl_sign_hash',
        'server_name',
        'secure_renegotiation',
        'renegotiate_size',
        'renegotiate_period',
        'options',
        'ocsp',
        'max_active_handshakes',
        'key',
        'handshake_timeout',
        'expire_cert_response_control',
        'cert',
        'chain',
        'authentication_frequency',
        'ciphers',
        'cipher_group',
        'crl_file',
        'cache_timeout',
        'cache_size',
        'ca_file',
        'c3d_cert_lifespan',
        'alert_timeout',
        'c3d_ca_key',
        'authenticate_depth',
        'authenticate_name',
        'c3d_ca_cert',
        'c3d_cert_extension_includes',
    ]

    @property
    def c3d_cert_extension_includes(self):
        if self._values['c3d_cert_extension_includes'] is None:
            return None
        if len(self._values['c3d_cert_extension_includes']) == 0:
            return None
        self._values['c3d_cert_extension_includes'].sort()
        return self._values['c3d_cert_extension_includes']

    @property
    def options(self):
        if self._values['options'] is None:
            return None
        if len(self._values['options']) == 0:
            return None
        self._values['options'].sort()
        return self._values['options']

    @property
    def c3d_ca_cert(self):
        if self._values['c3d_ca_cert'] in [None, 'none']:
            return None
        return self._values['c3d_ca_cert']

    @property
    def ocsp(self):
        if self._values['ocsp'] in [None, 'none']:
            return None
        return self._values['ocsp']

    @property
    def server_name(self):
        if self._values['server_name'] in [None, 'none']:
            return None
        return self._values['server_name']

    @property
    def cipher_group(self):
        if self._values['cipher_group'] is None:
            return None
        if self._values['cipher_group'] == 'none':
            return 'none'
        return self._values['cipher_group']

    @property
    def authenticate_name(self):
        if self._values['authenticate_name'] in [None, 'none']:
            return None
        return self._values['authenticate_name']

    @property
    def c3d_ca_key(self):
        if self._values['c3d_ca_key'] in [None, 'none']:
            return None
        return self._values['c3d_ca_key']

    @property
    def ca_file(self):
        if self._values['ca_file'] in [None, 'none']:
            return None
        return self._values['ca_file']

    @property
    def crl_file(self):
        if self._values['crl_file'] in [None, 'none']:
            return None
        return self._values['crl_file']

    @property
    def authentication_frequency(self):
        if self._values['authentication_frequency'] in [None, 'none']:
            return None
        return self._values['authentication_frequency']

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def proxy_ssl_passthrough(self):
        return flatten_boolean(self._values['proxy_ssl_passthrough'])

    @property
    def proxy_ssl(self):
        return flatten_boolean(self._values['proxy_ssl'])

    @property
    def generic_alert(self):
        return flatten_boolean(self._values['generic_alert'])

    @property
    def renegotiation(self):
        return flatten_boolean(self._values['renegotiation'])

    @property
    def bypass_on_handshake_alert(self):
        return flatten_boolean(self._values['bypass_on_handshake_alert'])

    @property
    def bypass_on_client_cert_fail(self):
        return flatten_boolean(self._values['bypass_on_client_cert_fail'])

    @property
    def mode(self):
        return flatten_boolean(self._values['mode'])

    @property
    def retain_certificate(self):
        return flatten_boolean(self._values['retain_certificate'])

    @property
    def allow_expired_crl(self):
        return flatten_boolean(self._values['allow_expired_crl'])

    @property
    def mod_ssl_methods(self):
        return flatten_boolean(self._values['mod_ssl_methods'])

    @property
    def session_ticket(self):
        return flatten_boolean(self._values['session_ticket'])

    @property
    def session_mirroring(self):
        return flatten_boolean(self._values['session_mirroring'])

    @property
    def unclean_shutdown(self):
        return flatten_boolean(self._values['unclean_shutdown'])

    @property
    def strict_resume(self):
        return flatten_boolean(self._values['strict_resume'])

    @property
    def ssl_forward_proxy_enabled(self):
        return flatten_boolean(self._values['ssl_forward_proxy_enabled'])

    @property
    def ssl_forward_proxy_bypass(self):
        return flatten_boolean(self._values['ssl_forward_proxy_bypass'])

    @property
    def sni_default(self):
        return flatten_boolean(self._values['sni_default'])

    @property
    def sni_require(self):
        return flatten_boolean(self._values['sni_require'])

    @property
    def ssl_c3d(self):
        return flatten_boolean(self._values['ssl_c3d'])


class ServerSslProfilesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ServerSslProfilesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(server_ssl_profiles=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = ServerSslProfilesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/server-ssl".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class SoftwareVolumesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'basebuild': 'base_build',
    }

    returnables = [
        'full_path',
        'name',
        'active',
        'base_build',
        'build',
        'product',
        'status',
        'version',
        'install_volume',
        'default_boot_location'
    ]

    @property
    def install_volume(self):
        if self._values['media'] is None:
            return None
        return self._values['media'].get('name', None)

    @property
    def default_boot_location(self):
        if self._values['media'] is None:
            return None
        return flatten_boolean(self._values['media'].get('defaultBootLocation', None))

    @property
    def active(self):
        if self._values['active'] is True:
            return 'yes'
        return 'no'


class SoftwareVolumesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SoftwareVolumesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(software_volumes=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = SoftwareVolumesParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/software/volume".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class SoftwareHotfixesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
    }

    returnables = [
        'name',
        'full_path',
        'build',
        'checksum',
        'id',
        'product',
        'title',
        'verified',
        'version',
    ]


class SoftwareHotfixesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SoftwareHotfixesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(software_hotfixes=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = SoftwareHotfixesParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/software/hotfix".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class SoftwareImagesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'buildDate': 'build_date',
        'fileSize': 'file_size',
        'lastModified': 'last_modified',
    }

    returnables = [
        'name',
        'full_path',
        'build',
        'build_date',
        'checksum',
        'file_size',
        'last_modified',
        'product',
        'verified',
        'version',
    ]

    @property
    def file_size(self):
        if self._values['file_size'] is None:
            return None
        matches = re.match(r'\d+', self._values['file_size'])
        if matches:
            return int(matches.group(0))

    @property
    def build_date(self):
        """Normalizes the build_date string

        The ISOs usually ship with a broken format

        ex: Tue May 15 15 26 30 PDT 2018

        This will re-format that time so that it looks like ISO 8601 without
        microseconds

        ex: 2018-05-15T15:26:30

        :return:
        """
        if self._values['build_date'] is None:
            return None

        d = self._values['build_date'].split(' ')

        # This removes the timezone portion from the string. This is done
        # because Python has awfule tz parsing and strptime doesnt work with
        # all timezones in %Z; it only uses the timezones found in time.tzname
        d.pop(6)

        result = datetime.datetime.strptime(' '.join(d), '%a %b %d %H %M %S %Y').isoformat()
        return result

    @property
    def last_modified(self):
        """Normalizes the last_modified string

        The strings that the system reports look like the following

        ex: Tue May 15 15:26:30 2018

        This property normalizes this value to be isoformat

        ex: 2018-05-15T15:26:30

        :return:
        """
        if self._values['last_modified'] is None:
            return None
        result = datetime.datetime.strptime(self._values['last_modified'], '%a %b %d %H:%M:%S %Y').isoformat()
        return result


class SoftwareImagesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SoftwareImagesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(software_images=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = SoftwareImagesParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/software/image".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class SslCertificatesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'keyType': 'key_type',
        'certificateKeySize': 'key_size',
        'systemPath': 'system_path',
        'checksum': 'sha1_checksum',
        'lastUpdateTime': 'last_update_time',
        'isBundle': 'is_bundle',
        'expirationString': 'expiration_date',
        'expirationDate': 'expiration_timestamp',
        'createTime': 'create_time',
        'subjectAlternativeName': 'subject_alternative_name',
        'serialNumber': 'serial_no',
    }

    returnables = [
        'full_path',
        'name',
        'key_type',
        'key_size',
        'system_path',
        'sha1_checksum',
        'subject',
        'last_update_time',
        'issuer',
        'is_bundle',
        'fingerprint',
        'expiration_date',
        'expiration_timestamp',
        'create_time',
        'subject_alternative_name',
        'serial_no',
    ]

    @property
    def sha1_checksum(self):
        if self._values['sha1_checksum'] is None:
            return None
        parts = self._values['sha1_checksum'].split(':')
        return parts[2]

    @property
    def is_bundle(self):
        if self._values['sha1_checksum'] is None:
            return None
        if self._values['is_bundle'] in BOOLEANS_TRUE:
            return 'yes'
        return 'no'


class SslCertificatesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SslCertificatesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(ssl_certs=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = SslCertificatesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/sys/file/ssl-cert".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class SslKeysParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'keyType': 'key_type',
        'keySize': 'key_size',
        'securityType': 'security_type',
        'systemPath': 'system_path',
        'checksum': 'sha1_checksum',
    }

    returnables = [
        'full_path',
        'name',
        'key_type',
        'key_size',
        'security_type',
        'system_path',
        'sha1_checksum',
    ]

    @property
    def sha1_checksum(self):
        if self._values['sha1_checksum'] is None:
            return None
        parts = self._values['sha1_checksum'].split(':')
        return parts[2]


class SslKeysFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SslKeysFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(ssl_keys=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = SslKeysParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/sys/file/ssl-key".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class SystemDbParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultValue': 'default',
        'scfConfig': 'scf_config',
        'valueRange': 'value_range'
    }

    returnables = [
        'name',
        'full_path',
        'default',
        'scf_config',
        'value',
        'value_range'
    ]


class SyncStatusParameters(BaseParameters):
    api_map = {
    }

    returnables = [
        'color',
        'details',
        'mode',
        'recommended_action',
        'status',
        'summary',
    ]

    @property
    def color(self):
        result = self._values.get('color', {}).get('description', "")
        if result.strip():
            return result
        return ""

    @property
    def details(self):
        result = []
        details = (self._values.get('https://localhost/mgmt/tm/cm/syncStatus/0/details', {})
                   .get('nestedStats', {})
                   .get('entries', {}))
        for entry in details.keys():
            result.append(
                details[entry].get('nestedStats', {})
                              .get('entries', {})
                              .get('details', {})
                              .get('description', "")
            )
        result.reverse()
        return result

    @property
    def mode(self):
        result = self._values.get('mode', {}).get('description', "")
        if result.strip():
            return result
        return ""

    @property
    def status(self):
        result = self._values.get('status', {}).get('description', "")
        if result.strip():
            return result
        return ""

    @property
    def summary(self):
        result = self._values.get('summary', {}).get('description', "")
        if result.strip():
            return result
        return ""

    @property
    def recommended_action(self):
        for entry in self.details:
            match = re.match(r".*[Rr]ecommended action:\s(.*)$", entry)
            if match:
                return match.group(1)
        return ""


class SyncStatusFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SyncStatusFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(sync_status=facts)
        return result

    def _exec_module(self):
        facts = self.read_facts()
        attrs = facts.to_return()
        result = [attrs]
        return result

    def read_facts(self):
        collection = self.read_collection_from_device()
        return SyncStatusParameters(params=collection)

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/cm/sync-status".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = response.get('entries', {}) \
            .get('https://localhost/mgmt/tm/cm/sync-status/0', {}) \
            .get('nestedStats', {}) \
            .get('entries')
        return result


class SystemDbFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SystemDbFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(system_db=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = SystemDbParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/db".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class SystemInfoParameters(BaseParameters):
    api_map = {

    }

    returnables = [
        'base_mac_address',
        'marketing_name',
        'time',
        'hardware_information',
        'product_information',
        'package_edition',
        'package_version',
        'product_code',
        'product_build',
        'product_built',
        'product_build_date',
        'product_changelist',
        'product_jobid',
        'product_version',
        'uptime',
        'chassis_serial',
        'host_board_part_revision',
        'host_board_serial',
        'platform',
        'switch_board_part_revision',
        'switch_board_serial'
    ]

    @property
    def chassis_serial(self):
        if self._values['system-info'] is None:
            return None
        if 'bigipChassisSerialNum' not in self._values['system-info'][0]:
            return None
        return self._values['system-info'][0]['bigipChassisSerialNum']

    @property
    def switch_board_serial(self):
        if self._values['system-info'] is None:
            return None
        if 'switchBoardSerialNum' not in self._values['system-info'][0]:
            return None
        if self._values['system-info'][0]['switchBoardSerialNum'].strip() == '':
            return None
        return self._values['system-info'][0]['switchBoardSerialNum']

    @property
    def switch_board_part_revision(self):
        if self._values['system-info'] is None:
            return None
        if 'switchBoardPartRevNum' not in self._values['system-info'][0]:
            return None
        if self._values['system-info'][0]['switchBoardPartRevNum'].strip() == '':
            return None
        return self._values['system-info'][0]['switchBoardPartRevNum']

    @property
    def platform(self):
        if self._values['system-info'] is None:
            return None
        return self._values['system-info'][0]['platform']

    @property
    def host_board_serial(self):
        if self._values['system-info'] is None:
            return None
        if 'hostBoardSerialNum' not in self._values['system-info'][0]:
            return None
        if self._values['system-info'][0]['hostBoardSerialNum'].strip() == '':
            return None
        return self._values['system-info'][0]['hostBoardSerialNum']

    @property
    def host_board_part_revision(self):
        if self._values['system-info'] is None:
            return None
        if 'hostBoardPartRevNum' not in self._values['system-info'][0]:
            return None
        if self._values['system-info'][0]['hostBoardPartRevNum'].strip() == '':
            return None
        return self._values['system-info'][0]['hostBoardPartRevNum']

    @property
    def package_edition(self):
        return self._values['Edition']

    @property
    def package_version(self):
        return 'Build {0} - {1}'.format(self._values['Build'], self._values['Date'])

    @property
    def product_build(self):
        return self._values['Build']

    @property
    def product_build_date(self):
        return self._values['Date']

    @property
    def product_built(self):
        if 'Built' in self._values['version_info']:
            return int(self._values['version_info']['Built'])

    @property
    def product_changelist(self):
        if 'Changelist' in self._values['version_info']:
            return int(self._values['version_info']['Changelist'])

    @property
    def product_jobid(self):
        if 'JobID' in self._values['version_info']:
            return int(self._values['version_info']['JobID'])

    @property
    def product_code(self):
        return self._values['Product']

    @property
    def product_version(self):
        return self._values['Version']

    @property
    def hardware_information(self):
        if self._values['hardware-version'] is None:
            return None
        self._transform_name_attribute(self._values['hardware-version'])
        result = [v for k, v in iteritems(self._values['hardware-version'])]
        return result

    def _transform_name_attribute(self, entry):
        if isinstance(entry, dict):
            for k, v in list(entry.items()):
                if k == 'tmName':
                    entry['name'] = entry.pop('tmName')
                self._transform_name_attribute(v)
        elif isinstance(entry, list):
            for k in entry:
                if k == 'tmName':
                    entry['name'] = entry.pop('tmName')
                self._transform_name_attribute(k)
        else:
            return

    @property
    def time(self):
        if self._values['fullDate'] is None:
            return None
        date = datetime.datetime.strptime(self._values['fullDate'], "%Y-%m-%dT%H:%M:%SZ")
        result = dict(
            day=date.day,
            hour=date.hour,
            minute=date.minute,
            month=date.month,
            second=date.second,
            year=date.year
        )
        return result

    @property
    def marketing_name(self):
        if self._values['platform'] is None:
            return None
        return self._values['platform'][0]['marketingName']

    @property
    def base_mac_address(self):
        if self._values['platform'] is None:
            return None
        return self._values['platform'][0]['baseMac']


class SystemInfoFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(SystemInfoFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(system_info=facts)
        return result

    def _exec_module(self):
        facts = self.read_facts()
        results = facts.to_return()
        return results

    def read_facts(self):
        collection = self.read_collection_from_device()
        params = SystemInfoParameters(params=collection)
        return params

    def read_collection_from_device(self):
        result = dict()
        tmp = self.read_hardware_info_from_device()
        if tmp:
            result.update(tmp)

        tmp = self.read_clock_info_from_device()
        if tmp:
            result.update(tmp)

        tmp = self.read_version_info_from_device()
        if tmp:
            result.update(tmp)

        tmp = self.read_uptime_info_from_device()
        if tmp:
            result.update(tmp)

        tmp = self.read_version_file_info_from_device()
        if tmp:
            result.update(tmp)

        return result

    def read_version_file_info_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/util/bash".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        args = dict(
            command='run',
            utilCmdArgs='-c "cat /VERSION"'
        )
        resp = self.client.api.post(uri, json=args)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        try:
            pattern = r'^(?P<key>(Product|Build|Sequence|BaseBuild|Edition|Date|Built|Changelist|JobID))\:(?P<value>.*)'
            result = response['commandResult'].strip()
        except KeyError:
            return None

        if 'No such file or directory' in result:
            return None

        lines = response['commandResult'].split("\n")
        result = dict()
        for line in lines:
            if not line:
                continue
            matches = re.match(pattern, line)
            if matches:
                result[matches.group('key')] = matches.group('value').strip()

        if result:
            return dict(
                version_info=result
            )

    def read_uptime_info_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/util/bash".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        args = dict(
            command='run',
            utilCmdArgs='-c "cat /proc/uptime"'
        )
        resp = self.client.api.post(uri, json=args)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        try:
            parts = response['commandResult'].strip().split(' ')
            return dict(
                uptime=math.floor(float(parts[0]))
            )
        except KeyError:
            pass

    def read_hardware_info_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/hardware".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = parseStats(response)
        return result

    def read_clock_info_from_device(self):
        """Parses clock info from the REST API

        The clock stat returned from the REST API (at the time of 13.1.0.7)
        is similar to the following.

        {
            "kind": "tm:sys:clock:clockstats",
            "selfLink": "https://localhost/mgmt/tm/sys/clock?ver=13.1.0.4",
            "entries": {
                "https://localhost/mgmt/tm/sys/clock/0": {
                    "nestedStats": {
                        "entries": {
                            "fullDate": {
                                "description": "2018-06-05T13:38:33Z"
                            }
                        }
                    }
                }
            }
        }

        Parsing this data using the ``parseStats`` method, yields a list of
        the clock stats in a format resembling that below.

        [{'fullDate': '2018-06-05T13:41:05Z'}]

        Therefore, this method cherry-picks the first entry from this list
        and returns it. There can be no other items in this list.

        Returns:
            A dict mapping keys to the corresponding clock stats. For
            example:

            {'fullDate': '2018-06-05T13:41:05Z'}

            There should never not be a clock stat, unless by chance it
            is removed from the API in the future, or changed to a different
            API endpoint.

        Raises:
            F5ModuleError: A non-successful HTTP code was returned or a JSON
                           response was not found.
        """
        uri = "https://{0}:{1}/mgmt/tm/sys/clock".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = parseStats(response)
        return result[0]

    def read_version_info_from_device(self):
        """Parses version info from the REST API

        The version stat returned from the REST API (at the time of 13.1.0.7)
        is similar to the following.

        {
            "kind": "tm:sys:version:versionstats",
            "selfLink": "https://localhost/mgmt/tm/sys/version?ver=13.1.0.4",
            "entries": {
                "https://localhost/mgmt/tm/sys/version/0": {
                    "nestedStats": {
                        "entries": {
                            "Build": {
                                "description": "0.0.6"
                            },
                            "Date": {
                                "description": "Tue Mar 13 20:10:42 PDT 2018"
                            },
                            "Edition": {
                                "description": "Point Release 4"
                            },
                            "Product": {
                                "description": "BIG-IP"
                            },
                            "Title": {
                                "description": "Main Package"
                            },
                            "Version": {
                                "description": "13.1.0.4"
                            }
                        }
                    }
                }
            }
        }

        Parsing this data using the ``parseStats`` method, yields a list of
        the clock stats in a format resembling that below.

        [{'Build': '0.0.6', 'Date': 'Tue Mar 13 20:10:42 PDT 2018',
          'Edition': 'Point Release 4', 'Product': 'BIG-IP', 'Title': 'Main Package',
          'Version': '13.1.0.4'}]

        Therefore, this method cherry-picks the first entry from this list
        and returns it. There can be no other items in this list.

        Returns:
            A dict mapping keys to the corresponding clock stats. For
            example:

            {'Build': '0.0.6', 'Date': 'Tue Mar 13 20:10:42 PDT 2018',
             'Edition': 'Point Release 4', 'Product': 'BIG-IP', 'Title': 'Main Package',
             'Version': '13.1.0.4'}

            There should never not be a version stat, unless by chance it
            is removed from the API in the future, or changed to a different
            API endpoint.

        Raises:
            F5ModuleError: A non-successful HTTP code was returned or a JSON
                           response was not found.
        """
        uri = "https://{0}:{1}/mgmt/tm/sys/version".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = parseStats(response)
        return result[0]


class TSParameters(BaseParameters):
    api_map = {
    }

    returnables = [

    ]


class TSFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        self.installed_packages = packages_installed(self.client)
        super(TSFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(ts_config=facts)
        return result

    def _exec_module(self):
        if 'ts' not in self.installed_packages:
            return []
        facts = self.read_facts()
        return facts

    def read_facts(self):
        collection = self.read_collection_from_device()
        return collection

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/shared/telemetry/declare".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'message' not in response:
            return []
        result = dict()
        result['declaration'] = response['declaration']
        return result


class TcpMonitorsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultsFrom': 'parent',
        'adaptiveDivergenceType': 'adaptive_divergence_type',
        'adaptiveDivergenceValue': 'adaptive_divergence_value',
        'adaptiveLimit': 'adaptive_limit',
        'adaptiveSamplingTimespan': 'adaptive_sampling_timespan',
        'ipDscp': 'ip_dscp',
        'manualResume': 'manual_resume',
        'timeUntilUp': 'time_until_up',
        'upInterval': 'up_interval',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'adaptive',
        'adaptive_divergence_type',
        'adaptive_divergence_value',
        'adaptive_limit',
        'adaptive_sampling_timespan',
        'destination',
        'interval',
        'ip_dscp',
        'manual_resume',
        'reverse',
        'time_until_up',
        'timeout',
        'transparent',
        'up_interval',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def transparent(self):
        return flatten_boolean(self._values['transparent'])

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])

    @property
    def adaptive(self):
        return flatten_boolean(self._values['adaptive'])

    @property
    def reverse(self):
        return flatten_boolean(self._values['reverse'])


class TcpMonitorsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(TcpMonitorsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(tcp_monitors=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = TcpMonitorsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/tcp".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class TcpHalfOpenMonitorsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultsFrom': 'parent',
        'manualResume': 'manual_resume',
        'timeUntilUp': 'time_until_up',
        'upInterval': 'up_interval',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'destination',
        'interval',
        'manual_resume',
        'time_until_up',
        'timeout',
        'transparent',
        'up_interval',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def transparent(self):
        return flatten_boolean(self._values['transparent'])

    @property
    def manual_resume(self):
        return flatten_boolean(self._values['manual_resume'])


class TcpHalfOpenMonitorsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(TcpHalfOpenMonitorsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(tcp_half_open_monitors=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = TcpHalfOpenMonitorsParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/monitor/tcp-half-open".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class TcpProfilesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'defaultsFrom': 'parent',
        'ackOnPush': 'ack_on_push',
        'autoProxyBufferSize': 'auto_proxy_buffer',
        'autoReceiveWindowSize': 'auto_receive_window',
        'autoSendBufferSize': 'auto_send_buffer',
        'closeWaitTimeout': 'close_wait',
        'cmetricsCache': 'congestion_metrics_cache',
        'cmetricsCacheTimeout': 'congestion_metrics_cache_timeout',
        'congestionControl': 'congestion_control',
        'deferredAccept': 'deferred_accept',
        'delayWindowControl': 'delay_window_control',
        'delayedAcks': 'delayed_acks',
        'earlyRetransmit': 'early_retransmit',
        'ecn': 'explicit_congestion_notification',
        'enhancedLossRecovery': 'enhanced_loss_recovery',
        'fastOpen': 'fast_open',
        'fastOpenCookieExpiration': 'fast_open_cookie_expiration',
        'finWaitTimeout': 'fin_wait_1',
        'finWait_2Timeout': 'fin_wait_2',
        'idleTimeout': 'idle_timeout',
        'initCwnd': 'initial_congestion_window_size',
        'initRwnd': 'initial_receive_window_size',
        'ipDfMode': 'dont_fragment_flag',
        'ipTosToClient': 'ip_tos',
        'ipTtlMode': 'time_to_live',
        'ipTtlV4': 'time_to_live_v4',
        'ipTtlV6': 'time_to_live_v6',
        'keepAliveInterval': 'keep_alive_interval',
        'limitedTransmit': 'limited_transmit_recovery',
        'linkQosToClient': 'link_qos',
        'maxRetrans': 'max_segment_retrans',
        'synMaxRetrans': 'max_syn_retrans',
        'rexmtThresh': 'retransmit_threshold',
        'maxSegmentSize': 'max_segment_size',
        'md5Signature': 'md5_signature',
        'minimumRto': 'minimum_rto',
        'mptcp': 'multipath_tcp',
        'mptcpCsum': 'mptcp_checksum',
        'mptcpCsumVerify': 'mptcp_checksum_verify',
        'mptcpFallback': 'mptcp_fallback',
        'mptcpFastjoin': 'mptcp_fast_join',
        'mptcpIdleTimeout': 'mptcp_idle_timeout',
        'mptcpJoinMax': 'mptcp_join_max',
        'mptcpMakeafterbreak': 'mptcp_make_after_break',
        'mptcpNojoindssack': 'mptcp_no_join_dss_ack',
        'mptcpRtomax': 'mptcp_rto_max',
        'mptcpRxmitmin': 'mptcp_retransmit_min',
        'mptcpSubflowmax': 'mptcp_subflow_max',
        'mptcpTimeout': 'mptcp_timeout',
        'nagle': 'nagle_algorithm',
        'pktLossIgnoreBurst': 'pkt_loss_ignore_burst',
        'pktLossIgnoreRate': 'pkt_loss_ignore_rate',
        'proxyBufferHigh': 'proxy_buffer_high',
        'proxyBufferLow': 'proxy_buffer_low',
        'proxyMss': 'proxy_max_segment',
        'proxyOptions': 'proxy_options',
        'pushFlag': 'push_flag',
        'ratePace': 'rate_pace',
        'ratePaceMaxRate': 'rate_pace_max_rate',
        'receiveWindowSize': 'receive_window',
        'resetOnTimeout': 'reset_on_timeout',
        'selectiveAcks': 'selective_acks',
        'selectiveNack': 'selective_nack',
        'sendBufferSize': 'send_buffer',
        'slowStart': 'slow_start',
        'synCookieEnable': 'syn_cookie_enable',
        'synCookieWhitelist': 'syn_cookie_white_list',
        'synRtoBase': 'syn_retrans_to_base',
        'tailLossProbe': 'tail_loss_probe',
        'timeWaitRecycle': 'time_wait_recycle',
        'timeWaitTimeout': 'time_wait',
        'verifiedAccept': 'verified_accept',
        'zeroWindowTimeout': 'zero_window_timeout',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'abc',
        'ack_on_push',
        'auto_proxy_buffer',
        'auto_receive_window',
        'auto_send_buffer',
        'close_wait',
        'congestion_metrics_cache',
        'congestion_metrics_cache_timeout',
        'congestion_control',
        'deferred_accept',
        'delay_window_control',
        'delayed_acks',
        'dsack',
        'early_retransmit',
        'explicit_congestion_notification',
        'enhanced_loss_recovery',
        'fast_open',
        'fast_open_cookie_expiration',
        'fin_wait_1',
        'fin_wait_2',
        'idle_timeout',
        'initial_congestion_window_size',
        'initial_receive_window_size',
        'dont_fragment_flag',
        'ip_tos',
        'time_to_live',
        'time_to_live_v4',
        'time_to_live_v6',
        'keep_alive_interval',
        'limited_transmit_recovery',
        'link_qos',
        'max_segment_retrans',
        'max_syn_retrans',
        'max_segment_size',
        'md5_signature',
        'minimum_rto',
        'multipath_tcp',
        'mptcp_checksum',
        'mptcp_checksum_verify',
        'mptcp_fallback',
        'mptcp_fast_join',
        'mptcp_idle_timeout',
        'mptcp_join_max',
        'mptcp_make_after_break',
        'mptcp_no_join_dss_ack',
        'mptcp_rto_max',
        'mptcp_retransmit_min',
        'mptcp_subflow_max',
        'mptcp_timeout',
        'nagle_algorithm',
        'pkt_loss_ignore_burst',
        'pkt_loss_ignore_rate',
        'proxy_buffer_high',
        'proxy_buffer_low',
        'proxy_max_segment',
        'proxy_options',
        'push_flag',
        'rate_pace',
        'rate_pace_max_rate',
        'receive_window',
        'reset_on_timeout',
        'retransmit_threshold',
        'selective_acks',
        'selective_nack',
        'send_buffer',
        'slow_start',
        'syn_cookie_enable',
        'syn_cookie_white_list',
        'syn_retrans_to_base',
        'tail_loss_probe',
        'time_wait_recycle',
        'time_wait',
        'timestamps',
        'verified_accept',
        'zero_window_timeout',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def time_wait(self):
        if self._values['time_wait'] is None:
            return None
        if self._values['time_wait'] == 0:
            return "immediate"
        if self._values['time_wait'] == 4294967295:
            return 'indefinite'
        return self._values['time_wait']

    @property
    def close_wait(self):
        if self._values['close_wait'] is None:
            return None
        if self._values['close_wait'] == 0:
            return "immediate"
        if self._values['close_wait'] == 4294967295:
            return 'indefinite'
        return self._values['close_wait']

    @property
    def fin_wait_1(self):
        if self._values['fin_wait_1'] is None:
            return None
        if self._values['fin_wait_1'] == 0:
            return "immediate"
        if self._values['fin_wait_1'] == 4294967295:
            return 'indefinite'
        return self._values['fin_wait_1']

    @property
    def fin_wait_2(self):
        if self._values['fin_wait_2'] is None:
            return None
        if self._values['fin_wait_2'] == 0:
            return "immediate"
        if self._values['fin_wait_2'] == 4294967295:
            return 'indefinite'
        return self._values['fin_wait_2']

    @property
    def zero_window_timeout(self):
        if self._values['zero_window_timeout'] is None:
            return None
        if self._values['zero_window_timeout'] == 4294967295:
            return 'indefinite'
        return self._values['zero_window_timeout']

    @property
    def idle_timeout(self):
        if self._values['idle_timeout'] is None:
            return None
        if self._values['idle_timeout'] == 4294967295:
            return 'indefinite'
        return self._values['idle_timeout']

    @property
    def keep_alive_interval(self):
        if self._values['keep_alive_interval'] is None:
            return None
        if self._values['keep_alive_interval'] == 4294967295:
            return 'indefinite'
        return self._values['keep_alive_interval']

    @property
    def verified_accept(self):
        return flatten_boolean(self._values['verified_accept'])

    @property
    def timestamps(self):
        return flatten_boolean(self._values['timestamps'])

    @property
    def time_wait_recycle(self):
        return flatten_boolean(self._values['time_wait_recycle'])

    @property
    def tail_loss_probe(self):
        return flatten_boolean(self._values['tail_loss_probe'])

    @property
    def syn_cookie_white_list(self):
        return flatten_boolean(self._values['syn_cookie_white_list'])

    @property
    def syn_cookie_enable(self):
        return flatten_boolean(self._values['syn_cookie_enable'])

    @property
    def slow_start(self):
        return flatten_boolean(self._values['slow_start'])

    @property
    def selective_nack(self):
        return flatten_boolean(self._values['selective_nack'])

    @property
    def selective_acks(self):
        return flatten_boolean(self._values['selective_acks'])

    @property
    def reset_on_timeout(self):
        return flatten_boolean(self._values['reset_on_timeout'])

    @property
    def rate_pace(self):
        return flatten_boolean(self._values['rate_pace'])

    @property
    def proxy_options(self):
        return flatten_boolean(self._values['proxy_options'])

    @property
    def proxy_max_segment(self):
        return flatten_boolean(self._values['proxy_max_segment'])

    @property
    def nagle_algorithm(self):
        return flatten_boolean(self._values['nagle_algorithm'])

    @property
    def mptcp_no_join_dss_ack(self):
        return flatten_boolean(self._values['mptcp_no_join_dss_ack'])

    @property
    def mptcp_make_after_break(self):
        return flatten_boolean(self._values['mptcp_make_after_break'])

    @property
    def mptcp_fast_join(self):
        return flatten_boolean(self._values['mptcp_fast_join'])

    @property
    def mptcp_checksum_verify(self):
        return flatten_boolean(self._values['mptcp_checksum_verify'])

    @property
    def mptcp_checksum(self):
        return flatten_boolean(self._values['mptcp_checksum'])

    @property
    def multipath_tcp(self):
        return flatten_boolean(self._values['multipath_tcp'])

    @property
    def md5_signature(self):
        return flatten_boolean(self._values['md5_signature'])

    @property
    def limited_transmit_recovery(self):
        return flatten_boolean(self._values['limited_transmit_recovery'])

    @property
    def fast_open(self):
        return flatten_boolean(self._values['fast_open'])

    @property
    def enhanced_loss_recovery(self):
        return flatten_boolean(self._values['enhanced_loss_recovery'])

    @property
    def explicit_congestion_notification(self):
        return flatten_boolean(self._values['explicit_congestion_notification'])

    @property
    def early_retransmit(self):
        return flatten_boolean(self._values['early_retransmit'])

    @property
    def dsack(self):
        return flatten_boolean(self._values['dsack'])

    @property
    def delayed_acks(self):
        return flatten_boolean(self._values['delayed_acks'])

    @property
    def delay_window_control(self):
        return flatten_boolean(self._values['delay_window_control'])

    @property
    def deferred_accept(self):
        return flatten_boolean(self._values['deferred_accept'])

    @property
    def congestion_metrics_cache(self):
        return flatten_boolean(self._values['congestion_metrics_cache'])

    @property
    def auto_send_buffer(self):
        return flatten_boolean(self._values['auto_send_buffer'])

    @property
    def auto_receive_window(self):
        return flatten_boolean(self._values['auto_receive_window'])

    @property
    def auto_proxy_buffer(self):
        return flatten_boolean(self._values['auto_proxy_buffer'])

    @property
    def abc(self):
        return flatten_boolean(self._values['abc'])

    @property
    def ack_on_push(self):
        return flatten_boolean(self._values['ack_on_push'])


class TcpProfilesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(TcpProfilesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(tcp_profiles=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = TcpProfilesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/tcp".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class TrafficGroupsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'autoFailbackEnabled': 'auto_failback_enabled',
        'autoFailbackTime': 'auto_failback_time',
        'haLoadFactor': 'ha_load_factor',
        'haOrder': 'ha_order',
        'isFloating': 'is_floating',
        'mac': 'mac_masquerade_address'
    }

    returnables = [
        'full_path',
        'name',
        'description',
        'auto_failback_enabled',
        'auto_failback_time',
        'ha_load_factor',
        'ha_order',
        'is_floating',
        'mac_masquerade_address'
    ]

    @property
    def auto_failback_time(self):
        if self._values['auto_failback_time'] is None:
            return None
        return int(self._values['auto_failback_time'])

    @property
    def auto_failback_enabled(self):
        if self._values['auto_failback_enabled'] is None:
            return None
        elif self._values['auto_failback_enabled'] == 'false':
            # Yes, the REST API stores this as a string
            return 'no'
        return 'yes'

    @property
    def is_floating(self):
        if self._values['is_floating'] is None:
            return None
        elif self._values['is_floating'] == 'true':
            # Yes, the REST API stores this as a string
            return 'yes'
        return 'no'

    @property
    def mac_masquerade_address(self):
        if self._values['mac_masquerade_address'] in [None, 'none']:
            return None
        return self._values['mac_masquerade_address']


class TrafficGroupsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(TrafficGroupsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(traffic_groups=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            attrs = resource
            attrs['stats'] = self.read_stats_from_device(attrs['fullPath'])
            params = TrafficGroupsParameters(params=attrs)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/cm/traffic-group".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result

    def read_stats_from_device(self, full_path):
        uri = "https://{0}:{1}/mgmt/tm/cm/traffic-group/{2}/stats".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=full_path)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = parseStats(response)
        try:
            return result['stats']
        except KeyError:
            return {}


class TrunksParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'media': 'media_speed',
        'lacpMode': 'lacp_mode',
        'lacp': 'lacp_state',
        'lacpTimeout': 'lacp_timeout',
        'stp': 'stp_enabled',
        'workingMbrCount': 'operational_member_count',
        'linkSelectPolicy': 'link_selection_policy',
        'distributionHash': 'distribution_hash',
        'cfgMbrCount': 'configured_member_count'
    }

    returnables = [
        'full_path',
        'name',
        'description',
        'media_speed',
        'lacp_mode',  # 'active' or 'passive'
        'lacp_enabled',
        'stp_enabled',
        'operational_member_count',
        'media_status',
        'link_selection_policy',
        'lacp_timeout',
        'interfaces',
        'distribution_hash',
        'configured_member_count'
    ]

    @property
    def lacp_enabled(self):
        if self._values['lacp_enabled'] is None:
            return None
        elif self._values['lacp_enabled'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def stp_enabled(self):
        if self._values['stp_enabled'] is None:
            return None
        elif self._values['stp_enabled'] == 'disabled':
            return 'no'
        return 'yes'

    @property
    def media_status(self):
        return self._values['stats']['status']


class TrunksFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(TrunksFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(trunks=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            attrs = resource
            attrs['stats'] = self.read_stats_from_device(attrs['fullPath'])
            params = TrunksParameters(params=attrs)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/net/trunk".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}".format(self.module.params['data_increment'], skip)
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result

    def read_stats_from_device(self, full_path):
        uri = "https://{0}:{1}/mgmt/tm/net/trunk/{2}/stats".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=full_path)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        result = parseStats(response)
        try:
            return result['stats']
        except KeyError:
            return {}


class UCSParameters(BaseParameters):
    api_map = {
        'filename': 'file_name',
        'encrypted': 'encrypted',
        'file_size': 'file_size',
        'apiRawValues': 'variables'
    }

    returnables = [
        'file_name',
        'encrypted',
        'file_size',
        'file_created_date'
    ]

    @property
    def file_name(self):
        name = self._values['variables']['filename'].split("/")[-1]
        return name

    @property
    def encrypted(self):
        return self._values['variables']['encrypted']

    @property
    def file_size(self):
        val = self._values['variables']['file_size']
        size = re.findall(r'\d+', val)[0]
        return size

    @property
    def file_created_date(self):
        date = self._values['variables']['file_created_date']
        return date


class UCSFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(UCSFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(ucs_files=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['file_name'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            attrs = resource
            params = UCSParameters(params=attrs)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/sys/ucs".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}".format(self.module.params['data_increment'], skip)
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class UsersParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'partitionAccess': 'partition_access',
    }

    returnables = [
        'full_path',
        'name',
        'description',
        'partition_access',
        'shell',
    ]

    @property
    def partition_access(self):
        result = []
        if self._values['partition_access'] is None:
            return []
        for partition in self._values['partition_access']:
            del partition['nameReference']
            result.append(partition)
        return result

    @property
    def shell(self):
        if self._values['shell'] in [None, 'none']:
            return None
        return self._values['shell']


class UsersFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(UsersFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(users=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            attrs = resource
            params = UsersParameters(params=attrs)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/auth/user".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class UdpProfilesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'allowNoPayload': 'allow_no_payload',
        'bufferMaxBytes': 'buffer_max_bytes',
        'bufferMaxPackets': 'buffer_max_packets',
        'datagramLoadBalancing': 'datagram_load_balancing',
        'defaultsFrom': 'parent',
        'idleTimeout': 'idle_timeout',
        'ipDfMode': 'ip_df_mode',
        'ipTosToClient': 'ip_tos_to_client',
        'ipTtlMode': 'ip_ttl_mode',
        'ipTtlV4': 'ip_ttl_v4',
        'ipTtlV6': 'ip_ttl_v6',
        'linkQosToClient': 'link_qos_to_client',
        'noChecksum': 'no_checksum',
        'proxyMss': 'proxy_mss',
    }

    returnables = [
        'full_path',
        'name',
        'parent',
        'description',
        'allow_no_payload',
        'buffer_max_bytes',
        'buffer_max_packets',
        'datagram_load_balancing',
        'idle_timeout',
        'ip_df_mode',
        'ip_tos_to_client',
        'ip_ttl_mode',
        'ip_ttl_v4',
        'ip_ttl_v6',
        'link_qos_to_client',
        'no_checksum',
        'proxy_mss',
    ]

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']

    @property
    def allow_no_payload(self):
        return flatten_boolean(self._values['allow_no_payload'])

    @property
    def datagram_load_balancing(self):
        return flatten_boolean(self._values['datagram_load_balancing'])

    @property
    def proxy_mss(self):
        return flatten_boolean(self._values['proxy_mss'])

    @property
    def no_checksum(self):
        return flatten_boolean(self._values['no_checksum'])


class UdpProfilesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(UdpProfilesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(udp_profiles=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = UdpProfilesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/udp".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class VcmpGuestsParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'allowedSlots': 'allowed_slots',
        'assignedSlots': 'assigned_slots',
        'bootPriority': 'boot_priority',
        'coresPerSlot': 'cores_per_slot',
        'initialImage': 'initial_image',
        'initialHotfix': 'hotfix_image',
        'managementGw': 'mgmt_route',
        'managementIp': 'mgmt_address',
        'managementNetwork': 'mgmt_network',
        'minSlots': 'min_number_of_slots',
        'slots': 'number_of_slots',
        'sslMode': 'ssl_mode',
        'virtualDisk': 'virtual_disk'
    }

    returnables = [
        'name',
        'full_path',
        'allowed_slots',
        'assigned_slots',
        'boot_priority',
        'cores_per_slot',
        'hostname',
        'hotfix_image',
        'initial_image',
        'mgmt_route',
        'mgmt_address',
        'mgmt_network',
        'vlans',
        'min_number_of_slots',
        'number_of_slots',
        'ssl_mode',
        'state',
        'virtual_disk',
    ]


class VcmpGuestsFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(VcmpGuestsFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(vcmp_guests=facts)
        return result

    def _exec_module(self):
        if 'vcmp' not in self.provisioned_modules:
            return []
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = VcmpGuestsParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/vcmp/guest".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class VirtualAddressesParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'arp': 'arp_enabled',
        'autoDelete': 'auto_delete_enabled',
        'connectionLimit': 'connection_limit',
        'icmpEcho': 'icmp_echo',
        'mask': 'netmask',
        'routeAdvertisement': 'route_advertisement',
        'trafficGroup': 'traffic_group',
        'inheritedTrafficGroup': 'inherited_traffic_group'
    }

    returnables = [
        'full_path',
        'name',
        'address',
        'arp_enabled',
        'auto_delete_enabled',
        'connection_limit',
        'description',
        'enabled',
        'icmp_echo',
        'floating',
        'netmask',
        'route_advertisement',
        'traffic_group',
        'spanning',
        'inherited_traffic_group'
    ]

    @property
    def spanning(self):
        return flatten_boolean(self._values['spanning'])

    @property
    def arp_enabled(self):
        return flatten_boolean(self._values['arp_enabled'])

    @property
    def route_advertisement(self):
        return flatten_boolean(self._values['route_advertisement'])

    @property
    def auto_delete_enabled(self):
        return flatten_boolean(self._values['auto_delete_enabled'])

    @property
    def inherited_traffic_group(self):
        return flatten_boolean(self._values['inherited_traffic_group'])

    @property
    def icmp_echo(self):
        return flatten_boolean(self._values['icmp_echo'])

    @property
    def floating(self):
        return flatten_boolean(self._values['floating'])

    @property
    def enabled(self):
        return flatten_boolean(self._values['enabled'])


class VirtualAddressesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(VirtualAddressesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(virtual_addresses=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            params = VirtualAddressesParameters(params=resource)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/virtual-address".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class VirtualServersParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
        'autoLasthop': 'auto_lasthop',
        'bwcPolicy': 'bw_controller_policy',
        'cmpEnabled': 'cmp_enabled',
        'connectionLimit': 'connection_limit',
        'fallbackPersistence': 'fallback_persistence_profile',
        'persist': 'persistence_profile',
        'translatePort': 'translate_port',
        'translateAddress': 'translate_address',
        'lastHopPool': 'last_hop_pool',
        'nat64': 'nat64_enabled',
        'sourcePort': 'source_port_behavior',
        'ipIntelligencePolicy': 'ip_intelligence_policy',
        'ipProtocol': 'protocol',
        'pool': 'default_pool',
        'rateLimitMode': 'rate_limit_mode',
        'rateLimitSrcMask': 'rate_limit_source_mask',
        'rateLimitDstMask': 'rate_limit_destination_mask',
        'rateLimit': 'rate_limit',
        'serversslUseSni': 'serverssl_use_sni',
        'sourceAddressTranslation': 'snat_type',
        'gtmScore': 'gtm_score',
        'rateClass': 'rate_class',
        'source': 'source_address',
        'auth': 'authentication_profile',
        'mirror': 'connection_mirror_enabled',
        'rules': 'irules',
        'securityLogProfiles': 'security_log_profiles',
        'profilesReference': 'profiles',
        'policiesReference': 'policies',
        'perFlowRequestAccessPolicy': 'per_flow_request_access_policy',
    }

    returnables = [
        'full_path',
        'name',
        'auto_lasthop',
        'bw_controller_policy',
        'cmp_enabled',
        'connection_limit',
        'description',
        'enabled',
        'fallback_persistence_profile',
        'persistence_profile',
        'translate_port',
        'translate_address',
        'vlans',
        'destination',
        'last_hop_pool',
        'nat64_enabled',
        'source_port_behavior',
        'ip_intelligence_policy',
        'protocol',
        'default_pool',
        'rate_limit_mode',
        'rate_limit_source_mask',
        'rate_limit',
        'snat_type',
        'snat_pool',
        'serverssl_use_sni',
        'gtm_score',
        'rate_class',
        'rate_limit_destination_mask',
        'source_address',
        'authentication_profile',
        'connection_mirror_enabled',
        'irules',
        'security_log_profiles',
        'type',
        'policies',
        'profiles',
        'per_flow_request_access_policy',
        'destination_address',
        'destination_port',
        'availability_status',
        'status_reason',
        'total_requests',
        'client_side_bits_in',
        'client_side_bits_out',
        'client_side_current_connections',
        'client_side_evicted_connections',
        'client_side_max_connections',
        'client_side_pkts_in',
        'client_side_pkts_out',
        'client_side_slow_killed',
        'client_side_total_connections',
        'cmp_mode',
        'ephemeral_bits_in',
        'ephemeral_bits_out',
        'ephemeral_current_connections',
        'ephemeral_evicted_connections',
        'ephemeral_max_connections',
        'ephemeral_pkts_in',
        'ephemeral_pkts_out',
        'ephemeral_slow_killed',
        'ephemeral_total_connections',
        'total_software_accepted_syn_cookies',
        'total_hardware_accepted_syn_cookies',
        'total_hardware_syn_cookies',
        'hardware_syn_cookie_instances',
        'total_software_rejected_syn_cookies',
        'software_syn_cookie_instances',
        'current_syn_cache',
        'syn_cache_overflow',
        'total_software_syn_cookies',
        'syn_cookies_status',
        'max_conn_duration',
        'mean_conn_duration',
        'min_conn_duration',
        'cpu_usage_ratio_last_5_min',
        'cpu_usage_ratio_last_5_sec',
        'cpu_usage_ratio_last_1_min',
    ]

    @property
    def max_conn_duration(self):
        return self._values['stats']['csMaxConnDur']

    @property
    def mean_conn_duration(self):
        return self._values['stats']['csMeanConnDur']

    @property
    def min_conn_duration(self):
        return self._values['stats']['csMinConnDur']

    @property
    def cpu_usage_ratio_last_5_min(self):
        return self._values['stats']['fiveMinAvgUsageRatio']

    @property
    def cpu_usage_ratio_last_5_sec(self):
        return self._values['stats']['fiveSecAvgUsageRatio']

    @property
    def cpu_usage_ratio_last_1_min(self):
        return self._values['stats']['oneMinAvgUsageRatio']

    @property
    def cmp_mode(self):
        return self._values['stats']['cmpEnableMode']

    @property
    def availability_status(self):
        return self._values['stats']['status']['availabilityState']

    @property
    def status_reason(self):
        return self._values['stats']['status']['statusReason']

    @property
    def total_requests(self):
        return self._values['stats']['totRequests']

    @property
    def ephemeral_bits_in(self):
        return self._values['stats']['ephemeral']['bitsIn']

    @property
    def ephemeral_bits_out(self):
        return self._values['stats']['ephemeral']['bitsOut']

    @property
    def ephemeral_current_connections(self):
        return self._values['stats']['ephemeral']['curConns']

    @property
    def ephemeral_evicted_connections(self):
        return self._values['stats']['ephemeral']['evictedConns']

    @property
    def ephemeral_max_connections(self):
        return self._values['stats']['ephemeral']['maxConns']

    @property
    def ephemeral_pkts_in(self):
        return self._values['stats']['ephemeral']['pktsIn']

    @property
    def ephemeral_pkts_out(self):
        return self._values['stats']['ephemeral']['pktsOut']

    @property
    def ephemeral_slow_killed(self):
        return self._values['stats']['ephemeral']['slowKilled']

    @property
    def ephemeral_total_connections(self):
        return self._values['stats']['ephemeral']['totConns']

    @property
    def client_side_bits_in(self):
        return self._values['stats']['clientside']['bitsIn']

    @property
    def client_side_bits_out(self):
        return self._values['stats']['clientside']['bitsOut']

    @property
    def client_side_current_connections(self):
        return self._values['stats']['clientside']['curConns']

    @property
    def client_side_evicted_connections(self):
        return self._values['stats']['clientside']['evictedConns']

    @property
    def client_side_max_connections(self):
        return self._values['stats']['clientside']['maxConns']

    @property
    def client_side_pkts_in(self):
        return self._values['stats']['clientside']['pktsIn']

    @property
    def client_side_pkts_out(self):
        return self._values['stats']['clientside']['pktsOut']

    @property
    def client_side_slow_killed(self):
        return self._values['stats']['clientside']['slowKilled']

    @property
    def client_side_total_connections(self):
        return self._values['stats']['clientside']['totConns']

    @property
    def total_software_accepted_syn_cookies(self):
        return self._values['stats']['syncookie']['accepts']

    @property
    def total_hardware_accepted_syn_cookies(self):
        return self._values['stats']['syncookie']['hwAccepts']

    @property
    def total_hardware_syn_cookies(self):
        return self._values['stats']['syncookie']['hwSyncookies']

    @property
    def hardware_syn_cookie_instances(self):
        return self._values['stats']['syncookie']['hwsyncookieInstance']

    @property
    def total_software_rejected_syn_cookies(self):
        return self._values['stats']['syncookie']['rejects']

    @property
    def software_syn_cookie_instances(self):
        return self._values['stats']['syncookie']['swsyncookieInstance']

    @property
    def current_syn_cache(self):
        return self._values['stats']['syncookie']['syncacheCurr']

    @property
    def syn_cache_overflow(self):
        return self._values['stats']['syncookie']['syncacheOver']

    @property
    def total_software_syn_cookies(self):
        return self._values['stats']['syncookie']['syncookies']

    @property
    def syn_cookies_status(self):
        return self._values['stats']['syncookieStatus']

    @property
    def destination_address(self):
        if self._values['destination'] is None:
            return None
        tup = self.destination_tuple
        return tup.ip

    @property
    def destination_port(self):
        if self._values['destination'] is None:
            return None
        tup = self.destination_tuple
        return tup.port

    @property
    def type(self):
        """Attempt to determine the current server type

        This check is very unscientific. It turns out that this information is not
        exactly available anywhere on a BIG-IP. Instead, we rely on a semi-reliable
        means for determining what the type of the virtual server is. Hopefully it
        always works.

        There are a handful of attributes that can be used to determine a specific
        type. There are some types though that can only be determined by looking at
        the profiles that are assigned to them. We follow that method for those
        complicated types; message-routing, fasthttp, and fastl4.

        Because type determination is an expensive operation, we cache the result
        from the operation.

        Returns:
            string: The server type.
        """
        if self._values['l2Forward'] is True:
            result = 'forwarding-l2'
        elif self._values['ipForward'] is True:
            result = 'forwarding-ip'
        elif self._values['stateless'] is True:
            result = 'stateless'
        elif self._values['reject'] is True:
            result = 'reject'
        elif self._values['dhcpRelay'] is True:
            result = 'dhcp'
        elif self._values['internal'] is True:
            result = 'internal'
        elif self.has_fasthttp_profiles:
            result = 'performance-http'
        elif self.has_fastl4_profiles:
            result = 'performance-l4'
        elif self.has_message_routing_profiles:
            result = 'message-routing'
        else:
            result = 'standard'
        return result

    @property
    def profiles(self):
        """Returns a list of profiles from the API

        The profiles are formatted so that they are usable in this module and
        are able to be compared by the Difference engine.

        Returns:
             list (:obj:`list` of :obj:`dict`): List of profiles.

             Each dictionary in the list contains the following three (3) keys.

             * name
             * context
             * fullPath

        Raises:
            F5ModuleError: If the specified context is a value other that
                ``all``, ``server-side``, or ``client-side``.
        """
        if 'items' not in self._values['profiles']:
            return None
        result = []
        for item in self._values['profiles']['items']:
            context = item['context']
            if context == 'serverside':
                context = 'server-side'
            elif context == 'clientside':
                context = 'client-side'
            name = item['name']
            if context in ['all', 'server-side', 'client-side']:
                result.append(dict(name=name, context=context, full_path=item['fullPath']))
            else:
                raise F5ModuleError(
                    "Unknown profile context found: '{0}'".format(context)
                )
        return result

    @property
    def has_message_routing_profiles(self):
        if self.profiles is None:
            return None
        current = self._read_current_message_routing_profiles_from_device()
        result = [x['name'] for x in self.profiles if x['name'] in current]
        if len(result) > 0:
            return True
        return False

    @property
    def has_fastl4_profiles(self):
        if self.profiles is None:
            return None
        current = self._read_current_fastl4_profiles_from_device()
        result = [x['name'] for x in self.profiles if x['name'] in current]
        if len(result) > 0:
            return True
        return False

    @property
    def has_fasthttp_profiles(self):
        """Check if ``fasthttp`` profile is in API profiles

        This method is used to determine the server type when doing comparisons
        in the Difference class.

        Returns:
             bool: True if server has ``fasthttp`` profiles. False otherwise.
        """
        if self.profiles is None:
            return None
        current = self._read_current_fasthttp_profiles_from_device()
        result = [x['name'] for x in self.profiles if x['name'] in current]
        if len(result) > 0:
            return True
        return False

    def _read_current_message_routing_profiles_from_device(self):
        result = []
        result += self._read_diameter_profiles_from_device()
        result += self._read_sip_profiles_from_device()
        return result

    def _read_diameter_profiles_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/diameter/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = [x['name'] for x in response['items']]
        return result

    def _read_sip_profiles_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/sip/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = [x['name'] for x in response['items']]
        return result

    def _read_current_fastl4_profiles_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/fastl4/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)
        result = [x['name'] for x in response['items']]
        return result

    def _read_current_fasthttp_profiles_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/fasthttp/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = [x['name'] for x in response['items']]
        return result

    @property
    def security_log_profiles(self):
        if self._values['security_log_profiles'] is None:
            return None
        result = list(set([x.strip('"') for x in self._values['security_log_profiles']]))
        result.sort()
        return result

    @property
    def snat_type(self):
        if self._values['snat_type'] is None:
            return None
        if 'type' in self._values['snat_type']:
            if self._values['snat_type']['type'] == 'automap':
                return 'automap'
            elif self._values['snat_type']['type'] == 'none':
                return 'none'
            elif self._values['snat_type']['type'] == 'snat':
                return 'snat'

    @property
    def snat_pool(self):
        if self._values['snat_type'] is None:
            return None
        if 'type' in self._values['snat_type']:
            if self._values['snat_type']['type'] == 'automap':
                return 'none'
            elif self._values['snat_type']['type'] == 'none':
                return 'none'
            elif self._values['snat_type']['type'] == 'snat':
                return self._values['snat_type']["pool"]

    @property
    def serverssl_use_sni(self):
        if self._values['serverssl_use_sni'] is None:
            return None
        if self._values['serverssl_use_sni'] == 'enabled':
            return 'enabled'
        return 'disabled'

    @property
    def connection_mirror_enabled(self):
        if self._values['connection_mirror_enabled'] is None:
            return None
        elif self._values['connection_mirror_enabled'] == 'enabled':
            return 'yes'
        return 'no'

    @property
    def rate_limit(self):
        if self._values['rate_limit'] is None:
            return None
        elif self._values['rate_limit'] == 'disabled':
            return -1
        return int(self._values['rate_limit'])

    @property
    def nat64_enabled(self):
        if self._values['nat64_enabled'] is None:
            return None
        elif self._values['nat64_enabled'] == 'enabled':
            return 'yes'
        return 'no'

    @property
    def enabled(self):
        if self._values['enabled'] is None:
            return 'no'
        elif self._values['enabled'] is True:
            return 'yes'
        return 'no'

    @property
    def translate_port(self):
        if self._values['translate_port'] is None:
            return None
        elif self._values['translate_port'] == 'enabled':
            return 'yes'
        return 'no'

    @property
    def translate_address(self):
        if self._values['translate_address'] is None:
            return None
        elif self._values['translate_address'] == 'enabled':
            return 'yes'
        return 'no'

    @property
    def persistence_profile(self):
        """Return persistence profile in a consumable form

        I don't know why the persistence profile is stored this way, but below is the
        general format of it.

            "persist": [
                {
                    "name": "msrdp",
                    "partition": "Common",
                    "tmDefault": "yes",
                    "nameReference": {
                        "link": "https://localhost/mgmt/tm/ltm/persistence/msrdp/~Common~msrdp?ver=13.1.0.4"
                    }
                }
            ],

        As you can see, this is quite different from something like the fallback
        persistence profile which is just simply

            /Common/fallback1

        This method makes the persistence profile look like the fallback profile.

        Returns:
             string: The persistence profile configured on the virtual.
        """
        if self._values['persistence_profile'] is None:
            return None
        profile = self._values['persistence_profile'][0]
        result = fq_name(profile['partition'], profile['name'])
        return result

    @property
    def destination_tuple(self):
        Destination = namedtuple('Destination', ['ip', 'port', 'route_domain', 'mask'])

        # Remove the partition
        if self._values['destination'] is None:
            result = Destination(ip=None, port=None, route_domain=None, mask=None)
            return result
        destination = re.sub(r'^/[a-zA-Z0-9_.-]+/([a-zA-Z0-9_.-]+\/)?', '', self._values['destination'])
        # Covers the following examples
        #
        # /Common/2700:bc00:1f10:101::6%2.80
        # 2700:bc00:1f10:101::6%2.80
        # 1.1.1.1%2:80
        # /Common/1.1.1.1%2:80
        # /Common/2700:bc00:1f10:101::6%2.any
        # /Common/Shared/1.1.1.1:80
        #
        pattern = r'(?P<ip>[^%]+)%(?P<route_domain>[0-9]+)[:.](?P<port>[0-9]+|any)'
        matches = re.search(pattern, destination)
        if matches:
            try:
                port = int(matches.group('port'))
            except ValueError:
                # Can be a port of "any". This only happens with IPv6
                port = matches.group('port')
                if port == 'any':
                    port = 0
            result = Destination(
                ip=matches.group('ip'),
                port=port,
                route_domain=int(matches.group('route_domain')),
                mask=self.mask
            )
            return result

        pattern = r'(?P<ip>[^%]+)%(?P<route_domain>[0-9]+)'
        matches = re.search(pattern, destination)
        if matches:
            result = Destination(
                ip=matches.group('ip'),
                port=None,
                route_domain=int(matches.group('route_domain')),
                mask=self.mask
            )
            return result

        # this will match any IPV4 Address and port, no RD
        pattern = r'^(?P<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]' \
                  r'[0-9]|25[0-5])):(?P<port>[0-9]+)'

        matches = re.search(pattern, destination)
        if matches:
            result = Destination(
                ip=matches.group('ip'),
                port=int(matches.group('port')),
                route_domain=None,
                mask=self.mask
            )
            return result

        # match standalone IPV6 address, no port
        pattern = r'^([0-9a-f]{0,4}:){2,7}(:|[0-9a-f]{1,4})$'
        matches = re.search(pattern, destination)
        if matches:
            result = Destination(
                ip=destination,
                port=None,
                route_domain=None,
                mask=self.mask
            )
            return result

        # match IPV6 address with port
        pattern = r'(?P<ip>([0-9a-f]{0,4}:){2,7}(:|[0-9a-f]{1,4}).(?P<port>[0-9]+|any))'
        matches = re.search(pattern, destination)
        if matches:
            ip = matches.group('ip').split('.')[0]
            try:
                port = int(matches.group('port'))
            except ValueError:
                # Can be a port of "any". This only happens with IPv6
                port = matches.group('port')
                if port == 'any':
                    port = 0
            result = Destination(
                ip=ip,
                port=port,
                route_domain=None,
                mask=self.mask
            )
            return result

        # this will match any alphanumeric Virtual Address and port
        pattern = r'(?P<name>^[a-zA-Z0-9_.-]+):(?P<port>[0-9]+)'
        matches = re.search(pattern, destination)
        if matches:
            result = Destination(
                ip=matches.group('name'),
                port=int(matches.group('port')),
                route_domain=None,
                mask=self.mask
            )
            return result

        # this will match any alphanumeric Virtual Address
        pattern = r'(?P<name>^[a-zA-Z0-9_.-]+)'
        matches = re.search(pattern, destination)
        if matches:
            result = Destination(
                ip=matches.group('name'),
                port=None,
                route_domain=None,
                mask=self.mask
            )
            return result

        # match IPv6 wildcard with port without RD
        pattern = r'(?P<ip>[^.]+).(?P<port>[0-9]+|any)'
        matches = re.search(pattern, destination)
        if matches:
            result = Destination(
                ip=matches.group('ip'),
                port=matches.group('port'),
                route_domain=None,
                mask=self.mask
            )
            return result

        result = Destination(ip=None, port=None, route_domain=None, mask=None)
        return result

    @property
    def policies(self):
        if 'items' not in self._values['policies']:
            return None
        results = []
        for item in self._values['policies']['items']:
            results.append(item['fullPath'])
        return results


# import logging
# import tempfile
import concurrent.futures

# Add a logger for debugging to a temp file
# temp_log = tempfile.NamedTemporaryFile(delete=False, mode='a', prefix='f5_bigip_device_info_', suffix='.log')
# logger = logging.getLogger("f5_bigip_device_info")
# logger.setLevel(logging.DEBUG)
# handler = logging.StreamHandler(temp_log)
# formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s')
# handler.setFormatter(formatter)
# if not logger.hasHandlers():
#     logger.addHandler(handler)


class VirtualServersFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(VirtualServersFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(virtual_servers=facts)
        return result

    def _exec_module(self):
        # results = []
        results = self.read_facts()
        # for item in results:
        #     attrs = item.to_return()
        #     logger.debug("Item attrs: %s", attrs)
        #     results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()

        # Prepare a mapping of fullPath to resource
        fullpath_to_resource = {resource['fullPath']: resource for resource in collection}

        # Run read_stats_from_device concurrently for all fullPaths
        stats_results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            future_to_fullpath = {
                executor.submit(self.read_stats_from_device, full_path): full_path
                for full_path in fullpath_to_resource
            }
            for future in concurrent.futures.as_completed(future_to_fullpath):
                full_path = future_to_fullpath[future]
                try:
                    stats_results[full_path] = future.result()
                except Exception as exc:
                    stats_results[full_path] = {}

        # Helper function for concurrent resource param creation
        def process_resource(full_path, resource):
            resource['stats'] = stats_results.get(full_path, {})
            params = VirtualServersParameters(client=self.client, params=resource)
            return params.to_return()

        # Run param creation concurrently as well
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            future_to_fullpath = {
                executor.submit(process_resource, full_path, resource): full_path
                for full_path, resource in fullpath_to_resource.items()
            }
            for future in concurrent.futures.as_completed(future_to_fullpath):
                try:
                    results.append(future.result())
                except Exception as exc:
                    full_path = future_to_fullpath[future]
        return results
    # def read_facts(self):
    #     logger.debug("Reading facts in VirtualServersFactManager")
    #     results = []
    #     collection = self.increment_read()
    #     logger.debug("Collection increment_read returned %d items", len(collection))
    #     for resource in collection:
    #         attrs = resource
    #         logger.debug("Processing resource: %s", attrs.get('fullPath', 'N/A'))
    #         attrs['stats'] = self.read_stats_from_device(attrs['fullPath'])
    #         params = VirtualServersParameters(client=self.client, params=attrs)
    #         results.append(params.to_return())
    #         logger.debug("Read Item resource:{}".format(len(results)))
    #     logger.debug("Returning %d fact objects", len(results))
    #     return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/ltm/virtual".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        if self.module.params['partition'] == 'all':
            query = "?expandSubcollections=true&$top={0}&$skip={1}".format(
                self.module.params['data_increment'], skip
            )
        else:
            query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
                self.module.params['data_increment'], skip, self.module.params['partition']
            )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result

    def read_stats_from_device(self, full_path):
        uri = "https://{0}:{1}/mgmt/tm/ltm/virtual/{2}/stats".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=full_path)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = parseStats(response)
        try:
            return result['stats']
        except KeyError:
            return {}


class VlansParameters(BaseParameters):
    api_map = {
        'autoLasthop': 'auto_lasthop',
        'cmpHash': 'cmp_hash_algorithm',
        'failsafeAction': 'failsafe_action',
        'failsafe': 'failsafe_enabled',
        'failsafeTimeout': 'failsafe_timeout',
        'ifIndex': 'if_index',
        'learning': 'learning_mode',
        'interfacesReference': 'interfaces',
        'sourceChecking': 'source_check_enabled',
        'fullPath': 'full_path'
    }

    returnables = [
        'full_path',
        'name',
        'auto_lasthop',
        'cmp_hash_algorithm',
        'description',
        'failsafe_action',
        'failsafe_enabled',
        'failsafe_timeout',
        'if_index',
        'learning_mode',
        'interfaces',
        'mtu',
        'sflow_poll_interval',
        'sflow_poll_interval_global',
        'sflow_sampling_rate',
        'sflow_sampling_rate_global',
        'source_check_enabled',
        'true_mac_address',
        'tag',
    ]

    @property
    def interfaces(self):
        if self._values['interfaces'] is None:
            return None
        if 'items' not in self._values['interfaces']:
            return None
        result = []
        for item in self._values['interfaces']['items']:
            tmp = dict(
                name=item['name'],
                full_path=item['fullPath']
            )
            if 'tagged' in item:
                tmp['tagged'] = 'yes'
            else:
                tmp['tagged'] = 'no'
            result.append(tmp)
        return result

    @property
    def sflow_poll_interval(self):
        return int(self._values['sflow']['pollInterval'])

    @property
    def sflow_poll_interval_global(self):
        return flatten_boolean(self._values['sflow']['pollIntervalGlobal'])

    @property
    def sflow_sampling_rate(self):
        return int(self._values['sflow']['samplingRate'])

    @property
    def sflow_sampling_rate_global(self):
        return flatten_boolean(self._values['sflow']['samplingRateGlobal'])

    @property
    def source_check_state(self):
        return flatten_boolean(self._values['source_check_state'])

    @property
    def true_mac_address(self):
        # Who made this field a "description"!?
        return self._values['stats']['macTrue']

    @property
    def tag(self):
        # We can't agree on field names...SMH
        return self._values['stats']['id']

    @property
    def failsafe_enabled(self):
        return flatten_boolean(self._values['failsafe_enabled'])


class VlansFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(VlansFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(vlans=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            attrs = resource
            attrs['stats'] = self.read_stats_from_device(attrs['fullPath'])
            params = VlansParameters(params=attrs)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/net/vlan".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result

    def read_stats_from_device(self, full_path):
        uri = "https://{0}:{1}/mgmt/tm/net/vlan/{2}/stats".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=full_path)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        result = parseStats(response)
        try:
            return result['stats']
        except KeyError:
            return {}


class ManagementRouteParameters(BaseParameters):
    api_map = {
        'fullPath': 'full_path',
    }

    returnables = [
        'full_path',
        'name',
        'description',
        'gateway',
        'mtu',
        'network',
    ]


class ManagementRouteFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ManagementRouteFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(management_routes=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['full_path'])
        return results

    def read_facts(self):
        results = []
        collection = self.increment_read()
        for resource in collection:
            attrs = resource
            params = ManagementRouteParameters(params=attrs)
            results.append(params)
        return results

    def increment_read(self):
        n = 0
        result = []
        while True:
            items = self.read_collection_from_device(skip=n)
            if not items:
                break
            result.extend(items)
            n = n + self.module.params['data_increment']
        return result

    def read_collection_from_device(self, skip=0):
        uri = "https://{0}:{1}/mgmt/tm/sys/management-route".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?expandSubcollections=true&$top={0}&$skip={1}&$filter=partition+eq+{2}".format(
            self.module.params['data_increment'], skip, self.module.params['partition']
        )
        resp = self.client.api.get(uri + query)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if 'items' not in response:
            return []
        result = response['items']
        return result


class RemoteSyslogParameters(BaseParameters):
    api_map = {
        'remoteServers': 'servers',
    }

    returnables = [
        'servers',
    ]

    def _morph_keys(self, key_map, item):
        for k, v in iteritems(key_map):
            item[v] = item.pop(k, None)
        result = self._filter_params(item)
        return result

    def _format_servers(self, items):
        result = list()
        key_map = {
            'name': 'name',
            'remotePort': 'remote_port',
            'localIp': 'local_ip',
            'host': 'remote_host'
        }
        for item in items:
            output = self._morph_keys(key_map, item)
            result.append(output)
        return result

    @property
    def servers(self):
        if self._values['servers'] is None:
            return None
        return self._format_servers(self._values['servers'])


class RemoteSyslogFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(RemoteSyslogFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(remote_syslog=facts)
        return result

    def _exec_module(self):
        facts = self.read_collection_from_device()
        params = RemoteSyslogParameters(params=facts)
        results = params.to_return()
        return results

    def read_collection_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/syslog/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)
        return response


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = kwargs.get('client', None)
        self.kwargs = kwargs
        self.want = Parameters(params=self.module.params)
        self.managers = {
            'apm-access-profiles': ApmAccessProfileFactManager,
            'apm-access-policies': ApmAccessPolicyFactManager,
            'as3': As3FactManager,
            'asm-policy-stats': AsmPolicyStatsFactManager,
            'asm-policies': AsmPolicyFactManager,
            'asm-server-technologies': AsmServerTechnologyFactManager,
            'asm-signature-sets': AsmSignatureSetsFactManager,
            'client-ssl-profiles': ClientSslProfilesFactManager,
            'cfe': CFEFactManager,
            'devices': DevicesFactManager,
            'device-groups': DeviceGroupsFactManager,
            'do': DOFactManager,
            'external-monitors': ExternalMonitorsFactManager,
            'fasthttp-profiles': FastHttpProfilesFactManager,
            'fastl4-profiles': FastL4ProfilesFactManager,
            'gateway-icmp-monitors': GatewayIcmpMonitorsFactManager,
            'gtm-a-pools': GtmAPoolsFactManager,
            'gtm-servers': GtmServersFactManager,
            'gtm-a-wide-ips': GtmAWideIpsFactManager,
            'gtm-aaaa-pools': GtmAaaaPoolsFactManager,
            'gtm-aaaa-wide-ips': GtmAaaaWideIpsFactManager,
            'gtm-cname-pools': GtmCnamePoolsFactManager,
            'gtm-cname-wide-ips': GtmCnameWideIpsFactManager,
            'gtm-mx-pools': GtmMxPoolsFactManager,
            'gtm-mx-wide-ips': GtmMxWideIpsFactManager,
            'gtm-naptr-pools': GtmNaptrPoolsFactManager,
            'gtm-naptr-wide-ips': GtmNaptrWideIpsFactManager,
            'gtm-srv-pools': GtmSrvPoolsFactManager,
            'gtm-srv-wide-ips': GtmSrvWideIpsFactManager,
            'gtm-topology-regions': GtmTopologyRegionFactManager,
            'http-monitors': HttpMonitorsFactManager,
            'https-monitors': HttpsMonitorsFactManager,
            'http-profiles': HttpProfilesFactManager,
            'iapp-services': IappServicesFactManager,
            'iapplx-packages': IapplxPackagesFactManager,
            'icmp-monitors': IcmpMonitorsFactManager,
            'interfaces': InterfacesFactManager,
            'internal-data-groups': InternalDataGroupsFactManager,
            'irules': IrulesFactManager,
            'license': LicenseFactManager,
            'ltm-pools': LtmPoolsFactManager,
            'snat-pools': SnatPoolsFactManager,
            'ltm-policies': LtmPolicyFactManager,
            'management-routes': ManagementRouteFactManager,
            'nodes': NodesFactManager,
            'oneconnect-profiles': OneConnectProfilesFactManager,
            'partitions': PartitionFactManager,
            'provision-info': ProvisionInfoFactManager,
            'route-domains': RouteDomainFactManager,
            'remote-syslog': RemoteSyslogFactManager,
            'self-ips': SelfIpsFactManager,
            'server-ssl-profiles': ServerSslProfilesFactManager,
            'software-volumes': SoftwareVolumesFactManager,
            'software-images': SoftwareImagesFactManager,
            'software-hotfixes': SoftwareHotfixesFactManager,
            'ssl-certs': SslCertificatesFactManager,
            'ssl-keys': SslKeysFactManager,
            'sync-status': SyncStatusFactManager,
            'system-db': SystemDbFactManager,
            'system-info': SystemInfoFactManager,
            'ts': TSFactManager,
            'tcp-monitors': TcpMonitorsFactManager,
            'tcp-half-open-monitors': TcpHalfOpenMonitorsFactManager,
            'tcp-profiles': TcpProfilesFactManager,
            'traffic-groups': TrafficGroupsFactManager,
            'trunks': TrunksFactManager,
            'ucs': UCSFactManager,
            'udp-profiles': UdpProfilesFactManager,
            'users': UsersFactManager,
            'vcmp-guests': VcmpGuestsFactManager,
            'virtual-addresses': VirtualAddressesFactManager,
            'virtual-servers': VirtualServersFactManager,
            'vlans': VlansFactManager,
        }

    def exec_module(self):
        start = datetime.datetime.now().isoformat()
        client = F5RestClient(**self.module.params)
        version = tmos_version(client)
        self.handle_all_keyword()
        self.handle_profiles_keyword()
        self.handle_monitors_keyword()
        self.handle_gtm_pools_keyword()
        self.handle_gtm_wide_ips_keyword()
        self.handle_packages_keyword()
        self.filter_excluded_meta_facts()
        res = self.check_valid_gather_subset(self.want.gather_subset)
        if res:
            invalid = ','.join(res)
            raise F5ModuleError(
                "The specified 'gather_subset' options are invalid: {0}".format(invalid)
            )
        result = self.filter_excluded_facts()

        managers = []
        for name in result:
            manager = self.get_manager(name)
            if manager:
                managers.append(manager)

        if not managers:
            result = dict(
                queried=False
            )
            return result

        result = self.execute_managers(managers)
        if result:
            result['queried'] = True
        else:
            result['queried'] = False
        send_teem(start, client, self.module, version)
        return result

    def filter_excluded_facts(self):
        # Remove the excluded entries from the list of possible facts
        exclude = [x[1:] for x in self.want.gather_subset if x[0] == '!']
        include = [x for x in self.want.gather_subset if x[0] != '!']
        result = [x for x in include if x not in exclude]
        return result

    def filter_excluded_meta_facts(self):
        gather_subset = set(self.want.gather_subset)
        gather_subset -= {'!all', '!profiles', '!monitors', '!gtm-pools', '!gtm-wide-ips', '!packages'}
        keys = self.managers.keys()

        if '!all' in self.want.gather_subset:
            gather_subset.clear()
        if '!profiles' in self.want.gather_subset:
            gather_subset -= {x for x in keys if '-profiles' in x}
        if '!monitors' in self.want.gather_subset:
            gather_subset -= {x for x in keys if '-monitors' in x}
        if '!gtm-pools' in self.want.gather_subset:
            gather_subset -= {x for x in keys if x.startswith('gtm-') and x.endswith('-pools')}
        if '!gtm-wide-ips' in self.want.gather_subset:
            gather_subset -= {x for x in keys if x.startswith('gtm-') and x.endswith('-wide-ips')}
        if '!packages' in self.want.gather_subset:
            gather_subset -= {'as3', 'do', 'cfe', 'ts'}

        self.want.update({'gather_subset': list(gather_subset)})

    def handle_all_keyword(self):
        if 'all' not in self.want.gather_subset:
            return
        managers = list(self.managers.keys()) + self.want.gather_subset
        managers.remove('all')
        self.want.update({'gather_subset': managers})

    def handle_profiles_keyword(self):
        if 'profiles' not in self.want.gather_subset:
            return
        managers = [x for x in self.managers.keys() if '-profiles' in x] + self.want.gather_subset
        managers.remove('profiles')
        self.want.update({'gather_subset': managers})

    def handle_monitors_keyword(self):
        if 'monitors' not in self.want.gather_subset:
            return
        managers = [x for x in self.managers.keys() if '-monitors' in x] + self.want.gather_subset
        managers.remove('monitors')
        self.want.update({'gather_subset': managers})

    def handle_gtm_pools_keyword(self):
        if 'gtm-pools' not in self.want.gather_subset:
            return
        keys = self.managers.keys()
        managers = [x for x in keys if x.startswith('gtm-') and x.endswith('-pools')]
        managers += self.want.gather_subset
        managers.remove('gtm-pools')
        self.want.update({'gather_subset': managers})

    def handle_gtm_wide_ips_keyword(self):
        if 'gtm-wide-ips' not in self.want.gather_subset:
            return
        keys = self.managers.keys()
        managers = [x for x in keys if x.startswith('gtm-') and x.endswith('-wide-ips')]
        managers += self.want.gather_subset
        managers.remove('gtm-wide-ips')
        self.want.update({'gather_subset': managers})

    def handle_packages_keyword(self):
        if 'packages' not in self.want.gather_subset:
            return
        managers = ['as3', 'do', 'cfe', 'ts']
        managers += self.want.gather_subset
        managers.remove('packages')
        self.want.update({'gather_subset': managers})

    def check_valid_gather_subset(self, includes):
        """Check that the specified subset is valid

        The ``gather_subset`` parameter is specified as a "raw" field which means that
        any Python type could technically be provided

        :param includes:
        :return:
        """
        keys = self.managers.keys()
        result = []
        for x in includes:
            if x not in keys:
                if x[0] == '!':
                    if x[1:] not in keys:
                        result.append(x)
                else:
                    result.append(x)
        return result

    def execute_managers(self, managers):
        results = dict()
        client = F5RestClient(**self.module.params)
        prov = modules_provisioned(client)
        for manager in managers:
            manager.provisioned_modules = prov
            result = manager.exec_module()
            results.update(result)
        return results

    def get_manager(self, which):
        result = {}
        manager = self.managers.get(which, None)
        if not manager:
            return result
        kwargs = dict()
        kwargs.update(self.kwargs)

        kwargs['client'] = F5RestClient(**self.module.params)
        result = manager(**kwargs)
        return result


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            data_increment=dict(
                type='int',
                default=10
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            gather_subset=dict(
                type='list',
                elements='str',
                required=True,
                aliases=['include'],
                choices=[
                    # Meta choices
                    'all',
                    'monitors',
                    'profiles',
                    'gtm-pools',
                    'gtm-wide-ips',
                    'packages',

                    # Non-meta choices
                    'apm-access-profiles',
                    'apm-access-policies',
                    'as3',
                    'asm-policies',
                    'asm-policy-stats',
                    'asm-server-technologies',
                    'asm-signature-sets',
                    'client-ssl-profiles',
                    'cfe',
                    'devices',
                    'device-groups',
                    'do',
                    'external-monitors',
                    'fasthttp-profiles',
                    'fastl4-profiles',
                    'gateway-icmp-monitors',
                    'gtm-a-pools',
                    'gtm-servers',
                    'gtm-a-wide-ips',
                    'gtm-aaaa-pools',
                    'gtm-aaaa-wide-ips',
                    'gtm-cname-pools',
                    'gtm-cname-wide-ips',
                    'gtm-mx-pools',
                    'gtm-mx-wide-ips',
                    'gtm-naptr-pools',
                    'gtm-naptr-wide-ips',
                    'gtm-srv-pools',
                    'gtm-srv-wide-ips',
                    'gtm-topology-regions',
                    'http-profiles',
                    'http-monitors',
                    'https-monitors',
                    'iapp-services',
                    'iapplx-packages',
                    'icmp-monitors',
                    'interfaces',
                    'internal-data-groups',
                    'irules',
                    'license',
                    'ltm-pools',
                    'snat-pools',
                    'ltm-policies',
                    'management-routes',
                    'nodes',
                    'oneconnect-profiles',
                    'partitions',
                    'provision-info',
                    'remote-syslog',
                    'route-domains',
                    'self-ips',
                    'server-ssl-profiles',
                    'software-volumes',
                    'software-images',
                    'software-hotfixes',
                    'ssl-certs',
                    'ssl-keys',
                    'sync-status',
                    'system-db',
                    'system-info',
                    'ts',
                    'tcp-monitors',
                    'tcp-half-open-monitors',
                    'tcp-profiles',
                    'traffic-groups',
                    'trunks',
                    'udp-profiles',
                    'users',
                    'ucs',
                    'vcmp-guests',
                    'virtual-addresses',
                    'virtual-servers',
                    'vlans',

                    # Negations of meta choices
                    '!all',
                    "!monitors",
                    '!profiles',
                    '!gtm-pools',
                    '!gtm-wide-ips',
                    '!packages',

                    # Negations of non-meta-choices
                    '!apm-access-profiles',
                    '!apm-access-policies',
                    '!as3',
                    '!do',
                    '!ts',
                    '!cfe',
                    '!asm-policy-stats',
                    '!asm-policies',
                    '!asm-server-technologies',
                    '!asm-signature-sets',
                    '!client-ssl-profiles',
                    '!devices',
                    '!device-groups',
                    '!external-monitors',
                    '!fasthttp-profiles',
                    '!fastl4-profiles',
                    '!gateway-icmp-monitors',
                    '!gtm-a-pools',
                    '!gtm-servers',
                    '!gtm-a-wide-ips',
                    '!gtm-aaaa-pools',
                    '!gtm-aaaa-wide-ips',
                    '!gtm-cname-pools',
                    '!gtm-cname-wide-ips',
                    '!gtm-mx-pools',
                    '!gtm-mx-wide-ips',
                    '!gtm-naptr-pools',
                    '!gtm-naptr-wide-ips',
                    '!gtm-srv-pools',
                    '!gtm-srv-wide-ips',
                    '!gtm-topology-regions',
                    '!http-profiles',
                    '!http-monitors',
                    '!https-monitors',
                    '!iapp-services',
                    '!iapplx-packages',
                    '!icmp-monitors',
                    '!interfaces',
                    '!internal-data-groups',
                    '!irules',
                    '!license',
                    '!ltm-pools',
                    '!snat-pools',
                    '!ltm-policies',
                    '!management-routes',
                    '!nodes',
                    '!oneconnect-profiles',
                    '!partitions',
                    '!provision-info',
                    '!remote-syslog',
                    '!route-domains',
                    '!self-ips',
                    '!server-ssl-profiles',
                    '!software-volumes',
                    '!software-images',
                    '!software-hotfixes',
                    '!ssl-certs',
                    '!ssl-keys',
                    '!sync-status',
                    '!system-db',
                    '!system-info',
                    '!tcp-monitors',
                    '!tcp-half-open-monitors',
                    '!tcp-profiles',
                    '!traffic-groups',
                    '!trunks',
                    '!udp-profiles',
                    '!users',
                    '!ucs',
                    '!vcmp-guests',
                    '!virtual-addresses',
                    '!virtual-servers',
                    '!vlans',
                ]
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )

    if not HAS_PACKAGING:
        module.fail_json(
            msg=missing_required_lib('packaging'),
            exception=PACKAGING_IMPORT_ERROR
        )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()

        # issue originally found and submitted in https://github.com/F5Networks/f5-ansible/pull/1477 by @traittinen

        ansible_facts = dict()

        for key, value in iteritems(results):
            key = 'ansible_net_%s' % key
            ansible_facts[key] = value

        module.exit_json(ansible_facts=ansible_facts, **results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
