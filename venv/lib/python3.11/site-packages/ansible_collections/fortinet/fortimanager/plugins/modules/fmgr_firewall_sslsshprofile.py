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
module: fmgr_firewall_sslsshprofile
short_description: Configure SSL/SSH protocol options.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    firewall_sslsshprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            caname:
                type: str
                description: CA certificate used by SSL Inspection.
            comment:
                type: str
                description: Optional comments.
            mapi_over_https:
                aliases: ['mapi-over-https']
                type: str
                description: Enable/disable inspection of MAPI over HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Name.
                required: true
            rpc_over_https:
                aliases: ['rpc-over-https']
                type: str
                description: Enable/disable inspection of RPC over HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            server_cert:
                aliases: ['server-cert']
                type: raw
                description: (list or str) Certificate used by SSL Inspection to replace server certificate.
            server_cert_mode:
                aliases: ['server-cert-mode']
                type: str
                description: Re-sign or replace the servers certificate.
                choices:
                    - 're-sign'
                    - 'replace'
            ssl_anomalies_log:
                aliases: ['ssl-anomalies-log']
                type: str
                description: Enable/disable logging SSL anomalies.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_exempt:
                aliases: ['ssl-exempt']
                type: list
                elements: dict
                description: Ssl exempt.
                suboptions:
                    address:
                        type: str
                        description: IPv4 address object.
                    address6:
                        type: str
                        description: IPv6 address object.
                    fortiguard_category:
                        aliases: ['fortiguard-category']
                        type: str
                        description: FortiGuard category ID.
                    id:
                        type: int
                        description: ID number.
                    regex:
                        type: str
                        description: Exempt servers by regular expression.
                    type:
                        type: str
                        description: Type of address object
                        choices:
                            - 'fortiguard-category'
                            - 'address'
                            - 'address6'
                            - 'wildcard-fqdn'
                            - 'regex'
                            - 'finger-print'
                    wildcard_fqdn:
                        aliases: ['wildcard-fqdn']
                        type: str
                        description: Exempt servers by wildcard FQDN.
            ssl_exemptions_log:
                aliases: ['ssl-exemptions-log']
                type: str
                description: Enable/disable logging SSL exemptions.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server:
                aliases: ['ssl-server']
                type: list
                elements: dict
                description: Ssl server.
                suboptions:
                    ftps_client_cert_request:
                        aliases: ['ftps-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the FTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https_client_cert_request:
                        aliases: ['https-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the HTTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    id:
                        type: int
                        description: SSL server ID.
                    imaps_client_cert_request:
                        aliases: ['imaps-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the IMAPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ip:
                        type: str
                        description: IPv4 address of the SSL server.
                    pop3s_client_cert_request:
                        aliases: ['pop3s-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the POP3S handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps_client_cert_request:
                        aliases: ['smtps-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the SMTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl_other_client_cert_request:
                        aliases: ['ssl-other-client-cert-request']
                        type: str
                        description: Action based on client certificate request during an SSL protocol handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ftps_client_certificate:
                        aliases: ['ftps-client-certificate']
                        type: str
                        description: Action based on received client certificate during the FTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https_client_certificate:
                        aliases: ['https-client-certificate']
                        type: str
                        description: Action based on received client certificate during the HTTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    imaps_client_certificate:
                        aliases: ['imaps-client-certificate']
                        type: str
                        description: Action based on received client certificate during the IMAPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    pop3s_client_certificate:
                        aliases: ['pop3s-client-certificate']
                        type: str
                        description: Action based on received client certificate during the POP3S handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps_client_certificate:
                        aliases: ['smtps-client-certificate']
                        type: str
                        description: Action based on received client certificate during the SMTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl_other_client_certificate:
                        aliases: ['ssl-other-client-certificate']
                        type: str
                        description: Action based on received client certificate during an SSL protocol handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
            untrusted_caname:
                aliases: ['untrusted-caname']
                type: str
                description: Untrusted CA certificate used by SSL Inspection.
            use_ssl_server:
                aliases: ['use-ssl-server']
                type: str
                description: Enable/disable the use of SSL server table for SSL offloading.
                choices:
                    - 'disable'
                    - 'enable'
            whitelist:
                type: str
                description: Enable/disable exempting servers by FortiGuard whitelist.
                choices:
                    - 'disable'
                    - 'enable'
            block_blacklisted_certificates:
                aliases: ['block-blacklisted-certificates']
                type: str
                description: Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blacklist.
                choices:
                    - 'disable'
                    - 'enable'
            certname:
                type: str
                description: Certificate containing the key to use when re-signing server certificates for SSL inspection.
            ssl_invalid_server_cert_log:
                aliases: ['ssl-invalid-server-cert-log']
                type: str
                description: Enable/disable SSL server certificate validation logging.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_negotiation_log:
                aliases: ['ssl-negotiation-log']
                type: str
                description: Enable/disable logging SSL negotiation.
                choices:
                    - 'disable'
                    - 'enable'
            ftps:
                type: dict
                description: Ftps.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        type: raw
                        description: (list) Ports to use for scanning
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Minimum SSL version to be allowed.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
            https:
                type: dict
                description: Https.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        type: raw
                        description: (list) Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_probe_failure:
                        aliases: ['cert-probe-failure']
                        type: str
                        description: Action based on certificate probe failure.
                        choices:
                            - 'block'
                            - 'allow'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Minimum SSL version to be allowed.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    quic:
                        type: str
                        description: Enable/disable QUIC inspection
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'bypass'
                            - 'block'
                            - 'inspect'
                    encrypted_client_hello:
                        aliases: ['encrypted-client-hello']
                        type: str
                        description: Block/allow session based on existence of encrypted-client-hello.
                        choices:
                            - 'block'
                            - 'allow'
                    udp_not_quic:
                        aliases: ['udp-not-quic']
                        type: str
                        description: Action to be taken when matched UDP packet is not QUIC.
                        choices:
                            - 'block'
                            - 'allow'
            imaps:
                type: dict
                description: Imaps.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        type: raw
                        description: (list) Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Min allowed ssl version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            pop3s:
                type: dict
                description: Pop3s.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        type: raw
                        description: (list) Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Min allowed ssl version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            smtps:
                type: dict
                description: Smtps.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        type: raw
                        description: (list) Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Min allowed ssl version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssh:
                type: dict
                description: Ssh.
                suboptions:
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Level of SSL inspection.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    ports:
                        type: raw
                        description: (list) Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    ssh_algorithm:
                        aliases: ['ssh-algorithm']
                        type: str
                        description: Relative strength of encryption algorithms accepted during negotiation.
                        choices:
                            - 'compatible'
                            - 'high-encryption'
                    ssh_tun_policy_check:
                        aliases: ['ssh-tun-policy-check']
                        type: str
                        description: Enable/disable SSH tunnel policy check.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_version:
                        aliases: ['unsupported-version']
                        type: str
                        description: Action based on SSH version being unsupported.
                        choices:
                            - 'block'
                            - 'bypass'
                    ssh_policy_check:
                        aliases: ['ssh-policy-check']
                        type: str
                        description: Enable/disable SSH policy check.
                        choices:
                            - 'disable'
                            - 'enable'
                    block:
                        type: list
                        elements: str
                        description: SSH blocking options.
                        choices:
                            - 'x11-filter'
                            - 'ssh-shell'
                            - 'exec'
                            - 'port-forward'
                    log:
                        type: list
                        elements: str
                        description: SSH logging options.
                        choices:
                            - 'x11-filter'
                            - 'ssh-shell'
                            - 'exec'
                            - 'port-forward'
            ssl:
                type: dict
                description: Ssl.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Level of SSL inspection.
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_probe_failure:
                        aliases: ['cert-probe-failure']
                        type: str
                        description: Action based on certificate probe failure.
                        choices:
                            - 'block'
                            - 'allow'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Minimum SSL version to be allowed.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    encrypted_client_hello:
                        aliases: ['encrypted-client-hello']
                        type: str
                        description: Block/allow session based on existence of encrypted-client-hello.
                        choices:
                            - 'block'
                            - 'allow'
            allowlist:
                type: str
                description: Enable/disable exempting servers by FortiGuard allowlist.
                choices:
                    - 'disable'
                    - 'enable'
            block_blocklisted_certificates:
                aliases: ['block-blocklisted-certificates']
                type: str
                description: Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blocklist.
                choices:
                    - 'disable'
                    - 'enable'
            dot:
                type: dict
                description: Dot.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Min allowed ssl version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    quic:
                        type: str
                        description: Enable/disable QUIC inspection
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'bypass'
                            - 'block'
                            - 'inspect'
                    udp_not_quic:
                        aliases: ['udp-not-quic']
                        type: str
                        description: Action to be taken when matched UDP packet is not QUIC.
                        choices:
                            - 'block'
                            - 'allow'
            supported_alpn:
                aliases: ['supported-alpn']
                type: str
                description: Configure ALPN option.
                choices:
                    - 'none'
                    - 'http1-1'
                    - 'http2'
                    - 'all'
            ssl_anomaly_log:
                aliases: ['ssl-anomaly-log']
                type: str
                description: Enable/disable logging of SSL anomalies.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_exemption_ip_rating:
                aliases: ['ssl-exemption-ip-rating']
                type: str
                description: Enable/disable IP based URL rating.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_exemption_log:
                aliases: ['ssl-exemption-log']
                type: str
                description: Enable/disable logging SSL exemptions.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_handshake_log:
                aliases: ['ssl-handshake-log']
                type: str
                description: Enable/disable logging of TLS handshakes.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_cert_log:
                aliases: ['ssl-server-cert-log']
                type: str
                description: Enable/disable logging of server certificate information.
                choices:
                    - 'disable'
                    - 'enable'
            ech_outer_sni:
                aliases: ['ech-outer-sni']
                type: list
                elements: dict
                description: Ech outer sni.
                suboptions:
                    name:
                        type: str
                        description: ClientHelloOuter SNI name.
                    sni:
                        type: str
                        description: ClientHelloOuter SNI to be blocked.
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
    - name: Configure SSL/SSH protocol options.
      fortinet.fortimanager.fmgr_firewall_sslsshprofile:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_sslsshprofile:
          comment: "ansible-comment1"
          mapi_over_https: disable # <value in [disable, enable]>
          name: "ansible-test"
          use_ssl_server: disable # <value in [disable, enable]>
          whitelist: enable # <value in [disable, enable]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the SSL/SSH protocol options
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_sslsshprofile"
          params:
            adom: "ansible"
            ssl_ssh_profile: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile',
        '/pm/config/global/obj/firewall/ssl-ssh-profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_sslsshprofile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'caname': {'type': 'str'},
                'comment': {'type': 'str'},
                'mapi-over-https': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'rpc-over-https': {'choices': ['disable', 'enable'], 'type': 'str'},
                'server-cert': {'type': 'raw'},
                'server-cert-mode': {'choices': ['re-sign', 'replace'], 'type': 'str'},
                'ssl-anomalies-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-exempt': {
                    'type': 'list',
                    'options': {
                        'address': {'type': 'str'},
                        'address6': {'type': 'str'},
                        'fortiguard-category': {'type': 'str'},
                        'id': {'type': 'int'},
                        'regex': {'type': 'str'},
                        'type': {'choices': ['fortiguard-category', 'address', 'address6', 'wildcard-fqdn', 'regex', 'finger-print'], 'type': 'str'},
                        'wildcard-fqdn': {'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ssl-exemptions-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server': {
                    'type': 'list',
                    'options': {
                        'ftps-client-cert-request': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'https-client-cert-request': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'id': {'type': 'int'},
                        'imaps-client-cert-request': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'ip': {'type': 'str'},
                        'pop3s-client-cert-request': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'smtps-client-cert-request': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'ssl-other-client-cert-request': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'ftps-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'https-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'imaps-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'pop3s-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'smtps-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'ssl-other-client-certificate': {'v_range': [['6.4.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'untrusted-caname': {'type': 'str'},
                'use-ssl-server': {'choices': ['disable', 'enable'], 'type': 'str'},
                'whitelist': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-blacklisted-certificates': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'certname': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'ssl-invalid-server-cert-log': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-negotiation-log': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ftps': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'cert-validation-timeout': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-certificate': {'v_range': [['6.4.5', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'expired-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'ports': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'revoked-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'untrusted-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'client-cert-request': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'invalid-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'allow-invalid-server-cert': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'untrusted-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.0.3', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow', 'inspect'], 'type': 'str'}
                    }
                },
                'https': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'cert-validation-timeout': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-certificate': {'v_range': [['6.4.5', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'expired-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'ports': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'proxy-after-tcp-handshake': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'certificate-inspection', 'deep-inspection'],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'untrusted-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'client-cert-request': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'invalid-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'allow-invalid-server-cert': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'untrusted-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'cert-probe-failure': {'v_range': [['7.0.0', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.0.3', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow', 'inspect'], 'type': 'str'},
                        'quic': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable', 'bypass', 'block', 'inspect'], 'type': 'str'},
                        'encrypted-client-hello': {'v_range': [['7.4.3', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'udp-not-quic': {'v_range': [['7.6.2', '']], 'choices': ['block', 'allow'], 'type': 'str'}
                    }
                },
                'imaps': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'cert-validation-timeout': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-certificate': {'v_range': [['6.4.5', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'expired-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'ports': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'proxy-after-tcp-handshake': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'untrusted-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'client-cert-request': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'invalid-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'allow-invalid-server-cert': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'untrusted-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl-version': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow', 'inspect'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.0.3', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        }
                    }
                },
                'pop3s': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'cert-validation-timeout': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-certificate': {'v_range': [['6.4.5', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'expired-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'ports': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'proxy-after-tcp-handshake': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'untrusted-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'client-cert-request': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'invalid-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'allow-invalid-server-cert': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'untrusted-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl-version': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow', 'inspect'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.0.3', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        }
                    }
                },
                'smtps': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'cert-validation-timeout': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-certificate': {'v_range': [['6.4.5', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'expired-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'ports': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'proxy-after-tcp-handshake': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'untrusted-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'client-cert-request': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'invalid-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'allow-invalid-server-cert': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'untrusted-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl-version': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow', 'inspect'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.0.3', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        }
                    }
                },
                'ssh': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'inspect-all': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'ports': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'raw'},
                        'proxy-after-tcp-handshake': {'v_range': [['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssh-algorithm': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['compatible', 'high-encryption'], 'type': 'str'},
                        'ssh-tun-policy-check': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-version': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['block', 'bypass'], 'type': 'str'},
                        'ssh-policy-check': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '6.4.15']],
                            'type': 'list',
                            'choices': ['x11-filter', 'ssh-shell', 'exec', 'port-forward'],
                            'elements': 'str'
                        },
                        'log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '6.4.15']],
                            'type': 'list',
                            'choices': ['x11-filter', 'ssh-shell', 'exec', 'port-forward'],
                            'elements': 'str'
                        }
                    }
                },
                'ssl': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'cert-validation-timeout': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-certificate': {'v_range': [['6.4.5', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'expired-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'inspect-all': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'certificate-inspection', 'deep-inspection'],
                            'type': 'str'
                        },
                        'revoked-server-cert': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['6.4.5', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'untrusted-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'client-cert-request': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'invalid-server-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'allow-invalid-server-cert': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'untrusted-cert': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'cert-probe-failure': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.0.3', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'unsupported-ssl-version': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow', 'inspect'], 'type': 'str'},
                        'encrypted-client-hello': {'v_range': [['7.4.3', '']], 'choices': ['block', 'allow'], 'type': 'str'}
                    }
                },
                'allowlist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'block-blocklisted-certificates': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dot': {
                    'v_range': [['7.0.0', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {'v_range': [['7.0.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'cert-validation-timeout': {'v_range': [['7.0.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-certificate': {'v_range': [['7.0.0', '']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'expired-server-cert': {'v_range': [['7.0.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['7.0.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {'v_range': [['7.0.0', '']], 'choices': ['enable', 'strict', 'disable'], 'type': 'str'},
                        'status': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['7.0.0', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['7.0.0', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'untrusted-server-cert': {'v_range': [['7.0.0', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'unsupported-ssl-version': {'v_range': [['7.0.1', '']], 'choices': ['block', 'allow', 'inspect'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.0.3', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'quic': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable', 'bypass', 'block', 'inspect'], 'type': 'str'},
                        'udp-not-quic': {'v_range': [['7.6.2', '']], 'choices': ['block', 'allow'], 'type': 'str'}
                    }
                },
                'supported-alpn': {'v_range': [['7.0.0', '']], 'choices': ['none', 'http1-1', 'http2', 'all'], 'type': 'str'},
                'ssl-anomaly-log': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-exemption-ip-rating': {'v_range': [['7.0.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-exemption-log': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-handshake-log': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-cert-log': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ech-outer-sni': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.4.3', '']], 'type': 'str'}, 'sni': {'v_range': [['7.4.3', '']], 'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile'),
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
