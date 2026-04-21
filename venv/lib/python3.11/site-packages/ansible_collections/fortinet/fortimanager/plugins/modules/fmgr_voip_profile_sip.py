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
module: fmgr_voip_profile_sip
short_description: SIP.
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    voip_profile_sip:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ack_rate:
                aliases: ['ack-rate']
                type: int
                description: ACK request rate limit
            block_ack:
                aliases: ['block-ack']
                type: str
                description: Enable/disable block ACK requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_bye:
                aliases: ['block-bye']
                type: str
                description: Enable/disable block BYE requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_cancel:
                aliases: ['block-cancel']
                type: str
                description: Enable/disable block CANCEL requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_geo_red_options:
                aliases: ['block-geo-red-options']
                type: str
                description: Enable/disable block OPTIONS requests, but OPTIONS requests still notify for redundancy.
                choices:
                    - 'disable'
                    - 'enable'
            block_info:
                aliases: ['block-info']
                type: str
                description: Enable/disable block INFO requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_invite:
                aliases: ['block-invite']
                type: str
                description: Enable/disable block INVITE requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_long_lines:
                aliases: ['block-long-lines']
                type: str
                description: Enable/disable block requests with headers exceeding max-line-length.
                choices:
                    - 'disable'
                    - 'enable'
            block_message:
                aliases: ['block-message']
                type: str
                description: Enable/disable block MESSAGE requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_notify:
                aliases: ['block-notify']
                type: str
                description: Enable/disable block NOTIFY requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_options:
                aliases: ['block-options']
                type: str
                description: Enable/disable block OPTIONS requests and no OPTIONS as notifying message for redundancy either.
                choices:
                    - 'disable'
                    - 'enable'
            block_prack:
                aliases: ['block-prack']
                type: str
                description: Enable/disable block prack requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_publish:
                aliases: ['block-publish']
                type: str
                description: Enable/disable block PUBLISH requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_refer:
                aliases: ['block-refer']
                type: str
                description: Enable/disable block REFER requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_register:
                aliases: ['block-register']
                type: str
                description: Enable/disable block REGISTER requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_subscribe:
                aliases: ['block-subscribe']
                type: str
                description: Enable/disable block SUBSCRIBE requests.
                choices:
                    - 'disable'
                    - 'enable'
            block_unknown:
                aliases: ['block-unknown']
                type: str
                description: Block unrecognized SIP requests
                choices:
                    - 'disable'
                    - 'enable'
            block_update:
                aliases: ['block-update']
                type: str
                description: Enable/disable block UPDATE requests.
                choices:
                    - 'disable'
                    - 'enable'
            bye_rate:
                aliases: ['bye-rate']
                type: int
                description: BYE request rate limit
            call_keepalive:
                aliases: ['call-keepalive']
                type: int
                description: Continue tracking calls with no RTP for this many minutes.
            cancel_rate:
                aliases: ['cancel-rate']
                type: int
                description: CANCEL request rate limit
            contact_fixup:
                aliases: ['contact-fixup']
                type: str
                description: Fixup contact anyway even if contacts IP
                choices:
                    - 'disable'
                    - 'enable'
            hnt_restrict_source_ip:
                aliases: ['hnt-restrict-source-ip']
                type: str
                description: Enable/disable restrict RTP source IP to be the same as SIP source IP when HNT is enabled.
                choices:
                    - 'disable'
                    - 'enable'
            hosted_nat_traversal:
                aliases: ['hosted-nat-traversal']
                type: str
                description: Hosted NAT Traversal
                choices:
                    - 'disable'
                    - 'enable'
            info_rate:
                aliases: ['info-rate']
                type: int
                description: INFO request rate limit
            invite_rate:
                aliases: ['invite-rate']
                type: int
                description: INVITE request rate limit
            ips_rtp:
                aliases: ['ips-rtp']
                type: str
                description: Enable/disable allow IPS on RTP.
                choices:
                    - 'disable'
                    - 'enable'
            log_call_summary:
                aliases: ['log-call-summary']
                type: str
                description: Enable/disable logging of SIP call summary.
                choices:
                    - 'disable'
                    - 'enable'
            log_violations:
                aliases: ['log-violations']
                type: str
                description: Enable/disable logging of SIP violations.
                choices:
                    - 'disable'
                    - 'enable'
            malformed_header_allow:
                aliases: ['malformed-header-allow']
                type: str
                description: Action for malformed Allow header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_call_id:
                aliases: ['malformed-header-call-id']
                type: str
                description: Action for malformed Call-ID header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_contact:
                aliases: ['malformed-header-contact']
                type: str
                description: Action for malformed Contact header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_content_length:
                aliases: ['malformed-header-content-length']
                type: str
                description: Action for malformed Content-Length header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_content_type:
                aliases: ['malformed-header-content-type']
                type: str
                description: Action for malformed Content-Type header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_cseq:
                aliases: ['malformed-header-cseq']
                type: str
                description: Action for malformed CSeq header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_expires:
                aliases: ['malformed-header-expires']
                type: str
                description: Action for malformed Expires header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_from:
                aliases: ['malformed-header-from']
                type: str
                description: Action for malformed From header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_max_forwards:
                aliases: ['malformed-header-max-forwards']
                type: str
                description: Action for malformed Max-Forwards header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_p_asserted_identity:
                aliases: ['malformed-header-p-asserted-identity']
                type: str
                description: Action for malformed P-Asserted-Identity header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_rack:
                aliases: ['malformed-header-rack']
                type: str
                description: Action for malformed RAck header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_record_route:
                aliases: ['malformed-header-record-route']
                type: str
                description: Action for malformed Record-Route header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_route:
                aliases: ['malformed-header-route']
                type: str
                description: Action for malformed Route header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_rseq:
                aliases: ['malformed-header-rseq']
                type: str
                description: Action for malformed RSeq header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_a:
                aliases: ['malformed-header-sdp-a']
                type: str
                description: Action for malformed SDP a line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_b:
                aliases: ['malformed-header-sdp-b']
                type: str
                description: Action for malformed SDP b line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_c:
                aliases: ['malformed-header-sdp-c']
                type: str
                description: Action for malformed SDP c line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_i:
                aliases: ['malformed-header-sdp-i']
                type: str
                description: Action for malformed SDP i line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_k:
                aliases: ['malformed-header-sdp-k']
                type: str
                description: Action for malformed SDP k line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_m:
                aliases: ['malformed-header-sdp-m']
                type: str
                description: Action for malformed SDP m line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_o:
                aliases: ['malformed-header-sdp-o']
                type: str
                description: Action for malformed SDP o line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_r:
                aliases: ['malformed-header-sdp-r']
                type: str
                description: Action for malformed SDP r line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_s:
                aliases: ['malformed-header-sdp-s']
                type: str
                description: Action for malformed SDP s line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_t:
                aliases: ['malformed-header-sdp-t']
                type: str
                description: Action for malformed SDP t line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_v:
                aliases: ['malformed-header-sdp-v']
                type: str
                description: Action for malformed SDP v line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_sdp_z:
                aliases: ['malformed-header-sdp-z']
                type: str
                description: Action for malformed SDP z line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_to:
                aliases: ['malformed-header-to']
                type: str
                description: Action for malformed To header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_via:
                aliases: ['malformed-header-via']
                type: str
                description: Action for malformed VIA header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_request_line:
                aliases: ['malformed-request-line']
                type: str
                description: Action for malformed request line.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            max_body_length:
                aliases: ['max-body-length']
                type: int
                description: Maximum SIP message body length
            max_dialogs:
                aliases: ['max-dialogs']
                type: int
                description: Maximum number of concurrent calls/dialogs
            max_idle_dialogs:
                aliases: ['max-idle-dialogs']
                type: int
                description: Maximum number established but idle dialogs to retain
            max_line_length:
                aliases: ['max-line-length']
                type: int
                description: Maximum SIP header line length
            message_rate:
                aliases: ['message-rate']
                type: int
                description: MESSAGE request rate limit
            nat_trace:
                aliases: ['nat-trace']
                type: str
                description: Enable/disable preservation of original IP in SDP i line.
                choices:
                    - 'disable'
                    - 'enable'
            no_sdp_fixup:
                aliases: ['no-sdp-fixup']
                type: str
                description: Enable/disable no SDP fix-up.
                choices:
                    - 'disable'
                    - 'enable'
            notify_rate:
                aliases: ['notify-rate']
                type: int
                description: NOTIFY request rate limit
            open_contact_pinhole:
                aliases: ['open-contact-pinhole']
                type: str
                description: Enable/disable open pinhole for non-REGISTER Contact port.
                choices:
                    - 'disable'
                    - 'enable'
            open_record_route_pinhole:
                aliases: ['open-record-route-pinhole']
                type: str
                description: Enable/disable open pinhole for Record-Route port.
                choices:
                    - 'disable'
                    - 'enable'
            open_register_pinhole:
                aliases: ['open-register-pinhole']
                type: str
                description: Enable/disable open pinhole for REGISTER Contact port.
                choices:
                    - 'disable'
                    - 'enable'
            open_via_pinhole:
                aliases: ['open-via-pinhole']
                type: str
                description: Enable/disable open pinhole for Via port.
                choices:
                    - 'disable'
                    - 'enable'
            options_rate:
                aliases: ['options-rate']
                type: int
                description: OPTIONS request rate limit
            prack_rate:
                aliases: ['prack-rate']
                type: int
                description: PRACK request rate limit
            preserve_override:
                aliases: ['preserve-override']
                type: str
                description: Override i line to preserve original IPS
                choices:
                    - 'disable'
                    - 'enable'
            provisional_invite_expiry_time:
                aliases: ['provisional-invite-expiry-time']
                type: int
                description: Expiry time for provisional INVITE
            publish_rate:
                aliases: ['publish-rate']
                type: int
                description: PUBLISH request rate limit
            refer_rate:
                aliases: ['refer-rate']
                type: int
                description: REFER request rate limit
            register_contact_trace:
                aliases: ['register-contact-trace']
                type: str
                description: Enable/disable trace original IP/port within the contact header of REGISTER requests.
                choices:
                    - 'disable'
                    - 'enable'
            register_rate:
                aliases: ['register-rate']
                type: int
                description: REGISTER request rate limit
            rfc2543_branch:
                aliases: ['rfc2543-branch']
                type: str
                description: Enable/disable support via branch compliant with RFC 2543.
                choices:
                    - 'disable'
                    - 'enable'
            rtp:
                type: str
                description: Enable/disable create pinholes for RTP traffic to traverse firewall.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Relative strength of encryption algorithms accepted in negotiation.
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            ssl_auth_client:
                aliases: ['ssl-auth-client']
                type: str
                description: Require a client certificate and authenticate it with the peer/peergrp.
            ssl_auth_server:
                aliases: ['ssl-auth-server']
                type: str
                description: Authenticate the servers certificate with the peer/peergrp.
            ssl_client_certificate:
                aliases: ['ssl-client-certificate']
                type: str
                description: Name of Certificate to offer to server if requested.
            ssl_client_renegotiation:
                aliases: ['ssl-client-renegotiation']
                type: str
                description: Allow/block client renegotiation by server.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'secure'
            ssl_max_version:
                aliases: ['ssl-max-version']
                type: str
                description: Highest SSL/TLS version to negotiate.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_min_version:
                aliases: ['ssl-min-version']
                type: str
                description: Lowest SSL/TLS version to negotiate.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_mode:
                aliases: ['ssl-mode']
                type: str
                description: SSL/TLS mode for encryption & decryption of traffic.
                choices:
                    - 'off'
                    - 'full'
            ssl_pfs:
                aliases: ['ssl-pfs']
                type: str
                description: SSL Perfect Forward Secrecy.
                choices:
                    - 'require'
                    - 'deny'
                    - 'allow'
            ssl_send_empty_frags:
                aliases: ['ssl-send-empty-frags']
                type: str
                description: Send empty fragments to avoid attack on CBC IV
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_certificate:
                aliases: ['ssl-server-certificate']
                type: str
                description: Name of Certificate return to the client in every SSL connection.
            status:
                type: str
                description: Enable/disable SIP.
                choices:
                    - 'disable'
                    - 'enable'
            strict_register:
                aliases: ['strict-register']
                type: str
                description: Enable/disable only allow the registrar to connect.
                choices:
                    - 'disable'
                    - 'enable'
            subscribe_rate:
                aliases: ['subscribe-rate']
                type: int
                description: SUBSCRIBE request rate limit
            unknown_header:
                aliases: ['unknown-header']
                type: str
                description: Action for unknown SIP header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            update_rate:
                aliases: ['update-rate']
                type: int
                description: UPDATE request rate limit
            nat_port_range:
                aliases: ['nat-port-range']
                type: str
                description: RTP NAT port range.
            ack_rate_track:
                aliases: ['ack-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            bye_rate_track:
                aliases: ['bye-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            cancel_rate_track:
                aliases: ['cancel-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            info_rate_track:
                aliases: ['info-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            invite_rate_track:
                aliases: ['invite-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            malformed_header_no_proxy_require:
                aliases: ['malformed-header-no-proxy-require']
                type: str
                description: Action for malformed SIP messages without Proxy-Require header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            malformed_header_no_require:
                aliases: ['malformed-header-no-require']
                type: str
                description: Action for malformed SIP messages without Require header.
                choices:
                    - 'pass'
                    - 'discard'
                    - 'respond'
            message_rate_track:
                aliases: ['message-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            notify_rate_track:
                aliases: ['notify-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            options_rate_track:
                aliases: ['options-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            prack_rate_track:
                aliases: ['prack-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            publish_rate_track:
                aliases: ['publish-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            refer_rate_track:
                aliases: ['refer-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            register_rate_track:
                aliases: ['register-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            subscribe_rate_track:
                aliases: ['subscribe-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            update_rate_track:
                aliases: ['update-rate-track']
                type: str
                description: Track the packet protocol field.
                choices:
                    - 'none'
                    - 'src-ip'
                    - 'dest-ip'
            call_id_regex:
                aliases: ['call-id-regex']
                type: str
                description: Validate PCRE regular expression for Call-Id header value.
            content_type_regex:
                aliases: ['content-type-regex']
                type: str
                description: Validate PCRE regular expression for Content-Type header value.
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
    - name: SIP.
      fortinet.fortimanager.fmgr_voip_profile_sip:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        profile: <your own value>
        voip_profile_sip:
          # ack_rate: <integer>
          # block_ack: <value in [disable, enable]>
          # block_bye: <value in [disable, enable]>
          # block_cancel: <value in [disable, enable]>
          # block_geo_red_options: <value in [disable, enable]>
          # block_info: <value in [disable, enable]>
          # block_invite: <value in [disable, enable]>
          # block_long_lines: <value in [disable, enable]>
          # block_message: <value in [disable, enable]>
          # block_notify: <value in [disable, enable]>
          # block_options: <value in [disable, enable]>
          # block_prack: <value in [disable, enable]>
          # block_publish: <value in [disable, enable]>
          # block_refer: <value in [disable, enable]>
          # block_register: <value in [disable, enable]>
          # block_subscribe: <value in [disable, enable]>
          # block_unknown: <value in [disable, enable]>
          # block_update: <value in [disable, enable]>
          # bye_rate: <integer>
          # call_keepalive: <integer>
          # cancel_rate: <integer>
          # contact_fixup: <value in [disable, enable]>
          # hnt_restrict_source_ip: <value in [disable, enable]>
          # hosted_nat_traversal: <value in [disable, enable]>
          # info_rate: <integer>
          # invite_rate: <integer>
          # ips_rtp: <value in [disable, enable]>
          # log_call_summary: <value in [disable, enable]>
          # log_violations: <value in [disable, enable]>
          # malformed_header_allow: <value in [pass, discard, respond]>
          # malformed_header_call_id: <value in [pass, discard, respond]>
          # malformed_header_contact: <value in [pass, discard, respond]>
          # malformed_header_content_length: <value in [pass, discard, respond]>
          # malformed_header_content_type: <value in [pass, discard, respond]>
          # malformed_header_cseq: <value in [pass, discard, respond]>
          # malformed_header_expires: <value in [pass, discard, respond]>
          # malformed_header_from: <value in [pass, discard, respond]>
          # malformed_header_max_forwards: <value in [pass, discard, respond]>
          # malformed_header_p_asserted_identity: <value in [pass, discard, respond]>
          # malformed_header_rack: <value in [pass, discard, respond]>
          # malformed_header_record_route: <value in [pass, discard, respond]>
          # malformed_header_route: <value in [pass, discard, respond]>
          # malformed_header_rseq: <value in [pass, discard, respond]>
          # malformed_header_sdp_a: <value in [pass, discard, respond]>
          # malformed_header_sdp_b: <value in [pass, discard, respond]>
          # malformed_header_sdp_c: <value in [pass, discard, respond]>
          # malformed_header_sdp_i: <value in [pass, discard, respond]>
          # malformed_header_sdp_k: <value in [pass, discard, respond]>
          # malformed_header_sdp_m: <value in [pass, discard, respond]>
          # malformed_header_sdp_o: <value in [pass, discard, respond]>
          # malformed_header_sdp_r: <value in [pass, discard, respond]>
          # malformed_header_sdp_s: <value in [pass, discard, respond]>
          # malformed_header_sdp_t: <value in [pass, discard, respond]>
          # malformed_header_sdp_v: <value in [pass, discard, respond]>
          # malformed_header_sdp_z: <value in [pass, discard, respond]>
          # malformed_header_to: <value in [pass, discard, respond]>
          # malformed_header_via: <value in [pass, discard, respond]>
          # malformed_request_line: <value in [pass, discard, respond]>
          # max_body_length: <integer>
          # max_dialogs: <integer>
          # max_idle_dialogs: <integer>
          # max_line_length: <integer>
          # message_rate: <integer>
          # nat_trace: <value in [disable, enable]>
          # no_sdp_fixup: <value in [disable, enable]>
          # notify_rate: <integer>
          # open_contact_pinhole: <value in [disable, enable]>
          # open_record_route_pinhole: <value in [disable, enable]>
          # open_register_pinhole: <value in [disable, enable]>
          # open_via_pinhole: <value in [disable, enable]>
          # options_rate: <integer>
          # prack_rate: <integer>
          # preserve_override: <value in [disable, enable]>
          # provisional_invite_expiry_time: <integer>
          # publish_rate: <integer>
          # refer_rate: <integer>
          # register_contact_trace: <value in [disable, enable]>
          # register_rate: <integer>
          # rfc2543_branch: <value in [disable, enable]>
          # rtp: <value in [disable, enable]>
          # ssl_algorithm: <value in [high, medium, low]>
          # ssl_auth_client: <string>
          # ssl_auth_server: <string>
          # ssl_client_certificate: <string>
          # ssl_client_renegotiation: <value in [allow, deny, secure]>
          # ssl_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_mode: <value in [off, full]>
          # ssl_pfs: <value in [require, deny, allow]>
          # ssl_send_empty_frags: <value in [disable, enable]>
          # ssl_server_certificate: <string>
          # status: <value in [disable, enable]>
          # strict_register: <value in [disable, enable]>
          # subscribe_rate: <integer>
          # unknown_header: <value in [pass, discard, respond]>
          # update_rate: <integer>
          # nat_port_range: <string>
          # ack_rate_track: <value in [none, src-ip, dest-ip]>
          # bye_rate_track: <value in [none, src-ip, dest-ip]>
          # cancel_rate_track: <value in [none, src-ip, dest-ip]>
          # info_rate_track: <value in [none, src-ip, dest-ip]>
          # invite_rate_track: <value in [none, src-ip, dest-ip]>
          # malformed_header_no_proxy_require: <value in [pass, discard, respond]>
          # malformed_header_no_require: <value in [pass, discard, respond]>
          # message_rate_track: <value in [none, src-ip, dest-ip]>
          # notify_rate_track: <value in [none, src-ip, dest-ip]>
          # options_rate_track: <value in [none, src-ip, dest-ip]>
          # prack_rate_track: <value in [none, src-ip, dest-ip]>
          # publish_rate_track: <value in [none, src-ip, dest-ip]>
          # refer_rate_track: <value in [none, src-ip, dest-ip]>
          # register_rate_track: <value in [none, src-ip, dest-ip]>
          # subscribe_rate_track: <value in [none, src-ip, dest-ip]>
          # update_rate_track: <value in [none, src-ip, dest-ip]>
          # call_id_regex: <string>
          # content_type_regex: <string>
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
        '/pm/config/adom/{adom}/obj/voip/profile/{profile}/sip',
        '/pm/config/global/obj/voip/profile/{profile}/sip'
    ]
    url_params = ['adom', 'profile']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'voip_profile_sip': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'ack-rate': {'type': 'int'},
                'block-ack': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-bye': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-cancel': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-geo-red-options': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-info': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-invite': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-long-lines': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-message': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-notify': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-options': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-prack': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-publish': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-refer': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-register': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-subscribe': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-unknown': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-update': {'choices': ['disable', 'enable'], 'type': 'str'},
                'bye-rate': {'type': 'int'},
                'call-keepalive': {'type': 'int'},
                'cancel-rate': {'type': 'int'},
                'contact-fixup': {'choices': ['disable', 'enable'], 'type': 'str'},
                'hnt-restrict-source-ip': {'choices': ['disable', 'enable'], 'type': 'str'},
                'hosted-nat-traversal': {'choices': ['disable', 'enable'], 'type': 'str'},
                'info-rate': {'type': 'int'},
                'invite-rate': {'type': 'int'},
                'ips-rtp': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-call-summary': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-violations': {'choices': ['disable', 'enable'], 'type': 'str'},
                'malformed-header-allow': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-call-id': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-contact': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-content-length': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-content-type': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-cseq': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-expires': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-from': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-max-forwards': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-p-asserted-identity': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-rack': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-record-route': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-route': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-rseq': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-a': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-b': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-c': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-i': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-k': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-m': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-o': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-r': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-s': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-t': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-v': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-sdp-z': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-to': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-via': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-request-line': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'max-body-length': {'type': 'int'},
                'max-dialogs': {'type': 'int'},
                'max-idle-dialogs': {'type': 'int'},
                'max-line-length': {'type': 'int'},
                'message-rate': {'type': 'int'},
                'nat-trace': {'choices': ['disable', 'enable'], 'type': 'str'},
                'no-sdp-fixup': {'choices': ['disable', 'enable'], 'type': 'str'},
                'notify-rate': {'type': 'int'},
                'open-contact-pinhole': {'choices': ['disable', 'enable'], 'type': 'str'},
                'open-record-route-pinhole': {'choices': ['disable', 'enable'], 'type': 'str'},
                'open-register-pinhole': {'choices': ['disable', 'enable'], 'type': 'str'},
                'open-via-pinhole': {'choices': ['disable', 'enable'], 'type': 'str'},
                'options-rate': {'type': 'int'},
                'prack-rate': {'type': 'int'},
                'preserve-override': {'choices': ['disable', 'enable'], 'type': 'str'},
                'provisional-invite-expiry-time': {'type': 'int'},
                'publish-rate': {'type': 'int'},
                'refer-rate': {'type': 'int'},
                'register-contact-trace': {'choices': ['disable', 'enable'], 'type': 'str'},
                'register-rate': {'type': 'int'},
                'rfc2543-branch': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rtp': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-algorithm': {'choices': ['high', 'medium', 'low'], 'type': 'str'},
                'ssl-auth-client': {'type': 'str'},
                'ssl-auth-server': {'type': 'str'},
                'ssl-client-certificate': {'type': 'str'},
                'ssl-client-renegotiation': {'choices': ['allow', 'deny', 'secure'], 'type': 'str'},
                'ssl-max-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-min-version': {'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-mode': {'choices': ['off', 'full'], 'type': 'str'},
                'ssl-pfs': {'choices': ['require', 'deny', 'allow'], 'type': 'str'},
                'ssl-send-empty-frags': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-certificate': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'strict-register': {'choices': ['disable', 'enable'], 'type': 'str'},
                'subscribe-rate': {'type': 'int'},
                'unknown-header': {'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'update-rate': {'type': 'int'},
                'nat-port-range': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'ack-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'bye-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'cancel-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'info-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'invite-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'malformed-header-no-proxy-require': {'v_range': [['7.0.0', '']], 'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'malformed-header-no-require': {'v_range': [['7.0.0', '']], 'choices': ['pass', 'discard', 'respond'], 'type': 'str'},
                'message-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'notify-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'options-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'prack-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'publish-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'refer-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'register-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'subscribe-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'update-rate-track': {'v_range': [['7.0.0', '']], 'choices': ['none', 'src-ip', 'dest-ip'], 'type': 'str'},
                'call-id-regex': {'v_range': [['7.2.3', '']], 'type': 'str'},
                'content-type-regex': {'v_range': [['7.2.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'voip_profile_sip'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
