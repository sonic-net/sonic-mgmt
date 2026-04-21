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
module: fortios_voip_profile
short_description: Configure VoIP profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify voip feature and profile category.
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
    voip_profile:
        description:
            - Configure VoIP profiles.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            feature_set:
                description:
                    - IPS or voipd (SIP-ALG) inspection feature set.
                type: str
                choices:
                    - 'ips'
                    - 'voipd'
                    - 'flow'
                    - 'proxy'
            msrp:
                description:
                    - MSRP.
                type: dict
                suboptions:
                    log_violations:
                        description:
                            - Enable/disable logging of MSRP violations.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    max_msg_size:
                        description:
                            - Maximum allowable MSRP message size (1-65535).
                        type: int
                    max_msg_size_action:
                        description:
                            - Action for violation of max-msg-size.
                        type: str
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                            - 'monitor'
                    status:
                        description:
                            - Enable/disable MSRP.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            sccp:
                description:
                    - SCCP.
                type: dict
                suboptions:
                    block_mcast:
                        description:
                            - Enable/disable block multicast RTP connections.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log_call_summary:
                        description:
                            - Enable/disable log summary of SCCP calls.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log_violations:
                        description:
                            - Enable/disable logging of SCCP violations.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    max_calls:
                        description:
                            - Maximum calls per minute per SCCP client (max 65535).
                        type: int
                    status:
                        description:
                            - Enable/disable SCCP.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    verify_header:
                        description:
                            - Enable/disable verify SCCP header content.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            sip:
                description:
                    - SIP.
                type: dict
                suboptions:
                    ack_rate:
                        description:
                            - ACK request rate limit (per second, per policy).
                        type: int
                    ack_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    block_ack:
                        description:
                            - Enable/disable block ACK requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_bye:
                        description:
                            - Enable/disable block BYE requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_cancel:
                        description:
                            - Enable/disable block CANCEL requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_geo_red_options:
                        description:
                            - Enable/disable block OPTIONS requests, but OPTIONS requests still notify for redundancy.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_info:
                        description:
                            - Enable/disable block INFO requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_invite:
                        description:
                            - Enable/disable block INVITE requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_long_lines:
                        description:
                            - Enable/disable block requests with headers exceeding max-line-length.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_message:
                        description:
                            - Enable/disable block MESSAGE requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_notify:
                        description:
                            - Enable/disable block NOTIFY requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_options:
                        description:
                            - Enable/disable block OPTIONS requests and no OPTIONS as notifying message for redundancy either.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_prack:
                        description:
                            - Enable/disable block prack requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_publish:
                        description:
                            - Enable/disable block PUBLISH requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_refer:
                        description:
                            - Enable/disable block REFER requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_register:
                        description:
                            - Enable/disable block REGISTER requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_subscribe:
                        description:
                            - Enable/disable block SUBSCRIBE requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_unknown:
                        description:
                            - Block unrecognized SIP requests (enabled by default).
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    block_update:
                        description:
                            - Enable/disable block UPDATE requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    bye_rate:
                        description:
                            - BYE request rate limit (per second, per policy).
                        type: int
                    bye_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    call_id_regex:
                        description:
                            - Validate PCRE regular expression for Call-Id header value.
                        type: str
                    call_keepalive:
                        description:
                            - Continue tracking calls with no RTP for this many minutes.
                        type: int
                    cancel_rate:
                        description:
                            - CANCEL request rate limit (per second, per policy).
                        type: int
                    cancel_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    contact_fixup:
                        description:
                            - 'Fixup contact anyway even if contact"s IP:port doesn"t match session"s IP:port.'
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    content_type_regex:
                        description:
                            - Validate PCRE regular expression for Content-Type header value.
                        type: str
                    hnt_restrict_source_ip:
                        description:
                            - Enable/disable restrict RTP source IP to be the same as SIP source IP when HNT is enabled.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    hosted_nat_traversal:
                        description:
                            - Hosted NAT Traversal (HNT).
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    info_rate:
                        description:
                            - INFO request rate limit (per second, per policy).
                        type: int
                    info_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    invite_rate:
                        description:
                            - INVITE request rate limit (per second, per policy).
                        type: int
                    invite_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    ips_rtp:
                        description:
                            - Enable/disable allow IPS on RTP.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log_call_summary:
                        description:
                            - Enable/disable logging of SIP call summary.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log_violations:
                        description:
                            - Enable/disable logging of SIP violations.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    malformed_header_allow:
                        description:
                            - Action for malformed Allow header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_call_id:
                        description:
                            - Action for malformed Call-ID header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_contact:
                        description:
                            - Action for malformed Contact header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_content_length:
                        description:
                            - Action for malformed Content-Length header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_content_type:
                        description:
                            - Action for malformed Content-Type header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_cseq:
                        description:
                            - Action for malformed CSeq header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_expires:
                        description:
                            - Action for malformed Expires header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_from:
                        description:
                            - Action for malformed From header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_max_forwards:
                        description:
                            - Action for malformed Max-Forwards header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_no_proxy_require:
                        description:
                            - Action for malformed SIP messages without Proxy-Require header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_no_require:
                        description:
                            - Action for malformed SIP messages without Require header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_p_asserted_identity:
                        description:
                            - Action for malformed P-Asserted-Identity header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_rack:
                        description:
                            - Action for malformed RAck header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_record_route:
                        description:
                            - Action for malformed Record-Route header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_route:
                        description:
                            - Action for malformed Route header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_rseq:
                        description:
                            - Action for malformed RSeq header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_a:
                        description:
                            - Action for malformed SDP a line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_b:
                        description:
                            - Action for malformed SDP b line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_c:
                        description:
                            - Action for malformed SDP c line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_i:
                        description:
                            - Action for malformed SDP i line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_k:
                        description:
                            - Action for malformed SDP k line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_m:
                        description:
                            - Action for malformed SDP m line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_o:
                        description:
                            - Action for malformed SDP o line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_r:
                        description:
                            - Action for malformed SDP r line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_s:
                        description:
                            - Action for malformed SDP s line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_t:
                        description:
                            - Action for malformed SDP t line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_v:
                        description:
                            - Action for malformed SDP v line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_sdp_z:
                        description:
                            - Action for malformed SDP z line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_to:
                        description:
                            - Action for malformed To header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_header_via:
                        description:
                            - Action for malformed VIA header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    malformed_request_line:
                        description:
                            - Action for malformed request line.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    max_body_length:
                        description:
                            - Maximum SIP message body length (0 meaning no limit).
                        type: int
                    max_dialogs:
                        description:
                            - Maximum number of concurrent calls/dialogs (per policy).
                        type: int
                    max_idle_dialogs:
                        description:
                            - Maximum number established but idle dialogs to retain (per policy).
                        type: int
                    max_line_length:
                        description:
                            - Maximum SIP header line length (78-4096).
                        type: int
                    message_rate:
                        description:
                            - MESSAGE request rate limit (per second, per policy).
                        type: int
                    message_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    nat_port_range:
                        description:
                            - RTP NAT port range.
                        type: str
                    nat_trace:
                        description:
                            - Enable/disable preservation of original IP in SDP i line.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    no_sdp_fixup:
                        description:
                            - Enable/disable no SDP fix-up.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    notify_rate:
                        description:
                            - NOTIFY request rate limit (per second, per policy).
                        type: int
                    notify_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    open_contact_pinhole:
                        description:
                            - Enable/disable open pinhole for non-REGISTER Contact port.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    open_record_route_pinhole:
                        description:
                            - Enable/disable open pinhole for Record-Route port.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    open_register_pinhole:
                        description:
                            - Enable/disable open pinhole for REGISTER Contact port.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    open_via_pinhole:
                        description:
                            - Enable/disable open pinhole for Via port.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    options_rate:
                        description:
                            - OPTIONS request rate limit (per second, per policy).
                        type: int
                    options_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    prack_rate:
                        description:
                            - PRACK request rate limit (per second, per policy).
                        type: int
                    prack_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    preserve_override:
                        description:
                            - 'Override i line to preserve original IPs .'
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    provisional_invite_expiry_time:
                        description:
                            - Expiry time (10-3600, in seconds) for provisional INVITE.
                        type: int
                    publish_rate:
                        description:
                            - PUBLISH request rate limit (per second, per policy).
                        type: int
                    publish_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    refer_rate:
                        description:
                            - REFER request rate limit (per second, per policy).
                        type: int
                    refer_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    register_contact_trace:
                        description:
                            - Enable/disable trace original IP/port within the contact header of REGISTER requests.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    register_rate:
                        description:
                            - REGISTER request rate limit (per second, per policy).
                        type: int
                    register_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    rfc2543_branch:
                        description:
                            - Enable/disable support via branch compliant with RFC 2543.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    rtp:
                        description:
                            - Enable/disable create pinholes for RTP traffic to traverse firewall.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_algorithm:
                        description:
                            - Relative strength of encryption algorithms accepted in negotiation.
                        type: str
                        choices:
                            - 'high'
                            - 'medium'
                            - 'low'
                    ssl_auth_client:
                        description:
                            - Require a client certificate and authenticate it with the peer/peergrp. Source user.peer.name user.peergrp.name.
                        type: str
                    ssl_auth_server:
                        description:
                            - Authenticate the server"s certificate with the peer/peergrp. Source user.peer.name user.peergrp.name.
                        type: str
                    ssl_client_certificate:
                        description:
                            - Name of Certificate to offer to server if requested. Source vpn.certificate.local.name.
                        type: str
                    ssl_client_renegotiation:
                        description:
                            - Allow/block client renegotiation by server.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
                            - 'secure'
                    ssl_max_version:
                        description:
                            - Highest SSL/TLS version to negotiate.
                        type: str
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_min_version:
                        description:
                            - Lowest SSL/TLS version to negotiate.
                        type: str
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ssl_mode:
                        description:
                            - SSL/TLS mode for encryption & decryption of traffic.
                        type: str
                        choices:
                            - 'off'
                            - 'full'
                    ssl_pfs:
                        description:
                            - SSL Perfect Forward Secrecy.
                        type: str
                        choices:
                            - 'require'
                            - 'deny'
                            - 'allow'
                    ssl_send_empty_frags:
                        description:
                            - Send empty fragments to avoid attack on CBC IV (SSL 3.0 & TLS 1.0 only).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ssl_server_certificate:
                        description:
                            - Name of Certificate return to the client in every SSL connection. Source vpn.certificate.local.name.
                        type: str
                    status:
                        description:
                            - Enable/disable SIP.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    strict_register:
                        description:
                            - Enable/disable only allow the registrar to connect.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    subscribe_rate:
                        description:
                            - SUBSCRIBE request rate limit (per second, per policy).
                        type: int
                    subscribe_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                    unknown_header:
                        description:
                            - Action for unknown SIP header.
                        type: str
                        choices:
                            - 'discard'
                            - 'pass'
                            - 'respond'
                    update_rate:
                        description:
                            - UPDATE request rate limit (per second, per policy).
                        type: int
                    update_rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
"""

EXAMPLES = """
- name: Configure VoIP profiles.
  fortinet.fortios.fortios_voip_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      voip_profile:
          comment: "Comment."
          feature_set: "ips"
          msrp:
              log_violations: "disable"
              max_msg_size: "0"
              max_msg_size_action: "pass"
              status: "disable"
          name: "default_name_10"
          sccp:
              block_mcast: "disable"
              log_call_summary: "disable"
              log_violations: "disable"
              max_calls: "0"
              status: "disable"
              verify_header: "disable"
          sip:
              ack_rate: "0"
              ack_rate_track: "none"
              block_ack: "disable"
              block_bye: "disable"
              block_cancel: "disable"
              block_geo_red_options: "disable"
              block_info: "disable"
              block_invite: "disable"
              block_long_lines: "disable"
              block_message: "disable"
              block_notify: "disable"
              block_options: "disable"
              block_prack: "disable"
              block_publish: "disable"
              block_refer: "disable"
              block_register: "disable"
              block_subscribe: "disable"
              block_unknown: "disable"
              block_update: "disable"
              bye_rate: "0"
              bye_rate_track: "none"
              call_id_regex: "<your_own_value>"
              call_keepalive: "0"
              cancel_rate: "0"
              cancel_rate_track: "none"
              contact_fixup: "disable"
              content_type_regex: "<your_own_value>"
              hnt_restrict_source_ip: "disable"
              hosted_nat_traversal: "disable"
              info_rate: "0"
              info_rate_track: "none"
              invite_rate: "0"
              invite_rate_track: "none"
              ips_rtp: "disable"
              log_call_summary: "disable"
              log_violations: "disable"
              malformed_header_allow: "discard"
              malformed_header_call_id: "discard"
              malformed_header_contact: "discard"
              malformed_header_content_length: "discard"
              malformed_header_content_type: "discard"
              malformed_header_cseq: "discard"
              malformed_header_expires: "discard"
              malformed_header_from: "discard"
              malformed_header_max_forwards: "discard"
              malformed_header_no_proxy_require: "discard"
              malformed_header_no_require: "discard"
              malformed_header_p_asserted_identity: "discard"
              malformed_header_rack: "discard"
              malformed_header_record_route: "discard"
              malformed_header_route: "discard"
              malformed_header_rseq: "discard"
              malformed_header_sdp_a: "discard"
              malformed_header_sdp_b: "discard"
              malformed_header_sdp_c: "discard"
              malformed_header_sdp_i: "discard"
              malformed_header_sdp_k: "discard"
              malformed_header_sdp_m: "discard"
              malformed_header_sdp_o: "discard"
              malformed_header_sdp_r: "discard"
              malformed_header_sdp_s: "discard"
              malformed_header_sdp_t: "discard"
              malformed_header_sdp_v: "discard"
              malformed_header_sdp_z: "discard"
              malformed_header_to: "discard"
              malformed_header_via: "discard"
              malformed_request_line: "discard"
              max_body_length: "0"
              max_dialogs: "0"
              max_idle_dialogs: "0"
              max_line_length: "998"
              message_rate: "0"
              message_rate_track: "none"
              nat_port_range: "<your_own_value>"
              nat_trace: "disable"
              no_sdp_fixup: "disable"
              notify_rate: "0"
              notify_rate_track: "none"
              open_contact_pinhole: "disable"
              open_record_route_pinhole: "disable"
              open_register_pinhole: "disable"
              open_via_pinhole: "disable"
              options_rate: "0"
              options_rate_track: "none"
              prack_rate: "0"
              prack_rate_track: "none"
              preserve_override: "disable"
              provisional_invite_expiry_time: "210"
              publish_rate: "0"
              publish_rate_track: "none"
              refer_rate: "0"
              refer_rate_track: "none"
              register_contact_trace: "disable"
              register_rate: "0"
              register_rate_track: "none"
              rfc2543_branch: "disable"
              rtp: "disable"
              ssl_algorithm: "high"
              ssl_auth_client: "<your_own_value> (source user.peer.name user.peergrp.name)"
              ssl_auth_server: "<your_own_value> (source user.peer.name user.peergrp.name)"
              ssl_client_certificate: "<your_own_value> (source vpn.certificate.local.name)"
              ssl_client_renegotiation: "allow"
              ssl_max_version: "ssl-3.0"
              ssl_min_version: "ssl-3.0"
              ssl_mode: "off"
              ssl_pfs: "require"
              ssl_send_empty_frags: "enable"
              ssl_server_certificate: "<your_own_value> (source vpn.certificate.local.name)"
              status: "disable"
              strict_register: "disable"
              subscribe_rate: "0"
              subscribe_rate_track: "none"
              unknown_header: "discard"
              update_rate: "0"
              update_rate_track: "none"
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


def filter_voip_profile_data(json):
    option_list = ["comment", "feature_set", "msrp", "name", "sccp", "sip"]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


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


def voip_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    voip_profile_data = data["voip_profile"]

    filtered_data = filter_voip_profile_data(voip_profile_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("voip", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("voip", "profile", vdom=vdom, mkey=mkey)
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
    data_copy["voip_profile"] = filtered_data
    fos.do_member_operation(
        "voip",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("voip", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("voip", "profile", mkey=converted_data["name"], vdom=vdom)
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


def fortios_voip(data, fos, check_mode):

    if data["voip_profile"]:
        resp = voip_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("voip_profile"))
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
        "feature_set": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ips", "v_range": [["v7.4.0", ""]]},
                {"value": "voipd", "v_range": [["v7.4.0", ""]]},
                {"value": "flow", "v_range": [["v7.0.0", "v7.2.4"]]},
                {"value": "proxy", "v_range": [["v7.0.0", "v7.2.4"]]},
            ],
        },
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sip": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "rtp": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "nat_port_range": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "open_register_pinhole": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "open_contact_pinhole": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "strict_register": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "register_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "register_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "invite_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "invite_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "max_dialogs": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "max_line_length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "block_long_lines": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_unknown": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "call_keepalive": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "block_ack": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_bye": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_cancel": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_info": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_invite": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_message": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_notify": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_prack": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_publish": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_refer": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_register": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_subscribe": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_update": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "register_contact_trace": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "open_via_pinhole": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "open_record_route_pinhole": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "rfc2543_branch": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log_violations": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log_call_summary": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "nat_trace": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "subscribe_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "subscribe_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "message_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "message_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "notify_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "notify_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "refer_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "refer_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "update_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "update_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "options_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "options_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "ack_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ack_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "prack_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "prack_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "info_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "info_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "publish_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "publish_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "bye_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "bye_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "cancel_rate": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "cancel_rate_track": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "none"},
                        {"value": "src-ip"},
                        {"value": "dest-ip"},
                    ],
                },
                "preserve_override": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "no_sdp_fixup": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "contact_fixup": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "max_idle_dialogs": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "block_geo_red_options": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "hosted_nat_traversal": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "hnt_restrict_source_ip": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "call_id_regex": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "content_type_regex": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "max_body_length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "unknown_header": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_request_line": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_via": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_from": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_to": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_call_id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_cseq": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_rack": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_rseq": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_contact": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_record_route": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_route": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_expires": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_content_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_content_length": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_max_forwards": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_allow": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_p_asserted_identity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_no_require": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_no_proxy_require": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_v": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_o": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_s": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_i": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_c": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_b": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_z": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_k": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_a": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_t": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_r": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "malformed_header_sdp_m": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "discard"},
                        {"value": "pass"},
                        {"value": "respond"},
                    ],
                },
                "provisional_invite_expiry_time": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                },
                "ips_rtp": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "ssl_mode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "off"}, {"value": "full"}],
                },
                "ssl_send_empty_frags": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ssl_client_renegotiation": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "deny"},
                        {"value": "secure"},
                    ],
                },
                "ssl_algorithm": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "high"},
                        {"value": "medium"},
                        {"value": "low"},
                    ],
                },
                "ssl_pfs": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "require"},
                        {"value": "deny"},
                        {"value": "allow"},
                    ],
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
                "ssl_client_certificate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "ssl_server_certificate": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                },
                "ssl_auth_client": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ssl_auth_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
        },
        "sccp": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "block_mcast": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "verify_header": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log_call_summary": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log_violations": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "max_calls": {"v_range": [["v6.0.0", ""]], "type": "integer"},
            },
        },
        "msrp": {
            "v_range": [["v7.0.2", ""]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log_violations": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "max_msg_size": {"v_range": [["v7.0.2", ""]], "type": "integer"},
                "max_msg_size_action": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "pass"},
                        {"value": "block"},
                        {"value": "reset"},
                        {"value": "monitor"},
                    ],
                },
            },
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
        "voip_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["voip_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["voip_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "voip_profile"
        )

        is_error, has_changed, result, diff = fortios_voip(
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
