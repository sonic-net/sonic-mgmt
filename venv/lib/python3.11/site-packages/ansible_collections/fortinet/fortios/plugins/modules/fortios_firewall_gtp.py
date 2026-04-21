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
module: fortios_firewall_gtp
short_description: Configure GTP in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and gtp category.
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
    firewall_gtp:
        description:
            - Configure GTP.
        default: null
        type: dict
        suboptions:
            addr_notify:
                description:
                    - overbilling notify address
                type: str
            apn:
                description:
                    - APN.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
                    apnmember:
                        description:
                            - APN member.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - APN name. Source gtp.apn.name gtp.apngrp.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    selection_mode:
                        description:
                            - APN selection mode.
                        type: list
                        elements: str
                        choices:
                            - 'ms'
                            - 'net'
                            - 'vrf'
            apn_filter:
                description:
                    - apn filter
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            authorized_ggsns:
                description:
                    - Authorized GGSN/PGW group. Source firewall.address.name firewall.addrgrp.name.
                type: str
            authorized_ggsns6:
                description:
                    - Authorized GGSN/PGW IPv6 group. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            authorized_sgsns:
                description:
                    - Authorized SGSN/SGW group. Source firewall.address.name firewall.addrgrp.name.
                type: str
            authorized_sgsns6:
                description:
                    - Authorized SGSN/SGW IPv6 group. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            comment:
                description:
                    - Comment.
                type: str
            context_id:
                description:
                    - Overbilling context.
                type: int
            control_plane_message_rate_limit:
                description:
                    - control plane message rate limit
                type: int
            default_apn_action:
                description:
                    - default apn action
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            default_imsi_action:
                description:
                    - default imsi action
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            default_ip_action:
                description:
                    - default action for encapsulated IP traffic
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            default_noip_action:
                description:
                    - default action for encapsulated non-IP traffic
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            default_policy_action:
                description:
                    - default advanced policy action
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            denied_log:
                description:
                    - log denied
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            echo_request_interval:
                description:
                    - echo request interval (in seconds)
                type: int
            echo_requires_path_in_use:
                description:
                    - Block GTP Echo Request if no active tunnel over the associated GTP path.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            extension_log:
                description:
                    - log in extension format
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forwarded_log:
                description:
                    - log forwarded
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            global_tunnel_limit:
                description:
                    - Global tunnel limit. Source gtp.tunnel-limit.name.
                type: str
            gtp_in_gtp:
                description:
                    - gtp in gtp
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            gtpu_denied_log:
                description:
                    - Enable/disable logging of denied GTP-U packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gtpu_forwarded_log:
                description:
                    - Enable/disable logging of forwarded GTP-U packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gtpu_log_freq:
                description:
                    - Logging of frequency of GTP-U packets.
                type: int
            gtpv0:
                description:
                    - GTPv0 traffic.
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            half_close_timeout:
                description:
                    - Half-close tunnel timeout (in seconds).
                type: int
            half_open_timeout:
                description:
                    - Half-open tunnel timeout (in seconds).
                type: int
            handover_group:
                description:
                    - Handover SGSN/SGW group. Source firewall.address.name firewall.addrgrp.name.
                type: str
            handover_group6:
                description:
                    - Handover SGSN/SGW IPv6 group. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            ie_allow_list_v0v1:
                description:
                    - IE allow list. Source gtp.ie-allow-list.name.
                type: str
            ie_allow_list_v2:
                description:
                    - IE allow list. Source gtp.ie-allow-list.name.
                type: str
            ie_remove_policy:
                description:
                    - IE remove policy.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    remove_ies:
                        description:
                            - GTP IEs to be removed.
                        type: list
                        elements: str
                        choices:
                            - 'apn-restriction'
                            - 'rat-type'
                            - 'rai'
                            - 'uli'
                            - 'imei'
                    sgsn_addr:
                        description:
                            - SGSN address name. Source firewall.address.name firewall.addrgrp.name.
                        type: str
                    sgsn_addr6:
                        description:
                            - SGSN IPv6 address name. Source firewall.address6.name firewall.addrgrp6.name.
                        type: str
            ie_remover:
                description:
                    - IE removal policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ie_validation:
                description:
                    - IE validation.
                type: dict
                suboptions:
                    apn_restriction:
                        description:
                            - Validate APN restriction.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    charging_gateway_addr:
                        description:
                            - Validate charging gateway address.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    charging_ID:
                        description:
                            - Validate charging ID.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    end_user_addr:
                        description:
                            - Validate end user address.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    gsn_addr:
                        description:
                            - Validate GSN address.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    imei:
                        description:
                            - Validate IMEI(SV).
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    imsi:
                        description:
                            - Validate IMSI.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    mm_context:
                        description:
                            - Validate MM context.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ms_tzone:
                        description:
                            - Validate MS time zone.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    ms_validated:
                        description:
                            - Validate MS validated.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    msisdn:
                        description:
                            - Validate MSISDN.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    nsapi:
                        description:
                            - Validate NSAPI.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    pdp_context:
                        description:
                            - Validate PDP context.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    qos_profile:
                        description:
                            - Validate Quality of Service(QoS) profile.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rai:
                        description:
                            - Validate RAI.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    rat_type:
                        description:
                            - Validate RAT type.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    reordering_required:
                        description:
                            - Validate re-ordering required.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    selection_mode:
                        description:
                            - Validate selection mode.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    uli:
                        description:
                            - Validate user location information.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            ie_white_list_v0v1:
                description:
                    - IE white list. Source gtp.ie-white-list.name.
                type: str
            ie_white_list_v2:
                description:
                    - IE white list. Source gtp.ie-white-list.name.
                type: str
            imsi:
                description:
                    - IMSI.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
                    apnmember:
                        description:
                            - APN member.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - APN name. Source gtp.apn.name gtp.apngrp.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    mcc_mnc:
                        description:
                            - MCC MNC.
                        type: str
                    msisdn_prefix:
                        description:
                            - MSISDN prefix.
                        type: str
                    selection_mode:
                        description:
                            - APN selection mode.
                        type: list
                        elements: str
                        choices:
                            - 'ms'
                            - 'net'
                            - 'vrf'
            imsi_filter:
                description:
                    - imsi filter
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            interface_notify:
                description:
                    - overbilling interface Source system.interface.name.
                type: str
            invalid_reserved_field:
                description:
                    - Invalid reserved field in GTP header
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            invalid_sgsns_to_log:
                description:
                    - Invalid SGSN group to be logged Source firewall.address.name firewall.addrgrp.name.
                type: str
            invalid_sgsns6_to_log:
                description:
                    - Invalid SGSN IPv6 group to be logged. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            ip_filter:
                description:
                    - IP filter for encapsulted traffic
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ip_policy:
                description:
                    - IP policy.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
                    dstaddr:
                        description:
                            - Destination address name. Source firewall.address.name firewall.addrgrp.name.
                        type: str
                    dstaddr6:
                        description:
                            - Destination IPv6 address name. Source firewall.address6.name firewall.addrgrp6.name.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    srcaddr:
                        description:
                            - Source address name. Source firewall.address.name firewall.addrgrp.name.
                        type: str
                    srcaddr6:
                        description:
                            - Source IPv6 address name. Source firewall.address6.name firewall.addrgrp6.name.
                        type: str
            log_freq:
                description:
                    - Logging of frequency of GTP-C packets.
                type: int
            log_gtpu_limit:
                description:
                    - the user data log limit (0-512 bytes)
                type: int
            log_imsi_prefix:
                description:
                    - IMSI prefix for selective logging.
                type: str
            log_msisdn_prefix:
                description:
                    - the msisdn prefix for selective logging
                type: str
            max_message_length:
                description:
                    - max message length
                type: int
            message_filter_v0v1:
                description:
                    - Message filter. Source gtp.message-filter-v0v1.name.
                type: str
            message_filter_v2:
                description:
                    - Message filter. Source gtp.message-filter-v2.name.
                type: str
            message_rate_limit:
                description:
                    - Message rate limiting.
                type: dict
                suboptions:
                    create_aa_pdp_request:
                        description:
                            - Rate limit for create AA PDP context request (packets per second).
                        type: int
                    create_aa_pdp_response:
                        description:
                            - Rate limit for create AA PDP context response (packets per second).
                        type: int
                    create_mbms_request:
                        description:
                            - Rate limit for create MBMS context request (packets per second).
                        type: int
                    create_mbms_response:
                        description:
                            - Rate limit for create MBMS context response (packets per second).
                        type: int
                    create_pdp_request:
                        description:
                            - Rate limit for create PDP context request (packets per second).
                        type: int
                    create_pdp_response:
                        description:
                            - Rate limit for create PDP context response (packets per second).
                        type: int
                    delete_aa_pdp_request:
                        description:
                            - Rate limit for delete AA PDP context request (packets per second).
                        type: int
                    delete_aa_pdp_response:
                        description:
                            - Rate limit for delete AA PDP context response (packets per second).
                        type: int
                    delete_mbms_request:
                        description:
                            - Rate limit for delete MBMS context request (packets per second).
                        type: int
                    delete_mbms_response:
                        description:
                            - Rate limit for delete MBMS context response (packets per second).
                        type: int
                    delete_pdp_request:
                        description:
                            - Rate limit for delete PDP context request (packets per second).
                        type: int
                    delete_pdp_response:
                        description:
                            - Rate limit for delete PDP context response (packets per second).
                        type: int
                    echo_reponse:
                        description:
                            - Rate limit for echo response (packets per second).
                        type: int
                    echo_request:
                        description:
                            - Rate limit for echo requests (packets per second).
                        type: int
                    echo_response:
                        description:
                            - Rate limit for echo response (packets per second).
                        type: int
                    error_indication:
                        description:
                            - Rate limit for error indication (packets per second).
                        type: int
                    failure_report_request:
                        description:
                            - Rate limit for failure report request (packets per second).
                        type: int
                    failure_report_response:
                        description:
                            - Rate limit for failure report response (packets per second).
                        type: int
                    fwd_reloc_complete_ack:
                        description:
                            - Rate limit for forward relocation complete acknowledge (packets per second).
                        type: int
                    fwd_relocation_complete:
                        description:
                            - Rate limit for forward relocation complete (packets per second).
                        type: int
                    fwd_relocation_request:
                        description:
                            - Rate limit for forward relocation request (packets per second).
                        type: int
                    fwd_relocation_response:
                        description:
                            - Rate limit for forward relocation response (packets per second).
                        type: int
                    fwd_srns_context:
                        description:
                            - Rate limit for forward SRNS context (packets per second).
                        type: int
                    fwd_srns_context_ack:
                        description:
                            - Rate limit for forward SRNS context acknowledge (packets per second).
                        type: int
                    g_pdu:
                        description:
                            - Rate limit for G-PDU (packets per second).
                        type: int
                    identification_request:
                        description:
                            - Rate limit for identification request (packets per second).
                        type: int
                    identification_response:
                        description:
                            - Rate limit for identification response (packets per second).
                        type: int
                    mbms_de_reg_request:
                        description:
                            - Rate limit for MBMS de-registration request (packets per second).
                        type: int
                    mbms_de_reg_response:
                        description:
                            - Rate limit for MBMS de-registration response (packets per second).
                        type: int
                    mbms_notify_rej_request:
                        description:
                            - Rate limit for MBMS notification reject request (packets per second).
                        type: int
                    mbms_notify_rej_response:
                        description:
                            - Rate limit for MBMS notification reject response (packets per second).
                        type: int
                    mbms_notify_request:
                        description:
                            - Rate limit for MBMS notification request (packets per second).
                        type: int
                    mbms_notify_response:
                        description:
                            - Rate limit for MBMS notification response (packets per second).
                        type: int
                    mbms_reg_request:
                        description:
                            - Rate limit for MBMS registration request (packets per second).
                        type: int
                    mbms_reg_response:
                        description:
                            - Rate limit for MBMS registration response (packets per second).
                        type: int
                    mbms_ses_start_request:
                        description:
                            - Rate limit for MBMS session start request (packets per second).
                        type: int
                    mbms_ses_start_response:
                        description:
                            - Rate limit for MBMS session start response (packets per second).
                        type: int
                    mbms_ses_stop_request:
                        description:
                            - Rate limit for MBMS session stop request (packets per second).
                        type: int
                    mbms_ses_stop_response:
                        description:
                            - Rate limit for MBMS session stop response (packets per second).
                        type: int
                    note_ms_request:
                        description:
                            - Rate limit for note MS GPRS present request (packets per second).
                        type: int
                    note_ms_response:
                        description:
                            - Rate limit for note MS GPRS present response (packets per second).
                        type: int
                    pdu_notify_rej_request:
                        description:
                            - Rate limit for PDU notify reject request (packets per second).
                        type: int
                    pdu_notify_rej_response:
                        description:
                            - Rate limit for PDU notify reject response (packets per second).
                        type: int
                    pdu_notify_request:
                        description:
                            - Rate limit for PDU notify request (packets per second).
                        type: int
                    pdu_notify_response:
                        description:
                            - Rate limit for PDU notify response (packets per second).
                        type: int
                    ran_info:
                        description:
                            - Rate limit for RAN information relay (packets per second).
                        type: int
                    relocation_cancel_request:
                        description:
                            - Rate limit for relocation cancel request (packets per second).
                        type: int
                    relocation_cancel_response:
                        description:
                            - Rate limit for relocation cancel response (packets per second).
                        type: int
                    send_route_request:
                        description:
                            - Rate limit for send routing information for GPRS request (packets per second).
                        type: int
                    send_route_response:
                        description:
                            - Rate limit for send routing information for GPRS response (packets per second).
                        type: int
                    sgsn_context_ack:
                        description:
                            - Rate limit for SGSN context acknowledgement (packets per second).
                        type: int
                    sgsn_context_request:
                        description:
                            - Rate limit for SGSN context request (packets per second).
                        type: int
                    sgsn_context_response:
                        description:
                            - Rate limit for SGSN context response (packets per second).
                        type: int
                    support_ext_hdr_notify:
                        description:
                            - Rate limit for support extension headers notification (packets per second).
                        type: int
                    update_mbms_request:
                        description:
                            - Rate limit for update MBMS context request (packets per second).
                        type: int
                    update_mbms_response:
                        description:
                            - Rate limit for update MBMS context response (packets per second).
                        type: int
                    update_pdp_request:
                        description:
                            - Rate limit for update PDP context request (packets per second).
                        type: int
                    update_pdp_response:
                        description:
                            - Rate limit for update PDP context response (packets per second).
                        type: int
                    version_not_support:
                        description:
                            - Rate limit for version not supported (packets per second).
                        type: int
            message_rate_limit_v0:
                description:
                    - Message rate limiting for GTP version 0.
                type: dict
                suboptions:
                    create_pdp_request:
                        description:
                            - Rate limit (packets/s) for create PDP context request.
                        type: int
                    delete_pdp_request:
                        description:
                            - Rate limit (packets/s) for delete PDP context request.
                        type: int
                    echo_request:
                        description:
                            - Rate limit (packets/s) for echo request.
                        type: int
            message_rate_limit_v1:
                description:
                    - Message rate limiting for GTP version 1.
                type: dict
                suboptions:
                    create_pdp_request:
                        description:
                            - Rate limit (packets/s) for create PDP context request.
                        type: int
                    delete_pdp_request:
                        description:
                            - Rate limit (packets/s) for delete PDP context request.
                        type: int
                    echo_request:
                        description:
                            - Rate limit (packets/s) for echo request.
                        type: int
            message_rate_limit_v2:
                description:
                    - Message rate limiting for GTP version 2.
                type: dict
                suboptions:
                    create_session_request:
                        description:
                            - Rate limit (packets/s) for create session request.
                        type: int
                    delete_session_request:
                        description:
                            - Rate limit (packets/s) for delete session request.
                        type: int
                    echo_request:
                        description:
                            - Rate limit (packets/s) for echo request.
                        type: int
            min_message_length:
                description:
                    - min message length
                type: int
            miss_must_ie:
                description:
                    - Missing mandatory information element
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            monitor_mode:
                description:
                    - GTP monitor mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'vdom'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            noip_filter:
                description:
                    - non-IP filter for encapsulted traffic
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            noip_policy:
                description:
                    - No IP policy.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
                    end:
                        description:
                            - End of protocol range (0 - 255).
                        type: int
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    start:
                        description:
                            - Start of protocol range (0 - 255).
                        type: int
                    type:
                        description:
                            - Protocol field type.
                        type: str
                        choices:
                            - 'etsi'
                            - 'ietf'
            out_of_state_ie:
                description:
                    - Out of state information element.
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            out_of_state_message:
                description:
                    - Out of state GTP message
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            per_apn_shaper:
                description:
                    - Per APN shaper.
                type: list
                elements: dict
                suboptions:
                    apn:
                        description:
                            - APN name. Source gtp.apn.name.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    rate_limit:
                        description:
                            - Rate limit (packets/s) for create PDP context request.
                        type: int
                    version:
                        description:
                            - 'GTP version number: 0 or 1.'
                        type: int
            policy:
                description:
                    - Policy.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
                    apn_sel_mode:
                        description:
                            - APN selection mode.
                        type: list
                        elements: str
                        choices:
                            - 'ms'
                            - 'net'
                            - 'vrf'
                    apnmember:
                        description:
                            - APN member.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - APN name. Source gtp.apn.name gtp.apngrp.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    imei:
                        description:
                            - IMEI pattern.
                        type: str
                    imsi:
                        description:
                            - IMSI prefix.
                        type: str
                    imsi_prefix:
                        description:
                            - IMSI prefix.
                        type: str
                    max_apn_restriction:
                        description:
                            - Maximum APN restriction value.
                        type: str
                        choices:
                            - 'all'
                            - 'public-1'
                            - 'public-2'
                            - 'private-1'
                            - 'private-2'
                    messages:
                        description:
                            - GTP messages.
                        type: list
                        elements: str
                        choices:
                            - 'create-req'
                            - 'create-res'
                            - 'update-req'
                            - 'update-res'
                    msisdn:
                        description:
                            - MSISDN prefix.
                        type: str
                    msisdn_prefix:
                        description:
                            - MSISDN prefix.
                        type: str
                    rai:
                        description:
                            - RAI pattern.
                        type: str
                    rat_type:
                        description:
                            - RAT Type.
                        type: list
                        elements: str
                        choices:
                            - 'any'
                            - 'utran'
                            - 'geran'
                            - 'wlan'
                            - 'gan'
                            - 'hspa'
                            - 'eutran'
                            - 'virtual'
                            - 'nbiot'
                    uli:
                        description:
                            - ULI pattern.
                        type: str
            policy_filter:
                description:
                    - Advanced policy filter
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            policy_v2:
                description:
                    - Apply allow or deny action to each GTPv2-c packet.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - 'allow'
                            - 'deny'
                    apn_sel_mode:
                        description:
                            - APN selection mode.
                        type: list
                        elements: str
                        choices:
                            - 'ms'
                            - 'net'
                            - 'vrf'
                    apnmember:
                        description:
                            - APN member.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - APN name. Source gtp.apn.name gtp.apngrp.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    imsi_prefix:
                        description:
                            - IMSI prefix.
                        type: str
                    max_apn_restriction:
                        description:
                            - Maximum APN restriction value.
                        type: str
                        choices:
                            - 'all'
                            - 'public-1'
                            - 'public-2'
                            - 'private-1'
                            - 'private-2'
                    mei:
                        description:
                            - MEI pattern.
                        type: str
                    messages:
                        description:
                            - GTP messages.
                        type: list
                        elements: str
                        choices:
                            - 'create-ses-req'
                            - 'create-ses-res'
                            - 'modify-bearer-req'
                            - 'modify-bearer-res'
                    msisdn_prefix:
                        description:
                            - MSISDN prefix.
                        type: str
                    rat_type:
                        description:
                            - RAT Type.
                        type: list
                        elements: str
                        choices:
                            - 'any'
                            - 'utran'
                            - 'geran'
                            - 'wlan'
                            - 'gan'
                            - 'hspa'
                            - 'eutran'
                            - 'virtual'
                            - 'nbiot'
                            - 'ltem'
                            - 'nr'
                    uli:
                        description:
                            - GTPv2 ULI patterns (in order of CGI SAI RAI TAI ECGI LAI).
                        type: list
                        elements: str
            port_notify:
                description:
                    - overbilling notify port
                type: int
            rat_timeout_profile:
                description:
                    - RAT timeout profile. Source gtp.rat-timeout-profile.name.
                type: str
            rate_limit_mode:
                description:
                    - GTP rate limit mode.
                type: str
                choices:
                    - 'per-profile'
                    - 'per-stream'
                    - 'per-apn'
            rate_limited_log:
                description:
                    - log rate limited
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rate_sampling_interval:
                description:
                    - rate sampling interval (1-3600 seconds)
                type: int
            remove_if_echo_expires:
                description:
                    - remove if echo response expires
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            remove_if_recovery_differ:
                description:
                    - remove upon different Recovery IE
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            reserved_ie:
                description:
                    - reserved information element
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            send_delete_when_timeout:
                description:
                    - send DELETE request to path endpoints when GTPv0/v1 tunnel timeout.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            send_delete_when_timeout_v2:
                description:
                    - send DELETE request to path endpoints when GTPv2 tunnel timeout.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            spoof_src_addr:
                description:
                    - Spoofed source address for Mobile Station.
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            state_invalid_log:
                description:
                    - log state invalid
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sub_second_interval:
                description:
                    - Sub-second interval (0.1, 0.25, or 0.5 sec).
                type: str
                choices:
                    - '0.5'
                    - '0.25'
                    - '0.1'
            sub_second_sampling:
                description:
                    - Enable/disable sub-second sampling.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            traffic_count_log:
                description:
                    - log tunnel traffic counter
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tunnel_limit:
                description:
                    - tunnel limit
                type: int
            tunnel_limit_log:
                description:
                    - tunnel limit
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tunnel_timeout:
                description:
                    - Established tunnel timeout (in seconds).
                type: int
            unknown_version_action:
                description:
                    - action for unknown gtp version
                type: str
                choices:
                    - 'allow'
                    - 'deny'
            user_plane_message_rate_limit:
                description:
                    - user plane message rate limit
                type: int
            warning_threshold:
                description:
                    - Warning threshold for rate limiting (0 - 99 percent).
                type: int
"""

EXAMPLES = """
- name: Configure GTP.
  fortinet.fortios.fortios_firewall_gtp:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_gtp:
          addr_notify: "<your_own_value>"
          apn:
              -
                  action: "allow"
                  apnmember:
                      -
                          name: "default_name_7 (source gtp.apn.name gtp.apngrp.name)"
                  id: "8"
                  selection_mode: "ms"
          apn_filter: "enable"
          authorized_ggsns: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          authorized_ggsns6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          authorized_sgsns: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          authorized_sgsns6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          comment: "Comment."
          context_id: "696"
          control_plane_message_rate_limit: "0"
          default_apn_action: "allow"
          default_imsi_action: "allow"
          default_ip_action: "allow"
          default_noip_action: "allow"
          default_policy_action: "allow"
          denied_log: "enable"
          echo_request_interval: "0"
          echo_requires_path_in_use: "enable"
          extension_log: "enable"
          forwarded_log: "enable"
          global_tunnel_limit: "<your_own_value> (source gtp.tunnel-limit.name)"
          gtp_in_gtp: "allow"
          gtpu_denied_log: "enable"
          gtpu_forwarded_log: "enable"
          gtpu_log_freq: "0"
          gtpv0: "allow"
          half_close_timeout: "10"
          half_open_timeout: "300"
          handover_group: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          handover_group6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          ie_allow_list_v0v1: "<your_own_value> (source gtp.ie-allow-list.name)"
          ie_allow_list_v2: "<your_own_value> (source gtp.ie-allow-list.name)"
          ie_remove_policy:
              -
                  id: "41"
                  remove_ies: "apn-restriction"
                  sgsn_addr: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                  sgsn_addr6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          ie_remover: "enable"
          ie_validation:
              apn_restriction: "enable"
              charging_gateway_addr: "enable"
              charging_ID: "enable"
              end_user_addr: "enable"
              gsn_addr: "enable"
              imei: "enable"
              imsi: "enable"
              mm_context: "enable"
              ms_tzone: "enable"
              ms_validated: "enable"
              msisdn: "enable"
              nsapi: "enable"
              pdp_context: "enable"
              qos_profile: "enable"
              rai: "enable"
              rat_type: "enable"
              reordering_required: "enable"
              selection_mode: "enable"
              uli: "enable"
          ie_white_list_v0v1: "<your_own_value> (source gtp.ie-white-list.name)"
          ie_white_list_v2: "<your_own_value> (source gtp.ie-white-list.name)"
          imsi:
              -
                  action: "allow"
                  apnmember:
                      -
                          name: "default_name_71 (source gtp.apn.name gtp.apngrp.name)"
                  id: "72"
                  mcc_mnc: "<your_own_value>"
                  msisdn_prefix: "<your_own_value>"
                  selection_mode: "ms"
          imsi_filter: "enable"
          interface_notify: "<your_own_value> (source system.interface.name)"
          invalid_reserved_field: "allow"
          invalid_sgsns_to_log: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          invalid_sgsns6_to_log: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          ip_filter: "enable"
          ip_policy:
              -
                  action: "allow"
                  dstaddr: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                  dstaddr6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
                  id: "86"
                  srcaddr: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                  srcaddr6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
          log_freq: "0"
          log_gtpu_limit: "0"
          log_imsi_prefix: "<your_own_value>"
          log_msisdn_prefix: "<your_own_value>"
          max_message_length: "1452"
          message_filter_v0v1: "<your_own_value> (source gtp.message-filter-v0v1.name)"
          message_filter_v2: "<your_own_value> (source gtp.message-filter-v2.name)"
          message_rate_limit:
              create_aa_pdp_request: "0"
              create_aa_pdp_response: "0"
              create_mbms_request: "0"
              create_mbms_response: "0"
              create_pdp_request: "0"
              create_pdp_response: "0"
              delete_aa_pdp_request: "0"
              delete_aa_pdp_response: "0"
              delete_mbms_request: "0"
              delete_mbms_response: "0"
              delete_pdp_request: "0"
              delete_pdp_response: "0"
              echo_reponse: "0"
              echo_request: "0"
              echo_response: "0"
              error_indication: "0"
              failure_report_request: "0"
              failure_report_response: "0"
              fwd_reloc_complete_ack: "0"
              fwd_relocation_complete: "0"
              fwd_relocation_request: "0"
              fwd_relocation_response: "0"
              fwd_srns_context: "0"
              fwd_srns_context_ack: "0"
              g_pdu: "0"
              identification_request: "0"
              identification_response: "0"
              mbms_de_reg_request: "0"
              mbms_de_reg_response: "0"
              mbms_notify_rej_request: "0"
              mbms_notify_rej_response: "0"
              mbms_notify_request: "0"
              mbms_notify_response: "0"
              mbms_reg_request: "0"
              mbms_reg_response: "0"
              mbms_ses_start_request: "0"
              mbms_ses_start_response: "0"
              mbms_ses_stop_request: "0"
              mbms_ses_stop_response: "0"
              note_ms_request: "0"
              note_ms_response: "0"
              pdu_notify_rej_request: "0"
              pdu_notify_rej_response: "0"
              pdu_notify_request: "0"
              pdu_notify_response: "0"
              ran_info: "0"
              relocation_cancel_request: "0"
              relocation_cancel_response: "0"
              send_route_request: "0"
              send_route_response: "0"
              sgsn_context_ack: "0"
              sgsn_context_request: "0"
              sgsn_context_response: "0"
              support_ext_hdr_notify: "0"
              update_mbms_request: "0"
              update_mbms_response: "0"
              update_pdp_request: "0"
              update_pdp_response: "0"
              version_not_support: "0"
          message_rate_limit_v0:
              create_pdp_request: "0"
              delete_pdp_request: "0"
              echo_request: "0"
          message_rate_limit_v1:
              create_pdp_request: "0"
              delete_pdp_request: "0"
              echo_request: "0"
          message_rate_limit_v2:
              create_session_request: "0"
              delete_session_request: "0"
              echo_request: "0"
          min_message_length: "0"
          miss_must_ie: "allow"
          monitor_mode: "enable"
          name: "default_name_171"
          noip_filter: "enable"
          noip_policy:
              -
                  action: "allow"
                  end: "0"
                  id: "176"
                  start: "0"
                  type: "etsi"
          out_of_state_ie: "allow"
          out_of_state_message: "allow"
          per_apn_shaper:
              -
                  apn: "<your_own_value> (source gtp.apn.name)"
                  id: "183"
                  rate_limit: "0"
                  version: "1"
          policy:
              -
                  action: "allow"
                  apn_sel_mode: "ms"
                  apnmember:
                      -
                          name: "default_name_190 (source gtp.apn.name gtp.apngrp.name)"
                  id: "191"
                  imei: "<your_own_value>"
                  imsi: "<your_own_value>"
                  imsi_prefix: "<your_own_value>"
                  max_apn_restriction: "all"
                  messages: "create-req"
                  msisdn: "<your_own_value>"
                  msisdn_prefix: "<your_own_value>"
                  rai: "<your_own_value>"
                  rat_type: "any"
                  uli: "<your_own_value>"
          policy_filter: "enable"
          policy_v2:
              -
                  action: "allow"
                  apn_sel_mode: "ms"
                  apnmember:
                      -
                          name: "default_name_207 (source gtp.apn.name gtp.apngrp.name)"
                  id: "208"
                  imsi_prefix: "<your_own_value>"
                  max_apn_restriction: "all"
                  mei: "<your_own_value>"
                  messages: "create-ses-req"
                  msisdn_prefix: "<your_own_value>"
                  rat_type: "any"
                  uli: "<your_own_value>"
          port_notify: "21123"
          rat_timeout_profile: "<your_own_value> (source gtp.rat-timeout-profile.name)"
          rate_limit_mode: "per-profile"
          rate_limited_log: "enable"
          rate_sampling_interval: "1"
          remove_if_echo_expires: "enable"
          remove_if_recovery_differ: "enable"
          reserved_ie: "allow"
          send_delete_when_timeout: "enable"
          send_delete_when_timeout_v2: "enable"
          spoof_src_addr: "allow"
          state_invalid_log: "enable"
          sub_second_interval: "0.5"
          sub_second_sampling: "enable"
          traffic_count_log: "enable"
          tunnel_limit: "0"
          tunnel_limit_log: "enable"
          tunnel_timeout: "86400"
          unknown_version_action: "allow"
          user_plane_message_rate_limit: "0"
          warning_threshold: "0"
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


def filter_firewall_gtp_data(json):
    option_list = [
        "addr_notify",
        "apn",
        "apn_filter",
        "authorized_ggsns",
        "authorized_ggsns6",
        "authorized_sgsns",
        "authorized_sgsns6",
        "comment",
        "context_id",
        "control_plane_message_rate_limit",
        "default_apn_action",
        "default_imsi_action",
        "default_ip_action",
        "default_noip_action",
        "default_policy_action",
        "denied_log",
        "echo_request_interval",
        "echo_requires_path_in_use",
        "extension_log",
        "forwarded_log",
        "global_tunnel_limit",
        "gtp_in_gtp",
        "gtpu_denied_log",
        "gtpu_forwarded_log",
        "gtpu_log_freq",
        "gtpv0",
        "half_close_timeout",
        "half_open_timeout",
        "handover_group",
        "handover_group6",
        "ie_allow_list_v0v1",
        "ie_allow_list_v2",
        "ie_remove_policy",
        "ie_remover",
        "ie_validation",
        "ie_white_list_v0v1",
        "ie_white_list_v2",
        "imsi",
        "imsi_filter",
        "interface_notify",
        "invalid_reserved_field",
        "invalid_sgsns_to_log",
        "invalid_sgsns6_to_log",
        "ip_filter",
        "ip_policy",
        "log_freq",
        "log_gtpu_limit",
        "log_imsi_prefix",
        "log_msisdn_prefix",
        "max_message_length",
        "message_filter_v0v1",
        "message_filter_v2",
        "message_rate_limit",
        "message_rate_limit_v0",
        "message_rate_limit_v1",
        "message_rate_limit_v2",
        "min_message_length",
        "miss_must_ie",
        "monitor_mode",
        "name",
        "noip_filter",
        "noip_policy",
        "out_of_state_ie",
        "out_of_state_message",
        "per_apn_shaper",
        "policy",
        "policy_filter",
        "policy_v2",
        "port_notify",
        "rat_timeout_profile",
        "rate_limit_mode",
        "rate_limited_log",
        "rate_sampling_interval",
        "remove_if_echo_expires",
        "remove_if_recovery_differ",
        "reserved_ie",
        "send_delete_when_timeout",
        "send_delete_when_timeout_v2",
        "spoof_src_addr",
        "state_invalid_log",
        "sub_second_interval",
        "sub_second_sampling",
        "traffic_count_log",
        "tunnel_limit",
        "tunnel_limit_log",
        "tunnel_timeout",
        "unknown_version_action",
        "user_plane_message_rate_limit",
        "warning_threshold",
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
        ["apn", "selection_mode"],
        ["imsi", "selection_mode"],
        ["policy", "messages"],
        ["policy", "apn_sel_mode"],
        ["policy", "rat_type"],
        ["policy_v2", "messages"],
        ["policy_v2", "apn_sel_mode"],
        ["policy_v2", "rat_type"],
        ["policy_v2", "uli"],
        ["ie_remove_policy", "remove_ies"],
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


def firewall_gtp(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_gtp_data = data["firewall_gtp"]

    filtered_data = filter_firewall_gtp_data(firewall_gtp_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "gtp", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "gtp", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_gtp"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "gtp",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "gtp", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("firewall", "gtp", mkey=converted_data["name"], vdom=vdom)
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

    if data["firewall_gtp"]:
        resp = firewall_gtp(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_gtp"))
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
        "name": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "required": True,
        },
        "comment": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "remove_if_echo_expires": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "remove_if_recovery_differ": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "send_delete_when_timeout": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "send_delete_when_timeout_v2": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gtp_in_gtp": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "unknown_version_action": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "gtpv0": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "min_message_length": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "max_message_length": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "control_plane_message_rate_limit": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "sub_second_sampling": {
            "v_range": [["v6.2.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rate_sampling_interval": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "sub_second_interval": {
            "v_range": [["v6.2.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "0.5"}, {"value": "0.25"}, {"value": "0.1"}],
        },
        "echo_request_interval": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "user_plane_message_rate_limit": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "tunnel_limit": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "global_tunnel_limit": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "tunnel_timeout": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "half_open_timeout": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "half_close_timeout": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "default_apn_action": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "default_imsi_action": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "default_policy_action": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "default_ip_action": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "default_noip_action": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "apn_filter": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "imsi_filter": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "policy_filter": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ie_remover": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_filter": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "noip_filter": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "echo_requires_path_in_use": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "monitor_mode": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "enable"},
                {"value": "disable"},
                {
                    "value": "vdom",
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                },
            ],
        },
        "forwarded_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "denied_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rate_limited_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "state_invalid_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tunnel_limit_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "extension_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "traffic_count_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_freq": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "gtpu_forwarded_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gtpu_denied_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gtpu_log_freq": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "log_gtpu_limit": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "log_imsi_prefix": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "log_msisdn_prefix": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "invalid_reserved_field": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "reserved_ie": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "miss_must_ie": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "out_of_state_message": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "out_of_state_ie": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "spoof_src_addr": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "allow"}, {"value": "deny"}],
        },
        "handover_group": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "handover_group6": {
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v6.4.4", "v7.0.8"],
                ["v7.2.0", "v7.2.4"],
                ["v7.4.3", ""],
            ],
            "type": "string",
        },
        "authorized_sgsns": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "authorized_sgsns6": {
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v6.4.4", "v7.0.8"],
                ["v7.2.0", "v7.2.4"],
                ["v7.4.3", ""],
            ],
            "type": "string",
        },
        "invalid_sgsns_to_log": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "invalid_sgsns6_to_log": {
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v6.4.4", "v7.0.8"],
                ["v7.2.0", "v7.2.4"],
                ["v7.4.3", ""],
            ],
            "type": "string",
        },
        "authorized_ggsns": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "authorized_ggsns6": {
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v6.4.4", "v7.0.8"],
                ["v7.2.0", "v7.2.4"],
                ["v7.4.3", ""],
            ],
            "type": "string",
        },
        "apn": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                },
                "apnmember": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [
                                ["v6.0.0", "v7.0.8"],
                                ["v7.2.0", "v7.2.4"],
                                ["v7.4.3", ""],
                            ],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                },
                "action": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "deny"}],
                },
                "selection_mode": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "options": [{"value": "ms"}, {"value": "net"}, {"value": "vrf"}],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "imsi": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                },
                "mcc_mnc": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "msisdn_prefix": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "apnmember": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [
                                ["v6.0.0", "v7.0.8"],
                                ["v7.2.0", "v7.2.4"],
                                ["v7.4.3", ""],
                            ],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                },
                "action": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "deny"}],
                },
                "selection_mode": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "options": [{"value": "ms"}, {"value": "net"}, {"value": "vrf"}],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "policy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                },
                "apnmember": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [
                                ["v6.0.0", "v7.0.8"],
                                ["v7.2.0", "v7.2.4"],
                                ["v7.4.3", ""],
                            ],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                },
                "messages": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "options": [
                        {"value": "create-req"},
                        {"value": "create-res"},
                        {"value": "update-req"},
                        {"value": "update-res"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "apn_sel_mode": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "options": [{"value": "ms"}, {"value": "net"}, {"value": "vrf"}],
                    "multiple_values": True,
                    "elements": "str",
                },
                "max_apn_restriction": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [
                        {"value": "all"},
                        {"value": "public-1"},
                        {"value": "public-2"},
                        {"value": "private-1"},
                        {"value": "private-2"},
                    ],
                },
                "imsi_prefix": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "msisdn_prefix": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "rat_type": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "options": [
                        {"value": "any"},
                        {"value": "utran"},
                        {"value": "geran"},
                        {"value": "wlan"},
                        {"value": "gan"},
                        {"value": "hspa"},
                        {
                            "value": "eutran",
                            "v_range": [
                                ["v6.2.0", "v7.0.8"],
                                ["v7.2.0", "v7.2.4"],
                                ["v7.4.3", ""],
                            ],
                        },
                        {
                            "value": "virtual",
                            "v_range": [
                                ["v6.2.0", "v7.0.8"],
                                ["v7.2.0", "v7.2.4"],
                                ["v7.4.3", ""],
                            ],
                        },
                        {
                            "value": "nbiot",
                            "v_range": [
                                ["v6.2.0", "v7.0.8"],
                                ["v7.2.0", "v7.2.4"],
                                ["v7.4.3", ""],
                            ],
                        },
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "imei": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "action": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "deny"}],
                },
                "rai": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "uli": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "imsi": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
                "msisdn": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
            },
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "policy_v2": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                },
                "apnmember": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [
                                ["v6.2.0", "v7.0.8"],
                                ["v7.2.0", "v7.2.4"],
                                ["v7.4.3", ""],
                            ],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                },
                "messages": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "options": [
                        {"value": "create-ses-req"},
                        {"value": "create-ses-res"},
                        {"value": "modify-bearer-req"},
                        {"value": "modify-bearer-res"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "apn_sel_mode": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "options": [{"value": "ms"}, {"value": "net"}, {"value": "vrf"}],
                    "multiple_values": True,
                    "elements": "str",
                },
                "max_apn_restriction": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [
                        {"value": "all"},
                        {"value": "public-1"},
                        {"value": "public-2"},
                        {"value": "private-1"},
                        {"value": "private-2"},
                    ],
                },
                "imsi_prefix": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "msisdn_prefix": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "rat_type": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "options": [
                        {"value": "any"},
                        {"value": "utran"},
                        {"value": "geran"},
                        {"value": "wlan"},
                        {"value": "gan"},
                        {"value": "hspa"},
                        {"value": "eutran"},
                        {"value": "virtual"},
                        {"value": "nbiot"},
                        {
                            "value": "ltem",
                            "v_range": [
                                ["v6.4.0", "v6.4.0"],
                                ["v6.4.4", "v7.0.8"],
                                ["v7.2.0", "v7.2.4"],
                                ["v7.4.3", ""],
                            ],
                        },
                        {
                            "value": "nr",
                            "v_range": [
                                ["v6.4.0", "v6.4.0"],
                                ["v6.4.4", "v7.0.8"],
                                ["v7.2.0", "v7.2.4"],
                                ["v7.4.3", ""],
                            ],
                        },
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "mei": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "action": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "deny"}],
                },
                "uli": {
                    "v_range": [
                        ["v6.2.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.2.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "addr_notify": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "port_notify": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "interface_notify": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "context_id": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "ie_remove_policy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                },
                "sgsn_addr": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "sgsn_addr6": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v6.4.4", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "remove_ies": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "list",
                    "options": [
                        {"value": "apn-restriction"},
                        {"value": "rat-type"},
                        {"value": "rai"},
                        {"value": "uli"},
                        {"value": "imei"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "ip_policy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                },
                "srcaddr": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "dstaddr": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "srcaddr6": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v6.4.4", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "dstaddr6": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v6.4.4", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "action": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "deny"}],
                },
            },
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "noip_policy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                },
                "type": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "etsi"}, {"value": "ietf"}],
                },
                "start": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "end": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "action": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "deny"}],
                },
            },
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "message_filter_v0v1": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "message_filter_v2": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "ie_allow_list_v0v1": {
            "v_range": [["v7.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "ie_allow_list_v2": {
            "v_range": [["v7.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "rat_timeout_profile": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "ie_validation": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "imsi": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rai": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "reordering_required": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ms_validated": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "selection_mode": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "nsapi": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "charging_ID": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "end_user_addr": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mm_context": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "pdp_context": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "gsn_addr": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "msisdn": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "qos_profile": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "apn_restriction": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rat_type": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "uli": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "ms_tzone": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "imei": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "charging_gateway_addr": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "message_rate_limit": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "echo_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "echo_response": {"v_range": [["v7.4.4", ""]], "type": "integer"},
                "version_not_support": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "create_pdp_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "create_pdp_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "update_pdp_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "update_pdp_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "delete_pdp_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "delete_pdp_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "create_aa_pdp_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "create_aa_pdp_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "delete_aa_pdp_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "delete_aa_pdp_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "error_indication": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "pdu_notify_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "pdu_notify_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "pdu_notify_rej_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "pdu_notify_rej_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "support_ext_hdr_notify": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "send_route_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "send_route_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "failure_report_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "failure_report_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "note_ms_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "note_ms_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "identification_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "identification_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "sgsn_context_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "sgsn_context_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "sgsn_context_ack": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "fwd_relocation_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "fwd_relocation_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "fwd_relocation_complete": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "relocation_cancel_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "relocation_cancel_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "fwd_srns_context": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "fwd_reloc_complete_ack": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "fwd_srns_context_ack": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "ran_info": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_notify_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_notify_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_notify_rej_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_notify_rej_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "create_mbms_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "create_mbms_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "update_mbms_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "update_mbms_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "delete_mbms_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "delete_mbms_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_reg_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_reg_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_de_reg_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_de_reg_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_ses_start_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_ses_start_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_ses_stop_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "mbms_ses_stop_response": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "g_pdu": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "echo_reponse": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", "v7.4.3"],
                    ],
                    "type": "integer",
                },
            },
        },
        "rate_limit_mode": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "per-profile"},
                {"value": "per-stream"},
                {"value": "per-apn"},
            ],
        },
        "warning_threshold": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "message_rate_limit_v0": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "echo_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "create_pdp_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "delete_pdp_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
            },
        },
        "message_rate_limit_v1": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "echo_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "create_pdp_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "delete_pdp_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
            },
        },
        "message_rate_limit_v2": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "echo_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "create_session_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "delete_session_request": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
            },
        },
        "per_apn_shaper": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                    "required": True,
                },
                "apn": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "version": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
                "rate_limit": {
                    "v_range": [
                        ["v6.0.0", "v7.0.8"],
                        ["v7.2.0", "v7.2.4"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
            },
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
        },
        "ie_white_list_v0v1": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
        "ie_white_list_v2": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
    },
    "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
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
        "firewall_gtp": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_gtp"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_gtp"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_gtp"
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
