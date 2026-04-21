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
module: fmgr_firewall_gtp
short_description: Configure GTP.
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
    firewall_gtp:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            addr_notify:
                aliases: ['addr-notify']
                type: str
                description: Overbilling notify address
            apn:
                type: list
                elements: dict
                description: Apn.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'deny'
                    apnmember:
                        type: raw
                        description: (list or str) APN member.
                    id:
                        type: int
                        description: ID.
                    selection_mode:
                        aliases: ['selection-mode']
                        type: list
                        elements: str
                        description: APN selection mode.
                        choices:
                            - 'ms'
                            - 'net'
                            - 'vrf'
            apn_filter:
                aliases: ['apn-filter']
                type: str
                description: Apn filter
                choices:
                    - 'disable'
                    - 'enable'
            authorized_ggsns:
                aliases: ['authorized-ggsns']
                type: str
                description: Authorized GGSN group
            authorized_sgsns:
                aliases: ['authorized-sgsns']
                type: str
                description: Authorized SGSN group
            comment:
                type: str
                description: Comment.
            context_id:
                aliases: ['context-id']
                type: int
                description: Overbilling context.
            control_plane_message_rate_limit:
                aliases: ['control-plane-message-rate-limit']
                type: int
                description: Control plane message rate limit
            default_apn_action:
                aliases: ['default-apn-action']
                type: str
                description: Default apn action
                choices:
                    - 'allow'
                    - 'deny'
            default_imsi_action:
                aliases: ['default-imsi-action']
                type: str
                description: Default imsi action
                choices:
                    - 'allow'
                    - 'deny'
            default_ip_action:
                aliases: ['default-ip-action']
                type: str
                description: Default action for encapsulated IP traffic
                choices:
                    - 'allow'
                    - 'deny'
            default_noip_action:
                aliases: ['default-noip-action']
                type: str
                description: Default action for encapsulated non-IP traffic
                choices:
                    - 'allow'
                    - 'deny'
            default_policy_action:
                aliases: ['default-policy-action']
                type: str
                description: Default advanced policy action
                choices:
                    - 'allow'
                    - 'deny'
            denied_log:
                aliases: ['denied-log']
                type: str
                description: Log denied
                choices:
                    - 'disable'
                    - 'enable'
            echo_request_interval:
                aliases: ['echo-request-interval']
                type: int
                description: Echo request interval
            extension_log:
                aliases: ['extension-log']
                type: str
                description: Log in extension format
                choices:
                    - 'disable'
                    - 'enable'
            forwarded_log:
                aliases: ['forwarded-log']
                type: str
                description: Log forwarded
                choices:
                    - 'disable'
                    - 'enable'
            global_tunnel_limit:
                aliases: ['global-tunnel-limit']
                type: str
                description: Global tunnel limit.
            gtp_in_gtp:
                aliases: ['gtp-in-gtp']
                type: str
                description: Gtp in gtp
                choices:
                    - 'allow'
                    - 'deny'
            gtpu_denied_log:
                aliases: ['gtpu-denied-log']
                type: str
                description: Enable/disable logging of denied GTP-U packets.
                choices:
                    - 'disable'
                    - 'enable'
            gtpu_forwarded_log:
                aliases: ['gtpu-forwarded-log']
                type: str
                description: Enable/disable logging of forwarded GTP-U packets.
                choices:
                    - 'disable'
                    - 'enable'
            gtpu_log_freq:
                aliases: ['gtpu-log-freq']
                type: int
                description: Logging of frequency of GTP-U packets.
            half_close_timeout:
                aliases: ['half-close-timeout']
                type: int
                description: Half-close tunnel timeout
            half_open_timeout:
                aliases: ['half-open-timeout']
                type: int
                description: Half-open tunnel timeout
            handover_group:
                aliases: ['handover-group']
                type: str
                description: Handover SGSN group
            ie_remove_policy:
                aliases: ['ie-remove-policy']
                type: list
                elements: dict
                description: Ie remove policy.
                suboptions:
                    id:
                        type: int
                        description: ID.
                    remove_ies:
                        aliases: ['remove-ies']
                        type: list
                        elements: str
                        description: GTP IEs to be removed.
                        choices:
                            - 'apn-restriction'
                            - 'rat-type'
                            - 'rai'
                            - 'uli'
                            - 'imei'
                    sgsn_addr:
                        aliases: ['sgsn-addr']
                        type: str
                        description: SGSN address name.
                    sgsn_addr6:
                        aliases: ['sgsn-addr6']
                        type: str
                        description: SGSN IPv6 address name.
            ie_remover:
                aliases: ['ie-remover']
                type: str
                description: IE removal policy.
                choices:
                    - 'disable'
                    - 'enable'
            ie_white_list_v0v1:
                aliases: ['ie-white-list-v0v1']
                type: str
                description: IE white list.
            ie_white_list_v2:
                aliases: ['ie-white-list-v2']
                type: str
                description: IE white list.
            imsi:
                type: list
                elements: dict
                description: Imsi.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'deny'
                    apnmember:
                        type: raw
                        description: (list or str) APN member.
                    id:
                        type: int
                        description: ID.
                    mcc_mnc:
                        aliases: ['mcc-mnc']
                        type: str
                        description: MCC MNC.
                    msisdn_prefix:
                        aliases: ['msisdn-prefix']
                        type: str
                        description: MSISDN prefix.
                    selection_mode:
                        aliases: ['selection-mode']
                        type: list
                        elements: str
                        description: APN selection mode.
                        choices:
                            - 'ms'
                            - 'net'
                            - 'vrf'
            imsi_filter:
                aliases: ['imsi-filter']
                type: str
                description: Imsi filter
                choices:
                    - 'disable'
                    - 'enable'
            interface_notify:
                aliases: ['interface-notify']
                type: str
                description: Overbilling interface
            invalid_reserved_field:
                aliases: ['invalid-reserved-field']
                type: str
                description: Invalid reserved field in GTP header
                choices:
                    - 'allow'
                    - 'deny'
            invalid_sgsns_to_log:
                aliases: ['invalid-sgsns-to-log']
                type: str
                description: Invalid SGSN group to be logged
            ip_filter:
                aliases: ['ip-filter']
                type: str
                description: IP filter for encapsulted traffic
                choices:
                    - 'disable'
                    - 'enable'
            ip_policy:
                aliases: ['ip-policy']
                type: list
                elements: dict
                description: Ip policy.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'deny'
                    dstaddr:
                        type: str
                        description: Destination address name.
                    id:
                        type: int
                        description: ID.
                    srcaddr:
                        type: str
                        description: Source address name.
                    dstaddr6:
                        type: str
                        description: Destination IPv6 address name.
                    srcaddr6:
                        type: str
                        description: Source IPv6 address name.
            log_freq:
                aliases: ['log-freq']
                type: int
                description: Logging of frequency of GTP-C packets.
            log_gtpu_limit:
                aliases: ['log-gtpu-limit']
                type: int
                description: The user data log limit
            log_imsi_prefix:
                aliases: ['log-imsi-prefix']
                type: str
                description: IMSI prefix for selective logging.
            log_msisdn_prefix:
                aliases: ['log-msisdn-prefix']
                type: str
                description: The msisdn prefix for selective logging
            max_message_length:
                aliases: ['max-message-length']
                type: int
                description: Max message length
            message_filter_v0v1:
                aliases: ['message-filter-v0v1']
                type: str
                description: Message filter.
            message_filter_v2:
                aliases: ['message-filter-v2']
                type: str
                description: Message filter.
            min_message_length:
                aliases: ['min-message-length']
                type: int
                description: Min message length
            miss_must_ie:
                aliases: ['miss-must-ie']
                type: str
                description: Missing mandatory information element
                choices:
                    - 'allow'
                    - 'deny'
            monitor_mode:
                aliases: ['monitor-mode']
                type: str
                description: GTP monitor mode
                choices:
                    - 'disable'
                    - 'enable'
                    - 'vdom'
            name:
                type: str
                description: Profile name.
                required: true
            noip_filter:
                aliases: ['noip-filter']
                type: str
                description: Non-IP filter for encapsulted traffic
                choices:
                    - 'disable'
                    - 'enable'
            noip_policy:
                aliases: ['noip-policy']
                type: list
                elements: dict
                description: Noip policy.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'deny'
                    end:
                        type: int
                        description: End of protocol range
                    id:
                        type: int
                        description: ID.
                    start:
                        type: int
                        description: Start of protocol range
                    type:
                        type: str
                        description: Protocol field type.
                        choices:
                            - 'etsi'
                            - 'ietf'
            out_of_state_ie:
                aliases: ['out-of-state-ie']
                type: str
                description: Out of state information element.
                choices:
                    - 'allow'
                    - 'deny'
            out_of_state_message:
                aliases: ['out-of-state-message']
                type: str
                description: Out of state GTP message
                choices:
                    - 'allow'
                    - 'deny'
            per_apn_shaper:
                aliases: ['per-apn-shaper']
                type: list
                elements: dict
                description: Per apn shaper.
                suboptions:
                    apn:
                        type: str
                        description: APN name.
                    id:
                        type: int
                        description: ID.
                    rate_limit:
                        aliases: ['rate-limit']
                        type: int
                        description: Rate limit
                    version:
                        type: int
                        description: GTP version number
            policy:
                type: list
                elements: dict
                description: Policy.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'allow'
                            - 'deny'
                    apn_sel_mode:
                        aliases: ['apn-sel-mode']
                        type: list
                        elements: str
                        description: APN selection mode.
                        choices:
                            - 'ms'
                            - 'net'
                            - 'vrf'
                    apnmember:
                        type: raw
                        description: (list or str) APN member.
                    id:
                        type: int
                        description: ID.
                    imei:
                        type: str
                        description: IMEI
                    imsi:
                        type: str
                        description: IMSI prefix.
                    max_apn_restriction:
                        aliases: ['max-apn-restriction']
                        type: str
                        description: Maximum APN restriction value.
                        choices:
                            - 'all'
                            - 'public-1'
                            - 'public-2'
                            - 'private-1'
                            - 'private-2'
                    messages:
                        type: list
                        elements: str
                        description: GTP messages.
                        choices:
                            - 'create-req'
                            - 'create-res'
                            - 'update-req'
                            - 'update-res'
                    msisdn:
                        type: str
                        description: MSISDN prefix.
                    rai:
                        type: str
                        description: RAI pattern.
                    rat_type:
                        aliases: ['rat-type']
                        type: list
                        elements: str
                        description: RAT Type.
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
                        type: str
                        description: ULI pattern.
                    imsi_prefix:
                        aliases: ['imsi-prefix']
                        type: str
                        description: IMSI prefix.
                    msisdn_prefix:
                        aliases: ['msisdn-prefix']
                        type: str
                        description: MSISDN prefix.
                    apn:
                        type: str
                        description: APN subfix.
            policy_filter:
                aliases: ['policy-filter']
                type: str
                description: Advanced policy filter
                choices:
                    - 'disable'
                    - 'enable'
            port_notify:
                aliases: ['port-notify']
                type: int
                description: Overbilling notify port
            rate_limit_mode:
                aliases: ['rate-limit-mode']
                type: str
                description: GTP rate limit mode.
                choices:
                    - 'per-profile'
                    - 'per-stream'
                    - 'per-apn'
            rate_limited_log:
                aliases: ['rate-limited-log']
                type: str
                description: Log rate limited
                choices:
                    - 'disable'
                    - 'enable'
            rate_sampling_interval:
                aliases: ['rate-sampling-interval']
                type: int
                description: Rate sampling interval
            remove_if_echo_expires:
                aliases: ['remove-if-echo-expires']
                type: str
                description: Remove if echo response expires
                choices:
                    - 'disable'
                    - 'enable'
            remove_if_recovery_differ:
                aliases: ['remove-if-recovery-differ']
                type: str
                description: Remove upon different Recovery IE
                choices:
                    - 'disable'
                    - 'enable'
            reserved_ie:
                aliases: ['reserved-ie']
                type: str
                description: Reserved information element
                choices:
                    - 'allow'
                    - 'deny'
            send_delete_when_timeout:
                aliases: ['send-delete-when-timeout']
                type: str
                description: Send DELETE request to path endpoints when GTPv0/v1 tunnel timeout.
                choices:
                    - 'disable'
                    - 'enable'
            send_delete_when_timeout_v2:
                aliases: ['send-delete-when-timeout-v2']
                type: str
                description: Send DELETE request to path endpoints when GTPv2 tunnel timeout.
                choices:
                    - 'disable'
                    - 'enable'
            spoof_src_addr:
                aliases: ['spoof-src-addr']
                type: str
                description: Spoofed source address for Mobile Station.
                choices:
                    - 'allow'
                    - 'deny'
            state_invalid_log:
                aliases: ['state-invalid-log']
                type: str
                description: Log state invalid
                choices:
                    - 'disable'
                    - 'enable'
            traffic_count_log:
                aliases: ['traffic-count-log']
                type: str
                description: Log tunnel traffic counter
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_limit:
                aliases: ['tunnel-limit']
                type: int
                description: Tunnel limit
            tunnel_limit_log:
                aliases: ['tunnel-limit-log']
                type: str
                description: Tunnel limit
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_timeout:
                aliases: ['tunnel-timeout']
                type: int
                description: Established tunnel timeout
            unknown_version_action:
                aliases: ['unknown-version-action']
                type: str
                description: Action for unknown gtp version
                choices:
                    - 'allow'
                    - 'deny'
            user_plane_message_rate_limit:
                aliases: ['user-plane-message-rate-limit']
                type: int
                description: User plane message rate limit
            warning_threshold:
                aliases: ['warning-threshold']
                type: int
                description: Warning threshold for rate limiting
            policy_v2:
                aliases: ['policy-v2']
                type: list
                elements: dict
                description: Policy v2.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'deny'
                            - 'allow'
                    apn_sel_mode:
                        aliases: ['apn-sel-mode']
                        type: list
                        elements: str
                        description: APN selection mode.
                        choices:
                            - 'ms'
                            - 'net'
                            - 'vrf'
                    apnmember:
                        type: raw
                        description: (list or str) APN member.
                    id:
                        type: int
                        description: ID.
                    imsi_prefix:
                        aliases: ['imsi-prefix']
                        type: str
                        description: IMSI prefix.
                    max_apn_restriction:
                        aliases: ['max-apn-restriction']
                        type: str
                        description: Maximum APN restriction value.
                        choices:
                            - 'all'
                            - 'public-1'
                            - 'public-2'
                            - 'private-1'
                            - 'private-2'
                    mei:
                        type: str
                        description: MEI pattern.
                    messages:
                        type: list
                        elements: str
                        description: GTP messages.
                        choices:
                            - 'create-ses-req'
                            - 'create-ses-res'
                            - 'modify-bearer-req'
                            - 'modify-bearer-res'
                    msisdn_prefix:
                        aliases: ['msisdn-prefix']
                        type: str
                        description: MSISDN prefix.
                    rat_type:
                        aliases: ['rat-type']
                        type: list
                        elements: str
                        description: RAT Type.
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
                        type: raw
                        description: (list) GTPv2 ULI patterns
            sub_second_interval:
                aliases: ['sub-second-interval']
                type: str
                description: Sub-second interval
                choices:
                    - '0.1'
                    - '0.25'
                    - '0.5'
            sub_second_sampling:
                aliases: ['sub-second-sampling']
                type: str
                description: Enable/disable sub-second sampling.
                choices:
                    - 'disable'
                    - 'enable'
            authorized_ggsns6:
                aliases: ['authorized-ggsns6']
                type: str
                description: Authorized GGSN/PGW IPv6 group.
            authorized_sgsns6:
                aliases: ['authorized-sgsns6']
                type: str
                description: Authorized SGSN/SGW IPv6 group.
            handover_group6:
                aliases: ['handover-group6']
                type: str
                description: Handover SGSN/SGW IPv6 group.
            invalid_sgsns6_to_log:
                aliases: ['invalid-sgsns6-to-log']
                type: str
                description: Invalid SGSN IPv6 group to be logged.
            ie_validation:
                aliases: ['ie-validation']
                type: dict
                description: Ie validation.
                suboptions:
                    apn_restriction:
                        aliases: ['apn-restriction']
                        type: str
                        description: Validate APN restriction.
                        choices:
                            - 'disable'
                            - 'enable'
                    charging_ID:
                        aliases: ['charging-ID']
                        type: str
                        description: Validate charging ID.
                        choices:
                            - 'disable'
                            - 'enable'
                    charging_gateway_addr:
                        aliases: ['charging-gateway-addr']
                        type: str
                        description: Validate charging gateway address.
                        choices:
                            - 'disable'
                            - 'enable'
                    end_user_addr:
                        aliases: ['end-user-addr']
                        type: str
                        description: Validate end user address.
                        choices:
                            - 'disable'
                            - 'enable'
                    gsn_addr:
                        aliases: ['gsn-addr']
                        type: str
                        description: Validate GSN address.
                        choices:
                            - 'disable'
                            - 'enable'
                    imei:
                        type: str
                        description: Validate IMEI
                        choices:
                            - 'disable'
                            - 'enable'
                    imsi:
                        type: str
                        description: Validate IMSI.
                        choices:
                            - 'disable'
                            - 'enable'
                    mm_context:
                        aliases: ['mm-context']
                        type: str
                        description: Validate MM context.
                        choices:
                            - 'disable'
                            - 'enable'
                    ms_tzone:
                        aliases: ['ms-tzone']
                        type: str
                        description: Validate MS time zone.
                        choices:
                            - 'disable'
                            - 'enable'
                    ms_validated:
                        aliases: ['ms-validated']
                        type: str
                        description: Validate MS validated.
                        choices:
                            - 'disable'
                            - 'enable'
                    msisdn:
                        type: str
                        description: Validate MSISDN.
                        choices:
                            - 'disable'
                            - 'enable'
                    nsapi:
                        type: str
                        description: Validate NSAPI.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdp_context:
                        aliases: ['pdp-context']
                        type: str
                        description: Validate PDP context.
                        choices:
                            - 'disable'
                            - 'enable'
                    qos_profile:
                        aliases: ['qos-profile']
                        type: str
                        description: Validate Quality of Service
                        choices:
                            - 'disable'
                            - 'enable'
                    rai:
                        type: str
                        description: Validate RAI.
                        choices:
                            - 'disable'
                            - 'enable'
                    rat_type:
                        aliases: ['rat-type']
                        type: str
                        description: Validate RAT type.
                        choices:
                            - 'disable'
                            - 'enable'
                    reordering_required:
                        aliases: ['reordering-required']
                        type: str
                        description: Validate re-ordering required.
                        choices:
                            - 'disable'
                            - 'enable'
                    selection_mode:
                        aliases: ['selection-mode']
                        type: str
                        description: Validate selection mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    uli:
                        type: str
                        description: Validate user location information.
                        choices:
                            - 'disable'
                            - 'enable'
            message_rate_limit:
                aliases: ['message-rate-limit']
                type: dict
                description: Message rate limit.
                suboptions:
                    create_aa_pdp_request:
                        aliases: ['create-aa-pdp-request']
                        type: int
                        description: Rate limit for create AA PDP context request
                    create_aa_pdp_response:
                        aliases: ['create-aa-pdp-response']
                        type: int
                        description: Rate limit for create AA PDP context response
                    create_mbms_request:
                        aliases: ['create-mbms-request']
                        type: int
                        description: Rate limit for create MBMS context request
                    create_mbms_response:
                        aliases: ['create-mbms-response']
                        type: int
                        description: Rate limit for create MBMS context response
                    create_pdp_request:
                        aliases: ['create-pdp-request']
                        type: int
                        description: Rate limit for create PDP context request
                    create_pdp_response:
                        aliases: ['create-pdp-response']
                        type: int
                        description: Rate limit for create PDP context response
                    delete_aa_pdp_request:
                        aliases: ['delete-aa-pdp-request']
                        type: int
                        description: Rate limit for delete AA PDP context request
                    delete_aa_pdp_response:
                        aliases: ['delete-aa-pdp-response']
                        type: int
                        description: Rate limit for delete AA PDP context response
                    delete_mbms_request:
                        aliases: ['delete-mbms-request']
                        type: int
                        description: Rate limit for delete MBMS context request
                    delete_mbms_response:
                        aliases: ['delete-mbms-response']
                        type: int
                        description: Rate limit for delete MBMS context response
                    delete_pdp_request:
                        aliases: ['delete-pdp-request']
                        type: int
                        description: Rate limit for delete PDP context request
                    delete_pdp_response:
                        aliases: ['delete-pdp-response']
                        type: int
                        description: Rate limit for delete PDP context response
                    echo_reponse:
                        aliases: ['echo-reponse']
                        type: int
                        description: Rate limit for echo response
                    echo_request:
                        aliases: ['echo-request']
                        type: int
                        description: Rate limit for echo requests
                    error_indication:
                        aliases: ['error-indication']
                        type: int
                        description: Rate limit for error indication
                    failure_report_request:
                        aliases: ['failure-report-request']
                        type: int
                        description: Rate limit for failure report request
                    failure_report_response:
                        aliases: ['failure-report-response']
                        type: int
                        description: Rate limit for failure report response
                    fwd_reloc_complete_ack:
                        aliases: ['fwd-reloc-complete-ack']
                        type: int
                        description: Rate limit for forward relocation complete acknowledge
                    fwd_relocation_complete:
                        aliases: ['fwd-relocation-complete']
                        type: int
                        description: Rate limit for forward relocation complete
                    fwd_relocation_request:
                        aliases: ['fwd-relocation-request']
                        type: int
                        description: Rate limit for forward relocation request
                    fwd_relocation_response:
                        aliases: ['fwd-relocation-response']
                        type: int
                        description: Rate limit for forward relocation response
                    fwd_srns_context:
                        aliases: ['fwd-srns-context']
                        type: int
                        description: Rate limit for forward SRNS context
                    fwd_srns_context_ack:
                        aliases: ['fwd-srns-context-ack']
                        type: int
                        description: Rate limit for forward SRNS context acknowledge
                    g_pdu:
                        aliases: ['g-pdu']
                        type: int
                        description: Rate limit for G-PDU
                    identification_request:
                        aliases: ['identification-request']
                        type: int
                        description: Rate limit for identification request
                    identification_response:
                        aliases: ['identification-response']
                        type: int
                        description: Rate limit for identification response
                    mbms_de_reg_request:
                        aliases: ['mbms-de-reg-request']
                        type: int
                        description: Rate limit for MBMS de-registration request
                    mbms_de_reg_response:
                        aliases: ['mbms-de-reg-response']
                        type: int
                        description: Rate limit for MBMS de-registration response
                    mbms_notify_rej_request:
                        aliases: ['mbms-notify-rej-request']
                        type: int
                        description: Rate limit for MBMS notification reject request
                    mbms_notify_rej_response:
                        aliases: ['mbms-notify-rej-response']
                        type: int
                        description: Rate limit for MBMS notification reject response
                    mbms_notify_request:
                        aliases: ['mbms-notify-request']
                        type: int
                        description: Rate limit for MBMS notification request
                    mbms_notify_response:
                        aliases: ['mbms-notify-response']
                        type: int
                        description: Rate limit for MBMS notification response
                    mbms_reg_request:
                        aliases: ['mbms-reg-request']
                        type: int
                        description: Rate limit for MBMS registration request
                    mbms_reg_response:
                        aliases: ['mbms-reg-response']
                        type: int
                        description: Rate limit for MBMS registration response
                    mbms_ses_start_request:
                        aliases: ['mbms-ses-start-request']
                        type: int
                        description: Rate limit for MBMS session start request
                    mbms_ses_start_response:
                        aliases: ['mbms-ses-start-response']
                        type: int
                        description: Rate limit for MBMS session start response
                    mbms_ses_stop_request:
                        aliases: ['mbms-ses-stop-request']
                        type: int
                        description: Rate limit for MBMS session stop request
                    mbms_ses_stop_response:
                        aliases: ['mbms-ses-stop-response']
                        type: int
                        description: Rate limit for MBMS session stop response
                    note_ms_request:
                        aliases: ['note-ms-request']
                        type: int
                        description: Rate limit for note MS GPRS present request
                    note_ms_response:
                        aliases: ['note-ms-response']
                        type: int
                        description: Rate limit for note MS GPRS present response
                    pdu_notify_rej_request:
                        aliases: ['pdu-notify-rej-request']
                        type: int
                        description: Rate limit for PDU notify reject request
                    pdu_notify_rej_response:
                        aliases: ['pdu-notify-rej-response']
                        type: int
                        description: Rate limit for PDU notify reject response
                    pdu_notify_request:
                        aliases: ['pdu-notify-request']
                        type: int
                        description: Rate limit for PDU notify request
                    pdu_notify_response:
                        aliases: ['pdu-notify-response']
                        type: int
                        description: Rate limit for PDU notify response
                    ran_info:
                        aliases: ['ran-info']
                        type: int
                        description: Rate limit for RAN information relay
                    relocation_cancel_request:
                        aliases: ['relocation-cancel-request']
                        type: int
                        description: Rate limit for relocation cancel request
                    relocation_cancel_response:
                        aliases: ['relocation-cancel-response']
                        type: int
                        description: Rate limit for relocation cancel response
                    send_route_request:
                        aliases: ['send-route-request']
                        type: int
                        description: Rate limit for send routing information for GPRS request
                    send_route_response:
                        aliases: ['send-route-response']
                        type: int
                        description: Rate limit for send routing information for GPRS response
                    sgsn_context_ack:
                        aliases: ['sgsn-context-ack']
                        type: int
                        description: Rate limit for SGSN context acknowledgement
                    sgsn_context_request:
                        aliases: ['sgsn-context-request']
                        type: int
                        description: Rate limit for SGSN context request
                    sgsn_context_response:
                        aliases: ['sgsn-context-response']
                        type: int
                        description: Rate limit for SGSN context response
                    support_ext_hdr_notify:
                        aliases: ['support-ext-hdr-notify']
                        type: int
                        description: Rate limit for support extension headers notification
                    update_mbms_request:
                        aliases: ['update-mbms-request']
                        type: int
                        description: Rate limit for update MBMS context request
                    update_mbms_response:
                        aliases: ['update-mbms-response']
                        type: int
                        description: Rate limit for update MBMS context response
                    update_pdp_request:
                        aliases: ['update-pdp-request']
                        type: int
                        description: Rate limit for update PDP context request
                    update_pdp_response:
                        aliases: ['update-pdp-response']
                        type: int
                        description: Rate limit for update PDP context response
                    version_not_support:
                        aliases: ['version-not-support']
                        type: int
                        description: Rate limit for version not supported
                    echo_response:
                        aliases: ['echo-response']
                        type: int
                        description: Rate limit for echo response
            message_rate_limit_v0:
                aliases: ['message-rate-limit-v0']
                type: dict
                description: Message rate limit v0.
                suboptions:
                    create_pdp_request:
                        aliases: ['create-pdp-request']
                        type: int
                        description: Rate limit
                    delete_pdp_request:
                        aliases: ['delete-pdp-request']
                        type: int
                        description: Rate limit
                    echo_request:
                        aliases: ['echo-request']
                        type: int
                        description: Rate limit
            message_rate_limit_v1:
                aliases: ['message-rate-limit-v1']
                type: dict
                description: Message rate limit v1.
                suboptions:
                    create_pdp_request:
                        aliases: ['create-pdp-request']
                        type: int
                        description: Rate limit
                    delete_pdp_request:
                        aliases: ['delete-pdp-request']
                        type: int
                        description: Rate limit
                    echo_request:
                        aliases: ['echo-request']
                        type: int
                        description: Rate limit
            message_rate_limit_v2:
                aliases: ['message-rate-limit-v2']
                type: dict
                description: Message rate limit v2.
                suboptions:
                    create_session_request:
                        aliases: ['create-session-request']
                        type: int
                        description: Rate limit
                    delete_session_request:
                        aliases: ['delete-session-request']
                        type: int
                        description: Rate limit
                    echo_request:
                        aliases: ['echo-request']
                        type: int
                        description: Rate limit
            ie_allow_list_v0v1:
                aliases: ['ie-allow-list-v0v1']
                type: str
                description: IE allow list.
            ie_allow_list_v2:
                aliases: ['ie-allow-list-v2']
                type: str
                description: IE allow list.
            rat_timeout_profile:
                aliases: ['rat-timeout-profile']
                type: str
                description: RAT timeout profile.
            message_filter:
                aliases: ['message-filter']
                type: dict
                description: Message filter.
                suboptions:
                    create_aa_pdp:
                        aliases: ['create-aa-pdp']
                        type: str
                        description: Create AA PDP.
                        choices:
                            - 'allow'
                            - 'deny'
                    create_mbms:
                        aliases: ['create-mbms']
                        type: str
                        description: Create MBMS.
                        choices:
                            - 'allow'
                            - 'deny'
                    create_pdp:
                        aliases: ['create-pdp']
                        type: str
                        description: Create PDP.
                        choices:
                            - 'allow'
                            - 'deny'
                    data_record:
                        aliases: ['data-record']
                        type: str
                        description: Data record.
                        choices:
                            - 'allow'
                            - 'deny'
                    delete_aa_pdp:
                        aliases: ['delete-aa-pdp']
                        type: str
                        description: Delete AA PDP.
                        choices:
                            - 'allow'
                            - 'deny'
                    delete_mbms:
                        aliases: ['delete-mbms']
                        type: str
                        description: Delete MBMS.
                        choices:
                            - 'allow'
                            - 'deny'
                    delete_pdp:
                        aliases: ['delete-pdp']
                        type: str
                        description: Delete PDP.
                        choices:
                            - 'allow'
                            - 'deny'
                    echo:
                        type: str
                        description: Echo.
                        choices:
                            - 'allow'
                            - 'deny'
                    error_indication:
                        aliases: ['error-indication']
                        type: str
                        description: Error indication.
                        choices:
                            - 'allow'
                            - 'deny'
                    failure_report:
                        aliases: ['failure-report']
                        type: str
                        description: Failure report.
                        choices:
                            - 'allow'
                            - 'deny'
                    fwd_relocation:
                        aliases: ['fwd-relocation']
                        type: str
                        description: Forward relocation.
                        choices:
                            - 'allow'
                            - 'deny'
                    fwd_srns_context:
                        aliases: ['fwd-srns-context']
                        type: str
                        description: Forward SRNS context.
                        choices:
                            - 'allow'
                            - 'deny'
                    gtp_pdu:
                        aliases: ['gtp-pdu']
                        type: str
                        description: GTP PDU.
                        choices:
                            - 'allow'
                            - 'deny'
                    identification:
                        type: str
                        description: Identification.
                        choices:
                            - 'allow'
                            - 'deny'
                    mbms_notification:
                        aliases: ['mbms-notification']
                        type: str
                        description: MBMS notification.
                        choices:
                            - 'allow'
                            - 'deny'
                    node_alive:
                        aliases: ['node-alive']
                        type: str
                        description: Node alive.
                        choices:
                            - 'allow'
                            - 'deny'
                    note_ms_present:
                        aliases: ['note-ms-present']
                        type: str
                        description: Note MS present.
                        choices:
                            - 'allow'
                            - 'deny'
                    pdu_notification:
                        aliases: ['pdu-notification']
                        type: str
                        description: PDU notification.
                        choices:
                            - 'allow'
                            - 'deny'
                    ran_info:
                        aliases: ['ran-info']
                        type: str
                        description: Ran info.
                        choices:
                            - 'allow'
                            - 'deny'
                    redirection:
                        type: str
                        description: Redirection.
                        choices:
                            - 'allow'
                            - 'deny'
                    relocation_cancel:
                        aliases: ['relocation-cancel']
                        type: str
                        description: Relocation cancel.
                        choices:
                            - 'allow'
                            - 'deny'
                    send_route:
                        aliases: ['send-route']
                        type: str
                        description: Send route.
                        choices:
                            - 'allow'
                            - 'deny'
                    sgsn_context:
                        aliases: ['sgsn-context']
                        type: str
                        description: SGSN context.
                        choices:
                            - 'allow'
                            - 'deny'
                    support_extension:
                        aliases: ['support-extension']
                        type: str
                        description: Support extension.
                        choices:
                            - 'allow'
                            - 'deny'
                    unknown_message_action:
                        aliases: ['unknown-message-action']
                        type: str
                        description: Unknown message action.
                        choices:
                            - 'allow'
                            - 'deny'
                    update_mbms:
                        aliases: ['update-mbms']
                        type: str
                        description: Update MBMS.
                        choices:
                            - 'allow'
                            - 'deny'
                    update_pdp:
                        aliases: ['update-pdp']
                        type: str
                        description: Update PDP.
                        choices:
                            - 'allow'
                            - 'deny'
                    version_not_support:
                        aliases: ['version-not-support']
                        type: str
                        description: Version not supported.
                        choices:
                            - 'allow'
                            - 'deny'
            gtpv0:
                type: str
                description: GTPv0 traffic.
                choices:
                    - 'allow'
                    - 'deny'
            echo_requires_path_in_use:
                aliases: ['echo-requires-path-in-use']
                type: str
                description: Block GTP Echo Request if no active tunnel over the associated GTP path.
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
    - name: Configure GTP.
      fortinet.fortimanager.fmgr_firewall_gtp:
        bypass_validation: false
        adom: FortiCarrier # This is FOC-only object, need a FortiCarrier adom
        state: present
        firewall_gtp:
          monitor_mode: disable # <value in [disable, enable, vdom]>
          name: "ansible-test"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the GTPs
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_gtp"
          params:
            adom: "FortiCarrier" # This is FOC-only object, need a FortiCarrier adom
            gtp: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/gtp',
        '/pm/config/global/obj/firewall/gtp'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_gtp': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'addr-notify': {'type': 'str'},
                'apn': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['allow', 'deny'], 'type': 'str'},
                        'apnmember': {'type': 'raw'},
                        'id': {'type': 'int'},
                        'selection-mode': {'type': 'list', 'choices': ['ms', 'net', 'vrf'], 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'apn-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'authorized-ggsns': {'type': 'str'},
                'authorized-sgsns': {'type': 'str'},
                'comment': {'type': 'str'},
                'context-id': {'type': 'int'},
                'control-plane-message-rate-limit': {'type': 'int'},
                'default-apn-action': {'choices': ['allow', 'deny'], 'type': 'str'},
                'default-imsi-action': {'choices': ['allow', 'deny'], 'type': 'str'},
                'default-ip-action': {'choices': ['allow', 'deny'], 'type': 'str'},
                'default-noip-action': {'choices': ['allow', 'deny'], 'type': 'str'},
                'default-policy-action': {'choices': ['allow', 'deny'], 'type': 'str'},
                'denied-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'echo-request-interval': {'type': 'int'},
                'extension-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'forwarded-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'global-tunnel-limit': {'type': 'str'},
                'gtp-in-gtp': {'choices': ['allow', 'deny'], 'type': 'str'},
                'gtpu-denied-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'gtpu-forwarded-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'gtpu-log-freq': {'type': 'int'},
                'half-close-timeout': {'type': 'int'},
                'half-open-timeout': {'type': 'int'},
                'handover-group': {'type': 'str'},
                'ie-remove-policy': {
                    'type': 'list',
                    'options': {
                        'id': {'type': 'int'},
                        'remove-ies': {'type': 'list', 'choices': ['apn-restriction', 'rat-type', 'rai', 'uli', 'imei'], 'elements': 'str'},
                        'sgsn-addr': {'type': 'str'},
                        'sgsn-addr6': {'v_range': [['6.4.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ie-remover': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ie-white-list-v0v1': {'type': 'str'},
                'ie-white-list-v2': {'type': 'str'},
                'imsi': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['allow', 'deny'], 'type': 'str'},
                        'apnmember': {'type': 'raw'},
                        'id': {'type': 'int'},
                        'mcc-mnc': {'type': 'str'},
                        'msisdn-prefix': {'type': 'str'},
                        'selection-mode': {'type': 'list', 'choices': ['ms', 'net', 'vrf'], 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'imsi-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'interface-notify': {'type': 'str'},
                'invalid-reserved-field': {'choices': ['allow', 'deny'], 'type': 'str'},
                'invalid-sgsns-to-log': {'type': 'str'},
                'ip-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-policy': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['allow', 'deny'], 'type': 'str'},
                        'dstaddr': {'type': 'str'},
                        'id': {'type': 'int'},
                        'srcaddr': {'type': 'str'},
                        'dstaddr6': {'v_range': [['6.4.2', '']], 'type': 'str'},
                        'srcaddr6': {'v_range': [['6.4.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'log-freq': {'type': 'int'},
                'log-gtpu-limit': {'type': 'int'},
                'log-imsi-prefix': {'type': 'str'},
                'log-msisdn-prefix': {'type': 'str'},
                'max-message-length': {'type': 'int'},
                'message-filter-v0v1': {'type': 'str'},
                'message-filter-v2': {'type': 'str'},
                'min-message-length': {'type': 'int'},
                'miss-must-ie': {'choices': ['allow', 'deny'], 'type': 'str'},
                'monitor-mode': {'choices': ['disable', 'enable', 'vdom'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'noip-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'noip-policy': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['allow', 'deny'], 'type': 'str'},
                        'end': {'type': 'int'},
                        'id': {'type': 'int'},
                        'start': {'type': 'int'},
                        'type': {'choices': ['etsi', 'ietf'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'out-of-state-ie': {'choices': ['allow', 'deny'], 'type': 'str'},
                'out-of-state-message': {'choices': ['allow', 'deny'], 'type': 'str'},
                'per-apn-shaper': {
                    'type': 'list',
                    'options': {'apn': {'type': 'str'}, 'id': {'type': 'int'}, 'rate-limit': {'type': 'int'}, 'version': {'type': 'int'}},
                    'elements': 'dict'
                },
                'policy': {
                    'type': 'list',
                    'options': {
                        'action': {'choices': ['allow', 'deny'], 'type': 'str'},
                        'apn-sel-mode': {'type': 'list', 'choices': ['ms', 'net', 'vrf'], 'elements': 'str'},
                        'apnmember': {'type': 'raw'},
                        'id': {'type': 'int'},
                        'imei': {'type': 'str'},
                        'imsi': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'max-apn-restriction': {'choices': ['all', 'public-1', 'public-2', 'private-1', 'private-2'], 'type': 'str'},
                        'messages': {'type': 'list', 'choices': ['create-req', 'create-res', 'update-req', 'update-res'], 'elements': 'str'},
                        'msisdn': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                        'rai': {'type': 'str'},
                        'rat-type': {
                            'type': 'list',
                            'choices': ['any', 'utran', 'geran', 'wlan', 'gan', 'hspa', 'eutran', 'virtual', 'nbiot'],
                            'elements': 'str'
                        },
                        'uli': {'type': 'str'},
                        'imsi-prefix': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'msisdn-prefix': {'v_range': [['6.2.0', '']], 'type': 'str'},
                        'apn': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'policy-filter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'port-notify': {'type': 'int'},
                'rate-limit-mode': {'choices': ['per-profile', 'per-stream', 'per-apn'], 'type': 'str'},
                'rate-limited-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rate-sampling-interval': {'type': 'int'},
                'remove-if-echo-expires': {'choices': ['disable', 'enable'], 'type': 'str'},
                'remove-if-recovery-differ': {'choices': ['disable', 'enable'], 'type': 'str'},
                'reserved-ie': {'choices': ['allow', 'deny'], 'type': 'str'},
                'send-delete-when-timeout': {'choices': ['disable', 'enable'], 'type': 'str'},
                'send-delete-when-timeout-v2': {'choices': ['disable', 'enable'], 'type': 'str'},
                'spoof-src-addr': {'choices': ['allow', 'deny'], 'type': 'str'},
                'state-invalid-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-count-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-limit': {'type': 'int'},
                'tunnel-limit-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-timeout': {'type': 'int'},
                'unknown-version-action': {'choices': ['allow', 'deny'], 'type': 'str'},
                'user-plane-message-rate-limit': {'type': 'int'},
                'warning-threshold': {'type': 'int'},
                'policy-v2': {
                    'v_range': [['6.2.1', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.2.1', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                        'apn-sel-mode': {'v_range': [['6.2.1', '']], 'type': 'list', 'choices': ['ms', 'net', 'vrf'], 'elements': 'str'},
                        'apnmember': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                        'id': {'v_range': [['6.2.1', '']], 'type': 'int'},
                        'imsi-prefix': {'v_range': [['6.2.1', '']], 'type': 'str'},
                        'max-apn-restriction': {
                            'v_range': [['6.2.1', '']],
                            'choices': ['all', 'public-1', 'public-2', 'private-1', 'private-2'],
                            'type': 'str'
                        },
                        'mei': {'v_range': [['6.2.1', '']], 'type': 'str'},
                        'messages': {
                            'v_range': [['6.2.1', '']],
                            'type': 'list',
                            'choices': ['create-ses-req', 'create-ses-res', 'modify-bearer-req', 'modify-bearer-res'],
                            'elements': 'str'
                        },
                        'msisdn-prefix': {'v_range': [['6.2.1', '']], 'type': 'str'},
                        'rat-type': {
                            'v_range': [['6.2.1', '']],
                            'type': 'list',
                            'choices': ['any', 'utran', 'geran', 'wlan', 'gan', 'hspa', 'eutran', 'virtual', 'nbiot', 'ltem', 'nr'],
                            'elements': 'str'
                        },
                        'uli': {'v_range': [['6.2.1', '']], 'type': 'raw'}
                    },
                    'elements': 'dict'
                },
                'sub-second-interval': {'v_range': [['6.2.2', '']], 'choices': ['0.1', '0.25', '0.5'], 'type': 'str'},
                'sub-second-sampling': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'authorized-ggsns6': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'authorized-sgsns6': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'handover-group6': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'invalid-sgsns6-to-log': {'v_range': [['6.4.2', '']], 'type': 'str'},
                'ie-validation': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'apn-restriction': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charging-ID': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'charging-gateway-addr': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'end-user-addr': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'gsn-addr': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'imei': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'imsi': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mm-context': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ms-tzone': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ms-validated': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'msisdn': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'nsapi': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdp-context': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'qos-profile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rai': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rat-type': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'reordering-required': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'selection-mode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uli': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'message-rate-limit': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'create-aa-pdp-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'create-aa-pdp-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'create-mbms-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'create-mbms-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'create-pdp-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'create-pdp-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'delete-aa-pdp-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'delete-aa-pdp-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'delete-mbms-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'delete-mbms-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'delete-pdp-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'delete-pdp-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'echo-reponse': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'echo-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'error-indication': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'failure-report-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'failure-report-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fwd-reloc-complete-ack': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fwd-relocation-complete': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fwd-relocation-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fwd-relocation-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fwd-srns-context': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'fwd-srns-context-ack': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'g-pdu': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'identification-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'identification-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-de-reg-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-de-reg-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-notify-rej-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-notify-rej-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-notify-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-notify-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-reg-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-reg-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-ses-start-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-ses-start-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-ses-stop-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'mbms-ses-stop-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'note-ms-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'note-ms-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'pdu-notify-rej-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'pdu-notify-rej-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'pdu-notify-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'pdu-notify-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'ran-info': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'relocation-cancel-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'relocation-cancel-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'send-route-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'send-route-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'sgsn-context-ack': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'sgsn-context-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'sgsn-context-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'support-ext-hdr-notify': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'update-mbms-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'update-mbms-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'update-pdp-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'update-pdp-response': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'version-not-support': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'echo-response': {'v_range': [['7.4.3', '']], 'type': 'int'}
                    }
                },
                'message-rate-limit-v0': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'create-pdp-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'delete-pdp-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'echo-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'}
                    }
                },
                'message-rate-limit-v1': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'create-pdp-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'delete-pdp-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'echo-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'}
                    }
                },
                'message-rate-limit-v2': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'create-session-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'delete-session-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'},
                        'echo-request': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'int'}
                    }
                },
                'ie-allow-list-v0v1': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'ie-allow-list-v2': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'rat-timeout-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'message-filter': {
                    'v_range': [['6.2.8', '6.2.13']],
                    'type': 'dict',
                    'options': {
                        'create-aa-pdp': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'create-mbms': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'create-pdp': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'data-record': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'delete-aa-pdp': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'delete-mbms': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'delete-pdp': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'echo': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'error-indication': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'failure-report': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'fwd-relocation': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'fwd-srns-context': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'gtp-pdu': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'identification': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'mbms-notification': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'node-alive': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'note-ms-present': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'pdu-notification': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'ran-info': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'redirection': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'relocation-cancel': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'send-route': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'sgsn-context': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'support-extension': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'unknown-message-action': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'update-mbms': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'update-pdp': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'},
                        'version-not-support': {'v_range': [['6.2.8', '6.2.13']], 'choices': ['allow', 'deny'], 'type': 'str'}
                    }
                },
                'gtpv0': {'v_range': [['7.6.0', '']], 'choices': ['allow', 'deny'], 'type': 'str'},
                'echo-requires-path-in-use': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_gtp'),
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
