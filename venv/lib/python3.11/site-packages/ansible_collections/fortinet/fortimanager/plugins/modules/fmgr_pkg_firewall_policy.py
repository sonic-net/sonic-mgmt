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
module: fmgr_pkg_firewall_policy
short_description: Configure IPv4 policies.
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_policy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action
                choices:
                    - 'deny'
                    - 'accept'
                    - 'ipsec'
                    - 'ssl-vpn'
                    - 'redirect'
                    - 'isolate'
            app_category:
                aliases: ['app-category']
                type: raw
                description: (list or str) Application category ID list.
            application:
                type: raw
                description: (list) Application ID list.
            application_list:
                aliases: ['application-list']
                type: str
                description: Name of an existing Application list.
            auth_cert:
                aliases: ['auth-cert']
                type: str
                description: HTTPS server certificate for policy authentication.
            auth_path:
                aliases: ['auth-path']
                type: str
                description: Enable/disable authentication-based routing.
                choices:
                    - 'disable'
                    - 'enable'
            auth_redirect_addr:
                aliases: ['auth-redirect-addr']
                type: str
                description: HTTP-to-HTTPS redirect address for firewall authentication.
            auto_asic_offload:
                aliases: ['auto-asic-offload']
                type: str
                description: Enable/disable offloading security profile processing to CP processors.
                choices:
                    - 'disable'
                    - 'enable'
            av_profile:
                aliases: ['av-profile']
                type: str
                description: Name of an existing Antivirus profile.
            block_notification:
                aliases: ['block-notification']
                type: str
                description: Enable/disable block notification.
                choices:
                    - 'disable'
                    - 'enable'
            captive_portal_exempt:
                aliases: ['captive-portal-exempt']
                type: str
                description: Enable to exempt some users from the captive portal.
                choices:
                    - 'disable'
                    - 'enable'
            capture_packet:
                aliases: ['capture-packet']
                type: str
                description: Enable/disable capture packets.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: raw
                description: (dict or str) Comment.
            custom_log_fields:
                aliases: ['custom-log-fields']
                type: raw
                description: (list or str) Custom fields to append to log messages for this policy.
            delay_tcp_npu_session:
                aliases: ['delay-tcp-npu-session']
                type: str
                description: Enable TCP NPU session delay to guarantee packet order of 3-way handshake.
                choices:
                    - 'disable'
                    - 'enable'
            devices:
                type: raw
                description: (list or str) Names of devices or device groups that can be matched by the policy.
            diffserv_forward:
                aliases: ['diffserv-forward']
                type: str
                description: Enable to change packets DiffServ values to the specified diffservcode-forward value.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv_reverse:
                aliases: ['diffserv-reverse']
                type: str
                description: Enable to change packets reverse
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode_forward:
                aliases: ['diffservcode-forward']
                type: str
                description: Change packets DiffServ to this value.
            diffservcode_rev:
                aliases: ['diffservcode-rev']
                type: str
                description: Change packets reverse
            disclaimer:
                type: str
                description: Enable/disable user authentication disclaimer.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'user'
                    - 'domain'
                    - 'policy'
            dlp_sensor:
                aliases: ['dlp-sensor']
                type: str
                description: Name of an existing DLP sensor.
            dnsfilter_profile:
                aliases: ['dnsfilter-profile']
                type: str
                description: Name of an existing DNS filter profile.
            dscp_match:
                aliases: ['dscp-match']
                type: str
                description: Enable DSCP check.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_negate:
                aliases: ['dscp-negate']
                type: str
                description: Enable negated DSCP match.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_value:
                aliases: ['dscp-value']
                type: str
                description: DSCP value.
            dsri:
                type: str
                description: Enable DSRI to ignore HTTP server responses.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) Destination address and address group names.
            dstaddr_negate:
                aliases: ['dstaddr-negate']
                type: str
                description: When enabled dstaddr specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            dstintf:
                type: raw
                description: (list or str) Outgoing
            firewall_session_dirty:
                aliases: ['firewall-session-dirty']
                type: str
                description: How to handle sessions if the configuration of this firewall policy changes.
                choices:
                    - 'check-all'
                    - 'check-new'
            fixedport:
                type: str
                description: Enable to prevent source NAT from changing a sessions source port.
                choices:
                    - 'disable'
                    - 'enable'
            fsso:
                type: str
                description: Enable/disable Fortinet Single Sign-On.
                choices:
                    - 'disable'
                    - 'enable'
            fsso_agent_for_ntlm:
                aliases: ['fsso-agent-for-ntlm']
                type: str
                description: FSSO agent to use for NTLM authentication.
            global_label:
                aliases: ['global-label']
                type: str
                description: Label for the policy that appears when the GUI is in Global View mode.
            groups:
                type: raw
                description: (list or str) Names of user groups that can authenticate with this policy.
            gtp_profile:
                aliases: ['gtp-profile']
                type: str
                description: GTP profile.
            icap_profile:
                aliases: ['icap-profile']
                type: str
                description: Name of an existing ICAP profile.
            identity_based_route:
                aliases: ['identity-based-route']
                type: str
                description: Name of identity-based routing rule.
            inbound:
                type: str
                description: Policy-based IPsec VPN
                choices:
                    - 'disable'
                    - 'enable'
            internet_service:
                aliases: ['internet-service']
                type: str
                description: Enable/disable use of Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_custom:
                aliases: ['internet-service-custom']
                type: raw
                description: (list or str) Custom Internet Service Name.
            internet_service_id:
                aliases: ['internet-service-id']
                type: raw
                description: (list or str) Internet Service ID.
            internet_service_negate:
                aliases: ['internet-service-negate']
                type: str
                description: When enabled internet-service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            ippool:
                type: str
                description: Enable to use IP Pools for source NAT.
                choices:
                    - 'disable'
                    - 'enable'
            ips_sensor:
                aliases: ['ips-sensor']
                type: str
                description: Name of an existing IPS sensor.
            label:
                type: str
                description: Label for the policy that appears when the GUI is in Section View mode.
            learning_mode:
                aliases: ['learning-mode']
                type: str
                description: Enable to allow everything, but log all of the meaningful data for security information gathering.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic:
                type: str
                description: Enable or disable logging.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            logtraffic_start:
                aliases: ['logtraffic-start']
                type: str
                description: Record logs when a session starts and ends.
                choices:
                    - 'disable'
                    - 'enable'
            match_vip:
                aliases: ['match-vip']
                type: str
                description: Enable to match packets that have had their destination addresses changed by a VIP.
                choices:
                    - 'disable'
                    - 'enable'
            mms_profile:
                aliases: ['mms-profile']
                type: str
                description: Name of an existing MMS profile.
            name:
                type: str
                description: Policy name.
            nat:
                type: str
                description: Enable/disable source NAT.
                choices:
                    - 'disable'
                    - 'enable'
            natinbound:
                type: str
                description: Policy-based IPsec VPN
                choices:
                    - 'disable'
                    - 'enable'
            natip:
                type: str
                description: Policy-based IPsec VPN
            natoutbound:
                type: str
                description: Policy-based IPsec VPN
                choices:
                    - 'disable'
                    - 'enable'
            ntlm:
                type: str
                description: Enable/disable NTLM authentication.
                choices:
                    - 'disable'
                    - 'enable'
            ntlm_enabled_browsers:
                aliases: ['ntlm-enabled-browsers']
                type: raw
                description: (list) HTTP-User-Agent value of supported browsers.
            ntlm_guest:
                aliases: ['ntlm-guest']
                type: str
                description: Enable/disable NTLM guest user access.
                choices:
                    - 'disable'
                    - 'enable'
            outbound:
                type: str
                description: Policy-based IPsec VPN
                choices:
                    - 'disable'
                    - 'enable'
            per_ip_shaper:
                aliases: ['per-ip-shaper']
                type: str
                description: Per-IP traffic shaper.
            permit_any_host:
                aliases: ['permit-any-host']
                type: str
                description: Accept UDP packets from any host.
                choices:
                    - 'disable'
                    - 'enable'
            permit_stun_host:
                aliases: ['permit-stun-host']
                type: str
                description: Accept UDP packets from any Session Traversal Utilities for NAT
                choices:
                    - 'disable'
                    - 'enable'
            policyid:
                type: int
                description: Policy ID.
                required: true
            poolname:
                type: raw
                description: (list or str) IP Pool names.
            profile_group:
                aliases: ['profile-group']
                type: str
                description: Name of profile group.
            profile_protocol_options:
                aliases: ['profile-protocol-options']
                type: str
                description: Name of an existing Protocol options profile.
            profile_type:
                aliases: ['profile-type']
                type: str
                description: Determine whether the firewall policy allows security profile groups or single profiles only.
                choices:
                    - 'single'
                    - 'group'
            radius_mac_auth_bypass:
                aliases: ['radius-mac-auth-bypass']
                type: str
                description: Enable MAC authentication bypass.
                choices:
                    - 'disable'
                    - 'enable'
            redirect_url:
                aliases: ['redirect-url']
                type: str
                description: URL users are directed to after seeing and accepting the disclaimer or authenticating.
            replacemsg_override_group:
                aliases: ['replacemsg-override-group']
                type: str
                description: Override the default replacement message group for this policy.
            rsso:
                type: str
                description: Enable/disable RADIUS single sign-on
                choices:
                    - 'disable'
                    - 'enable'
            rtp_addr:
                aliases: ['rtp-addr']
                type: raw
                description: (list or str) Address names if this is an RTP NAT policy.
            rtp_nat:
                aliases: ['rtp-nat']
                type: str
                description: Enable Real Time Protocol
                choices:
                    - 'disable'
                    - 'enable'
            scan_botnet_connections:
                aliases: ['scan-botnet-connections']
                type: str
                description: Block or monitor connections to Botnet servers or disable Botnet scanning.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                type: str
                description: Schedule name.
            schedule_timeout:
                aliases: ['schedule-timeout']
                type: str
                description: Enable to force current sessions to end when the schedule object times out.
                choices:
                    - 'disable'
                    - 'enable'
            send_deny_packet:
                aliases: ['send-deny-packet']
                type: str
                description: Enable to send a reply when a session is denied or blocked by a firewall policy.
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: raw
                description: (list or str) Service and service group names.
            service_negate:
                aliases: ['service-negate']
                type: str
                description: When enabled service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            session_ttl:
                aliases: ['session-ttl']
                type: raw
                description: (int or str) Session TTL in seconds for sessions accepted by this policy.
            spamfilter_profile:
                aliases: ['spamfilter-profile']
                type: str
                description: Name of an existing Spam filter profile.
            srcaddr:
                type: raw
                description: (list or str) Source address and address group names.
            srcaddr_negate:
                aliases: ['srcaddr-negate']
                type: str
                description: When enabled srcaddr specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcintf:
                type: raw
                description: (list or str) Incoming
            ssl_mirror:
                aliases: ['ssl-mirror']
                type: str
                description: Enable to copy decrypted SSL traffic to a FortiGate interface
                choices:
                    - 'disable'
                    - 'enable'
            ssl_mirror_intf:
                aliases: ['ssl-mirror-intf']
                type: raw
                description: (list or str) SSL mirror interface name.
            ssl_ssh_profile:
                aliases: ['ssl-ssh-profile']
                type: str
                description: Name of an existing SSL SSH profile.
            status:
                type: str
                description: Enable or disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: str
                description: Names of object-tags applied to this policy.
            tcp_mss_receiver:
                aliases: ['tcp-mss-receiver']
                type: int
                description: Receiver TCP maximum segment size
            tcp_mss_sender:
                aliases: ['tcp-mss-sender']
                type: int
                description: Sender TCP maximum segment size
            tcp_session_without_syn:
                aliases: ['tcp-session-without-syn']
                type: str
                description: Enable/disable creation of TCP session without SYN flag.
                choices:
                    - 'all'
                    - 'data-only'
                    - 'disable'
            timeout_send_rst:
                aliases: ['timeout-send-rst']
                type: str
                description: Enable/disable sending RST packets when TCP sessions expire.
                choices:
                    - 'disable'
                    - 'enable'
            traffic_shaper:
                aliases: ['traffic-shaper']
                type: str
                description: Traffic shaper.
            traffic_shaper_reverse:
                aliases: ['traffic-shaper-reverse']
                type: str
                description: Reverse traffic shaper.
            url_category:
                aliases: ['url-category']
                type: raw
                description: (list or str) URL category ID list.
            users:
                type: raw
                description: (list or str) Names of individual users that can authenticate with this policy.
            utm_status:
                aliases: ['utm-status']
                type: str
                description: Enable to add one or more security profiles
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            vlan_cos_fwd:
                aliases: ['vlan-cos-fwd']
                type: int
                description: VLAN forward direction user priority
            vlan_cos_rev:
                aliases: ['vlan-cos-rev']
                type: int
                description: VLAN reverse direction user priority
            voip_profile:
                aliases: ['voip-profile']
                type: str
                description: Name of an existing VoIP profile.
            vpn_dst_node:
                type: list
                elements: dict
                description: Vpn dst node.
                suboptions:
                    host:
                        type: str
                        description: Host.
                    seq:
                        type: int
                        description: Seq.
                    subnet:
                        type: str
                        description: Subnet.
            vpn_src_node:
                type: list
                elements: dict
                description: Vpn src node.
                suboptions:
                    host:
                        type: str
                        description: Host.
                    seq:
                        type: int
                        description: Seq.
                    subnet:
                        type: str
                        description: Subnet.
            vpntunnel:
                type: str
                description: Policy-based IPsec VPN
            waf_profile:
                aliases: ['waf-profile']
                type: str
                description: Name of an existing Web application firewall profile.
            wanopt:
                type: str
                description: Enable/disable WAN optimization.
                choices:
                    - 'disable'
                    - 'enable'
            wanopt_detection:
                aliases: ['wanopt-detection']
                type: str
                description: WAN optimization auto-detection mode.
                choices:
                    - 'active'
                    - 'passive'
                    - 'off'
            wanopt_passive_opt:
                aliases: ['wanopt-passive-opt']
                type: str
                description: WAN optimization passive mode options.
                choices:
                    - 'default'
                    - 'transparent'
                    - 'non-transparent'
            wanopt_peer:
                aliases: ['wanopt-peer']
                type: str
                description: WAN optimization peer.
            wanopt_profile:
                aliases: ['wanopt-profile']
                type: str
                description: WAN optimization profile.
            wccp:
                type: str
                description: Enable/disable forwarding traffic matching this policy to a configured WCCP server.
                choices:
                    - 'disable'
                    - 'enable'
            webcache:
                type: str
                description: Enable/disable web cache.
                choices:
                    - 'disable'
                    - 'enable'
            webcache_https:
                aliases: ['webcache-https']
                type: str
                description: Enable/disable web cache for HTTPS.
                choices:
                    - 'disable'
                    - 'ssl-server'
                    - 'any'
                    - 'enable'
            webfilter_profile:
                aliases: ['webfilter-profile']
                type: str
                description: Name of an existing Web filter profile.
            wsso:
                type: str
                description: Enable/disable WiFi Single Sign On
                choices:
                    - 'disable'
                    - 'enable'
            anti_replay:
                aliases: ['anti-replay']
                type: str
                description: Enable/disable anti-replay check.
                choices:
                    - 'disable'
                    - 'enable'
            app_group:
                aliases: ['app-group']
                type: raw
                description: (list or str) Application group names.
            cifs_profile:
                aliases: ['cifs-profile']
                type: str
                description: Name of an existing CIFS profile.
            email_collect:
                aliases: ['email-collect']
                type: str
                description: Enable/disable email collection.
                choices:
                    - 'disable'
                    - 'enable'
            emailfilter_profile:
                aliases: ['emailfilter-profile']
                type: str
                description: Name of an existing email filter profile.
            fsso_groups:
                aliases: ['fsso-groups']
                type: raw
                description: (list or str) Names of FSSO groups.
            geoip_anycast:
                aliases: ['geoip-anycast']
                type: str
                description: Enable/disable recognition of anycast IP addresses using the geography IP database.
                choices:
                    - 'disable'
                    - 'enable'
            http_policy_redirect:
                aliases: ['http-policy-redirect']
                type: str
                description: Redirect HTTP
                choices:
                    - 'disable'
                    - 'enable'
                    - 'legacy'
            inspection_mode:
                aliases: ['inspection-mode']
                type: str
                description: Policy inspection mode
                choices:
                    - 'proxy'
                    - 'flow'
            internet_service_custom_group:
                aliases: ['internet-service-custom-group']
                type: raw
                description: (list or str) Custom Internet Service group name.
            internet_service_group:
                aliases: ['internet-service-group']
                type: raw
                description: (list or str) Internet Service group name.
            internet_service_src:
                aliases: ['internet-service-src']
                type: str
                description: Enable/disable use of Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src_custom:
                aliases: ['internet-service-src-custom']
                type: raw
                description: (list or str) Custom Internet Service source name.
            internet_service_src_custom_group:
                aliases: ['internet-service-src-custom-group']
                type: raw
                description: (list or str) Custom Internet Service source group name.
            internet_service_src_group:
                aliases: ['internet-service-src-group']
                type: raw
                description: (list or str) Internet Service source group name.
            internet_service_src_id:
                aliases: ['internet-service-src-id']
                type: raw
                description: (list or str) Internet Service source ID.
            internet_service_src_negate:
                aliases: ['internet-service-src-negate']
                type: str
                description: When enabled internet-service-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            match_vip_only:
                aliases: ['match-vip-only']
                type: str
                description: Enable/disable matching of only those packets that have had their destination addresses changed by a VIP.
                choices:
                    - 'disable'
                    - 'enable'
            np_acceleration:
                aliases: ['np-acceleration']
                type: str
                description: Enable/disable UTM Network Processor acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            reputation_direction:
                aliases: ['reputation-direction']
                type: str
                description: Direction of the initial traffic for reputation to take effect.
                choices:
                    - 'source'
                    - 'destination'
            reputation_minimum:
                aliases: ['reputation-minimum']
                type: int
                description: Minimum Reputation to take action.
            ssh_filter_profile:
                aliases: ['ssh-filter-profile']
                type: str
                description: Name of an existing SSH filter profile.
            ssh_policy_redirect:
                aliases: ['ssh-policy-redirect']
                type: str
                description: Redirect SSH traffic to matching transparent proxy policy.
                choices:
                    - 'disable'
                    - 'enable'
            tos:
                type: str
                description: ToS
            tos_mask:
                aliases: ['tos-mask']
                type: str
                description: Non-zero bit positions are used for comparison while zero bit positions are ignored.
            tos_negate:
                aliases: ['tos-negate']
                type: str
                description: Enable negated TOS match.
                choices:
                    - 'disable'
                    - 'enable'
            vlan_filter:
                aliases: ['vlan-filter']
                type: str
                description: Set VLAN filters.
            webproxy_forward_server:
                aliases: ['webproxy-forward-server']
                type: str
                description: Webproxy forward server name.
            webproxy_profile:
                aliases: ['webproxy-profile']
                type: str
                description: Webproxy profile name.
            np_accelation:
                aliases: ['np-accelation']
                type: str
                description: Enable/disable UTM Network Processor acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            delay_tcp_npu_sessoin:
                aliases: ['delay-tcp-npu-sessoin']
                type: str
                description: Enable/disable TCP NPU session delay in order to guarantee packet order of 3-way handshake.
                choices:
                    - 'disable'
                    - 'enable'
            casi_profile:
                aliases: ['casi-profile']
                type: str
                description: CASI profile.
            best_route:
                aliases: ['best-route']
                type: str
                description: Enable/disable the use of best route.
                choices:
                    - 'disable'
                    - 'enable'
            decrypted_traffic_mirror:
                aliases: ['decrypted-traffic-mirror']
                type: str
                description: Decrypted traffic mirror.
            dstaddr6:
                type: raw
                description: (list or str) Destination IPv6 address name and address group names.
            geoip_match:
                aliases: ['geoip-match']
                type: str
                description: Match geography address based either on its physical location or registered location.
                choices:
                    - 'physical-location'
                    - 'registered-location'
            internet_service_name:
                aliases: ['internet-service-name']
                type: raw
                description: (list or str) Internet Service name.
            internet_service_src_name:
                aliases: ['internet-service-src-name']
                type: raw
                description: (list or str) Internet Service source name.
            poolname6:
                type: raw
                description: (list or str) IPv6 pool names.
            src_vendor_mac:
                aliases: ['src-vendor-mac']
                type: raw
                description: (list or str) Vendor MAC source ID.
            srcaddr6:
                type: raw
                description: (list or str) Source IPv6 address name and address group names.
            file_filter_profile:
                aliases: ['file-filter-profile']
                type: str
                description: Name of an existing file-filter profile.
            policy_offload:
                aliases: ['policy-offload']
                type: str
                description: Enable/Disable hardware session setup for CGNAT.
                choices:
                    - 'disable'
                    - 'enable'
            cgn_session_quota:
                aliases: ['cgn-session-quota']
                type: int
                description: Session quota
            cgn_eif:
                aliases: ['cgn-eif']
                type: str
                description: Enable/Disable CGN endpoint independent filtering.
                choices:
                    - 'disable'
                    - 'enable'
            cgn_log_server_grp:
                aliases: ['cgn-log-server-grp']
                type: str
                description: NP log server group name
            cgn_eim:
                aliases: ['cgn-eim']
                type: str
                description: Enable/Disable CGN endpoint independent mapping
                choices:
                    - 'disable'
                    - 'enable'
            cgn_resource_quota:
                aliases: ['cgn-resource-quota']
                type: int
                description: Resource quota
            dynamic_shaping:
                aliases: ['dynamic-shaping']
                type: str
                description: Enable/disable dynamic RADIUS defined traffic shaping.
                choices:
                    - 'disable'
                    - 'enable'
            passive_wan_health_measurement:
                aliases: ['passive-wan-health-measurement']
                type: str
                description: Enable/disable passive WAN health measurement.
                choices:
                    - 'disable'
                    - 'enable'
            videofilter_profile:
                aliases: ['videofilter-profile']
                type: str
                description: Name of an existing VideoFilter profile.
            ztna_ems_tag:
                aliases: ['ztna-ems-tag']
                type: raw
                description: (list or str) Source ztna-ems-tag names.
            ztna_geo_tag:
                aliases: ['ztna-geo-tag']
                type: raw
                description: (list or str) Source ztna-geo-tag names.
            ztna_status:
                aliases: ['ztna-status']
                type: str
                description: Enable/disable zero trust access.
                choices:
                    - 'disable'
                    - 'enable'
            _policy_block:
                type: int
                description: Assigned policy block.
            dlp_profile:
                aliases: ['dlp-profile']
                type: str
                description: Name of an existing DLP profile.
            fec:
                type: str
                description: Enable/disable Forward Error Correction on traffic matching this policy on a FEC device.
                choices:
                    - 'disable'
                    - 'enable'
            nat46:
                type: str
                description: Enable/disable NAT46.
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: Enable/disable NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            pfcp_profile:
                aliases: ['pfcp-profile']
                type: str
                description: PFCP profile.
            policy_expiry:
                aliases: ['policy-expiry']
                type: str
                description: Enable/disable policy expiry.
                choices:
                    - 'disable'
                    - 'enable'
            policy_expiry_date:
                aliases: ['policy-expiry-date']
                type: str
                description: Policy expiry date
            sctp_filter_profile:
                aliases: ['sctp-filter-profile']
                type: str
                description: Name of an existing SCTP filter profile.
            sgt:
                type: raw
                description: (list) Security group tags.
            sgt_check:
                aliases: ['sgt-check']
                type: str
                description: Enable/disable security group tags
                choices:
                    - 'disable'
                    - 'enable'
            tcp_timeout_pid:
                aliases: ['tcp-timeout-pid']
                type: str
                description: TCP timeout profile ID
            udp_timeout_pid:
                aliases: ['udp-timeout-pid']
                type: str
                description: UDP timeout profile ID
            diffserv_copy:
                aliases: ['diffserv-copy']
                type: str
                description: Enable to copy packets DiffServ values from sessions original direction to its reply direction.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6_negate:
                aliases: ['dstaddr6-negate']
                type: str
                description: When enabled dstaddr6 specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6:
                aliases: ['internet-service6']
                type: str
                description: Enable/disable use of IPv6 Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_custom:
                aliases: ['internet-service6-custom']
                type: raw
                description: (list) Custom IPv6 Internet Service name.
            internet_service6_custom_group:
                aliases: ['internet-service6-custom-group']
                type: raw
                description: (list) Custom Internet Service6 group name.
            internet_service6_group:
                aliases: ['internet-service6-group']
                type: raw
                description: (list) Internet Service group name.
            internet_service6_name:
                aliases: ['internet-service6-name']
                type: raw
                description: (list) IPv6 Internet Service name.
            internet_service6_negate:
                aliases: ['internet-service6-negate']
                type: str
                description: When enabled internet-service6 specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src:
                aliases: ['internet-service6-src']
                type: str
                description: Enable/disable use of IPv6 Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src_custom:
                aliases: ['internet-service6-src-custom']
                type: raw
                description: (list) Custom IPv6 Internet Service source name.
            internet_service6_src_custom_group:
                aliases: ['internet-service6-src-custom-group']
                type: raw
                description: (list) Custom Internet Service6 source group name.
            internet_service6_src_group:
                aliases: ['internet-service6-src-group']
                type: raw
                description: (list) Internet Service6 source group name.
            internet_service6_src_name:
                aliases: ['internet-service6-src-name']
                type: raw
                description: (list) IPv6 Internet Service source name.
            internet_service6_src_negate:
                aliases: ['internet-service6-src-negate']
                type: str
                description: When enabled internet-service6-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            network_service_dynamic:
                aliases: ['network-service-dynamic']
                type: raw
                description: (list) Dynamic Network Service name.
            network_service_src_dynamic:
                aliases: ['network-service-src-dynamic']
                type: raw
                description: (list) Dynamic Network Service source name.
            reputation_direction6:
                aliases: ['reputation-direction6']
                type: str
                description: Direction of the initial traffic for IPv6 reputation to take effect.
                choices:
                    - 'source'
                    - 'destination'
            reputation_minimum6:
                aliases: ['reputation-minimum6']
                type: int
                description: IPv6 Minimum Reputation to take action.
            srcaddr6_negate:
                aliases: ['srcaddr6-negate']
                type: str
                description: When enabled srcaddr6 specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            ip_version_type:
                aliases: ['ip-version-type']
                type: str
                description: IP version of the policy.
            ips_voip_filter:
                aliases: ['ips-voip-filter']
                type: str
                description: Name of an existing VoIP
            pcp_inbound:
                aliases: ['pcp-inbound']
                type: str
                description: Enable/disable PCP inbound DNAT.
                choices:
                    - 'disable'
                    - 'enable'
            pcp_outbound:
                aliases: ['pcp-outbound']
                type: str
                description: Enable/disable PCP outbound SNAT.
                choices:
                    - 'disable'
                    - 'enable'
            pcp_poolname:
                aliases: ['pcp-poolname']
                type: raw
                description: (list) PCP pool names.
            policy_behaviour_type:
                aliases: ['policy-behaviour-type']
                type: str
                description: Behaviour of the policy.
            policy_expiry_date_utc:
                aliases: ['policy-expiry-date-utc']
                type: str
                description: Policy expiry date and time, in epoch format.
            ztna_device_ownership:
                aliases: ['ztna-device-ownership']
                type: str
                description: Enable/disable zero trust device ownership.
                choices:
                    - 'disable'
                    - 'enable'
            ztna_ems_tag_secondary:
                aliases: ['ztna-ems-tag-secondary']
                type: raw
                description: (list) Source ztna-ems-tag-secondary names.
            ztna_policy_redirect:
                aliases: ['ztna-policy-redirect']
                type: str
                description: Redirect ZTNA traffic to matching Access-Proxy proxy-policy.
                choices:
                    - 'disable'
                    - 'enable'
            ztna_tags_match_logic:
                aliases: ['ztna-tags-match-logic']
                type: str
                description: ZTNA tag matching logic.
                choices:
                    - 'or'
                    - 'and'
            casb_profile:
                aliases: ['casb-profile']
                type: str
                description: Name of an existing CASB profile.
            virtual_patch_profile:
                aliases: ['virtual-patch-profile']
                type: str
                description: Name of an existing virtual-patch profile.
            diameter_filter_profile:
                aliases: ['diameter-filter-profile']
                type: str
                description: Name of an existing Diameter filter profile.
            port_preserve:
                aliases: ['port-preserve']
                type: str
                description: Enable/disable preservation of the original source port from source NAT if it has not been used.
                choices:
                    - 'disable'
                    - 'enable'
            cgn_sw_eif_ctrl:
                aliases: ['cgn-sw-eif-ctrl']
                type: str
                description: Enable/disable software endpoint independent filtering control.
                choices:
                    - 'disable'
                    - 'enable'
            eif_check:
                aliases: ['eif-check']
                type: str
                description: Enable/Disable check endpoint-independent-filtering pinhole.
                choices:
                    - 'disable'
                    - 'enable'
            eif_learn:
                aliases: ['eif-learn']
                type: str
                description: Enable/Disable learning of end-point-independent filtering pinhole.
                choices:
                    - 'disable'
                    - 'enable'
            log_http_transaction:
                aliases: ['log-http-transaction']
                type: str
                description: Enable/disable HTTP transaction log.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            radius_ip_auth_bypass:
                aliases: ['radius-ip-auth-bypass']
                type: str
                description: Enable IP authentication bypass.
                choices:
                    - 'disable'
                    - 'enable'
            app_monitor:
                aliases: ['app-monitor']
                type: str
                description: Enable/disable application TCP metrics in session logs.
                choices:
                    - 'disable'
                    - 'enable'
            port_random:
                aliases: ['port-random']
                type: str
                description: Enable/disable random source port selection for source NAT.
                choices:
                    - 'disable'
                    - 'enable'
            ztna_ems_tag_negate:
                aliases: ['ztna-ems-tag-negate']
                type: str
                description: When enabled ztna-ems-tag specifies what the tags must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            telemetry_profile:
                aliases: ['telemetry-profile']
                type: raw
                description: (list) Name of an existing telemetry profile.
            object_position:
                aliases: ['object position']
                type: list
                elements: str
                description: Object position.
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
    - name: Configure IPv4 policies.
      fortinet.fortimanager.fmgr_pkg_firewall_policy:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_policy:
          action: accept # <value in [deny, accept, ipsec, ...]>
          comments: ansible-comment
          dstaddr: all
          dstintf: any
          # name: ansible-test-policy
          nat: disable
          policyid: 1
          schedule: always
          service: ALL
          srcaddr: all
          srcintf: any
          status: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv4 policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_policy"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            policy: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy'
    ]
    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'pkg_firewall_policy': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['deny', 'accept', 'ipsec', 'ssl-vpn', 'redirect', 'isolate'], 'type': 'str'},
                'app-category': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'application': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'application-list': {'type': 'str'},
                'auth-cert': {'type': 'str'},
                'auth-path': {'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-redirect-addr': {'type': 'str'},
                'auto-asic-offload': {
                    'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'av-profile': {'type': 'str'},
                'block-notification': {'choices': ['disable', 'enable'], 'type': 'str'},
                'captive-portal-exempt': {'choices': ['disable', 'enable'], 'type': 'str'},
                'capture-packet': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'type': 'raw'},
                'custom-log-fields': {'type': 'raw'},
                'delay-tcp-npu-session': {'choices': ['disable', 'enable'], 'type': 'str'},
                'devices': {'v_range': [['6.0.0', '7.2.1']], 'type': 'raw'},
                'diffserv-forward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'type': 'str'},
                'diffservcode-rev': {'type': 'str'},
                'disclaimer': {'choices': ['disable', 'enable', 'user', 'domain', 'policy'], 'type': 'str'},
                'dlp-sensor': {'type': 'str'},
                'dnsfilter-profile': {'type': 'str'},
                'dscp-match': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-negate': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-value': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'dsri': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'dstaddr-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dstintf': {'type': 'raw'},
                'firewall-session-dirty': {'choices': ['check-all', 'check-new'], 'type': 'str'},
                'fixedport': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fsso': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fsso-agent-for-ntlm': {'type': 'str'},
                'global-label': {'type': 'str'},
                'groups': {'type': 'raw'},
                'gtp-profile': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'icap-profile': {'type': 'str'},
                'identity-based-route': {'type': 'str'},
                'inbound': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-custom': {'type': 'raw'},
                'internet-service-id': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'internet-service-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ippool': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-sensor': {'type': 'str'},
                'label': {'type': 'str'},
                'learning-mode': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic': {'choices': ['disable', 'enable', 'all', 'utm'], 'type': 'str'},
                'logtraffic-start': {'choices': ['disable', 'enable'], 'type': 'str'},
                'match-vip': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-profile': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'type': 'str'},
                'name': {'type': 'str'},
                'nat': {'choices': ['disable', 'enable'], 'type': 'str'},
                'natinbound': {'choices': ['disable', 'enable'], 'type': 'str'},
                'natip': {'type': 'str'},
                'natoutbound': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ntlm': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ntlm-enabled-browsers': {'type': 'raw'},
                'ntlm-guest': {'choices': ['disable', 'enable'], 'type': 'str'},
                'outbound': {'choices': ['disable', 'enable'], 'type': 'str'},
                'per-ip-shaper': {'type': 'str'},
                'permit-any-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'permit-stun-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'policyid': {'required': True, 'type': 'int'},
                'poolname': {'type': 'raw'},
                'profile-group': {'type': 'str'},
                'profile-protocol-options': {'type': 'str'},
                'profile-type': {'choices': ['single', 'group'], 'type': 'str'},
                'radius-mac-auth-bypass': {'choices': ['disable', 'enable'], 'type': 'str'},
                'redirect-url': {'type': 'str'},
                'replacemsg-override-group': {'type': 'str'},
                'rsso': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rtp-addr': {'type': 'raw'},
                'rtp-nat': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scan-botnet-connections': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'schedule': {'type': 'str'},
                'schedule-timeout': {'choices': ['disable', 'enable'], 'type': 'str'},
                'send-deny-packet': {'choices': ['disable', 'enable'], 'type': 'str'},
                'service': {'type': 'raw'},
                'service-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'session-ttl': {'type': 'raw'},
                'spamfilter-profile': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'srcaddr': {'type': 'raw'},
                'srcaddr-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'srcintf': {'type': 'raw'},
                'ssl-mirror': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-mirror-intf': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'ssl-ssh-profile': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['6.0.0', '6.4.15']], 'type': 'str'},
                'tcp-mss-receiver': {'type': 'int'},
                'tcp-mss-sender': {'type': 'int'},
                'tcp-session-without-syn': {'choices': ['all', 'data-only', 'disable'], 'type': 'str'},
                'timeout-send-rst': {'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'type': 'str'},
                'traffic-shaper-reverse': {'type': 'str'},
                'url-category': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'users': {'type': 'raw'},
                'utm-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'type': 'str'},
                'vlan-cos-fwd': {'type': 'int'},
                'vlan-cos-rev': {'type': 'int'},
                'voip-profile': {'type': 'str'},
                'vpn_dst_node': {
                    'v_range': [['6.0.0', '7.0.2']],
                    'type': 'list',
                    'options': {
                        'host': {'v_range': [['6.0.0', '7.0.2']], 'type': 'str'},
                        'seq': {'v_range': [['6.0.0', '7.0.2']], 'type': 'int'},
                        'subnet': {'v_range': [['6.0.0', '7.0.2']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'vpn_src_node': {
                    'v_range': [['6.0.0', '7.0.2']],
                    'type': 'list',
                    'options': {
                        'host': {'v_range': [['6.0.0', '7.0.2']], 'type': 'str'},
                        'seq': {'v_range': [['6.0.0', '7.0.2']], 'type': 'int'},
                        'subnet': {'v_range': [['6.0.0', '7.0.2']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'vpntunnel': {'type': 'str'},
                'waf-profile': {'type': 'str'},
                'wanopt': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wanopt-detection': {
                    'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['active', 'passive', 'off'],
                    'type': 'str'
                },
                'wanopt-passive-opt': {
                    'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['default', 'transparent', 'non-transparent'],
                    'type': 'str'
                },
                'wanopt-peer': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'wanopt-profile': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'wccp': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webcache': {'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webcache-https': {
                    'v_range': [['6.0.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'ssl-server', 'any', 'enable'],
                    'type': 'str'
                },
                'webfilter-profile': {'type': 'str'},
                'wsso': {'v_range': [['6.0.0', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'anti-replay': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'app-group': {'v_range': [['6.2.0', '7.6.2']], 'type': 'raw'},
                'cifs-profile': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'email-collect': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'emailfilter-profile': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'fsso-groups': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'geoip-anycast': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-policy-redirect': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable', 'legacy'], 'type': 'str'},
                'inspection-mode': {'v_range': [['6.2.0', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'internet-service-custom-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-src': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-src-custom-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-src-group': {'v_range': [['6.2.0', '']], 'type': 'raw'},
                'internet-service-src-id': {'v_range': [['6.2.0', '7.6.2']], 'type': 'raw'},
                'internet-service-src-negate': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'match-vip-only': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'np-acceleration': {'v_range': [['6.2.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'reputation-direction': {'v_range': [['6.2.0', '']], 'choices': ['source', 'destination'], 'type': 'str'},
                'reputation-minimum': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'ssh-filter-profile': {'v_range': [['6.2.0', '7.2.4'], ['7.2.6', '']], 'type': 'str'},
                'ssh-policy-redirect': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tos': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'tos-mask': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'tos-negate': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vlan-filter': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'webproxy-forward-server': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'webproxy-profile': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'np-accelation': {'v_range': [['6.2.1', '6.4.15']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'delay-tcp-npu-sessoin': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'casi-profile': {'v_range': [['6.2.0', '6.2.13']], 'type': 'str'},
                'best-route': {'v_range': [['6.2.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'decrypted-traffic-mirror': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'dstaddr6': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'geoip-match': {'v_range': [['6.4.0', '']], 'choices': ['physical-location', 'registered-location'], 'type': 'str'},
                'internet-service-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'internet-service-src-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'poolname6': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'src-vendor-mac': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'srcaddr6': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'file-filter-profile': {'v_range': [['6.4.1', '7.2.4'], ['7.2.6', '']], 'type': 'str'},
                'policy-offload': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-session-quota': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'type': 'int'},
                'cgn-eif': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-log-server-grp': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'type': 'str'},
                'cgn-eim': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-resource-quota': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'type': 'int'},
                'dynamic-shaping': {'v_range': [['6.4.6', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'passive-wan-health-measurement': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'videofilter-profile': {'v_range': [['7.0.0', '7.2.4'], ['7.2.6', '']], 'type': 'str'},
                'ztna-ems-tag': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'ztna-geo-tag': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'ztna-status': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_policy_block': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'dlp-profile': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'fec': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat46': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pfcp-profile': {'v_range': [['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'policy-expiry': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-expiry-date': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'sctp-filter-profile': {'v_range': [['7.0.1', '7.2.4'], ['7.2.6', '']], 'type': 'str'},
                'sgt': {'v_range': [['7.0.1', '']], 'type': 'raw'},
                'sgt-check': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-timeout-pid': {'v_range': [['7.0.3', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'udp-timeout-pid': {'v_range': [['7.0.3', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'diffserv-copy': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr6-negate': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-custom': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-custom-group': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-group': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-name': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-negate': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src-custom': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-src-custom-group': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-src-group': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-src-name': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-src-negate': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'network-service-dynamic': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'network-service-src-dynamic': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'reputation-direction6': {'v_range': [['7.2.1', '']], 'choices': ['source', 'destination'], 'type': 'str'},
                'reputation-minimum6': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'srcaddr6-negate': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-version-type': {'v_range': [['7.2.6', '']], 'type': 'str'},
                'ips-voip-filter': {'v_range': [['7.2.6', '']], 'type': 'str'},
                'pcp-inbound': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pcp-outbound': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pcp-poolname': {'v_range': [['7.4.0', '']], 'type': 'raw'},
                'policy-behaviour-type': {'v_range': [['7.2.6', '']], 'type': 'str'},
                'policy-expiry-date-utc': {'v_range': [['7.2.6', '']], 'type': 'str'},
                'ztna-device-ownership': {'v_range': [['7.2.6', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ztna-ems-tag-secondary': {'v_range': [['7.4.0', '']], 'type': 'raw'},
                'ztna-policy-redirect': {'v_range': [['7.2.6', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ztna-tags-match-logic': {'v_range': [['7.2.6', '']], 'choices': ['or', 'and'], 'type': 'str'},
                'casb-profile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'virtual-patch-profile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'diameter-filter-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'port-preserve': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-sw-eif-ctrl': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eif-check': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eif-learn': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-http-transaction': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable', 'all', 'utm'], 'type': 'str'},
                'radius-ip-auth-bypass': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'app-monitor': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port-random': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ztna-ems-tag-negate': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'telemetry-profile': {'v_range': [['7.6.3', '']], 'type': 'raw'},
                'object position': {'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_policy'),
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
