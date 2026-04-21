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
module: fortios_firewall_policy
short_description: Configure IPv4/IPv6 policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and policy category.
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
    - We highly recommend using your own value as the policyid instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks
    - Adjust object order by moving self after(before) another.
    - Only one of [after, before] must be specified when action is moving an object.

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
    action:
        description:
            - the action indiactor to move an object in the list
        type: str
        choices:
            - 'move'
    self:
        description:
            - mkey of self identifier
        type: str
    after:
        description:
            - mkey of target identifier
        type: str
    before:
        description:
            - mkey of target identifier
        type: str

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: false
        choices:
            - 'present'
            - 'absent'
    firewall_policy:
        description:
            - Configure IPv4/IPv6 policies.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Policy action (accept/deny/ipsec).
                type: str
                choices:
                    - 'accept'
                    - 'deny'
                    - 'ipsec'
            anti_replay:
                description:
                    - Enable/disable anti-replay check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            app_category:
                description:
                    - Application category ID list.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Category IDs. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            app_group:
                description:
                    - Application group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Application group names. Source application.group.name.
                        required: true
                        type: str
            app_monitor:
                description:
                    - Enable/disable application TCP metrics in session logs.When enabled, auto-asic-offload is disabled.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            application:
                description:
                    - Application ID list.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Application IDs. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            application_list:
                description:
                    - Name of an existing Application list. Source application.list.name.
                type: str
            auth_cert:
                description:
                    - HTTPS server certificate for policy authentication. Source vpn.certificate.local.name.
                type: str
            auth_path:
                description:
                    - Enable/disable authentication-based routing.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_redirect_addr:
                description:
                    - HTTP-to-HTTPS redirect address for firewall authentication.
                type: str
            auto_asic_offload:
                description:
                    - Enable/disable policy traffic ASIC offloading.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            av_profile:
                description:
                    - Name of an existing Antivirus profile. Source antivirus.profile.name.
                type: str
            block_notification:
                description:
                    - Enable/disable block notification.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            captive_portal_exempt:
                description:
                    - Enable to exempt some users from the captive portal.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            capture_packet:
                description:
                    - Enable/disable capture packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            casb_profile:
                description:
                    - Name of an existing CASB profile. Source casb.profile.name.
                type: str
            cifs_profile:
                description:
                    - Name of an existing CIFS profile. Source cifs.profile.name.
                type: str
            comments:
                description:
                    - Comment.
                type: str
            custom_log_fields:
                description:
                    - Custom fields to append to log messages for this policy.
                type: list
                elements: dict
                suboptions:
                    field_id:
                        description:
                            - Custom log field. Source log.custom-field.id.
                        required: true
                        type: str
            decrypted_traffic_mirror:
                description:
                    - Decrypted traffic mirror. Source firewall.decrypted-traffic-mirror.name.
                type: str
            delay_tcp_npu_session:
                description:
                    - Enable TCP NPU session delay to guarantee packet order of 3-way handshake.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            devices:
                description:
                    - Names of devices or device groups that can be matched by the policy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Device or group name. Source user.device.alias user.device-group.name user.device-category.name.
                        required: true
                        type: str
            diameter_filter_profile:
                description:
                    - Name of an existing Diameter filter profile. Source diameter-filter.profile.name.
                type: str
            diffserv_copy:
                description:
                    - Enable to copy packet"s DiffServ values from session"s original direction to its reply direction.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            diffserv_forward:
                description:
                    - Enable to change packet"s DiffServ values to the specified diffservcode-forward value.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            diffserv_reverse:
                description:
                    - Enable to change packet"s reverse (reply) DiffServ values to the specified diffservcode-rev value.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            diffservcode_forward:
                description:
                    - Change packet"s DiffServ to this value.
                type: str
            diffservcode_rev:
                description:
                    - Change packet"s reverse (reply) DiffServ to this value.
                type: str
            disclaimer:
                description:
                    - Enable/disable user authentication disclaimer.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dlp_profile:
                description:
                    - Name of an existing DLP profile. Source dlp.profile.name.
                type: str
            dlp_sensor:
                description:
                    - Name of an existing DLP sensor. Source dlp.sensor.name.
                type: str
            dnsfilter_profile:
                description:
                    - Name of an existing DNS filter profile. Source dnsfilter.profile.name.
                type: str
            dscp_match:
                description:
                    - Enable DSCP check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dscp_negate:
                description:
                    - Enable negated DSCP match.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dscp_value:
                description:
                    - DSCP value.
                type: str
            dsri:
                description:
                    - Enable DSRI to ignore HTTP server responses.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dstaddr:
                description:
                    - Destination IPv4 address and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource
                              .name.
                        required: true
                        type: str
            dstaddr_negate:
                description:
                    - When enabled dstaddr specifies what the destination address must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dstaddr6:
                description:
                    - Destination IPv6 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                              .external-resource.name.
                        required: true
                        type: str
            dstaddr6_negate:
                description:
                    - When enabled dstaddr6 specifies what the destination address must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dstintf:
                description:
                    - Outgoing (egress) interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                        required: true
                        type: str
            dynamic_shaping:
                description:
                    - Enable/disable dynamic RADIUS defined traffic shaping.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            email_collect:
                description:
                    - Enable/disable email collection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            emailfilter_profile:
                description:
                    - Name of an existing email filter profile. Source emailfilter.profile.name.
                type: str
            fec:
                description:
                    - Enable/disable Forward Error Correction on traffic matching this policy on a FEC device.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            file_filter_profile:
                description:
                    - Name of an existing file-filter profile. Source file-filter.profile.name.
                type: str
            firewall_session_dirty:
                description:
                    - How to handle sessions if the configuration of this firewall policy changes.
                type: str
                choices:
                    - 'check-all'
                    - 'check-new'
            fixedport:
                description:
                    - Enable to prevent source NAT from changing a session"s source port.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fsso:
                description:
                    - Enable/disable Fortinet Single Sign-On.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fsso_agent_for_ntlm:
                description:
                    - FSSO agent to use for NTLM authentication. Source user.fsso.name.
                type: str
            fsso_groups:
                description:
                    - Names of FSSO groups.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Names of FSSO groups. Source user.adgrp.name.
                        required: true
                        type: str
            geoip_anycast:
                description:
                    - Enable/disable recognition of anycast IP addresses using the geography IP database.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            geoip_match:
                description:
                    - Match geography address based either on its physical location or registered location.
                type: str
                choices:
                    - 'physical-location'
                    - 'registered-location'
            global_label:
                description:
                    - Label for the policy that appears when the GUI is in Global View mode.
                type: str
            groups:
                description:
                    - Names of user groups that can authenticate with this policy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Group name. Source user.group.name.
                        required: true
                        type: str
            gtp_profile:
                description:
                    - GTP profile. Source firewall.gtp.name.
                type: str
            http_policy_redirect:
                description:
                    - Redirect HTTP(S) traffic to matching transparent web proxy policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'legacy'
            icap_profile:
                description:
                    - Name of an existing ICAP profile. Source icap.profile.name.
                type: str
            identity_based_route:
                description:
                    - Name of identity-based routing rule. Source firewall.identity-based-route.name.
                type: str
            inbound:
                description:
                    - 'Policy-based IPsec VPN: only traffic from the remote network can initiate a VPN.'
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            inspection_mode:
                description:
                    - Policy inspection mode (Flow/proxy). Default is Flow mode.
                type: str
                choices:
                    - 'proxy'
                    - 'flow'
            internet_service:
                description:
                    - Enable/disable use of Internet Services for this policy. If enabled, destination address and service are not used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service_custom:
                description:
                    - Custom Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service_custom_group:
                description:
                    - Custom Internet Service group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service_fortiguard:
                description:
                    - FortiGuard Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FortiGuard Internet Service name. Source firewall.internet-service-fortiguard.name.
                        required: true
                        type: str
            internet_service_group:
                description:
                    - Internet Service group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service_id:
                description:
                    - Internet Service ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Internet Service ID. see <a href='#notes'>Notes</a>. Source firewall.internet-service.id.
                        required: true
                        type: int
            internet_service_name:
                description:
                    - Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            internet_service_negate:
                description:
                    - When enabled internet-service specifies what the service must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service_src:
                description:
                    - Enable/disable use of Internet Services in source for this policy. If enabled, source address is not used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service_src_custom:
                description:
                    - Custom Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service_src_custom_group:
                description:
                    - Custom Internet Service source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service_src_fortiguard:
                description:
                    - FortiGuard Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FortiGuard Internet Service name. Source firewall.internet-service-fortiguard.name.
                        required: true
                        type: str
            internet_service_src_group:
                description:
                    - Internet Service source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service_src_id:
                description:
                    - Internet Service source ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Internet Service ID. see <a href='#notes'>Notes</a>. Source firewall.internet-service.id.
                        required: true
                        type: int
            internet_service_src_name:
                description:
                    - Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            internet_service_src_negate:
                description:
                    - When enabled internet-service-src specifies what the service must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service6:
                description:
                    - Enable/disable use of IPv6 Internet Services for this policy. If enabled, destination address and service are not used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service6_custom:
                description:
                    - Custom IPv6 Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service6_custom_group:
                description:
                    - Custom Internet Service6 group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service6 group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service6_fortiguard:
                description:
                    - FortiGuard IPv6 Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FortiGuard Internet Service name. Source firewall.internet-service-fortiguard.name.
                        required: true
                        type: str
            internet_service6_group:
                description:
                    - Internet Service group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service6_name:
                description:
                    - IPv6 Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IPv6 Internet Service name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            internet_service6_negate:
                description:
                    - When enabled internet-service6 specifies what the service must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service6_src:
                description:
                    - Enable/disable use of IPv6 Internet Services in source for this policy. If enabled, source address is not used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service6_src_custom:
                description:
                    - Custom IPv6 Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service6_src_custom_group:
                description:
                    - Custom Internet Service6 source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service6 group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service6_src_fortiguard:
                description:
                    - FortiGuard IPv6 Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FortiGuard Internet Service name. Source firewall.internet-service-fortiguard.name.
                        required: true
                        type: str
            internet_service6_src_group:
                description:
                    - Internet Service6 source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service6_src_name:
                description:
                    - IPv6 Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            internet_service6_src_negate:
                description:
                    - When enabled internet-service6-src specifies what the service must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ippool:
                description:
                    - Enable to use IP Pools for source NAT.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ips_sensor:
                description:
                    - Name of an existing IPS sensor. Source ips.sensor.name.
                type: str
            ips_voip_filter:
                description:
                    - Name of an existing VoIP (ips) profile. Source voip.profile.name.
                type: str
            label:
                description:
                    - Label for the policy that appears when the GUI is in Section View mode.
                type: str
            learning_mode:
                description:
                    - Enable to allow everything, but log all of the meaningful data for security information gathering. A learning report will be generated.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_http_transaction:
                description:
                    - Enable/disable HTTP transaction log.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            logtraffic:
                description:
                    - Enable or disable logging. Log all sessions or security profile sessions.
                type: str
                choices:
                    - 'all'
                    - 'utm'
                    - 'disable'
            logtraffic_start:
                description:
                    - Record logs when a session starts.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            match_vip:
                description:
                    - Enable to match packets that have had their destination addresses changed by a VIP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            match_vip_only:
                description:
                    - Enable/disable matching of only those packets that have had their destination addresses changed by a VIP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mms_profile:
                description:
                    - Name of an existing MMS profile. Source firewall.mms-profile.name.
                type: str
            name:
                description:
                    - Policy name.
                type: str
            nat:
                description:
                    - Enable/disable source NAT.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nat46:
                description:
                    - Enable/disable NAT46.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nat64:
                description:
                    - Enable/disable NAT64.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            natinbound:
                description:
                    - 'Policy-based IPsec VPN: apply destination NAT to inbound traffic.'
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            natip:
                description:
                    - 'Policy-based IPsec VPN: source NAT IP address for outgoing traffic.'
                type: str
            natoutbound:
                description:
                    - 'Policy-based IPsec VPN: apply source NAT to outbound traffic.'
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            network_service_dynamic:
                description:
                    - Dynamic Network Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Dynamic Network Service name. Source firewall.network-service-dynamic.name.
                        required: true
                        type: str
            network_service_src_dynamic:
                description:
                    - Dynamic Network Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Dynamic Network Service name. Source firewall.network-service-dynamic.name.
                        required: true
                        type: str
            np_acceleration:
                description:
                    - Enable/disable UTM Network Processor acceleration.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ntlm:
                description:
                    - Enable/disable NTLM authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ntlm_enabled_browsers:
                description:
                    - HTTP-User-Agent value of supported browsers.
                type: list
                elements: dict
                suboptions:
                    user_agent_string:
                        description:
                            - User agent string.
                        required: true
                        type: str
            ntlm_guest:
                description:
                    - Enable/disable NTLM guest user access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            outbound:
                description:
                    - 'Policy-based IPsec VPN: only traffic from the internal network can initiate a VPN.'
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            passive_wan_health_measurement:
                description:
                    - Enable/disable passive WAN health measurement. When enabled, auto-asic-offload is disabled.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pcp_inbound:
                description:
                    - Enable/disable PCP inbound DNAT.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pcp_outbound:
                description:
                    - Enable/disable PCP outbound SNAT.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pcp_poolname:
                description:
                    - PCP pool names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - PCP pool name. Source system.pcp-server.pools.name.
                        required: true
                        type: str
            per_ip_shaper:
                description:
                    - Per-IP traffic shaper. Source firewall.shaper.per-ip-shaper.name.
                type: str
            permit_any_host:
                description:
                    - Accept UDP packets from any host.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            permit_stun_host:
                description:
                    - Accept UDP packets from any Session Traversal Utilities for NAT (STUN) host.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pfcp_profile:
                description:
                    - PFCP profile. Source firewall.pfcp.name.
                type: str
            policy_expiry:
                description:
                    - Enable/disable policy expiry.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            policy_expiry_date:
                description:
                    - 'Policy expiry date (YYYY-MM-DD HH:MM:SS).'
                type: str
            policy_expiry_date_utc:
                description:
                    - Policy expiry date and time, in epoch format.
                type: str
            policyid:
                description:
                    - Policy ID (0 - 4294967294). see <a href='#notes'>Notes</a>.
                required: true
                type: int
            poolname:
                description:
                    - IP Pool names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IP pool name. Source firewall.ippool.name.
                        required: true
                        type: str
            poolname6:
                description:
                    - IPv6 pool names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IPv6 pool name. Source firewall.ippool6.name.
                        required: true
                        type: str
            port_preserve:
                description:
                    - Enable/disable preservation of the original source port from source NAT if it has not been used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            port_random:
                description:
                    - Enable/disable random source port selection for source NAT.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            profile_group:
                description:
                    - Name of profile group. Source firewall.profile-group.name.
                type: str
            profile_protocol_options:
                description:
                    - Name of an existing Protocol options profile. Source firewall.profile-protocol-options.name.
                type: str
            profile_type:
                description:
                    - Determine whether the firewall policy allows security profile groups or single profiles only.
                type: str
                choices:
                    - 'single'
                    - 'group'
            radius_ip_auth_bypass:
                description:
                    - Enable IP authentication bypass. The bypassed IP address must be received from RADIUS server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            radius_mac_auth_bypass:
                description:
                    - Enable MAC authentication bypass. The bypassed MAC address must be received from RADIUS server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            redirect_url:
                description:
                    - URL users are directed to after seeing and accepting the disclaimer or authenticating.
                type: str
            replacemsg_override_group:
                description:
                    - Override the default replacement message group for this policy. Source system.replacemsg-group.name.
                type: str
            reputation_direction:
                description:
                    - Direction of the initial traffic for reputation to take effect.
                type: str
                choices:
                    - 'source'
                    - 'destination'
            reputation_direction6:
                description:
                    - Direction of the initial traffic for IPv6 reputation to take effect.
                type: str
                choices:
                    - 'source'
                    - 'destination'
            reputation_minimum:
                description:
                    - Minimum Reputation to take action. Source firewall.internet-service-reputation.id.
                type: int
            reputation_minimum6:
                description:
                    - IPv6 Minimum Reputation to take action. Source firewall.internet-service-reputation.id.
                type: int
            rsso:
                description:
                    - Enable/disable RADIUS single sign-on (RSSO).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rtp_addr:
                description:
                    - Address names if this is an RTP NAT policy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.internet-service-custom-group.name firewall.addrgrp.name.
                        required: true
                        type: str
            rtp_nat:
                description:
                    - Enable Real Time Protocol (RTP) NAT.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            saml_server:
                description:
                    - SAML server name. Source user.saml.name.
                type: str
            scan_botnet_connections:
                description:
                    - Block or monitor connections to Botnet servers or disable Botnet scanning.
                type: str
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                description:
                    - Schedule name. Source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name.
                type: str
            schedule_timeout:
                description:
                    - Enable to force current sessions to end when the schedule object times out. Disable allows them to end from inactivity.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            scim:
                description:
                    - Enable/disable SCIM .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            scim_groups:
                description:
                    - Names of SCIM groups.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Names of SCIM groups.
                        required: true
                        type: str
            scim_users:
                description:
                    - Names of SCIM users.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Names of SCIM users.
                        required: true
                        type: str
            sctp_filter_profile:
                description:
                    - Name of an existing SCTP filter profile. Source sctp-filter.profile.name.
                type: str
            send_deny_packet:
                description:
                    - Enable to send a reply when a session is denied or blocked by a firewall policy.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            service:
                description:
                    - Service and service group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Service and service group names. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
                        type: str
            service_negate:
                description:
                    - When enabled service specifies what the service must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            session_ttl:
                description:
                    - TTL in seconds for sessions accepted by this policy (0 means use the system ).
                type: str
            sgt:
                description:
                    - Security group tags.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Security group tag (1 - 65535). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            sgt_check:
                description:
                    - Enable/disable security group tags (SGT) check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            spamfilter_profile:
                description:
                    - Name of an existing Spam filter profile. Source spamfilter.profile.name.
                type: str
            src_vendor_mac:
                description:
                    - Vendor MAC source ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Vendor MAC ID. see <a href='#notes'>Notes</a>. Source firewall.vendor-mac.id.
                        required: true
                        type: int
            srcaddr:
                description:
                    - Source IPv4 address and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name system.external-resource.name.
                        required: true
                        type: str
            srcaddr_negate:
                description:
                    - When enabled srcaddr specifies what the source address must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            srcaddr6:
                description:
                    - Source IPv6 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name system.external-resource.name firewall.addrgrp6.name.
                        required: true
                        type: str
            srcaddr6_negate:
                description:
                    - When enabled srcaddr6 specifies what the source address must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            srcintf:
                description:
                    - Incoming (ingress) interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                        required: true
                        type: str
            ssh_filter_profile:
                description:
                    - Name of an existing SSH filter profile. Source ssh-filter.profile.name.
                type: str
            ssh_policy_redirect:
                description:
                    - Redirect SSH traffic to matching transparent proxy policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_mirror:
                description:
                    - Enable to copy decrypted SSL traffic to a FortiGate interface (called SSL mirroring).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_mirror_intf:
                description:
                    - SSL mirror interface name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Mirror Interface name. Source system.interface.name system.zone.name.
                        required: true
                        type: str
            ssl_ssh_profile:
                description:
                    - Name of an existing SSL SSH profile. Source firewall.ssl-ssh-profile.name.
                type: str
            status:
                description:
                    - Enable or disable this policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tcp_mss_receiver:
                description:
                    - Receiver TCP maximum segment size (MSS).
                type: int
            tcp_mss_sender:
                description:
                    - Sender TCP maximum segment size (MSS).
                type: int
            tcp_session_without_syn:
                description:
                    - Enable/disable creation of TCP session without SYN flag.
                type: str
                choices:
                    - 'all'
                    - 'data-only'
                    - 'disable'
            telemetry_profile:
                description:
                    - Name of an existing telemetry profile. Source telemetry-controller.profile.name.
                type: str
            timeout_send_rst:
                description:
                    - Enable/disable sending RST packets when TCP sessions expire.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tos:
                description:
                    - ToS (Type of Service) value used for comparison.
                type: str
            tos_mask:
                description:
                    - Non-zero bit positions are used for comparison while zero bit positions are ignored.
                type: str
            tos_negate:
                description:
                    - Enable negated TOS match.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            traffic_shaper:
                description:
                    - Traffic shaper. Source firewall.shaper.traffic-shaper.name.
                type: str
            traffic_shaper_reverse:
                description:
                    - Reverse traffic shaper. Source firewall.shaper.traffic-shaper.name.
                type: str
            url_category:
                description:
                    - URL category ID list.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - URL category ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            users:
                description:
                    - Names of individual users that can authenticate with this policy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Names of individual users that can authenticate with this policy. Source user.local.name user.certificate.name.
                        required: true
                        type: str
            utm_status:
                description:
                    - Enable to add one or more security profiles (AV, IPS, etc.) to the firewall policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            videofilter_profile:
                description:
                    - Name of an existing VideoFilter profile. Source videofilter.profile.name.
                type: str
            virtual_patch_profile:
                description:
                    - Name of an existing virtual-patch profile. Source virtual-patch.profile.name.
                type: str
            vlan_cos_fwd:
                description:
                    - 'VLAN forward direction user priority: 255 passthrough, 0 lowest, 7 highest.'
                type: int
            vlan_cos_rev:
                description:
                    - 'VLAN reverse direction user priority: 255 passthrough, 0 lowest, 7 highest.'
                type: int
            vlan_filter:
                description:
                    - VLAN ranges to allow
                type: str
            voip_profile:
                description:
                    - Name of an existing VoIP (voipd) profile. Source voip.profile.name.
                type: str
            vpntunnel:
                description:
                    - 'Policy-based IPsec VPN: name of the IPsec VPN Phase 1. Source vpn.ipsec.phase1.name vpn.ipsec.manualkey.name.'
                type: str
            waf_profile:
                description:
                    - Name of an existing Web application firewall profile. Source waf.profile.name.
                type: str
            wanopt:
                description:
                    - Enable/disable WAN optimization.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wanopt_detection:
                description:
                    - WAN optimization auto-detection mode.
                type: str
                choices:
                    - 'active'
                    - 'passive'
                    - 'off'
            wanopt_passive_opt:
                description:
                    - WAN optimization passive mode options. This option decides what IP address will be used to connect server.
                type: str
                choices:
                    - 'default'
                    - 'transparent'
                    - 'non-transparent'
            wanopt_peer:
                description:
                    - WAN optimization peer. Source wanopt.peer.peer-host-id.
                type: str
            wanopt_profile:
                description:
                    - WAN optimization profile. Source wanopt.profile.name.
                type: str
            wccp:
                description:
                    - Enable/disable forwarding traffic matching this policy to a configured WCCP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            webcache:
                description:
                    - Enable/disable web cache.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            webcache_https:
                description:
                    - Enable/disable web cache for HTTPS.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            webfilter_profile:
                description:
                    - Name of an existing Web filter profile. Source webfilter.profile.name.
                type: str
            webproxy_forward_server:
                description:
                    - Webproxy forward server name. Source web-proxy.forward-server.name web-proxy.forward-server-group.name.
                type: str
            webproxy_profile:
                description:
                    - Webproxy profile name. Source web-proxy.profile.name.
                type: str
            wsso:
                description:
                    - Enable/disable WiFi Single Sign On (WSSO).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ztna_device_ownership:
                description:
                    - Enable/disable zero trust device ownership.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ztna_ems_tag:
                description:
                    - Source ztna-ems-tag names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            ztna_ems_tag_negate:
                description:
                    - When enabled ztna-ems-tag specifies what the tags must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ztna_ems_tag_secondary:
                description:
                    - Source ztna-ems-tag-secondary names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            ztna_geo_tag:
                description:
                    - Source ztna-geo-tag names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            ztna_policy_redirect:
                description:
                    - Redirect ZTNA traffic to matching Access-Proxy proxy-policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ztna_status:
                description:
                    - Enable/disable zero trust access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ztna_tags_match_logic:
                description:
                    - ZTNA tag matching logic.
                type: str
                choices:
                    - 'or'
                    - 'and'
"""

EXAMPLES = """
- name: Configure IPv4/IPv6 policies.
  fortinet.fortios.fortios_firewall_policy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_policy:
          action: "accept"
          anti_replay: "enable"
          app_category:
              -
                  id: "6"
          app_group:
              -
                  name: "default_name_8 (source application.group.name)"
          app_monitor: "enable"
          application:
              -
                  id: "11"
          application_list: "<your_own_value> (source application.list.name)"
          auth_cert: "<your_own_value> (source vpn.certificate.local.name)"
          auth_path: "enable"
          auth_redirect_addr: "<your_own_value>"
          auto_asic_offload: "enable"
          av_profile: "<your_own_value> (source antivirus.profile.name)"
          block_notification: "enable"
          captive_portal_exempt: "enable"
          capture_packet: "enable"
          casb_profile: "<your_own_value> (source casb.profile.name)"
          cifs_profile: "<your_own_value> (source cifs.profile.name)"
          comments: "<your_own_value>"
          custom_log_fields:
              -
                  field_id: "<your_own_value> (source log.custom-field.id)"
          decrypted_traffic_mirror: "<your_own_value> (source firewall.decrypted-traffic-mirror.name)"
          delay_tcp_npu_session: "enable"
          devices:
              -
                  name: "default_name_29 (source user.device.alias user.device-group.name user.device-category.name)"
          diameter_filter_profile: "<your_own_value> (source diameter-filter.profile.name)"
          diffserv_copy: "enable"
          diffserv_forward: "enable"
          diffserv_reverse: "enable"
          diffservcode_forward: "<your_own_value>"
          diffservcode_rev: "<your_own_value>"
          disclaimer: "enable"
          dlp_profile: "<your_own_value> (source dlp.profile.name)"
          dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
          dnsfilter_profile: "<your_own_value> (source dnsfilter.profile.name)"
          dscp_match: "enable"
          dscp_negate: "enable"
          dscp_value: "<your_own_value>"
          dsri: "enable"
          dstaddr:
              -
                  name: "default_name_45 (source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource
                    .name)"
          dstaddr_negate: "enable"
          dstaddr6:
              -
                  name: "default_name_48 (source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                    .external-resource.name)"
          dstaddr6_negate: "enable"
          dstintf:
              -
                  name: "default_name_51 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          dynamic_shaping: "enable"
          email_collect: "enable"
          emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
          fec: "enable"
          file_filter_profile: "<your_own_value> (source file-filter.profile.name)"
          firewall_session_dirty: "check-all"
          fixedport: "enable"
          fsso: "enable"
          fsso_agent_for_ntlm: "<your_own_value> (source user.fsso.name)"
          fsso_groups:
              -
                  name: "default_name_62 (source user.adgrp.name)"
          geoip_anycast: "enable"
          geoip_match: "physical-location"
          global_label: "<your_own_value>"
          groups:
              -
                  name: "default_name_67 (source user.group.name)"
          gtp_profile: "<your_own_value> (source firewall.gtp.name)"
          http_policy_redirect: "enable"
          icap_profile: "<your_own_value> (source icap.profile.name)"
          identity_based_route: "<your_own_value> (source firewall.identity-based-route.name)"
          inbound: "enable"
          inspection_mode: "proxy"
          internet_service: "enable"
          internet_service_custom:
              -
                  name: "default_name_76 (source firewall.internet-service-custom.name)"
          internet_service_custom_group:
              -
                  name: "default_name_78 (source firewall.internet-service-custom-group.name)"
          internet_service_fortiguard:
              -
                  name: "default_name_80 (source firewall.internet-service-fortiguard.name)"
          internet_service_group:
              -
                  name: "default_name_82 (source firewall.internet-service-group.name)"
          internet_service_id:
              -
                  id: "84 (source firewall.internet-service.id)"
          internet_service_name:
              -
                  name: "default_name_86 (source firewall.internet-service-name.name)"
          internet_service_negate: "enable"
          internet_service_src: "enable"
          internet_service_src_custom:
              -
                  name: "default_name_90 (source firewall.internet-service-custom.name)"
          internet_service_src_custom_group:
              -
                  name: "default_name_92 (source firewall.internet-service-custom-group.name)"
          internet_service_src_fortiguard:
              -
                  name: "default_name_94 (source firewall.internet-service-fortiguard.name)"
          internet_service_src_group:
              -
                  name: "default_name_96 (source firewall.internet-service-group.name)"
          internet_service_src_id:
              -
                  id: "98 (source firewall.internet-service.id)"
          internet_service_src_name:
              -
                  name: "default_name_100 (source firewall.internet-service-name.name)"
          internet_service_src_negate: "enable"
          internet_service6: "enable"
          internet_service6_custom:
              -
                  name: "default_name_104 (source firewall.internet-service-custom.name)"
          internet_service6_custom_group:
              -
                  name: "default_name_106 (source firewall.internet-service-custom-group.name)"
          internet_service6_fortiguard:
              -
                  name: "default_name_108 (source firewall.internet-service-fortiguard.name)"
          internet_service6_group:
              -
                  name: "default_name_110 (source firewall.internet-service-group.name)"
          internet_service6_name:
              -
                  name: "default_name_112 (source firewall.internet-service-name.name)"
          internet_service6_negate: "enable"
          internet_service6_src: "enable"
          internet_service6_src_custom:
              -
                  name: "default_name_116 (source firewall.internet-service-custom.name)"
          internet_service6_src_custom_group:
              -
                  name: "default_name_118 (source firewall.internet-service-custom-group.name)"
          internet_service6_src_fortiguard:
              -
                  name: "default_name_120 (source firewall.internet-service-fortiguard.name)"
          internet_service6_src_group:
              -
                  name: "default_name_122 (source firewall.internet-service-group.name)"
          internet_service6_src_name:
              -
                  name: "default_name_124 (source firewall.internet-service-name.name)"
          internet_service6_src_negate: "enable"
          ippool: "enable"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          ips_voip_filter: "<your_own_value> (source voip.profile.name)"
          label: "<your_own_value>"
          learning_mode: "enable"
          log_http_transaction: "enable"
          logtraffic: "all"
          logtraffic_start: "enable"
          match_vip: "enable"
          match_vip_only: "enable"
          mms_profile: "<your_own_value> (source firewall.mms-profile.name)"
          name: "default_name_137"
          nat: "enable"
          nat46: "enable"
          nat64: "enable"
          natinbound: "enable"
          natip: "<your_own_value>"
          natoutbound: "enable"
          network_service_dynamic:
              -
                  name: "default_name_145 (source firewall.network-service-dynamic.name)"
          network_service_src_dynamic:
              -
                  name: "default_name_147 (source firewall.network-service-dynamic.name)"
          np_acceleration: "enable"
          ntlm: "enable"
          ntlm_enabled_browsers:
              -
                  user_agent_string: "<your_own_value>"
          ntlm_guest: "enable"
          outbound: "enable"
          passive_wan_health_measurement: "enable"
          pcp_inbound: "enable"
          pcp_outbound: "enable"
          pcp_poolname:
              -
                  name: "default_name_158 (source system.pcp-server.pools.name)"
          per_ip_shaper: "<your_own_value> (source firewall.shaper.per-ip-shaper.name)"
          permit_any_host: "enable"
          permit_stun_host: "enable"
          pfcp_profile: "<your_own_value> (source firewall.pfcp.name)"
          policy_expiry: "enable"
          policy_expiry_date: "<your_own_value>"
          policy_expiry_date_utc: "<your_own_value>"
          policyid: "<you_own_value>"
          poolname:
              -
                  name: "default_name_168 (source firewall.ippool.name)"
          poolname6:
              -
                  name: "default_name_170 (source firewall.ippool6.name)"
          port_preserve: "enable"
          port_random: "enable"
          profile_group: "<your_own_value> (source firewall.profile-group.name)"
          profile_protocol_options: "<your_own_value> (source firewall.profile-protocol-options.name)"
          profile_type: "single"
          radius_ip_auth_bypass: "enable"
          radius_mac_auth_bypass: "enable"
          redirect_url: "<your_own_value>"
          replacemsg_override_group: "<your_own_value> (source system.replacemsg-group.name)"
          reputation_direction: "source"
          reputation_direction6: "source"
          reputation_minimum: "0"
          reputation_minimum6: "0"
          rsso: "enable"
          rtp_addr:
              -
                  name: "default_name_186 (source firewall.internet-service-custom-group.name firewall.addrgrp.name)"
          rtp_nat: "disable"
          saml_server: "<your_own_value> (source user.saml.name)"
          scan_botnet_connections: "disable"
          schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
          schedule_timeout: "enable"
          scim: "enable"
          scim_groups:
              -
                  name: "default_name_194"
          scim_users:
              -
                  name: "default_name_196"
          sctp_filter_profile: "<your_own_value> (source sctp-filter.profile.name)"
          send_deny_packet: "disable"
          service:
              -
                  name: "default_name_200 (source firewall.service.custom.name firewall.service.group.name)"
          service_negate: "enable"
          session_ttl: "<your_own_value>"
          sgt:
              -
                  id: "204"
          sgt_check: "enable"
          spamfilter_profile: "<your_own_value> (source spamfilter.profile.name)"
          src_vendor_mac:
              -
                  id: "208 (source firewall.vendor-mac.id)"
          srcaddr:
              -
                  name: "default_name_210 (source firewall.address.name firewall.addrgrp.name system.external-resource.name)"
          srcaddr_negate: "enable"
          srcaddr6:
              -
                  name: "default_name_213 (source firewall.address6.name system.external-resource.name firewall.addrgrp6.name)"
          srcaddr6_negate: "enable"
          srcintf:
              -
                  name: "default_name_216 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          ssh_filter_profile: "<your_own_value> (source ssh-filter.profile.name)"
          ssh_policy_redirect: "enable"
          ssl_mirror: "enable"
          ssl_mirror_intf:
              -
                  name: "default_name_221 (source system.interface.name system.zone.name)"
          ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
          status: "enable"
          tcp_mss_receiver: "0"
          tcp_mss_sender: "0"
          tcp_session_without_syn: "all"
          telemetry_profile: "<your_own_value> (source telemetry-controller.profile.name)"
          timeout_send_rst: "enable"
          tos: "<your_own_value>"
          tos_mask: "<your_own_value>"
          tos_negate: "enable"
          traffic_shaper: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
          traffic_shaper_reverse: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
          url_category:
              -
                  id: "235"
          users:
              -
                  name: "default_name_237 (source user.local.name user.certificate.name)"
          utm_status: "enable"
          uuid: "<your_own_value>"
          videofilter_profile: "<your_own_value> (source videofilter.profile.name)"
          virtual_patch_profile: "<your_own_value> (source virtual-patch.profile.name)"
          vlan_cos_fwd: "255"
          vlan_cos_rev: "255"
          vlan_filter: "<your_own_value>"
          voip_profile: "<your_own_value> (source voip.profile.name)"
          vpntunnel: "<your_own_value> (source vpn.ipsec.phase1.name vpn.ipsec.manualkey.name)"
          waf_profile: "<your_own_value> (source waf.profile.name)"
          wanopt: "enable"
          wanopt_detection: "active"
          wanopt_passive_opt: "default"
          wanopt_peer: "<your_own_value> (source wanopt.peer.peer-host-id)"
          wanopt_profile: "<your_own_value> (source wanopt.profile.name)"
          wccp: "enable"
          webcache: "enable"
          webcache_https: "disable"
          webfilter_profile: "<your_own_value> (source webfilter.profile.name)"
          webproxy_forward_server: "<your_own_value> (source web-proxy.forward-server.name web-proxy.forward-server-group.name)"
          webproxy_profile: "<your_own_value> (source web-proxy.profile.name)"
          wsso: "enable"
          ztna_device_ownership: "enable"
          ztna_ems_tag:
              -
                  name: "default_name_262 (source firewall.address.name firewall.addrgrp.name)"
          ztna_ems_tag_negate: "enable"
          ztna_ems_tag_secondary:
              -
                  name: "default_name_265 (source firewall.address.name firewall.addrgrp.name)"
          ztna_geo_tag:
              -
                  name: "default_name_267 (source firewall.address.name firewall.addrgrp.name)"
          ztna_policy_redirect: "enable"
          ztna_status: "enable"
          ztna_tags_match_logic: "or"
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


def filter_firewall_policy_data(json):
    option_list = [
        "action",
        "anti_replay",
        "app_category",
        "app_group",
        "app_monitor",
        "application",
        "application_list",
        "auth_cert",
        "auth_path",
        "auth_redirect_addr",
        "auto_asic_offload",
        "av_profile",
        "block_notification",
        "captive_portal_exempt",
        "capture_packet",
        "casb_profile",
        "cifs_profile",
        "comments",
        "custom_log_fields",
        "decrypted_traffic_mirror",
        "delay_tcp_npu_session",
        "devices",
        "diameter_filter_profile",
        "diffserv_copy",
        "diffserv_forward",
        "diffserv_reverse",
        "diffservcode_forward",
        "diffservcode_rev",
        "disclaimer",
        "dlp_profile",
        "dlp_sensor",
        "dnsfilter_profile",
        "dscp_match",
        "dscp_negate",
        "dscp_value",
        "dsri",
        "dstaddr",
        "dstaddr_negate",
        "dstaddr6",
        "dstaddr6_negate",
        "dstintf",
        "dynamic_shaping",
        "email_collect",
        "emailfilter_profile",
        "fec",
        "file_filter_profile",
        "firewall_session_dirty",
        "fixedport",
        "fsso",
        "fsso_agent_for_ntlm",
        "fsso_groups",
        "geoip_anycast",
        "geoip_match",
        "global_label",
        "groups",
        "gtp_profile",
        "http_policy_redirect",
        "icap_profile",
        "identity_based_route",
        "inbound",
        "inspection_mode",
        "internet_service",
        "internet_service_custom",
        "internet_service_custom_group",
        "internet_service_fortiguard",
        "internet_service_group",
        "internet_service_id",
        "internet_service_name",
        "internet_service_negate",
        "internet_service_src",
        "internet_service_src_custom",
        "internet_service_src_custom_group",
        "internet_service_src_fortiguard",
        "internet_service_src_group",
        "internet_service_src_id",
        "internet_service_src_name",
        "internet_service_src_negate",
        "internet_service6",
        "internet_service6_custom",
        "internet_service6_custom_group",
        "internet_service6_fortiguard",
        "internet_service6_group",
        "internet_service6_name",
        "internet_service6_negate",
        "internet_service6_src",
        "internet_service6_src_custom",
        "internet_service6_src_custom_group",
        "internet_service6_src_fortiguard",
        "internet_service6_src_group",
        "internet_service6_src_name",
        "internet_service6_src_negate",
        "ippool",
        "ips_sensor",
        "ips_voip_filter",
        "label",
        "learning_mode",
        "log_http_transaction",
        "logtraffic",
        "logtraffic_start",
        "match_vip",
        "match_vip_only",
        "mms_profile",
        "name",
        "nat",
        "nat46",
        "nat64",
        "natinbound",
        "natip",
        "natoutbound",
        "network_service_dynamic",
        "network_service_src_dynamic",
        "np_acceleration",
        "ntlm",
        "ntlm_enabled_browsers",
        "ntlm_guest",
        "outbound",
        "passive_wan_health_measurement",
        "pcp_inbound",
        "pcp_outbound",
        "pcp_poolname",
        "per_ip_shaper",
        "permit_any_host",
        "permit_stun_host",
        "pfcp_profile",
        "policy_expiry",
        "policy_expiry_date",
        "policy_expiry_date_utc",
        "policyid",
        "poolname",
        "poolname6",
        "port_preserve",
        "port_random",
        "profile_group",
        "profile_protocol_options",
        "profile_type",
        "radius_ip_auth_bypass",
        "radius_mac_auth_bypass",
        "redirect_url",
        "replacemsg_override_group",
        "reputation_direction",
        "reputation_direction6",
        "reputation_minimum",
        "reputation_minimum6",
        "rsso",
        "rtp_addr",
        "rtp_nat",
        "saml_server",
        "scan_botnet_connections",
        "schedule",
        "schedule_timeout",
        "scim",
        "scim_groups",
        "scim_users",
        "sctp_filter_profile",
        "send_deny_packet",
        "service",
        "service_negate",
        "session_ttl",
        "sgt",
        "sgt_check",
        "spamfilter_profile",
        "src_vendor_mac",
        "srcaddr",
        "srcaddr_negate",
        "srcaddr6",
        "srcaddr6_negate",
        "srcintf",
        "ssh_filter_profile",
        "ssh_policy_redirect",
        "ssl_mirror",
        "ssl_mirror_intf",
        "ssl_ssh_profile",
        "status",
        "tcp_mss_receiver",
        "tcp_mss_sender",
        "tcp_session_without_syn",
        "telemetry_profile",
        "timeout_send_rst",
        "tos",
        "tos_mask",
        "tos_negate",
        "traffic_shaper",
        "traffic_shaper_reverse",
        "url_category",
        "users",
        "utm_status",
        "uuid",
        "videofilter_profile",
        "virtual_patch_profile",
        "vlan_cos_fwd",
        "vlan_cos_rev",
        "vlan_filter",
        "voip_profile",
        "vpntunnel",
        "waf_profile",
        "wanopt",
        "wanopt_detection",
        "wanopt_passive_opt",
        "wanopt_peer",
        "wanopt_profile",
        "wccp",
        "webcache",
        "webcache_https",
        "webfilter_profile",
        "webproxy_forward_server",
        "webproxy_profile",
        "wsso",
        "ztna_device_ownership",
        "ztna_ems_tag",
        "ztna_ems_tag_negate",
        "ztna_ems_tag_secondary",
        "ztna_geo_tag",
        "ztna_policy_redirect",
        "ztna_status",
        "ztna_tags_match_logic",
    ]

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


def firewall_policy(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_policy_data = data["firewall_policy"]

    filtered_data = filter_firewall_policy_data(firewall_policy_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "policy", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "policy", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_policy"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "policy",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "policy", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "policy", mkey=converted_data["policyid"], vdom=vdom
        )
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


def move_fortios_firewall(data, fos):
    if not data["self"] or (not data["after"] and not data["before"]):
        fos._module.fail_json(msg="self, after(or before) must not be empty")
    vdom = data["vdom"]
    params_set = dict()
    params_set["action"] = "move"
    if data["after"]:
        params_set["after"] = data["after"]
    if data["before"]:
        params_set["before"] = data["before"]
    return fos.set(
        "firewall",
        "policy",
        data=None,
        mkey=data["self"],
        vdom=vdom,
        parameters=params_set,
    )


def fortios_firewall(data, fos, check_mode):

    if data["action"] == "move":
        resp = move_fortios_firewall(data, fos)
    elif data["firewall_policy"]:
        resp = firewall_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_policy"))
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
        "policyid": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "uuid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "srcintf": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "dstintf": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "accept"}, {"value": "deny"}, {"value": "ipsec"}],
        },
        "nat64": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nat46": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ztna_status": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ztna_device_ownership": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "srcaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "dstaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "srcaddr6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "dstaddr6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "ztna_ems_tag": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
        },
        "ztna_ems_tag_secondary": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.0", ""]],
        },
        "ztna_tags_match_logic": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "or"}, {"value": "and"}],
        },
        "ztna_geo_tag": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
        },
        "internet_service": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "internet_service_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
        "internet_service_custom": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "network_service_dynamic": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service_custom_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
        "internet_service_src": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service_src_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "internet_service_src_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
        "internet_service_src_custom": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "network_service_src_dynamic": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service_src_custom_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
        "reputation_minimum": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "reputation_direction": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "source"}, {"value": "destination"}],
        },
        "src_vendor_mac": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.4.0", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v6.4.0", ""]],
        },
        "internet_service6": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service6_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service6_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service6_custom": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service6_custom_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service6_src": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service6_src_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service6_src_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service6_src_custom": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "internet_service6_src_custom_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.1", ""]],
        },
        "reputation_minimum6": {"v_range": [["v7.2.1", ""]], "type": "integer"},
        "reputation_direction6": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "source"}, {"value": "destination"}],
        },
        "rtp_nat": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "rtp_addr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "send_deny_packet": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "firewall_session_dirty": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "check-all"}, {"value": "check-new"}],
        },
        "schedule": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "schedule_timeout": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "policy_expiry": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "policy_expiry_date": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "policy_expiry_date_utc": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "service": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "tos_mask": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "tos": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "tos_negate": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "anti_replay": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tcp_session_without_syn": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "data-only"}, {"value": "disable"}],
        },
        "geoip_anycast": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "geoip_match": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [
                {"value": "physical-location"},
                {"value": "registered-location"},
            ],
        },
        "dynamic_shaping": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "passive_wan_health_measurement": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "app_monitor": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "utm_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "inspection_mode": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "proxy"}, {"value": "flow"}],
        },
        "http_policy_redirect": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "enable"},
                {"value": "disable"},
                {"value": "legacy", "v_range": [["v7.6.3", ""]]},
            ],
        },
        "ssh_policy_redirect": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ztna_policy_redirect": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webproxy_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "profile_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "single"}, {"value": "group"}],
        },
        "profile_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "profile_protocol_options": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssl_ssh_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "av_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "webfilter_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dnsfilter_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "emailfilter_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "dlp_profile": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "file_filter_profile": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "ips_sensor": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "application_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "voip_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ips_voip_filter": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "sctp_filter_profile": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "diameter_filter_profile": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "virtual_patch_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "icap_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "videofilter_profile": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "waf_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssh_filter_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "casb_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "telemetry_profile": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "logtraffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "utm"}, {"value": "disable"}],
        },
        "logtraffic_start": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_http_transaction": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "capture_packet": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "enable", "v_range": [["v6.0.0", ""]]},
                {"value": "disable", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "auto_asic_offload": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "np_acceleration": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wanopt": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "enable", "v_range": [["v6.0.0", ""]]},
                {"value": "disable", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "wanopt_detection": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "active", "v_range": [["v6.0.0", ""]]},
                {"value": "passive", "v_range": [["v6.0.0", ""]]},
                {"value": "off", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "wanopt_passive_opt": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "default", "v_range": [["v6.0.0", ""]]},
                {"value": "transparent", "v_range": [["v6.0.0", ""]]},
                {"value": "non-transparent", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "wanopt_profile": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
        },
        "wanopt_peer": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
        },
        "webcache": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "enable", "v_range": [["v6.0.0", ""]]},
                {"value": "disable", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "webcache_https": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "disable", "v_range": [["v6.0.0", ""]]},
                {"value": "enable", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "webproxy_forward_server": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "traffic_shaper": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "traffic_shaper_reverse": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "per_ip_shaper": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "nat": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pcp_outbound": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pcp_inbound": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pcp_poolname": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.0", ""]],
        },
        "permit_any_host": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "permit_stun_host": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fixedport": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "port_preserve": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "port_random": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ippool": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "poolname": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "poolname6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.4.0", ""]],
        },
        "session_ttl": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "vlan_cos_fwd": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "vlan_cos_rev": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "inbound": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "outbound": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "natinbound": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "natoutbound": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fec": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wccp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ntlm": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ntlm_guest": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ntlm_enabled_browsers": {
            "type": "list",
            "elements": "dict",
            "children": {
                "user_agent_string": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "fsso_agent_for_ntlm": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "groups": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "users": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "fsso_groups": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
        "scim": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "saml_server": {"v_range": [["v7.6.4", ""]], "type": "string"},
        "scim_users": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.4", ""]],
        },
        "scim_groups": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.4", ""]],
        },
        "auth_path": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "disclaimer": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "email_collect": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vpntunnel": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "natip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "match_vip": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "match_vip_only": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffserv_copy": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffserv_forward": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffserv_reverse": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffservcode_forward": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "diffservcode_rev": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tcp_mss_sender": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tcp_mss_receiver": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "gtp_profile": {
            "v_range": [["v6.0.0", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "pfcp_profile": {
            "v_range": [["v7.0.1", "v7.0.8"], ["v7.2.0", "v7.2.4"], ["v7.4.3", ""]],
            "type": "string",
        },
        "auth_cert": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_redirect_addr": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "redirect_url": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "identity_based_route": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "block_notification": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "custom_log_fields": {
            "type": "list",
            "elements": "dict",
            "children": {
                "field_id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "replacemsg_override_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "srcaddr_negate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "srcaddr6_negate": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dstaddr_negate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dstaddr6_negate": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ztna_ems_tag_negate": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "service_negate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service_negate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service_src_negate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service6_negate": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service6_src_negate": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "timeout_send_rst": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "captive_portal_exempt": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "decrypted_traffic_mirror": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "dsri": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "radius_mac_auth_bypass": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "radius_ip_auth_bypass": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "delay_tcp_npu_session": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vlan_filter": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sgt_check": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sgt": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v7.0.1", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v7.0.1", ""]],
        },
        "internet_service_fortiguard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.4", ""]],
        },
        "internet_service_src_fortiguard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.4", ""]],
        },
        "internet_service6_fortiguard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.4", ""]],
        },
        "internet_service6_src_fortiguard": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.4", ""]],
        },
        "cifs_profile": {"v_range": [["v6.2.0", "v7.6.0"]], "type": "string"},
        "dlp_sensor": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
        "internet_service_id": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "internet_service_src_id": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "mms_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "application": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "app_category": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "url_category": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "app_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "fsso": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wsso": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rsso": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_mirror": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_mirror_intf": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "devices": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
        },
        "label": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "global_label": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "learning_mode": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dscp_match": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dscp_negate": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dscp_value": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "spamfilter_profile": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "scan_botnet_connections": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "block"}, {"value": "monitor"}],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "policyid"
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
        "action": {"type": "str", "required": False, "choices": ["move"]},
        "self": {"type": "str", "required": False},
        "before": {"type": "str", "required": False},
        "after": {"type": "str", "required": False},
        "state": {"required": False, "type": "str", "choices": ["present", "absent"]},
        "firewall_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_policy"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_policy"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_policy"
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
