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
module: fortios_firewall_proxy_policy
short_description: Configure proxy policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and proxy_policy category.
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
    firewall_proxy_policy:
        description:
            - Configure proxy policies.
        default: null
        type: dict
        suboptions:
            access_proxy:
                description:
                    - IPv4 access proxy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Access Proxy name. Source firewall.access-proxy.name.
                        required: true
                        type: str
            access_proxy6:
                description:
                    - IPv6 access proxy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Access proxy name. Source firewall.access-proxy6.name.
                        required: true
                        type: str
            action:
                description:
                    - Accept or deny traffic matching the policy parameters.
                type: str
                choices:
                    - 'accept'
                    - 'deny'
                    - 'redirect'
                    - 'isolate'
            application_list:
                description:
                    - Name of an existing Application list. Source application.list.name.
                type: str
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
                    - Optional comments.
                type: str
            decrypted_traffic_mirror:
                description:
                    - Decrypted traffic mirror. Source firewall.decrypted-traffic-mirror.name.
                type: str
            detect_https_in_http_request:
                description:
                    - Enable/disable detection of HTTPS in HTTP request.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            device_ownership:
                description:
                    - When enabled, the ownership enforcement will be done at policy level.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            diameter_filter_profile:
                description:
                    - Name of an existing Diameter filter profile. Source diameter-filter.profile.name.
                type: str
            disclaimer:
                description:
                    - 'Web proxy disclaimer setting: by domain, policy, or user.'
                type: str
                choices:
                    - 'disable'
                    - 'domain'
                    - 'policy'
                    - 'user'
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
            dstaddr:
                description:
                    - Destination address objects.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name firewall.proxy-address.name firewall.proxy-addrgrp.name
                               firewall.vip.name firewall.vipgrp.name system.external-resource.name.
                        required: true
                        type: str
            dstaddr_negate:
                description:
                    - When enabled, destination addresses match against any address EXCEPT the specified destination addresses.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dstaddr6:
                description:
                    - IPv6 destination address objects.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                              .external-resource.name.
                        required: true
                        type: str
            dstintf:
                description:
                    - Destination interface names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                        required: true
                        type: str
            emailfilter_profile:
                description:
                    - Name of an existing email filter profile. Source emailfilter.profile.name.
                type: str
            file_filter_profile:
                description:
                    - Name of an existing file-filter profile. Source file-filter.profile.name.
                type: str
            global_label:
                description:
                    - Global web-based manager visible label.
                type: str
            groups:
                description:
                    - Names of group objects.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Group name. Source user.group.name.
                        required: true
                        type: str
            http_tunnel_auth:
                description:
                    - Enable/disable HTTP tunnel authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            https_sub_category:
                description:
                    - Enable/disable HTTPS sub-category policy matching.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            icap_profile:
                description:
                    - Name of an existing ICAP profile. Source icap.profile.name.
                type: str
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
                    - When enabled, Internet Services match against any internet service EXCEPT the selected Internet Service.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service6:
                description:
                    - Enable/disable use of Internet Services IPv6 for this policy. If enabled, destination IPv6 address and service are not used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service6_custom:
                description:
                    - Custom Internet Service IPv6 name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service IPv6 name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service6_custom_group:
                description:
                    - Custom Internet Service IPv6 group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service IPv6 group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service6_fortiguard:
                description:
                    - FortiGuard Internet Service IPv6 name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - FortiGuard Internet Service IPv6 name. Source firewall.internet-service-fortiguard.name.
                        required: true
                        type: str
            internet_service6_group:
                description:
                    - Internet Service IPv6 group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service IPv6 group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service6_name:
                description:
                    - Internet Service IPv6 name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service IPv6 name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            internet_service6_negate:
                description:
                    - When enabled, Internet Services match against any internet service IPv6 EXCEPT the selected Internet Service IPv6.
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
            isolator_server:
                description:
                    - Isolator server name. Source web-proxy.isolator-server.name.
                type: str
            label:
                description:
                    - VDOM-specific GUI visible label.
                type: str
            log_http_transaction:
                description:
                    - Enable/disable HTTP transaction log.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            logtraffic:
                description:
                    - Enable/disable logging traffic through the policy.
                type: str
                choices:
                    - 'all'
                    - 'utm'
                    - 'disable'
            logtraffic_start:
                description:
                    - Enable/disable policy log traffic start.
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
            policyid:
                description:
                    - Policy ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            poolname:
                description:
                    - Name of IP pool object.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IP pool name. Source firewall.ippool.name.
                        required: true
                        type: str
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
            proxy:
                description:
                    - Type of explicit proxy.
                type: str
                choices:
                    - 'explicit-web'
                    - 'transparent-web'
                    - 'ftp'
                    - 'ssh'
                    - 'ssh-tunnel'
                    - 'access-proxy'
                    - 'ztna-proxy'
                    - 'wanopt'
            redirect_url:
                description:
                    - Redirect URL for further explicit web proxy processing.
                type: str
            replacemsg_override_group:
                description:
                    - Authentication replacement message override group. Source system.replacemsg-group.name.
                type: str
            scan_botnet_connections:
                description:
                    - Enable/disable scanning of connections to Botnet servers.
                type: str
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                description:
                    - Name of schedule object. Source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name.
                type: str
            sctp_filter_profile:
                description:
                    - Name of an existing SCTP filter profile. Source sctp-filter.profile.name.
                type: str
            service:
                description:
                    - Name of service objects.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
                        type: str
            service_negate:
                description:
                    - When enabled, services match against any service EXCEPT the specified destination services.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            session_ttl:
                description:
                    - TTL in seconds for sessions accepted by this policy (0 means use the system ).
                type: int
            spamfilter_profile:
                description:
                    - Name of an existing Spam filter profile. Source spamfilter.profile.name.
                type: str
            srcaddr:
                description:
                    - Source address objects.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name firewall.proxy-address.name firewall.proxy-addrgrp.name system
                              .external-resource.name.
                        required: true
                        type: str
            srcaddr_negate:
                description:
                    - When enabled, source addresses match against any address EXCEPT the specified source addresses.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            srcaddr6:
                description:
                    - IPv6 source address objects.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
                        required: true
                        type: str
            srcintf:
                description:
                    - Source interface names.
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
            ssl_ssh_profile:
                description:
                    - Name of an existing SSL SSH profile. Source firewall.ssl-ssh-profile.name.
                type: str
            status:
                description:
                    - Enable/disable the active status of the policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            telemetry_profile:
                description:
                    - Name of an existing telemetry profile. Source telemetry-controller.profile.name.
                type: str
            transparent:
                description:
                    - Enable to use the IP address of the client to connect to the server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            url_risk:
                description:
                    - URL risk level name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Risk level name. Source webfilter.ftgd-risk-level.name.
                        required: true
                        type: str
            users:
                description:
                    - Names of user objects.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Group name. Source user.local.name user.certificate.name.
                        required: true
                        type: str
            utm_status:
                description:
                    - Enable the use of UTM profiles/sensors/lists.
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
            voip_profile:
                description:
                    - Name of an existing VoIP profile. Source voip.profile.name.
                type: str
            waf_profile:
                description:
                    - Name of an existing Web application firewall profile. Source waf.profile.name.
                type: str
            webcache:
                description:
                    - Enable/disable web caching.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            webcache_https:
                description:
                    - Enable/disable web caching for HTTPS (Requires deep-inspection enabled in ssl-ssh-profile).
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
                    - Web proxy forward server name. Source web-proxy.forward-server.name web-proxy.forward-server-group.name.
                type: str
            webproxy_profile:
                description:
                    - Name of web proxy profile. Source web-proxy.profile.name.
                type: str
            ztna_ems_tag:
                description:
                    - ZTNA EMS Tag names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - EMS Tag name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            ztna_ems_tag_negate:
                description:
                    - When enabled, ZTNA EMS tags match against any tag EXCEPT the specified ZTNA EMS tags.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ztna_proxy:
                description:
                    - ZTNA proxies.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - ZTNA proxy name. Source ztna.traffic-forward-proxy.name ztna.web-proxy.name ztna.web-portal.name.
                        required: true
                        type: str
            ztna_tags_match_logic:
                description:
                    - ZTNA tag matching logic.
                type: str
                choices:
                    - 'or'
                    - 'and'
"""

EXAMPLES = """
- name: Configure proxy policies.
  fortinet.fortios.fortios_firewall_proxy_policy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_proxy_policy:
          access_proxy:
              -
                  name: "default_name_4 (source firewall.access-proxy.name)"
          access_proxy6:
              -
                  name: "default_name_6 (source firewall.access-proxy6.name)"
          action: "accept"
          application_list: "<your_own_value> (source application.list.name)"
          av_profile: "<your_own_value> (source antivirus.profile.name)"
          block_notification: "enable"
          casb_profile: "<your_own_value> (source casb.profile.name)"
          cifs_profile: "<your_own_value> (source cifs.profile.name)"
          comments: "<your_own_value>"
          decrypted_traffic_mirror: "<your_own_value> (source firewall.decrypted-traffic-mirror.name)"
          detect_https_in_http_request: "enable"
          device_ownership: "enable"
          diameter_filter_profile: "<your_own_value> (source diameter-filter.profile.name)"
          disclaimer: "disable"
          dlp_profile: "<your_own_value> (source dlp.profile.name)"
          dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
          dnsfilter_profile: "<your_own_value> (source dnsfilter.profile.name)"
          dstaddr:
              -
                  name: "default_name_23 (source firewall.address.name firewall.addrgrp.name firewall.proxy-address.name firewall.proxy-addrgrp.name firewall
                    .vip.name firewall.vipgrp.name system.external-resource.name)"
          dstaddr_negate: "enable"
          dstaddr6:
              -
                  name: "default_name_26 (source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                    .external-resource.name)"
          dstintf:
              -
                  name: "default_name_28 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
          file_filter_profile: "<your_own_value> (source file-filter.profile.name)"
          global_label: "<your_own_value>"
          groups:
              -
                  name: "default_name_33 (source user.group.name)"
          http_tunnel_auth: "enable"
          https_sub_category: "enable"
          icap_profile: "<your_own_value> (source icap.profile.name)"
          internet_service: "enable"
          internet_service_custom:
              -
                  name: "default_name_39 (source firewall.internet-service-custom.name)"
          internet_service_custom_group:
              -
                  name: "default_name_41 (source firewall.internet-service-custom-group.name)"
          internet_service_fortiguard:
              -
                  name: "default_name_43 (source firewall.internet-service-fortiguard.name)"
          internet_service_group:
              -
                  name: "default_name_45 (source firewall.internet-service-group.name)"
          internet_service_id:
              -
                  id: "47 (source firewall.internet-service.id)"
          internet_service_name:
              -
                  name: "default_name_49 (source firewall.internet-service-name.name)"
          internet_service_negate: "enable"
          internet_service6: "enable"
          internet_service6_custom:
              -
                  name: "default_name_53 (source firewall.internet-service-custom.name)"
          internet_service6_custom_group:
              -
                  name: "default_name_55 (source firewall.internet-service-custom-group.name)"
          internet_service6_fortiguard:
              -
                  name: "default_name_57 (source firewall.internet-service-fortiguard.name)"
          internet_service6_group:
              -
                  name: "default_name_59 (source firewall.internet-service-group.name)"
          internet_service6_name:
              -
                  name: "default_name_61 (source firewall.internet-service-name.name)"
          internet_service6_negate: "enable"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          ips_voip_filter: "<your_own_value> (source voip.profile.name)"
          isolator_server: "<your_own_value> (source web-proxy.isolator-server.name)"
          label: "<your_own_value>"
          log_http_transaction: "enable"
          logtraffic: "all"
          logtraffic_start: "enable"
          mms_profile: "<your_own_value> (source firewall.mms-profile.name)"
          name: "default_name_71"
          policyid: "<you_own_value>"
          poolname:
              -
                  name: "default_name_74 (source firewall.ippool.name)"
          profile_group: "<your_own_value> (source firewall.profile-group.name)"
          profile_protocol_options: "<your_own_value> (source firewall.profile-protocol-options.name)"
          profile_type: "single"
          proxy: "explicit-web"
          redirect_url: "<your_own_value>"
          replacemsg_override_group: "<your_own_value> (source system.replacemsg-group.name)"
          scan_botnet_connections: "disable"
          schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
          sctp_filter_profile: "<your_own_value> (source sctp-filter.profile.name)"
          service:
              -
                  name: "default_name_85 (source firewall.service.custom.name firewall.service.group.name)"
          service_negate: "enable"
          session_ttl: "0"
          spamfilter_profile: "<your_own_value> (source spamfilter.profile.name)"
          srcaddr:
              -
                  name: "default_name_90 (source firewall.address.name firewall.addrgrp.name firewall.proxy-address.name firewall.proxy-addrgrp.name system
                    .external-resource.name)"
          srcaddr_negate: "enable"
          srcaddr6:
              -
                  name: "default_name_93 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
          srcintf:
              -
                  name: "default_name_95 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          ssh_filter_profile: "<your_own_value> (source ssh-filter.profile.name)"
          ssh_policy_redirect: "enable"
          ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
          status: "enable"
          telemetry_profile: "<your_own_value> (source telemetry-controller.profile.name)"
          transparent: "enable"
          url_risk:
              -
                  name: "default_name_103 (source webfilter.ftgd-risk-level.name)"
          users:
              -
                  name: "default_name_105 (source user.local.name user.certificate.name)"
          utm_status: "enable"
          uuid: "<your_own_value>"
          videofilter_profile: "<your_own_value> (source videofilter.profile.name)"
          virtual_patch_profile: "<your_own_value> (source virtual-patch.profile.name)"
          voip_profile: "<your_own_value> (source voip.profile.name)"
          waf_profile: "<your_own_value> (source waf.profile.name)"
          webcache: "enable"
          webcache_https: "disable"
          webfilter_profile: "<your_own_value> (source webfilter.profile.name)"
          webproxy_forward_server: "<your_own_value> (source web-proxy.forward-server.name web-proxy.forward-server-group.name)"
          webproxy_profile: "<your_own_value> (source web-proxy.profile.name)"
          ztna_ems_tag:
              -
                  name: "default_name_118 (source firewall.address.name firewall.addrgrp.name)"
          ztna_ems_tag_negate: "enable"
          ztna_proxy:
              -
                  name: "default_name_121 (source ztna.traffic-forward-proxy.name ztna.web-proxy.name ztna.web-portal.name)"
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


def filter_firewall_proxy_policy_data(json):
    option_list = [
        "access_proxy",
        "access_proxy6",
        "action",
        "application_list",
        "av_profile",
        "block_notification",
        "casb_profile",
        "cifs_profile",
        "comments",
        "decrypted_traffic_mirror",
        "detect_https_in_http_request",
        "device_ownership",
        "diameter_filter_profile",
        "disclaimer",
        "dlp_profile",
        "dlp_sensor",
        "dnsfilter_profile",
        "dstaddr",
        "dstaddr_negate",
        "dstaddr6",
        "dstintf",
        "emailfilter_profile",
        "file_filter_profile",
        "global_label",
        "groups",
        "http_tunnel_auth",
        "https_sub_category",
        "icap_profile",
        "internet_service",
        "internet_service_custom",
        "internet_service_custom_group",
        "internet_service_fortiguard",
        "internet_service_group",
        "internet_service_id",
        "internet_service_name",
        "internet_service_negate",
        "internet_service6",
        "internet_service6_custom",
        "internet_service6_custom_group",
        "internet_service6_fortiguard",
        "internet_service6_group",
        "internet_service6_name",
        "internet_service6_negate",
        "ips_sensor",
        "ips_voip_filter",
        "isolator_server",
        "label",
        "log_http_transaction",
        "logtraffic",
        "logtraffic_start",
        "mms_profile",
        "name",
        "policyid",
        "poolname",
        "profile_group",
        "profile_protocol_options",
        "profile_type",
        "proxy",
        "redirect_url",
        "replacemsg_override_group",
        "scan_botnet_connections",
        "schedule",
        "sctp_filter_profile",
        "service",
        "service_negate",
        "session_ttl",
        "spamfilter_profile",
        "srcaddr",
        "srcaddr_negate",
        "srcaddr6",
        "srcintf",
        "ssh_filter_profile",
        "ssh_policy_redirect",
        "ssl_ssh_profile",
        "status",
        "telemetry_profile",
        "transparent",
        "url_risk",
        "users",
        "utm_status",
        "uuid",
        "videofilter_profile",
        "virtual_patch_profile",
        "voip_profile",
        "waf_profile",
        "webcache",
        "webcache_https",
        "webfilter_profile",
        "webproxy_forward_server",
        "webproxy_profile",
        "ztna_ems_tag",
        "ztna_ems_tag_negate",
        "ztna_proxy",
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


def firewall_proxy_policy(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_proxy_policy_data = data["firewall_proxy_policy"]

    filtered_data = filter_firewall_proxy_policy_data(firewall_proxy_policy_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "proxy-policy", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "proxy-policy", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_proxy_policy"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "proxy-policy",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "proxy-policy", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "proxy-policy", mkey=converted_data["policyid"], vdom=vdom
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


def fortios_firewall(data, fos, check_mode):

    if data["firewall_proxy_policy"]:
        resp = firewall_proxy_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_proxy_policy"))
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
        "uuid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "policyid": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "name": {"v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]], "type": "string"},
        "proxy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "explicit-web"},
                {"value": "transparent-web"},
                {"value": "ftp"},
                {"value": "ssh"},
                {"value": "ssh-tunnel"},
                {"value": "access-proxy", "v_range": [["v7.0.0", ""]]},
                {"value": "ztna-proxy", "v_range": [["v7.6.0", ""]]},
                {"value": "wanopt", "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]]},
            ],
        },
        "access_proxy": {
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
        "access_proxy6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.1", ""]],
        },
        "ztna_proxy": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.0", ""]],
        },
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
        "ztna_tags_match_logic": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "or"}, {"value": "and"}],
        },
        "device_ownership": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "url_risk": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.6.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.6.1", ""]],
        },
        "internet_service": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service_negate": {
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
        "internet_service6": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service6_negate": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service6_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.4", ""]],
        },
        "internet_service6_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.4", ""]],
        },
        "internet_service6_custom": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.4", ""]],
        },
        "internet_service6_custom_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.4", ""]],
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
        "srcaddr_negate": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dstaddr_negate": {
            "v_range": [["v6.0.0", ""]],
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
        "action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "accept"},
                {"value": "deny"},
                {"value": "redirect"},
                {"value": "isolate", "v_range": [["v7.6.1", ""]]},
            ],
        },
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "schedule": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "logtraffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "utm"}, {"value": "disable"}],
        },
        "session_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "srcaddr6": {
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
        "dstaddr6": {
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
        "http_tunnel_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssh_policy_redirect": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webproxy_forward_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "isolator_server": {"v_range": [["v7.6.1", ""]], "type": "string"},
        "webproxy_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "transparent": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "disclaimer": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "domain"},
                {"value": "policy"},
                {"value": "user"},
            ],
        },
        "utm_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
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
        "dnsfilter_profile": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "emailfilter_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "dlp_profile": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "file_filter_profile": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "ips_sensor": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "application_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ips_voip_filter": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "sctp_filter_profile": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "icap_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "videofilter_profile": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "waf_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssh_filter_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "casb_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "telemetry_profile": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "replacemsg_override_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
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
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "block_notification": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "redirect_url": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "https_sub_category": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "decrypted_traffic_mirror": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "detect_https_in_http_request": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cifs_profile": {"v_range": [["v6.2.0", "v7.6.0"]], "type": "string"},
        "diameter_filter_profile": {
            "v_range": [["v7.4.2", "v7.4.3"]],
            "type": "string",
        },
        "virtual_patch_profile": {"v_range": [["v7.4.1", "v7.4.1"]], "type": "string"},
        "voip_profile": {"v_range": [["v7.0.0", "v7.2.4"]], "type": "string"},
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
        "mms_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "label": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "global_label": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
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
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "firewall_proxy_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_proxy_policy"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_proxy_policy"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "firewall_proxy_policy"
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
