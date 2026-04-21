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
module: fortios_firewall_security_policy
short_description: Configure NGFW IPv4/IPv6 application policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and security_policy category.
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
    firewall_security_policy:
        description:
            - Configure NGFW IPv4/IPv6 application policies.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Policy action (accept/deny).
                type: str
                choices:
                    - 'accept'
                    - 'deny'
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
            av_profile:
                description:
                    - Name of an existing Antivirus profile. Source antivirus.profile.name.
                type: str
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
            diameter_filter_profile:
                description:
                    - Name of an existing Diameter filter profile. Source diameter-filter.profile.name.
                type: str
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
                    - Destination IPv4 address name and address group names.
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
            dstaddr4:
                description:
                    - Destination IPv4 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name.
                        required: true
                        type: str
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
            emailfilter_profile:
                description:
                    - Name of an existing email filter profile. Source emailfilter.profile.name.
                type: str
            enforce_default_app_port:
                description:
                    - Enable/disable default application port enforcement for allowed applications.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            file_filter_profile:
                description:
                    - Name of an existing file-filter profile. Source file-filter.profile.name.
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
                            - User group name. Source user.group.name.
                        required: true
                        type: str
            icap_profile:
                description:
                    - Name of an existing ICAP profile. Source icap.profile.name.
                type: str
            internet_service:
                description:
                    - Enable/disable use of Internet Services for this policy. If enabled, destination address, service and default application port
                       enforcement are not used.
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
                    - Enable/disable use of IPv6 Internet Services for this policy. If enabled, destination address, service and default application port
                       enforcement are not used.
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
                            - Custom IPv6 Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service6_custom_group:
                description:
                    - Custom IPv6 Internet Service group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom IPv6 Internet Service group name. Source firewall.internet-service-custom-group.name.
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
            ips_sensor:
                description:
                    - Name of an existing IPS sensor. Source ips.sensor.name.
                type: str
            ips_voip_filter:
                description:
                    - Name of an existing VoIP (ips) profile. Source voip.profile.name.
                type: str
            learning_mode:
                description:
                    - Enable to allow everything, but log all of the meaningful data for security information gathering. A learning report will be generated.
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
            mms_profile:
                description:
                    - Name of an existing MMS profile. Source firewall.mms-profile.name.
                type: str
            name:
                description:
                    - Policy name.
                type: str
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
            policyid:
                description:
                    - Policy ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
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
            schedule:
                description:
                    - Schedule name. Source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name.
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
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
                        type: str
            service_negate:
                description:
                    - When enabled service specifies what the service must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            srcaddr:
                description:
                    - Source IPv4 address name and address group names.
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
            srcaddr4:
                description:
                    - Source IPv4 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            srcaddr6:
                description:
                    - Source IPv6 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
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
            telemetry_profile:
                description:
                    - Name of an existing telemetry profile. Source telemetry-controller.profile.name.
                type: str
            url_category:
                description:
                    - URL categories or groups.
                type: list
                elements: str
            users:
                description:
                    - Names of individual users that can authenticate with this policy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User name. Source user.local.name.
                        required: true
                        type: str
            utm_status:
                description:
                    - Enable security profiles.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            uuid_idx:
                description:
                    - uuid-idx
                type: int
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
                    - Name of an existing VoIP (voipd) profile. Source voip.profile.name.
                type: str
            webfilter_profile:
                description:
                    - Name of an existing Web filter profile. Source webfilter.profile.name.
                type: str
"""

EXAMPLES = """
- name: Configure NGFW IPv4/IPv6 application policies.
  fortinet.fortios.fortios_firewall_security_policy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_security_policy:
          action: "accept"
          app_category:
              -
                  id: "5"
          app_group:
              -
                  name: "default_name_7 (source application.group.name)"
          application:
              -
                  id: "9"
          application_list: "<your_own_value> (source application.list.name)"
          av_profile: "<your_own_value> (source antivirus.profile.name)"
          casb_profile: "<your_own_value> (source casb.profile.name)"
          cifs_profile: "<your_own_value> (source cifs.profile.name)"
          comments: "<your_own_value>"
          diameter_filter_profile: "<your_own_value> (source diameter-filter.profile.name)"
          dlp_profile: "<your_own_value> (source dlp.profile.name)"
          dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
          dnsfilter_profile: "<your_own_value> (source dnsfilter.profile.name)"
          dstaddr:
              -
                  name: "default_name_20 (source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource
                    .name)"
          dstaddr_negate: "enable"
          dstaddr4:
              -
                  name: "default_name_23 (source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name)"
          dstaddr6:
              -
                  name: "default_name_25 (source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                    .external-resource.name)"
          dstaddr6_negate: "enable"
          dstintf:
              -
                  name: "default_name_28 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
          enforce_default_app_port: "enable"
          file_filter_profile: "<your_own_value> (source file-filter.profile.name)"
          fsso_groups:
              -
                  name: "default_name_33 (source user.adgrp.name)"
          global_label: "<your_own_value>"
          groups:
              -
                  name: "default_name_36 (source user.group.name)"
          icap_profile: "<your_own_value> (source icap.profile.name)"
          internet_service: "enable"
          internet_service_custom:
              -
                  name: "default_name_40 (source firewall.internet-service-custom.name)"
          internet_service_custom_group:
              -
                  name: "default_name_42 (source firewall.internet-service-custom-group.name)"
          internet_service_group:
              -
                  name: "default_name_44 (source firewall.internet-service-group.name)"
          internet_service_id:
              -
                  id: "46 (source firewall.internet-service.id)"
          internet_service_name:
              -
                  name: "default_name_48 (source firewall.internet-service-name.name)"
          internet_service_negate: "enable"
          internet_service_src: "enable"
          internet_service_src_custom:
              -
                  name: "default_name_52 (source firewall.internet-service-custom.name)"
          internet_service_src_custom_group:
              -
                  name: "default_name_54 (source firewall.internet-service-custom-group.name)"
          internet_service_src_group:
              -
                  name: "default_name_56 (source firewall.internet-service-group.name)"
          internet_service_src_id:
              -
                  id: "58 (source firewall.internet-service.id)"
          internet_service_src_name:
              -
                  name: "default_name_60 (source firewall.internet-service-name.name)"
          internet_service_src_negate: "enable"
          internet_service6: "enable"
          internet_service6_custom:
              -
                  name: "default_name_64 (source firewall.internet-service-custom.name)"
          internet_service6_custom_group:
              -
                  name: "default_name_66 (source firewall.internet-service-custom-group.name)"
          internet_service6_group:
              -
                  name: "default_name_68 (source firewall.internet-service-group.name)"
          internet_service6_name:
              -
                  name: "default_name_70 (source firewall.internet-service-name.name)"
          internet_service6_negate: "enable"
          internet_service6_src: "enable"
          internet_service6_src_custom:
              -
                  name: "default_name_74 (source firewall.internet-service-custom.name)"
          internet_service6_src_custom_group:
              -
                  name: "default_name_76 (source firewall.internet-service-custom-group.name)"
          internet_service6_src_group:
              -
                  name: "default_name_78 (source firewall.internet-service-group.name)"
          internet_service6_src_name:
              -
                  name: "default_name_80 (source firewall.internet-service-name.name)"
          internet_service6_src_negate: "enable"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          ips_voip_filter: "<your_own_value> (source voip.profile.name)"
          learning_mode: "enable"
          logtraffic: "all"
          logtraffic_start: "enable"
          mms_profile: "<your_own_value> (source firewall.mms-profile.name)"
          name: "default_name_88"
          nat46: "enable"
          nat64: "enable"
          policyid: "<you_own_value>"
          profile_group: "<your_own_value> (source firewall.profile-group.name)"
          profile_protocol_options: "<your_own_value> (source firewall.profile-protocol-options.name)"
          profile_type: "single"
          schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
          sctp_filter_profile: "<your_own_value> (source sctp-filter.profile.name)"
          send_deny_packet: "disable"
          service:
              -
                  name: "default_name_99 (source firewall.service.custom.name firewall.service.group.name)"
          service_negate: "enable"
          srcaddr:
              -
                  name: "default_name_102 (source firewall.address.name firewall.addrgrp.name system.external-resource.name)"
          srcaddr_negate: "enable"
          srcaddr4:
              -
                  name: "default_name_105 (source firewall.address.name firewall.addrgrp.name)"
          srcaddr6:
              -
                  name: "default_name_107 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
          srcaddr6_negate: "enable"
          srcintf:
              -
                  name: "default_name_110 (source system.interface.name system.zone.name system.sdwan.zone.name)"
          ssh_filter_profile: "<your_own_value> (source ssh-filter.profile.name)"
          ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
          status: "enable"
          telemetry_profile: "<your_own_value> (source telemetry-controller.profile.name)"
          url_category: "<your_own_value>"
          users:
              -
                  name: "default_name_117 (source user.local.name)"
          utm_status: "enable"
          uuid: "<your_own_value>"
          uuid_idx: "2147483647"
          videofilter_profile: "<your_own_value> (source videofilter.profile.name)"
          virtual_patch_profile: "<your_own_value> (source virtual-patch.profile.name)"
          voip_profile: "<your_own_value> (source voip.profile.name)"
          webfilter_profile: "<your_own_value> (source webfilter.profile.name)"
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


def filter_firewall_security_policy_data(json):
    option_list = [
        "action",
        "app_category",
        "app_group",
        "application",
        "application_list",
        "av_profile",
        "casb_profile",
        "cifs_profile",
        "comments",
        "diameter_filter_profile",
        "dlp_profile",
        "dlp_sensor",
        "dnsfilter_profile",
        "dstaddr",
        "dstaddr_negate",
        "dstaddr4",
        "dstaddr6",
        "dstaddr6_negate",
        "dstintf",
        "emailfilter_profile",
        "enforce_default_app_port",
        "file_filter_profile",
        "fsso_groups",
        "global_label",
        "groups",
        "icap_profile",
        "internet_service",
        "internet_service_custom",
        "internet_service_custom_group",
        "internet_service_group",
        "internet_service_id",
        "internet_service_name",
        "internet_service_negate",
        "internet_service_src",
        "internet_service_src_custom",
        "internet_service_src_custom_group",
        "internet_service_src_group",
        "internet_service_src_id",
        "internet_service_src_name",
        "internet_service_src_negate",
        "internet_service6",
        "internet_service6_custom",
        "internet_service6_custom_group",
        "internet_service6_group",
        "internet_service6_name",
        "internet_service6_negate",
        "internet_service6_src",
        "internet_service6_src_custom",
        "internet_service6_src_custom_group",
        "internet_service6_src_group",
        "internet_service6_src_name",
        "internet_service6_src_negate",
        "ips_sensor",
        "ips_voip_filter",
        "learning_mode",
        "logtraffic",
        "logtraffic_start",
        "mms_profile",
        "name",
        "nat46",
        "nat64",
        "policyid",
        "profile_group",
        "profile_protocol_options",
        "profile_type",
        "schedule",
        "sctp_filter_profile",
        "send_deny_packet",
        "service",
        "service_negate",
        "srcaddr",
        "srcaddr_negate",
        "srcaddr4",
        "srcaddr6",
        "srcaddr6_negate",
        "srcintf",
        "ssh_filter_profile",
        "ssl_ssh_profile",
        "status",
        "telemetry_profile",
        "url_category",
        "users",
        "utm_status",
        "uuid",
        "uuid_idx",
        "videofilter_profile",
        "virtual_patch_profile",
        "voip_profile",
        "webfilter_profile",
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
        ["url_category"],
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


def firewall_security_policy(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_security_policy_data = data["firewall_security_policy"]

    filtered_data = filter_firewall_security_policy_data(firewall_security_policy_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "security-policy", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "security-policy", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_security_policy"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "security-policy",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "security-policy", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "security-policy", mkey=converted_data["policyid"], vdom=vdom
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

    if data["firewall_security_policy"]:
        resp = firewall_security_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_security_policy")
        )
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
        "uuid": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "policyid": {"v_range": [["v6.2.0", ""]], "type": "integer", "required": True},
        "name": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "comments": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "srcintf": {
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
        "dstintf": {
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
        "srcaddr": {
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
        "srcaddr_negate": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dstaddr": {
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
        "dstaddr_negate": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "srcaddr6": {
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
        "srcaddr6_negate": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dstaddr6": {
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
        "dstaddr6_negate": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service": {
            "v_range": [["v6.2.0", ""]],
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
        "internet_service_negate": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
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
            "v_range": [["v6.2.0", ""]],
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
        "internet_service_src_negate": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
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
        "internet_service6_negate": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "internet_service6_src_negate": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "enforce_default_app_port": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "service": {
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
        "service_negate": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "action": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "accept"}, {"value": "deny"}],
        },
        "send_deny_packet": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "schedule": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "logtraffic": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "utm"}, {"value": "disable"}],
        },
        "learning_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nat46": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nat64": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "profile_type": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "single"}, {"value": "group"}],
        },
        "profile_group": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "profile_protocol_options": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "ssl_ssh_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "av_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "webfilter_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "dnsfilter_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "emailfilter_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "dlp_profile": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "file_filter_profile": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "ips_sensor": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "application_list": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "voip_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "ips_voip_filter": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "sctp_filter_profile": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "diameter_filter_profile": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "virtual_patch_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "icap_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "videofilter_profile": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "ssh_filter_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "casb_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "telemetry_profile": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "application": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.2.0", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v6.2.0", ""]],
        },
        "app_category": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v6.2.0", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v6.2.0", ""]],
        },
        "url_category": {
            "v_range": [["v6.2.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "app_group": {
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
        "groups": {
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
        "users": {
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
        "cifs_profile": {"v_range": [["v6.2.0", "v7.6.0"]], "type": "string"},
        "dlp_sensor": {"v_range": [["v6.2.0", "v7.0.12"]], "type": "string"},
        "srcaddr4": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", "v6.2.7"]],
        },
        "dstaddr4": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", "v6.2.7"]],
        },
        "internet_service_id": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", "v6.2.7"]],
        },
        "internet_service_src_id": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", "v6.2.7"]],
        },
        "logtraffic_start": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mms_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "uuid_idx": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "integer"},
        "global_label": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "utm_status": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
    },
    "v_range": [["v6.2.0", ""]],
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
        "firewall_security_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_security_policy"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_security_policy"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_security_policy"
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
