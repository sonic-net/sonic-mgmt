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
module: fortios_firewall_consolidated_policy
short_description: Configure consolidated IPv4/IPv6 policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall_consolidated feature and policy category.
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
    firewall_consolidated_policy:
        description:
            - Configure consolidated IPv4/IPv6 policies.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Policy action (allow/deny/ipsec).
                type: str
                choices:
                    - 'accept'
                    - 'deny'
                    - 'ipsec'
            application_list:
                description:
                    - Name of an existing Application list. Source application.list.name.
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
            captive_portal_exempt:
                description:
                    - Enable exemption of some users from the captive portal.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cifs_profile:
                description:
                    - Name of an existing CIFS profile. Source cifs.profile.name.
                type: str
            comments:
                description:
                    - Comment.
                type: str
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
            dlp_sensor:
                description:
                    - Name of an existing DLP sensor. Source dlp.sensor.name.
                type: str
            dnsfilter_profile:
                description:
                    - Name of an existing DNS filter profile. Source dnsfilter.profile.name.
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
                            - Address name. Source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource
                              .name.
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
            dstintf:
                description:
                    - Outgoing (egress) interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name.
                        required: true
                        type: str
            emailfilter_profile:
                description:
                    - Name of an existing email filter profile. Source emailfilter.profile.name.
                type: str
            fixedport:
                description:
                    - Enable to prevent source NAT from changing a session"s source port.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
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
                            - Group name. Source user.group.name.
                        required: true
                        type: str
            http_policy_redirect:
                description:
                    - Redirect HTTP(S) traffic to matching transparent web proxy policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            icap_profile:
                description:
                    - Name of an existing ICAP profile. Source icap.profile.name.
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
            internet_service_src_negate:
                description:
                    - When enabled internet-service-src specifies what the service must NOT be.
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
            nat:
                description:
                    - Enable/disable source NAT.
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
            per_ip_shaper:
                description:
                    - Per-IP traffic shaper. Source firewall.shaper.per-ip-shaper.name.
                type: str
            policyid:
                description:
                    - Policy ID (0 - 4294967294). see <a href='#notes'>Notes</a>.
                required: true
                type: int
            poolname4:
                description:
                    - IPv4 pool names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IPv4 pool name. Source firewall.ippool.name.
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
            session_ttl:
                description:
                    - TTL in seconds for sessions accepted by this policy (0 means use the system ).
                type: int
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
                            - Address name. Source firewall.address.name firewall.addrgrp.name system.external-resource.name.
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
            srcintf:
                description:
                    - Incoming (ingress) interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name.
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
            traffic_shaper:
                description:
                    - Traffic shaper. Source firewall.shaper.traffic-shaper.name.
                type: str
            traffic_shaper_reverse:
                description:
                    - Reverse traffic shaper. Source firewall.shaper.traffic-shaper.name.
                type: str
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
                    - Enable to add one or more security profiles (AV, IPS, etc.) to the firewall policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            voip_profile:
                description:
                    - Name of an existing VoIP profile. Source voip.profile.name.
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
                    - WAN optimization passive mode options. This option decides what IP address will be used to connect to server.
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
"""

EXAMPLES = """
- name: Configure consolidated IPv4/IPv6 policies.
  fortinet.fortios.fortios_firewall_consolidated_policy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_consolidated_policy:
          action: "accept"
          application_list: "<your_own_value> (source application.list.name)"
          auto_asic_offload: "enable"
          av_profile: "<your_own_value> (source antivirus.profile.name)"
          captive_portal_exempt: "enable"
          cifs_profile: "<your_own_value> (source cifs.profile.name)"
          comments: "<your_own_value>"
          diffserv_forward: "enable"
          diffserv_reverse: "enable"
          diffservcode_forward: "<your_own_value>"
          diffservcode_rev: "<your_own_value>"
          dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
          dnsfilter_profile: "<your_own_value> (source dnsfilter.profile.name)"
          dstaddr_negate: "enable"
          dstaddr4:
              -
                  name: "default_name_18 (source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource
                    .name)"
          dstaddr6:
              -
                  name: "default_name_20 (source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                    .external-resource.name)"
          dstintf:
              -
                  name: "default_name_22 (source system.interface.name system.zone.name)"
          emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
          fixedport: "enable"
          fsso_groups:
              -
                  name: "default_name_26 (source user.adgrp.name)"
          global_label: "<your_own_value>"
          groups:
              -
                  name: "default_name_29 (source user.group.name)"
          http_policy_redirect: "enable"
          icap_profile: "<your_own_value> (source icap.profile.name)"
          inbound: "enable"
          inspection_mode: "proxy"
          internet_service: "enable"
          internet_service_custom:
              -
                  name: "default_name_36 (source firewall.internet-service-custom.name)"
          internet_service_custom_group:
              -
                  name: "default_name_38 (source firewall.internet-service-custom-group.name)"
          internet_service_group:
              -
                  name: "default_name_40 (source firewall.internet-service-group.name)"
          internet_service_id:
              -
                  id: "42 (source firewall.internet-service.id)"
          internet_service_negate: "enable"
          internet_service_src: "enable"
          internet_service_src_custom:
              -
                  name: "default_name_46 (source firewall.internet-service-custom.name)"
          internet_service_src_custom_group:
              -
                  name: "default_name_48 (source firewall.internet-service-custom-group.name)"
          internet_service_src_group:
              -
                  name: "default_name_50 (source firewall.internet-service-group.name)"
          internet_service_src_id:
              -
                  id: "52 (source firewall.internet-service.id)"
          internet_service_src_negate: "enable"
          ippool: "enable"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          logtraffic: "all"
          logtraffic_start: "enable"
          mms_profile: "<your_own_value> (source firewall.mms-profile.name)"
          name: "default_name_59"
          nat: "enable"
          outbound: "enable"
          per_ip_shaper: "<your_own_value> (source firewall.shaper.per-ip-shaper.name)"
          policyid: "<you_own_value>"
          poolname4:
              -
                  name: "default_name_65 (source firewall.ippool.name)"
          poolname6:
              -
                  name: "default_name_67 (source firewall.ippool6.name)"
          profile_group: "<your_own_value> (source firewall.profile-group.name)"
          profile_protocol_options: "<your_own_value> (source firewall.profile-protocol-options.name)"
          profile_type: "single"
          schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
          service:
              -
                  name: "default_name_73 (source firewall.service.custom.name firewall.service.group.name)"
          service_negate: "enable"
          session_ttl: "1382400"
          srcaddr_negate: "enable"
          srcaddr4:
              -
                  name: "default_name_78 (source firewall.address.name firewall.addrgrp.name system.external-resource.name)"
          srcaddr6:
              -
                  name: "default_name_80 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
          srcintf:
              -
                  name: "default_name_82 (source system.interface.name system.zone.name)"
          ssh_filter_profile: "<your_own_value> (source ssh-filter.profile.name)"
          ssh_policy_redirect: "enable"
          ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
          status: "enable"
          tcp_mss_receiver: "32767"
          tcp_mss_sender: "32767"
          traffic_shaper: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
          traffic_shaper_reverse: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
          users:
              -
                  name: "default_name_92 (source user.local.name)"
          utm_status: "enable"
          uuid: "<your_own_value>"
          voip_profile: "<your_own_value> (source voip.profile.name)"
          vpntunnel: "<your_own_value> (source vpn.ipsec.phase1.name vpn.ipsec.manualkey.name)"
          waf_profile: "<your_own_value> (source waf.profile.name)"
          wanopt: "enable"
          wanopt_detection: "active"
          wanopt_passive_opt: "default"
          wanopt_peer: "<your_own_value> (source wanopt.peer.peer-host-id)"
          wanopt_profile: "<your_own_value> (source wanopt.profile.name)"
          webcache: "enable"
          webcache_https: "disable"
          webfilter_profile: "<your_own_value> (source webfilter.profile.name)"
          webproxy_forward_server: "<your_own_value> (source web-proxy.forward-server.name web-proxy.forward-server-group.name)"
          webproxy_profile: "<your_own_value> (source web-proxy.profile.name)"
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


def filter_firewall_consolidated_policy_data(json):
    option_list = [
        "action",
        "application_list",
        "auto_asic_offload",
        "av_profile",
        "captive_portal_exempt",
        "cifs_profile",
        "comments",
        "diffserv_forward",
        "diffserv_reverse",
        "diffservcode_forward",
        "diffservcode_rev",
        "dlp_sensor",
        "dnsfilter_profile",
        "dstaddr_negate",
        "dstaddr4",
        "dstaddr6",
        "dstintf",
        "emailfilter_profile",
        "fixedport",
        "fsso_groups",
        "global_label",
        "groups",
        "http_policy_redirect",
        "icap_profile",
        "inbound",
        "inspection_mode",
        "internet_service",
        "internet_service_custom",
        "internet_service_custom_group",
        "internet_service_group",
        "internet_service_id",
        "internet_service_negate",
        "internet_service_src",
        "internet_service_src_custom",
        "internet_service_src_custom_group",
        "internet_service_src_group",
        "internet_service_src_id",
        "internet_service_src_negate",
        "ippool",
        "ips_sensor",
        "logtraffic",
        "logtraffic_start",
        "mms_profile",
        "name",
        "nat",
        "outbound",
        "per_ip_shaper",
        "policyid",
        "poolname4",
        "poolname6",
        "profile_group",
        "profile_protocol_options",
        "profile_type",
        "schedule",
        "service",
        "service_negate",
        "session_ttl",
        "srcaddr_negate",
        "srcaddr4",
        "srcaddr6",
        "srcintf",
        "ssh_filter_profile",
        "ssh_policy_redirect",
        "ssl_ssh_profile",
        "status",
        "tcp_mss_receiver",
        "tcp_mss_sender",
        "traffic_shaper",
        "traffic_shaper_reverse",
        "users",
        "utm_status",
        "uuid",
        "voip_profile",
        "vpntunnel",
        "waf_profile",
        "wanopt",
        "wanopt_detection",
        "wanopt_passive_opt",
        "wanopt_peer",
        "wanopt_profile",
        "webcache",
        "webcache_https",
        "webfilter_profile",
        "webproxy_forward_server",
        "webproxy_profile",
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


def firewall_consolidated_policy(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_consolidated_policy_data = data["firewall_consolidated_policy"]

    filtered_data = filter_firewall_consolidated_policy_data(
        firewall_consolidated_policy_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall.consolidated", "policy", filtered_data, vdom=vdom)
        current_data = fos.get("firewall.consolidated", "policy", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_consolidated_policy"] = filtered_data
    fos.do_member_operation(
        "firewall.consolidated",
        "policy",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "firewall.consolidated", "policy", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "firewall.consolidated",
            "policy",
            mkey=converted_data["policyid"],
            vdom=vdom,
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


def fortios_firewall_consolidated(data, fos, check_mode):

    if data["firewall_consolidated_policy"]:
        resp = firewall_consolidated_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_consolidated_policy")
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
        "policyid": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "integer",
            "required": True,
        },
        "status": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "name": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "uuid": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "srcintf": {
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
        "dstintf": {
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
        "srcaddr6": {
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
        "dstaddr6": {
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
        "srcaddr_negate": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dstaddr_negate": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "service_negate": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "internet_service_group": {
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
        "internet_service_custom": {
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
        "internet_service_custom_group": {
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
        "internet_service_src": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "internet_service_src_group": {
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
        "internet_service_src_custom": {
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
        "internet_service_src_custom_group": {
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
        "internet_service_negate": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service_src_negate": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "action": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "accept"}, {"value": "deny"}, {"value": "ipsec"}],
        },
        "schedule": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "service": {
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
        "utm_status": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "inspection_mode": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "proxy"}, {"value": "flow"}],
        },
        "http_policy_redirect": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssh_policy_redirect": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webproxy_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "profile_type": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "single"}, {"value": "group"}],
        },
        "profile_group": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "profile_protocol_options": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
        },
        "ssl_ssh_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "av_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "webfilter_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "dnsfilter_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "emailfilter_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "dlp_sensor": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "ips_sensor": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "application_list": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "voip_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "mms_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "icap_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "cifs_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "waf_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "ssh_filter_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "logtraffic": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "utm"}, {"value": "disable"}],
        },
        "logtraffic_start": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auto_asic_offload": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "groups": {
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
        "users": {
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
        "diffserv_forward": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffserv_reverse": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffservcode_forward": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "diffservcode_rev": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "tcp_mss_sender": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "integer"},
        "tcp_mss_receiver": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "integer"},
        "webproxy_forward_server": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
        },
        "wanopt": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wanopt_detection": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "active"}, {"value": "passive"}, {"value": "off"}],
        },
        "wanopt_passive_opt": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "transparent"},
                {"value": "non-transparent"},
            ],
        },
        "wanopt_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "wanopt_peer": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "webcache": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webcache_https": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "traffic_shaper": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "traffic_shaper_reverse": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "per_ip_shaper": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "nat": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fixedport": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ippool": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "poolname4": {
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
        "poolname6": {
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
        "session_ttl": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "integer"},
        "comments": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "vpntunnel": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "inbound": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "outbound": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "captive_portal_exempt": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fsso_groups": {
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
        "global_label": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
    },
    "v_range": [["v6.2.0", "v6.2.7"]],
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
        "firewall_consolidated_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_consolidated_policy"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_consolidated_policy"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_consolidated_policy"
        )

        is_error, has_changed, result, diff = fortios_firewall_consolidated(
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
