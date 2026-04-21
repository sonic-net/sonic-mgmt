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
module: fortios_firewall_policy6
short_description: Configure IPv6 policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and policy6 category.
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
    firewall_policy6:
        description:
            - Configure IPv6 policies.
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
                    - Log field index numbers to append custom log fields to log messages for this policy.
                type: list
                elements: dict
                suboptions:
                    field_id:
                        description:
                            - Custom log field. Source log.custom-field.id.
                        required: true
                        type: str
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
                    - Destination address and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                              .external-resource.name.
                        required: true
                        type: str
            dstaddr_negate:
                description:
                    - When enabled dstaddr specifies what the destination address must NOT be.
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
                            - Interface name. Source system.interface.name system.zone.name.
                        required: true
                        type: str
            emailfilter_profile:
                description:
                    - Name of an existing email filter profile. Source emailfilter.profile.name.
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
            label:
                description:
                    - Label for the policy that appears when the GUI is in Section View mode.
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
            natinbound:
                description:
                    - 'Policy-based IPsec VPN: apply destination NAT to inbound traffic.'
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            natoutbound:
                description:
                    - 'Policy-based IPsec VPN: apply source NAT to outbound traffic.'
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            np_acceleration:
                description:
                    - Enable/disable UTM Network Processor acceleration.
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
            poolname:
                description:
                    - IP Pool names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - IP pool name. Source firewall.ippool6.name.
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
            replacemsg_override_group:
                description:
                    - Override the default replacement message group for this policy. Source system.replacemsg-group.name.
                type: str
            rsso:
                description:
                    - Enable/disable RADIUS single sign-on (RSSO).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            schedule:
                description:
                    - Schedule name. Source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name.
                type: str
            send_deny_packet:
                description:
                    - Enable/disable return of deny-packet.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            service:
                description:
                    - Service and service group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.service.custom.name firewall.service.group.name.
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
                    - Session TTL in seconds for sessions accepted by this policy. 0 means use the system default session TTL.
                type: str
            spamfilter_profile:
                description:
                    - Name of an existing Spam filter profile. Source spamfilter.profile.name.
                type: str
            srcaddr:
                description:
                    - Source address and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
                        required: true
                        type: str
            srcaddr_negate:
                description:
                    - When enabled srcaddr specifies what the source address must NOT be.
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
                            - Interface name. Source system.zone.name system.interface.name.
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
                            - Interface name. Source system.zone.name system.interface.name.
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
                    - Reverse traffic shaper. Source firewall.shaper.traffic-shaper.name.
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
                            - Names of individual users that can authenticate with this policy. Source user.local.name.
                        required: true
                        type: str
            utm_status:
                description:
                    - Enable AV/web/ips protection profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            vlan_cos_fwd:
                description:
                    - 'VLAN forward direction user priority: 255 passthrough, 0 lowest, 7 highest'
                type: int
            vlan_cos_rev:
                description:
                    - 'VLAN reverse direction user priority: 255 passthrough, 0 lowest, 7 highest'
                type: int
            vlan_filter:
                description:
                    - Set VLAN filters.
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
                    - Web proxy forward server name. Source web-proxy.forward-server.name web-proxy.forward-server-group.name.
                type: str
            webproxy_profile:
                description:
                    - Webproxy profile name. Source web-proxy.profile.name.
                type: str
"""

EXAMPLES = """
- name: Configure IPv6 policies.
  fortinet.fortios.fortios_firewall_policy6:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_policy6:
          action: "accept"
          anti_replay: "enable"
          app_category:
              -
                  id: "6"
          app_group:
              -
                  name: "default_name_8 (source application.group.name)"
          application:
              -
                  id: "10"
          application_list: "<your_own_value> (source application.list.name)"
          auto_asic_offload: "enable"
          av_profile: "<your_own_value> (source antivirus.profile.name)"
          cifs_profile: "<your_own_value> (source cifs.profile.name)"
          comments: "<your_own_value>"
          custom_log_fields:
              -
                  field_id: "<your_own_value> (source log.custom-field.id)"
          devices:
              -
                  name: "default_name_19 (source user.device.alias user.device-group.name user.device-category.name)"
          diffserv_forward: "enable"
          diffserv_reverse: "enable"
          diffservcode_forward: "<your_own_value>"
          diffservcode_rev: "<your_own_value>"
          dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
          dnsfilter_profile: "<your_own_value> (source dnsfilter.profile.name)"
          dscp_match: "enable"
          dscp_negate: "enable"
          dscp_value: "<your_own_value>"
          dsri: "enable"
          dstaddr:
              -
                  name: "default_name_31 (source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                    .external-resource.name)"
          dstaddr_negate: "enable"
          dstintf:
              -
                  name: "default_name_34 (source system.interface.name system.zone.name)"
          emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
          firewall_session_dirty: "check-all"
          fixedport: "enable"
          fsso_groups:
              -
                  name: "default_name_39 (source user.adgrp.name)"
          global_label: "<your_own_value>"
          groups:
              -
                  name: "default_name_42 (source user.group.name)"
          http_policy_redirect: "enable"
          icap_profile: "<your_own_value> (source icap.profile.name)"
          inbound: "enable"
          inspection_mode: "proxy"
          ippool: "enable"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          label: "<your_own_value>"
          logtraffic: "all"
          logtraffic_start: "enable"
          mms_profile: "<your_own_value> (source firewall.mms-profile.name)"
          name: "default_name_53"
          nat: "enable"
          natinbound: "enable"
          natoutbound: "enable"
          np_acceleration: "enable"
          outbound: "enable"
          per_ip_shaper: "<your_own_value> (source firewall.shaper.per-ip-shaper.name)"
          policyid: "<you_own_value>"
          poolname:
              -
                  name: "default_name_62 (source firewall.ippool6.name)"
          profile_group: "<your_own_value> (source firewall.profile-group.name)"
          profile_protocol_options: "<your_own_value> (source firewall.profile-protocol-options.name)"
          profile_type: "single"
          replacemsg_override_group: "<your_own_value> (source system.replacemsg-group.name)"
          rsso: "enable"
          schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
          send_deny_packet: "enable"
          service:
              -
                  name: "default_name_71 (source firewall.service.custom.name firewall.service.group.name)"
          service_negate: "enable"
          session_ttl: "<your_own_value>"
          spamfilter_profile: "<your_own_value> (source spamfilter.profile.name)"
          srcaddr:
              -
                  name: "default_name_76 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
          srcaddr_negate: "enable"
          srcintf:
              -
                  name: "default_name_79 (source system.zone.name system.interface.name)"
          ssh_filter_profile: "<your_own_value> (source ssh-filter.profile.name)"
          ssh_policy_redirect: "enable"
          ssl_mirror: "enable"
          ssl_mirror_intf:
              -
                  name: "default_name_84 (source system.zone.name system.interface.name)"
          ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
          status: "enable"
          tcp_mss_receiver: "32767"
          tcp_mss_sender: "32767"
          tcp_session_without_syn: "all"
          timeout_send_rst: "enable"
          tos: "<your_own_value>"
          tos_mask: "<your_own_value>"
          tos_negate: "enable"
          traffic_shaper: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
          traffic_shaper_reverse: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
          url_category:
              -
                  id: "97"
          users:
              -
                  name: "default_name_99 (source user.local.name)"
          utm_status: "enable"
          uuid: "<your_own_value>"
          vlan_cos_fwd: "3"
          vlan_cos_rev: "3"
          vlan_filter: "<your_own_value>"
          voip_profile: "<your_own_value> (source voip.profile.name)"
          vpntunnel: "<your_own_value> (source vpn.ipsec.phase1.name vpn.ipsec.manualkey.name)"
          waf_profile: "<your_own_value> (source waf.profile.name)"
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


def filter_firewall_policy6_data(json):
    option_list = [
        "action",
        "anti_replay",
        "app_category",
        "app_group",
        "application",
        "application_list",
        "auto_asic_offload",
        "av_profile",
        "cifs_profile",
        "comments",
        "custom_log_fields",
        "devices",
        "diffserv_forward",
        "diffserv_reverse",
        "diffservcode_forward",
        "diffservcode_rev",
        "dlp_sensor",
        "dnsfilter_profile",
        "dscp_match",
        "dscp_negate",
        "dscp_value",
        "dsri",
        "dstaddr",
        "dstaddr_negate",
        "dstintf",
        "emailfilter_profile",
        "firewall_session_dirty",
        "fixedport",
        "fsso_groups",
        "global_label",
        "groups",
        "http_policy_redirect",
        "icap_profile",
        "inbound",
        "inspection_mode",
        "ippool",
        "ips_sensor",
        "label",
        "logtraffic",
        "logtraffic_start",
        "mms_profile",
        "name",
        "nat",
        "natinbound",
        "natoutbound",
        "np_acceleration",
        "outbound",
        "per_ip_shaper",
        "policyid",
        "poolname",
        "profile_group",
        "profile_protocol_options",
        "profile_type",
        "replacemsg_override_group",
        "rsso",
        "schedule",
        "send_deny_packet",
        "service",
        "service_negate",
        "session_ttl",
        "spamfilter_profile",
        "srcaddr",
        "srcaddr_negate",
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
        "vlan_cos_fwd",
        "vlan_cos_rev",
        "vlan_filter",
        "voip_profile",
        "vpntunnel",
        "waf_profile",
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


def firewall_policy6(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_policy6_data = data["firewall_policy6"]

    filtered_data = filter_firewall_policy6_data(firewall_policy6_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "policy6", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "policy6", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_policy6"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "policy6",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "policy6", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "policy6", mkey=converted_data["policyid"], vdom=vdom
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

    if data["firewall_policy6"]:
        resp = firewall_policy6(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_policy6"))
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
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "integer",
            "required": True,
        },
        "name": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "uuid": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "srcintf": {
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
        "dstintf": {
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
        "srcaddr": {
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
        "dstaddr": {
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
        "action": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "accept"}, {"value": "deny"}, {"value": "ipsec"}],
        },
        "firewall_session_dirty": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "check-all"}, {"value": "check-new"}],
        },
        "status": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vlan_cos_fwd": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "vlan_cos_rev": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "schedule": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "service": {
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
        "tos": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "tos_mask": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "tos_negate": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tcp_session_without_syn": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "data-only"}, {"value": "disable"}],
        },
        "anti_replay": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "utm_status": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "inspection_mode": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "proxy"}, {"value": "flow"}],
        },
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
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "single"}, {"value": "group"}],
        },
        "profile_group": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "profile_protocol_options": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
        },
        "ssl_ssh_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "av_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "webfilter_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "dnsfilter_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "emailfilter_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "dlp_sensor": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "ips_sensor": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "application_list": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "voip_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "mms_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "icap_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "cifs_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "waf_profile": {"v_range": [["v6.2.0", "v6.2.7"]], "type": "string"},
        "ssh_filter_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "logtraffic": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "utm"}, {"value": "disable"}],
        },
        "logtraffic_start": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auto_asic_offload": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "np_acceleration": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webproxy_forward_server": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "string",
        },
        "traffic_shaper": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "traffic_shaper_reverse": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "per_ip_shaper": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
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
        "nat": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fixedport": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ippool": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "poolname": {
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
        "session_ttl": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "inbound": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "outbound": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "natinbound": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "natoutbound": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "send_deny_packet": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vpntunnel": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "diffserv_forward": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffserv_reverse": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "diffservcode_forward": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "diffservcode_rev": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "tcp_mss_sender": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "tcp_mss_receiver": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "comments": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "rsso": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "custom_log_fields": {
            "type": "list",
            "elements": "dict",
            "children": {
                "field_id": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "replacemsg_override_group": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
        },
        "srcaddr_negate": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dstaddr_negate": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "service_negate": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "groups": {
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
        "users": {
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
        "timeout_send_rst": {
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
        "dsri": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vlan_filter": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
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
        "label": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "global_label": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
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
    },
    "v_range": [["v6.0.0", "v6.2.7"]],
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
        "firewall_policy6": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_policy6"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_policy6"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_policy6"
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
