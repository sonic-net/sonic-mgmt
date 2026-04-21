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
module: fortios_firewall_mms_profile
short_description: Configure MMS profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and mms_profile category.
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
    firewall_mms_profile:
        description:
            - Configure MMS profiles.
        default: null
        type: dict
        suboptions:
            avnotificationtable:
                description:
                    - AntiVirus notification table ID. Source antivirus.notification.id.
                type: int
            bwordtable:
                description:
                    - MMS banned word table ID. Source webfilter.content.id.
                type: int
            carrier_endpoint_prefix:
                description:
                    - Enable/disable prefixing of end point values.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            carrier_endpoint_prefix_range_max:
                description:
                    - Maximum length of end point value that can be prefixed (1 - 48).
                type: int
            carrier_endpoint_prefix_range_min:
                description:
                    - Minimum end point length to be prefixed (1 - 48).
                type: int
            carrier_endpoint_prefix_string:
                description:
                    - String with which to prefix End point values.
                type: str
            carrierendpointbwltable:
                description:
                    - Carrier end point filter table ID. Source firewall.carrier-endpoint-bwl.id.
                type: int
            comment:
                description:
                    - Comment.
                type: str
            dupe:
                description:
                    - Duplicate configuration.
                type: list
                elements: dict
                suboptions:
                    action1:
                        description:
                            - Action to take when threshold reached.
                        type: list
                        elements: str
                        choices:
                            - 'block'
                            - 'archive'
                            - 'log'
                            - 'archive-first'
                            - 'alert-notif'
                    action2:
                        description:
                            - Action to take when threshold reached.
                        type: list
                        elements: str
                        choices:
                            - 'block'
                            - 'archive'
                            - 'log'
                            - 'archive-first'
                            - 'alert-notif'
                    action3:
                        description:
                            - Action to take when threshold reached.
                        type: list
                        elements: str
                        choices:
                            - 'block'
                            - 'archive'
                            - 'log'
                            - 'archive-first'
                            - 'alert-notif'
                    block_time1:
                        description:
                            - Duration for which action takes effect (0 - 35791 min).
                        type: int
                    block_time2:
                        description:
                            - Duration for which action takes effect (0 - 35791 min).
                        type: int
                    block_time3:
                        description:
                            - Duration action takes effect (0 - 35791 min).
                        type: int
                    limit1:
                        description:
                            - Maximum number of messages allowed.
                        type: int
                    limit2:
                        description:
                            - Maximum number of messages allowed.
                        type: int
                    limit3:
                        description:
                            - Maximum number of messages allowed.
                        type: int
                    protocol:
                        description:
                            - Protocol.
                        required: true
                        type: str
                    status1:
                        description:
                            - Enable/disable status1 detection.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status2:
                        description:
                            - Enable/disable status2 detection.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status3:
                        description:
                            - Enable/disable status3 detection.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    window1:
                        description:
                            - Window to count messages over (1 - 2880 min).
                        type: int
                    window2:
                        description:
                            - Window to count messages over (1 - 2880 min).
                        type: int
                    window3:
                        description:
                            - Window to count messages over (1 - 2880 min).
                        type: int
            extended_utm_log:
                description:
                    - Enable/disable detailed UTM log messages.
                type: str
            flood:
                description:
                    - Flood configuration.
                type: list
                elements: dict
                suboptions:
                    action1:
                        description:
                            - Action to take when threshold reached.
                        type: list
                        elements: str
                        choices:
                            - 'block'
                            - 'archive'
                            - 'log'
                            - 'archive-first'
                            - 'alert-notif'
                    action2:
                        description:
                            - Action to take when threshold reached.
                        type: list
                        elements: str
                        choices:
                            - 'block'
                            - 'archive'
                            - 'log'
                            - 'archive-first'
                            - 'alert-notif'
                    action3:
                        description:
                            - Action to take when threshold reached.
                        type: list
                        elements: str
                        choices:
                            - 'block'
                            - 'archive'
                            - 'log'
                            - 'archive-first'
                            - 'alert-notif'
                    block_time1:
                        description:
                            - Duration for which action takes effect (0 - 35791 min).
                        type: int
                    block_time2:
                        description:
                            - Duration for which action takes effect (0 - 35791 min).
                        type: int
                    block_time3:
                        description:
                            - Duration action takes effect (0 - 35791 min).
                        type: int
                    limit1:
                        description:
                            - Maximum number of messages allowed.
                        type: int
                    limit2:
                        description:
                            - Maximum number of messages allowed.
                        type: int
                    limit3:
                        description:
                            - Maximum number of messages allowed.
                        type: int
                    protocol:
                        description:
                            - Protocol.
                        required: true
                        type: str
                    status1:
                        description:
                            - Enable/disable status1 detection.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status2:
                        description:
                            - Enable/disable status2 detection.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status3:
                        description:
                            - Enable/disable status3 detection.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    window1:
                        description:
                            - Window to count messages over (1 - 2880 min).
                        type: int
                    window2:
                        description:
                            - Window to count messages over (1 - 2880 min).
                        type: int
                    window3:
                        description:
                            - Window to count messages over (1 - 2880 min).
                        type: int
            mm1:
                description:
                    - MM1 options.
                type: list
                elements: str
                choices:
                    - 'avmonitor'
                    - 'oversize'
                    - 'quarantine'
                    - 'scan'
                    - 'bannedword'
                    - 'chunkedbypass'
                    - 'clientcomfort'
                    - 'servercomfort'
                    - 'carrier-endpoint-bwl'
                    - 'remove-blocked'
                    - 'mms-checksum'
            mm1_addr_hdr:
                description:
                    - HTTP header field (for MM1) containing user address.
                type: str
            mm1_addr_source:
                description:
                    - Source for MM1 user address.
                type: str
                choices:
                    - 'http-header'
                    - 'cookie'
            mm1_convert_hex:
                description:
                    - Enable/disable converting user address from HEX string for MM1.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mm1_outbreak_prevention:
                description:
                    - Enable Virus Outbreak Prevention service.
                type: str
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm1_retr_dupe:
                description:
                    - Enable/disable duplicate scanning of MM1 retr.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mm1_retrieve_scan:
                description:
                    - Enable/disable scanning on MM1 retrieve configuration messages.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mm1comfortamount:
                description:
                    - MM1 comfort amount (0 - 4294967295).
                type: int
            mm1comfortinterval:
                description:
                    - MM1 comfort interval (0 - 4294967295).
                type: int
            mm1oversizelimit:
                description:
                    - Maximum file size to scan (1 - 819200 kB).
                type: int
            mm3:
                description:
                    - MM3 options.
                type: list
                elements: str
                choices:
                    - 'avmonitor'
                    - 'oversize'
                    - 'quarantine'
                    - 'scan'
                    - 'bannedword'
                    - 'fragmail'
                    - 'splice'
                    - 'carrier-endpoint-bwl'
                    - 'remove-blocked'
                    - 'mms-checksum'
            mm3_outbreak_prevention:
                description:
                    - Enable Virus Outbreak Prevention service.
                type: str
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm3oversizelimit:
                description:
                    - Maximum file size to scan (1 - 819200 kB).
                type: int
            mm4:
                description:
                    - MM4 options.
                type: list
                elements: str
                choices:
                    - 'avmonitor'
                    - 'oversize'
                    - 'quarantine'
                    - 'scan'
                    - 'bannedword'
                    - 'fragmail'
                    - 'splice'
                    - 'carrier-endpoint-bwl'
                    - 'remove-blocked'
                    - 'mms-checksum'
            mm4_outbreak_prevention:
                description:
                    - Enable Virus Outbreak Prevention service.
                type: str
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm4oversizelimit:
                description:
                    - Maximum file size to scan (1 - 819200 kB).
                type: int
            mm7:
                description:
                    - MM7 options.
                type: list
                elements: str
                choices:
                    - 'avmonitor'
                    - 'oversize'
                    - 'quarantine'
                    - 'scan'
                    - 'bannedword'
                    - 'chunkedbypass'
                    - 'clientcomfort'
                    - 'servercomfort'
                    - 'carrier-endpoint-bwl'
                    - 'remove-blocked'
                    - 'mms-checksum'
            mm7_addr_hdr:
                description:
                    - HTTP header field (for MM7) containing user address.
                type: str
            mm7_addr_source:
                description:
                    - Source for MM7 user address.
                type: str
                choices:
                    - 'http-header'
                    - 'cookie'
            mm7_convert_hex:
                description:
                    - Enable/disable conversion of user address from HEX string for MM7.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mm7_outbreak_prevention:
                description:
                    - Enable Virus Outbreak Prevention service.
                type: str
                choices:
                    - 'disabled'
                    - 'files'
                    - 'full-archive'
            mm7comfortamount:
                description:
                    - MM7 comfort amount (0 - 4294967295).
                type: int
            mm7comfortinterval:
                description:
                    - MM7 comfort interval (0 - 4294967295).
                type: int
            mm7oversizelimit:
                description:
                    - Maximum file size to scan (1 - 819200 kB).
                type: int
            mms_antispam_mass_log:
                description:
                    - Enable/disable logging for MMS antispam mass.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mms_av_block_log:
                description:
                    - Enable/disable logging for MMS antivirus file blocking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mms_av_oversize_log:
                description:
                    - Enable/disable logging for MMS antivirus oversize file blocking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mms_av_virus_log:
                description:
                    - Enable/disable logging for MMS antivirus scanning.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mms_carrier_endpoint_filter_log:
                description:
                    - Enable/disable logging for MMS end point filter blocking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mms_checksum_log:
                description:
                    - Enable/disable MMS content checksum logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mms_checksum_table:
                description:
                    - MMS content checksum table ID. Source antivirus.mms-checksum.id.
                type: int
            mms_notification_log:
                description:
                    - Enable/disable logging for MMS notification messages.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mms_web_content_log:
                description:
                    - Enable/disable logging for MMS web content blocking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mmsbwordthreshold:
                description:
                    - MMS banned word threshold.
                type: int
            name:
                description:
                    - Profile name.
                required: true
                type: str
            notif_msisdn:
                description:
                    - Notification for MSISDNs.
                type: list
                elements: dict
                suboptions:
                    msisdn:
                        description:
                            - Recipient MSISDN.
                        required: true
                        type: str
                    threshold:
                        description:
                            - Thresholds on which this MSISDN will receive an alert.
                        type: list
                        elements: str
                        choices:
                            - 'flood-thresh-1'
                            - 'flood-thresh-2'
                            - 'flood-thresh-3'
                            - 'dupe-thresh-1'
                            - 'dupe-thresh-2'
                            - 'dupe-thresh-3'
            notification:
                description:
                    - Notification configuration.
                type: list
                elements: dict
                suboptions:
                    alert_int:
                        description:
                            - Alert notification send interval.
                        type: int
                    alert_int_mode:
                        description:
                            - Alert notification interval mode.
                        type: str
                        choices:
                            - 'hours'
                            - 'minutes'
                    alert_src_msisdn:
                        description:
                            - Specify from address for alert messages.
                        type: str
                    alert_status:
                        description:
                            - Alert notification status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bword_int:
                        description:
                            - Banned word notification send interval.
                        type: int
                    bword_int_mode:
                        description:
                            - Banned word notification interval mode.
                        type: str
                        choices:
                            - 'hours'
                            - 'minutes'
                    bword_status:
                        description:
                            - Banned word notification status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    carrier_endpoint_bwl_int:
                        description:
                            - Carrier end point black/white list notification send interval.
                        type: int
                    carrier_endpoint_bwl_int_mode:
                        description:
                            - Carrier end point black/white list notification interval mode.
                        type: str
                        choices:
                            - 'hours'
                            - 'minutes'
                    carrier_endpoint_bwl_status:
                        description:
                            - Carrier end point black/white list notification status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    days_allowed:
                        description:
                            - Weekdays on which notification messages may be sent.
                        type: list
                        elements: str
                        choices:
                            - 'sunday'
                            - 'monday'
                            - 'tuesday'
                            - 'wednesday'
                            - 'thursday'
                            - 'friday'
                            - 'saturday'
                    detect_server:
                        description:
                            - Enable/disable automatic server address determination.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    dupe_int:
                        description:
                            - Duplicate notification send interval.
                        type: int
                    dupe_int_mode:
                        description:
                            - Duplicate notification interval mode.
                        type: str
                        choices:
                            - 'hours'
                            - 'minutes'
                    dupe_status:
                        description:
                            - Duplicate notification status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    file_block_int:
                        description:
                            - File block notification send interval.
                        type: int
                    file_block_int_mode:
                        description:
                            - File block notification interval mode.
                        type: str
                        choices:
                            - 'hours'
                            - 'minutes'
                    file_block_status:
                        description:
                            - File block notification status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    flood_int:
                        description:
                            - Flood notification send interval.
                        type: int
                    flood_int_mode:
                        description:
                            - Flood notification interval mode.
                        type: str
                        choices:
                            - 'hours'
                            - 'minutes'
                    flood_status:
                        description:
                            - Flood notification status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    from_in_header:
                        description:
                            - Enable/disable insertion of from address in HTTP header.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    mms_checksum_int:
                        description:
                            - MMS checksum notification send interval.
                        type: int
                    mms_checksum_int_mode:
                        description:
                            - MMS checksum notification interval mode.
                        type: str
                        choices:
                            - 'hours'
                            - 'minutes'
                    mms_checksum_status:
                        description:
                            - MMS checksum notification status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    mmsc_hostname:
                        description:
                            - Host name or IP address of the MMSC.
                        type: str
                    mmsc_password:
                        description:
                            - Password required for authentication with the MMSC.
                        type: str
                    mmsc_port:
                        description:
                            - Port used on the MMSC for sending MMS messages (1 - 65535).
                        type: int
                    mmsc_url:
                        description:
                            - URL used on the MMSC for sending MMS messages.
                        type: str
                    mmsc_username:
                        description:
                            - User name required for authentication with the MMSC.
                        type: str
                    msg_protocol:
                        description:
                            - Protocol to use for sending notification messages.
                        type: str
                        choices:
                            - 'mm1'
                            - 'mm3'
                            - 'mm4'
                            - 'mm7'
                    msg_type:
                        description:
                            - MM7 message type.
                        type: str
                        choices:
                            - 'submit-req'
                            - 'deliver-req'
                    protocol:
                        description:
                            - Protocol.
                        required: true
                        type: str
                    rate_limit:
                        description:
                            - Rate limit for sending notification messages (0 - 250).
                        type: int
                    tod_window_duration:
                        description:
                            - Time of day window duration.
                        type: str
                    tod_window_end:
                        description:
                            - Obsolete.
                        type: str
                    tod_window_start:
                        description:
                            - Time of day window start.
                        type: str
                    user_domain:
                        description:
                            - Domain name to which the user addresses belong.
                        type: str
                    vas_id:
                        description:
                            - VAS identifier.
                        type: str
                    vasp_id:
                        description:
                            - VASP identifier.
                        type: str
                    virus_int:
                        description:
                            - Virus notification send interval.
                        type: int
                    virus_int_mode:
                        description:
                            - Virus notification interval mode.
                        type: str
                        choices:
                            - 'hours'
                            - 'minutes'
                    virus_status:
                        description:
                            - Virus notification status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            outbreak_prevention:
                description:
                    - Configure Virus Outbreak Prevention settings.
                type: dict
                suboptions:
                    external_blocklist:
                        description:
                            - Enable/disable external malware blocklist.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    ftgd_service:
                        description:
                            - Enable/disable FortiGuard Virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            remove_blocked_const_length:
                description:
                    - Enable/disable MMS replacement of blocked file constant length.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
"""

EXAMPLES = """
- name: Configure MMS profiles.
  fortinet.fortios.fortios_firewall_mms_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_mms_profile:
          avnotificationtable: "2147483647"
          bwordtable: "2147483647"
          carrier_endpoint_prefix: "enable"
          carrier_endpoint_prefix_range_max: "24"
          carrier_endpoint_prefix_range_min: "24"
          carrier_endpoint_prefix_string: "<your_own_value>"
          carrierendpointbwltable: "2147483647"
          comment: "Comment."
          dupe:
              -
                  action1: "block"
                  action2: "block"
                  action3: "block"
                  block_time1: "17895"
                  block_time2: "17895"
                  block_time3: "17895"
                  limit1: "1073741823"
                  limit2: "1073741823"
                  limit3: "1073741823"
                  protocol: "<your_own_value>"
                  status1: "enable"
                  status2: "enable"
                  status3: "enable"
                  window1: "1440"
                  window2: "1440"
                  window3: "1440"
          extended_utm_log: "<your_own_value>"
          flood:
              -
                  action1: "block"
                  action2: "block"
                  action3: "block"
                  block_time1: "17895"
                  block_time2: "17895"
                  block_time3: "17895"
                  limit1: "1073741823"
                  limit2: "1073741823"
                  limit3: "1073741823"
                  protocol: "<your_own_value>"
                  status1: "enable"
                  status2: "enable"
                  status3: "enable"
                  window1: "1440"
                  window2: "1440"
                  window3: "1440"
          mm1: "avmonitor"
          mm1_addr_hdr: "<your_own_value>"
          mm1_addr_source: "http-header"
          mm1_convert_hex: "enable"
          mm1_outbreak_prevention: "disabled"
          mm1_retr_dupe: "enable"
          mm1_retrieve_scan: "enable"
          mm1comfortamount: "2147483647"
          mm1comfortinterval: "2147483647"
          mm1oversizelimit: "409600"
          mm3: "avmonitor"
          mm3_outbreak_prevention: "disabled"
          mm3oversizelimit: "409600"
          mm4: "avmonitor"
          mm4_outbreak_prevention: "disabled"
          mm4oversizelimit: "409600"
          mm7: "avmonitor"
          mm7_addr_hdr: "<your_own_value>"
          mm7_addr_source: "http-header"
          mm7_convert_hex: "enable"
          mm7_outbreak_prevention: "disabled"
          mm7comfortamount: "2147483647"
          mm7comfortinterval: "2147483647"
          mm7oversizelimit: "409600"
          mms_antispam_mass_log: "enable"
          mms_av_block_log: "enable"
          mms_av_oversize_log: "enable"
          mms_av_virus_log: "enable"
          mms_carrier_endpoint_filter_log: "enable"
          mms_checksum_log: "enable"
          mms_checksum_table: "2147483647"
          mms_notification_log: "enable"
          mms_web_content_log: "enable"
          mmsbwordthreshold: "1073741823"
          name: "default_name_80"
          notif_msisdn:
              -
                  msisdn: "<your_own_value>"
                  threshold: "flood-thresh-1"
          notification:
              -
                  alert_int: "720"
                  alert_int_mode: "hours"
                  alert_src_msisdn: "<your_own_value>"
                  alert_status: "enable"
                  bword_int: "720"
                  bword_int_mode: "hours"
                  bword_status: "enable"
                  carrier_endpoint_bwl_int: "720"
                  carrier_endpoint_bwl_int_mode: "hours"
                  carrier_endpoint_bwl_status: "enable"
                  days_allowed: "sunday"
                  detect_server: "enable"
                  dupe_int: "720"
                  dupe_int_mode: "hours"
                  dupe_status: "enable"
                  file_block_int: "720"
                  file_block_int_mode: "hours"
                  file_block_status: "enable"
                  flood_int: "720"
                  flood_int_mode: "hours"
                  flood_status: "enable"
                  from_in_header: "enable"
                  mms_checksum_int: "720"
                  mms_checksum_int_mode: "hours"
                  mms_checksum_status: "enable"
                  mmsc_hostname: "myhostname"
                  mmsc_password: "<your_own_value>"
                  mmsc_port: "32767"
                  mmsc_url: "<your_own_value>"
                  mmsc_username: "<your_own_value>"
                  msg_protocol: "mm1"
                  msg_type: "submit-req"
                  protocol: "<your_own_value>"
                  rate_limit: "125"
                  tod_window_duration: "<your_own_value>"
                  tod_window_end: "<your_own_value>"
                  tod_window_start: "<your_own_value>"
                  user_domain: "<your_own_value>"
                  vas_id: "<your_own_value>"
                  vasp_id: "<your_own_value>"
                  virus_int: "720"
                  virus_int_mode: "hours"
                  virus_status: "enable"
          outbreak_prevention:
              external_blocklist: "disable"
              ftgd_service: "disable"
          remove_blocked_const_length: "enable"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
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


def filter_firewall_mms_profile_data(json):
    option_list = [
        "avnotificationtable",
        "bwordtable",
        "carrier_endpoint_prefix",
        "carrier_endpoint_prefix_range_max",
        "carrier_endpoint_prefix_range_min",
        "carrier_endpoint_prefix_string",
        "carrierendpointbwltable",
        "comment",
        "dupe",
        "extended_utm_log",
        "flood",
        "mm1",
        "mm1_addr_hdr",
        "mm1_addr_source",
        "mm1_convert_hex",
        "mm1_outbreak_prevention",
        "mm1_retr_dupe",
        "mm1_retrieve_scan",
        "mm1comfortamount",
        "mm1comfortinterval",
        "mm1oversizelimit",
        "mm3",
        "mm3_outbreak_prevention",
        "mm3oversizelimit",
        "mm4",
        "mm4_outbreak_prevention",
        "mm4oversizelimit",
        "mm7",
        "mm7_addr_hdr",
        "mm7_addr_source",
        "mm7_convert_hex",
        "mm7_outbreak_prevention",
        "mm7comfortamount",
        "mm7comfortinterval",
        "mm7oversizelimit",
        "mms_antispam_mass_log",
        "mms_av_block_log",
        "mms_av_oversize_log",
        "mms_av_virus_log",
        "mms_carrier_endpoint_filter_log",
        "mms_checksum_log",
        "mms_checksum_table",
        "mms_notification_log",
        "mms_web_content_log",
        "mmsbwordthreshold",
        "name",
        "notif_msisdn",
        "notification",
        "outbreak_prevention",
        "remove_blocked_const_length",
        "replacemsg_group",
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
        ["mm1"],
        ["mm3"],
        ["mm4"],
        ["mm7"],
        ["notification", "days_allowed"],
        ["notif_msisdn", "threshold"],
        ["flood", "action1"],
        ["flood", "action2"],
        ["flood", "action3"],
        ["dupe", "action1"],
        ["dupe", "action2"],
        ["dupe", "action3"],
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


def firewall_mms_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_mms_profile_data = data["firewall_mms_profile"]

    filtered_data = filter_firewall_mms_profile_data(firewall_mms_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "mms-profile", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "mms-profile", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_mms_profile"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "mms-profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "mms-profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "mms-profile", mkey=converted_data["name"], vdom=vdom
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

    if data["firewall_mms_profile"]:
        resp = firewall_mms_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_mms_profile"))
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
        "name": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string", "required": True},
        "comment": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "replacemsg_group": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "mmsbwordthreshold": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "mm1comfortinterval": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "mm7comfortinterval": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "mm1comfortamount": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "mm7comfortamount": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "extended_utm_log": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "mms_carrier_endpoint_filter_log": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mms_antispam_mass_log": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mms_notification_log": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mms_checksum_log": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mms_av_virus_log": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mms_av_block_log": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mms_av_oversize_log": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mms_web_content_log": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mm1_addr_hdr": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "mm7_addr_hdr": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "mm1_addr_source": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "http-header"}, {"value": "cookie"}],
        },
        "mm7_addr_source": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "http-header"}, {"value": "cookie"}],
        },
        "mm1_convert_hex": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mm7_convert_hex": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "carrier_endpoint_prefix": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "carrier_endpoint_prefix_string": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
        },
        "carrier_endpoint_prefix_range_min": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "integer",
        },
        "carrier_endpoint_prefix_range_max": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "integer",
        },
        "remove_blocked_const_length": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mm1": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "list",
            "options": [
                {"value": "avmonitor"},
                {"value": "oversize"},
                {"value": "quarantine"},
                {"value": "scan"},
                {"value": "bannedword"},
                {"value": "chunkedbypass"},
                {"value": "clientcomfort"},
                {"value": "servercomfort"},
                {"value": "carrier-endpoint-bwl"},
                {"value": "remove-blocked"},
                {"value": "mms-checksum"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "mm1_retrieve_scan": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mm3": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "list",
            "options": [
                {"value": "avmonitor"},
                {"value": "oversize"},
                {"value": "quarantine"},
                {"value": "scan"},
                {"value": "bannedword"},
                {"value": "fragmail"},
                {"value": "splice"},
                {"value": "carrier-endpoint-bwl"},
                {"value": "remove-blocked"},
                {"value": "mms-checksum"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "mm4": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "list",
            "options": [
                {"value": "avmonitor"},
                {"value": "oversize"},
                {"value": "quarantine"},
                {"value": "scan"},
                {"value": "bannedword"},
                {"value": "fragmail"},
                {"value": "splice"},
                {"value": "carrier-endpoint-bwl"},
                {"value": "remove-blocked"},
                {"value": "mms-checksum"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "mm7": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "list",
            "options": [
                {"value": "avmonitor"},
                {"value": "oversize"},
                {"value": "quarantine"},
                {"value": "scan"},
                {"value": "bannedword"},
                {"value": "chunkedbypass"},
                {"value": "clientcomfort"},
                {"value": "servercomfort"},
                {"value": "carrier-endpoint-bwl"},
                {"value": "remove-blocked"},
                {"value": "mms-checksum"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "mm1oversizelimit": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "mm3oversizelimit": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "mm4oversizelimit": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "mm7oversizelimit": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "outbreak_prevention": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "dict",
            "children": {
                "ftgd_service": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "external_blocklist": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
        },
        "mm1_outbreak_prevention": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [
                {"value": "disabled"},
                {"value": "files"},
                {"value": "full-archive"},
            ],
        },
        "mm3_outbreak_prevention": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [
                {"value": "disabled"},
                {"value": "files"},
                {"value": "full-archive"},
            ],
        },
        "mm4_outbreak_prevention": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [
                {"value": "disabled"},
                {"value": "files"},
                {"value": "full-archive"},
            ],
        },
        "mm7_outbreak_prevention": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [
                {"value": "disabled"},
                {"value": "files"},
                {"value": "full-archive"},
            ],
        },
        "notification": {
            "type": "list",
            "elements": "dict",
            "children": {
                "protocol": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                },
                "msg_protocol": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [
                        {"value": "mm1"},
                        {"value": "mm3"},
                        {"value": "mm4"},
                        {"value": "mm7"},
                    ],
                },
                "msg_type": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "submit-req"}, {"value": "deliver-req"}],
                },
                "detect_server": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mmsc_hostname": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "mmsc_url": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "mmsc_port": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "mmsc_username": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "mmsc_password": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "user_domain": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "vasp_id": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "vas_id": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "from_in_header": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "rate_limit": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "tod_window_start": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                },
                "tod_window_end": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
                "tod_window_duration": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                },
                "days_allowed": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "list",
                    "options": [
                        {"value": "sunday"},
                        {"value": "monday"},
                        {"value": "tuesday"},
                        {"value": "wednesday"},
                        {"value": "thursday"},
                        {"value": "friday"},
                        {"value": "saturday"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "alert_src_msisdn": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                },
                "bword_int_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "hours"}, {"value": "minutes"}],
                },
                "bword_int": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "bword_status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "file_block_int_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "hours"}, {"value": "minutes"}],
                },
                "file_block_int": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "file_block_status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "carrier_endpoint_bwl_int_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "hours"}, {"value": "minutes"}],
                },
                "carrier_endpoint_bwl_int": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "carrier_endpoint_bwl_status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "flood_int_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "hours"}, {"value": "minutes"}],
                },
                "flood_int": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "flood_status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "dupe_int_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "hours"}, {"value": "minutes"}],
                },
                "dupe_int": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "dupe_status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "alert_int_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "hours"}, {"value": "minutes"}],
                },
                "alert_int": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "alert_status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "mms_checksum_int_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "hours"}, {"value": "minutes"}],
                },
                "mms_checksum_int": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "integer",
                },
                "mms_checksum_status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "virus_int_mode": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "hours"}, {"value": "minutes"}],
                },
                "virus_int": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "virus_status": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "notif_msisdn": {
            "type": "list",
            "elements": "dict",
            "children": {
                "msisdn": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                },
                "threshold": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "list",
                    "options": [
                        {"value": "flood-thresh-1"},
                        {"value": "flood-thresh-2"},
                        {"value": "flood-thresh-3"},
                        {"value": "dupe-thresh-1"},
                        {"value": "dupe-thresh-2"},
                        {"value": "dupe-thresh-3"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "flood": {
            "type": "list",
            "elements": "dict",
            "children": {
                "protocol": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                },
                "status1": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "window1": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "limit1": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "action1": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "list",
                    "options": [
                        {"value": "block"},
                        {"value": "archive"},
                        {"value": "log"},
                        {"value": "archive-first"},
                        {"value": "alert-notif"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "block_time1": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "status2": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "window2": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "limit2": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "action2": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "list",
                    "options": [
                        {"value": "block"},
                        {"value": "archive"},
                        {"value": "log"},
                        {"value": "archive-first"},
                        {"value": "alert-notif"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "block_time2": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "status3": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "window3": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "limit3": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "action3": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "list",
                    "options": [
                        {"value": "block"},
                        {"value": "archive"},
                        {"value": "log"},
                        {"value": "archive-first"},
                        {"value": "alert-notif"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "block_time3": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "dupe": {
            "type": "list",
            "elements": "dict",
            "children": {
                "protocol": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "required": True,
                },
                "status1": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "window1": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "limit1": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "action1": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "list",
                    "options": [
                        {"value": "block"},
                        {"value": "archive"},
                        {"value": "log"},
                        {"value": "archive-first"},
                        {"value": "alert-notif"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "block_time1": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "status2": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "window2": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "limit2": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "action2": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "list",
                    "options": [
                        {"value": "block"},
                        {"value": "archive"},
                        {"value": "log"},
                        {"value": "archive-first"},
                        {"value": "alert-notif"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "block_time2": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "status3": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "window3": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "limit3": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
                "action3": {
                    "v_range": [["v6.0.0", "v6.2.7"]],
                    "type": "list",
                    "options": [
                        {"value": "block"},
                        {"value": "archive"},
                        {"value": "log"},
                        {"value": "archive-first"},
                        {"value": "alert-notif"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "block_time3": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
            },
            "v_range": [["v6.0.0", "v6.2.7"]],
        },
        "mm1_retr_dupe": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "carrierendpointbwltable": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "integer",
        },
        "avnotificationtable": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "mms_checksum_table": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "bwordtable": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
    },
    "v_range": [["v6.0.0", "v6.2.7"]],
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
        "firewall_mms_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_mms_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_mms_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_mms_profile"
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
