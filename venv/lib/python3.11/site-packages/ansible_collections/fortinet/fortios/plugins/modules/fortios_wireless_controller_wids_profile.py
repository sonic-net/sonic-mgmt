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
module: fortios_wireless_controller_wids_profile
short_description: Configure wireless intrusion detection system (WIDS) profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and wids_profile category.
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
    wireless_controller_wids_profile:
        description:
            - Configure wireless intrusion detection system (WIDS) profiles.
        default: null
        type: dict
        suboptions:
            adhoc_network:
                description:
                    - Enable/disable adhoc network detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            adhoc_valid_ssid:
                description:
                    - Enable/disable adhoc using valid SSID detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            air_jack:
                description:
                    - Enable/disable AirJack detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ap_auto_suppress:
                description:
                    - Enable/disable on-wire rogue AP auto-suppression .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ap_bgscan_disable_day:
                description:
                    - Optionally turn off scanning for one or more days of the week. Separate the days with a space. By default, no days are set.
                type: str
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            ap_bgscan_disable_end:
                description:
                    - 'End time, using a 24-hour clock in the format of hh:mm, for disabling background scanning .'
                type: str
            ap_bgscan_disable_schedules:
                description:
                    - Firewall schedules for turning off FortiAP radio background scan. Background scan will be disabled when at least one of the schedules is
                       valid. Separate multiple schedule names with a space.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Schedule name. Source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name.
                        required: true
                        type: str
            ap_bgscan_disable_start:
                description:
                    - 'Start time, using a 24-hour clock in the format of hh:mm, for disabling background scanning .'
                type: str
            ap_bgscan_duration:
                description:
                    - Listen time on scanning a channel (10 - 1000 msec).
                type: int
            ap_bgscan_idle:
                description:
                    - Wait time for channel inactivity before scanning this channel (0 - 1000 msec).
                type: int
            ap_bgscan_intv:
                description:
                    - Period between successive channel scans (1 - 600 sec).
                type: int
            ap_bgscan_period:
                description:
                    - Period between background scans (10 - 3600 sec).
                type: int
            ap_bgscan_report_intv:
                description:
                    - Period between background scan reports (15 - 600 sec).
                type: int
            ap_fgscan_report_intv:
                description:
                    - Period between foreground scan reports (15 - 600 sec).
                type: int
            ap_impersonation:
                description:
                    - Enable/disable AP impersonation detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ap_scan:
                description:
                    - Enable/disable rogue AP detection.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ap_scan_channel_list_2G_5G:
                description:
                    - Selected ap scan channel list for 2.4G and 5G bands.
                type: list
                elements: dict
                suboptions:
                    chan:
                        description:
                            - Channel number.
                        required: true
                        type: str
            ap_scan_channel_list_6G:
                description:
                    - Selected ap scan channel list for 6G band.
                type: list
                elements: dict
                suboptions:
                    chan:
                        description:
                            - Channel 6g number.
                        required: true
                        type: str
            ap_scan_passive:
                description:
                    - Enable/disable passive scanning. Enable means do not send probe request on any channels .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ap_scan_threshold:
                description:
                    - Minimum signal level/threshold in dBm required for the AP to report detected rogue AP (-95 to -20).
                type: str
            ap_spoofing:
                description:
                    - Enable/disable AP spoofing detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            asleap_attack:
                description:
                    - Enable/disable asleap attack detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            assoc_flood_thresh:
                description:
                    - The threshold value for association frame flooding.
                type: int
            assoc_flood_time:
                description:
                    - Number of seconds after which a station is considered not connected.
                type: int
            assoc_frame_flood:
                description:
                    - Enable/disable association frame flooding detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_flood_thresh:
                description:
                    - The threshold value for authentication frame flooding.
                type: int
            auth_flood_time:
                description:
                    - Number of seconds after which a station is considered not connected.
                type: int
            auth_frame_flood:
                description:
                    - Enable/disable authentication frame flooding detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bcn_flood:
                description:
                    - Enable/disable bcn flood detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bcn_flood_thresh:
                description:
                    - The threshold value for bcn flood.
                type: int
            bcn_flood_time:
                description:
                    - Detection Window Period.
                type: int
            beacon_wrong_channel:
                description:
                    - Enable/disable beacon wrong channel detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            block_ack_flood:
                description:
                    - Enable/disable block_ack flood detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            block_ack_flood_thresh:
                description:
                    - The threshold value for block_ack flood.
                type: int
            block_ack_flood_time:
                description:
                    - Detection Window Period.
                type: int
            chan_based_mitm:
                description:
                    - Enable/disable channel based mitm detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            client_flood:
                description:
                    - Enable/disable client flood detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            client_flood_thresh:
                description:
                    - The threshold value for client flood.
                type: int
            client_flood_time:
                description:
                    - Detection Window Period.
                type: int
            comment:
                description:
                    - Comment.
                type: str
            cts_flood:
                description:
                    - Enable/disable cts flood detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cts_flood_thresh:
                description:
                    - The threshold value for cts flood.
                type: int
            cts_flood_time:
                description:
                    - Detection Window Period.
                type: int
            deauth_broadcast:
                description:
                    - Enable/disable broadcasting de-authentication detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            deauth_unknown_src_thresh:
                description:
                    - 'Threshold value per second to deauth unknown src for DoS attack (0: no limit).'
                type: int
            disassoc_broadcast:
                description:
                    - Enable/disable broadcast dis-association detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            disconnect_station:
                description:
                    - Enable/disable disconnect station detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eapol_fail_flood:
                description:
                    - Enable/disable EAPOL-Failure flooding (to AP) detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eapol_fail_intv:
                description:
                    - The detection interval for EAPOL-Failure flooding (1 - 3600 sec).
                type: int
            eapol_fail_thresh:
                description:
                    - The threshold value for EAPOL-Failure flooding in specified interval.
                type: int
            eapol_key_overflow:
                description:
                    - Enable/disable overflow EAPOL key detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eapol_logoff_flood:
                description:
                    - Enable/disable EAPOL-Logoff flooding (to AP) detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eapol_logoff_intv:
                description:
                    - The detection interval for EAPOL-Logoff flooding (1 - 3600 sec).
                type: int
            eapol_logoff_thresh:
                description:
                    - The threshold value for EAPOL-Logoff flooding in specified interval.
                type: int
            eapol_pre_fail_flood:
                description:
                    - Enable/disable premature EAPOL-Failure flooding (to STA) detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eapol_pre_fail_intv:
                description:
                    - The detection interval for premature EAPOL-Failure flooding (1 - 3600 sec).
                type: int
            eapol_pre_fail_thresh:
                description:
                    - The threshold value for premature EAPOL-Failure flooding in specified interval.
                type: int
            eapol_pre_succ_flood:
                description:
                    - Enable/disable premature EAPOL-Success flooding (to STA) detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eapol_pre_succ_intv:
                description:
                    - The detection interval for premature EAPOL-Success flooding (1 - 3600 sec).
                type: int
            eapol_pre_succ_thresh:
                description:
                    - The threshold value for premature EAPOL-Success flooding in specified interval.
                type: int
            eapol_start_flood:
                description:
                    - Enable/disable EAPOL-Start flooding (to AP) detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eapol_start_intv:
                description:
                    - The detection interval for EAPOL-Start flooding (1 - 3600 sec).
                type: int
            eapol_start_thresh:
                description:
                    - The threshold value for EAPOL-Start flooding in specified interval.
                type: int
            eapol_succ_flood:
                description:
                    - Enable/disable EAPOL-Success flooding (to AP) detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            eapol_succ_intv:
                description:
                    - The detection interval for EAPOL-Success flooding (1 - 3600 sec).
                type: int
            eapol_succ_thresh:
                description:
                    - The threshold value for EAPOL-Success flooding in specified interval.
                type: int
            fata_jack:
                description:
                    - Enable/disable FATA-Jack detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fuzzed_beacon:
                description:
                    - Enable/disable fuzzed beacon detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fuzzed_probe_request:
                description:
                    - Enable/disable fuzzed probe request detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fuzzed_probe_response:
                description:
                    - Enable/disable fuzzed probe response detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            hotspotter_attack:
                description:
                    - Enable/disable hotspotter attack detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ht_40mhz_intolerance:
                description:
                    - Enable/disable HT 40 MHz intolerance detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ht_greenfield:
                description:
                    - Enable/disable HT greenfield detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            invalid_addr_combination:
                description:
                    - Enable/disable invalid address combination detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            invalid_mac_oui:
                description:
                    - Enable/disable invalid MAC OUI detection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            long_duration_attack:
                description:
                    - Enable/disable long duration attack detection based on user configured threshold .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            long_duration_thresh:
                description:
                    - Threshold value for long duration attack detection (1000 - 32767 usec).
                type: int
            malformed_association:
                description:
                    - Enable/disable malformed association request detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            malformed_auth:
                description:
                    - Enable/disable malformed auth frame detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            malformed_ht_ie:
                description:
                    - Enable/disable malformed HT IE detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - WIDS profile name.
                required: true
                type: str
            netstumbler:
                description:
                    - Enable/disable netstumbler detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            netstumbler_thresh:
                description:
                    - The threshold value for netstumbler.
                type: int
            netstumbler_time:
                description:
                    - Detection Window Period.
                type: int
            null_ssid_probe_resp:
                description:
                    - Enable/disable null SSID probe response detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            omerta_attack:
                description:
                    - Enable/disable omerta attack detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            overflow_ie:
                description:
                    - Enable/disable overflow IE detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            probe_flood:
                description:
                    - Enable/disable probe flood detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            probe_flood_thresh:
                description:
                    - The threshold value for probe flood.
                type: int
            probe_flood_time:
                description:
                    - Detection Window Period.
                type: int
            pspoll_flood:
                description:
                    - Enable/disable pspoll flood detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pspoll_flood_thresh:
                description:
                    - The threshold value for pspoll flood.
                type: int
            pspoll_flood_time:
                description:
                    - Detection Window Period.
                type: int
            pwsave_dos_attack:
                description:
                    - Enable/disable power save DOS attack detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            reassoc_flood:
                description:
                    - Enable/disable reassociation flood detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            reassoc_flood_thresh:
                description:
                    - The threshold value for reassociation flood.
                type: int
            reassoc_flood_time:
                description:
                    - Detection Window Period.
                type: int
            risky_encryption:
                description:
                    - Enable/disable Risky Encryption detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rts_flood:
                description:
                    - Enable/disable rts flood detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rts_flood_thresh:
                description:
                    - The threshold value for rts flood.
                type: int
            rts_flood_time:
                description:
                    - Detection Window Period.
                type: int
            sensor_mode:
                description:
                    - Scan nearby WiFi stations .
                type: str
                choices:
                    - 'disable'
                    - 'foreign'
                    - 'both'
            spoofed_deauth:
                description:
                    - Enable/disable spoofed de-authentication attack detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            unencrypted_valid:
                description:
                    - Enable/disable unencrypted valid detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            valid_client_misassociation:
                description:
                    - Enable/disable valid client misassociation detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            valid_ssid_misuse:
                description:
                    - Enable/disable valid SSID misuse detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            weak_wep_iv:
                description:
                    - Enable/disable weak WEP IV (Initialization Vector) detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wellenreiter:
                description:
                    - Enable/disable wellenreiter detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wellenreiter_thresh:
                description:
                    - The threshold value for wellenreiter.
                type: int
            wellenreiter_time:
                description:
                    - Detection Window Period.
                type: int
            windows_bridge:
                description:
                    - Enable/disable windows bridge detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wireless_bridge:
                description:
                    - Enable/disable wireless bridge detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wpa_ft_attack:
                description:
                    - Enable/disable WPA FT attack detection .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure wireless intrusion detection system (WIDS) profiles.
  fortinet.fortios.fortios_wireless_controller_wids_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_wids_profile:
          adhoc_network: "enable"
          adhoc_valid_ssid: "enable"
          air_jack: "enable"
          ap_auto_suppress: "enable"
          ap_bgscan_disable_day: "sunday"
          ap_bgscan_disable_end: "<your_own_value>"
          ap_bgscan_disable_schedules:
              -
                  name: "default_name_10 (source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name)"
          ap_bgscan_disable_start: "<your_own_value>"
          ap_bgscan_duration: "30"
          ap_bgscan_idle: "20"
          ap_bgscan_intv: "3"
          ap_bgscan_period: "600"
          ap_bgscan_report_intv: "30"
          ap_fgscan_report_intv: "15"
          ap_impersonation: "enable"
          ap_scan: "disable"
          ap_scan_channel_list_2G_5G:
              -
                  chan: "<your_own_value>"
          ap_scan_channel_list_6G:
              -
                  chan: "<your_own_value>"
          ap_scan_passive: "enable"
          ap_scan_threshold: "<your_own_value>"
          ap_spoofing: "enable"
          asleap_attack: "enable"
          assoc_flood_thresh: "30"
          assoc_flood_time: "10"
          assoc_frame_flood: "enable"
          auth_flood_thresh: "30"
          auth_flood_time: "10"
          auth_frame_flood: "enable"
          bcn_flood: "enable"
          bcn_flood_thresh: "15"
          bcn_flood_time: "1"
          beacon_wrong_channel: "enable"
          block_ack_flood: "enable"
          block_ack_flood_thresh: "50"
          block_ack_flood_time: "1"
          chan_based_mitm: "enable"
          client_flood: "enable"
          client_flood_thresh: "30"
          client_flood_time: "10"
          comment: "Comment."
          cts_flood: "enable"
          cts_flood_thresh: "30"
          cts_flood_time: "10"
          deauth_broadcast: "enable"
          deauth_unknown_src_thresh: "10"
          disassoc_broadcast: "enable"
          disconnect_station: "enable"
          eapol_fail_flood: "enable"
          eapol_fail_intv: "1"
          eapol_fail_thresh: "10"
          eapol_key_overflow: "enable"
          eapol_logoff_flood: "enable"
          eapol_logoff_intv: "1"
          eapol_logoff_thresh: "10"
          eapol_pre_fail_flood: "enable"
          eapol_pre_fail_intv: "1"
          eapol_pre_fail_thresh: "10"
          eapol_pre_succ_flood: "enable"
          eapol_pre_succ_intv: "1"
          eapol_pre_succ_thresh: "10"
          eapol_start_flood: "enable"
          eapol_start_intv: "1"
          eapol_start_thresh: "10"
          eapol_succ_flood: "enable"
          eapol_succ_intv: "1"
          eapol_succ_thresh: "10"
          fata_jack: "enable"
          fuzzed_beacon: "enable"
          fuzzed_probe_request: "enable"
          fuzzed_probe_response: "enable"
          hotspotter_attack: "enable"
          ht_40mhz_intolerance: "enable"
          ht_greenfield: "enable"
          invalid_addr_combination: "enable"
          invalid_mac_oui: "enable"
          long_duration_attack: "enable"
          long_duration_thresh: "8200"
          malformed_association: "enable"
          malformed_auth: "enable"
          malformed_ht_ie: "enable"
          name: "default_name_86"
          netstumbler: "enable"
          netstumbler_thresh: "5"
          netstumbler_time: "30"
          null_ssid_probe_resp: "enable"
          omerta_attack: "enable"
          overflow_ie: "enable"
          probe_flood: "enable"
          probe_flood_thresh: "30"
          probe_flood_time: "1"
          pspoll_flood: "enable"
          pspoll_flood_thresh: "30"
          pspoll_flood_time: "1"
          pwsave_dos_attack: "enable"
          reassoc_flood: "enable"
          reassoc_flood_thresh: "30"
          reassoc_flood_time: "10"
          risky_encryption: "enable"
          rts_flood: "enable"
          rts_flood_thresh: "30"
          rts_flood_time: "10"
          sensor_mode: "disable"
          spoofed_deauth: "enable"
          unencrypted_valid: "enable"
          valid_client_misassociation: "enable"
          valid_ssid_misuse: "enable"
          weak_wep_iv: "enable"
          wellenreiter: "enable"
          wellenreiter_thresh: "5"
          wellenreiter_time: "30"
          windows_bridge: "enable"
          wireless_bridge: "enable"
          wpa_ft_attack: "enable"
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


def filter_wireless_controller_wids_profile_data(json):
    option_list = [
        "adhoc_network",
        "adhoc_valid_ssid",
        "air_jack",
        "ap_auto_suppress",
        "ap_bgscan_disable_day",
        "ap_bgscan_disable_end",
        "ap_bgscan_disable_schedules",
        "ap_bgscan_disable_start",
        "ap_bgscan_duration",
        "ap_bgscan_idle",
        "ap_bgscan_intv",
        "ap_bgscan_period",
        "ap_bgscan_report_intv",
        "ap_fgscan_report_intv",
        "ap_impersonation",
        "ap_scan",
        "ap_scan_channel_list_2G_5G",
        "ap_scan_channel_list_6G",
        "ap_scan_passive",
        "ap_scan_threshold",
        "ap_spoofing",
        "asleap_attack",
        "assoc_flood_thresh",
        "assoc_flood_time",
        "assoc_frame_flood",
        "auth_flood_thresh",
        "auth_flood_time",
        "auth_frame_flood",
        "bcn_flood",
        "bcn_flood_thresh",
        "bcn_flood_time",
        "beacon_wrong_channel",
        "block_ack_flood",
        "block_ack_flood_thresh",
        "block_ack_flood_time",
        "chan_based_mitm",
        "client_flood",
        "client_flood_thresh",
        "client_flood_time",
        "comment",
        "cts_flood",
        "cts_flood_thresh",
        "cts_flood_time",
        "deauth_broadcast",
        "deauth_unknown_src_thresh",
        "disassoc_broadcast",
        "disconnect_station",
        "eapol_fail_flood",
        "eapol_fail_intv",
        "eapol_fail_thresh",
        "eapol_key_overflow",
        "eapol_logoff_flood",
        "eapol_logoff_intv",
        "eapol_logoff_thresh",
        "eapol_pre_fail_flood",
        "eapol_pre_fail_intv",
        "eapol_pre_fail_thresh",
        "eapol_pre_succ_flood",
        "eapol_pre_succ_intv",
        "eapol_pre_succ_thresh",
        "eapol_start_flood",
        "eapol_start_intv",
        "eapol_start_thresh",
        "eapol_succ_flood",
        "eapol_succ_intv",
        "eapol_succ_thresh",
        "fata_jack",
        "fuzzed_beacon",
        "fuzzed_probe_request",
        "fuzzed_probe_response",
        "hotspotter_attack",
        "ht_40mhz_intolerance",
        "ht_greenfield",
        "invalid_addr_combination",
        "invalid_mac_oui",
        "long_duration_attack",
        "long_duration_thresh",
        "malformed_association",
        "malformed_auth",
        "malformed_ht_ie",
        "name",
        "netstumbler",
        "netstumbler_thresh",
        "netstumbler_time",
        "null_ssid_probe_resp",
        "omerta_attack",
        "overflow_ie",
        "probe_flood",
        "probe_flood_thresh",
        "probe_flood_time",
        "pspoll_flood",
        "pspoll_flood_thresh",
        "pspoll_flood_time",
        "pwsave_dos_attack",
        "reassoc_flood",
        "reassoc_flood_thresh",
        "reassoc_flood_time",
        "risky_encryption",
        "rts_flood",
        "rts_flood_thresh",
        "rts_flood_time",
        "sensor_mode",
        "spoofed_deauth",
        "unencrypted_valid",
        "valid_client_misassociation",
        "valid_ssid_misuse",
        "weak_wep_iv",
        "wellenreiter",
        "wellenreiter_thresh",
        "wellenreiter_time",
        "windows_bridge",
        "wireless_bridge",
        "wpa_ft_attack",
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


def wireless_controller_wids_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wireless_controller_wids_profile_data = data["wireless_controller_wids_profile"]

    filtered_data = filter_wireless_controller_wids_profile_data(
        wireless_controller_wids_profile_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "wireless-controller", "wids-profile", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "wireless-controller", "wids-profile", vdom=vdom, mkey=mkey
        )
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
    data_copy["wireless_controller_wids_profile"] = filtered_data
    fos.do_member_operation(
        "wireless-controller",
        "wids-profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "wireless-controller", "wids-profile", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "wireless-controller",
            "wids-profile",
            mkey=converted_data["name"],
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


def fortios_wireless_controller(data, fos, check_mode):

    if data["wireless_controller_wids_profile"]:
        resp = wireless_controller_wids_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_wids_profile")
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
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sensor_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "foreign"}, {"value": "both"}],
        },
        "ap_scan": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ap_scan_channel_list_2G_5G": {
            "type": "list",
            "elements": "dict",
            "children": {
                "chan": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.1", ""]],
        },
        "ap_scan_channel_list_6G": {
            "type": "list",
            "elements": "dict",
            "children": {
                "chan": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.1", ""]],
        },
        "ap_bgscan_period": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ap_bgscan_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ap_bgscan_duration": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ap_bgscan_idle": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ap_bgscan_report_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ap_bgscan_disable_schedules": {
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
        "ap_fgscan_report_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ap_scan_passive": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ap_scan_threshold": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "ap_auto_suppress": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wireless_bridge": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "deauth_broadcast": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "null_ssid_probe_resp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "long_duration_attack": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "long_duration_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "invalid_mac_oui": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "weak_wep_iv": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_frame_flood": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_flood_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_flood_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "assoc_frame_flood": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "assoc_flood_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "assoc_flood_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "reassoc_flood": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "reassoc_flood_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "reassoc_flood_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "probe_flood": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "probe_flood_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "probe_flood_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "bcn_flood": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bcn_flood_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "bcn_flood_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "rts_flood": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rts_flood_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "rts_flood_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "cts_flood": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cts_flood_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "cts_flood_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "client_flood": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "client_flood_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "client_flood_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "block_ack_flood": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "block_ack_flood_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "block_ack_flood_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "pspoll_flood": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pspoll_flood_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "pspoll_flood_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "netstumbler": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "netstumbler_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "netstumbler_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "wellenreiter": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wellenreiter_time": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "wellenreiter_thresh": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "spoofed_deauth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "asleap_attack": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eapol_start_flood": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eapol_start_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_start_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_logoff_flood": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eapol_logoff_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_logoff_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_succ_flood": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eapol_succ_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_succ_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_fail_flood": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eapol_fail_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_fail_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_pre_succ_flood": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eapol_pre_succ_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_pre_succ_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_pre_fail_flood": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eapol_pre_fail_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eapol_pre_fail_intv": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "deauth_unknown_src_thresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "windows_bridge": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "disassoc_broadcast": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ap_spoofing": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "chan_based_mitm": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "adhoc_valid_ssid": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "adhoc_network": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "eapol_key_overflow": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ap_impersonation": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "invalid_addr_combination": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "beacon_wrong_channel": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ht_greenfield": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "overflow_ie": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "malformed_ht_ie": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "malformed_auth": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "malformed_association": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ht_40mhz_intolerance": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "valid_ssid_misuse": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "valid_client_misassociation": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "hotspotter_attack": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pwsave_dos_attack": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "omerta_attack": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "disconnect_station": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "unencrypted_valid": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fata_jack": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "risky_encryption": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fuzzed_beacon": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fuzzed_probe_request": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fuzzed_probe_response": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "air_jack": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wpa_ft_attack": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ap_bgscan_disable_day": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [
                {"value": "sunday"},
                {"value": "monday"},
                {"value": "tuesday"},
                {"value": "wednesday"},
                {"value": "thursday"},
                {"value": "friday"},
                {"value": "saturday"},
            ],
        },
        "ap_bgscan_disable_start": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
        },
        "ap_bgscan_disable_end": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
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
        "wireless_controller_wids_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_wids_profile"]["options"][attribute_name] = (
            module_spec["options"][attribute_name]
        )
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_wids_profile"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_wids_profile"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller(
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
