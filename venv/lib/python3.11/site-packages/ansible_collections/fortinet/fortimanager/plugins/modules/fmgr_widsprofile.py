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
module: fmgr_widsprofile
short_description: Configure wireless intrusion detection system
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
    widsprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ap_auto_suppress:
                aliases: ['ap-auto-suppress']
                type: str
                description: Enable/disable on-wire rogue AP auto-suppression
                choices:
                    - 'disable'
                    - 'enable'
            ap_bgscan_disable_day:
                aliases: ['ap-bgscan-disable-day']
                type: list
                elements: str
                description: Optionally turn off scanning for one or more days of the week.
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            ap_bgscan_disable_end:
                aliases: ['ap-bgscan-disable-end']
                type: str
                description: End time, using a 24-hour clock in the format of hh
            ap_bgscan_disable_start:
                aliases: ['ap-bgscan-disable-start']
                type: str
                description: Start time, using a 24-hour clock in the format of hh
            ap_bgscan_duration:
                aliases: ['ap-bgscan-duration']
                type: int
                description: Listening time on a scanning channel
            ap_bgscan_idle:
                aliases: ['ap-bgscan-idle']
                type: int
                description: Waiting time for channel inactivity before scanning this channel
            ap_bgscan_intv:
                aliases: ['ap-bgscan-intv']
                type: int
                description: Period of time between scanning two channels
            ap_bgscan_period:
                aliases: ['ap-bgscan-period']
                type: int
                description: Period of time between background scans
            ap_bgscan_report_intv:
                aliases: ['ap-bgscan-report-intv']
                type: int
                description: Period of time between background scan reports
            ap_fgscan_report_intv:
                aliases: ['ap-fgscan-report-intv']
                type: int
                description: Period of time between foreground scan reports
            ap_scan:
                aliases: ['ap-scan']
                type: str
                description: Enable/disable rogue AP detection.
                choices:
                    - 'disable'
                    - 'enable'
            ap_scan_passive:
                aliases: ['ap-scan-passive']
                type: str
                description: Enable/disable passive scanning.
                choices:
                    - 'disable'
                    - 'enable'
            asleap_attack:
                aliases: ['asleap-attack']
                type: str
                description: Enable/disable asleap attack detection
                choices:
                    - 'disable'
                    - 'enable'
            assoc_flood_thresh:
                aliases: ['assoc-flood-thresh']
                type: int
                description: The threshold value for association frame flooding.
            assoc_flood_time:
                aliases: ['assoc-flood-time']
                type: int
                description: Number of seconds after which a station is considered not connected.
            assoc_frame_flood:
                aliases: ['assoc-frame-flood']
                type: str
                description: Enable/disable association frame flooding detection
                choices:
                    - 'disable'
                    - 'enable'
            auth_flood_thresh:
                aliases: ['auth-flood-thresh']
                type: int
                description: The threshold value for authentication frame flooding.
            auth_flood_time:
                aliases: ['auth-flood-time']
                type: int
                description: Number of seconds after which a station is considered not connected.
            auth_frame_flood:
                aliases: ['auth-frame-flood']
                type: str
                description: Enable/disable authentication frame flooding detection
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            deauth_broadcast:
                aliases: ['deauth-broadcast']
                type: str
                description: Enable/disable broadcasting de-authentication detection
                choices:
                    - 'disable'
                    - 'enable'
            deauth_unknown_src_thresh:
                aliases: ['deauth-unknown-src-thresh']
                type: int
                description: Threshold value per second to deauth unknown src for DoS attack
            eapol_fail_flood:
                aliases: ['eapol-fail-flood']
                type: str
                description: Enable/disable EAPOL-Failure flooding
                choices:
                    - 'disable'
                    - 'enable'
            eapol_fail_intv:
                aliases: ['eapol-fail-intv']
                type: int
                description: The detection interval for EAPOL-Failure flooding
            eapol_fail_thresh:
                aliases: ['eapol-fail-thresh']
                type: int
                description: The threshold value for EAPOL-Failure flooding in specified interval.
            eapol_logoff_flood:
                aliases: ['eapol-logoff-flood']
                type: str
                description: Enable/disable EAPOL-Logoff flooding
                choices:
                    - 'disable'
                    - 'enable'
            eapol_logoff_intv:
                aliases: ['eapol-logoff-intv']
                type: int
                description: The detection interval for EAPOL-Logoff flooding
            eapol_logoff_thresh:
                aliases: ['eapol-logoff-thresh']
                type: int
                description: The threshold value for EAPOL-Logoff flooding in specified interval.
            eapol_pre_fail_flood:
                aliases: ['eapol-pre-fail-flood']
                type: str
                description: Enable/disable premature EAPOL-Failure flooding
                choices:
                    - 'disable'
                    - 'enable'
            eapol_pre_fail_intv:
                aliases: ['eapol-pre-fail-intv']
                type: int
                description: The detection interval for premature EAPOL-Failure flooding
            eapol_pre_fail_thresh:
                aliases: ['eapol-pre-fail-thresh']
                type: int
                description: The threshold value for premature EAPOL-Failure flooding in specified interval.
            eapol_pre_succ_flood:
                aliases: ['eapol-pre-succ-flood']
                type: str
                description: Enable/disable premature EAPOL-Success flooding
                choices:
                    - 'disable'
                    - 'enable'
            eapol_pre_succ_intv:
                aliases: ['eapol-pre-succ-intv']
                type: int
                description: The detection interval for premature EAPOL-Success flooding
            eapol_pre_succ_thresh:
                aliases: ['eapol-pre-succ-thresh']
                type: int
                description: The threshold value for premature EAPOL-Success flooding in specified interval.
            eapol_start_flood:
                aliases: ['eapol-start-flood']
                type: str
                description: Enable/disable EAPOL-Start flooding
                choices:
                    - 'disable'
                    - 'enable'
            eapol_start_intv:
                aliases: ['eapol-start-intv']
                type: int
                description: The detection interval for EAPOL-Start flooding
            eapol_start_thresh:
                aliases: ['eapol-start-thresh']
                type: int
                description: The threshold value for EAPOL-Start flooding in specified interval.
            eapol_succ_flood:
                aliases: ['eapol-succ-flood']
                type: str
                description: Enable/disable EAPOL-Success flooding
                choices:
                    - 'disable'
                    - 'enable'
            eapol_succ_intv:
                aliases: ['eapol-succ-intv']
                type: int
                description: The detection interval for EAPOL-Success flooding
            eapol_succ_thresh:
                aliases: ['eapol-succ-thresh']
                type: int
                description: The threshold value for EAPOL-Success flooding in specified interval.
            invalid_mac_oui:
                aliases: ['invalid-mac-oui']
                type: str
                description: Enable/disable invalid MAC OUI detection.
                choices:
                    - 'disable'
                    - 'enable'
            long_duration_attack:
                aliases: ['long-duration-attack']
                type: str
                description: Enable/disable long duration attack detection based on user configured threshold
                choices:
                    - 'disable'
                    - 'enable'
            long_duration_thresh:
                aliases: ['long-duration-thresh']
                type: int
                description: Threshold value for long duration attack detection
            name:
                type: str
                description: WIDS profile name.
                required: true
            null_ssid_probe_resp:
                aliases: ['null-ssid-probe-resp']
                type: str
                description: Enable/disable null SSID probe response detection
                choices:
                    - 'disable'
                    - 'enable'
            sensor_mode:
                aliases: ['sensor-mode']
                type: str
                description: Scan WiFi nearby stations
                choices:
                    - 'disable'
                    - 'foreign'
                    - 'both'
            spoofed_deauth:
                aliases: ['spoofed-deauth']
                type: str
                description: Enable/disable spoofed de-authentication attack detection
                choices:
                    - 'disable'
                    - 'enable'
            weak_wep_iv:
                aliases: ['weak-wep-iv']
                type: str
                description: Enable/disable weak WEP IV
                choices:
                    - 'disable'
                    - 'enable'
            wireless_bridge:
                aliases: ['wireless-bridge']
                type: str
                description: Enable/disable wireless bridge detection
                choices:
                    - 'disable'
                    - 'enable'
            ap_bgscan_disable_schedules:
                aliases: ['ap-bgscan-disable-schedules']
                type: raw
                description: (list or str) Firewall schedules for turning off FortiAP radio background scan.
            rogue_scan:
                aliases: ['rogue-scan']
                type: str
                description: Enable/disable rogue AP on-wire scan.
                choices:
                    - 'disable'
                    - 'enable'
            ap_scan_threshold:
                aliases: ['ap-scan-threshold']
                type: str
                description: Minimum signal level/threshold in dBm required for the AP to report detected rogue AP
            ap_scan_channel_list_2G_5G:
                aliases: ['ap-scan-channel-list-2G-5G']
                type: raw
                description: (list) Selected ap scan channel list for 2.
            ap_scan_channel_list_6G:
                aliases: ['ap-scan-channel-list-6G']
                type: raw
                description: (list) Selected ap scan channel list for 6G band.
            adhoc_network:
                aliases: ['adhoc-network']
                type: str
                description: Enable/disable adhoc network detection
                choices:
                    - 'disable'
                    - 'enable'
            adhoc_valid_ssid:
                aliases: ['adhoc-valid-ssid']
                type: str
                description: Enable/disable adhoc using valid SSID detection
                choices:
                    - 'disable'
                    - 'enable'
            air_jack:
                aliases: ['air-jack']
                type: str
                description: Enable/disable AirJack detection
                choices:
                    - 'disable'
                    - 'enable'
            ap_impersonation:
                aliases: ['ap-impersonation']
                type: str
                description: Enable/disable AP impersonation detection
                choices:
                    - 'disable'
                    - 'enable'
            ap_spoofing:
                aliases: ['ap-spoofing']
                type: str
                description: Enable/disable AP spoofing detection
                choices:
                    - 'disable'
                    - 'enable'
            bcn_flood:
                aliases: ['bcn-flood']
                type: str
                description: Enable/disable bcn flood detection
                choices:
                    - 'disable'
                    - 'enable'
            bcn_flood_thresh:
                aliases: ['bcn-flood-thresh']
                type: int
                description: The threshold value for bcn flood.
            bcn_flood_time:
                aliases: ['bcn-flood-time']
                type: int
                description: Detection Window Period.
            beacon_wrong_channel:
                aliases: ['beacon-wrong-channel']
                type: str
                description: Enable/disable beacon wrong channel detection
                choices:
                    - 'disable'
                    - 'enable'
            block_ack_flood:
                aliases: ['block_ack-flood']
                type: str
                description: Enable/disable block_ack flood detection
                choices:
                    - 'disable'
                    - 'enable'
            block_ack_flood_thresh:
                aliases: ['block_ack-flood-thresh']
                type: int
                description: The threshold value for block_ack flood.
            block_ack_flood_time:
                aliases: ['block_ack-flood-time']
                type: int
                description: Detection Window Period.
            chan_based_mitm:
                aliases: ['chan-based-mitm']
                type: str
                description: Enable/disable channel based mitm detection
                choices:
                    - 'disable'
                    - 'enable'
            client_flood:
                aliases: ['client-flood']
                type: str
                description: Enable/disable client flood detection
                choices:
                    - 'disable'
                    - 'enable'
            client_flood_thresh:
                aliases: ['client-flood-thresh']
                type: int
                description: The threshold value for client flood.
            client_flood_time:
                aliases: ['client-flood-time']
                type: int
                description: Detection Window Period.
            cts_flood:
                aliases: ['cts-flood']
                type: str
                description: Enable/disable cts flood detection
                choices:
                    - 'disable'
                    - 'enable'
            cts_flood_thresh:
                aliases: ['cts-flood-thresh']
                type: int
                description: The threshold value for cts flood.
            cts_flood_time:
                aliases: ['cts-flood-time']
                type: int
                description: Detection Window Period.
            disassoc_broadcast:
                aliases: ['disassoc-broadcast']
                type: str
                description: Enable/disable broadcast dis-association detection
                choices:
                    - 'disable'
                    - 'enable'
            disconnect_station:
                aliases: ['disconnect-station']
                type: str
                description: Enable/disable disconnect station detection
                choices:
                    - 'disable'
                    - 'enable'
            eapol_key_overflow:
                aliases: ['eapol-key-overflow']
                type: str
                description: Enable/disable overflow EAPOL key detection
                choices:
                    - 'disable'
                    - 'enable'
            fata_jack:
                aliases: ['fata-jack']
                type: str
                description: Enable/disable FATA-Jack detection
                choices:
                    - 'disable'
                    - 'enable'
            fuzzed_beacon:
                aliases: ['fuzzed-beacon']
                type: str
                description: Enable/disable fuzzed beacon detection
                choices:
                    - 'disable'
                    - 'enable'
            fuzzed_probe_request:
                aliases: ['fuzzed-probe-request']
                type: str
                description: Enable/disable fuzzed probe request detection
                choices:
                    - 'disable'
                    - 'enable'
            fuzzed_probe_response:
                aliases: ['fuzzed-probe-response']
                type: str
                description: Enable/disable fuzzed probe response detection
                choices:
                    - 'disable'
                    - 'enable'
            hotspotter_attack:
                aliases: ['hotspotter-attack']
                type: str
                description: Enable/disable hotspotter attack detection
                choices:
                    - 'disable'
                    - 'enable'
            ht_40mhz_intolerance:
                aliases: ['ht-40mhz-intolerance']
                type: str
                description: Enable/disable HT 40 MHz intolerance detection
                choices:
                    - 'disable'
                    - 'enable'
            ht_greenfield:
                aliases: ['ht-greenfield']
                type: str
                description: Enable/disable HT greenfield detection
                choices:
                    - 'disable'
                    - 'enable'
            invalid_addr_combination:
                aliases: ['invalid-addr-combination']
                type: str
                description: Enable/disable invalid address combination detection
                choices:
                    - 'disable'
                    - 'enable'
            malformed_association:
                aliases: ['malformed-association']
                type: str
                description: Enable/disable malformed association request detection
                choices:
                    - 'disable'
                    - 'enable'
            malformed_auth:
                aliases: ['malformed-auth']
                type: str
                description: Enable/disable malformed auth frame detection
                choices:
                    - 'disable'
                    - 'enable'
            malformed_ht_ie:
                aliases: ['malformed-ht-ie']
                type: str
                description: Enable/disable malformed HT IE detection
                choices:
                    - 'disable'
                    - 'enable'
            netstumbler:
                type: str
                description: Enable/disable netstumbler detection
                choices:
                    - 'disable'
                    - 'enable'
            netstumbler_thresh:
                aliases: ['netstumbler-thresh']
                type: int
                description: The threshold value for netstumbler.
            netstumbler_time:
                aliases: ['netstumbler-time']
                type: int
                description: Detection Window Period.
            omerta_attack:
                aliases: ['omerta-attack']
                type: str
                description: Enable/disable omerta attack detection
                choices:
                    - 'disable'
                    - 'enable'
            overflow_ie:
                aliases: ['overflow-ie']
                type: str
                description: Enable/disable overflow IE detection
                choices:
                    - 'disable'
                    - 'enable'
            probe_flood:
                aliases: ['probe-flood']
                type: str
                description: Enable/disable probe flood detection
                choices:
                    - 'disable'
                    - 'enable'
            probe_flood_thresh:
                aliases: ['probe-flood-thresh']
                type: int
                description: The threshold value for probe flood.
            probe_flood_time:
                aliases: ['probe-flood-time']
                type: int
                description: Detection Window Period.
            pspoll_flood:
                aliases: ['pspoll-flood']
                type: str
                description: Enable/disable pspoll flood detection
                choices:
                    - 'disable'
                    - 'enable'
            pspoll_flood_thresh:
                aliases: ['pspoll-flood-thresh']
                type: int
                description: The threshold value for pspoll flood.
            pspoll_flood_time:
                aliases: ['pspoll-flood-time']
                type: int
                description: Detection Window Period.
            pwsave_dos_attack:
                aliases: ['pwsave-dos-attack']
                type: str
                description: Enable/disable power save DOS attack detection
                choices:
                    - 'disable'
                    - 'enable'
            reassoc_flood:
                aliases: ['reassoc-flood']
                type: str
                description: Enable/disable reassociation flood detection
                choices:
                    - 'disable'
                    - 'enable'
            reassoc_flood_thresh:
                aliases: ['reassoc-flood-thresh']
                type: int
                description: The threshold value for reassociation flood.
            reassoc_flood_time:
                aliases: ['reassoc-flood-time']
                type: int
                description: Detection Window Period.
            risky_encryption:
                aliases: ['risky-encryption']
                type: str
                description: Enable/disable Risky Encryption detection
                choices:
                    - 'disable'
                    - 'enable'
            rts_flood:
                aliases: ['rts-flood']
                type: str
                description: Enable/disable rts flood detection
                choices:
                    - 'disable'
                    - 'enable'
            rts_flood_thresh:
                aliases: ['rts-flood-thresh']
                type: int
                description: The threshold value for rts flood.
            rts_flood_time:
                aliases: ['rts-flood-time']
                type: int
                description: Detection Window Period.
            unencrypted_valid:
                aliases: ['unencrypted-valid']
                type: str
                description: Enable/disable unencrypted valid detection
                choices:
                    - 'disable'
                    - 'enable'
            valid_client_misassociation:
                aliases: ['valid-client-misassociation']
                type: str
                description: Enable/disable valid client misassociation detection
                choices:
                    - 'disable'
                    - 'enable'
            valid_ssid_misuse:
                aliases: ['valid-ssid-misuse']
                type: str
                description: Enable/disable valid SSID misuse detection
                choices:
                    - 'disable'
                    - 'enable'
            wellenreiter:
                type: str
                description: Enable/disable wellenreiter detection
                choices:
                    - 'disable'
                    - 'enable'
            wellenreiter_thresh:
                aliases: ['wellenreiter-thresh']
                type: int
                description: The threshold value for wellenreiter.
            wellenreiter_time:
                aliases: ['wellenreiter-time']
                type: int
                description: Detection Window Period.
            windows_bridge:
                aliases: ['windows-bridge']
                type: str
                description: Enable/disable windows bridge detection
                choices:
                    - 'disable'
                    - 'enable'
            wpa_ft_attack:
                aliases: ['wpa-ft-attack']
                type: str
                description: Enable/disable WPA FT attack detection
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure wireless intrusion detection system
      fortinet.fortimanager.fmgr_widsprofile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        widsprofile:
          name: "your value" # Required variable, string
          # ap_auto_suppress: <value in [disable, enable]>
          # ap_bgscan_disable_day:
          #   - "sunday"
          #   - "monday"
          #   - "tuesday"
          #   - "wednesday"
          #   - "thursday"
          #   - "friday"
          #   - "saturday"
          # ap_bgscan_disable_end: <string>
          # ap_bgscan_disable_start: <string>
          # ap_bgscan_duration: <integer>
          # ap_bgscan_idle: <integer>
          # ap_bgscan_intv: <integer>
          # ap_bgscan_period: <integer>
          # ap_bgscan_report_intv: <integer>
          # ap_fgscan_report_intv: <integer>
          # ap_scan: <value in [disable, enable]>
          # ap_scan_passive: <value in [disable, enable]>
          # asleap_attack: <value in [disable, enable]>
          # assoc_flood_thresh: <integer>
          # assoc_flood_time: <integer>
          # assoc_frame_flood: <value in [disable, enable]>
          # auth_flood_thresh: <integer>
          # auth_flood_time: <integer>
          # auth_frame_flood: <value in [disable, enable]>
          # comment: <string>
          # deauth_broadcast: <value in [disable, enable]>
          # deauth_unknown_src_thresh: <integer>
          # eapol_fail_flood: <value in [disable, enable]>
          # eapol_fail_intv: <integer>
          # eapol_fail_thresh: <integer>
          # eapol_logoff_flood: <value in [disable, enable]>
          # eapol_logoff_intv: <integer>
          # eapol_logoff_thresh: <integer>
          # eapol_pre_fail_flood: <value in [disable, enable]>
          # eapol_pre_fail_intv: <integer>
          # eapol_pre_fail_thresh: <integer>
          # eapol_pre_succ_flood: <value in [disable, enable]>
          # eapol_pre_succ_intv: <integer>
          # eapol_pre_succ_thresh: <integer>
          # eapol_start_flood: <value in [disable, enable]>
          # eapol_start_intv: <integer>
          # eapol_start_thresh: <integer>
          # eapol_succ_flood: <value in [disable, enable]>
          # eapol_succ_intv: <integer>
          # eapol_succ_thresh: <integer>
          # invalid_mac_oui: <value in [disable, enable]>
          # long_duration_attack: <value in [disable, enable]>
          # long_duration_thresh: <integer>
          # null_ssid_probe_resp: <value in [disable, enable]>
          # sensor_mode: <value in [disable, foreign, both]>
          # spoofed_deauth: <value in [disable, enable]>
          # weak_wep_iv: <value in [disable, enable]>
          # wireless_bridge: <value in [disable, enable]>
          # ap_bgscan_disable_schedules: <list or string>
          # rogue_scan: <value in [disable, enable]>
          # ap_scan_threshold: <string>
          # ap_scan_channel_list_2G_5G: <list or string>
          # ap_scan_channel_list_6G: <list or string>
          # adhoc_network: <value in [disable, enable]>
          # adhoc_valid_ssid: <value in [disable, enable]>
          # air_jack: <value in [disable, enable]>
          # ap_impersonation: <value in [disable, enable]>
          # ap_spoofing: <value in [disable, enable]>
          # bcn_flood: <value in [disable, enable]>
          # bcn_flood_thresh: <integer>
          # bcn_flood_time: <integer>
          # beacon_wrong_channel: <value in [disable, enable]>
          # block_ack_flood: <value in [disable, enable]>
          # block_ack_flood_thresh: <integer>
          # block_ack_flood_time: <integer>
          # chan_based_mitm: <value in [disable, enable]>
          # client_flood: <value in [disable, enable]>
          # client_flood_thresh: <integer>
          # client_flood_time: <integer>
          # cts_flood: <value in [disable, enable]>
          # cts_flood_thresh: <integer>
          # cts_flood_time: <integer>
          # disassoc_broadcast: <value in [disable, enable]>
          # disconnect_station: <value in [disable, enable]>
          # eapol_key_overflow: <value in [disable, enable]>
          # fata_jack: <value in [disable, enable]>
          # fuzzed_beacon: <value in [disable, enable]>
          # fuzzed_probe_request: <value in [disable, enable]>
          # fuzzed_probe_response: <value in [disable, enable]>
          # hotspotter_attack: <value in [disable, enable]>
          # ht_40mhz_intolerance: <value in [disable, enable]>
          # ht_greenfield: <value in [disable, enable]>
          # invalid_addr_combination: <value in [disable, enable]>
          # malformed_association: <value in [disable, enable]>
          # malformed_auth: <value in [disable, enable]>
          # malformed_ht_ie: <value in [disable, enable]>
          # netstumbler: <value in [disable, enable]>
          # netstumbler_thresh: <integer>
          # netstumbler_time: <integer>
          # omerta_attack: <value in [disable, enable]>
          # overflow_ie: <value in [disable, enable]>
          # probe_flood: <value in [disable, enable]>
          # probe_flood_thresh: <integer>
          # probe_flood_time: <integer>
          # pspoll_flood: <value in [disable, enable]>
          # pspoll_flood_thresh: <integer>
          # pspoll_flood_time: <integer>
          # pwsave_dos_attack: <value in [disable, enable]>
          # reassoc_flood: <value in [disable, enable]>
          # reassoc_flood_thresh: <integer>
          # reassoc_flood_time: <integer>
          # risky_encryption: <value in [disable, enable]>
          # rts_flood: <value in [disable, enable]>
          # rts_flood_thresh: <integer>
          # rts_flood_time: <integer>
          # unencrypted_valid: <value in [disable, enable]>
          # valid_client_misassociation: <value in [disable, enable]>
          # valid_ssid_misuse: <value in [disable, enable]>
          # wellenreiter: <value in [disable, enable]>
          # wellenreiter_thresh: <integer>
          # wellenreiter_time: <integer>
          # windows_bridge: <value in [disable, enable]>
          # wpa_ft_attack: <value in [disable, enable]>
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
        '/pm/config/adom/{adom}/obj/wireless-controller/wids-profile',
        '/pm/config/global/obj/wireless-controller/wids-profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'widsprofile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'ap-auto-suppress': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ap-bgscan-disable-day': {
                    'v_range': [['6.0.0', '7.2.1']],
                    'type': 'list',
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                    'elements': 'str'
                },
                'ap-bgscan-disable-end': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'ap-bgscan-disable-start': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'ap-bgscan-duration': {'type': 'int'},
                'ap-bgscan-idle': {'type': 'int'},
                'ap-bgscan-intv': {'type': 'int'},
                'ap-bgscan-period': {'type': 'int'},
                'ap-bgscan-report-intv': {'type': 'int'},
                'ap-fgscan-report-intv': {'type': 'int'},
                'ap-scan': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ap-scan-passive': {'choices': ['disable', 'enable'], 'type': 'str'},
                'asleap-attack': {'choices': ['disable', 'enable'], 'type': 'str'},
                'assoc-flood-thresh': {'type': 'int'},
                'assoc-flood-time': {'type': 'int'},
                'assoc-frame-flood': {'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-flood-thresh': {'type': 'int'},
                'auth-flood-time': {'type': 'int'},
                'auth-frame-flood': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'type': 'str'},
                'deauth-broadcast': {'choices': ['disable', 'enable'], 'type': 'str'},
                'deauth-unknown-src-thresh': {'type': 'int'},
                'eapol-fail-flood': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eapol-fail-intv': {'type': 'int'},
                'eapol-fail-thresh': {'type': 'int'},
                'eapol-logoff-flood': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eapol-logoff-intv': {'type': 'int'},
                'eapol-logoff-thresh': {'type': 'int'},
                'eapol-pre-fail-flood': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eapol-pre-fail-intv': {'type': 'int'},
                'eapol-pre-fail-thresh': {'type': 'int'},
                'eapol-pre-succ-flood': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eapol-pre-succ-intv': {'type': 'int'},
                'eapol-pre-succ-thresh': {'type': 'int'},
                'eapol-start-flood': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eapol-start-intv': {'type': 'int'},
                'eapol-start-thresh': {'type': 'int'},
                'eapol-succ-flood': {'choices': ['disable', 'enable'], 'type': 'str'},
                'eapol-succ-intv': {'type': 'int'},
                'eapol-succ-thresh': {'type': 'int'},
                'invalid-mac-oui': {'choices': ['disable', 'enable'], 'type': 'str'},
                'long-duration-attack': {'choices': ['disable', 'enable'], 'type': 'str'},
                'long-duration-thresh': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'null-ssid-probe-resp': {'choices': ['disable', 'enable'], 'type': 'str'},
                'sensor-mode': {'choices': ['disable', 'foreign', 'both'], 'type': 'str'},
                'spoofed-deauth': {'choices': ['disable', 'enable'], 'type': 'str'},
                'weak-wep-iv': {'choices': ['disable', 'enable'], 'type': 'str'},
                'wireless-bridge': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ap-bgscan-disable-schedules': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'rogue-scan': {'v_range': [['6.2.0', '6.2.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ap-scan-threshold': {'v_range': [['6.2.3', '']], 'type': 'str'},
                'ap-scan-channel-list-2G-5G': {'v_range': [['7.4.1', '']], 'type': 'raw'},
                'ap-scan-channel-list-6G': {'v_range': [['7.4.1', '']], 'type': 'raw'},
                'adhoc-network': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'adhoc-valid-ssid': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'air-jack': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ap-impersonation': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ap-spoofing': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bcn-flood': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bcn-flood-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'bcn-flood-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'beacon-wrong-channel': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'block_ack-flood': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'block_ack-flood-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'block_ack-flood-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'chan-based-mitm': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-flood': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-flood-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'client-flood-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'cts-flood': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cts-flood-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'cts-flood-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'disassoc-broadcast': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'disconnect-station': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eapol-key-overflow': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fata-jack': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fuzzed-beacon': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fuzzed-probe-request': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fuzzed-probe-response': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hotspotter-attack': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ht-40mhz-intolerance': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ht-greenfield': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'invalid-addr-combination': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'malformed-association': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'malformed-auth': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'malformed-ht-ie': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'netstumbler': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'netstumbler-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'netstumbler-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'omerta-attack': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'overflow-ie': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'probe-flood': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'probe-flood-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'probe-flood-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'pspoll-flood': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pspoll-flood-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'pspoll-flood-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'pwsave-dos-attack': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'reassoc-flood': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'reassoc-flood-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'reassoc-flood-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'risky-encryption': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rts-flood': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rts-flood-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'rts-flood-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'unencrypted-valid': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'valid-client-misassociation': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'valid-ssid-misuse': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wellenreiter': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wellenreiter-thresh': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'wellenreiter-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'windows-bridge': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wpa-ft-attack': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'widsprofile'),
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
