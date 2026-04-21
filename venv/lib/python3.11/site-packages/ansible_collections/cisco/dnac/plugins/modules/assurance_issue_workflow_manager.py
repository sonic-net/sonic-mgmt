#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to perform operations on Assurance issue settings in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["A Mohamed Rafeek, Megha Kandari, Madhan Sankaranarayanan"]

DOCUMENTATION = r"""
---
module: assurance_issue_workflow_manager
short_description: Resource module for managing assurance
  global profile settings and issue resolution in Cisco
  Catalyst Center
description:
  - This module allows the management of assurance global
    profile settings and issues in Cisco Catalyst Center.
  - It supports creating, updating, and deleting configurations
    for issue settings and issue resolution functionalities.
  - This module interacts with Cisco Catalyst Center's
    Assurance settings to configure thresholds, rules,
    KPIs, and more for issue settings and issue resolution.
  - The functionality for updating 'Global and Customized Settings',
    including custom profiles site assignment, is currently unavailable
    due to an API/SDK upgrade. It will be accessible under the
    'Network Assurance Profile Workflow Manager' once the updated API is released
version_added: '6.31.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - A Mohamed Rafeek (@mabdulk2)
  - Megha Kandari (@mekandar)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: >
      Set to `true` to enable configuration verification
      on Cisco Catalyst Center after applying the playbook
      config. This will ensure that the system validates
      the configuration state after the change is applied.
    type: bool
    default: false
  state:
    description: >
      Specifies the desired state for the configuration.
      If `merged`, the module will create or update
      the configuration, adding new settings or modifying
      existing ones. If `deleted`, it will remove the
      specified settings.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  config:
    description: >
      A list of settings and parameters to be applied.
      It consists of different sub-configurations for
      managing assurance settings such as issue settings,
      health score, ICAP settings, issue resolution,
      and command execution.
    type: list
    elements: dict
    required: true
    suboptions:
      assurance_user_defined_issue_settings:
        description: >
          Configures user-defined issue settings for
          assurance in Cisco Catalyst Center. Allows
          defining issue names, descriptions, severity,
          priority, and rules governing network issues.
        type: list
        elements: dict
        suboptions:
          name:
            description: >
              The name of the issue setting, used for
              identification in the system. Required
              when creating a new setting or updating
              an existing one.
            type: str
            required: true
          description:
            description: >
              A brief explanation of the issue for clarity
              in reports and dashboards.
            type: str
          rules:
            description: >
              A set of rules that define the parameters
              for triggering the issue. Includes severity,
              facility, mnemonic, pattern, occurrences,
              and duration.
            type: list
            elements: dict
            suboptions:
              severity:
                description: >
                  Specifies the severity level of the
                  issue. The severity value can be an
                  integer (0 to 6) or its corresponding
                  string representation.
                type: str
                choices:
                  - "0" # Emergency
                  - "1" # Alert
                  - "2" # Critical
                  - "3" # Error
                  - "4" # Warning
                  - "5" # Notice
                  - "6" # Info
                  - "Emergency"
                  - "Alert"
                  - "Critical"
                  - "Error"
                  - "Warning"
                  - "Notice"
                  - "Info"
              facility:
                description: >
                  The facility type that the rule applies
                  to.
                choices:
                  - CI
                  - PLATFORM_ENV
                  - PLATFORM_THERMAL
                  - PLATFORM_FEP
                  - ENVMON
                  - HARDWARE
                  - SYS
                  - ENVM
                  - PLATFORM
                  - CTS
                  - THERMAL
                  - SPA
                  - IOSXE_RP_ALARM
                  - ENVIRONMENT
                  - SPANTREE
                  - CMRP_ENVMON
                  - LISP
                  - PM
                  - UDLD
                  - IP
                  - SW_MATM
                  - CMRP_PFU
                  - C4K_IOSMODPORTMAN
                  - C6KENV
                  - MAC_MOVE
                  - OSP
                  - SFF8472
                  - DUAL
                  - DMI
                  - BGP
                  - REDUNDANCY
                  - IFDAMP
                  - CAPWAPAC_SMGR_TRACE_MESSAGE
                  - OSPF
                  - DOT1X
                  - ILPOWER
                  - IOSXE_OIR
                  - TRANSCEIVER
                  - SMART_LIC
                  - STANDBY
                  - IOSXE_PEM
                  - PLATFORM_STACKPOWER
                  - ENV_MON
                  - IOSXE_INFRA
                  - STACKMGR
                type: str
              mnemonic:
                description: >
                  A system-generated identifier or label
                  representing the issue.
                choices:
                  - SHUT_LC_FANGONE #facility :CI
                  - SHUTFANGONE #facility :CI
                  - SHUTFANFAIL #facility :CI
                  - SHUT_LC_FANFAIL #facility :CI
                  - FRU_PS_FAN_FAILED #facility :PLATFORM_ENV
                  - RPS_FAN_FAILED #facility :PLATFORM_ENV, ENVMON
                  - FRU_PS_FAN_OK #facility :PLATFORM_ENV
                  - FAN #facility :PLATFORM_ENV, ENVIRONMENT
                  - FAN_NOT_PRESENT #facility :PLATFORM_ENV
                  - FRU_FAN_OK #facility :PLATFORM_ENV
                  - PLATFORM_FAN_CRITICAL #facility :PLATFORM_ENV
                  - RPS_PS_FAN_FAILED #facility :PLATFORM_ENV, PLATFORM_THERMAL
                  - FRU_FAN_FAILURE #facility :PLATFORM_THERMAL
                  - FRU_FAN_RECOVERY #facility :PLATFORM_THERMAL
                  - FAN_CRITICAL #facility :PLATFORM_THERMAL
                  - FRU_FAN_NOT_PRESENT #facility :PLATFORM_THERMAL
                  - FRU_FAN_DISABLED #facility :PLATFORM_THERMAL
                  - FRU_FAN_INSUFFICIENTFANTRAYSDETECTEDPOWERDOWN #facility :PLATFORM_THERMAL
                  - FRU_PS_SIGNAL_FAULTY #facility :PLATFORM_FEP
                  - FAN_FAILURE_LC_SHUT #facility :CI
                  - FAN_MISSING #facility :CI
                  - TOTALFANFAIL #facility :CI
                  - NOFAN #facility :CI
                  - THERMAL_CRITICAL #facility :HARDWARE
                  - OVERTEMP #facility :SYS
                  - OVERTEMP_ALERT #facility :ENVM
                  - PFM_ALERT #facility :PLATFORM
                  - PFU_FAN_FAILED #facility :CMRP_PFU
                  - MODULECRITICALTEMP #facility :C4K_IOSMODPORTMAN
                  - CRITICALTEMP #facility :C4K_IOSMODPORTMAN
                  - AUTHZ_POLICY_SGACL_ACE_FAILED #facility :CTS
                  - THERMAL_YELLOW_THRESHOLD #facility :THERMAL
                  - THERMAL_RED_THRESHOLD #facility :THERMAL
                  - TEMP_CRITICAL #facility :SPA
                  - PEM #facility :IOSXE_RP_ALARM
                  - FANOK #facility :EVN_MON, IOSXE_PEM
                  - FAN_FAULT #facility :ENVIRONMENT
                  - PS_RED_MODE_CHG #facility :PLATFORM
                  - PS_FAIL #facility :PLATFORM
                  - PS_DETECT #facility :PLATFORM
                  - PS_ABSENT #facility :PLATFORM
                  - BLOCK_BPDUGUARD #facility :SPANTREE
                  - MAJORTEMPALARM #facility :C6KENV
                  - PEER_MONITOR #facility :REDUNDANCY
                  - SWITCHOVER #facility :REDUNDANCY
                  - STANDBY_LOST #facility :REDUNDANCY
                  - PARTIAL_FAN_FAIL #facility :CI
                  - PARTFANFAIL #facility :CI
                  - PSFANFAIL #facility :CI
                  - DUPADDR #facility :STANDBY
                  - PEMCHASFSERR #facility :IOSXE_PEM
                  - PEMFAIL #facility :IOSXE_PEM
                  - FAN_FAIL_SHUTDOWN #facility :IOSXE_PEM
                  - FANFAIL #facility :IOSXE_PEM
                  - TEMP_SYS_SHUTDOWN_PENDING #facility :CMRP_ENVMON
                  - TEMP_WARN_CRITICAL #facility :CMRP_ENVMON
                  - TEMP_FRU_SHUTDOWN_PENDING #facility :CMRP_ENVMON
                  - MAP_CACHE_WARNING_THRESHOLD_REACHED #facility :LISP
                  - LOCAL_EID_NO_ROUTE #facility :LISP
                  - LOCAL_EID_MAP_REGISTER_FAILURE #facility :LISP
                  - CEF_DISABLED #facility :LISP
                  - ERR_DISABLE #facility :PM
                  - UNDER_BUDGET #facility :PLATFORM_STACKPOWER
                  - VERSION_MISMATCH #facility :PLATFORM_STACKPOWER
                  - TOO_MANY_ERRORS #facility :PLATFORM_STACKPOWER
                  - INSUFFICIENT_PWR #facility :PLATFORM_STACKPOWER
                  - REDUNDANCY_LOSS #facility :PLATFORM_STACKPOWER
                  - UDLD_PORT_DISABLED #facility :UDLD
                  - DUPADDR #facility :IP
                  - MACFLAP_NOTIF #facility :SW_MATM
                  - PFU_FAN_WARN #facility :CMRP_PFU
                  - MODULETEMPHIGH #facility :C4K_IOSMODPORTMAN
                  - POWERSUPPLYBAD #facility :C4K_IOSMODPORTMAN
                  - CRITICALTEMP #facility :C4K_IOSMODPORTMAN
                  - MODULECRITICALTEMP #facility :C4K_IOSMODPORTMAN
                  - TEMPHIGH #facility :C4K_IOSMODPORTMAN
                  - FANTRAYREMOVED #facility :C4K_IOSMODPORTMAN
                  - TERMINATOR_PS_TEMP_MAJORALARM #facility :C6KENV
                  - NOTIF #facility :MAC_MOVE
                  - THRESHOLD_VIOLATION #facility :SFF8472
                  - NBRCHANGE #facility :DUAL
                  - SUCCESS #facility :DOT1X
                  - FAIL #facility :DOT1X
                  - SYNC_NEEDED #facility :DMI
                  - SYNC_START #facility :DMI
                  - ADJCHANGE #facility :BGP
                  - PEER_MONITOR_EVENT #facility :REDUNDANCY
                  - UPDOWN #facility :IFDAMP
                  - AP_JOIN_DISJOIN #facility :CAPWAPAC_SMGR_TRACE_MESSAGE
                  - ADJCHG #facility :OSPF
                  - ILPOWER_POWER_DENY #facility :ILPOWER
                  - REMSPA #facility :IOSXE_OIR
                  - INSSPA #facility :IOSXE_OIR
                  - OFFLINECARD #facility :IOSXE_OIR
                  - REMOVED #facility :TRANSCEIVER
                  - INSERTED #facility :TRANSCEIVER
                  - AGENT_READY #facility :SMART_LIC
                  - HA_ROLE_CHANGED #facility :SMART_LIC
                  - AGENT_ENABLED #facility :SMART_LIC
                  - STATECHANGE #facility :STANDBY
                  - REMPEM_FM #facility :IOSXE_PEM
                  - PEMOK #facility :IOSXE_PEM
                  - CABLE_EVENT #facility :PLATFORM_STACKPOWER
                  - LINK_EVENT #facility :PLATFORM_STACKPOWER
                  - REMPEM #facility :ENV_MON
                  - HASTATUS_DETAIL #facility :PLATFORM
                  - HASTATUS #facility :PLATFORM
                  - PROCPATH_CLIENT_HOG #facility :IOSXE_INFRA
                  - STACK_LINK_CHANGE #facility :STACKMGR
                type: str
              pattern:
                description: >
                  A pattern or regular expression defining
                  the issue detection criteria.
                type: str
              occurrences:
                description: >
                  The number of times the issue pattern
                  must occur before triggering the issue.
                type: int
              duration_in_minutes:
                description: >
                  The duration, in minutes, for which
                  the issue pattern must persist to
                  be considered valid.
                type: int
          is_enabled:
            description: >
              Enables or disables the issue setting.
            type: bool
          priority:
            description: >
              Specifies the priority of the issue.
            choices: [P1, P2, P3, P4]
            type: str
          is_notification_enabled:
            description: >
              Boolean value to specify if notifications
              for this issue setting should be enabled.
            type: bool
          prev_name:
            description: >
              The previous name of the issue setting
              (used when updating an existing issue
              setting).
            type: str
      assurance_system_issue_settings:
        description: >
          Manages system issue settings for assurance
          in Cisco Catalyst Center.
        type: list
        elements: dict
        suboptions:
          name:
            description: >
              The name of the system issue setting,
              used to identify the configuration in
              the system. Required when creating or
              updating an issue setting.
            type: str
            required: true
          description:
            description: >
              Provides a detailed explanation of the
              system issue setting, including the specific
              threshold fields that require updates
              for the defined issue names. This field
              is essential for understanding which parameters
              need adjustment to align with the current
              system configurations and alerting criteria.
            type: str
            required: true
          device_type:
            description: >
              Specifies the type of device to which
              the issue configuration applies. For example,
              choices: - ROUTER - SWITCH_AND_HUB - UNIFIED_AP
              - WIRELESS_CLIENT - WIRED_CLIENT - WIRELESS_CONTROLLER
              - THIRD_PARTY_DEVICE - APPLICATION - SENSOR
            type: str
            required: true
          synchronize_to_health_threshold:
            description: >
              A boolean value indicating whether the
              system issue should be synchronized to
              the health threshold. Accepts "true" or
              "false".
            type: bool
            required: false
          priority:
            description: >
              Specifies the priority level of the issue.
            type: str
            choices: [P1, P2, P3, P4]
            required: true
          issue_enabled:
            description: >
              A boolean value that determines whether
              the issue is enabled or disabled. Accepts
              "true" or "false".
            type: bool
            required: true
          threshold_value:
            description: >
              The threshold value that triggers the
              issue. This is usually specified as a
              percentage or a numerical value depending
              on the nature of the issue. For example,
              for the issue "Wireless client exhibiting
              sticky behavior," the threshold could
              be a maximum RSSI value (e.g., -70 dBm).
              Similarly, for a "WLC Memory High Utilization",
              a threshold like 90% can be used. - **Percentage-based
              thresholds**: Must not exceed 100%. -
              **dBm (decibel-milliwatts) thresholds**:
              Must not exceed 0 dBm, meaning it should
              be a negative value.
            type: int
            required: false
      assurance_issue:
        description: >
          Allow to resolve, ignore, or execute commands
          based on the issue settings assurance in Cisco
          Catalyst Center.
        type: list
        elements: dict
        suboptions:
          issue_name:
            description: >
              The name of the issue to be processed
              (either resolved, ignored, or command
              executed). This field is required when
              creating or updating an issue.
            type: str
            required: true
          issue_process_type:
            description: >
              Defines the action to be taken on the
              issue. Possible values:
                resolution:
              Resolves the issue.
                ignore:
              Ignores the issue.
                command_execution:
              Executes commands to address the issue.
            type: str
            required: true
          ignore_duration:
            description: >
                Specifies how long to ignore the issue. The value is a string with a numeric
                value followed by a time unit suffix. Supported units:
                - 'h' for hours (e.g., '1h' for 1 hour, '24h' for 24 hours).
                - 'd' for days (e.g., '3d' for 3 days, '30d' for 30 days).
                The range is from '1h' to '30d'. The default value is '24h'.
                This parameter is available from Cisco Catalyst Center version 2.3.7.10 onwards.
                Example valid values: '1h', '3d', '24h'.
                Example invalid values: '24', '3days', 'h3', '0h', '31d', '2.5h'.
            type: str
            required: false
            default: 24h
          start_datetime:
            description: >
              A filter to select issues that started
              at or after this date and time. The format
              is "YYYY-MM-DD HH:MM:SS".
            type: str
            required: false
          end_datetime:
            description: >
              A filter to select issues that ended at
              or before this date and time. The format
              is "YYYY-MM-DD HH:MM:SS".
            type: str
            required: false
          site_hierarchy:
            description: >
              A filter to select issues based on the
              site location hierarchy. The format is
              "Global/Region/Location/Building", where
              each level is separated by a slash.
            type: str
            required: false
          priority:
            description: >
              A filter to select issues based on their
              priority. Acceptable values are:
                - P1 (Highest
              Priority)
                - P2
                - P3
                - P4 (Lowest
              Priority) type: str required: false
          issue_status:
            description: >
              A filter to select issues based on their
              status. Acceptable values are:
                ACTIVE:
              The issue is currently open.
                RESOLVED:
              The issue has been resolved.
                IGNORED:
              The issue has been ignored. type: str
              required: false
          device_name:
            description: >
              A filter to select issues based on the
              device name that is associated with the
              issue (e.g., `NY-EN-9300.cisco.local`).
            type: str
            required: false
          mac_address:
            description: >
              A filter to select issues based on the
              MAC address of the device associated with
              the issue.
            type: str
            required: false
          network_device_ip_address:
            description: >
              A filter to select issues based on the
              network device's IP address associated
              with the issue.
            type: str
            required: false
requirements:
  - dnacentersdk >= 2.8.6
  - python >= 3.9
notes:
  - SDK Methods used are issues.AssuranceSettings.get_all_the_custom_issue_definitions_based_on_the_given_filters
    issues.AssuranceSettings.creates_a_new_user_defined_issue_definitions
    issues.AssuranceSettings.deletes_an_existing_custom_issue_definition
    issues.AssuranceSettings.resolve_the_given_lists_of_issues
    issues.AssuranceSettings.ignore_the_given_list_of_issues
    issues.AssuranceSettings.execute_suggested_action_commands
  - Paths used are
    POST /dna/intent/api/api/v1/customIssueDefinitions
    POST /dna/intent/api/v1/assuranceIssues/resolve
    POST /dna/intent/api/v1/execute-suggested-actions-commands
    POST /dna/intent/api/v1/assuranceIssues/ignore POST
    /dna/intent/api/v1/flow-analysis/${flowAnalysisId}
    POST /dna/intent/api/v1/flow-analysis PUT /dna/intent/api/v1/systemIssueDefinitions/${id}
    DELETE /dna/intent/api/v1/flow-analysis/{flowAnalysisId}
    DELETE /dna/intent/api/v1/customIssueDefinitions/{id}
"""
# Facility and mnemonic mappings for severities 3, 4, 5, and 6
facility_mnemonic_map = r"""
    # Severity 3 facilities and mnemonics
    3: {
        "SFF8472": ["THRESHOLD_VIOLATION"],
        "WLANMGR_TRACE_MESSAGE": ["EWLC_WLANMGR_SCHEDULED_WLAN_DISABLE", "EWLC_WLANMGR_SCHEDULED_WLAN_ENABLE"],
        "POWER_SUPPLIES": ["PWR_FAIL"],
        "CLIENT_ORCH_AUDIT_MESSAGE": ["FIPS_AUDIT_FTA_TSE1_DENY_CLIENT_ACCESS"],
        "BGP": ["NOTIFICATION"],
        "REDUNDANCY": ["PEER_MONITOR", "SWITCHOVER", "STANDBY_LOST"],
        "CI": ["PARTIAL_FAN_FAIL", "PARTFANFAIL", "PSFANFAIL"],
        "STANDBY": ["DUPADDR"],
        "IOSXE_PEM": ["PEMCHASFSERR", "PEMFAIL", "FAN_FAIL_SHUTDOWN", "FANFAIL"],
        "CMRP_ENVMON": ["TEMP_SYS_SHUTDOWN_PENDING", "TEMP_WARN_CRITICAL", "TEMP_FRU_SHUTDOWN_PENDING"],
        "CMRP": ["FAN_FAILURE_SYS_SHUTDOWN"],
        "CMRP_PFU": ["PWR_MGMT_ALARM", "PWR_MGMT_LC_SHUTDOWN"],
        "CTS": ["AUTHZ_POLICY_SGACL_ACE_FAILED",
                "SXP_CONN_STATE_CHG_OFF",
                "AUTHZ_POLICY_SGACL_FAILED",
                "AAA_NO_RADIUS_SERVER",
                "AUTHZ_ENTRY_RADIUS_FAILED",
                "PAC_PROVI_FAIL"
                ],
        "ENVIRONMENT": ["OVERTEMP"],
        "ENVM": ["FAN_FAILED", "FAN_OK_ERR", "FAN_FAILED_ERR", "FAN_ON", "FAN_RECOVERED", "FAN_SHUTDOWN_ERR"],
        "FAN": ["FAN_OK", "FAN_FAILED"],
        "HARDWARE": ["THERMAL_NOT_FUNCTIONING"],
        "ILPOWER": ["CONTROLLER_ERR", "CONTROLLER_PORT_ERR", "SHUT_OVERDRAWN"],
        "LINK": ["UPDOWN"],
        "PLATFORM_THERMAL": ["OVERTEMP"],
        "RMGR": ["RED_WLC_SWITCHOVER", "RED_HEARTBEAT_TMOUT"],
        "RADIUS": ["ALLDEADSERVER"],
        "RPS": ["FANOK, FANFAIL"],
        "RTT": ["IPSLATHRESHOLD"],
        "SYS": ["DISK_SPACE_ALMOST_FULL"]
            },
    # Severity 4 facilities and mnemonics
    4: {
        "LISP": [
            "MAP_CACHE_WARNING_THRESHOLD_REACHED",
            "LOCAL_EID_NO_ROUTE",
            "LOCAL_EID_MAP_REGISTER_FAILURE",
            "CEF_DISABLED",
            "LOCAL_EID_RLOC_INCONSISTENCY"
        ],
        "PM": ["ERR_DISABLE"],
        "PLATFORM_STACKPOWER": [
            "UNDER_BUDGET",
            "VERSION_MISMATCH",
            "TOO_MANY_ERRORS",
            "INSUFFICIENT_PWR",
            "REDUNDANCY_LOSS"
        ],
        "UDLD": ["UDLD_PORT_DISABLED"],
        "IP": ["DUPADDR"],
        "SW_MATM": ["MACFLAP_NOTIF"],
        "CMRP_PFU": ["PFU_FAN_WARN"],
        "C4K_IOSMODPORTMAN": [
            "MODULETEMPHIGH",
            "POWERSUPPLYBAD",
            "CRITICALTEMP",
            "MODULECRITICALTEMP",
            "TEMPHIGH",
            "FANTRAYREMOVED"
        ],
        "C6KENV": ["TERMINATOR_PS_TEMP_MAJORALARM"],
        "MAC_MOVE": ["NOTIF"],
        "ACL_ERRMSG": ["HASH_FULL"],
        "CDP": ["NATIVE_VLAN_MISMATCH", "DUPLEX_MISMATCH"],
        "MAC_LIMIT": ["PORT_EXCEED", "VLAN_EXCEED"],
        "MM": ["MEMBER_DOWN", "MEMBER_UP"],
        "PM-SP": ["ERR_DISABLE"],
        "RADIUS": ["RADIUS_DEAD", "RADIUS_ALIVE"],
        "REP": ["LINKSTATUS"],
        "RTT": ["OPER_TIMEOUT"]
    },
    # Severity 5 facilities and mnemonics
    5: {
        "SFF8472": ["THRESHOLD_VIOLATION"],
        "DUAL": ["NBRCHANGE"],
        "DMI": ["SYNC_NEEDED", "SYNC_START"],
        "BGP": ["ADJCHANGE"],
        "REDUNDANCY": ["PEER_MONITOR_EVENT"],
        "IFDAMP": ["UPDOWN"],
        "CAPWAPAC_SMGR_TRACE_MESSAGE": ["AP_JOIN_DISJOIN"],
        "OSPF": ["ADJCHG"],
        "DOT1X": ["SUCCESS", "FAIL"],
        "ILPOWER": ["ILPOWER_POWER_DENY"],
        "AUTHMGR": ["START", "SUCCESS"],
        "CLNS": ["ADJCHANGE"],
        "ENVIRONMENTAL": ["SENSOROK"],
        "LINEPROTO": ["SENSOROK"],
        "LINK": ["CHANGED"],
        "MAB": ["FAIL", "SUCCESS"],
        "PORT": ["IF_UP", "IF_DOWN"],
        "PLATFORM": ["HALF_DUPLEX"],
        "SYS": ["RESTART", "RELOAD", "CONFIG_I"],
        "SESSION_MGR": ["START", "SUCCESS"],
        "SPANTREE": ["ROOTCHANGE"]
    },
    # Severity 6 facilities and mnemonics
    6: {
        "IOSXE_OIR": ["REMSPA", "INSSPA", "OFFLINECARD"],
        "TRANSCEIVER": ["REMOVED", "INSERTED"],
        "SMART_LIC": ["AGENT_READY", "HA_ROLE_CHANGED", "AGENT_ENABLED"],
        "STANDBY": ["STATECHANGE"],
        "IOSXE_PEM": ["REMPEM_FM", "FANOK", "PEMOK"],
        "PLATFORM_STACKPOWER": ["CABLE_EVENT", "LINK_EVENT"],
        "ENV_MON": ["REMPEM"],
        "PLATFORM": ["HASTATUS_DETAIL", "HASTATUS"],
        "IOSXE_INFRA": ["PROCPATH_CLIENT_HOG"],
        "STACKMGR": ["STACK_LINK_CHANGE"],
        "CMRP_PFU": ["PWR_MGMT_OK"],
        "C4K_IOSMODPORTMAN": ["MODULEINSERTED",
                            "POWERSUPPLYGOOD",
                            "POWERSUPPLYFANGOOD",
                            "MODULEREMOVED",
                            "FANTRAYINSERTEDDETAILED",
                            "MODULEOFFLINE",
                            "MODULEONLINE"
                            ],
        "CMCC": ["MGMT_SFP_REMOVED", "MGMT_SFP_INSERT"],
        "FLASH": ["DEVICE_INSERTED"],
        "HA": ["SWITCHOVER"],
        "HA_CONFIG_SYNC": ["BULK_CFGSYNC_SUCCEED"],
        "IGMP": ["IGMP_GROUP_LIMIT"],
        "IOSXE_REDUNDANCY": ["PEER-LOST", "PEER"],
        "IOSD_INFRA": ["IFS_DEVICE_OIR"],
        "OIR": ["INSCARD", "REMCARD"],
        "PLATFORM": ["HASTATUS_DETAIL", "HASTATUS"],
        "PTP": ["GRANDMASTER_CLOCK_CHANGE"],
        "RBM": ["SGACLHIT"],
        "SISF": ["ENTRY_CREATED"],
        "SYS": ["INTF_STATUS_CHANGE"],
        "SPA_OIR": ["OFFLINECARD"]
    }
}
"""

EXAMPLES = r"""
---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Create issue settings
      cisco.dnac.assurance_issue_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_user_defined_issue_settings:
              - name: High CPU Usage Alert
                description: Triggers an alert when
                  CPU usage exceeds threshold
                rules:
                  - severity: Warning
                    facility: redundancy
                    mnemonic: peer monitor event
                    pattern: issue test
                    occurrences: 1
                    duration_in_minutes: 2
                is_enabled: false
                priority: P1
                is_notification_enabled: false
    - name: update issue settings
      cisco.dnac.assurance_issue_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_user_defined_issue_settings:
              - prev_name: High CPU Usage Alert
                name: Excessive CPU Utilization Alert
                description: testing
                rules:
                  - severity: "2"
                    facility: redundancy
                    mnemonic: peer monitor event
                    pattern: issue test
                    occurrences: 1
                    duration_in_minutes: 2
                is_enabled: false
                priority: P1
                is_notification_enabled: false
    - name: Delete issue settings
      cisco.dnac.assurance_issue_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: true
        state: deleted
        config_verify: true
        config:
          - assurance_user_defined_issue_settings:
              - name: High CPU Usage Alert
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Update System issue
      cisco.dnac.assurance_issue_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_system_issue_settings:
              - name: "Assurance telemetry status is
                  poor"
                description: RF Noise (5GHz)
                device_type: WIRED_CLIENT
                synchronize_to_health_threshold: true
                priority: P1
                issue_enabled: false
                threshold_value: -10
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Resolving Issues
      cisco.dnac.assurance_issue_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_issue:
              - issue_name: Fabric BGP session status
                  is down with Peer Device  # required field
                issue_process_type: resolution  # required field
                start_datetime: "2024-12-11 16:00:00"  # optional field
                end_datetime: "2024-12-11 18:30:00"  # optional field
                site_hierarchy: Global/USA/San Jose/BLDG23  # optional field
                device_name: NY-EN-9300.cisco.local  # optional field
                priority: P4  # optional field
                issue_status: ACTIVE  # optional field
                mac_address: e4:38:7e:42:bc:40  # optional field
                network_device_ip_address: 204.1.2.4  # optional field
    - name: Ignoring issues
      cisco.dnac.assurance_issue_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_issue:
              - issue_name: Fabric BGP session status
                  is down with Peer Device  # required field
                issue_process_type: ignore  # required field
                ignore_duration: 4h
                start_datetime: "2024-12-11 16:00:00"  # optional field
                end_datetime: "2024-12-11 18:30:00"  # optional field
                site_hierarchy: Global/USA/San Jose/BLDG23  # optional field
                device_name: NY-EN-9300.cisco.local  # optional field
                priority: P4  # optional field
                issue_status: ACTIVE  # optional field
                mac_address: e4:38:7e:42:bc:40  # optional field
                network_device_ip_address: 204.1.2.4  # optional field
    - name: Execute suggested commands
      cisco.dnac.assurance_issue_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_issue:
              - issue_name: Fabric BGP session status
                  is down with Peer Device  # required field
                issue_process_type: command_execution  # required field
                start_datetime: "2024-12-11 16:00:00"  # optional field
                end_datetime: "2024-12-11 18:30:00"  # optional field
                site_hierarchy: Global/USA/San Jose/BLDG23  # optional field
                device_name: NY-EN-9300.cisco.local  # optional field
                priority: P4  # optional field
                issue_status: ACTIVE  # optional field
                mac_address: e4:38:7e:42:bc:40  # optional field
                network_device_ip_address: 204.1.2.4  # optional field
"""


RETURN = r"""
#Case 1: Successful creation of issue
response_create:
  description: Details of the response returned by the assurance settings create API.
  returned: always
  type: dict
  sample: {
      "response": {
          "id": "string",
          "name": "string",
          "description": "string",
          "profileId": "string",
          "triggerId": "string",
          "rules": [
              {
                  "type": "string",
                  "severity": 1,
                  "facility": "string",
                  "mnemonic": "string",
                  "pattern": "string",
                  "occurrences": 3,
                  "durationInMinutes": 15
              }
          ],
          "isEnabled": true,
          "priority": "P1",
          "isDeletable": true,
          "isNotificationEnabled": true,
          "createdTime": 1672531200,
          "lastUpdatedTime": 1672617600
      }
  }
#Case 2: Successful updation of issue
response_update:
  description: Details of the response returned by the assurance settings update API.
  returned: always
  type: dict
  sample: {
      "response": {
          "id": "string",
          "name": "string",
          "description": "string",
          "profileId": "string",
          "triggerId": "string",
          "rules": [
              {
                  "type": "string",
                  "severity": 1,
                  "facility": "string",
                  "mnemonic": "string",
                  "pattern": "string",
                  "occurrences": 5,
                  "durationInMinutes": 10
              }
          ],
          "isEnabled": true,
          "priority": "P1",
          "isDeletable": true,
          "isNotificationEnabled": true,
          "createdTime": 1672531200,
          "lastUpdatedTime": 1672617600
      }
  }
#Case 3: Successfully Resolved issue
response_resolved:
  description: The response after resolving issues in Cisco Catalyst Center.
  returned: always
  type: dict
  sample: {
      "response": {
          "successfulIssueIds": [
              "string"
          ],
          "failureIssueIds": [
              "string"
          ]
      },
      "version": "string"
  }
#Case 4: Successfully ignored issue
Response_ignore:
  description: The response after ignoring issues in Cisco Catalyst Center.
  returned: always
  type: dict
  sample: {
      "response": {
          "successfulIssueIds": [
              "string"
          ],
          "failureIssueIds": [
              "string"
          ]
      },
      "version": "string"
  }
#Case 5: Successfully executed commands of issue
Response:
  description: The response object containing execution details of suggested action commands.
  returned: always
  type: list
  elements: dict
  sample: [
    {
    "executionId": "dbde5a27-c2aa-4045-ac5d-b0c216da7513",
    "executionStatusUrl": "/dna/intent/api/v1/dnacaap/management/execution-status/dbde5a27-c2aa-4045-ac5d-b0c216da7513",
    "message": "The request has been accepted for execution"
    }
  ]
#Case 6: Successfully updated System issue
response_update_system_issue:
  description: The response object containing detailed information about the issue or configuration.
  returned: always
  type: dict
  sample: {
      "response": {
          "id": "string",
          "name": "string",
          "displayName": "string",
          "description": "string",
          "priority": "string",
          "defaultPriority": "string",
          "deviceType": "string",
          "issueEnabled": "boolean",
          "profileId": "string",
          "definitionStatus": "string",
          "categoryName": "string",
          "synchronizeToHealthThreshold": "boolean",
          "thresholdValue": "number",
          "lastModified": "string"
      }
  }
"""

import re
import time
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
    validate_str,
)


class AssuranceSettings(DnacBase):
    """Class containing member attributes for Assurance setting workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = [
            {"assurance_user_defined_issue_settings": {"response": {}, "msg": {}}},
            {"assurance_system_issue_settings": {"response": {}, "msg": {}}},
        ]
        self.user_defined_issue_obj_params = self.assurance_obj_params(
            "assurance_user_defined_issue_settings"
        )
        self.system_issue_obj_params = self.assurance_obj_params(
            "assurance_system_issue_settings"
        )
        self.supported_states = ["merged", "deleted"]
        self.state = self.params.get("state")  # Store 'state' inside the class
        self.issue_resolved, self.issue_ignored, self.issues_active = [], [], []
        self.success_list_resolved, self.failed_list_resolved = [], []
        self.success_list_ignored, self.failed_list_ignored = [], []
        self.cmd_executed, self.cmd_not_executed, self.issue_processed = [], [], []
        self.no_issues = []
        self.keymap = dict(
            issue_name="name",
            start_datetime="start_time",
            end_datetime="end_time",
            site_hierarchy="site_id",
            device_id="device_id",
            mac_address="mac_address",
            issue_status="issue_status",
            network_device_ip_address="management_ip_address",
            device_name="hostname",
        )

    def validate_input(self):
        """
        Validates the configuration provided in the playbook against a predefined schema.

        Ensures that all required parameters are present and have valid data types and values.
        Updates the instance attributes based on the validation result.

        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
            The method updates these attributes of the instance:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation ('success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        """
        self.log(
            "Validating playbook configuration parameters: {0}".format(
                self.pprint(self.config)
            ),
            "DEBUG",
        )

        # Specification for validation
        validation_schema = {
            "assurance_user_defined_issue_settings": {
                "type": "list",
                "elements": "dict",
                "name": {"type": "str", "required": True},
                "description": {"type": "str"},
                "rules": {
                    "type": "list",
                    "elements": "dict",
                    "severity": {
                        "type": "int",
                        "choices": [0, 1, 2, 3, 4, 5, 6],
                        "required": True,
                    },
                    "facility": {"type": "str"},
                    "mnemonic": {"type": "str"},
                    "pattern": {"type": "str", "required": True},
                    "occurrences": {"type": "int"},
                    "duration_in_minutes": {"type": "int"},
                },
                "is_enabled": {"type": "bool", "default": True},
                "priority": {"type": "str", "choices": ["P1", "P2", "P3", "P4"]},
                "is_notification_enabled": {"type": "bool", "default": False},
                "prev_name": {"type": "str"},
            },
            "assurance_system_issue_settings": {
                "type": "list",
                "elements": "dict",
                "name": {"type": "str", "required": True},
                "description": {"type": "str"},
                "issue_enabled": {"type": "bool"},
                "device_type": {"type": "str", "required": True},
                "priority": {"type": "str", "choices": ["P1", "P2", "P3", "P4"]},
                "synchronize_to_health_threshold": {"type": "bool", "required": False},
                "threshold_value": {"type": int, "required": False},
            },
            "assurance_issue": {
                "type": "list",
                "elements": "dict",
                "issue_name": {"type": "str", "required": True},
                "issue_process_type": {
                    "type": "str",
                    "choices": ["resolution", "ignore", "command_execution"],
                    "required": True,
                },
                "ignore_duration": {"type": "str", "required": False},
                "start_datetime": {"type": "str", "required": False},
                "end_datetime": {"type": "str", "required": False},
                "site_hierarchy": {"type": "str", "required": False},
                "device_name": {"type": "str", "required": False},
                "priority": {
                    "type": "str",
                    "choices": ["P1", "P2", "P3", "P4"],
                    "required": False,
                },
                "issue_status": {
                    "type": "str",
                    "choices": ["ACTIVE", "RESOLVED", "IGNORED"],
                    "required": False,
                },
                "network_device_ip_address": {"type": "str", "required": False},
                "mac_address": {"type": "str", "required": False},
            },
        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        valid_temp, invalid_params = validate_list_of_dicts(
            self.config, validation_schema
        )

        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(
                invalid_params
            )
            self.result["response"] = self.msg
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_temp)
        )
        self.log(self.msg, "INFO")

        return self

    def input_data_validation(self, config):
        """
        Additional validation to check if the provided input assurance data is correct
        and as per the UI Cisco Catalyst Center.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            config (dict): Dictionary containing the input assurance details.

        Returns:
            self: The current instance of the class with logs validation errors and
                  updates the operation result if invalid data is found.

        Description:
            Iterates through the provided assurance data, validating field types, lengths,
            and expected values. If any validation errors are found, logs the errors, updates
            the operation result, and stops execution. Otherwise, it logs a success message.
        """
        self.log(
            "Validating assurance issue input data: {0}".format(self.pprint(config)),
            "DEBUG",
        )
        errormsg = []

        assurance_issue = config.get("assurance_issue")
        if assurance_issue:
            for each_issue in assurance_issue:
                issue_name = each_issue.get("issue_name")
                if issue_name:
                    param_spec = dict(type="str")
                    validate_str(issue_name, param_spec, "issue_name", errormsg)
                else:
                    errormsg.append("issue_name: Issue Name is missing in playbook.")

                issue_process_type = each_issue.get("issue_process_type")
                issue_type = ("resolution", "ignore", "command_execution")
                if issue_process_type:
                    if issue_process_type not in issue_type:
                        errormsg.append(
                            "issue_process_type: Invalid issue process type '{0}' in playbook. "
                            "Must be one of: {1}.".format(
                                issue_process_type, ", ".join(issue_type)
                            )
                        )
                else:
                    errormsg.append(
                        "issue_process_type: issue process type is missing in playbook."
                    )

                ignore_duration = each_issue.get("ignore_duration")
                if ignore_duration:
                    if not self.validate_ignore_duration(ignore_duration):
                        errormsg.append(
                            "ignore_duration: Invalid Ignore Duration '{0}' in playbook. "
                            "valid duration: '1h' to '30d'.".format(
                                ignore_duration))

                site_hierarchy = each_issue.get("site_hierarchy")
                if site_hierarchy:
                    param_spec = dict(type="str", length_max=300)
                    validate_str(site_hierarchy, param_spec, "site_hierarchy", errormsg)

                priority = each_issue.get("priority")
                priority_list = ("P1", "P2", "P3", "P4")
                if priority and priority not in priority_list:
                    errormsg.append(
                        "priority: Invalid Priority '{0}' in playbook. "
                        "Must be one of: {1}.".format(
                            priority, ", ".join(priority_list)
                        )
                    )

                issue_status = each_issue.get("issue_status")
                status_list = ("ACTIVE", "RESOLVED", "IGNORED")
                if issue_status and issue_status not in status_list:
                    errormsg.append(
                        "issue_status: Invalid issue status '{0}' in playbook. "
                        "Must be one of: {1}.".format(
                            issue_status, ", ".join(status_list)
                        )
                    )

                device_name = each_issue.get("device_name")
                if device_name:
                    param_spec = dict(type="str", length_max=200)
                    validate_str(device_name, param_spec, "device_name", errormsg)

                start_datetime = each_issue.get("start_datetime")
                end_datetime = each_issue.get("end_datetime")
                if start_datetime:
                    param_spec = dict(type="str", length_max=20)
                    validate_str(start_datetime, param_spec, "start_datetime", errormsg)

                if end_datetime:
                    param_spec = dict(type="str", length_max=20)
                    validate_str(end_datetime, param_spec, "end_datetime", errormsg)

                mac_address = each_issue.get("mac_address")
                if mac_address:
                    mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
                    if not mac_regex.match(mac_address):
                        errormsg.append(
                            "mac_address: Invalid MAC Address '{0}' in playbook.".format(
                                mac_address
                            )
                        )

                network_device_ip_address = each_issue.get("network_device_ip_address")
                if network_device_ip_address and (
                    not self.is_valid_ipv4(network_device_ip_address)
                    and not self.is_valid_ipv6(network_device_ip_address)
                ):
                    errormsg.append(
                        "network_device_ip_address: Invalid Network device IP Address '{0}'\
                        in playbook.".format(
                            network_device_ip_address
                        )
                    )

                if start_datetime and end_datetime:
                    validated_datetime = self.validate_start_end_datetime(
                        start_datetime, end_datetime, errormsg
                    )

                if site_hierarchy and (
                    device_name or mac_address or network_device_ip_address
                ):
                    errormsg.append(
                        "Provide either 'site_hierarchy' or one of 'device_name', "
                        + "'mac_address', or 'network_device_ip_address' — not both."
                    )

        execute_commands = config.get("assurance_execute_suggested_commands")
        if execute_commands:
            for each_commands in execute_commands:
                entity_type = each_commands.get("entity_type")
                if entity_type:
                    param_spec = dict(type="str", length_max=255)
                    validate_str(entity_type, param_spec, "entity_type", errormsg)
                else:
                    errormsg.append("entity_type: Entity Type is missing in playbook.")

                entity_value = each_commands.get("entity_value")
                if entity_value:
                    param_spec = dict(type="str", length_max=255)
                    validate_str(entity_value, param_spec, "entity_value", errormsg)
                else:
                    errormsg.append(
                        "entity_value: Entity Value is missing in playbook."
                    )

        # Facility and mnemonic mappings for severities 3, 4, 5, and 6
        facility_mnemonic_map = {
            # Severity 3 facilities and mnemonics
            3: {
                "SFF8472": ["THRESHOLD_VIOLATION"],
                "WLANMGR_TRACE_MESSAGE": [
                    "EWLC_WLANMGR_SCHEDULED_WLAN_DISABLE",
                    "EWLC_WLANMGR_SCHEDULED_WLAN_ENABLE",
                ],
                "POWER_SUPPLIES": ["PWR_FAIL"],
                "CLIENT_ORCH_AUDIT_MESSAGE": ["FIPS_AUDIT_FTA_TSE1_DENY_CLIENT_ACCESS"],
                "BGP": ["NOTIFICATION"],
                "REDUNDANCY": ["PEER_MONITOR", "SWITCHOVER", "STANDBY_LOST"],
                "CI": ["PARTIAL_FAN_FAIL", "PARTFANFAIL", "PSFANFAIL"],
                "STANDBY": ["DUPADDR"],
                "IOSXE_PEM": [
                    "PEMCHASFSERR",
                    "PEMFAIL",
                    "FAN_FAIL_SHUTDOWN",
                    "FANFAIL",
                ],
                "CMRP_ENVMON": [
                    "TEMP_SYS_SHUTDOWN_PENDING",
                    "TEMP_WARN_CRITICAL",
                    "TEMP_FRU_SHUTDOWN_PENDING",
                ],
                "CMRP": ["FAN_FAILURE_SYS_SHUTDOWN"],
                "CMRP_PFU": ["PWR_MGMT_ALARM", "PWR_MGMT_LC_SHUTDOWN"],
                "CTS": [
                    "AUTHZ_POLICY_SGACL_ACE_FAILED",
                    "SXP_CONN_STATE_CHG_OFF",
                    "AUTHZ_POLICY_SGACL_FAILED",
                    "AAA_NO_RADIUS_SERVER",
                    "AUTHZ_ENTRY_RADIUS_FAILED",
                    "PAC_PROVI_FAIL",
                ],
                "ENVIRONMENT": ["OVERTEMP"],
                "ENVM": [
                    "FAN_FAILED",
                    "FAN_OK_ERR",
                    "FAN_FAILED_ERR",
                    "FAN_ON",
                    "FAN_RECOVERED",
                    "FAN_SHUTDOWN_ERR",
                ],
                "FAN": ["FAN_OK", "FAN_FAILED"],
                "HARDWARE": ["THERMAL_NOT_FUNCTIONING"],
                "ILPOWER": ["CONTROLLER_ERR", "CONTROLLER_PORT_ERR", "SHUT_OVERDRAWN"],
                "LINK": ["UPDOWN"],
                "PLATFORM_THERMAL": ["OVERTEMP"],
                "RMGR": ["RED_WLC_SWITCHOVER", "RED_HEARTBEAT_TMOUT"],
                "RADIUS": ["ALLDEADSERVER"],
                "RPS": ["FANOK, FANFAIL"],
                "RTT": ["IPSLATHRESHOLD"],
                "SYS": ["DISK_SPACE_ALMOST_FULL"],
            },
            # Severity 4 facilities and mnemonics
            4: {
                "LISP": [
                    "MAP_CACHE_WARNING_THRESHOLD_REACHED",
                    "LOCAL_EID_NO_ROUTE",
                    "LOCAL_EID_MAP_REGISTER_FAILURE",
                    "CEF_DISABLED",
                    "LOCAL_EID_RLOC_INCONSISTENCY",
                ],
                "PM": ["ERR_DISABLE"],
                "PLATFORM_STACKPOWER": [
                    "UNDER_BUDGET",
                    "VERSION_MISMATCH",
                    "TOO_MANY_ERRORS",
                    "INSUFFICIENT_PWR",
                    "REDUNDANCY_LOSS",
                ],
                "UDLD": ["UDLD_PORT_DISABLED"],
                "IP": ["DUPADDR"],
                "SW_MATM": ["MACFLAP_NOTIF"],
                "CMRP_PFU": ["PFU_FAN_WARN"],
                "C4K_IOSMODPORTMAN": [
                    "MODULETEMPHIGH",
                    "POWERSUPPLYBAD",
                    "CRITICALTEMP",
                    "MODULECRITICALTEMP",
                    "TEMPHIGH",
                    "FANTRAYREMOVED",
                ],
                "C6KENV": ["TERMINATOR_PS_TEMP_MAJORALARM"],
                "MAC_MOVE": ["NOTIF"],
                "ACL_ERRMSG": ["HASH_FULL"],
                "CDP": ["NATIVE_VLAN_MISMATCH", "DUPLEX_MISMATCH"],
                "MAC_LIMIT": ["PORT_EXCEED", "VLAN_EXCEED"],
                "MM": ["MEMBER_DOWN", "MEMBER_UP"],
                "PM-SP": ["ERR_DISABLE"],
                "RADIUS": ["RADIUS_DEAD", "RADIUS_ALIVE"],
                "REP": ["LINKSTATUS"],
                "RTT": ["OPER_TIMEOUT"],
            },
            # Severity 5 facilities and mnemonics
            5: {
                "SFF8472": ["THRESHOLD_VIOLATION"],
                "DUAL": ["NBRCHANGE"],
                "DMI": ["SYNC_NEEDED", "SYNC_START"],
                "BGP": ["ADJCHANGE"],
                "REDUNDANCY": ["PEER_MONITOR_EVENT"],
                "IFDAMP": ["UPDOWN"],
                "CAPWAPAC_SMGR_TRACE_MESSAGE": ["AP_JOIN_DISJOIN"],
                "OSPF": ["ADJCHG"],
                "DOT1X": ["SUCCESS", "FAIL"],
                "ILPOWER": ["ILPOWER_POWER_DENY"],
                "AUTHMGR": ["START", "SUCCESS"],
                "CLNS": ["ADJCHANGE"],
                "ENVIRONMENTAL": ["SENSOROK"],
                "LINEPROTO": ["SENSOROK"],
                "LINK": ["CHANGED"],
                "MAB": ["FAIL", "SUCCESS"],
                "PORT": ["IF_UP", "IF_DOWN"],
                "PLATFORM": ["HALF_DUPLEX"],
                "SYS": ["RESTART", "RELOAD", "CONFIG_I"],
                "SESSION_MGR": ["START", "SUCCESS"],
                "SPANTREE": ["ROOTCHANGE"],
            },
            # Severity 6 facilities and mnemonics
            6: {
                "IOSXE_OIR": ["REMSPA", "INSSPA", "OFFLINECARD"],
                "TRANSCEIVER": ["REMOVED", "INSERTED"],
                "SMART_LIC": ["AGENT_READY", "HA_ROLE_CHANGED", "AGENT_ENABLED"],
                "STANDBY": ["STATECHANGE"],
                "IOSXE_PEM": ["REMPEM_FM", "FANOK", "PEMOK"],
                "PLATFORM_STACKPOWER": ["CABLE_EVENT", "LINK_EVENT"],
                "ENV_MON": ["REMPEM"],
                "IOSXE_INFRA": ["PROCPATH_CLIENT_HOG"],
                "STACKMGR": ["STACK_LINK_CHANGE"],
                "CMRP_PFU": ["PWR_MGMT_OK"],
                "C4K_IOSMODPORTMAN": [
                    "MODULEINSERTED",
                    "POWERSUPPLYGOOD",
                    "POWERSUPPLYFANGOOD",
                    "MODULEREMOVED",
                    "FANTRAYINSERTEDDETAILED",
                    "MODULEOFFLINE",
                    "MODULEONLINE",
                ],
                "CMCC": ["MGMT_SFP_REMOVED", "MGMT_SFP_INSERT"],
                "FLASH": ["DEVICE_INSERTED"],
                "HA": ["SWITCHOVER"],
                "HA_CONFIG_SYNC": ["BULK_CFGSYNC_SUCCEED"],
                "IGMP": ["IGMP_GROUP_LIMIT"],
                "IOSXE_REDUNDANCY": ["PEER-LOST", "PEER"],
                "IOSD_INFRA": ["IFS_DEVICE_OIR"],
                "OIR": ["INSCARD", "REMCARD"],
                "PLATFORM": ["HASTATUS_DETAIL", "HASTATUS"],
                "PTP": ["GRANDMASTER_CLOCK_CHANGE"],
                "RBM": ["SGACLHIT"],
                "SISF": ["ENTRY_CREATED"],
                "SYS": ["INTF_STATUS_CHANGE"],
                "SPA_OIR": ["OFFLINECARD"],
            },
        }

        global_issue = config.get("assurance_user_defined_issue_settings")
        if global_issue:
            name_pattern = r"^[\w\s\-\./%*\(\)\[\]:,]+$"
            desc_pattern = r"^[\w\s,.;:\'\-()/><=%$]+$"
            required_fields = [
                "facility",
                "mnemonic",
                "pattern",
                "occurrences",
                "duration_in_minutes",
            ]
            for each_issue in global_issue:
                name = each_issue.get("name")
                if name is None:
                    self.msg = "Missing required parameter 'name' in assurance_user_defined_issue_settings"
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if not re.match(name_pattern, name):
                    self.msg = (
                        "The 'name' in assurance_user_defined_issue_settings only supports alphanumeric characters, "
                        "space, and the following characters: -, _, ., /, %, *, (), [], :, ,."
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if self.state != "deleted":
                    description = each_issue.get("description")
                    if description is None:
                        self.msg = "Missing required parameter 'description' in assurance_user_defined_issue_settings"
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

                    if not re.match(desc_pattern, description):
                        self.msg = (
                            "The 'description' in assurance_user_defined_issue_settings only supports Alphanumeric characters, "
                            "space, and the following characters: , . ; : ' - ( ) / > < = * % $"
                        )
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

                    # for rule in issue_setting.get("rules", []):
                    for rule in each_issue.get("rules", []):  # Loop through rules list
                        for field in required_fields:
                            if (
                                field not in rule or rule[field] is None
                            ):  # Check if the field is missing
                                self.msg = "Mandatory field '{}' is missing in rules. Please provide all required values.".format(
                                    field
                                )
                                self.set_operation_result(
                                    "failed", False, self.msg, "ERROR"
                                ).check_return_status()

                priority = each_issue.get("priority")
                priority_list = ("P1", "P2", "P3", "P4")
                if priority and priority not in priority_list:
                    errormsg.append(
                        "priority: Invalid Priority '{0}' in playbook. "
                        "Must be one of: {1}.".format(
                            priority, ", ".join(priority_list)
                        )
                    )

                rules = each_issue.get("rules", [])
                for rule in rules:
                    severity = rule.get("severity")
                    severity = int(severity)
                    if severity < 0 or severity > 6:
                        errormsg.append(
                            "severity: Invalid Severity '{0}' in playbook. "
                            "Must be an integer between 0 and 6.".format(severity)
                        )

                    if severity in facility_mnemonic_map:
                        facility = rule.get("facility")
                        if facility not in facility_mnemonic_map[severity]:
                            errormsg.append(
                                "facility: Facility '{0}' must be selected from pre-defined list for severity {1}: {2}.".format(
                                    facility,
                                    severity,
                                    ", ".join(facility_mnemonic_map[severity].keys()),
                                )
                            )
                        else:
                            mnemonic = rule.get("mnemonic")
                            valid_mnemonics = facility_mnemonic_map[severity][facility]
                            if mnemonic not in valid_mnemonics:
                                errormsg.append(
                                    "mnemonic: Invalid Mnemonic '{0}' for Facility '{1}' and Severity '{2}'. "
                                    "Must be one of: {3}.".format(
                                        mnemonic,
                                        facility,
                                        severity,
                                        ", ".join(valid_mnemonics),
                                    )
                                )

                    duration = rule.get("duration_in_minutes")
                    duration = int(duration)
                    if duration < 1 or duration > 15:
                        errormsg.append(
                            "duration_in_minutes: Invalid duration '{0}' in playbook. "
                            "Must be an integer between 1 and 15.".format(duration)
                        )

        if len(errormsg) > 0:
            self.msg = "Invalid parameters in playbook config: '{0}' ".format(errormsg)
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        self.msg = "Successfully validated config params: {0}".format(str(config))
        self.log(self.msg, "INFO")
        return self

    def validate_ignore_duration(self, duration: str) -> bool:
        """
        Validates that the ignore duration ends with 'h' or 'd'
        and is preceded by an integer between 1 and 720.

        Parameters:
            duration (str): String containing the duration, with a numeric value
                            followed by 'h' (hours) or 'd' (days).
                            Examples of valid inputs: '1h', '24d', '720h'.

        Returns:
            bool: True if the duration is valid, False otherwise.

        Examples:
            Valid inputs:
                - '1h', '24d', '720h'
            Invalid inputs:
                - '0h' (out of range)
                - '31d' (out of range)
                - '720' (missing unit)
                - '1x' (invalid unit)
                - 720 (not a string)
        """
        self.log("Validation the ignore duration: {0}.".format(
            duration
        ))

        if not isinstance(duration, str) or len(duration) < 2:
            self.log("Ignore duration '{0}' is invalid: Must be a string and at least 2 characters long.".format(
                duration), "ERROR")
            return False

        unit = duration[-1]
        number_part = duration[:-1]

        if unit not in ('h', 'd'):
            self.log("Ignore duration '{0}' is invalid: Unit must be 'h' (hours) or 'd' (days).".format(
                duration), "ERROR")
            return False

        if not number_part.isdigit():
            self.log("Ignore duration '{0}' is invalid: Must start with a numeric value.".format(
                duration), "ERROR")
            return False

        number = int(number_part)
        if (unit == 'd' and 1 <= number <= 30) or (
           unit == 'h' and 1 <= number <= 720):
            self.log("Ignore duration '{0}' is valid.".format(
                duration), "INFO")
            return True

        self.log("Ignore duration '{0}' is invalid: Value out of range.".format(
            duration), "ERROR")
        return False

    def validate_start_end_datetime(self, start_time, end_time, errormsg):
        """
        Validate the start and end Date time param from the input playbook
        Parameters:
            start_time (str): The start datetime string in "%Y-%m-%d %H:%M:%S" format.
            end_time (str): The end datetime string in "%Y-%m-%d %H:%M:%S" format.
            errormsg (list): A list to store error messages if validation fails.

        Returns:
            tuple: (start_epoch_ms, end_epoch_ms) if valid, otherwise (None, None).
        """
        self.log(
            "Validating start and end datetime: start='{0}', end='{1}'".format(
                start_time, end_time
            ),
            "DEBUG",
        )
        date_format = "%Y-%m-%d %H:%M:%S"

        try:
            start_datetime = datetime.strptime(start_time, date_format)
            end_datetime = datetime.strptime(end_time, date_format)
            seven_days_in_ms = 7 * 24 * 60 * 60 * 1000

            if start_datetime > end_datetime:
                errormsg.append(
                    "Start datetime '{start_time}' must be before end datetime '{end_time}'."
                )
                return None, None

            start_epoch_ms = int(start_datetime.timestamp() * 1000)
            end_epoch_ms = int(end_datetime.timestamp() * 1000)
            if (end_epoch_ms - start_epoch_ms) >= seven_days_in_ms:
                errormsg.append("The time range must not exceed 7 days.")
                return None, None

            self.log("Successfully validated start and end datetime.", "INFO")

            return start_epoch_ms, end_epoch_ms
        except ValueError as e:
            errormsg.append(
                "Unable to validate Start date time, end date time. {0}".format(str(e))
            )
            return None
        except Exception as e:
            errormsg.append(
                "An unexpected error occurred during datetime validation: {0}".format(
                    str(e)
                )
            )

    def get_device_details(self, config):
        """
        Retrieve device ID and MAC address based on the provided device name, MAC address,
        or network device IP address.

        Parameters:
            config (dict): Contains device identification details.

        Returns:
            dict or None: Device details if found, otherwise None.
        """
        self.log(
            "Fetching device details for input: {0}".format(self.pprint(config)),
            "DEBUG",
        )
        input_param = {}
        for key in ["mac_address", "network_device_ip_address", "device_name"]:
            if config.get(key):
                input_param[self.keymap[key]] = config[key]
                break

        if not input_param:
            self.log(
                "No valid device identifier found in config. Exiting function.", "DEBUG"
            )
            return None

        self.log("Input payload for the Device info: {0}".format(input_param), "INFO")
        try:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                params=input_param,
            )
            self.log(
                "Response from the Device info: {0}".format(self.pprint(response)),
                "INFO",
            )

            response_data = response.get("response") if response else None

            if response_data:
                self.log("Processing response data for device.", "DEBUG")
                device_response = self.camel_to_snake_case(response_data)
                self.log("Successfully retrieved device details.", "INFO")
                return device_response[0]

        except Exception as e:
            self.msg = "The provided device '{0}' is either invalid or not present in the \
                     Cisco Catalyst Center.".format(
                str(input_param)
            )
            self.log(self.msg + str(e), "WARNING")
            return None

        self.log("No valid device details found. Returning None.", "DEBUG")
        return None

    def assurance_obj_params(self, get_object):
        """
        Get the required comparison obj_params value

        Parameters:
            get_object (str) - identifier for the required obj_params

        Returns:
            obj_params (list) - obj_params value for comparison.
        """
        self.log(
            "Retrieving comparison parameters for object: {0}".format(get_object),
            "DEBUG",
        )

        try:
            if get_object == "assurance_user_defined_issue_settings":
                self.log(
                    "Fetching parameters for assurance_user_defined_issue_settings",
                    "DEBUG",
                )
                obj_params = [
                    ("name", "name"),
                    ("description", "description"),
                    ("rules", "rules"),
                    ("is_enabled", "is_enabled"),
                    ("priority", "priority"),
                    ("is_notification_enabled", "is_notification_enabled"),
                ]
            elif get_object == "assurance_system_issue_settings":
                self.log(
                    "Fetching parameters for assurance_system_issue_settings", "DEBUG"
                )
                obj_params = [
                    ("synchronizeToHealthThreshold", "synchronize_to_health_threshold"),
                    ("priority", "priority"),
                    ("issueEnabled", "issue_enabled"),
                    ("thresholdValue", "threshold_value"),
                ]
            else:
                error_message = (
                    "Received an unexpected value for 'get_object': {0}".format(
                        get_object
                    )
                )
                self.log(error_message, "ERROR")
                self.set_operation_result("failed", False, error_message, "ERROR")
        except Exception as msg:
            self.log("Received exception: {0}".format(msg), "CRITICAL")

        self.log(
            "Successfully retrieved comparison parameters: {0}".format(obj_params),
            "DEBUG",
        )
        return obj_params

    def get_want(self, config):
        """
        Parse and store assurance-related settings from the playbook configuration.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.
        Returns:
            self: The current instance of the class with updated 'want' attributes.

        Description:
            This function extracts assurance-related settings from the playbook configuration, including:
            - User-defined issue settings
            - System issue settings
            - Issue resolution
            - Ignored issues
            - Execution of suggested commands

            It also ensures that each rule in `assurance_user_defined_issue_settings` has a default `occurrences` value
            and converts `severity` to a string if present.

        """
        self.log(
            "Extracting desired state (want) from playbook configuration: {0}".format(
                self.pprint(config)
            ),
            "DEBUG",
        )

        if not config:
            self.log("Received empty config dictionary.", "WARNING")
            return self

        self.log("Received config: {0}".format(str(config)), "DEBUG")

        want = {
            "assurance_user_defined_issue_settings": config.get(
                "assurance_user_defined_issue_settings"
            ),
            "assurance_system_issue_settings": config.get(
                "assurance_system_issue_settings"
            ),
            "ignore_issue": [],
            "issue_resolution": [],
            "suggested_commands": [],
        }

        if config.get("assurance_issue"):
            for issue in config.get("assurance_issue", []):
                if issue.get("issue_process_type") == "ignore":
                    want["ignore_issue"].append(issue)
                elif issue.get("issue_process_type") == "resolution":
                    want["issue_resolution"].append(issue)
                elif issue.get("issue_process_type") == "command_execution":
                    want["suggested_commands"].append(issue)

        severity_mapping = {
            "Emergency": 0,
            "Alert": 1,
            "Critical": 2,
            "Error": 3,
            "Warning": 4,
            "Notice": 5,
            "Info": 6,
        }

        if want.get("assurance_user_defined_issue_settings"):
            for issue_setting in want.get("assurance_user_defined_issue_settings", []):
                for rule in issue_setting.get("rules", []):
                    if "occurrences" not in rule:
                        rule["occurrences"] = 1
                    elif (
                        not isinstance(rule["occurrences"], int)
                        or rule["occurrences"] < 0
                    ):
                        self.msg = "Invalid input: 'occurrences' must be a non-negative integer."
                        self.log(self.msg, "ERROR")
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

                    severity = rule.get("severity")
                    if severity is None:
                        self.msg = "Severity is mandatory field, please provide some valid value."
                        self.log(self.msg, "WARNING")
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

                    # Check if severity is not in severity_mapping
                    if isinstance(severity, str) and severity not in severity_mapping:
                        self.msg = "Invalid severity value '{}' . Allowed values are: {}.".format(
                            severity, ", ".join(severity_mapping.keys())
                        )
                        self.log(self.msg, "ERROR")
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

                    # Convert severity to string and check if it's a valid label
                    if isinstance(severity, str):
                        rule["severity"] = str(severity_mapping.get(severity, severity))
                    else:
                        rule["severity"] = str(severity)

        system_issue_settings = want.get("assurance_system_issue_settings")
        if system_issue_settings:
            # Iterate through the list of issue settings
            for issue_setting in system_issue_settings:
                # Check if the issue setting has the specified name
                if issue_setting.get("name") == "No Activity on Radio (5 GHz)":
                    threshold_value = issue_setting.get("threshold_value")
                    # Validate the 'threshold_value' if it exists
                    if threshold_value is not None:
                        min_threshold = 60
                        max_threshold = 240
                        if not (min_threshold <= threshold_value <= max_threshold):
                            self.msg = "Invalid threshold value: {}. Allowed range is between {} and {}.".format(
                                threshold_value, min_threshold, max_threshold
                            )
                            self.log(self.msg, "ERROR")
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            ).check_return_status()

        # Input Validation to Ensure Correct Range for Each Input Field
        self.input_data_validation(config).check_return_status()

        self.want = want
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
        Retrieve the current assurance-related settings from Cisco Catalyst Center.

        Parameters:
            config (dict): Dictionary containing assurance settings.

        Returns:
            self: The current object with updated assurance-related attributes.

        Description:
            This function retrieves the current state of assurance-related configurations,
            including:
            - User-defined issue settings
            - System issue settings
            - Issue resolution settings

            It calls helper methods to process user-defined and system issues, updating
            the internal `have` dictionary accordingly. Finally, it logs the retrieved state.
        """
        self.log(
            "Fetching current state (have) from Cisco Catalyst Center using playbook configuration: {0}".format(
                self.pprint(config)
            ),
            "DEBUG",
        )
        assurance_user_defined_issue_details = config.get(
            "assurance_user_defined_issue_settings"
        )
        assurance_system_issue_details = config.get("assurance_system_issue_settings")

        if assurance_user_defined_issue_details is not None:
            self.log("Processing user-defined assurance issues.", "DEBUG")
            self.get_have_assurance_user_issue(
                assurance_user_defined_issue_details
            ).check_return_status()

        if assurance_system_issue_details is not None:
            self.log("Processing system assurance issues.", "DEBUG")
            self.get_have_assurance_system_issue(
                assurance_system_issue_details
            ).check_return_status()

        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.msg = "Successfully retrieved the details from the system"
        self.status = "success"
        return self

    def get_system_issue_details(self, device_type):
        """
        Get system issue details from Cisco Catalyst Center based on the provided device type.
        This function retrieves all issues for the given device type and matches the displayName with the playbook.

        Parameters:
            device_type (str) - The device type to filter system issues by (e.g., ROUTER, UNIFIED_AP).

        Returns:
            total_response - A list of system issues for a particular device family.
        """
        self.log(
            "Fetching system issue details for device type: {0}".format(device_type),
            "DEBUG",
        )
        total_response = []
        try:
            # Loop through issueEnabled values to fetch both enabled and disabled issues
            for issue_enabled in ["true", "false"]:
                response = self.dnac._exec(
                    family="issues",
                    function="returns_all_issue_trigger_definitions_for_given_filters",
                    params={"deviceType": device_type, "issueEnabled": issue_enabled},
                )
                if response and response.get("response"):
                    total_response.append(response.get("response"))
            # Logging the API response for debugging purposes
            self.log(
                "Response from returns_all_issue_trigger_definitions_for_given_filters API:'{0}'".format(
                    self.pprint(total_response)
                ),
                "DEBUG",
            )

            # Combining both responses (enabled and disabled issues) into a single list
            # total_response = total_response[0] + total_response[1]
            if len(total_response) == 2:
                total_response = total_response[0] + total_response[1]
            elif len(total_response) == 1:
                total_response = total_response[0]  # Only one response available
            else:
                total_response = []  # No valid responses

            # Handle the case where no system issues are found
            if not total_response:
                self.msg = (
                    "No system issue details found for device type '{0}'.".format(
                        device_type
                    )
                )
                self.log(self.msg, "WARNING")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            return total_response

        except Exception as e:
            self.msg = "Failed to retrieve system issue details for device type '{0}': {1}".format(
                device_type, str(e)
            )
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def get_have_assurance_system_issue(self, assurance_system_issue_details):
        """
        Get the current System Defined Issues information from Cisco Catalyst Center
        based on the provided playbook details. This method collects and updates
        the issues based on device type and name from the playbook.

        Parameters:
            assurance_system_issue_details (dict) - Playbook details containing System Defined Issue configuration.

        Returns:
            self - The current object with updated system issue details.
        """
        self.log(
            "Fetching current system-defined assurance issues from Cisco Catalyst Center.",
            "DEBUG",
        )
        assurance_system_issues = []

        for issue_setting in assurance_system_issue_details:
            name = issue_setting.get("name")
            device_type = issue_setting.get("device_type")
            description = issue_setting.get("description")

            if not name:
                self.msg = "Missing required parameter 'name' in assurance_system_issue_details"
                self.log(self.msg, "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            if not device_type:
                self.msg = "Missing required parameter 'device_type' in assurance_system_issue_details"
                self.log(self.msg, "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            self.log(
                "Fetching system issue details for device type: {0}".format(
                    device_type
                ),
                "DEBUG",
            )
            system_issues = self.get_system_issue_details(device_type)

            if not system_issues:
                self.msg = (
                    "System issue details for '{0}' could not be retrieved.".format(
                        name
                    )
                )
                self.log(self.msg, "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            matching_issues = []
            for issue in system_issues:
                if issue.get("displayName") == name and (
                    not description or issue.get("description") == description
                ):
                    matching_issues.append(issue)

            if not matching_issues:
                self.msg = "No system issues with displayName '{0}' found for device type '{1}'.".format(
                    name, device_type
                )
                self.log(self.msg, "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            for issue in matching_issues:
                assurance_system_issues.append(issue)
                self.log(
                    "System issue details for '{0}': {1}".format(name, issue), "DEBUG"
                )

        self.have.update({"assurance_system_issue_settings": assurance_system_issues})
        self.msg = "Successfully retrieved and updated system issue details from Cisco Catalyst Center."
        self.status = "success"
        self.log(
            "Successfully retrieved and updated system-defined assurance issues.",
            "INFO",
        )

        return self

    def assurance_issues_exists(self, name):
        """
        Check if the Assurance issues with the given name exists

        Parameters:
            name (str) - The name of the Assurance issues to check for existence

        Returns:
            'assurance_issue' : Detailed information of the Assurance issue if it exists, else None.
        """
        self.log(
            "Checking existence of assurance issue with name: {0}".format(name), "DEBUG"
        )
        assurance_issue = {"exists": False, "assurance_issue_details": None, "id": None}

        self.log("Attempting to retrieve issue details for '{0}'".format(name), "DEBUG")
        try:
            response = self.dnac._exec(
                family="issues",
                function="get_all_the_custom_issue_definitions_based_on_the_given_filters",
                params={"name": name},
            )
        except Exception as msg:
            match = re.search(r"status_code:\s*(\d+)", str(msg))
            if match and int(match.group(1)) == 404:
                assurance_issue = {
                    "response": [],
                    "exists": False,
                    "message": "There is no assurance issue present in the system for the given input.",
                }
                return
            else:
                self.msg = "Exception occurred while getting the assurance issue details with name '{name}': {msg}".format(
                    name=name, msg=msg
                )
                self.log(str(msg), "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        if not isinstance(response, dict):
            self.msg = "Failed to retrieve the assurance issue details - Response is not a dictionary"
            self.log(self.msg, "CRITICAL")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        all_user_issue_details = response.get("response")
        if all_user_issue_details == []:
            self.log("No assurance issues returned for '{0}'.".format(name), "INFO")
            assurance_issue = {
                "response": [],
                "exists": False,
                "message": "There is no assurance issue present in the system for the given input.",
            }
            return assurance_issue

        all_assurance_issue_details = []
        for issue_detail in all_user_issue_details:
            rules = issue_detail.get("rules", [])
            for rule in rules:
                rule["duration_in_minutes"] = rule.pop("durationInMinutes", None)
                rule.pop("type", None)  # Safer to avoid KeyError

            # Create a copy to avoid modifying the original
            other_fields = issue_detail.copy()
            other_fields.pop("isEnabled", None)
            other_fields.pop("isNotificationEnabled", None)
            other_fields.pop("rules", None)

            transformed_detail = {
                "is_enabled": issue_detail.get("isEnabled"),
                "is_notification_enabled": issue_detail.get("isNotificationEnabled"),
                "rules": rules,
                **other_fields,
            }
            all_assurance_issue_details.append(transformed_detail)

        self.log(
            "Processed issue details: {0}".format(all_assurance_issue_details), "DEBUG"
        )

        assurance_issue_details = get_dict_result(
            all_assurance_issue_details, "user_issue", name
        )

        if assurance_issue_details:
            self.log(
                "Assurance issue found with name '{0}': {1}".format(
                    name, assurance_issue_details
                ),
                "INFO",
            )
            assurance_issue.update({"exists": True})
            assurance_issue.update({"id": assurance_issue_details.get("id")})
            assurance_issue["assurance_issue_details"] = assurance_issue_details

        self.log(
            "Formatted assurance issue details: {0}".format(assurance_issue), "DEBUG"
        )
        return assurance_issue

    def get_have_assurance_user_issue(self, assurance_user_defined_issue_settings):
        """
        Get the current Assurance Issue information from
        Cisco Catalyst Center based on the provided playbook details.
        check this API using check_return_status.

        Parameters:
            assurance_issue_details (dict) - Playbook details containing Assurance Issue configuration.

        Returns:
            self - The current object with updated information.
        """
        self.log(
            "Fetching current assurance user-defined issues from Cisco Catalyst Center.",
            "DEBUG",
        )
        assurance_issue = []
        assurance_issue_index = 0
        for issues_setting in assurance_user_defined_issue_settings:
            name = issues_setting.get("name")
            if name is None:
                self.msg = "Missing required parameter 'name' in assurance_user_defined_issue_settings"
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            name_length = len(name)
            if name_length > 100:
                self.msg = "The length of the '{0}' in assurance_user_defined_issue_settings should be less or equal to 100. Invalid_config: {1}".format(
                    name, issues_setting
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            self.log("Checking if assurance issue '{0}' exists".format(name), "DEBUG")
            assurance_issue.append(self.assurance_issues_exists(name))
            self.log(
                "Assurance issue details of '{0}': {1}".format(
                    name, assurance_issue[assurance_issue_index]
                ),
                "DEBUG",
            )
            prev_name = issues_setting.get("prev_name")
            if (
                assurance_issue[assurance_issue_index].get("exists") is False
                and prev_name is not None
            ):
                self.log(
                    "Previous name '{0}' not found. Checking prev_name.".format(
                        prev_name
                    ),
                    "DEBUG",
                )
                assurance_issue.pop()
                assurance_issue.append(self.assurance_issues_exists(prev_name))
                if assurance_issue[assurance_issue_index].get("exists") is False:
                    self.msg = "Prev name {0} doesn't exist in assurance_user_issue_details".format(
                        prev_name
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
                    return self

                assurance_issue[assurance_issue_index].update({"prev_name": name})
            assurance_issue_index += 1

        self.log("Assurance issue details: {0}".format(assurance_issue), "DEBUG")
        self.have.update({"assurance_user_defined_issue_settings": assurance_issue})
        self.msg = (
            "Collecting the assurance issue details from the Cisco Catalyst Center"
        )
        self.log(
            "Successfully retrieved and updated assurance user-defined issues.", "INFO"
        )

        return self

    def get_issue_ids_for_names(self, config_data, verify=None):
        """
        Get the issue ids from global or custom name.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config_data (dict): A dictionary containing input config data from playbook.

        Returns:
            list : Returns list of issue ids.

        Description:
            This function get the issue ids based on the issue name either global or custom
            issue name.
        """
        self.log(
            "Retrieving issue IDs for given playbook configuration: {0}".format(
                self.pprint(config_data)
            ),
            "DEBUG",
        )
        issue_keys = list(config_data.keys())

        if len(issue_keys) < 1:
            self.msg = "No data available in the config input: {0}".format(
                str(config_data)
            )
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        payload_data = {}
        avoid_keys = [
            "site_hierarchy",
            "start_datetime",
            "end_datetime",
            "issue_name",
            "network_device_ip_address",
            "device_name",
            "issue_process_type",
            "mac_address"
        ]

        for key, value in config_data.items():
            if value is not None and key not in avoid_keys:
                mapped_key = self.keymap.get(key, key)
                payload_data[mapped_key] = value

        issue_ids = []

        site_name = config_data.get("site_hierarchy")
        if site_name:
            self.log("Fetching site ID for site: {0}".format(site_name), "DEBUG")
            site_id = self.get_site_id(site_name)
            if site_id[0]:
                payload_data[self.keymap["site_hierarchy"]] = site_id[1]
            else:
                self.msg = "Unable to get the site details for given site: {0}".format(
                    str(site_name)
                )
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        start_date = config_data.get("start_datetime")
        end_date = config_data.get("end_datetime")
        if start_date and end_date:
            self.log("Validating start and end datetime", "DEBUG")
            payload_data["start_time"], payload_data["end_time"] = (
                self.validate_start_end_datetime(start_date, end_date, [])
            )

        if (
            config_data.get("device_name")
            or config_data.get("mac_address")
            or config_data.get("network_device_ip_address")
        ):
            device_info = self.get_device_details(config_data)

            if not device_info:
                self.msg = "Unable to get device info given device_name: {0}".format(
                    str(config_data.get("device_name"))
                )
                self.log(self.msg, "INFO")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            payload_data["device_id"] = device_info.get("id")

        self.log(
            "Collecting Issue ids for given config: {0}".format(
                self.pprint(payload_data)
            ),
            "INFO",
        )
        try:
            self.log(
                "Getting issue ids for the names: {0}".format(
                    self.pprint(payload_data)
                ),
                "INFO",
            )
            response = self.dnac._exec(
                family="issues", function="issues", params=payload_data
            )
            self.log("Response from the API: {0}".format(self.pprint(response)), "INFO")

            if response and isinstance(response, dict):
                all_issues = response.get("response")
                if isinstance(all_issues, list) and len(all_issues) > 0:
                    start_time = payload_data.get("start_time")
                    end_time = payload_data.get("end_time")
                    if start_time and end_time:
                        issue_ids = [
                            issue["issueId"]
                            for issue in all_issues
                            if (issue["name"] == config_data.get("issue_name"))
                            and (start_time <= issue["last_occurence_time"] <= end_time)
                        ]
                    else:
                        issue_ids = [
                            issue["issueId"]
                            for issue in all_issues
                            if issue["name"] == config_data.get("issue_name")
                        ]
            else:
                self.msg = "No data received for the issue: {0}".format(
                    str(payload_data)
                )
                self.log(self.msg, "INFO")
                self.changed = False
                self.status = "success"

        except Exception as e:
            self.msg = "An error occurred during get issue ids : {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        issue_ids = list(set(issue_ids))
        if len(issue_ids) > 0:
            self.msg = "Find the list of issue ids: {0}".format(self.pprint(issue_ids))
            self.log("Successfully retrieved issue IDs", "INFO")
            return issue_ids

        self.no_issues.append(config_data)
        self.msg = "No issues found to resolve or ignore. All issues are already cleared: {0}".format(
            config_data)
        self.log(self.msg, "ERROR")
        self.changed = False
        self.status = "success"
        return []

    def resolve_issue(self, issue_ids):
        """
        Resolve the issue based on the input issues name.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            issue_ids (list): A list containing issue ids from get issue ids.

        Returns:
            dict or None: A dictionary containing the task ID details if the issue was successfully resolved,
                         or None if the resolution was unsuccessful or the response was not in the expected format.

        Description:
            This function used to resolve the issue and show the status of the resolved
            status of the issue id.
        """
        self.log(
            "Resolving issues with provided issue IDs: {0}".format(
                self.pprint(issue_ids)
            ),
            "DEBUG",
        )
        try:
            response = self.dnac._exec(
                family="issues",
                function="resolve_the_given_lists_of_issues",
                op_modifies=True,
                params=dict(issueIds=issue_ids),
            )
            self.log(
                "Response from Resolve issue API response: {0}".format(response),
                "DEBUG",
            )

            if response and isinstance(response, dict):
                return response.get("response")

            self.log("Invalid response received from Resolve Issue API", "ERROR")
            return None

        except Exception as e:
            self.msg = "An error occurred during resolve issue: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def ignore_issue(self, issue_ids, duration=None):
        """
        Ignore the issue based on the input issues name.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            issue_ids (list): A list containing issue ids from get issue ids.

        Returns:
            dict or None: A dictionary containing task ID details if a response is received; otherwise, None.

        Description:
            This function used to ignore the issue and show the status of the processed
            status of the issue id.
        """

        self.log(
            "Ignore issue with parameters: {0}".format(self.pprint(issue_ids)), "INFO"
        )

        ignore_payload = dict(issueIds=issue_ids)
        if duration:
            unit = duration[-1]
            number_part = duration[:-1]
            payload_input = int(number_part)
            ignore_payload["ignoreHours"] = payload_input

            if unit == 'd':
                payload_input = payload_input * 24
                ignore_payload["ignoreHours"] = payload_input

        try:
            response = self.dnac._exec(
                family="issues",
                function="ignore_the_given_list_of_issues",
                op_modifies=True,
                params=ignore_payload,
            )
            self.log(
                "Response from ignore issue API response: {0}".format(response), "DEBUG"
            )

            if response and isinstance(response, dict):
                return response.get("response")

            self.log("Invalid response received from Ignore Issue API", "ERROR")
            return None

        except Exception as e:
            self.msg = "An error occurred during ignore issue API: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def execute_commands(self, issue_id):
        """
        Execute command function based on the input issues name and Issue id.

        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            issue_id (str): The issue ID for which suggested commands should be executed.

        Returns:
            dict or None: A dictionary with execution details if successful, otherwise None.

        Description:
            This function used to execute the command and show the processed
            status of the issue id.
        """
        self.log(
            "Executing suggested actions for issue ID: {0}".format(issue_id), "INFO"
        )

        try:
            response = self.dnac._exec(
                family="issues",
                function="execute_suggested_actions_commands",
                op_modifies=True,
                params={"entity_type": "issue_id", "entity_value": issue_id},
            )
            self.log(
                "Response from execute command API response: {0}".format(response),
                "DEBUG",
            )

            if not response or not isinstance(response, dict):
                self.log("Invalid response received from Execute Command API", "ERROR")
                return None

            execution_id = response.get("executionId")
            if not execution_id:
                self.log("No execution ID received from API response.", "ERROR")
                return None

            resync_retry_count = int(self.payload.get("dnac_api_task_timeout", 100))

            if response and isinstance(response, dict):
                executionid = response.get("executionId")
                resync_retry_count = int(self.payload.get("dnac_api_task_timeout", 100))
                resync_retry_interval = int(
                    self.payload.get("dnac_task_poll_interval", 5)
                )
                self.log(
                    "Polling execution details with retry count: {0}, interval: {1}s".format(
                        resync_retry_count, resync_retry_interval
                    ),
                    "DEBUG",
                )

                while resync_retry_count:
                    execution_details = self.get_execution_details(executionid)
                    self.log(
                        "Execution details: {0}".format(self.pprint(execution_details)),
                        "INFO",
                    )

                    if execution_details.get("status") == "SUCCESS":
                        self.log(
                            "Issue resolution successful with execution details: {0}".format(
                                self.pprint(execution_details)
                            ),
                            "INFO",
                        )
                        self.result["changed"] = True
                        self.result["response"] = execution_details
                        return execution_details

                    if execution_details.get("bapiError"):
                        msg = execution_details.get("bapiError")
                        self.log(
                            "Error encountered during issue resolution: {0}".format(
                                msg
                            ),
                            "ERROR",
                        )
                        self.set_operation_result(
                            "failed", False, msg, "ERROR", execution_details
                        ).check_return_status()
                        return execution_details

                    self.log(
                        "Polling task status, waiting for {} seconds before the next check...".format(
                            resync_retry_interval
                        ),
                        "DEBUG",
                    )
                    time.sleep(resync_retry_interval)
                    resync_retry_count = resync_retry_count - 1
                return response

            self.log("Execution polling timed out after retries.", "ERROR")
            return response

        except Exception as e:
            self.msg = "An error occurred during ignore issue API: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def update_system_issue(self, assurance_system_issue_details):
        """
        Update the system-defined issues in Cisco Catalyst Center based on the provided playbook details.
        This method directly updates the issues without checking if the issue exists.

        Parameters:
            assurance_system_issue_details (dict) - Playbook details containing System Defined Issue configuration.

        Returns:
            self - The current object with updated system issue details.
        """
        self.log(
            "Starting update_system_issue function {}".format(
                assurance_system_issue_details
            ),
            "DEBUG",
        )
        updated_system_issues = []
        result_response = self.result.get("response")
        if not result_response or len(result_response) < 2:
            self.msg = "Invalid response structure in result, expected assurance_system_issue_settings."
            self.log(self.msg, "ERROR")
            return self

        result_assurance_issue = result_response[1].get(
            "assurance_system_issue_settings"
        )
        system_issue = self.have.get("assurance_system_issue_settings")

        if not system_issue:
            self.msg = "No system issue data found in 'have'. Exiting update."
            self.log(self.msg, "ERROR")
            return self

        for issue_setting in assurance_system_issue_details:
            name = issue_setting.get("name")
            description = issue_setting.get("description")
            if name is None:
                self.msg = "Missing required parameter 'name' in assurance_system_issue_details"
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            self.log("Checking system issue for update: {0}".format(name), "DEBUG")

            for item in system_issue:
                if item.get("displayName") == name or (
                    description and item.get("description") == description
                ):
                    if not self.requires_update(
                        item, issue_setting, self.system_issue_obj_params
                    ):
                        self.log(
                            "System defined issue '{0}' doesn't require an update".format(
                                name
                            ),
                            "INFO",
                        )
                        result_assurance_issue.get("msg").update(
                            {name: "System defined issue doesn't require an update"}
                        )
                    elif issue_setting not in updated_system_issues:
                        updated_system_issues.append(issue_setting)

            if not updated_system_issues:
                self.log("No updates necessary for '{0}'.".format(name), "DEBUG")
                continue

            for issue in system_issue:

                if issue.get("displayName") == name and (
                    not description or issue.get("description") == description
                ):
                    if not issue_setting.get("issue_enabled") and (
                        issue_setting.get("threshold_value") != issue.get("threshold_value") or
                        issue_setting.get("priority") != issue.get("priority")
                    ):
                        self.msg = "For disabled issues, threshold and priority values can't be updated '{0}'.".format(
                            name
                        )
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

                    system_issue_params = {
                        "id": issue.get("id"),
                        "payload": {
                            "priority": issue_setting.get("priority"),
                            "issueEnabled": issue_setting.get("issue_enabled"),
                            "thresholdValue": issue_setting.get("threshold_value"),
                            "synchronizeToHealthThreshold": issue_setting.get(
                                "synchronize_to_health_threshold"
                            ),
                        },
                    }

                    self.log(
                        "Preparing update for system issue '{0}' with params: {1}".format(
                            name, system_issue_params
                        ),
                        "DEBUG",
                    )

                    try:
                        response = self.dnac._exec(
                            family="issues",
                            function="issue_trigger_definition_update",
                            op_modifies=True,
                            params=system_issue_params,
                        )
                        response_data = response.get("response")
                        if response_data:
                            self.log(
                                "Successfully updated system-defined issue '{0}' with details: {1}".format(
                                    name, response_data
                                ),
                                "INFO",
                            )
                            updated_system_issues.append(response_data)
                        else:
                            self.log(
                                "Failed to update system issue '{0}'".format(name),
                                "ERROR",
                            )

                    except Exception as e:
                        self.msg = "Exception occurred while updating the system-defined issue '{0}':".format(
                            str(e)
                        )
                        self.log(self.msg, "ERROR")
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

                    result_assurance_issue.get("response").update(
                        {"system issue": system_issue_params}
                    )
                    result_assurance_issue.get("msg").update(
                        {
                            response_data.get(
                                "displayName"
                            ): "System issue Updated Successfully"
                        }
                    )
                    self.msg = "Successfully updated system-defined issue details."
                    self.status = "success"
                    self.result["changed"] = True
                    self.log(
                        "Successfully updated system-defined assurance issues.", "INFO"
                    )

        return self

    def create_assurance_issue(self, assurance_details, config):
        """
        Update/Create Assurance issue in Cisco Catalyst Center with fields provided in playbook

        Parameters:
            assurance_details (list[dict]): A list of dictionaries containing assurance issue details.
            config (dict): Configuration details for processing assurance issues.

        Returns:
            self - The current object with Assurance Issue information.
        """
        self.log(
            "Processing Assurance Issue creation with input details: {0}".format(
                self.pprint(assurance_details)
            ),
            "DEBUG",
        )

        if not assurance_details:
            self.msg = "No assurance issue details provided for creation."
            self.log(self.msg, "WARNING")
            return self

        create_assurance_issue = []
        update_assurance_issue = []
        seen_names = set()
        duplicate_names = set()
        unique_create_assurance_issue = []
        assurance_index = 0

        result_response = self.result.get("response")
        if not result_response or len(result_response) < 1:
            self.msg = "Invalid response structure in result, expected assurance_user_defined_issue_settings."
            self.log(self.msg, "ERROR")
            return self

        result_assurance_issue = result_response[0].get(
            "assurance_user_defined_issue_settings"
        )
        want_assurance_issue = self.want.get("assurance_user_defined_issue_settings")
        have_assurance_issue = self.have.get("assurance_user_defined_issue_settings")

        if not want_assurance_issue or not have_assurance_issue:
            self.msg = (
                "Required assurance issue data is missing in 'want' or 'have'. Exiting."
            )
            self.log(self.msg, "ERROR")
            return self

        self.log(
            "Comparing 'want' and 'have' assurance issues to determine actions.",
            "DEBUG",
        )

        # Initialize containers for categorizing issues
        seen_names = set()
        duplicate_names = set()
        unique_create_assurance_issue = []
        update_assurance_issue = []

        # Process assurance issues
        for index, item in enumerate(have_assurance_issue):
            issue_name = want_assurance_issue[index].get("name")
            if not issue_name:
                self.log(
                    "Skipping issue at index {0} due to missing 'name' key.".format(
                        index
                    ),
                    "WARNING",
                )
                continue

            self.result["response"][0].setdefault("msg", {}).update({issue_name: {}})
            self.log("Processing issue: {0}".format(issue_name), "DEBUG")

            # If the issue exists, add it to the update list and skip further processing
            if item.get("exists"):
                self.log(
                    "Issue '{0}' exists. Adding to update list.".format(issue_name),
                    "DEBUG",
                )
                update_assurance_issue.append(want_assurance_issue[index])
                continue

            # Check for duplicates
            if issue_name in seen_names:
                self.log(
                    "Duplicate issue name detected: '{0}'. Adding to duplicates.".format(
                        issue_name
                    ),
                    "DEBUG",
                )
                duplicate_names.add(issue_name)
                continue

            # If the issue is new, add it to the create list
            self.log(
                "New issue detected: '{0}'. Adding to create list.".format(issue_name),
                "DEBUG",
            )
            seen_names.add(issue_name)
            unique_create_assurance_issue.append(want_assurance_issue[index])

        # Move duplicates to update list
        for issue in want_assurance_issue:
            if issue.get("name") in duplicate_names:
                self.log(
                    "Duplicate issue '{0}' moved to update list.".format(
                        issue.get("name")
                    ),
                    "DEBUG",
                )
                update_assurance_issue.append(issue)

        # Use the deduplicated list
        create_assurance_issue = unique_create_assurance_issue

        for issue in create_assurance_issue:
            self.log(
                "Assurance issue(s) details to be created: {0}".format(issue), "INFO"
            )
            user_issue_params = {
                "name": issue.get("name"),
                "description": issue.get("description"),
                "rules": [
                    {
                        "severity": rule.get("severity"),
                        "facility": rule.get("facility"),
                        "mnemonic": rule.get("mnemonic"),
                        "pattern": rule.get("pattern"),
                        "occurrences": rule.get("occurrences"),
                        "durationInMinutes": rule.get("duration_in_minutes"),
                    }
                    for rule in issue.get("rules", [])
                ],
                "isEnabled": issue.get("is_enabled"),
                "priority": issue.get("priority"),
                "isNotificationEnabled": issue.get("is_notification_enabled"),
            }

            try:
                response = self.dnac._exec(
                    family="issues",
                    function="creates_a_new_user_defined_issue_definitions",
                    op_modifies=True,
                    params=user_issue_params,
                )
            except Exception as msg:
                self.msg = "Exception occurred while creating the user defined issue: {msg}".format(
                    msg=msg
                )
                self.log(str(msg), "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            response_data = response.get("response")
            if not response_data:
                self.log(
                    "Failed to create user-defined issue: {0}".format(
                        issue.get("name")
                    ),
                    "ERROR",
                )
                return self

            if response_data:
                if "name" in response_data:
                    self.log(
                        "Successfully created user defined issue with these details: {0}".format(
                            response_data
                        ),
                        "INFO",
                    )
                name = issue.get("name")
                self.log(
                    "User Defined Issue '{0}' created successfully.".format(name),
                    "INFO",
                )
                result_assurance_issue.get("response").update(
                    {"created user-defined issue": issue}
                )
                result_assurance_issue.get("msg").update(
                    {
                        response_data.get(
                            "name"
                        ): "user-defined issue created successfully"
                    }
                )
                self.result["changed"] = True

        if update_assurance_issue:
            self.log("Updating existing assurance issues", "INFO")
            self.update_user_defined_issue(
                assurance_details, update_assurance_issue, config
            )

        self.status = "Success"
        self.log("Completed Assurance Issue creation process.", "DEBUG")
        return self

    def update_user_defined_issue(
        self, assurance_details, update_assurance_issue, config
    ):
        """
        Update the user-defined issues in Cisco Catalyst Center based on the provided assurance details.
        This method ensures updates are applied only to issues that require changes, based on the current system state.

        Parameters:
            assurance_details (dict): Details containing assurance configuration for user-defined issues.
            update_assurance_issue (list[dict]): A list of user-defined issue configurations to be updated.
            Each item should include details such as name, description, rules, and settings.

        Returns:
            self: The current object with updated user-defined issue details, including success or failure messages.
        """
        self.log(
            "Updating user-defined assurance issues with input details: {0}".format(
                self.pprint(update_assurance_issue)
            ),
            "DEBUG",
        )
        self.get_have(config)

        if not update_assurance_issue:
            self.msg = "No user-defined assurance issues provided for update."
            self.log(self.msg, "WARNING")
            return self

        result_response = self.result.get("response")
        if not result_response or len(result_response) < 1:
            self.msg = "Invalid response structure in result, expected assurance_user_defined_issue_settings."
            self.log(self.msg, "ERROR")
            return self

        result_assurance_issue = self.result.get("response")[0].get(
            "assurance_user_defined_issue_settings"
        )
        final_update_user_defined_issue = []
        for item in update_assurance_issue:
            name = item.get("name")
            for issue in self.have.get("assurance_user_defined_issue_settings"):
                if issue.get("exists") and (
                    issue.get("assurance_issue_details").get("name") == name
                    or issue.get("prev_name") == name
                ):
                    if not self.requires_update(
                        issue.get("assurance_issue_details"),
                        item,
                        self.user_defined_issue_obj_params,
                    ):
                        self.log(
                            "Assurance issue '{0}' doesn't require an update".format(
                                name
                            ),
                            "INFO",
                        )
                        result_assurance_issue.get("msg").update(
                            {name: "Assurance issue doesn't require an update"}
                        )
                    elif item not in final_update_user_defined_issue:
                        final_update_user_defined_issue.append(item)

        if not final_update_user_defined_issue:
            self.log(
                "No updates required for any user-defined assurance issues.", "INFO"
            )
            return self

        self.log(
            "User-defined assurance issues requiring updates: {0}".format(
                self.pprint(final_update_user_defined_issue)
            ),
            "DEBUG",
        )

        for issue in final_update_user_defined_issue:
            name = issue.get("name")
            prev_name = issue.get("prev_name")

            for id in self.have.get("assurance_user_defined_issue_settings"):
                assurance_issue_details = id.get("assurance_issue_details")
                if assurance_issue_details:
                    assurance_name = assurance_issue_details.get("name")

                    # Check if prev_name exists, otherwise fallback to checking name
                    if (
                        prev_name and assurance_name == prev_name
                    ) or assurance_name == name:
                        for rule in issue.get("rules", []):
                            if (
                                (
                                    "severity" in rule
                                    and rule["severity"]
                                    != id["assurance_issue_details"]["rules"][0][
                                        "severity"
                                    ]
                                )
                                or (
                                    "facility" in rule
                                    and rule["facility"]
                                    != id["assurance_issue_details"]["rules"][0][
                                        "facility"
                                    ]
                                )
                                or (
                                    "mnemonic" in rule
                                    and rule["mnemonic"]
                                    != id["assurance_issue_details"]["rules"][0][
                                        "mnemonic"
                                    ]
                                )
                            ):

                                self.msg = "Cannot update the severity, facility, or mnemonic for issue '{0}'.".format(
                                    name
                                )
                                self.log(self.msg, "ERROR")
                                self.set_operation_result(
                                    "failed", False, self.msg, "ERROR"
                                ).check_return_status()
                                return self

                        user_issue_params = {
                            "id": id.get("id"),
                            "payload": {
                                "name": issue.get("name"),
                                "description": issue.get("description"),
                                "rules": [
                                    {
                                        "severity": rule.get("severity"),
                                        "facility": rule.get("facility"),
                                        "mnemonic": rule.get("mnemonic"),
                                        "pattern": rule.get("pattern"),
                                        "occurrences": rule.get("occurrences"),
                                        "durationInMinutes": rule.get(
                                            "duration_in_minutes"
                                        ),
                                    }
                                    for rule in issue.get("rules", [])
                                ],
                                "isEnabled": issue.get("is_enabled"),
                                "priority": issue.get("priority"),
                                "isNotificationEnabled": issue.get(
                                    "is_notification_enabled"
                                ),
                            },
                        }

                        self.log(
                            "Desired State for user issue (want): {0}".format(
                                user_issue_params
                            ),
                            "DEBUG",
                        )

                        try:
                            response = self.dnac._exec(
                                family="issues",
                                function="updates_an_existing_custom_issue_definition_based_on_the_provided_id",
                                op_modifies=True,
                                params=user_issue_params,
                            )
                            self.log(
                                "Response from update API: {0}".format(
                                    self.pprint(response)
                                ),
                                "DEBUG",
                            )
                        except Exception as msg:
                            self.msg = "Exception occurred while updating the user defined: {msg}".format(
                                msg=msg
                            )
                            self.log(str(msg), "ERROR")
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            ).check_return_status()

                        if not response:
                            self.log(
                                "Failed to update user-defined assurance issue '{0}'.".format(
                                    name
                                ),
                                "ERROR",
                            )
                            return self

                        response_data = response.get("response")
                        if not response_data:
                            self.log(
                                "Failed to success response for update user-defined assurance issue '{0}'.".format(
                                    name
                                ),
                                "ERROR",
                            )
                            return self

                        if response_data:
                            if "name" in response_data:
                                self.log(
                                    "Successfully updated defined issue with these details: {0}".format(
                                        response_data
                                    ),
                                    "INFO",
                                )
                            self.log(
                                "User Defined Issue '{0}' update successfully.".format(
                                    name
                                ),
                                "INFO",
                            )
                            result_assurance_issue.get("response").update(
                                {"updated user defined issue Details": item}
                            )
                            result_assurance_issue.get("msg").update(
                                {name: "User defined issues updated Successfully"}
                            )
                            self.result["changed"] = True
                            self.log(
                                "Completed user-defined assurance issue updates.",
                                "DEBUG",
                            )

        return self

    def delete_assurance_issue(self, assurance_user_defined_issue_details):
        """
        Delete a Assurance Issue by name in Cisco Catalyst Center

        Parameters:
            assurance_issue_details (dict) - Assurance Issue details of the playbook

        Returns:
            self - The current object with Assurance Issue information.
        """
        self.log(
            "Deleting user-defined assurance issues with input details: {0}".format(
                self.pprint(assurance_user_defined_issue_details)
            ),
            "DEBUG",
        )
        try:
            result_response = self.result.get("response")
            if not result_response or len(result_response) < 1:
                self.msg = "Invalid response structure in result, expected assurance_user_defined_issue_settings."
                self.log(self.msg, "ERROR")
                return self

            result_assurance_issue = result_response[0].get(
                "assurance_user_defined_issue_settings"
            )
            assurance_issue_index = 0

            for item in self.have.get("assurance_user_defined_issue_settings"):
                assurance_issue_exists = item.get("exists")
                name = assurance_user_defined_issue_details[assurance_issue_index].get(
                    "name"
                )
                assurance_issue_index += 1

                if not assurance_issue_exists:
                    result_assurance_issue.get("msg").update(
                        {name: "Assurance issue not found"}
                    )
                    self.log("Assurance Issue '{0}' not found".format(name), "INFO")
                    continue

                self.log("Deleting Assurance Issue '{0}'".format(name), "INFO")
                try:
                    id = item.get("id")
                    response = self.dnac._exec(
                        family="issues",
                        function="deletes_an_existing_custom_issue_definition",
                        op_modifies=True,
                        params={"id": id},
                    )
                    self.log(
                        "Response from Delete API for issue '{0}': {1}".format(
                            name, self.pprint(response)
                        ),
                        "DEBUG",
                    )
                except Exception as e:
                    expected_exception_msgs = [
                        "Expecting value: line 1 column 1",
                        "not iterable",
                        "has no attribute",
                    ]

                    for msg in expected_exception_msgs:
                        if msg in str(e):
                            self.log(
                                "Exception while deleting Assurance Issue '{0}': {1}".format(
                                    name, str(e)
                                ),
                                "WARNING",
                            )
                        result_assurance_issue = self.result.get("response")[0].get(
                            "assurance_user_defined_issue_settings"
                        )
                        result_assurance_issue.get("msg").update(
                            {name: "Assurance user-defined issue deleted successfully"}
                        )
                        self.result["changed"] = True
                        self.msg = "Assurance Issue '{0}' deleted successfully".format(
                            name
                        )

        except Exception as e:
            self.msg = "An exception occurred while deleting the Assurance user issue with '{0}': {1}".format(
                name, str(e)
            )
            self.log(self.msg, "ERROR")
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return self

    def get_diff_merged(self, config):
        """
        Process Assurance Issues in Cisco Catalyst Center based on the provided playbook details.

        - Creates new user-defined assurance issues if they do not exist.
        - Updates system-defined assurance issues if changes are required.
        - Resolves, ignores, or executes commands for specific assurance issues.

        config (dict): Playbook details containing assurance issue configurations:
            - assurance_user_defined_issue_settings (list[dict]): User-defined assurance issues.
            - assurance_system_issue_settings (list[dict]): System-defined assurance issues.
            - assurance_issue (list[dict]): Specific issues to be processed.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """
        self.log(
            "Processing Assurance Issues with provided playbook details: {0}".format(
                self.pprint(config)
            ),
            "DEBUG",
        )
        assurance_user_defined_issue_details = config.get(
            "assurance_user_defined_issue_settings"
        )

        if assurance_user_defined_issue_details is not None:
            self.create_assurance_issue(
                assurance_user_defined_issue_details, config
            ).check_return_status()

        assurance_system_issue_details = config.get("assurance_system_issue_settings")
        if assurance_system_issue_details is not None:
            self.update_system_issue(
                assurance_system_issue_details
            ).check_return_status()

        assurance_issue = config.get("assurance_issue", [])

        if not assurance_issue:
            self.log("No specific assurance issues provided in the playbook.", "INFO")
            return self

        self.log("Processing specific assurance issues.", "DEBUG")

        if assurance_issue and len(assurance_issue) > 0:
            success_list = []
            self.issue_resolved, self.issue_ignored = [], []
            self.success_list_resolved, self.success_list_ignored = [], []
            self.failed_list_resolved, self.failed_list_ignored = [], []
            self.cmd_executed, self.cmd_not_executed = [], []
            self.msg = ""
            self.changed = False
            self.status = "failed"
            response = {}

            issue_resolution = self.want.get("issue_resolution")
            if issue_resolution:
                for each_issue in issue_resolution:
                    issue_ids = self.get_issue_ids_for_names(each_issue)
                    if issue_ids:
                        response = self.resolve_issue(issue_ids)

                        if response and isinstance(response, dict):
                            self.success_list_resolved.append(each_issue)
                            self.issue_resolved.append(response)
                            self.log(
                                "Successfully resolved issue: {0}".format(
                                    self.pprint(self.issue_resolved)
                                ),
                                "INFO",
                            )
                        else:
                            self.failed_list_resolved.append(each_issue)
                            self.log(
                                "Unable to process the issue for: {0}.".format(
                                    self.pprint(self.failed_list_resolved)
                                ),
                                "INFO",
                            )

            ignore_issue = self.want.get("ignore_issue")
            if ignore_issue:
                for each_issue in ignore_issue:
                    issue_ids = self.get_issue_ids_for_names(each_issue)
                    if issue_ids:
                        response = None
                        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.10") < 0:
                            response = self.ignore_issue(issue_ids)
                        else:
                            ignore_duration = each_issue.get("ignore_duration")
                            response = self.ignore_issue(issue_ids, ignore_duration)

                        if response and isinstance(response, dict):
                            self.success_list_ignored.append(each_issue)
                            self.issue_ignored.append(response)
                            self.log(
                                "Successfully ignored issue: {0}".format(
                                    self.pprint(self.issue_ignored)
                                ),
                                "INFO",
                            )
                        else:
                            self.failed_list_ignored.append(each_issue)
                            self.log(
                                "Unable to process the issue for: {0}.".format(
                                    self.pprint(self.failed_list_ignored)
                                ),
                                "INFO",
                            )

            suggested_commands = self.want.get("suggested_commands")
            if suggested_commands:
                for each_issue in suggested_commands:
                    issue_ids = self.get_issue_ids_for_names(each_issue)
                    if issue_ids:
                        response = self.execute_commands(issue_ids[0])

                        if response:
                            success_list.append(each_issue)
                            self.cmd_executed.append(response)
                            self.log(
                                "Successfully executed command for issue: {0}".format(
                                    self.pprint(response)
                                ),
                                "INFO",
                            )
                        else:
                            self.cmd_not_executed.append(each_issue)
                            self.log(
                                "Failed to execute command for issue: {0}".format(
                                    self.pprint(self.cmd_not_executed)
                                ),
                                "ERROR",
                            )

            if len(self.success_list_resolved) > 0:
                self.msg = "Issue resolved successfully. '{0}'.".format(
                    str(self.issue_resolved)
                )
                self.changed = True
                self.status = "success"
                self.log(self.msg, "INFO")

            if len(self.failed_list_resolved) > 0:
                self.msg = self.msg + "Unable to resolve the issue: '{0}'.".format(
                    str(self.failed_list_resolved)
                )
                self.log(self.msg, "INFO")

            if len(self.success_list_ignored) > 0:
                self.msg = self.msg + "Issue ignored successfully. '{0}'.".format(
                    str(self.issue_ignored)
                )
                self.changed = True
                self.status = "success"
                self.log(self.msg, "INFO")

            if len(self.failed_list_ignored) > 0:
                self.msg = self.msg + "Unable to ignore the issue: '{0}'.".format(
                    str(self.failed_list_ignored)
                )
                self.log(self.msg, "INFO")

            if len(success_list) > 0:
                self.msg = self.msg + "Command executed successfully for {0}.".format(
                    str(self.cmd_executed)
                )
                self.changed = True
                self.status = "success"

            if len(self.cmd_not_executed) > 0:
                self.msg = self.msg + "Unable to execute the command for {0}.".format(
                    str(self.cmd_not_executed)
                )

            self.log(self.msg, "INFO")
            success_list.extend(self.issue_resolved)
            success_list.extend(self.issue_ignored)
            self.set_operation_result(
                self.status, self.changed, self.msg, "INFO", success_list
            )
        return self

    def get_diff_deleted(self, config):
        """
        Delete user-defined assurance issues in Cisco Catalyst Center based on the playbook details.

        Parameters:
            config (dict): Playbook details containing:
                - assurance_user_defined_issue_settings (list[dict]): A list of user-defined assurance issues to be deleted.

        Returns:
            self: The current object with processed assurance issue details, including success or failure status.
        """
        self.log(
            "Processing deletion of user-defined assurance issues with provided playbook details: {0}".format(
                self.pprint(config)
            ),
            "DEBUG",
        )
        assurance_user_defined_issue_details = config.get(
            "assurance_user_defined_issue_settings"
        )

        if not assurance_user_defined_issue_details:
            self.log("No user-defined assurance issues provided for deletion.", "INFO")
            return self

        self.delete_assurance_issue(assurance_user_defined_issue_details)
        return self

    def deduplicate_by_name(self, items):
        """
        Remove duplicate dictionaries from a list based on the 'name' key.
        Args:
            items (list): A list of dictionaries, each expected to contain a 'name' key.
        Returns:
            list: A list of dictionaries with unique 'name' values, preserving the original order.
        Notes:
            - If an item does not have a 'name' key or the value is None, it will be skipped.
            - Order of first occurrences is maintained.
        """

        if not isinstance(items, list):
            self.log(
                "Invalid input: 'items' is not a list. Returning an empty list.",
                "ERROR",
            )
            return []

        self.log("Starting deduplication process for a list of dictionaries.", "INFO")
        seen_names = set()
        unique_items = []
        for index, item in enumerate(items or []):
            if not isinstance(item, dict):
                self.log(
                    "Skipping item at index {0}: Expected a dictionary, got {1}.".format(
                        index, type(item).__name__
                    ),
                    "WARNING",
                )
                continue

            name = item.get("name")
            if name is None:
                self.log(
                    "Skipping item at index {0}: Missing 'name' key or 'name' is None.".format(
                        index
                    ),
                    "WARNING",
                )
                continue

            if name not in seen_names:
                self.log("Adding unique item with name: '{0}'.".format(name), "DEBUG")
                seen_names.add(name)
                unique_items.append(item)
            else:
                self.log(
                    "Duplicate item with name: '{0}' found. Skipping.".format(name),
                    "DEBUG",
                )

        self.log(
            "Deduplication complete. Original count: {0}, Unique count: {1}.".format(
                len(items or []), len(unique_items)
            ),
            "INFO",
        )
        return unique_items

    def get_valid_assurance_issues(self, items):
        """
        Processes a list of assurance issues and returns:
        - All unique issues (based on 'name')
        - In case of duplicates, only keeps the second and later occurrences

        Args:
            items (list): List of assurance issue dictionaries.

        Returns:
            list: Filtered list containing unique items and second/later duplicates.
        """
        if not isinstance(items, list):
            self.log(
                "Invalid input: 'items' is not a list. Returning an empty list.",
                "ERROR",
            )
            return []

        self.log("Starting processing of assurance issues.", "INFO")
        name_counts = {}
        filtered_items = []

        for index, item in enumerate(items or []):
            # Ensure item is a dictionary
            if not isinstance(item, dict):
                self.log(
                    "Skipping item at index {0}: Expected a dictionary, got {1}.".format(
                        index, type(item).__name__
                    ),
                    "WARNING",
                )
                continue

            # Extract the 'name' key
            name = item.get("name")
            if not name:
                self.log(
                    "Skipping item at index {0}: Missing 'name' key or 'name' is None.".format(
                        index
                    ),
                    "WARNING",
                )
                continue

            # Count occurrences and decide whether to keep the item
            name_counts[name] = name_counts.get(name, 0) + 1
            if name_counts[name] > 1:
                self.log(
                    "Duplicate detected for name '{0}' at index {1}. Keeping this occurrence.".format(
                        name, index
                    ),
                    "DEBUG",
                )
                filtered_items.append(item)
            elif name_counts[name] == 1:
                self.log(
                    "First occurrence of name '{0}' at index {1}. Keeping it for now.".format(
                        name, index
                    ),
                    "DEBUG",
                )
                filtered_items.append(item)

        # Final filtering: Remove first occurrences of duplicates
        unique_and_duplicates = []
        seen = set()

        for item in filtered_items:
            name = item.get("name")
            if name in seen or name_counts[name] == 1:
                unique_and_duplicates.append(item)
            else:
                seen.add(name)

        self.log(
            "Processing complete. Total items: {0}, Filtered items: {1}.".format(
                len(items or []), len(unique_and_duplicates)
            ),
            "INFO",
        )
        return unique_and_duplicates

    def verify_diff_merged(self, config):
        """
        Validate applied Assurance Issue configurations in Cisco Catalyst Center against the playbook details.
        - Checks if user-defined assurance issues were successfully created or updated.
        - Validates if system-defined assurance issues were updated correctly.
        - Verifies the resolution, ignore, or command execution status of specific assurance issues.

        Parameters:
            config (dict): Playbook details containing assurance issue configurations:
                - assurance_user_defined_issue_settings (list[dict]): User-defined assurance issues.
                - assurance_system_issue_settings (list[dict]): System-defined assurance issues.
                - assurance_issue (list[dict]): Specific issues to validate.

        Returns:
            self - self: The current object with validation results, including success or failure status.
        """

        self.log(
            "Validating Assurance Issue configurations against playbook details: {0}".format(
                self.pprint(config)
            ),
            "DEBUG",
        )
        self.all_assurance_issue_details = {}
        # Deduplicate config before get_have
        user_defined_issues = config.get("assurance_user_defined_issue_settings", [])
        deduplicated_issues = self.deduplicate_by_name(user_defined_issues)
        config["assurance_user_defined_issue_settings"] = deduplicated_issues

        self.get_have(config)
        # Deduplicate AFTER validation
        self.want["assurance_user_defined_issue_settings"] = (
            self.get_valid_assurance_issues(
                self.want.get("assurance_user_defined_issue_settings")
            )
        )

        self.log("Current State (have): {0}".format(self.pprint(self.have)), "INFO")
        self.log("Requested State (want): {0}".format(self.pprint(self.want)), "INFO")
        user_defined_issues = config.get("assurance_user_defined_issue_settings")

        if user_defined_issues:
            self.log("Validating user-defined assurance issues.", "DEBUG")
            assurance_user_issue_index = 0
            self.log(
                "Desired State of assurance user issue (want): {0}".format(
                    self.want.get("assurance_user_defined_issue_settings")
                ),
                "DEBUG",
            )
            self.log(
                "Current State of assurance user issue (have): {0}".format(
                    self.have.get("assurance_user_defined_issue_settings")
                ),
                "DEBUG",
            )

            want_issues = self.want.get("assurance_user_defined_issue_settings", [])
            have_issues = self.have.get("assurance_user_defined_issue_settings", [])

            for want_item in want_issues:
                want_name = want_item.get("name")
                matched_have_item = None

                for have_entry in have_issues:
                    assurance_user_issue_details = have_entry.get(
                        "assurance_issue_details", {}
                    )
                    if assurance_user_issue_details.get("name") == want_name:
                        matched_have_item = assurance_user_issue_details
                        break

                self.log(
                    "User-defined issue details: {}".format(matched_have_item), "DEBUG"
                )

                if not matched_have_item:
                    self.msg = (
                        "User-defined assurance issue not found in have: {}".format(
                            want_name
                        )
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if self.requires_update(
                    matched_have_item, want_item, self.user_defined_issue_obj_params
                ):
                    self.msg = "User-defined assurance issue config mismatch in Cisco Catalyst Center for: {}".format(
                        want_name
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

            self.log("User-defined assurance issues validated successfully.", "INFO")
            self.result.get("response")[0].get(
                "assurance_user_defined_issue_settings"
            ).update({"Validation": "Success"})

        system_issues = config.get("assurance_system_issue_settings")

        if system_issues:
            self.log("Validating system-defined assurance issues.", "DEBUG")
            assurance_system_index = 0
            self.log(
                "Desired State of assurance system (want): {0}".format(
                    self.want.get("assurance_system_issue_settings")
                ),
                "DEBUG",
            )
            self.log(
                "Current State of assurance user issue (have): {0}".format(
                    self.have.get("assurance_system_issue_settings")
                ),
                "DEBUG",
            )
            for item in self.want.get("assurance_system_issue_settings"):
                assurance_system_details = self.have.get(
                    "assurance_system_issue_settings"
                )[assurance_system_index]
                self.log(
                    "System-defined issue details: {}".format(assurance_system_details)
                )

                if self.requires_update(
                    assurance_system_details, item, self.system_issue_obj_params
                ):
                    self.msg = "System-defined assurance issue config mismatch in Cisco Catalyst Center."
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                assurance_system_index += 1

            self.log("System-defined assurance issues validated successfully.", "INFO")
            self.result.get("response")[1].get(
                "assurance_system_issue_settings"
            ).update({"Validation": "Success"})

        assurance_issue = config.get("assurance_issue", [])
        if not assurance_issue:
            self.log("No specific assurance issues provided in the playbook.", "INFO")
            return self

        self.log("Processing specific assurance issues.", "DEBUG")

        if assurance_issue and len(assurance_issue) > 0:
            responses = {}
            responses = {"input_issue_config": assurance_issue}
            self.msg = ""
            self.changed = False
            self.status = "failed"

            if self.success_list_resolved or self.failed_list_resolved:
                response = {
                    "processed_issues_resolved": self.success_list_resolved,
                    "unprocessed_issues_resolved": self.failed_list_resolved,
                    "processed_logs_resolved": self.issue_resolved,
                }

                if self.success_list_resolved == assurance_issue:
                    self.msg = (
                        "Issue resolution verified successfully for '{0}'.".format(
                            str(self.success_list_resolved)
                        )
                    )
                    self.log(self.msg, "INFO")
                    self.changed = True
                    self.status = "success"
                else:
                    self.msg = (
                        self.msg
                        + "Unable to verify Issue resolution for '{0}'.".format(
                            str(assurance_issue)
                        )
                    )
                    self.log(self.msg, "INFO")

                responses["issue_resolved"] = response

            if len(self.success_list_ignored) > 0 or len(self.failed_list_ignored) > 0:
                response = {
                    "processed_issues_ignored": self.success_list_ignored,
                    "unprocessed_issues_ignored": self.failed_list_ignored,
                    "processed_logs_ignored": self.issue_ignored,
                }

                if self.success_list_ignored == assurance_issue:
                    self.msg = (
                        self.msg
                        + "Issue ignored verified successfully for '{0}'.".format(
                            str(self.success_list_ignored)
                        )
                    )
                    self.log(self.msg, "INFO")
                    self.changed = True
                    self.status = "success"
                else:
                    self.msg = (
                        self.msg
                        + "Unable to verify Issue resolution for '{0}'.".format(
                            str(assurance_issue)
                        )
                    )
                    self.log(self.msg, "INFO")

                responses["issue_ignored"] = response

            if self.cmd_executed or self.cmd_not_executed:
                response = {
                    "processed_command_execution": self.cmd_executed,
                    "unprocessed_command_execution": self.cmd_not_executed,
                }

                if len(self.cmd_executed) > 0:
                    self.msg += "Command execution verified successfully. "
                    self.log(self.msg, "INFO")
                    self.changed = True
                    self.status = "success"
                else:
                    self.msg += "Command execution verification failed. "
                    self.log(self.msg, "INFO")

                responses["command_executed"] = response

            if self.no_issues:
                self.msg += "No issues found to resolve or ignore. All issues are already cleared: {0}".format(
                    self.no_issues)
                self.changed = False
                self.status = "success"

            self.set_operation_result(
                self.status, self.changed, self.msg, "INFO", responses
            ).check_return_status()

        self.msg = "Successfully validated the Assurance issue."
        self.status = "success"
        return self

    def verify_diff_deleted(self, config):
        """
        Verify that user-defined assurance issues were successfully deleted from Cisco Catalyst Center.
            - Checks if the specified user-defined assurance issues no longer exist.
            - Logs validation results and updates the response accordingly.

        Parameters:
            config (dict): Playbook details containing:
                - assurance_user_defined_issue_settings (list[dict]): User-defined assurance issues expected to be deleted.

        Returns:
            self: The current object with validation results, including success or failure status.
        """
        self.log(
            "Verifying deletion of user-defined assurance issues with provided playbook details: {0}".format(
                self.pprint(config)
            ),
            "DEBUG",
        )
        self.all_assurance_user_issue_details = {}
        assurance_issues = config.get("assurance_user_defined_issue_settings")

        if not assurance_issues:
            self.log(
                "No user-defined assurance issues provided for deletion verification.",
                "INFO",
            )
            return self
        if config.get("assurance_user_defined_issue_settings") is not None:
            self.get_have(config)
            self.log("Current State (have): {0}".format(self.have), "INFO")
            self.log("Desired State (want): {0}".format(self.want), "INFO")
            assurance_issue_index = 0
            assurance_issue_details = self.have.get(
                "assurance_user_defined_issue_settings"
            )
            if not assurance_issue_details:
                self.log(
                    "No user-defined assurance issues found in Cisco Catalyst Center. Validation successful.",
                    "INFO",
                )
                self.result["response"][0][
                    "assurance_user_defined_issue_settings"
                ].update({"Validation": "Success"})
                self.status = "success"
                return self

            for item in assurance_issue_details:
                assurance_issue_exists = item.get("exists")
                name = config.get("assurance_user_defined_issue_settings")[
                    assurance_issue_index
                ].get("name")
                if assurance_issue_exists:
                    self.msg = "User-defined assurance issue '{0}' still exists in Cisco Catalyst Center.".format(
                        name
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                self.log(
                    "Successfully verified that user-defined assurance issue '{0}' is deleted.".format(
                        name
                    ),
                    "INFO",
                )
                assurance_issue_index += 1
            self.result.get("response")[0].get(
                "assurance_user_defined_issue_settings"
            ).update({"Validation": "Success"})

        self.msg = "Successfully validated deletion of user-defined assurance issues."
        self.status = "success"
        return self

    def update_issue_status_messages(self):
        """
        Updates the issue status messages for Cisco Catalyst Center.

        Args:
            self (object): Instance of the class containing attributes for issue statuses.

        Attributes:
            self.create_issue (list): List of issues created.
            self.update_issue (list): List of issues updated.
            self.no_update_issue (list): List of issues that require no update.
            self.issue_resolved (list): List of resolved issues.
            self.issue_ignored (list): List of ignored issues.
            self.issues_active (list): List of active (unresolved) issues.
            self.success_list_resolved (list): List of successfully resolved issues.
            self.failed_list_resolved (list): List of issues that failed to resolve.
            self.success_list_ignored (list): List of successfully ignored issues.
            self.failed_list_ignored (list): List of issues that failed to be ignored.
            self.cmd_executed (list): List of successfully executed command actions.
            self.cmd_not_executed (list): List of command actions that failed to execute.
            self.issue_processed (list): List of processed issues.

        Returns:
            self (object): An instance of a class representing the operation status,
                indicating success or failure and any error messages encountered.

        Description:
            This method constructs and logs messages based on issue-related actions such as creation, updates,
            resolution, and ignored issues. It updates the `self.result` dictionary to indicate changes
            and compiles the messages into a single response string.
        """

        self.result["changed"] = False
        result_msg_list = []

        if self.issue_resolved:
            issue_resolved_msg = (
                "Issue(s) '{}' resolved successfully in Cisco Catalyst Center.".format(
                    self.issue_resolved
                )
            )
            result_msg_list.append(issue_resolved_msg)

        if self.issue_ignored:
            issue_ignored_msg = (
                "Issue(s) '{}' ignored successfully in Cisco Catalyst Center.".format(
                    self.issue_ignored
                )
            )
            result_msg_list.append(issue_ignored_msg)

        if self.issues_active:
            issues_active_msg = (
                "Issue(s) '{}' remain active in Cisco Catalyst Center.".format(
                    self.issues_active
                )
            )
            result_msg_list.append(issues_active_msg)

        if self.success_list_resolved:
            success_resolved_msg = "Successfully resolved issues: {}.".format(
                self.success_list_resolved
            )
            result_msg_list.append(success_resolved_msg)

        if self.failed_list_resolved:
            failed_resolved_msg = "Failed to resolve issues: {}.".format(
                self.failed_list_resolved
            )
            result_msg_list.append(failed_resolved_msg)

        if self.success_list_ignored:
            success_ignored_msg = "Successfully ignored issues: {}.".format(
                self.success_list_ignored
            )
            result_msg_list.append(success_ignored_msg)

        if self.failed_list_ignored:
            failed_ignored_msg = "Failed to ignore issues: {}.".format(
                self.failed_list_ignored
            )
            result_msg_list.append(failed_ignored_msg)

        if self.cmd_executed:
            cmd_executed_msg = (
                "Successfully executed command(s) for issues: {}.".format(
                    self.cmd_executed
                )
            )
            result_msg_list.append(cmd_executed_msg)

        if self.cmd_not_executed:
            cmd_not_executed_msg = (
                "Failed to execute command(s) for issues: {}.".format(
                    self.cmd_not_executed
                )
            )
            result_msg_list.append(cmd_not_executed_msg)

        if self.issue_processed:
            issue_processed_msg = "Issue(s) '{}' have been processed.".format(
                self.issue_processed
            )
            result_msg_list.append(issue_processed_msg)

        if any(
            [
                self.issue_resolved,
                self.issue_ignored,
                self.success_list_resolved,
                self.failed_list_resolved,
                self.success_list_ignored,
                self.failed_list_ignored,
                self.cmd_executed,
                self.cmd_not_executed,
            ]
        ):
            self.result["changed"] = True

        self.msg = " ".join(result_msg_list)
        self.log(self.msg, "INFO")
        self.result["response"] = self.msg

        return self


def main():
    """main entry point for module execution"""

    # Define the specification for module arguments
    element_spec = {
        "dnac_host": {"type": "str", "required": True},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"type": "list", "required": True, "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
        "validate_response_schema": {"type": "bool", "default": True},
    }

    # Create an AnsibleModule object with argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_assurance = AssuranceSettings(module)
    state = ccc_assurance.params.get("state")

    # Validate Cisco Catalyst Center (CCC) Version Support
    current_version = ccc_assurance.get_ccc_version()
    required_version = "2.3.7.6"

    if ccc_assurance.compare_dnac_versions(current_version, required_version) < 0:
        ccc_assurance.status = "failed"
        ccc_assurance.msg = (
            "The specified version '{0}' does not support the assurance issue settings workflow feature. "
            "Supported versions start from '{1}' onwards.".format(
                current_version, required_version
            )
        )
        ccc_assurance.log(ccc_assurance.msg, "ERROR")
        ccc_assurance.check_return_status()

    if state not in ccc_assurance.supported_states:
        ccc_assurance.status = "invalid"
        ccc_assurance.msg = "State {0} is invalid".format(state)
        ccc_assurance.check_return_status()

    ccc_assurance.validate_input().check_return_status()
    config_verify = ccc_assurance.params.get("config_verify")

    for config in ccc_assurance.config:
        ccc_assurance.reset_values()
        ccc_assurance.get_have(config).check_return_status()
        ccc_assurance.get_want(config).check_return_status()
        ccc_assurance.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_assurance.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_assurance.result)

    # Invoke the API to check the status and log the output of each assurance issue on the console
    ccc_assurance.update_issue_status_messages().check_return_status()


if __name__ == "__main__":
    main()
