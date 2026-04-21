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
module: fortios_system_global
short_description: Configure global attributes in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and global category.
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

    system_global:
        description:
            - Configure global attributes.
        default: null
        type: dict
        suboptions:
            admin_concurrent:
                description:
                    - Enable/disable concurrent administrator logins. Use policy-auth-concurrent for firewall authenticated users.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_console_timeout:
                description:
                    - Console login timeout that overrides the admin timeout value (15 - 300 seconds).
                type: int
            admin_forticloud_sso_default_profile:
                description:
                    - Override access profile. Source system.accprofile.name.
                type: str
            admin_forticloud_sso_login:
                description:
                    - Enable/disable FortiCloud admin login via SSO.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_host:
                description:
                    - Administrative host for HTTP and HTTPS. When set, will be used in lieu of the client"s Host header for any redirection.
                type: str
            admin_hsts_max_age:
                description:
                    - HTTPS Strict-Transport-Security header max-age in seconds. A value of 0 will reset any HSTS records in the browser.When
                       admin-https-redirect is disabled the header max-age will be 0.
                type: int
            admin_https_pki_required:
                description:
                    - Enable/disable admin login method. Enable to force administrators to provide a valid certificate to log in if PKI is enabled. Disable to
                       allow administrators to log in with a certificate or password.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_https_redirect:
                description:
                    - Enable/disable redirection of HTTP administration access to HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_https_ssl_banned_ciphers:
                description:
                    - Select one or more cipher technologies that cannot be used in GUI HTTPS negotiations. Only applies to TLS 1.2 and below.
                type: list
                elements: str
                choices:
                    - 'RSA'
                    - 'DHE'
                    - 'ECDHE'
                    - 'DSS'
                    - 'ECDSA'
                    - 'AES'
                    - 'AESGCM'
                    - 'CAMELLIA'
                    - '3DES'
                    - 'SHA1'
                    - 'SHA256'
                    - 'SHA384'
                    - 'STATIC'
                    - 'CHACHA20'
                    - 'ARIA'
                    - 'AESCCM'
            admin_https_ssl_ciphersuites:
                description:
                    - Select one or more TLS 1.3 ciphersuites to enable. Does not affect ciphers in TLS 1.2 and below. At least one must be enabled. To
                       disable all, remove TLS1.3 from admin-https-ssl-versions.
                type: list
                elements: str
                choices:
                    - 'TLS-AES-128-GCM-SHA256'
                    - 'TLS-AES-256-GCM-SHA384'
                    - 'TLS-CHACHA20-POLY1305-SHA256'
                    - 'TLS-AES-128-CCM-SHA256'
                    - 'TLS-AES-128-CCM-8-SHA256'
            admin_https_ssl_versions:
                description:
                    - Allowed TLS versions for web administration.
                type: list
                elements: str
                choices:
                    - 'tlsv1-1'
                    - 'tlsv1-2'
                    - 'tlsv1-3'
                    - 'tlsv1-0'
            admin_lockout_duration:
                description:
                    - Amount of time in seconds that an administrator account is locked out after reaching the admin-lockout-threshold for repeated failed
                       login attempts.
                type: int
            admin_lockout_threshold:
                description:
                    - Number of failed login attempts before an administrator account is locked out for the admin-lockout-duration.
                type: int
            admin_login_max:
                description:
                    - Maximum number of administrators who can be logged in at the same time (1 - 100).
                type: int
            admin_maintainer:
                description:
                    - Enable/disable maintainer administrator login. When enabled, the maintainer account can be used to log in from the console after a hard
                       reboot. The password is "bcpb" followed by the FortiGate unit serial number. You have limited time to complete this login.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_port:
                description:
                    - Administrative access port for HTTP. (1 - 65535).
                type: int
            admin_restrict_local:
                description:
                    - Enable/disable local admin authentication restriction when remote authenticator is up and running .
                type: str
                choices:
                    - 'all'
                    - 'non-console-only'
                    - 'disable'
                    - 'enable'
            admin_scp:
                description:
                    - Enable/disable SCP support for system configuration backup, restore, and firmware file upload.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_server_cert:
                description:
                    - Server certificate that the FortiGate uses for HTTPS administrative connections. Source certificate.local.name.
                type: str
            admin_sport:
                description:
                    - Administrative access port for HTTPS. (1 - 65535).
                type: int
            admin_ssh_grace_time:
                description:
                    - Maximum time in seconds permitted between making an SSH connection to the FortiGate unit and authenticating (10 - 3600 sec (1 hour)).
                type: int
            admin_ssh_password:
                description:
                    - Enable/disable password authentication for SSH admin access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_ssh_port:
                description:
                    - Administrative access port for SSH. (1 - 65535).
                type: int
            admin_ssh_v1:
                description:
                    - Enable/disable SSH v1 compatibility.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_telnet:
                description:
                    - Enable/disable TELNET service.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            admin_telnet_port:
                description:
                    - Administrative access port for TELNET. (1 - 65535).
                type: int
            admintimeout:
                description:
                    - Number of minutes before an idle administrator session times out (1 - 480 minutes (8 hours)). A shorter idle timeout is more secure.
                type: int
            alias:
                description:
                    - Alias for your FortiGate unit.
                type: str
            allow_traffic_redirect:
                description:
                    - Disable to prevent traffic with same local ingress and egress interface from being forwarded without policy check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            anti_replay:
                description:
                    - Level of checking for packet replay and TCP sequence checking.
                type: str
                choices:
                    - 'disable'
                    - 'loose'
                    - 'strict'
            application_bandwidth_tracking:
                description:
                    - Enable/disable application bandwidth tracking.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            arp_max_entry:
                description:
                    - Maximum number of dynamically learned MAC addresses that can be added to the ARP table (131072 - 2147483647).
                type: int
            asymroute:
                description:
                    - Enable/disable asymmetric route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_cert:
                description:
                    - Server certificate that the FortiGate uses for HTTPS firewall authentication connections. Source certificate.local.name.
                type: str
            auth_http_port:
                description:
                    - User authentication HTTP port. (1 - 65535).
                type: int
            auth_https_port:
                description:
                    - User authentication HTTPS port. (1 - 65535).
                type: int
            auth_ike_saml_port:
                description:
                    - User IKE SAML authentication port (0 - 65535).
                type: int
            auth_keepalive:
                description:
                    - Enable to prevent user authentication sessions from timing out when idle.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_session_auto_backup:
                description:
                    - Enable/disable automatic and periodic backup of authentication sessions . Sessions are restored upon bootup.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_session_auto_backup_interval:
                description:
                    - Configure automatic authentication session backup interval .
                type: str
                choices:
                    - '1min'
                    - '5min'
                    - '15min'
                    - '30min'
                    - '1hr'
            auth_session_limit:
                description:
                    - Action to take when the number of allowed user authenticated sessions is reached.
                type: str
                choices:
                    - 'block-new'
                    - 'logout-inactive'
            auto_auth_extension_device:
                description:
                    - Enable/disable automatic authorization of dedicated Fortinet extension devices.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            autorun_log_fsck:
                description:
                    - Enable/disable automatic log partition check after ungraceful shutdown.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            av_affinity:
                description:
                    - Affinity setting for AV scanning (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx).
                type: str
            av_failopen:
                description:
                    - Set the action to take if the FortiGate is running low on memory or the proxy connection limit has been reached.
                type: str
                choices:
                    - 'pass'
                    - 'off'
                    - 'one-shot'
            av_failopen_session:
                description:
                    - When enabled and a proxy for a protocol runs out of room in its session table, that protocol goes into failopen mode and enacts the
                       action specified by av-failopen.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            batch_cmdb:
                description:
                    - Enable/disable batch mode, allowing you to enter a series of CLI commands that will execute as a group once they are loaded.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            bfd_affinity:
                description:
                    - Affinity setting for BFD daemon (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx).
                type: str
            block_session_timer:
                description:
                    - Duration in seconds for blocked sessions (1 - 300 sec  (5 minutes)).
                type: int
            br_fdb_max_entry:
                description:
                    - Maximum number of bridge forwarding database (FDB) entries.
                type: int
            cert_chain_max:
                description:
                    - Maximum number of certificates that can be traversed in a certificate chain.
                type: int
            cfg_revert_timeout:
                description:
                    - Time-out for reverting to the last saved configuration. (10 - 4294967295 seconds).
                type: int
            cfg_save:
                description:
                    - Configuration file save mode for CLI changes.
                type: str
                choices:
                    - 'automatic'
                    - 'manual'
                    - 'revert'
            check_protocol_header:
                description:
                    - Level of checking performed on protocol headers. Strict checking is more thorough but may affect performance. Loose checking is OK in
                       most cases.
                type: str
                choices:
                    - 'loose'
                    - 'strict'
            check_reset_range:
                description:
                    - Configure ICMP error message verification. You can either apply strict RST range checking or disable it.
                type: str
                choices:
                    - 'strict'
                    - 'disable'
            cli_audit_log:
                description:
                    - Enable/disable CLI audit log.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cloud_communication:
                description:
                    - Enable/disable all cloud communication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            clt_cert_req:
                description:
                    - Enable/disable requiring administrators to have a client certificate to log into the GUI using HTTPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cmdbsvr_affinity:
                description:
                    - Affinity setting for cmdbsvr (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx).
                type: str
            compliance_check:
                description:
                    - Enable/disable global PCI DSS compliance check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            compliance_check_time:
                description:
                    - Time of day to run scheduled PCI DSS compliance checks.
                type: str
            cpu_use_threshold:
                description:
                    - Threshold at which CPU usage is reported (% of total CPU).
                type: int
            csr_ca_attribute:
                description:
                    - Enable/disable the CA attribute in certificates. Some CA servers reject CSRs that have the CA attribute.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            daily_restart:
                description:
                    - Enable/disable daily restart of FortiGate unit. Use the restart-time option to set the time of day for the restart.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_service_source_port:
                description:
                    - Default service source port range .
                type: str
            delay_tcp_npu_session:
                description:
                    - Enable TCP NPU session delay to guarantee packet order of 3-way handshake.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            device_identification_active_scan_delay:
                description:
                    - Number of seconds to passively scan a device before performing an active scan. (20 - 3600 sec, (20 sec to 1 hour)).
                type: int
            device_idle_timeout:
                description:
                    - Time in seconds that a device must be idle to automatically log the device user out. (30 - 31536000 sec (30 sec to 1 year)).
                type: int
            dh_params:
                description:
                    - Number of bits to use in the Diffie-Hellman exchange for HTTPS/SSH protocols.
                type: str
                choices:
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
                    - '6144'
                    - '8192'
            dhcp_lease_backup_interval:
                description:
                    - DHCP leases backup interval in seconds (10 - 3600).
                type: int
            dnsproxy_worker_count:
                description:
                    - DNS proxy worker count. For a FortiGate with multiple logical CPUs, you can set the DNS process number from 1 to the number of logical
                       CPUs.
                type: int
            dst:
                description:
                    - Enable/disable daylight saving time.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            early_tcp_npu_session:
                description:
                    - Enable/disable early TCP NPU session.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            edit_vdom_prompt:
                description:
                    - Enable/disable edit new VDOM prompt.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            endpoint_control_fds_access:
                description:
                    - Enable/disable access to the FortiGuard network for non-compliant endpoints.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            endpoint_control_portal_port:
                description:
                    - Endpoint control portal port (1 - 65535).
                type: int
            extender_controller_reserved_network:
                description:
                    - Configure reserved network subnet for managed LAN extension FortiExtender units. This is available when the FortiExtender daemon is
                       running.
                type: str
            failtime:
                description:
                    - Fail-time for server lost.
                type: int
            faz_disk_buffer_size:
                description:
                    - Maximum disk buffer size to temporarily store logs destined for FortiAnalyzer. To be used in the event that FortiAnalyzer is unavailable.
                type: int
            fds_statistics:
                description:
                    - Enable/disable sending IPS, Application Control, and AntiVirus data to FortiGuard. This data is used to improve FortiGuard services and
                       is not shared with external parties and is protected by Fortinet"s privacy policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fds_statistics_period:
                description:
                    - FortiGuard statistics collection period in minutes. (1 - 1440 min (1 min to 24 hours)).
                type: int
            fec_port:
                description:
                    - Local UDP port for Forward Error Correction (49152 - 65535).
                type: int
            fgd_alert_subscription:
                description:
                    - Type of alert to retrieve from FortiGuard.
                type: list
                elements: str
                choices:
                    - 'advisory'
                    - 'latest-threat'
                    - 'latest-virus'
                    - 'latest-attack'
                    - 'new-antivirus-db'
                    - 'new-attack-db'
            forticarrier_bypass:
                description:
                    - Enable/disable forticarrier-bypass.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forticonverter_config_upload:
                description:
                    - Enable/disable config upload to FortiConverter.
                type: str
                choices:
                    - 'once'
                    - 'disable'
            forticonverter_integration:
                description:
                    - Enable/disable FortiConverter integration service.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortiextender:
                description:
                    - Enable/disable FortiExtender.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            fortiextender_data_port:
                description:
                    - FortiExtender data port (1024 - 49150).
                type: int
            fortiextender_discovery_lockdown:
                description:
                    - Enable/disable FortiExtender CAPWAP lockdown.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            fortiextender_provision_on_authorization:
                description:
                    - Enable/disable automatic provisioning of latest FortiExtender firmware on authorization.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortiextender_vlan_mode:
                description:
                    - Enable/disable FortiExtender VLAN mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortigslb_integration:
                description:
                    - Enable/disable integration with the FortiGSLB cloud service.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            fortiipam_integration:
                description:
                    - Enable/disable integration with the FortiIPAM cloud service.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortiservice_port:
                description:
                    - FortiService port (1 - 65535). Used by FortiClient endpoint compliance. Older versions of FortiClient used a different port.
                type: int
            fortitoken_cloud:
                description:
                    - Enable/disable FortiToken Cloud service.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortitoken_cloud_push_status:
                description:
                    - Enable/disable FTM push service of FortiToken Cloud.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortitoken_cloud_region:
                description:
                    - Region domain of FortiToken Cloud(unset to non-region).
                type: str
            fortitoken_cloud_sync_interval:
                description:
                    - Interval in which to clean up remote users in FortiToken Cloud (0 - 336 hours (14 days)).
                type: int
            gui_allow_default_hostname:
                description:
                    - Enable/disable the factory default hostname warning on the GUI setup wizard.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_allow_incompatible_fabric_fgt:
                description:
                    - Enable/disable Allow FGT with incompatible firmware to be treated as compatible in security fabric on the GUI. May cause unexpected
                       error.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_app_detection_sdwan:
                description:
                    - Enable/disable Allow app-detection based SD-WAN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_auto_upgrade_setup_warning:
                description:
                    - Enable/disable the automatic patch upgrade setup prompt on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_cdn_domain_override:
                description:
                    - Domain of CDN server.
                type: str
            gui_cdn_usage:
                description:
                    - Enable/disable Load GUI static files from a CDN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_certificates:
                description:
                    - Enable/disable the System > Certificate GUI page, allowing you to add and configure certificates from the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_custom_language:
                description:
                    - Enable/disable custom languages in GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_date_format:
                description:
                    - Default date format used throughout GUI.
                type: str
                choices:
                    - 'yyyy/MM/dd'
                    - 'dd/MM/yyyy'
                    - 'MM/dd/yyyy'
                    - 'yyyy-MM-dd'
                    - 'dd-MM-yyyy'
                    - 'MM-dd-yyyy'
            gui_date_time_source:
                description:
                    - Source from which the FortiGate GUI uses to display date and time entries.
                type: str
                choices:
                    - 'system'
                    - 'browser'
            gui_device_latitude:
                description:
                    - Add the latitude of the location of this FortiGate to position it on the Threat Map.
                type: str
            gui_device_longitude:
                description:
                    - Add the longitude of the location of this FortiGate to position it on the Threat Map.
                type: str
            gui_display_hostname:
                description:
                    - Enable/disable displaying the FortiGate"s hostname on the GUI login page.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_firmware_upgrade_warning:
                description:
                    - Enable/disable the firmware upgrade warning on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_forticare_registration_setup_warning:
                description:
                    - Enable/disable the FortiCare registration setup warning on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_fortigate_cloud_sandbox:
                description:
                    - Enable/disable displaying FortiGate Cloud Sandbox on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_fortiguard_resource_fetch:
                description:
                    - Enable/disable retrieving static GUI resources from FortiGuard. Disabling it will improve GUI load time for air-gapped environments.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_fortisandbox_cloud:
                description:
                    - Enable/disable displaying FortiSandbox Cloud on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_ipv6:
                description:
                    - Enable/disable IPv6 settings on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_lines_per_page:
                description:
                    - Number of lines to display per page for web administration.
                type: int
            gui_local_out:
                description:
                    - Enable/disable Local-out traffic on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_replacement_message_groups:
                description:
                    - Enable/disable replacement message groups on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_rest_api_cache:
                description:
                    - Enable/disable REST API result caching on FortiGate.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_theme:
                description:
                    - Color scheme for the administration GUI.
                type: str
                choices:
                    - 'jade'
                    - 'neutrino'
                    - 'mariner'
                    - 'graphite'
                    - 'melongene'
                    - 'jet-stream'
                    - 'security-fabric'
                    - 'retro'
                    - 'dark-matter'
                    - 'onyx'
                    - 'eclipse'
                    - 'green'
                    - 'blue'
                    - 'red'
            gui_wireless_opensecurity:
                description:
                    - Enable/disable wireless open security option on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gui_workflow_management:
                description:
                    - Enable/disable Workflow management features on the GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ha_affinity:
                description:
                    - Affinity setting for HA daemons (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx).
                type: str
            honor_df:
                description:
                    - Enable/disable honoring of Don"t-Fragment (DF) flag.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            hostname:
                description:
                    - FortiGate unit"s hostname. Most models will truncate names longer than 24 characters. Some models support hostnames up to 35 characters.
                type: str
            httpd_max_worker_count:
                description:
                    - Maximum number of simultaneous HTTP requests that will be served. This number may affect GUI and REST API performance (0 - 128).
                type: int
            igmp_state_limit:
                description:
                    - Maximum number of IGMP memberships (96 - 64000).
                type: int
            interface_subnet_usage:
                description:
                    - Enable/disable allowing use of interface-subnet setting in firewall addresses .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_database:
                description:
                    - Configure which Internet Service database size to download from FortiGuard and use.
                type: str
                choices:
                    - 'mini'
                    - 'standard'
                    - 'full'
                    - 'on-demand'
            internet_service_download_list:
                description:
                    - Configure which on-demand Internet Service IDs are to be downloaded.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Internet Service ID. see <a href='#notes'>Notes</a>. Source firewall.internet-service.id.
                        required: true
                        type: int
            interval:
                description:
                    - Dead gateway detection interval.
                type: int
            ip_conflict_detection:
                description:
                    - Enable/disable logging of IPv4 address conflict detection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ip_fragment_mem_thresholds:
                description:
                    - Maximum memory (MB) used to reassemble IPv4/IPv6 fragments.
                type: int
            ip_fragment_timeout:
                description:
                    - Timeout value in seconds for any fragment not being reassembled
                type: int
            ip_src_port_range:
                description:
                    - IP source port range used for traffic originating from the FortiGate unit.
                type: str
            ips_affinity:
                description:
                    - Affinity setting for IPS (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx; allowed CPUs must be less than total
                       number of IPS engine daemons).
                type: str
            ipsec_asic_offload:
                description:
                    - Enable/disable ASIC offloading (hardware acceleration) for IPsec VPN traffic. Hardware acceleration can offload IPsec VPN sessions and
                       accelerate encryption and decryption.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipsec_ha_seqjump_rate:
                description:
                    - ESP jump ahead rate (1G - 10G pps equivalent).
                type: int
            ipsec_hmac_offload:
                description:
                    - Enable/disable offloading (hardware acceleration) of HMAC processing for IPsec VPN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipsec_qat_offload:
                description:
                    - Enable/disable QAT offloading (Intel QuickAssist) for IPsec VPN traffic. QuickAssist can accelerate IPsec encryption and decryption.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipsec_round_robin:
                description:
                    - Enable/disable round-robin redistribution to multiple CPUs for IPsec VPN traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipsec_soft_dec_async:
                description:
                    - Enable/disable software decryption asynchronization (using multiple CPUs to do decryption) for IPsec VPN traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_accept_dad:
                description:
                    - Enable/disable acceptance of IPv6 Duplicate Address Detection (DAD).
                type: int
            ipv6_allow_anycast_probe:
                description:
                    - Enable/disable IPv6 address probe through Anycast.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_allow_local_in_silent_drop:
                description:
                    - Enable/disable silent drop of IPv6 local-in traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_allow_local_in_slient_drop:
                description:
                    - Enable/disable silent drop of IPv6 local-in traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_allow_multicast_probe:
                description:
                    - Enable/disable IPv6 address probe through Multicast.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_allow_traffic_redirect:
                description:
                    - Disable to prevent IPv6 traffic with same local ingress and egress interface from being forwarded without policy check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6_fragment_timeout:
                description:
                    - Timeout value in seconds for any IPv6 fragment not being reassembled
                type: int
            ipv6_snat_route_change:
                description:
                    - Enable/disable the ability to change the IPv6 source NAT route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            irq_time_accounting:
                description:
                    - Configure CPU IRQ time accounting mode.
                type: str
                choices:
                    - 'auto'
                    - 'force'
            language:
                description:
                    - GUI display language.
                type: str
                choices:
                    - 'english'
                    - 'french'
                    - 'spanish'
                    - 'portuguese'
                    - 'japanese'
                    - 'trach'
                    - 'simch'
                    - 'korean'
            ldapconntimeout:
                description:
                    - Global timeout for connections with remote LDAP servers in milliseconds (1 - 300000).
                type: int
            lldp_reception:
                description:
                    - Enable/disable Link Layer Discovery Protocol (LLDP) reception.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            lldp_transmission:
                description:
                    - Enable/disable Link Layer Discovery Protocol (LLDP) transmission.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_single_cpu_high:
                description:
                    - Enable/disable logging the event of a single CPU core reaching CPU usage threshold.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_ssl_connection:
                description:
                    - Enable/disable logging of SSL connection events.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_uuid:
                description:
                    - Whether UUIDs are added to traffic logs. You can disable UUIDs, add firewall policy UUIDs to traffic logs, or add all UUIDs to traffic
                       logs.
                type: str
                choices:
                    - 'disable'
                    - 'policy-only'
                    - 'extended'
            log_uuid_address:
                description:
                    - Enable/disable insertion of address UUIDs to traffic logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_uuid_policy:
                description:
                    - Enable/disable insertion of policy UUIDs to traffic logs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            login_timestamp:
                description:
                    - Enable/disable login time recording.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            long_vdom_name:
                description:
                    - Enable/disable long VDOM name support.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            management_ip:
                description:
                    - Management IP address of this FortiGate. Used to log into this FortiGate from another FortiGate in the Security Fabric.
                type: str
            management_port:
                description:
                    - Overriding port for management connection (Overrides admin port).
                type: int
            management_port_use_admin_sport:
                description:
                    - Enable/disable use of the admin-sport setting for the management port. If disabled, FortiGate will allow user to specify management-port.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            management_vdom:
                description:
                    - Management virtual domain name. Source system.vdom.name.
                type: str
            max_dlpstat_memory:
                description:
                    - Maximum DLP stat memory (0 - 4294967295).
                type: int
            max_route_cache_size:
                description:
                    - Maximum number of IP route cache entries (0 - 2147483647).
                type: int
            mc_ttl_notchange:
                description:
                    - Enable/disable no modification of multicast TTL.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            memory_use_threshold_extreme:
                description:
                    - Threshold at which memory usage is considered extreme (new sessions are dropped) (% of total RAM).
                type: int
            memory_use_threshold_green:
                description:
                    - Threshold at which memory usage forces the FortiGate to exit conserve mode (% of total RAM).
                type: int
            memory_use_threshold_red:
                description:
                    - Threshold at which memory usage forces the FortiGate to enter conserve mode (% of total RAM).
                type: int
            miglog_affinity:
                description:
                    - Affinity setting for logging (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx).
                type: str
            miglogd_children:
                description:
                    - Number of logging (miglogd) processes to be allowed to run. Higher number can reduce performance; lower number can slow log processing
                       time.
                type: int
            multi_factor_authentication:
                description:
                    - Enforce all login methods to require an additional authentication factor .
                type: str
                choices:
                    - 'optional'
                    - 'mandatory'
            multicast_forward:
                description:
                    - Enable/disable multicast forwarding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ndp_max_entry:
                description:
                    - Maximum number of NDP table entries (set to 65,536 or higher; if set to 0, kernel holds 65,536 entries).
                type: int
            npu_neighbor_update:
                description:
                    - Enable/disable sending of ARP/ICMP6 probing packets to update neighbors for offloaded sessions.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            per_user_bal:
                description:
                    - Enable/disable per-user block/allow list filter.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            per_user_bwl:
                description:
                    - Enable/disable per-user black/white list filter.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            pmtu_discovery:
                description:
                    - Enable/disable path MTU discovery.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            policy_auth_concurrent:
                description:
                    - Number of concurrent firewall use logins from the same user (1 - 100).
                type: int
            post_login_banner:
                description:
                    - Enable/disable displaying the administrator access disclaimer message after an administrator successfully logs in.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            pre_login_banner:
                description:
                    - Enable/disable displaying the administrator access disclaimer message on the login page before an administrator logs in.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            private_data_encryption:
                description:
                    - Enable/disable private data encryption using an AES 128-bit key or passpharse.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            proxy_auth_lifetime:
                description:
                    - Enable/disable authenticated users lifetime control. This is a cap on the total time a proxy user can be authenticated for after which
                       re-authentication will take place.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            proxy_auth_lifetime_timeout:
                description:
                    - Lifetime timeout in minutes for authenticated users (5  - 65535 min).
                type: int
            proxy_auth_timeout:
                description:
                    - Authentication timeout in minutes for authenticated users (1 - 10000 min).
                type: int
            proxy_cert_use_mgmt_vdom:
                description:
                    - Enable/disable using management VDOM to send requests.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            proxy_cipher_hardware_acceleration:
                description:
                    - Enable/disable using content processor (CP8 or CP9) hardware acceleration to encrypt and decrypt IPsec and SSL traffic.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            proxy_hardware_acceleration:
                description:
                    - Enable/disable email proxy hardware acceleration.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            proxy_keep_alive_mode:
                description:
                    - Control if users must re-authenticate after a session is closed, traffic has been idle, or from the point at which the user was
                       authenticated.
                type: str
                choices:
                    - 'session'
                    - 'traffic'
                    - 're-authentication'
            proxy_kxp_hardware_acceleration:
                description:
                    - Enable/disable using the content processor to accelerate KXP traffic.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            proxy_re_authentication_mode:
                description:
                    - Control if users must re-authenticate after a session is closed, traffic has been idle, or from the point at which the user was first
                       created.
                type: str
                choices:
                    - 'session'
                    - 'traffic'
                    - 'absolute'
            proxy_re_authentication_time:
                description:
                    - The time limit that users must re-authenticate if proxy-keep-alive-mode is set to re-authenticate (1  - 86400 sec, default=30s.
                type: int
            proxy_resource_mode:
                description:
                    - Enable/disable use of the maximum memory usage on the FortiGate unit"s proxy processing of resources, such as block lists, allow lists,
                       and external resources.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            proxy_worker_count:
                description:
                    - Proxy worker count.
                type: int
            purdue_level:
                description:
                    - Purdue Level of this FortiGate.
                type: str
                choices:
                    - '1'
                    - '1.5'
                    - '2'
                    - '2.5'
                    - '3'
                    - '3.5'
                    - '4'
                    - '5'
                    - '5.5'
            quic_ack_thresold:
                description:
                    - Maximum number of unacknowledged packets before sending ACK (2 - 5).
                type: int
            quic_congestion_control_algo:
                description:
                    - QUIC congestion control algorithm .
                type: str
                choices:
                    - 'cubic'
                    - 'bbr'
                    - 'bbr2'
                    - 'reno'
            quic_max_datagram_size:
                description:
                    - Maximum transmit datagram size (1200 - 1500).
                type: int
            quic_pmtud:
                description:
                    - Enable/disable path MTU discovery .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            quic_tls_handshake_timeout:
                description:
                    - Time-to-live (TTL) for TLS handshake in seconds (1 - 60).
                type: int
            quic_udp_payload_size_shaping_per_cid:
                description:
                    - Enable/disable UDP payload size shaping per connection ID .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            radius_port:
                description:
                    - RADIUS service port number.
                type: int
            reboot_upon_config_restore:
                description:
                    - Enable/disable reboot of system upon restoring configuration.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            refresh:
                description:
                    - Statistics refresh interval second(s) in GUI.
                type: int
            remoteauthtimeout:
                description:
                    - Number of seconds that the FortiGate waits for responses from remote RADIUS, LDAP, or TACACS+ authentication servers. (1-300 sec).
                type: int
            reset_sessionless_tcp:
                description:
                    - Action to perform if the FortiGate receives a TCP packet but cannot find a corresponding session in its session table. NAT/Route mode
                       only.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rest_api_key_url_query:
                description:
                    - Enable/disable support for passing REST API keys through URL query parameters.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            restart_time:
                description:
                    - 'Daily restart time (hh:mm).'
                type: str
            revision_backup_on_logout:
                description:
                    - Enable/disable back-up of the latest configuration revision when an administrator logs out of the CLI or GUI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            revision_image_auto_backup:
                description:
                    - Enable/disable back-up of the latest image revision after the firmware is upgraded.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            router_affinity:
                description:
                    - Affinity setting for BFD/VRRP/BGP/OSPF daemons (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx).
                type: str
            scanunit_count:
                description:
                    - Number of scanunits. The range and the default depend on the number of CPUs. Only available on FortiGate units with multiple CPUs.
                type: int
            scim_http_port:
                description:
                    - SCIM http port (0 - 65535).
                type: int
            scim_https_port:
                description:
                    - SCIM port (0 - 65535).
                type: int
            scim_server_cert:
                description:
                    - Server certificate that the FortiGate uses for SCIM connections. Source certificate.local.name.
                type: str
            security_rating_result_submission:
                description:
                    - Enable/disable the submission of Security Rating results to FortiGuard.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            security_rating_run_on_schedule:
                description:
                    - Enable/disable scheduled runs of Security Rating.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            send_pmtu_icmp:
                description:
                    - Enable/disable sending of path maximum transmission unit (PMTU) - ICMP destination unreachable packet and to support PMTUD protocol on
                       your network to reduce fragmentation of packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sflowd_max_children_num:
                description:
                    - Maximum number of sflowd child processes allowed to run.
                type: int
            single_vdom_npuvlink:
                description:
                    - Enable/disable NPU VDOMs links for single VDOM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            snat_route_change:
                description:
                    - Enable/disable the ability to change the source NAT route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            special_file_23_support:
                description:
                    - Enable/disable detection of those special format files when using Data Loss Prevention.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            speedtest_server:
                description:
                    - Enable/disable speed test server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            speedtestd_ctrl_port:
                description:
                    - Speedtest server controller port number.
                type: int
            speedtestd_server_port:
                description:
                    - Speedtest server port number.
                type: int
            split_port:
                description:
                    - Split port(s) to multiple 10Gbps ports.
                type: list
                elements: str
            split_port_mode:
                description:
                    - Configure split port mode of ports.
                type: list
                elements: dict
                suboptions:
                    interface:
                        description:
                            - Split port interface.
                        required: true
                        type: str
                    split_mode:
                        description:
                            - The configuration mode for the split port interface.
                        type: str
                        choices:
                            - 'disable'
                            - '4x10G'
                            - '4x25G'
                            - '4x50G'
                            - '8x25G'
                            - '8x50G'
                            - '4x100G'
                            - '2x200G'
            ssd_trim_date:
                description:
                    - Date within a month to run ssd trim.
                type: int
            ssd_trim_freq:
                description:
                    - How often to run SSD Trim . SSD Trim prevents SSD drive data loss by finding and isolating errors.
                type: str
                choices:
                    - 'never'
                    - 'hourly'
                    - 'daily'
                    - 'weekly'
                    - 'monthly'
            ssd_trim_hour:
                description:
                    - Hour of the day on which to run SSD Trim (0 - 23).
                type: int
            ssd_trim_min:
                description:
                    - Minute of the hour on which to run SSD Trim (0 - 59, 60 for random).
                type: int
            ssd_trim_weekday:
                description:
                    - Day of week to run SSD Trim.
                type: str
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            ssh_cbc_cipher:
                description:
                    - Enable/disable CBC cipher for SSH access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssh_enc_algo:
                description:
                    - Select one or more SSH ciphers.
                type: list
                elements: str
                choices:
                    - 'chacha20-poly1305@openssh.com'
                    - 'aes128-ctr'
                    - 'aes192-ctr'
                    - 'aes256-ctr'
                    - 'arcfour256'
                    - 'arcfour128'
                    - 'aes128-cbc'
                    - '3des-cbc'
                    - 'blowfish-cbc'
                    - 'cast128-cbc'
                    - 'aes192-cbc'
                    - 'aes256-cbc'
                    - 'arcfour'
                    - 'rijndael-cbc@lysator.liu.se'
                    - 'aes128-gcm@openssh.com'
                    - 'aes256-gcm@openssh.com'
            ssh_hmac_md5:
                description:
                    - Enable/disable HMAC-MD5 for SSH access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssh_hostkey:
                description:
                    - Config SSH host key.
                type: str
            ssh_hostkey_algo:
                description:
                    - Select one or more SSH hostkey algorithms.
                type: list
                elements: str
                choices:
                    - 'ssh-rsa'
                    - 'ecdsa-sha2-nistp521'
                    - 'ecdsa-sha2-nistp384'
                    - 'ecdsa-sha2-nistp256'
                    - 'rsa-sha2-256'
                    - 'rsa-sha2-512'
                    - 'ssh-ed25519'
            ssh_hostkey_override:
                description:
                    - Enable/disable SSH host key override in SSH daemon.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssh_hostkey_password:
                description:
                    - Password for ssh-hostkey.
                type: str
            ssh_kex_algo:
                description:
                    - Select one or more SSH kex algorithms.
                type: list
                elements: str
                choices:
                    - 'diffie-hellman-group1-sha1'
                    - 'diffie-hellman-group14-sha1'
                    - 'diffie-hellman-group14-sha256'
                    - 'diffie-hellman-group16-sha512'
                    - 'diffie-hellman-group18-sha512'
                    - 'diffie-hellman-group-exchange-sha1'
                    - 'diffie-hellman-group-exchange-sha256'
                    - 'curve25519-sha256@libssh.org'
                    - 'ecdh-sha2-nistp256'
                    - 'ecdh-sha2-nistp384'
                    - 'ecdh-sha2-nistp521'
            ssh_kex_sha1:
                description:
                    - Enable/disable SHA1 key exchange for SSH access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssh_mac_algo:
                description:
                    - Select one or more SSH MAC algorithms.
                type: list
                elements: str
                choices:
                    - 'hmac-md5'
                    - 'hmac-md5-etm@openssh.com'
                    - 'hmac-md5-96'
                    - 'hmac-md5-96-etm@openssh.com'
                    - 'hmac-sha1'
                    - 'hmac-sha1-etm@openssh.com'
                    - 'hmac-sha2-256'
                    - 'hmac-sha2-256-etm@openssh.com'
                    - 'hmac-sha2-512'
                    - 'hmac-sha2-512-etm@openssh.com'
                    - 'hmac-ripemd160'
                    - 'hmac-ripemd160@openssh.com'
                    - 'hmac-ripemd160-etm@openssh.com'
                    - 'umac-64@openssh.com'
                    - 'umac-128@openssh.com'
                    - 'umac-64-etm@openssh.com'
                    - 'umac-128-etm@openssh.com'
            ssh_mac_weak:
                description:
                    - Enable/disable HMAC-SHA1 and UMAC-64-ETM for SSH access.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_min_proto_version:
                description:
                    - Minimum supported protocol version for SSL/TLS connections .
                type: str
                choices:
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'TLSv1-3'
            ssl_static_key_ciphers:
                description:
                    - Enable/disable static key ciphers in SSL/TLS connections (e.g. AES128-SHA, AES256-SHA, AES128-SHA256, AES256-SHA256).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sslvpn_affinity:
                description:
                    - Agentless VPN CPU affinity.
                type: str
            sslvpn_cipher_hardware_acceleration:
                description:
                    - sslvpn-cipher-hardware-acceleration
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sslvpn_ems_sn_check:
                description:
                    - Enable/disable verification of EMS serial number in SSL-VPN connection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sslvpn_kxp_hardware_acceleration:
                description:
                    - sslvpn-kxp-hardware-acceleration
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sslvpn_max_worker_count:
                description:
                    - Maximum number of Agentless VPN processes. Upper limit for this value is the number of CPUs and depends on the model. Default value of
                       zero means the sslvpnd daemon decides the number of worker processes.
                type: int
            sslvpn_plugin_version_check:
                description:
                    - sslvpn-plugin-version-check
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sslvpn_web_mode:
                description:
                    - Enable/disable Agentless VPN web mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strict_dirty_session_check:
                description:
                    - Enable to check the session against the original policy when revalidating. This can prevent dropping of redirected sessions when
                       web-filtering and authentication are enabled together. If this option is enabled, the FortiGate unit deletes a session if a routing or
                          policy change causes the session to no longer match the policy that originally allowed the session.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strong_crypto:
                description:
                    - Enable to use strong encryption and only allow strong ciphers and digest for HTTPS/SSH/TLS/SSL functions.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller:
                description:
                    - Enable/disable switch controller feature. Switch controller allows you to manage FortiSwitch from the FortiGate itself.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            switch_controller_reserved_network:
                description:
                    - Configure reserved network subnet for managed switches. This is available when the switch controller is enabled.
                type: str
            sys_perf_log_interval:
                description:
                    - Time in minutes between updates of performance statistics logging. (1 - 15 min).
                type: int
            syslog_affinity:
                description:
                    - Affinity setting for syslog (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx).
                type: str
            tcp_halfclose_timer:
                description:
                    - Number of seconds the FortiGate unit should wait to close a session after one peer has sent a FIN packet but the other has not responded
                       (1 - 86400 sec (1 day)).
                type: int
            tcp_halfopen_timer:
                description:
                    - Number of seconds the FortiGate unit should wait to close a session after one peer has sent an open session packet but the other has not
                       responded (1 - 86400 sec (1 day)).
                type: int
            tcp_option:
                description:
                    - Enable SACK, timestamp and MSS TCP options.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tcp_rst_timer:
                description:
                    - Length of the TCP CLOSE state in seconds (5 - 300 sec).
                type: int
            tcp_timewait_timer:
                description:
                    - Length of the TCP TIME-WAIT state in seconds (1 - 300 sec).
                type: int
            telemetry_controller:
                description:
                    - Enable/disable FortiTelemetry controller to manage FortiTelemetry agents.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            telemetry_data_port:
                description:
                    - FortiTelemetry data channel port (1024 - 49150).
                type: int
            tftp:
                description:
                    - Enable/disable TFTP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            timezone:
                description:
                    - Timezone database name. Enter ? to view the list of timezone. Source system.timezone.name.
                type: str
            tls_session_cache:
                description:
                    - Enable/disable TLS session cache.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tp_mc_skip_policy:
                description:
                    - Enable/disable skip policy check and allow multicast through.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            traffic_priority:
                description:
                    - Choose Type of Service (ToS) or Differentiated Services Code Point (DSCP) for traffic prioritization in traffic shaping.
                type: str
                choices:
                    - 'tos'
                    - 'dscp'
            traffic_priority_level:
                description:
                    - Default system-wide level of priority for traffic prioritization.
                type: str
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'
            two_factor_email_expiry:
                description:
                    - Email-based two-factor authentication session timeout (30 - 300 seconds (5 minutes)).
                type: int
            two_factor_fac_expiry:
                description:
                    - FortiAuthenticator token authentication session timeout (10 - 3600 seconds (1 hour)).
                type: int
            two_factor_ftk_expiry:
                description:
                    - FortiToken authentication session timeout (60 - 600 sec (10 minutes)).
                type: int
            two_factor_ftm_expiry:
                description:
                    - FortiToken Mobile session timeout (1 - 168 hours (7 days)).
                type: int
            two_factor_sms_expiry:
                description:
                    - SMS-based two-factor authentication session timeout (30 - 300 sec).
                type: int
            udp_idle_timer:
                description:
                    - UDP connection session timeout. This command can be useful in managing CPU and memory resources (1 - 86400 seconds (1 day)).
                type: int
            upgrade_report:
                description:
                    - Enable/disable the generation of an upgrade report when upgrading the firmware.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            url_filter_affinity:
                description:
                    - URL filter CPU affinity.
                type: str
            url_filter_count:
                description:
                    - URL filter daemon count.
                type: int
            user_device_store_max_device_mem:
                description:
                    - Maximum percentage of total system memory allowed to be used for devices in the user device store.
                type: int
            user_device_store_max_devices:
                description:
                    - Maximum number of devices allowed in user device store.
                type: int
            user_device_store_max_unified_mem:
                description:
                    - Maximum unified memory allowed in user device store.
                type: int
            user_device_store_max_users:
                description:
                    - Maximum number of users allowed in user device store.
                type: int
            user_history_password_threshold:
                description:
                    - Maximum number of previous passwords saved per admin/user (3 - 15).
                type: int
            user_server_cert:
                description:
                    - Certificate to use for https user authentication. Source certificate.local.name.
                type: str
            vdom_admin:
                description:
                    - vdom-admin
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vdom_mode:
                description:
                    - Enable/disable support for multiple virtual domains (VDOMs).
                type: str
                choices:
                    - 'no-vdom'
                    - 'multi-vdom'
                    - 'split-vdom'
            vip_arp_range:
                description:
                    - Controls the number of ARPs that the FortiGate sends for a Virtual IP (VIP) address range.
                type: str
                choices:
                    - 'unlimited'
                    - 'restricted'
            virtual_server_count:
                description:
                    - Maximum number of virtual server processes to create. The maximum is the number of CPU cores. This is not available on single-core CPUs.
                type: int
            virtual_server_hardware_acceleration:
                description:
                    - Enable/disable virtual server hardware acceleration.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            virtual_switch_vlan:
                description:
                    - Enable/disable virtual switch VLAN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vpn_ems_sn_check:
                description:
                    - Enable/disable verification of EMS serial number in SSL-VPN connection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wad_affinity:
                description:
                    - Affinity setting for wad (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx).
                type: str
            wad_csvc_cs_count:
                description:
                    - Number of concurrent WAD-cache-service object-cache processes.
                type: int
            wad_csvc_db_count:
                description:
                    - Number of concurrent WAD-cache-service byte-cache processes.
                type: int
            wad_memory_change_granularity:
                description:
                    - Minimum percentage change in system memory usage detected by the wad daemon prior to adjusting TCP window size for any active connection.
                type: int
            wad_p2s_max_body_size:
                description:
                    - Maximum size of the body of the local out HTTP request (1 - 32 Mbytes).
                type: int
            wad_restart_end_time:
                description:
                    - 'WAD workers daily restart end time (hh:mm).'
                type: str
            wad_restart_mode:
                description:
                    - WAD worker restart mode .
                type: str
                choices:
                    - 'none'
                    - 'time'
                    - 'memory'
            wad_restart_start_time:
                description:
                    - 'WAD workers daily restart time (hh:mm).'
                type: str
            wad_source_affinity:
                description:
                    - Enable/disable dispatching traffic to WAD workers based on source affinity.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            wad_worker_count:
                description:
                    - Number of explicit proxy WAN optimization daemon (WAD) processes. By default WAN optimization, explicit proxy, and web caching is
                       handled by all of the CPU cores in a FortiGate unit.
                type: int
            wifi_ca_certificate:
                description:
                    - CA certificate that verifies the WiFi certificate. Source certificate.ca.name.
                type: str
            wifi_certificate:
                description:
                    - Certificate to use for WiFi authentication. Source certificate.local.name.
                type: str
            wimax_4g_usb:
                description:
                    - Enable/disable comparability with WiMAX 4G USB devices.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wireless_controller:
                description:
                    - Enable/disable the wireless controller feature to use the FortiGate unit to manage FortiAPs.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wireless_controller_port:
                description:
                    - Port used for the control channel in wireless controller mode (wireless-mode is ac). The data channel port is the control channel port
                       number plus one (1024 - 49150).
                type: int
"""

EXAMPLES = """
- name: Configure global attributes.
  fortinet.fortios.fortios_system_global:
      vdom: "{{ vdom }}"
      system_global:
          admin_concurrent: "enable"
          admin_console_timeout: "0"
          admin_forticloud_sso_default_profile: "<your_own_value> (source system.accprofile.name)"
          admin_forticloud_sso_login: "enable"
          admin_host: "myhostname"
          admin_hsts_max_age: "63072000"
          admin_https_pki_required: "enable"
          admin_https_redirect: "enable"
          admin_https_ssl_banned_ciphers: "RSA"
          admin_https_ssl_ciphersuites: "TLS-AES-128-GCM-SHA256"
          admin_https_ssl_versions: "tlsv1-1"
          admin_lockout_duration: "60"
          admin_lockout_threshold: "3"
          admin_login_max: "100"
          admin_maintainer: "enable"
          admin_port: "80"
          admin_restrict_local: "all"
          admin_scp: "enable"
          admin_server_cert: "<your_own_value> (source certificate.local.name)"
          admin_sport: "443"
          admin_ssh_grace_time: "120"
          admin_ssh_password: "enable"
          admin_ssh_port: "22"
          admin_ssh_v1: "enable"
          admin_telnet: "enable"
          admin_telnet_port: "23"
          admintimeout: "5"
          alias: "<your_own_value>"
          allow_traffic_redirect: "enable"
          anti_replay: "disable"
          application_bandwidth_tracking: "disable"
          arp_max_entry: "131072"
          asymroute: "enable"
          auth_cert: "<your_own_value> (source certificate.local.name)"
          auth_http_port: "1000"
          auth_https_port: "1003"
          auth_ike_saml_port: "1001"
          auth_keepalive: "enable"
          auth_session_auto_backup: "enable"
          auth_session_auto_backup_interval: "1min"
          auth_session_limit: "block-new"
          auto_auth_extension_device: "enable"
          autorun_log_fsck: "enable"
          av_affinity: "<your_own_value>"
          av_failopen: "pass"
          av_failopen_session: "enable"
          batch_cmdb: "enable"
          bfd_affinity: "<your_own_value>"
          block_session_timer: "30"
          br_fdb_max_entry: "8192"
          cert_chain_max: "8"
          cfg_revert_timeout: "600"
          cfg_save: "automatic"
          check_protocol_header: "loose"
          check_reset_range: "strict"
          cli_audit_log: "enable"
          cloud_communication: "enable"
          clt_cert_req: "enable"
          cmdbsvr_affinity: "<your_own_value>"
          compliance_check: "enable"
          compliance_check_time: "<your_own_value>"
          cpu_use_threshold: "90"
          csr_ca_attribute: "enable"
          daily_restart: "enable"
          default_service_source_port: "<your_own_value>"
          delay_tcp_npu_session: "enable"
          device_identification_active_scan_delay: "1800"
          device_idle_timeout: "300"
          dh_params: "1024"
          dhcp_lease_backup_interval: "60"
          dnsproxy_worker_count: "1"
          dst: "enable"
          early_tcp_npu_session: "enable"
          edit_vdom_prompt: "enable"
          endpoint_control_fds_access: "enable"
          endpoint_control_portal_port: "32767"
          extender_controller_reserved_network: "<your_own_value>"
          failtime: "5"
          faz_disk_buffer_size: "0"
          fds_statistics: "enable"
          fds_statistics_period: "60"
          fec_port: "50000"
          fgd_alert_subscription: "advisory"
          forticarrier_bypass: "enable"
          forticonverter_config_upload: "once"
          forticonverter_integration: "enable"
          fortiextender: "disable"
          fortiextender_data_port: "25246"
          fortiextender_discovery_lockdown: "disable"
          fortiextender_provision_on_authorization: "enable"
          fortiextender_vlan_mode: "enable"
          fortigslb_integration: "disable"
          fortiipam_integration: "enable"
          fortiservice_port: "8013"
          fortitoken_cloud: "enable"
          fortitoken_cloud_push_status: "enable"
          fortitoken_cloud_region: "<your_own_value>"
          fortitoken_cloud_sync_interval: "24"
          gui_allow_default_hostname: "enable"
          gui_allow_incompatible_fabric_fgt: "enable"
          gui_app_detection_sdwan: "enable"
          gui_auto_upgrade_setup_warning: "enable"
          gui_cdn_domain_override: "<your_own_value>"
          gui_cdn_usage: "enable"
          gui_certificates: "enable"
          gui_custom_language: "enable"
          gui_date_format: "yyyy/MM/dd"
          gui_date_time_source: "system"
          gui_device_latitude: "<your_own_value>"
          gui_device_longitude: "<your_own_value>"
          gui_display_hostname: "enable"
          gui_firmware_upgrade_warning: "enable"
          gui_forticare_registration_setup_warning: "enable"
          gui_fortigate_cloud_sandbox: "enable"
          gui_fortiguard_resource_fetch: "enable"
          gui_fortisandbox_cloud: "enable"
          gui_ipv6: "enable"
          gui_lines_per_page: "500"
          gui_local_out: "enable"
          gui_replacement_message_groups: "enable"
          gui_rest_api_cache: "enable"
          gui_theme: "jade"
          gui_wireless_opensecurity: "enable"
          gui_workflow_management: "enable"
          ha_affinity: "<your_own_value>"
          honor_df: "enable"
          hostname: "myhostname"
          httpd_max_worker_count: "0"
          igmp_state_limit: "3200"
          interface_subnet_usage: "disable"
          internet_service_database: "mini"
          internet_service_download_list:
              -
                  id: "135 (source firewall.internet-service.id)"
          interval: "5"
          ip_conflict_detection: "enable"
          ip_fragment_mem_thresholds: "32"
          ip_fragment_timeout: "30"
          ip_src_port_range: "<your_own_value>"
          ips_affinity: "<your_own_value>"
          ipsec_asic_offload: "enable"
          ipsec_ha_seqjump_rate: "10"
          ipsec_hmac_offload: "enable"
          ipsec_qat_offload: "enable"
          ipsec_round_robin: "enable"
          ipsec_soft_dec_async: "enable"
          ipv6_accept_dad: "1"
          ipv6_allow_anycast_probe: "enable"
          ipv6_allow_local_in_silent_drop: "enable"
          ipv6_allow_local_in_slient_drop: "enable"
          ipv6_allow_multicast_probe: "enable"
          ipv6_allow_traffic_redirect: "enable"
          ipv6_fragment_timeout: "60"
          ipv6_snat_route_change: "enable"
          irq_time_accounting: "auto"
          language: "english"
          ldapconntimeout: "500"
          lldp_reception: "enable"
          lldp_transmission: "enable"
          log_single_cpu_high: "enable"
          log_ssl_connection: "enable"
          log_uuid: "disable"
          log_uuid_address: "enable"
          log_uuid_policy: "enable"
          login_timestamp: "enable"
          long_vdom_name: "enable"
          management_ip: "<your_own_value>"
          management_port: "443"
          management_port_use_admin_sport: "enable"
          management_vdom: "<your_own_value> (source system.vdom.name)"
          max_dlpstat_memory: "172"
          max_route_cache_size: "0"
          mc_ttl_notchange: "enable"
          memory_use_threshold_extreme: "95"
          memory_use_threshold_green: "82"
          memory_use_threshold_red: "88"
          miglog_affinity: "<your_own_value>"
          miglogd_children: "0"
          multi_factor_authentication: "optional"
          multicast_forward: "enable"
          ndp_max_entry: "0"
          npu_neighbor_update: "enable"
          per_user_bal: "enable"
          per_user_bwl: "enable"
          pmtu_discovery: "enable"
          policy_auth_concurrent: "0"
          post_login_banner: "disable"
          pre_login_banner: "enable"
          private_data_encryption: "disable"
          proxy_auth_lifetime: "enable"
          proxy_auth_lifetime_timeout: "480"
          proxy_auth_timeout: "10"
          proxy_cert_use_mgmt_vdom: "enable"
          proxy_cipher_hardware_acceleration: "disable"
          proxy_hardware_acceleration: "disable"
          proxy_keep_alive_mode: "session"
          proxy_kxp_hardware_acceleration: "disable"
          proxy_re_authentication_mode: "session"
          proxy_re_authentication_time: "30"
          proxy_resource_mode: "enable"
          proxy_worker_count: "0"
          purdue_level: "1"
          quic_ack_thresold: "3"
          quic_congestion_control_algo: "cubic"
          quic_max_datagram_size: "1500"
          quic_pmtud: "enable"
          quic_tls_handshake_timeout: "5"
          quic_udp_payload_size_shaping_per_cid: "enable"
          radius_port: "1812"
          reboot_upon_config_restore: "enable"
          refresh: "0"
          remoteauthtimeout: "5"
          reset_sessionless_tcp: "enable"
          rest_api_key_url_query: "enable"
          restart_time: "<your_own_value>"
          revision_backup_on_logout: "enable"
          revision_image_auto_backup: "enable"
          router_affinity: "<your_own_value>"
          scanunit_count: "0"
          scim_http_port: "44558"
          scim_https_port: "44559"
          scim_server_cert: "<your_own_value> (source certificate.local.name)"
          security_rating_result_submission: "enable"
          security_rating_run_on_schedule: "enable"
          send_pmtu_icmp: "enable"
          sflowd_max_children_num: "6"
          single_vdom_npuvlink: "enable"
          snat_route_change: "enable"
          special_file_23_support: "disable"
          speedtest_server: "enable"
          speedtestd_ctrl_port: "5200"
          speedtestd_server_port: "5201"
          split_port: "<your_own_value>"
          split_port_mode:
              -
                  interface: "<your_own_value>"
                  split_mode: "disable"
          ssd_trim_date: "1"
          ssd_trim_freq: "never"
          ssd_trim_hour: "1"
          ssd_trim_min: "60"
          ssd_trim_weekday: "sunday"
          ssh_cbc_cipher: "enable"
          ssh_enc_algo: "chacha20-poly1305@openssh.com"
          ssh_hmac_md5: "enable"
          ssh_hostkey: "myhostname"
          ssh_hostkey_algo: "ssh-rsa"
          ssh_hostkey_override: "disable"
          ssh_hostkey_password: "myhostname"
          ssh_kex_algo: "diffie-hellman-group1-sha1"
          ssh_kex_sha1: "enable"
          ssh_mac_algo: "hmac-md5"
          ssh_mac_weak: "enable"
          ssl_min_proto_version: "SSLv3"
          ssl_static_key_ciphers: "enable"
          sslvpn_affinity: "<your_own_value>"
          sslvpn_cipher_hardware_acceleration: "enable"
          sslvpn_ems_sn_check: "enable"
          sslvpn_kxp_hardware_acceleration: "enable"
          sslvpn_max_worker_count: "0"
          sslvpn_plugin_version_check: "enable"
          sslvpn_web_mode: "enable"
          strict_dirty_session_check: "enable"
          strong_crypto: "enable"
          switch_controller: "disable"
          switch_controller_reserved_network: "<your_own_value>"
          sys_perf_log_interval: "5"
          syslog_affinity: "<your_own_value>"
          tcp_halfclose_timer: "120"
          tcp_halfopen_timer: "10"
          tcp_option: "enable"
          tcp_rst_timer: "5"
          tcp_timewait_timer: "1"
          telemetry_controller: "enable"
          telemetry_data_port: "35246"
          tftp: "enable"
          timezone: "<your_own_value> (source system.timezone.name)"
          tls_session_cache: "enable"
          tp_mc_skip_policy: "enable"
          traffic_priority: "tos"
          traffic_priority_level: "low"
          two_factor_email_expiry: "60"
          two_factor_fac_expiry: "60"
          two_factor_ftk_expiry: "60"
          two_factor_ftm_expiry: "72"
          two_factor_sms_expiry: "60"
          udp_idle_timer: "180"
          upgrade_report: "enable"
          url_filter_affinity: "<your_own_value>"
          url_filter_count: "1"
          user_device_store_max_device_mem: "2"
          user_device_store_max_devices: "676985"
          user_device_store_max_unified_mem: "3384928051"
          user_device_store_max_users: "676985"
          user_history_password_threshold: "3"
          user_server_cert: "<your_own_value> (source certificate.local.name)"
          vdom_admin: "enable"
          vdom_mode: "no-vdom"
          vip_arp_range: "unlimited"
          virtual_server_count: "20"
          virtual_server_hardware_acceleration: "disable"
          virtual_switch_vlan: "enable"
          vpn_ems_sn_check: "enable"
          wad_affinity: "<your_own_value>"
          wad_csvc_cs_count: "1"
          wad_csvc_db_count: "0"
          wad_memory_change_granularity: "10"
          wad_p2s_max_body_size: "4"
          wad_restart_end_time: "<your_own_value>"
          wad_restart_mode: "none"
          wad_restart_start_time: "<your_own_value>"
          wad_source_affinity: "disable"
          wad_worker_count: "0"
          wifi_ca_certificate: "<your_own_value> (source certificate.ca.name)"
          wifi_certificate: "<your_own_value> (source certificate.local.name)"
          wimax_4g_usb: "enable"
          wireless_controller: "enable"
          wireless_controller_port: "5246"
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


def filter_system_global_data(json):
    option_list = [
        "admin_concurrent",
        "admin_console_timeout",
        "admin_forticloud_sso_default_profile",
        "admin_forticloud_sso_login",
        "admin_host",
        "admin_hsts_max_age",
        "admin_https_pki_required",
        "admin_https_redirect",
        "admin_https_ssl_banned_ciphers",
        "admin_https_ssl_ciphersuites",
        "admin_https_ssl_versions",
        "admin_lockout_duration",
        "admin_lockout_threshold",
        "admin_login_max",
        "admin_maintainer",
        "admin_port",
        "admin_restrict_local",
        "admin_scp",
        "admin_server_cert",
        "admin_sport",
        "admin_ssh_grace_time",
        "admin_ssh_password",
        "admin_ssh_port",
        "admin_ssh_v1",
        "admin_telnet",
        "admin_telnet_port",
        "admintimeout",
        "alias",
        "allow_traffic_redirect",
        "anti_replay",
        "application_bandwidth_tracking",
        "arp_max_entry",
        "asymroute",
        "auth_cert",
        "auth_http_port",
        "auth_https_port",
        "auth_ike_saml_port",
        "auth_keepalive",
        "auth_session_auto_backup",
        "auth_session_auto_backup_interval",
        "auth_session_limit",
        "auto_auth_extension_device",
        "autorun_log_fsck",
        "av_affinity",
        "av_failopen",
        "av_failopen_session",
        "batch_cmdb",
        "bfd_affinity",
        "block_session_timer",
        "br_fdb_max_entry",
        "cert_chain_max",
        "cfg_revert_timeout",
        "cfg_save",
        "check_protocol_header",
        "check_reset_range",
        "cli_audit_log",
        "cloud_communication",
        "clt_cert_req",
        "cmdbsvr_affinity",
        "compliance_check",
        "compliance_check_time",
        "cpu_use_threshold",
        "csr_ca_attribute",
        "daily_restart",
        "default_service_source_port",
        "delay_tcp_npu_session",
        "device_identification_active_scan_delay",
        "device_idle_timeout",
        "dh_params",
        "dhcp_lease_backup_interval",
        "dnsproxy_worker_count",
        "dst",
        "early_tcp_npu_session",
        "edit_vdom_prompt",
        "endpoint_control_fds_access",
        "endpoint_control_portal_port",
        "extender_controller_reserved_network",
        "failtime",
        "faz_disk_buffer_size",
        "fds_statistics",
        "fds_statistics_period",
        "fec_port",
        "fgd_alert_subscription",
        "forticarrier_bypass",
        "forticonverter_config_upload",
        "forticonverter_integration",
        "fortiextender",
        "fortiextender_data_port",
        "fortiextender_discovery_lockdown",
        "fortiextender_provision_on_authorization",
        "fortiextender_vlan_mode",
        "fortigslb_integration",
        "fortiipam_integration",
        "fortiservice_port",
        "fortitoken_cloud",
        "fortitoken_cloud_push_status",
        "fortitoken_cloud_region",
        "fortitoken_cloud_sync_interval",
        "gui_allow_default_hostname",
        "gui_allow_incompatible_fabric_fgt",
        "gui_app_detection_sdwan",
        "gui_auto_upgrade_setup_warning",
        "gui_cdn_domain_override",
        "gui_cdn_usage",
        "gui_certificates",
        "gui_custom_language",
        "gui_date_format",
        "gui_date_time_source",
        "gui_device_latitude",
        "gui_device_longitude",
        "gui_display_hostname",
        "gui_firmware_upgrade_warning",
        "gui_forticare_registration_setup_warning",
        "gui_fortigate_cloud_sandbox",
        "gui_fortiguard_resource_fetch",
        "gui_fortisandbox_cloud",
        "gui_ipv6",
        "gui_lines_per_page",
        "gui_local_out",
        "gui_replacement_message_groups",
        "gui_rest_api_cache",
        "gui_theme",
        "gui_wireless_opensecurity",
        "gui_workflow_management",
        "ha_affinity",
        "honor_df",
        "hostname",
        "httpd_max_worker_count",
        "igmp_state_limit",
        "interface_subnet_usage",
        "internet_service_database",
        "internet_service_download_list",
        "interval",
        "ip_conflict_detection",
        "ip_fragment_mem_thresholds",
        "ip_fragment_timeout",
        "ip_src_port_range",
        "ips_affinity",
        "ipsec_asic_offload",
        "ipsec_ha_seqjump_rate",
        "ipsec_hmac_offload",
        "ipsec_qat_offload",
        "ipsec_round_robin",
        "ipsec_soft_dec_async",
        "ipv6_accept_dad",
        "ipv6_allow_anycast_probe",
        "ipv6_allow_local_in_silent_drop",
        "ipv6_allow_local_in_slient_drop",
        "ipv6_allow_multicast_probe",
        "ipv6_allow_traffic_redirect",
        "ipv6_fragment_timeout",
        "ipv6_snat_route_change",
        "irq_time_accounting",
        "language",
        "ldapconntimeout",
        "lldp_reception",
        "lldp_transmission",
        "log_single_cpu_high",
        "log_ssl_connection",
        "log_uuid",
        "log_uuid_address",
        "log_uuid_policy",
        "login_timestamp",
        "long_vdom_name",
        "management_ip",
        "management_port",
        "management_port_use_admin_sport",
        "management_vdom",
        "max_dlpstat_memory",
        "max_route_cache_size",
        "mc_ttl_notchange",
        "memory_use_threshold_extreme",
        "memory_use_threshold_green",
        "memory_use_threshold_red",
        "miglog_affinity",
        "miglogd_children",
        "multi_factor_authentication",
        "multicast_forward",
        "ndp_max_entry",
        "npu_neighbor_update",
        "per_user_bal",
        "per_user_bwl",
        "pmtu_discovery",
        "policy_auth_concurrent",
        "post_login_banner",
        "pre_login_banner",
        "private_data_encryption",
        "proxy_auth_lifetime",
        "proxy_auth_lifetime_timeout",
        "proxy_auth_timeout",
        "proxy_cert_use_mgmt_vdom",
        "proxy_cipher_hardware_acceleration",
        "proxy_hardware_acceleration",
        "proxy_keep_alive_mode",
        "proxy_kxp_hardware_acceleration",
        "proxy_re_authentication_mode",
        "proxy_re_authentication_time",
        "proxy_resource_mode",
        "proxy_worker_count",
        "purdue_level",
        "quic_ack_thresold",
        "quic_congestion_control_algo",
        "quic_max_datagram_size",
        "quic_pmtud",
        "quic_tls_handshake_timeout",
        "quic_udp_payload_size_shaping_per_cid",
        "radius_port",
        "reboot_upon_config_restore",
        "refresh",
        "remoteauthtimeout",
        "reset_sessionless_tcp",
        "rest_api_key_url_query",
        "restart_time",
        "revision_backup_on_logout",
        "revision_image_auto_backup",
        "router_affinity",
        "scanunit_count",
        "scim_http_port",
        "scim_https_port",
        "scim_server_cert",
        "security_rating_result_submission",
        "security_rating_run_on_schedule",
        "send_pmtu_icmp",
        "sflowd_max_children_num",
        "single_vdom_npuvlink",
        "snat_route_change",
        "special_file_23_support",
        "speedtest_server",
        "speedtestd_ctrl_port",
        "speedtestd_server_port",
        "split_port",
        "split_port_mode",
        "ssd_trim_date",
        "ssd_trim_freq",
        "ssd_trim_hour",
        "ssd_trim_min",
        "ssd_trim_weekday",
        "ssh_cbc_cipher",
        "ssh_enc_algo",
        "ssh_hmac_md5",
        "ssh_hostkey",
        "ssh_hostkey_algo",
        "ssh_hostkey_override",
        "ssh_hostkey_password",
        "ssh_kex_algo",
        "ssh_kex_sha1",
        "ssh_mac_algo",
        "ssh_mac_weak",
        "ssl_min_proto_version",
        "ssl_static_key_ciphers",
        "sslvpn_affinity",
        "sslvpn_cipher_hardware_acceleration",
        "sslvpn_ems_sn_check",
        "sslvpn_kxp_hardware_acceleration",
        "sslvpn_max_worker_count",
        "sslvpn_plugin_version_check",
        "sslvpn_web_mode",
        "strict_dirty_session_check",
        "strong_crypto",
        "switch_controller",
        "switch_controller_reserved_network",
        "sys_perf_log_interval",
        "syslog_affinity",
        "tcp_halfclose_timer",
        "tcp_halfopen_timer",
        "tcp_option",
        "tcp_rst_timer",
        "tcp_timewait_timer",
        "telemetry_controller",
        "telemetry_data_port",
        "tftp",
        "timezone",
        "tls_session_cache",
        "tp_mc_skip_policy",
        "traffic_priority",
        "traffic_priority_level",
        "two_factor_email_expiry",
        "two_factor_fac_expiry",
        "two_factor_ftk_expiry",
        "two_factor_ftm_expiry",
        "two_factor_sms_expiry",
        "udp_idle_timer",
        "upgrade_report",
        "url_filter_affinity",
        "url_filter_count",
        "user_device_store_max_device_mem",
        "user_device_store_max_devices",
        "user_device_store_max_unified_mem",
        "user_device_store_max_users",
        "user_history_password_threshold",
        "user_server_cert",
        "vdom_admin",
        "vdom_mode",
        "vip_arp_range",
        "virtual_server_count",
        "virtual_server_hardware_acceleration",
        "virtual_switch_vlan",
        "vpn_ems_sn_check",
        "wad_affinity",
        "wad_csvc_cs_count",
        "wad_csvc_db_count",
        "wad_memory_change_granularity",
        "wad_p2s_max_body_size",
        "wad_restart_end_time",
        "wad_restart_mode",
        "wad_restart_start_time",
        "wad_source_affinity",
        "wad_worker_count",
        "wifi_ca_certificate",
        "wifi_certificate",
        "wimax_4g_usb",
        "wireless_controller",
        "wireless_controller_port",
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
        ["admin_https_ssl_versions"],
        ["admin_https_ssl_ciphersuites"],
        ["admin_https_ssl_banned_ciphers"],
        ["split_port"],
        ["fgd_alert_subscription"],
        ["ssh_kex_algo"],
        ["ssh_enc_algo"],
        ["ssh_mac_algo"],
        ["ssh_hostkey_algo"],
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


def system_global(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_global_data = data["system_global"]

    filtered_data = filter_system_global_data(system_global_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "global", filtered_data, vdom=vdom)
        current_data = fos.get("system", "global", vdom=vdom, mkey=mkey)
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
    data_copy["system_global"] = filtered_data
    fos.do_member_operation(
        "system",
        "global",
        data_copy,
    )

    return fos.set("system", "global", data=converted_data, vdom=vdom)


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


def fortios_system(data, fos, check_mode):

    if data["system_global"]:
        resp = system_global(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_global"))
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
    "v_range": [["v6.0.0", ""]],
    "type": "dict",
    "children": {
        "language": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "english"},
                {"value": "french"},
                {"value": "spanish"},
                {"value": "portuguese"},
                {"value": "japanese"},
                {"value": "trach"},
                {"value": "simch"},
                {"value": "korean"},
            ],
        },
        "gui_allow_incompatible_fabric_fgt": {
            "v_range": [["v7.0.12", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_ipv6": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_replacement_message_groups": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_local_out": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_certificates": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_custom_language": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_wireless_opensecurity": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_app_detection_sdwan": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_display_hostname": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_fortigate_cloud_sandbox": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_firmware_upgrade_warning": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_forticare_registration_setup_warning": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_auto_upgrade_setup_warning": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_workflow_management": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_cdn_usage": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_https_ssl_versions": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "tlsv1-1"},
                {"value": "tlsv1-2"},
                {"value": "tlsv1-3", "v_range": [["v6.2.0", ""]]},
                {"value": "tlsv1-0", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "admin_https_ssl_ciphersuites": {
            "v_range": [["v7.0.2", ""]],
            "type": "list",
            "options": [
                {"value": "TLS-AES-128-GCM-SHA256"},
                {"value": "TLS-AES-256-GCM-SHA384"},
                {"value": "TLS-CHACHA20-POLY1305-SHA256"},
                {"value": "TLS-AES-128-CCM-SHA256"},
                {"value": "TLS-AES-128-CCM-8-SHA256"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "admin_https_ssl_banned_ciphers": {
            "v_range": [["v7.0.2", ""]],
            "type": "list",
            "options": [
                {"value": "RSA"},
                {"value": "DHE"},
                {"value": "ECDHE"},
                {"value": "DSS"},
                {"value": "ECDSA"},
                {"value": "AES"},
                {"value": "AESGCM"},
                {"value": "CAMELLIA"},
                {"value": "3DES"},
                {"value": "SHA1"},
                {"value": "SHA256"},
                {"value": "SHA384"},
                {"value": "STATIC"},
                {"value": "CHACHA20"},
                {"value": "ARIA"},
                {"value": "AESCCM"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "admintimeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "admin_console_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ssd_trim_freq": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "never", "v_range": [["v6.0.0", ""]]},
                {"value": "hourly", "v_range": [["v6.0.0", ""]]},
                {"value": "daily", "v_range": [["v6.0.0", ""]]},
                {"value": "weekly", "v_range": [["v6.0.0", ""]]},
                {"value": "monthly", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "ssd_trim_hour": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "ssd_trim_min": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "ssd_trim_weekday": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "sunday", "v_range": [["v6.0.0", ""]]},
                {"value": "monday", "v_range": [["v6.0.0", ""]]},
                {"value": "tuesday", "v_range": [["v6.0.0", ""]]},
                {"value": "wednesday", "v_range": [["v6.0.0", ""]]},
                {"value": "thursday", "v_range": [["v6.0.0", ""]]},
                {"value": "friday", "v_range": [["v6.0.0", ""]]},
                {"value": "saturday", "v_range": [["v6.0.0", ""]]},
            ],
        },
        "ssd_trim_date": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "integer",
        },
        "admin_concurrent": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_lockout_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "admin_lockout_duration": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "refresh": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "failtime": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "purdue_level": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [
                {"value": "1"},
                {"value": "1.5"},
                {"value": "2"},
                {"value": "2.5"},
                {"value": "3"},
                {"value": "3.5"},
                {"value": "4"},
                {"value": "5"},
                {"value": "5.5"},
            ],
        },
        "daily_restart": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "restart_time": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wad_restart_mode": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "time"}, {"value": "memory"}],
        },
        "wad_restart_start_time": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "wad_restart_end_time": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "wad_p2s_max_body_size": {"v_range": [["v7.6.3", ""]], "type": "integer"},
        "radius_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "speedtestd_server_port": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "speedtestd_ctrl_port": {"v_range": [["v7.4.2", ""]], "type": "integer"},
        "admin_login_max": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "remoteauthtimeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ldapconntimeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "batch_cmdb": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "multi_factor_authentication": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "optional"}, {"value": "mandatory"}],
        },
        "ssl_min_proto_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "SSLv3"},
                {"value": "TLSv1"},
                {"value": "TLSv1-1"},
                {"value": "TLSv1-2"},
                {"value": "TLSv1-3", "v_range": [["v6.2.0", ""]]},
            ],
        },
        "autorun_log_fsck": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "timezone": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "traffic_priority": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "tos"}, {"value": "dscp"}],
        },
        "traffic_priority_level": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "low"}, {"value": "medium"}, {"value": "high"}],
        },
        "quic_congestion_control_algo": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [
                {"value": "cubic"},
                {"value": "bbr"},
                {"value": "bbr2"},
                {"value": "reno"},
            ],
        },
        "quic_max_datagram_size": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "quic_udp_payload_size_shaping_per_cid": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "quic_ack_thresold": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "quic_pmtud": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "quic_tls_handshake_timeout": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "anti_replay": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "loose"}, {"value": "strict"}],
        },
        "send_pmtu_icmp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "honor_df": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pmtu_discovery": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "split_port": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "revision_image_auto_backup": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "revision_backup_on_logout": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "management_vdom": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "hostname": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "alias": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "strong_crypto": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_static_key_ciphers": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "snat_route_change": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_snat_route_change": {
            "v_range": [["v7.6.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "speedtest_server": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cli_audit_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dh_params": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "1024"},
                {"value": "1536"},
                {"value": "2048"},
                {"value": "3072"},
                {"value": "4096"},
                {"value": "6144"},
                {"value": "8192"},
            ],
        },
        "fds_statistics": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fds_statistics_period": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tcp_option": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "lldp_transmission": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "lldp_reception": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "proxy_auth_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "proxy_keep_alive_mode": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [
                {"value": "session"},
                {"value": "traffic"},
                {"value": "re-authentication"},
            ],
        },
        "proxy_re_authentication_time": {
            "v_range": [["v7.2.4", ""]],
            "type": "integer",
        },
        "proxy_auth_lifetime": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "proxy_auth_lifetime_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "proxy_resource_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "proxy_cert_use_mgmt_vdom": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sys_perf_log_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "check_protocol_header": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "loose"}, {"value": "strict"}],
        },
        "vip_arp_range": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "unlimited"}, {"value": "restricted"}],
        },
        "reset_sessionless_tcp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "allow_traffic_redirect": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_allow_traffic_redirect": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "strict_dirty_session_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tcp_halfclose_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tcp_halfopen_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tcp_timewait_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tcp_rst_timer": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "udp_idle_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "block_session_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ip_src_port_range": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "pre_login_banner": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "post_login_banner": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "tftp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "av_failopen": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "pass"}, {"value": "off"}, {"value": "one-shot"}],
        },
        "av_failopen_session": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "memory_use_threshold_extreme": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "memory_use_threshold_red": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "memory_use_threshold_green": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ip_fragment_mem_thresholds": {
            "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.4", ""]],
            "type": "integer",
        },
        "ip_fragment_timeout": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "ipv6_fragment_timeout": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "cpu_use_threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "log_single_cpu_high": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "check_reset_range": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "strict"}, {"value": "disable"}],
        },
        "single_vdom_npuvlink": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vdom_mode": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "no-vdom"},
                {"value": "multi-vdom"},
                {"value": "split-vdom", "v_range": [["v6.2.0", "v7.0.12"]]},
            ],
        },
        "long_vdom_name": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "upgrade_report": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "edit_vdom_prompt": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "admin_sport": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "admin_host": {
            "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
        },
        "admin_https_redirect": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_hsts_max_age": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "admin_ssh_password": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_restrict_local": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "all", "v_range": [["v7.6.0", ""]]},
                {"value": "non-console-only", "v_range": [["v7.6.0", ""]]},
                {"value": "disable"},
                {"value": "enable", "v_range": [["v6.0.0", "v7.4.4"]]},
            ],
        },
        "admin_ssh_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "admin_ssh_grace_time": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "admin_ssh_v1": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_telnet": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_telnet_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "admin_forticloud_sso_login": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_forticloud_sso_default_profile": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
        },
        "default_service_source_port": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "admin_server_cert": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "admin_https_pki_required": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wifi_certificate": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dhcp_lease_backup_interval": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "wifi_ca_certificate": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_http_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_https_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_ike_saml_port": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "auth_keepalive": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "policy_auth_concurrent": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_session_limit": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "block-new"}, {"value": "logout-inactive"}],
        },
        "auth_cert": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "clt_cert_req": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fortiservice_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "cfg_save": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "automatic"},
                {"value": "manual"},
                {"value": "revert"},
            ],
        },
        "cfg_revert_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "reboot_upon_config_restore": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "admin_scp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wireless_controller": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wireless_controller_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "fortiextender_data_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "fortiextender": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "extender_controller_reserved_network": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
        },
        "fortiextender_discovery_lockdown": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "fortiextender_vlan_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fortiextender_provision_on_authorization": {
            "v_range": [["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "telemetry_controller": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "telemetry_data_port": {"v_range": [["v7.6.3", ""]], "type": "integer"},
        "switch_controller": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "switch_controller_reserved_network": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
        },
        "dnsproxy_worker_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "url_filter_count": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "httpd_max_worker_count": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "proxy_worker_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "scanunit_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "proxy_hardware_acceleration": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "fgd_alert_subscription": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "advisory"},
                {"value": "latest-threat"},
                {"value": "latest-virus"},
                {"value": "latest-attack"},
                {"value": "new-antivirus-db"},
                {"value": "new-attack-db"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ipsec_hmac_offload": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_accept_dad": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ipv6_allow_anycast_probe": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_allow_multicast_probe": {
            "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_allow_local_in_silent_drop": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "csr_ca_attribute": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wimax_4g_usb": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cert_chain_max": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sslvpn_max_worker_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "sslvpn_affinity": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "sslvpn_web_mode": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "two_factor_ftk_expiry": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "two_factor_email_expiry": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "two_factor_sms_expiry": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "two_factor_fac_expiry": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "two_factor_ftm_expiry": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "per_user_bal": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wad_worker_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "wad_csvc_cs_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "wad_csvc_db_count": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "wad_source_affinity": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "wad_memory_change_granularity": {
            "v_range": [["v6.2.0", ""]],
            "type": "integer",
        },
        "login_timestamp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_conflict_detection": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "miglogd_children": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "special_file_23_support": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "log_uuid_address": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_ssl_connection": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_rest_api_cache": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rest_api_key_url_query": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_cdn_domain_override": {
            "v_range": [["v7.0.12", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
        },
        "arp_max_entry": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ha_affinity": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "bfd_affinity": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "cmdbsvr_affinity": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "av_affinity": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wad_affinity": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ips_affinity": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
        },
        "miglog_affinity": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "syslog_affinity": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "url_filter_affinity": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "router_affinity": {"v_range": [["v7.6.4", ""]], "type": "string"},
        "ndp_max_entry": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "br_fdb_max_entry": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "max_route_cache_size": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ipsec_asic_offload": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "device_idle_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "user_device_store_max_devices": {
            "v_range": [["v6.4.4", ""]],
            "type": "integer",
        },
        "user_device_store_max_device_mem": {
            "v_range": [["v7.6.3", ""]],
            "type": "integer",
        },
        "user_device_store_max_users": {"v_range": [["v6.4.4", ""]], "type": "integer"},
        "user_device_store_max_unified_mem": {
            "v_range": [["v7.0.2", ""]],
            "type": "integer",
        },
        "gui_device_latitude": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "gui_device_longitude": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "private_data_encryption": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "auto_auth_extension_device": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_theme": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "jade", "v_range": [["v7.0.0", ""]]},
                {"value": "neutrino", "v_range": [["v6.2.0", ""]]},
                {"value": "mariner"},
                {"value": "graphite", "v_range": [["v7.0.0", ""]]},
                {"value": "melongene"},
                {"value": "jet-stream", "v_range": [["v7.4.0", ""]]},
                {"value": "security-fabric", "v_range": [["v7.4.0", ""]]},
                {"value": "retro", "v_range": [["v7.0.0", ""]]},
                {"value": "dark-matter", "v_range": [["v7.0.0", ""]]},
                {"value": "onyx", "v_range": [["v7.0.0", ""]]},
                {"value": "eclipse", "v_range": [["v7.0.0", ""]]},
                {"value": "green", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "blue", "v_range": [["v6.0.0", "v6.4.4"]]},
                {"value": "red", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
        },
        "gui_date_format": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "yyyy/MM/dd"},
                {"value": "dd/MM/yyyy"},
                {"value": "MM/dd/yyyy"},
                {"value": "yyyy-MM-dd"},
                {"value": "dd-MM-yyyy"},
                {"value": "MM-dd-yyyy"},
            ],
        },
        "gui_date_time_source": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "system"}, {"value": "browser"}],
        },
        "igmp_state_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "cloud_communication": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipsec_ha_seqjump_rate": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "fortitoken_cloud": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fortitoken_cloud_push_status": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fortitoken_cloud_region": {"v_range": [["v7.6.4", ""]], "type": "string"},
        "fortitoken_cloud_sync_interval": {
            "v_range": [["v7.4.1", ""]],
            "type": "integer",
        },
        "faz_disk_buffer_size": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "irq_time_accounting": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "force"}],
        },
        "management_ip": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "management_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "management_port_use_admin_sport": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forticonverter_integration": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forticonverter_config_upload": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "once"}, {"value": "disable"}],
        },
        "internet_service_database": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [
                {"value": "mini"},
                {"value": "standard"},
                {"value": "full"},
                {"value": "on-demand", "v_range": [["v7.2.4", ""]]},
            ],
        },
        "internet_service_download_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v7.4.0", ""]], "type": "integer", "required": True}
            },
            "v_range": [["v7.4.0", ""]],
        },
        "early_tcp_npu_session": {
            "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "npu_neighbor_update": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "delay_tcp_npu_session": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "interface_subnet_usage": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "sflowd_max_children_num": {"v_range": [["v7.2.4", ""]], "type": "integer"},
        "fortigslb_integration": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "user_history_password_threshold": {
            "v_range": [["v7.6.0", ""]],
            "type": "integer",
        },
        "auth_session_auto_backup": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_session_auto_backup_interval": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [
                {"value": "1min"},
                {"value": "5min"},
                {"value": "15min"},
                {"value": "30min"},
                {"value": "1hr"},
            ],
        },
        "scim_https_port": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "scim_http_port": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "scim_server_cert": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "application_bandwidth_tracking": {
            "v_range": [["v7.6.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "tls_session_cache": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vpn_ems_sn_check": {
            "v_range": [["v7.4.0", "v7.6.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipsec_qat_offload": {
            "v_range": [],
            "type": "string",
            "options": [
                {"value": "enable", "v_range": [["v7.4.4", "v7.6.1"]]},
                {"value": "disable", "v_range": [["v7.4.4", "v7.6.1"]]},
            ],
        },
        "security_rating_run_on_schedule": {
            "v_range": [["v6.0.0", "v7.6.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipsec_round_robin": {
            "v_range": [["v7.4.0", "v7.6.0"]],
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "v_range": [
                        ["v7.0.6", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.0"],
                    ],
                },
                {
                    "value": "disable",
                    "v_range": [
                        ["v7.0.6", "v7.0.12"],
                        ["v7.2.1", "v7.2.2"],
                        ["v7.4.0", "v7.6.0"],
                    ],
                },
            ],
        },
        "ssh_kex_algo": {
            "v_range": [["v7.0.2", "v7.4.3"]],
            "type": "list",
            "options": [
                {"value": "diffie-hellman-group1-sha1"},
                {"value": "diffie-hellman-group14-sha1"},
                {
                    "value": "diffie-hellman-group14-sha256",
                    "v_range": [["v7.4.1", "v7.4.3"]],
                },
                {
                    "value": "diffie-hellman-group16-sha512",
                    "v_range": [["v7.4.1", "v7.4.3"]],
                },
                {
                    "value": "diffie-hellman-group18-sha512",
                    "v_range": [["v7.4.1", "v7.4.3"]],
                },
                {"value": "diffie-hellman-group-exchange-sha1"},
                {"value": "diffie-hellman-group-exchange-sha256"},
                {"value": "curve25519-sha256@libssh.org"},
                {"value": "ecdh-sha2-nistp256"},
                {"value": "ecdh-sha2-nistp384"},
                {"value": "ecdh-sha2-nistp521"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ssh_enc_algo": {
            "v_range": [["v7.0.2", "v7.4.3"]],
            "type": "list",
            "options": [
                {"value": "chacha20-poly1305@openssh.com"},
                {"value": "aes128-ctr"},
                {"value": "aes192-ctr"},
                {"value": "aes256-ctr"},
                {"value": "arcfour256"},
                {"value": "arcfour128"},
                {"value": "aes128-cbc"},
                {"value": "3des-cbc"},
                {"value": "blowfish-cbc"},
                {"value": "cast128-cbc"},
                {"value": "aes192-cbc"},
                {"value": "aes256-cbc"},
                {"value": "arcfour"},
                {"value": "rijndael-cbc@lysator.liu.se"},
                {"value": "aes128-gcm@openssh.com"},
                {"value": "aes256-gcm@openssh.com"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ssh_mac_algo": {
            "v_range": [["v7.0.2", "v7.4.3"]],
            "type": "list",
            "options": [
                {"value": "hmac-md5"},
                {"value": "hmac-md5-etm@openssh.com"},
                {"value": "hmac-md5-96"},
                {"value": "hmac-md5-96-etm@openssh.com"},
                {"value": "hmac-sha1"},
                {"value": "hmac-sha1-etm@openssh.com"},
                {"value": "hmac-sha2-256"},
                {"value": "hmac-sha2-256-etm@openssh.com"},
                {"value": "hmac-sha2-512"},
                {"value": "hmac-sha2-512-etm@openssh.com"},
                {"value": "hmac-ripemd160"},
                {"value": "hmac-ripemd160@openssh.com"},
                {"value": "hmac-ripemd160-etm@openssh.com"},
                {"value": "umac-64@openssh.com"},
                {"value": "umac-128@openssh.com"},
                {"value": "umac-64-etm@openssh.com"},
                {"value": "umac-128-etm@openssh.com"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ssh_hostkey_algo": {
            "v_range": [["v7.4.0", "v7.4.3"]],
            "type": "list",
            "options": [
                {"value": "ssh-rsa"},
                {"value": "ecdsa-sha2-nistp521"},
                {"value": "ecdsa-sha2-nistp384", "v_range": [["v7.4.2", "v7.4.3"]]},
                {"value": "ecdsa-sha2-nistp256", "v_range": [["v7.4.2", "v7.4.3"]]},
                {"value": "rsa-sha2-256"},
                {"value": "rsa-sha2-512"},
                {"value": "ssh-ed25519"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ssh_hostkey_override": {
            "v_range": [["v7.4.2", "v7.4.3"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssh_hostkey_password": {"v_range": [["v7.4.2", "v7.4.3"]], "type": "string"},
        "ssh_hostkey": {"v_range": [["v7.4.2", "v7.4.3"]], "type": "string"},
        "security_rating_result_submission": {
            "v_range": [["v6.0.0", "v7.4.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipv6_allow_local_in_slient_drop": {
            "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", "v7.4.3"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "virtual_switch_vlan": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "split_port_mode": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "required": True,
                },
                "split_mode": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "4x10G"},
                        {"value": "4x25G"},
                        {"value": "4x50G"},
                        {"value": "8x25G"},
                        {"value": "8x50G"},
                        {"value": "4x100G"},
                        {"value": "2x200G"},
                    ],
                },
            },
            "v_range": [["v7.4.2", "v7.4.2"]],
        },
        "ipsec_soft_dec_async": {
            "v_range": [["v6.0.0", "v7.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_allow_default_hostname": {
            "v_range": [["v6.2.0", "v7.4.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sslvpn_ems_sn_check": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "proxy_re_authentication_mode": {
            "v_range": [["v6.0.0", "v7.2.2"]],
            "type": "string",
            "options": [
                {"value": "session"},
                {"value": "traffic"},
                {"value": "absolute"},
            ],
        },
        "admin_maintainer": {
            "v_range": [["v6.0.0", "v7.2.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sslvpn_plugin_version_check": {
            "v_range": [["v6.0.0", "v7.2.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sslvpn_kxp_hardware_acceleration": {
            "v_range": [["v6.0.0", "v7.2.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sslvpn_cipher_hardware_acceleration": {
            "v_range": [["v6.0.0", "v7.2.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dst": {
            "v_range": [["v6.0.0", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "user_server_cert": {"v_range": [["v6.0.0", "v7.2.0"]], "type": "string"},
        "forticarrier_bypass": {
            "v_range": [["v7.0.4", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_fortiguard_resource_fetch": {
            "v_range": [["v7.0.6", "v7.0.12"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssh_cbc_cipher": {
            "v_range": [["v6.0.0", "v7.0.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssh_hmac_md5": {
            "v_range": [["v6.0.0", "v7.0.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssh_kex_sha1": {
            "v_range": [["v6.0.0", "v7.0.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssh_mac_weak": {
            "v_range": [["v6.2.0", "v7.0.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fec_port": {"v_range": [["v6.2.0", "v7.0.1"]], "type": "integer"},
        "fortiipam_integration": {
            "v_range": [["v6.4.4", "v7.0.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_fortisandbox_cloud": {
            "v_range": [["v6.2.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "per_user_bwl": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gui_lines_per_page": {
            "v_range": [["v6.0.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "integer",
        },
        "log_uuid_policy": {
            "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "max_dlpstat_memory": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "proxy_kxp_hardware_acceleration": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "proxy_cipher_hardware_acceleration": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "device_identification_active_scan_delay": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "integer",
        },
        "vdom_admin": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [
                {"value": "enable", "v_range": [["v6.0.0", "v6.0.11"]]},
                {"value": "disable", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
        },
        "virtual_server_count": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "integer",
        },
        "virtual_server_hardware_acceleration": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "multicast_forward": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mc_ttl_notchange": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "asymroute": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "endpoint_control_portal_port": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "integer",
        },
        "endpoint_control_fds_access": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tp_mc_skip_policy": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_uuid": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "policy-only"},
                {"value": "extended"},
            ],
        },
        "compliance_check": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "compliance_check_time": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
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
        "system_global": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_global"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_global"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_global"
        )

        is_error, has_changed, result, diff = fortios_system(
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
