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
module: fmgr_devprof_system_global
short_description: Configure global attributes.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    devprof:
        description: The parameter (devprof) in requested url.
        type: str
        required: true
    devprof_system_global:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            admin_https_redirect:
                aliases: ['admin-https-redirect']
                type: str
                description: Enable/disable redirection of HTTP administration access to HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            admin_port:
                aliases: ['admin-port']
                type: int
                description: Administrative access port for HTTP.
            admin_scp:
                aliases: ['admin-scp']
                type: str
                description: Enable/disable using SCP to download the system configuration.
                choices:
                    - 'disable'
                    - 'enable'
            admin_sport:
                aliases: ['admin-sport']
                type: int
                description: Administrative access port for HTTPS.
            admin_ssh_port:
                aliases: ['admin-ssh-port']
                type: int
                description: Administrative access port for SSH.
            admin_ssh_v1:
                aliases: ['admin-ssh-v1']
                type: str
                description: Enable/disable SSH v1 compatibility.
                choices:
                    - 'disable'
                    - 'enable'
            admin_telnet_port:
                aliases: ['admin-telnet-port']
                type: int
                description: Administrative access port for TELNET.
            admintimeout:
                type: int
                description: Number of minutes before an idle administrator session times out
            gui_ipv6:
                aliases: ['gui-ipv6']
                type: str
                description: Enable/disable IPv6 settings on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_lines_per_page:
                aliases: ['gui-lines-per-page']
                type: int
                description: Number of lines to display per page for web administration.
            gui_theme:
                aliases: ['gui-theme']
                type: str
                description: Color scheme for the administration GUI.
                choices:
                    - 'blue'
                    - 'green'
                    - 'melongene'
                    - 'red'
                    - 'mariner'
                    - 'neutrino'
                    - 'jade'
                    - 'graphite'
                    - 'dark-matter'
                    - 'onyx'
                    - 'eclipse'
                    - 'retro'
                    - 'fpx'
                    - 'jet-stream'
                    - 'security-fabric'
            language:
                type: str
                description: GUI display language.
                choices:
                    - 'english'
                    - 'simch'
                    - 'japanese'
                    - 'korean'
                    - 'spanish'
                    - 'trach'
                    - 'french'
                    - 'portuguese'
            switch_controller:
                aliases: ['switch-controller']
                type: str
                description: Enable/disable switch controller feature.
                choices:
                    - 'disable'
                    - 'enable'
            gui_device_latitude:
                aliases: ['gui-device-latitude']
                type: str
                description:
                    - Support meta variable
                    - Add the latitude of the location of this FortiGate to position it on the Threat Map.
            gui_device_longitude:
                aliases: ['gui-device-longitude']
                type: str
                description:
                    - Support meta variable
                    - Add the longitude of the location of this FortiGate to position it on the Threat Map.
            hostname:
                type: str
                description:
                    - Support meta variable
                    - FortiGate units hostname.
            timezone:
                type: list
                elements: str
                description:
                    - Support meta variable
                    - Timezone database name.
                choices:
                    - '00'
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
                    - '33'
                    - '34'
                    - '35'
                    - '36'
                    - '37'
                    - '38'
                    - '39'
                    - '40'
                    - '41'
                    - '42'
                    - '43'
                    - '44'
                    - '45'
                    - '46'
                    - '47'
                    - '48'
                    - '49'
                    - '50'
                    - '51'
                    - '52'
                    - '53'
                    - '54'
                    - '55'
                    - '56'
                    - '57'
                    - '58'
                    - '59'
                    - '60'
                    - '61'
                    - '62'
                    - '63'
                    - '64'
                    - '65'
                    - '66'
                    - '67'
                    - '68'
                    - '69'
                    - '70'
                    - '71'
                    - '72'
                    - '73'
                    - '74'
                    - '75'
                    - '76'
                    - '77'
                    - '78'
                    - '79'
                    - '80'
                    - '81'
                    - '82'
                    - '83'
                    - '84'
                    - '85'
                    - '86'
                    - '87'
            check_reset_range:
                aliases: ['check-reset-range']
                type: str
                description: Configure ICMP error message verification.
                choices:
                    - 'disable'
                    - 'strict'
            pmtu_discovery:
                aliases: ['pmtu-discovery']
                type: str
                description: Enable/disable path MTU discovery.
                choices:
                    - 'disable'
                    - 'enable'
            gui_allow_incompatible_fabric_fgt:
                aliases: ['gui-allow-incompatible-fabric-fgt']
                type: str
                description: Enable/disable Allow FGT with incompatible firmware to be treated as compatible in security fabric on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            admin_restrict_local:
                aliases: ['admin-restrict-local']
                type: str
                description: Enable/disable local admin authentication restriction when remote authenticator is up and running
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'non-console-only'
            gui_workflow_management:
                aliases: ['gui-workflow-management']
                type: str
                description: Enable/disable Workflow management features on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            send_pmtu_icmp:
                aliases: ['send-pmtu-icmp']
                type: str
                description: Enable/disable sending of path maximum transmission unit
                choices:
                    - 'disable'
                    - 'enable'
            tcp_halfclose_timer:
                aliases: ['tcp-halfclose-timer']
                type: int
                description: Number of seconds the FortiGate unit should wait to close a session after one peer has sent a FIN packet but the other has...
            admin_server_cert:
                aliases: ['admin-server-cert']
                type: raw
                description: (list) Server certificate that the FortiGate uses for HTTPS administrative connections.
            dnsproxy_worker_count:
                aliases: ['dnsproxy-worker-count']
                type: int
                description: DNS proxy worker count.
            show_backplane_intf:
                aliases: ['show-backplane-intf']
                type: str
                description: Show/hide backplane interfaces
                choices:
                    - 'disable'
                    - 'enable'
            gui_custom_language:
                aliases: ['gui-custom-language']
                type: str
                description: Enable/disable custom languages in GUI.
                choices:
                    - 'disable'
                    - 'enable'
            ldapconntimeout:
                type: int
                description: Global timeout for connections with remote LDAP servers in milliseconds
            auth_https_port:
                aliases: ['auth-https-port']
                type: int
                description: User authentication HTTPS port.
            revision_backup_on_logout:
                aliases: ['revision-backup-on-logout']
                type: str
                description: Enable/disable back-up of the latest configuration revision when an administrator logs out of the CLI or GUI.
                choices:
                    - 'disable'
                    - 'enable'
            arp_max_entry:
                aliases: ['arp-max-entry']
                type: int
                description: Maximum number of dynamically learned MAC addresses that can be added to the ARP table
            long_vdom_name:
                aliases: ['long-vdom-name']
                type: str
                description: Enable/disable long VDOM name support.
                choices:
                    - 'disable'
                    - 'enable'
            pre_login_banner:
                aliases: ['pre-login-banner']
                type: str
                description: Enable/disable displaying the administrator access disclaimer message on the login page before an administrator logs in.
                choices:
                    - 'disable'
                    - 'enable'
            qsfpdd_split8_port:
                aliases: ['qsfpdd-split8-port']
                type: raw
                description: (list) Split qsfpddd port
            max_route_cache_size:
                aliases: ['max-route-cache-size']
                type: int
                description: Maximum number of IP route cache entries
            fortitoken_cloud_push_status:
                aliases: ['fortitoken-cloud-push-status']
                type: str
                description: Enable/disable FTM push service of FortiToken Cloud.
                choices:
                    - 'disable'
                    - 'enable'
            ssh_hostkey_override:
                aliases: ['ssh-hostkey-override']
                type: str
                description: Enable/disable SSH host key override in SSH daemon.
                choices:
                    - 'disable'
                    - 'enable'
            proxy_hardware_acceleration:
                aliases: ['proxy-hardware-acceleration']
                type: str
                description: Enable/disable email proxy hardware acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            switch_controller_reserved_network:
                aliases: ['switch-controller-reserved-network']
                type: raw
                description: (list) Configure reserved network subnet for managed switches.
            ssd_trim_date:
                aliases: ['ssd-trim-date']
                type: int
                description: Date within a month to run ssd trim.
            wad_worker_count:
                aliases: ['wad-worker-count']
                type: int
                description: Number of explicit proxy WAN optimization daemon
            ssh_hostkey:
                aliases: ['ssh-hostkey']
                type: str
                description: Config SSH host key.
            wireless_controller_port:
                aliases: ['wireless-controller-port']
                type: int
                description: Port used for the control channel in wireless controller mode
            fgd_alert_subscription:
                aliases: ['fgd-alert-subscription']
                type: list
                elements: str
                description: Type of alert to retrieve from FortiGuard.
                choices:
                    - 'advisory'
                    - 'latest-threat'
                    - 'latest-virus'
                    - 'latest-attack'
                    - 'new-antivirus-db'
                    - 'new-attack-db'
            forticontroller_proxy_port:
                aliases: ['forticontroller-proxy-port']
                type: int
                description: FortiController proxy port
            dh_params:
                aliases: ['dh-params']
                type: str
                description: Number of bits to use in the Diffie-Hellman exchange for HTTPS/SSH protocols.
                choices:
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
                    - '6144'
                    - '8192'
            memory_use_threshold_green:
                aliases: ['memory-use-threshold-green']
                type: int
                description: Threshold at which memory usage forces the FortiGate to exit conserve mode
            proxy_cert_use_mgmt_vdom:
                aliases: ['proxy-cert-use-mgmt-vdom']
                type: str
                description: Enable/disable using management VDOM to send requests.
                choices:
                    - 'disable'
                    - 'enable'
            proxy_auth_lifetime_timeout:
                aliases: ['proxy-auth-lifetime-timeout']
                type: int
                description: Lifetime timeout in minutes for authenticated users
            gui_auto_upgrade_setup_warning:
                aliases: ['gui-auto-upgrade-setup-warning']
                type: str
                description: Enable/disable the automatic patch upgrade setup prompt on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_cdn_usage:
                aliases: ['gui-cdn-usage']
                type: str
                description: Enable/disable Load GUI static files from a CDN.
                choices:
                    - 'disable'
                    - 'enable'
            two_factor_email_expiry:
                aliases: ['two-factor-email-expiry']
                type: int
                description: Email-based two-factor authentication session timeout
            udp_idle_timer:
                aliases: ['udp-idle-timer']
                type: int
                description: UDP connection session timeout.
            interface_subnet_usage:
                aliases: ['interface-subnet-usage']
                type: str
                description: Enable/disable allowing use of interface-subnet setting in firewall addresses
                choices:
                    - 'disable'
                    - 'enable'
            forticontroller_proxy:
                aliases: ['forticontroller-proxy']
                type: str
                description: Enable/disable FortiController proxy.
                choices:
                    - 'disable'
                    - 'enable'
            ssh_enc_algo:
                aliases: ['ssh-enc-algo']
                type: list
                elements: str
                description: Select one or more SSH ciphers.
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
            block_session_timer:
                aliases: ['block-session-timer']
                type: int
                description: Duration in seconds for blocked sessions
            quic_pmtud:
                aliases: ['quic-pmtud']
                type: str
                description: Enable/disable path MTU discovery
                choices:
                    - 'disable'
                    - 'enable'
            admin_https_ssl_ciphersuites:
                aliases: ['admin-https-ssl-ciphersuites']
                type: list
                elements: str
                description: Select one or more TLS 1.
                choices:
                    - 'TLS-AES-128-GCM-SHA256'
                    - 'TLS-AES-256-GCM-SHA384'
                    - 'TLS-CHACHA20-POLY1305-SHA256'
                    - 'TLS-AES-128-CCM-SHA256'
                    - 'TLS-AES-128-CCM-8-SHA256'
            security_rating_result_submission:
                aliases: ['security-rating-result-submission']
                type: str
                description: Enable/disable the submission of Security Rating results to FortiGuard.
                choices:
                    - 'disable'
                    - 'enable'
            user_device_store_max_unified_mem:
                aliases: ['user-device-store-max-unified-mem']
                type: int
                description: Maximum unified memory allowed in user device store.
            management_port:
                aliases: ['management-port']
                type: int
                description: Overriding port for management connection
            fortigslb_integration:
                aliases: ['fortigslb-integration']
                type: str
                description: Enable/disable integration with the FortiGSLB cloud service.
                choices:
                    - 'disable'
                    - 'enable'
            admin_https_ssl_versions:
                aliases: ['admin-https-ssl-versions']
                type: list
                elements: str
                description: Allowed TLS versions for web administration.
                choices:
                    - 'tlsv1-0'
                    - 'tlsv1-1'
                    - 'tlsv1-2'
                    - 'sslv3'
                    - 'tlsv1-3'
            cert_chain_max:
                aliases: ['cert-chain-max']
                type: int
                description: Maximum number of certificates that can be traversed in a certificate chain.
            qsfp28_40g_port:
                aliases: ['qsfp28-40g-port']
                type: raw
                description: (list) Set port
            strong_crypto:
                aliases: ['strong-crypto']
                type: str
                description: Enable to use strong encryption and only allow strong ciphers and digest for HTTPS/SSH/TLS/SSL functions.
                choices:
                    - 'disable'
                    - 'enable'
            multi_factor_authentication:
                aliases: ['multi-factor-authentication']
                type: str
                description: Enforce all login methods to require an additional authentication factor
                choices:
                    - 'optional'
                    - 'mandatory'
            fds_statistics:
                aliases: ['fds-statistics']
                type: str
                description: Enable/disable sending IPS, Application Control, and AntiVirus data to FortiGuard.
                choices:
                    - 'disable'
                    - 'enable'
            gui_display_hostname:
                aliases: ['gui-display-hostname']
                type: str
                description: Enable/disable displaying the FortiGates hostname on the GUI login page.
                choices:
                    - 'disable'
                    - 'enable'
            two_factor_ftk_expiry:
                aliases: ['two-factor-ftk-expiry']
                type: int
                description: FortiToken authentication session timeout
            wad_source_affinity:
                aliases: ['wad-source-affinity']
                type: str
                description: Enable/disable dispatching traffic to WAD workers based on source affinity.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_static_key_ciphers:
                aliases: ['ssl-static-key-ciphers']
                type: str
                description: Enable/disable static key ciphers in SSL/TLS connections
                choices:
                    - 'disable'
                    - 'enable'
            daily_restart:
                aliases: ['daily-restart']
                type: str
                description: Enable/disable daily restart of FortiGate unit.
                choices:
                    - 'disable'
                    - 'enable'
            snat_route_change:
                aliases: ['snat-route-change']
                type: str
                description: Enable/disable the ability to change the source NAT route.
                choices:
                    - 'disable'
                    - 'enable'
            tcp_rst_timer:
                aliases: ['tcp-rst-timer']
                type: int
                description: Length of the TCP CLOSE state in seconds
            anti_replay:
                aliases: ['anti-replay']
                type: str
                description: Level of checking for packet replay and TCP sequence checking.
                choices:
                    - 'disable'
                    - 'loose'
                    - 'strict'
            ssl_min_proto_version:
                aliases: ['ssl-min-proto-version']
                type: str
                description: Minimum supported protocol version for SSL/TLS connections
                choices:
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1-3'
            speedtestd_server_port:
                aliases: ['speedtestd-server-port']
                type: int
                description: Speedtest server port number.
            cpu_use_threshold:
                aliases: ['cpu-use-threshold']
                type: int
                description: Threshold at which CPU usage is reported
            admin_host:
                aliases: ['admin-host']
                type: str
                description: Administrative host for HTTP and HTTPS.
            csr_ca_attribute:
                aliases: ['csr-ca-attribute']
                type: str
                description: Enable/disable the CA attribute in certificates.
                choices:
                    - 'disable'
                    - 'enable'
            fortiservice_port:
                aliases: ['fortiservice-port']
                type: int
                description: FortiService port
            ssd_trim_hour:
                aliases: ['ssd-trim-hour']
                type: int
                description: Hour of the day on which to run SSD Trim
            purdue_level:
                aliases: ['purdue-level']
                type: str
                description: Purdue Level of this FortiGate.
                choices:
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '1.5'
                    - '2.5'
                    - '3.5'
                    - '5.5'
            management_vdom:
                aliases: ['management-vdom']
                type: raw
                description: (list) Management virtual domain name.
            quic_ack_thresold:
                aliases: ['quic-ack-thresold']
                type: int
                description: Maximum number of unacknowledged packets before sending ACK
            qsfpdd_100g_port:
                aliases: ['qsfpdd-100g-port']
                type: raw
                description: (list) Split qsfpddd port
            ips_affinity:
                aliases: ['ips-affinity']
                type: str
                description: Affinity setting for IPS
            vip_arp_range:
                aliases: ['vip-arp-range']
                type: str
                description: Controls the number of ARPs that the FortiGate sends for a Virtual IP
                choices:
                    - 'restricted'
                    - 'unlimited'
            internet_service_database:
                aliases: ['internet-service-database']
                type: str
                description: Configure which Internet Service database size to download from FortiGuard and use.
                choices:
                    - 'mini'
                    - 'standard'
                    - 'full'
                    - 'on-demand'
            revision_image_auto_backup:
                aliases: ['revision-image-auto-backup']
                type: str
                description: Enable/disable back-up of the latest image revision after the firmware is upgraded.
                choices:
                    - 'disable'
                    - 'enable'
            sflowd_max_children_num:
                aliases: ['sflowd-max-children-num']
                type: int
                description: Maximum number of sflowd child processes allowed to run.
            admin_https_pki_required:
                aliases: ['admin-https-pki-required']
                type: str
                description: Enable/disable admin login method.
                choices:
                    - 'disable'
                    - 'enable'
            special_file_23_support:
                aliases: ['special-file-23-support']
                type: str
                description: Enable/disable detection of those special format files when using Data Loss Prevention.
                choices:
                    - 'disable'
                    - 'enable'
            npu_neighbor_update:
                aliases: ['npu-neighbor-update']
                type: str
                description: Enable/disable sending of ARP/ICMP6 probing packets to update neighbors for offloaded sessions.
                choices:
                    - 'disable'
                    - 'enable'
            log_single_cpu_high:
                aliases: ['log-single-cpu-high']
                type: str
                description: Enable/disable logging the event of a single CPU core reaching CPU usage threshold.
                choices:
                    - 'disable'
                    - 'enable'
            management_ip:
                aliases: ['management-ip']
                type: str
                description: Management IP address of this FortiGate.
            proxy_resource_mode:
                aliases: ['proxy-resource-mode']
                type: str
                description: Enable/disable use of the maximum memory usage on the FortiGate units proxy processing of resources, such as block lists, ...
                choices:
                    - 'disable'
                    - 'enable'
            admin_ble_button:
                aliases: ['admin-ble-button']
                type: str
                description: Press the BLE button can enable BLE function
                choices:
                    - 'disable'
                    - 'enable'
            gui_firmware_upgrade_warning:
                aliases: ['gui-firmware-upgrade-warning']
                type: str
                description: Enable/disable the firmware upgrade warning on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            dp_tcp_normal_timer:
                aliases: ['dp-tcp-normal-timer']
                type: int
                description: DP tcp normal timeout
            ipv6_allow_traffic_redirect:
                aliases: ['ipv6-allow-traffic-redirect']
                type: str
                description: Disable to prevent IPv6 traffic with same local ingress and egress interface from being forwarded without policy check.
                choices:
                    - 'disable'
                    - 'enable'
            cli_audit_log:
                aliases: ['cli-audit-log']
                type: str
                description: Enable/disable CLI audit log.
                choices:
                    - 'disable'
                    - 'enable'
            memory_use_threshold_extreme:
                aliases: ['memory-use-threshold-extreme']
                type: int
                description: Threshold at which memory usage is considered extreme
            ha_affinity:
                aliases: ['ha-affinity']
                type: str
                description: Affinity setting for HA daemons
            restart_time:
                aliases: ['restart-time']
                type: str
                description: Daily restart time
            speedtestd_ctrl_port:
                aliases: ['speedtestd-ctrl-port']
                type: int
                description: Speedtest server controller port number.
            gui_wireless_opensecurity:
                aliases: ['gui-wireless-opensecurity']
                type: str
                description: Enable/disable wireless open security option on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            memory_use_threshold_red:
                aliases: ['memory-use-threshold-red']
                type: int
                description: Threshold at which memory usage forces the FortiGate to enter conserve mode
            dp_fragment_timer:
                aliases: ['dp-fragment-timer']
                type: int
                description: DP fragment session timeout
            wad_restart_start_time:
                aliases: ['wad-restart-start-time']
                type: str
                description: WAD workers daily restart time
            proxy_re_authentication_time:
                aliases: ['proxy-re-authentication-time']
                type: int
                description: The time limit that users must re-authenticate if proxy-keep-alive-mode is set to re-authenticate
            gui_app_detection_sdwan:
                aliases: ['gui-app-detection-sdwan']
                type: str
                description: Enable/disable Allow app-detection based SD-WAN.
                choices:
                    - 'disable'
                    - 'enable'
            scanunit_count:
                aliases: ['scanunit-count']
                type: int
                description: Number of scanunits.
            tftp:
                type: str
                description: Enable/disable TFTP.
                choices:
                    - 'disable'
                    - 'enable'
            xstools_update_frequency:
                aliases: ['xstools-update-frequency']
                type: int
                description: Xenserver tools daemon update frequency
            clt_cert_req:
                aliases: ['clt-cert-req']
                type: str
                description: Enable/disable requiring administrators to have a client certificate to log into the GUI using HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            fortiextender_vlan_mode:
                aliases: ['fortiextender-vlan-mode']
                type: str
                description: Enable/disable FortiExtender VLAN mode.
                choices:
                    - 'disable'
                    - 'enable'
            auth_http_port:
                aliases: ['auth-http-port']
                type: int
                description: User authentication HTTP port.
            per_user_bal:
                aliases: ['per-user-bal']
                type: str
                description: Enable/disable per-user block/allow list filter.
                choices:
                    - 'disable'
                    - 'enable'
            gui_date_format:
                aliases: ['gui-date-format']
                type: str
                description: Default date format used throughout GUI.
                choices:
                    - 'yyyy/MM/dd'
                    - 'dd/MM/yyyy'
                    - 'MM/dd/yyyy'
                    - 'yyyy-MM-dd'
                    - 'dd-MM-yyyy'
                    - 'MM-dd-yyyy'
            log_uuid_address:
                aliases: ['log-uuid-address']
                type: str
                description: Enable/disable insertion of address UUIDs to traffic logs.
                choices:
                    - 'disable'
                    - 'enable'
            cloud_communication:
                aliases: ['cloud-communication']
                type: str
                description: Enable/disable all cloud communication.
                choices:
                    - 'disable'
                    - 'enable'
            lldp_reception:
                aliases: ['lldp-reception']
                type: str
                description: Enable/disable Link Layer Discovery Protocol
                choices:
                    - 'disable'
                    - 'enable'
            two_factor_ftm_expiry:
                aliases: ['two-factor-ftm-expiry']
                type: int
                description: FortiToken Mobile session timeout
            quic_udp_payload_size_shaping_per_cid:
                aliases: ['quic-udp-payload-size-shaping-per-cid']
                type: str
                description: Enable/disable UDP payload size shaping per connection ID
                choices:
                    - 'disable'
                    - 'enable'
            autorun_log_fsck:
                aliases: ['autorun-log-fsck']
                type: str
                description: Enable/disable automatic log partition check after ungraceful shutdown.
                choices:
                    - 'disable'
                    - 'enable'
            vpn_ems_sn_check:
                aliases: ['vpn-ems-sn-check']
                type: str
                description: Enable/disable verification of EMS serial number in SSL-VPN connection.
                choices:
                    - 'disable'
                    - 'enable'
            admin_ssh_password:
                aliases: ['admin-ssh-password']
                type: str
                description: Enable/disable password authentication for SSH admin access.
                choices:
                    - 'disable'
                    - 'enable'
            airplane_mode:
                aliases: ['airplane-mode']
                type: str
                description: Enable/disable airplane mode.
                choices:
                    - 'disable'
                    - 'enable'
            batch_cmdb:
                aliases: ['batch-cmdb']
                type: str
                description: Enable/disable batch mode, allowing you to enter a series of CLI commands that will execute as a group once they are loaded.
                choices:
                    - 'disable'
                    - 'enable'
            ip_src_port_range:
                aliases: ['ip-src-port-range']
                type: raw
                description: (list) IP source port range used for traffic originating from the FortiGate unit.
            strict_dirty_session_check:
                aliases: ['strict-dirty-session-check']
                type: str
                description: Enable to check the session against the original policy when revalidating.
                choices:
                    - 'disable'
                    - 'enable'
            user_device_store_max_devices:
                aliases: ['user-device-store-max-devices']
                type: int
                description: Maximum number of devices allowed in user device store.
            dp_udp_idle_timer:
                aliases: ['dp-udp-idle-timer']
                type: int
                description: DP udp idle timer
            internal_switch_speed:
                aliases: ['internal-switch-speed']
                type: list
                elements: str
                description: Internal port speed.
                choices:
                    - 'auto'
                    - '10full'
                    - '10half'
                    - '100full'
                    - '100half'
                    - '1000full'
                    - '1000auto'
            forticonverter_config_upload:
                aliases: ['forticonverter-config-upload']
                type: str
                description: Enable/disable config upload to FortiConverter.
                choices:
                    - 'disable'
                    - 'once'
            ipsec_round_robin:
                aliases: ['ipsec-round-robin']
                type: str
                description: Enable/disable round-robin redistribution to multiple CPUs for IPsec VPN traffic.
                choices:
                    - 'disable'
                    - 'enable'
            wad_affinity:
                aliases: ['wad-affinity']
                type: str
                description: Affinity setting for wad
            wifi_ca_certificate:
                aliases: ['wifi-ca-certificate']
                type: raw
                description: (list) CA certificate that verifies the WiFi certificate.
            wimax_4g_usb:
                aliases: ['wimax-4g-usb']
                type: str
                description: Enable/disable comparability with WiMAX 4G USB devices.
                choices:
                    - 'disable'
                    - 'enable'
            miglog_affinity:
                aliases: ['miglog-affinity']
                type: str
                description: Affinity setting for logging
            faz_disk_buffer_size:
                aliases: ['faz-disk-buffer-size']
                type: int
                description: Maximum disk buffer size to temporarily store logs destined for FortiAnalyzer.
            ssh_kex_algo:
                aliases: ['ssh-kex-algo']
                type: list
                elements: str
                description: Select one or more SSH kex algorithms.
                choices:
                    - 'diffie-hellman-group1-sha1'
                    - 'diffie-hellman-group14-sha1'
                    - 'diffie-hellman-group-exchange-sha1'
                    - 'diffie-hellman-group-exchange-sha256'
                    - 'curve25519-sha256@libssh.org'
                    - 'ecdh-sha2-nistp256'
                    - 'ecdh-sha2-nistp384'
                    - 'ecdh-sha2-nistp521'
                    - 'diffie-hellman-group14-sha256'
                    - 'diffie-hellman-group16-sha512'
                    - 'diffie-hellman-group18-sha512'
            auto_auth_extension_device:
                aliases: ['auto-auth-extension-device']
                type: str
                description: Enable/disable automatic authorization of dedicated Fortinet extension devices.
                choices:
                    - 'disable'
                    - 'enable'
            forticarrier_bypass:
                aliases: ['forticarrier-bypass']
                type: str
                description: Forticarrier bypass.
                choices:
                    - 'disable'
                    - 'enable'
            reset_sessionless_tcp:
                aliases: ['reset-sessionless-tcp']
                type: str
                description: Action to perform if the FortiGate receives a TCP packet but cannot find a corresponding session in its session table.
                choices:
                    - 'disable'
                    - 'enable'
            early_tcp_npu_session:
                aliases: ['early-tcp-npu-session']
                type: str
                description: Enable/disable early TCP NPU session.
                choices:
                    - 'disable'
                    - 'enable'
            http_unauthenticated_request_limit:
                aliases: ['http-unauthenticated-request-limit']
                type: int
                description: HTTP request body size limit before authentication.
            gui_local_out:
                aliases: ['gui-local-out']
                type: str
                description: Enable/disable Local-out traffic on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            tcp_option:
                aliases: ['tcp-option']
                type: str
                description: Enable SACK, timestamp and MSS TCP options.
                choices:
                    - 'disable'
                    - 'enable'
            proxy_auth_timeout:
                aliases: ['proxy-auth-timeout']
                type: int
                description: Authentication timeout in minutes for authenticated users
            fortiextender_discovery_lockdown:
                aliases: ['fortiextender-discovery-lockdown']
                type: str
                description: Enable/disable FortiExtender CAPWAP lockdown.
                choices:
                    - 'disable'
                    - 'enable'
            lldp_transmission:
                aliases: ['lldp-transmission']
                type: str
                description: Enable/disable Link Layer Discovery Protocol
                choices:
                    - 'disable'
                    - 'enable'
            split_port:
                aliases: ['split-port']
                type: raw
                description: (list) Split port
            gui_certificates:
                aliases: ['gui-certificates']
                type: str
                description: Enable/disable the System > Certificate GUI page, allowing you to add and configure certificates from the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            cfg_save:
                aliases: ['cfg-save']
                type: str
                description: Configuration file save mode for CLI changes.
                choices:
                    - 'automatic'
                    - 'manual'
                    - 'revert'
            auth_keepalive:
                aliases: ['auth-keepalive']
                type: str
                description: Enable to prevent user authentication sessions from timing out when idle.
                choices:
                    - 'disable'
                    - 'enable'
            split_port_mode:
                aliases: ['split-port-mode']
                type: list
                elements: dict
                description: Split port mode.
                suboptions:
                    interface:
                        type: str
                        description: Split port interface.
                    split_mode:
                        aliases: ['split-mode']
                        type: str
                        description: The configuration mode for the split port interface.
                        choices:
                            - 'disable'
                            - '4x10G'
                            - '4x25G'
                            - '4x50G'
                            - '8x50G'
                            - '4x100G'
                            - '2x200G'
                            - '8x25G'
            admin_forticloud_sso_login:
                aliases: ['admin-forticloud-sso-login']
                type: str
                description: Enable/disable FortiCloud admin login via SSO.
                choices:
                    - 'disable'
                    - 'enable'
            post_login_banner:
                aliases: ['post-login-banner']
                type: str
                description: Enable/disable displaying the administrator access disclaimer message after an administrator successfully logs in.
                choices:
                    - 'disable'
                    - 'enable'
            br_fdb_max_entry:
                aliases: ['br-fdb-max-entry']
                type: int
                description: Maximum number of bridge forwarding database
            ip_fragment_mem_thresholds:
                aliases: ['ip-fragment-mem-thresholds']
                type: int
                description: Maximum memory
            fortiextender_provision_on_authorization:
                aliases: ['fortiextender-provision-on-authorization']
                type: str
                description: Enable/disable automatic provisioning of latest FortiExtender firmware on authorization.
                choices:
                    - 'disable'
                    - 'enable'
            reboot_upon_config_restore:
                aliases: ['reboot-upon-config-restore']
                type: str
                description: Enable/disable reboot of system upon restoring configuration.
                choices:
                    - 'disable'
                    - 'enable'
            syslog_affinity:
                aliases: ['syslog-affinity']
                type: str
                description: Affinity setting for syslog
            fortiextender_data_port:
                aliases: ['fortiextender-data-port']
                type: int
                description: FortiExtender data port
            quic_tls_handshake_timeout:
                aliases: ['quic-tls-handshake-timeout']
                type: int
                description: Time-to-live
            forticonverter_integration:
                aliases: ['forticonverter-integration']
                type: str
                description: Enable/disable FortiConverter integration service.
                choices:
                    - 'disable'
                    - 'enable'
            proxy_keep_alive_mode:
                aliases: ['proxy-keep-alive-mode']
                type: str
                description: Control if users must re-authenticate after a session is closed, traffic has been idle, or from the point at which the use...
                choices:
                    - 'session'
                    - 'traffic'
                    - 're-authentication'
            cmdbsvr_affinity:
                aliases: ['cmdbsvr-affinity']
                type: str
                description: Affinity setting for cmdbsvr
            wad_memory_change_granularity:
                aliases: ['wad-memory-change-granularity']
                type: int
                description: Minimum percentage change in system memory usage detected by the wad daemon prior to adjusting TCP window size for any act...
            dhcp_lease_backup_interval:
                aliases: ['dhcp-lease-backup-interval']
                type: int
                description: DHCP leases backup interval in seconds
            check_protocol_header:
                aliases: ['check-protocol-header']
                type: str
                description: Level of checking performed on protocol headers.
                choices:
                    - 'loose'
                    - 'strict'
            av_failopen_session:
                aliases: ['av-failopen-session']
                type: str
                description: When enabled and a proxy for a protocol runs out of room in its session table, that protocol goes into failopen mode and e...
                choices:
                    - 'disable'
                    - 'enable'
            ipsec_ha_seqjump_rate:
                aliases: ['ipsec-ha-seqjump-rate']
                type: int
                description: ESP jump ahead rate
            admin_hsts_max_age:
                aliases: ['admin-hsts-max-age']
                type: int
                description: HTTPS Strict-Transport-Security header max-age in seconds.
            igmp_state_limit:
                aliases: ['igmp-state-limit']
                type: int
                description: Maximum number of IGMP memberships
            admin_login_max:
                aliases: ['admin-login-max']
                type: int
                description: Maximum number of administrators who can be logged in at the same time
            ipv6_allow_multicast_probe:
                aliases: ['ipv6-allow-multicast-probe']
                type: str
                description: Enable/disable IPv6 address probe through Multicast.
                choices:
                    - 'disable'
                    - 'enable'
            virtual_switch_vlan:
                aliases: ['virtual-switch-vlan']
                type: str
                description: Enable/disable virtual switch VLAN.
                choices:
                    - 'disable'
                    - 'enable'
            admin_lockout_threshold:
                aliases: ['admin-lockout-threshold']
                type: int
                description: Number of failed login attempts before an administrator account is locked out for the admin-lockout-duration.
            dp_pinhole_timer:
                aliases: ['dp-pinhole-timer']
                type: int
                description: DP pinhole session timeout
            wireless_controller:
                aliases: ['wireless-controller']
                type: str
                description: Enable/disable the wireless controller feature to use the FortiGate unit to manage FortiAPs.
                choices:
                    - 'disable'
                    - 'enable'
            bfd_affinity:
                aliases: ['bfd-affinity']
                type: str
                description: Affinity setting for BFD daemon
            ssd_trim_freq:
                aliases: ['ssd-trim-freq']
                type: str
                description: How often to run SSD Trim
                choices:
                    - 'daily'
                    - 'weekly'
                    - 'monthly'
                    - 'hourly'
                    - 'never'
            two_factor_sms_expiry:
                aliases: ['two-factor-sms-expiry']
                type: int
                description: SMS-based two-factor authentication session timeout
            traffic_priority:
                aliases: ['traffic-priority']
                type: str
                description: Choose Type of Service
                choices:
                    - 'tos'
                    - 'dscp'
            proxy_and_explicit_proxy:
                aliases: ['proxy-and-explicit-proxy']
                type: str
                description: Proxy and explicit proxy.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_web_mode:
                aliases: ['sslvpn-web-mode']
                type: str
                description: Enable/disable SSL-VPN web mode.
                choices:
                    - 'disable'
                    - 'enable'
            ssh_hostkey_password:
                aliases: ['ssh-hostkey-password']
                type: raw
                description: (list) Password for ssh-hostkey.
            wad_csvc_db_count:
                aliases: ['wad-csvc-db-count']
                type: int
                description: Number of concurrent WAD-cache-service byte-cache processes.
            ipv6_allow_anycast_probe:
                aliases: ['ipv6-allow-anycast-probe']
                type: str
                description: Enable/disable IPv6 address probe through Anycast.
                choices:
                    - 'disable'
                    - 'enable'
            honor_df:
                aliases: ['honor-df']
                type: str
                description: Enable/disable honoring of Dont-Fragment
                choices:
                    - 'disable'
                    - 'enable'
            hyper_scale_vdom_num:
                aliases: ['hyper-scale-vdom-num']
                type: int
                description: Number of VDOMs for hyper scale license.
            wad_csvc_cs_count:
                aliases: ['wad-csvc-cs-count']
                type: int
                description: Number of concurrent WAD-cache-service object-cache processes.
            internal_switch_mode:
                aliases: ['internal-switch-mode']
                type: str
                description: Internal switch mode.
                choices:
                    - 'switch'
                    - 'interface'
                    - 'hub'
            cfg_revert_timeout:
                aliases: ['cfg-revert-timeout']
                type: int
                description: Time-out for reverting to the last saved configuration.
            admin_concurrent:
                aliases: ['admin-concurrent']
                type: str
                description: Enable/disable concurrent administrator logins.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6_allow_local_in_silent_drop:
                aliases: ['ipv6-allow-local-in-silent-drop']
                type: str
                description: Enable/disable silent drop of IPv6 local-in traffic.
                choices:
                    - 'disable'
                    - 'enable'
            tcp_halfopen_timer:
                aliases: ['tcp-halfopen-timer']
                type: int
                description: Number of seconds the FortiGate unit should wait to close a session after one peer has sent an open session packet but the...
            dp_rsync_timer:
                aliases: ['dp-rsync-timer']
                type: int
                description: DP rsync session timeout
            management_port_use_admin_sport:
                aliases: ['management-port-use-admin-sport']
                type: str
                description: Enable/disable use of the admin-sport setting for the management port.
                choices:
                    - 'disable'
                    - 'enable'
            gui_forticare_registration_setup_warning:
                aliases: ['gui-forticare-registration-setup-warning']
                type: str
                description: Enable/disable the FortiCare registration setup warning on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            gui_replacement_message_groups:
                aliases: ['gui-replacement-message-groups']
                type: str
                description: Enable/disable replacement message groups on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            security_rating_run_on_schedule:
                aliases: ['security-rating-run-on-schedule']
                type: str
                description: Enable/disable scheduled runs of Security Rating.
                choices:
                    - 'disable'
                    - 'enable'
            admin_lockout_duration:
                aliases: ['admin-lockout-duration']
                type: int
                description: Amount of time in seconds that an administrator account is locked out after reaching the admin-lockout-threshold for repea...
            optimize_flow_mode:
                aliases: ['optimize-flow-mode']
                type: str
                description: Flow mode optimization option.
                choices:
                    - 'disable'
                    - 'enable'
            private_data_encryption:
                aliases: ['private-data-encryption']
                type: str
                description: Enable/disable private data encryption using an AES 128-bit key or passpharse.
                choices:
                    - 'disable'
                    - 'enable'
            wireless_mode:
                aliases: ['wireless-mode']
                type: str
                description: Wireless mode setting.
                choices:
                    - 'ac'
                    - 'client'
                    - 'wtp'
                    - 'fwfap'
            alias:
                type: str
                description: Alias for your FortiGate unit.
            ssh_hostkey_algo:
                aliases: ['ssh-hostkey-algo']
                type: list
                elements: str
                description: Select one or more SSH hostkey algorithms.
                choices:
                    - 'ssh-rsa'
                    - 'ecdsa-sha2-nistp521'
                    - 'rsa-sha2-256'
                    - 'rsa-sha2-512'
                    - 'ssh-ed25519'
                    - 'ecdsa-sha2-nistp384'
                    - 'ecdsa-sha2-nistp256'
            fortitoken_cloud:
                aliases: ['fortitoken-cloud']
                type: str
                description: Enable/disable FortiToken Cloud service.
                choices:
                    - 'disable'
                    - 'enable'
            av_affinity:
                aliases: ['av-affinity']
                type: str
                description: Affinity setting for AV scanning
            proxy_worker_count:
                aliases: ['proxy-worker-count']
                type: int
                description: Proxy worker count.
            ipsec_asic_offload:
                aliases: ['ipsec-asic-offload']
                type: str
                description: Enable/disable ASIC offloading
                choices:
                    - 'disable'
                    - 'enable'
            miglogd_children:
                aliases: ['miglogd-children']
                type: int
                description: Number of logging
            sslvpn_max_worker_count:
                aliases: ['sslvpn-max-worker-count']
                type: int
                description: Maximum number of SSL-VPN processes.
            ssh_mac_algo:
                aliases: ['ssh-mac-algo']
                type: list
                elements: str
                description: Select one or more SSH MAC algorithms.
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
            url_filter_count:
                aliases: ['url-filter-count']
                type: int
                description: URL filter daemon count.
            wifi_certificate:
                aliases: ['wifi-certificate']
                type: raw
                description: (list) Certificate to use for WiFi authentication.
            radius_port:
                aliases: ['radius-port']
                type: int
                description: RADIUS service port number.
            sys_perf_log_interval:
                aliases: ['sys-perf-log-interval']
                type: int
                description: Time in minutes between updates of performance statistics logging.
            gui_fortigate_cloud_sandbox:
                aliases: ['gui-fortigate-cloud-sandbox']
                type: str
                description: Enable/disable displaying FortiGate Cloud Sandbox on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            auth_cert:
                aliases: ['auth-cert']
                type: raw
                description: (list) Server certificate that the FortiGate uses for HTTPS firewall authentication connections.
            fortiextender:
                type: str
                description: Enable/disable FortiExtender.
                choices:
                    - 'disable'
                    - 'enable'
            admin_reset_button:
                aliases: ['admin-reset-button']
                type: str
                description: Press the reset button can reset to factory default.
                choices:
                    - 'disable'
                    - 'enable'
            av_failopen:
                aliases: ['av-failopen']
                type: str
                description: Set the action to take if the FortiGate is running low on memory or the proxy connection limit has been reached.
                choices:
                    - 'off'
                    - 'pass'
                    - 'one-shot'
                    - 'idledrop'
            user_device_store_max_users:
                aliases: ['user-device-store-max-users']
                type: int
                description: Maximum number of users allowed in user device store.
            auth_session_limit:
                aliases: ['auth-session-limit']
                type: str
                description: Action to take when the number of allowed user authenticated sessions is reached.
                choices:
                    - 'block-new'
                    - 'logout-inactive'
            ipv6_allow_local_in_slient_drop:
                aliases: ['ipv6-allow-local-in-slient-drop']
                type: str
                description: Enable/disable silent drop of IPv6 local-in traffic.
                choices:
                    - 'disable'
                    - 'enable'
            quic_congestion_control_algo:
                aliases: ['quic-congestion-control-algo']
                type: str
                description: QUIC congestion control algorithm
                choices:
                    - 'cubic'
                    - 'bbr'
                    - 'bbr2'
                    - 'reno'
            auth_ike_saml_port:
                aliases: ['auth-ike-saml-port']
                type: int
                description: User IKE SAML authentication port
            wad_restart_end_time:
                aliases: ['wad-restart-end-time']
                type: str
                description: WAD workers daily restart end time
            http_request_limit:
                aliases: ['http-request-limit']
                type: int
                description: HTTP request body size limit.
            irq_time_accounting:
                aliases: ['irq-time-accounting']
                type: str
                description: Configure CPU IRQ time accounting mode.
                choices:
                    - 'auto'
                    - 'force'
            remoteauthtimeout:
                type: int
                description: Number of seconds that the FortiGate waits for responses from remote RADIUS, LDAP, or TACACS+ authentication servers.
            admin_https_ssl_banned_ciphers:
                aliases: ['admin-https-ssl-banned-ciphers']
                type: list
                elements: str
                description: Select one or more cipher technologies that cannot be used in GUI HTTPS negotiations.
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
            allow_traffic_redirect:
                aliases: ['allow-traffic-redirect']
                type: str
                description: Disable to prevent traffic with same local ingress and egress interface from being forwarded without policy check.
                choices:
                    - 'disable'
                    - 'enable'
            legacy_poe_device_support:
                aliases: ['legacy-poe-device-support']
                type: str
                description: Enable/disable legacy POE device support.
                choices:
                    - 'disable'
                    - 'enable'
            wad_restart_mode:
                aliases: ['wad-restart-mode']
                type: str
                description: WAD worker restart mode
                choices:
                    - 'none'
                    - 'time'
                    - 'memory'
            fds_statistics_period:
                aliases: ['fds-statistics-period']
                type: int
                description: FortiGuard statistics collection period in minutes.
            admin_telnet:
                aliases: ['admin-telnet']
                type: str
                description: Enable/disable TELNET service.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6_accept_dad:
                aliases: ['ipv6-accept-dad']
                type: int
                description: Enable/disable acceptance of IPv6 Duplicate Address Detection
            tcp_timewait_timer:
                aliases: ['tcp-timewait-timer']
                type: int
                description: Length of the TCP TIME-WAIT state in seconds
            admin_console_timeout:
                aliases: ['admin-console-timeout']
                type: int
                description: Console login timeout that overrides the admin timeout value
            default_service_source_port:
                aliases: ['default-service-source-port']
                type: str
                description: Default service source port range
            quic_max_datagram_size:
                aliases: ['quic-max-datagram-size']
                type: int
                description: Maximum transmit datagram size
            refresh:
                type: int
                description: Statistics refresh interval second
            extender_controller_reserved_network:
                aliases: ['extender-controller-reserved-network']
                type: raw
                description: (list) Configure reserved network subnet for managed LAN extension FortiExtender units.
            url_filter_affinity:
                aliases: ['url-filter-affinity']
                type: str
                description: URL filter CPU affinity.
            policy_auth_concurrent:
                aliases: ['policy-auth-concurrent']
                type: int
                description: Number of concurrent firewall use logins from the same user
            ipsec_hmac_offload:
                aliases: ['ipsec-hmac-offload']
                type: str
                description: Enable/disable offloading
                choices:
                    - 'disable'
                    - 'enable'
            traffic_priority_level:
                aliases: ['traffic-priority-level']
                type: str
                description: Default system-wide level of priority for traffic prioritization.
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            ipsec_qat_offload:
                aliases: ['ipsec-qat-offload']
                type: str
                description: Enable/disable QAT offloading
                choices:
                    - 'disable'
                    - 'enable'
            ssd_trim_min:
                aliases: ['ssd-trim-min']
                type: int
                description: Minute of the hour on which to run SSD Trim
            gui_date_time_source:
                aliases: ['gui-date-time-source']
                type: str
                description: Source from which the FortiGate GUI uses to display date and time entries.
                choices:
                    - 'system'
                    - 'browser'
            log_ssl_connection:
                aliases: ['log-ssl-connection']
                type: str
                description: Enable/disable logging of SSL connection events.
                choices:
                    - 'disable'
                    - 'enable'
            ndp_max_entry:
                aliases: ['ndp-max-entry']
                type: int
                description: Maximum number of NDP table entries
            vdom_mode:
                aliases: ['vdom-mode']
                type: str
                description: Enable/disable support for multiple virtual domains
                choices:
                    - 'no-vdom'
                    - 'multi-vdom'
                    - 'split-vdom'
            internet_service_download_list:
                aliases: ['internet-service-download-list']
                type: raw
                description: (list) Configure which on-demand Internet Service IDs are to be downloaded.
            fortitoken_cloud_sync_interval:
                aliases: ['fortitoken-cloud-sync-interval']
                type: int
                description: Interval in which to clean up remote users in FortiToken Cloud
            ssd_trim_weekday:
                aliases: ['ssd-trim-weekday']
                type: str
                description: Day of week to run SSD Trim.
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            two_factor_fac_expiry:
                aliases: ['two-factor-fac-expiry']
                type: int
                description: FortiAuthenticator token authentication session timeout
            gui_rest_api_cache:
                aliases: ['gui-rest-api-cache']
                type: str
                description: Enable/disable REST API result caching on FortiGate.
                choices:
                    - 'disable'
                    - 'enable'
            admin_forticloud_sso_default_profile:
                aliases: ['admin-forticloud-sso-default-profile']
                type: raw
                description: (list) Override access profile.
            proxy_auth_lifetime:
                aliases: ['proxy-auth-lifetime']
                type: str
                description: Enable/disable authenticated users lifetime control.
                choices:
                    - 'disable'
                    - 'enable'
            device_idle_timeout:
                aliases: ['device-idle-timeout']
                type: int
                description: Time in seconds that a device must be idle to automatically log the device user out.
            login_timestamp:
                aliases: ['login-timestamp']
                type: str
                description: Enable/disable login time recording.
                choices:
                    - 'disable'
                    - 'enable'
            speedtest_server:
                aliases: ['speedtest-server']
                type: str
                description: Enable/disable speed test server.
                choices:
                    - 'disable'
                    - 'enable'
            edit_vdom_prompt:
                aliases: ['edit-vdom-prompt']
                type: str
                description: Enable/disable edit new VDOM prompt.
                choices:
                    - 'disable'
                    - 'enable'
            gui_cdn_domain_override:
                aliases: ['gui-cdn-domain-override']
                type: str
                description: Domain of CDN server.
            admin_ssh_grace_time:
                aliases: ['admin-ssh-grace-time']
                type: int
                description: Maximum time in seconds permitted between making an SSH connection to the FortiGate unit and authenticating
            sslvpn_ems_sn_check:
                aliases: ['sslvpn-ems-sn-check']
                type: str
                description: Enable/disable verification of EMS serial number in SSL-VPN connection.
                choices:
                    - 'disable'
                    - 'enable'
            user_server_cert:
                aliases: ['user-server-cert']
                type: raw
                description: (list) Certificate to use for https user authentication.
            gui_allow_default_hostname:
                aliases: ['gui-allow-default-hostname']
                type: str
                description: Enable/disable the factory default hostname warning on the GUI setup wizard.
                choices:
                    - 'disable'
                    - 'enable'
            proxy_re_authentication_mode:
                aliases: ['proxy-re-authentication-mode']
                type: str
                description: Control if users must re-authenticate after a session is closed, traffic has been idle, or from the point at which the use...
                choices:
                    - 'session'
                    - 'traffic'
                    - 'absolute'
            ipsec_soft_dec_async:
                aliases: ['ipsec-soft-dec-async']
                type: str
                description: Enable/disable software decryption asynchronization
                choices:
                    - 'disable'
                    - 'enable'
            admin_maintainer:
                aliases: ['admin-maintainer']
                type: str
                description: Enable/disable maintainer administrator login.
                choices:
                    - 'disable'
                    - 'enable'
            dst:
                type: str
                description: Enable/disable daylight saving time.
                choices:
                    - 'disable'
                    - 'enable'
            fec_port:
                aliases: ['fec-port']
                type: int
                description: Local UDP port for Forward Error Correction
            ssh_kex_sha1:
                aliases: ['ssh-kex-sha1']
                type: str
                description: Enable/disable SHA1 key exchange for SSH access.
                choices:
                    - 'disable'
                    - 'enable'
            ssh_mac_weak:
                aliases: ['ssh-mac-weak']
                type: str
                description: Enable/disable HMAC-SHA1 and UMAC-64-ETM for SSH access.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_cipher_hardware_acceleration:
                aliases: ['sslvpn-cipher-hardware-acceleration']
                type: str
                description: Enable/disable SSL-VPN hardware acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            sys_file_check_interval:
                aliases: ['sys-file-check-interval']
                type: int
                description: Set scheduled system file checking interval in minutes
            ssh_hmac_md5:
                aliases: ['ssh-hmac-md5']
                type: str
                description: Enable/disable HMAC-MD5 for SSH access.
                choices:
                    - 'disable'
                    - 'enable'
            ssh_cbc_cipher:
                aliases: ['ssh-cbc-cipher']
                type: str
                description: Enable/disable CBC cipher for SSH access.
                choices:
                    - 'disable'
                    - 'enable'
            gui_fortiguard_resource_fetch:
                aliases: ['gui-fortiguard-resource-fetch']
                type: str
                description: Enable/disable retrieving static GUI resources from FortiGuard.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_kxp_hardware_acceleration:
                aliases: ['sslvpn-kxp-hardware-acceleration']
                type: str
                description: Enable/disable SSL-VPN KXP hardware acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_plugin_version_check:
                aliases: ['sslvpn-plugin-version-check']
                type: str
                description: Enable/disable checking browsers plugin version by SSL-VPN.
                choices:
                    - 'disable'
                    - 'enable'
            fortiipam_integration:
                aliases: ['fortiipam-integration']
                type: str
                description: Enable/disable integration with the FortiIPAM cloud service.
                choices:
                    - 'disable'
                    - 'enable'
            gui_firmware_upgrade_setup_warning:
                aliases: ['gui-firmware-upgrade-setup-warning']
                type: str
                description: Gui firmware upgrade setup warning.
                choices:
                    - 'disable'
                    - 'enable'
            log_uuid_policy:
                aliases: ['log-uuid-policy']
                type: str
                description: Enable/disable insertion of policy UUIDs to traffic logs.
                choices:
                    - 'disable'
                    - 'enable'
            per_user_bwl:
                aliases: ['per-user-bwl']
                type: str
                description: Enable/disable per-user black/white list filter.
                choices:
                    - 'disable'
                    - 'enable'
            gui_fortisandbox_cloud:
                aliases: ['gui-fortisandbox-cloud']
                type: str
                description: Enable/disable displaying FortiSandbox Cloud on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            fortitoken_cloud_service:
                aliases: ['fortitoken-cloud-service']
                type: str
                description: Fortitoken cloud service.
                choices:
                    - 'disable'
                    - 'enable'
            hw_switch_ether_filter:
                aliases: ['hw-switch-ether-filter']
                type: str
                description: Enable/disable hardware filter for certain Ethernet packet types.
                choices:
                    - 'disable'
                    - 'enable'
            virtual_server_count:
                aliases: ['virtual-server-count']
                type: int
                description: Maximum number of virtual server processes to create.
            endpoint_control_fds_access:
                aliases: ['endpoint-control-fds-access']
                type: str
                description: Endpoint control fds access.
                choices:
                    - 'disable'
                    - 'enable'
            proxy_cipher_hardware_acceleration:
                aliases: ['proxy-cipher-hardware-acceleration']
                type: str
                description: Enable/disable using content processor
                choices:
                    - 'disable'
                    - 'enable'
            proxy_kxp_hardware_acceleration:
                aliases: ['proxy-kxp-hardware-acceleration']
                type: str
                description: Enable/disable using the content processor to accelerate KXP traffic.
                choices:
                    - 'disable'
                    - 'enable'
            virtual_server_hardware_acceleration:
                aliases: ['virtual-server-hardware-acceleration']
                type: str
                description: Enable/disable virtual server hardware acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            user_history_password_threshold:
                aliases: ['user-history-password-threshold']
                type: int
                description: Maximum number of previous passwords saved per admin/user
            delay_tcp_npu_session:
                aliases: ['delay-tcp-npu-session']
                type: str
                description: Enable TCP NPU session delay to guarantee packet order of 3-way handshake.
                choices:
                    - 'disable'
                    - 'enable'
            auth_session_auto_backup_interval:
                aliases: ['auth-session-auto-backup-interval']
                type: str
                description: Configure automatic authentication session backup interval in minutes
                choices:
                    - '1min'
                    - '5min'
                    - '15min'
                    - '30min'
                    - '1hr'
            ip_conflict_detection:
                aliases: ['ip-conflict-detection']
                type: str
                description: Enable/disable logging of IPv4 address conflict detection.
                choices:
                    - 'disable'
                    - 'enable'
            gtpu_dynamic_source_port:
                aliases: ['gtpu-dynamic-source-port']
                type: str
                description: Enable/disable GTP-U dynamic source port support.
                choices:
                    - 'disable'
                    - 'enable'
            ip_fragment_timeout:
                aliases: ['ip-fragment-timeout']
                type: int
                description: Timeout value in seconds for any fragment not being reassembled
            ipv6_fragment_timeout:
                aliases: ['ipv6-fragment-timeout']
                type: int
                description: Timeout value in seconds for any IPv6 fragment not being reassembled
            scim_server_cert:
                aliases: ['scim-server-cert']
                type: raw
                description: (list) Server certificate that the FortiGate uses for SCIM connections.
            scim_http_port:
                aliases: ['scim-http-port']
                type: int
                description: SCIM http port
            auth_session_auto_backup:
                aliases: ['auth-session-auto-backup']
                type: str
                description: Enable/disable automatic and periodic backup of authentication sessions
                choices:
                    - 'disable'
                    - 'enable'
            scim_https_port:
                aliases: ['scim-https-port']
                type: int
                description: SCIM port
            httpd_max_worker_count:
                aliases: ['httpd-max-worker-count']
                type: int
                description: Maximum number of simultaneous HTTP requests that will be served.
            rest_api_key_url_query:
                aliases: ['rest-api-key-url-query']
                type: str
                description: Enable/disable support for passing REST API keys through URL query parameters.
                choices:
                    - 'disable'
                    - 'enable'
            single_vdom_npuvlink:
                aliases: ['single-vdom-npuvlink']
                type: str
                description: Enable/disable NPU VDOMs links for single VDOM.
                choices:
                    - 'disable'
                    - 'enable'
            slbc_fragment_mem_thresholds:
                aliases: ['slbc-fragment-mem-thresholds']
                type: int
                description: Maximum memory
            upgrade_report:
                aliases: ['upgrade-report']
                type: str
                description: Enable/disable the generation of an upgrade report when upgrading the firmware.
                choices:
                    - 'disable'
                    - 'enable'
            application_bandwidth_tracking:
                aliases: ['application-bandwidth-tracking']
                type: str
                description: Enable/disable application bandwidth tracking.
                choices:
                    - 'disable'
                    - 'enable'
            fortitoken_cloud_region:
                aliases: ['fortitoken-cloud-region']
                type: str
                description: Region domain of FortiToken Cloud
            black_box_interval:
                aliases: ['black-box-interval']
                type: int
                description: Black box recording interval
            black_box:
                aliases: ['black-box']
                type: str
                description: Enable/disable the black box.
                choices:
                    - 'disable'
                    - 'enable'
            tls_session_cache:
                aliases: ['tls-session-cache']
                type: str
                description: Enable/disable TLS session cache.
                choices:
                    - 'disable'
                    - 'enable'
            wad_p2s_max_body_size:
                aliases: ['wad-p2s-max-body-size']
                type: int
                description: Maximum size of the body of the local out HTTP request
            telemetry_controller:
                aliases: ['telemetry-controller']
                type: str
                description: Enable/disable FortiTelemetry controller to manage FortiTelemetry agents.
                choices:
                    - 'disable'
                    - 'enable'
            telemetry_data_port:
                aliases: ['telemetry-data-port']
                type: int
                description: FortiTelemetry data channel port
            user_device_store_max_device_mem:
                aliases: ['user-device-store-max-device-mem']
                type: int
                description: Maximum percentage of total system memory allowed to be used for devices in the user device store.
            sslvpn_affinity:
                aliases: ['sslvpn-affinity']
                type: str
                description: Agentless VPN CPU affinity.
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
    - name: Configure global attributes.
      fortinet.fortimanager.fmgr_devprof_system_global:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        devprof: <your own value>
        devprof_system_global:
          # admin_https_redirect: <value in [disable, enable]>
          # admin_port: <integer>
          # admin_scp: <value in [disable, enable]>
          # admin_sport: <integer>
          # admin_ssh_port: <integer>
          # admin_ssh_v1: <value in [disable, enable]>
          # admin_telnet_port: <integer>
          # admintimeout: <integer>
          # gui_ipv6: <value in [disable, enable]>
          # gui_lines_per_page: <integer>
          # gui_theme: <value in [blue, green, melongene, ...]>
          # language: <value in [english, simch, japanese, ...]>
          # switch_controller: <value in [disable, enable]>
          # gui_device_latitude: <string>
          # gui_device_longitude: <string>
          # hostname: <string>
          # timezone:
          #   - "00"
          #   - "01"
          #   - "02"
          #   - "03"
          #   - "04"
          #   - "05"
          #   - "06"
          #   - "07"
          #   - "08"
          #   - "09"
          #   - "10"
          #   - "11"
          #   - "12"
          #   - "13"
          #   - "14"
          #   - "15"
          #   - "16"
          #   - "17"
          #   - "18"
          #   - "19"
          #   - "20"
          #   - "21"
          #   - "22"
          #   - "23"
          #   - "24"
          #   - "25"
          #   - "26"
          #   - "27"
          #   - "28"
          #   - "29"
          #   - "30"
          #   - "31"
          #   - "32"
          #   - "33"
          #   - "34"
          #   - "35"
          #   - "36"
          #   - "37"
          #   - "38"
          #   - "39"
          #   - "40"
          #   - "41"
          #   - "42"
          #   - "43"
          #   - "44"
          #   - "45"
          #   - "46"
          #   - "47"
          #   - "48"
          #   - "49"
          #   - "50"
          #   - "51"
          #   - "52"
          #   - "53"
          #   - "54"
          #   - "55"
          #   - "56"
          #   - "57"
          #   - "58"
          #   - "59"
          #   - "60"
          #   - "61"
          #   - "62"
          #   - "63"
          #   - "64"
          #   - "65"
          #   - "66"
          #   - "67"
          #   - "68"
          #   - "69"
          #   - "70"
          #   - "71"
          #   - "72"
          #   - "73"
          #   - "74"
          #   - "75"
          #   - "76"
          #   - "77"
          #   - "78"
          #   - "79"
          #   - "80"
          #   - "81"
          #   - "82"
          #   - "83"
          #   - "84"
          #   - "85"
          #   - "86"
          #   - "87"
          # check_reset_range: <value in [disable, strict]>
          # pmtu_discovery: <value in [disable, enable]>
          # gui_allow_incompatible_fabric_fgt: <value in [disable, enable]>
          # admin_restrict_local: <value in [disable, enable, all, ...]>
          # gui_workflow_management: <value in [disable, enable]>
          # send_pmtu_icmp: <value in [disable, enable]>
          # tcp_halfclose_timer: <integer>
          # admin_server_cert: <list or string>
          # dnsproxy_worker_count: <integer>
          # show_backplane_intf: <value in [disable, enable]>
          # gui_custom_language: <value in [disable, enable]>
          # ldapconntimeout: <integer>
          # auth_https_port: <integer>
          # revision_backup_on_logout: <value in [disable, enable]>
          # arp_max_entry: <integer>
          # long_vdom_name: <value in [disable, enable]>
          # pre_login_banner: <value in [disable, enable]>
          # qsfpdd_split8_port: <list or string>
          # max_route_cache_size: <integer>
          # fortitoken_cloud_push_status: <value in [disable, enable]>
          # ssh_hostkey_override: <value in [disable, enable]>
          # proxy_hardware_acceleration: <value in [disable, enable]>
          # switch_controller_reserved_network: <list or string>
          # ssd_trim_date: <integer>
          # wad_worker_count: <integer>
          # ssh_hostkey: <string>
          # wireless_controller_port: <integer>
          # fgd_alert_subscription:
          #   - "advisory"
          #   - "latest-threat"
          #   - "latest-virus"
          #   - "latest-attack"
          #   - "new-antivirus-db"
          #   - "new-attack-db"
          # forticontroller_proxy_port: <integer>
          # dh_params: <value in [1024, 1536, 2048, ...]>
          # memory_use_threshold_green: <integer>
          # proxy_cert_use_mgmt_vdom: <value in [disable, enable]>
          # proxy_auth_lifetime_timeout: <integer>
          # gui_auto_upgrade_setup_warning: <value in [disable, enable]>
          # gui_cdn_usage: <value in [disable, enable]>
          # two_factor_email_expiry: <integer>
          # udp_idle_timer: <integer>
          # interface_subnet_usage: <value in [disable, enable]>
          # forticontroller_proxy: <value in [disable, enable]>
          # ssh_enc_algo:
          #   - "chacha20-poly1305@openssh.com"
          #   - "aes128-ctr"
          #   - "aes192-ctr"
          #   - "aes256-ctr"
          #   - "arcfour256"
          #   - "arcfour128"
          #   - "aes128-cbc"
          #   - "3des-cbc"
          #   - "blowfish-cbc"
          #   - "cast128-cbc"
          #   - "aes192-cbc"
          #   - "aes256-cbc"
          #   - "arcfour"
          #   - "rijndael-cbc@lysator.liu.se"
          #   - "aes128-gcm@openssh.com"
          #   - "aes256-gcm@openssh.com"
          # block_session_timer: <integer>
          # quic_pmtud: <value in [disable, enable]>
          # admin_https_ssl_ciphersuites:
          #   - "TLS-AES-128-GCM-SHA256"
          #   - "TLS-AES-256-GCM-SHA384"
          #   - "TLS-CHACHA20-POLY1305-SHA256"
          #   - "TLS-AES-128-CCM-SHA256"
          #   - "TLS-AES-128-CCM-8-SHA256"
          # security_rating_result_submission: <value in [disable, enable]>
          # user_device_store_max_unified_mem: <integer>
          # management_port: <integer>
          # fortigslb_integration: <value in [disable, enable]>
          # admin_https_ssl_versions:
          #   - "tlsv1-0"
          #   - "tlsv1-1"
          #   - "tlsv1-2"
          #   - "sslv3"
          #   - "tlsv1-3"
          # cert_chain_max: <integer>
          # qsfp28_40g_port: <list or string>
          # strong_crypto: <value in [disable, enable]>
          # multi_factor_authentication: <value in [optional, mandatory]>
          # fds_statistics: <value in [disable, enable]>
          # gui_display_hostname: <value in [disable, enable]>
          # two_factor_ftk_expiry: <integer>
          # wad_source_affinity: <value in [disable, enable]>
          # ssl_static_key_ciphers: <value in [disable, enable]>
          # daily_restart: <value in [disable, enable]>
          # snat_route_change: <value in [disable, enable]>
          # tcp_rst_timer: <integer>
          # anti_replay: <value in [disable, loose, strict]>
          # ssl_min_proto_version: <value in [TLSv1, TLSv1-1, TLSv1-2, ...]>
          # speedtestd_server_port: <integer>
          # cpu_use_threshold: <integer>
          # admin_host: <string>
          # csr_ca_attribute: <value in [disable, enable]>
          # fortiservice_port: <integer>
          # ssd_trim_hour: <integer>
          # purdue_level: <value in [1, 2, 3, ...]>
          # management_vdom: <list or string>
          # quic_ack_thresold: <integer>
          # qsfpdd_100g_port: <list or string>
          # ips_affinity: <string>
          # vip_arp_range: <value in [restricted, unlimited]>
          # internet_service_database: <value in [mini, standard, full, ...]>
          # revision_image_auto_backup: <value in [disable, enable]>
          # sflowd_max_children_num: <integer>
          # admin_https_pki_required: <value in [disable, enable]>
          # special_file_23_support: <value in [disable, enable]>
          # npu_neighbor_update: <value in [disable, enable]>
          # log_single_cpu_high: <value in [disable, enable]>
          # management_ip: <string>
          # proxy_resource_mode: <value in [disable, enable]>
          # admin_ble_button: <value in [disable, enable]>
          # gui_firmware_upgrade_warning: <value in [disable, enable]>
          # dp_tcp_normal_timer: <integer>
          # ipv6_allow_traffic_redirect: <value in [disable, enable]>
          # cli_audit_log: <value in [disable, enable]>
          # memory_use_threshold_extreme: <integer>
          # ha_affinity: <string>
          # restart_time: <string>
          # speedtestd_ctrl_port: <integer>
          # gui_wireless_opensecurity: <value in [disable, enable]>
          # memory_use_threshold_red: <integer>
          # dp_fragment_timer: <integer>
          # wad_restart_start_time: <string>
          # proxy_re_authentication_time: <integer>
          # gui_app_detection_sdwan: <value in [disable, enable]>
          # scanunit_count: <integer>
          # tftp: <value in [disable, enable]>
          # xstools_update_frequency: <integer>
          # clt_cert_req: <value in [disable, enable]>
          # fortiextender_vlan_mode: <value in [disable, enable]>
          # auth_http_port: <integer>
          # per_user_bal: <value in [disable, enable]>
          # gui_date_format: <value in [yyyy/MM/dd, dd/MM/yyyy, MM/dd/yyyy, ...]>
          # log_uuid_address: <value in [disable, enable]>
          # cloud_communication: <value in [disable, enable]>
          # lldp_reception: <value in [disable, enable]>
          # two_factor_ftm_expiry: <integer>
          # quic_udp_payload_size_shaping_per_cid: <value in [disable, enable]>
          # autorun_log_fsck: <value in [disable, enable]>
          # vpn_ems_sn_check: <value in [disable, enable]>
          # admin_ssh_password: <value in [disable, enable]>
          # airplane_mode: <value in [disable, enable]>
          # batch_cmdb: <value in [disable, enable]>
          # ip_src_port_range: <list or string>
          # strict_dirty_session_check: <value in [disable, enable]>
          # user_device_store_max_devices: <integer>
          # dp_udp_idle_timer: <integer>
          # internal_switch_speed:
          #   - "auto"
          #   - "10full"
          #   - "10half"
          #   - "100full"
          #   - "100half"
          #   - "1000full"
          #   - "1000auto"
          # forticonverter_config_upload: <value in [disable, once]>
          # ipsec_round_robin: <value in [disable, enable]>
          # wad_affinity: <string>
          # wifi_ca_certificate: <list or string>
          # wimax_4g_usb: <value in [disable, enable]>
          # miglog_affinity: <string>
          # faz_disk_buffer_size: <integer>
          # ssh_kex_algo:
          #   - "diffie-hellman-group1-sha1"
          #   - "diffie-hellman-group14-sha1"
          #   - "diffie-hellman-group-exchange-sha1"
          #   - "diffie-hellman-group-exchange-sha256"
          #   - "curve25519-sha256@libssh.org"
          #   - "ecdh-sha2-nistp256"
          #   - "ecdh-sha2-nistp384"
          #   - "ecdh-sha2-nistp521"
          #   - "diffie-hellman-group14-sha256"
          #   - "diffie-hellman-group16-sha512"
          #   - "diffie-hellman-group18-sha512"
          # auto_auth_extension_device: <value in [disable, enable]>
          # forticarrier_bypass: <value in [disable, enable]>
          # reset_sessionless_tcp: <value in [disable, enable]>
          # early_tcp_npu_session: <value in [disable, enable]>
          # http_unauthenticated_request_limit: <integer>
          # gui_local_out: <value in [disable, enable]>
          # tcp_option: <value in [disable, enable]>
          # proxy_auth_timeout: <integer>
          # fortiextender_discovery_lockdown: <value in [disable, enable]>
          # lldp_transmission: <value in [disable, enable]>
          # split_port: <list or string>
          # gui_certificates: <value in [disable, enable]>
          # cfg_save: <value in [automatic, manual, revert]>
          # auth_keepalive: <value in [disable, enable]>
          # split_port_mode:
          #   - interface: <string>
          #     split_mode: <value in [disable, 4x10G, 4x25G, ...]>
          # admin_forticloud_sso_login: <value in [disable, enable]>
          # post_login_banner: <value in [disable, enable]>
          # br_fdb_max_entry: <integer>
          # ip_fragment_mem_thresholds: <integer>
          # fortiextender_provision_on_authorization: <value in [disable, enable]>
          # reboot_upon_config_restore: <value in [disable, enable]>
          # syslog_affinity: <string>
          # fortiextender_data_port: <integer>
          # quic_tls_handshake_timeout: <integer>
          # forticonverter_integration: <value in [disable, enable]>
          # proxy_keep_alive_mode: <value in [session, traffic, re-authentication]>
          # cmdbsvr_affinity: <string>
          # wad_memory_change_granularity: <integer>
          # dhcp_lease_backup_interval: <integer>
          # check_protocol_header: <value in [loose, strict]>
          # av_failopen_session: <value in [disable, enable]>
          # ipsec_ha_seqjump_rate: <integer>
          # admin_hsts_max_age: <integer>
          # igmp_state_limit: <integer>
          # admin_login_max: <integer>
          # ipv6_allow_multicast_probe: <value in [disable, enable]>
          # virtual_switch_vlan: <value in [disable, enable]>
          # admin_lockout_threshold: <integer>
          # dp_pinhole_timer: <integer>
          # wireless_controller: <value in [disable, enable]>
          # bfd_affinity: <string>
          # ssd_trim_freq: <value in [daily, weekly, monthly, ...]>
          # two_factor_sms_expiry: <integer>
          # traffic_priority: <value in [tos, dscp]>
          # proxy_and_explicit_proxy: <value in [disable, enable]>
          # sslvpn_web_mode: <value in [disable, enable]>
          # ssh_hostkey_password: <list or string>
          # wad_csvc_db_count: <integer>
          # ipv6_allow_anycast_probe: <value in [disable, enable]>
          # honor_df: <value in [disable, enable]>
          # hyper_scale_vdom_num: <integer>
          # wad_csvc_cs_count: <integer>
          # internal_switch_mode: <value in [switch, interface, hub]>
          # cfg_revert_timeout: <integer>
          # admin_concurrent: <value in [disable, enable]>
          # ipv6_allow_local_in_silent_drop: <value in [disable, enable]>
          # tcp_halfopen_timer: <integer>
          # dp_rsync_timer: <integer>
          # management_port_use_admin_sport: <value in [disable, enable]>
          # gui_forticare_registration_setup_warning: <value in [disable, enable]>
          # gui_replacement_message_groups: <value in [disable, enable]>
          # security_rating_run_on_schedule: <value in [disable, enable]>
          # admin_lockout_duration: <integer>
          # optimize_flow_mode: <value in [disable, enable]>
          # private_data_encryption: <value in [disable, enable]>
          # wireless_mode: <value in [ac, client, wtp, ...]>
          # alias: <string>
          # ssh_hostkey_algo:
          #   - "ssh-rsa"
          #   - "ecdsa-sha2-nistp521"
          #   - "rsa-sha2-256"
          #   - "rsa-sha2-512"
          #   - "ssh-ed25519"
          #   - "ecdsa-sha2-nistp384"
          #   - "ecdsa-sha2-nistp256"
          # fortitoken_cloud: <value in [disable, enable]>
          # av_affinity: <string>
          # proxy_worker_count: <integer>
          # ipsec_asic_offload: <value in [disable, enable]>
          # miglogd_children: <integer>
          # sslvpn_max_worker_count: <integer>
          # ssh_mac_algo:
          #   - "hmac-md5"
          #   - "hmac-md5-etm@openssh.com"
          #   - "hmac-md5-96"
          #   - "hmac-md5-96-etm@openssh.com"
          #   - "hmac-sha1"
          #   - "hmac-sha1-etm@openssh.com"
          #   - "hmac-sha2-256"
          #   - "hmac-sha2-256-etm@openssh.com"
          #   - "hmac-sha2-512"
          #   - "hmac-sha2-512-etm@openssh.com"
          #   - "hmac-ripemd160"
          #   - "hmac-ripemd160@openssh.com"
          #   - "hmac-ripemd160-etm@openssh.com"
          #   - "umac-64@openssh.com"
          #   - "umac-128@openssh.com"
          #   - "umac-64-etm@openssh.com"
          #   - "umac-128-etm@openssh.com"
          # url_filter_count: <integer>
          # wifi_certificate: <list or string>
          # radius_port: <integer>
          # sys_perf_log_interval: <integer>
          # gui_fortigate_cloud_sandbox: <value in [disable, enable]>
          # auth_cert: <list or string>
          # fortiextender: <value in [disable, enable]>
          # admin_reset_button: <value in [disable, enable]>
          # av_failopen: <value in [off, pass, one-shot, ...]>
          # user_device_store_max_users: <integer>
          # auth_session_limit: <value in [block-new, logout-inactive]>
          # ipv6_allow_local_in_slient_drop: <value in [disable, enable]>
          # quic_congestion_control_algo: <value in [cubic, bbr, bbr2, ...]>
          # auth_ike_saml_port: <integer>
          # wad_restart_end_time: <string>
          # http_request_limit: <integer>
          # irq_time_accounting: <value in [auto, force]>
          # remoteauthtimeout: <integer>
          # admin_https_ssl_banned_ciphers:
          #   - "RSA"
          #   - "DHE"
          #   - "ECDHE"
          #   - "DSS"
          #   - "ECDSA"
          #   - "AES"
          #   - "AESGCM"
          #   - "CAMELLIA"
          #   - "3DES"
          #   - "SHA1"
          #   - "SHA256"
          #   - "SHA384"
          #   - "STATIC"
          #   - "CHACHA20"
          #   - "ARIA"
          #   - "AESCCM"
          # allow_traffic_redirect: <value in [disable, enable]>
          # legacy_poe_device_support: <value in [disable, enable]>
          # wad_restart_mode: <value in [none, time, memory]>
          # fds_statistics_period: <integer>
          # admin_telnet: <value in [disable, enable]>
          # ipv6_accept_dad: <integer>
          # tcp_timewait_timer: <integer>
          # admin_console_timeout: <integer>
          # default_service_source_port: <string>
          # quic_max_datagram_size: <integer>
          # refresh: <integer>
          # extender_controller_reserved_network: <list or string>
          # url_filter_affinity: <string>
          # policy_auth_concurrent: <integer>
          # ipsec_hmac_offload: <value in [disable, enable]>
          # traffic_priority_level: <value in [high, medium, low]>
          # ipsec_qat_offload: <value in [disable, enable]>
          # ssd_trim_min: <integer>
          # gui_date_time_source: <value in [system, browser]>
          # log_ssl_connection: <value in [disable, enable]>
          # ndp_max_entry: <integer>
          # vdom_mode: <value in [no-vdom, multi-vdom, split-vdom]>
          # internet_service_download_list: <list or string>
          # fortitoken_cloud_sync_interval: <integer>
          # ssd_trim_weekday: <value in [sunday, monday, tuesday, ...]>
          # two_factor_fac_expiry: <integer>
          # gui_rest_api_cache: <value in [disable, enable]>
          # admin_forticloud_sso_default_profile: <list or string>
          # proxy_auth_lifetime: <value in [disable, enable]>
          # device_idle_timeout: <integer>
          # login_timestamp: <value in [disable, enable]>
          # speedtest_server: <value in [disable, enable]>
          # edit_vdom_prompt: <value in [disable, enable]>
          # gui_cdn_domain_override: <string>
          # admin_ssh_grace_time: <integer>
          # sslvpn_ems_sn_check: <value in [disable, enable]>
          # user_server_cert: <list or string>
          # gui_allow_default_hostname: <value in [disable, enable]>
          # proxy_re_authentication_mode: <value in [session, traffic, absolute]>
          # ipsec_soft_dec_async: <value in [disable, enable]>
          # admin_maintainer: <value in [disable, enable]>
          # dst: <value in [disable, enable]>
          # fec_port: <integer>
          # ssh_kex_sha1: <value in [disable, enable]>
          # ssh_mac_weak: <value in [disable, enable]>
          # sslvpn_cipher_hardware_acceleration: <value in [disable, enable]>
          # sys_file_check_interval: <integer>
          # ssh_hmac_md5: <value in [disable, enable]>
          # ssh_cbc_cipher: <value in [disable, enable]>
          # gui_fortiguard_resource_fetch: <value in [disable, enable]>
          # sslvpn_kxp_hardware_acceleration: <value in [disable, enable]>
          # sslvpn_plugin_version_check: <value in [disable, enable]>
          # fortiipam_integration: <value in [disable, enable]>
          # gui_firmware_upgrade_setup_warning: <value in [disable, enable]>
          # log_uuid_policy: <value in [disable, enable]>
          # per_user_bwl: <value in [disable, enable]>
          # gui_fortisandbox_cloud: <value in [disable, enable]>
          # fortitoken_cloud_service: <value in [disable, enable]>
          # hw_switch_ether_filter: <value in [disable, enable]>
          # virtual_server_count: <integer>
          # endpoint_control_fds_access: <value in [disable, enable]>
          # proxy_cipher_hardware_acceleration: <value in [disable, enable]>
          # proxy_kxp_hardware_acceleration: <value in [disable, enable]>
          # virtual_server_hardware_acceleration: <value in [disable, enable]>
          # user_history_password_threshold: <integer>
          # delay_tcp_npu_session: <value in [disable, enable]>
          # auth_session_auto_backup_interval: <value in [1min, 5min, 15min, ...]>
          # ip_conflict_detection: <value in [disable, enable]>
          # gtpu_dynamic_source_port: <value in [disable, enable]>
          # ip_fragment_timeout: <integer>
          # ipv6_fragment_timeout: <integer>
          # scim_server_cert: <list or string>
          # scim_http_port: <integer>
          # auth_session_auto_backup: <value in [disable, enable]>
          # scim_https_port: <integer>
          # httpd_max_worker_count: <integer>
          # rest_api_key_url_query: <value in [disable, enable]>
          # single_vdom_npuvlink: <value in [disable, enable]>
          # slbc_fragment_mem_thresholds: <integer>
          # upgrade_report: <value in [disable, enable]>
          # application_bandwidth_tracking: <value in [disable, enable]>
          # fortitoken_cloud_region: <string>
          # black_box_interval: <integer>
          # black_box: <value in [disable, enable]>
          # tls_session_cache: <value in [disable, enable]>
          # wad_p2s_max_body_size: <integer>
          # telemetry_controller: <value in [disable, enable]>
          # telemetry_data_port: <integer>
          # user_device_store_max_device_mem: <integer>
          # sslvpn_affinity: <string>
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
        '/pm/config/adom/{adom}/devprof/{devprof}/system/global'
    ]
    url_params = ['adom', 'devprof']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'devprof': {'required': True, 'type': 'str'},
        'devprof_system_global': {
            'type': 'dict',
            'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
            'options': {
                'admin-https-redirect': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'admin-port': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'admin-scp': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-sport': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'admin-ssh-port': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'admin-ssh-v1': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-telnet-port': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '7.2.4'], ['7.2.6', '7.4.1'], ['7.4.3', '']],
                    'type': 'int'
                },
                'admintimeout': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'gui-ipv6': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-lines-per-page': {'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']], 'type': 'int'},
                'gui-theme': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': [
                        'blue', 'green', 'melongene', 'red', 'mariner', 'neutrino', 'jade', 'graphite', 'dark-matter', 'onyx', 'eclipse', 'retro', 'fpx',
                        'jet-stream', 'security-fabric'
                    ],
                    'type': 'str'
                },
                'language': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']],
                    'choices': ['english', 'simch', 'japanese', 'korean', 'spanish', 'trach', 'french', 'portuguese'],
                    'type': 'str'
                },
                'switch-controller': {
                    'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'gui-device-latitude': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'gui-device-longitude': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'hostname': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'timezone': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20',
                        '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41',
                        '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62',
                        '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83',
                        '84', '85', '86', '87'
                    ],
                    'elements': 'str'
                },
                'check-reset-range': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'strict'], 'type': 'str'},
                'pmtu-discovery': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-allow-incompatible-fabric-fgt': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-restrict-local': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable', 'all', 'non-console-only'],
                    'type': 'str'
                },
                'gui-workflow-management': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'send-pmtu-icmp': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-halfclose-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'admin-server-cert': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'dnsproxy-worker-count': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'show-backplane-intf': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-custom-language': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ldapconntimeout': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'auth-https-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'revision-backup-on-logout': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'arp-max-entry': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'long-vdom-name': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pre-login-banner': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'qsfpdd-split8-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'max-route-cache-size': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'fortitoken-cloud-push-status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-hostkey-override': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-hardware-acceleration': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'switch-controller-reserved-network': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'ssd-trim-date': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'wad-worker-count': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ssh-hostkey': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'wireless-controller-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'fgd-alert-subscription': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['advisory', 'latest-threat', 'latest-virus', 'latest-attack', 'new-antivirus-db', 'new-attack-db'],
                    'elements': 'str'
                },
                'forticontroller-proxy-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'dh-params': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['1024', '1536', '2048', '3072', '4096', '6144', '8192'],
                    'type': 'str'
                },
                'memory-use-threshold-green': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'proxy-cert-use-mgmt-vdom': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-auth-lifetime-timeout': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'gui-auto-upgrade-setup-warning': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-cdn-usage': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'two-factor-email-expiry': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'udp-idle-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'interface-subnet-usage': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forticontroller-proxy': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-enc-algo': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'arcfour256', 'arcfour128', 'aes128-cbc', '3des-cbc',
                        'blowfish-cbc', 'cast128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour', 'rijndael-cbc@lysator.liu.se', 'aes128-gcm@openssh.com',
                        'aes256-gcm@openssh.com'
                    ],
                    'elements': 'str'
                },
                'block-session-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'quic-pmtud': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-https-ssl-ciphersuites': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'TLS-AES-128-GCM-SHA256', 'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256', 'TLS-AES-128-CCM-SHA256',
                        'TLS-AES-128-CCM-8-SHA256'
                    ],
                    'elements': 'str'
                },
                'security-rating-result-submission': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-device-store-max-unified-mem': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'management-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'fortigslb-integration': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-https-ssl-versions': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['tlsv1-0', 'tlsv1-1', 'tlsv1-2', 'sslv3', 'tlsv1-3'],
                    'elements': 'str'
                },
                'cert-chain-max': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'qsfp28-40g-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'strong-crypto': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multi-factor-authentication': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['optional', 'mandatory'], 'type': 'str'},
                'fds-statistics': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-display-hostname': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'two-factor-ftk-expiry': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'wad-source-affinity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-static-key-ciphers': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'daily-restart': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'snat-route-change': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-rst-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'anti-replay': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'loose', 'strict'], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                    'type': 'str'
                },
                'speedtestd-server-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'cpu-use-threshold': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'admin-host': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'csr-ca-attribute': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiservice-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ssd-trim-hour': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'purdue-level': {'v_range': [['7.4.3', '']], 'choices': ['1', '2', '3', '4', '5', '1.5', '2.5', '3.5', '5.5'], 'type': 'str'},
                'management-vdom': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'quic-ack-thresold': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'qsfpdd-100g-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'ips-affinity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'vip-arp-range': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['restricted', 'unlimited'], 'type': 'str'},
                'internet-service-database': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['mini', 'standard', 'full', 'on-demand'],
                    'type': 'str'
                },
                'revision-image-auto-backup': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sflowd-max-children-num': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'admin-https-pki-required': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'special-file-23-support': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'npu-neighbor-update': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-single-cpu-high': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'management-ip': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'proxy-resource-mode': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-ble-button': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-firmware-upgrade-warning': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-tcp-normal-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ipv6-allow-traffic-redirect': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cli-audit-log': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'memory-use-threshold-extreme': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ha-affinity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'restart-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'speedtestd-ctrl-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'gui-wireless-opensecurity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'memory-use-threshold-red': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'dp-fragment-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'wad-restart-start-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'proxy-re-authentication-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'gui-app-detection-sdwan': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'scanunit-count': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'tftp': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'xstools-update-frequency': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'clt-cert-req': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiextender-vlan-mode': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-http-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'per-user-bal': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-date-format': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['yyyy/MM/dd', 'dd/MM/yyyy', 'MM/dd/yyyy', 'yyyy-MM-dd', 'dd-MM-yyyy', 'MM-dd-yyyy'],
                    'type': 'str'
                },
                'log-uuid-address': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cloud-communication': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'lldp-reception': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'two-factor-ftm-expiry': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'quic-udp-payload-size-shaping-per-cid': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'autorun-log-fsck': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vpn-ems-sn-check': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-ssh-password': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'airplane-mode': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'batch-cmdb': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-src-port-range': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'strict-dirty-session-check': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-device-store-max-devices': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'dp-udp-idle-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'internal-switch-speed': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['auto', '10full', '10half', '100full', '100half', '1000full', '1000auto'],
                    'elements': 'str'
                },
                'forticonverter-config-upload': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'once'], 'type': 'str'},
                'ipsec-round-robin': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wad-affinity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'wifi-ca-certificate': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'wimax-4g-usb': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'miglog-affinity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'faz-disk-buffer-size': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ssh-kex-algo': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1',
                        'diffie-hellman-group-exchange-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384',
                        'ecdh-sha2-nistp521', 'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512'
                    ],
                    'elements': 'str'
                },
                'auto-auth-extension-device': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forticarrier-bypass': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'reset-sessionless-tcp': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'early-tcp-npu-session': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-unauthenticated-request-limit': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'gui-local-out': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-option': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-auth-timeout': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'fortiextender-discovery-lockdown': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'lldp-transmission': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'split-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'gui-certificates': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cfg-save': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['automatic', 'manual', 'revert'], 'type': 'str'},
                'auth-keepalive': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'split-port-mode': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'interface': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                        'split-mode': {
                            'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                            'choices': ['disable', '4x10G', '4x25G', '4x50G', '8x50G', '4x100G', '2x200G', '8x25G'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'admin-forticloud-sso-login': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'post-login-banner': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'br-fdb-max-entry': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ip-fragment-mem-thresholds': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'fortiextender-provision-on-authorization': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'reboot-upon-config-restore': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'syslog-affinity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'fortiextender-data-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'quic-tls-handshake-timeout': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'forticonverter-integration': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-keep-alive-mode': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['session', 'traffic', 're-authentication'],
                    'type': 'str'
                },
                'cmdbsvr-affinity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'wad-memory-change-granularity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'dhcp-lease-backup-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'check-protocol-header': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['loose', 'strict'], 'type': 'str'},
                'av-failopen-session': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipsec-ha-seqjump-rate': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'admin-hsts-max-age': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'igmp-state-limit': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'admin-login-max': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ipv6-allow-multicast-probe': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-switch-vlan': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-lockout-threshold': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'dp-pinhole-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'wireless-controller': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bfd-affinity': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'ssd-trim-freq': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['daily', 'weekly', 'monthly', 'hourly', 'never'],
                    'type': 'str'
                },
                'two-factor-sms-expiry': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'traffic-priority': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['tos', 'dscp'], 'type': 'str'},
                'proxy-and-explicit-proxy': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-web-mode': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-hostkey-password': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'raw'},
                'wad-csvc-db-count': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ipv6-allow-anycast-probe': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'honor-df': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hyper-scale-vdom-num': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'wad-csvc-cs-count': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'internal-switch-mode': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['switch', 'interface', 'hub'], 'type': 'str'},
                'cfg-revert-timeout': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'admin-concurrent': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6-allow-local-in-silent-drop': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-halfopen-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'dp-rsync-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'management-port-use-admin-sport': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-forticare-registration-setup-warning': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'gui-replacement-message-groups': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'security-rating-run-on-schedule': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-lockout-duration': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'optimize-flow-mode': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'private-data-encryption': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wireless-mode': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['ac', 'client', 'wtp', 'fwfap'], 'type': 'str'},
                'alias': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'ssh-hostkey-algo': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'ssh-rsa', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256'
                    ],
                    'elements': 'str'
                },
                'fortitoken-cloud': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av-affinity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'proxy-worker-count': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ipsec-asic-offload': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'miglogd-children': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'sslvpn-max-worker-count': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ssh-mac-algo': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'hmac-md5', 'hmac-md5-etm@openssh.com', 'hmac-md5-96', 'hmac-md5-96-etm@openssh.com', 'hmac-sha1', 'hmac-sha1-etm@openssh.com',
                        'hmac-sha2-256', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-512-etm@openssh.com', 'hmac-ripemd160',
                        'hmac-ripemd160@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com',
                        'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com'
                    ],
                    'elements': 'str'
                },
                'url-filter-count': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'wifi-certificate': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'radius-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'sys-perf-log-interval': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'gui-fortigate-cloud-sandbox': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-cert': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'fortiextender': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-reset-button': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av-failopen': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['off', 'pass', 'one-shot', 'idledrop'], 'type': 'str'},
                'user-device-store-max-users': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'auth-session-limit': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['block-new', 'logout-inactive'], 'type': 'str'},
                'ipv6-allow-local-in-slient-drop': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'quic-congestion-control-algo': {'v_range': [['7.4.3', '']], 'choices': ['cubic', 'bbr', 'bbr2', 'reno'], 'type': 'str'},
                'auth-ike-saml-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'wad-restart-end-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'http-request-limit': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'irq-time-accounting': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['auto', 'force'], 'type': 'str'},
                'remoteauthtimeout': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'admin-https-ssl-banned-ciphers': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'RSA', 'DHE', 'ECDHE', 'DSS', 'ECDSA', 'AES', 'AESGCM', 'CAMELLIA', '3DES', 'SHA1', 'SHA256', 'SHA384', 'STATIC', 'CHACHA20',
                        'ARIA', 'AESCCM'
                    ],
                    'elements': 'str'
                },
                'allow-traffic-redirect': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'legacy-poe-device-support': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wad-restart-mode': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['none', 'time', 'memory'], 'type': 'str'},
                'fds-statistics-period': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'admin-telnet': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6-accept-dad': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'tcp-timewait-timer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'admin-console-timeout': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'default-service-source-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'quic-max-datagram-size': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'refresh': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'extender-controller-reserved-network': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'url-filter-affinity': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'policy-auth-concurrent': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ipsec-hmac-offload': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-priority-level': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['high', 'medium', 'low'], 'type': 'str'},
                'ipsec-qat-offload': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssd-trim-min': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'gui-date-time-source': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['system', 'browser'], 'type': 'str'},
                'log-ssl-connection': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ndp-max-entry': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'vdom-mode': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['no-vdom', 'multi-vdom', 'split-vdom'], 'type': 'str'},
                'internet-service-download-list': {'v_range': [['7.4.3', '']], 'type': 'raw'},
                'fortitoken-cloud-sync-interval': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'ssd-trim-weekday': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                    'type': 'str'
                },
                'two-factor-fac-expiry': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'gui-rest-api-cache': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-forticloud-sso-default-profile': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'proxy-auth-lifetime': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'device-idle-timeout': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'login-timestamp': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'speedtest-server': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'edit-vdom-prompt': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-cdn-domain-override': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'str'},
                'admin-ssh-grace-time': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'sslvpn-ems-sn-check': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-server-cert': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'raw'},
                'gui-allow-default-hostname': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-re-authentication-mode': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']],
                    'choices': ['session', 'traffic', 'absolute'],
                    'type': 'str'
                },
                'ipsec-soft-dec-async': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-maintainer': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dst': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fec-port': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ssh-kex-sha1': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-mac-weak': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-cipher-hardware-acceleration': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sys-file-check-interval': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'type': 'int'},
                'ssh-hmac-md5': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-cbc-cipher': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-fortiguard-resource-fetch': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-kxp-hardware-acceleration': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-plugin-version-check': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiipam-integration': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-firmware-upgrade-setup-warning': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-uuid-policy': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'per-user-bwl': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gui-fortisandbox-cloud': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortitoken-cloud-service': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hw-switch-ether-filter': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-server-count': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'type': 'int'},
                'endpoint-control-fds-access': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-cipher-hardware-acceleration': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'proxy-kxp-hardware-acceleration': {'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-server-hardware-acceleration': {
                    'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'user-history-password-threshold': {'v_range': [['7.6.0', '']], 'no_log': True, 'type': 'int'},
                'delay-tcp-npu-session': {'v_range': [['7.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-session-auto-backup-interval': {'v_range': [['7.6.0', '']], 'choices': ['1min', '5min', '15min', '30min', '1hr'], 'type': 'str'},
                'ip-conflict-detection': {'v_range': [['7.4.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gtpu-dynamic-source-port': {'v_range': [['7.4.6', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-fragment-timeout': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ipv6-fragment-timeout': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'scim-server-cert': {'v_range': [['7.6.0', '']], 'type': 'raw'},
                'scim-http-port': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'auth-session-auto-backup': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'scim-https-port': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'httpd-max-worker-count': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'rest-api-key-url-query': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'single-vdom-npuvlink': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'slbc-fragment-mem-thresholds': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'upgrade-report': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'application-bandwidth-tracking': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortitoken-cloud-region': {'v_range': [['7.4.7', '7.4.7']], 'no_log': True, 'type': 'str'},
                'black-box-interval': {'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'int'},
                'black-box': {'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tls-session-cache': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wad-p2s-max-body-size': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'telemetry-controller': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'telemetry-data-port': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'user-device-store-max-device-mem': {'v_range': [['7.6.3', '']], 'type': 'int'},
                'sslvpn-affinity': {'v_range': [['7.6.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'devprof_system_global'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
