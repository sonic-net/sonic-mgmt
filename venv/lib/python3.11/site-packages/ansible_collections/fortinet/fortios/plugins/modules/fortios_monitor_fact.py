#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright 2020-2021 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}
DOCUMENTATION = """
---
module: fortios_monitor_fact
version_added: "2.0.0"
short_description: Retrieve Facts of FortiOS Monitor Objects.
description:
    - Collects monitor facts from network devices running the fortios operating system.
      This facts module will only collect those facts which user specified in playbook.
author:
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@fshen01)
notes:
    - Different selector may have different parameters, users are expected to look up them for a specific selector.
    - For some selectors, the objects are global, no params are allowed to appear.
    - Not all parameters are required for a slector.
    - This module is exclusivly for FortiOS monitor API.
    - The result of API request is stored in results.
requirements:
    - install galaxy collection fortinet.fortios >= 2.0.0.
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
        required: false
    filters:
        description:
            - A list of expressions to filter the returned results.
            - The items of the list are combined as LOGICAL AND with operator ampersand.
            - One item itself could be concatenated with a comma as LOGICAL OR.
        type: list
        elements: str
        required: false
    sorters:
        description:
            - A list of expressions to sort the returned results.
            - The items of the list are in ascending order with operator ampersand.
            - One item itself could be in decending order with a comma inside.
        type: list
        elements: str
        required: false
    formatters:
        description:
            - A list of fields to display for returned results.
        type: list
        elements: str
        required: false
    selectors:
        description:
            - A list of selectors for retrieving the fortiOS facts.
        type: list
        elements: dict
        required: false
        suboptions:
            filters:
                description:
                    - A list of expressions to filter the returned results.
                    - The items of the list are combined as LOGICAL AND with operator ampersand.
                    - One item itself could be concatenated with a comma as LOGICAL OR.
                type: list
                elements: str
                required: false
            sorters:
                description:
                    - A list of expressions to sort the returned results.
                    - The items of the list are in ascending order with operator ampersand.
                    - One item itself could be in decending order with a comma inside.
                type: list
                elements: str
                required: false
            formatters:
                description:
                    - A list of fields to display for returned results.
                type: list
                elements: str
                required: false
            params:
                description:
                    - the parameter for each selector, see definition in above list.
                type: dict
                required: false
            selector:
                description:
                    - selector of the retrieved fortiOS facts
                type: str
                required: true
                choices:
                 - 'endpoint-control_profile_xml'
                 - 'endpoint-control_record-list'
                 - 'endpoint-control_registration_summary'
                 - 'endpoint-control_installer'
                 - 'endpoint-control_installer_download'
                 - 'endpoint-control_avatar_download'
                 - 'firewall_health'
                 - 'firewall_local-in'
                 - 'firewall_acl'
                 - 'firewall_acl6'
                 - 'firewall_internet-service-match'
                 - 'firewall_internet-service-details'
                 - 'firewall_policy'
                 - 'firewall_policy6'
                 - 'firewall_proxy-policy'
                 - 'firewall_policy-lookup'
                 - 'firewall_session'
                 - 'firewall_shaper'
                 - 'firewall_per-ip-shaper'
                 - 'firewall_load-balance'
                 - 'firewall_address-fqdns'
                 - 'firewall_address-fqdns6'
                 - 'firewall_ippool'
                 - 'firewall_address-dynamic'
                 - 'firewall_address6-dynamic'
                 - 'fortiview_statistics'
                 - 'fortiview_sandbox-file-details'
                 - 'geoip_geoip-query'
                 - 'ips_rate-based'
                 - 'license_status'
                 - 'license_forticare-resellers'
                 - 'license_forticare-org-list'
                 - 'log_current-disk-usage'
                 - 'log_device_state'
                 - 'log_forticloud'
                 - 'log_fortianalyzer'
                 - 'log_fortianalyzer-queue'
                 - 'log_hourly-disk-usage'
                 - 'log_historic-daily-remote-logs'
                 - 'log_stats'
                 - 'log_forticloud-report_download'
                 - 'log_ips-archive_download'
                 - 'log_policy-archive_download'
                 - 'log_av-archive_download'
                 - 'log_event'
                 - 'registration_forticloud_disclaimer'
                 - 'registration_forticloud_domains'
                 - 'router_ipv4'
                 - 'router_ipv6'
                 - 'router_statistics'
                 - 'router_lookup'
                 - 'router_policy'
                 - 'router_policy6'
                 - 'system_config-revision'
                 - 'system_config-revision_file'
                 - 'system_config-revision_info'
                 - 'system_current-admins'
                 - 'system_time'
                 - 'system_global-resources'
                 - 'system_vdom-resource'
                 - 'system_dhcp'
                 - 'system_firmware'
                 - 'system_firmware_upgrade-paths'
                 - 'system_storage'
                 - 'system_csf'
                 - 'system_csf_pending-authorizations'
                 - 'system_modem'
                 - 'system_3g-modem'
                 - 'system_resource_usage'
                 - 'system_sniffer'
                 - 'system_sniffer_download'
                 - 'system_automation-stitch_stats'
                 - 'switch-controller_managed-switch'
                 - 'switch-controller_managed-switch_faceplate-xml'
                 - 'switch-controller_managed-switch_dhcp-snooping'
                 - 'switch-controller_fsw-firmware'
                 - 'switch-controller_detected-device'
                 - 'switch-controller_validate-switch-prefix'
                 - 'system_interface'
                 - 'system_interface_dhcp-status'
                 - 'system_available-interfaces'
                 - 'system_acquired-dns'
                 - 'system_resolve-fqdn'
                 - 'system_nat46-ippools'
                 - 'system_usb-log'
                 - 'system_ipconf'
                 - 'system_fortiguard_server-info'
                 - 'system_fortimanager_status'
                 - 'system_fortimanager_backup-summary'
                 - 'system_fortimanager_backup-details'
                 - 'system_available-certificates'
                 - 'system_certificate_download'
                 - 'system_debug_download'
                 - 'system_com-log_update'
                 - 'system_com-log_download'
                 - 'system_botnet_stat'
                 - 'system_botnet'
                 - 'system_botnet-domains'
                 - 'system_botnet-domains_stat'
                 - 'system_botnet-domains_hits'
                 - 'system_ha-statistics'
                 - 'system_ha-history'
                 - 'system_ha-checksums'
                 - 'system_ha-peer'
                 - 'system_link-monitor'
                 - 'system_config_backup'
                 - 'system_config_usb-filelist'
                 - 'system_sandbox_stats'
                 - 'system_sandbox_status'
                 - 'system_sandbox_test-connect'
                 - 'system_object_usage'
                 - 'system_object-tagging_usage'
                 - 'system_status'
                 - 'system_timezone'
                 - 'system_sensor-info'
                 - 'system_security-rating'
                 - 'system_security-rating_history'
                 - 'system_security-rating_status'
                 - 'system_security-rating_lang'
                 - 'system_fortiguard-blacklist'
                 - 'system_check-port-availability'
                 - 'system_external-resource_entry-list'
                 - 'extender-controller_extender'
                 - 'system_sdn-connector_status'
                 - 'user_firewall'
                 - 'user_banned'
                 - 'user_fortitoken'
                 - 'user_detected-device'
                 - 'user_device'
                 - 'user_device-type'
                 - 'user_device-category'
                 - 'user_fsso'
                 - 'utm_rating-lookup'
                 - 'utm_app-lookup'
                 - 'utm_application-categories'
                 - 'utm_antivirus_stats'
                 - 'virtual-wan_health-check'
                 - 'virtual-wan_members'
                 - 'webfilter_override'
                 - 'webfilter_malicious-urls'
                 - 'webfilter_malicious-urls_stat'
                 - 'webfilter_category-quota'
                 - 'webfilter_fortiguard-categories'
                 - 'webfilter_trusted-urls'
                 - 'vpn_ipsec'
                 - 'vpn_one-click_members'
                 - 'vpn_one-click_status'
                 - 'vpn_ssl'
                 - 'vpn_ssl_stats'
                 - 'wanopt_history'
                 - 'wanopt_webcache'
                 - 'wanopt_peer_stats'
                 - 'webproxy_pacfile_download'
                 - 'webcache_stats'
                 - 'wifi_client'
                 - 'wifi_managed_ap'
                 - 'wifi_firmware'
                 - 'wifi_ap_status'
                 - 'wifi_interfering_ap'
                 - 'wifi_euclid'
                 - 'wifi_rogue_ap'
                 - 'wifi_spectrum'
                 - 'endpoint-control_summary'
                 - 'endpoint-control_ems_status'
                 - 'firewall_consolidated-policy'
                 - 'firewall_security-policy'
                 - 'firewall_uuid-list'
                 - 'firewall_uuid-type-lookup'
                 - 'fortiguard_redirect-portal'
                 - 'firewall_sdn-connector-filters'
                 - 'fortiview_sandbox-file-list'
                 - 'ips_metadata'
                 - 'ips_anomaly'
                 - 'license_fortianalyzer-status'
                 - 'log_forticloud-report-list'
                 - 'log_local-report-list'
                 - 'log_local-report_download'
                 - 'network_lldp_neighbors'
                 - 'network_lldp_ports'
                 - 'network_dns_latency'
                 - 'network_fortiguard_live-services-latency'
                 - 'network_ddns_servers'
                 - 'network_ddns_lookup'
                 - 'router_lookup-policy'
                 - 'system_config-script'
                 - 'system_config-sync_status'
                 - 'system_vdom-link'
                 - 'switch-controller_managed-switch_transceivers'
                 - 'system_interface_poe'
                 - 'system_trusted-cert-authorities'
                 - 'system_sandbox_cloud-regions'
                 - 'system_interface_transceivers'
                 - 'system_vm-information'
                 - 'system_security-rating_supported-reports'
                 - 'nsx_service_status'
                 - 'nsx_instance'
                 - 'system_sdn-connector_nsx-security-tags'
                 - 'web-ui_custom-language_download'
                 - 'user_collected-email'
                 - 'user_info_query'
                 - 'user_info_thumbnail'
                 - 'utm_blacklisted-certificates'
                 - 'utm_blacklisted-certificates_statistics'
                 - 'virtual-wan_interface-log'
                 - 'virtual-wan_sla-log'
                 - 'vpn_ocvpn_members'
                 - 'vpn_ocvpn_status'
                 - 'vpn_ocvpn_meta'
                 - 'wifi_network_list'
                 - 'wifi_network_status'
                 - 'wifi_region-image'
                 - 'azure_application-list'
                 - 'endpoint-control_ems_cert-status'
                 - 'endpoint-control_ems_status-summary'
                 - 'fortiguard_service-communication-stats'
                 - 'network_reverse-ip-lookup'
                 - 'registration_forticloud_device-status'
                 - 'switch-controller_managed-switch_health'
                 - 'switch-controller_managed-switch_cable-status'
                 - 'switch-controller_mclag-icl_eligible-peer'
                 - 'system_interface_speed-test-status'
                 - 'user_fortitoken-cloud_status'
                 - 'wifi_vlan-probe'
                 - 'firewall_ippool_mapping'
                 - 'network_arp'
                 - 'system_interface-connected-admins-info'
                 - 'system_ntp_status'
                 - 'system_config-error-log_download'
                 - 'system_running-processes'
                 - 'user_device_query'
                 - 'ips_exceed-scan-range'
                 - 'firewall_multicast-policy'
                 - 'firewall_multicast-policy6'
                 - 'firewall_gtp-statistics'
                 - 'firewall_gtp-runtime-statistics'
                 - 'router_bgp_neighbors'
                 - 'router_bgp_neighbors6'
                 - 'router_bgp_paths'
                 - 'router_bgp_paths6'
                 - 'router_ospf_neighbors'
                 - 'system_automation-action_stats'
                 - 'switch-controller_matched-devices'
                 - 'system_ha-table-checksums'
                 - 'system_sandbox_connection'
                 - 'system_traffic-history_interface'
                 - 'system_traffic-history_top-applications'
                 - 'videofilter_fortiguard-categories'
                 - 'firewall_central-snat-map'
                 - 'firewall_dnat'
                 - 'ips_hold-signatures'
                 - 'router_bgp_paths-statistics'
                 - 'system_lte-modem_status'
                 - 'system_global-search'
                 - 'switch-controller_managed-switch_status'
                 - 'switch-controller_managed-switch_port-stats'
                 - 'switch-controller_managed-switch_models'
                 - 'system_interface_kernel-interfaces'
                 - 'system_config_restore-status'
                 - 'wifi_meta'
                 - 'wifi_ap_channels'
                 - 'wifi_ap-names'
                 - 'firewall_internet-service-reputation'
                 - 'firewall_shaper_multi-class-shaper'
                 - 'log_forticloud_connection'
                 - 'system_performance_status'
                 - 'system_ipam_list'
                 - 'system_ipam_status'
                 - 'system_acme-certificate-status'
                 - 'system_crash-log_download'
                 - 'user_banned_check'
                 - 'user_info_thumbnail-file'
                 - 'vpn-certificate_cert-name-available'
                 - 'wifi_unassociated-devices'
                 - 'wifi_matched-devices'
                 - 'firewall_proxy_sessions'
                 - 'firewall_gtp'
                 - 'fortiview_proxy-statistics'
                 - 'system_ha-hw-interface'
                 - 'user_firewall_count'
                 - 'firewall_internet-service-basic'
                 - 'firewall_vip-overlap'
                 - 'switch-controller_managed-switch_port-health'
                 - 'switch-controller_managed-switch_tx-rx'
                 - 'firewall_network-service-dynamic'
                 - 'system_ipam_utilization'
                 - 'system_ha-nonsync-checksums'
                 - 'wifi_station-capability'
                 - 'fortiguard_answers'
                 - 'ips_session_performance'
                 - 'switch-controller_nac-device_stats'
                 - 'switch-controller_isl-lockdown_status'
                 - 'wifi_nac-device_stats'
                 - 'firewall_sessions'
                 - 'fortiview_realtime-statistics'
                 - 'fortiview_historical-statistics'
                 - 'fortiview_realtime-proxy-statistics'
                 - 'log_feature-set'
                 - 'forticonverter_eligibility'
                 - 'forticonverter_ticket_status'
                 - 'forticonverter_sn-list'
                 - 'forticonverter_intf-list'
                 - 'forticonverter_custom-operation_status'
                 - 'forticonverter_intf-mapping'
                 - 'forticonverter_mgmt-intf'
                 - 'forticonverter_notes'
                 - 'forticonverter_download_ready'
                 - 'forticonverter_file_download'
                 - 'forticonverter_download_status'
                 - 'switch-controller_managed-switch_bios'
                 - 'system_available-interfaces_meta'
                 - 'system_central-management_status'
                 - 'user_device_stats'
                 - 'casb_saas-application_details'
                 - 'switch-controller_mclag-icl_tier-plus-candidates'
                 - 'extension-controller_fortigate'
                 - 'extension-controller_lan-extension-vdom-status'
                 - 'user_proxy'
                 - 'user_proxy_count'
                 - 'firewall_check-addrgrp-exclude-mac-member'
                 - 'firewall_saas-application'
                 - 'router_sdwan_routes'
                 - 'router_sdwan_routes6'
                 - 'router_sdwan_routes-statistics'
                 - 'extender-controller_extender_modem-firmware'
                 - 'user_radius_get-test-connect'
                 - 'endpoint-control_ems_malware-hash'
                 - 'switch-controller_managed-switch_health-status'
                 - 'firewall_local-in6'
                 - 'firmware_extension-device'
                 - 'service_ldap_query'
                 - 'router_bgp_neighbors-statistics'
                 - 'router_lookup_ha-peer'
                 - 'system_cluster_state'
                 - 'system_upgrade-report_exists'
                 - 'system_upgrade-report_saved'
                 - 'system_upgrade-report_current'
                 - 'system_ha-backup-hb-used'
                 - 'system_external-resource_validate-jsonpath'
                 - 'user_scim_groups'
                 - 'virtual-wan_sladb'
                 - 'wifi_statistics'
                 - 'router_charts'
                 - 'switch-controller_known-nac-device-criteria-list'
                 - 'system_sandbox_detect'
                 - 'system_monitor-sensor'
                 - 'user_device_iot-query'
                 - 'user_scim_users'
                 - 'telemetry-controller_agents'
                 - 'telemetry-controller_agent-tasks'
                 - 'firewall_internet-service-fqdn'
                 - 'firewall_internet-service-fqdn-icon-ids'
                 - 'system_5g-modem_status'
                 - 'system_interface_poe-usage'
                 - 'vpn_ipsec_connection-count'

    selector:
        description:
            - selector of the retrieved fortiOS facts.
        type: str
        required: false
        choices:
         - 'endpoint-control_profile_xml'
         - 'endpoint-control_record-list'
         - 'endpoint-control_registration_summary'
         - 'endpoint-control_installer'
         - 'endpoint-control_installer_download'
         - 'endpoint-control_avatar_download'
         - 'firewall_health'
         - 'firewall_local-in'
         - 'firewall_acl'
         - 'firewall_acl6'
         - 'firewall_internet-service-match'
         - 'firewall_internet-service-details'
         - 'firewall_policy'
         - 'firewall_policy6'
         - 'firewall_proxy-policy'
         - 'firewall_policy-lookup'
         - 'firewall_session'
         - 'firewall_shaper'
         - 'firewall_per-ip-shaper'
         - 'firewall_load-balance'
         - 'firewall_address-fqdns'
         - 'firewall_address-fqdns6'
         - 'firewall_ippool'
         - 'firewall_address-dynamic'
         - 'firewall_address6-dynamic'
         - 'fortiview_statistics'
         - 'fortiview_sandbox-file-details'
         - 'geoip_geoip-query'
         - 'ips_rate-based'
         - 'license_status'
         - 'license_forticare-resellers'
         - 'license_forticare-org-list'
         - 'log_current-disk-usage'
         - 'log_device_state'
         - 'log_forticloud'
         - 'log_fortianalyzer'
         - 'log_fortianalyzer-queue'
         - 'log_hourly-disk-usage'
         - 'log_historic-daily-remote-logs'
         - 'log_stats'
         - 'log_forticloud-report_download'
         - 'log_ips-archive_download'
         - 'log_policy-archive_download'
         - 'log_av-archive_download'
         - 'log_event'
         - 'registration_forticloud_disclaimer'
         - 'registration_forticloud_domains'
         - 'router_ipv4'
         - 'router_ipv6'
         - 'router_statistics'
         - 'router_lookup'
         - 'router_policy'
         - 'router_policy6'
         - 'system_config-revision'
         - 'system_config-revision_file'
         - 'system_config-revision_info'
         - 'system_current-admins'
         - 'system_time'
         - 'system_global-resources'
         - 'system_vdom-resource'
         - 'system_dhcp'
         - 'system_firmware'
         - 'system_firmware_upgrade-paths'
         - 'system_storage'
         - 'system_csf'
         - 'system_csf_pending-authorizations'
         - 'system_modem'
         - 'system_3g-modem'
         - 'system_resource_usage'
         - 'system_sniffer'
         - 'system_sniffer_download'
         - 'system_automation-stitch_stats'
         - 'switch-controller_managed-switch'
         - 'switch-controller_managed-switch_faceplate-xml'
         - 'switch-controller_managed-switch_dhcp-snooping'
         - 'switch-controller_fsw-firmware'
         - 'switch-controller_detected-device'
         - 'switch-controller_validate-switch-prefix'
         - 'system_interface'
         - 'system_interface_dhcp-status'
         - 'system_available-interfaces'
         - 'system_acquired-dns'
         - 'system_resolve-fqdn'
         - 'system_nat46-ippools'
         - 'system_usb-log'
         - 'system_ipconf'
         - 'system_fortiguard_server-info'
         - 'system_fortimanager_status'
         - 'system_fortimanager_backup-summary'
         - 'system_fortimanager_backup-details'
         - 'system_available-certificates'
         - 'system_certificate_download'
         - 'system_debug_download'
         - 'system_com-log_update'
         - 'system_com-log_download'
         - 'system_botnet_stat'
         - 'system_botnet'
         - 'system_botnet-domains'
         - 'system_botnet-domains_stat'
         - 'system_botnet-domains_hits'
         - 'system_ha-statistics'
         - 'system_ha-history'
         - 'system_ha-checksums'
         - 'system_ha-peer'
         - 'system_link-monitor'
         - 'system_config_backup'
         - 'system_config_usb-filelist'
         - 'system_sandbox_stats'
         - 'system_sandbox_status'
         - 'system_sandbox_test-connect'
         - 'system_object_usage'
         - 'system_object-tagging_usage'
         - 'system_status'
         - 'system_timezone'
         - 'system_sensor-info'
         - 'system_security-rating'
         - 'system_security-rating_history'
         - 'system_security-rating_status'
         - 'system_security-rating_lang'
         - 'system_fortiguard-blacklist'
         - 'system_check-port-availability'
         - 'system_external-resource_entry-list'
         - 'extender-controller_extender'
         - 'system_sdn-connector_status'
         - 'user_firewall'
         - 'user_banned'
         - 'user_fortitoken'
         - 'user_detected-device'
         - 'user_device'
         - 'user_device-type'
         - 'user_device-category'
         - 'user_fsso'
         - 'utm_rating-lookup'
         - 'utm_app-lookup'
         - 'utm_application-categories'
         - 'utm_antivirus_stats'
         - 'virtual-wan_health-check'
         - 'virtual-wan_members'
         - 'webfilter_override'
         - 'webfilter_malicious-urls'
         - 'webfilter_malicious-urls_stat'
         - 'webfilter_category-quota'
         - 'webfilter_fortiguard-categories'
         - 'webfilter_trusted-urls'
         - 'vpn_ipsec'
         - 'vpn_one-click_members'
         - 'vpn_one-click_status'
         - 'vpn_ssl'
         - 'vpn_ssl_stats'
         - 'wanopt_history'
         - 'wanopt_webcache'
         - 'wanopt_peer_stats'
         - 'webproxy_pacfile_download'
         - 'webcache_stats'
         - 'wifi_client'
         - 'wifi_managed_ap'
         - 'wifi_firmware'
         - 'wifi_ap_status'
         - 'wifi_interfering_ap'
         - 'wifi_euclid'
         - 'wifi_rogue_ap'
         - 'wifi_spectrum'
         - 'endpoint-control_summary'
         - 'endpoint-control_ems_status'
         - 'firewall_consolidated-policy'
         - 'firewall_security-policy'
         - 'firewall_uuid-list'
         - 'firewall_uuid-type-lookup'
         - 'fortiguard_redirect-portal'
         - 'firewall_sdn-connector-filters'
         - 'fortiview_sandbox-file-list'
         - 'ips_metadata'
         - 'ips_anomaly'
         - 'license_fortianalyzer-status'
         - 'log_forticloud-report-list'
         - 'log_local-report-list'
         - 'log_local-report_download'
         - 'network_lldp_neighbors'
         - 'network_lldp_ports'
         - 'network_dns_latency'
         - 'network_fortiguard_live-services-latency'
         - 'network_ddns_servers'
         - 'network_ddns_lookup'
         - 'router_lookup-policy'
         - 'system_config-script'
         - 'system_config-sync_status'
         - 'system_vdom-link'
         - 'switch-controller_managed-switch_transceivers'
         - 'system_interface_poe'
         - 'system_trusted-cert-authorities'
         - 'system_sandbox_cloud-regions'
         - 'system_interface_transceivers'
         - 'system_vm-information'
         - 'system_security-rating_supported-reports'
         - 'nsx_service_status'
         - 'nsx_instance'
         - 'system_sdn-connector_nsx-security-tags'
         - 'web-ui_custom-language_download'
         - 'user_collected-email'
         - 'user_info_query'
         - 'user_info_thumbnail'
         - 'utm_blacklisted-certificates'
         - 'utm_blacklisted-certificates_statistics'
         - 'virtual-wan_interface-log'
         - 'virtual-wan_sla-log'
         - 'vpn_ocvpn_members'
         - 'vpn_ocvpn_status'
         - 'vpn_ocvpn_meta'
         - 'wifi_network_list'
         - 'wifi_network_status'
         - 'wifi_region-image'
         - 'azure_application-list'
         - 'endpoint-control_ems_cert-status'
         - 'endpoint-control_ems_status-summary'
         - 'fortiguard_service-communication-stats'
         - 'network_reverse-ip-lookup'
         - 'registration_forticloud_device-status'
         - 'switch-controller_managed-switch_health'
         - 'switch-controller_managed-switch_cable-status'
         - 'switch-controller_mclag-icl_eligible-peer'
         - 'system_interface_speed-test-status'
         - 'user_fortitoken-cloud_status'
         - 'wifi_vlan-probe'
         - 'firewall_ippool_mapping'
         - 'network_arp'
         - 'system_interface-connected-admins-info'
         - 'system_ntp_status'
         - 'system_config-error-log_download'
         - 'system_running-processes'
         - 'user_device_query'
         - 'ips_exceed-scan-range'
         - 'firewall_multicast-policy'
         - 'firewall_multicast-policy6'
         - 'firewall_gtp-statistics'
         - 'firewall_gtp-runtime-statistics'
         - 'router_bgp_neighbors'
         - 'router_bgp_neighbors6'
         - 'router_bgp_paths'
         - 'router_bgp_paths6'
         - 'router_ospf_neighbors'
         - 'system_automation-action_stats'
         - 'switch-controller_matched-devices'
         - 'system_ha-table-checksums'
         - 'system_sandbox_connection'
         - 'system_traffic-history_interface'
         - 'system_traffic-history_top-applications'
         - 'videofilter_fortiguard-categories'
         - 'firewall_central-snat-map'
         - 'firewall_dnat'
         - 'ips_hold-signatures'
         - 'router_bgp_paths-statistics'
         - 'system_lte-modem_status'
         - 'system_global-search'
         - 'switch-controller_managed-switch_status'
         - 'switch-controller_managed-switch_port-stats'
         - 'switch-controller_managed-switch_models'
         - 'system_interface_kernel-interfaces'
         - 'system_config_restore-status'
         - 'wifi_meta'
         - 'wifi_ap_channels'
         - 'wifi_ap-names'
         - 'firewall_internet-service-reputation'
         - 'firewall_shaper_multi-class-shaper'
         - 'log_forticloud_connection'
         - 'system_performance_status'
         - 'system_ipam_list'
         - 'system_ipam_status'
         - 'system_acme-certificate-status'
         - 'system_crash-log_download'
         - 'user_banned_check'
         - 'user_info_thumbnail-file'
         - 'vpn-certificate_cert-name-available'
         - 'wifi_unassociated-devices'
         - 'wifi_matched-devices'
         - 'firewall_proxy_sessions'
         - 'firewall_gtp'
         - 'fortiview_proxy-statistics'
         - 'system_ha-hw-interface'
         - 'user_firewall_count'
         - 'firewall_internet-service-basic'
         - 'firewall_vip-overlap'
         - 'switch-controller_managed-switch_port-health'
         - 'switch-controller_managed-switch_tx-rx'
         - 'firewall_network-service-dynamic'
         - 'system_ipam_utilization'
         - 'system_ha-nonsync-checksums'
         - 'wifi_station-capability'
         - 'fortiguard_answers'
         - 'ips_session_performance'
         - 'switch-controller_nac-device_stats'
         - 'switch-controller_isl-lockdown_status'
         - 'wifi_nac-device_stats'
         - 'firewall_sessions'
         - 'fortiview_realtime-statistics'
         - 'fortiview_historical-statistics'
         - 'fortiview_realtime-proxy-statistics'
         - 'log_feature-set'
         - 'forticonverter_eligibility'
         - 'forticonverter_ticket_status'
         - 'forticonverter_sn-list'
         - 'forticonverter_intf-list'
         - 'forticonverter_custom-operation_status'
         - 'forticonverter_intf-mapping'
         - 'forticonverter_mgmt-intf'
         - 'forticonverter_notes'
         - 'forticonverter_download_ready'
         - 'forticonverter_file_download'
         - 'forticonverter_download_status'
         - 'switch-controller_managed-switch_bios'
         - 'system_available-interfaces_meta'
         - 'system_central-management_status'
         - 'user_device_stats'
         - 'casb_saas-application_details'
         - 'switch-controller_mclag-icl_tier-plus-candidates'
         - 'extension-controller_fortigate'
         - 'extension-controller_lan-extension-vdom-status'
         - 'user_proxy'
         - 'user_proxy_count'
         - 'firewall_check-addrgrp-exclude-mac-member'
         - 'firewall_saas-application'
         - 'router_sdwan_routes'
         - 'router_sdwan_routes6'
         - 'router_sdwan_routes-statistics'
         - 'extender-controller_extender_modem-firmware'
         - 'user_radius_get-test-connect'
         - 'endpoint-control_ems_malware-hash'
         - 'switch-controller_managed-switch_health-status'
         - 'firewall_local-in6'
         - 'firmware_extension-device'
         - 'service_ldap_query'
         - 'router_bgp_neighbors-statistics'
         - 'router_lookup_ha-peer'
         - 'system_cluster_state'
         - 'system_upgrade-report_exists'
         - 'system_upgrade-report_saved'
         - 'system_upgrade-report_current'
         - 'system_ha-backup-hb-used'
         - 'system_external-resource_validate-jsonpath'
         - 'user_scim_groups'
         - 'virtual-wan_sladb'
         - 'wifi_statistics'
         - 'router_charts'
         - 'switch-controller_known-nac-device-criteria-list'
         - 'system_sandbox_detect'
         - 'system_monitor-sensor'
         - 'user_device_iot-query'
         - 'user_scim_users'
         - 'telemetry-controller_agents'
         - 'telemetry-controller_agent-tasks'
         - 'firewall_internet-service-fqdn'
         - 'firewall_internet-service-fqdn-icon-ids'
         - 'system_5g-modem_status'
         - 'system_interface_poe-usage'
         - 'vpn_ipsec_connection-count'

    params:
        description:
            - the parameter for each selector, see definition in above list.
        type: dict
        required: false
"""

EXAMPLES = """
- name: Get license status
  fortinet.fortios.fortios_monitor_fact:
      vdom: root
      selectors:
          - selector: license_status
          - selector: system_status
          - selector: firewall_security-policy
            params:
                policyid: '1'

- name: Get system status
  fortinet.fortios.fortios_monitor_fact:
      vdom: root
      formatters:
          - model_name
      filters:
          - model_name==FortiGat
      selector: 'system_status'

- name: Get firewall acl info
  fortinet.fortios.fortios_monitor_fact:
      vdom: root
      access_token: "you_own_value"
      selector: 'firewall_acl'
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
  sample: 'GET'
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "firmware"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "system"
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
ansible_facts:
  description: The list of fact subsets collected from the device
  returned: always
  type: dict

"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)

# from urllib.parse import quote
try:
    # For Python 3
    from urllib.parse import quote
except ImportError:
    # For Python 2
    from urllib import quote

module_selectors_defs = {
    "endpoint-control_profile_xml": {
        "url": "endpoint-control/profile/xml",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "endpoint-control_record-list": {
        "url": "endpoint-control/record-list",
        "params": {"intf_name": {"type": "string", "required": "False"}},
    },
    "endpoint-control_registration_summary": {
        "url": "endpoint-control/registration/summary",
        "params": {},
    },
    "endpoint-control_installer": {
        "url": "endpoint-control/installer",
        "params": {"min_version": {"type": "string", "required": "False"}},
    },
    "endpoint-control_installer_download": {
        "url": "endpoint-control/installer/download",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "endpoint-control_avatar_download": {
        "url": "endpoint-control/avatar/download",
        "params": {
            "uid": {"type": "string", "required": "False"},
            "user": {"type": "string", "required": "False"},
            "fingerprint": {"type": "string", "required": "False"},
            "default": {"type": "string", "required": "False"},
        },
    },
    "firewall_health": {"url": "firewall/health", "params": {}},
    "firewall_local-in": {
        "url": "firewall/local-in",
        "params": {"include_ttl": {"type": "boolean", "required": "False"}},
    },
    "firewall_acl": {"url": "firewall/acl", "params": {}},
    "firewall_acl6": {"url": "firewall/acl6", "params": {}},
    "firewall_internet-service-match": {
        "url": "firewall/internet-service-match",
        "params": {
            "ip": {"type": "string", "required": "True"},
            "is_ipv6": {"type": "boolean", "required": "False"},
            "ipv4_mask": {"type": "string", "required": "False"},
            "ipv6_prefix": {"type": "int", "required": "False"},
        },
    },
    "firewall_internet-service-details": {
        "url": "firewall/internet-service-details",
        "params": {
            "id": {"type": "int", "required": "True"},
            "country_id": {"type": "int", "required": "False"},
            "region_id": {"type": "int", "required": "False"},
            "city_id": {"type": "int", "required": "False"},
            "summary_only": {"type": "boolean", "required": "False"},
            "ipv6_only": {"type": "boolean", "required": "False"},
        },
    },
    "firewall_policy": {
        "url": "firewall/policy",
        "params": {
            "policyid": {"type": "array", "required": "False"},
            "ip_version": {"type": "string", "required": "False"},
        },
    },
    "firewall_policy6": {
        "url": "firewall/policy6",
        "params": {"policyid": {"type": "int", "required": "False"}},
    },
    "firewall_proxy-policy": {
        "url": "firewall/proxy-policy",
        "params": {"policyid": {"type": "int", "required": "False"}},
    },
    "firewall_policy-lookup": {
        "url": "firewall/policy-lookup",
        "params": {
            "ipv6": {"type": "boolean", "required": "False"},
            "srcintf": {"type": "string", "required": "True"},
            "sourceport": {"type": "int", "required": "False"},
            "sourceip": {"type": "string", "required": "True"},
            "protocol": {"type": "string", "required": "True"},
            "dest": {"type": "string", "required": "True"},
            "destport": {"type": "int", "required": "False"},
            "icmptype": {"type": "int", "required": "False"},
            "icmpcode": {"type": "int", "required": "False"},
            "policy_type": {"type": "string", "required": "False"},
            "auth_type": {"type": "string", "required": "False"},
            "user_group": {"type": "array", "required": "False"},
            "server_name": {"type": "string", "required": "False"},
            "user_db": {"type": "string", "required": "False"},
            "group_attr_type": {"type": "string", "required": "False"},
        },
    },
    "firewall_session": {
        "url": "firewall/session",
        "params": {
            "ip_version": {"type": "string", "required": "False"},
            "count": {"type": "int", "required": "True"},
            "summary": {"type": "boolean", "required": "False"},
            "sourceport": {"type": "int", "required": "False"},
            "policyid": {"type": "int", "required": "False"},
            "security-policyid": {"type": "int", "required": "False"},
            "application": {"type": "string", "required": "False"},
            "protocol": {"type": "string", "required": "False"},
            "destport": {"type": "int", "required": "False"},
            "srcintf": {"type": "string", "required": "False"},
            "dstintf": {"type": "string", "required": "False"},
            "srcintfrole": {"type": "string", "required": "False"},
            "dstintfrole": {"type": "string", "required": "False"},
            "source": {"type": "string", "required": "False"},
            "srcuuid": {"type": "string", "required": "False"},
            "destination": {"type": "string", "required": "False"},
            "dstuuid": {"type": "string", "required": "False"},
            "username": {"type": "string", "required": "False"},
            "shaper": {"type": "string", "required": "False"},
            "country": {"type": "string", "required": "False"},
            "owner": {"type": "string", "required": "False"},
            "natsourceaddress": {"type": "string", "required": "False"},
            "natsourceport": {"type": "int", "required": "False"},
            "filter-csf": {"type": "boolean", "required": "False"},
            "since": {"type": "int", "required": "False"},
            "seconds": {"type": "int", "required": "False"},
            "web-domain": {"type": "string", "required": "False"},
            "web-category": {"type": "string", "required": "False"},
            "fortiasic": {"type": "int", "required": "False"},
        },
    },
    "firewall_shaper": {
        "url": "firewall/shaper",
        "params": {"shaper_name": {"type": "string", "required": "False"}},
    },
    "firewall_per-ip-shaper": {
        "url": "firewall/per-ip-shaper",
        "params": {"shaper_name": {"type": "string", "required": "False"}},
    },
    "firewall_load-balance": {
        "url": "firewall/load-balance",
        "params": {"count": {"type": "int", "required": "True"}},
    },
    "firewall_address-fqdns": {
        "url": "firewall/address-fqdns",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "firewall_address-fqdns6": {
        "url": "firewall/address-fqdns6",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "firewall_ippool": {"url": "firewall/ippool", "params": {}},
    "firewall_address-dynamic": {
        "url": "firewall/address-dynamic",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "firewall_address6-dynamic": {
        "url": "firewall/address6-dynamic",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "fortiview_statistics": {
        "url": "fortiview/statistics",
        "params": {
            "realtime": {"type": "boolean", "required": "False"},
            "filter": {"type": "object", "required": "False"},
            "sessionid": {"type": "int", "required": "False"},
            "device": {"type": "string", "required": "False"},
            "report_by": {"type": "string", "required": "False"},
            "sort_by": {"type": "string", "required": "False"},
            "chart_only": {"type": "boolean", "required": "False"},
            "end": {"type": "int", "required": "False"},
            "ip_version": {"type": "string", "required": "False"},
        },
    },
    "fortiview_sandbox-file-details": {
        "url": "fortiview/sandbox-file-details",
        "params": {"checksum": {"type": "string", "required": "True"}},
    },
    "geoip_geoip-query": {
        "url": "geoip/geoip-query",
        "params": {"ip_addresses": {"type": "string", "required": "True"}},
    },
    "ips_rate-based": {"url": "ips/rate-based", "params": {}},
    "license_status": {"url": "license/status", "params": {}},
    "license_forticare-resellers": {
        "url": "license/forticare-resellers",
        "params": {"country_code": {"type": "int", "required": "False"}},
    },
    "license_forticare-org-list": {"url": "license/forticare-org-list", "params": {}},
    "log_current-disk-usage": {"url": "log/current-disk-usage", "params": {}},
    "log_device_state": {
        "url": "log/device/state",
        "params": {"scope": {"type": "string", "required": "False"}},
    },
    "log_forticloud": {"url": "log/forticloud", "params": {}},
    "log_fortianalyzer": {
        "url": "log/fortianalyzer",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "server": {"type": "string", "required": "False"},
            "srcip": {"type": "string", "required": "False"},
        },
    },
    "log_fortianalyzer-queue": {
        "url": "log/fortianalyzer-queue",
        "params": {"scope": {"type": "string", "required": "False"}},
    },
    "log_hourly-disk-usage": {"url": "log/hourly-disk-usage", "params": {}},
    "log_historic-daily-remote-logs": {
        "url": "log/historic-daily-remote-logs",
        "params": {"server": {"type": "string", "required": "True"}},
    },
    "log_stats": {
        "url": "log/stats",
        "params": {"dev": {"type": "string", "required": "False"}},
    },
    "log_forticloud-report_download": {
        "url": "log/forticloud-report/download",
        "params": {
            "mkey": {"type": "int", "required": "True"},
            "report_name": {"type": "string", "required": "True"},
            "inline": {"type": "int", "required": "False"},
        },
    },
    "log_ips-archive_download": {
        "url": "log/ips-archive/download",
        "params": {
            "mkey": {"type": "int", "required": "True"},
            "pcap_no": {"type": "int", "required": "False"},
            "pcap_category": {"type": "int", "required": "False"},
        },
    },
    "log_policy-archive_download": {
        "url": "log/policy-archive/download",
        "params": {
            "mkey": {"type": "int", "required": "True"},
            "srcip": {"type": "string", "required": "True"},
            "dstip": {"type": "string", "required": "True"},
        },
    },
    "log_av-archive_download": {
        "url": "log/av-archive/download",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "log_event": {"url": "log/event", "params": {}},
    "registration_forticloud_disclaimer": {
        "url": "registration/forticloud/disclaimer",
        "params": {},
    },
    "registration_forticloud_domains": {
        "url": "registration/forticloud/domains",
        "params": {},
    },
    "router_ipv4": {
        "url": "router/ipv4",
        "params": {
            "operator": {"type": "string", "required": "False"},
            "ip_mask": {"type": "string", "required": "False"},
            "gateway": {"type": "string", "required": "False"},
            "type": {"type": "string", "required": "False"},
            "origin": {"type": "string", "required": "False"},
            "interface": {"type": "string", "required": "False"},
        },
    },
    "router_ipv6": {
        "url": "router/ipv6",
        "params": {
            "operator": {"type": "string", "required": "False"},
            "ip_mask": {"type": "string", "required": "False"},
            "gateway": {"type": "string", "required": "False"},
            "type": {"type": "string", "required": "False"},
            "origin": {"type": "string", "required": "False"},
            "interface": {"type": "string", "required": "False"},
        },
    },
    "router_statistics": {
        "url": "router/statistics",
        "params": {
            "operator": {"type": "string", "required": "False"},
            "ip_version": {"type": "int", "required": "False"},
            "ip_mask": {"type": "string", "required": "False"},
            "gateway": {"type": "string", "required": "False"},
            "type": {"type": "string", "required": "False"},
            "origin": {"type": "string", "required": "False"},
            "interface": {"type": "string", "required": "False"},
        },
    },
    "router_lookup": {
        "url": "router/lookup",
        "params": {
            "ipv6": {"type": "boolean", "required": "False"},
            "destination": {"type": "string", "required": "True"},
        },
    },
    "router_policy": {
        "url": "router/policy",
        "params": {"count_only": {"type": "boolean", "required": "False"}},
    },
    "router_policy6": {
        "url": "router/policy6",
        "params": {"count_only": {"type": "boolean", "required": "False"}},
    },
    "system_config-revision": {"url": "system/config-revision", "params": {}},
    "system_config-revision_file": {
        "url": "system/config-revision/file",
        "params": {"config_id": {"type": "int", "required": "False"}},
    },
    "system_config-revision_info": {
        "url": "system/config-revision/info",
        "params": {"config_id": {"type": "int", "required": "False"}},
    },
    "system_current-admins": {"url": "system/current-admins", "params": {}},
    "system_time": {"url": "system/time", "params": {}},
    "system_global-resources": {"url": "system/global-resources", "params": {}},
    "system_vdom-resource": {"url": "system/vdom-resource", "params": {}},
    "system_dhcp": {
        "url": "system/dhcp",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "ipv6": {"type": "boolean", "required": "False"},
            "interface": {"type": "string", "required": "False"},
        },
    },
    "system_firmware": {"url": "system/firmware", "params": {}},
    "system_firmware_upgrade-paths": {
        "url": "system/firmware/upgrade-paths",
        "params": {},
    },
    "system_storage": {"url": "system/storage", "params": {}},
    "system_csf": {
        "url": "system/csf",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "all_vdoms": {"type": "boolean", "required": "False"},
        },
    },
    "system_csf_pending-authorizations": {
        "url": "system/csf/pending-authorizations",
        "params": {},
    },
    "system_modem": {"url": "system/modem", "params": {}},
    "system_3g-modem": {"url": "system/3g-modem", "params": {}},
    "system_resource_usage": {
        "url": "system/resource/usage",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "resource": {"type": "string", "required": "False"},
            "interval": {"type": "string", "required": "False"},
        },
    },
    "system_sniffer": {"url": "system/sniffer", "params": {}},
    "system_sniffer_download": {
        "url": "system/sniffer/download",
        "params": {"mkey": {"type": "int", "required": "True"}},
    },
    "system_automation-stitch_stats": {
        "url": "system/automation-stitch/stats",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "switch-controller_managed-switch": {
        "url": "switch-controller/managed-switch",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "poe": {"type": "boolean", "required": "False"},
            "port_stats": {"type": "boolean", "required": "False"},
            "qos_stats": {"type": "boolean", "required": "False"},
            "stp_status": {"type": "boolean", "required": "False"},
            "igmp_snooping_group": {"type": "boolean", "required": "False"},
            "transceiver": {"type": "boolean", "required": "False"},
        },
    },
    "switch-controller_managed-switch_faceplate-xml": {
        "url": "switch-controller/managed-switch/faceplate-xml",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "switch-controller_managed-switch_dhcp-snooping": {
        "url": "switch-controller/managed-switch/dhcp-snooping",
        "params": {},
    },
    "switch-controller_fsw-firmware": {
        "url": "switch-controller/fsw-firmware",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "timeout": {"type": "int", "required": "False"},
            "version": {"type": "object", "required": "False"},
        },
    },
    "switch-controller_detected-device": {
        "url": "switch-controller/detected-device",
        "params": {},
    },
    "switch-controller_validate-switch-prefix": {
        "url": "switch-controller/validate-switch-prefix",
        "params": {"prefix": {"type": "string", "required": "False"}},
    },
    "system_interface": {
        "url": "system/interface",
        "params": {
            "interface_name": {"type": "string", "required": "False"},
            "include_vlan": {"type": "boolean", "required": "False"},
            "include_aggregate": {"type": "boolean", "required": "False"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "system_interface_dhcp-status": {
        "url": "system/interface/dhcp-status",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "ipv6": {"type": "boolean", "required": "False"},
        },
    },
    "system_available-interfaces": {
        "url": "system/available-interfaces",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "include_ha": {"type": "boolean", "required": "False"},
            "view_type": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "system_acquired-dns": {"url": "system/acquired-dns", "params": {}},
    "system_resolve-fqdn": {
        "url": "system/resolve-fqdn",
        "params": {
            "ipv6": {"type": "boolean", "required": "False"},
            "fqdn": {"type": "array", "required": "False"},
        },
    },
    "system_nat46-ippools": {"url": "system/nat46-ippools", "params": {}},
    "system_usb-log": {"url": "system/usb-log", "params": {}},
    "system_ipconf": {
        "url": "system/ipconf",
        "params": {
            "devs": {"type": "array", "required": "True"},
            "ipaddr": {"type": "string", "required": "True"},
        },
    },
    "system_fortiguard_server-info": {
        "url": "system/fortiguard/server-info",
        "params": {},
    },
    "system_fortimanager_status": {
        "url": "system/fortimanager/status",
        "params": {"skip_detect": {"type": "boolean", "required": "False"}},
    },
    "system_fortimanager_backup-summary": {
        "url": "system/fortimanager/backup-summary",
        "params": {},
    },
    "system_fortimanager_backup-details": {
        "url": "system/fortimanager/backup-details",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "datasource": {"type": "string", "required": "True"},
        },
    },
    "system_available-certificates": {
        "url": "system/available-certificates",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "with_remote": {"type": "boolean", "required": "False"},
            "with_ca": {"type": "boolean", "required": "False"},
            "with_crl": {"type": "boolean", "required": "False"},
            "mkey": {"type": "string", "required": "False"},
            "find_all_references": {"type": "boolean", "required": "False"},
        },
    },
    "system_certificate_download": {
        "url": "system/certificate/download",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "type": {"type": "string", "required": "True"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "system_debug_download": {"url": "system/debug/download", "params": {}},
    "system_com-log_update": {"url": "system/com-log/update", "params": {}},
    "system_com-log_download": {"url": "system/com-log/download", "params": {}},
    "system_botnet_stat": {"url": "system/botnet/stat", "params": {}},
    "system_botnet": {
        "url": "system/botnet",
        "params": {"include_hit_only": {"type": "boolean", "required": "False"}},
    },
    "system_botnet-domains": {"url": "system/botnet-domains", "params": {}},
    "system_botnet-domains_stat": {"url": "system/botnet-domains/stat", "params": {}},
    "system_botnet-domains_hits": {"url": "system/botnet-domains/hits", "params": {}},
    "system_ha-statistics": {"url": "system/ha-statistics", "params": {}},
    "system_ha-history": {"url": "system/ha-history", "params": {}},
    "system_ha-checksums": {"url": "system/ha-checksums", "params": {}},
    "system_ha-peer": {
        "url": "system/ha-peer",
        "params": {
            "serial_no": {"type": "string", "required": "False"},
            "vcluster_id": {"type": "int", "required": "False"},
        },
    },
    "system_link-monitor": {
        "url": "system/link-monitor",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "system_config_backup": {
        "url": "system/config/backup",
        "params": {
            "destination": {"type": "string", "required": "False"},
            "password": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "True"},
            "vdom": {"type": "string", "required": "False"},
            "password_mask": {"type": "boolean", "required": "False"},
            "file_format": {"type": "string", "required": "False"},
        },
    },
    "system_config_usb-filelist": {"url": "system/config/usb-filelist", "params": {}},
    "system_sandbox_stats": {"url": "system/sandbox/stats", "params": {}},
    "system_sandbox_status": {"url": "system/sandbox/status", "params": {}},
    "system_sandbox_test-connect": {
        "url": "system/sandbox/test-connect",
        "params": {"server": {"type": "string", "required": "True"}},
    },
    "system_object_usage": {
        "url": "system/object/usage",
        "params": {
            "q_path": {"type": "string", "required": "False"},
            "q_name": {"type": "string", "required": "False"},
            "qtypes": {"type": "array", "required": "False"},
            "scope": {"type": "string", "required": "False"},
            "mkey": {"type": "string", "required": "False"},
            "child_path": {"type": "string", "required": "False"},
        },
    },
    "system_object-tagging_usage": {"url": "system/object-tagging/usage", "params": {}},
    "system_status": {"url": "system/status", "params": {}},
    "system_timezone": {"url": "system/timezone", "params": {}},
    "system_sensor-info": {"url": "system/sensor-info", "params": {}},
    "system_security-rating": {
        "url": "system/security-rating",
        "params": {
            "id": {"type": "int", "required": "False"},
            "report_type": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "system_security-rating_history": {
        "url": "system/security-rating/history",
        "params": {"report_type": {"type": "string", "required": "False"}},
    },
    "system_security-rating_status": {
        "url": "system/security-rating/status",
        "params": {
            "id": {"type": "int", "required": "False"},
            "report_type": {"type": "string", "required": "False"},
            "progress": {"type": "boolean", "required": "False"},
        },
    },
    "system_security-rating_lang": {
        "url": "system/security-rating/lang",
        "params": {"key": {"type": "string", "required": "False"}},
    },
    "system_fortiguard-blacklist": {
        "url": "system/fortiguard-blacklist",
        "params": {
            "ip": {"type": "string", "required": "True"},
            "timeout": {"type": "int", "required": "False"},
        },
    },
    "system_check-port-availability": {
        "url": "system/check-port-availability",
        "params": {
            "port_ranges": {"type": "array", "required": "True"},
            "service": {"type": "string", "required": "False"},
        },
    },
    "system_external-resource_entry-list": {
        "url": "system/external-resource/entry-list",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "status_only": {"type": "boolean", "required": "False"},
            "include_notes": {"type": "boolean", "required": "False"},
            "counts_only": {"type": "boolean", "required": "False"},
            "entry": {"type": "object", "required": "False"},
        },
    },
    "extender-controller_extender": {
        "url": "extender-controller/extender",
        "params": {
            "fortiextender-name": {"type": "array", "required": "False"},
            "type": {"type": "string", "required": "False"},
        },
    },
    "system_sdn-connector_status": {
        "url": "system/sdn-connector/status",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "type": {"type": "string", "required": "False"},
        },
    },
    "user_firewall": {
        "url": "user/firewall",
        "params": {
            "ipv4": {"type": "boolean", "required": "False"},
            "ipv6": {"type": "boolean", "required": "False"},
            "include_fsso": {"type": "boolean", "required": "False"},
        },
    },
    "user_banned": {"url": "user/banned", "params": {}},
    "user_fortitoken": {"url": "user/fortitoken", "params": {}},
    "user_detected-device": {
        "url": "user/detected-device",
        "params": {
            "expand_child_macs": {"type": "boolean", "required": "False"},
            "with_dhcp": {"type": "boolean", "required": "False"},
            "with_endpoint": {"type": "boolean", "required": "False"},
            "with_fortilink": {"type": "boolean", "required": "False"},
            "with_fortiap": {"type": "boolean", "required": "False"},
            "with_user": {"type": "boolean", "required": "False"},
        },
    },
    "user_device": {
        "url": "user/device",
        "params": {
            "master_only": {"type": "boolean", "required": "False"},
            "master_mac": {"type": "string", "required": "False"},
        },
    },
    "user_device-type": {"url": "user/device-type", "params": {}},
    "user_device-category": {"url": "user/device-category", "params": {}},
    "user_fsso": {"url": "user/fsso", "params": {}},
    "utm_rating-lookup": {
        "url": "utm/rating-lookup",
        "params": {"url": {"type": "array", "required": "False"}},
    },
    "utm_app-lookup": {
        "url": "utm/app-lookup",
        "params": {"hosts": {"type": "array", "required": "False"}},
    },
    "utm_application-categories": {"url": "utm/application-categories", "params": {}},
    "utm_antivirus_stats": {"url": "utm/antivirus/stats", "params": {}},
    "virtual-wan_health-check": {
        "url": "virtual-wan/health-check",
        "params": {"health_check_name": {"type": "string", "required": "False"}},
    },
    "virtual-wan_members": {
        "url": "virtual-wan/members",
        "params": {
            "interface": {"type": "array", "required": "False"},
            "zone": {"type": "string", "required": "False"},
            "sla": {"type": "string", "required": "False"},
            "skip_vpn_child": {"type": "boolean", "required": "False"},
        },
    },
    "webfilter_override": {"url": "webfilter/override", "params": {}},
    "webfilter_malicious-urls": {"url": "webfilter/malicious-urls", "params": {}},
    "webfilter_malicious-urls_stat": {
        "url": "webfilter/malicious-urls/stat",
        "params": {},
    },
    "webfilter_category-quota": {
        "url": "webfilter/category-quota",
        "params": {
            "profile": {"type": "string", "required": "False"},
            "user": {"type": "string", "required": "False"},
        },
    },
    "webfilter_fortiguard-categories": {
        "url": "webfilter/fortiguard-categories",
        "params": {
            "include_unrated": {"type": "boolean", "required": "False"},
            "convert_unrated_id": {"type": "boolean", "required": "False"},
        },
    },
    "webfilter_trusted-urls": {"url": "webfilter/trusted-urls", "params": {}},
    "vpn_ipsec": {
        "url": "vpn/ipsec",
        "params": {"tunnel": {"type": "string", "required": "False"}},
    },
    "vpn_one-click_members": {"url": "vpn/one-click/members", "params": {}},
    "vpn_one-click_status": {"url": "vpn/one-click/status", "params": {}},
    "vpn_ssl": {"url": "vpn/ssl", "params": {}},
    "vpn_ssl_stats": {"url": "vpn/ssl/stats", "params": {}},
    "wanopt_history": {
        "url": "wanopt/history",
        "params": {"period": {"type": "string", "required": "False"}},
    },
    "wanopt_webcache": {
        "url": "wanopt/webcache",
        "params": {"period": {"type": "string", "required": "False"}},
    },
    "wanopt_peer_stats": {"url": "wanopt/peer_stats", "params": {}},
    "webproxy_pacfile_download": {"url": "webproxy/pacfile/download", "params": {}},
    "webcache_stats": {
        "url": "webcache/stats",
        "params": {"period": {"type": "string", "required": "False"}},
    },
    "wifi_client": {
        "url": "wifi/client",
        "params": {
            "type": {"type": "string", "required": "False"},
            "with_triangulation": {"type": "boolean", "required": "False"},
            "with_stats": {"type": "boolean", "required": "False"},
            "mac": {"type": "string", "required": "False"},
        },
    },
    "wifi_managed_ap": {
        "url": "wifi/managed_ap",
        "params": {
            "wtp_id": {"type": "string", "required": "False"},
            "incl_local": {"type": "boolean", "required": "False"},
            "skip_eos": {"type": "boolean", "required": "False"},
        },
    },
    "wifi_firmware": {
        "url": "wifi/firmware",
        "params": {
            "timeout": {"type": "int", "required": "False"},
            "version": {"type": "object", "required": "False"},
        },
    },
    "wifi_ap_status": {"url": "wifi/ap_status", "params": {}},
    "wifi_interfering_ap": {
        "url": "wifi/interfering_ap",
        "params": {
            "wtp": {"type": "string", "required": "False"},
            "radio": {"type": "int", "required": "False"},
        },
    },
    "wifi_euclid": {"url": "wifi/euclid", "params": {}},
    "wifi_rogue_ap": {
        "url": "wifi/rogue_ap",
        "params": {"managed_ssid_only": {"type": "boolean", "required": "False"}},
    },
    "wifi_spectrum": {
        "url": "wifi/spectrum",
        "params": {"wtp_id": {"type": "string", "required": "True"}},
    },
    "endpoint-control_summary": {"url": "endpoint-control/summary", "params": {}},
    "endpoint-control_ems_status": {
        "url": "endpoint-control/ems/status",
        "params": {
            "ems_id": {"type": "int", "required": "False"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "firewall_consolidated-policy": {
        "url": "firewall/consolidated-policy",
        "params": {"policyid": {"type": "int", "required": "False"}},
    },
    "firewall_security-policy": {
        "url": "firewall/security-policy",
        "params": {"policyid": {"type": "int", "required": "False"}},
    },
    "firewall_uuid-list": {"url": "firewall/uuid-list", "params": {}},
    "firewall_uuid-type-lookup": {
        "url": "firewall/uuid-type-lookup",
        "params": {"uuids": {"type": "array", "required": "False"}},
    },
    "fortiguard_redirect-portal": {"url": "fortiguard/redirect-portal", "params": {}},
    "firewall_sdn-connector-filters": {
        "url": "firewall/sdn-connector-filters",
        "params": {"connector": {"type": "string", "required": "True"}},
    },
    "fortiview_sandbox-file-list": {"url": "fortiview/sandbox-file-list", "params": {}},
    "ips_metadata": {"url": "ips/metadata", "params": {}},
    "ips_anomaly": {"url": "ips/anomaly", "params": {}},
    "license_fortianalyzer-status": {
        "url": "license/fortianalyzer-status",
        "params": {},
    },
    "log_forticloud-report-list": {"url": "log/forticloud-report-list", "params": {}},
    "log_local-report-list": {"url": "log/local-report-list", "params": {}},
    "log_local-report_download": {
        "url": "log/local-report/download",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "layout": {"type": "string", "required": "False"},
        },
    },
    "network_lldp_neighbors": {
        "url": "network/lldp/neighbors",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "port": {"type": "string", "required": "False"},
        },
    },
    "network_lldp_ports": {
        "url": "network/lldp/ports",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "network_dns_latency": {"url": "network/dns/latency", "params": {}},
    "network_fortiguard_live-services-latency": {
        "url": "network/fortiguard/live-services-latency",
        "params": {},
    },
    "network_ddns_servers": {"url": "network/ddns/servers", "params": {}},
    "network_ddns_lookup": {
        "url": "network/ddns/lookup",
        "params": {"domain": {"type": "string", "required": "True"}},
    },
    "router_lookup-policy": {
        "url": "router/lookup-policy",
        "params": {
            "ipv6": {"type": "boolean", "required": "False"},
            "destination": {"type": "string", "required": "True"},
            "source": {"type": "string", "required": "False"},
            "destination_port": {"type": "int", "required": "False"},
            "source_port": {"type": "int", "required": "False"},
            "interface_name": {"type": "string", "required": "False"},
            "protocol_number": {"type": "int", "required": "False"},
        },
    },
    "system_config-script": {"url": "system/config-script", "params": {}},
    "system_config-sync_status": {"url": "system/config-sync/status", "params": {}},
    "system_vdom-link": {
        "url": "system/vdom-link",
        "params": {"scope": {"type": "string", "required": "False"}},
    },
    "switch-controller_managed-switch_transceivers": {
        "url": "switch-controller/managed-switch/transceivers",
        "params": {},
    },
    "system_interface_poe": {
        "url": "system/interface/poe",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "system_trusted-cert-authorities": {
        "url": "system/trusted-cert-authorities",
        "params": {"scope": {"type": "string", "required": "False"}},
    },
    "system_sandbox_cloud-regions": {
        "url": "system/sandbox/cloud-regions",
        "params": {},
    },
    "system_interface_transceivers": {
        "url": "system/interface/transceivers",
        "params": {"scope": {"type": "string", "required": "False"}},
    },
    "system_vm-information": {"url": "system/vm-information", "params": {}},
    "system_security-rating_supported-reports": {
        "url": "system/security-rating/supported-reports",
        "params": {},
    },
    "nsx_service_status": {
        "url": "nsx/service/status",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "nsx_instance": {
        "url": "nsx/instance",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "system_sdn-connector_nsx-security-tags": {
        "url": "system/sdn-connector/nsx-security-tags",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "web-ui_custom-language_download": {
        "url": "web-ui/custom-language/download",
        "params": {"lang_name": {"type": "string", "required": "True"}},
    },
    "user_collected-email": {
        "url": "user/collected-email",
        "params": {"ipv6": {"type": "boolean", "required": "False"}},
    },
    "user_info_query": {
        "url": "user/info/query",
        "params": {
            "timestamp_from": {"type": "int", "required": "False"},
            "timestamp_to": {"type": "int", "required": "False"},
            "filters": {"type": "array", "required": "False"},
            "query_type": {"type": "string", "required": "False"},
            "query_id": {"type": "int", "required": "False"},
            "cache_query": {"type": "boolean", "required": "False"},
            "key_only": {"type": "boolean", "required": "False"},
            "filter_logic": {"type": "string", "required": "False"},
            "total_only": {"type": "boolean", "required": "False"},
        },
    },
    "user_info_thumbnail": {
        "url": "user/info/thumbnail",
        "params": {"filters": {"type": "array", "required": "True"}},
    },
    "utm_blacklisted-certificates": {
        "url": "utm/blacklisted-certificates",
        "params": {
            "start": {"type": "int", "required": "True"},
            "count": {"type": "int", "required": "True"},
        },
    },
    "utm_blacklisted-certificates_statistics": {
        "url": "utm/blacklisted-certificates/statistics",
        "params": {},
    },
    "virtual-wan_interface-log": {
        "url": "virtual-wan/interface-log",
        "params": {
            "interface": {"type": "string", "required": "False"},
            "since": {"type": "int", "required": "False"},
            "seconds": {"type": "int", "required": "False"},
        },
    },
    "virtual-wan_sla-log": {
        "url": "virtual-wan/sla-log",
        "params": {
            "sla": {"type": "array", "required": "False"},
            "interface": {"type": "string", "required": "False"},
            "since": {"type": "int", "required": "False"},
            "seconds": {"type": "int", "required": "False"},
            "latest": {"type": "boolean", "required": "False"},
            "min_sample_interval": {"type": "int", "required": "False"},
            "sampling_interval": {"type": "int", "required": "False"},
            "skip_vpn_child": {"type": "boolean", "required": "False"},
            "include_sla_targets_met": {"type": "boolean", "required": "False"},
        },
    },
    "vpn_ocvpn_members": {"url": "vpn/ocvpn/members", "params": {}},
    "vpn_ocvpn_status": {"url": "vpn/ocvpn/status", "params": {}},
    "vpn_ocvpn_meta": {"url": "vpn/ocvpn/meta", "params": {}},
    "wifi_network_list": {"url": "wifi/network/list", "params": {}},
    "wifi_network_status": {"url": "wifi/network/status", "params": {}},
    "wifi_region-image": {
        "url": "wifi/region-image",
        "params": {"region_name": {"type": "string", "required": "True"}},
    },
    "azure_application-list": {"url": "azure/application-list", "params": {}},
    "endpoint-control_ems_cert-status": {
        "url": "endpoint-control/ems/cert-status",
        "params": {
            "ems_id": {"type": "int", "required": "True"},
            "scope": {"type": "string", "required": "False"},
            "with_cert": {"type": "boolean", "required": "False"},
        },
    },
    "endpoint-control_ems_status-summary": {
        "url": "endpoint-control/ems/status-summary",
        "params": {"scope": {"type": "string", "required": "False"}},
    },
    "fortiguard_service-communication-stats": {
        "url": "fortiguard/service-communication-stats",
        "params": {
            "service_type": {"type": "string", "required": "False"},
            "timeslot": {"type": "string", "required": "False"},
        },
    },
    "network_reverse-ip-lookup": {
        "url": "network/reverse-ip-lookup",
        "params": {"ip": {"type": "string", "required": "True"}},
    },
    "registration_forticloud_device-status": {
        "url": "registration/forticloud/device-status",
        "params": {
            "serials": {"type": "array", "required": "True"},
            "update_cache": {"type": "boolean", "required": "False"},
        },
    },
    "switch-controller_managed-switch_health": {
        "url": "switch-controller/managed-switch/health",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "switch-controller_managed-switch_cable-status": {
        "url": "switch-controller/managed-switch/cable-status",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "port": {"type": "string", "required": "True"},
        },
    },
    "switch-controller_mclag-icl_eligible-peer": {
        "url": "switch-controller/mclag-icl/eligible-peer",
        "params": {"fortilink": {"type": "string", "required": "True"}},
    },
    "system_interface_speed-test-status": {
        "url": "system/interface/speed-test-status",
        "params": {"id": {"type": "int", "required": "True"}},
    },
    "user_fortitoken-cloud_status": {
        "url": "user/fortitoken-cloud/status",
        "params": {},
    },
    "wifi_vlan-probe": {
        "url": "wifi/vlan-probe",
        "params": {
            "ap_interface": {"type": "int", "required": "True"},
            "wtp": {"type": "string", "required": "True"},
        },
    },
    "firewall_ippool_mapping": {
        "url": "firewall/ippool/mapping",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "network_arp": {"url": "network/arp", "params": {}},
    "system_interface-connected-admins-info": {
        "url": "system/interface-connected-admins-info",
        "params": {"interface": {"type": "string", "required": "True"}},
    },
    "system_ntp_status": {"url": "system/ntp/status", "params": {}},
    "system_config-error-log_download": {
        "url": "system/config-error-log/download",
        "params": {},
    },
    "system_running-processes": {"url": "system/running-processes", "params": {}},
    "user_device_query": {
        "url": "user/device/query",
        "params": {
            "timestamp_from": {"type": "int", "required": "False"},
            "timestamp_to": {"type": "int", "required": "False"},
            "filters": {"type": "array", "required": "False"},
            "query_type": {"type": "string", "required": "False"},
            "view_type": {"type": "string", "required": "False"},
            "query_id": {"type": "int", "required": "False"},
            "cache_query": {"type": "boolean", "required": "False"},
            "key_only": {"type": "boolean", "required": "False"},
            "filter_logic": {"type": "string", "required": "False"},
            "total_only": {"type": "boolean", "required": "False"},
        },
    },
    "ips_exceed-scan-range": {
        "url": "ips/exceed-scan-range",
        "params": {"ids": {"type": "array", "required": "True"}},
    },
    "firewall_multicast-policy": {
        "url": "firewall/multicast-policy",
        "params": {"policyid": {"type": "int", "required": "False"}},
    },
    "firewall_multicast-policy6": {
        "url": "firewall/multicast-policy6",
        "params": {"policyid": {"type": "int", "required": "False"}},
    },
    "firewall_gtp-statistics": {"url": "firewall/gtp-statistics", "params": {}},
    "firewall_gtp-runtime-statistics": {
        "url": "firewall/gtp-runtime-statistics",
        "params": {},
    },
    "router_bgp_neighbors": {"url": "router/bgp/neighbors", "params": {}},
    "router_bgp_neighbors6": {"url": "router/bgp/neighbors6", "params": {}},
    "router_bgp_paths": {"url": "router/bgp/paths", "params": {}},
    "router_bgp_paths6": {"url": "router/bgp/paths6", "params": {}},
    "router_ospf_neighbors": {"url": "router/ospf/neighbors", "params": {}},
    "system_automation-action_stats": {
        "url": "system/automation-action/stats",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "switch-controller_matched-devices": {
        "url": "switch-controller/matched-devices",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "include_dynamic": {"type": "boolean", "required": "False"},
            "mac": {"type": "string", "required": "False"},
        },
    },
    "system_ha-table-checksums": {
        "url": "system/ha-table-checksums",
        "params": {
            "serial_no": {"type": "string", "required": "True"},
            "vdom_name": {"type": "string", "required": "False"},
        },
    },
    "system_sandbox_connection": {
        "url": "system/sandbox/connection",
        "params": {"server": {"type": "string", "required": "False"}},
    },
    "system_traffic-history_interface": {
        "url": "system/traffic-history/interface",
        "params": {
            "interface": {"type": "string", "required": "True"},
            "time_period": {"type": "string", "required": "True"},
        },
    },
    "system_traffic-history_top-applications": {
        "url": "system/traffic-history/top-applications",
        "params": {"time_period": {"type": "string", "required": "True"}},
    },
    "videofilter_fortiguard-categories": {
        "url": "videofilter/fortiguard-categories",
        "params": {},
    },
    "firewall_central-snat-map": {
        "url": "firewall/central-snat-map",
        "params": {
            "policyid": {"type": "int", "required": "False"},
            "ip_version": {"type": "string", "required": "False"},
        },
    },
    "firewall_dnat": {
        "url": "firewall/dnat",
        "params": {
            "uuid": {"type": "array", "required": "False"},
            "ip_version": {"type": "string", "required": "False"},
        },
    },
    "ips_hold-signatures": {
        "url": "ips/hold-signatures",
        "params": {"ips_sensor": {"type": "string", "required": "False"}},
    },
    "router_bgp_paths-statistics": {
        "url": "router/bgp/paths-statistics",
        "params": {"ip_version": {"type": "string", "required": "False"}},
    },
    "system_lte-modem_status": {"url": "system/lte-modem/status", "params": {}},
    "system_global-search": {
        "url": "system/global-search",
        "params": {
            "search": {"type": "string", "required": "True"},
            "scope": {"type": "string", "required": "False"},
            "search_tables": {"type": "array", "required": "False"},
            "skip_tables": {"type": "array", "required": "False"},
            "exact": {"type": "boolean", "required": "False"},
        },
    },
    "switch-controller_managed-switch_status": {
        "url": "switch-controller/managed-switch/status",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "switch-controller_managed-switch_port-stats": {
        "url": "switch-controller/managed-switch/port-stats",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "switch-controller_managed-switch_models": {
        "url": "switch-controller/managed-switch/models",
        "params": {},
    },
    "system_interface_kernel-interfaces": {
        "url": "system/interface/kernel-interfaces",
        "params": {},
    },
    "system_config_restore-status": {
        "url": "system/config/restore-status",
        "params": {"session_id": {"type": "string", "required": "True"}},
    },
    "wifi_meta": {"url": "wifi/meta", "params": {}},
    "wifi_ap_channels": {
        "url": "wifi/ap_channels",
        "params": {
            "country": {"type": "string", "required": "False"},
            "platform_type": {"type": "string", "required": "True"},
            "indoor_outdoor": {"type": "int", "required": "False"},
        },
    },
    "wifi_ap-names": {"url": "wifi/ap-names", "params": {}},
    "firewall_internet-service-reputation": {
        "url": "firewall/internet-service-reputation",
        "params": {
            "ip": {"type": "string", "required": "True"},
            "is_ipv6": {"type": "boolean", "required": "False"},
        },
    },
    "firewall_shaper_multi-class-shaper": {
        "url": "firewall/shaper/multi-class-shaper",
        "params": {},
    },
    "log_forticloud_connection": {"url": "log/forticloud/connection", "params": {}},
    "system_performance_status": {"url": "system/performance/status", "params": {}},
    "system_ipam_list": {"url": "system/ipam/list", "params": {}},
    "system_ipam_status": {"url": "system/ipam/status", "params": {}},
    "system_acme-certificate-status": {
        "url": "system/acme-certificate-status",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "system_crash-log_download": {"url": "system/crash-log/download", "params": {}},
    "user_banned_check": {
        "url": "user/banned/check",
        "params": {"ip_address": {"type": "string", "required": "True"}},
    },
    "user_info_thumbnail-file": {
        "url": "user/info/thumbnail-file",
        "params": {"filename": {"type": "string", "required": "True"}},
    },
    "vpn-certificate_cert-name-available": {
        "url": "vpn-certificate/cert-name-available",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "wifi_unassociated-devices": {
        "url": "wifi/unassociated-devices",
        "params": {"with_triangulation": {"type": "boolean", "required": "False"}},
    },
    "wifi_matched-devices": {
        "url": "wifi/matched-devices",
        "params": {"mac": {"type": "string", "required": "False"}},
    },
    "firewall_proxy_sessions": {
        "url": "firewall/proxy/sessions",
        "params": {
            "ip_version": {"type": "string", "required": "False"},
            "count": {"type": "int", "required": "True"},
            "summary": {"type": "boolean", "required": "False"},
            "srcaddr": {"type": "object", "required": "False"},
            "dstaddr": {"type": "object", "required": "False"},
            "srcaddr6": {"type": "object", "required": "False"},
            "dstaddr6": {"type": "object", "required": "False"},
            "srcport": {"type": "object", "required": "False"},
            "dstport": {"type": "object", "required": "False"},
            "srcintf": {"type": "object", "required": "False"},
            "dstintf": {"type": "object", "required": "False"},
            "policyid": {"type": "object", "required": "False"},
            "proxy-policyid": {"type": "object", "required": "False"},
            "protocol": {"type": "object", "required": "False"},
            "application": {"type": "object", "required": "False"},
            "country": {"type": "object", "required": "False"},
            "seconds": {"type": "object", "required": "False"},
            "since": {"type": "object", "required": "False"},
            "owner": {"type": "object", "required": "False"},
            "username": {"type": "object", "required": "False"},
            "src_uuid": {"type": "object", "required": "False"},
            "dst_uuid": {"type": "object", "required": "False"},
        },
    },
    "firewall_gtp": {"url": "firewall/gtp", "params": {}},
    "fortiview_proxy-statistics": {
        "url": "fortiview/proxy-statistics",
        "params": {
            "report_by": {"type": "string", "required": "False"},
            "sort_by": {"type": "string", "required": "False"},
            "count": {"type": "int", "required": "False"},
            "ip_version": {"type": "string", "required": "False"},
            "srcaddr": {"type": "object", "required": "False"},
            "dstaddr": {"type": "object", "required": "False"},
            "srcaddr6": {"type": "object", "required": "False"},
            "dstaddr6": {"type": "object", "required": "False"},
            "srcport": {"type": "object", "required": "False"},
            "dstport": {"type": "object", "required": "False"},
            "srcintf": {"type": "object", "required": "False"},
            "dstintf": {"type": "object", "required": "False"},
            "policyid": {"type": "object", "required": "False"},
            "proxy-policyid": {"type": "object", "required": "False"},
            "protocol": {"type": "object", "required": "False"},
            "application": {"type": "object", "required": "False"},
            "country": {"type": "object", "required": "False"},
            "seconds": {"type": "object", "required": "False"},
            "since": {"type": "object", "required": "False"},
            "owner": {"type": "object", "required": "False"},
            "username": {"type": "object", "required": "False"},
            "srcuuid": {"type": "object", "required": "False"},
            "dstuuid": {"type": "object", "required": "False"},
        },
    },
    "system_ha-hw-interface": {"url": "system/ha-hw-interface", "params": {}},
    "user_firewall_count": {
        "url": "user/firewall/count",
        "params": {
            "ipv4": {"type": "boolean", "required": "False"},
            "ipv6": {"type": "boolean", "required": "False"},
            "include_fsso": {"type": "boolean", "required": "False"},
        },
    },
    "firewall_internet-service-basic": {
        "url": "firewall/internet-service-basic",
        "params": {"ipv6_only": {"type": "boolean", "required": "False"}},
    },
    "firewall_vip-overlap": {"url": "firewall/vip-overlap", "params": {}},
    "switch-controller_managed-switch_port-health": {
        "url": "switch-controller/managed-switch/port-health",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "switch-controller_managed-switch_tx-rx": {
        "url": "switch-controller/managed-switch/tx-rx",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "port": {"type": "string", "required": "True"},
        },
    },
    "firewall_network-service-dynamic": {
        "url": "firewall/network-service-dynamic",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "system_ipam_utilization": {"url": "system/ipam/utilization", "params": {}},
    "system_ha-nonsync-checksums": {"url": "system/ha-nonsync-checksums", "params": {}},
    "wifi_station-capability": {
        "url": "wifi/station-capability",
        "params": {
            "mac_address": {"type": "string", "required": "False"},
            "min_age": {"type": "int", "required": "False"},
            "max_age": {"type": "int", "required": "False"},
        },
    },
    "fortiguard_answers": {
        "url": "fortiguard/answers",
        "params": {
            "page": {"type": "int", "required": "False"},
            "pagesize": {"type": "int", "required": "False"},
            "sortkey": {"type": "string", "required": "False"},
            "topics": {"type": "string", "required": "False"},
            "limit": {"type": "int", "required": "False"},
        },
    },
    "ips_session_performance": {"url": "ips/session/performance", "params": {}},
    "switch-controller_nac-device_stats": {
        "url": "switch-controller/nac-device/stats",
        "params": {},
    },
    "switch-controller_isl-lockdown_status": {
        "url": "switch-controller/isl-lockdown/status",
        "params": {"fortilink": {"type": "string", "required": "True"}},
    },
    "wifi_nac-device_stats": {"url": "wifi/nac-device/stats", "params": {}},
    "firewall_sessions": {
        "url": "firewall/sessions",
        "params": {
            "ip_version": {"type": "string", "required": "False"},
            "count": {"type": "int", "required": "True"},
            "summary": {"type": "boolean", "required": "False"},
            "srcport": {"type": "object", "required": "False"},
            "policyid": {"type": "object", "required": "False"},
            "security-policyid": {"type": "object", "required": "False"},
            "application": {"type": "object", "required": "False"},
            "protocol": {"type": "object", "required": "False"},
            "dstport": {"type": "object", "required": "False"},
            "srcintf": {"type": "object", "required": "False"},
            "dstintf": {"type": "object", "required": "False"},
            "srcintfrole": {"type": "array", "required": "False"},
            "dstintfrole": {"type": "array", "required": "False"},
            "srcaddr": {"type": "object", "required": "False"},
            "srcaddr6": {"type": "object", "required": "False"},
            "srcuuid": {"type": "object", "required": "False"},
            "dstaddr": {"type": "object", "required": "False"},
            "dstaddr6": {"type": "object", "required": "False"},
            "dstuuid": {"type": "object", "required": "False"},
            "username": {"type": "object", "required": "False"},
            "shaper": {"type": "object", "required": "False"},
            "country": {"type": "object", "required": "False"},
            "owner": {"type": "object", "required": "False"},
            "natsourceaddress": {"type": "object", "required": "False"},
            "natsourceport": {"type": "object", "required": "False"},
            "since": {"type": "object", "required": "False"},
            "seconds": {"type": "object", "required": "False"},
            "fortiasic": {"type": "object", "required": "False"},
            "nturbo": {"type": "object", "required": "False"},
        },
    },
    "fortiview_realtime-statistics": {
        "url": "fortiview/realtime-statistics",
        "params": {
            "srcaddr": {"type": "object", "required": "False"},
            "dstaddr": {"type": "object", "required": "False"},
            "srcaddr6": {"type": "object", "required": "False"},
            "dstaddr6": {"type": "object", "required": "False"},
            "srcport": {"type": "object", "required": "False"},
            "dstport": {"type": "object", "required": "False"},
            "srcintf": {"type": "object", "required": "False"},
            "srcintfrole": {"type": "array", "required": "False"},
            "dstintf": {"type": "object", "required": "False"},
            "dstintfrole": {"type": "array", "required": "False"},
            "policyid": {"type": "object", "required": "False"},
            "security-policyid": {"type": "object", "required": "False"},
            "protocol": {"type": "object", "required": "False"},
            "web-category": {"type": "object", "required": "False"},
            "web-domain": {"type": "object", "required": "False"},
            "application": {"type": "object", "required": "False"},
            "country": {"type": "object", "required": "False"},
            "seconds": {"type": "object", "required": "False"},
            "since": {"type": "object", "required": "False"},
            "owner": {"type": "object", "required": "False"},
            "username": {"type": "object", "required": "False"},
            "shaper": {"type": "object", "required": "False"},
            "srcuuid": {"type": "object", "required": "False"},
            "dstuuid": {"type": "object", "required": "False"},
            "sessionid": {"type": "int", "required": "False"},
            "report_by": {"type": "string", "required": "False"},
            "sort_by": {"type": "string", "required": "False"},
            "ip_version": {"type": "string", "required": "False"},
        },
    },
    "fortiview_historical-statistics": {
        "url": "fortiview/historical-statistics",
        "params": {
            "filter": {"type": "object", "required": "False"},
            "sessionid": {"type": "int", "required": "False"},
            "device": {"type": "string", "required": "False"},
            "report_by": {"type": "string", "required": "False"},
            "sort_by": {"type": "string", "required": "False"},
            "chart_only": {"type": "boolean", "required": "False"},
            "end": {"type": "int", "required": "False"},
            "ip_version": {"type": "string", "required": "False"},
        },
    },
    "fortiview_realtime-proxy-statistics": {
        "url": "fortiview/realtime-proxy-statistics",
        "params": {
            "report_by": {"type": "string", "required": "False"},
            "sort_by": {"type": "string", "required": "False"},
            "ip_version": {"type": "string", "required": "False"},
            "srcaddr": {"type": "object", "required": "False"},
            "dstaddr": {"type": "object", "required": "False"},
            "srcaddr6": {"type": "object", "required": "False"},
            "dstaddr6": {"type": "object", "required": "False"},
            "srcport": {"type": "object", "required": "False"},
            "dstport": {"type": "object", "required": "False"},
            "srcintf": {"type": "object", "required": "False"},
            "dstintf": {"type": "object", "required": "False"},
            "policyid": {"type": "object", "required": "False"},
            "proxy-policyid": {"type": "object", "required": "False"},
            "protocol": {"type": "object", "required": "False"},
            "application": {"type": "object", "required": "False"},
            "country": {"type": "object", "required": "False"},
            "seconds": {"type": "object", "required": "False"},
            "since": {"type": "object", "required": "False"},
            "owner": {"type": "object", "required": "False"},
            "username": {"type": "object", "required": "False"},
            "srcuuid": {"type": "object", "required": "False"},
            "dstuuid": {"type": "object", "required": "False"},
        },
    },
    "log_feature-set": {"url": "log/feature-set", "params": {}},
    "forticonverter_eligibility": {"url": "forticonverter/eligibility", "params": {}},
    "forticonverter_ticket_status": {
        "url": "forticonverter/ticket/status",
        "params": {},
    },
    "forticonverter_sn-list": {
        "url": "forticonverter/sn-list",
        "params": {"ticket_id": {"type": "string", "required": "True"}},
    },
    "forticonverter_intf-list": {
        "url": "forticonverter/intf-list",
        "params": {"ticket_id": {"type": "string", "required": "True"}},
    },
    "forticonverter_custom-operation_status": {
        "url": "forticonverter/custom-operation/status",
        "params": {"id": {"type": "int", "required": "True"}},
    },
    "forticonverter_intf-mapping": {
        "url": "forticonverter/intf-mapping",
        "params": {"ticket_id": {"type": "string", "required": "True"}},
    },
    "forticonverter_mgmt-intf": {
        "url": "forticonverter/mgmt-intf",
        "params": {"ticket_id": {"type": "string", "required": "True"}},
    },
    "forticonverter_notes": {
        "url": "forticonverter/notes",
        "params": {"ticket_id": {"type": "string", "required": "True"}},
    },
    "forticonverter_download_ready": {
        "url": "forticonverter/download/ready",
        "params": {
            "ticket_id": {"type": "string", "required": "True"},
            "extension": {"type": "string", "required": "True"},
        },
    },
    "forticonverter_file_download": {
        "url": "forticonverter/file/download",
        "params": {
            "ticket_id": {"type": "string", "required": "True"},
            "extension": {"type": "string", "required": "True"},
        },
    },
    "forticonverter_download_status": {
        "url": "forticonverter/download/status",
        "params": {
            "ticket_id": {"type": "string", "required": "True"},
            "extension": {"type": "string", "required": "True"},
        },
    },
    "switch-controller_managed-switch_bios": {
        "url": "switch-controller/managed-switch/bios",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "system_available-interfaces_meta": {
        "url": "system/available-interfaces/meta",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "include_ha": {"type": "boolean", "required": "False"},
        },
    },
    "system_central-management_status": {
        "url": "system/central-management/status",
        "params": {"skip_detect": {"type": "boolean", "required": "False"}},
    },
    "user_device_stats": {
        "url": "user/device/stats",
        "params": {
            "stat-query-type": {"type": "string", "required": "False"},
            "stat-key": {"type": "string", "required": "True"},
            "timestamp_from": {"type": "int", "required": "False"},
            "timestamp_to": {"type": "int", "required": "True"},
            "filters": {"type": "array", "required": "False"},
            "filter_logic": {"type": "string", "required": "False"},
        },
    },
    "casb_saas-application_details": {
        "url": "casb/saas-application/details",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "switch-controller_mclag-icl_tier-plus-candidates": {
        "url": "switch-controller/mclag-icl/tier-plus-candidates",
        "params": {
            "fortilink": {"type": "string", "required": "True"},
            "parent_peer1": {"type": "string", "required": "True"},
            "parent_peer2": {"type": "string", "required": "True"},
            "is_tier2": {"type": "boolean", "required": "True"},
        },
    },
    "extension-controller_fortigate": {
        "url": "extension-controller/fortigate",
        "params": {},
    },
    "extension-controller_lan-extension-vdom-status": {
        "url": "extension-controller/lan-extension-vdom-status",
        "params": {},
    },
    "user_proxy": {"url": "user/proxy", "params": {}},
    "user_proxy_count": {"url": "user/proxy/count", "params": {}},
    "firewall_check-addrgrp-exclude-mac-member": {
        "url": "firewall/check-addrgrp-exclude-mac-member",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "ip_version": {"type": "string", "required": "False"},
        },
    },
    "firewall_saas-application": {"url": "firewall/saas-application", "params": {}},
    "router_sdwan_routes": {"url": "router/sdwan/routes", "params": {}},
    "router_sdwan_routes6": {"url": "router/sdwan/routes6", "params": {}},
    "router_sdwan_routes-statistics": {
        "url": "router/sdwan/routes-statistics",
        "params": {"ip_version": {"type": "string", "required": "False"}},
    },
    "extender-controller_extender_modem-firmware": {
        "url": "extender-controller/extender/modem-firmware",
        "params": {"serial": {"type": "string", "required": "True"}},
    },
    "user_radius_get-test-connect": {
        "url": "user/radius/get-test-connect",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "ordinal": {"type": "string", "required": "False"},
            "server": {"type": "string", "required": "False"},
            "secret": {"type": "string", "required": "False"},
            "auth_type": {"type": "string", "required": "False"},
            "user": {"type": "string", "required": "False"},
            "password": {"type": "string", "required": "False"},
        },
    },
    "endpoint-control_ems_malware-hash": {
        "url": "endpoint-control/ems/malware-hash",
        "params": {},
    },
    "switch-controller_managed-switch_health-status": {
        "url": "switch-controller/managed-switch/health-status",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "serial": {"type": "string", "required": "False"},
        },
    },
    "firewall_local-in6": {"url": "firewall/local-in6", "params": {}},
    "firmware_extension-device": {
        "url": "firmware/extension-device",
        "params": {
            "type": {"type": "string", "required": "True"},
            "timeout": {"type": "int", "required": "False"},
            "version": {"type": "object", "required": "False"},
        },
    },
    "service_ldap_query": {
        "url": "service/ldap/query",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "server_info_only": {"type": "boolean", "required": "False"},
            "skip_schema": {"type": "boolean", "required": "False"},
            "ldap_filter": {"type": "string", "required": "False"},
            "ldap": {"type": "object", "required": "False"},
        },
    },
    "router_bgp_neighbors-statistics": {
        "url": "router/bgp/neighbors-statistics",
        "params": {"ip_version": {"type": "string", "required": "False"}},
    },
    "router_lookup_ha-peer": {
        "url": "router/lookup/ha-peer",
        "params": {
            "serial": {"type": "string", "required": "True"},
            "ipv6": {"type": "boolean", "required": "False"},
            "destination": {"type": "string", "required": "True"},
        },
    },
    "system_cluster_state": {"url": "system/cluster/state", "params": {}},
    "system_upgrade-report_exists": {
        "url": "system/upgrade-report/exists",
        "params": {},
    },
    "system_upgrade-report_saved": {"url": "system/upgrade-report/saved", "params": {}},
    "system_upgrade-report_current": {
        "url": "system/upgrade-report/current",
        "params": {},
    },
    "system_ha-backup-hb-used": {"url": "system/ha-backup-hb-used", "params": {}},
    "system_external-resource_validate-jsonpath": {
        "url": "system/external-resource/validate-jsonpath",
        "params": {"path_name": {"type": "string", "required": "True"}},
    },
    "user_scim_groups": {
        "url": "user/scim/groups",
        "params": {"client_name": {"type": "string", "required": "True"}},
    },
    "virtual-wan_sladb": {"url": "virtual-wan/sladb", "params": {}},
    "wifi_statistics": {"url": "wifi/statistics", "params": {}},
    "router_charts": {
        "url": "router/charts",
        "params": {
            "operator": {"type": "string", "required": "False"},
            "ip_version": {"type": "int", "required": "False"},
            "ip_mask": {"type": "string", "required": "False"},
            "gateway": {"type": "string", "required": "False"},
            "type": {"type": "string", "required": "False"},
            "origin": {"type": "string", "required": "False"},
            "interface": {"type": "string", "required": "False"},
        },
    },
    "switch-controller_known-nac-device-criteria-list": {
        "url": "switch-controller/known-nac-device-criteria-list",
        "params": {},
    },
    "system_sandbox_detect": {"url": "system/sandbox/detect", "params": {}},
    "system_monitor-sensor": {"url": "system/monitor-sensor", "params": {}},
    "user_device_iot-query": {
        "url": "user/device/iot-query",
        "params": {
            "mac": {"type": "string", "required": "True"},
            "ip": {"type": "string", "required": "True"},
        },
    },
    "user_scim_users": {
        "url": "user/scim/users",
        "params": {
            "client_name": {"type": "string", "required": "True"},
            "group_name": {"type": "string", "required": "False"},
            "user_name": {"type": "string", "required": "False"},
        },
    },
    "telemetry-controller_agents": {"url": "telemetry-controller/agents", "params": {}},
    "telemetry-controller_agent-tasks": {
        "url": "telemetry-controller/agent-tasks",
        "params": {},
    },
    "firewall_internet-service-fqdn": {
        "url": "firewall/internet-service-fqdn",
        "params": {},
    },
    "firewall_internet-service-fqdn-icon-ids": {
        "url": "firewall/internet-service-fqdn-icon-ids",
        "params": {},
    },
    "system_5g-modem_status": {
        "url": "system/5g-modem/status",
        "params": {"modem": {"type": "string", "required": "False"}},
    },
    "system_interface_poe-usage": {"url": "system/interface/poe-usage", "params": {}},
    "vpn_ipsec_connection-count": {"url": "vpn/ipsec/connection-count", "params": {}},
}


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


def validate_parameters(params, fos):
    # parameter validation will not block task, warning will be provided in case of parameters validation.
    selector = params["selector"]
    selector_params = params.get("params", {})

    if selector not in module_selectors_defs:
        return False, {"message": "unknown selector: " + selector}

    if selector_params:
        for param_key, param_value in selector_params.items():
            if not isinstance(param_value, (bool, int, str, list)):
                return False, {
                    "message": "value of param:%s must be atomic" % (param_key)
                }

    definition = module_selectors_defs.get(selector, {})

    if not params or len(params) == 0 or len(definition) == 0:
        return True, {}

    acceptable_param_names = list(definition.get("params").keys())
    provided_param_names = list(selector_params.keys() if selector_params else [])

    params_valid = True
    for param_name in acceptable_param_names:
        if param_name not in provided_param_names and eval(
            module_selectors_defs[selector]["params"][param_name]["required"]
        ):
            params_valid = False
            break
    if params_valid:
        for param_name in provided_param_names:
            if param_name not in acceptable_param_names:
                params_valid = False
                break
    if not params_valid:
        param_summary = [
            "%s(%s, %s)"
            % (
                param_name,
                param["type"],
                "required" if eval(param["required"]) else "optional",
            )
            for param_name, param in module_selectors_defs[selector]["params"].items()
        ]
        fos._module.warn(
            "selector:%s expects params:%s" % (selector, str(param_summary))
        )
    return True, {}


def fortios_monitor_fact(params, fos):
    valid, result = validate_parameters(params, fos)
    if not valid:
        return True, False, result

    selector = params["selector"]

    url_params = dict()
    if params["filters"] and len(params["filters"]):
        filter_body = quote(params["filters"][0])
        for filter_item in params["filters"][1:]:
            filter_body = "%s&filter=%s" % (filter_body, quote(filter_item))
        url_params["filter"] = filter_body
    if params["sorters"] and len(params["sorters"]):
        sorter_body = params["sorters"][0]
        for sorter_item in params["sorters"][1:]:
            sorter_body = "%s&sort=%s" % (sorter_body, sorter_item)
        url_params["sort"] = sorter_body
    if params["formatters"] and len(params["formatters"]):
        formatter_body = params["formatters"][0]
        for formatter_item in params["formatters"][1:]:
            formatter_body = "%s|%s" % (formatter_body, formatter_item)
        url_params["format"] = formatter_body
    if params["params"]:
        for selector_param_key, selector_param in params["params"].items():
            url_params[selector_param_key] = selector_param

    fact = fos.monitor_get(
        module_selectors_defs[selector]["url"], params["vdom"], url_params
    )

    return not is_successful_status(fact), False, fact


def main():
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "filters": {"required": False, "type": "list", "elements": "str"},
        "sorters": {"required": False, "type": "list", "elements": "str"},
        "formatters": {"required": False, "type": "list", "elements": "str"},
        "params": {"required": False, "type": "dict"},
        "selector": {
            "required": False,
            "type": "str",
            "choices": [
                "endpoint-control_profile_xml",
                "endpoint-control_record-list",
                "endpoint-control_registration_summary",
                "endpoint-control_installer",
                "endpoint-control_installer_download",
                "endpoint-control_avatar_download",
                "firewall_health",
                "firewall_local-in",
                "firewall_acl",
                "firewall_acl6",
                "firewall_internet-service-match",
                "firewall_internet-service-details",
                "firewall_policy",
                "firewall_policy6",
                "firewall_proxy-policy",
                "firewall_policy-lookup",
                "firewall_session",
                "firewall_shaper",
                "firewall_per-ip-shaper",
                "firewall_load-balance",
                "firewall_address-fqdns",
                "firewall_address-fqdns6",
                "firewall_ippool",
                "firewall_address-dynamic",
                "firewall_address6-dynamic",
                "fortiview_statistics",
                "fortiview_sandbox-file-details",
                "geoip_geoip-query",
                "ips_rate-based",
                "license_status",
                "license_forticare-resellers",
                "license_forticare-org-list",
                "log_current-disk-usage",
                "log_device_state",
                "log_forticloud",
                "log_fortianalyzer",
                "log_fortianalyzer-queue",
                "log_hourly-disk-usage",
                "log_historic-daily-remote-logs",
                "log_stats",
                "log_forticloud-report_download",
                "log_ips-archive_download",
                "log_policy-archive_download",
                "log_av-archive_download",
                "log_event",
                "registration_forticloud_disclaimer",
                "registration_forticloud_domains",
                "router_ipv4",
                "router_ipv6",
                "router_statistics",
                "router_lookup",
                "router_policy",
                "router_policy6",
                "system_config-revision",
                "system_config-revision_file",
                "system_config-revision_info",
                "system_current-admins",
                "system_time",
                "system_global-resources",
                "system_vdom-resource",
                "system_dhcp",
                "system_firmware",
                "system_firmware_upgrade-paths",
                "system_storage",
                "system_csf",
                "system_csf_pending-authorizations",
                "system_modem",
                "system_3g-modem",
                "system_resource_usage",
                "system_sniffer",
                "system_sniffer_download",
                "system_automation-stitch_stats",
                "switch-controller_managed-switch",
                "switch-controller_managed-switch_faceplate-xml",
                "switch-controller_managed-switch_dhcp-snooping",
                "switch-controller_fsw-firmware",
                "switch-controller_detected-device",
                "switch-controller_validate-switch-prefix",
                "system_interface",
                "system_interface_dhcp-status",
                "system_available-interfaces",
                "system_acquired-dns",
                "system_resolve-fqdn",
                "system_nat46-ippools",
                "system_usb-log",
                "system_ipconf",
                "system_fortiguard_server-info",
                "system_fortimanager_status",
                "system_fortimanager_backup-summary",
                "system_fortimanager_backup-details",
                "system_available-certificates",
                "system_certificate_download",
                "system_debug_download",
                "system_com-log_update",
                "system_com-log_download",
                "system_botnet_stat",
                "system_botnet",
                "system_botnet-domains",
                "system_botnet-domains_stat",
                "system_botnet-domains_hits",
                "system_ha-statistics",
                "system_ha-history",
                "system_ha-checksums",
                "system_ha-peer",
                "system_link-monitor",
                "system_config_backup",
                "system_config_usb-filelist",
                "system_sandbox_stats",
                "system_sandbox_status",
                "system_sandbox_test-connect",
                "system_object_usage",
                "system_object-tagging_usage",
                "system_status",
                "system_timezone",
                "system_sensor-info",
                "system_security-rating",
                "system_security-rating_history",
                "system_security-rating_status",
                "system_security-rating_lang",
                "system_fortiguard-blacklist",
                "system_check-port-availability",
                "system_external-resource_entry-list",
                "extender-controller_extender",
                "system_sdn-connector_status",
                "user_firewall",
                "user_banned",
                "user_fortitoken",
                "user_detected-device",
                "user_device",
                "user_device-type",
                "user_device-category",
                "user_fsso",
                "utm_rating-lookup",
                "utm_app-lookup",
                "utm_application-categories",
                "utm_antivirus_stats",
                "virtual-wan_health-check",
                "virtual-wan_members",
                "webfilter_override",
                "webfilter_malicious-urls",
                "webfilter_malicious-urls_stat",
                "webfilter_category-quota",
                "webfilter_fortiguard-categories",
                "webfilter_trusted-urls",
                "vpn_ipsec",
                "vpn_one-click_members",
                "vpn_one-click_status",
                "vpn_ssl",
                "vpn_ssl_stats",
                "wanopt_history",
                "wanopt_webcache",
                "wanopt_peer_stats",
                "webproxy_pacfile_download",
                "webcache_stats",
                "wifi_client",
                "wifi_managed_ap",
                "wifi_firmware",
                "wifi_ap_status",
                "wifi_interfering_ap",
                "wifi_euclid",
                "wifi_rogue_ap",
                "wifi_spectrum",
                "endpoint-control_summary",
                "endpoint-control_ems_status",
                "firewall_consolidated-policy",
                "firewall_security-policy",
                "firewall_uuid-list",
                "firewall_uuid-type-lookup",
                "fortiguard_redirect-portal",
                "firewall_sdn-connector-filters",
                "fortiview_sandbox-file-list",
                "ips_metadata",
                "ips_anomaly",
                "license_fortianalyzer-status",
                "log_forticloud-report-list",
                "log_local-report-list",
                "log_local-report_download",
                "network_lldp_neighbors",
                "network_lldp_ports",
                "network_dns_latency",
                "network_fortiguard_live-services-latency",
                "network_ddns_servers",
                "network_ddns_lookup",
                "router_lookup-policy",
                "system_config-script",
                "system_config-sync_status",
                "system_vdom-link",
                "switch-controller_managed-switch_transceivers",
                "system_interface_poe",
                "system_trusted-cert-authorities",
                "system_sandbox_cloud-regions",
                "system_interface_transceivers",
                "system_vm-information",
                "system_security-rating_supported-reports",
                "nsx_service_status",
                "nsx_instance",
                "system_sdn-connector_nsx-security-tags",
                "web-ui_custom-language_download",
                "user_collected-email",
                "user_info_query",
                "user_info_thumbnail",
                "utm_blacklisted-certificates",
                "utm_blacklisted-certificates_statistics",
                "virtual-wan_interface-log",
                "virtual-wan_sla-log",
                "vpn_ocvpn_members",
                "vpn_ocvpn_status",
                "vpn_ocvpn_meta",
                "wifi_network_list",
                "wifi_network_status",
                "wifi_region-image",
                "azure_application-list",
                "endpoint-control_ems_cert-status",
                "endpoint-control_ems_status-summary",
                "fortiguard_service-communication-stats",
                "network_reverse-ip-lookup",
                "registration_forticloud_device-status",
                "switch-controller_managed-switch_health",
                "switch-controller_managed-switch_cable-status",
                "switch-controller_mclag-icl_eligible-peer",
                "system_interface_speed-test-status",
                "user_fortitoken-cloud_status",
                "wifi_vlan-probe",
                "firewall_ippool_mapping",
                "network_arp",
                "system_interface-connected-admins-info",
                "system_ntp_status",
                "system_config-error-log_download",
                "system_running-processes",
                "user_device_query",
                "ips_exceed-scan-range",
                "firewall_multicast-policy",
                "firewall_multicast-policy6",
                "firewall_gtp-statistics",
                "firewall_gtp-runtime-statistics",
                "router_bgp_neighbors",
                "router_bgp_neighbors6",
                "router_bgp_paths",
                "router_bgp_paths6",
                "router_ospf_neighbors",
                "system_automation-action_stats",
                "switch-controller_matched-devices",
                "system_ha-table-checksums",
                "system_sandbox_connection",
                "system_traffic-history_interface",
                "system_traffic-history_top-applications",
                "videofilter_fortiguard-categories",
                "firewall_central-snat-map",
                "firewall_dnat",
                "ips_hold-signatures",
                "router_bgp_paths-statistics",
                "system_lte-modem_status",
                "system_global-search",
                "switch-controller_managed-switch_status",
                "switch-controller_managed-switch_port-stats",
                "switch-controller_managed-switch_models",
                "system_interface_kernel-interfaces",
                "system_config_restore-status",
                "wifi_meta",
                "wifi_ap_channels",
                "wifi_ap-names",
                "firewall_internet-service-reputation",
                "firewall_shaper_multi-class-shaper",
                "log_forticloud_connection",
                "system_performance_status",
                "system_ipam_list",
                "system_ipam_status",
                "system_acme-certificate-status",
                "system_crash-log_download",
                "user_banned_check",
                "user_info_thumbnail-file",
                "vpn-certificate_cert-name-available",
                "wifi_unassociated-devices",
                "wifi_matched-devices",
                "firewall_proxy_sessions",
                "firewall_gtp",
                "fortiview_proxy-statistics",
                "system_ha-hw-interface",
                "user_firewall_count",
                "firewall_internet-service-basic",
                "firewall_vip-overlap",
                "switch-controller_managed-switch_port-health",
                "switch-controller_managed-switch_tx-rx",
                "firewall_network-service-dynamic",
                "system_ipam_utilization",
                "system_ha-nonsync-checksums",
                "wifi_station-capability",
                "fortiguard_answers",
                "ips_session_performance",
                "switch-controller_nac-device_stats",
                "switch-controller_isl-lockdown_status",
                "wifi_nac-device_stats",
                "firewall_sessions",
                "fortiview_realtime-statistics",
                "fortiview_historical-statistics",
                "fortiview_realtime-proxy-statistics",
                "log_feature-set",
                "forticonverter_eligibility",
                "forticonverter_ticket_status",
                "forticonverter_sn-list",
                "forticonverter_intf-list",
                "forticonverter_custom-operation_status",
                "forticonverter_intf-mapping",
                "forticonverter_mgmt-intf",
                "forticonverter_notes",
                "forticonverter_download_ready",
                "forticonverter_file_download",
                "forticonverter_download_status",
                "switch-controller_managed-switch_bios",
                "system_available-interfaces_meta",
                "system_central-management_status",
                "user_device_stats",
                "casb_saas-application_details",
                "switch-controller_mclag-icl_tier-plus-candidates",
                "extension-controller_fortigate",
                "extension-controller_lan-extension-vdom-status",
                "user_proxy",
                "user_proxy_count",
                "firewall_check-addrgrp-exclude-mac-member",
                "firewall_saas-application",
                "router_sdwan_routes",
                "router_sdwan_routes6",
                "router_sdwan_routes-statistics",
                "extender-controller_extender_modem-firmware",
                "user_radius_get-test-connect",
                "endpoint-control_ems_malware-hash",
                "switch-controller_managed-switch_health-status",
                "firewall_local-in6",
                "firmware_extension-device",
                "service_ldap_query",
                "router_bgp_neighbors-statistics",
                "router_lookup_ha-peer",
                "system_cluster_state",
                "system_upgrade-report_exists",
                "system_upgrade-report_saved",
                "system_upgrade-report_current",
                "system_ha-backup-hb-used",
                "system_external-resource_validate-jsonpath",
                "user_scim_groups",
                "virtual-wan_sladb",
                "wifi_statistics",
                "router_charts",
                "switch-controller_known-nac-device-criteria-list",
                "system_sandbox_detect",
                "system_monitor-sensor",
                "user_device_iot-query",
                "user_scim_users",
                "telemetry-controller_agents",
                "telemetry-controller_agent-tasks",
                "firewall_internet-service-fqdn",
                "firewall_internet-service-fqdn-icon-ids",
                "system_5g-modem_status",
                "system_interface_poe-usage",
                "vpn_ipsec_connection-count",
            ],
        },
        "selectors": {
            "required": False,
            "type": "list",
            "elements": "dict",
            "options": {
                "filters": {"required": False, "type": "list", "elements": "str"},
                "sorters": {"required": False, "type": "list", "elements": "str"},
                "formatters": {"required": False, "type": "list", "elements": "str"},
                "params": {"required": False, "type": "dict"},
                "selector": {
                    "required": True,
                    "type": "str",
                    "choices": [
                        "endpoint-control_profile_xml",
                        "endpoint-control_record-list",
                        "endpoint-control_registration_summary",
                        "endpoint-control_installer",
                        "endpoint-control_installer_download",
                        "endpoint-control_avatar_download",
                        "firewall_health",
                        "firewall_local-in",
                        "firewall_acl",
                        "firewall_acl6",
                        "firewall_internet-service-match",
                        "firewall_internet-service-details",
                        "firewall_policy",
                        "firewall_policy6",
                        "firewall_proxy-policy",
                        "firewall_policy-lookup",
                        "firewall_session",
                        "firewall_shaper",
                        "firewall_per-ip-shaper",
                        "firewall_load-balance",
                        "firewall_address-fqdns",
                        "firewall_address-fqdns6",
                        "firewall_ippool",
                        "firewall_address-dynamic",
                        "firewall_address6-dynamic",
                        "fortiview_statistics",
                        "fortiview_sandbox-file-details",
                        "geoip_geoip-query",
                        "ips_rate-based",
                        "license_status",
                        "license_forticare-resellers",
                        "license_forticare-org-list",
                        "log_current-disk-usage",
                        "log_device_state",
                        "log_forticloud",
                        "log_fortianalyzer",
                        "log_fortianalyzer-queue",
                        "log_hourly-disk-usage",
                        "log_historic-daily-remote-logs",
                        "log_stats",
                        "log_forticloud-report_download",
                        "log_ips-archive_download",
                        "log_policy-archive_download",
                        "log_av-archive_download",
                        "log_event",
                        "registration_forticloud_disclaimer",
                        "registration_forticloud_domains",
                        "router_ipv4",
                        "router_ipv6",
                        "router_statistics",
                        "router_lookup",
                        "router_policy",
                        "router_policy6",
                        "system_config-revision",
                        "system_config-revision_file",
                        "system_config-revision_info",
                        "system_current-admins",
                        "system_time",
                        "system_global-resources",
                        "system_vdom-resource",
                        "system_dhcp",
                        "system_firmware",
                        "system_firmware_upgrade-paths",
                        "system_storage",
                        "system_csf",
                        "system_csf_pending-authorizations",
                        "system_modem",
                        "system_3g-modem",
                        "system_resource_usage",
                        "system_sniffer",
                        "system_sniffer_download",
                        "system_automation-stitch_stats",
                        "switch-controller_managed-switch",
                        "switch-controller_managed-switch_faceplate-xml",
                        "switch-controller_managed-switch_dhcp-snooping",
                        "switch-controller_fsw-firmware",
                        "switch-controller_detected-device",
                        "switch-controller_validate-switch-prefix",
                        "system_interface",
                        "system_interface_dhcp-status",
                        "system_available-interfaces",
                        "system_acquired-dns",
                        "system_resolve-fqdn",
                        "system_nat46-ippools",
                        "system_usb-log",
                        "system_ipconf",
                        "system_fortiguard_server-info",
                        "system_fortimanager_status",
                        "system_fortimanager_backup-summary",
                        "system_fortimanager_backup-details",
                        "system_available-certificates",
                        "system_certificate_download",
                        "system_debug_download",
                        "system_com-log_update",
                        "system_com-log_download",
                        "system_botnet_stat",
                        "system_botnet",
                        "system_botnet-domains",
                        "system_botnet-domains_stat",
                        "system_botnet-domains_hits",
                        "system_ha-statistics",
                        "system_ha-history",
                        "system_ha-checksums",
                        "system_ha-peer",
                        "system_link-monitor",
                        "system_config_backup",
                        "system_config_usb-filelist",
                        "system_sandbox_stats",
                        "system_sandbox_status",
                        "system_sandbox_test-connect",
                        "system_object_usage",
                        "system_object-tagging_usage",
                        "system_status",
                        "system_timezone",
                        "system_sensor-info",
                        "system_security-rating",
                        "system_security-rating_history",
                        "system_security-rating_status",
                        "system_security-rating_lang",
                        "system_fortiguard-blacklist",
                        "system_check-port-availability",
                        "system_external-resource_entry-list",
                        "extender-controller_extender",
                        "system_sdn-connector_status",
                        "user_firewall",
                        "user_banned",
                        "user_fortitoken",
                        "user_detected-device",
                        "user_device",
                        "user_device-type",
                        "user_device-category",
                        "user_fsso",
                        "utm_rating-lookup",
                        "utm_app-lookup",
                        "utm_application-categories",
                        "utm_antivirus_stats",
                        "virtual-wan_health-check",
                        "virtual-wan_members",
                        "webfilter_override",
                        "webfilter_malicious-urls",
                        "webfilter_malicious-urls_stat",
                        "webfilter_category-quota",
                        "webfilter_fortiguard-categories",
                        "webfilter_trusted-urls",
                        "vpn_ipsec",
                        "vpn_one-click_members",
                        "vpn_one-click_status",
                        "vpn_ssl",
                        "vpn_ssl_stats",
                        "wanopt_history",
                        "wanopt_webcache",
                        "wanopt_peer_stats",
                        "webproxy_pacfile_download",
                        "webcache_stats",
                        "wifi_client",
                        "wifi_managed_ap",
                        "wifi_firmware",
                        "wifi_ap_status",
                        "wifi_interfering_ap",
                        "wifi_euclid",
                        "wifi_rogue_ap",
                        "wifi_spectrum",
                        "endpoint-control_summary",
                        "endpoint-control_ems_status",
                        "firewall_consolidated-policy",
                        "firewall_security-policy",
                        "firewall_uuid-list",
                        "firewall_uuid-type-lookup",
                        "fortiguard_redirect-portal",
                        "firewall_sdn-connector-filters",
                        "fortiview_sandbox-file-list",
                        "ips_metadata",
                        "ips_anomaly",
                        "license_fortianalyzer-status",
                        "log_forticloud-report-list",
                        "log_local-report-list",
                        "log_local-report_download",
                        "network_lldp_neighbors",
                        "network_lldp_ports",
                        "network_dns_latency",
                        "network_fortiguard_live-services-latency",
                        "network_ddns_servers",
                        "network_ddns_lookup",
                        "router_lookup-policy",
                        "system_config-script",
                        "system_config-sync_status",
                        "system_vdom-link",
                        "switch-controller_managed-switch_transceivers",
                        "system_interface_poe",
                        "system_trusted-cert-authorities",
                        "system_sandbox_cloud-regions",
                        "system_interface_transceivers",
                        "system_vm-information",
                        "system_security-rating_supported-reports",
                        "nsx_service_status",
                        "nsx_instance",
                        "system_sdn-connector_nsx-security-tags",
                        "web-ui_custom-language_download",
                        "user_collected-email",
                        "user_info_query",
                        "user_info_thumbnail",
                        "utm_blacklisted-certificates",
                        "utm_blacklisted-certificates_statistics",
                        "virtual-wan_interface-log",
                        "virtual-wan_sla-log",
                        "vpn_ocvpn_members",
                        "vpn_ocvpn_status",
                        "vpn_ocvpn_meta",
                        "wifi_network_list",
                        "wifi_network_status",
                        "wifi_region-image",
                        "azure_application-list",
                        "endpoint-control_ems_cert-status",
                        "endpoint-control_ems_status-summary",
                        "fortiguard_service-communication-stats",
                        "network_reverse-ip-lookup",
                        "registration_forticloud_device-status",
                        "switch-controller_managed-switch_health",
                        "switch-controller_managed-switch_cable-status",
                        "switch-controller_mclag-icl_eligible-peer",
                        "system_interface_speed-test-status",
                        "user_fortitoken-cloud_status",
                        "wifi_vlan-probe",
                        "firewall_ippool_mapping",
                        "network_arp",
                        "system_interface-connected-admins-info",
                        "system_ntp_status",
                        "system_config-error-log_download",
                        "system_running-processes",
                        "user_device_query",
                        "ips_exceed-scan-range",
                        "firewall_multicast-policy",
                        "firewall_multicast-policy6",
                        "firewall_gtp-statistics",
                        "firewall_gtp-runtime-statistics",
                        "router_bgp_neighbors",
                        "router_bgp_neighbors6",
                        "router_bgp_paths",
                        "router_bgp_paths6",
                        "router_ospf_neighbors",
                        "system_automation-action_stats",
                        "switch-controller_matched-devices",
                        "system_ha-table-checksums",
                        "system_sandbox_connection",
                        "system_traffic-history_interface",
                        "system_traffic-history_top-applications",
                        "videofilter_fortiguard-categories",
                        "firewall_central-snat-map",
                        "firewall_dnat",
                        "ips_hold-signatures",
                        "router_bgp_paths-statistics",
                        "system_lte-modem_status",
                        "system_global-search",
                        "switch-controller_managed-switch_status",
                        "switch-controller_managed-switch_port-stats",
                        "switch-controller_managed-switch_models",
                        "system_interface_kernel-interfaces",
                        "system_config_restore-status",
                        "wifi_meta",
                        "wifi_ap_channels",
                        "wifi_ap-names",
                        "firewall_internet-service-reputation",
                        "firewall_shaper_multi-class-shaper",
                        "log_forticloud_connection",
                        "system_performance_status",
                        "system_ipam_list",
                        "system_ipam_status",
                        "system_acme-certificate-status",
                        "system_crash-log_download",
                        "user_banned_check",
                        "user_info_thumbnail-file",
                        "vpn-certificate_cert-name-available",
                        "wifi_unassociated-devices",
                        "wifi_matched-devices",
                        "firewall_proxy_sessions",
                        "firewall_gtp",
                        "fortiview_proxy-statistics",
                        "system_ha-hw-interface",
                        "user_firewall_count",
                        "firewall_internet-service-basic",
                        "firewall_vip-overlap",
                        "switch-controller_managed-switch_port-health",
                        "switch-controller_managed-switch_tx-rx",
                        "firewall_network-service-dynamic",
                        "system_ipam_utilization",
                        "system_ha-nonsync-checksums",
                        "wifi_station-capability",
                        "fortiguard_answers",
                        "ips_session_performance",
                        "switch-controller_nac-device_stats",
                        "switch-controller_isl-lockdown_status",
                        "wifi_nac-device_stats",
                        "firewall_sessions",
                        "fortiview_realtime-statistics",
                        "fortiview_historical-statistics",
                        "fortiview_realtime-proxy-statistics",
                        "log_feature-set",
                        "forticonverter_eligibility",
                        "forticonverter_ticket_status",
                        "forticonverter_sn-list",
                        "forticonverter_intf-list",
                        "forticonverter_custom-operation_status",
                        "forticonverter_intf-mapping",
                        "forticonverter_mgmt-intf",
                        "forticonverter_notes",
                        "forticonverter_download_ready",
                        "forticonverter_file_download",
                        "forticonverter_download_status",
                        "switch-controller_managed-switch_bios",
                        "system_available-interfaces_meta",
                        "system_central-management_status",
                        "user_device_stats",
                        "casb_saas-application_details",
                        "switch-controller_mclag-icl_tier-plus-candidates",
                        "extension-controller_fortigate",
                        "extension-controller_lan-extension-vdom-status",
                        "user_proxy",
                        "user_proxy_count",
                        "firewall_check-addrgrp-exclude-mac-member",
                        "firewall_saas-application",
                        "router_sdwan_routes",
                        "router_sdwan_routes6",
                        "router_sdwan_routes-statistics",
                        "extender-controller_extender_modem-firmware",
                        "user_radius_get-test-connect",
                        "endpoint-control_ems_malware-hash",
                        "switch-controller_managed-switch_health-status",
                        "firewall_local-in6",
                        "firmware_extension-device",
                        "service_ldap_query",
                        "router_bgp_neighbors-statistics",
                        "router_lookup_ha-peer",
                        "system_cluster_state",
                        "system_upgrade-report_exists",
                        "system_upgrade-report_saved",
                        "system_upgrade-report_current",
                        "system_ha-backup-hb-used",
                        "system_external-resource_validate-jsonpath",
                        "user_scim_groups",
                        "virtual-wan_sladb",
                        "wifi_statistics",
                        "router_charts",
                        "switch-controller_known-nac-device-criteria-list",
                        "system_sandbox_detect",
                        "system_monitor-sensor",
                        "user_device_iot-query",
                        "user_scim_users",
                        "telemetry-controller_agents",
                        "telemetry-controller_agent-tasks",
                        "firewall_internet-service-fqdn",
                        "firewall_internet-service-fqdn-icon-ids",
                        "system_5g-modem_status",
                        "system_interface_poe-usage",
                        "vpn_ipsec_connection-count",
                    ],
                },
            },
        },
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
    check_legacy_fortiosapi(module)

    if (
        module.params["selector"]
        and module.params["selectors"]
        or not module.params["selector"]
        and not module.params["selectors"]
    ):
        module.fail_json(msg="please use selector or selectors in a task.")

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        # Logging for fact module could be disabled/enabled.
        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)

        fos = FortiOSHandler(connection, module)

        if module.params["selector"]:
            is_error, has_changed, result = fortios_monitor_fact(module.params, fos)
        else:
            params = module.params
            selectors = params["selectors"]
            is_error = False
            has_changed = False
            result = []
            for selector_obj in selectors:
                per_selector = {
                    "vdom": params.get("vdom"),
                    # **selector_obj,
                }
                per_selector.update(selector_obj)
                is_error_local, has_changed_local, result_local = fortios_monitor_fact(
                    per_selector, fos
                )

                is_error = is_error or is_error_local
                has_changed = has_changed or has_changed_local
                result.append(result_local)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and galaxy, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.exit_json(changed=has_changed, meta=result)
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
