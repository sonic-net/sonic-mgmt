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
module: fmgr_clone
short_description: Clone an object in FortiManager.
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
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Access token of FortiCloud managed API users, this option is available with FortiManager later than 6.4.0.
        required: false
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other users to release workspace lock.
        required: false
        type: int
        default: 300
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    clone:
        description: Clone An Object.
        type: dict
        required: true
        suboptions:
            selector:
                required: true
                description: Selector of the clone object.
                type: str
                choices:
                    - 'antivirus_mmschecksum'
                    - 'antivirus_mmschecksum_entries'
                    - 'antivirus_notification'
                    - 'antivirus_notification_entries'
                    - 'antivirus_profile'
                    - 'apcfgprofile'
                    - 'apcfgprofile_commandlist'
                    - 'application_casi_profile'
                    - 'application_casi_profile_entries'
                    - 'application_categories'
                    - 'application_custom'
                    - 'application_group'
                    - 'application_internetservice_entry'
                    - 'application_internetservicecustom'
                    - 'application_internetservicecustom_disableentry'
                    - 'application_internetservicecustom_disableentry_iprange'
                    - 'application_internetservicecustom_entry'
                    - 'application_internetservicecustom_entry_portrange'
                    - 'application_list'
                    - 'application_list_defaultnetworkservices'
                    - 'application_list_entries'
                    - 'application_list_entries_parameters'
                    - 'application_list_entries_parameters_members'
                    - 'arrpprofile'
                    - 'authentication_scheme'
                    - 'bleprofile'
                    - 'bonjourprofile'
                    - 'bonjourprofile_policylist'
                    - 'casb_profile'
                    - 'casb_profile_saasapplication'
                    - 'casb_profile_saasapplication_accessrule'
                    - 'casb_profile_saasapplication_accessrule_attributefilter'
                    - 'casb_profile_saasapplication_advancedtenantcontrol'
                    - 'casb_profile_saasapplication_advancedtenantcontrol_attribute'
                    - 'casb_profile_saasapplication_customcontrol'
                    - 'casb_profile_saasapplication_customcontrol_attributefilter'
                    - 'casb_profile_saasapplication_customcontrol_option'
                    - 'casb_saasapplication'
                    - 'casb_saasapplication_inputattributes'
                    - 'casb_saasapplication_outputattributes'
                    - 'casb_useractivity'
                    - 'casb_useractivity_controloptions'
                    - 'casb_useractivity_controloptions_operations'
                    - 'casb_useractivity_match'
                    - 'casb_useractivity_match_rules'
                    - 'casb_useractivity_match_tenantextraction_filters'
                    - 'certificate_template'
                    - 'cifs_domaincontroller'
                    - 'cifs_profile'
                    - 'cifs_profile_filefilter_entries'
                    - 'cifs_profile_serverkeytab'
                    - 'cloud_orchestaws'
                    - 'cloud_orchestawsconnector'
                    - 'cloud_orchestawstemplate_autoscaleexistingvpc'
                    - 'cloud_orchestawstemplate_autoscalenewvpc'
                    - 'cloud_orchestawstemplate_autoscaletgwnewvpc'
                    - 'cloud_orchestration'
                    - 'credentialstore_domaincontroller'
                    - 'devprof_log_syslogd_filter_excludelist'
                    - 'devprof_log_syslogd_filter_excludelist_fields'
                    - 'devprof_log_syslogd_filter_freestyle'
                    - 'devprof_log_syslogd_setting_customfieldname'
                    - 'devprof_system_centralmanagement_serverlist'
                    - 'devprof_system_ntp_ntpserver'
                    - 'devprof_system_snmp_community'
                    - 'devprof_system_snmp_community_hosts'
                    - 'devprof_system_snmp_community_hosts6'
                    - 'devprof_system_snmp_user'
                    - 'diameterfilter_profile'
                    - 'dlp_datatype'
                    - 'dlp_dictionary'
                    - 'dlp_dictionary_entries'
                    - 'dlp_exactdatamatch'
                    - 'dlp_exactdatamatch_columns'
                    - 'dlp_filepattern'
                    - 'dlp_filepattern_entries'
                    - 'dlp_fpsensitivity'
                    - 'dlp_label'
                    - 'dlp_label_entries'
                    - 'dlp_profile'
                    - 'dlp_profile_rule'
                    - 'dlp_sensitivity'
                    - 'dlp_sensor'
                    - 'dlp_sensor_entries'
                    - 'dlp_sensor_filter'
                    - 'dnsfilter_domainfilter'
                    - 'dnsfilter_domainfilter_entries'
                    - 'dnsfilter_profile'
                    - 'dnsfilter_profile_dnstranslation'
                    - 'dnsfilter_profile_ftgddns_filters'
                    - 'dnsfilter_urlfilter'
                    - 'dnsfilter_urlfilter_entries'
                    - 'dvmdb_revision'
                    - 'dynamic_address'
                    - 'dynamic_address_dynamicaddrmapping'
                    - 'dynamic_certificate_local'
                    - 'dynamic_certificate_local_dynamicmapping'
                    - 'dynamic_input_interface'
                    - 'dynamic_input_interface_dynamicmapping'
                    - 'dynamic_interface'
                    - 'dynamic_interface_dynamicmapping'
                    - 'dynamic_interface_platformmapping'
                    - 'dynamic_ippool'
                    - 'dynamic_multicast_interface'
                    - 'dynamic_multicast_interface_dynamicmapping'
                    - 'dynamic_vip'
                    - 'dynamic_virtualwanlink_members'
                    - 'dynamic_virtualwanlink_members_dynamicmapping'
                    - 'dynamic_virtualwanlink_neighbor'
                    - 'dynamic_virtualwanlink_neighbor_dynamicmapping'
                    - 'dynamic_virtualwanlink_server'
                    - 'dynamic_virtualwanlink_server_dynamicmapping'
                    - 'dynamic_vpntunnel'
                    - 'dynamic_vpntunnel_dynamicmapping'
                    - 'emailfilter_blockallowlist'
                    - 'emailfilter_blockallowlist_entries'
                    - 'emailfilter_bwl'
                    - 'emailfilter_bwl_entries'
                    - 'emailfilter_bword'
                    - 'emailfilter_bword_entries'
                    - 'emailfilter_dnsbl'
                    - 'emailfilter_dnsbl_entries'
                    - 'emailfilter_iptrust'
                    - 'emailfilter_iptrust_entries'
                    - 'emailfilter_mheader'
                    - 'emailfilter_mheader_entries'
                    - 'emailfilter_profile'
                    - 'emailfilter_profile_filefilter_entries'
                    - 'endpointcontrol_fctems'
                    - 'extendercontroller_dataplan'
                    - 'extendercontroller_extenderprofile'
                    - 'extendercontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'extendercontroller_extenderprofile_lanextension_backhaul'
                    - 'extendercontroller_simprofile'
                    - 'extendercontroller_template'
                    - 'extensioncontroller_dataplan'
                    - 'extensioncontroller_extenderprofile'
                    - 'extensioncontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'extensioncontroller_extenderprofile_lanextension_backhaul'
                    - 'extensioncontroller_extenderprofile_lanextension_trafficsplitservices'
                    - 'extensioncontroller_extendervap'
                    - 'filefilter_profile'
                    - 'filefilter_profile_rules'
                    - 'firewall_accessproxy'
                    - 'firewall_accessproxy6'
                    - 'firewall_accessproxy6_apigateway'
                    - 'firewall_accessproxy6_apigateway6'
                    - 'firewall_accessproxy6_apigateway6_realservers'
                    - 'firewall_accessproxy6_apigateway6_sslciphersuites'
                    - 'firewall_accessproxy6_apigateway_realservers'
                    - 'firewall_accessproxy6_apigateway_sslciphersuites'
                    - 'firewall_accessproxy_apigateway'
                    - 'firewall_accessproxy_apigateway6'
                    - 'firewall_accessproxy_apigateway6_realservers'
                    - 'firewall_accessproxy_apigateway6_sslciphersuites'
                    - 'firewall_accessproxy_apigateway_realservers'
                    - 'firewall_accessproxy_apigateway_sslciphersuites'
                    - 'firewall_accessproxy_realservers'
                    - 'firewall_accessproxy_serverpubkeyauthsettings_certextension'
                    - 'firewall_accessproxysshclientcert'
                    - 'firewall_accessproxysshclientcert_certextension'
                    - 'firewall_accessproxyvirtualhost'
                    - 'firewall_address'
                    - 'firewall_address6'
                    - 'firewall_address6_dynamicmapping'
                    - 'firewall_address6_dynamicmapping_subnetsegment'
                    - 'firewall_address6_list'
                    - 'firewall_address6_profilelist'
                    - 'firewall_address6_subnetsegment'
                    - 'firewall_address6_tagging'
                    - 'firewall_address6template'
                    - 'firewall_address6template_subnetsegment'
                    - 'firewall_address6template_subnetsegment_values'
                    - 'firewall_address_dynamicmapping'
                    - 'firewall_address_list'
                    - 'firewall_address_profilelist'
                    - 'firewall_address_tagging'
                    - 'firewall_addrgrp'
                    - 'firewall_addrgrp6'
                    - 'firewall_addrgrp6_dynamicmapping'
                    - 'firewall_addrgrp6_tagging'
                    - 'firewall_addrgrp_dynamicmapping'
                    - 'firewall_addrgrp_tagging'
                    - 'firewall_carrierendpointbwl'
                    - 'firewall_carrierendpointbwl_entries'
                    - 'firewall_casbprofile'
                    - 'firewall_casbprofile_saasapplication'
                    - 'firewall_casbprofile_saasapplication_accessrule'
                    - 'firewall_casbprofile_saasapplication_customcontrol'
                    - 'firewall_casbprofile_saasapplication_customcontrol_option'
                    - 'firewall_decryptedtrafficmirror'
                    - 'firewall_explicitproxyaddress'
                    - 'firewall_explicitproxyaddress_headergroup'
                    - 'firewall_explicitproxyaddrgrp'
                    - 'firewall_gtp'
                    - 'firewall_gtp_apn'
                    - 'firewall_gtp_ieremovepolicy'
                    - 'firewall_gtp_imsi'
                    - 'firewall_gtp_ippolicy'
                    - 'firewall_gtp_noippolicy'
                    - 'firewall_gtp_perapnshaper'
                    - 'firewall_gtp_policy'
                    - 'firewall_gtp_policyv2'
                    - 'firewall_identitybasedroute'
                    - 'firewall_identitybasedroute_rule'
                    - 'firewall_internetservice_entry'
                    - 'firewall_internetserviceaddition'
                    - 'firewall_internetserviceaddition_entry'
                    - 'firewall_internetserviceaddition_entry_portrange'
                    - 'firewall_internetservicecustom'
                    - 'firewall_internetservicecustom_disableentry'
                    - 'firewall_internetservicecustom_disableentry_iprange'
                    - 'firewall_internetservicecustom_entry'
                    - 'firewall_internetservicecustom_entry_portrange'
                    - 'firewall_internetservicecustomgroup'
                    - 'firewall_internetserviceextension'
                    - 'firewall_internetserviceextension_disableentry'
                    - 'firewall_internetserviceextension_disableentry_ip6range'
                    - 'firewall_internetserviceextension_disableentry_iprange'
                    - 'firewall_internetserviceextension_disableentry_portrange'
                    - 'firewall_internetserviceextension_entry'
                    - 'firewall_internetserviceextension_entry_portrange'
                    - 'firewall_internetservicegroup'
                    - 'firewall_internetservicename'
                    - 'firewall_ippool'
                    - 'firewall_ippool6'
                    - 'firewall_ippool6_dynamicmapping'
                    - 'firewall_ippool_dynamicmapping'
                    - 'firewall_ippoolgrp'
                    - 'firewall_ldbmonitor'
                    - 'firewall_mmsprofile'
                    - 'firewall_mmsprofile_notifmsisdn'
                    - 'firewall_multicastaddress'
                    - 'firewall_multicastaddress6'
                    - 'firewall_multicastaddress6_tagging'
                    - 'firewall_multicastaddress_tagging'
                    - 'firewall_networkservicedynamic'
                    - 'firewall_profilegroup'
                    - 'firewall_profileprotocoloptions'
                    - 'firewall_profileprotocoloptions_cifs_filefilter_entries'
                    - 'firewall_profileprotocoloptions_cifs_serverkeytab'
                    - 'firewall_proxyaddress'
                    - 'firewall_proxyaddress_headergroup'
                    - 'firewall_proxyaddress_tagging'
                    - 'firewall_proxyaddrgrp'
                    - 'firewall_proxyaddrgrp_tagging'
                    - 'firewall_schedule_group'
                    - 'firewall_schedule_onetime'
                    - 'firewall_schedule_recurring'
                    - 'firewall_service_category'
                    - 'firewall_service_custom'
                    - 'firewall_service_group'
                    - 'firewall_shaper_peripshaper'
                    - 'firewall_shaper_trafficshaper'
                    - 'firewall_shapingprofile'
                    - 'firewall_shapingprofile_shapingentries'
                    - 'firewall_ssh_localca'
                    - 'firewall_sslsshprofile'
                    - 'firewall_sslsshprofile_echoutersni'
                    - 'firewall_sslsshprofile_sslexempt'
                    - 'firewall_sslsshprofile_sslserver'
                    - 'firewall_trafficclass'
                    - 'firewall_vip'
                    - 'firewall_vip46'
                    - 'firewall_vip46_dynamicmapping'
                    - 'firewall_vip46_realservers'
                    - 'firewall_vip6'
                    - 'firewall_vip64'
                    - 'firewall_vip64_dynamicmapping'
                    - 'firewall_vip64_realservers'
                    - 'firewall_vip6_dynamicmapping'
                    - 'firewall_vip6_dynamicmapping_realservers'
                    - 'firewall_vip6_dynamicmapping_sslciphersuites'
                    - 'firewall_vip6_realservers'
                    - 'firewall_vip6_sslciphersuites'
                    - 'firewall_vip6_sslserverciphersuites'
                    - 'firewall_vip_dynamicmapping'
                    - 'firewall_vip_dynamicmapping_realservers'
                    - 'firewall_vip_dynamicmapping_sslciphersuites'
                    - 'firewall_vip_gslbpublicips'
                    - 'firewall_vip_realservers'
                    - 'firewall_vip_sslciphersuites'
                    - 'firewall_vip_sslserverciphersuites'
                    - 'firewall_vipgrp'
                    - 'firewall_vipgrp46'
                    - 'firewall_vipgrp6'
                    - 'firewall_vipgrp64'
                    - 'firewall_vipgrp_dynamicmapping'
                    - 'firewall_wildcardfqdn_custom'
                    - 'firewall_wildcardfqdn_group'
                    - 'fmg_device_blueprint'
                    - 'fmg_fabric_authorization_template'
                    - 'fmg_fabric_authorization_template_platforms'
                    - 'fmg_variable'
                    - 'fmg_variable_dynamicmapping'
                    - 'fsp_vlan'
                    - 'fsp_vlan_dhcpserver_excluderange'
                    - 'fsp_vlan_dhcpserver_iprange'
                    - 'fsp_vlan_dhcpserver_options'
                    - 'fsp_vlan_dhcpserver_reservedaddress'
                    - 'fsp_vlan_dynamicmapping'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_excluderange'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_iprange'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_options'
                    - 'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist'
                    - 'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6'
                    - 'fsp_vlan_dynamicmapping_interface_secondaryip'
                    - 'fsp_vlan_dynamicmapping_interface_vrrp'
                    - 'fsp_vlan_dynamicmapping_interface_vrrp_proxyarp'
                    - 'fsp_vlan_interface_ipv6_ip6delegatedprefixlist'
                    - 'fsp_vlan_interface_ipv6_ip6extraaddr'
                    - 'fsp_vlan_interface_ipv6_ip6prefixlist'
                    - 'fsp_vlan_interface_ipv6_vrrp6'
                    - 'fsp_vlan_interface_secondaryip'
                    - 'fsp_vlan_interface_vrrp'
                    - 'fsp_vlan_interface_vrrp_proxyarp'
                    - 'gtp_apn'
                    - 'gtp_apngrp'
                    - 'gtp_ieallowlist'
                    - 'gtp_ieallowlist_entries'
                    - 'gtp_iewhitelist'
                    - 'gtp_iewhitelist_entries'
                    - 'gtp_messagefilterv0v1'
                    - 'gtp_messagefilterv2'
                    - 'gtp_rattimeoutprofile'
                    - 'gtp_tunnellimit'
                    - 'hotspot20_anqp3gppcellular'
                    - 'hotspot20_anqp3gppcellular_mccmnclist'
                    - 'hotspot20_anqpipaddresstype'
                    - 'hotspot20_anqpnairealm'
                    - 'hotspot20_anqpnairealm_nailist'
                    - 'hotspot20_anqpnairealm_nailist_eapmethod'
                    - 'hotspot20_anqpnairealm_nailist_eapmethod_authparam'
                    - 'hotspot20_anqpnetworkauthtype'
                    - 'hotspot20_anqproamingconsortium'
                    - 'hotspot20_anqproamingconsortium_oilist'
                    - 'hotspot20_anqpvenuename'
                    - 'hotspot20_anqpvenuename_valuelist'
                    - 'hotspot20_anqpvenueurl'
                    - 'hotspot20_anqpvenueurl_valuelist'
                    - 'hotspot20_h2qpadviceofcharge'
                    - 'hotspot20_h2qpadviceofcharge_aoclist'
                    - 'hotspot20_h2qpadviceofcharge_aoclist_planinfo'
                    - 'hotspot20_h2qpconncapability'
                    - 'hotspot20_h2qpoperatorname'
                    - 'hotspot20_h2qpoperatorname_valuelist'
                    - 'hotspot20_h2qposuprovider'
                    - 'hotspot20_h2qposuprovider_friendlyname'
                    - 'hotspot20_h2qposuprovider_servicedescription'
                    - 'hotspot20_h2qposuprovidernai'
                    - 'hotspot20_h2qposuprovidernai_nailist'
                    - 'hotspot20_h2qptermsandconditions'
                    - 'hotspot20_h2qpwanmetric'
                    - 'hotspot20_hsprofile'
                    - 'hotspot20_icon'
                    - 'hotspot20_icon_iconlist'
                    - 'hotspot20_qosmap'
                    - 'hotspot20_qosmap_dscpexcept'
                    - 'hotspot20_qosmap_dscprange'
                    - 'icap_profile'
                    - 'icap_profile_icapheaders'
                    - 'icap_profile_respmodforwardrules'
                    - 'icap_profile_respmodforwardrules_headergroup'
                    - 'icap_server'
                    - 'icap_servergroup'
                    - 'icap_servergroup_serverlist'
                    - 'ips_baseline_sensor'
                    - 'ips_baseline_sensor_entries'
                    - 'ips_baseline_sensor_entries_exemptip'
                    - 'ips_baseline_sensor_filter'
                    - 'ips_baseline_sensor_override'
                    - 'ips_baseline_sensor_override_exemptip'
                    - 'ips_custom'
                    - 'ips_sensor'
                    - 'ips_sensor_entries'
                    - 'ips_sensor_entries_exemptip'
                    - 'ips_sensor_filter'
                    - 'ips_sensor_override'
                    - 'ips_sensor_override_exemptip'
                    - 'log_customfield'
                    - 'log_npuserver_servergroup'
                    - 'log_npuserver_serverinfo'
                    - 'mpskprofile'
                    - 'mpskprofile_mpskgroup'
                    - 'mpskprofile_mpskgroup_mpskkey'
                    - 'nacprofile'
                    - 'pkg_authentication_rule'
                    - 'pkg_central_dnat'
                    - 'pkg_central_dnat6'
                    - 'pkg_firewall_acl'
                    - 'pkg_firewall_acl6'
                    - 'pkg_firewall_centralsnatmap'
                    - 'pkg_firewall_consolidated_policy'
                    - 'pkg_firewall_dospolicy'
                    - 'pkg_firewall_dospolicy6'
                    - 'pkg_firewall_dospolicy6_anomaly'
                    - 'pkg_firewall_dospolicy_anomaly'
                    - 'pkg_firewall_explicitproxypolicy'
                    - 'pkg_firewall_explicitproxypolicy_identitybasedpolicy'
                    - 'pkg_firewall_hyperscalepolicy'
                    - 'pkg_firewall_hyperscalepolicy46'
                    - 'pkg_firewall_hyperscalepolicy6'
                    - 'pkg_firewall_hyperscalepolicy64'
                    - 'pkg_firewall_interfacepolicy'
                    - 'pkg_firewall_interfacepolicy6'
                    - 'pkg_firewall_localinpolicy'
                    - 'pkg_firewall_localinpolicy6'
                    - 'pkg_firewall_multicastpolicy'
                    - 'pkg_firewall_multicastpolicy6'
                    - 'pkg_firewall_policy'
                    - 'pkg_firewall_policy46'
                    - 'pkg_firewall_policy6'
                    - 'pkg_firewall_policy64'
                    - 'pkg_firewall_policy_vpndstnode'
                    - 'pkg_firewall_policy_vpnsrcnode'
                    - 'pkg_firewall_proxypolicy'
                    - 'pkg_firewall_securitypolicy'
                    - 'pkg_firewall_shapingpolicy'
                    - 'pkg_footer_consolidated_policy'
                    - 'pkg_footer_policy'
                    - 'pkg_footer_policy6'
                    - 'pkg_footer_policy6_identitybasedpolicy6'
                    - 'pkg_footer_policy_identitybasedpolicy'
                    - 'pkg_footer_shapingpolicy'
                    - 'pkg_header_consolidated_policy'
                    - 'pkg_header_policy'
                    - 'pkg_header_policy6'
                    - 'pkg_header_policy6_identitybasedpolicy6'
                    - 'pkg_header_policy_identitybasedpolicy'
                    - 'pkg_header_shapingpolicy'
                    - 'pkg_user_nacpolicy'
                    - 'pkg_videofilter_youtubekey'
                    - 'pm_config_pblock_firewall_consolidated_policy'
                    - 'pm_config_pblock_firewall_policy'
                    - 'pm_config_pblock_firewall_policy6'
                    - 'pm_config_pblock_firewall_proxypolicy'
                    - 'pm_config_pblock_firewall_securitypolicy'
                    - 'qosprofile'
                    - 'region'
                    - 'router_accesslist'
                    - 'router_accesslist6'
                    - 'router_accesslist6_rule'
                    - 'router_accesslist_rule'
                    - 'router_aspathlist'
                    - 'router_aspathlist_rule'
                    - 'router_communitylist'
                    - 'router_communitylist_rule'
                    - 'router_prefixlist'
                    - 'router_prefixlist6'
                    - 'router_prefixlist6_rule'
                    - 'router_prefixlist_rule'
                    - 'router_routemap'
                    - 'router_routemap_rule'
                    - 'sctpfilter_profile'
                    - 'sctpfilter_profile_ppidfilters'
                    - 'spamfilter_bwl'
                    - 'spamfilter_bwl_entries'
                    - 'spamfilter_bword'
                    - 'spamfilter_bword_entries'
                    - 'spamfilter_dnsbl'
                    - 'spamfilter_dnsbl_entries'
                    - 'spamfilter_iptrust'
                    - 'spamfilter_iptrust_entries'
                    - 'spamfilter_mheader'
                    - 'spamfilter_mheader_entries'
                    - 'spamfilter_profile'
                    - 'sshfilter_profile'
                    - 'sshfilter_profile_filefilter_entries'
                    - 'sshfilter_profile_shellcommands'
                    - 'switchcontroller_acl_group'
                    - 'switchcontroller_acl_ingress'
                    - 'switchcontroller_customcommand'
                    - 'switchcontroller_dsl_policy'
                    - 'switchcontroller_dynamicportpolicy'
                    - 'switchcontroller_dynamicportpolicy_policy'
                    - 'switchcontroller_fortilinksettings'
                    - 'switchcontroller_lldpprofile'
                    - 'switchcontroller_lldpprofile_customtlvs'
                    - 'switchcontroller_lldpprofile_medlocationservice'
                    - 'switchcontroller_lldpprofile_mednetworkpolicy'
                    - 'switchcontroller_macpolicy'
                    - 'switchcontroller_managedswitch'
                    - 'switchcontroller_managedswitch_customcommand'
                    - 'switchcontroller_managedswitch_dhcpsnoopingstaticclient'
                    - 'switchcontroller_managedswitch_ipsourceguard'
                    - 'switchcontroller_managedswitch_ipsourceguard_bindingentry'
                    - 'switchcontroller_managedswitch_ports'
                    - 'switchcontroller_managedswitch_ports_dhcpsnoopoption82override'
                    - 'switchcontroller_managedswitch_remotelog'
                    - 'switchcontroller_managedswitch_routeoffloadrouter'
                    - 'switchcontroller_managedswitch_snmpcommunity'
                    - 'switchcontroller_managedswitch_snmpcommunity_hosts'
                    - 'switchcontroller_managedswitch_snmpuser'
                    - 'switchcontroller_managedswitch_vlan'
                    - 'switchcontroller_ptp_profile'
                    - 'switchcontroller_qos_dot1pmap'
                    - 'switchcontroller_qos_ipdscpmap'
                    - 'switchcontroller_qos_ipdscpmap_map'
                    - 'switchcontroller_qos_qospolicy'
                    - 'switchcontroller_qos_queuepolicy'
                    - 'switchcontroller_qos_queuepolicy_cosqueue'
                    - 'switchcontroller_securitypolicy_8021x'
                    - 'switchcontroller_securitypolicy_captiveportal'
                    - 'switchcontroller_switchinterfacetag'
                    - 'switchcontroller_trafficpolicy'
                    - 'switchcontroller_vlanpolicy'
                    - 'system_customlanguage'
                    - 'system_dhcp_server'
                    - 'system_dhcp_server_excluderange'
                    - 'system_dhcp_server_iprange'
                    - 'system_dhcp_server_options'
                    - 'system_dhcp_server_reservedaddress'
                    - 'system_externalresource'
                    - 'system_geoipcountry'
                    - 'system_geoipoverride'
                    - 'system_geoipoverride_ip6range'
                    - 'system_geoipoverride_iprange'
                    - 'system_meta'
                    - 'system_meta_sysmetafields'
                    - 'system_npu_dswdtsprofile'
                    - 'system_npu_dswqueuedtsprofile'
                    - 'system_npu_npqueues_ethernettype'
                    - 'system_npu_npqueues_ipprotocol'
                    - 'system_npu_npqueues_ipservice'
                    - 'system_npu_npqueues_profile'
                    - 'system_npu_npqueues_scheduler'
                    - 'system_npu_nputcam'
                    - 'system_npu_portcpumap'
                    - 'system_npu_portnpumap'
                    - 'system_npu_tcptimeoutprofile'
                    - 'system_npu_udptimeoutprofile'
                    - 'system_objecttag'
                    - 'system_objecttagging'
                    - 'system_replacemsggroup'
                    - 'system_replacemsggroup_admin'
                    - 'system_replacemsggroup_alertmail'
                    - 'system_replacemsggroup_auth'
                    - 'system_replacemsggroup_automation'
                    - 'system_replacemsggroup_custommessage'
                    - 'system_replacemsggroup_devicedetectionportal'
                    - 'system_replacemsggroup_ec'
                    - 'system_replacemsggroup_fortiguardwf'
                    - 'system_replacemsggroup_ftp'
                    - 'system_replacemsggroup_http'
                    - 'system_replacemsggroup_icap'
                    - 'system_replacemsggroup_mail'
                    - 'system_replacemsggroup_mm1'
                    - 'system_replacemsggroup_mm3'
                    - 'system_replacemsggroup_mm4'
                    - 'system_replacemsggroup_mm7'
                    - 'system_replacemsggroup_mms'
                    - 'system_replacemsggroup_nacquar'
                    - 'system_replacemsggroup_nntp'
                    - 'system_replacemsggroup_spam'
                    - 'system_replacemsggroup_sslvpn'
                    - 'system_replacemsggroup_trafficquota'
                    - 'system_replacemsggroup_utm'
                    - 'system_replacemsggroup_webproxy'
                    - 'system_replacemsgimage'
                    - 'system_sdnconnector'
                    - 'system_sdnconnector_compartmentlist'
                    - 'system_sdnconnector_externalaccountlist'
                    - 'system_sdnconnector_externalip'
                    - 'system_sdnconnector_forwardingrule'
                    - 'system_sdnconnector_gcpprojectlist'
                    - 'system_sdnconnector_nic'
                    - 'system_sdnconnector_nic_ip'
                    - 'system_sdnconnector_ociregionlist'
                    - 'system_sdnconnector_route'
                    - 'system_sdnconnector_routetable'
                    - 'system_sdnconnector_routetable_route'
                    - 'system_sdnproxy'
                    - 'system_smsserver'
                    - 'system_virtualwirepair'
                    - 'telemetrycontroller_agentprofile'
                    - 'telemetrycontroller_application_predefine'
                    - 'telemetrycontroller_profile'
                    - 'telemetrycontroller_profile_application'
                    - 'template'
                    - 'templategroup'
                    - 'ums_setting'
                    - 'user_adgrp'
                    - 'user_certificate'
                    - 'user_clearpass'
                    - 'user_connector'
                    - 'user_device'
                    - 'user_device_dynamicmapping'
                    - 'user_device_tagging'
                    - 'user_deviceaccesslist'
                    - 'user_deviceaccesslist_devicelist'
                    - 'user_devicecategory'
                    - 'user_devicegroup'
                    - 'user_devicegroup_dynamicmapping'
                    - 'user_devicegroup_tagging'
                    - 'user_domaincontroller'
                    - 'user_domaincontroller_extraserver'
                    - 'user_exchange'
                    - 'user_externalidentityprovider'
                    - 'user_flexvm'
                    - 'user_fortitoken'
                    - 'user_fsso'
                    - 'user_fsso_dynamicmapping'
                    - 'user_fssopolling'
                    - 'user_fssopolling_adgrp'
                    - 'user_group'
                    - 'user_group_dynamicmapping'
                    - 'user_group_dynamicmapping_guest'
                    - 'user_group_dynamicmapping_match'
                    - 'user_group_guest'
                    - 'user_group_match'
                    - 'user_json'
                    - 'user_krbkeytab'
                    - 'user_ldap'
                    - 'user_ldap_dynamicmapping'
                    - 'user_local'
                    - 'user_nsx'
                    - 'user_nsx_service'
                    - 'user_passwordpolicy'
                    - 'user_peer'
                    - 'user_peergrp'
                    - 'user_pop3'
                    - 'user_pxgrid'
                    - 'user_radius'
                    - 'user_radius_accountingserver'
                    - 'user_radius_dynamicmapping'
                    - 'user_radius_dynamicmapping_accountingserver'
                    - 'user_saml'
                    - 'user_saml_dynamicmapping'
                    - 'user_scim'
                    - 'user_securityexemptlist'
                    - 'user_securityexemptlist_rule'
                    - 'user_tacacs'
                    - 'user_tacacs_dynamicmapping'
                    - 'user_vcenter'
                    - 'user_vcenter_rule'
                    - 'utmprofile'
                    - 'vap'
                    - 'vap_dynamicmapping'
                    - 'vap_macfilterlist'
                    - 'vap_mpskkey'
                    - 'vap_vlanname'
                    - 'vap_vlanpool'
                    - 'vapgroup'
                    - 'videofilter_keyword'
                    - 'videofilter_keyword_word'
                    - 'videofilter_profile'
                    - 'videofilter_profile_filters'
                    - 'videofilter_profile_fortiguardcategory_filters'
                    - 'videofilter_youtubechannelfilter'
                    - 'videofilter_youtubechannelfilter_entries'
                    - 'videofilter_youtubekey'
                    - 'virtualpatch_profile'
                    - 'virtualpatch_profile_exemption'
                    - 'voip_profile'
                    - 'vpn_certificate_ca'
                    - 'vpn_certificate_ocspserver'
                    - 'vpn_certificate_remote'
                    - 'vpn_ipsec_fec'
                    - 'vpn_ipsec_fec_mappings'
                    - 'vpn_ssl_settings_authenticationrule'
                    - 'vpnmgr_node'
                    - 'vpnmgr_node_iprange'
                    - 'vpnmgr_node_ipv4excluderange'
                    - 'vpnmgr_node_protectedsubnet'
                    - 'vpnmgr_node_summaryaddr'
                    - 'vpnmgr_vpntable'
                    - 'vpnsslweb_hostchecksoftware'
                    - 'vpnsslweb_hostchecksoftware_checkitemlist'
                    - 'vpnsslweb_portal'
                    - 'vpnsslweb_portal_bookmarkgroup'
                    - 'vpnsslweb_portal_bookmarkgroup_bookmarks'
                    - 'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata'
                    - 'vpnsslweb_portal_landingpage_formdata'
                    - 'vpnsslweb_portal_macaddrcheckrule'
                    - 'vpnsslweb_portal_splitdns'
                    - 'vpnsslweb_realm'
                    - 'vpnsslweb_virtualdesktopapplist'
                    - 'vpnsslweb_virtualdesktopapplist_apps'
                    - 'waf_mainclass'
                    - 'waf_profile'
                    - 'waf_profile_constraint_exception'
                    - 'waf_profile_method_methodpolicy'
                    - 'waf_profile_signature_customsignature'
                    - 'waf_profile_urlaccess'
                    - 'waf_profile_urlaccess_accesspattern'
                    - 'waf_signature'
                    - 'waf_subclass'
                    - 'wagprofile'
                    - 'wanopt_authgroup'
                    - 'wanopt_peer'
                    - 'wanopt_profile'
                    - 'wanprof_system_sdwan_duplication'
                    - 'wanprof_system_sdwan_healthcheck'
                    - 'wanprof_system_sdwan_healthcheck_sla'
                    - 'wanprof_system_sdwan_members'
                    - 'wanprof_system_sdwan_neighbor'
                    - 'wanprof_system_sdwan_service'
                    - 'wanprof_system_sdwan_service_sla'
                    - 'wanprof_system_sdwan_zone'
                    - 'wanprof_system_virtualwanlink_healthcheck'
                    - 'wanprof_system_virtualwanlink_healthcheck_sla'
                    - 'wanprof_system_virtualwanlink_members'
                    - 'wanprof_system_virtualwanlink_neighbor'
                    - 'wanprof_system_virtualwanlink_service'
                    - 'wanprof_system_virtualwanlink_service_sla'
                    - 'webfilter_categories'
                    - 'webfilter_content'
                    - 'webfilter_content_entries'
                    - 'webfilter_contentheader'
                    - 'webfilter_contentheader_entries'
                    - 'webfilter_ftgdlocalcat'
                    - 'webfilter_ftgdlocalrating'
                    - 'webfilter_profile'
                    - 'webfilter_profile_antiphish_custompatterns'
                    - 'webfilter_profile_antiphish_inspectionentries'
                    - 'webfilter_profile_filefilter_entries'
                    - 'webfilter_profile_ftgdwf_filters'
                    - 'webfilter_profile_ftgdwf_quota'
                    - 'webfilter_profile_ftgdwf_risk'
                    - 'webfilter_profile_youtubechannelfilter'
                    - 'webfilter_urlfilter'
                    - 'webfilter_urlfilter_entries'
                    - 'webproxy_forwardserver'
                    - 'webproxy_forwardservergroup'
                    - 'webproxy_forwardservergroup_serverlist'
                    - 'webproxy_isolatorserver'
                    - 'webproxy_profile'
                    - 'webproxy_profile_headers'
                    - 'webproxy_wisp'
                    - 'widsprofile'
                    - 'wireless_accesscontrollist'
                    - 'wireless_accesscontrollist_layer3ipv4rules'
                    - 'wireless_accesscontrollist_layer3ipv6rules'
                    - 'wireless_address'
                    - 'wireless_addrgrp'
                    - 'wireless_ssidpolicy'
                    - 'wireless_syslogprofile'
                    - 'wireless_vap_ip6prefixlist'
                    - 'wtpprofile'
                    - 'wtpprofile_denymaclist'
                    - 'wtpprofile_splittunnelingacl'
            self:
                required: true
                description: The parameter for each selector.
                type: dict
            target:
                required: true
                description: Attribute to override for target object.
                type: dict
'''

EXAMPLES = '''
- name: Clone an object
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Clone a vip object using fmgr_clone module.
      fortinet.fortimanager.fmgr_clone:
        clone:
          selector: "firewall_vip"
          self:
            adom: "root"
            vip: "ansible-test-vip_first"
          target:
            name: "ansible-test-vip_fourth"
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager


def main():
    clone_metadata = {
        'antivirus_mmschecksum': {
            'params': ['adom', 'mms-checksum'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.6.2']]
        },
        'antivirus_mmschecksum_entries': {
            'params': ['adom', 'entries', 'mms-checksum'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}',
                '/pm/config/global/obj/antivirus/mms-checksum/{mms-checksum}/entries/{entries}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.6.2']]
        },
        'antivirus_notification': {
            'params': ['adom', 'notification'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}',
                '/pm/config/global/obj/antivirus/notification/{notification}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.6.2']]
        },
        'antivirus_notification_entries': {
            'params': ['adom', 'entries', 'notification'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/notification/{notification}/entries/{entries}',
                '/pm/config/global/obj/antivirus/notification/{notification}/entries/{entries}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.6.2']]
        },
        'antivirus_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/antivirus/profile/{profile}',
                '/pm/config/global/obj/antivirus/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'apcfgprofile': {
            'params': ['adom', 'apcfg-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}',
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}'
            ],
            'mkey': 'name', 'v_range': [['6.4.6', '']]
        },
        'apcfgprofile_commandlist': {
            'params': ['adom', 'apcfg-profile', 'command-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}',
                '/pm/config/global/obj/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'mkey': 'id', 'v_range': [['6.4.6', '']]
        },
        'application_casi_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/casi/profile/{profile}',
                '/pm/config/global/obj/application/casi/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '6.2.13']]
        },
        'application_casi_profile_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/casi/profile/{profile}/entries/{entries}',
                '/pm/config/global/obj/application/casi/profile/{profile}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'application_categories': {
            'params': ['adom', 'categories'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/categories/{categories}',
                '/pm/config/global/obj/application/categories/{categories}'
            ],
            'mkey': 'id'
        },
        'application_custom': {
            'params': ['adom', 'custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/custom/{custom}',
                '/pm/config/global/obj/application/custom/{custom}'
            ],
            'mkey': 'tag'
        },
        'application_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/group/{group}',
                '/pm/config/global/obj/application/group/{group}'
            ],
            'mkey': 'name'
        },
        'application_internetservice_entry': {
            'params': ['adom', 'entry'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service/entry/{entry}',
                '/pm/config/global/obj/application/internet-service/entry/{entry}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom': {
            'params': ['adom', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom_disableentry': {
            'params': ['adom', 'disable-entry', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom_disableentry_iprange': {
            'params': ['adom', 'disable-entry', 'internet-service-custom', 'ip-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom_entry': {
            'params': ['adom', 'entry', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'application_internetservicecustom_entry_portrange': {
            'params': ['adom', 'entry', 'internet-service-custom', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/application/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'application_list': {
            'params': ['adom', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}',
                '/pm/config/global/obj/application/list/{list}'
            ],
            'mkey': 'name'
        },
        'application_list_defaultnetworkservices': {
            'params': ['adom', 'default-network-services', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/default-network-services/{default-network-services}',
                '/pm/config/global/obj/application/list/{list}/default-network-services/{default-network-services}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'application_list_entries': {
            'params': ['adom', 'entries', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}'
            ],
            'mkey': 'id'
        },
        'application_list_entries_parameters': {
            'params': ['adom', 'entries', 'list', 'parameters'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}'
            ],
            'mkey': 'id'
        },
        'application_list_entries_parameters_members': {
            'params': ['adom', 'entries', 'list', 'members', 'parameters'],
            'urls': [
                '/pm/config/adom/{adom}/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members/{members}',
                '/pm/config/global/obj/application/list/{list}/entries/{entries}/parameters/{parameters}/members/{members}'
            ],
            'mkey': 'id', 'v_range': [['6.4.0', '']]
        },
        'arrpprofile': {
            'params': ['adom', 'arrp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/arrp-profile/{arrp-profile}',
                '/pm/config/global/obj/wireless-controller/arrp-profile/{arrp-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'authentication_scheme': {
            'params': ['adom', 'scheme'],
            'urls': [
                '/pm/config/adom/{adom}/obj/authentication/scheme/{scheme}',
                '/pm/config/global/obj/authentication/scheme/{scheme}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '']]
        },
        'bleprofile': {
            'params': ['adom', 'ble-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/ble-profile/{ble-profile}',
                '/pm/config/global/obj/wireless-controller/ble-profile/{ble-profile}'
            ],
            'mkey': 'name'
        },
        'bonjourprofile': {
            'params': ['adom', 'bonjour-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}'
            ],
            'mkey': 'name'
        },
        'bonjourprofile_policylist': {
            'params': ['adom', 'bonjour-profile', 'policy-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}',
                '/pm/config/global/obj/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}'
            ],
            'mkey': 'policy-id'
        },
        'casb_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}',
                '/pm/config/global/obj/casb/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'casb_profile_saasapplication': {
            'params': ['adom', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'casb_profile_saasapplication_accessrule': {
            'params': ['access-rule', 'adom', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'casb_profile_saasapplication_accessrule_attributefilter': {
            'params': ['access-rule', 'adom', 'attribute-filter', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}/attribute-filter/{attribute-'
                'filter}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}/attribute-filter/{attribute-filte'
                'r}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'casb_profile_saasapplication_advancedtenantcontrol': {
            'params': ['adom', 'advanced-tenant-control', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'casb_profile_saasapplication_advancedtenantcontrol_attribute': {
            'params': ['adom', 'advanced-tenant-control', 'attribute', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}/attr'
                'ibute/{attribute}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-control}/attribute'
                '/{attribute}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'casb_profile_saasapplication_customcontrol': {
            'params': ['adom', 'custom-control', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'casb_profile_saasapplication_customcontrol_attributefilter': {
            'params': ['adom', 'attribute-filter', 'custom-control', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/attribute-filter/{attr'
                'ibute-filter}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/attribute-filter/{attribute'
                '-filter}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'casb_profile_saasapplication_customcontrol_option': {
            'params': ['adom', 'custom-control', 'option', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/option/{option}',
                '/pm/config/global/obj/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/option/{option}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'casb_saasapplication': {
            'params': ['adom', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}',
                '/pm/config/global/obj/casb/saas-application/{saas-application}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'casb_saasapplication_inputattributes': {
            'params': ['adom', 'input-attributes', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}/input-attributes/{input-attributes}',
                '/pm/config/global/obj/casb/saas-application/{saas-application}/input-attributes/{input-attributes}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'casb_saasapplication_outputattributes': {
            'params': ['adom', 'output-attributes', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/saas-application/{saas-application}/output-attributes/{output-attributes}',
                '/pm/config/global/obj/casb/saas-application/{saas-application}/output-attributes/{output-attributes}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'casb_useractivity': {
            'params': ['adom', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_controloptions': {
            'params': ['adom', 'control-options', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/control-options/{control-options}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/control-options/{control-options}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_controloptions_operations': {
            'params': ['adom', 'control-options', 'operations', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/control-options/{control-options}/operations/{operations}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/control-options/{control-options}/operations/{operations}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_match': {
            'params': ['adom', 'match', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}'
            ],
            'mkey': 'id', 'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_match_rules': {
            'params': ['adom', 'match', 'rules', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/rules/{rules}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/rules/{rules}'
            ],
            'mkey': 'id', 'v_range': [['7.4.1', '']]
        },
        'casb_useractivity_match_tenantextraction_filters': {
            'params': ['adom', 'filters', 'match', 'user-activity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/casb/user-activity/{user-activity}/match/{match}/tenant-extraction/filters/{filters}',
                '/pm/config/global/obj/casb/user-activity/{user-activity}/match/{match}/tenant-extraction/filters/{filters}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'certificate_template': {
            'params': ['adom', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/certificate/template/{template}',
                '/pm/config/global/obj/certificate/template/{template}'
            ],
            'mkey': 'name'
        },
        'cifs_domaincontroller': {
            'params': ['adom', 'domain-controller'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/domain-controller/{domain-controller}',
                '/pm/config/global/obj/cifs/domain-controller/{domain-controller}'
            ],
            'mkey': None, 'v_range': [['6.2.0', '7.6.2']]
        },
        'cifs_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}',
                '/pm/config/global/obj/cifs/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '']]
        },
        'cifs_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/cifs/profile/{profile}/file-filter/entries/{entries}'
            ],
            'mkey': None, 'v_range': [['6.2.0', '7.6.2']]
        },
        'cifs_profile_serverkeytab': {
            'params': ['adom', 'profile', 'server-keytab'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cifs/profile/{profile}/server-keytab/{server-keytab}',
                '/pm/config/global/obj/cifs/profile/{profile}/server-keytab/{server-keytab}'
            ],
            'mkey': None, 'v_range': [['6.2.0', '']]
        },
        'cloud_orchestaws': {
            'params': ['adom', 'orchest-aws'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-aws/{orchest-aws}',
                '/pm/config/global/obj/cloud/orchest-aws/{orchest-aws}'
            ],
            'mkey': 'name', 'v_range': [['7.4.0', '']]
        },
        'cloud_orchestawsconnector': {
            'params': ['adom', 'orchest-awsconnector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-awsconnector/{orchest-awsconnector}',
                '/pm/config/global/obj/cloud/orchest-awsconnector/{orchest-awsconnector}'
            ],
            'mkey': 'name', 'v_range': [['7.4.0', '']]
        },
        'cloud_orchestawstemplate_autoscaleexistingvpc': {
            'params': ['adom', 'autoscale-existing-vpc'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-existing-vpc/{autoscale-existing-vpc}',
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-existing-vpc/{autoscale-existing-vpc}'
            ],
            'mkey': 'name', 'v_range': [['7.4.0', '']]
        },
        'cloud_orchestawstemplate_autoscalenewvpc': {
            'params': ['adom', 'autoscale-new-vpc'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-new-vpc/{autoscale-new-vpc}',
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-new-vpc/{autoscale-new-vpc}'
            ],
            'mkey': 'name', 'v_range': [['7.4.0', '']]
        },
        'cloud_orchestawstemplate_autoscaletgwnewvpc': {
            'params': ['adom', 'autoscale-tgw-new-vpc'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc/{autoscale-tgw-new-vpc}',
                '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc/{autoscale-tgw-new-vpc}'
            ],
            'mkey': 'name', 'v_range': [['7.4.0', '']]
        },
        'cloud_orchestration': {
            'params': ['adom', 'orchestration'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cloud/orchestration/{orchestration}',
                '/pm/config/global/obj/cloud/orchestration/{orchestration}'
            ],
            'mkey': 'name', 'v_range': [['7.4.0', '']]
        },
        'credentialstore_domaincontroller': {
            'params': ['adom', 'domain-controller'],
            'urls': [
                '/pm/config/adom/{adom}/obj/credential-store/domain-controller/{domain-controller}',
                '/pm/config/global/obj/credential-store/domain-controller/{domain-controller}'
            ],
            'mkey': None, 'v_range': [['6.4.0', '']]
        },
        'devprof_log_syslogd_filter_excludelist': {
            'params': ['adom', 'devprof', 'exclude-list'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/exclude-list/{exclude-list}'
            ],
            'mkey': 'id', 'v_range': [['7.0.4', '7.0.14']]
        },
        'devprof_log_syslogd_filter_excludelist_fields': {
            'params': ['adom', 'devprof', 'exclude-list', 'fields'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/exclude-list/{exclude-list}/fields/{fields}'
            ],
            'mkey': None, 'v_range': [['7.0.4', '7.0.14']]
        },
        'devprof_log_syslogd_filter_freestyle': {
            'params': ['adom', 'devprof', 'free-style'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']]
        },
        'devprof_log_syslogd_setting_customfieldname': {
            'params': ['adom', 'custom-field-name', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/log/syslogd/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']]
        },
        'devprof_system_centralmanagement_serverlist': {
            'params': ['adom', 'devprof', 'server-list'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/central-management/server-list/{server-list}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_ntp_ntpserver': {
            'params': ['adom', 'devprof', 'ntpserver'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/ntp/ntpserver/{ntpserver}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_snmp_community': {
            'params': ['adom', 'community', 'devprof'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_snmp_community_hosts': {
            'params': ['adom', 'community', 'devprof', 'hosts'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_snmp_community_hosts6': {
            'params': ['adom', 'community', 'devprof', 'hosts6'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'devprof_system_snmp_user': {
            'params': ['adom', 'devprof', 'user'],
            'urls': [
                '/pm/config/adom/{adom}/devprof/{devprof}/system/snmp/user/{user}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '6.2.5'], ['6.2.7', '6.4.1'], ['6.4.3', '']]
        },
        'diameterfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/diameter-filter/profile/{profile}',
                '/pm/config/global/obj/diameter-filter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.2', '']]
        },
        'dlp_datatype': {
            'params': ['adom', 'data-type'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/data-type/{data-type}',
                '/pm/config/global/obj/dlp/data-type/{data-type}'
            ],
            'mkey': 'name', 'v_range': [['7.2.0', '']]
        },
        'dlp_dictionary': {
            'params': ['adom', 'dictionary'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}',
                '/pm/config/global/obj/dlp/dictionary/{dictionary}'
            ],
            'mkey': 'name', 'v_range': [['7.2.0', '']]
        },
        'dlp_dictionary_entries': {
            'params': ['adom', 'dictionary', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/dictionary/{dictionary}/entries/{entries}',
                '/pm/config/global/obj/dlp/dictionary/{dictionary}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.2.0', '']]
        },
        'dlp_exactdatamatch': {
            'params': ['adom', 'exact-data-match'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/exact-data-match/{exact-data-match}',
                '/pm/config/global/obj/dlp/exact-data-match/{exact-data-match}'
            ],
            'mkey': 'name', 'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'dlp_exactdatamatch_columns': {
            'params': ['adom', 'columns', 'exact-data-match'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/exact-data-match/{exact-data-match}/columns/{columns}',
                '/pm/config/global/obj/dlp/exact-data-match/{exact-data-match}/columns/{columns}'
            ],
            'mkey': None, 'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'dlp_filepattern': {
            'params': ['adom', 'filepattern'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}'
            ],
            'mkey': 'id'
        },
        'dlp_filepattern_entries': {
            'params': ['adom', 'entries', 'filepattern'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}/entries/{entries}',
                '/pm/config/global/obj/dlp/filepattern/{filepattern}/entries/{entries}'
            ],
            'mkey': None
        },
        'dlp_fpsensitivity': {
            'params': ['adom', 'fp-sensitivity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/fp-sensitivity/{fp-sensitivity}',
                '/pm/config/global/obj/dlp/fp-sensitivity/{fp-sensitivity}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.2.1']]
        },
        'dlp_label': {
            'params': ['adom', 'label'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/label/{label}',
                '/pm/config/global/obj/dlp/label/{label}'
            ],
            'mkey': 'name', 'v_range': [['7.6.3', '']]
        },
        'dlp_label_entries': {
            'params': ['adom', 'entries', 'label'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/label/{label}/entries/{entries}',
                '/pm/config/global/obj/dlp/label/{label}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.6.3', '']]
        },
        'dlp_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}',
                '/pm/config/global/obj/dlp/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.0', '']]
        },
        'dlp_profile_rule': {
            'params': ['adom', 'profile', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/profile/{profile}/rule/{rule}',
                '/pm/config/global/obj/dlp/profile/{profile}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.2.0', '']]
        },
        'dlp_sensitivity': {
            'params': ['adom', 'sensitivity'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensitivity/{sensitivity}',
                '/pm/config/global/obj/dlp/sensitivity/{sensitivity}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '']]
        },
        'dlp_sensor': {
            'params': ['adom', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}',
                '/pm/config/global/obj/dlp/sensor/{sensor}'
            ],
            'mkey': 'name'
        },
        'dlp_sensor_entries': {
            'params': ['adom', 'entries', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/dlp/sensor/{sensor}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.2.0', '']]
        },
        'dlp_sensor_filter': {
            'params': ['adom', 'filter', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dlp/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/dlp/sensor/{sensor}/filter/{filter}'
            ],
            'mkey': 'id'
        },
        'dnsfilter_domainfilter': {
            'params': ['adom', 'domain-filter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}'
            ],
            'mkey': 'id'
        },
        'dnsfilter_domainfilter_entries': {
            'params': ['adom', 'domain-filter', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}',
                '/pm/config/global/obj/dnsfilter/domain-filter/{domain-filter}/entries/{entries}'
            ],
            'mkey': 'id'
        },
        'dnsfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'dnsfilter_profile_dnstranslation': {
            'params': ['adom', 'dns-translation', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/dns-translation/{dns-translation}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/dns-translation/{dns-translation}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'dnsfilter_profile_ftgddns_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}',
                '/pm/config/global/obj/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}'
            ],
            'mkey': 'id'
        },
        'dnsfilter_urlfilter': {
            'params': ['adom', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter/{urlfilter}',
                '/pm/config/global/obj/dnsfilter/urlfilter/{urlfilter}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'dnsfilter_urlfilter_entries': {
            'params': ['adom', 'entries', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dnsfilter/urlfilter/{urlfilter}/entries/{entries}',
                '/pm/config/global/obj/dnsfilter/urlfilter/{urlfilter}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'dvmdb_revision': {
            'params': ['adom', 'revision'],
            'urls': [
                '/dvmdb/adom/{adom}/revision/{revision}',
                '/dvmdb/global/revision/{revision}',
                '/dvmdb/revision/{revision}'
            ],
            'mkey': 'name'
        },
        'dynamic_address': {
            'params': ['address', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}',
                '/pm/config/global/obj/dynamic/address/{address}'
            ],
            'mkey': 'name'
        },
        'dynamic_address_dynamicaddrmapping': {
            'params': ['address', 'adom', 'dynamic_addr_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}',
                '/pm/config/global/obj/dynamic/address/{address}/dynamic_addr_mapping/{dynamic_addr_mapping}'
            ],
            'mkey': 'id'
        },
        'dynamic_certificate_local': {
            'params': ['adom', 'local'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}',
                '/pm/config/global/obj/dynamic/certificate/local/{local}'
            ],
            'mkey': 'name'
        },
        'dynamic_certificate_local_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'local'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/certificate/local/{local}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'dynamic_input_interface': {
            'params': ['adom', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/input/interface/{interface}',
                '/pm/config/global/obj/dynamic/input/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['6.2.2', '6.4.0']]
        },
        'dynamic_input_interface_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/input/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/input/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '6.4.0']]
        },
        'dynamic_interface': {
            'params': ['adom', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}',
                '/pm/config/global/obj/dynamic/interface/{interface}'
            ],
            'mkey': 'name'
        },
        'dynamic_interface_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'dynamic_interface_platformmapping': {
            'params': ['adom', 'interface', 'platform_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/interface/{interface}/platform_mapping/{platform_mapping}',
                '/pm/config/global/obj/dynamic/interface/{interface}/platform_mapping/{platform_mapping}'
            ],
            'mkey': 'name', 'v_range': [['6.4.1', '']]
        },
        'dynamic_ippool': {
            'params': ['adom', 'ippool'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/ippool/{ippool}',
                '/pm/config/global/obj/dynamic/ippool/{ippool}'
            ],
            'mkey': 'name'
        },
        'dynamic_multicast_interface': {
            'params': ['adom', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}'
            ],
            'mkey': 'name'
        },
        'dynamic_multicast_interface_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'interface'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/multicast/interface/{interface}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'dynamic_vip': {
            'params': ['adom', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vip/{vip}',
                '/pm/config/global/obj/dynamic/vip/{vip}'
            ],
            'mkey': 'name'
        },
        'dynamic_virtualwanlink_members': {
            'params': ['adom', 'members'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '6.4.15']]
        },
        'dynamic_virtualwanlink_members_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'members'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/members/{members}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '6.4.15']]
        },
        'dynamic_virtualwanlink_neighbor': {
            'params': ['adom', 'neighbor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor/{neighbor}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor/{neighbor}'
            ],
            'mkey': 'name', 'v_range': [['6.2.2', '6.4.15']]
        },
        'dynamic_virtualwanlink_neighbor_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'neighbor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/neighbor/{neighbor}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '6.4.15']]
        },
        'dynamic_virtualwanlink_server': {
            'params': ['adom', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '6.4.15']]
        },
        'dynamic_virtualwanlink_server_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/virtual-wan-link/server/{server}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '6.4.15']]
        },
        'dynamic_vpntunnel': {
            'params': ['adom', 'vpntunnel'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}'
            ],
            'mkey': 'name'
        },
        'dynamic_vpntunnel_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vpntunnel'],
            'urls': [
                '/pm/config/adom/{adom}/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/dynamic/vpntunnel/{vpntunnel}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'emailfilter_blockallowlist': {
            'params': ['adom', 'block-allow-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}',
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}'
            ],
            'mkey': 'id', 'v_range': [['7.0.0', '']]
        },
        'emailfilter_blockallowlist_entries': {
            'params': ['adom', 'block-allow-list', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.0.0', '']]
        },
        'emailfilter_bwl': {
            'params': ['adom', 'bwl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}',
                '/pm/config/global/obj/emailfilter/bwl/{bwl}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_bwl_entries': {
            'params': ['adom', 'bwl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/bwl/{bwl}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_bword': {
            'params': ['adom', 'bword'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}',
                '/pm/config/global/obj/emailfilter/bword/{bword}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_bword_entries': {
            'params': ['adom', 'bword', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/bword/{bword}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/bword/{bword}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_dnsbl': {
            'params': ['adom', 'dnsbl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl/{dnsbl}',
                '/pm/config/global/obj/emailfilter/dnsbl/{dnsbl}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_dnsbl_entries': {
            'params': ['adom', 'dnsbl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/dnsbl/{dnsbl}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/dnsbl/{dnsbl}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_iptrust': {
            'params': ['adom', 'iptrust'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust/{iptrust}',
                '/pm/config/global/obj/emailfilter/iptrust/{iptrust}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_iptrust_entries': {
            'params': ['adom', 'entries', 'iptrust'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/iptrust/{iptrust}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/iptrust/{iptrust}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_mheader': {
            'params': ['adom', 'mheader'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/mheader/{mheader}',
                '/pm/config/global/obj/emailfilter/mheader/{mheader}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_mheader_entries': {
            'params': ['adom', 'entries', 'mheader'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/mheader/{mheader}/entries/{entries}',
                '/pm/config/global/obj/emailfilter/mheader/{mheader}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}',
                '/pm/config/global/obj/emailfilter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '']]
        },
        'emailfilter_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/emailfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'mkey': None, 'v_range': [['6.2.0', '7.6.2']]
        },
        'endpointcontrol_fctems': {
            'params': ['adom', 'fctems'],
            'urls': [
                '/pm/config/adom/{adom}/obj/endpoint-control/fctems/{fctems}',
                '/pm/config/global/obj/endpoint-control/fctems/{fctems}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'extendercontroller_dataplan': {
            'params': ['adom', 'dataplan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/dataplan/{dataplan}',
                '/pm/config/global/obj/extender-controller/dataplan/{dataplan}'
            ],
            'mkey': 'name', 'v_range': [['6.4.4', '']]
        },
        'extendercontroller_extenderprofile': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': ['adom', 'extender-profile', 'receiver'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'extendercontroller_extenderprofile_lanextension_backhaul': {
            'params': ['adom', 'backhaul', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}',
                '/pm/config/global/obj/extender-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'extendercontroller_simprofile': {
            'params': ['adom', 'sim_profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/sim_profile/{sim_profile}',
                '/pm/config/global/obj/extender-controller/sim_profile/{sim_profile}'
            ],
            'mkey': 'name', 'v_range': [['6.4.4', '']]
        },
        'extendercontroller_template': {
            'params': ['adom', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extender-controller/template/{template}',
                '/pm/config/global/obj/extender-controller/template/{template}'
            ],
            'mkey': 'name', 'v_range': [['7.0.0', '']]
        },
        'extensioncontroller_dataplan': {
            'params': ['adom', 'dataplan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/dataplan/{dataplan}',
                '/pm/config/global/obj/extension-controller/dataplan/{dataplan}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile': {
            'params': ['adom', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}'
            ],
            'mkey': 'id', 'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': ['adom', 'extender-profile', 'receiver'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_lanextension_backhaul': {
            'params': ['adom', 'backhaul', 'extender-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/backhaul/{backhaul}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'extensioncontroller_extenderprofile_lanextension_trafficsplitservices': {
            'params': ['adom', 'extender-profile', 'traffic-split-services'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/traffic-split-services/{traffic-split-serv'
                'ices}',
                '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/lan-extension/traffic-split-services/{traffic-split-services}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'extensioncontroller_extendervap': {
            'params': ['adom', 'extender-vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/extension-controller/extender-vap/{extender-vap}',
                '/pm/config/global/obj/extension-controller/extender-vap/{extender-vap}'
            ],
            'mkey': 'name', 'v_range': [['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'filefilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}',
                '/pm/config/global/obj/file-filter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['6.4.1', '']]
        },
        'filefilter_profile_rules': {
            'params': ['adom', 'profile', 'rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/file-filter/profile/{profile}/rules/{rules}',
                '/pm/config/global/obj/file-filter/profile/{profile}/rules/{rules}'
            ],
            'mkey': 'name', 'v_range': [['6.4.1', '']]
        },
        'firewall_accessproxy': {
            'params': ['access-proxy', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}'
            ],
            'mkey': 'name', 'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy6': {
            'params': ['access-proxy6', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway': {
            'params': ['access-proxy6', 'adom', 'api-gateway'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}'
            ],
            'mkey': 'id', 'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway6': {
            'params': ['access-proxy6', 'adom', 'api-gateway6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway6_realservers': {
            'params': ['access-proxy6', 'adom', 'api-gateway6', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway6_sslciphersuites': {
            'params': ['access-proxy6', 'adom', 'api-gateway6', 'ssl-cipher-suites'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': None, 'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway_realservers': {
            'params': ['access-proxy6', 'adom', 'api-gateway', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy6_apigateway_sslciphersuites': {
            'params': ['access-proxy6', 'adom', 'api-gateway', 'ssl-cipher-suites'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': None, 'v_range': [['7.2.1', '']]
        },
        'firewall_accessproxy_apigateway': {
            'params': ['access-proxy', 'adom', 'api-gateway'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}'
            ],
            'mkey': 'id', 'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy_apigateway6': {
            'params': ['access-proxy', 'adom', 'api-gateway6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}'
            ],
            'mkey': 'id', 'v_range': [['7.0.1', '']]
        },
        'firewall_accessproxy_apigateway6_realservers': {
            'params': ['access-proxy', 'adom', 'api-gateway6', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.0.1', '']]
        },
        'firewall_accessproxy_apigateway6_sslciphersuites': {
            'params': ['access-proxy', 'adom', 'api-gateway6', 'ssl-cipher-suites'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': None, 'v_range': [['7.0.1', '']]
        },
        'firewall_accessproxy_apigateway_realservers': {
            'params': ['access-proxy', 'adom', 'api-gateway', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy_apigateway_sslciphersuites': {
            'params': ['access-proxy', 'adom', 'api-gateway', 'ssl-cipher-suites'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': None, 'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy_realservers': {
            'params': ['access-proxy', 'adom', 'realservers'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxy_serverpubkeyauthsettings_certextension': {
            'params': ['access-proxy', 'adom', 'cert-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension/{cert-extension}',
                '/pm/config/global/obj/firewall/access-proxy/{access-proxy}/server-pubkey-auth-settings/cert-extension/{cert-extension}'
            ],
            'mkey': 'name', 'v_range': [['7.0.0', '']]
        },
        'firewall_accessproxysshclientcert': {
            'params': ['access-proxy-ssh-client-cert', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}',
                '/pm/config/global/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}'
            ],
            'mkey': 'name', 'v_range': [['7.4.2', '']]
        },
        'firewall_accessproxysshclientcert_certextension': {
            'params': ['access-proxy-ssh-client-cert', 'adom', 'cert-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension/{cert-extension}',
                '/pm/config/global/obj/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension/{cert-extension}'
            ],
            'mkey': 'name', 'v_range': [['7.4.2', '']]
        },
        'firewall_accessproxyvirtualhost': {
            'params': ['access-proxy-virtual-host', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}',
                '/pm/config/global/obj/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}'
            ],
            'mkey': 'name', 'v_range': [['7.0.1', '']]
        },
        'firewall_address': {
            'params': ['address', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}',
                '/pm/config/global/obj/firewall/address/{address}'
            ],
            'mkey': 'name'
        },
        'firewall_address6': {
            'params': ['address6', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}',
                '/pm/config/global/obj/firewall/address6/{address6}'
            ],
            'mkey': 'name'
        },
        'firewall_address6_dynamicmapping': {
            'params': ['address6', 'adom', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_address6_dynamicmapping_subnetsegment': {
            'params': ['address6', 'adom', 'dynamic_mapping', 'subnet-segment'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6/{address6}/dynamic_mapping/{dynamic_mapping}/subnet-segment/{subnet-segment}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_address6_list': {
            'params': ['address6', 'adom', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/list/{list}',
                '/pm/config/global/obj/firewall/address6/{address6}/list/{list}'
            ],
            'mkey': 'ip'
        },
        'firewall_address6_profilelist': {
            'params': ['address6', 'adom', 'profile-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/profile-list/{profile-list}',
                '/pm/config/global/obj/firewall/address6/{address6}/profile-list/{profile-list}'
            ],
            'mkey': None, 'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_address6_subnetsegment': {
            'params': ['address6', 'adom', 'subnet-segment'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6/{address6}/subnet-segment/{subnet-segment}'
            ],
            'mkey': 'name'
        },
        'firewall_address6_tagging': {
            'params': ['address6', 'adom', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6/{address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address6/{address6}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_address6template': {
            'params': ['address6-template', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}'
            ],
            'mkey': 'name'
        },
        'firewall_address6template_subnetsegment': {
            'params': ['address6-template', 'adom', 'subnet-segment'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}'
            ],
            'mkey': 'id'
        },
        'firewall_address6template_subnetsegment_values': {
            'params': ['address6-template', 'adom', 'subnet-segment', 'values'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}',
                '/pm/config/global/obj/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}'
            ],
            'mkey': 'name'
        },
        'firewall_address_dynamicmapping': {
            'params': ['address', 'adom', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/address/{address}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_address_list': {
            'params': ['address', 'adom', 'list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/list/{list}',
                '/pm/config/global/obj/firewall/address/{address}/list/{list}'
            ],
            'mkey': 'ip'
        },
        'firewall_address_profilelist': {
            'params': ['address', 'adom', 'profile-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/profile-list/{profile-list}',
                '/pm/config/global/obj/firewall/address/{address}/profile-list/{profile-list}'
            ],
            'mkey': None, 'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_address_tagging': {
            'params': ['address', 'adom', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/address/{address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/address/{address}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_addrgrp': {
            'params': ['addrgrp', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}'
            ],
            'mkey': 'name'
        },
        'firewall_addrgrp6': {
            'params': ['addrgrp6', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}'
            ],
            'mkey': 'name'
        },
        'firewall_addrgrp6_dynamicmapping': {
            'params': ['addrgrp6', 'adom', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_addrgrp6_tagging': {
            'params': ['addrgrp6', 'adom', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_addrgrp_dynamicmapping': {
            'params': ['addrgrp', 'adom', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_addrgrp_tagging': {
            'params': ['addrgrp', 'adom', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/addrgrp/{addrgrp}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_carrierendpointbwl': {
            'params': ['adom', 'carrier-endpoint-bwl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_carrierendpointbwl_entries': {
            'params': ['adom', 'carrier-endpoint-bwl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}',
                '/pm/config/global/obj/firewall/carrier-endpoint-bwl/{carrier-endpoint-bwl}/entries/{entries}'
            ],
            'mkey': 'carrier-endpoint', 'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_casbprofile': {
            'params': ['adom', 'casb-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_casbprofile_saasapplication': {
            'params': ['adom', 'casb-profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_casbprofile_saasapplication_accessrule': {
            'params': ['access-rule', 'adom', 'casb-profile', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/access-rule/{access-rule}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/access-rule/{access-rule}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_casbprofile_saasapplication_customcontrol': {
            'params': ['adom', 'casb-profile', 'custom-control', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_casbprofile_saasapplication_customcontrol_option': {
            'params': ['adom', 'casb-profile', 'custom-control', 'option', 'saas-application'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}/option/{'
                'option}',
                '/pm/config/global/obj/firewall/casb-profile/{casb-profile}/saas-application/{saas-application}/custom-control/{custom-control}/option/{optio'
                'n}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '7.4.1']]
        },
        'firewall_decryptedtrafficmirror': {
            'params': ['adom', 'decrypted-traffic-mirror'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/decrypted-traffic-mirror/{decrypted-traffic-mirror}',
                '/pm/config/global/obj/firewall/decrypted-traffic-mirror/{decrypted-traffic-mirror}'
            ],
            'mkey': 'name', 'v_range': [['6.4.1', '']]
        },
        'firewall_explicitproxyaddress': {
            'params': ['adom', 'explicit-proxy-address'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-address/{explicit-proxy-address}',
                '/pm/config/global/obj/firewall/explicit-proxy-address/{explicit-proxy-address}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_explicitproxyaddress_headergroup': {
            'params': ['adom', 'explicit-proxy-address', 'header-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-address/{explicit-proxy-address}/header-group/{header-group}',
                '/pm/config/global/obj/firewall/explicit-proxy-address/{explicit-proxy-address}/header-group/{header-group}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_explicitproxyaddrgrp': {
            'params': ['adom', 'explicit-proxy-addrgrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/explicit-proxy-addrgrp/{explicit-proxy-addrgrp}',
                '/pm/config/global/obj/firewall/explicit-proxy-addrgrp/{explicit-proxy-addrgrp}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '6.2.13']]
        },
        'firewall_gtp': {
            'params': ['adom', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}',
                '/pm/config/global/obj/firewall/gtp/{gtp}'
            ],
            'mkey': 'name'
        },
        'firewall_gtp_apn': {
            'params': ['adom', 'apn', 'gtp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/apn/{apn}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/apn/{apn}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_ieremovepolicy': {
            'params': ['adom', 'gtp', 'ie-remove-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ie-remove-policy/{ie-remove-policy}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_imsi': {
            'params': ['adom', 'gtp', 'imsi'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/imsi/{imsi}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/imsi/{imsi}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_ippolicy': {
            'params': ['adom', 'gtp', 'ip-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/ip-policy/{ip-policy}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_noippolicy': {
            'params': ['adom', 'gtp', 'noip-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/noip-policy/{noip-policy}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_perapnshaper': {
            'params': ['adom', 'gtp', 'per-apn-shaper'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/per-apn-shaper/{per-apn-shaper}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_policy': {
            'params': ['adom', 'gtp', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy/{policy}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy/{policy}'
            ],
            'mkey': 'id'
        },
        'firewall_gtp_policyv2': {
            'params': ['adom', 'gtp', 'policy-v2'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/gtp/{gtp}/policy-v2/{policy-v2}',
                '/pm/config/global/obj/firewall/gtp/{gtp}/policy-v2/{policy-v2}'
            ],
            'mkey': 'id', 'v_range': [['6.2.1', '']]
        },
        'firewall_identitybasedroute': {
            'params': ['adom', 'identity-based-route'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}'
            ],
            'mkey': 'name'
        },
        'firewall_identitybasedroute_rule': {
            'params': ['adom', 'identity-based-route', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}',
                '/pm/config/global/obj/firewall/identity-based-route/{identity-based-route}/rule/{rule}'
            ],
            'mkey': 'id'
        },
        'firewall_internetservice_entry': {
            'params': ['adom', 'entry'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service/entry/{entry}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'firewall_internetserviceaddition': {
            'params': ['adom', 'internet-service-addition'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}',
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}'
            ],
            'mkey': 'id', 'v_range': [['6.2.2', '']]
        },
        'firewall_internetserviceaddition_entry': {
            'params': ['adom', 'entry', 'internet-service-addition'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}'
            ],
            'mkey': 'id', 'v_range': [['6.2.2', '']]
        },
        'firewall_internetserviceaddition_entry_portrange': {
            'params': ['adom', 'entry', 'internet-service-addition', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range/{port-range}'
            ],
            'mkey': 'id', 'v_range': [['6.2.2', '']]
        },
        'firewall_internetservicecustom': {
            'params': ['adom', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}'
            ],
            'mkey': 'name'
        },
        'firewall_internetservicecustom_disableentry': {
            'params': ['adom', 'disable-entry', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'firewall_internetservicecustom_disableentry_iprange': {
            'params': ['adom', 'disable-entry', 'internet-service-custom', 'ip-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'firewall_internetservicecustom_entry': {
            'params': ['adom', 'entry', 'internet-service-custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}'
            ],
            'mkey': 'id'
        },
        'firewall_internetservicecustom_entry_portrange': {
            'params': ['adom', 'entry', 'internet-service-custom', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}/port-range/{port-range}'
            ],
            'mkey': 'id'
        },
        'firewall_internetservicecustomgroup': {
            'params': ['adom', 'internet-service-custom-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-custom-group/{internet-service-custom-group}',
                '/pm/config/global/obj/firewall/internet-service-custom-group/{internet-service-custom-group}'
            ],
            'mkey': 'name'
        },
        'firewall_internetserviceextension': {
            'params': ['adom', 'internet-service-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}'
            ],
            'mkey': 'id', 'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_disableentry': {
            'params': ['adom', 'disable-entry', 'internet-service-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}'
            ],
            'mkey': 'id', 'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_disableentry_ip6range': {
            'params': ['adom', 'disable-entry', 'internet-service-extension', 'ip6-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-range/{ip6-ran'
                'ge}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-range/{ip6-range}'
            ],
            'mkey': 'id', 'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_disableentry_iprange': {
            'params': ['adom', 'disable-entry', 'internet-service-extension', 'ip-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-range/{ip-range'
                '}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-range/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_disableentry_portrange': {
            'params': ['adom', 'disable-entry', 'internet-service-extension', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-range/{port-r'
                'ange}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-range/{port-range}'
            ],
            'mkey': 'id', 'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_entry': {
            'params': ['adom', 'entry', 'internet-service-extension'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}'
            ],
            'mkey': 'id', 'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetserviceextension_entry_portrange': {
            'params': ['adom', 'entry', 'internet-service-extension', 'port-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range/{port-range}',
                '/pm/config/global/obj/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range/{port-range}'
            ],
            'mkey': 'id', 'v_range': [['7.4.7', '7.4.7']]
        },
        'firewall_internetservicegroup': {
            'params': ['adom', 'internet-service-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-group/{internet-service-group}',
                '/pm/config/global/obj/firewall/internet-service-group/{internet-service-group}'
            ],
            'mkey': 'name'
        },
        'firewall_internetservicename': {
            'params': ['adom', 'internet-service-name'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/internet-service-name/{internet-service-name}',
                '/pm/config/global/obj/firewall/internet-service-name/{internet-service-name}'
            ],
            'mkey': 'name', 'v_range': [['6.4.0', '']]
        },
        'firewall_ippool': {
            'params': ['adom', 'ippool'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}',
                '/pm/config/global/obj/firewall/ippool/{ippool}'
            ],
            'mkey': 'name'
        },
        'firewall_ippool6': {
            'params': ['adom', 'ippool6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}'
            ],
            'mkey': 'name'
        },
        'firewall_ippool6_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'ippool6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool6/{ippool6}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_ippool_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'ippool'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/ippool/{ippool}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_ippoolgrp': {
            'params': ['adom', 'ippool-grp', 'ippool_grp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ippool-grp/{ippool-grp}',
                '/pm/config/adom/{adom}/obj/firewall/ippool_grp/{ippool_grp}',
                '/pm/config/global/obj/firewall/ippool-grp/{ippool-grp}',
                '/pm/config/global/obj/firewall/ippool_grp/{ippool_grp}'
            ],
            'mkey': 'name', 'v_range': [['7.6.3', '']]
        },
        'firewall_ldbmonitor': {
            'params': ['adom', 'ldb-monitor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ldb-monitor/{ldb-monitor}',
                '/pm/config/global/obj/firewall/ldb-monitor/{ldb-monitor}'
            ],
            'mkey': 'name'
        },
        'firewall_mmsprofile': {
            'params': ['adom', 'mms-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_mmsprofile_notifmsisdn': {
            'params': ['adom', 'mms-profile', 'notif-msisdn'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}',
                '/pm/config/global/obj/firewall/mms-profile/{mms-profile}/notif-msisdn/{notif-msisdn}'
            ],
            'mkey': 'msisdn', 'v_range': [['6.0.0', '7.6.2']]
        },
        'firewall_multicastaddress': {
            'params': ['adom', 'multicast-address'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}'
            ],
            'mkey': 'name'
        },
        'firewall_multicastaddress6': {
            'params': ['adom', 'multicast-address6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}'
            ],
            'mkey': 'name'
        },
        'firewall_multicastaddress6_tagging': {
            'params': ['adom', 'multicast-address6', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_multicastaddress_tagging': {
            'params': ['adom', 'multicast-address', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/multicast-address/{multicast-address}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_networkservicedynamic': {
            'params': ['adom', 'network-service-dynamic'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/network-service-dynamic/{network-service-dynamic}',
                '/pm/config/global/obj/firewall/network-service-dynamic/{network-service-dynamic}'
            ],
            'mkey': 'id', 'v_range': [['7.2.2', '']]
        },
        'firewall_profilegroup': {
            'params': ['adom', 'profile-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-group/{profile-group}',
                '/pm/config/global/obj/firewall/profile-group/{profile-group}'
            ],
            'mkey': 'name'
        },
        'firewall_profileprotocoloptions': {
            'params': ['adom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}'
            ],
            'mkey': 'name'
        },
        'firewall_profileprotocoloptions_cifs_filefilter_entries': {
            'params': ['adom', 'entries', 'profile-protocol-options'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/file-filter/entries/{entries}'
            ],
            'mkey': None, 'v_range': [['6.4.2', '']]
        },
        'firewall_profileprotocoloptions_cifs_serverkeytab': {
            'params': ['adom', 'profile-protocol-options', 'server-keytab'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab/{server-keytab}',
                '/pm/config/global/obj/firewall/profile-protocol-options/{profile-protocol-options}/cifs/server-keytab/{server-keytab}'
            ],
            'mkey': None, 'v_range': [['6.4.2', '']]
        },
        'firewall_proxyaddress': {
            'params': ['adom', 'proxy-address'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}'
            ],
            'mkey': 'name'
        },
        'firewall_proxyaddress_headergroup': {
            'params': ['adom', 'header-group', 'proxy-address'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/header-group/{header-group}'
            ],
            'mkey': 'id'
        },
        'firewall_proxyaddress_tagging': {
            'params': ['adom', 'proxy-address', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-address/{proxy-address}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_proxyaddrgrp': {
            'params': ['adom', 'proxy-addrgrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}'
            ],
            'mkey': 'name'
        },
        'firewall_proxyaddrgrp_tagging': {
            'params': ['adom', 'proxy-addrgrp', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}',
                '/pm/config/global/obj/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}'
            ],
            'mkey': 'name'
        },
        'firewall_schedule_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/group/{group}',
                '/pm/config/global/obj/firewall/schedule/group/{group}'
            ],
            'mkey': 'name'
        },
        'firewall_schedule_onetime': {
            'params': ['adom', 'onetime'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/onetime/{onetime}',
                '/pm/config/global/obj/firewall/schedule/onetime/{onetime}'
            ],
            'mkey': 'name'
        },
        'firewall_schedule_recurring': {
            'params': ['adom', 'recurring'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/schedule/recurring/{recurring}',
                '/pm/config/global/obj/firewall/schedule/recurring/{recurring}'
            ],
            'mkey': 'name'
        },
        'firewall_service_category': {
            'params': ['adom', 'category'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/category/{category}',
                '/pm/config/global/obj/firewall/service/category/{category}'
            ],
            'mkey': 'name'
        },
        'firewall_service_custom': {
            'params': ['adom', 'custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/custom/{custom}',
                '/pm/config/global/obj/firewall/service/custom/{custom}'
            ],
            'mkey': 'name'
        },
        'firewall_service_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/service/group/{group}',
                '/pm/config/global/obj/firewall/service/group/{group}'
            ],
            'mkey': 'name'
        },
        'firewall_shaper_peripshaper': {
            'params': ['adom', 'per-ip-shaper'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}',
                '/pm/config/global/obj/firewall/shaper/per-ip-shaper/{per-ip-shaper}'
            ],
            'mkey': 'name'
        },
        'firewall_shaper_trafficshaper': {
            'params': ['adom', 'traffic-shaper'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper/{traffic-shaper}',
                '/pm/config/global/obj/firewall/shaper/traffic-shaper/{traffic-shaper}'
            ],
            'mkey': 'name'
        },
        'firewall_shapingprofile': {
            'params': ['adom', 'shaping-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}'
            ],
            'mkey': 'profile-name'
        },
        'firewall_shapingprofile_shapingentries': {
            'params': ['adom', 'shaping-entries', 'shaping-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}',
                '/pm/config/global/obj/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}'
            ],
            'mkey': 'id'
        },
        'firewall_ssh_localca': {
            'params': ['adom', 'local-ca'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssh/local-ca/{local-ca}',
                '/pm/config/global/obj/firewall/ssh/local-ca/{local-ca}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '']]
        },
        'firewall_sslsshprofile': {
            'params': ['adom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
            ],
            'mkey': 'name'
        },
        'firewall_sslsshprofile_echoutersni': {
            'params': ['adom', 'ech-outer-sni', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ech-outer-sni/{ech-outer-sni}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ech-outer-sni/{ech-outer-sni}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'firewall_sslsshprofile_sslexempt': {
            'params': ['adom', 'ssl-exempt', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}'
            ],
            'mkey': 'id'
        },
        'firewall_sslsshprofile_sslserver': {
            'params': ['adom', 'ssl-server', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}',
                '/pm/config/global/obj/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}'
            ],
            'mkey': 'id'
        },
        'firewall_trafficclass': {
            'params': ['adom', 'traffic-class'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/traffic-class/{traffic-class}',
                '/pm/config/global/obj/firewall/traffic-class/{traffic-class}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '']]
        },
        'firewall_vip': {
            'params': ['adom', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}',
                '/pm/config/global/obj/firewall/vip/{vip}'
            ],
            'mkey': 'name'
        },
        'firewall_vip46': {
            'params': ['adom', 'vip46'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}',
                '/pm/config/global/obj/firewall/vip46/{vip46}'
            ],
            'mkey': 'name'
        },
        'firewall_vip46_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vip46'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip46_realservers': {
            'params': ['adom', 'realservers', 'vip46'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip46/{vip46}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip46/{vip46}/realservers/{realservers}'
            ],
            'mkey': 'id'
        },
        'firewall_vip6': {
            'params': ['adom', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}',
                '/pm/config/global/obj/firewall/vip6/{vip6}'
            ],
            'mkey': 'name'
        },
        'firewall_vip64': {
            'params': ['adom', 'vip64'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}',
                '/pm/config/global/obj/firewall/vip64/{vip64}'
            ],
            'mkey': 'name'
        },
        'firewall_vip64_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vip64'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip64_realservers': {
            'params': ['adom', 'realservers', 'vip64'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip64/{vip64}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip64/{vip64}/realservers/{realservers}'
            ],
            'mkey': 'id'
        },
        'firewall_vip6_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip6_dynamicmapping_realservers': {
            'params': ['adom', 'dynamic_mapping', 'realservers', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip6_dynamicmapping_sslciphersuites': {
            'params': ['adom', 'dynamic_mapping', 'ssl-cipher-suites', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': None, 'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip6_realservers': {
            'params': ['adom', 'realservers', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/realservers/{realservers}'
            ],
            'mkey': 'id'
        },
        'firewall_vip6_sslciphersuites': {
            'params': ['adom', 'ssl-cipher-suites', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': 'priority'
        },
        'firewall_vip6_sslserverciphersuites': {
            'params': ['adom', 'ssl-server-cipher-suites', 'vip6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip6/{vip6}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
            ],
            'mkey': 'priority'
        },
        'firewall_vip_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip_dynamicmapping_realservers': {
            'params': ['adom', 'dynamic_mapping', 'realservers', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/realservers/{realservers}'
            ],
            'mkey': 'seq', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip_dynamicmapping_sslciphersuites': {
            'params': ['adom', 'dynamic_mapping', 'ssl-cipher-suites', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/dynamic_mapping/{dynamic_mapping}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_vip_gslbpublicips': {
            'params': ['adom', 'gslb-public-ips', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/gslb-public-ips/{gslb-public-ips}',
                '/pm/config/global/obj/firewall/vip/{vip}/gslb-public-ips/{gslb-public-ips}'
            ],
            'mkey': None, 'v_range': [['7.4.2', '']]
        },
        'firewall_vip_realservers': {
            'params': ['adom', 'realservers', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/realservers/{realservers}',
                '/pm/config/global/obj/firewall/vip/{vip}/realservers/{realservers}'
            ],
            'mkey': 'seq'
        },
        'firewall_vip_sslciphersuites': {
            'params': ['adom', 'ssl-cipher-suites', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': 'id'
        },
        'firewall_vip_sslserverciphersuites': {
            'params': ['adom', 'ssl-server-cipher-suites', 'vip'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}',
                '/pm/config/global/obj/firewall/vip/{vip}/ssl-server-cipher-suites/{ssl-server-cipher-suites}'
            ],
            'mkey': 'priority'
        },
        'firewall_vipgrp': {
            'params': ['adom', 'vipgrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}'
            ],
            'mkey': 'name'
        },
        'firewall_vipgrp46': {
            'params': ['adom', 'vipgrp46'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp46/{vipgrp46}',
                '/pm/config/global/obj/firewall/vipgrp46/{vipgrp46}'
            ],
            'mkey': 'name'
        },
        'firewall_vipgrp6': {
            'params': ['adom', 'vipgrp6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp6/{vipgrp6}',
                '/pm/config/global/obj/firewall/vipgrp6/{vipgrp6}'
            ],
            'mkey': 'name'
        },
        'firewall_vipgrp64': {
            'params': ['adom', 'vipgrp64'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp64/{vipgrp64}',
                '/pm/config/global/obj/firewall/vipgrp64/{vipgrp64}'
            ],
            'mkey': 'name'
        },
        'firewall_vipgrp_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vipgrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/firewall/vipgrp/{vipgrp}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'firewall_wildcardfqdn_custom': {
            'params': ['adom', 'custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom/{custom}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/custom/{custom}'
            ],
            'mkey': 'name'
        },
        'firewall_wildcardfqdn_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group/{group}',
                '/pm/config/global/obj/firewall/wildcard-fqdn/group/{group}'
            ],
            'mkey': 'name'
        },
        'fmg_device_blueprint': {
            'params': ['adom', 'blueprint'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/device/blueprint/{blueprint}',
                '/pm/config/global/obj/fmg/device/blueprint/{blueprint}'
            ],
            'mkey': 'name', 'v_range': [['7.2.0', '']]
        },
        'fmg_fabric_authorization_template': {
            'params': ['adom', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/fabric/authorization/template/{template}',
                '/pm/config/global/obj/fmg/fabric/authorization/template/{template}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'fmg_fabric_authorization_template_platforms': {
            'params': ['adom', 'platforms', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/fabric/authorization/template/{template}/platforms/{platforms}',
                '/pm/config/global/obj/fmg/fabric/authorization/template/{template}/platforms/{platforms}'
            ],
            'mkey': None, 'v_range': [['7.2.1', '']]
        },
        'fmg_variable': {
            'params': ['adom', 'variable'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/variable/{variable}',
                '/pm/config/global/obj/fmg/variable/{variable}'
            ],
            'mkey': 'name', 'v_range': [['7.2.0', '']]
        },
        'fmg_variable_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'variable'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fmg/variable/{variable}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/fmg/variable/{variable}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': None, 'v_range': [['7.2.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan': {
            'params': ['adom', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}',
                '/pm/config/global/obj/fsp/vlan/{vlan}'
            ],
            'mkey': 'name'
        },
        'fsp_vlan_dhcpserver_excluderange': {
            'params': ['adom', 'exclude-range', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/exclude-range/{exclude-range}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dhcpserver_iprange': {
            'params': ['adom', 'ip-range', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dhcpserver_options': {
            'params': ['adom', 'options', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/options/{options}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dhcpserver_reservedaddress': {
            'params': ['adom', 'reserved-address', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dhcp-server/reserved-address/{reserved-address}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': None, 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_dhcpserver_excluderange': {
            'params': ['adom', 'dynamic_mapping', 'exclude-range', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/exclude-range/{exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_dhcpserver_iprange': {
            'params': ['adom', 'dynamic_mapping', 'ip-range', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/ip-range/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_dhcpserver_options': {
            'params': ['adom', 'dynamic_mapping', 'options', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/options/{options}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_dhcpserver_reservedaddress': {
            'params': ['adom', 'dynamic_mapping', 'reserved-address', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/reserved-address/{reserved-address}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6delegatedprefixlist': {
            'params': ['adom', 'dynamic_mapping', 'ip6-delegated-prefix-list', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-'
                'list}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6extraaddr': {
            'params': ['adom', 'dynamic_mapping', 'ip6-extra-addr', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_ip6prefixlist': {
            'params': ['adom', 'dynamic_mapping', 'ip6-prefix-list', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_ipv6_vrrp6': {
            'params': ['adom', 'dynamic_mapping', 'vlan', 'vrrp6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6/{vrrp6}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/ipv6/vrrp6/{vrrp6}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_secondaryip': {
            'params': ['adom', 'dynamic_mapping', 'secondaryip', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip/{secondaryip}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/secondaryip/{secondaryip}'
            ],
            'mkey': 'id', 'v_range': [['6.2.3', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_vrrp': {
            'params': ['adom', 'dynamic_mapping', 'vlan', 'vrrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}'
            ],
            'mkey': None, 'v_range': [['7.4.0', '7.4.0']]
        },
        'fsp_vlan_dynamicmapping_interface_vrrp_proxyarp': {
            'params': ['adom', 'dynamic_mapping', 'proxy-arp', 'vlan', 'vrrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}'
            ],
            'mkey': 'id', 'v_range': [['7.4.0', '7.4.0']]
        },
        'fsp_vlan_interface_ipv6_ip6delegatedprefixlist': {
            'params': ['adom', 'ip6-delegated-prefix-list', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '']]
        },
        'fsp_vlan_interface_ipv6_ip6extraaddr': {
            'params': ['adom', 'ip6-extra-addr', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '']]
        },
        'fsp_vlan_interface_ipv6_ip6prefixlist': {
            'params': ['adom', 'ip6-prefix-list', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '']]
        },
        'fsp_vlan_interface_ipv6_vrrp6': {
            'params': ['adom', 'vlan', 'vrrp6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6/{vrrp6}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/ipv6/vrrp6/{vrrp6}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '']]
        },
        'fsp_vlan_interface_secondaryip': {
            'params': ['adom', 'secondaryip', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/secondaryip/{secondaryip}'
            ],
            'mkey': 'id'
        },
        'fsp_vlan_interface_vrrp': {
            'params': ['adom', 'vlan', 'vrrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}'
            ],
            'mkey': 'vrid'
        },
        'fsp_vlan_interface_vrrp_proxyarp': {
            'params': ['adom', 'proxy-arp', 'vlan', 'vrrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}',
                '/pm/config/global/obj/fsp/vlan/{vlan}/interface/vrrp/{vrrp}/proxy-arp/{proxy-arp}'
            ],
            'mkey': 'id', 'v_range': [['7.4.0', '']]
        },
        'gtp_apn': {
            'params': ['adom', 'apn'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apn/{apn}',
                '/pm/config/global/obj/gtp/apn/{apn}'
            ],
            'mkey': 'name'
        },
        'gtp_apngrp': {
            'params': ['adom', 'apngrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/apngrp/{apngrp}',
                '/pm/config/global/obj/gtp/apngrp/{apngrp}'
            ],
            'mkey': 'name'
        },
        'gtp_ieallowlist': {
            'params': ['adom', 'ie-allow-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-allow-list/{ie-allow-list}',
                '/pm/config/global/obj/gtp/ie-allow-list/{ie-allow-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.9', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.2', '']]
        },
        'gtp_ieallowlist_entries': {
            'params': ['adom', 'entries', 'ie-allow-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-allow-list/{ie-allow-list}/entries/{entries}',
                '/pm/config/global/obj/gtp/ie-allow-list/{ie-allow-list}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.2.9', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.2', '']]
        },
        'gtp_iewhitelist': {
            'params': ['adom', 'ie-white-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}'
            ],
            'mkey': 'name'
        },
        'gtp_iewhitelist_entries': {
            'params': ['adom', 'entries', 'ie-white-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}',
                '/pm/config/global/obj/gtp/ie-white-list/{ie-white-list}/entries/{entries}'
            ],
            'mkey': 'id'
        },
        'gtp_messagefilterv0v1': {
            'params': ['adom', 'message-filter-v0v1'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1/{message-filter-v0v1}',
                '/pm/config/global/obj/gtp/message-filter-v0v1/{message-filter-v0v1}'
            ],
            'mkey': 'name'
        },
        'gtp_messagefilterv2': {
            'params': ['adom', 'message-filter-v2'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/message-filter-v2/{message-filter-v2}',
                '/pm/config/global/obj/gtp/message-filter-v2/{message-filter-v2}'
            ],
            'mkey': 'name'
        },
        'gtp_rattimeoutprofile': {
            'params': ['adom', 'rat-timeout-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/rat-timeout-profile/{rat-timeout-profile}',
                '/pm/config/global/obj/gtp/rat-timeout-profile/{rat-timeout-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.7', '7.4.7']]
        },
        'gtp_tunnellimit': {
            'params': ['adom', 'tunnel-limit'],
            'urls': [
                '/pm/config/adom/{adom}/obj/gtp/tunnel-limit/{tunnel-limit}',
                '/pm/config/global/obj/gtp/tunnel-limit/{tunnel-limit}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqp3gppcellular': {
            'params': ['adom', 'anqp-3gpp-cellular'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqp3gppcellular_mccmnclist': {
            'params': ['adom', 'anqp-3gpp-cellular', 'mcc-mnc-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}'
            ],
            'mkey': 'id'
        },
        'hotspot20_anqpipaddresstype': {
            'params': ['adom', 'anqp-ip-address-type'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqpnairealm': {
            'params': ['adom', 'anqp-nai-realm'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqpnairealm_nailist': {
            'params': ['adom', 'anqp-nai-realm', 'nai-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqpnairealm_nailist_eapmethod': {
            'params': ['adom', 'anqp-nai-realm', 'eap-method', 'nai-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}'
            ],
            'mkey': 'index'
        },
        'hotspot20_anqpnairealm_nailist_eapmethod_authparam': {
            'params': ['adom', 'anqp-nai-realm', 'auth-param', 'eap-method', 'nai-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-pa'
                'ram/{auth-param}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-method}/auth-param/{'
                'auth-param}'
            ],
            'mkey': 'index'
        },
        'hotspot20_anqpnetworkauthtype': {
            'params': ['adom', 'anqp-network-auth-type'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqproamingconsortium': {
            'params': ['adom', 'anqp-roaming-consortium'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqproamingconsortium_oilist': {
            'params': ['adom', 'anqp-roaming-consortium', 'oi-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}'
            ],
            'mkey': 'index'
        },
        'hotspot20_anqpvenuename': {
            'params': ['adom', 'anqp-venue-name'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}'
            ],
            'mkey': 'name'
        },
        'hotspot20_anqpvenuename_valuelist': {
            'params': ['adom', 'anqp-venue-name', 'value-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}'
            ],
            'mkey': 'index'
        },
        'hotspot20_anqpvenueurl': {
            'params': ['adom', 'anqp-venue-url'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'hotspot20_anqpvenueurl_valuelist': {
            'params': ['adom', 'anqp-venue-url', 'value-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}'
            ],
            'mkey': None, 'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpadviceofcharge': {
            'params': ['adom', 'h2qp-advice-of-charge'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpadviceofcharge_aoclist': {
            'params': ['adom', 'aoc-list', 'h2qp-advice-of-charge'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpadviceofcharge_aoclist_planinfo': {
            'params': ['adom', 'aoc-list', 'h2qp-advice-of-charge', 'plan-info'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info/{plan-i'
                'nfo}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-info/{plan-info}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpconncapability': {
            'params': ['adom', 'h2qp-conn-capability'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}'
            ],
            'mkey': 'name'
        },
        'hotspot20_h2qpoperatorname': {
            'params': ['adom', 'h2qp-operator-name'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}'
            ],
            'mkey': 'name'
        },
        'hotspot20_h2qpoperatorname_valuelist': {
            'params': ['adom', 'h2qp-operator-name', 'value-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}'
            ],
            'mkey': 'index'
        },
        'hotspot20_h2qposuprovider': {
            'params': ['adom', 'h2qp-osu-provider'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}'
            ],
            'mkey': 'name'
        },
        'hotspot20_h2qposuprovider_friendlyname': {
            'params': ['adom', 'friendly-name', 'h2qp-osu-provider'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}'
            ],
            'mkey': 'index'
        },
        'hotspot20_h2qposuprovider_servicedescription': {
            'params': ['adom', 'h2qp-osu-provider', 'service-description'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-description}'
            ],
            'mkey': 'service-id'
        },
        'hotspot20_h2qposuprovidernai': {
            'params': ['adom', 'h2qp-osu-provider-nai'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qposuprovidernai_nailist': {
            'params': ['adom', 'h2qp-osu-provider-nai', 'nai-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qptermsandconditions': {
            'params': ['adom', 'h2qp-terms-and-conditions'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'hotspot20_h2qpwanmetric': {
            'params': ['adom', 'h2qp-wan-metric'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}',
                '/pm/config/global/obj/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}'
            ],
            'mkey': 'name'
        },
        'hotspot20_hsprofile': {
            'params': ['adom', 'hs-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}',
                '/pm/config/global/obj/wireless-controller/hotspot20/hs-profile/{hs-profile}'
            ],
            'mkey': 'name'
        },
        'hotspot20_icon': {
            'params': ['adom', 'icon'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon/{icon}',
                '/pm/config/global/obj/wireless-controller/hotspot20/icon/{icon}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'hotspot20_icon_iconlist': {
            'params': ['adom', 'icon', 'icon-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}',
                '/pm/config/global/obj/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'hotspot20_qosmap': {
            'params': ['adom', 'qos-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}'
            ],
            'mkey': 'name'
        },
        'hotspot20_qosmap_dscpexcept': {
            'params': ['adom', 'dscp-except', 'qos-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}'
            ],
            'mkey': 'index'
        },
        'hotspot20_qosmap_dscprange': {
            'params': ['adom', 'dscp-range', 'qos-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}',
                '/pm/config/global/obj/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}'
            ],
            'mkey': 'index'
        },
        'icap_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}',
                '/pm/config/global/obj/icap/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'icap_profile_icapheaders': {
            'params': ['adom', 'icap-headers', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/icap-headers/{icap-headers}',
                '/pm/config/global/obj/icap/profile/{profile}/icap-headers/{icap-headers}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '']]
        },
        'icap_profile_respmodforwardrules': {
            'params': ['adom', 'profile', 'respmod-forward-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}',
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}'
            ],
            'mkey': 'name', 'v_range': [['6.4.0', '']]
        },
        'icap_profile_respmodforwardrules_headergroup': {
            'params': ['adom', 'header-group', 'profile', 'respmod-forward-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group/{header-group}',
                '/pm/config/global/obj/icap/profile/{profile}/respmod-forward-rules/{respmod-forward-rules}/header-group/{header-group}'
            ],
            'mkey': 'id', 'v_range': [['6.4.0', '']]
        },
        'icap_server': {
            'params': ['adom', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/server/{server}',
                '/pm/config/global/obj/icap/server/{server}'
            ],
            'mkey': 'name'
        },
        'icap_servergroup': {
            'params': ['adom', 'server-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/server-group/{server-group}',
                '/pm/config/global/obj/icap/server-group/{server-group}'
            ],
            'mkey': 'name', 'v_range': [['7.6.3', '']]
        },
        'icap_servergroup_serverlist': {
            'params': ['adom', 'server-group', 'server-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/icap/server-group/{server-group}/server-list/{server-list}',
                '/pm/config/global/obj/icap/server-group/{server-group}/server-list/{server-list}'
            ],
            'mkey': 'name', 'v_range': [['7.6.3', '']]
        },
        'ips_baseline_sensor': {
            'params': ['adom', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}'
            ],
            'mkey': 'name', 'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_entries': {
            'params': ['adom', 'entries', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_entries_exemptip': {
            'params': ['adom', 'entries', 'exempt-ip', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}'
            ],
            'mkey': 'id', 'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_filter': {
            'params': ['adom', 'filter', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/filter/{filter}'
            ],
            'mkey': 'name', 'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_override': {
            'params': ['adom', 'override', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/override/{override}'
            ],
            'mkey': None, 'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_baseline_sensor_override_exemptip': {
            'params': ['adom', 'exempt-ip', 'override', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/baseline/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}'
            ],
            'mkey': 'id', 'v_range': [['7.0.1', '7.0.2']]
        },
        'ips_custom': {
            'params': ['adom', 'custom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ips/custom/{custom}',
                '/pm/config/global/obj/ips/custom/{custom}'
            ],
            'mkey': 'tag'
        },
        'ips_sensor': {
            'params': ['adom', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}',
                '/pm/config/global/obj/ips/sensor/{sensor}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'ips_sensor_entries': {
            'params': ['adom', 'entries', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries/{entries}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.0.3', '']]
        },
        'ips_sensor_entries_exemptip': {
            'params': ['adom', 'entries', 'exempt-ip', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}'
            ],
            'mkey': 'id', 'v_range': [['7.0.3', '']]
        },
        'ips_sensor_filter': {
            'params': ['adom', 'filter', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/filter/{filter}',
                '/pm/config/global/obj/ips/sensor/{sensor}/filter/{filter}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'ips_sensor_override': {
            'params': ['adom', 'override', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override/{override}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override/{override}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}'
            ],
            'mkey': 'rule-id', 'v_range': [['7.0.3', '']]
        },
        'ips_sensor_override_exemptip': {
            'params': ['adom', 'exempt-ip', 'override', 'sensor'],
            'urls': [
                '/pm/config/adom/{adom}/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/adom/{adom}/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/global/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}',
                '/pm/config/global/obj/ips/sensor/{sensor}/override/{override}/exempt-ip/{exempt-ip}'
            ],
            'mkey': 'id', 'v_range': [['7.0.3', '']]
        },
        'log_customfield': {
            'params': ['adom', 'custom-field'],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/custom-field/{custom-field}',
                '/pm/config/global/obj/log/custom-field/{custom-field}'
            ],
            'mkey': 'id'
        },
        'log_npuserver_servergroup': {
            'params': ['adom', 'server-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/npu-server/server-group/{server-group}',
                '/pm/config/global/obj/log/npu-server/server-group/{server-group}'
            ],
            'mkey': None, 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'log_npuserver_serverinfo': {
            'params': ['adom', 'server-info'],
            'urls': [
                '/pm/config/adom/{adom}/obj/log/npu-server/server-info/{server-info}',
                '/pm/config/global/obj/log/npu-server/server-info/{server-info}'
            ],
            'mkey': 'id', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'mpskprofile': {
            'params': ['adom', 'mpsk-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}'
            ],
            'mkey': 'name', 'v_range': [['6.4.2', '']]
        },
        'mpskprofile_mpskgroup': {
            'params': ['adom', 'mpsk-group', 'mpsk-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'mkey': 'name', 'v_range': [['6.4.2', '']]
        },
        'mpskprofile_mpskgroup_mpskkey': {
            'params': ['adom', 'mpsk-group', 'mpsk-key', 'mpsk-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}',
                '/pm/config/global/obj/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'mkey': 'name', 'v_range': [['6.4.2', '']]
        },
        'nacprofile': {
            'params': ['adom', 'nac-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/nac-profile/{nac-profile}',
                '/pm/config/global/obj/wireless-controller/nac-profile/{nac-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'pkg_authentication_rule': {
            'params': ['adom', 'pkg', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/authentication/rule/{rule}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '']]
        },
        'pkg_central_dnat': {
            'params': ['adom', 'dnat', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat/{dnat}'
            ],
            'mkey': 'name'
        },
        'pkg_central_dnat6': {
            'params': ['adom', 'dnat6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/central/dnat6/{dnat6}'
            ],
            'mkey': 'name', 'v_range': [['6.4.2', '']]
        },
        'pkg_firewall_acl': {
            'params': ['acl', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl/{acl}'
            ],
            'mkey': 'policyid', 'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_acl6': {
            'params': ['acl6', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl6/{acl6}'
            ],
            'mkey': 'policyid', 'v_range': [['7.2.0', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_centralsnatmap': {
            'params': ['adom', 'central-snat-map', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/central-snat-map/{central-snat-map}'
            ],
            'mkey': 'policyid'
        },
        'pkg_firewall_consolidated_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/consolidated/policy/{policy}'
            ],
            'mkey': 'policyid', 'v_range': [['6.2.0', '7.6.2']]
        },
        'pkg_firewall_dospolicy': {
            'params': ['DoS-policy', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}'
            ],
            'mkey': 'policyid'
        },
        'pkg_firewall_dospolicy6': {
            'params': ['DoS-policy6', 'adom', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}'
            ],
            'mkey': 'policyid'
        },
        'pkg_firewall_dospolicy6_anomaly': {
            'params': ['DoS-policy6', 'adom', 'anomaly', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6/{DoS-policy6}/anomaly/{anomaly}'
            ],
            'mkey': 'name'
        },
        'pkg_firewall_dospolicy_anomaly': {
            'params': ['DoS-policy', 'adom', 'anomaly', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{DoS-policy}/anomaly/{anomaly}'
            ],
            'mkey': 'name'
        },
        'pkg_firewall_explicitproxypolicy': {
            'params': ['adom', 'explicit-proxy-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['6.2.0', '6.2.13']]
        },
        'pkg_firewall_explicitproxypolicy_identitybasedpolicy': {
            'params': ['adom', 'explicit-proxy-policy', 'identity-based-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/explicit-proxy-policy/{explicit-proxy-policy}/identity-based-policy/{identity-based-policy}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.13']]
        },
        'pkg_firewall_hyperscalepolicy': {
            'params': ['adom', 'hyperscale-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy/{hyperscale-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_hyperscalepolicy46': {
            'params': ['adom', 'hyperscale-policy46', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy46/{hyperscale-policy46}'
            ],
            'mkey': 'policyid', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_hyperscalepolicy6': {
            'params': ['adom', 'hyperscale-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy6/{hyperscale-policy6}'
            ],
            'mkey': 'policyid', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '7.6.2']]
        },
        'pkg_firewall_hyperscalepolicy64': {
            'params': ['adom', 'hyperscale-policy64', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/hyperscale-policy64/{hyperscale-policy64}'
            ],
            'mkey': 'policyid', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.0'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_interfacepolicy': {
            'params': ['adom', 'interface-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy/{interface-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_interfacepolicy6': {
            'params': ['adom', 'interface-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy6/{interface-policy6}'
            ],
            'mkey': 'policyid', 'v_range': [['6.0.0', '7.2.2'], ['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'pkg_firewall_localinpolicy': {
            'params': ['adom', 'local-in-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy/{local-in-policy}'
            ],
            'mkey': 'policyid'
        },
        'pkg_firewall_localinpolicy6': {
            'params': ['adom', 'local-in-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy6/{local-in-policy6}'
            ],
            'mkey': 'policyid'
        },
        'pkg_firewall_multicastpolicy': {
            'params': ['adom', 'multicast-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy/{multicast-policy}'
            ],
            'mkey': 'id'
        },
        'pkg_firewall_multicastpolicy6': {
            'params': ['adom', 'multicast-policy6', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy6/{multicast-policy6}'
            ],
            'mkey': 'id'
        },
        'pkg_firewall_policy': {
            'params': ['adom', 'pkg', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}'
            ],
            'mkey': 'policyid'
        },
        'pkg_firewall_policy46': {
            'params': ['adom', 'pkg', 'policy46'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy46/{policy46}'
            ],
            'mkey': 'policyid'
        },
        'pkg_firewall_policy6': {
            'params': ['adom', 'pkg', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy6/{policy6}'
            ],
            'mkey': 'policyid', 'v_range': [['6.0.0', '7.6.2']]
        },
        'pkg_firewall_policy64': {
            'params': ['adom', 'pkg', 'policy64'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy64/{policy64}'
            ],
            'mkey': 'policyid'
        },
        'pkg_firewall_policy_vpndstnode': {
            'params': ['adom', 'pkg', 'policy', 'vpn_dst_node'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_dst_node/{vpn_dst_node}'
            ],
            'mkey': 'seq', 'v_range': [['6.0.0', '7.0.2']]
        },
        'pkg_firewall_policy_vpnsrcnode': {
            'params': ['adom', 'pkg', 'policy', 'vpn_src_node'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/vpn_src_node/{vpn_src_node}'
            ],
            'mkey': 'seq', 'v_range': [['6.0.0', '7.0.2']]
        },
        'pkg_firewall_proxypolicy': {
            'params': ['adom', 'pkg', 'proxy-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy/{proxy-policy}'
            ],
            'mkey': 'policyid'
        },
        'pkg_firewall_securitypolicy': {
            'params': ['adom', 'pkg', 'security-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy/{security-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['6.2.1', '']]
        },
        'pkg_firewall_shapingpolicy': {
            'params': ['adom', 'pkg', 'shaping-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy/{shaping-policy}'
            ],
            'mkey': 'id'
        },
        'pkg_footer_consolidated_policy': {
            'params': ['pkg', 'policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/consolidated/policy/{policy}'
            ],
            'mkey': 'policyid', 'v_range': [['6.0.0', '7.6.2']]
        },
        'pkg_footer_policy': {
            'params': ['pkg', 'policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}'
            ],
            'mkey': 'policyid'
        },
        'pkg_footer_policy6': {
            'params': ['pkg', 'policy6'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}'
            ],
            'mkey': 'policyid'
        },
        'pkg_footer_policy6_identitybasedpolicy6': {
            'params': ['identity-based-policy6', 'pkg', 'policy6'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '6.2.0']]
        },
        'pkg_footer_policy_identitybasedpolicy': {
            'params': ['identity-based-policy', 'pkg', 'policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '6.2.0']]
        },
        'pkg_footer_shapingpolicy': {
            'params': ['pkg', 'shaping-policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/footer/shaping-policy/{shaping-policy}'
            ],
            'mkey': 'id'
        },
        'pkg_header_consolidated_policy': {
            'params': ['pkg', 'policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/consolidated/policy/{policy}'
            ],
            'mkey': 'policyid', 'v_range': [['6.0.0', '7.6.2']]
        },
        'pkg_header_policy': {
            'params': ['pkg', 'policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}'
            ],
            'mkey': 'policyid'
        },
        'pkg_header_policy6': {
            'params': ['pkg', 'policy6'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}'
            ],
            'mkey': 'policyid'
        },
        'pkg_header_policy6_identitybasedpolicy6': {
            'params': ['identity-based-policy6', 'pkg', 'policy6'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy6/{policy6}/identity-based-policy6/{identity-based-policy6}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '6.2.0']]
        },
        'pkg_header_policy_identitybasedpolicy': {
            'params': ['identity-based-policy', 'pkg', 'policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}/identity-based-policy/{identity-based-policy}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '6.2.0']]
        },
        'pkg_header_shapingpolicy': {
            'params': ['pkg', 'shaping-policy'],
            'urls': [
                '/pm/config/global/pkg/{pkg}/global/header/shaping-policy/{shaping-policy}'
            ],
            'mkey': 'id'
        },
        'pkg_user_nacpolicy': {
            'params': ['adom', 'nac-policy', 'pkg'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/user/nac-policy/{nac-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'pkg_videofilter_youtubekey': {
            'params': ['adom', 'pkg', 'youtube-key'],
            'urls': [
                '/pm/config/adom/{adom}/pkg/{pkg}/videofilter/youtube-key/{youtube-key}'
            ],
            'mkey': 'id', 'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']]
        },
        'pm_config_pblock_firewall_consolidated_policy': {
            'params': ['adom', 'pblock', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/consolidated/policy/{policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.0.3', '7.6.2']]
        },
        'pm_config_pblock_firewall_policy': {
            'params': ['adom', 'pblock', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy/{policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.0.3', '']]
        },
        'pm_config_pblock_firewall_policy6': {
            'params': ['adom', 'pblock', 'policy6'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/policy6/{policy6}'
            ],
            'mkey': 'policyid', 'v_range': [['7.0.3', '7.6.2']]
        },
        'pm_config_pblock_firewall_proxypolicy': {
            'params': ['adom', 'pblock', 'proxy-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/proxy-policy/{proxy-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.6.0', '']]
        },
        'pm_config_pblock_firewall_securitypolicy': {
            'params': ['adom', 'pblock', 'security-policy'],
            'urls': [
                '/pm/config/adom/{adom}/pblock/{pblock}/firewall/security-policy/{security-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.0.3', '']]
        },
        'qosprofile': {
            'params': ['adom', 'qos-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/qos-profile/{qos-profile}',
                '/pm/config/global/obj/wireless-controller/qos-profile/{qos-profile}'
            ],
            'mkey': 'name'
        },
        'region': {
            'params': ['adom', 'region'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/region/{region}',
                '/pm/config/global/obj/wireless-controller/region/{region}'
            ],
            'mkey': 'name', 'v_range': [['6.2.8', '6.2.13'], ['6.4.6', '']]
        },
        'router_accesslist': {
            'params': ['access-list', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/access-list/{access-list}',
                '/pm/config/global/obj/router/access-list/{access-list}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'router_accesslist6': {
            'params': ['access-list6', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/access-list6/{access-list6}',
                '/pm/config/global/obj/router/access-list6/{access-list6}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'router_accesslist6_rule': {
            'params': ['access-list6', 'adom', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/access-list6/{access-list6}/rule/{rule}',
                '/pm/config/global/obj/router/access-list6/{access-list6}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '']]
        },
        'router_accesslist_rule': {
            'params': ['access-list', 'adom', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/access-list/{access-list}/rule/{rule}',
                '/pm/config/global/obj/router/access-list/{access-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '']]
        },
        'router_aspathlist': {
            'params': ['adom', 'aspath-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}',
                '/pm/config/global/obj/router/aspath-list/{aspath-list}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'router_aspathlist_rule': {
            'params': ['adom', 'aspath-list', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/aspath-list/{aspath-list}/rule/{rule}',
                '/pm/config/global/obj/router/aspath-list/{aspath-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '']]
        },
        'router_communitylist': {
            'params': ['adom', 'community-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/community-list/{community-list}',
                '/pm/config/global/obj/router/community-list/{community-list}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'router_communitylist_rule': {
            'params': ['adom', 'community-list', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/community-list/{community-list}/rule/{rule}',
                '/pm/config/global/obj/router/community-list/{community-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '']]
        },
        'router_prefixlist': {
            'params': ['adom', 'prefix-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}',
                '/pm/config/global/obj/router/prefix-list/{prefix-list}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'router_prefixlist6': {
            'params': ['adom', 'prefix-list6'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list6}',
                '/pm/config/global/obj/router/prefix-list6/{prefix-list6}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'router_prefixlist6_rule': {
            'params': ['adom', 'prefix-list6', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/prefix-list6/{prefix-list6}/rule/{rule}',
                '/pm/config/global/obj/router/prefix-list6/{prefix-list6}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '']]
        },
        'router_prefixlist_rule': {
            'params': ['adom', 'prefix-list', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/prefix-list/{prefix-list}/rule/{rule}',
                '/pm/config/global/obj/router/prefix-list/{prefix-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '']]
        },
        'router_routemap': {
            'params': ['adom', 'route-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/route-map/{route-map}',
                '/pm/config/global/obj/router/route-map/{route-map}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'router_routemap_rule': {
            'params': ['adom', 'route-map', 'rule'],
            'urls': [
                '/pm/config/adom/{adom}/obj/router/route-map/{route-map}/rule/{rule}',
                '/pm/config/global/obj/router/route-map/{route-map}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '']]
        },
        'sctpfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/sctp-filter/profile/{profile}',
                '/pm/config/global/obj/sctp-filter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.5', '7.2.11'], ['7.4.2', '']]
        },
        'sctpfilter_profile_ppidfilters': {
            'params': ['adom', 'ppid-filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/sctp-filter/profile/{profile}/ppid-filters/{ppid-filters}',
                '/pm/config/global/obj/sctp-filter/profile/{profile}/ppid-filters/{ppid-filters}'
            ],
            'mkey': 'id', 'v_range': [['7.2.5', '7.2.11'], ['7.4.2', '']]
        },
        'spamfilter_bwl': {
            'params': ['adom', 'bwl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_bwl_entries': {
            'params': ['adom', 'bwl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bwl/{bwl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bwl/{bwl}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_bword': {
            'params': ['adom', 'bword'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}',
                '/pm/config/global/obj/spamfilter/bword/{bword}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_bword_entries': {
            'params': ['adom', 'bword', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/bword/{bword}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/bword/{bword}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_dnsbl': {
            'params': ['adom', 'dnsbl'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_dnsbl_entries': {
            'params': ['adom', 'dnsbl', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/dnsbl/{dnsbl}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_iptrust': {
            'params': ['adom', 'iptrust'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_iptrust_entries': {
            'params': ['adom', 'entries', 'iptrust'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/iptrust/{iptrust}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/iptrust/{iptrust}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_mheader': {
            'params': ['adom', 'mheader'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_mheader_entries': {
            'params': ['adom', 'entries', 'mheader'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/mheader/{mheader}/entries/{entries}',
                '/pm/config/global/obj/spamfilter/mheader/{mheader}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.2.1']]
        },
        'spamfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/spamfilter/profile/{profile}',
                '/pm/config/global/obj/spamfilter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.2.1']]
        },
        'sshfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'sshfilter_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'mkey': None, 'v_range': [['6.2.2', '7.6.2']]
        },
        'sshfilter_profile_shellcommands': {
            'params': ['adom', 'profile', 'shell-commands'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}',
                '/pm/config/global/obj/ssh-filter/profile/{profile}/shell-commands/{shell-commands}'
            ],
            'mkey': 'id'
        },
        'switchcontroller_acl_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/acl/group/{group}',
                '/pm/config/global/obj/switch-controller/acl/group/{group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.0', '']]
        },
        'switchcontroller_acl_ingress': {
            'params': ['adom', 'ingress'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/acl/ingress/{ingress}',
                '/pm/config/global/obj/switch-controller/acl/ingress/{ingress}'
            ],
            'mkey': 'id', 'v_range': [['7.4.0', '']]
        },
        'switchcontroller_customcommand': {
            'params': ['adom', 'custom-command'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/custom-command/{custom-command}',
                '/pm/config/global/obj/switch-controller/custom-command/{custom-command}'
            ],
            'mkey': None, 'v_range': [['7.0.0', '']]
        },
        'switchcontroller_dsl_policy': {
            'params': ['adom', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/dsl/policy/{policy}',
                '/pm/config/global/obj/switch-controller/dsl/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'switchcontroller_dynamicportpolicy': {
            'params': ['adom', 'dynamic-port-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}',
                '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'switchcontroller_dynamicportpolicy_policy': {
            'params': ['adom', 'dynamic-port-policy', 'policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}',
                '/pm/config/global/obj/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'switchcontroller_fortilinksettings': {
            'params': ['adom', 'fortilink-settings'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/fortilink-settings/{fortilink-settings}',
                '/pm/config/global/obj/switch-controller/fortilink-settings/{fortilink-settings}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'switchcontroller_lldpprofile': {
            'params': ['adom', 'lldp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_lldpprofile_customtlvs': {
            'params': ['adom', 'custom-tlvs', 'lldp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_lldpprofile_medlocationservice': {
            'params': ['adom', 'lldp-profile', 'med-location-service'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '']]
        },
        'switchcontroller_lldpprofile_mednetworkpolicy': {
            'params': ['adom', 'lldp-profile', 'med-network-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}',
                '/pm/config/global/obj/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_macpolicy': {
            'params': ['adom', 'mac-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/mac-policy/{mac-policy}',
                '/pm/config/global/obj/switch-controller/mac-policy/{mac-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'switchcontroller_managedswitch': {
            'params': ['adom', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}'
            ],
            'mkey': 'switch-id'
        },
        'switchcontroller_managedswitch_customcommand': {
            'params': ['adom', 'custom-command', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}'
            ],
            'mkey': None, 'v_range': [['7.0.0', '']]
        },
        'switchcontroller_managedswitch_dhcpsnoopingstaticclient': {
            'params': ['adom', 'dhcp-snooping-static-client', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client/{dhcp-snooping-static-client}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client/{dhcp-snooping-static-client}'
            ],
            'mkey': 'name', 'v_range': [['7.2.2', '']]
        },
        'switchcontroller_managedswitch_ipsourceguard': {
            'params': ['adom', 'ip-source-guard', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}'
            ],
            'mkey': None, 'v_range': [['6.4.0', '6.4.1']]
        },
        'switchcontroller_managedswitch_ipsourceguard_bindingentry': {
            'params': ['adom', 'binding-entry', 'ip-source-guard', 'managed-switch'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{binding-entry}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{binding-entry}'
            ],
            'mkey': None, 'v_range': [['6.4.0', '6.4.1']]
        },
        'switchcontroller_managedswitch_ports': {
            'params': ['adom', 'managed-switch', 'ports'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}'
            ],
            'mkey': 'port-name'
        },
        'switchcontroller_managedswitch_ports_dhcpsnoopoption82override': {
            'params': ['adom', 'dhcp-snoop-option82-override', 'managed-switch', 'ports'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override/{dhcp-snoop-option82'
                '-override}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override/{dhcp-snoop-option82-over'
                'ride}'
            ],
            'mkey': None, 'v_range': [['7.4.0', '']]
        },
        'switchcontroller_managedswitch_remotelog': {
            'params': ['adom', 'managed-switch', 'remote-log'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_routeoffloadrouter': {
            'params': ['adom', 'managed-switch', 'route-offload-router'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/route-offload-router/{route-offload-router}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/route-offload-router/{route-offload-router}'
            ],
            'mkey': None, 'v_range': [['7.4.1', '']]
        },
        'switchcontroller_managedswitch_snmpcommunity': {
            'params': ['adom', 'managed-switch', 'snmp-community'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}'
            ],
            'mkey': 'id', 'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_snmpcommunity_hosts': {
            'params': ['adom', 'hosts', 'managed-switch', 'snmp-community'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_snmpuser': {
            'params': ['adom', 'managed-switch', 'snmp-user'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '6.2.3']]
        },
        'switchcontroller_managedswitch_vlan': {
            'params': ['adom', 'managed-switch', 'vlan'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}/vlan/{vlan}',
                '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}/vlan/{vlan}'
            ],
            'mkey': None, 'v_range': [['7.4.2', '']]
        },
        'switchcontroller_ptp_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/ptp/profile/{profile}',
                '/pm/config/global/obj/switch-controller/ptp/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'switchcontroller_qos_dot1pmap': {
            'params': ['adom', 'dot1p-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/dot1p-map/{dot1p-map}',
                '/pm/config/global/obj/switch-controller/qos/dot1p-map/{dot1p-map}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_ipdscpmap': {
            'params': ['adom', 'ip-dscp-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_ipdscpmap_map': {
            'params': ['adom', 'ip-dscp-map', 'map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}',
                '/pm/config/global/obj/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_qospolicy': {
            'params': ['adom', 'qos-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/qos-policy/{qos-policy}',
                '/pm/config/global/obj/switch-controller/qos/qos-policy/{qos-policy}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_queuepolicy': {
            'params': ['adom', 'queue-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_qos_queuepolicy_cosqueue': {
            'params': ['adom', 'cos-queue', 'queue-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}',
                '/pm/config/global/obj/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_securitypolicy_8021x': {
            'params': ['802-1X', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/802-1X/{802-1X}',
                '/pm/config/global/obj/switch-controller/security-policy/802-1X/{802-1X}'
            ],
            'mkey': 'name'
        },
        'switchcontroller_securitypolicy_captiveportal': {
            'params': ['adom', 'captive-portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/security-policy/captive-portal/{captive-portal}',
                '/pm/config/global/obj/switch-controller/security-policy/captive-portal/{captive-portal}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '6.2.1']]
        },
        'switchcontroller_switchinterfacetag': {
            'params': ['adom', 'switch-interface-tag'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/switch-interface-tag/{switch-interface-tag}',
                '/pm/config/global/obj/switch-controller/switch-interface-tag/{switch-interface-tag}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'switchcontroller_trafficpolicy': {
            'params': ['adom', 'traffic-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/traffic-policy/{traffic-policy}',
                '/pm/config/global/obj/switch-controller/traffic-policy/{traffic-policy}'
            ],
            'mkey': 'id', 'v_range': [['7.2.1', '']]
        },
        'switchcontroller_vlanpolicy': {
            'params': ['adom', 'vlan-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/switch-controller/vlan-policy/{vlan-policy}',
                '/pm/config/global/obj/switch-controller/vlan-policy/{vlan-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'system_customlanguage': {
            'params': ['adom', 'custom-language'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/custom-language/{custom-language}',
                '/pm/config/global/obj/system/custom-language/{custom-language}'
            ],
            'mkey': 'name'
        },
        'system_dhcp_server': {
            'params': ['adom', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}',
                '/pm/config/global/obj/system/dhcp/server/{server}'
            ],
            'mkey': 'id'
        },
        'system_dhcp_server_excluderange': {
            'params': ['adom', 'exclude-range', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/exclude-range/{exclude-range}'
            ],
            'mkey': 'id'
        },
        'system_dhcp_server_iprange': {
            'params': ['adom', 'ip-range', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/dhcp/server/{server}/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'system_dhcp_server_options': {
            'params': ['adom', 'options', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/options/{options}',
                '/pm/config/global/obj/system/dhcp/server/{server}/options/{options}'
            ],
            'mkey': 'id'
        },
        'system_dhcp_server_reservedaddress': {
            'params': ['adom', 'reserved-address', 'server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}',
                '/pm/config/global/obj/system/dhcp/server/{server}/reserved-address/{reserved-address}'
            ],
            'mkey': 'id'
        },
        'system_externalresource': {
            'params': ['adom', 'external-resource'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/external-resource/{external-resource}',
                '/pm/config/global/obj/system/external-resource/{external-resource}'
            ],
            'mkey': 'name'
        },
        'system_geoipcountry': {
            'params': ['adom', 'geoip-country'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-country/{geoip-country}',
                '/pm/config/global/obj/system/geoip-country/{geoip-country}'
            ],
            'mkey': 'id'
        },
        'system_geoipoverride': {
            'params': ['adom', 'geoip-override'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}'
            ],
            'mkey': 'name'
        },
        'system_geoipoverride_ip6range': {
            'params': ['adom', 'geoip-override', 'ip6-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip6-range/{ip6-range}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip6-range/{ip6-range}'
            ],
            'mkey': 'id', 'v_range': [['6.4.0', '']]
        },
        'system_geoipoverride_iprange': {
            'params': ['adom', 'geoip-override', 'ip-range'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}',
                '/pm/config/global/obj/system/geoip-override/{geoip-override}/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'system_meta': {
            'params': ['adom', 'meta'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta/{meta}',
                '/pm/config/global/obj/system/meta/{meta}'
            ],
            'mkey': 'name'
        },
        'system_meta_sysmetafields': {
            'params': ['adom', 'meta', 'sys_meta_fields'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}',
                '/pm/config/global/obj/system/meta/{meta}/sys_meta_fields/{sys_meta_fields}'
            ],
            'mkey': 'name'
        },
        'system_npu_dswdtsprofile': {
            'params': ['adom', 'dsw-dts-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/dsw-dts-profile/{dsw-dts-profile}',
                '/pm/config/global/obj/system/npu/dsw-dts-profile/{dsw-dts-profile}'
            ],
            'mkey': None, 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_dswqueuedtsprofile': {
            'params': ['adom', 'dsw-queue-dts-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/dsw-queue-dts-profile/{dsw-queue-dts-profile}',
                '/pm/config/global/obj/system/npu/dsw-queue-dts-profile/{dsw-queue-dts-profile}'
            ],
            'mkey': 'name', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_ethernettype': {
            'params': ['adom', 'ethernet-type'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ethernet-type/{ethernet-type}',
                '/pm/config/global/obj/system/npu/np-queues/ethernet-type/{ethernet-type}'
            ],
            'mkey': 'name', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_ipprotocol': {
            'params': ['adom', 'ip-protocol'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ip-protocol/{ip-protocol}',
                '/pm/config/global/obj/system/npu/np-queues/ip-protocol/{ip-protocol}'
            ],
            'mkey': 'name', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_ipservice': {
            'params': ['adom', 'ip-service'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/ip-service/{ip-service}',
                '/pm/config/global/obj/system/npu/np-queues/ip-service/{ip-service}'
            ],
            'mkey': 'name', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/profile/{profile}',
                '/pm/config/global/obj/system/npu/np-queues/profile/{profile}'
            ],
            'mkey': 'id', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_npqueues_scheduler': {
            'params': ['adom', 'scheduler'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/np-queues/scheduler/{scheduler}',
                '/pm/config/global/obj/system/npu/np-queues/scheduler/{scheduler}'
            ],
            'mkey': 'name', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_nputcam': {
            'params': ['adom', 'npu-tcam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/npu-tcam/{npu-tcam}',
                '/pm/config/global/obj/system/npu/npu-tcam/{npu-tcam}'
            ],
            'mkey': 'name', 'v_range': [['7.4.2', '']]
        },
        'system_npu_portcpumap': {
            'params': ['adom', 'port-cpu-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/port-cpu-map/{port-cpu-map}',
                '/pm/config/global/obj/system/npu/port-cpu-map/{port-cpu-map}'
            ],
            'mkey': None, 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_portnpumap': {
            'params': ['adom', 'port-npu-map'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/port-npu-map/{port-npu-map}',
                '/pm/config/global/obj/system/npu/port-npu-map/{port-npu-map}'
            ],
            'mkey': None, 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_tcptimeoutprofile': {
            'params': ['adom', 'tcp-timeout-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/tcp-timeout-profile/{tcp-timeout-profile}',
                '/pm/config/global/obj/system/npu/tcp-timeout-profile/{tcp-timeout-profile}'
            ],
            'mkey': 'id', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_npu_udptimeoutprofile': {
            'params': ['adom', 'udp-timeout-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/npu/udp-timeout-profile/{udp-timeout-profile}',
                '/pm/config/global/obj/system/npu/udp-timeout-profile/{udp-timeout-profile}'
            ],
            'mkey': 'id', 'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']]
        },
        'system_objecttag': {
            'params': ['adom', 'object-tag'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/object-tag/{object-tag}',
                '/pm/config/global/obj/system/object-tag/{object-tag}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '6.4.15']]
        },
        'system_objecttagging': {
            'params': ['adom', 'object-tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/object-tagging/{object-tagging}',
                '/pm/config/global/obj/system/object-tagging/{object-tagging}'
            ],
            'mkey': 'category'
        },
        'system_replacemsggroup': {
            'params': ['adom', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}'
            ],
            'mkey': 'name'
        },
        'system_replacemsggroup_admin': {
            'params': ['admin', 'adom', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/admin/{admin}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_alertmail': {
            'params': ['adom', 'alertmail', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_auth': {
            'params': ['adom', 'auth', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/auth/{auth}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_automation': {
            'params': ['adom', 'automation', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/automation/{automation}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/automation/{automation}'
            ],
            'mkey': None, 'v_range': [['7.0.0', '']]
        },
        'system_replacemsggroup_custommessage': {
            'params': ['adom', 'custom-message', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/custom-message/{custom-message}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_devicedetectionportal': {
            'params': ['adom', 'device-detection-portal', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/device-detection-portal/{device-detection-portal}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_ec': {
            'params': ['adom', 'ec', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ec/{ec}'
            ],
            'mkey': 'msg-type', 'v_range': [['6.0.0', '7.2.1']]
        },
        'system_replacemsggroup_fortiguardwf': {
            'params': ['adom', 'fortiguard-wf', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/fortiguard-wf/{fortiguard-wf}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_ftp': {
            'params': ['adom', 'ftp', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/ftp/{ftp}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_http': {
            'params': ['adom', 'http', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/http/{http}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/http/{http}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_icap': {
            'params': ['adom', 'icap', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/icap/{icap}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mail': {
            'params': ['adom', 'mail', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mail/{mail}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_mm1': {
            'params': ['adom', 'mm1', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm1/{mm1}'
            ],
            'mkey': 'msg-type', 'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_mm3': {
            'params': ['adom', 'mm3', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm3/{mm3}'
            ],
            'mkey': 'msg-type', 'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_mm4': {
            'params': ['adom', 'mm4', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm4/{mm4}'
            ],
            'mkey': 'msg-type', 'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_mm7': {
            'params': ['adom', 'mm7', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mm7/{mm7}'
            ],
            'mkey': 'msg-type', 'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_mms': {
            'params': ['adom', 'mms', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/mms/{mms}'
            ],
            'mkey': 'msg-type', 'v_range': [['6.0.0', '7.6.2']]
        },
        'system_replacemsggroup_nacquar': {
            'params': ['adom', 'nac-quar', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_nntp': {
            'params': ['adom', 'nntp', 'replacemsg-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/nntp/{nntp}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_spam': {
            'params': ['adom', 'replacemsg-group', 'spam'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/spam/{spam}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_sslvpn': {
            'params': ['adom', 'replacemsg-group', 'sslvpn'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/sslvpn/{sslvpn}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_trafficquota': {
            'params': ['adom', 'replacemsg-group', 'traffic-quota'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/traffic-quota/{traffic-quota}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_utm': {
            'params': ['adom', 'replacemsg-group', 'utm'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/utm/{utm}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsggroup_webproxy': {
            'params': ['adom', 'replacemsg-group', 'webproxy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}',
                '/pm/config/global/obj/system/replacemsg-group/{replacemsg-group}/webproxy/{webproxy}'
            ],
            'mkey': 'msg-type'
        },
        'system_replacemsgimage': {
            'params': ['adom', 'replacemsg-image'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/replacemsg-image/{replacemsg-image}',
                '/pm/config/global/obj/system/replacemsg-image/{replacemsg-image}'
            ],
            'mkey': 'name'
        },
        'system_sdnconnector': {
            'params': ['adom', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}'
            ],
            'mkey': 'name'
        },
        'system_sdnconnector_compartmentlist': {
            'params': ['adom', 'compartment-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/compartment-list/{compartment-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/compartment-list/{compartment-list}'
            ],
            'mkey': None, 'v_range': [['7.4.0', '']]
        },
        'system_sdnconnector_externalaccountlist': {
            'params': ['adom', 'external-account-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-account-list/{external-account-list}'
            ],
            'mkey': None, 'v_range': [['7.0.3', '']]
        },
        'system_sdnconnector_externalip': {
            'params': ['adom', 'external-ip', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/external-ip/{external-ip}'
            ],
            'mkey': 'name'
        },
        'system_sdnconnector_forwardingrule': {
            'params': ['adom', 'forwarding-rule', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/forwarding-rule/{forwarding-rule}'
            ],
            'mkey': None, 'v_range': [['7.0.2', '']]
        },
        'system_sdnconnector_gcpprojectlist': {
            'params': ['adom', 'gcp-project-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/gcp-project-list/{gcp-project-list}'
            ],
            'mkey': 'id', 'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']]
        },
        'system_sdnconnector_nic': {
            'params': ['adom', 'nic', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}'
            ],
            'mkey': 'name'
        },
        'system_sdnconnector_nic_ip': {
            'params': ['adom', 'ip', 'nic', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/nic/{nic}/ip/{ip}'
            ],
            'mkey': 'name'
        },
        'system_sdnconnector_ociregionlist': {
            'params': ['adom', 'oci-region-list', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/oci-region-list/{oci-region-list}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/oci-region-list/{oci-region-list}'
            ],
            'mkey': None, 'v_range': [['7.4.0', '']]
        },
        'system_sdnconnector_route': {
            'params': ['adom', 'route', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route/{route}'
            ],
            'mkey': 'name'
        },
        'system_sdnconnector_routetable': {
            'params': ['adom', 'route-table', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}'
            ],
            'mkey': 'name'
        },
        'system_sdnconnector_routetable_route': {
            'params': ['adom', 'route', 'route-table', 'sdn-connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}',
                '/pm/config/global/obj/system/sdn-connector/{sdn-connector}/route-table/{route-table}/route/{route}'
            ],
            'mkey': 'name'
        },
        'system_sdnproxy': {
            'params': ['adom', 'sdn-proxy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sdn-proxy/{sdn-proxy}',
                '/pm/config/global/obj/system/sdn-proxy/{sdn-proxy}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'system_smsserver': {
            'params': ['adom', 'sms-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/sms-server/{sms-server}',
                '/pm/config/global/obj/system/sms-server/{sms-server}'
            ],
            'mkey': 'name'
        },
        'system_virtualwirepair': {
            'params': ['adom', 'virtual-wire-pair'],
            'urls': [
                '/pm/config/adom/{adom}/obj/system/virtual-wire-pair/{virtual-wire-pair}',
                '/pm/config/global/obj/system/virtual-wire-pair/{virtual-wire-pair}'
            ],
            'mkey': 'name'
        },
        'telemetrycontroller_agentprofile': {
            'params': ['adom', 'agent-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/telemetry-controller/agent-profile/{agent-profile}',
                '/pm/config/global/obj/telemetry-controller/agent-profile/{agent-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.6.3', '']]
        },
        'telemetrycontroller_application_predefine': {
            'params': ['adom', 'predefine'],
            'urls': [
                '/pm/config/adom/{adom}/obj/telemetry-controller/application/predefine/{predefine}',
                '/pm/config/global/obj/telemetry-controller/application/predefine/{predefine}'
            ],
            'mkey': None, 'v_range': [['7.6.3', '']]
        },
        'telemetrycontroller_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/telemetry-controller/profile/{profile}',
                '/pm/config/global/obj/telemetry-controller/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.6.3', '']]
        },
        'telemetrycontroller_profile_application': {
            'params': ['adom', 'application', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/telemetry-controller/profile/{profile}/application/{application}',
                '/pm/config/global/obj/telemetry-controller/profile/{profile}/application/{application}'
            ],
            'mkey': 'id', 'v_range': [['7.6.3', '']]
        },
        'template': {
            'params': ['adom', 'template'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template/{template}',
                '/pm/config/global/obj/cli/template/{template}'
            ],
            'mkey': 'name'
        },
        'templategroup': {
            'params': ['adom', 'template-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/cli/template-group/{template-group}',
                '/pm/config/global/obj/cli/template-group/{template-group}'
            ],
            'mkey': 'name'
        },
        'ums_setting': {
            'params': ['adom', 'setting'],
            'urls': [
                '/pm/config/adom/{adom}/obj/ums/setting/{setting}',
                '/pm/config/global/obj/ums/setting/{setting}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'user_adgrp': {
            'params': ['adgrp', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/adgrp/{adgrp}',
                '/pm/config/global/obj/user/adgrp/{adgrp}'
            ],
            'mkey': 'id'
        },
        'user_certificate': {
            'params': ['adom', 'certificate'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/certificate/{certificate}',
                '/pm/config/global/obj/user/certificate/{certificate}'
            ],
            'mkey': 'id', 'v_range': [['7.0.8', '7.0.14'], ['7.2.3', '']]
        },
        'user_clearpass': {
            'params': ['adom', 'clearpass'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/clearpass/{clearpass}',
                '/pm/config/global/obj/user/clearpass/{clearpass}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '']]
        },
        'user_connector': {
            'params': ['adom', 'connector'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/connector/{connector}',
                '/pm/config/global/obj/user/connector/{connector}'
            ],
            'mkey': 'name', 'v_range': [['7.0.1', '']]
        },
        'user_device': {
            'params': ['adom', 'device'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}',
                '/pm/config/global/obj/user/device/{device}'
            ],
            'mkey': 'alias', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']]
        },
        'user_device_dynamicmapping': {
            'params': ['adom', 'device', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device/{device}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_device_tagging': {
            'params': ['adom', 'device', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device/{device}/tagging/{tagging}',
                '/pm/config/global/obj/user/device/{device}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.2']]
        },
        'user_deviceaccesslist': {
            'params': ['adom', 'device-access-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-access-list/{device-access-list}',
                '/pm/config/global/obj/user/device-access-list/{device-access-list}'
            ],
            'mkey': 'name', 'v_range': [['6.2.2', '7.2.1']]
        },
        'user_deviceaccesslist_devicelist': {
            'params': ['adom', 'device-access-list', 'device-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-access-list/{device-access-list}/device-list/{device-list}',
                '/pm/config/global/obj/user/device-access-list/{device-access-list}/device-list/{device-list}'
            ],
            'mkey': 'id', 'v_range': [['6.2.2', '7.2.1']]
        },
        'user_devicecategory': {
            'params': ['adom', 'device-category'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-category/{device-category}',
                '/pm/config/global/obj/user/device-category/{device-category}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.2.1']]
        },
        'user_devicegroup': {
            'params': ['adom', 'device-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}',
                '/pm/config/global/obj/user/device-group/{device-group}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.2.1']]
        },
        'user_devicegroup_dynamicmapping': {
            'params': ['adom', 'device-group', 'dynamic_mapping'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/device-group/{device-group}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.1']]
        },
        'user_devicegroup_tagging': {
            'params': ['adom', 'device-group', 'tagging'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/device-group/{device-group}/tagging/{tagging}',
                '/pm/config/global/obj/user/device-group/{device-group}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.2.1']]
        },
        'user_domaincontroller': {
            'params': ['adom', 'domain-controller'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/domain-controller/{domain-controller}',
                '/pm/config/global/obj/user/domain-controller/{domain-controller}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '']]
        },
        'user_domaincontroller_extraserver': {
            'params': ['adom', 'domain-controller', 'extra-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/domain-controller/{domain-controller}/extra-server/{extra-server}',
                '/pm/config/global/obj/user/domain-controller/{domain-controller}/extra-server/{extra-server}'
            ],
            'mkey': 'id', 'v_range': [['6.2.1', '']]
        },
        'user_exchange': {
            'params': ['adom', 'exchange'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/exchange/{exchange}',
                '/pm/config/global/obj/user/exchange/{exchange}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '']]
        },
        'user_externalidentityprovider': {
            'params': ['adom', 'external-identity-provider'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/external-identity-provider/{external-identity-provider}',
                '/pm/config/global/obj/user/external-identity-provider/{external-identity-provider}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.11'], ['7.4.3', '']]
        },
        'user_flexvm': {
            'params': ['adom', 'flexvm'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/flexvm/{flexvm}',
                '/pm/config/global/obj/user/flexvm/{flexvm}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'user_fortitoken': {
            'params': ['adom', 'fortitoken'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fortitoken/{fortitoken}',
                '/pm/config/global/obj/user/fortitoken/{fortitoken}'
            ],
            'mkey': 'serial-number'
        },
        'user_fsso': {
            'params': ['adom', 'fsso'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}',
                '/pm/config/global/obj/user/fsso/{fsso}'
            ],
            'mkey': 'name'
        },
        'user_fsso_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'fsso'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/fsso/{fsso}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_fssopolling': {
            'params': ['adom', 'fsso-polling'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}'
            ],
            'mkey': 'id'
        },
        'user_fssopolling_adgrp': {
            'params': ['adgrp', 'adom', 'fsso-polling'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}',
                '/pm/config/global/obj/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}'
            ],
            'mkey': 'name'
        },
        'user_group': {
            'params': ['adom', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}',
                '/pm/config/global/obj/user/group/{group}'
            ],
            'mkey': 'name'
        },
        'user_group_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_group_dynamicmapping_guest': {
            'params': ['adom', 'dynamic_mapping', 'group', 'guest'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest/{guest}',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/guest/{guest}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_group_dynamicmapping_match': {
            'params': ['adom', 'dynamic_mapping', 'group', 'match'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match/{match}',
                '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}/match/{match}'
            ],
            'mkey': 'id', 'v_range': [['7.0.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_group_guest': {
            'params': ['adom', 'group', 'guest'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/guest/{guest}',
                '/pm/config/global/obj/user/group/{group}/guest/{guest}'
            ],
            'mkey': 'user-id'
        },
        'user_group_match': {
            'params': ['adom', 'group', 'match'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/group/{group}/match/{match}',
                '/pm/config/global/obj/user/group/{group}/match/{match}'
            ],
            'mkey': 'id'
        },
        'user_json': {
            'params': ['adom', 'json'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/json/{json}',
                '/pm/config/global/obj/user/json/{json}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'user_krbkeytab': {
            'params': ['adom', 'krb-keytab'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/krb-keytab/{krb-keytab}',
                '/pm/config/global/obj/user/krb-keytab/{krb-keytab}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '']]
        },
        'user_ldap': {
            'params': ['adom', 'ldap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}',
                '/pm/config/global/obj/user/ldap/{ldap}'
            ],
            'mkey': 'name'
        },
        'user_ldap_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'ldap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/ldap/{ldap}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_local': {
            'params': ['adom', 'local'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/local/{local}',
                '/pm/config/global/obj/user/local/{local}'
            ],
            'mkey': 'name'
        },
        'user_nsx': {
            'params': ['adom', 'nsx'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/nsx/{nsx}',
                '/pm/config/global/obj/user/nsx/{nsx}'
            ],
            'mkey': 'name', 'v_range': [['6.2.1', '']]
        },
        'user_nsx_service': {
            'params': ['adom', 'nsx', 'service'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/nsx/{nsx}/service/{service}',
                '/pm/config/global/obj/user/nsx/{nsx}/service/{service}'
            ],
            'mkey': 'id', 'v_range': [['7.0.4', '']]
        },
        'user_passwordpolicy': {
            'params': ['adom', 'password-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/password-policy/{password-policy}',
                '/pm/config/global/obj/user/password-policy/{password-policy}'
            ],
            'mkey': 'name'
        },
        'user_peer': {
            'params': ['adom', 'peer'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peer/{peer}',
                '/pm/config/global/obj/user/peer/{peer}'
            ],
            'mkey': 'name'
        },
        'user_peergrp': {
            'params': ['adom', 'peergrp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/peergrp/{peergrp}',
                '/pm/config/global/obj/user/peergrp/{peergrp}'
            ],
            'mkey': 'name'
        },
        'user_pop3': {
            'params': ['adom', 'pop3'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pop3/{pop3}',
                '/pm/config/global/obj/user/pop3/{pop3}'
            ],
            'mkey': 'name'
        },
        'user_pxgrid': {
            'params': ['adom', 'pxgrid'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/pxgrid/{pxgrid}',
                '/pm/config/global/obj/user/pxgrid/{pxgrid}'
            ],
            'mkey': 'name'
        },
        'user_radius': {
            'params': ['adom', 'radius'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}',
                '/pm/config/global/obj/user/radius/{radius}'
            ],
            'mkey': 'name'
        },
        'user_radius_accountingserver': {
            'params': ['accounting-server', 'adom', 'radius'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/accounting-server/{accounting-server}',
                '/pm/config/global/obj/user/radius/{radius}/accounting-server/{accounting-server}'
            ],
            'mkey': 'id'
        },
        'user_radius_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'radius'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_radius_dynamicmapping_accountingserver': {
            'params': ['accounting-server', 'adom', 'dynamic_mapping', 'radius'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server/{accounting-server}',
                '/pm/config/global/obj/user/radius/{radius}/dynamic_mapping/{dynamic_mapping}/accounting-server/{accounting-server}'
            ],
            'mkey': 'id', 'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_saml': {
            'params': ['adom', 'saml'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/saml/{saml}',
                '/pm/config/global/obj/user/saml/{saml}'
            ],
            'mkey': 'name', 'v_range': [['6.4.0', '']]
        },
        'user_saml_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'saml'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/saml/{saml}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/saml/{saml}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': None, 'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_scim': {
            'params': ['adom', 'scim'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/scim/{scim}',
                '/pm/config/global/obj/user/scim/{scim}'
            ],
            'mkey': 'id', 'v_range': [['7.6.3', '']]
        },
        'user_securityexemptlist': {
            'params': ['adom', 'security-exempt-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}'
            ],
            'mkey': 'name'
        },
        'user_securityexemptlist_rule': {
            'params': ['adom', 'rule', 'security-exempt-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}',
                '/pm/config/global/obj/user/security-exempt-list/{security-exempt-list}/rule/{rule}'
            ],
            'mkey': 'id'
        },
        'user_tacacs': {
            'params': ['adom', 'tacacs+'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}'
            ],
            'mkey': 'name'
        },
        'user_tacacs_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'tacacs+'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/user/tacacs+/{tacacs+}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'user_vcenter': {
            'params': ['adom', 'vcenter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/vcenter/{vcenter}',
                '/pm/config/global/obj/user/vcenter/{vcenter}'
            ],
            'mkey': 'name', 'v_range': [['6.4.0', '']]
        },
        'user_vcenter_rule': {
            'params': ['adom', 'rule', 'vcenter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/user/vcenter/{vcenter}/rule/{rule}',
                '/pm/config/global/obj/user/vcenter/{vcenter}/rule/{rule}'
            ],
            'mkey': 'name', 'v_range': [['6.4.0', '']]
        },
        'utmprofile': {
            'params': ['adom', 'utm-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/utm-profile/{utm-profile}',
                '/pm/config/global/obj/wireless-controller/utm-profile/{utm-profile}'
            ],
            'mkey': 'name', 'v_range': [['6.2.2', '']]
        },
        'vap': {
            'params': ['adom', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}'
            ],
            'mkey': 'name'
        },
        'vap_dynamicmapping': {
            'params': ['adom', 'dynamic_mapping', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/dynamic_mapping/{dynamic_mapping}'
            ],
            'mkey': '_scope', 'v_range': [['6.0.0', '7.2.5'], ['7.4.0', '7.4.0']]
        },
        'vap_macfilterlist': {
            'params': ['adom', 'mac-filter-list', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}'
            ],
            'mkey': 'id'
        },
        'vap_mpskkey': {
            'params': ['adom', 'mpsk-key', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}'
            ],
            'mkey': 'key-name'
        },
        'vap_vlanname': {
            'params': ['adom', 'vap', 'vlan-name'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'mkey': 'name', 'v_range': [['7.0.3', '']]
        },
        'vap_vlanpool': {
            'params': ['adom', 'vap', 'vlan-pool'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}',
                '/pm/config/global/obj/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}'
            ],
            'mkey': 'id'
        },
        'vapgroup': {
            'params': ['adom', 'vap-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap-group/{vap-group}',
                '/pm/config/global/obj/wireless-controller/vap-group/{vap-group}'
            ],
            'mkey': 'name'
        },
        'videofilter_keyword': {
            'params': ['adom', 'keyword'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/keyword/{keyword}',
                '/pm/config/global/obj/videofilter/keyword/{keyword}'
            ],
            'mkey': 'id', 'v_range': [['7.4.2', '']]
        },
        'videofilter_keyword_word': {
            'params': ['adom', 'keyword', 'word'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/keyword/{keyword}/word/{word}',
                '/pm/config/global/obj/videofilter/keyword/{keyword}/word/{word}'
            ],
            'mkey': 'name', 'v_range': [['7.4.2', '']]
        },
        'videofilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}',
                '/pm/config/global/obj/videofilter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.0.0', '']]
        },
        'videofilter_profile_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/filters/{filters}',
                '/pm/config/global/obj/videofilter/profile/{profile}/filters/{filters}'
            ],
            'mkey': 'id', 'v_range': [['7.4.2', '']]
        },
        'videofilter_profile_fortiguardcategory_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}',
                '/pm/config/global/obj/videofilter/profile/{profile}/fortiguard-category/filters/{filters}'
            ],
            'mkey': 'id', 'v_range': [['7.0.0', '']]
        },
        'videofilter_youtubechannelfilter': {
            'params': ['adom', 'youtube-channel-filter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}',
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}'
            ],
            'mkey': 'id', 'v_range': [['7.0.0', '']]
        },
        'videofilter_youtubechannelfilter_entries': {
            'params': ['adom', 'entries', 'youtube-channel-filter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}',
                '/pm/config/global/obj/videofilter/youtube-channel-filter/{youtube-channel-filter}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.0.0', '']]
        },
        'videofilter_youtubekey': {
            'params': ['adom', 'youtube-key'],
            'urls': [
                '/pm/config/adom/{adom}/obj/videofilter/youtube-key/{youtube-key}',
                '/pm/config/global/obj/videofilter/youtube-key/{youtube-key}'
            ],
            'mkey': 'id', 'v_range': [['7.4.2', '7.4.3'], ['7.6.0', '7.6.1']]
        },
        'virtualpatch_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/virtual-patch/profile/{profile}',
                '/pm/config/global/obj/virtual-patch/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.1', '']]
        },
        'virtualpatch_profile_exemption': {
            'params': ['adom', 'exemption', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/virtual-patch/profile/{profile}/exemption/{exemption}',
                '/pm/config/global/obj/virtual-patch/profile/{profile}/exemption/{exemption}'
            ],
            'mkey': 'id', 'v_range': [['7.4.1', '']]
        },
        'voip_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/voip/profile/{profile}',
                '/pm/config/global/obj/voip/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'vpn_certificate_ca': {
            'params': ['adom', 'ca'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ca/{ca}',
                '/pm/config/global/obj/vpn/certificate/ca/{ca}'
            ],
            'mkey': 'name'
        },
        'vpn_certificate_ocspserver': {
            'params': ['adom', 'ocsp-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server/{ocsp-server}',
                '/pm/config/global/obj/vpn/certificate/ocsp-server/{ocsp-server}'
            ],
            'mkey': 'name'
        },
        'vpn_certificate_remote': {
            'params': ['adom', 'remote'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/certificate/remote/{remote}',
                '/pm/config/global/obj/vpn/certificate/remote/{remote}'
            ],
            'mkey': 'name'
        },
        'vpn_ipsec_fec': {
            'params': ['adom', 'fec'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}',
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}'
            ],
            'mkey': 'name', 'v_range': [['7.2.0', '']]
        },
        'vpn_ipsec_fec_mappings': {
            'params': ['adom', 'fec', 'mappings'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}',
                '/pm/config/global/obj/vpn/ipsec/fec/{fec}/mappings/{mappings}'
            ],
            'mkey': None, 'v_range': [['7.2.0', '']]
        },
        'vpn_ssl_settings_authenticationrule': {
            'params': ['authentication-rule', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule/{authentication-rule}'
            ],
            'mkey': 'id', 'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']]
        },
        'vpnmgr_node': {
            'params': ['adom', 'node'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}',
                '/pm/config/global/obj/vpnmgr/node/{node}'
            ],
            'mkey': 'id'
        },
        'vpnmgr_node_iprange': {
            'params': ['adom', 'ip-range', 'node'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ip-range/{ip-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ip-range/{ip-range}'
            ],
            'mkey': 'id'
        },
        'vpnmgr_node_ipv4excluderange': {
            'params': ['adom', 'ipv4-exclude-range', 'node'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}',
                '/pm/config/global/obj/vpnmgr/node/{node}/ipv4-exclude-range/{ipv4-exclude-range}'
            ],
            'mkey': 'id'
        },
        'vpnmgr_node_protectedsubnet': {
            'params': ['adom', 'node', 'protected_subnet'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}',
                '/pm/config/global/obj/vpnmgr/node/{node}/protected_subnet/{protected_subnet}'
            ],
            'mkey': 'seq'
        },
        'vpnmgr_node_summaryaddr': {
            'params': ['adom', 'node', 'summary_addr'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}',
                '/pm/config/global/obj/vpnmgr/node/{node}/summary_addr/{summary_addr}'
            ],
            'mkey': 'seq'
        },
        'vpnmgr_vpntable': {
            'params': ['adom', 'vpntable'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpnmgr/vpntable/{vpntable}',
                '/pm/config/global/obj/vpnmgr/vpntable/{vpntable}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_hostchecksoftware': {
            'params': ['adom', 'host-check-software'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_hostchecksoftware_checkitemlist': {
            'params': ['adom', 'check-item-list', 'host-check-software'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}',
                '/pm/config/global/obj/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}'
            ],
            'mkey': 'id'
        },
        'vpnsslweb_portal': {
            'params': ['adom', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_portal_bookmarkgroup': {
            'params': ['adom', 'bookmark-group', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks': {
            'params': ['adom', 'bookmark-group', 'bookmarks', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata': {
            'params': ['adom', 'bookmark-group', 'bookmarks', 'form-data', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-data}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_portal_landingpage_formdata': {
            'params': ['adom', 'form-data', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/landing-page/form-data/{form-data}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/landing-page/form-data/{form-data}'
            ],
            'mkey': 'name', 'v_range': [['7.4.0', '']]
        },
        'vpnsslweb_portal_macaddrcheckrule': {
            'params': ['adom', 'mac-addr-check-rule', 'portal'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}'
            ],
            'mkey': 'name'
        },
        'vpnsslweb_portal_splitdns': {
            'params': ['adom', 'portal', 'split-dns'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}',
                '/pm/config/global/obj/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}'
            ],
            'mkey': 'id'
        },
        'vpnsslweb_realm': {
            'params': ['adom', 'realm'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/realm/{realm}',
                '/pm/config/global/obj/vpn/ssl/web/realm/{realm}'
            ],
            'mkey': None
        },
        'vpnsslweb_virtualdesktopapplist': {
            'params': ['adom', 'virtual-desktop-app-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}',
                '/pm/config/global/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '6.2.13']]
        },
        'vpnsslweb_virtualdesktopapplist_apps': {
            'params': ['adom', 'apps', 'virtual-desktop-app-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}/apps/{apps}',
                '/pm/config/global/obj/vpn/ssl/web/virtual-desktop-app-list/{virtual-desktop-app-list}/apps/{apps}'
            ],
            'mkey': 'name', 'v_range': [['6.2.0', '6.2.13']]
        },
        'waf_mainclass': {
            'params': ['adom', 'main-class'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/main-class/{main-class}',
                '/pm/config/global/obj/waf/main-class/{main-class}'
            ],
            'mkey': 'id'
        },
        'waf_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}',
                '/pm/config/global/obj/waf/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'waf_profile_constraint_exception': {
            'params': ['adom', 'exception', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/constraint/exception/{exception}',
                '/pm/config/global/obj/waf/profile/{profile}/constraint/exception/{exception}'
            ],
            'mkey': 'id'
        },
        'waf_profile_method_methodpolicy': {
            'params': ['adom', 'method-policy', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/method/method-policy/{method-policy}',
                '/pm/config/global/obj/waf/profile/{profile}/method/method-policy/{method-policy}'
            ],
            'mkey': 'id'
        },
        'waf_profile_signature_customsignature': {
            'params': ['adom', 'custom-signature', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}',
                '/pm/config/global/obj/waf/profile/{profile}/signature/custom-signature/{custom-signature}'
            ],
            'mkey': 'name'
        },
        'waf_profile_urlaccess': {
            'params': ['adom', 'profile', 'url-access'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}'
            ],
            'mkey': 'id'
        },
        'waf_profile_urlaccess_accesspattern': {
            'params': ['access-pattern', 'adom', 'profile', 'url-access'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}',
                '/pm/config/global/obj/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}'
            ],
            'mkey': 'id'
        },
        'waf_signature': {
            'params': ['adom', 'signature'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/signature/{signature}',
                '/pm/config/global/obj/waf/signature/{signature}'
            ],
            'mkey': 'id'
        },
        'waf_subclass': {
            'params': ['adom', 'sub-class'],
            'urls': [
                '/pm/config/adom/{adom}/obj/waf/sub-class/{sub-class}',
                '/pm/config/global/obj/waf/sub-class/{sub-class}'
            ],
            'mkey': 'id'
        },
        'wagprofile': {
            'params': ['adom', 'wag-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wag-profile/{wag-profile}',
                '/pm/config/global/obj/wireless-controller/wag-profile/{wag-profile}'
            ],
            'mkey': 'name', 'v_range': [['6.2.3', '']]
        },
        'wanopt_authgroup': {
            'params': ['adom', 'auth-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/auth-group/{auth-group}',
                '/pm/config/global/obj/wanopt/auth-group/{auth-group}'
            ],
            'mkey': 'name'
        },
        'wanopt_peer': {
            'params': ['adom', 'peer'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/peer/{peer}',
                '/pm/config/global/obj/wanopt/peer/{peer}'
            ],
            'mkey': 'peer-host-id'
        },
        'wanopt_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}',
                '/pm/config/global/obj/wanopt/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'wanprof_system_sdwan_duplication': {
            'params': ['adom', 'duplication', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/duplication/{duplication}'
            ],
            'mkey': 'id', 'v_range': [['6.4.2', '']]
        },
        'wanprof_system_sdwan_healthcheck': {
            'params': ['adom', 'health-check', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}'
            ],
            'mkey': 'name', 'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_healthcheck_sla': {
            'params': ['adom', 'health-check', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/health-check/{health-check}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_members': {
            'params': ['adom', 'members', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/members/{members}'
            ],
            'mkey': 'seq-num', 'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_neighbor': {
            'params': ['adom', 'neighbor', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/neighbor/{neighbor}'
            ],
            'mkey': None, 'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_service': {
            'params': ['adom', 'service', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}'
            ],
            'mkey': 'id', 'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_service_sla': {
            'params': ['adom', 'service', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['6.4.1', '']]
        },
        'wanprof_system_sdwan_zone': {
            'params': ['adom', 'wanprof', 'zone'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/sdwan/zone/{zone}'
            ],
            'mkey': 'name', 'v_range': [['6.4.1', '']]
        },
        'wanprof_system_virtualwanlink_healthcheck': {
            'params': ['adom', 'health-check', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_healthcheck_sla': {
            'params': ['adom', 'health-check', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/health-check/{health-check}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_members': {
            'params': ['adom', 'members', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/members/{members}'
            ],
            'mkey': 'seq-num', 'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_neighbor': {
            'params': ['adom', 'neighbor', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/neighbor/{neighbor}'
            ],
            'mkey': None, 'v_range': [['6.2.1', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_service': {
            'params': ['adom', 'service', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.6.2']]
        },
        'wanprof_system_virtualwanlink_service_sla': {
            'params': ['adom', 'service', 'sla', 'wanprof'],
            'urls': [
                '/pm/config/adom/{adom}/wanprof/{wanprof}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['6.0.0', '7.6.2']]
        },
        'webfilter_categories': {
            'params': ['adom', 'categories'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/categories/{categories}',
                '/pm/config/global/obj/webfilter/categories/{categories}'
            ],
            'mkey': 'id'
        },
        'webfilter_content': {
            'params': ['adom', 'content'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}',
                '/pm/config/global/obj/webfilter/content/{content}'
            ],
            'mkey': 'id'
        },
        'webfilter_content_entries': {
            'params': ['adom', 'content', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content/{content}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content/{content}/entries/{entries}'
            ],
            'mkey': 'name'
        },
        'webfilter_contentheader': {
            'params': ['adom', 'content-header'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}',
                '/pm/config/global/obj/webfilter/content-header/{content-header}'
            ],
            'mkey': 'id'
        },
        'webfilter_contentheader_entries': {
            'params': ['adom', 'content-header', 'entries'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/content-header/{content-header}/entries/{entries}',
                '/pm/config/global/obj/webfilter/content-header/{content-header}/entries/{entries}'
            ],
            'mkey': None
        },
        'webfilter_ftgdlocalcat': {
            'params': ['adom', 'ftgd-local-cat'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}',
                '/pm/config/global/obj/webfilter/ftgd-local-cat/{ftgd-local-cat}'
            ],
            'mkey': 'id'
        },
        'webfilter_ftgdlocalrating': {
            'params': ['adom', 'ftgd-local-rating'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}',
                '/pm/config/global/obj/webfilter/ftgd-local-rating/{ftgd-local-rating}'
            ],
            'mkey': 'rating'
        },
        'webfilter_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}',
                '/pm/config/global/obj/webfilter/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'webfilter_profile_antiphish_custompatterns': {
            'params': ['adom', 'custom-patterns', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/custom-patterns/{custom-patterns}',
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/custom-patterns/{custom-patterns}'
            ],
            'mkey': None, 'v_range': [['6.4.0', '']]
        },
        'webfilter_profile_antiphish_inspectionentries': {
            'params': ['adom', 'inspection-entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/antiphish/inspection-entries/{inspection-entries}',
                '/pm/config/global/obj/webfilter/profile/{profile}/antiphish/inspection-entries/{inspection-entries}'
            ],
            'mkey': 'name', 'v_range': [['6.4.0', '']]
        },
        'webfilter_profile_filefilter_entries': {
            'params': ['adom', 'entries', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/file-filter/entries/{entries}',
                '/pm/config/global/obj/webfilter/profile/{profile}/file-filter/entries/{entries}'
            ],
            'mkey': None, 'v_range': [['6.2.0', '7.6.2']]
        },
        'webfilter_profile_ftgdwf_filters': {
            'params': ['adom', 'filters', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/filters/{filters}'
            ],
            'mkey': 'id'
        },
        'webfilter_profile_ftgdwf_quota': {
            'params': ['adom', 'profile', 'quota'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/quota/{quota}'
            ],
            'mkey': 'id'
        },
        'webfilter_profile_ftgdwf_risk': {
            'params': ['adom', 'profile', 'risk'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/ftgd-wf/risk/{risk}',
                '/pm/config/global/obj/webfilter/profile/{profile}/ftgd-wf/risk/{risk}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'webfilter_profile_youtubechannelfilter': {
            'params': ['adom', 'profile', 'youtube-channel-filter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}',
                '/pm/config/global/obj/webfilter/profile/{profile}/youtube-channel-filter/{youtube-channel-filter}'
            ],
            'mkey': 'id'
        },
        'webfilter_urlfilter': {
            'params': ['adom', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}'
            ],
            'mkey': 'id'
        },
        'webfilter_urlfilter_entries': {
            'params': ['adom', 'entries', 'urlfilter'],
            'urls': [
                '/pm/config/adom/{adom}/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}',
                '/pm/config/global/obj/webfilter/urlfilter/{urlfilter}/entries/{entries}'
            ],
            'mkey': 'id'
        },
        'webproxy_forwardserver': {
            'params': ['adom', 'forward-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server/{forward-server}',
                '/pm/config/global/obj/web-proxy/forward-server/{forward-server}'
            ],
            'mkey': 'name'
        },
        'webproxy_forwardservergroup': {
            'params': ['adom', 'forward-server-group'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}'
            ],
            'mkey': 'name'
        },
        'webproxy_forwardservergroup_serverlist': {
            'params': ['adom', 'forward-server-group', 'server-list'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}',
                '/pm/config/global/obj/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}'
            ],
            'mkey': 'name'
        },
        'webproxy_isolatorserver': {
            'params': ['adom', 'isolator-server'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/isolator-server/{isolator-server}',
                '/pm/config/global/obj/web-proxy/isolator-server/{isolator-server}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'webproxy_profile': {
            'params': ['adom', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}',
                '/pm/config/global/obj/web-proxy/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'webproxy_profile_headers': {
            'params': ['adom', 'headers', 'profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/profile/{profile}/headers/{headers}',
                '/pm/config/global/obj/web-proxy/profile/{profile}/headers/{headers}'
            ],
            'mkey': 'id'
        },
        'webproxy_wisp': {
            'params': ['adom', 'wisp'],
            'urls': [
                '/pm/config/adom/{adom}/obj/web-proxy/wisp/{wisp}',
                '/pm/config/global/obj/web-proxy/wisp/{wisp}'
            ],
            'mkey': 'name'
        },
        'widsprofile': {
            'params': ['adom', 'wids-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wids-profile/{wids-profile}',
                '/pm/config/global/obj/wireless-controller/wids-profile/{wids-profile}'
            ],
            'mkey': 'name'
        },
        'wireless_accesscontrollist': {
            'params': ['access-control-list', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'wireless_accesscontrollist_layer3ipv4rules': {
            'params': ['access-control-list', 'adom', 'layer3-ipv4-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}'
            ],
            'mkey': None, 'v_range': [['7.2.1', '']]
        },
        'wireless_accesscontrollist_layer3ipv6rules': {
            'params': ['access-control-list', 'adom', 'layer3-ipv6-rules'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}',
                '/pm/config/global/obj/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}'
            ],
            'mkey': None, 'v_range': [['7.2.1', '']]
        },
        'wireless_address': {
            'params': ['address', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/address/{address}',
                '/pm/config/global/obj/wireless-controller/address/{address}'
            ],
            'mkey': 'id', 'v_range': [['7.0.1', '']]
        },
        'wireless_addrgrp': {
            'params': ['addrgrp', 'adom'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/addrgrp/{addrgrp}',
                '/pm/config/global/obj/wireless-controller/addrgrp/{addrgrp}'
            ],
            'mkey': 'id', 'v_range': [['7.0.1', '']]
        },
        'wireless_ssidpolicy': {
            'params': ['adom', 'ssid-policy'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/ssid-policy/{ssid-policy}',
                '/pm/config/global/obj/wireless-controller/ssid-policy/{ssid-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'wireless_syslogprofile': {
            'params': ['adom', 'syslog-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/syslog-profile/{syslog-profile}',
                '/pm/config/global/obj/wireless-controller/syslog-profile/{syslog-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.1', '']]
        },
        'wireless_vap_ip6prefixlist': {
            'params': ['adom', 'ip6-prefix-list', 'vap'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/vap/{vap}/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'mkey': None, 'v_range': [['7.2.10', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']]
        },
        'wtpprofile': {
            'params': ['adom', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}'
            ],
            'mkey': 'name'
        },
        'wtpprofile_denymaclist': {
            'params': ['adom', 'deny-mac-list', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}'
            ],
            'mkey': 'id'
        },
        'wtpprofile_splittunnelingacl': {
            'params': ['adom', 'split-tunneling-acl', 'wtp-profile'],
            'urls': [
                '/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}',
                '/pm/config/global/obj/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}'
            ],
            'mkey': 'id'
        }
    }

    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'workspace_locking_adom': {'type': 'str'},
        'workspace_locking_timeout': {'type': 'int', 'default': 300},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'clone': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': list(clone_metadata.keys())
                },
                'self': {'required': True, 'type': 'dict'},
                'target': {'required': True, 'type': 'dict'}
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec, supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('clone', clone_metadata, None, None, None, module, connection)
    fmgr.process_task()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
